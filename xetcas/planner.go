package xetcas

import (
	"context"
	"errors"
	"fmt"
	"math"
	"sort"

	"github.com/jacobwoliver/xet-go/chunker"
	"github.com/jacobwoliver/xet-go/shard"
	"github.com/jacobwoliver/xet-go/xethash"
	"github.com/jacobwoliver/xet-go/xorb"
)

// XorbLayoutLookup resolves the canonical serialized and uncompressed chunk
// boundaries persisted during server xorb ingestion.
type XorbLayoutLookup func(xethash.Hash) (*xorb.Ingested, bool, error)

// ReconstructionPlan is an unsigned, storage-neutral reconstruction. Ranges
// are merged per xorb while Terms remain in logical file order.
type ReconstructionPlan struct {
	OffsetIntoFirstRange uint64
	Terms                []ReconstructionTerm
	Xorbs                map[xethash.Hash][]XorbRangeDescriptor
}

// PlanReconstruction crops a validated file recipe to a logical range and
// maps the selected chunks to inclusive serialized xorb byte ranges.
func PlanReconstruction(
	file shard.RegisteredFile,
	requested *FileRange,
	lookup XorbLayoutLookup,
) (*ReconstructionPlan, error) {
	return PlanReconstructionContext(context.Background(), file, requested, lookup)
}

// PlanReconstructionContext is PlanReconstruction with cancellation for
// server-side planning over untrusted or very large recipes.
func PlanReconstructionContext(
	ctx context.Context,
	file shard.RegisteredFile,
	requested *FileRange,
	lookup XorbLayoutLookup,
) (*ReconstructionPlan, error) {
	if ctx == nil {
		return nil, errors.New("xet CAS: nil reconstruction context")
	}
	if lookup == nil {
		return nil, errors.New("xet CAS: nil xorb layout lookup")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	var recipeSize uint64
	for i, term := range file.File.Terms {
		if i&1023 == 0 {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
		}
		if math.MaxUint64-recipeSize < uint64(term.UnpackedBytes) {
			return nil, errors.New("xet CAS: reconstruction size overflows")
		}
		recipeSize += uint64(term.UnpackedBytes)
	}
	if recipeSize != file.Size {
		return nil, fmt.Errorf("xet CAS: reconstruction size %d, expected %d", recipeSize, file.Size)
	}
	start, end := uint64(0), file.Size
	if requested != nil {
		if err := requested.Validate(); err != nil {
			return nil, err
		}
		if requested.Start >= file.Size {
			if file.Size == 0 && requested.Start == 0 {
				return &ReconstructionPlan{Xorbs: make(map[xethash.Hash][]XorbRangeDescriptor)}, nil
			}
			return nil, ErrRangeNotSatisfiable
		}
		start = requested.Start
		end = min(requested.End, file.Size)
	}
	plan := &ReconstructionPlan{Xorbs: make(map[xethash.Hash][]XorbRangeDescriptor)}
	if file.Size == 0 {
		if len(file.File.Terms) != 0 {
			return nil, errors.New("xet CAS: empty file has reconstruction terms")
		}
		return plan, nil
	}
	if len(file.File.Terms) == 0 {
		return nil, errors.New("xet CAS: non-empty file has no reconstruction terms")
	}

	layouts := make(map[xethash.Hash]*xorb.Ingested)
	resolve := func(hash xethash.Hash) (*xorb.Ingested, error) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if value, ok := layouts[hash]; ok {
			return value, nil
		}
		value, found, err := lookup(hash)
		if err != nil {
			return nil, fmt.Errorf("xet CAS: resolve xorb layout %s: %w", hash, err)
		}
		if !found || value == nil {
			return nil, fmt.Errorf("xet CAS: xorb layout %s not found", hash)
		}
		if value.Hash != hash {
			return nil, fmt.Errorf("xet CAS: xorb layout returned %s for %s", value.Hash, hash)
		}
		layouts[hash] = value
		return value, nil
	}

	termIndex := 0
	var cumulative uint64
	for termIndex < len(file.File.Terms) {
		if termIndex&1023 == 0 {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
		}
		termSize := uint64(file.File.Terms[termIndex].UnpackedBytes)
		if math.MaxUint64-cumulative < termSize {
			return nil, errors.New("xet CAS: reconstruction size overflows")
		}
		if cumulative+termSize > start {
			break
		}
		cumulative += termSize
		termIndex++
	}
	if termIndex == len(file.File.Terms) {
		return nil, errors.New("xet CAS: file size disagrees with reconstruction terms")
	}
	firstChunkByteStart := cumulative

	for termIndex < len(file.File.Terms) && cumulative < end {
		if termIndex&1023 == 0 {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
		}
		term := file.File.Terms[termIndex]
		layout, err := resolve(term.XorbHash)
		if err != nil {
			return nil, err
		}
		chunkRange := ChunkRange{Start: term.Start, End: term.End}
		if err := validateLayoutRange(layout, chunkRange); err != nil {
			return nil, fmt.Errorf("xet CAS: term %d: %w", termIndex, err)
		}
		unpacked := term.UnpackedBytes
		if cumulative < start {
			for chunkRange.Start < chunkRange.End {
				chunkSize := layout.Chunks[chunkRange.Start].UncompressedLength
				if cumulative+uint64(chunkSize) > start {
					break
				}
				cumulative += uint64(chunkSize)
				firstChunkByteStart += uint64(chunkSize)
				if chunkSize > unpacked {
					return nil, fmt.Errorf("xet CAS: term %d unpacked length underflows", termIndex)
				}
				unpacked -= chunkSize
				chunkRange.Start++
			}
		}
		if chunkRange.Start == chunkRange.End {
			return nil, fmt.Errorf("xet CAS: term %d was fully pruned", termIndex)
		}
		if cumulative+uint64(unpacked) > end {
			for chunkRange.End > chunkRange.Start {
				chunkSize := layout.Chunks[chunkRange.End-1].UncompressedLength
				if chunkSize > unpacked || cumulative+uint64(unpacked-chunkSize) < end {
					break
				}
				unpacked -= chunkSize
				chunkRange.End--
			}
		}
		if unpacked == 0 || chunkRange.Start == chunkRange.End {
			return nil, fmt.Errorf("xet CAS: term %d has no selected chunks", termIndex)
		}
		firstChunk := layout.Chunks[chunkRange.Start]
		lastChunk := layout.Chunks[chunkRange.End-1]
		serializedEnd := uint64(lastChunk.SerializedOffset) + uint64(lastChunk.SerializedLength)
		if serializedEnd == 0 || serializedEnd > uint64(layout.NetworkBytes) {
			return nil, fmt.Errorf("xet CAS: term %d serialized range exceeds xorb content", termIndex)
		}
		descriptor := XorbRangeDescriptor{
			Chunks: chunkRange,
			Bytes: HTTPRange{
				Start: uint64(firstChunk.SerializedOffset),
				End:   serializedEnd - 1,
			},
		}
		plan.Terms = append(plan.Terms, ReconstructionTerm{
			Hash: term.XorbHash, UnpackedLength: unpacked, Range: chunkRange,
		})
		plan.Xorbs[term.XorbHash] = append(plan.Xorbs[term.XorbHash], descriptor)
		cumulative += uint64(unpacked)
		termIndex++
	}
	plan.OffsetIntoFirstRange = start - firstChunkByteStart
	for hash, ranges := range plan.Xorbs {
		sort.Slice(ranges, func(i, j int) bool { return ranges[i].Chunks.Start < ranges[j].Chunks.Start })
		merged := ranges[:0]
		for _, value := range ranges {
			if len(merged) == 0 || value.Chunks.Start > merged[len(merged)-1].Chunks.End {
				merged = append(merged, value)
				continue
			}
			last := &merged[len(merged)-1]
			last.Chunks.End = max(last.Chunks.End, value.Chunks.End)
			last.Bytes.End = max(last.Bytes.End, value.Bytes.End)
		}
		plan.Xorbs[hash] = merged
	}
	return plan, nil
}

func validateLayoutRange(layout *xorb.Ingested, value ChunkRange) error {
	if err := value.Validate(); err != nil {
		return err
	}
	if value.End > uint32(len(layout.Chunks)) {
		return errors.New("chunk range exceeds xorb layout")
	}
	return nil
}

// PlanFileChunkHashes builds the v2 sparse-upload dirty windows, compact
// Merkle subtrees for stable gaps, and verification hashes for stable terms.
func PlanFileChunkHashes(
	file shard.RegisteredFile,
	dirty []FileRange,
	lookup XorbLayoutLookup,
) (*FileChunkHashesResponse, error) {
	return PlanFileChunkHashesContext(context.Background(), file, dirty, lookup)
}

// PlanFileChunkHashesContext is PlanFileChunkHashes with cancellation and
// bounded-memory gap accumulation for server-side sparse planning.
func PlanFileChunkHashesContext(
	ctx context.Context,
	file shard.RegisteredFile,
	dirty []FileRange,
	lookup XorbLayoutLookup,
) (*FileChunkHashesResponse, error) {
	if ctx == nil {
		return nil, errors.New("xet CAS: nil file chunk hash context")
	}
	if lookup == nil {
		return nil, errors.New("xet CAS: nil xorb layout lookup")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if len(dirty) == 0 {
		return nil, errors.New("xet CAS: file chunk hash query requires a dirty range")
	}
	for i, value := range dirty {
		if err := value.Validate(); err != nil {
			return nil, fmt.Errorf("xet CAS: dirty range %d: %w", i, err)
		}
		if i > 0 && dirty[i-1].End > value.Start {
			return nil, fmt.Errorf("xet CAS: dirty range %d overlaps or is unsorted", i)
		}
	}
	normalized := make([]FileRange, 0, len(dirty))
	for _, value := range dirty {
		value.End = min(value.End, file.Size)
		if value.Start < value.End && value.Start < file.Size {
			normalized = append(normalized, value)
		}
	}
	if len(normalized) == 0 {
		return nil, ErrRangeNotSatisfiable
	}

	layouts := make(map[xethash.Hash]*xorb.Ingested)
	resolve := func(hash xethash.Hash) (*xorb.Ingested, error) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if value, ok := layouts[hash]; ok {
			return value, nil
		}
		value, found, err := lookup(hash)
		if err != nil {
			return nil, fmt.Errorf("xet CAS: resolve xorb layout %s: %w", hash, err)
		}
		if !found || value == nil || value.Hash != hash {
			return nil, fmt.Errorf("xet CAS: xorb layout %s not found or mismatched", hash)
		}
		layouts[hash] = value
		return value, nil
	}

	builder := newChunkWindowBuilder(normalized)
	var total, totalChunks uint64
	for i, term := range file.File.Terms {
		if i&1023 == 0 {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
		}
		layout, err := resolve(term.XorbHash)
		if err != nil {
			return nil, err
		}
		rangeValue := ChunkRange{Start: term.Start, End: term.End}
		if err := validateLayoutRange(layout, rangeValue); err != nil {
			return nil, fmt.Errorf("xet CAS: term %d: %w", i, err)
		}
		for _, chunk := range layout.Chunks[term.Start:term.End] {
			if totalChunks&1023 == 0 {
				if err := ctx.Err(); err != nil {
					return nil, err
				}
			}
			node := xethash.Node{Hash: chunk.Hash, Size: uint64(chunk.UncompressedLength)}
			if math.MaxUint64-total < node.Size {
				return nil, errors.New("xet CAS: file chunk sizes overflow")
			}
			if totalChunks == math.MaxUint64 {
				return nil, errors.New("xet CAS: file chunk count overflows")
			}
			total += node.Size
			totalChunks++
			builder.process(node, total)
		}
	}
	if total != file.Size {
		return nil, fmt.Errorf("xet CAS: chunk sizes total %d, expected file size %d", total, file.Size)
	}
	windows, hashRanges, err := builder.finish()
	if err != nil {
		return nil, err
	}
	if len(windows) == 0 {
		return nil, ErrRangeNotSatisfiable
	}

	response := &FileChunkHashesResponse{
		TotalChunks: totalChunks, FileSize: file.Size,
		Windows: make([]ChunkWindow, len(windows)), HashRanges: hashRanges,
	}
	for i, value := range windows {
		response.Windows[i].DirtyByteRange = [2]uint64{value.Start, value.End}
	}
	hasVerification, hasMissingVerification := false, false
	for _, term := range file.File.Terms {
		if term.Verification.IsZero() {
			hasMissingVerification = true
		} else {
			hasVerification = true
		}
	}
	if hasVerification && hasMissingVerification {
		return nil, errors.New("xet CAS: file has partially populated term verification")
	}
	if hasVerification {
		var termStart uint64
		windowIndex := 0
		for _, term := range file.File.Terms {
			termEnd := termStart + uint64(term.UnpackedBytes)
			for windowIndex < len(windows) && windows[windowIndex].End <= termStart {
				windowIndex++
			}
			overlaps := windowIndex < len(windows) && windows[windowIndex].Start < termEnd
			if !overlaps {
				response.GapVerification = append(response.GapVerification, term.Verification)
			}
			termStart = termEnd
		}
	}
	if err := response.Validate(); err != nil {
		return nil, err
	}
	return response, nil
}

type subtreeAccumulator struct {
	atStart bool
	tree    *xethash.MerkleHashSubtree
	pending []xethash.Node
}

func newSubtreeAccumulator(atStart bool) subtreeAccumulator {
	return subtreeAccumulator{atStart: atStart, pending: make([]xethash.Node, 0, xorb.MaxChunks)}
}

func (a *subtreeAccumulator) add(node xethash.Node) error {
	if len(a.pending) == xorb.MaxChunks {
		if err := a.flush(false); err != nil {
			return err
		}
	}
	a.pending = append(a.pending, node)
	return nil
}

func (a *subtreeAccumulator) flush(atEnd bool) error {
	if len(a.pending) == 0 {
		return nil
	}
	part := xethash.NewSubtree(a.tree == nil && a.atStart, a.pending, atEnd)
	a.pending = a.pending[:0]
	if a.tree == nil {
		a.tree = part
		return nil
	}
	merged, err := xethash.MergeSubtrees(a.tree, part)
	if err != nil {
		return err
	}
	a.tree = merged
	return nil
}

func (a *subtreeAccumulator) finish(atEnd bool) (*xethash.MerkleHashSubtree, error) {
	if err := a.flush(atEnd); err != nil {
		return nil, err
	}
	return a.tree, nil
}

type chunkWindowBuilder struct {
	dirty        []FileRange
	dirtyIndex   int
	inDirty      bool
	cursor       uint64
	gap          subtreeAccumulator
	windows      []FileRange
	hashRanges   []*xethash.MerkleHashSubtree
	tailPrevious uint64
	hasTail      bool
	err          error
}

func newChunkWindowBuilder(dirty []FileRange) *chunkWindowBuilder {
	return &chunkWindowBuilder{dirty: dirty, gap: newSubtreeAccumulator(true)}
}

func (b *chunkWindowBuilder) process(chunk xethash.Node, byteEnd uint64) {
	byteStart := b.cursor
	overlaps := b.overlaps(b.dirtyIndex, byteStart, byteEnd)
	if !b.inDirty {
		if overlaps {
			b.open(byteEnd)
			b.inDirty = true
			b.hasTail = false
		} else {
			if b.err == nil {
				b.err = b.gap.add(chunk)
			}
		}
	} else if overlaps || b.overlaps(b.dirtyIndex+1, byteStart, byteEnd) {
		if !overlaps {
			b.dirtyIndex++
		}
		b.extend(byteEnd)
		b.mergeAhead(byteEnd)
		b.hasTail = false
	} else {
		b.extend(byteEnd)
		stable := b.hasTail && chunker.IsStableSize(int(b.tailPrevious)) && chunker.IsStableSize(int(chunk.Size))
		b.tailPrevious = chunk.Size
		b.hasTail = true
		if stable {
			b.dirtyIndex++
			b.inDirty = false
			b.hasTail = false
		}
	}
	b.cursor = byteEnd
}

func (b *chunkWindowBuilder) open(byteEnd uint64) {
	b.appendGap(false)
	b.gap = newSubtreeAccumulator(false)
	b.windows = append(b.windows, FileRange{Start: b.cursor, End: byteEnd})
	b.mergeAhead(byteEnd)
}

func (b *chunkWindowBuilder) extend(byteEnd uint64) { b.windows[len(b.windows)-1].End = byteEnd }

func (b *chunkWindowBuilder) overlaps(index int, start, end uint64) bool {
	return index < len(b.dirty) && end > b.dirty[index].Start && start < b.dirty[index].End
}

func (b *chunkWindowBuilder) mergeAhead(byteEnd uint64) {
	for b.dirtyIndex+1 < len(b.dirty) && byteEnd > b.dirty[b.dirtyIndex+1].Start {
		b.dirtyIndex++
	}
}

func (b *chunkWindowBuilder) appendGap(atEnd bool) {
	if b.err != nil {
		return
	}
	value, err := b.gap.finish(atEnd)
	if err != nil {
		b.err = fmt.Errorf("xet CAS: build compact gap subtree: %w", err)
		return
	}
	if value.IsEmpty() {
		value = nil
	}
	b.hashRanges = append(b.hashRanges, value)
}

func (b *chunkWindowBuilder) finish() ([]FileRange, []*xethash.MerkleHashSubtree, error) {
	b.appendGap(true)
	return b.windows, b.hashRanges, b.err
}
