package xetcas

import (
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
	if lookup == nil {
		return nil, errors.New("xet CAS: nil xorb layout lookup")
	}
	var recipeSize uint64
	for _, term := range file.File.Terms {
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
	if lookup == nil {
		return nil, errors.New("xet CAS: nil xorb layout lookup")
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

	chunks := make([]xethash.Node, 0)
	for i, term := range file.File.Terms {
		layout, err := resolve(term.XorbHash)
		if err != nil {
			return nil, err
		}
		rangeValue := ChunkRange{Start: term.Start, End: term.End}
		if err := validateLayoutRange(layout, rangeValue); err != nil {
			return nil, fmt.Errorf("xet CAS: term %d: %w", i, err)
		}
		for _, chunk := range layout.Chunks[term.Start:term.End] {
			chunks = append(chunks, xethash.Node{Hash: chunk.Hash, Size: uint64(chunk.UncompressedLength)})
		}
	}
	builder := newChunkWindowBuilder(normalized)
	var total uint64
	for _, chunk := range chunks {
		if math.MaxUint64-total < chunk.Size {
			return nil, errors.New("xet CAS: file chunk sizes overflow")
		}
		total += chunk.Size
		builder.process(chunk, total)
	}
	if total != file.Size {
		return nil, fmt.Errorf("xet CAS: chunk sizes total %d, expected file size %d", total, file.Size)
	}
	windows, hashRanges := builder.finish()
	if len(windows) == 0 {
		return nil, ErrRangeNotSatisfiable
	}

	response := &FileChunkHashesResponse{
		TotalChunks: uint64(len(chunks)), FileSize: file.Size,
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

type chunkWindowBuilder struct {
	dirty        []FileRange
	dirtyIndex   int
	inDirty      bool
	gapIsFirst   bool
	cursor       uint64
	gapChunks    []xethash.Node
	windows      []FileRange
	hashRanges   []*xethash.MerkleHashSubtree
	tailPrevious uint64
	hasTail      bool
}

func newChunkWindowBuilder(dirty []FileRange) *chunkWindowBuilder {
	return &chunkWindowBuilder{dirty: dirty, gapIsFirst: true}
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
			b.gapChunks = append(b.gapChunks, chunk)
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
			b.gapIsFirst = false
			b.inDirty = false
			b.hasTail = false
		}
	}
	b.cursor = byteEnd
}

func (b *chunkWindowBuilder) open(byteEnd uint64) {
	b.appendGap(false)
	b.gapChunks = b.gapChunks[:0]
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
	value := xethash.NewSubtree(b.gapIsFirst, b.gapChunks, atEnd)
	if value.IsEmpty() {
		value = nil
	}
	b.hashRanges = append(b.hashRanges, value)
}

func (b *chunkWindowBuilder) finish() ([]FileRange, []*xethash.MerkleHashSubtree) {
	b.appendGap(true)
	return b.windows, b.hashRanges
}
