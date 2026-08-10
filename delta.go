package xet

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"sort"
	"time"

	"github.com/jmwoliver/xet-go/shard"
	"github.com/jmwoliver/xet-go/xetcas"
	"github.com/jmwoliver/xet-go/xethash"
)

// DeltaEdit replaces Original, expressed in the original file's coordinates,
// with exactly NewLength bytes from Reader. Empty Original is an insertion;
// NewLength zero is a deletion and permits a nil Reader.
type DeltaEdit struct {
	Original  xetcas.FileRange
	Reader    io.Reader
	NewLength uint64
}

type fileChunkHashProtocol interface {
	QueryFileChunkHashes(context.Context, xethash.Hash, []xetcas.FileRange) (*xetcas.FileChunkHashesResponse, error)
}

type deltaUploadedWindow struct {
	start, end uint64
	file       uploadedFile
	terms      []shard.Term
}

// UploadDelta uploads an edited version of original while retaining unchanged
// reconstruction terms. It uses the v2 file-chunk-hashes API and exact compact
// Merkle-subtree merging. As in official xet-core range upload, the composed
// shard has no SHA-256 extension because calculating it would require reading
// the entire unchanged file.
func (c *Client) UploadDelta(ctx context.Context, original FileInfo, edits []DeltaEdit) (UploadResult, error) {
	if ctx == nil {
		return UploadResult{}, errors.New("xet: nil delta-upload context")
	}
	if err := validateDeltaEdits(original.Size, edits); err != nil {
		return UploadResult{}, err
	}
	totalSize, err := deltaResultSize(original.Size, edits)
	if err != nil {
		return UploadResult{}, err
	}
	if len(edits) == 0 {
		now := time.Now()
		return UploadResult{File: original, Report: UploadReport{StartedAt: now, CompletedAt: now}}, nil
	}
	if original.Size == 0 {
		readers := make([]io.Reader, len(edits))
		for i := range edits {
			readers[i] = &exactLengthReader{source: edits[i].Reader, remaining: edits[i].NewLength}
		}
		return c.Upload(ctx, io.MultiReader(readers...))
	}
	deltaProtocol, ok := c.protocol.(fileChunkHashProtocol)
	if !ok {
		return UploadResult{}, errors.New("xet: CAS protocol does not support v2 delta upload")
	}
	reconstruction, err := c.protocol.QueryReconstruction(ctx, original.Hash, nil)
	if err != nil {
		return UploadResult{}, err
	}
	if err := reconstruction.Validate(); err != nil {
		return UploadResult{}, err
	}
	segmentStarts, err := reconstructionSegmentStarts(reconstruction.Terms, original.Size)
	if err != nil {
		return UploadResult{}, err
	}
	dirty := snapDeltaRanges(edits, segmentStarts, original.Size)
	response, err := deltaProtocol.QueryFileChunkHashes(ctx, original.Hash, dirty)
	if err != nil {
		return UploadResult{}, err
	}
	if response.FileSize != original.Size {
		return UploadResult{}, fmt.Errorf("xet: delta response file size %d, expected %d", response.FileSize, original.Size)
	}
	if len(response.Windows) == 0 {
		return UploadResult{}, errors.New("xet: delta response has no dirty windows")
	}

	batch, err := c.NewUploadBatch(ctx)
	if err != nil {
		return UploadResult{}, err
	}
	abort := func(cause error) (UploadResult, error) {
		batch.Abort(cause)
		return UploadResult{}, cause
	}
	windows := make([]deltaUploadedWindow, 0, len(response.Windows))
	editIndex := 0
	for windowIndex, window := range response.Windows {
		start, end := window.DirtyByteRange[0], window.DirtyByteRange[1]
		if !isSegmentBoundary(segmentStarts, start) || !isSegmentBoundary(segmentStarts, end) {
			return abort(fmt.Errorf("xet: delta window %d [%d,%d) is not reconstruction-segment aligned", windowIndex, start, end))
		}
		editsEnd := editIndex
		for editsEnd < len(edits) && deltaEditBelongsToWindow(edits[editsEnd], end, original.Size) {
			editsEnd++
		}
		if editsEnd == editIndex {
			return abort(fmt.Errorf("xet: delta window %d contains no requested edit", windowIndex))
		}
		windowEdits := edits[editIndex:editsEnd]
		middleSize, sizeErr := editedWindowSize(start, end, windowEdits)
		if sizeErr != nil {
			return abort(sizeErr)
		}
		reader, producer := c.deltaWindowReader(ctx, original.Hash, start, end, windowEdits)
		info, addErr := batch.Add(reader)
		if addErr != nil {
			_ = reader.CloseWithError(addErr)
		}
		producerErr := <-producer
		_ = reader.Close()
		if addErr != nil {
			return abort(addErr)
		}
		if producerErr != nil {
			return abort(producerErr)
		}
		if info.Size != middleSize {
			return abort(fmt.Errorf("xet: delta window %d produced %d bytes, expected %d", windowIndex, info.Size, middleSize))
		}
		detached, detachErr := batch.detachLastFile()
		if detachErr != nil {
			return abort(detachErr)
		}
		windows = append(windows, deltaUploadedWindow{start: start, end: end, file: detached})
		editIndex = editsEnd
	}
	if editIndex != len(edits) {
		return abort(fmt.Errorf("xet: %d delta edits were not assigned to a server window", len(edits)-editIndex))
	}
	batch.mu.Lock()
	flushErr := batch.flushCurrent()
	batch.mu.Unlock()
	if flushErr != nil {
		return abort(flushErr)
	}
	for i := range windows {
		windowShard, buildErr := buildShardFile(windows[i].file)
		if buildErr != nil {
			return abort(buildErr)
		}
		windows[i].terms = windowShard.Terms
	}

	root, err := mergeDeltaHash(response.HashRanges, windows)
	if err != nil {
		return abort(err)
	}
	fileHash := xethash.Zero
	if totalSize != 0 {
		fileHash = xethash.Protect(root, xethash.Zero)
	}
	terms, err := composeDeltaTerms(reconstruction.Terms, segmentStarts, windows, response.GapVerification)
	if err != nil {
		return abort(err)
	}
	batch.mu.Lock()
	batch.composed = append(batch.composed, shard.File{Hash: fileHash, Terms: terms})
	batch.report.Files = 1
	batch.mu.Unlock()
	report, err := batch.Finalize()
	if err != nil {
		return UploadResult{}, err
	}
	return UploadResult{File: FileInfo{Hash: fileHash, Size: totalSize}, Report: report}, nil
}

func validateDeltaEdits(originalSize uint64, edits []DeltaEdit) error {
	var previousEnd uint64
	for i, edit := range edits {
		if edit.Original.End < edit.Original.Start || edit.Original.End > originalSize {
			return fmt.Errorf("xet: invalid delta edit %d range [%d,%d)", i, edit.Original.Start, edit.Original.End)
		}
		if i > 0 && edit.Original.Start < previousEnd {
			return fmt.Errorf("xet: delta edit %d overlaps or is out of order", i)
		}
		if edit.NewLength != 0 && edit.Reader == nil {
			return fmt.Errorf("xet: delta edit %d has nil reader", i)
		}
		previousEnd = edit.Original.End
	}
	return nil
}

func deltaResultSize(original uint64, edits []DeltaEdit) (uint64, error) {
	result := original
	for i, edit := range edits {
		removed := edit.Original.End - edit.Original.Start
		if result < removed {
			return 0, fmt.Errorf("xet: delta edit %d size underflow", i)
		}
		result -= removed
		if math.MaxUint64-result < edit.NewLength {
			return 0, fmt.Errorf("xet: delta edit %d size overflow", i)
		}
		result += edit.NewLength
	}
	return result, nil
}

func reconstructionSegmentStarts(terms []xetcas.ReconstructionTerm, expected uint64) ([]uint64, error) {
	starts := make([]uint64, len(terms)+1)
	for i, term := range terms {
		if math.MaxUint64-starts[i] < uint64(term.UnpackedLength) {
			return nil, errors.New("xet: reconstruction segment offsets overflow")
		}
		starts[i+1] = starts[i] + uint64(term.UnpackedLength)
	}
	if starts[len(starts)-1] != expected {
		return nil, fmt.Errorf("xet: reconstruction size %d, expected %d", starts[len(starts)-1], expected)
	}
	return starts, nil
}

func snapDeltaRanges(edits []DeltaEdit, starts []uint64, originalSize uint64) []xetcas.FileRange {
	ranges := make([]xetcas.FileRange, 0, len(edits))
	for _, edit := range edits {
		start, end := edit.Original.Start, edit.Original.End
		if start == end {
			position := start
			if position == originalSize {
				position--
			}
			index := sort.Search(len(starts)-1, func(i int) bool { return starts[i+1] > position })
			start, end = starts[index], starts[index+1]
		} else {
			first := sort.Search(len(starts)-1, func(i int) bool { return starts[i+1] > start })
			last := sort.Search(len(starts)-1, func(i int) bool { return starts[i+1] >= end })
			start, end = starts[first], starts[last+1]
		}
		if len(ranges) != 0 && start <= ranges[len(ranges)-1].End {
			ranges[len(ranges)-1].End = max(ranges[len(ranges)-1].End, end)
		} else {
			ranges = append(ranges, xetcas.FileRange{Start: start, End: end})
		}
	}
	return ranges
}

func isSegmentBoundary(starts []uint64, value uint64) bool {
	index := sort.Search(len(starts), func(i int) bool { return starts[i] >= value })
	return index < len(starts) && starts[index] == value
}

func deltaEditBelongsToWindow(edit DeltaEdit, end, originalSize uint64) bool {
	if edit.Original.Start == edit.Original.End {
		return edit.Original.Start < end || edit.Original.Start == end && end == originalSize
	}
	return edit.Original.End <= end
}

func editedWindowSize(start, end uint64, edits []DeltaEdit) (uint64, error) {
	result := end - start
	for _, edit := range edits {
		removed := edit.Original.End - edit.Original.Start
		if result < removed {
			return 0, errors.New("xet: edited window size underflow")
		}
		result -= removed
		if math.MaxUint64-result < edit.NewLength {
			return 0, errors.New("xet: edited window size overflow")
		}
		result += edit.NewLength
	}
	return result, nil
}

func (c *Client) deltaWindowReader(
	ctx context.Context,
	fileID xethash.Hash,
	start, end uint64,
	edits []DeltaEdit,
) (*io.PipeReader, <-chan error) {
	reader, writer := io.Pipe()
	result := make(chan error, 1)
	go func() {
		cursor := start
		var err error
		for i := range edits {
			edit := &edits[i]
			if edit.Original.Start < start || edit.Original.End > end || edit.Original.Start < cursor {
				err = errors.New("xet: delta edit lies outside its server window")
				break
			}
			if cursor < edit.Original.Start {
				_, err = c.DownloadRange(ctx, fileID,
					xetcas.FileRange{Start: cursor, End: edit.Original.Start}, writer)
				if err != nil {
					break
				}
			}
			if edit.NewLength != 0 {
				err = copyExactly(writer, edit.Reader, edit.NewLength)
				if err != nil {
					break
				}
			}
			cursor = edit.Original.End
		}
		if err == nil && cursor < end {
			_, err = c.DownloadRange(ctx, fileID, xetcas.FileRange{Start: cursor, End: end}, writer)
		}
		if err != nil {
			_ = writer.CloseWithError(err)
		} else {
			err = writer.Close()
		}
		result <- err
		close(result)
	}()
	return reader, result
}

func copyExactly(dst io.Writer, source io.Reader, count uint64) error {
	if source == nil {
		return errors.New("xet: nil delta source")
	}
	remaining := count
	for remaining != 0 {
		step := remaining
		if step > math.MaxInt64 {
			step = math.MaxInt64
		}
		written, err := io.CopyN(dst, source, int64(step))
		remaining -= uint64(written)
		if err != nil {
			return fmt.Errorf("xet: read delta source: %w", err)
		}
	}
	return nil
}

func (b *UploadBatch) detachLastFile() (uploadedFile, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(b.files) == 0 {
		return uploadedFile{}, errors.New("xet: no uploaded file to detach")
	}
	last := b.files[len(b.files)-1]
	b.files = b.files[:len(b.files)-1]
	b.report.Files = len(b.files)
	return last, nil
}

func mergeDeltaHash(hashRanges []*xethash.MerkleHashSubtree, windows []deltaUploadedWindow) (xethash.Hash, error) {
	if len(hashRanges) != len(windows)+1 {
		return xethash.Hash{}, errors.New("xet: delta hash-range/window count mismatch")
	}
	sequence := make([]*xethash.MerkleHashSubtree, 0, len(windows)*2+1)
	for i, window := range windows {
		if hashRanges[i] != nil {
			sequence = append(sequence, hashRanges[i])
		}
		atStart := i == 0 && hashRanges[0] == nil
		atEnd := i == len(windows)-1 && hashRanges[len(hashRanges)-1] == nil
		sequence = append(sequence, xethash.NewSubtree(atStart, window.file.chunkNodes, atEnd))
	}
	if trailing := hashRanges[len(hashRanges)-1]; trailing != nil {
		sequence = append(sequence, trailing)
	}
	merged, err := xethash.MergeSubtrees(sequence...)
	if err != nil {
		return xethash.Hash{}, err
	}
	root, ok := merged.FinalHash()
	if !ok {
		return xethash.Hash{}, errors.New("xet: merged delta subtree is not fully closed")
	}
	return root, nil
}

func composeDeltaTerms(
	original []xetcas.ReconstructionTerm,
	starts []uint64,
	windows []deltaUploadedWindow,
	verification []xethash.Hash,
) ([]shard.Term, error) {
	terms := make([]shard.Term, 0, len(original)+len(windows))
	segment, verify := 0, 0
	appendOriginal := func() error {
		if verify >= len(verification) {
			return errors.New("xet: delta response has too few gap-verification hashes")
		}
		value := original[segment]
		terms = append(terms, shard.Term{
			XorbHash: value.Hash, UnpackedBytes: value.UnpackedLength,
			Start: value.Range.Start, End: value.Range.End, Verification: verification[verify],
		})
		segment++
		verify++
		return nil
	}
	for _, window := range windows {
		for segment < len(original) && starts[segment] < window.start {
			if starts[segment+1] > window.start {
				return nil, errors.New("xet: delta window starts inside a reconstruction segment")
			}
			if err := appendOriginal(); err != nil {
				return nil, err
			}
		}
		for segment < len(original) && starts[segment] < window.end {
			if starts[segment+1] > window.end {
				return nil, errors.New("xet: delta window ends inside a reconstruction segment")
			}
			segment++
		}
		terms = append(terms, window.terms...)
	}
	for segment < len(original) {
		if err := appendOriginal(); err != nil {
			return nil, err
		}
	}
	if verify != len(verification) {
		return nil, errors.New("xet: delta response has extra gap-verification hashes")
	}
	return terms, nil
}

type exactLengthReader struct {
	source    io.Reader
	remaining uint64
}

func (r *exactLengthReader) Read(buffer []byte) (int, error) {
	if r.remaining == 0 {
		return 0, io.EOF
	}
	if uint64(len(buffer)) > r.remaining {
		buffer = buffer[:r.remaining]
	}
	n, err := r.source.Read(buffer)
	r.remaining -= uint64(n)
	if errors.Is(err, io.EOF) && r.remaining != 0 {
		err = io.ErrUnexpectedEOF
	}
	return n, err
}
