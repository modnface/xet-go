package xet

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"hash"
	"io"
	"sort"

	"github.com/jacobwoliver/xet-go/chunker"
	"github.com/jacobwoliver/xet-go/xetcas"
	"github.com/jacobwoliver/xet-go/xethash"
	"github.com/jacobwoliver/xet-go/xorb"
)

// DownloadReport describes verified logical and physical work. WholeFileHash
// is true only for a complete download whose chunk tree matched the requested
// file ID.
type DownloadReport struct {
	LogicalBytes   uint64
	FetchedBytes   uint64
	FetchedRanges  int
	CacheHitBytes  uint64
	CacheHitRanges int
	WholeFileHash  bool
	SHA256Verified bool
}

// Download reconstructs a complete file to dst and verifies its Xet identity.
// A nonzero FileInfo.Size and nonzero SHA256 are also enforced.
func (c *Client) Download(ctx context.Context, file FileInfo, dst io.Writer) (DownloadReport, error) {
	if dst == nil {
		return DownloadReport{}, errors.New("xet: nil download writer")
	}
	if file.Size > c.options.MaxReconstructionWindow {
		return c.downloadWindowed(ctx, file, dst)
	}
	return c.download(ctx, file, nil, dst)
}

// DownloadRange reconstructs exactly logical [Start,End) and writes only those
// bytes. The enclosing file ID cannot be recomputed from a partial response,
// but every xorb and declared term length is validated.
func (c *Client) DownloadRange(
	ctx context.Context,
	fileID xethash.Hash,
	requested xetcas.FileRange,
	dst io.Writer,
) (DownloadReport, error) {
	if dst == nil {
		return DownloadReport{}, errors.New("xet: nil download writer")
	}
	if err := requested.Validate(); err != nil {
		return DownloadReport{}, err
	}
	return c.download(ctx, FileInfo{Hash: fileID}, &requested, dst)
}

func (c *Client) download(
	ctx context.Context,
	file FileInfo,
	requested *xetcas.FileRange,
	dst io.Writer,
) (DownloadReport, error) {
	return c.downloadWithProgressBase(ctx, file, requested, dst, 0)
}

func (c *Client) downloadWithProgressBase(
	ctx context.Context,
	file FileInfo,
	requested *xetcas.FileRange,
	dst io.Writer,
	progressBase uint64,
) (DownloadReport, error) {
	if ctx == nil {
		return DownloadReport{}, errors.New("xet: nil download context")
	}
	for signedAttempt := 0; signedAttempt < 2; signedAttempt++ {
		reconstruction, err := c.protocol.QueryReconstruction(ctx, file.Hash, requested)
		if err != nil {
			return DownloadReport{}, err
		}
		tracked := &countingWriter{dst: dst}
		report, err := c.executeReconstruction(ctx, file, requested, reconstruction, tracked, progressBase)
		if errors.Is(err, xetcas.ErrSignedURLExpired) && signedAttempt == 0 && tracked.written == 0 {
			continue
		}
		return report, err
	}
	return DownloadReport{}, xetcas.ErrSignedURLExpired
}

type segmentKey struct {
	hash       xethash.Hash
	chunkStart uint32
	chunkEnd   uint32
}

type downloadDescriptor struct {
	hash xethash.Hash
	desc xetcas.XorbRangeDescriptor
	job  *downloadJob
}

func (d *downloadDescriptor) key() segmentKey {
	return segmentKey{hash: d.hash, chunkStart: d.desc.Chunks.Start, chunkEnd: d.desc.Chunks.End}
}

type downloadJob struct {
	url         string
	ranges      []xetcas.HTTPRange
	descriptors []*downloadDescriptor
	firstUse    int
}

type decodedSegment struct {
	chunks  []xorb.Chunk
	rawSize uint64
	lastUse int
}

type downloadJobResult struct {
	segments    map[segmentKey]decodedSegment
	fetched     uint64
	fetchRanges int
	cacheHit    uint64
	cacheRanges int
	err         error
}

func (c *Client) executeReconstruction(
	ctx context.Context,
	file FileInfo,
	requested *xetcas.FileRange,
	reconstruction *xetcas.Reconstruction,
	dst io.Writer,
	progressBase uint64,
) (DownloadReport, error) {
	if err := reconstruction.Validate(); err != nil {
		return DownloadReport{}, err
	}
	jobs, termDescriptors, err := planDownloads(reconstruction)
	if err != nil {
		return DownloadReport{}, err
	}
	executionContext, cancel := context.WithCancel(ctx)
	defer cancel()
	channels := make([]chan downloadJobResult, len(jobs))
	for i := range channels {
		channels[i] = make(chan downloadJobResult, 1)
	}
	startJob := func(index int) {
		go func() {
			channels[index] <- c.fetchJob(executionContext, jobs[index])
		}()
	}
	initial := min(c.options.DownloadConcurrency, len(jobs))
	for i := 0; i < initial; i++ {
		startJob(i)
	}

	segments := make(map[segmentKey]decodedSegment)
	lastUses := make(map[segmentKey]int)
	for termIndex, descriptor := range termDescriptors {
		lastUses[descriptor.key()] = termIndex
	}
	var retained uint64
	var report DownloadReport
	logicalHash := sha256.New()
	nodes := make([]xethash.Node, 0, len(reconstruction.Terms)*2)
	writer := &croppingWriter{dst: dst}
	if requested != nil {
		writer.skip = reconstruction.OffsetIntoFirstRange
		writer.remaining = requested.Len()
		writer.limited = true
	} else if reconstruction.OffsetIntoFirstRange != 0 {
		return DownloadReport{}, errors.New("xet: whole-file reconstruction has a nonzero initial offset")
	}

	nextTerm := 0
	for jobIndex := range jobs {
		result := <-channels[jobIndex]
		if result.err != nil {
			cancel()
			return report, result.err
		}
		report.FetchedBytes += result.fetched
		report.FetchedRanges += result.fetchRanges
		report.CacheHitBytes += result.cacheHit
		report.CacheHitRanges += result.cacheRanges
		for key, segment := range result.segments {
			lastUse, needed := lastUses[key]
			if !needed {
				continue
			}
			segment.lastUse = lastUse
			segments[key] = segment
			retained += segment.rawSize
		}
		if retained > c.options.MaxDownloadMemory {
			cancel()
			return report, fmt.Errorf("xet: decoded download working set %d exceeds limit %d", retained, c.options.MaxDownloadMemory)
		}
		if next := jobIndex + initial; next < len(jobs) {
			startJob(next)
		}

		for nextTerm < len(reconstruction.Terms) {
			descriptor := termDescriptors[nextTerm]
			key := descriptor.key()
			segment, ok := segments[key]
			if !ok {
				break
			}
			term := reconstruction.Terms[nextTerm]
			start := term.Range.Start - descriptor.desc.Chunks.Start
			end := term.Range.End - descriptor.desc.Chunks.Start
			if end > uint32(len(segment.chunks)) {
				cancel()
				return report, fmt.Errorf("xet: reconstruction term %d exceeds decoded segment", nextTerm)
			}
			var termBytes uint64
			for _, chunk := range segment.chunks[start:end] {
				termBytes += uint64(len(chunk.Data))
				nodes = append(nodes, xethash.Node{Hash: chunk.Hash, Size: uint64(len(chunk.Data))})
				_, _ = logicalHash.Write(chunk.Data)
				if _, err := writer.Write(chunk.Data); err != nil {
					cancel()
					return report, err
				}
			}
			if termBytes != uint64(term.UnpackedLength) {
				cancel()
				return report, fmt.Errorf("xet: reconstruction term %d decoded %d bytes, want %d", nextTerm, termBytes, term.UnpackedLength)
			}
			if segment.lastUse == nextTerm {
				retained -= segment.rawSize
				delete(segments, key)
			}
			nextTerm++
			if c.options.Progress != nil {
				c.options.Progress(Progress{
					Phase: ProgressDownloading, File: file.Hash,
					Completed: progressBase + writer.written, Total: file.Size,
				})
			}
		}
	}
	if nextTerm != len(reconstruction.Terms) {
		return report, fmt.Errorf("xet: reconstruction stopped at term %d of %d", nextTerm, len(reconstruction.Terms))
	}
	if writer.limited && writer.remaining != 0 {
		return report, fmt.Errorf("xet: range reconstruction wrote %d bytes, want %d", writer.written, requested.Len())
	}
	report.LogicalBytes = writer.written
	if requested == nil {
		if root := xethash.File(nodes); root != file.Hash {
			return report, fmt.Errorf("xet: reconstructed file hash %s, want %s", root, file.Hash)
		}
		report.WholeFileHash = true
		if file.Size != 0 && writer.written != file.Size {
			return report, fmt.Errorf("xet: reconstructed %d bytes, expected %d", writer.written, file.Size)
		}
		var computedSHA [sha256.Size]byte
		copy(computedSHA[:], logicalHash.Sum(nil))
		if file.SHA256 != ([sha256.Size]byte{}) {
			if computedSHA != file.SHA256 {
				return report, errors.New("xet: reconstructed SHA-256 mismatch")
			}
			report.SHA256Verified = true
		}
	}
	return report, nil
}

func (c *Client) downloadWindowed(ctx context.Context, file FileInfo, dst io.Writer) (DownloadReport, error) {
	verifier, err := newVerifyingWriter(ctx, dst)
	if err != nil {
		return DownloadReport{}, err
	}
	var report DownloadReport
	for start := uint64(0); start < file.Size; {
		end := start + min(c.options.MaxReconstructionWindow, file.Size-start)
		requested := xetcas.FileRange{Start: start, End: end}
		partial, err := c.downloadWithProgressBase(ctx, FileInfo{Hash: file.Hash}, &requested, verifier, start)
		report.LogicalBytes += partial.LogicalBytes
		report.FetchedBytes += partial.FetchedBytes
		report.FetchedRanges += partial.FetchedRanges
		report.CacheHitBytes += partial.CacheHitBytes
		report.CacheHitRanges += partial.CacheHitRanges
		if err != nil {
			return report, err
		}
		start = end
	}
	if err := verifier.Close(); err != nil {
		return report, err
	}
	if verifier.written != file.Size {
		return report, fmt.Errorf("xet: reconstructed %d bytes, expected %d", verifier.written, file.Size)
	}
	if root := xethash.File(verifier.nodes); root != file.Hash {
		return report, fmt.Errorf("xet: reconstructed file hash %s, want %s", root, file.Hash)
	}
	report.WholeFileHash = true
	if file.SHA256 != ([sha256.Size]byte{}) {
		var computed [sha256.Size]byte
		copy(computed[:], verifier.sha.Sum(nil))
		if computed != file.SHA256 {
			return report, errors.New("xet: reconstructed SHA-256 mismatch")
		}
		report.SHA256Verified = true
	}
	return report, nil
}

type verifyingWriter struct {
	dst      io.Writer
	sha      hash.Hash
	splitter *chunker.Writer
	nodes    []xethash.Node
	written  uint64
}

func newVerifyingWriter(ctx context.Context, dst io.Writer) (*verifyingWriter, error) {
	w := &verifyingWriter{dst: dst, sha: sha256.New()}
	splitter, err := chunker.NewWriter(ctx, chunker.DefaultConfig, func(value chunker.Chunk) error {
		w.nodes = append(w.nodes, xethash.Node{Hash: xethash.Chunk(value.Data), Size: uint64(len(value.Data))})
		return nil
	})
	if err != nil {
		return nil, err
	}
	w.splitter = splitter
	return w, nil
}

func (w *verifyingWriter) Write(data []byte) (int, error) {
	n, err := w.dst.Write(data)
	if n < 0 || n > len(data) {
		return 0, errors.New("xet: download writer returned invalid count")
	}
	if n != 0 {
		_, _ = w.sha.Write(data[:n])
		if _, splitErr := w.splitter.Write(data[:n]); splitErr != nil && err == nil {
			err = splitErr
		}
		w.written += uint64(n)
	}
	if err == nil && n != len(data) {
		err = io.ErrShortWrite
	}
	return n, err
}

func (w *verifyingWriter) Close() error {
	return w.splitter.Close()
}

type countingWriter struct {
	dst     io.Writer
	written uint64
}

func (w *countingWriter) Write(data []byte) (int, error) {
	n, err := w.dst.Write(data)
	w.written += uint64(n)
	return n, err
}

func planDownloads(reconstruction *xetcas.Reconstruction) ([]*downloadJob, []*downloadDescriptor, error) {
	var jobs []*downloadJob
	byHash := make(map[xethash.Hash][]*downloadDescriptor)
	seen := make(map[segmentKey]struct{})
	for hash, fetches := range reconstruction.Xorbs {
		for _, fetch := range fetches {
			job := &downloadJob{url: fetch.URL, firstUse: len(reconstruction.Terms) + 1}
			for _, descriptor := range fetch.Ranges {
				value := &downloadDescriptor{hash: hash, desc: descriptor, job: job}
				if _, duplicate := seen[value.key()]; duplicate {
					return nil, nil, fmt.Errorf("xet: duplicate fetch descriptor for xorb %s chunks [%d,%d)", hash, descriptor.Chunks.Start, descriptor.Chunks.End)
				}
				seen[value.key()] = struct{}{}
				job.descriptors = append(job.descriptors, value)
				job.ranges = append(job.ranges, descriptor.Bytes)
				byHash[hash] = append(byHash[hash], value)
			}
			jobs = append(jobs, job)
		}
	}
	terms := make([]*downloadDescriptor, len(reconstruction.Terms))
	used := make(map[*downloadJob]bool)
	for i, term := range reconstruction.Terms {
		for _, descriptor := range byHash[term.Hash] {
			if descriptor.desc.Chunks.Contains(term.Range) {
				terms[i] = descriptor
				descriptor.job.firstUse = min(descriptor.job.firstUse, i)
				used[descriptor.job] = true
				break
			}
		}
		if terms[i] == nil {
			return nil, nil, fmt.Errorf("xet: term %d has no containing fetch descriptor", i)
		}
	}
	filtered := jobs[:0]
	for _, job := range jobs {
		if used[job] {
			filtered = append(filtered, job)
		}
	}
	sort.SliceStable(filtered, func(i, j int) bool { return filtered[i].firstUse < filtered[j].firstUse })
	return filtered, terms, nil
}

func (c *Client) fetchJob(ctx context.Context, job *downloadJob) downloadJobResult {
	var fetched []xetcas.FetchedRange
	var cacheHitBytes uint64
	cacheHitRanges := 0
	allCached := c.options.Cache != nil
	if allCached {
		fetched = make([]xetcas.FetchedRange, 0, len(job.descriptors))
		for _, descriptor := range job.descriptors {
			data, found, _ := c.options.Cache.GetXorbRange(ctx, descriptor.hash,
				descriptor.desc.Chunks.Start, descriptor.desc.Chunks.End)
			if found {
				object, decodeErr := xorb.Decode(data)
				if decodeErr != nil || uint32(len(object.Chunks)) != descriptor.desc.Chunks.Len() {
					_ = c.options.Cache.DeleteXorbRange(ctx, descriptor.hash,
						descriptor.desc.Chunks.Start, descriptor.desc.Chunks.End)
					found = false
				}
			}
			if !found {
				allCached = false
				break
			}
			fetched = append(fetched, xetcas.FetchedRange{Range: descriptor.desc.Bytes, Data: data})
			cacheHitBytes += uint64(len(data))
			cacheHitRanges++
		}
	}
	var networkFetched uint64
	networkRanges := 0
	if !allCached {
		var err error
		fetched, err = c.protocol.FetchRanges(ctx, job.url, job.ranges)
		if err != nil {
			return downloadJobResult{err: err}
		}
		cacheHitBytes = 0
		cacheHitRanges = 0
		for _, value := range fetched {
			networkFetched += uint64(len(value.Data))
		}
		networkRanges = len(job.ranges)
	}
	byRange := make(map[xetcas.HTTPRange][]byte, len(fetched))
	for _, value := range fetched {
		if _, duplicate := byRange[value.Range]; duplicate {
			return downloadJobResult{err: fmt.Errorf("xet: duplicate fetched range %s", value.Range)}
		}
		byRange[value.Range] = value.Data
	}
	segments := make(map[segmentKey]decodedSegment, len(job.descriptors))
	for _, descriptor := range job.descriptors {
		body, ok := byRange[descriptor.desc.Bytes]
		if !ok {
			return downloadJobResult{err: fmt.Errorf("xet: signed response omitted range %s", descriptor.desc.Bytes)}
		}
		object, err := xorb.Decode(body)
		if err != nil {
			return downloadJobResult{err: fmt.Errorf("xet: decode fetched xorb %s: %w", descriptor.hash, err)}
		}
		if uint32(len(object.Chunks)) != descriptor.desc.Chunks.Len() {
			return downloadJobResult{err: fmt.Errorf("xet: fetched xorb range has %d chunks, want %d", len(object.Chunks), descriptor.desc.Chunks.Len())}
		}
		object.Body = nil
		segments[descriptor.key()] = decodedSegment{chunks: object.Chunks, rawSize: uint64(object.UncompressedSize)}
		if !allCached && c.options.Cache != nil {
			_ = c.options.Cache.PutXorbRange(ctx, descriptor.hash,
				descriptor.desc.Chunks.Start, descriptor.desc.Chunks.End, body)
		}
	}
	return downloadJobResult{
		segments:    segments,
		fetched:     networkFetched,
		fetchRanges: networkRanges,
		cacheHit:    cacheHitBytes,
		cacheRanges: cacheHitRanges,
	}
}

type croppingWriter struct {
	dst       io.Writer
	skip      uint64
	remaining uint64
	written   uint64
	limited   bool
}

func (w *croppingWriter) Write(data []byte) (int, error) {
	original := len(data)
	if w.skip != 0 {
		discard := min(uint64(len(data)), w.skip)
		data = data[discard:]
		w.skip -= discard
	}
	if w.limited && uint64(len(data)) > w.remaining {
		data = data[:w.remaining]
	}
	if len(data) != 0 {
		n, err := w.dst.Write(data)
		w.written += uint64(n)
		if w.limited {
			w.remaining -= uint64(n)
		}
		if err != nil {
			return 0, err
		}
		if n != len(data) {
			return 0, io.ErrShortWrite
		}
	}
	return original, nil
}
