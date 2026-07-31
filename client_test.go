package xet

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"sort"
	"sync"
	"testing"

	"github.com/jacobwoliver/xet-go/shard"
	"github.com/jacobwoliver/xet-go/xetcas"
	"github.com/jacobwoliver/xet-go/xethash"
	"github.com/jacobwoliver/xet-go/xorb"
)

type memoryProtocol struct {
	mu sync.Mutex

	objects       map[xethash.Hash]*xorb.Object
	metadata      *shard.Shard
	fetched       map[string]map[xetcas.HTTPRange][]byte
	uploadOrder   []string
	queryCalls    int
	fetchCalls    int
	expireFetches int
	corruptLength bool
}

func newMemoryProtocol() *memoryProtocol {
	return &memoryProtocol{
		objects: make(map[xethash.Hash]*xorb.Object),
		fetched: make(map[string]map[xetcas.HTTPRange][]byte),
	}
}

func (m *memoryProtocol) UploadXorb(
	_ context.Context,
	prefix string,
	hash xethash.Hash,
	body []byte,
) (bool, error) {
	if prefix != xetcas.DefaultPrefix {
		return false, fmt.Errorf("prefix %q", prefix)
	}
	object, err := xorb.Decode(body)
	if err != nil {
		return false, err
	}
	if object.Hash != hash {
		return false, fmt.Errorf("xorb hash %s, route hash %s", object.Hash, hash)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	_, existed := m.objects[hash]
	m.objects[hash] = object
	m.uploadOrder = append(m.uploadOrder, "xorb:"+hash.String())
	return !existed, nil
}

func (m *memoryProtocol) UploadShard(_ context.Context, body []byte, _ func(xetcas.ShardUploadEvent)) error {
	metadata, err := shard.Decode(body)
	if err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, value := range metadata.Xorbs {
		if _, ok := m.objects[value.Hash]; !ok {
			return fmt.Errorf("shard arrived before xorb %s", value.Hash)
		}
	}
	m.metadata = metadata
	m.uploadOrder = append(m.uploadOrder, "shard")
	return nil
}

func (*memoryProtocol) QueryGlobalDedup(context.Context, string, xethash.Hash) ([]byte, bool, error) {
	return nil, false, nil
}

func (m *memoryProtocol) QueryReconstruction(
	_ context.Context,
	fileID xethash.Hash,
	requested *xetcas.FileRange,
) (*xetcas.Reconstruction, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.queryCalls++
	if m.metadata == nil {
		return nil, errors.New("no shard")
	}
	var file *shard.File
	for i := range m.metadata.Files {
		if m.metadata.Files[i].Hash == fileID {
			file = &m.metadata.Files[i]
			break
		}
	}
	if file == nil {
		return nil, &xetcas.HTTPError{Method: "GET", URL: "memory", StatusCode: 404}
	}
	result := &xetcas.Reconstruction{Xorbs: make(map[xethash.Hash][]xetcas.MultiRangeFetch)}
	var logicalOffset uint64
	selected := make([]shard.Term, 0, len(file.Terms))
	for _, term := range file.Terms {
		termStart := logicalOffset
		termEnd := termStart + uint64(term.UnpackedBytes)
		logicalOffset = termEnd
		if requested != nil && (termEnd <= requested.Start || termStart >= requested.End) {
			continue
		}
		if len(selected) == 0 && requested != nil {
			result.OffsetIntoFirstRange = requested.Start - termStart
		}
		selected = append(selected, term)
	}

	descriptors := make(map[xethash.Hash]map[xetcas.ChunkRange]xetcas.XorbRangeDescriptor)
	for _, term := range selected {
		unpacked := term.UnpackedBytes
		if m.corruptLength {
			unpacked++
		}
		result.Terms = append(result.Terms, xetcas.ReconstructionTerm{
			Hash: term.XorbHash, UnpackedLength: unpacked,
			Range: xetcas.ChunkRange{Start: term.Start, End: term.End},
		})
		object := m.objects[term.XorbHash]
		if object == nil || term.End > uint32(len(object.Chunks)) {
			return nil, errors.New("bad stored xorb reference")
		}
		first := object.Chunks[term.Start]
		last := object.Chunks[term.End-1]
		physical := xetcas.HTTPRange{
			Start: uint64(first.SerializedOffset),
			End:   uint64(last.SerializedOffset + last.SerializedLength - 1),
		}
		chunkRange := xetcas.ChunkRange{Start: term.Start, End: term.End}
		if descriptors[term.XorbHash] == nil {
			descriptors[term.XorbHash] = make(map[xetcas.ChunkRange]xetcas.XorbRangeDescriptor)
		}
		descriptors[term.XorbHash][chunkRange] = xetcas.XorbRangeDescriptor{Chunks: chunkRange, Bytes: physical}
	}
	for hash, values := range descriptors {
		ranges := make([]xetcas.XorbRangeDescriptor, 0, len(values))
		for _, value := range values {
			ranges = append(ranges, value)
		}
		sort.Slice(ranges, func(i, j int) bool { return ranges[i].Chunks.Start < ranges[j].Chunks.Start })
		url := fmt.Sprintf("https://storage.invalid/%s?generation=%d", hash, m.queryCalls)
		bodies := make(map[xetcas.HTTPRange][]byte, len(ranges))
		object := m.objects[hash]
		for _, descriptor := range ranges {
			start := object.Chunks[descriptor.Chunks.Start].SerializedOffset
			last := object.Chunks[descriptor.Chunks.End-1]
			end := last.SerializedOffset + last.SerializedLength
			bodies[descriptor.Bytes] = append([]byte(nil), object.Body[start:end]...)
		}
		m.fetched[url] = bodies
		result.Xorbs[hash] = []xetcas.MultiRangeFetch{{URL: url, Ranges: ranges}}
	}
	return result, result.Validate()
}

func (m *memoryProtocol) FetchRanges(
	_ context.Context,
	url string,
	ranges []xetcas.HTTPRange,
) ([]xetcas.FetchedRange, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.fetchCalls++
	if m.expireFetches != 0 {
		m.expireFetches--
		return nil, xetcas.ErrSignedURLExpired
	}
	bodies := m.fetched[url]
	if bodies == nil {
		return nil, errors.New("unknown signed URL")
	}
	result := make([]xetcas.FetchedRange, 0, len(ranges))
	for i := len(ranges) - 1; i >= 0; i-- {
		body, ok := bodies[ranges[i]]
		if !ok {
			return nil, fmt.Errorf("range %s not signed", ranges[i])
		}
		result = append(result, xetcas.FetchedRange{Range: ranges[i], Data: append([]byte(nil), body...)})
	}
	return result, nil
}

func newTestEngine(t testing.TB, protocol Protocol) *Client {
	t.Helper()
	client, err := NewClient(protocol, Options{
		Compression:         xorb.None,
		CompressionSet:      true,
		UploadConcurrency:   3,
		DownloadConcurrency: 3,
	})
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func deterministicData(size int) []byte {
	data := make([]byte, size)
	rng := rand.New(rand.NewSource(int64(size) + 17))
	_, _ = rng.Read(data)
	for i := 0; i+4096 <= len(data); i += 32 << 10 {
		copy(data[i:i+4096], bytes.Repeat([]byte{byte(i >> 15)}, 4096))
	}
	return data
}

func TestUploadDownloadAndRangeEndToEnd(t *testing.T) {
	protocol := newMemoryProtocol()
	client := newTestEngine(t, protocol)
	data := deterministicData(2<<20 + 123)
	result, err := client.Upload(context.Background(), bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	if !result.Report.ShardUploaded || result.Report.Xorbs != 1 || result.File.Size != uint64(len(data)) {
		t.Fatalf("unexpected upload result: %#v", result)
	}
	protocol.mu.Lock()
	if len(protocol.uploadOrder) < 2 || protocol.uploadOrder[len(protocol.uploadOrder)-1] != "shard" {
		t.Fatalf("upload order %v", protocol.uploadOrder)
	}
	if protocol.metadata == nil || len(protocol.metadata.Files) != 1 || protocol.metadata.Files[0].SHA256 == nil {
		t.Fatalf("bad uploaded shard %#v", protocol.metadata)
	}
	protocol.mu.Unlock()

	var full bytes.Buffer
	download, err := client.Download(context.Background(), result.File, &full)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(full.Bytes(), data) || !download.WholeFileHash || !download.SHA256Verified {
		t.Fatalf("full download mismatch: %#v", download)
	}

	wanted := xetcas.FileRange{Start: 12_345, End: 987_654}
	var partial bytes.Buffer
	download, err = client.DownloadRange(context.Background(), result.File.Hash, wanted, &partial)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(partial.Bytes(), data[wanted.Start:wanted.End]) || download.LogicalBytes != wanted.Len() {
		t.Fatalf("range download mismatch: %#v", download)
	}
}

func TestUploadBatchSessionDeduplicatesIdenticalFiles(t *testing.T) {
	protocol := newMemoryProtocol()
	client := newTestEngine(t, protocol)
	batch, err := client.NewUploadBatch(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	data := deterministicData(900_000)
	first, err := batch.Add(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	second, err := batch.Add(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Fatalf("identical files produced different metadata")
	}
	report, err := batch.Finalize()
	if err != nil {
		t.Fatal(err)
	}
	if report.Files != 2 || report.Dedup.SessionDedupChunks == 0 || report.Dedup.SessionDedupBytes != uint64(len(data)) {
		t.Fatalf("dedup report %#v", report)
	}
	protocol.mu.Lock()
	defer protocol.mu.Unlock()
	if len(protocol.metadata.Files) != 1 {
		t.Fatalf("duplicate file IDs were written to shard: %d records", len(protocol.metadata.Files))
	}
}

func TestEmptyFileUploadsWithoutXorb(t *testing.T) {
	protocol := newMemoryProtocol()
	client := newTestEngine(t, protocol)
	result, err := client.Upload(context.Background(), bytes.NewReader(nil))
	if err != nil {
		t.Fatal(err)
	}
	if result.File.Hash != xethash.Zero || result.File.Size != 0 || result.Report.Xorbs != 0 {
		t.Fatalf("empty result %#v", result)
	}
	var output bytes.Buffer
	if _, err := client.Download(context.Background(), result.File, &output); err != nil {
		t.Fatal(err)
	}
	if output.Len() != 0 {
		t.Fatalf("empty output has %d bytes", output.Len())
	}
}

func TestDownloadRefreshesExpiredSignedURLBeforeWriting(t *testing.T) {
	protocol := newMemoryProtocol()
	client := newTestEngine(t, protocol)
	data := deterministicData(300_000)
	result, err := client.Upload(context.Background(), bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	protocol.mu.Lock()
	protocol.expireFetches = 1
	protocol.mu.Unlock()
	var output bytes.Buffer
	if _, err := client.Download(context.Background(), result.File, &output); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(output.Bytes(), data) {
		t.Fatal("retry duplicated or omitted output")
	}
	protocol.mu.Lock()
	defer protocol.mu.Unlock()
	if protocol.queryCalls != 2 {
		t.Fatalf("reconstruction queries = %d, want 2", protocol.queryCalls)
	}
}

func TestPersistentRangeCacheAvoidsSecondSignedFetch(t *testing.T) {
	protocol := newMemoryProtocol()
	cache, err := NewDiskCache(t.TempDir(), "memory-cas/test-scope")
	if err != nil {
		t.Fatal(err)
	}
	client, err := NewClient(protocol, Options{
		Compression:         xorb.None,
		CompressionSet:      true,
		UploadConcurrency:   2,
		DownloadConcurrency: 2,
		Cache:               cache,
	})
	if err != nil {
		t.Fatal(err)
	}
	data := deterministicData(700_000)
	upload, err := client.Upload(context.Background(), bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Download(context.Background(), upload.File, io.Discard); err != nil {
		t.Fatal(err)
	}
	protocol.mu.Lock()
	firstFetches := protocol.fetchCalls
	protocol.mu.Unlock()
	var output bytes.Buffer
	report, err := client.Download(context.Background(), upload.File, &output)
	if err != nil {
		t.Fatal(err)
	}
	protocol.mu.Lock()
	secondFetches := protocol.fetchCalls
	protocol.mu.Unlock()
	if secondFetches != firstFetches || report.FetchedBytes != 0 || report.CacheHitRanges == 0 {
		t.Fatalf("fetches %d->%d report=%#v", firstFetches, secondFetches, report)
	}
	if !bytes.Equal(output.Bytes(), data) {
		t.Fatal("cached download differs")
	}
}

func TestDownloadRejectsTermLengthMismatch(t *testing.T) {
	protocol := newMemoryProtocol()
	client := newTestEngine(t, protocol)
	result, err := client.Upload(context.Background(), bytes.NewReader(deterministicData(100_000)))
	if err != nil {
		t.Fatal(err)
	}
	protocol.mu.Lock()
	protocol.corruptLength = true
	protocol.mu.Unlock()
	_, err = client.Download(context.Background(), result.File, io.Discard)
	if err == nil || !stringsContains(err.Error(), "decoded") {
		t.Fatalf("error=%v", err)
	}
}

func stringsContains(value, substring string) bool {
	return bytes.Contains([]byte(value), []byte(substring))
}

type failingReader struct {
	done bool
}

func (r *failingReader) Read(data []byte) (int, error) {
	if r.done {
		return 0, errors.New("source failed")
	}
	r.done = true
	n := copy(data, bytes.Repeat([]byte("x"), 1024))
	return n, errors.New("source failed")
}

func TestUploadReaderFailureNeverRegistersShard(t *testing.T) {
	protocol := newMemoryProtocol()
	client := newTestEngine(t, protocol)
	batch, err := client.NewUploadBatch(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := batch.Add(&failingReader{}); err == nil {
		t.Fatal("Add succeeded")
	}
	if _, err := batch.Finalize(); !errors.Is(err, ErrBatchFinalized) {
		t.Fatalf("Finalize error=%v", err)
	}
	protocol.mu.Lock()
	defer protocol.mu.Unlock()
	if protocol.metadata != nil {
		t.Fatal("failed input registered a shard")
	}
}

func FuzzUploadDownload(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte("xet protocol"))
	f.Add(bytes.Repeat([]byte{0, 1, 2, 3}, 40_000))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 2<<20 {
			return
		}
		protocol := newMemoryProtocol()
		client := newTestEngine(t, protocol)
		result, err := client.Upload(context.Background(), bytes.NewReader(data))
		if err != nil {
			t.Fatal(err)
		}
		var output bytes.Buffer
		if _, err := client.Download(context.Background(), result.File, &output); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(output.Bytes(), data) {
			t.Fatal("round trip differs")
		}
	})
}

func BenchmarkUploadPipeline(b *testing.B) {
	data := deterministicData(8 << 20)
	b.SetBytes(int64(len(data)))
	b.ReportAllocs()
	for range b.N {
		protocol := newMemoryProtocol()
		client := newTestEngine(b, protocol)
		if _, err := client.Upload(context.Background(), bytes.NewReader(data)); err != nil {
			b.Fatal(err)
		}
	}
}
