package xet

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jmwoliver/xet-go/chunker"
	"github.com/jmwoliver/xet-go/shard"
	"github.com/jmwoliver/xet-go/xetcas"
	"github.com/jmwoliver/xet-go/xethash"
	"github.com/jmwoliver/xet-go/xorb"
)

type memoryProtocol struct {
	mu sync.Mutex

	objects          map[xethash.Hash]*xorb.Object
	metadata         *shard.Shard
	fetched          map[string]map[xetcas.HTTPRange][]byte
	uploadOrder      []string
	queryCalls       int
	fetchCalls       int
	expireFetches    int
	corruptLength    bool
	globalShard      []byte
	globalQueries    int
	fileChunks       *xetcas.FileChunkHashesResponse
	fileChunkQueries int
	shardFailures    int
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
	if prefix != xetcas.DefaultXorbPrefix {
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

func (m *memoryProtocol) XorbExists(_ context.Context, _ string, hash xethash.Hash) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, exists := m.objects[hash]
	return exists, nil
}

func (m *memoryProtocol) UploadShard(_ context.Context, body []byte, _ func(xetcas.ShardUploadEvent)) error {
	metadata, err := shard.Decode(body)
	if err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.shardFailures != 0 {
		m.shardFailures--
		return errors.New("injected shard failure")
	}
	for _, value := range metadata.Xorbs {
		if _, ok := m.objects[value.Hash]; !ok {
			return fmt.Errorf("shard arrived before xorb %s", value.Hash)
		}
	}
	m.metadata = metadata
	m.uploadOrder = append(m.uploadOrder, "shard")
	return nil
}

func (m *memoryProtocol) QueryGlobalDedup(_ context.Context, prefix string, _ xethash.Hash) ([]byte, bool, error) {
	if prefix != xetcas.DefaultDedupPrefix {
		return nil, false, fmt.Errorf("dedup prefix %q", prefix)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.globalQueries++
	if len(m.globalShard) == 0 {
		return nil, false, nil
	}
	return append([]byte(nil), m.globalShard...), true, nil
}

func (m *memoryProtocol) QueryFileChunkHashes(
	_ context.Context,
	_ xethash.Hash,
	_ []xetcas.FileRange,
) (*xetcas.FileChunkHashesResponse, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.fileChunkQueries++
	if m.fileChunks == nil {
		return nil, errors.New("no file-chunk-hashes response configured")
	}
	response := *m.fileChunks
	response.Windows = append([]xetcas.ChunkWindow(nil), response.Windows...)
	response.HashRanges = append([]*xethash.MerkleHashSubtree(nil), response.HashRanges...)
	response.GapVerification = append([]xethash.Hash(nil), response.GapVerification...)
	return &response, nil
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

func TestDefaultUploadUsesProtocolNamespaces(t *testing.T) {
	var mu sync.Mutex
	requests := make(map[string]int)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := r.Method + " " + r.URL.Path
		mu.Lock()
		requests[key]++
		mu.Unlock()

		switch {
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/v1/chunks/default-merkledb/"):
			http.NotFound(w, r)
		case r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/v1/xorbs/default/"):
			_, _ = io.Copy(io.Discard, r.Body)
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"was_inserted":true}`)
		case r.Method == http.MethodPost && r.URL.Path == "/v2/shards":
			_, _ = io.Copy(io.Discard, r.Body)
			w.Header().Set("Content-Type", "application/x-ndjson")
			_, _ = io.WriteString(w, `{"type":"result"}`)
		default:
			http.Error(w, "unexpected route", http.StatusBadRequest)
		}
	}))
	defer server.Close()

	endpoint, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	transport, err := xetcas.New(xetcas.NewStaticAccess(endpoint, ""), xetcas.Options{})
	if err != nil {
		t.Fatal(err)
	}
	client, err := NewClient(transport, Options{
		Compression: xorb.None, CompressionSet: true,
		GlobalDedup: true, UploadConcurrency: 1, DownloadConcurrency: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	result, err := client.UploadBytes(context.Background(), deterministicData(200_000))
	if err != nil {
		t.Fatal(err)
	}
	if result.File.SHA256 == nil {
		t.Fatal("upload omitted SHA-256 presence")
	}

	mu.Lock()
	defer mu.Unlock()
	var dedup, xorbs, shards int
	for request, count := range requests {
		switch {
		case strings.HasPrefix(request, "GET /v1/chunks/default-merkledb/"):
			dedup += count
		case strings.HasPrefix(request, "POST /v1/xorbs/default/"):
			xorbs += count
		case request == "POST /v2/shards":
			shards += count
		default:
			t.Fatalf("unexpected request %q", request)
		}
	}
	if dedup == 0 || xorbs == 0 || shards != 1 {
		t.Fatalf("requests=%v", requests)
	}
}

func TestWholeDownloadUsesBoundedReconstructionWindows(t *testing.T) {
	protocol := newMemoryProtocol()
	client, err := NewClient(protocol, Options{
		Compression: xorb.None, CompressionSet: true,
		UploadConcurrency: 2, DownloadConcurrency: 2,
		MaxReconstructionWindow: 200_000,
	})
	if err != nil {
		t.Fatal(err)
	}
	data := deterministicData(750_123)
	upload, err := client.Upload(context.Background(), bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	protocol.mu.Lock()
	protocol.queryCalls = 0
	protocol.mu.Unlock()
	var output bytes.Buffer
	report, err := client.Download(context.Background(), upload.File, &output)
	if err != nil {
		t.Fatal(err)
	}
	protocol.mu.Lock()
	queries := protocol.queryCalls
	protocol.mu.Unlock()
	if queries != 4 || !report.WholeFileHash || !report.SHA256Verified || report.LogicalBytes != uint64(len(data)) {
		t.Fatalf("windowed report=%#v queries=%d", report, queries)
	}
	if !bytes.Equal(output.Bytes(), data) {
		t.Fatal("windowed reconstruction differs")
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
	if !first.Equal(second) {
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

func TestGlobalDedupReusesExternalXorb(t *testing.T) {
	protocol := newMemoryProtocol()
	seedClient := newTestEngine(t, protocol)
	data := deterministicData(800_000)
	seed, err := seedClient.Upload(context.Background(), bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	protocol.mu.Lock()
	globalShard, err := shard.EncodeUpload(*protocol.metadata)
	if err == nil {
		protocol.globalShard = globalShard
	}
	protocol.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	dedupClient, err := NewClient(protocol, Options{
		Compression:         xorb.None,
		CompressionSet:      true,
		UploadConcurrency:   2,
		DownloadConcurrency: 2,
		GlobalDedup:         true,
	})
	if err != nil {
		t.Fatal(err)
	}
	result, err := dedupClient.Upload(context.Background(), bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	if result.File.Hash != seed.File.Hash || result.Report.Xorbs != 0 ||
		result.Report.Dedup.GlobalDedupBytes != uint64(len(data)) || result.Report.Dedup.NewBytes != 0 {
		t.Fatalf("global dedup result %#v", result)
	}
	var output bytes.Buffer
	if _, err := dedupClient.Download(context.Background(), result.File, &output); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(output.Bytes(), data) {
		t.Fatal("globally deduplicated reconstruction differs")
	}
}

func TestGlobalDedupProtectedShard(t *testing.T) {
	protocol := newMemoryProtocol()
	seedClient := newTestEngine(t, protocol)
	data := deterministicData(500_000)
	if _, err := seedClient.Upload(context.Background(), bytes.NewReader(data)); err != nil {
		t.Fatal(err)
	}
	protocol.mu.Lock()
	protected, err := makeProtectedGlobalShard(*protocol.metadata, xethash.Chunk([]byte("protection-key")))
	if err == nil {
		protocol.globalShard = protected
	}
	protocol.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	client, err := NewClient(protocol, Options{
		Compression: xorb.None, CompressionSet: true,
		UploadConcurrency: 2, DownloadConcurrency: 2, GlobalDedup: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	result, err := client.Upload(context.Background(), bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	if result.Report.Xorbs != 0 || result.Report.Dedup.GlobalDedupBytes != uint64(len(data)) {
		t.Fatalf("protected global dedup failed: %#v", result.Report)
	}
}

func TestFragmentationTrackerMatchesRustThresholds(t *testing.T) {
	tracker := newFragmentationTracker(Options{
		DefragWindow: 3, MinChunksPerRange: 8, DefragHysteresis: 0.5,
	})
	// The estimator deliberately permits all deduplication until its rolling
	// window is full.
	for range 3 {
		if !tracker.allowDedup(1) {
			t.Fatal("dedup rejected before estimator window filled")
		}
		tracker.addRange(2)
	}
	// Average chunks/range is 2, below the low threshold (4). A one-chunk
	// range is rejected and switches to the high threshold; a two-chunk range
	// is accepted because Rust uses a strict less-than lookahead comparison.
	if tracker.allowDedup(1) {
		t.Fatal("fragmenting one-chunk range accepted")
	}
	if !tracker.allowDedup(2) {
		t.Fatal("non-degrading two-chunk range rejected")
	}
	tracker.addRange(2)
	tracker.extendRange(3)
	if tracker.total != 9 {
		t.Fatalf("rolling chunk total = %d, want 9", tracker.total)
	}
}

func TestDefragPreventedSessionDedupDoesNotInflateFileSize(t *testing.T) {
	seed := chunker.Bytes(deterministicData(1 << 20))
	if len(seed) < 3 {
		t.Fatal("test fixture did not produce enough chunks")
	}
	data := make([]byte, 0, len(seed[0].Data)*2+len(seed[1].Data)+len(seed[2].Data))
	for _, index := range []int{0, 1, 2, 0} {
		data = append(data, seed[index].Data...)
	}
	if got := chunker.Bytes(data); len(got) != 4 || !bytes.Equal(got[0].Data, got[3].Data) {
		t.Fatalf("test fixture did not preserve the repeated chunk: %d chunks", len(got))
	}

	protocol := newMemoryProtocol()
	client, err := NewClient(protocol, Options{
		Compression: xorb.None, CompressionSet: true,
		UploadConcurrency: 1, DownloadConcurrency: 1,
		DefragWindow: 1, MinChunksPerRange: 100_000, DefragHysteresis: 0.5,
	})
	if err != nil {
		t.Fatal(err)
	}
	result, err := client.UploadBytes(context.Background(), data)
	if err != nil {
		t.Fatal(err)
	}
	if result.Report.Dedup.DefragSkippedChunks != 1 ||
		result.Report.Dedup.DefragSkippedBytes != uint64(len(seed[0].Data)) {
		t.Fatalf("defrag path not exercised: %#v", result.Report.Dedup)
	}
	if result.File.Size != uint64(len(data)) || result.Report.Dedup.TotalBytes != uint64(len(data)) ||
		result.Report.Dedup.NewBytes != uint64(len(data)) {
		t.Fatalf("size/accounting mismatch: file=%d input=%d report=%#v", result.File.Size, len(data), result.Report.Dedup)
	}
}

func makeProtectedGlobalShard(metadata shard.Shard, key xethash.Hash) ([]byte, error) {
	minimal := shard.Shard{Xorbs: metadata.Xorbs}
	body, err := shard.EncodeUpload(minimal)
	if err != nil {
		return nil, err
	}
	position := shard.HeaderSize + shard.RecordSize // empty file section bookend
	for _, xorbInfo := range minimal.Xorbs {
		position += shard.RecordSize // xorb header
		for _, chunk := range xorbInfo.Chunks {
			protected := xethash.Protect(chunk.Hash, key)
			copy(body[position:position+xethash.Size], protected[:])
			position += shard.RecordSize
		}
	}
	binary.LittleEndian.PutUint64(body[40:48], shard.FooterSize)
	footerStart := len(body)
	footer := make([]byte, shard.FooterSize)
	values := []uint64{
		1,
		shard.HeaderSize,
		shard.HeaderSize + shard.RecordSize,
		uint64(footerStart), 0,
		uint64(footerStart), 0,
		uint64(footerStart), 0,
	}
	for i, value := range values {
		binary.LittleEndian.PutUint64(footer[i*8:(i+1)*8], value)
	}
	copy(footer[72:104], key[:])
	binary.LittleEndian.PutUint64(footer[104:112], uint64(time.Now().Unix()))
	binary.LittleEndian.PutUint64(footer[112:120], uint64(time.Now().Add(time.Hour).Unix()))
	binary.LittleEndian.PutUint64(footer[192:200], uint64(footerStart))
	return append(body, footer...), nil
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
