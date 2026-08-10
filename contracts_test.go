package xet

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/jmwoliver/xet-go/chunker"
	"github.com/jmwoliver/xet-go/shard"
	"github.com/jmwoliver/xet-go/xetcas"
	"github.com/jmwoliver/xet-go/xethash"
	"github.com/jmwoliver/xet-go/xorb"
)

func TestClientOptionContracts(t *testing.T) {
	protocol := newMemoryProtocol()
	if _, err := NewClient(nil, Options{}); err == nil {
		t.Fatal("nil protocol succeeded")
	}
	for name, options := range map[string]Options{
		"compression":        {CompressionSet: true, Compression: xorb.Scheme(42)},
		"conflicting prefix": {Prefix: "legacy", XorbPrefix: "explicit"},
		"compression retest": {CompressionRetestInterval: -1},
		"upload workers":     {UploadConcurrency: -1},
		"download workers":   {DownloadConcurrency: -1},
		"download memory":    {MaxDownloadMemory: xorb.MaxRawSize - 1},
		"defrag window":      {DefragWindow: -1},
		"defrag minimum":     {MinChunksPerRange: -1},
		"defrag hysteresis":  {DefragHysteresis: 2},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := NewClient(protocol, options); err == nil {
				t.Fatalf("NewClient(%#v) succeeded", options)
			}
		})
	}
	client, err := NewClient(protocol, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if client.options.XorbPrefix != xetcas.DefaultXorbPrefix ||
		client.options.DedupPrefix != xetcas.DefaultDedupPrefix || client.options.Compression != xorb.Auto ||
		client.options.UploadConcurrency < 1 || client.options.DownloadConcurrency < 1 {
		t.Fatalf("defaults = %#v", client.options)
	}
	legacy, err := NewClient(protocol, Options{Prefix: "legacy-xorbs"})
	if err != nil {
		t.Fatal(err)
	}
	if legacy.options.XorbPrefix != "legacy-xorbs" || legacy.options.DedupPrefix != xetcas.DefaultDedupPrefix {
		t.Fatalf("legacy prefix options = %#v", legacy.options)
	}
}

func TestUploadBatchLifecycleContracts(t *testing.T) {
	client := newTestEngine(t, newMemoryProtocol())
	if _, err := client.NewUploadBatch(nil); err == nil { //nolint:staticcheck // Verify that the API rejects a nil context.
		t.Fatal("nil upload context succeeded")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := client.NewUploadBatch(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled batch = %v", err)
	}
	if _, err := client.Upload(context.Background(), nil); err == nil {
		t.Fatal("nil upload reader succeeded")
	}

	batch, err := client.NewUploadBatch(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := batch.Add(nil); err == nil {
		t.Fatal("nil batch reader succeeded")
	}
	batch.Abort(nil)
	if _, err := batch.Add(bytes.NewReader([]byte("x"))); !errors.Is(err, ErrBatchFinalized) {
		t.Fatalf("Add after Abort = %v", err)
	}
	if _, err := batch.Finalize(); !errors.Is(err, ErrBatchFinalized) {
		t.Fatalf("Finalize after Abort = %v", err)
	}
	batch.Abort(errors.New("ignored"))

	batch, err = client.NewUploadBatch(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := batch.Finalize(); err != nil {
		t.Fatalf("empty batch Finalize = %v", err)
	}
	if _, err := batch.Finalize(); !errors.Is(err, ErrBatchFinalized) {
		t.Fatalf("second Finalize = %v", err)
	}
}

func TestFileInfoSHA256PresenceAndOwnership(t *testing.T) {
	var zero [32]byte
	withZero := FileInfo{SHA256: &zero}
	if withZero.Equal(FileInfo{}) {
		t.Fatal("present all-zero SHA-256 compared equal to absent SHA-256")
	}
	zeroCopy := zero
	if !withZero.Equal(FileInfo{SHA256: &zeroCopy}) {
		t.Fatal("equal SHA-256 values compared unequal")
	}

	protocol := newMemoryProtocol()
	client := newTestEngine(t, protocol)
	batch, err := client.NewUploadBatch(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	info, err := batch.Add(strings.NewReader("immutable digest metadata"))
	if err != nil {
		t.Fatal(err)
	}
	if info.SHA256 == nil {
		t.Fatal("upload omitted SHA-256")
	}
	want := *info.SHA256
	info.SHA256[0] ^= 0xff
	if _, err := batch.Finalize(); err != nil {
		t.Fatal(err)
	}
	protocol.mu.Lock()
	defer protocol.mu.Unlock()
	if protocol.metadata == nil || len(protocol.metadata.Files) != 1 ||
		protocol.metadata.Files[0].SHA256 == nil || *protocol.metadata.Files[0].SHA256 != want {
		t.Fatalf("caller mutation changed published metadata: %#v", protocol.metadata)
	}
}

func TestUploadBatchSessionDeduplicatesRepeatedFiles(t *testing.T) {
	client := newTestEngine(t, newMemoryProtocol())
	batch, err := client.NewUploadBatch(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	data := deterministicData(200_000)
	first, err := batch.Add(bytes.NewReader(data))
	if err != nil {
		batch.Abort(err)
		t.Fatal(err)
	}
	second, err := batch.Add(bytes.NewReader(data))
	if err != nil {
		batch.Abort(err)
		t.Fatal(err)
	}
	if !first.Equal(second) {
		batch.Abort(errors.New("identity mismatch"))
		t.Fatalf("repeated file identities differ: %#v, %#v", first, second)
	}
	report, err := batch.Finalize()
	if err != nil {
		t.Fatal(err)
	}
	if report.Dedup.SessionDedupBytes != uint64(len(data)) || report.Dedup.SessionDedupChunks == 0 {
		t.Fatalf("session dedup report = %#v", report.Dedup)
	}
}

func TestUploadSourcesPropagatesFinalizeFailure(t *testing.T) {
	protocol := newMemoryProtocol()
	protocol.shardFailures = 1
	client := newTestEngine(t, protocol)
	if _, err := client.UploadSources(context.Background(), []UploadSource{{
		Reader: strings.NewReader("source"), Size: int64(len("source")),
	}}); err == nil {
		t.Fatal("failed source-batch finalization succeeded")
	}
}

func TestPlacementFragmentationAndShardHelpers(t *testing.T) {
	external := xethash.Chunk([]byte("external"))
	if got, err := (placement{externalHash: external}).xorbHash(); err != nil || got != external {
		t.Fatalf("external placement = %v, %v", got, err)
	}
	if _, err := (placement{}).xorbHash(); err == nil {
		t.Fatal("empty placement succeeded")
	}
	pending := &pendingXorb{}
	if _, err := (placement{pending: pending}).xorbHash(); err == nil {
		t.Fatal("unresolved placement succeeded")
	}
	pending.finalized = true
	pending.hash = xethash.Chunk([]byte("pending"))
	if got, err := (placement{pending: pending}).xorbHash(); err != nil || got != pending.hash {
		t.Fatalf("pending placement = %v, %v", got, err)
	}

	tracker := newFragmentationTracker(Options{DefragWindow: 2, MinChunksPerRange: 4, DefragHysteresis: .5})
	tracker.extendRange(2)
	tracker.addRange(2)
	tracker.addRange(1)
	tracker.extendRange(1)
	if tracker.total != 4 || tracker.start != 1 {
		t.Fatalf("tracker = %#v", tracker)
	}
	if placementsContinue(placement{index: 1}, placement{index: 3}) {
		t.Fatal("nonconsecutive placements continued")
	}
	if placementsContinue(placement{pending: pending, index: 0}, placement{pending: &pendingXorb{}, index: 1}) {
		t.Fatal("different pending xorbs continued")
	}
	if !placementsContinue(placement{externalHash: external, index: 0}, placement{externalHash: external, index: 1}) {
		t.Fatal("same external xorb did not continue")
	}

	if _, err := buildShardFile(uploadedFile{chunkNodes: []xethash.Node{{}}}); err == nil {
		t.Fatal("mismatched file metadata succeeded")
	}
	if _, err := buildShardFile(uploadedFile{chunkNodes: []xethash.Node{{}}, placements: []placement{{}}}); err == nil {
		t.Fatal("empty placement built a shard file")
	}
	placements := []placement{{externalHash: external, index: 0, length: math.MaxUint32}, {externalHash: external, index: 1, length: math.MaxUint32}}
	nodes := []xethash.Node{{Hash: xethash.Zero}, {Hash: xethash.Zero}}
	if _, err := buildShardFile(uploadedFile{chunkNodes: nodes, placements: placements}); err == nil {
		t.Fatal("overflowing reconstruction term succeeded")
	}
}

func TestUploadBatchInternalFailureContracts(t *testing.T) {
	client := newTestEngine(t, newMemoryProtocol())
	batch, err := client.NewUploadBatch(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer batch.Abort(nil)
	if _, err := batch.addNovelChunk(nil, 1); err == nil {
		t.Fatal("empty novel chunk succeeded")
	}
	if _, err := batch.addNovelChunk(make([]byte, chunker.MaxSize+1), 1); err == nil {
		t.Fatal("oversized novel chunk succeeded")
	}
	if err := batch.flushCurrent(); err != nil {
		t.Fatalf("empty flush = %v", err)
	}
	if _, err := batch.detachLastFile(); err == nil {
		t.Fatal("detached absent file")
	}
	batch.setFailure(nil)
	want := errors.New("first")
	batch.setFailure(want)
	batch.setFailure(errors.New("second"))
	if batch.failure() != want {
		t.Fatalf("failure = %v", batch.failure())
	}
	if _, err := batch.Add(strings.NewReader("x")); !errors.Is(err, ErrBatchFailed) {
		t.Fatalf("Add after worker failure = %v", err)
	}
}

type uploadFaultProtocol struct {
	Protocol
	existsErr error
	uploadErr error
}

func (p uploadFaultProtocol) XorbExists(context.Context, string, xethash.Hash) (bool, error) {
	return false, p.existsErr
}

func (p uploadFaultProtocol) UploadXorb(context.Context, string, xethash.Hash, []byte) (bool, error) {
	return false, p.uploadErr
}

func TestUploadWorkerAndFinalizeFailureContracts(t *testing.T) {
	for name, setup := range map[string]struct {
		protocol Protocol
		journal  UploadJournal
	}{
		"resume inspection": {
			protocol: uploadFaultProtocol{Protocol: newMemoryProtocol(), existsErr: errors.New("existence failed")},
			journal:  &journalFault{has: true},
		},
		"xorb upload": {
			protocol: uploadFaultProtocol{Protocol: newMemoryProtocol(), uploadErr: errors.New("upload failed")},
		},
	} {
		t.Run(name, func(t *testing.T) {
			client, err := NewClient(setup.protocol, Options{
				Compression: xorb.None, CompressionSet: true,
				UploadConcurrency: 1, DownloadConcurrency: 1, UploadJournal: setup.journal,
			})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := client.UploadBytes(context.Background(), deterministicData(200_000)); !errors.Is(err, ErrBatchFailed) {
				t.Fatalf("upload worker error = %v", err)
			}
		})
	}

	client := newTestEngine(t, newMemoryProtocol())
	batch, err := client.NewUploadBatch(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	batch.files = append(batch.files, uploadedFile{chunkNodes: []xethash.Node{{Hash: xethash.Zero, Size: 1}}})
	if _, err := batch.Finalize(); err == nil {
		t.Fatal("malformed uploaded file finalized")
	}

	protocol := newMemoryProtocol()
	client = newTestEngine(t, protocol)
	batch, err = client.NewUploadBatch(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	duplicate := uploadedFile{info: FileInfo{Hash: xethash.Zero}}
	batch.files = append(batch.files, duplicate, duplicate)
	batch.composed = append(batch.composed, shard.File{Hash: xethash.Zero})
	if report, err := batch.Finalize(); err != nil || !report.ShardUploaded {
		t.Fatalf("duplicate-file finalization = %#v, %v", report, err)
	}
	protocol.mu.Lock()
	defer protocol.mu.Unlock()
	if protocol.metadata == nil || len(protocol.metadata.Files) != 1 {
		t.Fatalf("deduplicated metadata = %#v", protocol.metadata)
	}
}

func TestAddNovelChunkPropagatesAutomaticFlushFailure(t *testing.T) {
	client := newTestEngine(t, newMemoryProtocol())
	batch, err := client.NewUploadBatch(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer batch.Abort(nil)
	batch.current = &pendingXorb{
		chunks:         [][]byte{[]byte("existing")},
		rawBytes:       xorb.MaxRawSize,
		fileBoundaries: []int{0},
	}
	batch.client.options.Compression = xorb.Scheme(42)
	if _, err := batch.addNovelChunk([]byte("next"), 1); err == nil {
		t.Fatal("automatic flush failure was ignored")
	}
}

type journalFault struct {
	has      bool
	hasErr   error
	markErr  error
	clearErr error
}

type cacheStub struct {
	rangeData    []byte
	rangeFound   bool
	shardData    []byte
	shardFound   bool
	deletedRange int
	deletedShard int
	putRange     int
	putShard     int
}

func (c *cacheStub) GetXorbRange(context.Context, xethash.Hash, uint32, uint32) ([]byte, bool, error) {
	return append([]byte(nil), c.rangeData...), c.rangeFound, nil
}
func (c *cacheStub) PutXorbRange(context.Context, xethash.Hash, uint32, uint32, []byte) error {
	c.putRange++
	return nil
}
func (c *cacheStub) DeleteXorbRange(context.Context, xethash.Hash, uint32, uint32) error {
	c.deletedRange++
	return nil
}
func (c *cacheStub) GetShard(context.Context, xethash.Hash) ([]byte, bool, error) {
	return append([]byte(nil), c.shardData...), c.shardFound, nil
}
func (c *cacheStub) PutShard(context.Context, xethash.Hash, []byte, time.Time) error {
	c.putShard++
	return nil
}
func (c *cacheStub) DeleteShard(context.Context, xethash.Hash) error {
	c.deletedShard++
	return nil
}

func (j *journalFault) HasXorb(context.Context, xethash.Hash) (bool, error) { return j.has, j.hasErr }
func (j *journalFault) MarkXorb(context.Context, xethash.Hash) error        { return j.markErr }
func (j *journalFault) Clear(context.Context) error                         { return j.clearErr }

func TestUploadJournalWorkerFailuresAreTransactional(t *testing.T) {
	for name, journal := range map[string]*journalFault{
		"inspect": {hasErr: errors.New("inspect failed")},
		"mark":    {markErr: errors.New("mark failed")},
	} {
		t.Run(name, func(t *testing.T) {
			client, err := NewClient(newMemoryProtocol(), Options{
				Compression: xorb.None, CompressionSet: true, UploadConcurrency: 1, DownloadConcurrency: 1,
				UploadJournal: journal,
			})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := client.UploadBytes(context.Background(), deterministicData(200_000)); !errors.Is(err, ErrBatchFailed) {
				t.Fatalf("upload error = %v", err)
			}
		})
	}

	journal := &journalFault{clearErr: errors.New("clear failed")}
	client, err := NewClient(newMemoryProtocol(), Options{
		Compression: xorb.None, CompressionSet: true, UploadConcurrency: 1, DownloadConcurrency: 1,
		UploadJournal: journal,
	})
	if err != nil {
		t.Fatal(err)
	}
	result, err := client.UploadBytes(context.Background(), deterministicData(200_000))
	if err != nil {
		t.Fatal(err)
	}
	if result.Report.JournalCleared {
		t.Fatal("failed journal clear reported success")
	}
}

func TestUploadProgressAndFlushFailureContracts(t *testing.T) {
	var phases []ProgressPhase
	client, err := NewClient(newMemoryProtocol(), Options{
		Compression: xorb.None, CompressionSet: true, UploadConcurrency: 1, DownloadConcurrency: 1,
		Progress: func(value Progress) { phases = append(phases, value.Phase) },
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.UploadBytes(context.Background(), deterministicData(200_000)); err != nil {
		t.Fatal(err)
	}
	for _, want := range []ProgressPhase{ProgressChunking, ProgressUploadingXorb, ProgressUploadingShard} {
		found := false
		for _, got := range phases {
			found = found || got == want
		}
		if !found {
			t.Errorf("missing progress phase %q in %v", want, phases)
		}
	}

	flushContext, cancelFlush := context.WithCancel(context.Background())
	batch := &UploadBatch{
		client: client, ctx: flushContext, cancel: cancelFlush, current: &pendingXorb{},
		tasks: make(chan xorbUploadTask),
	}
	if _, err := batch.addNovelChunk([]byte("x"), 1); err != nil {
		t.Fatal(err)
	}
	want := errors.New("canceled flush")
	batch.setFailure(want)
	if err := batch.flushCurrent(); !errors.Is(err, want) {
		t.Fatalf("canceled flush = %v", err)
	}

	batch, err = client.NewUploadBatch(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer batch.Abort(nil)
	if _, err := batch.addNovelChunk([]byte("x"), 1); err != nil {
		t.Fatal(err)
	}
	batch.client.options.Compression = xorb.Scheme(42)
	if err := batch.flushCurrent(); err == nil {
		t.Fatal("flush with invalid compression succeeded")
	}
}

func TestGlobalShardCacheFailureAndHitContracts(t *testing.T) {
	query := xethash.Chunk([]byte("query"))
	cache := &cacheStub{shardData: []byte("corrupt"), shardFound: true}
	client, err := NewClient(newMemoryProtocol(), Options{
		Compression: xorb.None, CompressionSet: true, UploadConcurrency: 1, DownloadConcurrency: 1,
		GlobalDedup: true, Cache: cache,
	})
	if err != nil {
		t.Fatal(err)
	}
	batch, err := client.NewUploadBatch(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer batch.Abort(nil)
	batch.loadGlobalShard(query)
	batch.loadGlobalShard(query)
	if cache.deletedShard != 1 || len(batch.global) != 0 {
		t.Fatalf("corrupt cached shard: deleted=%d global=%d", cache.deletedShard, len(batch.global))
	}

	data := []byte("global chunk")
	object, err := xorb.Encode([][]byte{data}, xorb.None)
	if err != nil {
		t.Fatal(err)
	}
	xorbInfo, err := shard.XorbFromObject(object)
	if err != nil {
		t.Fatal(err)
	}
	shardBody, err := shard.EncodeUpload(shard.Shard{Xorbs: []shard.Xorb{xorbInfo}})
	if err != nil {
		t.Fatal(err)
	}
	cache = &cacheStub{shardData: shardBody, shardFound: true}
	client.options.Cache = cache
	batch, err = client.NewUploadBatch(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer batch.Abort(nil)
	chunkHash := xethash.Chunk(data)
	batch.loadGlobalShard(chunkHash)
	if len(batch.global) != 1 {
		t.Fatalf("valid cached shard indexes = %d", len(batch.global))
	}
	if placement, ok := batch.lookupGlobal(chunkHash, uint32(len(data))); !ok || placement.externalHash != object.Hash {
		t.Fatalf("global placement = %#v, %v", placement, ok)
	}
	if _, ok := batch.lookupGlobal(chunkHash, uint32(len(data)+1)); ok {
		t.Fatal("global placement ignored length")
	}

	cache = &cacheStub{shardData: shardBody, shardFound: true}
	client.options.Cache = cache
	batch, err = client.NewUploadBatch(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer batch.Abort(nil)
	batch.loadGlobalShard(xethash.Chunk([]byte("absent")))
	if cache.deletedShard != 1 {
		t.Fatal("cached shard missing query was not evicted")
	}

	client.options.Cache = nil
	batch, err = client.NewUploadBatch(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer batch.Abort(nil)
	batch.loadGlobalShard(xethash.Chunk([]byte("network miss")))
	if len(batch.global) != 0 {
		t.Fatal("missing network shard produced an index")
	}
}

func TestGlobalShardNetworkCachingAndExpiryContracts(t *testing.T) {
	protocol := newMemoryProtocol()
	seedClient := newTestEngine(t, protocol)
	data := deterministicData(200_000)
	if _, err := seedClient.UploadBytes(context.Background(), data); err != nil {
		t.Fatal(err)
	}
	query := xethash.Chunk(chunker.Bytes(data)[0].Data)
	protocol.mu.Lock()
	protected, err := makeProtectedGlobalShard(*protocol.metadata, xethash.Chunk([]byte("cache key")))
	if err == nil {
		protocol.globalShard = protected
	}
	protocol.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}

	cache := &cacheStub{}
	client, err := NewClient(protocol, Options{
		Compression: xorb.None, CompressionSet: true,
		UploadConcurrency: 1, DownloadConcurrency: 1, GlobalDedup: true, Cache: cache,
	})
	if err != nil {
		t.Fatal(err)
	}
	batch, err := client.NewUploadBatch(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer batch.Abort(nil)
	batch.loadGlobalShard(query)
	if len(batch.global) != 1 || cache.putShard != 1 {
		t.Fatalf("network shard cache = indexes %d, puts %d", len(batch.global), cache.putShard)
	}

	expired := append([]byte(nil), protected...)
	footer := len(expired) - shard.FooterSize
	binary.LittleEndian.PutUint64(expired[footer+112:footer+120], uint64(time.Now().Add(-time.Hour).Unix()))
	cache = &cacheStub{shardData: expired, shardFound: true}
	client.options.Cache = cache
	batch, err = client.NewUploadBatch(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer batch.Abort(nil)
	batch.loadGlobalShard(query)
	if len(batch.global) != 0 || cache.deletedShard != 1 {
		t.Fatalf("expired cached shard = indexes %d, deletes %d", len(batch.global), cache.deletedShard)
	}
}

func TestDeltaHelperContracts(t *testing.T) {
	if _, err := deltaResultSize(0, []DeltaEdit{{Original: xetcas.FileRange{Start: 0, End: 1}}}); err == nil {
		t.Fatal("delta size underflow succeeded")
	}
	if _, err := deltaResultSize(math.MaxUint64, []DeltaEdit{{NewLength: 1}}); err == nil {
		t.Fatal("delta size overflow succeeded")
	}
	if starts, err := reconstructionSegmentStarts([]xetcas.ReconstructionTerm{{UnpackedLength: 2}}, 3); err == nil || starts != nil {
		t.Fatalf("mismatched reconstruction starts = %v, %v", starts, err)
	}
	starts := []uint64{0, 10, 20, 30}
	ranges := snapDeltaRanges([]DeltaEdit{
		{Original: xetcas.FileRange{Start: 10, End: 10}},
		{Original: xetcas.FileRange{Start: 20, End: 20}},
		{Original: xetcas.FileRange{Start: 30, End: 30}},
	}, starts, 30)
	if len(ranges) != 1 || ranges[0] != (xetcas.FileRange{Start: 10, End: 30}) {
		t.Fatalf("snapped insertion ranges = %#v", ranges)
	}
	if !isSegmentBoundary(starts, 20) || isSegmentBoundary(starts, 21) {
		t.Fatal("segment boundary classification differs")
	}
	if !deltaEditBelongsToWindow(DeltaEdit{Original: xetcas.FileRange{Start: 30, End: 30}}, 30, 30) ||
		deltaEditBelongsToWindow(DeltaEdit{Original: xetcas.FileRange{Start: 20, End: 25}}, 24, 30) {
		t.Fatal("window edit classification differs")
	}
	if _, err := editedWindowSize(0, 1, []DeltaEdit{{Original: xetcas.FileRange{Start: 0, End: 2}}}); err == nil {
		t.Fatal("edited window underflow succeeded")
	}
	if _, err := editedWindowSize(0, math.MaxUint64, []DeltaEdit{{NewLength: 1}}); err == nil {
		t.Fatal("edited window overflow succeeded")
	}
	if err := copyExactly(io.Discard, nil, 1); err == nil {
		t.Fatal("nil delta source succeeded")
	}
	if err := copyExactly(io.Discard, strings.NewReader("x"), 2); !errors.Is(err, io.EOF) {
		t.Fatalf("short delta source = %v", err)
	}
	if err := copyExactly(io.Discard, strings.NewReader("xy"), 2); err != nil {
		t.Fatalf("exact delta source = %v", err)
	}

	if _, err := mergeDeltaHash(nil, []deltaUploadedWindow{{}}); err == nil {
		t.Fatal("mismatched delta hash ranges succeeded")
	}
	if root, err := mergeDeltaHash([]*xethash.MerkleHashSubtree{nil}, nil); err != nil || root != xethash.Zero {
		t.Fatalf("empty delta root = %v, %v", root, err)
	}
	if _, err := mergeDeltaHash([]*xethash.MerkleHashSubtree{xethash.NewSubtree(false, nil, false)}, nil); err == nil {
		t.Fatal("open delta subtree produced a root")
	}
}

func TestComposeDeltaTermsContracts(t *testing.T) {
	hash := xethash.Chunk([]byte("xorb"))
	original := []xetcas.ReconstructionTerm{{Hash: hash, UnpackedLength: 10, Range: xetcas.ChunkRange{Start: 0, End: 1}}}
	starts := []uint64{0, 10}
	if _, err := composeDeltaTerms(original, starts, nil, nil); err == nil {
		t.Fatal("missing gap verification succeeded")
	}
	if _, err := composeDeltaTerms(nil, []uint64{0}, nil, []xethash.Hash{xethash.Zero}); err == nil {
		t.Fatal("extra gap verification succeeded")
	}
	window := deltaUploadedWindow{start: 5, end: 10}
	if _, err := composeDeltaTerms(original, starts, []deltaUploadedWindow{window}, nil); err == nil {
		t.Fatal("window starting inside a segment succeeded")
	}
	window = deltaUploadedWindow{start: 0, end: 5}
	if _, err := composeDeltaTerms(original, starts, []deltaUploadedWindow{window}, nil); err == nil {
		t.Fatal("window ending inside a segment succeeded")
	}
}

type protocolWithoutDelta struct{ Protocol }

type deltaFaultProtocol struct {
	*memoryProtocol
	reconstruction    *xetcas.Reconstruction
	reconstructionErr error
}

func (p *deltaFaultProtocol) QueryReconstruction(context.Context, xethash.Hash, *xetcas.FileRange) (*xetcas.Reconstruction, error) {
	return p.reconstruction, p.reconstructionErr
}

func TestUploadDeltaEarlyFailureContracts(t *testing.T) {
	client := newTestEngine(t, newMemoryProtocol())
	if _, err := client.UploadDelta(nil, FileInfo{}, nil); err == nil { //nolint:staticcheck // Verify that the API rejects a nil context.
		t.Fatal("nil delta context succeeded")
	}
	original := FileInfo{Hash: xethash.Chunk([]byte("original")), Size: 10}
	result, err := client.UploadDelta(context.Background(), original, nil)
	if err != nil || result.File != original || !result.Report.CompletedAt.After(time.Time{}) {
		t.Fatalf("no-op delta = %#v, %v", result, err)
	}
	withoutDelta, err := NewClient(protocolWithoutDelta{Protocol: newMemoryProtocol()}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := withoutDelta.UploadDelta(context.Background(), original, []DeltaEdit{{
		Original: xetcas.FileRange{Start: 0, End: 1}, Reader: strings.NewReader("x"), NewLength: 1,
	}}); err == nil {
		t.Fatal("delta upload without v2 protocol succeeded")
	}
}

func TestUploadDeltaRejectsServerWindowFaults(t *testing.T) {
	protocol := newMemoryProtocol()
	client := newTestEngine(t, protocol)
	data := deterministicData(200_000)
	upload, err := client.UploadBytes(context.Background(), data)
	if err != nil {
		t.Fatal(err)
	}
	edit := []DeltaEdit{{Original: xetcas.FileRange{Start: 10, End: 11}, Reader: strings.NewReader("x"), NewLength: 1}}

	if _, err := client.UploadDelta(context.Background(), upload.File, edit); err == nil {
		t.Fatal("missing file-chunk response succeeded")
	}
	protocol.fileChunks = &xetcas.FileChunkHashesResponse{FileSize: upload.File.Size + 1}
	if _, err := client.UploadDelta(context.Background(), upload.File, edit); err == nil {
		t.Fatal("wrong server file size succeeded")
	}
	protocol.fileChunks = &xetcas.FileChunkHashesResponse{FileSize: upload.File.Size}
	if _, err := client.UploadDelta(context.Background(), upload.File, edit); err == nil {
		t.Fatal("empty server windows succeeded")
	}
	protocol.fileChunks = &xetcas.FileChunkHashesResponse{
		FileSize: upload.File.Size,
		Windows:  []xetcas.ChunkWindow{{DirtyByteRange: [2]uint64{1, upload.File.Size}}},
	}
	if _, err := client.UploadDelta(context.Background(), upload.File, edit); err == nil {
		t.Fatal("misaligned server window succeeded")
	}
}

func TestUploadDeltaProtocolAndTransactionalFailures(t *testing.T) {
	edit := []DeltaEdit{{
		Original: xetcas.FileRange{Start: 0, End: 1}, Reader: strings.NewReader("x"), NewLength: 1,
	}}
	for name, protocol := range map[string]*deltaFaultProtocol{
		"query": {
			memoryProtocol:    newMemoryProtocol(),
			reconstructionErr: errors.New("query failed"),
		},
		"validation": {
			memoryProtocol: newMemoryProtocol(),
			reconstruction: &xetcas.Reconstruction{
				OffsetIntoFirstRange: 1,
			},
		},
	} {
		t.Run(name, func(t *testing.T) {
			client, err := NewClient(protocol, Options{})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := client.UploadDelta(context.Background(), FileInfo{Hash: xethash.Zero, Size: 1}, edit); err == nil {
				t.Fatal("faulty reconstruction succeeded")
			}
		})
	}

	protocol := newMemoryProtocol()
	client := newTestEngine(t, protocol)
	original, err := client.UploadBytes(context.Background(), deterministicData(200_000))
	if err != nil {
		t.Fatal(err)
	}
	base := &xetcas.FileChunkHashesResponse{
		FileSize: original.File.Size,
		Windows:  []xetcas.ChunkWindow{{DirtyByteRange: [2]uint64{0, original.File.Size}}},
	}

	protocol.fileChunks = &xetcas.FileChunkHashesResponse{
		FileSize: original.File.Size,
		Windows:  []xetcas.ChunkWindow{{DirtyByteRange: [2]uint64{0, 0}}},
	}
	if _, err := client.UploadDelta(context.Background(), original.File, []DeltaEdit{{
		Original: xetcas.FileRange{Start: 10, End: 11}, Reader: strings.NewReader("x"), NewLength: 1,
	}}); err == nil || !strings.Contains(err.Error(), "contains no requested edit") {
		t.Fatalf("empty server window error = %v", err)
	}

	value := *base
	protocol.fileChunks = &value
	if _, err := client.UploadDelta(context.Background(), original.File, []DeltaEdit{{
		Original: xetcas.FileRange{Start: 10, End: 11}, Reader: strings.NewReader("x"), NewLength: 2,
	}}); err == nil {
		t.Fatal("short window edit succeeded")
	}

	value = *base
	protocol.fileChunks = &value
	client.options.Compression = xorb.Scheme(42)
	if _, err := client.UploadDelta(context.Background(), original.File, []DeltaEdit{{
		Original: xetcas.FileRange{Start: 10, End: 11}, Reader: strings.NewReader("x"), NewLength: 1,
	}}); err == nil {
		t.Fatal("delta flush failure succeeded")
	}
	client.options.Compression = xorb.None

	value = *base
	protocol.fileChunks = &value
	if _, err := client.UploadDelta(context.Background(), original.File, []DeltaEdit{{
		Original: xetcas.FileRange{Start: 10, End: 11}, Reader: strings.NewReader("x"), NewLength: 1,
	}}); err == nil || !strings.Contains(err.Error(), "hash-range/window count") {
		t.Fatalf("delta hash merge error = %v", err)
	}

	value = *base
	value.HashRanges = []*xethash.MerkleHashSubtree{nil, nil}
	value.GapVerification = []xethash.Hash{xethash.Zero}
	protocol.fileChunks = &value
	if _, err := client.UploadDelta(context.Background(), original.File, []DeltaEdit{{
		Original: xetcas.FileRange{Start: 10, End: 11}, Reader: strings.NewReader("x"), NewLength: 1,
	}}); err == nil || !strings.Contains(err.Error(), "extra gap-verification") {
		t.Fatalf("delta term composition error = %v", err)
	}

	value.GapVerification = nil
	protocol.fileChunks = &value
	protocol.shardFailures = 1
	if _, err := client.UploadDelta(context.Background(), original.File, []DeltaEdit{{
		Original: xetcas.FileRange{Start: 10, End: 11}, Reader: strings.NewReader("x"), NewLength: 1,
	}}); err == nil {
		t.Fatal("delta shard upload failure succeeded")
	}
}

func TestDeltaWindowReaderPropagatesProducerFailures(t *testing.T) {
	drain := func(t *testing.T, reader *io.PipeReader, result <-chan error) error {
		t.Helper()
		_, _ = io.Copy(io.Discard, reader)
		return <-result
	}
	client := newTestEngine(t, newMemoryProtocol())
	reader, result := client.deltaWindowReader(context.Background(), xethash.Zero, 10, 20, []DeltaEdit{{
		Original: xetcas.FileRange{Start: 9, End: 10},
	}})
	if err := drain(t, reader, result); err == nil || !strings.Contains(err.Error(), "outside") {
		t.Fatalf("outside-window edit = %v", err)
	}

	fault := &deltaFaultProtocol{memoryProtocol: newMemoryProtocol(), reconstructionErr: errors.New("download failed")}
	client, err := NewClient(fault, Options{})
	if err != nil {
		t.Fatal(err)
	}
	reader, result = client.deltaWindowReader(context.Background(), xethash.Zero, 10, 20, []DeltaEdit{{
		Original: xetcas.FileRange{Start: 15, End: 20},
	}})
	if err := drain(t, reader, result); err == nil {
		t.Fatal("failed unchanged-prefix download succeeded")
	}

	reader, result = client.deltaWindowReader(context.Background(), xethash.Zero, 0, 1, []DeltaEdit{{
		Original: xetcas.FileRange{Start: 0, End: 1}, Reader: strings.NewReader("x"), NewLength: 2,
	}})
	if err := drain(t, reader, result); err == nil {
		t.Fatal("short edit source succeeded")
	}

	reader, result = client.deltaWindowReader(context.Background(), xethash.Zero, 0, 1, nil)
	if err := drain(t, reader, result); err == nil {
		t.Fatal("failed unchanged-suffix download succeeded")
	}
}

func TestExactLengthReaderContracts(t *testing.T) {
	reader := &exactLengthReader{source: strings.NewReader("x"), remaining: 2}
	buffer := make([]byte, 4)
	if n, err := reader.Read(buffer); n != 1 || err != nil {
		t.Fatalf("first short exact read = %d, %v", n, err)
	}
	if n, err := reader.Read(buffer); n != 0 || !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("terminal short exact read = %d, %v", n, err)
	}
	reader = &exactLengthReader{source: strings.NewReader("ignored")}
	if n, err := reader.Read(buffer); n != 0 || !errors.Is(err, io.EOF) {
		t.Fatalf("complete exact read = %d, %v", n, err)
	}
}

type invalidCountWriter struct {
	count int
	err   error
}

func (w invalidCountWriter) Write([]byte) (int, error) { return w.count, w.err }

func TestDownloadWriterAndPlanningContracts(t *testing.T) {
	client := newTestEngine(t, newMemoryProtocol())
	if _, err := client.Download(context.Background(), FileInfo{}, nil); err == nil {
		t.Fatal("nil complete writer succeeded")
	}
	if _, err := client.DownloadRange(context.Background(), xethash.Zero, xetcas.FileRange{Start: 0, End: 1}, nil); err == nil {
		t.Fatal("nil range writer succeeded")
	}
	if _, err := client.DownloadRange(context.Background(), xethash.Zero, xetcas.FileRange{}, io.Discard); err == nil {
		t.Fatal("invalid download range succeeded")
	}
	if _, err := client.download(nil, FileInfo{}, nil, io.Discard); err == nil { //nolint:staticcheck // Verify the internal nil-context guard.
		t.Fatal("nil download context succeeded")
	}

	for _, count := range []int{-1, 2} {
		writer, err := newVerifyingWriter(context.Background(), invalidCountWriter{count: count})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := writer.Write([]byte("x")); err == nil {
			t.Errorf("writer count %d succeeded", count)
		}
	}
	writer, err := newVerifyingWriter(context.Background(), invalidCountWriter{count: 0})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write([]byte("x")); !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("verifying short write = %v", err)
	}

	crop := &croppingWriter{dst: &bytes.Buffer{}, skip: 2, remaining: 2, limited: true}
	if n, err := crop.Write([]byte("abcdef")); err != nil || n != 6 || crop.written != 2 || crop.remaining != 0 || crop.skip != 0 {
		t.Fatalf("cropping write = %d, %v, %#v", n, err, crop)
	}
	crop = &croppingWriter{dst: invalidCountWriter{count: 0}}
	if _, err := crop.Write([]byte("x")); !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("cropping short write = %v", err)
	}

	hash := xethash.Chunk([]byte("xorb"))
	descriptor := xetcas.XorbRangeDescriptor{
		Chunks: xetcas.ChunkRange{Start: 0, End: 1}, Bytes: xetcas.HTTPRange{Start: 0, End: 1},
	}
	reconstruction := &xetcas.Reconstruction{Xorbs: map[xethash.Hash][]xetcas.MultiRangeFetch{
		hash: {{URL: "https://storage.example/x", Ranges: []xetcas.XorbRangeDescriptor{descriptor, descriptor}}},
	}}
	if _, _, err := planDownloads(reconstruction); err == nil {
		t.Fatal("duplicate fetch descriptor succeeded")
	}
	reconstruction = &xetcas.Reconstruction{Terms: []xetcas.ReconstructionTerm{{
		Hash: hash, UnpackedLength: 1, Range: xetcas.ChunkRange{Start: 0, End: 1},
	}}}
	if _, _, err := planDownloads(reconstruction); err == nil {
		t.Fatal("term without descriptor succeeded")
	}
}

func TestWholeReconstructionRejectsInitialOffset(t *testing.T) {
	hash := xethash.Chunk([]byte("xorb"))
	reconstruction := &xetcas.Reconstruction{
		OffsetIntoFirstRange: 1,
		Terms: []xetcas.ReconstructionTerm{{
			Hash: hash, UnpackedLength: 2, Range: xetcas.ChunkRange{Start: 0, End: 1},
		}},
		Xorbs: map[xethash.Hash][]xetcas.MultiRangeFetch{hash: {{
			URL: "https://storage.example/x", Ranges: []xetcas.XorbRangeDescriptor{{
				Chunks: xetcas.ChunkRange{Start: 0, End: 1}, Bytes: xetcas.HTTPRange{Start: 0, End: 0},
			}},
		}}},
	}
	client := newTestEngine(t, newMemoryProtocol())
	if _, err := client.executeReconstruction(context.Background(), FileInfo{}, nil, reconstruction, io.Discard, 0); err == nil {
		t.Fatal("whole reconstruction with initial offset succeeded")
	}
}

type fetchedProtocol struct {
	*memoryProtocol
	result []xetcas.FetchedRange
	err    error
}

func (p *fetchedProtocol) FetchRanges(context.Context, string, []xetcas.HTTPRange) ([]xetcas.FetchedRange, error) {
	return p.result, p.err
}

func TestFetchJobRejectsMalformedStorageResponses(t *testing.T) {
	data := []byte("chunk")
	object, err := xorb.Encode([][]byte{data}, xorb.None)
	if err != nil {
		t.Fatal(err)
	}
	hash := object.Hash
	rangeValue := xetcas.HTTPRange{Start: 0, End: uint64(len(object.Body) - 1)}
	descriptor := &downloadDescriptor{hash: hash, desc: xetcas.XorbRangeDescriptor{
		Chunks: xetcas.ChunkRange{Start: 0, End: 1}, Bytes: rangeValue,
	}}
	job := &downloadJob{url: "https://storage.example/x", ranges: []xetcas.HTTPRange{rangeValue}, descriptors: []*downloadDescriptor{descriptor}}

	for name, protocol := range map[string]*fetchedProtocol{
		"network": {memoryProtocol: newMemoryProtocol(), err: errors.New("fetch failed")},
		"duplicate": {memoryProtocol: newMemoryProtocol(), result: []xetcas.FetchedRange{
			{Range: rangeValue, Data: object.Body}, {Range: rangeValue, Data: object.Body},
		}},
		"omitted": {memoryProtocol: newMemoryProtocol()},
		"corrupt": {memoryProtocol: newMemoryProtocol(), result: []xetcas.FetchedRange{{Range: rangeValue, Data: []byte("bad")}}},
	} {
		t.Run(name, func(t *testing.T) {
			client := &Client{protocol: protocol, options: Options{}}
			if result := client.fetchJob(context.Background(), job); result.err == nil {
				t.Fatal("malformed storage response succeeded")
			}
		})
	}

	twoChunks, err := xorb.Encode([][]byte{[]byte("a"), []byte("b")}, xorb.None)
	if err != nil {
		t.Fatal(err)
	}
	protocol := &fetchedProtocol{memoryProtocol: newMemoryProtocol(), result: []xetcas.FetchedRange{{Range: rangeValue, Data: twoChunks.Body}}}
	client := &Client{protocol: protocol, options: Options{}}
	if result := client.fetchJob(context.Background(), job); result.err == nil {
		t.Fatal("wrong fetched chunk count succeeded")
	}

	cache := &cacheStub{rangeData: []byte("corrupt"), rangeFound: true}
	protocol = &fetchedProtocol{memoryProtocol: newMemoryProtocol(), result: []xetcas.FetchedRange{{Range: rangeValue, Data: object.Body}}}
	client = &Client{protocol: protocol, options: Options{Cache: cache}}
	if result := client.fetchJob(context.Background(), job); result.err != nil || cache.deletedRange != 1 || cache.putRange != 1 {
		t.Fatalf("corrupt cache recovery = %#v, cache=%#v", result, cache)
	}

	cache = &cacheStub{rangeData: object.Body, rangeFound: true}
	client = &Client{protocol: &fetchedProtocol{memoryProtocol: newMemoryProtocol(), err: errors.New("network must not run")}, options: Options{Cache: cache}}
	result := client.fetchJob(context.Background(), job)
	if result.err != nil || result.cacheRanges != 1 || result.fetched != 0 {
		t.Fatalf("cache hit = %#v", result)
	}
}

func TestExecuteReconstructionPlanningAndRangeContracts(t *testing.T) {
	hash := xethash.Chunk([]byte("xorb"))
	descriptor := xetcas.XorbRangeDescriptor{
		Chunks: xetcas.ChunkRange{Start: 0, End: 1}, Bytes: xetcas.HTTPRange{Start: 0, End: 0},
	}
	reconstruction := &xetcas.Reconstruction{
		Terms: []xetcas.ReconstructionTerm{{
			Hash: hash, UnpackedLength: 1, Range: xetcas.ChunkRange{Start: 0, End: 1},
		}},
		Xorbs: map[xethash.Hash][]xetcas.MultiRangeFetch{hash: {
			{URL: "https://storage.example/one", Ranges: []xetcas.XorbRangeDescriptor{descriptor}},
			{URL: "https://storage.example/two", Ranges: []xetcas.XorbRangeDescriptor{descriptor}},
		}},
	}
	client := newTestEngine(t, newMemoryProtocol())
	if _, err := client.executeReconstruction(context.Background(), FileInfo{}, nil, reconstruction, io.Discard, 0); err == nil {
		t.Fatal("duplicate planned descriptor succeeded")
	}
	if _, err := client.executeReconstruction(context.Background(), FileInfo{}, nil, nil, io.Discard, 0); err == nil {
		t.Fatal("nil reconstruction succeeded")
	}
}

func TestDownloadExhaustsRefreshedSignedURL(t *testing.T) {
	protocol := newMemoryProtocol()
	client := newTestEngine(t, protocol)
	upload, err := client.UploadBytes(context.Background(), deterministicData(200_000))
	if err != nil {
		t.Fatal(err)
	}
	protocol.mu.Lock()
	protocol.expireFetches = 2
	protocol.mu.Unlock()
	if _, err := client.Download(context.Background(), upload.File, io.Discard); !errors.Is(err, xetcas.ErrSignedURLExpired) {
		t.Fatalf("repeated signed URL expiry = %v", err)
	}
}

func TestExecuteReconstructionResourceAndIntegrityContracts(t *testing.T) {
	data := []byte("verified reconstruction bytes")
	object, err := xorb.Encode([][]byte{data}, xorb.None)
	if err != nil {
		t.Fatal(err)
	}
	physical := xetcas.HTTPRange{Start: 0, End: uint64(len(object.Body) - 1)}
	reconstruction := &xetcas.Reconstruction{
		Terms: []xetcas.ReconstructionTerm{{
			Hash: object.Hash, UnpackedLength: uint32(len(data)), Range: xetcas.ChunkRange{Start: 0, End: 1},
		}},
		Xorbs: map[xethash.Hash][]xetcas.MultiRangeFetch{
			object.Hash: {{
				URL: "https://storage.example/xorb",
				Ranges: []xetcas.XorbRangeDescriptor{{
					Chunks: xetcas.ChunkRange{Start: 0, End: 1}, Bytes: physical,
				}},
			}},
		},
	}
	fileHash := xethash.File([]xethash.Node{{Hash: xethash.Chunk(data), Size: uint64(len(data))}})
	file := FileInfo{Hash: fileHash, Size: uint64(len(data))}
	newClient := func(maxMemory uint64, progress func(Progress)) *Client {
		protocol := &fetchedProtocol{
			memoryProtocol: newMemoryProtocol(),
			result:         []xetcas.FetchedRange{{Range: physical, Data: object.Body}},
		}
		return &Client{protocol: protocol, options: Options{
			DownloadConcurrency: 1, MaxDownloadMemory: maxMemory, Progress: progress,
		}}
	}

	client := newClient(1, nil)
	if _, err := client.executeReconstruction(context.Background(), file, nil, reconstruction, io.Discard, 0); err == nil || !strings.Contains(err.Error(), "working set") {
		t.Fatalf("download memory limit = %v", err)
	}

	want := errors.New("destination failed")
	client = newClient(xorb.MaxRawSize, nil)
	if _, err := client.executeReconstruction(context.Background(), file, nil, reconstruction, invalidCountWriter{err: want}, 0); !errors.Is(err, want) {
		t.Fatalf("destination error = %v", err)
	}

	var progress []Progress
	client = newClient(xorb.MaxRawSize, func(value Progress) { progress = append(progress, value) })
	var output bytes.Buffer
	report, err := client.executeReconstruction(context.Background(), file, nil, reconstruction, &output, 7)
	if err != nil || !bytes.Equal(output.Bytes(), data) || !report.WholeFileHash || len(progress) != 1 || progress[0].Completed != 7+uint64(len(data)) {
		t.Fatalf("verified reconstruction = report %#v, progress %#v, output %q, error %v", report, progress, output.Bytes(), err)
	}

	badLength := *reconstruction
	badLength.Terms = append([]xetcas.ReconstructionTerm(nil), reconstruction.Terms...)
	badLength.Terms[0].UnpackedLength++
	client = newClient(xorb.MaxRawSize, nil)
	if _, err := client.executeReconstruction(context.Background(), file, nil, &badLength, io.Discard, 0); err == nil || !strings.Contains(err.Error(), "decoded") {
		t.Fatalf("term length mismatch = %v", err)
	}

	requested := xetcas.FileRange{Start: 0, End: uint64(len(data) + 1)}
	client = newClient(xorb.MaxRawSize, nil)
	if _, err := client.executeReconstruction(context.Background(), FileInfo{}, &requested, reconstruction, io.Discard, 0); err == nil || !strings.Contains(err.Error(), "range reconstruction wrote") {
		t.Fatalf("short logical range = %v", err)
	}

	client = newClient(xorb.MaxRawSize, nil)
	oversized := file
	oversized.Size++
	if _, err := client.executeReconstruction(context.Background(), oversized, nil, reconstruction, io.Discard, 0); err == nil || !strings.Contains(err.Error(), "expected") {
		t.Fatalf("whole-file size mismatch = %v", err)
	}
}

func TestWindowedAndWriterCancellationContracts(t *testing.T) {
	fault := &deltaFaultProtocol{memoryProtocol: newMemoryProtocol(), reconstructionErr: errors.New("query failed")}
	client, err := NewClient(fault, Options{MaxReconstructionWindow: 1})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.downloadWindowed(context.Background(), FileInfo{Hash: xethash.Zero, Size: 1}, io.Discard); err == nil {
		t.Fatal("failed window query succeeded")
	}

	ctx, cancel := context.WithCancel(context.Background())
	writer, err := newVerifyingWriter(ctx, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	cancel()
	if _, err := writer.Write([]byte("canceled")); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled verifying writer = %v", err)
	}

	want := errors.New("cropped destination failed")
	crop := &croppingWriter{dst: invalidCountWriter{err: want}}
	if _, err := crop.Write([]byte("x")); !errors.Is(err, want) {
		t.Fatalf("cropped destination error = %v", err)
	}
}

func TestDownloadGroupRangeWriterContract(t *testing.T) {
	client := newTestEngine(t, newMemoryProtocol())
	data := deterministicData(200_000)
	upload, err := client.UploadBytes(context.Background(), data)
	if err != nil {
		t.Fatal(err)
	}
	requested := xetcas.FileRange{Start: 17, End: 117}
	var output bytes.Buffer
	report, err := client.DownloadGroup(context.Background(), []DownloadRequest{{
		File: upload.File, Range: &requested, Writer: &output,
	}})
	if err != nil || len(report.Downloads) != 1 || report.Downloads[0].Err != nil {
		t.Fatalf("range download group = %#v, %v", report, err)
	}
	if !bytes.Equal(output.Bytes(), data[requested.Start:requested.End]) {
		t.Fatal("range download-group bytes differ")
	}
}
