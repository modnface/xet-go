package server

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jmwoliver/xet-go/shard"
	"github.com/jmwoliver/xet-go/xetcas"
	"github.com/jmwoliver/xet-go/xethash"
	"github.com/jmwoliver/xet-go/xorb"
)

func onePayloadAuditResult(
	t testing.TB,
	service *Service,
	request PayloadAuditRequest,
) PayloadAuditResult {
	t.Helper()
	page, err := service.AuditBlobPayloads(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Items) != 1 || page.NextCursor != "" || page.Kind != request.Kind {
		t.Fatalf("payload audit page = %#v", page)
	}
	return page.Items[0]
}

func requirePayloadAuditResult(
	t testing.TB,
	result PayloadAuditResult,
	status AuditStatus,
	finding PayloadAuditFinding,
) {
	t.Helper()
	if result.Status != status || result.Finding != finding {
		t.Fatalf("payload audit result = status %q, finding %q, error %v, entry %#v",
			result.Status, result.Finding, result.Err, result.Entry)
	}
}

func TestAuditBlobPayloadsValidCanonicalObjects(t *testing.T) {
	graph := newAuditGraph(t)
	for _, kind := range []BlobKind{BlobXorb, BlobShard} {
		t.Run(string(kind), func(t *testing.T) {
			result := onePayloadAuditResult(t, graph.service, PayloadAuditRequest{Kind: kind})
			requirePayloadAuditResult(t, result, AuditStatusNoIssueFound, PayloadAuditFindingNone)
			if result.Entry.Key.Kind != kind || result.Err != nil {
				t.Fatalf("successful payload result = %#v", result)
			}
		})
	}
	if graph.authCalls.Load() != 0 {
		t.Fatalf("payload audit authorization calls = %d", graph.authCalls.Load())
	}
}

func TestAuditBlobPayloadsDetectsSameSizeCorruptionBeyondInventoryAudit(t *testing.T) {
	graph := newAuditGraph(t)
	graph.store.mu.Lock()
	body := graph.store.blobs[graph.xorb]
	graph.store.blobs[graph.xorb] = bytes.Repeat([]byte{0xff}, len(body))
	graph.store.mu.Unlock()

	inventory := oneAuditResult(t, graph.service, AuditRequest{Kind: AuditKindXorbRecord})
	requireAuditResult(t, inventory, AuditStatusNoIssueFound, AuditFindingNone)
	payload := onePayloadAuditResult(t, graph.service, PayloadAuditRequest{Kind: BlobXorb})
	requirePayloadAuditResult(t, payload, AuditStatusIssue, PayloadAuditFindingPayloadInvalid)
	if !errors.Is(payload.Err, ErrCorrupt) {
		t.Fatalf("corrupt Xorb payload error = %v", payload.Err)
	}
}

func TestAuditBlobPayloadsClassifiesMalformedAndMismatchedObjects(t *testing.T) {
	t.Run("truncated Xorb", func(t *testing.T) {
		graph := newAuditGraph(t)
		graph.store.mu.Lock()
		body := graph.store.blobs[graph.xorb]
		graph.store.blobs[graph.xorb] = append([]byte(nil), body[:len(body)-1]...)
		graph.store.mu.Unlock()
		result := onePayloadAuditResult(t, graph.service, PayloadAuditRequest{Kind: BlobXorb})
		requirePayloadAuditResult(t, result, AuditStatusIssue, PayloadAuditFindingPayloadInvalid)
	})

	t.Run("truncated shard", func(t *testing.T) {
		graph := newAuditGraph(t)
		graph.store.mu.Lock()
		body := graph.store.blobs[graph.shard]
		graph.store.blobs[graph.shard] = append([]byte(nil), body[:len(body)-1]...)
		graph.store.mu.Unlock()
		result := onePayloadAuditResult(t, graph.service, PayloadAuditRequest{Kind: BlobShard})
		requirePayloadAuditResult(t, result, AuditStatusIssue, PayloadAuditFindingPayloadInvalid)
	})

	t.Run("Xorb key mismatch", func(t *testing.T) {
		graph := newAuditGraph(t)
		wrong := BlobKey{Kind: BlobXorb, Hash: xethash.Chunk([]byte("wrong Xorb key"))}
		graph.store.mu.Lock()
		body := append([]byte(nil), graph.store.blobs[graph.xorb]...)
		delete(graph.store.blobs, graph.xorb)
		graph.store.blobs[wrong] = body
		graph.store.mu.Unlock()
		result := onePayloadAuditResult(t, graph.service, PayloadAuditRequest{Kind: BlobXorb})
		requirePayloadAuditResult(t, result, AuditStatusIssue, PayloadAuditFindingIdentityMismatch)
	})

	t.Run("shard key mismatch", func(t *testing.T) {
		graph := newAuditGraph(t)
		wrong := BlobKey{Kind: BlobShard, Hash: xethash.Chunk([]byte("wrong shard key"))}
		graph.store.mu.Lock()
		body := append([]byte(nil), graph.store.blobs[graph.shard]...)
		delete(graph.store.blobs, graph.shard)
		graph.store.blobs[wrong] = body
		graph.store.mu.Unlock()
		result := onePayloadAuditResult(t, graph.service, PayloadAuditRequest{Kind: BlobShard})
		requirePayloadAuditResult(t, result, AuditStatusIssue, PayloadAuditFindingIdentityMismatch)
	})

	t.Run("noncanonical durable forms", func(t *testing.T) {
		graph := newAuditGraph(t)
		graph.store.mu.RLock()
		xorbBody := append([]byte(nil), graph.store.blobs[graph.xorb]...)
		shardBody := append([]byte(nil), graph.store.blobs[graph.shard]...)
		graph.store.mu.RUnlock()
		object, err := xorb.Decode(xorbBody)
		if err != nil {
			t.Fatal(err)
		}
		noncanonicalXorb, err := xorb.EncodeComplete(object, [4]byte{1})
		if err != nil {
			t.Fatal(err)
		}
		decodedShard, err := shard.Decode(shardBody)
		if err != nil {
			t.Fatal(err)
		}
		noncanonicalShard, err := shard.EncodeUpload(shard.Shard{
			Files: decodedShard.Files, Xorbs: decodedShard.Xorbs,
		})
		if err != nil {
			t.Fatal(err)
		}
		for _, test := range []struct {
			kind BlobKind
			key  BlobKey
			body []byte
		}{
			{BlobXorb, BlobKey{Kind: BlobXorb, Hash: object.Hash}, noncanonicalXorb},
			{BlobShard, BlobKey{Kind: BlobShard, Hash: xethash.Chunk(noncanonicalShard)}, noncanonicalShard},
		} {
			store := NewMemoryStore()
			store.blobs[test.key] = test.body
			service := testService(t, store, nil)
			result := onePayloadAuditResult(t, service, PayloadAuditRequest{Kind: test.kind})
			requirePayloadAuditResult(t, result, AuditStatusIssue, PayloadAuditFindingPayloadInvalid)
		}
	})
}

type payloadAuditFaultStore struct {
	*MemoryStore
	get func(context.Context, BlobKey, *xetcas.HTTPRange) (io.ReadCloser, error)
}

func (s *payloadAuditFaultStore) Get(
	ctx context.Context,
	key BlobKey,
	wanted *xetcas.HTTPRange,
) (io.ReadCloser, error) {
	if s.get != nil {
		return s.get(ctx, key, wanted)
	}
	return s.MemoryStore.Get(ctx, key, wanted)
}

type payloadAuditListStore struct {
	BlobStore
	page   BlobPage
	err    error
	cancel context.CancelFunc
}

func (s *payloadAuditListStore) ListBlobs(
	context.Context,
	BlobKind,
	PageRequest,
) (BlobPage, error) {
	if s.cancel != nil {
		s.cancel()
	}
	return s.page, s.err
}

type observedReadCloser struct {
	io.Reader
	closed   atomic.Bool
	closeErr error
}

func (r *observedReadCloser) Close() error {
	r.closed.Store(true)
	return r.closeErr
}

func TestAuditBlobPayloadsClassifiesReadBoundariesAndClosesReaders(t *testing.T) {
	graph := newAuditGraph(t)
	graph.store.mu.RLock()
	body := append([]byte(nil), graph.store.blobs[graph.xorb]...)
	graph.store.mu.RUnlock()
	sentinel := errors.New("injected payload read failure")

	for name, get := range map[string]func(context.Context, BlobKey, *xetcas.HTTPRange) (io.ReadCloser, error){
		"missing after list": func(context.Context, BlobKey, *xetcas.HTTPRange) (io.ReadCloser, error) {
			return nil, ErrNotFound
		},
		"get failure": func(context.Context, BlobKey, *xetcas.HTTPRange) (io.ReadCloser, error) {
			return nil, sentinel
		},
		"nil reader": func(context.Context, BlobKey, *xetcas.HTTPRange) (io.ReadCloser, error) {
			return nil, nil
		},
	} {
		t.Run(name, func(t *testing.T) {
			faults := &payloadAuditFaultStore{MemoryStore: graph.store, get: get}
			graph.service.blobs = faults
			result := onePayloadAuditResult(t, graph.service, PayloadAuditRequest{Kind: BlobXorb})
			if name == "missing after list" {
				requirePayloadAuditResult(t, result, AuditStatusIssue, PayloadAuditFindingBlobMissing)
				if result.Err != nil {
					t.Fatalf("missing payload error = %v", result.Err)
				}
			} else {
				requirePayloadAuditResult(t, result, AuditStatusFailed, PayloadAuditFindingCheckFailed)
			}
		})
	}
	readerWithError := &observedReadCloser{Reader: bytes.NewReader(body)}
	graph.service.blobs = &payloadAuditFaultStore{
		MemoryStore: graph.store,
		get: func(context.Context, BlobKey, *xetcas.HTTPRange) (io.ReadCloser, error) {
			return readerWithError, sentinel
		},
	}
	result := onePayloadAuditResult(t, graph.service, PayloadAuditRequest{Kind: BlobXorb})
	requirePayloadAuditResult(t, result, AuditStatusFailed, PayloadAuditFindingCheckFailed)
	if !readerWithError.closed.Load() {
		t.Fatal("reader returned with a Get error was not closed")
	}

	for name, reader := range map[string]*observedReadCloser{
		"short read":   {Reader: bytes.NewReader(body[:len(body)-1])},
		"long read":    {Reader: bytes.NewReader(append(append([]byte(nil), body...), 0))},
		"read failure": {Reader: failingReader{err: sentinel}},
		"close failure": {
			Reader: bytes.NewReader(body), closeErr: sentinel,
		},
	} {
		t.Run(name, func(t *testing.T) {
			faults := &payloadAuditFaultStore{MemoryStore: graph.store}
			faults.get = func(context.Context, BlobKey, *xetcas.HTTPRange) (io.ReadCloser, error) {
				return reader, nil
			}
			graph.service.blobs = faults
			result := onePayloadAuditResult(t, graph.service, PayloadAuditRequest{Kind: BlobXorb})
			switch name {
			case "short read", "long read":
				requirePayloadAuditResult(t, result, AuditStatusIssue, PayloadAuditFindingSizeInvalid)
			default:
				requirePayloadAuditResult(t, result, AuditStatusFailed, PayloadAuditFindingCheckFailed)
				if !errors.Is(result.Err, sentinel) {
					t.Fatalf("payload I/O failure = %v", result.Err)
				}
			}
			if !reader.closed.Load() {
				t.Fatal("payload reader was not closed")
			}
		})
	}

	graph.service.blobs = graph.store
	oversized := graph.service.auditBlobPayload(context.Background(), BlobXorb, BlobEntry{
		Key: graph.xorb, Info: BlobInfo{Size: xorb.MaxCompleteSize + 1},
	})
	requirePayloadAuditResult(t, oversized, AuditStatusIssue, PayloadAuditFindingSizeInvalid)
}

type cancelingPayloadReader struct {
	reader io.Reader
	cancel context.CancelFunc
	closed atomic.Bool
	reads  atomic.Int32
}

func (r *cancelingPayloadReader) Read(buffer []byte) (int, error) {
	n, err := r.reader.Read(buffer[:min(len(buffer), 1)])
	if r.reads.Add(1) == 1 {
		r.cancel()
	}
	return n, err
}

func (r *cancelingPayloadReader) Close() error {
	r.closed.Store(true)
	return nil
}

type blockingPayloadReader struct {
	*io.PipeReader
	started chan struct{}
	once    sync.Once
	closed  atomic.Bool
}

func (r *blockingPayloadReader) Read(buffer []byte) (int, error) {
	r.once.Do(func() { close(r.started) })
	return r.PipeReader.Read(buffer)
}

func (r *blockingPayloadReader) Close() error {
	r.closed.Store(true)
	return r.PipeReader.Close()
}

func TestAuditBlobPayloadsCancellationReturnsNoCursor(t *testing.T) {
	graph := newAuditGraph(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if page, err := graph.service.AuditBlobPayloads(ctx, PayloadAuditRequest{Kind: BlobXorb}); !errors.Is(err, context.Canceled) || page.NextCursor != "" {
		t.Fatalf("pre-canceled payload audit = %#v, %v", page, err)
	}

	graph.store.mu.RLock()
	body := append([]byte(nil), graph.store.blobs[graph.xorb]...)
	graph.store.mu.RUnlock()
	ctx, cancel = context.WithCancel(context.Background())
	reader := &cancelingPayloadReader{reader: bytes.NewReader(body), cancel: cancel}
	faults := &payloadAuditFaultStore{MemoryStore: graph.store}
	faults.get = func(context.Context, BlobKey, *xetcas.HTTPRange) (io.ReadCloser, error) {
		return reader, nil
	}
	graph.service.blobs = faults
	page, err := graph.service.AuditBlobPayloads(ctx, PayloadAuditRequest{Kind: BlobXorb})
	if !errors.Is(err, context.Canceled) || page.NextCursor != "" || len(page.Items) != 0 {
		t.Fatalf("read-canceled payload audit = %#v, %v", page, err)
	}
	if !reader.closed.Load() {
		t.Fatal("canceled payload reader was not closed")
	}

	pipeReader, pipeWriter := io.Pipe()
	t.Cleanup(func() { _ = pipeWriter.Close() })
	ctx, cancel = context.WithCancel(context.Background())
	blocking := &blockingPayloadReader{PipeReader: pipeReader, started: make(chan struct{})}
	faults.get = func(context.Context, BlobKey, *xetcas.HTTPRange) (io.ReadCloser, error) {
		return blocking, nil
	}
	result := make(chan struct {
		page PayloadAuditPage
		err  error
	}, 1)
	go func() {
		page, err := graph.service.AuditBlobPayloads(ctx, PayloadAuditRequest{Kind: BlobXorb})
		result <- struct {
			page PayloadAuditPage
			err  error
		}{page: page, err: err}
	}()
	select {
	case <-blocking.started:
	case <-time.After(time.Second):
		t.Fatal("payload audit did not begin its blocking read")
	}
	cancel()
	select {
	case outcome := <-result:
		if !errors.Is(outcome.err, context.Canceled) || outcome.page.NextCursor != "" {
			t.Fatalf("blocked-read cancellation = %#v, %v", outcome.page, outcome.err)
		}
	case <-time.After(time.Second):
		t.Fatal("payload audit did not interrupt its blocking read")
	}
	if !blocking.closed.Load() {
		t.Fatal("blocking payload reader was not closed")
	}
}

type sequentialPayloadStore struct {
	*MemoryStore
	active atomic.Int32
	max    atomic.Int32
}

func (s *sequentialPayloadStore) Get(
	ctx context.Context,
	key BlobKey,
	wanted *xetcas.HTTPRange,
) (io.ReadCloser, error) {
	reader, err := s.MemoryStore.Get(ctx, key, wanted)
	if err != nil {
		return nil, err
	}
	active := s.active.Add(1)
	for {
		previous := s.max.Load()
		if active <= previous || s.max.CompareAndSwap(previous, active) {
			break
		}
	}
	return &sequentialPayloadReader{ReadCloser: reader, active: &s.active}, nil
}

type sequentialPayloadReader struct {
	io.ReadCloser
	active *atomic.Int32
	once   sync.Once
}

func (r *sequentialPayloadReader) Close() error {
	err := r.ReadCloser.Close()
	r.once.Do(func() { r.active.Add(-1) })
	return err
}

func TestAuditBlobPayloadsReadsOneObjectAtATimeAndPaginates(t *testing.T) {
	store := NewMemoryStore()
	for i := range 3 {
		complete, err := xorb.Encode([][]byte{[]byte(fmt.Sprintf("payload page object %d", i))}, xorb.None)
		if err != nil {
			t.Fatal(err)
		}
		body, err := xorb.EncodeComplete(complete, [4]byte{})
		if err != nil {
			t.Fatal(err)
		}
		store.blobs[BlobKey{Kind: BlobXorb, Hash: complete.Hash}] = body
	}
	tracked := &sequentialPayloadStore{MemoryStore: store}
	service := testService(t, store, nil)
	service.blobs = tracked

	first, err := service.AuditBlobPayloads(context.Background(), PayloadAuditRequest{
		Kind: BlobXorb, Page: PageRequest{Limit: 1},
	})
	if err != nil || len(first.Items) != 1 || first.NextCursor == "" {
		t.Fatalf("first payload page = %#v, %v", first, err)
	}
	second, err := service.AuditBlobPayloads(context.Background(), PayloadAuditRequest{
		Kind: BlobXorb, Page: PageRequest{Limit: 2, Cursor: first.NextCursor},
	})
	if err != nil || len(second.Items) != 2 || second.NextCursor != "" {
		t.Fatalf("second payload page = %#v, %v", second, err)
	}
	if tracked.active.Load() != 0 || tracked.max.Load() != 1 {
		t.Fatalf("payload readers active %d, maximum %d", tracked.active.Load(), tracked.max.Load())
	}

	for name, request := range map[string]PayloadAuditRequest{
		"cross kind":       {Kind: BlobShard, Page: PageRequest{Cursor: first.NextCursor}},
		"inventory cursor": {Kind: BlobXorb, Page: PageRequest{Cursor: encodeAuditCursor(AuditKindBlobXorb, nil, "x")}},
		"malformed cursor": {Kind: BlobXorb, Page: PageRequest{Cursor: "bad"}},
		"unknown kind":     {Kind: "unknown"},
		"negative limit":   {Kind: BlobXorb, Page: PageRequest{Limit: -1}},
		"oversized limit":  {Kind: BlobXorb, Page: PageRequest{Limit: MaxPageSize + 1}},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := service.AuditBlobPayloads(context.Background(), request); !errors.Is(err, ErrInvalid) {
				t.Fatalf("invalid payload audit request = %v", err)
			}
		})
	}
}

func TestAuditBlobPayloadsListerContractsAndCapability(t *testing.T) {
	graph := newAuditGraph(t)
	graph.service.blobs = faultBlobStore{BlobStore: graph.store}
	if _, err := graph.service.AuditBlobPayloads(context.Background(), PayloadAuditRequest{Kind: BlobXorb}); !errors.Is(err, ErrAuditUnsupported) {
		t.Fatalf("payload audit without lister = %v", err)
	}

	sentinel := errors.New("injected payload list failure")
	graph.service.blobs = &payloadAuditListStore{BlobStore: graph.store, err: sentinel}
	if _, err := graph.service.AuditBlobPayloads(context.Background(), PayloadAuditRequest{Kind: BlobXorb}); !errors.Is(err, sentinel) {
		t.Fatalf("payload audit list failure = %v", err)
	}

	entry := BlobEntry{Key: graph.xorb, Info: BlobInfo{Size: 1}}
	for name, page := range map[string]BlobPage{
		"over limit":         {Items: []BlobEntry{entry, entry}},
		"empty continuation": {NextCursor: "next"},
		"stationary cursor":  {Items: []BlobEntry{entry}, NextCursor: "same"},
	} {
		t.Run(name, func(t *testing.T) {
			graph.service.blobs = &payloadAuditListStore{BlobStore: graph.store, page: page}
			request := PayloadAuditRequest{Kind: BlobXorb, Page: PageRequest{Limit: 1}}
			if name == "stationary cursor" {
				request.Page.Cursor = encodePayloadAuditCursor(BlobXorb, "same")
			}
			if _, err := graph.service.AuditBlobPayloads(context.Background(), request); !errors.Is(err, ErrCorrupt) {
				t.Fatalf("invalid payload page = %v", err)
			}
		})
	}

	ctx, cancel := context.WithCancel(context.Background())
	graph.service.blobs = &payloadAuditListStore{BlobStore: graph.store, cancel: cancel}
	if page, err := graph.service.AuditBlobPayloads(ctx, PayloadAuditRequest{Kind: BlobXorb}); !errors.Is(err, context.Canceled) || page.NextCursor != "" {
		t.Fatalf("payload list cancellation = %#v, %v", page, err)
	}

	wrongKind := BlobEntry{
		Key: BlobKey{Kind: BlobShard, Hash: graph.xorb.Hash}, Info: BlobInfo{Size: 1},
	}
	graph.service.blobs = &payloadAuditListStore{
		BlobStore: graph.store, page: BlobPage{Items: []BlobEntry{wrongKind}},
	}
	result := onePayloadAuditResult(t, graph.service, PayloadAuditRequest{Kind: BlobXorb})
	requirePayloadAuditResult(t, result, AuditStatusIssue, PayloadAuditFindingIdentityMismatch)
}

func TestAuditBlobPayloadsFailedCheckAdvancesPastRetainedDiagnostic(t *testing.T) {
	store := NewMemoryStore()
	for i := range 2 {
		object, err := xorb.Encode([][]byte{[]byte(fmt.Sprintf("failed payload check %d", i))}, xorb.None)
		if err != nil {
			t.Fatal(err)
		}
		body, err := xorb.EncodeComplete(object, [4]byte{})
		if err != nil {
			t.Fatal(err)
		}
		store.blobs[BlobKey{Kind: BlobXorb, Hash: object.Hash}] = body
	}
	raw, err := store.ListBlobs(context.Background(), BlobXorb, PageRequest{Limit: 1})
	if err != nil || len(raw.Items) != 1 || raw.NextCursor == "" {
		t.Fatalf("raw first payload page = %#v, %v", raw, err)
	}
	failedKey := raw.Items[0].Key
	sentinel := errors.New("injected retained payload diagnostic")
	faults := &payloadAuditFaultStore{MemoryStore: store}
	faults.get = func(ctx context.Context, key BlobKey, wanted *xetcas.HTTPRange) (io.ReadCloser, error) {
		if key == failedKey {
			return nil, sentinel
		}
		return store.Get(ctx, key, wanted)
	}
	service := testService(t, store, nil)
	service.blobs = faults
	first, err := service.AuditBlobPayloads(context.Background(), PayloadAuditRequest{
		Kind: BlobXorb, Page: PageRequest{Limit: 1},
	})
	if err != nil || len(first.Items) != 1 || first.NextCursor == "" {
		t.Fatalf("failed payload page = %#v, %v", first, err)
	}
	requirePayloadAuditResult(t, first.Items[0], AuditStatusFailed, PayloadAuditFindingCheckFailed)
	second, err := service.AuditBlobPayloads(context.Background(), PayloadAuditRequest{
		Kind: BlobXorb, Page: PageRequest{Limit: 1, Cursor: first.NextCursor},
	})
	if err != nil || len(second.Items) != 1 || second.NextCursor != "" {
		t.Fatalf("payload page after failed diagnostic = %#v, %v", second, err)
	}
	requirePayloadAuditResult(t, second.Items[0], AuditStatusNoIssueFound, PayloadAuditFindingNone)
}

func TestAuditBlobPayloadsFilesystemRestart(t *testing.T) {
	graph := newAuditGraph(t)
	graph.store.mu.RLock()
	xorbBody := append([]byte(nil), graph.store.blobs[graph.xorb]...)
	shardBody := append([]byte(nil), graph.store.blobs[graph.shard]...)
	graph.store.mu.RUnlock()
	root := t.TempDir()
	store, err := NewFilesystemBlobStore(root)
	if err != nil {
		t.Fatal(err)
	}
	for key, body := range map[BlobKey][]byte{graph.xorb: xorbBody, graph.shard: shardBody} {
		if _, err := store.PutIfAbsent(context.Background(), key, bytes.NewReader(body), int64(len(body))); err != nil {
			t.Fatal(err)
		}
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	store, err = NewFilesystemBlobStore(root)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	graph.service.blobs = store
	for _, kind := range []BlobKind{BlobXorb, BlobShard} {
		result := onePayloadAuditResult(t, graph.service, PayloadAuditRequest{Kind: kind})
		requirePayloadAuditResult(t, result, AuditStatusNoIssueFound, PayloadAuditFindingNone)
	}
}
