package server

import (
	"bytes"
	"context"
	"errors"
	"io"
	"path/filepath"
	"testing"
	"time"

	"github.com/jmwoliver/xet-go/xetcas"
	"github.com/jmwoliver/xet-go/xethash"
	"github.com/jmwoliver/xet-go/xorb"
)

func repairFixture(t testing.TB, seed string) (*xorb.Ingested, BlobKey) {
	t.Helper()
	object, err := xorb.Encode([][]byte{
		bytes.Repeat([]byte(seed+"-a"), 2_000),
		bytes.Repeat([]byte(seed+"-b"), 1_500),
	}, xorb.LZ4)
	if err != nil {
		t.Fatal(err)
	}
	ingested, err := xorb.IngestNetwork(object.Body, object.Hash)
	if err != nil {
		t.Fatal(err)
	}
	return ingested, BlobKey{Kind: BlobXorb, Hash: object.Hash}
}

func putRepairBlob(t testing.TB, store BlobStore, ingested *xorb.Ingested, key BlobKey) {
	t.Helper()
	inserted, err := store.PutIfAbsent(
		context.Background(), key, bytes.NewReader(ingested.Complete), int64(len(ingested.Complete)),
	)
	if err != nil || !inserted {
		t.Fatalf("put repair blob = %v, %v", inserted, err)
	}
}

type repairBlobSpy struct {
	*MemoryStore
	puts int
}

func (s *repairBlobSpy) PutIfAbsent(
	ctx context.Context,
	key BlobKey,
	body io.Reader,
	size int64,
) (bool, error) {
	s.puts++
	return s.MemoryStore.PutIfAbsent(ctx, key, body, size)
}

func TestRepairXorbIndexesRepairsMissingAndRecognizesValid(t *testing.T) {
	blobs := NewMemoryStore()
	index := NewMemoryStore()
	ingested, key := repairFixture(t, "repair missing")
	putRepairBlob(t, blobs, ingested, key)
	spy := &repairBlobSpy{MemoryStore: blobs}
	service, authorizationCalls := newRecoveryService(t, spy, index)

	page, err := service.RepairXorbIndexes(context.Background(), PageRequest{})
	if err != nil || len(page.Items) != 1 || page.NextCursor != "" ||
		page.Items[0].Status != XorbIndexRepairReconciled || page.Items[0].Err != nil {
		t.Fatalf("repair page = %#v, %v", page, err)
	}
	if record, found, err := index.GetXorb(context.Background(), key.Hash); err != nil || !found ||
		record.Blob != key || record.Layout.Complete != nil {
		t.Fatalf("repaired record = %#v, %v, %v", record, found, err)
	}
	page, err = service.RepairXorbIndexes(context.Background(), PageRequest{})
	if err != nil || len(page.Items) != 1 || page.Items[0].Status != XorbIndexRepairAlreadyValid {
		t.Fatalf("idempotent repair = %#v, %v", page, err)
	}
	if spy.puts != 0 || authorizationCalls.Load() != 0 {
		t.Fatalf("repair writes/auth = %d/%d", spy.puts, authorizationCalls.Load())
	}
}

func TestRepairXorbIndexesBoundedContinuation(t *testing.T) {
	blobs := NewMemoryStore()
	index := NewMemoryStore()
	for _, seed := range []string{"repair page one", "repair page two"} {
		ingested, key := repairFixture(t, seed)
		putRepairBlob(t, blobs, ingested, key)
	}
	service, _ := newRecoveryService(t, blobs, index)
	first, err := service.RepairXorbIndexes(context.Background(), PageRequest{Limit: 1})
	if err != nil || len(first.Items) != 1 || first.NextCursor == "" {
		t.Fatalf("first repair page = %#v, %v", first, err)
	}
	second, err := service.RepairXorbIndexes(
		context.Background(), PageRequest{Limit: 1, Cursor: first.NextCursor},
	)
	if err != nil || len(second.Items) != 1 || second.NextCursor != "" ||
		first.Items[0].Entry.Key == second.Items[0].Entry.Key {
		t.Fatalf("second repair page = %#v, %v", second, err)
	}
	if _, err := service.RepairXorbIndexes(context.Background(), PageRequest{
		Cursor: encodePayloadAuditCursor(BlobXorb, "foreign"),
	}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("cross-operation cursor = %v", err)
	}
}

func TestRepairXorbIndexesClassifiesUnsafeInputs(t *testing.T) {
	t.Run("missing after listing", func(t *testing.T) {
		_, key := repairFixture(t, "repair missing race")
		blobs := &payloadAuditListStore{
			BlobStore: NewMemoryStore(),
			page:      BlobPage{Items: []BlobEntry{{Key: key, Info: BlobInfo{Size: 1}}}},
		}
		service, _ := newRecoveryService(t, blobs, NewMemoryStore())
		page, err := service.RepairXorbIndexes(context.Background(), PageRequest{})
		if err != nil || len(page.Items) != 1 || page.Items[0].Status != XorbIndexRepairMissing ||
			page.Items[0].Err != nil {
			t.Fatalf("missing repair = %#v, %v", page, err)
		}
	})

	t.Run("invalid payload", func(t *testing.T) {
		blobs := NewMemoryStore()
		_, key := repairFixture(t, "repair corrupt")
		blobs.blobs[key] = []byte("not a canonical Xorb")
		service, _ := newRecoveryService(t, blobs, NewMemoryStore())
		page, err := service.RepairXorbIndexes(context.Background(), PageRequest{})
		if err != nil || len(page.Items) != 1 || page.Items[0].Status != XorbIndexRepairInvalidPayload ||
			!errors.Is(page.Items[0].Err, ErrCorrupt) {
			t.Fatalf("invalid repair = %#v, %v", page, err)
		}
	})

	t.Run("invalid inventory", func(t *testing.T) {
		_, key := repairFixture(t, "repair inventory")
		key.Kind = BlobShard
		blobs := &payloadAuditListStore{
			BlobStore: NewMemoryStore(),
			page:      BlobPage{Items: []BlobEntry{{Key: key, Info: BlobInfo{Size: 1}}}},
		}
		service, _ := newRecoveryService(t, blobs, NewMemoryStore())
		page, err := service.RepairXorbIndexes(context.Background(), PageRequest{})
		if err != nil || len(page.Items) != 1 || page.Items[0].Status != XorbIndexRepairInvalidInventory ||
			!errors.Is(page.Items[0].Err, ErrCorrupt) {
			t.Fatalf("invalid inventory repair = %#v, %v", page, err)
		}
	})

	t.Run("invalid inventory size", func(t *testing.T) {
		_, key := repairFixture(t, "repair inventory size")
		blobs := &payloadAuditListStore{
			BlobStore: NewMemoryStore(),
			page:      BlobPage{Items: []BlobEntry{{Key: key}}},
		}
		service, _ := newRecoveryService(t, blobs, NewMemoryStore())
		page, err := service.RepairXorbIndexes(context.Background(), PageRequest{})
		if err != nil || len(page.Items) != 1 || page.Items[0].Status != XorbIndexRepairInvalidInventory ||
			!errors.Is(page.Items[0].Err, ErrCorrupt) {
			t.Fatalf("invalid inventory size repair = %#v, %v", page, err)
		}
	})

	t.Run("conflicting index", func(t *testing.T) {
		blobs := NewMemoryStore()
		index := NewMemoryStore()
		ingested, key := repairFixture(t, "repair conflict")
		putRepairBlob(t, blobs, ingested, key)
		alternate, err := xorbRecordFromComplete(ingested.Complete, key)
		if err != nil {
			t.Fatal(err)
		}
		alternate.Layout.Chunks = append([]xorb.IngestedChunk(nil), alternate.Layout.Chunks...)
		alternate.Layout.Chunks[0].SerializedLength++
		alternate.Layout.Chunks[1].SerializedOffset++
		alternate.Layout.NetworkBytes++
		if _, err := ValidateXorbRecord(key.Hash, alternate); err != nil {
			t.Fatalf("alternate retained record is not valid: %v", err)
		}
		if err := index.PutXorb(context.Background(), alternate); err != nil {
			t.Fatal(err)
		}
		service, _ := newRecoveryService(t, blobs, index)
		page, err := service.RepairXorbIndexes(context.Background(), PageRequest{})
		if err != nil || len(page.Items) != 1 || page.Items[0].Status != XorbIndexRepairConflict ||
			!errors.Is(page.Items[0].Err, ErrConflict) {
			t.Fatalf("conflicting repair = %#v, %v", page, err)
		}
	})

	t.Run("corrupt retained index", func(t *testing.T) {
		blobs := NewMemoryStore()
		index := NewMemoryStore()
		ingested, key := repairFixture(t, "repair retained corruption")
		putRepairBlob(t, blobs, ingested, key)
		corrupt, err := xorbRecordFromComplete(ingested.Complete, key)
		if err != nil {
			t.Fatal(err)
		}
		corrupt.Layout.NetworkBytes++
		if err := index.PutXorb(context.Background(), corrupt); err != nil {
			t.Fatal(err)
		}
		service, _ := newRecoveryService(t, blobs, index)
		page, err := service.RepairXorbIndexes(context.Background(), PageRequest{})
		if err != nil || len(page.Items) != 1 || page.Items[0].Status != XorbIndexRepairIndexCorrupt ||
			!errors.Is(page.Items[0].Err, ErrCorrupt) {
			t.Fatalf("corrupt retained repair = %#v, %v", page, err)
		}
	})
}

type repairFaultIndex struct {
	IndexStore
	getErr error
	putErr error
}

func (s repairFaultIndex) GetXorb(
	context.Context,
	xethash.Hash,
) (XorbRecord, bool, error) {
	if s.getErr != nil {
		return XorbRecord{}, false, s.getErr
	}
	return XorbRecord{}, false, nil
}

func (s repairFaultIndex) PutXorb(context.Context, XorbRecord) error { return s.putErr }

func TestRepairXorbIndexesClassifiesIndexFailures(t *testing.T) {
	blobs := NewMemoryStore()
	ingested, key := repairFixture(t, "repair index failures")
	putRepairBlob(t, blobs, ingested, key)
	sentinel := errors.New("index backend failed")
	for _, test := range []struct {
		name   string
		index  IndexStore
		status XorbIndexRepairStatus
		phase  XorbIndexRepairPhase
		want   error
	}{
		{
			name:   "corrupt retained index",
			index:  repairFaultIndex{IndexStore: NewMemoryStore(), getErr: ErrCorrupt},
			status: XorbIndexRepairIndexCorrupt, phase: XorbIndexRepairLookup, want: ErrCorrupt,
		},
		{
			name:   "conflicting index lookup",
			index:  repairFaultIndex{IndexStore: NewMemoryStore(), getErr: ErrConflict},
			status: XorbIndexRepairConflict, phase: XorbIndexRepairLookup, want: ErrConflict,
		},
		{
			name:   "index lookup backend failure",
			index:  repairFaultIndex{IndexStore: NewMemoryStore(), getErr: sentinel},
			status: XorbIndexRepairFailed, phase: XorbIndexRepairLookup, want: sentinel,
		},
		{
			name:   "corrupt concurrent publication",
			index:  repairFaultIndex{IndexStore: NewMemoryStore(), putErr: ErrCorrupt},
			status: XorbIndexRepairIndexCorrupt, phase: XorbIndexRepairPublish, want: ErrCorrupt,
		},
		{
			name:   "conflicting concurrent publication",
			index:  repairFaultIndex{IndexStore: NewMemoryStore(), putErr: ErrConflict},
			status: XorbIndexRepairConflict, phase: XorbIndexRepairPublish, want: ErrConflict,
		},
		{
			name:   "publish backend failure",
			index:  repairFaultIndex{IndexStore: NewMemoryStore(), putErr: sentinel},
			status: XorbIndexRepairFailed, phase: XorbIndexRepairPublish, want: sentinel,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			service, _ := newRecoveryService(t, blobs, test.index)
			page, err := service.RepairXorbIndexes(context.Background(), PageRequest{})
			if err != nil || len(page.Items) != 1 || page.Items[0].Status != test.status ||
				page.Items[0].Phase != test.phase || !errors.Is(page.Items[0].Err, test.want) {
				t.Fatalf("index failure repair = %#v, %v", page, err)
			}
		})
	}
}

func TestRepairXorbIndexesClosesReadersAndInterruptsCancellation(t *testing.T) {
	blobs := NewMemoryStore()
	ingested, key := repairFixture(t, "repair reader lifecycle")
	putRepairBlob(t, blobs, ingested, key)
	body := append([]byte(nil), ingested.Complete...)
	sentinel := errors.New("repair reader failure")

	readerWithError := &observedReadCloser{Reader: bytes.NewReader(body)}
	for _, test := range []struct {
		name   string
		get    func(context.Context, BlobKey, *xetcas.HTTPRange) (io.ReadCloser, error)
		status XorbIndexRepairStatus
		want   error
		reader *observedReadCloser
	}{
		{
			name: "missing after inventory",
			get: func(context.Context, BlobKey, *xetcas.HTTPRange) (io.ReadCloser, error) {
				return nil, ErrNotFound
			},
			status: XorbIndexRepairMissing,
		},
		{
			name: "nil successful reader",
			get: func(context.Context, BlobKey, *xetcas.HTTPRange) (io.ReadCloser, error) {
				return nil, nil
			},
			status: XorbIndexRepairFailed,
		},
		{
			name: "reader returned with error",
			get: func(context.Context, BlobKey, *xetcas.HTTPRange) (io.ReadCloser, error) {
				return readerWithError, sentinel
			},
			status: XorbIndexRepairFailed, want: sentinel, reader: readerWithError,
		},
		{
			name: "short reader",
			get: func(context.Context, BlobKey, *xetcas.HTTPRange) (io.ReadCloser, error) {
				reader := &observedReadCloser{Reader: bytes.NewReader(body[:len(body)-1])}
				return reader, nil
			},
			status: XorbIndexRepairInvalidInventory, want: ErrCorrupt,
		},
		{
			name: "close failure",
			get: func(context.Context, BlobKey, *xetcas.HTTPRange) (io.ReadCloser, error) {
				return &observedReadCloser{Reader: bytes.NewReader(body), closeErr: sentinel}, nil
			},
			status: XorbIndexRepairFailed, want: sentinel,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			faults := &payloadAuditFaultStore{MemoryStore: blobs, get: test.get}
			service, _ := newRecoveryService(t, faults, NewMemoryStore())
			page, err := service.RepairXorbIndexes(context.Background(), PageRequest{})
			if err != nil || len(page.Items) != 1 || page.Items[0].Status != test.status ||
				test.want != nil && !errors.Is(page.Items[0].Err, test.want) {
				t.Fatalf("reader lifecycle repair = %#v, %v", page, err)
			}
			if test.reader != nil && !test.reader.closed.Load() {
				t.Fatal("repair did not close reader returned with an error")
			}
		})
	}

	pipeReader, pipeWriter := io.Pipe()
	t.Cleanup(func() { _ = pipeWriter.Close() })
	ctx, cancel := context.WithCancel(context.Background())
	blocking := &blockingPayloadReader{PipeReader: pipeReader, started: make(chan struct{})}
	faults := &payloadAuditFaultStore{MemoryStore: blobs}
	faults.get = func(context.Context, BlobKey, *xetcas.HTTPRange) (io.ReadCloser, error) {
		return blocking, nil
	}
	service, _ := newRecoveryService(t, faults, NewMemoryStore())
	result := make(chan struct {
		page XorbIndexRepairPage
		err  error
	}, 1)
	go func() {
		page, err := service.RepairXorbIndexes(ctx, PageRequest{})
		result <- struct {
			page XorbIndexRepairPage
			err  error
		}{page: page, err: err}
	}()
	select {
	case <-blocking.started:
	case <-time.After(time.Second):
		t.Fatal("repair did not begin its blocking read")
	}
	cancel()
	select {
	case outcome := <-result:
		if !errors.Is(outcome.err, context.Canceled) || len(outcome.page.Items) != 0 ||
			outcome.page.NextCursor != "" {
			t.Fatalf("blocked repair cancellation = %#v, %v", outcome.page, outcome.err)
		}
	case <-time.After(time.Second):
		t.Fatal("repair did not interrupt its blocking read")
	}
	if !blocking.closed.Load() {
		t.Fatal("repair did not close its blocked reader")
	}
}

func TestRepairXorbIndexesReleasesIngestPermitAfterBackendPanic(t *testing.T) {
	blobs := NewMemoryStore()
	ingested, key := repairFixture(t, "repair panic permit")
	putRepairBlob(t, blobs, ingested, key)
	faults := &payloadAuditFaultStore{MemoryStore: blobs}
	faults.get = func(context.Context, BlobKey, *xetcas.HTTPRange) (io.ReadCloser, error) {
		panic("injected repair backend panic")
	}
	service, _ := newRecoveryService(t, faults, NewMemoryStore())
	service.ingestSlots = make(chan struct{}, 1)
	func() {
		defer func() {
			if recover() == nil {
				t.Fatal("repair backend panic did not propagate")
			}
		}()
		_, _ = service.RepairXorbIndexes(context.Background(), PageRequest{})
	}()

	faults.get = nil
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	page, err := service.RepairXorbIndexes(ctx, PageRequest{})
	if err != nil || len(page.Items) != 1 || page.Items[0].Status != XorbIndexRepairReconciled {
		t.Fatalf("repair after backend panic = %#v, %v", page, err)
	}
}

func TestRepairXorbIndexesRejectsBrokenInventoryAndCancellation(t *testing.T) {
	index := NewMemoryStore()
	service, _ := newRecoveryService(t, blobStoreWithoutLister{BlobStore: NewMemoryStore()}, index)
	if _, err := service.RepairXorbIndexes(context.Background(), PageRequest{}); !errors.Is(err, ErrRepairUnsupported) {
		t.Fatalf("unsupported repair = %v", err)
	}
	if _, err := service.RepairXorbIndexes(context.Background(), PageRequest{Limit: -1}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("invalid repair limit = %v", err)
	}

	sentinel := errors.New("repair inventory failed")
	faulted := &payloadAuditListStore{BlobStore: NewMemoryStore(), err: sentinel}
	service, _ = newRecoveryService(t, faulted, index)
	if _, err := service.RepairXorbIndexes(context.Background(), PageRequest{}); !errors.Is(err, sentinel) {
		t.Fatalf("faulted repair inventory = %v", err)
	}
	afterList, cancelAfterList := context.WithCancel(context.Background())
	faulted = &payloadAuditListStore{BlobStore: NewMemoryStore(), cancel: cancelAfterList}
	service, _ = newRecoveryService(t, faulted, index)
	if _, err := service.RepairXorbIndexes(afterList, PageRequest{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("repair cancellation after inventory = %v", err)
	}

	bad := &payloadAuditListStore{
		BlobStore: NewMemoryStore(),
		page: BlobPage{
			Items: []BlobEntry{{}, {}}, NextCursor: "same",
		},
	}
	service, _ = newRecoveryService(t, bad, index)
	if _, err := service.RepairXorbIndexes(context.Background(), PageRequest{Limit: 1}); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("oversized inventory = %v", err)
	}
	bad.page = BlobPage{NextCursor: "next"}
	if _, err := service.RepairXorbIndexes(context.Background(), PageRequest{}); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("empty continuing inventory = %v", err)
	}
	bad.page = BlobPage{Items: []BlobEntry{{}}, NextCursor: "same"}
	if _, err := service.RepairXorbIndexes(context.Background(), PageRequest{
		Cursor: encodeXorbIndexRepairCursor("same"),
	}); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("stationary repair inventory = %v", err)
	}

	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if page, err := service.RepairXorbIndexes(canceled, PageRequest{}); !errors.Is(err, context.Canceled) ||
		len(page.Items) != 0 || page.NextCursor != "" {
		t.Fatalf("canceled repair = %#v, %v", page, err)
	}
	if _, err := service.repairXorbIndexWithPermit(canceled, BlobEntry{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled repair admission = %v", err)
	}
	if err := repairContextError(context.Background(), context.DeadlineExceeded); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("repair item cancellation = %v", err)
	}
	if err := validateXorbIndexRepairPage(PageRequest{Limit: -1}, BlobPage{}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("invalid internal repair page = %v", err)
	}
}

type blobStoreWithoutLister struct{ BlobStore }

func TestSQLiteFilesystemXorbRepairAcrossRestart(t *testing.T) {
	requireLocalDurability(t)
	ctx := context.Background()
	root := t.TempDir()
	blobRoot, indexPath := filepath.Join(root, "blobs"), filepath.Join(root, "index.db")
	blobs, err := NewFilesystemBlobStore(blobRoot)
	if err != nil {
		t.Fatal(err)
	}
	index, err := OpenSQLiteIndexStore(indexPath)
	if err != nil {
		t.Fatal(err)
	}
	ingested, key := repairFixture(t, "durable repair")
	putRepairBlob(t, blobs, ingested, key)
	if err := index.Close(); err != nil {
		t.Fatal(err)
	}
	if err := blobs.Close(); err != nil {
		t.Fatal(err)
	}

	blobs, err = NewFilesystemBlobStore(blobRoot)
	if err != nil {
		t.Fatal(err)
	}
	defer blobs.Close() //nolint:errcheck // Test cleanup.
	index, err = OpenSQLiteIndexStore(indexPath)
	if err != nil {
		t.Fatal(err)
	}
	defer index.Close() //nolint:errcheck // Test cleanup.
	service, _ := newRecoveryService(t, blobs, index)
	page, err := service.RepairXorbIndexes(ctx, PageRequest{})
	if err != nil || len(page.Items) != 1 || page.Items[0].Status != XorbIndexRepairReconciled {
		t.Fatalf("durable Xorb repair = %#v, %v", page, err)
	}
	if _, found, err := index.GetXorb(ctx, key.Hash); err != nil || !found {
		t.Fatalf("durable repaired Xorb = %v, %v", found, err)
	}
}
