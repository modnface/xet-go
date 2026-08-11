package memory

import (
	"bytes"
	"container/heap"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jmwoliver/xet-go/content"
)

func TestStorePublicationAndCorruption(t *testing.T) {
	store := New()
	body := []byte("immutable memory content")
	blob := content.Blob{SHA256: sha256.Sum256(body), Size: int64(len(body))}
	if inserted, err := store.Put(context.Background(), blob, bytes.NewReader(body)); err != nil || !inserted {
		t.Fatalf("put = %v, %v", inserted, err)
	}
	if inserted, err := store.Put(context.Background(), blob, bytes.NewReader(body)); err != nil || inserted {
		t.Fatalf("idempotent put = %v, %v", inserted, err)
	}
	if info, found, err := store.Head(context.Background(), blob.SHA256); err != nil || !found || info.Size != blob.Size {
		t.Fatalf("head = %#v, %v, %v", info, found, err)
	}

	store.mu.Lock()
	store.blobs[blob.SHA256] = []byte("conflicting retained bytes")
	store.mu.Unlock()
	if _, err := store.Put(context.Background(), blob, bytes.NewReader(body)); !errors.Is(err, content.ErrConflict) {
		t.Fatalf("conflicting put = %v", err)
	}
	if _, err := store.Open(context.Background(), blob, nil); !errors.Is(err, content.ErrCorrupt) {
		t.Fatalf("corrupt open = %v", err)
	}
}

func TestStoreValidationAndCancellation(t *testing.T) {
	store := New()
	body := []byte("validation")
	blob := content.Blob{SHA256: sha256.Sum256(body), Size: int64(len(body))}
	missing := content.Blob{SHA256: sha256.Sum256([]byte("missing")), Size: 7}
	if info, found, err := store.Head(context.Background(), missing.SHA256); err != nil || found || info.Size != 0 {
		t.Fatalf("missing head = %#v, %v, %v", info, found, err)
	}
	if _, err := store.Open(context.Background(), missing, nil); !errors.Is(err, content.ErrNotFound) {
		t.Fatalf("missing open = %v", err)
	}
	sentinel := errors.New("source failed")
	if _, err := store.Put(context.Background(), blob, errorReader{err: sentinel}); !errors.Is(err, sentinel) {
		t.Fatalf("source failure = %v", err)
	}
	if _, err := store.Put(context.Background(), blob, nil); !errors.Is(err, content.ErrInvalid) {
		t.Fatalf("nil body = %v", err)
	}
	if _, err := store.Put(context.Background(), content.Blob{Size: -1}, bytes.NewReader(nil)); !errors.Is(err, content.ErrInvalid) {
		t.Fatalf("invalid blob = %v", err)
	}
	if _, err := store.Put(context.Background(), blob, bytes.NewReader(body[:len(body)-1])); !errors.Is(err, content.ErrCorrupt) {
		t.Fatalf("short body = %v", err)
	}
	if _, err := store.Put(context.Background(), blob, bytes.NewReader(append(body, '!'))); !errors.Is(err, content.ErrCorrupt) {
		t.Fatalf("long body = %v", err)
	}
	wrongDigest := blob
	wrongDigest.SHA256[0] ^= 0xff
	if _, err := store.Put(context.Background(), wrongDigest, bytes.NewReader(body)); !errors.Is(err, content.ErrCorrupt) {
		t.Fatalf("wrong digest = %v", err)
	}
	if _, err := store.Put(nil, blob, bytes.NewReader(body)); !errors.Is(err, content.ErrInvalid) { //nolint:staticcheck // Verify that the API rejects a nil context.
		t.Fatalf("nil-context put = %v", err)
	}
	if _, err := store.Open(nil, blob, nil); !errors.Is(err, content.ErrInvalid) { //nolint:staticcheck // Verify that the API rejects a nil context.
		t.Fatalf("nil-context open = %v", err)
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := store.Put(canceled, blob, bytes.NewReader(body)); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled put = %v", err)
	}
	if _, err := store.Open(canceled, blob, nil); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled open = %v", err)
	}
	if _, _, err := store.Head(canceled, blob.SHA256); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled head = %v", err)
	}
	if _, _, err := store.Head(nil, blob.SHA256); !errors.Is(err, content.ErrInvalid) { //nolint:staticcheck // Verify that the API rejects a nil context.
		t.Fatalf("nil-context head = %v", err)
	}
	if _, _, err := store.Head(&errAfterContext{remaining: 1}, blob.SHA256); !errors.Is(err, context.Canceled) {
		t.Fatalf("head canceled under lock = %v", err)
	}
	if _, err := store.Open(&errAfterContext{remaining: 1}, missing, nil); !errors.Is(err, context.Canceled) {
		t.Fatalf("open canceled after lookup = %v", err)
	}
	empty := content.Blob{SHA256: sha256.Sum256(nil)}
	if _, err := store.Put(&errAfterContext{remaining: 3}, empty, bytes.NewReader(nil)); !errors.Is(err, context.Canceled) {
		t.Fatalf("put canceled before publication = %v", err)
	}
}

func TestStoreConcurrentPublication(t *testing.T) {
	store := New()
	body := bytes.Repeat([]byte("concurrent"), 1_000)
	blob := content.Blob{SHA256: sha256.Sum256(body), Size: int64(len(body))}
	const writers = 20
	var wait sync.WaitGroup
	results := make(chan bool, writers)
	errorsSeen := make(chan error, writers)
	for range writers {
		wait.Add(1)
		go func() {
			defer wait.Done()
			inserted, err := store.Put(context.Background(), blob, bytes.NewReader(body))
			results <- inserted
			errorsSeen <- err
		}()
	}
	wait.Wait()
	close(results)
	close(errorsSeen)
	inserted := 0
	for result := range results {
		if result {
			inserted++
		}
	}
	for err := range errorsSeen {
		if err != nil {
			t.Fatal(err)
		}
	}
	if inserted != 1 {
		t.Fatalf("insertions = %d, want 1", inserted)
	}
	reader, err := store.Open(context.Background(), blob, nil)
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(reader)
	_ = reader.Close()
	if err != nil || !bytes.Equal(got, body) {
		t.Fatalf("read = %d bytes, %v", len(got), err)
	}
	wanted := content.Range{Start: 2, End: 20}
	reader, err = store.Open(context.Background(), blob, &wanted)
	if err != nil {
		t.Fatal(err)
	}
	got, err = io.ReadAll(reader)
	_ = reader.Close()
	if err != nil || !bytes.Equal(got, body[wanted.Start:wanted.End]) {
		t.Fatalf("range read = %q, %v", got, err)
	}
	if _, err = store.Open(context.Background(), blob, &content.Range{Start: 3, End: 3}); !errors.Is(err, content.ErrRangeNotSatisfiable) {
		t.Fatalf("invalid range = %v", err)
	}
	wrongSize := blob
	wrongSize.Size++
	if _, err = store.Open(context.Background(), wrongSize, nil); !errors.Is(err, content.ErrCorrupt) {
		t.Fatalf("wrong size = %v", err)
	}
}

func TestBlobInventoryPaginationValidationAndCancellation(t *testing.T) {
	store := New()
	expected := make([]content.Blob, 0, 320)
	store.mu.Lock()
	for index := range 320 {
		var sum [32]byte
		sum[29], sum[30], sum[31] = byte(index>>16), byte(index>>8), byte(index)
		value := make([]byte, index%19)
		store.blobs[sum] = value
		expected = append(expected, content.Blob{SHA256: sum, Size: int64(len(value))})
	}
	store.mu.Unlock()

	var got []content.Blob
	cursor := ""
	for len(got) < len(expected) {
		page, err := store.ListBlobs(context.Background(), content.PageRequest{Limit: 17, Cursor: cursor})
		if err != nil || len(page.Items) == 0 {
			t.Fatalf("inventory page = %#v, %v", page, err)
		}
		got = append(got, page.Items...)
		cursor = page.NextCursor
	}
	if !slices.Equal(got, expected) || cursor != "" {
		t.Fatalf("inventory count = %d, cursor %q", len(got), cursor)
	}
	lastCursor := hex.EncodeToString(expected[len(expected)-1].SHA256[:])
	if page, err := store.ListBlobs(context.Background(), content.PageRequest{Cursor: lastCursor}); err != nil || len(page.Items) != 0 {
		t.Fatalf("terminal cursor page = %#v, %v", page, err)
	}
	for _, request := range []content.PageRequest{
		{Limit: -1}, {Limit: content.MaxPageSize + 1}, {Cursor: "bad"}, {Cursor: strings.Repeat("A", 64)},
	} {
		if _, err := store.ListBlobs(context.Background(), request); !errors.Is(err, content.ErrInvalid) {
			t.Fatalf("invalid request %#v = %v", request, err)
		}
	}
	if _, err := store.ListBlobs(nil, content.PageRequest{}); !errors.Is(err, content.ErrInvalid) { //nolint:staticcheck // Verify nil rejection.
		t.Fatalf("nil context = %v", err)
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := store.ListBlobs(canceled, content.PageRequest{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("pre-canceled inventory = %v", err)
	}
	if _, err := store.ListBlobs(&errAfterContext{remaining: 3}, content.PageRequest{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("inventory cancellation during scan = %v", err)
	}

	values := blobMaxHeap{expected[0], expected[1]}
	heap.Init(&values)
	heap.Push(&values, expected[2])
	if popped := heap.Pop(&values).(content.Blob); popped != expected[2] { //nolint:forcetypeassert // Internal heap contract.
		t.Fatalf("max heap popped %#v, want %#v", popped, expected[2])
	}
}

type errorReader struct{ err error }

func (reader errorReader) Read([]byte) (int, error) { return 0, reader.err }

type errAfterContext struct{ remaining int }

func (ctx *errAfterContext) Deadline() (time.Time, bool) { return time.Time{}, false }
func (ctx *errAfterContext) Done() <-chan struct{}       { return nil }
func (ctx *errAfterContext) Value(any) any               { return nil }
func (ctx *errAfterContext) Err() error {
	if ctx.remaining > 0 {
		ctx.remaining--
		return nil
	}
	return context.Canceled
}
