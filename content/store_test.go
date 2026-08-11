package content_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/jmwoliver/xet-go/content"
	"github.com/jmwoliver/xet-go/content/filesystem"
	"github.com/jmwoliver/xet-go/content/memory"
)

type storeFactory func(testing.TB) content.Store

func TestStoreContract(t *testing.T) {
	factories := map[string]storeFactory{
		"memory": func(testing.TB) content.Store { return memory.New() },
	}
	if runtime.GOOS == "linux" || runtime.GOOS == "darwin" {
		factories["filesystem"] = func(t testing.TB) content.Store {
			t.Helper()
			store, err := filesystem.Open(filepath.Join(t.TempDir(), "content"))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = store.Close() })
			return store
		}
	}
	for name, factory := range factories {
		t.Run(name, func(t *testing.T) { runStoreContract(t, factory) })
	}
}

func runStoreContract(t *testing.T, factory storeFactory) {
	t.Helper()
	store := factory(t)
	ctx := context.Background()
	body := bytes.Repeat([]byte("ordinary content"), 1_000)
	blob := content.Blob{SHA256: sha256.Sum256(body), Size: int64(len(body))}
	missing := content.Blob{SHA256: sha256.Sum256([]byte("missing")), Size: 7}

	if info, found, err := store.Head(ctx, missing.SHA256); err != nil || found || info.Size != 0 {
		t.Fatalf("missing head = %#v, %v, %v", info, found, err)
	}
	if _, err := store.Open(ctx, missing, nil); !errors.Is(err, content.ErrNotFound) {
		t.Fatalf("missing open = %v", err)
	}
	if inserted, err := store.Put(ctx, blob, bytes.NewReader(body)); err != nil || !inserted {
		t.Fatalf("put = %v, %v", inserted, err)
	}
	if inserted, err := store.Put(ctx, blob, bytes.NewReader(body)); err != nil || inserted {
		t.Fatalf("idempotent put = %v, %v", inserted, err)
	}
	if info, found, err := store.Head(ctx, blob.SHA256); err != nil || !found || info.Size != blob.Size {
		t.Fatalf("head = %#v, %v, %v", info, found, err)
	}

	wrongIdentity := blob
	wrongIdentity.SHA256[0] ^= 0xff
	if _, err := store.Put(ctx, wrongIdentity, bytes.NewReader(body)); !errors.Is(err, content.ErrCorrupt) {
		t.Fatalf("wrong digest = %v", err)
	}
	if _, err := store.Put(ctx, blob, bytes.NewReader(body[:len(body)-1])); !errors.Is(err, content.ErrCorrupt) {
		t.Fatalf("short body = %v", err)
	}
	if _, err := store.Put(ctx, blob, bytes.NewReader(append(append([]byte(nil), body...), 0))); !errors.Is(err, content.ErrCorrupt) {
		t.Fatalf("long body = %v", err)
	}
	if _, err := store.Put(ctx, content.Blob{Size: -1}, bytes.NewReader(nil)); !errors.Is(err, content.ErrInvalid) {
		t.Fatalf("negative size = %v", err)
	}
	if _, err := store.Put(ctx, blob, nil); !errors.Is(err, content.ErrInvalid) {
		t.Fatalf("nil body = %v", err)
	}

	reader, err := store.Open(ctx, blob, nil)
	if err != nil {
		t.Fatal(err)
	}
	got, readErr := io.ReadAll(reader)
	closeErr := reader.Close()
	if readErr != nil || closeErr != nil || !bytes.Equal(got, body) {
		t.Fatalf("full open = %d bytes, %v, %v", len(got), readErr, closeErr)
	}
	wanted := content.Range{Start: 7, End: blob.Size - 9}
	if wanted.Len() != wanted.End-wanted.Start {
		t.Fatalf("range length = %d", wanted.Len())
	}
	reader, err = store.Open(ctx, blob, &wanted)
	if err != nil {
		t.Fatal(err)
	}
	got, readErr = io.ReadAll(reader)
	_ = reader.Close()
	if readErr != nil || !bytes.Equal(got, body[wanted.Start:wanted.End]) {
		t.Fatalf("range open = %d bytes, %v", len(got), readErr)
	}
	for _, invalid := range []content.Range{{Start: -1, End: 1}, {Start: 2, End: 1}, {Start: 0, End: blob.Size + 1}} {
		if _, err := store.Open(ctx, blob, &invalid); !errors.Is(err, content.ErrRangeNotSatisfiable) {
			t.Fatalf("invalid range %#v = %v", invalid, err)
		}
	}
	wrongSize := blob
	wrongSize.Size++
	if _, err := store.Open(ctx, wrongSize, nil); !errors.Is(err, content.ErrCorrupt) {
		t.Fatalf("wrong retained size = %v", err)
	}

	empty := content.Blob{SHA256: sha256.Sum256(nil), Size: 0}
	if inserted, err := store.Put(ctx, empty, bytes.NewReader(nil)); err != nil || !inserted {
		t.Fatalf("empty put = %v, %v", inserted, err)
	}
	reader, err = store.Open(ctx, empty, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got, err = io.ReadAll(reader); err != nil || len(got) != 0 {
		t.Fatalf("empty open = %x, %v", got, err)
	}
	_ = reader.Close()

	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if _, _, err := store.Head(canceled, blob.SHA256); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled head = %v", err)
	}
	if _, err := store.Open(canceled, blob, nil); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled open = %v", err)
	}
	if _, err := store.Put(canceled, blob, bytes.NewReader(body)); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled put = %v", err)
	}
	if _, _, err := store.Head(nil, blob.SHA256); !errors.Is(err, content.ErrInvalid) { //nolint:staticcheck // Verify that the API rejects a nil context.
		t.Fatalf("nil-context head = %v", err)
	}
}
