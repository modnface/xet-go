package server

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jmwoliver/xet-go/shard"
	"github.com/jmwoliver/xet-go/xetcas"
	"github.com/jmwoliver/xet-go/xethash"
	"github.com/jmwoliver/xet-go/xorb"
)

type cancelAfterCheckContext struct {
	context.Context
	checks int
	after  int
}

type sqliteCodeTestError struct{ code int }

func (e sqliteCodeTestError) Error() string { return fmt.Sprintf("SQLite test error %d", e.code) }
func (e sqliteCodeTestError) Code() int     { return e.code }

func (c *cancelAfterCheckContext) Err() error {
	c.checks++
	if c.checks >= c.after {
		return context.Canceled
	}
	return nil
}

type firstCheckContext struct {
	context.Context
	once    sync.Once
	checked chan struct{}
}

func (c *firstCheckContext) Err() error {
	c.once.Do(func() { close(c.checked) })
	return c.Context.Err()
}

type signalingEOFReader struct {
	once sync.Once
	read chan struct{}
}

func (r *signalingEOFReader) Read([]byte) (int, error) {
	r.once.Do(func() { close(r.read) })
	return 0, io.EOF
}

func requireLocalDurability(t testing.TB) {
	t.Helper()
	if err := checkFilesystemDurabilitySupported(); err != nil {
		t.Skipf("strict local durability is unavailable: %v", err)
	}
}

type blobStoreFactory func(testing.TB) BlobStore

func runBlobStoreContract(t *testing.T, factory blobStoreFactory) {
	t.Helper()
	t.Run("immutable ranges and cancellation", func(t *testing.T) {
		store := factory(t)
		ctx := context.Background()
		key := BlobKey{Kind: BlobXorb, Hash: xethash.Chunk([]byte("blob contract"))}
		body := bytes.Repeat([]byte("durable blob"), 1_000)
		if info, found, err := store.Head(ctx, key); err != nil || found || info.Size != 0 {
			t.Fatalf("missing head = %#v, %v, %v", info, found, err)
		}
		if _, err := store.Get(ctx, key, nil); !errors.Is(err, ErrNotFound) {
			t.Fatalf("missing get = %v", err)
		}
		if inserted, err := store.PutIfAbsent(ctx, key, bytes.NewReader(body), int64(len(body))); err != nil || !inserted {
			t.Fatalf("insert = %v, %v", inserted, err)
		}
		if inserted, err := store.PutIfAbsent(ctx, key, bytes.NewReader(body), int64(len(body))); err != nil || inserted {
			t.Fatalf("idempotent insert = %v, %v", inserted, err)
		}
		conflict := append([]byte(nil), body...)
		conflict[len(conflict)/2] ^= 0xff
		if _, err := store.PutIfAbsent(ctx, key, bytes.NewReader(conflict), int64(len(conflict))); !errors.Is(err, ErrConflict) {
			t.Fatalf("conflicting insert = %v", err)
		}
		if _, err := store.PutIfAbsent(ctx, key, bytes.NewReader(body[:len(body)-1]), int64(len(body))); err == nil {
			t.Fatal("short insert succeeded")
		}
		if _, err := store.PutIfAbsent(ctx, key, bytes.NewReader(append(append([]byte(nil), body...), 0)), int64(len(body))); err == nil {
			t.Fatal("long insert succeeded")
		}
		info, found, err := store.Head(ctx, key)
		if err != nil || !found || info.Size != int64(len(body)) {
			t.Fatalf("head = %#v, %v, %v", info, found, err)
		}
		reader, err := store.Get(ctx, key, nil)
		if err != nil {
			t.Fatal(err)
		}
		got, readErr := io.ReadAll(reader)
		closeErr := reader.Close()
		if readErr != nil || closeErr != nil || !bytes.Equal(got, body) {
			t.Fatalf("full get = %d bytes, %v, %v", len(got), readErr, closeErr)
		}
		wanted := xetcas.HTTPRange{Start: 7, End: uint64(len(body)) - 9}
		reader, err = store.Get(ctx, key, &wanted)
		if err != nil {
			t.Fatal(err)
		}
		got, readErr = io.ReadAll(reader)
		_ = reader.Close()
		if readErr != nil || !bytes.Equal(got, body[wanted.Start:wanted.End+1]) {
			t.Fatalf("range get = %d bytes, %v", len(got), readErr)
		}
		for _, bad := range []xetcas.HTTPRange{{Start: 2, End: 1}, {Start: 0, End: uint64(len(body))}} {
			if _, err := store.Get(ctx, key, &bad); !errors.Is(err, xetcas.ErrRangeNotSatisfiable) {
				t.Fatalf("bad range %#v = %v", bad, err)
			}
		}
		canceled, cancel := context.WithCancel(ctx)
		cancel()
		if _, _, err := store.Head(canceled, key); !errors.Is(err, context.Canceled) {
			t.Fatalf("canceled head = %v", err)
		}
		if _, err := store.Get(canceled, key, nil); !errors.Is(err, context.Canceled) {
			t.Fatalf("canceled get = %v", err)
		}
		if _, err := store.PutIfAbsent(canceled, BlobKey{Kind: BlobShard, Hash: key.Hash}, bytes.NewReader(body), int64(len(body))); !errors.Is(err, context.Canceled) {
			t.Fatalf("canceled put = %v", err)
		}
	})
}

func TestBlobStoreContracts(t *testing.T) {
	t.Run("memory", func(t *testing.T) {
		runBlobStoreContract(t, func(testing.TB) BlobStore { return NewMemoryStore() })
	})
	t.Run("filesystem", func(t *testing.T) {
		requireLocalDurability(t)
		runBlobStoreContract(t, func(t testing.TB) BlobStore {
			t.Helper()
			store, err := NewFilesystemBlobStore(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = store.Close() })
			return store
		})
	})
}

type indexStoreFactory func(testing.TB) IndexStore

func runIndexStoreContract(t *testing.T, factory indexStoreFactory) {
	t.Helper()
	t.Run("immutable and scoped indexes", func(t *testing.T) {
		store := factory(t)
		ctx := context.Background()
		chunkHash := xethash.Chunk([]byte("index chunk"))
		xorbHash := xethash.Xorb([]xethash.Node{{Hash: chunkHash, Size: 7}})
		fileHash := xethash.Chunk([]byte("index file"))
		shardKey := BlobKey{Kind: BlobShard, Hash: xethash.Chunk([]byte("index shard"))}
		xorbRecord := XorbRecord{
			Blob: BlobKey{Kind: BlobXorb, Hash: xorbHash},
			Layout: xorb.Ingested{
				Hash: xorbHash, NetworkBytes: 15, UncompressedSize: 7,
				Chunks: []xorb.IngestedChunk{{
					Hash: chunkHash, SerializedLength: 15, UncompressedLength: 7,
				}},
			},
		}
		fileRecord := FileRecord{
			File: shard.RegisteredFile{File: shard.File{
				Hash:  fileHash,
				Terms: []shard.Term{{XorbHash: xorbHash, Start: 0, End: 1, UnpackedBytes: 7}},
			}, Size: 7},
			Shard: shardKey,
		}
		dedupRecord := DedupRecord{Shard: shardKey}
		sum := [32]byte{1, 2, 3}
		if _, found, err := store.GetXorb(ctx, xorbHash); err != nil || found {
			t.Fatalf("missing xorb = %v, %v", found, err)
		}
		if err := store.PutXorb(ctx, xorbRecord); err != nil {
			t.Fatal(err)
		}
		if err := store.PutXorb(ctx, xorbRecord); err != nil {
			t.Fatalf("idempotent xorb = %v", err)
		}
		conflictingXorb := xorbRecord
		conflictingXorb.Layout.Chunks = append([]xorb.IngestedChunk(nil), conflictingXorb.Layout.Chunks...)
		conflictingXorb.Layout.Chunks[0].SerializedLength++
		conflictingXorb.Layout.NetworkBytes++
		if _, err := ValidateXorbRecord(xorbHash, conflictingXorb); err != nil {
			t.Fatalf("valid conflicting Xorb = %v", err)
		}
		if err := store.PutXorb(ctx, conflictingXorb); !errors.Is(err, ErrConflict) {
			t.Fatalf("xorb conflict = %v", err)
		}
		gotXorb, found, err := store.GetXorb(ctx, xorbHash)
		if err != nil || !found || !reflect.DeepEqual(gotXorb, xorbRecord) {
			t.Fatalf("xorb = %#v, %v, %v", gotXorb, found, err)
		}

		t.Run("concurrent Xorb insertion never replaces", func(t *testing.T) {
			concurrent := factory(t)
			left, right := xorbRecord, conflictingXorb
			start := make(chan struct{})
			results := make(chan error, 2)
			for _, record := range []XorbRecord{left, right} {
				go func() {
					<-start
					results <- concurrent.PutXorb(ctx, record)
				}()
			}
			close(start)
			first, second := <-results, <-results
			if (first == nil) == (second == nil) ||
				first != nil && !errors.Is(first, ErrConflict) ||
				second != nil && !errors.Is(second, ErrConflict) {
				t.Fatalf("concurrent Xorb results = %v, %v", first, second)
			}
			retained, found, err := concurrent.GetXorb(ctx, xorbHash)
			if err != nil || !found || !reflect.DeepEqual(retained, left) && !reflect.DeepEqual(retained, right) {
				t.Fatalf("concurrent retained Xorb = %#v, %v, %v", retained, found, err)
			}
		})

		t.Run("corrupt retained Xorb is not a conflict", func(t *testing.T) {
			corruptStore := factory(t)
			corrupt := xorbRecord
			corrupt.Layout.NetworkBytes++
			if _, err := ValidateXorbRecord(xorbHash, corrupt); !errors.Is(err, ErrCorrupt) {
				t.Fatalf("corrupt retained fixture = %v", err)
			}
			if err := corruptStore.PutXorb(ctx, corrupt); err != nil {
				if !errors.Is(err, ErrInvalid) {
					t.Fatalf("reject corrupt supplied Xorb = %v", err)
				}
				return
			}
			if err := corruptStore.PutXorb(ctx, xorbRecord); !errors.Is(err, ErrCorrupt) {
				t.Fatalf("put over corrupt retained Xorb = %v", err)
			}
		})

		if err := store.PutFile(ctx, "a", fileRecord); err != nil {
			t.Fatal(err)
		}
		alternativeFile := fileRecord
		alternativeFile.Shard.Hash = xethash.Chunk([]byte("alternative shard"))
		if err := store.PutFile(ctx, "a", alternativeFile); err != nil {
			t.Fatalf("alternative file source = %v", err)
		}
		if _, found, err := store.GetFile(ctx, "b", fileHash); err != nil || found {
			t.Fatalf("cross-scope file = %v, %v", found, err)
		}
		gotFile, found, err := store.GetFile(ctx, "a", fileHash)
		if err != nil || !found || !reflect.DeepEqual(gotFile, fileRecord) {
			t.Fatalf("file = %#v, %v, %v", gotFile, found, err)
		}

		if err := store.PutDedup(ctx, "a", chunkHash, dedupRecord); err != nil {
			t.Fatal(err)
		}
		if err := store.PutDedup(ctx, "a", chunkHash, DedupRecord{Shard: alternativeFile.Shard}); err != nil {
			t.Fatalf("alternative dedup source = %v", err)
		}
		if _, found, err := store.GetDedup(ctx, "b", chunkHash); err != nil || found {
			t.Fatalf("cross-scope dedup = %v, %v", found, err)
		}
		gotDedup, found, err := store.GetDedup(ctx, "a", chunkHash)
		if err != nil || !found || gotDedup != dedupRecord {
			t.Fatalf("dedup = %#v, %v, %v", gotDedup, found, err)
		}

		if err := store.PutSHA256(ctx, "a", sum, 7, fileHash); err != nil {
			t.Fatal(err)
		}
		if err := store.PutSHA256(ctx, "a", sum, 7, fileHash); err != nil {
			t.Fatalf("idempotent SHA = %v", err)
		}
		if err := store.PutSHA256(ctx, "a", sum, 7, xethash.Zero); !errors.Is(err, ErrConflict) {
			t.Fatalf("SHA conflict = %v", err)
		}
		if _, found, err := store.ResolveSHA256(ctx, "b", sum, 7); err != nil || found {
			t.Fatalf("cross-scope SHA = %v, %v", found, err)
		}
		gotSHA, found, err := store.ResolveSHA256(ctx, "a", sum, 7)
		if err != nil || !found || gotSHA != fileHash {
			t.Fatalf("SHA = %s, %v, %v", gotSHA, found, err)
		}

		canceled, cancel := context.WithCancel(ctx)
		cancel()
		operations := []struct {
			name string
			call func() error
		}{
			{"get xorb", func() error { _, _, err := store.GetXorb(canceled, xorbHash); return err }},
			{"put xorb", func() error { return store.PutXorb(canceled, xorbRecord) }},
			{"get file", func() error { _, _, err := store.GetFile(canceled, "a", fileHash); return err }},
			{"put file", func() error { return store.PutFile(canceled, "a", fileRecord) }},
			{"get dedup", func() error { _, _, err := store.GetDedup(canceled, "a", chunkHash); return err }},
			{"put dedup", func() error { return store.PutDedup(canceled, "a", chunkHash, dedupRecord) }},
			{"resolve SHA", func() error { _, _, err := store.ResolveSHA256(canceled, "a", sum, 7); return err }},
			{"put SHA", func() error { return store.PutSHA256(canceled, "a", sum, 7, fileHash) }},
		}
		for _, operation := range operations {
			if err := operation.call(); !errors.Is(err, context.Canceled) {
				t.Fatalf("canceled %s = %v", operation.name, err)
			}
		}
	})

	t.Run("atomic shard publication", func(t *testing.T) {
		store := factory(t)
		ctx := context.Background()
		fileHash := xethash.Chunk([]byte("published file"))
		chunkHash := xethash.Chunk([]byte("published chunk"))
		sum := [32]byte{9}
		shardKey := BlobKey{Kind: BlobShard, Hash: xethash.Chunk([]byte("published shard"))}
		publication := ShardPublication{
			Namespace: "scope",
			Shard:     shardKey,
			Dedup: []DedupAssociation{{
				Chunk: chunkHash,
				Value: DedupRecord{Shard: shardKey},
			}},
			SHA256: []SHA256Association{{Sum: sum, Size: 1, File: fileHash}},
			Files:  []FileRecord{{File: shard.RegisteredFile{File: shard.File{Hash: fileHash}, Size: 1}, Shard: shardKey}},
		}
		if err := store.PublishShard(ctx, publication); err != nil {
			t.Fatal(err)
		}
		if err := store.PublishShard(ctx, publication); err != nil {
			t.Fatalf("idempotent publication = %v", err)
		}
		if _, found, err := store.GetFile(ctx, "scope", fileHash); err != nil || !found {
			t.Fatalf("published file = %v, %v", found, err)
		}
		if got, found, err := store.GetShard(ctx, "scope", shardKey.Hash); err != nil || !found || got.Blob != shardKey {
			t.Fatalf("published shard = %#v, %v, %v", got, found, err)
		}
		if _, found, err := store.GetShard(ctx, "other", shardKey.Hash); err != nil || found {
			t.Fatalf("cross-scope shard = %v, %v", found, err)
		}
		alternateShard := BlobKey{Kind: BlobShard, Hash: xethash.Chunk([]byte("alternate published shard"))}
		alternate := publication
		alternate.Shard = alternateShard
		alternate.Dedup = []DedupAssociation{{Chunk: chunkHash, Value: DedupRecord{Shard: alternateShard}}}
		alternate.Files = []FileRecord{{
			File: publication.Files[0].File, Shard: alternateShard,
		}}
		if err := store.PublishShard(ctx, alternate); err != nil {
			t.Fatalf("alternate valid publication = %v", err)
		}
		if retained, found, err := store.GetFile(ctx, "scope", fileHash); err != nil || !found || retained.Shard != shardKey {
			t.Fatalf("retained first file source = %#v, %v, %v", retained, found, err)
		}
		if retained, found, err := store.GetDedup(ctx, "scope", chunkHash); err != nil || !found || retained.Shard != shardKey {
			t.Fatalf("retained first dedup source = %#v, %v, %v", retained, found, err)
		}
		if got, found, err := store.GetShard(ctx, "scope", alternateShard.Hash); err != nil || !found || got.Blob != alternateShard {
			t.Fatalf("alternate shard registration = %#v, %v, %v", got, found, err)
		}
		if err := store.PublishShard(ctx, ShardPublication{}); !errors.Is(err, ErrInvalid) {
			t.Fatalf("invalid shard publication identity = %v", err)
		}
		fileMismatch := ShardPublication{
			Shard: shardKey,
			Files: []FileRecord{{
				File: publication.Files[0].File, Shard: alternateShard,
			}},
		}
		if err := store.PublishShard(ctx, fileMismatch); !errors.Is(err, ErrInvalid) {
			t.Fatalf("file source mismatch = %v", err)
		}
		mismatch := publication
		mismatch.Shard.Hash = xethash.Chunk([]byte("mismatched publication shard"))
		if err := store.PublishShard(ctx, mismatch); !errors.Is(err, ErrInvalid) {
			t.Fatalf("publication source mismatch = %v", err)
		}
		existingConflict := publication
		existingConflict.SHA256 = []SHA256Association{{Sum: sum, Size: 1, File: xethash.Zero}}
		extraFile := xethash.Chunk([]byte("must roll back"))
		existingConflict.Files = []FileRecord{{File: shard.RegisteredFile{File: shard.File{Hash: extraFile}, Size: 1}, Shard: shardKey}}
		if err := store.PublishShard(ctx, existingConflict); !errors.Is(err, ErrConflict) {
			t.Fatalf("existing SHA conflict = %v", err)
		}
		if _, found, err := store.GetFile(ctx, "scope", extraFile); err != nil || found {
			t.Fatalf("file visible after existing conflict = %v, %v", found, err)
		}
		conflict := publication
		conflict.Namespace = "other"
		conflict.SHA256 = append([]SHA256Association(nil), publication.SHA256...)
		conflict.SHA256 = append(conflict.SHA256, SHA256Association{Sum: sum, Size: 1, File: xethash.Zero})
		if err := store.PublishShard(ctx, conflict); !errors.Is(err, ErrConflict) {
			t.Fatalf("contradictory publication = %v", err)
		}
		if _, found, err := store.GetFile(ctx, "other", fileHash); err != nil || found {
			t.Fatalf("file visible after atomic rollback = %v, %v", found, err)
		}
		canceled, cancel := context.WithCancel(ctx)
		cancel()
		if err := store.PublishShard(canceled, publication); !errors.Is(err, context.Canceled) {
			t.Fatalf("canceled publication = %v", err)
		}
	})
}

func TestIndexStoreContracts(t *testing.T) {
	t.Run("memory", func(t *testing.T) {
		runIndexStoreContract(t, func(testing.TB) IndexStore { return NewMemoryStore() })
	})
	t.Run("sqlite", func(t *testing.T) {
		requireLocalDurability(t)
		runIndexStoreContract(t, func(t testing.TB) IndexStore {
			t.Helper()
			store, err := OpenSQLiteIndexStore(filepath.Join(t.TempDir(), "index.db"))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = store.Close() })
			return store
		})
	})
}

func runBlobListerContract(t *testing.T, factory blobStoreFactory) {
	t.Helper()
	store := factory(t)
	lister, ok := store.(BlobLister)
	if !ok {
		t.Fatalf("%T does not implement BlobLister", store)
	}
	ctx := context.Background()
	want := make(map[string]int64)
	for i := range 7 {
		body := bytes.Repeat([]byte{byte(i + 1)}, i+1)
		hash := xethash.Chunk(append([]byte("listed blob"), byte(i)))
		key := BlobKey{Kind: BlobXorb, Hash: hash}
		if _, err := store.PutIfAbsent(ctx, key, bytes.NewReader(body), int64(len(body))); err != nil {
			t.Fatal(err)
		}
		want[hash.String()] = int64(len(body))
	}
	shardKey := BlobKey{Kind: BlobShard, Hash: xethash.Chunk([]byte("listed shard"))}
	if _, err := store.PutIfAbsent(ctx, shardKey, bytes.NewReader([]byte("shard")), 5); err != nil {
		t.Fatal(err)
	}

	seen := make(map[string]struct{})
	request := PageRequest{Limit: 2}
	for {
		page, err := lister.ListBlobs(ctx, BlobXorb, request)
		if err != nil {
			t.Fatal(err)
		}
		if len(page.Items) > request.Limit {
			t.Fatalf("page has %d items, limit %d", len(page.Items), request.Limit)
		}
		for _, item := range page.Items {
			key := item.Key.Hash.String()
			if item.Key.Kind != BlobXorb || item.Info.Size != want[key] {
				t.Fatalf("blob item = %#v", item)
			}
			if _, duplicate := seen[key]; duplicate {
				t.Fatalf("duplicate blob %s", key)
			}
			seen[key] = struct{}{}
		}
		if page.NextCursor == "" {
			break
		}
		if page.NextCursor == request.Cursor {
			t.Fatal("blob cursor did not advance")
		}
		request.Cursor = page.NextCursor
	}
	if len(seen) != len(want) {
		t.Fatalf("listed %d blobs, want %d", len(seen), len(want))
	}
	shards, err := lister.ListBlobs(ctx, BlobShard, PageRequest{Limit: 1})
	if err != nil || len(shards.Items) != 1 || shards.Items[0].Key != shardKey || shards.NextCursor != "" {
		t.Fatalf("shard page = %#v, %v", shards, err)
	}
	firstXorb, err := lister.ListBlobs(ctx, BlobXorb, PageRequest{Limit: 1})
	if err != nil || firstXorb.NextCursor == "" {
		t.Fatalf("first xorb page = %#v, %v", firstXorb, err)
	}
	if _, err := lister.ListBlobs(ctx, BlobShard, PageRequest{Cursor: firstXorb.NextCursor, Limit: 1}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("cross-kind blob cursor = %v", err)
	}
	for name, request := range map[string]PageRequest{
		"negative limit": {Limit: -1},
		"large limit":    {Limit: MaxPageSize + 1},
		"bad cursor":     {Cursor: "bad", Limit: 1},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := lister.ListBlobs(ctx, BlobXorb, request); !errors.Is(err, ErrInvalid) {
				t.Fatalf("error = %v", err)
			}
		})
	}
	if _, err := lister.ListBlobs(ctx, BlobKind("unknown"), PageRequest{}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("invalid blob kind = %v", err)
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := lister.ListBlobs(canceled, BlobXorb, PageRequest{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled blob list = %v", err)
	}
	duringScan := &cancelAfterCheckContext{Context: ctx, after: 2}
	if _, err := lister.ListBlobs(duringScan, BlobXorb, PageRequest{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("blob list canceled during scan = %v", err)
	}
}

func TestBlobListerContracts(t *testing.T) {
	t.Run("memory", func(t *testing.T) {
		runBlobListerContract(t, func(testing.TB) BlobStore { return NewMemoryStore() })
	})
	t.Run("filesystem", func(t *testing.T) {
		requireLocalDurability(t)
		runBlobListerContract(t, func(t testing.TB) BlobStore {
			store, err := NewFilesystemBlobStore(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = store.Close() })
			return store
		})
	})
}

func TestFilesystemBlobListerSafety(t *testing.T) {
	requireLocalDurability(t)
	newStore := func(t *testing.T) (*FilesystemBlobStore, string) {
		t.Helper()
		store, err := NewFilesystemBlobStore(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = store.Close() })
		root := filepath.Join(store.root, filesystemLayoutVersion, string(BlobXorb))
		return store, root
	}

	t.Run("empty", func(t *testing.T) {
		store, _ := newStore(t)
		page, err := store.ListBlobs(context.Background(), BlobXorb, PageRequest{})
		if err != nil || len(page.Items) != 0 || page.NextCursor != "" {
			t.Fatalf("empty page = %#v, %v", page, err)
		}
	})

	t.Run("intermediate symlink", func(t *testing.T) {
		store, root := newStore(t)
		external := t.TempDir()
		if err := os.MkdirAll(filepath.Join(external, string(BlobXorb)), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(external, filepath.Join(store.root, filesystemLayoutVersion)); err != nil {
			t.Fatal(err)
		}
		if _, err := store.ListBlobs(context.Background(), BlobXorb, PageRequest{}); !errors.Is(err, ErrCorrupt) {
			t.Fatalf("list through intermediate symlink %q = %v", root, err)
		}
	})

	t.Run("replaced store root", func(t *testing.T) {
		store, _ := newStore(t)
		original := store.root + ".original"
		if err := os.Rename(store.root, original); err != nil {
			t.Fatal(err)
		}
		external := t.TempDir()
		if err := os.MkdirAll(filepath.Join(external, filesystemLayoutVersion, string(BlobXorb)), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(external, store.root); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			_ = os.Remove(store.root)
			_ = os.Rename(original, store.root)
		})
		if _, err := store.ListBlobs(context.Background(), BlobXorb, PageRequest{}); !errors.Is(err, ErrCorrupt) {
			t.Fatalf("list through replaced root = %v", err)
		}
	})

	for _, test := range []struct {
		name  string
		setup func(*testing.T, string)
	}{
		{"kind root is a file", func(t *testing.T, root string) {
			if err := os.MkdirAll(filepath.Dir(root), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(root, nil, 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{"malformed first prefix", func(t *testing.T, root string) {
			if err := os.MkdirAll(filepath.Join(root, "zz"), 0o700); err != nil {
				t.Fatal(err)
			}
		}},
		{"symlink prefix", func(t *testing.T, root string) {
			if err := os.MkdirAll(root, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(t.TempDir(), filepath.Join(root, "00")); err != nil {
				t.Fatal(err)
			}
		}},
		{"malformed second prefix", func(t *testing.T, root string) {
			if err := os.MkdirAll(filepath.Join(root, "00", "zz"), 0o700); err != nil {
				t.Fatal(err)
			}
		}},
		{"malformed object name", func(t *testing.T, root string) {
			objectRoot := filepath.Join(root, "00", "00")
			if err := os.MkdirAll(objectRoot, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(objectRoot, "not-a-hash"), nil, 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{"misplaced object", func(t *testing.T, root string) {
			objectRoot := filepath.Join(root, "11", "11")
			if err := os.MkdirAll(objectRoot, 0o700); err != nil {
				t.Fatal(err)
			}
			name := strings.Repeat("0", xethash.StringSize)
			if err := os.WriteFile(filepath.Join(objectRoot, name), nil, 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{"symlink object", func(t *testing.T, root string) {
			objectRoot := filepath.Join(root, "00", "00")
			if err := os.MkdirAll(objectRoot, 0o700); err != nil {
				t.Fatal(err)
			}
			name := strings.Repeat("0", xethash.StringSize)
			if err := os.Symlink(filepath.Join(t.TempDir(), "target"), filepath.Join(objectRoot, name)); err != nil {
				t.Fatal(err)
			}
		}},
		{"non-regular object", func(t *testing.T, root string) {
			name := strings.Repeat("0", xethash.StringSize)
			if err := os.MkdirAll(filepath.Join(root, "00", "00", name), 0o700); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			store, root := newStore(t)
			test.setup(t, root)
			if _, err := store.ListBlobs(context.Background(), BlobXorb, PageRequest{}); !errors.Is(err, ErrCorrupt) {
				t.Fatalf("corrupt filesystem list = %v", err)
			}
		})
	}

	t.Run("temporary objects are hidden", func(t *testing.T) {
		store, root := newStore(t)
		objectRoot := filepath.Join(root, "00", "00")
		if err := os.MkdirAll(objectRoot, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(objectRoot, tempPrefix+"active"), []byte("partial"), 0o600); err != nil {
			t.Fatal(err)
		}
		page, err := store.ListBlobs(context.Background(), BlobXorb, PageRequest{})
		if err != nil || len(page.Items) != 0 {
			t.Fatalf("temporary object page = %#v, %v", page, err)
		}
	})

	t.Run("cursor seeks past earlier prefixes", func(t *testing.T) {
		store, root := newStore(t)
		if err := os.MkdirAll(filepath.Join(root, "00", "zz"), 0o700); err != nil {
			t.Fatal(err)
		}
		cursor := encodeHashCursor(cursorBlobXorb, xethash.MustParse(strings.Repeat("8", xethash.StringSize)))
		page, err := store.ListBlobs(context.Background(), BlobXorb, PageRequest{Cursor: cursor, Limit: 1})
		if err != nil || len(page.Items) != 0 {
			t.Fatalf("seek page = %#v, %v", page, err)
		}
	})

	t.Run("cursor seeks within a first-level prefix", func(t *testing.T) {
		store, root := newStore(t)
		if err := os.MkdirAll(filepath.Join(root, "00", "00"), 0o700); err != nil {
			t.Fatal(err)
		}
		text := "0088" + strings.Repeat("0", xethash.StringSize-4)
		cursor := encodeHashCursor(cursorBlobXorb, xethash.MustParse(text))
		page, err := store.ListBlobs(context.Background(), BlobXorb, PageRequest{Cursor: cursor, Limit: 1})
		if err != nil || len(page.Items) != 0 {
			t.Fatalf("same-prefix seek page = %#v, %v", page, err)
		}
	})

	t.Run("cancellation during traversal", func(t *testing.T) {
		store, root := newStore(t)
		objectRoot := filepath.Join(root, "00", "00")
		if err := os.MkdirAll(objectRoot, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(objectRoot, strings.Repeat("0", xethash.StringSize)), nil, 0o600); err != nil {
			t.Fatal(err)
		}
		for _, after := range []int{2, 3, 4} {
			ctx := &cancelAfterCheckContext{Context: context.Background(), after: after}
			if _, err := store.ListBlobs(ctx, BlobXorb, PageRequest{}); !errors.Is(err, context.Canceled) {
				t.Fatalf("list canceled at check %d = %v", after, err)
			}
		}
	})
}

func runIndexListerContract(t *testing.T, factory indexStoreFactory) {
	t.Helper()
	store := factory(t)
	lister, ok := store.(IndexLister)
	if !ok {
		t.Fatalf("%T does not implement IndexLister", store)
	}
	ctx := context.Background()
	const recordsPerNamespace = 3
	namespaces := []string{"", "alpha", "beta"}
	for i := range 7 {
		hash := xethash.Chunk(append([]byte("listed xorb"), byte(i)))
		if err := store.PutXorb(ctx, XorbRecord{
			Blob: BlobKey{Kind: BlobXorb, Hash: hash}, Layout: xorb.Ingested{Hash: hash},
		}); err != nil {
			t.Fatal(err)
		}
	}
	for namespaceIndex, namespace := range namespaces {
		for shardIndex := range 3 {
			listedShard := BlobKey{
				Kind: BlobShard,
				Hash: xethash.Chunk([]byte(fmt.Sprintf("registered shard %d %d", namespaceIndex, shardIndex))),
			}
			if err := store.PublishShard(ctx, ShardPublication{Namespace: namespace, Shard: listedShard}); err != nil {
				t.Fatal(err)
			}
		}
		for i := range recordsPerNamespace {
			fileHash := xethash.Chunk([]byte(fmt.Sprintf("listed file %d %d", namespaceIndex, i)))
			chunkHash := xethash.Chunk([]byte(fmt.Sprintf("listed dedup %d %d", namespaceIndex, i)))
			shardKey := BlobKey{Kind: BlobShard, Hash: xethash.Chunk([]byte(fmt.Sprintf("listed shard %d %d", namespaceIndex, i)))}
			if err := store.PutFile(ctx, namespace, FileRecord{
				File: shard.RegisteredFile{File: shard.File{Hash: fileHash}}, Shard: shardKey,
			}); err != nil {
				t.Fatal(err)
			}
			if err := store.PutDedup(ctx, namespace, chunkHash, DedupRecord{Shard: shardKey}); err != nil {
				t.Fatal(err)
			}
			var sum [32]byte
			sum[0] = byte(namespaceIndex)
			if err := store.PutSHA256(ctx, namespace, sum, uint64(i+1), fileHash); err != nil {
				t.Fatal(err)
			}
		}
	}

	var xorbCursor string
	seenXorbs := make(map[xethash.Hash]struct{})
	for {
		page, err := lister.ListXorbs(ctx, PageRequest{Cursor: xorbCursor, Limit: 2})
		if err != nil {
			t.Fatal(err)
		}
		for _, record := range page.Items {
			if _, duplicate := seenXorbs[record.Layout.Hash]; duplicate {
				t.Fatalf("duplicate xorb %s", record.Layout.Hash)
			}
			seenXorbs[record.Layout.Hash] = struct{}{}
		}
		if page.NextCursor == "" {
			break
		}
		xorbCursor = page.NextCursor
	}
	if len(seenXorbs) != 7 {
		t.Fatalf("listed %d xorbs, want 7", len(seenXorbs))
	}

	shardPage, err := lister.ListShards(ctx, nil, PageRequest{Limit: 1})
	if err != nil || shardPage.NextCursor == "" {
		t.Fatalf("first shard page = %#v, %v", shardPage, err)
	}
	alpha := "alpha"
	if _, err := lister.ListShards(ctx, &alpha, PageRequest{Cursor: shardPage.NextCursor, Limit: 1}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("cross-filter shard cursor = %v", err)
	}
	if _, err := lister.ListFiles(ctx, nil, PageRequest{Cursor: shardPage.NextCursor, Limit: 1}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("cross-method shard cursor = %v", err)
	}
	shardCount := len(shardPage.Items)
	for shardPage.NextCursor != "" {
		shardPage, err = lister.ListShards(ctx, nil, PageRequest{Cursor: shardPage.NextCursor, Limit: 1})
		if err != nil {
			t.Fatal(err)
		}
		shardCount += len(shardPage.Items)
	}
	if shardCount != len(namespaces)*3 {
		t.Fatalf("listed %d shards, want %d", shardCount, len(namespaces)*3)
	}

	countFiles := func(namespace *string) int {
		t.Helper()
		count := 0
		request := PageRequest{Limit: 2}
		for {
			page, err := lister.ListFiles(ctx, namespace, request)
			if err != nil {
				t.Fatal(err)
			}
			count += len(page.Items)
			if page.NextCursor == "" {
				return count
			}
			request.Cursor = page.NextCursor
		}
	}
	if got := countFiles(nil); got != len(namespaces)*recordsPerNamespace {
		t.Fatalf("all file count = %d", got)
	}
	for _, namespace := range namespaces {
		if got := countFiles(&namespace); got != recordsPerNamespace {
			t.Fatalf("namespace %q file count = %d", namespace, got)
		}
	}

	countDedup, countSHA := 0, 0
	dedupRequest, shaRequest := PageRequest{Limit: 2}, PageRequest{Limit: 2}
	for {
		page, err := lister.ListDedup(ctx, nil, dedupRequest)
		if err != nil {
			t.Fatal(err)
		}
		countDedup += len(page.Items)
		if page.NextCursor == "" {
			break
		}
		dedupRequest.Cursor = page.NextCursor
	}
	for {
		page, err := lister.ListSHA256(ctx, nil, shaRequest)
		if err != nil {
			t.Fatal(err)
		}
		countSHA += len(page.Items)
		if page.NextCursor == "" {
			break
		}
		shaRequest.Cursor = page.NextCursor
	}
	wantScoped := len(namespaces) * recordsPerNamespace
	if countDedup != wantScoped || countSHA != wantScoped {
		t.Fatalf("dedup/SHA counts = %d/%d, want %d", countDedup, countSHA, wantScoped)
	}
	for _, namespace := range namespaces {
		dedupCount, shaCount := 0, 0
		dedupRequest, shaRequest := PageRequest{Limit: 1}, PageRequest{Limit: 1}
		for {
			page, err := lister.ListDedup(ctx, &namespace, dedupRequest)
			if err != nil {
				t.Fatal(err)
			}
			dedupCount += len(page.Items)
			if page.NextCursor == "" {
				break
			}
			dedupRequest.Cursor = page.NextCursor
		}
		for {
			page, err := lister.ListSHA256(ctx, &namespace, shaRequest)
			if err != nil {
				t.Fatal(err)
			}
			shaCount += len(page.Items)
			if page.NextCursor == "" {
				break
			}
			shaRequest.Cursor = page.NextCursor
		}
		if dedupCount != recordsPerNamespace || shaCount != recordsPerNamespace {
			t.Fatalf("namespace %q dedup/SHA counts = %d/%d", namespace, dedupCount, shaCount)
		}
	}

	first, err := lister.ListFiles(ctx, &alpha, PageRequest{Limit: 1})
	if err != nil || first.NextCursor == "" {
		t.Fatalf("first filtered page = %#v, %v", first, err)
	}
	beta := "beta"
	if _, err := lister.ListFiles(ctx, &beta, PageRequest{Cursor: first.NextCursor, Limit: 1}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("cross-namespace cursor = %v", err)
	}
	if _, err := lister.ListFiles(ctx, nil, PageRequest{Cursor: first.NextCursor, Limit: 1}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("cross-filter cursor = %v", err)
	}
	if _, err := lister.ListDedup(ctx, &alpha, PageRequest{Cursor: first.NextCursor, Limit: 1}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("cross-method cursor = %v", err)
	}
	if _, err := lister.ListSHA256(ctx, &alpha, PageRequest{Cursor: first.NextCursor, Limit: 1}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("cross-method SHA cursor = %v", err)
	}
	firstSHA, err := lister.ListSHA256(ctx, &alpha, PageRequest{Limit: 1})
	if err != nil || firstSHA.NextCursor == "" {
		t.Fatalf("first filtered SHA page = %#v, %v", firstSHA, err)
	}
	if _, err := lister.ListSHA256(ctx, &beta, PageRequest{Cursor: firstSHA.NextCursor, Limit: 1}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("cross-namespace SHA cursor = %v", err)
	}
	mutationPage, err := lister.ListFiles(ctx, nil, PageRequest{Limit: 1})
	if err != nil || mutationPage.NextCursor == "" {
		t.Fatalf("mutation test first page = %#v, %v", mutationPage, err)
	}
	behind, ahead := xethash.Zero, xethash.Hash{}
	for i := range ahead {
		ahead[i] = 0xff
	}
	mutationNamespace := mutationPage.Items[0].Namespace
	for _, hash := range []xethash.Hash{behind, ahead} {
		if err := store.PutFile(ctx, mutationNamespace, FileRecord{
			File:  shard.RegisteredFile{File: shard.File{Hash: hash}},
			Shard: BlobKey{Kind: BlobShard, Hash: xethash.Chunk([]byte("mutation shard"))},
		}); err != nil {
			t.Fatal(err)
		}
	}
	foundBehind, foundAhead := false, false
	request := PageRequest{Cursor: mutationPage.NextCursor, Limit: 2}
	for {
		page, err := lister.ListFiles(ctx, nil, request)
		if err != nil {
			t.Fatal(err)
		}
		for _, item := range page.Items {
			foundBehind = foundBehind || item.Record.File.File.Hash == behind
			foundAhead = foundAhead || item.Record.File.File.Hash == ahead
		}
		if page.NextCursor == "" {
			break
		}
		request.Cursor = page.NextCursor
	}
	if foundBehind || !foundAhead {
		t.Fatalf("concurrent inserts behind/ahead cursor found = %v/%v", foundBehind, foundAhead)
	}
	for _, operation := range []func(context.Context) error{
		func(ctx context.Context) error { _, err := lister.ListXorbs(ctx, PageRequest{}); return err },
		func(ctx context.Context) error { _, err := lister.ListShards(ctx, nil, PageRequest{}); return err },
		func(ctx context.Context) error { _, err := lister.ListFiles(ctx, nil, PageRequest{}); return err },
		func(ctx context.Context) error { _, err := lister.ListDedup(ctx, nil, PageRequest{}); return err },
		func(ctx context.Context) error { _, err := lister.ListSHA256(ctx, nil, PageRequest{}); return err },
	} {
		canceled, cancel := context.WithCancel(ctx)
		cancel()
		if err := operation(canceled); !errors.Is(err, context.Canceled) {
			t.Fatalf("canceled index list = %v", err)
		}
	}
	if _, err := lister.ListXorbs(ctx, PageRequest{Cursor: "bad"}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("malformed xorb cursor = %v", err)
	}
	if _, err := lister.ListXorbs(ctx, PageRequest{Limit: MaxPageSize + 1}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("invalid xorb limit = %v", err)
	}
	if _, err := lister.ListFiles(ctx, nil, PageRequest{Limit: MaxPageSize + 1}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("invalid file limit = %v", err)
	}
	if _, err := lister.ListSHA256(ctx, nil, PageRequest{Cursor: encodeScopedCursor(cursorSHA256All, "", make([]byte, 40)), Limit: MaxPageSize + 1}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("invalid index limit = %v", err)
	}
}

func TestIndexListerContracts(t *testing.T) {
	t.Run("memory", func(t *testing.T) {
		runIndexListerContract(t, func(testing.TB) IndexStore { return NewMemoryStore() })
	})
	t.Run("sqlite", func(t *testing.T) {
		requireLocalDurability(t)
		runIndexListerContract(t, func(t testing.TB) IndexStore {
			store, err := OpenSQLiteIndexStore(filepath.Join(t.TempDir(), "index.db"))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = store.Close() })
			return store
		})
	})
}

func TestPageCursorValidation(t *testing.T) {
	if _, _, err := decodeScopedCursor(
		encodeScopedCursor(cursorFileAll, "scope", []byte{1}), cursorFileAll, len(xethash.Hash{}),
	); !errors.Is(err, ErrInvalid) {
		t.Fatalf("wrong-sized scoped cursor = %v", err)
	}
	if _, err := decodeCursor("AA=="); !errors.Is(err, ErrInvalid) {
		t.Fatalf("non-canonical cursor = %v", err)
	}
}

func TestKeepFirstBoundsUnorderedSelection(t *testing.T) {
	const retained = 4
	items := make([]int, 0, retained)
	for index := range 10_001 {
		// 7,919 is coprime with 10,001, producing a deterministic permutation
		// that exercises insertion, replacement, and rejection positions.
		value := index * 7_919 % 10_001
		items = keepFirst(items, value, retained, func(left, right int) int { return left - right })
		if len(items) > retained || cap(items) > retained {
			t.Fatalf("retained selector size/capacity = %d/%d", len(items), cap(items))
		}
	}
	if want := []int{0, 1, 2, 3}; !reflect.DeepEqual(items, want) {
		t.Fatalf("retained selector = %v, want %v", items, want)
	}
}

func TestMemoryFileListerSelectsBeforeCloning(t *testing.T) {
	store := NewMemoryStore()
	const records = 300
	namespace := "bounded"
	terms := make([]shard.Term, 128)
	store.mu.Lock()
	for i := range records {
		var hash xethash.Hash
		binary.BigEndian.PutUint16(hash[:2], uint16(i))
		key := scopedHash{namespace: namespace, hash: hash}
		store.files[key] = FileRecord{
			File:  shard.RegisteredFile{File: shard.File{Hash: hash, Terms: terms}},
			Shard: BlobKey{Kind: BlobShard, Hash: xethash.Chunk([]byte(fmt.Sprintf("bounded shard %d", i)))},
		}
	}
	store.mu.Unlock()

	page, err := store.ListFiles(context.Background(), &namespace, PageRequest{Limit: 3})
	if err != nil || len(page.Items) != 3 || page.NextCursor == "" {
		t.Fatalf("first bounded file page = %#v, %v", page, err)
	}
	for i, item := range page.Items {
		if got := binary.BigEndian.Uint16(item.Record.File.File.Hash[:2]); got != uint16(i) {
			t.Fatalf("first bounded file page item %d = %d", i, got)
		}
	}
	page.Items[0].Record.File.File.Terms[0].End = 99
	store.mu.RLock()
	first := store.files[scopedHash{namespace: namespace, hash: page.Items[0].Record.File.File.Hash}]
	store.mu.RUnlock()
	if first.File.File.Terms[0].End == 99 {
		t.Fatal("listed file recipe aliases the retained memory record")
	}

	page, err = store.ListFiles(context.Background(), &namespace, PageRequest{
		Cursor: page.NextCursor, Limit: 3,
	})
	if err != nil || len(page.Items) != 3 || page.NextCursor == "" {
		t.Fatalf("second bounded file page = %#v, %v", page, err)
	}
	for i, item := range page.Items {
		if got := binary.BigEndian.Uint16(item.Record.File.File.Hash[:2]); got != uint16(i+3) {
			t.Fatalf("second bounded file page item %d = %d", i, got)
		}
	}
}

func TestMemoryIndexListerCancellationDuringScan(t *testing.T) {
	store := NewMemoryStore()
	ctx := context.Background()
	hash := xethash.Chunk([]byte("cancel index listing"))
	shardKey := BlobKey{Kind: BlobShard, Hash: xethash.Chunk([]byte("cancel index shard"))}
	if err := store.PutXorb(ctx, XorbRecord{Blob: BlobKey{Kind: BlobXorb, Hash: hash}, Layout: xorb.Ingested{Hash: hash}}); err != nil {
		t.Fatal(err)
	}
	if err := store.PutFile(ctx, "scope", FileRecord{File: shard.RegisteredFile{File: shard.File{Hash: hash}}, Shard: shardKey}); err != nil {
		t.Fatal(err)
	}
	if err := store.PutDedup(ctx, "scope", hash, DedupRecord{Shard: shardKey}); err != nil {
		t.Fatal(err)
	}
	if err := store.PutSHA256(ctx, "scope", [32]byte{}, 1, hash); err != nil {
		t.Fatal(err)
	}
	if err := store.PublishShard(ctx, ShardPublication{Namespace: "scope", Shard: shardKey}); err != nil {
		t.Fatal(err)
	}
	for name, operation := range map[string]func(context.Context) error{
		"xorbs": func(ctx context.Context) error { _, err := store.ListXorbs(ctx, PageRequest{}); return err },
		"shards": func(ctx context.Context) error {
			_, err := store.ListShards(ctx, nil, PageRequest{})
			return err
		},
		"files": func(ctx context.Context) error { _, err := store.ListFiles(ctx, nil, PageRequest{}); return err },
		"dedup": func(ctx context.Context) error { _, err := store.ListDedup(ctx, nil, PageRequest{}); return err },
		"SHA":   func(ctx context.Context) error { _, err := store.ListSHA256(ctx, nil, PageRequest{}); return err },
	} {
		t.Run(name, func(t *testing.T) {
			ctx := &cancelAfterCheckContext{Context: context.Background(), after: 2}
			if err := operation(ctx); !errors.Is(err, context.Canceled) {
				t.Fatalf("index list canceled during scan = %v", err)
			}
		})
	}
}

func TestSQLiteShardBackfillFailures(t *testing.T) {
	requireLocalDurability(t)
	ctx := context.Background()
	t.Run("malformed legacy storage class", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "index.db")
		db := openSQLiteV3TestIndex(t, path)
		connection, err := db.Conn(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := connection.ExecContext(ctx, "PRAGMA ignore_check_constraints=ON"); err != nil {
			_ = connection.Close()
			t.Fatal(err)
		}
		fileHash := xethash.Chunk([]byte("legacy text record"))
		source := BlobKey{Kind: BlobShard, Hash: xethash.Chunk([]byte("legacy text source"))}
		data, err := encodeIndexRecord(FileRecord{
			File: shard.RegisteredFile{File: shard.File{Hash: fileHash}}, Shard: source,
		})
		if err != nil {
			_ = connection.Close()
			t.Fatal(err)
		}
		_, err = connection.ExecContext(ctx,
			"INSERT INTO files(namespace, hash, record) VALUES(?, ?, ?)",
			"scope", hashBytes(fileHash), string(data),
		)
		_ = connection.Close()
		if err != nil {
			t.Fatal(err)
		}
		if err := db.Close(); err != nil {
			t.Fatal(err)
		}
		if _, err := OpenSQLiteIndexStore(path); !errors.Is(err, ErrCorrupt) {
			t.Fatalf("legacy text record migration = %v", err)
		}
	})

	t.Run("backfill backend and cancellation errors", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "index.db")
		db := openSQLiteV3TestIndex(t, path)
		fileHash := xethash.Chunk([]byte("backfill backend file"))
		source := BlobKey{Kind: BlobShard, Hash: xethash.Chunk([]byte("backfill backend source"))}
		data, err := encodeIndexRecord(FileRecord{
			File: shard.RegisteredFile{File: shard.File{Hash: fileHash}}, Shard: source,
		})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := db.ExecContext(ctx,
			"INSERT INTO files(namespace, hash, record) VALUES(?, ?, ?)",
			"scope", hashBytes(fileHash), data,
		); err != nil {
			t.Fatal(err)
		}
		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		if err := backfillSQLiteShards(ctx, tx); err == nil {
			t.Fatal("backfill without destination table succeeded")
		}
		_ = tx.Rollback()
		tx, err = db.BeginTx(ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		canceled, cancel := context.WithCancel(ctx)
		cancel()
		if err := backfillSQLiteShards(canceled, tx); !errors.Is(err, context.Canceled) {
			t.Fatalf("canceled backfill = %v", err)
		}
		_ = tx.Rollback()
		if err := db.Close(); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("publication verifier cancellation", func(t *testing.T) {
		store, err := OpenSQLiteIndexStore(filepath.Join(t.TempDir(), "index.db"))
		if err != nil {
			t.Fatal(err)
		}
		defer store.Close() //nolint:errcheck // Test cleanup.
		tx, err := store.db.BeginTx(ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback() //nolint:errcheck // Test cleanup.
		canceled, cancel := context.WithCancel(ctx)
		cancel()
		hash := xethash.Chunk([]byte("canceled publication verification"))
		for name, verify := range map[string]func() error{
			"shard": func() error { return verifySQLiteShardRow(canceled, tx, "scope", hash) },
			"file":  func() error { return verifySQLiteFileRow(canceled, tx, "scope", hash) },
			"dedup": func() error { return verifySQLiteDedupRow(canceled, tx, "scope", hash) },
		} {
			t.Run(name, func(t *testing.T) {
				if err := verify(); !errors.Is(err, context.Canceled) {
					t.Fatalf("canceled %s verification = %v", name, err)
				}
			})
		}
		if err := store.initialize(canceled); !errors.Is(err, context.Canceled) {
			t.Fatalf("canceled initialization = %v", err)
		}
	})

	t.Run("version four schema collision rolls back", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "index.db")
		db := openSQLiteV3TestIndex(t, path)
		if _, err := db.ExecContext(ctx, "CREATE TABLE shards(conflict INTEGER)"); err != nil {
			t.Fatal(err)
		}
		if err := db.Close(); err != nil {
			t.Fatal(err)
		}
		if _, err := OpenSQLiteIndexStore(path); err == nil {
			t.Fatal("conflicting version four migration succeeded")
		}
		db, err := sql.Open("sqlite", path)
		if err != nil {
			t.Fatal(err)
		}
		defer db.Close() //nolint:errcheck // Test cleanup.
		var version, conflictColumns int
		if err := db.QueryRowContext(ctx, "PRAGMA user_version").Scan(&version); err != nil {
			t.Fatal(err)
		}
		if err := db.QueryRowContext(ctx,
			"SELECT count(*) FROM pragma_table_info('shards') WHERE name = 'conflict'",
		).Scan(&conflictColumns); err != nil {
			t.Fatal(err)
		}
		if version != 3 || conflictColumns != 1 {
			t.Fatalf("rolled-back collision = version %d, conflict columns %d", version, conflictColumns)
		}
	})

	t.Run("version four backfill query failure rolls back", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "index.db")
		db := openSQLiteV3TestIndex(t, path)
		if _, err := db.ExecContext(ctx, "DROP TABLE files; CREATE TABLE files(namespace TEXT)"); err != nil {
			t.Fatal(err)
		}
		if err := db.Close(); err != nil {
			t.Fatal(err)
		}
		if _, err := OpenSQLiteIndexStore(path); err == nil {
			t.Fatal("version four migration with malformed source schema succeeded")
		}
		db, err := sql.Open("sqlite", path)
		if err != nil {
			t.Fatal(err)
		}
		defer db.Close() //nolint:errcheck // Test cleanup.
		var version, shardTables int
		if err := db.QueryRowContext(ctx, "PRAGMA user_version").Scan(&version); err != nil {
			t.Fatal(err)
		}
		if err := db.QueryRowContext(ctx,
			"SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name = 'shards'",
		).Scan(&shardTables); err != nil {
			t.Fatal(err)
		}
		if version != 3 || shardTables != 0 {
			t.Fatalf("rolled-back backfill = version %d, shard tables %d", version, shardTables)
		}
	})
}

func TestSQLiteIndexListerBackendAndCorruptionErrors(t *testing.T) {
	requireLocalDurability(t)
	ctx := context.Background()
	t.Run("closed", func(t *testing.T) {
		store, err := OpenSQLiteIndexStore(filepath.Join(t.TempDir(), "index.db"))
		if err != nil {
			t.Fatal(err)
		}
		if err := store.Close(); err != nil {
			t.Fatal(err)
		}
		for name, operation := range map[string]func() error{
			"xorbs":  func() error { _, err := store.ListXorbs(ctx, PageRequest{}); return err },
			"shards": func() error { _, err := store.ListShards(ctx, nil, PageRequest{}); return err },
			"files":  func() error { _, err := store.ListFiles(ctx, nil, PageRequest{}); return err },
			"dedup":  func() error { _, err := store.ListDedup(ctx, nil, PageRequest{}); return err },
			"SHA":    func() error { _, err := store.ListSHA256(ctx, nil, PageRequest{}); return err },
		} {
			t.Run(name, func(t *testing.T) {
				if err := operation(); err == nil {
					t.Fatal("listing against closed SQLite store succeeded")
				}
			})
		}
	})

	t.Run("malformed xorb key", func(t *testing.T) {
		store, err := OpenSQLiteIndexStore(filepath.Join(t.TempDir(), "index.db"))
		if err != nil {
			t.Fatal(err)
		}
		defer store.Close() //nolint:errcheck // Test cleanup.
		connection, err := store.db.Conn(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer connection.Close() //nolint:errcheck // Test cleanup.
		if _, err := connection.ExecContext(ctx, "PRAGMA ignore_check_constraints=ON"); err != nil {
			t.Fatal(err)
		}
		if _, err := connection.ExecContext(ctx, "INSERT INTO xorbs(hash, record) VALUES(?, ?)", []byte{1}, []byte("{}")); err != nil {
			t.Fatal(err)
		}
		if _, err := store.ListXorbs(ctx, PageRequest{}); !errors.Is(err, ErrCorrupt) {
			t.Fatalf("malformed SQLite xorb key = %v", err)
		}
	})

	for _, test := range []struct {
		name   string
		insert func(*testing.T, *sql.Conn)
		list   func(*SQLiteIndexStore) error
	}{
		{"xorb text hash", func(t *testing.T, connection *sql.Conn) {
			hash := xethash.Chunk([]byte("text xorb hash"))
			record, err := encodeIndexRecord(XorbRecord{
				Blob: BlobKey{Kind: BlobXorb, Hash: hash}, Layout: xorb.Ingested{Hash: hash},
			})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := connection.ExecContext(ctx, "INSERT INTO xorbs(hash, record) VALUES(?, ?)", string(hash[:]), record); err != nil {
				t.Fatal(err)
			}
		}, func(store *SQLiteIndexStore) error {
			_, err := store.ListXorbs(ctx, PageRequest{})
			return err
		}},
		{"shard text hash", func(t *testing.T, connection *sql.Conn) {
			hash := xethash.Chunk([]byte("text shard hash"))
			record, err := encodeIndexRecord(ShardRecord{Blob: BlobKey{Kind: BlobShard, Hash: hash}})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := connection.ExecContext(ctx,
				"INSERT INTO shards(namespace, hash, record) VALUES(?, ?, ?)",
				"scope", string(hash[:]), record,
			); err != nil {
				t.Fatal(err)
			}
		}, func(store *SQLiteIndexStore) error {
			_, err := store.ListShards(ctx, nil, PageRequest{})
			return err
		}},
		{"shard short hash", func(t *testing.T, connection *sql.Conn) {
			hash := xethash.Chunk([]byte("short shard hash"))
			record, err := encodeIndexRecord(ShardRecord{Blob: BlobKey{Kind: BlobShard, Hash: hash}})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := connection.ExecContext(ctx,
				"INSERT INTO shards(namespace, hash, record) VALUES(?, ?, ?)",
				"scope", []byte{1}, record,
			); err != nil {
				t.Fatal(err)
			}
		}, func(store *SQLiteIndexStore) error {
			_, err := store.ListShards(ctx, nil, PageRequest{})
			return err
		}},
		{"shard malformed record", func(t *testing.T, connection *sql.Conn) {
			hash := xethash.Chunk([]byte("malformed shard record"))
			if _, err := connection.ExecContext(ctx,
				"INSERT INTO shards(namespace, hash, record) VALUES(?, ?, ?)",
				"scope", hashBytes(hash), []byte("{"),
			); err != nil {
				t.Fatal(err)
			}
		}, func(store *SQLiteIndexStore) error {
			_, err := store.ListShards(ctx, nil, PageRequest{})
			return err
		}},
		{"shard mismatched record", func(t *testing.T, connection *sql.Conn) {
			hash := xethash.Chunk([]byte("mismatched shard record"))
			record, err := encodeIndexRecord(ShardRecord{Blob: BlobKey{
				Kind: BlobShard, Hash: xethash.Chunk([]byte("different shard record")),
			}})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := connection.ExecContext(ctx,
				"INSERT INTO shards(namespace, hash, record) VALUES(?, ?, ?)",
				"scope", hashBytes(hash), record,
			); err != nil {
				t.Fatal(err)
			}
		}, func(store *SQLiteIndexStore) error {
			_, err := store.ListShards(ctx, nil, PageRequest{})
			return err
		}},
		{"file blob namespace", func(t *testing.T, connection *sql.Conn) {
			hash := xethash.Chunk([]byte("blob file namespace"))
			record, err := encodeIndexRecord(FileRecord{
				File: shard.RegisteredFile{File: shard.File{Hash: hash}}, Shard: BlobKey{Kind: BlobShard},
			})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := connection.ExecContext(ctx, "INSERT INTO files(namespace, hash, record) VALUES(?, ?, ?)", []byte("scope"), hashBytes(hash), record); err != nil {
				t.Fatal(err)
			}
		}, func(store *SQLiteIndexStore) error {
			_, err := store.ListFiles(ctx, nil, PageRequest{})
			return err
		}},
		{"dedup text hash", func(t *testing.T, connection *sql.Conn) {
			hash := xethash.Chunk([]byte("text dedup hash"))
			record, err := encodeIndexRecord(DedupRecord{Shard: BlobKey{Kind: BlobShard}})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := connection.ExecContext(ctx, "INSERT INTO dedup(namespace, chunk_hash, record) VALUES(?, ?, ?)", "scope", string(hash[:]), record); err != nil {
				t.Fatal(err)
			}
		}, func(store *SQLiteIndexStore) error {
			_, err := store.ListDedup(ctx, nil, PageRequest{})
			return err
		}},
		{"SHA real size", func(t *testing.T, connection *sql.Conn) {
			if _, err := connection.ExecContext(ctx, `
INSERT INTO sha256_associations(namespace, sum, size, file_hash) VALUES(?, ?, ?, ?)`,
				"scope", make([]byte, 32), 1.5, make([]byte, 32)); err != nil {
				t.Fatal(err)
			}
		}, func(store *SQLiteIndexStore) error {
			_, err := store.ListSHA256(ctx, nil, PageRequest{})
			return err
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			store, err := OpenSQLiteIndexStore(filepath.Join(t.TempDir(), "index.db"))
			if err != nil {
				t.Fatal(err)
			}
			defer store.Close() //nolint:errcheck // Test cleanup.
			connection, err := store.db.Conn(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer connection.Close() //nolint:errcheck // Test cleanup.
			if _, err := connection.ExecContext(ctx, "PRAGMA ignore_check_constraints=ON"); err != nil {
				t.Fatal(err)
			}
			test.insert(t, connection)
			if err := test.list(store); !errors.Is(err, ErrCorrupt) {
				t.Fatalf("malformed SQLite storage class = %v", err)
			}
		})
	}
}

func TestSQLiteIndexListerQueryPlans(t *testing.T) {
	requireLocalDurability(t)
	store, err := OpenSQLiteIndexStore(filepath.Join(t.TempDir(), "index.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close() //nolint:errcheck // Test cleanup.
	hash := xethash.Chunk([]byte("SQLite query plan cursor"))
	var sum [32]byte
	copy(sum[:], hash[:])
	fileQuery, fileArguments := scopedHashQuery(
		"SELECT namespace, hash, record FROM files", "hash", nil, "scope", hash, true, 1,
	)
	shardQuery, shardArguments := scopedHashQuery(
		"SELECT namespace, hash, record FROM shards", "hash", nil, "scope", hash, true, 1,
	)
	shaQuery, shaArguments := scopedSHAQuery(nil, "scope", sum, 1, true, 1)
	for name, plan := range map[string]struct {
		table     string
		query     string
		arguments []any
	}{
		"shards": {table: "shards", query: shardQuery, arguments: shardArguments},
		"files":  {table: "files", query: fileQuery, arguments: fileArguments},
		"SHA":    {table: "sha256_associations", query: shaQuery, arguments: shaArguments},
	} {
		t.Run(name, func(t *testing.T) {
			rows, err := store.db.QueryContext(context.Background(), "EXPLAIN QUERY PLAN "+plan.query, plan.arguments...)
			if err != nil {
				t.Fatal(err)
			}
			defer rows.Close() //nolint:errcheck // Test failure is decisive.
			foundSearch := false
			for rows.Next() {
				var id, parent, unused int
				var detail string
				if err := rows.Scan(&id, &parent, &unused, &detail); err != nil {
					t.Fatal(err)
				}
				if strings.Contains(detail, "MULTI-INDEX OR") || strings.Contains(detail, "USE TEMP B-TREE") {
					t.Fatalf("unbounded query plan: %s", detail)
				}
				if strings.Contains(detail, "SEARCH "+plan.table+" USING PRIMARY KEY") {
					foundSearch = true
				}
			}
			if err := rows.Err(); err != nil {
				t.Fatal(err)
			}
			if !foundSearch {
				t.Fatal("query plan did not seek through the composite primary key")
			}
		})
	}
}

func testProtectionID(value uint16) ProtectionID {
	var id ProtectionID
	id[len(id)-2], id[len(id)-1] = byte(value>>8), byte(value)
	return id
}

func runProtectionStoreContract(t *testing.T, store ProtectionStore) {
	t.Helper()
	ctx := context.Background()
	createdAt := time.Date(2026, time.August, 10, 12, 0, 0, 123, time.FixedZone("test", 3600))
	expiresAt := createdAt.Add(time.Hour)
	if err := store.PutBlobStage(ctx, BlobStage{}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("invalid blob stage = %v", err)
	}
	if err := store.PutFileLease(ctx, FileLease{}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("invalid file lease = %v", err)
	}
	for name, invalid := range map[string]BlobStage{
		"kind": {
			ID: testProtectionID(910), Blob: BlobKey{
				Kind: "invalid", Hash: xethash.Chunk([]byte("invalid stage kind")),
			},
			CreatedAt: createdAt, ExpiresAt: expiresAt,
		},
		"hash": {
			ID: testProtectionID(914), Blob: BlobKey{Kind: BlobXorb},
			CreatedAt: createdAt, ExpiresAt: expiresAt,
		},
		"creation": {
			ID: testProtectionID(911), Blob: BlobKey{
				Kind: BlobXorb, Hash: xethash.Chunk([]byte("stage without creation")),
			}, ExpiresAt: expiresAt,
		},
		"expiration": {
			ID: testProtectionID(912), Blob: BlobKey{
				Kind: BlobXorb, Hash: xethash.Chunk([]byte("stage without expiration")),
			}, CreatedAt: createdAt,
		},
		"reversed": {
			ID: testProtectionID(913), Blob: BlobKey{
				Kind: BlobXorb, Hash: xethash.Chunk([]byte("stage with reversed expiration")),
			},
			CreatedAt: createdAt, ExpiresAt: createdAt.Add(-time.Second),
		},
	} {
		if err := store.PutBlobStage(ctx, invalid); !errors.Is(err, ErrInvalid) {
			t.Fatalf("invalid blob stage %s = %v", name, err)
		}
	}
	for name, invalid := range map[string]FileLease{
		"creation":   {ID: testProtectionID(920), ExpiresAt: expiresAt},
		"expiration": {ID: testProtectionID(921), CreatedAt: createdAt},
		"reversed": {
			ID: testProtectionID(922), CreatedAt: createdAt, ExpiresAt: createdAt.Add(-time.Second),
		},
	} {
		if err := store.PutFileLease(ctx, invalid); !errors.Is(err, ErrInvalid) {
			t.Fatalf("invalid file lease %s = %v", name, err)
		}
	}
	outOfRange := time.Date(3000, time.January, 1, 0, 0, 0, 0, time.UTC)
	if err := store.PutBlobStage(ctx, BlobStage{
		ID: testProtectionID(900), Blob: BlobKey{Kind: BlobXorb},
		CreatedAt: createdAt, ExpiresAt: outOfRange,
	}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("out-of-range blob stage = %v", err)
	}
	if err := store.PutFileLease(ctx, FileLease{
		ID: testProtectionID(901), CreatedAt: createdAt, ExpiresAt: outOfRange,
	}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("out-of-range file lease = %v", err)
	}

	namespaces := []string{"", "alpha", "beta"}
	wantStages, wantLeases := 0, 0
	for namespaceIndex, namespace := range namespaces {
		for i := range 3 {
			value := uint16(namespaceIndex*10 + i + 1)
			id := testProtectionID(value)
			hash := xethash.Chunk([]byte(fmt.Sprintf("protection %s %d", namespace, i)))
			stage := BlobStage{
				ID: id, Namespace: namespace, Blob: BlobKey{Kind: BlobXorb, Hash: hash},
				CreatedAt: createdAt, ExpiresAt: expiresAt,
			}
			if err := store.PutBlobStage(ctx, stage); err != nil {
				t.Fatal(err)
			}
			if err := store.PutBlobStage(ctx, stage); err != nil {
				t.Fatalf("idempotent blob stage = %v", err)
			}
			lease := FileLease{
				ID: id, Namespace: namespace, File: hash,
				CreatedAt: createdAt, ExpiresAt: expiresAt,
			}
			if err := store.PutFileLease(ctx, lease); err != nil {
				t.Fatal(err)
			}
			if err := store.PutFileLease(ctx, lease); err != nil {
				t.Fatalf("idempotent file lease = %v", err)
			}
			wantStages++
			wantLeases++
		}
	}

	conflictingStage := BlobStage{
		ID: testProtectionID(1), Blob: BlobKey{
			Kind: BlobShard, Hash: xethash.Chunk([]byte("retargeted stage")),
		}, CreatedAt: createdAt, ExpiresAt: expiresAt,
	}
	if err := store.PutBlobStage(ctx, conflictingStage); !errors.Is(err, ErrConflict) {
		t.Fatalf("retargeted blob stage = %v", err)
	}
	conflictingLease := FileLease{
		ID: testProtectionID(1), File: xethash.Chunk([]byte("retargeted lease")),
		CreatedAt: createdAt, ExpiresAt: expiresAt,
	}
	if err := store.PutFileLease(ctx, conflictingLease); !errors.Is(err, ErrConflict) {
		t.Fatalf("retargeted file lease = %v", err)
	}
	if err := store.RenewBlobStage(ctx, "", testProtectionID(1), expiresAt.Add(-time.Minute)); err != nil {
		t.Fatalf("shortening stage renewal = %v", err)
	}
	extendedStage := expiresAt.Add(30 * time.Minute)
	if err := store.RenewBlobStage(ctx, "", testProtectionID(1), extendedStage); err != nil {
		t.Fatalf("extending stage renewal = %v", err)
	}
	if err := store.RenewBlobStage(ctx, "missing", testProtectionID(500), extendedStage); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing stage renewal = %v", err)
	}
	if err := store.RenewFileLease(ctx, "", testProtectionID(1), expiresAt.Add(-time.Minute)); err != nil {
		t.Fatalf("shortening renewal = %v", err)
	}
	extended := expiresAt.Add(time.Hour)
	if err := store.RenewFileLease(ctx, "", testProtectionID(1), extended); err != nil {
		t.Fatalf("extending renewal = %v", err)
	}
	if err := store.RenewFileLease(ctx, "missing", testProtectionID(500), extended); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing renewal = %v", err)
	}

	countStages := func(namespace *string) (int, map[ProtectionID]BlobStage, string) {
		t.Helper()
		count, cursor := 0, ""
		records := make(map[ProtectionID]BlobStage)
		for {
			page, err := store.ListBlobStages(ctx, namespace, PageRequest{Cursor: cursor, Limit: 2})
			if err != nil {
				t.Fatal(err)
			}
			for _, stage := range page.Items {
				records[stage.ID] = stage
			}
			count += len(page.Items)
			if page.NextCursor == "" {
				return count, records, cursor
			}
			cursor = page.NextCursor
		}
	}
	countLeases := func(namespace *string) (int, map[ProtectionID]FileLease, string) {
		t.Helper()
		count, cursor := 0, ""
		records := make(map[ProtectionID]FileLease)
		for {
			page, err := store.ListFileLeases(ctx, namespace, PageRequest{Cursor: cursor, Limit: 2})
			if err != nil {
				t.Fatal(err)
			}
			for _, lease := range page.Items {
				records[lease.ID] = lease
			}
			count += len(page.Items)
			if page.NextCursor == "" {
				return count, records, cursor
			}
			cursor = page.NextCursor
		}
	}
	stageCount, stages, stageCursor := countStages(nil)
	leaseCount, leases, leaseCursor := countLeases(nil)
	if stageCount != wantStages || leaseCount != wantLeases {
		t.Fatalf("stage/lease counts = %d/%d, want %d/%d", stageCount, leaseCount, wantStages, wantLeases)
	}
	if got := leases[testProtectionID(1)].ExpiresAt; !got.Equal(extended) {
		t.Fatalf("renewed lease expiration = %v, want %v", got, extended)
	}
	if got := stages[testProtectionID(1)].ExpiresAt; !got.Equal(extendedStage) {
		t.Fatalf("renewed stage expiration = %v, want %v", got, extendedStage)
	}
	for _, namespace := range namespaces {
		if count, _, _ := countStages(&namespace); count != 3 {
			t.Fatalf("namespace %q stage count = %d", namespace, count)
		}
		if count, _, _ := countLeases(&namespace); count != 3 {
			t.Fatalf("namespace %q lease count = %d", namespace, count)
		}
	}
	if _, err := store.ListFileLeases(ctx, nil, PageRequest{Cursor: stageCursor, Limit: 1}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("cross-method protection cursor = %v", err)
	}
	alpha := "alpha"
	if _, err := store.ListFileLeases(ctx, &alpha, PageRequest{Cursor: leaseCursor, Limit: 1}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("cross-filter protection cursor = %v", err)
	}
	if _, err := store.ListBlobStages(ctx, nil, PageRequest{Cursor: "bad"}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("malformed stage cursor = %v", err)
	}
	if _, err := store.ListFileLeases(ctx, nil, PageRequest{Limit: MaxPageSize + 1}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("oversized lease page = %v", err)
	}

	if err := store.DeleteBlobStage(ctx, "", testProtectionID(1)); err != nil {
		t.Fatal(err)
	}
	if err := store.DeleteBlobStage(ctx, "", testProtectionID(1)); err != nil {
		t.Fatalf("idempotent stage delete = %v", err)
	}
	if err := store.DeleteFileLease(ctx, "", testProtectionID(1)); err != nil {
		t.Fatal(err)
	}
	if err := store.DeleteFileLease(ctx, "", testProtectionID(1)); err != nil {
		t.Fatalf("idempotent lease delete = %v", err)
	}
	if count, _, _ := countStages(nil); count != wantStages-1 {
		t.Fatalf("stage count after delete = %d", count)
	}
	if count, _, _ := countLeases(nil); count != wantLeases-1 {
		t.Fatalf("lease count after delete = %d", count)
	}

	canceled, cancel := context.WithCancel(ctx)
	cancel()
	validStage := BlobStage{
		ID: testProtectionID(930), Blob: BlobKey{
			Kind: BlobXorb, Hash: xethash.Chunk([]byte("canceled stage")),
		},
		CreatedAt: createdAt, ExpiresAt: expiresAt,
	}
	validLease := FileLease{
		ID: testProtectionID(931), CreatedAt: createdAt, ExpiresAt: expiresAt,
	}
	for name, call := range map[string]func() error{
		"put stage":    func() error { return store.PutBlobStage(canceled, validStage) },
		"renew stage":  func() error { return store.RenewBlobStage(canceled, "", testProtectionID(2), extended) },
		"delete stage": func() error { return store.DeleteBlobStage(canceled, "", testProtectionID(2)) },
		"put lease":    func() error { return store.PutFileLease(canceled, validLease) },
		"renew lease":  func() error { return store.RenewFileLease(canceled, "", testProtectionID(2), extended) },
		"delete lease": func() error { return store.DeleteFileLease(canceled, "", testProtectionID(2)) },
	} {
		if err := call(); !errors.Is(err, context.Canceled) {
			t.Fatalf("canceled %s = %v", name, err)
		}
	}
	if err := store.RenewBlobStage(ctx, "", testProtectionID(2), time.Time{}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("invalid stage renewal time = %v", err)
	}
	if err := store.RenewFileLease(ctx, "", testProtectionID(2), time.Time{}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("invalid lease renewal time = %v", err)
	}
	if _, err := store.ListBlobStages(canceled, nil, PageRequest{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled stage list = %v", err)
	}
	if _, err := store.ListFileLeases(canceled, nil, PageRequest{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled lease list = %v", err)
	}
	if memory, ok := store.(*MemoryStore); ok {
		if err := memory.PutBlobStage(
			&cancelAfterCheckContext{Context: ctx, after: 2}, validStage,
		); !errors.Is(err, context.Canceled) {
			t.Fatalf("blob-stage cancellation after lock = %v", err)
		}
		if err := memory.PutFileLease(
			&cancelAfterCheckContext{Context: ctx, after: 2}, validLease,
		); !errors.Is(err, context.Canceled) {
			t.Fatalf("file-lease cancellation after lock = %v", err)
		}
		if err := memory.RenewBlobStage(
			&cancelAfterCheckContext{Context: ctx, after: 2}, "", testProtectionID(2), extended,
		); !errors.Is(err, context.Canceled) {
			t.Fatalf("blob-stage renewal cancellation after lock = %v", err)
		}
		if err := memory.DeleteBlobStage(
			&cancelAfterCheckContext{Context: ctx, after: 2}, "", testProtectionID(2),
		); !errors.Is(err, context.Canceled) {
			t.Fatalf("blob-stage deletion cancellation after lock = %v", err)
		}
		if err := memory.RenewFileLease(
			&cancelAfterCheckContext{Context: ctx, after: 2}, "", testProtectionID(2), extended,
		); !errors.Is(err, context.Canceled) {
			t.Fatalf("file-lease renewal cancellation after lock = %v", err)
		}
		if err := memory.DeleteFileLease(
			&cancelAfterCheckContext{Context: ctx, after: 2}, "", testProtectionID(2),
		); !errors.Is(err, context.Canceled) {
			t.Fatalf("file-lease deletion cancellation after lock = %v", err)
		}
		if _, err := memory.ListBlobStages(
			&cancelAfterCheckContext{Context: ctx, after: 2}, nil, PageRequest{},
		); !errors.Is(err, context.Canceled) {
			t.Fatalf("blob-stage cancellation during scan = %v", err)
		}
		if _, err := memory.ListFileLeases(
			&cancelAfterCheckContext{Context: ctx, after: 2}, nil, PageRequest{},
		); !errors.Is(err, context.Canceled) {
			t.Fatalf("file-lease cancellation during scan = %v", err)
		}
	}
}

func TestProtectionStoreContracts(t *testing.T) {
	t.Run("memory", func(t *testing.T) {
		runProtectionStoreContract(t, NewMemoryStore())
	})
	t.Run("sqlite", func(t *testing.T) {
		requireLocalDurability(t)
		store, err := OpenSQLiteIndexStore(filepath.Join(t.TempDir(), "index.db"))
		if err != nil {
			t.Fatal(err)
		}
		defer store.Close() //nolint:errcheck // Test cleanup.
		runProtectionStoreContract(t, store)
	})
}

type protectionExpiryTestStore interface {
	ProtectionStore
	ProtectionExpiryStore
}

func runProtectionExpiryStoreContract(t *testing.T, store protectionExpiryTestStore) {
	t.Helper()
	ctx := context.Background()
	cutoff := time.Date(2026, time.August, 10, 16, 0, 0, 123, time.UTC)
	createdAt := cutoff.Add(-time.Hour)

	if page, err := store.ListExpiredBlobStages(ctx, cutoff, PageRequest{}); err != nil || len(page.Items) != 0 {
		t.Fatalf("empty expired stage page = %#v, %v", page, err)
	}
	if page, err := store.ListExpiredFileLeases(ctx, cutoff, PageRequest{}); err != nil || len(page.Items) != 0 {
		t.Fatalf("empty expired lease page = %#v, %v", page, err)
	}

	type expirationSpec struct {
		namespace string
		id        ProtectionID
		expiresAt time.Time
	}
	specs := []expirationSpec{
		{namespace: "beta", id: testProtectionID(1), expiresAt: cutoff},
		{namespace: "alpha", id: testProtectionID(2), expiresAt: cutoff},
		{namespace: "zeta", id: testProtectionID(4), expiresAt: cutoff.Add(-2 * time.Minute)},
		{namespace: "", id: testProtectionID(3), expiresAt: cutoff.Add(-time.Minute)},
		{namespace: "alpha", id: testProtectionID(1), expiresAt: cutoff},
		{namespace: "alpha", id: testProtectionID(9), expiresAt: cutoff.Add(time.Nanosecond)},
	}
	wantStages := make([]BlobStage, 0, len(specs)-1)
	wantLeases := make([]FileLease, 0, len(specs)-1)
	for _, spec := range specs {
		payload := []byte(fmt.Sprintf("expiry %s %x", spec.namespace, spec.id))
		hash := xethash.Chunk(payload)
		stage := BlobStage{
			ID: spec.id, Namespace: spec.namespace, Blob: BlobKey{Kind: BlobXorb, Hash: hash},
			CreatedAt: createdAt, ExpiresAt: spec.expiresAt,
		}
		lease := FileLease{
			ID: spec.id, Namespace: spec.namespace, File: hash,
			CreatedAt: createdAt, ExpiresAt: spec.expiresAt,
		}
		if err := store.PutBlobStage(ctx, stage); err != nil {
			t.Fatal(err)
		}
		if err := store.PutFileLease(ctx, lease); err != nil {
			t.Fatal(err)
		}
		if !spec.expiresAt.After(cutoff) {
			wantStages = append(wantStages, stage)
			wantLeases = append(wantLeases, lease)
		}
	}
	slices.SortFunc(wantStages, func(left, right BlobStage) int {
		return compareProtectionExpiry(
			left.ExpiresAt, left.Namespace, left.ID, right.ExpiresAt, right.Namespace, right.ID,
		)
	})
	slices.SortFunc(wantLeases, func(left, right FileLease) int {
		return compareProtectionExpiry(
			left.ExpiresAt, left.Namespace, left.ID, right.ExpiresAt, right.Namespace, right.ID,
		)
	})

	collectStages := func(limit int) ([]BlobStage, string) {
		t.Helper()
		var items []BlobStage
		cursor, penultimateCursor := "", ""
		seen := make(map[string]struct{})
		for {
			page, err := store.ListExpiredBlobStages(ctx, cutoff, PageRequest{Cursor: cursor, Limit: limit})
			if err != nil {
				t.Fatal(err)
			}
			items = append(items, page.Items...)
			if page.NextCursor == "" {
				return items, penultimateCursor
			}
			if _, duplicate := seen[page.NextCursor]; duplicate {
				t.Fatalf("repeated expired-stage cursor %q", page.NextCursor)
			}
			seen[page.NextCursor] = struct{}{}
			penultimateCursor, cursor = page.NextCursor, page.NextCursor
		}
	}
	collectLeases := func(limit int) ([]FileLease, string) {
		t.Helper()
		var items []FileLease
		cursor, penultimateCursor := "", ""
		seen := make(map[string]struct{})
		for {
			page, err := store.ListExpiredFileLeases(ctx, cutoff, PageRequest{Cursor: cursor, Limit: limit})
			if err != nil {
				t.Fatal(err)
			}
			items = append(items, page.Items...)
			if page.NextCursor == "" {
				return items, penultimateCursor
			}
			if _, duplicate := seen[page.NextCursor]; duplicate {
				t.Fatalf("repeated expired-lease cursor %q", page.NextCursor)
			}
			seen[page.NextCursor] = struct{}{}
			penultimateCursor, cursor = page.NextCursor, page.NextCursor
		}
	}
	for _, limit := range []int{1, 2, DefaultPageSize} {
		stages, _ := collectStages(limit)
		if !reflect.DeepEqual(stages, wantStages) {
			t.Fatalf("expired stages with limit %d = %#v, want %#v", limit, stages, wantStages)
		}
		leases, _ := collectLeases(limit)
		if !reflect.DeepEqual(leases, wantLeases) {
			t.Fatalf("expired leases with limit %d = %#v, want %#v", limit, leases, wantLeases)
		}
	}

	firstStagePage, err := store.ListExpiredBlobStages(ctx, cutoff, PageRequest{Limit: 1})
	if err != nil || firstStagePage.NextCursor == "" {
		t.Fatalf("first expired stage page = %#v, %v", firstStagePage, err)
	}
	if _, err := store.ListExpiredBlobStages(
		ctx, cutoff.Add(time.Nanosecond), PageRequest{Cursor: firstStagePage.NextCursor, Limit: 1},
	); !errors.Is(err, ErrInvalid) {
		t.Fatalf("expiry cursor with different cutoff = %v", err)
	}
	if _, err := store.ListExpiredBlobStages(
		ctx, cutoff.In(time.FixedZone("same instant", 3600)), PageRequest{Cursor: firstStagePage.NextCursor, Limit: 1},
	); err != nil {
		t.Fatalf("expiry cursor with equivalent cutoff = %v", err)
	}
	if _, err := store.ListExpiredFileLeases(
		ctx, cutoff, PageRequest{Cursor: firstStagePage.NextCursor, Limit: 1},
	); !errors.Is(err, ErrInvalid) {
		t.Fatalf("cross-method expiry cursor = %v", err)
	}
	for name, request := range map[string]PageRequest{
		"malformed cursor": {Cursor: "bad"},
		"oversized page":   {Limit: MaxPageSize + 1},
		"negative page":    {Limit: -1},
	} {
		if _, err := store.ListExpiredBlobStages(ctx, cutoff, request); !errors.Is(err, ErrInvalid) {
			t.Fatalf("%s = %v", name, err)
		}
	}
	for name, invalidCutoff := range map[string]time.Time{
		"zero":         {},
		"out of range": time.Date(3000, time.January, 1, 0, 0, 0, 0, time.UTC),
	} {
		if _, err := store.ListExpiredFileLeases(ctx, invalidCutoff, PageRequest{}); !errors.Is(err, ErrInvalid) {
			t.Fatalf("%s expiry cutoff = %v", name, err)
		}
		if _, err := store.DeleteExpiredBlobStage(
			ctx, "alpha", testProtectionID(9), invalidCutoff,
		); !errors.Is(err, ErrInvalid) {
			t.Fatalf("%s stage deletion cutoff = %v", name, err)
		}
		if _, err := store.DeleteExpiredFileLease(
			ctx, "alpha", testProtectionID(9), invalidCutoff,
		); !errors.Is(err, ErrInvalid) {
			t.Fatalf("%s lease deletion cutoff = %v", name, err)
		}
	}

	if deleted, err := store.DeleteExpiredBlobStage(ctx, "missing", testProtectionID(500), cutoff); err != nil || deleted {
		t.Fatalf("missing expired stage deletion = %v, %v", deleted, err)
	}
	if deleted, err := store.DeleteExpiredFileLease(ctx, "missing", testProtectionID(500), cutoff); err != nil || deleted {
		t.Fatalf("missing expired lease deletion = %v, %v", deleted, err)
	}
	if deleted, err := store.DeleteExpiredBlobStage(ctx, "alpha", testProtectionID(9), cutoff); err != nil || deleted {
		t.Fatalf("unexpired stage deletion = %v, %v", deleted, err)
	}
	if deleted, err := store.DeleteExpiredFileLease(ctx, "alpha", testProtectionID(9), cutoff); err != nil || deleted {
		t.Fatalf("unexpired lease deletion = %v, %v", deleted, err)
	}
	if _, err := store.DeleteExpiredBlobStage(ctx, "alpha", ProtectionID{}, cutoff); !errors.Is(err, ErrInvalid) {
		t.Fatalf("zero stage identity deletion = %v", err)
	}
	if _, err := store.DeleteExpiredFileLease(ctx, "alpha", ProtectionID{}, cutoff); !errors.Is(err, ErrInvalid) {
		t.Fatalf("zero lease identity deletion = %v", err)
	}

	if deleted, err := store.DeleteExpiredBlobStage(ctx, "alpha", testProtectionID(1), cutoff); err != nil || !deleted {
		t.Fatalf("expired stage deletion = %v, %v", deleted, err)
	}
	if deleted, err := store.DeleteExpiredBlobStage(ctx, "alpha", testProtectionID(1), cutoff); err != nil || deleted {
		t.Fatalf("repeated expired stage deletion = %v, %v", deleted, err)
	}
	if deleted, err := store.DeleteExpiredFileLease(ctx, "alpha", testProtectionID(1), cutoff); err != nil || !deleted {
		t.Fatalf("expired lease deletion = %v, %v", deleted, err)
	}
	stages, err := store.ListBlobStages(ctx, nil, PageRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if !hasBlobStage(stages.Items, "beta", testProtectionID(1)) {
		t.Fatal("same stage ID in another namespace was deleted")
	}
	leases, err := store.ListFileLeases(ctx, nil, PageRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if !hasFileLease(leases.Items, "beta", testProtectionID(1)) {
		t.Fatal("same lease ID in another namespace was deleted")
	}

	renewedExpiration := cutoff.Add(time.Hour)
	if err := store.RenewBlobStage(ctx, "alpha", testProtectionID(2), renewedExpiration); err != nil {
		t.Fatal(err)
	}
	if deleted, err := store.DeleteExpiredBlobStage(ctx, "alpha", testProtectionID(2), cutoff); err != nil || deleted {
		t.Fatalf("stale stage deletion after renewal = %v, %v", deleted, err)
	}
	if err := store.RenewFileLease(ctx, "alpha", testProtectionID(2), renewedExpiration); err != nil {
		t.Fatal(err)
	}
	if deleted, err := store.DeleteExpiredFileLease(ctx, "alpha", testProtectionID(2), cutoff); err != nil || deleted {
		t.Fatalf("stale lease deletion after renewal = %v, %v", deleted, err)
	}

	assertProtectionExpiryRace(t, store, cutoff, createdAt)

	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := store.ListExpiredBlobStages(canceled, cutoff, PageRequest{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled expired stage list = %v", err)
	}
	if _, err := store.ListExpiredFileLeases(canceled, cutoff, PageRequest{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled expired lease list = %v", err)
	}
	if _, err := store.DeleteExpiredBlobStage(
		canceled, "beta", testProtectionID(1), cutoff,
	); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled expired stage deletion = %v", err)
	}
	if _, err := store.DeleteExpiredFileLease(
		canceled, "beta", testProtectionID(1), cutoff,
	); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled expired lease deletion = %v", err)
	}
	if memory, ok := store.(*MemoryStore); ok {
		if _, err := memory.ListExpiredBlobStages(
			&cancelAfterCheckContext{Context: ctx, after: 2}, cutoff, PageRequest{},
		); !errors.Is(err, context.Canceled) {
			t.Fatalf("expired-stage cancellation during scan = %v", err)
		}
		if _, err := memory.ListExpiredFileLeases(
			&cancelAfterCheckContext{Context: ctx, after: 2}, cutoff, PageRequest{},
		); !errors.Is(err, context.Canceled) {
			t.Fatalf("expired-lease cancellation during scan = %v", err)
		}
		if _, err := memory.DeleteExpiredBlobStage(
			&cancelAfterCheckContext{Context: ctx, after: 2}, "beta", testProtectionID(1), cutoff,
		); !errors.Is(err, context.Canceled) {
			t.Fatalf("expired-stage cancellation after lock = %v", err)
		}
		if _, err := memory.DeleteExpiredFileLease(
			&cancelAfterCheckContext{Context: ctx, after: 2}, "beta", testProtectionID(1), cutoff,
		); !errors.Is(err, context.Canceled) {
			t.Fatalf("expired-lease cancellation after lock = %v", err)
		}
	}
}

func hasBlobStage(stages []BlobStage, namespace string, id ProtectionID) bool {
	return slices.ContainsFunc(stages, func(stage BlobStage) bool {
		return stage.Namespace == namespace && stage.ID == id
	})
}

func hasFileLease(leases []FileLease, namespace string, id ProtectionID) bool {
	return slices.ContainsFunc(leases, func(lease FileLease) bool {
		return lease.Namespace == namespace && lease.ID == id
	})
}

func assertProtectionExpiryRace(
	t *testing.T,
	store protectionExpiryTestStore,
	cutoff, createdAt time.Time,
) {
	t.Helper()
	ctx := context.Background()
	id := testProtectionID(100)
	hash := xethash.Chunk([]byte("protection expiry race"))
	stage := BlobStage{
		ID: id, Namespace: "race", Blob: BlobKey{Kind: BlobShard, Hash: hash},
		CreatedAt: createdAt, ExpiresAt: cutoff,
	}
	lease := FileLease{
		ID: id, Namespace: "race", File: hash,
		CreatedAt: createdAt, ExpiresAt: cutoff,
	}
	if err := store.PutBlobStage(ctx, stage); err != nil {
		t.Fatal(err)
	}
	if err := store.PutFileLease(ctx, lease); err != nil {
		t.Fatal(err)
	}
	renewedExpiration := cutoff.Add(time.Hour)
	t.Run("stage renewal versus deletion", func(t *testing.T) {
		start := make(chan struct{})
		renewed := make(chan error, 1)
		deleted := make(chan struct {
			value bool
			err   error
		}, 1)
		go func() {
			<-start
			renewed <- store.RenewBlobStage(ctx, stage.Namespace, stage.ID, renewedExpiration)
		}()
		go func() {
			<-start
			value, err := store.DeleteExpiredBlobStage(ctx, stage.Namespace, stage.ID, cutoff)
			deleted <- struct {
				value bool
				err   error
			}{value: value, err: err}
		}()
		close(start)
		renewErr, deletion := <-renewed, <-deleted
		if renewErr == nil {
			if deletion.err != nil || deletion.value {
				t.Fatalf("renewed stage was deleted = %v, %v", deletion.value, deletion.err)
			}
		} else if !errors.Is(renewErr, ErrNotFound) || deletion.err != nil || !deletion.value {
			t.Fatalf("stage race = renewal %v, deletion %v, %v", renewErr, deletion.value, deletion.err)
		}
	})
	t.Run("lease renewal versus deletion", func(t *testing.T) {
		start := make(chan struct{})
		renewed := make(chan error, 1)
		deleted := make(chan struct {
			value bool
			err   error
		}, 1)
		go func() {
			<-start
			renewed <- store.RenewFileLease(ctx, lease.Namespace, lease.ID, renewedExpiration)
		}()
		go func() {
			<-start
			value, err := store.DeleteExpiredFileLease(ctx, lease.Namespace, lease.ID, cutoff)
			deleted <- struct {
				value bool
				err   error
			}{value: value, err: err}
		}()
		close(start)
		renewErr, deletion := <-renewed, <-deleted
		if renewErr == nil {
			if deletion.err != nil || deletion.value {
				t.Fatalf("renewed lease was deleted = %v, %v", deletion.value, deletion.err)
			}
		} else if !errors.Is(renewErr, ErrNotFound) || deletion.err != nil || !deletion.value {
			t.Fatalf("lease race = renewal %v, deletion %v, %v", renewErr, deletion.value, deletion.err)
		}
	})
}

func TestProtectionExpiryStoreContracts(t *testing.T) {
	t.Run("memory", func(t *testing.T) {
		runProtectionExpiryStoreContract(t, NewMemoryStore())
	})
	t.Run("sqlite", func(t *testing.T) {
		requireLocalDurability(t)
		store, err := OpenSQLiteIndexStore(filepath.Join(t.TempDir(), "index.db"))
		if err != nil {
			t.Fatal(err)
		}
		defer store.Close() //nolint:errcheck // Test cleanup.
		runProtectionExpiryStoreContract(t, store)
	})
}

func TestMemoryProtectionExpiryDeletionDoesNotDeleteBlob(t *testing.T) {
	store := NewMemoryStore()
	ctx := context.Background()
	payload := []byte("expired protection does not delete content")
	key := BlobKey{Kind: BlobXorb, Hash: xethash.Chunk(payload)}
	if inserted, err := store.PutIfAbsent(ctx, key, bytes.NewReader(payload), int64(len(payload))); err != nil || !inserted {
		t.Fatalf("put protected blob = %v, %v", inserted, err)
	}
	cutoff := time.Date(2026, time.August, 10, 17, 0, 0, 0, time.UTC)
	stage := BlobStage{
		ID: testProtectionID(200), Namespace: "scope", Blob: key,
		CreatedAt: cutoff.Add(-time.Hour), ExpiresAt: cutoff,
	}
	if err := store.PutBlobStage(ctx, stage); err != nil {
		t.Fatal(err)
	}
	if deleted, err := store.DeleteExpiredBlobStage(ctx, stage.Namespace, stage.ID, cutoff); err != nil || !deleted {
		t.Fatalf("delete expired stage = %v, %v", deleted, err)
	}
	body, err := store.Get(ctx, key, nil)
	if err != nil {
		t.Fatalf("open blob after stage deletion: %v", err)
	}
	defer body.Close() //nolint:errcheck // Test read is decisive.
	got, err := io.ReadAll(body)
	if err != nil || !bytes.Equal(got, payload) {
		t.Fatalf("blob after stage deletion = %q, %v", got, err)
	}
}

func TestSQLiteProtectionExpiryQueryPlans(t *testing.T) {
	requireLocalDurability(t)
	store, err := OpenSQLiteIndexStore(filepath.Join(t.TempDir(), "index.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close() //nolint:errcheck // Test cleanup.
	for _, plan := range []struct {
		table, index, columns string
	}{
		{table: "blob_stages", index: "blob_stages_expiration", columns: "namespace, id, blob_kind, expires_at"},
		{table: "file_leases", index: "file_leases_expiration", columns: "namespace, id, file_hash, expires_at"},
	} {
		t.Run(plan.table, func(t *testing.T) {
			for _, hasCursor := range []bool{false, true} {
				query, arguments := sqliteProtectionExpiryQuery(
					"SELECT "+plan.columns+" FROM "+plan.table,
					1000, 500, "scope", testProtectionID(1), hasCursor, 10,
				)
				rows, err := store.db.QueryContext(context.Background(), "EXPLAIN QUERY PLAN "+query, arguments...)
				if err != nil {
					t.Fatal(err)
				}
				foundSearch := false
				for rows.Next() {
					var id, parent, unused int
					var detail string
					if err := rows.Scan(&id, &parent, &unused, &detail); err != nil {
						t.Fatal(err)
					}
					if strings.Contains(detail, "MULTI-INDEX OR") || strings.Contains(detail, "USE TEMP B-TREE") ||
						strings.HasPrefix(detail, "SCAN "+plan.table) {
						t.Fatalf("unbounded expiry query plan: %s", detail)
					}
					if strings.HasPrefix(detail, "SEARCH "+plan.table+" ") &&
						(strings.Contains(detail, "USING INDEX "+plan.index) ||
							strings.Contains(detail, "USING COVERING INDEX "+plan.index)) {
						foundSearch = true
					}
				}
				if err := finishSQLiteRows(rows); err != nil {
					t.Fatal(err)
				}
				if !foundSearch {
					t.Fatalf("expiry query plan did not seek through %s (cursor=%t)", plan.index, hasCursor)
				}
			}
		})
	}
}

func TestRetrySQLiteBusy(t *testing.T) {
	ctx := context.Background()
	busy := sqliteCodeTestError{code: 5 | 1<<8}
	attempts := 0
	value, err := retrySQLiteBusy(ctx, time.Second, func() (string, error) {
		attempts++
		if attempts < 3 {
			return "", busy
		}
		return "wal", nil
	})
	if err != nil || value != "wal" || attempts != 3 {
		t.Fatalf("transient SQLite busy retry = %q, %v after %d attempts", value, err, attempts)
	}

	sentinel := errors.New("not busy")
	attempts = 0
	if _, err := retrySQLiteBusy(ctx, time.Second, func() (string, error) {
		attempts++
		return "", sentinel
	}); !errors.Is(err, sentinel) || attempts != 1 {
		t.Fatalf("non-busy SQLite error = %v after %d attempts", err, attempts)
	}

	attempts = 0
	if _, err := retrySQLiteBusy(ctx, 0, func() (string, error) {
		attempts++
		return "", busy
	}); !errors.Is(err, busy) || attempts != 1 {
		t.Fatalf("expired SQLite retry window = %v after %d attempts", err, attempts)
	}

	canceled, cancel := context.WithCancel(ctx)
	cancel()
	attempts = 0
	if _, err := retrySQLiteBusy(canceled, time.Second, func() (string, error) {
		attempts++
		return "", busy
	}); !errors.Is(err, context.Canceled) || attempts != 1 {
		t.Fatalf("canceled SQLite retry = %v after %d attempts", err, attempts)
	}
}

func TestProtectionExpiryCursorBoundaries(t *testing.T) {
	namespace := "scope"
	id := testProtectionID(1)
	for _, nanoseconds := range []int64{math.MinInt64, -1, 0, math.MaxInt64} {
		cutoff := time.Unix(0, nanoseconds).UTC()
		cursor := encodeProtectionExpiryCursor(cursorBlobStageExpired, cutoff, cutoff, namespace, id)
		decoded, err := decodeProtectionExpiryCursor(cursor, cursorBlobStageExpired, cutoff)
		if err != nil {
			t.Fatalf("decode expiry cursor at %d: %v", nanoseconds, err)
		}
		if !decoded.cutoff.Equal(cutoff) || !decoded.expiresAt.Equal(cutoff) ||
			decoded.namespace != namespace || decoded.id != id {
			t.Fatalf("expiry cursor at %d = %#v", nanoseconds, decoded)
		}
	}

	cutoff := time.Unix(0, 1).UTC()
	valid := encodeProtectionExpiryCursor(cursorBlobStageExpired, cutoff, cutoff, namespace, id)
	data, err := base64.RawURLEncoding.DecodeString(valid)
	if err != nil {
		t.Fatal(err)
	}
	badNamespaceSize := append([]byte(nil), data...)
	binary.BigEndian.PutUint32(badNamespaceSize[17:21], uint32(len(namespace)+1))
	for name, malformed := range map[string][]byte{
		"truncated":          data[:len(data)-1],
		"trailing byte":      append(append([]byte(nil), data...), 0),
		"bad namespace size": badNamespaceSize,
	} {
		cursor := base64.RawURLEncoding.EncodeToString(malformed)
		if _, err := decodeProtectionExpiryCursor(cursor, cursorBlobStageExpired, cutoff); !errors.Is(err, ErrInvalid) {
			t.Fatalf("%s expiry cursor = %v", name, err)
		}
	}
}

func TestSQLiteProtectionStoreRestart(t *testing.T) {
	requireLocalDurability(t)
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "index.db")
	store, err := OpenSQLiteIndexStore(path)
	if err != nil {
		t.Fatal(err)
	}
	createdAt := time.Date(2026, time.August, 10, 14, 0, 0, 0, time.UTC)
	stage := BlobStage{
		ID: testProtectionID(100), Namespace: "scope",
		Blob:      BlobKey{Kind: BlobShard, Hash: xethash.Chunk([]byte("restart stage"))},
		CreatedAt: createdAt, ExpiresAt: createdAt.Add(time.Hour),
	}
	lease := FileLease{
		ID: testProtectionID(101), Namespace: "scope", File: xethash.Chunk([]byte("restart lease")),
		CreatedAt: createdAt, ExpiresAt: createdAt.Add(time.Hour),
	}
	if err := store.PutBlobStage(ctx, stage); err != nil {
		t.Fatal(err)
	}
	if err := store.PutFileLease(ctx, lease); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	store, err = OpenSQLiteIndexStore(path)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close() //nolint:errcheck // Test cleanup.
	stages, err := store.ListBlobStages(ctx, nil, PageRequest{})
	if err != nil || len(stages.Items) != 1 || stages.Items[0] != stage {
		t.Fatalf("reopened stages = %#v, %v", stages, err)
	}
	leases, err := store.ListFileLeases(ctx, nil, PageRequest{})
	if err != nil || len(leases.Items) != 1 || leases.Items[0] != lease {
		t.Fatalf("reopened leases = %#v, %v", leases, err)
	}
	expiredStages, err := store.ListExpiredBlobStages(ctx, stage.ExpiresAt, PageRequest{})
	if err != nil || len(expiredStages.Items) != 1 || expiredStages.Items[0] != stage {
		t.Fatalf("reopened expired stages = %#v, %v", expiredStages, err)
	}
	expiredLeases, err := store.ListExpiredFileLeases(ctx, lease.ExpiresAt, PageRequest{})
	if err != nil || len(expiredLeases.Items) != 1 || expiredLeases.Items[0] != lease {
		t.Fatalf("reopened expired leases = %#v, %v", expiredLeases, err)
	}
}

func TestSQLiteProtectionStoreCorruption(t *testing.T) {
	requireLocalDurability(t)
	ctx := context.Background()
	createdAt := time.Date(2026, time.August, 10, 14, 0, 0, 0, time.UTC)
	stage := BlobStage{
		ID: testProtectionID(300), Namespace: "scope",
		Blob:      BlobKey{Kind: BlobShard, Hash: xethash.Chunk([]byte("corrupt stage"))},
		CreatedAt: createdAt, ExpiresAt: createdAt.Add(time.Hour),
	}
	lease := FileLease{
		ID: testProtectionID(301), Namespace: "scope", File: xethash.Chunk([]byte("corrupt lease")),
		CreatedAt: createdAt, ExpiresAt: createdAt.Add(time.Hour),
	}
	for _, test := range []struct {
		name    string
		prepare func(*SQLiteIndexStore) error
		corrupt string
		check   func(*SQLiteIndexStore) error
	}{
		{
			name: "stage put validates conflict", prepare: func(store *SQLiteIndexStore) error {
				return store.PutBlobStage(ctx, stage)
			},
			corrupt: "UPDATE blob_stages SET created_at = X'01'",
			check:   func(store *SQLiteIndexStore) error { return store.PutBlobStage(ctx, stage) },
		},
		{
			name: "stage renewal validates result", prepare: func(store *SQLiteIndexStore) error {
				return store.PutBlobStage(ctx, stage)
			},
			corrupt: "UPDATE blob_stages SET expires_at = X'01'",
			check: func(store *SQLiteIndexStore) error {
				return store.RenewBlobStage(ctx, stage.Namespace, stage.ID, stage.ExpiresAt.Add(time.Hour))
			},
		},
		{
			name: "lease put validates conflict", prepare: func(store *SQLiteIndexStore) error {
				return store.PutFileLease(ctx, lease)
			},
			corrupt: "UPDATE file_leases SET created_at = X'01'",
			check:   func(store *SQLiteIndexStore) error { return store.PutFileLease(ctx, lease) },
		},
		{
			name: "lease renewal validates result", prepare: func(store *SQLiteIndexStore) error {
				return store.PutFileLease(ctx, lease)
			},
			corrupt: "UPDATE file_leases SET expires_at = X'01'",
			check: func(store *SQLiteIndexStore) error {
				return store.RenewFileLease(ctx, lease.Namespace, lease.ID, lease.ExpiresAt.Add(time.Hour))
			},
		},
		{
			name: "stage listing validates kind", prepare: func(store *SQLiteIndexStore) error {
				return store.PutBlobStage(ctx, stage)
			},
			corrupt: "UPDATE blob_stages SET blob_kind = 'invalid'",
			check: func(store *SQLiteIndexStore) error {
				_, err := store.ListBlobStages(ctx, nil, PageRequest{})
				return err
			},
		},
		{
			name: "expired stage listing validates timestamp", prepare: func(store *SQLiteIndexStore) error {
				return store.PutBlobStage(ctx, stage)
			},
			corrupt: "UPDATE blob_stages SET created_at = X'01'",
			check: func(store *SQLiteIndexStore) error {
				_, err := store.ListExpiredBlobStages(ctx, stage.ExpiresAt, PageRequest{})
				return err
			},
		},
		{
			name: "expired lease listing validates hash", prepare: func(store *SQLiteIndexStore) error {
				return store.PutFileLease(ctx, lease)
			},
			corrupt: "UPDATE file_leases SET file_hash = X'01'",
			check: func(store *SQLiteIndexStore) error {
				_, err := store.ListExpiredFileLeases(ctx, lease.ExpiresAt, PageRequest{})
				return err
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			store, err := OpenSQLiteIndexStore(filepath.Join(t.TempDir(), "index.db"))
			if err != nil {
				t.Fatal(err)
			}
			defer store.Close() //nolint:errcheck // Test cleanup.
			if err := test.prepare(store); err != nil {
				t.Fatal(err)
			}
			if _, err := store.db.ExecContext(ctx, "PRAGMA ignore_check_constraints=ON"); err != nil {
				t.Fatal(err)
			}
			if _, err := store.db.ExecContext(ctx, test.corrupt); err != nil {
				t.Fatal(err)
			}
			if err := test.check(store); !errors.Is(err, ErrCorrupt) {
				t.Fatalf("corrupt lifecycle operation = %v", err)
			}
		})
	}

	t.Run("backend errors", func(t *testing.T) {
		store, err := OpenSQLiteIndexStore(filepath.Join(t.TempDir(), "index.db"))
		if err != nil {
			t.Fatal(err)
		}
		defer store.Close() //nolint:errcheck // Test cleanup.
		if _, err := store.db.ExecContext(ctx, "DROP TABLE blob_stages; DROP TABLE file_leases"); err != nil {
			t.Fatal(err)
		}
		for name, call := range map[string]func() error{
			"put stage":    func() error { return store.PutBlobStage(ctx, stage) },
			"renew stage":  func() error { return store.RenewBlobStage(ctx, stage.Namespace, stage.ID, stage.ExpiresAt) },
			"delete stage": func() error { return store.DeleteBlobStage(ctx, stage.Namespace, stage.ID) },
			"list stages":  func() error { _, err := store.ListBlobStages(ctx, nil, PageRequest{}); return err },
			"list expired stages": func() error {
				_, err := store.ListExpiredBlobStages(ctx, stage.ExpiresAt, PageRequest{})
				return err
			},
			"delete expired stage": func() error {
				_, err := store.DeleteExpiredBlobStage(ctx, stage.Namespace, stage.ID, stage.ExpiresAt)
				return err
			},
			"put lease":    func() error { return store.PutFileLease(ctx, lease) },
			"renew lease":  func() error { return store.RenewFileLease(ctx, lease.Namespace, lease.ID, lease.ExpiresAt) },
			"delete lease": func() error { return store.DeleteFileLease(ctx, lease.Namespace, lease.ID) },
			"list leases":  func() error { _, err := store.ListFileLeases(ctx, nil, PageRequest{}); return err },
			"list expired leases": func() error {
				_, err := store.ListExpiredFileLeases(ctx, lease.ExpiresAt, PageRequest{})
				return err
			},
			"delete expired lease": func() error {
				_, err := store.DeleteExpiredFileLease(ctx, lease.Namespace, lease.ID, lease.ExpiresAt)
				return err
			},
		} {
			if err := call(); err == nil {
				t.Fatalf("%s against missing table succeeded", name)
			}
		}
	})
}

func TestFilesystemBlobStoreRestartRecoveryAndSafety(t *testing.T) {
	requireLocalDurability(t)
	barrierRoot := t.TempDir()
	nestedRoot := filepath.Join(barrierRoot, "one", "two", "blobs")
	synced := make(map[string]int)
	if err := ensurePrivateDirectory(nestedRoot, func(path string) error {
		synced[path]++
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{
		barrierRoot,
		filepath.Join(barrierRoot, "one"),
		filepath.Join(barrierRoot, "one", "two"),
		nestedRoot,
	} {
		if synced[path] == 0 {
			t.Fatalf("directory durability barrier omitted %q", path)
		}
	}

	root := t.TempDir()
	store, err := NewFilesystemBlobStore(root)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	key := BlobKey{Kind: BlobShard, Hash: xethash.Chunk([]byte("restart blob"))}
	body := []byte("restart-persistent-body")
	if _, err := store.PutIfAbsent(ctx, key, bytes.NewReader(body), int64(len(body))); err != nil {
		t.Fatal(err)
	}
	if _, err := NewFilesystemBlobStore(root); !errors.Is(err, ErrConflict) {
		t.Fatalf("second live store = %v", err)
	}
	path, err := store.objectPath(key)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	store, err = NewFilesystemBlobStore(root)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close() //nolint:errcheck // Test cleanup.
	reader, err := store.Get(ctx, key, nil)
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(reader)
	_ = reader.Close()
	if err != nil || !bytes.Equal(got, body) {
		t.Fatalf("restart body = %q, %v", got, err)
	}

	external := filepath.Join(t.TempDir(), "external")
	if err := os.WriteFile(external, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(external, path); err != nil {
		if runtime.GOOS == "windows" {
			t.Skipf("symlink unavailable: %v", err)
		}
		t.Fatal(err)
	}
	if _, err := store.Get(ctx, key, nil); err == nil {
		t.Fatal("object symlink was followed")
	}
	if data, err := os.ReadFile(external); err != nil || string(data) != "secret" {
		t.Fatalf("external file changed: %q, %v", data, err)
	}
}

func TestPrivateDirectoryPublicationFailures(t *testing.T) {
	requireLocalDurability(t)
	injected := errors.New("injected private-directory failure")
	defaultOps := func() privateDirectoryOperations {
		return privateDirectoryOperations{
			lstat: os.Lstat,
			mkdir: func(path string) error { return os.Mkdir(path, 0o700) },
			chmod: func(path string) error { return os.Chmod(path, 0o700) },
			sync:  func(string) error { return nil },
		}
	}
	run := func(t *testing.T, path string, ops privateDirectoryOperations) {
		t.Helper()
		if err := ensurePrivateDirectoryWithOperations(path, ops); !errors.Is(err, injected) {
			t.Fatalf("error = %v, want injected failure", err)
		}
	}

	t.Run("inspect ancestor", func(t *testing.T) {
		ops := defaultOps()
		ops.lstat = func(string) (os.FileInfo, error) { return nil, injected }
		run(t, filepath.Join(t.TempDir(), "missing"), ops)
	})
	t.Run("no existing ancestor", func(t *testing.T) {
		ops := defaultOps()
		ops.lstat = func(string) (os.FileInfo, error) { return nil, os.ErrNotExist }
		if err := ensurePrivateDirectoryWithOperations(string(filepath.Separator), ops); err == nil {
			t.Fatal("root without an existing ancestor succeeded")
		}
	})
	t.Run("create", func(t *testing.T) {
		ops := defaultOps()
		ops.mkdir = func(string) error { return injected }
		run(t, filepath.Join(t.TempDir(), "missing"), ops)
	})
	t.Run("inspect created", func(t *testing.T) {
		ops := defaultOps()
		ops.mkdir = func(string) error { return nil }
		path := filepath.Join(t.TempDir(), "missing")
		if err := ensurePrivateDirectoryWithOperations(path, ops); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("created-directory inspection error = %v", err)
		}
	})
	t.Run("created non-directory", func(t *testing.T) {
		ops := defaultOps()
		ops.mkdir = func(path string) error { return os.WriteFile(path, nil, 0o600) }
		if err := ensurePrivateDirectoryWithOperations(filepath.Join(t.TempDir(), "missing"), ops); err == nil {
			t.Fatal("created regular file succeeded as directory")
		}
	})
	t.Run("protect created", func(t *testing.T) {
		ops := defaultOps()
		ops.chmod = func(string) error { return injected }
		run(t, filepath.Join(t.TempDir(), "missing"), ops)
	})
	t.Run("sync created", func(t *testing.T) {
		ops := defaultOps()
		ops.sync = func(string) error { return injected }
		run(t, filepath.Join(t.TempDir(), "missing"), ops)
	})
	t.Run("publish created", func(t *testing.T) {
		ops := defaultOps()
		var calls int
		ops.sync = func(string) error {
			calls++
			if calls == 2 {
				return injected
			}
			return nil
		}
		run(t, filepath.Join(t.TempDir(), "missing"), ops)
	})
	t.Run("inspect final", func(t *testing.T) {
		path := t.TempDir()
		ops := defaultOps()
		var calls int
		ops.lstat = func(value string) (os.FileInfo, error) {
			calls++
			if calls == 2 {
				return nil, injected
			}
			return os.Lstat(value)
		}
		run(t, path, ops)
	})
	t.Run("final non-directory", func(t *testing.T) {
		path := t.TempDir()
		regular := filepath.Join(t.TempDir(), "regular")
		if err := os.WriteFile(regular, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		regularInfo, err := os.Lstat(regular)
		if err != nil {
			t.Fatal(err)
		}
		ops := defaultOps()
		var calls int
		ops.lstat = func(value string) (os.FileInfo, error) {
			calls++
			if calls == 2 {
				return regularInfo, nil
			}
			return os.Lstat(value)
		}
		if err := ensurePrivateDirectoryWithOperations(path, ops); err == nil {
			t.Fatal("final regular file succeeded as directory")
		}
	})
	t.Run("protect final", func(t *testing.T) {
		ops := defaultOps()
		ops.chmod = func(string) error { return injected }
		run(t, t.TempDir(), ops)
	})
	t.Run("sync final", func(t *testing.T) {
		ops := defaultOps()
		ops.sync = func(string) error { return injected }
		run(t, t.TempDir(), ops)
	})
	t.Run("sync final parent", func(t *testing.T) {
		ops := defaultOps()
		var calls int
		ops.sync = func(string) error {
			calls++
			if calls == 2 {
				return injected
			}
			return nil
		}
		run(t, t.TempDir(), ops)
	})
}

func TestFilesystemBlobStoreConcurrentAndFailureRecovery(t *testing.T) {
	requireLocalDurability(t)
	store, err := NewFilesystemBlobStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close() //nolint:errcheck // Test cleanup.
	ctx := context.Background()
	key := BlobKey{Kind: BlobXorb, Hash: xethash.Chunk([]byte("concurrent blob"))}
	body := bytes.Repeat([]byte("concurrent"), 10_000)
	const writers = 16
	type writerResult struct {
		inserted bool
		err      error
	}
	results := make(chan writerResult, writers)
	var wait sync.WaitGroup
	for range writers {
		wait.Add(1)
		go func() {
			defer wait.Done()
			inserted, err := store.PutIfAbsent(ctx, key, bytes.NewReader(body), int64(len(body)))
			results <- writerResult{inserted: inserted, err: err}
		}()
	}
	wait.Wait()
	close(results)
	insertedCount := 0
	for result := range results {
		if result.err != nil {
			t.Fatal(result.err)
		}
		if result.inserted {
			insertedCount++
		}
	}
	if insertedCount != 1 {
		t.Fatalf("concurrent inserted count = %d", insertedCount)
	}

	conflictKey := BlobKey{Kind: BlobShard, Hash: xethash.Chunk([]byte("concurrent conflict"))}
	conflictingBodies := [][]byte{bytes.Repeat([]byte("a"), 64_000), bytes.Repeat([]byte("b"), 64_000)}
	results = make(chan writerResult, len(conflictingBodies))
	for _, value := range conflictingBodies {
		wait.Add(1)
		go func(value []byte) {
			defer wait.Done()
			inserted, err := store.PutIfAbsent(ctx, conflictKey, bytes.NewReader(value), int64(len(value)))
			results <- writerResult{inserted: inserted, err: err}
		}(value)
	}
	wait.Wait()
	close(results)
	insertedCount, conflicts := 0, 0
	for result := range results {
		if result.inserted && result.err == nil {
			insertedCount++
		} else if errors.Is(result.err, ErrConflict) {
			conflicts++
		} else {
			t.Fatalf("conflicting writer = %v, %v", result.inserted, result.err)
		}
	}
	if insertedCount != 1 || conflicts != 1 {
		t.Fatalf("conflicting writers = %d inserted, %d conflicts", insertedCount, conflicts)
	}

	injected := errors.New("injected filesystem failure")
	for _, stage := range []string{"after-temp-sync", "after-publish", "after-durable"} {
		failureKey := BlobKey{Kind: BlobShard, Hash: xethash.Chunk([]byte(stage))}
		store.testHook = func(got string) error {
			if got == stage {
				return injected
			}
			return nil
		}
		if _, err := store.PutIfAbsent(ctx, failureKey, bytes.NewReader(body), int64(len(body))); !errors.Is(err, injected) {
			t.Fatalf("%s failure = %v", stage, err)
		}
		durableBarrier := false
		store.testHook = func(got string) error {
			if got == "after-durable" {
				durableBarrier = true
			}
			return nil
		}
		inserted, err := store.PutIfAbsent(ctx, failureKey, bytes.NewReader(body), int64(len(body)))
		store.testHook = nil
		if err != nil {
			t.Fatalf("%s repair = %v", stage, err)
		}
		if !durableBarrier {
			t.Fatalf("%s repair skipped the publication durability barrier", stage)
		}
		if stage == "after-temp-sync" && !inserted {
			t.Fatal("pre-publication failure unexpectedly exposed an object")
		}
		if stage != "after-temp-sync" && inserted {
			t.Fatal("post-publication retry did not reuse the complete object")
		}
	}
}

func TestFilesystemBlobStoreCleansOnlyAbandonedTemps(t *testing.T) {
	requireLocalDurability(t)
	root := t.TempDir()
	dir := filepath.Join(root, filesystemLayoutVersion, string(BlobXorb), "aa", "bb")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	old := filepath.Join(dir, tempPrefix+"old")
	fresh := filepath.Join(dir, tempPrefix+"fresh")
	for _, path := range []string{old, fresh} {
		if err := os.WriteFile(path, []byte("temporary"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	oldTimestamp := time.Now().Add(-2 * time.Hour)
	if err := os.Chtimes(old, oldTimestamp, oldTimestamp); err != nil {
		t.Fatal(err)
	}
	store, err := NewFilesystemBlobStore(root, FilesystemBlobStoreOptions{TempGracePeriod: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close() //nolint:errcheck // Test cleanup.
	if _, err := os.Stat(old); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("abandoned temp remains: %v", err)
	}
	if _, err := os.Stat(fresh); err != nil {
		t.Fatalf("fresh temp removed: %v", err)
	}
	retryTemp := filepath.Join(dir, tempPrefix+"retry")
	if err := os.WriteFile(retryTemp, []byte("retry"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(retryTemp, oldTimestamp, oldTimestamp); err != nil {
		t.Fatal(err)
	}
	injected := errors.New("injected cleanup directory sync failure")
	syncDirectory := store.ops.syncDirectory
	store.ops.syncDirectory = func(path string) error {
		if path == dir {
			return injected
		}
		return syncDirectory(path)
	}
	if err := store.cleanupTemps(time.Hour); !errors.Is(err, injected) {
		t.Fatalf("cleanup directory sync failure = %v", err)
	}
	if _, err := os.Stat(retryTemp); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("failed-barrier temp remains: %v", err)
	}
	store.ops.syncDirectory = syncDirectory
	if err := store.cleanupTemps(time.Hour); err != nil {
		t.Fatalf("cleanup barrier retry: %v", err)
	}
}

func TestFilesystemBlobStoreRejectsSymlinkedDirectoriesAndReplacedRoot(t *testing.T) {
	requireLocalDurability(t)
	if runtime.GOOS == "windows" {
		t.Skip("strict filesystem backend is unsupported on Windows")
	}
	ctx := context.Background()
	t.Run("object directory", func(t *testing.T) {
		container := t.TempDir()
		root := filepath.Join(container, "blobs")
		store, err := NewFilesystemBlobStore(root)
		if err != nil {
			t.Fatal(err)
		}
		defer store.Close() //nolint:errcheck // Test cleanup.
		external := filepath.Join(container, "external")
		if err := os.Mkdir(external, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(external, filepath.Join(root, filesystemLayoutVersion)); err != nil {
			t.Fatal(err)
		}
		key := BlobKey{Kind: BlobXorb, Hash: xethash.Chunk([]byte("symlinked directory"))}
		if _, err := store.PutIfAbsent(ctx, key, bytes.NewReader(nil), 0); err == nil {
			t.Fatal("write through symlinked object directory succeeded")
		}
		entries, err := os.ReadDir(external)
		if err != nil || len(entries) != 0 {
			t.Fatalf("symlink target was modified: %d entries, %v", len(entries), err)
		}
	})
	t.Run("root", func(t *testing.T) {
		container := t.TempDir()
		root := filepath.Join(container, "blobs")
		moved := filepath.Join(container, "moved")
		external := filepath.Join(container, "external")
		store, err := NewFilesystemBlobStore(root)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(external, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(root, moved); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(external, root); err != nil {
			t.Fatal(err)
		}
		key := BlobKey{Kind: BlobShard, Hash: xethash.Chunk([]byte("replaced root"))}
		if _, err := store.PutIfAbsent(ctx, key, bytes.NewReader(nil), 0); err == nil {
			t.Fatal("write through replaced root succeeded")
		}
		entries, err := os.ReadDir(external)
		if err != nil || len(entries) != 0 {
			t.Fatalf("replacement root target was modified: %d entries, %v", len(entries), err)
		}
		if err := store.Close(); err != nil {
			t.Fatal(err)
		}
		if err := os.Remove(root); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(moved, root); err != nil {
			t.Fatal(err)
		}
	})
}

func TestFilesystemBlobStoreErrorAndClosureSemantics(t *testing.T) {
	requireLocalDurability(t)
	if runtime.GOOS == "windows" {
		t.Skip("strict filesystem backend is unsupported on Windows")
	}
	ctx := context.Background()
	root := filepath.Join(t.TempDir(), "blobs")
	store, err := NewFilesystemBlobStore(root)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.makeObjectDir(root); err != nil {
		t.Fatalf("prepare existing root: %v", err)
	}
	key := BlobKey{Kind: BlobXorb, Hash: xethash.Chunk([]byte("closure semantics"))}
	if _, err := store.PutIfAbsent(ctx, key, nil, 0); !errors.Is(err, ErrInvalid) {
		t.Fatalf("nil body = %v", err)
	}
	if _, err := store.PutIfAbsent(ctx, key, bytes.NewReader(nil), -1); !errors.Is(err, ErrInvalid) {
		t.Fatalf("negative size = %v", err)
	}
	body := []byte("cancel returned reader")
	if _, err := store.PutIfAbsent(ctx, key, bytes.NewReader(body), int64(len(body))); err != nil {
		t.Fatal(err)
	}
	readContext, cancelRead := context.WithCancel(ctx)
	reader, err := store.Get(readContext, key, nil)
	if err != nil {
		t.Fatal(err)
	}
	cancelRead()
	if _, err := reader.Read(make([]byte, 1)); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled returned reader = %v", err)
	}
	_ = reader.Close()
	path, err := store.objectPath(key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := compareFile(ctx, filepath.Join(root, "missing"), path, int64(len(body))); err == nil {
		t.Fatal("missing comparison source succeeded")
	}
	if _, err := compareFile(ctx, path, filepath.Join(root, "missing"), int64(len(body))); err == nil {
		t.Fatal("missing comparison peer succeeded")
	}
	if equal, err := compareFile(ctx, path, path, int64(len(body))+1); err != nil || equal {
		t.Fatalf("wrong-size comparison = %v, %v", equal, err)
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := compareFile(canceled, path, path, int64(len(body))); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled comparison = %v", err)
	}
	if err := validateObjectPath(root, filepath.Dir(root)); !errors.Is(err, ErrInvalid) {
		t.Fatalf("path outside root = %v", err)
	}
	if err := syncDirectoryHierarchy(root, filepath.Dir(root)); !errors.Is(err, ErrInvalid) {
		t.Fatalf("sync outside root = %v", err)
	}
	if err := store.makeObjectDir(filepath.Dir(root)); !errors.Is(err, ErrInvalid) {
		t.Fatalf("create directory outside root = %v", err)
	}
	if err := validateObjectPath(filepath.Join(root, "missing-root"), root); err == nil {
		t.Fatal("missing validation root succeeded")
	}
	if err := validateObjectPath(root, filepath.Join(root, "missing-component")); err == nil {
		t.Fatal("missing validation component succeeded")
	}
	directoryObject := filepath.Join(root, "directory-object")
	if err := os.Mkdir(directoryObject, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := safeObjectInfo(root, directoryObject); err == nil {
		t.Fatal("directory accepted as blob object")
	}
	if err := syncDirectory(filepath.Join(root, "missing-directory")); err == nil {
		t.Fatal("missing directory sync succeeded")
	}

	deleteTempKey := BlobKey{Kind: BlobShard, Hash: xethash.Chunk([]byte("delete temporary before link"))}
	deleteTempPath, err := store.objectPath(deleteTempKey)
	if err != nil {
		t.Fatal(err)
	}
	store.testHook = func(stage string) error {
		if stage != "after-temp-sync" {
			return nil
		}
		entries, err := os.ReadDir(filepath.Dir(deleteTempPath))
		if err != nil {
			return err
		}
		for _, entry := range entries {
			if strings.HasPrefix(entry.Name(), tempPrefix) {
				return os.Remove(filepath.Join(filepath.Dir(deleteTempPath), entry.Name()))
			}
		}
		return errors.New("temporary file not found")
	}
	if _, err := store.PutIfAbsent(ctx, deleteTempKey, bytes.NewReader(body), int64(len(body))); err == nil {
		t.Fatal("publication without temporary file succeeded")
	}
	store.testHook = nil

	syncFailureKey := BlobKey{Kind: BlobShard, Hash: xethash.Chunk([]byte("directory sync failure"))}
	syncFailurePath, err := store.objectPath(syncFailureKey)
	if err != nil {
		t.Fatal(err)
	}
	syncFailureDir := filepath.Dir(syncFailurePath)
	directorySyncFailure := errors.New("injected directory sync failure")
	originalSyncHierarchy := store.ops.syncHierarchy
	var directorySyncCalls int
	store.ops.syncHierarchy = func(root, leaf string) error {
		if leaf == syncFailureDir {
			directorySyncCalls++
			if directorySyncCalls == 1 {
				return directorySyncFailure
			}
		}
		return originalSyncHierarchy(root, leaf)
	}
	if _, err := store.PutIfAbsent(ctx, syncFailureKey, bytes.NewReader(body), int64(len(body))); !errors.Is(err, directorySyncFailure) {
		t.Fatalf("publication directory sync failure = %v", err)
	}
	store.ops.syncHierarchy = originalSyncHierarchy
	if inserted, err := store.PutIfAbsent(ctx, syncFailureKey, bytes.NewReader(body), int64(len(body))); err != nil || inserted {
		t.Fatalf("retry after directory sync failure = %v, %v", inserted, err)
	}

	injected := errors.New("injected filesystem operation failure")
	put := func(label string) error {
		key := BlobKey{Kind: BlobXorb, Hash: xethash.Chunk([]byte(label))}
		_, err := store.PutIfAbsent(ctx, key, bytes.NewReader(body), int64(len(body)))
		return err
	}
	createTemp := store.ops.createTemp
	store.ops.createTemp = func(string, string) (*os.File, error) { return nil, injected }
	if err := put("create temporary failure"); !errors.Is(err, injected) {
		t.Fatalf("create temporary failure = %v", err)
	}
	store.ops.createTemp = createTemp
	chmod := store.ops.chmod
	store.ops.chmod = func(*os.File, os.FileMode) error { return injected }
	if err := put("chmod failure"); !errors.Is(err, injected) {
		t.Fatalf("chmod failure = %v", err)
	}
	store.ops.chmod = chmod
	syncFile := store.ops.sync
	store.ops.sync = func(*os.File) error { return injected }
	if err := put("file sync failure"); !errors.Is(err, injected) {
		t.Fatalf("file sync failure = %v", err)
	}
	store.ops.sync = syncFile
	closeFile := store.ops.close
	store.ops.close = func(file *os.File) error {
		_ = file.Close()
		return injected
	}
	if err := put("file close failure"); !errors.Is(err, injected) {
		t.Fatalf("file close failure = %v", err)
	}
	store.ops.close = closeFile
	link := store.ops.link
	store.ops.link = func(string, string) error { return injected }
	if err := put("link failure"); !errors.Is(err, injected) {
		t.Fatalf("link failure = %v", err)
	}
	store.ops.link = link
	syncHierarchy := store.ops.syncHierarchy
	store.ops.syncHierarchy = func(string, string) error { return injected }
	if err := put("new publication sync failure"); !errors.Is(err, injected) {
		t.Fatalf("new publication sync failure = %v", err)
	}
	store.ops.syncHierarchy = syncHierarchy

	existingKey := BlobKey{Kind: BlobXorb, Hash: xethash.Chunk([]byte("injected existing object"))}
	if _, err := store.PutIfAbsent(ctx, existingKey, bytes.NewReader(body), int64(len(body))); err != nil {
		t.Fatal(err)
	}
	safeInfo := store.ops.safeInfo
	store.ops.safeInfo = func(string, string) (os.FileInfo, error) { return nil, injected }
	if _, err := store.PutIfAbsent(ctx, existingKey, bytes.NewReader(body), int64(len(body))); !errors.Is(err, injected) {
		t.Fatalf("existing object inspection failure = %v", err)
	}
	if _, _, err := store.Head(ctx, existingKey); !errors.Is(err, injected) {
		t.Fatalf("head inspection failure = %v", err)
	}
	if _, err := store.Get(ctx, existingKey, nil); !errors.Is(err, injected) {
		t.Fatalf("get inspection failure = %v", err)
	}
	store.ops.safeInfo = safeInfo
	compare := store.ops.compare
	store.ops.compare = func(context.Context, string, string, int64) (bool, error) { return false, injected }
	if _, err := store.PutIfAbsent(ctx, existingKey, bytes.NewReader(body), int64(len(body))); !errors.Is(err, injected) {
		t.Fatalf("existing object comparison failure = %v", err)
	}
	store.ops.compare = compare
	store.ops.syncHierarchy = func(string, string) error { return injected }
	if _, err := store.PutIfAbsent(ctx, existingKey, bytes.NewReader(body), int64(len(body))); !errors.Is(err, injected) {
		t.Fatalf("existing publication sync failure = %v", err)
	}
	store.ops.syncHierarchy = syncHierarchy
	store.testHook = func(stage string) error {
		if stage == "after-durable" {
			return injected
		}
		return nil
	}
	if _, err := store.PutIfAbsent(ctx, existingKey, bytes.NewReader(body), int64(len(body))); !errors.Is(err, injected) {
		t.Fatalf("existing post-durability failure = %v", err)
	}
	store.testHook = nil
	open := store.ops.open
	store.ops.open = func(string) (*os.File, error) { return nil, os.ErrNotExist }
	if _, err := store.Get(ctx, existingKey, nil); !errors.Is(err, ErrNotFound) {
		t.Fatalf("disappeared object open = %v", err)
	}
	store.ops.open = func(string) (*os.File, error) { return nil, injected }
	if _, err := store.Get(ctx, existingKey, nil); !errors.Is(err, injected) {
		t.Fatalf("object open failure = %v", err)
	}
	store.ops.open = open
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("idempotent close = %v", err)
	}
	if _, _, err := store.Head(ctx, key); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("head after close = %v", err)
	}
	if _, err := store.Get(ctx, key, nil); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("get after close = %v", err)
	}
	if _, err := store.PutIfAbsent(ctx, key, bytes.NewReader(body), int64(len(body))); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("put after close = %v", err)
	}

	for name, prepare := range map[string]func(string) error{
		"root symlink": func(candidate string) error {
			target := filepath.Join(filepath.Dir(candidate), "target")
			if err := os.Mkdir(target, 0o700); err != nil {
				return err
			}
			return os.Symlink(target, candidate)
		},
		"lock symlink": func(candidate string) error {
			if err := os.Mkdir(candidate, 0o700); err != nil {
				return err
			}
			return os.Symlink("target", filepath.Join(candidate, filesystemLockName))
		},
		"cleanup symlink": func(candidate string) error {
			if err := os.Mkdir(candidate, 0o700); err != nil {
				return err
			}
			return os.Symlink("target", filepath.Join(candidate, "unsafe"))
		},
	} {
		t.Run(name, func(t *testing.T) {
			candidate := filepath.Join(t.TempDir(), "candidate")
			if err := prepare(candidate); err != nil {
				t.Fatal(err)
			}
			if opened, err := NewFilesystemBlobStore(candidate); err == nil {
				_ = opened.Close()
				t.Fatal("unsafe filesystem root succeeded")
			}
		})
	}
	t.Run("uncreatable nested root", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("permission failure is not observable as root")
		}
		parent := filepath.Join(t.TempDir(), "protected")
		if err := os.Mkdir(parent, 0o500); err != nil {
			t.Fatal(err)
		}
		defer func() { _ = os.Chmod(parent, 0o700) }() // Permit test cleanup.
		if _, err := NewFilesystemBlobStore(filepath.Join(parent, "nested", "blobs")); err == nil {
			t.Fatal("blob root below unwritable directory succeeded")
		}
	})
	t.Run("unreadable cleanup directory", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("permission failure is not observable as root")
		}
		candidate := filepath.Join(t.TempDir(), "candidate")
		blocked := filepath.Join(candidate, "blocked")
		if err := os.MkdirAll(blocked, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(blocked, 0); err != nil {
			t.Fatal(err)
		}
		defer func() { _ = os.Chmod(blocked, 0o700) }()
		if opened, err := NewFilesystemBlobStore(candidate); err == nil {
			_ = opened.Close()
			t.Fatal("blob root with unreadable recovery directory succeeded")
		}
	})
}

func openSQLiteV3TestIndex(t testing.TB, path string) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	for _, schema := range []string{sqliteSchemaV1, sqliteSchemaV2, sqliteSchemaV3} {
		if _, err := db.Exec(schema); err != nil {
			_ = db.Close()
			t.Fatal(err)
		}
	}
	if _, err := db.Exec("PRAGMA user_version = 3"); err != nil {
		_ = db.Close()
		t.Fatal(err)
	}
	return db
}

func TestSQLiteVersionThreeShardRegistrationMigration(t *testing.T) {
	requireLocalDurability(t)
	ctx := context.Background()

	t.Run("bounded backfill", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "index.db")
		db := openSQLiteV3TestIndex(t, path)
		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		expected := make(map[scopedHash]BlobKey)
		alphaA := BlobKey{Kind: BlobShard, Hash: xethash.Chunk([]byte("migration alpha A"))}
		alphaB := BlobKey{Kind: BlobShard, Hash: xethash.Chunk([]byte("migration alpha B"))}
		beta := BlobKey{Kind: BlobShard, Hash: xethash.Chunk([]byte("migration beta"))}
		for i := range 260 {
			namespace, source := "alpha", alphaA
			if i%2 != 0 {
				source = alphaB
			}
			if i >= 257 {
				namespace, source = "beta", beta
			}
			fileHash := xethash.Chunk([]byte(fmt.Sprintf("migration file %03d", i)))
			data, err := encodeIndexRecord(FileRecord{
				File: shard.RegisteredFile{File: shard.File{Hash: fileHash}}, Shard: source,
			})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := tx.ExecContext(ctx,
				"INSERT INTO files(namespace, hash, record) VALUES(?, ?, ?)",
				namespace, hashBytes(fileHash), data,
			); err != nil {
				t.Fatal(err)
			}
			expected[scopedHash{namespace: namespace, hash: source.Hash}] = source
		}
		gamma := BlobKey{Kind: BlobShard, Hash: xethash.Chunk([]byte("migration dedup only"))}
		for i, association := range []struct {
			namespace string
			source    BlobKey
		}{{"alpha", alphaA}, {"gamma", gamma}} {
			chunk := xethash.Chunk([]byte(fmt.Sprintf("migration dedup %d", i)))
			data, err := encodeIndexRecord(DedupRecord{Shard: association.source})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := tx.ExecContext(ctx,
				"INSERT INTO dedup(namespace, chunk_hash, record) VALUES(?, ?, ?)",
				association.namespace, hashBytes(chunk), data,
			); err != nil {
				t.Fatal(err)
			}
			expected[scopedHash{namespace: association.namespace, hash: association.source.Hash}] = association.source
		}
		if err := tx.Commit(); err != nil {
			t.Fatal(err)
		}
		if err := db.Close(); err != nil {
			t.Fatal(err)
		}

		store, err := OpenSQLiteIndexStore(path)
		if err != nil {
			t.Fatal(err)
		}
		defer store.Close() //nolint:errcheck // Test cleanup.
		for key, want := range expected {
			got, found, err := store.GetShard(ctx, key.namespace, key.hash)
			if err != nil || !found || got.Blob != want {
				t.Fatalf("migrated shard %q/%s = %#v, %v, %v", key.namespace, key.hash, got, found, err)
			}
		}
		seen := make(map[scopedHash]BlobKey)
		request := PageRequest{Limit: 2}
		for {
			page, err := store.ListShards(ctx, nil, request)
			if err != nil {
				t.Fatal(err)
			}
			for _, item := range page.Items {
				seen[scopedHash{namespace: item.Namespace, hash: item.Record.Blob.Hash}] = item.Record.Blob
			}
			if page.NextCursor == "" {
				break
			}
			request.Cursor = page.NextCursor
		}
		if !reflect.DeepEqual(seen, expected) {
			t.Fatalf("migrated shard registrations = %#v, want %#v", seen, expected)
		}
		var version int
		if err := store.db.QueryRowContext(ctx, "PRAGMA user_version").Scan(&version); err != nil || version != 4 {
			t.Fatalf("migrated version = %d, %v", version, err)
		}
	})

	for _, test := range []struct {
		name   string
		record func(xethash.Hash, BlobKey) []byte
	}{
		{"malformed JSON", func(xethash.Hash, BlobKey) []byte { return []byte("{") }},
		{"invalid shard source", func(hash xethash.Hash, _ BlobKey) []byte {
			data, _ := encodeIndexRecord(FileRecord{
				File:  shard.RegisteredFile{File: shard.File{Hash: hash}},
				Shard: BlobKey{Kind: BlobXorb, Hash: xethash.Chunk([]byte("invalid migration source"))},
			})
			return data
		}},
		{"file identity mismatch", func(_ xethash.Hash, source BlobKey) []byte {
			data, _ := encodeIndexRecord(FileRecord{
				File:  shard.RegisteredFile{File: shard.File{Hash: xethash.Chunk([]byte("wrong migration file"))}},
				Shard: source,
			})
			return data
		}},
	} {
		t.Run("late corruption "+test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "index.db")
			db := openSQLiteV3TestIndex(t, path)
			tx, err := db.BeginTx(ctx, nil)
			if err != nil {
				t.Fatal(err)
			}
			source := BlobKey{Kind: BlobShard, Hash: xethash.Chunk([]byte("valid migration source"))}
			for i := range 256 {
				fileHash := xethash.Chunk([]byte(fmt.Sprintf("valid migration row %03d", i)))
				data, err := encodeIndexRecord(FileRecord{
					File: shard.RegisteredFile{File: shard.File{Hash: fileHash}}, Shard: source,
				})
				if err != nil {
					t.Fatal(err)
				}
				if _, err := tx.ExecContext(ctx,
					"INSERT INTO files(namespace, hash, record) VALUES(?, ?, ?)",
					"a", hashBytes(fileHash), data,
				); err != nil {
					t.Fatal(err)
				}
			}
			corruptHash := xethash.Chunk([]byte("late corrupt migration row"))
			if _, err := tx.ExecContext(ctx,
				"INSERT INTO files(namespace, hash, record) VALUES(?, ?, ?)",
				"z", hashBytes(corruptHash), test.record(corruptHash, source),
			); err != nil {
				t.Fatal(err)
			}
			if err := tx.Commit(); err != nil {
				t.Fatal(err)
			}
			if err := db.Close(); err != nil {
				t.Fatal(err)
			}
			if _, err := OpenSQLiteIndexStore(path); !errors.Is(err, ErrCorrupt) {
				t.Fatalf("corrupt v3 migration = %v", err)
			}
			db, err = sql.Open("sqlite", path)
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close() //nolint:errcheck // Test cleanup.
			var version, files, shardTables int
			if err := db.QueryRowContext(ctx, "PRAGMA user_version").Scan(&version); err != nil {
				t.Fatal(err)
			}
			if err := db.QueryRowContext(ctx, "SELECT count(*) FROM files").Scan(&files); err != nil {
				t.Fatal(err)
			}
			if err := db.QueryRowContext(ctx,
				"SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name = 'shards'",
			).Scan(&shardTables); err != nil {
				t.Fatal(err)
			}
			if version != 3 || files != 257 || shardTables != 0 {
				t.Fatalf("rolled-back migration = version %d, files %d, shard tables %d", version, files, shardTables)
			}
		})
	}

	for _, test := range []struct {
		name   string
		record []byte
	}{
		{"malformed dedup JSON", []byte("{")},
		{"invalid dedup source", func() []byte {
			data, _ := encodeIndexRecord(DedupRecord{Shard: BlobKey{
				Kind: BlobXorb, Hash: xethash.Chunk([]byte("invalid migration dedup source")),
			}})
			return data
		}()},
	} {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "index.db")
			db := openSQLiteV3TestIndex(t, path)
			chunk := xethash.Chunk([]byte("corrupt migration dedup"))
			if _, err := db.ExecContext(ctx,
				"INSERT INTO dedup(namespace, chunk_hash, record) VALUES(?, ?, ?)",
				"scope", hashBytes(chunk), test.record,
			); err != nil {
				t.Fatal(err)
			}
			if err := db.Close(); err != nil {
				t.Fatal(err)
			}
			if _, err := OpenSQLiteIndexStore(path); !errors.Is(err, ErrCorrupt) {
				t.Fatalf("corrupt v3 dedup migration = %v", err)
			}
		})
	}
}

type corruptPublicationFixture struct {
	publication             ShardPublication
	newFile, retainedFile   xethash.Hash
	newChunk, retainedChunk xethash.Hash
	newSum, retainedSum     [32]byte
}

func newCorruptPublicationFixture(label string) corruptPublicationFixture {
	key := func(value string) xethash.Hash { return xethash.Chunk([]byte(label + " " + value)) }
	fixture := corruptPublicationFixture{
		newFile: key("new file"), retainedFile: key("retained file"),
		newChunk: key("new chunk"), retainedChunk: key("retained chunk"),
	}
	newSum, retainedSum := key("new SHA"), key("retained SHA")
	copy(fixture.newSum[:], newSum[:])
	copy(fixture.retainedSum[:], retainedSum[:])
	shardKey := BlobKey{Kind: BlobShard, Hash: key("publication shard")}
	fixture.publication = ShardPublication{
		Namespace: "scope", Shard: shardKey,
		Dedup: []DedupAssociation{
			{Chunk: fixture.newChunk, Value: DedupRecord{Shard: shardKey}},
			{Chunk: fixture.retainedChunk, Value: DedupRecord{Shard: shardKey}},
		},
		SHA256: []SHA256Association{
			{Sum: fixture.newSum, Size: 1, File: fixture.newFile},
			{Sum: fixture.retainedSum, Size: 2, File: fixture.retainedFile},
		},
		Files: []FileRecord{
			{File: shard.RegisteredFile{File: shard.File{Hash: fixture.newFile}, Size: 1}, Shard: shardKey},
			{File: shard.RegisteredFile{File: shard.File{Hash: fixture.retainedFile}, Size: 2}, Shard: shardKey},
		},
	}
	return fixture
}

func TestShardPublicationRejectsCorruptRetainedRecordsAtomically(t *testing.T) {
	ctx := context.Background()

	t.Run("memory", func(t *testing.T) {
		for _, kind := range []string{"shard", "file", "dedup"} {
			t.Run(kind, func(t *testing.T) {
				store := NewMemoryStore()
				fixture := newCorruptPublicationFixture("memory " + kind)
				switch kind {
				case "shard":
					store.shards[scopedHash{
						namespace: fixture.publication.Namespace, hash: fixture.publication.Shard.Hash,
					}] = ShardRecord{Blob: BlobKey{Kind: BlobXorb, Hash: fixture.publication.Shard.Hash}}
				case "file":
					store.files[scopedHash{
						namespace: fixture.publication.Namespace, hash: fixture.retainedFile,
					}] = FileRecord{
						File:  shard.RegisteredFile{File: shard.File{Hash: fixture.retainedFile}},
						Shard: BlobKey{Kind: BlobXorb, Hash: fixture.publication.Shard.Hash},
					}
				case "dedup":
					store.dedup[scopedHash{
						namespace: fixture.publication.Namespace, hash: fixture.retainedChunk,
					}] = DedupRecord{Shard: BlobKey{Kind: BlobXorb, Hash: fixture.publication.Shard.Hash}}
				}
				if err := store.PublishShard(ctx, fixture.publication); !errors.Is(err, ErrCorrupt) {
					t.Fatalf("publication over corrupt %s = %v", kind, err)
				}
				switch kind {
				case "shard":
					if _, _, err := store.GetShard(ctx, "scope", fixture.publication.Shard.Hash); !errors.Is(err, ErrCorrupt) {
						t.Fatalf("get corrupt memory shard = %v", err)
					}
					if _, err := store.ListShards(ctx, nil, PageRequest{}); !errors.Is(err, ErrCorrupt) {
						t.Fatalf("list corrupt memory shard = %v", err)
					}
				case "file":
					if _, _, err := store.GetFile(ctx, "scope", fixture.retainedFile); !errors.Is(err, ErrCorrupt) {
						t.Fatalf("get corrupt memory file = %v", err)
					}
					if _, err := store.ListFiles(ctx, nil, PageRequest{}); !errors.Is(err, ErrCorrupt) {
						t.Fatalf("list corrupt memory file = %v", err)
					}
				case "dedup":
					if _, _, err := store.GetDedup(ctx, "scope", fixture.retainedChunk); !errors.Is(err, ErrCorrupt) {
						t.Fatalf("get corrupt memory dedup = %v", err)
					}
					if _, err := store.ListDedup(ctx, nil, PageRequest{}); !errors.Is(err, ErrCorrupt) {
						t.Fatalf("list corrupt memory dedup = %v", err)
					}
				}
				if _, found := store.files[scopedHash{namespace: "scope", hash: fixture.newFile}]; found {
					t.Fatal("failed publication exposed new file")
				}
				if _, found := store.dedup[scopedHash{namespace: "scope", hash: fixture.newChunk}]; found {
					t.Fatal("failed publication exposed new dedup")
				}
				if _, found := store.sha256[shaKey{namespace: "scope", sum: fixture.newSum, size: 1}]; found {
					t.Fatal("failed publication exposed new SHA")
				}
				if kind != "shard" {
					if _, found := store.shards[scopedHash{namespace: "scope", hash: fixture.publication.Shard.Hash}]; found {
						t.Fatal("failed publication exposed shard registration")
					}
				}
			})
		}
	})

	t.Run("sqlite", func(t *testing.T) {
		requireLocalDurability(t)
		for _, kind := range []string{
			"shard", "shard JSON", "shard storage",
			"file", "file JSON", "file storage",
			"dedup", "dedup JSON", "dedup storage",
			"SHA",
		} {
			t.Run(kind, func(t *testing.T) {
				store, err := OpenSQLiteIndexStore(filepath.Join(t.TempDir(), "index.db"))
				if err != nil {
					t.Fatal(err)
				}
				defer store.Close() //nolint:errcheck // Test cleanup.
				fixture := newCorruptPublicationFixture("SQLite " + kind)
				baseKind := strings.TrimSuffix(strings.TrimSuffix(kind, " JSON"), " storage")
				insertRecord := func(query string, args ...any) {
					t.Helper()
					if strings.HasSuffix(kind, " storage") {
						connection, err := store.db.Conn(ctx)
						if err != nil {
							t.Fatal(err)
						}
						if _, err := connection.ExecContext(ctx, "PRAGMA ignore_check_constraints=ON"); err != nil {
							_ = connection.Close()
							t.Fatal(err)
						}
						args[len(args)-1] = string(args[len(args)-1].([]byte))
						_, err = connection.ExecContext(ctx, query, args...)
						_ = connection.Close()
						if err != nil {
							t.Fatal(err)
						}
						return
					}
					if _, err := store.db.ExecContext(ctx, query, args...); err != nil {
						t.Fatal(err)
					}
				}
				switch baseKind {
				case "shard":
					data, err := encodeIndexRecord(ShardRecord{Blob: BlobKey{
						Kind: BlobShard, Hash: xethash.Chunk([]byte("wrong retained shard")),
					}})
					if err != nil {
						t.Fatal(err)
					}
					if kind != baseKind {
						data = []byte("{")
					}
					insertRecord(
						"INSERT INTO shards(namespace, hash, record) VALUES(?, ?, ?)",
						"scope", hashBytes(fixture.publication.Shard.Hash), data,
					)
				case "file":
					data, err := encodeIndexRecord(FileRecord{
						File:  shard.RegisteredFile{File: shard.File{Hash: fixture.retainedFile}},
						Shard: BlobKey{Kind: BlobXorb, Hash: fixture.publication.Shard.Hash},
					})
					if err != nil {
						t.Fatal(err)
					}
					if kind != baseKind {
						data = []byte("{")
					}
					insertRecord(
						"INSERT INTO files(namespace, hash, record) VALUES(?, ?, ?)",
						"scope", hashBytes(fixture.retainedFile), data,
					)
				case "dedup":
					data, err := encodeIndexRecord(DedupRecord{Shard: BlobKey{
						Kind: BlobXorb, Hash: fixture.publication.Shard.Hash,
					}})
					if err != nil {
						t.Fatal(err)
					}
					if kind != baseKind {
						data = []byte("{")
					}
					insertRecord(
						"INSERT INTO dedup(namespace, chunk_hash, record) VALUES(?, ?, ?)",
						"scope", hashBytes(fixture.retainedChunk), data,
					)
				case "SHA":
					connection, err := store.db.Conn(ctx)
					if err != nil {
						t.Fatal(err)
					}
					if _, err := connection.ExecContext(ctx, "PRAGMA ignore_check_constraints=ON"); err != nil {
						_ = connection.Close()
						t.Fatal(err)
					}
					_, err = connection.ExecContext(ctx, `
INSERT INTO sha256_associations(namespace, sum, size, file_hash) VALUES(?, ?, ?, ?)`,
						"scope", fixture.retainedSum[:], 2, string(fixture.retainedFile[:]))
					_ = connection.Close()
					if err != nil {
						t.Fatal(err)
					}
				}
				switch baseKind {
				case "shard":
					if _, _, err := store.GetShard(ctx, "scope", fixture.publication.Shard.Hash); !errors.Is(err, ErrCorrupt) {
						t.Fatalf("get corrupt SQLite shard = %v", err)
					}
					if _, err := store.ListShards(ctx, nil, PageRequest{}); !errors.Is(err, ErrCorrupt) {
						t.Fatalf("list corrupt SQLite shard = %v", err)
					}
				case "file":
					if _, _, err := store.GetFile(ctx, "scope", fixture.retainedFile); !errors.Is(err, ErrCorrupt) {
						t.Fatalf("get corrupt SQLite file = %v", err)
					}
					if _, err := store.ListFiles(ctx, nil, PageRequest{}); !errors.Is(err, ErrCorrupt) {
						t.Fatalf("list corrupt SQLite file = %v", err)
					}
				case "dedup":
					if _, _, err := store.GetDedup(ctx, "scope", fixture.retainedChunk); !errors.Is(err, ErrCorrupt) {
						t.Fatalf("get corrupt SQLite dedup = %v", err)
					}
					if _, err := store.ListDedup(ctx, nil, PageRequest{}); !errors.Is(err, ErrCorrupt) {
						t.Fatalf("list corrupt SQLite dedup = %v", err)
					}
				case "SHA":
					if _, err := store.ListSHA256(ctx, nil, PageRequest{}); !errors.Is(err, ErrCorrupt) {
						t.Fatalf("list corrupt SQLite SHA = %v", err)
					}
				}
				if err := store.PublishShard(ctx, fixture.publication); !errors.Is(err, ErrCorrupt) {
					t.Fatalf("publication over corrupt %s = %v", kind, err)
				}
				if _, found, err := store.GetFile(ctx, "scope", fixture.newFile); err != nil || found {
					t.Fatalf("new file after failed publication = %v, %v", found, err)
				}
				if _, found, err := store.GetDedup(ctx, "scope", fixture.newChunk); err != nil || found {
					t.Fatalf("new dedup after failed publication = %v, %v", found, err)
				}
				if _, found, err := store.ResolveSHA256(ctx, "scope", fixture.newSum, 1); err != nil || found {
					t.Fatalf("new SHA after failed publication = %v, %v", found, err)
				}
				if baseKind != "shard" {
					if _, found, err := store.GetShard(ctx, "scope", fixture.publication.Shard.Hash); err != nil || found {
						t.Fatalf("new shard after failed publication = %v, %v", found, err)
					}
				}
			})
		}
	})
}

func TestSQLiteIndexStoreRestartMigrationAndAtomicFailures(t *testing.T) {
	requireLocalDurability(t)
	path := filepath.Join(t.TempDir(), "index.db")
	store, err := OpenSQLiteIndexStore(path)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	fileHash := xethash.Chunk([]byte("SQLite durable file"))
	chunkHash := xethash.Chunk([]byte("SQLite durable chunk"))
	sum := [32]byte{4, 5, 6}
	shardKey := BlobKey{Kind: BlobShard, Hash: xethash.Chunk([]byte("SQLite shard"))}
	publication := ShardPublication{
		Namespace: "scope",
		Shard:     shardKey,
		Dedup: []DedupAssociation{{
			Chunk: chunkHash, Value: DedupRecord{Shard: shardKey},
		}},
		SHA256: []SHA256Association{{Sum: sum, Size: 10, File: fileHash}},
		Files:  []FileRecord{{File: shard.RegisteredFile{File: shard.File{Hash: fileHash}, Size: 10}, Shard: shardKey}},
	}
	injected := errors.New("injected SQLite transaction failure")
	for _, stage := range []string{"after-dedup", "after-sha256", "after-files", "after-shard", "before-commit"} {
		store.testHook = func(got string) error {
			if got == stage {
				return injected
			}
			return nil
		}
		if err := store.PublishShard(ctx, publication); !errors.Is(err, injected) {
			t.Fatalf("%s failure = %v", stage, err)
		}
		if _, found, err := store.GetFile(ctx, "scope", fileHash); err != nil || found {
			t.Fatalf("%s partial file = %v, %v", stage, found, err)
		}
		if _, found, err := store.GetDedup(ctx, "scope", chunkHash); err != nil || found {
			t.Fatalf("%s partial dedup = %v, %v", stage, found, err)
		}
		if _, found, err := store.ResolveSHA256(ctx, "scope", sum, 10); err != nil || found {
			t.Fatalf("%s partial SHA = %v, %v", stage, found, err)
		}
		if _, found, err := store.GetShard(ctx, "scope", shardKey.Hash); err != nil || found {
			t.Fatalf("%s partial shard registration = %v, %v", stage, found, err)
		}
	}
	store.testHook = nil
	if err := store.PublishShard(ctx, publication); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	store, err = OpenSQLiteIndexStore(path)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close() //nolint:errcheck // Test cleanup.
	if got, found, err := store.ResolveSHA256(ctx, "scope", sum, 10); err != nil || !found || got != fileHash {
		t.Fatalf("reopened SHA = %s, %v, %v", got, found, err)
	}
	if got, found, err := store.GetShard(ctx, "scope", shardKey.Hash); err != nil || !found || got.Blob != shardKey {
		t.Fatalf("reopened shard registration = %#v, %v, %v", got, found, err)
	}
	var version int
	if err := store.db.QueryRow("PRAGMA user_version").Scan(&version); err != nil || version != sqliteSchemaVersion {
		t.Fatalf("schema version = %d, %v", version, err)
	}
	connections := make([]*sql.Conn, 0, 4)
	for range 4 {
		connection, err := store.db.Conn(ctx)
		if err != nil {
			t.Fatal(err)
		}
		connections = append(connections, connection)
	}
	defer func() {
		for _, connection := range connections {
			_ = connection.Close()
		}
	}()
	for i, connection := range connections {
		var foreignKeys, synchronous, busyTimeout int
		if err := connection.QueryRowContext(ctx, "PRAGMA foreign_keys").Scan(&foreignKeys); err != nil {
			t.Fatal(err)
		}
		if err := connection.QueryRowContext(ctx, "PRAGMA synchronous").Scan(&synchronous); err != nil {
			t.Fatal(err)
		}
		if err := connection.QueryRowContext(ctx, "PRAGMA busy_timeout").Scan(&busyTimeout); err != nil {
			t.Fatal(err)
		}
		if foreignKeys != 1 || synchronous != 2 || busyTimeout != 5_000 {
			t.Fatalf("connection %d pragmas = foreign_keys:%d synchronous:%d busy_timeout:%d", i, foreignKeys, synchronous, busyTimeout)
		}
	}
}

func TestSQLiteIndexStoreSecurityConcurrencyAndCorruption(t *testing.T) {
	requireLocalDurability(t)
	ctx := context.Background()
	t.Run("permissions and corruption", func(t *testing.T) {
		parent := filepath.Join(t.TempDir(), "private")
		if err := os.Mkdir(parent, 0o777); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(parent, "index.db")
		if err := os.WriteFile(path, nil, 0o666); err != nil {
			t.Fatal(err)
		}
		store, err := OpenSQLiteIndexStore(path)
		if err != nil {
			t.Fatal(err)
		}
		defer store.Close() //nolint:errcheck // Test cleanup.
		if info, err := os.Stat(parent); err != nil || info.Mode().Perm() != 0o700 {
			t.Fatalf("SQLite parent mode = %v, %v", info.Mode().Perm(), err)
		}
		if info, err := os.Stat(path); err != nil || info.Mode().Perm() != 0o600 {
			t.Fatalf("SQLite mode = %v, %v", info.Mode().Perm(), err)
		}

		hash := xethash.Chunk([]byte("corrupt SQLite xorb"))
		record := XorbRecord{Blob: BlobKey{Kind: BlobXorb, Hash: hash}, Layout: xorb.Ingested{Hash: hash}}
		if err := store.PutXorb(ctx, record); err != nil {
			t.Fatal(err)
		}
		for _, suffix := range []string{"-wal", "-shm"} {
			info, err := os.Stat(path + suffix)
			if err != nil {
				t.Fatalf("SQLite %s file: %v", suffix, err)
			}
			if info.Mode().Perm()&0o077 != 0 {
				t.Fatalf("SQLite %s mode = %v", suffix, info.Mode().Perm())
			}
		}
		if _, err := store.db.ExecContext(ctx,
			"INSERT INTO xorbs(hash, record) VALUES(?, ?)", []byte{1}, []byte("{}")); err == nil {
			t.Fatal("SQLite accepted a truncated hash key")
		}
		corrupt := record
		corrupt.Blob.Hash = xethash.Zero
		encoded, err := encodeIndexRecord(corrupt)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := store.db.ExecContext(ctx, "UPDATE xorbs SET record = ? WHERE hash = ?", encoded, hashBytes(hash)); err != nil {
			t.Fatal(err)
		}
		if _, _, err := store.GetXorb(ctx, hash); !errors.Is(err, ErrCorrupt) {
			t.Fatalf("corrupt SQLite record = %v", err)
		}
		if _, err := store.ListXorbs(ctx, PageRequest{}); !errors.Is(err, ErrCorrupt) {
			t.Fatalf("list corrupt SQLite xorb = %v", err)
		}
		fileHash := xethash.Chunk([]byte("corrupt SQLite file"))
		if err := store.PutFile(ctx, "scope", FileRecord{File: shard.RegisteredFile{File: shard.File{Hash: fileHash}}}); err != nil {
			t.Fatal(err)
		}
		if _, err := store.db.ExecContext(ctx, "UPDATE files SET record = ? WHERE namespace = ? AND hash = ?", []byte("{"), "scope", hashBytes(fileHash)); err != nil {
			t.Fatal(err)
		}
		if _, _, err := store.GetFile(ctx, "scope", fileHash); !errors.Is(err, ErrCorrupt) {
			t.Fatalf("corrupt SQLite file = %v", err)
		}
		if _, err := store.ListFiles(ctx, nil, PageRequest{}); !errors.Is(err, ErrCorrupt) {
			t.Fatalf("list corrupt SQLite file = %v", err)
		}
		mismatchedFile := FileRecord{File: shard.RegisteredFile{File: shard.File{Hash: xethash.Zero}}}
		encodedFile, err := encodeIndexRecord(mismatchedFile)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := store.db.ExecContext(ctx, "UPDATE files SET record = ? WHERE namespace = ? AND hash = ?", encodedFile, "scope", hashBytes(fileHash)); err != nil {
			t.Fatal(err)
		}
		if _, _, err := store.GetFile(ctx, "scope", fileHash); !errors.Is(err, ErrCorrupt) {
			t.Fatalf("mismatched SQLite file = %v", err)
		}
		if _, err := store.ListFiles(ctx, nil, PageRequest{}); !errors.Is(err, ErrCorrupt) {
			t.Fatalf("list mismatched SQLite file = %v", err)
		}
		wrongShardKind := FileRecord{
			File: shard.RegisteredFile{File: shard.File{Hash: fileHash}}, Shard: BlobKey{Kind: BlobXorb},
		}
		encodedFile, err = encodeIndexRecord(wrongShardKind)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := store.db.ExecContext(ctx, "UPDATE files SET record = ? WHERE namespace = ? AND hash = ?", encodedFile, "scope", hashBytes(fileHash)); err != nil {
			t.Fatal(err)
		}
		if _, err := store.ListFiles(ctx, nil, PageRequest{}); !errors.Is(err, ErrCorrupt) {
			t.Fatalf("list mismatched SQLite file shard kind = %v", err)
		}
		chunkHash := xethash.Chunk([]byte("corrupt SQLite dedup"))
		if err := store.PutDedup(ctx, "scope", chunkHash, DedupRecord{}); err != nil {
			t.Fatal(err)
		}
		if _, err := store.db.ExecContext(ctx, "UPDATE dedup SET record = ? WHERE namespace = ? AND chunk_hash = ?", []byte("{"), "scope", hashBytes(chunkHash)); err != nil {
			t.Fatal(err)
		}
		if _, _, err := store.GetDedup(ctx, "scope", chunkHash); !errors.Is(err, ErrCorrupt) {
			t.Fatalf("corrupt SQLite dedup = %v", err)
		}
		if _, err := store.ListDedup(ctx, nil, PageRequest{}); !errors.Is(err, ErrCorrupt) {
			t.Fatalf("list corrupt SQLite dedup = %v", err)
		}
		encodedDedup, err := encodeIndexRecord(DedupRecord{})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := store.db.ExecContext(ctx, "UPDATE dedup SET record = ? WHERE namespace = ? AND chunk_hash = ?", encodedDedup, "scope", hashBytes(chunkHash)); err != nil {
			t.Fatal(err)
		}
		if _, err := store.ListDedup(ctx, nil, PageRequest{}); !errors.Is(err, ErrCorrupt) {
			t.Fatalf("list mismatched SQLite dedup shard kind = %v", err)
		}
		connection, err := store.db.Conn(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer connection.Close() //nolint:errcheck // Test cleanup.
		if _, err := connection.ExecContext(ctx, "PRAGMA ignore_check_constraints=ON"); err != nil {
			t.Fatal(err)
		}
		shortSum := [32]byte{8}
		if _, err := connection.ExecContext(ctx, `
INSERT INTO sha256_associations(namespace, sum, size, file_hash) VALUES(?, ?, ?, ?)`,
			"scope", shortSum[:], 1, []byte{1}); err != nil {
			t.Fatal(err)
		}
		if _, _, err := store.ResolveSHA256(ctx, "scope", shortSum, 1); !errors.Is(err, ErrCorrupt) {
			t.Fatalf("truncated SQLite SHA file hash = %v", err)
		}
		if _, err := store.ListSHA256(ctx, nil, PageRequest{}); !errors.Is(err, ErrCorrupt) {
			t.Fatalf("list truncated SQLite SHA file hash = %v", err)
		}
		if err := store.PutSHA256(ctx, "scope", shortSum, 1, hash); !errors.Is(err, ErrCorrupt) {
			t.Fatalf("put over truncated SQLite SHA file hash = %v", err)
		}
		if err := store.PutXorb(ctx, record); !errors.Is(err, ErrCorrupt) {
			t.Fatalf("put over corrupt SQLite xorb = %v", err)
		}
		if _, _, err := store.ResolveSHA256(ctx, "scope", shortSum, ^uint64(0)); !errors.Is(err, ErrInvalid) {
			t.Fatalf("overflowing SQLite SHA resolve = %v", err)
		}
		if err := store.PutSHA256(ctx, "scope", shortSum, ^uint64(0), hash); !errors.Is(err, ErrInvalid) {
			t.Fatalf("overflowing SQLite SHA put = %v", err)
		}
		if value, err := uint64ToSQLite(uint64(^uint64(0) >> 1)); err != nil || value < 0 {
			t.Fatalf("maximum SQLite integer = %d, %v", value, err)
		}
		if _, err := encodeIndexRecord(make(chan struct{})); err == nil {
			t.Fatal("unsupported SQLite record encoded")
		}
		if err := decodeIndexRecord([]byte("{"), &record); !errors.Is(err, ErrCorrupt) {
			t.Fatalf("invalid SQLite record decode = %v", err)
		}
		if err := store.PublishShard(ctx, ShardPublication{
			Namespace: "overflow", Shard: BlobKey{Kind: BlobShard, Hash: hash}, SHA256: []SHA256Association{{Size: ^uint64(0)}},
		}); !errors.Is(err, ErrInvalid) {
			t.Fatalf("overflowing SQLite publication = %v", err)
		}
	})

	t.Run("concurrent migration", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "index", "index.db")
		const openers = 8
		results := make(chan error, openers)
		var wait sync.WaitGroup
		for range openers {
			wait.Add(1)
			go func() {
				defer wait.Done()
				store, err := OpenSQLiteIndexStore(path)
				if err == nil {
					err = store.Close()
				}
				results <- err
			}()
		}
		wait.Wait()
		close(results)
		for err := range results {
			if err != nil {
				t.Fatal(err)
			}
		}
	})

	t.Run("version one migration", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "index.db")
		db, err := sql.Open("sqlite", path)
		if err != nil {
			t.Fatal(err)
		}
		hash := xethash.Chunk([]byte("SQLite version one migration"))
		record := XorbRecord{Blob: BlobKey{Kind: BlobXorb, Hash: hash}, Layout: xorb.Ingested{Hash: hash}}
		encoded, err := encodeIndexRecord(record)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := db.ExecContext(ctx, sqliteSchemaV1); err != nil {
			t.Fatal(err)
		}
		if _, err := db.ExecContext(ctx, "INSERT INTO xorbs(hash, record) VALUES(?, ?)", hashBytes(hash), encoded); err != nil {
			t.Fatal(err)
		}
		if _, err := db.ExecContext(ctx, "PRAGMA user_version = 1"); err != nil {
			t.Fatal(err)
		}
		if err := db.Close(); err != nil {
			t.Fatal(err)
		}

		store, err := OpenSQLiteIndexStore(path)
		if err != nil {
			t.Fatal(err)
		}
		defer store.Close() //nolint:errcheck // Test cleanup.
		got, found, err := store.GetXorb(ctx, hash)
		if err != nil || !found || !reflect.DeepEqual(got, record) {
			t.Fatalf("migrated xorb = %#v, %v, %v", got, found, err)
		}
		var version int
		if err := store.db.QueryRowContext(ctx, "PRAGMA user_version").Scan(&version); err != nil || version != sqliteSchemaVersion {
			t.Fatalf("migrated schema version = %d, %v", version, err)
		}
		if _, err := store.db.ExecContext(ctx,
			"INSERT INTO xorbs(hash, record) VALUES(?, ?)", strings.Repeat("x", 32), []byte("{}")); err == nil {
			t.Fatal("current schema accepted a text hash")
		}
	})

	t.Run("version two migration", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "index.db")
		db, err := sql.Open("sqlite", path)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := db.ExecContext(ctx, sqliteSchemaV1); err != nil {
			t.Fatal(err)
		}
		if _, err := db.ExecContext(ctx, sqliteSchemaV2); err != nil {
			t.Fatal(err)
		}
		if _, err := db.ExecContext(ctx, "PRAGMA user_version = 2"); err != nil {
			t.Fatal(err)
		}
		hash := xethash.Chunk([]byte("preserved version two Xorb"))
		record := XorbRecord{Blob: BlobKey{Kind: BlobXorb, Hash: hash}, Layout: xorb.Ingested{Hash: hash}}
		encoded, err := encodeIndexRecord(record)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := db.ExecContext(ctx, "INSERT INTO xorbs(hash, record) VALUES(?, ?)", hashBytes(hash), encoded); err != nil {
			t.Fatal(err)
		}
		if err := db.Close(); err != nil {
			t.Fatal(err)
		}
		store, err := OpenSQLiteIndexStore(path)
		if err != nil {
			t.Fatal(err)
		}
		defer store.Close() //nolint:errcheck // Test cleanup.
		createdAt := time.Date(2026, time.August, 10, 15, 0, 0, 0, time.UTC)
		if err := store.PutFileLease(ctx, FileLease{
			ID: testProtectionID(200), Namespace: "migrated", File: xethash.Zero,
			CreatedAt: createdAt, ExpiresAt: createdAt.Add(time.Hour),
		}); err != nil {
			t.Fatal(err)
		}
		var version int
		if err := store.db.QueryRowContext(ctx, "PRAGMA user_version").Scan(&version); err != nil || version != sqliteSchemaVersion {
			t.Fatalf("version two migration result = %d, %v", version, err)
		}
		if got, found, err := store.GetXorb(ctx, hash); err != nil || !found || !reflect.DeepEqual(got, record) {
			t.Fatalf("version two row after migration = %#v, %v, %v", got, found, err)
		}
	})

	t.Run("version two failed migration rolls back", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "index.db")
		db, err := sql.Open("sqlite", path)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := db.ExecContext(ctx, sqliteSchemaV1); err != nil {
			t.Fatal(err)
		}
		if _, err := db.ExecContext(ctx, sqliteSchemaV2); err != nil {
			t.Fatal(err)
		}
		if _, err := db.ExecContext(ctx, "CREATE TABLE blob_stages(conflict INTEGER); PRAGMA user_version = 2"); err != nil {
			t.Fatal(err)
		}
		if err := db.Close(); err != nil {
			t.Fatal(err)
		}
		if _, err := OpenSQLiteIndexStore(path); err == nil {
			t.Fatal("conflicting version two migration succeeded")
		}
		db, err = sql.Open("sqlite", path)
		if err != nil {
			t.Fatal(err)
		}
		defer db.Close() //nolint:errcheck // Test cleanup.
		var version int
		if err := db.QueryRowContext(ctx, "PRAGMA user_version").Scan(&version); err != nil || version != 2 {
			t.Fatalf("rolled-back version = %d, %v", version, err)
		}
		var columns int
		if err := db.QueryRowContext(ctx,
			"SELECT count(*) FROM pragma_table_info('blob_stages') WHERE name = 'conflict'",
		).Scan(&columns); err != nil || columns != 1 {
			t.Fatalf("pre-migration table after rollback = %d, %v", columns, err)
		}
	})

	t.Run("version one corrupt migration rolls back", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "index.db")
		db, err := sql.Open("sqlite", path)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := db.ExecContext(ctx, sqliteSchemaV1); err != nil {
			t.Fatal(err)
		}
		if _, err := db.ExecContext(ctx,
			"INSERT INTO xorbs(hash, record) VALUES(?, ?)", strings.Repeat("x", 32), []byte("{}")); err != nil {
			t.Fatal(err)
		}
		if _, err := db.ExecContext(ctx, "PRAGMA user_version = 1"); err != nil {
			t.Fatal(err)
		}
		if err := db.Close(); err != nil {
			t.Fatal(err)
		}
		if _, err := OpenSQLiteIndexStore(path); err == nil {
			t.Fatal("corrupt version one SQLite index migrated")
		}
		db, err = sql.Open("sqlite", path)
		if err != nil {
			t.Fatal(err)
		}
		defer db.Close() //nolint:errcheck // Test cleanup.
		var version, count int
		if err := db.QueryRowContext(ctx, "PRAGMA user_version").Scan(&version); err != nil {
			t.Fatal(err)
		}
		if err := db.QueryRowContext(ctx, "SELECT count(*) FROM xorbs").Scan(&count); err != nil {
			t.Fatal(err)
		}
		if version != 1 || count != 1 {
			t.Fatalf("rolled-back version one index = version %d, rows %d", version, count)
		}
	})

	t.Run("future migration", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "index.db")
		store, err := OpenSQLiteIndexStore(path)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := store.db.ExecContext(ctx, fmt.Sprintf("PRAGMA user_version = %d", sqliteSchemaVersion+1)); err != nil {
			t.Fatal(err)
		}
		if err := store.Close(); err != nil {
			t.Fatal(err)
		}
		if _, err := OpenSQLiteIndexStore(path); err == nil {
			t.Fatal("future SQLite schema version succeeded")
		}
	})

	t.Run("migration collision and invalid database", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "collision.db")
		db, err := sql.Open("sqlite", path)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := db.ExecContext(ctx, "CREATE TABLE xorbs (value INTEGER)"); err != nil {
			t.Fatal(err)
		}
		if err := db.Close(); err != nil {
			t.Fatal(err)
		}
		if _, err := OpenSQLiteIndexStore(path); err == nil {
			t.Fatal("conflicting version-zero schema succeeded")
		}

		invalid := filepath.Join(t.TempDir(), "invalid.db")
		if err := os.WriteFile(invalid, []byte("not a SQLite database"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := OpenSQLiteIndexStore(invalid); err == nil {
			t.Fatal("invalid SQLite database succeeded")
		}

		memory, err := sql.Open("sqlite", ":memory:")
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = memory.Close() }()
		if err := (&SQLiteIndexStore{db: memory}).initialize(ctx); err == nil {
			t.Fatal("SQLite memory database accepted as WAL-durable")
		}
	})

	t.Run("private path failures", func(t *testing.T) {
		leafDirectory := filepath.Join(t.TempDir(), "index.db")
		if err := os.Mkdir(leafDirectory, 0o700); err != nil {
			t.Fatal(err)
		}
		if _, err := OpenSQLiteIndexStore(leafDirectory); err == nil {
			t.Fatal("SQLite directory accepted as index file")
		}
		if os.Geteuid() != 0 {
			parent := filepath.Join(t.TempDir(), "protected")
			if err := os.Mkdir(parent, 0o500); err != nil {
				t.Fatal(err)
			}
			defer func() { _ = os.Chmod(parent, 0o700) }() // Permit test cleanup.
			if _, err := OpenSQLiteIndexStore(filepath.Join(parent, "nested", "index.db")); err == nil {
				t.Fatal("SQLite index below unwritable directory succeeded")
			}
		}
	})

	t.Run("corrupt backend tables", func(t *testing.T) {
		hash := xethash.Chunk([]byte("corrupt backend shard"))
		for _, test := range []struct {
			name        string
			table       string
			publication ShardPublication
		}{
			{"dedup", "dedup", ShardPublication{Shard: BlobKey{Kind: BlobShard, Hash: hash}, Dedup: []DedupAssociation{{Value: DedupRecord{Shard: BlobKey{Kind: BlobShard, Hash: hash}}}}}},
			{"SHA", "sha256_associations", ShardPublication{Shard: BlobKey{Kind: BlobShard, Hash: hash}, SHA256: []SHA256Association{{}}}},
			{"files", "files", ShardPublication{Shard: BlobKey{Kind: BlobShard, Hash: hash}, Files: []FileRecord{{Shard: BlobKey{Kind: BlobShard, Hash: hash}}}}},
			{"shards", "shards", ShardPublication{Shard: BlobKey{Kind: BlobShard, Hash: hash}}},
		} {
			t.Run(test.name, func(t *testing.T) {
				store, err := OpenSQLiteIndexStore(filepath.Join(t.TempDir(), "index.db"))
				if err != nil {
					t.Fatal(err)
				}
				defer store.Close() //nolint:errcheck // Test cleanup.
				if _, err := store.db.ExecContext(ctx, "DROP TABLE "+test.table); err != nil {
					t.Fatal(err)
				}
				if err := store.PublishShard(ctx, test.publication); err == nil {
					t.Fatal("publication against missing table succeeded")
				}
			})
		}
	})
}

type failingResponseWriter struct {
	header http.Header
	writes int
	failAt int
}

func (w *failingResponseWriter) Header() http.Header {
	if w.header == nil {
		w.header = make(http.Header)
	}
	return w.header
}

func (*failingResponseWriter) WriteHeader(int) {}

func (w *failingResponseWriter) Write(value []byte) (int, error) {
	w.writes++
	if w.writes == w.failAt {
		return 0, errors.New("injected response write failure")
	}
	return len(value), nil
}

func TestShardV2StreamingAndIngestCancellationFailures(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()
	service := testService(t, store, nil)
	none, _, _, shardBody := uploadFixture(t)
	if _, err := service.UploadXorb(ctx, "", xetcas.DefaultXorbPrefix, none.Hash,
		bytes.NewReader(none.Body), int64(len(none.Body))); err != nil {
		t.Fatal(err)
	}
	for _, failAt := range []int{1, 2, 3} {
		writer := &failingResponseWriter{failAt: failAt}
		request := httptest.NewRequest(http.MethodPost, "/v2/shards", bytes.NewReader(shardBody))
		service.handleShardV2(writer, request, "")
		if writer.writes != failAt {
			t.Fatalf("failure at write %d stopped after %d writes", failAt, writer.writes)
		}
	}
	service.blobs = faultBlobStore{BlobStore: store, delay: 15 * time.Millisecond}
	service.shardHeartbeat = time.Millisecond
	heartbeatWriter := &failingResponseWriter{failAt: 2}
	service.handleShardV2(heartbeatWriter,
		httptest.NewRequest(http.MethodPost, "/v2/shards", bytes.NewReader(shardBody)), "")
	if heartbeatWriter.writes != 2 {
		t.Fatalf("heartbeat write failure stopped after %d writes", heartbeatWriter.writes)
	}

	service.blobs = store
	releases := make([]func(), 0, cap(service.ingestSlots))
	for range cap(service.ingestSlots) {
		release, err := service.acquireIngest(ctx)
		if err != nil {
			t.Fatal(err)
		}
		releases = append(releases, release)
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := service.UploadShard(canceled, "", bytes.NewReader(shardBody), int64(len(shardBody))); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled queued shard upload = %v", err)
	}
	if _, err := service.UploadXorb(canceled, "", xetcas.DefaultXorbPrefix, none.Hash,
		bytes.NewReader(none.Body), int64(len(none.Body))); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled queued xorb upload = %v", err)
	}
	response := httptest.NewRecorder()
	service.handleShardV2(response,
		httptest.NewRequest(http.MethodPost, "/v2/shards", bytes.NewReader(shardBody)).WithContext(canceled), "")
	if response.Code != serverErrorStatus(context.Canceled) {
		t.Fatalf("canceled queued HTTP shard status = %d", response.Code)
	}
	for _, release := range releases {
		release()
	}
}

func TestSQLiteIndexStoreClosedErrors(t *testing.T) {
	requireLocalDurability(t)
	store, err := OpenSQLiteIndexStore(filepath.Join(t.TempDir(), "index.db"))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	hash := xethash.Chunk([]byte("closed SQLite"))
	record := XorbRecord{Blob: BlobKey{Kind: BlobXorb, Hash: hash}, Layout: xorb.Ingested{Hash: hash}}
	file := FileRecord{File: shard.RegisteredFile{File: shard.File{Hash: hash}}}
	sum := [32]byte{1}
	createdAt := time.Date(2026, time.August, 10, 15, 0, 0, 0, time.UTC)
	stage := BlobStage{
		ID: testProtectionID(400), Namespace: "scope", Blob: BlobKey{Kind: BlobXorb, Hash: hash},
		CreatedAt: createdAt, ExpiresAt: createdAt.Add(time.Hour),
	}
	lease := FileLease{
		ID: testProtectionID(401), Namespace: "scope", File: hash,
		CreatedAt: createdAt, ExpiresAt: createdAt.Add(time.Hour),
	}
	operations := []struct {
		name string
		call func() error
	}{
		{"get xorb", func() error { _, _, err := store.GetXorb(ctx, hash); return err }},
		{"put xorb", func() error { return store.PutXorb(ctx, record) }},
		{"get shard", func() error { _, _, err := store.GetShard(ctx, "scope", hash); return err }},
		{"get file", func() error { _, _, err := store.GetFile(ctx, "scope", hash); return err }},
		{"put file", func() error { return store.PutFile(ctx, "scope", file) }},
		{"get dedup", func() error { _, _, err := store.GetDedup(ctx, "scope", hash); return err }},
		{"put dedup", func() error { return store.PutDedup(ctx, "scope", hash, DedupRecord{}) }},
		{"resolve SHA", func() error { _, _, err := store.ResolveSHA256(ctx, "scope", sum, 1); return err }},
		{"put SHA", func() error { return store.PutSHA256(ctx, "scope", sum, 1, hash) }},
		{"publish", func() error {
			return store.PublishShard(ctx, ShardPublication{Shard: BlobKey{Kind: BlobShard, Hash: hash}})
		}},
		{"put stage", func() error { return store.PutBlobStage(ctx, stage) }},
		{"renew stage", func() error {
			return store.RenewBlobStage(ctx, stage.Namespace, stage.ID, stage.ExpiresAt.Add(time.Hour))
		}},
		{"delete stage", func() error { return store.DeleteBlobStage(ctx, stage.Namespace, stage.ID) }},
		{"list stages", func() error { _, err := store.ListBlobStages(ctx, nil, PageRequest{}); return err }},
		{"list expired stages", func() error {
			_, err := store.ListExpiredBlobStages(ctx, stage.ExpiresAt, PageRequest{})
			return err
		}},
		{"delete expired stage", func() error {
			_, err := store.DeleteExpiredBlobStage(ctx, stage.Namespace, stage.ID, stage.ExpiresAt)
			return err
		}},
		{"put lease", func() error { return store.PutFileLease(ctx, lease) }},
		{"renew lease", func() error {
			return store.RenewFileLease(ctx, lease.Namespace, lease.ID, lease.ExpiresAt.Add(time.Hour))
		}},
		{"delete lease", func() error { return store.DeleteFileLease(ctx, lease.Namespace, lease.ID) }},
		{"list leases", func() error { _, err := store.ListFileLeases(ctx, nil, PageRequest{}); return err }},
		{"list expired leases", func() error {
			_, err := store.ListExpiredFileLeases(ctx, lease.ExpiresAt, PageRequest{})
			return err
		}},
		{"delete expired lease", func() error {
			_, err := store.DeleteExpiredFileLease(ctx, lease.Namespace, lease.ID, lease.ExpiresAt)
			return err
		}},
	}
	for _, operation := range operations {
		if err := operation.call(); err == nil {
			t.Fatalf("%s after close succeeded", operation.name)
		}
	}
}

func TestDurableCASServiceRoundTripAcrossRestart(t *testing.T) {
	requireLocalDurability(t)
	root := t.TempDir()
	blobRoot := filepath.Join(root, "blobs")
	indexPath := filepath.Join(root, "index.db")
	open := func(t testing.TB) (*FilesystemBlobStore, *SQLiteIndexStore, *Service) {
		t.Helper()
		blobs, err := NewFilesystemBlobStore(blobRoot)
		if err != nil {
			t.Fatal(err)
		}
		index, err := OpenSQLiteIndexStore(indexPath)
		if err != nil {
			_ = blobs.Close()
			t.Fatal(err)
		}
		service, err := New(Options{
			Blobs: blobs, Index: index,
			Authorizer: AllowAllAuthorizer{Namespace: "durable"},
			Signer: RangeURLSignerFunc(func(context.Context, BlobKey, xetcas.HTTPRange) (SignedRange, error) {
				return signedTestRange("https://storage.example/object"), nil
			}),
			DedupProtectionKey: xethash.Chunk([]byte("durable key")),
		})
		if err != nil {
			_ = index.Close()
			_ = blobs.Close()
			t.Fatal(err)
		}
		return blobs, index, service
	}

	ctx := context.Background()
	none, _, value, shardBody := uploadFixture(t)
	blobs, index, service := open(t)
	if _, err := service.UploadXorb(ctx, "", xetcas.DefaultXorbPrefix, none.Hash,
		bytes.NewReader(none.Body), int64(len(none.Body))); err != nil {
		t.Fatal(err)
	}
	if _, err := service.UploadShard(ctx, "", bytes.NewReader(shardBody), int64(len(shardBody))); err != nil {
		t.Fatal(err)
	}
	if err := index.Close(); err != nil {
		t.Fatal(err)
	}
	if err := blobs.Close(); err != nil {
		t.Fatal(err)
	}

	blobs, index, service = open(t)
	defer blobs.Close() //nolint:errcheck // Test cleanup.
	defer index.Close() //nolint:errcheck // Test cleanup.
	opened, err := service.OpenFile(ctx, "", value.Files[0].Hash, nil)
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(opened.Body)
	_ = opened.Body.Close()
	if err != nil || !bytes.Equal(got, objectContents(none)) {
		t.Fatalf("reopened file = %d bytes, %v", len(got), err)
	}
	if dedup, err := service.GlobalDedup(ctx, "", xetcas.DefaultDedupPrefix, none.Chunks[0].Hash); err != nil || len(dedup) == 0 {
		t.Fatalf("reopened dedup = %d bytes, %v", len(dedup), err)
	}
}

func TestDurableStoreInputSafety(t *testing.T) {
	if _, err := NewFilesystemBlobStore(""); err == nil {
		t.Fatal("empty blob root succeeded")
	}
	if _, err := OpenSQLiteIndexStore(""); err == nil {
		t.Fatal("empty SQLite path succeeded")
	}
	requireLocalDurability(t)
	regular := filepath.Join(t.TempDir(), "regular")
	if err := os.WriteFile(regular, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewFilesystemBlobStore(regular); err == nil {
		t.Fatal("regular-file blob root succeeded")
	}
	store, err := NewFilesystemBlobStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close() //nolint:errcheck // Test cleanup.
	bad := BlobKey{Kind: BlobKind("../../escape"), Hash: xethash.Zero}
	if _, err := store.PutIfAbsent(context.Background(), bad, bytes.NewReader(nil), 0); !errors.Is(err, ErrInvalid) {
		t.Fatalf("unsafe blob kind = %v", err)
	}
	if _, err := NewFilesystemBlobStore(t.TempDir(), FilesystemBlobStoreOptions{}, FilesystemBlobStoreOptions{}); err == nil {
		t.Fatal("multiple filesystem options succeeded")
	}
	if _, err := OpenSQLiteIndexStore(filepath.Join(regular, "index.db")); err == nil {
		t.Fatal("SQLite under regular file succeeded")
	}
	if runtime.GOOS != "windows" {
		target := filepath.Join(t.TempDir(), "target.db")
		if err := os.WriteFile(target, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		link := filepath.Join(t.TempDir(), "link.db")
		if err := os.Symlink(target, link); err != nil {
			t.Fatal(err)
		}
		if _, err := OpenSQLiteIndexStore(link); err == nil {
			t.Fatal("SQLite symlink succeeded")
		}
		realParent := filepath.Join(t.TempDir(), "real-parent")
		if err := os.Mkdir(realParent, 0o700); err != nil {
			t.Fatal(err)
		}
		linkedParent := filepath.Join(t.TempDir(), "linked-parent")
		if err := os.Symlink(realParent, linkedParent); err != nil {
			t.Fatal(err)
		}
		if _, err := OpenSQLiteIndexStore(filepath.Join(linkedParent, "index.db")); err == nil {
			t.Fatal("SQLite symlinked parent succeeded")
		}
	}
	if _, err := uint64ToSQLite(mathMaxUint64()); !errors.Is(err, ErrInvalid) {
		t.Fatalf("SQLite integer overflow = %v", err)
	}
}

func TestMemoryIndexStoreRechecksCancellationAfterAdmission(t *testing.T) {
	store := NewMemoryStore()
	var sum [32]byte
	hash := xethash.Chunk([]byte("cancellation shard"))
	tests := []struct {
		name string
		call func(context.Context) error
	}{
		{"get xorb", func(ctx context.Context) error { _, _, err := store.GetXorb(ctx, xethash.Hash{}); return err }},
		{"put xorb", func(ctx context.Context) error { return store.PutXorb(ctx, XorbRecord{}) }},
		{"get shard", func(ctx context.Context) error {
			_, _, err := store.GetShard(ctx, "namespace", xethash.Hash{})
			return err
		}},
		{"get file", func(ctx context.Context) error {
			_, _, err := store.GetFile(ctx, "namespace", xethash.Hash{})
			return err
		}},
		{"put file", func(ctx context.Context) error { return store.PutFile(ctx, "namespace", FileRecord{}) }},
		{"get dedup", func(ctx context.Context) error {
			_, _, err := store.GetDedup(ctx, "namespace", xethash.Hash{})
			return err
		}},
		{"put dedup", func(ctx context.Context) error {
			return store.PutDedup(ctx, "namespace", xethash.Hash{}, DedupRecord{})
		}},
		{"resolve SHA-256", func(ctx context.Context) error {
			_, _, err := store.ResolveSHA256(ctx, "namespace", sum, 0)
			return err
		}},
		{"put SHA-256", func(ctx context.Context) error {
			return store.PutSHA256(ctx, "namespace", sum, 0, xethash.Hash{})
		}},
		{"publish shard", func(ctx context.Context) error {
			return store.PublishShard(ctx, ShardPublication{Shard: BlobKey{Kind: BlobShard, Hash: hash}})
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx := &cancelAfterCheckContext{Context: context.Background(), after: 2}
			if err := test.call(ctx); !errors.Is(err, context.Canceled) {
				t.Fatalf("error = %v, want context cancellation", err)
			}
		})
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := store.GetShard(canceled, "namespace", hash); !errors.Is(err, context.Canceled) {
		t.Fatalf("pre-canceled shard lookup = %v", err)
	}
}

func TestMemoryBlobStoreRechecksCancellationAfterAdmission(t *testing.T) {
	tests := []struct {
		name string
		call func(*MemoryStore, context.Context, chan struct{}) error
	}{
		{"put", func(store *MemoryStore, ctx context.Context, admitted chan struct{}) error {
			_, err := store.PutIfAbsent(ctx, BlobKey{}, &signalingEOFReader{read: admitted}, 0)
			return err
		}},
		{"head", func(store *MemoryStore, ctx context.Context, admitted chan struct{}) error {
			_, _, err := store.Head(&firstCheckContext{Context: ctx, checked: admitted}, BlobKey{})
			return err
		}},
		{"get", func(store *MemoryStore, ctx context.Context, admitted chan struct{}) error {
			_, err := store.Get(&firstCheckContext{Context: ctx, checked: admitted}, BlobKey{}, nil)
			return err
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			store := NewMemoryStore()
			ctx, cancel := context.WithCancel(context.Background())
			admitted := make(chan struct{})
			result := make(chan error, 1)
			store.mu.Lock()
			go func() { result <- test.call(store, ctx, admitted) }()
			<-admitted
			cancel()
			store.mu.Unlock()
			if err := <-result; !errors.Is(err, context.Canceled) {
				t.Fatalf("error = %v, want context cancellation", err)
			}
		})
	}
	store := NewMemoryStore()
	key := BlobKey{Kind: BlobXorb, Hash: xethash.Chunk([]byte("cancel after copy"))}
	if _, err := store.PutIfAbsent(context.Background(), key, bytes.NewReader([]byte("data")), 4); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Get(&cancelAfterCheckContext{Context: context.Background(), after: 3}, key, nil); !errors.Is(err, context.Canceled) {
		t.Fatalf("post-copy cancellation = %v", err)
	}

	pipeReader, pipeWriter := io.Pipe()
	canceled, cancel := context.WithCancel(context.Background())
	reader, done := closeReaderOnCancellation(canceled, pipeReader)
	cancel()
	if _, err := reader.Read(make([]byte, 1)); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("cancellation close error = %v", err)
	}
	close(done)
	_ = pipeWriter.Close()
}

func mathMaxUint64() uint64 { return ^uint64(0) }

func ExampleOpenSQLiteIndexStore() {
	if checkFilesystemDurabilitySupported() != nil {
		fmt.Println(true)
		return
	}
	root, _ := os.MkdirTemp("", "xet-cas-example-")
	defer os.RemoveAll(root) //nolint:errcheck // Example cleanup.
	index, _ := OpenSQLiteIndexStore(filepath.Join(root, "index.db"))
	defer index.Close() //nolint:errcheck // Example cleanup.
	fmt.Println(index != nil)
	// Output: true
}
