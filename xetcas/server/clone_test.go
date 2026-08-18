package server

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/jmwoliver/xet-go/shard"
	"github.com/jmwoliver/xet-go/xetcas"
	"github.com/jmwoliver/xet-go/xethash"
	"github.com/jmwoliver/xet-go/xorb"
)

func TestCloneFileBetweenNamespacesBackendsAndPayloadIsolation(t *testing.T) {
	for name, factory := range map[string]func(*testing.T) IndexStore{
		"memory": func(*testing.T) IndexStore { return NewMemoryStore() },
		"sqlite": func(t *testing.T) IndexStore {
			requireLocalDurability(t)
			store, err := OpenSQLiteIndexStore(filepath.Join(t.TempDir(), "clone.db"))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = store.Close() })
			return store
		},
	} {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			blobs := NewMemoryStore()
			index := factory(t)
			service := testService(t, blobs, index)
			none, _, value, shardBody := uploadFixture(t)
			if _, err := service.UploadXorb(ctx, "", xetcas.DefaultXorbPrefix, none.Hash,
				bytes.NewReader(none.Body), int64(len(none.Body))); err != nil {
				t.Fatal(err)
			}
			if _, err := service.UploadShard(ctx, "", bytes.NewReader(shardBody), int64(len(shardBody))); err != nil {
				t.Fatal(err)
			}
			fileHash := value.Files[0].Hash
			fileSize := uint64(len(objectContents(none)))
			fileSum := value.Files[0].SHA256

			spy := &cloneBlobSpy{BlobStore: blobs}
			service.blobs = spy
			var signed atomic.Int32
			service.signer = RangeURLSignerFunc(func(context.Context, BlobKey, xetcas.HTTPRange) (SignedRange, error) {
				signed.Add(1)
				return SignedRange{}, errors.New("clone must not reconstruct")
			})
			if err := service.CloneFileBetweenNamespaces(
				ctx, "tenant-a", "tenant-b", fileHash, fileSize, fileSum,
			); err != nil {
				t.Fatal(err)
			}
			if spy.xorbGets.Load() != 0 || spy.xorbPuts.Load() != 0 || spy.shardGets.Load() != 1 ||
				spy.shardPuts.Load() != 1 || signed.Load() != 0 {
				t.Fatalf("clone storage calls = xorb get %d put %d, shard get %d put %d, signed %d",
					spy.xorbGets.Load(), spy.xorbPuts.Load(), spy.shardGets.Load(), spy.shardPuts.Load(), signed.Load())
			}
			if err := service.VerifyFileInNamespace(ctx, "tenant-c", fileHash, fileSize, fileSum); !errors.Is(err, ErrNotFound) {
				t.Fatalf("third namespace verification = %v", err)
			}
			if _, found, err := index.GetDedup(ctx, "tenant-b", none.Chunks[0].Hash); err != nil || !found {
				t.Fatalf("destination first-chunk dedup = %v, %v", found, err)
			}
			service.authorizer = AllowAllAuthorizer{Namespace: "tenant-b"}
			protected, err := service.GlobalDedup(ctx, "", xetcas.DefaultDedupPrefix, none.Chunks[0].Hash)
			if err != nil {
				t.Fatalf("destination global dedup = %v", err)
			}
			decoded, err := shard.Decode(protected)
			if err != nil || decoded.Footer == nil || len(decoded.Xorbs) != 1 {
				t.Fatalf("destination protected dedup = %#v, %v", decoded, err)
			}

			other := xethash.Chunk([]byte("backend conflict target"))
			if err := index.PutSHA256(ctx, "tenant-conflict", *fileSum, fileSize, other); err != nil {
				t.Fatal(err)
			}
			if err := service.CloneFileBetweenNamespaces(
				ctx, "tenant-a", "tenant-conflict", fileHash, fileSize, fileSum,
			); !errors.Is(err, ErrConflict) {
				t.Fatalf("backend destination conflict = %v", err)
			}
			if _, found, err := index.GetFile(ctx, "tenant-conflict", fileHash); err != nil || found {
				t.Fatalf("file visible after backend conflict = %v, %v", found, err)
			}
			sourceFile, found, err := index.GetFile(ctx, "tenant-a", fileHash)
			if err != nil || !found {
				t.Fatalf("source after backend conflict = %#v, %v, %v", sourceFile, found, err)
			}
			if _, found, err := index.GetShard(ctx, "tenant-conflict", sourceFile.Shard.Hash); err != nil || found {
				t.Fatalf("shard visible after backend conflict = %v, %v", found, err)
			}

			service.blobs = blobs
			for _, namespace := range []string{"tenant-a", "tenant-b"} {
				opened, err := service.OpenFileInNamespace(ctx, namespace, fileHash, nil)
				if err != nil {
					t.Fatalf("open %s: %v", namespace, err)
				}
				got, readErr := io.ReadAll(opened.Body)
				closeErr := opened.Body.Close()
				if readErr != nil || closeErr != nil || !bytes.Equal(got, objectContents(none)) {
					t.Fatalf("read %s = %d bytes, %v, %v", namespace, len(got), readErr, closeErr)
				}
			}
		})
	}
}

func TestCloneFileBetweenNamespacesStagesOnlyDestinationShardMetadata(t *testing.T) {
	ctx := context.Background()
	blobs := NewMemoryStore()
	index := &cloneStageIndex{MemoryStore: NewMemoryStore()}
	service := testService(t, blobs, index)
	none, _, value, shardBody := uploadFixture(t)
	if _, err := service.UploadXorb(ctx, "", xetcas.DefaultXorbPrefix, none.Hash,
		bytes.NewReader(none.Body), int64(len(none.Body))); err != nil {
		t.Fatal(err)
	}
	if _, err := service.UploadShard(ctx, "", bytes.NewReader(shardBody), int64(len(shardBody))); err != nil {
		t.Fatal(err)
	}
	index.mu.Lock()
	index.staged = nil
	index.mu.Unlock()
	if err := service.CloneFileBetweenNamespaces(
		ctx, "tenant-a", "tenant-b", value.Files[0].Hash,
		uint64(len(objectContents(none))), value.Files[0].SHA256,
	); err != nil {
		t.Fatal(err)
	}
	index.mu.Lock()
	defer index.mu.Unlock()
	if len(index.staged) != 1 || index.staged[0] != BlobShard {
		t.Fatalf("clone stages = %#v, want one metadata shard", index.staged)
	}
}

func TestCloneFileBetweenNamespacesValidatesExactRequirements(t *testing.T) {
	ctx := context.Background()
	for name, mutate := range map[string]func(*uint64, **[32]byte){
		"wrong size": func(size *uint64, _ **[32]byte) { (*size)++ },
		"wrong SHA": func(_ *uint64, sum **[32]byte) {
			wrong := **sum
			wrong[0] ^= 0xff
			*sum = &wrong
		},
	} {
		t.Run(name, func(t *testing.T) {
			store, service, none, value := cloneSourceFixture(t)
			size := uint64(len(objectContents(none)))
			sum := value.Files[0].SHA256
			mutate(&size, &sum)
			if err := service.CloneFileBetweenNamespaces(
				ctx, "tenant-a", "tenant-b", value.Files[0].Hash, size, sum,
			); !errors.Is(err, ErrNotFound) {
				t.Fatalf("mismatch = %v", err)
			}
			assertCloneDestinationMissing(t, store, value.Files[0].Hash)
		})
	}

	t.Run("wrong Xet hash", func(t *testing.T) {
		store, service, none, value := cloneSourceFixture(t)
		wrong := xethash.Chunk([]byte("wrong Xet hash"))
		if err := service.CloneFileBetweenNamespaces(
			ctx, "tenant-a", "tenant-b", wrong, uint64(len(objectContents(none))), value.Files[0].SHA256,
		); !errors.Is(err, ErrNotFound) {
			t.Fatalf("wrong Xet hash = %v", err)
		}
		assertCloneDestinationMissing(t, store, wrong)
	})

	t.Run("missing source SHA association", func(t *testing.T) {
		store, service, none, value := cloneSourceFixture(t)
		size := uint64(len(objectContents(none)))
		store.mu.Lock()
		delete(store.sha256, shaKey{namespace: "tenant-a", sum: *value.Files[0].SHA256, size: size})
		store.mu.Unlock()
		if err := service.CloneFileBetweenNamespaces(
			ctx, "tenant-a", "tenant-b", value.Files[0].Hash, size, value.Files[0].SHA256,
		); !errors.Is(err, ErrNotFound) {
			t.Fatalf("missing SHA association = %v", err)
		}
		assertCloneDestinationMissing(t, store, value.Files[0].Hash)
	})

	t.Run("optional SHA omitted", func(t *testing.T) {
		_, service, none, value := cloneSourceFixture(t)
		if err := service.CloneFileBetweenNamespaces(
			ctx, "tenant-a", "tenant-b", value.Files[0].Hash, uint64(len(objectContents(none))), nil,
		); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("SHA association augments retained SHA-less recipe", func(t *testing.T) {
		store := NewMemoryStore()
		service := testService(t, store, nil)
		none, _, value, _ := uploadFixture(t)
		if _, err := service.UploadXorb(ctx, "", xetcas.DefaultXorbPrefix, none.Hash,
			bytes.NewReader(none.Body), int64(len(none.Body))); err != nil {
			t.Fatal(err)
		}
		withoutSHA := value
		withoutSHA.Files = append([]shard.File(nil), value.Files...)
		withoutSHA.Files[0].SHA256 = nil
		for _, source := range []shard.Shard{withoutSHA, value} {
			body, err := shard.EncodeUpload(source)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := service.UploadShard(ctx, "", bytes.NewReader(body), int64(len(body))); err != nil {
				t.Fatal(err)
			}
		}
		hash := value.Files[0].Hash
		retained, found, err := store.GetFile(ctx, "tenant-a", hash)
		if err != nil || !found || retained.File.File.SHA256 != nil {
			t.Fatalf("retained source recipe = %#v, %v, %v", retained, found, err)
		}
		size := uint64(len(objectContents(none)))
		if err := service.CloneFileBetweenNamespaces(
			ctx, "tenant-a", "tenant-b", hash, size, value.Files[0].SHA256,
		); err != nil {
			t.Fatal(err)
		}
		if associated, found, err := store.ResolveSHA256(
			ctx, "tenant-b", *value.Files[0].SHA256, size,
		); err != nil || !found || associated != hash {
			t.Fatalf("destination SHA association = %s, %v, %v", associated, found, err)
		}
	})
}

func TestCloneFileBetweenNamespacesRejectsMissingAndCorruptDependencies(t *testing.T) {
	tests := []struct {
		name   string
		wanted error
		mutate func(*MemoryStore, *xorb.Object, shard.Shard)
	}{
		{"file record missing", ErrNotFound, func(store *MemoryStore, _ *xorb.Object, value shard.Shard) {
			delete(store.files, scopedHash{namespace: "tenant-a", hash: value.Files[0].Hash})
		}},
		{"file record corrupt", ErrCorrupt, func(store *MemoryStore, _ *xorb.Object, value shard.Shard) {
			key := scopedHash{namespace: "tenant-a", hash: value.Files[0].Hash}
			record := store.files[key]
			record.File.Size++
			store.files[key] = record
		}},
		{"shard record missing", ErrNotFound, func(store *MemoryStore, _ *xorb.Object, value shard.Shard) {
			file := store.files[scopedHash{namespace: "tenant-a", hash: value.Files[0].Hash}]
			delete(store.shards, scopedHash{namespace: "tenant-a", hash: file.Shard.Hash})
		}},
		{"shard record corrupt", ErrCorrupt, func(store *MemoryStore, _ *xorb.Object, value shard.Shard) {
			file := store.files[scopedHash{namespace: "tenant-a", hash: value.Files[0].Hash}]
			key := scopedHash{namespace: "tenant-a", hash: file.Shard.Hash}
			record := store.shards[key]
			record.Blob.Hash = xethash.Chunk([]byte("wrong shard"))
			store.shards[key] = record
		}},
		{"shard blob missing", ErrNotFound, func(store *MemoryStore, _ *xorb.Object, value shard.Shard) {
			file := store.files[scopedHash{namespace: "tenant-a", hash: value.Files[0].Hash}]
			delete(store.blobs, file.Shard)
		}},
		{"shard blob corrupt", ErrCorrupt, func(store *MemoryStore, _ *xorb.Object, value shard.Shard) {
			file := store.files[scopedHash{namespace: "tenant-a", hash: value.Files[0].Hash}]
			store.blobs[file.Shard][0] ^= 0xff
		}},
		{"Xorb record missing", ErrNotFound, func(store *MemoryStore, object *xorb.Object, _ shard.Shard) {
			delete(store.xorbs, object.Hash)
		}},
		{"Xorb record corrupt", ErrCorrupt, func(store *MemoryStore, object *xorb.Object, _ shard.Shard) {
			record := store.xorbs[object.Hash]
			record.Layout.Hash = xethash.Chunk([]byte("wrong Xorb"))
			store.xorbs[object.Hash] = record
		}},
		{"Xorb blob missing", ErrNotFound, func(store *MemoryStore, object *xorb.Object, _ shard.Shard) {
			delete(store.blobs, BlobKey{Kind: BlobXorb, Hash: object.Hash})
		}},
		{"Xorb blob corrupt size", ErrCorrupt, func(store *MemoryStore, object *xorb.Object, _ shard.Shard) {
			key := BlobKey{Kind: BlobXorb, Hash: object.Hash}
			store.blobs[key] = store.blobs[key][:len(store.blobs[key])-1]
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			store, service, object, value := cloneSourceFixture(t)
			store.mu.Lock()
			test.mutate(store, object, value)
			store.mu.Unlock()
			if err := service.CloneFileBetweenNamespaces(
				context.Background(), "tenant-a", "tenant-b", value.Files[0].Hash,
				uint64(len(objectContents(object))), value.Files[0].SHA256,
			); !errors.Is(err, test.wanted) {
				t.Fatalf("clone error = %v, want %v", err, test.wanted)
			}
			assertCloneDestinationMissing(t, store, value.Files[0].Hash)
		})
	}
}

func TestCloneFileBetweenNamespacesSelectsOneFile(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()
	service := testService(t, store, nil)
	chunks := [][]byte{[]byte("first file"), []byte("second "), []byte("file")}
	object, err := xorb.Encode(chunks, xorb.None)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.UploadXorb(ctx, "", xetcas.DefaultXorbPrefix, object.Hash,
		bytes.NewReader(object.Body), int64(len(object.Body))); err != nil {
		t.Fatal(err)
	}
	xorbInfo, err := shard.XorbFromObject(object)
	if err != nil {
		t.Fatal(err)
	}
	firstHash := xethash.File([]xethash.Node{{Hash: xethash.Chunk(chunks[0]), Size: uint64(len(chunks[0]))}})
	secondNodes := []xethash.Node{
		{Hash: xethash.Chunk(chunks[1]), Size: uint64(len(chunks[1]))},
		{Hash: xethash.Chunk(chunks[2]), Size: uint64(len(chunks[2]))},
	}
	firstSum := sha256.Sum256(chunks[0])
	secondBody := append(append([]byte(nil), chunks[1]...), chunks[2]...)
	secondSum := sha256.Sum256(secondBody)
	value := shard.Shard{Xorbs: []shard.Xorb{xorbInfo}, Files: []shard.File{
		{Hash: firstHash, SHA256: &firstSum, Terms: []shard.Term{{
			XorbHash: object.Hash, Start: 0, End: 1, UnpackedBytes: uint32(len(chunks[0])),
			Verification: xethash.Verification([]xethash.Hash{xethash.Chunk(chunks[0])}),
		}}},
		{Hash: xethash.File(secondNodes), SHA256: &secondSum, Terms: []shard.Term{{
			XorbHash: object.Hash, Start: 1, End: 3, UnpackedBytes: uint32(len(secondBody)),
			Verification: xethash.Verification([]xethash.Hash{xethash.Chunk(chunks[1]), xethash.Chunk(chunks[2])}),
		}}},
	}}
	body, err := shard.EncodeUpload(value)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.UploadShard(ctx, "", bytes.NewReader(body), int64(len(body))); err != nil {
		t.Fatal(err)
	}
	if err := service.CloneFileBetweenNamespaces(
		ctx, "tenant-a", "tenant-b", firstHash, uint64(len(chunks[0])), &firstSum,
	); err != nil {
		t.Fatal(err)
	}
	destination, found, err := store.GetFile(ctx, "tenant-b", firstHash)
	if err != nil || !found {
		t.Fatalf("destination file = %#v, %v, %v", destination, found, err)
	}
	reader, err := store.Get(ctx, destination.Shard, nil)
	if err != nil {
		t.Fatal(err)
	}
	metadata, err := io.ReadAll(reader)
	if closeErr := reader.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := shard.Decode(metadata)
	if err != nil || len(decoded.Files) != 1 || decoded.Files[0].Hash != firstHash {
		t.Fatalf("destination shard files = %#v, %v", decoded.Files, err)
	}
	if _, found, err := store.GetFile(ctx, "tenant-b", value.Files[1].Hash); err != nil || found {
		t.Fatalf("unselected destination file = %v, %v", found, err)
	}
	if _, found, err := store.GetFile(ctx, "tenant-a", value.Files[1].Hash); err != nil || !found {
		t.Fatalf("unselected source file = %v, %v", found, err)
	}
}

func TestCloneFileBetweenNamespacesReplayConcurrencyAndConflict(t *testing.T) {
	t.Run("replay and concurrency", func(t *testing.T) {
		store, service, object, value := cloneSourceFixture(t)
		size := uint64(len(objectContents(object)))
		for range 2 {
			if err := service.CloneFileBetweenNamespaces(
				context.Background(), "tenant-a", "tenant-b", value.Files[0].Hash, size, value.Files[0].SHA256,
			); err != nil {
				t.Fatal(err)
			}
		}
		start := make(chan struct{})
		errorsFound := make(chan error, 16)
		for range 16 {
			go func() {
				<-start
				errorsFound <- service.CloneFileBetweenNamespaces(
					context.Background(), "tenant-a", "tenant-b", value.Files[0].Hash, size, value.Files[0].SHA256,
				)
			}()
		}
		close(start)
		for range 16 {
			if err := <-errorsFound; err != nil {
				t.Fatal(err)
			}
		}
		store.mu.RLock()
		defer store.mu.RUnlock()
		if _, ok := store.files[scopedHash{namespace: "tenant-b", hash: value.Files[0].Hash}]; !ok {
			t.Fatal("concurrent clone did not publish destination file")
		}
		for key := range store.shards {
			if key.namespace == "tenant-b" {
				return
			}
		}
		t.Fatal("concurrent clone did not publish destination shard")
	})

	t.Run("destination SHA conflict rolls back", func(t *testing.T) {
		store, service, object, value := cloneSourceFixture(t)
		size := uint64(len(objectContents(object)))
		other := xethash.Chunk([]byte("different destination file"))
		if err := store.PutSHA256(context.Background(), "tenant-b", *value.Files[0].SHA256, size, other); err != nil {
			t.Fatal(err)
		}
		if err := service.CloneFileBetweenNamespaces(
			context.Background(), "tenant-a", "tenant-b", value.Files[0].Hash, size, value.Files[0].SHA256,
		); !errors.Is(err, ErrConflict) {
			t.Fatalf("destination conflict = %v", err)
		}
		assertCloneDestinationMissing(t, store, value.Files[0].Hash)
		if got, found, err := store.ResolveSHA256(
			context.Background(), "tenant-b", *value.Files[0].SHA256, size,
		); err != nil || !found || got != other {
			t.Fatalf("retained destination SHA = %s, %v, %v", got, found, err)
		}
		store.mu.RLock()
		defer store.mu.RUnlock()
		for key := range store.dedup {
			if key.namespace == "tenant-b" {
				t.Fatalf("destination dedup visible after conflict: %#v", key)
			}
		}
		for key := range store.shards {
			if key.namespace == "tenant-b" {
				t.Fatalf("destination shard visible after conflict: %#v", key)
			}
		}
	})
}

func TestCloneFileBetweenNamespacesCancellationAndEmptyFile(t *testing.T) {
	t.Run("invalid trusted boundary", func(t *testing.T) {
		store := NewMemoryStore()
		service := testService(t, store, nil)
		if err := service.CloneFileBetweenNamespaces(nil, "tenant-a", "tenant-b", xethash.Zero, 0, nil); err == nil { //nolint:staticcheck // Verify nil-context rejection.
			t.Fatal("nil clone context succeeded")
		}
		if err := service.CloneFileBetweenNamespaces(
			context.Background(), "", "tenant-b", xethash.Zero, 0, nil,
		); !errors.Is(err, ErrInvalid) {
			t.Fatalf("empty source namespace = %v", err)
		}
	})

	t.Run("canceled before validation", func(t *testing.T) {
		store, service, object, value := cloneSourceFixture(t)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if err := service.CloneFileBetweenNamespaces(
			ctx, "tenant-a", "tenant-b", value.Files[0].Hash,
			uint64(len(objectContents(object))), value.Files[0].SHA256,
		); !errors.Is(err, context.Canceled) {
			t.Fatalf("pre-canceled clone = %v", err)
		}
		assertCloneDestinationMissing(t, store, value.Files[0].Hash)
	})

	t.Run("canceled during Xorb validation", func(t *testing.T) {
		store, service, object, value := cloneSourceFixture(t)
		ctx, cancel := context.WithCancel(context.Background())
		service.blobs = &cancelCloneHeadStore{BlobStore: store, cancel: cancel}
		if err := service.CloneFileBetweenNamespaces(
			ctx, "tenant-a", "tenant-b", value.Files[0].Hash,
			uint64(len(objectContents(object))), value.Files[0].SHA256,
		); !errors.Is(err, context.Canceled) {
			t.Fatalf("clone cancellation during validation = %v", err)
		}
		assertCloneDestinationMissing(t, store, value.Files[0].Hash)
	})

	t.Run("empty zero-hash file", func(t *testing.T) {
		ctx := context.Background()
		store := NewMemoryStore()
		service := testService(t, store, nil)
		sum := sha256.Sum256(nil)
		body, err := shard.EncodeUpload(shard.Shard{Files: []shard.File{{Hash: xethash.Zero, SHA256: &sum}}})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := service.UploadShard(ctx, "", bytes.NewReader(body), int64(len(body))); err != nil {
			t.Fatal(err)
		}
		if err := service.CloneFileBetweenNamespaces(
			ctx, "tenant-a", "tenant-b", xethash.Zero, 0, &sum,
		); err != nil {
			t.Fatal(err)
		}
		opened, err := service.OpenFileInNamespace(ctx, "tenant-b", xethash.Zero, nil)
		if err != nil {
			t.Fatal(err)
		}
		got, readErr := io.ReadAll(opened.Body)
		closeErr := opened.Body.Close()
		if readErr != nil || closeErr != nil || len(got) != 0 {
			t.Fatalf("cloned empty file = %x, %v, %v", got, readErr, closeErr)
		}
	})
}

func cloneSourceFixture(t *testing.T) (*MemoryStore, *Service, *xorb.Object, shard.Shard) {
	t.Helper()
	ctx := context.Background()
	store := NewMemoryStore()
	service := testService(t, store, nil)
	none, _, value, shardBody := uploadFixture(t)
	if _, err := service.UploadXorb(ctx, "", xetcas.DefaultXorbPrefix, none.Hash,
		bytes.NewReader(none.Body), int64(len(none.Body))); err != nil {
		t.Fatal(err)
	}
	if _, err := service.UploadShard(ctx, "", bytes.NewReader(shardBody), int64(len(shardBody))); err != nil {
		t.Fatal(err)
	}
	return store, service, none, value
}

func assertCloneDestinationMissing(t *testing.T, store *MemoryStore, hash xethash.Hash) {
	t.Helper()
	if _, found, err := store.GetFile(context.Background(), "tenant-b", hash); err != nil || found {
		t.Fatalf("destination file after failed clone = %v, %v", found, err)
	}
}

type cloneBlobSpy struct {
	BlobStore
	xorbGets  atomic.Int32
	xorbPuts  atomic.Int32
	shardGets atomic.Int32
	shardPuts atomic.Int32
}

func (store *cloneBlobSpy) PutIfAbsent(
	ctx context.Context,
	key BlobKey,
	body io.Reader,
	size int64,
) (bool, error) {
	switch key.Kind {
	case BlobXorb:
		store.xorbPuts.Add(1)
	case BlobShard:
		store.shardPuts.Add(1)
	}
	return store.BlobStore.PutIfAbsent(ctx, key, body, size)
}

func (store *cloneBlobSpy) Get(
	ctx context.Context,
	key BlobKey,
	wanted *xetcas.HTTPRange,
) (io.ReadCloser, error) {
	switch key.Kind {
	case BlobXorb:
		store.xorbGets.Add(1)
	case BlobShard:
		store.shardGets.Add(1)
	}
	return store.BlobStore.Get(ctx, key, wanted)
}

type cancelCloneHeadStore struct {
	BlobStore
	cancel context.CancelFunc
	once   sync.Once
}

func (store *cancelCloneHeadStore) Head(ctx context.Context, key BlobKey) (BlobInfo, bool, error) {
	if key.Kind == BlobXorb {
		store.once.Do(store.cancel)
	}
	return store.BlobStore.Head(ctx, key)
}

type cloneStageIndex struct {
	*MemoryStore
	mu     sync.Mutex
	staged []BlobKind
}

func (store *cloneStageIndex) PutBlobStage(ctx context.Context, stage BlobStage) error {
	store.mu.Lock()
	store.staged = append(store.staged, stage.Blob.Kind)
	store.mu.Unlock()
	return store.MemoryStore.PutBlobStage(ctx, stage)
}
