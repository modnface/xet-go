package server

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/url"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/jacobwoliver/xet-go/shard"
	"github.com/jacobwoliver/xet-go/xetcas"
	"github.com/jacobwoliver/xet-go/xethash"
	"github.com/jacobwoliver/xet-go/xorb"
)

func testService(t testing.TB, store *MemoryStore, index IndexStore) *Service {
	t.Helper()
	if index == nil {
		index = store
	}
	service, err := New(Options{
		Blobs: store, Index: index,
		Signer: RangeURLSignerFunc(func(_ context.Context, key BlobKey, value xetcas.HTTPRange) (string, error) {
			return fmt.Sprintf("https://storage.example/%s/%s?range=%s", key.Kind, key.Hash, value.String()), nil
		}),
		Authorizer:         AllowAllAuthorizer{Namespace: "tenant-a"},
		Now:                func() time.Time { return time.Unix(1_000, 0) },
		DedupProtectionKey: xethash.Chunk([]byte("fixed server dedup key")),
		DedupTTL:           time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	return service
}

func uploadFixture(t testing.TB) (*xorb.Object, *xorb.Object, shard.Shard, []byte) {
	t.Helper()
	chunks := [][]byte{
		bytes.Repeat([]byte("server-xorb-a"), 4_000),
		bytes.Repeat([]byte("server-xorb-b"), 5_000),
		bytes.Repeat([]byte("server-xorb-c"), 3_000),
	}
	none, err := xorb.Encode(chunks, xorb.None)
	if err != nil {
		t.Fatal(err)
	}
	compressed, err := xorb.Encode(chunks, xorb.LZ4)
	if err != nil {
		t.Fatal(err)
	}
	if none.Hash != compressed.Hash || bytes.Equal(none.Body, compressed.Body) {
		t.Fatal("fixture did not produce alternate encodings of one xorb")
	}
	xorbInfo, err := shard.XorbFromObject(compressed)
	if err != nil {
		t.Fatal(err)
	}
	nodes := make([]xethash.Node, len(chunks))
	hashes := make([]xethash.Hash, len(chunks))
	var contents []byte
	for i, chunk := range chunks {
		hashes[i] = xethash.Chunk(chunk)
		nodes[i] = xethash.Node{Hash: hashes[i], Size: uint64(len(chunk))}
		contents = append(contents, chunk...)
	}
	sum := [32]byte{1, 2, 3, 4}
	value := shard.Shard{
		Files: []shard.File{{
			Hash: xethash.File(nodes),
			Terms: []shard.Term{{
				XorbHash: compressed.Hash, UnpackedBytes: uint32(len(contents)), Start: 0, End: uint32(len(chunks)),
				Verification: xethash.Verification(hashes),
			}},
			SHA256: &sum,
		}},
		Xorbs: []shard.Xorb{xorbInfo},
	}
	body, err := shard.EncodeUpload(value)
	if err != nil {
		t.Fatal(err)
	}
	return none, compressed, value, body
}

func TestServiceUploadPublicationAndReadPlanning(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()
	service := testService(t, store, nil)
	none, compressed, value, shardBody := uploadFixture(t)

	inserted, err := service.UploadXorb(ctx, "", xetcas.DefaultXorbPrefix, none.Hash,
		bytes.NewReader(none.Body), int64(len(none.Body)))
	if err != nil || !inserted {
		t.Fatalf("first xorb upload = %v, %v", inserted, err)
	}
	// The xorb hash authenticates logical chunks, not one compression byte
	// stream. An equivalent representation must reuse the durable first body.
	inserted, err = service.UploadXorb(ctx, "", xetcas.DefaultXorbPrefix, compressed.Hash,
		bytes.NewReader(compressed.Body), int64(len(compressed.Body)))
	if err != nil || inserted {
		t.Fatalf("equivalent xorb upload = %v, %v", inserted, err)
	}

	result, err := service.UploadShard(ctx, "", bytes.NewReader(shardBody), int64(len(shardBody)))
	if err != nil {
		t.Fatal(err)
	}
	if !result.Inserted || result.Files != 1 || result.GlobalDedupChunks == 0 {
		t.Fatalf("shard result = %#v", result)
	}
	result, err = service.UploadShard(ctx, "", bytes.NewReader(shardBody), int64(len(shardBody)))
	if err != nil || result.Inserted {
		t.Fatalf("replayed shard = %#v, %v", result, err)
	}

	fileHash := value.Files[0].Hash
	record, err := service.File(ctx, "", fileHash)
	if err != nil || record.File.Size != uint64(value.Files[0].Terms[0].UnpackedBytes) {
		t.Fatalf("file record = %#v, %v", record, err)
	}
	if got, found, err := store.ResolveSHA256(ctx, "tenant-a", *value.Files[0].SHA256, record.File.Size); err != nil || !found || got != fileHash {
		t.Fatalf("SHA-256 association = %s, %v, %v", got, found, err)
	}

	reconstruction, err := service.ReconstructionV2(ctx, "", fileHash, &xetcas.FileRange{Start: 1, End: record.File.Size - 1})
	if err != nil {
		t.Fatal(err)
	}
	if reconstruction.OffsetIntoFirstRange != 1 || len(reconstruction.Terms) != 1 || len(reconstruction.Xorbs[none.Hash]) != 1 {
		t.Fatalf("reconstruction = %#v", reconstruction)
	}
	parsed, err := url.Parse(reconstruction.Xorbs[none.Hash][0].URL)
	if err != nil || parsed.Host != "storage.example" {
		t.Fatalf("signed URL = %q, %v", reconstruction.Xorbs[none.Hash][0].URL, err)
	}
	v1, err := service.ReconstructionV1(ctx, "", fileHash, nil)
	if err != nil || len(v1.FetchInfo[none.Hash]) != 1 {
		t.Fatalf("v1 reconstruction = %#v, %v", v1, err)
	}
	batch, err := service.BatchReconstructionV1(ctx, "", []xethash.Hash{fileHash, fileHash, xethash.Chunk([]byte("missing"))})
	if err != nil || len(batch.Files) != 1 {
		t.Fatalf("batch reconstruction = %#v, %v", batch, err)
	}

	dedup, err := service.GlobalDedup(ctx, "", xetcas.DefaultDedupPrefix, none.Chunks[0].Hash)
	if err != nil {
		t.Fatal(err)
	}
	protected, err := shard.Decode(dedup)
	if err != nil {
		t.Fatal(err)
	}
	if len(protected.Files) != 0 || len(protected.Xorbs) != 1 || protected.Footer == nil ||
		protected.Footer.CreatedAtUnix != 1_000 || protected.Footer.KeyExpiresAtUnix != 1_060 ||
		protected.Footer.ChunkProtectionKey.IsZero() {
		t.Fatalf("protected dedup shard = %#v", protected)
	}
	if protected.Xorbs[0].SerializedBytes != uint32(len(none.Body)) {
		t.Fatalf("dedup shard retained client representation size %d, stored size is %d",
			protected.Xorbs[0].SerializedBytes, len(none.Body))
	}
	if legacy, err := service.GlobalDedup(ctx, "", xetcas.DefaultXorbPrefix, none.Chunks[0].Hash); err != nil || len(legacy) == 0 {
		t.Fatalf("released Rust dedup prefix compatibility = %d bytes, %v", len(legacy), err)
	}
}

func TestServiceAuthLimitsAndExistence(t *testing.T) {
	store := NewMemoryStore()
	service, err := New(Options{
		Blobs: store, Index: store,
		Signer: RangeURLSignerFunc(func(context.Context, BlobKey, xetcas.HTTPRange) (string, error) {
			return "https://storage.example/object", nil
		}),
		Authorizer:  StaticTokenAuthorizer{Token: "secret", Namespace: "scope"},
		MaxXorbBody: 64,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	hash := xethash.Chunk([]byte("body"))
	if _, err := service.UploadXorb(ctx, "", xetcas.DefaultXorbPrefix, hash, bytes.NewReader([]byte("body")), 4); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("missing credential error = %v", err)
	}
	if _, err := service.UploadXorb(ctx, "wrong", xetcas.DefaultXorbPrefix, hash, bytes.NewReader([]byte("body")), 4); !errors.Is(err, ErrForbidden) {
		t.Fatalf("wrong credential error = %v", err)
	}
	if _, err := service.UploadXorb(ctx, "secret", xetcas.DefaultXorbPrefix, hash, bytes.NewReader(make([]byte, 65)), 65); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("oversized body error = %v", err)
	}
	if found, err := service.XorbExists(ctx, "secret", xetcas.DefaultXorbPrefix, hash); err != nil || found {
		t.Fatalf("absent xorb = %v, %v", found, err)
	}
}

type faultIndex struct {
	IndexStore
	mu     sync.Mutex
	failAt string
}

func (f *faultIndex) take(name string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failAt == name {
		f.failAt = ""
		return errors.New("injected " + name + " failure")
	}
	return nil
}

func (f *faultIndex) PutXorb(ctx context.Context, value XorbRecord) error {
	if err := f.take("xorb"); err != nil {
		return err
	}
	return f.IndexStore.PutXorb(ctx, value)
}
func (f *faultIndex) GetXorb(ctx context.Context, hash xethash.Hash) (XorbRecord, bool, error) {
	if err := f.take("get-xorb"); err != nil {
		return XorbRecord{}, false, err
	}
	return f.IndexStore.GetXorb(ctx, hash)
}
func (f *faultIndex) GetFile(ctx context.Context, hash xethash.Hash) (FileRecord, bool, error) {
	if err := f.take("get-file"); err != nil {
		return FileRecord{}, false, err
	}
	return f.IndexStore.GetFile(ctx, hash)
}
func (f *faultIndex) GetDedup(ctx context.Context, hash xethash.Hash) (DedupRecord, bool, error) {
	if err := f.take("get-dedup"); err != nil {
		return DedupRecord{}, false, err
	}
	return f.IndexStore.GetDedup(ctx, hash)
}
func (f *faultIndex) PutDedup(ctx context.Context, hash xethash.Hash, value DedupRecord) error {
	if err := f.take("dedup"); err != nil {
		return err
	}
	return f.IndexStore.PutDedup(ctx, hash, value)
}
func (f *faultIndex) PutSHA256(ctx context.Context, namespace string, sum [32]byte, size uint64, hash xethash.Hash) error {
	if err := f.take("sha"); err != nil {
		return err
	}
	return f.IndexStore.PutSHA256(ctx, namespace, sum, size, hash)
}
func (f *faultIndex) PutFile(ctx context.Context, value FileRecord) error {
	if err := f.take("file"); err != nil {
		return err
	}
	return f.IndexStore.PutFile(ctx, value)
}

func TestServiceRepairsLostPublicationResponses(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()
	faults := &faultIndex{IndexStore: store, failAt: "xorb"}
	service := testService(t, store, faults)
	none, _, value, shardBody := uploadFixture(t)

	if _, err := service.UploadXorb(ctx, "", xetcas.DefaultXorbPrefix, none.Hash,
		bytes.NewReader(none.Body), int64(len(none.Body))); err == nil {
		t.Fatal("injected xorb index failure succeeded")
	}
	if found, err := service.XorbExists(ctx, "", xetcas.DefaultXorbPrefix, none.Hash); err != nil || found {
		t.Fatalf("unpublished xorb existence = %v, %v", found, err)
	}
	if inserted, err := service.UploadXorb(ctx, "", xetcas.DefaultXorbPrefix, none.Hash,
		bytes.NewReader(none.Body), int64(len(none.Body))); err != nil || inserted {
		t.Fatalf("xorb repair = %v, %v", inserted, err)
	}

	faults.failAt = "sha"
	if _, err := service.UploadShard(ctx, "", bytes.NewReader(shardBody), int64(len(shardBody))); err == nil {
		t.Fatal("injected SHA publication failure succeeded")
	}
	if _, found, err := store.GetFile(ctx, value.Files[0].Hash); err != nil || found {
		t.Fatalf("file published before SHA association = %v, %v", found, err)
	}
	if _, err := service.UploadShard(ctx, "", bytes.NewReader(shardBody), int64(len(shardBody))); err != nil {
		t.Fatalf("shard repair = %v", err)
	}

	reader, err := store.Get(ctx, BlobKey{Kind: BlobXorb, Hash: none.Hash}, nil)
	if err != nil {
		t.Fatal(err)
	}
	stored, err := io.ReadAll(reader)
	_ = reader.Close()
	if err != nil || len(stored) <= len(none.Body) {
		t.Fatalf("stored canonical xorb length = %d, %v", len(stored), err)
	}
}

func TestMemoryStoreDedupIndexKeepsAValidExistingSource(t *testing.T) {
	store := NewMemoryStore()
	chunk := xethash.Chunk([]byte("shared chunk"))
	first := DedupRecord{Shard: BlobKey{Kind: BlobShard, Hash: xethash.Chunk([]byte("first shard"))}}
	second := DedupRecord{Shard: BlobKey{Kind: BlobShard, Hash: xethash.Chunk([]byte("second shard"))}}
	if err := store.PutDedup(context.Background(), chunk, first); err != nil {
		t.Fatal(err)
	}
	if err := store.PutDedup(context.Background(), chunk, second); err != nil {
		t.Fatalf("second valid dedup source conflicted: %v", err)
	}
	got, found, err := store.GetDedup(context.Background(), chunk)
	if err != nil || !found || got != first {
		t.Fatalf("dedup source = %#v, %v, %v; want first source", got, found, err)
	}
}

func TestMemoryStoreFileIndexKeepsAValidExistingRecipe(t *testing.T) {
	store := NewMemoryStore()
	hash := xethash.Chunk([]byte("logical file"))
	first := FileRecord{
		File:  shard.RegisteredFile{File: shard.File{Hash: hash}, Size: 12},
		Shard: BlobKey{Kind: BlobShard, Hash: xethash.Chunk([]byte("first shard"))},
	}
	second := first
	second.Shard.Hash = xethash.Chunk([]byte("second shard"))
	second.File.File.SHA256 = &[32]byte{1}
	if err := store.PutFile(context.Background(), first); err != nil {
		t.Fatal(err)
	}
	if err := store.PutFile(context.Background(), second); err != nil {
		t.Fatalf("second valid file recipe conflicted: %v", err)
	}
	got, found, err := store.GetFile(context.Background(), hash)
	if err != nil || !found || !reflect.DeepEqual(got, first) {
		t.Fatalf("file record = %#v, %v, %v; want first recipe %#v", got, found, err, first)
	}
}
