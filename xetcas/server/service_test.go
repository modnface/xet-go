package server

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net/url"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jmwoliver/xet-go/shard"
	"github.com/jmwoliver/xet-go/xetcas"
	"github.com/jmwoliver/xet-go/xethash"
	"github.com/jmwoliver/xet-go/xorb"
)

type authorizerFunc func(context.Context, string, AccessRequest) (Grant, error)

func (f authorizerFunc) Authorize(ctx context.Context, credential string, request AccessRequest) (Grant, error) {
	return f(ctx, credential, request)
}

func signedTestRange(url string) SignedRange {
	return SignedRange{URL: url, ExpiresAt: time.Unix(2_000_000_000, 0)}
}

func testService(t testing.TB, store *MemoryStore, index IndexStore) *Service {
	t.Helper()
	if index == nil {
		index = store
	}
	service, err := New(Options{
		Blobs: store, Index: index,
		Signer: RangeURLSignerFunc(func(_ context.Context, key BlobKey, value xetcas.HTTPRange) (SignedRange, error) {
			return signedTestRange(fmt.Sprintf("https://storage.example/%s/%s?range=%s", key.Kind, key.Hash, value.String())), nil
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
	sum := sha256.Sum256(contents)
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

func objectContents(object *xorb.Object) []byte {
	var result []byte
	for _, chunk := range object.Chunks {
		result = append(result, chunk.Data...)
	}
	return result
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
	if got, found, err := store.GetShard(ctx, "tenant-a", result.Shard.Hash); err != nil || !found || got.Blob != result.Shard {
		t.Fatalf("registered uploaded shard = %#v, %v, %v", got, found, err)
	}
	if _, found, err := store.GetShard(ctx, "tenant-b", result.Shard.Hash); err != nil || found {
		t.Fatalf("cross-namespace uploaded shard = %v, %v", found, err)
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

func TestServiceOpenFileStreamsFullAndRange(t *testing.T) {
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
	want := objectContents(none)
	fileHash := value.Files[0].Hash
	sum := sha256.Sum256(want)
	if err := service.VerifyFileInNamespace(ctx, "tenant-a", fileHash, uint64(len(want)), &sum); err != nil {
		t.Fatalf("file availability = %v", err)
	}
	if leases, err := store.ListFileLeases(ctx, nil, PageRequest{}); err != nil || len(leases.Items) != 0 {
		t.Fatalf("availability verification created leases = %#v, %v", leases, err)
	}
	if err := service.VerifyFileInNamespace(ctx, "tenant-b", fileHash, uint64(len(want)), &sum); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-namespace availability = %v", err)
	}
	if err := service.VerifyFileInNamespace(ctx, "", fileHash, uint64(len(want)), &sum); !errors.Is(err, ErrInvalid) {
		t.Fatalf("empty availability namespace = %v", err)
	}
	if err := service.VerifyFileInNamespace(nil, "tenant-a", fileHash, uint64(len(want)), &sum); err == nil { //nolint:staticcheck // Verify nil-context rejection.
		t.Fatal("nil-context availability succeeded")
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if err := service.VerifyFileInNamespace(canceled, "tenant-a", fileHash, uint64(len(want)), &sum); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled availability = %v", err)
	}

	opened, err := service.OpenFile(ctx, "", fileHash, nil)
	if err != nil {
		t.Fatal(err)
	}
	got, readErr := io.ReadAll(opened.Body)
	closeErr := opened.Body.Close()
	if readErr != nil || closeErr != nil || !bytes.Equal(got, want) {
		t.Fatalf("whole stream = %d bytes, read %v, close %v", len(got), readErr, closeErr)
	}
	if opened.Hash != fileHash || opened.FileSize != uint64(len(want)) || opened.Size != uint64(len(want)) ||
		opened.Range != (xetcas.FileRange{Start: 0, End: uint64(len(want))}) || opened.SHA256 == nil ||
		*opened.SHA256 != sha256.Sum256(want) {
		t.Fatalf("whole stream metadata = %#v", opened)
	}

	wanted := xetcas.FileRange{Start: 17, End: uint64(len(want)) + 10_000}
	opened, err = service.OpenFile(ctx, "", fileHash, &wanted)
	if err != nil {
		t.Fatal(err)
	}
	got, readErr = io.ReadAll(opened.Body)
	closeErr = opened.Body.Close()
	if readErr != nil || closeErr != nil || !bytes.Equal(got, want[wanted.Start:]) {
		t.Fatalf("range stream = %d bytes, read %v, close %v", len(got), readErr, closeErr)
	}
	if opened.Range != (xetcas.FileRange{Start: wanted.Start, End: uint64(len(want))}) ||
		opened.Size != uint64(len(want))-wanted.Start {
		t.Fatalf("range metadata = %#v", opened)
	}

	// An explicit range that covers the complete file receives the same SHA
	// verification guarantee as a nil whole-file range.
	explicitFull := xetcas.FileRange{Start: 0, End: uint64(len(want)) + 1}
	opened, err = service.OpenFile(ctx, "", fileHash, &explicitFull)
	if err != nil {
		t.Fatal(err)
	}
	got, readErr = io.ReadAll(opened.Body)
	_ = opened.Body.Close()
	if readErr != nil || !bytes.Equal(got, want) {
		t.Fatalf("explicit whole stream = %d bytes, %v", len(got), readErr)
	}
	store.mu.Lock()
	key := scopedHash{namespace: "tenant-a", hash: fileHash}
	record := store.files[key]
	record.File.File.SHA256 = &[32]byte{1}
	store.files[key] = record
	store.mu.Unlock()
	opened, err = service.OpenFile(ctx, "", fileHash, &explicitFull)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadAll(opened.Body); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("explicit whole SHA mismatch = %v", err)
	}
	_ = opened.Body.Close()
	partial := xetcas.FileRange{Start: 1, End: 2}
	opened, err = service.OpenFile(ctx, "", fileHash, &partial)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := io.ReadAll(opened.Body); err != nil || !bytes.Equal(got, want[1:2]) {
		t.Fatalf("partial stream with untrusted whole-file SHA = %x, %v", got, err)
	}
	_ = opened.Body.Close()
	afterFirstChunk := xetcas.FileRange{Start: uint64(len(none.Chunks[0].Data)) + 1, End: uint64(len(want))}
	opened, err = service.OpenFile(ctx, "", fileHash, &afterFirstChunk)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := io.ReadAll(opened.Body); err != nil || !bytes.Equal(got, want[afterFirstChunk.Start:]) {
		t.Fatalf("whole-chunk cropped stream = %d bytes, %v", len(got), err)
	}
	_ = opened.Body.Close()

	invalid := xetcas.FileRange{Start: uint64(len(want)), End: uint64(len(want)) + 1}
	if _, err := service.OpenFile(ctx, "", fileHash, &invalid); !errors.Is(err, xetcas.ErrRangeNotSatisfiable) {
		t.Fatalf("range at EOF = %v", err)
	}
	if _, err := service.OpenFile(nil, "", fileHash, nil); err == nil { //nolint:staticcheck // Verify nil-context rejection.
		t.Fatal("nil-context open succeeded")
	}
}

func TestVerifyFileInNamespaceRequiresPhysicalDependencies(t *testing.T) {
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
	fileHash := value.Files[0].Hash
	fileSize := uint64(len(objectContents(none)))
	fileSum := value.Files[0].SHA256
	spy := &availabilityBlobStore{BlobStore: store}
	service.blobs = spy
	if err := service.VerifyFileInNamespace(ctx, "tenant-a", fileHash, fileSize, fileSum); err != nil {
		t.Fatal(err)
	}
	if err := service.VerifyFileInNamespace(ctx, "tenant-a", fileHash, fileSize, nil); err != nil {
		t.Fatalf("optional SHA omitted = %v", err)
	}
	if err := service.VerifyFileInNamespace(ctx, "tenant-a", fileHash, fileSize+1, nil); !errors.Is(err, ErrNotFound) {
		t.Fatalf("wrong required size = %v", err)
	}
	wrongSum := *fileSum
	wrongSum[0] ^= 0xff
	if err := service.VerifyFileInNamespace(ctx, "tenant-a", fileHash, fileSize, &wrongSum); !errors.Is(err, ErrNotFound) {
		t.Fatalf("wrong required SHA-256 = %v", err)
	}
	if spy.heads.Load() < 2 || spy.gets.Load() != 0 {
		t.Fatalf("availability storage calls = %d heads, %d gets", spy.heads.Load(), spy.gets.Load())
	}

	limits := service.registration
	service.registration.MaxTerms = 0
	if err := service.VerifyFileInNamespace(ctx, "tenant-a", fileHash, fileSize, fileSum); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("over-budget availability = %v", err)
	}
	service.registration = limits

	canceled, cancel := context.WithCancel(ctx)
	service.index = cancelingResolveIndex{IndexStore: store, cancel: cancel}
	if err := service.VerifyFileInNamespace(canceled, "tenant-a", fileHash, fileSize, fileSum); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation during final dependency = %v", err)
	}
	service.index = store

	store.mu.Lock()
	xorbKey := BlobKey{Kind: BlobXorb, Hash: none.Hash}
	complete := append([]byte(nil), store.blobs[xorbKey]...)
	store.blobs[xorbKey] = complete[:len(complete)-1]
	store.mu.Unlock()
	if err := service.VerifyFileInNamespace(ctx, "tenant-a", fileHash, fileSize, fileSum); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("wrong physical Xorb size = %v", err)
	}
	store.mu.Lock()
	delete(store.blobs, BlobKey{Kind: BlobXorb, Hash: none.Hash})
	store.mu.Unlock()
	if err := service.VerifyFileInNamespace(ctx, "tenant-a", fileHash, fileSize, fileSum); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing physical Xorb = %v", err)
	}
}

type availabilityBlobStore struct {
	BlobStore
	heads atomic.Int32
	gets  atomic.Int32
}

func (store *availabilityBlobStore) Head(ctx context.Context, key BlobKey) (BlobInfo, bool, error) {
	store.heads.Add(1)
	return store.BlobStore.Head(ctx, key)
}

func (store *availabilityBlobStore) Get(
	ctx context.Context,
	key BlobKey,
	wanted *xetcas.HTTPRange,
) (io.ReadCloser, error) {
	store.gets.Add(1)
	return store.BlobStore.Get(ctx, key, wanted)
}

type cancelingResolveIndex struct {
	IndexStore
	cancel context.CancelFunc
}

func (index cancelingResolveIndex) ResolveSHA256(
	_ context.Context,
	namespace string,
	sum [32]byte,
	size uint64,
) (xethash.Hash, bool, error) {
	hash, found, err := index.IndexStore.ResolveSHA256(context.Background(), namespace, sum, size)
	index.cancel()
	return hash, found, err
}

func TestServiceOpenFileCancellationAndCorruption(t *testing.T) {
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
	fileHash := value.Files[0].Hash

	canceled, cancel := context.WithCancel(ctx)
	opened, err := service.OpenFile(canceled, "", fileHash, nil)
	if err != nil {
		t.Fatal(err)
	}
	cancel()
	if _, err := io.ReadAll(opened.Body); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled stream = %v", err)
	}
	_ = opened.Body.Close()

	backendFailure := errors.New("backend unavailable")
	service.blobs = faultBlobStore{BlobStore: store, getErr: backendFailure}
	opened, err = service.OpenFile(ctx, "", fileHash, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadAll(opened.Body); !errors.Is(err, backendFailure) || errors.Is(err, ErrCorrupt) {
		t.Fatalf("backend get failure = %v", err)
	}
	_ = opened.Body.Close()
	readFailure := errors.New("backend stream failed")
	service.blobs = faultBlobStore{
		BlobStore: store,
		reader:    controlledReadCloser{Reader: failingReader{err: readFailure}},
	}
	opened, err = service.OpenFile(ctx, "", fileHash, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadAll(opened.Body); !errors.Is(err, readFailure) || errors.Is(err, ErrCorrupt) {
		t.Fatalf("backend stream failure = %v", err)
	}
	_ = opened.Body.Close()
	closeFailure := errors.New("backend close failed")
	service.blobs = faultBlobStore{
		BlobStore: store,
		reader:    controlledReadCloser{Reader: bytes.NewReader(none.Body), closeErr: closeFailure},
	}
	opened, err = service.OpenFile(ctx, "", fileHash, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadAll(opened.Body); !errors.Is(err, closeFailure) {
		t.Fatalf("backend close failure = %v", err)
	}
	_ = opened.Body.Close()
	terminalFailure := errors.New("backend terminal read failed")
	service.blobs = faultBlobStore{
		BlobStore: store,
		reader: controlledReadCloser{Reader: terminalErrorReader{
			Reader: bytes.NewReader(none.Body), err: terminalFailure,
		}},
	}
	opened, err = service.OpenFile(ctx, "", fileHash, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadAll(opened.Body); !errors.Is(err, terminalFailure) {
		t.Fatalf("backend terminal failure = %v", err)
	}
	_ = opened.Body.Close()
	service.blobs = faultBlobStore{
		BlobStore: store,
		reader:    io.NopCloser(bytes.NewReader(append(append([]byte(nil), none.Body...), 0))),
	}
	opened, err = service.OpenFile(ctx, "", fileHash, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadAll(opened.Body); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("overlong backend range = %v", err)
	}
	_ = opened.Body.Close()
	service.blobs = store

	key := BlobKey{Kind: BlobXorb, Hash: none.Hash}
	store.mu.Lock()
	original := append([]byte(nil), store.blobs[key]...)
	store.blobs[key][xorb.HeaderSize] ^= 0xff
	store.mu.Unlock()
	opened, err = service.OpenFile(ctx, "", fileHash, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadAll(opened.Body); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("corrupt xorb stream = %v", err)
	}
	_ = opened.Body.Close()

	store.mu.Lock()
	store.blobs[key] = original
	delete(store.blobs, key)
	store.mu.Unlock()
	opened, err = service.OpenFile(ctx, "", fileHash, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadAll(opened.Body); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("missing xorb stream = %v", err)
	}
	_ = opened.Body.Close()
}

func TestServiceOpenEmptyFileMatchesReconstructionRangeSemantics(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()
	service := testService(t, store, nil)
	emptySHA := sha256.Sum256(nil)
	body, err := shard.EncodeUpload(shard.Shard{Files: []shard.File{{Hash: xethash.Zero, SHA256: &emptySHA}}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.UploadShard(ctx, "", bytes.NewReader(body), int64(len(body))); err != nil {
		t.Fatal(err)
	}
	for name, wanted := range map[string]*xetcas.FileRange{
		"whole":                nil,
		"official empty range": {Start: 0, End: 1},
	} {
		t.Run(name, func(t *testing.T) {
			opened, err := service.OpenFile(ctx, "", xethash.Zero, wanted)
			if err != nil {
				t.Fatal(err)
			}
			got, readErr := io.ReadAll(opened.Body)
			closeErr := opened.Body.Close()
			if readErr != nil || closeErr != nil || len(got) != 0 || opened.FileSize != 0 || opened.Size != 0 ||
				opened.Range != (xetcas.FileRange{}) {
				t.Fatalf("empty stream = %#v, %q, %v, %v", opened, got, readErr, closeErr)
			}
		})
	}
}

func TestServiceNamespaceScopesLogicalReachability(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()
	tenantA := testService(t, store, nil)
	none, _, value, shardBody := uploadFixture(t)
	if _, err := tenantA.UploadXorb(ctx, "", xetcas.DefaultXorbPrefix, none.Hash,
		bytes.NewReader(none.Body), int64(len(none.Body))); err != nil {
		t.Fatal(err)
	}
	if _, err := tenantA.UploadShard(ctx, "", bytes.NewReader(shardBody), int64(len(shardBody))); err != nil {
		t.Fatal(err)
	}
	tenantB, err := New(Options{
		Blobs: store, Index: store,
		Signer: RangeURLSignerFunc(func(context.Context, BlobKey, xetcas.HTTPRange) (SignedRange, error) {
			return signedTestRange("https://storage.example/object"), nil
		}),
		Authorizer:         AllowAllAuthorizer{Namespace: "tenant-b"},
		DedupProtectionKey: xethash.Chunk([]byte("namespace test key")),
	})
	if err != nil {
		t.Fatal(err)
	}
	fileHash := value.Files[0].Hash
	if _, err := tenantB.File(ctx, "", fileHash); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-namespace file read = %v", err)
	}
	if _, err := tenantB.OpenFile(ctx, "", fileHash, nil); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-namespace stream = %v", err)
	}
	if _, err := tenantB.OpenFileInNamespace(ctx, "", fileHash, nil); !errors.Is(err, ErrInvalid) {
		t.Fatalf("empty trusted namespace = %v", err)
	}
	if _, err := tenantB.OpenFileInNamespace(ctx, "tenant-a", xethash.Chunk([]byte("missing file")), nil); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing trusted file = %v", err)
	}
	trusted, err := tenantB.OpenFileInNamespace(ctx, "tenant-a", fileHash, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got, readErr := io.ReadAll(trusted.Body); readErr != nil || !bytes.Equal(got, objectContents(none)) {
		t.Fatalf("trusted scoped stream = %d bytes, %v", len(got), readErr)
	}
	if err := trusted.Body.Close(); err != nil {
		t.Fatal(err)
	}
	trustedRange := xetcas.FileRange{Start: 11, End: 127}
	trusted, err = tenantB.OpenFileInNamespace(ctx, "tenant-a", fileHash, &trustedRange)
	if err != nil {
		t.Fatal(err)
	}
	if got, readErr := io.ReadAll(trusted.Body); readErr != nil || !bytes.Equal(got, objectContents(none)[trustedRange.Start:trustedRange.End]) {
		t.Fatalf("trusted scoped range = %d bytes, %v", len(got), readErr)
	}
	if err := trusted.Body.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := tenantB.OpenFileInNamespace(nil, "tenant-a", fileHash, nil); err == nil { //nolint:staticcheck // Verify nil-context rejection.
		t.Fatal("trusted nil-context open succeeded")
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := tenantB.OpenFileInNamespace(canceled, "tenant-a", fileHash, nil); !errors.Is(err, context.Canceled) {
		t.Fatalf("trusted canceled open = %v", err)
	}
	var authorizationCalls atomic.Int64
	trustedOnly, err := New(Options{
		Blobs: store, Index: store,
		Signer: RangeURLSignerFunc(func(context.Context, BlobKey, xetcas.HTTPRange) (SignedRange, error) {
			return signedTestRange("https://storage.example/object"), nil
		}),
		Authorizer: authorizerFunc(func(context.Context, string, AccessRequest) (Grant, error) {
			authorizationCalls.Add(1)
			return Grant{}, ErrForbidden
		}),
		DedupProtectionKey: xethash.Chunk([]byte("trusted bypass test key")),
	})
	if err != nil {
		t.Fatal(err)
	}
	trusted, err = trustedOnly.OpenFileInNamespace(ctx, "tenant-a", fileHash, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got, readErr := io.ReadAll(trusted.Body); readErr != nil || !bytes.Equal(got, objectContents(none)) {
		t.Fatalf("trusted authorization bypass = %d bytes, %v", len(got), readErr)
	}
	if err := trusted.Body.Close(); err != nil {
		t.Fatal(err)
	}
	if got := authorizationCalls.Load(); got != 0 {
		t.Fatalf("trusted open authorization calls = %d", got)
	}
	if _, err := trustedOnly.OpenFile(ctx, "credential", fileHash, nil); !errors.Is(err, ErrForbidden) {
		t.Fatalf("credential open authorization = %v", err)
	}
	if got := authorizationCalls.Load(); got != 1 {
		t.Fatalf("credential open authorization calls = %d", got)
	}
	if _, err := tenantB.GlobalDedup(ctx, "", xetcas.DefaultDedupPrefix, none.Chunks[0].Hash); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-namespace dedup read = %v", err)
	}
	if found, err := tenantB.XorbExists(ctx, "", xetcas.DefaultXorbPrefix, none.Hash); err != nil || !found {
		t.Fatalf("global physical xorb existence = %v, %v", found, err)
	}
	// Publishing a validated shard establishes tenant B's own logical links to
	// the already-durable, globally deduplicated xorb.
	if _, err := tenantB.UploadShard(ctx, "", bytes.NewReader(shardBody), int64(len(shardBody))); err != nil {
		t.Fatal(err)
	}
	opened, err := tenantB.OpenFile(ctx, "", fileHash, nil)
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(opened.Body)
	_ = opened.Body.Close()
	if err != nil || !bytes.Equal(got, objectContents(none)) {
		t.Fatalf("tenant B stream after publication = %d bytes, %v", len(got), err)
	}
}

func TestReconstructionGroupsCoalesceAdjacentTerms(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()
	service := testService(t, store, nil)
	none, _, _, _ := uploadFixture(t)
	if _, err := service.UploadXorb(ctx, "", xetcas.DefaultXorbPrefix, none.Hash,
		bytes.NewReader(none.Body), int64(len(none.Body))); err != nil {
		t.Fatal(err)
	}
	plan := &xetcas.ReconstructionPlan{Terms: []xetcas.ReconstructionTerm{
		{Hash: none.Hash, Range: xetcas.ChunkRange{Start: 0, End: 1}, UnpackedLength: uint32(len(none.Chunks[0].Data))},
		{Hash: none.Hash, Range: xetcas.ChunkRange{Start: 1, End: 3}, UnpackedLength: uint32(len(none.Chunks[1].Data) + len(none.Chunks[2].Data))},
	}}
	groups, err := service.reconstructionGroups(ctx, plan)
	if err != nil {
		t.Fatal(err)
	}
	if len(groups) != 1 || len(groups[0].chunks) != 3 || groups[0].bytes.Start != 0 ||
		groups[0].bytes.End+1 != uint64(len(none.Body)) {
		t.Fatalf("coalesced groups = %#v", groups)
	}
	closedReader, closedWriter := io.Pipe()
	_ = closedReader.Close()
	if err := service.streamReconstruction(ctx, closedWriter, groups, 0, uint64(len(objectContents(none))), false, nil); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("closed destination = %v", err)
	}
	_ = closedWriter.Close()
	unusedReader, unusedWriter := io.Pipe()
	defer func() { _ = unusedReader.Close() }()
	if err := service.streamReconstruction(ctx, unusedWriter, groups, uint64(len(objectContents(none)))+1, 0, false, nil); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("unconsumed reconstruction bytes = %v", err)
	}
	_ = unusedWriter.Close()
}

func TestReconstructionGroupsRejectBrokenLayouts(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()
	service := testService(t, store, nil)
	none, _, _, _ := uploadFixture(t)
	if _, err := service.UploadXorb(ctx, "", xetcas.DefaultXorbPrefix, none.Hash,
		bytes.NewReader(none.Body), int64(len(none.Body))); err != nil {
		t.Fatal(err)
	}
	term := xetcas.ReconstructionTerm{
		Hash: none.Hash, Range: xetcas.ChunkRange{Start: 0, End: 1},
		UnpackedLength: uint32(len(none.Chunks[0].Data)),
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := service.reconstructionGroups(canceled, &xetcas.ReconstructionPlan{Terms: []xetcas.ReconstructionTerm{term}}); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled group planning = %v", err)
	}
	faults := &faultIndex{IndexStore: store, failAt: "get-xorb"}
	service.index = faults
	if _, err := service.reconstructionGroups(ctx, &xetcas.ReconstructionPlan{Terms: []xetcas.ReconstructionTerm{term}}); err == nil {
		t.Fatal("xorb index failure succeeded")
	}
	service.index = store
	missing := term
	missing.Hash = xethash.Chunk([]byte("missing xorb"))
	if _, err := service.reconstructionGroups(ctx, &xetcas.ReconstructionPlan{Terms: []xetcas.ReconstructionTerm{missing}}); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("missing layout = %v", err)
	}
	invalid := term
	invalid.Range.End = uint32(len(none.Chunks)) + 1
	if _, err := service.reconstructionGroups(ctx, &xetcas.ReconstructionPlan{Terms: []xetcas.ReconstructionTerm{invalid}}); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("invalid layout range = %v", err)
	}
	wrongSize := term
	wrongSize.UnpackedLength++
	if _, err := service.reconstructionGroups(ctx, &xetcas.ReconstructionPlan{Terms: []xetcas.ReconstructionTerm{wrongSize}}); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("wrong term size = %v", err)
	}
	store.mu.Lock()
	record := store.xorbs[none.Hash]
	record.Layout.NetworkBytes = 1
	store.xorbs[none.Hash] = record
	store.mu.Unlock()
	if _, err := service.reconstructionGroups(ctx, &xetcas.ReconstructionPlan{Terms: []xetcas.ReconstructionTerm{term}}); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("out-of-bounds serialized layout = %v", err)
	}
}

func TestServiceAuthLimitsAndExistence(t *testing.T) {
	store := NewMemoryStore()
	service, err := New(Options{
		Blobs: store, Index: store,
		Signer: RangeURLSignerFunc(func(context.Context, BlobKey, xetcas.HTTPRange) (SignedRange, error) {
			return signedTestRange("https://storage.example/object"), nil
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

func TestServiceRejectsAmplifiedShardBeforePublication(t *testing.T) {
	store := NewMemoryStore()
	service, err := New(Options{
		Blobs: store, Index: store,
		Signer: RangeURLSignerFunc(func(context.Context, BlobKey, xetcas.HTTPRange) (SignedRange, error) {
			return signedTestRange("https://storage.example/object"), nil
		}),
		Authorizer: AllowAllAuthorizer{},
		RegistrationLimits: shard.RegistrationLimits{
			MaxChunkReferences: 2,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	none, _, value, body := uploadFixture(t)
	if _, err := service.UploadXorb(ctx, "", xetcas.DefaultXorbPrefix, none.Hash,
		bytes.NewReader(none.Body), int64(len(none.Body))); err != nil {
		t.Fatal(err)
	}
	if _, err := service.UploadShard(ctx, "", bytes.NewReader(body), int64(len(body))); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("amplified shard error = %v", err)
	}
	if _, found, err := store.GetFile(ctx, "", value.Files[0].Hash); err != nil || found {
		t.Fatalf("over-budget file publication = %v, %v", found, err)
	}
}

func TestReadPlanningRejectsAmplifiedStoredRecipe(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()
	writer := testService(t, store, nil)
	none, _, value, body := uploadFixture(t)
	if _, err := writer.UploadXorb(ctx, "", xetcas.DefaultXorbPrefix, none.Hash,
		bytes.NewReader(none.Body), int64(len(none.Body))); err != nil {
		t.Fatal(err)
	}
	if _, err := writer.UploadShard(ctx, "", bytes.NewReader(body), int64(len(body))); err != nil {
		t.Fatal(err)
	}
	reader, err := New(Options{
		Blobs: store, Index: store, Authorizer: AllowAllAuthorizer{Namespace: "tenant-a"},
		Signer: RangeURLSignerFunc(func(context.Context, BlobKey, xetcas.HTTPRange) (SignedRange, error) {
			return signedTestRange("https://storage.example/object"), nil
		}),
		RegistrationLimits: shard.RegistrationLimits{MaxChunkReferences: 2},
	})
	if err != nil {
		t.Fatal(err)
	}
	fileHash := value.Files[0].Hash
	if _, err := reader.ReconstructionV2(ctx, "", fileHash, nil); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("v2 amplified recipe = %v", err)
	}
	if _, err := reader.ReconstructionV1(ctx, "", fileHash, nil); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("v1 amplified recipe = %v", err)
	}
	if _, err := reader.FileChunkHashes(ctx, "", fileHash, []xetcas.FileRange{{Start: 0, End: 1}}); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("chunk-hash amplified recipe = %v", err)
	}
}

func TestGlobalFileIndexStillRequiresScopedReadAuthorization(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()
	writer := testService(t, store, nil)
	none, _, value, body := uploadFixture(t)
	if _, err := writer.UploadXorb(ctx, "", xetcas.DefaultXorbPrefix, none.Hash,
		bytes.NewReader(none.Body), int64(len(none.Body))); err != nil {
		t.Fatal(err)
	}
	if _, err := writer.UploadShard(ctx, "", bytes.NewReader(body), int64(len(body))); err != nil {
		t.Fatal(err)
	}

	fileHash := value.Files[0].Hash
	var authorized AccessRequest
	reader, err := New(Options{
		Blobs: store, Index: store,
		Signer: RangeURLSignerFunc(func(context.Context, BlobKey, xetcas.HTTPRange) (SignedRange, error) {
			return signedTestRange("https://storage.example/object"), nil
		}),
		Authorizer: authorizerFunc(func(_ context.Context, credential string, request AccessRequest) (Grant, error) {
			authorized = request
			if credential != "tenant-b" || request.Operation != OperationReadFile || request.Hash == fileHash {
				return Grant{}, ErrForbidden
			}
			return Grant{Namespace: "tenant-b"}, nil
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := reader.ReconstructionV2(ctx, "tenant-b", fileHash, nil); !errors.Is(err, ErrForbidden) {
		t.Fatalf("cross-scope reconstruction = %v", err)
	}
	if authorized.Operation != OperationReadFile || authorized.Hash != fileHash {
		t.Fatalf("authorization request = %#v", authorized)
	}
}

type faultIndex struct {
	IndexStore
	mu     sync.Mutex
	failAt string
}

type protectionFaultIndex struct {
	*MemoryStore
	mu                sync.Mutex
	failAt            string
	stageRenewalCount int
	requireReadLease  bool
}

type blockingLeaseFinalizationIndex struct {
	*MemoryStore
	once     sync.Once
	started  chan struct{}
	release  chan struct{}
	renewals atomic.Int32
}

func (s *blockingLeaseFinalizationIndex) RenewFileLease(
	ctx context.Context,
	namespace string,
	id ProtectionID,
	expiresAt time.Time,
) error {
	first := false
	s.once.Do(func() {
		first = true
		close(s.started)
	})
	if first {
		select {
		case <-s.release:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	s.renewals.Add(1)
	return s.MemoryStore.RenewFileLease(ctx, namespace, id, expiresAt)
}

func (f *protectionFaultIndex) take(name string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failAt == name {
		f.failAt = ""
		return errors.New("injected " + name + " failure")
	}
	return nil
}

func (f *protectionFaultIndex) PutXorb(ctx context.Context, record XorbRecord) error {
	if err := f.take("xorb"); err != nil {
		return err
	}
	return f.MemoryStore.PutXorb(ctx, record)
}

func (f *protectionFaultIndex) requireLeaseBeforeRead() error {
	f.mu.Lock()
	required := f.requireReadLease
	f.mu.Unlock()
	if !required {
		return nil
	}
	f.MemoryStore.mu.RLock()
	defer f.MemoryStore.mu.RUnlock()
	if len(f.leases) == 0 {
		return errors.New("read graph traversed before file lease publication")
	}
	return nil
}

func (f *protectionFaultIndex) GetFile(
	ctx context.Context,
	namespace string,
	hash xethash.Hash,
) (FileRecord, bool, error) {
	if err := f.requireLeaseBeforeRead(); err != nil {
		return FileRecord{}, false, err
	}
	return f.MemoryStore.GetFile(ctx, namespace, hash)
}

func (f *protectionFaultIndex) GetXorb(ctx context.Context, hash xethash.Hash) (XorbRecord, bool, error) {
	if err := f.requireLeaseBeforeRead(); err != nil {
		return XorbRecord{}, false, err
	}
	return f.MemoryStore.GetXorb(ctx, hash)
}

func (f *protectionFaultIndex) PublishShard(ctx context.Context, publication ShardPublication) error {
	if err := f.take("shard"); err != nil {
		return err
	}
	return f.MemoryStore.PublishShard(ctx, publication)
}

func (f *protectionFaultIndex) PutBlobStage(ctx context.Context, stage BlobStage) error {
	if err := f.take("put-stage"); err != nil {
		return err
	}
	return f.MemoryStore.PutBlobStage(ctx, stage)
}

func (f *protectionFaultIndex) DeleteBlobStage(ctx context.Context, namespace string, id ProtectionID) error {
	if err := f.take("delete-stage"); err != nil {
		return err
	}
	return f.MemoryStore.DeleteBlobStage(ctx, namespace, id)
}

func (f *protectionFaultIndex) RenewBlobStage(
	ctx context.Context,
	namespace string,
	id ProtectionID,
	expiresAt time.Time,
) error {
	f.mu.Lock()
	f.stageRenewalCount++
	f.mu.Unlock()
	if err := f.take("renew-stage"); err != nil {
		return err
	}
	return f.MemoryStore.RenewBlobStage(ctx, namespace, id, expiresAt)
}

func (f *protectionFaultIndex) PutFileLease(ctx context.Context, lease FileLease) error {
	if err := f.take("put-lease"); err != nil {
		return err
	}
	return f.MemoryStore.PutFileLease(ctx, lease)
}

func (f *protectionFaultIndex) RenewFileLease(
	ctx context.Context,
	namespace string,
	id ProtectionID,
	expiresAt time.Time,
) error {
	if err := f.take("renew-lease"); err != nil {
		return err
	}
	return f.MemoryStore.RenewFileLease(ctx, namespace, id, expiresAt)
}

func (f *protectionFaultIndex) DeleteFileLease(ctx context.Context, namespace string, id ProtectionID) error {
	if err := f.take("delete-lease"); err != nil {
		return err
	}
	return f.MemoryStore.DeleteFileLease(ctx, namespace, id)
}

func TestServicePublicationStagesAndReadLeases(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()
	faults := &protectionFaultIndex{MemoryStore: store, failAt: "xorb"}
	service := testService(t, store, faults)
	none, _, value, shardBody := uploadFixture(t)

	if _, err := service.UploadXorb(ctx, "", xetcas.DefaultXorbPrefix, none.Hash,
		bytes.NewReader(none.Body), int64(len(none.Body))); err == nil {
		t.Fatal("injected Xorb publication failure succeeded")
	}
	stages, err := store.ListBlobStages(ctx, nil, PageRequest{})
	if err != nil || len(stages.Items) != 1 || stages.Items[0].Blob != (BlobKey{Kind: BlobXorb, Hash: none.Hash}) ||
		stages.Items[0].Namespace != "tenant-a" {
		t.Fatalf("failed Xorb stages = %#v, %v", stages, err)
	}
	if _, found, err := store.Head(ctx, stages.Items[0].Blob); err != nil || !found {
		t.Fatalf("staged Xorb blob = %v, %v", found, err)
	}
	if _, err := service.UploadXorb(ctx, "", xetcas.DefaultXorbPrefix, none.Hash,
		bytes.NewReader(none.Body), int64(len(none.Body))); err != nil {
		t.Fatal(err)
	}
	stages, err = store.ListBlobStages(ctx, nil, PageRequest{})
	if err != nil || len(stages.Items) != 1 {
		t.Fatalf("repaired Xorb stages = %#v, %v", stages, err)
	}
	if err := store.DeleteBlobStage(ctx, stages.Items[0].Namespace, stages.Items[0].ID); err != nil {
		t.Fatal(err)
	}

	service.stagingTTL = 15 * time.Millisecond
	service.now = time.Now
	service.blobs = faultBlobStore{BlobStore: store, delay: 25 * time.Millisecond}
	renewedBody, err := shard.EncodeUpload(shard.Shard{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.UploadShard(ctx, "", bytes.NewReader(renewedBody), int64(len(renewedBody))); err != nil {
		t.Fatalf("publication with a renewed stage = %v", err)
	}
	faults.mu.Lock()
	renewalCount := faults.stageRenewalCount
	faults.mu.Unlock()
	if renewalCount == 0 {
		t.Fatal("slow publication did not renew its stage")
	}
	faults.failAt = "renew-stage"
	if _, err := service.UploadShard(ctx, "", bytes.NewReader(renewedBody), int64(len(renewedBody))); err == nil ||
		!strings.Contains(err.Error(), "renew blob stage") {
		t.Fatalf("publication after stage renewal failure = %v", err)
	}
	service.blobs = store
	service.stagingTTL = defaultStagingProtectionTTL
	service.now = func() time.Time { return time.Unix(1_000, 0) }
	stages, err = store.ListBlobStages(ctx, nil, PageRequest{})
	if err != nil || len(stages.Items) != 1 {
		t.Fatalf("stage after renewal failure = %#v, %v", stages, err)
	}
	if err := store.DeleteBlobStage(ctx, stages.Items[0].Namespace, stages.Items[0].ID); err != nil {
		t.Fatal(err)
	}

	faults.failAt = "shard"
	if _, err := service.UploadShard(ctx, "", bytes.NewReader(shardBody), int64(len(shardBody))); err == nil {
		t.Fatal("injected shard publication failure succeeded")
	}
	stages, err = store.ListBlobStages(ctx, nil, PageRequest{})
	if err != nil || len(stages.Items) != 1 || stages.Items[0].Blob.Kind != BlobShard {
		t.Fatalf("failed shard stages = %#v, %v", stages, err)
	}
	if _, err := service.UploadShard(ctx, "", bytes.NewReader(shardBody), int64(len(shardBody))); err != nil {
		t.Fatal(err)
	}
	if err := store.DeleteBlobStage(ctx, stages.Items[0].Namespace, stages.Items[0].ID); err != nil {
		t.Fatal(err)
	}

	faults.failAt = "put-stage"
	unstaged, err := xorb.Encode([][]byte{[]byte("must not publish without a stage")}, xorb.None)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.UploadXorb(ctx, "", xetcas.DefaultXorbPrefix, unstaged.Hash,
		bytes.NewReader(unstaged.Body), int64(len(unstaged.Body))); err == nil {
		t.Fatal("upload without durable stage succeeded")
	}
	if _, found, err := store.Head(ctx, BlobKey{Kind: BlobXorb, Hash: unstaged.Hash}); err != nil || found {
		t.Fatalf("blob after failed staging = %v, %v", found, err)
	}
	faults.failAt = "delete-stage"
	stale, err := xorb.Encode([][]byte{[]byte("published with stale stage")}, xorb.None)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.UploadXorb(ctx, "", xetcas.DefaultXorbPrefix, stale.Hash,
		bytes.NewReader(stale.Body), int64(len(stale.Body))); err == nil {
		t.Fatal("upload with failed stage release succeeded")
	}
	if found, err := service.XorbExists(ctx, "", xetcas.DefaultXorbPrefix, stale.Hash); err != nil || !found {
		t.Fatalf("indexed Xorb after failed stage release = %v, %v", found, err)
	}
	stages, err = store.ListBlobStages(ctx, nil, PageRequest{})
	if err != nil || len(stages.Items) != 1 || stages.Items[0].Blob.Hash != stale.Hash {
		t.Fatalf("stage after failed release = %#v, %v", stages, err)
	}
	if err := store.DeleteBlobStage(ctx, stages.Items[0].Namespace, stages.Items[0].ID); err != nil {
		t.Fatal(err)
	}

	fileHash := value.Files[0].Hash
	faults.mu.Lock()
	faults.requireReadLease = true
	faults.mu.Unlock()
	signedExpiry := service.now().Add(5 * time.Minute)
	service.signer = RangeURLSignerFunc(func(context.Context, BlobKey, xetcas.HTTPRange) (SignedRange, error) {
		return SignedRange{
			URL:       "https://storage.example/object",
			ExpiresAt: time.Unix(0, int64(^uint64(0)>>1)).Add(-time.Minute),
		}, nil
	})
	if _, err := service.ReconstructionV2(ctx, "", fileHash, nil); !errors.Is(err, ErrInvalid) {
		t.Fatalf("signed URL whose lease grace overflows = %v", err)
	}
	service.signer = RangeURLSignerFunc(func(context.Context, BlobKey, xetcas.HTTPRange) (SignedRange, error) {
		if err := faults.requireLeaseBeforeRead(); err != nil {
			return SignedRange{}, err
		}
		return SignedRange{URL: "https://storage.example/object", ExpiresAt: signedExpiry}, nil
	})
	if _, err := service.ReconstructionV2(ctx, "", fileHash, nil); err != nil {
		t.Fatal(err)
	}
	leases, err := store.ListFileLeases(ctx, nil, PageRequest{})
	if err != nil || len(leases.Items) != 1 || leases.Items[0].Namespace != "tenant-a" || leases.Items[0].File != fileHash {
		t.Fatalf("detached reconstruction leases = %#v, %v", leases, err)
	}
	if want := signedExpiry.Add(service.readLeaseTTL); !leases.Items[0].ExpiresAt.Equal(want) {
		t.Fatalf("signed reconstruction lease expires at %v, want %v", leases.Items[0].ExpiresAt, want)
	}
	if err := store.DeleteFileLease(ctx, leases.Items[0].Namespace, leases.Items[0].ID); err != nil {
		t.Fatal(err)
	}
	if _, err := service.ReconstructionV2(ctx, "", xethash.Chunk([]byte("missing protected file")), nil); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing file reconstruction = %v", err)
	}
	if _, err := service.OpenFile(ctx, "", xethash.Chunk([]byte("missing protected stream")), nil); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing file stream = %v", err)
	}
	leases, err = store.ListFileLeases(ctx, nil, PageRequest{})
	if err != nil || len(leases.Items) != 0 {
		t.Fatalf("provisional leases after failed planning = %#v, %v", leases, err)
	}
	if _, err := service.FileChunkHashes(ctx, "", fileHash, []xetcas.FileRange{{Start: 0, End: 1}}); err != nil {
		t.Fatalf("protected chunk-hash plan = %v", err)
	}
	leases, err = store.ListFileLeases(ctx, nil, PageRequest{})
	if err != nil || len(leases.Items) != 0 {
		t.Fatalf("leases after chunk-hash planning = %#v, %v", leases, err)
	}
	faults.failAt = "delete-lease"
	if _, err := service.FileChunkHashes(ctx, "", fileHash, []xetcas.FileRange{{Start: 0, End: 1}}); err == nil ||
		!strings.Contains(err.Error(), "release file read lease") {
		t.Fatalf("chunk-hash lease cleanup failure = %v", err)
	}
	leases, err = store.ListFileLeases(ctx, nil, PageRequest{})
	if err != nil || len(leases.Items) != 1 {
		t.Fatalf("lease after failed chunk-hash cleanup = %#v, %v", leases, err)
	}
	if err := store.DeleteFileLease(ctx, leases.Items[0].Namespace, leases.Items[0].ID); err != nil {
		t.Fatal(err)
	}
	opened, err := service.OpenFile(ctx, "", fileHash, nil)
	if err != nil {
		t.Fatal(err)
	}
	leases, err = store.ListFileLeases(ctx, nil, PageRequest{})
	if err != nil || len(leases.Items) != 1 {
		t.Fatalf("active read leases = %#v, %v", leases, err)
	}
	if err := opened.Body.Close(); err != nil {
		t.Fatal(err)
	}
	leases, err = store.ListFileLeases(ctx, nil, PageRequest{})
	if err != nil || len(leases.Items) != 0 {
		t.Fatalf("leases after active read close = %#v, %v", leases, err)
	}

	faults.failAt = "put-lease"
	if _, err := service.ReconstructionV1(ctx, "", fileHash, nil); err == nil {
		t.Fatal("signed reconstruction without lease succeeded")
	}
	faults.failAt = "put-lease"
	if _, err := service.OpenFile(ctx, "", fileHash, nil); err == nil {
		t.Fatal("typed stream without lease succeeded")
	}
	faults.failAt = "renew-lease"
	if _, err := service.ReconstructionV1(ctx, "", fileHash, nil); err == nil ||
		!strings.Contains(err.Error(), "finalize signed reconstruction lease") {
		t.Fatalf("signed reconstruction after final lease renewal failure = %v", err)
	}
	leases, err = store.ListFileLeases(ctx, nil, PageRequest{})
	if err != nil || len(leases.Items) != 0 {
		t.Fatalf("leases after failed signed-lease finalization = %#v, %v", leases, err)
	}
	faults.failAt = "delete-lease"
	opened, err = service.OpenFile(ctx, "", fileHash, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadAll(opened.Body); err == nil {
		t.Fatal("read with failed lease release succeeded")
	}
	_ = opened.Body.Close()
	faults.failAt = "delete-lease"
	opened, err = service.OpenFile(ctx, "", fileHash, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := opened.Body.Close(); err == nil || !strings.Contains(err.Error(), "release file read lease") {
		t.Fatalf("early close after failed lease release = %v", err)
	}

	leases, err = store.ListFileLeases(ctx, nil, PageRequest{})
	if err != nil {
		t.Fatal(err)
	}
	staleLeaseCount := len(leases.Items)
	faults.failAt = "renew-lease"
	service.readLeaseTTL = 30 * time.Millisecond
	opened, err = service.OpenFile(ctx, "", fileHash, nil)
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Second)
	for {
		leases, err = store.ListFileLeases(ctx, nil, PageRequest{})
		if err != nil {
			t.Fatal(err)
		}
		if len(leases.Items) == staleLeaseCount {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("lease renewal failure did not settle unread stream")
		}
		time.Sleep(5 * time.Millisecond)
	}
	if _, err := io.ReadAll(opened.Body); err == nil || !strings.Contains(err.Error(), "renew file read lease") {
		t.Fatalf("read after lease renewal failure = %v", err)
	}
	if err := opened.Body.Close(); err == nil || !strings.Contains(err.Error(), "renew file read lease") {
		t.Fatalf("close after lease renewal failure = %v", err)
	}
}

func TestTypedStreamRetainsCombinedReadAndCloseFailures(t *testing.T) {
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
	closeFailure := errors.New("injected Xorb close failure")
	service.blobs = &getOverrideBlobStore{
		BlobStore: store,
		get: func(context.Context, BlobKey, *xetcas.HTTPRange) (io.ReadCloser, error) {
			return &faultReadCloser{Reader: bytes.NewReader([]byte{0xff}), closeErr: closeFailure}, nil
		},
	}
	opened, err := service.OpenFile(ctx, "", value.Files[0].Hash, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = io.ReadAll(opened.Body); !errors.Is(err, ErrCorrupt) || !errors.Is(err, closeFailure) {
		t.Fatalf("combined stream failure = %v", err)
	}
	if err = opened.Body.Close(); !errors.Is(err, ErrCorrupt) || !errors.Is(err, closeFailure) {
		t.Fatalf("combined close failure = %v", err)
	}
}

func TestSignedLeaseFinalizationKeepsHeartbeatActive(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()
	index := &blockingLeaseFinalizationIndex{
		MemoryStore: store, started: make(chan struct{}), release: make(chan struct{}),
	}
	service := testService(t, store, index)
	service.readLeaseTTL = 30 * time.Millisecond
	service.now = time.Now
	none, _, value, shardBody := uploadFixture(t)
	if _, err := service.UploadXorb(ctx, "", xetcas.DefaultXorbPrefix, none.Hash,
		bytes.NewReader(none.Body), int64(len(none.Body))); err != nil {
		t.Fatal(err)
	}
	if _, err := service.UploadShard(ctx, "", bytes.NewReader(shardBody), int64(len(shardBody))); err != nil {
		t.Fatal(err)
	}
	service.signer = RangeURLSignerFunc(func(context.Context, BlobKey, xetcas.HTTPRange) (SignedRange, error) {
		return SignedRange{URL: "https://storage.example/object", ExpiresAt: time.Now().Add(time.Minute)}, nil
	})
	result := make(chan error, 1)
	go func() {
		_, err := service.ReconstructionV2(ctx, "", value.Files[0].Hash, nil)
		result <- err
	}()
	select {
	case <-index.started:
	case <-time.After(time.Second):
		t.Fatal("signed lease finalization did not start")
	}
	time.Sleep(45 * time.Millisecond)
	leases, err := store.ListFileLeases(ctx, nil, PageRequest{})
	if err != nil || len(leases.Items) != 1 || !leases.Items[0].ExpiresAt.After(time.Now()) || index.renewals.Load() == 0 {
		t.Fatalf("lease while finalization blocked = %#v, renewals %d, %v", leases, index.renewals.Load(), err)
	}
	close(index.release)
	if err := <-result; err != nil {
		t.Fatal(err)
	}
	leases, err = store.ListFileLeases(ctx, nil, PageRequest{})
	if err != nil || len(leases.Items) != 1 {
		t.Fatalf("detached lease after finalization = %#v, %v", leases, err)
	}
	if err := store.DeleteFileLease(ctx, leases.Items[0].Namespace, leases.Items[0].ID); err != nil {
		t.Fatal(err)
	}
}

func TestCancelReadCloserReturnsSettledStreamError(t *testing.T) {
	reader, writer := io.Pipe()
	defer writer.Close() //nolint:errcheck // Test cleanup.
	ctx, cancel := context.WithCancelCause(context.Background())
	settlement := &openFileSettlement{done: make(chan struct{})}
	streamError := fmt.Errorf("%w: settled before close", ErrCorrupt)
	settlement.finish(streamError, nil)
	body := &cancelReadCloser{PipeReader: reader, ctx: ctx, cancel: cancel, settlement: settlement}
	if err := body.Close(); !errors.Is(err, streamError) {
		t.Fatalf("close after settled stream error = %v", err)
	}
}

type getOverrideBlobStore struct {
	BlobStore
	get func(context.Context, BlobKey, *xetcas.HTTPRange) (io.ReadCloser, error)
}

func (store *getOverrideBlobStore) Get(ctx context.Context, key BlobKey, wanted *xetcas.HTTPRange) (io.ReadCloser, error) {
	return store.get(ctx, key, wanted)
}

type faultReadCloser struct {
	io.Reader
	closeErr error
}

func (reader *faultReadCloser) Close() error { return reader.closeErr }

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
func (f *faultIndex) GetFile(ctx context.Context, namespace string, hash xethash.Hash) (FileRecord, bool, error) {
	if err := f.take("get-file"); err != nil {
		return FileRecord{}, false, err
	}
	return f.IndexStore.GetFile(ctx, namespace, hash)
}
func (f *faultIndex) GetDedup(ctx context.Context, namespace string, hash xethash.Hash) (DedupRecord, bool, error) {
	if err := f.take("get-dedup"); err != nil {
		return DedupRecord{}, false, err
	}
	return f.IndexStore.GetDedup(ctx, namespace, hash)
}
func (f *faultIndex) PutDedup(ctx context.Context, namespace string, hash xethash.Hash, value DedupRecord) error {
	if err := f.take("dedup"); err != nil {
		return err
	}
	return f.IndexStore.PutDedup(ctx, namespace, hash, value)
}
func (f *faultIndex) PutSHA256(ctx context.Context, namespace string, sum [32]byte, size uint64, hash xethash.Hash) error {
	if err := f.take("sha"); err != nil {
		return err
	}
	return f.IndexStore.PutSHA256(ctx, namespace, sum, size, hash)
}
func (f *faultIndex) PutFile(ctx context.Context, namespace string, value FileRecord) error {
	if err := f.take("file"); err != nil {
		return err
	}
	return f.IndexStore.PutFile(ctx, namespace, value)
}

func (f *faultIndex) PublishShard(ctx context.Context, publication ShardPublication) error {
	for _, stage := range []string{"dedup", "sha", "file"} {
		if err := f.take(stage); err != nil {
			return err
		}
	}
	return f.IndexStore.PublishShard(ctx, publication)
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
	if _, found, err := store.GetFile(ctx, "tenant-a", value.Files[0].Hash); err != nil || found {
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
	if err := store.PutDedup(context.Background(), "scope", chunk, first); err != nil {
		t.Fatal(err)
	}
	if err := store.PutDedup(context.Background(), "scope", chunk, second); err != nil {
		t.Fatalf("second valid dedup source conflicted: %v", err)
	}
	got, found, err := store.GetDedup(context.Background(), "scope", chunk)
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
	if err := store.PutFile(context.Background(), "scope", first); err != nil {
		t.Fatal(err)
	}
	if err := store.PutFile(context.Background(), "scope", second); err != nil {
		t.Fatalf("second valid file recipe conflicted: %v", err)
	}
	got, found, err := store.GetFile(context.Background(), "scope", hash)
	if err != nil || !found || !reflect.DeepEqual(got, first) {
		t.Fatalf("file record = %#v, %v, %v; want first recipe %#v", got, found, err, first)
	}
}
