package server

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/jmwoliver/xet-go/shard"
	"github.com/jmwoliver/xet-go/xetcas"
	"github.com/jmwoliver/xet-go/xethash"
	"github.com/jmwoliver/xet-go/xorb"
)

type failingReader struct{ err error }

func (r failingReader) Read([]byte) (int, error) { return 0, r.err }

type controlledReadCloser struct {
	io.Reader
	closeErr error
}

func (r controlledReadCloser) Close() error { return r.closeErr }

type terminalErrorReader struct {
	io.Reader
	err error
}

func (r terminalErrorReader) Read(data []byte) (int, error) {
	n, err := r.Reader.Read(data)
	if errors.Is(err, io.EOF) {
		return n, r.err
	}
	return n, err
}

type faultBlobStore struct {
	BlobStore
	putErr error
	getErr error
	reader io.ReadCloser
	delay  time.Duration
}

func (s faultBlobStore) PutIfAbsent(ctx context.Context, key BlobKey, body io.Reader, size int64) (bool, error) {
	if s.delay != 0 && key.Kind == BlobShard {
		select {
		case <-time.After(s.delay):
		case <-ctx.Done():
			return false, ctx.Err()
		}
	}
	if s.putErr != nil {
		return false, s.putErr
	}
	return s.BlobStore.PutIfAbsent(ctx, key, body, size)
}

func (s faultBlobStore) Get(ctx context.Context, key BlobKey, wanted *xetcas.HTTPRange) (io.ReadCloser, error) {
	if s.getErr != nil {
		return nil, s.getErr
	}
	if s.reader != nil {
		return s.reader, nil
	}
	return s.BlobStore.Get(ctx, key, wanted)
}

func TestNewServiceValidationAndDefaults(t *testing.T) {
	store := NewMemoryStore()
	signer := RangeURLSignerFunc(func(context.Context, BlobKey, xetcas.HTTPRange) (SignedRange, error) {
		return signedTestRange("x"), nil
	})
	base := Options{Blobs: store, Index: store, Signer: signer, Authorizer: AllowAllAuthorizer{}}
	for name, mutate := range map[string]func(*Options){
		"missing dependency": func(value *Options) { value.Signer = nil },
		"short dedup TTL":    func(value *Options) { value.DedupTTL = time.Millisecond },
		"zero xorb limit":    func(value *Options) { value.MaxXorbBody = -1 },
		"large xorb limit":   func(value *Options) { value.MaxXorbBody = xorb.MaxNetworkSize + 1 },
		"zero shard limit":   func(value *Options) { value.MaxShardBody = -1 },
		"large shard limit":  func(value *Options) { value.MaxShardBody = shard.MaxSize + 1 },
		"negative ingests":   func(value *Options) { value.MaxConcurrentIngests = -1 },
		"short staging TTL":  func(value *Options) { value.StagingProtectionTTL = time.Second },
		"short read TTL":     func(value *Options) { value.ReadLeaseTTL = time.Second },
		"missing protection store": func(value *Options) {
			value.Index = &faultIndex{IndexStore: store}
			value.ReadLeaseTTL = time.Minute
		},
	} {
		t.Run(name, func(t *testing.T) {
			options := base
			mutate(&options)
			if _, err := New(options); err == nil {
				t.Fatal("invalid options succeeded")
			}
		})
	}
	service, err := New(base)
	if err != nil {
		t.Fatal(err)
	}
	if service.now == nil || service.dedupKey.IsZero() || service.dedupTTL != time.Hour ||
		service.maxXorb != xorb.MaxNetworkSize || service.maxShard != shard.MaxSize ||
		service.registration.MaxFiles != defaultMaxRegistrationFiles ||
		service.registration.MaxXorbs != defaultMaxRegistrationXorbs ||
		service.registration.MaxTerms != defaultMaxRegistrationTerms ||
		service.registration.MaxChunkReferences != defaultMaxRegistrationChunkRefs ||
		cap(service.ingestSlots) != defaultMaxConcurrentIngests ||
		service.shardHeartbeat != defaultShardHeartbeat || service.protections != store ||
		service.stagingTTL != defaultStagingProtectionTTL || service.readLeaseTTL != defaultReadLeaseTTL {
		t.Fatalf("defaults = %#v", service)
	}

	release, err := service.acquireIngest(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	service.ingestSlots <- struct{}{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := service.acquireIngest(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("ingest admission cancellation = %v", err)
	}
	<-service.ingestSlots
	release()
}

func TestMemoryStoreBlobContractsAndClonesIndexes(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()
	chunkHash := xethash.Chunk([]byte("chunk"))
	key := BlobKey{Kind: BlobXorb, Hash: xethash.Xorb([]xethash.Node{{Hash: chunkHash, Size: 5}})}
	wantRead := errors.New("read failed")
	for name, body := range map[string]struct {
		body   io.Reader
		size   int64
		target error
	}{
		"nil":      {nil, 0, nil},
		"negative": {bytes.NewReader(nil), -1, nil},
		"reader":   {failingReader{wantRead}, 1, wantRead},
		"short":    {bytes.NewReader([]byte("x")), 2, nil},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := store.PutIfAbsent(ctx, key, body.body, body.size); err == nil ||
				(body.target != nil && !errors.Is(err, body.target)) {
				t.Fatalf("PutIfAbsent error = %v", err)
			}
		})
	}
	inserted, err := store.PutIfAbsent(ctx, key, bytes.NewReader([]byte("body")), 4)
	if err != nil || !inserted {
		t.Fatalf("insert = %v, %v", inserted, err)
	}
	if inserted, err := store.PutIfAbsent(ctx, key, bytes.NewReader([]byte("body")), 4); err != nil || inserted {
		t.Fatalf("idempotent insert = %v, %v", inserted, err)
	}
	if _, err := store.PutIfAbsent(ctx, key, bytes.NewReader([]byte("evil")), 4); !errors.Is(err, ErrConflict) {
		t.Fatalf("blob conflict = %v", err)
	}
	if _, err := store.Get(ctx, BlobKey{Kind: BlobXorb, Hash: xethash.Zero}, nil); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing blob = %v", err)
	}
	for _, wanted := range []xetcas.HTTPRange{{Start: 2, End: 1}, {Start: 0, End: 4}} {
		if _, err := store.Get(ctx, key, &wanted); !errors.Is(err, xetcas.ErrRangeNotSatisfiable) {
			t.Fatalf("bad range %#v = %v", wanted, err)
		}
	}
	reader, err := store.Get(ctx, key, &xetcas.HTTPRange{Start: 1, End: 2})
	if err != nil {
		t.Fatal(err)
	}
	data, _ := io.ReadAll(reader)
	_ = reader.Close()
	if string(data) != "od" {
		t.Fatalf("range = %q", data)
	}

	layout := xorb.Ingested{
		Hash: key.Hash, NetworkBytes: 15, UncompressedSize: 5,
		Chunks: []xorb.IngestedChunk{{Hash: chunkHash, SerializedLength: 15, UncompressedLength: 5}},
	}
	xorbRecord := XorbRecord{Blob: key, Layout: layout}
	if err := store.PutXorb(ctx, xorbRecord); err != nil {
		t.Fatal(err)
	}
	layout.Chunks[0].UncompressedLength++
	gotXorb, found, err := store.GetXorb(ctx, key.Hash)
	if err != nil || !found || gotXorb.Layout.Chunks[0].UncompressedLength != 5 {
		t.Fatalf("cloned xorb = %#v, %v, %v", gotXorb, found, err)
	}
	conflictingXorb := gotXorb
	conflictingXorb.Layout.Chunks[0].SerializedLength++
	conflictingXorb.Layout.NetworkBytes++
	if err := store.PutXorb(ctx, conflictingXorb); !errors.Is(err, ErrConflict) {
		t.Fatalf("xorb conflict = %v", err)
	}

	fileHash := xethash.Chunk([]byte("file"))
	sum := [32]byte{7}
	fileRecord := FileRecord{File: shard.RegisteredFile{File: shard.File{
		Hash: fileHash, SHA256: &sum, Terms: []shard.Term{{XorbHash: key.Hash, Start: 0, End: 1}},
	}, Size: 5}, Shard: BlobKey{Kind: BlobShard, Hash: xethash.Chunk([]byte("file shard"))}}
	if err := store.PutFile(ctx, "scope", fileRecord); err != nil {
		t.Fatal(err)
	}
	fileRecord.File.File.Terms[0].End = 2
	*fileRecord.File.File.SHA256 = [32]byte{9}
	gotFile, found, err := store.GetFile(ctx, "scope", fileHash)
	if err != nil || !found || gotFile.File.File.Terms[0].End != 1 || *gotFile.File.File.SHA256 != ([32]byte{7}) {
		t.Fatalf("cloned file = %#v, %v, %v", gotFile, found, err)
	}
	conflictingFile := gotFile
	conflictingFile.File.Size++
	if err := store.PutFile(ctx, "scope", conflictingFile); err != nil {
		t.Fatalf("alternative file record = %v", err)
	}
	retained, found, err := store.GetFile(ctx, "scope", fileHash)
	if err != nil || !found || !reflect.DeepEqual(retained, gotFile) {
		t.Fatalf("retained file = %#v, %v, %v; want %#v", retained, found, err, gotFile)
	}
	sum = [32]byte{7}
	if err := store.PutSHA256(ctx, "scope", sum, 5, fileHash); err != nil {
		t.Fatal(err)
	}
	if err := store.PutSHA256(ctx, "scope", sum, 5, xethash.Zero); !errors.Is(err, ErrConflict) {
		t.Fatalf("SHA conflict = %v", err)
	}
	if got, found, err := store.ResolveSHA256(ctx, "scope", sum, 5); err != nil || !found || got != fileHash {
		t.Fatalf("SHA resolve = %s, %v, %v", got, found, err)
	}
}

func TestMemoryStorePublishesShardIndexesAtomically(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()
	fileHash := xethash.Chunk([]byte("atomic file"))
	chunkHash := xethash.Chunk([]byte("atomic chunk"))
	sum := sha256.Sum256([]byte("atomic bytes"))
	shardKey := BlobKey{Kind: BlobShard, Hash: xethash.Chunk([]byte("shard"))}
	publication := ShardPublication{
		Namespace: "scope",
		Shard:     shardKey,
		Dedup: []DedupAssociation{{
			Chunk: chunkHash,
			Value: DedupRecord{Shard: shardKey},
		}},
		SHA256: []SHA256Association{
			{Sum: sum, Size: 12, File: fileHash},
			{Sum: sum, Size: 12, File: xethash.Chunk([]byte("conflict"))},
		},
		Files: []FileRecord{{File: shard.RegisteredFile{File: shard.File{Hash: fileHash}, Size: 12}, Shard: shardKey}},
	}
	if err := store.PublishShard(ctx, publication); !errors.Is(err, ErrConflict) {
		t.Fatalf("conflicting publication = %v", err)
	}
	if _, found, err := store.GetDedup(ctx, "scope", chunkHash); err != nil || found {
		t.Fatalf("dedup visible after rollback = %v, %v", found, err)
	}
	if _, found, err := store.GetFile(ctx, "scope", fileHash); err != nil || found {
		t.Fatalf("file visible after rollback = %v, %v", found, err)
	}
	publication.SHA256 = publication.SHA256[:1]
	if err := store.PublishShard(ctx, publication); err != nil {
		t.Fatal(err)
	}
	if err := store.PublishShard(ctx, publication); err != nil {
		t.Fatalf("idempotent publication = %v", err)
	}
	if got, found, err := store.ResolveSHA256(ctx, "scope", sum, 12); err != nil || !found || got != fileHash {
		t.Fatalf("published SHA = %s, %v, %v", got, found, err)
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if err := store.PublishShard(canceled, ShardPublication{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled publication = %v", err)
	}
}

func TestServiceRepairsAlternateXorbAfterIndexFailure(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()
	faults := &faultIndex{IndexStore: store, failAt: "xorb"}
	service := testService(t, store, faults)
	none, compressed, _, _ := uploadFixture(t)
	if _, err := service.UploadXorb(ctx, "", xetcas.DefaultXorbPrefix, none.Hash,
		bytes.NewReader(none.Body), int64(len(none.Body))); err == nil {
		t.Fatal("injected publication failure succeeded")
	}
	inserted, err := service.UploadXorb(ctx, "", xetcas.DefaultXorbPrefix, compressed.Hash,
		bytes.NewReader(compressed.Body), int64(len(compressed.Body)))
	if err != nil || inserted {
		t.Fatalf("alternate representation repair = %v, %v", inserted, err)
	}
	record, found, err := store.GetXorb(ctx, none.Hash)
	if err != nil || !found || record.Layout.NetworkBytes != uint32(len(none.Body)) {
		t.Fatalf("repaired canonical layout = %#v, %v, %v", record, found, err)
	}

	broken := NewMemoryStore()
	brokenService := testService(t, broken, nil)
	key := BlobKey{Kind: BlobXorb, Hash: none.Hash}
	if _, err := broken.PutIfAbsent(ctx, key, bytes.NewReader([]byte("broken")), 6); err != nil {
		t.Fatal(err)
	}
	if _, err := brokenService.UploadXorb(ctx, "", xetcas.DefaultXorbPrefix, none.Hash,
		bytes.NewReader(none.Body), int64(len(none.Body))); err == nil {
		t.Fatal("invalid stored representation repaired")
	}
}

func TestServiceValidationAndReadFailures(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()
	service := testService(t, store, nil)
	none, _, value, uploadBody := uploadFixture(t)
	if _, err := service.UploadXorb(ctx, "", "bad", none.Hash, bytes.NewReader(none.Body), int64(len(none.Body))); !errors.Is(err, ErrNotFound) {
		t.Fatalf("bad xorb prefix = %v", err)
	}
	if _, err := service.UploadXorb(ctx, "", xetcas.DefaultXorbPrefix, none.Hash, bytes.NewReader([]byte("bad")), 3); !errors.Is(err, ErrInvalid) {
		t.Fatalf("invalid xorb = %v", err)
	}
	if found, err := service.XorbExists(ctx, "", "bad", none.Hash); err != nil || found {
		t.Fatalf("bad-prefix existence = %v, %v", found, err)
	}
	if _, err := service.UploadShard(ctx, "", bytes.NewReader([]byte("bad")), 3); !errors.Is(err, ErrInvalid) {
		t.Fatalf("invalid shard = %v", err)
	}
	full, err := shard.EncodeFull(value)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.UploadShard(ctx, "", bytes.NewReader(full), int64(len(full))); !errors.Is(err, ErrInvalid) {
		t.Fatalf("full upload shard = %v", err)
	}
	if _, err := service.UploadShard(ctx, "", bytes.NewReader(uploadBody), int64(len(uploadBody))); !errors.Is(err, ErrInvalid) {
		t.Fatalf("missing xorb registration = %v", err)
	}
	if _, err := readBounded(nil, 0, 1); err == nil {
		t.Fatal("nil body succeeded")
	}
	if _, err := readBounded(bytes.NewReader([]byte("xx")), 2, 1); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("declared too large = %v", err)
	}
	if _, err := readBounded(failingReader{errors.New("read")}, -1, 1); err == nil {
		t.Fatal("read error succeeded")
	}
	if _, err := readBounded(bytes.NewReader([]byte("xx")), -1, 1); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("stream too large = %v", err)
	}
	if _, err := readBounded(bytes.NewReader([]byte("x")), 2, 2); !errors.Is(err, ErrInvalid) {
		t.Fatalf("declared mismatch = %v", err)
	}

	if _, err := service.File(ctx, "", value.Files[0].Hash); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing file = %v", err)
	}
	if _, err := service.GlobalDedup(ctx, "", "bad", xethash.Zero); !errors.Is(err, ErrNotFound) {
		t.Fatalf("bad dedup prefix = %v", err)
	}
	if _, err := service.GlobalDedup(ctx, "", xetcas.DefaultDedupPrefix, xethash.Zero); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing dedup = %v", err)
	}
}

func TestValidateRecipeWorkRejectsAmplifiedAndMalformedRecipes(t *testing.T) {
	service := &Service{registration: shard.RegistrationLimits{MaxTerms: 1, MaxChunkReferences: 2}}
	if err := service.validateRecipeWork(context.Background(), shard.RegisteredFile{File: shard.File{Terms: []shard.Term{{}, {}}}}); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("term limit error = %v", err)
	}
	if err := service.validateRecipeWork(context.Background(), shard.RegisteredFile{File: shard.File{Terms: []shard.Term{{Start: 2, End: 1}}}}); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("reversed stored range = %v", err)
	}
	if err := service.validateRecipeWork(context.Background(), shard.RegisteredFile{File: shard.File{Terms: []shard.Term{{Start: 0, End: 3}}}}); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("chunk reference limit error = %v", err)
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := service.validateRecipeWork(canceled, shard.RegisteredFile{File: shard.File{Terms: []shard.Term{{}}}}); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled recipe validation = %v", err)
	}
}

func TestInjectedStorageIndexAndSignerFailuresPropagate(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()
	faults := &faultIndex{IndexStore: store}
	service := testService(t, store, faults)
	none, _, value, uploadBody := uploadFixture(t)

	faults.failAt = "get-xorb"
	if _, err := service.UploadXorb(ctx, "", xetcas.DefaultXorbPrefix, none.Hash,
		bytes.NewReader(none.Body), int64(len(none.Body))); err == nil {
		t.Fatal("xorb index read failure succeeded")
	}
	putFailure := errors.New("blob put failed")
	service.blobs = faultBlobStore{BlobStore: store, putErr: putFailure}
	if _, err := service.UploadXorb(ctx, "", xetcas.DefaultXorbPrefix, none.Hash,
		bytes.NewReader(none.Body), int64(len(none.Body))); !errors.Is(err, putFailure) {
		t.Fatalf("xorb blob failure = %v", err)
	}
	service.blobs = store
	if _, err := service.UploadXorb(ctx, "", xetcas.DefaultXorbPrefix, none.Hash,
		bytes.NewReader(none.Body), int64(len(none.Body))); err != nil {
		t.Fatal(err)
	}
	faults.failAt = "get-xorb"
	if _, err := service.UploadShard(ctx, "", bytes.NewReader(uploadBody), int64(len(uploadBody))); err == nil || errors.Is(err, ErrInvalid) || !errors.Is(err, shard.ErrXorbLookup) {
		t.Fatalf("registration index failure = %v", err)
	}
	service.blobs = faultBlobStore{BlobStore: store, putErr: putFailure}
	if _, err := service.UploadShard(ctx, "", bytes.NewReader(uploadBody), int64(len(uploadBody))); !errors.Is(err, putFailure) {
		t.Fatalf("shard blob failure = %v", err)
	}
	service.blobs = store
	for _, failAt := range []string{"dedup", "sha", "file"} {
		faults.failAt = failAt
		if _, err := service.UploadShard(ctx, "", bytes.NewReader(uploadBody), int64(len(uploadBody))); err == nil {
			t.Fatalf("injected %s publication failure succeeded", failAt)
		}
	}
	if _, err := service.UploadShard(ctx, "", bytes.NewReader(uploadBody), int64(len(uploadBody))); err != nil {
		t.Fatal(err)
	}

	faults.failAt = "get-file"
	if _, err := service.File(ctx, "", value.Files[0].Hash); err == nil {
		t.Fatal("file index read failure succeeded")
	}
	faults.failAt = "get-file"
	if _, err := service.BatchReconstructionV1(ctx, "", []xethash.Hash{value.Files[0].Hash}); err == nil {
		t.Fatal("batch index read failure succeeded")
	}
	faults.failAt = "get-xorb"
	if _, err := service.ReconstructionV2(ctx, "", value.Files[0].Hash, nil); err == nil {
		t.Fatal("v2 layout read failure succeeded")
	}
	faults.failAt = "get-xorb"
	if _, err := service.ReconstructionV1(ctx, "", value.Files[0].Hash, nil); err == nil {
		t.Fatal("v1 layout read failure succeeded")
	}

	signFailure := errors.New("sign failed")
	service.signer = RangeURLSignerFunc(func(context.Context, BlobKey, xetcas.HTTPRange) (SignedRange, error) {
		return SignedRange{}, signFailure
	})
	if _, err := service.ReconstructionV2(ctx, "", value.Files[0].Hash, nil); !errors.Is(err, signFailure) {
		t.Fatalf("v2 signer failure = %v", err)
	}
	if _, err := service.ReconstructionV1(ctx, "", value.Files[0].Hash, nil); !errors.Is(err, signFailure) {
		t.Fatalf("v1 signer failure = %v", err)
	}
	service.signer = RangeURLSignerFunc(func(context.Context, BlobKey, xetcas.HTTPRange) (SignedRange, error) {
		return SignedRange{}, nil
	})
	if _, err := service.ReconstructionV2(ctx, "", value.Files[0].Hash, nil); err == nil {
		t.Fatal("invalid signed URL succeeded")
	}
	for name, expiresAt := range map[string]time.Time{
		"expired":      service.now(),
		"out of range": time.Date(3000, time.January, 1, 0, 0, 0, 0, time.UTC),
	} {
		t.Run("signed URL "+name, func(t *testing.T) {
			service.signer = RangeURLSignerFunc(func(context.Context, BlobKey, xetcas.HTTPRange) (SignedRange, error) {
				return SignedRange{URL: "https://storage.example/object", ExpiresAt: expiresAt}, nil
			})
			if _, err := service.ReconstructionV2(ctx, "", value.Files[0].Hash, nil); !errors.Is(err, ErrInvalid) {
				t.Fatalf("invalid signed URL expiration = %v", err)
			}
		})
	}
	faults.failAt = "get-dedup"
	if _, err := service.GlobalDedup(ctx, "", xetcas.DefaultDedupPrefix, none.Chunks[0].Hash); err == nil {
		t.Fatal("dedup index read failure succeeded")
	}
	readFailure := errors.New("blob read failed")
	service.blobs = faultBlobStore{BlobStore: store, reader: controlledReadCloser{Reader: failingReader{readFailure}}}
	if _, err := service.GlobalDedup(ctx, "", xetcas.DefaultDedupPrefix, none.Chunks[0].Hash); !errors.Is(err, readFailure) {
		t.Fatalf("dedup blob read failure = %v", err)
	}
	closeFailure := errors.New("blob close failed")
	service.blobs = faultBlobStore{BlobStore: store, reader: controlledReadCloser{Reader: bytes.NewReader([]byte("x")), closeErr: closeFailure}}
	if _, err := service.GlobalDedup(ctx, "", xetcas.DefaultDedupPrefix, none.Chunks[0].Hash); !errors.Is(err, closeFailure) {
		t.Fatalf("dedup blob close failure = %v", err)
	}
	service.blobs = faultBlobStore{BlobStore: store, reader: io.NopCloser(bytes.NewReader([]byte("invalid")))}
	if _, err := service.GlobalDedup(ctx, "", xetcas.DefaultDedupPrefix, none.Chunks[0].Hash); err == nil {
		t.Fatal("invalid dedup shard decoded")
	}
}

func TestLayoutRepairReaderAndIdentityFailures(t *testing.T) {
	service := testService(t, NewMemoryStore(), nil)
	key := BlobKey{Kind: BlobXorb, Hash: xethash.Chunk([]byte("expected"))}
	getFailure := errors.New("get failed")
	service.blobs = faultBlobStore{BlobStore: service.blobs, getErr: getFailure}
	if _, err := service.layoutFromStoredXorb(context.Background(), key, key.Hash); !errors.Is(err, getFailure) {
		t.Fatalf("get failure = %v", err)
	}
	readFailure := errors.New("read failed")
	service.blobs = faultBlobStore{BlobStore: service.blobs, reader: controlledReadCloser{Reader: failingReader{readFailure}}}
	if _, err := service.layoutFromStoredXorb(context.Background(), key, key.Hash); !errors.Is(err, readFailure) {
		t.Fatalf("read failure = %v", err)
	}
	closeFailure := errors.New("close failed")
	service.blobs = faultBlobStore{BlobStore: service.blobs, reader: controlledReadCloser{Reader: bytes.NewReader([]byte("invalid")), closeErr: closeFailure}}
	if _, err := service.layoutFromStoredXorb(context.Background(), key, key.Hash); !errors.Is(err, closeFailure) {
		t.Fatalf("close failure = %v", err)
	}
	object, err := xorb.Encode([][]byte{[]byte("content")}, xorb.None)
	if err != nil {
		t.Fatal(err)
	}
	service.blobs = faultBlobStore{BlobStore: service.blobs, reader: io.NopCloser(bytes.NewReader(object.Body))}
	if _, err := service.layoutFromStoredXorb(context.Background(), key, key.Hash); !errors.Is(err, ErrConflict) {
		t.Fatalf("footerless stored xorb = %v", err)
	}
	complete, err := xorb.EncodeComplete(object, [4]byte{})
	if err != nil {
		t.Fatal(err)
	}
	service.blobs = faultBlobStore{BlobStore: service.blobs, reader: io.NopCloser(bytes.NewReader(complete))}
	if _, err := service.layoutFromStoredXorb(context.Background(), key, key.Hash); !errors.Is(err, ErrConflict) {
		t.Fatalf("stored xorb identity mismatch = %v", err)
	}
}

func TestGlobalDedupRejectsBrokenDurableStateAndClock(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()
	service := testService(t, store, nil)
	none, _, value, uploadBody := uploadFixture(t)
	if _, err := service.UploadXorb(ctx, "", xetcas.DefaultXorbPrefix, none.Hash,
		bytes.NewReader(none.Body), int64(len(none.Body))); err != nil {
		t.Fatal(err)
	}
	if _, err := service.UploadShard(ctx, "", bytes.NewReader(uploadBody), int64(len(uploadBody))); err != nil {
		t.Fatal(err)
	}
	dedup, found, err := store.GetDedup(ctx, "tenant-a", none.Chunks[0].Hash)
	if err != nil || !found {
		t.Fatalf("dedup record = %#v, %v, %v", dedup, found, err)
	}
	store.mu.Lock()
	original := append([]byte(nil), store.blobs[dedup.Shard]...)
	delete(store.blobs, dedup.Shard)
	store.mu.Unlock()
	if _, err := service.GlobalDedup(ctx, "", xetcas.DefaultDedupPrefix, none.Chunks[0].Hash); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing shard blob = %v", err)
	}
	store.mu.Lock()
	store.blobs[dedup.Shard] = append([]byte(nil), uploadBody...)
	store.mu.Unlock()
	if _, err := service.GlobalDedup(ctx, "", xetcas.DefaultDedupPrefix, none.Chunks[0].Hash); err == nil ||
		!strings.Contains(err.Error(), "footerless") {
		t.Fatalf("footerless durable shard = %v", err)
	}
	store.mu.Lock()
	store.blobs[dedup.Shard] = original
	store.mu.Unlock()
	service.now = func() time.Time { return time.Unix(-1, 0) }
	if _, err := service.GlobalDedup(ctx, "", xetcas.DefaultDedupPrefix, none.Chunks[0].Hash); err == nil ||
		!strings.Contains(err.Error(), "precedes") {
		t.Fatalf("negative clock = %v", err)
	}

	// A file whose first term points outside the embedded xorb set must not
	// contribute file-start eligibility to a protected shard source.
	filtered := dedupSource(shard.Shard{Files: []shard.File{{}, value.Files[0]}, Xorbs: nil})
	if len(filtered.Files) != 0 {
		t.Fatalf("dedup source retained unrelated files: %#v", filtered.Files)
	}
}

func TestHandlerValidationStatusesAndParsers(t *testing.T) {
	service := testService(t, NewMemoryStore(), nil)
	handler := service.Handler()
	hash := xethash.Chunk([]byte("missing")).String()
	requests := []struct {
		name    string
		method  string
		path    string
		body    string
		headers map[string]string
		status  int
	}{
		{"unknown", http.MethodGet, "/unknown", "", nil, http.StatusNotFound},
		{"bad hash", http.MethodGet, "/v2/reconstructions/nope", "", nil, http.StatusBadRequest},
		{"missing v1", http.MethodGet, "/v1/reconstructions/" + hash, "", nil, http.StatusNotFound},
		{"bad v1 range", http.MethodGet, "/v1/reconstructions/" + hash, "", map[string]string{"Range": "bytes=2-1"}, http.StatusBadRequest},
		{"missing head", http.MethodHead, "/v1/files/" + hash, "", nil, http.StatusNotFound},
		{"bad xorb", http.MethodPost, "/v1/xorbs/default/" + hash, "bad", nil, http.StatusBadRequest},
		{"missing xorb", http.MethodHead, "/v1/xorbs/default/" + hash, "", nil, http.StatusNotFound},
		{"bad shard v1", http.MethodPost, "/v1/shards", "bad", nil, http.StatusBadRequest},
		{"batch syntax", http.MethodPost, "/v1/reconstructions", "{", nil, http.StatusBadRequest},
		{"batch values", http.MethodPost, "/v1/reconstructions", "[] []", nil, http.StatusBadRequest},
		{"batch prefix", http.MethodPost, "/v1/reconstructions", `[{"prefix":"bad","hash":"` + hash + `"}]`, nil, http.StatusBadRequest},
		{"batch GET hash", http.MethodGet, "/v1/reconstructions?file_id=nope", "", nil, http.StatusBadRequest},
		{"batch GET query escape", http.MethodGet, "/v1/reconstructions?file_id=%gh", "", nil, http.StatusBadRequest},
		{"batch GET missing", http.MethodGet, "/v1/reconstructions?file_id=" + hash, "", nil, http.StatusOK},
		{"batch GET empty", http.MethodGet, "/v1/reconstructions", "", nil, http.StatusOK},
		{"dirty missing", http.MethodGet, "/v2/file-chunk-hashes/" + hash, "", nil, http.StatusBadRequest},
		{"dirty overlap", http.MethodGet, "/v2/file-chunk-hashes/" + hash, "", map[string]string{xetcas.DirtyRangeHeader: "bytes=0-2,2-3"}, http.StatusBadRequest},
		{"dirty missing file", http.MethodGet, "/v2/file-chunk-hashes/" + hash, "", map[string]string{xetcas.DirtyRangeHeader: "bytes=0-1"}, http.StatusNotFound},
	}
	for _, test := range requests {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(test.method, test.path, strings.NewReader(test.body))
			for key, value := range test.headers {
				request.Header.Set(key, value)
			}
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != test.status {
				t.Fatalf("status = %d, want %d; body %q", response.Code, test.status, response.Body.String())
			}
		})
	}
	large := httptest.NewRequest(http.MethodPost, "/v1/reconstructions", bytes.NewReader(make([]byte, maxBatchRequestBody+1)))
	largeResponse := httptest.NewRecorder()
	handler.ServeHTTP(largeResponse, large)
	if largeResponse.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("large batch status = %d", largeResponse.Code)
	}
	keys := make([]xetcas.Key, 10_001)
	for i := range keys {
		keys[i] = xetcas.Key{Prefix: xetcas.DefaultFilePrefix, Hash: xethash.Zero}
	}
	body, _ := json.Marshal(keys)
	tooMany := httptest.NewRequest(http.MethodPost, "/v1/reconstructions", bytes.NewReader(body))
	tooManyResponse := httptest.NewRecorder()
	handler.ServeHTTP(tooManyResponse, tooMany)
	if tooManyResponse.Code != http.StatusBadRequest {
		t.Fatalf("large batch count status = %d, body size %d", tooManyResponse.Code, len(body))
	}
	query := make(url.Values)
	query["file_id"] = make([]string, 10_001)
	tooManyGET := httptest.NewRequest(http.MethodGet, "/v1/reconstructions?"+query.Encode(), nil)
	tooManyGETResponse := httptest.NewRecorder()
	handler.ServeHTTP(tooManyGETResponse, tooManyGET)
	if tooManyGETResponse.Code != http.StatusBadRequest {
		t.Fatalf("large GET batch count status = %d", tooManyGETResponse.Code)
	}
	faultStore := NewMemoryStore()
	faults := &faultIndex{IndexStore: faultStore, failAt: "get-file"}
	faultService := testService(t, faultStore, faults)
	faultResponse := httptest.NewRecorder()
	faultService.Handler().ServeHTTP(faultResponse,
		httptest.NewRequest(http.MethodGet, "/v1/reconstructions?file_id="+hash, nil))
	if faultResponse.Code != http.StatusInternalServerError {
		t.Fatalf("batch index failure status = %d", faultResponse.Code)
	}

	for _, value := range []string{"", "units=0-1", "bytes=-1", "bytes=0-", "bytes=x-1", "bytes=0-x", "bytes=0-18446744073709551615"} {
		if _, err := parseRanges(value); err == nil {
			t.Fatalf("invalid range %q succeeded", value)
		}
	}
	if ranges, err := parseRanges(" BYTES = 0-0 , 2-3"); err != nil || len(ranges) != 2 || ranges[1].End != 4 {
		t.Fatalf("parsed ranges = %#v, %v", ranges, err)
	}
	if _, err := parseOptionalRange("bytes=0-0,2-2"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("multi reconstruction range = %v", err)
	}
	if credential, err := bearerCredential("bEaReR token"); err != nil || credential != "token" {
		t.Fatalf("bearer = %q, %v", credential, err)
	}
}

func TestHandlerErrorMappingAndStreamingShardEvents(t *testing.T) {
	for name, value := range map[string]struct {
		err    error
		status int
	}{
		"unauthorized": {ErrUnauthorized, http.StatusUnauthorized},
		"forbidden":    {ErrForbidden, http.StatusForbidden},
		"not found":    {ErrNotFound, http.StatusNotFound},
		"range":        {xetcas.ErrRangeNotSatisfiable, http.StatusRequestedRangeNotSatisfiable},
		"too large":    {ErrTooLarge, http.StatusRequestEntityTooLarge},
		"conflict":     {ErrConflict, http.StatusConflict},
		"invalid":      {ErrInvalid, http.StatusBadRequest},
		"lookup marker precedence": {
			fmt.Errorf("%w: %w", shard.ErrXorbLookup, ErrNotFound), http.StatusInternalServerError,
		},
		"internal": {errors.New("internal"), http.StatusInternalServerError},
	} {
		t.Run(name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, "/", nil)
			response := httptest.NewRecorder()
			writeServerError(response, request, value.err)
			if response.Code != value.status {
				t.Fatalf("status = %d, want %d", response.Code, value.status)
			}
			if value.status == http.StatusUnauthorized && response.Header().Get("WWW-Authenticate") != "Bearer" {
				t.Fatal("unauthorized response lacks challenge")
			}
		})
	}
	head := httptest.NewRecorder()
	writeServerError(head, httptest.NewRequest(http.MethodHead, "/", nil), ErrConflict)
	if head.Code != http.StatusConflict || head.Body.Len() != 0 {
		t.Fatalf("HEAD error = %d %q", head.Code, head.Body.String())
	}

	service := testService(t, NewMemoryStore(), nil)
	service.shardHeartbeat = time.Millisecond
	invalid := httptest.NewRecorder()
	service.Handler().ServeHTTP(invalid, httptest.NewRequest(http.MethodPost, "/v2/shards", strings.NewReader("bad")))
	if invalid.Code != http.StatusOK || !strings.Contains(invalid.Body.String(), `"type":"error"`) {
		t.Fatalf("v2 terminal error = %d %q", invalid.Code, invalid.Body.String())
	}
}

func TestHandlerShardHeartbeatSuccessAndEarlyFailures(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()
	service := testService(t, store, nil)
	none, _, _, uploadBody := uploadFixture(t)
	if _, err := service.UploadXorb(ctx, "", xetcas.DefaultXorbPrefix, none.Hash,
		bytes.NewReader(none.Body), int64(len(none.Body))); err != nil {
		t.Fatal(err)
	}

	v1 := httptest.NewRecorder()
	service.Handler().ServeHTTP(v1, httptest.NewRequest(http.MethodPost, "/v1/shards", bytes.NewReader(uploadBody)))
	if v1.Code != http.StatusOK || !strings.Contains(v1.Body.String(), `"result":1`) {
		t.Fatalf("v1 inserted response = %d %q", v1.Code, v1.Body.String())
	}

	service.blobs = faultBlobStore{BlobStore: store, delay: 15 * time.Millisecond}
	service.shardHeartbeat = time.Millisecond
	v2 := httptest.NewRecorder()
	service.Handler().ServeHTTP(v2, httptest.NewRequest(http.MethodPost, "/v2/shards", bytes.NewReader(uploadBody)))
	if v2.Code != http.StatusOK || !strings.Contains(v2.Body.String(), `"type":"result"`) ||
		strings.Count(v2.Body.String(), `"type":"validating"`) < 3 {
		t.Fatalf("v2 heartbeat response = %d %q", v2.Code, v2.Body.String())
	}

	secure, err := New(Options{
		Blobs: store, Index: store,
		Signer: RangeURLSignerFunc(func(context.Context, BlobKey, xetcas.HTTPRange) (SignedRange, error) {
			return signedTestRange("x"), nil
		}),
		Authorizer:         StaticTokenAuthorizer{Token: "secret"},
		DedupProtectionKey: xethash.Chunk([]byte("key")),
		MaxShardBody:       1,
	})
	if err != nil {
		t.Fatal(err)
	}
	for name, method := range map[string]struct {
		method string
		path   string
		token  string
		body   string
		status int
	}{
		"head authorization": {http.MethodHead, "/v1/xorbs/default/" + none.Hash.String(), "wrong", "", http.StatusForbidden},
		"v2 authorization":   {http.MethodPost, "/v2/shards", "wrong", "x", http.StatusForbidden},
		"v2 body limit":      {http.MethodPost, "/v2/shards", "secret", "xx", http.StatusRequestEntityTooLarge},
	} {
		t.Run(name, func(t *testing.T) {
			request := httptest.NewRequest(method.method, method.path, strings.NewReader(method.body))
			request.Header.Set("Authorization", "Bearer "+method.token)
			response := httptest.NewRecorder()
			secure.Handler().ServeHTTP(response, request)
			if response.Code != method.status {
				t.Fatalf("status = %d, want %d", response.Code, method.status)
			}
		})
	}
}

func TestServiceAuthorizationLimitsAndExistingConflict(t *testing.T) {
	store := NewMemoryStore()
	service, err := New(Options{
		Blobs: store, Index: store,
		Signer: RangeURLSignerFunc(func(context.Context, BlobKey, xetcas.HTTPRange) (SignedRange, error) {
			return signedTestRange("x"), nil
		}),
		Authorizer:         StaticTokenAuthorizer{Token: "secret"},
		DedupProtectionKey: xethash.Chunk([]byte("key")),
		MaxShardBody:       1,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	none, _, _, _ := uploadFixture(t)
	if _, err := service.UploadShard(ctx, "", strings.NewReader("x"), 1); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("shard authorization = %v", err)
	}
	if _, err := service.UploadShard(ctx, "secret", strings.NewReader("xx"), 2); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("shard body limit = %v", err)
	}
	if _, err := service.UploadXorb(ctx, "secret", xetcas.DefaultXorbPrefix, none.Hash,
		bytes.NewReader(none.Body), int64(len(none.Body))); err != nil {
		t.Fatal(err)
	}
	store.mu.Lock()
	record := store.xorbs[none.Hash]
	record.Layout.UncompressedSize++
	store.xorbs[none.Hash] = record
	store.mu.Unlock()
	if _, err := service.UploadXorb(ctx, "secret", xetcas.DefaultXorbPrefix, none.Hash,
		bytes.NewReader(none.Body), int64(len(none.Body))); !errors.Is(err, ErrConflict) {
		t.Fatalf("existing layout conflict = %v", err)
	}
	if _, err := service.XorbExists(ctx, "wrong", xetcas.DefaultXorbPrefix, none.Hash); !errors.Is(err, ErrForbidden) {
		t.Fatalf("existence authorization = %v", err)
	}
	if _, err := service.GlobalDedup(ctx, "wrong", xetcas.DefaultDedupPrefix, none.Chunks[0].Hash); !errors.Is(err, ErrForbidden) {
		t.Fatalf("dedup authorization = %v", err)
	}
}

func TestDecodeBoundedJSONFailures(t *testing.T) {
	var destination map[string]any
	if err := decodeBoundedJSON(failingReader{errors.New("read")}, 10, &destination); err == nil {
		t.Fatal("JSON read failure succeeded")
	}
	if err := decodeBoundedJSON(strings.NewReader(`{"unknown":1}`), 20, &struct {
		Known int `json:"known"`
	}{}); err == nil {
		t.Fatal("unknown JSON field succeeded")
	}
	if err := decodeBoundedJSON(bytes.NewReader(make([]byte, 2)), 1, &destination); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("large JSON = %v", err)
	}
}

func TestSameLayoutEveryIdentityField(t *testing.T) {
	base := &xorb.Ingested{Hash: xethash.Chunk([]byte("x")), UncompressedSize: 2, Chunks: []xorb.IngestedChunk{{
		Hash: xethash.Chunk([]byte("c")), UncompressedOffset: 1, UncompressedLength: 1,
	}}}
	if sameLayout(nil, base) || sameLayout(base, nil) || !sameLayout(base, base) {
		t.Fatal("nil/equal layout comparison differs")
	}
	mutations := []func(*xorb.Ingested){
		func(value *xorb.Ingested) { value.Hash = xethash.Zero },
		func(value *xorb.Ingested) { value.UncompressedSize++ },
		func(value *xorb.Ingested) { value.Chunks = nil },
		func(value *xorb.Ingested) { value.Chunks[0].Hash = xethash.Zero },
		func(value *xorb.Ingested) { value.Chunks[0].UncompressedOffset++ },
		func(value *xorb.Ingested) { value.Chunks[0].UncompressedLength++ },
	}
	for _, mutate := range mutations {
		copyValue := *base
		copyValue.Chunks = append([]xorb.IngestedChunk(nil), base.Chunks...)
		mutate(&copyValue)
		if sameLayout(base, &copyValue) {
			t.Fatalf("different layout accepted: %#v", copyValue)
		}
	}
	if _, err := readBounded(bytes.NewReader(nil), math.MaxInt64, 1); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("maximum declared body = %v", err)
	}
}
