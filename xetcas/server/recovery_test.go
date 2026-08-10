package server

import (
	"bytes"
	"context"
	"errors"
	"io"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jmwoliver/xet-go/shard"
	"github.com/jmwoliver/xet-go/xetcas"
	"github.com/jmwoliver/xet-go/xethash"
	"github.com/jmwoliver/xet-go/xorb"
)

func newRecoveryService(
	t testing.TB,
	blobs BlobStore,
	index IndexStore,
) (*Service, *atomic.Int32) {
	t.Helper()
	var authorizationCalls atomic.Int32
	service, err := New(Options{
		Blobs: blobs, Index: index,
		Signer: RangeURLSignerFunc(func(context.Context, BlobKey, xetcas.HTTPRange) (SignedRange, error) {
			return signedTestRange("https://storage.example/recovery"), nil
		}),
		Authorizer: authorizerFunc(func(context.Context, string, AccessRequest) (Grant, error) {
			authorizationCalls.Add(1)
			return Grant{}, ErrForbidden
		}),
		DedupProtectionKey: xethash.Chunk([]byte("recovery dedup key")),
	})
	if err != nil {
		t.Fatal(err)
	}
	return service, &authorizationCalls
}

func putRecoveryStage(
	t testing.TB,
	store ProtectionStore,
	id ProtectionID,
	namespace string,
	key BlobKey,
	createdAt, expiresAt time.Time,
) BlobStage {
	t.Helper()
	stage := BlobStage{
		ID: id, Namespace: namespace, Blob: key,
		CreatedAt: createdAt, ExpiresAt: expiresAt,
	}
	if err := store.PutBlobStage(context.Background(), stage); err != nil {
		t.Fatal(err)
	}
	return stage
}

func recoveryFixture(
	t testing.TB,
) (*xorb.Ingested, BlobKey, []byte, BlobKey, shard.Shard) {
	t.Helper()
	_, network, logicalShard, _ := uploadFixture(t)
	ingested, err := xorb.IngestNetwork(network.Body, network.Hash)
	if err != nil {
		t.Fatal(err)
	}
	xorbKey := BlobKey{Kind: BlobXorb, Hash: network.Hash}
	fullShard, err := shard.EncodeFull(logicalShard)
	if err != nil {
		t.Fatal(err)
	}
	shardKey := BlobKey{Kind: BlobShard, Hash: xethash.Chunk(fullShard)}
	return ingested, xorbKey, fullShard, shardKey, logicalShard
}

type recoveryBlobSpy struct {
	BlobStore
	puts atomic.Int32
}

func (s *recoveryBlobSpy) PutIfAbsent(
	ctx context.Context,
	key BlobKey,
	body io.Reader,
	size int64,
) (bool, error) {
	s.puts.Add(1)
	return s.BlobStore.PutIfAbsent(ctx, key, body, size)
}

func TestServiceRecoversExpiredXorbThenBlockedShard(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()
	ingested, xorbKey, fullShard, shardKey, logicalShard := recoveryFixture(t)
	if inserted, err := store.PutIfAbsent(
		ctx, xorbKey, bytes.NewReader(ingested.Complete), int64(len(ingested.Complete)),
	); err != nil || !inserted {
		t.Fatalf("put recovery xorb = %v, %v", inserted, err)
	}
	if inserted, err := store.PutIfAbsent(
		ctx, shardKey, bytes.NewReader(fullShard), int64(len(fullShard)),
	); err != nil || !inserted {
		t.Fatalf("put recovery shard = %v, %v", inserted, err)
	}
	cutoff := time.Date(2026, time.August, 10, 18, 0, 0, 0, time.UTC)
	createdAt := cutoff.Add(-2 * time.Hour)
	shardStage := putRecoveryStage(
		t, store, testProtectionID(1), "tenant", shardKey, createdAt, cutoff.Add(-2*time.Minute),
	)
	xorbStage := putRecoveryStage(
		t, store, testProtectionID(2), "tenant", xorbKey, createdAt, cutoff.Add(-time.Minute),
	)
	spy := &recoveryBlobSpy{BlobStore: store}
	service, authorizationCalls := newRecoveryService(t, spy, store)

	page, err := service.RecoverExpiredBlobStages(ctx, cutoff, PageRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Items) != 2 || page.Items[0].Stage != shardStage || page.Items[0].Status != BlobStageRecoveryBlocked ||
		!errors.Is(page.Items[0].Err, shard.ErrXorbNotFound) || page.Items[1].Stage != xorbStage ||
		page.Items[1].Status != BlobStageRecoveryPublishedRemoved || page.Items[1].Err != nil {
		t.Fatalf("first recovery page = %#v", page)
	}
	if _, found, err := store.GetXorb(ctx, xorbKey.Hash); err != nil || !found {
		t.Fatalf("recovered xorb index = %v, %v", found, err)
	}
	stages, err := store.ListBlobStages(ctx, nil, PageRequest{})
	if err != nil || len(stages.Items) != 1 || stages.Items[0] != shardStage {
		t.Fatalf("stages after xorb recovery = %#v, %v", stages, err)
	}

	page, err = service.RecoverExpiredBlobStages(ctx, cutoff, PageRequest{})
	if err != nil || len(page.Items) != 1 || page.Items[0].Status != BlobStageRecoveryPublishedRemoved {
		t.Fatalf("second recovery page = %#v, %v", page, err)
	}
	file, found, err := store.GetFile(ctx, "tenant", logicalShard.Files[0].Hash)
	if err != nil || !found || file.Shard != shardKey {
		t.Fatalf("recovered shard file = %#v, %v, %v", file, found, err)
	}
	if registered, found, err := store.GetShard(ctx, "tenant", shardKey.Hash); err != nil || !found || registered.Blob != shardKey {
		t.Fatalf("recovered shard registration = %#v, %v, %v", registered, found, err)
	}
	if logicalShard.Files[0].SHA256 == nil {
		t.Fatal("fixture lacks SHA-256")
	}
	if hash, found, err := store.ResolveSHA256(
		ctx, "tenant", *logicalShard.Files[0].SHA256, file.File.Size,
	); err != nil || !found || hash != logicalShard.Files[0].Hash {
		t.Fatalf("recovered shard SHA = %s, %v, %v", hash, found, err)
	}
	if stages, err := store.ListBlobStages(ctx, nil, PageRequest{}); err != nil || len(stages.Items) != 0 {
		t.Fatalf("stages after recovery = %#v, %v", stages, err)
	}
	if spy.puts.Load() != 0 {
		t.Fatalf("recovery performed %d blob writes", spy.puts.Load())
	}
	if authorizationCalls.Load() != 0 {
		t.Fatalf("recovery performed %d authorization calls", authorizationCalls.Load())
	}
}

type staticRecoveryBlobStore struct {
	info    BlobInfo
	found   bool
	headErr error
	getErr  error
	reader  func() io.ReadCloser
}

func (s *staticRecoveryBlobStore) PutIfAbsent(context.Context, BlobKey, io.Reader, int64) (bool, error) {
	return false, errors.New("unexpected blob write")
}

func (s *staticRecoveryBlobStore) Head(context.Context, BlobKey) (BlobInfo, bool, error) {
	return s.info, s.found, s.headErr
}

func (s *staticRecoveryBlobStore) Get(context.Context, BlobKey, *xetcas.HTTPRange) (io.ReadCloser, error) {
	if s.getErr != nil {
		return nil, s.getErr
	}
	return s.reader(), nil
}

type recoveryFaultReader struct {
	readErr, closeErr error
}

func (r recoveryFaultReader) Read([]byte) (int, error) { return 0, r.readErr }
func (r recoveryFaultReader) Close() error             { return r.closeErr }

type cancelOnCloseReader struct {
	*bytes.Reader
	cancel context.CancelFunc
}

func (r cancelOnCloseReader) Close() error {
	r.cancel()
	return nil
}

func TestServiceRecoveryRetainsMissingCorruptAndFailedStages(t *testing.T) {
	cutoff := time.Date(2026, time.August, 10, 19, 0, 0, 0, time.UTC)
	key := BlobKey{Kind: BlobXorb, Hash: xethash.Chunk([]byte("recovery read classifications"))}
	sentinel := errors.New("backend failure")
	for _, test := range []struct {
		name       string
		blobs      *staticRecoveryBlobStore
		wantStatus BlobStageRecoveryStatus
		wantPhase  BlobStageRecoveryPhase
		wantError  error
	}{
		{
			name: "missing at head", blobs: &staticRecoveryBlobStore{},
			wantStatus: BlobStageRecoveryMissing, wantPhase: BlobStageRecoveryHead,
		},
		{
			name: "head backend failure", blobs: &staticRecoveryBlobStore{headErr: sentinel},
			wantStatus: BlobStageRecoveryFailed, wantPhase: BlobStageRecoveryHead, wantError: sentinel,
		},
		{
			name: "missing at get", blobs: &staticRecoveryBlobStore{
				found: true, info: BlobInfo{Size: 1}, getErr: ErrNotFound,
			},
			wantStatus: BlobStageRecoveryMissing, wantPhase: BlobStageRecoveryRead,
		},
		{
			name: "get backend failure", blobs: &staticRecoveryBlobStore{
				found: true, info: BlobInfo{Size: 1}, getErr: sentinel,
			},
			wantStatus: BlobStageRecoveryFailed, wantPhase: BlobStageRecoveryRead, wantError: sentinel,
		},
		{
			name: "zero size", blobs: &staticRecoveryBlobStore{found: true},
			wantStatus: BlobStageRecoveryCorrupt, wantPhase: BlobStageRecoveryValidate, wantError: ErrCorrupt,
		},
		{
			name: "oversized", blobs: &staticRecoveryBlobStore{
				found: true, info: BlobInfo{Size: xorb.MaxCompleteSize + 1},
			},
			wantStatus: BlobStageRecoveryCorrupt, wantPhase: BlobStageRecoveryValidate, wantError: ErrCorrupt,
		},
		{
			name: "short read", blobs: &staticRecoveryBlobStore{
				found: true, info: BlobInfo{Size: 2}, reader: func() io.ReadCloser {
					return io.NopCloser(bytes.NewReader([]byte{1}))
				},
			},
			wantStatus: BlobStageRecoveryCorrupt, wantPhase: BlobStageRecoveryValidate, wantError: ErrCorrupt,
		},
		{
			name: "extra byte", blobs: &staticRecoveryBlobStore{
				found: true, info: BlobInfo{Size: 1}, reader: func() io.ReadCloser {
					return io.NopCloser(bytes.NewReader([]byte{1, 2}))
				},
			},
			wantStatus: BlobStageRecoveryCorrupt, wantPhase: BlobStageRecoveryValidate, wantError: ErrCorrupt,
		},
		{
			name: "read failure", blobs: &staticRecoveryBlobStore{
				found: true, info: BlobInfo{Size: 1}, reader: func() io.ReadCloser {
					return recoveryFaultReader{readErr: sentinel}
				},
			},
			wantStatus: BlobStageRecoveryFailed, wantPhase: BlobStageRecoveryRead, wantError: sentinel,
		},
		{
			name: "close failure", blobs: &staticRecoveryBlobStore{
				found: true, info: BlobInfo{Size: 1}, reader: func() io.ReadCloser {
					return recoveryFaultReader{readErr: io.EOF, closeErr: sentinel}
				},
			},
			wantStatus: BlobStageRecoveryFailed, wantPhase: BlobStageRecoveryRead, wantError: sentinel,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			index := NewMemoryStore()
			stage := putRecoveryStage(
				t, index, testProtectionID(20), "tenant", key, cutoff.Add(-time.Hour), cutoff,
			)
			service, _ := newRecoveryService(t, test.blobs, index)
			page, err := service.RecoverExpiredBlobStages(context.Background(), cutoff, PageRequest{})
			if err != nil || len(page.Items) != 1 {
				t.Fatalf("recovery page = %#v, %v", page, err)
			}
			result := page.Items[0]
			if result.Stage != stage || result.Status != test.wantStatus || result.Phase != test.wantPhase ||
				!errors.Is(result.Err, test.wantError) {
				t.Fatalf("recovery result = %#v", result)
			}
			stages, err := index.ListBlobStages(context.Background(), nil, PageRequest{})
			if err != nil || len(stages.Items) != 1 || stages.Items[0] != stage {
				t.Fatalf("retained stage = %#v, %v", stages, err)
			}
		})
	}
}

func TestServiceRecoveryRejectsNoncanonicalArtifacts(t *testing.T) {
	ctx := context.Background()
	cutoff := time.Date(2026, time.August, 10, 20, 0, 0, 0, time.UTC)
	object, err := xorb.Encode([][]byte{[]byte("noncanonical recovery xorb")}, xorb.None)
	if err != nil {
		t.Fatal(err)
	}
	noncanonicalXorb, err := xorb.EncodeComplete(object, [4]byte{1})
	if err != nil {
		t.Fatal(err)
	}
	footerlessShard, err := shard.EncodeUpload(shard.Shard{})
	if err != nil {
		t.Fatal(err)
	}
	_, _, canonicalShard, _, _ := recoveryFixture(t)
	decodedShard, err := shard.Decode(canonicalShard)
	if err != nil || decodedShard.Footer == nil || decodedShard.Footer.FileLookupEntries == 0 {
		t.Fatalf("decode canonical shard fixture = %#v, %v", decodedShard, err)
	}
	alteredLookupShard := append([]byte(nil), canonicalShard...)
	alteredLookupShard[decodedShard.Footer.FileLookupOffset] ^= 1
	canonicalXorb, err := xorb.EncodeComplete(object, [4]byte{})
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name string
		key  BlobKey
		body []byte
	}{
		{
			name: "xorb nonce", key: BlobKey{Kind: BlobXorb, Hash: object.Hash}, body: noncanonicalXorb,
		},
		{
			name: "footerless xorb", key: BlobKey{Kind: BlobXorb, Hash: object.Hash}, body: object.Body,
		},
		{
			name: "wrong xorb key", key: BlobKey{Kind: BlobXorb, Hash: xethash.Chunk([]byte("wrong xorb key"))},
			body: canonicalXorb,
		},
		{
			name: "footerless shard", key: BlobKey{Kind: BlobShard, Hash: xethash.Chunk(footerlessShard)}, body: footerlessShard,
		},
		{
			name: "wrong shard key", key: BlobKey{Kind: BlobShard, Hash: xethash.Chunk([]byte("wrong"))},
			body: func() []byte {
				value, encodeErr := shard.EncodeFull(shard.Shard{})
				if encodeErr != nil {
					t.Fatal(encodeErr)
				}
				return value
			}(),
		},
		{
			name: "altered shard lookup", key: BlobKey{Kind: BlobShard, Hash: xethash.Chunk(alteredLookupShard)},
			body: alteredLookupShard,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			store := NewMemoryStore()
			if inserted, err := store.PutIfAbsent(
				ctx, test.key, bytes.NewReader(test.body), int64(len(test.body)),
			); err != nil || !inserted {
				t.Fatalf("put noncanonical artifact = %v, %v", inserted, err)
			}
			putRecoveryStage(t, store, testProtectionID(30), "tenant", test.key, cutoff.Add(-time.Hour), cutoff)
			service, _ := newRecoveryService(t, store, store)
			page, err := service.RecoverExpiredBlobStages(ctx, cutoff, PageRequest{})
			if err != nil || len(page.Items) != 1 || page.Items[0].Status != BlobStageRecoveryCorrupt ||
				!errors.Is(page.Items[0].Err, ErrCorrupt) {
				t.Fatalf("noncanonical recovery = %#v, %v", page, err)
			}
			if stages, err := store.ListBlobStages(ctx, nil, PageRequest{}); err != nil || len(stages.Items) != 1 {
				t.Fatalf("noncanonical stage = %#v, %v", stages, err)
			}
		})
	}
}

type recoveryPublishFaultIndex struct {
	*MemoryStore
	putXorbErr          error
	putXorbApplyThenErr error
	publishShardErr     error
	getXorbErr          error
	getXorbRecord       *XorbRecord
}

func (s *recoveryPublishFaultIndex) GetXorb(
	ctx context.Context,
	hash xethash.Hash,
) (XorbRecord, bool, error) {
	if s.getXorbErr != nil {
		return XorbRecord{}, false, s.getXorbErr
	}
	if s.getXorbRecord != nil {
		return *s.getXorbRecord, true, nil
	}
	return s.MemoryStore.GetXorb(ctx, hash)
}

func (s *recoveryPublishFaultIndex) PutXorb(ctx context.Context, record XorbRecord) error {
	if s.putXorbErr != nil {
		return s.putXorbErr
	}
	if s.putXorbApplyThenErr != nil {
		if err := s.MemoryStore.PutXorb(ctx, record); err != nil {
			return err
		}
		return s.putXorbApplyThenErr
	}
	return s.MemoryStore.PutXorb(ctx, record)
}

func (s *recoveryPublishFaultIndex) PublishShard(ctx context.Context, publication ShardPublication) error {
	if s.publishShardErr != nil {
		return s.publishShardErr
	}
	return s.MemoryStore.PublishShard(ctx, publication)
}

func TestServiceRecoveryPublicationFailuresAndRegistrationLimits(t *testing.T) {
	ctx := context.Background()
	cutoff := time.Date(2026, time.August, 10, 20, 30, 0, 0, time.UTC)
	t.Run("xorb conflict and backend failure", func(t *testing.T) {
		for _, test := range []struct {
			name       string
			publishErr error
			status     BlobStageRecoveryStatus
		}{
			{name: "conflict", publishErr: ErrConflict, status: BlobStageRecoveryConflict},
			{name: "backend", publishErr: errors.New("xorb index unavailable"), status: BlobStageRecoveryFailed},
		} {
			t.Run(test.name, func(t *testing.T) {
				store := NewMemoryStore()
				stage := putRecoverableXorb(t, store, testProtectionID(35), cutoff)
				index := &recoveryPublishFaultIndex{MemoryStore: store, putXorbErr: test.publishErr}
				service, _ := newRecoveryService(t, store, index)
				page, err := service.RecoverExpiredBlobStages(ctx, cutoff, PageRequest{})
				if err != nil || len(page.Items) != 1 || page.Items[0].Status != test.status ||
					page.Items[0].Phase != BlobStageRecoveryPublish || !errors.Is(page.Items[0].Err, test.publishErr) {
					t.Fatalf("xorb publication failure = %#v, %v", page, err)
				}
				if stages, err := store.ListBlobStages(ctx, nil, PageRequest{}); err != nil ||
					len(stages.Items) != 1 || stages.Items[0] != stage {
					t.Fatalf("stage after xorb publication failure = %#v, %v", stages, err)
				}
			})
		}
	})

	t.Run("ambiguous xorb publication is retryable", func(t *testing.T) {
		store := NewMemoryStore()
		stage := putRecoverableXorb(t, store, testProtectionID(34), cutoff)
		sentinel := errors.New("lost xorb publication response")
		index := &recoveryPublishFaultIndex{MemoryStore: store, putXorbApplyThenErr: sentinel}
		service, _ := newRecoveryService(t, store, index)
		page, err := service.RecoverExpiredBlobStages(ctx, cutoff, PageRequest{})
		if err != nil || len(page.Items) != 1 || page.Items[0].Status != BlobStageRecoveryFailed ||
			!errors.Is(page.Items[0].Err, sentinel) {
			t.Fatalf("ambiguous xorb publication = %#v, %v", page, err)
		}
		if _, found, err := store.GetXorb(ctx, stage.Blob.Hash); err != nil || !found {
			t.Fatalf("ambiguously published xorb = %v, %v", found, err)
		}
		index.putXorbApplyThenErr = nil
		page, err = service.RecoverExpiredBlobStages(ctx, cutoff, PageRequest{})
		if err != nil || len(page.Items) != 1 || page.Items[0].Status != BlobStageRecoveryPublishedRemoved {
			t.Fatalf("ambiguous xorb publication retry = %#v, %v", page, err)
		}
	})

	t.Run("shard publication failure", func(t *testing.T) {
		for _, test := range []struct {
			name       string
			publishErr error
			status     BlobStageRecoveryStatus
		}{
			{name: "conflict", publishErr: ErrConflict, status: BlobStageRecoveryConflict},
			{name: "backend", publishErr: errors.New("shard index unavailable"), status: BlobStageRecoveryFailed},
		} {
			t.Run(test.name, func(t *testing.T) {
				store := NewMemoryStore()
				ingested, xorbKey, fullShard, shardKey, _ := recoveryFixture(t)
				xorbRecord, err := xorbRecordFromComplete(ingested.Complete, xorbKey)
				if err != nil {
					t.Fatal(err)
				}
				if err := store.PutXorb(ctx, xorbRecord); err != nil {
					t.Fatal(err)
				}
				if inserted, err := store.PutIfAbsent(
					ctx, shardKey, bytes.NewReader(fullShard), int64(len(fullShard)),
				); err != nil || !inserted {
					t.Fatalf("put failed-publication shard = %v, %v", inserted, err)
				}
				stage := putRecoveryStage(
					t, store, testProtectionID(36), "tenant", shardKey, cutoff.Add(-time.Hour), cutoff,
				)
				index := &recoveryPublishFaultIndex{MemoryStore: store, publishShardErr: test.publishErr}
				service, _ := newRecoveryService(t, store, index)
				page, err := service.RecoverExpiredBlobStages(ctx, cutoff, PageRequest{})
				if err != nil || len(page.Items) != 1 || page.Items[0].Status != test.status ||
					page.Items[0].Phase != BlobStageRecoveryPublish || !errors.Is(page.Items[0].Err, test.publishErr) {
					t.Fatalf("shard publication failure = %#v, %v", page, err)
				}
				if stages, err := store.ListBlobStages(ctx, nil, PageRequest{}); err != nil ||
					len(stages.Items) != 1 || stages.Items[0] != stage {
					t.Fatalf("stage after shard publication failure = %#v, %v", stages, err)
				}
			})
		}
	})

	t.Run("shard dependency failure", func(t *testing.T) {
		lookupUnavailable := errors.New("xorb lookup unavailable")
		for _, test := range []struct {
			name       string
			configure  func(testing.TB, *recoveryPublishFaultIndex)
			wantError  error
			wantStatus BlobStageRecoveryStatus
		}{
			{
				name: "backend", wantError: lookupUnavailable, wantStatus: BlobStageRecoveryFailed,
				configure: func(_ testing.TB, index *recoveryPublishFaultIndex) {
					index.getXorbErr = lookupUnavailable
				},
			},
			{
				name: "conflict", wantError: shard.ErrXorbConflict, wantStatus: BlobStageRecoveryConflict,
				configure: func(t testing.TB, index *recoveryPublishFaultIndex) {
					other, err := xorb.Encode([][]byte{[]byte("other durable xorb")}, xorb.None)
					if err != nil {
						t.Fatal(err)
					}
					ingested, err := xorb.IngestNetwork(other.Body, other.Hash)
					if err != nil {
						t.Fatal(err)
					}
					record, err := xorbRecordFromComplete(
						ingested.Complete, BlobKey{Kind: BlobXorb, Hash: other.Hash},
					)
					if err != nil {
						t.Fatal(err)
					}
					index.getXorbRecord = &record
				},
			},
		} {
			t.Run(test.name, func(t *testing.T) {
				store := NewMemoryStore()
				_, _, fullShard, shardKey, _ := recoveryFixture(t)
				if inserted, err := store.PutIfAbsent(
					ctx, shardKey, bytes.NewReader(fullShard), int64(len(fullShard)),
				); err != nil || !inserted {
					t.Fatalf("put dependency-failure shard = %v, %v", inserted, err)
				}
				putRecoveryStage(t, store, testProtectionID(39), "tenant", shardKey, cutoff.Add(-time.Hour), cutoff)
				index := &recoveryPublishFaultIndex{MemoryStore: store}
				test.configure(t, index)
				service, _ := newRecoveryService(t, store, index)
				page, err := service.RecoverExpiredBlobStages(ctx, cutoff, PageRequest{})
				if err != nil || len(page.Items) != 1 || page.Items[0].Status != test.wantStatus ||
					page.Items[0].Phase != BlobStageRecoveryResolve || !errors.Is(page.Items[0].Err, test.wantError) {
					t.Fatalf("shard dependency failure = %#v, %v", page, err)
				}
			})
		}
	})

	t.Run("registration limit can be retried", func(t *testing.T) {
		store := NewMemoryStore()
		ingested, xorbKey, fullShard, shardKey, _ := recoveryFixture(t)
		xorbRecord, err := xorbRecordFromComplete(ingested.Complete, xorbKey)
		if err != nil {
			t.Fatal(err)
		}
		if err := store.PutXorb(ctx, xorbRecord); err != nil {
			t.Fatal(err)
		}
		if inserted, err := store.PutIfAbsent(
			ctx, shardKey, bytes.NewReader(fullShard), int64(len(fullShard)),
		); err != nil || !inserted {
			t.Fatalf("put limited shard = %v, %v", inserted, err)
		}
		putRecoveryStage(t, store, testProtectionID(37), "tenant", shardKey, cutoff.Add(-time.Hour), cutoff)
		service, _ := newRecoveryService(t, store, store)
		originalLimit := service.registration.MaxChunkReferences
		service.registration.MaxChunkReferences = 1
		page, err := service.RecoverExpiredBlobStages(ctx, cutoff, PageRequest{})
		if err != nil || len(page.Items) != 1 || page.Items[0].Status != BlobStageRecoveryBlocked ||
			!errors.Is(page.Items[0].Err, shard.ErrRegistrationLimit) {
			t.Fatalf("limited shard recovery = %#v, %v", page, err)
		}
		service.registration.MaxChunkReferences = originalLimit
		page, err = service.RecoverExpiredBlobStages(ctx, cutoff, PageRequest{})
		if err != nil || len(page.Items) != 1 || page.Items[0].Status != BlobStageRecoveryPublishedRemoved {
			t.Fatalf("retried limited shard recovery = %#v, %v", page, err)
		}
	})

	t.Run("empty shard", func(t *testing.T) {
		store := NewMemoryStore()
		body, err := shard.EncodeFull(shard.Shard{})
		if err != nil {
			t.Fatal(err)
		}
		key := BlobKey{Kind: BlobShard, Hash: xethash.Chunk(body)}
		if inserted, err := store.PutIfAbsent(ctx, key, bytes.NewReader(body), int64(len(body))); err != nil || !inserted {
			t.Fatalf("put empty shard = %v, %v", inserted, err)
		}
		putRecoveryStage(t, store, testProtectionID(38), "tenant", key, cutoff.Add(-time.Hour), cutoff)
		service, _ := newRecoveryService(t, store, store)
		page, err := service.RecoverExpiredBlobStages(ctx, cutoff, PageRequest{})
		if err != nil || len(page.Items) != 1 || page.Items[0].Status != BlobStageRecoveryPublishedRemoved {
			t.Fatalf("empty shard recovery = %#v, %v", page, err)
		}
	})
}

type recoveryControlIndex struct {
	*MemoryStore
	listErr             error
	deleteErr           error
	deleteAfterApplyErr error
	beforeDelete        func(context.Context, string, ProtectionID, time.Time)
}

func (s *recoveryControlIndex) ListExpiredBlobStages(
	ctx context.Context,
	cutoff time.Time,
	request PageRequest,
) (BlobStagePage, error) {
	if s.listErr != nil {
		return BlobStagePage{}, s.listErr
	}
	return s.MemoryStore.ListExpiredBlobStages(ctx, cutoff, request)
}

func (s *recoveryControlIndex) DeleteExpiredBlobStage(
	ctx context.Context,
	namespace string,
	id ProtectionID,
	cutoff time.Time,
) (bool, error) {
	if s.beforeDelete != nil {
		s.beforeDelete(ctx, namespace, id, cutoff)
	}
	if s.deleteErr != nil {
		return false, s.deleteErr
	}
	deleted, err := s.MemoryStore.DeleteExpiredBlobStage(ctx, namespace, id, cutoff)
	if err == nil && s.deleteAfterApplyErr != nil {
		return false, s.deleteAfterApplyErr
	}
	return deleted, err
}

func putRecoverableXorb(
	t testing.TB,
	store *MemoryStore,
	id ProtectionID,
	cutoff time.Time,
) BlobStage {
	t.Helper()
	object, err := xorb.Encode([][]byte{[]byte("recoverable stage")}, xorb.LZ4)
	if err != nil {
		t.Fatal(err)
	}
	ingested, err := xorb.IngestNetwork(object.Body, object.Hash)
	if err != nil {
		t.Fatal(err)
	}
	key := BlobKey{Kind: BlobXorb, Hash: object.Hash}
	if inserted, err := store.PutIfAbsent(
		context.Background(), key, bytes.NewReader(ingested.Complete), int64(len(ingested.Complete)),
	); err != nil || !inserted {
		t.Fatalf("put recoverable xorb = %v, %v", inserted, err)
	}
	return putRecoveryStage(t, store, id, "tenant", key, cutoff.Add(-time.Hour), cutoff)
}

func TestServiceRecoveryConditionalDeletionOutcomes(t *testing.T) {
	ctx := context.Background()
	cutoff := time.Date(2026, time.August, 10, 21, 0, 0, 0, time.UTC)
	t.Run("renewed", func(t *testing.T) {
		store := NewMemoryStore()
		stage := putRecoverableXorb(t, store, testProtectionID(40), cutoff)
		index := &recoveryControlIndex{MemoryStore: store}
		index.beforeDelete = func(ctx context.Context, namespace string, id ProtectionID, _ time.Time) {
			index.beforeDelete = nil
			if err := store.RenewBlobStage(ctx, namespace, id, cutoff.Add(time.Hour)); err != nil {
				t.Error(err)
			}
		}
		service, _ := newRecoveryService(t, store, index)
		page, err := service.RecoverExpiredBlobStages(ctx, cutoff, PageRequest{})
		if err != nil || len(page.Items) != 1 || page.Items[0].Status != BlobStageRecoveryPublishedNotRemoved {
			t.Fatalf("renewed recovery = %#v, %v", page, err)
		}
		stages, err := store.ListBlobStages(ctx, nil, PageRequest{})
		if err != nil || len(stages.Items) != 1 || stages.Items[0].ID != stage.ID ||
			!stages.Items[0].ExpiresAt.Equal(cutoff.Add(time.Hour)) {
			t.Fatalf("renewed recovery stage = %#v, %v", stages, err)
		}
	})

	t.Run("delete failure and retry", func(t *testing.T) {
		store := NewMemoryStore()
		stage := putRecoverableXorb(t, store, testProtectionID(41), cutoff)
		sentinel := errors.New("delete failed")
		index := &recoveryControlIndex{MemoryStore: store, deleteErr: sentinel}
		service, _ := newRecoveryService(t, store, index)
		page, err := service.RecoverExpiredBlobStages(ctx, cutoff, PageRequest{})
		if err != nil || len(page.Items) != 1 || page.Items[0].Status != BlobStageRecoveryPublishedDeleteFailed ||
			page.Items[0].Phase != BlobStageRecoveryDelete || !errors.Is(page.Items[0].Err, sentinel) {
			t.Fatalf("failed stage deletion = %#v, %v", page, err)
		}
		if _, found, err := store.GetXorb(ctx, stage.Blob.Hash); err != nil || !found {
			t.Fatalf("published xorb before delete failure = %v, %v", found, err)
		}
		index.deleteErr = nil
		page, err = service.RecoverExpiredBlobStages(ctx, cutoff, PageRequest{})
		if err != nil || len(page.Items) != 1 || page.Items[0].Status != BlobStageRecoveryPublishedRemoved {
			t.Fatalf("stage deletion retry = %#v, %v", page, err)
		}
	})

	t.Run("ambiguous applied delete", func(t *testing.T) {
		store := NewMemoryStore()
		putRecoverableXorb(t, store, testProtectionID(42), cutoff)
		sentinel := errors.New("lost stage deletion response")
		index := &recoveryControlIndex{MemoryStore: store, deleteAfterApplyErr: sentinel}
		service, _ := newRecoveryService(t, store, index)
		page, err := service.RecoverExpiredBlobStages(ctx, cutoff, PageRequest{})
		if err != nil || len(page.Items) != 1 || page.Items[0].Status != BlobStageRecoveryPublishedDeleteFailed ||
			!errors.Is(page.Items[0].Err, sentinel) {
			t.Fatalf("ambiguous stage deletion = %#v, %v", page, err)
		}
		if stages, err := store.ListBlobStages(ctx, nil, PageRequest{}); err != nil || len(stages.Items) != 0 {
			t.Fatalf("ambiguously deleted stage = %#v, %v", stages, err)
		}
		page, err = service.RecoverExpiredBlobStages(ctx, cutoff, PageRequest{})
		if err != nil || len(page.Items) != 0 {
			t.Fatalf("recovery after ambiguous applied delete = %#v, %v", page, err)
		}
	})
}

type duplicateRecoveryIndex struct {
	*MemoryStore
	arrived atomic.Int32
	release chan struct{}
}

func (s *duplicateRecoveryIndex) DeleteExpiredBlobStage(
	ctx context.Context,
	namespace string,
	id ProtectionID,
	cutoff time.Time,
) (bool, error) {
	if s.arrived.Add(1) == 2 {
		close(s.release)
	}
	select {
	case <-s.release:
	case <-ctx.Done():
		return false, ctx.Err()
	}
	return s.MemoryStore.DeleteExpiredBlobStage(ctx, namespace, id, cutoff)
}

func TestServiceRecoveryDuplicateWorkers(t *testing.T) {
	store := NewMemoryStore()
	cutoff := time.Date(2026, time.August, 10, 22, 0, 0, 0, time.UTC)
	putRecoverableXorb(t, store, testProtectionID(50), cutoff)
	index := &duplicateRecoveryIndex{MemoryStore: store, release: make(chan struct{})}
	first, _ := newRecoveryService(t, store, index)
	second, _ := newRecoveryService(t, store, index)
	results := make(chan BlobStageRecoveryPage, 2)
	errorsFound := make(chan error, 2)
	var wait sync.WaitGroup
	for _, service := range []*Service{first, second} {
		wait.Add(1)
		go func() {
			defer wait.Done()
			page, err := service.RecoverExpiredBlobStages(context.Background(), cutoff, PageRequest{})
			results <- page
			errorsFound <- err
		}()
	}
	wait.Wait()
	close(results)
	close(errorsFound)
	for err := range errorsFound {
		if err != nil {
			t.Fatal(err)
		}
	}
	statuses := make(map[BlobStageRecoveryStatus]int)
	for page := range results {
		if len(page.Items) != 1 {
			t.Fatalf("duplicate-worker page = %#v", page)
		}
		statuses[page.Items[0].Status]++
	}
	if statuses[BlobStageRecoveryPublishedRemoved] != 1 || statuses[BlobStageRecoveryPublishedNotRemoved] != 1 {
		t.Fatalf("duplicate-worker statuses = %#v", statuses)
	}
}

type indexWithoutProtectionExpiry struct{ IndexStore }

type cancelSecondRecoveryHead struct {
	cancel context.CancelFunc
	calls  atomic.Int32
}

func (*cancelSecondRecoveryHead) PutIfAbsent(context.Context, BlobKey, io.Reader, int64) (bool, error) {
	return false, errors.New("unexpected blob write")
}

func (s *cancelSecondRecoveryHead) Head(ctx context.Context, _ BlobKey) (BlobInfo, bool, error) {
	if s.calls.Add(1) == 2 {
		s.cancel()
		return BlobInfo{}, false, ctx.Err()
	}
	return BlobInfo{}, false, nil
}

func (*cancelSecondRecoveryHead) Get(context.Context, BlobKey, *xetcas.HTTPRange) (io.ReadCloser, error) {
	return nil, errors.New("unexpected blob read")
}

func TestServiceRecoveryPaginationAndMidPageCancellation(t *testing.T) {
	ctx := context.Background()
	cutoff := time.Date(2026, time.August, 10, 22, 30, 0, 0, time.UTC)
	store := NewMemoryStore()
	first := putRecoveryStage(
		t, store, testProtectionID(55), "tenant",
		BlobKey{Kind: BlobXorb, Hash: xethash.Chunk([]byte("first missing recovery"))},
		cutoff.Add(-time.Hour), cutoff.Add(-time.Minute),
	)
	second := putRecoveryStage(
		t, store, testProtectionID(56), "tenant",
		BlobKey{Kind: BlobXorb, Hash: xethash.Chunk([]byte("second missing recovery"))},
		cutoff.Add(-time.Hour), cutoff,
	)
	service, _ := newRecoveryService(t, store, store)
	page, err := service.RecoverExpiredBlobStages(ctx, cutoff, PageRequest{Limit: 1})
	if err != nil || len(page.Items) != 1 || page.Items[0].Stage != first ||
		page.Items[0].Status != BlobStageRecoveryMissing || page.NextCursor == "" {
		t.Fatalf("first recovery page = %#v, %v", page, err)
	}
	next, err := service.RecoverExpiredBlobStages(
		ctx, cutoff, PageRequest{Limit: 1, Cursor: page.NextCursor},
	)
	if err != nil || len(next.Items) != 1 || next.Items[0].Stage != second ||
		next.Items[0].Status != BlobStageRecoveryMissing || next.NextCursor != "" {
		t.Fatalf("second recovery page = %#v, %v", next, err)
	}
	if _, err := service.RecoverExpiredBlobStages(
		ctx, cutoff.Add(time.Nanosecond), PageRequest{Limit: 1, Cursor: page.NextCursor},
	); !errors.Is(err, ErrInvalid) {
		t.Fatalf("recovery cursor with changed cutoff = %v", err)
	}

	cancelContext, cancel := context.WithCancel(ctx)
	blobs := &cancelSecondRecoveryHead{cancel: cancel}
	service, _ = newRecoveryService(t, blobs, store)
	partial, err := service.RecoverExpiredBlobStages(cancelContext, cutoff, PageRequest{})
	if !errors.Is(err, context.Canceled) || len(partial.Items) != 1 || partial.Items[0].Stage != first ||
		partial.Items[0].Status != BlobStageRecoveryMissing || partial.NextCursor != "" {
		t.Fatalf("mid-page canceled recovery = %#v, %v", partial, err)
	}
	stages, err := store.ListBlobStages(ctx, nil, PageRequest{})
	if err != nil || len(stages.Items) != 2 {
		t.Fatalf("stages after missing/canceled recovery = %#v, %v", stages, err)
	}
}

func TestServiceRecoveryCancellationDuringShardRegistration(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	_, _, fullShard, shardKey, _ := recoveryFixture(t)
	blobs := &staticRecoveryBlobStore{
		found: true, info: BlobInfo{Size: int64(len(fullShard))},
		reader: func() io.ReadCloser {
			return cancelOnCloseReader{Reader: bytes.NewReader(fullShard), cancel: cancel}
		},
	}
	store := NewMemoryStore()
	cutoff := time.Date(2026, time.August, 10, 22, 45, 0, 0, time.UTC)
	stage := putRecoveryStage(
		t, store, testProtectionID(57), "tenant", shardKey, cutoff.Add(-time.Hour), cutoff,
	)
	service, _ := newRecoveryService(t, blobs, store)
	page, err := service.RecoverExpiredBlobStages(ctx, cutoff, PageRequest{})
	if !errors.Is(err, context.Canceled) || len(page.Items) != 0 || page.NextCursor != "" {
		t.Fatalf("registration-canceled recovery = %#v, %v", page, err)
	}
	stages, err := store.ListBlobStages(context.Background(), nil, PageRequest{})
	if err != nil || len(stages.Items) != 1 || stages.Items[0] != stage {
		t.Fatalf("stage after registration cancellation = %#v, %v", stages, err)
	}
}

func TestServiceRecoveryTopLevelErrorsAndCancellation(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()
	service, _ := newRecoveryService(t, store, indexWithoutProtectionExpiry{IndexStore: store})
	if _, err := service.RecoverExpiredBlobStages(ctx, time.Now(), PageRequest{}); !errors.Is(
		err, ErrProtectionExpiryUnsupported,
	) {
		t.Fatalf("unsupported recovery = %v", err)
	}

	sentinel := errors.New("expiry listing failed")
	index := &recoveryControlIndex{MemoryStore: store, listErr: sentinel}
	service, _ = newRecoveryService(t, store, index)
	if _, err := service.RecoverExpiredBlobStages(ctx, time.Now(), PageRequest{}); !errors.Is(err, sentinel) {
		t.Fatalf("failed recovery listing = %v", err)
	}

	cutoff := time.Date(2026, time.August, 10, 23, 0, 0, 0, time.UTC)
	stage := putRecoveryStage(
		t, store, testProtectionID(60), "tenant",
		BlobKey{Kind: BlobXorb, Hash: xethash.Chunk([]byte("waiting recovery"))},
		cutoff.Add(-time.Hour), cutoff,
	)
	service, _ = newRecoveryService(t, store, store)
	service.ingestSlots <- struct{}{}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	page, err := service.RecoverExpiredBlobStages(canceled, cutoff, PageRequest{})
	<-service.ingestSlots
	if !errors.Is(err, context.Canceled) || len(page.Items) != 0 || page.NextCursor != "" {
		t.Fatalf("canceled queued recovery = %#v, %v", page, err)
	}
	stages, err := store.ListBlobStages(ctx, nil, PageRequest{})
	if err != nil || len(stages.Items) != 1 || stages.Items[0] != stage {
		t.Fatalf("stage after canceled recovery = %#v, %v", stages, err)
	}
}

func TestSQLiteFilesystemRecoveryAcrossRestart(t *testing.T) {
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
	ingested, key, _, _, _ := recoveryFixture(t)
	if inserted, err := blobs.PutIfAbsent(
		ctx, key, bytes.NewReader(ingested.Complete), int64(len(ingested.Complete)),
	); err != nil || !inserted {
		t.Fatalf("put durable recovery xorb = %v, %v", inserted, err)
	}
	cutoff := time.Date(2026, time.August, 11, 0, 0, 0, 0, time.UTC)
	stage := putRecoveryStage(t, index, testProtectionID(70), "tenant", key, cutoff.Add(-time.Hour), cutoff)
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
	service, authorizationCalls := newRecoveryService(t, blobs, index)
	page, err := service.RecoverExpiredBlobStages(ctx, cutoff, PageRequest{})
	if err != nil || len(page.Items) != 1 || page.Items[0].Stage != stage ||
		page.Items[0].Status != BlobStageRecoveryPublishedRemoved {
		t.Fatalf("durable recovery = %#v, %v", page, err)
	}
	if _, found, err := index.GetXorb(ctx, key.Hash); err != nil || !found {
		t.Fatalf("durable recovered xorb = %v, %v", found, err)
	}
	if authorizationCalls.Load() != 0 {
		t.Fatalf("durable recovery performed %d authorization calls", authorizationCalls.Load())
	}
}
