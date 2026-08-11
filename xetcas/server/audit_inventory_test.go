package server

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"path/filepath"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jmwoliver/xet-go/shard"
	"github.com/jmwoliver/xet-go/xetcas"
	"github.com/jmwoliver/xet-go/xethash"
	"github.com/jmwoliver/xet-go/xorb"
)

type auditGraph struct {
	service   *Service
	store     *MemoryStore
	xorb      BlobKey
	shard     BlobKey
	file      xethash.Hash
	chunk     xethash.Hash
	stage     BlobStage
	lease     FileLease
	authCalls *atomic.Int32
}

func newAuditGraph(t testing.TB) auditGraph {
	t.Helper()
	store := NewMemoryStore()
	service := testService(t, store, nil)
	none, _, value, shardBody := uploadFixture(t)
	ctx := context.Background()
	if _, err := service.UploadXorb(ctx, "", xetcas.DefaultXorbPrefix, none.Hash,
		bytes.NewReader(none.Body), int64(len(none.Body))); err != nil {
		t.Fatal(err)
	}
	result, err := service.UploadShard(ctx, "", bytes.NewReader(shardBody), int64(len(shardBody)))
	if err != nil {
		t.Fatal(err)
	}
	dedupPage, err := store.ListDedup(ctx, stringPointer("tenant-a"), PageRequest{Limit: 1})
	if err != nil || len(dedupPage.Items) != 1 {
		t.Fatalf("audit fixture dedup = %#v, %v", dedupPage, err)
	}
	createdAt := time.Date(2026, time.August, 10, 12, 0, 0, 0, time.UTC)
	stage := BlobStage{
		ID: testProtectionID(230), Namespace: "tenant-a", Blob: BlobKey{Kind: BlobXorb, Hash: none.Hash},
		CreatedAt: createdAt, ExpiresAt: createdAt.Add(time.Hour),
	}
	lease := FileLease{
		ID: testProtectionID(231), Namespace: "tenant-a", File: value.Files[0].Hash,
		CreatedAt: createdAt, ExpiresAt: createdAt.Add(time.Hour),
	}
	if err := store.PutBlobStage(ctx, stage); err != nil {
		t.Fatal(err)
	}
	if err := store.PutFileLease(ctx, lease); err != nil {
		t.Fatal(err)
	}
	graph := auditGraph{
		service: service, store: store,
		xorb: BlobKey{Kind: BlobXorb, Hash: none.Hash}, shard: result.Shard,
		file: value.Files[0].Hash, chunk: dedupPage.Items[0].Chunk,
		stage: stage, lease: lease, authCalls: new(atomic.Int32),
	}
	service.authorizer = authorizerFunc(func(context.Context, string, AccessRequest) (Grant, error) {
		graph.authCalls.Add(1)
		return Grant{}, errors.New("audit invoked tenant authorization")
	})
	return graph
}

func stringPointer(value string) *string { return &value }

func oneAuditResult(t testing.TB, service *Service, request AuditRequest) AuditResult {
	t.Helper()
	page, err := service.AuditInventory(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Items) != 1 || page.NextCursor != "" || page.Kind != request.Kind {
		t.Fatalf("audit page = %#v", page)
	}
	return page.Items[0]
}

func requireAuditResult(
	t testing.TB,
	result AuditResult,
	status AuditStatus,
	finding AuditFinding,
) {
	t.Helper()
	if result.Status != status || result.Finding != finding {
		t.Fatalf("audit result = status %q, finding %q, error %v, subject %#v",
			result.Status, result.Finding, result.Err, result.Subject)
	}
}

func TestAuditInventoryConsistentForwardGraph(t *testing.T) {
	graph := newAuditGraph(t)
	for _, test := range []struct {
		kind      AuditKind
		namespace *string
		status    AuditStatus
		finding   AuditFinding
		subject   any
	}{
		{AuditKindBlobXorb, nil, AuditStatusNoIssueFound, AuditFindingNone, BlobAuditSubject{}},
		{AuditKindBlobShard, nil, AuditStatusIndeterminate, AuditFindingShardReverseLookupUnavailable, BlobAuditSubject{}},
		{AuditKindXorbRecord, nil, AuditStatusNoIssueFound, AuditFindingNone, XorbRecordAuditSubject{}},
		{AuditKindShardRecord, stringPointer("tenant-a"), AuditStatusNoIssueFound, AuditFindingNone, ShardRecordAuditSubject{}},
		{AuditKindFileRecord, stringPointer("tenant-a"), AuditStatusNoIssueFound, AuditFindingNone, FileRecordAuditSubject{}},
		{AuditKindDedupRecord, stringPointer("tenant-a"), AuditStatusNoIssueFound, AuditFindingNone, DedupRecordAuditSubject{}},
		{AuditKindSHA256Association, stringPointer("tenant-a"), AuditStatusNoIssueFound, AuditFindingNone, SHA256AssociationAuditSubject{}},
		{AuditKindBlobStage, stringPointer("tenant-a"), AuditStatusNoIssueFound, AuditFindingNone, BlobStageAuditSubject{}},
		{AuditKindFileLease, stringPointer("tenant-a"), AuditStatusNoIssueFound, AuditFindingNone, FileLeaseAuditSubject{}},
	} {
		t.Run(string(test.kind), func(t *testing.T) {
			result := oneAuditResult(t, graph.service, AuditRequest{Kind: test.kind, Namespace: test.namespace})
			requireAuditResult(t, result, test.status, test.finding)
			if reflect.TypeOf(result.Subject) != reflect.TypeOf(test.subject) {
				t.Fatalf("audit subject type = %T, want %T", result.Subject, test.subject)
			}
			if result.Err != nil {
				t.Fatalf("successful audit error = %v", result.Err)
			}
		})
	}
	if graph.authCalls.Load() != 0 {
		t.Fatalf("audit authorization calls = %d", graph.authCalls.Load())
	}
}

func TestAuditInventorySHA256AssociationAllowsRetainedRecipeWithoutSHA(t *testing.T) {
	store := NewMemoryStore()
	service := testService(t, store, nil)
	none, _, value, shardBody := uploadFixture(t)
	ctx := context.Background()
	if _, err := service.UploadXorb(ctx, "", xetcas.DefaultXorbPrefix, none.Hash,
		bytes.NewReader(none.Body), int64(len(none.Body))); err != nil {
		t.Fatal(err)
	}
	withoutSHA := value
	withoutSHA.Files = append([]shard.File(nil), value.Files...)
	withoutSHA.Files[0].Terms = append([]shard.Term(nil), value.Files[0].Terms...)
	withoutSHA.Files[0].SHA256 = nil
	firstBody, err := shard.EncodeUpload(withoutSHA)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.UploadShard(ctx, "", bytes.NewReader(firstBody), int64(len(firstBody))); err != nil {
		t.Fatal(err)
	}
	if _, err := service.UploadShard(ctx, "", bytes.NewReader(shardBody), int64(len(shardBody))); err != nil {
		t.Fatal(err)
	}
	file, found, err := store.GetFile(ctx, "tenant-a", value.Files[0].Hash)
	if err != nil || !found || file.File.File.SHA256 != nil {
		t.Fatalf("retained first file recipe = %#v, %v, %v", file, found, err)
	}
	result := oneAuditResult(t, service, AuditRequest{
		Kind: AuditKindSHA256Association, Namespace: stringPointer("tenant-a"),
	})
	requireAuditResult(t, result, AuditStatusNoIssueFound, AuditFindingNone)
}

func TestAuditInventoryChecksFileDeclaredSHA256Association(t *testing.T) {
	graph := newAuditGraph(t)
	graph.store.mu.RLock()
	file := cloneFileRecord(graph.store.files[scopedHash{namespace: "tenant-a", hash: graph.file}])
	graph.store.mu.RUnlock()
	if file.File.File.SHA256 == nil {
		t.Fatal("audit fixture file has no SHA-256")
	}
	key := shaKey{namespace: "tenant-a", sum: *file.File.File.SHA256, size: file.File.Size}
	scoped := ScopedFileRecord{Namespace: "tenant-a", Record: file}

	graph.store.mu.Lock()
	delete(graph.store.sha256, key)
	graph.store.mu.Unlock()
	for _, result := range []AuditResult{
		graph.service.auditFileRecord(context.Background(), scoped),
		graph.service.auditFileLease(context.Background(), graph.lease),
	} {
		requireAuditResult(t, result, AuditStatusIssue, AuditFindingSHA256AssociationMissing)
		if result.Target == nil || result.Target.Kind != AuditTargetSHA256 ||
			result.Target.Namespace != "tenant-a" || result.Target.Sum != key.sum || result.Target.Size != key.size {
			t.Fatalf("missing SHA-256 target = %#v", result.Target)
		}
	}

	graph.store.mu.Lock()
	graph.store.sha256[key] = xethash.Chunk([]byte("conflicting SHA-256 file"))
	graph.store.mu.Unlock()
	result := graph.service.auditFileRecord(context.Background(), scoped)
	requireAuditResult(t, result, AuditStatusIssue, AuditFindingRecordInvalid)

	graph.store.mu.Lock()
	graph.store.sha256[key] = graph.file
	graph.store.mu.Unlock()
	sentinel := errors.New("injected SHA-256 association lookup")
	faults := &auditFaultIndex{MemoryStore: graph.store, resolveSHAErr: sentinel}
	graph.service.index = faults
	for _, result := range []AuditResult{
		graph.service.auditFileRecord(context.Background(), scoped),
		graph.service.auditFileLease(context.Background(), graph.lease),
	} {
		requireAuditResult(t, result, AuditStatusFailed, AuditFindingCheckFailed)
		if !errors.Is(result.Err, sentinel) {
			t.Fatalf("SHA-256 lookup failure = %v", result.Err)
		}
	}
}

func TestAuditInventoryDoesNotClaimPayloadVerification(t *testing.T) {
	graph := newAuditGraph(t)
	graph.store.mu.Lock()
	body := graph.store.blobs[graph.xorb]
	graph.store.blobs[graph.xorb] = bytes.Repeat([]byte{0xff}, len(body))
	graph.store.mu.Unlock()
	result := oneAuditResult(t, graph.service, AuditRequest{Kind: AuditKindXorbRecord})
	// The bounded inventory intentionally performs metadata and Head checks
	// only. A future payload audit must use a distinct, stronger operation.
	requireAuditResult(t, result, AuditStatusNoIssueFound, AuditFindingNone)
}

func TestAuditInventoryClassifiesMissingForwardDependencies(t *testing.T) {
	t.Run("Xorb payload", func(t *testing.T) {
		graph := newAuditGraph(t)
		graph.store.mu.Lock()
		delete(graph.store.blobs, graph.xorb)
		graph.store.mu.Unlock()
		for _, kind := range []AuditKind{
			AuditKindXorbRecord, AuditKindFileRecord, AuditKindSHA256Association,
			AuditKindBlobStage, AuditKindFileLease,
		} {
			namespace := stringPointer("tenant-a")
			if kind == AuditKindXorbRecord {
				namespace = nil
			}
			result := oneAuditResult(t, graph.service, AuditRequest{Kind: kind, Namespace: namespace})
			requireAuditResult(t, result, AuditStatusIssue, AuditFindingBlobMissing)
			if result.Target == nil || result.Target.Kind != AuditTargetBlob || result.Target.Blob != graph.xorb {
				t.Fatalf("missing Xorb target = %#v", result.Target)
			}
		}
	})

	t.Run("shard payload", func(t *testing.T) {
		graph := newAuditGraph(t)
		graph.store.mu.Lock()
		delete(graph.store.blobs, graph.shard)
		graph.store.mu.Unlock()
		for _, kind := range []AuditKind{
			AuditKindShardRecord, AuditKindFileRecord, AuditKindDedupRecord,
			AuditKindSHA256Association, AuditKindFileLease,
		} {
			result := oneAuditResult(t, graph.service, AuditRequest{
				Kind: kind, Namespace: stringPointer("tenant-a"),
			})
			requireAuditResult(t, result, AuditStatusIssue, AuditFindingBlobMissing)
			if result.Target == nil || result.Target.Blob != graph.shard {
				t.Fatalf("missing shard target = %#v", result.Target)
			}
		}
	})

	t.Run("shard registration and namespace isolation", func(t *testing.T) {
		graph := newAuditGraph(t)
		graph.store.mu.Lock()
		delete(graph.store.shards, scopedHash{namespace: "tenant-a", hash: graph.shard.Hash})
		graph.store.shards[scopedHash{namespace: "tenant-b", hash: graph.shard.Hash}] = ShardRecord{Blob: graph.shard}
		graph.store.mu.Unlock()
		for _, kind := range []AuditKind{
			AuditKindFileRecord, AuditKindDedupRecord,
			AuditKindSHA256Association, AuditKindFileLease,
		} {
			result := oneAuditResult(t, graph.service, AuditRequest{
				Kind: kind, Namespace: stringPointer("tenant-a"),
			})
			requireAuditResult(t, result, AuditStatusIssue, AuditFindingShardRecordMissing)
			if result.Target == nil || result.Target.Namespace != "tenant-a" || result.Target.Hash != graph.shard.Hash {
				t.Fatalf("missing scoped shard target = %#v", result.Target)
			}
		}
	})

	t.Run("file record and namespace isolation", func(t *testing.T) {
		graph := newAuditGraph(t)
		graph.store.mu.Lock()
		file := graph.store.files[scopedHash{namespace: "tenant-a", hash: graph.file}]
		delete(graph.store.files, scopedHash{namespace: "tenant-a", hash: graph.file})
		graph.store.files[scopedHash{namespace: "tenant-b", hash: graph.file}] = file
		graph.store.mu.Unlock()
		for _, kind := range []AuditKind{AuditKindSHA256Association, AuditKindFileLease} {
			result := oneAuditResult(t, graph.service, AuditRequest{
				Kind: kind, Namespace: stringPointer("tenant-a"),
			})
			requireAuditResult(t, result, AuditStatusIssue, AuditFindingFileRecordMissing)
			if result.Target == nil || result.Target.Namespace != "tenant-a" || result.Target.Hash != graph.file {
				t.Fatalf("missing scoped file target = %#v", result.Target)
			}
		}
	})

	t.Run("Xorb record", func(t *testing.T) {
		graph := newAuditGraph(t)
		graph.store.mu.Lock()
		delete(graph.store.xorbs, graph.xorb.Hash)
		graph.store.mu.Unlock()
		physical := oneAuditResult(t, graph.service, AuditRequest{Kind: AuditKindBlobXorb})
		requireAuditResult(t, physical, AuditStatusIndeterminate, AuditFindingXorbRecordMissing)
		for _, kind := range []AuditKind{
			AuditKindFileRecord, AuditKindSHA256Association, AuditKindFileLease,
		} {
			result := oneAuditResult(t, graph.service, AuditRequest{
				Kind: kind, Namespace: stringPointer("tenant-a"),
			})
			requireAuditResult(t, result, AuditStatusIssue, AuditFindingXorbRecordMissing)
		}
	})

	t.Run("stage payload", func(t *testing.T) {
		graph := newAuditGraph(t)
		graph.store.mu.Lock()
		graph.store.stages[scopedProtection{namespace: graph.stage.Namespace, id: graph.stage.ID}] = BlobStage{
			ID: graph.stage.ID, Namespace: graph.stage.Namespace,
			Blob:      BlobKey{Kind: BlobShard, Hash: xethash.Chunk([]byte("missing staged shard"))},
			CreatedAt: graph.stage.CreatedAt, ExpiresAt: graph.stage.ExpiresAt,
		}
		graph.store.mu.Unlock()
		result := oneAuditResult(t, graph.service, AuditRequest{
			Kind: AuditKindBlobStage, Namespace: stringPointer("tenant-a"),
		})
		requireAuditResult(t, result, AuditStatusIssue, AuditFindingBlobMissing)
	})
}

func TestAuditInventoryClassifiesInvalidStoredMetadata(t *testing.T) {
	t.Run("physical blob size", func(t *testing.T) {
		graph := newAuditGraph(t)
		graph.store.mu.Lock()
		graph.store.blobs[graph.xorb] = nil
		graph.store.mu.Unlock()
		result := oneAuditResult(t, graph.service, AuditRequest{Kind: AuditKindBlobXorb})
		requireAuditResult(t, result, AuditStatusIssue, AuditFindingBlobSizeInvalid)
		if !errors.Is(result.Err, ErrCorrupt) {
			t.Fatalf("invalid physical size error = %v", result.Err)
		}
	})

	t.Run("Xorb layout", func(t *testing.T) {
		graph := newAuditGraph(t)
		graph.store.mu.Lock()
		record := graph.store.xorbs[graph.xorb.Hash]
		record.Layout.NetworkBytes = 0
		graph.store.xorbs[graph.xorb.Hash] = record
		graph.store.mu.Unlock()
		for _, kind := range []AuditKind{
			AuditKindBlobXorb, AuditKindXorbRecord, AuditKindFileRecord,
			AuditKindSHA256Association, AuditKindFileLease,
		} {
			namespace := stringPointer("tenant-a")
			if kind == AuditKindBlobXorb || kind == AuditKindXorbRecord {
				namespace = nil
			}
			result := oneAuditResult(t, graph.service, AuditRequest{Kind: kind, Namespace: namespace})
			requireAuditResult(t, result, AuditStatusIssue, AuditFindingRecordInvalid)
			if !errors.Is(result.Err, ErrCorrupt) {
				t.Fatalf("invalid Xorb error = %v", result.Err)
			}
		}
	})

	t.Run("file term", func(t *testing.T) {
		graph := newAuditGraph(t)
		graph.store.mu.Lock()
		key := scopedHash{namespace: "tenant-a", hash: graph.file}
		record := graph.store.files[key]
		record.File.File.Terms[0].End++
		graph.store.files[key] = record
		graph.store.mu.Unlock()
		for _, kind := range []AuditKind{
			AuditKindFileRecord, AuditKindSHA256Association, AuditKindFileLease,
		} {
			result := oneAuditResult(t, graph.service, AuditRequest{
				Kind: kind, Namespace: stringPointer("tenant-a"),
			})
			requireAuditResult(t, result, AuditStatusIssue, AuditFindingRecordInvalid)
		}
	})

	t.Run("recipe work bound", func(t *testing.T) {
		graph := newAuditGraph(t)
		graph.service.registration.MaxTerms = 1
		graph.store.mu.Lock()
		key := scopedHash{namespace: "tenant-a", hash: graph.file}
		record := graph.store.files[key]
		record.File.File.Terms = append(record.File.File.Terms, record.File.File.Terms[0])
		graph.store.files[key] = record
		graph.store.mu.Unlock()
		for _, kind := range []AuditKind{
			AuditKindFileRecord, AuditKindSHA256Association, AuditKindFileLease,
		} {
			result := oneAuditResult(t, graph.service, AuditRequest{
				Kind: kind, Namespace: stringPointer("tenant-a"),
			})
			requireAuditResult(t, result, AuditStatusIssue, AuditFindingRecordInvalid)
			if !errors.Is(result.Err, ErrCorrupt) {
				t.Fatalf("work-bound audit error = %v", result.Err)
			}
		}
	})

	t.Run("protected records", func(t *testing.T) {
		graph := newAuditGraph(t)
		graph.store.mu.Lock()
		stageKey := scopedProtection{namespace: graph.stage.Namespace, id: graph.stage.ID}
		stage := graph.store.stages[stageKey]
		stage.ExpiresAt = stage.CreatedAt
		graph.store.stages[stageKey] = stage
		leaseKey := scopedProtection{namespace: graph.lease.Namespace, id: graph.lease.ID}
		lease := graph.store.leases[leaseKey]
		lease.ExpiresAt = lease.CreatedAt
		graph.store.leases[leaseKey] = lease
		graph.store.mu.Unlock()
		for _, kind := range []AuditKind{AuditKindBlobStage, AuditKindFileLease} {
			result := oneAuditResult(t, graph.service, AuditRequest{
				Kind: kind, Namespace: stringPointer("tenant-a"),
			})
			requireAuditResult(t, result, AuditStatusIssue, AuditFindingRecordInvalid)
		}
	})
}

func TestAuditInventoryPaginationAndCursorBinding(t *testing.T) {
	store := NewMemoryStore()
	service := testService(t, store, nil)
	ctx := context.Background()
	alpha := "alpha"
	for i := range 3 {
		key := BlobKey{Kind: BlobShard, Hash: xethash.Chunk([]byte(fmt.Sprintf("audit shard %d", i)))}
		if err := store.PublishShard(ctx, ShardPublication{Namespace: alpha, Shard: key}); err != nil {
			t.Fatal(err)
		}
	}
	first, err := service.AuditInventory(ctx, AuditRequest{
		Kind: AuditKindShardRecord, Namespace: &alpha, Page: PageRequest{Limit: 1},
	})
	if err != nil || len(first.Items) != 1 || first.NextCursor == "" {
		t.Fatalf("first audit page = %#v, %v", first, err)
	}
	second, err := service.AuditInventory(ctx, AuditRequest{
		Kind: AuditKindShardRecord, Namespace: &alpha,
		Page: PageRequest{Limit: 2, Cursor: first.NextCursor},
	})
	if err != nil || len(second.Items) != 2 || second.NextCursor != "" {
		t.Fatalf("second audit page = %#v, %v", second, err)
	}

	raw, err := store.ListShards(ctx, &alpha, PageRequest{Limit: 1})
	if err != nil || raw.NextCursor == "" {
		t.Fatalf("raw shard cursor = %#v, %v", raw, err)
	}
	for name, request := range map[string]AuditRequest{
		"cross kind": {
			Kind: AuditKindFileRecord, Namespace: &alpha, Page: PageRequest{Cursor: first.NextCursor},
		},
		"different namespace": {
			Kind: AuditKindShardRecord, Namespace: stringPointer("beta"), Page: PageRequest{Cursor: first.NextCursor},
		},
		"nil namespace": {
			Kind: AuditKindShardRecord, Page: PageRequest{Cursor: first.NextCursor},
		},
		"raw cursor": {
			Kind: AuditKindShardRecord, Namespace: &alpha, Page: PageRequest{Cursor: raw.NextCursor},
		},
		"malformed cursor": {
			Kind: AuditKindShardRecord, Namespace: &alpha, Page: PageRequest{Cursor: "bad"},
		},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := service.AuditInventory(ctx, request); !errors.Is(err, ErrInvalid) {
				t.Fatalf("invalid audit cursor = %v", err)
			}
		})
	}
	for name, request := range map[string]AuditRequest{
		"unknown kind":     {Kind: "unknown"},
		"negative limit":   {Kind: AuditKindBlobXorb, Page: PageRequest{Limit: -1}},
		"oversized limit":  {Kind: AuditKindBlobXorb, Page: PageRequest{Limit: MaxPageSize + 1}},
		"global namespace": {Kind: AuditKindBlobXorb, Namespace: &alpha},
		"Xorb namespace":   {Kind: AuditKindXorbRecord, Namespace: &alpha},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := service.AuditInventory(ctx, request); !errors.Is(err, ErrInvalid) {
				t.Fatalf("invalid audit request = %v", err)
			}
		})
	}
}

func TestAuditInventoryOptionalCapabilities(t *testing.T) {
	store := NewMemoryStore()
	service := testService(t, store, &faultIndex{IndexStore: store})
	if page, err := service.AuditInventory(context.Background(), AuditRequest{Kind: AuditKindBlobXorb}); err != nil || len(page.Items) != 0 {
		t.Fatalf("independent blob audit capability = %#v, %v", page, err)
	}
	for _, kind := range []AuditKind{AuditKindXorbRecord, AuditKindBlobStage, AuditKindFileLease} {
		if _, err := service.AuditInventory(context.Background(), AuditRequest{Kind: kind}); !errors.Is(err, ErrAuditUnsupported) {
			t.Fatalf("unsupported %s audit = %v", kind, err)
		}
	}
	service.blobs = faultBlobStore{BlobStore: store}
	if _, err := service.AuditInventory(context.Background(), AuditRequest{Kind: AuditKindBlobXorb}); !errors.Is(err, ErrAuditUnsupported) {
		t.Fatalf("unsupported blob audit = %v", err)
	}
}

type auditFaultIndex struct {
	*MemoryStore
	mu            sync.Mutex
	getXorbErr    map[xethash.Hash]error
	getShardErr   error
	getShardValue *ShardRecord
	getFileErr    error
	resolveSHAErr error
	listXorbErr   error
	listXorbPage  *XorbRecordPage
	listShardErr  error
	listFileErr   error
	listFilePage  *FileRecordPage
	listDedupErr  error
	listSHAErr    error
}

func (s *auditFaultIndex) GetXorb(ctx context.Context, hash xethash.Hash) (XorbRecord, bool, error) {
	s.mu.Lock()
	err := s.getXorbErr[hash]
	s.mu.Unlock()
	if err != nil {
		return XorbRecord{}, false, err
	}
	return s.MemoryStore.GetXorb(ctx, hash)
}

func (s *auditFaultIndex) GetShard(ctx context.Context, namespace string, hash xethash.Hash) (ShardRecord, bool, error) {
	s.mu.Lock()
	err := s.getShardErr
	s.mu.Unlock()
	if err != nil {
		return ShardRecord{}, false, err
	}
	if s.getShardValue != nil {
		return *s.getShardValue, true, nil
	}
	return s.MemoryStore.GetShard(ctx, namespace, hash)
}

func (s *auditFaultIndex) GetFile(ctx context.Context, namespace string, hash xethash.Hash) (FileRecord, bool, error) {
	s.mu.Lock()
	err := s.getFileErr
	s.mu.Unlock()
	if err != nil {
		return FileRecord{}, false, err
	}
	return s.MemoryStore.GetFile(ctx, namespace, hash)
}

func (s *auditFaultIndex) ResolveSHA256(
	ctx context.Context,
	namespace string,
	sum [32]byte,
	size uint64,
) (xethash.Hash, bool, error) {
	s.mu.Lock()
	err := s.resolveSHAErr
	s.mu.Unlock()
	if err != nil {
		return xethash.Hash{}, false, err
	}
	return s.MemoryStore.ResolveSHA256(ctx, namespace, sum, size)
}

func (s *auditFaultIndex) ListXorbs(ctx context.Context, request PageRequest) (XorbRecordPage, error) {
	s.mu.Lock()
	err := s.listXorbErr
	page := s.listXorbPage
	s.mu.Unlock()
	if err != nil {
		return XorbRecordPage{}, err
	}
	if page != nil {
		return *page, nil
	}
	return s.MemoryStore.ListXorbs(ctx, request)
}

func (s *auditFaultIndex) ListShards(ctx context.Context, namespace *string, request PageRequest) (ShardRecordPage, error) {
	s.mu.Lock()
	err := s.listShardErr
	s.mu.Unlock()
	if err != nil {
		return ShardRecordPage{}, err
	}
	return s.MemoryStore.ListShards(ctx, namespace, request)
}

func (s *auditFaultIndex) ListFiles(ctx context.Context, namespace *string, request PageRequest) (FileRecordPage, error) {
	s.mu.Lock()
	err := s.listFileErr
	page := s.listFilePage
	s.mu.Unlock()
	if err != nil {
		return FileRecordPage{}, err
	}
	if page != nil {
		return *page, nil
	}
	return s.MemoryStore.ListFiles(ctx, namespace, request)
}

func (s *auditFaultIndex) ListDedup(ctx context.Context, namespace *string, request PageRequest) (DedupRecordPage, error) {
	s.mu.Lock()
	err := s.listDedupErr
	s.mu.Unlock()
	if err != nil {
		return DedupRecordPage{}, err
	}
	return s.MemoryStore.ListDedup(ctx, namespace, request)
}

func (s *auditFaultIndex) ListSHA256(ctx context.Context, namespace *string, request PageRequest) (SHA256AssociationPage, error) {
	s.mu.Lock()
	err := s.listSHAErr
	s.mu.Unlock()
	if err != nil {
		return SHA256AssociationPage{}, err
	}
	return s.MemoryStore.ListSHA256(ctx, namespace, request)
}

type cancelingAuditBlobStore struct {
	*MemoryStore
	cancel   context.CancelFunc
	cancelAt int32
	calls    atomic.Int32
}

func (s *cancelingAuditBlobStore) Head(ctx context.Context, key BlobKey) (BlobInfo, bool, error) {
	info, found, err := s.MemoryStore.Head(ctx, key)
	if s.calls.Add(1) == s.cancelAt {
		s.cancel()
	}
	return info, found, err
}

type auditBlobListFaultStore struct {
	*MemoryStore
	err    error
	cancel context.CancelFunc
	page   *BlobPage
}

func (s *auditBlobListFaultStore) ListBlobs(ctx context.Context, kind BlobKind, request PageRequest) (BlobPage, error) {
	if s.err != nil {
		return BlobPage{}, s.err
	}
	if s.page != nil {
		if s.cancel != nil {
			s.cancel()
		}
		return *s.page, nil
	}
	page, err := s.MemoryStore.ListBlobs(ctx, kind, request)
	if s.cancel != nil {
		s.cancel()
	}
	return page, err
}

type auditProtectionListFaultIndex struct {
	*MemoryStore
	stageErr  error
	leaseErr  error
	stagePage *BlobStagePage
}

func (s *auditProtectionListFaultIndex) ListBlobStages(ctx context.Context, namespace *string, request PageRequest) (BlobStagePage, error) {
	if s.stageErr != nil {
		return BlobStagePage{}, s.stageErr
	}
	if s.stagePage != nil {
		return *s.stagePage, nil
	}
	return s.MemoryStore.ListBlobStages(ctx, namespace, request)
}

func (s *auditProtectionListFaultIndex) ListFileLeases(ctx context.Context, namespace *string, request PageRequest) (FileLeasePage, error) {
	if s.leaseErr != nil {
		return FileLeasePage{}, s.leaseErr
	}
	return s.MemoryStore.ListFileLeases(ctx, namespace, request)
}

type auditHeadFaultStore struct {
	*MemoryStore
	err  error
	info *BlobInfo
}

func (s *auditHeadFaultStore) Head(ctx context.Context, key BlobKey) (BlobInfo, bool, error) {
	if s.err != nil {
		return BlobInfo{}, false, s.err
	}
	if s.info != nil {
		return *s.info, true, nil
	}
	return s.MemoryStore.Head(ctx, key)
}

type cancelOnErrContext struct {
	context.Context
	cancelAt int32
	calls    atomic.Int32
}

func (c *cancelOnErrContext) Err() error {
	if c.calls.Add(1) >= c.cancelAt {
		return context.Canceled
	}
	return nil
}

func TestAuditInventoryListerFailures(t *testing.T) {
	sentinel := errors.New("injected audit list failure")
	store := NewMemoryStore()
	index := &auditFaultIndex{
		MemoryStore: store, getXorbErr: make(map[xethash.Hash]error),
		listXorbErr: sentinel, listShardErr: sentinel, listFileErr: sentinel,
		listDedupErr: sentinel, listSHAErr: sentinel,
	}
	service := testService(t, store, index)
	for _, kind := range []AuditKind{
		AuditKindXorbRecord, AuditKindShardRecord, AuditKindFileRecord,
		AuditKindDedupRecord, AuditKindSHA256Association,
	} {
		if page, err := service.AuditInventory(context.Background(), AuditRequest{Kind: kind}); !errors.Is(err, sentinel) || len(page.Items) != 0 || page.NextCursor != "" {
			t.Fatalf("%s list failure = %#v, %v", kind, page, err)
		}
	}
	service.blobs = &auditBlobListFaultStore{MemoryStore: store, err: sentinel}
	if page, err := service.AuditInventory(context.Background(), AuditRequest{Kind: AuditKindBlobShard}); !errors.Is(err, sentinel) || len(page.Items) != 0 {
		t.Fatalf("blob list failure = %#v, %v", page, err)
	}

	protections := &auditProtectionListFaultIndex{MemoryStore: store, stageErr: sentinel, leaseErr: sentinel}
	service = testService(t, store, protections)
	for _, kind := range []AuditKind{AuditKindBlobStage, AuditKindFileLease} {
		if page, err := service.AuditInventory(context.Background(), AuditRequest{Kind: kind}); !errors.Is(err, sentinel) || len(page.Items) != 0 || page.NextCursor != "" {
			t.Fatalf("%s list failure = %#v, %v", kind, page, err)
		}
	}

	graph := newAuditGraph(t)
	canceled, cancel := context.WithCancel(context.Background())
	graph.service.blobs = &auditBlobListFaultStore{MemoryStore: graph.store, cancel: cancel}
	page, err := graph.service.AuditInventory(canceled, AuditRequest{Kind: AuditKindBlobXorb})
	if !errors.Is(err, context.Canceled) || len(page.Items) != 0 || page.NextCursor != "" {
		t.Fatalf("canceled physical page = %#v, %v", page, err)
	}

	deadlineIndex := &auditFaultIndex{
		MemoryStore: graph.store,
		getXorbErr:  map[xethash.Hash]error{graph.xorb.Hash: context.DeadlineExceeded},
	}
	graph.service.index = deadlineIndex
	page, err = graph.service.AuditInventory(context.Background(), AuditRequest{Kind: AuditKindBlobXorb})
	if !errors.Is(err, context.DeadlineExceeded) || len(page.Items) != 0 || page.NextCursor != "" {
		t.Fatalf("deadline physical page = %#v, %v", page, err)
	}
}

func TestAuditInventoryRejectsBrokenListerContracts(t *testing.T) {
	t.Run("physical page exceeds limit", func(t *testing.T) {
		store := NewMemoryStore()
		service := testService(t, store, nil)
		service.blobs = &auditBlobListFaultStore{MemoryStore: store, page: &BlobPage{Items: []BlobEntry{
			{Key: BlobKey{Kind: BlobXorb, Hash: xethash.Chunk([]byte("first extra audit blob"))}, Info: BlobInfo{Size: 1}},
			{Key: BlobKey{Kind: BlobXorb, Hash: xethash.Chunk([]byte("second extra audit blob"))}, Info: BlobInfo{Size: 1}},
		}}}
		page, err := service.AuditInventory(context.Background(), AuditRequest{
			Kind: AuditKindBlobXorb, Page: PageRequest{Limit: 1},
		})
		if !errors.Is(err, ErrCorrupt) || len(page.Items) != 0 || page.NextCursor != "" {
			t.Fatalf("oversized physical page = %#v, %v", page, err)
		}
	})

	t.Run("logical page exceeds limit", func(t *testing.T) {
		graph := newAuditGraph(t)
		graph.store.mu.RLock()
		record := cloneFileRecord(graph.store.files[scopedHash{namespace: "tenant-a", hash: graph.file}])
		graph.store.mu.RUnlock()
		index := &auditFaultIndex{MemoryStore: graph.store, listFilePage: &FileRecordPage{Items: []ScopedFileRecord{
			{Namespace: "tenant-a", Record: record},
			{Namespace: "tenant-a", Record: record},
		}}}
		graph.service.index = index
		page, err := graph.service.AuditInventory(context.Background(), AuditRequest{
			Kind: AuditKindFileRecord, Namespace: stringPointer("tenant-a"), Page: PageRequest{Limit: 1},
		})
		if !errors.Is(err, ErrCorrupt) || len(page.Items) != 0 || page.NextCursor != "" {
			t.Fatalf("oversized logical page = %#v, %v", page, err)
		}
	})

	t.Run("scoped page crosses namespace", func(t *testing.T) {
		graph := newAuditGraph(t)
		graph.store.mu.RLock()
		record := cloneFileRecord(graph.store.files[scopedHash{namespace: "tenant-a", hash: graph.file}])
		graph.store.mu.RUnlock()
		index := &auditFaultIndex{MemoryStore: graph.store, listFilePage: &FileRecordPage{Items: []ScopedFileRecord{
			{Namespace: "tenant-b", Record: record},
		}}}
		graph.service.index = index
		page, err := graph.service.AuditInventory(context.Background(), AuditRequest{
			Kind: AuditKindFileRecord, Namespace: stringPointer("tenant-a"),
		})
		if !errors.Is(err, ErrCorrupt) || len(page.Items) != 0 || page.NextCursor != "" {
			t.Fatalf("cross-namespace logical page = %#v, %v", page, err)
		}
	})

	t.Run("continuation without items", func(t *testing.T) {
		store := NewMemoryStore()
		service := testService(t, store, nil)
		service.blobs = &auditBlobListFaultStore{
			MemoryStore: store, page: &BlobPage{NextCursor: "unexpected"},
		}
		page, err := service.AuditInventory(context.Background(), AuditRequest{Kind: AuditKindBlobXorb})
		if !errors.Is(err, ErrCorrupt) || len(page.Items) != 0 || page.NextCursor != "" {
			t.Fatalf("empty advancing page = %#v, %v", page, err)
		}
	})

	t.Run("stationary continuations", func(t *testing.T) {
		graph := newAuditGraph(t)
		graph.store.mu.RLock()
		xorbRecord := cloneXorbRecord(graph.store.xorbs[graph.xorb.Hash])
		stage := graph.store.stages[scopedProtection{namespace: graph.stage.Namespace, id: graph.stage.ID}]
		graph.store.mu.RUnlock()
		for _, test := range []struct {
			name      string
			kind      AuditKind
			namespace *string
			configure func()
		}{
			{
				name: "blob", kind: AuditKindBlobXorb,
				configure: func() {
					graph.service.blobs = &auditBlobListFaultStore{MemoryStore: graph.store, page: &BlobPage{
						Items: []BlobEntry{{Key: graph.xorb, Info: BlobInfo{Size: 1}}}, NextCursor: "stationary",
					}}
				},
			},
			{
				name: "index", kind: AuditKindXorbRecord,
				configure: func() {
					graph.service.index = &auditFaultIndex{MemoryStore: graph.store, listXorbPage: &XorbRecordPage{
						Items: []XorbRecord{xorbRecord}, NextCursor: "stationary",
					}}
				},
			},
			{
				name: "protection", kind: AuditKindBlobStage, namespace: stringPointer("tenant-a"),
				configure: func() {
					protections := &auditProtectionListFaultIndex{MemoryStore: graph.store, stagePage: &BlobStagePage{
						Items: []BlobStage{stage}, NextCursor: "stationary",
					}}
					graph.service.protections = protections
				},
			},
		} {
			t.Run(test.name, func(t *testing.T) {
				test.configure()
				page, err := graph.service.AuditInventory(context.Background(), AuditRequest{
					Kind: test.kind, Namespace: test.namespace,
					Page: PageRequest{Cursor: encodeAuditCursor(test.kind, test.namespace, "stationary")},
				})
				if !errors.Is(err, ErrCorrupt) || len(page.Items) != 0 || page.NextCursor != "" {
					t.Fatalf("stationary %s page = %#v, %v", test.name, page, err)
				}
			})
		}
	})

	t.Run("finalization cancellation withholds cursor", func(t *testing.T) {
		for _, cancelAt := range []int32{3, 4} {
			store := NewMemoryStore()
			service := testService(t, store, nil)
			service.blobs = &auditBlobListFaultStore{MemoryStore: store, page: &BlobPage{}}
			ctx := &cancelOnErrContext{Context: context.Background(), cancelAt: cancelAt}
			page, err := service.AuditInventory(ctx, AuditRequest{Kind: AuditKindBlobXorb})
			if !errors.Is(err, context.Canceled) || len(page.Items) != 0 || page.NextCursor != "" {
				t.Fatalf("finalization cancellation %d = %#v, %v", cancelAt, page, err)
			}
		}
	})
}

func TestAuditInventoryPointCheckBoundaries(t *testing.T) {
	graph := newAuditGraph(t)
	graph.store.mu.RLock()
	file := cloneFileRecord(graph.store.files[scopedHash{namespace: "tenant-a", hash: graph.file}])
	dedup := graph.store.dedup[scopedHash{namespace: "tenant-a", hash: graph.chunk}]
	var sha ScopedSHA256Association
	for key, hash := range graph.store.sha256 {
		sha = ScopedSHA256Association{
			Namespace: key.namespace,
			Record:    SHA256Association{Sum: key.sum, Size: key.size, File: hash},
		}
		break
	}
	xorbRecord := cloneXorbRecord(graph.store.xorbs[graph.xorb.Hash])
	graph.store.mu.RUnlock()
	scopedFile := ScopedFileRecord{Namespace: "tenant-a", Record: file}
	scopedDedup := ScopedDedupRecord{Namespace: "tenant-a", Chunk: graph.chunk, Record: dedup}

	sentinel := errors.New("injected audit point lookup")
	faults := &auditFaultIndex{MemoryStore: graph.store, getXorbErr: make(map[xethash.Hash]error)}
	graph.service.index = faults
	faults.getShardErr = sentinel
	for _, result := range []AuditResult{
		graph.service.auditFileRecord(context.Background(), scopedFile),
		graph.service.auditDedupRecord(context.Background(), scopedDedup),
	} {
		requireAuditResult(t, result, AuditStatusFailed, AuditFindingCheckFailed)
		if !errors.Is(result.Err, sentinel) {
			t.Fatalf("shard lookup error = %v", result.Err)
		}
	}
	faults.getShardErr = nil
	faults.getXorbErr[graph.xorb.Hash] = sentinel
	result := graph.service.auditFileRecord(context.Background(), scopedFile)
	requireAuditResult(t, result, AuditStatusFailed, AuditFindingCheckFailed)
	faults.getXorbErr = make(map[xethash.Hash]error)
	faults.getFileErr = sentinel
	for _, result := range []AuditResult{
		graph.service.auditSHA256Association(context.Background(), sha),
		graph.service.auditFileLease(context.Background(), graph.lease),
	} {
		requireAuditResult(t, result, AuditStatusFailed, AuditFindingCheckFailed)
	}
	faults.getFileErr = nil
	missingSHA := sha
	graph.store.mu.Lock()
	fileKey := scopedHash{namespace: sha.Namespace, hash: sha.Record.File}
	storedFile := graph.store.files[fileKey]
	storedFile.File.File.SHA256 = nil
	graph.store.files[fileKey] = storedFile
	graph.store.mu.Unlock()
	result = graph.service.auditSHA256Association(context.Background(), missingSHA)
	requireAuditResult(t, result, AuditStatusNoIssueFound, AuditFindingNone)
	graph.store.mu.Lock()
	storedFile.File.File.SHA256 = &sha.Record.Sum
	graph.store.files[fileKey] = storedFile
	graph.store.mu.Unlock()
	wrongSHA := sha
	wrongSHA.Record.Sum[0] ^= 0xff
	result = graph.service.auditSHA256Association(context.Background(), wrongSHA)
	requireAuditResult(t, result, AuditStatusNoIssueFound, AuditFindingNone)
	wrongSize := sha
	wrongSize.Record.Size++
	result = graph.service.auditSHA256Association(context.Background(), wrongSize)
	requireAuditResult(t, result, AuditStatusIssue, AuditFindingRecordInvalid)

	faults.getXorbErr[graph.xorb.Hash] = ErrCorrupt
	result = graph.service.auditBlobInventory(context.Background(), AuditKindBlobXorb, BlobEntry{
		Key: graph.xorb, Info: BlobInfo{Size: 1},
	})
	requireAuditResult(t, result, AuditStatusIssue, AuditFindingRecordInvalid)
	faults.getXorbErr = make(map[xethash.Hash]error)

	expectedXorbSize, err := xorb.ValidateIngested(&xorbRecord.Layout)
	if err != nil {
		t.Fatal(err)
	}
	for _, size := range []int64{expectedXorbSize - 1, expectedXorbSize + 1} {
		graph.service.blobs = &auditHeadFaultStore{MemoryStore: graph.store, info: &BlobInfo{Size: size}}
		result = graph.service.auditXorbRecord(context.Background(), xorbRecord)
		requireAuditResult(t, result, AuditStatusIssue, AuditFindingBlobSizeInvalid)
	}
	result = graph.service.auditBlobInventory(context.Background(), AuditKindBlobXorb, BlobEntry{
		Key: graph.xorb, Info: BlobInfo{Size: expectedXorbSize + 1},
	})
	requireAuditResult(t, result, AuditStatusIssue, AuditFindingBlobSizeInvalid)
	graph.service.blobs = &auditHeadFaultStore{MemoryStore: graph.store, err: sentinel}
	result = graph.service.auditXorbRecord(context.Background(), xorbRecord)
	requireAuditResult(t, result, AuditStatusFailed, AuditFindingCheckFailed)
	graph.service.blobs = &auditHeadFaultStore{MemoryStore: graph.store, err: ErrCorrupt}
	result = graph.service.auditXorbRecord(context.Background(), xorbRecord)
	requireAuditResult(t, result, AuditStatusFailed, AuditFindingCheckFailed)
	graph.service.blobs = &auditHeadFaultStore{MemoryStore: graph.store, info: &BlobInfo{Size: 0}}
	result = graph.service.auditShardRecord(context.Background(), ScopedShardRecord{
		Namespace: "tenant-a", Record: ShardRecord{Blob: graph.shard},
	})
	requireAuditResult(t, result, AuditStatusIssue, AuditFindingBlobSizeInvalid)
	graph.service.blobs = graph.store

	result = graph.service.auditShardRecord(context.Background(), ScopedShardRecord{
		Namespace: "tenant-a", Record: ShardRecord{Blob: BlobKey{Kind: BlobXorb, Hash: graph.shard.Hash}},
	})
	requireAuditResult(t, result, AuditStatusIssue, AuditFindingRecordInvalid)
	result = graph.service.auditDedupRecord(context.Background(), ScopedDedupRecord{
		Namespace: "tenant-a", Chunk: graph.chunk,
		Record: DedupRecord{Shard: BlobKey{Kind: BlobXorb, Hash: graph.shard.Hash}},
	})
	requireAuditResult(t, result, AuditStatusIssue, AuditFindingRecordInvalid)
	result = graph.service.auditDedupRecord(context.Background(), ScopedDedupRecord{
		Namespace: "tenant-a", Record: DedupRecord{Shard: graph.shard},
	})
	requireAuditResult(t, result, AuditStatusIssue, AuditFindingRecordInvalid)
	zeroStage := graph.stage
	zeroStage.Blob.Hash = xethash.Zero
	result = graph.service.auditBlobStage(context.Background(), zeroStage)
	requireAuditResult(t, result, AuditStatusIssue, AuditFindingRecordInvalid)
	cloneScopedFile := func() ScopedFileRecord {
		return ScopedFileRecord{Namespace: scopedFile.Namespace, Record: cloneFileRecord(scopedFile.Record)}
	}
	invalidFile := cloneScopedFile()
	invalidFile.Record.Shard.Kind = BlobXorb
	result = graph.service.auditFileRecord(context.Background(), invalidFile)
	requireAuditResult(t, result, AuditStatusIssue, AuditFindingRecordInvalid)
	invalidFile = cloneScopedFile()
	invalidFile.Record.File.File.Terms[0].Verification = xethash.Zero
	result = graph.service.auditFileRecord(context.Background(), invalidFile)
	requireAuditResult(t, result, AuditStatusIssue, AuditFindingRecordInvalid)
	invalidFile = cloneScopedFile()
	invalidFile.Record.File.File.Hash = xethash.Chunk([]byte("wrong audited file identity"))
	result = graph.service.auditFileRecord(context.Background(), invalidFile)
	requireAuditResult(t, result, AuditStatusIssue, AuditFindingRecordInvalid)
	invalidFile = cloneScopedFile()
	invalidFile.Record.File.Size++
	result = graph.service.auditFileRecord(context.Background(), invalidFile)
	requireAuditResult(t, result, AuditStatusIssue, AuditFindingRecordInvalid)

	invalidShard := ShardRecord{Blob: BlobKey{Kind: BlobXorb, Hash: graph.shard.Hash}}
	faults.getShardValue = &invalidShard
	result = graph.service.auditFileRecord(context.Background(), scopedFile)
	requireAuditResult(t, result, AuditStatusIssue, AuditFindingRecordInvalid)
	result = graph.service.auditDedupRecord(context.Background(), scopedDedup)
	requireAuditResult(t, result, AuditStatusIssue, AuditFindingRecordInvalid)
	faults.getShardValue = nil

	cancelAfterXorbHead, cancel := context.WithCancel(context.Background())
	graph.service.blobs = &cancelingAuditBlobStore{MemoryStore: graph.store, cancel: cancel, cancelAt: 2}
	result = graph.service.auditFileRecord(cancelAfterXorbHead, scopedFile)
	if !errors.Is(result.Err, context.Canceled) {
		t.Fatalf("file dependency cancellation = %v", result.Err)
	}
	graph.service.blobs = graph.store

	corruptXorb := xorbRecord
	corruptXorb.Blob.Hash = xethash.Chunk([]byte("wrong audit Xorb identity"))
	if _, err := ValidateXorbRecord(graph.xorb.Hash, corruptXorb); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("Xorb identity validation = %v", err)
	}
	corruptXorb = xorbRecord
	corruptXorb.Layout.Chunks = nil
	if _, err := ValidateXorbRecord(graph.xorb.Hash, corruptXorb); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("Xorb layout validation = %v", err)
	}
	corruptXorb = xorbRecord
	corruptXorb.Layout.Complete = []byte{1}
	if _, err := ValidateXorbRecord(graph.xorb.Hash, corruptXorb); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("persisted Xorb payload retention = %v", err)
	}
	if err := validateAuditBlobSize(BlobKey{Kind: "unknown", Hash: graph.xorb.Hash}, BlobInfo{Size: 1}); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("unknown blob validation = %v", err)
	}
	result = graph.service.auditBlobInventory(context.Background(), AuditKindBlobXorb, BlobEntry{
		Key: BlobKey{Kind: BlobShard, Hash: graph.xorb.Hash}, Info: BlobInfo{Size: 1},
	})
	requireAuditResult(t, result, AuditStatusIssue, AuditFindingRecordInvalid)

	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	result = graph.service.auditFileRecord(canceled, scopedFile)
	if !errors.Is(result.Err, context.Canceled) {
		t.Fatalf("file audit cancellation = %v", result.Err)
	}
	if !errors.Is(auditContextError(context.DeadlineExceeded), context.DeadlineExceeded) {
		t.Fatal("deadline audit context was not preserved")
	}

	wantCodes := map[AuditKind]byte{
		AuditKindBlobXorb: 1, AuditKindBlobShard: 2, AuditKindXorbRecord: 3,
		AuditKindShardRecord: 4, AuditKindFileRecord: 5, AuditKindDedupRecord: 6,
		AuditKindSHA256Association: 7, AuditKindBlobStage: 8, AuditKindFileLease: 9,
	}
	for kind, want := range wantCodes {
		if got, ok := auditKindCode(kind); !ok || got != want {
			t.Fatalf("audit kind code %q = %d, %v", kind, got, ok)
		}
	}
	if _, ok := auditKindCode("unknown"); ok {
		t.Fatal("unknown audit kind has a cursor code")
	}
	if _, err := decodeAuditCursor(encodeAuditCursor(AuditKindBlobXorb, nil, ""), AuditKindBlobXorb, nil); !errors.Is(err, ErrInvalid) {
		t.Fatalf("empty nested audit cursor = %v", err)
	}
	malformedLength := []byte{cursorAuditEnvelope, 1, 0, 0xff, 0xff, 0xff, 0xff, 'x'}
	if _, err := decodeAuditCursor(base64.RawURLEncoding.EncodeToString(malformedLength), AuditKindBlobXorb, nil); !errors.Is(err, ErrInvalid) {
		t.Fatalf("malformed audit namespace length = %v", err)
	}
}

func TestAuditInventoryPointFailuresAndCancellation(t *testing.T) {
	t.Run("point failure does not stop page", func(t *testing.T) {
		store := NewMemoryStore()
		index := &auditFaultIndex{MemoryStore: store, getXorbErr: make(map[xethash.Hash]error)}
		service := testService(t, store, index)
		objects := make([]*xorb.Object, 0, 2)
		for i := range 2 {
			object, err := xorb.Encode([][]byte{[]byte(fmt.Sprintf("audit point object %d", i))}, xorb.None)
			if err != nil {
				t.Fatal(err)
			}
			objects = append(objects, object)
			if _, err := service.UploadXorb(context.Background(), "", xetcas.DefaultXorbPrefix, object.Hash,
				bytes.NewReader(object.Body), int64(len(object.Body))); err != nil {
				t.Fatal(err)
			}
		}
		sentinel := errors.New("injected audit point failure")
		index.mu.Lock()
		index.getXorbErr[objects[0].Hash] = sentinel
		index.mu.Unlock()
		page, err := service.AuditInventory(context.Background(), AuditRequest{Kind: AuditKindBlobXorb})
		if err != nil || len(page.Items) != 2 {
			t.Fatalf("point-failure page = %#v, %v", page, err)
		}
		statuses := make(map[AuditStatus]int)
		for _, result := range page.Items {
			statuses[result.Status]++
			if result.Status == AuditStatusFailed && !errors.Is(result.Err, sentinel) {
				t.Fatalf("failed point error = %v", result.Err)
			}
		}
		if statuses[AuditStatusFailed] != 1 || statuses[AuditStatusNoIssueFound] != 1 {
			t.Fatalf("point-failure statuses = %#v", statuses)
		}
	})

	t.Run("lister failure is top level", func(t *testing.T) {
		store := NewMemoryStore()
		sentinel := errors.New("injected audit lister failure")
		index := &auditFaultIndex{MemoryStore: store, listXorbErr: sentinel}
		service := testService(t, store, index)
		if page, err := service.AuditInventory(context.Background(), AuditRequest{Kind: AuditKindXorbRecord}); !errors.Is(err, sentinel) || len(page.Items) != 0 || page.NextCursor != "" {
			t.Fatalf("lister failure = %#v, %v", page, err)
		}
	})

	t.Run("partial page cancellation does not advance", func(t *testing.T) {
		store := NewMemoryStore()
		service := testService(t, store, nil)
		for i := range 2 {
			object, err := xorb.Encode([][]byte{[]byte(fmt.Sprintf("audit cancellation object %d", i))}, xorb.None)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := service.UploadXorb(context.Background(), "", xetcas.DefaultXorbPrefix, object.Hash,
				bytes.NewReader(object.Body), int64(len(object.Body))); err != nil {
				t.Fatal(err)
			}
		}
		ctx, cancel := context.WithCancel(context.Background())
		service.blobs = &cancelingAuditBlobStore{MemoryStore: store, cancel: cancel, cancelAt: 2}
		page, err := service.AuditInventory(ctx, AuditRequest{
			Kind: AuditKindXorbRecord, Page: PageRequest{Limit: 2},
		})
		if !errors.Is(err, context.Canceled) || len(page.Items) != 1 || page.NextCursor != "" {
			t.Fatalf("canceled audit page = %#v, %v", page, err)
		}
	})

	t.Run("cancellation after final lookup does not publish a result", func(t *testing.T) {
		graph := newAuditGraph(t)
		ctx, cancel := context.WithCancel(context.Background())
		graph.service.blobs = &cancelingAuditBlobStore{
			MemoryStore: graph.store, cancel: cancel, cancelAt: 1,
		}
		page, err := graph.service.AuditInventory(ctx, AuditRequest{Kind: AuditKindXorbRecord})
		if !errors.Is(err, context.Canceled) || len(page.Items) != 0 || page.NextCursor != "" {
			t.Fatalf("final-lookup cancellation = %#v, %v", page, err)
		}
	})

	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if page, err := newAuditGraph(t).service.AuditInventory(canceled, AuditRequest{Kind: AuditKindBlobXorb}); !errors.Is(err, context.Canceled) || len(page.Items) != 0 {
		t.Fatalf("pre-canceled audit = %#v, %v", page, err)
	}
}

func TestDurableAuditInventoryAcrossRestart(t *testing.T) {
	requireLocalDurability(t)
	root := t.TempDir()
	blobRoot, indexPath := filepath.Join(root, "blobs"), filepath.Join(root, "index.db")
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
			Signer: RangeURLSignerFunc(func(context.Context, BlobKey, xetcas.HTTPRange) (SignedRange, error) {
				return signedTestRange("https://storage.example/audit"), nil
			}),
			Authorizer:         AllowAllAuthorizer{},
			DedupProtectionKey: xethash.Chunk([]byte("durable audit dedup key")),
		})
		if err != nil {
			_ = index.Close()
			_ = blobs.Close()
			t.Fatal(err)
		}
		return blobs, index, service
	}
	blobs, index, service := open(t)
	none, _, value, shardBody := uploadFixture(t)
	ctx := context.Background()
	if _, err := service.UploadXorb(ctx, "", xetcas.DefaultXorbPrefix, none.Hash,
		bytes.NewReader(none.Body), int64(len(none.Body))); err != nil {
		t.Fatal(err)
	}
	if _, err := service.UploadShard(ctx, "", bytes.NewReader(shardBody), int64(len(shardBody))); err != nil {
		t.Fatal(err)
	}
	createdAt := time.Date(2026, time.August, 10, 18, 0, 0, 0, time.UTC)
	if err := index.PutFileLease(ctx, FileLease{
		ID: testProtectionID(240), File: value.Files[0].Hash,
		CreatedAt: createdAt, ExpiresAt: createdAt.Add(time.Hour),
	}); err != nil {
		t.Fatal(err)
	}
	before := make(map[AuditKind][]AuditStatus)
	for _, kind := range []AuditKind{AuditKindBlobXorb, AuditKindBlobShard, AuditKindXorbRecord, AuditKindShardRecord, AuditKindFileRecord, AuditKindFileLease} {
		page, err := service.AuditInventory(ctx, AuditRequest{Kind: kind})
		if err != nil {
			t.Fatal(err)
		}
		for _, result := range page.Items {
			before[kind] = append(before[kind], result.Status)
		}
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
	for kind, want := range before {
		page, err := service.AuditInventory(ctx, AuditRequest{Kind: kind})
		if err != nil {
			t.Fatal(err)
		}
		got := make([]AuditStatus, 0, len(page.Items))
		for _, result := range page.Items {
			got = append(got, result.Status)
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("%s audit after restart = %v, want %v", kind, got, want)
		}
	}
}

var _ IndexLister = (*auditFaultIndex)(nil)
var _ BlobLister = (*cancelingAuditBlobStore)(nil)
