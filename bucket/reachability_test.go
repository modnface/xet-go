package bucket

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"testing"
	"time"

	"github.com/jmwoliver/xet-go/catalog"
	catalogmemory "github.com/jmwoliver/xet-go/catalog/memory"
	"github.com/jmwoliver/xet-go/content"
	contentmemory "github.com/jmwoliver/xet-go/content/memory"
	"github.com/jmwoliver/xet-go/model"
	"github.com/jmwoliver/xet-go/xetcas"
	casserver "github.com/jmwoliver/xet-go/xetcas/server"
	"github.com/jmwoliver/xet-go/xethash"
)

func TestAuditRefReachabilityPinsSnapshotAcrossRefAdvance(t *testing.T) {
	ctx := context.Background()
	repo := testRepo(t, "owner", "reachability")
	metadata := catalogmemory.New()
	ordinary := contentmemory.New()
	if err := metadata.CreateRepository(ctx, model.Repository{Key: repo, CreatedAt: time.Unix(1_700_700_000, 0)}); err != nil {
		t.Fatal(err)
	}
	body := []byte("reachable ordinary content")
	sum := sha256.Sum256(body)
	blobRef, err := model.NewBlobFileRef(sum, int64(len(body)))
	if err != nil {
		t.Fatal(err)
	}
	if inserted, err := ordinary.Put(ctx, content.Blob{SHA256: sum, Size: int64(len(body))}, bytes.NewReader(body)); err != nil || !inserted {
		t.Fatalf("ordinary put = %v, %v", inserted, err)
	}
	xetHash := xethash.Chunk([]byte("reachable Xet identity"))
	xetSum := sha256.Sum256([]byte("logical Xet bytes"))
	xetRef, err := model.NewXetFileRef(xetHash, 4321, &xetSum)
	if err != nil {
		t.Fatal(err)
	}
	firstOID := testOID(t, 'a')
	if err = metadata.PublishSnapshot(ctx, model.Snapshot{
		Repo: repo, OID: firstOID, CreatedAt: time.Unix(1_700_700_001, 0),
		Author: model.Identity{Name: "Auditor"}, Message: "first",
		Files: []model.FileEntry{{Path: "config.json", Ref: blobRef}, {Path: "weights.bin", Ref: xetRef}},
	}, catalog.ExpectRef("main", nil)); err != nil {
		t.Fatal(err)
	}
	var verification reachabilityVerification
	cas := &reachabilityCAS{verify: func(_ context.Context, namespace string, hash xethash.Hash, size uint64, sum *[32]byte) error {
		verification = reachabilityVerification{namespace: namespace, hash: hash, size: size, sum: sum}
		return nil
	}}
	service, err := New(Options{Catalog: metadata, Content: ordinary, CAS: cas})
	if err != nil {
		t.Fatal(err)
	}
	first, err := service.AuditRefReachability(ctx, ReachabilityAuditRequest{
		Repo: repo, Ref: "main", Limit: 1,
	})
	if err != nil || first.Root.SnapshotOID != firstOID || len(first.Items) != 1 || first.Items[0].Status != ReachabilityAuditNoIssueFound ||
		first.Items[0].Entry.Path != "config.json" || first.Items[0].Target == nil ||
		first.Items[0].Target.Blob.SHA256 != sum || first.Retry == nil || first.Retry.root != first.Root ||
		first.Retry.cursor != "" || first.Next == nil {
		t.Fatalf("first reachability page = %#v, %v", first, err)
	}
	secondOID := testOID(t, 'b')
	if err = metadata.PublishSnapshot(ctx, model.Snapshot{
		Repo: repo, OID: secondOID, Parent: &firstOID, CreatedAt: time.Unix(1_700_700_002, 0),
		Author: model.Identity{Name: "Auditor"}, Message: "empty second",
	}, catalog.ExpectRef("main", &firstOID)); err != nil {
		t.Fatal(err)
	}
	second, err := service.AuditRefReachability(ctx, ReachabilityAuditRequest{
		Repo: repo, Continuation: first.Next, Limit: 1,
	})
	if err != nil || second.Root.SnapshotOID != firstOID || len(second.Items) != 1 ||
		second.Items[0].Entry.Path != "weights.bin" || second.Items[0].Status != ReachabilityAuditNoIssueFound || second.Next != nil {
		t.Fatalf("pinned reachability page = %#v, %v", second, err)
	}
	wantNamespace := mustRepositoryNamespace(t, repo)
	if verification.namespace != wantNamespace || verification.hash != xetHash || verification.size != 4321 ||
		verification.sum == nil || *verification.sum != xetSum {
		t.Fatalf("Xet verification = %#v", verification)
	}
	if _, err = service.AuditRefReachability(ctx, ReachabilityAuditRequest{
		Repo: repo, Ref: "main", Continuation: first.Next, Limit: 1,
	}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("continuation with ref = %v", err)
	}
	current, err := service.AuditRefReachability(ctx, ReachabilityAuditRequest{Repo: repo, Ref: "main"})
	if err != nil || current.Root.SnapshotOID != secondOID || len(current.Items) != 0 {
		t.Fatalf("current reachability root = %#v, %v", current, err)
	}
}

func TestAuditRefReachabilityClassifiesMissingCorruptAndFailedDependencies(t *testing.T) {
	ctx := context.Background()
	repo := testRepo(t, "owner", "reachability-findings")
	metadata := catalogmemory.New()
	baseContent := contentmemory.New()
	ordinary := &reachabilityContent{Store: baseContent}
	if err := metadata.CreateRepository(ctx, model.Repository{Key: repo, CreatedAt: time.Unix(1_700_710_000, 0)}); err != nil {
		t.Fatal(err)
	}
	ordinaryRef := func(label string) model.FileRef {
		body := []byte(label)
		ref, err := model.NewBlobFileRef(sha256.Sum256(body), int64(len(body)))
		if err != nil {
			t.Fatal(err)
		}
		return ref
	}
	missingBlob := ordinaryRef("missing")
	notFoundBlob := ordinaryRef("not-found-error")
	wrongBlob := ordinaryRef("wrong-size")
	failedBlob := ordinaryRef("backend-failure")
	corruptBlob := ordinaryRef("corrupt")
	invalidBlob := ordinaryRef("invalid-head")
	wrongSum, _ := wrongBlob.SHA256()
	notFoundSum, _ := notFoundBlob.SHA256()
	failedSum, _ := failedBlob.SHA256()
	corruptSum, _ := corruptBlob.SHA256()
	invalidSum, _ := invalidBlob.SHA256()
	ordinary.head = func(ctx context.Context, sum [32]byte) (content.Info, bool, error) {
		switch sum {
		case notFoundSum:
			return content.Info{}, false, content.ErrNotFound
		case wrongSum:
			return content.Info{Size: wrongBlob.FileSize() + 1}, true, nil
		case failedSum:
			return content.Info{}, false, content.ErrUnavailable
		case corruptSum:
			return content.Info{}, false, content.ErrCorrupt
		case invalidSum:
			return content.Info{}, false, content.ErrInvalid
		default:
			return baseContent.Head(ctx, sum)
		}
	}
	xetRef := func(label string) model.FileRef {
		ref, err := model.NewXetFileRef(xethash.Chunk([]byte(label)), 10, nil)
		if err != nil {
			t.Fatal(err)
		}
		return ref
	}
	missingXet, corruptXet, failedXet, invalidXet, canceledXet := xetRef("missing-xet"), xetRef("corrupt-xet"),
		xetRef("failed-xet"), xetRef("invalid-xet"), xetRef("canceled-xet")
	missingHash, _ := missingXet.XetHash()
	corruptHash, _ := corruptXet.XetHash()
	failedHash, _ := failedXet.XetHash()
	invalidHash, _ := invalidXet.XetHash()
	canceledHash, _ := canceledXet.XetHash()
	backendFailure := errors.New("CAS backend failed")
	cas := &reachabilityCAS{verify: func(_ context.Context, _ string, hash xethash.Hash, _ uint64, _ *[32]byte) error {
		switch hash {
		case missingHash:
			return casserver.ErrNotFound
		case corruptHash:
			return casserver.ErrCorrupt
		case failedHash:
			return backendFailure
		case invalidHash:
			return casserver.ErrInvalid
		case canceledHash:
			return context.Canceled
		default:
			return nil
		}
	}}
	oid := testOID(t, 'c')
	if err := metadata.PublishSnapshot(ctx, model.Snapshot{
		Repo: repo, OID: oid, CreatedAt: time.Unix(1_700_710_001, 0),
		Author: model.Identity{Name: "Auditor"}, Message: "findings",
		Files: []model.FileEntry{
			{Path: "01-missing-blob", Ref: missingBlob},
			{Path: "02-not-found-blob", Ref: notFoundBlob},
			{Path: "03-wrong-blob", Ref: wrongBlob},
			{Path: "04-failed-blob", Ref: failedBlob},
			{Path: "05-corrupt-blob", Ref: corruptBlob},
			{Path: "06-invalid-blob", Ref: invalidBlob},
			{Path: "07-missing-xet", Ref: missingXet},
			{Path: "08-corrupt-xet", Ref: corruptXet},
			{Path: "09-failed-xet", Ref: failedXet},
			{Path: "10-invalid-xet", Ref: invalidXet},
		},
	}, catalog.ExpectRef("main", nil)); err != nil {
		t.Fatal(err)
	}
	service, err := New(Options{Catalog: metadata, Content: ordinary, CAS: cas})
	if err != nil {
		t.Fatal(err)
	}
	page, err := service.AuditRefReachability(ctx, ReachabilityAuditRequest{Repo: repo, Ref: "main"})
	if err != nil || len(page.Items) != 10 {
		t.Fatalf("reachability findings = %#v, %v", page, err)
	}
	wants := []struct {
		status  ReachabilityAuditStatus
		finding ReachabilityAuditFinding
		err     error
	}{
		{ReachabilityAuditIssue, ReachabilityFindingOrdinaryBlobMissing, nil},
		{ReachabilityAuditIssue, ReachabilityFindingOrdinaryBlobMissing, nil},
		{ReachabilityAuditIssue, ReachabilityFindingOrdinarySizeMismatch, ErrCorrupt},
		{ReachabilityAuditFailed, ReachabilityFindingCheckFailed, ErrUnavailable},
		{ReachabilityAuditIssue, ReachabilityFindingOrdinaryBlobInvalid, ErrCorrupt},
		{ReachabilityAuditFailed, ReachabilityFindingCheckFailed, ErrInvariant},
		{ReachabilityAuditIssue, ReachabilityFindingXetRequirementUnavailable, nil},
		{ReachabilityAuditIssue, ReachabilityFindingXetDependencyInvalid, ErrCorrupt},
		{ReachabilityAuditFailed, ReachabilityFindingCheckFailed, backendFailure},
		{ReachabilityAuditFailed, ReachabilityFindingCheckFailed, ErrInvariant},
	}
	for index, want := range wants {
		got := page.Items[index]
		if got.Target == nil || got.Status != want.status || got.Finding != want.finding ||
			(want.err == nil && got.Err != nil || want.err != nil && !errors.Is(got.Err, want.err)) {
			t.Fatalf("finding %d = %#v, want %#v", index, got, want)
		}
	}
	canceled := service.auditReachableFile(ctx, mustRepositoryNamespace(t, repo),
		model.FileEntry{Path: "canceled-xet", Ref: canceledXet})
	if canceled.Status != ReachabilityAuditFailed || canceled.Finding != ReachabilityFindingCheckFailed ||
		!errors.Is(canceled.Err, context.Canceled) {
		t.Fatalf("canceled Xet finding = %#v", canceled)
	}
}

func TestAuditRefReachabilityValidationAndCancellation(t *testing.T) {
	ctx := context.Background()
	repo := testRepo(t, "owner", "reachability-validation")
	metadata := catalogmemory.New()
	ordinary := contentmemory.New()
	cas := &reachabilityCAS{}
	service, err := New(Options{Catalog: metadata, Content: ordinary, CAS: cas})
	if err != nil {
		t.Fatal(err)
	}
	zero := model.OID{}
	validOID := testOID(t, 'e')
	validRoot := ReachabilityRoot{Repo: repo, Ref: "main", SnapshotOID: validOID}
	for _, request := range []ReachabilityAuditRequest{
		{}, {Repo: repo}, {Repo: repo, Ref: "bad ref"},
		{Repo: repo, Ref: "main", Continuation: &ReachabilityAuditContinuation{root: validRoot, cursor: "cursor", afterPath: "a"}},
		{Repo: repo, Continuation: &ReachabilityAuditContinuation{root: ReachabilityRoot{Repo: repo, Ref: "main", SnapshotOID: zero}, cursor: "cursor", afterPath: "a"}},
		{Repo: repo, Continuation: &ReachabilityAuditContinuation{root: validRoot, afterPath: "a"}},
		{Repo: repo, Continuation: &ReachabilityAuditContinuation{root: validRoot, cursor: "cursor", afterPath: "../bad"}},
		{Repo: repo, Ref: "main", Limit: -1},
		{Repo: repo, Ref: "main", Limit: catalog.MaxPageSize + 1},
	} {
		if _, err := service.AuditRefReachability(ctx, request); !errors.Is(err, ErrInvalid) {
			t.Fatalf("invalid request %#v = %v", request, err)
		}
	}
	if _, err := service.AuditRefReachability(nil, ReachabilityAuditRequest{Repo: repo, Ref: "main"}); !errors.Is(err, ErrInvalid) { //nolint:staticcheck // Verify nil rejection.
		t.Fatalf("nil context = %v", err)
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := service.AuditRefReachability(canceled, ReachabilityAuditRequest{Repo: repo, Ref: "main"}); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled request = %v", err)
	}
	if _, err := service.AuditRefReachability(ctx, ReachabilityAuditRequest{Repo: repo, Ref: "main"}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing ref = %v", err)
	}
	for name, page := range map[string]catalog.FilePage{
		"wrong snapshot":       {SnapshotOID: testOID(t, 'f')},
		"too many items":       {SnapshotOID: validOID, Items: make([]model.FileEntry, 2)},
		"empty continuation":   {SnapshotOID: validOID, NextCursor: "next"},
		"stalled continuation": {SnapshotOID: validOID, Items: []model.FileEntry{{}}, NextCursor: "same"},
		"duplicate paths":      {SnapshotOID: validOID, Items: []model.FileEntry{{Path: "a"}, {Path: "a"}}},
		"reversed paths":       {SnapshotOID: validOID, Items: []model.FileEntry{{Path: "b"}, {Path: "a"}}},
		"repeated prior path":  {SnapshotOID: validOID, Items: []model.FileEntry{{Path: "a"}}},
	} {
		t.Run(name, func(t *testing.T) {
			query := catalog.FileQuery{Limit: 1}
			if name == "stalled continuation" {
				query.Cursor = "same"
			}
			if name == "duplicate paths" || name == "reversed paths" {
				query.Limit = 2
			}
			var after model.FilePath
			if name == "repeated prior path" {
				after = "a"
			}
			if err := validateReachabilityFilePage(query, validOID, after, page); !errors.Is(err, ErrCorrupt) {
				t.Fatalf("invalid page = %v", err)
			}
		})
	}
	if err := validateReachabilityFilePage(catalog.FileQuery{}, validOID, "", catalog.FilePage{SnapshotOID: validOID}); err != nil {
		t.Fatalf("valid empty page = %v", err)
	}

	validRef, _ := model.NewBlobFileRef(sha256.Sum256(nil), 0)
	badEntry := model.FileEntry{Path: "../bad", Ref: validRef}
	result := service.auditReachableFile(ctx, mustRepositoryNamespace(t, repo), badEntry)
	if result.Finding != ReachabilityFindingRecordInvalid || !errors.Is(result.Err, ErrCorrupt) ||
		result.Target == nil || result.Target.Blob.SHA256 != sha256.Sum256(nil) {
		t.Fatalf("invalid catalog entry = %#v", result)
	}
	result = service.auditReachableFile(ctx, mustRepositoryNamespace(t, repo), model.FileEntry{Path: "valid"})
	if result.Finding != ReachabilityFindingRecordInvalid || !errors.Is(result.Err, ErrCorrupt) || result.Target != nil {
		t.Fatalf("unknown file kind = %#v", result)
	}
}

func TestAuditRefReachabilityCancellationRetryRemainsPinned(t *testing.T) {
	ctx := context.Background()
	repo := testRepo(t, "owner", "reachability-retry")
	metadata := catalogmemory.New()
	baseContent := contentmemory.New()
	if err := metadata.CreateRepository(ctx, model.Repository{Key: repo, CreatedAt: time.Unix(1_700_720_000, 0)}); err != nil {
		t.Fatal(err)
	}
	fileRef := func(value string) model.FileRef {
		ref, err := model.NewBlobFileRef(sha256.Sum256([]byte(value)), int64(len(value)))
		if err != nil {
			t.Fatal(err)
		}
		return ref
	}
	firstRef, secondRef := fileRef("one"), fileRef("two")
	firstOID := testOID(t, '1')
	if err := metadata.PublishSnapshot(ctx, model.Snapshot{
		Repo: repo, OID: firstOID, CreatedAt: time.Unix(1_700_720_001, 0),
		Author: model.Identity{Name: "Auditor"}, Message: "first",
		Files: []model.FileEntry{{Path: "one", Ref: firstRef}, {Path: "two", Ref: secondRef}},
	}, catalog.ExpectRef("main", nil)); err != nil {
		t.Fatal(err)
	}
	canceled, cancel := context.WithCancel(ctx)
	checks := 0
	ordinary := &reachabilityContent{Store: baseContent}
	ordinary.head = func(_ context.Context, sum [32]byte) (content.Info, bool, error) {
		checks++
		if checks == 2 {
			cancel()
			return content.Info{}, false, canceled.Err()
		}
		return content.Info{Size: firstRef.FileSize()}, true, nil
	}
	service, err := New(Options{Catalog: metadata, Content: ordinary, CAS: &reachabilityCAS{}})
	if err != nil {
		t.Fatal(err)
	}
	page, err := service.AuditRefReachability(canceled, ReachabilityAuditRequest{Repo: repo, Ref: "main"})
	if !errors.Is(err, context.Canceled) || page.Root.SnapshotOID != firstOID || page.Retry == nil ||
		page.Retry.root != page.Root || page.Retry.cursor != "" || len(page.Items) != 1 || page.Next != nil {
		t.Fatalf("canceled page = %#v, %v", page, err)
	}
	secondOID := testOID(t, '2')
	if err = metadata.PublishSnapshot(ctx, model.Snapshot{
		Repo: repo, OID: secondOID, Parent: &firstOID, CreatedAt: time.Unix(1_700_720_002, 0),
		Author: model.Identity{Name: "Auditor"}, Message: "second",
	}, catalog.ExpectRef("main", &firstOID)); err != nil {
		t.Fatal(err)
	}
	ordinary.head = func(_ context.Context, _ [32]byte) (content.Info, bool, error) {
		return content.Info{Size: firstRef.FileSize()}, true, nil
	}
	retried, err := service.AuditRefReachability(ctx, ReachabilityAuditRequest{Repo: repo, Continuation: page.Retry})
	if err != nil || retried.Root.SnapshotOID != firstOID || len(retried.Items) != 2 || retried.Next != nil {
		t.Fatalf("retried pinned page = %#v, %v", retried, err)
	}
	current, err := service.AuditRefReachability(ctx, ReachabilityAuditRequest{Repo: repo, Ref: "main"})
	if err != nil || current.Root.SnapshotOID != secondOID || len(current.Items) != 0 {
		t.Fatalf("advanced current page = %#v, %v", current, err)
	}
}

func TestAuditRefReachabilityPreservesRootAndTargetsOnCatalogFailure(t *testing.T) {
	ctx := context.Background()
	repo := testRepo(t, "owner", "reachability-catalog-failure")
	metadata := catalogmemory.New()
	ordinary := contentmemory.New()
	if err := metadata.CreateRepository(ctx, model.Repository{Key: repo, CreatedAt: time.Unix(1_700_730_000, 0)}); err != nil {
		t.Fatal(err)
	}
	oid := testOID(t, '3')
	if err := metadata.PublishSnapshot(ctx, model.Snapshot{
		Repo: repo, OID: oid, CreatedAt: time.Unix(1_700_730_001, 0),
		Author: model.Identity{Name: "Auditor"}, Message: "root",
	}, catalog.ExpectRef("main", nil)); err != nil {
		t.Fatal(err)
	}
	fault := &reachabilityCatalog{Catalog: metadata, listErr: catalog.ErrUnavailable}
	service, err := New(Options{Catalog: fault, Content: ordinary, CAS: &reachabilityCAS{}})
	if err != nil {
		t.Fatal(err)
	}
	page, err := service.AuditRefReachability(ctx, ReachabilityAuditRequest{Repo: repo, Ref: "main"})
	if !errors.Is(err, ErrUnavailable) || page.Root.SnapshotOID != oid || page.Retry == nil ||
		page.Retry.root != page.Root || len(page.Items) != 0 || page.Next != nil {
		t.Fatalf("catalog failure page = %#v, %v", page, err)
	}

	ref, err := model.NewBlobFileRef(sha256.Sum256(nil), 0)
	if err != nil {
		t.Fatal(err)
	}
	fault.listErr = nil
	fault.page = catalog.FilePage{
		SnapshotOID: oid,
		Items:       []model.FileEntry{{Path: "../bad", Ref: ref}},
		NextCursor:  "unsafe-next",
	}
	page, err = service.AuditRefReachability(ctx, ReachabilityAuditRequest{Repo: repo, Ref: "main", Limit: 1})
	if !errors.Is(err, ErrCorrupt) || len(page.Items) != 1 || page.Items[0].Target == nil ||
		page.Items[0].Finding != ReachabilityFindingRecordInvalid || page.Next != nil {
		t.Fatalf("invalid path page = %#v, %v", page, err)
	}
}

type reachabilityContent struct {
	content.Store
	head func(context.Context, [32]byte) (content.Info, bool, error)
}

func (store *reachabilityContent) Head(ctx context.Context, sum [32]byte) (content.Info, bool, error) {
	return store.head(ctx, sum)
}

type reachabilityCatalog struct {
	catalog.Catalog
	page    catalog.FilePage
	listErr error
}

func (store *reachabilityCatalog) ListFiles(
	context.Context,
	model.RepoKey,
	model.Revision,
	catalog.FileQuery,
) (catalog.FilePage, error) {
	return store.page, store.listErr
}

type reachabilityCAS struct {
	verify func(context.Context, string, xethash.Hash, uint64, *[32]byte) error
}

func (*reachabilityCAS) OpenFileInNamespace(
	context.Context,
	string,
	xethash.Hash,
	*xetcas.FileRange,
) (*casserver.OpenedFile, error) {
	return nil, errors.New("unused reachability stream")
}

func (service *reachabilityCAS) VerifyFileInNamespace(
	ctx context.Context,
	namespace string,
	hash xethash.Hash,
	size uint64,
	sum *[32]byte,
) error {
	if service.verify == nil {
		return errors.New("unused reachability verifier")
	}
	return service.verify(ctx, namespace, hash, size, sum)
}

type reachabilityVerification struct {
	namespace string
	hash      xethash.Hash
	size      uint64
	sum       *[32]byte
}
