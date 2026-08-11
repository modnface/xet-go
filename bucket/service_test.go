package bucket

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jmwoliver/xet-go/catalog"
	catalogmemory "github.com/jmwoliver/xet-go/catalog/memory"
	catalogsqlite "github.com/jmwoliver/xet-go/catalog/sqlite"
	"github.com/jmwoliver/xet-go/content"
	contentfilesystem "github.com/jmwoliver/xet-go/content/filesystem"
	contentmemory "github.com/jmwoliver/xet-go/content/memory"
	"github.com/jmwoliver/xet-go/model"
	"github.com/jmwoliver/xet-go/shard"
	"github.com/jmwoliver/xet-go/xetcas"
	casserver "github.com/jmwoliver/xet-go/xetcas/server"
	"github.com/jmwoliver/xet-go/xethash"
	"github.com/jmwoliver/xet-go/xorb"
)

type catalogWithoutRefListing struct{ catalog.Catalog }

func TestServiceStreamsOrdinaryAndXetFiles(t *testing.T) {
	ctx := context.Background()
	repo := testRepo(t, "owner", "model")
	namespace, err := RepositoryNamespace(repo)
	if err != nil || namespace == "" || strings.Contains(namespace, "/") {
		t.Fatalf("repository namespace = %q, %v", namespace, err)
	}
	other := testRepo(t, "owner", "other")
	otherNamespace, err := RepositoryNamespace(other)
	if err != nil || otherNamespace == namespace {
		t.Fatalf("other repository namespace = %q, %v", otherNamespace, err)
	}
	if _, err := RepositoryNamespace(model.RepoKey{}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("invalid repository namespace = %v", err)
	}

	metadata := catalogmemory.New()
	ordinary := contentmemory.New()
	casStore := casserver.NewMemoryStore()
	cas, err := casserver.New(casserver.Options{
		Blobs: casStore, Index: casStore,
		Authorizer: casserver.AllowAllAuthorizer{Namespace: namespace},
		Signer: casserver.RangeURLSignerFunc(func(context.Context, casserver.BlobKey, xetcas.HTTPRange) (casserver.SignedRange, error) {
			return casserver.SignedRange{URL: "https://storage.example/object", ExpiresAt: time.Now().Add(time.Hour)}, nil
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	service, err := New(Options{Catalog: metadata, Content: ordinary, CAS: cas})
	if err != nil {
		t.Fatal(err)
	}
	repository := model.Repository{Key: repo, CreatedAt: time.Unix(1_700_000_000, 0)}
	if err = service.CreateRepository(ctx, repository); err != nil {
		t.Fatal(err)
	}

	ordinaryBody := []byte("{\"model_type\":\"xet-go-test\"}\n")
	ordinarySum := sha256.Sum256(ordinaryBody)
	ordinaryRef, err := model.NewBlobFileRef(ordinarySum, int64(len(ordinaryBody)))
	if err != nil {
		t.Fatal(err)
	}
	if inserted, putErr := service.PutBlob(ctx, content.Blob{SHA256: ordinarySum, Size: int64(len(ordinaryBody))}, bytes.NewReader(ordinaryBody)); putErr != nil || !inserted {
		t.Fatalf("ordinary put = %v, %v", inserted, putErr)
	}
	emptySum := sha256.Sum256(nil)
	emptyRef, err := model.NewBlobFileRef(emptySum, 0)
	if err != nil {
		t.Fatal(err)
	}
	if inserted, putErr := service.PutBlob(ctx, content.Blob{SHA256: emptySum, Size: 0}, bytes.NewReader(nil)); putErr != nil || !inserted {
		t.Fatalf("empty ordinary put = %v, %v", inserted, putErr)
	}

	xetBody, fileHash, xetSum := publishXetFixture(t, ctx, cas)
	xetRef, err := model.NewXetFileRef(fileHash, int64(len(xetBody)), &xetSum)
	if err != nil {
		t.Fatal(err)
	}
	oid := testOID(t, '1')
	snapshot := model.Snapshot{
		Repo: repo, OID: oid, CreatedAt: time.Unix(1_700_000_001, 0),
		Author: model.Identity{Name: "Test Author"}, Message: "initial snapshot",
		Files: []model.FileEntry{
			{Path: "weights/model.safetensors", Ref: xetRef},
			{Path: "config.json", Ref: ordinaryRef},
			{Path: "config-copy.json", Ref: ordinaryRef},
			{Path: "empty.txt", Ref: emptyRef},
		},
	}
	if err = service.PublishSnapshot(ctx, snapshot, catalog.ExpectRef("main", nil)); err != nil {
		t.Fatal(err)
	}
	revision, err := model.ParseRevision("main")
	if err != nil {
		t.Fatal(err)
	}

	if got, err := service.GetRepository(ctx, repo); err != nil || got.Key != repo {
		t.Fatalf("get repository = %#v, %v", got, err)
	}
	if page, err := service.ListRepositories(ctx, catalog.RepositoryQuery{}); err != nil || len(page.Items) != 1 {
		t.Fatalf("list repositories = %#v, %v", page, err)
	}
	if got, err := service.ResolveRevision(ctx, repo, revision); err != nil || got.OID != oid {
		t.Fatalf("resolve revision = %#v, %v", got, err)
	}
	if got, err := service.GetSnapshot(ctx, repo, oid); err != nil || got.OID != oid {
		t.Fatalf("get snapshot = %#v, %v", got, err)
	}
	if page, err := service.ListSnapshots(ctx, repo, catalog.SnapshotQuery{}); err != nil || len(page.Items) != 1 {
		t.Fatalf("list snapshots = %#v, %v", page, err)
	}
	if ref, err := service.GetRef(ctx, repo, "main"); err != nil || ref.OID != oid {
		t.Fatalf("get main ref = %#v, %v", ref, err)
	}
	if err := service.CompareAndSwapRef(ctx, repo, "release", nil, oid); err != nil {
		t.Fatalf("create release ref: %v", err)
	}
	if ref, err := service.GetRef(ctx, repo, "release"); err != nil || ref.OID != oid {
		t.Fatalf("get release ref = %#v, %v", ref, err)
	}
	firstRefs, err := service.ListRefs(ctx, repo, catalog.RefQuery{Limit: 1})
	if err != nil || len(firstRefs.Items) != 1 || firstRefs.Items[0].Name != "main" || firstRefs.NextCursor == "" {
		t.Fatalf("first ref page = %#v, %v", firstRefs, err)
	}
	secondRefs, err := service.ListRefs(ctx, repo, catalog.RefQuery{Limit: 1, Cursor: firstRefs.NextCursor})
	if err != nil || len(secondRefs.Items) != 1 || secondRefs.Items[0].Name != "release" || secondRefs.NextCursor != "" {
		t.Fatalf("second ref page = %#v, %v", secondRefs, err)
	}
	if page, err := service.ListFiles(ctx, repo, revision, catalog.FileQuery{}); err != nil || len(page.Items) != 4 || page.SnapshotOID != oid {
		t.Fatalf("list files = %#v, %v", page, err)
	}

	assertOpenFile(t, service, repo, revision, "config.json", nil, ordinaryBody, model.FileKindBlob, "sha256:")
	assertOpenFile(t, service, repo, revision, "config-copy.json", nil, ordinaryBody, model.FileKindBlob, "sha256:")
	assertOpenFile(t, service, repo, revision, "empty.txt", nil, nil, model.FileKindBlob, "sha256:")
	ordinaryRange := content.Range{Start: 2, End: int64(len(ordinaryBody) - 3)}
	assertOpenFile(t, service, repo, revision, "config.json", &ordinaryRange,
		ordinaryBody[ordinaryRange.Start:ordinaryRange.End], model.FileKindBlob, "sha256:")
	assertOpenFile(t, service, repo, revision, "weights/model.safetensors", nil, xetBody, model.FileKindXet, "sha256:")
	xetRange := content.Range{Start: 7, End: int64(len(xetBody) - 11)}
	assertOpenFile(t, service, repo, revision, "weights/model.safetensors", &xetRange,
		xetBody[xetRange.Start:xetRange.End], model.FileKindXet, "sha256:")

	invalidRange := content.Range{Start: 0, End: int64(len(ordinaryBody) + 1)}
	if _, err := service.OpenFile(ctx, repo, revision, "config.json", OpenOptions{Range: &invalidRange}); !errors.Is(err, ErrRangeNotSatisfiable) {
		t.Fatalf("invalid range = %v", err)
	}
	if _, err := service.OpenFile(ctx, repo, revision, "missing", OpenOptions{}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing file = %v", err)
	}

	otherRepository := model.Repository{Key: other, CreatedAt: time.Unix(1_700_000_002, 0)}
	if err = service.CreateRepository(ctx, otherRepository); err != nil {
		t.Fatal(err)
	}
	otherOID := testOID(t, '3')
	otherSnapshot := model.Snapshot{
		Repo: other, OID: otherOID, CreatedAt: time.Unix(1_700_000_003, 0),
		Author: model.Identity{Name: "Other"}, Message: "same Xet identity, different repository",
		Files: []model.FileEntry{{Path: "weights/model.safetensors", Ref: xetRef}},
	}
	if err = service.PublishSnapshot(ctx, otherSnapshot, catalog.ExpectRef("main", nil)); !errors.Is(err, ErrContentNotUploaded) {
		t.Fatalf("cross-repository publication = %v", err)
	}
	if _, err := service.GetSnapshot(ctx, other, otherOID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-repository publication exposed snapshot = %v", err)
	}
	if _, err := service.GetRef(ctx, other, "main"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-repository publication exposed ref = %v", err)
	}
	if err = metadata.PublishSnapshot(ctx, model.Snapshot{
		Repo: otherSnapshot.Repo, OID: otherSnapshot.OID, CreatedAt: otherSnapshot.CreatedAt,
		Author: otherSnapshot.Author, Message: otherSnapshot.Message, Files: otherSnapshot.Files,
	}, catalog.ExpectRef("main", nil)); err != nil {
		t.Fatal(err)
	}
	if _, err := service.OpenFile(ctx, other, revision, "weights/model.safetensors", OpenOptions{}); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("cross-repository Xet read = %v", err)
	}

	secondOID := testOID(t, '4')
	if err = service.PublishSnapshot(ctx, model.Snapshot{
		Repo: repo, OID: secondOID, Parent: &oid, CreatedAt: time.Unix(1_700_000_004, 0),
		Author: model.Identity{Name: "Test Author"}, Message: "delete ordinary files",
		Files: []model.FileEntry{{Path: "weights/model.safetensors", Ref: xetRef}},
	}, catalog.ExpectRef("main", &oid)); err != nil {
		t.Fatal(err)
	}
	if got, err := service.ResolveRevision(ctx, repo, revision); err != nil || got.OID != secondOID {
		t.Fatalf("updated main = %#v, %v", got, err)
	}
	oldRevision, err := model.ParseRevision(oid.String())
	if err != nil {
		t.Fatal(err)
	}
	assertOpenFile(t, service, repo, oldRevision, "config.json", nil, ordinaryBody, model.FileKindBlob, "sha256:")
	if _, err := service.OpenFile(ctx, repo, revision, "config.json", OpenOptions{}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("deleted file at updated main = %v", err)
	}
}

func TestServiceConfigurationAndErrors(t *testing.T) {
	if _, err := New(Options{}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("empty options = %v", err)
	}
	metadata := catalogmemory.New()
	ordinary := contentmemory.New()
	cas := casOpenerFunc(func(context.Context, string, xethash.Hash, *xetcas.FileRange) (*casserver.OpenedFile, error) {
		return nil, errors.New("unused")
	})
	for name, options := range map[string]Options{
		"catalog": {Content: ordinary, CAS: cas},
		"content": {Catalog: metadata, CAS: cas},
		"CAS":     {Catalog: metadata, Content: ordinary},
	} {
		if _, err := New(options); !errors.Is(err, ErrInvalid) {
			t.Fatalf("missing %s = %v", name, err)
		}
	}
	service, err := New(Options{Catalog: metadata, Content: ordinary, CAS: cas})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.GetRepository(nil, model.RepoKey{}); !errors.Is(err, ErrInvalid) { //nolint:staticcheck // Verify nil-context rejection.
		t.Fatalf("nil context = %v", err)
	}
	withoutRefs, err := New(Options{Catalog: catalogWithoutRefListing{metadata}, Content: ordinary, CAS: cas})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := withoutRefs.ListRefs(context.Background(), testRepo(t, "owner", "unsupported-refs"), catalog.RefQuery{}); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("unsupported ref inventory = %v", err)
	}
	validRepo := testRepo(t, "owner", "input-validation")
	validRevision, err := model.ParseRevision("main")
	if err != nil {
		t.Fatal(err)
	}
	validOID := testOID(t, '5')
	for name, call := range map[string]func() error{
		"create": func() error {
			return service.CreateRepository(nil, model.Repository{}) //nolint:staticcheck // Verify nil-context rejection.
		},
		"resolve": func() error {
			_, err := service.ResolveRevision(nil, validRepo, validRevision) //nolint:staticcheck // Verify nil-context rejection.
			return err
		},
		"snapshot": func() error {
			_, err := service.GetSnapshot(nil, validRepo, validOID) //nolint:staticcheck // Verify nil-context rejection.
			return err
		},
		"snapshots": func() error {
			_, err := service.ListSnapshots(nil, validRepo, catalog.SnapshotQuery{}) //nolint:staticcheck // Verify nil-context rejection.
			return err
		},
		"ref": func() error {
			_, err := service.GetRef(nil, validRepo, "main") //nolint:staticcheck // Verify that the API rejects a nil context.
			return err
		},
		"refs": func() error {
			_, err := service.ListRefs(nil, validRepo, catalog.RefQuery{}) //nolint:staticcheck // Verify that the API rejects a nil context.
			return err
		},
		"compare ref": func() error {
			return service.CompareAndSwapRef(nil, validRepo, "main", nil, validOID) //nolint:staticcheck // Verify that the API rejects a nil context.
		},
		"put blob": func() error {
			_, err := service.PutBlob(nil, content.Blob{}, bytes.NewReader(nil)) //nolint:staticcheck // Verify that the API rejects a nil context.
			return err
		},
		"publish": func() error {
			return service.PublishSnapshot(nil, model.Snapshot{}, catalog.RefExpectation{}) //nolint:staticcheck // Verify that the API rejects a nil context.
		},
		"files": func() error {
			_, err := service.ListFiles(nil, validRepo, validRevision, catalog.FileQuery{}) //nolint:staticcheck // Verify nil-context rejection.
			return err
		},
	} {
		if err := call(); !errors.Is(err, ErrInvalid) {
			t.Fatalf("nil context %s = %v", name, err)
		}
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := service.ListRepositories(canceled, catalog.RepositoryQuery{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled context = %v", err)
	}
	for name, call := range map[string]func() error{
		"repository": func() error {
			_, err := service.OpenFile(context.Background(), model.RepoKey{}, validRevision, "file", OpenOptions{})
			return err
		},
		"revision": func() error {
			_, err := service.OpenFile(context.Background(), validRepo, model.Revision{}, "file", OpenOptions{})
			return err
		},
		"path": func() error {
			_, err := service.OpenFile(context.Background(), validRepo, validRevision, "", OpenOptions{})
			return err
		},
	} {
		if err := call(); !errors.Is(err, ErrInvalid) {
			t.Fatalf("invalid %s = %v", name, err)
		}
	}

	tests := map[string]struct {
		err  error
		want error
	}{
		"catalog invalid":     {catalog.ErrInvalid, ErrInvalid},
		"catalog missing":     {catalog.ErrNotFound, ErrNotFound},
		"catalog exists":      {catalog.ErrAlreadyExists, ErrConflict},
		"catalog conflict":    {catalog.ErrConflict, ErrConflict},
		"catalog corrupt":     {catalog.ErrCorrupt, ErrCorrupt},
		"catalog unavailable": {catalog.ErrUnavailable, ErrUnavailable},
		"catalog unknown":     {errors.New("unknown"), ErrUnavailable},
		"content invalid":     {content.ErrInvalid, ErrInvalid},
		"content missing":     {content.ErrNotFound, ErrCorrupt},
		"content conflict":    {content.ErrConflict, ErrCorrupt},
		"content corrupt":     {content.ErrCorrupt, ErrCorrupt},
		"content range":       {content.ErrRangeNotSatisfiable, ErrRangeNotSatisfiable},
		"content durability":  {content.ErrDurabilityUnsupported, ErrUnsupported},
		"content unavailable": {content.ErrUnavailable, ErrUnavailable},
		"content unknown":     {errors.New("unknown"), ErrUnavailable},
		"CAS unauthenticated": {casserver.ErrUnauthorized, ErrUnauthenticated},
		"CAS permission":      {casserver.ErrForbidden, ErrPermissionDenied},
		"CAS range":           {xetcas.ErrRangeNotSatisfiable, ErrRangeNotSatisfiable},
		"CAS missing":         {casserver.ErrNotFound, ErrCorrupt},
		"CAS conflict":        {casserver.ErrConflict, ErrCorrupt},
		"CAS corrupt":         {casserver.ErrCorrupt, ErrCorrupt},
		"CAS invalid":         {casserver.ErrInvalid, ErrInvalid},
		"CAS too large":       {casserver.ErrTooLarge, ErrUnsupported},
		"CAS durability":      {casserver.ErrDurabilityUnsupported, ErrUnsupported},
		"CAS unknown":         {errors.New("unknown"), ErrUnavailable},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			var got error
			switch {
			case strings.HasPrefix(name, "catalog"):
				got = mapCatalogError(test.err)
			case strings.HasPrefix(name, "content"):
				got = mapContentReadError(test.err)
			default:
				got = mapCASReadError(test.err)
			}
			if !errors.Is(got, test.want) || !errors.Is(got, test.err) {
				t.Fatalf("mapped error = %v, want %v", got, test.want)
			}
		})
	}
	for _, mapper := range []func(error) error{mapCatalogError, mapContentReadError, mapCASReadError} {
		if mapper(nil) != nil {
			t.Fatal("nil error mapping is inconsistent")
		}
	}
}

func TestServicePublishSnapshotRequiresDurableContent(t *testing.T) {
	ctx := context.Background()
	repo := testRepo(t, "owner", "publication")
	metadata := catalogmemory.New()
	ordinary := contentmemory.New()
	casStore := casserver.NewMemoryStore()
	cas, err := casserver.New(casserver.Options{
		Blobs: casStore, Index: casStore,
		Authorizer: casserver.AllowAllAuthorizer{Namespace: mustRepositoryNamespace(t, repo)},
		Signer: casserver.RangeURLSignerFunc(func(context.Context, casserver.BlobKey, xetcas.HTTPRange) (casserver.SignedRange, error) {
			return casserver.SignedRange{URL: "https://storage.example/object", ExpiresAt: time.Now().Add(time.Hour)}, nil
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	service, err := New(Options{Catalog: metadata, Content: ordinary, CAS: cas})
	if err != nil {
		t.Fatal(err)
	}
	if err := service.CreateRepository(ctx, model.Repository{Key: repo, CreatedAt: time.Unix(1_700_100_000, 0)}); err != nil {
		t.Fatal(err)
	}
	body := []byte("available")
	sum := sha256.Sum256(body)
	ref, err := model.NewBlobFileRef(sum, int64(len(body)))
	if err != nil {
		t.Fatal(err)
	}
	firstOID := testOID(t, '6')
	first := model.Snapshot{
		Repo: repo, OID: firstOID, CreatedAt: time.Unix(1_700_100_001, 0),
		Author: model.Identity{Name: "Publisher"}, Message: "first",
		Files: []model.FileEntry{{Path: "config.json", Ref: ref}},
	}
	if err := service.PublishSnapshot(ctx, first, catalog.ExpectRef("main", nil)); !errors.Is(err, ErrContentNotUploaded) {
		t.Fatalf("missing ordinary content = %v", err)
	}
	if _, err := service.GetRef(ctx, repo, "main"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("failed publication exposed main = %v", err)
	}
	if _, err := service.PutBlob(ctx, content.Blob{SHA256: sum, Size: int64(len(body))}, nil); !errors.Is(err, ErrInvalid) {
		t.Fatalf("nil ordinary body = %v", err)
	}
	if _, err := service.PutBlob(ctx, content.Blob{SHA256: sum, Size: int64(len(body))}, bytes.NewReader([]byte("different"))); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("invalid ordinary body = %v", err)
	}
	if inserted, err := service.PutBlob(ctx, content.Blob{SHA256: sum, Size: int64(len(body))}, bytes.NewReader(body)); err != nil || !inserted {
		t.Fatalf("publish ordinary body = %v, %v", inserted, err)
	}
	if err := service.PublishSnapshot(ctx, first, catalog.ExpectRef("main", nil)); err != nil {
		t.Fatal(err)
	}

	missingXetHash := xethash.Chunk([]byte("missing Xet file"))
	missingXet, err := model.NewXetFileRef(missingXetHash, 123, nil)
	if err != nil {
		t.Fatal(err)
	}
	secondOID := testOID(t, '7')
	second := model.Snapshot{
		Repo: repo, OID: secondOID, Parent: &firstOID, CreatedAt: time.Unix(1_700_100_002, 0),
		Author: model.Identity{Name: "Publisher"}, Message: "missing Xet dependency",
		Files: []model.FileEntry{{Path: "weights/model.safetensors", Ref: missingXet}},
	}
	if err := service.PublishSnapshot(ctx, second, catalog.ExpectRef("main", &firstOID)); !errors.Is(err, ErrContentNotUploaded) {
		t.Fatalf("missing Xet content = %v", err)
	}
	if _, err := service.GetSnapshot(ctx, repo, secondOID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("failed publication exposed snapshot = %v", err)
	}
	if ref, err := service.GetRef(ctx, repo, "main"); err != nil || ref.OID != firstOID {
		t.Fatalf("failed publication changed main = %#v, %v", ref, err)
	}
	invalid := first
	invalid.OID = model.OID{}
	if err := service.PublishSnapshot(ctx, invalid, catalog.ExpectRef("main", &firstOID)); !errors.Is(err, ErrInvalid) {
		t.Fatalf("invalid snapshot = %v", err)
	}
}

func TestServicePublishSnapshotRejectsMismatchedXetMetadata(t *testing.T) {
	ctx := context.Background()
	repo := testRepo(t, "owner", "xet-metadata")
	metadata := catalogmemory.New()
	ordinary := contentmemory.New()
	casStore := casserver.NewMemoryStore()
	cas, err := casserver.New(casserver.Options{
		Blobs: casStore, Index: casStore,
		Authorizer: casserver.AllowAllAuthorizer{Namespace: mustRepositoryNamespace(t, repo)},
		Signer: casserver.RangeURLSignerFunc(func(context.Context, casserver.BlobKey, xetcas.HTTPRange) (casserver.SignedRange, error) {
			return casserver.SignedRange{URL: "https://storage.example/object", ExpiresAt: time.Now().Add(time.Hour)}, nil
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	service, err := New(Options{Catalog: metadata, Content: ordinary, CAS: cas})
	if err != nil {
		t.Fatal(err)
	}
	if err := service.CreateRepository(ctx, model.Repository{Key: repo, CreatedAt: time.Unix(1_700_200_000, 0)}); err != nil {
		t.Fatal(err)
	}
	body, hash, sum := publishXetFixture(t, ctx, cas)
	wrongSize, err := model.NewXetFileRef(hash, int64(len(body))+1, &sum)
	if err != nil {
		t.Fatal(err)
	}
	wrongSum := sum
	wrongSum[0] ^= 0xff
	wrongSHA, err := model.NewXetFileRef(hash, int64(len(body)), &wrongSum)
	if err != nil {
		t.Fatal(err)
	}
	for name, ref := range map[string]model.FileRef{"size": wrongSize, "SHA-256": wrongSHA} {
		t.Run(name, func(t *testing.T) {
			snapshot := model.Snapshot{
				Repo: repo, OID: testOID(t, 'a'), CreatedAt: time.Unix(1_700_200_001, 0),
				Author: model.Identity{Name: "Publisher"}, Message: "mismatch",
				Files: []model.FileEntry{{Path: "weights.bin", Ref: ref}},
			}
			if err := service.PublishSnapshot(ctx, snapshot, catalog.ExpectRef("main", nil)); !errors.Is(err, ErrContentNotUploaded) {
				t.Fatalf("mismatched %s = %v", name, err)
			}
		})
	}
}

func TestServicePublishSnapshotUsesScopedSHAAssociation(t *testing.T) {
	ctx := context.Background()
	repo := testRepo(t, "owner", "xet-sha-association")
	metadata := catalogmemory.New()
	ordinary := contentmemory.New()
	casStore := casserver.NewMemoryStore()
	namespace := mustRepositoryNamespace(t, repo)
	cas, err := casserver.New(casserver.Options{
		Blobs: casStore, Index: casStore,
		Authorizer: casserver.AllowAllAuthorizer{Namespace: namespace},
		Signer: casserver.RangeURLSignerFunc(func(context.Context, casserver.BlobKey, xetcas.HTTPRange) (casserver.SignedRange, error) {
			return casserver.SignedRange{URL: "https://storage.example/object", ExpiresAt: time.Now().Add(time.Hour)}, nil
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	body, hash, sum := publishXetFixtureWithSHA(t, ctx, cas, false)
	if _, secondHash, secondSum := publishXetFixtureWithSHA(t, ctx, cas, true); secondHash != hash || secondSum != sum {
		t.Fatal("SHA-bearing retry changed logical Xet identity")
	}
	retained, found, err := casStore.GetFile(ctx, namespace, hash)
	if err != nil || !found || retained.File.File.SHA256 != nil {
		t.Fatalf("retained first-valid recipe = %#v, %v, %v", retained, found, err)
	}
	tracking := &trackingCASFileService{CASFileService: cas}
	service, err := New(Options{Catalog: metadata, Content: ordinary, CAS: tracking})
	if err != nil {
		t.Fatal(err)
	}
	if err := service.CreateRepository(ctx, model.Repository{Key: repo, CreatedAt: time.Unix(1_700_300_000, 0)}); err != nil {
		t.Fatal(err)
	}
	withoutSHA, err := model.NewXetFileRef(hash, int64(len(body)), nil)
	if err != nil {
		t.Fatal(err)
	}
	withSHA, err := model.NewXetFileRef(hash, int64(len(body)), &sum)
	if err != nil {
		t.Fatal(err)
	}
	snapshot := model.Snapshot{
		Repo: repo, OID: testOID(t, 'b'), CreatedAt: time.Unix(1_700_300_001, 0),
		Author: model.Identity{Name: "Publisher"}, Message: "both optional SHA forms",
		Files: []model.FileEntry{
			{Path: "without-sha.bin", Ref: withoutSHA},
			{Path: "with-sha.bin", Ref: withSHA},
			{Path: "with-sha-copy.bin", Ref: withSHA},
		},
	}
	if err := service.PublishSnapshot(ctx, snapshot, catalog.ExpectRef("main", nil)); err != nil {
		t.Fatal(err)
	}
	if tracking.verifications != 2 {
		t.Fatalf("exact Xet requirements verified %d times, want 2", tracking.verifications)
	}
}

func TestPublicationErrorMapping(t *testing.T) {
	for name, test := range map[string]struct {
		err  error
		want error
	}{
		"nil":         {},
		"canceled":    {err: context.Canceled, want: context.Canceled},
		"deadline":    {err: context.DeadlineExceeded, want: context.DeadlineExceeded},
		"invalid":     {err: content.ErrInvalid, want: ErrInvalid},
		"conflict":    {err: content.ErrConflict, want: ErrCorrupt},
		"corrupt":     {err: content.ErrCorrupt, want: ErrCorrupt},
		"durability":  {err: content.ErrDurabilityUnsupported, want: ErrUnsupported},
		"unavailable": {err: content.ErrUnavailable, want: ErrUnavailable},
		"unknown":     {err: io.ErrUnexpectedEOF, want: ErrUnavailable},
	} {
		t.Run("content "+name, func(t *testing.T) {
			if err := mapContentPublicationError(test.err); !errors.Is(err, test.want) || test.want == nil && err != nil {
				t.Fatalf("map content %v = %v", test.err, err)
			}
		})
	}
	for name, test := range map[string]struct {
		err  error
		want error
	}{
		"canceled":   {err: context.Canceled, want: context.Canceled},
		"deadline":   {err: context.DeadlineExceeded, want: context.DeadlineExceeded},
		"missing":    {err: casserver.ErrNotFound, want: ErrContentNotUploaded},
		"conflict":   {err: casserver.ErrConflict, want: ErrCorrupt},
		"corrupt":    {err: casserver.ErrCorrupt, want: ErrCorrupt},
		"invalid":    {err: casserver.ErrInvalid, want: ErrInvalid},
		"large":      {err: casserver.ErrTooLarge, want: ErrUnsupported},
		"durability": {err: casserver.ErrDurabilityUnsupported, want: ErrUnsupported},
		"unknown":    {err: io.ErrUnexpectedEOF, want: ErrUnavailable},
	} {
		t.Run("CAS "+name, func(t *testing.T) {
			if err := mapCASPublicationError("file", test.err); !errors.Is(err, test.want) {
				t.Fatalf("map CAS %v = %v", test.err, err)
			}
		})
	}
}

func TestServiceMissingOrdinaryContentAndXetWithoutSHA(t *testing.T) {
	ctx := context.Background()
	repo := testRepo(t, "owner", "missing-content")
	metadata := catalogmemory.New()
	if err := metadata.CreateRepository(ctx, model.Repository{Key: repo, CreatedAt: time.Unix(200, 0)}); err != nil {
		t.Fatal(err)
	}
	missingSum := sha256.Sum256([]byte("not uploaded"))
	missingRef, err := model.NewBlobFileRef(missingSum, int64(len("not uploaded")))
	if err != nil {
		t.Fatal(err)
	}
	xetBody := []byte("Xet")
	xetHash := xethash.Chunk([]byte("Xet identity without SHA"))
	xetRef, err := model.NewXetFileRef(xetHash, int64(len(xetBody)), nil)
	if err != nil {
		t.Fatal(err)
	}
	oid := testOID(t, '6')
	if err = metadata.PublishSnapshot(ctx, model.Snapshot{
		Repo: repo, OID: oid, CreatedAt: time.Unix(201, 0), Author: model.Identity{Name: "Test"}, Message: "fixture",
		Files: []model.FileEntry{{Path: "missing.txt", Ref: missingRef}, {Path: "weights.bin", Ref: xetRef}},
	}, catalog.ExpectRef("main", nil)); err != nil {
		t.Fatal(err)
	}
	namespace, err := RepositoryNamespace(repo)
	if err != nil {
		t.Fatal(err)
	}
	xetSum := sha256.Sum256(xetBody)
	cas := casOpenerFunc(func(_ context.Context, gotNamespace string, gotHash xethash.Hash, wanted *xetcas.FileRange) (*casserver.OpenedFile, error) {
		if gotNamespace != namespace || gotHash != xetHash || wanted != nil {
			t.Fatalf("CAS open = %q, %s, %#v", gotNamespace, gotHash, wanted)
		}
		return &casserver.OpenedFile{
			Hash: xetHash, FileSize: uint64(len(xetBody)), Range: xetcas.FileRange{Start: 0, End: uint64(len(xetBody))},
			Size: uint64(len(xetBody)), SHA256: &xetSum, Body: io.NopCloser(bytes.NewReader(xetBody)),
		}, nil
	})
	service, err := New(Options{Catalog: metadata, Content: contentmemory.New(), CAS: cas})
	if err != nil {
		t.Fatal(err)
	}
	revision, err := model.ParseRevision("main")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.OpenFile(ctx, repo, revision, "missing.txt", OpenOptions{}); !errors.Is(err, ErrCorrupt) || !errors.Is(err, content.ErrNotFound) {
		t.Fatalf("missing ordinary content = %v", err)
	}
	opened, err := service.OpenFile(ctx, repo, revision, "weights.bin", OpenOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if opened.ETag != "xet:"+xetHash.String() || opened.SHA256 == nil || *opened.SHA256 != xetSum {
		t.Fatalf("Xet metadata without SHA = %#v", opened)
	}
	if got, readErr := io.ReadAll(opened.Body); readErr != nil || !bytes.Equal(got, xetBody) {
		t.Fatalf("Xet stream without SHA = %q, %v", got, readErr)
	}
	if err := opened.Body.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestLocalServiceSurvivesRestartWithRevisionHistory(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	repo := testRepo(t, "owner", "durable-model")
	namespace, err := RepositoryNamespace(repo)
	if err != nil {
		t.Fatal(err)
	}
	open := func() (*Service, *catalogsqlite.Store, *contentfilesystem.Store, *casserver.FilesystemBlobStore, *casserver.SQLiteIndexStore) {
		t.Helper()
		metadata, openErr := catalogsqlite.Open(filepath.Join(root, "catalog.db"))
		if openErr != nil {
			t.Fatal(openErr)
		}
		ordinary, openErr := contentfilesystem.Open(filepath.Join(root, "content"))
		if openErr != nil {
			_ = metadata.Close()
			t.Fatal(openErr)
		}
		blobs, openErr := casserver.NewFilesystemBlobStore(filepath.Join(root, "cas"))
		if openErr != nil {
			_ = ordinary.Close()
			_ = metadata.Close()
			t.Fatal(openErr)
		}
		index, openErr := casserver.OpenSQLiteIndexStore(filepath.Join(root, "cas-index.db"))
		if openErr != nil {
			_ = blobs.Close()
			_ = ordinary.Close()
			_ = metadata.Close()
			t.Fatal(openErr)
		}
		cas, openErr := casserver.New(casserver.Options{
			Blobs: blobs, Index: index,
			Authorizer: casAuthorizerFunc(func(_ context.Context, _ string, request casserver.AccessRequest) (casserver.Grant, error) {
				if request.Operation == casserver.OperationReadFile {
					return casserver.Grant{}, casserver.ErrForbidden
				}
				return casserver.Grant{Namespace: namespace}, nil
			}),
			Signer: casserver.RangeURLSignerFunc(func(context.Context, casserver.BlobKey, xetcas.HTTPRange) (casserver.SignedRange, error) {
				return casserver.SignedRange{URL: "https://storage.example/object", ExpiresAt: time.Now().Add(time.Hour)}, nil
			}),
			DedupProtectionKey: xethash.Chunk([]byte("durable bucket test dedup key")),
		})
		if openErr != nil {
			_ = index.Close()
			_ = blobs.Close()
			_ = ordinary.Close()
			_ = metadata.Close()
			t.Fatal(openErr)
		}
		service, openErr := New(Options{Catalog: metadata, Content: ordinary, CAS: cas})
		if openErr != nil {
			t.Fatal(openErr)
		}
		return service, metadata, ordinary, blobs, index
	}
	closeProfile := func(metadata *catalogsqlite.Store, ordinary *contentfilesystem.Store, blobs *casserver.FilesystemBlobStore, index *casserver.SQLiteIndexStore) {
		t.Helper()
		for name, closeErr := range map[string]error{
			"CAS index": index.Close(), "CAS blobs": blobs.Close(), "content": ordinary.Close(), "catalog": metadata.Close(),
		} {
			if closeErr != nil {
				t.Fatalf("close %s: %v", name, closeErr)
			}
		}
	}

	service, metadata, ordinary, blobs, index := open()
	if err = service.CreateRepository(ctx, model.Repository{Key: repo, CreatedAt: time.Unix(300, 0)}); err != nil {
		t.Fatal(err)
	}
	firstBody := []byte("revision one\n")
	firstSum := sha256.Sum256(firstBody)
	firstRef, err := model.NewBlobFileRef(firstSum, int64(len(firstBody)))
	if err != nil {
		t.Fatal(err)
	}
	if inserted, putErr := service.PutBlob(ctx, content.Blob{SHA256: firstSum, Size: int64(len(firstBody))}, bytes.NewReader(firstBody)); putErr != nil || !inserted {
		t.Fatalf("first content put = %v, %v", inserted, putErr)
	}
	xetBody, xetHash, xetSum := publishXetFixture(t, ctx, service.cas.(*casserver.Service))
	xetRef, err := model.NewXetFileRef(xetHash, int64(len(xetBody)), &xetSum)
	if err != nil {
		t.Fatal(err)
	}
	firstOID := testOID(t, '7')
	if err = service.PublishSnapshot(ctx, model.Snapshot{
		Repo: repo, OID: firstOID, CreatedAt: time.Unix(301, 0), Author: model.Identity{Name: "Test"}, Message: "first",
		Files: []model.FileEntry{{Path: "config.txt", Ref: firstRef}, {Path: "weights.bin", Ref: xetRef}},
	}, catalog.ExpectRef("main", nil)); err != nil {
		t.Fatal(err)
	}
	mainRevision, _ := model.ParseRevision("main")
	assertOpenFile(t, service, repo, mainRevision, "config.txt", nil, firstBody, model.FileKindBlob, "sha256:")
	assertOpenFile(t, service, repo, mainRevision, "weights.bin", nil, xetBody, model.FileKindXet, "sha256:")
	closeProfile(metadata, ordinary, blobs, index)

	service, metadata, ordinary, blobs, index = open()
	firstRevision, _ := model.RevisionFromOID(firstOID)
	assertOpenFile(t, service, repo, firstRevision, "config.txt", nil, firstBody, model.FileKindBlob, "sha256:")
	assertOpenFile(t, service, repo, firstRevision, "weights.bin", nil, xetBody, model.FileKindXet, "sha256:")
	secondBody := []byte("revision two\n")
	secondSum := sha256.Sum256(secondBody)
	secondRef, err := model.NewBlobFileRef(secondSum, int64(len(secondBody)))
	if err != nil {
		t.Fatal(err)
	}
	if inserted, putErr := service.PutBlob(ctx, content.Blob{SHA256: secondSum, Size: int64(len(secondBody))}, bytes.NewReader(secondBody)); putErr != nil || !inserted {
		t.Fatalf("second content put = %v, %v", inserted, putErr)
	}
	secondOID := testOID(t, '8')
	if err = service.PublishSnapshot(ctx, model.Snapshot{
		Repo: repo, OID: secondOID, Parent: &firstOID, CreatedAt: time.Unix(302, 0), Author: model.Identity{Name: "Test"}, Message: "second",
		Files: []model.FileEntry{{Path: "config.txt", Ref: secondRef}},
	}, catalog.ExpectRef("main", &firstOID)); err != nil {
		t.Fatal(err)
	}
	otherRepo := testRepo(t, "owner", "durable-other")
	if err = service.CreateRepository(ctx, model.Repository{Key: otherRepo, CreatedAt: time.Unix(303, 0)}); err != nil {
		t.Fatal(err)
	}
	if err = metadata.PublishSnapshot(ctx, model.Snapshot{
		Repo: otherRepo, OID: testOID(t, '9'), CreatedAt: time.Unix(304, 0), Author: model.Identity{Name: "Test"}, Message: "unpublished namespace",
		Files: []model.FileEntry{{Path: "weights.bin", Ref: xetRef}},
	}, catalog.ExpectRef("main", nil)); err != nil {
		t.Fatal(err)
	}
	closeProfile(metadata, ordinary, blobs, index)

	service, metadata, ordinary, blobs, index = open()
	t.Cleanup(func() { closeProfile(metadata, ordinary, blobs, index) })
	assertOpenFile(t, service, repo, mainRevision, "config.txt", nil, secondBody, model.FileKindBlob, "sha256:")
	if _, err = service.OpenFile(ctx, repo, mainRevision, "weights.bin", OpenOptions{}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Xet file deleted from main = %v", err)
	}
	assertOpenFile(t, service, repo, firstRevision, "config.txt", nil, firstBody, model.FileKindBlob, "sha256:")
	assertOpenFile(t, service, repo, firstRevision, "weights.bin", nil, xetBody, model.FileKindXet, "sha256:")
	if _, err = service.OpenFile(ctx, otherRepo, mainRevision, "weights.bin", OpenOptions{}); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("durable cross-repository Xet read = %v", err)
	}
}

func TestServiceRejectsInconsistentCASMetadataAndMapsStreams(t *testing.T) {
	repo, revision, metadata, entry := xetCatalogFixture(t, nil)
	ordinary := contentmemory.New()
	wantedHash, _ := entry.Ref.XetHash()
	namespace, _ := RepositoryNamespace(repo)
	body := []byte("fake xet stream")
	base := &casserver.OpenedFile{
		Hash: wantedHash, FileSize: uint64(entry.Ref.FileSize()),
		Range: xetcas.FileRange{Start: 0, End: uint64(entry.Ref.FileSize())}, Size: uint64(entry.Ref.FileSize()),
		Body: io.NopCloser(bytes.NewReader(body)),
	}
	if sum, ok := entry.Ref.SHA256(); ok {
		base.SHA256 = &sum
	}
	for name, mutate := range map[string]func(*casserver.OpenedFile){
		"nil result": func(*casserver.OpenedFile) {},
		"nil body":   func(result *casserver.OpenedFile) { result.Body = nil },
		"hash":       func(result *casserver.OpenedFile) { result.Hash[0] ^= 0xff },
		"size":       func(result *casserver.OpenedFile) { result.FileSize++ },
		"range":      func(result *casserver.OpenedFile) { result.Range.End-- },
		"range size": func(result *casserver.OpenedFile) { result.Size-- },
		"SHA mismatch": func(result *casserver.OpenedFile) {
			wrong := sha256.Sum256([]byte("wrong SHA"))
			result.SHA256 = &wrong
		},
	} {
		t.Run(name, func(t *testing.T) {
			closed := false
			cas := casOpenerFunc(func(_ context.Context, gotNamespace string, _ xethash.Hash, _ *xetcas.FileRange) (*casserver.OpenedFile, error) {
				if gotNamespace != namespace {
					t.Fatalf("namespace = %q, want %q", gotNamespace, namespace)
				}
				if name == "nil result" {
					return nil, nil
				}
				result := *base
				result.Body = &trackingReadCloser{Reader: bytes.NewReader(body), closed: &closed}
				mutate(&result)
				return &result, nil
			})
			service, err := New(Options{Catalog: metadata, Content: ordinary, CAS: cas})
			if err != nil {
				t.Fatal(err)
			}
			_, err = service.OpenFile(context.Background(), repo, revision, entry.Path, OpenOptions{})
			want := ErrCorrupt
			if name == "nil result" || name == "nil body" {
				want = ErrInvariant
			}
			if !errors.Is(err, want) {
				t.Fatalf("error = %v, want %v", err, want)
			}
			if name != "nil result" && name != "nil body" && !closed {
				t.Fatal("rejected CAS stream was not closed")
			}
		})
	}
	casWithoutSHA := casOpenerFunc(func(context.Context, string, xethash.Hash, *xetcas.FileRange) (*casserver.OpenedFile, error) {
		result := *base
		result.SHA256 = nil
		result.Body = io.NopCloser(bytes.NewReader(body))
		return &result, nil
	})
	serviceWithoutSHA, err := New(Options{Catalog: metadata, Content: ordinary, CAS: casWithoutSHA})
	if err != nil {
		t.Fatal(err)
	}
	openedWithoutSHA, err := serviceWithoutSHA.OpenFile(context.Background(), repo, revision, entry.Path, OpenOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if openedWithoutSHA.SHA256 == nil || *openedWithoutSHA.SHA256 != *base.SHA256 {
		t.Fatalf("catalog SHA with SHA-less CAS recipe = %#v", openedWithoutSHA.SHA256)
	}
	if got, readErr := io.ReadAll(openedWithoutSHA.Body); readErr != nil || !bytes.Equal(got, body) {
		t.Fatalf("SHA-less CAS recipe stream = %q, %v", got, readErr)
	}
	if err := openedWithoutSHA.Body.Close(); err != nil {
		t.Fatal(err)
	}

	sentinel := errors.New("stream failed")
	cas := casOpenerFunc(func(context.Context, string, xethash.Hash, *xetcas.FileRange) (*casserver.OpenedFile, error) {
		result := *base
		result.Body = &errorReadCloser{err: sentinel}
		return &result, nil
	})
	service, err := New(Options{Catalog: metadata, Content: ordinary, CAS: cas})
	if err != nil {
		t.Fatal(err)
	}
	opened, err := service.OpenFile(context.Background(), repo, revision, entry.Path, OpenOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = opened.Body.Read(make([]byte, 1)); !errors.Is(err, ErrUnavailable) || !errors.Is(err, sentinel) {
		t.Fatalf("mapped stream read = %v", err)
	}
	if err = opened.Body.Close(); !errors.Is(err, ErrUnavailable) || !errors.Is(err, sentinel) {
		t.Fatalf("mapped stream close = %v", err)
	}
}

func publishXetFixture(t *testing.T, ctx context.Context, service *casserver.Service) ([]byte, xethash.Hash, [32]byte) {
	return publishXetFixtureWithSHA(t, ctx, service, true)
}

func publishXetFixtureWithSHA(
	t *testing.T,
	ctx context.Context,
	service *casserver.Service,
	includeSHA bool,
) ([]byte, xethash.Hash, [32]byte) {
	t.Helper()
	chunks := [][]byte{
		bytes.Repeat([]byte("xet-backed-a"), 500),
		bytes.Repeat([]byte("xet-backed-b"), 700),
	}
	object, err := xorb.Encode(chunks, xorb.LZ4)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = service.UploadXorb(ctx, "", xetcas.DefaultXorbPrefix, object.Hash,
		bytes.NewReader(object.Body), int64(len(object.Body))); err != nil {
		t.Fatal(err)
	}
	xorbInfo, err := shard.XorbFromObject(object)
	if err != nil {
		t.Fatal(err)
	}
	var body []byte
	nodes := make([]xethash.Node, len(chunks))
	hashes := make([]xethash.Hash, len(chunks))
	for index, chunk := range chunks {
		body = append(body, chunk...)
		hashes[index] = xethash.Chunk(chunk)
		nodes[index] = xethash.Node{Hash: hashes[index], Size: uint64(len(chunk))}
	}
	fileHash := xethash.File(nodes)
	sum := sha256.Sum256(body)
	var shardSum *[32]byte
	if includeSHA {
		shardSum = &sum
	}
	shardBody, err := shard.EncodeUpload(shard.Shard{
		Xorbs: []shard.Xorb{xorbInfo},
		Files: []shard.File{{
			Hash: fileHash, SHA256: shardSum,
			Terms: []shard.Term{{
				XorbHash: object.Hash, UnpackedBytes: uint32(len(body)), Start: 0, End: uint32(len(chunks)),
				Verification: xethash.Verification(hashes),
			}},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = service.UploadShard(ctx, "", bytes.NewReader(shardBody), int64(len(shardBody))); err != nil {
		t.Fatal(err)
	}
	return body, fileHash, sum
}

func assertOpenFile(
	t *testing.T,
	service *Service,
	repo model.RepoKey,
	revision model.Revision,
	path model.FilePath,
	wanted *content.Range,
	expected []byte,
	kind model.FileKind,
	etagPrefix string,
) {
	t.Helper()
	opened, err := service.OpenFile(context.Background(), repo, revision, path, OpenOptions{Range: wanted})
	if err != nil {
		t.Fatal(err)
	}
	got, readErr := io.ReadAll(opened.Body)
	closeErr := opened.Body.Close()
	if readErr != nil || closeErr != nil || !bytes.Equal(got, expected) {
		t.Fatalf("open %q = %d bytes, %v, %v", path, len(got), readErr, closeErr)
	}
	if opened.Entry.Ref.Kind() != kind || opened.Size != int64(len(expected)) ||
		!opened.RangeSupported || opened.ContentType != "" || !strings.HasPrefix(opened.ETag, etagPrefix) || opened.SHA256 == nil {
		t.Fatalf("open metadata = %#v", opened)
	}
}

func xetCatalogFixture(t *testing.T, sum *[32]byte) (model.RepoKey, model.Revision, *catalogmemory.Store, model.FileEntry) {
	t.Helper()
	repo := testRepo(t, "owner", "fixture")
	hash := xethash.Chunk([]byte("fake xet identity"))
	if sum == nil {
		value := sha256.Sum256([]byte("fake xet logical bytes"))
		sum = &value
	}
	ref, err := model.NewXetFileRef(hash, int64(len("fake xet stream")), sum)
	if err != nil {
		t.Fatal(err)
	}
	entry := model.FileEntry{Path: "weights.bin", Ref: ref}
	store := catalogmemory.New()
	if err = store.CreateRepository(context.Background(), model.Repository{Key: repo, CreatedAt: time.Unix(100, 0)}); err != nil {
		t.Fatal(err)
	}
	oid := testOID(t, '2')
	if err = store.PublishSnapshot(context.Background(), model.Snapshot{
		Repo: repo, OID: oid, CreatedAt: time.Unix(101, 0), Author: model.Identity{Name: "Test"},
		Message: "fixture", Files: []model.FileEntry{entry},
	}, catalog.ExpectRef("main", nil)); err != nil {
		t.Fatal(err)
	}
	revision, err := model.ParseRevision("main")
	if err != nil {
		t.Fatal(err)
	}
	return repo, revision, store, entry
}

func testRepo(t *testing.T, namespace, name string) model.RepoKey {
	t.Helper()
	repo, err := model.NewRepoKey(namespace, name, model.RepoTypeModel)
	if err != nil {
		t.Fatal(err)
	}
	return repo
}

func mustRepositoryNamespace(t *testing.T, repo model.RepoKey) string {
	t.Helper()
	namespace, err := RepositoryNamespace(repo)
	if err != nil {
		t.Fatal(err)
	}
	return namespace
}

func testOID(t *testing.T, character byte) model.OID {
	t.Helper()
	oid, err := model.ParseOID(strings.Repeat(string(character), 40))
	if err != nil {
		t.Fatal(err)
	}
	return oid
}

type casAuthorizerFunc func(context.Context, string, casserver.AccessRequest) (casserver.Grant, error)

func (function casAuthorizerFunc) Authorize(
	ctx context.Context,
	credential string,
	request casserver.AccessRequest,
) (casserver.Grant, error) {
	return function(ctx, credential, request)
}

type casOpenerFunc func(context.Context, string, xethash.Hash, *xetcas.FileRange) (*casserver.OpenedFile, error)

func (function casOpenerFunc) OpenFileInNamespace(
	ctx context.Context,
	namespace string,
	hash xethash.Hash,
	wanted *xetcas.FileRange,
) (*casserver.OpenedFile, error) {
	return function(ctx, namespace, hash, wanted)
}

func (casOpenerFunc) VerifyFileInNamespace(
	context.Context,
	string,
	xethash.Hash,
	uint64,
	*[32]byte,
) error {
	return errors.New("unused CAS verifier")
}

type trackingCASFileService struct {
	CASFileService
	verifications int
}

func (service *trackingCASFileService) VerifyFileInNamespace(
	ctx context.Context,
	namespace string,
	hash xethash.Hash,
	size uint64,
	sum *[32]byte,
) error {
	service.verifications++
	return service.CASFileService.VerifyFileInNamespace(ctx, namespace, hash, size, sum)
}

type errorReadCloser struct{ err error }

func (reader *errorReadCloser) Read([]byte) (int, error) { return 0, reader.err }
func (reader *errorReadCloser) Close() error             { return reader.err }

type trackingReadCloser struct {
	io.Reader
	closed *bool
}

func (reader *trackingReadCloser) Close() error {
	*reader.closed = true
	return nil
}

func ExampleService_OpenFile() {
	fmt.Println("bucket.Service opens ordinary and Xet-backed files through one API")
	// Output: bucket.Service opens ordinary and Xet-backed files through one API
}
