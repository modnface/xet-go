package memory_test

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jmwoliver/xet-go/catalog"
	"github.com/jmwoliver/xet-go/catalog/memory"
	postgrescatalog "github.com/jmwoliver/xet-go/catalog/postgres"
	sqlitecatalog "github.com/jmwoliver/xet-go/catalog/sqlite"
	"github.com/jmwoliver/xet-go/model"
)

type catalogFactory func(testing.TB) catalog.Catalog

func TestMemoryCatalogContract(t *testing.T) {
	runCatalogContract(t, func(testing.TB) catalog.Catalog { return memory.New() })
}

func TestSQLiteCatalogContract(t *testing.T) {
	runCatalogContract(t, func(tb testing.TB) catalog.Catalog {
		store, err := sqlitecatalog.Open(filepath.Join(tb.TempDir(), "catalog.db"))
		if err != nil {
			tb.Fatal(err)
		}
		tb.Cleanup(func() { _ = store.Close() })
		return store
	})
}

var postgresSchemaSequence atomic.Uint64

func TestPostgreSQLCatalogContract(t *testing.T) {
	if os.Getenv("XET_POSTGRES_INTEGRATION") != "1" {
		t.Skip("set XET_POSTGRES_INTEGRATION=1 with XET_POSTGRES_DSN to run")
	}
	dsn := os.Getenv("XET_POSTGRES_DSN")
	if dsn == "" {
		t.Fatal("XET_POSTGRES_DSN is required")
	}
	pool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Fatal("configure PostgreSQL test pool")
	}
	t.Cleanup(pool.Close)
	runCatalogContract(t, func(tb testing.TB) catalog.Catalog {
		schema := fmt.Sprintf("xet_catalog_contract_%d_%d", os.Getpid(), postgresSchemaSequence.Add(1))
		store, openErr := postgrescatalog.New(context.Background(), pool, postgrescatalog.Options{Schema: schema})
		if openErr != nil {
			tb.Fatal(openErr)
		}
		tb.Cleanup(func() {
			_ = store.Close()
			_, _ = pool.Exec(context.Background(), `DROP SCHEMA `+schema+` CASCADE`)
		})
		return store
	})
}

func runCatalogContract(t *testing.T, factory catalogFactory) {
	t.Helper()
	t.Run("repositories", func(t *testing.T) { testRepositories(t, factory(t)) })
	t.Run("publication and reads", func(t *testing.T) { testPublicationAndReads(t, factory(t)) })
	t.Run("first publication", func(t *testing.T) { testFirstPublicationCreatesMain(t, factory(t)) })
	t.Run("concurrent publication", func(t *testing.T) { testConcurrentPublication(t, factory(t)) })
	t.Run("snapshot pagination order", func(t *testing.T) { testSnapshotPaginationOrder(t, factory(t)) })
	t.Run("error semantics", func(t *testing.T) { testErrorSemantics(t, factory(t)) })
	t.Run("cancellation", func(t *testing.T) { testCancellation(t, factory(t)) })
}

func testRepositories(t *testing.T, store catalog.Catalog) {
	t.Helper()
	created := time.Date(2026, 8, 11, 12, 0, 0, 0, time.FixedZone("offset", 3600))
	repositories := []model.Repository{
		{Key: repoKey(t, "team", "beta"), CreatedAt: created.Add(time.Second)},
		{Key: repoKey(t, "other", "alpha"), CreatedAt: created},
		{Key: repoKey(t, "team", "alpha"), CreatedAt: created.Add(2 * time.Second)},
	}
	for _, repository := range repositories {
		if err := store.CreateRepository(context.Background(), repository); err != nil {
			t.Fatalf("create %v: %v", repository.Key, err)
		}
	}
	if err := store.CreateRepository(context.Background(), repositories[0]); !errors.Is(err, catalog.ErrAlreadyExists) {
		t.Fatalf("duplicate repository = %v", err)
	}
	got, err := store.GetRepository(context.Background(), repositories[0].Key)
	if err != nil || got.Key != repositories[0].Key || got.CreatedAt.Location() != time.UTC {
		t.Fatalf("get repository = %#v, %v", got, err)
	}
	if _, err := store.GetRepository(context.Background(), repoKey(t, "missing", "repo")); !errors.Is(err, catalog.ErrNotFound) {
		t.Fatalf("missing repository = %v", err)
	}
	if err := store.CreateRepository(context.Background(), model.Repository{Key: repositories[0].Key}); !errors.Is(err, catalog.ErrInvalid) {
		t.Fatalf("invalid repository = %v", err)
	}

	first, err := store.ListRepositories(context.Background(), catalog.RepositoryQuery{Limit: 2})
	if err != nil || len(first.Items) != 2 || first.NextCursor == "" {
		t.Fatalf("first repository page = %#v, %v", first, err)
	}
	second, err := store.ListRepositories(context.Background(), catalog.RepositoryQuery{Limit: 2, Cursor: first.NextCursor})
	if err != nil || len(second.Items) != 1 || second.NextCursor != "" {
		t.Fatalf("second repository page = %#v, %v", second, err)
	}
	gotKeys := []model.RepoKey{first.Items[0].Key, first.Items[1].Key, second.Items[0].Key}
	wantKeys := []model.RepoKey{repositories[1].Key, repositories[2].Key, repositories[0].Key}
	for index := range wantKeys {
		if gotKeys[index] != wantKeys[index] {
			t.Fatalf("repository order = %v, want %v", gotKeys, wantKeys)
		}
	}
	team, err := store.ListRepositories(context.Background(), catalog.RepositoryQuery{Namespace: "team", Limit: 1})
	if err != nil || len(team.Items) != 1 || team.NextCursor == "" {
		t.Fatalf("filtered repository page = %#v, %v", team, err)
	}
	if _, err := store.ListRepositories(context.Background(), catalog.RepositoryQuery{
		Namespace: "other", Limit: 1, Cursor: team.NextCursor,
	}); !errors.Is(err, catalog.ErrInvalid) {
		t.Fatalf("cross-query repository cursor = %v", err)
	}
	for _, query := range []catalog.RepositoryQuery{
		{Cursor: "not-a-cursor"}, {Limit: -1}, {Limit: catalog.MaxPageSize + 1}, {Namespace: "../bad"}, {Type: "dataset"},
	} {
		if _, err := store.ListRepositories(context.Background(), query); !errors.Is(err, catalog.ErrInvalid) {
			t.Fatalf("invalid repository query %#v = %v", query, err)
		}
	}
}

func testPublicationAndReads(t *testing.T, store catalog.Catalog) {
	t.Helper()
	ctx := context.Background()
	repo := createRepository(t, store, "team", "model")
	root := snapshot(t, repo, oid(t, 1), nil, time.Unix(100, 0), "root", "config.json", "weights/model.bin")
	if err := store.PublishSnapshot(ctx, root, catalog.ExpectRef("main", nil)); err != nil {
		t.Fatalf("publish root: %v", err)
	}
	root.Files[0].Path = "mutated"

	main, err := store.GetRef(ctx, repo, "main")
	if err != nil || main.OID != root.OID {
		t.Fatalf("main after root = %#v, %v", main, err)
	}
	byOID, err := store.GetSnapshot(ctx, repo, root.OID)
	if err != nil || byOID.Files[0].Path != "config.json" {
		t.Fatalf("root by OID = %#v, %v", byOID, err)
	}
	mainRevision := revisionRef(t, "main")
	byRef, err := store.ResolveRevision(ctx, repo, mainRevision)
	if err != nil || byRef.OID != root.OID {
		t.Fatalf("root by ref = %#v, %v", byRef, err)
	}
	byRef.Files[0].Path = "changed"
	again, err := store.GetSnapshot(ctx, repo, root.OID)
	if err != nil || again.Files[0].Path != "config.json" {
		t.Fatalf("returned snapshot aliases catalog = %#v, %v", again, err)
	}

	entry, err := store.GetFile(ctx, repo, mainRevision, "config.json")
	if err != nil || entry.Ref.Kind() != model.FileKindBlob {
		t.Fatalf("get ordinary file = %#v, %v", entry, err)
	}
	files, err := store.ListFiles(ctx, repo, mainRevision, catalog.FileQuery{Prefix: "weights/"})
	if err != nil || len(files.Items) != 1 || files.Items[0].Path != "weights/model.bin" || files.SnapshotOID != root.OID {
		t.Fatalf("list file prefix = %#v, %v", files, err)
	}
	firstFiles, err := store.ListFiles(ctx, repo, mainRevision, catalog.FileQuery{Limit: 1})
	if err != nil || len(firstFiles.Items) != 1 || firstFiles.Items[0].Path != "config.json" || firstFiles.NextCursor == "" {
		t.Fatalf("first file page = %#v, %v", firstFiles, err)
	}
	if _, err := store.ListFiles(ctx, repo, mainRevision, catalog.FileQuery{
		Prefix: "weights/", Cursor: firstFiles.NextCursor, Limit: 1,
	}); !errors.Is(err, catalog.ErrInvalid) {
		t.Fatalf("cross-prefix file cursor = %v", err)
	}
	if _, err := store.GetFile(ctx, repo, mainRevision, "missing"); !errors.Is(err, catalog.ErrNotFound) {
		t.Fatalf("missing file = %v", err)
	}

	second := snapshot(t, repo, oid(t, 2), &root.OID, time.Unix(200, 0), "second", "config.json", "tokenizer.json")
	if err := store.PublishSnapshot(ctx, second, catalog.ExpectRef("main", &root.OID)); err != nil {
		t.Fatalf("publish second: %v", err)
	}
	if _, err := store.ListFiles(ctx, repo, mainRevision, catalog.FileQuery{
		Cursor: firstFiles.NextCursor, Limit: 1,
	}); !errors.Is(err, catalog.ErrConflict) {
		t.Fatalf("file cursor followed advanced ref = %v", err)
	}
	immutableFiles, err := store.ListFiles(ctx, repo, revisionOID(t, root.OID), catalog.FileQuery{
		Cursor: firstFiles.NextCursor, Limit: 1,
	})
	if err != nil || len(immutableFiles.Items) != 1 || immutableFiles.Items[0].Path != "weights/model.bin" ||
		immutableFiles.NextCursor != "" || immutableFiles.SnapshotOID != root.OID {
		t.Fatalf("immutable file continuation = %#v, %v", immutableFiles, err)
	}
	if err := store.PublishSnapshot(ctx, second, catalog.ExpectRef("main", &root.OID)); err != nil {
		t.Fatalf("idempotent publication replay: %v", err)
	}
	old, err := store.GetSnapshot(ctx, repo, root.OID)
	if err != nil || len(old.Files) != 2 || old.Files[1].Path != "weights/model.bin" {
		t.Fatalf("old immutable revision = %#v, %v", old, err)
	}
	current, err := store.ResolveRevision(ctx, repo, mainRevision)
	if err != nil || current.OID != second.OID || current.Files[1].Path != "tokenizer.json" {
		t.Fatalf("updated main = %#v, %v", current, err)
	}

	conflicting := second
	conflicting.Message = "different immutable value"
	if err := store.PublishSnapshot(ctx, conflicting, catalog.ExpectRef("main", &root.OID)); !errors.Is(err, catalog.ErrConflict) {
		t.Fatalf("conflicting immutable snapshot = %v", err)
	}
	third := snapshot(t, repo, oid(t, 3), &root.OID, time.Unix(300, 0), "stale", "config.json")
	if err := store.PublishSnapshot(ctx, third, catalog.ExpectRef("main", &root.OID)); !errors.Is(err, catalog.ErrConflict) {
		t.Fatalf("stale ref publication = %v", err)
	}
	if _, err := store.GetSnapshot(ctx, repo, third.OID); !errors.Is(err, catalog.ErrNotFound) {
		t.Fatalf("failed publication exposed snapshot = %v", err)
	}
	main, _ = store.GetRef(ctx, repo, "main")
	if main.OID != second.OID {
		t.Fatalf("failed publication moved main to %s", main.OID)
	}

	page, err := store.ListSnapshots(ctx, repo, catalog.SnapshotQuery{Limit: 1})
	if err != nil || len(page.Items) != 1 || page.Items[0].OID != second.OID || page.NextCursor == "" {
		t.Fatalf("first snapshot page = %#v, %v", page, err)
	}
	next, err := store.ListSnapshots(ctx, repo, catalog.SnapshotQuery{Limit: 1, Cursor: page.NextCursor})
	if err != nil || len(next.Items) != 1 || next.Items[0].OID != root.OID || next.NextCursor != "" {
		t.Fatalf("second snapshot page = %#v, %v", next, err)
	}
	otherRepo := createRepository(t, store, "team", "other")
	if _, err := store.ListSnapshots(ctx, otherRepo, catalog.SnapshotQuery{Cursor: page.NextCursor}); !errors.Is(err, catalog.ErrInvalid) {
		t.Fatalf("cross-repository snapshot cursor = %v", err)
	}
	if _, err := store.ListSnapshots(ctx, repo, catalog.SnapshotQuery{Cursor: "bad"}); !errors.Is(err, catalog.ErrInvalid) {
		t.Fatalf("malformed snapshot cursor = %v", err)
	}

	if err := store.CompareAndSwapRef(ctx, repo, "release", nil, root.OID); err != nil {
		t.Fatalf("create release ref: %v", err)
	}
	if err := store.CompareAndSwapRef(ctx, repo, "release", nil, root.OID); err != nil {
		t.Fatalf("idempotent release ref replay: %v", err)
	}
	wrong := oid(t, 9)
	if err := store.CompareAndSwapRef(ctx, repo, "release", &wrong, second.OID); !errors.Is(err, catalog.ErrConflict) {
		t.Fatalf("stale release ref CAS = %v", err)
	}
	if err := store.CompareAndSwapRef(ctx, repo, "release", &root.OID, oid(t, 10)); !errors.Is(err, catalog.ErrNotFound) {
		t.Fatalf("CAS to missing snapshot = %v", err)
	}
	if _, err := store.ResolveRevision(ctx, repo, model.Revision{}); !errors.Is(err, catalog.ErrInvalid) {
		t.Fatalf("empty revision = %v", err)
	}
	if _, err := store.GetSnapshot(ctx, otherRepo, root.OID); !errors.Is(err, catalog.ErrNotFound) {
		t.Fatalf("cross-repository OID read = %v", err)
	}
}

func testFirstPublicationCreatesMain(t *testing.T, store catalog.Catalog) {
	t.Helper()
	repo := createRepository(t, store, "team", "first")
	root := snapshot(t, repo, oid(t, 20), nil, time.Unix(100, 0), "root", "a")
	if err := store.PublishSnapshot(context.Background(), root, catalog.ExpectRef("development", nil)); err != nil {
		t.Fatal(err)
	}
	for _, name := range []model.RefName{"development", "main"} {
		ref, err := store.GetRef(context.Background(), repo, name)
		if err != nil || ref.OID != root.OID {
			t.Fatalf("first ref %q = %#v, %v", name, ref, err)
		}
	}
}

func testConcurrentPublication(t *testing.T, store catalog.Catalog) {
	t.Helper()
	ctx := context.Background()
	repo := createRepository(t, store, "team", "concurrent")
	root := snapshot(t, repo, oid(t, 30), nil, time.Unix(100, 0), "root", "a")
	if err := store.PublishSnapshot(ctx, root, catalog.ExpectRef("main", nil)); err != nil {
		t.Fatal(err)
	}
	candidates := []model.Snapshot{
		snapshot(t, repo, oid(t, 31), &root.OID, time.Unix(200, 0), "left", "left"),
		snapshot(t, repo, oid(t, 32), &root.OID, time.Unix(200, 0), "right", "right"),
	}
	start := make(chan struct{})
	errs := make([]error, len(candidates))
	var wait sync.WaitGroup
	for index := range candidates {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			<-start
			errs[index] = store.PublishSnapshot(ctx, candidates[index], catalog.ExpectRef("main", &root.OID))
		}(index)
	}
	close(start)
	wait.Wait()
	successes, conflicts := 0, 0
	var winner, loser model.OID
	for index, err := range errs {
		if err == nil {
			successes++
			winner = candidates[index].OID
		} else if errors.Is(err, catalog.ErrConflict) {
			conflicts++
			loser = candidates[index].OID
		} else {
			t.Fatalf("concurrent publication %d = %v", index, err)
		}
	}
	if successes != 1 || conflicts != 1 {
		t.Fatalf("concurrent outcomes = %v", errs)
	}
	main, err := store.GetRef(ctx, repo, "main")
	if err != nil || main.OID != winner {
		t.Fatalf("concurrent winner = %s, ref %#v, %v", winner, main, err)
	}
	if _, err := store.GetSnapshot(ctx, repo, loser); !errors.Is(err, catalog.ErrNotFound) {
		t.Fatalf("losing snapshot became visible = %v", err)
	}
}

func testSnapshotPaginationOrder(t *testing.T, store catalog.Catalog) {
	t.Helper()
	ctx := context.Background()
	repo := createRepository(t, store, "order", "snapshots")
	root := snapshot(t, repo, oid(t, 60), nil, time.Unix(-2, 0), "root", "a")
	second := snapshot(t, repo, oid(t, 61), &root.OID, time.Unix(-1, 0), "second", "b")
	third := snapshot(t, repo, oid(t, 62), &second.OID, time.Unix(-1, 0), "third", "c")
	fourth := snapshot(t, repo, oid(t, 63), &third.OID, time.Unix(0, 0), "fourth", "d")
	chain := []model.Snapshot{root, second, third, fourth}
	var expected *model.OID
	for _, value := range chain {
		if err := store.PublishSnapshot(ctx, value, catalog.ExpectRef("main", expected)); err != nil {
			t.Fatalf("publish ordered snapshot %s: %v", value.OID, err)
		}
		oid := value.OID
		expected = &oid
	}
	want := []model.OID{fourth.OID, third.OID, second.OID, root.OID}
	cursor := ""
	for index, oid := range want {
		page, err := store.ListSnapshots(ctx, repo, catalog.SnapshotQuery{Limit: 1, Cursor: cursor})
		if err != nil || len(page.Items) != 1 || page.Items[0].OID != oid {
			t.Fatalf("snapshot page %d = %#v, %v; want %s", index, page, err, oid)
		}
		cursor = page.NextCursor
		if (index < len(want)-1) != (cursor != "") {
			t.Fatalf("snapshot continuation %d = %q", index, cursor)
		}
	}
}

func testErrorSemantics(t *testing.T, store catalog.Catalog) {
	t.Helper()
	ctx := context.Background()
	repo := createRepository(t, store, "errors", "model")
	missingRepo := repoKey(t, "errors", "missing")
	root := snapshot(t, repo, oid(t, 50), nil, time.Unix(100, 0), "root", "a")
	missingParent := oid(t, 59)

	if _, err := store.ResolveRevision(ctx, missingRepo, revisionRef(t, "main")); !errors.Is(err, catalog.ErrNotFound) {
		t.Fatalf("resolve missing repository = %v", err)
	}
	if _, err := store.ListSnapshots(ctx, missingRepo, catalog.SnapshotQuery{}); !errors.Is(err, catalog.ErrNotFound) {
		t.Fatalf("list missing repository = %v", err)
	}
	if _, err := store.GetRef(ctx, missingRepo, "main"); !errors.Is(err, catalog.ErrNotFound) {
		t.Fatalf("get ref from missing repository = %v", err)
	}
	if err := store.CompareAndSwapRef(ctx, missingRepo, "main", nil, root.OID); !errors.Is(err, catalog.ErrNotFound) {
		t.Fatalf("CAS missing repository = %v", err)
	}
	missingRepoSnapshot := root
	missingRepoSnapshot.Repo = missingRepo
	if err := store.PublishSnapshot(ctx, missingRepoSnapshot, catalog.ExpectRef("main", nil)); !errors.Is(err, catalog.ErrNotFound) {
		t.Fatalf("publish to missing repository = %v", err)
	}
	if err := store.PublishSnapshot(ctx, root, catalog.ExpectRef("main", nil)); err != nil {
		t.Fatal(err)
	}

	missingParentSnapshot := snapshot(t, repo, oid(t, 51), &missingParent, time.Unix(200, 0), "missing parent", "b")
	if err := store.PublishSnapshot(ctx, missingParentSnapshot, catalog.ExpectRef("other", nil)); !errors.Is(err, catalog.ErrNotFound) {
		t.Fatalf("missing parent publication = %v", err)
	}
	secondRoot := snapshot(t, repo, oid(t, 52), nil, time.Unix(200, 0), "second root", "b")
	if err := store.PublishSnapshot(ctx, secondRoot, catalog.ExpectRef("other", nil)); !errors.Is(err, catalog.ErrInvalid) {
		t.Fatalf("second root publication = %v", err)
	}
	if err := store.PublishSnapshot(ctx, secondRoot, catalog.ExpectRef("../bad", nil)); !errors.Is(err, catalog.ErrInvalid) {
		t.Fatalf("invalid publication ref = %v", err)
	}

	second := snapshot(t, repo, oid(t, 53), &root.OID, time.Unix(300, 0), "second", "b")
	if err := store.PublishSnapshot(ctx, second, catalog.ExpectRef("main", &root.OID)); err != nil {
		t.Fatal(err)
	}
	wrongParent := snapshot(t, repo, oid(t, 54), &root.OID, time.Unix(400, 0), "wrong parent", "c")
	if err := store.PublishSnapshot(ctx, wrongParent, catalog.ExpectRef("main", &second.OID)); !errors.Is(err, catalog.ErrInvalid) {
		t.Fatalf("parent/ref mismatch = %v", err)
	}

	if err := store.CompareAndSwapRef(ctx, repo, "release", &root.OID, second.OID); !errors.Is(err, catalog.ErrConflict) {
		t.Fatalf("create ref with expected value = %v", err)
	}
	zero := model.OID{}
	if err := store.CompareAndSwapRef(ctx, repo, "release", &zero, second.OID); !errors.Is(err, catalog.ErrInvalid) {
		t.Fatalf("zero expected ref = %v", err)
	}
	if err := store.CompareAndSwapRef(ctx, repo, "../bad", nil, second.OID); !errors.Is(err, catalog.ErrInvalid) {
		t.Fatalf("invalid CAS ref = %v", err)
	}
	if err := store.CompareAndSwapRef(ctx, repo, "release", nil, root.OID); err != nil {
		t.Fatal(err)
	}
	if err := store.CompareAndSwapRef(ctx, repo, "release", &root.OID, second.OID); err != nil {
		t.Fatalf("advance release ref = %v", err)
	}
	if ref, err := store.GetRef(ctx, repo, "release"); err != nil || ref.OID != second.OID {
		t.Fatalf("advanced release ref = %#v, %v", ref, err)
	}
	if _, err := store.GetRef(ctx, repo, "../bad"); !errors.Is(err, catalog.ErrInvalid) {
		t.Fatalf("invalid get ref = %v", err)
	}
	if _, err := store.GetRef(ctx, repo, "missing"); !errors.Is(err, catalog.ErrNotFound) {
		t.Fatalf("missing ref = %v", err)
	}

	if _, err := store.GetFile(ctx, repo, revisionRef(t, "main"), "../bad"); !errors.Is(err, catalog.ErrInvalid) {
		t.Fatalf("invalid get file path = %v", err)
	}
	if _, err := store.ListFiles(ctx, repo, revisionRef(t, "main"), catalog.FileQuery{Prefix: "../bad"}); !errors.Is(err, catalog.ErrInvalid) {
		t.Fatalf("invalid list file prefix = %v", err)
	}
	if _, err := store.ListSnapshots(ctx, repo, catalog.SnapshotQuery{Limit: -1}); !errors.Is(err, catalog.ErrInvalid) {
		t.Fatalf("invalid snapshot limit = %v", err)
	}
	if _, err := store.GetRepository(ctx, model.RepoKey{}); !errors.Is(err, catalog.ErrInvalid) {
		t.Fatalf("invalid repository key = %v", err)
	}
}

func testCancellation(t *testing.T, store catalog.Catalog) {
	t.Helper()
	repo := repoKey(t, "team", "canceled")
	repository := model.Repository{Key: repo, CreatedAt: time.Unix(1, 0)}
	revision := revisionRef(t, "main")
	snapshot := snapshot(t, repo, oid(t, 40), nil, time.Unix(2, 0), "root", "a")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	operations := []func() error{
		func() error { return store.CreateRepository(ctx, repository) },
		func() error { _, err := store.GetRepository(ctx, repo); return err },
		func() error { _, err := store.ListRepositories(ctx, catalog.RepositoryQuery{}); return err },
		func() error { _, err := store.ResolveRevision(ctx, repo, revision); return err },
		func() error { _, err := store.GetSnapshot(ctx, repo, snapshot.OID); return err },
		func() error { _, err := store.ListSnapshots(ctx, repo, catalog.SnapshotQuery{}); return err },
		func() error { _, err := store.GetRef(ctx, repo, "main"); return err },
		func() error { return store.CompareAndSwapRef(ctx, repo, "main", nil, snapshot.OID) },
		func() error { return store.PublishSnapshot(ctx, snapshot, catalog.ExpectRef("main", nil)) },
		func() error { _, err := store.GetFile(ctx, repo, revision, "a"); return err },
		func() error { _, err := store.ListFiles(ctx, repo, revision, catalog.FileQuery{}); return err },
	}
	for index, operation := range operations {
		if err := operation(); !errors.Is(err, context.Canceled) {
			t.Fatalf("canceled operation %d = %v", index, err)
		}
	}
	if _, err := store.GetRepository(context.Background(), repo); !errors.Is(err, catalog.ErrNotFound) {
		t.Fatalf("canceled create retained repository = %v", err)
	}
}

func createRepository(t testing.TB, store catalog.Catalog, namespace, name string) model.RepoKey {
	t.Helper()
	key := repoKey(t, namespace, name)
	if err := store.CreateRepository(context.Background(), model.Repository{Key: key, CreatedAt: time.Unix(1, 0)}); err != nil {
		t.Fatalf("create repository %v: %v", key, err)
	}
	return key
}

func repoKey(t testing.TB, namespace, name string) model.RepoKey {
	t.Helper()
	key, err := model.NewRepoKey(namespace, name, model.RepoTypeModel)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func oid(t testing.TB, value byte) model.OID {
	t.Helper()
	oid, err := model.ParseOID(strings.Repeat(fmt.Sprintf("%02x", value), 20))
	if err != nil {
		t.Fatal(err)
	}
	return oid
}

func revisionRef(t testing.TB, name model.RefName) model.Revision {
	t.Helper()
	revision, err := model.RevisionFromRef(name)
	if err != nil {
		t.Fatal(err)
	}
	return revision
}

func revisionOID(t testing.TB, oid model.OID) model.Revision {
	t.Helper()
	revision, err := model.RevisionFromOID(oid)
	if err != nil {
		t.Fatal(err)
	}
	return revision
}

func snapshot(
	t testing.TB,
	repo model.RepoKey,
	oid model.OID,
	parent *model.OID,
	createdAt time.Time,
	message string,
	paths ...model.FilePath,
) model.Snapshot {
	t.Helper()
	files := make([]model.FileEntry, len(paths))
	for index, path := range paths {
		bytes := []byte(path)
		sum := sha256.Sum256(bytes)
		ref, err := model.NewBlobFileRef(sum, int64(len(bytes)))
		if err != nil {
			t.Fatal(err)
		}
		files[index] = model.FileEntry{Path: path, Ref: ref}
	}
	return model.Snapshot{
		Repo: repo, OID: oid, Parent: parent, CreatedAt: createdAt,
		Author: model.Identity{Name: "author", Email: "author@example.com"}, Message: message, Files: files,
	}
}
