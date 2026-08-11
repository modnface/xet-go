package sqlite

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jmwoliver/xet-go/catalog"
	"github.com/jmwoliver/xet-go/model"
	"github.com/jmwoliver/xet-go/xethash"
	_ "modernc.org/sqlite"
)

func TestRestartPersistsRevisionsAndFileKinds(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "catalog.db")
	store := openTestStore(t, path)
	repo := testRepo(t, "durable", "model")
	if err := store.CreateRepository(ctx, model.Repository{Key: repo, CreatedAt: time.Unix(1, 0)}); err != nil {
		t.Fatal(err)
	}
	root := testSnapshot(t, repo, testOID(t, 1), nil, time.Unix(2, 0), "root")
	if err := store.PublishSnapshot(ctx, root, catalog.ExpectRef("main", nil)); err != nil {
		t.Fatal(err)
	}
	second := testSnapshot(t, repo, testOID(t, 2), &root.OID, time.Unix(3, 0), "second")
	if err := store.PublishSnapshot(ctx, second, catalog.ExpectRef("main", &root.OID)); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	store = openTestStore(t, path)

	main, err := store.ResolveRevision(ctx, repo, testRevisionRef(t, "main"))
	if err != nil || main.OID != second.OID || len(main.Files) != 2 {
		t.Fatalf("main after restart = %#v, %v", main, err)
	}
	old, err := store.GetSnapshot(ctx, repo, root.OID)
	if err != nil || old.OID != root.OID || old.Files[0].Ref.Kind() != model.FileKindBlob ||
		old.Files[1].Ref.Kind() != model.FileKindXet {
		t.Fatalf("old revision after restart = %#v, %v", old, err)
	}
	page, err := store.ListFiles(ctx, repo, testRevisionOID(t, root.OID), catalog.FileQuery{Limit: 1})
	if err != nil || len(page.Items) != 1 || page.NextCursor == "" || page.SnapshotOID != root.OID {
		t.Fatalf("first persisted file page = %#v, %v", page, err)
	}
	page, err = store.ListFiles(ctx, repo, testRevisionOID(t, root.OID), catalog.FileQuery{Limit: 1, Cursor: page.NextCursor})
	if err != nil || len(page.Items) != 1 || page.NextCursor != "" || page.Items[0].Ref.Kind() != model.FileKindXet {
		t.Fatalf("second persisted file page = %#v, %v", page, err)
	}
}

func TestIndependentHandlesSerializePublication(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "catalog.db")
	left := openTestStore(t, path)
	right := openTestStore(t, path)
	repo := testRepo(t, "concurrent", "model")
	if err := left.CreateRepository(ctx, model.Repository{Key: repo, CreatedAt: time.Unix(1, 0)}); err != nil {
		t.Fatal(err)
	}
	root := testSnapshot(t, repo, testOID(t, 10), nil, time.Unix(2, 0), "root")
	if err := left.PublishSnapshot(ctx, root, catalog.ExpectRef("main", nil)); err != nil {
		t.Fatal(err)
	}
	candidates := []model.Snapshot{
		testSnapshot(t, repo, testOID(t, 11), &root.OID, time.Unix(3, 0), "left"),
		testSnapshot(t, repo, testOID(t, 12), &root.OID, time.Unix(3, 0), "right"),
	}
	stores := []*Store{left, right}
	errs := make([]error, 2)
	start := make(chan struct{})
	var wait sync.WaitGroup
	for index := range stores {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			<-start
			errs[index] = stores[index].PublishSnapshot(ctx, candidates[index], catalog.ExpectRef("main", &root.OID))
		}(index)
	}
	close(start)
	wait.Wait()
	successes, conflicts := 0, 0
	for _, err := range errs {
		if err == nil {
			successes++
		} else if errors.Is(err, catalog.ErrConflict) {
			conflicts++
		} else {
			t.Fatalf("publication outcome = %v", err)
		}
	}
	if successes != 1 || conflicts != 1 {
		t.Fatalf("publication outcomes = %v", errs)
	}
}

func TestConcurrentFirstOpen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "catalog.db")
	start := make(chan struct{})
	errorsByWorker := make([]error, 8)
	var wait sync.WaitGroup
	for index := range errorsByWorker {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			store, err := Open(path)
			if err == nil {
				err = store.Close()
			}
			errorsByWorker[index] = err
		}()
	}
	close(start)
	wait.Wait()
	for index, err := range errorsByWorker {
		if err != nil {
			t.Errorf("Open worker %d = %v", index, err)
		}
	}
	store := openTestStore(t, path)
	if _, err := store.ListRepositories(context.Background(), catalog.RepositoryQuery{}); err != nil {
		t.Fatalf("catalog after concurrent initialization = %v", err)
	}
}

func TestIndependentHandleWriteLockHonorsContext(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "catalog.db")
	first := openTestStore(t, path)
	second := openTestStore(t, path)
	repo := testRepo(t, "concurrent", "cancellation")
	if err := first.CreateRepository(ctx, model.Repository{Key: repo, CreatedAt: time.Unix(1, 0)}); err != nil {
		t.Fatal(err)
	}
	root := testSnapshot(t, repo, testOID(t, 72), nil, time.Unix(2, 0), "root")
	if err := first.PublishSnapshot(ctx, root, catalog.ExpectRef("main", nil)); err != nil {
		t.Fatal(err)
	}
	winner := testSnapshot(t, repo, testOID(t, 73), &root.OID, time.Unix(3, 0), "winner")
	loser := testSnapshot(t, repo, testOID(t, 74), &root.OID, time.Unix(3, 0), "loser")
	locked := make(chan struct{})
	release := make(chan struct{})
	first.testHook = func(stage string) error {
		if stage == "after-insert" {
			close(locked)
			<-release
		}
		return nil
	}
	result := make(chan error, 1)
	go func() { result <- first.PublishSnapshot(ctx, winner, catalog.ExpectRef("main", &root.OID)) }()
	select {
	case <-locked:
	case <-time.After(2 * time.Second):
		t.Fatal("first publication did not acquire the write lock")
	}
	defer func() {
		select {
		case <-release:
		default:
			close(release)
		}
	}()
	deadlineContext, cancel := context.WithTimeout(ctx, 100*time.Millisecond)
	defer cancel()
	started := time.Now()
	if err := second.PublishSnapshot(deadlineContext, loser, catalog.ExpectRef("main", &root.OID)); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("blocked publication = %v", err)
	}
	if elapsed := time.Since(started); elapsed > 2*time.Second {
		t.Fatalf("blocked publication ignored cancellation for %s", elapsed)
	}
	close(release)
	if err := <-result; err != nil {
		t.Fatalf("first publication = %v", err)
	}
	first.testHook = nil
	main, err := second.GetRef(ctx, repo, "main")
	if err != nil || main.OID != winner.OID {
		t.Fatalf("main after lock contention = %#v, %v", main, err)
	}
	if _, err := second.GetSnapshot(ctx, repo, loser.OID); !errors.Is(err, catalog.ErrNotFound) {
		t.Fatalf("canceled snapshot visible = %v", err)
	}
}

func TestPublicationFaultsRollbackAcrossRestart(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "catalog.db")
	store := openTestStore(t, path)
	repo := testRepo(t, "fault", "model")
	if err := store.CreateRepository(ctx, model.Repository{Key: repo, CreatedAt: time.Unix(1, 0)}); err != nil {
		t.Fatal(err)
	}
	root := testSnapshot(t, repo, testOID(t, 20), nil, time.Unix(2, 0), "root")
	if err := store.PublishSnapshot(ctx, root, catalog.ExpectRef("main", nil)); err != nil {
		t.Fatal(err)
	}
	sentinel := errors.New("injected publication failure")
	for index, stage := range []string{"after-insert", "after-ref"} {
		candidate := testSnapshot(t, repo, testOID(t, byte(21+index)), &root.OID, time.Unix(int64(3+index), 0), stage)
		store.testHook = func(current string) error {
			if current == stage {
				return sentinel
			}
			return nil
		}
		if err := store.PublishSnapshot(ctx, candidate, catalog.ExpectRef("main", &root.OID)); !errors.Is(err, sentinel) {
			t.Fatalf("fault at %s = %v", stage, err)
		}
		store.testHook = nil
		if err := store.Close(); err != nil {
			t.Fatal(err)
		}
		store = openTestStore(t, path)
		main, err := store.GetRef(ctx, repo, "main")
		if err != nil || main.OID != root.OID {
			t.Fatalf("main after %s restart = %#v, %v", stage, main, err)
		}
		if _, err := store.GetSnapshot(ctx, repo, candidate.OID); !errors.Is(err, catalog.ErrNotFound) {
			t.Fatalf("candidate after %s restart = %v", stage, err)
		}
	}
}

func TestPublicationRetainedStateAndInvariantFailures(t *testing.T) {
	ctx := context.Background()
	store := openTestStore(t, filepath.Join(t.TempDir(), "catalog.db"))
	repo := testRepo(t, "publication", "state")
	if err := store.CreateRepository(ctx, model.Repository{Key: repo, CreatedAt: time.Unix(1, 0)}); err != nil {
		t.Fatal(err)
	}
	root := testSnapshot(t, repo, testOID(t, 54), nil, time.Unix(2, 0), "root")
	if err := store.PublishSnapshot(ctx, root, catalog.ExpectRef("main", nil)); err != nil {
		t.Fatal(err)
	}
	if err := store.PublishSnapshot(ctx, root, catalog.ExpectRef("main", nil)); err != nil {
		t.Fatalf("target-state publication = %v", err)
	}
	conflicting := root
	conflicting.Message = "different immutable snapshot"
	if err := store.PublishSnapshot(ctx, conflicting, catalog.ExpectRef("main", nil)); !errors.Is(err, catalog.ErrConflict) {
		t.Fatalf("same OID with different content = %v", err)
	}
	secondRoot := testSnapshot(t, repo, testOID(t, 55), nil, time.Unix(3, 0), "second root")
	if err := store.PublishSnapshot(ctx, secondRoot, catalog.ExpectRef("other", nil)); !errors.Is(err, catalog.ErrInvalid) {
		t.Fatalf("second root = %v", err)
	}
	missingParent := testOID(t, 56)
	orphan := testSnapshot(t, repo, testOID(t, 57), &missingParent, time.Unix(3, 0), "orphan")
	if err := store.PublishSnapshot(ctx, orphan, catalog.ExpectRef("other", nil)); !errors.Is(err, catalog.ErrNotFound) {
		t.Fatalf("missing parent = %v", err)
	}
	missingRepo := testRepo(t, "publication", "missing")
	missingRoot := testSnapshot(t, missingRepo, testOID(t, 58), nil, time.Unix(2, 0), "missing")
	if err := store.PublishSnapshot(ctx, missingRoot, catalog.ExpectRef("main", nil)); !errors.Is(err, catalog.ErrNotFound) {
		t.Fatalf("missing repository = %v", err)
	}
}

func TestPublicationDetectsCorruptRetainedState(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*Store, model.Snapshot) error
	}{
		{name: "fingerprint encoding", mutate: func(store *Store, root model.Snapshot) error {
			_, err := store.db.Exec("UPDATE snapshots SET fingerprint=x'01' WHERE oid=?", root.OID[:])
			return err
		}},
		{name: "fingerprint version type", mutate: func(store *Store, root model.Snapshot) error {
			_, err := store.db.Exec("UPDATE snapshots SET fingerprint_version='bad' WHERE oid=?", root.OID[:])
			return err
		}},
		{name: "snapshot body", mutate: func(store *Store, root model.Snapshot) error {
			_, err := store.db.Exec("UPDATE files SET path='../bad' WHERE oid=? AND path='config.json'", root.OID[:])
			return err
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx := context.Background()
			store := openTestStore(t, filepath.Join(t.TempDir(), "catalog.db"))
			repo := testRepo(t, "publication-corrupt", nameToRepo(t, test.name))
			if err := store.CreateRepository(ctx, model.Repository{Key: repo, CreatedAt: time.Unix(1, 0)}); err != nil {
				t.Fatal(err)
			}
			root := testSnapshot(t, repo, testOID(t, 59), nil, time.Unix(2, 0), "root")
			if err := store.PublishSnapshot(ctx, root, catalog.ExpectRef("main", nil)); err != nil {
				t.Fatal(err)
			}
			store.db.SetMaxOpenConns(1)
			if _, err := store.db.Exec("PRAGMA ignore_check_constraints=ON"); err != nil {
				t.Fatal(err)
			}
			if err := test.mutate(store, root); err != nil {
				t.Fatal(err)
			}
			if err := store.PublishSnapshot(ctx, root, catalog.ExpectRef("main", nil)); !errors.Is(err, catalog.ErrCorrupt) {
				t.Fatalf("publication over corrupt state = %v", err)
			}
		})
	}

	t.Run("dangling repository ref", func(t *testing.T) {
		ctx := context.Background()
		store := openTestStore(t, filepath.Join(t.TempDir(), "catalog.db"))
		repo := testRepo(t, "publication-corrupt", "dangling-ref")
		if err := store.CreateRepository(ctx, model.Repository{Key: repo, CreatedAt: time.Unix(1, 0)}); err != nil {
			t.Fatal(err)
		}
		store.db.SetMaxOpenConns(1)
		if _, err := store.db.Exec("PRAGMA foreign_keys=OFF"); err != nil {
			t.Fatal(err)
		}
		dangling := testOID(t, 60)
		if _, err := store.db.Exec("INSERT INTO refs VALUES(?,?,?,?,?)", repo.Type, repo.Namespace, repo.Name, "dangling", dangling[:]); err != nil {
			t.Fatal(err)
		}
		root := testSnapshot(t, repo, testOID(t, 61), nil, time.Unix(2, 0), "root")
		if err := store.PublishSnapshot(ctx, root, catalog.ExpectRef("main", nil)); !errors.Is(err, catalog.ErrCorrupt) {
			t.Fatalf("publication with dangling ref = %v", err)
		}
	})
}

func TestPublicationSQLFailuresRollback(t *testing.T) {
	tests := []struct {
		name, trigger, ref string
	}{
		{name: "snapshot", trigger: "CREATE TRIGGER fail_write BEFORE INSERT ON snapshots BEGIN SELECT RAISE(ABORT,'injected'); END", ref: "main"},
		{name: "file", trigger: "CREATE TRIGGER fail_write BEFORE INSERT ON files BEGIN SELECT RAISE(ABORT,'injected'); END", ref: "main"},
		{name: "target ref", trigger: "CREATE TRIGGER fail_write BEFORE INSERT ON refs WHEN NEW.ref_name='release' BEGIN SELECT RAISE(ABORT,'injected'); END", ref: "release"},
		{name: "main ref", trigger: "CREATE TRIGGER fail_write BEFORE INSERT ON refs WHEN NEW.ref_name='main' BEGIN SELECT RAISE(ABORT,'injected'); END", ref: "release"},
	}
	for index, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx := context.Background()
			store := openTestStore(t, filepath.Join(t.TempDir(), "catalog.db"))
			repo := testRepo(t, "sql-failure", fmt.Sprintf("case-%d", index))
			if err := store.CreateRepository(ctx, model.Repository{Key: repo, CreatedAt: time.Unix(1, 0)}); err != nil {
				t.Fatal(err)
			}
			if _, err := store.db.Exec(test.trigger); err != nil {
				t.Fatal(err)
			}
			root := testSnapshot(t, repo, testOID(t, byte(62+index)), nil, time.Unix(2, 0), "root")
			if err := store.PublishSnapshot(ctx, root, catalog.ExpectRef(model.RefName(test.ref), nil)); !errors.Is(err, catalog.ErrUnavailable) {
				t.Fatalf("publication SQL failure = %v", err)
			}
			if _, err := store.GetSnapshot(ctx, repo, root.OID); !errors.Is(err, catalog.ErrNotFound) {
				t.Fatalf("failed snapshot visible = %v", err)
			}
			if _, err := store.GetRef(ctx, repo, model.RefName(test.ref)); !errors.Is(err, catalog.ErrNotFound) {
				t.Fatalf("failed ref visible = %v", err)
			}
		})
	}
}

func TestOpenValidationSchemaAndCorruption(t *testing.T) {
	if _, err := Open(""); !errors.Is(err, catalog.ErrInvalid) {
		t.Fatalf("empty path = %v", err)
	}
	directoryPath := filepath.Join(t.TempDir(), "directory")
	if err := os.Mkdir(directoryPath, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(directoryPath); !errors.Is(err, catalog.ErrInvalid) {
		t.Fatalf("directory path = %v", err)
	}
	if err := os.Symlink(directoryPath, directoryPath+"-link"); err == nil {
		if _, err := Open(directoryPath + "-link"); !errors.Is(err, catalog.ErrInvalid) {
			t.Fatalf("symlink path = %v", err)
		}
	}
	parent := t.TempDir()
	if err := os.Chmod(parent, 0o755); err != nil {
		t.Fatal(err)
	}
	parentInfo, err := os.Stat(parent)
	if err != nil {
		t.Fatal(err)
	}
	store := openTestStore(t, filepath.Join(parent, "permissions.db"))
	if err = store.Close(); err != nil {
		t.Fatal(err)
	}
	afterInfo, err := os.Stat(parent)
	if err != nil {
		t.Fatal(err)
	}
	if afterInfo.Mode().Perm() != parentInfo.Mode().Perm() {
		t.Fatalf("Open changed parent mode from %o to %o", parentInfo.Mode().Perm(), afterInfo.Mode().Perm())
	}
	realParent := filepath.Join(t.TempDir(), "real")
	if err = os.Mkdir(realParent, 0o700); err != nil {
		t.Fatal(err)
	}
	ancestorLink := realParent + "-link"
	if err = os.Symlink(realParent, ancestorLink); err == nil {
		if _, err = Open(filepath.Join(ancestorLink, "nested", "catalog.db")); !errors.Is(err, catalog.ErrInvalid) {
			t.Fatalf("symlink ancestor = %v", err)
		}
	}

	newer := filepath.Join(t.TempDir(), "newer.db")
	db, err := sql.Open("sqlite", newer)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec("PRAGMA user_version=2"); err != nil {
		t.Fatal(err)
	}
	if err = db.Close(); err != nil {
		t.Fatal(err)
	}
	if err = os.Chmod(newer, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(newer); !errors.Is(err, catalog.ErrUnavailable) {
		t.Fatalf("newer schema = %v", err)
	}
	inspection, err := sql.Open("sqlite", newer)
	if err != nil {
		t.Fatal(err)
	}
	var journalMode string
	if err = inspection.QueryRow("PRAGMA journal_mode").Scan(&journalMode); err != nil {
		t.Fatal(err)
	}
	if err = inspection.Close(); err != nil {
		t.Fatal(err)
	}
	if strings.EqualFold(journalMode, "wal") {
		t.Fatal("unsupported schema was changed to WAL before rejection")
	}
	missingSchema := filepath.Join(t.TempDir(), "missing-schema.db")
	db, err = sql.Open("sqlite", missingSchema)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec("PRAGMA user_version=1"); err != nil {
		t.Fatal(err)
	}
	if err = db.Close(); err != nil {
		t.Fatal(err)
	}
	if err = os.Chmod(missingSchema, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err = Open(missingSchema); !errors.Is(err, catalog.ErrCorrupt) {
		t.Fatalf("missing schema = %v", err)
	}
	notDatabase := filepath.Join(t.TempDir(), "not-database.db")
	if err = os.WriteFile(notDatabase, []byte("not a sqlite database"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err = Open(notDatabase); !errors.Is(err, catalog.ErrCorrupt) {
		t.Fatalf("non-database file = %v", err)
	}
	insecure := filepath.Join(t.TempDir(), "insecure.db")
	if err = os.WriteFile(insecure, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err = Open(insecure); !errors.Is(err, catalog.ErrInvalid) {
		t.Fatalf("insecure database permissions = %v", err)
	}
	parentFile := filepath.Join(t.TempDir(), "parent-file")
	if err = os.WriteFile(parentFile, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err = Open(filepath.Join(parentFile, "catalog.db")); !errors.Is(err, catalog.ErrInvalid) {
		t.Fatalf("non-directory parent component = %v", err)
	}
	if runtime.GOOS == "linux" {
		if _, err = Open(filepath.Join("/proc", fmt.Sprintf("xet-go-%d.db", os.Getpid()))); !errors.Is(err, catalog.ErrUnavailable) {
			t.Fatalf("unwritable database location = %v", err)
		}
	}

	negative := filepath.Join(t.TempDir(), "negative.db")
	db, err = sql.Open("sqlite", negative)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec("PRAGMA user_version=-1"); err != nil {
		t.Fatal(err)
	}
	if err = db.Close(); err != nil {
		t.Fatal(err)
	}
	if err = os.Chmod(negative, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err = Open(negative); !errors.Is(err, catalog.ErrUnavailable) {
		t.Fatalf("negative schema version = %v", err)
	}
	partial := filepath.Join(t.TempDir(), "partial.db")
	db, err = sql.Open("sqlite", partial)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec("CREATE TABLE repositories(value TEXT)"); err != nil {
		t.Fatal(err)
	}
	if err = db.Close(); err != nil {
		t.Fatal(err)
	}
	if err = os.Chmod(partial, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err = Open(partial); !errors.Is(err, catalog.ErrUnavailable) {
		t.Fatalf("partial version-zero schema = %v", err)
	}
	missingIndex := filepath.Join(t.TempDir(), "missing-index.db")
	store = openTestStore(t, missingIndex)
	if _, err = store.db.Exec("DROP INDEX snapshots_order"); err != nil {
		t.Fatal(err)
	}
	if err = store.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err = Open(missingIndex); !errors.Is(err, catalog.ErrCorrupt) {
		t.Fatalf("missing required index = %v", err)
	}
	memoryDB, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer memoryDB.Close() //nolint:errcheck // test cleanup only.
	if err = (&Store{db: memoryDB}).init(context.Background()); !errors.Is(err, catalog.ErrUnavailable) {
		t.Fatalf("non-WAL database = %v", err)
	}

	path := filepath.Join(t.TempDir(), "corrupt.db")
	store = openTestStore(t, path)
	repo := testRepo(t, "corrupt", "model")
	if err := store.CreateRepository(context.Background(), model.Repository{Key: repo, CreatedAt: time.Unix(1, 0)}); err != nil {
		t.Fatal(err)
	}
	root := testSnapshot(t, repo, testOID(t, 30), nil, time.Unix(2, 0), "root")
	if err := store.PublishSnapshot(context.Background(), root, catalog.ExpectRef("main", nil)); err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.Exec("PRAGMA ignore_check_constraints=ON"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.Exec("UPDATE snapshots SET file_count=-1 WHERE oid=?", root.OID[:]); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ListSnapshots(context.Background(), repo, catalog.SnapshotQuery{}); !errors.Is(err, catalog.ErrCorrupt) {
		t.Fatalf("corrupt snapshot metadata = %v", err)
	}
}

func TestRetainedRefCorruptionIsNeverAConflict(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "catalog.db")
	store := openTestStore(t, path)
	repo := testRepo(t, "corrupt-ref", "model")
	if err := store.CreateRepository(ctx, model.Repository{Key: repo, CreatedAt: time.Unix(1, 0)}); err != nil {
		t.Fatal(err)
	}
	root := testSnapshot(t, repo, testOID(t, 35), nil, time.Unix(2, 0), "root")
	if err := store.PublishSnapshot(ctx, root, catalog.ExpectRef("main", nil)); err != nil {
		t.Fatal(err)
	}
	candidate := testSnapshot(t, repo, testOID(t, 36), &root.OID, time.Unix(3, 0), "candidate")
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec("PRAGMA foreign_keys=OFF"); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec("PRAGMA ignore_check_constraints=ON"); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec("UPDATE refs SET oid=? WHERE ref_name='main'", []byte{1}); err != nil {
		t.Fatal(err)
	}
	if err = db.Close(); err != nil {
		t.Fatal(err)
	}
	store = openTestStore(t, path)
	for operation, run := range map[string]func() error{
		"get": func() error { _, err := store.GetRef(ctx, repo, "main"); return err },
		"resolve": func() error {
			_, err := store.ResolveRevision(ctx, repo, testRevisionRef(t, "main"))
			return err
		},
		"cas":     func() error { return store.CompareAndSwapRef(ctx, repo, "main", &root.OID, root.OID) },
		"publish": func() error { return store.PublishSnapshot(ctx, candidate, catalog.ExpectRef("main", &root.OID)) },
	} {
		if err := run(); !errors.Is(err, catalog.ErrCorrupt) {
			t.Fatalf("%s with malformed ref = %v", operation, err)
		}
	}
}

func TestRetainedScalarTypeCorruption(t *testing.T) {
	ctx := context.Background()
	store := openTestStore(t, filepath.Join(t.TempDir(), "catalog.db"))
	repo := testRepo(t, "corrupt-type", "model")
	if err := store.CreateRepository(ctx, model.Repository{Key: repo, CreatedAt: time.Unix(1, 0)}); err != nil {
		t.Fatal(err)
	}
	root := testSnapshot(t, repo, testOID(t, 37), nil, time.Unix(2, 0), "root")
	if err := store.PublishSnapshot(ctx, root, catalog.ExpectRef("main", nil)); err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.Exec("PRAGMA ignore_check_constraints=ON"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.Exec("UPDATE snapshots SET file_count='not-an-integer' WHERE oid=?", root.OID[:]); err != nil {
		t.Fatal(err)
	}
	if _, err := store.GetSnapshot(ctx, repo, root.OID); !errors.Is(err, catalog.ErrCorrupt) {
		t.Fatalf("single snapshot scalar corruption = %v", err)
	}
	if _, err := store.ListSnapshots(ctx, repo, catalog.SnapshotQuery{}); !errors.Is(err, catalog.ErrCorrupt) {
		t.Fatalf("snapshot list scalar corruption = %v", err)
	}
}

func TestRetainedSnapshotCorruptionVariants(t *testing.T) {
	tests := map[string]func(*Store, model.Snapshot) error{
		"snapshot encoding": func(store *Store, root model.Snapshot) error {
			_, err := store.db.Exec("UPDATE snapshots SET fingerprint=? WHERE oid=?", []byte{1}, root.OID[:])
			return err
		},
		"parent encoding": func(store *Store, root model.Snapshot) error {
			_, err := store.db.Exec("UPDATE snapshots SET parent=? WHERE oid=?", []byte{1}, root.OID[:])
			return err
		},
		"file count": func(store *Store, root model.Snapshot) error {
			_, err := store.db.Exec("DELETE FROM files WHERE oid=? AND path='config.json'", root.OID[:])
			return err
		},
		"snapshot metadata": func(store *Store, root model.Snapshot) error {
			_, err := store.db.Exec("UPDATE snapshots SET author_name='' WHERE oid=?", root.OID[:])
			return err
		},
		"fingerprint": func(store *Store, root model.Snapshot) error {
			_, err := store.db.Exec("UPDATE snapshots SET fingerprint=? WHERE oid=?", bytes.Repeat([]byte{9}, 32), root.OID[:])
			return err
		},
		"file path": func(store *Store, root model.Snapshot) error {
			_, err := store.db.Exec("UPDATE files SET path='../bad' WHERE oid=? AND path='config.json'", root.OID[:])
			return err
		},
		"file scalar": func(store *Store, root model.Snapshot) error {
			_, err := store.db.Exec("UPDATE files SET size='bad' WHERE oid=? AND path='config.json'", root.OID[:])
			return err
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			store := openTestStore(t, filepath.Join(t.TempDir(), "catalog.db"))
			repo := testRepo(t, "snapshot-corruption", nameToRepo(t, name))
			if err := store.CreateRepository(ctx, model.Repository{Key: repo, CreatedAt: time.Unix(1, 0)}); err != nil {
				t.Fatal(err)
			}
			root := testSnapshot(t, repo, testOID(t, 38), nil, time.Unix(2, 0), "root")
			if err := store.PublishSnapshot(ctx, root, catalog.ExpectRef("main", nil)); err != nil {
				t.Fatal(err)
			}
			store.db.SetMaxOpenConns(1)
			if _, err := store.db.Exec("PRAGMA foreign_keys=OFF"); err != nil {
				t.Fatal(err)
			}
			if _, err := store.db.Exec("PRAGMA ignore_check_constraints=ON"); err != nil {
				t.Fatal(err)
			}
			if err := mutate(store, root); err != nil {
				t.Fatal(err)
			}
			if _, err := store.GetSnapshot(ctx, repo, root.OID); !errors.Is(err, catalog.ErrCorrupt) {
				t.Fatalf("corruption result = %v", err)
			}
		})
	}
}

func TestRetainedListingCorruptionVariants(t *testing.T) {
	tests := map[string]string{
		"oid":         "UPDATE snapshots SET oid=x'01'",
		"parent":      "UPDATE snapshots SET parent=x'01'",
		"author name": "UPDATE snapshots SET author_name=''",
	}
	for name, statement := range tests {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			store := openTestStore(t, filepath.Join(t.TempDir(), "catalog.db"))
			repo := testRepo(t, "list-corruption", nameToRepo(t, name))
			if err := store.CreateRepository(ctx, model.Repository{Key: repo, CreatedAt: time.Unix(1, 0)}); err != nil {
				t.Fatal(err)
			}
			root := testSnapshot(t, repo, testOID(t, 39), nil, time.Unix(2, 0), "root")
			if err := store.PublishSnapshot(ctx, root, catalog.ExpectRef("main", nil)); err != nil {
				t.Fatal(err)
			}
			store.db.SetMaxOpenConns(1)
			if _, err := store.db.Exec("PRAGMA foreign_keys=OFF"); err != nil {
				t.Fatal(err)
			}
			if _, err := store.db.Exec("PRAGMA ignore_check_constraints=ON"); err != nil {
				t.Fatal(err)
			}
			if _, err := store.db.Exec(statement); err != nil {
				t.Fatal(err)
			}
			if _, err := store.ListSnapshots(ctx, repo, catalog.SnapshotQuery{}); !errors.Is(err, catalog.ErrCorrupt) {
				t.Fatalf("corruption result = %v", err)
			}
		})
	}
}

func TestFileRowDecoderRejectsEveryMalformedRepresentation(t *testing.T) {
	store := openTestStore(t, filepath.Join(t.TempDir(), "catalog.db"))
	hash := bytes.Repeat([]byte{1}, 32)
	sha := bytes.Repeat([]byte{2}, 32)
	tests := []struct {
		name       string
		path, kind any
		size       any
		sha, xet   any
	}{
		{name: "path", path: "../bad", kind: "blob", size: int64(1), sha: sha},
		{name: "blob encoding", path: "file", kind: "blob", size: int64(1)},
		{name: "xet sha", path: "file", kind: "xet", size: int64(1), sha: []byte{1}, xet: hash},
		{name: "blob size", path: "file", kind: "blob", size: int64(-1), sha: sha},
		{name: "xet identity", path: "file", kind: "xet", size: int64(1), xet: make([]byte, 32)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			rows, err := store.db.Query("SELECT ?,?,?,?,?", test.path, test.kind, test.size, test.sha, test.xet)
			if err != nil {
				t.Fatal(err)
			}
			defer rows.Close() //nolint:errcheck // test only inspects the decoded row.
			if !rows.Next() {
				t.Fatal("missing synthetic row")
			}
			if _, err = scanFile(rows); !errors.Is(err, catalog.ErrCorrupt) {
				t.Fatalf("decoder result = %v", err)
			}
		})
	}
	if _, err := scanFile(errorScanner{errors.New("scan failure")}); err == nil {
		t.Fatal("scanner error was discarded")
	}
}

func TestListOperationsRejectMalformedRetainedRows(t *testing.T) {
	for _, test := range []struct {
		name, statement string
		list            func(context.Context, *Store, model.RepoKey, model.OID) error
	}{
		{
			name: "repository scalar", statement: "UPDATE repositories SET created_at='bad'",
			list: func(ctx context.Context, store *Store, _ model.RepoKey, _ model.OID) error {
				_, err := store.ListRepositories(ctx, catalog.RepositoryQuery{})
				return err
			},
		},
		{
			name: "repository identity", statement: "UPDATE repositories SET namespace='../bad'",
			list: func(ctx context.Context, store *Store, _ model.RepoKey, _ model.OID) error {
				_, err := store.ListRepositories(ctx, catalog.RepositoryQuery{})
				return err
			},
		},
		{
			name: "file encoding", statement: "UPDATE files SET kind='bad' WHERE path='config.json'",
			list: func(ctx context.Context, store *Store, repo model.RepoKey, oid model.OID) error {
				_, err := store.ListFiles(ctx, repo, testRevisionOID(t, oid), catalog.FileQuery{})
				return err
			},
		},
		{
			name: "file scalar", statement: "UPDATE files SET size='bad' WHERE path='config.json'",
			list: func(ctx context.Context, store *Store, repo model.RepoKey, oid model.OID) error {
				_, err := store.ListFiles(ctx, repo, testRevisionOID(t, oid), catalog.FileQuery{})
				return err
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx := context.Background()
			store := openTestStore(t, filepath.Join(t.TempDir(), "catalog.db"))
			repo := testRepo(t, "list-row-corruption", nameToRepo(t, test.name))
			if err := store.CreateRepository(ctx, model.Repository{Key: repo, CreatedAt: time.Unix(1, 0)}); err != nil {
				t.Fatal(err)
			}
			root := testSnapshot(t, repo, testOID(t, 67), nil, time.Unix(2, 0), "root")
			if err := store.PublishSnapshot(ctx, root, catalog.ExpectRef("main", nil)); err != nil {
				t.Fatal(err)
			}
			store.db.SetMaxOpenConns(1)
			if _, err := store.db.Exec("PRAGMA foreign_keys=OFF"); err != nil {
				t.Fatal(err)
			}
			if _, err := store.db.Exec("PRAGMA ignore_check_constraints=ON"); err != nil {
				t.Fatal(err)
			}
			if _, err := store.db.Exec(test.statement); err != nil {
				t.Fatal(err)
			}
			if err := test.list(ctx, store, repo, root.OID); !errors.Is(err, catalog.ErrCorrupt) {
				t.Fatalf("malformed retained row = %v", err)
			}
		})
	}
}

func TestBrokenSchemaOperationsAreUnavailable(t *testing.T) {
	t.Run("missing files", func(t *testing.T) {
		ctx := context.Background()
		store := openTestStore(t, filepath.Join(t.TempDir(), "catalog.db"))
		repo := testRepo(t, "broken-schema", "files")
		if err := store.CreateRepository(ctx, model.Repository{Key: repo, CreatedAt: time.Unix(1, 0)}); err != nil {
			t.Fatal(err)
		}
		root := testSnapshot(t, repo, testOID(t, 68), nil, time.Unix(2, 0), "root")
		if err := store.PublishSnapshot(ctx, root, catalog.ExpectRef("main", nil)); err != nil {
			t.Fatal(err)
		}
		if _, err := store.db.Exec("PRAGMA foreign_keys=OFF"); err != nil {
			t.Fatal(err)
		}
		if _, err := store.db.Exec("DROP TABLE files"); err != nil {
			t.Fatal(err)
		}
		for name, operation := range map[string]func() error{
			"snapshot": func() error { _, err := store.GetSnapshot(ctx, repo, root.OID); return err },
			"files": func() error {
				_, err := store.ListFiles(ctx, repo, testRevisionOID(t, root.OID), catalog.FileQuery{})
				return err
			},
		} {
			if err := operation(); !errors.Is(err, catalog.ErrUnavailable) {
				t.Errorf("%s = %v", name, err)
			}
		}
	})

	t.Run("missing snapshots", func(t *testing.T) {
		ctx := context.Background()
		store := openTestStore(t, filepath.Join(t.TempDir(), "catalog.db"))
		repo := testRepo(t, "broken-schema", "snapshots")
		if err := store.CreateRepository(ctx, model.Repository{Key: repo, CreatedAt: time.Unix(1, 0)}); err != nil {
			t.Fatal(err)
		}
		if _, err := store.db.Exec("PRAGMA foreign_keys=OFF"); err != nil {
			t.Fatal(err)
		}
		if _, err := store.db.Exec("DROP TABLE snapshots"); err != nil {
			t.Fatal(err)
		}
		if _, err := store.ListSnapshots(ctx, repo, catalog.SnapshotQuery{}); !errors.Is(err, catalog.ErrUnavailable) {
			t.Fatalf("snapshot list = %v", err)
		}
		root := testSnapshot(t, repo, testOID(t, 69), nil, time.Unix(2, 0), "root")
		if err := store.PublishSnapshot(ctx, root, catalog.ExpectRef("main", nil)); !errors.Is(err, catalog.ErrUnavailable) {
			t.Fatalf("publication = %v", err)
		}
	})
}

func TestCASWriteFailureIsUnavailableAndAtomic(t *testing.T) {
	ctx := context.Background()
	store := openTestStore(t, filepath.Join(t.TempDir(), "catalog.db"))
	repo := testRepo(t, "cas-failure", "model")
	if err := store.CreateRepository(ctx, model.Repository{Key: repo, CreatedAt: time.Unix(1, 0)}); err != nil {
		t.Fatal(err)
	}
	root := testSnapshot(t, repo, testOID(t, 70), nil, time.Unix(2, 0), "root")
	child := testSnapshot(t, repo, testOID(t, 71), &root.OID, time.Unix(3, 0), "child")
	if err := store.PublishSnapshot(ctx, root, catalog.ExpectRef("main", nil)); err != nil {
		t.Fatal(err)
	}
	if err := store.PublishSnapshot(ctx, child, catalog.ExpectRef("main", &root.OID)); err != nil {
		t.Fatal(err)
	}
	if err := store.CompareAndSwapRef(ctx, repo, "release", nil, root.OID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.Exec("CREATE TRIGGER fail_cas BEFORE UPDATE ON refs WHEN OLD.ref_name='release' BEGIN SELECT RAISE(ABORT,'injected'); END"); err != nil {
		t.Fatal(err)
	}
	if err := store.CompareAndSwapRef(ctx, repo, "release", &root.OID, child.OID); !errors.Is(err, catalog.ErrUnavailable) {
		t.Fatalf("CAS SQL failure = %v", err)
	}
	ref, err := store.GetRef(ctx, repo, "release")
	if err != nil || ref.OID != root.OID {
		t.Fatalf("release after failed CAS = %#v, %v", ref, err)
	}
}

func TestClosedStoreAndCancellation(t *testing.T) {
	store := openTestStore(t, filepath.Join(t.TempDir(), "catalog.db"))
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("second close = %v", err)
	}
	repo := testRepo(t, "closed", "model")
	if _, err := store.GetRepository(context.Background(), repo); !errors.Is(err, catalog.ErrUnavailable) {
		t.Fatalf("closed read = %v", err)
	}
	if _, err := store.ListRepositories(context.Background(), catalog.RepositoryQuery{}); !errors.Is(err, catalog.ErrUnavailable) {
		t.Fatalf("closed list = %v", err)
	}
	if _, err := store.GetRef(context.Background(), repo, "main"); !errors.Is(err, catalog.ErrUnavailable) {
		t.Fatalf("closed ref = %v", err)
	}
	root := testSnapshot(t, repo, testOID(t, 66), nil, time.Unix(2, 0), "root")
	if err := store.PublishSnapshot(context.Background(), root, catalog.ExpectRef("main", nil)); !errors.Is(err, catalog.ErrUnavailable) {
		t.Fatalf("closed publication = %v", err)
	}

	store = openTestStore(t, filepath.Join(t.TempDir(), "canceled.db"))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := store.CreateRepository(ctx, model.Repository{Key: repo, CreatedAt: time.Unix(1, 0)}); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled create = %v", err)
	}
}

func TestRepositoryRefAndFileOperations(t *testing.T) {
	ctx := context.Background()
	store := openTestStore(t, filepath.Join(t.TempDir(), "catalog.db"))
	repos := []model.RepoKey{
		testRepo(t, "operations", "b"), testRepo(t, "operations", "a"), testRepo(t, "other", "c"),
	}
	for index, repo := range repos {
		if err := store.CreateRepository(ctx, model.Repository{Key: repo, CreatedAt: time.Unix(int64(index+1), 0)}); err != nil {
			t.Fatal(err)
		}
	}
	if err := store.CreateRepository(ctx, model.Repository{Key: repos[0], CreatedAt: time.Unix(1, 0)}); !errors.Is(err, catalog.ErrAlreadyExists) {
		t.Fatalf("duplicate repository = %v", err)
	}
	if _, err := store.GetRepository(ctx, testRepo(t, "missing", "repo")); !errors.Is(err, catalog.ErrNotFound) {
		t.Fatalf("missing repository = %v", err)
	}
	first, err := store.ListRepositories(ctx, catalog.RepositoryQuery{Namespace: "operations", Limit: 1})
	if err != nil || len(first.Items) != 1 || first.Items[0].Key != repos[1] || first.NextCursor == "" {
		t.Fatalf("first repository page = %#v, %v", first, err)
	}
	second, err := store.ListRepositories(ctx, catalog.RepositoryQuery{Namespace: "operations", Limit: 1, Cursor: first.NextCursor})
	if err != nil || len(second.Items) != 1 || second.Items[0].Key != repos[0] || second.NextCursor != "" {
		t.Fatalf("second repository page = %#v, %v", second, err)
	}
	for _, query := range []catalog.RepositoryQuery{{Cursor: "bad"}, {Limit: -1}, {Type: "dataset"}, {Namespace: "../bad"}} {
		if _, err := store.ListRepositories(ctx, query); !errors.Is(err, catalog.ErrInvalid) {
			t.Fatalf("invalid repository query %#v = %v", query, err)
		}
	}

	repo := repos[1]
	root := testSnapshot(t, repo, testOID(t, 40), nil, time.Unix(-1, 0), "root")
	secondSnapshot := testSnapshot(t, repo, testOID(t, 41), &root.OID, time.Unix(0, 0), "second")
	if err := store.PublishSnapshot(ctx, root, catalog.ExpectRef("main", nil)); err != nil {
		t.Fatal(err)
	}
	if err := store.PublishSnapshot(ctx, secondSnapshot, catalog.ExpectRef("main", &root.OID)); err != nil {
		t.Fatal(err)
	}
	snapshots, err := store.ListSnapshots(ctx, repo, catalog.SnapshotQuery{Limit: 1})
	if err != nil || len(snapshots.Items) != 1 || snapshots.Items[0].OID != secondSnapshot.OID || snapshots.NextCursor == "" {
		t.Fatalf("first snapshot page = %#v, %v", snapshots, err)
	}
	if _, err := store.ListSnapshots(ctx, repo, catalog.SnapshotQuery{Limit: 1, Cursor: snapshots.NextCursor}); err != nil {
		t.Fatalf("second snapshot page = %v", err)
	}
	if _, err := store.ListSnapshots(ctx, repo, catalog.SnapshotQuery{Cursor: "bad"}); !errors.Is(err, catalog.ErrInvalid) {
		t.Fatalf("invalid snapshot cursor = %v", err)
	}

	if err := store.CompareAndSwapRef(ctx, repo, "release", nil, root.OID); err != nil {
		t.Fatal(err)
	}
	if err := store.CompareAndSwapRef(ctx, repo, "release", nil, root.OID); err != nil {
		t.Fatalf("target-state CAS = %v", err)
	}
	wrong := testOID(t, 49)
	if err := store.CompareAndSwapRef(ctx, repo, "release", &wrong, secondSnapshot.OID); !errors.Is(err, catalog.ErrConflict) {
		t.Fatalf("stale CAS = %v", err)
	}
	if err := store.CompareAndSwapRef(ctx, repo, "release", &root.OID, secondSnapshot.OID); err != nil {
		t.Fatalf("advance ref = %v", err)
	}
	if err := store.CompareAndSwapRef(ctx, repo, "missing-target", nil, wrong); !errors.Is(err, catalog.ErrNotFound) {
		t.Fatalf("missing target CAS = %v", err)
	}
	if _, err := store.GetRef(ctx, repo, "missing"); !errors.Is(err, catalog.ErrNotFound) {
		t.Fatalf("missing ref = %v", err)
	}

	file, err := store.GetFile(ctx, repo, testRevisionRef(t, "main"), "config.json")
	if err != nil || file.Ref.Kind() != model.FileKindBlob {
		t.Fatalf("get file = %#v, %v", file, err)
	}
	if _, err := store.GetFile(ctx, repo, testRevisionRef(t, "main"), "missing"); !errors.Is(err, catalog.ErrNotFound) {
		t.Fatalf("missing file = %v", err)
	}
	if _, err := store.GetFile(ctx, repo, testRevisionRef(t, "main"), "../bad"); !errors.Is(err, catalog.ErrInvalid) {
		t.Fatalf("invalid file = %v", err)
	}
	if _, err := store.ListFiles(ctx, repo, testRevisionOID(t, wrong), catalog.FileQuery{}); !errors.Is(err, catalog.ErrNotFound) {
		t.Fatalf("list missing snapshot = %v", err)
	}
	prefixPage, err := store.ListFiles(ctx, repo, testRevisionRef(t, "main"), catalog.FileQuery{Prefix: "config"})
	if err != nil || len(prefixPage.Items) != 1 || prefixPage.Items[0].Path != "config.json" {
		t.Fatalf("prefix page = %#v, %v", prefixPage, err)
	}
	staleCursor := enc(cursor{Kind: "files", Repository: sortKey(repo), Last: "config.json", OID: wrong.String()})
	if _, err := store.ListFiles(ctx, repo, testRevisionRef(t, "main"), catalog.FileQuery{Cursor: staleCursor}); !errors.Is(err, catalog.ErrConflict) {
		t.Fatalf("stale file cursor = %v", err)
	}
	wrongOperationCursor := enc(cursor{Kind: "snapshots", Repository: sortKey(repo), Last: "config.json", OID: secondSnapshot.OID.String()})
	if _, err := store.ListFiles(ctx, repo, testRevisionRef(t, "main"), catalog.FileQuery{Cursor: wrongOperationCursor}); !errors.Is(err, catalog.ErrInvalid) {
		t.Fatalf("wrong-operation file cursor = %v", err)
	}
}

func TestEncodingAndErrorBoundaries(t *testing.T) {
	for _, value := range []string{
		"%%%",
		base64.RawURLEncoding.EncodeToString([]byte(`{"unknown":true}`)),
		base64.RawURLEncoding.EncodeToString([]byte(`{"kind":"files"}{}`)),
	} {
		if _, err := dec(value); err == nil {
			t.Fatalf("invalid cursor accepted: %q", value)
		}
	}
	if got, err := limit(0); err != nil || got != catalog.DefaultPageSize {
		t.Fatalf("default limit = %d, %v", got, err)
	}
	if _, err := limit(catalog.MaxPageSize + 1); !errors.Is(err, catalog.ErrInvalid) {
		t.Fatalf("oversized limit = %v", err)
	}
	if oid, present, err := copyExpected(nil); err != nil || present || !oid.IsZero() {
		t.Fatalf("nil expectation = %s/%v, %v", oid, present, err)
	}
	zero := model.OID{}
	if _, _, err := copyExpected(&zero); !errors.Is(err, catalog.ErrInvalid) {
		t.Fatalf("zero expectation = %v", err)
	}
	var oid model.OID
	if copyOID(&oid, []byte{1}) || copyOID(&oid, make([]byte, 20)) {
		t.Fatal("invalid encoded OID accepted")
	}
	if boolInt(false) != 0 || boolInt(true) != 1 {
		t.Fatal("boolean encoding mismatch")
	}
	if !errors.Is(rowErr(context.Background(), sql.ErrNoRows), catalog.ErrNotFound) {
		t.Fatal("no-row error not classified")
	}
	if rowErr(context.Background(), nil) != nil {
		t.Fatal("nil row error not preserved")
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if !errors.Is(rowErr(canceled, errors.New("scan")), context.Canceled) {
		t.Fatal("canceled row error not preserved")
	}
	if !errors.Is(rowErr(context.Background(), codedError{sqliteNotADB}), catalog.ErrCorrupt) {
		t.Fatal("coded row corruption not classified")
	}
	if !errors.Is(rowErr(context.Background(), sql.ErrConnDone), catalog.ErrUnavailable) {
		t.Fatal("closed connection not classified")
	}
	if !errors.Is(dbErr(canceled, errors.New("backend")), context.Canceled) || dbErr(context.Background(), nil) != nil {
		t.Fatal("database error classification mismatch")
	}

	store := openTestStore(t, filepath.Join(t.TempDir(), "catalog.db"))
	var value int
	if err := scanOne(context.Background(), store.db, "SELECT 1 UNION ALL SELECT 2", nil, func(row scanner) error {
		return row.Scan(&value)
	}); !errors.Is(err, catalog.ErrCorrupt) {
		t.Fatalf("non-unique query = %v", err)
	}
	if err := scanOne(context.Background(), store.db, "SELECT 'not-an-integer'", nil, func(row scanner) error {
		return row.Scan(&value)
	}); !errors.Is(err, catalog.ErrCorrupt) {
		t.Fatalf("scan conversion = %v", err)
	}
	if err := scanOne(context.Background(), store.db, "SELECT 1", nil, func(scanner) error {
		return corrupt(errors.New("retained corruption"))
	}); !errors.Is(err, catalog.ErrCorrupt) {
		t.Fatalf("typed scan corruption = %v", err)
	}
}

func TestInvalidInputsAcrossOperations(t *testing.T) {
	ctx := context.Background()
	store := openTestStore(t, filepath.Join(t.TempDir(), "catalog.db"))
	repo := testRepo(t, "invalid", "model")
	if err := store.CreateRepository(ctx, model.Repository{Key: repo, CreatedAt: time.Unix(1, 0)}); err != nil {
		t.Fatal(err)
	}
	root := testSnapshot(t, repo, testOID(t, 50), nil, time.Unix(2, 0), "root")
	if err := store.PublishSnapshot(ctx, root, catalog.ExpectRef("main", nil)); err != nil {
		t.Fatal(err)
	}
	badKey := model.RepoKey{}
	zero := model.OID{}
	invalidSnapshot := root
	invalidSnapshot.OID = zero
	parentMismatch := testSnapshot(t, repo, testOID(t, 51), &root.OID, time.Unix(3, 0), "mismatch")
	wrong := testOID(t, 52)
	badSnapshotCursor := enc(cursor{Kind: "snapshots", Repository: sortKey(repo), Timestamp: new(int64), OID: "bad"})
	badFileCursor := enc(cursor{Kind: "files", Repository: sortKey(repo), Last: "config.json", OID: "bad"})

	checks := map[string]func() error{
		"create repository": func() error {
			return store.CreateRepository(ctx, model.Repository{CreatedAt: time.Unix(1, 0)})
		},
		"get snapshot key":   func() error { _, err := store.GetSnapshot(ctx, badKey, root.OID); return err },
		"get snapshot oid":   func() error { _, err := store.GetSnapshot(ctx, repo, zero); return err },
		"resolve key":        func() error { _, err := store.ResolveRevision(ctx, badKey, model.Revision{}); return err },
		"resolve revision":   func() error { _, err := store.ResolveRevision(ctx, repo, model.Revision{}); return err },
		"list snapshots key": func() error { _, err := store.ListSnapshots(ctx, badKey, catalog.SnapshotQuery{}); return err },
		"list snapshots limit": func() error {
			_, err := store.ListSnapshots(ctx, repo, catalog.SnapshotQuery{Limit: -1})
			return err
		},
		"list snapshots oid cursor": func() error {
			_, err := store.ListSnapshots(ctx, repo, catalog.SnapshotQuery{Cursor: badSnapshotCursor})
			return err
		},
		"get ref":          func() error { _, err := store.GetRef(ctx, repo, "../bad"); return err },
		"cas ref":          func() error { return store.CompareAndSwapRef(ctx, repo, "../bad", nil, root.OID) },
		"cas expectation":  func() error { return store.CompareAndSwapRef(ctx, repo, "main", &zero, root.OID) },
		"publish snapshot": func() error { return store.PublishSnapshot(ctx, invalidSnapshot, catalog.ExpectRef("main", nil)) },
		"publish ref": func() error {
			return store.PublishSnapshot(ctx, parentMismatch, catalog.ExpectRef("../bad", &root.OID))
		},
		"publish expectation": func() error {
			return store.PublishSnapshot(ctx, parentMismatch, catalog.ExpectRef("main", &zero))
		},
		"publish parent": func() error { return store.PublishSnapshot(ctx, parentMismatch, catalog.ExpectRef("main", &wrong)) },
		"get file key": func() error {
			_, err := store.GetFile(ctx, badKey, testRevisionOID(t, root.OID), "config.json")
			return err
		},
		"get file path": func() error {
			_, err := store.GetFile(ctx, repo, testRevisionOID(t, root.OID), "../bad")
			return err
		},
		"get file revision": func() error { _, err := store.GetFile(ctx, repo, model.Revision{}, "config.json"); return err },
		"list files key": func() error {
			_, err := store.ListFiles(ctx, badKey, testRevisionOID(t, root.OID), catalog.FileQuery{})
			return err
		},
		"list files limit": func() error {
			_, err := store.ListFiles(ctx, repo, testRevisionOID(t, root.OID), catalog.FileQuery{Limit: -1})
			return err
		},
		"list files prefix": func() error {
			_, err := store.ListFiles(ctx, repo, testRevisionOID(t, root.OID), catalog.FileQuery{Prefix: "../bad"})
			return err
		},
		"list files revision": func() error { _, err := store.ListFiles(ctx, repo, model.Revision{}, catalog.FileQuery{}); return err },
		"list files oid cursor": func() error {
			_, err := store.ListFiles(ctx, repo, testRevisionOID(t, root.OID), catalog.FileQuery{Cursor: badFileCursor})
			return err
		},
	}
	for name, check := range checks {
		if err := check(); !errors.Is(err, catalog.ErrInvalid) {
			t.Errorf("%s = %v", name, err)
		}
	}
}

func TestUnexpectedDatabaseClosureIsUnavailable(t *testing.T) {
	ctx := context.Background()
	store := openTestStore(t, filepath.Join(t.TempDir(), "catalog.db"))
	repo := testRepo(t, "unavailable", "model")
	root := testSnapshot(t, repo, testOID(t, 53), nil, time.Unix(2, 0), "root")
	if err := store.db.Close(); err != nil {
		t.Fatal(err)
	}
	checks := map[string]func() error{
		"create": func() error {
			return store.CreateRepository(ctx, model.Repository{Key: repo, CreatedAt: time.Unix(1, 0)})
		},
		"get repository":    func() error { _, err := store.GetRepository(ctx, repo); return err },
		"list repositories": func() error { _, err := store.ListRepositories(ctx, catalog.RepositoryQuery{}); return err },
		"get snapshot":      func() error { _, err := store.GetSnapshot(ctx, repo, root.OID); return err },
		"resolve":           func() error { _, err := store.ResolveRevision(ctx, repo, testRevisionRef(t, "main")); return err },
		"list snapshots":    func() error { _, err := store.ListSnapshots(ctx, repo, catalog.SnapshotQuery{}); return err },
		"get ref":           func() error { _, err := store.GetRef(ctx, repo, "main"); return err },
		"cas":               func() error { return store.CompareAndSwapRef(ctx, repo, "main", nil, root.OID) },
		"publish":           func() error { return store.PublishSnapshot(ctx, root, catalog.ExpectRef("main", nil)) },
		"get file": func() error {
			_, err := store.GetFile(ctx, repo, testRevisionOID(t, root.OID), "config.json")
			return err
		},
		"list files": func() error {
			_, err := store.ListFiles(ctx, repo, testRevisionOID(t, root.OID), catalog.FileQuery{})
			return err
		},
	}
	for name, check := range checks {
		if err := check(); !errors.Is(err, catalog.ErrUnavailable) {
			t.Errorf("%s = %v", name, err)
		}
	}
}

func openTestStore(t testing.TB, path string) *Store {
	t.Helper()
	store, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return store
}

func testRepo(t testing.TB, namespace, name string) model.RepoKey {
	t.Helper()
	repo, err := model.NewRepoKey(namespace, name, model.RepoTypeModel)
	if err != nil {
		t.Fatal(err)
	}
	return repo
}

func testOID(t testing.TB, value byte) model.OID {
	t.Helper()
	oid, err := model.ParseOID(strings.Repeat(fmt.Sprintf("%02x", value), 20))
	if err != nil {
		t.Fatal(err)
	}
	return oid
}

func testSnapshot(
	t testing.TB,
	repo model.RepoKey,
	oid model.OID,
	parent *model.OID,
	createdAt time.Time,
	message string,
) model.Snapshot {
	t.Helper()
	blobSum := sha256.Sum256([]byte("blob"))
	blob, err := model.NewBlobFileRef(blobSum, 4)
	if err != nil {
		t.Fatal(err)
	}
	xetSum := sha256.Sum256([]byte("xet"))
	xet, err := model.NewXetFileRef(xethash.Chunk([]byte("xet")), 3, &xetSum)
	if err != nil {
		t.Fatal(err)
	}
	return model.Snapshot{
		Repo: repo, OID: oid, Parent: parent, CreatedAt: createdAt,
		Author: model.Identity{Name: "author", Email: "author@example.com"}, Message: message,
		Files: []model.FileEntry{{Path: "config.json", Ref: blob}, {Path: "weights/model.bin", Ref: xet}},
	}
}

func testRevisionRef(t testing.TB, ref model.RefName) model.Revision {
	t.Helper()
	revision, err := model.RevisionFromRef(ref)
	if err != nil {
		t.Fatal(err)
	}
	return revision
}

func testRevisionOID(t testing.TB, oid model.OID) model.Revision {
	t.Helper()
	revision, err := model.RevisionFromOID(oid)
	if err != nil {
		t.Fatal(err)
	}
	return revision
}

type errorScanner struct{ err error }

func (scanner errorScanner) Scan(...any) error { return scanner.err }

type codedError struct{ code int }

func (err codedError) Error() string { return "coded database error" }
func (err codedError) Code() int     { return err.code }

func nameToRepo(t testing.TB, value string) string {
	t.Helper()
	return strings.ReplaceAll(value, " ", "-")
}
