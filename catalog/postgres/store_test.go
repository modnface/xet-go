package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jmwoliver/xet-go/catalog"
	"github.com/jmwoliver/xet-go/model"
	"github.com/jmwoliver/xet-go/xethash"
)

func TestOptionsAndConstructionErrors(t *testing.T) {
	if schema, err := parseOptions(Options{}); err != nil || schema != "xet_catalog" {
		t.Fatalf("default options = %q, %v", schema, err)
	}
	for _, schema := range []string{"catalog", "_catalog2", "a" + strings.Repeat("0", 62)} {
		if got, err := parseOptions(Options{Schema: schema}); err != nil || got != schema {
			t.Fatalf("valid schema %q = %q, %v", schema, got, err)
		}
	}
	for _, schema := range []string{"Catalog", "has-dash", "1catalog", `x"y`, "a.b", "a" + strings.Repeat("0", 63)} {
		if _, err := parseOptions(Options{Schema: schema}); !errors.Is(err, catalog.ErrInvalid) {
			t.Fatalf("invalid schema %q = %v", schema, err)
		}
	}
	if _, err := New(context.Background(), nil, Options{}); !errors.Is(err, catalog.ErrInvalid) {
		t.Fatalf("nil pool = %v", err)
	}
	secret := "catalog-secret-password"
	if _, err := Open(context.Background(), "postgres://user:"+secret+"@%", Options{}); err == nil ||
		strings.Contains(err.Error(), secret) {
		t.Fatalf("invalid connection error = %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Open(ctx, "postgres://user:"+secret+"@127.0.0.1:1/database?sslmode=disable", Options{}); !errors.Is(err, context.Canceled) ||
		strings.Contains(err.Error(), secret) {
		t.Fatalf("canceled connection error = %v", err)
	}
}

func TestEncodingAndErrorHelpers(t *testing.T) {
	key := testRepoKey(t, "team", "model")
	if got, ok := parseScope(scope(key)); !ok || got != key {
		t.Fatalf("scope round trip = %#v, %v", got, ok)
	}
	for _, value := range []string{"", "model\x00team", "dataset\x00team\x00model", "model\x00../bad\x00model"} {
		if _, ok := parseScope(value); ok {
			t.Fatalf("invalid scope accepted: %q", value)
		}
	}
	position := int64(4)
	encoded := enc(cursor{Op: "snapshots", Scope: scope(key), Time: &position, OID: testOID(t, 1).String()})
	decoded, err := dec(encoded)
	if err != nil || decoded.Op != "snapshots" || decoded.V != schemaVersion || decoded.Time == nil || *decoded.Time != position {
		t.Fatalf("cursor round trip = %#v, %v", decoded, err)
	}
	for _, value := range []string{
		"%%%",
		base64.RawURLEncoding.EncodeToString([]byte(`{"v":1,"Op":"files","unknown":true}`)),
		base64.RawURLEncoding.EncodeToString([]byte(`{"v":1}{}`)),
		base64.RawURLEncoding.EncodeToString([]byte(`{"v":2}`)),
	} {
		if _, err := dec(value); err == nil {
			t.Fatalf("invalid cursor accepted: %q", value)
		}
	}
	if _, err := limit(-1); !errors.Is(err, catalog.ErrInvalid) {
		t.Fatalf("negative limit = %v", err)
	}
	if got, err := limit(0); err != nil || got != catalog.DefaultPageSize {
		t.Fatalf("default limit = %d, %v", got, err)
	}
	if _, err := limit(catalog.MaxPageSize + 1); !errors.Is(err, catalog.ErrInvalid) {
		t.Fatalf("oversized limit = %v", err)
	}
	if _, err := oidBytes(nil); !errors.Is(err, catalog.ErrCorrupt) {
		t.Fatalf("short OID = %v", err)
	}
	if _, err := oidBytes(make([]byte, 20)); !errors.Is(err, catalog.ErrCorrupt) {
		t.Fatalf("zero OID = %v", err)
	}
	if err := expectOne(context.Background(), pgconn.NewCommandTag("INSERT 0 0"), nil, "test"); !errors.Is(err, catalog.ErrUnavailable) {
		t.Fatalf("suppressed write = %v", err)
	}
	if err := expectOne(context.Background(), pgconn.CommandTag{}, errors.New("backend"), "test"); !errors.Is(err, catalog.ErrUnavailable) {
		t.Fatalf("failed write = %v", err)
	}
	if err := rowErr(context.Background(), pgx.ErrNoRows); !errors.Is(err, catalog.ErrNotFound) {
		t.Fatalf("missing row = %v", err)
	}
	scanFailure := pgx.ScanArgError{ColumnIndex: 1, FieldName: "created_at", Err: errors.New("bad integer")}
	if err := rowErr(context.Background(), scanFailure); !errors.Is(err, catalog.ErrCorrupt) {
		t.Fatalf("scan failure = %v", err)
	}
	if err := dbErr(context.Background(), &pgconn.PgError{Code: "40001"}); !errors.Is(err, catalog.ErrUnavailable) {
		t.Fatalf("serialization failure = %v", err)
	}
	if err := dbErr(context.Background(), &pgconn.PgError{Code: "22003"}); !errors.Is(err, catalog.ErrUnavailable) {
		t.Fatalf("data exception = %v", err)
	}
	if got := (&Store{schema: "select"}).q("files"); got != `"select"."files"` {
		t.Fatalf("quoted reserved schema = %q", got)
	}
	if err := schemaErr(context.Background(), pgx.ScanArgError{Err: errors.New("bad schema value")}); !errors.Is(err, catalog.ErrCorrupt) {
		t.Fatalf("schema scan error = %v", err)
	}
	if err := schemaErr(context.Background(), &pgconn.PgError{Code: "42703"}); !errors.Is(err, catalog.ErrCorrupt) {
		t.Fatalf("missing schema column = %v", err)
	}
	if err := schemaErr(context.Background(), errors.New("backend")); !errors.Is(err, catalog.ErrUnavailable) {
		t.Fatalf("schema backend error = %v", err)
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := dbErr(canceled, errors.New("backend")); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled backend error = %v", err)
	}
	if _, err := scanFile(errorScanner{pgx.ErrNoRows}); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("scan error = %v", err)
	}
	if _, err := scanFile(fileScanner{path: "file", kind: "blob", size: 1, sha: []byte{1}}); !errors.Is(err, catalog.ErrCorrupt) {
		t.Fatalf("malformed file encoding = %v", err)
	}
	if _, err := scanFile(fileScanner{path: "file", kind: "xet", size: 1, xet: make([]byte, 32)}); !errors.Is(err, catalog.ErrCorrupt) {
		t.Fatalf("invalid xet identity = %v", err)
	}
	if err := rowErr(context.Background(), corrupt(errors.New("retained"))); !errors.Is(err, catalog.ErrCorrupt) {
		t.Fatalf("typed row corruption = %v", err)
	}
	if err := schemaErr(context.Background(), nil); err != nil {
		t.Fatalf("nil schema error = %v", err)
	}
	if err := schemaErr(canceled, errors.New("backend")); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled schema error = %v", err)
	}
	if err := validKey(canceled, key); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled key validation = %v", err)
	}
}

type errorScanner struct{ err error }

func (scanner errorScanner) Scan(...any) error { return scanner.err }

type fileScanner struct {
	path, kind string
	size       int64
	sha, xet   []byte
}

func (scanner fileScanner) Scan(destinations ...any) error {
	*destinations[0].(*string) = scanner.path
	*destinations[1].(*string) = scanner.kind
	*destinations[2].(*int64) = scanner.size
	*destinations[3].(*[]byte) = scanner.sha
	*destinations[4].(*[]byte) = scanner.xet
	return nil
}

var integrationSequence atomic.Uint64

func TestPostgreSQLIntegration(t *testing.T) {
	if os.Getenv("XET_POSTGRES_INTEGRATION") != "1" {
		t.Skip("set XET_POSTGRES_INTEGRATION=1 with XET_POSTGRES_DSN to run")
	}
	if os.Getenv("XET_POSTGRES_DSN") == "" {
		t.Fatal("XET_POSTGRES_DSN is required")
	}
	t.Run("complete durable behavior", testCompleteDurableBehavior)
	t.Run("initialization and ownership", testInitializationAndOwnership)
	t.Run("independent writer serialization", testIndependentWriterSerialization)
	t.Run("independent process durability", testIndependentProcessDurability)
	t.Run("probe backend faults are typed", testProbeBackendFaults)
	t.Run("publication faults roll back", testPublicationFaults)
	t.Run("retained corruption is detected", testRetainedCorruption)
	t.Run("cursor state is bound", testCursorBinding)
	t.Run("input and state errors are typed", testInputAndStateErrors)
	t.Run("closed pool is unavailable", testClosedPool)
}

func testCompleteDurableBehavior(t *testing.T) {
	ctx := context.Background()
	pool, schema, store := integrationStore(t)
	repo := testRepoKey(t, "durable", "model")
	created := time.Date(2026, 8, 11, 2, 3, 4, 567890123, time.FixedZone("offset", 3600))
	if err := store.CreateRepository(ctx, model.Repository{Key: repo, CreatedAt: created}); err != nil {
		t.Fatal(err)
	}
	if err := store.CreateRepository(ctx, model.Repository{Key: repo, CreatedAt: created}); !errors.Is(err, catalog.ErrAlreadyExists) {
		t.Fatalf("duplicate repository = %v", err)
	}
	for index, name := range []string{"alpha", "zeta"} {
		key := testRepoKey(t, "durable", name)
		if err := store.CreateRepository(ctx, model.Repository{Key: key, CreatedAt: created.Add(time.Duration(index + 1))}); err != nil {
			t.Fatal(err)
		}
	}
	gotRepository, err := store.GetRepository(ctx, repo)
	if err != nil || gotRepository.CreatedAt.UnixNano() != created.UnixNano() || gotRepository.CreatedAt.Location() != time.UTC {
		t.Fatalf("repository = %#v, %v", gotRepository, err)
	}
	firstRepos, err := store.ListRepositories(ctx, catalog.RepositoryQuery{Namespace: "durable", Limit: 2})
	if err != nil || len(firstRepos.Items) != 2 || firstRepos.NextCursor == "" {
		t.Fatalf("first repository page = %#v, %v", firstRepos, err)
	}
	secondRepos, err := store.ListRepositories(ctx, catalog.RepositoryQuery{Namespace: "durable", Limit: 2, Cursor: firstRepos.NextCursor})
	if err != nil || len(secondRepos.Items) != 1 || secondRepos.NextCursor != "" {
		t.Fatalf("second repository page = %#v, %v", secondRepos, err)
	}
	for _, name := range []string{"zeta", "éclair"} {
		key := testRepoKey(t, "tëam", name)
		if err := store.CreateRepository(ctx, model.Repository{Key: key, CreatedAt: created}); err != nil {
			t.Fatal(err)
		}
	}
	unicodeRepositories, err := store.ListRepositories(ctx, catalog.RepositoryQuery{Namespace: "tëam"})
	if err != nil || len(unicodeRepositories.Items) != 2 || unicodeRepositories.Items[0].Key.Name != "zeta" || unicodeRepositories.Items[1].Key.Name != "éclair" {
		t.Fatalf("UTF-8 byte order = %#v, %v", unicodeRepositories, err)
	}
	unicodeRepositories, err = store.ListRepositories(ctx, catalog.RepositoryQuery{Namespace: "tëam", Limit: 1})
	if err != nil || len(unicodeRepositories.Items) != 1 || unicodeRepositories.Items[0].Key.Name != "zeta" || unicodeRepositories.NextCursor == "" {
		t.Fatalf("first UTF-8 repository page = %#v, %v", unicodeRepositories, err)
	}
	unicodeRepositories, err = store.ListRepositories(ctx, catalog.RepositoryQuery{Namespace: "tëam", Limit: 1, Cursor: unicodeRepositories.NextCursor})
	if err != nil || len(unicodeRepositories.Items) != 1 || unicodeRepositories.Items[0].Key.Name != "éclair" || unicodeRepositories.NextCursor != "" {
		t.Fatalf("second UTF-8 repository page = %#v, %v", unicodeRepositories, err)
	}

	unicodeFileRepo := testRepoKey(t, "tëam", "unicode-files")
	if err := store.CreateRepository(ctx, model.Repository{Key: unicodeFileRepo, CreatedAt: created}); err != nil {
		t.Fatal(err)
	}
	unicodeRoot := testSnapshot(t, unicodeFileRepo, testOID(t, 10), nil, created.Add(time.Second), "unicode files")
	unicodeRoot.Files = []model.FileEntry{
		{Path: "zeta", Ref: unicodeRoot.Files[0].Ref},
		{Path: "éclair", Ref: unicodeRoot.Files[1].Ref},
	}
	if err := store.PublishSnapshot(ctx, unicodeRoot, catalog.ExpectRef("main", nil)); err != nil {
		t.Fatal(err)
	}
	unicodeFiles, err := store.ListFiles(ctx, unicodeFileRepo, testRevisionRef(t, "main"), catalog.FileQuery{Limit: 1})
	if err != nil || len(unicodeFiles.Items) != 1 || unicodeFiles.Items[0].Path != "zeta" || unicodeFiles.NextCursor == "" {
		t.Fatalf("first UTF-8 file page = %#v, %v", unicodeFiles, err)
	}
	unicodeFiles, err = store.ListFiles(ctx, unicodeFileRepo, testRevisionRef(t, "main"), catalog.FileQuery{Limit: 1, Cursor: unicodeFiles.NextCursor})
	if err != nil || len(unicodeFiles.Items) != 1 || unicodeFiles.Items[0].Path != "éclair" || unicodeFiles.NextCursor != "" {
		t.Fatalf("second UTF-8 file page = %#v, %v", unicodeFiles, err)
	}

	root := testSnapshot(t, repo, testOID(t, 1), nil, created.Add(time.Second), "root")
	if err := store.PublishSnapshot(ctx, root, catalog.ExpectRef("development", nil)); err != nil {
		t.Fatal(err)
	}
	for _, name := range []model.RefName{"development", "main"} {
		ref, refErr := store.GetRef(ctx, repo, name)
		if refErr != nil || ref.OID != root.OID {
			t.Fatalf("initial ref %q = %#v, %v", name, ref, refErr)
		}
	}
	byOID, err := store.GetSnapshot(ctx, repo, root.OID)
	if err != nil || byOID.CreatedAt.UnixNano() != root.CreatedAt.UnixNano() || len(byOID.Files) != 3 ||
		byOID.Files[0].Ref.Kind() != model.FileKindBlob || byOID.Files[1].Ref.Kind() != model.FileKindXet {
		t.Fatalf("root snapshot = %#v, %v", byOID, err)
	}
	mainRevision := testRevisionRef(t, "main")
	resolved, err := store.ResolveRevision(ctx, repo, mainRevision)
	if err != nil || resolved.OID != root.OID {
		t.Fatalf("resolved root = %#v, %v", resolved, err)
	}
	ordinary, err := store.GetFile(ctx, repo, mainRevision, "config.json")
	if err != nil || ordinary.Ref.Kind() != model.FileKindBlob {
		t.Fatalf("ordinary file = %#v, %v", ordinary, err)
	}
	if _, err := store.GetFile(ctx, repo, mainRevision, "missing"); !errors.Is(err, catalog.ErrNotFound) {
		t.Fatalf("missing file = %v", err)
	}
	firstFiles, err := store.ListFiles(ctx, repo, mainRevision, catalog.FileQuery{Limit: 1})
	if err != nil || len(firstFiles.Items) != 1 || firstFiles.NextCursor == "" || firstFiles.SnapshotOID != root.OID {
		t.Fatalf("first file page = %#v, %v", firstFiles, err)
	}
	remaining, err := store.ListFiles(ctx, repo, testRevisionOID(t, root.OID), catalog.FileQuery{Limit: 2, Cursor: firstFiles.NextCursor})
	if err != nil || len(remaining.Items) != 2 || remaining.NextCursor != "" || remaining.SnapshotOID != root.OID {
		t.Fatalf("remaining files = %#v, %v", remaining, err)
	}
	prefixed, err := store.ListFiles(ctx, repo, mainRevision, catalog.FileQuery{Prefix: "weights/"})
	if err != nil || len(prefixed.Items) != 2 {
		t.Fatalf("prefixed files = %#v, %v", prefixed, err)
	}

	second := testSnapshot(t, repo, testOID(t, 2), &root.OID, created.Add(2*time.Second), "second")
	second.Files = second.Files[:2]
	if err := store.PublishSnapshot(ctx, second, catalog.ExpectRef("main", &root.OID)); err != nil {
		t.Fatal(err)
	}
	if err := store.PublishSnapshot(ctx, second, catalog.ExpectRef("main", &root.OID)); err != nil {
		t.Fatalf("target-state replay = %v", err)
	}
	if _, err := store.ListFiles(ctx, repo, mainRevision, catalog.FileQuery{Limit: 1, Cursor: firstFiles.NextCursor}); !errors.Is(err, catalog.ErrConflict) {
		t.Fatalf("mutable revision cursor = %v", err)
	}
	old, err := store.GetSnapshot(ctx, repo, root.OID)
	if err != nil || len(old.Files) != 3 {
		t.Fatalf("old immutable snapshot = %#v, %v", old, err)
	}
	snapshots, err := store.ListSnapshots(ctx, repo, catalog.SnapshotQuery{Limit: 1})
	if err != nil || len(snapshots.Items) != 1 || snapshots.Items[0].OID != second.OID || snapshots.NextCursor == "" {
		t.Fatalf("snapshot page = %#v, %v", snapshots, err)
	}
	snapshots, err = store.ListSnapshots(ctx, repo, catalog.SnapshotQuery{Limit: 1, Cursor: snapshots.NextCursor})
	if err != nil || len(snapshots.Items) != 1 || snapshots.Items[0].OID != root.OID || snapshots.NextCursor != "" {
		t.Fatalf("snapshot continuation = %#v, %v", snapshots, err)
	}
	if err := store.CompareAndSwapRef(ctx, repo, "release", nil, root.OID); err != nil {
		t.Fatal(err)
	}
	if err := store.CompareAndSwapRef(ctx, repo, "release", nil, root.OID); err != nil {
		t.Fatalf("idempotent ref replay = %v", err)
	}
	wrong := testOID(t, 9)
	if err := store.CompareAndSwapRef(ctx, repo, "release", &wrong, second.OID); !errors.Is(err, catalog.ErrConflict) {
		t.Fatalf("stale ref update = %v", err)
	}
	if err := store.CompareAndSwapRef(ctx, repo, "release", &root.OID, second.OID); err != nil {
		t.Fatal(err)
	}

	secondPool, err := pgxpool.New(ctx, postgresDSN(t))
	if err != nil {
		t.Fatal("configure second pool")
	}
	defer secondPool.Close()
	reopened, err := New(ctx, secondPool, Options{Schema: schema})
	if err != nil {
		t.Fatal(err)
	}
	main, err := reopened.ResolveRevision(ctx, repo, mainRevision)
	if err != nil || main.OID != second.OID || main.CreatedAt.UnixNano() != second.CreatedAt.UnixNano() {
		t.Fatalf("main after restart = %#v, %v", main, err)
	}
	if err := reopened.Close(); err != nil {
		t.Fatal(err)
	}
	if err := secondPool.Ping(ctx); err != nil {
		t.Fatal("closing a caller-owned store closed its pool")
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	if err := pool.Ping(ctx); err != nil {
		t.Fatal("closing a caller-owned store closed its pool")
	}
}

func testInitializationAndOwnership(t *testing.T) {
	ctx := context.Background()
	pool, schema, _ := integrationStore(t)
	concurrentSchema := schema + "_concurrent"
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), `DROP SCHEMA `+concurrentSchema+` CASCADE`) })
	start := make(chan struct{})
	errs := make(chan error, 8)
	for range 8 {
		go func() {
			<-start
			store, err := New(ctx, pool, Options{Schema: concurrentSchema})
			if err == nil {
				err = store.Close()
			}
			errs <- err
		}()
	}
	close(start)
	for range 8 {
		if err := <-errs; err != nil {
			t.Fatal(err)
		}
	}
	if _, err := pool.Exec(ctx, `UPDATE `+schema+`.schema_version SET version=$1`, schemaVersion+1); err != nil {
		t.Fatal(err)
	}
	if _, err := New(ctx, pool, Options{Schema: schema}); !errors.Is(err, catalog.ErrUnavailable) {
		t.Fatalf("future schema = %v", err)
	}
	if _, err := pool.Exec(ctx, `UPDATE `+schema+`.schema_version SET version=$1`, schemaVersion); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `DROP INDEX `+schema+`.snapshots_order`); err != nil {
		t.Fatal(err)
	}
	if _, err := New(ctx, pool, Options{Schema: schema}); !errors.Is(err, catalog.ErrCorrupt) {
		t.Fatalf("missing schema index = %v", err)
	}
	if _, err := pool.Exec(ctx, `CREATE INDEX snapshots_order ON `+schema+`.snapshots(repo_type,namespace,name,created_at DESC,oid DESC)`); err != nil {
		t.Fatal(err)
	}

	ownedSchema := schema + "_owned"
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), `DROP SCHEMA `+ownedSchema+` CASCADE`) })
	owned, err := Open(ctx, postgresDSN(t), Options{Schema: ownedSchema})
	if err != nil {
		t.Fatal(err)
	}
	if err := owned.Close(); err != nil {
		t.Fatal(err)
	}
	if err := owned.Close(); err != nil {
		t.Fatal("second owned close failed")
	}
	if err := owned.pool.Ping(ctx); err == nil {
		t.Fatal("owned pool remained open")
	}
	if _, err := owned.ListRepositories(ctx, catalog.RepositoryQuery{}); !errors.Is(err, catalog.ErrUnavailable) {
		t.Fatalf("closed owned store = %v", err)
	}

	if _, err := Open(ctx, postgresDSN(t), Options{Schema: "Invalid"}); !errors.Is(err, catalog.ErrInvalid) {
		t.Fatalf("invalid Open options = %v", err)
	}
	if _, err := New(ctx, pool, Options{Schema: "Invalid"}); !errors.Is(err, catalog.ErrInvalid) {
		t.Fatalf("invalid New options = %v", err)
	}
	unavailableContext, unavailableCancel := context.WithTimeout(ctx, time.Second)
	defer unavailableCancel()
	if _, err := Open(unavailableContext, "postgres://xet@127.0.0.1:1/postgres?sslmode=disable", Options{}); !errors.Is(err, catalog.ErrUnavailable) {
		t.Fatalf("unavailable Open = %v", err)
	}

	malformedSchema := schema + "_malformed"
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), `DROP SCHEMA `+malformedSchema+` CASCADE`) })
	if _, err := pool.Exec(ctx, `CREATE SCHEMA `+malformedSchema+`; CREATE TABLE `+malformedSchema+`.schema_version(singleton boolean PRIMARY KEY,version integer NOT NULL); INSERT INTO `+malformedSchema+`.schema_version VALUES(true,1)`); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(ctx, postgresDSN(t), Options{Schema: malformedSchema}); !errors.Is(err, catalog.ErrCorrupt) {
		t.Fatalf("corrupt Open schema = %v", err)
	}

	negativeSchema := schema + "_negative"
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), `DROP SCHEMA `+negativeSchema+` CASCADE`) })
	negativeStore, err := New(ctx, pool, Options{Schema: negativeSchema})
	if err != nil {
		t.Fatal(err)
	}
	_ = negativeStore.Close()
	if _, err := pool.Exec(ctx, `ALTER TABLE `+negativeSchema+`.schema_version DROP CONSTRAINT schema_version_nonnegative; UPDATE `+negativeSchema+`.schema_version SET version=-1`); err != nil {
		t.Fatal(err)
	}
	if _, err := New(ctx, pool, Options{Schema: negativeSchema}); !errors.Is(err, catalog.ErrCorrupt) {
		t.Fatalf("negative schema version = %v", err)
	}

	missingTableSchema := schema + "_missing"
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), `DROP SCHEMA `+missingTableSchema+` CASCADE`) })
	missingTableStore, err := New(ctx, pool, Options{Schema: missingTableSchema})
	if err != nil {
		t.Fatal(err)
	}
	_ = missingTableStore.Close()
	if _, err := pool.Exec(ctx, `DROP TABLE `+missingTableSchema+`.files`); err != nil {
		t.Fatal(err)
	}
	if _, err := New(ctx, pool, Options{Schema: missingTableSchema}); !errors.Is(err, catalog.ErrCorrupt) {
		t.Fatalf("missing schema table = %v", err)
	}

	partialSchema := schema + "_partial"
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), `DROP SCHEMA `+partialSchema+` CASCADE`) })
	partialStore := &Store{schema: partialSchema}
	if _, err := pool.Exec(ctx, `CREATE SCHEMA `+partialSchema+`;
CREATE TABLE `+partialStore.q("schema_version")+`(singleton boolean NOT NULL DEFAULT true CONSTRAINT schema_version_singleton CHECK(singleton),version integer NOT NULL CONSTRAINT schema_version_nonnegative CHECK(version>=0),CONSTRAINT schema_version_pkey PRIMARY KEY(singleton));
INSERT INTO `+partialStore.q("schema_version")+` VALUES(true,0);
`+partialStore.schemaV1()[0]); err != nil {
		t.Fatal(err)
	}
	resumed, err := New(ctx, pool, Options{Schema: partialSchema})
	if err != nil {
		t.Fatalf("resume exact partial migration: %v", err)
	}
	_ = resumed.Close()
	var resumedVersion int
	if err := pool.QueryRow(ctx, `SELECT version FROM `+partialStore.q("schema_version")).Scan(&resumedVersion); err != nil || resumedVersion != schemaVersion {
		t.Fatalf("resumed schema version = %d, %v", resumedVersion, err)
	}

	malformedPartialSchema := schema + "_partial_bad"
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), `DROP SCHEMA `+malformedPartialSchema+` CASCADE`) })
	malformedPartial := &Store{schema: malformedPartialSchema}
	if _, err := pool.Exec(ctx, `CREATE SCHEMA `+malformedPartialSchema+`;
CREATE TABLE `+malformedPartial.q("schema_version")+`(singleton boolean NOT NULL DEFAULT true CONSTRAINT schema_version_singleton CHECK(singleton),version integer NOT NULL CONSTRAINT schema_version_nonnegative CHECK(version>=0),CONSTRAINT schema_version_pkey PRIMARY KEY(singleton));
INSERT INTO `+malformedPartial.q("schema_version")+` VALUES(true,0);
CREATE TABLE `+malformedPartial.q("repositories")+`(repo_type text NOT NULL)`); err != nil {
		t.Fatal(err)
	}
	if _, err := New(ctx, pool, Options{Schema: malformedPartialSchema}); !errors.Is(err, catalog.ErrCorrupt) {
		t.Fatalf("malformed partial migration = %v", err)
	}
	var retainedVersion int
	if err := pool.QueryRow(ctx, `SELECT version FROM `+malformedPartial.q("schema_version")).Scan(&retainedVersion); err != nil || retainedVersion != 0 {
		t.Fatalf("malformed partial version = %d, %v", retainedVersion, err)
	}

	for _, mutation := range []struct {
		name, sql string
	}{
		{name: "unlogged table", sql: `ALTER TABLE %s.schema_version SET UNLOGGED`},
		{name: "custom same-named type", sql: `CREATE DOMAIN %[1]s.text AS pg_catalog.text; ALTER TABLE %[1]s.snapshots ALTER COLUMN author_name TYPE %[1]s.text`},
		{name: "missing primary key", sql: `ALTER TABLE %s.refs DROP CONSTRAINT refs_pkey`},
		{name: "wrong column type", sql: `ALTER TABLE %s.snapshots ALTER COLUMN author_name TYPE varchar(255)`},
		{name: "wrong key collation", sql: `ALTER TABLE %s.files ALTER COLUMN path TYPE text COLLATE pg_catalog."default"`},
		{name: "missing foreign key", sql: `ALTER TABLE %s.files DROP CONSTRAINT files_snapshot_fkey`},
		{name: "cross-schema foreign key", sql: `ALTER TABLE %[1]s.refs DROP CONSTRAINT refs_snapshot_fkey; CREATE SCHEMA %[1]s_other; CREATE TABLE %[1]s_other.snapshots(repo_type text,namespace text,name text,oid bytea,PRIMARY KEY(repo_type,namespace,name,oid)); ALTER TABLE %[1]s.refs ADD CONSTRAINT refs_snapshot_fkey FOREIGN KEY(repo_type,namespace,name,oid) REFERENCES %[1]s_other.snapshots(repo_type,namespace,name,oid)`},
		{name: "wrong foreign key action", sql: `ALTER TABLE %[1]s.refs DROP CONSTRAINT refs_snapshot_fkey; ALTER TABLE %[1]s.refs ADD CONSTRAINT refs_snapshot_fkey FOREIGN KEY(repo_type,namespace,name,oid) REFERENCES %[1]s.snapshots(repo_type,namespace,name,oid) MATCH FULL ON UPDATE CASCADE`},
		{name: "missing check", sql: `ALTER TABLE %s.files DROP CONSTRAINT files_size_nonnegative`},
		{name: "different check grouping", sql: `ALTER TABLE %[1]s.files DROP CONSTRAINT files_representation; ALTER TABLE %[1]s.files ADD CONSTRAINT files_representation CHECK(kind='blob' AND sha256 IS NOT NULL AND (xet_hash IS NULL OR kind='xet') AND xet_hash IS NOT NULL)`},
		{name: "wrong index keys", sql: `DROP INDEX %[1]s.snapshots_order; CREATE INDEX snapshots_order ON %[1]s.snapshots(oid)`},
		{name: "partial index", sql: `DROP INDEX %[1]s.snapshots_order; CREATE INDEX snapshots_order ON %[1]s.snapshots(repo_type,namespace,name,created_at DESC,oid DESC) WHERE created_at>=0`},
		{name: "wrong index collation", sql: `DROP INDEX %[1]s.snapshots_order; CREATE INDEX snapshots_order ON %[1]s.snapshots(repo_type COLLATE pg_catalog."default",namespace,name,created_at DESC,oid DESC)`},
		{name: "wrong index null order", sql: `DROP INDEX %[1]s.snapshots_order; CREATE INDEX snapshots_order ON %[1]s.snapshots(repo_type,namespace,name,created_at DESC NULLS LAST,oid DESC)`},
	} {
		t.Run(mutation.name, func(t *testing.T) {
			mutatedSchema := fmt.Sprintf("xet_catalog_shape_%d_%d", os.Getpid(), integrationSequence.Add(1))
			mutated, err := New(ctx, pool, Options{Schema: mutatedSchema})
			if err != nil {
				t.Fatal(err)
			}
			_ = mutated.Close()
			t.Cleanup(func() {
				_, _ = pool.Exec(context.Background(), `DROP SCHEMA `+mutatedSchema+` CASCADE`)
				_, _ = pool.Exec(context.Background(), `DROP SCHEMA IF EXISTS `+mutatedSchema+`_other CASCADE`)
			})
			statement := fmt.Sprintf(mutation.sql, mutatedSchema)
			if _, err := pool.Exec(ctx, statement); err != nil {
				t.Fatal(err)
			}
			if _, err := New(ctx, pool, Options{Schema: mutatedSchema}); !errors.Is(err, catalog.ErrCorrupt) {
				t.Fatalf("incompatible schema accepted: %v", err)
			}
		})
	}

	nonUTFConfig, err := pgxpool.ParseConfig(postgresDSN(t))
	if err != nil {
		t.Fatal(err)
	}
	nonUTFConfig.ConnConfig.RuntimeParams["client_encoding"] = "SQL_ASCII"
	nonUTFPool, err := pgxpool.NewWithConfig(ctx, nonUTFConfig)
	if err != nil {
		t.Fatal(err)
	}
	defer nonUTFPool.Close()
	if _, err := New(ctx, nonUTFPool, Options{Schema: schema + "_non_utf"}); !errors.Is(err, catalog.ErrUnavailable) {
		t.Fatalf("non-UTF8 caller pool = %v", err)
	}
}

func testIndependentWriterSerialization(t *testing.T) {
	ctx := context.Background()
	pool, schema, first := integrationStore(t)
	secondPool, err := pgxpool.New(ctx, postgresDSN(t))
	if err != nil {
		t.Fatal(err)
	}
	defer secondPool.Close()
	second, err := New(ctx, secondPool, Options{Schema: schema})
	if err != nil {
		t.Fatal(err)
	}
	repo := testRepoKey(t, "concurrent", "model")
	if err := first.CreateRepository(ctx, model.Repository{Key: repo, CreatedAt: time.Unix(0, 1)}); err != nil {
		t.Fatal(err)
	}
	root := testSnapshot(t, repo, testOID(t, 20), nil, time.Unix(0, 2), "root")
	if err := first.PublishSnapshot(ctx, root, catalog.ExpectRef("main", nil)); err != nil {
		t.Fatal(err)
	}
	candidates := []model.Snapshot{
		testSnapshot(t, repo, testOID(t, 21), &root.OID, time.Unix(0, 3), "left"),
		testSnapshot(t, repo, testOID(t, 22), &root.OID, time.Unix(0, 3), "right"),
	}
	stores := []*Store{first, second}
	results := make([]error, 2)
	start := make(chan struct{})
	var wait sync.WaitGroup
	for index := range stores {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			<-start
			results[index] = stores[index].PublishSnapshot(ctx, candidates[index], catalog.ExpectRef("main", &root.OID))
		}(index)
	}
	close(start)
	wait.Wait()
	successes, conflicts := 0, 0
	for _, result := range results {
		if result == nil {
			successes++
		} else if errors.Is(result, catalog.ErrConflict) {
			conflicts++
		} else {
			t.Fatalf("publication result = %v", result)
		}
	}
	if successes != 1 || conflicts != 1 {
		t.Fatalf("publication results = %v", results)
	}

	lock, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer rollback(lock)
	if _, err := lock.Exec(ctx, `SELECT 1 FROM `+schema+`.repositories WHERE repo_type=$1 AND namespace=$2 AND name=$3 FOR UPDATE`, args(repo)...); err != nil {
		t.Fatal(err)
	}
	main, err := first.GetRef(ctx, repo, "main")
	if err != nil {
		t.Fatal(err)
	}
	blocked := testSnapshot(t, repo, testOID(t, 23), &main.OID, time.Unix(0, 4), "blocked")
	deadline, cancel := context.WithTimeout(ctx, 75*time.Millisecond)
	defer cancel()
	if err := second.PublishSnapshot(deadline, blocked, catalog.ExpectRef("main", &main.OID)); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("blocked publication = %v", err)
	}
	if _, err := second.GetSnapshot(ctx, repo, blocked.OID); !errors.Is(err, catalog.ErrNotFound) {
		t.Fatalf("blocked snapshot visible = %v", err)
	}
}

func TestPostgreSQLProcessHelper(t *testing.T) {
	action := os.Getenv("XET_POSTGRES_PROCESS_ACTION")
	if action == "" {
		t.Skip("subprocess helper")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	pool, err := pgxpool.New(ctx, os.Getenv("XET_POSTGRES_DSN"))
	if err != nil {
		t.Fatal("configure subprocess pool")
	}
	defer pool.Close()
	store, err := New(ctx, pool, Options{Schema: os.Getenv("XET_POSTGRES_PROCESS_SCHEMA")})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close() //nolint:errcheck // The pool remains caller-owned.
	repo := testRepoKey(t, "process", "model")
	root := testSnapshot(t, repo, testOID(t, 90), nil, time.Unix(0, 2), "root")
	switch action {
	case "seed":
		if err := store.CreateRepository(ctx, model.Repository{Key: repo, CreatedAt: time.Unix(0, 1)}); err != nil {
			t.Fatal(err)
		}
		if err := store.PublishSnapshot(ctx, root, catalog.ExpectRef("main", nil)); err != nil {
			t.Fatal(err)
		}
	case "read":
		snapshot, err := store.ResolveRevision(ctx, repo, testRevisionRef(t, "main"))
		if err != nil || snapshot.OID != root.OID {
			t.Fatalf("subprocess read = %#v, %v", snapshot, err)
		}
	case "publish-left", "publish-right":
		ready, start := os.Getenv("XET_POSTGRES_PROCESS_READY"), os.Getenv("XET_POSTGRES_PROCESS_START")
		if err := os.WriteFile(ready, []byte("ready"), 0600); err != nil {
			t.Fatal(err)
		}
		for {
			if _, err := os.Stat(start); err == nil {
				break
			} else if !errors.Is(err, os.ErrNotExist) {
				t.Fatal(err)
			}
			select {
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			case <-time.After(5 * time.Millisecond):
			}
		}
		value := byte(91)
		if action == "publish-right" {
			value = 92
		}
		candidate := testSnapshot(t, repo, testOID(t, value), &root.OID, time.Unix(0, 3), action)
		err := store.PublishSnapshot(ctx, candidate, catalog.ExpectRef("main", &root.OID))
		if err == nil {
			fmt.Println("XET_PROCESS_RESULT=success")
		} else if errors.Is(err, catalog.ErrConflict) {
			fmt.Println("XET_PROCESS_RESULT=conflict")
		} else {
			t.Fatal(err)
		}
	default:
		t.Fatalf("unknown subprocess action %q", action)
	}
}

func testIndependentProcessDurability(t *testing.T) {
	_, schema, store := integrationStore(t)
	run := func(action, ready, start string) *exec.Cmd {
		command := exec.Command(os.Args[0], "-test.run=^TestPostgreSQLProcessHelper$")
		command.Env = append(os.Environ(),
			"XET_POSTGRES_PROCESS_ACTION="+action,
			"XET_POSTGRES_PROCESS_SCHEMA="+schema,
			"XET_POSTGRES_PROCESS_READY="+ready,
			"XET_POSTGRES_PROCESS_START="+start,
		)
		return command
	}
	for _, action := range []string{"seed", "read"} {
		if output, err := run(action, "", "").CombinedOutput(); err != nil {
			t.Fatalf("%s subprocess: %v\n%s", action, err, output)
		}
	}
	directory := t.TempDir()
	start := filepath.Join(directory, "start")
	commands := []*exec.Cmd{
		run("publish-left", filepath.Join(directory, "left-ready"), start),
		run("publish-right", filepath.Join(directory, "right-ready"), start),
	}
	outputs := make([]strings.Builder, len(commands))
	for index, command := range commands {
		command.Stdout = &outputs[index]
		command.Stderr = &outputs[index]
		if err := command.Start(); err != nil {
			t.Fatal(err)
		}
	}
	deadline := time.Now().Add(10 * time.Second)
	for _, ready := range []string{filepath.Join(directory, "left-ready"), filepath.Join(directory, "right-ready")} {
		for {
			if _, err := os.Stat(ready); err == nil {
				break
			} else if !errors.Is(err, os.ErrNotExist) {
				t.Fatal(err)
			}
			if time.Now().After(deadline) {
				t.Fatal("timed out waiting for subprocess readiness")
			}
			time.Sleep(5 * time.Millisecond)
		}
	}
	if err := os.WriteFile(start, []byte("start"), 0600); err != nil {
		t.Fatal(err)
	}
	for index, command := range commands {
		if err := command.Wait(); err != nil {
			t.Fatalf("publication subprocess %d: %v\n%s", index, err, outputs[index].String())
		}
	}
	successes, conflicts := 0, 0
	for _, output := range outputs {
		if strings.Contains(output.String(), "XET_PROCESS_RESULT=success") {
			successes++
		}
		if strings.Contains(output.String(), "XET_PROCESS_RESULT=conflict") {
			conflicts++
		}
	}
	if successes != 1 || conflicts != 1 {
		t.Fatalf("subprocess outcomes = %q, %q", outputs[0].String(), outputs[1].String())
	}
	repo := testRepoKey(t, "process", "model")
	main, err := store.ResolveRevision(context.Background(), repo, testRevisionRef(t, "main"))
	if err != nil || main.OID != testOID(t, 91) && main.OID != testOID(t, 92) {
		t.Fatalf("main after subprocess race = %#v, %v", main, err)
	}
}

type faultTx struct {
	pgx.Tx
	execs, queries, queryRows               int
	failExecAt, failQueryAt, failQueryRowAt int
}

func (tx *faultTx) Exec(ctx context.Context, sql string, arguments ...any) (pgconn.CommandTag, error) {
	tx.execs++
	if tx.execs == tx.failExecAt {
		return pgconn.CommandTag{}, errors.New("injected transaction exec failure")
	}
	return tx.Tx.Exec(ctx, sql, arguments...)
}

func (tx *faultTx) Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error) {
	tx.queries++
	if tx.queries == tx.failQueryAt {
		return nil, errors.New("injected transaction query failure")
	}
	return tx.Tx.Query(ctx, sql, args...)
}

func (tx *faultTx) QueryRow(ctx context.Context, sql string, args ...any) pgx.Row {
	tx.queryRows++
	if tx.queryRows == tx.failQueryRowAt {
		return errorScanner{errors.New("injected transaction row failure")}
	}
	return tx.Tx.QueryRow(ctx, sql, args...)
}

func testProbeBackendFaults(t *testing.T) {
	pool, _, store := integrationStore(t)
	tests := []struct {
		name string
		faultTx
		operation func(context.Context, pgx.Tx) error
	}{
		{name: "column query", faultTx: faultTx{failQueryAt: 1}, operation: func(ctx context.Context, tx pgx.Tx) error {
			return store.probeColumns(ctx, tx)
		}},
		{name: "schema delegates column failure", faultTx: faultTx{failQueryAt: 1}, operation: func(ctx context.Context, tx pgx.Tx) error {
			return store.probeSchema(ctx, tx)
		}},
		{name: "canonical check backend ID", faultTx: faultTx{failQueryRowAt: 1}, operation: func(ctx context.Context, tx pgx.Tx) error {
			_, err := canonicalCheckExpressions(ctx, tx)
			return err
		}},
		{name: "canonical check table", faultTx: faultTx{failExecAt: 1}, operation: func(ctx context.Context, tx pgx.Tx) error {
			_, err := canonicalCheckExpressions(ctx, tx)
			return err
		}},
		{name: "canonical check query", faultTx: faultTx{failQueryAt: 1}, operation: func(ctx context.Context, tx pgx.Tx) error {
			_, err := canonicalCheckExpressions(ctx, tx)
			return err
		}},
		{name: "constraint canonical checks", faultTx: faultTx{failQueryRowAt: 1}, operation: store.probeConstraints},
		{name: "constraint capability query", faultTx: faultTx{failQueryRowAt: 2}, operation: store.probeConstraints},
		{name: "constraint manifest query", faultTx: faultTx{failQueryAt: 2}, operation: store.probeConstraints},
		{name: "index query", faultTx: faultTx{failQueryRowAt: 1}, operation: store.probeSnapshotIndex},
		{name: "schema singleton query", faultTx: faultTx{failQueryRowAt: 4}, operation: store.probeSchema},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			transaction, err := pool.Begin(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			defer rollback(transaction)
			tx := test.faultTx
			tx.Tx = transaction
			if err := test.operation(context.Background(), &tx); !errors.Is(err, catalog.ErrUnavailable) {
				t.Fatalf("probe fault = %v", err)
			}
		})
	}
}

func testPublicationFaults(t *testing.T) {
	ctx := context.Background()
	pool, schema, store := integrationStore(t)
	if _, err := pool.Exec(ctx, `CREATE FUNCTION `+schema+`.reject_write() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'injected write failure'; END $$`); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `CREATE FUNCTION `+schema+`.skip_write() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RETURN NULL; END $$`); err != nil {
		t.Fatal(err)
	}
	index := byte(30)
	for _, function := range []string{"reject_write", "skip_write"} {
		for _, test := range []struct {
			name, table, condition string
		}{
			{name: "snapshot", table: "snapshots"},
			{name: "file", table: "files"},
			{name: "target-ref", table: "refs", condition: ` WHEN (NEW.ref_name='release')`},
			{name: "main-ref", table: "refs", condition: ` WHEN (NEW.ref_name='main')`},
		} {
			t.Run(function+"/"+test.name, func(t *testing.T) {
				index++
				repo := testRepoKey(t, "fault", fmt.Sprintf("repo-%d", index))
				if err := store.CreateRepository(ctx, model.Repository{Key: repo, CreatedAt: time.Unix(0, 1)}); err != nil {
					t.Fatal(err)
				}
				trigger := "fault_" + function + "_" + strings.ReplaceAll(test.name, "-", "_")
				if _, err := pool.Exec(ctx, `CREATE TRIGGER `+trigger+` BEFORE INSERT ON `+schema+`.`+test.table+
					` FOR EACH ROW`+test.condition+` EXECUTE FUNCTION `+schema+`.`+function+`() `); err != nil {
					t.Fatal(err)
				}
				root := testSnapshot(t, repo, testOID(t, index), nil, time.Unix(0, 2), "root")
				if err := store.PublishSnapshot(ctx, root, catalog.ExpectRef("release", nil)); !errors.Is(err, catalog.ErrUnavailable) {
					t.Fatalf("faulted publication = %v", err)
				}
				if _, err := pool.Exec(ctx, `DROP TRIGGER `+trigger+` ON `+schema+`.`+test.table); err != nil {
					t.Fatal(err)
				}
				if _, err := store.GetSnapshot(ctx, repo, root.OID); !errors.Is(err, catalog.ErrNotFound) {
					t.Fatalf("faulted snapshot visible = %v", err)
				}
				for _, ref := range []model.RefName{"release", "main"} {
					if _, err := store.GetRef(ctx, repo, ref); !errors.Is(err, catalog.ErrNotFound) {
						t.Fatalf("faulted ref %q visible = %v", ref, err)
					}
				}
			})
		}
	}

	if _, err := pool.Exec(ctx, `CREATE TRIGGER suppress_repository BEFORE INSERT ON `+schema+`.repositories FOR EACH ROW EXECUTE FUNCTION `+schema+`.skip_write()`); err != nil {
		t.Fatal(err)
	}
	suppressed := testRepoKey(t, "fault", "suppressed-repository")
	if err := store.CreateRepository(ctx, model.Repository{Key: suppressed, CreatedAt: time.Unix(0, 1)}); !errors.Is(err, catalog.ErrUnavailable) {
		t.Fatalf("suppressed repository insert = %v", err)
	}
	if _, err := store.GetRepository(ctx, suppressed); !errors.Is(err, catalog.ErrNotFound) {
		t.Fatalf("suppressed repository visible = %v", err)
	}
	if _, err := pool.Exec(ctx, `DROP TRIGGER suppress_repository ON `+schema+`.repositories`); err != nil {
		t.Fatal(err)
	}

	casRepo, casRoot := createRoot(t, store, "fault", "cas-update", 59)
	casSecond := testSnapshot(t, casRepo, testOID(t, 58), &casRoot.OID, time.Unix(0, 3), "second")
	if err := store.PublishSnapshot(ctx, casSecond, catalog.ExpectRef("staging", nil)); err != nil {
		t.Fatal(err)
	}
	if err := store.CompareAndSwapRef(ctx, casRepo, "release", nil, casRoot.OID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `CREATE TRIGGER suppress_cas BEFORE UPDATE ON `+schema+`.refs FOR EACH ROW WHEN (OLD.ref_name='release') EXECUTE FUNCTION `+schema+`.skip_write()`); err != nil {
		t.Fatal(err)
	}
	if err := store.CompareAndSwapRef(ctx, casRepo, "release", &casRoot.OID, casSecond.OID); !errors.Is(err, catalog.ErrUnavailable) {
		t.Fatalf("suppressed CAS update = %v", err)
	}
}

func testRetainedCorruption(t *testing.T) {
	ctx := context.Background()
	t.Run("repository row", func(t *testing.T) {
		pool, schema, store := integrationStore(t)
		repo := testRepoKey(t, "corrupt", "repository")
		if err := store.CreateRepository(ctx, model.Repository{Key: repo, CreatedAt: time.Unix(0, 1)}); err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Exec(ctx, `UPDATE `+schema+`.repositories SET name='../bad' WHERE repo_type=$1 AND namespace=$2 AND name=$3`, args(repo)...); err != nil {
			t.Fatal(err)
		}
		if _, err := store.ListRepositories(ctx, catalog.RepositoryQuery{Namespace: repo.Namespace}); !errors.Is(err, catalog.ErrCorrupt) {
			t.Fatalf("malformed repository list row = %v", err)
		}
	})
	t.Run("snapshot body on replay", func(t *testing.T) {
		pool, schema, store := integrationStore(t)
		repo, root := createRoot(t, store, "corrupt", "body", 60)
		if _, err := pool.Exec(ctx, `UPDATE `+schema+`.files SET path='../bad' WHERE repo_type=$1 AND namespace=$2 AND name=$3 AND oid=$4 AND path='config.json'`, repo.Type, repo.Namespace, repo.Name, root.OID[:]); err != nil {
			t.Fatal(err)
		}
		if err := store.PublishSnapshot(ctx, root, catalog.ExpectRef("main", nil)); !errors.Is(err, catalog.ErrCorrupt) {
			t.Fatalf("replay over malformed body = %v", err)
		}
	})
	t.Run("fingerprint and file count", func(t *testing.T) {
		pool, schema, store := integrationStore(t)
		repo, root := createRoot(t, store, "corrupt", "fingerprint", 61)
		if _, err := pool.Exec(ctx, `UPDATE `+schema+`.snapshots SET fingerprint=$1,file_count=file_count+1 WHERE repo_type=$2 AND namespace=$3 AND name=$4 AND oid=$5`, make([]byte, 32), repo.Type, repo.Namespace, repo.Name, root.OID[:]); err != nil {
			t.Fatal(err)
		}
		if _, err := store.GetSnapshot(ctx, repo, root.OID); !errors.Is(err, catalog.ErrCorrupt) {
			t.Fatalf("malformed retained snapshot = %v", err)
		}
	})
	t.Run("fingerprint mismatch", func(t *testing.T) {
		pool, schema, store := integrationStore(t)
		repo, root := createRoot(t, store, "corrupt", "fingerprint-mismatch", 64)
		if _, err := pool.Exec(ctx, `UPDATE `+schema+`.snapshots SET fingerprint=$1 WHERE repo_type=$2 AND namespace=$3 AND name=$4 AND oid=$5`, make([]byte, 32), repo.Type, repo.Namespace, repo.Name, root.OID[:]); err != nil {
			t.Fatal(err)
		}
		if _, err := store.GetSnapshot(ctx, repo, root.OID); !errors.Is(err, catalog.ErrCorrupt) {
			t.Fatalf("fingerprint mismatch = %v", err)
		}
	})
	t.Run("fingerprint version on replay", func(t *testing.T) {
		pool, schema, store := integrationStore(t)
		repo, root := createRoot(t, store, "corrupt", "fingerprint-version", 65)
		if _, err := pool.Exec(ctx, `ALTER TABLE `+schema+`.snapshots DROP CONSTRAINT snapshots_fingerprint_version`); err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Exec(ctx, `UPDATE `+schema+`.snapshots SET fingerprint_version=2 WHERE repo_type=$1 AND namespace=$2 AND name=$3 AND oid=$4`, repo.Type, repo.Namespace, repo.Name, root.OID[:]); err != nil {
			t.Fatal(err)
		}
		if err := store.PublishSnapshot(ctx, root, catalog.ExpectRef("main", nil)); !errors.Is(err, catalog.ErrCorrupt) {
			t.Fatalf("retained fingerprint version = %v", err)
		}
	})
	t.Run("dangling ref", func(t *testing.T) {
		pool, schema, store := integrationStore(t)
		repo, root := createRoot(t, store, "corrupt", "ref", 62)
		var constraint string
		if err := pool.QueryRow(ctx, `SELECT c.conname FROM pg_constraint c JOIN pg_class t ON t.oid=c.conrelid JOIN pg_namespace n ON n.oid=t.relnamespace WHERE n.nspname=$1 AND t.relname='refs' AND c.contype='f'`, schema).Scan(&constraint); err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Exec(ctx, `ALTER TABLE `+schema+`.refs DROP CONSTRAINT `+pgx.Identifier{constraint}.Sanitize()); err != nil {
			t.Fatal(err)
		}
		missing := testOID(t, 99)
		if _, err := pool.Exec(ctx, `UPDATE `+schema+`.refs SET oid=$1 WHERE repo_type=$2 AND namespace=$3 AND name=$4 AND ref_name='main'`, missing[:], repo.Type, repo.Namespace, repo.Name); err != nil {
			t.Fatal(err)
		}
		if _, err := store.GetRef(ctx, repo, "main"); !errors.Is(err, catalog.ErrCorrupt) {
			t.Fatalf("dangling ref = %v", err)
		}
		candidate := testSnapshot(t, repo, testOID(t, 69), nil, time.Unix(0, 3), "candidate")
		if err := store.PublishSnapshot(ctx, candidate, catalog.ExpectRef("main", nil)); !errors.Is(err, catalog.ErrCorrupt) {
			t.Fatalf("publication through dangling ref = %v", err)
		}
		if err := store.CompareAndSwapRef(ctx, repo, "main", nil, root.OID); !errors.Is(err, catalog.ErrCorrupt) {
			t.Fatalf("CAS through dangling ref = %v", err)
		}
	})
	t.Run("zero ref encoding", func(t *testing.T) {
		pool, schema, store := integrationStore(t)
		repo, _ := createRoot(t, store, "corrupt", "zero-ref", 66)
		if _, err := pool.Exec(ctx, `ALTER TABLE `+schema+`.refs DROP CONSTRAINT refs_snapshot_fkey`); err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Exec(ctx, `UPDATE `+schema+`.refs SET oid=$1 WHERE repo_type=$2 AND namespace=$3 AND name=$4 AND ref_name='main'`, make([]byte, 20), repo.Type, repo.Namespace, repo.Name); err != nil {
			t.Fatal(err)
		}
		if _, err := store.GetRef(ctx, repo, "main"); !errors.Is(err, catalog.ErrCorrupt) {
			t.Fatalf("zero ref encoding = %v", err)
		}
	})
	t.Run("snapshot list metadata", func(t *testing.T) {
		pool, schema, store := integrationStore(t)
		repo, root := createRoot(t, store, "corrupt", "list", 63)
		if _, err := pool.Exec(ctx, `UPDATE `+schema+`.snapshots SET author_name=chr(1) WHERE repo_type=$1 AND namespace=$2 AND name=$3 AND oid=$4`, repo.Type, repo.Namespace, repo.Name, root.OID[:]); err != nil {
			t.Fatal(err)
		}
		if _, err := store.ListSnapshots(ctx, repo, catalog.SnapshotQuery{}); !errors.Is(err, catalog.ErrCorrupt) {
			t.Fatalf("malformed snapshot list row = %v", err)
		}
	})
	t.Run("snapshot list OID and count", func(t *testing.T) {
		pool, schema, store := integrationStore(t)
		repo, root := createRoot(t, store, "corrupt", "list-values", 67)
		if _, err := pool.Exec(ctx, `INSERT INTO `+schema+`.snapshots(repo_type,namespace,name,oid,parent,created_at,author_name,author_email,message,file_count,fingerprint,fingerprint_version) VALUES($1,$2,$3,$4,$5,$6,'author','author@example.com','zero',0,$7,1)`, repo.Type, repo.Namespace, repo.Name, make([]byte, 20), root.OID[:], int64(100), make([]byte, 32)); err != nil {
			t.Fatal(err)
		}
		if _, err := store.ListSnapshots(ctx, repo, catalog.SnapshotQuery{}); !errors.Is(err, catalog.ErrCorrupt) {
			t.Fatalf("zero snapshot list OID = %v", err)
		}
		if _, err := pool.Exec(ctx, `DELETE FROM `+schema+`.snapshots WHERE oid=$1`, make([]byte, 20)); err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Exec(ctx, `ALTER TABLE `+schema+`.snapshots DROP CONSTRAINT snapshots_file_count_nonnegative`); err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Exec(ctx, `UPDATE `+schema+`.snapshots SET file_count=-1 WHERE oid=$1`, root.OID[:]); err != nil {
			t.Fatal(err)
		}
		if _, err := store.ListSnapshots(ctx, repo, catalog.SnapshotQuery{}); !errors.Is(err, catalog.ErrCorrupt) {
			t.Fatalf("negative snapshot file count = %v", err)
		}
	})
	t.Run("file list row", func(t *testing.T) {
		pool, schema, store := integrationStore(t)
		repo, root := createRoot(t, store, "corrupt", "file-list", 68)
		if _, err := pool.Exec(ctx, `UPDATE `+schema+`.files SET path='../bad' WHERE repo_type=$1 AND namespace=$2 AND name=$3 AND oid=$4 AND path='config.json'`, repo.Type, repo.Namespace, repo.Name, root.OID[:]); err != nil {
			t.Fatal(err)
		}
		if _, err := store.ListFiles(ctx, repo, testRevisionOID(t, root.OID), catalog.FileQuery{}); !errors.Is(err, catalog.ErrCorrupt) {
			t.Fatalf("malformed file list row = %v", err)
		}
	})
}

func testCursorBinding(t *testing.T) {
	ctx := context.Background()
	_, _, store := integrationStore(t)
	repo, root := createRoot(t, store, "cursor", "model", 70)
	secondRepo := testRepoKey(t, "cursor", "other")
	if err := store.CreateRepository(ctx, model.Repository{Key: secondRepo, CreatedAt: time.Unix(0, 1)}); err != nil {
		t.Fatal(err)
	}
	repositories, err := store.ListRepositories(ctx, catalog.RepositoryQuery{Namespace: "cursor", Limit: 1})
	if err != nil || repositories.NextCursor == "" {
		t.Fatalf("repository cursor = %#v, %v", repositories, err)
	}
	repositoryCursor, _ := dec(repositories.NextCursor)
	for _, mutate := range []func(*cursor){
		func(value *cursor) { value.Scope = scope(repo) },
		func(value *cursor) { value.Last = "bad" },
		func(value *cursor) { value.Filter = "other\x00model" },
		func(value *cursor) { value.Op = "files" },
	} {
		value := repositoryCursor
		mutate(&value)
		if _, err := store.ListRepositories(ctx, catalog.RepositoryQuery{Namespace: "cursor", Limit: 1, Cursor: enc(value)}); !errors.Is(err, catalog.ErrInvalid) {
			t.Fatalf("mutated repository cursor %#v = %v", value, err)
		}
	}
	second := testSnapshot(t, repo, testOID(t, 71), &root.OID, time.Unix(0, 3), "second")
	if err := store.PublishSnapshot(ctx, second, catalog.ExpectRef("main", &root.OID)); err != nil {
		t.Fatal(err)
	}
	snapshots, err := store.ListSnapshots(ctx, repo, catalog.SnapshotQuery{Limit: 1})
	if err != nil || snapshots.NextCursor == "" {
		t.Fatalf("snapshot cursor = %#v, %v", snapshots, err)
	}
	snapshotCursor, _ := dec(snapshots.NextCursor)
	snapshotCursor.Last = "unexpected"
	if _, err := store.ListSnapshots(ctx, repo, catalog.SnapshotQuery{Limit: 1, Cursor: enc(snapshotCursor)}); !errors.Is(err, catalog.ErrInvalid) {
		t.Fatalf("mutated snapshot cursor = %v", err)
	}
	snapshotCursor.Last = ""
	snapshotCursor.OID = "bad"
	if _, err := store.ListSnapshots(ctx, repo, catalog.SnapshotQuery{Limit: 1, Cursor: enc(snapshotCursor)}); !errors.Is(err, catalog.ErrInvalid) {
		t.Fatalf("malformed snapshot cursor OID = %v", err)
	}
	files, err := store.ListFiles(ctx, repo, testRevisionOID(t, root.OID), catalog.FileQuery{Limit: 1})
	if err != nil || files.NextCursor == "" {
		t.Fatalf("file cursor = %#v, %v", files, err)
	}
	fileCursor, _ := dec(files.NextCursor)
	for _, mutate := range []func(*cursor){
		func(value *cursor) { value.Last = "../bad" },
		func(value *cursor) { value.Op = "snapshots" },
		func(value *cursor) { n := int64(1); value.Time = &n },
		func(value *cursor) { value.Scope = scope(secondRepo) },
		func(value *cursor) { value.OID = "bad" },
	} {
		value := fileCursor
		mutate(&value)
		if _, err := store.ListFiles(ctx, repo, testRevisionOID(t, root.OID), catalog.FileQuery{Limit: 1, Cursor: enc(value)}); !errors.Is(err, catalog.ErrInvalid) {
			t.Fatalf("mutated file cursor %#v = %v", value, err)
		}
	}
}

func testInputAndStateErrors(t *testing.T) {
	ctx := context.Background()
	_, _, store := integrationStore(t)
	repo, root := createRoot(t, store, "errors", "model", 75)
	missingRepo := testRepoKey(t, "errors", "missing")
	mainRevision := testRevisionRef(t, "main")

	if err := store.CreateRepository(ctx, model.Repository{Key: repo}); !errors.Is(err, catalog.ErrInvalid) {
		t.Fatalf("invalid repository = %v", err)
	}
	if _, err := store.GetRepository(ctx, model.RepoKey{}); !errors.Is(err, catalog.ErrInvalid) {
		t.Fatalf("invalid repository key = %v", err)
	}
	for _, query := range []catalog.RepositoryQuery{
		{Namespace: "../bad"}, {Type: "dataset"}, {Limit: -1}, {Cursor: "bad"},
	} {
		if _, err := store.ListRepositories(ctx, query); !errors.Is(err, catalog.ErrInvalid) {
			t.Fatalf("invalid repository query %#v = %v", query, err)
		}
	}
	if _, err := store.GetSnapshot(ctx, repo, model.OID{}); !errors.Is(err, catalog.ErrInvalid) {
		t.Fatalf("zero snapshot OID = %v", err)
	}
	if _, err := store.ResolveRevision(ctx, repo, model.Revision{}); !errors.Is(err, catalog.ErrInvalid) {
		t.Fatalf("empty revision = %v", err)
	}
	if _, err := store.ResolveRevision(ctx, model.RepoKey{}, mainRevision); !errors.Is(err, catalog.ErrInvalid) {
		t.Fatalf("invalid revision repository = %v", err)
	}
	if _, err := store.ResolveRevision(ctx, missingRepo, mainRevision); !errors.Is(err, catalog.ErrNotFound) {
		t.Fatalf("missing revision = %v", err)
	}
	if _, err := store.ListSnapshots(ctx, missingRepo, catalog.SnapshotQuery{}); !errors.Is(err, catalog.ErrNotFound) {
		t.Fatalf("missing repository snapshots = %v", err)
	}
	if _, err := store.ListSnapshots(ctx, model.RepoKey{}, catalog.SnapshotQuery{}); !errors.Is(err, catalog.ErrInvalid) {
		t.Fatalf("invalid snapshot repository = %v", err)
	}
	for _, query := range []catalog.SnapshotQuery{{Limit: -1}, {Cursor: "bad"}} {
		if _, err := store.ListSnapshots(ctx, repo, query); !errors.Is(err, catalog.ErrInvalid) {
			t.Fatalf("invalid snapshot query %#v = %v", query, err)
		}
	}
	if _, err := store.GetRef(ctx, repo, "../bad"); !errors.Is(err, catalog.ErrInvalid) {
		t.Fatalf("invalid ref = %v", err)
	}
	if _, err := store.GetRef(ctx, repo, "missing"); !errors.Is(err, catalog.ErrNotFound) {
		t.Fatalf("missing ref = %v", err)
	}
	if err := store.CompareAndSwapRef(ctx, model.RepoKey{}, "main", nil, root.OID); !errors.Is(err, catalog.ErrInvalid) {
		t.Fatalf("invalid CAS repository = %v", err)
	}
	zero := model.OID{}
	if err := store.CompareAndSwapRef(ctx, repo, "release", &zero, root.OID); !errors.Is(err, catalog.ErrInvalid) {
		t.Fatalf("zero expected ref = %v", err)
	}
	if err := store.CompareAndSwapRef(ctx, missingRepo, "main", nil, root.OID); !errors.Is(err, catalog.ErrNotFound) {
		t.Fatalf("CAS missing repository = %v", err)
	}
	if err := store.CompareAndSwapRef(ctx, repo, "release", nil, testOID(t, 76)); !errors.Is(err, catalog.ErrNotFound) {
		t.Fatalf("CAS missing target = %v", err)
	}
	if err := store.CompareAndSwapRef(ctx, repo, "release", &root.OID, root.OID); !errors.Is(err, catalog.ErrConflict) {
		t.Fatalf("create ref with expected value = %v", err)
	}

	invalidSnapshot := root
	invalidSnapshot.OID = model.OID{}
	if err := store.PublishSnapshot(ctx, invalidSnapshot, catalog.ExpectRef("main", nil)); !errors.Is(err, catalog.ErrInvalid) {
		t.Fatalf("invalid snapshot = %v", err)
	}
	if err := store.PublishSnapshot(ctx, root, catalog.ExpectRef("../bad", nil)); !errors.Is(err, catalog.ErrInvalid) {
		t.Fatalf("invalid publication ref = %v", err)
	}
	if err := store.PublishSnapshot(ctx, root, catalog.ExpectRef("main", &zero)); !errors.Is(err, catalog.ErrInvalid) {
		t.Fatalf("zero publication expectation = %v", err)
	}
	wrongParent := testOID(t, 77)
	child := testSnapshot(t, repo, testOID(t, 78), &wrongParent, time.Unix(0, 3), "wrong parent")
	if err := store.PublishSnapshot(ctx, child, catalog.ExpectRef("main", &root.OID)); !errors.Is(err, catalog.ErrInvalid) {
		t.Fatalf("parent expectation mismatch = %v", err)
	}
	missingRepoRoot := testSnapshot(t, missingRepo, testOID(t, 79), nil, time.Unix(0, 2), "missing repo")
	if err := store.PublishSnapshot(ctx, missingRepoRoot, catalog.ExpectRef("main", nil)); !errors.Is(err, catalog.ErrNotFound) {
		t.Fatalf("publication to missing repository = %v", err)
	}
	secondRoot := testSnapshot(t, repo, testOID(t, 81), nil, time.Unix(0, 3), "second root")
	if err := store.PublishSnapshot(ctx, secondRoot, catalog.ExpectRef("other", nil)); !errors.Is(err, catalog.ErrInvalid) {
		t.Fatalf("second root = %v", err)
	}
	orphan := testSnapshot(t, repo, testOID(t, 82), &wrongParent, time.Unix(0, 3), "orphan")
	if err := store.PublishSnapshot(ctx, orphan, catalog.ExpectRef("other", nil)); !errors.Is(err, catalog.ErrNotFound) {
		t.Fatalf("missing parent = %v", err)
	}
	expectedWithoutRef := testSnapshot(t, repo, testOID(t, 85), &root.OID, time.Unix(0, 3), "missing expected ref")
	if err := store.PublishSnapshot(ctx, expectedWithoutRef, catalog.ExpectRef("absent", &root.OID)); !errors.Is(err, catalog.ErrConflict) {
		t.Fatalf("missing expected ref = %v", err)
	}
	conflicting := root
	conflicting.Message = "different immutable body"
	if err := store.PublishSnapshot(ctx, conflicting, catalog.ExpectRef("main", nil)); !errors.Is(err, catalog.ErrConflict) {
		t.Fatalf("immutable conflict = %v", err)
	}
	advanced := testSnapshot(t, repo, testOID(t, 83), &root.OID, time.Unix(0, 4), "advanced")
	if err := store.PublishSnapshot(ctx, advanced, catalog.ExpectRef("main", &root.OID)); err != nil {
		t.Fatal(err)
	}
	stale := testSnapshot(t, repo, testOID(t, 84), &root.OID, time.Unix(0, 5), "stale")
	if err := store.PublishSnapshot(ctx, stale, catalog.ExpectRef("main", &root.OID)); !errors.Is(err, catalog.ErrConflict) {
		t.Fatalf("stale publication = %v", err)
	}
	if _, err := store.GetSnapshot(ctx, repo, stale.OID); !errors.Is(err, catalog.ErrNotFound) {
		t.Fatalf("stale snapshot visible = %v", err)
	}

	if _, err := store.GetFile(ctx, repo, mainRevision, "../bad"); !errors.Is(err, catalog.ErrInvalid) {
		t.Fatalf("invalid file path = %v", err)
	}
	if _, err := store.GetFile(ctx, model.RepoKey{}, mainRevision, "config.json"); !errors.Is(err, catalog.ErrInvalid) {
		t.Fatalf("invalid file repository = %v", err)
	}
	if _, err := store.ListFiles(ctx, model.RepoKey{}, mainRevision, catalog.FileQuery{}); !errors.Is(err, catalog.ErrInvalid) {
		t.Fatalf("invalid file-list repository = %v", err)
	}
	if _, err := store.ListFiles(ctx, repo, testRevisionOID(t, testOID(t, 86)), catalog.FileQuery{}); !errors.Is(err, catalog.ErrNotFound) {
		t.Fatalf("missing file-list snapshot = %v", err)
	}
	for _, query := range []catalog.FileQuery{{Prefix: "../bad"}, {Limit: -1}, {Cursor: "bad"}} {
		if _, err := store.ListFiles(ctx, repo, mainRevision, query); !errors.Is(err, catalog.ErrInvalid) {
			t.Fatalf("invalid file query %#v = %v", query, err)
		}
	}

	rootOnlyRepo := testRepoKey(t, "errors", "refs-without-snapshots")
	if err := store.CreateRepository(ctx, model.Repository{Key: rootOnlyRepo, CreatedAt: time.Unix(0, 1)}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.pool.Exec(ctx, `ALTER TABLE `+store.schema+`.refs DROP CONSTRAINT refs_snapshot_fkey`); err != nil {
		t.Fatal(err)
	}
	danglingOID := testOID(t, 87)
	if _, err := store.pool.Exec(ctx, `INSERT INTO `+store.schema+`.refs VALUES($1,$2,$3,'dangling',$4)`, rootOnlyRepo.Type, rootOnlyRepo.Namespace, rootOnlyRepo.Name, danglingOID[:]); err != nil {
		t.Fatal(err)
	}
	rootOnly := testSnapshot(t, rootOnlyRepo, testOID(t, 88), nil, time.Unix(0, 2), "root")
	if err := store.PublishSnapshot(ctx, rootOnly, catalog.ExpectRef("main", nil)); !errors.Is(err, catalog.ErrCorrupt) {
		t.Fatalf("refs without snapshots = %v", err)
	}

	prefixRepo := testRepoKey(t, "errors", "prefix-boundary")
	if err := store.CreateRepository(ctx, model.Repository{Key: prefixRepo, CreatedAt: time.Unix(0, 1)}); err != nil {
		t.Fatal(err)
	}
	prefixRoot := testSnapshot(t, prefixRepo, testOID(t, 89), nil, time.Unix(0, 2), "root")
	boundaryRef, err := model.NewBlobFileRef(sha256.Sum256([]byte("boundary")), 8)
	if err != nil {
		t.Fatal(err)
	}
	prefixRoot.Files = append(prefixRoot.Files, model.FileEntry{Path: "weights0.bin", Ref: boundaryRef})
	if err := store.PublishSnapshot(ctx, prefixRoot, catalog.ExpectRef("main", nil)); err != nil {
		t.Fatal(err)
	}
	prefixFiles, err := store.ListFiles(ctx, prefixRepo, testRevisionRef(t, "main"), catalog.FileQuery{Prefix: "weights/"})
	if err != nil || len(prefixFiles.Items) != 2 {
		t.Fatalf("prefix boundary = %#v, %v", prefixFiles, err)
	}

	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if err := store.CreateRepository(canceled, model.Repository{Key: missingRepo, CreatedAt: time.Unix(0, 1)}); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled create = %v", err)
	}

	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	closedOperations := []func() error{
		func() error {
			return store.CreateRepository(ctx, model.Repository{Key: missingRepo, CreatedAt: time.Unix(0, 1)})
		},
		func() error { _, err := store.GetRepository(ctx, repo); return err },
		func() error { _, err := store.ListRepositories(ctx, catalog.RepositoryQuery{}); return err },
		func() error { _, err := store.ResolveRevision(ctx, repo, mainRevision); return err },
		func() error { _, err := store.GetSnapshot(ctx, repo, root.OID); return err },
		func() error { _, err := store.ListSnapshots(ctx, repo, catalog.SnapshotQuery{}); return err },
		func() error { _, err := store.GetRef(ctx, repo, "main"); return err },
		func() error { return store.CompareAndSwapRef(ctx, repo, "main", nil, root.OID) },
		func() error { return store.PublishSnapshot(ctx, root, catalog.ExpectRef("main", nil)) },
		func() error { _, err := store.GetFile(ctx, repo, mainRevision, "config.json"); return err },
		func() error { _, err := store.ListFiles(ctx, repo, mainRevision, catalog.FileQuery{}); return err },
	}
	for index, operation := range closedOperations {
		if err := operation(); !errors.Is(err, catalog.ErrUnavailable) {
			t.Errorf("closed store operation %d = %v", index, err)
		}
	}
}

func testClosedPool(t *testing.T) {
	ctx := context.Background()
	pool, schema, store := integrationStore(t)
	repo := testRepoKey(t, "closed", "model")
	root := testSnapshot(t, repo, testOID(t, 80), nil, time.Unix(0, 2), "root")
	revision := testRevisionRef(t, "main")
	pool.Close()
	operations := []func() error{
		func() error {
			return store.CreateRepository(ctx, model.Repository{Key: repo, CreatedAt: time.Unix(0, 1)})
		},
		func() error { _, err := store.GetRepository(ctx, repo); return err },
		func() error { _, err := store.ListRepositories(ctx, catalog.RepositoryQuery{}); return err },
		func() error { _, err := store.ResolveRevision(ctx, repo, revision); return err },
		func() error { _, err := store.GetSnapshot(ctx, repo, root.OID); return err },
		func() error { _, err := store.ListSnapshots(ctx, repo, catalog.SnapshotQuery{}); return err },
		func() error { _, err := store.GetRef(ctx, repo, "main"); return err },
		func() error { return store.CompareAndSwapRef(ctx, repo, "main", nil, root.OID) },
		func() error { return store.PublishSnapshot(ctx, root, catalog.ExpectRef("main", nil)) },
		func() error { _, err := store.GetFile(ctx, repo, revision, "config.json"); return err },
		func() error { _, err := store.ListFiles(ctx, repo, revision, catalog.FileQuery{}); return err },
	}
	for index, operation := range operations {
		if err := operation(); !errors.Is(err, catalog.ErrUnavailable) {
			t.Errorf("closed pool operation %d = %v", index, err)
		}
	}
	if _, err := New(ctx, pool, Options{Schema: schema}); !errors.Is(err, catalog.ErrUnavailable) {
		t.Fatalf("new with closed pool = %v", err)
	}
}

func integrationStore(t *testing.T) (*pgxpool.Pool, string, *Store) {
	t.Helper()
	ctx := context.Background()
	dsn := postgresDSN(t)
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal("configure PostgreSQL integration pool")
	}
	schema := fmt.Sprintf("xet_catalog_test_%d_%d", os.Getpid(), integrationSequence.Add(1))
	store, err := New(ctx, pool, Options{Schema: schema})
	if err != nil {
		pool.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = store.Close()
		pool.Close()
		cleanup, cleanupErr := pgxpool.New(context.Background(), dsn)
		if cleanupErr == nil {
			_, _ = cleanup.Exec(context.Background(), `DROP SCHEMA `+schema+` CASCADE`)
			cleanup.Close()
		}
	})
	return pool, schema, store
}

func postgresDSN(t *testing.T) string {
	t.Helper()
	dsn := os.Getenv("XET_POSTGRES_DSN")
	if dsn == "" {
		t.Fatal("XET_POSTGRES_DSN is required")
	}
	return dsn
}

func createRoot(t *testing.T, store *Store, namespace, name string, value byte) (model.RepoKey, model.Snapshot) {
	t.Helper()
	ctx := context.Background()
	repo := testRepoKey(t, namespace, name)
	if err := store.CreateRepository(ctx, model.Repository{Key: repo, CreatedAt: time.Unix(0, 1)}); err != nil {
		t.Fatal(err)
	}
	root := testSnapshot(t, repo, testOID(t, value), nil, time.Unix(0, 2), "root")
	if err := store.PublishSnapshot(ctx, root, catalog.ExpectRef("main", nil)); err != nil {
		t.Fatal(err)
	}
	return repo, root
}

func testRepoKey(t *testing.T, namespace, name string) model.RepoKey {
	t.Helper()
	key, err := model.NewRepoKey(namespace, name, model.RepoTypeModel)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func testOID(t *testing.T, value byte) model.OID {
	t.Helper()
	oid, err := model.ParseOID(strings.Repeat(fmt.Sprintf("%02x", value), 20))
	if err != nil {
		t.Fatal(err)
	}
	return oid
}

func testRevisionRef(t *testing.T, name model.RefName) model.Revision {
	t.Helper()
	revision, err := model.RevisionFromRef(name)
	if err != nil {
		t.Fatal(err)
	}
	return revision
}

func testRevisionOID(t *testing.T, oid model.OID) model.Revision {
	t.Helper()
	revision, err := model.RevisionFromOID(oid)
	if err != nil {
		t.Fatal(err)
	}
	return revision
}

func testSnapshot(t *testing.T, repo model.RepoKey, oid model.OID, parent *model.OID, created time.Time, message string) model.Snapshot {
	t.Helper()
	blobSum := sha256.Sum256([]byte("config"))
	blob, err := model.NewBlobFileRef(blobSum, 6)
	if err != nil {
		t.Fatal(err)
	}
	var xetID xethash.Hash
	xetID[0] = 1
	xet, err := model.NewXetFileRef(xetID, 17, nil)
	if err != nil {
		t.Fatal(err)
	}
	optionalSum := [32]byte{}
	xetWithSHA, err := model.NewXetFileRef(xetID, 17, &optionalSum)
	if err != nil {
		t.Fatal(err)
	}
	return model.Snapshot{
		Repo: repo, OID: oid, Parent: parent, CreatedAt: created,
		Author: model.Identity{Name: "author", Email: "author@example.com"}, Message: message,
		Files: []model.FileEntry{
			{Path: "weights/z.bin", Ref: xetWithSHA},
			{Path: "config.json", Ref: blob},
			{Path: "weights/a.bin", Ref: xet},
		},
	}
}
