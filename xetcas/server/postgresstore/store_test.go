package postgresstore

import (
	"context"
	"errors"
	"os"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jmwoliver/xet-go/shard"
	"github.com/jmwoliver/xet-go/xetcas/server"
	"github.com/jmwoliver/xet-go/xethash"
	"github.com/jmwoliver/xet-go/xorb"
)

func TestOptions(t *testing.T) {
	for _, good := range []string{"", "xet_cas", "a", "a1_b"} {
		if _, err := options(Options{Schema: good}); err != nil {
			t.Errorf("valid %q: %v", good, err)
		}
	}
	for _, bad := range []string{"Xet", "has-dash", "1schema", `x"y`, "a.b", "a" + string(make([]byte, 63))} {
		if _, err := options(Options{Schema: bad}); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}

func TestCursorBindingAndCanonicalForm(t *testing.T) {
	raw := curEncode(cursor{Op: "files", Mode: "scoped", Filter: "a", NS: "a", Key: make([]byte, 32)})
	if _, err := curDecode(raw, "files", "scoped", "a", 0); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct{ op, mode, scope string }{{"dedup", "scoped", "a"}, {"files", "all", "a"}, {"files", "scoped", "b"}} {
		if _, err := curDecode(raw, test.op, test.mode, test.scope, 0); !errors.Is(err, server.ErrInvalid) {
			t.Errorf("binding %+v: %v", test, err)
		}
	}
	if _, err := curDecode(raw+"=", "files", "scoped", "a", 0); !errors.Is(err, server.ErrInvalid) {
		t.Fatalf("noncanonical cursor: %v", err)
	}
}

func TestEncodingAndCursorHelpers(t *testing.T) {
	if _, err := enc(make(chan struct{})); err == nil {
		t.Fatal("unsupported JSON value encoded")
	}
	if _, err := hash([]byte{1}); !errors.Is(err, server.ErrCorrupt) {
		t.Fatalf("short hash = %v", err)
	}
	if got := bytesUint64([]byte{1}); got != ^uint64(0) {
		t.Fatalf("short uint64 = %d", got)
	}
	backendFailure := errors.New("scanner failure")
	if _, err := scanStage(scannerFunc(func(...any) error { return backendFailure })); !errors.Is(err, backendFailure) {
		t.Fatalf("stage scan error = %v", err)
	}
	if _, err := scanLease(scannerFunc(func(...any) error { return backendFailure })); !errors.Is(err, backendFailure) {
		t.Fatalf("lease scan error = %v", err)
	}
	shortIdentity := scannerFunc(func(values ...any) error {
		*values[0].(*string) = "scope"
		*values[1].(*[]byte) = []byte{1}
		if len(values) == 6 {
			*values[2].(*string) = string(server.BlobXorb)
			*values[3].(*[]byte) = make([]byte, 32)
			*values[4].(*int64), *values[5].(*int64) = 1, 2
		} else {
			*values[2].(*[]byte) = make([]byte, 32)
			*values[3].(*int64), *values[4].(*int64) = 1, 2
		}
		return nil
	})
	if _, err := scanStage(shortIdentity); !errors.Is(err, server.ErrCorrupt) {
		t.Fatalf("short stage identity = %v", err)
	}
	if _, err := scanLease(shortIdentity); !errors.Is(err, server.ErrCorrupt) {
		t.Fatalf("short lease identity = %v", err)
	}
	reversedLease := scannerFunc(func(values ...any) error {
		*values[0].(*string) = "scope"
		*values[1].(*[]byte) = make([]byte, 16)
		(*values[1].(*[]byte))[0] = 1
		*values[2].(*[]byte) = make([]byte, 32)
		*values[3].(*int64), *values[4].(*int64) = 2, 1
		return nil
	})
	if _, err := scanLease(reversedLease); !errors.Is(err, server.ErrCorrupt) {
		t.Fatalf("reversed lease scan = %v", err)
	}
}

type scannerFunc func(...any) error

func (f scannerFunc) Scan(values ...any) error { return f(values...) }

func TestConstructionErrorsDoNotExposeCredentials(t *testing.T) {
	if _, err := New(context.Background(), nil, Options{}); err == nil {
		t.Fatal("nil pool succeeded")
	}
	secret := "not-a-real-password"
	if _, err := Open(context.Background(), "postgres://user:"+secret+"@%", Options{}); err == nil || strings.Contains(err.Error(), secret) {
		t.Fatalf("invalid connection error = %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Open(ctx, "postgres://user:"+secret+"@127.0.0.1:1/database?sslmode=disable", Options{}); !errors.Is(err, context.Canceled) || strings.Contains(err.Error(), secret) {
		t.Fatalf("canceled connection error = %v", err)
	}
}

func TestPostgreSQLIntegration(t *testing.T) {
	if os.Getenv("XET_POSTGRES_INTEGRATION") != "1" {
		t.Skip("set XET_POSTGRES_INTEGRATION=1 with XET_POSTGRES_DSN to run")
	}
	dsn := os.Getenv("XET_POSTGRES_DSN")
	if dsn == "" {
		t.Fatal("XET_POSTGRES_DSN is required")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal("connect PostgreSQL")
	}
	defer pool.Close()
	schema := "xet_cas_test_" + randomIdentifier(t)
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), `DROP SCHEMA `+schema+` CASCADE`) })
	store, err := New(ctx, pool, Options{Schema: schema})
	if err != nil {
		t.Fatal(err)
	}
	// Compile-time and runtime construction coverage for all promised capabilities.
	var _ server.IndexStore = store
	var _ server.IndexLister = store
	var _ server.ProtectionStore = store
	var _ server.ProtectionExpiryStore = store

	t.Run("core index and atomic publication", func(t *testing.T) {
		testCoreIndex(t, ctx, store)
	})
	t.Run("bounded index iteration", func(t *testing.T) {
		testIndexIteration(t, ctx, store)
	})
	t.Run("protections and expiry races", func(t *testing.T) {
		testProtections(t, ctx, store)
	})
	t.Run("malformed retained records", func(t *testing.T) {
		testMalformedRecords(t, ctx, pool, schema, store)
	})
	t.Run("closed pool errors", func(t *testing.T) {
		testClosedPoolErrors(t, ctx, dsn)
	})
	t.Run("database fault injection", func(t *testing.T) {
		testDatabaseFaultInjection(t, ctx, pool)
	})

	persistent := indexFixture("independent pool persistence")
	if err := store.PublishShard(ctx, publication("persistence", persistent)); err != nil {
		t.Fatal(err)
	}
	secondPool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal("open second PostgreSQL pool")
	}
	defer secondPool.Close()
	second, err := New(ctx, secondPool, Options{Schema: schema})
	if err != nil {
		t.Fatal(err)
	}
	file := persistent.file
	if got, found, err := second.GetFile(ctx, "persistence", file.File.File.Hash); err != nil || !found ||
		!reflect.DeepEqual(got, file) {
		t.Fatalf("second-process file = %#v, %v, %v", got, found, err)
	}
	_ = second.Close()
	if err := secondPool.Ping(ctx); err != nil {
		t.Fatal("closing caller-owned store closed its pool")
	}

	t.Run("concurrent initialization", func(t *testing.T) {
		concurrentSchema := "xet_cas_init_" + randomIdentifier(t)
		t.Cleanup(func() { _, _ = pool.Exec(context.Background(), `DROP SCHEMA `+concurrentSchema+` CASCADE`) })
		start := make(chan struct{})
		errorsFound := make(chan error, 2)
		for range 2 {
			go func() {
				<-start
				value, openErr := New(ctx, secondPool, Options{Schema: concurrentSchema})
				if openErr == nil {
					openErr = value.Close()
				}
				errorsFound <- openErr
			}()
		}
		close(start)
		for range 2 {
			if err := <-errorsFound; err != nil {
				t.Fatal(err)
			}
		}
	})

	t.Run("owned pool and newer migration", func(t *testing.T) {
		ownedSchema := "xet_cas_owned_" + randomIdentifier(t)
		t.Cleanup(func() { _, _ = pool.Exec(context.Background(), `DROP SCHEMA `+ownedSchema+` CASCADE`) })
		owned, err := Open(ctx, dsn, Options{Schema: ownedSchema})
		if err != nil {
			t.Fatal(err)
		}
		if err := owned.Close(); err != nil {
			t.Fatal(err)
		}
		if err := owned.Close(); err != nil {
			t.Fatal("second owned close failed")
		}
		if _, err := Open(ctx, dsn, Options{Schema: "Invalid"}); err == nil || strings.Contains(err.Error(), dsn) {
			t.Fatalf("invalid owned schema error = %v", err)
		}
		if _, err := pool.Exec(ctx, `UPDATE `+schema+`.schema_version SET version=$1`, schemaVersion+1); err != nil {
			t.Fatal(err)
		}
		if _, err := New(ctx, pool, Options{Schema: schema}); err == nil {
			t.Fatal("newer schema version succeeded")
		}
		if _, err := pool.Exec(ctx, `UPDATE `+schema+`.schema_version SET version=$1`, schemaVersion); err != nil {
			t.Fatal(err)
		}
	})
}

func testClosedPoolErrors(t *testing.T, ctx context.Context, dsn string) {
	t.Helper()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	schema := "xet_cas_closed_" + randomIdentifier(t)
	store, err := New(ctx, pool, Options{Schema: schema})
	if err != nil {
		pool.Close()
		t.Fatal(err)
	}
	cleanupPool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		pool.Close()
		t.Fatal(err)
	}
	defer cleanupPool.Close()
	t.Cleanup(func() { _, _ = cleanupPool.Exec(context.Background(), `DROP SCHEMA `+schema+` CASCADE`) })
	pool.Close()
	value := indexFixture("closed pool")
	stage := server.BlobStage{
		ID: server.ProtectionID{1}, Namespace: "closed", Blob: value.xorb.Blob,
		CreatedAt: time.Unix(0, 1).UTC(), ExpiresAt: time.Unix(0, 2).UTC(),
	}
	lease := server.FileLease{
		ID: server.ProtectionID{1}, Namespace: "closed", File: value.file.File.File.Hash,
		CreatedAt: time.Unix(0, 1).UTC(), ExpiresAt: time.Unix(0, 2).UTC(),
	}
	operations := []func() error{
		func() error { _, _, err := store.GetXorb(ctx, value.xorb.Blob.Hash); return err },
		func() error { return store.PutXorb(ctx, value.xorb) },
		func() error { _, _, err := store.GetShard(ctx, "closed", value.shard.Hash); return err },
		func() error { _, _, err := store.GetFile(ctx, "closed", value.file.File.File.Hash); return err },
		func() error { return store.PutFile(ctx, "closed", value.file) },
		func() error { _, _, err := store.GetDedup(ctx, "closed", value.chunk); return err },
		func() error {
			return store.PutDedup(ctx, "closed", value.chunk, server.DedupRecord{Shard: value.shard})
		},
		func() error { _, _, err := store.ResolveSHA256(ctx, "closed", value.sum, 7); return err },
		func() error { return store.PutSHA256(ctx, "closed", value.sum, 7, value.file.File.File.Hash) },
		func() error { return store.PublishShard(ctx, publication("closed", value)) },
		func() error { _, err := store.ListXorbs(ctx, server.PageRequest{}); return err },
		func() error { _, err := store.ListShards(ctx, nil, server.PageRequest{}); return err },
		func() error { _, err := store.ListFiles(ctx, nil, server.PageRequest{}); return err },
		func() error { _, err := store.ListDedup(ctx, nil, server.PageRequest{}); return err },
		func() error { _, err := store.ListSHA256(ctx, nil, server.PageRequest{}); return err },
		func() error { return store.PutBlobStage(ctx, stage) },
		func() error { return store.RenewBlobStage(ctx, stage.Namespace, stage.ID, stage.ExpiresAt) },
		func() error { return store.DeleteBlobStage(ctx, stage.Namespace, stage.ID) },
		func() error { _, err := store.ListBlobStages(ctx, nil, server.PageRequest{}); return err },
		func() error {
			_, err := store.ListExpiredBlobStages(ctx, stage.ExpiresAt, server.PageRequest{})
			return err
		},
		func() error {
			_, err := store.DeleteExpiredBlobStage(ctx, stage.Namespace, stage.ID, stage.ExpiresAt)
			return err
		},
		func() error { return store.PutFileLease(ctx, lease) },
		func() error { return store.RenewFileLease(ctx, lease.Namespace, lease.ID, lease.ExpiresAt) },
		func() error { return store.DeleteFileLease(ctx, lease.Namespace, lease.ID) },
		func() error { _, err := store.ListFileLeases(ctx, nil, server.PageRequest{}); return err },
		func() error {
			_, err := store.ListExpiredFileLeases(ctx, lease.ExpiresAt, server.PageRequest{})
			return err
		},
		func() error {
			_, err := store.DeleteExpiredFileLease(ctx, lease.Namespace, lease.ID, lease.ExpiresAt)
			return err
		},
	}
	for index, operation := range operations {
		if err := operation(); err == nil {
			t.Errorf("closed-pool operation %d succeeded", index)
		}
	}
	if _, err := New(ctx, pool, Options{Schema: schema}); err == nil {
		t.Fatal("construction with closed pool succeeded")
	}
}

func testDatabaseFaultInjection(t *testing.T, ctx context.Context, pool *pgxpool.Pool) {
	t.Helper()
	schema := "xet_cas_fault_" + randomIdentifier(t)
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), `DROP SCHEMA `+schema+` CASCADE`) })
	store, err := New(ctx, pool, Options{Schema: schema})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `CREATE FUNCTION `+schema+`.reject_write() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'injected write failure'; END $$`); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `CREATE FUNCTION `+schema+`.skip_write() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RETURN NULL; END $$`); err != nil {
		t.Fatal(err)
	}
	value := indexFixture("fault injection")
	stage := server.BlobStage{
		ID: server.ProtectionID{1}, Namespace: "fault", Blob: value.xorb.Blob,
		CreatedAt: time.Unix(0, 1).UTC(), ExpiresAt: time.Unix(0, 2).UTC(),
	}
	lease := server.FileLease{
		ID: server.ProtectionID{1}, Namespace: "fault", File: value.file.File.File.Hash,
		CreatedAt: time.Unix(0, 1).UTC(), ExpiresAt: time.Unix(0, 2).UTC(),
	}
	direct := map[string]func() error{
		"xorbs": func() error { return store.PutXorb(ctx, value.xorb) },
		"files": func() error { return store.PutFile(ctx, "fault", value.file) },
		"dedup": func() error {
			return store.PutDedup(ctx, "fault", value.chunk, server.DedupRecord{Shard: value.shard})
		},
		"sha256_associations": func() error {
			return store.PutSHA256(ctx, "fault", value.sum, 7, value.file.File.File.Hash)
		},
		"blob_stages": func() error { return store.PutBlobStage(ctx, stage) },
		"file_leases": func() error { return store.PutFileLease(ctx, lease) },
	}
	publication := publication("fault-publication", value)
	for _, function := range []string{"reject_write", "skip_write"} {
		for table, operation := range direct {
			trigger := "injected_" + function
			if _, err := pool.Exec(ctx, `CREATE TRIGGER `+trigger+` BEFORE INSERT ON `+schema+`.`+table+
				` FOR EACH ROW EXECUTE FUNCTION `+schema+`.`+function+`() `); err != nil {
				t.Fatal(err)
			}
			if err := operation(); err == nil {
				t.Errorf("%s direct %s fault succeeded", function, table)
			}
			if _, err := pool.Exec(ctx, `DROP TRIGGER `+trigger+` ON `+schema+`.`+table); err != nil {
				t.Fatal(err)
			}
		}
		for _, table := range []string{"dedup", "sha256_associations", "files", "shards"} {
			trigger := "injected_publication_" + function
			if _, err := pool.Exec(ctx, `CREATE TRIGGER `+trigger+` BEFORE INSERT ON `+schema+`.`+table+
				` FOR EACH ROW EXECUTE FUNCTION `+schema+`.`+function+`() `); err != nil {
				t.Fatal(err)
			}
			if err := store.PublishShard(ctx, publication); err == nil {
				t.Errorf("%s publication %s fault succeeded", function, table)
			}
			if _, err := pool.Exec(ctx, `DROP TRIGGER `+trigger+` ON `+schema+`.`+table); err != nil {
				t.Fatal(err)
			}
			if _, found, err := store.GetShard(ctx, publication.Namespace, publication.Shard.Hash); err != nil || found {
				t.Fatalf("faulted publication shard visible after %s/%s = %v, %v", function, table, found, err)
			}
		}
	}
}

type fixture struct {
	xorb  server.XorbRecord
	chunk xethash.Hash
	file  server.FileRecord
	shard server.BlobKey
	sum   [32]byte
}

func indexFixture(label string) fixture {
	chunkHash := xethash.Chunk([]byte("chunk " + label))
	xorbHash := xethash.Xorb([]xethash.Node{{Hash: chunkHash, Size: 7}})
	fileHash := xethash.Chunk([]byte("file " + label))
	shardKey := server.BlobKey{Kind: server.BlobShard, Hash: xethash.Chunk([]byte("shard " + label))}
	var sum [32]byte
	sumHash := xethash.Chunk([]byte("sha " + label))
	copy(sum[:], sumHash[:])
	return fixture{
		xorb: server.XorbRecord{
			Blob: server.BlobKey{Kind: server.BlobXorb, Hash: xorbHash},
			Layout: xorb.Ingested{
				Hash: xorbHash, NetworkBytes: 15, UncompressedSize: 7,
				Chunks: []xorb.IngestedChunk{{
					Hash: chunkHash, SerializedLength: 15, UncompressedLength: 7,
				}},
			},
		},
		chunk: chunkHash,
		file: server.FileRecord{
			File: shard.RegisteredFile{File: shard.File{
				Hash:  fileHash,
				Terms: []shard.Term{{XorbHash: xorbHash, Start: 0, End: 1, UnpackedBytes: 7}},
			}, Size: 7},
			Shard: shardKey,
		},
		shard: shardKey,
		sum:   sum,
	}
}

func publication(namespace string, value fixture) server.ShardPublication {
	return server.ShardPublication{
		Namespace: namespace,
		Shard:     value.shard,
		Dedup: []server.DedupAssociation{{
			Chunk: value.chunk, Value: server.DedupRecord{Shard: value.shard},
		}},
		SHA256: []server.SHA256Association{{Sum: value.sum, Size: 7, File: value.file.File.File.Hash}},
		Files:  []server.FileRecord{value.file},
	}
}

func testCoreIndex(t *testing.T, ctx context.Context, store *Store) {
	t.Helper()
	value := indexFixture("published")
	if _, found, err := store.GetXorb(ctx, value.xorb.Blob.Hash); err != nil || found {
		t.Fatalf("missing Xorb = %v, %v", found, err)
	}
	if err := store.PutXorb(ctx, value.xorb); err != nil {
		t.Fatal(err)
	}
	if err := store.PutXorb(ctx, value.xorb); err != nil {
		t.Fatalf("idempotent Xorb = %v", err)
	}
	conflictingXorb := value.xorb
	conflictingXorb.Layout.NetworkBytes++
	if err := store.PutXorb(ctx, conflictingXorb); !errors.Is(err, server.ErrConflict) {
		t.Fatalf("Xorb conflict = %v", err)
	}
	if err := store.PublishShard(ctx, publication("tenant-a", value)); err != nil {
		t.Fatal(err)
	}
	if err := store.PublishShard(ctx, publication("tenant-a", value)); err != nil {
		t.Fatalf("idempotent publication = %v", err)
	}
	if _, found, err := store.GetFile(ctx, "tenant-b", value.file.File.File.Hash); err != nil || found {
		t.Fatalf("cross-namespace file = %v, %v", found, err)
	}
	if got, found, err := store.GetShard(ctx, "tenant-a", value.shard.Hash); err != nil || !found ||
		got.Blob != value.shard {
		t.Fatalf("shard = %#v, %v, %v", got, found, err)
	}
	if got, found, err := store.GetDedup(ctx, "tenant-a", value.chunk); err != nil || !found ||
		got.Shard != value.shard {
		t.Fatalf("dedup = %#v, %v, %v", got, found, err)
	}
	if got, found, err := store.ResolveSHA256(ctx, "tenant-a", value.sum, 7); err != nil || !found ||
		got != value.file.File.File.Hash {
		t.Fatalf("SHA = %s, %v, %v", got, found, err)
	}
	if _, found, err := store.ResolveSHA256(ctx, "missing", value.sum, 7); err != nil || found {
		t.Fatalf("missing SHA = %v, %v", found, err)
	}

	alternative := indexFixture("first-valid")
	alternativeFile := alternative.file
	alternativeFile.Shard = value.shard
	if err := store.PutFile(ctx, "tenant-a", alternativeFile); err != nil {
		t.Fatal(err)
	}
	alternativeFile.Shard = alternative.shard
	if err := store.PutFile(ctx, "tenant-a", alternativeFile); err != nil {
		t.Fatalf("alternative file source = %v", err)
	}
	if got, found, err := store.GetFile(ctx, "tenant-a", alternativeFile.File.File.Hash); err != nil || !found ||
		got.Shard != value.shard {
		t.Fatalf("retained file = %#v, %v, %v", got, found, err)
	}
	if err := store.PutDedup(ctx, "tenant-a", alternative.chunk, server.DedupRecord{Shard: value.shard}); err != nil {
		t.Fatal(err)
	}
	if err := store.PutDedup(ctx, "tenant-a", alternative.chunk, server.DedupRecord{Shard: alternative.shard}); err != nil {
		t.Fatalf("alternative dedup source = %v", err)
	}
	if err := store.PutSHA256(ctx, "tenant-a", alternative.sum, 7, alternative.file.File.File.Hash); err != nil {
		t.Fatal(err)
	}
	if err := store.PutSHA256(ctx, "tenant-a", alternative.sum, 7, alternative.file.File.File.Hash); err != nil {
		t.Fatalf("idempotent SHA = %v", err)
	}
	if err := store.PutSHA256(ctx, "tenant-a", alternative.sum, 7, value.file.File.File.Hash); !errors.Is(err, server.ErrConflict) {
		t.Fatalf("SHA conflict = %v", err)
	}

	rollback := indexFixture("rollback")
	if err := store.PutSHA256(ctx, "tenant-a", rollback.sum, 7, value.file.File.File.Hash); err != nil {
		t.Fatal(err)
	}
	if err := store.PublishShard(ctx, publication("tenant-a", rollback)); !errors.Is(err, server.ErrConflict) {
		t.Fatalf("conflicting publication = %v", err)
	}
	if _, found, err := store.GetFile(ctx, "tenant-a", rollback.file.File.File.Hash); err != nil || found {
		t.Fatalf("rolled-back file = %v, %v", found, err)
	}
	if _, found, err := store.GetDedup(ctx, "tenant-a", rollback.chunk); err != nil || found {
		t.Fatalf("rolled-back dedup = %v, %v", found, err)
	}
	if _, found, err := store.GetShard(ctx, "tenant-a", rollback.shard.Hash); err != nil || found {
		t.Fatalf("rolled-back shard = %v, %v", found, err)
	}

	t.Run("concurrent immutable writes", func(t *testing.T) {
		concurrent := indexFixture("concurrent Xorb")
		conflict := concurrent.xorb
		conflict.Layout.Chunks = append([]xorb.IngestedChunk(nil), conflict.Layout.Chunks...)
		conflict.Layout.Chunks[0].SerializedLength++
		conflict.Layout.NetworkBytes++
		if _, err := server.ValidateXorbRecord(conflict.Layout.Hash, conflict); err != nil {
			t.Fatalf("valid concurrent Xorb conflict = %v", err)
		}
		start := make(chan struct{})
		results := make(chan error, 2)
		for _, record := range []server.XorbRecord{concurrent.xorb, conflict} {
			record := record
			go func() {
				<-start
				results <- store.PutXorb(ctx, record)
			}()
		}
		close(start)
		got := []error{<-results, <-results}
		var successes, conflicts int
		for _, err := range got {
			if err == nil {
				successes++
			} else if errors.Is(err, server.ErrConflict) {
				conflicts++
			} else {
				t.Fatalf("concurrent write = %v", err)
			}
		}
		if successes != 1 || conflicts != 1 {
			t.Fatalf("concurrent outcomes = %d success, %d conflict", successes, conflicts)
		}
	})

	t.Run("concurrent conflicting publications", func(t *testing.T) {
		left, right := indexFixture("concurrent publication left"), indexFixture("concurrent publication right")
		right.sum = left.sum
		start := make(chan struct{})
		results := make(chan error, 2)
		for _, value := range []fixture{left, right} {
			value := value
			go func() {
				<-start
				results <- store.PublishShard(ctx, publication("publication-race", value))
			}()
		}
		close(start)
		var successes, conflicts int
		for range 2 {
			err := <-results
			if err == nil {
				successes++
			} else if errors.Is(err, server.ErrConflict) {
				conflicts++
			} else {
				t.Fatalf("concurrent publication = %v", err)
			}
		}
		if successes != 1 || conflicts != 1 {
			t.Fatalf("concurrent publication outcomes = %d success, %d conflict", successes, conflicts)
		}
		winner, found, err := store.ResolveSHA256(ctx, "publication-race", left.sum, 7)
		if err != nil || !found {
			t.Fatalf("publication winner = %s, %v, %v", winner, found, err)
		}
		for _, value := range []fixture{left, right} {
			_, fileFound, fileErr := store.GetFile(ctx, "publication-race", value.file.File.File.Hash)
			_, shardFound, shardErr := store.GetShard(ctx, "publication-race", value.shard.Hash)
			want := winner == value.file.File.File.Hash
			if fileErr != nil || shardErr != nil || fileFound != want || shardFound != want {
				t.Fatalf("publication %s visible file/shard = %v/%v, want %v (errors %v/%v)",
					value.file.File.File.Hash, fileFound, shardFound, want, fileErr, shardErr)
			}
		}
	})

	t.Run("concurrent idempotent publications with opposite input order", func(t *testing.T) {
		left, right := indexFixture("ordered publication left"), indexFixture("ordered publication right")
		commonShard := server.BlobKey{Kind: server.BlobShard, Hash: xethash.Chunk([]byte("ordered publication shard"))}
		left.shard, left.file.Shard = commonShard, commonShard
		right.shard, right.file.Shard = commonShard, commonShard
		forward := server.ShardPublication{
			Namespace: "ordered-publication", Shard: commonShard,
			Dedup: []server.DedupAssociation{
				{Chunk: left.chunk, Value: server.DedupRecord{Shard: commonShard}},
				{Chunk: right.chunk, Value: server.DedupRecord{Shard: commonShard}},
			},
			SHA256: []server.SHA256Association{
				{Sum: left.sum, Size: 7, File: left.file.File.File.Hash},
				{Sum: right.sum, Size: 7, File: right.file.File.File.Hash},
			},
			Files: []server.FileRecord{left.file, right.file},
		}
		sameSumDifferentSize := forward.SHA256[0]
		sameSumDifferentSize.Size = 8
		forward.SHA256 = append(forward.SHA256, sameSumDifferentSize)
		reverse := forward
		reverse.Dedup = []server.DedupAssociation{forward.Dedup[1], forward.Dedup[0]}
		reverse.SHA256 = []server.SHA256Association{forward.SHA256[1], forward.SHA256[2], forward.SHA256[0]}
		reverse.Files = []server.FileRecord{forward.Files[1], forward.Files[0]}
		start := make(chan struct{})
		results := make(chan error, 2)
		for _, value := range []server.ShardPublication{forward, reverse} {
			value := value
			go func() {
				<-start
				results <- store.PublishShard(ctx, value)
			}()
		}
		close(start)
		for range 2 {
			if err := <-results; err != nil {
				t.Fatalf("opposite-order publication = %v", err)
			}
		}
	})

	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if _, _, err := store.GetFile(canceled, "tenant-a", value.file.File.File.Hash); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled lookup = %v", err)
	}
	if _, _, err := store.ResolveSHA256(ctx, "tenant-a", value.sum, ^uint64(0)); !errors.Is(err, server.ErrInvalid) {
		t.Fatalf("oversized SHA key = %v", err)
	}
	if err := store.PutSHA256(ctx, "tenant-a", value.sum, ^uint64(0), value.file.File.File.Hash); !errors.Is(err, server.ErrInvalid) {
		t.Fatalf("oversized SHA put = %v", err)
	}
	if err := store.PutXorb(ctx, server.XorbRecord{}); !errors.Is(err, server.ErrInvalid) {
		t.Fatalf("invalid Xorb = %v", err)
	}
	if err := store.PutFile(ctx, "tenant-a", server.FileRecord{}); !errors.Is(err, server.ErrInvalid) {
		t.Fatalf("invalid file = %v", err)
	}
	if err := store.PutDedup(ctx, "tenant-a", xethash.Zero, server.DedupRecord{}); !errors.Is(err, server.ErrInvalid) {
		t.Fatalf("invalid dedup = %v", err)
	}
	if err := store.PublishShard(ctx, server.ShardPublication{}); !errors.Is(err, server.ErrInvalid) {
		t.Fatalf("invalid publication = %v", err)
	}
	mismatchedDedup := publication("tenant-a", indexFixture("mismatched dedup"))
	mismatchedDedup.Dedup[0].Value.Shard = value.shard
	if err := store.PublishShard(ctx, mismatchedDedup); !errors.Is(err, server.ErrInvalid) {
		t.Fatalf("mismatched publication dedup = %v", err)
	}
	mismatchedFile := publication("tenant-a", indexFixture("mismatched file"))
	mismatchedFile.Files[0].Shard = value.shard
	if err := store.PublishShard(ctx, mismatchedFile); !errors.Is(err, server.ErrInvalid) {
		t.Fatalf("mismatched publication file = %v", err)
	}
	oversized := publication("tenant-a", indexFixture("oversized publication"))
	oversized.SHA256[0].Size = ^uint64(0)
	if err := store.PublishShard(ctx, oversized); !errors.Is(err, server.ErrInvalid) {
		t.Fatalf("oversized publication SHA = %v", err)
	}
	contradictory := publication("tenant-a", indexFixture("contradictory publication"))
	second := contradictory.SHA256[0]
	second.File = value.file.File.File.Hash
	contradictory.SHA256 = append(contradictory.SHA256, second)
	if err := store.PublishShard(ctx, contradictory); !errors.Is(err, server.ErrConflict) {
		t.Fatalf("contradictory publication SHA = %v", err)
	}
}

func testIndexIteration(t *testing.T, ctx context.Context, store *Store) {
	t.Helper()
	for _, label := range []string{"list-a", "list-b", "list-c"} {
		value := indexFixture(label)
		if err := store.PutXorb(ctx, value.xorb); err != nil {
			t.Fatal(err)
		}
		if err := store.PublishShard(ctx, publication("list", value)); err != nil {
			t.Fatal(err)
		}
	}
	xorbs, err := store.ListXorbs(ctx, server.PageRequest{Limit: 1})
	if err != nil || len(xorbs.Items) != 1 || xorbs.NextCursor == "" {
		t.Fatalf("Xorb page = %#v, %v", xorbs, err)
	}
	if _, err := store.ListXorbs(ctx, server.PageRequest{Cursor: xorbs.NextCursor, Limit: 1}); err != nil {
		t.Fatal(err)
	}
	namespace := "list"
	files, err := store.ListFiles(ctx, &namespace, server.PageRequest{Limit: 1})
	if err != nil || len(files.Items) != 1 || files.NextCursor == "" {
		t.Fatalf("file page = %#v, %v", files, err)
	}
	if _, err := store.ListDedup(ctx, &namespace, server.PageRequest{Cursor: files.NextCursor, Limit: 1}); !errors.Is(err, server.ErrInvalid) {
		t.Fatalf("cross-operation cursor = %v", err)
	}
	other := "other"
	if _, err := store.ListFiles(ctx, &other, server.PageRequest{Cursor: files.NextCursor, Limit: 1}); !errors.Is(err, server.ErrInvalid) {
		t.Fatalf("cross-scope cursor = %v", err)
	}
	shards, err := store.ListShards(ctx, &namespace, server.PageRequest{Limit: 2})
	if err != nil || len(shards.Items) != 2 || shards.NextCursor == "" {
		t.Fatalf("shard page = %#v, %v", shards, err)
	}
	dedup, err := store.ListDedup(ctx, nil, server.PageRequest{Limit: 2})
	if err != nil || len(dedup.Items) != 2 || dedup.NextCursor == "" {
		t.Fatalf("dedup page = %#v, %v", dedup, err)
	}
	sha, err := store.ListSHA256(ctx, &namespace, server.PageRequest{Limit: 2})
	if err != nil || len(sha.Items) != 2 || sha.NextCursor == "" {
		t.Fatalf("SHA page = %#v, %v", sha, err)
	}
	if next, err := store.ListSHA256(ctx, &namespace, server.PageRequest{Cursor: sha.NextCursor, Limit: 2}); err != nil || len(next.Items) == 0 {
		t.Fatalf("second SHA page = %#v, %v", next, err)
	}
	if next, err := store.ListShards(ctx, &namespace, server.PageRequest{Cursor: shards.NextCursor, Limit: 2}); err != nil || len(next.Items) == 0 {
		t.Fatalf("second shard page = %#v, %v", next, err)
	}
	if next, err := store.ListDedup(ctx, nil, server.PageRequest{Cursor: dedup.NextCursor, Limit: 2}); err != nil || len(next.Items) == 0 {
		t.Fatalf("second dedup page = %#v, %v", next, err)
	}
	allFiles, err := store.ListFiles(ctx, nil, server.PageRequest{Limit: 1})
	if err != nil || len(allFiles.Items) != 1 || allFiles.NextCursor == "" {
		t.Fatalf("global file page = %#v, %v", allFiles, err)
	}
	if _, err := store.ListFiles(ctx, nil, server.PageRequest{Cursor: allFiles.NextCursor, Limit: 1}); err != nil {
		t.Fatal(err)
	}
	allSHA, err := store.ListSHA256(ctx, nil, server.PageRequest{Limit: 1})
	if err != nil || len(allSHA.Items) != 1 || allSHA.NextCursor == "" {
		t.Fatalf("global SHA page = %#v, %v", allSHA, err)
	}
	if _, err := store.ListSHA256(ctx, nil, server.PageRequest{Cursor: allSHA.NextCursor, Limit: 1}); err != nil {
		t.Fatal(err)
	}
	for _, invalid := range []server.PageRequest{{Limit: -1}, {Limit: server.MaxPageSize + 1}, {Cursor: "garbage"}} {
		if _, err := store.ListXorbs(ctx, invalid); !errors.Is(err, server.ErrInvalid) {
			t.Errorf("invalid page %#v = %v", invalid, err)
		}
	}
	invalidXorbCursor := curEncode(cursor{Op: "xorbs", Mode: "global", NS: "unexpected", Key: make([]byte, 32)})
	if _, err := store.ListXorbs(ctx, server.PageRequest{Cursor: invalidXorbCursor}); !errors.Is(err, server.ErrInvalid) {
		t.Fatalf("invalid Xorb cursor shape = %v", err)
	}
	invalidSHACursor := curEncode(cursor{
		Op: "sha256", Mode: "scoped", Filter: namespace, NS: namespace,
		Key: append(make([]byte, 32), 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff),
	})
	if _, err := store.ListSHA256(ctx, &namespace, server.PageRequest{Cursor: invalidSHACursor}); !errors.Is(err, server.ErrInvalid) {
		t.Fatalf("invalid SHA cursor size = %v", err)
	}
	wrongLengthSHACursor := curEncode(cursor{
		Op: "sha256", Mode: "scoped", Filter: namespace, NS: namespace, Key: make([]byte, 39),
	})
	if _, err := store.ListSHA256(ctx, &namespace, server.PageRequest{Cursor: wrongLengthSHACursor}); !errors.Is(err, server.ErrInvalid) {
		t.Fatalf("wrong-length SHA cursor = %v", err)
	}
	if _, err := store.ListSHA256(ctx, &namespace, server.PageRequest{Cursor: "bad"}); !errors.Is(err, server.ErrInvalid) {
		t.Fatalf("malformed SHA cursor = %v", err)
	}
	invalidProtectionCursor := curEncode(cursor{
		Op: "stages", Mode: "scoped", Filter: namespace, NS: namespace,
		Key: make([]byte, 16), Exp: 1,
	})
	if _, err := store.ListBlobStages(ctx, &namespace, server.PageRequest{Cursor: invalidProtectionCursor}); !errors.Is(err, server.ErrInvalid) {
		t.Fatalf("invalid protection cursor shape = %v", err)
	}
	invalidFileCursor := curEncode(cursor{
		Op: "files", Mode: "scoped", Filter: namespace, NS: namespace, Key: make([]byte, 31),
	})
	if _, err := store.ListFiles(ctx, &namespace, server.PageRequest{Cursor: invalidFileCursor}); !errors.Is(err, server.ErrInvalid) {
		t.Fatalf("invalid file cursor shape = %v", err)
	}
	if _, err := store.ListFiles(ctx, nil, server.PageRequest{Limit: -1}); !errors.Is(err, server.ErrInvalid) {
		t.Fatalf("invalid file page = %v", err)
	}
	if _, err := store.ListSHA256(ctx, nil, server.PageRequest{Limit: -1}); !errors.Is(err, server.ErrInvalid) {
		t.Fatalf("invalid SHA page = %v", err)
	}
	if _, err := store.ListBlobStages(ctx, nil, server.PageRequest{Limit: -1}); !errors.Is(err, server.ErrInvalid) {
		t.Fatalf("invalid stage page = %v", err)
	}
	if _, err := store.ListExpiredFileLeases(ctx, time.Time{}, server.PageRequest{}); !errors.Is(err, server.ErrInvalid) {
		t.Fatalf("invalid lease expiry cutoff = %v", err)
	}
}

func testProtections(t *testing.T, ctx context.Context, store *Store) {
	t.Helper()
	base := time.Date(2026, 8, 11, 12, 0, 0, 0, time.UTC)
	value := indexFixture("protection")
	if err := store.PutBlobStage(ctx, server.BlobStage{}); !errors.Is(err, server.ErrInvalid) {
		t.Fatalf("invalid stage = %v", err)
	}
	if err := store.PutFileLease(ctx, server.FileLease{}); !errors.Is(err, server.ErrInvalid) {
		t.Fatalf("invalid lease = %v", err)
	}
	if err := store.PutFileLease(ctx, server.FileLease{
		ID: server.ProtectionID{99}, CreatedAt: base.Add(time.Minute), ExpiresAt: base,
	}); !errors.Is(err, server.ErrInvalid) {
		t.Fatalf("reversed lease = %v", err)
	}
	stage := server.BlobStage{
		ID: server.ProtectionID{1}, Namespace: "tenant-a", Blob: value.shard,
		CreatedAt: base, ExpiresAt: base.Add(time.Minute),
	}
	if err := store.PutBlobStage(ctx, stage); err != nil {
		t.Fatal(err)
	}
	if err := store.PutBlobStage(ctx, stage); err != nil {
		t.Fatalf("idempotent stage = %v", err)
	}
	retargeted := stage
	retargeted.Blob.Hash = xethash.Chunk([]byte("retargeted"))
	if err := store.PutBlobStage(ctx, retargeted); !errors.Is(err, server.ErrConflict) {
		t.Fatalf("retargeted stage = %v", err)
	}
	if err := store.RenewBlobStage(ctx, stage.Namespace, stage.ID, base.Add(3*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := store.RenewBlobStage(ctx, stage.Namespace, stage.ID, base.Add(2*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := store.RenewBlobStage(ctx, stage.Namespace, stage.ID, time.Time{}); !errors.Is(err, server.ErrInvalid) {
		t.Fatalf("invalid stage renewal = %v", err)
	}
	if _, found, err := store.getBlobStage(ctx, "missing", server.ProtectionID{99}); err != nil || found {
		t.Fatalf("missing stage lookup = %v, %v", found, err)
	}
	if _, found, err := store.getFileLease(ctx, "missing", server.ProtectionID{99}); err != nil || found {
		t.Fatalf("missing lease lookup = %v, %v", found, err)
	}
	for _, id := range []byte{6, 7} {
		additional := stage
		additional.ID = server.ProtectionID{id}
		additional.Blob.Hash = xethash.Chunk([]byte{'s', id})
		if err := store.PutBlobStage(ctx, additional); err != nil {
			t.Fatal(err)
		}
	}
	page, err := store.ListBlobStages(ctx, &stage.Namespace, server.PageRequest{Limit: 1})
	if err != nil || len(page.Items) != 1 || !page.Items[0].ExpiresAt.Equal(base.Add(3*time.Minute)) {
		t.Fatalf("stage page = %#v, %v", page, err)
	}
	stageCount := len(page.Items)
	for page.NextCursor != "" {
		page, err = store.ListBlobStages(ctx, &stage.Namespace, server.PageRequest{Cursor: page.NextCursor, Limit: 1})
		if err != nil {
			t.Fatal(err)
		}
		stageCount += len(page.Items)
	}
	if stageCount != 3 {
		t.Fatalf("multipage stage count = %d", stageCount)
	}

	lease := server.FileLease{
		ID: server.ProtectionID{2}, Namespace: "tenant-a", File: xethash.Zero,
		CreatedAt: base, ExpiresAt: base.Add(time.Minute),
	}
	if err := store.PutFileLease(ctx, lease); err != nil {
		t.Fatalf("zero-file lease parity = %v", err)
	}
	longer := lease
	longer.ExpiresAt = base.Add(4 * time.Minute)
	if err := store.PutFileLease(ctx, longer); err != nil {
		t.Fatalf("extended lease = %v", err)
	}
	for _, id := range []byte{6, 7} {
		additional := lease
		additional.ID = server.ProtectionID{id}
		additional.File = xethash.Chunk([]byte{'l', id})
		if err := store.PutFileLease(ctx, additional); err != nil {
			t.Fatal(err)
		}
	}
	retargetedLease := longer
	retargetedLease.File = value.file.File.File.Hash
	if err := store.PutFileLease(ctx, retargetedLease); !errors.Is(err, server.ErrConflict) {
		t.Fatalf("retargeted lease = %v", err)
	}
	leases, err := store.ListFileLeases(ctx, nil, server.PageRequest{Limit: 1})
	if err != nil || len(leases.Items) != 1 || leases.NextCursor == "" {
		t.Fatalf("lease page = %#v, %v", leases, err)
	}
	leaseCount := len(leases.Items)
	for leases.NextCursor != "" {
		leases, err = store.ListFileLeases(ctx, nil, server.PageRequest{Cursor: leases.NextCursor, Limit: 1})
		if err != nil {
			t.Fatal(err)
		}
		leaseCount += len(leases.Items)
	}
	if leaseCount != 3 {
		t.Fatalf("multipage lease count = %d", leaseCount)
	}
	if err := store.RenewFileLease(ctx, lease.Namespace, lease.ID, base.Add(3*time.Minute)); err != nil {
		t.Fatalf("shortening lease renewal = %v", err)
	}
	if err := store.RenewFileLease(ctx, lease.Namespace, lease.ID, base.Add(5*time.Minute)); err != nil {
		t.Fatalf("extending lease renewal = %v", err)
	}
	if err := store.RenewFileLease(ctx, "missing", server.ProtectionID{99}, base.Add(time.Minute)); !errors.Is(err, server.ErrNotFound) {
		t.Fatalf("missing lease renewal = %v", err)
	}
	if err := store.RenewFileLease(ctx, lease.Namespace, lease.ID, time.Time{}); !errors.Is(err, server.ErrInvalid) {
		t.Fatalf("invalid lease renewal = %v", err)
	}
	expiredLeases, err := store.ListExpiredFileLeases(ctx, base.Add(time.Minute), server.PageRequest{Limit: 1})
	if err != nil || len(expiredLeases.Items) != 1 || expiredLeases.NextCursor == "" {
		t.Fatalf("expired lease page = %#v, %v", expiredLeases, err)
	}
	if _, err := store.ListExpiredFileLeases(ctx, base.Add(2*time.Minute), server.PageRequest{Cursor: expiredLeases.NextCursor}); !errors.Is(err, server.ErrInvalid) {
		t.Fatalf("expiry lease cutoff cursor = %v", err)
	}
	if next, err := store.ListExpiredFileLeases(ctx, base.Add(time.Minute), server.PageRequest{
		Cursor: expiredLeases.NextCursor, Limit: 1,
	}); err != nil || len(next.Items) != 1 {
		t.Fatalf("second expired lease page = %#v, %v", next, err)
	}
	expiredLease := expiredLeases.Items[0]
	if deleted, err := store.DeleteExpiredFileLease(ctx, expiredLease.Namespace, expiredLease.ID, base.Add(time.Minute)); err != nil || !deleted {
		t.Fatalf("delete expired lease = %v, %v", deleted, err)
	}
	if deleted, err := store.DeleteExpiredFileLease(ctx, expiredLease.Namespace, expiredLease.ID, base.Add(time.Minute)); err != nil || deleted {
		t.Fatalf("repeat expired lease deletion = %v, %v", deleted, err)
	}
	if _, err := store.DeleteExpiredFileLease(ctx, lease.Namespace, server.ProtectionID{}, base); !errors.Is(err, server.ErrInvalid) {
		t.Fatalf("zero expired lease identity = %v", err)
	}

	expired := stage
	expired.ID = server.ProtectionID{3}
	expired.ExpiresAt = base.Add(time.Minute)
	if err := store.PutBlobStage(ctx, expired); err != nil {
		t.Fatal(err)
	}
	secondExpired := expired
	secondExpired.ID = server.ProtectionID{8}
	secondExpired.Blob.Hash = xethash.Chunk([]byte("second expired stage"))
	if err := store.PutBlobStage(ctx, secondExpired); err != nil {
		t.Fatal(err)
	}
	expiredPage, err := store.ListExpiredBlobStages(ctx, base.Add(time.Minute), server.PageRequest{Limit: 1})
	if err != nil || len(expiredPage.Items) != 1 || expiredPage.NextCursor == "" {
		t.Fatalf("expired stage page = %#v, %v", expiredPage, err)
	}
	if _, err := store.ListExpiredBlobStages(ctx, base.Add(2*time.Minute), server.PageRequest{Cursor: expiredPage.NextCursor}); !errors.Is(err, server.ErrInvalid) {
		t.Fatalf("expiry cutoff cursor = %v", err)
	}
	if next, err := store.ListExpiredBlobStages(ctx, base.Add(time.Minute), server.PageRequest{
		Cursor: expiredPage.NextCursor, Limit: 1,
	}); err != nil || len(next.Items) != 1 {
		t.Fatalf("second expired stage page = %#v, %v", next, err)
	}
	if deleted, err := store.DeleteExpiredBlobStage(ctx, expired.Namespace, expired.ID, base.Add(time.Minute)); err != nil || !deleted {
		t.Fatalf("delete expired stage = %v, %v", deleted, err)
	}
	if deleted, err := store.DeleteExpiredBlobStage(ctx, expired.Namespace, expired.ID, base.Add(time.Minute)); err != nil || deleted {
		t.Fatalf("repeat expired deletion = %v, %v", deleted, err)
	}
	if _, err := store.DeleteExpiredBlobStage(ctx, stage.Namespace, server.ProtectionID{}, base); !errors.Is(err, server.ErrInvalid) {
		t.Fatalf("zero expired stage identity = %v", err)
	}
	if _, err := store.DeleteExpiredBlobStage(ctx, stage.Namespace, stage.ID, time.Time{}); !errors.Is(err, server.ErrInvalid) {
		t.Fatalf("invalid expired stage cutoff = %v", err)
	}
	if _, err := store.DeleteExpiredFileLease(ctx, lease.Namespace, lease.ID, time.Time{}); !errors.Is(err, server.ErrInvalid) {
		t.Fatalf("invalid expired lease cutoff = %v", err)
	}
	nanosecondStage := stage
	nanosecondStage.ID = server.ProtectionID{5}
	nanosecondStage.CreatedAt = base.Add(-time.Nanosecond)
	nanosecondStage.ExpiresAt = base.Add(time.Nanosecond)
	if err := store.PutBlobStage(ctx, nanosecondStage); err != nil {
		t.Fatal(err)
	}
	if page, err := store.ListExpiredBlobStages(ctx, base, server.PageRequest{}); err != nil {
		t.Fatal(err)
	} else {
		for _, item := range page.Items {
			if item.ID == nanosecondStage.ID && item.Namespace == nanosecondStage.Namespace {
				t.Fatal("nanosecond-future stage was rounded into expired set")
			}
		}
	}

	race := stage
	race.ID = server.ProtectionID{4}
	race.ExpiresAt = base.Add(time.Minute)
	if err := store.PutBlobStage(ctx, race); err != nil {
		t.Fatal(err)
	}
	start := make(chan struct{})
	var wait sync.WaitGroup
	wait.Add(2)
	var renewed error
	var deleted bool
	var deleteErr error
	go func() {
		defer wait.Done()
		<-start
		renewed = store.RenewBlobStage(ctx, race.Namespace, race.ID, base.Add(10*time.Minute))
	}()
	go func() {
		defer wait.Done()
		<-start
		deleted, deleteErr = store.DeleteExpiredBlobStage(ctx, race.Namespace, race.ID, base.Add(time.Minute))
	}()
	close(start)
	wait.Wait()
	if deleteErr != nil || renewed != nil && !errors.Is(renewed, server.ErrNotFound) {
		t.Fatalf("renew/delete race = renewed %v, deleted %v, delete error %v", renewed, deleted, deleteErr)
	}
	if renewed == nil && deleted {
		t.Fatal("successful renewal was removed by stale expiry deletion")
	}
	if errors.Is(renewed, server.ErrNotFound) && !deleted {
		t.Fatal("renewal missed without successful deletion")
	}

	if err := store.DeleteBlobStage(ctx, stage.Namespace, stage.ID); err != nil {
		t.Fatal(err)
	}
	if err := store.DeleteBlobStage(ctx, stage.Namespace, stage.ID); err != nil {
		t.Fatal("repeat stage deletion failed")
	}
	if err := store.DeleteFileLease(ctx, lease.Namespace, lease.ID); err != nil {
		t.Fatal(err)
	}

	canceled, cancel := context.WithCancel(ctx)
	cancel()
	for name, operation := range map[string]func() error{
		"put stage": func() error { return store.PutBlobStage(canceled, stage) },
		"renew stage": func() error {
			return store.RenewBlobStage(canceled, stage.Namespace, stage.ID, base.Add(time.Hour))
		},
		"delete stage": func() error { return store.DeleteBlobStage(canceled, stage.Namespace, stage.ID) },
		"put lease":    func() error { return store.PutFileLease(canceled, lease) },
		"renew lease": func() error {
			return store.RenewFileLease(canceled, lease.Namespace, lease.ID, base.Add(time.Hour))
		},
		"delete lease": func() error { return store.DeleteFileLease(canceled, lease.Namespace, lease.ID) },
	} {
		if err := operation(); !errors.Is(err, context.Canceled) {
			t.Fatalf("canceled %s = %v", name, err)
		}
	}
}

func testMalformedRecords(
	t *testing.T,
	ctx context.Context,
	pool *pgxpool.Pool,
	schema string,
	store *Store,
) {
	t.Helper()
	fileValue := indexFixture("malformed file")
	if _, err := pool.Exec(ctx, `INSERT INTO `+schema+`.files(namespace,hash,record) VALUES($1,$2,$3)`,
		"corrupt", fileValue.file.File.File.Hash[:], []byte(`{"truncated"`)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.GetFile(ctx, "corrupt", fileValue.file.File.File.Hash); !errors.Is(err, server.ErrCorrupt) {
		t.Fatalf("malformed file lookup = %v", err)
	}
	if err := store.PutFile(ctx, "corrupt", fileValue.file); !errors.Is(err, server.ErrCorrupt) {
		t.Fatalf("malformed retained file = %v", err)
	}
	corruptNamespace := "corrupt"
	if _, err := store.ListFiles(ctx, &corruptNamespace, server.PageRequest{}); !errors.Is(err, server.ErrCorrupt) {
		t.Fatalf("malformed listed file = %v", err)
	}
	if err := store.PublishShard(ctx, publication("corrupt", fileValue)); !errors.Is(err, server.ErrCorrupt) {
		t.Fatalf("publication over malformed file = %v", err)
	}
	wrongFileKey := xethash.Chunk([]byte("wrong retained file key"))
	wrongFileRecord, err := enc(fileValue.file)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO `+schema+`.files(namespace,hash,record) VALUES($1,$2,$3)`,
		"wrong-file", wrongFileKey[:], wrongFileRecord); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.GetFile(ctx, "wrong-file", wrongFileKey); !errors.Is(err, server.ErrCorrupt) {
		t.Fatalf("wrong file identity = %v", err)
	}

	dedupValue := indexFixture("malformed dedup")
	if _, err := pool.Exec(ctx, `INSERT INTO `+schema+`.dedup(namespace,chunk_hash,record) VALUES($1,$2,$3)`,
		"corrupt", dedupValue.chunk[:], []byte(`null`)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.GetDedup(ctx, "corrupt", dedupValue.chunk); !errors.Is(err, server.ErrCorrupt) {
		t.Fatalf("malformed dedup lookup = %v", err)
	}
	if err := store.PutDedup(ctx, "corrupt", dedupValue.chunk, server.DedupRecord{Shard: dedupValue.shard}); !errors.Is(err, server.ErrCorrupt) {
		t.Fatalf("malformed retained dedup = %v", err)
	}
	if _, err := store.ListDedup(ctx, &corruptNamespace, server.PageRequest{}); !errors.Is(err, server.ErrCorrupt) {
		t.Fatalf("malformed listed dedup = %v", err)
	}
	if err := store.PublishShard(ctx, publication("corrupt", dedupValue)); !errors.Is(err, server.ErrCorrupt) {
		t.Fatalf("publication over malformed dedup = %v", err)
	}

	xorbValue := indexFixture("malformed Xorb")
	invalidLayout := xorbValue.xorb
	invalidLayout.Layout.NetworkBytes++
	invalidLayoutData, err := enc(invalidLayout)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO `+schema+`.xorbs(hash,record) VALUES($1,$2)`,
		xorbValue.xorb.Blob.Hash[:], invalidLayoutData); err != nil {
		t.Fatal(err)
	}
	if err := store.PutXorb(ctx, xorbValue.xorb); !errors.Is(err, server.ErrCorrupt) {
		t.Fatalf("invalid-layout retained Xorb = %v", err)
	}
	if _, err := pool.Exec(ctx, `UPDATE `+schema+`.xorbs SET record=$1 WHERE hash=$2`,
		[]byte(`{}`), xorbValue.xorb.Blob.Hash[:]); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.GetXorb(ctx, xorbValue.xorb.Blob.Hash); !errors.Is(err, server.ErrCorrupt) {
		t.Fatalf("malformed Xorb lookup = %v", err)
	}
	if err := store.PutXorb(ctx, xorbValue.xorb); !errors.Is(err, server.ErrCorrupt) {
		t.Fatalf("malformed retained Xorb = %v", err)
	}
	previous := xorbValue.xorb.Blob.Hash
	for index := len(previous) - 1; index >= 0; index-- {
		if previous[index] != 0 {
			previous[index]--
			break
		}
		previous[index] = 0xff
	}
	if _, err := store.ListXorbs(ctx, server.PageRequest{
		Cursor: curEncode(cursor{Op: "xorbs", Mode: "global", Key: previous[:]}), Limit: 1,
	}); !errors.Is(err, server.ErrCorrupt) {
		t.Fatalf("malformed listed Xorb = %v", err)
	}
	truncatedXorb := indexFixture("truncated Xorb")
	if _, err := pool.Exec(ctx, `INSERT INTO `+schema+`.xorbs(hash,record) VALUES($1,$2)`,
		truncatedXorb.xorb.Blob.Hash[:], []byte(`{"truncated"`)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.GetXorb(ctx, truncatedXorb.xorb.Blob.Hash); !errors.Is(err, server.ErrCorrupt) {
		t.Fatalf("truncated Xorb lookup = %v", err)
	}

	shardValue := indexFixture("malformed shard")
	wrongShard := server.ShardRecord{Blob: server.BlobKey{
		Kind: server.BlobShard, Hash: xethash.Chunk([]byte("wrong shard identity")),
	}}
	shardRecord, err := enc(wrongShard)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO `+schema+`.shards(namespace,hash,record) VALUES($1,$2,$3)`,
		"corrupt-shard", shardValue.shard.Hash[:], shardRecord); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.GetShard(ctx, "corrupt-shard", shardValue.shard.Hash); !errors.Is(err, server.ErrCorrupt) {
		t.Fatalf("malformed shard lookup = %v", err)
	}
	shardNamespace := "corrupt-shard"
	if _, err := store.ListShards(ctx, &shardNamespace, server.PageRequest{}); !errors.Is(err, server.ErrCorrupt) {
		t.Fatalf("malformed listed shard = %v", err)
	}
	if err := store.PublishShard(ctx, server.ShardPublication{Namespace: shardNamespace, Shard: shardValue.shard}); !errors.Is(err, server.ErrCorrupt) {
		t.Fatalf("publication over malformed shard = %v", err)
	}

	stageValue := indexFixture("malformed stage")
	stageID := server.ProtectionID{9}
	if _, err := pool.Exec(ctx, `INSERT INTO `+schema+`.blob_stages(namespace,id,blob_kind,blob_hash,created_at,expires_at) VALUES($1,$2,$3,$4,$5,$6)`,
		"corrupt", stageID[:], server.BlobXorb, make([]byte, len(xethash.Hash{})), int64(1), int64(2)); err != nil {
		t.Fatal(err)
	}
	validStage := server.BlobStage{
		ID: stageID, Namespace: "corrupt", Blob: stageValue.xorb.Blob,
		CreatedAt: time.Unix(0, 1).UTC(), ExpiresAt: time.Unix(0, 2).UTC(),
	}
	if err := store.PutBlobStage(ctx, validStage); !errors.Is(err, server.ErrCorrupt) {
		t.Fatalf("malformed retained stage = %v", err)
	}
	if _, err := store.ListBlobStages(ctx, &corruptNamespace, server.PageRequest{}); !errors.Is(err, server.ErrCorrupt) {
		t.Fatalf("malformed listed stage = %v", err)
	}

	for _, cleanup := range []struct {
		query string
		args  []any
	}{
		{query: `DELETE FROM ` + schema + `.files WHERE namespace='corrupt'`},
		{query: `DELETE FROM ` + schema + `.files WHERE namespace='wrong-file'`},
		{query: `DELETE FROM ` + schema + `.dedup WHERE namespace='corrupt'`},
		{query: `DELETE FROM ` + schema + `.xorbs WHERE hash=$1`, args: []any{xorbValue.xorb.Blob.Hash[:]}},
		{query: `DELETE FROM ` + schema + `.xorbs WHERE hash=$1`, args: []any{truncatedXorb.xorb.Blob.Hash[:]}},
		{query: `DELETE FROM ` + schema + `.blob_stages WHERE namespace='corrupt'`},
		{query: `DELETE FROM ` + schema + `.shards WHERE namespace='corrupt-shard'`},
	} {
		if _, err := pool.Exec(ctx, cleanup.query, cleanup.args...); err != nil {
			t.Fatal(err)
		}
	}
}

func randomIdentifier(t *testing.T) string {
	t.Helper()
	f, err := os.CreateTemp("", "pgschema")
	if err != nil {
		t.Fatal(err)
	}
	name := f.Name()
	_ = f.Close()
	_ = os.Remove(name)
	b := []byte(name)
	out := ""
	for _, c := range b {
		if c >= 'a' && c <= 'z' || c >= '0' && c <= '9' {
			out += string(c)
		}
	}
	if len(out) > 24 {
		out = out[len(out)-24:]
	}
	return out
}
