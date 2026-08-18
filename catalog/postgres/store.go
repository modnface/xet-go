// Package postgres implements a durable PostgreSQL catalog.
package postgres

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jmwoliver/xet-go/catalog"
	"github.com/jmwoliver/xet-go/model"
	"github.com/jmwoliver/xet-go/xethash"
)

const schemaVersion = 1

var identifier = regexp.MustCompile(`^[a-z_][a-z0-9_]{0,62}$`)

// Options selects the private PostgreSQL schema that owns the catalog tables.
type Options struct{ Schema string }

// Store implements a durable PostgreSQL catalog. The configured pool remains
// owned by the caller when the store is constructed with New.
type Store struct {
	pool   *pgxpool.Pool
	schema string
	owned  bool
	mu     sync.RWMutex
	closed bool
}

var _ catalog.Catalog = (*Store)(nil)

func parseOptions(o Options) (string, error) {
	if o.Schema == "" {
		o.Schema = "xet_catalog"
	}
	if !identifier.MatchString(o.Schema) {
		return "", invalid(errors.New("schema must be an unquoted lowercase PostgreSQL identifier"))
	}
	return o.Schema, nil
}

// Open creates and owns a PostgreSQL pool. Returned errors never include the
// supplied connection string.
func Open(ctx context.Context, dsn string, o Options) (*Store, error) {
	schema, e := parseOptions(o)
	if e != nil {
		return nil, e
	}
	config, e := pgxpool.ParseConfig(dsn)
	if e != nil {
		return nil, unavailable(errors.New("invalid PostgreSQL connection configuration"))
	}
	config.ConnConfig.RuntimeParams["client_encoding"] = "UTF8"
	p, e := pgxpool.NewWithConfig(ctx, config)
	if e != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, unavailable(errors.New("could not open PostgreSQL pool"))
	}
	s, e := New(ctx, p, Options{Schema: schema})
	if e != nil {
		p.Close()
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if errors.Is(e, catalog.ErrCorrupt) {
			return nil, corrupt(errors.New("could not initialize PostgreSQL catalog schema"))
		}
		return nil, unavailable(errors.New("could not initialize PostgreSQL catalog"))
	}
	s.owned = true
	return s, nil
}

// New initializes a store using p. Close does not close the caller-owned pool.
// Every connection supplied by p must retain client_encoding=UTF8.
func New(ctx context.Context, p *pgxpool.Pool, o Options) (*Store, error) {
	if p == nil {
		return nil, invalid(errors.New("nil pool"))
	}
	schema, e := parseOptions(o)
	if e != nil {
		return nil, e
	}
	s := &Store{pool: p, schema: schema}
	if e = s.init(ctx); e != nil {
		return nil, e
	}
	return s, nil
}
func (s *Store) q(table string) string { return pgx.Identifier{s.schema, table}.Sanitize() }
func (s *Store) quotedSchema() string  { return pgx.Identifier{s.schema}.Sanitize() }
func (s *Store) init(ctx context.Context) error {
	tx, e := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if e != nil {
		return dbErr(ctx, e)
	}
	defer rollback(tx)
	// A stable, schema-specific transaction lock serializes independent initializers.
	if _, e = tx.Exec(ctx, `SELECT pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended($1, 0))`, "xet-go/catalog/"+s.schema); e != nil {
		return dbErr(ctx, e)
	}
	if _, e = tx.Exec(ctx, `SELECT pg_catalog.set_config('search_path','pg_catalog',true)`); e != nil {
		return dbErr(ctx, e)
	}
	var serverEncoding, clientEncoding string
	if e = tx.QueryRow(ctx, `SELECT pg_catalog.current_setting('server_encoding'),pg_catalog.current_setting('client_encoding')`).Scan(&serverEncoding, &clientEncoding); e != nil {
		return dbErr(ctx, e)
	}
	if serverEncoding != "UTF8" || clientEncoding != "UTF8" {
		return unavailable(fmt.Errorf("PostgreSQL server_encoding and client_encoding must both be UTF8, got %s and %s", serverEncoding, clientEncoding))
	}
	if _, e = tx.Exec(ctx, `CREATE SCHEMA IF NOT EXISTS `+s.quotedSchema()); e != nil {
		return dbErr(ctx, e)
	}
	if _, e = tx.Exec(ctx, `CREATE TABLE IF NOT EXISTS `+s.q("schema_version")+`(singleton boolean NOT NULL DEFAULT true CONSTRAINT schema_version_singleton CHECK(singleton),version integer NOT NULL CONSTRAINT schema_version_nonnegative CHECK(version>=0),CONSTRAINT schema_version_pkey PRIMARY KEY(singleton))`); e != nil {
		return dbErr(ctx, e)
	}
	var version int
	e = tx.QueryRow(ctx, `SELECT version FROM `+s.q("schema_version")+` WHERE singleton=true FOR UPDATE`).Scan(&version)
	if errors.Is(e, pgx.ErrNoRows) {
		_, e = tx.Exec(ctx, `INSERT INTO `+s.q("schema_version")+`(singleton,version) VALUES(true,0)`)
		version = 0
	}
	if e != nil {
		return schemaErr(ctx, e)
	}
	if version > schemaVersion {
		return unavailable(fmt.Errorf("schema version %d is newer than supported version %d", version, schemaVersion))
	}
	if version < 0 {
		return corrupt(errors.New("negative schema version"))
	}
	if version < 1 {
		for _, statement := range s.schemaV1() {
			if _, e = tx.Exec(ctx, statement); e != nil {
				return schemaErr(ctx, e)
			}
		}
		if _, e = tx.Exec(ctx, `UPDATE `+s.q("schema_version")+` SET version=1 WHERE singleton=true`); e != nil {
			return dbErr(ctx, e)
		}
	}
	if e = s.probeSchema(ctx, tx); e != nil {
		return e
	}
	return dbErr(ctx, tx.Commit(ctx))
}

func (s *Store) schemaV1() []string {
	return []string{
		`CREATE TABLE IF NOT EXISTS ` + s.q("repositories") + `(repo_type text COLLATE pg_catalog."C" NOT NULL,namespace text COLLATE pg_catalog."C" NOT NULL,name text COLLATE pg_catalog."C" NOT NULL,created_at bigint NOT NULL,CONSTRAINT repositories_pkey PRIMARY KEY(repo_type,namespace,name))`,
		`CREATE TABLE IF NOT EXISTS ` + s.q("snapshots") + `(repo_type text COLLATE pg_catalog."C" NOT NULL,namespace text COLLATE pg_catalog."C" NOT NULL,name text COLLATE pg_catalog."C" NOT NULL,oid bytea NOT NULL CONSTRAINT snapshots_oid_length CHECK(pg_catalog.octet_length(oid)=20),parent bytea CONSTRAINT snapshots_parent_length CHECK(parent IS NULL OR pg_catalog.octet_length(parent)=20),created_at bigint NOT NULL,author_name text NOT NULL,author_email text NOT NULL,message text NOT NULL,file_count bigint NOT NULL CONSTRAINT snapshots_file_count_nonnegative CHECK(file_count>=0),fingerprint bytea NOT NULL CONSTRAINT snapshots_fingerprint_length CHECK(pg_catalog.octet_length(fingerprint)=32),fingerprint_version integer NOT NULL CONSTRAINT snapshots_fingerprint_version CHECK(fingerprint_version=1),CONSTRAINT snapshots_pkey PRIMARY KEY(repo_type,namespace,name,oid),CONSTRAINT snapshots_repository_fkey FOREIGN KEY(repo_type,namespace,name) REFERENCES ` + s.q("repositories") + ` ON DELETE CASCADE,CONSTRAINT snapshots_parent_fkey FOREIGN KEY(repo_type,namespace,name,parent) REFERENCES ` + s.q("snapshots") + `(repo_type,namespace,name,oid))`,
		`CREATE INDEX IF NOT EXISTS snapshots_order ON ` + s.q("snapshots") + `(repo_type,namespace,name,created_at DESC,oid DESC)`,
		`CREATE TABLE IF NOT EXISTS ` + s.q("refs") + `(repo_type text COLLATE pg_catalog."C" NOT NULL,namespace text COLLATE pg_catalog."C" NOT NULL,name text COLLATE pg_catalog."C" NOT NULL,ref_name text COLLATE pg_catalog."C" NOT NULL,oid bytea NOT NULL CONSTRAINT refs_oid_length CHECK(pg_catalog.octet_length(oid)=20),CONSTRAINT refs_pkey PRIMARY KEY(repo_type,namespace,name,ref_name),CONSTRAINT refs_snapshot_fkey FOREIGN KEY(repo_type,namespace,name,oid) REFERENCES ` + s.q("snapshots") + `(repo_type,namespace,name,oid))`,
		`CREATE TABLE IF NOT EXISTS ` + s.q("files") + `(repo_type text COLLATE pg_catalog."C" NOT NULL,namespace text COLLATE pg_catalog."C" NOT NULL,name text COLLATE pg_catalog."C" NOT NULL,oid bytea NOT NULL,path text COLLATE pg_catalog."C" NOT NULL,kind text NOT NULL CONSTRAINT files_kind CHECK(kind IN ('blob','xet')),size bigint NOT NULL CONSTRAINT files_size_nonnegative CHECK(size>=0),sha256 bytea CONSTRAINT files_sha256_length CHECK(sha256 IS NULL OR pg_catalog.octet_length(sha256)=32),xet_hash bytea CONSTRAINT files_xet_hash_length CHECK(xet_hash IS NULL OR pg_catalog.octet_length(xet_hash)=32),CONSTRAINT files_representation CHECK((kind='blob' AND sha256 IS NOT NULL AND xet_hash IS NULL) OR (kind='xet' AND xet_hash IS NOT NULL)),CONSTRAINT files_pkey PRIMARY KEY(repo_type,namespace,name,oid,path),CONSTRAINT files_snapshot_fkey FOREIGN KEY(repo_type,namespace,name,oid) REFERENCES ` + s.q("snapshots") + ` ON DELETE CASCADE)`,
	}
}

func (s *Store) probeSchema(ctx context.Context, tx pgx.Tx) error {
	if e := s.probeColumns(ctx, tx); e != nil {
		return e
	}
	if e := s.probeConstraints(ctx, tx); e != nil {
		return e
	}
	if e := s.probeSnapshotIndex(ctx, tx); e != nil {
		return e
	}
	var rows, singletonRows int
	if e := tx.QueryRow(ctx, `SELECT count(*),count(*) FILTER (WHERE singleton) FROM `+s.q("schema_version")).Scan(&rows, &singletonRows); e != nil {
		return schemaErr(ctx, e)
	}
	if rows != 1 || singletonRows != 1 {
		return corrupt(errors.New("schema version table must contain exactly one singleton row"))
	}
	return nil
}

type columnManifest struct {
	typeName  string
	notNull   bool
	collation string
}

func expectedColumns() map[string]columnManifest {
	manifest := make(map[string]columnManifest)
	add := func(table, typ string, notNull bool, collation string, names ...string) {
		for _, name := range names {
			manifest[table+"."+name] = columnManifest{typeName: typ, notNull: notNull, collation: collation}
		}
	}
	add("schema_version", "bool", true, "", "singleton")
	add("schema_version", "int4", true, "", "version")
	add("repositories", "text", true, "C", "repo_type", "namespace", "name")
	add("repositories", "int8", true, "", "created_at")
	add("snapshots", "text", true, "C", "repo_type", "namespace", "name")
	add("snapshots", "bytea", true, "", "oid", "fingerprint")
	add("snapshots", "bytea", false, "", "parent")
	add("snapshots", "int8", true, "", "created_at", "file_count")
	add("snapshots", "text", true, "*", "author_name", "author_email", "message")
	add("snapshots", "int4", true, "", "fingerprint_version")
	add("refs", "text", true, "C", "repo_type", "namespace", "name", "ref_name")
	add("refs", "bytea", true, "", "oid")
	add("files", "text", true, "C", "repo_type", "namespace", "name", "path")
	add("files", "bytea", true, "", "oid")
	add("files", "text", true, "*", "kind")
	add("files", "int8", true, "", "size")
	add("files", "bytea", false, "", "sha256", "xet_hash")
	return manifest
}

func (s *Store) probeColumns(ctx context.Context, tx pgx.Tx) error {
	expected := expectedColumns()
	rows, e := tx.Query(ctx, `SELECT c.relname,c.relpersistence::text,a.attname,t.typname,tns.nspname,a.attnotnull,COALESCE(coll.collname,''),COALESCE(collns.nspname,'')
FROM pg_catalog.pg_class c
JOIN pg_catalog.pg_namespace ns ON ns.oid=c.relnamespace
JOIN pg_catalog.pg_attribute a ON a.attrelid=c.oid AND a.attnum>0 AND NOT a.attisdropped
JOIN pg_catalog.pg_type t ON t.oid=a.atttypid
JOIN pg_catalog.pg_namespace tns ON tns.oid=t.typnamespace
LEFT JOIN pg_catalog.pg_collation coll ON coll.oid=a.attcollation
LEFT JOIN pg_catalog.pg_namespace collns ON collns.oid=coll.collnamespace
WHERE ns.nspname=$1 AND c.relkind='r' AND c.relname=ANY($2::text[])
ORDER BY c.relname,a.attnum`, s.schema, []string{"schema_version", "repositories", "snapshots", "refs", "files"})
	if e != nil {
		return schemaErr(ctx, e)
	}
	defer rows.Close()
	seen := make(map[string]struct{}, len(expected))
	for rows.Next() {
		var table, persistence, name, typ, typeSchema, collation, collationSchema string
		var notNull bool
		if e = rows.Scan(&table, &persistence, &name, &typ, &typeSchema, &notNull, &collation, &collationSchema); e != nil {
			return schemaErr(ctx, e)
		}
		key := table + "." + name
		want, ok := expected[key]
		if !ok || persistence != "p" || typeSchema != "pg_catalog" || typ != want.typeName || notNull != want.notNull ||
			(want.collation != "*" && (collation != want.collation || want.collation != "" && collationSchema != "pg_catalog")) {
			return corrupt(fmt.Errorf("incompatible catalog column %s", key))
		}
		seen[key] = struct{}{}
	}
	if e = rows.Err(); e != nil {
		return schemaErr(ctx, e)
	}
	if len(seen) != len(expected) {
		return corrupt(fmt.Errorf("catalog schema has %d of %d required columns", len(seen), len(expected)))
	}
	return nil
}

type constraintManifest struct {
	kind, table, referenced, deleteAction string
	columns, referencedColumns            []string
	check                                 bool
}

func expectedConstraints() map[string]constraintManifest {
	manifest := make(map[string]constraintManifest)
	primary := func(table, name string, columns ...string) {
		manifest[name] = constraintManifest{kind: "p", table: table, columns: columns}
	}
	foreign := func(table, name, referenced, deleteAction string, columns, referencedColumns []string) {
		manifest[name] = constraintManifest{kind: "f", table: table, referenced: referenced, deleteAction: deleteAction, columns: columns, referencedColumns: referencedColumns}
	}
	check := func(table, name string) {
		manifest[name] = constraintManifest{kind: "c", table: table, check: true}
	}
	primary("schema_version", "schema_version_pkey", "singleton")
	check("schema_version", "schema_version_singleton")
	check("schema_version", "schema_version_nonnegative")
	primary("repositories", "repositories_pkey", "repo_type", "namespace", "name")
	primary("snapshots", "snapshots_pkey", "repo_type", "namespace", "name", "oid")
	check("snapshots", "snapshots_oid_length")
	check("snapshots", "snapshots_parent_length")
	check("snapshots", "snapshots_file_count_nonnegative")
	check("snapshots", "snapshots_fingerprint_length")
	check("snapshots", "snapshots_fingerprint_version")
	foreign("snapshots", "snapshots_repository_fkey", "repositories", "c", []string{"repo_type", "namespace", "name"}, []string{"repo_type", "namespace", "name"})
	foreign("snapshots", "snapshots_parent_fkey", "snapshots", "a", []string{"repo_type", "namespace", "name", "parent"}, []string{"repo_type", "namespace", "name", "oid"})
	primary("refs", "refs_pkey", "repo_type", "namespace", "name", "ref_name")
	check("refs", "refs_oid_length")
	foreign("refs", "refs_snapshot_fkey", "snapshots", "a", []string{"repo_type", "namespace", "name", "oid"}, []string{"repo_type", "namespace", "name", "oid"})
	primary("files", "files_pkey", "repo_type", "namespace", "name", "oid", "path")
	check("files", "files_kind")
	check("files", "files_size_nonnegative")
	check("files", "files_sha256_length")
	check("files", "files_xet_hash_length")
	check("files", "files_representation")
	foreign("files", "files_snapshot_fkey", "snapshots", "c", []string{"repo_type", "namespace", "name", "oid"}, []string{"repo_type", "namespace", "name", "oid"})
	return manifest
}

func canonicalCheckExpressions(ctx context.Context, tx pgx.Tx) (map[string]string, error) {
	var backendPID int
	if e := tx.QueryRow(ctx, `SELECT pg_catalog.pg_backend_pid()`).Scan(&backendPID); e != nil {
		return nil, schemaErr(ctx, e)
	}
	tableName := fmt.Sprintf("xet_catalog_check_manifest_%d", backendPID)
	table := pgx.Identifier{"pg_temp", tableName}.Sanitize()
	_, e := tx.Exec(ctx, `CREATE TEMP TABLE `+table+`(
singleton boolean CONSTRAINT schema_version_singleton CHECK(singleton),
version integer CONSTRAINT schema_version_nonnegative CHECK(version>=0),
oid bytea CONSTRAINT snapshots_oid_length CHECK(pg_catalog.octet_length(oid)=20),
parent bytea CONSTRAINT snapshots_parent_length CHECK(parent IS NULL OR pg_catalog.octet_length(parent)=20),
file_count bigint CONSTRAINT snapshots_file_count_nonnegative CHECK(file_count>=0),
fingerprint bytea CONSTRAINT snapshots_fingerprint_length CHECK(pg_catalog.octet_length(fingerprint)=32),
fingerprint_version integer CONSTRAINT snapshots_fingerprint_version CHECK(fingerprint_version=1),
kind text CONSTRAINT files_kind CHECK(kind IN ('blob','xet')),
size bigint CONSTRAINT files_size_nonnegative CHECK(size>=0),
sha256 bytea CONSTRAINT files_sha256_length CHECK(sha256 IS NULL OR pg_catalog.octet_length(sha256)=32),
xet_hash bytea CONSTRAINT files_xet_hash_length CHECK(xet_hash IS NULL OR pg_catalog.octet_length(xet_hash)=32),
CONSTRAINT refs_oid_length CHECK(pg_catalog.octet_length(oid)=20),
CONSTRAINT files_representation CHECK((kind='blob' AND sha256 IS NOT NULL AND xet_hash IS NULL) OR (kind='xet' AND xet_hash IS NOT NULL))
) ON COMMIT DROP`)
	if e != nil {
		return nil, schemaErr(ctx, e)
	}
	rows, e := tx.Query(ctx, `SELECT con.conname,pg_catalog.pg_get_expr(con.conbin,con.conrelid,true)
FROM pg_catalog.pg_constraint con
JOIN pg_catalog.pg_class t ON t.oid=con.conrelid
WHERE t.relnamespace=pg_catalog.pg_my_temp_schema() AND t.relname=$1 AND con.contype='c'`, tableName)
	if e != nil {
		return nil, schemaErr(ctx, e)
	}
	defer rows.Close()
	expressions := make(map[string]string)
	for rows.Next() {
		var name, expression string
		if e = rows.Scan(&name, &expression); e != nil {
			return nil, schemaErr(ctx, e)
		}
		expressions[name] = expression
	}
	if e = rows.Err(); e != nil {
		return nil, schemaErr(ctx, e)
	}
	return expressions, nil
}

func (s *Store) probeConstraints(ctx context.Context, tx pgx.Tx) error {
	expected := expectedConstraints()
	checks, e := canonicalCheckExpressions(ctx, tx)
	if e != nil {
		return e
	}
	var supportsEnforced bool
	if e = tx.QueryRow(ctx, `SELECT EXISTS(
SELECT 1 FROM pg_catalog.pg_attribute a
JOIN pg_catalog.pg_class c ON c.oid=a.attrelid
JOIN pg_catalog.pg_namespace ns ON ns.oid=c.relnamespace
WHERE ns.nspname='pg_catalog' AND c.relname='pg_constraint' AND a.attname='conenforced' AND NOT a.attisdropped)`).Scan(&supportsEnforced); e != nil {
		return schemaErr(ctx, e)
	}
	enforcedExpression := "true"
	if supportsEnforced {
		enforcedExpression = "con.conenforced"
	}
	rows, e := tx.Query(ctx, `SELECT con.conname,con.contype::text,t.relname,COALESCE(rns.nspname,''),COALESCE(rt.relname,''),
con.confdeltype::text,con.confupdtype::text,con.confmatchtype::text,
con.condeferrable,con.condeferred,con.convalidated,con.connoinherit,`+enforcedExpression+`,COALESCE(pg_catalog.pg_get_expr(con.conbin,con.conrelid,true),''),
ARRAY(SELECT a.attname FROM unnest(con.conkey) WITH ORDINALITY AS key(attnum,ord) JOIN pg_catalog.pg_attribute a ON a.attrelid=con.conrelid AND a.attnum=key.attnum ORDER BY key.ord),
ARRAY(SELECT a.attname FROM unnest(con.confkey) WITH ORDINALITY AS key(attnum,ord) JOIN pg_catalog.pg_attribute a ON a.attrelid=con.confrelid AND a.attnum=key.attnum ORDER BY key.ord)
FROM pg_catalog.pg_constraint con
JOIN pg_catalog.pg_class t ON t.oid=con.conrelid
JOIN pg_catalog.pg_namespace ns ON ns.oid=t.relnamespace
LEFT JOIN pg_catalog.pg_class rt ON rt.oid=con.confrelid
LEFT JOIN pg_catalog.pg_namespace rns ON rns.oid=rt.relnamespace
WHERE ns.nspname=$1 AND t.relname=ANY($2::text[])
ORDER BY con.conname`, s.schema, []string{"schema_version", "repositories", "snapshots", "refs", "files"})
	if e != nil {
		return schemaErr(ctx, e)
	}
	defer rows.Close()
	seen := make(map[string]struct{}, len(expected))
	for rows.Next() {
		var name, kind, table, referencedSchema, referenced, deleteAction, updateAction, matchType, expression string
		var deferrable, deferred, validated, noInherit, enforced bool
		var columns, referencedColumns []string
		if e = rows.Scan(&name, &kind, &table, &referencedSchema, &referenced, &deleteAction, &updateAction, &matchType,
			&deferrable, &deferred, &validated, &noInherit, &enforced, &expression, &columns, &referencedColumns); e != nil {
			return schemaErr(ctx, e)
		}
		want, ok := expected[name]
		if !ok || kind != want.kind || table != want.table || deferrable || deferred || !validated || !enforced || noInherit != (kind == "p" || kind == "f") ||
			(kind == "p" || kind == "f") && !slices.Equal(columns, want.columns) || kind == "f" && (referenced != want.referenced || deleteAction != want.deleteAction || !slices.Equal(referencedColumns, want.referencedColumns)) ||
			kind == "f" && (referencedSchema != s.schema || updateAction != "a" || matchType != "s") ||
			kind == "c" && (!want.check || expression != checks[name]) {
			return corrupt(fmt.Errorf("incompatible catalog constraint %s", name))
		}
		seen[name] = struct{}{}
	}
	if e = rows.Err(); e != nil {
		return schemaErr(ctx, e)
	}
	if len(seen) != len(expected) {
		return corrupt(fmt.Errorf("catalog schema has %d of %d required constraints", len(seen), len(expected)))
	}
	return nil
}

func (s *Store) probeSnapshotIndex(ctx context.Context, tx pgx.Tx) error {
	var unique, valid, ready, live, noPredicate, noExpressions bool
	var accessMethod string
	var keyCount, attributeCount int
	var columns, collations, operatorClasses []string
	var options []int16
	e := tx.QueryRow(ctx, `SELECT i.indisunique,i.indisvalid,i.indisready,i.indislive,am.amname,i.indnkeyatts,i.indnatts,
i.indpred IS NULL,i.indexprs IS NULL,
ARRAY(SELECT a.attname FROM unnest(i.indkey::smallint[]) WITH ORDINALITY AS key(attnum,ord) JOIN pg_catalog.pg_attribute a ON a.attrelid=i.indrelid AND a.attnum=key.attnum ORDER BY key.ord),
i.indoption::smallint[],
ARRAY(SELECT CASE WHEN coll.oid IS NULL THEN '' ELSE collns.nspname||'.'||coll.collname END FROM unnest(i.indcollation::oid[]) WITH ORDINALITY AS key(oid,ord) LEFT JOIN pg_catalog.pg_collation coll ON coll.oid=key.oid LEFT JOIN pg_catalog.pg_namespace collns ON collns.oid=coll.collnamespace ORDER BY key.ord),
ARRAY(SELECT opcns.nspname||'.'||opc.opcname FROM unnest(i.indclass::oid[]) WITH ORDINALITY AS key(oid,ord) JOIN pg_catalog.pg_opclass opc ON opc.oid=key.oid JOIN pg_catalog.pg_namespace opcns ON opcns.oid=opc.opcnamespace ORDER BY key.ord)
FROM pg_catalog.pg_index i
JOIN pg_catalog.pg_class idx ON idx.oid=i.indexrelid
JOIN pg_catalog.pg_namespace idxns ON idxns.oid=idx.relnamespace
JOIN pg_catalog.pg_am am ON am.oid=idx.relam
JOIN pg_catalog.pg_class t ON t.oid=i.indrelid
JOIN pg_catalog.pg_namespace ns ON ns.oid=t.relnamespace
WHERE ns.nspname=$1 AND idxns.nspname=$1 AND t.relname='snapshots' AND idx.relname='snapshots_order'`, s.schema).Scan(
		&unique, &valid, &ready, &live, &accessMethod, &keyCount, &attributeCount, &noPredicate, &noExpressions,
		&columns, &options, &collations, &operatorClasses)
	if e != nil {
		if errors.Is(e, pgx.ErrNoRows) {
			return corrupt(errors.New("missing snapshots_order index"))
		}
		return schemaErr(ctx, e)
	}
	if unique || !valid || !ready || !live || accessMethod != "btree" || keyCount != 5 || attributeCount != 5 || !noPredicate || !noExpressions ||
		!slices.Equal(columns, []string{"repo_type", "namespace", "name", "created_at", "oid"}) ||
		!slices.Equal(options, []int16{0, 0, 0, 3, 3}) ||
		!slices.Equal(collations, []string{"pg_catalog.C", "pg_catalog.C", "pg_catalog.C", "", ""}) ||
		!slices.Equal(operatorClasses, []string{"pg_catalog.text_ops", "pg_catalog.text_ops", "pg_catalog.text_ops", "pg_catalog.int8_ops", "pg_catalog.bytea_ops"}) {
		return corrupt(errors.New("incompatible snapshots_order index"))
	}
	return nil
}
func rollback(tx pgx.Tx) {
	c, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_ = tx.Rollback(c)
}

// Close is idempotent and closes only a pool created by Open.
func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	if s.owned {
		s.pool.Close()
	}
	return nil
}
func (s *Store) check(ctx context.Context) error {
	if e := ctx.Err(); e != nil {
		return e
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed {
		return unavailable(errors.New("store closed"))
	}
	return nil
}

func args(k model.RepoKey) []any { return []any{k.Type, k.Namespace, k.Name} }
func validKey(ctx context.Context, k model.RepoKey) error {
	if e := ctx.Err(); e != nil {
		return e
	}
	if e := model.ValidateRepoKey(k); e != nil {
		return invalid(e)
	}
	return nil
}
func (s *Store) CreateRepository(ctx context.Context, r model.Repository) error {
	if e := s.check(ctx); e != nil {
		return e
	}
	r, e := model.CanonicalRepository(r)
	if e != nil {
		return invalid(e)
	}
	inserted, e := s.pool.Exec(ctx, `INSERT INTO `+s.q("repositories")+` VALUES($1,$2,$3,$4)`, r.Key.Type, r.Key.Namespace, r.Key.Name, r.CreatedAt.UnixNano())
	if ctx.Err() != nil {
		return ctx.Err()
	}
	var postgresError *pgconn.PgError
	if errors.As(e, &postgresError) && postgresError.Code == "23505" && postgresError.SchemaName == s.schema &&
		postgresError.TableName == "repositories" && postgresError.ConstraintName == "repositories_pkey" {
		return fmt.Errorf("repository: %w", catalog.ErrAlreadyExists)
	}
	return expectOne(ctx, inserted, e, "repository insert")
}
func (s *Store) GetRepository(ctx context.Context, k model.RepoKey) (model.Repository, error) {
	if e := s.check(ctx); e != nil {
		return model.Repository{}, e
	}
	if e := validKey(ctx, k); e != nil {
		return model.Repository{}, e
	}
	var ns, name, typ string
	var t int64
	e := s.pool.QueryRow(ctx, `SELECT repo_type,namespace,name,created_at FROM `+s.q("repositories")+` WHERE repo_type=$1 AND namespace=$2 AND name=$3`, args(k)...).Scan(&typ, &ns, &name, &t)
	if e != nil {
		return model.Repository{}, rowErr(ctx, e)
	}
	repository, e := model.CanonicalRepository(model.Repository{
		Key:       model.RepoKey{Type: model.RepoType(typ), Namespace: model.Namespace(ns), Name: model.RepoName(name)},
		CreatedAt: time.Unix(0, t).UTC(),
	})
	if e != nil {
		return model.Repository{}, corrupt(e)
	}
	return repository, nil
}

type cursor struct {
	V                            int `json:"v"`
	Op, Scope, Filter, Last, OID string
	Time                         *int64 `json:"time,omitempty"`
}

func enc(c cursor) string {
	c.V = schemaVersion
	b, _ := json.Marshal(c)
	return base64.RawURLEncoding.EncodeToString(b)
}
func dec(v string) (cursor, error) {
	b, e := base64.RawURLEncoding.DecodeString(v)
	if e != nil {
		return cursor{}, e
	}
	var c cursor
	d := json.NewDecoder(strings.NewReader(string(b)))
	d.DisallowUnknownFields()
	if e = d.Decode(&c); e != nil {
		return c, e
	}
	if e = d.Decode(&struct{}{}); !errors.Is(e, io.EOF) {
		return c, errors.New("trailing cursor data")
	}
	if c.V != schemaVersion {
		return c, errors.New("cursor version")
	}
	return c, nil
}
func limit(n int) (int, error) {
	if n < 0 || n > catalog.MaxPageSize {
		return 0, invalid(errors.New("invalid page limit"))
	}
	if n == 0 {
		return catalog.DefaultPageSize, nil
	}
	return n, nil
}
func scope(k model.RepoKey) string {
	return string(k.Type) + "\x00" + string(k.Namespace) + "\x00" + string(k.Name)
}

func parseScope(value string) (model.RepoKey, bool) {
	parts := strings.Split(value, "\x00")
	if len(parts) != 3 {
		return model.RepoKey{}, false
	}
	key, e := model.NewRepoKey(parts[1], parts[2], model.RepoType(parts[0]))
	return key, e == nil && scope(key) == value
}

func (s *Store) ListRepositories(ctx context.Context, q catalog.RepositoryQuery) (catalog.RepositoryPage, error) {
	if e := s.check(ctx); e != nil {
		return catalog.RepositoryPage{}, e
	}
	n, e := limit(q.Limit)
	if e != nil {
		return catalog.RepositoryPage{}, e
	}
	if q.Namespace != "" {
		if _, e = model.ParseNamespace(string(q.Namespace)); e != nil {
			return catalog.RepositoryPage{}, invalid(e)
		}
	}
	if q.Type != "" && q.Type != model.RepoTypeModel {
		return catalog.RepositoryPage{}, invalid(errors.New("unsupported repository type"))
	}
	var after model.RepoKey
	hasAfter := false
	if q.Cursor != "" {
		c, x := dec(q.Cursor)
		key, valid := parseScope(c.Last)
		if x != nil || c.Op != "repos" || c.Scope != "" ||
			c.Filter != string(q.Namespace)+"\x00"+string(q.Type) || c.Time != nil || c.OID != "" || !valid ||
			(q.Namespace != "" && key.Namespace != q.Namespace) || (q.Type != "" && key.Type != q.Type) {
			return catalog.RepositoryPage{}, invalid(errors.New("mismatched cursor"))
		}
		after = key
		hasAfter = true
	}
	rows, e := s.pool.Query(ctx, `SELECT repo_type,namespace,name,created_at FROM `+s.q("repositories")+`
WHERE ($1='' OR namespace=$1) AND ($2='' OR repo_type=$2)
AND (NOT $3 OR (repo_type COLLATE pg_catalog."C",namespace COLLATE pg_catalog."C",name COLLATE pg_catalog."C")>($4,$5,$6))
ORDER BY repo_type COLLATE pg_catalog."C",namespace COLLATE pg_catalog."C",name COLLATE pg_catalog."C" LIMIT $7`,
		q.Namespace, q.Type, hasAfter, after.Type, after.Namespace, after.Name, n+1)
	if e != nil {
		return catalog.RepositoryPage{}, dbErr(ctx, e)
	}
	defer rows.Close()
	p := catalog.RepositoryPage{}
	for rows.Next() {
		var typ, ns, name string
		var t int64
		if e = rows.Scan(&typ, &ns, &name, &t); e != nil {
			return p, corrupt(e)
		}
		r := model.Repository{Key: model.RepoKey{Type: model.RepoType(typ), Namespace: model.Namespace(ns), Name: model.RepoName(name)}, CreatedAt: time.Unix(0, t).UTC()}
		r, x := model.CanonicalRepository(r)
		if x != nil {
			return p, corrupt(x)
		}
		p.Items = append(p.Items, r)
	}
	if e = rows.Err(); e != nil {
		return p, dbErr(ctx, e)
	}
	if len(p.Items) > n {
		p.Items = p.Items[:n]
		p.NextCursor = enc(cursor{Op: "repos", Filter: string(q.Namespace) + "\x00" + string(q.Type), Last: scope(p.Items[len(p.Items)-1].Key)})
	}
	return p, nil
}

func oidBytes(b []byte) (model.OID, error) {
	if len(b) != 20 {
		return model.OID{}, corrupt(errors.New("malformed OID"))
	}
	var o model.OID
	copy(o[:], b)
	if o.IsZero() {
		return o, corrupt(errors.New("zero OID"))
	}
	return o, nil
}
func (s *Store) resolveOID(ctx context.Context, k model.RepoKey, r model.Revision) (model.OID, error) {
	if o, ok := r.OID(); ok {
		return o, nil
	}
	n, ok := r.Ref()
	if !ok {
		return model.OID{}, invalid(errors.New("empty revision"))
	}
	return s.loadRefOID(ctx, s.pool, k, n)
}

func (s *Store) loadRefOID(ctx context.Context, q querier, k model.RepoKey, n model.RefName) (model.OID, error) {
	var encoded, target []byte
	e := q.QueryRow(ctx, `SELECT r.oid,s.oid FROM `+s.q("refs")+` r
LEFT JOIN `+s.q("snapshots")+` s ON s.repo_type=r.repo_type AND s.namespace=r.namespace AND s.name=r.name AND s.oid=r.oid
WHERE r.repo_type=$1 AND r.namespace=$2 AND r.name=$3 AND r.ref_name=$4`, k.Type, k.Namespace, k.Name, n).Scan(&encoded, &target)
	if e != nil {
		return model.OID{}, rowErr(ctx, e)
	}
	oid, e := oidBytes(encoded)
	if e != nil {
		return model.OID{}, e
	}
	targetOID, e := oidBytes(target)
	if e != nil || oid != targetOID {
		return model.OID{}, corrupt(errors.New("invalid or dangling ref OID"))
	}
	return oid, nil
}
func (s *Store) GetSnapshot(ctx context.Context, k model.RepoKey, o model.OID) (model.Snapshot, error) {
	r, e := model.RevisionFromOID(o)
	if e != nil {
		return model.Snapshot{}, invalid(e)
	}
	return s.ResolveRevision(ctx, k, r)
}
func (s *Store) ResolveRevision(ctx context.Context, k model.RepoKey, r model.Revision) (model.Snapshot, error) {
	if e := s.check(ctx); e != nil {
		return model.Snapshot{}, e
	}
	if e := validKey(ctx, k); e != nil {
		return model.Snapshot{}, e
	}
	o, e := s.resolveOID(ctx, k, r)
	if e != nil {
		return model.Snapshot{}, e
	}
	return s.loadSnapshot(ctx, s.pool, k, o)
}

type querier interface {
	QueryRow(context.Context, string, ...any) pgx.Row
	Query(context.Context, string, ...any) (pgx.Rows, error)
}

func (s *Store) loadSnapshot(ctx context.Context, q querier, k model.RepoKey, o model.OID) (model.Snapshot, error) {
	var ob, pb, fp []byte
	var t, count int64
	var fingerprintVersion int
	var an, ae, msg string
	e := q.QueryRow(ctx, `SELECT oid,parent,created_at,author_name,author_email,message,file_count,fingerprint,fingerprint_version FROM `+s.q("snapshots")+` WHERE repo_type=$1 AND namespace=$2 AND name=$3 AND oid=$4`, k.Type, k.Namespace, k.Name, o[:]).Scan(&ob, &pb, &t, &an, &ae, &msg, &count, &fp, &fingerprintVersion)
	if e != nil {
		return model.Snapshot{}, rowErr(ctx, e)
	}
	got, e := oidBytes(ob)
	if e != nil {
		return model.Snapshot{}, e
	}
	var parent *model.OID
	if pb != nil {
		x, e := oidBytes(pb)
		if e != nil {
			return model.Snapshot{}, e
		}
		parent = &x
	}
	rows, e := q.Query(ctx, `SELECT path,kind,size,sha256,xet_hash FROM `+s.q("files")+` WHERE repo_type=$1 AND namespace=$2 AND name=$3 AND oid=$4 ORDER BY path COLLATE pg_catalog."C"`, k.Type, k.Namespace, k.Name, o[:])
	if e != nil {
		return model.Snapshot{}, dbErr(ctx, e)
	}
	defer rows.Close()
	snap := model.Snapshot{Repo: k, OID: got, Parent: parent, CreatedAt: time.Unix(0, t).UTC(), Author: model.Identity{Name: an, Email: ae}, Message: msg}
	for rows.Next() {
		f, e := scanFile(rows)
		if e != nil {
			return model.Snapshot{}, corrupt(e)
		}
		snap.Files = append(snap.Files, f)
	}
	if e = rows.Err(); e != nil {
		return model.Snapshot{}, dbErr(ctx, e)
	}
	canonical, e := model.CanonicalSnapshot(snap)
	if e != nil || int64(len(canonical.Files)) != count || len(fp) != 32 || fingerprintVersion != model.SnapshotFingerprintVersion {
		return model.Snapshot{}, corrupt(errors.New("malformed snapshot"))
	}
	finger, e := model.FingerprintSnapshot(canonical)
	if e != nil {
		return model.Snapshot{}, corrupt(e)
	}
	if string(finger[:]) != string(fp) {
		return model.Snapshot{}, corrupt(errors.New("snapshot fingerprint mismatch"))
	}
	return canonical, nil
}
func scanFile(r interface{ Scan(...any) error }) (model.FileEntry, error) {
	var path, kind string
	var size int64
	var sha, xet []byte
	if e := r.Scan(&path, &kind, &size, &sha, &xet); e != nil {
		return model.FileEntry{}, e
	}
	p, e := model.ParseFilePath(path)
	if e != nil {
		return model.FileEntry{}, corrupt(e)
	}
	var ref model.FileRef
	if kind == "blob" && len(sha) == 32 && xet == nil {
		var h [32]byte
		copy(h[:], sha)
		ref, e = model.NewBlobFileRef(h, size)
	} else if kind == "xet" && len(xet) == 32 && (sha == nil || len(sha) == 32) {
		var h xethash.Hash
		copy(h[:], xet)
		var sum *[32]byte
		if sha != nil {
			var v [32]byte
			copy(v[:], sha)
			sum = &v
		}
		ref, e = model.NewXetFileRef(h, size, sum)
	} else {
		e = errors.New("malformed file")
	}
	if e != nil {
		return model.FileEntry{}, corrupt(e)
	}
	return model.FileEntry{Path: p, Ref: ref}, nil
}

func (s *Store) ensureRepositoryExists(ctx context.Context, q querier, k model.RepoKey) error {
	var exists int
	e := q.QueryRow(ctx, `SELECT 1 FROM `+s.q("repositories")+` WHERE repo_type=$1 AND namespace=$2 AND name=$3`, args(k)...).Scan(&exists)
	return rowErr(ctx, e)
}

func (s *Store) ensureSnapshotExists(ctx context.Context, q querier, k model.RepoKey, o model.OID) error {
	var exists int
	e := q.QueryRow(ctx, `SELECT 1 FROM `+s.q("snapshots")+` WHERE repo_type=$1 AND namespace=$2 AND name=$3 AND oid=$4`, k.Type, k.Namespace, k.Name, o[:]).Scan(&exists)
	return rowErr(ctx, e)
}

func (s *Store) ListSnapshots(ctx context.Context, k model.RepoKey, q catalog.SnapshotQuery) (catalog.SnapshotPage, error) {
	if e := s.check(ctx); e != nil {
		return catalog.SnapshotPage{}, e
	}
	if e := validKey(ctx, k); e != nil {
		return catalog.SnapshotPage{}, e
	}
	if e := s.ensureRepositoryExists(ctx, s.pool, k); e != nil {
		return catalog.SnapshotPage{}, e
	}
	n, e := limit(q.Limit)
	if e != nil {
		return catalog.SnapshotPage{}, e
	}
	var at *int64
	var ao []byte
	if q.Cursor != "" {
		c, x := dec(q.Cursor)
		if x != nil || c.Op != "snapshots" || c.Scope != scope(k) || c.Filter != "" ||
			c.Last != "" || c.Time == nil {
			return catalog.SnapshotPage{}, invalid(errors.New("mismatched cursor"))
		}
		o, x := model.ParseOID(c.OID)
		if x != nil {
			return catalog.SnapshotPage{}, invalid(x)
		}
		at = c.Time
		ao = o[:]
	}
	rows, e := s.pool.Query(ctx, `SELECT oid,parent,created_at,author_name,author_email,message,file_count FROM `+s.q("snapshots")+` WHERE repo_type=$1 AND namespace=$2 AND name=$3 AND ($4::bigint IS NULL OR (created_at,oid)<($4,$5)) ORDER BY created_at DESC,oid DESC LIMIT $6`, k.Type, k.Namespace, k.Name, at, ao, n+1)
	if e != nil {
		return catalog.SnapshotPage{}, dbErr(ctx, e)
	}
	defer rows.Close()
	p := catalog.SnapshotPage{}
	for rows.Next() {
		var ob, pb []byte
		var t, c int64
		var an, ae, m string
		if e = rows.Scan(&ob, &pb, &t, &an, &ae, &m, &c); e != nil {
			return p, corrupt(e)
		}
		o, x := oidBytes(ob)
		if x != nil {
			return p, x
		}
		var parent *model.OID
		if pb != nil {
			v, x := oidBytes(pb)
			if x != nil {
				return p, x
			}
			parent = &v
		}
		if c < 0 || uint64(c) > uint64(^uint(0)>>1) {
			return p, corrupt(errors.New("snapshot file count overflows int"))
		}
		i := model.SnapshotInfo{Repo: k, OID: o, Parent: parent, CreatedAt: time.Unix(0, t).UTC(), Author: model.Identity{Name: an, Email: ae}, Message: m, FileCount: int(c)}
		i, x = model.CanonicalSnapshotInfo(i)
		if x != nil {
			return p, corrupt(x)
		}
		p.Items = append(p.Items, i)
	}
	if e = rows.Err(); e != nil {
		return p, dbErr(ctx, e)
	}
	if len(p.Items) > n {
		p.Items = p.Items[:n]
		last := p.Items[n-1]
		t := last.CreatedAt.UnixNano()
		p.NextCursor = enc(cursor{Op: "snapshots", Scope: scope(k), Time: &t, OID: last.OID.String()})
	}
	return p, nil
}
func (s *Store) GetRef(ctx context.Context, k model.RepoKey, n model.RefName) (model.Ref, error) {
	if e := s.check(ctx); e != nil {
		return model.Ref{}, e
	}
	if e := model.ValidateRef(model.Ref{Repo: k, Name: n, OID: model.OID{1}}); e != nil {
		return model.Ref{}, invalid(e)
	}
	o, e := s.loadRefOID(ctx, s.pool, k, n)
	if e != nil {
		return model.Ref{}, e
	}
	return model.Ref{Repo: k, Name: n, OID: o}, nil
}

func (s *Store) ListRefs(ctx context.Context, k model.RepoKey, q catalog.RefQuery) (catalog.RefPage, error) {
	if e := s.check(ctx); e != nil {
		return catalog.RefPage{}, e
	}
	if e := validKey(ctx, k); e != nil {
		return catalog.RefPage{}, e
	}
	n, e := limit(q.Limit)
	if e != nil {
		return catalog.RefPage{}, e
	}
	var after *string
	if q.Cursor != "" {
		c, x := dec(q.Cursor)
		name, nameErr := model.ParseRefName(c.Last)
		if x != nil || nameErr != nil || c.Op != "refs" || c.Scope != scope(k) || c.Filter != "" ||
			c.Time != nil || c.OID != "" {
			return catalog.RefPage{}, invalid(errors.New("mismatched cursor"))
		}
		value := string(name)
		after = &value
	}
	if e := s.ensureRepositoryExists(ctx, s.pool, k); e != nil {
		return catalog.RefPage{}, e
	}
	rows, e := s.pool.Query(ctx, `SELECT r.ref_name,r.oid,s.oid FROM `+s.q("refs")+` r
LEFT JOIN `+s.q("snapshots")+` s ON s.repo_type=r.repo_type AND s.namespace=r.namespace AND s.name=r.name AND s.oid=r.oid
WHERE r.repo_type=$1 AND r.namespace=$2 AND r.name=$3 AND ($4::text IS NULL OR r.ref_name COLLATE pg_catalog."C">$4)
ORDER BY r.ref_name COLLATE pg_catalog."C" LIMIT $5`, k.Type, k.Namespace, k.Name, after, n+1)
	if e != nil {
		return catalog.RefPage{}, dbErr(ctx, e)
	}
	defer rows.Close()
	p := catalog.RefPage{}
	for rows.Next() {
		var name string
		var encoded, target []byte
		if e = rows.Scan(&name, &encoded, &target); e != nil {
			return p, corrupt(e)
		}
		parsed, parseErr := model.ParseRefName(name)
		oid, oidErr := oidBytes(encoded)
		targetOID, targetErr := oidBytes(target)
		if parseErr != nil || oidErr != nil || targetErr != nil || oid != targetOID {
			return p, corrupt(errors.New("invalid ref"))
		}
		ref := model.Ref{Repo: k, Name: parsed, OID: oid}
		if e = model.ValidateRef(ref); e != nil {
			return p, corrupt(e)
		}
		p.Items = append(p.Items, ref)
	}
	if e = rows.Err(); e != nil {
		return p, dbErr(ctx, e)
	}
	if len(p.Items) > n {
		p.Items = p.Items[:n]
		p.NextCursor = enc(cursor{Op: "refs", Scope: scope(k), Last: string(p.Items[n-1].Name)})
	}
	return p, nil
}

func copyExpected(o *model.OID) (model.OID, bool, error) {
	if o == nil {
		return model.OID{}, false, nil
	}
	if o.IsZero() {
		return model.OID{}, false, invalid(errors.New("zero expected OID"))
	}
	return *o, true, nil
}
func (s *Store) CompareAndSwapRef(ctx context.Context, k model.RepoKey, n model.RefName, expected *model.OID, newOID model.OID) error {
	if e := s.check(ctx); e != nil {
		return e
	}
	if e := model.ValidateRef(model.Ref{Repo: k, Name: n, OID: newOID}); e != nil {
		return invalid(e)
	}
	want, present, e := copyExpected(expected)
	if e != nil {
		return e
	}
	tx, e := s.pool.Begin(ctx)
	if e != nil {
		return dbErr(ctx, e)
	}
	defer rollback(tx)
	tag, e := tx.Exec(ctx, `SELECT 1 FROM `+s.q("repositories")+` WHERE repo_type=$1 AND namespace=$2 AND name=$3 FOR UPDATE`, args(k)...)
	if e != nil {
		return dbErr(ctx, e)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("repository: %w", catalog.ErrNotFound)
	}
	if e = s.ensureSnapshotExists(ctx, tx, k, newOID); e != nil {
		return e
	}
	current, e := s.loadRefOID(ctx, tx, k, n)
	found := e == nil
	if e != nil && !errors.Is(e, catalog.ErrNotFound) {
		return e
	}
	if found {
		if current == newOID {
			return dbErr(ctx, tx.Commit(ctx))
		}
		if !present || current != want {
			return fmt.Errorf("ref conflict: %w", catalog.ErrConflict)
		}
	} else if present {
		return fmt.Errorf("ref conflict: %w", catalog.ErrConflict)
	}
	updated, updateErr := tx.Exec(ctx, `INSERT INTO `+s.q("refs")+` VALUES($1,$2,$3,$4,$5) ON CONFLICT(repo_type,namespace,name,ref_name) DO UPDATE SET oid=excluded.oid`, k.Type, k.Namespace, k.Name, n, newOID[:])
	if e = expectOne(ctx, updated, updateErr, "ref update"); e != nil {
		return e
	}
	return dbErr(ctx, tx.Commit(ctx))
}
func (s *Store) PublishSnapshot(ctx context.Context, snap model.Snapshot, x catalog.RefExpectation) error {
	if e := s.check(ctx); e != nil {
		return e
	}
	snap, e := model.CanonicalSnapshot(snap)
	if e != nil {
		return invalid(e)
	}
	var want model.OID
	var present bool
	if x.UpdatesRef() {
		if _, e = model.ParseRefName(string(x.Name)); e != nil {
			return invalid(e)
		}
		want, present, e = copyExpected(x.OID)
		if e != nil {
			return e
		}
		if present && (snap.Parent == nil || *snap.Parent != want) {
			return invalid(errors.New("parent does not match expectation"))
		}
	}
	fp, e := model.FingerprintSnapshot(snap)
	if e != nil {
		return invalid(e)
	}
	tx, e := s.pool.Begin(ctx)
	if e != nil {
		return dbErr(ctx, e)
	}
	defer rollback(tx)
	tag, e := tx.Exec(ctx, `SELECT 1 FROM `+s.q("repositories")+` WHERE repo_type=$1 AND namespace=$2 AND name=$3 FOR UPDATE`, args(snap.Repo)...)
	if e != nil {
		return dbErr(ctx, e)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("repository: %w", catalog.ErrNotFound)
	}
	var retained []byte
	var retainedVersion int
	e = tx.QueryRow(ctx, `SELECT fingerprint,fingerprint_version FROM `+s.q("snapshots")+` WHERE repo_type=$1 AND namespace=$2 AND name=$3 AND oid=$4`, snap.Repo.Type, snap.Repo.Namespace, snap.Repo.Name, snap.OID[:]).Scan(&retained, &retainedVersion)
	exists := e == nil
	if e != nil && !errors.Is(e, pgx.ErrNoRows) {
		return rowErr(ctx, e)
	}
	if exists {
		if len(retained) != 32 || retainedVersion != model.SnapshotFingerprintVersion {
			return corrupt(errors.New("malformed retained snapshot fingerprint"))
		}
		retainedSnapshot, loadErr := s.loadSnapshot(ctx, tx, snap.Repo, snap.OID)
		if loadErr != nil {
			return loadErr
		}
		retainedFingerprint, fingerprintErr := model.FingerprintSnapshot(retainedSnapshot)
		if fingerprintErr != nil {
			return corrupt(fingerprintErr)
		}
		if retainedFingerprint != fp || string(retained) != string(fp[:]) {
			return fmt.Errorf("immutable snapshot: %w", catalog.ErrConflict)
		}
	}
	if exists && !x.UpdatesRef() {
		return dbErr(ctx, tx.Commit(ctx))
	}
	if x.UpdatesRef() {
		current, refErr := s.loadRefOID(ctx, tx, snap.Repo, x.Name)
		refExists := refErr == nil
		if refErr != nil && !errors.Is(refErr, catalog.ErrNotFound) {
			return refErr
		}
		if refExists {
			if exists && current == snap.OID {
				return dbErr(ctx, tx.Commit(ctx))
			}
			if !present || current != want {
				return fmt.Errorf("ref conflict: %w", catalog.ErrConflict)
			}
		} else if present {
			return fmt.Errorf("ref conflict: %w", catalog.ErrConflict)
		}
	}
	var count int64
	if e = tx.QueryRow(ctx, `SELECT count(*) FROM `+s.q("snapshots")+` WHERE repo_type=$1 AND namespace=$2 AND name=$3`, args(snap.Repo)...).Scan(&count); e != nil {
		return dbErr(ctx, e)
	}
	if snap.Parent == nil && count != 0 {
		return invalid(errors.New("only first snapshot may have no parent"))
	}
	if snap.Parent == nil {
		var refCount int64
		if e = tx.QueryRow(ctx, `SELECT count(*) FROM `+s.q("refs")+` WHERE repo_type=$1 AND namespace=$2 AND name=$3`, args(snap.Repo)...).Scan(&refCount); e != nil {
			return dbErr(ctx, e)
		}
		if refCount != 0 {
			return corrupt(errors.New("refs exist without snapshots"))
		}
	}
	if snap.Parent != nil {
		var pc int64
		if e = tx.QueryRow(ctx, `SELECT count(*) FROM `+s.q("snapshots")+` WHERE repo_type=$1 AND namespace=$2 AND name=$3 AND oid=$4`, snap.Repo.Type, snap.Repo.Namespace, snap.Repo.Name, snap.Parent[:]).Scan(&pc); e != nil {
			return dbErr(ctx, e)
		}
		if pc == 0 {
			return fmt.Errorf("parent: %w", catalog.ErrNotFound)
		}
	}
	if !exists {
		var parent any
		if snap.Parent != nil {
			parent = snap.Parent[:]
		}
		inserted, insertErr := tx.Exec(ctx, `INSERT INTO `+s.q("snapshots")+` VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`, snap.Repo.Type, snap.Repo.Namespace, snap.Repo.Name, snap.OID[:], parent, snap.CreatedAt.UnixNano(), snap.Author.Name, snap.Author.Email, snap.Message, len(snap.Files), fp[:], model.SnapshotFingerprintVersion)
		if e = expectOne(ctx, inserted, insertErr, "snapshot insert"); e != nil {
			return e
		}
		for _, f := range snap.Files {
			var sha, xh any
			if h, ok := f.Ref.SHA256(); ok {
				sha = h[:]
			}
			if h, ok := f.Ref.XetHash(); ok {
				xh = h[:]
			}
			inserted, insertErr = tx.Exec(ctx, `INSERT INTO `+s.q("files")+` VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)`, snap.Repo.Type, snap.Repo.Namespace, snap.Repo.Name, snap.OID[:], f.Path, f.Ref.Kind(), f.Ref.FileSize(), sha, xh)
			if e = expectOne(ctx, inserted, insertErr, "file insert"); e != nil {
				return e
			}
		}
	}
	if x.UpdatesRef() {
		updated, updateErr := tx.Exec(ctx, `INSERT INTO `+s.q("refs")+` VALUES($1,$2,$3,$4,$5) ON CONFLICT(repo_type,namespace,name,ref_name) DO UPDATE SET oid=excluded.oid`, snap.Repo.Type, snap.Repo.Namespace, snap.Repo.Name, x.Name, snap.OID[:])
		if e = expectOne(ctx, updated, updateErr, "target ref update"); e != nil {
			return e
		}
	}
	if x.UpdatesRef() && count == 0 {
		var updated pgconn.CommandTag
		var updateErr error
		updated, updateErr = tx.Exec(ctx, `INSERT INTO `+s.q("refs")+` VALUES($1,$2,$3,'main',$4) ON CONFLICT(repo_type,namespace,name,ref_name) DO UPDATE SET oid=excluded.oid`, snap.Repo.Type, snap.Repo.Namespace, snap.Repo.Name, snap.OID[:])
		if e = expectOne(ctx, updated, updateErr, "initial main ref update"); e != nil {
			return e
		}
	}
	return dbErr(ctx, tx.Commit(ctx))
}
func (s *Store) GetFile(ctx context.Context, k model.RepoKey, r model.Revision, p model.FilePath) (model.FileEntry, error) {
	if e := s.check(ctx); e != nil {
		return model.FileEntry{}, e
	}
	if e := validKey(ctx, k); e != nil {
		return model.FileEntry{}, e
	}
	path, e := model.ParseFilePath(string(p))
	if e != nil {
		return model.FileEntry{}, invalid(e)
	}
	oid, e := s.resolveOID(ctx, k, r)
	if e != nil {
		return model.FileEntry{}, e
	}
	file, e := scanFile(s.pool.QueryRow(ctx, `SELECT path,kind,size,sha256,xet_hash FROM `+s.q("files")+`
WHERE repo_type=$1 AND namespace=$2 AND name=$3 AND oid=$4 AND path=$5`, k.Type, k.Namespace, k.Name, oid[:], path))
	if e != nil {
		return model.FileEntry{}, rowErr(ctx, e)
	}
	return file, nil
}
func (s *Store) ListFiles(ctx context.Context, k model.RepoKey, r model.Revision, q catalog.FileQuery) (catalog.FilePage, error) {
	if e := s.check(ctx); e != nil {
		return catalog.FilePage{}, e
	}
	if e := validKey(ctx, k); e != nil {
		return catalog.FilePage{}, e
	}
	n, e := limit(q.Limit)
	if e != nil {
		return catalog.FilePage{}, e
	}
	prefix, e := model.ParseFilePrefix(string(q.Prefix))
	if e != nil {
		return catalog.FilePage{}, invalid(e)
	}
	oid, e := s.resolveOID(ctx, k, r)
	if e != nil {
		return catalog.FilePage{}, e
	}
	if e = s.ensureSnapshotExists(ctx, s.pool, k, oid); e != nil {
		return catalog.FilePage{}, e
	}
	after := ""
	if q.Cursor != "" {
		c, x := dec(q.Cursor)
		path, pathErr := model.ParseFilePath(c.Last)
		if x != nil || c.Op != "files" || c.Scope != scope(k) || c.Filter != string(prefix) ||
			c.Time != nil || pathErr != nil || (prefix != "" && !strings.HasPrefix(string(path), string(prefix))) {
			return catalog.FilePage{}, invalid(errors.New("mismatched cursor"))
		}
		o, oidErr := model.ParseOID(c.OID)
		if oidErr != nil {
			return catalog.FilePage{}, invalid(oidErr)
		}
		if o != oid {
			return catalog.FilePage{}, fmt.Errorf("revision changed: %w", catalog.ErrConflict)
		}
		after = string(path)
	}
	comparison := ">="
	start := string(prefix)
	if after != "" {
		comparison, start = ">", after
	}
	rows, e := s.pool.Query(ctx, `SELECT path,kind,size,sha256,xet_hash FROM `+s.q("files")+`
WHERE repo_type=$1 AND namespace=$2 AND name=$3 AND oid=$4 AND path COLLATE pg_catalog."C" `+comparison+` $5
ORDER BY path COLLATE pg_catalog."C" LIMIT $6`, k.Type, k.Namespace, k.Name, oid[:], start, n+1)
	if e != nil {
		return catalog.FilePage{}, dbErr(ctx, e)
	}
	defer rows.Close()
	p := catalog.FilePage{SnapshotOID: oid}
	for rows.Next() {
		file, scanErr := scanFile(rows)
		if scanErr != nil {
			return catalog.FilePage{}, corrupt(scanErr)
		}
		if prefix != "" && !strings.HasPrefix(string(file.Path), string(prefix)) {
			break
		}
		p.Items = append(p.Items, file)
	}
	if e = rows.Err(); e != nil {
		return catalog.FilePage{}, dbErr(ctx, e)
	}
	if len(p.Items) > n {
		p.Items = p.Items[:n]
		p.NextCursor = enc(cursor{Op: "files", Scope: scope(k), Filter: string(prefix), Last: string(p.Items[len(p.Items)-1].Path), OID: oid.String()})
	}
	return p, nil
}

func code(e error) string {
	var p *pgconn.PgError
	if errors.As(e, &p) {
		return p.Code
	}
	return ""
}

func expectOne(ctx context.Context, tag pgconn.CommandTag, e error, operation string) error {
	if e != nil {
		return dbErr(ctx, e)
	}
	if tag.RowsAffected() != 1 {
		return unavailable(fmt.Errorf("%s affected %d rows", operation, tag.RowsAffected()))
	}
	return nil
}

func rowErr(ctx context.Context, e error) error {
	if errors.Is(e, pgx.ErrNoRows) {
		return fmt.Errorf("row: %w", catalog.ErrNotFound)
	}
	if errors.Is(e, catalog.ErrCorrupt) {
		return e
	}
	var scanError pgx.ScanArgError
	if errors.As(e, &scanError) {
		return corrupt(e)
	}
	return dbErr(ctx, e)
}
func dbErr(ctx context.Context, e error) error {
	if e == nil {
		return nil
	}
	if ctx != nil && ctx.Err() != nil {
		return ctx.Err()
	}
	c := code(e)
	if c == "40001" || c == "40P01" || c == "55P03" || strings.HasPrefix(c, "57P") || strings.HasPrefix(c, "08") {
		return unavailable(e)
	}
	return unavailable(e)
}
func schemaErr(ctx context.Context, e error) error {
	if e == nil {
		return nil
	}
	if ctx != nil && ctx.Err() != nil {
		return ctx.Err()
	}
	var scanError pgx.ScanArgError
	if errors.As(e, &scanError) || code(e) == "42P01" || code(e) == "42P07" || code(e) == "42P10" ||
		code(e) == "42703" || code(e) == "42704" || code(e) == "42710" || code(e) == "42804" || code(e) == "42830" {
		return corrupt(e)
	}
	return dbErr(ctx, e)
}
func invalid(e error) error     { return fmt.Errorf("%w: %v", catalog.ErrInvalid, e) }
func corrupt(e error) error     { return fmt.Errorf("%w: %v", catalog.ErrCorrupt, e) }
func unavailable(e error) error { return fmt.Errorf("%w: %v", catalog.ErrUnavailable, e) }
