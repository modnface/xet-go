// Package postgresstore provides the PostgreSQL durable metadata backend.
package postgresstore

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const schemaVersion = 1

// Options selects the private PostgreSQL schema that owns all CAS index tables.
type Options struct{ Schema string }

// Store implements the durable CAS index, lifecycle, and iteration contracts.
// It stores metadata only; Xorb and shard payload bytes belong in a BlobStore.
type Store struct {
	pool   *pgxpool.Pool
	schema string
	owned  bool
	close  sync.Once
}

var identifier = regexp.MustCompile(`^[a-z_][a-z0-9_]*$`)

func options(o Options) (string, error) {
	if o.Schema == "" {
		o.Schema = "xet_cas"
	}
	if len(o.Schema) > 63 || !identifier.MatchString(o.Schema) {
		return "", fmt.Errorf("invalid PostgreSQL schema identifier %q", o.Schema)
	}
	return o.Schema, nil
}

// New initializes a store using pool. Close does not close a caller-owned pool.
func New(ctx context.Context, pool *pgxpool.Pool, o Options) (*Store, error) {
	if pool == nil {
		return nil, errors.New("postgresstore: nil pool")
	}
	schema, err := options(o)
	if err != nil {
		return nil, err
	}
	s := &Store{pool: pool, schema: schema}
	if err := s.migrate(ctx); err != nil {
		return nil, fmt.Errorf("postgresstore: initialize: %w", err)
	}
	return s, nil
}

// Open creates and owns a pool. Errors deliberately omit the connection string.
func Open(ctx context.Context, connectionString string, o Options) (*Store, error) {
	cfg, err := pgxpool.ParseConfig(connectionString)
	if err != nil {
		return nil, errors.New("postgresstore: invalid connection configuration")
	}
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, errors.New("postgresstore: open PostgreSQL pool")
	}
	s, err := New(ctx, pool, o)
	if err != nil {
		pool.Close()
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, errors.New("postgresstore: initialize PostgreSQL store")
	}
	s.owned = true
	return s, nil
}

// Close is idempotent and closes only pools created by Open.
func (s *Store) Close() error {
	if s != nil && s.owned {
		s.close.Do(s.pool.Close)
	}
	return nil
}
func (s *Store) t(name string) string { return s.schema + "." + name }

func (s *Store) migrate(ctx context.Context) error {
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return err
	}
	defer rollback(tx)
	// The lock key is stable and schema-specific; hashtextextended avoids client-side hash collisions.
	if _, err = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`, "xet-go/postgresstore/"+s.schema); err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, `CREATE SCHEMA IF NOT EXISTS `+s.schema); err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, `CREATE TABLE IF NOT EXISTS `+s.t("schema_version")+` (singleton boolean PRIMARY KEY DEFAULT true CHECK(singleton), version bigint NOT NULL CHECK(version >= 0))`); err != nil {
		return err
	}
	var version int64
	err = tx.QueryRow(ctx, `SELECT version FROM `+s.t("schema_version")+` WHERE singleton=true FOR UPDATE`).Scan(&version)
	if errors.Is(err, pgx.ErrNoRows) {
		_, err = tx.Exec(ctx, `INSERT INTO `+s.t("schema_version")+`(singleton,version) VALUES(true,0)`)
		version = 0
	}
	if err != nil {
		return err
	}
	if version > schemaVersion {
		return fmt.Errorf("schema version %d is newer than supported version %d", version, schemaVersion)
	}
	if version < 1 {
		for _, q := range s.schemaV1() {
			if _, err = tx.Exec(ctx, q); err != nil {
				return err
			}
		}
		if _, err = tx.Exec(ctx, `UPDATE `+s.t("schema_version")+` SET version=1 WHERE singleton=true`); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

func rollback(tx pgx.Tx) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = tx.Rollback(ctx)
}

func (s *Store) schemaV1() []string {
	return []string{
		`CREATE TABLE ` + s.t("xorbs") + ` (hash bytea PRIMARY KEY CHECK(octet_length(hash)=32), record bytea NOT NULL)`,
		`CREATE TABLE ` + s.t("shards") + ` (namespace text NOT NULL, hash bytea NOT NULL CHECK(octet_length(hash)=32), record bytea NOT NULL, PRIMARY KEY(namespace,hash))`,
		`CREATE TABLE ` + s.t("files") + ` (namespace text NOT NULL, hash bytea NOT NULL CHECK(octet_length(hash)=32), record bytea NOT NULL, PRIMARY KEY(namespace,hash))`,
		`CREATE TABLE ` + s.t("dedup") + ` (namespace text NOT NULL, chunk_hash bytea NOT NULL CHECK(octet_length(chunk_hash)=32), record bytea NOT NULL, PRIMARY KEY(namespace,chunk_hash))`,
		`CREATE TABLE ` + s.t("sha256_associations") + ` (namespace text NOT NULL, sum bytea NOT NULL CHECK(octet_length(sum)=32), size bigint NOT NULL CHECK(size>=0), file_hash bytea NOT NULL CHECK(octet_length(file_hash)=32), PRIMARY KEY(namespace,sum,size))`,
		`CREATE TABLE ` + s.t("blob_stages") + ` (namespace text NOT NULL, id bytea NOT NULL CHECK(octet_length(id)=16), blob_kind text NOT NULL CHECK(blob_kind IN ('xorb','shard')), blob_hash bytea NOT NULL CHECK(octet_length(blob_hash)=32), created_at bigint NOT NULL, expires_at bigint NOT NULL CHECK(expires_at>created_at), PRIMARY KEY(namespace,id))`,
		`CREATE INDEX blob_stages_expiration ON ` + s.t("blob_stages") + ` (expires_at,namespace,id)`,
		`CREATE TABLE ` + s.t("file_leases") + ` (namespace text NOT NULL, id bytea NOT NULL CHECK(octet_length(id)=16), file_hash bytea NOT NULL CHECK(octet_length(file_hash)=32), created_at bigint NOT NULL, expires_at bigint NOT NULL CHECK(expires_at>created_at), PRIMARY KEY(namespace,id))`,
		`CREATE INDEX file_leases_expiration ON ` + s.t("file_leases") + ` (expires_at,namespace,id)`,
	}
}
