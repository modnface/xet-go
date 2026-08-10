package server

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"time"

	"github.com/jmwoliver/xet-go/xethash"
	_ "modernc.org/sqlite"
)

const sqliteSchemaVersion = 3

// SQLiteIndexStore is a durable single-node IndexStore. Payload bytes remain
// in a BlobStore; SQLite contains only validated layouts, recipes, and scoped
// logical associations.
type SQLiteIndexStore struct {
	db *sql.DB

	// testHook injects failures at transaction boundaries in package tests.
	testHook func(stage string) error
}

// OpenSQLiteIndexStore opens or creates a versioned SQLite index at path.
// Platforms without strict directory durability return
// ErrDurabilityUnsupported without modifying path.
func OpenSQLiteIndexStore(path string) (*SQLiteIndexStore, error) {
	if path == "" {
		return nil, errors.New("xet CAS server: empty SQLite index path")
	}
	if err := checkFilesystemDurabilitySupported(); err != nil {
		return nil, err
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("xet CAS server: SQLite index path: %w", err)
	}
	if err := ensureSQLitePath(absolute); err != nil {
		return nil, err
	}
	query := make(url.Values)
	query.Set("_txlock", "immediate")
	query.Add("_pragma", "busy_timeout(5000)")
	query.Add("_pragma", "foreign_keys(ON)")
	query.Add("_pragma", "synchronous(FULL)")
	dsn := (&url.URL{Scheme: "file", Path: filepath.ToSlash(absolute), RawQuery: query.Encode()}).String()
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("xet CAS server: open SQLite index: %w", err)
	}
	db.SetMaxOpenConns(4)
	db.SetMaxIdleConns(4)
	store := &SQLiteIndexStore{db: db}
	if err := store.initialize(context.Background()); err != nil {
		_ = db.Close()
		return nil, err
	}
	if err := syncDirectory(filepath.Dir(absolute)); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("xet CAS server: sync SQLite index directory: %w", err)
	}
	return store, nil
}

func ensureSQLitePath(path string) error {
	parent := filepath.Dir(path)
	if err := ensurePrivateDirectory(parent, syncDirectory); err != nil {
		return fmt.Errorf("xet CAS server: create SQLite directory: %w", err)
	}
	parentInfo, err := os.Lstat(parent)
	if err != nil {
		return fmt.Errorf("xet CAS server: inspect SQLite directory: %w", err)
	}
	if parentInfo.Mode()&os.ModeSymlink != 0 || !parentInfo.IsDir() {
		return errors.New("xet CAS server: SQLite parent is not a real directory")
	}
	if err := os.Chmod(parent, 0o700); err != nil {
		return fmt.Errorf("xet CAS server: protect SQLite directory: %w", err)
	}
	for {
		info, err := os.Lstat(path)
		if err == nil {
			if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
				return errors.New("xet CAS server: SQLite index is not a regular file")
			}
			if err := os.Chmod(path, 0o600); err != nil {
				return fmt.Errorf("xet CAS server: protect SQLite index: %w", err)
			}
			return nil
		}
		if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("xet CAS server: inspect SQLite index: %w", err)
		}
		file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
		if errors.Is(err, os.ErrExist) {
			continue
		}
		if err != nil {
			return fmt.Errorf("xet CAS server: create SQLite index: %w", err)
		}
		if err := file.Sync(); err != nil {
			_ = file.Close()
			return fmt.Errorf("xet CAS server: sync new SQLite index: %w", err)
		}
		if err := file.Close(); err != nil {
			return fmt.Errorf("xet CAS server: close new SQLite index: %w", err)
		}
		if err := syncDirectory(parent); err != nil {
			return fmt.Errorf("xet CAS server: publish new SQLite index: %w", err)
		}
		return nil
	}
}

func (s *SQLiteIndexStore) initialize(ctx context.Context) error {
	var journalMode string
	if err := s.db.QueryRowContext(ctx, "PRAGMA journal_mode=WAL").Scan(&journalMode); err != nil {
		return fmt.Errorf("xet CAS server: configure SQLite WAL: %w", err)
	}
	if journalMode != "wal" {
		return fmt.Errorf("xet CAS server: SQLite refused WAL journal mode %q", journalMode)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("xet CAS server: begin SQLite migration: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck // Commit below determines the result.
	var version int
	if err := tx.QueryRowContext(ctx, "PRAGMA user_version").Scan(&version); err != nil {
		return fmt.Errorf("xet CAS server: read SQLite schema version: %w", err)
	}
	if version > sqliteSchemaVersion {
		return fmt.Errorf("xet CAS server: SQLite schema version %d is newer than supported version %d", version, sqliteSchemaVersion)
	}
	if version == sqliteSchemaVersion {
		if err := tx.Commit(); err != nil {
			return fmt.Errorf("xet CAS server: finish SQLite schema check: %w", err)
		}
		return nil
	}
	if version < 1 {
		if _, err := tx.ExecContext(ctx, sqliteSchemaV1); err != nil {
			return fmt.Errorf("xet CAS server: migrate SQLite schema to version 1: %w", err)
		}
		version = 1
	}
	if version < 2 {
		if _, err := tx.ExecContext(ctx, sqliteSchemaV2); err != nil {
			return fmt.Errorf("xet CAS server: migrate SQLite schema to version 2: %w", err)
		}
	}
	if version < 3 {
		if _, err := tx.ExecContext(ctx, sqliteSchemaV3); err != nil {
			return fmt.Errorf("xet CAS server: migrate SQLite schema to version 3: %w", err)
		}
	}
	if _, err := tx.ExecContext(ctx, "PRAGMA user_version = 3"); err != nil {
		return fmt.Errorf("xet CAS server: record SQLite schema version: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("xet CAS server: commit SQLite migration: %w", err)
	}
	return nil
}

const sqliteSchemaV1 = `
CREATE TABLE xorbs (
    hash BLOB PRIMARY KEY NOT NULL CHECK(length(hash) = 32),
    record BLOB NOT NULL
) WITHOUT ROWID;
CREATE TABLE files (
    namespace TEXT NOT NULL,
    hash BLOB NOT NULL CHECK(length(hash) = 32),
    record BLOB NOT NULL,
    PRIMARY KEY(namespace, hash)
) WITHOUT ROWID;
CREATE TABLE dedup (
    namespace TEXT NOT NULL,
    chunk_hash BLOB NOT NULL CHECK(length(chunk_hash) = 32),
    record BLOB NOT NULL,
    PRIMARY KEY(namespace, chunk_hash)
) WITHOUT ROWID;
CREATE TABLE sha256_associations (
    namespace TEXT NOT NULL,
    sum BLOB NOT NULL CHECK(length(sum) = 32),
    size INTEGER NOT NULL CHECK(size >= 0),
    file_hash BLOB NOT NULL CHECK(length(file_hash) = 32),
    PRIMARY KEY(namespace, sum, size)
) WITHOUT ROWID;
`

const sqliteSchemaV2 = `
ALTER TABLE xorbs RENAME TO xorbs_v1;
CREATE TABLE xorbs (
    hash BLOB PRIMARY KEY NOT NULL CHECK(typeof(hash) = 'blob' AND length(hash) = 32),
    record BLOB NOT NULL CHECK(typeof(record) = 'blob')
) WITHOUT ROWID;
INSERT INTO xorbs(hash, record) SELECT hash, record FROM xorbs_v1;
DROP TABLE xorbs_v1;

ALTER TABLE files RENAME TO files_v1;
CREATE TABLE files (
    namespace TEXT NOT NULL CHECK(typeof(namespace) = 'text'),
    hash BLOB NOT NULL CHECK(typeof(hash) = 'blob' AND length(hash) = 32),
    record BLOB NOT NULL CHECK(typeof(record) = 'blob'),
    PRIMARY KEY(namespace, hash)
) WITHOUT ROWID;
INSERT INTO files(namespace, hash, record) SELECT namespace, hash, record FROM files_v1;
DROP TABLE files_v1;

ALTER TABLE dedup RENAME TO dedup_v1;
CREATE TABLE dedup (
    namespace TEXT NOT NULL CHECK(typeof(namespace) = 'text'),
    chunk_hash BLOB NOT NULL CHECK(typeof(chunk_hash) = 'blob' AND length(chunk_hash) = 32),
    record BLOB NOT NULL CHECK(typeof(record) = 'blob'),
    PRIMARY KEY(namespace, chunk_hash)
) WITHOUT ROWID;
INSERT INTO dedup(namespace, chunk_hash, record) SELECT namespace, chunk_hash, record FROM dedup_v1;
DROP TABLE dedup_v1;

ALTER TABLE sha256_associations RENAME TO sha256_associations_v1;
CREATE TABLE sha256_associations (
    namespace TEXT NOT NULL CHECK(typeof(namespace) = 'text'),
    sum BLOB NOT NULL CHECK(typeof(sum) = 'blob' AND length(sum) = 32),
    size INTEGER NOT NULL CHECK(typeof(size) = 'integer' AND size >= 0),
    file_hash BLOB NOT NULL CHECK(typeof(file_hash) = 'blob' AND length(file_hash) = 32),
    PRIMARY KEY(namespace, sum, size)
) WITHOUT ROWID;
INSERT INTO sha256_associations(namespace, sum, size, file_hash)
SELECT namespace, sum, size, file_hash FROM sha256_associations_v1;
DROP TABLE sha256_associations_v1;
`

const sqliteSchemaV3 = `
CREATE TABLE blob_stages (
    namespace TEXT NOT NULL CHECK(typeof(namespace) = 'text'),
    id BLOB NOT NULL CHECK(typeof(id) = 'blob' AND length(id) = 16),
    blob_kind TEXT NOT NULL CHECK(typeof(blob_kind) = 'text' AND blob_kind IN ('xorb', 'shard')),
    blob_hash BLOB NOT NULL CHECK(typeof(blob_hash) = 'blob' AND length(blob_hash) = 32),
    created_at INTEGER NOT NULL CHECK(typeof(created_at) = 'integer'),
    expires_at INTEGER NOT NULL CHECK(typeof(expires_at) = 'integer' AND expires_at > created_at),
    PRIMARY KEY(namespace, id)
) WITHOUT ROWID;
CREATE INDEX blob_stages_expiration ON blob_stages(expires_at, namespace, id);

CREATE TABLE file_leases (
    namespace TEXT NOT NULL CHECK(typeof(namespace) = 'text'),
    id BLOB NOT NULL CHECK(typeof(id) = 'blob' AND length(id) = 16),
    file_hash BLOB NOT NULL CHECK(typeof(file_hash) = 'blob' AND length(file_hash) = 32),
    created_at INTEGER NOT NULL CHECK(typeof(created_at) = 'integer'),
    expires_at INTEGER NOT NULL CHECK(typeof(expires_at) = 'integer' AND expires_at > created_at),
    PRIMARY KEY(namespace, id)
) WITHOUT ROWID;
CREATE INDEX file_leases_expiration ON file_leases(expires_at, namespace, id);
`

func (s *SQLiteIndexStore) Close() error { return s.db.Close() }

func encodeIndexRecord(value any) ([]byte, error) {
	data, err := json.Marshal(value)
	if err != nil {
		return nil, fmt.Errorf("xet CAS server: encode SQLite index record: %w", err)
	}
	return data, nil
}

func decodeIndexRecord(data []byte, destination any) error {
	if err := json.Unmarshal(data, destination); err != nil {
		return fmt.Errorf("%w: decode SQLite index record: %v", ErrCorrupt, err)
	}
	return nil
}

func hashBytes(hash xethash.Hash) []byte { return append([]byte(nil), hash[:]...) }

func uint64ToSQLite(value uint64) (int64, error) {
	if value > math.MaxInt64 {
		return 0, fmt.Errorf("%w: value %d exceeds SQLite integer range", ErrInvalid, value)
	}
	return int64(value), nil
}

func (s *SQLiteIndexStore) GetXorb(ctx context.Context, hash xethash.Hash) (XorbRecord, bool, error) {
	var data []byte
	err := s.db.QueryRowContext(ctx, "SELECT record FROM xorbs WHERE hash = ?", hashBytes(hash)).Scan(&data)
	if errors.Is(err, sql.ErrNoRows) {
		return XorbRecord{}, false, nil
	}
	if err != nil {
		return XorbRecord{}, false, fmt.Errorf("xet CAS server: query SQLite xorb: %w", err)
	}
	var value XorbRecord
	if err := decodeIndexRecord(data, &value); err != nil {
		return XorbRecord{}, false, err
	}
	if value.Layout.Hash != hash || value.Blob.Kind != BlobXorb || value.Blob.Hash != hash {
		return XorbRecord{}, false, fmt.Errorf("%w: SQLite xorb identity mismatch", ErrCorrupt)
	}
	return value, true, nil
}

func (s *SQLiteIndexStore) PutXorb(ctx context.Context, value XorbRecord) error {
	data, err := encodeIndexRecord(value)
	if err != nil {
		return err
	}
	result, err := s.db.ExecContext(ctx,
		"INSERT INTO xorbs(hash, record) VALUES(?, ?) ON CONFLICT(hash) DO NOTHING",
		hashBytes(value.Layout.Hash), data)
	if err != nil {
		return fmt.Errorf("xet CAS server: insert SQLite xorb: %w", err)
	}
	inserted, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("xet CAS server: inspect SQLite xorb insert: %w", err)
	}
	if inserted != 0 {
		return nil
	}
	existing, found, err := s.GetXorb(ctx, value.Layout.Hash)
	if err != nil {
		return err
	}
	if !found || !reflect.DeepEqual(existing, value) {
		return ErrConflict
	}
	return nil
}

func (s *SQLiteIndexStore) GetFile(ctx context.Context, namespace string, hash xethash.Hash) (FileRecord, bool, error) {
	var data []byte
	err := s.db.QueryRowContext(ctx,
		"SELECT record FROM files WHERE namespace = ? AND hash = ?", namespace, hashBytes(hash)).Scan(&data)
	if errors.Is(err, sql.ErrNoRows) {
		return FileRecord{}, false, nil
	}
	if err != nil {
		return FileRecord{}, false, fmt.Errorf("xet CAS server: query SQLite file: %w", err)
	}
	var value FileRecord
	if err := decodeIndexRecord(data, &value); err != nil {
		return FileRecord{}, false, err
	}
	if value.File.File.Hash != hash {
		return FileRecord{}, false, fmt.Errorf("%w: SQLite file identity mismatch", ErrCorrupt)
	}
	return value, true, nil
}

func (s *SQLiteIndexStore) PutFile(ctx context.Context, namespace string, value FileRecord) error {
	data, err := encodeIndexRecord(value)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx,
		"INSERT INTO files(namespace, hash, record) VALUES(?, ?, ?) ON CONFLICT(namespace, hash) DO NOTHING",
		namespace, hashBytes(value.File.File.Hash), data)
	if err != nil {
		return fmt.Errorf("xet CAS server: insert SQLite file: %w", err)
	}
	return nil
}

func (s *SQLiteIndexStore) GetDedup(ctx context.Context, namespace string, hash xethash.Hash) (DedupRecord, bool, error) {
	var data []byte
	err := s.db.QueryRowContext(ctx,
		"SELECT record FROM dedup WHERE namespace = ? AND chunk_hash = ?", namespace, hashBytes(hash)).Scan(&data)
	if errors.Is(err, sql.ErrNoRows) {
		return DedupRecord{}, false, nil
	}
	if err != nil {
		return DedupRecord{}, false, fmt.Errorf("xet CAS server: query SQLite dedup: %w", err)
	}
	var value DedupRecord
	if err := decodeIndexRecord(data, &value); err != nil {
		return DedupRecord{}, false, err
	}
	return value, true, nil
}

func (s *SQLiteIndexStore) PutDedup(
	ctx context.Context,
	namespace string,
	hash xethash.Hash,
	value DedupRecord,
) error {
	data, err := encodeIndexRecord(value)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx,
		"INSERT INTO dedup(namespace, chunk_hash, record) VALUES(?, ?, ?) ON CONFLICT(namespace, chunk_hash) DO NOTHING",
		namespace, hashBytes(hash), data)
	if err != nil {
		return fmt.Errorf("xet CAS server: insert SQLite dedup: %w", err)
	}
	return nil
}

func (s *SQLiteIndexStore) ResolveSHA256(
	ctx context.Context,
	namespace string,
	sum [32]byte,
	size uint64,
) (xethash.Hash, bool, error) {
	databaseSize, err := uint64ToSQLite(size)
	if err != nil {
		return xethash.Hash{}, false, err
	}
	var data []byte
	err = s.db.QueryRowContext(ctx,
		"SELECT file_hash FROM sha256_associations WHERE namespace = ? AND sum = ? AND size = ?",
		namespace, sum[:], databaseSize).Scan(&data)
	if errors.Is(err, sql.ErrNoRows) {
		return xethash.Hash{}, false, nil
	}
	if err != nil {
		return xethash.Hash{}, false, fmt.Errorf("xet CAS server: query SQLite SHA-256: %w", err)
	}
	if len(data) != len(xethash.Hash{}) {
		return xethash.Hash{}, false, fmt.Errorf("%w: invalid SQLite file hash length", ErrCorrupt)
	}
	var hash xethash.Hash
	copy(hash[:], data)
	return hash, true, nil
}

func (s *SQLiteIndexStore) PutSHA256(
	ctx context.Context,
	namespace string,
	sum [32]byte,
	size uint64,
	hash xethash.Hash,
) error {
	databaseSize, err := uint64ToSQLite(size)
	if err != nil {
		return err
	}
	result, err := s.db.ExecContext(ctx, `
INSERT INTO sha256_associations(namespace, sum, size, file_hash) VALUES(?, ?, ?, ?)
ON CONFLICT(namespace, sum, size) DO NOTHING`, namespace, sum[:], databaseSize, hashBytes(hash))
	if err != nil {
		return fmt.Errorf("xet CAS server: insert SQLite SHA-256: %w", err)
	}
	inserted, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("xet CAS server: inspect SQLite SHA-256 insert: %w", err)
	}
	if inserted != 0 {
		return nil
	}
	existing, found, err := s.ResolveSHA256(ctx, namespace, sum, size)
	if err != nil {
		return err
	}
	if !found || existing != hash {
		return ErrConflict
	}
	return nil
}

func (s *SQLiteIndexStore) PublishShard(ctx context.Context, publication ShardPublication) error {
	// Detect contradictory immutable records before opening a write transaction.
	pending := make(map[shaKey]xethash.Hash, len(publication.SHA256))
	for _, association := range publication.SHA256 {
		key := shaKey{namespace: publication.Namespace, sum: association.Sum, size: association.Size}
		if previous, ok := pending[key]; ok && previous != association.File {
			return ErrConflict
		}
		pending[key] = association.File
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("xet CAS server: begin SQLite shard publication: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck // Commit below determines the result.
	for _, association := range publication.Dedup {
		data, err := encodeIndexRecord(association.Value)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx,
			"INSERT INTO dedup(namespace, chunk_hash, record) VALUES(?, ?, ?) ON CONFLICT(namespace, chunk_hash) DO NOTHING",
			publication.Namespace, hashBytes(association.Chunk), data); err != nil {
			return fmt.Errorf("xet CAS server: publish SQLite dedup: %w", err)
		}
	}
	if err := s.runTestHook("after-dedup"); err != nil {
		return err
	}
	for _, association := range publication.SHA256 {
		databaseSize, err := uint64ToSQLite(association.Size)
		if err != nil {
			return err
		}
		result, err := tx.ExecContext(ctx, `
INSERT INTO sha256_associations(namespace, sum, size, file_hash) VALUES(?, ?, ?, ?)
ON CONFLICT(namespace, sum, size) DO NOTHING`, publication.Namespace, association.Sum[:], databaseSize, hashBytes(association.File))
		if err != nil {
			return fmt.Errorf("xet CAS server: publish SQLite SHA-256: %w", err)
		}
		inserted, err := result.RowsAffected()
		if err != nil {
			return fmt.Errorf("xet CAS server: inspect SQLite SHA-256 publication: %w", err)
		}
		if inserted == 0 {
			var existing []byte
			if err := tx.QueryRowContext(ctx, `
SELECT file_hash FROM sha256_associations WHERE namespace = ? AND sum = ? AND size = ?`,
				publication.Namespace, association.Sum[:], databaseSize).Scan(&existing); err != nil {
				return fmt.Errorf("xet CAS server: verify SQLite SHA-256 publication: %w", err)
			}
			if !reflect.DeepEqual(existing, hashBytes(association.File)) {
				return ErrConflict
			}
		}
	}
	if err := s.runTestHook("after-sha256"); err != nil {
		return err
	}
	for _, record := range publication.Files {
		data, err := encodeIndexRecord(record)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx,
			"INSERT INTO files(namespace, hash, record) VALUES(?, ?, ?) ON CONFLICT(namespace, hash) DO NOTHING",
			publication.Namespace, hashBytes(record.File.File.Hash), data); err != nil {
			return fmt.Errorf("xet CAS server: publish SQLite file: %w", err)
		}
	}
	if err := s.runTestHook("after-files"); err != nil {
		return err
	}
	if err := s.runTestHook("before-commit"); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("xet CAS server: commit SQLite shard publication: %w", err)
	}
	return nil
}

func (s *SQLiteIndexStore) PutBlobStage(ctx context.Context, stage BlobStage) error {
	stage, err := normalizeBlobStage(stage)
	if err != nil {
		return err
	}
	createdAt, err := protectionTimeToSQLite(stage.CreatedAt)
	if err != nil {
		return err
	}
	expiresAt, err := protectionTimeToSQLite(stage.ExpiresAt)
	if err != nil {
		return err
	}
	row := s.db.QueryRowContext(ctx, `
INSERT INTO blob_stages(namespace, id, blob_kind, blob_hash, created_at, expires_at)
VALUES(?, ?, ?, ?, ?, ?)
ON CONFLICT(namespace, id) DO UPDATE SET id = excluded.id
WHERE blob_kind = excluded.blob_kind AND blob_hash = excluded.blob_hash
  AND created_at = excluded.created_at AND expires_at = excluded.expires_at
RETURNING namespace, id, blob_kind, blob_hash, created_at, expires_at,
  typeof(namespace), typeof(id), typeof(blob_kind), typeof(blob_hash), typeof(created_at), typeof(expires_at)`,
		stage.Namespace, stage.ID[:], string(stage.Blob.Kind), hashBytes(stage.Blob.Hash), createdAt, expiresAt)
	stored, err := scanSQLiteBlobStage(row)
	if errors.Is(err, sql.ErrNoRows) {
		if _, lookupErr := s.sqliteBlobStage(ctx, stage.Namespace, stage.ID); lookupErr != nil {
			return fmt.Errorf("xet CAS server: inspect conflicting SQLite blob stage: %w", lookupErr)
		}
		return ErrConflict
	}
	if err != nil {
		return fmt.Errorf("xet CAS server: put SQLite blob stage: %w", err)
	}
	if stored != stage {
		return ErrConflict
	}
	return nil
}

func (s *SQLiteIndexStore) DeleteBlobStage(ctx context.Context, namespace string, id ProtectionID) error {
	if _, err := s.db.ExecContext(ctx, "DELETE FROM blob_stages WHERE namespace = ? AND id = ?", namespace, id[:]); err != nil {
		return fmt.Errorf("xet CAS server: delete SQLite blob stage: %w", err)
	}
	return nil
}

func (s *SQLiteIndexStore) RenewBlobStage(
	ctx context.Context,
	namespace string,
	id ProtectionID,
	expiresAt time.Time,
) error {
	expiresAt, err := normalizeProtectionTime(expiresAt)
	if err != nil {
		return err
	}
	databaseExpiration, err := protectionTimeToSQLite(expiresAt)
	if err != nil {
		return err
	}
	row := s.db.QueryRowContext(ctx, `
UPDATE blob_stages SET expires_at = max(expires_at, ?) WHERE namespace = ? AND id = ?
RETURNING namespace, id, blob_kind, blob_hash, created_at, expires_at,
  typeof(namespace), typeof(id), typeof(blob_kind), typeof(blob_hash), typeof(created_at), typeof(expires_at)`,
		databaseExpiration, namespace, id[:])
	stage, err := scanSQLiteBlobStage(row)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return fmt.Errorf("xet CAS server: renew SQLite blob stage: %w", err)
	}
	if stage.Namespace != namespace || stage.ID != id || stage.ExpiresAt.Before(expiresAt) {
		return fmt.Errorf("%w: SQLite blob stage renewal identity mismatch", ErrCorrupt)
	}
	return nil
}

func (s *SQLiteIndexStore) ListBlobStages(
	ctx context.Context,
	namespace *string,
	request PageRequest,
) (BlobStagePage, error) {
	cursorKind := cursorBlobStageAll
	if namespace != nil {
		cursorKind = cursorBlobStageScoped
	}
	limit, cursorNamespace, cursorID, hasCursor, err := scopedProtectionPage(request, namespace, cursorKind)
	if err != nil {
		return BlobStagePage{}, err
	}
	const base = `SELECT namespace, id, blob_kind, blob_hash, created_at, expires_at,
typeof(namespace), typeof(id), typeof(blob_kind), typeof(blob_hash), typeof(created_at), typeof(expires_at)
FROM blob_stages`
	query, arguments := scopedProtectionQuery(base, namespace, cursorNamespace, cursorID, hasCursor, limit)
	rows, err := s.db.QueryContext(ctx, query, arguments...)
	if err != nil {
		return BlobStagePage{}, fmt.Errorf("xet CAS server: list SQLite blob stages: %w", err)
	}
	defer rows.Close() //nolint:errcheck // rows.Err and the explicit close below determine the result.
	page := BlobStagePage{Items: make([]BlobStage, 0, limit)}
	for rows.Next() {
		stage, err := scanSQLiteBlobStage(rows)
		if err != nil {
			return BlobStagePage{}, fmt.Errorf("xet CAS server: scan SQLite blob stage: %w", err)
		}
		page.Items = append(page.Items, stage)
	}
	if err := finishSQLiteRows(rows); err != nil {
		return BlobStagePage{}, fmt.Errorf("xet CAS server: finish SQLite blob stage page: %w", err)
	}
	if len(page.Items) > limit {
		page.Items = page.Items[:limit]
		last := page.Items[len(page.Items)-1]
		page.NextCursor = encodeScopedCursor(cursorKind, last.Namespace, last.ID[:])
	}
	return page, nil
}

func (s *SQLiteIndexStore) PutFileLease(ctx context.Context, lease FileLease) error {
	lease, err := normalizeFileLease(lease)
	if err != nil {
		return err
	}
	createdAt, err := protectionTimeToSQLite(lease.CreatedAt)
	if err != nil {
		return err
	}
	expiresAt, err := protectionTimeToSQLite(lease.ExpiresAt)
	if err != nil {
		return err
	}
	row := s.db.QueryRowContext(ctx, `
INSERT INTO file_leases(namespace, id, file_hash, created_at, expires_at)
VALUES(?, ?, ?, ?, ?)
ON CONFLICT(namespace, id) DO UPDATE SET expires_at = max(file_leases.expires_at, excluded.expires_at)
WHERE file_hash = excluded.file_hash AND created_at = excluded.created_at
RETURNING namespace, id, file_hash, created_at, expires_at,
  typeof(namespace), typeof(id), typeof(file_hash), typeof(created_at), typeof(expires_at)`,
		lease.Namespace, lease.ID[:], hashBytes(lease.File), createdAt, expiresAt)
	stored, err := scanSQLiteFileLease(row)
	if errors.Is(err, sql.ErrNoRows) {
		if _, lookupErr := s.sqliteFileLease(ctx, lease.Namespace, lease.ID); lookupErr != nil {
			return fmt.Errorf("xet CAS server: inspect conflicting SQLite file lease: %w", lookupErr)
		}
		return ErrConflict
	}
	if err != nil {
		return fmt.Errorf("xet CAS server: put SQLite file lease: %w", err)
	}
	if stored.Namespace != lease.Namespace || stored.ID != lease.ID || stored.File != lease.File ||
		!stored.CreatedAt.Equal(lease.CreatedAt) || stored.ExpiresAt.Before(lease.ExpiresAt) {
		return ErrConflict
	}
	return nil
}

func (s *SQLiteIndexStore) RenewFileLease(
	ctx context.Context,
	namespace string,
	id ProtectionID,
	expiresAt time.Time,
) error {
	expiresAt, err := normalizeProtectionTime(expiresAt)
	if err != nil {
		return err
	}
	databaseExpiration, err := protectionTimeToSQLite(expiresAt)
	if err != nil {
		return err
	}
	row := s.db.QueryRowContext(ctx, `
UPDATE file_leases SET expires_at = max(expires_at, ?) WHERE namespace = ? AND id = ?
RETURNING namespace, id, file_hash, created_at, expires_at,
  typeof(namespace), typeof(id), typeof(file_hash), typeof(created_at), typeof(expires_at)`,
		databaseExpiration, namespace, id[:])
	lease, err := scanSQLiteFileLease(row)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return fmt.Errorf("xet CAS server: renew SQLite file lease: %w", err)
	}
	if lease.Namespace != namespace || lease.ID != id || lease.ExpiresAt.Before(expiresAt) {
		return fmt.Errorf("%w: SQLite file lease renewal identity mismatch", ErrCorrupt)
	}
	return nil
}

func (s *SQLiteIndexStore) DeleteFileLease(ctx context.Context, namespace string, id ProtectionID) error {
	if _, err := s.db.ExecContext(ctx, "DELETE FROM file_leases WHERE namespace = ? AND id = ?", namespace, id[:]); err != nil {
		return fmt.Errorf("xet CAS server: delete SQLite file lease: %w", err)
	}
	return nil
}

func (s *SQLiteIndexStore) ListFileLeases(
	ctx context.Context,
	namespace *string,
	request PageRequest,
) (FileLeasePage, error) {
	cursorKind := cursorFileLeaseAll
	if namespace != nil {
		cursorKind = cursorFileLeaseScoped
	}
	limit, cursorNamespace, cursorID, hasCursor, err := scopedProtectionPage(request, namespace, cursorKind)
	if err != nil {
		return FileLeasePage{}, err
	}
	const base = `SELECT namespace, id, file_hash, created_at, expires_at,
typeof(namespace), typeof(id), typeof(file_hash), typeof(created_at), typeof(expires_at)
FROM file_leases`
	query, arguments := scopedProtectionQuery(base, namespace, cursorNamespace, cursorID, hasCursor, limit)
	rows, err := s.db.QueryContext(ctx, query, arguments...)
	if err != nil {
		return FileLeasePage{}, fmt.Errorf("xet CAS server: list SQLite file leases: %w", err)
	}
	defer rows.Close() //nolint:errcheck // rows.Err and the explicit close below determine the result.
	page := FileLeasePage{Items: make([]FileLease, 0, limit)}
	for rows.Next() {
		lease, err := scanSQLiteFileLease(rows)
		if err != nil {
			return FileLeasePage{}, fmt.Errorf("xet CAS server: scan SQLite file lease: %w", err)
		}
		page.Items = append(page.Items, lease)
	}
	if err := finishSQLiteRows(rows); err != nil {
		return FileLeasePage{}, fmt.Errorf("xet CAS server: finish SQLite file lease page: %w", err)
	}
	if len(page.Items) > limit {
		page.Items = page.Items[:limit]
		last := page.Items[len(page.Items)-1]
		page.NextCursor = encodeScopedCursor(cursorKind, last.Namespace, last.ID[:])
	}
	return page, nil
}

func (s *SQLiteIndexStore) ListXorbs(ctx context.Context, request PageRequest) (XorbRecordPage, error) {
	limit, err := pageLimit(request)
	if err != nil {
		return XorbRecordPage{}, err
	}
	query := "SELECT hash, record, typeof(hash), typeof(record) FROM xorbs ORDER BY hash LIMIT ?"
	arguments := []any{limit + 1}
	if request.Cursor != "" {
		cursor, err := decodeHashCursor(request.Cursor, cursorIndexXorb)
		if err != nil {
			return XorbRecordPage{}, err
		}
		query = "SELECT hash, record, typeof(hash), typeof(record) FROM xorbs WHERE hash > ? ORDER BY hash LIMIT ?"
		arguments = []any{hashBytes(cursor), limit + 1}
	}
	rows, err := s.db.QueryContext(ctx, query, arguments...)
	if err != nil {
		return XorbRecordPage{}, fmt.Errorf("xet CAS server: list SQLite xorbs: %w", err)
	}
	defer rows.Close() //nolint:errcheck // rows.Err and the explicit close below determine the result.
	page := XorbRecordPage{Items: make([]XorbRecord, 0, limit)}
	for rows.Next() {
		var hashData, recordData []byte
		var hashType, recordType string
		if err := rows.Scan(&hashData, &recordData, &hashType, &recordType); err != nil {
			return XorbRecordPage{}, fmt.Errorf("xet CAS server: scan SQLite xorb page: %w", err)
		}
		if hashType != "blob" || recordType != "blob" {
			return XorbRecordPage{}, fmt.Errorf("%w: malformed SQLite xorb storage class", ErrCorrupt)
		}
		hash, err := sqliteHash(hashData)
		if err != nil {
			return XorbRecordPage{}, err
		}
		var record XorbRecord
		if err := decodeIndexRecord(recordData, &record); err != nil {
			return XorbRecordPage{}, err
		}
		if record.Layout.Hash != hash || record.Blob.Kind != BlobXorb || record.Blob.Hash != hash {
			return XorbRecordPage{}, fmt.Errorf("%w: SQLite xorb identity mismatch", ErrCorrupt)
		}
		page.Items = append(page.Items, record)
	}
	if err := finishSQLiteRows(rows); err != nil {
		return XorbRecordPage{}, fmt.Errorf("xet CAS server: finish SQLite xorb page: %w", err)
	}
	if len(page.Items) > limit {
		page.Items = page.Items[:limit]
		page.NextCursor = encodeHashCursor(cursorIndexXorb, page.Items[len(page.Items)-1].Layout.Hash)
	}
	return page, nil
}

func (s *SQLiteIndexStore) ListFiles(
	ctx context.Context,
	namespace *string,
	request PageRequest,
) (FileRecordPage, error) {
	cursorKind := cursorFileAll
	if namespace != nil {
		cursorKind = cursorFileScoped
	}
	limit, cursorNamespace, cursorHash, hasCursor, err := scopedHashPage(request, namespace, cursorKind)
	if err != nil {
		return FileRecordPage{}, err
	}
	query, arguments := scopedHashQuery(
		"SELECT namespace, hash, record, typeof(namespace), typeof(hash), typeof(record) FROM files", "hash", namespace,
		cursorNamespace, cursorHash, hasCursor, limit,
	)
	rows, err := s.db.QueryContext(ctx, query, arguments...)
	if err != nil {
		return FileRecordPage{}, fmt.Errorf("xet CAS server: list SQLite files: %w", err)
	}
	defer rows.Close() //nolint:errcheck // rows.Err and the explicit close below determine the result.
	page := FileRecordPage{Items: make([]ScopedFileRecord, 0, limit)}
	for rows.Next() {
		var scope string
		var hashData, recordData []byte
		var scopeType, hashType, recordType string
		if err := rows.Scan(&scope, &hashData, &recordData, &scopeType, &hashType, &recordType); err != nil {
			return FileRecordPage{}, fmt.Errorf("xet CAS server: scan SQLite file page: %w", err)
		}
		if scopeType != "text" || hashType != "blob" || recordType != "blob" {
			return FileRecordPage{}, fmt.Errorf("%w: malformed SQLite file storage class", ErrCorrupt)
		}
		hash, err := sqliteHash(hashData)
		if err != nil {
			return FileRecordPage{}, err
		}
		var record FileRecord
		if err := decodeIndexRecord(recordData, &record); err != nil {
			return FileRecordPage{}, err
		}
		if record.File.File.Hash != hash || record.Shard.Kind != BlobShard {
			return FileRecordPage{}, fmt.Errorf("%w: SQLite file identity mismatch", ErrCorrupt)
		}
		page.Items = append(page.Items, ScopedFileRecord{Namespace: scope, Record: record})
	}
	if err := finishSQLiteRows(rows); err != nil {
		return FileRecordPage{}, fmt.Errorf("xet CAS server: finish SQLite file page: %w", err)
	}
	if len(page.Items) > limit {
		page.Items = page.Items[:limit]
		last := page.Items[len(page.Items)-1]
		page.NextCursor = encodeScopedCursor(cursorKind, last.Namespace, last.Record.File.File.Hash[:])
	}
	return page, nil
}

func (s *SQLiteIndexStore) ListDedup(
	ctx context.Context,
	namespace *string,
	request PageRequest,
) (DedupRecordPage, error) {
	cursorKind := cursorDedupAll
	if namespace != nil {
		cursorKind = cursorDedupScoped
	}
	limit, cursorNamespace, cursorHash, hasCursor, err := scopedHashPage(request, namespace, cursorKind)
	if err != nil {
		return DedupRecordPage{}, err
	}
	query, arguments := scopedHashQuery(
		"SELECT namespace, chunk_hash, record, typeof(namespace), typeof(chunk_hash), typeof(record) FROM dedup", "chunk_hash", namespace,
		cursorNamespace, cursorHash, hasCursor, limit,
	)
	rows, err := s.db.QueryContext(ctx, query, arguments...)
	if err != nil {
		return DedupRecordPage{}, fmt.Errorf("xet CAS server: list SQLite dedup: %w", err)
	}
	defer rows.Close() //nolint:errcheck // rows.Err and the explicit close below determine the result.
	page := DedupRecordPage{Items: make([]ScopedDedupRecord, 0, limit)}
	for rows.Next() {
		var scope string
		var hashData, recordData []byte
		var scopeType, hashType, recordType string
		if err := rows.Scan(&scope, &hashData, &recordData, &scopeType, &hashType, &recordType); err != nil {
			return DedupRecordPage{}, fmt.Errorf("xet CAS server: scan SQLite dedup page: %w", err)
		}
		if scopeType != "text" || hashType != "blob" || recordType != "blob" {
			return DedupRecordPage{}, fmt.Errorf("%w: malformed SQLite dedup storage class", ErrCorrupt)
		}
		hash, err := sqliteHash(hashData)
		if err != nil {
			return DedupRecordPage{}, err
		}
		var record DedupRecord
		if err := decodeIndexRecord(recordData, &record); err != nil {
			return DedupRecordPage{}, err
		}
		if record.Shard.Kind != BlobShard {
			return DedupRecordPage{}, fmt.Errorf("%w: SQLite dedup shard kind mismatch", ErrCorrupt)
		}
		page.Items = append(page.Items, ScopedDedupRecord{Namespace: scope, Chunk: hash, Record: record})
	}
	if err := finishSQLiteRows(rows); err != nil {
		return DedupRecordPage{}, fmt.Errorf("xet CAS server: finish SQLite dedup page: %w", err)
	}
	if len(page.Items) > limit {
		page.Items = page.Items[:limit]
		last := page.Items[len(page.Items)-1]
		page.NextCursor = encodeScopedCursor(cursorKind, last.Namespace, last.Chunk[:])
	}
	return page, nil
}

func (s *SQLiteIndexStore) ListSHA256(
	ctx context.Context,
	namespace *string,
	request PageRequest,
) (SHA256AssociationPage, error) {
	cursorKind := cursorSHA256All
	if namespace != nil {
		cursorKind = cursorSHA256Scoped
	}
	limit, cursorNamespace, cursorSum, cursorSize, hasCursor, err := scopedSHAPage(request, namespace, cursorKind)
	if err != nil {
		return SHA256AssociationPage{}, err
	}
	var databaseCursorSize int64
	if hasCursor {
		databaseCursorSize, err = uint64ToSQLite(cursorSize)
		if err != nil {
			return SHA256AssociationPage{}, err
		}
	}
	query, arguments := scopedSHAQuery(namespace, cursorNamespace, cursorSum, databaseCursorSize, hasCursor, limit)
	rows, err := s.db.QueryContext(ctx, query, arguments...)
	if err != nil {
		return SHA256AssociationPage{}, fmt.Errorf("xet CAS server: list SQLite SHA-256 associations: %w", err)
	}
	defer rows.Close() //nolint:errcheck // rows.Err and the explicit close below determine the result.
	page := SHA256AssociationPage{Items: make([]ScopedSHA256Association, 0, limit)}
	for rows.Next() {
		var scope string
		var sumData, fileData []byte
		var databaseSize any
		var scopeType, sumType, sizeType, fileType string
		if err := rows.Scan(
			&scope, &sumData, &databaseSize, &fileData,
			&scopeType, &sumType, &sizeType, &fileType,
		); err != nil {
			return SHA256AssociationPage{}, fmt.Errorf("xet CAS server: scan SQLite SHA-256 page: %w", err)
		}
		size, sizeOK := databaseSize.(int64)
		if scopeType != "text" || sumType != "blob" || sizeType != "integer" || fileType != "blob" ||
			!sizeOK || len(sumData) != 32 || len(fileData) != len(xethash.Hash{}) || size < 0 {
			return SHA256AssociationPage{}, fmt.Errorf("%w: malformed SQLite SHA-256 association", ErrCorrupt)
		}
		var sum [32]byte
		var file xethash.Hash
		copy(sum[:], sumData)
		copy(file[:], fileData)
		page.Items = append(page.Items, ScopedSHA256Association{Namespace: scope, Record: SHA256Association{
			Sum: sum, Size: uint64(size), File: file,
		}})
	}
	if err := finishSQLiteRows(rows); err != nil {
		return SHA256AssociationPage{}, fmt.Errorf("xet CAS server: finish SQLite SHA-256 page: %w", err)
	}
	if len(page.Items) > limit {
		page.Items = page.Items[:limit]
		last := page.Items[len(page.Items)-1]
		page.NextCursor = encodeScopedCursor(cursorKind, last.Namespace, shaCursorKey(last.Record.Sum, last.Record.Size))
	}
	return page, nil
}

func scopedHashQuery(
	base, column string,
	namespace *string,
	cursorNamespace string,
	cursorHash xethash.Hash,
	hasCursor bool,
	limit int,
) (string, []any) {
	order := " ORDER BY namespace, " + column + " LIMIT ?"
	if namespace != nil {
		if hasCursor {
			return base + " WHERE namespace = ? AND " + column + " > ?" + order,
				[]any{*namespace, hashBytes(cursorHash), limit + 1}
		}
		return base + " WHERE namespace = ?" + order, []any{*namespace, limit + 1}
	}
	if hasCursor {
		return base + " WHERE (namespace, " + column + ") > (?, ?)" + order,
			[]any{cursorNamespace, hashBytes(cursorHash), limit + 1}
	}
	return base + order, []any{limit + 1}
}

func scopedProtectionQuery(
	base string,
	namespace *string,
	cursorNamespace string,
	cursorID ProtectionID,
	hasCursor bool,
	limit int,
) (string, []any) {
	const order = " ORDER BY namespace, id LIMIT ?"
	if namespace != nil {
		if hasCursor {
			return base + " WHERE namespace = ? AND id > ?" + order,
				[]any{*namespace, cursorID[:], limit + 1}
		}
		return base + " WHERE namespace = ?" + order, []any{*namespace, limit + 1}
	}
	if hasCursor {
		return base + " WHERE (namespace, id) > (?, ?)" + order,
			[]any{cursorNamespace, cursorID[:], limit + 1}
	}
	return base + order, []any{limit + 1}
}

func scopedSHAQuery(
	namespace *string,
	cursorNamespace string,
	cursorSum [32]byte,
	cursorSize int64,
	hasCursor bool,
	limit int,
) (string, []any) {
	const base = `SELECT namespace, sum, size, file_hash,
typeof(namespace), typeof(sum), typeof(size), typeof(file_hash) FROM sha256_associations`
	const order = " ORDER BY namespace, sum, size LIMIT ?"
	if namespace != nil {
		if hasCursor {
			return base + ` WHERE namespace = ? AND (sum, size) > (?, ?)` + order,
				[]any{*namespace, cursorSum[:], cursorSize, limit + 1}
		}
		return base + " WHERE namespace = ?" + order, []any{*namespace, limit + 1}
	}
	if hasCursor {
		return base + ` WHERE (namespace, sum, size) > (?, ?, ?)` + order,
			[]any{cursorNamespace, cursorSum[:], cursorSize, limit + 1}
	}
	return base + order, []any{limit + 1}
}

type sqliteScanner interface {
	Scan(...any) error
}

func (s *SQLiteIndexStore) sqliteBlobStage(
	ctx context.Context,
	namespace string,
	id ProtectionID,
) (BlobStage, error) {
	return scanSQLiteBlobStage(s.db.QueryRowContext(ctx, `
SELECT namespace, id, blob_kind, blob_hash, created_at, expires_at,
  typeof(namespace), typeof(id), typeof(blob_kind), typeof(blob_hash), typeof(created_at), typeof(expires_at)
FROM blob_stages WHERE namespace = ? AND id = ?`, namespace, id[:]))
}

func (s *SQLiteIndexStore) sqliteFileLease(
	ctx context.Context,
	namespace string,
	id ProtectionID,
) (FileLease, error) {
	return scanSQLiteFileLease(s.db.QueryRowContext(ctx, `
SELECT namespace, id, file_hash, created_at, expires_at,
  typeof(namespace), typeof(id), typeof(file_hash), typeof(created_at), typeof(expires_at)
FROM file_leases WHERE namespace = ? AND id = ?`, namespace, id[:]))
}

func scanSQLiteBlobStage(scanner sqliteScanner) (BlobStage, error) {
	var namespace, kind string
	var idData, hashData []byte
	var createdValue, expiresValue any
	var namespaceType, idType, kindType, hashType, createdType, expiresType string
	if err := scanner.Scan(
		&namespace, &idData, &kind, &hashData, &createdValue, &expiresValue,
		&namespaceType, &idType, &kindType, &hashType, &createdType, &expiresType,
	); err != nil {
		return BlobStage{}, err
	}
	createdAt, createdOK := createdValue.(int64)
	expiresAt, expiresOK := expiresValue.(int64)
	if namespaceType != "text" || idType != "blob" || kindType != "text" || hashType != "blob" ||
		createdType != "integer" || expiresType != "integer" || len(idData) != len(ProtectionID{}) ||
		!createdOK || !expiresOK {
		return BlobStage{}, fmt.Errorf("%w: malformed SQLite blob stage", ErrCorrupt)
	}
	hash, err := sqliteHash(hashData)
	if err != nil {
		return BlobStage{}, err
	}
	var id ProtectionID
	copy(id[:], idData)
	stage, err := normalizeBlobStage(BlobStage{
		ID: id, Namespace: namespace, Blob: BlobKey{Kind: BlobKind(kind), Hash: hash},
		CreatedAt: protectionTimeFromSQLite(createdAt), ExpiresAt: protectionTimeFromSQLite(expiresAt),
	})
	if err != nil {
		return BlobStage{}, fmt.Errorf("%w: malformed SQLite blob stage value: %v", ErrCorrupt, err)
	}
	return stage, nil
}

func scanSQLiteFileLease(scanner sqliteScanner) (FileLease, error) {
	var namespace string
	var idData, hashData []byte
	var createdValue, expiresValue any
	var namespaceType, idType, hashType, createdType, expiresType string
	if err := scanner.Scan(
		&namespace, &idData, &hashData, &createdValue, &expiresValue,
		&namespaceType, &idType, &hashType, &createdType, &expiresType,
	); err != nil {
		return FileLease{}, err
	}
	createdAt, createdOK := createdValue.(int64)
	expiresAt, expiresOK := expiresValue.(int64)
	if namespaceType != "text" || idType != "blob" || hashType != "blob" || createdType != "integer" ||
		expiresType != "integer" || len(idData) != len(ProtectionID{}) || !createdOK || !expiresOK {
		return FileLease{}, fmt.Errorf("%w: malformed SQLite file lease", ErrCorrupt)
	}
	hash, err := sqliteHash(hashData)
	if err != nil {
		return FileLease{}, err
	}
	var id ProtectionID
	copy(id[:], idData)
	lease, err := normalizeFileLease(FileLease{
		ID: id, Namespace: namespace, File: hash,
		CreatedAt: protectionTimeFromSQLite(createdAt), ExpiresAt: protectionTimeFromSQLite(expiresAt),
	})
	if err != nil {
		return FileLease{}, fmt.Errorf("%w: malformed SQLite file lease value: %v", ErrCorrupt, err)
	}
	return lease, nil
}

func sqliteHash(data []byte) (xethash.Hash, error) {
	if len(data) != len(xethash.Hash{}) {
		return xethash.Hash{}, fmt.Errorf("%w: invalid SQLite hash length", ErrCorrupt)
	}
	var hash xethash.Hash
	copy(hash[:], data)
	return hash, nil
}

func protectionTimeToSQLite(value time.Time) (int64, error) {
	value, err := normalizeProtectionTime(value)
	if err != nil {
		return 0, err
	}
	nanoseconds := value.UnixNano()
	if !time.Unix(0, nanoseconds).Equal(value) {
		return 0, fmt.Errorf("%w: protection timestamp is outside SQLite nanosecond range", ErrInvalid)
	}
	return nanoseconds, nil
}

func protectionTimeFromSQLite(nanoseconds int64) time.Time {
	return time.Unix(0, nanoseconds).UTC()
}

func finishSQLiteRows(rows *sql.Rows) error {
	if err := rows.Err(); err != nil {
		return err
	}
	return rows.Close()
}

func (s *SQLiteIndexStore) runTestHook(stage string) error {
	if s.testHook == nil {
		return nil
	}
	return s.testHook(stage)
}
