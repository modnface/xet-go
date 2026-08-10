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

	"github.com/jmwoliver/xet-go/xethash"
	_ "modernc.org/sqlite"
)

const sqliteSchemaVersion = 1

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
	if _, err := tx.ExecContext(ctx, sqliteSchemaV1); err != nil {
		return fmt.Errorf("xet CAS server: migrate SQLite schema: %w", err)
	}
	if _, err := tx.ExecContext(ctx, "PRAGMA user_version = 1"); err != nil {
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

func (s *SQLiteIndexStore) runTestHook(stage string) error {
	if s.testHook == nil {
		return nil
	}
	return s.testHook(stage)
}
