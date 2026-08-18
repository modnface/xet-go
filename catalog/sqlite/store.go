// Package sqlite implements the durable SQLite catalog backend.
package sqlite

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/jmwoliver/xet-go/catalog"
	"github.com/jmwoliver/xet-go/model"
	"github.com/jmwoliver/xet-go/xethash"
	_ "modernc.org/sqlite"
)

const (
	schemaVersion    = 1
	sqliteError      = 1
	sqliteBusy       = 5
	sqliteLocked     = 6
	sqliteCorrupt    = 11
	sqliteSchema     = 17
	sqliteConstraint = 19
	sqliteNotADB     = 26
	initLockTimeout  = 5 * time.Second
)

type Store struct {
	db       *sql.DB
	mu       sync.RWMutex
	closed   bool
	testHook func(string) error
}

var _ catalog.Catalog = (*Store)(nil)

const schema = `
CREATE TABLE repositories(repo_type TEXT COLLATE BINARY NOT NULL,namespace TEXT COLLATE BINARY NOT NULL,name TEXT COLLATE BINARY NOT NULL,created_at INTEGER NOT NULL CHECK(typeof(created_at)='integer'),PRIMARY KEY(repo_type,namespace,name)) WITHOUT ROWID;
CREATE TABLE snapshots(repo_type TEXT NOT NULL,namespace TEXT NOT NULL,name TEXT NOT NULL,oid BLOB NOT NULL CHECK(typeof(oid)='blob' AND length(oid)=20),parent BLOB CHECK(parent IS NULL OR (typeof(parent)='blob' AND length(parent)=20)),created_at INTEGER NOT NULL CHECK(typeof(created_at)='integer'),author_name TEXT COLLATE BINARY NOT NULL,author_email TEXT COLLATE BINARY NOT NULL,message TEXT COLLATE BINARY NOT NULL,file_count INTEGER NOT NULL CHECK(file_count>=0),fingerprint BLOB NOT NULL CHECK(typeof(fingerprint)='blob' AND length(fingerprint)=32),fingerprint_version INTEGER NOT NULL CHECK(fingerprint_version=1),PRIMARY KEY(repo_type,namespace,name,oid),FOREIGN KEY(repo_type,namespace,name) REFERENCES repositories(repo_type,namespace,name) ON DELETE CASCADE,FOREIGN KEY(repo_type,namespace,name,parent) REFERENCES snapshots(repo_type,namespace,name,oid)) WITHOUT ROWID;
CREATE INDEX snapshots_order ON snapshots(repo_type,namespace,name,created_at DESC,oid DESC);
CREATE TABLE refs(repo_type TEXT NOT NULL,namespace TEXT NOT NULL,name TEXT NOT NULL,ref_name TEXT COLLATE BINARY NOT NULL,oid BLOB NOT NULL CHECK(typeof(oid)='blob' AND length(oid)=20),PRIMARY KEY(repo_type,namespace,name,ref_name),FOREIGN KEY(repo_type,namespace,name,oid) REFERENCES snapshots(repo_type,namespace,name,oid)) WITHOUT ROWID;
CREATE TABLE files(repo_type TEXT NOT NULL,namespace TEXT NOT NULL,name TEXT NOT NULL,oid BLOB NOT NULL,path TEXT COLLATE BINARY NOT NULL,kind TEXT NOT NULL CHECK(kind IN ('blob','xet')),size INTEGER NOT NULL CHECK(size>=0),sha256 BLOB CHECK(sha256 IS NULL OR (typeof(sha256)='blob' AND length(sha256)=32)),xet_hash BLOB CHECK(xet_hash IS NULL OR (typeof(xet_hash)='blob' AND length(xet_hash)=32)),CHECK((kind='blob' AND sha256 IS NOT NULL AND xet_hash IS NULL) OR (kind='xet' AND xet_hash IS NOT NULL)),PRIMARY KEY(repo_type,namespace,name,oid,path),FOREIGN KEY(repo_type,namespace,name,oid) REFERENCES snapshots(repo_type,namespace,name,oid) ON DELETE CASCADE) WITHOUT ROWID;`

func Open(path string) (*Store, error) {
	if path == "" {
		return nil, invalid(errors.New("empty path"))
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, unavailable(err)
	}
	if err = securePath(abs); err != nil {
		return nil, err
	}
	q := url.Values{}
	q.Set("_txlock", "immediate")
	q.Add("_pragma", "busy_timeout(50)")
	q.Add("_pragma", "foreign_keys(ON)")
	q.Add("_pragma", "synchronous(FULL)")
	db, err := sql.Open("sqlite", (&url.URL{Scheme: "file", Path: filepath.ToSlash(abs), RawQuery: q.Encode()}).String())
	if err != nil {
		return nil, unavailable(err)
	}
	db.SetMaxOpenConns(4)
	s := &Store{db: db}
	if err = s.init(context.Background()); err != nil {
		_ = db.Close()
		return nil, err
	}
	return s, nil
}

// securePath rejects symlinks and creates a new database file durably. Callers
// must keep the database directory private from identities that can replace
// path components concurrently; pathname checks cannot fence hostile renames.
func securePath(path string) error {
	parent := filepath.Dir(path)
	if err := validateDirectoryChain(parent); err != nil {
		return err
	}
	if err := os.MkdirAll(parent, 0700); err != nil {
		return unavailable(err)
	}
	if err := validateDirectoryChain(parent); err != nil {
		return err
	}
	_, e := os.Lstat(path)
	if e == nil {
		return validateDatabaseFile(path)
	}
	if !errors.Is(e, os.ErrNotExist) {
		return unavailable(e)
	}
	f, e := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
	if e != nil {
		if errors.Is(e, os.ErrExist) {
			return validateDatabaseFile(path)
		}
		return unavailable(e)
	}
	if e = f.Sync(); e != nil {
		_ = f.Close()
		return unavailable(e)
	}
	if e = f.Close(); e != nil {
		return unavailable(e)
	}
	directory, e := os.Open(parent)
	if e != nil {
		return unavailable(e)
	}
	defer directory.Close() //nolint:errcheck // Sync result determines durability.
	if e = directory.Sync(); e != nil {
		return unavailable(e)
	}
	return nil
}

func validateDatabaseFile(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return unavailable(err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return invalid(errors.New("database path is not a regular file"))
	}
	if info.Mode().Perm()&0077 != 0 {
		return invalid(errors.New("database file permissions must not grant group or other access"))
	}
	return nil
}

func validateDirectoryChain(path string) error {
	for current := filepath.Clean(path); ; current = filepath.Dir(current) {
		info, err := os.Lstat(current)
		if err == nil {
			if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
				return invalid(fmt.Errorf("database parent component %q is not a real directory", current))
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			return unavailable(err)
		}
		next := filepath.Dir(current)
		if next == current {
			return nil
		}
	}
}
func (s *Store) init(ctx context.Context) error {
	var version int
	if err := s.db.QueryRowContext(ctx, "PRAGMA user_version").Scan(&version); err != nil {
		return dbErr(ctx, err)
	}
	if version != 0 && version != schemaVersion {
		return fmt.Errorf("%w: unsupported schema version %d", catalog.ErrUnavailable, version)
	}
	var mode string
	if err := s.db.QueryRowContext(ctx, "PRAGMA journal_mode=WAL").Scan(&mode); err != nil {
		return dbErr(ctx, err)
	}
	if strings.ToLower(mode) != "wal" {
		return unavailable(fmt.Errorf("WAL refused"))
	}
	lockContext, cancel := context.WithTimeout(ctx, initLockTimeout)
	defer cancel()
	tx, e := s.beginWrite(lockContext)
	if e != nil {
		if ctx.Err() == nil && errors.Is(e, context.DeadlineExceeded) {
			return unavailable(errors.New("timed out acquiring schema initialization lock"))
		}
		return dbErr(ctx, e)
	}
	defer tx.Rollback() //nolint:errcheck // Commit below determines the result.
	var v int
	if e = tx.QueryRowContext(ctx, "PRAGMA user_version").Scan(&v); e != nil {
		return dbErr(ctx, e)
	}
	switch v {
	case 0:
		if _, e = tx.ExecContext(ctx, schema); e != nil {
			return dbErr(ctx, e)
		}
		if _, e = tx.ExecContext(ctx, "PRAGMA user_version=1"); e != nil {
			return dbErr(ctx, e)
		}
	case schemaVersion:
		// The schema probe below detects a version marker copied into an empty
		// or incompatible database instead of delaying failure to first use.
	default:
		return fmt.Errorf("%w: unsupported schema version %d", catalog.ErrUnavailable, v)
	}
	if e = probeSchema(ctx, tx); e != nil {
		return e
	}
	if e = tx.Commit(); e != nil {
		return dbErr(ctx, e)
	}
	return nil
}

func probeSchema(ctx context.Context, tx *sql.Tx) error {
	queries := []string{
		"SELECT repo_type,namespace,name,created_at FROM repositories LIMIT 0",
		"SELECT repo_type,namespace,name,oid,parent,created_at,author_name,author_email,message,file_count,fingerprint,fingerprint_version FROM snapshots LIMIT 0",
		"SELECT repo_type,namespace,name,ref_name,oid FROM refs LIMIT 0",
		"SELECT repo_type,namespace,name,oid,path,kind,size,sha256,xet_hash FROM files LIMIT 0",
	}
	for _, query := range queries {
		rows, err := tx.QueryContext(ctx, query)
		if err != nil {
			return schemaErr(ctx, err)
		}
		if err = rows.Close(); err != nil {
			return dbErr(ctx, err)
		}
	}
	var indexExists int
	if err := tx.QueryRowContext(ctx, "SELECT count(*) FROM sqlite_master WHERE type='index' AND name='snapshots_order'").Scan(&indexExists); err != nil {
		return schemaErr(ctx, err)
	}
	if indexExists != 1 {
		return corrupt(errors.New("missing snapshots_order index"))
	}
	return nil
}
func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	return s.db.Close()
}
func (s *Store) check(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed {
		return unavailable(errors.New("store closed"))
	}
	return nil
}

func (s *Store) beginWrite(ctx context.Context) (*sql.Tx, error) {
	for {
		tx, err := s.db.BeginTx(ctx, nil)
		if err == nil {
			return tx, nil
		}
		code := sqliteCode(err)
		if code != sqliteBusy && code != sqliteLocked {
			return nil, dbErr(ctx, err)
		}
		timer := time.NewTimer(10 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil, ctx.Err()
		case <-timer.C:
		}
	}
}
func kargs(k model.RepoKey) []any { return []any{string(k.Type), string(k.Namespace), string(k.Name)} }

func (s *Store) CreateRepository(ctx context.Context, r model.Repository) error {
	if e := s.check(ctx); e != nil {
		return e
	}
	c, e := model.CanonicalRepository(r)
	if e != nil {
		return invalid(e)
	}
	tx, e := s.beginWrite(ctx)
	if e != nil {
		return e
	}
	defer tx.Rollback() //nolint:errcheck // Commit below determines the result.
	_, e = tx.ExecContext(ctx, "INSERT INTO repositories VALUES(?,?,?,?)", c.Key.Type, c.Key.Namespace, c.Key.Name, c.CreatedAt.UnixNano())
	if e != nil {
		if sqliteCode(e) == sqliteConstraint {
			var exists int
			queryErr := tx.QueryRowContext(ctx,
				"SELECT count(*) FROM repositories WHERE repo_type=? AND namespace=? AND name=?", kargs(c.Key)...).Scan(&exists)
			if queryErr == nil && exists == 1 {
				return fmt.Errorf("%w", catalog.ErrAlreadyExists)
			}
		}
		return dbErr(ctx, e)
	}
	return dbErr(ctx, tx.Commit())
}
func (s *Store) GetRepository(ctx context.Context, k model.RepoKey) (model.Repository, error) {
	if e := validKey(ctx, s, k); e != nil {
		return model.Repository{}, e
	}
	var at int64
	e := scanOne(ctx, s.db, "SELECT created_at FROM repositories WHERE repo_type=? AND namespace=? AND name=?", kargs(k), func(row scanner) error {
		return row.Scan(&at)
	})
	if e != nil {
		return model.Repository{}, e
	}
	return model.Repository{Key: k, CreatedAt: time.Unix(0, at).UTC()}, nil
}

type cursor struct {
	Kind       string `json:"kind"`
	Namespace  string `json:"namespace,omitempty"`
	RepoType   string `json:"repo_type,omitempty"`
	Repository string `json:"repository,omitempty"`
	Prefix     string `json:"prefix,omitempty"`
	Last       string `json:"last,omitempty"`
	Timestamp  *int64 `json:"timestamp,omitempty"`
	OID        string `json:"oid,omitempty"`
}

func enc(c cursor) string { b, _ := json.Marshal(c); return base64.RawURLEncoding.EncodeToString(b) }
func dec(v string) (cursor, error) {
	b, e := base64.RawURLEncoding.DecodeString(v)
	if e != nil {
		return cursor{}, e
	}
	d := json.NewDecoder(strings.NewReader(string(b)))
	d.DisallowUnknownFields()
	var c cursor
	if e = d.Decode(&c); e != nil {
		return c, e
	}
	if e = d.Decode(&struct{}{}); !errors.Is(e, io.EOF) {
		return c, errors.New("trailing cursor")
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
func sortKey(k model.RepoKey) string {
	return string(k.Type) + "\x00" + string(k.Namespace) + "\x00" + string(k.Name)
}
func (s *Store) ListRepositories(ctx context.Context, q catalog.RepositoryQuery) (catalog.RepositoryPage, error) {
	if e := s.check(ctx); e != nil {
		return catalog.RepositoryPage{}, e
	}
	l, e := limit(q.Limit)
	if e != nil {
		return catalog.RepositoryPage{}, e
	}
	if q.Namespace != "" {
		if _, e = model.ParseNamespace(string(q.Namespace)); e != nil {
			return catalog.RepositoryPage{}, invalid(e)
		}
	}
	if q.Type != "" && q.Type != model.RepoTypeModel {
		return catalog.RepositoryPage{}, invalid(errors.New("bad type"))
	}
	var afterKey model.RepoKey
	hasAfter := false
	if q.Cursor != "" {
		c, x := dec(q.Cursor)
		parts := strings.Split(c.Last, "\x00")
		validLast := len(parts) == 3
		if validLast {
			key, keyErr := model.NewRepoKey(parts[1], parts[2], model.RepoType(parts[0]))
			validLast = keyErr == nil && sortKey(key) == c.Last &&
				(q.Namespace == "" || key.Namespace == q.Namespace) && (q.Type == "" || key.Type == q.Type)
		}
		if x != nil || c.Kind != "repositories" || c.Namespace != string(q.Namespace) || c.RepoType != string(q.Type) ||
			c.Repository != "" || c.Prefix != "" || c.Timestamp != nil || c.OID != "" || !validLast {
			return catalog.RepositoryPage{}, invalid(errors.New("bad cursor"))
		}
		afterKey, _ = model.NewRepoKey(parts[1], parts[2], model.RepoType(parts[0]))
		hasAfter = true
	}
	rows, e := s.db.QueryContext(ctx, `SELECT repo_type,namespace,name,created_at FROM repositories
WHERE (?='' OR namespace=?) AND (?='' OR repo_type=?)
AND (?=0 OR (repo_type,namespace,name)>(?,?,?))
ORDER BY repo_type COLLATE BINARY,namespace COLLATE BINARY,name COLLATE BINARY LIMIT ?`,
		q.Namespace, q.Namespace, q.Type, q.Type, boolInt(hasAfter), afterKey.Type, afterKey.Namespace, afterKey.Name, l+1)
	if e != nil {
		return catalog.RepositoryPage{}, dbErr(ctx, e)
	}
	defer rows.Close() //nolint:errcheck // rows.Err reports iteration failures.
	p := catalog.RepositoryPage{}
	for rows.Next() {
		var t, n, a string
		var ts int64
		if e = rows.Scan(&t, &n, &a, &ts); e != nil {
			return p, corrupt(e)
		}
		r, ce := model.CanonicalRepository(model.Repository{Key: model.RepoKey{Type: model.RepoType(t), Namespace: model.Namespace(n), Name: model.RepoName(a)}, CreatedAt: time.Unix(0, ts).UTC()})
		if ce != nil {
			return p, corrupt(ce)
		}
		p.Items = append(p.Items, r)
	}
	if e = rows.Err(); e != nil {
		return p, dbErr(ctx, e)
	}
	if len(p.Items) > l {
		p.Items = p.Items[:l]
		p.NextCursor = enc(cursor{Kind: "repositories", Namespace: string(q.Namespace), RepoType: string(q.Type), Last: sortKey(p.Items[l-1].Key)})
	}
	return p, nil
}

func (s *Store) GetSnapshot(ctx context.Context, k model.RepoKey, o model.OID) (model.Snapshot, error) {
	if e := validKey(ctx, s, k); e != nil {
		return model.Snapshot{}, e
	}
	if o.IsZero() {
		return model.Snapshot{}, invalid(errors.New("zero oid"))
	}
	return loadSnapshotFrom(ctx, s.db, k, o)
}
func (s *Store) ResolveRevision(ctx context.Context, k model.RepoKey, r model.Revision) (model.Snapshot, error) {
	if e := validKey(ctx, s, k); e != nil {
		return model.Snapshot{}, e
	}
	o, e := resolveOID(ctx, s.db, k, r)
	if e != nil {
		return model.Snapshot{}, e
	}
	return loadSnapshotFrom(ctx, s.db, k, o)
}

type queryer interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}

func loadSnapshotFrom(ctx context.Context, source queryer, k model.RepoKey, o model.OID) (model.Snapshot, error) {
	var oid, parent, fp []byte
	var at int64
	var an, ae, msg string
	var count, ver int
	e := scanOne(ctx, source, "SELECT oid,parent,created_at,author_name,author_email,message,file_count,fingerprint,fingerprint_version FROM snapshots WHERE repo_type=? AND namespace=? AND name=? AND oid=?", append(kargs(k), o[:]), func(row scanner) error {
		return row.Scan(&oid, &parent, &at, &an, &ae, &msg, &count, &fp, &ver)
	})
	if e != nil {
		return model.Snapshot{}, e
	}
	snap := model.Snapshot{Repo: k, CreatedAt: time.Unix(0, at).UTC(), Author: model.Identity{Name: an, Email: ae}, Message: msg}
	if !copyOID(&snap.OID, oid) || len(fp) != 32 || ver != model.SnapshotFingerprintVersion {
		return snap, corrupt(errors.New("bad snapshot encoding"))
	}
	if parent != nil {
		var p model.OID
		if !copyOID(&p, parent) {
			return snap, corrupt(errors.New("bad parent"))
		}
		snap.Parent = &p
	}
	rows, e := source.QueryContext(ctx, "SELECT path,kind,size,sha256,xet_hash FROM files WHERE repo_type=? AND namespace=? AND name=? AND oid=? ORDER BY path", append(kargs(k), o[:])...)
	if e != nil {
		return snap, dbErr(ctx, e)
	}
	defer rows.Close() //nolint:errcheck // rows.Err reports iteration failures.
	for rows.Next() {
		f, ce := scanFile(rows)
		if ce != nil {
			if errors.Is(ce, catalog.ErrCorrupt) {
				return snap, ce
			}
			return snap, rowErr(ctx, ce)
		}
		snap.Files = append(snap.Files, f)
	}
	if e = rows.Err(); e != nil {
		return snap, dbErr(ctx, e)
	}
	if len(snap.Files) != count {
		return snap, corrupt(errors.New("file count mismatch"))
	}
	c, e := model.CanonicalSnapshot(snap)
	if e != nil {
		return snap, corrupt(e)
	}
	got, e := model.FingerprintSnapshot(c)
	if e != nil || !equal(got[:], fp) {
		return snap, corrupt(errors.New("fingerprint mismatch"))
	}
	return c, nil
}

func resolveOID(ctx context.Context, source queryer, key model.RepoKey, revision model.Revision) (model.OID, error) {
	oid, isOID := revision.OID()
	if isOID {
		return oid, nil
	}
	name, isRef := revision.Ref()
	if !isRef {
		return model.OID{}, invalid(errors.New("empty revision"))
	}
	return loadRefOID(ctx, source, key, name)
}

func loadRefOID(ctx context.Context, source queryer, key model.RepoKey, name model.RefName) (model.OID, error) {
	var encoded, target []byte
	err := scanOne(ctx, source, `SELECT r.oid,s.oid FROM refs r
LEFT JOIN snapshots s ON s.repo_type=r.repo_type AND s.namespace=r.namespace AND s.name=r.name AND s.oid=r.oid
WHERE r.repo_type=? AND r.namespace=? AND r.name=? AND r.ref_name=?`, append(kargs(key), name), func(row scanner) error {
		return row.Scan(&encoded, &target)
	})
	if err != nil {
		return model.OID{}, err
	}
	var oid, targetOID model.OID
	if !copyOID(&oid, encoded) || !copyOID(&targetOID, target) || oid != targetOID {
		return model.OID{}, corrupt(errors.New("invalid or dangling ref oid"))
	}
	return oid, nil
}

func (s *Store) ListSnapshots(ctx context.Context, k model.RepoKey, q catalog.SnapshotQuery) (catalog.SnapshotPage, error) {
	if e := validKey(ctx, s, k); e != nil {
		return catalog.SnapshotPage{}, e
	}
	if _, e := s.GetRepository(ctx, k); e != nil {
		return catalog.SnapshotPage{}, e
	}
	l, e := limit(q.Limit)
	if e != nil {
		return catalog.SnapshotPage{}, e
	}
	var ts int64
	var oid model.OID
	has := false
	if q.Cursor != "" {
		c, x := dec(q.Cursor)
		if x != nil || c.Kind != "snapshots" || c.Repository != sortKey(k) || c.Timestamp == nil ||
			c.Namespace != "" || c.RepoType != "" || c.Prefix != "" || c.Last != "" {
			return catalog.SnapshotPage{}, invalid(errors.New("bad cursor"))
		}
		o, x := model.ParseOID(c.OID)
		if x != nil {
			return catalog.SnapshotPage{}, invalid(x)
		}
		ts = *c.Timestamp
		oid = o
		has = true
	}
	rows, e := s.db.QueryContext(ctx, "SELECT oid,parent,created_at,author_name,author_email,message,file_count FROM snapshots WHERE repo_type=? AND namespace=? AND name=? AND (?=0 OR created_at<? OR (created_at=? AND oid<?)) ORDER BY created_at DESC,oid DESC LIMIT ?", append(kargs(k), boolInt(has), ts, ts, oid[:], l+1)...)
	if e != nil {
		return catalog.SnapshotPage{}, dbErr(ctx, e)
	}
	defer rows.Close() //nolint:errcheck // rows.Err reports iteration failures.
	p := catalog.SnapshotPage{}
	for rows.Next() {
		var ob, pb []byte
		var at int64
		var an, ae, m string
		var fc int
		if e = rows.Scan(&ob, &pb, &at, &an, &ae, &m, &fc); e != nil {
			return p, corrupt(e)
		}
		var o model.OID
		if !copyOID(&o, ob) {
			return p, corrupt(errors.New("oid"))
		}
		i := model.SnapshotInfo{Repo: k, OID: o, CreatedAt: time.Unix(0, at).UTC(), Author: model.Identity{Name: an, Email: ae}, Message: m, FileCount: fc}
		if pb != nil {
			var po model.OID
			if !copyOID(&po, pb) {
				return p, corrupt(errors.New("parent"))
			}
			i.Parent = &po
		}
		canonical, canonicalErr := model.CanonicalSnapshotInfo(i)
		if canonicalErr != nil {
			return p, corrupt(canonicalErr)
		}
		p.Items = append(p.Items, canonical)
	}
	if e = rows.Err(); e != nil {
		return p, dbErr(ctx, e)
	}
	if len(p.Items) > l {
		p.Items = p.Items[:l]
		x := p.Items[l-1]
		n := x.CreatedAt.UnixNano()
		p.NextCursor = enc(cursor{Kind: "snapshots", Repository: sortKey(k), Timestamp: &n, OID: x.OID.String()})
	}
	return p, nil
}

func (s *Store) GetRef(ctx context.Context, k model.RepoKey, n model.RefName) (model.Ref, error) {
	if e := validRef(ctx, s, k, n, model.OID{1}); e != nil {
		return model.Ref{}, e
	}
	o, e := loadRefOID(ctx, s.db, k, n)
	if e != nil {
		return model.Ref{}, e
	}
	return model.Ref{Repo: k, Name: n, OID: o}, nil
}

func (s *Store) ListRefs(ctx context.Context, k model.RepoKey, q catalog.RefQuery) (catalog.RefPage, error) {
	if e := validKey(ctx, s, k); e != nil {
		return catalog.RefPage{}, e
	}
	l, e := limit(q.Limit)
	if e != nil {
		return catalog.RefPage{}, e
	}
	var after model.RefName
	hasAfter := false
	if q.Cursor != "" {
		c, x := dec(q.Cursor)
		name, nameErr := model.ParseRefName(c.Last)
		if x != nil || nameErr != nil || c.Kind != "refs" || c.Repository != sortKey(k) ||
			c.Namespace != "" || c.RepoType != "" || c.Prefix != "" || c.Timestamp != nil || c.OID != "" {
			return catalog.RefPage{}, invalid(errors.New("bad cursor"))
		}
		after = name
		hasAfter = true
	}
	if _, e := s.GetRepository(ctx, k); e != nil {
		return catalog.RefPage{}, e
	}
	rows, e := s.db.QueryContext(ctx, `SELECT r.ref_name,r.oid,s.oid FROM refs r
LEFT JOIN snapshots s ON s.repo_type=r.repo_type AND s.namespace=r.namespace AND s.name=r.name AND s.oid=r.oid
WHERE r.repo_type=? AND r.namespace=? AND r.name=? AND (?=0 OR r.ref_name>?)
ORDER BY r.ref_name COLLATE BINARY LIMIT ?`, append(kargs(k), boolInt(hasAfter), after, l+1)...)
	if e != nil {
		return catalog.RefPage{}, dbErr(ctx, e)
	}
	defer rows.Close() //nolint:errcheck // rows.Err reports iteration failures.
	p := catalog.RefPage{}
	for rows.Next() {
		var name string
		var encoded, target []byte
		if e = rows.Scan(&name, &encoded, &target); e != nil {
			return p, corrupt(e)
		}
		parsed, parseErr := model.ParseRefName(name)
		var oid, targetOID model.OID
		if parseErr != nil || !copyOID(&oid, encoded) || !copyOID(&targetOID, target) || oid != targetOID {
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
	if len(p.Items) > l {
		p.Items = p.Items[:l]
		p.NextCursor = enc(cursor{Kind: "refs", Repository: sortKey(k), Last: string(p.Items[l-1].Name)})
	}
	return p, nil
}

func (s *Store) CompareAndSwapRef(ctx context.Context, k model.RepoKey, n model.RefName, expected *model.OID, newOID model.OID) error {
	if e := validRef(ctx, s, k, n, newOID); e != nil {
		return e
	}
	ex, has, e := copyExpected(expected)
	if e != nil {
		return e
	}
	tx, e := s.beginWrite(ctx)
	if e != nil {
		return e
	}
	defer tx.Rollback() //nolint:errcheck // Commit below determines the result.
	var dummy int
	if e = tx.QueryRowContext(ctx, "SELECT 1 FROM snapshots WHERE repo_type=? AND namespace=? AND name=? AND oid=?", append(kargs(k), newOID[:])...).Scan(&dummy); e != nil {
		return rowErr(ctx, e)
	}
	cur, e := loadRefOID(ctx, tx, k, n)
	exists := e == nil
	if e != nil && !errors.Is(e, catalog.ErrNotFound) {
		return e
	}
	if exists && cur == newOID {
		return dbErr(ctx, tx.Commit())
	}
	if exists != has || (exists && cur != ex) {
		return fmt.Errorf("%w", catalog.ErrConflict)
	}
	_, e = tx.ExecContext(ctx, "INSERT INTO refs VALUES(?,?,?,?,?) ON CONFLICT(repo_type,namespace,name,ref_name) DO UPDATE SET oid=excluded.oid", append(kargs(k), n, newOID[:])...)
	if e != nil {
		return dbErr(ctx, e)
	}
	return dbErr(ctx, tx.Commit())
}

func (s *Store) PublishSnapshot(ctx context.Context, snap model.Snapshot, x catalog.RefExpectation) error {
	if e := s.check(ctx); e != nil {
		return e
	}
	c, e := model.CanonicalSnapshot(snap)
	if e != nil {
		return invalid(e)
	}
	var ex model.OID
	var has bool
	if x.UpdatesRef() {
		if e = validRef(ctx, s, c.Repo, x.Name, c.OID); e != nil {
			return e
		}
		ex, has, e = copyExpected(x.OID)
		if e != nil {
			return e
		}
		if has && (c.Parent == nil || *c.Parent != ex) {
			return invalid(errors.New("parent does not match expected ref"))
		}
	}
	fp, _ := model.FingerprintSnapshot(c)
	tx, e := s.beginWrite(ctx)
	if e != nil {
		return e
	}
	defer tx.Rollback() //nolint:errcheck // Commit below determines the result.
	var repoCount, snapshotCount int
	if e = tx.QueryRowContext(ctx, "SELECT count(*) FROM repositories WHERE repo_type=? AND namespace=? AND name=?", kargs(c.Repo)...).Scan(&repoCount); e != nil {
		return dbErr(ctx, e)
	}
	if repoCount == 0 {
		return fmt.Errorf("%w", catalog.ErrNotFound)
	}
	if e = tx.QueryRowContext(ctx, "SELECT count(*) FROM snapshots WHERE repo_type=? AND namespace=? AND name=?", kargs(c.Repo)...).Scan(&snapshotCount); e != nil {
		return dbErr(ctx, e)
	}
	var existing []byte
	var existingVersion int
	e = scanOne(ctx, tx, "SELECT fingerprint,fingerprint_version FROM snapshots WHERE repo_type=? AND namespace=? AND name=? AND oid=?", append(kargs(c.Repo), c.OID[:]), func(row scanner) error {
		return row.Scan(&existing, &existingVersion)
	})
	snapExists := e == nil
	if e != nil && !errors.Is(e, catalog.ErrNotFound) {
		return e
	}
	if snapExists {
		if len(existing) != len(fp) || existingVersion != model.SnapshotFingerprintVersion {
			return corrupt(errors.New("invalid retained snapshot fingerprint"))
		}
		retained, loadErr := loadSnapshotFrom(ctx, tx, c.Repo, c.OID)
		if loadErr != nil {
			return loadErr
		}
		retainedFingerprint, _ := model.FingerprintSnapshot(retained)
		if retainedFingerprint != fp || !equal(existing, fp[:]) {
			return fmt.Errorf("%w", catalog.ErrConflict)
		}
	}
	if snapExists && !x.UpdatesRef() {
		return dbErr(ctx, tx.Commit())
	}
	if x.UpdatesRef() {
		cur, refErr := loadRefOID(ctx, tx, c.Repo, x.Name)
		refExists := refErr == nil
		if refErr != nil && !errors.Is(refErr, catalog.ErrNotFound) {
			return refErr
		}
		if snapExists && refExists && cur == c.OID {
			return dbErr(ctx, tx.Commit())
		}
		if refExists != has || (refExists && cur != ex) {
			return fmt.Errorf("%w", catalog.ErrConflict)
		}
	}
	if c.Parent != nil {
		var n int
		if e = tx.QueryRowContext(ctx, "SELECT count(*) FROM snapshots WHERE repo_type=? AND namespace=? AND name=? AND oid=?", append(kargs(c.Repo), c.Parent[:])...).Scan(&n); e != nil {
			return dbErr(ctx, e)
		}
		if n == 0 {
			return fmt.Errorf("%w", catalog.ErrNotFound)
		}
	} else {
		if snapshotCount != 0 {
			return invalid(errors.New("second root"))
		}
		var refCount int
		if e = tx.QueryRowContext(ctx, "SELECT count(*) FROM refs WHERE repo_type=? AND namespace=? AND name=?", kargs(c.Repo)...).Scan(&refCount); e != nil {
			return dbErr(ctx, e)
		}
		if refCount != 0 {
			return corrupt(errors.New("refs exist without snapshots"))
		}
	}
	if !snapExists {
		var parent any
		if c.Parent != nil {
			parent = c.Parent[:]
		}
		_, e = tx.ExecContext(ctx, "INSERT INTO snapshots VALUES(?,?,?,?,?,?,?,?,?,?,?,?)", c.Repo.Type, c.Repo.Namespace, c.Repo.Name, c.OID[:], parent, c.CreatedAt.UnixNano(), c.Author.Name, c.Author.Email, c.Message, len(c.Files), fp[:], model.SnapshotFingerprintVersion)
		if e != nil {
			return dbErr(ctx, e)
		}
		for _, f := range c.Files {
			kind, size, sha, xh := fileParts(f.Ref)
			_, e = tx.ExecContext(ctx, "INSERT INTO files VALUES(?,?,?,?,?,?,?,?,?)", c.Repo.Type, c.Repo.Namespace, c.Repo.Name, c.OID[:], f.Path, kind, size, sha, xh)
			if e != nil {
				return dbErr(ctx, e)
			}
		}
	}
	if s.testHook != nil {
		if e = s.testHook("after-insert"); e != nil {
			return e
		}
	}
	if x.UpdatesRef() {
		_, e = tx.ExecContext(ctx, "INSERT INTO refs VALUES(?,?,?,?,?) ON CONFLICT(repo_type,namespace,name,ref_name) DO UPDATE SET oid=excluded.oid", c.Repo.Type, c.Repo.Namespace, c.Repo.Name, x.Name, c.OID[:])
		if e != nil {
			return dbErr(ctx, e)
		}
		if s.testHook != nil {
			if e = s.testHook("after-ref"); e != nil {
				return e
			}
		}
	}
	if x.UpdatesRef() && !snapExists && snapshotCount == 0 {
		_, e = tx.ExecContext(ctx, "INSERT INTO refs VALUES(?,?,?,?,?) ON CONFLICT(repo_type,namespace,name,ref_name) DO UPDATE SET oid=excluded.oid", c.Repo.Type, c.Repo.Namespace, c.Repo.Name, "main", c.OID[:])
		if e != nil {
			return dbErr(ctx, e)
		}
	}
	return dbErr(ctx, tx.Commit())
}

func (s *Store) GetFile(ctx context.Context, k model.RepoKey, r model.Revision, p model.FilePath) (model.FileEntry, error) {
	if e := validKey(ctx, s, k); e != nil {
		return model.FileEntry{}, e
	}
	path, e := model.ParseFilePath(string(p))
	if e != nil {
		return model.FileEntry{}, invalid(e)
	}
	oid, e := resolveOID(ctx, s.db, k, r)
	if e != nil {
		return model.FileEntry{}, e
	}
	var file model.FileEntry
	e = scanOne(ctx, s.db, `SELECT path,kind,size,sha256,xet_hash FROM files
WHERE repo_type=? AND namespace=? AND name=? AND oid=? AND path=?`, append(kargs(k), oid[:], path), func(row scanner) error {
		var scanErr error
		file, scanErr = scanFile(row)
		return scanErr
	})
	if e != nil {
		return model.FileEntry{}, e
	}
	return file, nil
}
func (s *Store) ListFiles(ctx context.Context, k model.RepoKey, r model.Revision, q catalog.FileQuery) (catalog.FilePage, error) {
	if e := validKey(ctx, s, k); e != nil {
		return catalog.FilePage{}, e
	}
	l, e := limit(q.Limit)
	if e != nil {
		return catalog.FilePage{}, e
	}
	prefix, e := model.ParseFilePrefix(string(q.Prefix))
	if e != nil {
		return catalog.FilePage{}, invalid(e)
	}
	oid, e := resolveOID(ctx, s.db, k, r)
	if e != nil {
		return catalog.FilePage{}, e
	}
	if e = ensureSnapshotExists(ctx, s.db, k, oid); e != nil {
		return catalog.FilePage{}, e
	}
	after := ""
	if q.Cursor != "" {
		c, x := dec(q.Cursor)
		path, pathErr := model.ParseFilePath(c.Last)
		if x != nil || c.Kind != "files" || c.Repository != sortKey(k) || c.Prefix != string(prefix) ||
			c.Namespace != "" || c.RepoType != "" || c.Timestamp != nil || pathErr != nil ||
			(prefix != "" && !strings.HasPrefix(string(path), string(prefix))) {
			return catalog.FilePage{}, invalid(errors.New("bad cursor"))
		}
		o, x := model.ParseOID(c.OID)
		if x != nil {
			return catalog.FilePage{}, invalid(x)
		}
		if o != oid {
			return catalog.FilePage{}, fmt.Errorf("%w", catalog.ErrConflict)
		}
		after = c.Last
	}
	comparison := ">="
	start := string(prefix)
	if after != "" {
		comparison, start = ">", after
	}
	query := `SELECT path,kind,size,sha256,xet_hash FROM files
WHERE repo_type=? AND namespace=? AND name=? AND oid=? AND path ` + comparison + ` ?
ORDER BY path COLLATE BINARY LIMIT ?`
	rows, e := s.db.QueryContext(ctx, query, append(kargs(k), oid[:], start, l+1)...)
	if e != nil {
		return catalog.FilePage{}, dbErr(ctx, e)
	}
	defer rows.Close() //nolint:errcheck // rows.Err reports iteration failures.
	p := catalog.FilePage{SnapshotOID: oid}
	for rows.Next() {
		file, scanErr := scanFile(rows)
		if scanErr != nil {
			if errors.Is(scanErr, catalog.ErrCorrupt) {
				return catalog.FilePage{}, scanErr
			}
			return catalog.FilePage{}, rowErr(ctx, scanErr)
		}
		if prefix != "" && !strings.HasPrefix(string(file.Path), string(prefix)) {
			break
		}
		p.Items = append(p.Items, file)
	}
	if e = rows.Err(); e != nil {
		return catalog.FilePage{}, dbErr(ctx, e)
	}
	if len(p.Items) > l {
		p.Items = p.Items[:l]
		p.NextCursor = enc(cursor{Kind: "files", Repository: sortKey(k), Prefix: string(prefix), Last: string(p.Items[l-1].Path), OID: oid.String()})
	}
	return p, nil
}

type scanner interface{ Scan(...any) error }

func scanOne(ctx context.Context, source queryer, query string, args []any, scan func(scanner) error) error {
	rows, err := source.QueryContext(ctx, query, args...)
	if err != nil {
		return dbErr(ctx, err)
	}
	if !rows.Next() {
		iterationErr := rows.Err()
		closeErr := rows.Close()
		if iterationErr != nil {
			return dbErr(ctx, iterationErr)
		}
		if closeErr != nil {
			return dbErr(ctx, closeErr)
		}
		return fmt.Errorf("%w", catalog.ErrNotFound)
	}
	if err = scan(rows); err != nil {
		_ = rows.Close()
		if errors.Is(err, catalog.ErrCorrupt) {
			return err
		}
		return corrupt(err)
	}
	if rows.Next() {
		_ = rows.Close()
		return corrupt(errors.New("non-unique row"))
	}
	if err = rows.Err(); err != nil {
		_ = rows.Close()
		return dbErr(ctx, err)
	}
	return dbErr(ctx, rows.Close())
}

func scanFile(r scanner) (model.FileEntry, error) {
	var p, k string
	var size int64
	var sha, xh []byte
	if e := r.Scan(&p, &k, &size, &sha, &xh); e != nil {
		return model.FileEntry{}, e
	}
	path, e := model.ParseFilePath(p)
	if e != nil {
		return model.FileEntry{}, corrupt(e)
	}
	var ref model.FileRef
	if k == "blob" && len(sha) == 32 && xh == nil {
		var a [32]byte
		copy(a[:], sha)
		ref, e = model.NewBlobFileRef(a, size)
	} else if k == "xet" && len(xh) == 32 {
		var h xethash.Hash
		copy(h[:], xh)
		var a *[32]byte
		if sha != nil {
			if len(sha) != 32 {
				return model.FileEntry{}, corrupt(errors.New("sha"))
			}
			a = new([32]byte)
			copy(a[:], sha)
		}
		ref, e = model.NewXetFileRef(h, size, a)
	} else {
		return model.FileEntry{}, corrupt(errors.New("file encoding"))
	}
	if e != nil {
		return model.FileEntry{}, corrupt(e)
	}
	return model.FileEntry{Path: path, Ref: ref}, nil
}

func ensureSnapshotExists(ctx context.Context, source queryer, key model.RepoKey, oid model.OID) error {
	var exists int
	err := scanOne(ctx, source, "SELECT 1 FROM snapshots WHERE repo_type=? AND namespace=? AND name=? AND oid=?",
		append(kargs(key), oid[:]), func(row scanner) error { return row.Scan(&exists) })
	if err != nil {
		return err
	}
	return nil
}
func fileParts(r model.FileRef) (string, int64, any, any) {
	sha, has := r.SHA256()
	var s any
	if has {
		s = sha[:]
	}
	if h, ok := r.XetHash(); ok {
		return string(model.FileKindXet), r.FileSize(), s, h[:]
	}
	return string(model.FileKindBlob), r.FileSize(), s, nil
}
func validKey(ctx context.Context, s *Store, k model.RepoKey) error {
	if e := s.check(ctx); e != nil {
		return e
	}
	if e := model.ValidateRepoKey(k); e != nil {
		return invalid(e)
	}
	return nil
}
func validRef(ctx context.Context, s *Store, k model.RepoKey, n model.RefName, o model.OID) error {
	if e := s.check(ctx); e != nil {
		return e
	}
	if e := model.ValidateRef(model.Ref{Repo: k, Name: n, OID: o}); e != nil {
		return invalid(e)
	}
	return nil
}
func copyExpected(p *model.OID) (model.OID, bool, error) {
	if p == nil {
		return model.OID{}, false, nil
	}
	o := *p
	if o.IsZero() {
		return o, false, invalid(errors.New("zero expected oid"))
	}
	return o, true, nil
}
func copyOID(dst *model.OID, b []byte) bool {
	if len(b) != 20 {
		return false
	}
	copy(dst[:], b)
	return !dst.IsZero()
}
func equal(a, b []byte) bool { return string(a) == string(b) }
func boolInt(v bool) int {
	if v {
		return 1
	}
	return 0
}
func sqliteCode(e error) int {
	var c interface{ Code() int }
	if errors.As(e, &c) {
		return c.Code() & 255
	}
	return 0
}
func rowErr(ctx context.Context, e error) error {
	if errors.Is(e, sql.ErrNoRows) {
		return fmt.Errorf("%w", catalog.ErrNotFound)
	}
	if e == nil {
		return nil
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if code := sqliteCode(e); code != 0 {
		return dbErr(ctx, e)
	}
	if errors.Is(e, sql.ErrConnDone) {
		return unavailable(e)
	}
	// QueryRow.Scan reports retained-value conversion failures without a
	// driver error code. A syntactically valid query reaching this branch has
	// encountered data that does not conform to the v1 schema.
	return corrupt(e)
}
func dbErr(ctx context.Context, e error) error {
	if e == nil {
		return nil
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if code := sqliteCode(e); code == sqliteCorrupt || code == sqliteNotADB {
		return corrupt(e)
	}
	return unavailable(e)
}
func schemaErr(ctx context.Context, e error) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if code := sqliteCode(e); code == sqliteError || code == sqliteSchema {
		return corrupt(e)
	}
	return dbErr(ctx, e)
}
func invalid(e error) error     { return fmt.Errorf("%w: %v", catalog.ErrInvalid, e) }
func corrupt(e error) error     { return fmt.Errorf("%w: %v", catalog.ErrCorrupt, e) }
func unavailable(e error) error { return fmt.Errorf("%w: %v", catalog.ErrUnavailable, e) }
