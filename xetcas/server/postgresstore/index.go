package postgresstore

import (
	"bytes"
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"reflect"
	"slices"

	"github.com/jackc/pgx/v5"
	"github.com/jmwoliver/xet-go/xetcas/server"
	"github.com/jmwoliver/xet-go/xethash"
)

func enc(v any) ([]byte, error) {
	b, e := json.Marshal(v)
	if e != nil {
		return nil, e
	}
	return b, nil
}
func dec(b []byte, v any) error {
	if err := json.Unmarshal(b, v); err != nil {
		return fmt.Errorf("%w: malformed PostgreSQL JSON record", server.ErrCorrupt)
	}
	return nil
}
func hash(b []byte) (xethash.Hash, error) {
	if len(b) != 32 {
		return xethash.Hash{}, fmt.Errorf("%w: malformed hash", server.ErrCorrupt)
	}
	var h xethash.Hash
	copy(h[:], b)
	return h, nil
}
func size64(n uint64) (int64, error) {
	if n > math.MaxInt64 {
		return 0, fmt.Errorf("%w: size exceeds PostgreSQL bigint", server.ErrInvalid)
	}
	return int64(n), nil
}
func validShard(k server.BlobKey) bool { return k.Kind == server.BlobShard && k.Hash != xethash.Zero }
func validXorb(h xethash.Hash, r server.XorbRecord) bool {
	return r.Blob.Kind == server.BlobXorb && r.Blob.Hash == h && r.Layout.Hash == h
}
func validFile(h xethash.Hash, r server.FileRecord) bool {
	return r.File.File.Hash == h && validShard(r.Shard)
}

func (s *Store) GetXorb(c context.Context, h xethash.Hash) (server.XorbRecord, bool, error) {
	var b []byte
	e := s.pool.QueryRow(c, `SELECT record FROM `+s.t("xorbs")+` WHERE hash=$1`, h[:]).Scan(&b)
	if errors.Is(e, pgx.ErrNoRows) {
		return server.XorbRecord{}, false, nil
	}
	if e != nil {
		return server.XorbRecord{}, false, e
	}
	var r server.XorbRecord
	if e = dec(b, &r); e != nil || !validXorb(h, r) {
		if e == nil {
			e = server.ErrCorrupt
		}
		return r, false, e
	}
	return r, true, nil
}
func (s *Store) PutXorb(c context.Context, r server.XorbRecord) error {
	if !validXorb(r.Layout.Hash, r) {
		return server.ErrInvalid
	}
	b, e := enc(r)
	if e != nil {
		return e
	}
	tag, e := s.pool.Exec(c, `INSERT INTO `+s.t("xorbs")+` VALUES($1,$2) ON CONFLICT DO NOTHING`, r.Layout.Hash[:], b)
	if e != nil {
		return e
	}
	if tag.RowsAffected() > 0 {
		return nil
	}
	old, ok, e := s.GetXorb(c, r.Layout.Hash)
	if e != nil {
		return e
	}
	if !ok || !reflect.DeepEqual(old, r) {
		return server.ErrConflict
	}
	return nil
}
func (s *Store) getJSON(c context.Context, table, col, ns string, h xethash.Hash, out any) (bool, error) {
	var b []byte
	e := s.pool.QueryRow(c, `SELECT record FROM `+s.t(table)+` WHERE namespace=$1 AND `+col+`=$2`, ns, h[:]).Scan(&b)
	if errors.Is(e, pgx.ErrNoRows) {
		return false, nil
	}
	if e != nil {
		return false, e
	}
	return true, dec(b, out)
}
func (s *Store) GetShard(c context.Context, n string, h xethash.Hash) (server.ShardRecord, bool, error) {
	var r server.ShardRecord
	ok, e := s.getJSON(c, "shards", "hash", n, h, &r)
	if e == nil && ok && (!validShard(r.Blob) || r.Blob.Hash != h) {
		e = server.ErrCorrupt
	}
	return r, ok && e == nil, e
}
func (s *Store) GetFile(c context.Context, n string, h xethash.Hash) (server.FileRecord, bool, error) {
	var r server.FileRecord
	ok, e := s.getJSON(c, "files", "hash", n, h, &r)
	if e == nil && ok && !validFile(h, r) {
		e = server.ErrCorrupt
	}
	return r, ok && e == nil, e
}
func (s *Store) PutFile(c context.Context, n string, r server.FileRecord) error {
	if !validFile(r.File.File.Hash, r) {
		return server.ErrInvalid
	}
	b, e := enc(r)
	if e != nil {
		return e
	}
	tag, e := s.pool.Exec(c, `INSERT INTO `+s.t("files")+` VALUES($1,$2,$3) ON CONFLICT DO NOTHING`, n, r.File.File.Hash[:], b)
	if e != nil || tag.RowsAffected() > 0 {
		return e
	}
	// File recipes are non-unique. Retaining a different recipe is valid, but
	// retaining malformed metadata is not.
	_, found, e := s.GetFile(c, n, r.File.File.Hash)
	if e != nil {
		return e
	}
	if !found {
		return server.ErrConflict
	}
	return nil
}
func (s *Store) GetDedup(c context.Context, n string, h xethash.Hash) (server.DedupRecord, bool, error) {
	var r server.DedupRecord
	ok, e := s.getJSON(c, "dedup", "chunk_hash", n, h, &r)
	if e == nil && ok && !validShard(r.Shard) {
		e = server.ErrCorrupt
	}
	return r, ok && e == nil, e
}
func (s *Store) PutDedup(c context.Context, n string, h xethash.Hash, r server.DedupRecord) error {
	if !validShard(r.Shard) {
		return server.ErrInvalid
	}
	b, e := enc(r)
	if e != nil {
		return e
	}
	tag, e := s.pool.Exec(c, `INSERT INTO `+s.t("dedup")+` VALUES($1,$2,$3) ON CONFLICT DO NOTHING`, n, h[:], b)
	if e != nil || tag.RowsAffected() > 0 {
		return e
	}
	_, found, e := s.GetDedup(c, n, h)
	if e != nil {
		return e
	}
	if !found {
		return server.ErrConflict
	}
	return nil
}
func (s *Store) ResolveSHA256(c context.Context, n string, sum [32]byte, z uint64) (xethash.Hash, bool, error) {
	sz, e := size64(z)
	if e != nil {
		return xethash.Hash{}, false, e
	}
	var b []byte
	e = s.pool.QueryRow(c, `SELECT file_hash FROM `+s.t("sha256_associations")+` WHERE namespace=$1 AND sum=$2 AND size=$3`, n, sum[:], sz).Scan(&b)
	if errors.Is(e, pgx.ErrNoRows) {
		return xethash.Hash{}, false, nil
	}
	if e != nil {
		return xethash.Hash{}, false, e
	}
	h, e := hash(b)
	return h, e == nil, e
}
func (s *Store) PutSHA256(c context.Context, n string, sum [32]byte, z uint64, h xethash.Hash) error {
	sz, e := size64(z)
	if e != nil {
		return e
	}
	tag, e := s.pool.Exec(c, `INSERT INTO `+s.t("sha256_associations")+` VALUES($1,$2,$3,$4) ON CONFLICT DO NOTHING`, n, sum[:], sz, h[:])
	if e != nil {
		return e
	}
	if tag.RowsAffected() > 0 {
		return nil
	}
	old, ok, e := s.ResolveSHA256(c, n, sum, z)
	if e != nil {
		return e
	}
	if !ok || old != h {
		return server.ErrConflict
	}
	return nil
}

func (s *Store) PublishShard(c context.Context, p server.ShardPublication) error {
	if !validShard(p.Shard) {
		return server.ErrInvalid
	}
	seen := map[[40]byte]xethash.Hash{}
	for _, a := range p.Dedup {
		if a.Value.Shard != p.Shard {
			return server.ErrInvalid
		}
	}
	for _, r := range p.Files {
		if r.Shard != p.Shard || !validFile(r.File.File.Hash, r) {
			return server.ErrInvalid
		}
	}
	for _, a := range p.SHA256 {
		z, e := size64(a.Size)
		if e != nil {
			return e
		}
		var k [40]byte
		copy(k[:32], a.Sum[:])
		for i := 0; i < 8; i++ {
			k[32+i] = byte(uint64(z) >> uint(56-8*i))
		}
		if h, ok := seen[k]; ok && h != a.File {
			return server.ErrConflict
		}
		seen[k] = a.File
	}
	// PostgreSQL's unique indexes lock conflicting keys. Stable key ordering
	// prevents otherwise-idempotent concurrent publications with differently
	// ordered input slices from deadlocking. Clone first so callers may safely
	// reuse a publication concurrently.
	dedup := slices.Clone(p.Dedup)
	slices.SortFunc(dedup, func(left, right server.DedupAssociation) int {
		return bytes.Compare(left.Chunk[:], right.Chunk[:])
	})
	sha256 := slices.Clone(p.SHA256)
	slices.SortFunc(sha256, func(left, right server.SHA256Association) int {
		if order := bytes.Compare(left.Sum[:], right.Sum[:]); order != 0 {
			return order
		}
		return cmp.Compare(left.Size, right.Size)
	})
	files := slices.Clone(p.Files)
	slices.SortFunc(files, func(left, right server.FileRecord) int {
		return bytes.Compare(left.File.File.Hash[:], right.File.File.Hash[:])
	})
	tx, e := s.pool.Begin(c)
	if e != nil {
		return e
	}
	defer rollback(tx)
	for _, a := range dedup {
		b, encodeErr := enc(a.Value)
		if encodeErr != nil {
			return encodeErr
		}
		if _, e = tx.Exec(c, `INSERT INTO `+s.t("dedup")+` VALUES($1,$2,$3) ON CONFLICT DO NOTHING`, p.Namespace, a.Chunk[:], b); e != nil {
			return e
		}
		var retained []byte
		if e = tx.QueryRow(c, `SELECT record FROM `+s.t("dedup")+` WHERE namespace=$1 AND chunk_hash=$2`, p.Namespace, a.Chunk[:]).Scan(&retained); e != nil {
			return e
		}
		var r server.DedupRecord
		if dec(retained, &r) != nil || !validShard(r.Shard) {
			return server.ErrCorrupt
		}
	}
	for _, a := range sha256 {
		z, _ := size64(a.Size)
		if _, e = tx.Exec(c, `INSERT INTO `+s.t("sha256_associations")+` VALUES($1,$2,$3,$4) ON CONFLICT DO NOTHING`, p.Namespace, a.Sum[:], z, a.File[:]); e != nil {
			return e
		}
		var h []byte
		if e = tx.QueryRow(c, `SELECT file_hash FROM `+s.t("sha256_associations")+` WHERE namespace=$1 AND sum=$2 AND size=$3`, p.Namespace, a.Sum[:], z).Scan(&h); e != nil {
			return e
		}
		retainedHash, hashErr := hash(h)
		if hashErr != nil {
			return hashErr
		}
		if retainedHash != a.File {
			return server.ErrConflict
		}
	}
	for _, r := range files {
		b, encodeErr := enc(r)
		if encodeErr != nil {
			return encodeErr
		}
		if _, e = tx.Exec(c, `INSERT INTO `+s.t("files")+` VALUES($1,$2,$3) ON CONFLICT DO NOTHING`, p.Namespace, r.File.File.Hash[:], b); e != nil {
			return e
		}
		var retained []byte
		if e = tx.QueryRow(c, `SELECT record FROM `+s.t("files")+` WHERE namespace=$1 AND hash=$2`, p.Namespace, r.File.File.Hash[:]).Scan(&retained); e != nil {
			return e
		}
		var v server.FileRecord
		if dec(retained, &v) != nil || !validFile(r.File.File.Hash, v) {
			return server.ErrCorrupt
		}
	}
	r := server.ShardRecord{Blob: p.Shard}
	b, e := enc(r)
	if e != nil {
		return e
	}
	if _, e = tx.Exec(c, `INSERT INTO `+s.t("shards")+` VALUES($1,$2,$3) ON CONFLICT DO NOTHING`, p.Namespace, p.Shard.Hash[:], b); e != nil {
		return e
	}
	var retained []byte
	if e = tx.QueryRow(c, `SELECT record FROM `+s.t("shards")+` WHERE namespace=$1 AND hash=$2`, p.Namespace, p.Shard.Hash[:]).Scan(&retained); e != nil {
		return e
	}
	var v server.ShardRecord
	if dec(retained, &v) != nil || v != r {
		return server.ErrCorrupt
	}
	return tx.Commit(c)
}
