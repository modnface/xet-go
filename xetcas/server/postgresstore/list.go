package postgresstore

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math"
	"time"

	"github.com/jmwoliver/xet-go/xetcas/server"
)

type cursor struct {
	Op     string `json:"o"`
	Mode   string `json:"m"`
	Filter string `json:"f"`
	NS     string `json:"n"`
	Key    []byte `json:"k"`
	Exp    int64  `json:"e,omitempty"`
	Cut    int64  `json:"c,omitempty"`
}

func limit(r server.PageRequest) (int, error) {
	if r.Limit == 0 {
		return server.DefaultPageSize, nil
	}
	if r.Limit < 1 || r.Limit > server.MaxPageSize {
		return 0, server.ErrInvalid
	}
	return r.Limit, nil
}
func curEncode(c cursor) string {
	b, _ := json.Marshal(c)
	return base64.RawURLEncoding.EncodeToString(b)
}
func curDecode(raw, op, mode, ns string, cut int64) (cursor, error) {
	if raw == "" {
		return cursor{}, nil
	}
	b, e := base64.RawURLEncoding.DecodeString(raw)
	if e != nil || base64.RawURLEncoding.EncodeToString(b) != raw {
		return cursor{}, server.ErrInvalid
	}
	var c cursor
	if json.Unmarshal(b, &c) != nil || curEncode(c) != raw || c.Op != op || c.Mode != mode || c.Filter != ns || c.Cut != cut {
		return cursor{}, server.ErrInvalid
	}
	return c, nil
}
func mode(n *string) (string, string) {
	if n == nil {
		return "all", ""
	}
	return "scoped", *n
}
func (s *Store) listRecords(c context.Context, table, col, op string, n *string, r server.PageRequest, scan func(string, []byte, []byte) error) (string, error) {
	l, e := limit(r)
	if e != nil {
		return "", e
	}
	m, scope := mode(n)
	u, e := curDecode(r.Cursor, op, m, scope, 0)
	if e != nil {
		return "", e
	}
	if r.Cursor != "" && (len(u.Key) != 32 || n != nil && u.NS != *n || u.Exp != 0) {
		return "", server.ErrInvalid
	}
	q := `SELECT namespace,` + col + `,record FROM ` + s.t(table)
	args := []any{}
	if n != nil {
		args = append(args, *n)
		q += ` WHERE namespace=$1`
		if len(u.Key) > 0 {
			args = append(args, u.Key)
			q += ` AND ` + col + `>$2`
		}
	} else if len(u.Key) > 0 {
		args = append(args, u.NS, u.Key)
		q += ` WHERE (namespace,` + col + `)>($1,$2)`
	}
	args = append(args, l+1)
	q += fmt.Sprintf(` ORDER BY namespace,%s LIMIT $%d`, col, len(args))
	rows, e := s.pool.Query(c, q, args...)
	if e != nil {
		return "", e
	}
	defer rows.Close()
	count := 0
	var ln string
	var lk []byte
	for rows.Next() {
		var ns string
		var k, b []byte
		if e = rows.Scan(&ns, &k, &b); e != nil {
			return "", e
		}
		if count < l {
			if e = scan(ns, k, b); e != nil {
				return "", e
			}
			ln, lk = ns, append([]byte(nil), k...)
		}
		count++
	}
	if e = rows.Err(); e != nil {
		return "", e
	}
	if count > l {
		return curEncode(cursor{Op: op, Mode: m, Filter: scope, NS: ln, Key: lk}), nil
	}
	return "", nil
}
func (s *Store) ListXorbs(c context.Context, r server.PageRequest) (server.XorbRecordPage, error) {
	l, e := limit(r)
	if e != nil {
		return server.XorbRecordPage{}, e
	}
	u, e := curDecode(r.Cursor, "xorbs", "global", "", 0)
	if e != nil {
		return server.XorbRecordPage{}, e
	}
	if r.Cursor != "" && (len(u.Key) != 32 || u.NS != "" || u.Exp != 0) {
		return server.XorbRecordPage{}, server.ErrInvalid
	}
	q := `SELECT hash,record FROM ` + s.t("xorbs")
	args := []any{}
	if len(u.Key) > 0 {
		q += ` WHERE hash>$1`
		args = append(args, u.Key)
	}
	args = append(args, l+1)
	q += fmt.Sprintf(` ORDER BY hash LIMIT $%d`, len(args))
	rows, e := s.pool.Query(c, q, args...)
	if e != nil {
		return server.XorbRecordPage{}, e
	}
	defer rows.Close()
	p := server.XorbRecordPage{}
	for rows.Next() {
		var k, b []byte
		if e = rows.Scan(&k, &b); e != nil {
			return p, e
		}
		h, e := hash(k)
		if e != nil {
			return p, e
		}
		var v server.XorbRecord
		if dec(b, &v) != nil || !validXorb(h, v) {
			return p, server.ErrCorrupt
		}
		p.Items = append(p.Items, v)
	}
	if e = rows.Err(); e != nil {
		return p, e
	}
	if len(p.Items) > l {
		p.Items = p.Items[:l]
		p.NextCursor = curEncode(cursor{Op: "xorbs", Mode: "global", Key: p.Items[l-1].Blob.Hash[:]})
	}
	return p, nil
}
func (s *Store) ListShards(c context.Context, n *string, r server.PageRequest) (p server.ShardRecordPage, e error) {
	p.Items = []server.ScopedShardRecord{}
	p.NextCursor, e = s.listRecords(c, "shards", "hash", "shards", n, r, func(ns string, k, b []byte) error {
		h, e := hash(k)
		var v server.ShardRecord
		if e != nil {
			return e
		}
		if dec(b, &v) != nil || !validShard(v.Blob) || v.Blob.Hash != h {
			return server.ErrCorrupt
		}
		p.Items = append(p.Items, server.ScopedShardRecord{Namespace: ns, Record: v})
		return nil
	})
	return
}
func (s *Store) ListFiles(c context.Context, n *string, r server.PageRequest) (p server.FileRecordPage, e error) {
	p.NextCursor, e = s.listRecords(c, "files", "hash", "files", n, r, func(ns string, k, b []byte) error {
		h, e := hash(k)
		var v server.FileRecord
		if e != nil {
			return e
		}
		if dec(b, &v) != nil || !validFile(h, v) {
			return server.ErrCorrupt
		}
		p.Items = append(p.Items, server.ScopedFileRecord{Namespace: ns, Record: v})
		return nil
	})
	return
}
func (s *Store) ListDedup(c context.Context, n *string, r server.PageRequest) (p server.DedupRecordPage, e error) {
	p.NextCursor, e = s.listRecords(c, "dedup", "chunk_hash", "dedup", n, r, func(ns string, k, b []byte) error {
		h, e := hash(k)
		var v server.DedupRecord
		if e != nil {
			return e
		}
		if dec(b, &v) != nil || !validShard(v.Shard) {
			return server.ErrCorrupt
		}
		p.Items = append(p.Items, server.ScopedDedupRecord{Namespace: ns, Chunk: h, Record: v})
		return nil
	})
	return
}
func (s *Store) ListSHA256(c context.Context, n *string, r server.PageRequest) (p server.SHA256AssociationPage, e error) {
	l, e := limit(r)
	if e != nil {
		return p, e
	}
	m, scope := mode(n)
	u, e := curDecode(r.Cursor, "sha256", m, scope, 0)
	if e != nil {
		return p, e
	}
	if r.Cursor != "" && (len(u.Key) != 40 || n != nil && u.NS != *n || u.Exp != 0) {
		return p, server.ErrInvalid
	}
	if len(u.Key) == 40 && bytesUint64(u.Key[32:]) > math.MaxInt64 {
		return p, server.ErrInvalid
	}
	q := `SELECT namespace,sum,size,file_hash FROM ` + s.t("sha256_associations")
	args := []any{}
	if n != nil {
		args = append(args, *n)
		q += ` WHERE namespace=$1`
		if len(u.Key) > 0 {
			args = append(args, u.Key[:32], int64(bytesUint64(u.Key[32:])))
			q += ` AND (sum,size)>($2,$3)`
		}
	} else if len(u.Key) > 0 {
		args = append(args, u.NS, u.Key[:32], int64(bytesUint64(u.Key[32:])))
		q += ` WHERE (namespace,sum,size)>($1,$2,$3)`
	}
	args = append(args, l+1)
	q += fmt.Sprintf(` ORDER BY namespace,sum,size LIMIT $%d`, len(args))
	rows, e := s.pool.Query(c, q, args...)
	if e != nil {
		return p, e
	}
	defer rows.Close()
	for rows.Next() {
		var ns string
		var sb, hb []byte
		var z int64
		if e = rows.Scan(&ns, &sb, &z, &hb); e != nil {
			return p, e
		}
		if len(sb) != 32 || z < 0 {
			return p, server.ErrCorrupt
		}
		h, e := hash(hb)
		if e != nil {
			return p, e
		}
		var sum [32]byte
		copy(sum[:], sb)
		p.Items = append(p.Items, server.ScopedSHA256Association{Namespace: ns, Record: server.SHA256Association{Sum: sum, Size: uint64(z), File: h}})
	}
	if e = rows.Err(); e != nil {
		return p, e
	}
	if len(p.Items) > l {
		p.Items = p.Items[:l]
		v := p.Items[l-1]
		k := append([]byte(nil), v.Record.Sum[:]...)
		k = append(k, uint64Bytes(v.Record.Size)...)
		p.NextCursor = curEncode(cursor{Op: "sha256", Mode: m, Filter: scope, NS: v.Namespace, Key: k})
	}
	return p, nil
}
func uint64Bytes(v uint64) []byte {
	b := make([]byte, 8)
	for i := 7; i >= 0; i-- {
		b[i] = byte(v)
		v >>= 8
	}
	return b
}
func bytesUint64(b []byte) uint64 {
	if len(b) != 8 {
		return ^uint64(0)
	}
	var v uint64
	for _, x := range b {
		v = v<<8 | uint64(x)
	}
	return v
}

func (s *Store) listProtection(c context.Context, table, op string, n *string, cut *time.Time, r server.PageRequest, stage bool) ([]server.BlobStage, []server.FileLease, string, error) {
	l, e := limit(r)
	if e != nil {
		return nil, nil, "", e
	}
	m, scope := mode(n)
	var cv int64
	if cut != nil {
		cv, e = nanotime(*cut)
		if e != nil {
			return nil, nil, "", e
		}
		m = "expired"
	}
	u, e := curDecode(r.Cursor, op, m, scope, cv)
	if e != nil {
		return nil, nil, "", e
	}
	if r.Cursor != "" && (len(u.Key) != 16 || cut == nil && u.Exp != 0 ||
		cut == nil && n != nil && u.NS != *n || cut != nil && u.Exp > cv) {
		return nil, nil, "", server.ErrInvalid
	}
	cols := "namespace,id,file_hash,created_at,expires_at"
	if stage {
		cols = "namespace,id,blob_kind,blob_hash,created_at,expires_at"
	}
	q := `SELECT ` + cols + ` FROM ` + s.t(table)
	args := []any{}
	if cut != nil {
		args = append(args, cv)
		q += ` WHERE expires_at<=$1`
		if len(u.Key) > 0 {
			args = append(args, u.Exp, u.NS, u.Key)
			q += ` AND (expires_at,namespace,id)>($2,$3,$4)`
		}
	} else if n != nil {
		args = append(args, *n)
		q += ` WHERE namespace=$1`
		if len(u.Key) > 0 {
			args = append(args, u.Key)
			q += ` AND id>$2`
		}
	} else if len(u.Key) > 0 {
		args = append(args, u.NS, u.Key)
		q += ` WHERE (namespace,id)>($1,$2)`
	}
	order := "namespace,id"
	if cut != nil {
		order = "expires_at,namespace,id"
	}
	args = append(args, l+1)
	q += fmt.Sprintf(` ORDER BY %s LIMIT $%d`, order, len(args))
	rows, e := s.pool.Query(c, q, args...)
	if e != nil {
		return nil, nil, "", e
	}
	defer rows.Close()
	var bs []server.BlobStage
	var fs []server.FileLease
	for rows.Next() {
		if stage {
			v, e := scanStage(rows)
			if e != nil {
				return nil, nil, "", e
			}
			bs = append(bs, v)
		} else {
			v, e := scanLease(rows)
			if e != nil {
				return nil, nil, "", e
			}
			fs = append(fs, v)
		}
	}
	if e = rows.Err(); e != nil {
		return nil, nil, "", e
	}
	count := len(bs)
	if !stage {
		count = len(fs)
	}
	next := ""
	if count > l {
		var ns string
		var id []byte
		var exp int64
		if stage {
			v := bs[l-1]
			ns, id = v.Namespace, v.ID[:]
			if cut != nil {
				exp = v.ExpiresAt.UnixNano()
			}
			bs = bs[:l]
		} else {
			v := fs[l-1]
			ns, id = v.Namespace, v.ID[:]
			if cut != nil {
				exp = v.ExpiresAt.UnixNano()
			}
			fs = fs[:l]
		}
		next = curEncode(cursor{Op: op, Mode: m, Filter: scope, NS: ns, Key: id, Exp: exp, Cut: cv})
	}
	return bs, fs, next, nil
}
func (s *Store) ListBlobStages(c context.Context, n *string, r server.PageRequest) (server.BlobStagePage, error) {
	b, _, x, e := s.listProtection(c, "blob_stages", "stages", n, nil, r, true)
	return server.BlobStagePage{Items: b, NextCursor: x}, e
}
func (s *Store) ListFileLeases(c context.Context, n *string, r server.PageRequest) (server.FileLeasePage, error) {
	_, f, x, e := s.listProtection(c, "file_leases", "leases", n, nil, r, false)
	return server.FileLeasePage{Items: f, NextCursor: x}, e
}
func (s *Store) ListExpiredBlobStages(c context.Context, t time.Time, r server.PageRequest) (server.BlobStagePage, error) {
	b, _, x, e := s.listProtection(c, "blob_stages", "expired-stages", nil, &t, r, true)
	return server.BlobStagePage{Items: b, NextCursor: x}, e
}
func (s *Store) ListExpiredFileLeases(c context.Context, t time.Time, r server.PageRequest) (server.FileLeasePage, error) {
	_, f, x, e := s.listProtection(c, "file_leases", "expired-leases", nil, &t, r, false)
	return server.FileLeasePage{Items: f, NextCursor: x}, e
}
