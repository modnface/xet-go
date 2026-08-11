package postgresstore

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jmwoliver/xet-go/xetcas/server"
	"github.com/jmwoliver/xet-go/xethash"
)

func nanotime(t time.Time) (int64, error) {
	t = t.UTC()
	if t.IsZero() || !time.Unix(0, t.UnixNano()).Equal(t) {
		return 0, fmt.Errorf("%w: invalid protection timestamp", server.ErrInvalid)
	}
	return t.UnixNano(), nil
}
func stageValid(v server.BlobStage) error {
	c, e := nanotime(v.CreatedAt)
	if e != nil {
		return e
	}
	x, e := nanotime(v.ExpiresAt)
	if e != nil || x <= c || v.ID == (server.ProtectionID{}) ||
		v.Blob.Kind != server.BlobXorb && v.Blob.Kind != server.BlobShard || v.Blob.Hash == xethash.Zero {
		return fmt.Errorf("%w: invalid blob stage", server.ErrInvalid)
	}
	return nil
}
func leaseValid(v server.FileLease) error {
	c, e := nanotime(v.CreatedAt)
	if e != nil {
		return e
	}
	x, e := nanotime(v.ExpiresAt)
	if e != nil || x <= c || v.ID == (server.ProtectionID{}) {
		return fmt.Errorf("%w: invalid file lease", server.ErrInvalid)
	}
	return nil
}

type scanner interface{ Scan(...any) error }

func scanStage(r scanner) (server.BlobStage, error) {
	var n, k string
	var id, h []byte
	var c, x int64
	if e := r.Scan(&n, &id, &k, &h, &c, &x); e != nil {
		return server.BlobStage{}, e
	}
	hh, e := hash(h)
	if e != nil || len(id) != 16 {
		return server.BlobStage{}, server.ErrCorrupt
	}
	var i server.ProtectionID
	copy(i[:], id)
	v := server.BlobStage{ID: i, Namespace: n, Blob: server.BlobKey{Kind: server.BlobKind(k), Hash: hh}, CreatedAt: time.Unix(0, c).UTC(), ExpiresAt: time.Unix(0, x).UTC()}
	if stageValid(v) != nil {
		return v, server.ErrCorrupt
	}
	return v, nil
}
func scanLease(r scanner) (server.FileLease, error) {
	var n string
	var id, h []byte
	var c, x int64
	if e := r.Scan(&n, &id, &h, &c, &x); e != nil {
		return server.FileLease{}, e
	}
	hh, e := hash(h)
	if e != nil || len(id) != 16 {
		return server.FileLease{}, server.ErrCorrupt
	}
	var i server.ProtectionID
	copy(i[:], id)
	v := server.FileLease{ID: i, Namespace: n, File: hh, CreatedAt: time.Unix(0, c).UTC(), ExpiresAt: time.Unix(0, x).UTC()}
	if leaseValid(v) != nil {
		return v, server.ErrCorrupt
	}
	return v, nil
}

func (s *Store) getBlobStage(c context.Context, namespace string, id server.ProtectionID) (server.BlobStage, bool, error) {
	row := s.pool.QueryRow(c, `SELECT namespace,id,blob_kind,blob_hash,created_at,expires_at FROM `+
		s.t("blob_stages")+` WHERE namespace=$1 AND id=$2`, namespace, id[:])
	stage, err := scanStage(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return server.BlobStage{}, false, nil
	}
	return stage, err == nil, err
}

func (s *Store) getFileLease(c context.Context, namespace string, id server.ProtectionID) (server.FileLease, bool, error) {
	row := s.pool.QueryRow(c, `SELECT namespace,id,file_hash,created_at,expires_at FROM `+
		s.t("file_leases")+` WHERE namespace=$1 AND id=$2`, namespace, id[:])
	lease, err := scanLease(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return server.FileLease{}, false, nil
	}
	return lease, err == nil, err
}

func (s *Store) PutBlobStage(c context.Context, v server.BlobStage) error {
	if e := stageValid(v); e != nil {
		return e
	}
	ct, _ := nanotime(v.CreatedAt)
	xt, _ := nanotime(v.ExpiresAt)
	v.CreatedAt, v.ExpiresAt = time.Unix(0, ct).UTC(), time.Unix(0, xt).UTC()
	row := s.pool.QueryRow(c, `INSERT INTO `+s.t("blob_stages")+` VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT(namespace,id) DO UPDATE SET id=excluded.id WHERE blob_stages.blob_kind=excluded.blob_kind AND blob_stages.blob_hash=excluded.blob_hash AND blob_stages.created_at=excluded.created_at AND blob_stages.expires_at=excluded.expires_at RETURNING namespace,id,blob_kind,blob_hash,created_at,expires_at`, v.Namespace, v.ID[:], v.Blob.Kind, v.Blob.Hash[:], ct, xt)
	got, e := scanStage(row)
	if errors.Is(e, pgx.ErrNoRows) {
		if _, found, lookupErr := s.getBlobStage(c, v.Namespace, v.ID); lookupErr != nil {
			return lookupErr
		} else if !found {
			return server.ErrConflict
		}
		return server.ErrConflict
	}
	if e != nil {
		return e
	}
	if got != v {
		return server.ErrConflict
	}
	return nil
}
func (s *Store) RenewBlobStage(c context.Context, n string, id server.ProtectionID, t time.Time) error {
	x, e := nanotime(t)
	if e != nil {
		return e
	}
	row := s.pool.QueryRow(c, `UPDATE `+s.t("blob_stages")+` SET expires_at=GREATEST(expires_at,$3) WHERE namespace=$1 AND id=$2 RETURNING namespace,id,blob_kind,blob_hash,created_at,expires_at`, n, id[:], x)
	stage, e := scanStage(row)
	if errors.Is(e, pgx.ErrNoRows) {
		return server.ErrNotFound
	}
	if e != nil {
		return e
	}
	if stage.Namespace != n || stage.ID != id || stage.ExpiresAt.Before(time.Unix(0, x)) {
		return server.ErrCorrupt
	}
	return nil
}
func (s *Store) DeleteBlobStage(c context.Context, n string, id server.ProtectionID) error {
	_, e := s.pool.Exec(c, `DELETE FROM `+s.t("blob_stages")+` WHERE namespace=$1 AND id=$2`, n, id[:])
	return e
}
func (s *Store) PutFileLease(c context.Context, v server.FileLease) error {
	if e := leaseValid(v); e != nil {
		return e
	}
	ct, _ := nanotime(v.CreatedAt)
	xt, _ := nanotime(v.ExpiresAt)
	row := s.pool.QueryRow(c, `INSERT INTO `+s.t("file_leases")+` VALUES($1,$2,$3,$4,$5) ON CONFLICT(namespace,id) DO UPDATE SET expires_at=GREATEST(file_leases.expires_at,excluded.expires_at) WHERE file_leases.file_hash=excluded.file_hash AND file_leases.created_at=excluded.created_at RETURNING namespace,id,file_hash,created_at,expires_at`, v.Namespace, v.ID[:], v.File[:], ct, xt)
	got, e := scanLease(row)
	if errors.Is(e, pgx.ErrNoRows) {
		if _, found, lookupErr := s.getFileLease(c, v.Namespace, v.ID); lookupErr != nil {
			return lookupErr
		} else if !found {
			return server.ErrConflict
		}
		return server.ErrConflict
	}
	if e != nil {
		return e
	}
	if got.Namespace != v.Namespace || got.ID != v.ID || got.File != v.File || !got.CreatedAt.Equal(v.CreatedAt) || got.ExpiresAt.Before(v.ExpiresAt) {
		return server.ErrConflict
	}
	return nil
}
func (s *Store) RenewFileLease(c context.Context, n string, id server.ProtectionID, t time.Time) error {
	x, e := nanotime(t)
	if e != nil {
		return e
	}
	row := s.pool.QueryRow(c, `UPDATE `+s.t("file_leases")+` SET expires_at=GREATEST(expires_at,$3) WHERE namespace=$1 AND id=$2 RETURNING namespace,id,file_hash,created_at,expires_at`, n, id[:], x)
	lease, e := scanLease(row)
	if errors.Is(e, pgx.ErrNoRows) {
		return server.ErrNotFound
	}
	if e != nil {
		return e
	}
	if lease.Namespace != n || lease.ID != id || lease.ExpiresAt.Before(time.Unix(0, x)) {
		return server.ErrCorrupt
	}
	return nil
}
func (s *Store) DeleteFileLease(c context.Context, n string, id server.ProtectionID) error {
	_, e := s.pool.Exec(c, `DELETE FROM `+s.t("file_leases")+` WHERE namespace=$1 AND id=$2`, n, id[:])
	return e
}
func (s *Store) DeleteExpiredBlobStage(c context.Context, n string, id server.ProtectionID, t time.Time) (bool, error) {
	if id == (server.ProtectionID{}) {
		return false, server.ErrInvalid
	}
	x, e := nanotime(t)
	if e != nil {
		return false, e
	}
	tag, e := s.pool.Exec(c, `DELETE FROM `+s.t("blob_stages")+` WHERE namespace=$1 AND id=$2 AND expires_at<=$3`, n, id[:], x)
	if e != nil {
		return false, e
	}
	return tag.RowsAffected() > 0, nil
}
func (s *Store) DeleteExpiredFileLease(c context.Context, n string, id server.ProtectionID, t time.Time) (bool, error) {
	if id == (server.ProtectionID{}) {
		return false, server.ErrInvalid
	}
	x, e := nanotime(t)
	if e != nil {
		return false, e
	}
	tag, e := s.pool.Exec(c, `DELETE FROM `+s.t("file_leases")+` WHERE namespace=$1 AND id=$2 AND expires_at<=$3`, n, id[:], x)
	if e != nil {
		return false, e
	}
	return tag.RowsAffected() > 0, nil
}
