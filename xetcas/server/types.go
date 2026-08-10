// Package server implements the storage-neutral server half of the Xet CAS
// protocol. It deliberately contains no repository-hosting or cloud-vendor
// concepts.
package server

import (
	"context"
	"errors"
	"io"
	"time"

	"github.com/jacobwoliver/xet-go/shard"
	"github.com/jacobwoliver/xet-go/xetcas"
	"github.com/jacobwoliver/xet-go/xethash"
	"github.com/jacobwoliver/xet-go/xorb"
)

var (
	ErrNotFound     = errors.New("xet CAS server: not found")
	ErrUnauthorized = errors.New("xet CAS server: unauthorized")
	ErrForbidden    = errors.New("xet CAS server: forbidden")
	ErrConflict     = errors.New("xet CAS server: immutable value conflict")
	ErrTooLarge     = errors.New("xet CAS server: request body too large")
	ErrInvalid      = errors.New("xet CAS server: invalid request")
)

type BlobKind string

const (
	BlobXorb  BlobKind = "xorb"
	BlobShard BlobKind = "shard"
)

// BlobKey is a logical immutable storage key. Cloud-specific paths belong in
// BlobStore implementations.
type BlobKey struct {
	Kind BlobKind
	Hash xethash.Hash
}

type BlobInfo struct{ Size int64 }

// BlobStore stores immutable protocol objects. PutIfAbsent must return
// ErrConflict if a key already contains different bytes.
type BlobStore interface {
	PutIfAbsent(context.Context, BlobKey, io.Reader, int64) (inserted bool, err error)
	Head(context.Context, BlobKey) (BlobInfo, bool, error)
	Get(context.Context, BlobKey, *xetcas.HTTPRange) (io.ReadCloser, error)
}

type XorbRecord struct {
	Blob   BlobKey
	Layout xorb.Ingested
}

type FileRecord struct {
	File  shard.RegisteredFile
	Shard BlobKey
}

type DedupRecord struct {
	Shard BlobKey
}

// IndexStore xorb and SHA values are immutable and every Put operation must be
// idempotent. File and dedup keys are non-unique secondary indexes: the same
// logical content can have more than one valid shard recipe. PutFile and
// PutDedup must retain either an existing valid record or the supplied valid
// record without returning a conflict. The Service validates supplied records
// and orders calls so file records, the public reconstruction point, are
// written last.
type IndexStore interface {
	GetXorb(context.Context, xethash.Hash) (XorbRecord, bool, error)
	PutXorb(context.Context, XorbRecord) error
	GetFile(context.Context, xethash.Hash) (FileRecord, bool, error)
	PutFile(context.Context, FileRecord) error
	GetDedup(context.Context, xethash.Hash) (DedupRecord, bool, error)
	PutDedup(context.Context, xethash.Hash, DedupRecord) error
	ResolveSHA256(context.Context, string, [32]byte, uint64) (xethash.Hash, bool, error)
	PutSHA256(context.Context, string, [32]byte, uint64, xethash.Hash) error
}

type Operation string

const (
	OperationReadFile   Operation = "read-file"
	OperationReadXorb   Operation = "read-xorb"
	OperationReadDedup  Operation = "read-dedup"
	OperationWriteXorb  Operation = "write-xorb"
	OperationWriteShard Operation = "write-shard"
)

type AccessRequest struct {
	Operation Operation
	Prefix    string
	Hash      xethash.Hash
}

// Grant contains storage-index scope derived from a generic CAS credential.
// Namespace is used only for scoped SHA-256 associations.
type Grant struct{ Namespace string }

type Authorizer interface {
	Authorize(context.Context, string, AccessRequest) (Grant, error)
}

type RangeURLSigner interface {
	SignRange(context.Context, BlobKey, xetcas.HTTPRange) (string, error)
}

type RangeURLSignerFunc func(context.Context, BlobKey, xetcas.HTTPRange) (string, error)

func (f RangeURLSignerFunc) SignRange(ctx context.Context, key BlobKey, value xetcas.HTTPRange) (string, error) {
	return f(ctx, key, value)
}

type Options struct {
	Blobs      BlobStore
	Index      IndexStore
	Signer     RangeURLSigner
	Authorizer Authorizer
	Now        func() time.Time

	DedupProtectionKey xethash.Hash
	DedupTTL           time.Duration
	MaxXorbBody        int64
	MaxShardBody       int64
}

type ShardResult struct {
	Shard             BlobKey
	Inserted          bool
	Files             int
	GlobalDedupChunks int
}
