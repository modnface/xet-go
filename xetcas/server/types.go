// Package server implements the storage-neutral server half of the Xet CAS
// protocol. It deliberately contains no repository-hosting or cloud-vendor
// concepts.
package server

import (
	"context"
	"errors"
	"io"
	"time"

	"github.com/jmwoliver/xet-go/shard"
	"github.com/jmwoliver/xet-go/xetcas"
	"github.com/jmwoliver/xet-go/xethash"
	"github.com/jmwoliver/xet-go/xorb"
)

var (
	ErrNotFound     = errors.New("xet CAS server: not found")
	ErrUnauthorized = errors.New("xet CAS server: unauthorized")
	ErrForbidden    = errors.New("xet CAS server: forbidden")
	ErrConflict     = errors.New("xet CAS server: immutable value conflict")
	ErrTooLarge     = errors.New("xet CAS server: request body too large")
	ErrInvalid      = errors.New("xet CAS server: invalid request")
	ErrCorrupt      = errors.New("xet CAS server: corrupt content")
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

// IndexStore keeps physical xorb metadata global while scoping every logical
// file, dedup, and SHA association to an authorized storage namespace. File
// and dedup keys are non-unique secondary indexes: the same logical content
// can have more than one valid shard recipe. PutFile and PutDedup must retain
// either an existing valid record or the supplied valid record without
// returning a conflict. Every Put operation is idempotent. The Service
// validates supplied records and orders calls so scoped file records, the
// public reconstruction point, are written last.
type IndexStore interface {
	GetXorb(context.Context, xethash.Hash) (XorbRecord, bool, error)
	PutXorb(context.Context, XorbRecord) error
	GetFile(context.Context, string, xethash.Hash) (FileRecord, bool, error)
	PutFile(context.Context, string, FileRecord) error
	GetDedup(context.Context, string, xethash.Hash) (DedupRecord, bool, error)
	PutDedup(context.Context, string, xethash.Hash, DedupRecord) error
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

// Grant contains the logical storage-index scope derived from a generic CAS
// credential. Physical content may be deduplicated globally, but file, dedup,
// and SHA reachability is always evaluated within Namespace.
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

	DedupProtectionKey   xethash.Hash
	DedupTTL             time.Duration
	MaxXorbBody          int64
	MaxShardBody         int64
	RegistrationLimits   shard.RegistrationLimits
	MaxConcurrentIngests int
}

type ShardResult struct {
	Shard             BlobKey
	Inserted          bool
	Files             int
	GlobalDedupChunks int
}

// OpenedFile is a typed, streaming reconstruction result. FileSize is the
// complete logical file size, while Range and Size describe the returned
// half-open logical range. Body verifies every decoded chunk against durable
// xorb metadata and, for whole-file reads, verifies optional SHA-256 metadata.
// The caller must close Body; closing it cancels outstanding storage reads.
type OpenedFile struct {
	Hash     xethash.Hash
	FileSize uint64
	Range    xetcas.FileRange
	Size     uint64
	SHA256   *[32]byte
	Body     io.ReadCloser
}
