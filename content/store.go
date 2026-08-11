// Package content defines immutable ordinary-blob storage independently of
// repository metadata and the Xet CAS protocol.
package content

import (
	"context"
	"errors"
	"fmt"
	"io"
)

var (
	ErrInvalid               = errors.New("content: invalid input")
	ErrNotFound              = errors.New("content: not found")
	ErrConflict              = errors.New("content: immutable value conflict")
	ErrCorrupt               = errors.New("content: corrupt content")
	ErrRangeNotSatisfiable   = errors.New("content: range not satisfiable")
	ErrUnavailable           = errors.New("content: backend unavailable")
	ErrDurabilityUnsupported = errors.New("content: strict filesystem durability is unsupported")
)

// Blob identifies ordinary content by its conventional SHA-256 and exact
// length. SHA256 is the physical identity; Size is retained and checked so a
// collision or corrupted object cannot be accepted under the same key.
type Blob struct {
	SHA256 [32]byte
	Size   int64
}

func (blob Blob) Validate() error {
	if blob.Size < 0 {
		return fmt.Errorf("%w: negative blob size", ErrInvalid)
	}
	return nil
}

// Range is a half-open byte interval [Start, End).
type Range struct {
	Start int64
	End   int64
}

func (r Range) Len() int64 { return r.End - r.Start }

func (r Range) Validate(size int64) error {
	if size < 0 || r.Start < 0 || r.End <= r.Start || r.End > size {
		return ErrRangeNotSatisfiable
	}
	return nil
}

type Info struct{ Size int64 }

const (
	DefaultPageSize = 100
	MaxPageSize     = 1_000
)

// PageRequest controls bounded, weakly consistent physical inventory. A zero
// limit selects DefaultPageSize. Concurrent inserts at or before a returned
// cursor may be missed; destructive maintenance requires an epoch, quiescence,
// or an equivalent lease/grace barrier.
type PageRequest struct {
	Cursor string
	Limit  int
}

type BlobPage struct {
	Items      []Blob
	NextCursor string
}

// BlobLister is the optional administrative inventory capability. Results are
// ordered by SHA-256 bytes. It does not establish catalog reachability or make
// deletion safe.
type BlobLister interface {
	ListBlobs(context.Context, PageRequest) (BlobPage, error)
}

// Store publishes and opens immutable ordinary blobs. Put verifies the exact
// declared length and SHA-256 before publication. Repeating identical bytes is
// success with inserted=false; different retained bytes under the same digest
// return ErrConflict. Open verifies retained length before returning a stream.
// Full streams verify SHA-256 at EOF; range streams verify their exact length.
// Callers must close returned readers, and Close must be safe to call while a
// concurrent Read is blocked.
type Store interface {
	Put(context.Context, Blob, io.Reader) (inserted bool, err error)
	Head(context.Context, [32]byte) (Info, bool, error)
	Open(context.Context, Blob, *Range) (io.ReadCloser, error)
}
