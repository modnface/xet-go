// Package catalog defines transactional repository metadata storage without
// binding callers to SQL, HTTP, or a content backend.
package catalog

import (
	"context"
	"errors"

	"github.com/jmwoliver/xet-go/model"
)

var (
	ErrInvalid       = errors.New("catalog: invalid input")
	ErrNotFound      = errors.New("catalog: not found")
	ErrAlreadyExists = errors.New("catalog: already exists")
	ErrConflict      = errors.New("catalog: ref or immutable value conflict")
	ErrCorrupt       = errors.New("catalog: corrupt metadata")
	ErrUnavailable   = errors.New("catalog: backend unavailable")
)

const (
	DefaultPageSize = 100
	MaxPageSize     = 1_000
)

type RepositoryQuery struct {
	Namespace model.Namespace
	Type      model.RepoType
	Cursor    string
	Limit     int
}

// RepositoryPage is ordered by repository type, namespace, and name using
// their case-sensitive canonical UTF-8 bytes.
type RepositoryPage struct {
	Items      []model.Repository
	NextCursor string
}

type SnapshotQuery struct {
	Cursor string
	Limit  int
}

// SnapshotPage is ordered by creation time and then OID, newest first.
type SnapshotPage struct {
	Items      []model.SnapshotInfo
	NextCursor string
}

type RefQuery struct {
	Cursor string
	Limit  int
}

// RefPage is ordered by canonical, case-sensitive ref-name bytes. Pagination
// is weakly consistent across calls: advancing or creating refs during a scan
// can change later pages. It is inventory, not destructive-GC authority;
// deletion requires an epoch, quiescence, or equivalent lease/grace protocol.
type RefPage struct {
	Items      []model.Ref
	NextCursor string
}

// RefLister is an optional maintenance capability so existing Catalog
// implementations are not forced to support operational inventory.
type RefLister interface {
	ListRefs(context.Context, model.RepoKey, RefQuery) (RefPage, error)
}

type FileQuery struct {
	Prefix model.FilePrefix
	Cursor string
	Limit  int
}

// FilePage is ordered by canonical path bytes. SnapshotOID identifies the
// immutable tree resolved for this page. A continuation cursor is bound to
// that OID and cannot silently continue through an advanced mutable ref.
type FilePage struct {
	Items       []model.FileEntry
	NextCursor  string
	SnapshotOID model.OID
}

// RefExpectation selects the ref behavior of PublishSnapshot. Values returned
// by ExpectRef require Name to contain OID, or to be absent when OID is nil,
// immediately before publication. A value returned by NoRefUpdate leaves all
// refs unchanged.
type RefExpectation struct {
	Name        model.RefName
	OID         *model.OID
	noRefUpdate bool
}

func ExpectRef(name model.RefName, oid *model.OID) RefExpectation {
	var copy *model.OID
	if oid != nil {
		value := *oid
		copy = &value
	}
	return RefExpectation{Name: name, OID: copy}
}

// NoRefUpdate publishes an immutable snapshot without creating or updating
// any ref. This includes the first snapshot in a repository. It is the only
// constructor for this mode.
func NoRefUpdate() RefExpectation {
	return RefExpectation{noRefUpdate: true}
}

// UpdatesRef reports whether publication performs the ref compare-and-swap.
func (x RefExpectation) UpdatesRef() bool { return !x.noRefUpdate }

// Catalog stores repositories, immutable complete snapshots, and mutable
// refs. Every lookup is repository-scoped. A trusted control-plane layer must
// allocate the opaque OID before publication; the catalog never derives it
// from SnapshotFingerprint. Implementations must clone mutable input and
// output state and make PublishSnapshot atomic with its ref update. Except in
// NoRefUpdate mode, a successful first publication must also create main when
// another target ref was requested.
//
// Ref writes are target-state idempotent: if an identical immutable snapshot
// is already retained and the target ref already equals the requested new OID,
// the operation succeeds even when its old-value expectation is now stale.
// Success in that case does not prove the expectation held during this call.
// Competing updates to different target OIDs from the same prior ref conflict.
// NoRefUpdate publication is target-state idempotent on the immutable
// snapshot: replaying the same OID and snapshot succeeds, while different
// content under that OID conflicts. It still enforces repository, parent, and
// existing-snapshot invariants and is serialized per repository.
type Catalog interface {
	CreateRepository(context.Context, model.Repository) error
	GetRepository(context.Context, model.RepoKey) (model.Repository, error)
	ListRepositories(context.Context, RepositoryQuery) (RepositoryPage, error)

	ResolveRevision(context.Context, model.RepoKey, model.Revision) (model.Snapshot, error)
	GetSnapshot(context.Context, model.RepoKey, model.OID) (model.Snapshot, error)
	ListSnapshots(context.Context, model.RepoKey, SnapshotQuery) (SnapshotPage, error)

	GetRef(context.Context, model.RepoKey, model.RefName) (model.Ref, error)
	CompareAndSwapRef(context.Context, model.RepoKey, model.RefName, *model.OID, model.OID) error
	PublishSnapshot(context.Context, model.Snapshot, RefExpectation) error

	GetFile(context.Context, model.RepoKey, model.Revision, model.FilePath) (model.FileEntry, error)
	ListFiles(context.Context, model.RepoKey, model.Revision, FileQuery) (FilePage, error)
}
