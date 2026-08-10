// Package server implements the storage-neutral server half of the Xet CAS
// protocol. It deliberately contains no repository-hosting or cloud-vendor
// concepts.
package server

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/jmwoliver/xet-go/shard"
	"github.com/jmwoliver/xet-go/xetcas"
	"github.com/jmwoliver/xet-go/xethash"
	"github.com/jmwoliver/xet-go/xorb"
)

var (
	ErrNotFound                    = errors.New("xet CAS server: not found")
	ErrUnauthorized                = errors.New("xet CAS server: unauthorized")
	ErrForbidden                   = errors.New("xet CAS server: forbidden")
	ErrConflict                    = errors.New("xet CAS server: immutable value conflict")
	ErrTooLarge                    = errors.New("xet CAS server: request body too large")
	ErrInvalid                     = errors.New("xet CAS server: invalid request")
	ErrCorrupt                     = errors.New("xet CAS server: corrupt content")
	ErrDurabilityUnsupported       = errors.New("xet CAS server: strict filesystem durability is unsupported")
	ErrProtectionExpiryUnsupported = errors.New("xet CAS server: protection expiry operations are unsupported")
	ErrAuditUnsupported            = errors.New("xet CAS server: selected audit inventory is unsupported")
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

const (
	DefaultPageSize = 100
	MaxPageSize     = 1_000
)

// PageRequest controls bounded operational iteration. Cursor is an opaque
// continuation value returned by the same method and backend. A zero Limit
// selects DefaultPageSize. Multi-page iteration is weakly consistent rather
// than a snapshot: stable records are returned once, but concurrent inserts
// at or before an emitted cursor may be missed. Destructive maintenance must
// combine iteration with writer quiescence, an epoch or lease, or an age/grace
// barrier.
type PageRequest struct {
	Cursor string
	Limit  int
}

type BlobEntry struct {
	Key  BlobKey
	Info BlobInfo
}

type BlobPage struct {
	Items      []BlobEntry
	NextCursor string
}

// BlobStore stores immutable protocol objects. PutIfAbsent must return
// ErrConflict if a key already contains different bytes.
type BlobStore interface {
	PutIfAbsent(context.Context, BlobKey, io.Reader, int64) (inserted bool, err error)
	Head(context.Context, BlobKey) (BlobInfo, bool, error)
	Get(context.Context, BlobKey, *xetcas.HTTPRange) (io.ReadCloser, error)
}

// BlobLister is the optional operational-iteration capability implemented by
// stores that support audit, migration, and garbage collection. Results are
// ordered deterministically within one backend and bounded by PageRequest.
// The filesystem implementation reads and sorts one four-hex-character hash
// leaf at a time, so a page does not imply O(Limit) backend work. Listing
// physical objects is an administrative capability; this interface performs
// no tenant authorization.
type BlobLister interface {
	ListBlobs(context.Context, BlobKind, PageRequest) (BlobPage, error)
}

type XorbRecord struct {
	Blob BlobKey
	// Layout contains metadata only. Service publication stores Complete in
	// Blob and clears Layout.Complete before publishing the index record.
	Layout xorb.Ingested
}

type FileRecord struct {
	File  shard.RegisteredFile
	Shard BlobKey
}

type DedupRecord struct {
	Shard BlobKey
}

type DedupAssociation struct {
	Chunk xethash.Hash
	Value DedupRecord
}

type SHA256Association struct {
	Sum  [32]byte
	Size uint64
	File xethash.Hash
}

// ShardRecord registers a successfully published logical shard. Registration
// is namespace-scoped even though the immutable shard blob remains global.
type ShardRecord struct {
	Blob BlobKey
}

type ScopedShardRecord struct {
	Namespace string
	Record    ShardRecord
}

type ShardRecordPage struct {
	Items      []ScopedShardRecord
	NextCursor string
}

type ScopedFileRecord struct {
	Namespace string
	Record    FileRecord
}

type FileRecordPage struct {
	Items      []ScopedFileRecord
	NextCursor string
}

type ScopedDedupRecord struct {
	Namespace string
	Chunk     xethash.Hash
	Record    DedupRecord
}

type DedupRecordPage struct {
	Items      []ScopedDedupRecord
	NextCursor string
}

type ScopedSHA256Association struct {
	Namespace string
	Record    SHA256Association
}

type SHA256AssociationPage struct {
	Items      []ScopedSHA256Association
	NextCursor string
}

type XorbRecordPage struct {
	Items      []XorbRecord
	NextCursor string
}

type ProtectionID [16]byte

type BlobStage struct {
	ID        ProtectionID
	Namespace string
	Blob      BlobKey
	CreatedAt time.Time
	ExpiresAt time.Time
}

type BlobStagePage struct {
	Items      []BlobStage
	NextCursor string
}

// BlobStageRecoveryStatus is the durable disposition of one expired stage
// inspection. Only published-removed releases protection metadata. A
// published-not-removed result indicates a harmless renewal or duplicate-worker
// race; all other non-published results leave the original stage intact.
type BlobStageRecoveryStatus string

const (
	BlobStageRecoveryMissing               BlobStageRecoveryStatus = "missing"
	BlobStageRecoveryCorrupt               BlobStageRecoveryStatus = "corrupt"
	BlobStageRecoveryBlocked               BlobStageRecoveryStatus = "blocked"
	BlobStageRecoveryConflict              BlobStageRecoveryStatus = "conflict"
	BlobStageRecoveryFailed                BlobStageRecoveryStatus = "failed"
	BlobStageRecoveryPublishedRemoved      BlobStageRecoveryStatus = "published-removed"
	BlobStageRecoveryPublishedNotRemoved   BlobStageRecoveryStatus = "published-not-removed"
	BlobStageRecoveryPublishedDeleteFailed BlobStageRecoveryStatus = "published-delete-failed"
)

type BlobStageRecoveryPhase string

const (
	BlobStageRecoveryHead     BlobStageRecoveryPhase = "head"
	BlobStageRecoveryRead     BlobStageRecoveryPhase = "read"
	BlobStageRecoveryValidate BlobStageRecoveryPhase = "validate"
	BlobStageRecoveryResolve  BlobStageRecoveryPhase = "resolve-xorbs"
	BlobStageRecoveryPublish  BlobStageRecoveryPhase = "publish"
	BlobStageRecoveryDelete   BlobStageRecoveryPhase = "delete-stage"
)

type BlobStageRecoveryResult struct {
	Stage  BlobStage
	Status BlobStageRecoveryStatus
	Phase  BlobStageRecoveryPhase
	// Err is nil for missing and successful outcomes. Callers can use errors.Is
	// with ErrCorrupt, ErrConflict, context cancellation, and backend errors.
	Err error
}

type BlobStageRecoveryPage struct {
	Items      []BlobStageRecoveryResult
	NextCursor string
}

type FileLease struct {
	ID        ProtectionID
	Namespace string
	File      xethash.Hash
	CreatedAt time.Time
	ExpiresAt time.Time
}

type FileLeasePage struct {
	Items      []FileLease
	NextCursor string
}

// AuditKind selects one bounded administrative metadata inventory. Namespace
// must be nil for global physical-blob and Xorb-record inventories. A nil
// namespace on a scoped kind lists all namespaces; a non-nil value selects
// that exact namespace. Audit iteration performs no tenant authorization and
// never reads, hashes, or decodes payload bytes.
type AuditKind string

const (
	// AuditKindBlobXorb checks a listed physical Xorb key and size against
	// its global Xorb layout record and metadata-derived canonical size.
	AuditKindBlobXorb AuditKind = "blob-xorb"
	// AuditKindBlobShard checks a listed physical shard key and reported
	// size. Reachability is indeterminate without a global reverse index.
	AuditKindBlobShard AuditKind = "blob-shard"
	// AuditKindXorbRecord checks layout identity and bounds plus existence and
	// exact reported size of its canonical physical Xorb object.
	AuditKindXorbRecord AuditKind = "xorb-record"
	// AuditKindShardRecord checks a scoped registration and the existence and
	// reported size bounds of its physical shard object.
	AuditKindShardRecord AuditKind = "shard-record"
	// AuditKindFileRecord checks its scoped shard publication, complete file
	// recipe through canonical registration validation, every referenced Xorb
	// layout and reported object size, and any SHA association it declares.
	AuditKindFileRecord AuditKind = "file-record"
	// AuditKindDedupRecord checks its nonzero chunk identity, scoped shard
	// publication, and physical shard object's existence and reported bounds.
	AuditKindDedupRecord AuditKind = "dedup-record"
	// AuditKindSHA256Association checks its scoped file target with the same
	// deep metadata checks as AuditKindFileRecord and compares derived size.
	// It does not hash reconstructed file bytes.
	AuditKindSHA256Association AuditKind = "sha256-association"
	// AuditKindBlobStage validates protection metadata and checks the staged
	// physical object's existence and reported size bounds.
	AuditKindBlobStage AuditKind = "blob-stage"
	// AuditKindFileLease validates protection metadata and checks its scoped
	// file target with the same deep metadata checks as AuditKindFileRecord.
	AuditKindFileLease AuditKind = "file-lease"
)

// AuditRequest requests at most one bounded, weakly consistent inventory page.
type AuditRequest struct {
	Kind      AuditKind
	Namespace *string
	Page      PageRequest
}

// AuditSubject is a closed union of compact inventory identities. Audit pages
// deliberately do not copy potentially large Xorb layouts or file recipes.
type AuditSubject interface{ auditSubject() }

type auditSubjectMarker struct{}

func (auditSubjectMarker) auditSubject() {}

type BlobAuditSubject struct {
	auditSubjectMarker
	Entry BlobEntry
}

type XorbRecordAuditSubject struct {
	auditSubjectMarker
	Blob BlobKey
}

type ShardRecordAuditSubject struct {
	auditSubjectMarker
	Namespace string
	Blob      BlobKey
}

type FileRecordAuditSubject struct {
	auditSubjectMarker
	Namespace string
	File      xethash.Hash
	Shard     BlobKey
}

type DedupRecordAuditSubject struct {
	auditSubjectMarker
	Namespace string
	Chunk     xethash.Hash
	Shard     BlobKey
}

type SHA256AssociationAuditSubject struct {
	auditSubjectMarker
	Namespace string
	Sum       [32]byte
	Size      uint64
	File      xethash.Hash
}

type BlobStageAuditSubject struct {
	auditSubjectMarker
	Stage BlobStage
}

type FileLeaseAuditSubject struct {
	auditSubjectMarker
	Lease FileLease
}

// AuditStatus is the common outcome of an administrative check. The operation
// and result type define the evidence checked; no status by itself proves
// reachability, retention, liveness, or deletion safety.
type AuditStatus string

const (
	AuditStatusNoIssueFound  AuditStatus = "no-issue-found"
	AuditStatusIssue         AuditStatus = "issue"
	AuditStatusIndeterminate AuditStatus = "indeterminate"
	AuditStatusFailed        AuditStatus = "failed"
)

type AuditFinding string

const (
	AuditFindingNone                          AuditFinding = ""
	AuditFindingBlobMissing                   AuditFinding = "blob-missing"
	AuditFindingBlobSizeInvalid               AuditFinding = "blob-size-invalid"
	AuditFindingXorbRecordMissing             AuditFinding = "xorb-record-missing"
	AuditFindingShardRecordMissing            AuditFinding = "shard-record-missing"
	AuditFindingFileRecordMissing             AuditFinding = "file-record-missing"
	AuditFindingSHA256AssociationMissing      AuditFinding = "sha256-association-missing"
	AuditFindingRecordInvalid                 AuditFinding = "record-invalid"
	AuditFindingShardReverseLookupUnavailable AuditFinding = "shard-reverse-lookup-unavailable"
	AuditFindingCheckFailed                   AuditFinding = "check-failed"
)

type AuditTargetKind string

const (
	AuditTargetBlob        AuditTargetKind = "blob"
	AuditTargetXorbRecord  AuditTargetKind = "xorb-record"
	AuditTargetShardRecord AuditTargetKind = "shard-record"
	AuditTargetFileRecord  AuditTargetKind = "file-record"
	AuditTargetSHA256      AuditTargetKind = "sha256-association"
)

type AuditTarget struct {
	Kind      AuditTargetKind
	Namespace string
	Blob      BlobKey
	Hash      xethash.Hash
	Sum       [32]byte
	Size      uint64
}

type AuditResult struct {
	Subject AuditSubject
	Status  AuditStatus
	Finding AuditFinding
	Target  *AuditTarget
	// Err is nil for no-issue-found, missing-target, and indeterminate outcomes.
	// Corrupt/invalid records and failed backend checks retain their typed error.
	Err error
}

// AuditPage contains diagnostic results from one page. If AuditInventory
// returns a non-nil error, Items may contain checks completed before failure,
// but NextCursor is always empty and callers must retry the original request.
type AuditPage struct {
	Kind       AuditKind
	Items      []AuditResult
	NextCursor string
}

// PayloadAuditRequest selects one bounded page of globally stored physical
// objects for full byte verification. Only BlobXorb and BlobShard are valid;
// logical namespace reachability is deliberately outside this operation.
type PayloadAuditRequest struct {
	Kind BlobKind
	Page PageRequest
}

// PayloadAuditFinding classifies full physical-object checks. A successful
// check proves that the bytes read during that check were the exact canonical
// durable encoding for Entry.Key. It does not prove reachability, retention,
// or deletion safety.
type PayloadAuditFinding string

const (
	PayloadAuditFindingNone             PayloadAuditFinding = ""
	PayloadAuditFindingBlobMissing      PayloadAuditFinding = "blob-missing"
	PayloadAuditFindingSizeInvalid      PayloadAuditFinding = "blob-size-invalid"
	PayloadAuditFindingPayloadInvalid   PayloadAuditFinding = "payload-invalid"
	PayloadAuditFindingIdentityMismatch PayloadAuditFinding = "identity-mismatch"
	PayloadAuditFindingCheckFailed      PayloadAuditFinding = "check-failed"
)

type PayloadAuditResult struct {
	Entry   BlobEntry
	Status  AuditStatus
	Finding PayloadAuditFinding
	// Err is nil for no-issue-found and missing outcomes. Invalid payloads
	// retain ErrCorrupt; failed reads retain their backend error.
	Err error
}

// PayloadAuditPage contains checks from one physical-object page. Per-item
// failures do not fail the page and its continuation advances past them, so
// callers must retain and retry failed entries explicitly. If AuditBlobPayloads
// returns a non-nil error, Items may contain completed checks, but NextCursor
// is always empty and callers must retry the request.
type PayloadAuditPage struct {
	Kind       BlobKind
	Items      []PayloadAuditResult
	NextCursor string
}

// ShardPublication is the complete set of logical index records exposed by
// one validated shard. PublishShard must commit all records atomically within
// Namespace or expose none of them.
type ShardPublication struct {
	Namespace string
	Shard     BlobKey
	Dedup     []DedupAssociation
	SHA256    []SHA256Association
	Files     []FileRecord
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
	GetShard(context.Context, string, xethash.Hash) (ShardRecord, bool, error)
	GetFile(context.Context, string, xethash.Hash) (FileRecord, bool, error)
	PutFile(context.Context, string, FileRecord) error
	GetDedup(context.Context, string, xethash.Hash) (DedupRecord, bool, error)
	PutDedup(context.Context, string, xethash.Hash, DedupRecord) error
	ResolveSHA256(context.Context, string, [32]byte, uint64) (xethash.Hash, bool, error)
	PutSHA256(context.Context, string, [32]byte, uint64, xethash.Hash) error
	PublishShard(context.Context, ShardPublication) error
}

// ProtectionStore is an optional durable lifecycle capability. Blob stages
// protect immutable objects whose logical index publication has not completed.
// File leases protect namespace-scoped reconstruction roots while reads are in
// flight or signed range capabilities remain valid. Put operations are
// idempotent for an identical record; IDs cannot be retargeted. Renewals may
// extend but never shorten a protection. Delete operations are idempotent.
type ProtectionStore interface {
	PutBlobStage(context.Context, BlobStage) error
	RenewBlobStage(context.Context, string, ProtectionID, time.Time) error
	DeleteBlobStage(context.Context, string, ProtectionID) error
	ListBlobStages(context.Context, *string, PageRequest) (BlobStagePage, error)

	PutFileLease(context.Context, FileLease) error
	RenewFileLease(context.Context, string, ProtectionID, time.Time) error
	DeleteFileLease(context.Context, string, ProtectionID) error
	ListFileLeases(context.Context, *string, PageRequest) (FileLeasePage, error)
}

// ProtectionExpiryStore is the optional administrative capability used by
// recovery and garbage collection to scan protections that expired at or
// before a stable cutoff. Cursors are bound to both the method and cutoff.
// Conditional deletion prevents a stale scan from removing a concurrently
// renewed protection. Delete methods remove protection metadata only and must
// never delete BlobStore payloads. Deleting a stage does not authorize deleting
// its Blob; callers must first preserve or classify that object under a
// reachability and grace protocol.
type ProtectionExpiryStore interface {
	ListExpiredBlobStages(context.Context, time.Time, PageRequest) (BlobStagePage, error)
	DeleteExpiredBlobStage(context.Context, string, ProtectionID, time.Time) (bool, error)
	ListExpiredFileLeases(context.Context, time.Time, PageRequest) (FileLeasePage, error)
	DeleteExpiredFileLease(context.Context, string, ProtectionID, time.Time) (bool, error)
}

// IndexLister is the optional operational-iteration capability implemented by
// durable indexes. A nil namespace lists all namespaces; a non-nil namespace,
// including a pointer to the empty string, restricts the page to that exact
// scope. Cursors are opaque and may only be reused with the same method and
// namespace filter. All-namespace listing is an administrative capability;
// this interface performs no tenant authorization.
type IndexLister interface {
	ListXorbs(context.Context, PageRequest) (XorbRecordPage, error)
	ListShards(context.Context, *string, PageRequest) (ShardRecordPage, error)
	ListFiles(context.Context, *string, PageRequest) (FileRecordPage, error)
	ListDedup(context.Context, *string, PageRequest) (DedupRecordPage, error)
	ListSHA256(context.Context, *string, PageRequest) (SHA256AssociationPage, error)
}

func pageLimit(request PageRequest) (int, error) {
	if request.Limit == 0 {
		return DefaultPageSize, nil
	}
	if request.Limit < 0 || request.Limit > MaxPageSize {
		return 0, fmt.Errorf("%w: page limit must be 0 or between 1 and %d", ErrInvalid, MaxPageSize)
	}
	return request.Limit, nil
}

const (
	cursorBlobXorb byte = iota + 1
	cursorBlobShard
	cursorIndexXorb
	cursorShardAll
	cursorShardScoped
	cursorFileAll
	cursorFileScoped
	cursorDedupAll
	cursorDedupScoped
	cursorSHA256All
	cursorSHA256Scoped
	cursorBlobStageAll
	cursorBlobStageScoped
	cursorFileLeaseAll
	cursorFileLeaseScoped
	cursorBlobStageExpired
	cursorFileLeaseExpired
	cursorAuditEnvelope
	cursorPayloadAuditEnvelope
)

// validateShardPublication is shared by durable backends so contradictory
// source identities are rejected before any state changes.
func validateShardPublication(publication ShardPublication) error {
	if err := validateShardSource(publication.Shard); err != nil {
		return fmt.Errorf("%w: invalid shard publication identity", ErrInvalid)
	}
	for _, association := range publication.Dedup {
		if association.Value.Shard != publication.Shard {
			return fmt.Errorf("%w: dedup source differs from publication shard", ErrInvalid)
		}
	}
	for _, record := range publication.Files {
		if record.Shard != publication.Shard {
			return fmt.Errorf("%w: file source differs from publication shard", ErrInvalid)
		}
	}
	return nil
}

func validateShardSource(source BlobKey) error {
	if source.Kind != BlobShard || source.Hash == xethash.Zero {
		return fmt.Errorf("%w: invalid shard source", ErrCorrupt)
	}
	return nil
}

func validateShardRecord(key xethash.Hash, record ShardRecord) error {
	if err := validateShardSource(record.Blob); err != nil || record.Blob.Hash != key {
		return fmt.Errorf("%w: shard record identity mismatch", ErrCorrupt)
	}
	return nil
}

func validateFileRecord(key xethash.Hash, record FileRecord) error {
	if record.File.File.Hash != key {
		return fmt.Errorf("%w: file record identity mismatch", ErrCorrupt)
	}
	return validateShardSource(record.Shard)
}

func validateDedupRecord(record DedupRecord) error {
	return validateShardSource(record.Shard)
}

func encodeHashCursor(kind byte, hash xethash.Hash) string {
	data := make([]byte, 1+len(hash))
	data[0] = kind
	copy(data[1:], hash[:])
	return base64.RawURLEncoding.EncodeToString(data)
}

func decodeHashCursor(cursor string, kind byte) (xethash.Hash, error) {
	data, err := decodeCursor(cursor)
	if err != nil || len(data) != 1+len(xethash.Hash{}) || data[0] != kind {
		return xethash.Hash{}, fmt.Errorf("%w: malformed page cursor", ErrInvalid)
	}
	var hash xethash.Hash
	copy(hash[:], data[1:])
	return hash, nil
}

func encodeScopedCursor(kind byte, namespace string, key []byte) string {
	data := make([]byte, 5+len(namespace)+len(key))
	data[0] = kind
	binary.BigEndian.PutUint32(data[1:5], uint32(len(namespace)))
	copy(data[5:], namespace)
	copy(data[5+len(namespace):], key)
	return base64.RawURLEncoding.EncodeToString(data)
}

func decodeScopedCursor(cursor string, kind byte, keySize int) (string, []byte, error) {
	data, err := decodeCursor(cursor)
	if err != nil || len(data) < 5 || data[0] != kind {
		return "", nil, fmt.Errorf("%w: malformed page cursor", ErrInvalid)
	}
	namespaceSize := uint64(binary.BigEndian.Uint32(data[1:5]))
	if namespaceSize > uint64(len(data)-5) || uint64(len(data))-5-namespaceSize != uint64(keySize) {
		return "", nil, fmt.Errorf("%w: malformed page cursor", ErrInvalid)
	}
	offset := 5 + int(namespaceSize)
	return string(data[5:offset]), append([]byte(nil), data[offset:]...), nil
}

func decodeCursor(cursor string) ([]byte, error) {
	data, err := base64.RawURLEncoding.DecodeString(cursor)
	if err != nil || base64.RawURLEncoding.EncodeToString(data) != cursor {
		return nil, fmt.Errorf("%w: malformed page cursor", ErrInvalid)
	}
	return data, nil
}

type protectionExpiryCursor struct {
	cutoff    time.Time
	expiresAt time.Time
	namespace string
	id        ProtectionID
}

func encodeProtectionExpiryCursor(
	kind byte,
	cutoff, expiresAt time.Time,
	namespace string,
	id ProtectionID,
) string {
	data := make([]byte, 21+len(namespace)+len(id))
	data[0] = kind
	binary.BigEndian.PutUint64(data[1:9], uint64(cutoff.UnixNano()))
	binary.BigEndian.PutUint64(data[9:17], uint64(expiresAt.UnixNano()))
	binary.BigEndian.PutUint32(data[17:21], uint32(len(namespace)))
	copy(data[21:], namespace)
	copy(data[21+len(namespace):], id[:])
	return base64.RawURLEncoding.EncodeToString(data)
}

func decodeProtectionExpiryCursor(cursor string, kind byte, cutoff time.Time) (protectionExpiryCursor, error) {
	data, err := decodeCursor(cursor)
	if err != nil || len(data) < 21+len(ProtectionID{}) || data[0] != kind {
		return protectionExpiryCursor{}, fmt.Errorf("%w: malformed protection expiry cursor", ErrInvalid)
	}
	namespaceSize := uint64(binary.BigEndian.Uint32(data[17:21]))
	if namespaceSize > uint64(len(data)-21) || uint64(len(data))-21-namespaceSize != uint64(len(ProtectionID{})) {
		return protectionExpiryCursor{}, fmt.Errorf("%w: malformed protection expiry cursor", ErrInvalid)
	}
	storedCutoff := protectionTimeFromCursor(binary.BigEndian.Uint64(data[1:9]))
	if !storedCutoff.Equal(cutoff) {
		return protectionExpiryCursor{}, fmt.Errorf("%w: protection expiry cursor cutoff differs from request", ErrInvalid)
	}
	namespaceEnd := 21 + int(namespaceSize)
	var id ProtectionID
	copy(id[:], data[namespaceEnd:])
	return protectionExpiryCursor{
		cutoff: storedCutoff, expiresAt: protectionTimeFromCursor(binary.BigEndian.Uint64(data[9:17])),
		namespace: string(data[21:namespaceEnd]), id: id,
	}, nil
}

func protectionTimeFromCursor(value uint64) time.Time {
	return time.Unix(0, int64(value)).UTC()
}

func protectionExpiryPage(
	cutoff time.Time,
	request PageRequest,
	cursorKind byte,
) (time.Time, int, protectionExpiryCursor, bool, error) {
	var err error
	cutoff, err = normalizeProtectionTime(cutoff)
	if err != nil {
		return time.Time{}, 0, protectionExpiryCursor{}, false, err
	}
	limit, err := pageLimit(request)
	if err != nil {
		return time.Time{}, 0, protectionExpiryCursor{}, false, err
	}
	if request.Cursor == "" {
		return cutoff, limit, protectionExpiryCursor{}, false, nil
	}
	cursor, err := decodeProtectionExpiryCursor(request.Cursor, cursorKind, cutoff)
	if err != nil {
		return time.Time{}, 0, protectionExpiryCursor{}, false, err
	}
	return cutoff, limit, cursor, true, nil
}

func normalizeBlobStage(stage BlobStage) (BlobStage, error) {
	if stage.ID == (ProtectionID{}) || stage.Blob.Hash == xethash.Zero ||
		stage.Blob.Kind != BlobXorb && stage.Blob.Kind != BlobShard {
		return BlobStage{}, fmt.Errorf("%w: invalid blob stage identity", ErrInvalid)
	}
	createdAt, err := normalizeProtectionTime(stage.CreatedAt)
	if err != nil {
		return BlobStage{}, err
	}
	expiresAt, err := normalizeProtectionTime(stage.ExpiresAt)
	if err != nil {
		return BlobStage{}, err
	}
	if !expiresAt.After(createdAt) {
		return BlobStage{}, fmt.Errorf("%w: blob stage expiration must follow creation", ErrInvalid)
	}
	stage.CreatedAt, stage.ExpiresAt = createdAt, expiresAt
	return stage, nil
}

func normalizeFileLease(lease FileLease) (FileLease, error) {
	if lease.ID == (ProtectionID{}) {
		return FileLease{}, fmt.Errorf("%w: invalid file lease identity", ErrInvalid)
	}
	createdAt, err := normalizeProtectionTime(lease.CreatedAt)
	if err != nil {
		return FileLease{}, err
	}
	expiresAt, err := normalizeProtectionTime(lease.ExpiresAt)
	if err != nil {
		return FileLease{}, err
	}
	if !expiresAt.After(createdAt) {
		return FileLease{}, fmt.Errorf("%w: file lease expiration must follow creation", ErrInvalid)
	}
	lease.CreatedAt, lease.ExpiresAt = createdAt, expiresAt
	return lease, nil
}

func normalizeProtectionTime(value time.Time) (time.Time, error) {
	if value.IsZero() {
		return time.Time{}, fmt.Errorf("%w: protection timestamp is required", ErrInvalid)
	}
	value = value.Round(0).UTC()
	if !time.Unix(0, value.UnixNano()).Equal(value) {
		return time.Time{}, fmt.Errorf("%w: protection timestamp is outside the supported nanosecond range", ErrInvalid)
	}
	return value, nil
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

// SignedRange is one object-store capability and its authoritative expiration.
// The service retains a namespace-scoped file lease through ExpiresAt plus its
// configured read-lease grace interval.
type SignedRange struct {
	URL       string
	ExpiresAt time.Time
}

type RangeURLSigner interface {
	SignRange(context.Context, BlobKey, xetcas.HTTPRange) (SignedRange, error)
}

type RangeURLSignerFunc func(context.Context, BlobKey, xetcas.HTTPRange) (SignedRange, error)

func (f RangeURLSignerFunc) SignRange(ctx context.Context, key BlobKey, value xetcas.HTTPRange) (SignedRange, error) {
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
	StagingProtectionTTL time.Duration
	ReadLeaseTTL         time.Duration
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
