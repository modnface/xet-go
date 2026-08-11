// Package model defines repository, snapshot, revision, and file identities
// independently of persistence and HTTP compatibility layers.
//
// Commit OIDs are opaque server-assigned identifiers. A hosting compatibility
// adapter may derive them according to that host's observed commit rules; this
// package does not invent a commit preimage or claim Git object compatibility.
package model

import (
	"encoding/hex"
	"fmt"
	"time"

	"github.com/jmwoliver/xet-go/xethash"
)

type RepoType string

const RepoTypeModel RepoType = "model"

type Namespace string
type RepoName string
type FilePath string
type RefName string

type RepoKey struct {
	Namespace Namespace
	Name      RepoName
	Type      RepoType
}

func NewRepoKey(namespace, name string, repoType RepoType) (RepoKey, error) {
	key := RepoKey{Namespace: Namespace(namespace), Name: RepoName(name), Type: repoType}
	if err := ValidateRepoKey(key); err != nil {
		return RepoKey{}, err
	}
	return key, nil
}

func ValidateRepoKey(key RepoKey) error {
	if key.Type != RepoTypeModel {
		return fmt.Errorf("model: unsupported repository type %q", key.Type)
	}
	if err := validateRepoComponent("namespace", string(key.Namespace), MaxNamespaceRunes); err != nil {
		return err
	}
	return validateRepoComponent("repository name", string(key.Name), MaxRepoNameRunes)
}

// OID is a strict 20-byte commit identifier. The model layer treats it as an
// opaque server-assigned value; computing Hugging Face/Git-compatible commit
// preimages belongs to the future compatibility control plane.
type OID [20]byte

func ParseOID(value string) (OID, error) {
	if len(value) != hex.EncodedLen(len(OID{})) {
		return OID{}, fmt.Errorf("model: commit OID must contain exactly 40 lowercase hexadecimal characters")
	}
	for _, character := range value {
		if character < '0' || character > '9' {
			if character < 'a' || character > 'f' {
				return OID{}, fmt.Errorf("model: commit OID must contain exactly 40 lowercase hexadecimal characters")
			}
		}
	}
	var oid OID
	if _, err := hex.Decode(oid[:], []byte(value)); err != nil {
		return OID{}, fmt.Errorf("model: decode commit OID: %w", err)
	}
	if oid == (OID{}) {
		return OID{}, fmt.Errorf("model: zero commit OID is invalid")
	}
	return oid, nil
}

func (oid OID) String() string { return hex.EncodeToString(oid[:]) }

func (oid OID) IsZero() bool { return oid == (OID{}) }

// Revision is a closed union containing either an immutable OID or a ref.
type Revision struct {
	oid *OID
	ref *RefName
}

func ParseRevision(value string) (Revision, error) {
	if len(value) == 40 {
		if oid, err := ParseOID(value); err == nil {
			return Revision{oid: &oid}, nil
		}
	}
	ref, err := ParseRefName(value)
	if err != nil {
		return Revision{}, err
	}
	return Revision{ref: &ref}, nil
}

func RevisionFromOID(oid OID) (Revision, error) {
	if oid.IsZero() {
		return Revision{}, fmt.Errorf("model: zero commit OID is invalid")
	}
	copy := oid
	return Revision{oid: &copy}, nil
}

func RevisionFromRef(ref RefName) (Revision, error) {
	parsed, err := ParseRefName(string(ref))
	if err != nil {
		return Revision{}, err
	}
	return Revision{ref: &parsed}, nil
}

func (revision Revision) OID() (OID, bool) {
	if revision.oid == nil || revision.ref != nil {
		return OID{}, false
	}
	return *revision.oid, true
}

func (revision Revision) Ref() (RefName, bool) {
	if revision.ref == nil || revision.oid != nil {
		return "", false
	}
	return *revision.ref, true
}

func (revision Revision) String() string {
	if oid, ok := revision.OID(); ok {
		return oid.String()
	}
	if ref, ok := revision.Ref(); ok {
		return string(ref)
	}
	return ""
}

type FileKind string

const (
	FileKindBlob FileKind = "blob"
	FileKindXet  FileKind = "xet"
)

// FileRef is an immutable discriminated value for ordinary or Xet-backed
// content. Its zero value is invalid. Use NewBlobFileRef or NewXetFileRef.
type FileRef struct {
	kind    FileKind
	size    int64
	sha256  *[32]byte
	xetHash xethash.Hash
}

func NewBlobFileRef(sum [32]byte, size int64) (FileRef, error) {
	return canonicalFileRef(FileRef{kind: FileKindBlob, size: size, sha256: &sum})
}

func NewXetFileRef(hash xethash.Hash, size int64, sum *[32]byte) (FileRef, error) {
	return canonicalFileRef(FileRef{kind: FileKindXet, size: size, sha256: cloneSHA256(sum), xetHash: hash})
}

func (ref FileRef) Kind() FileKind { return ref.kind }

func (ref FileRef) FileSize() int64 { return ref.size }

// SHA256 returns the optional conventional SHA-256 of the logical whole-file
// bytes. Ordinary blob references always have one. A present all-zero value is
// distinct from an absent value.
func (ref FileRef) SHA256() ([32]byte, bool) {
	if ref.sha256 == nil {
		return [32]byte{}, false
	}
	return *ref.sha256, true
}

func (ref FileRef) XetHash() (xethash.Hash, bool) {
	return ref.xetHash, ref.kind == FileKindXet
}

type FileEntry struct {
	Path FilePath
	Ref  FileRef
}

type Identity struct {
	Name  string
	Email string
}

// Snapshot is an immutable complete repository tree. Files are canonicalized
// by CanonicalSnapshot before persistence or hashing.
type Snapshot struct {
	Repo      RepoKey
	OID       OID
	Parent    *OID
	CreatedAt time.Time
	Author    Identity
	Message   string
	Files     []FileEntry
}

type SnapshotInfo struct {
	Repo      RepoKey
	OID       OID
	Parent    *OID
	CreatedAt time.Time
	Author    Identity
	Message   string
	FileCount int
}

func (snapshot Snapshot) Info() SnapshotInfo {
	return SnapshotInfo{
		Repo: snapshot.Repo, OID: snapshot.OID, Parent: cloneOID(snapshot.Parent),
		CreatedAt: snapshot.CreatedAt, Author: snapshot.Author, Message: snapshot.Message,
		FileCount: len(snapshot.Files),
	}
}

// CloneSnapshot returns a deep copy without changing or revalidating it.
func CloneSnapshot(snapshot Snapshot) Snapshot {
	clone := snapshot
	clone.Parent = cloneOID(snapshot.Parent)
	clone.Files = make([]FileEntry, len(snapshot.Files))
	for index, entry := range snapshot.Files {
		entry.Ref.sha256 = cloneSHA256(entry.Ref.sha256)
		clone.Files[index] = entry
	}
	return clone
}

type Repository struct {
	Key       RepoKey
	CreatedAt time.Time
}

// CanonicalRepository validates a repository and normalizes its timestamp to
// UTC in the signed Unix-nanosecond range used by durable catalogs.
func CanonicalRepository(repository Repository) (Repository, error) {
	if err := ValidateRepoKey(repository.Key); err != nil {
		return Repository{}, err
	}
	createdAt, err := canonicalTime(repository.CreatedAt)
	if err != nil {
		return Repository{}, fmt.Errorf("model: repository creation time: %w", err)
	}
	repository.CreatedAt = createdAt
	return repository, nil
}

type Ref struct {
	Repo RepoKey
	Name RefName
	OID  OID
}

func ValidateRef(ref Ref) error {
	if err := ValidateRepoKey(ref.Repo); err != nil {
		return err
	}
	if _, err := ParseRefName(string(ref.Name)); err != nil {
		return err
	}
	if ref.OID.IsZero() {
		return fmt.Errorf("model: ref has a zero commit OID")
	}
	return nil
}

func cloneOID(value *OID) *OID {
	if value == nil {
		return nil
	}
	copy := *value
	return &copy
}

func cloneSHA256(value *[32]byte) *[32]byte {
	if value == nil {
		return nil
	}
	copy := *value
	return &copy
}
