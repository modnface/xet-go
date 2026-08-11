package model

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"hash"
	"slices"
	"time"
)

const snapshotFingerprintDomain = "xet-go-snapshot-v1\x00"

// SnapshotFingerprintVersion identifies the canonical equality encoding used
// by FingerprintSnapshot. Durable catalogs must persist this version with a
// retained fingerprint.
const SnapshotFingerprintVersion = 1

// CanonicalSnapshot validates and deep-clones a complete snapshot, ordering
// files by canonical UTF-8 path bytes. It does not derive or reinterpret OID.
func CanonicalSnapshot(snapshot Snapshot) (Snapshot, error) {
	if err := ValidateRepoKey(snapshot.Repo); err != nil {
		return Snapshot{}, err
	}
	if snapshot.OID.IsZero() {
		return Snapshot{}, fmt.Errorf("model: snapshot has a zero commit OID")
	}
	if snapshot.Parent != nil && (snapshot.Parent.IsZero() || *snapshot.Parent == snapshot.OID) {
		return Snapshot{}, fmt.Errorf("model: snapshot parent is zero or self-referential")
	}
	createdAt, err := canonicalTime(snapshot.CreatedAt)
	if err != nil {
		return Snapshot{}, fmt.Errorf("model: snapshot creation time: %w", err)
	}
	if err := validateText("author name", snapshot.Author.Name, MaxIdentityBytes, true, false); err != nil {
		return Snapshot{}, err
	}
	if err := validateText("author email", snapshot.Author.Email, MaxIdentityBytes, false, false); err != nil {
		return Snapshot{}, err
	}
	if err := validateText("snapshot message", snapshot.Message, MaxMessageBytes, true, true); err != nil {
		return Snapshot{}, err
	}
	result := Snapshot{
		Repo: snapshot.Repo, OID: snapshot.OID, Parent: cloneOID(snapshot.Parent), CreatedAt: createdAt,
		Author: snapshot.Author, Message: snapshot.Message, Files: make([]FileEntry, len(snapshot.Files)),
	}
	for index, entry := range snapshot.Files {
		path, err := ParseFilePath(string(entry.Path))
		if err != nil {
			return Snapshot{}, err
		}
		ref, err := canonicalFileRef(entry.Ref)
		if err != nil {
			return Snapshot{}, fmt.Errorf("model: file %q: %w", path, err)
		}
		result.Files[index] = FileEntry{Path: path, Ref: ref}
	}
	slices.SortFunc(result.Files, func(left, right FileEntry) int {
		if left.Path < right.Path {
			return -1
		}
		if left.Path > right.Path {
			return 1
		}
		return 0
	})
	for index := 1; index < len(result.Files); index++ {
		if result.Files[index-1].Path == result.Files[index].Path {
			return Snapshot{}, fmt.Errorf("model: duplicate snapshot path %q", result.Files[index].Path)
		}
	}
	paths := make(map[FilePath]struct{}, len(result.Files))
	for _, entry := range result.Files {
		paths[entry.Path] = struct{}{}
	}
	for _, entry := range result.Files {
		path := string(entry.Path)
		for separator := 0; separator < len(path); separator++ {
			if path[separator] != '/' {
				continue
			}
			ancestor := FilePath(path[:separator])
			if _, exists := paths[ancestor]; exists {
				return Snapshot{}, fmt.Errorf("model: path %q is both a file and directory", ancestor)
			}
		}
	}
	return result, nil
}

func canonicalFileRef(ref FileRef) (FileRef, error) {
	if ref.size < 0 {
		return FileRef{}, fmt.Errorf("file size is negative")
	}
	switch ref.kind {
	case FileKindBlob:
		if ref.sha256 == nil || !ref.xetHash.IsZero() {
			return FileRef{}, fmt.Errorf("ordinary blob reference is incomplete")
		}
	case FileKindXet:
		if (ref.size == 0) != ref.xetHash.IsZero() {
			return FileRef{}, fmt.Errorf("xet file size and identity disagree")
		}
	default:
		return FileRef{}, fmt.Errorf("unknown file kind %q", ref.kind)
	}
	ref.sha256 = cloneSHA256(ref.sha256)
	return ref, nil
}

func canonicalTime(value time.Time) (time.Time, error) {
	if value.IsZero() {
		return time.Time{}, fmt.Errorf("timestamp is required")
	}
	nanoseconds := value.UnixNano()
	canonical := time.Unix(0, nanoseconds).UTC()
	if !canonical.Equal(value) {
		return time.Time{}, fmt.Errorf("timestamp is outside signed nanosecond range")
	}
	return canonical, nil
}

// SnapshotFingerprint is an equality fingerprint for xet-go's version-one
// canonical snapshot representation. It must not be truncated or used as a
// Git, Hugging Face, or model commit OID.
type SnapshotFingerprint [32]byte

// FingerprintSnapshot returns the version-one equality fingerprint of all
// immutable snapshot metadata except OID.
func FingerprintSnapshot(snapshot Snapshot) (SnapshotFingerprint, error) {
	canonical, err := CanonicalSnapshot(snapshot)
	if err != nil {
		return SnapshotFingerprint{}, err
	}
	digest := sha256.New()
	_, _ = digest.Write([]byte(snapshotFingerprintDomain))
	writeString(digest, string(canonical.Repo.Type))
	writeString(digest, string(canonical.Repo.Namespace))
	writeString(digest, string(canonical.Repo.Name))
	if canonical.Parent == nil {
		_, _ = digest.Write([]byte{0})
	} else {
		_, _ = digest.Write([]byte{1})
		_, _ = digest.Write(canonical.Parent[:])
	}
	writeUint64(digest, uint64(canonical.CreatedAt.UnixNano()))
	writeString(digest, canonical.Author.Name)
	writeString(digest, canonical.Author.Email)
	writeString(digest, canonical.Message)
	writeUint64(digest, uint64(len(canonical.Files)))
	for _, entry := range canonical.Files {
		writeString(digest, string(entry.Path))
		ref := entry.Ref
		switch ref.kind {
		case FileKindBlob:
			_, _ = digest.Write([]byte{1})
			writeUint64(digest, uint64(ref.size))
			_, _ = digest.Write(ref.sha256[:])
		case FileKindXet:
			_, _ = digest.Write([]byte{2})
			writeUint64(digest, uint64(ref.size))
			_, _ = digest.Write(ref.xetHash[:])
			if ref.sha256 == nil {
				_, _ = digest.Write([]byte{0})
			} else {
				_, _ = digest.Write([]byte{1})
				_, _ = digest.Write(ref.sha256[:])
			}
		}
	}
	var result SnapshotFingerprint
	copy(result[:], digest.Sum(nil))
	return result, nil
}

func writeString(destination hash.Hash, value string) {
	writeUint64(destination, uint64(len(value)))
	_, _ = destination.Write([]byte(value))
}

func writeUint64(destination hash.Hash, value uint64) {
	var encoded [8]byte
	binary.BigEndian.PutUint64(encoded[:], value)
	_, _ = destination.Write(encoded[:])
}
