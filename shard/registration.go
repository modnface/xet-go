package shard

import (
	"context"
	"errors"
	"fmt"
	"math"
	"sort"

	"github.com/jacobwoliver/xet-go/xethash"
)

// XorbLookup resolves durable, server-ingested xorb metadata by identity.
type XorbLookup func(xethash.Hash) (Xorb, bool, error)

// RegisteredFile is a validated reconstruction recipe and its derived size.
type RegisteredFile struct {
	File File
	Size uint64
}

// Registration is the validated, storage-neutral result of ingesting one
// footerless upload shard.
type Registration struct {
	Files             []RegisteredFile
	Xorbs             []Xorb
	GlobalDedupChunks []xethash.Hash
}

// RegistrationLimits bounds work that can be amplified by compact shard
// terms. Zero fields are unlimited; protocol servers should configure finite
// values before passing untrusted shards.
type RegistrationLimits struct {
	MaxFiles           uint64
	MaxXorbs           uint64
	MaxTerms           uint64
	MaxChunkReferences uint64
}

var (
	// ErrRegistrationLimit indicates that a structurally valid shard exceeds a
	// configured registration work limit.
	ErrRegistrationLimit = errors.New("shard: registration limit exceeded")
	// ErrXorbLookup marks a backing-index failure while resolving a referenced
	// xorb, as distinct from invalid or missing client metadata.
	ErrXorbLookup = errors.New("shard: xorb lookup failed")
)

// ValidateRegistration verifies an upload shard against already-ingested xorb
// metadata, including external xorb references, and recomputes every file
// identity, size, term verification hash, and global-dedup key.
func ValidateRegistration(value Shard, lookup XorbLookup) (*Registration, error) {
	return ValidateRegistrationContext(context.Background(), value, lookup, RegistrationLimits{})
}

// ValidateRegistrationContext is ValidateRegistration with cancellation and
// explicit work limits for untrusted protocol input.
func ValidateRegistrationContext(
	ctx context.Context,
	value Shard,
	lookup XorbLookup,
	limits RegistrationLimits,
) (*Registration, error) {
	if ctx == nil {
		return nil, errors.New("shard: nil registration context")
	}
	if lookup == nil {
		return nil, errors.New("shard: nil xorb lookup")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if limitExceeded(uint64(len(value.Files)), limits.MaxFiles) {
		return nil, fmt.Errorf("%w: %d files exceeds %d", ErrRegistrationLimit, len(value.Files), limits.MaxFiles)
	}
	if limitExceeded(uint64(len(value.Xorbs)), limits.MaxXorbs) {
		return nil, fmt.Errorf("%w: %d xorbs exceeds %d", ErrRegistrationLimit, len(value.Xorbs), limits.MaxXorbs)
	}
	var terms, chunkReferences uint64
	for i, file := range value.Files {
		if i&1023 == 0 {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
		}
		if math.MaxUint64-terms < uint64(len(file.Terms)) {
			return nil, fmt.Errorf("%w: term count overflows", ErrRegistrationLimit)
		}
		terms += uint64(len(file.Terms))
		if limitExceeded(terms, limits.MaxTerms) {
			return nil, fmt.Errorf("%w: %d terms exceeds %d", ErrRegistrationLimit, terms, limits.MaxTerms)
		}
		for j, term := range file.Terms {
			if j&1023 == 0 {
				if err := ctx.Err(); err != nil {
					return nil, err
				}
			}
			if term.End < term.Start {
				continue
			}
			references := uint64(term.End - term.Start)
			if math.MaxUint64-chunkReferences < references {
				return nil, fmt.Errorf("%w: chunk reference count overflows", ErrRegistrationLimit)
			}
			chunkReferences += references
			if limitExceeded(chunkReferences, limits.MaxChunkReferences) {
				return nil, fmt.Errorf("%w: %d chunk references exceeds %d",
					ErrRegistrationLimit, chunkReferences, limits.MaxChunkReferences)
			}
		}
	}
	if err := validateContext(ctx, &value, true); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	resolved := make(map[xethash.Hash]Xorb)
	resolve := func(hash xethash.Hash) (Xorb, error) {
		if err := ctx.Err(); err != nil {
			return Xorb{}, err
		}
		if value, ok := resolved[hash]; ok {
			return value, nil
		}
		value, found, err := lookup(hash)
		if err != nil {
			return Xorb{}, fmt.Errorf("%w: resolve %s: %w", ErrXorbLookup, hash, err)
		}
		if !found {
			return Xorb{}, fmt.Errorf("shard: referenced xorb %s not found", hash)
		}
		if err := validateContext(ctx, &Shard{Xorbs: []Xorb{value}}, true); err != nil {
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				return Xorb{}, err
			}
			return Xorb{}, fmt.Errorf("%w: stored xorb %s is invalid: %v", ErrXorbLookup, hash, err)
		}
		if value.Hash != hash {
			return Xorb{}, fmt.Errorf("%w: xorb lookup returned %s for %s", ErrXorbLookup, value.Hash, hash)
		}
		resolved[hash] = value
		return value, nil
	}

	result := &Registration{
		Files: make([]RegisteredFile, 0, len(value.Files)),
		Xorbs: make([]Xorb, 0, len(value.Xorbs)),
	}
	for i, claimed := range value.Xorbs {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		stored, err := resolve(claimed.Hash)
		if err != nil {
			return nil, err
		}
		if !sameXorbMetadata(claimed, stored) {
			return nil, fmt.Errorf("shard: xorb %d metadata conflicts with stored xorb %s", i, claimed.Hash)
		}
		canonical := stored
		canonical.Chunks = append([]XorbChunk(nil), stored.Chunks...)
		for j := range canonical.Chunks {
			canonical.Chunks[j].Flags = claimed.Chunks[j].Flags
		}
		result.Xorbs = append(result.Xorbs, canonical)
	}

	eligible := make(map[xethash.Hash]struct{})
	for _, value := range result.Xorbs {
		for _, chunk := range value.Chunks {
			if chunk.Flags&ChunkFlagGlobalDedup != 0 || chunk.Hash.LastUint64()%1024 == 0 {
				eligible[chunk.Hash] = struct{}{}
			}
		}
	}
	for i, file := range value.Files {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		var fileSubtree *xethash.MerkleHashSubtree
		var size uint64
		for j, term := range file.Terms {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			xorbInfo, err := resolve(term.XorbHash)
			if err != nil {
				return nil, fmt.Errorf("shard: file %d term %d: %w", i, j, err)
			}
			if term.Start >= term.End || term.End > uint32(len(xorbInfo.Chunks)) {
				return nil, fmt.Errorf("shard: file %d term %d exceeds stored xorb chunks", i, j)
			}
			hashes := make([]xethash.Hash, 0, term.End-term.Start)
			nodes := make([]xethash.Node, 0, term.End-term.Start)
			var termSize uint64
			for _, chunk := range xorbInfo.Chunks[term.Start:term.End] {
				if math.MaxUint64-termSize < uint64(chunk.Length) || math.MaxUint64-size < uint64(chunk.Length) {
					return nil, fmt.Errorf("shard: file %d size overflows", i)
				}
				termSize += uint64(chunk.Length)
				size += uint64(chunk.Length)
				hashes = append(hashes, chunk.Hash)
				nodes = append(nodes, xethash.Node{Hash: chunk.Hash, Size: uint64(chunk.Length)})
			}
			if termSize != uint64(term.UnpackedBytes) {
				return nil, fmt.Errorf("shard: file %d term %d unpacked length mismatch", i, j)
			}
			if xethash.Verification(hashes) != term.Verification {
				return nil, fmt.Errorf("shard: file %d term %d verification mismatch", i, j)
			}
			termSubtree := xethash.NewSubtree(j == 0, nodes, j == len(file.Terms)-1)
			if fileSubtree == nil {
				fileSubtree = termSubtree
			} else {
				fileSubtree, err = xethash.MergeSubtrees(fileSubtree, termSubtree)
				if err != nil {
					return nil, fmt.Errorf("shard: file %d term %d Merkle merge: %w", i, j, err)
				}
			}
		}
		computed := xethash.Zero
		if fileSubtree != nil {
			root, ok := fileSubtree.FinalHash()
			if !ok {
				return nil, fmt.Errorf("shard: file %d has incomplete Merkle tree", i)
			}
			computed = xethash.Protect(root, xethash.Zero)
		}
		if computed != file.Hash {
			return nil, fmt.Errorf("shard: file %d hash mismatch: declared %s, computed %s", i, file.Hash, computed)
		}
		if len(file.Terms) != 0 {
			first := file.Terms[0]
			if embeddedXorb(value.Xorbs, first.XorbHash) {
				xorbInfo := resolved[first.XorbHash]
				eligible[xorbInfo.Chunks[first.Start].Hash] = struct{}{}
			}
		}
		result.Files = append(result.Files, RegisteredFile{File: cloneFile(file), Size: size})
	}
	result.GlobalDedupChunks = make([]xethash.Hash, 0, len(eligible))
	for hash := range eligible {
		result.GlobalDedupChunks = append(result.GlobalDedupChunks, hash)
	}
	sort.Slice(result.GlobalDedupChunks, func(i, j int) bool {
		return result.GlobalDedupChunks[i].String() < result.GlobalDedupChunks[j].String()
	})
	return result, nil
}

func limitExceeded(value, limit uint64) bool { return limit != 0 && value > limit }

func sameXorbMetadata(claimed, stored Xorb) bool {
	if claimed.Hash != stored.Hash || claimed.RawBytes != stored.RawBytes || len(claimed.Chunks) != len(stored.Chunks) {
		return false
	}
	for i := range claimed.Chunks {
		if claimed.Chunks[i].Hash != stored.Chunks[i].Hash ||
			claimed.Chunks[i].Offset != stored.Chunks[i].Offset ||
			claimed.Chunks[i].Length != stored.Chunks[i].Length {
			return false
		}
	}
	return true
}

func cloneFile(value File) File {
	value.Terms = append([]Term(nil), value.Terms...)
	if value.SHA256 != nil {
		sum := *value.SHA256
		value.SHA256 = &sum
	}
	return value
}

func embeddedXorb(values []Xorb, hash xethash.Hash) bool {
	for _, value := range values {
		if value.Hash == hash {
			return true
		}
	}
	return false
}
