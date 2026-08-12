package server

import (
	"context"
	"errors"
	"fmt"
	"slices"

	"github.com/jmwoliver/xet-go/shard"
	"github.com/jmwoliver/xet-go/xethash"
)

// CloneFileBetweenNamespaces is a trusted embedding capability that publishes
// one durably registered source file in another namespace of this same CAS.
// It does not perform CAS credential authorization: the embedding service must
// independently authorize source reads and destination writes before calling
// it. No Xorb payload is read, copied, uploaded, or staged.
func (s *Service) CloneFileBetweenNamespaces(
	ctx context.Context,
	sourceNamespace string,
	destinationNamespace string,
	hash xethash.Hash,
	expectedSize uint64,
	expectedSHA256 *[32]byte,
) (returnError error) {
	if ctx == nil {
		return errors.New("xet CAS server: nil clone-file context")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if sourceNamespace == "" || destinationNamespace == "" {
		return fmt.Errorf("%w: trusted clone requires source and destination namespaces", ErrInvalid)
	}
	release, err := s.acquireIngest(ctx)
	if err != nil {
		return err
	}
	defer release()

	cloneContext, cancelClone := context.WithCancelCause(ctx)
	defer cancelClone(nil)
	lease, err := s.acquireActiveFileLease(cloneContext, cancelClone, sourceNamespace, hash)
	if err != nil {
		return err
	}
	defer func() { returnError = errors.Join(returnError, lease.Close()) }()

	file, cloneShard, registration, err := s.validatedCloneSource(cloneContext, sourceNamespace, hash)
	if err != nil {
		return err
	}
	if registration.Files[0].Size != expectedSize {
		return fmt.Errorf("%w: source file size %d differs from required size %d",
			ErrNotFound, registration.Files[0].Size, expectedSize)
	}
	if file.File.File.SHA256 != nil {
		if err := s.requireScopedSHA256(
			cloneContext, sourceNamespace, *file.File.File.SHA256, expectedSize, hash,
		); err != nil {
			return err
		}
	}
	if expectedSHA256 != nil {
		if err := s.requireScopedSHA256(
			cloneContext, sourceNamespace, *expectedSHA256, expectedSize, hash,
		); err != nil {
			return err
		}
		sum := *expectedSHA256
		cloneShard.Files[0].SHA256 = &sum
		cloneShard.Files[0].Flags |= shard.FileFlagSHA256
	}

	body, err := shard.EncodeUpload(cloneShard)
	if err != nil {
		return fmt.Errorf("%w: encode validated clone shard: %v", ErrCorrupt, err)
	}
	if _, err := s.publishShard(cloneContext, Grant{Namespace: destinationNamespace}, body); err != nil {
		return err
	}
	return s.VerifyFileInNamespace(
		cloneContext, destinationNamespace, hash, expectedSize, expectedSHA256,
	)
}

func (s *Service) validatedCloneSource(
	ctx context.Context,
	namespace string,
	hash xethash.Hash,
) (FileRecord, shard.Shard, *shard.Registration, error) {
	file, err := s.scopedFile(ctx, namespace, hash)
	if err != nil {
		return FileRecord{}, shard.Shard{}, nil, err
	}
	if err := s.validateRecipeWork(ctx, file.File); err != nil {
		return FileRecord{}, shard.Shard{}, nil, err
	}
	registeredShard, found, err := s.index.GetShard(ctx, namespace, file.Shard.Hash)
	if err != nil {
		return FileRecord{}, shard.Shard{}, nil, err
	}
	if !found {
		return FileRecord{}, shard.Shard{}, nil,
			fmt.Errorf("%w: source shard registration is unavailable", ErrNotFound)
	}
	if err := validateShardRecord(file.Shard.Hash, registeredShard); err != nil {
		return FileRecord{}, shard.Shard{}, nil, err
	}

	body, found, _, err := s.readStoredBlob(ctx, file.Shard, shard.MaxSize)
	if err != nil {
		return FileRecord{}, shard.Shard{}, nil, err
	}
	if !found {
		return FileRecord{}, shard.Shard{}, nil,
			fmt.Errorf("%w: source shard blob is unavailable", ErrNotFound)
	}
	if xethash.Chunk(body) != file.Shard.Hash {
		return FileRecord{}, shard.Shard{}, nil,
			fmt.Errorf("%w: source shard blob identity differs from its key", ErrCorrupt)
	}
	logical, err := decodeCanonicalShard(body)
	if err != nil {
		return FileRecord{}, shard.Shard{}, nil,
			fmt.Errorf("%w: invalid source shard: %v", ErrCorrupt, err)
	}
	var selected *shard.File
	for i := range logical.Files {
		if logical.Files[i].Hash == hash {
			selected = &logical.Files[i]
			break
		}
	}
	if selected == nil || !sameCloneFile(*selected, file.File.File) {
		return FileRecord{}, shard.Shard{}, nil,
			fmt.Errorf("%w: source file record differs from its shard", ErrCorrupt)
	}

	xorbs, err := s.durableCloneXorbs(ctx, selected.Terms)
	if err != nil {
		return FileRecord{}, shard.Shard{}, nil, err
	}
	cloneShard := shard.Shard{Files: []shard.File{*selected}}
	if len(selected.Terms) != 0 {
		firstHash := selected.Terms[0].XorbHash
		cloneShard.Xorbs = []shard.Xorb{xorbs[firstHash]}
		for _, embedded := range logical.Xorbs {
			if embedded.Hash == firstHash {
				cloneShard.Xorbs[0] = embedded
				break
			}
		}
	}
	registration, err := shard.ValidateRegistrationContext(ctx, cloneShard,
		func(hash xethash.Hash) (shard.Xorb, bool, error) {
			value, ok := xorbs[hash]
			return value, ok, nil
		}, s.registration)
	if err != nil {
		switch {
		case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
			return FileRecord{}, shard.Shard{}, nil, err
		case errors.Is(err, shard.ErrRegistrationLimit):
			return FileRecord{}, shard.Shard{}, nil, fmt.Errorf("%w: %v", ErrTooLarge, err)
		default:
			return FileRecord{}, shard.Shard{}, nil,
				fmt.Errorf("%w: source file registration is invalid: %v", ErrCorrupt, err)
		}
	}
	if len(registration.Files) != 1 || registration.Files[0].Size != file.File.Size {
		return FileRecord{}, shard.Shard{}, nil,
			fmt.Errorf("%w: source file record size differs from its validated shard", ErrCorrupt)
	}
	return file, cloneShard, registration, nil
}

func sameCloneFile(left, right shard.File) bool {
	if left.Hash != right.Hash || left.Flags != right.Flags || !slices.Equal(left.Terms, right.Terms) {
		return false
	}
	if left.SHA256 == nil || right.SHA256 == nil {
		return left.SHA256 == nil && right.SHA256 == nil
	}
	return *left.SHA256 == *right.SHA256
}

func (s *Service) durableCloneXorbs(
	ctx context.Context,
	terms []shard.Term,
) (map[xethash.Hash]shard.Xorb, error) {
	result := make(map[xethash.Hash]shard.Xorb)
	for i, term := range terms {
		if i&1023 == 0 {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
		}
		if _, ok := result[term.XorbHash]; ok {
			continue
		}
		record, found, err := s.index.GetXorb(ctx, term.XorbHash)
		if err != nil {
			return nil, err
		}
		if !found {
			return nil, fmt.Errorf("%w: source Xorb %s is not indexed", ErrNotFound, term.XorbHash)
		}
		expectedSize, err := ValidateXorbRecord(term.XorbHash, record)
		if err != nil {
			return nil, err
		}
		info, found, err := s.blobs.Head(ctx, record.Blob)
		if err != nil {
			return nil, err
		}
		if !found {
			return nil, fmt.Errorf("%w: source Xorb %s blob is unavailable", ErrNotFound, term.XorbHash)
		}
		if info.Size != expectedSize {
			return nil, fmt.Errorf("%w: source Xorb %s blob size %d differs from expected %d",
				ErrCorrupt, term.XorbHash, info.Size, expectedSize)
		}
		value, err := shard.XorbFromIngested(&record.Layout)
		if err != nil {
			return nil, fmt.Errorf("%w: source Xorb %s layout is invalid: %v", ErrCorrupt, term.XorbHash, err)
		}
		result[term.XorbHash] = value
	}
	return result, nil
}

func (s *Service) requireScopedSHA256(
	ctx context.Context,
	namespace string,
	sum [32]byte,
	size uint64,
	hash xethash.Hash,
) error {
	associated, found, err := s.index.ResolveSHA256(ctx, namespace, sum, size)
	if err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if !found || associated != hash {
		return fmt.Errorf("%w: source SHA-256 association is unavailable", ErrNotFound)
	}
	return nil
}
