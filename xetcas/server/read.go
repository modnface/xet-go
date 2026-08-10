package server

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"time"

	"github.com/jacobwoliver/xet-go/shard"
	"github.com/jacobwoliver/xet-go/xetcas"
	"github.com/jacobwoliver/xet-go/xethash"
	"github.com/jacobwoliver/xet-go/xorb"
)

func (s *Service) file(ctx context.Context, credential string, hash xethash.Hash) (FileRecord, error) {
	if _, err := s.authorize(ctx, credential, AccessRequest{Operation: OperationReadFile, Hash: hash}); err != nil {
		return FileRecord{}, err
	}
	value, found, err := s.index.GetFile(ctx, hash)
	if err != nil {
		return FileRecord{}, err
	}
	if !found {
		return FileRecord{}, ErrNotFound
	}
	return value, nil
}

func (s *Service) File(ctx context.Context, credential string, hash xethash.Hash) (FileRecord, error) {
	return s.file(ctx, credential, hash)
}

func (s *Service) validateRecipeWork(ctx context.Context, file shard.RegisteredFile) error {
	if uint64(len(file.File.Terms)) > s.registration.MaxTerms {
		return fmt.Errorf("%w: reconstruction has %d terms, limit %d",
			ErrTooLarge, len(file.File.Terms), s.registration.MaxTerms)
	}
	var references uint64
	for i, term := range file.File.Terms {
		if i&1023 == 0 {
			if err := ctx.Err(); err != nil {
				return err
			}
		}
		if term.End < term.Start {
			return errors.New("xet CAS server: stored reconstruction has a reversed chunk range")
		}
		count := uint64(term.End - term.Start)
		if math.MaxUint64-references < count || references+count > s.registration.MaxChunkReferences {
			return fmt.Errorf("%w: reconstruction exceeds %d chunk references",
				ErrTooLarge, s.registration.MaxChunkReferences)
		}
		references += count
	}
	return nil
}

func (s *Service) layoutLookup(ctx context.Context) xetcas.XorbLayoutLookup {
	return func(hash xethash.Hash) (*xorb.Ingested, bool, error) {
		value, found, err := s.index.GetXorb(ctx, hash)
		if err != nil || !found {
			return nil, found, err
		}
		layout := value.Layout
		layout.Chunks = append([]xorb.IngestedChunk(nil), value.Layout.Chunks...)
		return &layout, true, nil
	}
}

func (s *Service) ReconstructionV2(
	ctx context.Context,
	credential string,
	hash xethash.Hash,
	requested *xetcas.FileRange,
) (*xetcas.Reconstruction, error) {
	file, err := s.file(ctx, credential, hash)
	if err != nil {
		return nil, err
	}
	if err := s.validateRecipeWork(ctx, file.File); err != nil {
		return nil, err
	}
	plan, err := xetcas.PlanReconstructionContext(ctx, file.File, requested, s.layoutLookup(ctx))
	if err != nil {
		return nil, err
	}
	response := &xetcas.Reconstruction{
		OffsetIntoFirstRange: plan.OffsetIntoFirstRange,
		Terms:                append([]xetcas.ReconstructionTerm(nil), plan.Terms...),
		Xorbs:                make(map[xethash.Hash][]xetcas.MultiRangeFetch, len(plan.Xorbs)),
	}
	for xorbHash, ranges := range plan.Xorbs {
		for _, value := range ranges {
			url, err := s.signer.SignRange(ctx, BlobKey{Kind: BlobXorb, Hash: xorbHash}, value.Bytes)
			if err != nil {
				return nil, fmt.Errorf("xet CAS server: sign xorb %s range: %w", xorbHash, err)
			}
			// One range per URL works with direct S3 GetObject, which does not
			// implement HTTP multi-range requests.
			response.Xorbs[xorbHash] = append(response.Xorbs[xorbHash], xetcas.MultiRangeFetch{
				URL: url, Ranges: []xetcas.XorbRangeDescriptor{value},
			})
		}
	}
	if err := response.Validate(); err != nil {
		return nil, err
	}
	return response, nil
}

func (s *Service) ReconstructionV1(
	ctx context.Context,
	credential string,
	hash xethash.Hash,
	requested *xetcas.FileRange,
) (*xetcas.ReconstructionV1, error) {
	file, err := s.file(ctx, credential, hash)
	if err != nil {
		return nil, err
	}
	if err := s.validateRecipeWork(ctx, file.File); err != nil {
		return nil, err
	}
	plan, err := xetcas.PlanReconstructionContext(ctx, file.File, requested, s.layoutLookup(ctx))
	if err != nil {
		return nil, err
	}
	response := &xetcas.ReconstructionV1{
		OffsetIntoFirstRange: plan.OffsetIntoFirstRange,
		Terms:                append([]xetcas.ReconstructionTerm(nil), plan.Terms...),
		FetchInfo:            make(map[xethash.Hash][]xetcas.V1FetchInfo, len(plan.Xorbs)),
	}
	for xorbHash, ranges := range plan.Xorbs {
		for _, value := range ranges {
			url, err := s.signer.SignRange(ctx, BlobKey{Kind: BlobXorb, Hash: xorbHash}, value.Bytes)
			if err != nil {
				return nil, fmt.Errorf("xet CAS server: sign xorb %s range: %w", xorbHash, err)
			}
			response.FetchInfo[xorbHash] = append(response.FetchInfo[xorbHash], xetcas.V1FetchInfo{
				Range: value.Chunks, URL: url, URLRange: value.Bytes,
			})
		}
	}
	return response, nil
}

func (s *Service) BatchReconstructionV1(
	ctx context.Context,
	credential string,
	hashes []xethash.Hash,
) (*xetcas.BatchReconstructionV1, error) {
	response := &xetcas.BatchReconstructionV1{
		Files:     make(map[xethash.Hash][]xetcas.ReconstructionTerm),
		FetchInfo: make(map[xethash.Hash][]xetcas.V1FetchInfo),
	}
	seen := make(map[xethash.Hash]struct{}, len(hashes))
	var responseTerms uint64
	for _, hash := range hashes {
		if _, duplicate := seen[hash]; duplicate {
			continue
		}
		seen[hash] = struct{}{}
		value, err := s.ReconstructionV1(ctx, credential, hash, nil)
		if errors.Is(err, ErrNotFound) {
			continue
		}
		if err != nil {
			return nil, err
		}
		if uint64(len(value.Terms)) > s.registration.MaxTerms-responseTerms {
			return nil, fmt.Errorf("%w: batch reconstruction exceeds %d terms",
				ErrTooLarge, s.registration.MaxTerms)
		}
		responseTerms += uint64(len(value.Terms))
		response.Files[hash] = value.Terms
		for xorbHash, fetches := range value.FetchInfo {
			response.FetchInfo[xorbHash] = append(response.FetchInfo[xorbHash], fetches...)
		}
	}
	return response, nil
}

func (s *Service) FileChunkHashes(
	ctx context.Context,
	credential string,
	hash xethash.Hash,
	dirty []xetcas.FileRange,
) (*xetcas.FileChunkHashesResponse, error) {
	file, err := s.file(ctx, credential, hash)
	if err != nil {
		return nil, err
	}
	if err := s.validateRecipeWork(ctx, file.File); err != nil {
		return nil, err
	}
	return xetcas.PlanFileChunkHashesContext(ctx, file.File, dirty, s.layoutLookup(ctx))
}

func (s *Service) GlobalDedup(
	ctx context.Context,
	credential, prefix string,
	hash xethash.Hash,
) ([]byte, error) {
	// The OpenAPI contract specifies default-merkledb, while released official
	// xet-core clients send the shared data default "default" to both xorb and
	// dedup routes. Accept that legacy wire value without changing the Go
	// client's spec-conforming default.
	if prefix != xetcas.DefaultDedupPrefix && prefix != xetcas.DefaultXorbPrefix {
		return nil, ErrNotFound
	}
	if _, err := s.authorize(ctx, credential, AccessRequest{
		Operation: OperationReadDedup, Prefix: prefix, Hash: hash,
	}); err != nil {
		return nil, err
	}
	record, found, err := s.index.GetDedup(ctx, hash)
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, ErrNotFound
	}
	reader, err := s.blobs.Get(ctx, record.Shard, nil)
	if err != nil {
		return nil, err
	}
	body, err := io.ReadAll(io.LimitReader(reader, shard.MaxSize+1))
	if err != nil {
		_ = reader.Close()
		return nil, err
	}
	if err := reader.Close(); err != nil {
		return nil, fmt.Errorf("xet CAS server: close dedup shard: %w", err)
	}
	if len(body) > shard.MaxSize {
		return nil, ErrTooLarge
	}
	full, err := shard.Decode(body)
	if err != nil {
		return nil, err
	}
	if full.Footer == nil {
		return nil, errors.New("xet CAS server: dedup index points to a footerless shard")
	}
	source := dedupSource(*full)
	now := s.now().Unix()
	if now < 0 {
		return nil, errors.New("xet CAS server: dedup clock precedes Unix epoch")
	}
	created := uint64(now)
	ttl := uint64(s.dedupTTL / time.Second)
	expires := created + ttl
	return shard.EncodeProtectedDedup(source, s.dedupKey, created, expires)
}

func dedupSource(value shard.Shard) shard.Shard {
	present := make(map[xethash.Hash]struct{}, len(value.Xorbs))
	for _, xorbInfo := range value.Xorbs {
		present[xorbInfo.Hash] = struct{}{}
	}
	files := make([]shard.File, 0, len(value.Files))
	for _, file := range value.Files {
		if len(file.Terms) == 0 {
			continue
		}
		if _, ok := present[file.Terms[0].XorbHash]; ok {
			files = append(files, file)
		}
	}
	return shard.Shard{Files: files, Xorbs: value.Xorbs}
}
