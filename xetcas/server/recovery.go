package server

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/jmwoliver/xet-go/shard"
	"github.com/jmwoliver/xet-go/xethash"
	"github.com/jmwoliver/xet-go/xorb"
)

// RecoverExpiredBlobStages validates and republishes immutable objects whose
// logical publication may have been interrupted. It never writes or deletes
// blob payloads and never authenticates as a tenant. Missing, corrupt, blocked,
// conflicting, and backend-failed stages remain protected for a later pass or
// operator decision.
func (s *Service) RecoverExpiredBlobStages(
	ctx context.Context,
	cutoff time.Time,
	request PageRequest,
) (BlobStageRecoveryPage, error) {
	expiry, ok := s.index.(ProtectionExpiryStore)
	if !ok {
		return BlobStageRecoveryPage{}, ErrProtectionExpiryUnsupported
	}
	stages, err := expiry.ListExpiredBlobStages(ctx, cutoff, request)
	if err != nil {
		return BlobStageRecoveryPage{}, err
	}
	page := BlobStageRecoveryPage{Items: make([]BlobStageRecoveryResult, 0, len(stages.Items))}
	for _, stage := range stages.Items {
		if err := ctx.Err(); err != nil {
			return page, err
		}
		release, err := s.acquireIngest(ctx)
		if err != nil {
			return page, err
		}
		result := s.recoverExpiredBlobStage(ctx, expiry, stage, cutoff)
		release()
		if errors.Is(result.Err, context.Canceled) || errors.Is(result.Err, context.DeadlineExceeded) {
			return page, result.Err
		}
		page.Items = append(page.Items, result)
	}
	page.NextCursor = stages.NextCursor
	return page, nil
}

func (s *Service) recoverExpiredBlobStage(
	ctx context.Context,
	expiry ProtectionExpiryStore,
	stage BlobStage,
	cutoff time.Time,
) BlobStageRecoveryResult {
	limit := int64(0)
	switch stage.Blob.Kind {
	case BlobXorb:
		limit = xorb.MaxCompleteSize
	case BlobShard:
		limit = shard.MaxSize
	default:
		return corruptRecovery(stage, BlobStageRecoveryValidate, errors.New("unsupported blob kind"))
	}
	body, found, phase, err := s.readStoredBlob(ctx, stage.Blob, limit)
	if err != nil {
		if errors.Is(err, ErrCorrupt) {
			return BlobStageRecoveryResult{Stage: stage, Status: BlobStageRecoveryCorrupt, Phase: phase, Err: err}
		}
		return BlobStageRecoveryResult{Stage: stage, Status: BlobStageRecoveryFailed, Phase: phase, Err: err}
	}
	if !found {
		return BlobStageRecoveryResult{Stage: stage, Status: BlobStageRecoveryMissing, Phase: phase}
	}

	var result BlobStageRecoveryResult
	switch stage.Blob.Kind {
	case BlobXorb:
		result = s.recoverXorbStage(ctx, stage, body)
	case BlobShard:
		result = s.recoverShardStage(ctx, stage, body)
	}
	if result.Status != BlobStageRecoveryPublishedNotRemoved {
		return result
	}
	removed, err := expiry.DeleteExpiredBlobStage(ctx, stage.Namespace, stage.ID, cutoff)
	if err != nil {
		result.Status = BlobStageRecoveryPublishedDeleteFailed
		result.Phase = BlobStageRecoveryDelete
		result.Err = err
		return result
	}
	if removed {
		result.Status = BlobStageRecoveryPublishedRemoved
	}
	return result
}

func (s *Service) readStoredBlob(
	ctx context.Context,
	key BlobKey,
	limit int64,
) ([]byte, bool, BlobStageRecoveryPhase, error) {
	info, found, err := s.blobs.Head(ctx, key)
	if err != nil {
		return nil, false, BlobStageRecoveryHead, err
	}
	if !found {
		return nil, false, BlobStageRecoveryHead, nil
	}
	if info.Size <= 0 || info.Size > limit {
		return nil, true, BlobStageRecoveryValidate,
			fmt.Errorf("%w: stored %s size %d is outside [1,%d]", ErrCorrupt, key.Kind, info.Size, limit)
	}
	reader, err := s.blobs.Get(ctx, key, nil)
	if errors.Is(err, ErrNotFound) {
		return nil, false, BlobStageRecoveryRead, nil
	}
	if err != nil {
		return nil, true, BlobStageRecoveryRead, err
	}
	body, readErr := io.ReadAll(io.LimitReader(reader, info.Size+1))
	closeErr := reader.Close()
	if err := errors.Join(readErr, closeErr); err != nil {
		return nil, true, BlobStageRecoveryRead, err
	}
	if int64(len(body)) != info.Size {
		return nil, true, BlobStageRecoveryValidate,
			fmt.Errorf("%w: stored %s size %d differs from declared %d", ErrCorrupt, key.Kind, len(body), info.Size)
	}
	return body, true, "", nil
}

func (s *Service) recoverXorbStage(
	ctx context.Context,
	stage BlobStage,
	body []byte,
) BlobStageRecoveryResult {
	record, err := xorbRecordFromComplete(body, stage.Blob)
	if err != nil {
		return corruptRecovery(stage, BlobStageRecoveryValidate, err)
	}
	if err := s.index.PutXorb(ctx, record); err != nil {
		status := BlobStageRecoveryFailed
		if errors.Is(err, ErrConflict) {
			status = BlobStageRecoveryConflict
		}
		return BlobStageRecoveryResult{Stage: stage, Status: status, Phase: BlobStageRecoveryPublish, Err: err}
	}
	return BlobStageRecoveryResult{Stage: stage, Status: BlobStageRecoveryPublishedNotRemoved}
}

func xorbRecordFromComplete(body []byte, key BlobKey) (XorbRecord, error) {
	object, err := decodeCanonicalXorb(body)
	if err != nil {
		return XorbRecord{}, err
	}
	if object.Hash != key.Hash {
		return XorbRecord{}, errors.New("stored xorb identity differs from key")
	}
	record := XorbRecord{Blob: key, Layout: xorb.Ingested{
		Hash: object.Hash, NetworkBytes: object.FooterOffset, UncompressedSize: object.UncompressedSize,
		Chunks: make([]xorb.IngestedChunk, len(object.Chunks)),
	}}
	for i, chunk := range object.Chunks {
		record.Layout.Chunks[i] = xorb.IngestedChunk{
			Hash: chunk.Hash, SerializedOffset: chunk.SerializedOffset, SerializedLength: chunk.SerializedLength,
			UncompressedOffset: chunk.UncompressedOffset, UncompressedLength: chunk.UncompressedLength,
		}
	}
	return record, nil
}

func decodeCanonicalXorb(body []byte) (*xorb.Object, error) {
	object, err := xorb.Decode(body)
	if err != nil {
		return nil, err
	}
	if object.Footer == nil || object.Footer.Version != 1 || object.LegacyTrailer ||
		object.Footer.UniquenessNonce != ([4]byte{}) || object.FooterOffset == 0 {
		return nil, errors.New("stored xorb is not a canonical complete object")
	}
	canonical, err := xorb.EncodeComplete(object, [4]byte{})
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(canonical, body) {
		return nil, errors.New("stored xorb complete encoding is not canonical")
	}
	return object, nil
}

func (s *Service) recoverShardStage(
	ctx context.Context,
	stage BlobStage,
	body []byte,
) BlobStageRecoveryResult {
	logical, err := decodeCanonicalShard(body)
	if err != nil {
		return corruptRecovery(stage, BlobStageRecoveryValidate, err)
	}
	if xethash.Chunk(body) != stage.Blob.Hash {
		return corruptRecovery(stage, BlobStageRecoveryValidate, errors.New("stored shard identity differs from key"))
	}
	registration, err := s.validateShardRegistration(ctx, logical)
	if err != nil {
		status := BlobStageRecoveryFailed
		switch {
		case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
			// Preserve cancellation so the page stops without advancing its cursor.
		case errors.Is(err, shard.ErrRegistrationLimit), errors.Is(err, shard.ErrXorbNotFound):
			status = BlobStageRecoveryBlocked
		case errors.Is(err, shard.ErrXorbConflict):
			status = BlobStageRecoveryConflict
		case !errors.Is(err, shard.ErrXorbLookup):
			status = BlobStageRecoveryCorrupt
			err = fmt.Errorf("%w: %v", ErrCorrupt, err)
		}
		return BlobStageRecoveryResult{Stage: stage, Status: status, Phase: BlobStageRecoveryResolve, Err: err}
	}
	if err := s.index.PublishShard(ctx, makeShardPublication(stage.Namespace, stage.Blob, registration)); err != nil {
		status := BlobStageRecoveryFailed
		if errors.Is(err, ErrConflict) {
			status = BlobStageRecoveryConflict
		}
		return BlobStageRecoveryResult{Stage: stage, Status: status, Phase: BlobStageRecoveryPublish, Err: err}
	}
	return BlobStageRecoveryResult{Stage: stage, Status: BlobStageRecoveryPublishedNotRemoved}
}

func decodeCanonicalShard(body []byte) (shard.Shard, error) {
	decoded, err := shard.Decode(body)
	if err != nil {
		return shard.Shard{}, err
	}
	if decoded.Footer == nil {
		return shard.Shard{}, errors.New("stored shard is footerless")
	}
	logical := shard.Shard{
		Files: append([]shard.File(nil), decoded.Files...),
		Xorbs: append([]shard.Xorb(nil), decoded.Xorbs...),
	}
	canonical, err := shard.EncodeFull(logical)
	if err != nil {
		return shard.Shard{}, err
	}
	if !bytes.Equal(canonical, body) {
		return shard.Shard{}, errors.New("stored shard full encoding is not canonical")
	}
	return logical, nil
}

func corruptRecovery(
	stage BlobStage,
	phase BlobStageRecoveryPhase,
	err error,
) BlobStageRecoveryResult {
	return BlobStageRecoveryResult{
		Stage: stage, Status: BlobStageRecoveryCorrupt, Phase: phase,
		Err: fmt.Errorf("%w: %v", ErrCorrupt, err),
	}
}
