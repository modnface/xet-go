package server

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/jmwoliver/xet-go/shard"
	"github.com/jmwoliver/xet-go/xethash"
	"github.com/jmwoliver/xet-go/xorb"
)

var errAuditDependency = errors.New("xet CAS server: audit dependency check stopped")

// AuditInventory performs bounded, read-only forward-integrity checks over one
// administrative inventory. It does not authenticate as a tenant, repair
// records, establish a consistent store snapshot, determine catalog liveness,
// or authorize payload deletion.
func (s *Service) AuditInventory(ctx context.Context, request AuditRequest) (AuditPage, error) {
	pageRequest, err := prepareAuditPage(request)
	if err != nil {
		return AuditPage{}, err
	}
	if err := ctx.Err(); err != nil {
		return AuditPage{}, err
	}
	page := AuditPage{Kind: request.Kind}
	var nextCursor string

	switch request.Kind {
	case AuditKindBlobXorb, AuditKindBlobShard:
		lister, ok := s.blobs.(BlobLister)
		if !ok {
			return AuditPage{}, fmt.Errorf("xet CAS server: audit %s requires BlobLister: %w", request.Kind, ErrAuditUnsupported)
		}
		kind := BlobXorb
		if request.Kind == AuditKindBlobShard {
			kind = BlobShard
		}
		inventory, err := lister.ListBlobs(ctx, kind, pageRequest)
		if err != nil {
			return AuditPage{}, err
		}
		if err := ctx.Err(); err != nil {
			return AuditPage{}, err
		}
		if err := validateAuditPage(request, pageRequest, len(inventory.Items), inventory.NextCursor, nil); err != nil {
			return AuditPage{}, err
		}
		page.Items = make([]AuditResult, 0, len(inventory.Items))
		for _, entry := range inventory.Items {
			if err := ctx.Err(); err != nil {
				return page, err
			}
			result := s.auditBlobInventory(ctx, request.Kind, entry)
			if err := ctx.Err(); err != nil {
				return page, err
			}
			if err := auditContextError(result.Err); err != nil {
				return page, err
			}
			page.Items = append(page.Items, result)
		}
		nextCursor = inventory.NextCursor

	case AuditKindXorbRecord, AuditKindShardRecord, AuditKindFileRecord,
		AuditKindDedupRecord, AuditKindSHA256Association:
		lister, ok := s.index.(IndexLister)
		if !ok {
			return AuditPage{}, fmt.Errorf("xet CAS server: audit %s requires IndexLister: %w", request.Kind, ErrAuditUnsupported)
		}
		page.Items, nextCursor, err = s.auditIndexInventory(ctx, lister, request, pageRequest)
		if err != nil {
			page.NextCursor = ""
			return page, err
		}

	case AuditKindBlobStage, AuditKindFileLease:
		if s.protections == nil {
			return AuditPage{}, fmt.Errorf("xet CAS server: audit %s requires ProtectionStore: %w", request.Kind, ErrAuditUnsupported)
		}
		page.Items, nextCursor, err = s.auditProtectionInventory(ctx, request, pageRequest)
		if err != nil {
			page.NextCursor = ""
			return page, err
		}
	}

	if err := ctx.Err(); err != nil {
		page.NextCursor = ""
		return page, err
	}
	if nextCursor != "" {
		page.NextCursor = encodeAuditCursor(request.Kind, request.Namespace, nextCursor)
	}
	if err := ctx.Err(); err != nil {
		page.NextCursor = ""
		return page, err
	}
	return page, nil
}

func (s *Service) auditIndexInventory(
	ctx context.Context,
	lister IndexLister,
	request AuditRequest,
	pageRequest PageRequest,
) ([]AuditResult, string, error) {
	switch request.Kind {
	case AuditKindXorbRecord:
		page, err := lister.ListXorbs(ctx, pageRequest)
		if err != nil {
			return nil, "", err
		}
		results, err := auditItems(ctx, request, pageRequest, page.Items, page.NextCursor, nil, s.auditXorbRecord)
		return results, page.NextCursor, err
	case AuditKindShardRecord:
		page, err := lister.ListShards(ctx, request.Namespace, pageRequest)
		if err != nil {
			return nil, "", err
		}
		results, err := auditItems(ctx, request, pageRequest, page.Items, page.NextCursor,
			func(value ScopedShardRecord) string { return value.Namespace }, s.auditShardRecord)
		return results, page.NextCursor, err
	case AuditKindFileRecord:
		page, err := lister.ListFiles(ctx, request.Namespace, pageRequest)
		if err != nil {
			return nil, "", err
		}
		results, err := auditItems(ctx, request, pageRequest, page.Items, page.NextCursor,
			func(value ScopedFileRecord) string { return value.Namespace }, s.auditFileRecord)
		return results, page.NextCursor, err
	case AuditKindDedupRecord:
		page, err := lister.ListDedup(ctx, request.Namespace, pageRequest)
		if err != nil {
			return nil, "", err
		}
		results, err := auditItems(ctx, request, pageRequest, page.Items, page.NextCursor,
			func(value ScopedDedupRecord) string { return value.Namespace }, s.auditDedupRecord)
		return results, page.NextCursor, err
	case AuditKindSHA256Association:
		page, err := lister.ListSHA256(ctx, request.Namespace, pageRequest)
		if err != nil {
			return nil, "", err
		}
		results, err := auditItems(ctx, request, pageRequest, page.Items, page.NextCursor,
			func(value ScopedSHA256Association) string { return value.Namespace }, s.auditSHA256Association)
		return results, page.NextCursor, err
	default:
		return nil, "", fmt.Errorf("%w: unknown index audit kind %q", ErrInvalid, request.Kind)
	}
}

func (s *Service) auditProtectionInventory(
	ctx context.Context,
	request AuditRequest,
	pageRequest PageRequest,
) ([]AuditResult, string, error) {
	if request.Kind == AuditKindBlobStage {
		page, err := s.protections.ListBlobStages(ctx, request.Namespace, pageRequest)
		if err != nil {
			return nil, "", err
		}
		results, err := auditItems(ctx, request, pageRequest, page.Items, page.NextCursor,
			func(value BlobStage) string { return value.Namespace }, s.auditBlobStage)
		return results, page.NextCursor, err
	}
	page, err := s.protections.ListFileLeases(ctx, request.Namespace, pageRequest)
	if err != nil {
		return nil, "", err
	}
	results, err := auditItems(ctx, request, pageRequest, page.Items, page.NextCursor,
		func(value FileLease) string { return value.Namespace }, s.auditFileLease)
	return results, page.NextCursor, err
}

func auditItems[T any](
	ctx context.Context,
	request AuditRequest,
	pageRequest PageRequest,
	items []T,
	nextCursor string,
	namespace func(T) string,
	classify func(context.Context, T) AuditResult,
) ([]AuditResult, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := validateAuditPage(request, pageRequest, len(items), nextCursor, func(index int) string {
		return namespace(items[index])
	}); err != nil {
		return nil, err
	}
	results := make([]AuditResult, 0, len(items))
	for _, item := range items {
		if err := ctx.Err(); err != nil {
			return results, err
		}
		result := classify(ctx, item)
		if err := ctx.Err(); err != nil {
			return results, err
		}
		if err := auditContextError(result.Err); err != nil {
			return results, err
		}
		results = append(results, result)
	}
	return results, nil
}

func validateAuditPage(
	request AuditRequest,
	pageRequest PageRequest,
	count int,
	nextCursor string,
	namespace func(int) string,
) error {
	limit, err := pageLimit(pageRequest)
	if err != nil {
		return err
	}
	if count > limit {
		return fmt.Errorf("%w: audit %s lister returned %d items for limit %d", ErrCorrupt, request.Kind, count, limit)
	}
	if request.Namespace != nil {
		for i := range count {
			if namespace == nil || namespace(i) != *request.Namespace {
				return fmt.Errorf("%w: audit %s lister returned a record outside namespace %q",
					ErrCorrupt, request.Kind, *request.Namespace)
			}
		}
	}
	if nextCursor != "" && count == 0 {
		return fmt.Errorf("%w: audit %s lister returned a continuation without items", ErrCorrupt, request.Kind)
	}
	if pageRequest.Cursor != "" && nextCursor == pageRequest.Cursor {
		return fmt.Errorf("%w: audit %s lister did not advance its continuation", ErrCorrupt, request.Kind)
	}
	return nil
}

func (s *Service) auditBlobInventory(ctx context.Context, kind AuditKind, entry BlobEntry) AuditResult {
	subject := BlobAuditSubject{Entry: entry}
	wantKind := BlobXorb
	if kind == AuditKindBlobShard {
		wantKind = BlobShard
	}
	if entry.Key.Kind != wantKind || entry.Key.Hash == xethash.Zero {
		return auditInvalid(subject, nil, errors.New("listed blob identity does not match its inventory"))
	}
	if err := validateAuditBlobSize(entry.Key, entry.Info); err != nil {
		return auditIssue(subject, AuditFindingBlobSizeInvalid, auditBlobTarget(entry.Key), err)
	}
	if kind == AuditKindBlobShard {
		return AuditResult{
			Subject: subject, Status: AuditStatusIndeterminate,
			Finding: AuditFindingShardReverseLookupUnavailable,
		}
	}
	record, found, err := s.index.GetXorb(ctx, entry.Key.Hash)
	if err != nil {
		return auditLookupError(subject, auditXorbTarget(entry.Key.Hash), err)
	}
	if !found {
		return AuditResult{
			Subject: subject, Status: AuditStatusIndeterminate, Finding: AuditFindingXorbRecordMissing,
			Target: auditXorbTarget(entry.Key.Hash),
		}
	}
	expectedSize, err := ValidateXorbRecord(entry.Key.Hash, record)
	if err != nil {
		return auditInvalid(subject, auditXorbTarget(entry.Key.Hash), err)
	}
	if entry.Info.Size != expectedSize {
		return auditIssue(subject, AuditFindingBlobSizeInvalid, auditBlobTarget(entry.Key),
			fmt.Errorf("%w: stored Xorb size %d, expected %d", ErrCorrupt, entry.Info.Size, expectedSize))
	}
	return auditNoIssueFound(subject)
}

func (s *Service) auditXorbRecord(ctx context.Context, record XorbRecord) AuditResult {
	subject := XorbRecordAuditSubject{Blob: record.Blob}
	expectedSize, err := ValidateXorbRecord(record.Layout.Hash, record)
	if err != nil {
		return auditInvalid(subject, nil, err)
	}
	if result := s.auditBlobTargetSize(ctx, subject, record.Blob, expectedSize); result != nil {
		return *result
	}
	return auditNoIssueFound(subject)
}

func (s *Service) auditShardRecord(ctx context.Context, scoped ScopedShardRecord) AuditResult {
	subject := ShardRecordAuditSubject{Namespace: scoped.Namespace, Blob: scoped.Record.Blob}
	if err := validateShardRecord(scoped.Record.Blob.Hash, scoped.Record); err != nil {
		return auditInvalid(subject, nil, err)
	}
	if result := s.auditBlobTarget(ctx, subject, scoped.Record.Blob); result != nil {
		return *result
	}
	return auditNoIssueFound(subject)
}

func (s *Service) auditFileRecord(ctx context.Context, scoped ScopedFileRecord) AuditResult {
	hash := scoped.Record.File.File.Hash
	subject := FileRecordAuditSubject{Namespace: scoped.Namespace, File: hash, Shard: scoped.Record.Shard}
	if _, result := s.auditFileTarget(ctx, subject, scoped.Namespace, hash, scoped.Record); result != nil {
		return *result
	}
	return auditNoIssueFound(subject)
}

func (s *Service) auditFileTarget(
	ctx context.Context,
	subject AuditSubject,
	namespace string,
	hash xethash.Hash,
	file FileRecord,
) (uint64, *AuditResult) {
	if err := validateFileRecord(hash, file); err != nil {
		result := auditInvalid(subject, auditFileTarget(namespace, hash), err)
		return 0, &result
	}
	if err := s.validateRecipeWork(ctx, file.File); err != nil {
		if contextErr := auditContextError(err); contextErr != nil {
			result := auditLookupError(subject, auditFileTarget(namespace, hash), contextErr)
			return 0, &result
		}
		result := auditInvalid(subject, auditFileTarget(namespace, hash), err)
		return 0, &result
	}
	shardRecord, found, err := s.index.GetShard(ctx, namespace, file.Shard.Hash)
	if err != nil {
		result := auditLookupError(subject, auditShardTarget(namespace, file.Shard.Hash), err)
		return 0, &result
	}
	if !found {
		result := auditIssue(subject, AuditFindingShardRecordMissing,
			auditShardTarget(namespace, file.Shard.Hash), nil)
		return 0, &result
	}
	if err := validateShardRecord(file.Shard.Hash, shardRecord); err != nil {
		result := auditInvalid(subject, auditShardTarget(namespace, file.Shard.Hash), err)
		return 0, &result
	}
	if result := s.auditBlobTarget(ctx, subject, file.Shard); result != nil {
		return 0, result
	}
	size, result := s.auditRegisteredFile(ctx, subject, file.File)
	if result != nil {
		return 0, result
	}
	if file.File.File.SHA256 == nil {
		return size, nil
	}
	sum := *file.File.File.SHA256
	associated, found, err := s.index.ResolveSHA256(ctx, namespace, sum, size)
	target := auditSHA256Target(namespace, sum, size)
	if err != nil {
		result := auditLookupError(subject, target, err)
		return 0, &result
	}
	if !found {
		result := auditIssue(subject, AuditFindingSHA256AssociationMissing, target, nil)
		return 0, &result
	}
	if associated != hash {
		result := auditInvalid(subject, target,
			fmt.Errorf("SHA-256 association resolves to file %s, expected %s", associated, hash))
		return 0, &result
	}
	return size, nil
}

func (s *Service) auditRegisteredFile(
	ctx context.Context,
	subject AuditSubject,
	file shard.RegisteredFile,
) (uint64, *AuditResult) {
	var dependency *AuditResult
	lookup := func(hash xethash.Hash) (shard.Xorb, bool, error) {
		record, found, err := s.index.GetXorb(ctx, hash)
		if err != nil {
			result := auditLookupError(subject, auditXorbTarget(hash), err)
			dependency = &result
			return shard.Xorb{}, false, errAuditDependency
		}
		if !found {
			result := auditIssue(subject, AuditFindingXorbRecordMissing, auditXorbTarget(hash), nil)
			dependency = &result
			return shard.Xorb{}, false, errAuditDependency
		}
		expectedSize, err := ValidateXorbRecord(hash, record)
		if err != nil {
			result := auditInvalid(subject, auditXorbTarget(hash), err)
			dependency = &result
			return shard.Xorb{}, false, errAuditDependency
		}
		if result := s.auditBlobTargetSize(ctx, subject, record.Blob, expectedSize); result != nil {
			dependency = result
			return shard.Xorb{}, false, errAuditDependency
		}
		if err := ctx.Err(); err != nil {
			result := auditLookupError(subject, auditXorbTarget(hash), err)
			dependency = &result
			return shard.Xorb{}, false, errAuditDependency
		}
		value, err := shard.XorbFromIngested(&record.Layout)
		if err != nil {
			result := auditInvalid(subject, auditXorbTarget(hash), err)
			dependency = &result
			return shard.Xorb{}, false, errAuditDependency
		}
		return value, true, nil
	}
	limits := s.registration
	limits.MaxFiles = 1
	registration, err := shard.ValidateRegistrationContext(ctx,
		shard.Shard{Files: []shard.File{file.File}}, lookup, limits)
	if dependency != nil {
		return 0, dependency
	}
	if err != nil {
		result := auditInvalid(subject, nil, err)
		if contextErr := auditContextError(err); contextErr != nil {
			result = auditLookupError(subject, nil, contextErr)
		}
		return 0, &result
	}
	if len(registration.Files) != 1 || registration.Files[0].Size != file.Size {
		result := auditInvalid(subject, nil,
			fmt.Errorf("registered file size %d differs from validated size", file.Size))
		return 0, &result
	}
	return registration.Files[0].Size, nil
}

func (s *Service) auditDedupRecord(ctx context.Context, scoped ScopedDedupRecord) AuditResult {
	subject := DedupRecordAuditSubject{
		Namespace: scoped.Namespace, Chunk: scoped.Chunk, Shard: scoped.Record.Shard,
	}
	if scoped.Chunk == xethash.Zero {
		return auditInvalid(subject, nil, errors.New("dedup record has a zero chunk identity"))
	}
	if err := validateDedupRecord(scoped.Record); err != nil {
		return auditInvalid(subject, nil, err)
	}
	record, found, err := s.index.GetShard(ctx, scoped.Namespace, scoped.Record.Shard.Hash)
	if err != nil {
		return auditLookupError(subject, auditShardTarget(scoped.Namespace, scoped.Record.Shard.Hash), err)
	}
	if !found {
		return auditIssue(subject, AuditFindingShardRecordMissing,
			auditShardTarget(scoped.Namespace, scoped.Record.Shard.Hash), nil)
	}
	if err := validateShardRecord(scoped.Record.Shard.Hash, record); err != nil {
		return auditInvalid(subject, auditShardTarget(scoped.Namespace, scoped.Record.Shard.Hash), err)
	}
	if result := s.auditBlobTarget(ctx, subject, scoped.Record.Shard); result != nil {
		return *result
	}
	return auditNoIssueFound(subject)
}

func (s *Service) auditSHA256Association(ctx context.Context, scoped ScopedSHA256Association) AuditResult {
	record := scoped.Record
	subject := SHA256AssociationAuditSubject{
		Namespace: scoped.Namespace, Sum: record.Sum, Size: record.Size, File: record.File,
	}
	file, found, err := s.index.GetFile(ctx, scoped.Namespace, record.File)
	if err != nil {
		return auditLookupError(subject, auditFileTarget(scoped.Namespace, record.File), err)
	}
	if !found {
		return auditIssue(subject, AuditFindingFileRecordMissing,
			auditFileTarget(scoped.Namespace, record.File), nil)
	}
	size, result := s.auditFileTarget(ctx, subject, scoped.Namespace, record.File, file)
	if result != nil {
		return *result
	}
	if size != record.Size {
		return auditInvalid(subject, auditFileTarget(scoped.Namespace, record.File),
			fmt.Errorf("SHA-256 association size %d differs from validated file size %d", record.Size, size))
	}
	return auditNoIssueFound(subject)
}

func (s *Service) auditBlobStage(ctx context.Context, stage BlobStage) AuditResult {
	subject := BlobStageAuditSubject{Stage: stage}
	if _, err := normalizeBlobStage(stage); err != nil {
		return auditInvalid(subject, nil, err)
	}
	if result := s.auditBlobTarget(ctx, subject, stage.Blob); result != nil {
		return *result
	}
	return auditNoIssueFound(subject)
}

func (s *Service) auditFileLease(ctx context.Context, lease FileLease) AuditResult {
	subject := FileLeaseAuditSubject{Lease: lease}
	if _, err := normalizeFileLease(lease); err != nil {
		return auditInvalid(subject, nil, err)
	}
	file, found, err := s.index.GetFile(ctx, lease.Namespace, lease.File)
	if err != nil {
		return auditLookupError(subject, auditFileTarget(lease.Namespace, lease.File), err)
	}
	if !found {
		return auditIssue(subject, AuditFindingFileRecordMissing,
			auditFileTarget(lease.Namespace, lease.File), nil)
	}
	if _, result := s.auditFileTarget(ctx, subject, lease.Namespace, lease.File, file); result != nil {
		return *result
	}
	return auditNoIssueFound(subject)
}

func (s *Service) auditBlobTarget(ctx context.Context, subject AuditSubject, key BlobKey) *AuditResult {
	return s.auditBlobTargetSize(ctx, subject, key, 0)
}

func (s *Service) auditBlobTargetSize(
	ctx context.Context,
	subject AuditSubject,
	key BlobKey,
	expectedSize int64,
) *AuditResult {
	info, found, err := s.blobs.Head(ctx, key)
	if err != nil {
		result := auditCheckFailed(subject, auditBlobTarget(key), err)
		return &result
	}
	if !found {
		result := auditIssue(subject, AuditFindingBlobMissing, auditBlobTarget(key), nil)
		return &result
	}
	if err := validateAuditBlobSize(key, info); err != nil {
		result := auditIssue(subject, AuditFindingBlobSizeInvalid, auditBlobTarget(key), err)
		return &result
	}
	if expectedSize != 0 && info.Size != expectedSize {
		result := auditIssue(subject, AuditFindingBlobSizeInvalid, auditBlobTarget(key),
			fmt.Errorf("%w: stored %s size %d, expected %d", ErrCorrupt, key.Kind, info.Size, expectedSize))
		return &result
	}
	return nil
}

func validateAuditBlobSize(key BlobKey, info BlobInfo) error {
	limit := int64(0)
	switch key.Kind {
	case BlobXorb:
		limit = xorb.MaxCompleteSize
	case BlobShard:
		limit = shard.MaxSize
	default:
		return fmt.Errorf("%w: unsupported blob kind %q", ErrCorrupt, key.Kind)
	}
	if key.Hash == xethash.Zero || info.Size <= 0 || info.Size > limit {
		return fmt.Errorf("%w: stored %s size %d is outside [1,%d]", ErrCorrupt, key.Kind, info.Size, limit)
	}
	return nil
}

func auditNoIssueFound(subject AuditSubject) AuditResult {
	subject.auditSubject()
	return AuditResult{Subject: subject, Status: AuditStatusNoIssueFound}
}

func auditIssue(subject AuditSubject, finding AuditFinding, target *AuditTarget, err error) AuditResult {
	subject.auditSubject()
	return AuditResult{Subject: subject, Status: AuditStatusIssue, Finding: finding, Target: target, Err: err}
}

func auditInvalid(subject AuditSubject, target *AuditTarget, err error) AuditResult {
	if !errors.Is(err, ErrCorrupt) {
		err = fmt.Errorf("%w: %v", ErrCorrupt, err)
	}
	return auditIssue(subject, AuditFindingRecordInvalid, target, err)
}

func auditLookupError(subject AuditSubject, target *AuditTarget, err error) AuditResult {
	if errors.Is(err, ErrCorrupt) {
		return auditIssue(subject, AuditFindingRecordInvalid, target, err)
	}
	return auditCheckFailed(subject, target, err)
}

func auditCheckFailed(subject AuditSubject, target *AuditTarget, err error) AuditResult {
	subject.auditSubject()
	return AuditResult{
		Subject: subject, Status: AuditStatusFailed, Finding: AuditFindingCheckFailed, Target: target, Err: err,
	}
}

func auditContextError(err error) error {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	return nil
}

func auditBlobTarget(key BlobKey) *AuditTarget {
	return &AuditTarget{Kind: AuditTargetBlob, Blob: key}
}

func auditXorbTarget(hash xethash.Hash) *AuditTarget {
	return &AuditTarget{Kind: AuditTargetXorbRecord, Hash: hash}
}

func auditShardTarget(namespace string, hash xethash.Hash) *AuditTarget {
	return &AuditTarget{Kind: AuditTargetShardRecord, Namespace: namespace, Hash: hash}
}

func auditFileTarget(namespace string, hash xethash.Hash) *AuditTarget {
	return &AuditTarget{Kind: AuditTargetFileRecord, Namespace: namespace, Hash: hash}
}

func auditSHA256Target(namespace string, sum [32]byte, size uint64) *AuditTarget {
	return &AuditTarget{Kind: AuditTargetSHA256, Namespace: namespace, Sum: sum, Size: size}
}

func prepareAuditPage(request AuditRequest) (PageRequest, error) {
	if _, err := pageLimit(request.Page); err != nil {
		return PageRequest{}, err
	}
	switch request.Kind {
	case AuditKindBlobXorb, AuditKindBlobShard, AuditKindXorbRecord:
		if request.Namespace != nil {
			return PageRequest{}, fmt.Errorf("%w: audit kind %q is global and does not accept a namespace", ErrInvalid, request.Kind)
		}
	case AuditKindShardRecord, AuditKindFileRecord, AuditKindDedupRecord,
		AuditKindSHA256Association, AuditKindBlobStage, AuditKindFileLease:
		// Nil and exact namespace filters are both valid.
	default:
		return PageRequest{}, fmt.Errorf("%w: unknown audit kind %q", ErrInvalid, request.Kind)
	}
	page := request.Page
	if request.Page.Cursor == "" {
		return page, nil
	}
	underlying, err := decodeAuditCursor(request.Page.Cursor, request.Kind, request.Namespace)
	if err != nil {
		return PageRequest{}, err
	}
	page.Cursor = underlying
	return page, nil
}

func auditKindCode(kind AuditKind) (byte, bool) {
	switch kind {
	case AuditKindBlobXorb:
		return 1, true
	case AuditKindBlobShard:
		return 2, true
	case AuditKindXorbRecord:
		return 3, true
	case AuditKindShardRecord:
		return 4, true
	case AuditKindFileRecord:
		return 5, true
	case AuditKindDedupRecord:
		return 6, true
	case AuditKindSHA256Association:
		return 7, true
	case AuditKindBlobStage:
		return 8, true
	case AuditKindFileLease:
		return 9, true
	default:
		return 0, false
	}
}

func encodeAuditCursor(kind AuditKind, namespace *string, underlying string) string {
	code, _ := auditKindCode(kind)
	namespaceLength := 0
	if namespace != nil {
		namespaceLength = len(*namespace)
	}
	data := make([]byte, 7+namespaceLength+len(underlying))
	data[0], data[1] = cursorAuditEnvelope, code
	if namespace != nil {
		data[2] = 1
		binary.BigEndian.PutUint32(data[3:7], uint32(namespaceLength))
		copy(data[7:], *namespace)
	}
	copy(data[7+namespaceLength:], underlying)
	return base64.RawURLEncoding.EncodeToString(data)
}

func decodeAuditCursor(cursor string, kind AuditKind, namespace *string) (string, error) {
	data, err := decodeCursor(cursor)
	code, validKind := auditKindCode(kind)
	if err != nil || !validKind || len(data) < 8 || data[0] != cursorAuditEnvelope || data[1] != code || data[2] > 1 {
		return "", fmt.Errorf("%w: malformed audit cursor", ErrInvalid)
	}
	namespaceLength := uint64(binary.BigEndian.Uint32(data[3:7]))
	if namespaceLength > uint64(len(data)-7) || uint64(len(data))-7-namespaceLength == 0 {
		return "", fmt.Errorf("%w: malformed audit cursor", ErrInvalid)
	}
	namespaceEnd := 7 + int(namespaceLength)
	if namespace == nil {
		if data[2] != 0 || namespaceLength != 0 {
			return "", fmt.Errorf("%w: audit cursor namespace differs from request", ErrInvalid)
		}
	} else if data[2] != 1 || string(data[7:namespaceEnd]) != *namespace {
		return "", fmt.Errorf("%w: audit cursor namespace differs from request", ErrInvalid)
	}
	return string(data[namespaceEnd:]), nil
}
