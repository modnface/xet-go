package server

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"

	"github.com/jmwoliver/xet-go/xethash"
)

// AuditBlobPayloads performs full, bounded, read-only validation of one page
// of physical Xorb or shard objects. Objects are read and validated
// sequentially, so at most one complete payload is retained at a time. This
// administrative operation performs no tenant authorization, namespace
// reachability check, repair, or deletion.
func (s *Service) AuditBlobPayloads(
	ctx context.Context,
	request PayloadAuditRequest,
) (PayloadAuditPage, error) {
	pageRequest, err := preparePayloadAuditPage(request)
	if err != nil {
		return PayloadAuditPage{}, err
	}
	if err := ctx.Err(); err != nil {
		return PayloadAuditPage{}, err
	}
	lister, ok := s.blobs.(BlobLister)
	if !ok {
		return PayloadAuditPage{}, fmt.Errorf(
			"xet CAS server: payload audit %s requires BlobLister: %w", request.Kind, ErrAuditUnsupported)
	}
	inventory, err := lister.ListBlobs(ctx, request.Kind, pageRequest)
	if err != nil {
		return PayloadAuditPage{}, err
	}
	if err := ctx.Err(); err != nil {
		return PayloadAuditPage{}, err
	}
	if err := validatePayloadAuditPage(request, pageRequest, inventory); err != nil {
		return PayloadAuditPage{}, err
	}

	page := PayloadAuditPage{
		Kind: request.Kind, Items: make([]PayloadAuditResult, 0, len(inventory.Items)),
	}
	for _, entry := range inventory.Items {
		if err := ctx.Err(); err != nil {
			return page, err
		}
		result := s.auditBlobPayload(ctx, request.Kind, entry)
		if err := ctx.Err(); err != nil {
			return page, err
		}
		if err := auditContextError(result.Err); err != nil {
			return page, err
		}
		page.Items = append(page.Items, result)
	}
	if err := ctx.Err(); err != nil {
		return page, err
	}
	if inventory.NextCursor != "" {
		page.NextCursor = encodePayloadAuditCursor(request.Kind, inventory.NextCursor)
	}
	if err := ctx.Err(); err != nil {
		page.NextCursor = ""
		return page, err
	}
	return page, nil
}

func (s *Service) auditBlobPayload(
	ctx context.Context,
	kind BlobKind,
	entry BlobEntry,
) PayloadAuditResult {
	result := PayloadAuditResult{Entry: entry}
	if entry.Key.Kind != kind || entry.Key.Hash == xethash.Zero {
		return payloadAuditIssue(result, PayloadAuditFindingIdentityMismatch,
			errors.New("listed blob identity does not match its payload inventory"))
	}
	if err := validateAuditBlobSize(entry.Key, entry.Info); err != nil {
		return payloadAuditIssue(result, PayloadAuditFindingSizeInvalid, err)
	}

	reader, err := s.blobs.Get(ctx, entry.Key, nil)
	if err != nil {
		var closeErr error
		if reader != nil {
			closeErr = reader.Close()
		}
		if contextErr := ctx.Err(); contextErr != nil {
			return payloadAuditFailed(result, contextErr)
		}
		if closeErr != nil {
			return payloadAuditFailed(result, errors.Join(err, closeErr))
		}
		if errors.Is(err, ErrNotFound) {
			result.Status = AuditStatusIssue
			result.Finding = PayloadAuditFindingBlobMissing
			return result
		}
		return payloadAuditFailed(result, err)
	}
	if reader == nil {
		return payloadAuditFailed(result, errors.New("xet CAS server: blob store returned a nil payload reader"))
	}
	reader, readerDone := closeReaderOnCancellation(ctx, reader)
	body, readErr := io.ReadAll(io.LimitReader(&contextAuditReader{ctx: ctx, reader: reader}, entry.Info.Size+1))
	close(readerDone)
	closeErr := reader.Close()
	if err := ctx.Err(); err != nil {
		return payloadAuditFailed(result, err)
	}
	if err := errors.Join(readErr, closeErr); err != nil {
		return payloadAuditFailed(result, err)
	}
	if int64(len(body)) != entry.Info.Size {
		return payloadAuditIssue(result, PayloadAuditFindingSizeInvalid,
			fmt.Errorf("%w: read %s payload size %d, listed size %d",
				ErrCorrupt, kind, len(body), entry.Info.Size))
	}
	if err := ctx.Err(); err != nil {
		return payloadAuditFailed(result, err)
	}

	switch kind {
	case BlobXorb:
		object, err := decodeCanonicalXorb(body)
		if err != nil {
			return payloadAuditIssue(result, PayloadAuditFindingPayloadInvalid, err)
		}
		if object.Hash != entry.Key.Hash {
			return payloadAuditIssue(result, PayloadAuditFindingIdentityMismatch,
				fmt.Errorf("xorb payload identity %s differs from key %s", object.Hash, entry.Key.Hash))
		}
	case BlobShard:
		if _, err := decodeCanonicalShard(body); err != nil {
			return payloadAuditIssue(result, PayloadAuditFindingPayloadInvalid, err)
		}
		if hash := xethash.Chunk(body); hash != entry.Key.Hash {
			return payloadAuditIssue(result, PayloadAuditFindingIdentityMismatch,
				fmt.Errorf("shard payload identity %s differs from key %s", hash, entry.Key.Hash))
		}
	default:
		return payloadAuditIssue(result, PayloadAuditFindingPayloadInvalid,
			fmt.Errorf("unsupported blob kind %q", kind))
	}
	if err := ctx.Err(); err != nil {
		return payloadAuditFailed(result, err)
	}
	result.Status = AuditStatusNoIssueFound
	return result
}

func payloadAuditIssue(
	result PayloadAuditResult,
	finding PayloadAuditFinding,
	err error,
) PayloadAuditResult {
	if !errors.Is(err, ErrCorrupt) {
		err = fmt.Errorf("%w: %v", ErrCorrupt, err)
	}
	result.Status = AuditStatusIssue
	result.Finding = finding
	result.Err = err
	return result
}

func payloadAuditFailed(result PayloadAuditResult, err error) PayloadAuditResult {
	result.Status = AuditStatusFailed
	result.Finding = PayloadAuditFindingCheckFailed
	result.Err = err
	return result
}

type contextAuditReader struct {
	ctx    context.Context
	reader io.Reader
}

func (r *contextAuditReader) Read(buffer []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.reader.Read(buffer)
}

func preparePayloadAuditPage(request PayloadAuditRequest) (PageRequest, error) {
	if request.Kind != BlobXorb && request.Kind != BlobShard {
		return PageRequest{}, fmt.Errorf("%w: unsupported payload audit kind %q", ErrInvalid, request.Kind)
	}
	if _, err := pageLimit(request.Page); err != nil {
		return PageRequest{}, err
	}
	page := request.Page
	if page.Cursor == "" {
		return page, nil
	}
	underlying, err := decodePayloadAuditCursor(page.Cursor, request.Kind)
	if err != nil {
		return PageRequest{}, err
	}
	page.Cursor = underlying
	return page, nil
}

func validatePayloadAuditPage(
	request PayloadAuditRequest,
	pageRequest PageRequest,
	page BlobPage,
) error {
	limit, err := pageLimit(pageRequest)
	if err != nil {
		return err
	}
	if len(page.Items) > limit {
		return fmt.Errorf("%w: payload audit %s lister returned %d items for limit %d",
			ErrCorrupt, request.Kind, len(page.Items), limit)
	}
	if page.NextCursor != "" && len(page.Items) == 0 {
		return fmt.Errorf("%w: payload audit %s lister returned a continuation without items",
			ErrCorrupt, request.Kind)
	}
	if pageRequest.Cursor != "" && page.NextCursor == pageRequest.Cursor {
		return fmt.Errorf("%w: payload audit %s lister did not advance its continuation",
			ErrCorrupt, request.Kind)
	}
	return nil
}

func payloadAuditKindCode(kind BlobKind) (byte, bool) {
	switch kind {
	case BlobXorb:
		return 1, true
	case BlobShard:
		return 2, true
	default:
		return 0, false
	}
}

func encodePayloadAuditCursor(kind BlobKind, underlying string) string {
	code, _ := payloadAuditKindCode(kind)
	return base64.RawURLEncoding.EncodeToString(
		append([]byte{cursorPayloadAuditEnvelope, code}, []byte(underlying)...))
}

func decodePayloadAuditCursor(cursor string, kind BlobKind) (string, error) {
	data, err := decodeCursor(cursor)
	code, validKind := payloadAuditKindCode(kind)
	if err != nil || !validKind || len(data) < 3 || data[0] != cursorPayloadAuditEnvelope || data[1] != code {
		return "", fmt.Errorf("%w: malformed payload audit cursor", ErrInvalid)
	}
	return string(data[2:]), nil
}
