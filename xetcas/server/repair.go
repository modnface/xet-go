package server

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"reflect"

	"github.com/jmwoliver/xet-go/xethash"
)

// RepairXorbIndexes boundedly rebuilds missing global Xorb layout records from
// canonical immutable Xorb payloads. It performs no tenant authorization,
// payload writes/deletes, shard repair, or reachability decision. Existing
// conflicting or corrupt index records are reported and never overwritten.
func (s *Service) RepairXorbIndexes(
	ctx context.Context,
	request PageRequest,
) (XorbIndexRepairPage, error) {
	pageRequest, err := prepareXorbIndexRepairPage(request)
	if err != nil {
		return XorbIndexRepairPage{}, err
	}
	if err := ctx.Err(); err != nil {
		return XorbIndexRepairPage{}, err
	}
	lister, ok := s.blobs.(BlobLister)
	if !ok {
		return XorbIndexRepairPage{}, fmt.Errorf(
			"xet CAS server: Xorb index repair requires BlobLister: %w", ErrRepairUnsupported)
	}
	inventory, err := lister.ListBlobs(ctx, BlobXorb, pageRequest)
	if err != nil {
		return XorbIndexRepairPage{}, err
	}
	if err := ctx.Err(); err != nil {
		return XorbIndexRepairPage{}, err
	}
	if err := validateXorbIndexRepairPage(pageRequest, inventory); err != nil {
		return XorbIndexRepairPage{}, err
	}
	page := XorbIndexRepairPage{Items: make([]XorbIndexRepairResult, 0, len(inventory.Items))}
	for _, entry := range inventory.Items {
		if err := ctx.Err(); err != nil {
			return page, err
		}
		result, err := s.repairXorbIndexWithPermit(ctx, entry)
		if err != nil {
			return page, err
		}
		if err := repairContextError(ctx, result.Err); err != nil {
			return page, err
		}
		page.Items = append(page.Items, result)
	}
	if err := ctx.Err(); err != nil {
		return page, err
	}
	if inventory.NextCursor != "" {
		page.NextCursor = encodeXorbIndexRepairCursor(inventory.NextCursor)
	}
	if err := ctx.Err(); err != nil {
		page.NextCursor = ""
		return page, err
	}
	return page, nil
}

func (s *Service) repairXorbIndexWithPermit(
	ctx context.Context,
	entry BlobEntry,
) (XorbIndexRepairResult, error) {
	release, err := s.acquireIngest(ctx)
	if err != nil {
		return XorbIndexRepairResult{}, err
	}
	defer release()
	return s.repairXorbIndex(ctx, entry), nil
}

func (s *Service) repairXorbIndex(
	ctx context.Context,
	entry BlobEntry,
) XorbIndexRepairResult {
	result := XorbIndexRepairResult{Entry: entry}
	if entry.Key.Kind != BlobXorb || entry.Key.Hash == xethash.Zero {
		return invalidXorbRepairInventory(result, errors.New("listed blob identity does not match Xorb inventory"))
	}
	if err := validateAuditBlobSize(entry.Key, entry.Info); err != nil {
		return invalidXorbRepairInventory(result, err)
	}
	body, found, err := s.readExactStoredBlob(ctx, entry.Key, entry.Info.Size)
	if err != nil {
		if errors.Is(err, ErrCorrupt) {
			return invalidXorbRepairInventory(result, err)
		}
		result.Status, result.Phase, result.Err = XorbIndexRepairFailed, XorbIndexRepairRead, err
		return result
	}
	if !found {
		result.Status, result.Phase = XorbIndexRepairMissing, XorbIndexRepairRead
		return result
	}
	record, err := xorbRecordFromComplete(body, entry.Key)
	if err != nil {
		return invalidXorbRepairPayload(result, err)
	}
	existing, indexed, err := s.index.GetXorb(ctx, entry.Key.Hash)
	if err != nil {
		result.Phase, result.Err = XorbIndexRepairLookup, err
		if errors.Is(err, ErrCorrupt) {
			result.Status = XorbIndexRepairIndexCorrupt
		} else if errors.Is(err, ErrConflict) {
			result.Status = XorbIndexRepairConflict
		} else {
			result.Status = XorbIndexRepairFailed
		}
		return result
	}
	if indexed {
		if _, err := ValidateXorbRecord(entry.Key.Hash, existing); err != nil {
			result.Status, result.Phase, result.Err = XorbIndexRepairIndexCorrupt, XorbIndexRepairLookup, err
			return result
		}
		if reflect.DeepEqual(existing, record) {
			result.Status = XorbIndexRepairAlreadyValid
			return result
		}
		result.Status, result.Phase, result.Err = XorbIndexRepairConflict, XorbIndexRepairLookup, ErrConflict
		return result
	}
	if err := s.index.PutXorb(ctx, record); err != nil {
		result.Phase, result.Err = XorbIndexRepairPublish, err
		if errors.Is(err, ErrCorrupt) {
			result.Status = XorbIndexRepairIndexCorrupt
		} else if errors.Is(err, ErrConflict) {
			result.Status = XorbIndexRepairConflict
		} else {
			result.Status = XorbIndexRepairFailed
		}
		return result
	}
	// Another writer may have inserted the same immutable record after the
	// lookup. Reconciled means the derived record was accepted, not that this
	// invocation owned the insert.
	result.Status = XorbIndexRepairReconciled
	return result
}

func invalidXorbRepairInventory(
	result XorbIndexRepairResult,
	err error,
) XorbIndexRepairResult {
	if !errors.Is(err, ErrCorrupt) {
		err = fmt.Errorf("%w: %v", ErrCorrupt, err)
	}
	result.Status, result.Phase, result.Err = XorbIndexRepairInvalidInventory, XorbIndexRepairValidate, err
	return result
}

func invalidXorbRepairPayload(
	result XorbIndexRepairResult,
	err error,
) XorbIndexRepairResult {
	if !errors.Is(err, ErrCorrupt) {
		err = fmt.Errorf("%w: %v", ErrCorrupt, err)
	}
	result.Status, result.Phase, result.Err = XorbIndexRepairInvalidPayload, XorbIndexRepairValidate, err
	return result
}

func repairContextError(ctx context.Context, err error) error {
	if contextErr := ctx.Err(); contextErr != nil {
		return contextErr
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	return nil
}

func prepareXorbIndexRepairPage(request PageRequest) (PageRequest, error) {
	if _, err := pageLimit(request); err != nil {
		return PageRequest{}, err
	}
	if request.Cursor == "" {
		return request, nil
	}
	underlying, err := decodeXorbIndexRepairCursor(request.Cursor)
	if err != nil {
		return PageRequest{}, err
	}
	request.Cursor = underlying
	return request, nil
}

func validateXorbIndexRepairPage(request PageRequest, page BlobPage) error {
	limit, err := pageLimit(request)
	if err != nil {
		return err
	}
	if len(page.Items) > limit {
		return fmt.Errorf("%w: Xorb repair lister returned %d items for limit %d",
			ErrCorrupt, len(page.Items), limit)
	}
	if page.NextCursor != "" && len(page.Items) == 0 {
		return fmt.Errorf("%w: Xorb repair lister returned a continuation without items", ErrCorrupt)
	}
	if request.Cursor != "" && page.NextCursor == request.Cursor {
		return fmt.Errorf("%w: Xorb repair lister did not advance its continuation", ErrCorrupt)
	}
	return nil
}

func encodeXorbIndexRepairCursor(underlying string) string {
	return base64.RawURLEncoding.EncodeToString(
		append([]byte{cursorXorbIndexRepairEnvelope}, []byte(underlying)...))
}

func decodeXorbIndexRepairCursor(cursor string) (string, error) {
	data, err := decodeCursor(cursor)
	if err != nil || len(data) < 2 || data[0] != cursorXorbIndexRepairEnvelope {
		return "", fmt.Errorf("%w: malformed Xorb repair cursor", ErrInvalid)
	}
	return string(data[1:]), nil
}
