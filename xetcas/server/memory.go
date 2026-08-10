package server

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"reflect"
	"sort"
	"sync"
	"time"

	"github.com/jmwoliver/xet-go/shard"
	"github.com/jmwoliver/xet-go/xetcas"
	"github.com/jmwoliver/xet-go/xethash"
	"github.com/jmwoliver/xet-go/xorb"
)

type shaKey struct {
	namespace string
	sum       [32]byte
	size      uint64
}

type scopedHash struct {
	namespace string
	hash      xethash.Hash
}

type scopedProtection struct {
	namespace string
	id        ProtectionID
}

// MemoryStore is a concurrency-safe reference BlobStore and IndexStore. It is
// intended for tests, local development, and protocol interoperability suites.
type MemoryStore struct {
	mu     sync.RWMutex
	blobs  map[BlobKey][]byte
	xorbs  map[xethash.Hash]XorbRecord
	files  map[scopedHash]FileRecord
	dedup  map[scopedHash]DedupRecord
	sha256 map[shaKey]xethash.Hash
	stages map[scopedProtection]BlobStage
	leases map[scopedProtection]FileLease
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		blobs: make(map[BlobKey][]byte), xorbs: make(map[xethash.Hash]XorbRecord),
		files: make(map[scopedHash]FileRecord), dedup: make(map[scopedHash]DedupRecord),
		sha256: make(map[shaKey]xethash.Hash),
		stages: make(map[scopedProtection]BlobStage), leases: make(map[scopedProtection]FileLease),
	}
}

func (s *MemoryStore) PutIfAbsent(ctx context.Context, key BlobKey, body io.Reader, size int64) (bool, error) {
	if body == nil || size < 0 {
		return false, errorsf("invalid blob body or size")
	}
	if err := ctx.Err(); err != nil {
		return false, err
	}
	data, err := io.ReadAll(io.LimitReader(&contextReader{ctx: ctx, r: body}, size+1))
	if err != nil {
		return false, err
	}
	if int64(len(data)) != size {
		return false, fmt.Errorf("xet CAS server: blob size %d, expected %d", len(data), size)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return false, err
	}
	if previous, ok := s.blobs[key]; ok {
		if !bytes.Equal(previous, data) {
			return false, ErrConflict
		}
		return false, nil
	}
	s.blobs[key] = append([]byte(nil), data...)
	return true, nil
}

func (s *MemoryStore) Head(ctx context.Context, key BlobKey) (BlobInfo, bool, error) {
	if err := ctx.Err(); err != nil {
		return BlobInfo{}, false, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if err := ctx.Err(); err != nil {
		return BlobInfo{}, false, err
	}
	value, ok := s.blobs[key]
	return BlobInfo{Size: int64(len(value))}, ok, nil
}

func (s *MemoryStore) Get(ctx context.Context, key BlobKey, wanted *xetcas.HTTPRange) (io.ReadCloser, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.mu.RLock()
	if err := ctx.Err(); err != nil {
		s.mu.RUnlock()
		return nil, err
	}
	value, ok := s.blobs[key]
	if ok {
		value = append([]byte(nil), value...)
	}
	s.mu.RUnlock()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !ok {
		return nil, ErrNotFound
	}
	if wanted != nil {
		if err := wanted.Validate(); err != nil || wanted.End >= uint64(len(value)) {
			return nil, xetcas.ErrRangeNotSatisfiable
		}
		value = value[wanted.Start : wanted.End+1]
	}
	reader := io.NopCloser(bytes.NewReader(value))
	return &contextReadCloser{ctx: ctx, Reader: reader, close: reader}, nil
}

func (s *MemoryStore) ListBlobs(ctx context.Context, kind BlobKind, request PageRequest) (BlobPage, error) {
	if kind != BlobXorb && kind != BlobShard {
		return BlobPage{}, fmt.Errorf("%w: unsupported blob kind %q", ErrInvalid, kind)
	}
	limit, err := pageLimit(request)
	if err != nil {
		return BlobPage{}, err
	}
	cursorKind := cursorBlobXorb
	if kind == BlobShard {
		cursorKind = cursorBlobShard
	}
	var cursor xethash.Hash
	if request.Cursor != "" {
		cursor, err = decodeHashCursor(request.Cursor, cursorKind)
		if err != nil {
			return BlobPage{}, err
		}
	}
	if err := ctx.Err(); err != nil {
		return BlobPage{}, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	items := make([]BlobEntry, 0, min(limit+1, len(s.blobs)))
	for key, value := range s.blobs {
		if err := ctx.Err(); err != nil {
			return BlobPage{}, err
		}
		if key.Kind == kind && (request.Cursor == "" || bytes.Compare(key.Hash[:], cursor[:]) > 0) {
			items = append(items, BlobEntry{Key: key, Info: BlobInfo{Size: int64(len(value))}})
		}
	}
	sort.Slice(items, func(i, j int) bool { return bytes.Compare(items[i].Key.Hash[:], items[j].Key.Hash[:]) < 0 })
	page := BlobPage{Items: items}
	if len(page.Items) > limit {
		page.Items = page.Items[:limit]
		page.NextCursor = encodeHashCursor(cursorKind, page.Items[len(page.Items)-1].Key.Hash)
	}
	return page, nil
}

func (s *MemoryStore) GetXorb(ctx context.Context, hash xethash.Hash) (XorbRecord, bool, error) {
	if err := ctx.Err(); err != nil {
		return XorbRecord{}, false, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if err := ctx.Err(); err != nil {
		return XorbRecord{}, false, err
	}
	value, ok := s.xorbs[hash]
	return cloneXorbRecord(value), ok, nil
}

func (s *MemoryStore) PutXorb(ctx context.Context, value XorbRecord) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	if previous, ok := s.xorbs[value.Layout.Hash]; ok && !reflect.DeepEqual(previous, value) {
		return ErrConflict
	}
	s.xorbs[value.Layout.Hash] = cloneXorbRecord(value)
	return nil
}

func (s *MemoryStore) GetFile(ctx context.Context, namespace string, hash xethash.Hash) (FileRecord, bool, error) {
	if err := ctx.Err(); err != nil {
		return FileRecord{}, false, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if err := ctx.Err(); err != nil {
		return FileRecord{}, false, err
	}
	value, ok := s.files[scopedHash{namespace: namespace, hash: hash}]
	return cloneFileRecord(value), ok, nil
}

func (s *MemoryStore) PutFile(ctx context.Context, namespace string, value FileRecord) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	key := scopedHash{namespace: namespace, hash: value.File.File.Hash}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	if _, ok := s.files[key]; ok {
		// A file identity authenticates the logical chunk sequence, not one
		// particular shard recipe or the presence of optional SHA metadata.
		// Keep the first durable, already validated reconstruction source.
		return nil
	}
	s.files[key] = cloneFileRecord(value)
	return nil
}

func (s *MemoryStore) GetDedup(ctx context.Context, namespace string, hash xethash.Hash) (DedupRecord, bool, error) {
	if err := ctx.Err(); err != nil {
		return DedupRecord{}, false, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if err := ctx.Err(); err != nil {
		return DedupRecord{}, false, err
	}
	value, ok := s.dedup[scopedHash{namespace: namespace, hash: hash}]
	return value, ok, nil
}

func (s *MemoryStore) PutDedup(ctx context.Context, namespace string, hash xethash.Hash, value DedupRecord) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	key := scopedHash{namespace: namespace, hash: hash}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	if _, ok := s.dedup[key]; ok {
		// A chunk may legitimately occur in many shards. Keep the first durable
		// source; replacing it is unnecessary and a different source is not an
		// immutable-value conflict.
		return nil
	}
	s.dedup[key] = value
	return nil
}

func (s *MemoryStore) ResolveSHA256(ctx context.Context, namespace string, sum [32]byte, size uint64) (xethash.Hash, bool, error) {
	if err := ctx.Err(); err != nil {
		return xethash.Hash{}, false, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if err := ctx.Err(); err != nil {
		return xethash.Hash{}, false, err
	}
	value, ok := s.sha256[shaKey{namespace: namespace, sum: sum, size: size}]
	return value, ok, nil
}

func (s *MemoryStore) PutSHA256(ctx context.Context, namespace string, sum [32]byte, size uint64, hash xethash.Hash) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	key := shaKey{namespace: namespace, sum: sum, size: size}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	if previous, ok := s.sha256[key]; ok && previous != hash {
		return ErrConflict
	}
	s.sha256[key] = hash
	return nil
}

func (s *MemoryStore) PublishShard(ctx context.Context, publication ShardPublication) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	// Preflight every immutable SHA association before changing any map. File
	// and dedup records deliberately retain their first already-valid source.
	pendingSHA := make(map[shaKey]xethash.Hash, len(publication.SHA256))
	for _, association := range publication.SHA256 {
		key := shaKey{namespace: publication.Namespace, sum: association.Sum, size: association.Size}
		if previous, ok := s.sha256[key]; ok && previous != association.File {
			return ErrConflict
		}
		if previous, ok := pendingSHA[key]; ok && previous != association.File {
			return ErrConflict
		}
		pendingSHA[key] = association.File
	}
	for key, hash := range pendingSHA {
		s.sha256[key] = hash
	}
	for _, association := range publication.Dedup {
		key := scopedHash{namespace: publication.Namespace, hash: association.Chunk}
		if _, ok := s.dedup[key]; !ok {
			s.dedup[key] = association.Value
		}
	}
	for _, record := range publication.Files {
		key := scopedHash{namespace: publication.Namespace, hash: record.File.File.Hash}
		if _, ok := s.files[key]; !ok {
			s.files[key] = cloneFileRecord(record)
		}
	}
	return nil
}

func (s *MemoryStore) ListXorbs(ctx context.Context, request PageRequest) (XorbRecordPage, error) {
	limit, err := pageLimit(request)
	if err != nil {
		return XorbRecordPage{}, err
	}
	var cursor xethash.Hash
	if request.Cursor != "" {
		cursor, err = decodeHashCursor(request.Cursor, cursorIndexXorb)
		if err != nil {
			return XorbRecordPage{}, err
		}
	}
	if err := ctx.Err(); err != nil {
		return XorbRecordPage{}, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	items := make([]XorbRecord, 0, min(limit+1, len(s.xorbs)))
	for hash, record := range s.xorbs {
		if err := ctx.Err(); err != nil {
			return XorbRecordPage{}, err
		}
		if request.Cursor == "" || bytes.Compare(hash[:], cursor[:]) > 0 {
			items = append(items, cloneXorbRecord(record))
		}
	}
	sort.Slice(items, func(i, j int) bool {
		return bytes.Compare(items[i].Layout.Hash[:], items[j].Layout.Hash[:]) < 0
	})
	page := XorbRecordPage{Items: items}
	if len(page.Items) > limit {
		page.Items = page.Items[:limit]
		page.NextCursor = encodeHashCursor(cursorIndexXorb, page.Items[len(page.Items)-1].Layout.Hash)
	}
	return page, nil
}

func (s *MemoryStore) ListFiles(
	ctx context.Context,
	namespace *string,
	request PageRequest,
) (FileRecordPage, error) {
	cursorKind := cursorFileAll
	if namespace != nil {
		cursorKind = cursorFileScoped
	}
	limit, cursorNamespace, cursorHash, hasCursor, err := scopedHashPage(request, namespace, cursorKind)
	if err != nil {
		return FileRecordPage{}, err
	}
	if err := ctx.Err(); err != nil {
		return FileRecordPage{}, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	items := make([]ScopedFileRecord, 0, min(limit+1, len(s.files)))
	for key, record := range s.files {
		if err := ctx.Err(); err != nil {
			return FileRecordPage{}, err
		}
		if namespace != nil && key.namespace != *namespace {
			continue
		}
		if hasCursor && compareScopedHash(key.namespace, key.hash, cursorNamespace, cursorHash) <= 0 {
			continue
		}
		items = append(items, ScopedFileRecord{Namespace: key.namespace, Record: cloneFileRecord(record)})
	}
	sort.Slice(items, func(i, j int) bool {
		return compareScopedHash(items[i].Namespace, items[i].Record.File.File.Hash,
			items[j].Namespace, items[j].Record.File.File.Hash) < 0
	})
	page := FileRecordPage{Items: items}
	if len(page.Items) > limit {
		page.Items = page.Items[:limit]
		last := page.Items[len(page.Items)-1]
		page.NextCursor = encodeScopedCursor(cursorKind, last.Namespace, last.Record.File.File.Hash[:])
	}
	return page, nil
}

func (s *MemoryStore) ListDedup(
	ctx context.Context,
	namespace *string,
	request PageRequest,
) (DedupRecordPage, error) {
	cursorKind := cursorDedupAll
	if namespace != nil {
		cursorKind = cursorDedupScoped
	}
	limit, cursorNamespace, cursorHash, hasCursor, err := scopedHashPage(request, namespace, cursorKind)
	if err != nil {
		return DedupRecordPage{}, err
	}
	if err := ctx.Err(); err != nil {
		return DedupRecordPage{}, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	items := make([]ScopedDedupRecord, 0, min(limit+1, len(s.dedup)))
	for key, record := range s.dedup {
		if err := ctx.Err(); err != nil {
			return DedupRecordPage{}, err
		}
		if namespace != nil && key.namespace != *namespace {
			continue
		}
		if hasCursor && compareScopedHash(key.namespace, key.hash, cursorNamespace, cursorHash) <= 0 {
			continue
		}
		items = append(items, ScopedDedupRecord{Namespace: key.namespace, Chunk: key.hash, Record: record})
	}
	sort.Slice(items, func(i, j int) bool {
		return compareScopedHash(items[i].Namespace, items[i].Chunk, items[j].Namespace, items[j].Chunk) < 0
	})
	page := DedupRecordPage{Items: items}
	if len(page.Items) > limit {
		page.Items = page.Items[:limit]
		last := page.Items[len(page.Items)-1]
		page.NextCursor = encodeScopedCursor(cursorKind, last.Namespace, last.Chunk[:])
	}
	return page, nil
}

func (s *MemoryStore) ListSHA256(
	ctx context.Context,
	namespace *string,
	request PageRequest,
) (SHA256AssociationPage, error) {
	cursorKind := cursorSHA256All
	if namespace != nil {
		cursorKind = cursorSHA256Scoped
	}
	limit, cursorNamespace, cursorSum, cursorSize, hasCursor, err := scopedSHAPage(request, namespace, cursorKind)
	if err != nil {
		return SHA256AssociationPage{}, err
	}
	if err := ctx.Err(); err != nil {
		return SHA256AssociationPage{}, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	items := make([]ScopedSHA256Association, 0, min(limit+1, len(s.sha256)))
	for key, file := range s.sha256 {
		if err := ctx.Err(); err != nil {
			return SHA256AssociationPage{}, err
		}
		if namespace != nil && key.namespace != *namespace {
			continue
		}
		if hasCursor && compareScopedSHA(key.namespace, key.sum, key.size,
			cursorNamespace, cursorSum, cursorSize) <= 0 {
			continue
		}
		items = append(items, ScopedSHA256Association{Namespace: key.namespace, Record: SHA256Association{
			Sum: key.sum, Size: key.size, File: file,
		}})
	}
	sort.Slice(items, func(i, j int) bool {
		left, right := items[i], items[j]
		return compareScopedSHA(left.Namespace, left.Record.Sum, left.Record.Size,
			right.Namespace, right.Record.Sum, right.Record.Size) < 0
	})
	page := SHA256AssociationPage{Items: items}
	if len(page.Items) > limit {
		page.Items = page.Items[:limit]
		last := page.Items[len(page.Items)-1]
		page.NextCursor = encodeScopedCursor(cursorKind, last.Namespace, shaCursorKey(last.Record.Sum, last.Record.Size))
	}
	return page, nil
}

func (s *MemoryStore) PutBlobStage(ctx context.Context, stage BlobStage) error {
	stage, err := normalizeBlobStage(stage)
	if err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	key := scopedProtection{namespace: stage.Namespace, id: stage.ID}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	if previous, found := s.stages[key]; found {
		if previous != stage {
			return ErrConflict
		}
		return nil
	}
	s.stages[key] = stage
	return nil
}

func (s *MemoryStore) RenewBlobStage(
	ctx context.Context,
	namespace string,
	id ProtectionID,
	expiresAt time.Time,
) error {
	expiresAt, err := normalizeProtectionTime(expiresAt)
	if err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	key := scopedProtection{namespace: namespace, id: id}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	stage, found := s.stages[key]
	if !found {
		return ErrNotFound
	}
	if expiresAt.After(stage.ExpiresAt) {
		stage.ExpiresAt = expiresAt
		s.stages[key] = stage
	}
	return nil
}

func (s *MemoryStore) DeleteBlobStage(ctx context.Context, namespace string, id ProtectionID) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	delete(s.stages, scopedProtection{namespace: namespace, id: id})
	return nil
}

func (s *MemoryStore) ListBlobStages(
	ctx context.Context,
	namespace *string,
	request PageRequest,
) (BlobStagePage, error) {
	cursorKind := cursorBlobStageAll
	if namespace != nil {
		cursorKind = cursorBlobStageScoped
	}
	limit, cursorNamespace, cursorID, hasCursor, err := scopedProtectionPage(request, namespace, cursorKind)
	if err != nil {
		return BlobStagePage{}, err
	}
	if err := ctx.Err(); err != nil {
		return BlobStagePage{}, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	items := make([]BlobStage, 0, min(limit+1, len(s.stages)))
	for key, stage := range s.stages {
		if err := ctx.Err(); err != nil {
			return BlobStagePage{}, err
		}
		if namespace != nil && key.namespace != *namespace {
			continue
		}
		if hasCursor && compareScopedProtection(key.namespace, key.id, cursorNamespace, cursorID) <= 0 {
			continue
		}
		items = append(items, stage)
	}
	sort.Slice(items, func(i, j int) bool {
		return compareScopedProtection(items[i].Namespace, items[i].ID, items[j].Namespace, items[j].ID) < 0
	})
	page := BlobStagePage{Items: items}
	if len(page.Items) > limit {
		page.Items = page.Items[:limit]
		last := page.Items[len(page.Items)-1]
		page.NextCursor = encodeScopedCursor(cursorKind, last.Namespace, last.ID[:])
	}
	return page, nil
}

func (s *MemoryStore) PutFileLease(ctx context.Context, lease FileLease) error {
	lease, err := normalizeFileLease(lease)
	if err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	key := scopedProtection{namespace: lease.Namespace, id: lease.ID}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	if previous, found := s.leases[key]; found {
		if previous.ID != lease.ID || previous.Namespace != lease.Namespace || previous.File != lease.File ||
			!previous.CreatedAt.Equal(lease.CreatedAt) {
			return ErrConflict
		}
		if lease.ExpiresAt.After(previous.ExpiresAt) {
			previous.ExpiresAt = lease.ExpiresAt
			s.leases[key] = previous
		}
		return nil
	}
	s.leases[key] = lease
	return nil
}

func (s *MemoryStore) RenewFileLease(
	ctx context.Context,
	namespace string,
	id ProtectionID,
	expiresAt time.Time,
) error {
	expiresAt, err := normalizeProtectionTime(expiresAt)
	if err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	key := scopedProtection{namespace: namespace, id: id}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	lease, found := s.leases[key]
	if !found {
		return ErrNotFound
	}
	if expiresAt.After(lease.ExpiresAt) {
		lease.ExpiresAt = expiresAt
		s.leases[key] = lease
	}
	return nil
}

func (s *MemoryStore) DeleteFileLease(ctx context.Context, namespace string, id ProtectionID) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	delete(s.leases, scopedProtection{namespace: namespace, id: id})
	return nil
}

func (s *MemoryStore) ListFileLeases(
	ctx context.Context,
	namespace *string,
	request PageRequest,
) (FileLeasePage, error) {
	cursorKind := cursorFileLeaseAll
	if namespace != nil {
		cursorKind = cursorFileLeaseScoped
	}
	limit, cursorNamespace, cursorID, hasCursor, err := scopedProtectionPage(request, namespace, cursorKind)
	if err != nil {
		return FileLeasePage{}, err
	}
	if err := ctx.Err(); err != nil {
		return FileLeasePage{}, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	items := make([]FileLease, 0, min(limit+1, len(s.leases)))
	for key, lease := range s.leases {
		if err := ctx.Err(); err != nil {
			return FileLeasePage{}, err
		}
		if namespace != nil && key.namespace != *namespace {
			continue
		}
		if hasCursor && compareScopedProtection(key.namespace, key.id, cursorNamespace, cursorID) <= 0 {
			continue
		}
		items = append(items, lease)
	}
	sort.Slice(items, func(i, j int) bool {
		return compareScopedProtection(items[i].Namespace, items[i].ID, items[j].Namespace, items[j].ID) < 0
	})
	page := FileLeasePage{Items: items}
	if len(page.Items) > limit {
		page.Items = page.Items[:limit]
		last := page.Items[len(page.Items)-1]
		page.NextCursor = encodeScopedCursor(cursorKind, last.Namespace, last.ID[:])
	}
	return page, nil
}

func (s *MemoryStore) ListExpiredBlobStages(
	ctx context.Context,
	cutoff time.Time,
	request PageRequest,
) (BlobStagePage, error) {
	cutoff, limit, cursor, hasCursor, err := protectionExpiryPage(cutoff, request, cursorBlobStageExpired)
	if err != nil {
		return BlobStagePage{}, err
	}
	if err := ctx.Err(); err != nil {
		return BlobStagePage{}, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	items := make([]BlobStage, 0, min(limit+1, len(s.stages)))
	for _, stage := range s.stages {
		if err := ctx.Err(); err != nil {
			return BlobStagePage{}, err
		}
		if stage.ExpiresAt.After(cutoff) || hasCursor && compareProtectionExpiry(
			stage.ExpiresAt, stage.Namespace, stage.ID, cursor.expiresAt, cursor.namespace, cursor.id,
		) <= 0 {
			continue
		}
		items = keepFirstProtections(items, stage, limit+1, func(left, right BlobStage) int {
			return compareProtectionExpiry(
				left.ExpiresAt, left.Namespace, left.ID, right.ExpiresAt, right.Namespace, right.ID,
			)
		})
	}
	page := BlobStagePage{Items: items}
	if len(page.Items) > limit {
		page.Items = page.Items[:limit]
		last := page.Items[len(page.Items)-1]
		page.NextCursor = encodeProtectionExpiryCursor(
			cursorBlobStageExpired, cutoff, last.ExpiresAt, last.Namespace, last.ID,
		)
	}
	return page, nil
}

func (s *MemoryStore) DeleteExpiredBlobStage(
	ctx context.Context,
	namespace string,
	id ProtectionID,
	cutoff time.Time,
) (bool, error) {
	if id == (ProtectionID{}) {
		return false, fmt.Errorf("%w: invalid blob stage identity", ErrInvalid)
	}
	cutoff, err := normalizeProtectionTime(cutoff)
	if err != nil {
		return false, err
	}
	if err := ctx.Err(); err != nil {
		return false, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return false, err
	}
	key := scopedProtection{namespace: namespace, id: id}
	stage, found := s.stages[key]
	if !found || stage.ExpiresAt.After(cutoff) {
		return false, nil
	}
	delete(s.stages, key)
	return true, nil
}

func (s *MemoryStore) ListExpiredFileLeases(
	ctx context.Context,
	cutoff time.Time,
	request PageRequest,
) (FileLeasePage, error) {
	cutoff, limit, cursor, hasCursor, err := protectionExpiryPage(cutoff, request, cursorFileLeaseExpired)
	if err != nil {
		return FileLeasePage{}, err
	}
	if err := ctx.Err(); err != nil {
		return FileLeasePage{}, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	items := make([]FileLease, 0, min(limit+1, len(s.leases)))
	for _, lease := range s.leases {
		if err := ctx.Err(); err != nil {
			return FileLeasePage{}, err
		}
		if lease.ExpiresAt.After(cutoff) || hasCursor && compareProtectionExpiry(
			lease.ExpiresAt, lease.Namespace, lease.ID, cursor.expiresAt, cursor.namespace, cursor.id,
		) <= 0 {
			continue
		}
		items = keepFirstProtections(items, lease, limit+1, func(left, right FileLease) int {
			return compareProtectionExpiry(
				left.ExpiresAt, left.Namespace, left.ID, right.ExpiresAt, right.Namespace, right.ID,
			)
		})
	}
	page := FileLeasePage{Items: items}
	if len(page.Items) > limit {
		page.Items = page.Items[:limit]
		last := page.Items[len(page.Items)-1]
		page.NextCursor = encodeProtectionExpiryCursor(
			cursorFileLeaseExpired, cutoff, last.ExpiresAt, last.Namespace, last.ID,
		)
	}
	return page, nil
}

func (s *MemoryStore) DeleteExpiredFileLease(
	ctx context.Context,
	namespace string,
	id ProtectionID,
	cutoff time.Time,
) (bool, error) {
	if id == (ProtectionID{}) {
		return false, fmt.Errorf("%w: invalid file lease identity", ErrInvalid)
	}
	cutoff, err := normalizeProtectionTime(cutoff)
	if err != nil {
		return false, err
	}
	if err := ctx.Err(); err != nil {
		return false, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return false, err
	}
	key := scopedProtection{namespace: namespace, id: id}
	lease, found := s.leases[key]
	if !found || lease.ExpiresAt.After(cutoff) {
		return false, nil
	}
	delete(s.leases, key)
	return true, nil
}

func keepFirstProtections[T any](items []T, value T, limit int, compare func(T, T) int) []T {
	position := sort.Search(len(items), func(index int) bool {
		return compare(items[index], value) >= 0
	})
	if position >= limit {
		return items
	}
	if len(items) < limit {
		items = append(items, value)
	}
	copy(items[position+1:], items[position:len(items)-1])
	items[position] = value
	return items
}

func compareProtectionExpiry(
	leftExpiry time.Time,
	leftNamespace string,
	leftID ProtectionID,
	rightExpiry time.Time,
	rightNamespace string,
	rightID ProtectionID,
) int {
	if comparison := leftExpiry.Compare(rightExpiry); comparison != 0 {
		return comparison
	}
	return compareScopedProtection(leftNamespace, leftID, rightNamespace, rightID)
}

func scopedProtectionPage(
	request PageRequest,
	namespace *string,
	cursorKind byte,
) (int, string, ProtectionID, bool, error) {
	limit, err := pageLimit(request)
	if err != nil {
		return 0, "", ProtectionID{}, false, err
	}
	if request.Cursor == "" {
		return limit, "", ProtectionID{}, false, nil
	}
	cursorNamespace, key, err := decodeScopedCursor(request.Cursor, cursorKind, len(ProtectionID{}))
	if err != nil {
		return 0, "", ProtectionID{}, false, err
	}
	if namespace != nil && cursorNamespace != *namespace {
		return 0, "", ProtectionID{}, false, fmt.Errorf("%w: cursor namespace differs from filter", ErrInvalid)
	}
	var id ProtectionID
	copy(id[:], key)
	return limit, cursorNamespace, id, true, nil
}

func compareScopedProtection(
	leftNamespace string,
	leftID ProtectionID,
	rightNamespace string,
	rightID ProtectionID,
) int {
	if leftNamespace < rightNamespace {
		return -1
	}
	if leftNamespace > rightNamespace {
		return 1
	}
	return bytes.Compare(leftID[:], rightID[:])
}

func scopedHashPage(
	request PageRequest,
	namespace *string,
	cursorKind byte,
) (int, string, xethash.Hash, bool, error) {
	limit, err := pageLimit(request)
	if err != nil {
		return 0, "", xethash.Hash{}, false, err
	}
	if request.Cursor == "" {
		return limit, "", xethash.Hash{}, false, nil
	}
	cursorNamespace, key, err := decodeScopedCursor(request.Cursor, cursorKind, len(xethash.Hash{}))
	if err != nil {
		return 0, "", xethash.Hash{}, false, err
	}
	if namespace != nil && cursorNamespace != *namespace {
		return 0, "", xethash.Hash{}, false, fmt.Errorf("%w: cursor namespace differs from filter", ErrInvalid)
	}
	var cursorHash xethash.Hash
	copy(cursorHash[:], key)
	return limit, cursorNamespace, cursorHash, true, nil
}

func scopedSHAPage(
	request PageRequest,
	namespace *string,
	cursorKind byte,
) (int, string, [32]byte, uint64, bool, error) {
	limit, err := pageLimit(request)
	if err != nil {
		return 0, "", [32]byte{}, 0, false, err
	}
	if request.Cursor == "" {
		return limit, "", [32]byte{}, 0, false, nil
	}
	cursorNamespace, key, err := decodeScopedCursor(request.Cursor, cursorKind, 40)
	if err != nil {
		return 0, "", [32]byte{}, 0, false, err
	}
	if namespace != nil && cursorNamespace != *namespace {
		return 0, "", [32]byte{}, 0, false, fmt.Errorf("%w: cursor namespace differs from filter", ErrInvalid)
	}
	var sum [32]byte
	copy(sum[:], key[:32])
	return limit, cursorNamespace, sum, binary.BigEndian.Uint64(key[32:]), true, nil
}

func compareScopedHash(leftNamespace string, leftHash xethash.Hash, rightNamespace string, rightHash xethash.Hash) int {
	if leftNamespace < rightNamespace {
		return -1
	}
	if leftNamespace > rightNamespace {
		return 1
	}
	return bytes.Compare(leftHash[:], rightHash[:])
}

func compareScopedSHA(
	leftNamespace string,
	leftSum [32]byte,
	leftSize uint64,
	rightNamespace string,
	rightSum [32]byte,
	rightSize uint64,
) int {
	if leftNamespace < rightNamespace {
		return -1
	}
	if leftNamespace > rightNamespace {
		return 1
	}
	if result := bytes.Compare(leftSum[:], rightSum[:]); result != 0 {
		return result
	}
	if leftSize < rightSize {
		return -1
	}
	if leftSize > rightSize {
		return 1
	}
	return 0
}

func shaCursorKey(sum [32]byte, size uint64) []byte {
	key := make([]byte, 40)
	copy(key, sum[:])
	binary.BigEndian.PutUint64(key[32:], size)
	return key
}

func cloneXorbRecord(value XorbRecord) XorbRecord {
	value.Layout.Complete = append([]byte(nil), value.Layout.Complete...)
	value.Layout.Chunks = append([]xorb.IngestedChunk(nil), value.Layout.Chunks...)
	return value
}

func cloneFileRecord(value FileRecord) FileRecord {
	value.File.File.Terms = append([]shard.Term(nil), value.File.File.Terms...)
	if value.File.File.SHA256 != nil {
		sum := *value.File.File.SHA256
		value.File.File.SHA256 = &sum
	}
	return value
}

func errorsf(message string) error { return fmt.Errorf("xet CAS server: %s", message) }
