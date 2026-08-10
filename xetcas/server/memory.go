package server

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"reflect"
	"sync"

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

// MemoryStore is a concurrency-safe reference BlobStore and IndexStore. It is
// intended for tests, local development, and protocol interoperability suites.
type MemoryStore struct {
	mu     sync.RWMutex
	blobs  map[BlobKey][]byte
	xorbs  map[xethash.Hash]XorbRecord
	files  map[scopedHash]FileRecord
	dedup  map[scopedHash]DedupRecord
	sha256 map[shaKey]xethash.Hash
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		blobs: make(map[BlobKey][]byte), xorbs: make(map[xethash.Hash]XorbRecord),
		files: make(map[scopedHash]FileRecord), dedup: make(map[scopedHash]DedupRecord),
		sha256: make(map[shaKey]xethash.Hash),
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
