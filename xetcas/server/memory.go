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

// MemoryStore is a concurrency-safe reference BlobStore and IndexStore. It is
// intended for tests, local development, and protocol interoperability suites.
type MemoryStore struct {
	mu     sync.RWMutex
	blobs  map[BlobKey][]byte
	xorbs  map[xethash.Hash]XorbRecord
	files  map[xethash.Hash]FileRecord
	dedup  map[xethash.Hash]DedupRecord
	sha256 map[shaKey]xethash.Hash
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		blobs: make(map[BlobKey][]byte), xorbs: make(map[xethash.Hash]XorbRecord),
		files: make(map[xethash.Hash]FileRecord), dedup: make(map[xethash.Hash]DedupRecord),
		sha256: make(map[shaKey]xethash.Hash),
	}
}

func (s *MemoryStore) PutIfAbsent(_ context.Context, key BlobKey, body io.Reader, size int64) (bool, error) {
	if body == nil || size < 0 {
		return false, errorsf("invalid blob body or size")
	}
	data, err := io.ReadAll(io.LimitReader(body, size+1))
	if err != nil {
		return false, err
	}
	if int64(len(data)) != size {
		return false, fmt.Errorf("xet CAS server: blob size %d, expected %d", len(data), size)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if previous, ok := s.blobs[key]; ok {
		if !bytes.Equal(previous, data) {
			return false, ErrConflict
		}
		return false, nil
	}
	s.blobs[key] = append([]byte(nil), data...)
	return true, nil
}

func (s *MemoryStore) Head(_ context.Context, key BlobKey) (BlobInfo, bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	value, ok := s.blobs[key]
	return BlobInfo{Size: int64(len(value))}, ok, nil
}

func (s *MemoryStore) Get(_ context.Context, key BlobKey, wanted *xetcas.HTTPRange) (io.ReadCloser, error) {
	s.mu.RLock()
	value, ok := s.blobs[key]
	if ok {
		value = append([]byte(nil), value...)
	}
	s.mu.RUnlock()
	if !ok {
		return nil, ErrNotFound
	}
	if wanted != nil {
		if err := wanted.Validate(); err != nil || wanted.End >= uint64(len(value)) {
			return nil, xetcas.ErrRangeNotSatisfiable
		}
		value = value[wanted.Start : wanted.End+1]
	}
	return io.NopCloser(bytes.NewReader(value)), nil
}

func (s *MemoryStore) GetXorb(_ context.Context, hash xethash.Hash) (XorbRecord, bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	value, ok := s.xorbs[hash]
	return cloneXorbRecord(value), ok, nil
}

func (s *MemoryStore) PutXorb(_ context.Context, value XorbRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if previous, ok := s.xorbs[value.Layout.Hash]; ok && !reflect.DeepEqual(previous, value) {
		return ErrConflict
	}
	s.xorbs[value.Layout.Hash] = cloneXorbRecord(value)
	return nil
}

func (s *MemoryStore) GetFile(_ context.Context, hash xethash.Hash) (FileRecord, bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	value, ok := s.files[hash]
	return cloneFileRecord(value), ok, nil
}

func (s *MemoryStore) PutFile(_ context.Context, value FileRecord) error {
	hash := value.File.File.Hash
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.files[hash]; ok {
		// A file identity authenticates the logical chunk sequence, not one
		// particular shard recipe or the presence of optional SHA metadata.
		// Keep the first durable, already validated reconstruction source.
		return nil
	}
	s.files[hash] = cloneFileRecord(value)
	return nil
}

func (s *MemoryStore) GetDedup(_ context.Context, hash xethash.Hash) (DedupRecord, bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	value, ok := s.dedup[hash]
	return value, ok, nil
}

func (s *MemoryStore) PutDedup(_ context.Context, hash xethash.Hash, value DedupRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.dedup[hash]; ok {
		// A chunk may legitimately occur in many shards. Keep the first durable
		// source; replacing it is unnecessary and a different source is not an
		// immutable-value conflict.
		return nil
	}
	s.dedup[hash] = value
	return nil
}

func (s *MemoryStore) ResolveSHA256(_ context.Context, namespace string, sum [32]byte, size uint64) (xethash.Hash, bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	value, ok := s.sha256[shaKey{namespace: namespace, sum: sum, size: size}]
	return value, ok, nil
}

func (s *MemoryStore) PutSHA256(_ context.Context, namespace string, sum [32]byte, size uint64, hash xethash.Hash) error {
	key := shaKey{namespace: namespace, sum: sum, size: size}
	s.mu.Lock()
	defer s.mu.Unlock()
	if previous, ok := s.sha256[key]; ok && previous != hash {
		return ErrConflict
	}
	s.sha256[key] = hash
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
