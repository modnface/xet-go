// Package memory implements an ephemeral ordinary-content store.
package memory

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
	"io"
	"sync"

	"github.com/jmwoliver/xet-go/content"
	"github.com/jmwoliver/xet-go/content/internal/verified"
)

type Store struct {
	mu    sync.RWMutex
	blobs map[[32]byte][]byte
}

func New() *Store { return &Store{blobs: make(map[[32]byte][]byte)} }

var _ content.Store = (*Store)(nil)

func (s *Store) Put(ctx context.Context, blob content.Blob, body io.Reader) (bool, error) {
	if err := valid(ctx, blob); err != nil {
		return false, err
	}
	if body == nil {
		return false, fmt.Errorf("%w: nil blob body", content.ErrInvalid)
	}
	var data bytes.Buffer
	if err := verified.Write(ctx, &data, body, blob); err != nil {
		return false, err
	}
	value := data.Bytes()
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return false, err
	}
	if retained, exists := s.blobs[blob.SHA256]; exists {
		if !bytes.Equal(retained, value) {
			return false, content.ErrConflict
		}
		return false, nil
	}
	s.blobs[blob.SHA256] = append([]byte(nil), value...)
	return true, nil
}

func (s *Store) Head(ctx context.Context, sum [32]byte) (content.Info, bool, error) {
	if ctx == nil {
		return content.Info{}, false, fmt.Errorf("%w: nil context", content.ErrInvalid)
	}
	if err := ctx.Err(); err != nil {
		return content.Info{}, false, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if err := ctx.Err(); err != nil {
		return content.Info{}, false, err
	}
	value, found := s.blobs[sum]
	return content.Info{Size: int64(len(value))}, found, nil
}

func (s *Store) Open(ctx context.Context, blob content.Blob, wanted *content.Range) (io.ReadCloser, error) {
	if err := valid(ctx, blob); err != nil {
		return nil, err
	}
	s.mu.RLock()
	value, found := s.blobs[blob.SHA256]
	value = append([]byte(nil), value...)
	s.mu.RUnlock()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !found {
		return nil, content.ErrNotFound
	}
	retainedHash := hash(value)
	if int64(len(value)) != blob.Size || subtle.ConstantTimeCompare(retainedHash[:], blob.SHA256[:]) != 1 {
		return nil, fmt.Errorf("%w: retained blob identity mismatch", content.ErrCorrupt)
	}
	start, end := int64(0), blob.Size
	full := wanted == nil
	if wanted != nil {
		if err := wanted.Validate(blob.Size); err != nil {
			return nil, err
		}
		start, end = wanted.Start, wanted.End
	}
	body := io.NopCloser(bytes.NewReader(value[start:end]))
	return verified.New(ctx, body, blob, end-start, full), nil
}

func valid(ctx context.Context, blob content.Blob) error {
	if ctx == nil {
		return fmt.Errorf("%w: nil context", content.ErrInvalid)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return blob.Validate()
}

func hash(value []byte) [32]byte { return sha256.Sum256(value) }
