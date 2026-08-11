// Package memory implements an ephemeral ordinary-content store.
package memory

import (
	"bytes"
	"container/heap"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"io"
	"slices"
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
var _ content.BlobLister = (*Store)(nil)

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

func (s *Store) ListBlobs(ctx context.Context, request content.PageRequest) (content.BlobPage, error) {
	if ctx == nil {
		return content.BlobPage{}, fmt.Errorf("%w: nil context", content.ErrInvalid)
	}
	if err := ctx.Err(); err != nil {
		return content.BlobPage{}, err
	}
	limit, err := pageLimit(request.Limit)
	if err != nil {
		return content.BlobPage{}, err
	}
	after, hasAfter, err := parseCursor(request.Cursor)
	if err != nil {
		return content.BlobPage{}, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if err := ctx.Err(); err != nil {
		return content.BlobPage{}, err
	}
	items := make(blobMaxHeap, 0, min(limit+1, len(s.blobs)))
	index := 0
	for sum, value := range s.blobs {
		if index&255 == 0 {
			if err := ctx.Err(); err != nil {
				return content.BlobPage{}, err
			}
		}
		index++
		if hasAfter && bytes.Compare(sum[:], after[:]) <= 0 {
			continue
		}
		blob := content.Blob{SHA256: sum, Size: int64(len(value))}
		if len(items) < limit+1 {
			heap.Push(&items, blob)
		} else if bytes.Compare(sum[:], items[0].SHA256[:]) < 0 {
			heap.Pop(&items)
			heap.Push(&items, blob)
		}
	}
	slices.SortFunc(items, func(left, right content.Blob) int {
		return bytes.Compare(left.SHA256[:], right.SHA256[:])
	})
	page := content.BlobPage{Items: items}
	if len(items) > limit {
		page.Items = items[:limit]
		page.NextCursor = hex.EncodeToString(page.Items[limit-1].SHA256[:])
	}
	return page, nil
}

type blobMaxHeap []content.Blob

func (blobs blobMaxHeap) Len() int { return len(blobs) }
func (blobs blobMaxHeap) Less(i, j int) bool {
	return bytes.Compare(blobs[i].SHA256[:], blobs[j].SHA256[:]) > 0
}
func (blobs blobMaxHeap) Swap(i, j int) { blobs[i], blobs[j] = blobs[j], blobs[i] }
func (blobs *blobMaxHeap) Push(value any) {
	*blobs = append(*blobs, value.(content.Blob)) //nolint:forcetypeassert // heap values are internal.
}
func (blobs *blobMaxHeap) Pop() any {
	old := *blobs
	last := old[len(old)-1]
	*blobs = old[:len(old)-1]
	return last
}

func pageLimit(value int) (int, error) {
	if value < 0 || value > content.MaxPageSize {
		return 0, fmt.Errorf("%w: page limit is outside [0,%d]", content.ErrInvalid, content.MaxPageSize)
	}
	if value == 0 {
		return content.DefaultPageSize, nil
	}
	return value, nil
}

func parseCursor(value string) ([32]byte, bool, error) {
	var sum [32]byte
	if value == "" {
		return sum, false, nil
	}
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != len(sum) || hex.EncodeToString(decoded) != value {
		return [32]byte{}, false, fmt.Errorf("%w: malformed blob cursor", content.ErrInvalid)
	}
	copy(sum[:], decoded)
	return sum, true, nil
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
