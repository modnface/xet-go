// Package cache implements the standard persistent Xet content cache.
package cache

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/jacobwoliver/xet-go/xethash"
)

const (
	entryHeaderSize = 56
	maxEntrySize    = 160 << 20
	lockStaleAfter  = 10 * time.Minute
)

var entryMagic = [8]byte{'X', 'E', 'T', 'C', 'A', 'C', 'H', '1'}

type Disk struct {
	root string
	now  func() time.Time
	mu   [64]sync.Mutex
}

func NewDisk(directory, namespace string) (*Disk, error) {
	if directory == "" {
		return nil, errors.New("xet cache: empty directory")
	}
	if namespace == "" {
		return nil, errors.New("xet cache: empty CAS namespace")
	}
	absolute, err := filepath.Abs(directory)
	if err != nil {
		return nil, fmt.Errorf("xet cache: absolute path: %w", err)
	}
	digest := sha256.Sum256([]byte(namespace))
	root := filepath.Join(absolute, "xet-go-v1", hex.EncodeToString(digest[:]))
	if err := os.MkdirAll(root, 0o700); err != nil {
		return nil, fmt.Errorf("xet cache: create namespace: %w", err)
	}
	return &Disk{root: root, now: time.Now}, nil
}

func (d *Disk) GetXorbRange(
	ctx context.Context,
	hash xethash.Hash,
	start, end uint32,
) ([]byte, bool, error) {
	if end <= start {
		return nil, false, errors.New("xet cache: invalid chunk range")
	}
	return d.read(ctx, d.rangePath(hash, start, end))
}

func (d *Disk) PutXorbRange(
	ctx context.Context,
	hash xethash.Hash,
	start, end uint32,
	data []byte,
) error {
	if end <= start {
		return errors.New("xet cache: invalid chunk range")
	}
	return d.write(ctx, d.rangePath(hash, start, end), data, time.Time{})
}

func (d *Disk) DeleteXorbRange(_ context.Context, hash xethash.Hash, start, end uint32) error {
	return removeIfExists(d.rangePath(hash, start, end))
}

func (d *Disk) GetShard(ctx context.Context, chunkHash xethash.Hash) ([]byte, bool, error) {
	return d.read(ctx, d.shardPath(chunkHash))
}

func (d *Disk) PutShard(ctx context.Context, chunkHash xethash.Hash, data []byte, expiresAt time.Time) error {
	if expiresAt.IsZero() {
		return errors.New("xet cache: global dedup shard requires an expiry")
	}
	if !expiresAt.After(d.now()) {
		return nil
	}
	return d.write(ctx, d.shardPath(chunkHash), data, expiresAt)
}

func (d *Disk) DeleteShard(_ context.Context, chunkHash xethash.Hash) error {
	return removeIfExists(d.shardPath(chunkHash))
}

func (d *Disk) rangePath(hash xethash.Hash, start, end uint32) string {
	return filepath.Join(d.root, "ranges", hash.String(), fmt.Sprintf("%d-%d.entry", start, end))
}

func (d *Disk) shardPath(hash xethash.Hash) string {
	return filepath.Join(d.root, "shards", hash.String()+".entry")
}

func (d *Disk) read(ctx context.Context, path string) ([]byte, bool, error) {
	if err := ctx.Err(); err != nil {
		return nil, false, err
	}
	file, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("xet cache: open entry: %w", err)
	}
	defer func() { _ = file.Close() }()
	info, err := file.Stat()
	if err != nil {
		return nil, false, fmt.Errorf("xet cache: stat entry: %w", err)
	}
	if info.Size() < entryHeaderSize || info.Size() > entryHeaderSize+maxEntrySize {
		_ = file.Close()
		_ = removeIfExists(path)
		return nil, false, nil
	}
	var header [entryHeaderSize]byte
	if _, err := io.ReadFull(file, header[:]); err != nil || headerMagic(header) != entryMagic {
		_ = file.Close()
		_ = removeIfExists(path)
		return nil, false, nil
	}
	expiresUnix := int64(binary.LittleEndian.Uint64(header[8:16]))
	if expiresUnix != 0 && !time.Unix(expiresUnix, 0).After(d.now()) {
		_ = file.Close()
		_ = removeIfExists(path)
		return nil, false, nil
	}
	length := binary.LittleEndian.Uint64(header[16:24])
	if length > maxEntrySize || int64(length)+entryHeaderSize != info.Size() {
		_ = file.Close()
		_ = removeIfExists(path)
		return nil, false, nil
	}
	if uint64(int(length)) != length {
		return nil, false, errors.New("xet cache: entry length overflows int")
	}
	data := make([]byte, int(length))
	if _, err := io.ReadFull(file, data); err != nil {
		_ = file.Close()
		_ = removeIfExists(path)
		return nil, false, nil
	}
	digest := sha256.Sum256(data)
	if !equalBytes(digest[:], header[24:56]) {
		_ = file.Close()
		_ = removeIfExists(path)
		return nil, false, nil
	}
	return data, true, nil
}

func (d *Disk) write(ctx context.Context, path string, data []byte, expiresAt time.Time) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if len(data) > maxEntrySize {
		return fmt.Errorf("xet cache: entry size %d exceeds limit %d", len(data), maxEntrySize)
	}
	lock := &d.mu[shardForPath(path)]
	lock.Lock()
	defer lock.Unlock()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("xet cache: create entry directory: %w", err)
	}
	release, err := d.acquireFileLock(ctx, path+".lock")
	if err != nil {
		return err
	}
	defer release()

	file, err := os.CreateTemp(filepath.Dir(path), ".xet-cache-*")
	if err != nil {
		return fmt.Errorf("xet cache: create temporary entry: %w", err)
	}
	temporary := file.Name()
	defer removeIfExists(temporary) //nolint:errcheck // best-effort cleanup after close/rename
	if err := file.Chmod(0o600); err != nil {
		_ = file.Close()
		return fmt.Errorf("xet cache: set entry mode: %w", err)
	}
	var header [entryHeaderSize]byte
	copy(header[:8], entryMagic[:])
	if !expiresAt.IsZero() {
		binary.LittleEndian.PutUint64(header[8:16], uint64(expiresAt.Unix()))
	}
	binary.LittleEndian.PutUint64(header[16:24], uint64(len(data)))
	digest := sha256.Sum256(data)
	copy(header[24:56], digest[:])
	_, writeErr := file.Write(header[:])
	if writeErr == nil {
		_, writeErr = file.Write(data)
	}
	if writeErr != nil {
		_ = file.Close()
		return fmt.Errorf("xet cache: write entry: %w", writeErr)
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return fmt.Errorf("xet cache: sync entry: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("xet cache: close entry: %w", err)
	}
	if err := os.Rename(temporary, path); err != nil {
		return fmt.Errorf("xet cache: publish entry: %w", err)
	}
	return nil
}

func (d *Disk) acquireFileLock(ctx context.Context, path string) (func(), error) {
	for {
		file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err == nil {
			return func() {
				_ = file.Close()
				_ = removeIfExists(path)
			}, nil
		}
		if !errors.Is(err, os.ErrExist) {
			return nil, fmt.Errorf("xet cache: acquire entry lock: %w", err)
		}
		if info, statErr := os.Stat(path); statErr == nil && d.now().Sub(info.ModTime()) > lockStaleAfter {
			_ = removeIfExists(path)
			continue
		}
		timer := time.NewTimer(10 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil, ctx.Err()
		case <-timer.C:
		}
	}
}

func headerMagic(header [entryHeaderSize]byte) [8]byte {
	var value [8]byte
	copy(value[:], header[:8])
	return value
}

func shardForPath(path string) int {
	digest := sha256.Sum256([]byte(path))
	return int(digest[0]) % 64
}

func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var difference byte
	for i := range a {
		difference |= a[i] ^ b[i]
	}
	return difference == 0
}

func removeIfExists(path string) error {
	err := os.Remove(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}
