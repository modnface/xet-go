package cache

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/jmwoliver/xet-go/xethash"
)

func TestRangeRoundTripAndCorruptionEviction(t *testing.T) {
	cache, err := NewDisk(t.TempDir(), "https://cas.example/scope")
	if err != nil {
		t.Fatal(err)
	}
	hash := xethash.Chunk([]byte("range"))
	data := bytes.Repeat([]byte("serialized-xorb"), 100)
	if err := cache.PutXorbRange(context.Background(), hash, 2, 8, data); err != nil {
		t.Fatal(err)
	}
	got, found, err := cache.GetXorbRange(context.Background(), hash, 2, 8)
	if err != nil || !found || !bytes.Equal(got, data) {
		t.Fatalf("got=%d bytes found=%v err=%v", len(got), found, err)
	}
	path := cache.rangePath(hash, 2, 8)
	file, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.WriteAt([]byte{0xff}, entryHeaderSize+3); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if _, found, err := cache.GetXorbRange(context.Background(), hash, 2, 8); err != nil || found {
		t.Fatalf("corrupt entry found=%v err=%v", found, err)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("corrupt entry was not evicted: %v", err)
	}
}

func TestShardExpiry(t *testing.T) {
	cache, err := NewDisk(t.TempDir(), "scope")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(2_000_000_000, 0)
	cache.now = func() time.Time { return now }
	hash := xethash.Chunk([]byte("dedup"))
	if err := cache.PutShard(context.Background(), hash, []byte("shard"), now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if data, found, err := cache.GetShard(context.Background(), hash); err != nil || !found || string(data) != "shard" {
		t.Fatalf("before expiry data=%q found=%v err=%v", data, found, err)
	}
	now = now.Add(2 * time.Hour)
	if _, found, err := cache.GetShard(context.Background(), hash); err != nil || found {
		t.Fatalf("after expiry found=%v err=%v", found, err)
	}
}

func TestConcurrentImmutableWriters(t *testing.T) {
	cache, err := NewDisk(t.TempDir(), "scope")
	if err != nil {
		t.Fatal(err)
	}
	hash := xethash.Chunk([]byte("concurrent"))
	data := bytes.Repeat([]byte{0xab}, 64<<10)
	const writers = 24
	var wg sync.WaitGroup
	errorsFound := make(chan error, writers)
	for range writers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errorsFound <- cache.PutXorbRange(context.Background(), hash, 0, 1, data)
		}()
	}
	wg.Wait()
	close(errorsFound)
	for err := range errorsFound {
		if err != nil {
			t.Fatal(err)
		}
	}
	got, found, err := cache.GetXorbRange(context.Background(), hash, 0, 1)
	if err != nil || !found || !bytes.Equal(got, data) {
		t.Fatalf("got=%d found=%v err=%v", len(got), found, err)
	}
}

func TestNamespaceIsolationAndCancellation(t *testing.T) {
	directory := t.TempDir()
	first, err := NewDisk(directory, "scope-a")
	if err != nil {
		t.Fatal(err)
	}
	second, err := NewDisk(directory, "scope-b")
	if err != nil {
		t.Fatal(err)
	}
	hash := xethash.Chunk([]byte("namespace"))
	if err := first.PutXorbRange(context.Background(), hash, 0, 1, []byte("a")); err != nil {
		t.Fatal(err)
	}
	if _, found, err := second.GetXorbRange(context.Background(), hash, 0, 1); err != nil || found {
		t.Fatalf("second namespace found=%v err=%v", found, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := first.PutXorbRange(ctx, hash, 1, 2, []byte("b")); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled write error=%v", err)
	}
}

func TestDiskInputAndDeletionContracts(t *testing.T) {
	if _, err := NewDisk("", "scope"); err == nil {
		t.Fatal("empty directory succeeded")
	}
	if _, err := NewDisk(t.TempDir(), ""); err == nil {
		t.Fatal("empty namespace succeeded")
	}
	parentFile := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(parentFile, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewDisk(filepath.Join(parentFile, "cache"), "scope"); err == nil {
		t.Fatal("cache below a regular file succeeded")
	}

	cache, err := NewDisk(t.TempDir(), "scope")
	if err != nil {
		t.Fatal(err)
	}
	hash := xethash.Chunk([]byte("delete"))
	if _, _, err := cache.GetXorbRange(context.Background(), hash, 2, 2); err == nil {
		t.Fatal("empty GetXorbRange succeeded")
	}
	if err := cache.PutXorbRange(context.Background(), hash, 2, 2, nil); err == nil {
		t.Fatal("empty PutXorbRange succeeded")
	}
	if err := cache.PutShard(context.Background(), hash, nil, time.Time{}); err == nil {
		t.Fatal("shard without expiry succeeded")
	}
	cache.now = func() time.Time { return time.Unix(100, 0) }
	if err := cache.PutShard(context.Background(), hash, []byte("old"), time.Unix(99, 0)); err != nil {
		t.Fatal(err)
	}
	if _, found, err := cache.GetShard(context.Background(), hash); err != nil || found {
		t.Fatalf("expired shard found = %v, err = %v", found, err)
	}

	if err := cache.PutXorbRange(context.Background(), hash, 0, 1, []byte("range")); err != nil {
		t.Fatal(err)
	}
	if err := cache.DeleteXorbRange(context.Background(), hash, 0, 1); err != nil {
		t.Fatal(err)
	}
	if err := cache.DeleteXorbRange(context.Background(), hash, 0, 1); err != nil {
		t.Fatalf("idempotent range deletion: %v", err)
	}
	if err := cache.PutShard(context.Background(), hash, []byte("shard"), time.Unix(200, 0)); err != nil {
		t.Fatal(err)
	}
	if err := cache.DeleteShard(context.Background(), hash); err != nil {
		t.Fatal(err)
	}
	if err := cache.DeleteShard(context.Background(), hash); err != nil {
		t.Fatalf("idempotent shard deletion: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := cache.GetShard(ctx, hash); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled read error = %v", err)
	}
}

func TestCorruptEntryFormsAreEvicted(t *testing.T) {
	cache, err := NewDisk(t.TempDir(), "scope")
	if err != nil {
		t.Fatal(err)
	}
	hash := xethash.Chunk([]byte("corruption forms"))
	path := cache.rangePath(hash, 0, 1)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}

	tests := map[string]func(string){
		"short header": func(path string) {
			if err := os.WriteFile(path, []byte("short"), 0o600); err != nil {
				t.Fatal(err)
			}
		},
		"oversized file": func(path string) {
			file, err := os.Create(path)
			if err != nil {
				t.Fatal(err)
			}
			if err := file.Truncate(entryHeaderSize + maxEntrySize + 1); err != nil {
				t.Fatal(err)
			}
			_ = file.Close()
		},
		"bad magic": func(path string) {
			if err := os.WriteFile(path, make([]byte, entryHeaderSize), 0o600); err != nil {
				t.Fatal(err)
			}
		},
		"length mismatch": func(path string) {
			header := validEntryHeader([]byte("x"), time.Time{})
			binary.LittleEndian.PutUint64(header[16:24], 2)
			if err := os.WriteFile(path, append(header[:], 'x'), 0o600); err != nil {
				t.Fatal(err)
			}
		},
		"expired": func(path string) {
			header := validEntryHeader(nil, time.Unix(99, 0))
			if err := os.WriteFile(path, header[:], 0o600); err != nil {
				t.Fatal(err)
			}
		},
	}
	cache.now = func() time.Time { return time.Unix(100, 0) }
	for name, prepare := range tests {
		t.Run(name, func(t *testing.T) {
			prepare(path)
			if _, found, err := cache.GetXorbRange(context.Background(), hash, 0, 1); err != nil || found {
				t.Fatalf("found = %v, err = %v", found, err)
			}
			if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("corrupt entry remains: %v", err)
			}
		})
	}
}

func TestFileLockCancellationAndStaleRecovery(t *testing.T) {
	cache, err := NewDisk(t.TempDir(), "scope")
	if err != nil {
		t.Fatal(err)
	}
	hash := xethash.Chunk([]byte("locked"))
	path := cache.rangePath(hash, 0, 1)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	lockPath := path + ".lock"
	if err := os.WriteFile(lockPath, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	ctx := &cancelWhenDoneObserved{Context: context.Background(), done: make(chan struct{})}
	if err := cache.PutXorbRange(ctx, hash, 0, 1, []byte("x")); !errors.Is(err, context.Canceled) {
		t.Fatalf("lock cancellation error = %v", err)
	}

	old := time.Now().Add(-lockStaleAfter - time.Minute)
	if err := os.Chtimes(lockPath, old, old); err != nil {
		t.Fatal(err)
	}
	cache.now = time.Now
	if err := cache.PutXorbRange(context.Background(), hash, 0, 1, []byte("recovered")); err != nil {
		t.Fatalf("stale lock recovery: %v", err)
	}

	cache.root = filepath.Join(t.TempDir(), "root-file")
	if err := os.WriteFile(cache.root, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := cache.PutXorbRange(context.Background(), hash, 1, 2, []byte("x")); err == nil {
		t.Fatal("write below regular file succeeded")
	}
	if equalBytes([]byte{1}, []byte{1, 2}) || equalBytes([]byte{1}, []byte{2}) || !equalBytes(nil, nil) {
		t.Fatal("equalBytes contract differs")
	}

	component := filepath.Join(t.TempDir(), "regular-component")
	if err := os.WriteFile(component, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := cache.read(context.Background(), filepath.Join(component, "entry")); err == nil {
		t.Fatal("cache read below regular path component succeeded")
	}
	if _, err := cache.acquireFileLock(context.Background(), filepath.Join(component, "entry.lock")); err == nil {
		t.Fatal("file lock below regular path component succeeded")
	}
}

type cancelWhenDoneObserved struct {
	context.Context
	done     chan struct{}
	observed bool
}

func (c *cancelWhenDoneObserved) Done() <-chan struct{} {
	if !c.observed {
		c.observed = true
		close(c.done)
	}
	return c.done
}

func (c *cancelWhenDoneObserved) Err() error {
	if c.observed {
		return context.Canceled
	}
	return nil
}

func validEntryHeader(data []byte, expires time.Time) [entryHeaderSize]byte {
	var header [entryHeaderSize]byte
	copy(header[:8], entryMagic[:])
	if !expires.IsZero() {
		binary.LittleEndian.PutUint64(header[8:16], uint64(expires.Unix()))
	}
	binary.LittleEndian.PutUint64(header[16:24], uint64(len(data)))
	digest := sha256.Sum256(data)
	copy(header[24:56], digest[:])
	return header
}

func FuzzEntryRoundTrip(f *testing.F) {
	f.Add([]byte("cache"))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 1<<20 {
			return
		}
		cache, err := NewDisk(t.TempDir(), "fuzz")
		if err != nil {
			t.Fatal(err)
		}
		hash := xethash.Chunk(data)
		if err := cache.PutXorbRange(context.Background(), hash, 0, 1, data); err != nil {
			t.Fatal(err)
		}
		got, found, err := cache.GetXorbRange(context.Background(), hash, 0, 1)
		if err != nil || !found || !bytes.Equal(got, data) {
			t.Fatalf("found=%v err=%v", found, err)
		}
	})
}
