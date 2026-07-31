package cache

import (
	"bytes"
	"context"
	"errors"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/jacobwoliver/xet-go/xethash"
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
