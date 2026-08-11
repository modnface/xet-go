//go:build linux || darwin

package filesystem

import (
	"bytes"
	"container/heap"
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/jmwoliver/xet-go/content"
)

func TestOpenValidatesPrivateRealRoot(t *testing.T) {
	if _, err := Open(""); !errors.Is(err, content.ErrInvalid) {
		t.Fatalf("empty root = %v", err)
	}
	parent := t.TempDir()
	file := filepath.Join(parent, "file")
	if err := os.WriteFile(file, []byte("not a directory"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(file); !errors.Is(err, content.ErrInvalid) {
		t.Fatalf("file root = %v", err)
	}
	if _, err := Open(string([]byte{'\x00'})); !errors.Is(err, content.ErrUnavailable) {
		t.Fatalf("invalid root path = %v", err)
	}
	if _, err := Open(filepath.Join("/proc", "xet-go-content-test", "root")); !errors.Is(err, content.ErrUnavailable) {
		t.Fatalf("unwritable root = %v", err)
	}

	insecure := filepath.Join(parent, "insecure")
	if err := os.Mkdir(insecure, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(insecure, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(insecure); !errors.Is(err, content.ErrInvalid) {
		t.Fatalf("insecure root = %v", err)
	}

	target := filepath.Join(parent, "target")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	rootLink := filepath.Join(parent, "root-link")
	if err := os.Symlink(target, rootLink); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if _, err := Open(rootLink); !errors.Is(err, content.ErrInvalid) {
		t.Fatalf("symlink root = %v", err)
	}
	parentLink := filepath.Join(parent, "parent-link")
	if err := os.Symlink(target, parentLink); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(filepath.Join(parentLink, "nested")); !errors.Is(err, content.ErrInvalid) {
		t.Fatalf("symlinked parent = %v", err)
	}

	nested := filepath.Join(parent, "one", "two", "store")
	store, err := Open(nested)
	if err != nil {
		t.Fatal(err)
	}
	if err = store.Close(); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(nested)
	if err != nil || info.Mode().Perm()&0o077 != 0 {
		t.Fatalf("created root mode = %v, %v", info.Mode().Perm(), err)
	}
}

func TestPersistenceConcurrentHandlesAndClose(t *testing.T) {
	root := filepath.Join(t.TempDir(), "content")
	first := openTestStore(t, root)
	second := openTestStore(t, root)
	body := bytes.Repeat([]byte("durable ordinary content"), 2_000)
	blob := content.Blob{SHA256: sha256.Sum256(body), Size: int64(len(body))}

	const writers = 20
	var wait sync.WaitGroup
	insertions := make(chan bool, writers)
	errorsSeen := make(chan error, writers)
	for index := range writers {
		store := first
		if index%2 == 1 {
			store = second
		}
		wait.Add(1)
		go func() {
			defer wait.Done()
			inserted, err := store.Put(context.Background(), blob, bytes.NewReader(body))
			insertions <- inserted
			errorsSeen <- err
		}()
	}
	wait.Wait()
	close(insertions)
	close(errorsSeen)
	count := 0
	for inserted := range insertions {
		if inserted {
			count++
		}
	}
	for err := range errorsSeen {
		if err != nil {
			t.Fatal(err)
		}
	}
	if count != 1 {
		t.Fatalf("insertions = %d, want 1", count)
	}

	reader, err := first.Open(context.Background(), blob, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err = first.Close(); err != nil {
		t.Fatal(err)
	}
	if err = first.Close(); err != nil {
		t.Fatalf("second close = %v", err)
	}
	if _, _, err = first.Head(context.Background(), blob.SHA256); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("head after close = %v", err)
	}
	got, err := io.ReadAll(reader)
	closeErr := reader.Close()
	if err != nil || closeErr != nil || !bytes.Equal(got, body) {
		t.Fatalf("reader after close = %d bytes, %v, %v", len(got), err, closeErr)
	}
	_ = second.Close()

	reopened := openTestStore(t, root)
	reader, err = reopened.Open(context.Background(), blob, nil)
	if err != nil {
		t.Fatal(err)
	}
	got, err = io.ReadAll(reader)
	_ = reader.Close()
	if err != nil || !bytes.Equal(got, body) {
		t.Fatalf("restarted read = %d bytes, %v", len(got), err)
	}
	rangeReader, err := reopened.Open(context.Background(), blob, &content.Range{Start: 3, End: 31})
	if err != nil {
		t.Fatal(err)
	}
	got, err = io.ReadAll(rangeReader)
	closeErr = rangeReader.Close()
	if err != nil || closeErr != nil || !bytes.Equal(got, body[3:31]) {
		t.Fatalf("range read = %q, %v, %v", got, err, closeErr)
	}
	if _, err = reopened.Open(context.Background(), blob, &content.Range{Start: 5, End: 5}); !errors.Is(err, content.ErrRangeNotSatisfiable) {
		t.Fatalf("invalid range = %v", err)
	}
}

func TestCorruptAndSymlinkedObjectsAreRejected(t *testing.T) {
	store := openTestStore(t, filepath.Join(t.TempDir(), "content"))
	ctx := context.Background()
	body := []byte("retained object bytes")
	blob := content.Blob{SHA256: sha256.Sum256(body), Size: int64(len(body))}
	if _, err := store.Put(ctx, blob, bytes.NewReader(body)); err != nil {
		t.Fatal(err)
	}
	path := store.objectPath(blob.SHA256)

	corrupt := bytes.Repeat([]byte{'x'}, len(body))
	if err := os.WriteFile(path, corrupt, 0o600); err != nil {
		t.Fatal(err)
	}
	reader, err := store.Open(ctx, blob, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = io.ReadAll(reader); !errors.Is(err, content.ErrCorrupt) {
		t.Fatalf("same-size corruption = %v", err)
	}
	_ = reader.Close()
	if _, err = store.Put(ctx, blob, bytes.NewReader(body)); !errors.Is(err, content.ErrConflict) {
		t.Fatalf("put over corruption = %v", err)
	}

	if err = os.WriteFile(path, append(body, '!'), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err = store.Open(ctx, blob, nil); !errors.Is(err, content.ErrCorrupt) {
		t.Fatalf("extended object = %v", err)
	}
	if err = os.WriteFile(path, body[:len(body)-1], 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err = store.Open(ctx, blob, nil); !errors.Is(err, content.ErrCorrupt) {
		t.Fatalf("truncated object = %v", err)
	}

	target := filepath.Join(t.TempDir(), "target")
	if err = os.WriteFile(target, []byte("target"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err = os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err = os.Symlink(target, path); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if _, _, err = store.Head(ctx, blob.SHA256); !errors.Is(err, content.ErrCorrupt) {
		t.Fatalf("symlink head = %v", err)
	}
	if _, err = store.Open(ctx, blob, nil); !errors.Is(err, content.ErrCorrupt) {
		t.Fatalf("symlink open = %v", err)
	}
	if _, err = store.Put(ctx, blob, bytes.NewReader(body)); !errors.Is(err, content.ErrCorrupt) {
		t.Fatalf("symlink put = %v", err)
	}
	if got, err := os.ReadFile(target); err != nil || string(got) != "target" {
		t.Fatalf("symlink target = %q, %v", got, err)
	}
}

func TestSymlinkedObjectDirectoryIsRejected(t *testing.T) {
	store := openTestStore(t, filepath.Join(t.TempDir(), "content"))
	body := []byte("directory attack")
	blob := content.Blob{SHA256: sha256.Sum256(body), Size: int64(len(body))}
	directory := filepath.Dir(store.objectPath(blob.SHA256))
	if err := os.MkdirAll(filepath.Dir(directory), 0o700); err != nil {
		t.Fatal(err)
	}
	target := t.TempDir()
	if err := os.Symlink(target, directory); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if _, err := store.Put(context.Background(), blob, bytes.NewReader(body)); !errors.Is(err, content.ErrCorrupt) {
		t.Fatalf("put through symlinked directory = %v", err)
	}
	entries, err := os.ReadDir(target)
	if err != nil || len(entries) != 0 {
		t.Fatalf("symlink target entries = %d, %v", len(entries), err)
	}
}

func TestBlobInventoryOrdersLargeLeafWithoutLoadingItAsAPage(t *testing.T) {
	store := openTestStore(t, filepath.Join(t.TempDir(), "content"))
	expected := make([]content.Blob, 0, 300)
	for index := range 300 {
		var sum [32]byte
		sum[0], sum[1] = 0xaa, 0xbb
		sum[29], sum[30], sum[31] = byte(index>>16), byte(index>>8), byte(index)
		blob := content.Blob{SHA256: sum, Size: int64(index % 17)}
		objectPath := store.objectPath(sum)
		if err := os.MkdirAll(filepath.Dir(objectPath), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(objectPath, make([]byte, blob.Size), 0o600); err != nil {
			t.Fatal(err)
		}
		expected = append(expected, blob)
	}
	var got []content.Blob
	cursor := ""
	for len(got) < len(expected) {
		page, err := store.ListBlobs(context.Background(), content.PageRequest{Limit: 37, Cursor: cursor})
		if err != nil {
			t.Fatal(err)
		}
		got = append(got, page.Items...)
		cursor = page.NextCursor
	}
	if len(got) != len(expected) {
		t.Fatalf("inventory count = %d, want %d", len(got), len(expected))
	}
	for index := range expected {
		if got[index] != expected[index] {
			t.Fatalf("inventory item %d = %#v, want %#v", index, got[index], expected[index])
		}
	}
}

func TestBlobInventoryRejectsMalformedFilesystemState(t *testing.T) {
	type mutation func(*testing.T, *Store, string)
	for name, mutate := range map[string]mutation{
		"blob root file": func(t *testing.T, _ *Store, root string) {
			if err := os.MkdirAll(filepath.Dir(root), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(root, nil, 0o600); err != nil {
				t.Fatal(err)
			}
		},
		"blob root symlink": func(t *testing.T, _ *Store, root string) {
			if err := os.MkdirAll(filepath.Dir(root), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(t.TempDir(), root); err != nil {
				t.Skipf("symlink unavailable: %v", err)
			}
		},
		"content version file": func(t *testing.T, _ *Store, root string) {
			if err := os.WriteFile(filepath.Dir(root), nil, 0o600); err != nil {
				t.Fatal(err)
			}
		},
		"content version symlink": func(t *testing.T, _ *Store, root string) {
			if err := os.Symlink(t.TempDir(), filepath.Dir(root)); err != nil {
				t.Skipf("symlink unavailable: %v", err)
			}
		},
		"malformed first prefix": func(t *testing.T, _ *Store, root string) {
			if err := os.MkdirAll(filepath.Join(root, "GG"), 0o700); err != nil {
				t.Fatal(err)
			}
		},
		"symlink first prefix": func(t *testing.T, _ *Store, root string) {
			if err := os.MkdirAll(root, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(t.TempDir(), filepath.Join(root, "00")); err != nil {
				t.Skipf("symlink unavailable: %v", err)
			}
		},
		"malformed second prefix": func(t *testing.T, _ *Store, root string) {
			if err := os.MkdirAll(filepath.Join(root, "00", "x"), 0o700); err != nil {
				t.Fatal(err)
			}
		},
		"malformed object": func(t *testing.T, _ *Store, root string) {
			directory := filepath.Join(root, "00", "00")
			if err := os.MkdirAll(directory, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(directory, "short"), nil, 0o600); err != nil {
				t.Fatal(err)
			}
		},
		"object in wrong prefix": func(t *testing.T, _ *Store, root string) {
			directory := filepath.Join(root, "00", "00")
			if err := os.MkdirAll(directory, 0o700); err != nil {
				t.Fatal(err)
			}
			name := "0001" + strings.Repeat("0", 60)
			if err := os.WriteFile(filepath.Join(directory, name), nil, 0o600); err != nil {
				t.Fatal(err)
			}
		},
		"object directory": func(t *testing.T, _ *Store, root string) {
			if err := os.MkdirAll(filepath.Join(root, "00", "00", strings.Repeat("0", 64)), 0o700); err != nil {
				t.Fatal(err)
			}
		},
		"object symlink": func(t *testing.T, _ *Store, root string) {
			directory := filepath.Join(root, "00", "00")
			if err := os.MkdirAll(directory, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(filepath.Join(t.TempDir(), "target"), filepath.Join(directory, strings.Repeat("0", 64))); err != nil {
				t.Skipf("symlink unavailable: %v", err)
			}
		},
		"temporary directory": func(t *testing.T, _ *Store, root string) {
			if err := os.MkdirAll(filepath.Join(root, "00", "00", tempPrefix+"staged"), 0o700); err != nil {
				t.Fatal(err)
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			store := openTestStore(t, filepath.Join(t.TempDir(), "content"))
			root := filepath.Join(store.root, layoutVersion, "blobs")
			mutate(t, store, root)
			if _, err := store.ListBlobs(context.Background(), content.PageRequest{}); !errors.Is(err, content.ErrCorrupt) {
				t.Fatalf("malformed inventory = %v", err)
			}
		})
	}
	t.Run("temporary objects are not published", func(t *testing.T) {
		store := openTestStore(t, filepath.Join(t.TempDir(), "content"))
		directory := filepath.Join(store.root, layoutVersion, "blobs", "00", "00")
		if err := os.MkdirAll(directory, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(directory, tempPrefix+"abandoned"), []byte("staged"), 0o600); err != nil {
			t.Fatal(err)
		}
		page, err := store.ListBlobs(context.Background(), content.PageRequest{})
		if err != nil || len(page.Items) != 0 {
			t.Fatalf("temporary inventory = %#v, %v", page, err)
		}
	})
	t.Run("closed store", func(t *testing.T) {
		store := openTestStore(t, filepath.Join(t.TempDir(), "content"))
		if err := store.Close(); err != nil {
			t.Fatal(err)
		}
		if _, err := store.ListBlobs(context.Background(), content.PageRequest{}); !errors.Is(err, os.ErrClosed) {
			t.Fatalf("closed inventory = %v", err)
		}
	})
}

func TestBlobInventoryInternalBoundaries(t *testing.T) {
	ctx := context.Background()
	store := openTestStore(t, filepath.Join(t.TempDir(), "content"))
	if page, err := store.ListBlobs(ctx, content.PageRequest{}); err != nil || len(page.Items) != 0 {
		t.Fatalf("empty inventory = %#v, %v", page, err)
	}
	if _, err := store.ListBlobs(ctx, content.PageRequest{Limit: -1}); !errors.Is(err, content.ErrInvalid) {
		t.Fatalf("invalid limit = %v", err)
	}
	if _, err := store.ListBlobs(ctx, content.PageRequest{Cursor: "bad"}); !errors.Is(err, content.ErrInvalid) {
		t.Fatalf("invalid cursor = %v", err)
	}
	if _, err := readInventoryPrefixes(ctx, filepath.Join(t.TempDir(), "missing")); !errors.Is(err, content.ErrUnavailable) {
		t.Fatalf("missing prefix directory = %v", err)
	}
	if blobs, err := store.readBlobCandidates(ctx, "unused", "0000", "", false, 0); err != nil || blobs != nil {
		t.Fatalf("zero-capacity candidates = %#v, %v", blobs, err)
	}
	if _, err := store.readBlobCandidates(ctx, filepath.Join(t.TempDir(), "missing"), "0000", "", false, 1); !errors.Is(err, content.ErrUnavailable) {
		t.Fatalf("missing candidate directory = %v", err)
	}

	root := filepath.Join(store.root, layoutVersion, "blobs")
	for _, digest := range []string{
		"0000" + strings.Repeat("0", 60),
		"0001" + strings.Repeat("0", 60),
		"0100" + strings.Repeat("0", 60),
	} {
		sum, err := parseDigest(digest)
		if err != nil {
			t.Fatal(err)
		}
		objectPath := store.objectPath(sum)
		if err = os.MkdirAll(filepath.Dir(objectPath), 0o700); err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(objectPath, nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if page, err := store.ListBlobs(ctx, content.PageRequest{Cursor: "0001" + strings.Repeat("0", 60)}); err != nil || len(page.Items) != 1 {
		t.Fatalf("second-prefix cursor = %#v, %v", page, err)
	}
	if page, err := store.ListBlobs(ctx, content.PageRequest{Cursor: "0100" + strings.Repeat("0", 60)}); err != nil || len(page.Items) != 0 {
		t.Fatalf("first-prefix cursor = %#v, %v", page, err)
	}
	if _, err := readInventoryPrefixes(&errAfterContext{remaining: 0}, root); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled prefix scan = %v", err)
	}
	objectRoot := filepath.Join(root, "00", "00")
	if _, err := store.readBlobCandidates(&errAfterContext{remaining: 0}, objectRoot, "0000", "", false, 1); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled candidate scan = %v", err)
	}
	page := content.BlobPage{}
	if err := store.walkBlobPage(&errAfterContext{remaining: 3}, root, "", false, 10, &page); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled inventory walk = %v", err)
	}

	candidates := candidateMaxHeap{
		{name: "00", size: 0},
		{name: "01", size: 1},
	}
	heap.Init(&candidates)
	heap.Push(&candidates, blobCandidate{name: "02", size: 2})
	if popped := heap.Pop(&candidates).(blobCandidate); popped.name != "02" { //nolint:forcetypeassert // Internal heap contract.
		t.Fatalf("candidate heap popped %#v", popped)
	}
}

func TestPublicationFailureRecovery(t *testing.T) {
	ctx := context.Background()
	for _, stage := range []string{"after-temp-sync", "after-publish", "after-durable"} {
		t.Run(stage, func(t *testing.T) {
			store := openTestStore(t, filepath.Join(t.TempDir(), "content"))
			body := []byte("failure at " + stage)
			blob := content.Blob{SHA256: sha256.Sum256(body), Size: int64(len(body))}
			sentinel := errors.New("injected publication failure")
			store.testHook = func(current string) error {
				if current == stage {
					return sentinel
				}
				return nil
			}
			if _, err := store.Put(ctx, blob, bytes.NewReader(body)); !errors.Is(err, sentinel) {
				t.Fatalf("injected failure = %v", err)
			}
			_, found, err := store.Head(ctx, blob.SHA256)
			if err != nil {
				t.Fatal(err)
			}
			published := stage != "after-temp-sync"
			if found != published {
				t.Fatalf("published = %v, want %v", found, published)
			}
			store.testHook = nil
			inserted, err := store.Put(ctx, blob, bytes.NewReader(body))
			if err != nil || inserted == published {
				t.Fatalf("retry = %v, %v", inserted, err)
			}
			assertNoTemporaryFiles(t, store.root)
		})
	}

	t.Run("directory sync after link", func(t *testing.T) {
		store := openTestStore(t, filepath.Join(t.TempDir(), "content"))
		body := []byte("directory sync recovery")
		blob := content.Blob{SHA256: sha256.Sum256(body), Size: int64(len(body))}
		sentinel := errors.New("injected directory sync failure")
		originalLink := store.ops.link
		originalSync := store.ops.syncDirectory
		armed := false
		store.ops.link = func(oldPath, newPath string) error {
			err := originalLink(oldPath, newPath)
			if err == nil {
				armed = true
			}
			return err
		}
		store.ops.syncDirectory = func(path string) error {
			if armed {
				armed = false
				return sentinel
			}
			return originalSync(path)
		}
		if _, err := store.Put(ctx, blob, bytes.NewReader(body)); !errors.Is(err, content.ErrUnavailable) {
			t.Fatalf("sync failure = %v", err)
		}
		if _, found, err := store.Head(ctx, blob.SHA256); err != nil || !found {
			t.Fatalf("published object = %v, %v", found, err)
		}
		store.ops.link = originalLink
		store.ops.syncDirectory = originalSync
		if inserted, err := store.Put(ctx, blob, bytes.NewReader(body)); err != nil || inserted {
			t.Fatalf("sync repair = %v, %v", inserted, err)
		}
	})

	t.Run("existing publication sync", func(t *testing.T) {
		store := openTestStore(t, filepath.Join(t.TempDir(), "content"))
		body := []byte("existing directory sync recovery")
		blob := content.Blob{SHA256: sha256.Sum256(body), Size: int64(len(body))}
		if _, err := store.Put(ctx, blob, bytes.NewReader(body)); err != nil {
			t.Fatal(err)
		}
		sentinel := errors.New("existing publication sync failure")
		originalLink := store.ops.link
		originalSync := store.ops.syncDirectory
		armed := false
		store.ops.link = func(oldPath, newPath string) error {
			err := originalLink(oldPath, newPath)
			if errors.Is(err, os.ErrExist) {
				armed = true
			}
			return err
		}
		store.ops.syncDirectory = func(path string) error {
			if armed {
				armed = false
				return sentinel
			}
			return originalSync(path)
		}
		if _, err := store.Put(ctx, blob, bytes.NewReader(body)); !errors.Is(err, content.ErrUnavailable) {
			t.Fatalf("sync failure = %v", err)
		}
		store.ops.link = originalLink
		store.ops.syncDirectory = originalSync
		store.testHook = func(stage string) error {
			if stage == "after-durable" {
				return sentinel
			}
			return nil
		}
		if _, err := store.Put(ctx, blob, bytes.NewReader(body)); !errors.Is(err, sentinel) {
			t.Fatalf("post-durability failure = %v", err)
		}
	})
}

func TestFilesystemOperationFailures(t *testing.T) {
	ctx := context.Background()
	sentinel := errors.New("injected filesystem operation failure")
	fixture := func(t *testing.T) (*Store, content.Blob, []byte) {
		t.Helper()
		store := openTestStore(t, filepath.Join(t.TempDir(), "content"))
		body := []byte("filesystem operation failure")
		return store, content.Blob{SHA256: sha256.Sum256(body), Size: int64(len(body))}, body
	}
	t.Run("input validation", func(t *testing.T) {
		store, blob, body := fixture(t)
		if _, err := store.Put(nil, blob, bytes.NewReader(body)); !errors.Is(err, content.ErrInvalid) { //nolint:staticcheck // Verify that the API rejects a nil context.
			t.Fatalf("nil context = %v", err)
		}
		canceled, cancel := context.WithCancel(ctx)
		cancel()
		if _, err := store.Open(canceled, blob, nil); !errors.Is(err, context.Canceled) {
			t.Fatalf("canceled context = %v", err)
		}
		if _, err := store.Put(ctx, content.Blob{Size: -1}, bytes.NewReader(nil)); !errors.Is(err, content.ErrInvalid) {
			t.Fatalf("invalid blob = %v", err)
		}
		if _, err := store.Put(ctx, blob, nil); !errors.Is(err, content.ErrInvalid) {
			t.Fatalf("nil body = %v", err)
		}
		if _, err := store.Open(ctx, blob, nil); !errors.Is(err, content.ErrNotFound) {
			t.Fatalf("missing open = %v", err)
		}
	})

	t.Run("create temporary", func(t *testing.T) {
		store, blob, body := fixture(t)
		store.ops.createTemp = func(string, string) (*os.File, error) { return nil, sentinel }
		if _, err := store.Put(ctx, blob, bytes.NewReader(body)); !errors.Is(err, content.ErrUnavailable) {
			t.Fatalf("error = %v", err)
		}
	})
	t.Run("chmod temporary", func(t *testing.T) {
		store, blob, body := fixture(t)
		store.ops.chmod = func(*os.File, os.FileMode) error { return sentinel }
		if _, err := store.Put(ctx, blob, bytes.NewReader(body)); !errors.Is(err, content.ErrUnavailable) {
			t.Fatalf("error = %v", err)
		}
		assertNoTemporaryFiles(t, store.root)
	})
	t.Run("sync temporary", func(t *testing.T) {
		store, blob, body := fixture(t)
		store.ops.sync = func(*os.File) error { return sentinel }
		if _, err := store.Put(ctx, blob, bytes.NewReader(body)); !errors.Is(err, content.ErrUnavailable) {
			t.Fatalf("error = %v", err)
		}
		assertNoTemporaryFiles(t, store.root)
	})
	t.Run("close temporary", func(t *testing.T) {
		store, blob, body := fixture(t)
		store.ops.close = func(file *os.File) error {
			_ = file.Close()
			return sentinel
		}
		if _, err := store.Put(ctx, blob, bytes.NewReader(body)); !errors.Is(err, content.ErrUnavailable) {
			t.Fatalf("error = %v", err)
		}
		assertNoTemporaryFiles(t, store.root)
	})
	t.Run("publish link", func(t *testing.T) {
		store, blob, body := fixture(t)
		store.ops.link = func(string, string) error { return sentinel }
		if _, err := store.Put(ctx, blob, bytes.NewReader(body)); !errors.Is(err, content.ErrUnavailable) {
			t.Fatalf("error = %v", err)
		}
	})
	t.Run("existing inspection", func(t *testing.T) {
		store, blob, body := fixture(t)
		if _, err := store.Put(ctx, blob, bytes.NewReader(body)); err != nil {
			t.Fatal(err)
		}
		store.ops.safeInfo = func(string, string) (os.FileInfo, error) { return nil, sentinel }
		if _, err := store.Put(ctx, blob, bytes.NewReader(body)); !errors.Is(err, sentinel) || !errors.Is(err, content.ErrUnavailable) {
			t.Fatalf("error = %v", err)
		}
		if _, _, err := store.Head(ctx, blob.SHA256); !errors.Is(err, sentinel) || !errors.Is(err, content.ErrUnavailable) {
			t.Fatalf("head error = %v", err)
		}
		if _, err := store.Open(ctx, blob, nil); !errors.Is(err, sentinel) || !errors.Is(err, content.ErrUnavailable) {
			t.Fatalf("open error = %v", err)
		}
	})
	t.Run("existing comparison", func(t *testing.T) {
		store, blob, body := fixture(t)
		if _, err := store.Put(ctx, blob, bytes.NewReader(body)); err != nil {
			t.Fatal(err)
		}
		store.ops.compare = func(context.Context, string, string, int64) (bool, error) { return false, sentinel }
		if _, err := store.Put(ctx, blob, bytes.NewReader(body)); !errors.Is(err, sentinel) || !errors.Is(err, content.ErrUnavailable) {
			t.Fatalf("error = %v", err)
		}
	})
	t.Run("open object", func(t *testing.T) {
		store, blob, body := fixture(t)
		if _, err := store.Put(ctx, blob, bytes.NewReader(body)); err != nil {
			t.Fatal(err)
		}
		store.ops.open = func(string) (*os.File, error) { return nil, sentinel }
		if _, err := store.Open(ctx, blob, nil); !errors.Is(err, content.ErrUnavailable) {
			t.Fatalf("error = %v", err)
		}
	})
	t.Run("missing during open", func(t *testing.T) {
		store, blob, body := fixture(t)
		if _, err := store.Put(ctx, blob, bytes.NewReader(body)); err != nil {
			t.Fatal(err)
		}
		store.ops.open = func(string) (*os.File, error) { return nil, os.ErrNotExist }
		if _, err := store.Open(ctx, blob, nil); !errors.Is(err, content.ErrNotFound) {
			t.Fatalf("error = %v", err)
		}
	})
	t.Run("source read", func(t *testing.T) {
		store, blob, _ := fixture(t)
		if _, err := store.Put(ctx, blob, failingSource{err: sentinel}); !errors.Is(err, sentinel) {
			t.Fatalf("error = %v", err)
		}
		assertNoTemporaryFiles(t, store.root)
	})
	t.Run("path replaced before publication", func(t *testing.T) {
		store, blob, body := fixture(t)
		directory := filepath.Dir(store.objectPath(blob.SHA256))
		moved := directory + "-moved"
		target := t.TempDir()
		store.testHook = func(stage string) error {
			if stage != "after-temp-sync" {
				return nil
			}
			if err := os.Rename(directory, moved); err != nil {
				return err
			}
			return os.Symlink(target, directory)
		}
		if _, err := store.Put(ctx, blob, bytes.NewReader(body)); !errors.Is(err, content.ErrCorrupt) {
			t.Fatalf("replaced path = %v", err)
		}
		entries, err := os.ReadDir(target)
		if err != nil || len(entries) != 0 {
			t.Fatalf("replacement target entries = %d, %v", len(entries), err)
		}
	})
}

func TestNoPartialVisibilityAndCloseWaitsForUpload(t *testing.T) {
	store := openTestStore(t, filepath.Join(t.TempDir(), "content"))
	body := []byte("blocked publication")
	blob := content.Blob{SHA256: sha256.Sum256(body), Size: int64(len(body))}
	source := &blockedSource{body: body, started: make(chan struct{}), release: make(chan struct{})}
	putResult := make(chan error, 1)
	go func() {
		_, err := store.Put(context.Background(), blob, source)
		putResult <- err
	}()
	select {
	case <-source.started:
	case <-time.After(time.Second):
		t.Fatal("upload did not block")
	}
	if _, found, err := store.Head(context.Background(), blob.SHA256); err != nil || found {
		t.Fatalf("partial head = %v, %v", found, err)
	}
	closeResult := make(chan error, 1)
	go func() { closeResult <- store.Close() }()
	select {
	case err := <-closeResult:
		t.Fatalf("close returned during upload: %v", err)
	case <-time.After(25 * time.Millisecond):
	}
	close(source.release)
	if err := <-putResult; err != nil {
		t.Fatal(err)
	}
	if err := <-closeResult; err != nil {
		t.Fatal(err)
	}
}

func TestCancellationBeforePublicationCommit(t *testing.T) {
	store := openTestStore(t, filepath.Join(t.TempDir(), "content"))
	body := []byte("cancel before immutable link")
	blob := content.Blob{SHA256: sha256.Sum256(body), Size: int64(len(body))}
	ctx, cancel := context.WithCancel(context.Background())
	originalSync := store.ops.sync
	started, release := make(chan struct{}), make(chan struct{})
	store.ops.sync = func(file *os.File) error {
		close(started)
		<-release
		return originalSync(file)
	}
	result := make(chan error, 1)
	go func() {
		_, err := store.Put(ctx, blob, bytes.NewReader(body))
		result <- err
	}()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("temporary sync did not start")
	}
	cancel()
	close(release)
	if err := <-result; !errors.Is(err, context.Canceled) {
		t.Fatalf("put result = %v", err)
	}
	if _, found, err := store.Head(context.Background(), blob.SHA256); err != nil || found {
		t.Fatalf("object after canceled commit = %v, %v", found, err)
	}
	assertNoTemporaryFiles(t, store.root)
}

func TestMissingRootIsBackendFailure(t *testing.T) {
	root := filepath.Join(t.TempDir(), "content")
	store := openTestStore(t, root)
	body := []byte("missing root")
	blob := content.Blob{SHA256: sha256.Sum256(body), Size: int64(len(body))}
	if err := os.RemoveAll(root); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.Head(context.Background(), blob.SHA256); !errors.Is(err, content.ErrUnavailable) {
		t.Fatalf("head = %v", err)
	}
	if _, err := store.Open(context.Background(), blob, nil); !errors.Is(err, content.ErrUnavailable) {
		t.Fatalf("open = %v", err)
	}
	if _, err := store.Put(context.Background(), blob, bytes.NewReader(body)); !errors.Is(err, content.ErrUnavailable) {
		t.Fatalf("put = %v", err)
	}
	if _, err := os.Lstat(root); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("put recreated missing root: %v", err)
	}
}

func TestFilesystemHelpersAndErrorClassification(t *testing.T) {
	root := filepath.Join(t.TempDir(), "content")
	store := openTestStore(t, root)
	ctx := context.Background()

	left := filepath.Join(t.TempDir(), "left")
	right := filepath.Join(t.TempDir(), "right")
	large := bytes.Repeat([]byte{'a'}, 64*1024)
	if err := os.WriteFile(left, large, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(right, large, 0o600); err != nil {
		t.Fatal(err)
	}
	if equal, err := compareFiles(ctx, left, right, int64(len(large))); err != nil || !equal {
		t.Fatalf("equal files = %v, %v", equal, err)
	}
	if err := os.WriteFile(right, bytes.Repeat([]byte{'b'}, len(large)), 0o600); err != nil {
		t.Fatal(err)
	}
	if equal, err := compareFiles(ctx, left, right, int64(len(large))); err != nil || equal {
		t.Fatalf("different files = %v, %v", equal, err)
	}
	if equal, err := compareFiles(ctx, left, right, int64(len(large)+1)); err != nil || equal {
		t.Fatalf("wrong expected size = %v, %v", equal, err)
	}
	if _, err := compareFiles(ctx, filepath.Join(t.TempDir(), "missing"), right, 1); !errors.Is(err, content.ErrUnavailable) {
		t.Fatalf("missing left = %v", err)
	}
	if _, err := compareFiles(ctx, left, filepath.Join(t.TempDir(), "missing"), 1); !errors.Is(err, content.ErrUnavailable) {
		t.Fatalf("missing right = %v", err)
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := compareFiles(canceled, left, right, int64(len(large))); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled comparison = %v", err)
	}

	if err := validateObjectPath(root, filepath.Dir(root)); !errors.Is(err, content.ErrInvalid) {
		t.Fatalf("outside path = %v", err)
	}
	if err := validateObjectPath(root, filepath.Join(root, "missing")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing path = %v", err)
	}
	if err := validateDirectoryChain(filepath.Join(root, "missing")); !errors.Is(err, content.ErrUnavailable) {
		t.Fatalf("missing directory chain = %v", err)
	}
	directoryObject := filepath.Join(root, "directory-object")
	if err := os.Mkdir(directoryObject, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := safeObjectInfo(root, directoryObject); !errors.Is(err, content.ErrCorrupt) {
		t.Fatalf("directory object = %v", err)
	}
	if _, err := safeObjectInfo(root, filepath.Join(root, "missing")); !errors.Is(err, content.ErrNotFound) {
		t.Fatalf("missing object = %v", err)
	}
	var synced []string
	store.ops.syncDirectory = func(path string) error {
		synced = append(synced, path)
		return nil
	}
	volumeRoot := filepath.VolumeName(root) + string(filepath.Separator)
	if err := store.syncToAncestor(root, volumeRoot); err != nil {
		t.Fatal(err)
	}
	expected := root
	for index, path := range synced {
		if path != expected {
			t.Fatalf("sync path %d = %q, want %q", index, path, expected)
		}
		if expected == volumeRoot {
			expected = ""
			break
		}
		expected = filepath.Dir(expected)
	}
	if expected != "" {
		t.Fatalf("sync hierarchy stopped before volume root: next %q", expected)
	}
	store.ops.syncDirectory = func(string) error { return nil }
	if err := store.syncToAncestor(root, filepath.Join(t.TempDir(), "not-an-ancestor")); !errors.Is(err, content.ErrInvalid) {
		t.Fatalf("invalid sync ancestor = %v", err)
	}
	if err := syncDirectory(filepath.Join(root, "missing")); err == nil {
		t.Fatal("syncing missing directory succeeded")
	}
	if err := classifyDirectorySyncError(syscall.EINVAL); !errors.Is(err, content.ErrDurabilityUnsupported) {
		t.Fatalf("unsupported directory sync = %v", err)
	}
	sentinel := errors.New("directory sync I/O failure")
	if err := classifyDirectorySyncError(sentinel); !errors.Is(err, content.ErrUnavailable) || !errors.Is(err, sentinel) {
		t.Fatalf("failed directory sync = %v", err)
	}
	if !equal([]byte{1}, []byte{1}) || equal([]byte{1}, []byte{1, 2}) {
		t.Fatal("byte equality helper is inconsistent")
	}
	if _, err := validateOrFindAncestor(string([]byte{'\x00'})); !errors.Is(err, content.ErrUnavailable) {
		t.Fatalf("invalid ancestor path = %v", err)
	}
	broken := &Store{root: "/proc", ops: defaultOperations()}
	if err := broken.makeObjectDirectory(filepath.Join("/proc", "xet-go-content-test", "objects")); !errors.Is(err, content.ErrUnavailable) {
		t.Fatalf("unwritable object directory = %v", err)
	}
}

func openTestStore(t *testing.T, root string) *Store {
	t.Helper()
	store, err := Open(root)
	if errors.Is(err, content.ErrDurabilityUnsupported) {
		t.Skipf("strict filesystem durability unavailable: %v", err)
	}
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return store
}

func assertNoTemporaryFiles(t *testing.T, root string) {
	t.Helper()
	err := filepath.WalkDir(root, func(_ string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !entry.IsDir() && len(entry.Name()) >= len(tempPrefix) && entry.Name()[:len(tempPrefix)] == tempPrefix {
			t.Errorf("temporary file retained: %s", entry.Name())
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

type blockedSource struct {
	body    []byte
	started chan struct{}
	release chan struct{}
	once    sync.Once
}

func (source *blockedSource) Read(buffer []byte) (int, error) {
	source.once.Do(func() {
		close(source.started)
		<-source.release
	})
	if len(source.body) == 0 {
		return 0, io.EOF
	}
	n := copy(buffer, source.body)
	source.body = source.body[n:]
	return n, nil
}

type failingSource struct{ err error }

func (source failingSource) Read([]byte) (int, error) { return 0, source.err }

type errAfterContext struct{ remaining int }

func (*errAfterContext) Deadline() (time.Time, bool) { return time.Time{}, false }
func (*errAfterContext) Done() <-chan struct{}       { return nil }
func (*errAfterContext) Value(any) any               { return nil }
func (ctx *errAfterContext) Err() error {
	if ctx.remaining > 0 {
		ctx.remaining--
		return nil
	}
	return context.Canceled
}
