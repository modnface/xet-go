package server

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/jmwoliver/xet-go/xetcas"
	"github.com/jmwoliver/xet-go/xethash"
)

const (
	filesystemLayoutVersion = "blobs-v1"
	filesystemLockName      = ".xet-store.lock"
	defaultTempGrace        = time.Hour
	tempPrefix              = ".xet-blob-tmp-"
)

// FilesystemBlobStoreOptions controls filesystem store recovery.
type FilesystemBlobStoreOptions struct {
	// TempGracePeriod is the minimum age of an abandoned temporary file before
	// constructor recovery removes it. Zero selects one hour. A negative value
	// disables cleanup.
	TempGracePeriod time.Duration
}

// FilesystemBlobStore is a durable, immutable BlobStore rooted in a private
// directory. It does not defend against an attacker running as the service
// identity, but rejects symlinks encountered in its root and object paths.
type FilesystemBlobStore struct {
	root   string
	mu     sync.RWMutex
	closed bool
	lock   *filesystemRootLock
	ops    filesystemOperations

	// testHook is intentionally unexported; production publication has no
	// callbacks. Tests use it to model a process failure at durability edges.
	testHook func(stage string) error
}

type filesystemOperations struct {
	createTemp    func(string, string) (*os.File, error)
	chmod         func(*os.File, os.FileMode) error
	sync          func(*os.File) error
	close         func(*os.File) error
	link          func(string, string) error
	open          func(string) (*os.File, error)
	safeInfo      func(string, string) (os.FileInfo, error)
	compare       func(context.Context, string, string, int64) (bool, error)
	syncDirectory func(string) error
	syncHierarchy func(string, string) error
}

func defaultFilesystemOperations() filesystemOperations {
	return filesystemOperations{
		createTemp:    os.CreateTemp,
		chmod:         func(file *os.File, mode os.FileMode) error { return file.Chmod(mode) },
		sync:          func(file *os.File) error { return file.Sync() },
		close:         func(file *os.File) error { return file.Close() },
		link:          os.Link,
		open:          os.Open,
		safeInfo:      safeObjectInfo,
		compare:       compareFile,
		syncDirectory: syncDirectory,
		syncHierarchy: syncDirectoryHierarchy,
	}
}

// NewFilesystemBlobStore opens or creates root. At most one options value may
// be supplied. Platforms without strict directory durability return
// ErrDurabilityUnsupported without modifying root.
func NewFilesystemBlobStore(root string, options ...FilesystemBlobStoreOptions) (*FilesystemBlobStore, error) {
	if root == "" || len(options) > 1 {
		return nil, fmt.Errorf("xet CAS server: invalid filesystem blob store options")
	}
	if err := checkFilesystemDurabilitySupported(); err != nil {
		return nil, err
	}
	abs, err := filepath.Abs(root)
	if err != nil {
		return nil, fmt.Errorf("xet CAS server: blob root: %w", err)
	}
	if err := ensurePrivateRoot(abs); err != nil {
		return nil, err
	}
	lock, err := acquireFilesystemRootLock(abs)
	if err != nil {
		return nil, err
	}
	s := &FilesystemBlobStore{root: abs, lock: lock, ops: defaultFilesystemOperations()}
	grace := defaultTempGrace
	if len(options) == 1 && options[0].TempGracePeriod != 0 {
		grace = options[0].TempGracePeriod
	}
	if grace >= 0 {
		if err := s.cleanupTemps(grace); err != nil {
			_ = lock.Close()
			return nil, err
		}
	}
	return s, nil
}

// Close prevents new operations. Already returned readers remain usable.
func (s *FilesystemBlobStore) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	s.mu.Unlock()
	return s.lock.Close()
}

func (s *FilesystemBlobStore) beginOperation() error {
	s.mu.RLock()
	if s.closed {
		s.mu.RUnlock()
		return os.ErrClosed
	}
	return nil
}

func (s *FilesystemBlobStore) endOperation() { s.mu.RUnlock() }

// objectPath is the single definition of the on-disk key layout. Every path
// component after root comes from a validated enum or a hexadecimal hash.
func (s *FilesystemBlobStore) objectPath(key BlobKey) (string, error) {
	kind := string(key.Kind)
	if key.Kind != BlobXorb && key.Kind != BlobShard {
		return "", fmt.Errorf("%w: unsupported blob kind %q", ErrInvalid, key.Kind)
	}
	hash := key.Hash.String()
	return filepath.Join(s.root, filesystemLayoutVersion, kind, hash[:2], hash[2:4], hash), nil
}

func (s *FilesystemBlobStore) PutIfAbsent(ctx context.Context, key BlobKey, body io.Reader, size int64) (bool, error) {
	if err := s.beginOperation(); err != nil {
		return false, err
	}
	defer s.endOperation()
	if body == nil || size < 0 {
		return false, fmt.Errorf("%w: invalid blob body or size", ErrInvalid)
	}
	path, err := s.objectPath(key)
	if err != nil {
		return false, err
	}
	dir := filepath.Dir(path)
	if err := s.makeObjectDir(dir); err != nil {
		return false, err
	}
	f, err := s.ops.createTemp(dir, tempPrefix)
	if err != nil {
		return false, fmt.Errorf("xet CAS server: create blob temporary: %w", err)
	}
	tmp := f.Name()
	defer func() { _ = os.Remove(tmp) }() // best effort, including injected/process-like failures
	if err := s.ops.chmod(f, 0o600); err != nil {
		_ = s.ops.close(f)
		return false, err
	}
	if err := copyExact(ctx, f, body, size); err != nil {
		_ = s.ops.close(f)
		return false, err
	}
	if err := s.ops.sync(f); err != nil {
		_ = s.ops.close(f)
		return false, fmt.Errorf("xet CAS server: sync blob: %w", err)
	}
	if err := s.ops.close(f); err != nil {
		return false, fmt.Errorf("xet CAS server: close blob: %w", err)
	}
	if s.testHook != nil {
		if err := s.testHook("after-temp-sync"); err != nil {
			return false, err
		}
	}
	if err := validateObjectPath(s.root, dir); err != nil {
		return false, err
	}
	if err := s.ops.link(tmp, path); err == nil {
		if s.testHook != nil {
			if err := s.testHook("after-publish"); err != nil {
				return false, err
			}
		}
		if err := s.ops.syncHierarchy(s.root, dir); err != nil {
			// Publication already happened. A retry observes and verifies it.
			return false, fmt.Errorf("xet CAS server: sync blob publication: %w", err)
		}
		if s.testHook != nil {
			if err := s.testHook("after-durable"); err != nil {
				return false, err
			}
		}
		return true, nil
	} else if !errors.Is(err, os.ErrExist) {
		return false, fmt.Errorf("xet CAS server: publish blob: %w", err)
	}
	if _, err := s.ops.safeInfo(s.root, path); err != nil {
		return false, err
	}
	equal, err := s.ops.compare(ctx, path, tmp, size)
	if err != nil {
		return false, err
	}
	if !equal {
		return false, ErrConflict
	}
	// A prior writer may have linked the object but failed before making the
	// directory entry durable. Every successful retry repeats the barrier.
	if err := s.ops.syncHierarchy(s.root, dir); err != nil {
		return false, fmt.Errorf("xet CAS server: sync existing blob publication: %w", err)
	}
	if s.testHook != nil {
		if err := s.testHook("after-durable"); err != nil {
			return false, err
		}
	}
	return false, nil
}

func (s *FilesystemBlobStore) Head(ctx context.Context, key BlobKey) (BlobInfo, bool, error) {
	if err := s.beginOperation(); err != nil {
		return BlobInfo{}, false, err
	}
	defer s.endOperation()
	if err := ctx.Err(); err != nil {
		return BlobInfo{}, false, err
	}
	path, err := s.objectPath(key)
	if err != nil {
		return BlobInfo{}, false, err
	}
	info, err := s.ops.safeInfo(s.root, path)
	if errors.Is(err, os.ErrNotExist) {
		return BlobInfo{}, false, nil
	}
	if err != nil {
		return BlobInfo{}, false, err
	}
	return BlobInfo{Size: info.Size()}, true, nil
}

func (s *FilesystemBlobStore) Get(ctx context.Context, key BlobKey, wanted *xetcas.HTTPRange) (io.ReadCloser, error) {
	if err := s.beginOperation(); err != nil {
		return nil, err
	}
	defer s.endOperation()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	path, err := s.objectPath(key)
	if err != nil {
		return nil, err
	}
	info, err := s.ops.safeInfo(s.root, path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	f, err := s.ops.open(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if wanted == nil {
		return &contextReadCloser{ctx: ctx, Reader: f, close: f}, nil
	}
	if err := wanted.Validate(); err != nil || wanted.End >= uint64(info.Size()) {
		_ = f.Close()
		return nil, xetcas.ErrRangeNotSatisfiable
	}
	section := io.NewSectionReader(f, int64(wanted.Start), int64(wanted.End-wanted.Start+1))
	return &contextReadCloser{ctx: ctx, Reader: section, close: f}, nil
}

func (s *FilesystemBlobStore) ListBlobs(
	ctx context.Context,
	kind BlobKind,
	request PageRequest,
) (BlobPage, error) {
	if err := s.beginOperation(); err != nil {
		return BlobPage{}, err
	}
	defer s.endOperation()
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
	var cursorHash xethash.Hash
	if request.Cursor != "" {
		cursorHash, err = decodeHashCursor(request.Cursor, cursorKind)
		if err != nil {
			return BlobPage{}, err
		}
	}
	cursor := cursorHash.String()
	if err := ctx.Err(); err != nil {
		return BlobPage{}, err
	}
	root := filepath.Join(s.root, filesystemLayoutVersion, string(kind))
	rootInfo, err := os.Lstat(root)
	if errors.Is(err, os.ErrNotExist) {
		return BlobPage{Items: []BlobEntry{}}, nil
	}
	if err != nil {
		return BlobPage{}, err
	}
	if rootInfo.Mode()&os.ModeSymlink != 0 || !rootInfo.IsDir() {
		return BlobPage{}, fmt.Errorf("%w: blob kind root is not a real directory", ErrCorrupt)
	}
	if err := validateObjectPath(s.root, root); err != nil {
		return BlobPage{}, fmt.Errorf("%w: unsafe blob kind path: %v", ErrCorrupt, err)
	}
	page := BlobPage{Items: make([]BlobEntry, 0, limit)}
	err = s.walkBlobPage(ctx, root, kind, cursor, request.Cursor != "", limit, &page)
	if err != nil {
		return BlobPage{}, err
	}
	if len(page.Items) > limit {
		page.Items = page.Items[:limit]
		page.NextCursor = encodeHashCursor(cursorKind, page.Items[len(page.Items)-1].Key.Hash)
	}
	return page, nil
}

func (s *FilesystemBlobStore) walkBlobPage(
	ctx context.Context,
	root string,
	kind BlobKind,
	cursor string,
	hasCursor bool,
	limit int,
	page *BlobPage,
) error {
	firstLevel, err := os.ReadDir(root)
	if err != nil {
		return err
	}
	for _, first := range firstLevel {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := validateBlobPrefix(first); err != nil {
			return err
		}
		if hasCursor && first.Name() < cursor[:2] {
			continue
		}
		firstPath := filepath.Join(root, first.Name())
		secondLevel, err := os.ReadDir(firstPath)
		if err != nil {
			return err
		}
		for _, second := range secondLevel {
			if err := ctx.Err(); err != nil {
				return err
			}
			if err := validateBlobPrefix(second); err != nil {
				return err
			}
			prefix := first.Name() + second.Name()
			if hasCursor && prefix < cursor[:4] {
				continue
			}
			objectRoot := filepath.Join(firstPath, second.Name())
			objects, err := os.ReadDir(objectRoot)
			if err != nil {
				return err
			}
			for _, entry := range objects {
				if err := ctx.Err(); err != nil {
					return err
				}
				if entry.Type()&os.ModeSymlink != 0 {
					return fmt.Errorf("%w: symlink beneath blob kind root", ErrCorrupt)
				}
				if strings.HasPrefix(entry.Name(), tempPrefix) {
					continue
				}
				hash, err := xethash.Parse(entry.Name())
				if err != nil || hash.String() != entry.Name() || entry.Name()[:4] != prefix {
					return fmt.Errorf("%w: malformed blob object name %q", ErrCorrupt, entry.Name())
				}
				if hasCursor && entry.Name() <= cursor {
					continue
				}
				info, err := entry.Info()
				if err != nil {
					return err
				}
				if !info.Mode().IsRegular() {
					return fmt.Errorf("%w: blob object is not a regular file", ErrCorrupt)
				}
				page.Items = append(page.Items, BlobEntry{
					Key:  BlobKey{Kind: kind, Hash: hash},
					Info: BlobInfo{Size: info.Size()},
				})
				if len(page.Items) > limit {
					return nil
				}
			}
		}
	}
	return nil
}

func validateBlobPrefix(entry os.DirEntry) error {
	if entry.Type()&os.ModeSymlink != 0 || !entry.IsDir() {
		return fmt.Errorf("%w: invalid blob prefix path %q", ErrCorrupt, entry.Name())
	}
	name := entry.Name()
	if len(name) != 2 || !isLowerHex(name[0]) || !isLowerHex(name[1]) {
		return fmt.Errorf("%w: malformed blob prefix %q", ErrCorrupt, name)
	}
	return nil
}

func isLowerHex(value byte) bool {
	return value >= '0' && value <= '9' || value >= 'a' && value <= 'f'
}

type contextReadCloser struct {
	ctx context.Context
	io.Reader
	close io.Closer
}

func (r *contextReadCloser) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.Reader.Read(p)
}
func (r *contextReadCloser) Close() error { return r.close.Close() }

func copyExact(ctx context.Context, dst io.Writer, src io.Reader, size int64) error {
	n, err := io.Copy(dst, io.LimitReader(&contextReader{ctx, src}, size+1))
	if err != nil {
		return err
	}
	if n != size {
		return fmt.Errorf("xet CAS server: blob size %d, expected %d", n, size)
	}
	return nil
}

type contextReader struct {
	ctx context.Context
	r   io.Reader
}

func (r *contextReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.r.Read(p)
}

func compareFile(ctx context.Context, a, b string, size int64) (bool, error) {
	af, err := os.Open(a)
	if err != nil {
		return false, err
	}
	defer func() { _ = af.Close() }()
	bf, err := os.Open(b)
	if err != nil {
		return false, err
	}
	defer func() { _ = bf.Close() }()
	ai, err := af.Stat()
	if err != nil || !ai.Mode().IsRegular() || ai.Size() != size {
		return false, err
	}
	ba, bb := make([]byte, 32*1024), make([]byte, 32*1024)
	for {
		if err := ctx.Err(); err != nil {
			return false, err
		}
		na, ea := io.ReadFull(af, ba)
		nb, eb := io.ReadFull(bf, bb)
		if na != nb || !bytes.Equal(ba[:na], bb[:nb]) {
			return false, nil
		}
		if ea == io.EOF || ea == io.ErrUnexpectedEOF {
			return eb == io.EOF || eb == io.ErrUnexpectedEOF, nil
		}
		if ea != nil {
			return false, ea
		}
		if eb != nil {
			return false, eb
		}
	}
}

func ensurePrivateRoot(root string) error {
	if err := ensurePrivateDirectory(root, syncDirectory); err != nil {
		return fmt.Errorf("xet CAS server: prepare blob root: %w", err)
	}
	return nil
}

// ensurePrivateDirectory creates each missing path component separately and
// durably publishes it before creating the next. Existing ancestors are never
// chmodded; only the requested directory and directories created for it become
// private.
func ensurePrivateDirectory(path string, syncDir func(string) error) error {
	return ensurePrivateDirectoryWithOperations(path, privateDirectoryOperations{
		lstat: os.Lstat,
		mkdir: func(path string) error { return os.Mkdir(path, 0o700) },
		chmod: func(path string) error { return os.Chmod(path, 0o700) },
		sync:  syncDir,
	})
}

type privateDirectoryOperations struct {
	lstat func(string) (os.FileInfo, error)
	mkdir func(string) error
	chmod func(string) error
	sync  func(string) error
}

func ensurePrivateDirectoryWithOperations(path string, ops privateDirectoryOperations) error {
	missing := make([]string, 0, 4)
	ancestor := path
	for {
		info, err := ops.lstat(ancestor)
		if err == nil {
			if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
				return fmt.Errorf("path component %q is not a real directory", ancestor)
			}
			break
		}
		if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		missing = append(missing, ancestor)
		parent := filepath.Dir(ancestor)
		if parent == ancestor {
			return fmt.Errorf("no existing directory ancestor for %q", path)
		}
		ancestor = parent
	}
	for i := len(missing) - 1; i >= 0; i-- {
		directory := missing[i]
		if err := ops.mkdir(directory); err != nil && !errors.Is(err, os.ErrExist) {
			return err
		}
		info, err := ops.lstat(directory)
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return fmt.Errorf("path component %q is not a real directory", directory)
		}
		if err := ops.chmod(directory); err != nil {
			return err
		}
		if err := ops.sync(directory); err != nil {
			return fmt.Errorf("sync new directory %q: %w", directory, err)
		}
		if err := ops.sync(filepath.Dir(directory)); err != nil {
			return fmt.Errorf("publish new directory %q: %w", directory, err)
		}
	}
	info, err := ops.lstat(path)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return fmt.Errorf("path %q is not a real directory", path)
	}
	if err := ops.chmod(path); err != nil {
		return err
	}
	if err := ops.sync(path); err != nil {
		return fmt.Errorf("sync directory %q: %w", path, err)
	}
	if err := ops.sync(filepath.Dir(path)); err != nil {
		return fmt.Errorf("sync directory parent %q: %w", path, err)
	}
	return nil
}

func (s *FilesystemBlobStore) makeObjectDir(dir string) error {
	if err := validateObjectPath(s.root, s.root); err != nil {
		return err
	}
	relative, err := filepath.Rel(s.root, dir)
	if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return fmt.Errorf("%w: blob directory traversal", ErrInvalid)
	}
	path := s.root
	for _, component := range strings.Split(relative, string(filepath.Separator)) {
		if component == "." {
			continue
		}
		path = filepath.Join(path, component)
		info, err := os.Lstat(path)
		if errors.Is(err, os.ErrNotExist) {
			if err := os.Mkdir(path, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
				return err
			}
			info, err = os.Lstat(path)
		}
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return fmt.Errorf("xet CAS server: unsafe blob path component")
		}
		if err := os.Chmod(path, 0o700); err != nil {
			return err
		}
	}
	if err := validateObjectPath(s.root, dir); err != nil {
		return err
	}
	return syncDirectoryHierarchy(s.root, dir)
}

func validateObjectPath(root, path string) error {
	rootInfo, err := os.Lstat(root)
	if err != nil {
		return err
	}
	if rootInfo.Mode()&os.ModeSymlink != 0 || !rootInfo.IsDir() {
		return fmt.Errorf("xet CAS server: blob root is not a real directory")
	}
	rel, err := filepath.Rel(root, path)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return fmt.Errorf("%w: blob path traversal", ErrInvalid)
	}
	p := root
	for _, component := range strings.Split(rel, string(filepath.Separator)) {
		if component == "." {
			continue
		}
		p = filepath.Join(p, component)
		info, err := os.Lstat(p)
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return fmt.Errorf("xet CAS server: unsafe blob path component")
		}
	}
	return nil
}

func safeObjectInfo(root, path string) (os.FileInfo, error) {
	if err := validateObjectPath(root, filepath.Dir(path)); err != nil {
		return nil, err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return nil, fmt.Errorf("xet CAS server: blob object is not a regular file")
	}
	return info, nil
}

func syncDirectoryHierarchy(root, leaf string) error {
	if err := validateObjectPath(root, leaf); err != nil {
		return err
	}
	for path := leaf; ; path = filepath.Dir(path) {
		if err := syncDirectory(path); err != nil {
			return err
		}
		if path == root {
			return nil
		}
	}
}

func (s *FilesystemBlobStore) cleanupTemps(grace time.Duration) error {
	cutoff := time.Now().Add(-grace)
	directories := make([]string, 0, 16)
	if err := filepath.Walk(s.root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("xet CAS server: symlink beneath blob root")
		}
		if info.IsDir() {
			directories = append(directories, path)
			return nil
		}
		if info.Mode().IsRegular() && strings.HasPrefix(info.Name(), tempPrefix) && info.ModTime().Before(cutoff) {
			return os.Remove(path)
		}
		return nil
	}); err != nil {
		return err
	}
	// Sync after the complete walk so deletions in a directory happen before
	// its barrier. Sync every visited directory, not only directories changed in
	// this invocation: a retry must repair a prior failed deletion barrier after
	// the in-memory namespace has already forgotten the temporary name.
	sort.Slice(directories, func(i, j int) bool { return len(directories[i]) > len(directories[j]) })
	for _, directory := range directories {
		if err := s.ops.syncDirectory(directory); err != nil {
			return fmt.Errorf("xet CAS server: sync temporary cleanup: %w", err)
		}
	}
	return nil
}
