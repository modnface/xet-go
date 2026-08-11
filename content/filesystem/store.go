// Package filesystem implements durable immutable ordinary-content storage.
package filesystem

import (
	"bufio"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/jmwoliver/xet-go/content"
	"github.com/jmwoliver/xet-go/content/internal/verified"
)

const (
	layoutVersion = "content-v1"
	tempPrefix    = ".content-tmp-"
)

// Store is a concurrent, immutable content store rooted in a trusted private
// directory. Separate processes may safely publish the same objects. The
// implementation rejects observed symlinks but cannot fence hostile path
// replacement by another identity that can mutate the root concurrently.
type Store struct {
	root     string
	mu       sync.RWMutex
	closed   bool
	ops      operations
	testHook func(string) error
}

type operations struct {
	createTemp    func(string, string) (*os.File, error)
	chmod         func(*os.File, os.FileMode) error
	sync          func(*os.File) error
	close         func(*os.File) error
	link          func(string, string) error
	open          func(string) (*os.File, error)
	safeInfo      func(string, string) (os.FileInfo, error)
	compare       func(context.Context, string, string, int64) (bool, error)
	syncDirectory func(string) error
}

func defaultOperations() operations {
	return operations{
		createTemp:    os.CreateTemp,
		chmod:         func(file *os.File, mode os.FileMode) error { return file.Chmod(mode) },
		sync:          func(file *os.File) error { return file.Sync() },
		close:         func(file *os.File) error { return file.Close() },
		link:          os.Link,
		open:          os.Open,
		safeInfo:      safeObjectInfo,
		compare:       compareFiles,
		syncDirectory: syncDirectory,
	}
}

var _ content.Store = (*Store)(nil)

// Open creates or opens root. Strict directory durability is currently
// supported on Linux and macOS. Existing parent modes are never changed.
func Open(root string) (*Store, error) {
	if root == "" {
		return nil, fmt.Errorf("%w: empty content root", content.ErrInvalid)
	}
	if err := checkDurabilitySupported(); err != nil {
		return nil, err
	}
	abs, err := filepath.Abs(root)
	if err != nil {
		return nil, unavailable(err)
	}
	_, err = validateOrFindAncestor(abs)
	if err != nil {
		return nil, err
	}
	if err = os.MkdirAll(abs, 0o700); err != nil {
		return nil, unavailable(err)
	}
	if err = validateDirectoryChain(abs); err != nil {
		return nil, err
	}
	info, err := os.Stat(abs)
	if err != nil {
		return nil, unavailable(err)
	}
	if info.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("%w: content root permissions grant group or other access", content.ErrInvalid)
	}
	store := &Store{root: abs, ops: defaultOperations()}
	volumeRoot := filepath.VolumeName(abs) + string(filepath.Separator)
	if err = store.syncToAncestor(abs, volumeRoot); err != nil {
		return nil, err
	}
	return store, nil
}

// Close prevents new store operations. Readers returned before Close remain
// usable and retain ownership of their file descriptor.
func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	return nil
}

func (s *Store) begin(ctx context.Context, blob *content.Blob) error {
	if ctx == nil {
		return fmt.Errorf("%w: nil context", content.ErrInvalid)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if blob != nil {
		if err := blob.Validate(); err != nil {
			return err
		}
	}
	s.mu.RLock()
	if s.closed {
		s.mu.RUnlock()
		return os.ErrClosed
	}
	return nil
}

func (s *Store) end() { s.mu.RUnlock() }

func (s *Store) Put(ctx context.Context, blob content.Blob, body io.Reader) (bool, error) {
	if err := s.begin(ctx, &blob); err != nil {
		return false, err
	}
	defer s.end()
	if body == nil {
		return false, fmt.Errorf("%w: nil blob body", content.ErrInvalid)
	}
	path := s.objectPath(blob.SHA256)
	directory := filepath.Dir(path)
	if err := s.makeObjectDirectory(directory); err != nil {
		return false, err
	}
	temporary, err := s.ops.createTemp(directory, tempPrefix)
	if err != nil {
		return false, unavailable(err)
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath) //nolint:errcheck // temporary cleanup is best effort.
	if err = s.ops.chmod(temporary, 0o600); err != nil {
		_ = s.ops.close(temporary)
		return false, unavailable(err)
	}
	if err = verified.Write(ctx, temporary, body, blob); err != nil {
		_ = s.ops.close(temporary)
		return false, err
	}
	if err = s.ops.sync(temporary); err != nil {
		_ = s.ops.close(temporary)
		return false, unavailable(err)
	}
	if err = s.ops.close(temporary); err != nil {
		return false, unavailable(err)
	}
	if s.testHook != nil {
		if err = s.testHook("after-temp-sync"); err != nil {
			return false, err
		}
	}
	if err = validateObjectPath(s.root, directory); err != nil {
		return false, normalizeFilesystemError(err)
	}
	if err = ctx.Err(); err != nil {
		return false, err
	}
	if err = s.ops.link(temporaryPath, path); err == nil {
		if s.testHook != nil {
			if err = s.testHook("after-publish"); err != nil {
				return false, err
			}
		}
		if err = s.syncHierarchy(directory); err != nil {
			return false, err
		}
		if s.testHook != nil {
			if err = s.testHook("after-durable"); err != nil {
				return false, err
			}
		}
		return true, nil
	} else if !errors.Is(err, os.ErrExist) {
		return false, unavailable(err)
	}
	if _, err = s.ops.safeInfo(s.root, path); err != nil {
		return false, normalizeFilesystemError(err)
	}
	equal, err := s.ops.compare(ctx, path, temporaryPath, blob.Size)
	if err != nil {
		return false, normalizeFilesystemError(err)
	}
	if !equal {
		return false, content.ErrConflict
	}
	if err = s.syncHierarchy(directory); err != nil {
		return false, err
	}
	if s.testHook != nil {
		if err = s.testHook("after-durable"); err != nil {
			return false, err
		}
	}
	return false, nil
}

func (s *Store) Head(ctx context.Context, sum [32]byte) (content.Info, bool, error) {
	if err := s.begin(ctx, nil); err != nil {
		return content.Info{}, false, err
	}
	defer s.end()
	info, err := s.ops.safeInfo(s.root, s.objectPath(sum))
	if errors.Is(err, content.ErrNotFound) {
		return content.Info{}, false, nil
	}
	if err != nil {
		return content.Info{}, false, normalizeFilesystemError(err)
	}
	return content.Info{Size: info.Size()}, true, nil
}

func (s *Store) Open(ctx context.Context, blob content.Blob, wanted *content.Range) (io.ReadCloser, error) {
	if err := s.begin(ctx, &blob); err != nil {
		return nil, err
	}
	defer s.end()
	path := s.objectPath(blob.SHA256)
	info, err := s.ops.safeInfo(s.root, path)
	if errors.Is(err, content.ErrNotFound) {
		return nil, content.ErrNotFound
	}
	if err != nil {
		return nil, normalizeFilesystemError(err)
	}
	if info.Size() != blob.Size {
		return nil, fmt.Errorf("%w: retained length %d, expected %d", content.ErrCorrupt, info.Size(), blob.Size)
	}
	file, err := s.ops.open(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, content.ErrNotFound
	}
	if err != nil {
		return nil, unavailable(err)
	}
	start, end := int64(0), blob.Size
	full := wanted == nil
	var body io.ReadCloser = file
	if wanted != nil {
		if err = wanted.Validate(blob.Size); err != nil {
			_ = file.Close()
			return nil, err
		}
		start, end = wanted.Start, wanted.End
		body = &sectionReadCloser{Reader: io.NewSectionReader(file, start, end-start), close: file}
	}
	return verified.New(ctx, body, blob, end-start, full), nil
}

func (s *Store) objectPath(sum [32]byte) string {
	digest := hex.EncodeToString(sum[:])
	return filepath.Join(s.root, layoutVersion, "blobs", digest[:2], digest[2:4], digest)
}

func (s *Store) makeObjectDirectory(directory string) error {
	if err := validateRealDirectory(s.root); err != nil {
		return normalizeFilesystemError(err)
	}
	if err := validateObjectPath(s.root, filepath.Dir(directory)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return normalizeFilesystemError(err)
	}
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return unavailable(err)
	}
	if err := validateObjectPath(s.root, directory); err != nil {
		return normalizeFilesystemError(err)
	}
	return s.syncHierarchy(directory)
}

func (s *Store) syncHierarchy(directory string) error {
	return s.syncToAncestor(directory, s.root)
}

func (s *Store) syncToAncestor(directory, ancestor string) error {
	current := filepath.Clean(directory)
	ancestor = filepath.Clean(ancestor)
	for {
		if err := s.ops.syncDirectory(current); err != nil {
			return classifyDirectorySyncError(err)
		}
		if current == ancestor {
			return nil
		}
		next := filepath.Dir(current)
		if next == current {
			return fmt.Errorf("%w: directory escapes content root", content.ErrInvalid)
		}
		current = next
	}
}

func compareFiles(ctx context.Context, leftPath, rightPath string, size int64) (bool, error) {
	left, err := os.Open(leftPath)
	if err != nil {
		return false, unavailable(err)
	}
	defer left.Close() //nolint:errcheck // read result determines the outcome.
	right, err := os.Open(rightPath)
	if err != nil {
		return false, unavailable(err)
	}
	defer right.Close() //nolint:errcheck // read result determines the outcome.
	leftInfo, err := left.Stat()
	if err != nil {
		return false, unavailable(err)
	}
	rightInfo, err := right.Stat()
	if err != nil {
		return false, unavailable(err)
	}
	if leftInfo.Size() != size || rightInfo.Size() != size {
		return false, nil
	}
	leftReader, rightReader := bufio.NewReader(left), bufio.NewReader(right)
	leftBuffer, rightBuffer := make([]byte, 64*1024), make([]byte, 64*1024)
	for {
		if err = ctx.Err(); err != nil {
			return false, err
		}
		leftCount, leftErr := io.ReadFull(leftReader, leftBuffer)
		rightCount, rightErr := io.ReadFull(rightReader, rightBuffer)
		if leftCount != rightCount || !equal(leftBuffer[:leftCount], rightBuffer[:rightCount]) {
			return false, nil
		}
		if errors.Is(leftErr, io.EOF) || errors.Is(leftErr, io.ErrUnexpectedEOF) {
			if errors.Is(rightErr, io.EOF) || errors.Is(rightErr, io.ErrUnexpectedEOF) {
				return true, nil
			}
			if rightErr != nil {
				return false, unavailable(rightErr)
			}
			return false, nil
		}
		if leftErr != nil {
			return false, unavailable(leftErr)
		}
		if rightErr != nil {
			return false, unavailable(rightErr)
		}
	}
}

func safeObjectInfo(root, path string) (os.FileInfo, error) {
	if err := validateRealDirectory(root); err != nil {
		return nil, normalizeFilesystemError(err)
	}
	if err := validateObjectPath(root, filepath.Dir(path)); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, content.ErrNotFound
		}
		return nil, normalizeFilesystemError(err)
	}
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, content.ErrNotFound
	}
	if err != nil {
		return nil, unavailable(err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%w: content object is not a regular file", content.ErrCorrupt)
	}
	return info, nil
}

func validateObjectPath(root, path string) error {
	root = filepath.Clean(root)
	path = filepath.Clean(path)
	relative, err := filepath.Rel(root, path)
	if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) || filepath.IsAbs(relative) {
		return fmt.Errorf("%w: content path escapes root", content.ErrInvalid)
	}
	current := root
	if err = validateRealDirectory(current); err != nil {
		return err
	}
	if relative == "." {
		return nil
	}
	for _, component := range splitPath(relative) {
		current = filepath.Join(current, component)
		if err = validateRealDirectory(current); err != nil {
			return err
		}
	}
	return nil
}

func validateDirectoryChain(path string) error {
	for current := filepath.Clean(path); ; current = filepath.Dir(current) {
		info, err := os.Lstat(current)
		if err != nil {
			return unavailable(err)
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return fmt.Errorf("%w: content root component is not a real directory", content.ErrInvalid)
		}
		next := filepath.Dir(current)
		if next == current {
			return nil
		}
	}
}

func validateOrFindAncestor(path string) (string, error) {
	for current := filepath.Clean(path); ; current = filepath.Dir(current) {
		info, err := os.Lstat(current)
		if err == nil {
			if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
				return "", fmt.Errorf("%w: content root component is not a real directory", content.ErrInvalid)
			}
			return current, nil
		}
		if !errors.Is(err, os.ErrNotExist) {
			return "", unavailable(err)
		}
		next := filepath.Dir(current)
		if next == current {
			return "", unavailable(err)
		}
	}
}

func validateRealDirectory(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return fmt.Errorf("%w: content path component is not a real directory", content.ErrCorrupt)
	}
	return nil
}

func splitPath(path string) []string {
	var parts []string
	for path != "." && path != string(filepath.Separator) {
		directory, file := filepath.Split(path)
		parts = append([]string{file}, parts...)
		path = filepath.Clean(directory)
	}
	return parts
}

func equal(left, right []byte) bool {
	if len(left) != len(right) {
		return false
	}
	var difference byte
	for index := range left {
		difference |= left[index] ^ right[index]
	}
	return difference == 0
}

func normalizeFilesystemError(err error) error {
	if err == nil || errors.Is(err, content.ErrInvalid) || errors.Is(err, content.ErrNotFound) ||
		errors.Is(err, content.ErrConflict) || errors.Is(err, content.ErrCorrupt) ||
		errors.Is(err, content.ErrRangeNotSatisfiable) || errors.Is(err, content.ErrUnavailable) ||
		errors.Is(err, content.ErrDurabilityUnsupported) || errors.Is(err, context.Canceled) ||
		errors.Is(err, context.DeadlineExceeded) || errors.Is(err, os.ErrClosed) {
		return err
	}
	return unavailable(err)
}

func unavailable(err error) error { return fmt.Errorf("%w: %w", content.ErrUnavailable, err) }

type sectionReadCloser struct {
	io.Reader
	close io.Closer
}

func (reader *sectionReadCloser) Close() error { return reader.close.Close() }
