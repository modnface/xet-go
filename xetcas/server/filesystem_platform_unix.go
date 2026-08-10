//go:build linux || darwin

package server

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

func checkFilesystemDurabilitySupported() error { return nil }

type filesystemRootLock struct{ file *os.File }

func acquireFilesystemRootLock(root string) (*filesystemRootLock, error) {
	path := filepath.Join(root, filesystemLockName)
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return nil, fmt.Errorf("xet CAS server: filesystem lock is not a regular file")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("xet CAS server: inspect filesystem lock: %w", err)
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("xet CAS server: open filesystem lock: %w", err)
	}
	if err := file.Chmod(0o600); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("xet CAS server: protect filesystem lock: %w", err)
	}
	if err := unix.Flock(int(file.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		_ = file.Close()
		if errors.Is(err, unix.EWOULDBLOCK) || errors.Is(err, unix.EAGAIN) {
			return nil, fmt.Errorf("%w: filesystem blob root is already open", ErrConflict)
		}
		return nil, fmt.Errorf("xet CAS server: lock filesystem blob root: %w", err)
	}
	if err := syncDirectory(root); err != nil {
		_ = unix.Flock(int(file.Fd()), unix.LOCK_UN)
		_ = file.Close()
		return nil, fmt.Errorf("xet CAS server: sync filesystem lock: %w", err)
	}
	return &filesystemRootLock{file: file}, nil
}

func (l *filesystemRootLock) Close() error {
	unlockErr := unix.Flock(int(l.file.Fd()), unix.LOCK_UN)
	closeErr := l.file.Close()
	return errors.Join(unlockErr, closeErr)
}

func syncDirectory(path string) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	return errors.Join(file.Sync(), file.Close())
}
