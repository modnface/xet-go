//go:build !linux && !darwin

package server

type filesystemRootLock struct{}

func checkFilesystemDurabilitySupported() error { return ErrDurabilityUnsupported }

func acquireFilesystemRootLock(string) (*filesystemRootLock, error) {
	return nil, ErrDurabilityUnsupported
}

func (*filesystemRootLock) Close() error { return nil }

func syncDirectory(string) error { return ErrDurabilityUnsupported }
