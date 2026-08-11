//go:build linux || darwin

package filesystem

import (
	"errors"
	"fmt"
	"os"
	"syscall"

	"github.com/jmwoliver/xet-go/content"
)

func checkDurabilitySupported() error { return nil }

func syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	return errors.Join(directory.Sync(), directory.Close())
}

func classifyDirectorySyncError(err error) error {
	if errors.Is(err, syscall.EINVAL) || errors.Is(err, syscall.ENOTSUP) {
		return fmt.Errorf("%w: %v", content.ErrDurabilityUnsupported, err)
	}
	return unavailable(err)
}
