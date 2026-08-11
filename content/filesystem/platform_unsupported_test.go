//go:build !linux && !darwin

package filesystem

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/jmwoliver/xet-go/content"
)

func TestUnsupportedPlatformHasNoFilesystemSideEffects(t *testing.T) {
	root := filepath.Join(t.TempDir(), "missing", "content")
	if _, err := Open(root); !errors.Is(err, content.ErrDurabilityUnsupported) {
		t.Fatalf("open = %v", err)
	}
	if _, err := os.Lstat(filepath.Dir(root)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("open changed root parent: %v", err)
	}
}
