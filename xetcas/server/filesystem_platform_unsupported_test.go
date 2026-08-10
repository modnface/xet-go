//go:build !linux && !darwin

package server

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestUnsupportedLocalDurabilityHasNoFilesystemSideEffects(t *testing.T) {
	root := filepath.Join(t.TempDir(), "missing", "blobs")
	if _, err := NewFilesystemBlobStore(root); !errors.Is(err, ErrDurabilityUnsupported) {
		t.Fatalf("filesystem constructor error = %v", err)
	}
	if _, err := os.Lstat(filepath.Dir(root)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("filesystem constructor changed root parent: %v", err)
	}

	index := filepath.Join(t.TempDir(), "missing", "index.db")
	if _, err := OpenSQLiteIndexStore(index); !errors.Is(err, ErrDurabilityUnsupported) {
		t.Fatalf("SQLite constructor error = %v", err)
	}
	if _, err := os.Lstat(filepath.Dir(index)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("SQLite constructor changed index parent: %v", err)
	}
}
