package xet

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/jmwoliver/xet-go/xethash"
)

// UploadJournal records content identities that reached CAS during an
// interrupted upload. Implementations must never persist access tokens or
// signed URLs. A journal hit is only a hint: the engine verifies the Xorb with
// CAS before omitting a replayed upload.
type UploadJournal interface {
	HasXorb(context.Context, xethash.Hash) (bool, error)
	MarkXorb(context.Context, xethash.Hash) error
	Clear(context.Context) error
}

// DiskUploadJournal is a process-safe-enough immutable-entry journal. Each
// Xorb identity is written through a same-directory temporary file and atomic
// rename. Concurrent writers may publish the same identical entry safely.
type DiskUploadJournal struct {
	directory string
}

// NewDiskUploadJournal scopes a journal below root using an opaque operation
// ID. The ID is hashed before use and therefore cannot escape root.
func NewDiskUploadJournal(root, operationID string) (*DiskUploadJournal, error) {
	if strings.TrimSpace(root) == "" {
		return nil, errors.New("xet: empty upload-journal root")
	}
	if strings.TrimSpace(operationID) == "" {
		return nil, errors.New("xet: empty upload-journal operation ID")
	}
	abs, err := filepath.Abs(root)
	if err != nil {
		return nil, fmt.Errorf("xet: resolve upload-journal root: %w", err)
	}
	scope := sha256.Sum256([]byte(operationID))
	return &DiskUploadJournal{directory: filepath.Join(abs, hex.EncodeToString(scope[:]))}, nil
}

func (j *DiskUploadJournal) HasXorb(ctx context.Context, hash xethash.Hash) (bool, error) {
	if err := validateJournal(j); err != nil {
		return false, err
	}
	if err := ctx.Err(); err != nil {
		return false, err
	}
	path := filepath.Join(j.directory, hash.String()+".xorb")
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("xet: read upload journal: %w", err)
	}
	want := hash.String() + "\n"
	if string(data) != want {
		_ = os.Remove(path)
		return false, nil
	}
	return true, nil
}

func (j *DiskUploadJournal) MarkXorb(ctx context.Context, hash xethash.Hash) error {
	if err := validateJournal(j); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := os.MkdirAll(j.directory, 0o700); err != nil {
		return fmt.Errorf("xet: create upload journal: %w", err)
	}
	path := filepath.Join(j.directory, hash.String()+".xorb")
	if _, err := os.Stat(path); err == nil {
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("xet: inspect upload journal: %w", err)
	}
	temporary, err := os.CreateTemp(j.directory, ".entry-*")
	if err != nil {
		return fmt.Errorf("xet: create upload-journal entry: %w", err)
	}
	temporaryPath := temporary.Name()
	removeTemporary := true
	defer func() {
		_ = temporary.Close()
		if removeTemporary {
			_ = os.Remove(temporaryPath)
		}
	}()
	if err := temporary.Chmod(0o600); err != nil {
		return err
	}
	if _, err := temporary.WriteString(hash.String() + "\n"); err != nil {
		return fmt.Errorf("xet: write upload-journal entry: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		return fmt.Errorf("xet: sync upload-journal entry: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("xet: close upload-journal entry: %w", err)
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		if _, statErr := os.Stat(path); statErr == nil {
			return nil
		}
		return fmt.Errorf("xet: publish upload-journal entry: %w", err)
	}
	removeTemporary = false
	return nil
}

func (j *DiskUploadJournal) Clear(ctx context.Context) error {
	if err := validateJournal(j); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	entries, err := os.ReadDir(j.directory)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("xet: read upload-journal directory: %w", err)
	}
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return err
		}
		if entry.IsDir() {
			return errors.New("xet: upload journal contains an unexpected directory")
		}
		if err := os.Remove(filepath.Join(j.directory, entry.Name())); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("xet: remove upload-journal entry: %w", err)
		}
	}
	if err := os.Remove(j.directory); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("xet: remove upload-journal directory: %w", err)
	}
	return nil
}

func validateJournal(j *DiskUploadJournal) error {
	if j == nil || j.directory == "" {
		return errors.New("xet: nil or uninitialized upload journal")
	}
	return nil
}
