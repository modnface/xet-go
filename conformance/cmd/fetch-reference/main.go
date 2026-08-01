// Command fetch-reference downloads and verifies the pinned official Xet
// protocol reference corpus without requiring Git LFS.
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type manifest struct {
	SchemaVersion int            `json:"schema_version"`
	Repository    string         `json:"repository"`
	Revision      string         `json:"revision"`
	Files         []manifestFile `json:"files"`
}

type manifestFile struct {
	Name   string `json:"name"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

func main() {
	os.Exit(command(os.Args[1:], os.Stderr))
}

func command(args []string, stderr io.Writer) int {
	flags := flag.NewFlagSet("fetch-reference", flag.ContinueOnError)
	flags.SetOutput(stderr)
	manifestPath := flags.String("manifest", "conformance/reference-manifest.json", "fixture manifest path")
	destination := flags.String("destination", ".cache/xet-spec-reference-files", "download directory")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if err := run(*manifestPath, *destination); err != nil {
		_, _ = fmt.Fprintln(stderr, "fetch-reference:", err)
		return 1
	}
	return 0
}

func run(manifestPath, destination string) error {
	data, err := os.ReadFile(manifestPath)
	if err != nil {
		return err
	}
	var m manifest
	if err := json.Unmarshal(data, &m); err != nil {
		return fmt.Errorf("decode manifest: %w", err)
	}
	if m.SchemaVersion != 1 || m.Repository == "" || len(m.Revision) != 40 || len(m.Files) == 0 {
		return errors.New("invalid manifest metadata")
	}
	if err := os.MkdirAll(destination, 0o755); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()
	client := &http.Client{Timeout: 30 * time.Minute}
	for _, file := range m.Files {
		if err := validateEntry(file); err != nil {
			return err
		}
		target := filepath.Join(destination, file.Name)
		if filepath.Dir(target) != filepath.Clean(destination) {
			return fmt.Errorf("unsafe manifest path %q", file.Name)
		}
		if ok, err := matches(target, file); err != nil {
			return err
		} else if ok {
			fmt.Printf("verified %s\n", file.Name)
			continue
		}
		if err := fetch(ctx, client, m, file, target); err != nil {
			return err
		}
		fmt.Printf("downloaded and verified %s\n", file.Name)
	}
	return nil
}

func validateEntry(file manifestFile) error {
	if file.Name == "" || file.Name != filepath.Base(file.Name) || file.Size < 0 {
		return fmt.Errorf("invalid manifest entry %q", file.Name)
	}
	digest, err := hex.DecodeString(file.SHA256)
	if err != nil || len(digest) != sha256.Size || strings.ToLower(file.SHA256) != file.SHA256 {
		return fmt.Errorf("invalid SHA-256 for %q", file.Name)
	}
	return nil
}

func fetch(ctx context.Context, client *http.Client, m manifest, file manifestFile, target string) (err error) {
	base, err := url.Parse(m.Repository)
	if err != nil {
		return err
	}
	base.Path = strings.TrimSuffix(base.Path, "/") + "/resolve/" + m.Revision + "/" + url.PathEscape(file.Name)
	query := base.Query()
	query.Set("download", "true")
	base.RawQuery = query.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base.String(), nil)
	if err != nil {
		return err
	}
	response, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("download %q: %w", file.Name, err)
	}
	defer func() {
		if closeErr := response.Body.Close(); err == nil {
			err = closeErr
		}
	}()
	if response.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4<<10))
		return fmt.Errorf("download %q: HTTP %s", file.Name, response.Status)
	}
	temporary, err := os.CreateTemp(filepath.Dir(target), ".xet-reference-*")
	if err != nil {
		return err
	}
	temporaryName := temporary.Name()
	defer func() {
		_ = temporary.Close()
		if err != nil {
			_ = os.Remove(temporaryName)
		}
	}()
	hash := sha256.New()
	written, err := io.Copy(io.MultiWriter(temporary, hash), io.LimitReader(response.Body, file.Size+1))
	if err != nil {
		return fmt.Errorf("download %q: %w", file.Name, err)
	}
	if written != file.Size || hex.EncodeToString(hash.Sum(nil)) != file.SHA256 {
		return fmt.Errorf("download %q failed integrity check (size %d, SHA-256 %x)", file.Name, written, hash.Sum(nil))
	}
	if err := temporary.Sync(); err != nil {
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Chmod(temporaryName, 0o644); err != nil {
		return err
	}
	if err := os.Rename(temporaryName, target); err != nil {
		return err
	}
	return nil
}

func matches(path string, file manifestFile) (bool, error) {
	input, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	defer func() { _ = input.Close() }()
	info, err := input.Stat()
	if err != nil {
		return false, err
	}
	if !info.Mode().IsRegular() || info.Size() != file.Size {
		return false, nil
	}
	hash := sha256.New()
	if _, err := io.Copy(hash, input); err != nil {
		return false, err
	}
	return hex.EncodeToString(hash.Sum(nil)) == file.SHA256, nil
}
