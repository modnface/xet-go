package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) { return f(request) }

type faultBody struct {
	io.Reader
	readErr  error
	closeErr error
}

func (b *faultBody) Read(buffer []byte) (int, error) {
	if b.Reader != nil {
		n, err := b.Reader.Read(buffer)
		if n != 0 || err == nil || b.readErr == nil {
			return n, err
		}
	}
	return 0, b.readErr
}

func (b *faultBody) Close() error { return b.closeErr }

func TestRunDownloadsAndReusesVerifiedReference(t *testing.T) {
	payload := []byte("official reference payload")
	digest := sha256.Sum256(payload)
	var requests int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if r.URL.Path != "/resolve/0123456789012345678901234567890123456789/fixture.bin" {
			t.Errorf("path = %q", r.URL.Path)
		}
		if r.URL.Query().Get("download") != "true" {
			t.Errorf("download query = %q", r.URL.RawQuery)
		}
		_, _ = w.Write(payload)
	}))
	defer server.Close()

	directory := t.TempDir()
	manifestPath := filepath.Join(directory, "manifest.json")
	destination := filepath.Join(directory, "fixtures")
	writeManifest(t, manifestPath, manifest{
		SchemaVersion: 1,
		Repository:    server.URL,
		Revision:      "0123456789012345678901234567890123456789",
		Files: []manifestFile{{
			Name: "fixture.bin", Size: int64(len(payload)), SHA256: hex.EncodeToString(digest[:]),
		}},
	})

	if err := run(manifestPath, destination); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join(destination, "fixture.bin"))
	if err != nil || string(got) != string(payload) {
		t.Fatalf("downloaded payload = %q, err = %v", got, err)
	}
	if err := run(manifestPath, destination); err != nil {
		t.Fatal(err)
	}
	if requests != 1 {
		t.Fatalf("requests = %d, want 1 after verified reuse", requests)
	}
}

func TestRunRejectsInvalidManifests(t *testing.T) {
	directory := t.TempDir()
	missing := filepath.Join(directory, "missing.json")
	if err := run(missing, filepath.Join(directory, "out")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing manifest error = %v", err)
	}

	invalidJSON := filepath.Join(directory, "invalid.json")
	if err := os.WriteFile(invalidJSON, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := run(invalidJSON, filepath.Join(directory, "out")); err == nil || !strings.Contains(err.Error(), "decode manifest") {
		t.Fatalf("invalid JSON error = %v", err)
	}

	validEntry := manifestFile{Name: "fixture", SHA256: strings.Repeat("0", sha256.Size*2)}
	for name, value := range map[string]manifest{
		"schema":     {Repository: "https://example.test", Revision: strings.Repeat("a", 40), Files: []manifestFile{validEntry}},
		"repository": {SchemaVersion: 1, Revision: strings.Repeat("a", 40), Files: []manifestFile{validEntry}},
		"revision":   {SchemaVersion: 1, Repository: "https://example.test", Files: []manifestFile{validEntry}},
		"files":      {SchemaVersion: 1, Repository: "https://example.test", Revision: strings.Repeat("a", 40)},
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "manifest.json")
			writeManifest(t, path, value)
			if err := run(path, filepath.Join(t.TempDir(), "out")); err == nil || !strings.Contains(err.Error(), "invalid manifest metadata") {
				t.Fatalf("error = %v", err)
			}
		})
	}
}

func TestCommandExitContracts(t *testing.T) {
	var stderr bytes.Buffer
	if code := command([]string{"-unknown"}, &stderr); code != 2 || stderr.Len() == 0 {
		t.Fatalf("flag failure = code %d, stderr %q", code, stderr.String())
	}
	stderr.Reset()
	if code := command([]string{"-manifest", filepath.Join(t.TempDir(), "missing")}, &stderr); code != 1 || !strings.Contains(stderr.String(), "fetch-reference") {
		t.Fatalf("run failure = code %d, stderr %q", code, stderr.String())
	}

	payload := []byte("already verified")
	digest := sha256.Sum256(payload)
	directory := t.TempDir()
	destination := filepath.Join(directory, "fixtures")
	if err := os.MkdirAll(destination, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(destination, "fixture"), payload, 0o600); err != nil {
		t.Fatal(err)
	}
	manifestPath := filepath.Join(directory, "manifest.json")
	writeManifest(t, manifestPath, manifest{
		SchemaVersion: 1, Repository: "https://example.test", Revision: strings.Repeat("a", 40),
		Files: []manifestFile{{Name: "fixture", Size: int64(len(payload)), SHA256: hex.EncodeToString(digest[:])}},
	})
	stderr.Reset()
	if code := command([]string{"-manifest", manifestPath, "-destination", destination}, &stderr); code != 0 || stderr.Len() != 0 {
		t.Fatalf("successful command = code %d, stderr %q", code, stderr.String())
	}
}

func TestManifestEntryValidation(t *testing.T) {
	validDigest := strings.Repeat("0", sha256.Size*2)
	for name, entry := range map[string]manifestFile{
		"empty name":  {SHA256: validDigest},
		"nested name": {Name: "nested/file", SHA256: validDigest},
		"negative":    {Name: "file", Size: -1, SHA256: validDigest},
		"bad hex":     {Name: "file", SHA256: "not-hex"},
		"short hash":  {Name: "file", SHA256: "00"},
		"uppercase":   {Name: "file", SHA256: strings.Repeat("A", sha256.Size*2)},
	} {
		t.Run(name, func(t *testing.T) {
			if err := validateEntry(entry); err == nil {
				t.Fatalf("validateEntry(%#v) succeeded", entry)
			}
		})
	}
	if err := validateEntry(manifestFile{Name: "file", SHA256: validDigest}); err != nil {
		t.Fatalf("valid entry: %v", err)
	}
}

func TestRunRejectsEntryAndDownloadFailures(t *testing.T) {
	digest := sha256.Sum256([]byte("expected"))
	base := manifest{
		SchemaVersion: 1, Repository: "://bad", Revision: strings.Repeat("a", 40),
		Files: []manifestFile{{Name: "fixture", Size: 8, SHA256: hex.EncodeToString(digest[:])}},
	}
	path := filepath.Join(t.TempDir(), "manifest.json")
	writeManifest(t, path, base)
	if err := run(path, filepath.Join(t.TempDir(), "out")); err == nil {
		t.Fatal("invalid repository URL succeeded")
	}

	base.Files[0].Name = "../fixture"
	writeManifest(t, path, base)
	if err := run(path, filepath.Join(t.TempDir(), "out")); err == nil {
		t.Fatal("unsafe entry succeeded")
	}

	for name, handler := range map[string]http.HandlerFunc{
		"status":    func(w http.ResponseWriter, _ *http.Request) { http.Error(w, "no", http.StatusNotFound) },
		"integrity": func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "wrong") },
	} {
		t.Run(name, func(t *testing.T) {
			server := httptest.NewServer(handler)
			defer server.Close()
			value := base
			value.Repository = server.URL
			value.Files[0].Name = "fixture"
			manifestPath := filepath.Join(t.TempDir(), "manifest.json")
			writeManifest(t, manifestPath, value)
			if err := run(manifestPath, filepath.Join(t.TempDir(), "out")); err == nil {
				t.Fatal("download failure succeeded")
			}
		})
	}
}

func TestFetchCancellationAndMatches(t *testing.T) {
	payload := []byte("payload")
	digest := sha256.Sum256(payload)
	entry := manifestFile{Name: "fixture", Size: int64(len(payload)), SHA256: hex.EncodeToString(digest[:])}
	directory := t.TempDir()
	path := filepath.Join(directory, entry.Name)

	if ok, err := matches(path, entry); err != nil || ok {
		t.Fatalf("missing match = %v, %v", ok, err)
	}
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	if ok, err := matches(path, entry); err != nil || ok {
		t.Fatalf("directory match = %v, %v", ok, err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("short"), 0o600); err != nil {
		t.Fatal(err)
	}
	if ok, err := matches(path, entry); err != nil || ok {
		t.Fatalf("size mismatch = %v, %v", ok, err)
	}
	if err := os.WriteFile(path, []byte("garbage"), 0o600); err != nil {
		t.Fatal(err)
	}
	if ok, err := matches(path, entry); err != nil || ok {
		t.Fatalf("hash mismatch = %v, %v", ok, err)
	}
	if err := os.WriteFile(path, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	if ok, err := matches(path, entry); err != nil || !ok {
		t.Fatalf("valid match = %v, %v", ok, err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := fetch(ctx, http.DefaultClient, manifest{Repository: "https://example.test", Revision: strings.Repeat("a", 40)}, entry, path)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled fetch error = %v", err)
	}
}

func TestFetchFilesystemAndTransportFailures(t *testing.T) {
	payload := []byte("payload")
	digest := sha256.Sum256(payload)
	entry := manifestFile{Name: "fixture", Size: int64(len(payload)), SHA256: hex.EncodeToString(digest[:])}
	value := manifest{Repository: "https://example.test", Revision: strings.Repeat("a", 40)}
	parent := t.TempDir()
	target := filepath.Join(parent, entry.Name)

	if err := fetch(context.Background(), http.DefaultClient, manifest{Repository: "%"}, entry, target); err == nil {
		t.Fatal("invalid repository URL succeeded")
	}
	want := errors.New("transport failed")
	client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return nil, want
	})}
	if err := fetch(context.Background(), client, value, entry, target); !errors.Is(err, want) {
		t.Fatalf("transport failure = %v", err)
	}

	success := func(body io.ReadCloser) *http.Client {
		return &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: http.StatusOK, Status: "200 OK", Header: make(http.Header), Body: body}, nil
		})}
	}
	client = success(io.NopCloser(bytes.NewReader(payload)))
	if err := fetch(context.Background(), client, value, entry, filepath.Join(parent, "missing", entry.Name)); err == nil {
		t.Fatal("temporary file below missing directory succeeded")
	}

	client = success(&faultBody{readErr: io.ErrUnexpectedEOF})
	if err := fetch(context.Background(), client, value, entry, target); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("response read failure = %v", err)
	}

	directoryTarget := filepath.Join(parent, "existing-directory")
	if err := os.Mkdir(directoryTarget, 0o700); err != nil {
		t.Fatal(err)
	}
	client = success(io.NopCloser(bytes.NewReader(payload)))
	if err := fetch(context.Background(), client, value, entry, directoryTarget); err == nil {
		t.Fatal("rename over directory succeeded")
	}

	want = errors.New("response close failed")
	client = success(&faultBody{Reader: bytes.NewReader(payload), closeErr: want})
	if err := fetch(context.Background(), client, value, entry, target); !errors.Is(err, want) {
		t.Fatalf("response close failure = %v", err)
	}

	regular := filepath.Join(parent, "regular-file")
	if err := os.WriteFile(regular, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := matches(filepath.Join(regular, "child"), entry); err == nil {
		t.Fatal("matches below regular file succeeded")
	}
	manifestPath := filepath.Join(parent, "manifest.json")
	writeManifest(t, manifestPath, manifest{
		SchemaVersion: 1, Repository: value.Repository, Revision: value.Revision, Files: []manifestFile{entry},
	})
	if err := run(manifestPath, regular); err == nil {
		t.Fatal("reference destination at regular file succeeded")
	}
}

func writeManifest(t *testing.T, path string, value manifest) {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}
