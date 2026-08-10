package conformance_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jmwoliver/xet-go/chunker"
	"github.com/jmwoliver/xet-go/xetcas"
	cas_server "github.com/jmwoliver/xet-go/xetcas/server"
	"github.com/jmwoliver/xet-go/xethash"
)

type rustRemoteRoundtrip struct {
	FileHash       string `json:"file_hash"`
	FileSize       uint64 `json:"file_size"`
	SHA256         string `json:"sha256"`
	DownloadedSize uint64 `json:"downloaded_bytes"`
	GlobalDedup    uint64 `json:"global_dedup_bytes"`
}

// TestOfficialRustClientGoCASRoundTrip exercises the released Rust client's
// real RemoteClient against the Go HTTP handler. It is gated on the separately
// built pinned oracle so ordinary `go test ./...` stays self-contained.
func TestOfficialRustClientGoCASRoundTrip(t *testing.T) {
	oracle := os.Getenv("XET_RUST_ORACLE")
	if oracle == "" {
		t.Skip("set XET_RUST_ORACLE to the binary produced by conformance/build-rust-oracle.sh")
	}

	store := cas_server.NewMemoryStore()
	storage := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" {
			t.Errorf("CAS authorization leaked to signed storage")
		}
		parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
		if len(parts) != 2 || parts[0] != string(cas_server.BlobXorb) {
			http.NotFound(w, r)
			return
		}
		hash, err := xethash.Parse(parts[1])
		if err != nil {
			http.Error(w, "invalid hash", http.StatusBadRequest)
			return
		}
		value, err := singleHTTPRange(r.Header.Get("Range"))
		if err != nil {
			http.Error(w, "invalid range", http.StatusRequestedRangeNotSatisfiable)
			return
		}
		key := cas_server.BlobKey{Kind: cas_server.BlobXorb, Hash: hash}
		reader, err := store.Get(r.Context(), key, &value)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		body, err := io.ReadAll(reader)
		if err != nil {
			_ = reader.Close()
			t.Error(err)
			return
		}
		if err := reader.Close(); err != nil {
			t.Error(err)
			return
		}
		info, found, err := store.Head(r.Context(), key)
		if err != nil || !found {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", value.Start, value.End, info.Size))
		w.Header().Set("Content-Length", strconv.Itoa(len(body)))
		w.WriteHeader(http.StatusPartialContent)
		_, _ = w.Write(body)
	}))
	defer storage.Close()

	service, err := cas_server.New(cas_server.Options{
		Blobs: store,
		Index: store,
		Signer: cas_server.RangeURLSignerFunc(func(_ context.Context, key cas_server.BlobKey, _ xetcas.HTTPRange) (string, error) {
			return storage.URL + "/" + string(key.Kind) + "/" + key.Hash.String() + "?signed=1", nil
		}),
		Authorizer:         cas_server.StaticTokenAuthorizer{Token: "official-rust-token", Namespace: "rust-client"},
		DedupProtectionKey: xethash.Chunk([]byte("official Rust client test key")),
		Now:                func() time.Time { return time.Unix(2_000_000_000, 0) },
	})
	if err != nil {
		t.Fatal(err)
	}
	var captured struct {
		sync.Mutex
		shard []byte
	}
	var globalDedupQueries atomic.Int32
	handler := service.Handler()
	cas := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/v1/chunks/") {
			globalDedupQueries.Add(1)
		}
		if r.Method == http.MethodPost && r.URL.Path == "/v2/shards" {
			body, readErr := io.ReadAll(r.Body)
			if readErr != nil {
				http.Error(w, "read shard", http.StatusInternalServerError)
				return
			}
			captured.Lock()
			captured.shard = append(captured.shard[:0], body...)
			captured.Unlock()
			r.Body = io.NopCloser(bytes.NewReader(body))
		}
		handler.ServeHTTP(w, r)
	}))
	defer cas.Close()

	data := make([]byte, 3<<20+937)
	rng := rand.New(rand.NewSource(0x52555354))
	_, _ = rng.Read(data)
	copy(data[1<<20:2<<20], data[:1<<20])
	temporary := t.TempDir()
	input := filepath.Join(temporary, "input.bin")
	output := filepath.Join(temporary, "output.bin")
	if err := os.WriteFile(input, data, 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, oracle, "remote-roundtrip", input, cas.URL, "official-rust-token", output)
	command.Env = append(os.Environ(), "HF_XET_CACHE="+filepath.Join(temporary, "cache"))
	raw, err := command.CombinedOutput()
	if err != nil {
		captured.Lock()
		shardBody := append([]byte(nil), captured.shard...)
		captured.Unlock()
		_, validationErr := service.UploadShard(context.Background(), "official-rust-token", bytes.NewReader(shardBody), int64(len(shardBody)))
		t.Fatalf("official Rust client: %v; Go shard validation: %v\n%s", err, validationErr, raw)
	}
	var result rustRemoteRoundtrip
	if err := json.Unmarshal(bytes.TrimSpace(raw), &result); err != nil {
		t.Fatalf("decode Rust result: %v\n%s", err, raw)
	}
	downloaded, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(downloaded, data) {
		t.Fatal("official Rust client reconstruction from Go CAS differs")
	}
	if result.FileSize != uint64(len(data)) || result.DownloadedSize != uint64(len(data)) {
		t.Fatalf("Rust sizes = file %d, downloaded %d; want %d", result.FileSize, result.DownloadedSize, len(data))
	}
	parts := chunker.Bytes(data)
	nodes := make([]xethash.Node, len(parts))
	for i := range parts {
		nodes[i] = xethash.Node{Hash: xethash.Chunk(parts[i].Data), Size: uint64(len(parts[i].Data))}
	}
	if want := xethash.File(nodes).String(); result.FileHash != want {
		t.Fatalf("Rust file hash = %s, Go = %s", result.FileHash, want)
	}

	// A fresh Rust process and cache must be able to consume the protected
	// global-dedup shard dynamically generated by the Go server. Change only the
	// tail so the file identity is new but its stable leading chunks are shared.
	globalDedupQueries.Store(0)
	dedupData := append([]byte(nil), data...)
	for i := len(dedupData) - 64<<10; i < len(dedupData); i++ {
		dedupData[i] ^= 0xa5
	}
	secondInput := filepath.Join(temporary, "input-dedup.bin")
	if err := os.WriteFile(secondInput, dedupData, 0o600); err != nil {
		t.Fatal(err)
	}
	secondOutput := filepath.Join(temporary, "output-dedup.bin")
	second := exec.CommandContext(ctx, oracle, "remote-roundtrip", secondInput, cas.URL, "official-rust-token", secondOutput)
	second.Env = append(os.Environ(), "HF_XET_CACHE="+filepath.Join(temporary, "cache-dedup"))
	secondRaw, err := second.CombinedOutput()
	if err != nil {
		t.Fatalf("official Rust global-dedup client: %v\n%s", err, secondRaw)
	}
	var secondResult rustRemoteRoundtrip
	if err := json.Unmarshal(bytes.TrimSpace(secondRaw), &secondResult); err != nil {
		t.Fatalf("decode Rust global-dedup result: %v\n%s", err, secondRaw)
	}
	secondData, err := os.ReadFile(secondOutput)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(secondData, dedupData) {
		t.Fatal("official Rust client reconstruction after Go global dedup differs")
	}
	if globalDedupQueries.Load() == 0 {
		t.Fatal("fresh official Rust client did not query Go global dedup")
	}
	if secondResult.GlobalDedup == 0 {
		t.Fatalf("official Rust client did not consume Go protected global-dedup shard: %#v", secondResult)
	}
}

func singleHTTPRange(header string) (xetcas.HTTPRange, error) {
	if !strings.HasPrefix(header, "bytes=") || strings.Contains(header, ",") {
		return xetcas.HTTPRange{}, fmt.Errorf("expected one bytes range")
	}
	startText, endText, ok := strings.Cut(strings.TrimPrefix(header, "bytes="), "-")
	if !ok {
		return xetcas.HTTPRange{}, fmt.Errorf("missing range separator")
	}
	start, err := strconv.ParseUint(startText, 10, 64)
	if err != nil {
		return xetcas.HTTPRange{}, err
	}
	end, err := strconv.ParseUint(endText, 10, 64)
	if err != nil || end < start {
		return xetcas.HTTPRange{}, fmt.Errorf("invalid range end")
	}
	return xetcas.HTTPRange{Start: start, End: end}, nil
}
