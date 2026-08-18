package hfcompat

import (
	"bytes"
	"context"
	"crypto/sha256"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	xet "github.com/jmwoliver/xet-go"
	"github.com/jmwoliver/xet-go/auth"
	"github.com/jmwoliver/xet-go/bucket"
	"github.com/jmwoliver/xet-go/catalog"
	catalogmemory "github.com/jmwoliver/xet-go/catalog/memory"
	"github.com/jmwoliver/xet-go/content"
	contentmemory "github.com/jmwoliver/xet-go/content/memory"
	"github.com/jmwoliver/xet-go/model"
	"github.com/jmwoliver/xet-go/xetcas"
	casserver "github.com/jmwoliver/xet-go/xetcas/server"
	"github.com/jmwoliver/xet-go/xethash"
	"github.com/jmwoliver/xet-go/xorb"
)

func TestOfficialPythonClientReadCompatibility(t *testing.T) {
	python := os.Getenv("XET_HF_CLIENT_PYTHON")
	if python == "" {
		t.Skip("set XET_HF_CLIENT_PYTHON to the pinned conformance Python executable")
	}
	if !filepath.IsAbs(python) {
		python = filepath.Join("..", python)
	}
	fixture := newHandlerFixture(t, 0)
	server := httptest.NewUnstartedServer(fixture.handler)
	fixture.handler.hubURL = "http://" + server.Listener.Addr().String()
	server.Start()
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	command := exec.CommandContext(
		ctx,
		python,
		filepath.Join("..", "conformance", "hf-client", "check-read-endpoint.py"),
		"--endpoint", server.URL,
		"--token", "hub-token",
	)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("official Python client read compatibility: %v\n%s", err, output)
	}
	if string(output) != "official Hub read compatibility passed\n" {
		t.Fatalf("official Python client output = %q", output)
	}
}

func TestOfficialPythonClientSnapshotDownloadUsesCAS(t *testing.T) {
	python := os.Getenv("XET_HF_CLIENT_PYTHON")
	if python == "" {
		t.Skip("set XET_HF_CLIENT_PYTHON to the pinned conformance Python executable")
	}
	if !filepath.IsAbs(python) {
		python = filepath.Join("..", python)
	}
	fixture := newPythonCASFixture(t)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/xet-read-token/") {
			fixture.tokenRequests.Add(1)
		}
		if r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/weights/model.bin") {
			fixture.xetFallbackRequests.Add(1)
		}
		fixture.handler.ServeHTTP(w, r)
	}))
	fixture.handler.hubURL = "http://" + server.Listener.Addr().String()
	server.Start()
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	command := exec.CommandContext(
		ctx,
		python,
		filepath.Join("..", "conformance", "hf-client", "check-read-endpoint.py"),
		"--endpoint", server.URL,
		"--token", "hub-token",
		"--snapshot-dir", t.TempDir(),
	)
	command.Env = append(os.Environ(), "HF_HUB_DISABLE_PROGRESS_BARS=1", "HF_HUB_DISABLE_XET=0")
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("official Python snapshot download: %v\n%s", err, output)
	}
	if !strings.Contains(string(output), "official Hub read compatibility passed\n") {
		t.Fatalf("official Python client output = %q", output)
	}
	if fixture.tokenRequests.Load() < 2 || fixture.reconstructionRequests.Load() == 0 || fixture.storageRequests.Load() == 0 ||
		fixture.xetFallbackRequests.Load() != 0 {
		t.Fatalf(
			"Xet transport requests: token=%d reconstruction=%d storage=%d fallback=%d",
			fixture.tokenRequests.Load(), fixture.reconstructionRequests.Load(), fixture.storageRequests.Load(),
			fixture.xetFallbackRequests.Load(),
		)
	}
}

func TestOfficialPythonClientNativeXetDownloadThenUploadSameProcess(t *testing.T) {
	python := os.Getenv("XET_HF_CLIENT_PYTHON")
	if python == "" {
		t.Skip("set XET_HF_CLIENT_PYTHON to the pinned conformance Python executable")
	}
	if !filepath.IsAbs(python) {
		python = filepath.Join("..", python)
	}
	fixture := newPythonCASFixture(t)
	fixture.handler.large = 1 << 20
	var writeTokens atomic.Int32
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/xet-write-token/") {
			writeTokens.Add(1)
		}
		if r.Method == http.MethodGet && (strings.HasSuffix(r.URL.Path, "/weights/model.bin") || strings.HasSuffix(r.URL.Path, "/uploaded/model.bin")) {
			fixture.xetFallbackRequests.Add(1)
		}
		fixture.handler.ServeHTTP(w, r)
	}))
	fixture.handler.hubURL = "http://" + server.Listener.Addr().String()
	server.Start()
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	command := exec.CommandContext(
		ctx,
		python,
		filepath.Join("..", "conformance", "hf-client", "check-write-endpoint.py"),
		"--endpoint", server.URL,
		"--token", "hub-token",
		"--download-dir", t.TempDir(),
	)
	command.Env = append(os.Environ(), "HF_HUB_DISABLE_PROGRESS_BARS=1", "HF_ENDPOINT="+server.URL)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("official Python native-Xet write: %v\n%s", err, output)
	}
	if !strings.HasSuffix(string(output), "official Hub write compatibility passed\n") || writeTokens.Load() == 0 ||
		fixture.xetFallbackRequests.Load() != 0 {
		t.Fatalf("official Python output = %q, write tokens = %d, HTTP fallbacks = %d",
			output, writeTokens.Load(), fixture.xetFallbackRequests.Load())
	}
}

func TestOfficialPythonClientLegacyLFSFallback(t *testing.T) {
	python := os.Getenv("XET_HF_CLIENT_PYTHON")
	if python == "" {
		t.Skip("set XET_HF_CLIENT_PYTHON to the pinned conformance Python executable")
	}
	if !filepath.IsAbs(python) {
		python = filepath.Join("..", python)
	}
	fixture := newPythonCASFixture(t)
	fixture.handler.large = 1 << 20
	var batches atomic.Int32
	var writeTokens atomic.Int32
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, ".git/info/lfs/objects/batch") {
			batches.Add(1)
		}
		if strings.Contains(r.URL.Path, "/xet-write-token/") {
			writeTokens.Add(1)
		}
		fixture.handler.ServeHTTP(w, r)
	}))
	fixture.handler.hubURL = "http://" + server.Listener.Addr().String()
	server.Start()
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	command := exec.CommandContext(
		ctx,
		python,
		filepath.Join("..", "conformance", "hf-client", "check-write-endpoint.py"),
		"--endpoint", server.URL,
		"--token", "hub-token",
		"--download-dir", t.TempDir(),
	)
	command.Env = append(os.Environ(), "HF_HUB_DISABLE_PROGRESS_BARS=1", "HF_HUB_DISABLE_XET=1", "HF_ENDPOINT="+server.URL)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("official Python legacy-LFS write: %v\n%s", err, output)
	}
	if !strings.HasSuffix(string(output), "official Hub write compatibility passed\n") || batches.Load() == 0 || writeTokens.Load() != 0 {
		t.Fatalf("official Python output = %q, LFS batches = %d, write tokens = %d", output, batches.Load(), writeTokens.Load())
	}
}

type pythonCASFixture struct {
	handler                *Service
	tokenRequests          atomic.Int32
	reconstructionRequests atomic.Int32
	storageRequests        atomic.Int32
	xetFallbackRequests    atomic.Int32
}

func newPythonCASFixture(t *testing.T) *pythonCASFixture {
	t.Helper()
	ctx := context.Background()
	repo, err := model.NewRepoKey("owner", "model", model.RepoTypeModel)
	if err != nil {
		t.Fatal(err)
	}
	manager, err := auth.NewCASTokenManager(auth.CASTokenManagerOptions{
		Issuer: "hfcompat-python", Audience: "cas",
		SigningKey: auth.HMACKey{ID: "python", Secret: bytes.Repeat([]byte{0x71}, 32)},
	})
	if err != nil {
		t.Fatal(err)
	}
	broker, err := auth.NewBroker(auth.BrokerOptions{
		Authenticator: auth.StaticTokenAuthenticator{
			Token: "hub-token", Principal: auth.Principal{Subject: "user:python"},
		},
		Authorizer: auth.RepositoryAuthorizerFunc(func(_ context.Context, access auth.RepositoryAccess) error {
			if access.Repository != repo ||
				access.Permission != auth.RepositoryRead && access.Permission != auth.RepositoryWrite {
				return auth.ErrPermissionDenied
			}
			return nil
		}),
		Tokens: manager,
	})
	if err != nil {
		t.Fatal(err)
	}

	store := casserver.NewMemoryStore()
	fixture := &pythonCASFixture{}
	storageServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		wantedRange := r.URL.Query().Get("range")
		if r.Header.Get("Authorization") != "" || wantedRange == "" || r.Header.Get("Range") != "bytes="+wantedRange {
			http.Error(w, "invalid storage capability", http.StatusForbidden)
			return
		}
		parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
		if len(parts) != 2 || parts[0] != string(casserver.BlobXorb) {
			http.NotFound(w, r)
			return
		}
		hash, parseErr := xethash.Parse(parts[1])
		if parseErr != nil {
			http.Error(w, "invalid object", http.StatusBadRequest)
			return
		}
		fixture.storageRequests.Add(1)
		reader, getErr := store.Get(r.Context(), casserver.BlobKey{Kind: casserver.BlobXorb, Hash: hash}, nil)
		if getErr != nil {
			http.NotFound(w, r)
			return
		}
		body, readErr := io.ReadAll(reader)
		closeErr := reader.Close()
		if readErr != nil || closeErr != nil {
			http.Error(w, "read object", http.StatusInternalServerError)
			return
		}
		http.ServeContent(w, r, hash.String(), time.Time{}, bytes.NewReader(body))
	}))
	t.Cleanup(storageServer.Close)

	cas, err := casserver.New(casserver.Options{
		Blobs: store, Index: store, Authorizer: auth.CASAuthorizer{Verifier: manager},
		Signer: casserver.RangeURLSignerFunc(func(_ context.Context, key casserver.BlobKey, value xetcas.HTTPRange) (casserver.SignedRange, error) {
			return casserver.SignedRange{
				URL:       storageServer.URL + "/" + string(key.Kind) + "/" + key.Hash.String() + "?range=" + value.String(),
				ExpiresAt: time.Now().Add(time.Minute),
			}, nil
		}),
		DedupProtectionKey: xethash.Chunk([]byte("hfcompat Python dedup protection")),
	})
	if err != nil {
		t.Fatal(err)
	}
	casServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "reconstructions") {
			fixture.reconstructionRequests.Add(1)
		}
		cas.Handler().ServeHTTP(w, r)
	}))
	t.Cleanup(casServer.Close)

	uploadToken, err := broker.IssueCASToken(ctx, "hub-token", repo, auth.CASRead|auth.CASWrite, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	casEndpoint, err := url.Parse(casServer.URL)
	if err != nil {
		t.Fatal(err)
	}
	protocol, err := xetcas.New(xetcas.NewStaticAccess(casEndpoint, uploadToken.Value), xetcas.Options{
		Retry: xetcas.RetryPolicy{MaxAttempts: 1},
	})
	if err != nil {
		t.Fatal(err)
	}
	client, err := xet.NewClient(protocol, xet.Options{
		Compression: xorb.LZ4, CompressionSet: true, GlobalDedup: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	xetBody := bytes.Repeat([]byte("xet-model-data"), 100)
	upload, err := client.UploadBytes(ctx, xetBody)
	if err != nil {
		t.Fatal(err)
	}
	if !upload.Report.ShardUploaded || upload.File.SHA256 == nil || upload.File.Size != uint64(len(xetBody)) {
		t.Fatalf("Xet fixture upload = %#v", upload)
	}

	metadata := catalogmemory.New()
	ordinary := contentmemory.New()
	service, err := bucket.New(bucket.Options{Catalog: metadata, Content: ordinary, CAS: cas})
	if err != nil {
		t.Fatal(err)
	}
	if err = service.CreateRepository(ctx, model.Repository{
		Key: repo, CreatedAt: time.Unix(1_700_000_000, 123).UTC(),
	}); err != nil {
		t.Fatal(err)
	}
	ordinaryBody := []byte("{\"model_type\":\"bert\"}\n")
	ordinarySum := sha256.Sum256(ordinaryBody)
	if inserted, putErr := service.PutBlob(
		ctx, content.Blob{SHA256: ordinarySum, Size: int64(len(ordinaryBody))}, bytes.NewReader(ordinaryBody),
	); putErr != nil || !inserted {
		t.Fatalf("put ordinary fixture = %v, %v", inserted, putErr)
	}
	ordinaryRef, err := model.NewBlobFileRef(ordinarySum, int64(len(ordinaryBody)))
	if err != nil {
		t.Fatal(err)
	}
	xetRef, err := model.NewXetFileRef(upload.File.Hash, int64(upload.File.Size), upload.File.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	oid, err := model.ParseOID(strings.Repeat("1", 40))
	if err != nil {
		t.Fatal(err)
	}
	snapshot := model.Snapshot{
		Repo: repo, OID: oid, CreatedAt: time.Unix(1_700_000_100, 456).UTC(),
		Author: model.Identity{Name: "Test"}, Message: "publish official Python fixture",
		Files: []model.FileEntry{
			{Path: "config.json", Ref: ordinaryRef},
			{Path: "weights/model.bin", Ref: xetRef},
		},
	}
	if err = service.PublishSnapshot(ctx, snapshot, catalog.ExpectRef("main", nil)); err != nil {
		t.Fatal(err)
	}
	if err = service.CompareAndSwapRef(ctx, repo, "feature/test", nil, oid); err != nil {
		t.Fatal(err)
	}

	handler, err := New(Options{
		Bucket: service, Broker: broker,
		HubBaseURL: "https://hub.invalid", CASBaseURL: casServer.URL,
		Ingester: XetFileIngestFunc(func(ctx context.Context, got model.RepoKey, source io.Reader) (XetFileIngestResult, error) {
			if got != repo {
				return XetFileIngestResult{}, bucket.ErrPermissionDenied
			}
			result, uploadErr := client.Upload(ctx, source)
			if uploadErr != nil {
				return XetFileIngestResult{}, uploadErr
			}
			if result.File.SHA256 == nil {
				return XetFileIngestResult{}, bucket.ErrInvariant
			}
			return XetFileIngestResult{Hash: result.File.Hash, Size: result.File.Size, SHA256: *result.File.SHA256}, nil
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	fixture.handler = handler
	fixture.reconstructionRequests.Store(0)
	fixture.storageRequests.Store(0)
	return fixture
}
