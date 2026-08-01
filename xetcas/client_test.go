package xetcas

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jacobwoliver/xet-go/xethash"
)

func testClient(t testing.TB, endpoint *url.URL, token string, options Options) *Client {
	t.Helper()
	if options.Retry.Sleep == nil {
		options.Retry.Sleep = func(context.Context, time.Duration) error { return nil }
	}
	if options.Retry.MaxAttempts == 0 {
		options.Retry.MaxAttempts = 3
	}
	client, err := New(NewStaticAccess(endpoint, token), options)
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func serverURL(t testing.TB, raw string) *url.URL {
	t.Helper()
	value, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func emptyReconstructionJSON() string {
	return `{"offset_into_first_range":0,"terms":[],"xorbs":{}}`
}

func TestQueryReconstructionV2RangeAndAuthentication(t *testing.T) {
	fileID := xethash.Chunk([]byte("file"))
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Method != http.MethodGet || r.URL.Path != "/base/v2/reconstructions/"+fileID.String() {
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
		}
		if got := r.Header.Get("Range"); got != "bytes=7-18" {
			t.Errorf("Range = %q", got)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer cas-secret" {
			t.Errorf("Authorization = %q", got)
		}
		if got := r.Header.Get(SessionIDHeader); got != "session-1" {
			t.Errorf("session = %q", got)
		}
		_, _ = io.WriteString(w, emptyReconstructionJSON())
	}))
	defer server.Close()
	endpoint := serverURL(t, server.URL+"/base")
	client := testClient(t, endpoint, "cas-secret", Options{SessionID: "session-1"})
	value, err := client.QueryReconstruction(context.Background(), fileID, &FileRange{Start: 7, End: 19})
	if err != nil {
		t.Fatal(err)
	}
	if value == nil || len(value.Terms) != 0 || calls.Load() != 1 {
		t.Fatalf("unexpected response %#v, calls %d", value, calls.Load())
	}
}

func TestQueryReconstructionFallsBackAndPinsV1(t *testing.T) {
	fileID := xethash.Chunk([]byte("fallback"))
	xorbID := xethash.Chunk([]byte("xorb"))
	var v1, v2 atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "/v2/"):
			v2.Add(1)
			http.Error(w, "not implemented", http.StatusNotImplemented)
		case strings.Contains(r.URL.Path, "/v1/"):
			v1.Add(1)
			response := reconstructionV1{
				Terms: []ReconstructionTerm{{Hash: xorbID, UnpackedLength: 3, Range: ChunkRange{Start: 2, End: 3}}},
				FetchInfo: map[xethash.Hash][]v1FetchInfo{
					xorbID: {{Range: ChunkRange{Start: 2, End: 3}, URL: serverURLForRequest(r) + "/signed", URLRange: HTTPRange{Start: 10, End: 20}}},
				},
			}
			_ = json.NewEncoder(w).Encode(response)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	client := testClient(t, serverURL(t, server.URL), "", Options{})
	for i := 0; i < 2; i++ {
		value, err := client.QueryReconstruction(context.Background(), fileID, nil)
		if err != nil {
			t.Fatal(err)
		}
		if len(value.Terms) != 1 || len(value.Xorbs[xorbID]) != 1 {
			t.Fatalf("bad normalization: %#v", value)
		}
	}
	if v2.Load() != 1 || v1.Load() != 2 {
		t.Fatalf("v2 calls %d, v1 calls %d", v2.Load(), v1.Load())
	}
}

func serverURLForRequest(r *http.Request) string {
	return "http://" + r.Host
}

type rotatingProvider struct {
	endpoint    *url.URL
	mu          sync.Mutex
	calls       int
	invalidates int
	block       chan struct{}
}

func (p *rotatingProvider) Access(ctx context.Context, _ Access) (CASAccess, error) {
	if p.block != nil {
		select {
		case <-ctx.Done():
			return CASAccess{}, ctx.Err()
		case <-p.block:
		}
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.calls++
	return CASAccess{Endpoint: p.endpoint, BearerToken: fmt.Sprintf("token-%d", p.calls)}, nil
}

func (p *rotatingProvider) Invalidate(Access) {
	p.mu.Lock()
	p.invalidates++
	p.mu.Unlock()
}

func TestAccessRefreshCoalescesConcurrentCallers(t *testing.T) {
	block := make(chan struct{})
	provider := &rotatingProvider{endpoint: serverURL(t, "https://cas.example"), block: block}
	client, err := New(provider, Options{})
	if err != nil {
		t.Fatal(err)
	}
	const goroutines = 32
	results := make(chan error, goroutines)
	for range goroutines {
		go func() {
			access, err := client.access.get(context.Background(), AccessRead)
			if err == nil && access.BearerToken != "token-1" {
				err = fmt.Errorf("token = %q", access.BearerToken)
			}
			results <- err
		}()
	}
	close(block)
	for range goroutines {
		if err := <-results; err != nil {
			t.Fatal(err)
		}
	}
	provider.mu.Lock()
	defer provider.mu.Unlock()
	if provider.calls != 1 {
		t.Fatalf("provider calls = %d, want 1", provider.calls)
	}
}

func TestCAS401InvalidatesAndRefreshesOnce(t *testing.T) {
	fileID := xethash.Chunk([]byte("auth-refresh"))
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.Header.Get("Authorization") == "Bearer token-1" {
			http.Error(w, "expired", http.StatusUnauthorized)
			return
		}
		_, _ = io.WriteString(w, emptyReconstructionJSON())
	}))
	defer server.Close()
	provider := &rotatingProvider{endpoint: serverURL(t, server.URL)}
	client, err := New(provider, Options{Retry: RetryPolicy{Sleep: func(context.Context, time.Duration) error { return nil }}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.QueryReconstruction(context.Background(), fileID, nil); err != nil {
		t.Fatal(err)
	}
	provider.mu.Lock()
	defer provider.mu.Unlock()
	if requests.Load() != 2 || provider.calls != 2 || provider.invalidates != 1 {
		t.Fatalf("requests=%d calls=%d invalidates=%d", requests.Load(), provider.calls, provider.invalidates)
	}
}

func TestTransientStatusRetryAndNonTransientNoRetry(t *testing.T) {
	fileID := xethash.Chunk([]byte("retry"))
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if requests.Add(1) == 1 {
			w.Header().Set("Retry-After", "0")
			http.Error(w, "busy", http.StatusServiceUnavailable)
			return
		}
		_, _ = io.WriteString(w, emptyReconstructionJSON())
	}))
	defer server.Close()
	var sleeps atomic.Int32
	client := testClient(t, serverURL(t, server.URL), "", Options{Retry: RetryPolicy{
		Sleep: func(context.Context, time.Duration) error { sleeps.Add(1); return nil },
	}})
	if _, err := client.QueryReconstruction(context.Background(), fileID, nil); err != nil {
		t.Fatal(err)
	}
	if requests.Load() != 2 || sleeps.Load() != 1 {
		t.Fatalf("requests=%d sleeps=%d", requests.Load(), sleeps.Load())
	}

	requests.Store(0)
	forbidden := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		http.Error(w, "forbidden", http.StatusForbidden)
	}))
	defer forbidden.Close()
	client = testClient(t, serverURL(t, forbidden.URL), "", Options{})
	_, err := client.QueryReconstruction(context.Background(), fileID, nil)
	var httpErr *HTTPError
	if !errors.As(err, &httpErr) || httpErr.StatusCode != http.StatusForbidden || requests.Load() != 1 {
		t.Fatalf("error=%v requests=%d", err, requests.Load())
	}
}

func TestSignedFetchExactMultipartRangeAndCredentialIsolation(t *testing.T) {
	var gotRange, gotAuth, gotSession, gotCookie string
	storage := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotRange = r.Header.Get("Range")
		gotAuth = r.Header.Get("Authorization")
		gotSession = r.Header.Get(SessionIDHeader)
		gotCookie = r.Header.Get("Cookie")
		w.Header().Set("Content-Type", `multipart/byteranges; boundary="xet-boundary"`)
		w.WriteHeader(http.StatusPartialContent)
		_, _ = io.WriteString(w, "--xet-boundary\r\nContent-Range: bytes 10-13/100\r\n\r\ndefg\r\n")
		_, _ = io.WriteString(w, "--xet-boundary\r\nContent-Range: bytes 0-2/100\r\n\r\nabc\r\n")
		_, _ = io.WriteString(w, "--xet-boundary--\r\n")
	}))
	defer storage.Close()

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	storageURL := serverURL(t, storage.URL)
	jar.SetCookies(storageURL, []*http.Cookie{{Name: "ambient", Value: "secret"}})
	client := testClient(t, serverURL(t, "https://cas.invalid"), "cas-token", Options{
		HTTPClient: &http.Client{Jar: jar}, SessionID: "must-not-leak",
	})
	results, err := client.FetchRanges(context.Background(), storage.URL+"?X-Amz-Signature=secret", []HTTPRange{{0, 2}, {10, 13}})
	if err != nil {
		t.Fatal(err)
	}
	if gotRange != "bytes=0-2,10-13" || gotAuth != "" || gotSession != "" || gotCookie != "" {
		t.Fatalf("range=%q auth=%q session=%q cookie=%q", gotRange, gotAuth, gotSession, gotCookie)
	}
	if len(results) != 2 || string(results[0].Data) != "abc" || string(results[1].Data) != "defg" {
		t.Fatalf("unexpected sorted parts: %#v", results)
	}
}

func TestSignedFetchSingleAndExpired(t *testing.T) {
	var status atomic.Int32
	status.Store(http.StatusOK)
	storage := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(int(status.Load()))
		if status.Load() == http.StatusOK {
			_, _ = io.WriteString(w, "hello")
		}
	}))
	defer storage.Close()
	client := testClient(t, serverURL(t, "https://cas.invalid"), "", Options{})
	parts, err := client.FetchRanges(context.Background(), storage.URL, []HTTPRange{{4, 8}})
	if err != nil || len(parts) != 1 || string(parts[0].Data) != "hello" {
		t.Fatalf("parts=%#v err=%v", parts, err)
	}
	status.Store(http.StatusForbidden)
	_, err = client.FetchRanges(context.Background(), storage.URL+"?token=redacted", []HTTPRange{{4, 8}})
	if !errors.Is(err, ErrSignedURLExpired) || strings.Contains(err.Error(), "token=redacted") {
		t.Fatalf("unexpected expired error %v", err)
	}
}

func TestUploadShardV2RetriesTerminalError(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if string(body) != "shard-data" {
			t.Errorf("body=%q", body)
		}
		w.Header().Set("Content-Type", "application/x-ndjson")
		if calls.Add(1) == 1 {
			_, _ = io.WriteString(w, `{"type":"error","message":"try again","retryable":true}`+"\n")
			return
		}
		_, _ = io.WriteString(w, `{"type":"validating","verified":1,"total":1}`+"\n")
		_, _ = io.WriteString(w, `{"type":"committing","stage":"syncing"}`+"\n")
		_, _ = io.WriteString(w, `{"type":"result"}`)
	}))
	defer server.Close()
	client := testClient(t, serverURL(t, server.URL), "", Options{})
	var events []ShardUploadEvent
	if err := client.UploadShard(context.Background(), []byte("shard-data"), func(event ShardUploadEvent) {
		events = append(events, event)
	}); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 2 || len(events) != 4 || events[len(events)-1].Type != "result" {
		t.Fatalf("calls=%d events=%#v", calls.Load(), events)
	}
}

func TestUploadShardFallbackAndMissingTerminal(t *testing.T) {
	var v1, v2 atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v2/shards" {
			v2.Add(1)
			http.Error(w, "unsupported", http.StatusNotFound)
			return
		}
		if r.URL.Path == "/v1/shards" {
			v1.Add(1)
			_, _ = io.WriteString(w, `{"result":1}`)
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()
	client := testClient(t, serverURL(t, server.URL), "", Options{})
	if err := client.UploadShard(context.Background(), []byte("data"), nil); err != nil {
		t.Fatal(err)
	}
	if err := client.UploadShard(context.Background(), []byte("data"), nil); err != nil {
		t.Fatal(err)
	}
	if v2.Load() != 1 || v1.Load() != 2 {
		t.Fatalf("v2=%d v1=%d", v2.Load(), v1.Load())
	}

	incomplete := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"type":"validating","verified":0,"total":1}`)
	}))
	defer incomplete.Close()
	client = testClient(t, serverURL(t, incomplete.URL), "", Options{})
	if err := client.UploadShard(context.Background(), []byte("data"), nil); !errors.Is(err, ErrMissingTerminal) {
		t.Fatalf("error=%v", err)
	}
}

func TestObjectEndpoints(t *testing.T) {
	hash := xethash.Chunk([]byte("object"))
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/v1/xorbs/default/"+hash.String():
			body, _ := io.ReadAll(r.Body)
			if !bytes.Equal(body, []byte("xorb")) {
				t.Errorf("xorb body=%q", body)
			}
			_, _ = io.WriteString(w, `{"was_inserted":true}`)
		case r.Method == http.MethodHead && r.URL.Path == "/v1/xorbs/default/"+hash.String():
			w.WriteHeader(http.StatusOK)
		case r.Method == http.MethodHead && r.URL.Path == "/v1/files/"+hash.String():
			w.Header().Set("Content-Length", "1234")
			w.WriteHeader(http.StatusOK)
		case r.Method == http.MethodGet && r.URL.Path == "/v1/chunks/default/"+hash.String():
			_, _ = w.Write([]byte("shard"))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	client := testClient(t, serverURL(t, server.URL), "", Options{})
	inserted, err := client.UploadXorb(context.Background(), DefaultPrefix, hash, []byte("xorb"))
	if err != nil || !inserted {
		t.Fatalf("inserted=%v err=%v", inserted, err)
	}
	exists, err := client.XorbExists(context.Background(), DefaultPrefix, hash)
	if err != nil || !exists {
		t.Fatalf("exists=%v err=%v", exists, err)
	}
	size, found, err := client.FileSize(context.Background(), hash)
	if err != nil || !found || size != 1234 {
		t.Fatalf("size=%d found=%v err=%v", size, found, err)
	}
	data, found, err := client.QueryGlobalDedup(context.Background(), DefaultPrefix, hash)
	if err != nil || !found || string(data) != "shard" {
		t.Fatalf("data=%q found=%v err=%v", data, found, err)
	}
}

func TestBatchReconstructionPostThenLegacyGetFallback(t *testing.T) {
	first := xethash.Chunk([]byte("batch-first"))
	second := xethash.Chunk([]byte("batch-second"))
	var postCalls, getCalls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPost:
			postCalls.Add(1)
			var keys []struct {
				Prefix string       `json:"prefix"`
				Hash   xethash.Hash `json:"hash"`
			}
			if err := json.NewDecoder(r.Body).Decode(&keys); err != nil {
				t.Error(err)
			}
			if len(keys) != 2 || keys[0].Prefix != DefaultPrefix {
				t.Errorf("keys=%#v", keys)
			}
			http.Error(w, "legacy only", http.StatusMethodNotAllowed)
		case http.MethodGet:
			getCalls.Add(1)
			if got := r.URL.Query()["file_id"]; len(got) != 2 || got[0] != first.String() || got[1] != second.String() {
				t.Errorf("file_id query=%v", got)
			}
			_ = json.NewEncoder(w).Encode(batchReconstructionV1{
				Files:     map[xethash.Hash][]ReconstructionTerm{first: {}, second: {}},
				FetchInfo: map[xethash.Hash][]v1FetchInfo{},
			})
		default:
			t.Errorf("method=%s", r.Method)
		}
	}))
	defer server.Close()
	client := testClient(t, serverURL(t, server.URL), "", Options{})
	result, err := client.BatchQueryReconstruction(context.Background(), []xethash.Hash{first, second, first})
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 2 || postCalls.Load() != 1 || getCalls.Load() != 1 {
		t.Fatalf("result=%#v post=%d get=%d", result, postCalls.Load(), getCalls.Load())
	}
}

func TestQueryFileChunkHashesHeaderAndValidation(t *testing.T) {
	fileID := xethash.Chunk([]byte("delta-base"))
	verification := xethash.Chunk([]byte("gap"))
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v2/file-chunk-hashes/"+fileID.String() {
			t.Errorf("path=%s", r.URL.Path)
		}
		if got := r.Header.Get(DirtyRangeHeader); got != "bytes=10-19,30-39" {
			t.Errorf("dirty header=%q", got)
		}
		_ = json.NewEncoder(w).Encode(FileChunkHashesResponse{
			TotalChunks:     10,
			FileSize:        100,
			Windows:         []ChunkWindow{{DirtyByteRange: [2]uint64{8, 42}}},
			HashRanges:      []*xethash.MerkleHashSubtree{nil, nil},
			GapVerification: []xethash.Hash{verification},
		})
	}))
	defer server.Close()
	client := testClient(t, serverURL(t, server.URL), "", Options{})
	result, err := client.QueryFileChunkHashes(context.Background(), fileID, []FileRange{{10, 20}, {30, 40}})
	if err != nil {
		t.Fatal(err)
	}
	if result.FileSize != 100 || len(result.Windows) != 1 || result.GapVerification[0] != verification {
		t.Fatalf("response=%#v", result)
	}
}

func TestRedirectsAreNotFollowedAndErrorsAreRedacted(t *testing.T) {
	targetCalls := atomic.Int32{}
	target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { targetCalls.Add(1) }))
	defer target.Close()
	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+"?secret=leak", http.StatusFound)
	}))
	defer redirect.Close()
	client := testClient(t, serverURL(t, redirect.URL), "secret-token", Options{})
	_, err := client.QueryReconstruction(context.Background(), xethash.Zero, nil)
	var httpErr *HTTPError
	if !errors.As(err, &httpErr) || httpErr.StatusCode != http.StatusFound || targetCalls.Load() != 0 {
		t.Fatalf("error=%v target calls=%d", err, targetCalls.Load())
	}
}

func TestAccessValidation(t *testing.T) {
	tests := []CASAccess{
		{},
		{Endpoint: serverURL(t, "ftp://cas.example")},
		{Endpoint: serverURL(t, "https://user:pass@cas.example")},
		{Endpoint: serverURL(t, "https://cas.example?token=x")},
		{Endpoint: serverURL(t, "https://cas.example"), ExpiresAt: time.Now().Add(-time.Second)},
	}
	for _, access := range tests {
		if err := validateAccess(access, time.Now()); err == nil {
			t.Errorf("validateAccess(%#v) succeeded", access)
		}
	}
}

func FuzzParseContentRange(f *testing.F) {
	for _, seed := range []string{"bytes 0-9/10", "bytes 5-5/*", "bytes 9-0/10", "", "items 0-1/2"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, value string) {
		rangeValue, err := parseContentRange(value)
		if err == nil {
			if validationErr := rangeValue.Validate(); validationErr != nil {
				t.Fatalf("accepted invalid range: %v", validationErr)
			}
		}
	})
}

func FuzzDecodeMultipart(f *testing.F) {
	f.Add("multipart/byteranges; boundary=x", "--x\r\nContent-Range: bytes 0-0/1\r\n\r\na\r\n--x--\r\n")
	f.Add("text/plain", "garbage")
	f.Fuzz(func(t *testing.T, contentType, body string) {
		client := &Client{maxResponseBytes: 1 << 20}
		response := &http.Response{
			StatusCode: http.StatusPartialContent,
			Header:     http.Header{"Content-Type": []string{contentType}},
			Body:       io.NopCloser(strings.NewReader(body)),
		}
		_, _ = client.decodeRangeResponse(response, []HTTPRange{{Start: 0, End: 0}}, 1)
	})
}

func BenchmarkDecodeMultipart(b *testing.B) {
	const contentType = "multipart/byteranges; boundary=bench"
	payload := strings.Repeat("x", 64<<10)
	body := "--bench\r\nContent-Range: bytes 65536-131071/131072\r\n\r\n" + payload +
		"\r\n--bench\r\nContent-Range: bytes 0-65535/131072\r\n\r\n" + payload + "\r\n--bench--\r\n"
	client := &Client{maxResponseBytes: 1 << 20}
	ranges := []HTTPRange{{Start: 0, End: 65535}, {Start: 65536, End: 131071}}
	b.SetBytes(128 << 10)
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		response := &http.Response{
			StatusCode: http.StatusPartialContent,
			Header:     http.Header{"Content-Type": []string{contentType}},
			Body:       io.NopCloser(strings.NewReader(body)),
		}
		if _, err := client.decodeRangeResponse(response, ranges, 128<<10); err != nil {
			b.Fatal(err)
		}
	}
}
