package xetcas

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/jacobwoliver/xet-go/xethash"
)

func TestClientConstructionContracts(t *testing.T) {
	endpoint := serverURL(t, "https://cas.example")
	provider := NewStaticAccess(endpoint, "")
	if _, err := New(nil, Options{}); err == nil {
		t.Fatal("nil access provider succeeded")
	}
	for name, options := range map[string]Options{
		"refresh":              {RefreshBefore: -1},
		"attempts":             {Retry: RetryPolicy{MaxAttempts: -1}},
		"backoff":              {Retry: RetryPolicy{InitialBackoff: -1}},
		"maximum backoff":      {Retry: RetryPolicy{InitialBackoff: time.Second, MaximumBackoff: time.Millisecond}},
		"upload concurrency":   {UploadConcurrency: ConcurrencyPolicy{Initial: -1}},
		"download concurrency": {DownloadConcurrency: ConcurrencyPolicy{Initial: -1}},
		"response limit":       {MaxResponseBytes: -1},
		"error limit":          {MaxErrorBytes: -1},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := New(provider, options); err == nil {
				t.Fatalf("New(%#v) succeeded", options)
			}
		})
	}

	original := &http.Client{Jar: mustCookieJar(t)}
	client, err := New(provider, Options{HTTPClient: original, Now: func() time.Time { return time.Unix(1, 0) }})
	if err != nil {
		t.Fatal(err)
	}
	if client.http == original || client.http.Jar != nil || client.http.CheckRedirect == nil {
		t.Fatal("HTTP client was not safely shallow-copied")
	}
	if err := client.http.CheckRedirect(nil, nil); !errors.Is(err, http.ErrUseLastResponse) {
		t.Fatalf("redirect policy = %v", err)
	}
}

func mustCookieJar(t *testing.T) http.CookieJar {
	t.Helper()
	jar, err := cookieJar()
	if err != nil {
		t.Fatal(err)
	}
	return jar
}

func cookieJar() (http.CookieJar, error) {
	return cookiejar.New(nil)
}

func TestHTTPAndRetryHelpers(t *testing.T) {
	requestErr := &HTTPError{Method: "GET", URL: "https://cas.example/x", StatusCode: 500, RequestID: "request-1"}
	if got := requestErr.Error(); !strings.Contains(got, "request request-1") {
		t.Fatalf("HTTPError = %q", got)
	}
	cause := io.ErrUnexpectedEOF
	transportErr := &transportFailure{cause: cause}
	if transportErr.Error() != "transport failure" || !errors.Is(transportErr, cause) {
		t.Fatalf("transport failure = %v", transportErr)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := sleepContext(ctx, time.Hour); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled sleep = %v", err)
	}
	if err := sleepContext(context.Background(), 0); err != nil {
		t.Fatalf("zero sleep = %v", err)
	}

	fixed := time.Unix(100, 0)
	for _, value := range []string{"", "invalid", "-1"} {
		if _, ok := parseRetryAfter(value, fixed); ok {
			t.Errorf("Retry-After %q parsed", value)
		}
	}
	var delay time.Duration
	client := &Client{now: func() time.Time { return fixed }, retry: RetryPolicy{
		InitialBackoff: time.Second, MaximumBackoff: 2 * time.Second,
		Sleep: func(_ context.Context, got time.Duration) error { delay = got; return nil },
	}}
	if err := client.waitRetry(context.Background(), 20, ""); err != nil || delay > 2*time.Second {
		t.Fatalf("retry delay = %v, err = %v", delay, err)
	}
}

func TestURLHeaderAndReadHelpers(t *testing.T) {
	endpoint := serverURL(t, "https://user:pass@cas.example/base/?secret=old#fragment")
	got := endpointURL(endpoint, "/v1/object?part=2")
	if got.String() != "https://user:pass@cas.example/base/v1/object?part=2" {
		t.Fatalf("endpointURL = %q", got)
	}
	if redactURL(nil) != "<nil>" || strings.Contains(redactURL(got), "user") || strings.Contains(redactURL(got), "part=2") {
		t.Fatalf("redacted URL = %q", redactURL(got))
	}
	dst := make(http.Header)
	copyHeaders(dst, http.Header{"Authorization": {"secret"}, "X-Test": {"a", "b"}})
	if dst.Get("Authorization") != "" || len(dst.Values("X-Test")) != 2 {
		t.Fatalf("copied headers = %#v", dst)
	}
	if _, err := readLimited(strings.NewReader("x"), -1); err == nil {
		t.Fatal("negative read limit succeeded")
	}
	if _, err := readLimited(strings.NewReader("xx"), 1); !errors.Is(err, errResponseTooLarge) {
		t.Fatalf("oversize read = %v", err)
	}
	want := errors.New("read failure")
	if _, err := readLimited(errorReader{err: want}, 10); !errors.Is(err, want) {
		t.Fatalf("read failure = %v", err)
	}
}

type errorReader struct{ err error }

func (r errorReader) Read([]byte) (int, error) { return 0, r.err }

type timeoutError struct{}

func (timeoutError) Error() string   { return "timeout" }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return true }

func TestRetryableNetworkErrorClassification(t *testing.T) {
	certificate := &tls.CertificateVerificationError{Err: errors.New("bad certificate")}
	permanentDNS := &net.DNSError{Err: "not found", Name: "invalid", IsTemporary: false, IsTimeout: false}
	if isRetryableNetworkError(certificate) || isRetryableNetworkError(permanentDNS) {
		t.Fatal("permanent network error classified as retryable")
	}
	operation := &net.OpError{Op: "dial", Net: "tcp", Err: syscall.ECONNREFUSED}
	for _, err := range []error{timeoutError{}, operation, io.EOF, io.ErrUnexpectedEOF, syscall.ECONNRESET, syscall.ECONNREFUSED, syscall.EPIPE} {
		if !isRetryableNetworkError(err) {
			t.Errorf("%T %v was not retryable", err, err)
		}
	}
	if isRetryableNetworkError(errors.New("permanent")) {
		t.Fatal("ordinary error was retryable")
	}
}

func TestEndpointInputAndMissingObjectContracts(t *testing.T) {
	client := testClient(t, serverURL(t, "https://cas.invalid"), "", Options{})
	if result, err := client.BatchQueryReconstruction(context.Background(), nil); err != nil || len(result) != 0 {
		t.Fatalf("empty batch = %#v, %v", result, err)
	}
	if _, err := client.BatchQueryReconstruction(context.Background(), make([]xethash.Hash, 10_001)); err == nil {
		t.Fatal("oversized batch succeeded")
	}
	if _, err := client.QueryFileChunkHashes(context.Background(), xethash.Zero, nil); err == nil {
		t.Fatal("empty dirty range succeeded")
	}
	if _, err := client.QueryFileChunkHashes(context.Background(), xethash.Zero, []FileRange{{}}); err == nil {
		t.Fatal("invalid dirty range succeeded")
	}
	if _, err := client.QueryReconstruction(context.Background(), xethash.Zero, &FileRange{}); err == nil {
		t.Fatal("invalid reconstruction range succeeded")
	}
	for _, prefix := range []string{"", ".", "..", "a/b", `a\\b`, "a?b", "a#b"} {
		if err := validatePrefix(prefix); err == nil {
			t.Errorf("prefix %q validated", prefix)
		}
		if _, err := client.UploadXorb(context.Background(), prefix, xethash.Zero, nil); err == nil {
			t.Errorf("UploadXorb prefix %q succeeded", prefix)
		}
		if _, _, err := client.QueryGlobalDedup(context.Background(), prefix, xethash.Zero); err == nil {
			t.Errorf("QueryGlobalDedup prefix %q succeeded", prefix)
		}
		if _, err := client.XorbExists(context.Background(), prefix, xethash.Zero); err == nil {
			t.Errorf("XorbExists prefix %q succeeded", prefix)
		}
	}
}

func TestMissingAndMalformedObjectEndpoints(t *testing.T) {
	var mode string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch mode {
		case "missing":
			http.NotFound(w, r)
		case "bad-length":
			w.Header().Set("Content-Length", "bad")
		case "no-length":
			w.Header().Del("Content-Length")
		case "invalid-v1-result":
			if r.URL.Path == "/v2/shards" {
				http.NotFound(w, r)
				return
			}
			_, _ = io.WriteString(w, `{"result":7}`)
		default:
			http.Error(w, "failure", http.StatusBadRequest)
		}
	}))
	defer server.Close()
	client := testClient(t, serverURL(t, server.URL), "", Options{Retry: RetryPolicy{MaxAttempts: 1}})
	hash := xethash.Chunk([]byte("object"))

	mode = "missing"
	if data, found, err := client.QueryGlobalDedup(context.Background(), DefaultPrefix, hash); err != nil || found || data != nil {
		t.Fatalf("missing dedup = %q, %v, %v", data, found, err)
	}
	if found, err := client.XorbExists(context.Background(), DefaultPrefix, hash); err != nil || found {
		t.Fatalf("missing xorb = %v, %v", found, err)
	}
	if size, found, err := client.FileSize(context.Background(), hash); err != nil || found || size != 0 {
		t.Fatalf("missing file = %d, %v, %v", size, found, err)
	}

	mode = "bad-length"
	if _, _, err := client.FileSize(context.Background(), hash); err == nil {
		t.Fatal("invalid Content-Length succeeded")
	}
	mode = "no-length"
	if _, _, err := client.FileSize(context.Background(), hash); err == nil {
		t.Fatal("missing Content-Length succeeded")
	}
	mode = "invalid-v1-result"
	if err := client.UploadShard(context.Background(), []byte("shard"), nil); err == nil {
		t.Fatal("invalid v1 shard result succeeded")
	}
	mode = "error"
	if _, _, err := client.QueryGlobalDedup(context.Background(), DefaultPrefix, hash); err == nil {
		t.Fatal("dedup HTTP error succeeded")
	}
	if _, err := client.XorbExists(context.Background(), DefaultPrefix, hash); err == nil {
		t.Fatal("xorb HEAD HTTP error succeeded")
	}
	if _, _, err := client.FileSize(context.Background(), hash); err == nil {
		t.Fatal("file HEAD HTTP error succeeded")
	}
}

func TestRangeErrorMapping(t *testing.T) {
	original := errors.New("original")
	if mapRangeError(original) != original {
		t.Fatal("non-HTTP range error changed")
	}
	httpErr := &HTTPError{StatusCode: http.StatusRequestedRangeNotSatisfiable}
	if err := mapRangeError(httpErr); !errors.Is(err, ErrRangeNotSatisfiable) {
		t.Fatalf("mapped range error = %v", err)
	}
}

func TestResponseProcessorsRejectMalformedBodies(t *testing.T) {
	client := &Client{maxErrorBytes: 8}
	response := func(body string) *http.Response {
		return &http.Response{Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body))}
	}
	var value map[string]any
	if _, _, err := client.jsonProcessor(&value, 8)(response("{")); err == nil {
		t.Fatal("invalid JSON succeeded")
	}
	if _, _, err := client.jsonProcessor(&value, 1)(response("{}")); !errors.Is(err, errResponseTooLarge) {
		t.Fatalf("oversize JSON = %v", err)
	}
	if _, _, err := client.bytesProcessor(1)(response("xx")); !errors.Is(err, errResponseTooLarge) {
		t.Fatalf("oversize bytes = %v", err)
	}
	unsupported := &http.Response{
		Header: http.Header{"Content-Encoding": {"br"}},
		Body:   io.NopCloser(strings.NewReader("body")),
	}
	if _, _, err := client.bytesProcessor(8)(unsupported); err == nil {
		t.Fatal("unsupported binary response encoding succeeded")
	}
	malformed := &http.Response{
		Header: http.Header{"Content-Encoding": {","}},
		Body:   io.NopCloser(strings.NewReader("body")),
	}
	if _, _, err := client.bytesProcessor(8)(malformed); err == nil {
		t.Fatal("malformed response encoding succeeded")
	}
	zstdFailure := &http.Response{
		Header: http.Header{"Content-Encoding": {"zstd"}},
		Body:   io.NopCloser(strings.NewReader("not-a-zstd-frame")),
	}
	if _, _, err := client.bytesProcessor(8)(zstdFailure); err == nil {
		t.Fatal("unreadable zstd response succeeded")
	}
	wantClose := errors.New("decoder close failure")
	if err := closeDecoders([]func() error{
		func() error { return nil },
		func() error { return wantClose },
	}); !errors.Is(err, wantClose) {
		t.Fatalf("decoder close error = %v", err)
	}
}

type closeErrorBody struct {
	io.Reader
	err error
}

func (b closeErrorBody) Close() error { return b.err }

type dataErrorReader struct {
	data []byte
	err  error
}

func (r *dataErrorReader) Read(buffer []byte) (int, error) {
	if len(r.data) == 0 {
		return 0, r.err
	}
	n := copy(buffer, r.data)
	r.data = r.data[n:]
	return n, r.err
}

func TestCASCallTransportAndResourceContracts(t *testing.T) {
	want := errors.New("access failure")
	client, err := New(&errorAccessProvider{err: want}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := client.QueryGlobalDedup(context.Background(), DefaultPrefix, xethash.Zero); !errors.Is(err, want) {
		t.Fatalf("access error = %v", err)
	}

	var casUserAgent, storageUserAgent string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/signed" {
			storageUserAgent = r.Header.Get("User-Agent")
			w.Header().Set("Content-Range", "bytes 0-0/1")
			_, _ = io.WriteString(w, "x")
			return
		}
		casUserAgent = r.Header.Get("User-Agent")
		_, _ = io.WriteString(w, "metadata")
	}))
	defer server.Close()
	client = testClient(t, serverURL(t, server.URL), "", Options{UserAgent: "xet-go-contract-test"})
	if _, found, err := client.QueryGlobalDedup(context.Background(), DefaultPrefix, xethash.Zero); err != nil || !found {
		t.Fatalf("CAS request = found %v, error %v", found, err)
	}
	if _, err := client.FetchRanges(context.Background(), server.URL+"/signed", []HTTPRange{{Start: 0, End: 0}}); err != nil {
		t.Fatal(err)
	}
	if casUserAgent != "xet-go-contract-test" || storageUserAgent != "xet-go-contract-test" {
		t.Fatalf("user agents = CAS %q, storage %q", casUserAgent, storageUserAgent)
	}

	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := client.UploadXorb(canceled, DefaultPrefix, xethash.Zero, []byte("x")); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled upload permit = %v", err)
	}
	if _, err := client.FetchRanges(canceled, server.URL+"/signed", []HTTPRange{{Start: 0, End: 0}}); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled download permit = %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	transport := roundTripFunc(func(*http.Request) (*http.Response, error) {
		cancel()
		return nil, io.ErrUnexpectedEOF
	})
	client = testClient(t, serverURL(t, "https://cas.invalid"), "", Options{
		HTTPClient: &http.Client{Transport: transport},
		Retry:      RetryPolicy{MaxAttempts: 2},
	})
	if _, _, err := client.QueryGlobalDedup(ctx, DefaultPrefix, xethash.Zero); !errors.Is(err, context.Canceled) {
		t.Fatalf("transport cancellation = %v", err)
	}

	want = errors.New("retry sleep failure")
	transport = roundTripFunc(func(*http.Request) (*http.Response, error) { return nil, io.ErrUnexpectedEOF })
	client = testClient(t, serverURL(t, "https://cas.invalid"), "", Options{
		HTTPClient: &http.Client{Transport: transport},
		Retry: RetryPolicy{MaxAttempts: 2, Sleep: func(context.Context, time.Duration) error {
			return want
		}},
	})
	if _, _, err := client.QueryGlobalDedup(context.Background(), DefaultPrefix, xethash.Zero); !errors.Is(err, want) {
		t.Fatalf("transport retry sleep error = %v", err)
	}

	transport = roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("x"))}, nil
	})
	client = testClient(t, serverURL(t, "https://cas.invalid"), "", Options{
		HTTPClient: &http.Client{Transport: transport},
		Retry: RetryPolicy{MaxAttempts: 2, Sleep: func(context.Context, time.Duration) error {
			return want
		}},
	})
	_, err = client.casCall(context.Background(), AccessRead, http.MethodGet, "retry", nil, nil,
		func(*http.Response) (any, bool, error) { return nil, true, io.ErrUnexpectedEOF })
	if !errors.Is(err, want) {
		t.Fatalf("processor retry sleep error = %v", err)
	}

	want = errors.New("body close failure")
	transport = roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     make(http.Header),
			Body:       closeErrorBody{Reader: strings.NewReader("metadata"), err: want},
		}, nil
	})
	client = testClient(t, serverURL(t, "https://cas.invalid"), "", Options{
		HTTPClient: &http.Client{Transport: transport},
		Retry:      RetryPolicy{MaxAttempts: 1},
	})
	if _, _, err := client.QueryGlobalDedup(context.Background(), DefaultPrefix, xethash.Zero); !errors.Is(err, want) {
		t.Fatalf("CAS close error = %v", err)
	}
	if _, err := client.FetchRanges(context.Background(), "https://storage.invalid/signed", []HTTPRange{{Start: 0, End: 7}}); !errors.Is(err, want) {
		t.Fatalf("signed response close error = %v", err)
	}

	var delay time.Duration
	client.retry = RetryPolicy{
		InitialBackoff: 2 * time.Second,
		MaximumBackoff: 3 * time.Second,
		Sleep: func(_ context.Context, value time.Duration) error {
			delay = value
			return nil
		},
	}
	if err := client.waitRetry(context.Background(), 1, ""); err != nil || delay > 3*time.Second {
		t.Fatalf("bounded exponential retry = %v, %v", delay, err)
	}
}

func TestEndpointFallbackAndValidationFailures(t *testing.T) {
	var mode string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch mode {
		case "batch status":
			http.Error(w, "bad request", http.StatusBadRequest)
		case "batch fallback":
			if r.Method == http.MethodPost {
				http.NotFound(w, r)
				return
			}
			http.Error(w, "fallback failed", http.StatusInternalServerError)
		case "file status":
			http.Error(w, "failed", http.StatusBadRequest)
		case "file invalid":
			_, _ = io.WriteString(w, `{}`)
		case "reconstruction invalid":
			_, _ = io.WriteString(w, `{"offset_into_first_range":1}`)
		case "reconstruction fallback status":
			if strings.HasPrefix(r.URL.Path, "/v2/") {
				http.NotFound(w, r)
				return
			}
			http.Error(w, "fallback failed", http.StatusInternalServerError)
		case "reconstruction fallback invalid":
			if strings.HasPrefix(r.URL.Path, "/v2/") {
				http.NotFound(w, r)
				return
			}
			_, _ = io.WriteString(w, `{"offset_into_first_range":1}`)
		case "shard fallback status":
			if r.URL.Path == "/v2/shards" {
				http.NotFound(w, r)
				return
			}
			http.Error(w, "fallback failed", http.StatusInternalServerError)
		case "shard fallback success":
			if r.URL.Path == "/v2/shards" {
				http.NotFound(w, r)
				return
			}
			_, _ = io.WriteString(w, `{"result":0}`)
		}
	}))
	defer server.Close()
	newClient := func() *Client {
		return testClient(t, serverURL(t, server.URL), "", Options{Retry: RetryPolicy{MaxAttempts: 1}})
	}

	hash := xethash.Chunk([]byte("file"))
	mode = "batch status"
	if _, err := newClient().BatchQueryReconstruction(context.Background(), []xethash.Hash{hash}); err == nil {
		t.Fatal("non-fallback batch status succeeded")
	}
	mode = "batch fallback"
	if _, err := newClient().BatchQueryReconstruction(context.Background(), []xethash.Hash{hash}); err == nil {
		t.Fatal("failed batch fallback succeeded")
	}
	mode = "file status"
	if _, err := newClient().QueryFileChunkHashes(context.Background(), hash, []FileRange{{Start: 0, End: 1}}); err == nil {
		t.Fatal("failed chunk-hash query succeeded")
	}
	mode = "file invalid"
	if _, err := newClient().QueryFileChunkHashes(context.Background(), hash, []FileRange{{Start: 0, End: 1}}); err == nil {
		t.Fatal("invalid chunk-hash response succeeded")
	}
	mode = "reconstruction invalid"
	if _, err := newClient().QueryReconstruction(context.Background(), hash, nil); err == nil {
		t.Fatal("invalid v2 reconstruction succeeded")
	}
	mode = "reconstruction fallback status"
	if _, err := newClient().QueryReconstruction(context.Background(), hash, nil); err == nil {
		t.Fatal("failed v1 reconstruction fallback succeeded")
	}
	mode = "reconstruction fallback invalid"
	if _, err := newClient().QueryReconstruction(context.Background(), hash, nil); err == nil {
		t.Fatal("invalid v1 reconstruction fallback succeeded")
	}
	mode = "shard fallback status"
	if err := newClient().UploadShard(context.Background(), []byte("shard"), nil); err == nil {
		t.Fatal("failed v1 shard fallback succeeded")
	}
	mode = "shard fallback success"
	var events []ShardUploadEvent
	if err := newClient().UploadShard(context.Background(), []byte("shard"), func(event ShardUploadEvent) {
		events = append(events, event)
	}); err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 || events[0].Type != "result" {
		t.Fatalf("v1 shard progress = %#v", events)
	}
}

func TestNDJSONReadFailuresAndMissingMessage(t *testing.T) {
	client := &Client{maxResponseBytes: 1 << 20}
	for _, test := range []struct {
		name string
		body io.ReadCloser
	}{
		{"blank read failure", io.NopCloser(&dataErrorReader{err: io.ErrUnexpectedEOF})},
		{"nonblank read failure", io.NopCloser(&dataErrorReader{data: []byte(`{"type":"future"}`), err: io.ErrUnexpectedEOF})},
	} {
		t.Run(test.name, func(t *testing.T) {
			response := &http.Response{Header: make(http.Header), Body: test.body}
			if _, retry, err := client.ndjsonProcessor(nil)(response); !errors.Is(err, io.ErrUnexpectedEOF) || !retry {
				t.Fatalf("read error = %v, retry = %v", err, retry)
			}
		})
	}
	response := &http.Response{
		Header: make(http.Header),
		Body:   io.NopCloser(strings.NewReader(`{"type":"error"}` + "\n")),
	}
	if _, retry, err := client.ndjsonProcessor(nil)(response); err == nil || retry || !strings.Contains(err.Error(), "unspecified") {
		t.Fatalf("unspecified error = %v, retry = %v", err, retry)
	}
	response = &http.Response{
		Header: http.Header{"Content-Encoding": {"br"}},
		Body:   io.NopCloser(strings.NewReader("ignored")),
	}
	if _, _, err := client.ndjsonProcessor(nil)(response); err == nil {
		t.Fatal("unsupported NDJSON encoding succeeded")
	}
}

func TestFileSizeRejectsTransportHeader(t *testing.T) {
	transport := roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{"Content-Length": {"not-a-number"}},
			Body:       io.NopCloser(strings.NewReader("")),
		}, nil
	})
	client := testClient(t, serverURL(t, "https://cas.invalid"), "", Options{
		HTTPClient: &http.Client{Transport: transport},
		Retry:      RetryPolicy{MaxAttempts: 1},
	})
	if _, _, err := client.FileSize(context.Background(), xethash.Zero); err == nil {
		t.Fatal("invalid transport Content-Length succeeded")
	}
}

func TestFetchRangesInputContracts(t *testing.T) {
	client := testClient(t, serverURL(t, "https://cas.invalid"), "", Options{MaxResponseBytes: 3})
	if _, err := client.FetchRanges(context.Background(), "relative", []HTTPRange{{0, 0}}); err == nil {
		t.Fatal("relative signed URL succeeded")
	}
	if _, err := client.FetchRanges(context.Background(), "https://storage.example/x", nil); err == nil {
		t.Fatal("empty range list succeeded")
	}
	if _, err := client.FetchRanges(context.Background(), "https://storage.example/x", []HTTPRange{{2, 1}}); err == nil {
		t.Fatal("invalid range succeeded")
	}
	if _, err := client.FetchRanges(context.Background(), "https://storage.example/x", []HTTPRange{{0, 0}, {0, 0}}); err == nil {
		t.Fatal("duplicate range succeeded")
	}
	if _, err := client.FetchRanges(context.Background(), "https://storage.example/x", []HTTPRange{{0, 3}}); err == nil {
		t.Fatal("range above response limit succeeded")
	}
	client.maxResponseBytes = 1<<63 - 1
	if _, err := client.FetchRanges(context.Background(), "https://storage.example/x", []HTTPRange{{0, ^uint64(0) - 1}, {^uint64(0), ^uint64(0)}}); err == nil {
		t.Fatal("overflowing range total succeeded")
	}
}

func TestFetchRangesHTTPAndSingleResponseContracts(t *testing.T) {
	var mode string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		switch mode {
		case "status":
			http.Error(w, "teapot", http.StatusTeapot)
		case "short":
			_, _ = io.WriteString(w, "x")
		case "invalid range":
			w.Header().Set("Content-Range", "invalid")
			_, _ = io.WriteString(w, "xx")
		case "mismatch":
			w.Header().Set("Content-Range", "bytes 2-3/10")
			_, _ = io.WriteString(w, "xx")
		default:
			w.Header().Set("Content-Range", "bytes 0-1/10")
			_, _ = io.WriteString(w, "xx")
		}
	}))
	defer server.Close()
	client := testClient(t, serverURL(t, "https://cas.invalid"), "", Options{Retry: RetryPolicy{MaxAttempts: 1}})
	ranges := []HTTPRange{{0, 1}}
	parts, err := client.FetchRanges(context.Background(), server.URL, ranges)
	if err != nil || len(parts) != 1 || string(parts[0].Data) != "xx" {
		t.Fatalf("single range = %#v, %v", parts, err)
	}
	for _, failure := range []string{"status", "short", "invalid range", "mismatch"} {
		mode = failure
		if _, err := client.FetchRanges(context.Background(), server.URL, ranges); err == nil {
			t.Errorf("%s response succeeded", failure)
		}
	}
}

func TestDecodeRangeResponseContentTypeContracts(t *testing.T) {
	client := &Client{maxResponseBytes: 1 << 20}
	response := func(contentType string) *http.Response {
		return &http.Response{Header: http.Header{"Content-Type": {contentType}}, Body: io.NopCloser(strings.NewReader("body"))}
	}
	ranges := []HTTPRange{{0, 0}, {2, 2}}
	if _, err := client.decodeRangeResponse(response("text/plain"), ranges, 2); err == nil {
		t.Fatal("non-multipart multi-range response succeeded")
	}
	if _, err := client.decodeRangeResponse(response("multipart/byteranges"), ranges, 2); err == nil {
		t.Fatal("multipart response without boundary succeeded")
	}
	if _, err := client.decodeRangeResponse(response("multipart/byteranges; boundary=x"), []HTTPRange{{0, 0}}, 1); err == nil {
		t.Fatal("empty multipart response succeeded")
	}

	for _, value := range []string{"bytes x-1/2", "bytes 0-x/2", "bytes 0-1/x", "bytes 0-2/2", "bytes 0-1/0", "bytes 0/2", "bytes -1/2"} {
		if _, err := parseContentRange(value); err == nil {
			t.Errorf("Content-Range %q parsed", value)
		}
	}

	multipartResponse := func(body string) *http.Response {
		return &http.Response{
			Header: http.Header{"Content-Type": {"multipart/byteranges; boundary=b"}},
			Body:   io.NopCloser(strings.NewReader(body)),
		}
	}
	for name, body := range map[string]string{
		"malformed header": "--b\r\nBad Header\r\n\r\nx\r\n--b--\r\n",
		"invalid range":    "--b\r\nContent-Range: invalid\r\n\r\nx\r\n--b--\r\n",
		"oversize part":    "--b\r\nContent-Range: bytes 0-0/3\r\n\r\nxx\r\n--b--\r\n",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := client.decodeRangeResponse(multipartResponse(body), []HTTPRange{{Start: 0, End: 0}}, 1); err == nil {
				t.Fatal("malformed multipart response succeeded")
			}
		})
	}
	omitted := "--b\r\nContent-Range: bytes 0-0/3\r\n\r\nx\r\n--b--\r\n"
	if _, err := client.decodeRangeResponse(multipartResponse(omitted), ranges, 2); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("omitted multipart range = %v", err)
	}
	readFailure := &http.Response{
		Header: http.Header{"Content-Type": {"multipart/byteranges; boundary=b"}},
		Body:   io.NopCloser(errorReader{err: io.ErrUnexpectedEOF}),
	}
	if _, err := client.decodeRangeResponse(readFailure, ranges, 2); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("multipart body read failure = %v", err)
	}
	singleReadFailure := &http.Response{
		Header: make(http.Header),
		Body:   io.NopCloser(errorReader{err: io.ErrUnexpectedEOF}),
	}
	if _, err := client.decodeRangeResponse(singleReadFailure, []HTTPRange{{Start: 0, End: 0}}, 1); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("single-range body read failure = %v", err)
	}
	if _, err := parseContentRange("bytes 0-0/not-a-size"); err == nil {
		t.Fatal("invalid Content-Range total succeeded")
	}
}

func TestFetchRangesRetryContracts(t *testing.T) {
	rangeOne := []HTTPRange{{Start: 0, End: 0}}
	response := func(status int, body string) *http.Response {
		return &http.Response{
			StatusCode: status,
			Header:     http.Header{"Content-Range": {"bytes 0-0/1"}},
			Body:       io.NopCloser(strings.NewReader(body)),
		}
	}
	newClient := func(transport http.RoundTripper, sleep func(context.Context, time.Duration) error) *Client {
		return testClient(t, serverURL(t, "https://cas.invalid"), "", Options{
			HTTPClient: &http.Client{Transport: transport},
			Retry:      RetryPolicy{MaxAttempts: 2, Sleep: sleep},
		})
	}

	ctx, cancel := context.WithCancel(context.Background())
	client := newClient(roundTripFunc(func(*http.Request) (*http.Response, error) {
		cancel()
		return nil, io.ErrUnexpectedEOF
	}), func(context.Context, time.Duration) error { return nil })
	if _, err := client.FetchRanges(ctx, "https://storage.invalid/x", rangeOne); !errors.Is(err, context.Canceled) {
		t.Fatalf("signed transport cancellation = %v", err)
	}

	want := errors.New("signed retry sleep failure")
	client = newClient(roundTripFunc(func(*http.Request) (*http.Response, error) {
		return nil, io.ErrUnexpectedEOF
	}), func(context.Context, time.Duration) error { return want })
	if _, err := client.FetchRanges(context.Background(), "https://storage.invalid/x", rangeOne); !errors.Is(err, want) {
		t.Fatalf("signed network retry sleep = %v", err)
	}

	var calls int
	client = newClient(roundTripFunc(func(*http.Request) (*http.Response, error) {
		calls++
		if calls == 1 {
			return response(http.StatusServiceUnavailable, "busy"), nil
		}
		return response(http.StatusPartialContent, "x"), nil
	}), func(context.Context, time.Duration) error { return nil })
	if values, err := client.FetchRanges(context.Background(), "https://storage.invalid/x", rangeOne); err != nil || len(values) != 1 || string(values[0].Data) != "x" || calls != 2 {
		t.Fatalf("transient signed fetch = %#v, calls %d, error %v", values, calls, err)
	}

	client = newClient(roundTripFunc(func(*http.Request) (*http.Response, error) {
		return response(http.StatusServiceUnavailable, "busy"), nil
	}), func(context.Context, time.Duration) error { return want })
	if _, err := client.FetchRanges(context.Background(), "https://storage.invalid/x", rangeOne); !errors.Is(err, want) {
		t.Fatalf("signed status retry sleep = %v", err)
	}

	client = testClient(t, serverURL(t, "https://cas.invalid"), "", Options{
		HTTPClient: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			return response(http.StatusServiceUnavailable, "busy"), nil
		})},
		Retry: RetryPolicy{MaxAttempts: 1},
	})
	if _, err := client.FetchRanges(context.Background(), "https://storage.invalid/x", rangeOne); err == nil {
		t.Fatal("terminal transient signed status succeeded")
	}

	calls = 0
	client = newClient(roundTripFunc(func(*http.Request) (*http.Response, error) {
		calls++
		if calls == 1 {
			return response(http.StatusPartialContent, ""), nil
		}
		return response(http.StatusPartialContent, "x"), nil
	}), func(context.Context, time.Duration) error { return nil })
	if _, err := client.FetchRanges(context.Background(), "https://storage.invalid/x", rangeOne); err != nil || calls != 2 {
		t.Fatalf("truncated signed retry = calls %d, error %v", calls, err)
	}

	client = newClient(roundTripFunc(func(*http.Request) (*http.Response, error) {
		return response(http.StatusPartialContent, ""), nil
	}), func(context.Context, time.Duration) error { return want })
	if _, err := client.FetchRanges(context.Background(), "https://storage.invalid/x", rangeOne); !errors.Is(err, want) {
		t.Fatalf("truncated retry sleep = %v", err)
	}
}
