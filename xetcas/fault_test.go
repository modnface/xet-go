package xetcas

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jacobwoliver/xet-go/xethash"
	"github.com/klauspost/compress/zstd"
)

func TestCompressedReconstructionResponses(t *testing.T) {
	for _, encoding := range []string{"gzip", "zstd", "gzip, zstd"} {
		t.Run(strings.ReplaceAll(encoding, ", ", "_"), func(t *testing.T) {
			payload := []byte(emptyReconstructionJSON())
			encoded := encodeResponse(t, payload, encoding)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if got := r.Header.Get("Accept-Encoding"); got != "gzip, zstd" {
					t.Errorf("Accept-Encoding = %q", got)
				}
				if got := r.Header.Get("Range"); got != "bytes=0-0" {
					t.Errorf("Range = %q", got)
				}
				w.Header().Set("Content-Encoding", encoding)
				_, _ = w.Write(encoded)
			}))
			defer server.Close()
			client := testClient(t, serverURL(t, server.URL), "", Options{})
			value, err := client.QueryReconstruction(context.Background(), xethash.Zero, &FileRange{Start: 0, End: 1})
			if err != nil || value == nil || len(value.Terms) != 0 {
				t.Fatalf("value=%#v error=%v", value, err)
			}
		})
	}
}

func TestCompressedBinaryAndNDJSONResponses(t *testing.T) {
	t.Run("binary", func(t *testing.T) {
		encoded := encodeResponse(t, []byte("protected-shard"), "gzip")
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Encoding", "gzip")
			_, _ = w.Write(encoded)
		}))
		defer server.Close()
		client := testClient(t, serverURL(t, server.URL), "", Options{})
		data, found, err := client.QueryGlobalDedup(context.Background(), DefaultDedupPrefix, xethash.Zero)
		if err != nil || !found || string(data) != "protected-shard" {
			t.Fatalf("data=%q found=%v error=%v", data, found, err)
		}
	})

	t.Run("ndjson", func(t *testing.T) {
		encoded := encodeResponse(t, []byte("{\"type\":\"result\"}\n"), "zstd")
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Encoding", "zstd")
			_, _ = w.Write(encoded)
		}))
		defer server.Close()
		client := testClient(t, serverURL(t, server.URL), "", Options{})
		if err := client.UploadShard(context.Background(), []byte("shard"), nil); err != nil {
			t.Fatal(err)
		}
	})
}

func TestCompressedResponseLimitsAndCorruption(t *testing.T) {
	var requests atomic.Int32
	encoded := encodeResponse(t, append([]byte(emptyReconstructionJSON()), bytes.Repeat([]byte(" "), 4096)...), "gzip")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		w.Header().Set("Content-Encoding", "gzip")
		_, _ = w.Write(encoded)
	}))
	defer server.Close()
	client := testClient(t, serverURL(t, server.URL), "", Options{MaxResponseBytes: 64})
	_, err := client.QueryReconstruction(context.Background(), xethash.Zero, nil)
	if !errors.Is(err, errResponseTooLarge) || requests.Load() != 1 {
		t.Fatalf("error=%v requests=%d", err, requests.Load())
	}

	requests.Store(0)
	corrupt := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		w.Header().Set("Content-Encoding", "gzip")
		_, _ = w.Write([]byte("not-gzip"))
	}))
	defer corrupt.Close()
	client = testClient(t, serverURL(t, corrupt.URL), "", Options{})
	if _, err := client.QueryReconstruction(context.Background(), xethash.Zero, nil); err == nil || requests.Load() != 1 {
		t.Fatalf("corrupt encoding error=%v requests=%d", err, requests.Load())
	}

	unsupported := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Encoding", "br")
		_, _ = io.WriteString(w, "ignored")
	}))
	defer unsupported.Close()
	client = testClient(t, serverURL(t, unsupported.URL), "", Options{})
	if _, err := client.QueryReconstruction(context.Background(), xethash.Zero, nil); err == nil || !strings.Contains(err.Error(), "unsupported Content-Encoding") {
		t.Fatalf("unsupported encoding error=%v", err)
	}
}

func TestRepeated401StopsAfterOneRefresh(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		http.Error(w, "still unauthorized", http.StatusUnauthorized)
	}))
	defer server.Close()
	provider := &rotatingProvider{endpoint: serverURL(t, server.URL)}
	client, err := New(provider, Options{Retry: RetryPolicy{MaxAttempts: 4, Sleep: func(context.Context, time.Duration) error { return nil }}})
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.QueryReconstruction(context.Background(), xethash.Zero, nil)
	var httpErr *HTTPError
	if !errors.As(err, &httpErr) || httpErr.StatusCode != http.StatusUnauthorized {
		t.Fatalf("error=%v", err)
	}
	provider.mu.Lock()
	defer provider.mu.Unlock()
	if requests.Load() != 2 || provider.calls != 2 || provider.invalidates != 1 {
		t.Fatalf("requests=%d access=%d invalidates=%d", requests.Load(), provider.calls, provider.invalidates)
	}
}

func TestRetryAfterDateDeltaExhaustionAndCancellation(t *testing.T) {
	fixed := time.Date(2026, time.July, 31, 12, 0, 0, 0, time.UTC)
	for _, test := range []struct {
		name       string
		retryAfter string
		want       time.Duration
	}{
		{"delta", "2", 2 * time.Second},
		{"date", fixed.Add(3 * time.Second).Format(http.TimeFormat), 3 * time.Second},
		{"clamped", fixed.Add(time.Minute).Format(http.TimeFormat), 5 * time.Second},
		{"past", fixed.Add(-time.Second).Format(http.TimeFormat), 0},
	} {
		t.Run(test.name, func(t *testing.T) {
			var requests atomic.Int32
			var delay time.Duration
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				if requests.Add(1) == 1 {
					w.Header().Set("Retry-After", test.retryAfter)
					http.Error(w, "busy", http.StatusTooManyRequests)
					return
				}
				_, _ = io.WriteString(w, emptyReconstructionJSON())
			}))
			defer server.Close()
			client := testClient(t, serverURL(t, server.URL), "", Options{
				Now: fixedTime(fixed),
				Retry: RetryPolicy{MaximumBackoff: 5 * time.Second, Sleep: func(_ context.Context, value time.Duration) error {
					delay = value
					return nil
				}},
			})
			if _, err := client.QueryReconstruction(context.Background(), xethash.Zero, nil); err != nil {
				t.Fatal(err)
			}
			if delay != test.want || requests.Load() != 2 {
				t.Fatalf("delay=%v requests=%d", delay, requests.Load())
			}
		})
	}

	var requests atomic.Int32
	exhausted := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		http.Error(w, "busy", http.StatusServiceUnavailable)
	}))
	defer exhausted.Close()
	var sleeps atomic.Int32
	client := testClient(t, serverURL(t, exhausted.URL), "", Options{Retry: RetryPolicy{
		MaxAttempts: 3, Sleep: func(context.Context, time.Duration) error { sleeps.Add(1); return nil },
	}})
	_, err := client.QueryReconstruction(context.Background(), xethash.Zero, nil)
	var httpErr *HTTPError
	if !errors.As(err, &httpErr) || httpErr.StatusCode != http.StatusServiceUnavailable || requests.Load() != 3 || sleeps.Load() != 2 {
		t.Fatalf("error=%v requests=%d sleeps=%d", err, requests.Load(), sleeps.Load())
	}

	ctx, cancel := context.WithCancel(context.Background())
	requests.Store(0)
	client = testClient(t, serverURL(t, exhausted.URL), "", Options{Retry: RetryPolicy{
		Sleep: func(ctx context.Context, _ time.Duration) error {
			cancel()
			return ctx.Err()
		},
	}})
	_, err = client.QueryReconstruction(ctx, xethash.Zero, nil)
	if !errors.Is(err, context.Canceled) || requests.Load() != 1 {
		t.Fatalf("cancellation error=%v requests=%d", err, requests.Load())
	}
}

func TestNetworkErrorsRedactSignedURL(t *testing.T) {
	const secret = "X-Amz-Credential=credential-secret"
	transport := roundTripFunc(func(request *http.Request) (*http.Response, error) {
		return nil, fmt.Errorf("storage rejected %s", request.URL.String())
	})
	client := testClient(t, serverURL(t, "https://cas.invalid"), "cas-secret", Options{HTTPClient: &http.Client{Transport: transport}})
	_, err := client.FetchRanges(context.Background(), "https://storage.invalid/object?"+secret, []HTTPRange{{Start: 0, End: 0}})
	if err == nil || strings.Contains(err.Error(), secret) || strings.Contains(err.Error(), "credential-secret") {
		t.Fatalf("unsafe error=%v", err)
	}
	var transportErr *transportFailure
	if !errors.As(err, &transportErr) {
		t.Fatalf("transport cause is not preserved: %T", err)
	}
}

func TestNDJSONStructuralFaults(t *testing.T) {
	tests := []struct {
		name string
		body string
		max  int64
		want error
	}{
		{"invalid_json", "{\n", 1 << 20, nil},
		{"invalid_progress", "{\"type\":\"validating\",\"verified\":2,\"total\":1}\n", 1 << 20, nil},
		{"invalid_stage", "{\"type\":\"committing\",\"stage\":\"bad\"}\n", 1 << 20, nil},
		{"nonretryable_error", "{\"type\":\"error\",\"message\":\"no\"}\n", 1 << 20, nil},
		{"missing_terminal", "{\"type\":\"unknown\"}\n", 1 << 20, ErrMissingTerminal},
		{"oversize_line", strings.Repeat("x", defaultMaxNDJSONLine+1), 2 << 20, nil},
		{"oversize_stream", strings.Repeat("{\"type\":\"unknown\"}\n", 8), 64, errResponseTooLarge},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			client := &Client{maxResponseBytes: test.max}
			response := &http.Response{Header: make(http.Header), Body: io.NopCloser(strings.NewReader(test.body))}
			_, retry, err := client.ndjsonProcessor(nil)(response)
			if err == nil || retry || (test.want != nil && !errors.Is(err, test.want)) {
				t.Fatalf("error=%v retry=%v", err, retry)
			}
		})
	}

	client := &Client{maxResponseBytes: 1 << 20}
	response := &http.Response{Header: make(http.Header), Body: io.NopCloser(strings.NewReader("\n{\"type\":\"future\"}\n{\"type\":\"result\"}\n"))}
	var events []ShardUploadEvent
	if _, _, err := client.ndjsonProcessor(func(event ShardUploadEvent) { events = append(events, event) })(response); err != nil {
		t.Fatal(err)
	}
	if len(events) != 2 || events[0].Type != "future" || events[1].Type != "result" {
		t.Fatalf("events=%#v", events)
	}
}

func TestMultipartStructuralFaults(t *testing.T) {
	ranges := []HTTPRange{{Start: 0, End: 0}, {Start: 2, End: 2}}
	tests := []struct {
		name string
		body string
	}{
		{"missing", multipartBody("bytes 0-0/3", "a")},
		{"duplicate", multipartBody("bytes 0-0/3", "a") + multipartBody("bytes 0-0/3", "a")},
		{"unexpected", multipartBody("bytes 0-0/3", "a") + multipartBody("bytes 1-1/3", "b")},
		{"wrong_length", multipartBody("bytes 0-0/3", "ab") + multipartBody("bytes 2-2/3", "c")},
		{"invalid_range", multipartBody("invalid", "a")},
		{"truncated", "--fault\r\nContent-Range: bytes 0-0/3\r\n\r\na"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			body := test.body
			if test.name != "truncated" {
				body += "--fault--\r\n"
			}
			client := &Client{maxResponseBytes: 1 << 20}
			response := &http.Response{
				Header: http.Header{"Content-Type": []string{"multipart/byteranges; boundary=fault"}},
				Body:   io.NopCloser(strings.NewReader(body)),
			}
			if _, err := client.decodeRangeResponse(response, ranges, 2); err == nil {
				t.Fatal("malformed multipart response accepted")
			}
		})
	}
}

func encodeResponse(t testing.TB, data []byte, encoding string) []byte {
	t.Helper()
	result := append([]byte(nil), data...)
	for _, value := range strings.Split(encoding, ",") {
		switch strings.TrimSpace(value) {
		case "gzip":
			var output bytes.Buffer
			writer := gzip.NewWriter(&output)
			if _, err := writer.Write(result); err != nil {
				t.Fatal(err)
			}
			if err := writer.Close(); err != nil {
				t.Fatal(err)
			}
			result = output.Bytes()
		case "zstd":
			writer, err := zstd.NewWriter(nil, zstd.WithEncoderConcurrency(1))
			if err != nil {
				t.Fatal(err)
			}
			result = writer.EncodeAll(result, nil)
			if err := writer.Close(); err != nil {
				t.Fatal(err)
			}
		default:
			t.Fatalf("unknown test encoding %q", value)
		}
	}
	return result
}

func multipartBody(contentRange, data string) string {
	return "--fault\r\nContent-Range: " + contentRange + "\r\n\r\n" + data + "\r\n"
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) { return f(request) }

func fixedTime(value time.Time) func() time.Time { return func() time.Time { return value } }

func TestDecodeResponseRejectsMissingBody(t *testing.T) {
	_, _, err := decodeResponse(&http.Response{Header: make(http.Header)}, 1)
	if err == nil {
		t.Fatal("missing response body accepted")
	}
	_, _, err = decodeResponse(&http.Response{Header: make(http.Header), Body: io.NopCloser(strings.NewReader(""))}, 0)
	if err == nil {
		t.Fatal("zero response limit accepted")
	}
}

func FuzzDecodeContentEncoding(f *testing.F) {
	f.Add("identity", []byte("plain"), uint16(32))
	f.Add("gzip", encodeResponse(f, []byte("gzip"), "gzip"), uint16(32))
	f.Add("zstd", encodeResponse(f, []byte("zstd"), "zstd"), uint16(32))
	f.Add("gzip, zstd", encodeResponse(f, []byte("stacked"), "gzip, zstd"), uint16(32))
	f.Add("gzip", []byte("corrupt"), uint16(1))
	f.Fuzz(func(t *testing.T, encoding string, data []byte, rawLimit uint16) {
		if len(data) > 1<<20 {
			return
		}
		limit := int64(rawLimit) + 1
		response := &http.Response{
			Header: http.Header{"Content-Encoding": []string{encoding}},
			Body:   io.NopCloser(bytes.NewReader(data)),
		}
		reader, closeDecoder, err := decodeResponse(response, limit)
		if err != nil {
			return
		}
		_, _ = readLimited(reader, limit)
		_ = closeDecoder()
	})
}

func TestValidateSignedURLStillRejectsCredentials(t *testing.T) {
	for _, raw := range []string{"http://user:pass@example.com/x", "ftp://example.com/x", "/relative", "http://example.com/x#fragment"} {
		if err := validateSignedURL(raw); err == nil {
			t.Errorf("accepted %q", raw)
		}
	}
	if err := validateSignedURL((&url.URL{Scheme: "https", Host: "example.com", Path: "/x", RawQuery: "signature=allowed"}).String()); err != nil {
		t.Fatal(err)
	}
}
