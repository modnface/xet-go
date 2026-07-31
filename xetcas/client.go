package xetcas

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/jacobwoliver/xet-go/xethash"
)

const (
	SessionIDHeader       = "X-Xet-Session-Id"
	RequestIDHeader       = "X-Request-Id"
	DirtyRangeHeader      = "X-Range-Dirty"
	defaultMaxResponse    = 160 << 20
	defaultMaxErrorBody   = 16 << 10
	defaultMaxNDJSONLine  = 1 << 20
	defaultMaxAttempts    = 4
	defaultInitialBackoff = 100 * time.Millisecond
	defaultMaximumBackoff = 5 * time.Second
	defaultAccessLeadTime = 30 * time.Second
)

// HTTPError is a sanitized non-success CAS or object-storage response. URL
// never includes credentials, query parameters, or fragments.
type HTTPError struct {
	Method     string
	URL        string
	StatusCode int
	RequestID  string
	Body       string
}

func (e *HTTPError) Error() string {
	requestID := ""
	if e.RequestID != "" {
		requestID = ", request " + e.RequestID
	}
	return fmt.Sprintf("xet CAS: %s %s returned %d%s", e.Method, e.URL, e.StatusCode, requestID)
}

// RetryPolicy controls replay-safe HTTP retries. The zero value uses bounded
// production defaults. Sleep is primarily an injection point for tests.
type RetryPolicy struct {
	MaxAttempts    int
	InitialBackoff time.Duration
	MaximumBackoff time.Duration
	Sleep          func(context.Context, time.Duration) error
}

// Options configures a Client. HTTPClient is shallow-copied and redirects are
// disabled so bearer tokens and signed URL authority cannot cross origins.
type Options struct {
	HTTPClient       *http.Client
	Retry            RetryPolicy
	RefreshBefore    time.Duration
	MaxResponseBytes int64
	MaxErrorBytes    int64
	SessionID        string
	UserAgent        string
	Now              func() time.Time
}

// Client implements Xet CAS requests and signed object-storage retrieval.
type Client struct {
	http              *http.Client
	access            accessCache
	retry             RetryPolicy
	maxResponseBytes  int64
	maxErrorBytes     int64
	sessionID         string
	userAgent         string
	reconstructionAPI atomic.Uint32
	shardAPI          atomic.Uint32
}

func New(provider CASAccessProvider, options Options) (*Client, error) {
	if provider == nil {
		return nil, errors.New("xet CAS: nil access provider")
	}
	now := options.Now
	if now == nil {
		now = time.Now
	}
	refreshBefore := options.RefreshBefore
	if refreshBefore == 0 {
		refreshBefore = defaultAccessLeadTime
	}
	if refreshBefore < 0 {
		return nil, errors.New("xet CAS: RefreshBefore must not be negative")
	}
	retry, err := normalizeRetry(options.Retry)
	if err != nil {
		return nil, err
	}
	maxResponse := options.MaxResponseBytes
	if maxResponse == 0 {
		maxResponse = defaultMaxResponse
	}
	maxError := options.MaxErrorBytes
	if maxError == 0 {
		maxError = defaultMaxErrorBody
	}
	if maxResponse < 1 || maxError < 1 {
		return nil, errors.New("xet CAS: response limits must be positive")
	}
	httpClient := &http.Client{}
	if options.HTTPClient != nil {
		*httpClient = *options.HTTPClient
	}
	// Xet CAS authentication is bearer-only. A caller's cookie jar could leak
	// unrelated ambient credentials to CAS or signed storage origins.
	httpClient.Jar = nil
	httpClient.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}
	return &Client{
		http:             httpClient,
		access:           accessCache{provider: provider, refreshBefore: refreshBefore, now: now},
		retry:            retry,
		maxResponseBytes: maxResponse,
		maxErrorBytes:    maxError,
		sessionID:        options.SessionID,
		userAgent:        options.UserAgent,
	}, nil
}

func normalizeRetry(policy RetryPolicy) (RetryPolicy, error) {
	if policy.MaxAttempts == 0 {
		policy.MaxAttempts = defaultMaxAttempts
	}
	if policy.InitialBackoff == 0 {
		policy.InitialBackoff = defaultInitialBackoff
	}
	if policy.MaximumBackoff == 0 {
		policy.MaximumBackoff = defaultMaximumBackoff
	}
	if policy.Sleep == nil {
		policy.Sleep = sleepContext
	}
	if policy.MaxAttempts < 1 || policy.InitialBackoff < 0 || policy.MaximumBackoff < policy.InitialBackoff {
		return RetryPolicy{}, errors.New("xet CAS: invalid retry policy")
	}
	return policy, nil
}

func sleepContext(ctx context.Context, delay time.Duration) error {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

type responseProcessor func(*http.Response) (value any, retry bool, err error)

// casCall performs one replay-safe logical operation. A CAS 401 invalidates
// access and is retried once independently of transient retries.
func (c *Client) casCall(
	ctx context.Context,
	mode Access,
	method, route string,
	headers http.Header,
	body []byte,
	process responseProcessor,
) (any, error) {
	authRetried := false
	var lastErr error
	for attempt := 0; attempt < c.retry.MaxAttempts; attempt++ {
		access, err := c.access.get(ctx, mode)
		if err != nil {
			return nil, err
		}
		requestURL := endpointURL(access.Endpoint, route)
		req, err := http.NewRequestWithContext(ctx, method, requestURL.String(), bytes.NewReader(body))
		if err != nil {
			return nil, fmt.Errorf("xet CAS: build request: %w", err)
		}
		copyHeaders(req.Header, headers)
		if len(body) != 0 {
			req.ContentLength = int64(len(body))
		}
		if access.BearerToken != "" {
			req.Header.Set("Authorization", "Bearer "+access.BearerToken)
		}
		if c.sessionID != "" {
			req.Header.Set(SessionIDHeader, c.sessionID)
		}
		if c.userAgent != "" {
			req.Header.Set("User-Agent", c.userAgent)
		}

		resp, err := c.http.Do(req)
		if err != nil {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			lastErr = fmt.Errorf("xet CAS: %s %s: %w", method, redactURL(requestURL), err)
			if !isRetryableNetworkError(err) || attempt+1 == c.retry.MaxAttempts {
				return nil, lastErr
			}
			if err := c.waitRetry(ctx, attempt, ""); err != nil {
				return nil, err
			}
			continue
		}

		if resp.StatusCode == http.StatusUnauthorized && !authRetried {
			drainAndClose(resp.Body, c.maxErrorBytes)
			c.access.invalidate(mode)
			authRetried = true
			attempt--
			continue
		}
		if isTransientStatus(resp.StatusCode) {
			retryAfter := resp.Header.Get("Retry-After")
			lastErr = c.httpError(resp, method, requestURL)
			if attempt+1 == c.retry.MaxAttempts {
				return nil, lastErr
			}
			if err := c.waitRetry(ctx, attempt, retryAfter); err != nil {
				return nil, err
			}
			continue
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return nil, c.httpError(resp, method, requestURL)
		}
		value, retry, err := process(resp)
		closeErr := resp.Body.Close()
		if err == nil && closeErr != nil {
			err = closeErr
		}
		if err == nil {
			return value, nil
		}
		lastErr = err
		if !retry || attempt+1 == c.retry.MaxAttempts {
			return nil, err
		}
		if err := c.waitRetry(ctx, attempt, ""); err != nil {
			return nil, err
		}
	}
	return nil, lastErr
}

func (c *Client) waitRetry(ctx context.Context, attempt int, retryAfter string) error {
	delay, ok := parseRetryAfter(retryAfter, time.Now())
	if !ok {
		delay = c.retry.InitialBackoff
		for i := 0; i < attempt && delay < c.retry.MaximumBackoff; i++ {
			if delay > c.retry.MaximumBackoff/2 {
				delay = c.retry.MaximumBackoff
				break
			}
			delay *= 2
		}
		if delay > c.retry.MaximumBackoff {
			delay = c.retry.MaximumBackoff
		}
		// Full jitter avoids synchronized retries while preserving the cap.
		if delay > 0 {
			delay = time.Duration(rand.Int63n(int64(delay) + 1))
		}
	}
	if delay > c.retry.MaximumBackoff {
		delay = c.retry.MaximumBackoff
	}
	return c.retry.Sleep(ctx, delay)
}

func parseRetryAfter(value string, now time.Time) (time.Duration, bool) {
	if value == "" {
		return 0, false
	}
	if seconds, err := strconv.ParseUint(strings.TrimSpace(value), 10, 31); err == nil {
		return time.Duration(seconds) * time.Second, true
	}
	when, err := http.ParseTime(value)
	if err != nil {
		return 0, false
	}
	if delay := when.Sub(now); delay > 0 {
		return delay, true
	}
	return 0, true
}

func (c *Client) httpError(resp *http.Response, method string, requestURL *url.URL) error {
	drainAndClose(resp.Body, c.maxErrorBytes)
	return &HTTPError{
		Method:     method,
		URL:        redactURL(requestURL),
		StatusCode: resp.StatusCode,
		RequestID:  resp.Header.Get(RequestIDHeader),
	}
}

func endpointURL(endpoint *url.URL, route string) *url.URL {
	u := cloneURL(endpoint)
	u.Path = strings.TrimRight(u.Path, "/") + "/" + strings.TrimLeft(route, "/")
	u.RawPath = ""
	u.RawQuery = ""
	u.Fragment = ""
	return u
}

func redactURL(u *url.URL) string {
	if u == nil {
		return "<nil>"
	}
	copy := *u
	copy.User = nil
	copy.RawQuery = ""
	copy.Fragment = ""
	return copy.String()
}

func copyHeaders(dst, src http.Header) {
	for name, values := range src {
		if strings.EqualFold(name, "Authorization") {
			continue
		}
		for _, value := range values {
			dst.Add(name, value)
		}
	}
}

func readLimited(reader io.Reader, limit int64) ([]byte, error) {
	if limit < 0 {
		return nil, errors.New("xet CAS: negative response limit")
	}
	data, err := io.ReadAll(io.LimitReader(reader, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("xet CAS: response exceeds %d-byte limit", limit)
	}
	return data, nil
}

func drainAndClose(body io.ReadCloser, limit int64) {
	_, _ = io.Copy(io.Discard, io.LimitReader(body, limit))
	_ = body.Close()
}

func isTransientStatus(status int) bool {
	switch status {
	case http.StatusTooManyRequests, http.StatusInternalServerError, http.StatusBadGateway,
		http.StatusServiceUnavailable, http.StatusGatewayTimeout:
		return true
	default:
		return false
	}
}

func isRetryableNetworkError(err error) bool {
	var certificateError *tls.CertificateVerificationError
	if errors.As(err, &certificateError) {
		return false
	}
	var dnsError *net.DNSError
	if errors.As(err, &dnsError) && !dnsError.IsTemporary && !dnsError.IsTimeout {
		return false
	}
	var netError net.Error
	if errors.As(err, &netError) {
		if netError.Timeout() {
			return true
		}
	}
	var operationError *net.OpError
	if errors.As(err, &operationError) {
		return true
	}
	return errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) ||
		errors.Is(err, syscall.ECONNRESET) || errors.Is(err, syscall.ECONNREFUSED) || errors.Is(err, syscall.EPIPE)
}

func (c *Client) jsonProcessor(out any, limit int64) responseProcessor {
	return func(resp *http.Response) (any, bool, error) {
		body, err := readLimited(resp.Body, limit)
		if err != nil {
			return nil, true, fmt.Errorf("xet CAS: read response: %w", err)
		}
		if err := json.Unmarshal(body, out); err != nil {
			return nil, false, fmt.Errorf("xet CAS: decode JSON: %w", err)
		}
		return out, false, nil
	}
}

func (c *Client) bytesProcessor(limit int64) responseProcessor {
	return func(resp *http.Response) (any, bool, error) {
		body, err := readLimited(resp.Body, limit)
		if err != nil {
			return nil, true, fmt.Errorf("xet CAS: read response: %w", err)
		}
		return body, false, nil
	}
}

func (c *Client) emptyProcessor(resp *http.Response) (any, bool, error) {
	_, err := io.Copy(io.Discard, io.LimitReader(resp.Body, c.maxErrorBytes))
	return nil, err != nil, err
}

func (c *Client) QueryReconstruction(ctx context.Context, fileID xethash.Hash, requested *FileRange) (*Reconstruction, error) {
	headers := make(http.Header)
	if requested != nil {
		rangeValue, err := requested.HTTPRange()
		if err != nil {
			return nil, err
		}
		headers.Set("Range", "bytes="+rangeValue.String())
	}
	version := c.reconstructionAPI.Load()
	if version == 0 {
		version = 2
	}
	query := func(version uint32) (*Reconstruction, error) {
		route := fmt.Sprintf("v%d/reconstructions/%s", version, fileID)
		if version == 2 {
			value := &Reconstruction{}
			_, err := c.casCall(ctx, AccessRead, http.MethodGet, route, headers, nil, c.jsonProcessor(value, c.maxResponseBytes))
			if err != nil {
				return nil, mapRangeError(err)
			}
			if err := value.Validate(); err != nil {
				return nil, err
			}
			return value, nil
		}
		value := &reconstructionV1{}
		_, err := c.casCall(ctx, AccessRead, http.MethodGet, route, headers, nil, c.jsonProcessor(value, c.maxResponseBytes))
		if err != nil {
			return nil, mapRangeError(err)
		}
		normalized := value.normalize()
		if err := normalized.Validate(); err != nil {
			return nil, err
		}
		return normalized, nil
	}

	value, err := query(version)
	if err == nil {
		c.reconstructionAPI.Store(version)
		return value, nil
	}
	var httpErr *HTTPError
	if version == 2 && errors.As(err, &httpErr) &&
		(httpErr.StatusCode == http.StatusNotFound || httpErr.StatusCode == http.StatusNotImplemented) {
		value, fallbackErr := query(1)
		if fallbackErr == nil {
			c.reconstructionAPI.Store(1)
		}
		return value, fallbackErr
	}
	return nil, err
}

func mapRangeError(err error) error {
	var httpErr *HTTPError
	if errors.As(err, &httpErr) && httpErr.StatusCode == http.StatusRequestedRangeNotSatisfiable {
		return fmt.Errorf("%w: %v", ErrRangeNotSatisfiable, httpErr)
	}
	return err
}

func validatePrefix(prefix string) error {
	if prefix == "" {
		return errors.New("xet CAS: empty key prefix")
	}
	if strings.ContainsAny(prefix, "/\\?#") || prefix == "." || prefix == ".." {
		return errors.New("xet CAS: key prefix must be one safe path segment")
	}
	return nil
}

func (c *Client) UploadXorb(ctx context.Context, prefix string, hash xethash.Hash, body []byte) (bool, error) {
	if err := validatePrefix(prefix); err != nil {
		return false, err
	}
	headers := make(http.Header)
	headers.Set("Content-Type", "application/octet-stream")
	response := struct {
		WasInserted bool `json:"was_inserted"`
	}{}
	route := fmt.Sprintf("v1/xorbs/%s/%s", prefix, hash)
	_, err := c.casCall(ctx, AccessWrite, http.MethodPost, route, headers, body, c.jsonProcessor(&response, c.maxErrorBytes))
	return response.WasInserted, err
}

func (c *Client) UploadShard(ctx context.Context, body []byte, progress func(ShardUploadEvent)) error {
	version := c.shardAPI.Load()
	if version == 0 {
		version = 2
	}
	upload := func(version uint32) error {
		headers := make(http.Header)
		headers.Set("Content-Type", "application/octet-stream")
		if version == 2 {
			_, err := c.casCall(ctx, AccessWrite, http.MethodPost, "v2/shards", headers, body, c.ndjsonProcessor(progress))
			return err
		}
		response := struct {
			Result int `json:"result"`
		}{Result: -1}
		_, err := c.casCall(ctx, AccessWrite, http.MethodPost, "v1/shards", headers, body, c.jsonProcessor(&response, c.maxErrorBytes))
		if err != nil {
			return err
		}
		if response.Result != 0 && response.Result != 1 {
			return fmt.Errorf("xet CAS: invalid v1 shard result %d", response.Result)
		}
		if progress != nil {
			progress(ShardUploadEvent{Type: "result"})
		}
		return nil
	}

	err := upload(version)
	if err == nil {
		c.shardAPI.Store(version)
		return nil
	}
	var httpErr *HTTPError
	if version == 2 && errors.As(err, &httpErr) &&
		(httpErr.StatusCode == http.StatusNotFound || httpErr.StatusCode == http.StatusNotImplemented) {
		if err := upload(1); err != nil {
			return err
		}
		c.shardAPI.Store(1)
		return nil
	}
	return err
}

func (c *Client) ndjsonProcessor(progress func(ShardUploadEvent)) responseProcessor {
	return func(resp *http.Response) (any, bool, error) {
		reader := bufio.NewReaderSize(resp.Body, defaultMaxNDJSONLine+1)
		for {
			line, readErr := reader.ReadSlice('\n')
			if errors.Is(readErr, bufio.ErrBufferFull) || len(line) > defaultMaxNDJSONLine+1 {
				return nil, false, fmt.Errorf("xet CAS: shard progress frame exceeds %d-byte limit", defaultMaxNDJSONLine)
			}
			line = bytes.TrimSuffix(line, []byte{'\n'})
			if len(line) > defaultMaxNDJSONLine {
				return nil, false, fmt.Errorf("xet CAS: shard progress frame exceeds %d-byte limit", defaultMaxNDJSONLine)
			}
			if len(bytes.TrimSpace(line)) == 0 {
				if readErr == nil {
					continue
				}
				if errors.Is(readErr, io.EOF) {
					return nil, false, ErrMissingTerminal
				}
				return nil, true, fmt.Errorf("xet CAS: read shard progress stream: %w", readErr)
			}
			var event ShardUploadEvent
			if err := json.Unmarshal(line, &event); err != nil {
				return nil, false, fmt.Errorf("xet CAS: decode shard progress frame: %w", err)
			}
			if progress != nil {
				progress(event)
			}
			switch event.Type {
			case "validating":
				if event.Verified > event.Total {
					return nil, false, errors.New("xet CAS: invalid shard validation progress")
				}
			case "committing":
				if event.Stage != "uploading" && event.Stage != "syncing" {
					return nil, false, fmt.Errorf("xet CAS: invalid shard commit stage %q", event.Stage)
				}
			case "result":
				return nil, false, nil
			case "error":
				if event.Message == "" {
					event.Message = "CAS reported an unspecified shard upload error"
				}
				return nil, event.Retryable, errors.New(event.Message)
			default:
				// Forward-compatible unknown events are intentionally ignored.
			}
			if readErr == nil {
				continue
			}
			if errors.Is(readErr, io.EOF) {
				return nil, false, ErrMissingTerminal
			}
			return nil, true, fmt.Errorf("xet CAS: read shard progress stream: %w", readErr)
		}
	}
}

// QueryGlobalDedup fetches the footer-bearing metadata shard associated with a
// canonical chunk hash. A missing entry is not an error.
func (c *Client) QueryGlobalDedup(ctx context.Context, prefix string, chunkHash xethash.Hash) ([]byte, bool, error) {
	if err := validatePrefix(prefix); err != nil {
		return nil, false, err
	}
	route := fmt.Sprintf("v1/chunks/%s/%s", prefix, chunkHash)
	value, err := c.casCall(ctx, AccessWrite, http.MethodGet, route, nil, nil, c.bytesProcessor(c.maxResponseBytes))
	if err != nil {
		var httpErr *HTTPError
		if errors.As(err, &httpErr) && httpErr.StatusCode == http.StatusNotFound {
			return nil, false, nil
		}
		return nil, false, err
	}
	return value.([]byte), true, nil
}

func (c *Client) XorbExists(ctx context.Context, prefix string, hash xethash.Hash) (bool, error) {
	if err := validatePrefix(prefix); err != nil {
		return false, err
	}
	route := fmt.Sprintf("v1/xorbs/%s/%s", prefix, hash)
	_, err := c.casCall(ctx, AccessRead, http.MethodHead, route, nil, nil, c.emptyProcessor)
	if err != nil {
		var httpErr *HTTPError
		if errors.As(err, &httpErr) && httpErr.StatusCode == http.StatusNotFound {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

// FileSize returns the logical size advertised by HEAD /v1/files/{id}. A
// missing file returns found=false.
func (c *Client) FileSize(ctx context.Context, fileID xethash.Hash) (size uint64, found bool, err error) {
	processor := func(resp *http.Response) (any, bool, error) {
		value := resp.Header.Get("Content-Length")
		if value == "" {
			return nil, false, errors.New("xet CAS: file HEAD response has no Content-Length")
		}
		size, err := strconv.ParseUint(value, 10, 64)
		if err != nil {
			return nil, false, fmt.Errorf("xet CAS: invalid file Content-Length: %w", err)
		}
		return size, false, nil
	}
	value, err := c.casCall(ctx, AccessRead, http.MethodHead, "v1/files/"+fileID.String(), nil, nil, processor)
	if err != nil {
		var httpErr *HTTPError
		if errors.As(err, &httpErr) && httpErr.StatusCode == http.StatusNotFound {
			return 0, false, nil
		}
		return 0, false, err
	}
	return value.(uint64), true, nil
}
