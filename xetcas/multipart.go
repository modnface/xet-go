package xetcas

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// FetchRanges retrieves the exact inclusive ranges authorized by a signed
// object-storage URL. No CAS bearer token, session ID, or cookie is sent.
// Multipart parts are matched by Content-Range and returned sorted by range.
func (c *Client) FetchRanges(ctx context.Context, rawURL string, ranges []HTTPRange) ([]FetchedRange, error) {
	if err := validateSignedURL(rawURL); err != nil {
		return nil, err
	}
	if len(ranges) == 0 {
		return nil, errors.New("xet CAS: signed fetch requires at least one range")
	}
	var expected uint64
	seen := make(map[HTTPRange]struct{}, len(ranges))
	values := make([]string, len(ranges))
	for i, value := range ranges {
		if err := value.Validate(); err != nil {
			return nil, fmt.Errorf("xet CAS: signed fetch range %d: %w", i, err)
		}
		if _, duplicate := seen[value]; duplicate {
			return nil, fmt.Errorf("xet CAS: duplicate signed fetch range %s", value)
		}
		seen[value] = struct{}{}
		if ^uint64(0)-expected < value.Len() {
			return nil, errors.New("xet CAS: signed fetch byte count overflows uint64")
		}
		expected += value.Len()
		values[i] = value.String()
	}
	if expected > uint64(c.maxResponseBytes) {
		return nil, fmt.Errorf("xet CAS: signed fetch requests %d bytes, limit is %d", expected, c.maxResponseBytes)
	}
	rangeHeader := "bytes=" + strings.Join(values, ",")
	parsedURL, _ := url.Parse(rawURL)

	var lastErr error
	for attempt := 0; attempt < c.retry.MaxAttempts; attempt++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
		if err != nil {
			return nil, fmt.Errorf("xet CAS: build signed fetch: %w", err)
		}
		req.Header.Set("Range", rangeHeader)
		if c.userAgent != "" {
			req.Header.Set("User-Agent", c.userAgent)
		}
		resp, err := c.http.Do(req)
		if err != nil {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			lastErr = fmt.Errorf("xet CAS: signed GET %s: %w", redactURL(parsedURL), err)
			if !isRetryableNetworkError(err) || attempt+1 == c.retry.MaxAttempts {
				return nil, lastErr
			}
			if err := c.waitRetry(ctx, attempt, ""); err != nil {
				return nil, err
			}
			continue
		}
		if resp.StatusCode == http.StatusForbidden {
			drainAndClose(resp.Body, c.maxErrorBytes)
			return nil, fmt.Errorf("%w: signed GET %s", ErrSignedURLExpired, redactURL(parsedURL))
		}
		if isTransientStatus(resp.StatusCode) {
			retryAfter := resp.Header.Get("Retry-After")
			lastErr = c.httpError(resp, http.MethodGet, parsedURL)
			if attempt+1 == c.retry.MaxAttempts {
				return nil, lastErr
			}
			if err := c.waitRetry(ctx, attempt, retryAfter); err != nil {
				return nil, err
			}
			continue
		}
		if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusPartialContent {
			return nil, c.httpError(resp, http.MethodGet, parsedURL)
		}
		result, err := c.decodeRangeResponse(resp, ranges, expected)
		closeErr := resp.Body.Close()
		if err == nil && closeErr != nil {
			err = closeErr
		}
		if err == nil {
			return result, nil
		}
		lastErr = err
		// Truncated/failed reads may be transient; structurally invalid responses
		// are deterministic and should not be hammered repeatedly.
		if !errors.Is(err, io.ErrUnexpectedEOF) || attempt+1 == c.retry.MaxAttempts {
			return nil, err
		}
		if err := c.waitRetry(ctx, attempt, ""); err != nil {
			return nil, err
		}
	}
	return nil, lastErr
}

func (c *Client) decodeRangeResponse(resp *http.Response, ranges []HTTPRange, expected uint64) ([]FetchedRange, error) {
	mediaType, params, _ := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if len(ranges) == 1 && !strings.EqualFold(mediaType, "multipart/byteranges") {
		body, err := readLimited(resp.Body, c.maxResponseBytes)
		if err != nil {
			return nil, err
		}
		if uint64(len(body)) != expected {
			return nil, fmt.Errorf("xet CAS: signed range returned %d bytes, want %d: %w", len(body), expected, io.ErrUnexpectedEOF)
		}
		declared := ranges[0]
		if value := resp.Header.Get("Content-Range"); value != "" {
			parsed, err := parseContentRange(value)
			if err != nil {
				return nil, err
			}
			if parsed != declared {
				return nil, fmt.Errorf("xet CAS: signed response Content-Range %s, want %s", parsed, declared)
			}
		}
		return []FetchedRange{{Range: declared, Data: body}}, nil
	}
	if !strings.EqualFold(mediaType, "multipart/byteranges") {
		return nil, fmt.Errorf("xet CAS: multi-range response has Content-Type %q", resp.Header.Get("Content-Type"))
	}
	boundary := params["boundary"]
	if boundary == "" {
		return nil, errors.New("xet CAS: multipart response has no boundary")
	}
	// Bound framing overhead in addition to the exact requested data.
	limit := int64(expected) + int64(len(ranges))*(64<<10) + 64<<10
	if limit > c.maxResponseBytes {
		limit = c.maxResponseBytes
	}
	body, err := readLimited(resp.Body, limit)
	if err != nil {
		return nil, err
	}
	reader := multipart.NewReader(bytes.NewReader(body), boundary)
	wanted := make(map[HTTPRange]struct{}, len(ranges))
	for _, value := range ranges {
		wanted[value] = struct{}{}
	}
	results := make([]FetchedRange, 0, len(ranges))
	for {
		part, err := reader.NextPart()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("xet CAS: parse multipart response: %w", err)
		}
		declared, err := parseContentRange(part.Header.Get("Content-Range"))
		if err != nil {
			_ = part.Close()
			return nil, err
		}
		if _, ok := wanted[declared]; !ok {
			_ = part.Close()
			return nil, fmt.Errorf("xet CAS: unexpected or duplicate multipart range %s", declared)
		}
		data, err := readLimited(part, int64(declared.Len()))
		_ = part.Close()
		if err != nil {
			return nil, err
		}
		if uint64(len(data)) != declared.Len() {
			return nil, fmt.Errorf("xet CAS: multipart range %s contains %d bytes, want %d: %w", declared, len(data), declared.Len(), io.ErrUnexpectedEOF)
		}
		delete(wanted, declared)
		results = append(results, FetchedRange{Range: declared, Data: data})
	}
	if len(wanted) != 0 {
		return nil, fmt.Errorf("xet CAS: multipart response omitted %d requested ranges: %w", len(wanted), io.ErrUnexpectedEOF)
	}
	sortFetchedRanges(results)
	return results, nil
}

func parseContentRange(value string) (HTTPRange, error) {
	value = strings.TrimSpace(value)
	if len(value) < 6 || !strings.EqualFold(value[:6], "bytes ") {
		return HTTPRange{}, fmt.Errorf("xet CAS: invalid Content-Range %q", value)
	}
	rangeAndSize := strings.TrimSpace(value[6:])
	slash := strings.IndexByte(rangeAndSize, '/')
	if slash < 1 {
		return HTTPRange{}, fmt.Errorf("xet CAS: invalid Content-Range %q", value)
	}
	span := rangeAndSize[:slash]
	dash := strings.IndexByte(span, '-')
	if dash < 1 || dash == len(span)-1 {
		return HTTPRange{}, fmt.Errorf("xet CAS: invalid Content-Range %q", value)
	}
	start, err := strconv.ParseUint(span[:dash], 10, 64)
	if err != nil {
		return HTTPRange{}, fmt.Errorf("xet CAS: invalid Content-Range start: %w", err)
	}
	end, err := strconv.ParseUint(span[dash+1:], 10, 64)
	if err != nil {
		return HTTPRange{}, fmt.Errorf("xet CAS: invalid Content-Range end: %w", err)
	}
	result := HTTPRange{Start: start, End: end}
	if err := result.Validate(); err != nil {
		return HTTPRange{}, err
	}
	if total := rangeAndSize[slash+1:]; total != "*" {
		size, err := strconv.ParseUint(total, 10, 64)
		if err != nil || size == 0 || result.End >= size {
			return HTTPRange{}, fmt.Errorf("xet CAS: invalid Content-Range total %q", total)
		}
	}
	return result, nil
}
