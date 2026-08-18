package hfcompat

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
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jmwoliver/xet-go/bucket"
	"github.com/jmwoliver/xet-go/model"
	"github.com/jmwoliver/xet-go/xethash"
)

type lfsObjectKey struct {
	sum  [32]byte
	size uint64
}

type lfsTestWriter struct {
	*bucket.Service
	mu                     sync.Mutex
	objects                map[lfsObjectKey]xethash.Hash
	calls                  int
	resolveErr             error
	resolveAfterIngestErr  error
	resolveAfterIngestHash *xethash.Hash
	ingestErr              error
	ingestResult           *XetFileIngestResult
	ingested               bool
}

func (writer *lfsTestWriter) ResolveXetFile(ctx context.Context, repo model.RepoKey, sum [32]byte, size uint64) (xethash.Hash, error) {
	writer.mu.Lock()
	if writer.resolveErr != nil {
		err := writer.resolveErr
		writer.mu.Unlock()
		return xethash.Hash{}, err
	}
	if writer.ingested && writer.resolveAfterIngestErr != nil {
		err := writer.resolveAfterIngestErr
		writer.mu.Unlock()
		return xethash.Hash{}, err
	}
	if writer.ingested && writer.resolveAfterIngestHash != nil {
		hash := *writer.resolveAfterIngestHash
		writer.mu.Unlock()
		return hash, nil
	}
	hash, exists := writer.objects[lfsObjectKey{sum: sum, size: size}]
	writer.mu.Unlock()
	if exists {
		return hash, nil
	}
	return writer.Service.ResolveXetFile(ctx, repo, sum, size)
}

func (writer *lfsTestWriter) ingest(ctx context.Context, repo model.RepoKey, source io.Reader) (XetFileIngestResult, error) {
	body, err := io.ReadAll(source)
	if err != nil {
		return XetFileIngestResult{}, err
	}
	writer.mu.Lock()
	writer.calls++
	if writer.ingestErr != nil {
		err = writer.ingestErr
		writer.mu.Unlock()
		return XetFileIngestResult{}, err
	}
	sum := sha256.Sum256(body)
	hash := xethash.Chunk(body)
	writer.objects[lfsObjectKey{sum: sum, size: uint64(len(body))}] = hash
	writer.ingested = true
	if writer.ingestResult != nil {
		result := *writer.ingestResult
		writer.mu.Unlock()
		return result, nil
	}
	writer.mu.Unlock()
	return XetFileIngestResult{Hash: hash, Size: uint64(len(body)), SHA256: sum}, nil
}

func TestLFSBatchUploadCapabilityAndDedup(t *testing.T) {
	fixture := newHandlerFixture(t, 0)
	writer := &lfsTestWriter{Service: fixture.bucket, objects: make(map[lfsObjectKey]xethash.Hash)}
	handler := newLFSHandler(t, fixture, writer)
	audit := &recordingWriteAudit{}
	handler.audit = audit
	body := []byte("new legacy LFS object")
	sum := sha256.Sum256(body)
	batch := lfsBatchBody(t,
		lfsObjectDTO{OID: hex.EncodeToString(fixture.cas.sum[:]), Size: int64(len(fixture.xetBody))},
		lfsObjectDTO{OID: hex.EncodeToString(sum[:]), Size: int64(len(body))},
	)
	response := requestBody(t, handler, http.MethodPost, "/owner/model.git/info/lfs/objects/batch", "Bearer hub-token", bytes.NewReader(batch), map[string]string{"Content-Type": lfsMediaType})
	if response.Code != http.StatusOK || response.Header().Get("Content-Type") != lfsMediaType {
		t.Fatalf("batch = %d, %#v, %s", response.Code, response.Header(), response.Body.String())
	}
	var decoded lfsBatchResponseDTO
	if err := json.Unmarshal(response.Body.Bytes(), &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Transfer != "basic" || len(decoded.Objects) != 2 || decoded.Objects[0].Actions != nil || decoded.Objects[1].Actions == nil {
		t.Fatalf("batch response = %#v", decoded)
	}
	href := decoded.Objects[1].Actions.Upload.Href
	if !strings.HasPrefix(href, "https://hub.test/base/owner/model.git/info/lfs/objects/upload/") {
		t.Fatalf("upload href = %q", href)
	}
	wrongMethod := requestBody(t, handler, http.MethodPost, lfsHandlerTarget(href), "", bytes.NewReader(body), nil)
	if wrongMethod.Code != http.StatusMethodNotAllowed || wrongMethod.Header().Get("Allow") != "PUT" || writer.calls != 0 {
		t.Fatalf("upload method = %d, %#v, calls=%d", wrongMethod.Code, wrongMethod.Header(), writer.calls)
	}
	upload := requestBody(t, handler, http.MethodPut, lfsHandlerTarget(href), "", bytes.NewReader(body), nil)
	if upload.Code != http.StatusOK || writer.calls != 1 {
		t.Fatalf("upload = %d, calls=%d, body=%s", upload.Code, writer.calls, upload.Body.String())
	}
	audit.mu.Lock()
	events := append([]WriteAuditEvent(nil), audit.events...)
	audit.mu.Unlock()
	if len(events) != 3 || events[0].Operation != "lfs-batch" || events[0].StatusCode != http.StatusOK ||
		events[1].Operation != "lfs-upload" || events[1].StatusCode != http.StatusMethodNotAllowed ||
		events[2].Operation != "lfs-upload" || events[2].StatusCode != http.StatusOK ||
		events[2].Principal.Subject != "user:test" || events[2].Repository != fixture.repo {
		t.Fatalf("LFS audit events = %#v", events)
	}
	replay := requestBody(t, handler, http.MethodPut, lfsHandlerTarget(href), "", bytes.NewReader(body), nil)
	if replay.Code != http.StatusUnauthorized || writer.calls != 1 {
		t.Fatalf("replay = %d, calls=%d", replay.Code, writer.calls)
	}

	response = requestBody(t, handler, http.MethodPost, "/owner/model.git/info/lfs/objects/batch", "Bearer hub-token", bytes.NewReader(lfsBatchBody(t,
		lfsObjectDTO{OID: hex.EncodeToString(sum[:]), Size: int64(len(body))},
	)), map[string]string{"Content-Type": lfsMediaType})
	if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &decoded) != nil || decoded.Objects[0].Actions != nil {
		t.Fatalf("deduplicated batch = %d, %s", response.Code, response.Body.String())
	}
}

func TestLFSRoutesRequireIngestionComposition(t *testing.T) {
	fixture := newHandlerFixture(t, 0)
	batch := requestBody(t, fixture.handler, http.MethodPost, "/owner/model.git/info/lfs/objects/batch", "Bearer hub-token", bytes.NewReader(lfsBatchBody(t)), map[string]string{"Content-Type": lfsMediaType})
	if batch.Code != http.StatusNotImplemented {
		t.Fatalf("batch without ingester = %d, %s", batch.Code, batch.Body.String())
	}
	upload := requestBody(t, fixture.handler, http.MethodPut, "/owner/model.git/info/lfs/objects/upload/"+strings.Repeat("0", 64), "", bytes.NewReader(nil), nil)
	if upload.Code != http.StatusNotImplemented {
		t.Fatalf("upload without ingester = %d, %s", upload.Code, upload.Body.String())
	}
}

func TestLFSUploadRejectsMismatchTruncationTamperingAndExpiry(t *testing.T) {
	tests := map[string]func(*testing.T, *Service, string, []byte) *httptest.ResponseRecorder{
		"wrong hash": func(t *testing.T, handler *Service, href string, body []byte) *httptest.ResponseRecorder {
			wrong := append([]byte(nil), body...)
			wrong[0] ^= 0xff
			return requestBody(t, handler, http.MethodPut, lfsHandlerTarget(href), "", bytes.NewReader(wrong), nil)
		},
		"truncated": func(t *testing.T, handler *Service, href string, body []byte) *httptest.ResponseRecorder {
			return requestBody(t, handler, http.MethodPut, lfsHandlerTarget(href), "", bytes.NewReader(body[:len(body)-1]), nil)
		},
		"object tampering": func(t *testing.T, handler *Service, href string, body []byte) *httptest.ResponseRecorder {
			parsed, _ := url.Parse(href)
			last := parsed.Path[len(parsed.Path)-1]
			if last == '0' {
				last = '1'
			} else {
				last = '0'
			}
			parsed.Path = parsed.Path[:len(parsed.Path)-1] + string(last)
			return requestBody(t, handler, http.MethodPut, lfsHandlerTarget(parsed.String()), "", bytes.NewReader(body), nil)
		},
		"size tampering": func(t *testing.T, handler *Service, href string, body []byte) *httptest.ResponseRecorder {
			parsed, _ := url.Parse(href)
			query := parsed.Query()
			query.Set("size", "1")
			parsed.RawQuery = query.Encode()
			return requestBody(t, handler, http.MethodPut, lfsHandlerTarget(parsed.String()), "", bytes.NewReader(body), nil)
		},
		"range widening": func(t *testing.T, handler *Service, href string, body []byte) *httptest.ResponseRecorder {
			parsed, _ := url.Parse(href)
			query := parsed.Query()
			query.Set("range", "0-")
			parsed.RawQuery = query.Encode()
			return requestBody(t, handler, http.MethodPut, lfsHandlerTarget(parsed.String()), "", bytes.NewReader(body), nil)
		},
		"expired": func(t *testing.T, handler *Service, href string, body []byte) *httptest.ResponseRecorder {
			handler.now = func() time.Time { return time.Now().Add(2 * handler.lfsTTL) }
			return requestBody(t, handler, http.MethodPut, lfsHandlerTarget(href), "", bytes.NewReader(body), nil)
		},
	}
	for name, run := range tests {
		t.Run(name, func(t *testing.T) {
			fixture := newHandlerFixture(t, 0)
			writer := &lfsTestWriter{Service: fixture.bucket, objects: make(map[lfsObjectKey]xethash.Hash)}
			handler := newLFSHandler(t, fixture, writer)
			body := []byte("capability-bound object")
			href := requestLFSHref(t, handler, body)
			response := run(t, handler, href, body)
			want := http.StatusBadRequest
			if name == "object tampering" || name == "size tampering" || name == "range widening" || name == "expired" {
				want = http.StatusUnauthorized
			}
			if response.Code != want || writer.calls != 0 {
				t.Fatalf("response = %d, calls=%d, body=%s", response.Code, writer.calls, response.Body.String())
			}
		})
	}
}

func TestLFSUploadPreservesBackendAndDurabilityFailures(t *testing.T) {
	t.Run("batch resolution", func(t *testing.T) {
		fixture := newHandlerFixture(t, 0)
		writer := &lfsTestWriter{Service: fixture.bucket, objects: make(map[lfsObjectKey]xethash.Hash), resolveErr: bucket.ErrUnavailable}
		handler := newLFSHandler(t, fixture, writer)
		body := []byte("batch resolution failure")
		sum := sha256.Sum256(body)
		response := requestBody(t, handler, http.MethodPost, "/owner/model.git/info/lfs/objects/batch", "Bearer hub-token", bytes.NewReader(lfsBatchBody(t,
			lfsObjectDTO{OID: hex.EncodeToString(sum[:]), Size: int64(len(body))},
		)), map[string]string{"Content-Type": lfsMediaType})
		if response.Code != http.StatusServiceUnavailable || writer.calls != 0 {
			t.Fatalf("response = %d, calls=%d, body=%s", response.Code, writer.calls, response.Body.String())
		}
	})

	tests := map[string]struct {
		configure func(*lfsTestWriter)
		status    int
	}{
		"upload preflight": {
			configure: func(writer *lfsTestWriter) { writer.resolveErr = bucket.ErrUnavailable },
			status:    http.StatusServiceUnavailable,
		},
		"ingest": {
			configure: func(writer *lfsTestWriter) { writer.ingestErr = bucket.ErrUnavailable },
			status:    http.StatusServiceUnavailable,
		},
		"invalid ingest identity": {
			configure: func(writer *lfsTestWriter) { writer.ingestResult = &XetFileIngestResult{} },
			status:    http.StatusInternalServerError,
		},
		"durability lookup": {
			configure: func(writer *lfsTestWriter) { writer.resolveAfterIngestErr = bucket.ErrUnavailable },
			status:    http.StatusServiceUnavailable,
		},
		"durability identity": {
			configure: func(writer *lfsTestWriter) {
				wrong := xethash.Chunk([]byte("different durable identity"))
				writer.resolveAfterIngestHash = &wrong
			},
			status: http.StatusInternalServerError,
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			fixture := newHandlerFixture(t, 0)
			writer := &lfsTestWriter{Service: fixture.bucket, objects: make(map[lfsObjectKey]xethash.Hash)}
			handler := newLFSHandler(t, fixture, writer)
			body := []byte("backend failure object")
			href := requestLFSHref(t, handler, body)
			test.configure(writer)
			response := requestBody(t, handler, http.MethodPut, lfsHandlerTarget(href), "", bytes.NewReader(body), nil)
			if response.Code != test.status || writer.calls > 1 {
				t.Fatalf("response = %d, calls=%d, body=%s", response.Code, writer.calls, response.Body.String())
			}
		})
	}
}

func TestLFSUploadRejectsBodyReadFailureAndExpiryDuringTransfer(t *testing.T) {
	fixture := newHandlerFixture(t, 0)
	writer := &lfsTestWriter{Service: fixture.bucket, objects: make(map[lfsObjectKey]xethash.Hash)}
	handler := newLFSHandler(t, fixture, writer)
	body := []byte("body read failure")
	href := requestLFSHref(t, handler, body)
	response := requestBody(t, handler, http.MethodPut, lfsHandlerTarget(href), "", failingReader{err: errors.New("read failed")}, nil)
	if response.Code != http.StatusBadRequest || writer.calls != 0 {
		t.Fatalf("read failure = %d, calls=%d, body=%s", response.Code, writer.calls, response.Body.String())
	}

	fixture = newHandlerFixture(t, 0)
	writer = &lfsTestWriter{Service: fixture.bucket, objects: make(map[lfsObjectKey]xethash.Hash)}
	handler = newLFSHandler(t, fixture, writer)
	body = []byte("expires while spooling")
	base := time.Unix(2_100_000_000, 0).UTC()
	handler.now = func() time.Time { return base }
	href = requestLFSHref(t, handler, body)
	calls := 0
	handler.now = func() time.Time {
		calls++
		if calls == 1 {
			return base
		}
		return base.Add(2 * handler.lfsTTL)
	}
	response = requestBody(t, handler, http.MethodPut, lfsHandlerTarget(href), "", bytes.NewReader(body), nil)
	if response.Code != http.StatusUnauthorized || writer.calls != 0 {
		t.Fatalf("transfer expiry = %d, calls=%d, body=%s", response.Code, writer.calls, response.Body.String())
	}
}

func TestLFSCapabilityRejectsMalformedAndConcurrentClaims(t *testing.T) {
	fixture := newHandlerFixture(t, 0)
	writer := &lfsTestWriter{Service: fixture.bucket, objects: make(map[lfsObjectKey]xethash.Hash)}
	handler := newLFSHandler(t, fixture, writer)
	body := []byte("capability validation object")
	href := requestLFSHref(t, handler, body)
	parsed, err := url.Parse(href)
	if err != nil {
		t.Fatal(err)
	}
	query := parsed.Query()
	nonce := query.Get("nonce")

	malformed := []func(url.Values){
		func(values url.Values) { values.Del("expires") },
		func(values url.Values) { values.Set("size", "not-a-number") },
		func(values url.Values) { values.Set("subject", "!") },
		func(values url.Values) { values.Add("nonce", nonce) },
	}
	for index, mutate := range malformed {
		copyURL := *parsed
		values := copyURL.Query()
		mutate(values)
		copyURL.RawQuery = values.Encode()
		response := requestBody(t, handler, http.MethodPut, lfsHandlerTarget(copyURL.String()), "", bytes.NewReader(body), nil)
		if response.Code != http.StatusUnauthorized || writer.calls != 0 {
			t.Fatalf("malformed claim %d = %d, calls=%d", index, response.Code, writer.calls)
		}
	}

	handler.lfsMu.Lock()
	state := handler.lfsUploads[nonce]
	state.active = true
	handler.lfsUploads[nonce] = state
	handler.lfsMu.Unlock()
	response := requestBody(t, handler, http.MethodPut, lfsHandlerTarget(href), "", bytes.NewReader(body), nil)
	if response.Code != http.StatusUnauthorized || writer.calls != 0 {
		t.Fatalf("concurrent claim = %d, calls=%d", response.Code, writer.calls)
	}
}

type failingReader struct{ err error }

func (reader failingReader) Read([]byte) (int, error) { return 0, reader.err }

func TestLFSBatchAdmissionLimits(t *testing.T) {
	fixture := newHandlerFixture(t, 0)
	writer := &lfsTestWriter{Service: fixture.bucket, objects: make(map[lfsObjectKey]xethash.Hash)}
	handler := newLFSHandler(t, fixture, writer)
	first := sha256.Sum256([]byte("first"))
	second := sha256.Sum256([]byte("second"))

	handler.lfsBatch = 1
	response := requestBody(t, handler, http.MethodPost, "/owner/model.git/info/lfs/objects/batch", "Bearer hub-token", bytes.NewReader(lfsBatchBody(t,
		lfsObjectDTO{OID: hex.EncodeToString(first[:]), Size: 5},
		lfsObjectDTO{OID: hex.EncodeToString(second[:]), Size: 6},
	)), map[string]string{"Content-Type": lfsMediaType})
	if response.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("object-count limit = %d, %s", response.Code, response.Body.String())
	}

	handler.lfsBatch = defaultLFSBatchMax
	handler.fileBytes = 4
	response = requestBody(t, handler, http.MethodPost, "/owner/model.git/info/lfs/objects/batch", "Bearer hub-token", bytes.NewReader(lfsBatchBody(t,
		lfsObjectDTO{OID: hex.EncodeToString(first[:]), Size: 5},
	)), map[string]string{"Content-Type": lfsMediaType})
	if response.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("declared-file limit = %d, %s", response.Code, response.Body.String())
	}
}

func TestLFSBatchRejectsMalformedNegotiation(t *testing.T) {
	fixture := newHandlerFixture(t, 0)
	writer := &lfsTestWriter{Service: fixture.bucket, objects: make(map[lfsObjectKey]xethash.Hash)}
	handler := newLFSHandler(t, fixture, writer)
	sum := sha256.Sum256([]byte("object"))
	oid := hex.EncodeToString(sum[:])
	tests := []struct {
		name        string
		body        []byte
		contentType string
		target      string
		status      int
	}{
		{"content type", lfsBatchBody(t, lfsObjectDTO{OID: oid, Size: 6}), "application/json", "/owner/model.git/info/lfs/objects/batch", http.StatusBadRequest},
		{"query", lfsBatchBody(t, lfsObjectDTO{OID: oid, Size: 6}), lfsMediaType, "/owner/model.git/info/lfs/objects/batch?x=1", http.StatusBadRequest},
		{"no basic transfer", marshalJSON(t, lfsBatchDTO{Operation: "upload", Transfers: []string{"multipart"}, HashAlgo: "sha256"}), lfsMediaType, "/owner/model.git/info/lfs/objects/batch", http.StatusBadRequest},
		{"invalid ref", marshalJSON(t, lfsBatchDTO{Operation: "upload", Transfers: []string{"basic"}, HashAlgo: "sha256", Ref: &lfsRefDTO{Name: "../bad"}}), lfsMediaType, "/owner/model.git/info/lfs/objects/batch", http.StatusBadRequest},
		{"negative size", lfsBatchBody(t, lfsObjectDTO{OID: oid, Size: -1}), lfsMediaType, "/owner/model.git/info/lfs/objects/batch", http.StatusBadRequest},
		{"uppercase OID", lfsBatchBody(t, lfsObjectDTO{OID: strings.ToUpper(oid), Size: 6}), lfsMediaType, "/owner/model.git/info/lfs/objects/batch", http.StatusBadRequest},
		{"duplicate OID", lfsBatchBody(t, lfsObjectDTO{OID: oid, Size: 6}, lfsObjectDTO{OID: oid, Size: 6}), lfsMediaType, "/owner/model.git/info/lfs/objects/batch", http.StatusBadRequest},
		{"unknown field", []byte(`{"operation":"upload","transfers":["basic"],"hash_algo":"sha256","objects":[],"unknown":true}`), lfsMediaType, "/owner/model.git/info/lfs/objects/batch", http.StatusBadRequest},
		{"multiple JSON values", append(lfsBatchBody(t), []byte(`{}`)...), lfsMediaType, "/owner/model.git/info/lfs/objects/batch", http.StatusBadRequest},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			response := requestBody(t, handler, http.MethodPost, test.target, "Bearer hub-token", bytes.NewReader(test.body), map[string]string{"Content-Type": test.contentType})
			if response.Code != test.status || writer.calls != 0 {
				t.Fatalf("response = %d, calls=%d, body=%s", response.Code, writer.calls, response.Body.String())
			}
		})
	}

	handler.lfsBatch = 1
	objects := make([]lfsObjectDTO, 100)
	for index := range objects {
		objects[index] = lfsObjectDTO{OID: oid, Size: 6}
	}
	oversizedBody := marshalJSON(t, lfsBatchDTO{Operation: "upload", Transfers: []string{"basic"}, HashAlgo: "sha256", Objects: objects})
	oversized := requestBody(t, handler, http.MethodPost, "/owner/model.git/info/lfs/objects/batch", "Bearer hub-token", bytes.NewReader(oversizedBody), map[string]string{"Content-Type": lfsMediaType})
	if oversized.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized body = %d, %s", oversized.Code, oversized.Body.String())
	}

	parameterized := requestBody(t, handler, http.MethodPost, "/owner/model.git/info/lfs/objects/batch", "Bearer hub-token", bytes.NewReader(lfsBatchBody(t)), map[string]string{
		"Content-Type": lfsMediaType + "; charset=utf-8",
	})
	if parameterized.Code != http.StatusOK {
		t.Fatalf("parameterized media type = %d, %s", parameterized.Code, parameterized.Body.String())
	}
}

func TestLFSCapabilityCleanupRemovesExpiredState(t *testing.T) {
	fixture := newHandlerFixture(t, 0)
	writer := &lfsTestWriter{Service: fixture.bucket, objects: make(map[lfsObjectKey]xethash.Hash)}
	handler := newLFSHandler(t, fixture, writer)
	base := time.Unix(2_200_000_000, 0).UTC()
	handler.now = func() time.Time { return base }
	_ = requestLFSHref(t, handler, []byte("first capability"))
	if len(handler.lfsUploads) != 1 {
		t.Fatalf("initial capabilities = %d", len(handler.lfsUploads))
	}
	handler.now = func() time.Time { return base.Add(2 * handler.lfsTTL) }
	_ = requestLFSHref(t, handler, []byte("second capability"))
	if len(handler.lfsUploads) != 1 {
		t.Fatalf("capabilities after cleanup = %d", len(handler.lfsUploads))
	}
	handler.finishLFSUpload("not-issued", true)
}

func TestLFSUploadCapabilityWorksAcrossInstancesAndRestart(t *testing.T) {
	fixture := newHandlerFixture(t, 0)
	writer := &lfsTestWriter{Service: fixture.bucket, objects: make(map[lfsObjectKey]xethash.Hash)}
	key := bytes.Repeat([]byte{0x6b}, 32)
	issuer := newLFSHandlerWithKey(t, fixture, writer, key)
	receiver := newLFSHandlerWithKey(t, fixture, writer, key)
	body := []byte("shared capability key object")
	href := requestLFSHref(t, issuer, body)
	upload := requestBody(t, http.StripPrefix("/base", receiver), http.MethodPut, externalHandlerTarget(href), "", bytes.NewReader(body), nil)
	if upload.Code != http.StatusOK || writer.calls != 1 {
		t.Fatalf("cross-instance upload = %d, calls=%d, body=%s", upload.Code, writer.calls, upload.Body.String())
	}

	restarted := newLFSHandlerWithKey(t, fixture, writer, key)
	replay := requestBody(t, http.StripPrefix("/base", restarted), http.MethodPut, externalHandlerTarget(href), "", bytes.NewReader(body), nil)
	if replay.Code != http.StatusUnauthorized || writer.calls != 1 {
		t.Fatalf("post-restart replay = %d, calls=%d", replay.Code, writer.calls)
	}
}

func newLFSHandler(t *testing.T, fixture handlerFixture, writer *lfsTestWriter) *Service {
	t.Helper()
	return newLFSHandlerWithKey(t, fixture, writer, nil)
}

func newLFSHandlerWithKey(t *testing.T, fixture handlerFixture, writer *lfsTestWriter, key []byte) *Service {
	t.Helper()
	handler, err := New(Options{
		Bucket: fixture.bucket, Writer: writer, Publisher: fixture.bucket, Ingester: XetFileIngestFunc(writer.ingest),
		Broker: fixture.handler.broker, HubBaseURL: "https://hub.test/base", CASBaseURL: "https://cas.test/base",
		LFSUploadCapabilityKey: key,
	})
	if err != nil {
		t.Fatal(err)
	}
	return handler
}

func requestLFSHref(t *testing.T, handler *Service, body []byte) string {
	t.Helper()
	sum := sha256.Sum256(body)
	response := requestBody(t, handler, http.MethodPost, "/owner/model.git/info/lfs/objects/batch", "Bearer hub-token", bytes.NewReader(lfsBatchBody(t,
		lfsObjectDTO{OID: hex.EncodeToString(sum[:]), Size: int64(len(body))},
	)), map[string]string{"Content-Type": lfsMediaType})
	var decoded lfsBatchResponseDTO
	if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &decoded) != nil || len(decoded.Objects) != 1 || decoded.Objects[0].Actions == nil {
		t.Fatalf("batch = %d, %s", response.Code, response.Body.String())
	}
	return decoded.Objects[0].Actions.Upload.Href
}

func lfsBatchBody(t *testing.T, objects ...lfsObjectDTO) []byte {
	t.Helper()
	return marshalJSON(t, lfsBatchDTO{
		Operation: "upload", Transfers: []string{"basic", "multipart"}, Objects: objects,
		HashAlgo: "sha256", Ref: &lfsRefDTO{Name: "main"},
	})
}

func lfsHandlerTarget(href string) string {
	parsed, _ := url.Parse(href)
	parsed.Scheme = ""
	parsed.Host = ""
	parsed.Path = strings.TrimPrefix(parsed.Path, "/base")
	return parsed.String()
}

func externalHandlerTarget(href string) string {
	parsed, _ := url.Parse(href)
	parsed.Scheme = ""
	parsed.Host = ""
	return parsed.String()
}
