package server

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/jmwoliver/xet-go/shard"
	"github.com/jmwoliver/xet-go/xetcas"
	"github.com/jmwoliver/xet-go/xethash"
)

const maxBatchRequestBody = 1 << 20

func (s *Service) Handler() http.Handler { return http.HandlerFunc(s.serveHTTP) }

func (s *Service) serveHTTP(w http.ResponseWriter, r *http.Request) {
	credential, err := bearerCredential(r.Header.Get("Authorization"))
	if err != nil {
		writeServerError(w, r, err)
		return
	}
	path := strings.TrimPrefix(r.URL.Path, "/")
	parts := strings.Split(path, "/")

	switch {
	case path == "v1/reconstructions" && (r.Method == http.MethodPost || r.Method == http.MethodGet):
		s.handleBatchReconstruction(w, r, credential)
	case len(parts) == 3 && parts[0] == "v2" && parts[1] == "reconstructions" && r.Method == http.MethodGet:
		hash, ok := parseRouteHash(w, r, parts[2])
		if ok {
			s.handleReconstructionV2(w, r, credential, hash)
		}
	case len(parts) == 3 && parts[0] == "v1" && parts[1] == "reconstructions" && r.Method == http.MethodGet:
		hash, ok := parseRouteHash(w, r, parts[2])
		if ok {
			s.handleReconstructionV1(w, r, credential, hash)
		}
	case len(parts) == 4 && parts[0] == "v1" && parts[1] == "chunks" && r.Method == http.MethodGet:
		hash, ok := parseRouteHash(w, r, parts[3])
		if ok {
			s.handleGlobalDedup(w, r, credential, parts[2], hash)
		}
	case len(parts) == 4 && parts[0] == "v1" && parts[1] == "xorbs" &&
		(r.Method == http.MethodPost || r.Method == http.MethodHead):
		hash, ok := parseRouteHash(w, r, parts[3])
		if ok {
			s.handleXorb(w, r, credential, parts[2], hash)
		}
	case path == "v2/shards" && r.Method == http.MethodPost:
		s.handleShardV2(w, r, credential)
	case path == "v1/shards" && r.Method == http.MethodPost:
		s.handleShardV1(w, r, credential)
	case len(parts) == 3 && parts[0] == "v1" && parts[1] == "files" && r.Method == http.MethodHead:
		hash, ok := parseRouteHash(w, r, parts[2])
		if ok {
			s.handleFileHead(w, r, credential, hash)
		}
	case len(parts) == 3 && parts[0] == "v2" && parts[1] == "file-chunk-hashes" && r.Method == http.MethodGet:
		hash, ok := parseRouteHash(w, r, parts[2])
		if ok {
			s.handleFileChunkHashes(w, r, credential, hash)
		}
	default:
		http.NotFound(w, r)
	}
}

func (s *Service) handleXorb(w http.ResponseWriter, r *http.Request, credential, prefix string, hash xethash.Hash) {
	if r.Method == http.MethodHead {
		found, err := s.XorbExists(r.Context(), credential, prefix, hash)
		if err != nil {
			writeServerError(w, r, err)
			return
		}
		if !found {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Length", "0")
		w.WriteHeader(http.StatusOK)
		return
	}
	inserted, err := s.UploadXorb(r.Context(), credential, prefix, hash, r.Body, r.ContentLength)
	if err != nil {
		writeServerError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, struct {
		WasInserted bool `json:"was_inserted"`
	}{WasInserted: inserted})
}

func (s *Service) handleShardV1(w http.ResponseWriter, r *http.Request, credential string) {
	result, err := s.UploadShard(r.Context(), credential, r.Body, r.ContentLength)
	if err != nil {
		writeServerError(w, r, err)
		return
	}
	value := 0
	if result.Inserted {
		value = 1
	}
	writeJSON(w, http.StatusOK, struct {
		Result int `json:"result"`
	}{Result: value})
}

func (s *Service) handleShardV2(w http.ResponseWriter, r *http.Request, credential string) {
	grant, err := s.authorize(r.Context(), credential, AccessRequest{Operation: OperationWriteShard})
	if err != nil {
		writeServerError(w, r, err)
		return
	}
	release, err := s.acquireIngest(r.Context())
	if err != nil {
		writeServerError(w, r, err)
		return
	}
	data, err := readBounded(r.Body, r.ContentLength, s.maxShard)
	if err != nil {
		release()
		writeServerError(w, r, err)
		return
	}
	w.Header().Set("Content-Type", "application/x-ndjson")
	w.WriteHeader(http.StatusOK)
	encoder := json.NewEncoder(w)
	type validationEvent struct {
		Type     string `json:"type"`
		Verified uint64 `json:"verified"`
		Total    uint64 `json:"total"`
	}
	last := validationEvent{Type: "validating"}
	if encoder.Encode(last) != nil {
		release()
		return
	}
	flushResponse(w)
	type outcome struct {
		result ShardResult
		err    error
	}
	completed := make(chan outcome, 1)
	go func() {
		defer release()
		result, err := s.publishShard(r.Context(), grant, data)
		completed <- outcome{result: result, err: err}
	}()
	ticker := time.NewTicker(s.shardHeartbeat)
	defer ticker.Stop()
	for {
		select {
		case value := <-completed:
			if value.err != nil {
				_ = encoder.Encode(xetcas.ShardUploadEvent{
					Type: "error", Message: http.StatusText(serverErrorStatus(value.err)),
					Retryable: serverErrorStatus(value.err) >= http.StatusInternalServerError,
				})
				flushResponse(w)
				return
			}
			if encoder.Encode(validationEvent{
				Type: "validating", Verified: uint64(value.result.Files), Total: uint64(value.result.Files),
			}) != nil {
				return
			}
			if encoder.Encode(xetcas.ShardUploadEvent{Type: "committing", Stage: "syncing"}) != nil {
				return
			}
			_ = encoder.Encode(xetcas.ShardUploadEvent{Type: "result"})
			flushResponse(w)
			return
		case <-ticker.C:
			if encoder.Encode(last) != nil {
				return
			}
			flushResponse(w)
		case <-r.Context().Done():
			return
		}
	}
}

func flushResponse(w http.ResponseWriter) {
	if flusher, ok := w.(http.Flusher); ok {
		flusher.Flush()
	}
}

func (s *Service) handleFileHead(w http.ResponseWriter, r *http.Request, credential string, hash xethash.Hash) {
	value, err := s.File(r.Context(), credential, hash)
	if err != nil {
		writeServerError(w, r, err)
		return
	}
	w.Header().Set("Content-Length", strconv.FormatUint(value.File.Size, 10))
	w.WriteHeader(http.StatusOK)
}

func (s *Service) handleReconstructionV2(w http.ResponseWriter, r *http.Request, credential string, hash xethash.Hash) {
	wanted, err := parseOptionalRange(r.Header.Get("Range"))
	if err != nil {
		writeServerError(w, r, err)
		return
	}
	value, err := s.ReconstructionV2(r.Context(), credential, hash, wanted)
	if err != nil {
		writeServerError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, value)
}

func (s *Service) handleReconstructionV1(w http.ResponseWriter, r *http.Request, credential string, hash xethash.Hash) {
	wanted, err := parseOptionalRange(r.Header.Get("Range"))
	if err != nil {
		writeServerError(w, r, err)
		return
	}
	value, err := s.ReconstructionV1(r.Context(), credential, hash, wanted)
	if err != nil {
		writeServerError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, value)
}

func (s *Service) handleBatchReconstruction(w http.ResponseWriter, r *http.Request, credential string) {
	var hashes []xethash.Hash
	if r.Method == http.MethodPost {
		var keys []xetcas.Key
		if err := decodeBoundedJSON(r.Body, maxBatchRequestBody, &keys); err != nil {
			if errors.Is(err, ErrTooLarge) {
				writeServerError(w, r, err)
				return
			}
			writeServerError(w, r, fmt.Errorf("%w: %v", ErrInvalid, err))
			return
		}
		if len(keys) > 10_000 {
			writeServerError(w, r, fmt.Errorf("%w: batch exceeds 10000 files", ErrInvalid))
			return
		}
		for _, key := range keys {
			if key.Prefix != xetcas.DefaultFilePrefix {
				writeServerError(w, r, fmt.Errorf("%w: unsupported file prefix %q", ErrInvalid, key.Prefix))
				return
			}
			hashes = append(hashes, key.Hash)
		}
	} else {
		values := r.URL.Query()["file_id"]
		if len(values) > 10_000 {
			writeServerError(w, r, fmt.Errorf("%w: batch exceeds 10000 files", ErrInvalid))
			return
		}
		for _, value := range values {
			hash, err := xethash.Parse(value)
			if err != nil {
				writeServerError(w, r, fmt.Errorf("%w: invalid file hash", ErrInvalid))
				return
			}
			hashes = append(hashes, hash)
		}
	}
	value, err := s.BatchReconstructionV1(r.Context(), credential, hashes)
	if err != nil {
		writeServerError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, value)
}

func (s *Service) handleGlobalDedup(w http.ResponseWriter, r *http.Request, credential, prefix string, hash xethash.Hash) {
	body, err := s.GlobalDedup(r.Context(), credential, prefix, hash)
	if err != nil {
		writeServerError(w, r, err)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}

func (s *Service) handleFileChunkHashes(w http.ResponseWriter, r *http.Request, credential string, hash xethash.Hash) {
	dirty, err := parseRanges(r.Header.Get(xetcas.DirtyRangeHeader))
	if err != nil {
		writeServerError(w, r, fmt.Errorf("%w: %v", ErrInvalid, err))
		return
	}
	for i := 1; i < len(dirty); i++ {
		if dirty[i-1].End > dirty[i].Start {
			writeServerError(w, r, fmt.Errorf("%w: dirty ranges overlap or are unsorted", ErrInvalid))
			return
		}
	}
	value, err := s.FileChunkHashes(r.Context(), credential, hash, dirty)
	if err != nil {
		writeServerError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, value)
}

func bearerCredential(header string) (string, error) {
	if header == "" {
		return "", nil
	}
	scheme, value, ok := strings.Cut(header, " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") || value == "" || strings.ContainsAny(value, " \t\r\n,") {
		return "", ErrUnauthorized
	}
	return value, nil
}

func parseRouteHash(w http.ResponseWriter, r *http.Request, value string) (xethash.Hash, bool) {
	hash, err := xethash.Parse(value)
	if err != nil {
		writeServerError(w, r, fmt.Errorf("%w: invalid hash", ErrInvalid))
		return xethash.Hash{}, false
	}
	return hash, true
}

func parseOptionalRange(value string) (*xetcas.FileRange, error) {
	if value == "" {
		return nil, nil
	}
	ranges, err := parseRanges(value)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	if len(ranges) != 1 {
		return nil, fmt.Errorf("%w: reconstruction requires one range", ErrInvalid)
	}
	return &ranges[0], nil
}

func parseRanges(value string) ([]xetcas.FileRange, error) {
	prefix, values, ok := strings.Cut(value, "=")
	if !ok || !strings.EqualFold(strings.TrimSpace(prefix), "bytes") || values == "" {
		return nil, errors.New("expected bytes=start-end")
	}
	parts := strings.Split(values, ",")
	ranges := make([]xetcas.FileRange, 0, len(parts))
	for _, part := range parts {
		startText, endText, ok := strings.Cut(strings.TrimSpace(part), "-")
		if !ok || startText == "" || endText == "" {
			return nil, errors.New("open or suffix ranges are unsupported")
		}
		start, err := strconv.ParseUint(startText, 10, 64)
		if err != nil {
			return nil, errors.New("invalid range start")
		}
		end, err := strconv.ParseUint(endText, 10, 64)
		if err != nil || end < start || end == ^uint64(0) {
			return nil, errors.New("invalid range end")
		}
		ranges = append(ranges, xetcas.FileRange{Start: start, End: end + 1})
	}
	return ranges, nil
}

func decodeBoundedJSON(body io.Reader, limit int64, destination any) error {
	data, err := io.ReadAll(io.LimitReader(body, limit+1))
	if err != nil {
		return err
	}
	if int64(len(data)) > limit {
		return ErrTooLarge
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	if decoder.Decode(new(any)) != io.EOF {
		return errors.New("multiple JSON values")
	}
	return nil
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func writeServerError(w http.ResponseWriter, r *http.Request, err error) {
	status := serverErrorStatus(err)
	if status == http.StatusUnauthorized {
		w.Header().Set("WWW-Authenticate", "Bearer")
	}
	if r.Method == http.MethodHead {
		w.WriteHeader(status)
		return
	}
	http.Error(w, http.StatusText(status), status)
}

func serverErrorStatus(err error) int {
	switch {
	case errors.Is(err, shard.ErrXorbLookup):
		return http.StatusInternalServerError
	case errors.Is(err, ErrUnauthorized):
		return http.StatusUnauthorized
	case errors.Is(err, ErrForbidden):
		return http.StatusForbidden
	case errors.Is(err, ErrNotFound):
		return http.StatusNotFound
	case errors.Is(err, xetcas.ErrRangeNotSatisfiable):
		return http.StatusRequestedRangeNotSatisfiable
	case errors.Is(err, ErrTooLarge):
		return http.StatusRequestEntityTooLarge
	case errors.Is(err, ErrConflict):
		return http.StatusConflict
	case errors.Is(err, ErrInvalid):
		return http.StatusBadRequest
	}
	return http.StatusInternalServerError
}
