package hfcompat

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/jmwoliver/xet-go/auth"
	"github.com/jmwoliver/xet-go/bucket"
	"github.com/jmwoliver/xet-go/model"
)

const lfsMediaType = "application/vnd.git-lfs+json"

var errUploadCapability = errors.New("hfcompat: invalid or expired upload capability")

type lfsBatchDTO struct {
	Operation string         `json:"operation"`
	Transfers []string       `json:"transfers"`
	Objects   []lfsObjectDTO `json:"objects"`
	HashAlgo  string         `json:"hash_algo"`
	Ref       *lfsRefDTO     `json:"ref,omitempty"`
}

type lfsRefDTO struct {
	Name string `json:"name"`
}

type lfsObjectDTO struct {
	OID     string         `json:"oid"`
	Size    int64          `json:"size"`
	Actions *lfsActionsDTO `json:"actions,omitempty"`
}

type lfsActionsDTO struct {
	Upload lfsActionDTO `json:"upload"`
}

type lfsActionDTO struct {
	Href   string            `json:"href"`
	Header map[string]string `json:"header"`
}

type lfsBatchResponseDTO struct {
	Objects  []lfsObjectDTO `json:"objects"`
	Transfer string         `json:"transfer"`
}

type lfsUploadState struct {
	repo      model.RepoKey
	principal auth.Principal
	oid       [32]byte
	size      int64
	expiresAt time.Time
	active    bool
	used      bool
}

func (s *Service) lfsBatchRequest(w http.ResponseWriter, r *http.Request, rt route, principal auth.Principal, bases baseURLs) {
	if s.writer == nil || s.ingester == nil {
		s.fail(w, r, bucket.ErrUnsupported)
		return
	}
	if _, err := s.bucket.GetRepository(r.Context(), rt.repo); err != nil {
		s.failNotFound(w, r, err, "RepoNotFound")
		return
	}
	if r.URL.RawQuery != "" || mediaType(r.Header.Get("Content-Type")) != lfsMediaType {
		s.fail(w, r, errInput)
		return
	}
	maximumBody := int64(s.lfsBatch)*(64+256) + 4096
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, maximumBody))
	decoder.DisallowUnknownFields()
	var request lfsBatchDTO
	if err := decoder.Decode(&request); err != nil {
		s.failJSONInput(w, r, err)
		return
	}
	if err := requireJSONEOF(decoder); err != nil {
		s.failJSONInput(w, r, err)
		return
	}
	if len(request.Objects) > s.lfsBatch {
		s.failStatus(w, r, http.StatusRequestEntityTooLarge)
		return
	}
	if request.Operation != "upload" || request.HashAlgo != "sha256" || !containsString(request.Transfers, "basic") {
		s.fail(w, r, errInput)
		return
	}
	if request.Ref != nil {
		if _, err := model.ParseRevision(request.Ref.Name); err != nil {
			s.fail(w, r, errInput)
			return
		}
	}
	response := lfsBatchResponseDTO{Objects: make([]lfsObjectDTO, len(request.Objects)), Transfer: "basic"}
	seen := make(map[[32]byte]struct{}, len(request.Objects))
	for index, object := range request.Objects {
		oid, err := parseLFSOID(object.OID)
		if err != nil || object.Size < 0 {
			s.fail(w, r, errInput)
			return
		}
		if object.Size > s.fileBytes {
			s.failStatus(w, r, http.StatusRequestEntityTooLarge)
			return
		}
		if _, duplicate := seen[oid]; duplicate {
			s.fail(w, r, errInput)
			return
		}
		seen[oid] = struct{}{}
		response.Objects[index] = lfsObjectDTO{OID: object.OID, Size: object.Size}
		if _, err = s.writer.ResolveXetFile(r.Context(), rt.repo, oid, uint64(object.Size)); err == nil {
			continue
		} else if !errors.Is(err, bucket.ErrContentNotUploaded) {
			s.fail(w, r, err)
			return
		}
		href, err := s.newLFSUploadCapability(rt.repo, principal, oid, object.Size, bases)
		if err != nil {
			s.fail(w, r, err)
			return
		}
		response.Objects[index].Actions = &lfsActionsDTO{Upload: lfsActionDTO{Href: href, Header: map[string]string{}}}
	}
	w.Header().Set("Content-Type", lfsMediaType)
	w.Header().Set("Cache-Control", "private, no-store")
	_ = json.NewEncoder(w).Encode(response)
}

func (s *Service) newLFSUploadCapability(
	repo model.RepoKey,
	principal auth.Principal,
	oid [32]byte,
	size int64,
	bases baseURLs,
) (string, error) {
	nonceBytes := make([]byte, 18)
	if _, err := rand.Read(nonceBytes); err != nil {
		return "", fmt.Errorf("hfcompat: generate LFS capability: %w", err)
	}
	nonce := base64.RawURLEncoding.EncodeToString(nonceBytes)
	now := s.now()
	expiresAt := now.UTC().Add(s.lfsTTL)
	signature := s.signLFSUpload(repo, principal.Subject, oid, size, expiresAt.Unix(), nonce)
	s.lfsMu.Lock()
	for key, state := range s.lfsUploads {
		if state.used || !now.Before(state.expiresAt) {
			delete(s.lfsUploads, key)
		}
	}
	s.lfsUploads[nonce] = lfsUploadState{repo: repo, principal: principal, oid: oid, size: size, expiresAt: expiresAt}
	s.lfsMu.Unlock()
	query := make(url.Values)
	query.Set("expires", strconv.FormatInt(expiresAt.Unix(), 10))
	query.Set("nonce", nonce)
	query.Set("size", strconv.FormatInt(size, 10))
	query.Set("signature", signature)
	query.Set("subject", base64.RawURLEncoding.EncodeToString([]byte(principal.Subject)))
	return bases.hub + "/" + url.PathEscape(string(repo.Namespace)) + "/" + url.PathEscape(string(repo.Name)) +
		".git/info/lfs/objects/upload/" + hex.EncodeToString(oid[:]) + "?" + query.Encode(), nil
}

func (s *Service) lfsUpload(w http.ResponseWriter, r *http.Request, rt route, auditEvent *WriteAuditEvent) {
	if s.writer == nil || s.ingester == nil {
		s.fail(w, r, bucket.ErrUnsupported)
		return
	}
	state, nonce, err := s.claimLFSUpload(r, rt)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if auditEvent != nil {
		auditEvent.Principal = state.principal
	}
	succeeded := false
	defer func() { s.finishLFSUpload(nonce, succeeded) }()
	if _, err = s.writer.ResolveXetFile(r.Context(), state.repo, state.oid, uint64(state.size)); err == nil {
		s.fail(w, r, errUploadCapability)
		return
	} else if !errors.Is(err, bucket.ErrContentNotUploaded) {
		s.fail(w, r, err)
		return
	}
	if r.ContentLength >= 0 && r.ContentLength != state.size {
		s.fail(w, r, errInput)
		return
	}
	temporary, err := os.CreateTemp("", "xet-go-lfs-upload-*")
	if err != nil {
		s.fail(w, r, bucket.ErrUnavailable)
		return
	}
	name := temporary.Name()
	defer func() { _ = os.Remove(name) }()
	defer func() { _ = temporary.Close() }()
	digest := sha256.New()
	written, err := io.Copy(io.MultiWriter(temporary, digest), io.LimitReader(r.Body, state.size+1))
	if err != nil || written != state.size {
		s.fail(w, r, errInput)
		return
	}
	var got [32]byte
	copy(got[:], digest.Sum(nil))
	if got != state.oid {
		s.fail(w, r, errInput)
		return
	}
	if !s.now().Before(state.expiresAt) {
		s.fail(w, r, errUploadCapability)
		return
	}
	if _, err = temporary.Seek(0, io.SeekStart); err != nil {
		s.fail(w, r, bucket.ErrUnavailable)
		return
	}
	result, err := s.ingester.IngestXetFile(r.Context(), state.repo, temporary)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if result.Size != uint64(state.size) || result.SHA256 != state.oid {
		s.fail(w, r, bucket.ErrInvariant)
		return
	}
	resolved, err := s.writer.ResolveXetFile(r.Context(), state.repo, state.oid, result.Size)
	if err != nil || resolved != result.Hash {
		s.fail(w, r, errors.Join(bucket.ErrInvariant, err))
		return
	}
	succeeded = true
	w.WriteHeader(http.StatusOK)
}

func (s *Service) claimLFSUpload(r *http.Request, rt route) (lfsUploadState, string, error) {
	query, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil || len(query) != 5 {
		return lfsUploadState{}, "", errUploadCapability
	}
	value := func(name string) (string, bool) {
		values, exists := query[name]
		returnValue := ""
		if exists && len(values) == 1 {
			returnValue = values[0]
		}
		return returnValue, exists && len(values) == 1 && returnValue != ""
	}
	nonce, nonceOK := value("nonce")
	sizeText, sizeOK := value("size")
	expiresText, expiresOK := value("expires")
	signature, signatureOK := value("signature")
	subjectText, subjectOK := value("subject")
	size, sizeErr := strconv.ParseInt(sizeText, 10, 64)
	expires, expiresErr := strconv.ParseInt(expiresText, 10, 64)
	subject, subjectErr := base64.RawURLEncoding.DecodeString(subjectText)
	principal := auth.Principal{Subject: string(subject)}
	if !nonceOK || !sizeOK || !expiresOK || !signatureOK || !subjectOK || sizeErr != nil || expiresErr != nil || subjectErr != nil ||
		size < 0 || principal.Validate() != nil {
		return lfsUploadState{}, "", errUploadCapability
	}
	want := s.signLFSUpload(rt.repo, principal.Subject, rt.lfsOID, size, expires, nonce)
	if !hmac.Equal([]byte(signature), []byte(want)) {
		return lfsUploadState{}, "", errUploadCapability
	}
	s.lfsMu.Lock()
	defer s.lfsMu.Unlock()
	state, exists := s.lfsUploads[nonce]
	if !exists {
		state = lfsUploadState{
			repo: rt.repo, principal: principal, oid: rt.lfsOID, size: size,
			expiresAt: time.Unix(expires, 0).UTC(),
		}
	}
	if state.active || state.used || state.repo != rt.repo || state.principal != principal || state.oid != rt.lfsOID || state.size != size ||
		state.expiresAt.Unix() != expires || !s.now().Before(state.expiresAt) {
		return lfsUploadState{}, "", errUploadCapability
	}
	state.active = true
	s.lfsUploads[nonce] = state
	return state, nonce, nil
}

func (s *Service) finishLFSUpload(nonce string, success bool) {
	s.lfsMu.Lock()
	defer s.lfsMu.Unlock()
	state, exists := s.lfsUploads[nonce]
	if !exists {
		return
	}
	state.active = false
	state.used = success
	s.lfsUploads[nonce] = state
}

func (s *Service) signLFSUpload(repo model.RepoKey, subject string, oid [32]byte, size, expires int64, nonce string) string {
	// Deliberately do not bind a base URL: the same repository may be reached
	// through multiple public addresses. RepoKey binds the logical upload target.
	digest := hmac.New(sha256.New, s.lfsKey[:])
	_, _ = fmt.Fprintf(digest, "xet-go-lfs-v1\x00%s\x00%s\x00%s\x00%s\x00%x\x00%d\x00%d\x00%s",
		repo.Type, repo.Namespace, repo.Name, subject, oid, size, expires, nonce)
	return base64.RawURLEncoding.EncodeToString(digest.Sum(nil))
}

func parseLFSOID(value string) ([32]byte, error) {
	var oid [32]byte
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != len(oid) || value != strings.ToLower(value) {
		return oid, errInput
	}
	copy(oid[:], decoded)
	return oid, nil
}

func containsString(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

func mediaType(value string) string {
	if index := strings.IndexByte(value, ';'); index >= 0 {
		value = value[:index]
	}
	return strings.TrimSpace(strings.ToLower(value))
}

var _ XetFileIngester = XetFileIngestFunc(nil)

type XetFileIngestFunc func(context.Context, model.RepoKey, io.Reader) (XetFileIngestResult, error)

func (function XetFileIngestFunc) IngestXetFile(ctx context.Context, repo model.RepoKey, source io.Reader) (XetFileIngestResult, error) {
	return function(ctx, repo, source)
}
