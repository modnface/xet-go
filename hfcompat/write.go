package hfcompat

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha1" //nolint:gosec // Git blob identity is a pinned Hub wire compatibility requirement.
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/jmwoliver/xet-go/auth"
	"github.com/jmwoliver/xet-go/bucket"
	"github.com/jmwoliver/xet-go/catalog"
	"github.com/jmwoliver/xet-go/content"
	"github.com/jmwoliver/xet-go/model"
)

const (
	maxCreateBodyBytes = 64 << 10
	maxUploadSample    = 512
)

var (
	errCommitInput    = errors.New("hfcompat: invalid commit body")
	errCommitTooLarge = errors.New("hfcompat: commit body limit exceeded")
)

type whoamiDTO struct {
	Type string `json:"type"`
	Name string `json:"name"`
}

// whoami deliberately exposes only the stable principal subject. Pinned write
// clients require name; richer organization and role data remains host policy.
func (s *Service) whoami(w http.ResponseWriter, r *http.Request, principal auth.Principal) {
	s.json(w, r, whoamiDTO{Type: "user", Name: principal.Subject})
}

type createRepositoryDTO struct {
	Name         string  `json:"name"`
	Organization *string `json:"organization"`
	Type         string  `json:"type"`
	Visibility   string  `json:"visibility"`
}

func (s *Service) createRepository(
	w http.ResponseWriter,
	r *http.Request,
	credential string,
	principal auth.Principal,
	auditEvent *WriteAuditEvent,
) {
	if s.writer == nil {
		s.fail(w, r, bucket.ErrUnsupported)
		return
	}
	var request createRepositoryDTO
	body := http.MaxBytesReader(w, r.Body, maxCreateBodyBytes)
	decoder := json.NewDecoder(body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		s.failJSONInput(w, r, err)
		return
	}
	if err := requireJSONEOF(decoder); err != nil {
		s.failJSONInput(w, r, err)
		return
	}
	if request.Type != "" && request.Type != string(model.RepoTypeModel) {
		w.Header().Set("X-Error-Code", "UnsupportedRepoType")
		s.fail(w, r, bucket.ErrUnsupported)
		return
	}
	if request.Visibility != "" && request.Visibility != "public" && request.Visibility != "private" {
		s.fail(w, r, errInput)
		return
	}
	namespace := principal.Subject
	if request.Organization != nil {
		namespace = *request.Organization
	}
	repo, err := model.NewRepoKey(namespace, request.Name, model.RepoTypeModel)
	if err != nil {
		s.fail(w, r, fmt.Errorf("%w: repository key: %v", errInput, err))
		return
	}
	if auditEvent != nil {
		auditEvent.Repository = repo
	}
	if _, err = s.broker.AuthorizeRepository(r.Context(), credential, repo, auth.RepositoryWrite); err != nil {
		if errors.Is(err, auth.ErrPermissionDenied) {
			w.Header().Set("X-Error-Code", "RepoNotFound")
		}
		s.fail(w, r, err)
		return
	}
	bases, err := s.resolveBaseURLs(r)
	if err != nil {
		s.failBaseURLResolution(w, r, err)
		return
	}
	result := struct {
		URL string `json:"url"`
	}{URL: bases.hub + "/" + url.PathEscape(string(repo.Namespace)) + "/" + url.PathEscape(string(repo.Name))}
	err = s.writer.CreateRepository(r.Context(), model.Repository{Key: repo, CreatedAt: time.Now().UTC()})
	if errors.Is(err, bucket.ErrConflict) {
		s.jsonStatus(w, r, http.StatusConflict, result)
		return
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.json(w, r, result)
}

func requireJSONEOF(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); err == nil {
		return errors.New("multiple JSON values")
	} else if !errors.Is(err, io.EOF) {
		return err
	}
	return nil
}

func (s *Service) failJSONInput(w http.ResponseWriter, r *http.Request, err error) {
	var tooLarge *http.MaxBytesError
	if errors.As(err, &tooLarge) {
		s.failStatus(w, r, http.StatusRequestEntityTooLarge)
		return
	}
	s.fail(w, r, errInput)
}

func (s *Service) jsonStatus(w http.ResponseWriter, r *http.Request, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "private, no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

type preuploadRequestDTO struct {
	Files     []preuploadFileRequestDTO `json:"files"`
	GitIgnore *string                   `json:"gitIgnore,omitempty"`
}

type preuploadFileRequestDTO struct {
	Path   string `json:"path"`
	Sample []byte `json:"sample"`
	Size   int64  `json:"size"`
}

type preuploadResponseDTO struct {
	Files []preuploadFileResponseDTO `json:"files"`
}

type preuploadFileResponseDTO struct {
	Path         string  `json:"path"`
	UploadMode   string  `json:"uploadMode"`
	ShouldIgnore bool    `json:"shouldIgnore"`
	OID          *string `json:"oid"`
}

func (s *Service) preupload(w http.ResponseWriter, r *http.Request, rt route) {
	if r.URL.RawQuery != "" {
		s.fail(w, r, bucket.ErrUnsupported)
		return
	}
	maximumBody := int64(s.preuploadMax)*(int64(s.pathBytes)+4*maxUploadSample/3+256) + 4096
	body := http.MaxBytesReader(w, r.Body, maximumBody)
	decoder := json.NewDecoder(body)
	decoder.DisallowUnknownFields()
	var request preuploadRequestDTO
	if err := decoder.Decode(&request); err != nil {
		s.failJSONInput(w, r, err)
		return
	}
	if err := requireJSONEOF(decoder); err != nil {
		s.failJSONInput(w, r, err)
		return
	}
	if len(request.Files) > s.preuploadMax {
		s.failStatus(w, r, http.StatusRequestEntityTooLarge)
		return
	}
	parent, err := s.resolveOptionalRevision(r.Context(), rt)
	if err != nil {
		s.failRevision(w, r, rt.repo, err)
		return
	}
	current := make(map[model.FilePath]model.FileRef)
	if parent != nil {
		for _, entry := range parent.Files {
			current[entry.Path] = entry.Ref
		}
	}
	response := preuploadResponseDTO{Files: make([]preuploadFileResponseDTO, len(request.Files))}
	seen := make(map[model.FilePath]struct{}, len(request.Files))
	for index, file := range request.Files {
		path, err := s.commitPath(file.Path)
		if err != nil || file.Size < 0 || len(file.Sample) > maxUploadSample {
			s.fail(w, r, errInput)
			return
		}
		if file.Size > s.fileBytes {
			s.failStatus(w, r, http.StatusRequestEntityTooLarge)
			return
		}
		if _, duplicate := seen[path]; duplicate {
			s.fail(w, r, errInput)
			return
		}
		seen[path] = struct{}{}
		mode := "regular"
		if file.Size >= s.large && file.Size != 0 {
			mode = "lfs"
		}
		var oid *string
		if ref, exists := current[path]; exists {
			oid, err = s.remoteFileOID(r.Context(), rt.repo, parent.OID, path, ref)
			if err != nil {
				s.fail(w, r, err)
				return
			}
		}
		response.Files[index] = preuploadFileResponseDTO{
			Path: string(path), UploadMode: mode, ShouldIgnore: false, OID: oid,
		}
	}
	s.json(w, r, response)
}

func (s *Service) remoteFileOID(
	ctx context.Context,
	repo model.RepoKey,
	snapshotOID model.OID,
	path model.FilePath,
	ref model.FileRef,
) (*string, error) {
	if ref.Kind() == model.FileKindXet {
		sum, ok := ref.SHA256()
		if !ok || s.writer == nil {
			return nil, nil
		}
		if _, err := s.writer.ResolveXetFile(ctx, repo, sum, uint64(ref.FileSize())); err != nil {
			if errors.Is(err, bucket.ErrContentNotUploaded) {
				return nil, nil
			}
			return nil, err
		}
		value := hex.EncodeToString(sum[:])
		return &value, nil
	}
	pinned, err := model.RevisionFromOID(snapshotOID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid resolved snapshot OID", bucket.ErrInvariant)
	}
	opened, err := s.bucket.OpenFile(ctx, repo, pinned, path, bucket.OpenOptions{})
	if err != nil {
		if errors.Is(err, bucket.ErrNotFound) || errors.Is(err, bucket.ErrContentNotUploaded) || errors.Is(err, content.ErrNotFound) {
			return nil, nil
		}
		return nil, err
	}
	digest := sha1.New() //nolint:gosec // Git blob identity is required by huggingface_hub's no-op comparison.
	_, _ = fmt.Fprintf(digest, "blob %d\x00", ref.FileSize())
	_, copyErr := io.Copy(digest, opened.Body)
	closeErr := opened.Body.Close()
	if copyErr != nil {
		return nil, copyErr
	}
	if closeErr != nil {
		return nil, closeErr
	}
	value := hex.EncodeToString(digest.Sum(nil))
	return &value, nil
}

// resolveOptionalRevision returns nil only when the repository exists but the
// requested ref does not yet exist, as for the first commit to main.
func (s *Service) resolveOptionalRevision(ctx context.Context, rt route) (*model.Snapshot, error) {
	snapshot, err := s.bucket.ResolveRevision(ctx, rt.repo, rt.revision)
	if err == nil {
		return &snapshot, nil
	}
	if !errors.Is(err, bucket.ErrNotFound) {
		return nil, err
	}
	if _, explicit := rt.revision.OID(); explicit {
		return nil, err
	}
	if _, repositoryErr := s.bucket.GetRepository(ctx, rt.repo); repositoryErr != nil {
		return nil, repositoryErr
	}
	return nil, nil
}

type commitEnvelopeDTO struct {
	Key   string          `json:"key"`
	Value json.RawMessage `json:"value"`
}

type commitHeaderDTO struct {
	Summary      string `json:"summary"`
	Description  string `json:"description"`
	ParentCommit string `json:"parentCommit,omitempty"`
}

type commitFileDTO struct {
	Content  string `json:"content"`
	Path     string `json:"path"`
	Encoding string `json:"encoding"`
}

type commitLFSFileDTO struct {
	Path string `json:"path"`
	Algo string `json:"algo"`
	OID  string `json:"oid"`
	Size *int64 `json:"size"`
}

type commitDeleteDTO struct {
	Path string `json:"path"`
}

type commitOperation struct {
	kind string
	path model.FilePath
	ref  model.FileRef
}

func (s *Service) commit(w http.ResponseWriter, r *http.Request, rt route, principal auth.Principal, bases baseURLs) {
	if s.writer == nil || s.publisher == nil {
		s.fail(w, r, bucket.ErrUnsupported)
		return
	}
	if r.URL.RawQuery != "" {
		s.fail(w, r, bucket.ErrUnsupported)
		return
	}
	refName, targetIsRef := rt.revision.Ref()
	if !targetIsRef {
		s.fail(w, r, errInput)
		return
	}
	parent, err := s.commitParent(r.Context(), rt)
	if err != nil {
		s.failRevision(w, r, rt.repo, err)
		return
	}
	header, operations, bodyDigest, err := s.readCommit(r, w, rt.repo)
	if err != nil {
		s.failCommitInput(w, r, err)
		return
	}
	if len(operations) == 0 {
		s.fail(w, r, errCommitInput)
		return
	}

	// A retry after an applied publication sees the prepared OID as the current
	// snapshot. Recompute it from that snapshot's parent before enforcing the
	// stale parent guard.
	if parent != nil {
		replayOID := commitOID(rt.repo, refName, principal.Subject, bodyDigest, parent.Parent)
		if parent.OID == replayOID {
			s.commitResponse(w, r, rt.repo, replayOID, bases)
			return
		}
	}
	if err := validateParentCommit(header.ParentCommit, parent); err != nil {
		s.fail(w, r, err)
		return
	}
	var parentOID *model.OID
	if parent != nil {
		value := parent.OID
		parentOID = &value
	}
	oid := commitOID(rt.repo, refName, principal.Subject, bodyDigest, parentOID)
	files, err := applyCommitOperations(parent, operations)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	message := header.Summary
	if header.Description != "" {
		message += "\n\n" + header.Description
	}
	snapshot, err := model.CanonicalSnapshot(model.Snapshot{
		Repo: rt.repo, OID: oid, Parent: parentOID, CreatedAt: time.Now().UTC(),
		Author: model.Identity{Name: principal.Subject}, Message: message, Files: files,
	})
	if err != nil {
		s.fail(w, r, fmt.Errorf("%w: %v", errCommitInput, err))
		return
	}
	if s.snapshots != nil {
		retained, retainedErr := s.snapshots.GetSnapshot(r.Context(), rt.repo, oid)
		switch {
		case retainedErr == nil:
			retained, err = model.CanonicalSnapshot(retained)
			if err != nil {
				s.fail(w, r, bucket.ErrInvariant)
				return
			}
			snapshot.CreatedAt = retained.CreatedAt
			snapshot, err = model.CanonicalSnapshot(snapshot)
			if err != nil {
				s.fail(w, r, fmt.Errorf("%w: %v", errCommitInput, err))
				return
			}
			preparedFingerprint, fingerprintErr := model.FingerprintSnapshot(snapshot)
			retainedFingerprint, retainedFingerprintErr := model.FingerprintSnapshot(retained)
			if fingerprintErr != nil || retainedFingerprintErr != nil || preparedFingerprint != retainedFingerprint {
				s.fail(w, r, bucket.ErrConflict)
				return
			}
			snapshot = retained
		case !errors.Is(retainedErr, bucket.ErrNotFound):
			s.fail(w, r, retainedErr)
			return
		}
	}
	expectation := catalog.ExpectRef(refName, parentOID)
	lock := &s.commits[oid[0]]
	lock.Lock()
	defer lock.Unlock()
	current, currentErr := s.bucket.ResolveRevision(r.Context(), rt.repo, rt.revision)
	if currentErr == nil && current.OID == oid {
		s.commitResponse(w, r, rt.repo, oid, bases)
		return
	}
	if currentErr != nil && !errors.Is(currentErr, bucket.ErrNotFound) {
		s.fail(w, r, currentErr)
		return
	}
	if parent == nil && currentErr == nil || parent != nil && (currentErr != nil || current.OID != parent.OID) {
		s.fail(w, r, bucket.ErrConflict)
		return
	}
	if err = s.publisher.PublishSnapshot(r.Context(), snapshot, expectation); err != nil {
		s.fail(w, r, err)
		return
	}
	s.commitResponse(w, r, rt.repo, oid, bases)
}

func (s *Service) commitParent(ctx context.Context, rt route) (*model.Snapshot, error) {
	snapshot, err := s.bucket.ResolveRevision(ctx, rt.repo, rt.revision)
	if err == nil {
		return &snapshot, nil
	}
	if !errors.Is(err, bucket.ErrNotFound) {
		return nil, err
	}
	if _, repositoryErr := s.bucket.GetRepository(ctx, rt.repo); repositoryErr != nil {
		return nil, repositoryErr
	}
	return nil, nil
}

func (s *Service) readCommit(
	r *http.Request,
	w http.ResponseWriter,
	repo model.RepoKey,
) (commitHeaderDTO, []commitOperation, [32]byte, error) {
	body := http.MaxBytesReader(w, r.Body, s.metadata)
	reader := bufio.NewReaderSize(body, min(s.lineBytes+1, 64<<10))
	digest := sha256.New()
	var header commitHeaderDTO
	operations := make([]commitOperation, 0)
	seen := make(map[model.FilePath]string)
	for lineNumber := 0; ; lineNumber++ {
		line, err := readNDJSONLine(reader, s.lineBytes)
		if errors.Is(err, io.EOF) {
			if lineNumber == 0 {
				return header, nil, [32]byte{}, errCommitInput
			}
			break
		}
		if err != nil {
			return header, nil, [32]byte{}, err
		}
		_, _ = digest.Write(line)
		_, _ = digest.Write([]byte{'\n'})
		var envelope commitEnvelopeDTO
		if err = decodeStrict(line, &envelope); err != nil || len(envelope.Value) == 0 {
			return header, nil, [32]byte{}, errCommitInput
		}
		if lineNumber == 0 {
			if envelope.Key != "header" || decodeStrict(envelope.Value, &header) != nil || header.Summary == "" {
				return header, nil, [32]byte{}, errCommitInput
			}
			continue
		}
		if envelope.Key == "header" {
			return header, nil, [32]byte{}, errCommitInput
		}
		if len(operations) == s.commitOps {
			return header, nil, [32]byte{}, errCommitTooLarge
		}
		operation, err := s.decodeCommitOperation(r, repo, envelope)
		if err != nil {
			return header, nil, [32]byte{}, err
		}
		if previous, duplicate := seen[operation.path]; duplicate {
			return header, nil, [32]byte{}, fmt.Errorf("%w: path %q has both %s and %s operations", errCommitInput, operation.path, previous, operation.kind)
		}
		seen[operation.path] = operation.kind
		operations = append(operations, operation)
	}
	for _, left := range operations {
		if left.kind != "deletedFolder" {
			continue
		}
		prefix := string(left.path) + "/"
		for _, right := range operations {
			if left.path != right.path && strings.HasPrefix(string(right.path), prefix) {
				return header, nil, [32]byte{}, fmt.Errorf("%w: folder deletion overlaps %q", errCommitInput, right.path)
			}
		}
	}
	var sum [32]byte
	copy(sum[:], digest.Sum(nil))
	return header, operations, sum, nil
}

func readNDJSONLine(reader *bufio.Reader, maximum int) ([]byte, error) {
	line := make([]byte, 0, min(maximum, 64<<10))
	for {
		part, err := reader.ReadSlice('\n')
		if len(line)+len(part) > maximum+1 {
			return nil, errCommitTooLarge
		}
		line = append(line, part...)
		switch {
		case err == nil:
			line = line[:len(line)-1]
			if len(line) == 0 || line[len(line)-1] == '\r' {
				return nil, errCommitInput
			}
			return line, nil
		case errors.Is(err, bufio.ErrBufferFull):
			continue
		case errors.Is(err, io.EOF) && len(line) == 0:
			return nil, io.EOF
		case errors.Is(err, io.EOF):
			return nil, errCommitInput
		default:
			var tooLarge *http.MaxBytesError
			if errors.As(err, &tooLarge) {
				return nil, errCommitTooLarge
			}
			return nil, err
		}
	}
}

func (s *Service) decodeCommitOperation(r *http.Request, repo model.RepoKey, envelope commitEnvelopeDTO) (commitOperation, error) {
	operation := commitOperation{kind: envelope.Key}
	switch envelope.Key {
	case "file":
		var value commitFileDTO
		if decodeStrict(envelope.Value, &value) != nil || value.Encoding != "base64" {
			return operation, errCommitInput
		}
		path, err := s.commitPath(value.Path)
		if err != nil {
			return operation, err
		}
		maximumEncoded := base64.StdEncoding.EncodedLen(int(min(s.fileBytes, int64(s.lineBytes))))
		if len(value.Content) > maximumEncoded {
			return operation, errCommitTooLarge
		}
		body, err := base64.StdEncoding.DecodeString(value.Content)
		if err != nil {
			return operation, errCommitInput
		}
		if int64(len(body)) > s.fileBytes {
			return operation, errCommitTooLarge
		}
		sum := sha256.Sum256(body)
		if _, err = s.writer.PutBlob(r.Context(), content.Blob{SHA256: sum, Size: int64(len(body))}, bytes.NewReader(body)); err != nil {
			return operation, err
		}
		operation.path = path
		operation.ref, err = model.NewBlobFileRef(sum, int64(len(body)))
		return operation, err
	case "lfsFile":
		var value commitLFSFileDTO
		if decodeStrict(envelope.Value, &value) != nil || value.Algo != "sha256" || value.Size == nil || *value.Size < 0 {
			return operation, errCommitInput
		}
		if *value.Size > s.fileBytes {
			return operation, errCommitTooLarge
		}
		path, err := s.commitPath(value.Path)
		if err != nil {
			return operation, err
		}
		var sum [32]byte
		decoded, err := hex.DecodeString(value.OID)
		if err != nil || len(decoded) != len(sum) || value.OID != strings.ToLower(value.OID) {
			return operation, errCommitInput
		}
		copy(sum[:], decoded)
		hash, err := s.writer.ResolveXetFile(r.Context(), repo, sum, uint64(*value.Size))
		if err != nil {
			return operation, err
		}
		operation.path = path
		operation.ref, err = model.NewXetFileRef(hash, *value.Size, &sum)
		return operation, err
	case "deletedFile", "deletedFolder":
		var value commitDeleteDTO
		if decodeStrict(envelope.Value, &value) != nil {
			return operation, errCommitInput
		}
		pathValue := value.Path
		if envelope.Key == "deletedFolder" {
			pathValue = strings.TrimSuffix(pathValue, "/")
		}
		path, err := s.commitPath(pathValue)
		operation.path = path
		return operation, err
	default:
		return operation, errCommitInput
	}
}

func (s *Service) commitPath(value string) (model.FilePath, error) {
	if len(value) == 0 || len(value) > s.pathBytes {
		return "", errCommitInput
	}
	path, err := model.ParseFilePath(value)
	if err != nil {
		return "", fmt.Errorf("%w: %v", errCommitInput, err)
	}
	return path, nil
}

func decodeStrict(data []byte, destination any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	return requireJSONEOF(decoder)
}

func validateParentCommit(value string, parent *model.Snapshot) error {
	if value == "" {
		return nil
	}
	oid, err := model.ParseOID(value)
	if err != nil {
		return errCommitInput
	}
	if parent == nil || parent.OID != oid {
		return bucket.ErrConflict
	}
	return nil
}

func commitOID(repo model.RepoKey, ref model.RefName, author string, body [32]byte, parent *model.OID) model.OID {
	digest := sha256.New()
	writeCommitPart(digest, "xet-go-hf-commit-v1")
	writeCommitPart(digest, string(repo.Type))
	writeCommitPart(digest, string(repo.Namespace))
	writeCommitPart(digest, string(repo.Name))
	writeCommitPart(digest, string(ref))
	writeCommitPart(digest, author)
	_, _ = digest.Write(body[:])
	if parent == nil {
		_, _ = digest.Write([]byte{0})
	} else {
		_, _ = digest.Write([]byte{1})
		_, _ = digest.Write(parent[:])
	}
	encoded := digest.Sum(nil)
	var oid model.OID
	copy(oid[:], encoded)
	if oid.IsZero() {
		oid[len(oid)-1] = 1
	}
	return oid
}

func writeCommitPart(destination hash.Hash, value string) {
	_, _ = fmt.Fprintf(destination, "%d:", len(value))
	_, _ = io.WriteString(destination, value)
}

func applyCommitOperations(parent *model.Snapshot, operations []commitOperation) ([]model.FileEntry, error) {
	files := make(map[model.FilePath]model.FileRef)
	if parent != nil {
		for _, entry := range parent.Files {
			files[entry.Path] = entry.Ref
		}
	}
	for _, operation := range operations {
		switch operation.kind {
		case "file", "lfsFile":
			files[operation.path] = operation.ref
		case "deletedFile":
			if _, exists := files[operation.path]; !exists {
				return nil, fmt.Errorf("%w: deleted file %q does not exist", errCommitInput, operation.path)
			}
			delete(files, operation.path)
		case "deletedFolder":
			prefix := string(operation.path) + "/"
			deleted := false
			for path := range files {
				if strings.HasPrefix(string(path), prefix) {
					delete(files, path)
					deleted = true
				}
			}
			if !deleted {
				return nil, fmt.Errorf("%w: deleted folder %q does not exist", errCommitInput, operation.path)
			}
		}
	}
	result := make([]model.FileEntry, 0, len(files))
	for path, ref := range files {
		result = append(result, model.FileEntry{Path: path, Ref: ref})
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Path < result[j].Path })
	return result, nil
}

func (s *Service) commitResponse(w http.ResponseWriter, r *http.Request, repo model.RepoKey, oid model.OID, bases baseURLs) {
	commitURL := bases.hub + "/" + url.PathEscape(string(repo.Namespace)) + "/" + url.PathEscape(string(repo.Name)) + "/commit/" + oid.String()
	s.json(w, r, struct {
		CommitURL string `json:"commitUrl"`
		CommitOID string `json:"commitOid"`
	}{CommitURL: commitURL, CommitOID: oid.String()})
}

func (s *Service) failCommitInput(w http.ResponseWriter, r *http.Request, err error) {
	if errors.Is(err, errCommitTooLarge) {
		s.failStatus(w, r, http.StatusRequestEntityTooLarge)
		return
	}
	s.fail(w, r, err)
}
