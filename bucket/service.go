// Package bucket composes repository metadata, ordinary content, and Xet CAS
// reconstruction into a hosting-neutral model-bucket service API.
package bucket

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"

	"github.com/jmwoliver/xet-go/auth"
	"github.com/jmwoliver/xet-go/catalog"
	"github.com/jmwoliver/xet-go/content"
	"github.com/jmwoliver/xet-go/model"
	"github.com/jmwoliver/xet-go/xetcas"
	casserver "github.com/jmwoliver/xet-go/xetcas/server"
	"github.com/jmwoliver/xet-go/xethash"
)

var (
	ErrInvalid             = errors.New("bucket: invalid input")
	ErrUnauthenticated     = errors.New("bucket: unauthenticated")
	ErrPermissionDenied    = errors.New("bucket: permission denied")
	ErrNotFound            = errors.New("bucket: not found")
	ErrConflict            = errors.New("bucket: conflict")
	ErrContentNotUploaded  = errors.New("bucket: content not uploaded")
	ErrRangeNotSatisfiable = errors.New("bucket: range not satisfiable")
	ErrCorrupt             = errors.New("bucket: corrupt content or metadata")
	ErrUnsupported         = errors.New("bucket: unsupported capability")
	ErrUnavailable         = errors.New("bucket: backend unavailable")
	ErrInvariant           = errors.New("bucket: internal invariant violation")
)

// CASFileOpener is the narrow trusted CAS capability used by Service. The
// namespace has already been derived from an authorized repository; it is not
// a caller-provided credential.
type CASFileOpener interface {
	OpenFileInNamespace(context.Context, string, xethash.Hash, *xetcas.FileRange) (*casserver.OpenedFile, error)
}

// CASFileCloner is the narrow trusted same-CAS clone capability used by
// Service. Service derives both namespaces from application repository keys.
type CASFileCloner interface {
	CloneFileBetweenNamespaces(context.Context, string, string, xethash.Hash, uint64, *[32]byte) error
}

// CASFileService opens and verifies exact files in trusted repository scopes
// without exposing raw namespaces to bucket callers. CloneXetFile additionally
// requires CASFileCloner.
type CASFileService interface {
	CASFileOpener
	VerifyFileInNamespace(context.Context, string, xethash.Hash, uint64, *[32]byte) error
}

type Options struct {
	Catalog catalog.Catalog
	Content content.Store
	CAS     CASFileService
}

type Service struct {
	catalog catalog.Catalog
	content content.Store
	cas     CASFileService
}

func New(options Options) (*Service, error) {
	if options.Catalog == nil || options.Content == nil || options.CAS == nil {
		return nil, fmt.Errorf("%w: catalog, content, and CAS are required", ErrInvalid)
	}
	return &Service{catalog: options.Catalog, content: options.Content, cas: options.CAS}, nil
}

// RepositoryNamespace is the canonical, versioned logical CAS namespace for
// one repository. CAS token issuance and trusted bucket reads must use this
// same mapping. The encoding is traversal-free and injective for valid keys.
func RepositoryNamespace(repo model.RepoKey) (string, error) {
	namespace, err := auth.RepositoryNamespace(repo)
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrInvalid, err)
	}
	return namespace, nil
}

func (service *Service) CreateRepository(ctx context.Context, repository model.Repository) error {
	if err := validContext(ctx); err != nil {
		return err
	}
	return mapCatalogError(service.catalog.CreateRepository(ctx, repository))
}

func (service *Service) GetRepository(ctx context.Context, repo model.RepoKey) (model.Repository, error) {
	if err := validContext(ctx); err != nil {
		return model.Repository{}, err
	}
	result, err := service.catalog.GetRepository(ctx, repo)
	return result, mapCatalogError(err)
}

func (service *Service) ListRepositories(ctx context.Context, query catalog.RepositoryQuery) (catalog.RepositoryPage, error) {
	if err := validContext(ctx); err != nil {
		return catalog.RepositoryPage{}, err
	}
	result, err := service.catalog.ListRepositories(ctx, query)
	return result, mapCatalogError(err)
}

func (service *Service) ResolveRevision(
	ctx context.Context,
	repo model.RepoKey,
	revision model.Revision,
) (model.Snapshot, error) {
	if err := validContext(ctx); err != nil {
		return model.Snapshot{}, err
	}
	result, err := service.catalog.ResolveRevision(ctx, repo, revision)
	return result, mapCatalogError(err)
}

func (service *Service) GetSnapshot(ctx context.Context, repo model.RepoKey, oid model.OID) (model.Snapshot, error) {
	if err := validContext(ctx); err != nil {
		return model.Snapshot{}, err
	}
	result, err := service.catalog.GetSnapshot(ctx, repo, oid)
	return result, mapCatalogError(err)
}

func (service *Service) ListSnapshots(
	ctx context.Context,
	repo model.RepoKey,
	query catalog.SnapshotQuery,
) (catalog.SnapshotPage, error) {
	if err := validContext(ctx); err != nil {
		return catalog.SnapshotPage{}, err
	}
	result, err := service.catalog.ListSnapshots(ctx, repo, query)
	return result, mapCatalogError(err)
}

func (service *Service) GetRef(ctx context.Context, repo model.RepoKey, name model.RefName) (model.Ref, error) {
	if err := validContext(ctx); err != nil {
		return model.Ref{}, err
	}
	result, err := service.catalog.GetRef(ctx, repo, name)
	return result, mapCatalogError(err)
}

func (service *Service) ListRefs(
	ctx context.Context,
	repo model.RepoKey,
	query catalog.RefQuery,
) (catalog.RefPage, error) {
	if err := validContext(ctx); err != nil {
		return catalog.RefPage{}, err
	}
	lister, ok := service.catalog.(catalog.RefLister)
	if !ok {
		return catalog.RefPage{}, ErrUnsupported
	}
	result, err := lister.ListRefs(ctx, repo, query)
	return result, mapCatalogError(err)
}

func (service *Service) CompareAndSwapRef(
	ctx context.Context,
	repo model.RepoKey,
	name model.RefName,
	expected *model.OID,
	newOID model.OID,
) error {
	if err := validContext(ctx); err != nil {
		return err
	}
	return mapCatalogError(service.catalog.CompareAndSwapRef(ctx, repo, name, expected, newOID))
}

// PutBlob verifies and immutably publishes one ordinary content object.
func (service *Service) PutBlob(ctx context.Context, blob content.Blob, body io.Reader) (bool, error) {
	if err := validContext(ctx); err != nil {
		return false, err
	}
	if body == nil {
		return false, fmt.Errorf("%w: ordinary content body is nil", ErrInvalid)
	}
	inserted, err := service.content.Put(ctx, blob, body)
	return inserted, mapContentPublicationError(err)
}

// CloneXetFile makes one exact, durably registered source Xet file available
// in another repository namespace of the same CAS without reading, chunking,
// or uploading logical file or Xorb payload bytes. The caller must separately
// authorize source repository reads and destination repository writes.
func (service *Service) CloneXetFile(
	ctx context.Context,
	sourceRepo model.RepoKey,
	destinationRepo model.RepoKey,
	hash xethash.Hash,
	expectedSize uint64,
	expectedSHA256 *[32]byte,
) error {
	if err := validContext(ctx); err != nil {
		return err
	}
	sourceNamespace, err := RepositoryNamespace(sourceRepo)
	if err != nil {
		return err
	}
	destinationNamespace, err := RepositoryNamespace(destinationRepo)
	if err != nil {
		return err
	}
	cloner, ok := service.cas.(CASFileCloner)
	if !ok {
		return ErrUnsupported
	}
	return mapCASCloneError(cloner.CloneFileBetweenNamespaces(
		ctx, sourceNamespace, destinationNamespace, hash, expectedSize, expectedSHA256,
	))
}

// PublishSnapshot validates a complete immutable tree, preflights every
// referenced ordinary and Xet key/index dependency and reported size, then
// atomically publishes snapshot metadata and advances its expected catalog
// ref. The preflight is not an object-store transaction and does not rehash
// payload bytes.
func (service *Service) PublishSnapshot(
	ctx context.Context,
	snapshot model.Snapshot,
	expectation catalog.RefExpectation,
) error {
	if err := validContext(ctx); err != nil {
		return err
	}
	canonical, err := model.CanonicalSnapshot(snapshot)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	namespace, err := RepositoryNamespace(canonical.Repo)
	if err != nil {
		return err
	}
	verifiedBlobs := make(map[content.Blob]struct{})
	type xetRequirement struct {
		hash   xethash.Hash
		size   uint64
		sum    [32]byte
		hasSum bool
	}
	verifiedXet := make(map[xetRequirement]struct{})
	for _, entry := range canonical.Files {
		if err := ctx.Err(); err != nil {
			return err
		}
		switch entry.Ref.Kind() {
		case model.FileKindBlob:
			sum, _ := entry.Ref.SHA256()
			blob := content.Blob{SHA256: sum, Size: entry.Ref.FileSize()}
			if _, alreadyVerified := verifiedBlobs[blob]; alreadyVerified {
				continue
			}
			info, found, err := service.content.Head(ctx, sum)
			if err != nil {
				return mapContentPublicationError(err)
			}
			if !found || info.Size != blob.Size {
				return fmt.Errorf("%w: ordinary file %q is not available with its declared identity and size", ErrContentNotUploaded, entry.Path)
			}
			verifiedBlobs[blob] = struct{}{}
		case model.FileKindXet:
			hash, _ := entry.Ref.XetHash()
			sum, hasSum := entry.Ref.SHA256()
			requirement := xetRequirement{hash: hash, size: uint64(entry.Ref.FileSize()), sum: sum, hasSum: hasSum}
			if _, alreadyVerified := verifiedXet[requirement]; alreadyVerified {
				continue
			}
			var wantedSum *[32]byte
			if hasSum {
				wantedSum = &sum
			}
			if err = service.cas.VerifyFileInNamespace(ctx, namespace, hash, requirement.size, wantedSum); err != nil {
				return mapCASPublicationError(entry.Path, err)
			}
			verifiedXet[requirement] = struct{}{}
		}
	}
	return mapCatalogError(service.catalog.PublishSnapshot(ctx, canonical, expectation))
}

func (service *Service) ListFiles(
	ctx context.Context,
	repo model.RepoKey,
	revision model.Revision,
	query catalog.FileQuery,
) (catalog.FilePage, error) {
	if err := validContext(ctx); err != nil {
		return catalog.FilePage{}, err
	}
	result, err := service.catalog.ListFiles(ctx, repo, revision, query)
	return result, mapCatalogError(err)
}

type OpenOptions struct {
	// Range is a half-open logical file range. Nil opens the complete file.
	Range *content.Range
}

// FileReader is a representation-independent logical file stream. FileSize is
// the complete size; Range and Size describe Body. ContentType is empty until
// trusted metadata supplies one. ETag is a stable logical identity without HTTP
// quoting. The caller must close Body.
type FileReader struct {
	Entry          model.FileEntry
	FileSize       int64
	Range          content.Range
	Size           int64
	ContentType    string
	ETag           string
	RangeSupported bool
	SHA256         *[32]byte
	Body           io.ReadCloser
}

func (service *Service) OpenFile(
	ctx context.Context,
	repo model.RepoKey,
	revision model.Revision,
	path model.FilePath,
	options OpenOptions,
) (*FileReader, error) {
	if err := validContext(ctx); err != nil {
		return nil, err
	}
	if err := model.ValidateRepoKey(repo); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	if revision.String() == "" {
		return nil, fmt.Errorf("%w: revision is empty", ErrInvalid)
	}
	if _, err := model.ParseFilePath(string(path)); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	entry, err := service.catalog.GetFile(ctx, repo, revision, path)
	if err != nil {
		return nil, mapCatalogError(err)
	}
	selected, err := selectedRange(entry.Ref.FileSize(), options.Range)
	if err != nil {
		return nil, err
	}
	result := &FileReader{
		Entry: entry, FileSize: entry.Ref.FileSize(), Range: selected, Size: selected.Len(),
		ETag: entityTag(entry.Ref), RangeSupported: true,
	}
	if sum, present := entry.Ref.SHA256(); present {
		result.SHA256 = &sum
	}
	switch entry.Ref.Kind() {
	case model.FileKindBlob:
		return service.openBlob(ctx, result, options.Range)
	case model.FileKindXet:
		return service.openXet(ctx, repo, result, options.Range)
	default:
		return nil, fmt.Errorf("%w: catalog returned unknown file kind %q", ErrInvariant, entry.Ref.Kind())
	}
}

func (service *Service) openBlob(
	ctx context.Context,
	result *FileReader,
	wanted *content.Range,
) (*FileReader, error) {
	sum, present := result.Entry.Ref.SHA256()
	if !present {
		return nil, fmt.Errorf("%w: ordinary file has no SHA-256", ErrInvariant)
	}
	body, err := service.content.Open(ctx, content.Blob{SHA256: sum, Size: result.FileSize}, wanted)
	if err != nil {
		return nil, mapContentReadError(err)
	}
	if body == nil {
		return nil, fmt.Errorf("%w: content store returned a nil reader", ErrInvariant)
	}
	result.Body = &mappedReadCloser{ReadCloser: body, mapError: mapContentReadError}
	return result, nil
}

func (service *Service) openXet(
	ctx context.Context,
	repo model.RepoKey,
	result *FileReader,
	wanted *content.Range,
) (*FileReader, error) {
	hash, present := result.Entry.Ref.XetHash()
	if !present {
		return nil, fmt.Errorf("%w: Xet file has no Xet identity", ErrInvariant)
	}
	namespace, err := RepositoryNamespace(repo)
	if err != nil {
		return nil, err
	}
	var requested *xetcas.FileRange
	if wanted != nil {
		requested = &xetcas.FileRange{Start: uint64(wanted.Start), End: uint64(wanted.End)}
	}
	opened, err := service.cas.OpenFileInNamespace(ctx, namespace, hash, requested)
	if err != nil {
		return nil, mapCASReadError(err)
	}
	if err := validateCASResult(result, hash, opened); err != nil {
		if opened != nil && opened.Body != nil {
			err = errors.Join(err, mapCASReadError(opened.Body.Close()))
		}
		return nil, err
	}
	if result.SHA256 == nil && opened.SHA256 != nil {
		sum := *opened.SHA256
		result.SHA256 = &sum
	}
	result.Body = &mappedReadCloser{ReadCloser: opened.Body, mapError: mapCASReadError}
	return result, nil
}

func selectedRange(size int64, wanted *content.Range) (content.Range, error) {
	selected := content.Range{Start: 0, End: size}
	if wanted == nil {
		return selected, nil
	}
	if err := wanted.Validate(size); err != nil {
		return content.Range{}, fmt.Errorf("%w: %w", ErrRangeNotSatisfiable, err)
	}
	return *wanted, nil
}

func validateCASResult(expected *FileReader, hash xethash.Hash, opened *casserver.OpenedFile) error {
	if opened == nil || opened.Body == nil {
		return fmt.Errorf("%w: CAS returned an incomplete stream", ErrInvariant)
	}
	if opened.Hash != hash || opened.FileSize != uint64(expected.FileSize) || opened.Size != uint64(expected.Size) ||
		opened.Range.Start != uint64(expected.Range.Start) || opened.Range.End != uint64(expected.Range.End) {
		return fmt.Errorf("%w: catalog and CAS file metadata disagree", ErrCorrupt)
	}
	if expected.SHA256 != nil && opened.SHA256 != nil && *opened.SHA256 != *expected.SHA256 {
		return fmt.Errorf("%w: catalog and CAS SHA-256 metadata disagree", ErrCorrupt)
	}
	return nil
}

func entityTag(ref model.FileRef) string {
	if sum, present := ref.SHA256(); present {
		return "sha256:" + hex.EncodeToString(sum[:])
	}
	hash, _ := ref.XetHash()
	return "xet:" + hash.String()
}

type mappedReadCloser struct {
	io.ReadCloser
	mapError func(error) error
}

func (reader *mappedReadCloser) Read(buffer []byte) (int, error) {
	n, err := reader.ReadCloser.Read(buffer)
	return n, reader.mapError(err)
}

func (reader *mappedReadCloser) Close() error { return reader.mapError(reader.ReadCloser.Close()) }

func validContext(ctx context.Context) error {
	if ctx == nil {
		return fmt.Errorf("%w: nil context", ErrInvalid)
	}
	return ctx.Err()
}

func mapCatalogError(err error) error {
	switch {
	case err == nil, errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return err
	case errors.Is(err, catalog.ErrInvalid):
		return fmt.Errorf("%w: %w", ErrInvalid, err)
	case errors.Is(err, catalog.ErrNotFound):
		return fmt.Errorf("%w: %w", ErrNotFound, err)
	case errors.Is(err, catalog.ErrAlreadyExists), errors.Is(err, catalog.ErrConflict):
		return fmt.Errorf("%w: %w", ErrConflict, err)
	case errors.Is(err, catalog.ErrCorrupt):
		return fmt.Errorf("%w: %w", ErrCorrupt, err)
	case errors.Is(err, catalog.ErrUnavailable):
		return fmt.Errorf("%w: %w", ErrUnavailable, err)
	default:
		return fmt.Errorf("%w: catalog: %w", ErrUnavailable, err)
	}
}

func mapContentReadError(err error) error {
	switch {
	case err == nil, errors.Is(err, io.EOF), errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return err
	case errors.Is(err, content.ErrInvalid):
		return fmt.Errorf("%w: %w", ErrInvalid, err)
	case errors.Is(err, content.ErrNotFound):
		return fmt.Errorf("%w: published snapshot references missing ordinary content: %w", ErrCorrupt, err)
	case errors.Is(err, content.ErrConflict), errors.Is(err, content.ErrCorrupt):
		return fmt.Errorf("%w: %w", ErrCorrupt, err)
	case errors.Is(err, content.ErrRangeNotSatisfiable):
		return fmt.Errorf("%w: %w", ErrRangeNotSatisfiable, err)
	case errors.Is(err, content.ErrDurabilityUnsupported):
		return fmt.Errorf("%w: %w", ErrUnsupported, err)
	case errors.Is(err, content.ErrUnavailable):
		return fmt.Errorf("%w: %w", ErrUnavailable, err)
	default:
		return fmt.Errorf("%w: content: %w", ErrUnavailable, err)
	}
}

func mapContentPublicationError(err error) error {
	switch {
	case err == nil, errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return err
	case errors.Is(err, content.ErrInvalid):
		return fmt.Errorf("%w: %w", ErrInvalid, err)
	case errors.Is(err, content.ErrConflict), errors.Is(err, content.ErrCorrupt):
		return fmt.Errorf("%w: %w", ErrCorrupt, err)
	case errors.Is(err, content.ErrDurabilityUnsupported):
		return fmt.Errorf("%w: %w", ErrUnsupported, err)
	case errors.Is(err, content.ErrUnavailable):
		return fmt.Errorf("%w: %w", ErrUnavailable, err)
	default:
		return fmt.Errorf("%w: content: %w", ErrUnavailable, err)
	}
}

func mapCASPublicationError(path model.FilePath, err error) error {
	switch {
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return err
	case errors.Is(err, casserver.ErrNotFound):
		return fmt.Errorf("%w: Xet file %q is not durably available", ErrContentNotUploaded, path)
	case errors.Is(err, casserver.ErrConflict), errors.Is(err, casserver.ErrCorrupt):
		return fmt.Errorf("%w: Xet file %q: %w", ErrCorrupt, path, err)
	case errors.Is(err, casserver.ErrInvalid):
		return fmt.Errorf("%w: Xet file %q: %w", ErrInvalid, path, err)
	case errors.Is(err, casserver.ErrTooLarge), errors.Is(err, casserver.ErrDurabilityUnsupported):
		return fmt.Errorf("%w: Xet file %q: %w", ErrUnsupported, path, err)
	default:
		return fmt.Errorf("%w: Xet file %q: %w", ErrUnavailable, path, err)
	}
}

func mapCASCloneError(err error) error {
	switch {
	case err == nil, errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return err
	case errors.Is(err, casserver.ErrNotFound):
		return fmt.Errorf("%w: source Xet file is not durably available: %w", ErrContentNotUploaded, err)
	case errors.Is(err, casserver.ErrConflict):
		return fmt.Errorf("%w: destination Xet metadata conflicts: %w", ErrConflict, err)
	case errors.Is(err, casserver.ErrCorrupt):
		return fmt.Errorf("%w: source or destination Xet metadata: %w", ErrCorrupt, err)
	case errors.Is(err, casserver.ErrInvalid):
		return fmt.Errorf("%w: %w", ErrInvalid, err)
	case errors.Is(err, casserver.ErrTooLarge), errors.Is(err, casserver.ErrDurabilityUnsupported):
		return fmt.Errorf("%w: %w", ErrUnsupported, err)
	default:
		return fmt.Errorf("%w: CAS clone: %w", ErrUnavailable, err)
	}
}

func mapCASReadError(err error) error {
	switch {
	case err == nil, errors.Is(err, io.EOF), errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return err
	case errors.Is(err, casserver.ErrUnauthorized):
		return fmt.Errorf("%w: %w", ErrUnauthenticated, err)
	case errors.Is(err, casserver.ErrForbidden):
		return fmt.Errorf("%w: %w", ErrPermissionDenied, err)
	case errors.Is(err, xetcas.ErrRangeNotSatisfiable):
		return fmt.Errorf("%w: %w", ErrRangeNotSatisfiable, err)
	case errors.Is(err, casserver.ErrNotFound):
		return fmt.Errorf("%w: published snapshot references missing Xet content: %w", ErrCorrupt, err)
	case errors.Is(err, casserver.ErrConflict), errors.Is(err, casserver.ErrCorrupt):
		return fmt.Errorf("%w: %w", ErrCorrupt, err)
	case errors.Is(err, casserver.ErrInvalid):
		return fmt.Errorf("%w: %w", ErrInvalid, err)
	case errors.Is(err, casserver.ErrTooLarge), errors.Is(err, casserver.ErrDurabilityUnsupported):
		return fmt.Errorf("%w: %w", ErrUnsupported, err)
	default:
		return fmt.Errorf("%w: CAS: %w", ErrUnavailable, err)
	}
}
