package bucket

import (
	"context"
	"errors"
	"fmt"

	"github.com/jmwoliver/xet-go/catalog"
	"github.com/jmwoliver/xet-go/content"
	"github.com/jmwoliver/xet-go/model"
	casserver "github.com/jmwoliver/xet-go/xetcas/server"
	"github.com/jmwoliver/xet-go/xethash"
)

// ReachabilityAuditRequest selects one bounded page from the complete tree
// rooted at a live ref. Ref is required on the first request and must be empty
// when Continuation is set. Continuations are returned by this service and
// must be passed back unmodified.
type ReachabilityAuditRequest struct {
	Repo         model.RepoKey
	Ref          model.RefName
	Continuation *ReachabilityAuditContinuation
	Limit        int
}

// ReachabilityAuditContinuation is an opaque, process-local value that pins
// subsequent pages to the immutable root observed by the first request. It is
// not an authorization capability or durable checkpoint. Untrusted adapters
// must keep it server-side or issue their own integrity-protected token.
type ReachabilityAuditContinuation struct {
	root      ReachabilityRoot
	cursor    string
	afterPath model.FilePath
}

type ReachabilityAuditStatus string

const (
	ReachabilityAuditNoIssueFound ReachabilityAuditStatus = "no-issue-found"
	ReachabilityAuditIssue        ReachabilityAuditStatus = "issue"
	ReachabilityAuditFailed       ReachabilityAuditStatus = "failed"
)

type ReachabilityAuditFinding string

const (
	ReachabilityFindingNone                      ReachabilityAuditFinding = ""
	ReachabilityFindingRecordInvalid             ReachabilityAuditFinding = "record-invalid"
	ReachabilityFindingOrdinaryBlobMissing       ReachabilityAuditFinding = "ordinary-blob-missing"
	ReachabilityFindingOrdinaryBlobInvalid       ReachabilityAuditFinding = "ordinary-blob-invalid"
	ReachabilityFindingOrdinarySizeMismatch      ReachabilityAuditFinding = "ordinary-blob-size-mismatch"
	ReachabilityFindingXetRequirementUnavailable ReachabilityAuditFinding = "xet-requirement-unavailable"
	ReachabilityFindingXetDependencyInvalid      ReachabilityAuditFinding = "xet-dependency-invalid"
	ReachabilityFindingCheckFailed               ReachabilityAuditFinding = "check-failed"
)

// ReachabilityTarget is the catalog root identity retained by one file. Blob
// is populated for ordinary content; Namespace and XetFile are populated for
// Xet content. It does not enumerate the Xet shard/Xorb dependency closure.
type ReachabilityTarget struct {
	Kind      model.FileKind
	Blob      content.Blob
	Namespace string
	XetFile   xethash.Hash
}

type ReachabilityAuditResult struct {
	Entry   model.FileEntry
	Target  *ReachabilityTarget
	Status  ReachabilityAuditStatus
	Finding ReachabilityAuditFinding
	// Err is nil for no-issue and missing-target findings. Invalid retained
	// state and failed backend checks preserve a typed bucket error.
	Err error
}

// ReachabilityRoot identifies the immutable snapshot observed through Ref by
// the first request. Ref may have advanced by the time later pages are read.
type ReachabilityRoot struct {
	Repo        model.RepoKey
	Ref         model.RefName
	SnapshotOID model.OID
}

// ReachabilityAuditPage is rooted at one immutable snapshot. If the audit
// returns a non-nil error, Items may contain completed diagnostic checks and
// Next is nil. Retry always identifies the exact pinned page request once Root
// was resolved; partial Items must be discarded or deduplicated before retry.
type ReachabilityAuditPage struct {
	Root  ReachabilityRoot
	Items []ReachabilityAuditResult
	Retry *ReachabilityAuditContinuation
	Next  *ReachabilityAuditContinuation
}

// AuditRefReachability verifies metadata-level availability of one bounded
// page of files rooted from a live ref. It checks ordinary object existence and
// size and the complete Xet file→shard→Xorb metadata/physical dependency graph.
// It does not read or hash payload bytes, retain a transactional catalog view,
// prove that unlisted objects are unreachable, or make deletion safe.
func (service *Service) AuditRefReachability(
	ctx context.Context,
	request ReachabilityAuditRequest,
) (ReachabilityAuditPage, error) {
	if err := validateReachabilityRequest(ctx, request); err != nil {
		return ReachabilityAuditPage{}, err
	}
	root, query, err := service.reachabilityQuery(ctx, request)
	if err != nil {
		return ReachabilityAuditPage{}, err
	}
	retry := ReachabilityAuditContinuation{root: root}
	if request.Continuation != nil {
		retry.cursor = request.Continuation.cursor
		retry.afterPath = request.Continuation.afterPath
	}
	page := ReachabilityAuditPage{
		Root: root, Items: make([]ReachabilityAuditResult, 0), Retry: &retry,
	}
	revision, _ := model.RevisionFromOID(root.SnapshotOID) // Root validation rejects the only invalid value (zero).
	files, err := service.catalog.ListFiles(ctx, request.Repo, revision, query)
	if err != nil {
		return page, mapCatalogError(err)
	}
	var after model.FilePath
	if request.Continuation != nil {
		after = request.Continuation.afterPath
	}
	if err = validateReachabilityFilePage(query, root.SnapshotOID, after, files); err != nil {
		return page, err
	}
	namespace, err := RepositoryNamespace(request.Repo)
	if err != nil {
		return page, err
	}
	page.Items = make([]ReachabilityAuditResult, 0, len(files.Items))
	for _, entry := range files.Items {
		if err = ctx.Err(); err != nil {
			return page, err
		}
		result := service.auditReachableFile(ctx, namespace, entry)
		if errors.Is(result.Err, context.Canceled) || errors.Is(result.Err, context.DeadlineExceeded) {
			return page, result.Err
		}
		page.Items = append(page.Items, result)
	}
	if err = ctx.Err(); err != nil {
		return page, err
	}
	if files.NextCursor != "" {
		lastPath := files.Items[len(files.Items)-1].Path
		if _, pathErr := model.ParseFilePath(string(lastPath)); pathErr != nil {
			return page, fmt.Errorf("%w: catalog continuation follows an invalid file path", ErrCorrupt)
		}
		page.Next = &ReachabilityAuditContinuation{
			root: root, cursor: files.NextCursor, afterPath: lastPath,
		}
	}
	return page, nil
}

func validateReachabilityRequest(ctx context.Context, request ReachabilityAuditRequest) error {
	if err := validContext(ctx); err != nil {
		return err
	}
	if err := model.ValidateRepoKey(request.Repo); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	if request.Continuation == nil {
		if _, err := model.ParseRefName(string(request.Ref)); err != nil {
			return fmt.Errorf("%w: %v", ErrInvalid, err)
		}
	} else {
		continuation := request.Continuation
		if request.Ref != "" || continuation.root.Repo != request.Repo || continuation.root.SnapshotOID.IsZero() {
			return fmt.Errorf("%w: malformed reachability continuation", ErrInvalid)
		}
		if _, err := model.ParseRefName(string(continuation.root.Ref)); err != nil {
			return fmt.Errorf("%w: malformed reachability continuation: %v", ErrInvalid, err)
		}
		if continuation.cursor == "" {
			if continuation.afterPath != "" {
				return fmt.Errorf("%w: malformed reachability continuation", ErrInvalid)
			}
		} else if _, err := model.ParseFilePath(string(continuation.afterPath)); err != nil {
			return fmt.Errorf("%w: malformed reachability continuation: %v", ErrInvalid, err)
		}
	}
	limit := request.Limit
	if limit < 0 || limit > catalog.MaxPageSize {
		return fmt.Errorf("%w: reachability page limit is outside [0,%d]", ErrInvalid, catalog.MaxPageSize)
	}
	return nil
}

func (service *Service) reachabilityQuery(
	ctx context.Context,
	request ReachabilityAuditRequest,
) (ReachabilityRoot, catalog.FileQuery, error) {
	if request.Continuation != nil {
		return request.Continuation.root, catalog.FileQuery{
			Cursor: request.Continuation.cursor, Limit: request.Limit,
		}, nil
	}
	root, err := service.catalog.GetRef(ctx, request.Repo, request.Ref)
	if err != nil {
		return ReachabilityRoot{}, catalog.FileQuery{}, mapCatalogError(err)
	}
	if err = model.ValidateRef(root); err != nil || root.Repo != request.Repo || root.Name != request.Ref {
		return ReachabilityRoot{}, catalog.FileQuery{}, fmt.Errorf("%w: catalog returned an invalid reachability root", ErrCorrupt)
	}
	return ReachabilityRoot{Repo: root.Repo, Ref: root.Name, SnapshotOID: root.OID},
		catalog.FileQuery{Limit: request.Limit}, nil
}

func validateReachabilityFilePage(
	query catalog.FileQuery,
	oid model.OID,
	after model.FilePath,
	page catalog.FilePage,
) error {
	limit := query.Limit
	if limit == 0 {
		limit = catalog.DefaultPageSize
	}
	if page.SnapshotOID != oid {
		return fmt.Errorf("%w: catalog file page changed reachability snapshot", ErrCorrupt)
	}
	if len(page.Items) > limit || page.NextCursor != "" && len(page.Items) == 0 ||
		query.Cursor != "" && page.NextCursor == query.Cursor {
		return fmt.Errorf("%w: catalog returned an invalid reachability page", ErrCorrupt)
	}
	previous := after
	for _, entry := range page.Items {
		if previous != "" && entry.Path <= previous {
			return fmt.Errorf("%w: catalog reachability paths are not strictly increasing", ErrCorrupt)
		}
		previous = entry.Path
	}
	return nil
}

func (service *Service) auditReachableFile(
	ctx context.Context,
	namespace string,
	entry model.FileEntry,
) ReachabilityAuditResult {
	result := ReachabilityAuditResult{Entry: entry}
	target, targetErr := reachabilityTarget(namespace, entry.Ref)
	result.Target = target
	if _, err := model.ParseFilePath(string(entry.Path)); err != nil {
		result.Status, result.Finding = ReachabilityAuditIssue, ReachabilityFindingRecordInvalid
		result.Err = fmt.Errorf("%w: catalog returned an invalid file entry", ErrCorrupt)
		return result
	}
	if targetErr != nil {
		result.Status, result.Finding = ReachabilityAuditIssue, ReachabilityFindingRecordInvalid
		result.Err = targetErr
		return result
	}
	if target.Kind == model.FileKindBlob {
		sum, _ := entry.Ref.SHA256()
		info, found, err := service.content.Head(ctx, sum)
		if err != nil {
			switch {
			case errors.Is(err, content.ErrNotFound):
				result.Status, result.Finding = ReachabilityAuditIssue, ReachabilityFindingOrdinaryBlobMissing
			case errors.Is(err, content.ErrConflict), errors.Is(err, content.ErrCorrupt):
				result.Status, result.Finding, result.Err = ReachabilityAuditIssue,
					ReachabilityFindingOrdinaryBlobInvalid, mapReachabilityContentError(err)
			default:
				result.Status, result.Finding, result.Err = ReachabilityAuditFailed,
					ReachabilityFindingCheckFailed, mapReachabilityContentError(err)
			}
			return result
		}
		if !found {
			result.Status, result.Finding = ReachabilityAuditIssue, ReachabilityFindingOrdinaryBlobMissing
			return result
		}
		if info.Size != entry.Ref.FileSize() {
			result.Status, result.Finding = ReachabilityAuditIssue, ReachabilityFindingOrdinarySizeMismatch
			result.Err = fmt.Errorf("%w: ordinary blob size %d differs from catalog size %d", ErrCorrupt, info.Size, entry.Ref.FileSize())
			return result
		}
	} else {
		hash, _ := entry.Ref.XetHash()
		sum, hasSum := entry.Ref.SHA256()
		var wantedSum *[32]byte
		if hasSum {
			wantedSum = &sum
		}
		err := service.cas.VerifyFileInNamespace(ctx, namespace, hash, uint64(entry.Ref.FileSize()), wantedSum)
		switch {
		case err == nil:
		case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
			result.Status, result.Finding, result.Err = ReachabilityAuditFailed, ReachabilityFindingCheckFailed, err
			return result
		case errors.Is(err, casserver.ErrNotFound):
			result.Status, result.Finding = ReachabilityAuditIssue, ReachabilityFindingXetRequirementUnavailable
			return result
		case errors.Is(err, casserver.ErrCorrupt), errors.Is(err, casserver.ErrConflict):
			result.Status, result.Finding, result.Err = ReachabilityAuditIssue,
				ReachabilityFindingXetDependencyInvalid, mapReachabilityCASError(err)
			return result
		default:
			result.Status, result.Finding, result.Err = ReachabilityAuditFailed,
				ReachabilityFindingCheckFailed, mapReachabilityCASError(err)
			return result
		}
	}
	result.Status = ReachabilityAuditNoIssueFound
	return result
}

func reachabilityTarget(namespace string, ref model.FileRef) (*ReachabilityTarget, error) {
	switch ref.Kind() {
	case model.FileKindBlob:
		sum, _ := ref.SHA256() // FileRef's opaque constructor guarantees this discriminant.
		return &ReachabilityTarget{
			Kind: model.FileKindBlob, Blob: content.Blob{SHA256: sum, Size: ref.FileSize()},
		}, nil
	case model.FileKindXet:
		hash, _ := ref.XetHash() // FileRef's opaque constructor guarantees this discriminant.
		return &ReachabilityTarget{Kind: model.FileKindXet, Namespace: namespace, XetFile: hash}, nil
	default:
		return nil, fmt.Errorf("%w: catalog returned unknown file kind %q", ErrCorrupt, ref.Kind())
	}
}

func mapReachabilityContentError(err error) error {
	if errors.Is(err, content.ErrInvalid) {
		return fmt.Errorf("%w: content Head violated its trusted contract: %w", ErrInvariant, err)
	}
	return mapContentReadError(err)
}

func mapReachabilityCASError(err error) error {
	if errors.Is(err, casserver.ErrInvalid) || errors.Is(err, casserver.ErrUnauthorized) ||
		errors.Is(err, casserver.ErrForbidden) {
		return fmt.Errorf("%w: trusted CAS verification violated its contract: %w", ErrInvariant, err)
	}
	return mapCASReadError(err)
}
