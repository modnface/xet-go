package server

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"math"
	"sync"
	"time"

	"github.com/jmwoliver/xet-go/shard"
	"github.com/jmwoliver/xet-go/xetcas"
	"github.com/jmwoliver/xet-go/xethash"
	"github.com/jmwoliver/xet-go/xorb"
)

func (s *Service) authorizedFile(
	ctx context.Context,
	credential string,
	hash xethash.Hash,
) (Grant, FileRecord, error) {
	grant, err := s.authorize(ctx, credential, AccessRequest{Operation: OperationReadFile, Hash: hash})
	if err != nil {
		return Grant{}, FileRecord{}, err
	}
	file, err := s.scopedFile(ctx, grant.Namespace, hash)
	return grant, file, err
}

func (s *Service) scopedFile(ctx context.Context, namespace string, hash xethash.Hash) (FileRecord, error) {
	value, found, err := s.index.GetFile(ctx, namespace, hash)
	if err != nil {
		return FileRecord{}, err
	}
	if !found {
		return FileRecord{}, ErrNotFound
	}
	return value, nil
}

func (s *Service) file(ctx context.Context, credential string, hash xethash.Hash) (FileRecord, error) {
	_, file, err := s.authorizedFile(ctx, credential, hash)
	return file, err
}

func (s *Service) File(ctx context.Context, credential string, hash xethash.Hash) (FileRecord, error) {
	return s.file(ctx, credential, hash)
}

func (s *Service) validateRecipeWork(ctx context.Context, file shard.RegisteredFile) error {
	if uint64(len(file.File.Terms)) > s.registration.MaxTerms {
		return fmt.Errorf("%w: reconstruction has %d terms, limit %d",
			ErrTooLarge, len(file.File.Terms), s.registration.MaxTerms)
	}
	var references uint64
	for i, term := range file.File.Terms {
		if i&1023 == 0 {
			if err := ctx.Err(); err != nil {
				return err
			}
		}
		if term.End < term.Start {
			return errors.New("xet CAS server: stored reconstruction has a reversed chunk range")
		}
		count := uint64(term.End - term.Start)
		if math.MaxUint64-references < count || references+count > s.registration.MaxChunkReferences {
			return fmt.Errorf("%w: reconstruction exceeds %d chunk references",
				ErrTooLarge, s.registration.MaxChunkReferences)
		}
		references += count
	}
	return nil
}

func (s *Service) layoutLookup(ctx context.Context) xetcas.XorbLayoutLookup {
	return func(hash xethash.Hash) (*xorb.Ingested, bool, error) {
		value, found, err := s.index.GetXorb(ctx, hash)
		if err != nil || !found {
			return nil, found, err
		}
		layout := value.Layout
		layout.Chunks = append([]xorb.IngestedChunk(nil), value.Layout.Chunks...)
		return &layout, true, nil
	}
}

func (s *Service) reconstructionPlan(
	ctx context.Context,
	namespace string,
	hash xethash.Hash,
	requested *xetcas.FileRange,
) (FileRecord, *xetcas.ReconstructionPlan, error) {
	file, err := s.scopedFile(ctx, namespace, hash)
	if err != nil {
		return FileRecord{}, nil, err
	}
	if err := s.validateRecipeWork(ctx, file.File); err != nil {
		return FileRecord{}, nil, err
	}
	plan, err := xetcas.PlanReconstructionContext(ctx, file.File, requested, s.layoutLookup(ctx))
	if err != nil {
		return FileRecord{}, nil, err
	}
	return file, plan, nil
}

func (s *Service) ReconstructionV2(
	ctx context.Context,
	credential string,
	hash xethash.Hash,
	requested *xetcas.FileRange,
) (result *xetcas.Reconstruction, returnError error) {
	grant, err := s.authorize(ctx, credential, AccessRequest{Operation: OperationReadFile, Hash: hash})
	if err != nil {
		return nil, err
	}
	leaseContext, cancelLease := context.WithCancelCause(ctx)
	defer cancelLease(nil)
	lease, err := s.acquireActiveFileLease(leaseContext, cancelLease, grant.Namespace, hash)
	if err != nil {
		return nil, err
	}
	detached := false
	defer func() {
		if !detached {
			returnError = errors.Join(returnError, lease.Close())
		}
	}()
	_, plan, err := s.reconstructionPlan(leaseContext, grant.Namespace, hash, requested)
	if err != nil {
		return nil, err
	}
	response := &xetcas.Reconstruction{
		OffsetIntoFirstRange: plan.OffsetIntoFirstRange,
		Terms:                append([]xetcas.ReconstructionTerm(nil), plan.Terms...),
		Xorbs:                make(map[xethash.Hash][]xetcas.MultiRangeFetch, len(plan.Xorbs)),
	}
	var maximumExpiry time.Time
	for xorbHash, ranges := range plan.Xorbs {
		for _, value := range ranges {
			signed, err := s.signRange(leaseContext, BlobKey{Kind: BlobXorb, Hash: xorbHash}, value.Bytes)
			if err != nil {
				return nil, fmt.Errorf("xet CAS server: sign xorb %s range: %w", xorbHash, err)
			}
			if signed.ExpiresAt.After(maximumExpiry) {
				maximumExpiry = signed.ExpiresAt
			}
			// One range per URL works with direct S3 GetObject, which does not
			// implement HTTP multi-range requests.
			response.Xorbs[xorbHash] = append(response.Xorbs[xorbHash], xetcas.MultiRangeFetch{
				URL: signed.URL, Ranges: []xetcas.XorbRangeDescriptor{value},
			})
		}
	}
	if err := response.Validate(); err != nil {
		return nil, err
	}
	if err := lease.Detach(maximumExpiry); err != nil {
		return nil, err
	}
	detached = true
	return response, nil
}

func (s *Service) ReconstructionV1(
	ctx context.Context,
	credential string,
	hash xethash.Hash,
	requested *xetcas.FileRange,
) (result *xetcas.ReconstructionV1, returnError error) {
	grant, err := s.authorize(ctx, credential, AccessRequest{Operation: OperationReadFile, Hash: hash})
	if err != nil {
		return nil, err
	}
	leaseContext, cancelLease := context.WithCancelCause(ctx)
	defer cancelLease(nil)
	lease, err := s.acquireActiveFileLease(leaseContext, cancelLease, grant.Namespace, hash)
	if err != nil {
		return nil, err
	}
	detached := false
	defer func() {
		if !detached {
			returnError = errors.Join(returnError, lease.Close())
		}
	}()
	_, plan, err := s.reconstructionPlan(leaseContext, grant.Namespace, hash, requested)
	if err != nil {
		return nil, err
	}
	response := &xetcas.ReconstructionV1{
		OffsetIntoFirstRange: plan.OffsetIntoFirstRange,
		Terms:                append([]xetcas.ReconstructionTerm(nil), plan.Terms...),
		FetchInfo:            make(map[xethash.Hash][]xetcas.V1FetchInfo, len(plan.Xorbs)),
	}
	var maximumExpiry time.Time
	for xorbHash, ranges := range plan.Xorbs {
		for _, value := range ranges {
			signed, err := s.signRange(leaseContext, BlobKey{Kind: BlobXorb, Hash: xorbHash}, value.Bytes)
			if err != nil {
				return nil, fmt.Errorf("xet CAS server: sign xorb %s range: %w", xorbHash, err)
			}
			if signed.ExpiresAt.After(maximumExpiry) {
				maximumExpiry = signed.ExpiresAt
			}
			response.FetchInfo[xorbHash] = append(response.FetchInfo[xorbHash], xetcas.V1FetchInfo{
				Range: value.Chunks, URL: signed.URL, URLRange: value.Bytes,
			})
		}
	}
	if err := lease.Detach(maximumExpiry); err != nil {
		return nil, err
	}
	detached = true
	return response, nil
}

func (s *Service) signRange(ctx context.Context, key BlobKey, value xetcas.HTTPRange) (SignedRange, error) {
	signed, err := s.signer.SignRange(ctx, key, value)
	if err != nil {
		return SignedRange{}, err
	}
	expiresAt, err := normalizeProtectionTime(signed.ExpiresAt)
	if err != nil || signed.URL == "" || !expiresAt.After(s.now()) {
		return SignedRange{}, fmt.Errorf("%w: signer returned an empty URL or invalid expiration", ErrInvalid)
	}
	signed.ExpiresAt = expiresAt
	return signed, nil
}

type activeFileLease struct {
	store        ProtectionStore
	namespace    string
	id           ProtectionID
	expiresAt    time.Time
	ttl          time.Duration
	now          func() time.Time
	cancelRenew  context.CancelFunc
	done         <-chan struct{}
	renewalError error
	closeOnce    sync.Once
	closeError   error
}

func (s *Service) acquireActiveFileLease(
	ctx context.Context,
	failStream func(error),
	namespace string,
	hash xethash.Hash,
) (*activeFileLease, error) {
	if s.protections == nil {
		return nil, nil
	}
	id, err := newProtectionID()
	if err != nil {
		return nil, err
	}
	createdAt := s.now()
	if err := s.protections.PutFileLease(ctx, FileLease{
		ID: id, Namespace: namespace, File: hash,
		CreatedAt: createdAt, ExpiresAt: createdAt.Add(s.readLeaseTTL),
	}); err != nil {
		return nil, fmt.Errorf("xet CAS server: acquire file read lease: %w", err)
	}
	renewContext, cancelRenew := context.WithCancel(ctx)
	done := make(chan struct{})
	lease := &activeFileLease{
		store: s.protections, namespace: namespace, id: id, expiresAt: createdAt.Add(s.readLeaseTTL),
		ttl: s.readLeaseTTL, now: s.now,
		cancelRenew: cancelRenew, done: done,
	}
	go func() {
		defer close(done)
		ticker := time.NewTicker(lease.ttl / 3)
		defer ticker.Stop()
		for {
			select {
			case <-renewContext.Done():
				return
			case <-ticker.C:
				expiresAt := lease.now().Add(lease.ttl)
				if !expiresAt.After(lease.expiresAt) {
					expiresAt = lease.expiresAt.Add(lease.ttl / 3)
				}
				if err := lease.store.RenewFileLease(
					renewContext, lease.namespace, lease.id, expiresAt,
				); err != nil {
					if renewContext.Err() != nil {
						return
					}
					lease.renewalError = fmt.Errorf("xet CAS server: renew file read lease: %w", err)
					failStream(lease.renewalError)
					return
				}
				lease.expiresAt = expiresAt
			}
		}
	}()
	return lease, nil
}

func (l *activeFileLease) stopRenewal() error {
	if l == nil {
		return nil
	}
	l.cancelRenew()
	<-l.done
	return l.renewalError
}

func (l *activeFileLease) Detach(signedExpiry time.Time) error {
	if l == nil {
		return nil
	}
	expiresAt := l.now().Add(l.ttl)
	if !signedExpiry.IsZero() {
		signedWithGrace := signedExpiry.Add(l.ttl)
		if signedWithGrace.After(expiresAt) {
			expiresAt = signedWithGrace
		}
	}
	expiresAt, err := normalizeProtectionTime(expiresAt)
	if err != nil {
		return errors.Join(err, l.Close())
	}
	finalizeContext, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	finalizeError := l.store.RenewFileLease(finalizeContext, l.namespace, l.id, expiresAt)
	renewalError := l.stopRenewal()
	if finalizeError != nil || renewalError != nil {
		if finalizeError != nil {
			finalizeError = fmt.Errorf("xet CAS server: finalize signed reconstruction lease: %w", finalizeError)
		}
		return errors.Join(finalizeError, renewalError, l.Close())
	}
	return nil
}

func (l *activeFileLease) Close() error {
	if l == nil {
		return nil
	}
	l.closeOnce.Do(func() {
		renewalError := l.stopRenewal()
		releaseContext, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		var releaseError error
		if err := l.store.DeleteFileLease(releaseContext, l.namespace, l.id); err != nil {
			releaseError = fmt.Errorf("xet CAS server: release file read lease: %w", err)
		}
		l.closeError = errors.Join(renewalError, releaseError)
	})
	return l.closeError
}

type reconstructionGroup struct {
	blob   BlobKey
	bytes  xetcas.HTTPRange
	chunks []xorb.IngestedChunk
}

func (s *Service) reconstructionGroups(
	ctx context.Context,
	plan *xetcas.ReconstructionPlan,
) ([]reconstructionGroup, error) {
	groups := make([]reconstructionGroup, 0, len(plan.Terms))
	for i, term := range plan.Terms {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		record, found, err := s.index.GetXorb(ctx, term.Hash)
		if err != nil {
			return nil, fmt.Errorf("xet CAS server: resolve reconstruction xorb %s: %w", term.Hash, err)
		}
		if !found {
			return nil, fmt.Errorf("%w: reconstruction xorb %s is not indexed", ErrCorrupt, term.Hash)
		}
		if err := term.Range.Validate(); err != nil || term.Range.End > uint32(len(record.Layout.Chunks)) {
			return nil, fmt.Errorf("%w: reconstruction term %d has an invalid xorb chunk range", ErrCorrupt, i)
		}
		chunks := append([]xorb.IngestedChunk(nil), record.Layout.Chunks[term.Range.Start:term.Range.End]...)
		var unpacked uint64
		for _, chunk := range chunks {
			unpacked += uint64(chunk.UncompressedLength)
		}
		if unpacked != uint64(term.UnpackedLength) {
			return nil, fmt.Errorf("%w: reconstruction term %d is %d bytes, expected %d",
				ErrCorrupt, i, unpacked, term.UnpackedLength)
		}
		first, last := chunks[0], chunks[len(chunks)-1]
		end := uint64(last.SerializedOffset) + uint64(last.SerializedLength)
		if end == 0 || end > uint64(record.Layout.NetworkBytes) {
			return nil, fmt.Errorf("%w: reconstruction term %d exceeds xorb %s", ErrCorrupt, i, term.Hash)
		}
		bytes := xetcas.HTTPRange{Start: uint64(first.SerializedOffset), End: end - 1}
		if len(groups) != 0 {
			previous := &groups[len(groups)-1]
			if previous.blob == record.Blob && previous.bytes.End != math.MaxUint64 && previous.bytes.End+1 == bytes.Start {
				previous.bytes.End = bytes.End
				previous.chunks = append(previous.chunks, chunks...)
				continue
			}
		}
		groups = append(groups, reconstructionGroup{blob: record.Blob, bytes: bytes, chunks: chunks})
	}
	return groups, nil
}

// OpenFile opens a verified, backpressured full-file or logical-range stream
// without exposing reconstruction descriptors or signed object-store URLs to
// the caller. Physical xorb content remains globally deduplicated, while the
// file recipe used to reach it is resolved in the Authorizer grant namespace.
func (s *Service) OpenFile(
	ctx context.Context,
	credential string,
	hash xethash.Hash,
	requested *xetcas.FileRange,
) (*OpenedFile, error) {
	if ctx == nil {
		return nil, errors.New("xet CAS server: nil open-file context")
	}
	grant, err := s.authorize(ctx, credential, AccessRequest{Operation: OperationReadFile, Hash: hash})
	if err != nil {
		return nil, err
	}
	return s.openFileInNamespace(ctx, grant.Namespace, hash, requested)
}

// OpenFileInNamespace is the trusted embedding form of OpenFile. It skips CAS
// credential authorization because the calling service has already authorized
// repository access and resolved that repository to a logical CAS namespace.
// HTTP handlers and untrusted callers must use OpenFile instead.
func (s *Service) OpenFileInNamespace(
	ctx context.Context,
	namespace string,
	hash xethash.Hash,
	requested *xetcas.FileRange,
) (*OpenedFile, error) {
	if ctx == nil {
		return nil, errors.New("xet CAS server: nil open-file context")
	}
	if namespace == "" {
		return nil, fmt.Errorf("%w: trusted open requires a namespace", ErrInvalid)
	}
	return s.openFileInNamespace(ctx, namespace, hash, requested)
}

func (s *Service) openFileInNamespace(
	ctx context.Context,
	namespace string,
	hash xethash.Hash,
	requested *xetcas.FileRange,
) (*OpenedFile, error) {
	streamContext, cancel := context.WithCancelCause(ctx)
	lease, err := s.acquireActiveFileLease(streamContext, cancel, namespace, hash)
	if err != nil {
		cancel(err)
		return nil, err
	}
	file, plan, err := s.reconstructionPlan(streamContext, namespace, hash, requested)
	if err != nil {
		cancel(err)
		return nil, errors.Join(err, lease.Close())
	}
	selected := xetcas.FileRange{Start: 0, End: file.File.Size}
	if requested != nil {
		selected.Start = requested.Start
		selected.End = min(requested.End, file.File.Size)
	}
	wholeFile := selected.Start == 0 && selected.End == file.File.Size
	groups, err := s.reconstructionGroups(streamContext, plan)
	if err != nil {
		cancel(err)
		return nil, errors.Join(err, lease.Close())
	}
	reader, writer := io.Pipe()
	settlement := &openFileSettlement{done: make(chan struct{})}
	go func() {
		streamError := s.streamReconstruction(streamContext, writer, groups, plan.OffsetIntoFirstRange,
			selected.Len(), wholeFile, file.File.File.SHA256)
		leaseError := lease.Close()
		settlement.finish(streamError, leaseError)
		_ = writer.CloseWithError(errors.Join(streamError, leaseError))
	}()
	go func() {
		select {
		case <-streamContext.Done():
			_ = reader.CloseWithError(context.Cause(streamContext))
		case <-settlement.done:
		}
	}()
	result := &OpenedFile{
		Hash: hash, FileSize: file.File.Size, Range: selected, Size: selected.Len(),
		Body: &cancelReadCloser{
			PipeReader: reader, ctx: streamContext, cancel: cancel, settlement: settlement,
		},
	}
	if file.File.File.SHA256 != nil {
		sum := *file.File.File.SHA256
		result.SHA256 = &sum
	}
	return result, nil
}

type openFileSettlement struct {
	done      chan struct{}
	mu        sync.Mutex
	streamErr error
	leaseErr  error
}

func (s *openFileSettlement) finish(streamErr, leaseErr error) {
	s.mu.Lock()
	s.streamErr = streamErr
	s.leaseErr = leaseErr
	s.mu.Unlock()
	close(s.done)
}

func (s *openFileSettlement) errors() (error, error) {
	<-s.done
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.streamErr, s.leaseErr
}

type cancelReadCloser struct {
	*io.PipeReader
	ctx        context.Context
	cancel     context.CancelCauseFunc
	settlement *openFileSettlement
	once       sync.Once
	err        error
}

func (r *cancelReadCloser) Read(data []byte) (int, error) {
	n, err := r.PipeReader.Read(data)
	if err != nil && r.ctx.Err() != nil {
		return n, context.Cause(r.ctx)
	}
	return n, err
}

func (r *cancelReadCloser) Close() error {
	r.once.Do(func() {
		r.cancel(nil)
		pipeError := r.PipeReader.Close()
		streamError, leaseError := r.settlement.errors()
		if streamError == io.ErrClosedPipe || streamError == context.Canceled {
			streamError = nil
		}
		r.err = errors.Join(pipeError, streamError, leaseError)
	})
	return r.err
}

type onceReadCloser struct {
	io.ReadCloser
	once sync.Once
	err  error
}

func (r *onceReadCloser) Close() error {
	r.once.Do(func() { r.err = r.ReadCloser.Close() })
	return r.err
}

func closeReaderOnCancellation(ctx context.Context, reader io.ReadCloser) (*onceReadCloser, chan struct{}) {
	value := &onceReadCloser{ReadCloser: reader}
	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = value.Close()
		case <-done:
		}
	}()
	return value, done
}

func (s *Service) streamReconstruction(
	ctx context.Context,
	destination *io.PipeWriter,
	groups []reconstructionGroup,
	skip, wanted uint64,
	wholeFile bool,
	expectedSHA *[32]byte,
) error {
	remaining := wanted
	var hasher = sha256.New()
	for _, group := range groups {
		if err := ctx.Err(); err != nil {
			return err
		}
		reader, err := s.blobs.Get(ctx, group.blob, &group.bytes)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if errors.Is(err, ErrNotFound) {
				return fmt.Errorf("%w: xorb %s range %s is missing: %w", ErrCorrupt, group.blob.Hash, group.bytes, err)
			}
			return fmt.Errorf("xet CAS server: read xorb %s range %s: %w", group.blob.Hash, group.bytes, err)
		}
		reader, readerDone := closeReaderOnCancellation(ctx, reader)
		groupErr := func() error {
			for i, expected := range group.chunks {
				if err := ctx.Err(); err != nil {
					return err
				}
				chunk, err := xorb.ReadChunk(reader)
				if err != nil {
					if ctx.Err() != nil {
						return ctx.Err()
					}
					var formatErr *xorb.FormatError
					if errors.As(err, &formatErr) || errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
						return fmt.Errorf("%w: decode xorb %s chunk %d: %w", ErrCorrupt, group.blob.Hash, i, err)
					}
					return fmt.Errorf("xet CAS server: read xorb %s chunk %d: %w", group.blob.Hash, i, err)
				}
				if chunk.Hash != expected.Hash || chunk.SerializedLength != expected.SerializedLength ||
					chunk.UncompressedLength != expected.UncompressedLength {
					return fmt.Errorf("%w: xorb %s chunk %d differs from its durable layout", ErrCorrupt, group.blob.Hash, i)
				}
				if wholeFile && expectedSHA != nil {
					_, _ = hasher.Write(chunk.Data)
				}
				data := chunk.Data
				if skip >= uint64(len(data)) {
					skip -= uint64(len(data))
					continue
				}
				if skip != 0 {
					data = data[skip:]
					skip = 0
				}
				if uint64(len(data)) > remaining {
					data = data[:remaining]
				}
				if len(data) != 0 {
					if _, err := destination.Write(data); err != nil {
						return err
					}
					remaining -= uint64(len(data))
				}
			}
			extra, err := io.CopyN(io.Discard, reader, 1)
			if extra != 0 {
				return fmt.Errorf("%w: xorb %s range returned extra bytes", ErrCorrupt, group.blob.Hash)
			}
			if err != nil && !errors.Is(err, io.EOF) {
				return fmt.Errorf("xet CAS server: finish xorb %s range: %w", group.blob.Hash, err)
			}
			return nil
		}()
		close(readerDone)
		closeErr := reader.Close()
		if closeErr != nil {
			closeErr = fmt.Errorf("xet CAS server: close xorb %s range: %w", group.blob.Hash, closeErr)
		}
		if err := errors.Join(groupErr, closeErr); err != nil {
			return err
		}
	}
	if skip != 0 || remaining != 0 {
		return fmt.Errorf("%w: reconstruction ended with %d skipped and %d missing bytes", ErrCorrupt, skip, remaining)
	}
	if wholeFile && expectedSHA != nil {
		var actual [sha256.Size]byte
		copy(actual[:], hasher.Sum(nil))
		if actual != *expectedSHA {
			return fmt.Errorf("%w: reconstructed SHA-256 mismatch", ErrCorrupt)
		}
	}
	return nil
}

func (s *Service) BatchReconstructionV1(
	ctx context.Context,
	credential string,
	hashes []xethash.Hash,
) (*xetcas.BatchReconstructionV1, error) {
	response := &xetcas.BatchReconstructionV1{
		Files:     make(map[xethash.Hash][]xetcas.ReconstructionTerm),
		FetchInfo: make(map[xethash.Hash][]xetcas.V1FetchInfo),
	}
	seen := make(map[xethash.Hash]struct{}, len(hashes))
	var responseTerms uint64
	for _, hash := range hashes {
		if _, duplicate := seen[hash]; duplicate {
			continue
		}
		seen[hash] = struct{}{}
		value, err := s.ReconstructionV1(ctx, credential, hash, nil)
		if errors.Is(err, ErrNotFound) {
			continue
		}
		if err != nil {
			return nil, err
		}
		if uint64(len(value.Terms)) > s.registration.MaxTerms-responseTerms {
			return nil, fmt.Errorf("%w: batch reconstruction exceeds %d terms",
				ErrTooLarge, s.registration.MaxTerms)
		}
		responseTerms += uint64(len(value.Terms))
		response.Files[hash] = value.Terms
		for xorbHash, fetches := range value.FetchInfo {
			response.FetchInfo[xorbHash] = append(response.FetchInfo[xorbHash], fetches...)
		}
	}
	return response, nil
}

func (s *Service) FileChunkHashes(
	ctx context.Context,
	credential string,
	hash xethash.Hash,
	dirty []xetcas.FileRange,
) (result *xetcas.FileChunkHashesResponse, returnError error) {
	grant, err := s.authorize(ctx, credential, AccessRequest{Operation: OperationReadFile, Hash: hash})
	if err != nil {
		return nil, err
	}
	leaseContext, cancelLease := context.WithCancelCause(ctx)
	defer cancelLease(nil)
	lease, err := s.acquireActiveFileLease(leaseContext, cancelLease, grant.Namespace, hash)
	if err != nil {
		return nil, err
	}
	defer func() { returnError = errors.Join(returnError, lease.Close()) }()
	file, err := s.scopedFile(leaseContext, grant.Namespace, hash)
	if err != nil {
		return nil, err
	}
	if err := s.validateRecipeWork(leaseContext, file.File); err != nil {
		return nil, err
	}
	return xetcas.PlanFileChunkHashesContext(leaseContext, file.File, dirty, s.layoutLookup(leaseContext))
}

func (s *Service) GlobalDedup(
	ctx context.Context,
	credential, prefix string,
	hash xethash.Hash,
) ([]byte, error) {
	// The OpenAPI contract specifies default-merkledb, while released official
	// xet-core clients send the shared data default "default" to both xorb and
	// dedup routes. Accept that legacy wire value without changing the Go
	// client's spec-conforming default.
	if prefix != xetcas.DefaultDedupPrefix && prefix != xetcas.DefaultXorbPrefix {
		return nil, ErrNotFound
	}
	grant, err := s.authorize(ctx, credential, AccessRequest{
		Operation: OperationReadDedup, Prefix: prefix, Hash: hash,
	})
	if err != nil {
		return nil, err
	}
	record, found, err := s.index.GetDedup(ctx, grant.Namespace, hash)
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, ErrNotFound
	}
	reader, err := s.blobs.Get(ctx, record.Shard, nil)
	if err != nil {
		return nil, err
	}
	body, err := io.ReadAll(io.LimitReader(reader, shard.MaxSize+1))
	if err != nil {
		_ = reader.Close()
		return nil, err
	}
	if err := reader.Close(); err != nil {
		return nil, fmt.Errorf("xet CAS server: close dedup shard: %w", err)
	}
	if len(body) > shard.MaxSize {
		return nil, ErrTooLarge
	}
	full, err := shard.Decode(body)
	if err != nil {
		return nil, err
	}
	if full.Footer == nil {
		return nil, errors.New("xet CAS server: dedup index points to a footerless shard")
	}
	source := dedupSource(*full)
	now := s.now().Unix()
	if now < 0 {
		return nil, errors.New("xet CAS server: dedup clock precedes Unix epoch")
	}
	created := uint64(now)
	ttl := uint64(s.dedupTTL / time.Second)
	expires := created + ttl
	return shard.EncodeProtectedDedup(source, s.dedupKey, created, expires)
}

func dedupSource(value shard.Shard) shard.Shard {
	present := make(map[xethash.Hash]struct{}, len(value.Xorbs))
	for _, xorbInfo := range value.Xorbs {
		present[xorbInfo.Hash] = struct{}{}
	}
	files := make([]shard.File, 0, len(value.Files))
	for _, file := range value.Files {
		if len(file.Terms) == 0 {
			continue
		}
		if _, ok := present[file.Terms[0].XorbHash]; ok {
			files = append(files, file)
		}
	}
	return shard.Shard{Files: files, Xorbs: value.Xorbs}
}
