package server

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/jmwoliver/xet-go/shard"
	"github.com/jmwoliver/xet-go/xetcas"
	"github.com/jmwoliver/xet-go/xethash"
	"github.com/jmwoliver/xet-go/xorb"
)

const (
	defaultDedupTTL                 = time.Hour
	defaultShardHeartbeat           = 5 * time.Second
	defaultMaxRegistrationFiles     = 100_000
	defaultMaxRegistrationXorbs     = 65_536
	defaultMaxRegistrationTerms     = 250_000
	defaultMaxRegistrationChunkRefs = 4_000_000
	defaultMaxConcurrentIngests     = 2
)

type Service struct {
	blobs          BlobStore
	index          IndexStore
	signer         RangeURLSigner
	authorizer     Authorizer
	now            func() time.Time
	dedupKey       xethash.Hash
	dedupTTL       time.Duration
	maxXorb        int64
	maxShard       int64
	registration   shard.RegistrationLimits
	ingestSlots    chan struct{}
	shardHeartbeat time.Duration
}

func New(options Options) (*Service, error) {
	if options.Blobs == nil || options.Index == nil || options.Signer == nil || options.Authorizer == nil {
		return nil, errors.New("xet CAS server: blobs, index, signer, and authorizer are required")
	}
	now := options.Now
	if now == nil {
		now = time.Now
	}
	dedupTTL := options.DedupTTL
	if dedupTTL == 0 {
		dedupTTL = defaultDedupTTL
	}
	if dedupTTL < time.Second {
		return nil, errors.New("xet CAS server: dedup TTL must be at least one second")
	}
	dedupKey := options.DedupProtectionKey
	if dedupKey.IsZero() {
		if _, err := rand.Read(dedupKey[:]); err != nil {
			return nil, fmt.Errorf("xet CAS server: generate dedup protection key: %w", err)
		}
	}
	maxXorb := options.MaxXorbBody
	if maxXorb == 0 {
		maxXorb = xorb.MaxNetworkSize
	}
	maxShard := options.MaxShardBody
	if maxShard == 0 {
		maxShard = shard.MaxSize
	}
	if maxXorb < 1 || maxXorb > xorb.MaxNetworkSize || maxShard < 1 || maxShard > shard.MaxSize {
		return nil, errors.New("xet CAS server: invalid request body limits")
	}
	registration := options.RegistrationLimits
	if registration.MaxFiles == 0 {
		registration.MaxFiles = defaultMaxRegistrationFiles
	}
	if registration.MaxXorbs == 0 {
		registration.MaxXorbs = defaultMaxRegistrationXorbs
	}
	if registration.MaxTerms == 0 {
		registration.MaxTerms = defaultMaxRegistrationTerms
	}
	if registration.MaxChunkReferences == 0 {
		registration.MaxChunkReferences = defaultMaxRegistrationChunkRefs
	}
	maxConcurrentIngests := options.MaxConcurrentIngests
	if maxConcurrentIngests == 0 {
		maxConcurrentIngests = defaultMaxConcurrentIngests
	}
	if maxConcurrentIngests < 1 {
		return nil, errors.New("xet CAS server: maximum concurrent ingests must be positive")
	}
	return &Service{
		blobs: options.Blobs, index: options.Index, signer: options.Signer, authorizer: options.Authorizer,
		now: now, dedupKey: dedupKey, dedupTTL: dedupTTL, maxXorb: maxXorb, maxShard: maxShard,
		registration: registration, ingestSlots: make(chan struct{}, maxConcurrentIngests),
		shardHeartbeat: defaultShardHeartbeat,
	}, nil
}

func (s *Service) authorize(ctx context.Context, credential string, request AccessRequest) (Grant, error) {
	grant, err := s.authorizer.Authorize(ctx, credential, request)
	if err != nil {
		return Grant{}, err
	}
	return grant, nil
}

func (s *Service) acquireIngest(ctx context.Context) (func(), error) {
	select {
	case s.ingestSlots <- struct{}{}:
		return func() { <-s.ingestSlots }, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// UploadXorb validates a footerless body, stores its canonical complete form,
// and publishes its layout index only after the blob is durable.
func (s *Service) UploadXorb(
	ctx context.Context,
	credential, prefix string,
	expected xethash.Hash,
	body io.Reader,
	contentLength int64,
) (bool, error) {
	if prefix != xetcas.DefaultXorbPrefix {
		return false, ErrNotFound
	}
	if _, err := s.authorize(ctx, credential, AccessRequest{
		Operation: OperationWriteXorb, Prefix: prefix, Hash: expected,
	}); err != nil {
		return false, err
	}
	release, err := s.acquireIngest(ctx)
	if err != nil {
		return false, err
	}
	defer release()
	data, err := readBounded(body, contentLength, s.maxXorb)
	if err != nil {
		return false, err
	}
	ingested, err := xorb.IngestNetwork(data, expected)
	if err != nil {
		return false, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	if existing, found, err := s.index.GetXorb(ctx, expected); err != nil {
		return false, err
	} else if found {
		if !sameLayout(&existing.Layout, ingested) {
			return false, ErrConflict
		}
		return false, nil
	}

	key := BlobKey{Kind: BlobXorb, Hash: expected}
	inserted, err := s.blobs.PutIfAbsent(ctx, key, bytes.NewReader(ingested.Complete), int64(len(ingested.Complete)))
	if errors.Is(err, ErrConflict) {
		// The xorb identity covers uncompressed chunks, not a particular valid
		// compression byte stream. Preserve the first representation and repair
		// its index after a lost response or concurrent equivalent upload.
		ingested, err = s.layoutFromStoredXorb(ctx, key, expected)
		inserted = false
	}
	if err != nil {
		return false, err
	}
	record := XorbRecord{Blob: key, Layout: *ingested}
	record.Layout.Complete = nil
	if err := s.index.PutXorb(ctx, record); err != nil {
		return false, err
	}
	return inserted, nil
}

func (s *Service) layoutFromStoredXorb(ctx context.Context, key BlobKey, expected xethash.Hash) (*xorb.Ingested, error) {
	reader, err := s.blobs.Get(ctx, key, nil)
	if err != nil {
		return nil, err
	}
	body, err := io.ReadAll(io.LimitReader(reader, int64(xorb.MaxNetworkSize)+1<<20))
	if err != nil {
		_ = reader.Close()
		return nil, err
	}
	if err := reader.Close(); err != nil {
		return nil, fmt.Errorf("xet CAS server: close stored xorb: %w", err)
	}
	object, err := xorb.Decode(body)
	if err != nil {
		return nil, err
	}
	if object.Footer == nil || object.Hash != expected || object.FooterOffset == 0 {
		return nil, ErrConflict
	}
	result := &xorb.Ingested{
		Hash: expected, NetworkBytes: object.FooterOffset, UncompressedSize: object.UncompressedSize,
		Chunks: make([]xorb.IngestedChunk, len(object.Chunks)),
	}
	for i, chunk := range object.Chunks {
		result.Chunks[i] = xorb.IngestedChunk{
			Hash: chunk.Hash, SerializedOffset: chunk.SerializedOffset, SerializedLength: chunk.SerializedLength,
			UncompressedOffset: chunk.UncompressedOffset, UncompressedLength: chunk.UncompressedLength,
		}
	}
	return result, nil
}

func sameLayout(left *xorb.Ingested, right *xorb.Ingested) bool {
	if left == nil || right == nil || left.Hash != right.Hash || left.UncompressedSize != right.UncompressedSize ||
		len(left.Chunks) != len(right.Chunks) {
		return false
	}
	for i := range left.Chunks {
		a, b := left.Chunks[i], right.Chunks[i]
		if a.Hash != b.Hash || a.UncompressedOffset != b.UncompressedOffset || a.UncompressedLength != b.UncompressedLength {
			return false
		}
	}
	return true
}

func (s *Service) XorbExists(ctx context.Context, credential, prefix string, hash xethash.Hash) (bool, error) {
	if prefix != xetcas.DefaultXorbPrefix {
		return false, nil
	}
	if _, err := s.authorize(ctx, credential, AccessRequest{Operation: OperationReadXorb, Prefix: prefix, Hash: hash}); err != nil {
		return false, err
	}
	_, found, err := s.index.GetXorb(ctx, hash)
	return found, err
}

// UploadShard publishes in repairable order: canonical shard blob, dedup
// entries, scoped SHA-256 associations, and file reconstruction records last.
func (s *Service) UploadShard(
	ctx context.Context,
	credential string,
	body io.Reader,
	contentLength int64,
) (ShardResult, error) {
	grant, err := s.authorize(ctx, credential, AccessRequest{Operation: OperationWriteShard})
	if err != nil {
		return ShardResult{}, err
	}
	release, err := s.acquireIngest(ctx)
	if err != nil {
		return ShardResult{}, err
	}
	defer release()
	data, err := readBounded(body, contentLength, s.maxShard)
	if err != nil {
		return ShardResult{}, err
	}
	return s.publishShard(ctx, grant, data)
}

func (s *Service) publishShard(ctx context.Context, grant Grant, data []byte) (ShardResult, error) {
	upload, err := shard.Decode(data)
	if err != nil {
		return ShardResult{}, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	if upload.Footer != nil {
		return ShardResult{}, fmt.Errorf("%w: shard upload must be footerless", ErrInvalid)
	}
	registration, err := shard.ValidateRegistrationContext(ctx, *upload, func(hash xethash.Hash) (shard.Xorb, bool, error) {
		record, found, err := s.index.GetXorb(ctx, hash)
		if err != nil || !found {
			return shard.Xorb{}, found, err
		}
		value, err := shard.XorbFromIngested(&record.Layout)
		return value, err == nil, err
	}, s.registration)
	if err != nil {
		if errors.Is(err, shard.ErrRegistrationLimit) {
			return ShardResult{}, fmt.Errorf("%w: %v", ErrTooLarge, err)
		}
		if errors.Is(err, shard.ErrXorbLookup) {
			return ShardResult{}, err
		}
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return ShardResult{}, err
		}
		return ShardResult{}, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	canonical := shard.Shard{Files: make([]shard.File, len(registration.Files)), Xorbs: registration.Xorbs}
	for i := range registration.Files {
		canonical.Files[i] = registration.Files[i].File
	}
	full, err := shard.EncodeFull(canonical)
	if err != nil {
		return ShardResult{}, err
	}
	shardKey := BlobKey{Kind: BlobShard, Hash: xethash.Chunk(full)}
	inserted, err := s.blobs.PutIfAbsent(ctx, shardKey, bytes.NewReader(full), int64(len(full)))
	if err != nil {
		return ShardResult{}, err
	}
	for _, hash := range registration.GlobalDedupChunks {
		if err := s.index.PutDedup(ctx, grant.Namespace, hash, DedupRecord{Shard: shardKey}); err != nil {
			return ShardResult{}, fmt.Errorf("xet CAS server: publish dedup chunk %s: %w", hash, err)
		}
	}
	for _, file := range registration.Files {
		if file.File.SHA256 != nil {
			if err := s.index.PutSHA256(ctx, grant.Namespace, *file.File.SHA256, file.Size, file.File.Hash); err != nil {
				return ShardResult{}, fmt.Errorf("xet CAS server: publish SHA-256 for %s: %w", file.File.Hash, err)
			}
		}
	}
	for _, file := range registration.Files {
		if err := s.index.PutFile(ctx, grant.Namespace, FileRecord{File: file, Shard: shardKey}); err != nil {
			return ShardResult{}, fmt.Errorf("xet CAS server: publish file %s: %w", file.File.Hash, err)
		}
	}
	return ShardResult{
		Shard: shardKey, Inserted: inserted, Files: len(registration.Files),
		GlobalDedupChunks: len(registration.GlobalDedupChunks),
	}, nil
}

func readBounded(body io.Reader, declared, limit int64) ([]byte, error) {
	if body == nil {
		return nil, errors.New("xet CAS server: nil request body")
	}
	if declared > limit {
		return nil, ErrTooLarge
	}
	data, err := io.ReadAll(io.LimitReader(body, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, ErrTooLarge
	}
	if declared >= 0 && int64(len(data)) != declared {
		return nil, fmt.Errorf("%w: body size %d, declared %d", ErrInvalid, len(data), declared)
	}
	return data, nil
}
