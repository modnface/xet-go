package xetcas

import (
	"context"
	"errors"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jmwoliver/xet-go/xethash"
)

func TestRangeTypesUseDocumentedInclusiveAndHalfOpenSemantics(t *testing.T) {
	fileRange := FileRange{Start: 4, End: 9}
	if fileRange.Len() != 5 || fileRange.Validate() != nil {
		t.Fatalf("file range = %#v, len %d", fileRange, fileRange.Len())
	}
	httpRange, err := fileRange.HTTPRange()
	if err != nil || httpRange != (HTTPRange{Start: 4, End: 8}) {
		t.Fatalf("HTTPRange = %#v, %v", httpRange, err)
	}
	if got := (FileRange{Start: 9, End: 4}).Len(); got != 0 {
		t.Fatalf("reversed FileRange.Len = %d", got)
	}
	if _, err := (FileRange{Start: 1, End: 1}).HTTPRange(); err == nil {
		t.Fatal("empty file range converted to HTTP range")
	}

	chunkRange := ChunkRange{Start: 2, End: 5}
	if chunkRange.Len() != 3 || chunkRange.Validate() != nil || !chunkRange.Contains(ChunkRange{Start: 3, End: 4}) {
		t.Fatalf("chunk range = %#v", chunkRange)
	}
	if err := (ChunkRange{Start: 3, End: 3}).Validate(); err == nil {
		t.Fatal("empty chunk range validated")
	}

	inclusive := HTTPRange{Start: 2, End: 5}
	if inclusive.Len() != 4 || inclusive.Validate() != nil || inclusive.String() != "2-5" {
		t.Fatalf("HTTP range = %#v, len %d", inclusive, inclusive.Len())
	}
	if got := (HTTPRange{Start: 5, End: 2}).Len(); got != 0 {
		t.Fatalf("reversed HTTPRange.Len = %d", got)
	}
	if err := (HTTPRange{Start: 5, End: 2}).Validate(); err == nil {
		t.Fatal("reversed HTTP range validated")
	}
}

func validReconstruction() *Reconstruction {
	hash := xethash.Chunk([]byte("xorb"))
	return &Reconstruction{
		OffsetIntoFirstRange: 1,
		Terms:                []ReconstructionTerm{{Hash: hash, UnpackedLength: 3, Range: ChunkRange{Start: 1, End: 2}}},
		Xorbs: map[xethash.Hash][]MultiRangeFetch{
			hash: {{URL: "https://storage.example/object?signature=secret", Ranges: []XorbRangeDescriptor{{
				Chunks: ChunkRange{Start: 0, End: 3}, Bytes: HTTPRange{Start: 10, End: 20},
			}}}},
		},
	}
}

func TestReconstructionValidationContracts(t *testing.T) {
	if (*Reconstruction)(nil).Validate() == nil {
		t.Fatal("nil reconstruction validated")
	}
	if err := (&Reconstruction{}).Validate(); err != nil {
		t.Fatalf("empty reconstruction: %v", err)
	}
	if err := (&Reconstruction{OffsetIntoFirstRange: 1}).Validate(); err == nil {
		t.Fatal("offset on empty reconstruction validated")
	}
	if err := validReconstruction().Validate(); err != nil {
		t.Fatalf("valid reconstruction: %v", err)
	}

	for name, mutate := range map[string]func(*Reconstruction){
		"offset":       func(r *Reconstruction) { r.OffsetIntoFirstRange = 3 },
		"term range":   func(r *Reconstruction) { r.Terms[0].Range.End = r.Terms[0].Range.Start },
		"zero term":    func(r *Reconstruction) { r.Terms[0].UnpackedLength = 0 },
		"missing xorb": func(r *Reconstruction) { r.Xorbs = nil },
		"uncovered":    func(r *Reconstruction) { r.Xorbs[r.Terms[0].Hash][0].Ranges[0].Chunks = ChunkRange{4, 5} },
		"bad URL":      func(r *Reconstruction) { r.Xorbs[r.Terms[0].Hash][0].URL = "relative" },
		"no ranges":    func(r *Reconstruction) { r.Xorbs[r.Terms[0].Hash][0].Ranges = nil },
		"bad bytes":    func(r *Reconstruction) { r.Xorbs[r.Terms[0].Hash][0].Ranges[0].Bytes = HTTPRange{2, 1} },
		"overlap": func(r *Reconstruction) {
			fetch := r.Xorbs[r.Terms[0].Hash][0]
			fetch.Ranges = append(fetch.Ranges, XorbRangeDescriptor{Chunks: ChunkRange{2, 4}, Bytes: HTTPRange{21, 22}})
			r.Xorbs[r.Terms[0].Hash][0] = fetch
		},
	} {
		t.Run(name, func(t *testing.T) {
			value := validReconstruction()
			mutate(value)
			if err := value.Validate(); err == nil {
				t.Fatalf("mutated reconstruction validated: %#v", value)
			}
		})
	}

	zeroTerm := validReconstruction()
	zeroTerm.Terms = append(zeroTerm.Terms, ReconstructionTerm{
		Hash: zeroTerm.Terms[0].Hash, Range: ChunkRange{Start: 2, End: 3},
	})
	if err := zeroTerm.Validate(); err == nil || !strings.Contains(err.Error(), "zero unpacked") {
		t.Fatalf("zero-length term = %v", err)
	}

	noRanges := validReconstruction()
	hash := noRanges.Terms[0].Hash
	noRanges.Xorbs[hash] = append(noRanges.Xorbs[hash], MultiRangeFetch{URL: "https://storage.example/empty"})
	if err := noRanges.Validate(); err == nil || !strings.Contains(err.Error(), "has no ranges") {
		t.Fatalf("empty fetch ranges = %v", err)
	}

	invalidDescriptor := validReconstruction()
	invalidDescriptor.Xorbs[hash][0].Ranges = append(invalidDescriptor.Xorbs[hash][0].Ranges, XorbRangeDescriptor{
		Chunks: ChunkRange{}, Bytes: HTTPRange{Start: 21, End: 21},
	})
	if err := invalidDescriptor.Validate(); err == nil || !strings.Contains(err.Error(), "invalid chunk range") {
		t.Fatalf("invalid fetch descriptor = %v", err)
	}
}

func TestAdaptiveLimiterNilAndBlockedCancellation(t *testing.T) {
	var nilLimiter *adaptiveLimiter
	if _, err := nilLimiter.acquire(context.Background()); err == nil {
		t.Fatal("nil limiter acquired")
	}
	limiter := newAdaptiveLimiter(ConcurrencyPolicy{Initial: 1, Minimum: 1, Maximum: 1})
	first, err := limiter.acquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	ctx := &cancelWhenDoneObserved{Context: context.Background(), done: make(chan struct{})}
	if _, err := limiter.acquire(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("blocked limiter cancellation = %v", err)
	}
	first.done(true, false)
}

type cancelWhenDoneObserved struct {
	context.Context
	done     chan struct{}
	observed bool
}

func (c *cancelWhenDoneObserved) Done() <-chan struct{} {
	if !c.observed {
		c.observed = true
		close(c.done)
	}
	return c.done
}

func (c *cancelWhenDoneObserved) Err() error {
	if c.observed {
		return context.Canceled
	}
	return nil
}

func TestLegacyReconstructionNormalization(t *testing.T) {
	file := xethash.Chunk([]byte("file"))
	xorbHash := xethash.Chunk([]byte("xorb"))
	term := ReconstructionTerm{Hash: xorbHash, UnpackedLength: 1, Range: ChunkRange{0, 1}}
	info := V1FetchInfo{Range: ChunkRange{0, 1}, URL: "https://storage.example/x", URLRange: HTTPRange{0, 9}}

	normalized := (ReconstructionV1{OffsetIntoFirstRange: 0, Terms: []ReconstructionTerm{term}, FetchInfo: map[xethash.Hash][]V1FetchInfo{xorbHash: {info}}}).normalize()
	if err := normalized.Validate(); err != nil {
		t.Fatalf("single normalization: %v", err)
	}

	batch := BatchReconstructionV1{
		Files:     map[xethash.Hash][]ReconstructionTerm{file: {term, term}},
		FetchInfo: map[xethash.Hash][]V1FetchInfo{xorbHash: {info}},
	}
	result, err := batch.normalize()
	if err != nil || len(result) != 1 || len(result[file].Xorbs) != 1 {
		t.Fatalf("batch normalization = %#v, %v", result, err)
	}
	batch.FetchInfo = nil
	if _, err := batch.normalize(); err == nil {
		t.Fatal("batch without fetch data normalized")
	}
	batch.FetchInfo = map[xethash.Hash][]V1FetchInfo{xorbHash: {{Range: ChunkRange{}, URL: "relative"}}}
	if _, err := batch.normalize(); err == nil {
		t.Fatal("batch with invalid reconstruction normalized")
	}
}

func TestFileChunkHashAndSignedURLValidation(t *testing.T) {
	if (*FileChunkHashesResponse)(nil).Validate() == nil {
		t.Fatal("nil response validated")
	}
	valid := &FileChunkHashesResponse{
		FileSize:   100,
		Windows:    []ChunkWindow{{DirtyByteRange: [2]uint64{10, 20}}, {DirtyByteRange: [2]uint64{30, 40}}},
		HashRanges: make([]*xethash.MerkleHashSubtree, 3),
	}
	if err := valid.Validate(); err != nil {
		t.Fatalf("valid response: %v", err)
	}
	for name, value := range map[string]*FileChunkHashesResponse{
		"range count":  {HashRanges: make([]*xethash.MerkleHashSubtree, 2)},
		"empty window": {FileSize: 100, Windows: []ChunkWindow{{DirtyByteRange: [2]uint64{10, 10}}}, HashRanges: make([]*xethash.MerkleHashSubtree, 2)},
		"past end":     {FileSize: 100, Windows: []ChunkWindow{{DirtyByteRange: [2]uint64{10, 101}}}, HashRanges: make([]*xethash.MerkleHashSubtree, 2)},
		"overlap":      {FileSize: 100, Windows: []ChunkWindow{{DirtyByteRange: [2]uint64{10, 30}}, {DirtyByteRange: [2]uint64{20, 40}}}, HashRanges: make([]*xethash.MerkleHashSubtree, 3)},
	} {
		t.Run(name, func(t *testing.T) {
			if err := value.Validate(); err == nil {
				t.Fatal("invalid response validated")
			}
		})
	}

	for _, raw := range []string{"%", "relative", "ftp://example.test/x", "https://user@example.test/x", "https://example.test/x#fragment"} {
		if err := validateSignedURL(raw); err == nil {
			t.Errorf("signed URL %q validated", raw)
		}
	}
	if err := validateSignedURL("https://example.test/x?signature=secret"); err != nil {
		t.Fatalf("valid signed URL: %v", err)
	}

	ranges := []FetchedRange{{Range: HTTPRange{2, 4}}, {Range: HTTPRange{1, 5}}, {Range: HTTPRange{1, 3}}}
	sortFetchedRanges(ranges)
	want := []HTTPRange{{1, 3}, {1, 5}, {2, 4}}
	got := []HTTPRange{ranges[0].Range, ranges[1].Range, ranges[2].Range}
	if !slices.Equal(got, want) {
		t.Fatalf("sorted ranges = %v", got)
	}
	if !(ShardUploadEvent{Type: "result"}).Terminal() || !(ShardUploadEvent{Type: "error"}).Terminal() || (ShardUploadEvent{Type: "progress"}).Terminal() {
		t.Fatal("terminal event classification differs")
	}
}

func TestStaticAccessAndCacheContracts(t *testing.T) {
	var nilProvider *StaticAccessProvider
	if _, err := nilProvider.Access(context.Background(), AccessRead); err == nil {
		t.Fatal("nil provider returned access")
	}
	endpoint, err := url.Parse("https://cas.example/base")
	if err != nil {
		t.Fatal(err)
	}
	provider := NewStaticAccess(endpoint, "token")
	endpoint.Host = "mutated.example"
	read, err := provider.Access(context.Background(), AccessRead)
	if err != nil || read.Endpoint.Host != "cas.example" {
		t.Fatalf("read access = %#v, %v", read, err)
	}
	read.Endpoint.Host = "caller-mutated.example"
	write, err := provider.Access(context.Background(), AccessWrite)
	if err != nil || write.Endpoint.Host != "cas.example" {
		t.Fatalf("write access = %#v, %v", write, err)
	}
	if _, err := provider.Access(context.Background(), Access(99)); err == nil {
		t.Fatal("invalid access mode succeeded")
	}
	provider.Invalidate(AccessRead)
	if cloneURL(nil) != nil {
		t.Fatal("cloneURL(nil) was non-nil")
	}

	cache := &accessCache{provider: provider, now: time.Now}
	if _, err := cache.get(context.Background(), Access(99)); err == nil {
		t.Fatal("cache accepted invalid mode")
	}
	cache.invalidate(Access(99))

	waiting := &accessCache{provider: provider, now: time.Now}
	waiting.entries[AccessRead].refreshing = make(chan struct{})
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := waiting.get(canceled, AccessRead); !errors.Is(err, context.Canceled) {
		t.Fatalf("waiting cache ignored cancellation: %v", err)
	}

	want := errors.New("provider failed")
	failed := &errorAccessProvider{err: want}
	cache = &accessCache{provider: failed, now: time.Now}
	if _, err := cache.get(context.Background(), AccessRead); !errors.Is(err, want) {
		t.Fatalf("provider error = %v", err)
	}
}

type errorAccessProvider struct{ err error }

func (p *errorAccessProvider) Access(context.Context, Access) (CASAccess, error) {
	return CASAccess{}, p.err
}
func (*errorAccessProvider) Invalidate(Access) {}
