// Package xetcas implements the Xet content-addressable-storage HTTP protocol.
//
// It deliberately accepts already-issued CAS access. It does not know how to
// authenticate to a hosting provider or resolve repository paths.
package xetcas

import (
	"errors"
	"fmt"
	"net/url"
	"sort"

	"github.com/jmwoliver/xet-go/xethash"
)

const (
	// DefaultXorbPrefix is the only namespace accepted by the public xorb
	// upload and existence routes.
	DefaultXorbPrefix = "default"
	// DefaultFilePrefix is the namespace used by batch reconstruction keys.
	DefaultFilePrefix = "default"
	// DefaultDedupPrefix is the namespace specified by the public global
	// chunk-deduplication API. Servers may additionally accept
	// DefaultXorbPrefix for compatibility with released xet-core clients, which
	// currently send their shared default prefix to both APIs.
	DefaultDedupPrefix = "default-merkledb"

	// DefaultPrefix is retained as a source-compatible alias for the xorb
	// namespace. New code should name the protocol namespace explicitly.
	//
	// Deprecated: use DefaultXorbPrefix, DefaultFilePrefix, or
	// DefaultDedupPrefix as appropriate.
	DefaultPrefix = DefaultXorbPrefix
)

// Key is the namespace-qualified object identity used by batch CAS requests.
type Key struct {
	Prefix string       `json:"prefix"`
	Hash   xethash.Hash `json:"hash"`
}

var (
	ErrRangeNotSatisfiable = errors.New("xet CAS: range not satisfiable")
	ErrSignedURLExpired    = errors.New("xet CAS: signed URL expired")
	ErrMissingTerminal     = errors.New("xet CAS: shard upload ended without a terminal event")
)

// FileRange is a half-open logical byte range [Start, End).
type FileRange struct {
	Start uint64 `json:"start"`
	End   uint64 `json:"end"`
}

func (r FileRange) Len() uint64 {
	if r.End < r.Start {
		return 0
	}
	return r.End - r.Start
}

func (r FileRange) Validate() error {
	if r.End <= r.Start {
		return fmt.Errorf("xet CAS: invalid file range [%d,%d)", r.Start, r.End)
	}
	return nil
}

func (r FileRange) HTTPRange() (HTTPRange, error) {
	if err := r.Validate(); err != nil {
		return HTTPRange{}, err
	}
	return HTTPRange{Start: r.Start, End: r.End - 1}, nil
}

// ChunkRange is a half-open range [Start, End) of chunks in one xorb.
type ChunkRange struct {
	Start uint32 `json:"start"`
	End   uint32 `json:"end"`
}

func (r ChunkRange) Len() uint32 { return r.End - r.Start }

func (r ChunkRange) Validate() error {
	if r.End <= r.Start {
		return fmt.Errorf("xet CAS: invalid chunk range [%d,%d)", r.Start, r.End)
	}
	return nil
}

func (r ChunkRange) Contains(other ChunkRange) bool {
	return r.Start <= other.Start && other.End <= r.End
}

// HTTPRange uses the inclusive end mandated by HTTP byte ranges.
type HTTPRange struct {
	Start uint64 `json:"start"`
	End   uint64 `json:"end"`
}

func (r HTTPRange) Len() uint64 {
	if r.End < r.Start {
		return 0
	}
	return r.End - r.Start + 1
}

func (r HTTPRange) Validate() error {
	if r.End < r.Start {
		return fmt.Errorf("xet CAS: invalid HTTP range [%d,%d]", r.Start, r.End)
	}
	return nil
}

func (r HTTPRange) String() string { return fmt.Sprintf("%d-%d", r.Start, r.End) }

// ReconstructionTerm selects chunks from an xorb and states their total raw
// length. The range is half-open.
type ReconstructionTerm struct {
	Hash           xethash.Hash `json:"hash"`
	UnpackedLength uint32       `json:"unpacked_length"`
	Range          ChunkRange   `json:"range"`
}

// XorbRangeDescriptor maps a chunk range to its inclusive serialized range in
// the xorb object.
type XorbRangeDescriptor struct {
	Chunks ChunkRange `json:"chunks"`
	Bytes  HTTPRange  `json:"bytes"`
}

// MultiRangeFetch is one signed URL and the exact byte ranges authorized for
// it. The caller must not add CAS credentials to this URL.
type MultiRangeFetch struct {
	URL    string                `json:"url"`
	Ranges []XorbRangeDescriptor `json:"ranges"`
}

// Reconstruction is the normalized v2 representation. V1 responses are
// losslessly converted into this shape.
type Reconstruction struct {
	OffsetIntoFirstRange uint64                             `json:"offset_into_first_range"`
	Terms                []ReconstructionTerm               `json:"terms"`
	Xorbs                map[xethash.Hash][]MultiRangeFetch `json:"xorbs"`
}

func (r *Reconstruction) Validate() error {
	if r == nil {
		return errors.New("xet CAS: nil reconstruction")
	}
	if len(r.Terms) == 0 {
		if r.OffsetIntoFirstRange != 0 {
			return errors.New("xet CAS: empty reconstruction has nonzero initial offset")
		}
		return nil
	}
	if r.OffsetIntoFirstRange >= uint64(r.Terms[0].UnpackedLength) {
		return errors.New("xet CAS: initial offset is outside the first reconstruction term")
	}
	for i, term := range r.Terms {
		if err := term.Range.Validate(); err != nil {
			return fmt.Errorf("xet CAS: term %d: %w", i, err)
		}
		if term.UnpackedLength == 0 {
			return fmt.Errorf("xet CAS: term %d has zero unpacked length", i)
		}
		fetches, ok := r.Xorbs[term.Hash]
		if !ok {
			return fmt.Errorf("xet CAS: term %d has no fetch entry for xorb %s", i, term.Hash)
		}
		covered := false
		for _, fetch := range fetches {
			for _, descriptor := range fetch.Ranges {
				if descriptor.Chunks.Contains(term.Range) {
					covered = true
				}
			}
		}
		if !covered {
			return fmt.Errorf("xet CAS: term %d range is not covered by a fetch descriptor", i)
		}
	}
	for hash, fetches := range r.Xorbs {
		for i, fetch := range fetches {
			if err := validateSignedURL(fetch.URL); err != nil {
				return fmt.Errorf("xet CAS: xorb %s fetch %d: %w", hash, i, err)
			}
			if len(fetch.Ranges) == 0 {
				return fmt.Errorf("xet CAS: xorb %s fetch %d has no ranges", hash, i)
			}
			for j, descriptor := range fetch.Ranges {
				if err := descriptor.Chunks.Validate(); err != nil {
					return fmt.Errorf("xet CAS: xorb %s fetch %d range %d: %w", hash, i, j, err)
				}
				if err := descriptor.Bytes.Validate(); err != nil {
					return fmt.Errorf("xet CAS: xorb %s fetch %d range %d: %w", hash, i, j, err)
				}
				if j > 0 && fetch.Ranges[j-1].Chunks.End > descriptor.Chunks.Start {
					return fmt.Errorf("xet CAS: xorb %s fetch %d has unsorted or overlapping chunk ranges", hash, i)
				}
			}
		}
	}
	return nil
}

// FetchedRange is one signed object-storage result identified by its declared
// Content-Range rather than by multipart ordering.
type FetchedRange struct {
	Range HTTPRange
	Data  []byte
}

// ShardUploadEvent is one v2 NDJSON progress frame.
type ShardUploadEvent struct {
	Type      string `json:"type"`
	Verified  uint64 `json:"verified,omitempty"`
	Total     uint64 `json:"total,omitempty"`
	Stage     string `json:"stage,omitempty"`
	Message   string `json:"message,omitempty"`
	Retryable bool   `json:"retryable,omitempty"`
}

func (e ShardUploadEvent) Terminal() bool { return e.Type == "result" || e.Type == "error" }

// V1FetchInfo is one legacy signed single-range xorb fetch.
type V1FetchInfo struct {
	Range    ChunkRange `json:"range"`
	URL      string     `json:"url"`
	URLRange HTTPRange  `json:"url_range"`
}

// ReconstructionV1 is the deprecated single-file v1 wire response.
type ReconstructionV1 struct {
	OffsetIntoFirstRange uint64                         `json:"offset_into_first_range"`
	Terms                []ReconstructionTerm           `json:"terms"`
	FetchInfo            map[xethash.Hash][]V1FetchInfo `json:"fetch_info"`
}

// BatchReconstructionV1 is the v1 batch reconstruction wire response.
type BatchReconstructionV1 struct {
	Files     map[xethash.Hash][]ReconstructionTerm `json:"files"`
	FetchInfo map[xethash.Hash][]V1FetchInfo        `json:"fetch_info"`
}

func (v BatchReconstructionV1) normalize() (map[xethash.Hash]*Reconstruction, error) {
	result := make(map[xethash.Hash]*Reconstruction, len(v.Files))
	for fileID, terms := range v.Files {
		reconstruction := &Reconstruction{
			Terms: terms,
			Xorbs: make(map[xethash.Hash][]MultiRangeFetch),
		}
		for _, term := range terms {
			if _, exists := reconstruction.Xorbs[term.Hash]; exists {
				continue
			}
			infos, ok := v.FetchInfo[term.Hash]
			if !ok {
				return nil, fmt.Errorf("xet CAS: batch file %s has no fetch data for xorb %s", fileID, term.Hash)
			}
			fetches := make([]MultiRangeFetch, 0, len(infos))
			for _, info := range infos {
				fetches = append(fetches, MultiRangeFetch{
					URL:    info.URL,
					Ranges: []XorbRangeDescriptor{{Chunks: info.Range, Bytes: info.URLRange}},
				})
			}
			reconstruction.Xorbs[term.Hash] = fetches
		}
		if err := reconstruction.Validate(); err != nil {
			return nil, fmt.Errorf("xet CAS: batch file %s: %w", fileID, err)
		}
		result[fileID] = reconstruction
	}
	return result, nil
}

type ChunkWindow struct {
	DirtyByteRange [2]uint64 `json:"dirtyByteRange"`
}

// FileChunkHashesResponse is the v2 delta-upload response. A nil HashRanges
// entry is an empty gap; non-nil entries use the exact Rust subtree JSON form.
type FileChunkHashesResponse struct {
	TotalChunks     uint64                       `json:"totalChunks"`
	FileSize        uint64                       `json:"fileSize"`
	Windows         []ChunkWindow                `json:"windows"`
	HashRanges      []*xethash.MerkleHashSubtree `json:"hashRanges"`
	GapVerification []xethash.Hash               `json:"gapVerification"`
}

func (r *FileChunkHashesResponse) Validate() error {
	if r == nil {
		return errors.New("xet CAS: nil file chunk hash response")
	}
	if len(r.HashRanges) != len(r.Windows)+1 {
		return fmt.Errorf("xet CAS: file chunk hash response has %d windows and %d hash ranges", len(r.Windows), len(r.HashRanges))
	}
	var previous uint64
	for i, window := range r.Windows {
		start, end := window.DirtyByteRange[0], window.DirtyByteRange[1]
		if end <= start || end > r.FileSize || (i > 0 && start < previous) {
			return fmt.Errorf("xet CAS: invalid dirty window %d [%d,%d)", i, start, end)
		}
		previous = end
	}
	return nil
}

func (v ReconstructionV1) normalize() *Reconstruction {
	r := &Reconstruction{
		OffsetIntoFirstRange: v.OffsetIntoFirstRange,
		Terms:                v.Terms,
		Xorbs:                make(map[xethash.Hash][]MultiRangeFetch, len(v.FetchInfo)),
	}
	for hash, infos := range v.FetchInfo {
		fetches := make([]MultiRangeFetch, 0, len(infos))
		for _, info := range infos {
			fetches = append(fetches, MultiRangeFetch{
				URL:    info.URL,
				Ranges: []XorbRangeDescriptor{{Chunks: info.Range, Bytes: info.URLRange}},
			})
		}
		r.Xorbs[hash] = fetches
	}
	return r
}

func validateSignedURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("invalid signed URL: %w", err)
	}
	if (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return errors.New("signed URL must be an absolute HTTP(S) URL")
	}
	if u.User != nil {
		return errors.New("signed URL must not contain user information")
	}
	if u.Fragment != "" {
		return errors.New("signed URL must not contain a fragment")
	}
	return nil
}

func sortFetchedRanges(ranges []FetchedRange) {
	sort.Slice(ranges, func(i, j int) bool {
		if ranges[i].Range.Start == ranges[j].Range.Start {
			return ranges[i].Range.End < ranges[j].Range.End
		}
		return ranges[i].Range.Start < ranges[j].Range.Start
	})
}
