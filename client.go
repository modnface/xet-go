package xet

import (
	"context"
	"errors"
	"fmt"
	"io"
	"runtime"
	"time"

	"github.com/jacobwoliver/xet-go/xetcas"
	"github.com/jacobwoliver/xet-go/xethash"
	"github.com/jacobwoliver/xet-go/xorb"
)

// Protocol is the Xet CAS data-plane surface consumed by the transfer engine.
// *xetcas.Client implements it. The interface also enables deterministic local
// and fault-injection testing without a hosting control plane.
type Protocol interface {
	QueryReconstruction(context.Context, xethash.Hash, *xetcas.FileRange) (*xetcas.Reconstruction, error)
	FetchRanges(context.Context, string, []xetcas.HTTPRange) ([]xetcas.FetchedRange, error)
	UploadXorb(context.Context, string, xethash.Hash, []byte) (bool, error)
	UploadShard(context.Context, []byte, func(xetcas.ShardUploadEvent)) error
	QueryGlobalDedup(context.Context, string, xethash.Hash) ([]byte, bool, error)
}

type ProgressPhase string

const (
	ProgressChunking       ProgressPhase = "chunking"
	ProgressUploadingXorb  ProgressPhase = "uploading_xorb"
	ProgressUploadingShard ProgressPhase = "uploading_shard"
	ProgressDownloading    ProgressPhase = "downloading"
)

// Progress is a monotonic transfer observation. Callbacks can be made from
// several bounded worker goroutines and therefore must be concurrency-safe.
type Progress struct {
	Phase     ProgressPhase
	File      xethash.Hash
	Completed uint64
	Total     uint64
}

// Options controls engine behavior. Zero values select production defaults.
type Options struct {
	Prefix      string
	Compression xorb.Scheme
	// CompressionSet distinguishes explicit None (whose numeric value is zero)
	// from the zero Options value, which selects Auto.
	CompressionSet            bool
	CompressionRetestInterval int
	UploadConcurrency         int
	DownloadConcurrency       int
	MaxDownloadMemory         uint64
	GlobalDedup               bool
	Progress                  func(Progress)
}

// Client is the high-level, hosting-decoupled Xet transfer engine.
type Client struct {
	protocol Protocol
	options  Options
}

func NewClient(protocol Protocol, options Options) (*Client, error) {
	if protocol == nil {
		return nil, errors.New("xet: nil CAS protocol client")
	}
	if options.Prefix == "" {
		options.Prefix = xetcas.DefaultPrefix
	}
	if !options.CompressionSet {
		options.Compression = xorb.Auto
	}
	if options.Compression != xorb.None && options.Compression != xorb.LZ4 &&
		options.Compression != xorb.BG4LZ4 && options.Compression != xorb.Auto {
		return nil, fmt.Errorf("xet: invalid compression scheme %d", options.Compression)
	}
	if options.CompressionRetestInterval < 0 {
		return nil, errors.New("xet: negative compression retest interval")
	}
	if options.UploadConcurrency == 0 {
		options.UploadConcurrency = min(4, max(1, runtime.GOMAXPROCS(0)))
	}
	if options.DownloadConcurrency == 0 {
		options.DownloadConcurrency = min(8, max(1, runtime.GOMAXPROCS(0)))
	}
	if options.UploadConcurrency < 1 || options.DownloadConcurrency < 1 {
		return nil, errors.New("xet: transfer concurrency must be positive")
	}
	if options.MaxDownloadMemory == 0 {
		options.MaxDownloadMemory = uint64(options.DownloadConcurrency) * xorb.MaxRawSize
	}
	if options.MaxDownloadMemory < xorb.MaxRawSize {
		return nil, errors.New("xet: maximum download memory must permit at least one xorb")
	}
	return &Client{protocol: protocol, options: options}, nil
}

// FileInfo is hosting-independent Xet metadata for one logical file.
type FileInfo struct {
	Hash   xethash.Hash
	Size   uint64
	SHA256 [32]byte
}

// DedupReport accounts for chunks and bytes before protocol compression.
type DedupReport struct {
	TotalChunks        uint64
	TotalBytes         uint64
	NewChunks          uint64
	NewBytes           uint64
	SessionDedupChunks uint64
	SessionDedupBytes  uint64
	GlobalDedupChunks  uint64
	GlobalDedupBytes   uint64
}

// UploadReport describes the completed CAS transaction. ShardUploaded is true
// only after CAS has registered all reconstruction metadata.
type UploadReport struct {
	Files               int
	Xorbs               int
	SerializedXorbBytes uint64
	InsertedXorbs       int
	ShardBytes          uint64
	ShardUploaded       bool
	Dedup               DedupReport
	StartedAt           time.Time
	CompletedAt         time.Time
}

type UploadResult struct {
	File   FileInfo
	Report UploadReport
}

// Upload ingests one reader, uploads all xorbs, then registers the file by
// uploading its shard. It returns only after the file is reconstructable.
func (c *Client) Upload(ctx context.Context, source io.Reader) (UploadResult, error) {
	batch, err := c.NewUploadBatch(ctx)
	if err != nil {
		return UploadResult{}, err
	}
	info, err := batch.Add(source)
	if err != nil {
		batch.Abort(err)
		return UploadResult{}, err
	}
	report, err := batch.Finalize()
	if err != nil {
		return UploadResult{}, err
	}
	return UploadResult{File: info, Report: report}, nil
}
