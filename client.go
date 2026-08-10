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
	// XorbPrefix selects the xorb upload/existence namespace. The zero value
	// selects xetcas.DefaultXorbPrefix.
	XorbPrefix string
	// DedupPrefix selects the global chunk-deduplication namespace. The zero
	// value selects xetcas.DefaultDedupPrefix.
	DedupPrefix string
	// Prefix is the former combined namespace option. It remains an alias for
	// XorbPrefix only; global deduplication always uses DedupPrefix.
	//
	// Deprecated: use XorbPrefix.
	Prefix      string
	Compression xorb.Scheme
	// CompressionSet distinguishes explicit None (whose numeric value is zero)
	// from the zero Options value, which selects Auto.
	CompressionSet            bool
	CompressionRetestInterval int
	UploadConcurrency         int
	DownloadConcurrency       int
	MaxDownloadMemory         uint64
	MaxReconstructionWindow   uint64
	GlobalDedup               bool
	UploadJournal             UploadJournal
	// DefragWindow is the number of recent reconstruction ranges used to
	// estimate fragmentation. The zero value selects the Rust default of 128.
	DefragWindow int
	// MinChunksPerRange and DefragHysteresis select the same rolling
	// defragmentation thresholds as xet-core. Zero values select 8 and 0.5.
	MinChunksPerRange float64
	DefragHysteresis  float64
	Cache             Cache
	Progress          func(Progress)
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
	if options.Prefix != "" {
		if options.XorbPrefix != "" && options.XorbPrefix != options.Prefix {
			return nil, errors.New("xet: conflicting Prefix and XorbPrefix options")
		}
		options.XorbPrefix = options.Prefix
	}
	if options.XorbPrefix == "" {
		options.XorbPrefix = xetcas.DefaultXorbPrefix
	}
	if options.DedupPrefix == "" {
		options.DedupPrefix = xetcas.DefaultDedupPrefix
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
	if options.MaxReconstructionWindow == 0 {
		options.MaxReconstructionWindow = 10 << 30
	}
	if options.DefragWindow == 0 {
		options.DefragWindow = 128
	}
	if options.MinChunksPerRange == 0 {
		options.MinChunksPerRange = 8
	}
	if options.DefragHysteresis == 0 {
		options.DefragHysteresis = 0.5
	}
	if options.DefragWindow < 1 || options.MinChunksPerRange < 1 ||
		options.DefragHysteresis <= 0 || options.DefragHysteresis > 1 {
		return nil, errors.New("xet: invalid defragmentation policy")
	}
	return &Client{protocol: protocol, options: options}, nil
}

// FileInfo is hosting-independent Xet metadata for one logical file.
type FileInfo struct {
	Hash xethash.Hash
	// Size is always present. Zero denotes an empty file, not an unknown size.
	Size uint64
	// SHA256 is nil only when the source metadata did not include a digest.
	// Uploads always return a non-nil value, including an all-zero digest.
	SHA256 *[32]byte
}

// Equal reports whether two file records carry the same identities and size.
// SHA256 pointers are compared by value, including nil presence.
func (f FileInfo) Equal(other FileInfo) bool {
	if f.Hash != other.Hash || f.Size != other.Size || (f.SHA256 == nil) != (other.SHA256 == nil) {
		return false
	}
	return f.SHA256 == nil || *f.SHA256 == *other.SHA256
}

func cloneFileInfo(info FileInfo) FileInfo {
	if info.SHA256 != nil {
		sum := *info.SHA256
		info.SHA256 = &sum
	}
	return info
}

// DedupReport accounts for chunks and bytes before protocol compression.
type DedupReport struct {
	TotalChunks         uint64
	TotalBytes          uint64
	NewChunks           uint64
	NewBytes            uint64
	SessionDedupChunks  uint64
	SessionDedupBytes   uint64
	GlobalDedupChunks   uint64
	GlobalDedupBytes    uint64
	DefragSkippedChunks uint64
	DefragSkippedBytes  uint64
}

// UploadReport describes the completed CAS transaction. ShardUploaded is true
// only after CAS has registered all reconstruction metadata.
type UploadReport struct {
	Files               int
	Xorbs               int
	SerializedXorbBytes uint64
	InsertedXorbs       int
	ResumedXorbs        int
	ShardBytes          uint64
	ShardUploaded       bool
	JournalCleared      bool
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
