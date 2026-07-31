package xet

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/jacobwoliver/xet-go/chunker"
	"github.com/jacobwoliver/xet-go/shard"
	"github.com/jacobwoliver/xet-go/xethash"
	"github.com/jacobwoliver/xet-go/xorb"
)

var (
	ErrBatchFinalized = errors.New("xet: upload batch is already finalized")
	ErrBatchFailed    = errors.New("xet: upload batch has failed")
)

type pendingXorb struct {
	chunks         [][]byte
	rawBytes       int
	fileBoundaries []int
	lastFile       uint64
	hash           xethash.Hash
	finalized      bool
}

type placement struct {
	pending *pendingXorb
	index   uint32
	length  uint32
}

func (p placement) xorbHash() (xethash.Hash, error) {
	if p.pending == nil || !p.pending.finalized {
		return xethash.Hash{}, errors.New("xet: unresolved xorb placement")
	}
	return p.pending.hash, nil
}

type uploadedFile struct {
	info       FileInfo
	chunkNodes []xethash.Node
	placements []placement
}

type xorbUploadTask struct {
	object *xorb.Object
}

// UploadBatch shares xorb packing and session deduplication across files. Add
// returns deterministic metadata early, but files are not reconstructable
// until Finalize succeeds. Add and Finalize are intentionally serialized.
type UploadBatch struct {
	client *Client
	ctx    context.Context
	cancel context.CancelFunc

	mu         sync.Mutex
	finalized  bool
	fileSerial uint64
	files      []uploadedFile
	current    *pendingXorb
	locations  map[xethash.Hash]placement
	xorbs      []shard.Xorb
	tasks      chan xorbUploadTask
	workers    sync.WaitGroup

	errMu sync.Mutex
	err   error

	reportMu sync.Mutex
	report   UploadReport
}

func (c *Client) NewUploadBatch(ctx context.Context) (*UploadBatch, error) {
	if ctx == nil {
		return nil, errors.New("xet: nil upload context")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	batchContext, cancel := context.WithCancel(ctx)
	b := &UploadBatch{
		client:    c,
		ctx:       batchContext,
		cancel:    cancel,
		current:   &pendingXorb{},
		locations: make(map[xethash.Hash]placement),
		tasks:     make(chan xorbUploadTask, c.options.UploadConcurrency),
		report:    UploadReport{StartedAt: time.Now()},
	}
	for range c.options.UploadConcurrency {
		b.workers.Add(1)
		go b.uploadWorker()
	}
	return b, nil
}

// Add consumes one file reader. It may upload completed xorbs in the
// background but does not upload reconstruction metadata.
func (b *UploadBatch) Add(source io.Reader) (FileInfo, error) {
	if source == nil {
		return FileInfo{}, errors.New("xet: nil upload reader")
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.finalized {
		return FileInfo{}, ErrBatchFinalized
	}
	if err := b.failure(); err != nil {
		return FileInfo{}, fmt.Errorf("%w: %v", ErrBatchFailed, err)
	}
	b.fileSerial++
	fileSerial := b.fileSerial
	sha := sha256.New()
	file := uploadedFile{}
	reader := io.TeeReader(source, sha)
	err := chunker.SplitContext(b.ctx, reader, chunker.DefaultConfig, func(value chunker.Chunk) error {
		if err := b.failure(); err != nil {
			return err
		}
		hash := xethash.Chunk(value.Data)
		node := xethash.Node{Hash: hash, Size: uint64(len(value.Data))}
		file.chunkNodes = append(file.chunkNodes, node)
		b.report.Dedup.TotalChunks++
		b.report.Dedup.TotalBytes += uint64(len(value.Data))
		if existing, ok := b.locations[hash]; ok {
			file.placements = append(file.placements, existing)
			b.report.Dedup.SessionDedupChunks++
			b.report.Dedup.SessionDedupBytes += uint64(len(value.Data))
		} else {
			placement, err := b.addNovelChunk(value.Data, fileSerial)
			if err != nil {
				return err
			}
			b.locations[hash] = placement
			file.placements = append(file.placements, placement)
			b.report.Dedup.NewChunks++
			b.report.Dedup.NewBytes += uint64(len(value.Data))
		}
		if b.client.options.Progress != nil {
			b.client.options.Progress(Progress{Phase: ProgressChunking, Completed: uint64(value.End())})
		}
		return nil
	})
	if err != nil {
		b.setFailure(err)
		b.finalized = true
		close(b.tasks)
		return FileInfo{}, err
	}
	file.info.Hash = xethash.File(file.chunkNodes)
	for _, node := range file.chunkNodes {
		file.info.Size += node.Size
	}
	copy(file.info.SHA256[:], sha.Sum(nil))
	b.files = append(b.files, file)
	b.report.Files = len(b.files)
	return file.info, nil
}

// Abort cancels a batch and releases its workers without registering a shard.
// It is safe to call after an Add error and is required when abandoning an
// otherwise live batch without Finalize.
func (b *UploadBatch) Abort(cause error) {
	if cause == nil {
		cause = context.Canceled
	}
	b.mu.Lock()
	if !b.finalized {
		b.finalized = true
		b.setFailure(cause)
		close(b.tasks)
	}
	b.mu.Unlock()
}

func (b *UploadBatch) addNovelChunk(data []byte, fileSerial uint64) (placement, error) {
	if len(data) == 0 || len(data) > chunker.MaxSize {
		return placement{}, fmt.Errorf("xet: chunk length %d outside protocol bounds", len(data))
	}
	if b.current.rawBytes+len(data) > xorb.MaxRawSize || len(b.current.chunks) == xorb.MaxChunks {
		if err := b.flushCurrent(); err != nil {
			return placement{}, err
		}
	}
	if len(b.current.chunks) == 0 {
		b.current.fileBoundaries = []int{0}
		b.current.lastFile = fileSerial
	} else if b.current.lastFile != fileSerial {
		b.current.fileBoundaries = append(b.current.fileBoundaries, len(b.current.chunks))
		b.current.lastFile = fileSerial
	}
	index := len(b.current.chunks)
	b.current.chunks = append(b.current.chunks, data)
	b.current.rawBytes += len(data)
	return placement{pending: b.current, index: uint32(index), length: uint32(len(data))}, nil
}

func (b *UploadBatch) flushCurrent() error {
	if len(b.current.chunks) == 0 {
		return nil
	}
	pending := b.current
	object, err := xorb.EncodeProduction(pending.chunks, xorb.EncodeOptions{
		Scheme:         b.client.options.Compression,
		FileBoundaries: pending.fileBoundaries,
		RetestInterval: b.client.options.CompressionRetestInterval,
	})
	if err != nil {
		return err
	}
	pending.hash = object.Hash
	pending.finalized = true
	metadata, err := shard.XorbFromObject(object)
	if err != nil {
		return err
	}
	b.xorbs = append(b.xorbs, metadata)
	for i := range object.Chunks {
		object.Chunks[i].Data = nil
	}
	b.current = &pendingXorb{}
	select {
	case <-b.ctx.Done():
		if err := b.failure(); err != nil {
			return err
		}
		return b.ctx.Err()
	case b.tasks <- xorbUploadTask{object: object}:
		return nil
	}
}

func (b *UploadBatch) uploadWorker() {
	defer b.workers.Done()
	for task := range b.tasks {
		if b.ctx.Err() != nil {
			continue
		}
		inserted, err := b.client.protocol.UploadXorb(b.ctx, b.client.options.Prefix, task.object.Hash, task.object.Body)
		if err != nil {
			b.setFailure(err)
			continue
		}
		b.reportMu.Lock()
		b.report.Xorbs++
		b.report.SerializedXorbBytes += uint64(len(task.object.Body))
		if inserted {
			b.report.InsertedXorbs++
		}
		completed := b.report.SerializedXorbBytes
		b.reportMu.Unlock()
		if b.client.options.Progress != nil {
			b.client.options.Progress(Progress{Phase: ProgressUploadingXorb, File: task.object.Hash, Completed: completed})
		}
	}
}

// Finalize uploads the last xorb, waits for every xorb to succeed, and only
// then uploads the footerless shard. It may be called exactly once.
func (b *UploadBatch) Finalize() (UploadReport, error) {
	b.mu.Lock()
	if b.finalized {
		b.mu.Unlock()
		return UploadReport{}, ErrBatchFinalized
	}
	b.finalized = true
	flushErr := b.flushCurrent()
	close(b.tasks)
	b.mu.Unlock()
	b.workers.Wait()
	if flushErr != nil {
		b.setFailure(flushErr)
	}
	if err := b.failure(); err != nil {
		b.cancel()
		return UploadReport{}, fmt.Errorf("%w: %v", ErrBatchFailed, err)
	}

	files := make([]shard.File, 0, len(b.files))
	seenFiles := make(map[xethash.Hash]struct{}, len(b.files))
	for i := range b.files {
		if _, duplicate := seenFiles[b.files[i].info.Hash]; duplicate {
			continue
		}
		file, err := buildShardFile(b.files[i])
		if err != nil {
			b.cancel()
			return UploadReport{}, err
		}
		seenFiles[file.Hash] = struct{}{}
		files = append(files, file)
	}
	shardBody, err := shard.EncodeUpload(shard.Shard{Files: files, Xorbs: b.xorbs})
	if err != nil {
		b.cancel()
		return UploadReport{}, err
	}
	if b.client.options.Progress != nil {
		b.client.options.Progress(Progress{Phase: ProgressUploadingShard, Total: uint64(len(shardBody))})
	}
	if err := b.client.protocol.UploadShard(b.ctx, shardBody, nil); err != nil {
		b.cancel()
		return UploadReport{}, err
	}
	b.reportMu.Lock()
	b.report.ShardBytes = uint64(len(shardBody))
	b.report.ShardUploaded = true
	b.report.CompletedAt = time.Now()
	report := b.report
	b.reportMu.Unlock()
	b.cancel()
	return report, nil
}

func buildShardFile(file uploadedFile) (shard.File, error) {
	if len(file.chunkNodes) != len(file.placements) {
		return shard.File{}, errors.New("xet: file chunk and placement counts differ")
	}
	result := shard.File{Hash: file.info.Hash}
	shaValue := file.info.SHA256
	result.SHA256 = &shaValue
	for start := 0; start < len(file.placements); {
		xorbHash, err := file.placements[start].xorbHash()
		if err != nil {
			return shard.File{}, err
		}
		end := start + 1
		lastIndex := file.placements[start].index
		rawBytes := uint64(file.placements[start].length)
		for end < len(file.placements) {
			nextHash, err := file.placements[end].xorbHash()
			if err != nil {
				return shard.File{}, err
			}
			if nextHash != xorbHash || file.placements[end].index != lastIndex+1 {
				break
			}
			lastIndex++
			rawBytes += uint64(file.placements[end].length)
			end++
		}
		if rawBytes > uint64(^uint32(0)) {
			return shard.File{}, errors.New("xet: reconstruction term raw length exceeds uint32")
		}
		hashes := make([]xethash.Hash, end-start)
		for i := start; i < end; i++ {
			hashes[i-start] = file.chunkNodes[i].Hash
		}
		result.Terms = append(result.Terms, shard.Term{
			XorbHash:      xorbHash,
			UnpackedBytes: uint32(rawBytes),
			Start:         file.placements[start].index,
			End:           lastIndex + 1,
			Verification:  xethash.Verification(hashes),
		})
		start = end
	}
	return result, nil
}

func (b *UploadBatch) setFailure(err error) {
	if err == nil {
		return
	}
	b.errMu.Lock()
	if b.err == nil {
		b.err = err
		b.cancel()
	}
	b.errMu.Unlock()
}

func (b *UploadBatch) failure() error {
	b.errMu.Lock()
	defer b.errMu.Unlock()
	return b.err
}
