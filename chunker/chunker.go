// Package chunker implements Xet's streaming GearHash content-defined
// chunking.
package chunker

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math/bits"
)

const (
	TargetSize = 64 << 10
	MinSize    = TargetSize / 8
	MaxSize    = TargetSize * 2
	Mask       = uint64(0xffff000000000000)

	defaultReadBufferSize = 256 << 10
)

// Config controls a chunking stream. The zero value selects the Xet protocol
// constants. Custom configurations are useful for tests and specialized local
// partitioning, but content identities use DefaultConfig.
type Config struct {
	TargetSize     int
	MinSize        int
	MaxSize        int
	ReadBufferSize int
}

var DefaultConfig = Config{
	TargetSize:     TargetSize,
	MinSize:        MinSize,
	MaxSize:        MaxSize,
	ReadBufferSize: defaultReadBufferSize,
}

// Chunk is one independently owned logical byte range.
type Chunk struct {
	Offset int64
	Data   []byte
}

func (c Chunk) End() int64 { return c.Offset + int64(len(c.Data)) }

// Split emits chunks in order. Emitted Data remains owned by the recipient and
// is never reused by Split.
func Split(r io.Reader, emit func(Chunk) error) error {
	return SplitContext(context.Background(), r, DefaultConfig, emit)
}

// SplitContext is Split with cancellation and explicit limits.
func SplitContext(ctx context.Context, r io.Reader, cfg Config, emit func(Chunk) error) error {
	if r == nil {
		return errors.New("chunker: nil reader")
	}
	if emit == nil {
		return errors.New("chunker: nil emitter")
	}
	writer, err := NewWriter(ctx, cfg, emit)
	if err != nil {
		return err
	}
	readBuf := make([]byte, writer.cfg.ReadBufferSize)

	emptyReads := 0
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		n, readErr := r.Read(readBuf)
		if n < 0 || n > len(readBuf) {
			return fmt.Errorf("chunker: reader returned invalid count %d", n)
		}
		if n == 0 && readErr == nil {
			emptyReads++
			if emptyReads >= 100 {
				return io.ErrNoProgress
			}
		} else {
			emptyReads = 0
		}

		if n != 0 {
			if _, err := writer.Write(readBuf[:n]); err != nil {
				return err
			}
		}

		if readErr != nil {
			if !errors.Is(readErr, io.EOF) {
				return readErr
			}
			return writer.Close()
		}
	}
}

// Writer incrementally applies Xet content-defined chunking to successive
// writes. Write boundaries never affect emitted chunks. Close emits the final
// short chunk, if any, and must be called exactly once.
type Writer struct {
	ctx      context.Context
	cfg      Config
	mask     uint64
	emit     func(Chunk) error
	chunkBuf []byte
	state    uint64
	offset   int64
	closed   bool
	err      error
}

// NewWriter constructs an incremental chunker. The caller retains ownership
// of input slices; emitted Chunk.Data is independently owned.
func NewWriter(ctx context.Context, cfg Config, emit func(Chunk) error) (*Writer, error) {
	if ctx == nil {
		return nil, errors.New("chunker: nil context")
	}
	if emit == nil {
		return nil, errors.New("chunker: nil emitter")
	}
	cfg, mask, err := normalize(cfg)
	if err != nil {
		return nil, err
	}
	return &Writer{
		ctx: ctx, cfg: cfg, mask: mask, emit: emit,
		chunkBuf: make([]byte, 0, cfg.MaxSize),
	}, nil
}

func (w *Writer) Write(data []byte) (int, error) {
	if w.closed {
		return 0, errors.New("chunker: write after close")
	}
	if w.err != nil {
		return 0, w.err
	}
	for i, value := range data {
		if i&0x3fff == 0 {
			if err := w.ctx.Err(); err != nil {
				w.err = err
				return i, err
			}
		}
		w.state = (w.state << 1) + gearTable[value]
		w.chunkBuf = append(w.chunkBuf, value)
		if len(w.chunkBuf) == w.cfg.MaxSize ||
			(len(w.chunkBuf) >= w.cfg.MinSize && w.state&w.mask == 0) {
			if err := w.emitChunk(); err != nil {
				w.err = err
				return i + 1, err
			}
		}
	}
	return len(data), nil
}

func (w *Writer) Close() error {
	if w.closed {
		return errors.New("chunker: close after close")
	}
	w.closed = true
	if w.err != nil {
		return w.err
	}
	if err := w.ctx.Err(); err != nil {
		return err
	}
	return w.emitChunk()
}

func (w *Writer) emitChunk() error {
	if len(w.chunkBuf) == 0 {
		return nil
	}
	data := w.chunkBuf
	if err := w.emit(Chunk{Offset: w.offset, Data: data}); err != nil {
		return err
	}
	w.offset += int64(len(data))
	w.chunkBuf = make([]byte, 0, w.cfg.MaxSize)
	w.state = 0
	return nil
}

// Bytes chunks an in-memory value and returns independently owned chunks.
func Bytes(data []byte) []Chunk {
	chunks := make([]Chunk, 0, len(data)/TargetSize+1)
	r := bytesReader(data)
	_ = Split(&r, func(c Chunk) error {
		chunks = append(chunks, c)
		return nil
	})
	return chunks
}

type bytesReader []byte

func (r *bytesReader) Read(p []byte) (int, error) {
	if len(*r) == 0 {
		return 0, io.EOF
	}
	n := copy(p, *r)
	*r = (*r)[n:]
	return n, nil
}

func normalize(cfg Config) (Config, uint64, error) {
	if cfg.TargetSize == 0 {
		cfg.TargetSize = TargetSize
	}
	if cfg.TargetSize <= 64 || cfg.TargetSize&(cfg.TargetSize-1) != 0 {
		return Config{}, 0, fmt.Errorf("chunker: target size %d must be a power of two greater than 64", cfg.TargetSize)
	}
	if cfg.MinSize == 0 {
		cfg.MinSize = cfg.TargetSize / 8
	}
	if cfg.MaxSize == 0 {
		if cfg.TargetSize > int(^uint(0)>>1)/2 {
			return Config{}, 0, errors.New("chunker: maximum size overflows int")
		}
		cfg.MaxSize = cfg.TargetSize * 2
	}
	if cfg.MinSize < 1 || cfg.MaxSize <= cfg.MinSize {
		return Config{}, 0, fmt.Errorf("chunker: invalid size range [%d,%d]", cfg.MinSize, cfg.MaxSize)
	}
	if cfg.ReadBufferSize == 0 {
		cfg.ReadBufferSize = defaultReadBufferSize
	}
	if cfg.ReadBufferSize < 1 {
		return Config{}, 0, errors.New("chunker: read buffer size must be positive")
	}
	baseMask := uint64(cfg.TargetSize - 1)
	mask := baseMask << bits.LeadingZeros64(baseMask)
	return cfg, mask, nil
}

// NextStableBoundary returns the first boundary satisfying Xet's two-chunk
// delta-restart stability rule. Boundaries are absolute offsets and normally
// include zero.
func NextStableBoundary(start int, boundaries []int) (int, bool) {
	i := 0
	for i < len(boundaries) && boundaries[i] < start {
		i++
	}
	for ; i+2 < len(boundaries); i++ {
		a := boundaries[i+1] - boundaries[i]
		b := boundaries[i+2] - boundaries[i+1]
		if IsStableSize(a) && IsStableSize(b) {
			return boundaries[i+2], true
		}
	}
	return 0, false
}

func IsStableSize(size int) bool {
	return size >= 2*MinSize && size < MaxSize-MinSize
}
