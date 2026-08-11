package verified

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"hash"
	"io"
	"sync"

	"github.com/jmwoliver/xet-go/content"
)

// New wraps one already length-bounded backend reader. Full reads additionally
// verify the whole-file SHA-256. Closing the result unblocks an in-flight read
// when the underlying reader honors concurrent Close.
func New(ctx context.Context, body io.ReadCloser, blob content.Blob, size int64, full bool) io.ReadCloser {
	reader := &reader{ctx: ctx, body: body, blob: blob, remaining: size, done: make(chan struct{})}
	if full {
		reader.digest = sha256.New()
	}
	go func() {
		select {
		case <-ctx.Done():
			_ = reader.closeBody()
		case <-reader.done:
		}
	}()
	return reader
}

type reader struct {
	ctx       context.Context
	body      io.ReadCloser
	blob      content.Blob
	remaining int64
	digest    hash.Hash
	settled   bool
	done      chan struct{}
	closeOnce sync.Once
	closeErr  error
}

func (r *reader) Read(buffer []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	if r.settled {
		return 0, io.EOF
	}
	if len(buffer) == 0 {
		return 0, nil
	}
	if int64(len(buffer)) > r.remaining {
		buffer = buffer[:r.remaining]
	}
	n, err := r.body.Read(buffer)
	if n < 0 || n > len(buffer) {
		r.settled = true
		return 0, fmt.Errorf("%w: backend returned an invalid byte count", content.ErrCorrupt)
	}
	if n > 0 {
		r.remaining -= int64(n)
		if r.digest != nil {
			_, _ = r.digest.Write(buffer[:n])
		}
	}
	if contextErr := r.ctx.Err(); contextErr != nil {
		return n, contextErr
	}
	if r.remaining == 0 {
		if err != nil && !errors.Is(err, io.EOF) {
			r.settled = true
			return n, err
		}
		if err == nil {
			if probeErr := r.expectEOF(); probeErr != nil {
				r.settled = true
				return n, probeErr
			}
		}
		r.settled = true
		if r.digest != nil && !equal(r.digest.Sum(nil), r.blob.SHA256[:]) {
			return n, fmt.Errorf("%w: SHA-256 mismatch", content.ErrCorrupt)
		}
		return n, io.EOF
	}
	if errors.Is(err, io.EOF) {
		r.settled = true
		return n, fmt.Errorf("%w: stream ended with %d bytes missing", content.ErrCorrupt, r.remaining)
	}
	return n, err
}

func (r *reader) expectEOF() error {
	var probe [1]byte
	for attempts := 0; attempts < 100; attempts++ {
		n, err := r.body.Read(probe[:])
		if contextErr := r.ctx.Err(); contextErr != nil {
			return contextErr
		}
		if n != 0 {
			return fmt.Errorf("%w: stream exceeds declared length", content.ErrCorrupt)
		}
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
	}
	return io.ErrNoProgress
}

func (r *reader) Close() error { return r.closeBody() }

func (r *reader) closeBody() error {
	r.closeOnce.Do(func() {
		close(r.done)
		r.closeErr = r.body.Close()
	})
	return r.closeErr
}

func equal(left, right []byte) bool {
	if len(left) != len(right) {
		return false
	}
	var difference byte
	for index := range left {
		difference |= left[index] ^ right[index]
	}
	return difference == 0
}

// Write copies exactly blob.Size bytes from source to destination and verifies
// SHA-256 before returning. A non-EOF source error is never hidden merely
// because it arrived with the final declared bytes.
func Write(ctx context.Context, destination io.Writer, source io.Reader, blob content.Blob) error {
	if ctx == nil || destination == nil || source == nil {
		return fmt.Errorf("%w: nil write argument", content.ErrInvalid)
	}
	if err := blob.Validate(); err != nil {
		return err
	}
	digest := sha256.New()
	buffer := make([]byte, 64*1024)
	remaining := blob.Size
	noProgress := 0
	for remaining > 0 {
		if err := ctx.Err(); err != nil {
			return err
		}
		wanted := int64(len(buffer))
		if wanted > remaining {
			wanted = remaining
		}
		n, readErr := source.Read(buffer[:wanted])
		if n < 0 || int64(n) > wanted {
			return fmt.Errorf("%w: source returned an invalid byte count", content.ErrCorrupt)
		}
		if n > 0 {
			noProgress = 0
			written, writeErr := destination.Write(buffer[:n])
			if written < 0 || written > n {
				return io.ErrShortWrite
			}
			if written > 0 {
				_, _ = digest.Write(buffer[:written])
			}
			if writeErr != nil {
				return writeErr
			}
			if written != n {
				return io.ErrShortWrite
			}
			remaining -= int64(n)
		} else {
			noProgress++
			if noProgress >= 100 && readErr == nil {
				return io.ErrNoProgress
			}
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if readErr != nil {
			if !errors.Is(readErr, io.EOF) {
				return readErr
			}
			if remaining != 0 {
				return fmt.Errorf("%w: body ended with %d bytes missing", content.ErrCorrupt, remaining)
			}
			return verifyDigest(digest, blob)
		}
	}
	if err := expectSourceEOF(ctx, source); err != nil {
		return err
	}
	return verifyDigest(digest, blob)
}

func expectSourceEOF(ctx context.Context, source io.Reader) error {
	var probe [1]byte
	for attempts := 0; attempts < 100; attempts++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		n, err := source.Read(probe[:])
		if n < 0 || n > len(probe) {
			return fmt.Errorf("%w: source returned an invalid byte count", content.ErrCorrupt)
		}
		if contextErr := ctx.Err(); contextErr != nil {
			return contextErr
		}
		if n != 0 {
			return fmt.Errorf("%w: body exceeds declared size", content.ErrCorrupt)
		}
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
	}
	return io.ErrNoProgress
}

func verifyDigest(digest hash.Hash, blob content.Blob) error {
	if !equal(digest.Sum(nil), blob.SHA256[:]) {
		return fmt.Errorf("%w: SHA-256 mismatch", content.ErrCorrupt)
	}
	return nil
}
