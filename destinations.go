package xet

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"math"
	"os"
	"path/filepath"

	"github.com/jacobwoliver/xet-go/xetcas"
	"github.com/jacobwoliver/xet-go/xethash"
)

// DownloadAt reconstructs a complete file into dst starting at offset zero.
// WriterAt lets callers target files and block devices without changing a
// shared seek position. The file's Xet identity and optional SHA-256 are
// verified exactly as in Download.
func (c *Client) DownloadAt(ctx context.Context, file FileInfo, dst io.WriterAt) (DownloadReport, error) {
	if dst == nil {
		return DownloadReport{}, errors.New("xet: nil random-access download writer")
	}
	return c.Download(ctx, file, &sequentialWriterAt{dst: dst})
}

// DownloadRangeAt writes logical [Start,End) at destinationOffset. The
// destination offset is independent of the logical file offset.
func (c *Client) DownloadRangeAt(
	ctx context.Context,
	fileID xethash.Hash,
	requested xetcas.FileRange,
	dst io.WriterAt,
	destinationOffset int64,
) (DownloadReport, error) {
	if dst == nil {
		return DownloadReport{}, errors.New("xet: nil random-access download writer")
	}
	if destinationOffset < 0 {
		return DownloadReport{}, errors.New("xet: negative destination offset")
	}
	if err := requested.Validate(); err != nil {
		return DownloadReport{}, err
	}
	return c.download(ctx, FileInfo{Hash: fileID}, &requested, &sequentialWriterAt{dst: dst, offset: destinationOffset})
}

type sequentialWriterAt struct {
	dst    io.WriterAt
	offset int64
}

func (w *sequentialWriterAt) Write(data []byte) (int, error) {
	if int64(len(data)) > math.MaxInt64-w.offset {
		return 0, errors.New("xet: destination offset overflow")
	}
	n, err := w.dst.WriteAt(data, w.offset)
	w.offset += int64(n)
	if err == nil && n != len(data) {
		err = io.ErrShortWrite
	}
	return n, err
}

// DownloadFileOptions controls atomic filesystem completion. Mode defaults to
// 0666 (subject to the process umask). Sync defaults to true; set NoSync only
// when durability across an immediate system crash is not required.
type DownloadFileOptions struct {
	Mode   fs.FileMode
	NoSync bool
}

// DownloadFile reconstructs into a same-directory temporary file and renames
// it over path only after all integrity checks succeed. Caller-visible partial
// files are never left at path.
func (c *Client) DownloadFile(
	ctx context.Context,
	file FileInfo,
	path string,
	options DownloadFileOptions,
) (DownloadReport, error) {
	if path == "" {
		return DownloadReport{}, errors.New("xet: empty download path")
	}
	mode := options.Mode
	if mode == 0 {
		mode = 0o666
	}
	if mode&fs.ModeType != 0 {
		return DownloadReport{}, errors.New("xet: download mode must describe a regular file")
	}
	directory := filepath.Dir(path)
	base := filepath.Base(path)
	temporary, err := os.CreateTemp(directory, "."+base+".xet-*")
	if err != nil {
		return DownloadReport{}, fmt.Errorf("xet: create temporary download: %w", err)
	}
	temporaryPath := temporary.Name()
	completed := false
	defer func() {
		if !completed {
			_ = temporary.Close()
			_ = os.Remove(temporaryPath)
		}
	}()
	if err := temporary.Chmod(mode); err != nil {
		return DownloadReport{}, fmt.Errorf("xet: set temporary download mode: %w", err)
	}
	if file.Size > math.MaxInt64 {
		return DownloadReport{}, errors.New("xet: file size exceeds local filesystem offset range")
	}
	if file.Size != 0 {
		if err := temporary.Truncate(int64(file.Size)); err != nil {
			return DownloadReport{}, fmt.Errorf("xet: size temporary download: %w", err)
		}
	}
	report, err := c.DownloadAt(ctx, file, temporary)
	if err != nil {
		return report, err
	}
	if !options.NoSync {
		if err := temporary.Sync(); err != nil {
			return report, fmt.Errorf("xet: sync temporary download: %w", err)
		}
	}
	if err := temporary.Close(); err != nil {
		return report, fmt.Errorf("xet: close temporary download: %w", err)
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return report, fmt.Errorf("xet: publish completed download: %w", err)
	}
	completed = true
	if !options.NoSync {
		dir, openErr := os.Open(directory)
		if openErr == nil {
			syncErr := dir.Sync()
			closeErr := dir.Close()
			if syncErr != nil {
				return report, fmt.Errorf("xet: sync download directory: %w", syncErr)
			}
			if closeErr != nil {
				return report, fmt.Errorf("xet: close download directory: %w", closeErr)
			}
		}
	}
	return report, nil
}
