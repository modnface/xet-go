package xet

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
)

// UploadSource describes one caller-owned input. Exactly one of Path, Reader,
// or ReaderAt must be set. ReaderAt requires a non-negative Size. For Reader,
// Size -1 means unknown; every other value is verified after ingestion.
type UploadSource struct {
	Path     string
	Reader   io.Reader
	ReaderAt io.ReaderAt
	Size     int64
	SHA256   *[32]byte
}

// BatchUploadResult contains the metadata for every input in source order and
// the shared upload report. No file is registered until the batch finalizes.
type BatchUploadResult struct {
	Files  []FileInfo
	Report UploadReport
}

// AddSource ingests one path, reader, or random-access source into the batch.
// Caller-owned readers are never closed. A file opened from Path is closed by
// this method.
func (b *UploadBatch) AddSource(source UploadSource) (FileInfo, error) {
	reader, closeInput, expectedSize, err := openUploadSource(source)
	if err != nil {
		return FileInfo{}, err
	}
	info, addErr := b.Add(reader)
	closeErr := error(nil)
	if closeInput != nil {
		closeErr = closeInput()
	}
	if addErr != nil {
		return FileInfo{}, addErr
	}
	if closeErr != nil {
		b.setFailure(closeErr)
		return FileInfo{}, fmt.Errorf("xet: close upload source: %w", closeErr)
	}
	if expectedSize >= 0 && info.Size != uint64(expectedSize) {
		err := fmt.Errorf("xet: upload source size %d, expected %d", info.Size, expectedSize)
		b.setFailure(err)
		return FileInfo{}, err
	}
	if source.SHA256 != nil && info.SHA256 != *source.SHA256 {
		err := errors.New("xet: upload source SHA-256 mismatch")
		b.setFailure(err)
		return FileInfo{}, err
	}
	return info, nil
}

func openUploadSource(source UploadSource) (io.Reader, func() error, int64, error) {
	selected := 0
	if source.Path != "" {
		selected++
	}
	if source.Reader != nil {
		selected++
	}
	if source.ReaderAt != nil {
		selected++
	}
	if selected != 1 {
		return nil, nil, 0, errors.New("xet: upload source must set exactly one of Path, Reader, or ReaderAt")
	}
	if source.Path != "" {
		file, err := os.Open(source.Path)
		if err != nil {
			return nil, nil, 0, fmt.Errorf("xet: open upload source: %w", err)
		}
		info, err := file.Stat()
		if err != nil {
			_ = file.Close()
			return nil, nil, 0, fmt.Errorf("xet: stat upload source: %w", err)
		}
		if !info.Mode().IsRegular() {
			_ = file.Close()
			return nil, nil, 0, errors.New("xet: upload path is not a regular file")
		}
		if source.Size >= 0 && source.Size != info.Size() {
			_ = file.Close()
			return nil, nil, 0, fmt.Errorf("xet: upload path size %d, expected %d", info.Size(), source.Size)
		}
		return file, file.Close, info.Size(), nil
	}
	if source.ReaderAt != nil {
		if source.Size < 0 {
			return nil, nil, 0, errors.New("xet: ReaderAt upload source requires a non-negative Size")
		}
		return io.NewSectionReader(source.ReaderAt, 0, source.Size), nil, source.Size, nil
	}
	if source.Size < -1 {
		return nil, nil, 0, errors.New("xet: upload source Size must be -1 or non-negative")
	}
	return source.Reader, nil, source.Size, nil
}

// UploadSources uploads several inputs in one deduplicating and xorb-packing
// batch. Results preserve source order.
func (c *Client) UploadSources(ctx context.Context, sources []UploadSource) (BatchUploadResult, error) {
	if len(sources) == 0 {
		return BatchUploadResult{}, errors.New("xet: no upload sources")
	}
	batch, err := c.NewUploadBatch(ctx)
	if err != nil {
		return BatchUploadResult{}, err
	}
	result := BatchUploadResult{Files: make([]FileInfo, 0, len(sources))}
	for i, source := range sources {
		info, err := batch.AddSource(source)
		if err != nil {
			batch.Abort(err)
			return BatchUploadResult{}, fmt.Errorf("xet: upload source %d: %w", i, err)
		}
		result.Files = append(result.Files, info)
	}
	result.Report, err = batch.Finalize()
	if err != nil {
		return BatchUploadResult{}, err
	}
	return result, nil
}

// UploadBytes is a convenience wrapper that does not retain data after the
// operation returns.
func (c *Client) UploadBytes(ctx context.Context, data []byte) (UploadResult, error) {
	return c.Upload(ctx, bytes.NewReader(data))
}

// UploadFile uploads one regular file. The opened file is always closed.
func (c *Client) UploadFile(ctx context.Context, path string) (UploadResult, error) {
	result, err := c.UploadSources(ctx, []UploadSource{{Path: path, Size: -1}})
	if err != nil {
		return UploadResult{}, err
	}
	return UploadResult{File: result.Files[0], Report: result.Report}, nil
}
