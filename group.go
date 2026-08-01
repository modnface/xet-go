package xet

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"

	"github.com/jacobwoliver/xet-go/xetcas"
)

// DownloadRequest is one item in DownloadGroup. Set exactly one of Writer and
// WriterAt. Range nil requests the complete file; WriterAtOffset applies only
// to WriterAt destinations.
type DownloadRequest struct {
	File           FileInfo
	Range          *xetcas.FileRange
	Writer         io.Writer
	WriterAt       io.WriterAt
	WriterAtOffset int64
}

// DownloadResult preserves the request index and a useful partial report when
// a transfer fails.
type DownloadResult struct {
	Report DownloadReport
	Err    error
}

// DownloadGroupReport contains one result for every input request in order.
type DownloadGroupReport struct {
	Downloads    []DownloadResult
	LogicalBytes uint64
	FetchedBytes uint64
}

// DownloadGroup runs several independent file/range reconstructions with a
// bounded number of workers. The first error cancels work that has not yet
// completed; every per-request outcome remains available in the report.
func (c *Client) DownloadGroup(ctx context.Context, requests []DownloadRequest) (DownloadGroupReport, error) {
	if ctx == nil {
		return DownloadGroupReport{}, errors.New("xet: nil download-group context")
	}
	if len(requests) == 0 {
		return DownloadGroupReport{Downloads: []DownloadResult{}}, nil
	}
	for i, request := range requests {
		if (request.Writer == nil) == (request.WriterAt == nil) {
			return DownloadGroupReport{}, fmt.Errorf("xet: download request %d must set exactly one destination", i)
		}
		if request.WriterAtOffset < 0 {
			return DownloadGroupReport{}, fmt.Errorf("xet: download request %d has negative destination offset", i)
		}
		if request.Range != nil {
			if err := request.Range.Validate(); err != nil {
				return DownloadGroupReport{}, fmt.Errorf("xet: download request %d: %w", i, err)
			}
		}
	}
	report := DownloadGroupReport{Downloads: make([]DownloadResult, len(requests))}
	if err := ctx.Err(); err != nil {
		for i := range report.Downloads {
			report.Downloads[i].Err = err
		}
		return report, err
	}
	operationContext, cancel := context.WithCancel(ctx)
	defer cancel()
	jobs := make(chan int)
	workers := min(c.options.DownloadConcurrency, len(requests))
	var group sync.WaitGroup
	var firstMu sync.Mutex
	var firstErr error
	for range workers {
		group.Add(1)
		go func() {
			defer group.Done()
			for index := range jobs {
				request := requests[index]
				var result DownloadReport
				var err error
				if request.Range == nil {
					if request.Writer != nil {
						result, err = c.Download(operationContext, request.File, request.Writer)
					} else {
						result, err = c.download(operationContext, request.File, nil,
							&sequentialWriterAt{dst: request.WriterAt, offset: request.WriterAtOffset})
					}
				} else if request.Writer != nil {
					result, err = c.DownloadRange(operationContext, request.File.Hash, *request.Range, request.Writer)
				} else {
					result, err = c.DownloadRangeAt(operationContext, request.File.Hash, *request.Range,
						request.WriterAt, request.WriterAtOffset)
				}
				report.Downloads[index] = DownloadResult{Report: result, Err: err}
				if err != nil {
					firstMu.Lock()
					if firstErr == nil {
						firstErr = fmt.Errorf("xet: download request %d: %w", index, err)
						cancel()
					}
					firstMu.Unlock()
				}
			}
		}()
	}
	for index := range requests {
		select {
		case jobs <- index:
		case <-operationContext.Done():
			for remaining := index; remaining < len(requests); remaining++ {
				report.Downloads[remaining].Err = operationContext.Err()
			}
			close(jobs)
			group.Wait()
			return summarizeDownloadGroup(report), firstDownloadGroupError(firstErr, ctx, operationContext)
		}
	}
	close(jobs)
	group.Wait()
	return summarizeDownloadGroup(report), firstDownloadGroupError(firstErr, ctx, operationContext)
}

func summarizeDownloadGroup(report DownloadGroupReport) DownloadGroupReport {
	for _, result := range report.Downloads {
		report.LogicalBytes += result.Report.LogicalBytes
		report.FetchedBytes += result.Report.FetchedBytes
	}
	return report
}

func firstDownloadGroupError(first error, parent, operation context.Context) error {
	if first != nil {
		return first
	}
	if err := parent.Err(); err != nil {
		return err
	}
	return operation.Err()
}
