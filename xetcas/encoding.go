package xetcas

import (
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/klauspost/compress/zstd"
)

// decodeResponse applies Content-Encoding values in reverse order. The caller
// must still impose an output byte limit while reading; maxOutput additionally
// bounds zstd's window and decoder memory.
func decodeResponse(response *http.Response, maxOutput int64) (io.Reader, func() error, error) {
	if response == nil || response.Body == nil {
		return nil, nil, errors.New("xet CAS: response has no body")
	}
	if maxOutput < 1 {
		return nil, nil, errors.New("xet CAS: invalid decoded response limit")
	}
	reader := io.Reader(response.Body)
	var closes []func() error
	rawEncoding := response.Header.Get("Content-Encoding")
	if rawEncoding == "" {
		return reader, func() error { return nil }, nil
	}
	encodings := strings.Split(rawEncoding, ",")
	for i := len(encodings) - 1; i >= 0; i-- {
		encoding := strings.ToLower(strings.TrimSpace(encodings[i]))
		switch encoding {
		case "identity":
			continue
		case "":
			_ = closeDecoders(closes)
			return nil, nil, errors.New("xet CAS: malformed empty Content-Encoding")
		case "gzip":
			decoder, err := gzip.NewReader(reader)
			if err != nil {
				_ = closeDecoders(closes)
				return nil, nil, fmt.Errorf("xet CAS: initialize gzip response: %w", err)
			}
			reader = decoder
			closes = append(closes, decoder.Close)
		case "zstd":
			memoryLimit := uint64(maxOutput) + 1
			if memoryLimit < 1<<20 {
				memoryLimit = 1 << 20
			}
			decoder, err := zstd.NewReader(reader,
				zstd.WithDecoderConcurrency(1),
				zstd.WithDecoderLowmem(true),
				zstd.WithDecoderMaxMemory(memoryLimit),
				zstd.WithDecoderMaxWindow(memoryLimit),
			)
			if err != nil {
				_ = closeDecoders(closes)
				return nil, nil, fmt.Errorf("xet CAS: initialize zstd response: %w", err)
			}
			reader = decoder
			closes = append(closes, func() error {
				decoder.Close()
				return nil
			})
		default:
			_ = closeDecoders(closes)
			return nil, nil, fmt.Errorf("xet CAS: unsupported Content-Encoding %q", encoding)
		}
	}
	return reader, func() error { return closeDecoders(closes) }, nil
}

func closeDecoders(closes []func() error) error {
	var result error
	for i := len(closes) - 1; i >= 0; i-- {
		result = errors.Join(result, closes[i]())
	}
	return result
}
