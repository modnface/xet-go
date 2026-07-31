// Package xorb implements the strict footerless Xet network-xorb codec.
package xorb

import (
	"bytes"
	"errors"
	"fmt"
	"io"

	"github.com/jacobwoliver/xet-go/chunker"
	"github.com/jacobwoliver/xet-go/xethash"
	"github.com/pierrec/lz4/v4"
)

const (
	HeaderSize       = 8
	MaxRawSize       = 64 << 20
	DefaultTargetRaw = 63 << 20
	MaxChunks        = 8192
	maxUint24        = 1<<24 - 1
)

// Scheme is the compression transform stored in a chunk header.
type Scheme uint8

const (
	None   Scheme = 0
	LZ4    Scheme = 1
	BG4LZ4 Scheme = 2
	Auto   Scheme = 255 // encoder-only: try both compression schemes
)

func (s Scheme) String() string {
	switch s {
	case None:
		return "none"
	case LZ4:
		return "lz4"
	case BG4LZ4:
		return "bg4-lz4"
	case Auto:
		return "auto"
	default:
		return fmt.Sprintf("scheme(%d)", s)
	}
}

// FormatError identifies malformed untrusted xorb data without retaining its
// contents.
type FormatError struct {
	Offset int
	Reason string
}

func (e *FormatError) Error() string {
	return fmt.Sprintf("xorb: malformed data at offset %d: %s", e.Offset, e.Reason)
}

// Chunk describes one serialized and logical range in an Object.
type Chunk struct {
	Hash               xethash.Hash
	Scheme             Scheme
	SerializedOffset   uint32
	SerializedLength   uint32
	UncompressedOffset uint32
	UncompressedLength uint32
	Data               []byte
}

// Object is a footerless network xorb. Body contains repeated chunk records.
type Object struct {
	Hash             xethash.Hash
	Body             []byte
	Chunks           []Chunk
	UncompressedSize uint32
}

// Encode serializes an ordered set of chunks. It rejects inputs exceeding the
// protocol xorb limits rather than silently changing object membership.
func Encode(chunks [][]byte, scheme Scheme) (*Object, error) {
	if len(chunks) == 0 {
		return nil, errors.New("xorb: cannot encode an empty object")
	}
	if len(chunks) > MaxChunks {
		return nil, fmt.Errorf("xorb: %d chunks exceeds maximum %d", len(chunks), MaxChunks)
	}
	object := &Object{Chunks: make([]Chunk, 0, len(chunks))}
	nodes := make([]xethash.Node, 0, len(chunks))
	var body bytes.Buffer
	var rawTotal uint64
	for i, data := range chunks {
		if len(data) == 0 || len(data) > chunker.MaxSize {
			return nil, fmt.Errorf("xorb: chunk %d length %d outside [1,%d]", i, len(data), chunker.MaxSize)
		}
		rawTotal += uint64(len(data))
		if rawTotal > MaxRawSize {
			return nil, fmt.Errorf("xorb: raw size %d exceeds maximum %d", rawTotal, MaxRawSize)
		}
		start := body.Len()
		used, payload, err := encodePayload(data, scheme)
		if err != nil {
			return nil, fmt.Errorf("xorb: chunk %d: %w", i, err)
		}
		if len(payload) > maxUint24 {
			return nil, fmt.Errorf("xorb: chunk %d serialized payload too large", i)
		}
		header := [HeaderSize]byte{0}
		putUint24(header[1:4], uint32(len(payload)))
		header[4] = byte(used)
		putUint24(header[5:8], uint32(len(data)))
		body.Write(header[:])
		body.Write(payload)

		hash := xethash.Chunk(data)
		object.Chunks = append(object.Chunks, Chunk{
			Hash:               hash,
			Scheme:             used,
			SerializedOffset:   uint32(start),
			SerializedLength:   uint32(HeaderSize + len(payload)),
			UncompressedOffset: object.UncompressedSize,
			UncompressedLength: uint32(len(data)),
			Data:               append([]byte(nil), data...),
		})
		object.UncompressedSize += uint32(len(data))
		nodes = append(nodes, xethash.Node{Hash: hash, Size: uint64(len(data))})
	}
	object.Body = body.Bytes()
	object.Hash = xethash.Xorb(nodes)
	return object, nil
}

// Decode validates and decompresses a footerless network xorb. All declared
// lengths are checked before allocation.
func Decode(body []byte) (*Object, error) {
	if len(body) == 0 {
		return nil, &FormatError{Reason: "empty object"}
	}
	object := &Object{Body: append([]byte(nil), body...)}
	nodes := make([]xethash.Node, 0, 1024)
	for offset := 0; offset < len(body); {
		if len(object.Chunks) == MaxChunks {
			return nil, &FormatError{Offset: offset, Reason: "too many chunks"}
		}
		if len(body)-offset < HeaderSize {
			return nil, &FormatError{Offset: offset, Reason: "truncated chunk header"}
		}
		header := body[offset : offset+HeaderSize]
		if header[0] != 0 {
			return nil, &FormatError{Offset: offset, Reason: fmt.Sprintf("unsupported version %d", header[0])}
		}
		compressedLen := int(getUint24(header[1:4]))
		scheme := Scheme(header[4])
		uncompressedLen := int(getUint24(header[5:8]))
		if compressedLen == 0 {
			return nil, &FormatError{Offset: offset + 1, Reason: "zero compressed length"}
		}
		if compressedLen > 2*chunker.MaxSize {
			return nil, &FormatError{Offset: offset + 1, Reason: "compressed length exceeds limit"}
		}
		if uncompressedLen == 0 || uncompressedLen > chunker.MaxSize {
			return nil, &FormatError{Offset: offset + 5, Reason: "uncompressed length outside limit"}
		}
		payloadStart := offset + HeaderSize
		payloadEnd := payloadStart + compressedLen
		if payloadEnd < payloadStart || payloadEnd > len(body) {
			return nil, &FormatError{Offset: payloadStart, Reason: "truncated chunk payload"}
		}
		data, err := decodePayload(body[payloadStart:payloadEnd], scheme, uncompressedLen)
		if err != nil {
			return nil, &FormatError{Offset: payloadStart, Reason: err.Error()}
		}
		if uint64(object.UncompressedSize)+uint64(len(data)) > MaxRawSize {
			return nil, &FormatError{Offset: offset, Reason: "raw object size exceeds limit"}
		}
		hash := xethash.Chunk(data)
		object.Chunks = append(object.Chunks, Chunk{
			Hash:               hash,
			Scheme:             scheme,
			SerializedOffset:   uint32(offset),
			SerializedLength:   uint32(HeaderSize + compressedLen),
			UncompressedOffset: object.UncompressedSize,
			UncompressedLength: uint32(len(data)),
			Data:               data,
		})
		object.UncompressedSize += uint32(len(data))
		nodes = append(nodes, xethash.Node{Hash: hash, Size: uint64(len(data))})
		offset = payloadEnd
	}
	object.Hash = xethash.Xorb(nodes)
	return object, nil
}

func encodePayload(data []byte, requested Scheme) (Scheme, []byte, error) {
	if requested != None && requested != LZ4 && requested != BG4LZ4 && requested != Auto {
		return 0, nil, fmt.Errorf("unknown compression scheme %d", requested)
	}
	if requested == None {
		return None, append([]byte(nil), data...), nil
	}
	if requested == Auto {
		lz4Data, err := compressLZ4(data)
		if err != nil {
			return 0, nil, err
		}
		bg4Data, err := compressLZ4(bg4Split(data))
		if err != nil {
			return 0, nil, err
		}
		used, best := LZ4, lz4Data
		if len(bg4Data) < len(best) {
			used, best = BG4LZ4, bg4Data
		}
		if len(best) >= len(data) {
			return None, append([]byte(nil), data...), nil
		}
		return used, best, nil
	}
	input := data
	if requested == BG4LZ4 {
		input = bg4Split(data)
	}
	compressed, err := compressLZ4(input)
	if err != nil {
		return 0, nil, err
	}
	if len(compressed) >= len(data) {
		return None, append([]byte(nil), data...), nil
	}
	return requested, compressed, nil
}

func decodePayload(payload []byte, scheme Scheme, want int) ([]byte, error) {
	if scheme == None {
		if len(payload) != want {
			return nil, fmt.Errorf("uncompressed payload length %d, want %d", len(payload), want)
		}
		return append([]byte(nil), payload...), nil
	}
	if scheme != LZ4 && scheme != BG4LZ4 {
		return nil, fmt.Errorf("unknown compression scheme %d", scheme)
	}
	r := lz4.NewReader(bytes.NewReader(payload))
	data, err := io.ReadAll(io.LimitReader(r, int64(want)+1))
	if err != nil {
		return nil, fmt.Errorf("invalid LZ4 frame: %w", err)
	}
	if len(data) != want {
		return nil, fmt.Errorf("decompressed length %d, want %d", len(data), want)
	}
	if scheme == BG4LZ4 {
		data = bg4Regroup(data)
	}
	return data, nil
}

func compressLZ4(data []byte) ([]byte, error) {
	var out bytes.Buffer
	w := lz4.NewWriter(&out)
	blockSize := lz4.Block64Kb
	if len(data) > 64<<10 {
		blockSize = lz4.Block256Kb
	}
	if err := w.Apply(
		lz4.BlockSizeOption(blockSize),
		lz4.BlockChecksumOption(false),
		lz4.ChecksumOption(false),
		lz4.CompressionLevelOption(lz4.Fast),
		lz4.ConcurrencyOption(1),
	); err != nil {
		return nil, err
	}
	if _, err := w.Write(data); err != nil {
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

func bg4Split(data []byte) []byte {
	out := make([]byte, len(data))
	group := 0
	for mod := 0; mod < 4; mod++ {
		for i := mod; i < len(data); i += 4 {
			out[group] = data[i]
			group++
		}
	}
	return out
}

func bg4Regroup(grouped []byte) []byte {
	out := make([]byte, len(grouped))
	base, remainder := len(grouped)/4, len(grouped)%4
	start := 0
	for mod := 0; mod < 4; mod++ {
		length := base
		if mod < remainder {
			length++
		}
		for i := 0; i < length; i++ {
			out[4*i+mod] = grouped[start+i]
		}
		start += length
	}
	return out
}

func putUint24(dst []byte, n uint32) {
	dst[0] = byte(n)
	dst[1] = byte(n >> 8)
	dst[2] = byte(n >> 16)
}

func getUint24(src []byte) uint32 {
	return uint32(src[0]) | uint32(src[1])<<8 | uint32(src[2])<<16
}
