// Package xorb implements strict Xet network and complete/cache xorb codecs.
package xorb

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"math/bits"

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
	footerV0BaseSize = 60
	footerV1BaseSize = 92
)

var (
	footerMagic       = [7]byte{'X', 'E', 'T', 'B', 'L', 'O', 'B'}
	footerHashesMagic = [7]byte{'X', 'B', 'L', 'B', 'H', 'S', 'H'}
	footerBoundsMagic = [7]byte{'X', 'B', 'L', 'B', 'B', 'N', 'D'}
	legacyTrailer     = [4]byte{'X', 'E', 'T', 'B'}
)

// Scheme is the compression transform stored in a chunk header.
type Scheme uint8

const (
	None   Scheme = 0
	LZ4    Scheme = 1
	BG4LZ4 Scheme = 2
	Auto   Scheme = 99 // encoder-only: choose using Rust's BG4 predictor
)

// EncodeOptions controls production auto-compression grouping. FileBoundaries
// contains sorted chunk indices where a new logical file begins (normally
// starting with zero). Auto is re-evaluated every RetestInterval chunks within
// each file. A zero interval selects the official default of 32.
type EncodeOptions struct {
	Scheme         Scheme
	FileBoundaries []int
	RetestInterval int
}

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

// Footer is metadata carried by complete/cache xorbs. Version 0 does not
// serialize UnpackedChunkOffsets; the decoder reconstructs and validates them.
type Footer struct {
	Version                 uint8
	XorbHash                xethash.Hash
	ChunkHashes             []xethash.Hash
	ChunkBoundaryOffsets    []uint32
	UnpackedChunkOffsets    []uint32
	UniquenessNonce         [4]byte
	HashesOffsetFromEnd     uint32
	BoundariesOffsetFromEnd uint32
}

// Object is a decoded xorb. Body contains the complete input. FooterOffset is
// len(Body) for the footerless network form and the start of Footer otherwise.
type Object struct {
	Hash             xethash.Hash
	Body             []byte
	Chunks           []Chunk
	UncompressedSize uint32
	FooterOffset     uint32
	Footer           *Footer
	// LegacyTrailer reports the historical "XETB" terminator carried by the
	// official protocol reference xorb. New network objects do not emit it.
	LegacyTrailer bool
}

// Encode serializes an ordered set of chunks. It rejects inputs exceeding the
// protocol xorb limits rather than silently changing object membership.
func Encode(chunks [][]byte, scheme Scheme) (*Object, error) {
	schemes := make([]Scheme, len(chunks))
	for i := range chunks {
		schemes[i] = scheme
	}
	return encode(chunks, schemes)
}

// EncodeProduction applies the official xet-core upload compression policy,
// including per-file and periodic Auto retesting.
func EncodeProduction(chunks [][]byte, options EncodeOptions) (*Object, error) {
	if options.Scheme != None && options.Scheme != LZ4 && options.Scheme != BG4LZ4 && options.Scheme != Auto {
		return nil, fmt.Errorf("xorb: unknown compression scheme %d", options.Scheme)
	}
	if options.Scheme != Auto {
		return Encode(chunks, options.Scheme)
	}
	if len(chunks) == 0 {
		return nil, errors.New("xorb: cannot encode an empty object")
	}
	boundaries := append([]int(nil), options.FileBoundaries...)
	if len(boundaries) == 0 {
		boundaries = []int{0}
	}
	if boundaries[0] != 0 {
		return nil, errors.New("xorb: first file boundary must be zero")
	}
	for i, boundary := range boundaries {
		if boundary < 0 || boundary >= len(chunks) || (i > 0 && boundary <= boundaries[i-1]) {
			return nil, fmt.Errorf("xorb: invalid file boundary %d at index %d", boundary, i)
		}
	}
	retest := options.RetestInterval
	if retest == 0 {
		retest = 32
	}
	if retest < 0 {
		return nil, errors.New("xorb: retest interval must not be negative")
	}
	schemes := make([]Scheme, len(chunks))
	for fileIndex, start := range boundaries {
		end := len(chunks)
		if fileIndex+1 < len(boundaries) {
			end = boundaries[fileIndex+1]
		}
		for block := start; block < end; block += retest {
			blockEnd := block + retest
			if blockEnd > end {
				blockEnd = end
			}
			selected := chooseCompression(chunks[block])
			for i := block; i < blockEnd; i++ {
				schemes[i] = selected
			}
		}
	}
	return encode(chunks, schemes)
}

func encode(chunks [][]byte, schemes []Scheme) (*Object, error) {
	if len(chunks) == 0 {
		return nil, errors.New("xorb: cannot encode an empty object")
	}
	if len(schemes) != len(chunks) {
		return nil, errors.New("xorb: compression scheme count differs from chunk count")
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
		used, payload, err := encodePayload(data, schemes[i])
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
	object.FooterOffset = uint32(len(object.Body))
	object.Hash = xethash.Xorb(nodes)
	return object, nil
}

// EncodeComplete appends the current V1 XETBLOB footer to an object. Network
// uploads must continue to use Object.Body from Encode/EncodeProduction.
func EncodeComplete(object *Object, nonce [4]byte) ([]byte, error) {
	if object == nil {
		return nil, errors.New("xorb: nil object")
	}
	contentEnd := int(object.FooterOffset)
	if contentEnd == 0 && len(object.Body) != 0 && object.Footer == nil {
		contentEnd = len(object.Body)
	}
	if contentEnd <= 0 || contentEnd > len(object.Body) {
		return nil, errors.New("xorb: invalid content boundary")
	}
	decoded, err := decodeContent(object.Body[:contentEnd])
	if err != nil {
		return nil, fmt.Errorf("xorb: encode complete: %w", err)
	}
	n := len(decoded.Chunks)
	if n > MaxChunks {
		return nil, errors.New("xorb: complete footer chunk count exceeds limit")
	}
	infoLength := footerV1BaseSize + 40*n
	out := make([]byte, contentEnd, contentEnd+infoLength+4)
	copy(out, object.Body[:contentEnd])
	footer := make([]byte, infoLength)
	position := 0
	copy(footer[position:position+7], footerMagic[:])
	position += 7
	footer[position] = 1
	position++
	copy(footer[position:position+xethash.Size], decoded.Hash[:])
	position += xethash.Size
	copy(footer[position:position+7], footerHashesMagic[:])
	position += 7
	footer[position] = 0
	position++
	binary.LittleEndian.PutUint32(footer[position:position+4], uint32(n))
	position += 4
	for _, chunk := range decoded.Chunks {
		copy(footer[position:position+xethash.Size], chunk.Hash[:])
		position += xethash.Size
	}
	copy(footer[position:position+7], footerBoundsMagic[:])
	position += 7
	footer[position] = 1
	position++
	binary.LittleEndian.PutUint32(footer[position:position+4], uint32(n))
	position += 4
	for _, chunk := range decoded.Chunks {
		boundary := chunk.SerializedOffset + chunk.SerializedLength
		binary.LittleEndian.PutUint32(footer[position:position+4], boundary)
		position += 4
	}
	for _, chunk := range decoded.Chunks {
		boundary := chunk.UncompressedOffset + chunk.UncompressedLength
		binary.LittleEndian.PutUint32(footer[position:position+4], boundary)
		position += 4
	}
	binary.LittleEndian.PutUint32(footer[position:position+4], uint32(n))
	position += 4
	hashesFromEnd := uint32(52 + 40*n)
	boundsFromEnd := uint32(40 + 8*n)
	binary.LittleEndian.PutUint32(footer[position:position+4], hashesFromEnd)
	position += 4
	binary.LittleEndian.PutUint32(footer[position:position+4], boundsFromEnd)
	position += 4
	copy(footer[position:position+4], nonce[:])
	position += 16 // nonce followed by twelve reserved zero bytes
	if position != infoLength {
		return nil, errors.New("xorb: internal complete footer length mismatch")
	}
	out = append(out, footer...)
	out = binary.LittleEndian.AppendUint32(out, uint32(infoLength))
	return out, nil
}

// Decode validates and decompresses either a footerless network xorb or a V0
// or V1 complete/cache xorb. All declared lengths are checked before allocation.
func Decode(body []byte) (*Object, error) {
	if len(body) == 0 {
		return nil, &FormatError{Reason: "empty object"}
	}
	parseBody := body
	legacy := len(body) >= len(legacyTrailer) && bytes.Equal(body[len(body)-len(legacyTrailer):], legacyTrailer[:])
	if legacy {
		parseBody = body[:len(body)-len(legacyTrailer)]
		if len(parseBody) == 0 {
			return nil, &FormatError{Reason: "legacy trailer has no content"}
		}
	}
	contentEnd, footer, err := splitFooter(parseBody)
	if err != nil {
		return nil, err
	}
	object, err := decodeContent(parseBody[:contentEnd])
	if err != nil {
		return nil, err
	}
	object.Body = append([]byte(nil), body...)
	object.FooterOffset = uint32(contentEnd)
	object.Footer = footer
	object.LegacyTrailer = legacy
	if footer != nil {
		if err := validateFooter(object, footer); err != nil {
			return nil, err
		}
	}
	return object, nil
}

func decodeContent(body []byte) (*Object, error) {
	if len(body) == 0 {
		return nil, &FormatError{Reason: "empty content section"}
	}
	object := &Object{Body: append([]byte(nil), body...), FooterOffset: uint32(len(body))}
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

func splitFooter(body []byte) (int, *Footer, error) {
	if len(body) < 4 {
		return len(body), nil, nil
	}
	infoLength := int(binary.LittleEndian.Uint32(body[len(body)-4:]))
	if infoLength > len(body)-4 || infoLength < 8 {
		return len(body), nil, nil
	}
	start := len(body) - 4 - infoLength
	if start < HeaderSize || !bytes.Equal(body[start:start+7], footerMagic[:]) {
		return len(body), nil, nil
	}
	version := body[start+7]
	if (version == 0 && (infoLength < footerV0BaseSize || (infoLength-footerV0BaseSize)%36 != 0)) ||
		(version == 1 && (infoLength < footerV1BaseSize || (infoLength-footerV1BaseSize)%40 != 0)) {
		return 0, nil, &FormatError{Offset: start, Reason: "invalid complete footer length"}
	}
	if version != 0 && version != 1 {
		return 0, nil, &FormatError{Offset: start + 7, Reason: fmt.Sprintf("unsupported footer version %d", version)}
	}
	footer, err := parseFooter(body[start:len(body)-4], start)
	if err != nil {
		return 0, nil, err
	}
	return start, footer, nil
}

func parseFooter(data []byte, base int) (*Footer, error) {
	version := data[7]
	footer := &Footer{Version: version}
	copy(footer.XorbHash[:], data[8:40])
	if version == 0 {
		n := int(binary.LittleEndian.Uint32(data[40:44]))
		if n > MaxChunks || footerV0BaseSize+36*n != len(data) {
			return nil, &FormatError{Offset: base + 40, Reason: "invalid V0 footer chunk count"}
		}
		position := 44
		footer.ChunkBoundaryOffsets = make([]uint32, n)
		for i := range footer.ChunkBoundaryOffsets {
			footer.ChunkBoundaryOffsets[i] = binary.LittleEndian.Uint32(data[position : position+4])
			position += 4
		}
		footer.ChunkHashes = make([]xethash.Hash, n)
		for i := range footer.ChunkHashes {
			copy(footer.ChunkHashes[i][:], data[position:position+xethash.Size])
			position += xethash.Size
		}
		copy(footer.UniquenessNonce[:], data[position:position+4])
		return footer, nil
	}
	if !bytes.Equal(data[40:47], footerHashesMagic[:]) || data[47] != 0 {
		return nil, &FormatError{Offset: base + 40, Reason: "invalid hash footer section"}
	}
	n := int(binary.LittleEndian.Uint32(data[48:52]))
	if n > MaxChunks || footerV1BaseSize+40*n != len(data) {
		return nil, &FormatError{Offset: base + 48, Reason: "invalid V1 footer chunk count"}
	}
	position := 52
	footer.ChunkHashes = make([]xethash.Hash, n)
	for i := range footer.ChunkHashes {
		copy(footer.ChunkHashes[i][:], data[position:position+xethash.Size])
		position += xethash.Size
	}
	if !bytes.Equal(data[position:position+7], footerBoundsMagic[:]) || data[position+7] != 1 {
		return nil, &FormatError{Offset: base + position, Reason: "invalid boundary footer section"}
	}
	position += 8
	if count := int(binary.LittleEndian.Uint32(data[position : position+4])); count != n {
		return nil, &FormatError{Offset: base + position, Reason: "inconsistent footer chunk counts"}
	}
	position += 4
	footer.ChunkBoundaryOffsets = make([]uint32, n)
	for i := range footer.ChunkBoundaryOffsets {
		footer.ChunkBoundaryOffsets[i] = binary.LittleEndian.Uint32(data[position : position+4])
		position += 4
	}
	footer.UnpackedChunkOffsets = make([]uint32, n)
	for i := range footer.UnpackedChunkOffsets {
		footer.UnpackedChunkOffsets[i] = binary.LittleEndian.Uint32(data[position : position+4])
		position += 4
	}
	if count := int(binary.LittleEndian.Uint32(data[position : position+4])); count != n {
		return nil, &FormatError{Offset: base + position, Reason: "inconsistent footer terminal chunk count"}
	}
	position += 4
	footer.HashesOffsetFromEnd = binary.LittleEndian.Uint32(data[position : position+4])
	position += 4
	footer.BoundariesOffsetFromEnd = binary.LittleEndian.Uint32(data[position : position+4])
	position += 4
	if footer.HashesOffsetFromEnd != uint32(len(data)-40) ||
		footer.BoundariesOffsetFromEnd != uint32(len(data)-(52+32*n)) {
		return nil, &FormatError{Offset: base + position - 8, Reason: "invalid footer jump offset"}
	}
	copy(footer.UniquenessNonce[:], data[position:position+4])
	return footer, nil
}

func validateFooter(object *Object, footer *Footer) error {
	if footer.XorbHash != object.Hash {
		return &FormatError{Offset: int(object.FooterOffset) + 8, Reason: "footer xorb hash mismatch"}
	}
	if len(footer.ChunkHashes) != len(object.Chunks) ||
		len(footer.ChunkBoundaryOffsets) != len(object.Chunks) {
		return &FormatError{Offset: int(object.FooterOffset), Reason: "footer chunk count differs from content"}
	}
	if footer.Version == 0 {
		footer.UnpackedChunkOffsets = make([]uint32, len(object.Chunks))
	}
	for i, chunk := range object.Chunks {
		if footer.ChunkHashes[i] != chunk.Hash {
			return &FormatError{Offset: int(object.FooterOffset), Reason: fmt.Sprintf("footer chunk hash %d mismatch", i)}
		}
		if footer.ChunkBoundaryOffsets[i] != chunk.SerializedOffset+chunk.SerializedLength {
			return &FormatError{Offset: int(object.FooterOffset), Reason: fmt.Sprintf("footer chunk boundary %d mismatch", i)}
		}
		unpacked := chunk.UncompressedOffset + chunk.UncompressedLength
		if footer.Version == 1 && footer.UnpackedChunkOffsets[i] != unpacked {
			return &FormatError{Offset: int(object.FooterOffset), Reason: fmt.Sprintf("footer unpacked boundary %d mismatch", i)}
		}
		footer.UnpackedChunkOffsets[i] = unpacked
	}
	return nil
}

func encodePayload(data []byte, requested Scheme) (Scheme, []byte, error) {
	if requested != None && requested != LZ4 && requested != BG4LZ4 && requested != Auto {
		return 0, nil, fmt.Errorf("unknown compression scheme %d", requested)
	}
	if requested == None {
		return None, append([]byte(nil), data...), nil
	}
	if requested == Auto {
		return encodePayload(data, chooseCompression(data))
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

// chooseCompression is the scalar equivalent of xet-core's BG4Predictor. It
// uses popcount histograms and the same maximum KL-divergence threshold.
func chooseCompression(data []byte) Scheme {
	var histograms [4][9]uint32
	for i, value := range data {
		histograms[i&3][bits.OnesCount8(value)]++
	}
	baseCounts := [9]uint32{1, 1, 1, 1, 1, 1, 1, 1, 1}
	var totals [4]uint32
	for i := range histograms {
		for j, count := range histograms[i] {
			baseCounts[j] += count
			totals[i] += count
		}
	}
	baseTotal := totals[0] + totals[1] + totals[2] + totals[3]
	var maximum float64
	if baseTotal != 0 {
		for i := range histograms {
			if totals[i] == 0 {
				continue
			}
			divergence := 0.0
			valid := true
			for j, count := range histograms[i] {
				if count == 0 {
					// Rust evaluates 0*ln(0/q) as NaN and f64::max
					// ignores that group. Preserve that behavior directly.
					valid = false
					break
				}
				p := float64(count) / float64(totals[i])
				q := float64(baseCounts[j]) / float64(baseTotal)
				divergence += p * math.Log(p/q)
			}
			if valid && divergence > maximum {
				maximum = divergence
			}
		}
	}
	if maximum > 0.02 {
		return BG4LZ4
	}
	return LZ4
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
