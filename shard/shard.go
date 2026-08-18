// Package shard implements Xet metadata shard encoding, decoding, and
// validation.
package shard

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"sort"

	"github.com/jmwoliver/xet-go/xethash"
	"github.com/jmwoliver/xet-go/xorb"
)

const (
	RecordSize = 48
	HeaderSize = 48
	FooterSize = 200
	Version    = 2
	MaxSize    = 64 << 20

	FileFlagVerification = uint32(1 << 31)
	FileFlagSHA256       = uint32(1 << 30)
	ChunkFlagGlobalDedup = uint32(1 << 31)
)

var (
	headerMagic = [32]byte{
		0x48, 0x46, 0x52, 0x65, 0x70, 0x6f, 0x4d, 0x65,
		0x74, 0x61, 0x44, 0x61, 0x74, 0x61, 0x00, 0x55,
		0x69, 0x67, 0x45, 0x6a, 0x7b, 0x81, 0x57, 0x83,
		0xa5, 0xbd, 0xd9, 0x5c, 0xcd, 0xd1, 0x4a, 0xa9,
	}
	bookendHash = xethash.Hash{
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	}
)

type FormatError struct {
	Offset int
	Reason string
}

func (e *FormatError) Error() string {
	return fmt.Sprintf("shard: malformed data at offset %d: %s", e.Offset, e.Reason)
}

// Term refers to the half-open chunk interval [Start, End) within a xorb.
type Term struct {
	XorbHash      xethash.Hash
	Flags         uint32
	UnpackedBytes uint32
	Start         uint32
	End           uint32
	Verification  xethash.Hash
}

// File describes one logical reconstruction recipe. SHA256 uses conventional
// raw digest byte order; it is not a Xet hash string.
type File struct {
	Hash   xethash.Hash
	Flags  uint32
	Terms  []Term
	SHA256 *[sha256.Size]byte
}

type XorbChunk struct {
	Hash   xethash.Hash
	Offset uint32
	Length uint32
	Flags  uint32
}

type Xorb struct {
	Hash            xethash.Hash
	Flags           uint32
	RawBytes        uint32
	SerializedBytes uint32
	Chunks          []XorbChunk
}

// Footer is present on cache/download shards and absent from upload shards.
type Footer struct {
	Version            uint64
	FileInfoOffset     uint64
	XorbInfoOffset     uint64
	FileLookupOffset   uint64
	FileLookupEntries  uint64
	XorbLookupOffset   uint64
	XorbLookupEntries  uint64
	ChunkLookupOffset  uint64
	ChunkLookupEntries uint64
	ChunkProtectionKey xethash.Hash
	CreatedAtUnix      uint64
	KeyExpiresAtUnix   uint64
	Reserved           [6]uint64
	StoredBytesOnDisk  uint64
	MaterializedBytes  uint64
	StoredBytes        uint64
	Offset             uint64
}

type Shard struct {
	Files  []File
	Xorbs  []Xorb
	Footer *Footer
}

// XorbFromObject converts an encoded network xorb's exact metadata into a
// shard record.
func XorbFromObject(object *xorb.Object) (Xorb, error) {
	if object == nil {
		return Xorb{}, errors.New("shard: nil xorb object")
	}
	if uint64(len(object.Body)) > uint64(^uint32(0)) {
		return Xorb{}, errors.New("shard: serialized xorb length exceeds uint32")
	}
	result := Xorb{
		Hash:            object.Hash,
		RawBytes:        object.UncompressedSize,
		SerializedBytes: uint32(len(object.Body)),
		Chunks:          make([]XorbChunk, len(object.Chunks)),
	}
	for i, chunk := range object.Chunks {
		result.Chunks[i] = XorbChunk{
			Hash:   chunk.Hash,
			Offset: chunk.UncompressedOffset,
			Length: chunk.UncompressedLength,
		}
	}
	return result, nil
}

// XorbFromIngested converts canonical server-ingestion metadata into the
// shard record used for registration and reconstruction planning.
func XorbFromIngested(object *xorb.Ingested) (Xorb, error) {
	if object == nil {
		return Xorb{}, errors.New("shard: nil ingested xorb")
	}
	result := Xorb{
		Hash:            object.Hash,
		RawBytes:        object.UncompressedSize,
		SerializedBytes: object.NetworkBytes,
		Chunks:          make([]XorbChunk, len(object.Chunks)),
	}
	for i, chunk := range object.Chunks {
		result.Chunks[i] = XorbChunk{
			Hash: chunk.Hash, Offset: chunk.UncompressedOffset, Length: chunk.UncompressedLength,
		}
	}
	if err := validate(&Shard{Xorbs: []Xorb{result}}, true); err != nil {
		return Xorb{}, err
	}
	return result, nil
}

// EncodeUpload emits the production footerless shard form accepted by the CAS.
// Files and xorbs are sorted by hash, matching the official Rust BTreeMap writer.
func EncodeUpload(value Shard) ([]byte, error) {
	if err := validate(&value, true); err != nil {
		return nil, err
	}
	files := append([]File(nil), value.Files...)
	xorbs := append([]Xorb(nil), value.Xorbs...)
	sort.Slice(files, func(i, j int) bool { return files[i].Hash.String() < files[j].Hash.String() })
	sort.Slice(xorbs, func(i, j int) bool { return xorbs[i].Hash.String() < xorbs[j].Hash.String() })

	var out bytes.Buffer
	out.Grow(estimateSize(files, xorbs))
	out.Write(headerMagic[:])
	writeU64(&out, Version)
	writeU64(&out, 0)
	for i := range files {
		writeFile(&out, files[i])
	}
	writeBookend(&out)
	for i := range xorbs {
		writeXorb(&out, xorbs[i])
	}
	writeBookend(&out)
	if out.Len() > MaxSize {
		return nil, fmt.Errorf("shard: encoded size %d exceeds maximum %d", out.Len(), MaxSize)
	}
	return out.Bytes(), nil
}

type lookup12 struct {
	key   uint64
	index uint32
}

type lookup16 struct {
	key        uint64
	xorbIndex  uint32
	chunkIndex uint32
}

// EncodeFull emits the canonical footer-bearing shard form with complete
// file, xorb, and chunk lookup tables. Its zero-valued timestamps match the
// deterministic xet-core in-memory shard encoder.
func EncodeFull(value Shard) ([]byte, error) {
	if err := validate(&value, true); err != nil {
		return nil, err
	}
	return encodeFull(value.Files, value.Xorbs, Footer{Version: 1, KeyExpiresAtUnix: math.MaxUint64})
}

// EncodeProtectedDedup emits a footer-bearing, file-free shard for global
// deduplication. Chunk hashes are keyed, and file-start chunks are marked
// globally eligible before the file section is removed.
func EncodeProtectedDedup(value Shard, key xethash.Hash, createdAtUnix, expiresAtUnix uint64) ([]byte, error) {
	if key.IsZero() {
		return nil, errors.New("shard: protected dedup key is zero")
	}
	if expiresAtUnix <= createdAtUnix {
		return nil, errors.New("shard: protected dedup expiry must follow creation")
	}
	if err := validate(&value, true); err != nil {
		return nil, err
	}
	xorbs := cloneXorbs(value.Xorbs)
	byHash := make(map[xethash.Hash]int, len(xorbs))
	for i := range xorbs {
		byHash[xorbs[i].Hash] = i
	}
	for i, file := range value.Files {
		if len(file.Terms) == 0 {
			continue
		}
		first := file.Terms[0]
		xorbIndex, ok := byHash[first.XorbHash]
		if !ok || first.Start >= uint32(len(xorbs[xorbIndex].Chunks)) {
			return nil, fmt.Errorf("shard: file %d start chunk is not present in protected dedup xorbs", i)
		}
		xorbs[xorbIndex].Chunks[first.Start].Flags |= ChunkFlagGlobalDedup
	}
	for i := range xorbs {
		for j := range xorbs[i].Chunks {
			xorbs[i].Chunks[j].Hash = xethash.Protect(xorbs[i].Chunks[j].Hash, key)
		}
	}
	return encodeFull(nil, xorbs, Footer{
		Version: 1, ChunkProtectionKey: key,
		CreatedAtUnix: createdAtUnix, KeyExpiresAtUnix: expiresAtUnix,
	})
}

func encodeFull(files []File, xorbs []Xorb, footer Footer) ([]byte, error) {
	files = append([]File(nil), files...)
	xorbs = cloneXorbs(xorbs)
	sort.Slice(files, func(i, j int) bool { return files[i].Hash.String() < files[j].Hash.String() })
	sort.Slice(xorbs, func(i, j int) bool { return xorbs[i].Hash.String() < xorbs[j].Hash.String() })

	var out bytes.Buffer
	out.Write(headerMagic[:])
	writeU64(&out, Version)
	writeU64(&out, FooterSize)
	footer.FileInfoOffset = HeaderSize
	fileLookup := make([]lookup12, 0, len(files))
	var fileIndex uint32
	for _, file := range files {
		fileLookup = append(fileLookup, lookup12{key: truncateHash(file.Hash), index: fileIndex})
		writeFile(&out, file)
		fileIndex += uint32(1 + 2*len(file.Terms))
		if file.SHA256 != nil {
			fileIndex++
		}
		for _, term := range file.Terms {
			footer.MaterializedBytes += uint64(term.UnpackedBytes)
		}
	}
	writeBookend(&out)

	footer.XorbInfoOffset = uint64(out.Len())
	xorbLookup := make([]lookup12, 0, len(xorbs))
	chunkLookup := make([]lookup16, 0)
	var xorbIndex uint32
	for _, value := range xorbs {
		xorbLookup = append(xorbLookup, lookup12{key: truncateHash(value.Hash), index: xorbIndex})
		writeXorb(&out, value)
		for i, chunk := range value.Chunks {
			chunkLookup = append(chunkLookup, lookup16{
				key: truncateHash(chunk.Hash), xorbIndex: xorbIndex, chunkIndex: uint32(i),
			})
		}
		xorbIndex += uint32(1 + len(value.Chunks))
		footer.StoredBytesOnDisk += uint64(value.SerializedBytes)
		footer.StoredBytes += uint64(value.RawBytes)
	}
	writeBookend(&out)

	footer.FileLookupOffset = uint64(out.Len())
	footer.FileLookupEntries = uint64(len(fileLookup))
	for _, entry := range fileLookup {
		writeU64(&out, entry.key)
		writeU32(&out, entry.index)
	}
	footer.XorbLookupOffset = uint64(out.Len())
	footer.XorbLookupEntries = uint64(len(xorbLookup))
	for _, entry := range xorbLookup {
		writeU64(&out, entry.key)
		writeU32(&out, entry.index)
	}
	sort.Slice(chunkLookup, func(i, j int) bool {
		if chunkLookup[i].key != chunkLookup[j].key {
			return chunkLookup[i].key < chunkLookup[j].key
		}
		if chunkLookup[i].xorbIndex != chunkLookup[j].xorbIndex {
			return chunkLookup[i].xorbIndex < chunkLookup[j].xorbIndex
		}
		return chunkLookup[i].chunkIndex < chunkLookup[j].chunkIndex
	})
	footer.ChunkLookupOffset = uint64(out.Len())
	footer.ChunkLookupEntries = uint64(len(chunkLookup))
	for _, entry := range chunkLookup {
		writeU64(&out, entry.key)
		writeU32(&out, entry.xorbIndex)
		writeU32(&out, entry.chunkIndex)
	}
	footer.Offset = uint64(out.Len())
	writeFooter(&out, footer)
	if out.Len() > MaxSize {
		return nil, fmt.Errorf("shard: encoded size %d exceeds maximum %d", out.Len(), MaxSize)
	}
	return out.Bytes(), nil
}

func writeFooter(out *bytes.Buffer, value Footer) {
	writeU64(out, value.Version)
	writeU64(out, value.FileInfoOffset)
	writeU64(out, value.XorbInfoOffset)
	writeU64(out, value.FileLookupOffset)
	writeU64(out, value.FileLookupEntries)
	writeU64(out, value.XorbLookupOffset)
	writeU64(out, value.XorbLookupEntries)
	writeU64(out, value.ChunkLookupOffset)
	writeU64(out, value.ChunkLookupEntries)
	out.Write(value.ChunkProtectionKey[:])
	writeU64(out, value.CreatedAtUnix)
	writeU64(out, value.KeyExpiresAtUnix)
	for _, reserved := range value.Reserved {
		writeU64(out, reserved)
	}
	writeU64(out, value.StoredBytesOnDisk)
	writeU64(out, value.MaterializedBytes)
	writeU64(out, value.StoredBytes)
	writeU64(out, value.Offset)
}

func truncateHash(hash xethash.Hash) uint64 { return binary.LittleEndian.Uint64(hash[:8]) }

func cloneXorbs(values []Xorb) []Xorb {
	result := append([]Xorb(nil), values...)
	for i := range result {
		result[i].Chunks = append([]XorbChunk(nil), result[i].Chunks...)
	}
	return result
}

// Decode parses both footerless upload shards and footer-bearing cache/global
// dedup shards. Lookup tables are bounds-validated but not retained.
func Decode(data []byte) (*Shard, error) {
	if len(data) > MaxSize {
		return nil, &FormatError{Reason: "shard exceeds size limit"}
	}
	if len(data) < HeaderSize+2*RecordSize {
		return nil, &FormatError{Reason: "truncated shard"}
	}
	if !bytes.Equal(data[:32], headerMagic[:]) {
		return nil, &FormatError{Reason: "wrong header magic"}
	}
	if version := binary.LittleEndian.Uint64(data[32:40]); version != Version {
		return nil, &FormatError{Offset: 32, Reason: fmt.Sprintf("unsupported version %d", version)}
	}
	footerSize := binary.LittleEndian.Uint64(data[40:48])
	if footerSize != 0 && footerSize != FooterSize {
		return nil, &FormatError{Offset: 40, Reason: fmt.Sprintf("unsupported footer size %d", footerSize)}
	}
	limit := len(data)
	if footerSize != 0 {
		if uint64(len(data)) < footerSize+HeaderSize+2*RecordSize {
			return nil, &FormatError{Offset: 40, Reason: "footer extends before metadata"}
		}
		limit -= int(footerSize)
	}

	result := &Shard{}
	pos := HeaderSize
	for {
		record, err := takeRecord(data, pos, limit)
		if err != nil {
			return nil, err
		}
		if isBookend(record) {
			pos += RecordSize
			break
		}
		file, next, err := readFile(data, pos, limit)
		if err != nil {
			return nil, err
		}
		result.Files = append(result.Files, file)
		pos = next
	}
	xorbStart := pos
	for {
		record, err := takeRecord(data, pos, limit)
		if err != nil {
			return nil, err
		}
		if isBookend(record) {
			pos += RecordSize
			break
		}
		xorbInfo, next, err := readXorb(data, pos, limit)
		if err != nil {
			return nil, err
		}
		result.Xorbs = append(result.Xorbs, xorbInfo)
		pos = next
	}

	if footerSize == 0 {
		if pos != len(data) {
			return nil, &FormatError{Offset: pos, Reason: "trailing data after footerless shard"}
		}
	} else {
		footer, err := readFooter(data[limit:], limit)
		if err != nil {
			return nil, err
		}
		if err := validateFooter(footer, pos, xorbStart, limit, len(data)); err != nil {
			return nil, err
		}
		result.Footer = footer
	}
	if err := validate(result, false); err != nil {
		return nil, &FormatError{Reason: err.Error()}
	}
	return result, nil
}

func writeFile(out *bytes.Buffer, file File) {
	flags := file.Flags | FileFlagVerification
	if file.SHA256 != nil {
		flags |= FileFlagSHA256
	}
	out.Write(file.Hash[:])
	writeU32(out, flags)
	writeU32(out, uint32(len(file.Terms)))
	writeU64(out, 0)
	for _, term := range file.Terms {
		out.Write(term.XorbHash[:])
		writeU32(out, term.Flags)
		writeU32(out, term.UnpackedBytes)
		writeU32(out, term.Start)
		writeU32(out, term.End)
	}
	for _, term := range file.Terms {
		out.Write(term.Verification[:])
		out.Write(make([]byte, 16))
	}
	if file.SHA256 != nil {
		writeSHA256(out, *file.SHA256)
		out.Write(make([]byte, 16))
	}
}

// MerkleDB stores the conventional SHA-256 digest as four little-endian u64
// words. File.SHA256 remains in the conventional byte order used by sha256.Sum256
// and Git LFS OIDs, so the wire conversion is explicit at this boundary.
func writeSHA256(out *bytes.Buffer, sum [sha256.Size]byte) {
	for offset := 0; offset < len(sum); offset += 8 {
		for index := offset + 7; index >= offset; index-- {
			_ = out.WriteByte(sum[index])
		}
	}
}

func writeXorb(out *bytes.Buffer, value Xorb) {
	out.Write(value.Hash[:])
	writeU32(out, value.Flags)
	writeU32(out, uint32(len(value.Chunks)))
	writeU32(out, value.RawBytes)
	writeU32(out, value.SerializedBytes)
	for _, chunk := range value.Chunks {
		out.Write(chunk.Hash[:])
		writeU32(out, chunk.Offset)
		writeU32(out, chunk.Length)
		writeU32(out, chunk.Flags)
		writeU32(out, 0)
	}
}

func readFile(data []byte, pos, limit int) (File, int, error) {
	header, err := takeRecord(data, pos, limit)
	if err != nil {
		return File{}, pos, err
	}
	file := File{}
	copy(file.Hash[:], header[:32])
	file.Flags = binary.LittleEndian.Uint32(header[32:36])
	count := binary.LittleEndian.Uint32(header[36:40])
	if file.Flags & ^uint32(FileFlagVerification|FileFlagSHA256) != 0 {
		return File{}, pos, &FormatError{Offset: pos + 32, Reason: "unknown file flags"}
	}
	if !allZero(header[40:48]) {
		return File{}, pos, &FormatError{Offset: pos + 40, Reason: "nonzero file reserved field"}
	}
	extra := uint64(count)
	if file.Flags&FileFlagVerification != 0 {
		extra += uint64(count)
	}
	if file.Flags&FileFlagSHA256 != 0 {
		extra++
	}
	if extra > uint64((limit-pos-RecordSize)/RecordSize) {
		return File{}, pos, &FormatError{Offset: pos + 36, Reason: "file entry count exceeds remaining data"}
	}
	pos += RecordSize
	file.Terms = make([]Term, count)
	for i := range file.Terms {
		record := data[pos : pos+RecordSize]
		copy(file.Terms[i].XorbHash[:], record[:32])
		file.Terms[i].Flags = binary.LittleEndian.Uint32(record[32:36])
		file.Terms[i].UnpackedBytes = binary.LittleEndian.Uint32(record[36:40])
		file.Terms[i].Start = binary.LittleEndian.Uint32(record[40:44])
		file.Terms[i].End = binary.LittleEndian.Uint32(record[44:48])
		pos += RecordSize
	}
	if file.Flags&FileFlagVerification != 0 {
		for i := range file.Terms {
			record := data[pos : pos+RecordSize]
			copy(file.Terms[i].Verification[:], record[:32])
			if !allZero(record[32:]) {
				return File{}, pos, &FormatError{Offset: pos + 32, Reason: "nonzero verification reserved field"}
			}
			pos += RecordSize
		}
	}
	if file.Flags&FileFlagSHA256 != 0 {
		record := data[pos : pos+RecordSize]
		var sum [sha256.Size]byte
		for offset := 0; offset < len(sum); offset += 8 {
			for index := 0; index < 8; index++ {
				sum[offset+index] = record[offset+7-index]
			}
		}
		file.SHA256 = &sum
		if !allZero(record[32:]) {
			return File{}, pos, &FormatError{Offset: pos + 32, Reason: "nonzero SHA-256 reserved field"}
		}
		pos += RecordSize
	}
	return file, pos, nil
}

func readXorb(data []byte, pos, limit int) (Xorb, int, error) {
	header, err := takeRecord(data, pos, limit)
	if err != nil {
		return Xorb{}, pos, err
	}
	value := Xorb{}
	copy(value.Hash[:], header[:32])
	value.Flags = binary.LittleEndian.Uint32(header[32:36])
	count := binary.LittleEndian.Uint32(header[36:40])
	value.RawBytes = binary.LittleEndian.Uint32(header[40:44])
	value.SerializedBytes = binary.LittleEndian.Uint32(header[44:48])
	if uint64(count) > uint64((limit-pos-RecordSize)/RecordSize) {
		return Xorb{}, pos, &FormatError{Offset: pos + 36, Reason: "xorb entry count exceeds remaining data"}
	}
	pos += RecordSize
	value.Chunks = make([]XorbChunk, count)
	for i := range value.Chunks {
		record := data[pos : pos+RecordSize]
		copy(value.Chunks[i].Hash[:], record[:32])
		value.Chunks[i].Offset = binary.LittleEndian.Uint32(record[32:36])
		value.Chunks[i].Length = binary.LittleEndian.Uint32(record[36:40])
		value.Chunks[i].Flags = binary.LittleEndian.Uint32(record[40:44])
		if !allZero(record[44:48]) {
			return Xorb{}, pos, &FormatError{Offset: pos + 44, Reason: "nonzero xorb chunk reserved field"}
		}
		pos += RecordSize
	}
	return value, pos, nil
}

func readFooter(data []byte, base int) (*Footer, error) {
	if len(data) != FooterSize {
		return nil, &FormatError{Offset: base, Reason: "wrong footer length"}
	}
	f := &Footer{}
	pos := 0
	read := func() uint64 {
		value := binary.LittleEndian.Uint64(data[pos : pos+8])
		pos += 8
		return value
	}
	f.Version = read()
	f.FileInfoOffset = read()
	f.XorbInfoOffset = read()
	f.FileLookupOffset = read()
	f.FileLookupEntries = read()
	f.XorbLookupOffset = read()
	f.XorbLookupEntries = read()
	f.ChunkLookupOffset = read()
	f.ChunkLookupEntries = read()
	copy(f.ChunkProtectionKey[:], data[pos:pos+32])
	pos += 32
	f.CreatedAtUnix = read()
	f.KeyExpiresAtUnix = read()
	for i := range f.Reserved {
		f.Reserved[i] = read()
	}
	f.StoredBytesOnDisk = read()
	f.MaterializedBytes = read()
	f.StoredBytes = read()
	f.Offset = read()
	if f.Version != 1 {
		return nil, &FormatError{Offset: base, Reason: fmt.Sprintf("unsupported footer version %d", f.Version)}
	}
	return f, nil
}

func validateFooter(f *Footer, metadataEnd, xorbStart, footerStart, total int) error {
	if f.FileInfoOffset != HeaderSize || f.XorbInfoOffset != uint64(xorbStart) || f.Offset != uint64(footerStart) {
		return &FormatError{Offset: footerStart, Reason: "footer section offsets do not match shard layout"}
	}
	fileEnd, ok := checkedTableEnd(f.FileLookupOffset, f.FileLookupEntries, 12)
	if !ok || f.FileLookupOffset != uint64(metadataEnd) || fileEnd > uint64(footerStart) {
		return &FormatError{Offset: footerStart, Reason: "invalid file lookup bounds"}
	}
	xorbEnd, ok := checkedTableEnd(f.XorbLookupOffset, f.XorbLookupEntries, 12)
	if !ok || f.XorbLookupOffset < fileEnd || xorbEnd > uint64(footerStart) {
		return &FormatError{Offset: footerStart, Reason: "invalid xorb lookup bounds"}
	}
	chunkEnd, ok := checkedTableEnd(f.ChunkLookupOffset, f.ChunkLookupEntries, 16)
	if !ok || f.ChunkLookupOffset < xorbEnd || chunkEnd != uint64(footerStart) || total != footerStart+FooterSize {
		return &FormatError{Offset: footerStart, Reason: "invalid chunk lookup bounds"}
	}
	return nil
}

func validate(value *Shard, upload bool) error {
	return validateContext(context.Background(), value, upload)
}

func validateContext(ctx context.Context, value *Shard, upload bool) error {
	if ctx == nil {
		return errors.New("shard: nil validation context")
	}
	if value == nil {
		return errors.New("shard: nil value")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if upload && value.Footer != nil {
		return errors.New("shard: upload form cannot contain a footer")
	}
	xorbs := make(map[xethash.Hash]Xorb, len(value.Xorbs))
	for i, x := range value.Xorbs {
		if i&1023 == 0 {
			if err := ctx.Err(); err != nil {
				return err
			}
		}
		if _, exists := xorbs[x.Hash]; exists {
			return fmt.Errorf("shard: duplicate xorb hash %s", x.Hash)
		}
		if upload && x.Flags != 0 {
			return fmt.Errorf("shard: xorb %d has unsupported flags", i)
		}
		if len(x.Chunks) == 0 {
			return fmt.Errorf("shard: xorb %d has no chunks", i)
		}
		// Official upload sessions may leave SerializedBytes zero. The CAS must
		// derive the durable serialized layout from the separately ingested xorb,
		// rather than treating this unauthenticated accounting field as identity.
		var end uint64
		nodes := make([]xethash.Node, len(x.Chunks))
		for j, chunk := range x.Chunks {
			if j&1023 == 0 {
				if err := ctx.Err(); err != nil {
					return err
				}
			}
			if upload && chunk.Flags&^uint32(ChunkFlagGlobalDedup) != 0 {
				return fmt.Errorf("shard: xorb %d chunk %d has unsupported flags", i, j)
			}
			if chunk.Length == 0 || uint64(chunk.Offset) != end {
				return fmt.Errorf("shard: xorb %d chunk %d has non-contiguous range", i, j)
			}
			end += uint64(chunk.Length)
			if end > uint64(^uint32(0)) {
				return fmt.Errorf("shard: xorb %d raw range overflows", i)
			}
			nodes[j] = xethash.Node{Hash: chunk.Hash, Size: uint64(chunk.Length)}
		}
		if uint32(end) != x.RawBytes {
			return fmt.Errorf("shard: xorb %d raw size %d, chunks total %d", i, x.RawBytes, end)
		}
		if value.Footer == nil || value.Footer.ChunkProtectionKey.IsZero() {
			if root := xethash.Xorb(nodes); root != x.Hash {
				return fmt.Errorf("shard: xorb %d hash mismatch", i)
			}
		}
		xorbs[x.Hash] = x
	}
	files := make(map[xethash.Hash]struct{}, len(value.Files))
	for i, file := range value.Files {
		if i&1023 == 0 {
			if err := ctx.Err(); err != nil {
				return err
			}
		}
		if _, exists := files[file.Hash]; exists {
			return fmt.Errorf("shard: duplicate file hash %s", file.Hash)
		}
		files[file.Hash] = struct{}{}
		if upload && file.Flags&^uint32(FileFlagVerification|FileFlagSHA256) != 0 {
			return fmt.Errorf("shard: file %d has unsupported flags", i)
		}
		for j, term := range file.Terms {
			if j&1023 == 0 {
				if err := ctx.Err(); err != nil {
					return err
				}
			}
			if upload && term.Flags != 0 {
				return fmt.Errorf("shard: file %d term %d has unsupported flags", i, j)
			}
			if term.Start >= term.End || term.UnpackedBytes == 0 {
				return fmt.Errorf("shard: file %d term %d has empty or reversed range", i, j)
			}
			if upload && term.Verification.IsZero() {
				return fmt.Errorf("shard: file %d term %d lacks verification", i, j)
			}
			if x, ok := xorbs[term.XorbHash]; ok {
				if term.End > uint32(len(x.Chunks)) {
					return fmt.Errorf("shard: file %d term %d exceeds xorb chunks", i, j)
				}
				var size uint64
				hashes := make([]xethash.Hash, 0, term.End-term.Start)
				for k, chunk := range x.Chunks[term.Start:term.End] {
					if k&1023 == 0 {
						if err := ctx.Err(); err != nil {
							return err
						}
					}
					size += uint64(chunk.Length)
					hashes = append(hashes, chunk.Hash)
				}
				if size != uint64(term.UnpackedBytes) {
					return fmt.Errorf("shard: file %d term %d unpacked length mismatch", i, j)
				}
				if !term.Verification.IsZero() && xethash.Verification(hashes) != term.Verification {
					return fmt.Errorf("shard: file %d term %d verification mismatch", i, j)
				}
			}
		}
	}
	return nil
}

func estimateSize(files []File, xorbs []Xorb) int {
	size := HeaderSize + 2*RecordSize
	for _, file := range files {
		size += RecordSize * (1 + 2*len(file.Terms))
		if file.SHA256 != nil {
			size += RecordSize
		}
	}
	for _, x := range xorbs {
		size += RecordSize * (1 + len(x.Chunks))
	}
	return size
}

func takeRecord(data []byte, pos, limit int) ([]byte, error) {
	if pos < 0 || pos > limit || limit-pos < RecordSize {
		return nil, &FormatError{Offset: pos, Reason: "truncated 48-byte record"}
	}
	return data[pos : pos+RecordSize], nil
}

func isBookend(record []byte) bool {
	return len(record) == RecordSize && bytes.Equal(record[:32], bookendHash[:]) && allZero(record[32:])
}

func writeBookend(out *bytes.Buffer) {
	out.Write(bookendHash[:])
	out.Write(make([]byte, 16))
}

func writeU32(out *bytes.Buffer, value uint32) {
	var buf [4]byte
	binary.LittleEndian.PutUint32(buf[:], value)
	out.Write(buf[:])
}

func writeU64(out *bytes.Buffer, value uint64) {
	var buf [8]byte
	binary.LittleEndian.PutUint64(buf[:], value)
	out.Write(buf[:])
}

func allZero(data []byte) bool {
	for _, b := range data {
		if b != 0 {
			return false
		}
	}
	return true
}

func checkedTableEnd(offset, count, width uint64) (uint64, bool) {
	if count != 0 && width > (^uint64(0)-offset)/count {
		return 0, false
	}
	return offset + count*width, true
}
