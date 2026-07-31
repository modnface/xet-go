package shard

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"testing"

	"github.com/jacobwoliver/xet-go/xethash"
	"github.com/jacobwoliver/xet-go/xorb"
)

func sampleShard(t testing.TB) Shard {
	t.Helper()
	parts := [][]byte{
		bytes.Repeat([]byte("a"), 10_000),
		bytes.Repeat([]byte("b"), 20_000),
		bytes.Repeat([]byte("c"), 30_000),
	}
	object, err := xorb.Encode(parts, xorb.Auto)
	if err != nil {
		t.Fatal(err)
	}
	xorbInfo, err := XorbFromObject(object)
	if err != nil {
		t.Fatal(err)
	}
	nodes := make([]xethash.Node, len(parts))
	hashes := make([]xethash.Hash, len(parts))
	var source []byte
	for i, part := range parts {
		hashes[i] = xethash.Chunk(part)
		nodes[i] = xethash.Node{Hash: hashes[i], Size: uint64(len(part))}
		source = append(source, part...)
	}
	sum := sha256.Sum256(source)
	return Shard{
		Files: []File{{
			Hash: xethash.File(nodes),
			Terms: []Term{{
				XorbHash: object.Hash, UnpackedBytes: uint32(len(source)), Start: 0, End: uint32(len(parts)),
				Verification: xethash.Verification(hashes),
			}},
			SHA256: &sum,
		}},
		Xorbs: []Xorb{xorbInfo},
	}
}

func TestUploadRoundTripAndLayout(t *testing.T) {
	want := sampleShard(t)
	data, err := EncodeUpload(want)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(data[:32], headerMagic[:]) {
		t.Fatal("header magic differs")
	}
	if got := binary.LittleEndian.Uint64(data[32:40]); got != Version {
		t.Fatalf("version = %d", got)
	}
	if got := binary.LittleEndian.Uint64(data[40:48]); got != 0 {
		t.Fatalf("upload footer size = %d, want 0", got)
	}
	if len(data)%RecordSize != 0 {
		t.Fatalf("size %d is not record-aligned", len(data))
	}
	got, err := Decode(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Files) != 1 || len(got.Xorbs) != 1 || got.Footer != nil {
		t.Fatalf("decoded shape = %+v", got)
	}
	if got.Files[0].Hash != want.Files[0].Hash || got.Files[0].Terms[0] != want.Files[0].Terms[0] || *got.Files[0].SHA256 != *want.Files[0].SHA256 {
		t.Fatalf("file differs: got %+v, want %+v", got.Files[0], want.Files[0])
	}
	if got.Xorbs[0].Hash != want.Xorbs[0].Hash || len(got.Xorbs[0].Chunks) != len(want.Xorbs[0].Chunks) {
		t.Fatalf("xorb differs: got %+v, want %+v", got.Xorbs[0], want.Xorbs[0])
	}
}

func TestEncodeSortsRecordsLikeRustBTreeMap(t *testing.T) {
	value := sampleShard(t)
	second := value.Files[0]
	second.Hash = xethash.Chunk([]byte("sort-second"))
	value.Files = []File{second, value.Files[0]}
	data, err := EncodeUpload(value)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := Decode(data)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.Files[0].Hash.String() > decoded.Files[1].Hash.String() {
		t.Fatal("file records are not canonical hash order")
	}
}

func TestEncodeRejectsInvalidMetadata(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Shard)
	}{
		{"missing verification", func(s *Shard) { s.Files[0].Terms[0].Verification = xethash.Zero }},
		{"bad term size", func(s *Shard) { s.Files[0].Terms[0].UnpackedBytes++ }},
		{"bad term range", func(s *Shard) { s.Files[0].Terms[0].End++ }},
		{"bad chunk offset", func(s *Shard) { s.Xorbs[0].Chunks[1].Offset++ }},
		{"bad xorb hash", func(s *Shard) { s.Xorbs[0].Hash = xethash.Chunk([]byte("wrong")) }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			value := sampleShard(t)
			test.mutate(&value)
			if _, err := EncodeUpload(value); err == nil {
				t.Fatal("invalid metadata accepted")
			}
		})
	}
}

func TestDecodeRejectsEveryTruncation(t *testing.T) {
	data, err := EncodeUpload(sampleShard(t))
	if err != nil {
		t.Fatal(err)
	}
	for i := range data {
		_, err := Decode(data[:i])
		if err == nil {
			t.Fatalf("accepted truncation at %d of %d", i, len(data))
		}
		var formatErr *FormatError
		if !errors.As(err, &formatErr) {
			t.Fatalf("truncation %d error type = %T", i, err)
		}
	}
}

func TestFooterValidation(t *testing.T) {
	upload, err := EncodeUpload(sampleShard(t))
	if err != nil {
		t.Fatal(err)
	}
	full := append([]byte(nil), upload...)
	binary.LittleEndian.PutUint64(full[40:48], FooterSize)
	footerStart := uint64(len(full))
	footer := make([]byte, FooterSize)
	values := []uint64{
		1, HeaderSize,
		uint64(HeaderSize + RecordSize*(1+2*len(sampleShard(t).Files[0].Terms)+1) + RecordSize),
		footerStart, 0,
		footerStart, 0,
		footerStart, 0,
	}
	for i, value := range values {
		binary.LittleEndian.PutUint64(footer[i*8:(i+1)*8], value)
	}
	binary.LittleEndian.PutUint64(footer[192:200], footerStart)
	full = append(full, footer...)
	decoded, err := Decode(full)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.Footer == nil || decoded.Footer.Offset != footerStart {
		t.Fatalf("footer = %+v", decoded.Footer)
	}
	full[len(full)-1] ^= 1
	if _, err := Decode(full); err == nil {
		t.Fatal("accepted corrupt footer offset")
	}
}

func FuzzDecode(f *testing.F) {
	data, err := EncodeUpload(sampleShard(f))
	if err != nil {
		f.Fatal(err)
	}
	f.Add(data)
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 2<<20 {
			return
		}
		_, _ = Decode(data)
	})
}

func BenchmarkEncodeUpload(b *testing.B) {
	value := sampleShard(b)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := EncodeUpload(value); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDecodeUpload(b *testing.B) {
	data, err := EncodeUpload(sampleShard(b))
	if err != nil {
		b.Fatal(err)
	}
	b.SetBytes(int64(len(data)))
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := Decode(data); err != nil {
			b.Fatal(err)
		}
	}
}
