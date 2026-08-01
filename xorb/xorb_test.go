package xorb

import (
	"bytes"
	"encoding/binary"
	"errors"
	"math/rand"
	"strings"
	"testing"

	"github.com/jacobwoliver/xet-go/chunker"
	"github.com/jacobwoliver/xet-go/xethash"
)

func TestHeaderEncoding(t *testing.T) {
	data := bytes.Repeat([]byte{0xab}, 0x010203)
	object, err := Encode([][]byte{data}, None)
	if err != nil {
		t.Fatal(err)
	}
	want := []byte{0, 0x03, 0x02, 0x01, 0, 0x03, 0x02, 0x01}
	if !bytes.Equal(object.Body[:HeaderSize], want) {
		t.Fatalf("header = %x, want %x", object.Body[:HeaderSize], want)
	}
}

func TestSchemesRoundTrip(t *testing.T) {
	structured := make([]byte, 100_003)
	for i := range structured {
		structured[i] = byte(i / 4)
	}
	rng := rand.New(rand.NewSource(7))
	random := make([]byte, chunker.MaxSize)
	_, _ = rng.Read(random)
	for _, scheme := range []Scheme{None, LZ4, BG4LZ4, Auto} {
		t.Run(scheme.String(), func(t *testing.T) {
			object, err := Encode([][]byte{[]byte("tiny"), structured, random}, scheme)
			if err != nil {
				t.Fatal(err)
			}
			decoded, err := Decode(object.Body)
			if err != nil {
				t.Fatal(err)
			}
			if decoded.Hash != object.Hash || decoded.UncompressedSize != object.UncompressedSize || len(decoded.Chunks) != len(object.Chunks) {
				t.Fatalf("metadata differs: got %+v, want %+v", decoded, object)
			}
			for i := range decoded.Chunks {
				if !bytes.Equal(decoded.Chunks[i].Data, object.Chunks[i].Data) {
					t.Errorf("chunk %d data differs", i)
				}
				if decoded.Chunks[i].Hash != object.Chunks[i].Hash {
					t.Errorf("chunk %d hash differs", i)
				}
			}
		})
	}
}

func TestDecodeOwnsInputWithUncompressedViews(t *testing.T) {
	encoded, err := Encode([][]byte{[]byte("owned decoded payload")}, None)
	if err != nil {
		t.Fatal(err)
	}
	input := append([]byte(nil), encoded.Body...)
	decoded, err := Decode(input)
	if err != nil {
		t.Fatal(err)
	}
	wantBody := append([]byte(nil), decoded.Body...)
	wantData := append([]byte(nil), decoded.Chunks[0].Data...)
	for i := range input {
		input[i] ^= 0xff
	}
	if !bytes.Equal(decoded.Body, wantBody) || !bytes.Equal(decoded.Chunks[0].Data, wantData) {
		t.Fatal("decoded object changed when caller input was mutated")
	}
}

func TestEncodeOwnsInputWithUncompressedViews(t *testing.T) {
	input := []byte("owned encoded payload")
	encoded, err := Encode([][]byte{input}, None)
	if err != nil {
		t.Fatal(err)
	}
	wantBody := append([]byte(nil), encoded.Body...)
	wantData := append([]byte(nil), encoded.Chunks[0].Data...)
	for i := range input {
		input[i] ^= 0xff
	}
	if !bytes.Equal(encoded.Body, wantBody) || !bytes.Equal(encoded.Chunks[0].Data, wantData) {
		t.Fatal("encoded object changed when caller input was mutated")
	}
}

func TestCompleteV1RoundTrip(t *testing.T) {
	object, err := Encode([][]byte{
		bytes.Repeat([]byte("xet-complete"), 1_000),
		bytes.Repeat([]byte{0, 1, 2, 3}, 8_000),
	}, LZ4)
	if err != nil {
		t.Fatal(err)
	}
	nonce := [4]byte{1, 2, 3, 4}
	complete, err := EncodeComplete(object, nonce)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := Decode(complete)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.Footer == nil || decoded.Footer.Version != 1 || decoded.FooterOffset != uint32(len(object.Body)) ||
		decoded.Footer.XorbHash != object.Hash || decoded.Footer.UniquenessNonce != nonce {
		t.Fatalf("bad complete metadata: %#v", decoded)
	}
	if len(decoded.Footer.ChunkHashes) != len(object.Chunks) ||
		len(decoded.Footer.UnpackedChunkOffsets) != len(object.Chunks) {
		t.Fatalf("bad complete chunk metadata: %#v", decoded.Footer)
	}
	infoLength := binary.LittleEndian.Uint32(complete[len(complete)-4:])
	if infoLength != uint32(footerV1BaseSize+40*len(object.Chunks)) {
		t.Fatalf("info length %d", infoLength)
	}
}

func TestCompleteV0Decode(t *testing.T) {
	object, err := Encode([][]byte{[]byte("first"), bytes.Repeat([]byte("second"), 2_000)}, None)
	if err != nil {
		t.Fatal(err)
	}
	n := len(object.Chunks)
	infoLength := footerV0BaseSize + 36*n
	footer := make([]byte, infoLength)
	copy(footer[:7], footerMagic[:])
	footer[7] = 0
	copy(footer[8:40], object.Hash[:])
	binary.LittleEndian.PutUint32(footer[40:44], uint32(n))
	position := 44
	for _, chunk := range object.Chunks {
		binary.LittleEndian.PutUint32(footer[position:position+4], chunk.SerializedOffset+chunk.SerializedLength)
		position += 4
	}
	for _, chunk := range object.Chunks {
		copy(footer[position:position+xethash.Size], chunk.Hash[:])
		position += xethash.Size
	}
	copy(footer[position:position+4], []byte{9, 8, 7, 6})
	complete := append(append(append([]byte(nil), object.Body...), footer...), make([]byte, 4)...)
	binary.LittleEndian.PutUint32(complete[len(complete)-4:], uint32(infoLength))
	decoded, err := Decode(complete)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.Footer == nil || decoded.Footer.Version != 0 || decoded.Footer.UniquenessNonce != [4]byte{9, 8, 7, 6} {
		t.Fatalf("bad V0 footer: %#v", decoded.Footer)
	}
	for i, chunk := range decoded.Chunks {
		if decoded.Footer.UnpackedChunkOffsets[i] != chunk.UncompressedOffset+chunk.UncompressedLength {
			t.Fatalf("unpacked offset %d not reconstructed", i)
		}
	}
}

func TestOfficialLegacyTrailerDecode(t *testing.T) {
	object, err := Encode([][]byte{[]byte("official reference trailer")}, None)
	if err != nil {
		t.Fatal(err)
	}
	legacy := append(append([]byte(nil), object.Body...), legacyTrailer[:]...)
	decoded, err := Decode(legacy)
	if err != nil {
		t.Fatal(err)
	}
	if !decoded.LegacyTrailer || decoded.Footer != nil || decoded.FooterOffset != uint32(len(object.Body)) ||
		decoded.Hash != object.Hash || !bytes.Equal(decoded.Body, legacy) {
		t.Fatalf("legacy trailer metadata differs: %+v", decoded)
	}
	corrupt := append([]byte(nil), legacy...)
	corrupt[len(corrupt)-4] = 1
	if _, err := Decode(corrupt); err == nil {
		t.Fatal("accepted malformed legacy trailer as chunk data")
	}
}

func TestCompleteFooterRejectsCorruption(t *testing.T) {
	object, err := Encode([][]byte{bytes.Repeat([]byte("footer"), 2_000)}, None)
	if err != nil {
		t.Fatal(err)
	}
	complete, err := EncodeComplete(object, [4]byte{})
	if err != nil {
		t.Fatal(err)
	}
	footerStart := len(object.Body)
	for _, offset := range []int{footerStart + 8, footerStart + 40, footerStart + 47, footerStart + 52} {
		corrupt := append([]byte(nil), complete...)
		corrupt[offset] ^= 0xff
		if _, err := Decode(corrupt); err == nil {
			t.Fatalf("accepted complete footer corruption at %d", offset)
		}
	}
}

func TestEncodeProductionRetestsAndResetsAtFileBoundaries(t *testing.T) {
	chunks := make([][]byte, 66)
	for i := range chunks {
		chunks[i] = bytes.Repeat([]byte{byte(i), byte(i >> 1), 0, 0xff}, 4096)
	}
	object, err := EncodeProduction(chunks, EncodeOptions{
		Scheme:         Auto,
		FileBoundaries: []int{0, 40},
		RetestInterval: 32,
	})
	if err != nil {
		t.Fatal(err)
	}
	want := make([]Scheme, len(chunks))
	for _, span := range [][2]int{{0, 32}, {32, 40}, {40, 66}} {
		selected := chooseCompression(chunks[span[0]])
		for i := span[0]; i < span[1]; i++ {
			want[i] = selected
		}
	}
	for i, chunk := range object.Chunks {
		if chunk.Scheme != want[i] && chunk.Scheme != None {
			t.Fatalf("chunk %d scheme=%s, want %s or none fallback", i, chunk.Scheme, want[i])
		}
	}
}

func TestEncodeProductionRejectsBadBoundaries(t *testing.T) {
	chunks := [][]byte{[]byte("a"), []byte("b")}
	for _, boundaries := range [][]int{{1}, {0, 0}, {0, 2}, {0, -1}} {
		if _, err := EncodeProduction(chunks, EncodeOptions{Scheme: Auto, FileBoundaries: boundaries}); err == nil {
			t.Fatalf("boundaries %v accepted", boundaries)
		}
	}
}

func TestProductionDefaultsAndCompleteBoundaryInference(t *testing.T) {
	plain, err := EncodeProduction([][]byte{[]byte("plain production chunk")}, EncodeOptions{Scheme: None})
	if err != nil || plain.Chunks[0].Scheme != None {
		t.Fatalf("production none = %#v, %v", plain, err)
	}
	auto, err := EncodeProduction([][]byte{bytes.Repeat([]byte("compressible"), 100)}, EncodeOptions{Scheme: Auto})
	if err != nil || len(auto.Chunks) != 1 {
		t.Fatalf("production defaults = %#v, %v", auto, err)
	}
	auto.FooterOffset = 0
	complete, err := EncodeComplete(auto, [4]byte{1})
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := Decode(complete)
	if err != nil || decoded.Footer == nil || decoded.FooterOffset != uint32(len(auto.Body)) {
		t.Fatalf("inferred complete boundary = %#v, %v", decoded, err)
	}
}

func TestEncodingInputContracts(t *testing.T) {
	if got := Scheme(42).String(); got != "scheme(42)" {
		t.Fatalf("unknown scheme string = %q", got)
	}
	formatErr := &FormatError{Offset: 3, Reason: "reason"}
	if got := formatErr.Error(); got != "xorb: malformed data at offset 3: reason" {
		t.Fatalf("FormatError = %q", got)
	}
	if _, err := EncodeProduction([][]byte{[]byte("x")}, EncodeOptions{Scheme: 42}); err == nil {
		t.Fatal("unknown production scheme succeeded")
	}
	if _, err := EncodeProduction(nil, EncodeOptions{Scheme: Auto}); err == nil {
		t.Fatal("empty production object succeeded")
	}
	if _, err := EncodeProduction([][]byte{[]byte("x")}, EncodeOptions{Scheme: Auto, RetestInterval: -1}); err == nil {
		t.Fatal("negative retest interval succeeded")
	}
	if _, err := encode(nil, nil); err == nil {
		t.Fatal("empty object succeeded")
	}
	if _, err := encode([][]byte{[]byte("x")}, nil); err == nil {
		t.Fatal("scheme count mismatch succeeded")
	}
	if _, err := Encode(make([][]byte, MaxChunks+1), None); err == nil {
		t.Fatal("excessive chunk count succeeded")
	}
	if _, err := Encode([][]byte{nil}, None); err == nil {
		t.Fatal("empty chunk succeeded")
	}
	if _, err := Encode([][]byte{make([]byte, chunker.MaxSize+1)}, None); err == nil {
		t.Fatal("oversized chunk succeeded")
	}
	if _, err := Encode([][]byte{[]byte("x")}, Scheme(42)); err == nil {
		t.Fatal("unknown chunk scheme succeeded")
	}
}

func TestEncodeCompleteInputContracts(t *testing.T) {
	if _, err := EncodeComplete(nil, [4]byte{}); err == nil {
		t.Fatal("nil complete object succeeded")
	}
	for name, object := range map[string]*Object{
		"empty":       {},
		"past body":   {Body: []byte("x"), FooterOffset: 2},
		"bad content": {Body: []byte("not a xorb"), FooterOffset: uint32(len("not a xorb"))},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := EncodeComplete(object, [4]byte{}); err == nil {
				t.Fatal("invalid complete object succeeded")
			}
		})
	}
}

func TestCompleteFooterSemanticCorruption(t *testing.T) {
	object, err := Encode([][]byte{bytes.Repeat([]byte("footer"), 50)}, None)
	if err != nil {
		t.Fatal(err)
	}
	complete, err := EncodeComplete(object, [4]byte{})
	if err != nil {
		t.Fatal(err)
	}
	start := len(object.Body)
	tests := map[string]int{
		"version":             start + 7,
		"xorb hash":           start + 8,
		"hash magic":          start + 40,
		"hash marker":         start + 47,
		"chunk count":         start + 48,
		"chunk hash":          start + 52,
		"boundary magic":      start + 84,
		"boundary marker":     start + 91,
		"boundary count":      start + 92,
		"serialized boundary": start + 96,
		"unpacked boundary":   start + 100,
		"terminal count":      start + 104,
		"hash jump":           start + 108,
		"boundary jump":       start + 112,
	}
	for name, offset := range tests {
		t.Run(name, func(t *testing.T) {
			corrupt := append([]byte(nil), complete...)
			corrupt[offset] ^= 0xff
			if _, err := Decode(corrupt); err == nil {
				t.Fatal("corrupt footer decoded")
			}
		})
	}
}

func TestDecodeStructuralLimits(t *testing.T) {
	if _, err := Decode(legacyTrailer[:]); err == nil {
		t.Fatal("bare legacy trailer decoded")
	}
	largeCompressed := []byte{0, 1, 0, 4, byte(None), 1, 0, 0}
	if _, err := Decode(largeCompressed); err == nil {
		t.Fatal("excessive compressed length decoded")
	}
	header := []byte{0, 1, 0, 0, byte(None), 1, 0, 0, 'x'}
	many := bytes.Repeat(header, MaxChunks+1)
	if _, err := Decode(many); err == nil {
		t.Fatal("excessive decoded chunk count succeeded")
	}
}

func TestCodecInternalFormatContracts(t *testing.T) {
	if _, err := decodeContent(nil); err == nil {
		t.Fatal("empty content section decoded")
	}
	if _, err := decodePayload([]byte("x"), None, 2); err == nil {
		t.Fatal("mismatched uncompressed payload decoded")
	}
	if _, err := decodePayload([]byte("not an lz4 frame"), LZ4, 1); err == nil {
		t.Fatal("invalid LZ4 frame decoded")
	}
	compressed, err := compressLZ4([]byte("decompressed length contract"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decodePayload(compressed, LZ4, len("decompressed length contract")-1); err == nil {
		t.Fatal("wrong declared LZ4 length decoded")
	}

	object, err := Encode([][]byte{[]byte("one"), []byte("two")}, None)
	if err != nil {
		t.Fatal(err)
	}
	complete, err := EncodeComplete(object, [4]byte{})
	if err != nil {
		t.Fatal(err)
	}
	complete[len(object.Body)+7] = 0
	if _, err := Decode(complete); err == nil || !strings.Contains(err.Error(), "invalid complete footer length") {
		t.Fatalf("inconsistent footer version/length = %v", err)
	}

	hashes := make([]xethash.Hash, len(object.Chunks))
	for i := range object.Chunks {
		hashes[i] = object.Chunks[i].Hash
	}
	footer := &Footer{XorbHash: object.Hash, ChunkHashes: hashes, ChunkBoundaryOffsets: []uint32{object.Chunks[0].SerializedLength}}
	if err := validateFooter(object, footer); err == nil {
		t.Fatal("footer/content chunk count mismatch succeeded")
	}
}

func TestChooseCompressionCanSelectBG4(t *testing.T) {
	const samples = 109
	data := make([]byte, samples*4)
	representatives := []byte{0x00, 0x01, 0x03, 0x07, 0x0f, 0x1f, 0x3f, 0x7f, 0xff}
	for mod := 0; mod < 4; mod++ {
		for i, value := range representatives {
			data[4*i+mod] = value
		}
		var fill byte
		switch mod {
		case 1:
			fill = 0xff
		case 2:
			fill = 0x0f
		case 3:
			fill = 0x03
		}
		for i := len(representatives); i < samples; i++ {
			data[4*i+mod] = fill
		}
	}
	if got := chooseCompression(data); got != BG4LZ4 {
		t.Fatalf("structured four-byte data chose %s", got)
	}
}

func TestBG4Remainders(t *testing.T) {
	for n := 0; n < 32; n++ {
		data := make([]byte, n)
		for i := range data {
			data[i] = byte(i)
		}
		if got := bg4Regroup(bg4Split(data)); !bytes.Equal(got, data) {
			t.Fatalf("length %d round trip = %x, want %x", n, got, data)
		}
	}
}

func TestDecodeRejectsCorruptionAndTruncation(t *testing.T) {
	object, err := Encode([][]byte{bytes.Repeat([]byte("abcd"), 4096)}, LZ4)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < len(object.Body); i++ {
		_, err := Decode(object.Body[:i])
		if err == nil {
			t.Fatalf("accepted truncation at %d of %d", i, len(object.Body))
		}
		var formatErr *FormatError
		if !errors.As(err, &formatErr) {
			t.Fatalf("truncation %d error type = %T", i, err)
		}
	}

	cases := [][]byte{
		{1, 1, 0, 0, 0, 1, 0, 0, 'x'}, // version
		{0, 1, 0, 0, 9, 1, 0, 0, 'x'}, // scheme
		{0, 0, 0, 0, 0, 1, 0, 0},      // zero payload
		{0, 1, 0, 0, 0, 0, 0, 0, 'x'}, // zero output
	}
	for i, body := range cases {
		if _, err := Decode(body); err == nil {
			t.Errorf("accepted malformed case %d", i)
		}
	}
}

func FuzzDecode(f *testing.F) {
	object, err := Encode([][]byte{bytes.Repeat([]byte("xet"), 4096)}, Auto)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(object.Body)
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 2<<20 {
			return
		}
		_, _ = Decode(data)
	})
}

func FuzzSchemesRoundTrip(f *testing.F) {
	f.Add([]byte("xet"), uint8(Auto))
	f.Fuzz(func(t *testing.T, data []byte, rawScheme uint8) {
		if len(data) == 0 || len(data) > chunker.MaxSize {
			return
		}
		schemes := [...]Scheme{None, LZ4, BG4LZ4, Auto}
		scheme := schemes[int(rawScheme)%len(schemes)]
		object, err := Encode([][]byte{data}, scheme)
		if err != nil {
			t.Fatal(err)
		}
		decoded, err := Decode(object.Body)
		if err != nil {
			t.Fatal(err)
		}
		if len(decoded.Chunks) != 1 || !bytes.Equal(decoded.Chunks[0].Data, data) {
			t.Fatal("round trip mismatch")
		}
	})
}

func BenchmarkEncodeLZ4(b *testing.B) {
	data := bytes.Repeat([]byte("xet-protocol-structured-data"), chunker.TargetSize/28)
	b.SetBytes(int64(len(data)))
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := Encode([][]byte{data}, LZ4); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDecodeLZ4(b *testing.B) {
	data := bytes.Repeat([]byte("xet-protocol-structured-data"), chunker.TargetSize/28)
	object, err := Encode([][]byte{data}, LZ4)
	if err != nil {
		b.Fatal(err)
	}
	b.SetBytes(int64(len(data)))
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := Decode(object.Body); err != nil {
			b.Fatal(err)
		}
	}
}
