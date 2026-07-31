package xorb

import (
	"bytes"
	"errors"
	"math/rand"
	"testing"

	"github.com/jacobwoliver/xet-go/chunker"
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
