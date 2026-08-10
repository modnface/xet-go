package xorb

import (
	"bytes"
	"testing"

	"github.com/jmwoliver/xet-go/chunker"
	"github.com/jmwoliver/xet-go/xethash"
)

func TestIngestNetworkCanonicalizesAndDescribesXorb(t *testing.T) {
	chunks := [][]byte{
		bytes.Repeat([]byte("canonical-ingestion"), 2_000),
		bytes.Repeat([]byte{0x7a}, 17_000),
	}
	object, err := Encode(chunks, LZ4)
	if err != nil {
		t.Fatal(err)
	}
	ingested, err := IngestNetwork(object.Body, object.Hash)
	if err != nil {
		t.Fatal(err)
	}
	if ingested.Hash != object.Hash || ingested.NetworkBytes != uint32(len(object.Body)) ||
		ingested.UncompressedSize != object.UncompressedSize || len(ingested.Chunks) != len(object.Chunks) {
		t.Fatalf("ingested metadata = %#v", ingested)
	}
	for i, chunk := range ingested.Chunks {
		want := object.Chunks[i]
		if chunk.Hash != want.Hash || chunk.SerializedOffset != want.SerializedOffset ||
			chunk.SerializedLength != want.SerializedLength || chunk.UncompressedOffset != want.UncompressedOffset ||
			chunk.UncompressedLength != want.UncompressedLength {
			t.Fatalf("chunk %d = %#v, want %#v", i, chunk, want)
		}
	}
	complete, err := Decode(ingested.Complete)
	if err != nil {
		t.Fatal(err)
	}
	if complete.Footer == nil || complete.Footer.Version != 1 || complete.Footer.UniquenessNonce != [4]byte{} ||
		complete.FooterOffset != uint32(len(object.Body)) || complete.Hash != object.Hash {
		t.Fatalf("complete object = %#v", complete)
	}
	if !bytes.Equal(ingested.Complete[:ingested.NetworkBytes], object.Body) {
		t.Fatal("complete object changed the uploaded content section")
	}
	if len(ingested.Complete) > MaxCompleteSize ||
		MaxCompleteSize != MaxNetworkSize+footerV1BaseSize+40*MaxChunks+4 {
		t.Fatalf("complete size/bound = %d/%d", len(ingested.Complete), MaxCompleteSize)
	}
}

func TestIngestNetworkRejectsWrongIdentityAndNonNetworkForms(t *testing.T) {
	object, err := Encode([][]byte{[]byte("ingestion contracts")}, None)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := IngestNetwork(object.Body, xethash.Zero); err == nil {
		t.Fatal("wrong route identity succeeded")
	}
	complete, err := EncodeComplete(object, [4]byte{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := IngestNetwork(complete, object.Hash); err == nil {
		t.Fatal("complete xorb accepted as a network upload")
	}
	legacy := append(append([]byte(nil), object.Body...), legacyTrailer[:]...)
	if _, err := IngestNetwork(legacy, object.Hash); err == nil {
		t.Fatal("legacy xorb accepted as a network upload")
	}
	if _, err := IngestNetwork(nil, object.Hash); err == nil {
		t.Fatal("empty network upload succeeded")
	}
}

func TestValidateIngestedAcceptsCanonicalAndOmittedComplete(t *testing.T) {
	object, err := Encode([][]byte{
		bytes.Repeat([]byte("persisted layout"), 100),
		bytes.Repeat([]byte{0x8a}, 4_096),
	}, LZ4)
	if err != nil {
		t.Fatal(err)
	}
	ingested, err := IngestNetwork(object.Body, object.Hash)
	if err != nil {
		t.Fatal(err)
	}
	want := int64(len(ingested.Complete))
	if got, err := ValidateIngested(ingested); err != nil || got != want {
		t.Fatalf("fresh ingested layout length = %d, %v; want %d", got, err, want)
	}
	persisted := cloneIngested(ingested)
	persisted.Complete = nil
	if got, err := ValidateIngested(persisted); err != nil || got != want {
		t.Fatalf("persisted ingested layout length = %d, %v; want %d", got, err, want)
	}
	persisted.Complete = make([]byte, want-1)
	if _, err := ValidateIngested(persisted); err == nil {
		t.Fatal("wrong complete object length succeeded")
	}
}

func TestValidateIngestedRejectsInvalidMetadata(t *testing.T) {
	object, err := Encode([][]byte{[]byte("persisted layout validation")}, None)
	if err != nil {
		t.Fatal(err)
	}
	valid, err := IngestNetwork(object.Body, object.Hash)
	if err != nil {
		t.Fatal(err)
	}
	valid.Complete = nil
	tests := map[string]func(*Ingested){
		"zero identity":       func(value *Ingested) { value.Hash = xethash.Zero },
		"zero network length": func(value *Ingested) { value.NetworkBytes = 0 },
		"oversized network length": func(value *Ingested) {
			value.NetworkBytes = MaxNetworkSize + 1
		},
		"zero uncompressed length": func(value *Ingested) { value.UncompressedSize = 0 },
		"oversized uncompressed length": func(value *Ingested) {
			value.UncompressedSize = MaxRawSize + 1
		},
		"no chunks": func(value *Ingested) { value.Chunks = nil },
		"too many chunks": func(value *Ingested) {
			value.Chunks = make([]IngestedChunk, MaxChunks+1)
		},
		"zero chunk identity": func(value *Ingested) { value.Chunks[0].Hash = xethash.Zero },
		"zero serialized payload": func(value *Ingested) {
			value.Chunks[0].SerializedLength = HeaderSize
		},
		"oversized serialized payload": func(value *Ingested) {
			value.Chunks[0].SerializedLength = HeaderSize + 2*chunker.MaxSize + 1
		},
		"serialized offset gap":   func(value *Ingested) { value.Chunks[0].SerializedOffset = 1 },
		"zero uncompressed chunk": func(value *Ingested) { value.Chunks[0].UncompressedLength = 0 },
		"oversized uncompressed chunk": func(value *Ingested) {
			value.Chunks[0].UncompressedLength = chunker.MaxSize + 1
		},
		"uncompressed offset gap":              func(value *Ingested) { value.Chunks[0].UncompressedOffset = 1 },
		"serialized total mismatch":            func(value *Ingested) { value.NetworkBytes++ },
		"uncompressed total mismatch":          func(value *Ingested) { value.UncompressedSize++ },
		"declared serialized bound exceeded":   func(value *Ingested) { value.NetworkBytes-- },
		"declared uncompressed bound exceeded": func(value *Ingested) { value.UncompressedSize-- },
		"Xorb identity mismatch": func(value *Ingested) {
			value.Hash = xethash.Chunk([]byte("different persisted Xorb"))
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			value := cloneIngested(valid)
			mutate(value)
			if _, err := ValidateIngested(value); err == nil {
				t.Fatal("invalid persisted layout succeeded")
			}
		})
	}
	if _, err := ValidateIngested(nil); err == nil {
		t.Fatal("nil persisted layout succeeded")
	}
}

func cloneIngested(value *Ingested) *Ingested {
	result := *value
	result.Complete = append([]byte(nil), value.Complete...)
	result.Chunks = append([]IngestedChunk(nil), value.Chunks...)
	return &result
}
