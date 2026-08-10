package xorb

import (
	"bytes"
	"testing"

	"github.com/jacobwoliver/xet-go/xethash"
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
