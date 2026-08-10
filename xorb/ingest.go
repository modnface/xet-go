package xorb

import (
	"errors"
	"fmt"

	"github.com/jmwoliver/xet-go/xethash"
)

const (
	// MaxNetworkSize is the largest canonical footerless xorb emitted by the
	// protocol encoder: the maximum raw payload plus one header per chunk.
	MaxNetworkSize = MaxRawSize + MaxChunks*HeaderSize
	// MaxCompleteSize adds the largest canonical V1 metadata footer to a
	// MaxNetworkSize content section.
	MaxCompleteSize = MaxNetworkSize + footerV1BaseSize + 40*MaxChunks + 4
)

// IngestedChunk is the storage metadata derived from one validated network
// xorb chunk. Serialized ranges address the footerless/complete xorb content
// section; uncompressed ranges address the logical xorb data.
type IngestedChunk struct {
	Hash               xethash.Hash
	SerializedOffset   uint32
	SerializedLength   uint32
	UncompressedOffset uint32
	UncompressedLength uint32
}

// Ingested is the canonical durable form of a footerless network xorb.
// Complete contains an exact V1 XETBLOB footer with the canonical zero nonce.
type Ingested struct {
	Hash             xethash.Hash
	NetworkBytes     uint32
	UncompressedSize uint32
	Complete         []byte
	Chunks           []IngestedChunk
}

// IngestNetwork validates a footerless upload, recomputes its identities, and
// returns the canonical complete/cache representation and range metadata.
func IngestNetwork(body []byte, expected xethash.Hash) (*Ingested, error) {
	if len(body) > MaxNetworkSize {
		return nil, fmt.Errorf("xorb: network object size %d exceeds maximum %d", len(body), MaxNetworkSize)
	}
	object, err := Decode(body)
	if err != nil {
		return nil, fmt.Errorf("xorb: ingest network object: %w", err)
	}
	if object.Footer != nil || object.LegacyTrailer || int(object.FooterOffset) != len(object.Body) {
		return nil, errors.New("xorb: network upload must be footerless")
	}
	if object.Hash != expected {
		return nil, fmt.Errorf("xorb: hash mismatch: expected %s, computed %s", expected, object.Hash)
	}
	complete, err := EncodeComplete(object, [4]byte{})
	if err != nil {
		return nil, fmt.Errorf("xorb: build complete object: %w", err)
	}
	result := &Ingested{
		Hash:             object.Hash,
		NetworkBytes:     uint32(len(body)),
		UncompressedSize: object.UncompressedSize,
		Complete:         complete,
		Chunks:           make([]IngestedChunk, len(object.Chunks)),
	}
	for i, chunk := range object.Chunks {
		result.Chunks[i] = IngestedChunk{
			Hash:               chunk.Hash,
			SerializedOffset:   chunk.SerializedOffset,
			SerializedLength:   chunk.SerializedLength,
			UncompressedOffset: chunk.UncompressedOffset,
			UncompressedLength: chunk.UncompressedLength,
		}
	}
	return result, nil
}
