package xorb

import (
	"errors"
	"fmt"

	"github.com/jmwoliver/xet-go/chunker"
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

// ValidateIngested verifies persisted Xorb layout metadata without reading or
// decompressing the backing object. It returns the exact byte length of the
// canonical complete/cache object described by the layout. Complete, when
// present on a freshly ingested value, must have that length; durable indexes
// may omit it after publishing the immutable bytes.
func ValidateIngested(value *Ingested) (int64, error) {
	if value == nil {
		return 0, errors.New("xorb: nil ingested layout")
	}
	if value.Hash == xethash.Zero || value.NetworkBytes == 0 || value.NetworkBytes > MaxNetworkSize {
		return 0, errors.New("xorb: invalid ingested identity or network length")
	}
	if value.UncompressedSize == 0 || value.UncompressedSize > MaxRawSize {
		return 0, errors.New("xorb: invalid ingested uncompressed length")
	}
	if len(value.Chunks) == 0 || len(value.Chunks) > MaxChunks {
		return 0, fmt.Errorf("xorb: invalid ingested chunk count %d", len(value.Chunks))
	}
	nodes := make([]xethash.Node, len(value.Chunks))
	var serializedEnd, uncompressedEnd uint64
	for i, chunk := range value.Chunks {
		if chunk.Hash == xethash.Zero {
			return 0, fmt.Errorf("xorb: ingested chunk %d has a zero identity", i)
		}
		if uint64(chunk.SerializedOffset) != serializedEnd ||
			chunk.SerializedLength <= HeaderSize ||
			chunk.SerializedLength > HeaderSize+2*chunker.MaxSize {
			return 0, fmt.Errorf("xorb: ingested chunk %d has a non-contiguous serialized range", i)
		}
		if uint64(chunk.UncompressedOffset) != uncompressedEnd ||
			chunk.UncompressedLength == 0 || chunk.UncompressedLength > chunker.MaxSize {
			return 0, fmt.Errorf("xorb: ingested chunk %d has a non-contiguous uncompressed range", i)
		}
		serializedEnd += uint64(chunk.SerializedLength)
		uncompressedEnd += uint64(chunk.UncompressedLength)
		if serializedEnd > uint64(value.NetworkBytes) || uncompressedEnd > uint64(value.UncompressedSize) {
			return 0, fmt.Errorf("xorb: ingested chunk %d exceeds declared bounds", i)
		}
		nodes[i] = xethash.Node{Hash: chunk.Hash, Size: uint64(chunk.UncompressedLength)}
	}
	if serializedEnd != uint64(value.NetworkBytes) || uncompressedEnd != uint64(value.UncompressedSize) {
		return 0, errors.New("xorb: ingested terminal ranges differ from declared lengths")
	}
	if computed := xethash.Xorb(nodes); computed != value.Hash {
		return 0, fmt.Errorf("xorb: ingested hash mismatch: declared %s, computed %s", value.Hash, computed)
	}
	completeSize := int64(value.NetworkBytes) + footerV1BaseSize + 40*int64(len(value.Chunks)) + 4
	if value.Complete != nil && int64(len(value.Complete)) != completeSize {
		return 0, fmt.Errorf("xorb: complete object length %d, expected %d", len(value.Complete), completeSize)
	}
	return completeSize, nil
}
