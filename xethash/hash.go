// Package xethash implements Xet's byte-native hash representation and keyed
// BLAKE3 operations.
package xethash

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"lukechampine.com/blake3"
)

const (
	Size       = 32
	StringSize = 64
)

// Hash is a Xet Merkle hash in its canonical raw, on-wire byte order.
type Hash [Size]byte

// Zero is the all-zero hash used for empty aggregate and file identities.
var Zero Hash

// ErrInvalidHash is returned when a textual or binary hash has the wrong form.
var ErrInvalidHash = errors.New("invalid Xet hash")

var (
	dataKey = [Size]byte{
		0x66, 0x97, 0xf5, 0x77, 0x5b, 0x95, 0x50, 0xde,
		0x31, 0x35, 0xcb, 0xac, 0xa5, 0x97, 0x18, 0x1c,
		0x9d, 0xe4, 0x21, 0x10, 0x9b, 0xeb, 0x2b, 0x58,
		0xb4, 0xd0, 0xb0, 0x4b, 0x93, 0xad, 0xf2, 0x29,
	}
	internalKey = [Size]byte{
		0x01, 0x7e, 0xc5, 0xc7, 0xa5, 0x47, 0x29, 0x96,
		0xfd, 0x94, 0x66, 0x66, 0xb4, 0x8a, 0x02, 0xe6,
		0x5d, 0xdd, 0x53, 0x6f, 0x37, 0xc7, 0x6d, 0xd2,
		0xf8, 0x63, 0x52, 0xe6, 0x4a, 0x53, 0x71, 0x3f,
	}
	verificationKey = [Size]byte{
		0x7f, 0x18, 0x57, 0xd6, 0xce, 0x56, 0xed, 0x66,
		0x12, 0x7f, 0xf9, 0x13, 0xe7, 0xa5, 0xc3, 0xf3,
		0xa4, 0xcd, 0x26, 0xd5, 0xb5, 0xdb, 0x49, 0xe6,
		0x41, 0x24, 0x98, 0x7f, 0x28, 0xfb, 0x94, 0xc3,
	}
)

// FromBytes validates and copies a raw 32-byte Xet hash.
func FromBytes(b []byte) (Hash, error) {
	if len(b) != Size {
		return Hash{}, fmt.Errorf("%w: raw length %d, want %d", ErrInvalidHash, len(b), Size)
	}
	var h Hash
	copy(h[:], b)
	return h, nil
}

// Parse parses Xet's 64-character representation. Each displayed 16-character
// limb represents an underlying little-endian uint64, so this is deliberately
// not ordinary hex decoding of the raw bytes.
func Parse(s string) (Hash, error) {
	if len(s) != StringSize {
		return Hash{}, fmt.Errorf("%w: text length %d, want %d", ErrInvalidHash, len(s), StringSize)
	}
	var h Hash
	var limb [8]byte
	for i := 0; i < 4; i++ {
		if _, err := hex.Decode(limb[:], []byte(s[i*16:(i+1)*16])); err != nil {
			return Hash{}, fmt.Errorf("%w: %v", ErrInvalidHash, err)
		}
		for j := range limb {
			h[i*8+j] = limb[7-j]
		}
	}
	return h, nil
}

// MustParse is intended for trusted constants and panics on invalid input.
func MustParse(s string) Hash {
	h, err := Parse(s)
	if err != nil {
		panic(err)
	}
	return h
}

// String returns Xet's canonical lowercase representation.
func (h Hash) String() string {
	var dst [StringSize]byte
	for i := 0; i < 4; i++ {
		var limb [8]byte
		for j := range limb {
			limb[j] = h[i*8+7-j]
		}
		hex.Encode(dst[i*16:(i+1)*16], limb[:])
	}
	return string(dst[:])
}

// Base64 returns the unpadded URL-safe encoding of the raw hash bytes.
func (h Hash) Base64() string { return base64.RawURLEncoding.EncodeToString(h[:]) }

// ParseBase64 parses an unpadded URL-safe raw hash encoding.
func ParseBase64(s string) (Hash, error) {
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return Hash{}, fmt.Errorf("%w: invalid base64", ErrInvalidHash)
	}
	return FromBytes(b)
}

// Bytes returns a copy of the raw on-wire bytes.
func (h Hash) Bytes() []byte {
	b := make([]byte, Size)
	copy(b, h[:])
	return b
}

func (h Hash) IsZero() bool { return h == Zero }

func (h Hash) MarshalText() ([]byte, error) { return []byte(h.String()), nil }

func (h *Hash) UnmarshalText(text []byte) error {
	parsed, err := Parse(string(text))
	if err != nil {
		return err
	}
	*h = parsed
	return nil
}

func (h Hash) MarshalJSON() ([]byte, error) { return json.Marshal(h.String()) }

func (h *Hash) UnmarshalJSON(data []byte) error {
	var text string
	if err := json.Unmarshal(data, &text); err != nil {
		return fmt.Errorf("%w: expected JSON string", ErrInvalidHash)
	}
	return h.UnmarshalText([]byte(text))
}

// LastUint64 returns the final eight raw bytes interpreted little-endian. Xet
// uses this value for Merkle natural cuts and deduplication sampling.
func (h Hash) LastUint64() uint64 { return binary.LittleEndian.Uint64(h[24:]) }

func keyedHash(key [Size]byte, parts ...[]byte) Hash {
	h := blake3.New(Size, key[:])
	for _, part := range parts {
		_, _ = h.Write(part)
	}
	var out Hash
	copy(out[:], h.Sum(nil))
	return out
}

// Chunk computes the Xet leaf hash of uncompressed chunk bytes.
func Chunk(data []byte) Hash { return keyedHash(dataKey, data) }

// Internal computes the Xet internal-node hash of an already formatted node
// message.
func Internal(message []byte) Hash { return keyedHash(internalKey, message) }

// Protect computes Xet's historically named HMAC operation. It is keyed
// BLAKE3 over the raw hash bytes, not RFC HMAC.
func Protect(hash Hash, key Hash) Hash { return keyedHash([Size]byte(key), hash[:]) }

// Verification computes the hash for an ordered reconstruction-term chunk
// range.
func Verification(hashes []Hash) Hash {
	h := blake3.New(Size, verificationKey[:])
	for i := range hashes {
		_, _ = h.Write(hashes[i][:])
	}
	var out Hash
	copy(out[:], h.Sum(nil))
	return out
}

// Node associates a hash with the uncompressed byte length represented by it.
type Node struct {
	Hash Hash
	Size uint64
}

func nextMergeCut(nodes []Node) int {
	if len(nodes) <= 2 {
		return len(nodes)
	}
	end := len(nodes)
	if end > 9 {
		end = 9
	}
	for i := 2; i < end; i++ {
		if nodes[i].Hash.LastUint64()%4 == 0 {
			return i + 1
		}
	}
	return end
}

func merge(nodes []Node) Node {
	var b strings.Builder
	b.Grow(len(nodes) * 88)
	var size uint64
	for _, n := range nodes {
		b.WriteString(n.Hash.String())
		b.WriteString(" : ")
		fmt.Fprint(&b, n.Size)
		b.WriteByte('\n')
		size += n.Size
	}
	return Node{Hash: Internal([]byte(b.String())), Size: size}
}

// Aggregate computes Xet's variable-arity Merkle root. Empty input maps to
// Zero; a single leaf is returned unchanged.
func Aggregate(nodes []Node) Hash {
	if len(nodes) == 0 {
		return Zero
	}
	level := append([]Node(nil), nodes...)
	for len(level) > 1 {
		next := make([]Node, 0, (len(level)+1)/2)
		for pos := 0; pos < len(level); {
			cut := pos + nextMergeCut(level[pos:])
			next = append(next, merge(level[pos:cut]))
			pos = cut
		}
		level = next
	}
	return level[0].Hash
}

// Xorb computes the Xet identity of an ordered sequence of chunks.
func Xorb(nodes []Node) Hash { return Aggregate(nodes) }

// File computes the default all-zero-salted file identity.
func File(nodes []Node) Hash { return FileWithSalt(nodes, Hash{}) }

// FileWithSalt computes the Xet file identity for an ordered chunk sequence.
func FileWithSalt(nodes []Node, salt Hash) Hash {
	if len(nodes) == 0 {
		return Zero
	}
	root := Aggregate(nodes)
	return Protect(root, salt)
}
