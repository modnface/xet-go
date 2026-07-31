package conformance_test

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/jacobwoliver/xet-go/chunker"
	"github.com/jacobwoliver/xet-go/xethash"
	"github.com/jacobwoliver/xet-go/xorb"
)

type oracleChunk struct {
	End    int    `json:"end"`
	Length int    `json:"len"`
	Hash   string `json:"hash"`
	RawHex string `json:"raw_hex"`
}

type encodedXorb struct {
	BodyHex string `json:"body_hex"`
	Chunks  int    `json:"chunks"`
}

type decodedXorb struct {
	DataHex    string   `json:"data_hex"`
	Boundaries []uint32 `json:"boundaries"`
}

type oracleCorpus struct {
	Size     int           `json:"size"`
	Chunks   []oracleChunk `json:"chunks"`
	XorbHash string        `json:"xorb_hash"`
	FileHash string        `json:"file_hash"`
}

func TestRustDifferentialXorb(t *testing.T) {
	oracle := os.Getenv("XET_RUST_ORACLE")
	if oracle == "" {
		t.Skip("set XET_RUST_ORACLE to the binary produced by conformance/build-rust-oracle.sh")
	}
	rng := rand.New(rand.NewSource(91))
	random := make([]byte, 400_000)
	_, _ = rng.Read(random)
	inputs := [][]byte{
		[]byte("small footerless xorb"),
		bytes.Repeat([]byte("structured-xet-data"), 20_000),
		random,
	}
	schemes := []struct {
		name string
		goID xorb.Scheme
	}{
		{name: "none", goID: xorb.None},
		{name: "lz4", goID: xorb.LZ4},
		{name: "bg4-lz4", goID: xorb.BG4LZ4},
	}
	for inputIndex, data := range inputs {
		for _, scheme := range schemes {
			t.Logf("comparing input %d with %s", inputIndex, scheme.name)
			compareXorb(t, oracle, data, scheme.name, scheme.goID)
		}
	}
}

func compareXorb(t *testing.T, oracle string, data []byte, schemeName string, schemeID xorb.Scheme) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "input.bin")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	output, err := exec.Command(oracle, "encode-xorb", path, schemeName).CombinedOutput()
	if err != nil {
		t.Fatalf("Rust encode: %v\n%s", err, output)
	}
	var rustEncoded encodedXorb
	if err := json.Unmarshal(output, &rustEncoded); err != nil {
		t.Fatal(err)
	}
	rustBody, err := hex.DecodeString(rustEncoded.BodyHex)
	if err != nil {
		t.Fatal(err)
	}
	rustDecoded, err := xorb.Decode(rustBody)
	if err != nil {
		t.Fatalf("Go decode of Rust xorb: %v", err)
	}
	if got := joinXorb(rustDecoded); !bytes.Equal(got, data) {
		t.Fatal("Go decode of Rust xorb differs")
	}

	parts := chunker.Bytes(data)
	chunkData := make([][]byte, len(parts))
	for i := range parts {
		chunkData[i] = parts[i].Data
	}
	goEncoded, err := xorb.Encode(chunkData, schemeID)
	if err != nil {
		t.Fatal(err)
	}
	bodyPath := filepath.Join(t.TempDir(), "xorb.bin")
	if err := os.WriteFile(bodyPath, goEncoded.Body, 0o600); err != nil {
		t.Fatal(err)
	}
	output, err = exec.Command(oracle, "decode-xorb", bodyPath).CombinedOutput()
	if err != nil {
		t.Fatalf("Rust decode of Go xorb: %v\n%s", err, output)
	}
	var decoded decodedXorb
	if err := json.Unmarshal(output, &decoded); err != nil {
		t.Fatal(err)
	}
	rustData, err := hex.DecodeString(decoded.DataHex)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(rustData, data) {
		t.Fatal("Rust decode of Go xorb differs")
	}
	if schemeID == xorb.None && !bytes.Equal(goEncoded.Body, rustBody) {
		t.Fatal("uncompressed xorb encoding differs byte-for-byte")
	}
}

func joinXorb(object *xorb.Object) []byte {
	var out []byte
	for _, chunk := range object.Chunks {
		out = append(out, chunk.Data...)
	}
	return out
}

func TestRustDifferentialCorpus(t *testing.T) {
	oracle := os.Getenv("XET_RUST_ORACLE")
	if oracle == "" {
		t.Skip("set XET_RUST_ORACLE to the binary produced by conformance/build-rust-oracle.sh")
	}
	lengths := []int{0, 1, 8191, 8192, 8193, 65536, 131071, 131072, 131073, 1 << 20, 8 << 20}
	for seed := int64(0); seed < 8; seed++ {
		for _, length := range lengths {
			t.Run(fmt.Sprintf("seed_%d_len_%d", seed, length), func(t *testing.T) {
				rng := rand.New(rand.NewSource(seed))
				data := make([]byte, length)
				_, _ = rng.Read(data)
				compareCorpus(t, oracle, data)
			})
		}
	}
}

func compareCorpus(t *testing.T, oracle string, data []byte) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "input.bin")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	command := exec.Command(oracle, "corpus", path)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("Rust oracle: %v\n%s", err, output)
	}
	var want oracleCorpus
	if err := json.Unmarshal(output, &want); err != nil {
		t.Fatalf("decode Rust output: %v\n%s", err, output)
	}

	gotChunks := chunker.Bytes(data)
	if len(gotChunks) != len(want.Chunks) {
		t.Fatalf("chunk count = %d, Rust = %d", len(gotChunks), len(want.Chunks))
	}
	nodes := make([]xethash.Node, len(gotChunks))
	for i, got := range gotChunks {
		hash := xethash.Chunk(got.Data)
		raw, err := hex.DecodeString(want.Chunks[i].RawHex)
		if err != nil {
			t.Fatal(err)
		}
		if got.End() != int64(want.Chunks[i].End) || len(got.Data) != want.Chunks[i].Length ||
			hash.String() != want.Chunks[i].Hash || !bytes.Equal(hash[:], raw) {
			t.Fatalf("chunk %d differs: Go end=%d len=%d hash=%s raw=%x; Rust=%+v", i, got.End(), len(got.Data), hash, hash, want.Chunks[i])
		}
		nodes[i] = xethash.Node{Hash: hash, Size: uint64(len(got.Data))}
	}
	if got := xethash.Xorb(nodes).String(); got != want.XorbHash {
		t.Errorf("xorb hash = %s, Rust = %s", got, want.XorbHash)
	}
	if got := xethash.File(nodes).String(); got != want.FileHash {
		t.Errorf("file hash = %s, Rust = %s", got, want.FileHash)
	}
}
