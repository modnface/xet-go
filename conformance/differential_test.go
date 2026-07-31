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
)

type oracleChunk struct {
	End    int    `json:"end"`
	Length int    `json:"len"`
	Hash   string `json:"hash"`
	RawHex string `json:"raw_hex"`
}

type oracleCorpus struct {
	Size     int           `json:"size"`
	Chunks   []oracleChunk `json:"chunks"`
	XorbHash string        `json:"xorb_hash"`
	FileHash string        `json:"file_hash"`
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
