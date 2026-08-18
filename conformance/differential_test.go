package conformance_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/jmwoliver/xet-go/chunker"
	"github.com/jmwoliver/xet-go/shard"
	"github.com/jmwoliver/xet-go/xethash"
	"github.com/jmwoliver/xet-go/xorb"
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

type encodedShard struct {
	BodyHex     string `json:"body_hex"`
	FullBodyHex string `json:"full_body_hex"`
	FileHash    string `json:"file_hash"`
	XorbHash    string `json:"xorb_hash"`
}

type decodedShard struct {
	Files        int  `json:"files"`
	Xorbs        int  `json:"xorbs"`
	Verification bool `json:"verification"`
}

type acceptanceRecord struct {
	Accepted bool `json:"accepted"`
}

type artifactAcceptanceCase struct {
	Body []byte
	Go   bool
	Rust bool
}

type oracleCorpus struct {
	Size     int           `json:"size"`
	Chunks   []oracleChunk `json:"chunks"`
	XorbHash string        `json:"xorb_hash"`
	FileHash string        `json:"file_hash"`
}

type subtreeRecord struct {
	Full      json.RawMessage `json:"full"`
	Left      json.RawMessage `json:"left"`
	Right     json.RawMessage `json:"right"`
	Merged    json.RawMessage `json:"merged"`
	FinalHash string          `json:"final_hash"`
}

func TestRustDifferentialMerkleSubtree(t *testing.T) {
	oracle := os.Getenv("XET_RUST_ORACLE")
	if oracle == "" {
		t.Skip("set XET_RUST_ORACLE to the binary produced by conformance/build-rust-oracle.sh")
	}
	data := make([]byte, 8<<20)
	rng := rand.New(rand.NewSource(0x53554254524545))
	_, _ = rng.Read(data)
	parts := chunker.Bytes(data)
	split := len(parts) / 3
	path := filepath.Join(t.TempDir(), "input.bin")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	output, err := exec.Command(oracle, "subtree", path, fmt.Sprint(split)).CombinedOutput()
	if err != nil {
		t.Fatalf("Rust subtree: %v\n%s", err, output)
	}
	var rust subtreeRecord
	if err := json.Unmarshal(output, &rust); err != nil {
		t.Fatal(err)
	}
	nodes := make([]xethash.Node, len(parts))
	for i, part := range parts {
		nodes[i] = xethash.Node{Hash: xethash.Chunk(part.Data), Size: uint64(len(part.Data))}
	}
	left := xethash.NewSubtree(true, nodes[:split], false)
	right := xethash.NewSubtree(false, nodes[split:], true)
	full := xethash.NewSubtree(true, nodes, true)
	merged, err := xethash.MergeSubtrees(left, right)
	if err != nil {
		t.Fatal(err)
	}
	comparisons := []struct {
		name   string
		goTree *xethash.MerkleHashSubtree
		rust   json.RawMessage
	}{{"full", full, rust.Full}, {"left", left, rust.Left}, {"right", right, rust.Right}, {"merged", merged, rust.Merged}}
	for _, comparison := range comparisons {
		goJSON, err := json.Marshal(comparison.goTree)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(goJSON, comparison.rust) {
			t.Fatalf("%s subtree JSON differs\nGo:   %s\nRust: %s", comparison.name, goJSON, comparison.rust)
		}
	}
	final, ok := merged.FinalHash()
	if !ok || final.String() != rust.FinalHash {
		t.Fatalf("subtree final hash %s,%v; Rust %s", final, ok, rust.FinalHash)
	}
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
		{name: "auto", goID: xorb.Auto},
	}
	for inputIndex, data := range inputs {
		for _, scheme := range schemes {
			t.Logf("comparing input %d with %s", inputIndex, scheme.name)
			compareXorb(t, oracle, data, scheme.name, scheme.goID)
		}
	}
}

func TestRustDifferentialCompleteXorb(t *testing.T) {
	oracle := os.Getenv("XET_RUST_ORACLE")
	if oracle == "" {
		t.Skip("set XET_RUST_ORACLE to the binary produced by conformance/build-rust-oracle.sh")
	}
	data := bytes.Repeat([]byte("official-complete-xorb-vector"), 10_000)
	path := filepath.Join(t.TempDir(), "input.bin")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	output, err := exec.Command(oracle, "encode-xorb-complete", path, "none").CombinedOutput()
	if err != nil {
		t.Fatalf("Rust complete encode: %v\n%s", err, output)
	}
	var rust encodedXorb
	if err := json.Unmarshal(output, &rust); err != nil {
		t.Fatal(err)
	}
	rustBody, err := hex.DecodeString(rust.BodyHex)
	if err != nil {
		t.Fatal(err)
	}
	rustDecoded, err := xorb.Decode(rustBody)
	if err != nil {
		t.Fatalf("Go decode of Rust complete xorb: %v", err)
	}
	if rustDecoded.Footer == nil || !bytes.Equal(joinXorb(rustDecoded), data) {
		t.Fatal("Go decode of Rust complete xorb differs")
	}
	parts := chunker.Bytes(data)
	chunks := make([][]byte, len(parts))
	for i := range parts {
		chunks[i] = parts[i].Data
	}
	goObject, err := xorb.Encode(chunks, xorb.None)
	if err != nil {
		t.Fatal(err)
	}
	ingested, err := xorb.IngestNetwork(goObject.Body, goObject.Hash)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(ingested.Complete, rustBody) {
		t.Fatalf("ingested complete xorb differs byte-for-byte: Go %d bytes, Rust %d", len(ingested.Complete), len(rustBody))
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
	if len(goEncoded.Chunks) != len(rustDecoded.Chunks) {
		t.Fatalf("%s xorb chunk count differs", schemeName)
	}
	for i := range goEncoded.Chunks {
		if goEncoded.Chunks[i].Scheme != rustDecoded.Chunks[i].Scheme {
			t.Fatalf("%s xorb chunk %d selected scheme %s, Rust selected %s", schemeName, i,
				goEncoded.Chunks[i].Scheme, rustDecoded.Chunks[i].Scheme)
		}
	}
	// LZ4 permits multiple conforming compressed representations. The raw form
	// is deterministic and must match byte-for-byte; compressed forms are
	// compared by selected scheme and bidirectional decoding above.
	if schemeID == xorb.None && !bytes.Equal(goEncoded.Body, rustBody) {
		first := 0
		for first < len(goEncoded.Body) && first < len(rustBody) && goEncoded.Body[first] == rustBody[first] {
			first++
		}
		goEnd := min(first+24, len(goEncoded.Body))
		rustEnd := min(first+24, len(rustBody))
		t.Fatalf("%s xorb encoding differs byte-for-byte at %d (Go len=%d bytes=%x; Rust len=%d bytes=%x)",
			schemeName, first, len(goEncoded.Body), goEncoded.Body[first:goEnd], len(rustBody), rustBody[first:rustEnd])
	}
}

func joinXorb(object *xorb.Object) []byte {
	var out []byte
	for _, chunk := range object.Chunks {
		out = append(out, chunk.Data...)
	}
	return out
}

func TestRustDifferentialShard(t *testing.T) {
	oracle := os.Getenv("XET_RUST_ORACLE")
	if oracle == "" {
		t.Skip("set XET_RUST_ORACLE to the binary produced by conformance/build-rust-oracle.sh")
	}
	rng := rand.New(rand.NewSource(119))
	data := make([]byte, 2<<20)
	_, _ = rng.Read(data)
	inputPath := filepath.Join(t.TempDir(), "input.bin")
	if err := os.WriteFile(inputPath, data, 0o600); err != nil {
		t.Fatal(err)
	}
	output, err := exec.Command(oracle, "encode-shard", inputPath).CombinedOutput()
	if err != nil {
		t.Fatalf("Rust encode shard: %v\n%s", err, output)
	}
	var rust encodedShard
	if err := json.Unmarshal(output, &rust); err != nil {
		t.Fatal(err)
	}
	rustBody, err := hex.DecodeString(rust.BodyHex)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := shard.Decode(rustBody); err != nil {
		t.Fatalf("Go decode of Rust shard: %v", err)
	}
	fullBody, err := hex.DecodeString(rust.FullBodyHex)
	if err != nil {
		t.Fatal(err)
	}
	fullShard, err := shard.Decode(fullBody)
	if err != nil {
		t.Fatalf("Go decode of full Rust shard: %v", err)
	}
	if fullShard.Footer == nil {
		t.Fatal("full Rust shard footer was not decoded")
	}

	parts := chunker.Bytes(data)
	chunkData := make([][]byte, len(parts))
	nodes := make([]xethash.Node, len(parts))
	hashes := make([]xethash.Hash, len(parts))
	for i := range parts {
		chunkData[i] = parts[i].Data
		hashes[i] = xethash.Chunk(parts[i].Data)
		nodes[i] = xethash.Node{Hash: hashes[i], Size: uint64(len(parts[i].Data))}
	}
	object, err := xorb.Encode(chunkData, xorb.None)
	if err != nil {
		t.Fatal(err)
	}
	xorbInfo, err := shard.XorbFromObject(object)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(data)
	goBody, err := shard.EncodeUpload(shard.Shard{
		Files: []shard.File{{
			Hash: xethash.File(nodes),
			Terms: []shard.Term{{
				XorbHash: object.Hash, UnpackedBytes: uint32(len(data)), Start: 0, End: uint32(len(parts)),
				Verification: xethash.Verification(hashes),
			}},
			SHA256: &sum,
		}},
		Xorbs: []shard.Xorb{xorbInfo},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(goBody, rustBody) {
		first := firstDifference(goBody, rustBody)
		t.Fatalf("upload shard differs byte-for-byte at %d: Go %d bytes (%x), Rust %d (%x)",
			first, len(goBody), goBody[first:min(first+32, len(goBody))], len(rustBody), rustBody[first:min(first+32, len(rustBody))])
	}
	goFullBody, err := shard.EncodeFull(shard.Shard{
		Files: []shard.File{{
			Hash: xethash.File(nodes),
			Terms: []shard.Term{{
				XorbHash: object.Hash, UnpackedBytes: uint32(len(data)), Start: 0, End: uint32(len(parts)),
				Verification: xethash.Verification(hashes),
			}},
			SHA256: &sum,
		}},
		Xorbs: []shard.Xorb{xorbInfo},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(goFullBody, fullBody) {
		first := firstDifference(goFullBody, fullBody)
		t.Fatalf("full shard differs byte-for-byte at %d: Go %d bytes (%x), Rust %d (%x)",
			first, len(goFullBody), goFullBody[first:min(first+32, len(goFullBody))], len(fullBody), fullBody[first:min(first+32, len(fullBody))])
	}
	shardPath := filepath.Join(t.TempDir(), "upload.mdb")
	if err := os.WriteFile(shardPath, goBody, 0o600); err != nil {
		t.Fatal(err)
	}
	output, err = exec.Command(oracle, "decode-shard", shardPath).CombinedOutput()
	if err != nil {
		t.Fatalf("Rust decode of Go shard: %v\n%s", err, output)
	}
	var decoded decodedShard
	if err := json.Unmarshal(output, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Files != 1 || decoded.Xorbs != 1 || !decoded.Verification {
		t.Fatalf("Rust decoded shard = %+v", decoded)
	}
	protected, err := shard.EncodeProtectedDedup(shard.Shard{
		Files: []shard.File{{
			Hash: xethash.File(nodes),
			Terms: []shard.Term{{
				XorbHash: object.Hash, UnpackedBytes: uint32(len(data)), Start: 0, End: uint32(len(parts)),
				Verification: xethash.Verification(hashes),
			}},
			SHA256: &sum,
		}},
		Xorbs: []shard.Xorb{xorbInfo},
	}, xethash.Chunk([]byte("rust protected shard decode key")), 100, 200)
	if err != nil {
		t.Fatal(err)
	}
	protectedPath := filepath.Join(t.TempDir(), "protected.mdb")
	if err := os.WriteFile(protectedPath, protected, 0o600); err != nil {
		t.Fatal(err)
	}
	output, err = exec.Command(oracle, "decode-shard", protectedPath).CombinedOutput()
	if err != nil {
		t.Fatalf("Rust decode of Go protected shard: %v\n%s", err, output)
	}
	if err := json.Unmarshal(output, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Files != 0 || decoded.Xorbs != 1 {
		t.Fatalf("Rust decoded protected shard = %+v", decoded)
	}
}

func firstDifference(left, right []byte) int {
	limit := min(len(left), len(right))
	for index := 0; index < limit; index++ {
		if left[index] != right[index] {
			return index
		}
	}
	return limit
}

func TestRustDifferentialArtifactAcceptance(t *testing.T) {
	oracle := os.Getenv("XET_RUST_ORACLE")
	if oracle == "" {
		t.Skip("set XET_RUST_ORACLE to the binary produced by conformance/build-rust-oracle.sh")
	}

	object, err := xorb.Encode([][]byte{bytes.Repeat([]byte("negative-xorb-vector"), 4096)}, xorb.LZ4)
	if err != nil {
		t.Fatal(err)
	}
	xorbCases := map[string]artifactAcceptanceCase{
		"valid":                   {Body: object.Body, Go: true, Rust: true},
		"empty":                   {Body: []byte{}, Go: false, Rust: true},
		"short header":            {Body: object.Body[:xorb.HeaderSize-1], Go: false, Rust: false},
		"truncated payload":       {Body: object.Body[:len(object.Body)-1], Go: false, Rust: true},
		"trailing partial header": {Body: append(append([]byte(nil), object.Body...), 0), Go: false, Rust: false},
	}
	invalidVersion := append([]byte(nil), object.Body...)
	invalidVersion[0] = 1
	xorbCases["unsupported version"] = artifactAcceptanceCase{Body: invalidVersion, Go: false, Rust: false}
	invalidScheme := append([]byte(nil), object.Body...)
	invalidScheme[4] = 9
	xorbCases["unsupported scheme"] = artifactAcceptanceCase{Body: invalidScheme, Go: false, Rust: false}
	zeroCompressed := append([]byte(nil), object.Body...)
	clear(zeroCompressed[1:4])
	xorbCases["zero compressed length"] = artifactAcceptanceCase{Body: zeroCompressed, Go: false, Rust: false}
	zeroUncompressed := append([]byte(nil), object.Body...)
	clear(zeroUncompressed[5:8])
	xorbCases["zero uncompressed length"] = artifactAcceptanceCase{Body: zeroUncompressed, Go: false, Rust: false}
	for name, test := range xorbCases {
		t.Run("Xorb/"+name, func(t *testing.T) {
			compareArtifactAcceptance(t, oracle, "accept-xorb", test, func() error {
				_, err := xorb.Decode(test.Body)
				return err
			})
		})
	}

	parts := chunker.Bytes(bytes.Repeat([]byte("negative-shard-vector"), 20_000))
	chunks := make([][]byte, len(parts))
	for i := range parts {
		chunks[i] = parts[i].Data
	}
	shardXorb, err := xorb.Encode(chunks, xorb.None)
	if err != nil {
		t.Fatal(err)
	}
	xorbInfo, err := shard.XorbFromObject(shardXorb)
	if err != nil {
		t.Fatal(err)
	}
	logical := shard.Shard{Xorbs: []shard.Xorb{xorbInfo}}
	uploadShard, err := shard.EncodeUpload(logical)
	if err != nil {
		t.Fatal(err)
	}
	fullShard, err := shard.EncodeFull(logical)
	if err != nil {
		t.Fatal(err)
	}
	shardCases := map[string]artifactAcceptanceCase{
		"valid upload":         {Body: uploadShard, Go: true, Rust: true},
		"valid full":           {Body: fullShard, Go: true, Rust: true},
		"empty":                {Body: []byte{}, Go: false, Rust: false},
		"short header":         {Body: uploadShard[:shard.HeaderSize-1], Go: false, Rust: false},
		"truncated upload":     {Body: uploadShard[:len(uploadShard)-1], Go: false, Rust: false},
		"truncated full":       {Body: fullShard[:len(fullShard)-1], Go: false, Rust: true},
		"trailing upload data": {Body: append(append([]byte(nil), uploadShard...), 0), Go: false, Rust: true},
	}
	wrongMagic := append([]byte(nil), uploadShard...)
	wrongMagic[0] ^= 1
	shardCases["wrong magic"] = artifactAcceptanceCase{Body: wrongMagic, Go: false, Rust: false}
	wrongVersion := append([]byte(nil), uploadShard...)
	wrongVersion[32]++
	shardCases["unsupported version"] = artifactAcceptanceCase{Body: wrongVersion, Go: false, Rust: true}
	invalidFooterSize := append([]byte(nil), uploadShard...)
	invalidFooterSize[40] = 1
	shardCases["invalid footer size"] = artifactAcceptanceCase{Body: invalidFooterSize, Go: false, Rust: true}
	for name, test := range shardCases {
		t.Run("shard/"+name, func(t *testing.T) {
			compareArtifactAcceptance(t, oracle, "accept-shard", test, func() error {
				_, err := shard.Decode(test.Body)
				return err
			})
		})
	}
}

func compareArtifactAcceptance(
	t testing.TB,
	oracle string,
	mode string,
	test artifactAcceptanceCase,
	goDecode func() error,
) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "artifact.bin")
	if err := os.WriteFile(path, test.Body, 0o600); err != nil {
		t.Fatal(err)
	}
	output, err := exec.Command(oracle, mode, path).CombinedOutput()
	if err != nil {
		t.Fatalf("Rust %s: %v\n%s", mode, err, output)
	}
	var rust acceptanceRecord
	if err := json.Unmarshal(output, &rust); err != nil {
		t.Fatalf("decode Rust %s result: %v\n%s", mode, err, output)
	}
	goAccepted := goDecode() == nil
	if goAccepted != test.Go || rust.Accepted != test.Rust {
		t.Fatalf("artifact acceptance changed: Go accepted=%v (want %v), Rust accepted=%v (want %v)",
			goAccepted, test.Go, rust.Accepted, test.Rust)
	}
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
