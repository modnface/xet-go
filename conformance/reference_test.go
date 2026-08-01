package conformance_test

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"github.com/jacobwoliver/xet-go/chunker"
	"github.com/jacobwoliver/xet-go/shard"
	"github.com/jacobwoliver/xet-go/xethash"
	"github.com/jacobwoliver/xet-go/xorb"
)

const (
	referenceFileName  = "Electric_Vehicle_Population_Data_20250917.csv"
	referenceFileHash  = "118a53328412787fee04011dcf82fdc4acf3a4a1eddec341c910d30a306aaf97"
	referenceXorbHash  = "eea25d6ee393ccae385820daed127b96ef0ea034dfb7cf6da3a950ce334b7632"
	referenceRangeHash = "d81c11b1fc9bc2a25587108c675bbfe65ca2e5d350b0cd92c58329fcc8444178"
)

type referenceManifest struct {
	SchemaVersion int                     `json:"schema_version"`
	Repository    string                  `json:"repository"`
	Revision      string                  `json:"revision"`
	Files         []referenceManifestFile `json:"files"`
}

type referenceManifestFile struct {
	Name   string `json:"name"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

type referenceChunk struct {
	Hash   xethash.Hash
	Length int
}

func TestOfficialReferenceCorpus(t *testing.T) {
	directory := os.Getenv("XET_REFERENCE_FIXTURES")
	if directory == "" {
		t.Skip("set XET_REFERENCE_FIXTURES to the output directory from fetch-reference-fixtures.sh")
	}
	directory, err := filepath.Abs(directory)
	if err != nil {
		t.Fatal(err)
	}
	manifest := loadReferenceManifest(t)
	t.Run("integrity", func(t *testing.T) {
		verifyReferenceIntegrity(t, directory, manifest)
	})

	chunkList := readReferenceChunks(t, filepath.Join(directory, referenceFileName+".chunks"))
	if len(chunkList) != 796 {
		t.Fatalf("official chunk count = %d, want 796", len(chunkList))
	}
	xorbChunkList, err := os.ReadFile(filepath.Join(directory, referenceXorbHash+".xorb.chunks"))
	if err != nil {
		t.Fatal(err)
	}
	fileChunkList, err := os.ReadFile(filepath.Join(directory, referenceFileName+".chunks"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(fileChunkList, xorbChunkList) {
		t.Fatal("official file and xorb chunk manifests differ")
	}

	t.Run("chunking_and_hashes", func(t *testing.T) {
		verifyReferenceChunking(t, filepath.Join(directory, referenceFileName), chunkList)
	})
	t.Run("reference_xorb", func(t *testing.T) {
		verifyReferenceXorb(t, directory, chunkList)
	})
	t.Run("shards", func(t *testing.T) {
		verifyReferenceShards(t, directory, chunkList)
	})
	t.Run("standalone_chunks", func(t *testing.T) {
		for _, expected := range chunkList[:3] {
			path := filepath.Join(directory, expected.Hash.String()+".chunk")
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if len(data) != expected.Length || xethash.Chunk(data) != expected.Hash {
				t.Errorf("%s does not match its official length and Xet hash", filepath.Base(path))
			}
		}
	})
}

func loadReferenceManifest(t *testing.T) referenceManifest {
	t.Helper()
	_, source, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate reference manifest")
	}
	data, err := os.ReadFile(filepath.Join(filepath.Dir(source), "reference-manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var manifest referenceManifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		t.Fatal(err)
	}
	if manifest.SchemaVersion != 1 || manifest.Revision != "c4aa3a3f15b1395fff5ce934784bf6c8f2d62de8" || len(manifest.Files) == 0 {
		t.Fatalf("unexpected official reference manifest metadata: %+v", manifest)
	}
	return manifest
}

func verifyReferenceIntegrity(t *testing.T, directory string, manifest referenceManifest) {
	t.Helper()
	for _, expected := range manifest.Files {
		expected := expected
		t.Run(expected.Name, func(t *testing.T) {
			path := filepath.Join(directory, expected.Name)
			input, err := os.Open(path)
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				if err := input.Close(); err != nil {
					t.Error(err)
				}
			}()
			info, err := input.Stat()
			if err != nil {
				t.Fatal(err)
			}
			if info.Size() != expected.Size {
				t.Fatalf("size = %d, want %d (an LFS pointer may have been supplied)", info.Size(), expected.Size)
			}
			hash := sha256.New()
			if _, err := io.Copy(hash, input); err != nil {
				t.Fatal(err)
			}
			if got := hex.EncodeToString(hash.Sum(nil)); got != expected.SHA256 {
				t.Fatalf("SHA-256 = %s, want %s", got, expected.SHA256)
			}
		})
	}
}

func readReferenceChunks(t *testing.T, path string) []referenceChunk {
	t.Helper()
	input, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := input.Close(); err != nil {
			t.Error(err)
		}
	}()
	var chunks []referenceChunk
	scanner := bufio.NewScanner(input)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) != 2 {
			t.Fatalf("malformed official chunk line %q", scanner.Text())
		}
		hash, err := xethash.Parse(fields[0])
		if err != nil {
			t.Fatal(err)
		}
		length, err := strconv.Atoi(fields[1])
		if err != nil || length < chunker.MinSize || length > chunker.MaxSize {
			t.Fatalf("invalid official chunk length %q", fields[1])
		}
		chunks = append(chunks, referenceChunk{Hash: hash, Length: length})
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	return chunks
}

func verifyReferenceChunking(t *testing.T, path string, expected []referenceChunk) {
	t.Helper()
	input, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := input.Close(); err != nil {
			t.Error(err)
		}
	}()
	nodes := make([]xethash.Node, 0, len(expected))
	hashes := make([]xethash.Hash, 0, len(expected))
	index := 0
	err = chunker.Split(input, func(chunk chunker.Chunk) error {
		if index >= len(expected) {
			return fmt.Errorf("Go emitted unexpected chunk %d", index)
		}
		want := expected[index]
		gotHash := xethash.Chunk(chunk.Data)
		if len(chunk.Data) != want.Length || gotHash != want.Hash {
			return fmt.Errorf("chunk %d differs: length %d/%d, hash %s/%s", index, len(chunk.Data), want.Length, gotHash, want.Hash)
		}
		nodes = append(nodes, xethash.Node{Hash: gotHash, Size: uint64(len(chunk.Data))})
		hashes = append(hashes, gotHash)
		index++
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if index != len(expected) {
		t.Fatalf("Go emitted %d chunks, want %d", index, len(expected))
	}
	if got := xethash.File(nodes).String(); got != referenceFileHash {
		t.Errorf("file hash = %s, want %s", got, referenceFileHash)
	}
	if got := xethash.Xorb(nodes).String(); got != referenceXorbHash {
		t.Errorf("xorb hash = %s, want %s", got, referenceXorbHash)
	}
	if got := xethash.Verification(hashes).String(); got != referenceRangeHash {
		t.Errorf("range verification hash = %s, want %s", got, referenceRangeHash)
	}
}

func verifyReferenceXorb(t *testing.T, directory string, expected []referenceChunk) {
	t.Helper()
	body, err := os.ReadFile(filepath.Join(directory, referenceXorbHash+".xorb"))
	if err != nil {
		t.Fatal(err)
	}
	object, err := xorb.Decode(body)
	if err != nil {
		t.Fatal(err)
	}
	if !object.LegacyTrailer || object.Footer != nil || object.Hash.String() != referenceXorbHash || len(object.Chunks) != len(expected) {
		t.Fatalf("decoded official xorb metadata differs: legacy=%v footer=%v hash=%s chunks=%d",
			object.LegacyTrailer, object.Footer != nil, object.Hash, len(object.Chunks))
	}
	input, err := os.Open(filepath.Join(directory, referenceFileName))
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := input.Close(); err != nil {
			t.Error(err)
		}
	}()
	var offset uint32
	for i, chunk := range object.Chunks {
		want := expected[i]
		if chunk.Hash != want.Hash || chunk.UncompressedLength != uint32(want.Length) || chunk.UncompressedOffset != offset {
			t.Fatalf("official xorb chunk %d metadata differs", i)
		}
		data := make([]byte, want.Length)
		if _, err := io.ReadFull(input, data); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(data, chunk.Data) {
			t.Fatalf("official xorb chunk %d content differs from source file", i)
		}
		offset += uint32(want.Length)
	}
	var trailing [1]byte
	if n, err := input.Read(trailing[:]); n != 0 || !errors.Is(err, io.EOF) {
		t.Fatalf("source has trailing data after xorb reconstruction: n=%d err=%v", n, err)
	}
	assertHashFile(t, filepath.Join(directory, referenceFileName+".xet-file-hash"), referenceFileHash)
	assertHashFile(t, filepath.Join(directory, referenceFileName+".xet-xorb-hash"), referenceXorbHash)
	assertHashFile(t, filepath.Join(directory, referenceXorbHash+".xorb.range-hash"), referenceRangeHash)
}

func verifyReferenceShards(t *testing.T, directory string, expected []referenceChunk) {
	t.Helper()
	base := decodeReferenceShard(t, filepath.Join(directory, referenceFileName+".shard"))
	assertReferenceShardMetadata(t, base, expected, false)
	if base.Footer == nil {
		t.Fatal("base reference shard has no footer")
	}

	verified := decodeReferenceShard(t, filepath.Join(directory, referenceFileName+".shard.verification"))
	assertReferenceShardMetadata(t, verified, expected, true)
	if verified.Footer == nil {
		t.Fatal("verified reference shard has no footer")
	}

	footerlessPath := filepath.Join(directory, referenceFileName+".shard.verification-no-footer")
	footerlessBytes, err := os.ReadFile(footerlessPath)
	if err != nil {
		t.Fatal(err)
	}
	footerless, err := shard.Decode(footerlessBytes)
	if err != nil {
		t.Fatal(err)
	}
	assertReferenceShardMetadata(t, footerless, expected, true)
	if footerless.Footer != nil {
		t.Fatal("footerless reference shard unexpectedly has a footer")
	}
	// This legacy reference predates the mandatory serialized-byte field and
	// leaves it zero. Normalize that single field before comparing the current
	// canonical upload encoding.
	footerless.Xorbs[0].SerializedBytes = 14737817
	reencoded, err := shard.EncodeUpload(*footerless)
	if err != nil {
		t.Fatal(err)
	}
	normalizedFixture := append([]byte(nil), footerlessBytes...)
	const fixtureXorbHeaderOffset = 288
	binary.LittleEndian.PutUint32(normalizedFixture[fixtureXorbHeaderOffset+44:fixtureXorbHeaderOffset+48], 14737817)
	if !bytes.Equal(reencoded, normalizedFixture) {
		t.Fatal("Go upload-shard encoding differs from the normalized official footerless fixture")
	}

	dedupe := decodeReferenceShard(t, filepath.Join(directory, referenceFileName+".shard.dedupe"))
	key := xethash.MustParse("1234567812345678123456781234567812345678123456781234567812345678")
	if dedupe.Footer == nil || dedupe.Footer.ChunkProtectionKey != key || len(dedupe.Files) != 0 || len(dedupe.Xorbs) != 1 {
		t.Fatalf("official dedupe shard metadata differs: files=%d xorbs=%d footer=%v", len(dedupe.Files), len(dedupe.Xorbs), dedupe.Footer != nil)
	}
	if dedupe.Xorbs[0].Hash.String() != referenceXorbHash || len(dedupe.Xorbs[0].Chunks) != len(expected) {
		t.Fatal("official dedupe shard xorb metadata differs")
	}
	for i, chunk := range dedupe.Xorbs[0].Chunks {
		if chunk.Hash != xethash.Protect(expected[i].Hash, key) || chunk.Flags != 0 {
			t.Fatalf("protected dedupe chunk %d differs", i)
		}
	}
}

func decodeReferenceShard(t *testing.T, path string) *shard.Shard {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := shard.Decode(data)
	if err != nil {
		t.Fatal(err)
	}
	return decoded
}

func assertReferenceShardMetadata(t *testing.T, value *shard.Shard, expected []referenceChunk, verification bool) {
	t.Helper()
	if len(value.Files) != 1 || len(value.Xorbs) != 1 {
		t.Fatalf("reference shard has %d files and %d xorbs", len(value.Files), len(value.Xorbs))
	}
	file, object := value.Files[0], value.Xorbs[0]
	if file.Hash.String() != referenceFileHash || object.Hash.String() != referenceXorbHash || len(file.Terms) != 1 || len(object.Chunks) != len(expected) {
		t.Fatal("reference shard identities or counts differ")
	}
	term := file.Terms[0]
	if term.XorbHash != object.Hash || term.Start != 0 || term.End != uint32(len(expected)) || term.UnpackedBytes != object.RawBytes {
		t.Fatal("reference shard reconstruction term differs")
	}
	if verification {
		if term.Verification.String() != referenceRangeHash {
			t.Fatalf("reference shard verification hash = %s", term.Verification)
		}
	} else if !term.Verification.IsZero() {
		t.Fatalf("base reference shard unexpectedly has verification %s", term.Verification)
	}
	var offset uint32
	for i, chunk := range object.Chunks {
		if chunk.Hash != expected[i].Hash || chunk.Offset != offset || chunk.Length != uint32(expected[i].Length) {
			t.Fatalf("reference shard xorb chunk %d differs", i)
		}
		offset += chunk.Length
	}
	if object.RawBytes != offset || object.SerializedBytes != 0 {
		t.Fatalf("reference shard sizes = raw %d serialized %d", object.RawBytes, object.SerializedBytes)
	}
}

func assertHashFile(t *testing.T, path, expected string) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.TrimSpace(string(data)); got != expected {
		t.Fatalf("%s = %q, want %q", filepath.Base(path), got, expected)
	}
}
