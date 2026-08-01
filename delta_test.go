package xet

import (
	"bytes"
	"context"
	"testing"

	"github.com/jacobwoliver/xet-go/chunker"
	"github.com/jacobwoliver/xet-go/shard"
	"github.com/jacobwoliver/xet-go/xetcas"
	"github.com/jacobwoliver/xet-go/xethash"
)

func TestUploadDeltaReusesStableOriginalTerms(t *testing.T) {
	protocol := newMemoryProtocol()
	client := newTestEngine(t, protocol)
	originalData := deterministicData(4 << 20)
	original, err := client.UploadBytes(context.Background(), originalData)
	if err != nil {
		t.Fatal(err)
	}
	replacement := bytes.Repeat([]byte("resized-delta-edit"), 40)
	editStart, editEnd := uint64(100), uint64(180)
	expected := make([]byte, 0, len(originalData)-int(editEnd-editStart)+len(replacement))
	expected = append(expected, originalData[:editStart]...)
	expected = append(expected, replacement...)
	expected = append(expected, originalData[editEnd:]...)

	originalChunks := chunker.Bytes(originalData)
	modifiedChunks := chunker.Bytes(expected)
	originalSplit, modifiedSplit, originalBoundary := findStableSharedSuffix(
		t, originalChunks, modifiedChunks, int64(len(replacement))-int64(editEnd-editStart),
	)
	if originalSplit == 0 || originalSplit == len(originalChunks) {
		t.Fatal("test data did not produce an interior stable suffix")
	}

	protocol.mu.Lock()
	metadataFile := &protocol.metadata.Files[0]
	originalXorb := metadataFile.Terms[0].XorbHash
	firstBytes := chunkBytes(originalChunks[:originalSplit])
	secondBytes := chunkBytes(originalChunks[originalSplit:])
	firstHashes := chunkHashes(originalChunks[:originalSplit])
	secondHashes := chunkHashes(originalChunks[originalSplit:])
	metadataFile.Terms = []shard.Term{
		{XorbHash: originalXorb, UnpackedBytes: uint32(firstBytes), Start: 0, End: uint32(originalSplit), Verification: xethash.Verification(firstHashes)},
		{XorbHash: originalXorb, UnpackedBytes: uint32(secondBytes), Start: uint32(originalSplit), End: uint32(len(originalChunks)), Verification: xethash.Verification(secondHashes)},
	}
	gapNodes := make([]xethash.Node, len(originalChunks)-originalSplit)
	for i, value := range originalChunks[originalSplit:] {
		gapNodes[i] = xethash.Node{Hash: xethash.Chunk(value.Data), Size: uint64(len(value.Data))}
	}
	protocol.fileChunks = &xetcas.FileChunkHashesResponse{
		TotalChunks: uint64(len(originalChunks)),
		FileSize:    uint64(len(originalData)),
		Windows: []xetcas.ChunkWindow{{
			DirtyByteRange: [2]uint64{0, uint64(originalBoundary)},
		}},
		HashRanges:      []*xethash.MerkleHashSubtree{nil, xethash.NewSubtree(false, gapNodes, true)},
		GapVerification: []xethash.Hash{xethash.Verification(secondHashes)},
	}
	protocol.mu.Unlock()

	result, err := client.UploadDelta(context.Background(), original.File, []DeltaEdit{{
		Original: xetcas.FileRange{Start: editStart, End: editEnd},
		Reader:   bytes.NewReader(replacement), NewLength: uint64(len(replacement)),
	}})
	if err != nil {
		t.Fatal(err)
	}
	if result.File.Size != uint64(len(expected)) || result.Report.Dedup.NewBytes != uint64(chunkBytes(modifiedChunks[:modifiedSplit])) ||
		result.Report.Dedup.NewBytes >= result.File.Size || !result.Report.ShardUploaded {
		t.Fatalf("unexpected delta result: %#v", result)
	}
	expectedNodes := make([]xethash.Node, len(modifiedChunks))
	for i, value := range modifiedChunks {
		expectedNodes[i] = xethash.Node{Hash: xethash.Chunk(value.Data), Size: uint64(len(value.Data))}
	}
	if result.File.Hash != xethash.File(expectedNodes) {
		t.Fatalf("delta hash %s, full rechunk hash %s", result.File.Hash, xethash.File(expectedNodes))
	}
	protocol.mu.Lock()
	composed := *protocol.metadata
	protocol.mu.Unlock()
	if len(composed.Files) != 1 || len(composed.Files[0].Terms) < 2 ||
		composed.Files[0].Terms[len(composed.Files[0].Terms)-1].XorbHash != originalXorb {
		t.Fatalf("delta shard did not retain original term: %#v", composed.Files)
	}
	var output bytes.Buffer
	if _, err := client.Download(context.Background(), result.File, &output); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(output.Bytes(), expected) {
		t.Fatal("delta reconstruction differs from expected edited bytes")
	}
}

func findStableSharedSuffix(
	t *testing.T,
	original, modified []chunker.Chunk,
	offsetDelta int64,
) (int, int, int64) {
	t.Helper()
	originalOffset := int64(0)
	for originalIndex, chunk := range original {
		originalOffset += int64(len(chunk.Data))
		if originalIndex < 4 || len(original)-originalIndex < 4 {
			continue
		}
		modifiedOffset := int64(0)
		for modifiedIndex, candidate := range modified {
			modifiedOffset += int64(len(candidate.Data))
			if modifiedOffset != originalOffset+offsetDelta {
				continue
			}
			if equalChunkSuffix(original[originalIndex+1:], modified[modifiedIndex+1:]) {
				return originalIndex + 1, modifiedIndex + 1, originalOffset
			}
		}
	}
	t.Fatal("no shared stable chunk suffix found")
	return 0, 0, 0
}

func equalChunkSuffix(first, second []chunker.Chunk) bool {
	if len(first) != len(second) {
		return false
	}
	for i := range first {
		if len(first[i].Data) != len(second[i].Data) || xethash.Chunk(first[i].Data) != xethash.Chunk(second[i].Data) {
			return false
		}
	}
	return true
}

func chunkBytes(chunks []chunker.Chunk) int {
	total := 0
	for _, chunk := range chunks {
		total += len(chunk.Data)
	}
	return total
}

func chunkHashes(chunks []chunker.Chunk) []xethash.Hash {
	result := make([]xethash.Hash, len(chunks))
	for i, chunk := range chunks {
		result[i] = xethash.Chunk(chunk.Data)
	}
	return result
}

func TestUploadDeltaValidatesEdits(t *testing.T) {
	client := newTestEngine(t, newMemoryProtocol())
	original := FileInfo{Hash: xethash.Chunk([]byte("original")), Size: 100}
	cases := [][]DeltaEdit{
		{{Original: xetcas.FileRange{Start: 20, End: 10}}},
		{{Original: xetcas.FileRange{Start: 0, End: 101}}},
		{{Original: xetcas.FileRange{Start: 0, End: 10}}, {Original: xetcas.FileRange{Start: 9, End: 20}}},
		{{Original: xetcas.FileRange{Start: 0, End: 1}, NewLength: 1}},
	}
	for i, edits := range cases {
		if _, err := client.UploadDelta(context.Background(), original, edits); err == nil {
			t.Fatalf("accepted invalid delta case %d", i)
		}
	}
}

func TestUploadDeltaEmptyOriginalUsesFreshUpload(t *testing.T) {
	protocol := newMemoryProtocol()
	client := newTestEngine(t, protocol)
	first := []byte("inserted-at-empty-start")
	second := bytes.Repeat([]byte{7}, 10_000)
	result, err := client.UploadDelta(context.Background(), FileInfo{Hash: xethash.Zero}, []DeltaEdit{
		{Original: xetcas.FileRange{}, Reader: bytes.NewReader(first), NewLength: uint64(len(first))},
		{Original: xetcas.FileRange{}, Reader: bytes.NewReader(second), NewLength: uint64(len(second))},
	})
	if err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	if _, err := client.Download(context.Background(), result.File, &output); err != nil {
		t.Fatal(err)
	}
	want := append(append([]byte(nil), first...), second...)
	if !bytes.Equal(output.Bytes(), want) {
		t.Fatal("fresh delta upload differs")
	}
	if _, err := client.UploadDelta(context.Background(), FileInfo{}, []DeltaEdit{{
		Original: xetcas.FileRange{}, Reader: bytes.NewReader([]byte("short")), NewLength: 100,
	}}); err == nil {
		t.Fatal("accepted a short fresh delta reader")
	}
}
