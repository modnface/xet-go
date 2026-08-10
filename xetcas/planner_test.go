package xetcas

import (
	"bytes"
	"errors"
	"testing"

	"github.com/jacobwoliver/xet-go/chunker"
	"github.com/jacobwoliver/xet-go/shard"
	"github.com/jacobwoliver/xet-go/xethash"
	"github.com/jacobwoliver/xet-go/xorb"
)

func plannerFixture(t testing.TB, sizes []int, ranges []ChunkRange) (shard.RegisteredFile, *xorb.Ingested) {
	t.Helper()
	chunks := make([][]byte, len(sizes))
	for i, size := range sizes {
		chunks[i] = bytes.Repeat([]byte{byte(i + 1)}, size)
	}
	object, err := xorb.Encode(chunks, xorb.None)
	if err != nil {
		t.Fatal(err)
	}
	ingested, err := xorb.IngestNetwork(object.Body, object.Hash)
	if err != nil {
		t.Fatal(err)
	}
	nodes := make([]xethash.Node, len(chunks))
	for i := range chunks {
		nodes[i] = xethash.Node{Hash: object.Chunks[i].Hash, Size: uint64(len(chunks[i]))}
	}
	file := shard.File{Hash: xethash.File(nodes)}
	var total uint64
	for _, value := range ranges {
		var unpacked uint32
		hashes := make([]xethash.Hash, 0, value.Len())
		for i := value.Start; i < value.End; i++ {
			unpacked += uint32(sizes[i])
			hashes = append(hashes, object.Chunks[i].Hash)
		}
		file.Terms = append(file.Terms, shard.Term{
			XorbHash: object.Hash, UnpackedBytes: unpacked, Start: value.Start, End: value.End,
			Verification: xethash.Verification(hashes),
		})
		total += uint64(unpacked)
	}
	return shard.RegisteredFile{File: file, Size: total}, ingested
}

func layoutLookup(want *xorb.Ingested) XorbLayoutLookup {
	return func(hash xethash.Hash) (*xorb.Ingested, bool, error) {
		return want, hash == want.Hash, nil
	}
}

func TestPlanReconstructionMatchesRustRangeCropping(t *testing.T) {
	file, layout := plannerFixture(t, []int{100, 200, 300}, []ChunkRange{{Start: 0, End: 3}})
	plan, err := PlanReconstruction(file, &FileRange{Start: 150, End: 600}, layoutLookup(layout))
	if err != nil {
		t.Fatal(err)
	}
	if plan.OffsetIntoFirstRange != 50 || len(plan.Terms) != 1 ||
		plan.Terms[0].Range != (ChunkRange{Start: 1, End: 3}) || plan.Terms[0].UnpackedLength != 500 {
		t.Fatalf("partial plan = %#v", plan)
	}
	ranges := plan.Xorbs[layout.Hash]
	wantEnd := uint64(layout.Chunks[2].SerializedOffset+layout.Chunks[2].SerializedLength) - 1
	if len(ranges) != 1 || ranges[0].Bytes.Start != uint64(layout.Chunks[1].SerializedOffset) || ranges[0].Bytes.End != wantEnd {
		t.Fatalf("partial serialized ranges = %#v", ranges)
	}

	plan, err = PlanReconstruction(file, &FileRange{Start: 100, End: 300}, layoutLookup(layout))
	if err != nil {
		t.Fatal(err)
	}
	if plan.OffsetIntoFirstRange != 0 || plan.Terms[0].Range != (ChunkRange{Start: 1, End: 2}) ||
		plan.Terms[0].UnpackedLength != 200 {
		t.Fatalf("boundary plan = %#v", plan)
	}
}

func TestPlanReconstructionMergesRangesAndHandlesBounds(t *testing.T) {
	file, layout := plannerFixture(t, []int{100, 100, 100, 100}, []ChunkRange{{0, 2}, {2, 4}})
	plan, err := PlanReconstruction(file, nil, layoutLookup(layout))
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Terms) != 2 || len(plan.Xorbs[layout.Hash]) != 1 ||
		plan.Xorbs[layout.Hash][0].Chunks != (ChunkRange{0, 4}) {
		t.Fatalf("merged plan = %#v", plan)
	}
	if _, err := PlanReconstruction(file, &FileRange{Start: file.Size, End: file.Size + 1}, layoutLookup(layout)); !errors.Is(err, ErrRangeNotSatisfiable) {
		t.Fatalf("out-of-bounds error = %v", err)
	}
	empty, err := PlanReconstruction(shard.RegisteredFile{}, &FileRange{Start: 0, End: 1}, layoutLookup(layout))
	if err != nil || len(empty.Terms) != 0 || len(empty.Xorbs) != 0 {
		t.Fatalf("empty plan = %#v, %v", empty, err)
	}
}

func TestPlanReconstructionRejectsUnusableRecipes(t *testing.T) {
	file, layout := plannerFixture(t, []int{100}, []ChunkRange{{0, 1}})
	if _, err := PlanReconstruction(file, nil, nil); err == nil {
		t.Fatal("nil layout lookup succeeded")
	}
	wrongSize := file
	wrongSize.Size++
	if _, err := PlanReconstruction(wrongSize, nil, layoutLookup(layout)); err == nil {
		t.Fatal("recipe size mismatch succeeded")
	}
	if _, err := PlanReconstruction(shard.RegisteredFile{Size: 1}, nil, layoutLookup(layout)); err == nil {
		t.Fatal("non-empty file without terms succeeded")
	}
}

func TestPlanFileChunkHashesMatchesRustStableWindow(t *testing.T) {
	stable := 2 * chunker.MinSize
	file, layout := plannerFixture(t,
		[]int{stable, stable, stable, stable, stable, stable},
		[]ChunkRange{{0, 4}, {4, 6}},
	)
	response, err := PlanFileChunkHashes(file, []FileRange{{Start: 1, End: uint64(stable + 1)}}, layoutLookup(layout))
	if err != nil {
		t.Fatal(err)
	}
	if response.TotalChunks != 6 || response.FileSize != uint64(6*stable) || len(response.Windows) != 1 ||
		response.Windows[0].DirtyByteRange != [2]uint64{0, uint64(4 * stable)} {
		t.Fatalf("delta windows = %#v", response)
	}
	if len(response.HashRanges) != 2 || response.HashRanges[0] != nil || response.HashRanges[1] == nil ||
		len(response.GapVerification) != 1 || response.GapVerification[0] != file.File.Terms[1].Verification {
		t.Fatalf("delta gaps = %#v", response)
	}
}

func TestPlanFileChunkHashesContracts(t *testing.T) {
	file, layout := plannerFixture(t, []int{100, 100}, []ChunkRange{{0, 2}})
	if _, err := PlanFileChunkHashes(file, []FileRange{{0, 1}}, nil); err == nil {
		t.Fatal("nil layout lookup succeeded")
	}
	if _, err := PlanFileChunkHashes(file, nil, layoutLookup(layout)); err == nil {
		t.Fatal("empty dirty ranges succeeded")
	}
	if _, err := PlanFileChunkHashes(file, []FileRange{{10, 20}, {15, 30}}, layoutLookup(layout)); err == nil {
		t.Fatal("overlapping dirty ranges succeeded")
	}
	if _, err := PlanFileChunkHashes(file, []FileRange{{file.Size, file.Size + 1}}, layoutLookup(layout)); !errors.Is(err, ErrRangeNotSatisfiable) {
		t.Fatalf("out-of-bounds dirty error = %v", err)
	}
}
