package xetcas

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/jmwoliver/xet-go/chunker"
	"github.com/jmwoliver/xet-go/shard"
	"github.com/jmwoliver/xet-go/xethash"
	"github.com/jmwoliver/xet-go/xorb"
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

type cancelOnSecondCheckContext struct {
	context.Context
	calls int
}

func (c *cancelOnSecondCheckContext) Err() error {
	c.calls++
	if c.calls >= 2 {
		return context.Canceled
	}
	return nil
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
	if _, err := PlanReconstructionContext(nil, file, nil, layoutLookup(layout)); err == nil { //nolint:staticcheck // Verify that the API rejects a nil context.
		t.Fatal("nil context succeeded")
	}
	wrongSize := file
	wrongSize.Size++
	if _, err := PlanReconstruction(wrongSize, nil, layoutLookup(layout)); err == nil {
		t.Fatal("recipe size mismatch succeeded")
	}
	if _, err := PlanReconstruction(shard.RegisteredFile{Size: 1}, nil, layoutLookup(layout)); err == nil {
		t.Fatal("non-empty file without terms succeeded")
	}
	emptyWithTerms := shard.RegisteredFile{File: shard.File{Terms: []shard.Term{{}}}}
	if _, err := PlanReconstruction(emptyWithTerms, nil, layoutLookup(layout)); err == nil {
		t.Fatal("empty file with terms succeeded")
	}
	if _, err := PlanReconstruction(file, &FileRange{Start: 1, End: 1}, layoutLookup(layout)); err == nil {
		t.Fatal("empty requested range succeeded")
	}
	wantErr := errors.New("layout failed")
	if _, err := PlanReconstruction(file, nil, func(xethash.Hash) (*xorb.Ingested, bool, error) {
		return nil, false, wantErr
	}); !errors.Is(err, wantErr) {
		t.Fatalf("layout error = %v", err)
	}
	if _, err := PlanReconstruction(file, nil, func(xethash.Hash) (*xorb.Ingested, bool, error) {
		return nil, false, nil
	}); err == nil {
		t.Fatal("missing layout succeeded")
	}
	mismatchedLayout := *layout
	mismatchedLayout.Hash = xethash.Chunk([]byte("other xorb"))
	if _, err := PlanReconstruction(file, nil, func(xethash.Hash) (*xorb.Ingested, bool, error) {
		return &mismatchedLayout, true, nil
	}); err == nil {
		t.Fatal("mismatched layout succeeded")
	}
	badRange := file
	badRange.File.Terms = append([]shard.Term(nil), file.File.Terms...)
	badRange.File.Terms[0].End++
	if _, err := PlanReconstruction(badRange, nil, layoutLookup(layout)); err == nil {
		t.Fatal("out-of-bounds chunk range succeeded")
	}
	badSerializedLayout := *layout
	badSerializedLayout.NetworkBytes = 0
	if _, err := PlanReconstruction(file, nil, layoutLookup(&badSerializedLayout)); err == nil {
		t.Fatal("out-of-bounds serialized range succeeded")
	}
	if err := validateLayoutRange(layout, ChunkRange{}); err == nil {
		t.Fatal("empty layout range succeeded")
	}
	if err := validateLayoutRange(layout, ChunkRange{Start: 0, End: uint32(len(layout.Chunks) + 1)}); err == nil {
		t.Fatal("oversized layout range succeeded")
	}
	if plan, err := PlanReconstruction(shard.RegisteredFile{}, nil, layoutLookup(layout)); err != nil || len(plan.Terms) != 0 {
		t.Fatalf("empty full-file plan = %#v, %v", plan, err)
	}
}

func TestPlanReconstructionSkipsTermsAndPropagatesMidPlanCancellation(t *testing.T) {
	file, layout := plannerFixture(t, []int{100, 100}, []ChunkRange{{0, 1}, {1, 2}})
	plan, err := PlanReconstruction(file, &FileRange{Start: 100, End: 200}, layoutLookup(layout))
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Terms) != 1 || plan.Terms[0].Range != (ChunkRange{Start: 1, End: 2}) {
		t.Fatalf("term-boundary plan = %#v", plan)
	}

	ctx, cancel := context.WithCancel(context.Background())
	_, err = PlanReconstructionContext(ctx, file, nil, func(hash xethash.Hash) (*xorb.Ingested, bool, error) {
		cancel()
		return layout, hash == layout.Hash, nil
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("mid-plan cancellation = %v", err)
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
	if _, err := PlanFileChunkHashesContext(nil, file, []FileRange{{0, 1}}, layoutLookup(layout)); err == nil { //nolint:staticcheck // Verify that the API rejects a nil context.
		t.Fatal("nil context succeeded")
	}
	if _, err := PlanFileChunkHashes(file, nil, layoutLookup(layout)); err == nil {
		t.Fatal("empty dirty ranges succeeded")
	}
	if _, err := PlanFileChunkHashes(file, []FileRange{{10, 20}, {15, 30}}, layoutLookup(layout)); err == nil {
		t.Fatal("overlapping dirty ranges succeeded")
	}
	if _, err := PlanFileChunkHashes(file, []FileRange{{20, 10}}, layoutLookup(layout)); err == nil {
		t.Fatal("reversed dirty range succeeded")
	}
	if _, err := PlanFileChunkHashes(file, []FileRange{{file.Size, file.Size + 1}}, layoutLookup(layout)); !errors.Is(err, ErrRangeNotSatisfiable) {
		t.Fatalf("out-of-bounds dirty error = %v", err)
	}
	wantErr := errors.New("layout failed")
	if _, err := PlanFileChunkHashes(file, []FileRange{{0, 1}}, func(xethash.Hash) (*xorb.Ingested, bool, error) {
		return nil, false, wantErr
	}); !errors.Is(err, wantErr) {
		t.Fatalf("layout error = %v", err)
	}
	if _, err := PlanFileChunkHashes(file, []FileRange{{0, 1}}, func(xethash.Hash) (*xorb.Ingested, bool, error) {
		return nil, false, nil
	}); err == nil {
		t.Fatal("missing layout succeeded")
	}
	mismatched := *layout
	mismatched.Hash = xethash.Chunk([]byte("other xorb"))
	if _, err := PlanFileChunkHashes(file, []FileRange{{0, 1}}, func(xethash.Hash) (*xorb.Ingested, bool, error) {
		return &mismatched, true, nil
	}); err == nil {
		t.Fatal("mismatched layout succeeded")
	}
	badRange := file
	badRange.File.Terms = append([]shard.Term(nil), file.File.Terms...)
	badRange.File.Terms[0].End++
	if _, err := PlanFileChunkHashes(badRange, []FileRange{{0, 1}}, layoutLookup(layout)); err == nil {
		t.Fatal("bad term range succeeded")
	}
	wrongSize := file
	wrongSize.Size++
	if _, err := PlanFileChunkHashes(wrongSize, []FileRange{{0, 1}}, layoutLookup(layout)); err == nil {
		t.Fatal("wrong file size succeeded")
	}
	partial, partialLayout := plannerFixture(t, []int{100, 100}, []ChunkRange{{0, 1}, {1, 2}})
	partial.File.Terms[1].Verification = xethash.Zero
	if _, err := PlanFileChunkHashes(partial, []FileRange{{0, 1}}, layoutLookup(partialLayout)); err == nil {
		t.Fatal("partial verification succeeded")
	}
}

func TestPlanFileChunkHashesPropagatesMidPlanCancellation(t *testing.T) {
	file, layout := plannerFixture(t, []int{100}, []ChunkRange{{0, 1}})
	ctx, cancel := context.WithCancel(context.Background())
	_, err := PlanFileChunkHashesContext(ctx, file, []FileRange{{0, 1}}, func(hash xethash.Hash) (*xorb.Ingested, bool, error) {
		cancel()
		return layout, hash == layout.Hash, nil
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("mid-plan cancellation = %v", err)
	}
}

func TestChunkWindowBuilderBridgesMultipleDirtyRanges(t *testing.T) {
	builder := &chunkWindowBuilder{
		dirty:      []FileRange{{Start: 0, End: 1}, {Start: 2, End: 3}, {Start: 4, End: 5}},
		inDirty:    true,
		cursor:     1,
		gap:        newSubtreeAccumulator(false),
		windows:    []FileRange{{Start: 0, End: 1}},
		dirtyIndex: 0,
	}
	builder.process(xethash.Node{Hash: xethash.Chunk([]byte("bridge")), Size: 5}, 6)
	if builder.dirtyIndex != 2 || builder.windows[0].End != 6 {
		t.Fatalf("bridged builder = %#v", builder)
	}
	wantErr := errors.New("earlier gap failure")
	builder.err = wantErr
	builder.appendGap(false)
	if !errors.Is(builder.err, wantErr) {
		t.Fatalf("preserved gap error = %v", builder.err)
	}
}

func TestPlanningContextCancellationAndBoundedGapAccumulation(t *testing.T) {
	file, layout := plannerFixture(t, []int{100}, []ChunkRange{{0, 1}})
	if _, err := PlanReconstructionContext(&cancelOnSecondCheckContext{Context: context.Background()}, file, nil,
		layoutLookup(layout)); !errors.Is(err, context.Canceled) {
		t.Fatalf("reconstruction preflight cancellation = %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := PlanReconstructionContext(ctx, file, nil, layoutLookup(layout)); !errors.Is(err, context.Canceled) {
		t.Fatalf("reconstruction cancellation = %v", err)
	}
	if _, err := PlanFileChunkHashesContext(ctx, file, []FileRange{{0, 1}}, layoutLookup(layout)); !errors.Is(err, context.Canceled) {
		t.Fatalf("chunk-hash cancellation = %v", err)
	}

	sizes := make([]int, xorb.MaxChunks)
	for i := range sizes {
		sizes[i] = 1
	}
	file, layout = plannerFixture(t, sizes, []ChunkRange{{0, 5_000}, {0, 5_000}})
	response, err := PlanFileChunkHashes(file, []FileRange{{9_999, 10_000}}, layoutLookup(layout))
	if err != nil {
		t.Fatal(err)
	}
	wantNodes := make([]xethash.Node, 0, 9_999)
	for len(wantNodes) < cap(wantNodes) {
		for _, chunk := range layout.Chunks[:5_000] {
			if len(wantNodes) == cap(wantNodes) {
				break
			}
			wantNodes = append(wantNodes, xethash.Node{Hash: chunk.Hash, Size: uint64(chunk.UncompressedLength)})
		}
	}
	want, err := json.Marshal(xethash.NewSubtree(true, wantNodes, false))
	if err != nil {
		t.Fatal(err)
	}
	got, err := json.Marshal(response.HashRanges[0])
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("batched compact gap differs from one-shot subtree")
	}
}
