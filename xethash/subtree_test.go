package xethash

import (
	"encoding/binary"
	"encoding/json"
	"math/rand"
	"testing"
)

func subtreeNodes(count int) []Node {
	nodes := make([]Node, count)
	var input [16]byte
	for i := range nodes {
		binary.LittleEndian.PutUint64(input[:8], uint64(i))
		binary.LittleEndian.PutUint64(input[8:], uint64(i)*0x9e3779b97f4a7c15)
		nodes[i] = Node{Hash: Chunk(input[:]), Size: uint64(100 + i%10_000)}
	}
	return nodes
}

func TestSubtreeFinalHashMatchesAggregate(t *testing.T) {
	for _, count := range []int{0, 1, 2, 3, 8, 9, 10, 100, 1_000, 10_000} {
		nodes := subtreeNodes(count)
		tree := NewSubtree(true, nodes, true)
		got, ok := tree.FinalHash()
		if !ok || got != Aggregate(nodes) {
			t.Fatalf("count %d final hash = %s,%v; want %s", count, got, ok, Aggregate(nodes))
		}
		if count > 1 && tree.NumNodes() >= count {
			t.Fatalf("count %d subtree did not compact: %d nodes", count, tree.NumNodes())
		}
	}
}

func TestSubtreeMergeAtEverySplit(t *testing.T) {
	nodes := subtreeNodes(500)
	for split := 0; split <= len(nodes); split++ {
		left := NewSubtree(true, nodes[:split], false)
		right := NewSubtree(false, nodes[split:], true)
		merged, err := MergeSubtrees(left, right)
		if err != nil {
			t.Fatalf("split %d: %v", split, err)
		}
		got, ok := merged.FinalHash()
		if !ok || got != Aggregate(nodes) {
			t.Fatalf("split %d merged hash = %s,%v; want %s", split, got, ok, Aggregate(nodes))
		}
	}
}

func TestSubtreeManyRangeMergeAndJSON(t *testing.T) {
	nodes := subtreeNodes(10_000)
	rng := rand.New(rand.NewSource(0x584554))
	var ranges []*MerkleHashSubtree
	for start := 0; start < len(nodes); {
		end := min(start+rng.Intn(300)+1, len(nodes))
		tree := NewSubtree(start == 0, nodes[start:end], end == len(nodes))
		wire, err := json.Marshal(tree)
		if err != nil {
			t.Fatal(err)
		}
		var decoded MerkleHashSubtree
		if err := json.Unmarshal(wire, &decoded); err != nil {
			t.Fatal(err)
		}
		if decoded.NumNodes() != tree.NumNodes() || decoded.NumLevels() != tree.NumLevels() ||
			decoded.AtStart() != tree.AtStart() || decoded.AtEnd() != tree.AtEnd() {
			t.Fatalf("JSON round trip differs at [%d,%d)", start, end)
		}
		ranges = append(ranges, &decoded)
		start = end
	}
	merged, err := MergeSubtrees(ranges...)
	if err != nil {
		t.Fatal(err)
	}
	got, ok := merged.FinalHash()
	if !ok || got != Aggregate(nodes) {
		t.Fatalf("many-range hash = %s,%v; want %s", got, ok, Aggregate(nodes))
	}
}

func TestSubtreeRejectsInvalidJSONAndOrder(t *testing.T) {
	bad := []string{
		`{"nodes":[{"hash":"0000000000000000000000000000000000000000000000000000000000000000","size":1}],"levels":[],"at_start":false,"at_end":false}`,
		`{"nodes":[],"levels":[[1,0]],"at_start":false,"at_end":false}`,
	}
	for _, wire := range bad {
		var tree MerkleHashSubtree
		if err := json.Unmarshal([]byte(wire), &tree); err == nil {
			t.Fatalf("accepted invalid subtree %s", wire)
		}
	}
	left := NewSubtree(true, subtreeNodes(5), true)
	right := NewSubtree(false, subtreeNodes(5), true)
	if _, err := MergeSubtrees(left, right); err == nil {
		t.Fatal("accepted a range after at_end")
	}
}

func TestSubtreeEmptyNilAndInvalidContracts(t *testing.T) {
	var nilTree *MerkleHashSubtree
	if nilTree.AtStart() || nilTree.AtEnd() || nilTree.NumNodes() != 0 || nilTree.NumLevels() != 0 || !nilTree.IsEmpty() {
		t.Fatal("nil subtree accessors differ")
	}
	if _, ok := nilTree.FinalHash(); ok {
		t.Fatal("nil subtree has a final hash")
	}
	empty, err := MergeSubtrees()
	if err != nil {
		t.Fatal(err)
	}
	if hash, ok := empty.FinalHash(); !ok || hash != Zero {
		t.Fatalf("empty final hash = %v, %v", hash, ok)
	}
	if _, err := MergeSubtrees(nilTree); err == nil {
		t.Fatal("nil first subtree merged")
	}
	if _, err := MergeSubtrees(NewSubtree(true, nil, false), nilTree); err == nil {
		t.Fatal("nil later subtree merged")
	}
	partial := NewSubtree(true, subtreeNodes(2), false)
	if _, ok := partial.FinalHash(); ok {
		t.Fatal("partial subtree has a final hash")
	}

	corruptions := []*MerkleHashSubtree{
		{atStart: true, atEnd: true, nodes: subtreeNodes(1)},
		{atStart: true, atEnd: true, nodes: subtreeNodes(2), levels: [][2]int{{2, 0}}, leftOffsets: []int{0}, rightOffsets: []int{2}},
		{atStart: true, atEnd: true, nodes: subtreeNodes(2), levels: [][2]int{{1, 0}, {1, 0}}, leftOffsets: []int{0, 1}, rightOffsets: []int{2, 2}},
	}
	for i, tree := range corruptions {
		if _, ok := tree.FinalHash(); ok {
			t.Errorf("corrupt subtree %d has a final hash", i)
		}
	}
}

func TestSubtreeJSONFailureContracts(t *testing.T) {
	var nilTree *MerkleHashSubtree
	if err := nilTree.UnmarshalJSON([]byte(`{}`)); err == nil {
		t.Fatal("nil receiver unmarshal succeeded")
	}
	for name, wire := range map[string]string{
		"syntax":       `{`,
		"negative":     `{"nodes":[],"levels":[[-1,0]]}`,
		"zero size":    `{"nodes":[{"hash":"0000000000000000000000000000000000000000000000000000000000000000","size":0}],"levels":[[1,0]]}`,
		"invalid root": `{"nodes":[{"hash":"0000000000000000000000000000000000000000000000000000000000000000","size":1},{"hash":"0000000000000000000000000000000000000000000000000000000000000000","size":1}],"levels":[[2,0]],"at_start":true,"at_end":true}`,
	} {
		t.Run(name, func(t *testing.T) {
			var tree MerkleHashSubtree
			if err := tree.UnmarshalJSON([]byte(wire)); err == nil {
				t.Fatal("invalid subtree JSON succeeded")
			}
		})
	}
}

func FuzzSubtreeMerge(f *testing.F) {
	f.Add(uint16(100), uint16(37))
	f.Add(uint16(1), uint16(0))
	f.Fuzz(func(t *testing.T, rawCount, rawSplit uint16) {
		count := int(rawCount % 1_000)
		nodes := subtreeNodes(count)
		split := 0
		if count != 0 {
			split = int(rawSplit) % (count + 1)
		}
		merged, err := MergeSubtrees(
			NewSubtree(true, nodes[:split], false),
			NewSubtree(false, nodes[split:], true),
		)
		if err != nil {
			t.Fatal(err)
		}
		got, ok := merged.FinalHash()
		if !ok || got != Aggregate(nodes) {
			t.Fatalf("count=%d split=%d", count, split)
		}
	})
}

func BenchmarkSubtreeMergeMillion(b *testing.B) {
	nodes := subtreeNodes(1_000_000)
	ranges := make([]*MerkleHashSubtree, 0, 1_000)
	for start := 0; start < len(nodes); start += 1_000 {
		end := min(start+1_000, len(nodes))
		ranges = append(ranges, NewSubtree(start == 0, nodes[start:end], end == len(nodes)))
	}
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		if _, err := MergeSubtrees(ranges...); err != nil {
			b.Fatal(err)
		}
	}
}
