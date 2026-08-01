package xethash

import (
	"encoding/json"
	"errors"
	"fmt"
)

const (
	subtreeMinGroup = 2
	subtreeMaxGroup = 9
	maxSubtreeNodes = 1_000_000
)

// MerkleHashSubtree is Xet's compact O(log n) representation of a contiguous
// chunk-hash range. It can be serialized in the exact JSON shape used by the
// v2 file-chunk-hashes API and merged with adjacent ranges without recovering
// their original per-chunk lists.
type MerkleHashSubtree struct {
	nodes        []Node
	levels       [][2]int
	leftOffsets  []int
	rightOffsets []int
	atStart      bool
	atEnd        bool
}

// NewSubtree builds a compact subtree from level-zero chunk nodes. atStart and
// atEnd declare whether the corresponding full-file boundary is known.
func NewSubtree(atStart bool, chunks []Node, atEnd bool) *MerkleHashSubtree {
	nodes, levels := buildHump(chunks, atStart, atEnd)
	left, right := subtreeOffsets(levels)
	return &MerkleHashSubtree{
		nodes: nodes, levels: levels, leftOffsets: left, rightOffsets: right,
		atStart: atStart, atEnd: atEnd,
	}
}

func (s *MerkleHashSubtree) AtStart() bool { return s != nil && s.atStart }
func (s *MerkleHashSubtree) AtEnd() bool   { return s != nil && s.atEnd }
func (s *MerkleHashSubtree) NumNodes() int {
	if s == nil {
		return 0
	}
	return len(s.nodes)
}
func (s *MerkleHashSubtree) NumLevels() int {
	if s == nil {
		return 0
	}
	return len(s.levels)
}
func (s *MerkleHashSubtree) IsEmpty() bool { return s == nil || len(s.nodes) == 0 }

// FinalHash returns the unsalted aggregate root only when both full-file
// boundaries are known.
func (s *MerkleHashSubtree) FinalHash() (Hash, bool) {
	if s == nil || !s.atStart || !s.atEnd {
		return Hash{}, false
	}
	if len(s.nodes) == 0 {
		return Zero, true
	}
	if len(s.levels) == 0 {
		return Hash{}, false
	}
	top := len(s.levels) - 1
	left := s.leftAt(top)
	if len(left) != 1 || len(s.rightAt(top)) != 0 {
		return Hash{}, false
	}
	for _, level := range s.levels[:top] {
		if level != [2]int{} {
			return Hash{}, false
		}
	}
	return left[0].Hash, true
}

// MergeSubtrees merges adjacent ranges from left to right. An empty input
// returns the fully closed empty subtree.
func MergeSubtrees(ranges ...*MerkleHashSubtree) (*MerkleHashSubtree, error) {
	if len(ranges) == 0 {
		return NewSubtree(true, nil, true), nil
	}
	if ranges[0] == nil {
		return nil, errors.New("xethash: nil Merkle subtree")
	}
	result := ranges[0].clone()
	for i, value := range ranges[1:] {
		if value == nil {
			return nil, fmt.Errorf("xethash: nil Merkle subtree %d", i+1)
		}
		if err := result.mergeInto(value); err != nil {
			return nil, fmt.Errorf("xethash: merge Merkle subtree %d: %w", i+1, err)
		}
	}
	return result, nil
}

func (s *MerkleHashSubtree) clone() *MerkleHashSubtree {
	return &MerkleHashSubtree{
		nodes: append([]Node(nil), s.nodes...), levels: append([][2]int(nil), s.levels...),
		leftOffsets: append([]int(nil), s.leftOffsets...), rightOffsets: append([]int(nil), s.rightOffsets...),
		atStart: s.atStart, atEnd: s.atEnd,
	}
}

func (s *MerkleHashSubtree) leftAt(level int) []Node {
	start := s.leftOffsets[level]
	return s.nodes[start : start+s.levels[level][0]]
}

func (s *MerkleHashSubtree) rightAt(level int) []Node {
	start := s.rightOffsets[level]
	return s.nodes[start : start+s.levels[level][1]]
}

func subtreeOffsets(levels [][2]int) ([]int, []int) {
	left := make([]int, len(levels))
	right := make([]int, len(levels))
	totalLeft := 0
	for i, level := range levels {
		left[i] = totalLeft
		totalLeft += level[0]
	}
	rightAfter := 0
	for _, level := range levels {
		rightAfter += level[1]
	}
	for i, level := range levels {
		rightAfter -= level[1]
		right[i] = totalLeft + rightAfter
	}
	return left, right
}

func (s *MerkleHashSubtree) mergeInto(other *MerkleHashSubtree) error {
	if s.atEnd || other.atStart {
		return errors.New("subtree boundaries are not adjacent")
	}
	combinedStart, combinedEnd := s.atStart, other.atEnd
	maxLevels := max(len(s.levels), len(other.levels))
	leftLevels := make([][]Node, 0, maxLevels+2)
	rightLevels := make([][]Node, 0, maxLevels+2)
	carry := []Node(nil)
	allLeftEmpty, allRightEmpty := true, true
	for level := 0; level < maxLevels; level++ {
		full := make([]Node, 0, len(carry)+32)
		if level < len(s.levels) {
			full = append(full, s.leftAt(level)...)
			full = append(full, s.rightAt(level)...)
		}
		full = append(full, carry...)
		if level < len(other.levels) {
			full = append(full, other.leftAt(level)...)
			full = append(full, other.rightAt(level)...)
		}
		prefix, promoted, suffix := splitAndPromote(full,
			combinedStart && allLeftEmpty, combinedEnd && allRightEmpty)
		leftLevels = append(leftLevels, append([]Node(nil), full[:prefix]...))
		rightLevels = append(rightLevels, append([]Node(nil), full[len(full)-suffix:]...))
		allLeftEmpty = allLeftEmpty && prefix == 0
		allRightEmpty = allRightEmpty && suffix == 0
		carry = promoted
	}
	for len(carry) != 0 {
		if len(carry) == 1 {
			leftLevels = append(leftLevels, append([]Node(nil), carry...))
			rightLevels = append(rightLevels, nil)
			carry = nil
			continue
		}
		prefix, promoted, suffix := splitAndPromote(carry,
			combinedStart && allLeftEmpty, combinedEnd && allRightEmpty)
		leftLevels = append(leftLevels, append([]Node(nil), carry[:prefix]...))
		rightLevels = append(rightLevels, append([]Node(nil), carry[len(carry)-suffix:]...))
		allLeftEmpty = allLeftEmpty && prefix == 0
		allRightEmpty = allRightEmpty && suffix == 0
		carry = promoted
	}
	for len(leftLevels) > 1 && len(leftLevels[len(leftLevels)-1]) == 0 && len(rightLevels[len(rightLevels)-1]) == 0 {
		leftLevels = leftLevels[:len(leftLevels)-1]
		rightLevels = rightLevels[:len(rightLevels)-1]
	}
	s.nodes, s.levels = flattenHump(leftLevels, rightLevels)
	s.leftOffsets, s.rightOffsets = subtreeOffsets(s.levels)
	s.atStart, s.atEnd = combinedStart, combinedEnd
	return nil
}

func buildHump(chunks []Node, atStart, atEnd bool) ([]Node, [][2]int) {
	current := append([]Node(nil), chunks...)
	leftLevels := make([][]Node, 0, 12)
	rightLevels := make([][]Node, 0, 12)
	allLeftEmpty, allRightEmpty := true, true
	for {
		prefix, promoted, suffix := splitAndPromote(current,
			atStart && allLeftEmpty, atEnd && allRightEmpty)
		leftLevels = append(leftLevels, append([]Node(nil), current[:prefix]...))
		rightLevels = append(rightLevels, append([]Node(nil), current[len(current)-suffix:]...))
		allLeftEmpty = allLeftEmpty && prefix == 0
		allRightEmpty = allRightEmpty && suffix == 0
		if len(promoted) == 0 {
			break
		}
		if len(promoted) == 1 {
			leftLevels = append(leftLevels, promoted)
			rightLevels = append(rightLevels, nil)
			break
		}
		current = promoted
	}
	return flattenHump(leftLevels, rightLevels)
}

func flattenHump(leftLevels, rightLevels [][]Node) ([]Node, [][2]int) {
	levels := make([][2]int, len(leftLevels))
	total := 0
	for i := range levels {
		levels[i] = [2]int{len(leftLevels[i]), len(rightLevels[i])}
		total += len(leftLevels[i]) + len(rightLevels[i])
	}
	nodes := make([]Node, 0, total)
	for _, values := range leftLevels {
		nodes = append(nodes, values...)
	}
	for i := len(rightLevels) - 1; i >= 0; i-- {
		nodes = append(nodes, rightLevels[i]...)
	}
	return nodes, levels
}

func splitAndPromote(nodes []Node, atStart, atEnd bool) (int, []Node, int) {
	if len(nodes) <= 1 {
		return len(nodes), nil, 0
	}
	stableStart := 0
	if !atStart {
		var found bool
		stableStart, found = findStableStart(nodes)
		if !found {
			return len(nodes), nil, 0
		}
	}
	stableEnd := len(nodes)
	if !atEnd {
		relative, found := findStableEnd(nodes[stableStart:])
		if !found {
			return len(nodes), nil, 0
		}
		stableEnd = stableStart + relative
	}
	if stableStart >= stableEnd {
		return len(nodes), nil, 0
	}
	mergeable := nodes[stableStart:stableEnd]
	promoted := make([]Node, 0, (len(mergeable)+1)/2)
	for position := 0; position < len(mergeable); {
		cut := position + nextMergeCut(mergeable[position:])
		promoted = append(promoted, merge(mergeable[position:cut]))
		position = cut
	}
	return stableStart, promoted, len(nodes) - stableEnd
}

func findStableStart(nodes []Node) (int, bool) {
	if len(nodes) < subtreeMinGroup+1 {
		return 0, false
	}
	previousPrevious, previous := -1, -1
	for position, node := range nodes {
		if node.Hash.LastUint64()%4 != 0 {
			continue
		}
		if previousPrevious >= 0 && validStableGap(position-previous) && validStableGap(previous-previousPrevious) {
			return previous + 1, true
		}
		previousPrevious, previous = previous, position
	}
	return 0, false
}

func findStableEnd(nodes []Node) (int, bool) {
	if len(nodes) < subtreeMinGroup+1 {
		return 0, false
	}
	nextNext, next := -1, -1
	for position := len(nodes) - 1; position >= 0; position-- {
		if nodes[position].Hash.LastUint64()%4 != 0 {
			continue
		}
		if nextNext >= 0 && validStableGap(next-position) && validStableGap(nextNext-next) {
			return next + 1, true
		}
		nextNext, next = next, position
	}
	return 0, false
}

func validStableGap(gap int) bool {
	return gap > subtreeMinGroup && gap < subtreeMaxGroup-1
}

type subtreeJSONNode struct {
	Hash Hash   `json:"hash"`
	Size uint64 `json:"size"`
}

type subtreeJSON struct {
	Nodes   []subtreeJSONNode `json:"nodes"`
	Levels  [][2]int          `json:"levels"`
	AtStart bool              `json:"at_start"`
	AtEnd   bool              `json:"at_end"`
}

func (s MerkleHashSubtree) MarshalJSON() ([]byte, error) {
	nodes := make([]subtreeJSONNode, len(s.nodes))
	for i, node := range s.nodes {
		nodes[i] = subtreeJSONNode(node)
	}
	return json.Marshal(subtreeJSON{Nodes: nodes, Levels: s.levels, AtStart: s.atStart, AtEnd: s.atEnd})
}

func (s *MerkleHashSubtree) UnmarshalJSON(data []byte) error {
	if s == nil {
		return errors.New("xethash: unmarshal Merkle subtree into nil receiver")
	}
	var wire subtreeJSON
	if err := json.Unmarshal(data, &wire); err != nil {
		return fmt.Errorf("xethash: decode Merkle subtree: %w", err)
	}
	if len(wire.Nodes) > maxSubtreeNodes || len(wire.Levels) > maxSubtreeNodes {
		return errors.New("xethash: Merkle subtree exceeds structural limit")
	}
	total := 0
	for i, level := range wire.Levels {
		if level[0] < 0 || level[1] < 0 || level[0] > len(wire.Nodes)-total || level[1] > len(wire.Nodes)-total-level[0] {
			return fmt.Errorf("xethash: invalid Merkle subtree level %d", i)
		}
		total += level[0] + level[1]
	}
	if total != len(wire.Nodes) || (len(wire.Nodes) != 0 && len(wire.Levels) == 0) {
		return errors.New("xethash: Merkle subtree level counts do not cover nodes")
	}
	nodes := make([]Node, len(wire.Nodes))
	for i, node := range wire.Nodes {
		nodes[i] = Node(node)
		if node.Size == 0 {
			return fmt.Errorf("xethash: Merkle subtree node %d has zero size", i)
		}
	}
	left, right := subtreeOffsets(wire.Levels)
	*s = MerkleHashSubtree{
		nodes: nodes, levels: append([][2]int(nil), wire.Levels...),
		leftOffsets: left, rightOffsets: right, atStart: wire.AtStart, atEnd: wire.AtEnd,
	}
	if wire.AtStart && wire.AtEnd {
		if _, ok := s.FinalHash(); !ok {
			return errors.New("xethash: fully closed Merkle subtree has no valid final hash")
		}
	}
	return nil
}
