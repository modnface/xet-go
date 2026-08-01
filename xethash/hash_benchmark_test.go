package xethash

import "testing"

func BenchmarkFileHash(b *testing.B) {
	for _, count := range []int{1, 16, 256, 796, maxBenchmarkNodes} {
		b.Run(nodeCountName(count), func(b *testing.B) {
			nodes := benchmarkNodes(count)
			b.ReportAllocs()
			b.ResetTimer()
			var result Hash
			for range b.N {
				result = File(nodes)
			}
			if result.IsZero() {
				b.Fatal("unexpected zero hash")
			}
		})
	}
}

const maxBenchmarkNodes = 8192

func benchmarkNodes(count int) []Node {
	nodes := make([]Node, count)
	for i := range nodes {
		for j := range nodes[i].Hash {
			nodes[i].Hash[j] = byte(i*131 + j*17)
		}
		nodes[i].Size = uint64(8<<10 + i%(120<<10))
	}
	return nodes
}

func nodeCountName(count int) string {
	const digits = "0123456789"
	var storage [20]byte
	position := len(storage)
	for {
		position--
		storage[position] = digits[count%10]
		count /= 10
		if count == 0 {
			return string(storage[position:])
		}
	}
}
