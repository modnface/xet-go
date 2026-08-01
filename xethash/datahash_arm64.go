//go:build arm64

package xethash

import (
	"sync"

	forge "goforge.dev/blake3sum/components/blake3"
)

const chunkBatchEnabled = true

var forgeDataHashers = sync.Pool{
	New: func() any { return forge.NewKeyed(dataKey[:]) },
}

func pooledDataHash(data []byte) Hash { return pooledForgeHash(data) }

func pooledBatchHash(data []byte) Hash { return pooledForgeHash(data) }

func pooledForgeHash(data []byte) Hash {
	h := forgeDataHashers.Get().(*forge.Hasher)
	_, _ = h.Write(data)
	var out Hash
	h.Sum(out[:0])
	h.Reset()
	forgeDataHashers.Put(h)
	return out
}
