//go:build !arm64

package xethash

import (
	"sync"

	"lukechampine.com/blake3"
)

const chunkBatchEnabled = false

var dataHashers = sync.Pool{
	New: func() any { return blake3.New(Size, dataKey[:]) },
}

func pooledDataHash(data []byte) Hash { return pooledHash(&dataHashers, data) }

func pooledBatchHash(data []byte) Hash { return pooledDataHash(data) }
