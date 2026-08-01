package xethash

import (
	"runtime"
	"sync"

	"github.com/jmwoliver/blake3"
)

// The fork selects its compression backend internally. This caller-level batch
// is still ARM64-specific scheduling: the unchanged AMD64 backend already
// parallelizes eigentrees around its wider AVX2/AVX-512 compression kernels.
const chunkBatchEnabled = runtime.GOARCH == "arm64"

var dataHashers = sync.Pool{
	New: func() any { return blake3.New(Size, dataKey[:]) },
}

var batchDataHashers = sync.Pool{
	New: func() any { return blake3.NewSerial(Size, dataKey[:]) },
}

func pooledDataHash(data []byte) Hash { return pooledHash(&dataHashers, data) }

func pooledBatchHash(data []byte) Hash { return pooledHash(&batchDataHashers, data) }
