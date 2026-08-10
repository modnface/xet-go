package xet

import (
	"context"
	"time"

	diskcache "github.com/jmwoliver/xet-go/internal/cache"
	"github.com/jmwoliver/xet-go/xethash"
)

// Cache stores immutable serialized xorb ranges and expiring global-dedup
// shards. Implementations must never store signed URLs or bearer credentials.
type Cache interface {
	GetXorbRange(context.Context, xethash.Hash, uint32, uint32) ([]byte, bool, error)
	PutXorbRange(context.Context, xethash.Hash, uint32, uint32, []byte) error
	DeleteXorbRange(context.Context, xethash.Hash, uint32, uint32) error
	GetShard(context.Context, xethash.Hash) ([]byte, bool, error)
	PutShard(context.Context, xethash.Hash, []byte, time.Time) error
	DeleteShard(context.Context, xethash.Hash) error
}

// DiskCache is the standard checksum-verified, atomically-written persistent
// cache. Namespace should identify the CAS deployment/repository scope without
// containing credentials; it is hashed before use as a directory name.
type DiskCache = diskcache.Disk

func NewDiskCache(directory, namespace string) (*DiskCache, error) {
	return diskcache.NewDisk(directory, namespace)
}
