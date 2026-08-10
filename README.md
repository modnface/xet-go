# xet-go

`xet-go` is a native, CGO-free Go implementation of the Xet v1.1 data plane.
It produces and consumes official Xet hashes, chunks, xorbs, metadata shards,
CAS requests, reconstruction recipes, and sparse delta uploads without invoking
Rust or requiring a Hugging Face-specific SDK at runtime.

The module is deliberately hosting-decoupled. Callers provide an already-issued
Xet CAS endpoint and bearer token through `xetcas.CASAccessProvider`; repository
lookup, host authentication, branches, and commits remain in the calling
application. The optional `xetcas/server` package implements the other side of
that boundary through injected blob storage, indexes, range-URL signing, and
authorization.

The implementation is verified against official `huggingface/xet-core` 1.6.0
commit `de71453d952bd8b806edaa997c72313051a49050` and the checksummed official
reference corpus. See [CONFORMANCE.md](CONFORMANCE.md),
[PROTOCOL_COMPATIBILITY.md](PROTOCOL_COMPATIBILITY.md), and
[IMPLEMENTATION_SOURCES.md](IMPLEMENTATION_SOURCES.md) for the exact claims and
source baseline.

## Requirements

- Go 1.23 or newer to build the module.
- A patched, supported Go release for production deployment. CI performs the
  vulnerability gate with Go 1.25.12 while retaining Go 1.23 compatibility
  tests.
- An Xet CAS endpoint and access token for real transfers. The token may be
  empty for an unauthenticated local CAS.

```sh
go get github.com/jmwoliver/xet-go
```

The release library has no C or Rust dependency. Its direct dependencies are
pure-Go BLAKE3, LZ4, compressed-response codecs, pure-Go SQLite, and the Go
platform syscall package used for strict local-filesystem locking.

## Connect to Xet CAS

Use `NewStaticAccess` when the endpoint and token outlive the client:

```go
endpoint, err := url.Parse(os.Getenv("XET_CAS_ENDPOINT"))
if err != nil {
	return err
}
transport, err := xetcas.New(
	xetcas.NewStaticAccess(endpoint, os.Getenv("XET_CAS_TOKEN")),
	xetcas.Options{
		HTTPClient: &http.Client{Timeout: 2 * time.Minute},
		SessionID:  "my-service-operation-id",
		UserAgent:  "my-service/1.0",
	},
)
if err != nil {
	return err
}

cache, err := xet.NewDiskCache("/var/cache/my-service/xet", endpoint.Host)
if err != nil {
	return err
}
client, err := xet.NewClient(transport, xet.Options{
	Cache:       cache,
	GlobalDedup: true,
})
if err != nil {
	return err
}
```

For expiring access, implement `xetcas.CASAccessProvider`. `Access` returns a
fresh read or write credential with `ExpiresAt`; concurrent refreshes are
coalesced, refresh starts 30 seconds early by default, and a CAS 401 calls
`Invalidate` and retries once. The provider owns all host-specific token
exchange policy.

The high-level engine uses bounded upload/download worker pools. The transport
also has separate adaptive stream controllers, starting at 2 uploads and 4
downloads and bounded at 64. Configure those with
`xetcas.Options.UploadConcurrency` and `DownloadConcurrency`; set a policy's
initial, minimum, and maximum values equal for a fixed transport limit.

## Upload

```go
ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
defer cancel()

result, err := client.UploadFile(ctx, "model.safetensors")
if err != nil {
	return err
}

// Persist this hosting-independent metadata with the caller's object record.
fmt.Printf("xet=%s size=%d sha256=%x\n",
	result.File.Hash, result.File.Size, *result.File.SHA256)
```

`Upload`, `UploadBytes`, and `UploadFile` stream their input, pack chunks into
protocol-sized xorbs, upload xorbs concurrently, and publish the shard only
after every required xorb succeeds. `UploadSources` and batches created by
`NewUploadBatch` share packing and session deduplication across several files.

To resume a replay-safe upload after process failure, give the client a
`DiskUploadJournal`. Journal entries contain only xorb identities. A replay
checks CAS existence before trusting an entry, and a successful shard commit
clears the journal.

```go
journal, err := xet.NewDiskUploadJournal("/var/lib/my-service/xet-journals", operationID)
if err != nil {
	return err
}
client, err = xet.NewClient(transport, xet.Options{UploadJournal: journal})
```

`UploadDelta` applies sorted, non-overlapping edits in original-file
coordinates and uploads only the server-selected dirty windows. Unchanged terms
and compact Merkle subtrees are retained exactly; like the official sparse
upload path, the resulting metadata omits whole-file SHA-256 because unchanged
bytes are not reread.

## Download

Atomic file publication is the safest complete-file API:

```go
report, err := client.DownloadFile(ctx, fileInfo, "model.safetensors", xet.DownloadFileOptions{})
if err != nil {
	return err
}
fmt.Printf("logical=%d fetched=%d cached=%d\n",
	report.LogicalBytes, report.FetchedBytes, report.CacheHitBytes)
```

`Download` streams in logical order to `io.Writer`. `DownloadAt` can write
independent ranges concurrently to a file or block device. `DownloadRange` and
`DownloadRangeAt` reconstruct an exact half-open logical range:

```go
requested := xetcas.FileRange{Start: 1 << 20, End: 2 << 20}
var data bytes.Buffer
_, err := client.DownloadRange(ctx, fileInfo.Hash, requested, &data)
```

Complete downloads verify every chunk, reconstruction-term verification hash,
the Xet file identity, declared size, and present SHA-256. Partial downloads
verify all available structure and term data but cannot recompute a whole-file
identity. Reconstruction is windowed and decoded bytes are kept under
`MaxDownloadMemory`. Signed object-storage URLs never receive CAS authorization,
session, or cookie headers.

`DownloadGroup` runs independent complete or range requests with bounded
workers and returns one ordered result per request.

## Serve Xet CAS

`xetcas/server` is cloud- and hosting-neutral. A production adapter implements
`BlobStore`, `IndexStore`, `RangeURLSigner`, and `Authorizer`. The reference
memory store is intended for tests and ephemeral development:

```go
store := server.NewMemoryStore()
cas, err := server.New(server.Options{
	Blobs:      store,
	Index:      store,
	Authorizer: server.StaticTokenAuthorizer{
		Token: os.Getenv("XET_CAS_TOKEN"), Namespace: "local",
	},
	Signer:     objectRangeSigner,
	// Optional: each protected shard embeds the key needed by clients, so key
	// rotation does not invalidate shards already issued within their TTL.
	DedupProtectionKey: protectionKey,
})
if err != nil {
	return err
}
return http.ListenAndServe(":8080", cas.Handler())
```

For a durable single-node CAS on Linux or macOS, pair the immutable filesystem
blob store with the transactional SQLite index:

```go
blobs, err := server.NewFilesystemBlobStore("/var/lib/my-service/xet/blobs")
if err != nil {
	return err
}
index, err := server.OpenSQLiteIndexStore("/var/lib/my-service/xet/index.db")
if err != nil {
	_ = blobs.Close()
	return err
}
cas, err := server.New(server.Options{
	Blobs: blobs, Index: index,
	Authorizer: authorizer, Signer: objectRangeSigner,
	DedupProtectionKey: protectionKey,
})
```

Filesystem writes use exact-length temporary files, file sync, non-replacing
hard-link publication, and directory durability barriers. SQLite uses WAL,
`synchronous=FULL`, immediate write transactions, and one atomic
`PublishShard` transaction. Schema version 3 enforces SQLite storage classes as
well as key lengths and adds durable namespace-scoped blob stages and file read
leases. Both constructors reject symlinked leaf paths and return
`ErrDurabilityUnsupported` without modifying their target on platforms where
strict directory durability is not implemented.

When the index implements `ProtectionStore`, the service durably stages each
Xorb or shard before writing its immutable blob, renews that stage throughout a
slow publication, and removes it only after logical index publication. A failed
or ambiguously completed publication conservatively leaves the stage for future
recovery and reachability-aware cleanup. Active typed reads acquire and renew a
file lease before traversing the reconstruction graph. Signed reconstruction
responses retain a detached lease through the maximum `SignedRange.ExpiresAt`
returned by the signer plus `ReadLeaseTTL` as a grace interval. This is why a
`RangeURLSigner` must return both the URL and its authoritative expiration.
Reachability audit and destructive garbage collection are not yet implemented;
expired protection records must not be treated as permission to delete bytes
without the documented age/grace and reachability checks.

Stores may additionally implement `BlobLister`, `IndexLister`, and
`ProtectionStore` for bounded, keyset-paginated operational scans and lifecycle
roots. The memory, filesystem, and SQLite stores collectively provide these
capabilities for blobs, Xorbs, namespace-scoped files and dedup records,
namespace-scoped SHA associations, blob stages, and file leases.
Cursors are opaque and tied to one operation, blob kind, and namespace-filter
mode. SQLite seeks through its
composite primary keys; filesystem scans seek the two-level hash-prefix tree
and stop after finding one page, while reading and sorting one
four-hex-character leaf as the smallest unit of work. Listers expose physical
or all-namespace state without performing tenant authorization and belong
behind an administrative boundary. Pages are weakly consistent rather than a
snapshot, so destructive maintenance still requires quiescence, an epoch or
lease, or a grace barrier.

Embedders can stream reconstructed content without interpreting protocol JSON
or making an internal HTTP request:

```go
opened, err := cas.OpenFile(ctx, token, fileID, requestedRange)
if err != nil {
	return err
}
defer opened.Body.Close()
_, err = io.Copy(destination, opened.Body)
```

`OpenFile` uses the same bounded reconstruction planner as the wire routes,
coalesces safe adjacent Xorb reads, validates every decoded chunk and length,
verifies a present SHA-256 for complete coverage, and propagates cancellation
while closing active backend readers. Where lifecycle protection is available,
the lease is durable before the first file/index lookup and lease renewal or
cleanup failures are propagated through the stream and `Body.Close`.

Xorb bodies are decoded and identity-checked before canonical complete storage.
Shard registration resolves durable xorb metadata and recomputes term and file
identities instead of trusting client accounting. Publication writes the full
shard under a renewable durable stage, then atomically publishes its scoped
dedup, SHA, and file indexes. v2
shard responses stream NDJSON heartbeats and a terminal result or error.
Registration has configurable file, xorb, term, and aggregate chunk-reference
budgets; ingestion admission is bounded before request bodies are buffered.

The OpenAPI dedup namespace is `default-merkledb`; the server also accepts
`default` because released official Rust clients currently reuse their xorb
prefix for dedup requests. Repository reachability policy and S3/GCS signing
belong in the injected adapters, not this module. Xorb layout metadata and
bytes are physically global for content deduplication. File recipes, dedup
records, and SHA-256 associations are keyed by `Grant.Namespace`; every logical
read resolves one of those scoped records before reaching physical content.

## Package map

| Package | Purpose |
|---|---|
| `xet` | Streaming upload, reconstruction, batches, ranges, groups, delta upload, persistent cache, and replay journal |
| `xetcas` | Access refresh, Xet CAS v1/v2 routes, signed multipart ranges, retry, response bounds, and adaptive concurrency |
| `xetcas/server` | Storage-neutral CAS ingestion, shard registration, reconstruction/delta planning, authorization, signed range URLs, and HTTP handlers |
| `chunker` | Streaming official GearHash content-defined chunking |
| `xethash` | Canonical hashes, BLAKE3 domains, Merkle aggregation, and compact subtrees |
| `xorb` | Network and complete/cache xorb codecs for none, LZ4, BG4-LZ4, and production auto selection |
| `shard` | Footerless upload, canonical full, and protected global-dedup shard codecs and registration validation |

All parsers treat network bytes as untrusted: declared lengths and offsets are
bounds-checked before allocation, compressed bodies have decoded-size caps,
redirects are disabled, error URLs are redacted, and credential-bearing signed
URLs are never persisted.

## Verify

The ordinary release checks are:

```sh
go test ./...
go test -race ./...
go vet ./...
golangci-lint run ./...
./conformance/check-coverage.sh
./conformance/fuzz-smoke.sh
./conformance/cross-compile.sh
```

Run every pinned official reference, Rust differential, and Rust local-CAS gate
with Rust 1.95.0 installed:

```sh
./conformance/run-official-conformance.sh
```

Run alternating optimized Go/Rust performance samples over the official
63.5 MB corpus:

```sh
./conformance/compare-performance.sh
```

Reports are written to ignored `.cache/performance/latest.{json,md}` and include
identity checks, chunk counts, encoded sizes, median timings, throughput, and
the Go/Rust ratio. See [PERFORMANCE.md](PERFORMANCE.md) for the recorded baseline
and [conformance/README.md](conformance/README.md) for individual gate commands.

## Compatibility and versioning

`xet.ProtocolVersion` is the wire specification target, currently `1.1.0`;
it is not the Go module's semantic version. Before the first tagged v1 module
release, exported Go APIs may still receive compatibility-preserving cleanup.
Protocol encodings and conformance pins change only with an explicit baseline
update recorded in the compatibility and source documents.
