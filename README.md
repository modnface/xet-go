# xet-go

`xet-go` is a native, CGO-free Go implementation of the Xet v1.1 data plane.
It produces and consumes official Xet hashes, chunks, xorbs, metadata shards,
CAS requests, reconstruction recipes, and sparse delta uploads without invoking
Rust or requiring a Hugging Face-specific SDK at runtime.

The module is deliberately hosting-decoupled. Callers provide an already-issued
Xet CAS endpoint and bearer token through `xetcas.CASAccessProvider`; repository
lookup, host authentication, and compatible commit transport remain in the
calling application. The optional `xetcas/server` package implements the other
side of the CAS boundary through injected blob storage, indexes, range-URL
signing, and authorization. The independent `model` package defines validated
repository keys, opaque commit OIDs, refs, immutable complete snapshots, and
ordinary or Xet-backed file references for higher-level catalogs. It does not
invent Hugging Face/Git commit hashing or import persistence and HTTP policy.
The `catalog` contract and its memory, SQLite, and PostgreSQL implementations
add repository-scoped revision/file lookup, atomic immutable-snapshot
publication, compare-and-swap refs, and snapshot-bound bounded pagination.
SQLite uses a versioned schema, WAL with `synchronous=FULL`, context-aware
immediate write transactions, and one atomic transaction for snapshot, file,
and ref publication. PostgreSQL uses versioned private-schema migrations,
per-repository transaction locks for independent writers, explicit UTF-8 byte
ordering, and the same atomic publication contract across independent pools. A
trusted control-plane adapter allocates an opaque OID before publication; the
catalog does not derive one from its versioned internal equality fingerprint.

The independent `content` contract stores ordinary files by SHA-256 and exact
length without importing repository or CAS policy. Its memory and Linux/macOS
filesystem implementations provide absent-or-identical immutable publication,
full and half-open range streams, exact upload verification, full-read hash
verification, cancellation, and typed corruption/range/backend errors. The
filesystem backend uses private versioned keys, same-directory temporary files,
file sync, atomic hard-link publication, and directory barriers through the
filesystem root. Separate processes may safely race identical publication.
The `content/s3` implementation provides the same immutable contract over an
operator-configured S3-compatible prefix: it verifies SHA-256 and exact length
in a local spool before one conditional `PutObject`, compares any retained
collision exactly, validates full/range response metadata, and hash-checks full
downloads. It deliberately avoids optional checksum trailers for wider S3
compatibility and does not claim multipart upload, listing, caching, or delete.

`catalog/sqlite` requires a trusted private directory: it rejects symlink path
components but cannot fence hostile concurrent path, WAL, or SHM replacement by
another identity that can rename entries in that directory. Durability also
depends on truthful local-filesystem locking and sync behavior. Callers should
use contexts with deadlines when write-lock wait time must be bounded.
`content/filesystem` has the same trusted-root and truthful-sync assumptions;
it rejects observed symlinks but does not defend against hostile same-identity
path replacement or provide object deletion.

The hosting-neutral `bucket` façade composes a catalog, ordinary-content store,
and trusted CAS reconstruction capability. Repository keys map to deterministic
opaque CAS namespaces, so callers select repositories rather than raw storage
scopes. `OpenFile` resolves one immutable snapshot entry and returns the same
typed metadata and stream shape for ordinary and Xet-backed files, including
half-open ranges, stable entity tags, cancellation, and typed backend errors.
`PutBlob` immutably verifies ordinary content. `PublishSnapshot` canonicalizes
the complete tree, observes each expected ordinary key and namespace-scoped
Xet index dependency and reported size, then delegates the snapshot/ref update
to the catalog's atomic publication transaction. The preflight is not an
object-store transaction: it does not rehash payload bytes or prevent
out-of-band deletion after a successful check.
The local filesystem + SQLite profile is restart-tested with old-revision Xet
reads and durable cross-repository namespace isolation. Authentication and
Hugging Face-compatible HTTP translation remain separate higher boundaries.
An opt-in remote composition test exercises the same typed publication and
full/range reads across S3 ordinary/CAS bytes, PostgreSQL catalog/CAS metadata,
scoped CAS tokens, process restart, and repository-isolation failures.
The independent `auth` package supplies hosting-neutral contracts for
pluggable Hub credential authentication, separate repository authorization,
canonical repository-to-CAS scope exchange, and short-lived HMAC-SHA256 CAS
bearer credentials. It does not define Hub HTTP routes or a hosted-provider
token format.

The top-level `hfcompat` adapter implements the pinned authenticated model read
and write profile without moving hosting concepts into `bucket`, `model`, or
CAS. In addition to metadata, tree, token, and range-capable resolve routes, it
supports whoami, model-repository creation, preupload, streamed commit control,
native Xet write-token exchange, and a capability-bound basic LFS fallback.
Mutable refs are pinned to an immutable OID before file access, every recognized
repository request is authorized before catalog lookup, and denied repositories
are concealed as absent. `BucketService` decorators and delegated
`SnapshotPublisher` implementations support host-owned versioning; see
[docs/HF_WRITE_AND_VERSIONING.md](docs/HF_WRITE_AND_VERSIONING.md).

The `bucket/hosted` package is the embeddable application composition boundary.
Its constructor accepts one catalog, ordinary-content store, CAS blob/index
bundle, repository policy, and coherent CAS token authority; it installs the
namespace-scoped CAS authorizer rather than accepting a second policy. The
result promotes the typed `bucket.Service` API and exposes separate
`HubHandler` and `CASHandler` mounts. It also exposes bounded read-only CAS
inventory and payload-audit pages and requires the catalog's optional,
repository-scoped `RefLister` inventory capability. Core `bucket.Service`
remains compatible with catalogs that omit that maintenance capability and
returns `bucket.ErrUnsupported` from `ListRefs`. Ref and CAS inventory pages
are weakly consistent diagnostics; they do not establish complete reachability
or make object deletion safe.

The implementation is verified against official `huggingface/xet-core` 1.6.0
commit `de71453d952bd8b806edaa997c72313051a49050` and the checksummed official
reference corpus. See [CONFORMANCE.md](CONFORMANCE.md),
[PROTOCOL_COMPATIBILITY.md](PROTOCOL_COMPATIBILITY.md), and
[IMPLEMENTATION_SOURCES.md](IMPLEMENTATION_SOURCES.md) for the exact claims and
source baseline.

## Requirements

- Go 1.26 or newer to build the module. The minimum was raised deliberately so
  every supported build can consume patched Unicode, PostgreSQL, and S3
  dependencies; CI runs all jobs on the latest Go 1.26 patch release.
- An Xet CAS endpoint and access token for real transfers. The token may be
  empty for an unauthenticated local CAS.

```sh
go get github.com/jmwoliver/xet-go
```

The release library has no C or Rust dependency. Its direct dependencies are
pure-Go BLAKE3, LZ4, compressed-response codecs, SQLite, PostgreSQL, and S3
clients, plus the Go platform syscall package used for strict local-filesystem
locking. Cloud and SQL dependencies remain isolated in their backend packages;
the primitives and standalone client do not import them.

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

## Issue repository-scoped CAS credentials

Hub authentication, repository policy, and CAS authorization are deliberately
separate. A control plane can compose them without passing the Hub credential
to the CAS server:

```go
tokens, err := auth.NewCASTokenManager(auth.CASTokenManagerOptions{
	Issuer:     "miniface",
	Audience:   "https://cas.example",
	SigningKey: auth.HMACKey{ID: "2026-08", Secret: casSigningKey},
	DefaultTTL: 5 * time.Minute,
	MaximumTTL: 15 * time.Minute,
})
if err != nil {
	return err
}
broker, err := auth.NewBroker(auth.BrokerOptions{
	Authenticator: hubAuthenticator,
	Authorizer:    repositoryPolicy,
	Tokens:        tokens,
})
if err != nil {
	return err
}
casAuthorizer := auth.CASAuthorizer{Verifier: tokens}
```

`Broker.IssueCASToken` accepts a validated `model.RepoKey`, never an arbitrary
storage namespace. It authenticates the Hub credential, separately authorizes
each requested read/write permission, and issues a credential containing the
subject, exact opaque audience, derived namespace, permissions, issue/not-before
times, expiration, key ID, and random token ID. Read credentials cannot upload;
write credentials can upload Xorbs and shards and perform the namespace-scoped
dedup lookup used by the pinned official Rust upload flow, but cannot read files
or Xorbs. Unknown CAS operations fail closed.

The compact credential is a private hosting-neutral format, not a claim of
wire parity with any hosted token issuer; official Rust treats the bearer as
opaque. Keys must contain at least 32 random bytes. Verification keys support
rotation and are defensively copied. Because HMAC verifiers can also mint
credentials, deploy them only inside the signing trust boundary; use an
asymmetric issuer before placing verifiers outside that boundary. The bearer is
reusable and therefore replayable until expiration. Use TLS, short TTLs, exact
audiences, least privilege, key retirement, and audit the token ID rather than
the credential. One-time consumption is intentionally not offered because one
official upload reuses a token across concurrent dedup, Xorb, shard, and retry
requests.

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
`PublishShard` transaction. Schema version 4 adds durable namespace-scoped
shard registrations to the typed tables introduced by earlier versions. The
v3-to-v4 migration boundedly backfills shard sources visible in existing file
and dedup indexes. New namespace-scoped shard registrations commit atomically
with their file, dedup, and SHA indexes and are available through bounded
`IndexLister` pagination. Both constructors reject symlinked leaf paths and
return `ErrDurabilityUnsupported` without modifying their target on platforms
where strict directory durability is not implemented.

For S3-compatible CAS bytes, configure an AWS SDK v2 client with the provider's
endpoint, credentials, addressing mode, and retry policy, then wrap it with the
isolated `xetcas/server/s3store` adapter:

```go
s3Client := s3.NewFromConfig(awsConfig, func(options *s3.Options) {
	options.BaseEndpoint = aws.String("https://objects.example")
	options.UsePathStyle = true // commonly required by MinIO
})
blobs, err := s3store.New(s3Client, s3store.Options{
	Bucket:          "model-content",
	Prefix:          "production/xet",
	TempDirectory:   "/var/lib/my-service/xet-spool",
	PresignExpiry:   15 * time.Minute,
})
if err != nil {
	return err
}
cas, err := server.New(server.Options{
	Blobs: blobs, Index: durableIndex,
	Authorizer: authorizer, Signer: blobs,
	DedupProtectionKey: protectionKey,
})
```

The adapter implements `BlobStore`, `BlobLister`, and `RangeURLSigner`. It uses
versioned hash-derived keys below one normalized operator-controlled prefix,
exact-length local spooling, S3 `If-None-Match: *` publication, and a full byte
comparison before treating a conditional collision as idempotent. Reads verify
S3 length and `Content-Range` metadata. Presigned URLs bind the exact requested
`Range` header; consumers must send that same header, as the Xet client does.
Listing is bounded and lexically keyset-paginated rather than loading a bucket
inventory. S3 stores only immutable Xorb/shard bytes: namespace-scoped file,
dedup, SHA, stage, lease, and shard-registration truth remains in the injected
index. The current adapter deliberately uses streaming single-object
`PutObject`, not multipart upload, and makes no multipart claim.

Inventory requires general-purpose S3 semantics: lexically ordered
`ListObjectsV2` results plus `StartAfter` support. S3 directory buckets are not
supported. `If-None-Match` prevents overwrites made through the adapter, but
operators must use bucket policy, Object Lock, lifecycle controls, and scoped
credentials as appropriate to prevent out-of-band replacement or deletion.
Signing credentials must remain valid through `PresignExpiry`; the returned
lease lifetime is derived from the URL's actual `X-Amz-Date` and
`X-Amz-Expires`, not from a separate local clock.

An opt-in real-backend test exercises sequential conditional writes,
byte-identical retry, conflict detection, `HEAD`, exact ranges, inventory,
SigV4 range signing, and cleanup against MinIO or another compatible endpoint:

```bash
XET_S3_INTEGRATION=1 \
XET_S3_ENDPOINT=http://127.0.0.1:9000 \
XET_S3_BUCKET=xet-go-test \
XET_S3_ACCESS_KEY=... \
XET_S3_SECRET_KEY=... \
go test -run TestS3CompatibleIntegration ./xetcas/server/s3store
```

The bucket must already exist unless the test is explicitly allowed to create
it with `XET_S3_CREATE_BUCKET=1`. `XET_S3_REGION` defaults to `us-east-1`; set
`XET_S3_PATH_STYLE=false` for providers requiring virtual-hosted bucket URLs.

For durable remote CAS metadata, pair the S3 blob adapter with
`xetcas/server/postgresstore`. `Open` owns its connection pool; `New` accepts a
caller-owned pool and leaves it open on `Close`:

```go
pool, err := pgxpool.New(ctx, os.Getenv("XET_POSTGRES_DSN"))
if err != nil {
	return err
}
defer pool.Close()

index, err := postgresstore.New(ctx, pool, postgresstore.Options{
	Schema: "xet_cas",
})
if err != nil {
	return err
}
cas, err := server.New(server.Options{
	Blobs: blobs, Index: index,
	Authorizer: authorizer, Signer: blobs,
	DedupProtectionKey: protectionKey,
})
```

The adapter implements `IndexStore`, `IndexLister`, `ProtectionStore`, and
`ProtectionExpiryStore`; it stores no payload bytes. It uses a private,
explicitly qualified schema without changing `search_path`. Construction takes
a schema-specific transaction advisory lock, applies versioned migrations, and
rejects a database schema newer than the library. Xorb metadata is global
inside that schema. Shard registrations, files, dedup records, SHA
associations, stages, and leases are namespace-scoped. `PublishShard` sorts
logical keys into a stable lock order and commits all records in one
transaction, preventing partial visibility and opposite-order deadlocks.
Protection timestamps remain nanosecond-exact signed integers; renewals only
extend them and expired cleanup uses an atomic compare-and-delete.

The opt-in PostgreSQL integration suite requires a pre-existing database and a
principal allowed to create and drop private test schemas:

```sh
XET_POSTGRES_INTEGRATION=1 \
XET_POSTGRES_DSN='postgres://xet@127.0.0.1:5432/postgres?sslmode=disable' \
go test -race -run TestPostgreSQLIntegration ./xetcas/server/postgresstore
```

It covers namespace isolation, immutable conflict handling, transactional
rollback, independent-pool restart visibility, concurrent publication and
migration, bounded scoped/global pagination, nanosecond expiry, stale cleanup
versus renewal, retained corruption detection, and pool ownership. PostgreSQL
and S3 still cannot share a transaction: CAS publication relies on immutable
object writes followed by protected atomic index publication, and ambiguous or
failed index publication retains its durable stage for reconciliation.

The separate `catalog/postgres` adapter implements the model catalog over
PostgreSQL. It follows the same ownership convention: `Open` owns its pool and
`New` leaves a caller-owned pool open. The default private schema is
`xet_catalog`; a deployment may select another lowercase unquoted PostgreSQL
identifier:

```go
modelCatalog, err := catalogpostgres.New(ctx, pool, catalogpostgres.Options{
	Schema: "xet_catalog",
})
if err != nil {
	return err
}
defer modelCatalog.Close()
```

Initialization requires UTF-8 server and client encodings, serializes migration
with a schema-specific advisory transaction lock, and rejects newer or
structurally incompatible retained schemas. Text keys and pagination use
PostgreSQL's `C` collation to preserve the catalog contract's UTF-8 byte order.
Snapshot rows, their complete file tree, the target ref, and first-publication
`main` are committed in one transaction after locking the repository row.
Publication and ref updates accept exact target-state replay, making retry safe
after an ambiguous commit result without permitting a stale writer to overwrite
a different ref value.

Run the real-backend contract against a principal allowed to create and drop
private test schemas:

```sh
XET_POSTGRES_INTEGRATION=1 \
XET_POSTGRES_DSN='postgres://xet@127.0.0.1:5432/postgres?sslmode=disable' \
go test -race ./catalog/postgres ./catalog/memory
```

The suite runs the shared catalog contract and separately checks independent
pool restart visibility, concurrent writers, migration serialization, exact
nanosecond timestamps, UTF-8 byte-order pagination, fault-injected transaction
rollback, retained-state/schema corruption, cursor isolation, and pool
ownership. It does not claim Hugging Face-compatible commit OID derivation or a
Hub control plane.

With both backends available, run the composed remote-profile contract:

```sh
XET_POSTGRES_INTEGRATION=1 \
XET_POSTGRES_DSN='postgres://xet@127.0.0.1:5432/postgres?sslmode=disable' \
XET_S3_INTEGRATION=1 \
XET_S3_ENDPOINT=http://127.0.0.1:9000 \
XET_S3_BUCKET=xet-go-test \
XET_S3_ACCESS_KEY=... \
XET_S3_SECRET_KEY=... \
go test -race -run TestS3PostgreSQLRemoteProfile ./xetcas/server
```

This suite injects cross-backend failure before the object write, after an S3
write whose success response is lost, at the PostgreSQL shard-publication
boundary, and both before and after an applied stage deletion. It closes and
recreates both adapters between recovery passes, reconstructs exact full and
ranged files, reconciles an unstaged canonical Xorb's missing global layout
after restart, denies an identical file hash in another namespace, and races
two separate Go processes publishing the same content. Required Linux CI runs
it against PostgreSQL 15 and MinIO `RELEASE.2025-09-07T16-13-09Z`.

When the index implements `ProtectionStore`, the service durably stages each
Xorb or shard before writing its immutable blob, renews that stage throughout a
slow publication, and removes it only after logical index publication. A failed
or ambiguously completed publication conservatively leaves the stage for future
recovery and reachability-aware cleanup. Active typed reads acquire and renew a
file lease before traversing the reconstruction graph. Signed reconstruction
responses retain a detached lease through the maximum `SignedRange.ExpiresAt`
returned by the signer plus `ReadLeaseTTL` as a grace interval. This is why a
`RangeURLSigner` must return both the URL and its authoritative expiration.
Catalog reachability and destructive garbage collection are not yet
implemented. `ProtectionExpiryStore` only lists and conditionally removes
expired protection metadata. Its cursors are bound to a stable cutoff, and
compare-before-delete preserves a record renewed after it was listed. These
methods never delete blob payloads: an expired or removed stage must not be
treated as permission to delete bytes without the documented classification,
age/grace, and reachability checks.

`Service.RecoverExpiredBlobStages` is the restart-safe publication reconciler.
It reads one expiry page at a stable cutoff, exactly and boundedly reads each
present object, requires the canonical complete Xorb or full-shard encoding,
reruns shard registration against durable Xorb metadata, and idempotently
replays the same logical index publication used by uploads. Only successful
publication is followed by cutoff-bound conditional stage deletion. Missing,
corrupt, dependency-blocked, conflicting, and backend-failed stages remain for
a later pass or operator decision. Recovery is administrative: it does not call
the tenant authorizer, create replacement stages, write blobs, or delete blob
payloads. A canceled partial page has no continuation cursor and is safe to
retry from the original request.

Stores may additionally implement `BlobLister`, `IndexLister`,
`ProtectionStore`, and `ProtectionExpiryStore` for bounded, keyset-paginated
operational scans and lifecycle roots. Memory and SQLite implement expiry scans
with pages ordered by expiration, namespace, and protection ID. The memory,
filesystem, and SQLite stores collectively provide these capabilities for blobs,
Xorbs, namespace-scoped files and dedup records, namespace-scoped SHA
associations, blob stages, and file leases. Cursors are opaque and tied to one
operation, blob kind, namespace-filter mode, and, for expiry scans, cutoff.
SQLite seeks through its
composite primary keys; filesystem scans seek the two-level hash-prefix tree
and stop after finding one page, while reading and sorting one
four-hex-character leaf as the smallest unit of work. The memory backend scans
its unordered maps but retains at most `Limit+1` keys and clones only selected
Xorb layouts and file recipes, so retained page memory is bounded even though
scan work is O(N). Listers expose physical or all-namespace state without
performing tenant authorization and belong behind an administrative boundary.
Pages are weakly consistent rather than a snapshot, so destructive maintenance
still requires quiescence, an epoch or lease, or a grace barrier.

`Service.AuditInventory` composes those listers into one bounded, read-only
administrative page of forward metadata checks. It covers physical Xorb and
shard objects; global Xorb layouts; namespace-scoped shard, file, dedup, and
SHA-256 records; and blob stages and file leases. File, SHA, and lease checks
reuse canonical shard registration validation, including recipe identities,
term verification, derived size, referenced Xorb metadata, and backing-object
sizes. Scoped dependencies are always resolved in the listed record's
namespace. The operation never calls the tenant `Authorizer`; expose it only
behind a separate administrative authorization boundary.

An audit result of `AuditStatusNoIssueFound` means only that the documented
metadata and `BlobStore.Head` checks found no issue at their individual lookup
times. Audit does not read, decode, or hash payload bytes, recompute a file's
SHA-256, prove that a shard payload contains a listed file or dedup term,
establish catalog reachability, or authorize retention or deletion. Physical
shard reachability is therefore explicitly indeterminate. Registrations,
stages, and leases are evidence and protection roots, never deletion authority.
Pages are weakly consistent; concurrent publication can produce transient
results or inserts behind a cursor. Backend point failures remain per-item
diagnostics and iteration advances past them, so operators must retain and
retry failed subjects explicitly. Cancellation may return completed diagnostic
items, but never a continuation; retry from the original request cursor. There
is no payload-sweep API.

`Service.AuditBlobPayloads` is the separate, stronger physical-byte check. It
lists one bounded Xorb or shard page, reads each object exactly and one at a
time, closes every reader, and validates the canonical durable encoding and
its key identity. Xorbs must be current V1 complete objects with a zero
uniqueness nonce; shards must be canonical full shards. Results distinguish a
missing object, invalid listed/read size, malformed or noncanonical payload,
key/content identity mismatch, and backend check failure. A successful result
proves only the bytes read for that object at that time. It does not inspect
namespace-scoped registration or catalog reachability, recompute reconstructed
file SHA-256 values, repair content, or authorize retention or deletion. Like
the metadata audit, it is administrative, weakly consistent across pages, and
withholds the continuation cursor after cancellation. Backend point failures
remain per-item diagnostics and iteration advances past them, so operators must
retain and retry failed entries explicitly.

`Service.RepairXorbIndexes` is the deliberately narrower repair boundary. It
boundedly lists physical Xorbs, exactly reads and canonicalizes one complete V1
payload at a time, and inserts only a missing global `XorbRecord`. Existing
metadata must be fully valid and byte-layout-identical; a valid different
layout is reported as a conflict and malformed retained metadata as corruption.
`reconciled` is observational: under a concurrent identical writer it means
the derived immutable record was accepted, not that this invocation owned the
insert. The operation never writes or deletes payloads, performs no tenant
authorization, and makes no reachability or retention decision. A physical
shard does not encode its publication namespace, so namespace-scoped shard,
file, dedup, and SHA indexes are not inferred without a retained stage.
Cancellation withholds the continuation cursor.

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
| `xetcas/server/s3store` | S3-compatible immutable Xorb/shard bytes, bounded inventory, and exact SigV4 range signing |
| `xetcas/server/postgresstore` | PostgreSQL CAS indexes, transactional shard publication, protections, expiry, and bounded inventory |
| `model` | Validated repository, revision, immutable snapshot, ref, path, and ordinary/Xet file-reference domain types |
| `catalog` | Hosting-neutral repository catalog contract and typed errors |
| `catalog/memory` | Transactional in-memory catalog reference semantics |
| `catalog/sqlite` | Pure-Go durable SQLite catalog with atomic snapshot/ref publication, restart persistence, and bounded keyset pagination |
| `catalog/postgres` | PostgreSQL catalog with versioned private-schema migrations, serialized repository publication, strict schema validation, and bounded byte-ordered pagination |
| `content` | CAS-independent immutable ordinary-blob storage contract, identities, ranges, and typed errors |
| `content/memory` | Concurrent ephemeral ordinary-content storage and reference semantics |
| `content/filesystem` | Linux/macOS crash-consistent immutable ordinary-content publication and streaming |
| `content/s3` | S3-compatible conditionally immutable ordinary-content publication and verified full/range streaming |
| `auth` | Pluggable Hub identity/policy contracts and scoped short-lived CAS bearer credentials |
| `bucket` | Hosting-neutral repository publication/ref façade and uniform ordinary/Xet file streaming with derived CAS namespace isolation |
| `hfcompat` | Authenticated Hugging Face model read/write translation, scoped CAS token exchange, and basic LFS fallback |
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
./conformance/check-coverage.sh # core-only unless PostgreSQL integration is configured
./conformance/fuzz-smoke.sh
./conformance/cross-compile.sh
```

The required Linux CI job provisions PostgreSQL 15 and pinned MinIO, sets both
integration capability bundles, and executes the individual and composed real
backend suites under race and coverage. It enforces the complete 95% aggregate;
the coverage script refuses a PostgreSQL-free run when `CI=true`.

Run every pinned official reference, Rust differential, and Rust local-CAS gate
with Rust 1.95.0 installed:

```sh
./conformance/run-official-conformance.sh
```

The opt-in pinned official Python read and `hf_xet` reconstruction checks use
the isolated environment documented in `conformance/README.md`:

```sh
XET_HF_CLIENT_PYTHON="$(pwd)/.cache/hf-client/bin/python" \
  go test -race -run '^TestOfficialPythonClient' -count=1 -v ./hfcompat
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
