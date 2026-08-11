# Protocol compatibility

## Baseline

- Hugging Face Xet specification: v1.1.0.
- Official Rust implementation: `huggingface/xet-core` 1.6.0 commit
  `de71453d952bd8b806edaa997c72313051a49050`.
- Official reference files: `xet-team/xet-spec-reference-files` commit
  `c4aa3a3f15b1395fff5ce934784bf6c8f2d62de8`.

## Compatibility decisions

| Topic | Behavior |
|---|---|
| Hash text | Four little-endian 64-bit limbs rendered as lowercase hexadecimal |
| Chunking | Official 64 KiB GearHash target, 8 KiB minimum, 128 KiB maximum, and exact gear table |
| Xorb compression | None, LZ4, and BG4-LZ4 decode; production Auto uses the official BG4 predictor and 32-chunk/file-boundary retest policy |
| Network xorb footer | Never emitted; the universal decoder accepts footerless, current V0/V1 `XETBLOB`, and official-reference legacy `XETB` forms |
| Upload shard footer | Omitted and header footer size set to zero |
| Upload verification | One verification entry per reconstruction term |
| Xorb namespace | `default` |
| Dedup namespace | Go clients use OpenAPI's `default-merkledb`; servers also accept released xet-core's shared-prefix `default` for wire compatibility |
| Reconstruction | v2 preferred; v1 fallback only when the newer route is unsupported |
| Batch reconstruction | Documented POST preferred; legacy GET is an explicit fallback |
| Shard upload | v2 NDJSON preferred; v1 fallback only when unsupported |
| Xorb limits | At most 64 MiB raw input and 8,192 chunks, with serialized-size validation |
| Global protection hash | Keyed BLAKE3, despite historical “HMAC” naming |
| Upload shard accounting | Zero serialized-xorb size is accepted and preserved because released xet-core upload sessions emit it; durable size/layout come from the independently validated xorb |
| CAS server | Storage-neutral blob/index/signer/authorizer interfaces; canonical xorb and shard publication; v1/v2, batch, dedup, HEAD, and sparse-delta routes |
| Shard publication | Renewable namespace-scoped stage, canonical blob, then one atomic `PublishShard` for non-unique dedup, immutable SHA-256, and first-valid file records; failed/ambiguous publication retains the stage |
| Shard progress | v2 NDJSON emits validation/commit/result or terminal error frames and periodically repeats the latest frame as a heartbeat |
| Server work limits | Configurable file/xorb/term/chunk-reference budgets, context-aware planners, bounded compact-gap memory, and pre-buffer ingestion admission |
| Typed reconstruction | `Service.OpenFile` streams full files or ranges directly from global physical Xorbs reached through a namespace-scoped file recipe, with chunk/length validation, optional whole-file SHA-256, backpressure, cancellation, and deterministic closure |
| Local durable storage | Linux/macOS immutable filesystem blobs plus a pure-Go SQLite WAL index; strict file/directory barriers, process-root locking, restart persistence, transactional shard-index publication, and schema-v4 lifecycle and shard-registration metadata |
| S3-compatible CAS bytes | Isolated AWS SDK v2 adapter with versioned canonical keys, exact-length spooling, conditional immutable publication plus byte-identical collision verification, strict range metadata, bounded lexical inventory, and SigV4 URLs bound to one exact range |
| PostgreSQL CAS metadata | Isolated pgx adapter with versioned private-schema migrations, global Xorb metadata, namespace-scoped logical indexes/protections, transactional shard publication, stable lock ordering, nanosecond expiry, and bounded keyset inventory |
| Administrative audit | Bounded, weakly consistent, read-only forward metadata checks across blob/index/protection inventories; no tenant authorization, payload hashing, catalog reachability, repair, or deletion authority |
| Physical payload audit | Bounded, sequential exact reads of physical Xorbs and shards with canonical durable-form and key-identity verification; no namespace reachability, repair, retention, or deletion authority |
| Delta upload | v2 file-chunk-hashes dirty windows with exact compact Merkle-subtree JSON and merging |
| CAS response encoding | Bounded identity, gzip, zstd, and stacked content encoding for JSON, NDJSON, and binary bodies |
| Credential refresh | Refresh 30 seconds before expiry, coalesce concurrent refresh, and retry exactly once after a 401 invalidation |
| Signed URLs | No bearer token, session ID, cookie, redirect, query-bearing error, or cache persistence |
| Retry | Replay-safe exponential retry, bounded attempts, HTTP-date/delta Retry-After, and context cancellation |
| Transport concurrency | Separate adaptive upload/download limits; official starting points 2/4 and maximum 64; fixed mode supported |
| Download verification | Complete files verify structure, term hashes, Xet identity, size, and optional SHA-256; ranges verify all available structure but not a whole-file identity |
| Persistent state | Content-only checksummed range/shard cache and identity-only replay journal; credentials and signed URLs are excluded |
| Runtime | Pure Go, CGO disabled, Go 1.23 language baseline |

## Exactness boundary

Canonical hashes, Merkle trees/subtrees, uncompressed network/complete V1
xorbs, footerless upload shards, and footer-bearing full shards match official
Rust byte-for-byte. Protected dedup shards are accepted by the Rust decoder,
and released Rust clients consume them for nonzero global-dedup reuse. LZ4 has
more than one valid serialized representation, so compressed xorbs are
required to select the same per-chunk scheme and decode bidirectionally with
identical content, boundaries, lengths, and identities. The adaptive controller
preserves the official limits and behavioral contract but uses Go-native AIMD rather than
copying Rust's latency model. Both allowances are explicitly permitted by the
module boundary because they do not alter the protocol.

Malformed-input permissiveness is not an interoperability promise. The pinned
negative differential matrix records that xet-core's streaming readers accept
some empty/truncated Xorb streams and ignore some shard version/footer/trailing
conditions that Go rejects. Go retains the stricter bounded decoder because it
accepts every canonical artifact produced by the pinned Rust implementation and
does not need to accept malformed artifacts for wire compatibility.

The core and server APIs contain no Hugging Face repository, revision, path,
user token, commit, Git, S3, or LFS concepts. They accept only generic Xet CAS
credentials, storage capabilities, logical storage namespaces, and protocol
identities. Mapping repository policy to a grant namespace and cloud-specific
signing remain adapter responsibilities.

Compatibility is continuously checked by the requirement matrix in
[CONFORMANCE.md](CONFORMANCE.md).

## Namespace and publication invariants

- Xorb bytes may be physically deduplicated globally, but hash possession is
  not authorization. `Authorizer.Authorize` runs before every externally
  reachable file, xorb, dedup, and shard operation and must enforce the
  credential's repository/storage reachability.
- `Grant.Namespace` scopes file recipes, dedup records, and `(SHA-256, size) ->
  Xet file` associations. All file, reconstruction, chunk-hash, and dedup reads
  resolve those scoped records before they can reach global physical objects.
- Xorb layout metadata and bytes remain global content-addressed identities.
  Xorb existence can therefore be reused across namespaces without copying
  bytes, but it does not expose file bytes or a dedup shard. Publishing a
  validated shard under `OperationWriteShard` creates that grant namespace's
  own logical file and dedup links to its transitive Xorbs.
- Every successful logical shard publication also creates a durable
  namespace-scoped shard registration. It commits atomically with that
  publication's file, dedup, and SHA indexes and is available through bounded
  operational iteration; the physical shard blob remains globally addressed.
- File reconstruction and shard registration authorize their top-level
  operation once; transitive Xorb lookups inherit the enclosing scoped file or
  shard-write grant. The interface deliberately does not authorize each
  content-addressed Xorb a second time.
- `Service.OpenFile` and the v1/v2 HTTP reconstruction routes share the same
  bounded planner. The typed stream additionally reads chunk-aligned physical
  ranges, coalesces adjacent reads in logical order, and validates decoded
  chunks before returning bytes.
- Reconstruction publishes a namespace-scoped file lease before the first file
  or Xorb-index lookup. Active typed streams renew that lease until settlement;
  signed reconstruction descriptors retain it through the signer's maximum
  declared URL expiration plus the configured read-lease grace interval.
- Xorb publication stores canonical immutable bytes before publishing layout
  metadata. When `ProtectionStore` is present, Xorb and shard publication first
  creates and renews a durable namespace-scoped stage. Shard publication then
  atomically publishes all namespace-scoped dedup, SHA, and reconstructable
  file records through one index-store call before releasing its stage.
- Every index write is idempotent. File and dedup indexes are non-unique
  secondary indexes and may retain any already-valid durable source. A SHA key
  is immutable within its namespace.
- SHA associations are independent `(namespace, digest, size) -> file`
  mappings. Because a file index may retain an earlier valid recipe without
  optional SHA metadata, auditing a SHA row validates its scoped file target
  and derived size rather than requiring the retained recipe to repeat that
  SHA. A retained file recipe that does declare SHA metadata must resolve back
  through the corresponding scoped association.
- The service's publication order makes retry after a lost response safe.
  Object and index stores still do not share a transaction: failed or ambiguous
  index publication retains the durable stage as a recovery/GC root. Durable
  adapters must not report success before their writes are durable.

## Durable backend status and gap list

The concurrency-safe memory store remains the semantic reference. The local
durable profile now pairs `FilesystemBlobStore` with `SQLiteIndexStore`:

- blobs use versioned, hash-derived paths, exact declared-length streaming,
  immutable hard-link publication, byte-for-byte idempotence checks, and file
  plus directory durability barriers;
- one process owns a filesystem root at a time, startup removes only abandoned
  temporary files older than the configured grace period, and path components
  beneath the private root are rejected when they are symlinks;
- SQLite is created privately, uses WAL with `synchronous=FULL`, applies safety
  pragmas to every pooled connection, enforces key storage classes and lengths
  through schema version 4, publishes shard registrations, dedup, scoped SHA,
  and file records in one immediate transaction, and persists renewable blob
  stages and file leases; migration to v4 boundedly backfills registrations
  from shard sources visible in existing file and dedup indexes;
- file and dedup indexes deterministically retain their first valid source,
  while Xorb and scoped SHA identities reject immutable conflicts;
- optional operational listers provide opaque, operation- and filter-specific
  keyset cursors for blobs, Xorbs, scoped file and dedup records, scoped SHA
  associations, shard registrations, blob stages, and file leases; SQLite
  query-plan tests prove composite-primary-key seeks, while expiration scans seek dedicated
  `(expires_at, namespace, id)` indexes with cursors bound to a stable cutoff;
- memory and SQLite conditionally delete expired stage/lease metadata in the
  same atomic comparison as deletion, so a stale scan cannot remove a renewed
  protection; this never deletes payloads or authorizes physical collection;
- the CAS service can reconcile expired stages after restart without tenant
  credentials or new blob writes: canonical complete Xorbs and full shards are
  exactly revalidated, shard registration is recomputed from durable Xorb
  metadata, logical indexes are replayed idempotently, and only then is the
  original stage conditionally removed; missing, corrupt, blocked, conflicting,
  and backend-failed stages remain protected;
- filesystem pages seek the hash-prefix tree without collecting the whole
  store (one four-hex-character leaf remains the minimum sorted work unit);
- memory pages scan unordered maps but retain only `Limit+1` ordered keys and
  clone only selected large records, bounding retained memory independently of
  inventory size;
- one bounded administrative audit page can perform forward checks over every
  current blob/index/protection inventory. `no-issue-found` means only that the
  kind-specific metadata and `Head` checks succeeded at lookup time. It does
  not read or hash payload bytes, prove shard contents, recompute file SHA-256,
  determine catalog reachability, or authorize deletion. Physical shard
  reachability remains indeterminate; point failures advance as retained
  diagnostics, while cancellation withholds the cursor and requires retry from
  the original request;
- a separate bounded physical-payload audit exactly reads one Xorb or shard at
  a time and verifies its canonical durable encoding and key identity. It
  distinguishes missing, size-invalid, malformed/noncanonical,
  identity-mismatched, and backend-failed objects. Success proves only the
  bytes observed for that object, not namespace reachability, file SHA-256,
  retention, or deletion safety; and
- the same backend contract suite runs against memory/filesystem and
  memory/SQLite, including cancellation, namespace isolation, concurrent
  publication and pagination mutation, corrupt-row detection, injected
  publication failures, close/reopen, and full reconstruction after restart.
- `xetcas/server/s3store` implements only remote immutable physical bytes,
  bounded physical inventory, and signed range capabilities. It centralizes a
  versioned key layout, rejects ambiguous prefixes and object metadata, uses
  `If-None-Match: *`, compares existing bytes before accepting an idempotent
  collision, retries bounded S3 `409` publication races, and binds `Range` into
  SigV4 signed headers. Its authoritative capability expiry is parsed from the
  signed URL. Inventory requires general-purpose S3's lexical `ListObjectsV2`
  and `StartAfter` semantics; directory buckets are unsupported. Adapter-level
  conditionals do not replace bucket policy/Object Lock controls against
  out-of-band mutation. A sequential real-backend opt-in suite was exercised
  against MinIO
  `RELEASE.2025-09-07T16-13-09Z`, including conditional retry/conflict,
  `HEAD`, `GET` range metadata, inventory, and fetching the presigned range.
  The adapter uses single-object `PutObject`; multipart publication has not
  been implemented or claimed.
- `xetcas/server/postgresstore` implements the remote index, iteration, stage,
  lease, and expiry contracts over PostgreSQL. Every table is explicitly
  schema-qualified; construction serializes versioned migrations with a
  schema-specific transaction advisory lock and rejects newer schemas. Xorb
  layout metadata is global within the private schema, while shard
  registrations, file recipes, dedup records, SHA associations, stages, and
  leases are namespace-scoped. Shard publication clones and sorts caller input
  into a stable lock order, validates retained records, and atomically commits
  all logical metadata. Protection times are signed Unix nanoseconds rather
  than lossy PostgreSQL timestamps. Bounded cursors are canonical and bound to
  operation, scope, mode, and expiry cutoff. An opt-in real PostgreSQL 15 suite
  proves independent-pool restart visibility, migration serialization,
  opposite-order and conflicting concurrent publication, transactional
  rollback, scoped/global continuation, retained-corruption detection,
  nanosecond expiry, renewal/deletion races, and caller/adapter pool ownership.

Strict directory durability is currently implemented only on Linux and macOS.
Other platforms return `ErrDurabilityUnsupported` before changing the requested
filesystem or SQLite path. The local backend assumes a filesystem with truthful
`fsync`, hard-link, and advisory-lock semantics; concurrent mutation by another
process running as the service identity is outside its threat model.

Remaining production storage boundaries are:

1. operator policy and grace-based cleanup for missing, corrupt, or persistently
   blocked recovery stages (expiration or protection deletion alone never
   authorizes object deletion);
2. catalog reachability roots and read/maintenance epochs for destructive work;
3. repair, resumable mark-and-sweep, and guarded garbage collection built on
   the current bounded metadata and physical-payload audits plus explicit root
   primitives;
4. MinIO/PostgreSQL combined multi-process and cross-backend publication
   fault-injection evidence for the remote profile.
