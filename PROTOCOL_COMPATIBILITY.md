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
| Shard publication | Canonical blob, non-unique dedup indexes, scoped SHA-256, then first-valid reconstructable file records; in-process tests prove idempotent replay after partial failure, not cross-store atomicity |
| Shard progress | v2 NDJSON emits validation/commit/result or terminal error frames and periodically repeats the latest frame as a heartbeat |
| Server work limits | Configurable file/xorb/term/chunk-reference budgets, context-aware planners, bounded compact-gap memory, and pre-buffer ingestion admission |
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

The core and server APIs contain no Hugging Face repository, revision, path,
user token, commit, Git, S3, or LFS concepts. They accept only generic Xet CAS
credentials, storage capabilities, scopes, and protocol identities. Repository
reachability and cloud-specific signing remain adapter responsibilities.

Compatibility is continuously checked by the requirement matrix in
[CONFORMANCE.md](CONFORMANCE.md).

## Namespace and publication invariants

- Xorb bytes may be physically deduplicated globally, but hash possession is
  not authorization. `Authorizer.Authorize` runs before every externally
  reachable file, xorb, dedup, and shard operation and must enforce the
  credential's repository/storage reachability.
- File reconstruction and shard registration authorize their top-level
  operation once; underlying global Xorb lookups inherit that grant. An
  `OperationWriteShard` grant therefore must be allowed to reference the
  service's entire Xorb storage domain unless the injected index is itself
  partitioned. The current interface does not authorize each referenced Xorb.
- `Grant.Namespace` scopes `(SHA-256, size) -> Xet file` associations only.
  File, xorb, and dedup index keys are global protocol identities; a static
  all-operations token is suitable only for a single-scope deployment.
- Xorb publication stores canonical immutable bytes before publishing layout
  metadata. Shard publication stores the canonical shard before dedup and SHA
  secondary indexes and publishes reconstructable file records last.
- Every index write is idempotent. File and dedup indexes are non-unique
  secondary indexes and may retain any already-valid durable source. A SHA key
  is immutable within its namespace.
- The service's publication order makes retry after a lost response safe, but
  the interfaces do not create a transaction across object and index stores.
  Durable adapters must not report success before their writes are durable.

## Durable backend gap list

The current server provides only the concurrency-safe memory reference store.
Filesystem/SQLite and S3/PostgreSQL adapters still need to prove these
invariants before production durability is claimed:

1. conditional immutable object writes with identity/length verification and
   crash-safe replacement on local filesystems;
2. one SQL transaction for dedup, scoped SHA, and file-index publication, with
   readers unable to observe a dangling or incomplete reconstruction root;
3. staged-object protection and restart cleanup for a crash between object
   publication and SQL commit;
4. deterministic first-valid selection when duplicate file or dedup rows exist,
   plus constraints for truly immutable xorb and SHA records;
5. repository-aware authorization or partitioning for global identities,
   including an explicit policy for transitive Xorb dependencies;
6. paginated iteration over objects and indexes for audit, repair, migration,
   and garbage collection without whole-bucket materialization; and
7. cancellation-aware filesystem, SQL, S3, and signed-range operations, tested
   with failures injected after every publication step and a real process
   restart.
