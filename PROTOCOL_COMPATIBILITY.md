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
| Shard publication | Canonical blob, non-unique dedup indexes, scoped SHA-256, then first-valid reconstructable file records; every write is retryable after partial failure |
| Shard progress | v2 NDJSON emits validation/commit/result or terminal error frames and periodically repeats the latest frame as a heartbeat |
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
