# Conformance and release evidence

The compatibility target is Xet specification v1.1.0, official
`huggingface/xet-core` 1.6.0 commit
`de71453d952bd8b806edaa997c72313051a49050`, and official reference corpus
commit `c4aa3a3f15b1395fff5ce934784bf6c8f2d62de8`.

“Exact” below means byte-for-byte agreement where the protocol has one
canonical representation. LZ4 permits multiple valid byte streams; compressed
forms therefore require identical chunk boundaries, selected schemes,
identities, lengths, and bidirectional Go/Rust decoding rather than incidental
compressed-byte equality. Adaptive-concurrency internals are likewise allowed
to differ while preserving bounded, cancelable, backoff/recovery semantics.

## Requirement matrix

| Requirement | Evidence | Agreement checked |
|---|---|---|
| GearHash boundaries and chunk hashes | `TestOfficialReferenceCorpus`, `TestRustDifferentialCorpus`, `FuzzReaderSegmentation` | All 796 official chunks plus seeded boundary-size corpus; read segmentation independence |
| Hash text byte order and domain-separated BLAKE3 | `TestHashOfficialEndianVector`, `TestOfficialMerkleVectors`, `TestRustDifferentialCorpus` | Canonical text, chunk/xorb/file/verification identities |
| Compact Merkle subtrees | `TestRustDifferentialMerkleSubtree`, `TestSubtreeMergeAtEverySplit`, `FuzzSubtreeMerge` | Exact JSON shape, boundary flags, merge result, and final identity |
| Footerless network xorbs | `TestRustDifferentialXorb`, `TestSchemesRoundTrip`, `FuzzDecode` | None form byte-exact; none/LZ4/BG4-LZ4/auto cross-decode and scheme selection |
| Complete/cache xorbs | `TestRustDifferentialCompleteXorb`, `TestCompleteV1RoundTrip`, `TestCompleteV0Decode` | Current V1 byte-exact; historical V0 decode |
| Official historical xorb | `TestOfficialReferenceCorpus`, `TestOfficialLegacyTrailerDecode` | Legacy `XETB` terminator accepted on decode only |
| Footerless upload shards | `TestRustDifferentialShard`, `TestUploadRoundTripAndLayout` | Byte-exact sorted file/xorb records, verification and SHA-256 extensions |
| Cache/global-dedup shards | `TestOfficialReferenceCorpus`, `TestFooterValidation`, `TestGlobalDedupProtectedShard` | All four official shard variants, footer bounds, protected lookup hashes |
| Pinned malformed streaming-parser acceptance | `TestRustDifferentialArtifactAcceptance`, codec truncation/corruption tests | `deserialize_chunks`/`MDBMinimalShard::from_reader` two-sided matrix for deterministic malformed, truncated, and corrupt network Xorbs and upload/full MDB shards; canonical inputs pass both and intentional Go strictness is explicit |
| Server xorb ingestion | `TestIngestNetworkCanonicalizesAndDescribesXorb`, `TestRustDifferentialCompleteXorb`, server fault tests | Footerless-only input, URL identity, decoded bounds, canonical complete V1 bytes, representation-independent index repair |
| Server shard registration | `TestValidateRegistrationRecomputesFilesAndDedupKeys`, `TestRustDifferentialShard` | External xorb resolution, term/file identity recomputation, canonical full shard exactness, protected shard interoperability |
| Server reconstruction planners | `TestPlanReconstructionMatchesRustRangeCropping`, `TestPlanFileChunkHashesMatchesRustStableWindow` | Exact Rust range cropping, offsets, range merging, dirty windows, compact subtrees, and gap verification |
| Whole and range reconstruction | `TestUploadDownloadAndRangeEndToEnd`, `TestWholeDownloadUsesBoundedReconstructionWindows`, `FuzzUploadDownload` | Logical order, exact ranges, term verification, bounded windows, final identities |
| Rust CAS black-box interoperability | `TestOfficialRustLocalCASRoundTrip` | Go upload/full download/range download/global dedup through official Rust server |
| Go CAS black-box interoperability | `TestOfficialRustClientGoCASRoundTrip` | Released Rust RemoteClient upload/download through an in-process memory-backed Go server; a second Rust process with a fresh cache consumes protected Go dedup with nonzero metrics |
| CAS HTTP server | `TestHTTPHandlerGoClientEndToEnd`, handler audit/status tests | All v1/v2 routes, exact namespace paths, signed one-range URLs without CAS credentials, bearer enforcement, limits, error mapping, and NDJSON heartbeat/terminal semantics |
| In-process server publication recovery | service memory/fault/audit tests | Immutable xorb/SHA records, first-valid file/dedup secondary indexes, file-last visibility, alternative compressed representation repair, and idempotent replay after injected write failures |
| Administrative integrity audit | `TestAuditInventory*`, `TestAuditBlobPayloads*` | Bounded metadata/forward checks remain distinct from exact canonical payload-byte and key-identity checks; cancellation withholds cursors; filesystem payload verification survives restart |
| Reconstruction API versions | `TestQueryReconstructionV2RangeAndAuthentication`, `TestQueryReconstructionFallsBackAndPinsV1`, `TestBatchReconstructionPostThenLegacyGetFallback` | v2 preferred, explicit unsupported-route v1 fallback, normalized DTOs |
| Shard API versions and NDJSON | `TestUploadShardV2RetriesTerminalError`, `TestUploadShardFallbackAndMissingTerminal`, `TestNDJSONStructuralFaults` | v2 progress/terminal handling, retryable errors, v1 fallback |
| Signed multipart ranges | `TestSignedFetchExactMultipartRangeAndCredentialIsolation`, `TestMultipartStructuralFaults`, `FuzzDecodeMultipart` | Content-Range matching, reordering, truncation, duplicate/missing parts, no CAS credentials |
| Response compression and bounds | `TestCompressedReconstructionResponses`, `TestCompressedBinaryAndNDJSONResponses`, `TestCompressedResponseLimitsAndCorruption`, `FuzzDecodeContentEncoding` | identity/gzip/zstd/stacked decoding, corruption, decoded-size and NDJSON caps |
| Credential lifecycle | `TestAccessRefreshCoalescesConcurrentCallers`, `TestCAS401InvalidatesAndRefreshesOnce`, `TestRepeated401StopsAfterOneRefresh` | early refresh, singleflight, exactly one invalidation retry |
| Retry and adaptive concurrency | `TestTransientStatusRetryAndNonTransientNoRetry`, `TestRetryAfterDateDeltaExhaustionAndCancellation`, `TestAdaptiveLimiterIncreaseDecreaseAndCancellation`, `TestUploadLimiterBacksOffBeforeRetry`, `TestDownloadLimiterBoundsConcurrentSignedFetches` | bounded replay-safe attempts, Retry-After, context waits, additive recovery, multiplicative backoff |
| Error and URL security | `TestRedirectsAreNotFollowedAndErrorsAreRedacted`, `TestNetworkErrorsRedactSignedURL`, `TestValidateSignedURLStillRejectsCredentials` | no redirect credential forwarding; no query/userinfo leakage |
| Session/global dedup and defragmentation | `TestUploadBatchSessionDeduplicatesIdenticalFiles`, `TestGlobalDedupReusesExternalXorb`, `TestGlobalDedupProtectedShard`, `TestFragmentationTrackerMatchesRustThresholds` | source-order recipes, protected global lookup, Rust rolling thresholds, contiguous-term policy |
| Sparse delta upload | `TestUploadDeltaReusesStableOriginalTerms`, `TestUploadDeltaValidatesEdits`, `TestQueryFileChunkHashesHeaderAndValidation` | dirty-window protocol, unchanged terms, exact subtree merge, invalid edit rejection |
| Cache and durable replay | `TestPersistentRangeCacheAvoidsSecondSignedFetch`, `TestRangeRoundTripAndCorruptionEviction`, `TestUploadJournalResumesAfterShardFailure`, `TestDiskUploadJournalLifecycleAndCorruption` | checksum/expiry, atomic publication, corruption eviction, CAS existence recheck |
| Random access, atomic files, groups | `TestDownloadAtAndRangeAt`, `TestDownloadFilePublishesOnlyVerifiedContent`, `TestDownloadGroupPreservesRequestOrder` | independent offsets, verified rename, ordered outcomes and cancellation |
| Fault containment | all `xetcas` client/server structural/fault tests plus xorb/shard truncation tests | untrusted sizes, malformed frames, corrupt durable state, publication faults, bad content ranges, transient network failures |
| Fuzzing | `conformance/fuzz-smoke.sh` | 11 fuzz targets spanning end-to-end transfer, chunking, hashes, subtrees, codecs, multipart, compression, and cache |
| Matched performance | `conformance/compare-performance.sh` | Alternating optimized Go/Rust samples with identity, count, scheme, and none-size preconditions |
| Portability and purity | OS CI matrix and `conformance/cross-compile.sh` | CGO disabled; Linux amd64/arm64/386, Windows amd64/arm64, Darwin amd64/arm64 production and test compilation |
| Release hygiene | race, vet, golangci-lint, `check-coverage.sh`, govulncheck | Race freedom, static analysis, at least 95% aggregate statement coverage, no reachable known vulnerability on patched Go |

## Reproduce the official gates

Rust 1.95.0 is required only for development conformance:

```sh
rustup toolchain install 1.95.0 --profile minimal
./conformance/run-official-conformance.sh
```

The script checksums the official corpus, builds the oracle from the exact
pinned commit, runs every differential/reference test, builds the official
simulation `local_cas_server`, and runs a full black-box round trip. Downloads
and Rust build products stay under ignored `.cache/` and `.oracle/`.

The matched benchmark is separate so release correctness never depends on a
machine-specific speed ratio:

```sh
XET_PERF_ITERATIONS=3 XET_PERF_SAMPLES=5 \
  ./conformance/compare-performance.sh
```

Each implementation receives the same input, operation, iteration count, and
optimized build mode. The comparator alternates process order and refuses to
report timing unless semantic identities match. Throughput ratios are evidence
for regression review, not a wire-compatibility criterion. The recorded
five-sample baseline is in [PERFORMANCE.md](PERFORMANCE.md).
