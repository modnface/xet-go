# Go versus official Rust performance

This report records the 2026-08-01 ARM64 BLAKE3 investigation. It compares
this module with official `huggingface/xet-core` commit
`7a267506b77b484688654c46079e3aec35394611` and explains why the previous Go
implementation was slower and produced far more context switches.

## Outcome

The recommended implementation is now the published
`github.com/jmwoliver/blake3` fork of
`lukechampine.com/blake3` v1.4.1. It retains Luke's portable, AMD64 AVX2, and
AVX-512 implementations, adds the attributed GoForge ARM64 NEON four-chunk
kernel, and provides a serial hasher for callers that already own the outer
parallelism. Xet imports this one module from one untagged `datahash.go`; the
fork selects the architecture backend internally. The result remains CGO-free
and restores the module's previous Go 1.23 minimum.

The Xet module pins public fork commit `4b8a4e2a3803` through Go pseudo-version
`v0.0.0-20260801214204-4b8a4e2a3803`; no local `replace` or architecture-
specific Xet import is required. Native AMD64 hardware is still needed for a
final AVX2/AVX-512 performance comparison.

On the official 63.5 MB CSV, the integrated fork is 1.03–4.47x official Rust
for every hashing-inclusive xorb encode/decode case, and 1.55x for chunking
plus the file hash. Owned chunking remains close at 0.96x. Merkle-only hashing
is 0.69x but takes only about 0.12 ms per pass, so it is not an end-to-end
bottleneck.

| Operation | Go before, MiB/s | Go final, MiB/s | Go speedup | Rust final, MiB/s | Final Go/Rust |
|---|---:|---:|---:|---:|---:|
| Owned chunking | 1,856.09 | 1,896.69 | 1.02x | 1,985.40 | 0.955x |
| Leaf hash, prepared chunks | 1,613.18 | 16,674.77 | 10.34x | 2,320.95 | 7.184x |
| Merkle/file hash, prepared nodes | 482,156.91 | 523,154.89 | 1.09x | 761,268.70 | 0.687x |
| Chunk + file hash | 849.70 | 1,653.86 | 1.95x | 1,065.58 | 1.552x |
| Encode prepared chunks, none | 1,485.78 | 8,699.57 | 5.86x | 2,062.79 | 4.217x |
| Encode prepared chunks, LZ4 | 549.81 | 848.95 | 1.54x | 776.74 | 1.093x |
| End-to-end encode, none | 819.05 | 1,547.06 | 1.89x | 1,003.15 | 1.542x |
| End-to-end encode, LZ4 | 408.13 | 579.44 | 1.42x | 563.80 | 1.028x |
| Decode, none | 1,473.19 | 9,213.27 | 6.25x | 2,062.24 | 4.468x |
| Decode, LZ4 | 1,111.08 | 3,782.87 | 3.40x | 1,399.98 | 2.702x |

Every sample produced 796 chunks and matching protocol identities. The
uncompressed xorb also had the same serialized length. LZ4 streams may differ
because multiple compressed representations conform to the format. Complete
sample ranges are in `performance/arm64-blake3/end-to-end.tsv`.

## Controlled method

- Host: Apple M4 Pro, 10 performance and 4 efficiency cores, 48 GiB memory,
  `darwin/arm64`, macOS 26.5.2.
- Toolchains: Go 1.26.5 for measurements; Rust 1.95.0; Cargo 1.95.0; LLVM
  22.1.2. Go 1.23.0, 1.24.0, and 1.25.12 were also used as compatibility
  gates.
- Input: official `Electric_Vehicle_Population_Data_20250917.csv`, 63,527,244
  bytes, SHA-256
  `f41255b252f776125f2b657136654e4d4d5d2ccf8ef4db0ec186bd1981b69734`.
- Full comparison: median of seven alternating Go/Rust samples, three passes
  per sample. Preparation is outside the timed region for prepared-stage
  operations. The comparator rejects identity, chunk-count, scheme, and
  required serialized-size mismatches.
- BLAKE3 microbenchmarks: identical deterministic bytes, Xet data key, message
  size, processed-byte count, caller count, warmup, and seven-sample
  alternating order. These distinguish fixed-message, streaming, segmented,
  owned-input, and symmetric caller-parallel cases.
- Context-switch comparison: seven interleaved baseline/retained samples and
  nine final-fork samples of the same 20-pass chunk/file-hash workload,
  measured with `/usr/bin/time -l`. This processes 1,270,544,880 bytes per
  sample. Profiles recorded their own target JSON so overhead could be checked
  against unprofiled runs; target throughput stayed within a few percent.

The end-to-end comparison intentionally runs each implementation through its
normal path. The pinned Rust hasher is serial here; final Go batches independent
Xet chunks. The symmetric microbench and the `GOMAXPROCS` matrix make the
resource difference explicit instead of presenting it as a primitive
single-core advantage.

## Root cause

The previous ARM64 dependency selected `guts/compress_noasm.go`. Go
disassembly contained scalar `ADD`, `EOR`, and rotate operations and no vector
compression. For writes above 1,024 bytes it also built goroutine eigentrees;
`CompressEigentree` added another goroutine layer for groups above 16 KiB.
Most Xet chunks therefore paid scheduler and transient-tree costs even though
they were only tens of KiB.

The official Rust `blake3` 1.8.3 build selected `blake3_hash_many_neon` on
AArch64. Its disassembly contains vector load, transpose, add, and XOR
instructions. The normal Rust hasher used `SerialJoin`, so it stayed on one OS
thread for this workload.

The evidence agrees across tools:

- Baseline Go CPU pprof attributed about 52% to `pthread_cond_wait` and 21% to
  signaling; only about 13% was the chunker. Block pprof attributed 94% to
  `sync.WaitGroup.Wait`.
- Baseline allocation pprof attributed 22.9% of allocated space to BLAKE3
  eigentrees. A one-pass chunk/hash run allocated 86,136,816 bytes in 23,262
  allocations; the input itself was 63,527,244 bytes.
- Process inspection observed 13 Go OS threads versus one Rust thread. Samply,
  Go execution traces, pprof, and Instruments all showed the same park/wakeup
  pattern.
- A baseline Instruments System Trace exported 314,942 scheduler-state rows.
  The optimized trace exported 20,020, a 93.6% reduction.
- Optimized CPU pprof moved useful work into ARM64 symbols including
  `compressChunksNEON`; scheduler wait/signal samples fell from about 73% to
  about 9.4%. Go disassembly contains NEON `VDUP`, `VLD1`, `VTRN`, vector add,
  and vector XOR instructions.

## Primitive-size result

A single hash call does not explain the end-to-end win. The unified fork is
still slower than Rust for common 8–128 KiB messages, but it avoids the old
unbounded scheduler behavior and becomes faster on a 1 MiB message.
Independent chunk batching supplies the large end-to-end gain.

| Message | Previous Go | Final Go | Rust final | Final Go/Rust |
|---|---:|---:|---:|---:|
| 8 KiB | 566.85 MiB/s | 989.31 MiB/s | 2,425.13 MiB/s | 0.408x |
| 64 KiB | 1,319.86 MiB/s | 1,485.09 MiB/s | 2,453.19 MiB/s | 0.605x |
| 128 KiB | 1,852.06 MiB/s | 1,723.81 MiB/s | 2,442.47 MiB/s | 0.706x |
| 1 MiB | 4,706.36 MiB/s | 7,458.81 MiB/s | 2,452.46 MiB/s | 3.041x |

The official CSV chunk distribution is 8,407 bytes minimum, 18,670 p10,
37,216 p25, 78,993 median, and 131,072 p75/p90/maximum. Chunks below 32 KiB
are 22.7% by count but only 5.7% by bytes. Segmenting the existing dependency
into 1,024-byte writes avoids its eigentree: it improves an 8 KiB hash from
about 567 to 906 MiB/s, but falls to about 900 MiB/s for 64 KiB and larger.
The crossover is roughly 24–32 KiB, so segmentation alone cannot optimize the
whole distribution.

Batching is enabled when there are at least four chunks totaling 64 KiB, or at
least two totaling 128 KiB. Below those thresholds `Chunks` calls the ordinary
single-chunk path. A package-wide budget bounds additional outer workers across
concurrent callers. Batch workers use the fork's `NewSerial` API, so the Xet
outer layer cannot nest with internal tree workers; ordinary standalone
hashers retain bounded internal parallelism for large messages. Threshold
measurements found 36–52% gains at 128 KiB total, 22–31% gains for four or more
chunks at 64 KiB total, and only a 2% gain for two 32 KiB chunks.

## Context switches and core scaling

The original report cited roughly 88,500 Go versus 451 Rust involuntary
switches. Fresh controlled samples did not reproduce those exact counts, but
did reproduce the same two-orders-of-magnitude problem: medians were 79,742
Go versus 298 Rust. Unified-fork medians are 3,223 Go versus 214 Rust.

| 20-pass chunk/hash | Go MiB/s | Rust MiB/s | Go involuntary | Rust involuntary | Go/Rust switches |
|---|---:|---:|---:|---:|---:|
| Baseline | 866.77 | 1,047.42 | 79,742 | 298 | 267.6x |
| Unified fork | 1,750.13 | 1,102.91 | 3,223 | 214 | 15.1x |

For the same 1.183 GiB of input work, Go fell from about 67,390 to 2,724
involuntary switches/GiB, a 96.0% reduction. Rust final is about 181/GiB. The
remaining difference is largely the cost of useful cross-core batch execution:
final Go completes the workload about 1.59x faster and uses parallel workers,
while Rust remains serial. Setting `GOMAXPROCS=1` reduces the fork to a median
323 switches and about 960 MiB/s.

The final split/fork comparison for the same workload was:

| GOMAXPROCS | Split MiB/s | Fork MiB/s | Split involuntary | Fork involuntary |
|---:|---:|---:|---:|---:|
| 1 | 906.9 | 960.0 | 338 | 323 |
| 2 | 1,241.6 | 1,292.9 | 514 | 508 |
| 4 | 1,480.4 | 1,523.2 | 1,165 | 1,069 |
| 10 | 1,718.4 | 1,737.0 | 2,393 | 2,301 |
| 14 | 1,745.9 | 1,760.0 | 3,433 | 3,262 |

A proposed ten-worker library cap was tested separately. With the runtime
still exposing 14 Ps it raised switches to roughly 8,000–9,400 because idle Ps
stole runnable work, without a useful throughput gain. It was rejected. Caller
stress with 1, 2, and 10 concurrent operations also showed no nested-parallel
collapse: at 10 callers the retained encode/decode prototypes reached about
10.3/11.0 GiB/s versus 6.2/6.3 GiB/s for the dependency-only batch.

## Alternatives considered

| Candidate | Evidence | Decision |
|---|---|---|
| Keep `lukechampine` direct | No dependency or toolchain change; baseline scalar ARM64 path and nested eigentrees | Rejected: source of the measured gap |
| Segment existing writes + outer batch | About 8.9 GiB/s prepared leaf hashing, 1,504 MiB/s chunk/hash, allocation-light | Viable fallback, rejected because retained candidate was consistently faster end to end |
| `github.com/zeebo/blake3` v0.2.4 | Mature Go 1.18 dependency; no ARM64 SIMD; about 954 MiB/s sequential and 9.5 GiB/s over the official chunk batch | Rejected: weaker ARM64 result |
| `goforge.dev/blake3sum` v1.0.0 | Go 1.24, CGO-free ARM64 NEON; about 1,598 MiB/s sequential distribution and 14.5 GiB/s batched | Useful split prototype; superseded by the unified fork |
| CGO/Rust or C BLAKE3 | Mature SIMD implementations | Rejected: violates the module's CGO-free deployment contract |
| Luke-based unified fork | Existing AVX2/AVX-512 and zero-allocation small path plus attributed GoForge ARM64 NEON | Published and integrated; native AMD64 performance validation pending |

The GoForge dependency was newer and had a shorter release history than the
other Go candidates. That risk motivated the universal-fork follow-up rather
than becoming a reason to skip it. The fork preserves the mature Luke API and
AMD64 code, attributes and tests the imported NEON kernel, and restores Go
1.23 compatibility.

### Why universal GoForge was rejected

A follow-up prototype replaced every `lukechampine.com/blake3` use with
`goforge.dev/blake3sum` and enabled goforge's architecture dispatch on every
platform. The code compiled, focused protocol tests passed, and the matched
end-to-end comparator produced identical Xet identities. Hashing-inclusive
xorb Go/Rust ratios remained within normal run-to-run variation.

It was not retained because it failed the "as fast" requirement for small
keyed operations. The goforge public API requires `Hasher.Write` plus
`Hasher.Sum` for a keyed one-shot hash; its lower-level keyed compression
kernel is not exported. The existing implementation can call
`lukechampine/blake3/guts` directly for messages up to 1,024 bytes. On this
ARM64 host, representative median latency changed as follows:

| Operation | Current | Universal goforge | Regression |
|---|---:|---:|---:|
| Keyed 32-byte chunk | 97.2 ns | 157.4 ns | 1.62x |
| Keyed 792-byte internal node | 840 ns | 1,559 ns | 1.86x |
| File protection hash | 99.9 ns | 228.5 ns | 2.29x |
| Verification over 1,024 hashes | 39.0 us | 68.4 us | 1.75x |
| Merkle root over 1,024 chunks | 144.6 us | 228.4 us | 1.58x |
| Compact-subtree merge over one million chunks | 24.1 ms | 38.2 ms | 1.59x |

Pooling the goforge hasher and output buffer eliminated nearly all new
allocations but did not remove the latency gap. Parallelizing independent
Merkle groups made an ordinary 796-leaf file hash faster, but could not help
the sequential compact-subtree path and added substantial allocation and
scheduler complexity. The experiment was therefore rejected. Goforge remains
the ARM64 data-leaf backend in the retained split commit, while lukechampine
handles zero-allocation small keyed, internal, protection, and verification
hashes there. The unified fork supersedes that two-module arrangement.
Detailed samples are in
`performance/arm64-blake3/universal-goforge.tsv`.

### Unified Luke-based fork

A published fork starting from `lukechampine.com/blake3` v1.4.1 combines its
existing portable, AVX2, and AVX-512 paths with the attributed GoForge ARM64
NEON four-chunk kernel. The fork keeps the original MIT license, includes the
GoForge MIT license and a third-party notice, and exposes a zero-allocation
keyed one-shot API so Xet no longer imports the internal `guts` package. With
the fork integrated, Xet imports one BLAKE3 module, removes both original
BLAKE3 module requirements, and no longer needs architecture-tagged data-hash
files. MIT-to-MIT reuse permits this fork as long as both copyright/license
notices remain with distributed copies; `LICENSE`, `LICENSE-GOFORGE`, and
`THIRD_PARTY_NOTICES.md` do that and record the exact source commits.

The ARM64 dispatcher deliberately retains the portable scalar kernel for a
single compression node. Although the imported single-node NEON kernel is
bit-exact, it was slower for the small keyed operations that dominate Merkle,
protection, and verification work on this Apple M4 Pro. NEON is selected for
four independent full chunks, where it produces the measured gain. The AMD64
AVX2/AVX-512 sources are byte-for-byte unchanged from upstream Luke; 386 and
unsupported SIMD cases retain the portable implementation. NEON machine code
cannot run on x86; the single import works there because the fork selects
Luke's AVX2/AVX-512 backend on capable `amd64` CPUs instead. `GOARCH=386`
remains portable scalar.

The fork also changes scheduling without changing hash semantics. Upstream
Luke creates one goroutine per root eigentree for any write above 1 KiB, then
another goroutine per 16-chunk group inside eigentrees above 16 KiB. The fork
starts root parallel work only at 256 KiB, and both root and compression pools
are bounded by `GOMAXPROCS`. Its new `NewSerial` constructor retains the normal
streaming API while disabling internal goroutines. Xet uses `NewSerial` only
inside its already-bounded outer chunk batch, eliminating nested parallelism
without slowing large standalone hashes.

Nine alternating fresh-process comparisons against the retained split
implementation found the final fork 0.3% to 13.8% faster on every pipeline
median. On chunk/file hashing, opting the batch into serial hashers reduced
allocation count 39.6%, allocated bytes 0.2%, involuntary switches 9.9%, and
peak RSS 0.8% versus the otherwise-identical nested fork, while improving
throughput 0.6%. Against the split implementation, the fork stayed faster and
lower-switching at `GOMAXPROCS` 1, 2, 4, 10, and 14.

The complete 256 MiB-per-worker BLAKE3 matrix shows where the gains originate:

| Scenario | Size | Previous Go | Fork | Fork/previous | Rust |
|---|---:|---:|---:|---:|---:|
| One shot | 64 B | 628.51 MiB/s | 682.82 MiB/s | 1.086x | 1,302.62 MiB/s |
| One shot | 8 KiB | 566.85 MiB/s | 989.31 MiB/s | 1.745x | 2,425.13 MiB/s |
| One shot | 128 KiB | 1,852.06 MiB/s | 1,723.81 MiB/s | 0.931x | 2,442.47 MiB/s |
| One shot | 1 MiB | 4,706.36 MiB/s | 7,458.81 MiB/s | 1.585x | 2,452.46 MiB/s |
| One shot | 16 MiB | 8,257.20 MiB/s | 16,708.50 MiB/s | 2.024x | 2,436.77 MiB/s |
| Caller parallel | 64 KiB, 2 callers | 1,697.55 MiB/s | 2,570.37 MiB/s | 1.514x | 4,469.85 MiB/s |

The maximum fork median absolute deviation in the 41-row matrix was 3.85%; all
but one row were lower, and all samples enforced equal digest and byte-count
semantics. AMD64-specific differential tests compare AVX2 and AVX-512 buffer,
block, and parent kernels against the portable implementation. Cross-builds
and a Rosetta execution pass succeeded, but Rosetta exposed neither AVX feature
and therefore skipped those runtime SIMD tests. Native AMD64 correctness and
performance remain a release gate rather than an inferred result.

An attempted follow-up removed the fork's 16 KiB eigentree padding allocation.
It substantially reduced allocated bytes, but representative pipeline medians
regressed by 1.3% to 8.9%, so that change was reverted. A global policy that
made every write below 256 KiB serial improved 64 KiB by 19.1% but regressed
1 MiB by 7.9%; it was also rejected in favor of explicit caller-managed
serial operation. The complete comparisons and rejected samples are in
`performance/arm64-blake3/fork-unified.tsv`.

### Remaining gap

There is no remaining throughput deficit in the complete chunk/hash or xorb
pipelines on this ARM64 host. The fork's current seven-sample official results
are 1.03–4.47x Rust for all hashing-inclusive encode/decode operations and
1.55x Rust for chunk/file hashing. The isolated exceptions are owned chunking
at 0.96x Rust and the tiny Merkle-only stage at 0.69x. Primitive 64–128 KiB
single hashes also remain 0.61–0.71x Rust, but bounded batching more than
recovers that gap in the real pipeline.

Memory and scheduling still differ materially. In the final nine-sample
20-pass run, Go used 270,729,216 bytes peak RSS versus Rust's 154,435,584
(75.3% more), allocated 1,704,848,064 versus 1,277,056,240 bytes (33.5% more),
and made 144,273 versus 16,160 allocations (8.9x). Go completed 1.59x faster,
used 17 short GC cycles with a 1.59 ms median total pause, and made 2,724 versus
181 involuntary switches/GiB. These remaining costs are primarily Go object,
runtime, and useful cross-core-worker overhead, not evidence of a remaining
scalar data-leaf path: disassembly and profiles confirm NEON execution.

## Validation

The final integrated code passed:

- `go test ./...`, `go test -race ./...`, `go vet ./...`, and
  `golangci-lint` 2.12.2 with Go 1.25.12;
- the exact 95.0% repository coverage gate (98.9% in `xethash`), all 11 fuzz
  smoke targets, and Linux/Windows/macOS cross-compiles for the configured
  amd64, arm64, and 386 targets;
- `go test ./...` and `go vet ./...` on the restored minimum Go 1.23.0, plus
  tests on Go 1.24.0 and CI Go 1.25.12;
- `go mod verify`, the unified fork's upstream and architecture-differential
  tests, and `govulncheck` v1.1.4 with no called vulnerabilities;
- official Rust differential Merkle, xorb, complete-file, shard, corpus,
  boundary-size, reference-fixture, and local-CAS round-trip suites.

## Reproduce

Build and run the pinned end-to-end oracle:

```sh
XET_PERF_ITERATIONS=3 XET_PERF_SAMPLES=7 \
  ./conformance/compare-performance.sh
```

This writes `.cache/performance/latest.{json,md}`. Build the controlled BLAKE3
oracle and harness with:

```sh
RUST_BLAKE3="$(./conformance/build-rust-blake3-oracle.sh)"
go build -trimpath -o .oracle/bin/xet-go-blake3-perf \
  ./conformance/cmd/blake3-perf
go build -trimpath -o .oracle/bin/xet-go-blake3-compare \
  ./conformance/cmd/blake3-compare
.oracle/bin/xet-go-blake3-compare \
  -go .oracle/bin/xet-go-blake3-perf -rust "$RUST_BLAKE3" \
  -scenario one_shot -size 131072 -iterations 2048 \
  -workers 1 -samples 7
```

Run the complete fixed-message, state-reuse, segmented, owned-buffer, and
caller-parallel matrix with:

```sh
XET_BLAKE3_MATRIX_BYTES=268435456 XET_BLAKE3_MATRIX_SAMPLES=7 \
  ./conformance/compare-blake3-matrix.sh
```

The Go end-to-end binary accepts `XET_PERF_CPU_PROFILE`,
`XET_PERF_ALLOCS_PROFILE`, `XET_PERF_HEAP_PROFILE`,
`XET_PERF_BLOCK_PROFILE`, `XET_PERF_MUTEX_PROFILE`,
`XET_PERF_GOROUTINE_PROFILE`, and `XET_PERF_TRACE`. The tracked compact data
and raw-artifact manifest are in `performance/arm64-blake3/`. CI runs a
one-sample semantic performance smoke test but does not enforce ratios because
shared-runner throughput is unstable.

The exact pprof, execution-trace, `/usr/bin/time -l`, Samply, Instruments,
native process-inspection, and disassembly commands are in
`performance/arm64-blake3/PROFILING.md`. A sanitized machine and toolchain
snapshot is in `performance/arm64-blake3/environment.txt`.
