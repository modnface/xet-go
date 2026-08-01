# Go versus official Rust performance

This report records the 2026-08-01 ARM64 BLAKE3 investigation. It compares
this module with official `huggingface/xet-core` commit
`7a267506b77b484688654c46079e3aec35394611` and explains why the previous Go
implementation was slower and produced far more context switches.

## Outcome

The retained implementation replaces scalar data-leaf hashing on ARM64 with
the NEON path in `goforge.dev/blake3sum` v1.0.0 and batches independent Xet
leaf hashes behind a package-wide outer-worker budget. It remains CGO-free.
Other architectures keep the prior `lukechampine.com/blake3` data-hash path,
without outer batch workers. The module minimum is now Go 1.24.

On the official 63.5 MB CSV, final Go is 1.02–4.20x official Rust for every
hashing-inclusive xorb encode/decode case, and 1.54x for chunking plus the file
hash. Owned chunking remains close at 0.94x. Merkle-only hashing is 0.64x but
takes only about 0.11 ms per pass, so it is not an end-to-end bottleneck.

| Operation | Go before, MiB/s | Go final, MiB/s | Go speedup | Rust final, MiB/s | Final Go/Rust |
|---|---:|---:|---:|---:|---:|
| Owned chunking | 1,856.09 | 1,936.27 | 1.04x | 2,050.24 | 0.944x |
| Leaf hash, prepared chunks | 1,613.18 | 15,008.86 | 9.30x | 2,380.07 | 6.306x |
| Merkle/file hash, prepared nodes | 482,156.91 | 533,586.50 | 1.11x | 835,322.92 | 0.639x |
| Chunk + file hash | 849.70 | 1,676.05 | 1.97x | 1,090.46 | 1.537x |
| Encode prepared chunks, none | 1,485.78 | 8,329.66 | 5.61x | 2,110.58 | 3.947x |
| Encode prepared chunks, LZ4 | 549.81 | 858.51 | 1.56x | 804.82 | 1.067x |
| End-to-end encode, none | 819.05 | 1,548.65 | 1.89x | 1,024.04 | 1.512x |
| End-to-end encode, LZ4 | 408.13 | 590.02 | 1.45x | 576.66 | 1.023x |
| Decode, none | 1,473.19 | 8,810.23 | 5.98x | 2,095.80 | 4.204x |
| Decode, LZ4 | 1,111.08 | 3,739.12 | 3.37x | 1,443.09 | 2.591x |

Every sample produced 796 chunks and matching protocol identities. The
uncompressed xorb also had the same serialized length. LZ4 streams may differ
because multiple compressed representations conform to the format. Complete
sample ranges are in `performance/arm64-blake3/end-to-end.tsv`.

## Controlled method

- Host: Apple M4 Pro, 10 performance and 4 efficiency cores, 48 GiB memory,
  `darwin/arm64`, macOS 26.5.2.
- Toolchains: Go 1.26.5 for measurements; Rust 1.95.0; Cargo 1.95.0; LLVM
  22.1.2. Go 1.24.0 and 1.25.12 were also used as compatibility gates.
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
- Context-switch comparison: seven interleaved samples of the same 20-pass
  chunk/file-hash workload, measured with `/usr/bin/time -l`. This processes
  1,270,544,880 bytes per sample. Profiles recorded their own target JSON so
  overhead could be checked against unprofiled runs; target throughput stayed
  within a few percent.

The end-to-end comparison intentionally runs each implementation as shipped.
The pinned Rust hasher is serial for this path; final Go batches independent
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

A single hash call does not explain the end-to-end win. The retained hasher is
still slower than Rust for common 8–128 KiB messages, but it avoids the old
nested scheduler behavior and becomes faster on a 1 MiB message. Independent
chunk batching supplies the large end-to-end gain.

| Message | Previous Go | Final Go | Rust final | Final Go/Rust |
|---|---:|---:|---:|---:|
| 8 KiB | 566.85 MiB/s | 670.41 MiB/s | 2,429.64 MiB/s | 0.276x |
| 64 KiB | 1,319.86 MiB/s | 1,303.56 MiB/s | 2,453.40 MiB/s | 0.531x |
| 128 KiB | 1,852.06 MiB/s | 1,588.71 MiB/s | 2,451.61 MiB/s | 0.648x |
| 1 MiB | 4,706.36 MiB/s | 7,116.66 MiB/s | 2,454.02 MiB/s | 2.900x |

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
concurrent callers; the dependency may still use its own bounded work for a
large individual message. Threshold measurements found 36–52% gains at 128
KiB total, 22–31% gains for four or more chunks at 64 KiB total, and only a 2%
gain for two 32 KiB chunks.

## Context switches and core scaling

The original report cited roughly 88,500 Go versus 451 Rust involuntary
switches. Fresh controlled samples did not reproduce those exact counts, but
did reproduce the same two-orders-of-magnitude problem: medians were 79,742
Go versus 298 Rust. Final medians are 3,677 Go versus 202 Rust.

| 20-pass chunk/hash | Go MiB/s | Rust MiB/s | Go involuntary | Rust involuntary | Go/Rust switches |
|---|---:|---:|---:|---:|---:|
| Baseline | 866.77 | 1,047.42 | 79,742 | 298 | 267.6x |
| Final | 1,750.32 | 1,113.74 | 3,677 | 202 | 18.2x |

For the same 1.183 GiB of input work, Go fell from about 67,390 to 3,108
involuntary switches/GiB, a 95.4% reduction. Rust final is about 171/GiB. The
remaining difference is the cost of useful cross-core batch execution: final
Go completes the workload about 1.60x faster and uses parallel workers, while
Rust remains serial. Setting `GOMAXPROCS=1` reduces Go to a median 586 switches
but also to about 907 MiB/s.

The measured final Go scaling for the same workload was:

| GOMAXPROCS | Median MiB/s | Median involuntary switches |
|---:|---:|---:|
| 1 | 906.7 | 586 |
| 2 | 1,231.4 | 792 |
| 4 | 1,482.0 | 1,231 |
| 8 | 1,671.0 | 1,752 |
| 10 | 1,712.5 | 2,065 |
| 14 | 1,739.3 | 3,794 |

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
| `goforge.dev/blake3sum` v1.0.0 | Go 1.24, CGO-free ARM64 NEON; about 1,598 MiB/s sequential distribution and 14.5 GiB/s batched | Retained with explicit version pin, compatibility tests, and conformance gates |
| CGO/Rust or C BLAKE3 | Mature SIMD implementations | Rejected: violates the module's CGO-free deployment contract |
| New hand-written assembly/fork | Could target more message sizes | Rejected for complexity and long-term maintenance risk after a conforming dependency met the end-to-end goal |

The retained dependency is newer and has a shorter release history than the
other Go candidates. That risk is why the version is pinned, its own package
tests and `govulncheck` are gates, and every Xet boundary size is compared with
the official Rust oracle. The Go 1.24 requirement was accepted only after the
dependency-free and older-toolchain alternatives were measured.

## Validation

The final code passed:

- `go test ./...`, `go test -race ./...`, `go vet ./...`, and
  `golangci-lint` 2.12.2 with Go 1.25.12;
- the exact 95.0% repository coverage gate (98.9% in `xethash`), all 11 fuzz
  smoke targets, and Linux/Windows/macOS cross-compiles for the configured
  amd64, arm64, and 386 targets;
- `go test ./...` on the minimum Go 1.24.0 and CI Go 1.25.12;
- `go mod verify`, the upstream `goforge` BLAKE3 package tests, and
  `govulncheck` v1.1.4 with no called vulnerabilities;
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

The Go end-to-end binary accepts `XET_PERF_CPU_PROFILE`,
`XET_PERF_ALLOCS_PROFILE`, `XET_PERF_HEAP_PROFILE`,
`XET_PERF_BLOCK_PROFILE`, `XET_PERF_MUTEX_PROFILE`,
`XET_PERF_GOROUTINE_PROFILE`, and `XET_PERF_TRACE`. The tracked compact data
and raw-artifact manifest are in `performance/arm64-blake3/`. CI runs a
one-sample semantic performance smoke test but does not enforce ratios because
shared-runner throughput is unstable.
