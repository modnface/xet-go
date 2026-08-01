# Go versus official Rust performance

This report compares the Go module with the official `huggingface/xet-core`
implementation pinned at `7a267506b77b484688654c46079e3aec35394611`. Every
sample is rejected unless Go and Rust produce the same identity, chunk count,
and compression scheme; uncompressed xorbs must also have the same serialized
length.

## Result

The optimized Go implementation reaches 74.5–83.7% of official Rust throughput
on the 63.5 MB reference CSV, up from the recorded 45.1–60.5% baseline. On the
current Go 1.26.5 toolchain, the original byte-at-a-time chunker had regressed
further; relative to that checked-out implementation, the retained changes are
1.11–3.78x faster.

Host and sampling details:

- Date: 2026-08-01 UTC.
- Host: Apple M4 Pro (`darwin/arm64`), 14 logical CPUs, 48 GiB memory.
- Go: 1.26.5; Rust: 1.95.0.
- Input: official `Electric_Vehicle_Population_Data_20250917.csv`, 63,527,244
  bytes, SHA-256
  `f41255b252f776125f2b657136654e4d4d5d2ccf8ef4db0ec186bd1981b69734`.
- Final sampling: median of seven alternating samples, three iterations per
  sample. Go and Rust execution order alternates between samples. Input reads,
  stage preparation, and JSON/string presentation are outside the timed loop.

| End-to-end operation | Go before, MiB/s | Go final, MiB/s | Go speedup | Rust final, MiB/s | Final Go/Rust |
|---|---:|---:|---:|---:|---:|
| Chunk + file hash | 227.74 | 842.99 | 3.70x | 1,033.30 | 0.816x |
| Xorb encode, none | 215.09 | 812.16 | 3.78x | 969.96 | 0.837x |
| Xorb encode, LZ4 | 178.42 | 409.52 | 2.30x | 544.13 | 0.753x |
| Xorb decode, none | 1,302.50 | 1,469.51 | 1.13x | 1,971.87 | 0.745x |
| Xorb decode, LZ4 | 986.21 | 1,095.20 | 1.11x | 1,350.61 | 0.811x |

All final operations produced matching protocol identities and 796 chunks. The
none-encoded xorb had the same 63,533,612-byte layout. LZ4 byte streams can
differ because the format permits multiple conforming encodings.

The earlier published baseline used Go 1.24.5 and measured 553.12, 483.29,
324.61, 1,297.17, and 910.48 MiB/s for the operations above. The large Go
1.25/1.26 regression was isolated to the old byte-at-a-time `Writer.Write`
loop: three identical chunk/hash passes took about 371 ms on Go 1.24.5 and 844
ms on Go 1.26.5. Bulk boundary scanning eliminates that code-generation
sensitivity; the optimized builds measured about 246 and 241 ms respectively.

## Stage breakdown

The matched oracle also measures stages independently. Chunk inputs and hashes
for later stages are prepared outside the timed interval.

| Stage, reference CSV | Go MiB/s | Rust MiB/s | Go/Rust | What is timed |
|---|---:|---:|---:|---|
| Owned chunking | 1,864.75 | 1,931.75 | 0.965x | GearHash boundaries and owned chunk copies |
| Leaf hashing | 1,573.21 | 2,282.18 | 0.689x | Keyed BLAKE3 and node output |
| Merkle/file hash | 516,405.09 | 774,791.45 | 0.667x | Aggregate formatting, internal hashes, protection |
| Chunk + file hash | 842.99 | 1,033.30 | 0.816x | Owned chunking, leaf hashes, aggregate |
| Encode prepared chunks, none | 1,451.19 | 1,971.84 | 0.736x | Leaf hashes, metadata, ownership, serialization |
| Encode prepared chunks, LZ4 | 542.05 | 763.53 | 0.710x | Leaf hashes, compression, metadata, serialization |

Merkle aggregation is slower in relative terms but immaterial in absolute
terms: three complete aggregate passes took 0.352 ms in Go versus 0.235 ms in
Rust, less than 0.2% of the end-to-end chunk/hash interval. The significant
remaining large-input costs are leaf BLAKE3 and xorb ownership/serialization.

## Input size and entropy

The deterministic random fixtures use identical bytes in both implementations.
Small cases use more iterations so the timed interval remains measurable.

| Random input | Chunk + hash | Encode none | Encode LZ4 request | Decode none | Decode LZ4 request |
|---|---:|---:|---:|---:|---:|
| 8 KiB | 0.244x | 0.232x | 0.214x | 0.266x | 0.268x |
| 1 MiB | 0.725x | 0.734x | 0.675x | 0.635x | 0.647x |
| 16 MiB | 0.771x | 0.813x | 0.762x | 0.715x | 0.715x |
| 63 MiB | 0.776x | 0.789x | 0.759x | 0.685x | 0.684x |

The 8 KiB result is a fixed-cost case, not a sustainable byte rate: it contains
one Xet chunk and Go's hasher/runtime allocation costs dominate. At 1 MiB and
above, steady-state ratios are much more representative. Random data is not
compressible, so an LZ4 request correctly falls back to uncompressed chunk
storage in both implementations.

Content changes chunk shape and compression cost substantially:

| 16 MiB content | Chunk + hash | Encode none | Encode LZ4 | Decode none | Decode LZ4 |
|---|---:|---:|---:|---:|---:|
| Deterministic random | 0.771x | 0.813x | 0.762x | 0.715x | 0.715x |
| All zero | 0.924x | 0.955x | 0.836x | 0.912x | 0.879x |
| Repeated text | 0.926x | 0.957x | 0.830x | 0.916x | 0.907x |

Repetitive inputs produce maximum-sized chunks, amortize hash setup, and are
cheap to compress. For these workloads, Go is already within roughly 8–20% of
Rust end to end.

## Profile findings

CPU, allocation, live-heap, GC, context-switch, instruction, and flame-graph
profiles were captured from the same optimized binaries.

- Owned chunking is no longer a primary gap. Direct in-memory scanning, bulk
  copies, and skipping bytes that cannot influence a pre-minimum boundary move
  it to 97% of Rust on the CSV and 91–100% on large matrix inputs. The skip
  raises the isolated 8 KiB owned-chunk rate from 1.58 to 10.3 GiB/s.
- The pinned Rust BLAKE3 backend uses AArch64 NEON. The pure-Go BLAKE3 dependency
  uses generic ARM64 compression and creates goroutine eigentrees for large
  writes. In a 20-pass random 63 MiB chunk/hash run, Go used 2.78 s user and
  0.38 s system CPU over 1.59 s wall time and recorded 88,524 involuntary
  context switches. Rust used 1.25 s user and 0.03 s system CPU over 1.29 s
  wall time with 451 involuntary context switches. Samply and pprof attribute
  most Go samples to runtime park/wakeup paths around those hash workers.
- The final chunk/hash allocation profile is about 1.41 allocated bytes per
  input byte: 1.00x is the required independently owned chunk data and about
  0.36x is transient BLAKE3 eigentree storage. Live heap after 50 passes was
  97 MB, dominated by the 63 MB input and the final owned chunks.
- Exact xorb sizing removes geometric `bytes.Buffer` growth. Exact LZ4 decode
  sizing removes `io.ReadAll` growth. Uncompressed chunk views now share the
  containing object's owned body, preserving caller-input ownership while
  eliminating a redundant full-data copy.
- Over 50 random 63 MiB uncompressed decodes, the zero-copy view reduced
  cumulative allocations from about 7.4 GiB to 3.3 GiB and improved wall time
  5–6%. A paired 20-pass process peaked at 498 MB footprint in Go versus 1.53
  GiB in Rust; allocator retention makes process peaks different from live
  result size. Ten uncompressed encodes peaked at 407 MB in Go versus 806 MB in
  Rust on the same input.
- GC is not the limiting factor. The final 20-pass chunk/hash trace reported
  0% GC time with sub-millisecond collections. Disabling GC was 4–5% slower in
  repeated checks. There are no application file syscalls in the timed loop;
  the input read and decode-body preparation occur before timing. macOS
  `dtruss`, `fs_usage`, and `sc_usage` require elevated privileges and were
  unavailable under System Integrity Protection, so system behavior was
  grounded with `/usr/bin/time -l` counters and Samply context-switch markers.

A bounded replacement for the dependency's per-hash goroutine tree was also
tested. It removed about 90% of transient hash allocations and improved the 8
KiB case 11–13%, but regressed CSV leaf hashing about 7.5% and uncompressed
decode about 10%; it was rejected rather than trading away important
dimensions.

## Realistic remaining gap

On this ARM64 host, a realistic current target for large inputs is 75–85% of
Rust end-to-end, with 83–96% common for compressible or repetitive data. Random
inputs expose a 64–81% range depending on whether hashing, ownership copies, or
codec work dominates. Tiny single-chunk objects remain a fixed-cost weakness.

Closing the next material gap requires a mature pure-Go ARM64 NEON BLAKE3
backend that supports Go 1.23, or a carefully batched hashing API that improves
both small and large cases. The investigated SIMD-capable alternative requires
Go 1.24, and the CGO alternative would violate this module's CGO-free contract;
neither was adopted. The remaining Merkle and GC costs are too small to justify
additional complexity.

## Reproduce

```sh
XET_PERF_ITERATIONS=3 XET_PERF_SAMPLES=7 \
  ./conformance/compare-performance.sh
```

This writes the complete machine-readable report and concise table to
`.cache/performance/latest.{json,md}`. CPU and memory profiles can be requested
from the Go benchmark binary with `XET_PERF_CPU_PROFILE`,
`XET_PERF_ALLOCS_PROFILE`, and `XET_PERF_HEAP_PROFILE`.

Deterministic matrix inputs can be generated with:

```sh
go run ./conformance/cmd/perf-fixture \
  -size 16777216 -pattern random -output .cache/performance/random-16m.bin
./conformance/compare-performance.sh \
  .cache/performance/random-16m.bin .cache/performance/random-16m
```

`-pattern` accepts `random`, `zero`, or `repeat`. CI runs a one-sample semantic
smoke check but does not enforce ratios because shared-runner performance is
not stable.
