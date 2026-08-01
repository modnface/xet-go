# ARM64 BLAKE3 investigation completion audit

This audit maps the investigation requirements to reproducible evidence. Raw
machine-specific artifacts remain under `.cache/performance-investigation/`;
compact results and commands are tracked in this directory and in
`PERFORMANCE.md`.

## Controlled baseline and workload equivalence

- `environment.txt` records the host, CPU topology, memory, OS, Go/Rust/LLVM
  versions, build modes, dependency commits, fixture digest, and pinned Rust
  oracle commit.
- `end-to-end.tsv` covers separately timed owned chunking, prepared leaf
  hashing, prepared Merkle construction, combined chunk/file hashing, prepared
  XORB encoding, end-to-end encoding, and decoding. Every sample checks chunk
  count and protocol identity; required serialized sizes also match.
- `blake3-one-shot.tsv` and `unified-fork-matrix.tsv` cover 64-byte through
  16-MiB messages, Xet-sized chunks, many sequential messages, new and reused
  hashers, contiguous and segmented writes, owned and borrowed buffers, caller
  concurrency, and one/two/all-core settings. Inputs, operation counts, warmup,
  and alternating seven-sample order are shared with the Rust oracle.
- `worker-scaling.tsv`, `context-switches.tsv`, and `context-resources.tsv`
  report medians and raw ranges for throughput, CPU time/utilization, RSS,
  allocations, GC, thread observations, and context switches per second and per
  GiB. Full JSON and `/usr/bin/time -l` samples are retained in the cache.
- Whole-process versus internally timed medians bound startup, fixture I/O,
  result serialization, and exit to about 1% for both implementations. The
  method and rounding limitation are recorded in `PERFORMANCE.md`.

## Low-level causal evidence

- `PROFILING.md` and `conformance/capture-performance-profiles.sh` reproduce
  CPU, allocation, heap, block, mutex, goroutine, execution-trace scheduler,
  execution-trace synchronization, Samply, Instruments Time Profiler, and
  Instruments System Trace captures for Go and Rust.
- The same script captures `sample`, per-thread `ps`, `vmmap`, symbol tables,
  Go/Rust disassembly, and compiler escape/inlining diagnostics. It records
  profiler target timing separately so measurement perturbation is visible.
- Baseline profiles and disassembly establish scalar Go ARM64 compression plus
  nested eigentree goroutines. Rust disassembly establishes
  `blake3_hash_many_neon` plus serial joining. Retained profiles establish Go
  `compressChunksNEON` execution and a 93.6% reduction in System Trace
  scheduler-state rows.
- The fresh reproduction was 79,742 versus 298 median involuntary switches,
  not the originally reported 88,500 versus 451. Controlled serial/bounded
  experiments reduce Go to 3,223, and `GOMAXPROCS=1` reduces it to 323. This
  demonstrates that the large baseline gap was real and primarily caused by
  BLAKE3 fan-out, while the remaining gap includes useful caller-level parallel
  execution.

## Alternatives and retained changes

- `universal-goforge.tsv` records the universal GoForge prototype and why its
  1.58-2.29x small keyed/Merkle latency regressions were rejected.
- `fork-unified.tsv` records the retained split-versus-fork pipeline, nested
  versus explicit-serial batching, all core counts, and rejected no-padding and
  global-serial policies.
- Native AMD64 measurements rejected a generic callback for small trees; an
  ARM64 recapture then rejected static large-tree partitioning on heterogeneous
  Apple cores. The retained direct-small/dynamic-bounded policy is recorded in
  `amd64-fork.tsv` and `unified-fork-matrix.tsv`.
- The retained Xet changes remove architecture-tagged imports, use one public
  BLAKE3 module, batch independent chunks with a package-wide bounded budget,
  and select the fork's explicit serial hasher inside that outer batch.
- The public fork preserves Luke's scalar/AVX2/AVX-512 implementations, adds
  attributed ARM64 NEON, exposes zero-allocation small keyed hashing, and keeps
  both MIT notices. Native AMD64 AVX2 differential tests and performance
  medians are in `amd64-fork.tsv`.

## Correctness and release gates

- Xet passed unit, race, full vet, lint, exact 95.0% coverage, all 11 fuzz-smoke
  targets, vulnerability scanning, module verification, Go 1.23/1.24/current
  compatibility, and configured Linux/macOS/Windows amd64/arm64/386 builds.
- The official Rust differential corpus, boundary, reference-fixture, Merkle,
  XORB, shard, complete-file, and local-CAS round trips all passed against the
  downloaded public module with no local `replace`.
- The fork's public CI passes Linux, macOS, and Windows on Go 1.22 and current
  Go, plus native AVX2 buffer/block/parent differential tests. The inherited
  Avo assembly requires `go vet -asmdecl=false`; its runtime entry points are
  covered by those differential tests.

## Explicit limitations

- The available native AMD64 runner exposed AVX2 but not AVX-512. AVX-512 code
  is unchanged from upstream, compiles on every configured target, and has
  differential tests that skip without the feature; native AVX-512 execution
  is therefore not claimed.
- `amd64` uses AVX2/AVX-512 when available. Go's 32-bit `386` target remains
  portable scalar; ARM NEON instructions cannot execute on either x86 target.
- Graphviz was unavailable, so the equivalent symbolized pprof trees, raw
  interactive pprof inputs, Samply profiles, and Instruments exports are the
  retained flame-graph evidence.
