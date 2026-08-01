# ARM64 BLAKE3 profiling protocol

The exact repeatable capture commands are implemented in
`conformance/capture-performance-profiles.sh`. Run them from the repository
root with the official fixture already fetched:

```sh
XET_PROFILE_ITERATIONS=30 \
XET_PROFILE_CONTEXT_ITERATIONS=20 \
XET_PROFILE_CONTEXT_SAMPLES=7 \
XET_PROFILE_INSPECTION_ITERATIONS=200 \
  ./conformance/capture-performance-profiles.sh \
  .cache/xet-spec-reference-files/Electric_Vehicle_Population_Data_20250917.csv \
  .cache/performance-profiles
```

The script rebuilds Go with `-trimpath` and the official Rust oracle with
Cargo `--locked --release` at xet-core commit
`7a267506b77b484688654c46079e3aec35394611`. It records the input digest,
toolchains, dependency graph, CPU topology, operation count, and
`GOMAXPROCS`. It then captures:

- separate CPU, runtime, and execution-trace runs so combined profiler
  overhead does not distort the scheduler evidence;
- CPU call trees and top reports, allocation/heap/block/mutex profiles, and
  scheduler/synchronization profiles derived with `go tool trace`;
- compiler escape and inlining diagnostics for both `xethash` and the pinned
  BLAKE3 module;
- Go and Rust compression-loop disassembly;
- seven alternating fresh-process `/usr/bin/time -l` samples;
- symmetric Go/Rust Samply profiles with context-switch markers;
- symmetric Instruments Time Profiler and System Trace recordings, including
  exported time samples, context switches, and syscalls;
- separate `sample`, thread-list, and `vmmap` inspection runs. These inspection
  runs are not used as throughput samples because attachment perturbs them.

Raw captures are intentionally kept below `.cache/` because Instruments trace
bundles and XML exports are hundreds of megabytes and contain machine-specific
process metadata. Compact, reviewable medians are tracked as TSV files in this
directory. Existing baseline and retained-candidate captures are in
`.cache/performance-investigation/profiles-baseline/` and
`.cache/performance-investigation/profiles-optimized/`; the unified-fork
prototype is in `.cache/performance-investigation/fork-unified-profiles/`.
A bounded five-pass validation of every command path, including non-empty
Samply profiles and Instruments exports, is in
`.cache/performance-investigation/fork-unified-recapture/`; its short timings
are command validation only and are not used in reported performance medians.

Graphviz was not installed on the measurement host, so `go tool pprof -svg`
could not produce a static SVG. The script emits the equivalent symbolized
`pprof -tree` report, preserves the raw pprof for the interactive flame-graph
view (`go tool pprof -http=:0 <profile>`), and preserves Samply and Instruments
profiles. The earlier zero-byte attempted SVG is ignored with the other raw
cache files and is not evidence used by the report.

The compiler diagnostics confirm that `smallKeyedHash` is inlineable and its
input does not escape. `NewSerial` is inlineable; hashers intentionally escape
when installed in `sync.Pool`. The batch function itself is not inlineable and
its worker closure, `WaitGroup`, and atomic work index escape, as expected for
goroutine-owned state. The NEON assembly declarations report that their input,
output, and key pointers do not escape. The scalar `CompressNode` and ARM64
`CompressChunk` bodies exceed the inliner budget, but profiles and disassembly
show that the four-chunk hot path enters `compressChunksNEON` directly.

No SIP or security setting was changed. `fs_usage`/`dtruss` were not used:
System Trace supplied syscall and thread-state data without `sudo`, while the
benchmark loads its fixture before the timed region. `sample`, `vmmap`,
Samply, and both Instruments templates worked without privileged attachment.
`spindump` was unnecessary because neither implementation hung.
