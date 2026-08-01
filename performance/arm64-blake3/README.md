# ARM64 BLAKE3 investigation artifacts

These compact artifacts back `PERFORMANCE.md`. They were captured on
2026-08-01 from the official 63,527,244-byte CSV using Go 1.26.5, Rust 1.95.0,
and pinned xet-core commit `7a267506b77b484688654c46079e3aec35394611`.

- `end-to-end.tsv`: seven-sample median before/final/Rust comparison for every
  matched operation. Min/max ranges remain in the raw JSON.
- `blake3-one-shot.tsv`: matched 256 MiB-per-sample fixed-message experiment.
- `context-switches.tsv`: every fresh baseline and final 20-pass sample.
- `worker-scaling.tsv`: three-sample final `GOMAXPROCS` sweep.
- `universal-goforge.tsv`: the rejected attempt to use goforge for every
  keyed BLAKE3 operation, including small-hash and subtree regressions.
- `fork-unified.tsv`: the Luke-based unified-fork comparison against the
  retained split implementation, scheduler samples, and the rejected
  no-padding eigentree experiment.

Large machine-specific captures are intentionally not committed. In the
investigation worktree they are under:

- `.cache/performance-investigation/baseline-existing/latest.{json,md}`
- `.cache/performance-investigation/final-full/latest.{json,md}`
- `.cache/performance-investigation/blake3-baseline/`
- `.cache/performance-investigation/final-blake3/`
- `.cache/performance-investigation/context-switch-baseline/`
- `.cache/performance-investigation/final-context-switches/`
- `.cache/performance-investigation/profiles-baseline/`
- `.cache/performance-investigation/profiles-optimized/`
- `.cache/performance-investigation/disassembly/`
- `.cache/performance-investigation/goforge-everywhere/`
- `.cache/performance-investigation/fork-unified-profiles/`

The profile directories contain pprof CPU/allocation/block profiles, Go
execution traces, Samply profiles, Instruments Time Profiler and System Trace
exports, target JSON, process/thread samples, and disassembly excerpts. Target
JSON records the work completed inside each profiling run so profile overhead
can be checked rather than assumed.
