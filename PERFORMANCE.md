# Performance baseline

This baseline compares optimized Go code with the exact official Rust oracle,
not with a mock or a third-party implementation. It is intentionally reported
separately from correctness: performance varies by machine, while every timed
sample must pass identity and layout preconditions.

## Recorded baseline

- Date: 2026-08-01 UTC.
- Host: Apple M4 Pro (`darwin/arm64`), 14 logical CPUs, 48 GiB memory.
- Go: 1.24.5; Rust: 1.95.0.
- Rust source: `huggingface/xet-core`
  `7a267506b77b484688654c46079e3aec35394611`.
- Input: official `Electric_Vehicle_Population_Data_20250917.csv`, 63,527,244
  bytes, SHA-256
  `f41255b252f776125f2b657136654e4d4d5d2ccf8ef4db0ec186bd1981b69734`.
- Sampling: median of five alternating samples, three iterations per sample.

| Operation | Go MiB/s | Rust MiB/s | Go/Rust | Verified identity |
|---|---:|---:|---:|---|
| Chunk + hash | 553.12 | 1,137.24 | 0.486x | file `118a5332…aaf97` |
| Xorb encode, none | 483.29 | 1,072.66 | 0.451x | xorb `eea25d6e…b7632` |
| Xorb encode, LZ4 | 324.61 | 608.05 | 0.534x | xorb `eea25d6e…b7632` |
| Xorb decode, none | 1,297.17 | 2,158.98 | 0.601x | xorb `eea25d6e…b7632` |
| Xorb decode, LZ4 | 910.48 | 1,503.78 | 0.605x | xorb `eea25d6e…b7632` |

The Go implementation measured 45.1–60.5% of official Rust throughput in this
baseline. All operations produced identical Xet identities and 796 chunks. The
uncompressed xorb was also byte-length identical at 63,533,612 bytes. Go and
Rust emitted different valid LZ4 streams (14,173,791 versus 14,737,813 bytes),
which is expected because the format permits multiple conforming encodings.

## Reproduce

```sh
XET_PERF_ITERATIONS=3 XET_PERF_SAMPLES=5 \
  ./conformance/compare-performance.sh
```

The harness builds both implementations with optimized settings, alternates
their execution order, records each process result, and rejects a comparison
if identities, chunk counts, schemes, or the uncompressed serialized size do
not agree. The complete machine-readable result is written to ignored
`.cache/performance/latest.json`; the concise regenerated table is
`.cache/performance/latest.md`.

CI runs a one-sample semantic performance smoke check. It deliberately does not
enforce the ratio above because shared-runner speed is not stable. Regressions
should be assessed by repeating the full sampling protocol on comparable
hardware.
