# Conformance harness

Run every official gate, including the reference corpus, Rust differential
oracle, and official Rust local CAS, with one command:

```sh
rustup toolchain install 1.95.0 --profile minimal
./conformance/run-official-conformance.sh
```

The individual components are documented below for focused investigation.

Build the official Rust differential oracle from the exact pinned revision:

```sh
oracle="$(./conformance/build-rust-oracle.sh)"
XET_RUST_ORACLE="$oracle" go test ./conformance -run RustDifferential
```

The Rust checkout and binary live below ignored `.oracle/`. They are development
and CI dependencies only; the released Go module remains pure Go and CGO-free.
The build uses Rust 1.95.0 because the pinned upstream source uses standard
library APIs newer than the module's product toolchain requirements.

Download and checksum the official protocol reference files from their pinned
Hugging Face revision, then run the full-corpus gate:

```sh
./conformance/fetch-reference-fixtures.sh
XET_REFERENCE_FIXTURES="$(pwd)/.cache/xet-spec-reference-files" \
  go test ./conformance -run OfficialReference
```

The downloader verifies every object against
`conformance/reference-manifest.json`; it does not require Git LFS. The command
prints one status line per object, so its destination is the documented
`.cache/xet-spec-reference-files` unless an explicit argument is provided.
The gate checks all 796 chunk boundaries and hashes, aggregate identities,
byte-for-byte reconstruction, xorb metadata, verification hashes, all four
shard variants, and protected global-dedup entries. The historical reference
xorb's `XETB` terminator and zero serialized-byte shard field are accepted only
on decode; current encoders retain the production formats documented above.

For black-box HTTP interoperability, build and run the official local CAS at
the same pinned revision:

```sh
cd .oracle/xet-core
cargo +1.95.0 build --locked --release -p xet-client --features simulation --bin local_cas_server
target/release/local_cas_server --in-memory --port 18080
```

Then, from this repository:

```sh
XET_LOCAL_CAS_ENDPOINT=http://127.0.0.1:18080 go test ./conformance -run TestOfficialRustLocalCASRoundTrip -v
```

For matched performance measurements, run:

```sh
./conformance/compare-performance.sh
```

This builds optimized Go executables and the pinned optimized Rust oracle, then
alternates five timed samples for owned chunking, leaf hashing, Merkle hashing,
combined chunking+hashing, prepared-chunk and end-to-end none/LZ4 xorb encoding,
and none/LZ4 decoding over the official 63.5 MB corpus. It writes a detailed
machine-readable report and a median-throughput table to
`.cache/performance/latest.{json,md}`. `XET_PERF_ITERATIONS` and
`XET_PERF_SAMPLES` control repetition; the first and second positional
arguments select another input and output directory. Every sample must produce
the same identity and chunk count in both implementations, and the none-encoded
xorb must have the same serialized length, before timings are reported.

The Go benchmark supports optional pprof output through
`XET_PERF_CPU_PROFILE`, `XET_PERF_ALLOCS_PROFILE`, and
`XET_PERF_HEAP_PROFILE`. Deterministic size/entropy fixtures can be generated
with `go run ./conformance/cmd/perf-fixture`; its `-pattern` flag accepts
`random`, `zero`, and `repeat`. See [../PERFORMANCE.md](../PERFORMANCE.md) for
the recorded matrix, profile analysis, and realistic remaining gap.

The local release gates are:

```sh
./conformance/check-coverage.sh   # 75% aggregate statement floor
./conformance/fuzz-smoke.sh       # all 11 fuzz targets; XET_FUZZ_TIME overrides 2s
./conformance/cross-compile.sh    # seven supported GOOS/GOARCH targets
```

See [../CONFORMANCE.md](../CONFORMANCE.md) for the requirement-to-test matrix
and exactness boundary.
