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
The differential gate compares positive encoding and decoding in both
directions and pins the Go/Rust acceptance matrix for deterministic malformed,
truncated, and corrupt network Xorbs and upload/full MDB shards. The Go decoder
intentionally rejects several malformed forms accepted by xet-core's permissive
streaming parsers; canonical valid forms must remain accepted by both. Oracle
acceptance modes return structured JSON rather than panicking on rejected
input, so both shared and intentionally stricter boundaries remain ordinary
conformance assertions.

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
xorb's `XETB` terminator is accepted only on decode. A zero serialized-byte
field is also accepted and preserved in upload shards because official upload
sessions emit it; CAS registration derives durable accounting from the
separately validated xorb object.

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

The reverse direction uses the same pinned oracle binary as an official Rust
RemoteClient against an in-process Go CAS, including a second fresh-client
upload that must consume Go's protected global-dedup shard:

```sh
oracle="$(./conformance/build-rust-oracle.sh)"
XET_RUST_ORACLE="${oracle}" \
  go test ./conformance -run TestOfficialRustClientGoCASRoundTrip -v
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
./conformance/check-coverage.sh   # 95% core-only floor without PostgreSQL
./conformance/fuzz-smoke.sh       # all 12 fuzz targets; XET_FUZZ_TIME overrides 2s
./conformance/cross-compile.sh    # seven supported GOOS/GOARCH targets
```

The required Linux CI gate provisions PostgreSQL 15 and pinned MinIO, then runs
the individual and composed real-backend tests under race detection and the 95%
complete aggregate. To reproduce that complete coverage gate locally, set the
`XET_POSTGRES_*` and `XET_S3_*` integration variables documented in the root
README; the PostgreSQL principal must be able to create and drop private test
schemas. The coverage script fails rather than silently excluding PostgreSQL
when `CI=true`.

The composed profile also verifies the administrative Xorb-index repair
boundary after recreating both S3 and PostgreSQL adapters. It starts from a
canonical complete Xorb with no retained global layout and proves bounded
reconciliation survives restart. This is not shard-index repair: physical
shards do not carry the namespace needed to recreate scoped shard, file, dedup,
or SHA associations, and the operation neither changes payloads nor supplies
reachability or garbage-collection evidence.

The first Hub-control-plane evidence is a sanitized public-read transcript from
`huggingface_hub==1.27.0` with `hf_xet==1.6.0`. It pins model metadata, immutable
revision metadata, recursive tree listing, ordinary and Xet `HEAD`, Xet read
token refresh, redirects, and an ordinary ranged `GET` against one immutable
public model revision. Reproduce it in an isolated environment with:

```sh
python3 -m venv .cache/hf-client
.cache/hf-client/bin/pip install -r conformance/hf-client/requirements.txt
.cache/hf-client/bin/python conformance/hf-client/capture-public-read.py \
  --output conformance/hf-client/public-read-transcript.json
go test ./conformance -run TestPinnedOfficialHubPublicReadTranscript
```

The capture retains only protocol-relevant headers, redacts bearer values and
signed URL queries, and records the client/runtime versions. It is read-side
evidence only: hosted write-policy responses, compatible commit-OID generation,
and write-error bodies still require an authenticated sanitized capture.

The `hfcompat` black-box checks run the same pinned official client against an
in-process authenticated Go model endpoint. Read coverage requires official
`hf_xet` reconstruction without ordinary resolve-GET fallback. Write coverage
performs create/re-create, preupload, transfer, commit, and byte-identical
download through `HfApi.upload_file`, `HfApi.upload_folder`, the supported
`ModelHubMixin.push_to_hub` profile, and `hf upload`: native Xet with no
disabling environment variable, including download then upload in one process,
and the basic LFS fallback with `HF_HUB_DISABLE_XET=1`. The checker asserts
installed client versions before sending traffic:

```sh
XET_HF_CLIENT_PYTHON="$(pwd)/.cache/hf-client/bin/python" \
  go test -race -run '^TestOfficialPythonClient' -count=1 -v ./hfcompat
```

These tests are opt-in outside CI and skip when `XET_HF_CLIENT_PYTHON` is not
set; the transcript fixture remains the always-on sanitized wire-evidence gate.

See [../CONFORMANCE.md](../CONFORMANCE.md) for the requirement-to-test matrix
and exactness boundary.
