# Conformance harness

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
