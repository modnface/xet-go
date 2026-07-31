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
