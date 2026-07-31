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
