# xet-go

`xet-go` is a native, CGO-free Go implementation of the Xet formats, Xet CAS
data-plane protocol, and transfer engine.

The module is hosting-decoupled. Callers provide a Xet file ID and fixed or
renewable Xet CAS access; repository discovery, Hugging Face authentication,
and repository commits intentionally live outside this module.

The implementation is independently derived from the official Xet protocol
specification and pinned official Hugging Face source and reference artifacts.
See [IMPLEMENTATION_SOURCES.md](IMPLEMENTATION_SOURCES.md) and
[PROTOCOL_COMPATIBILITY.md](PROTOCOL_COMPATIBILITY.md) for the exact baseline.

This repository is under active development and its public API is not yet
stable.

