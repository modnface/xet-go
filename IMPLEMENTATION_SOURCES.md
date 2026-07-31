# Implementation sources

Only official Hugging Face sources and general algorithm/library
specifications may define behavior in this module. Third-party Go Xet
implementations are excluded as code sources, fixtures, dependencies, design
references, and conformance oracles.

## Pinned authority

| Source | Revision | Use |
|---|---|---|
| Hugging Face Xet specification | v1.1.0 | Public protocol contract |
| `huggingface/xet-core` | `7a267506b77b484688654c46079e3aec35394611` | Production semantic oracle and ambiguity resolution |
| `xet-team/xet-spec-reference-files` | `c4aa3a3f15b1395fff5ce934784bf6c8f2d62de8` | Official binary and chunking fixtures |
| `huggingface/huggingface.js` | `075c9fe6131565babd35a45f11537a71bddbbc44` | Secondary official implementation evidence |

## Component provenance

| Go component | Specification | Official Rust source |
|---|---|---|
| `xethash.Hash` text encoding and keyed hashes | `hashing` | `xet_core_structures/src/merklehash/data_hash.rs` |
| Merkle aggregation and file salting | `hashing` | `xet_core_structures/src/merklehash/aggregated_hashes.rs` |
| Content-defined chunking | `chunking` | `xet_data/src/deduplication/chunking.rs`; `xet_core_structures/src/xorb_object/constants.rs` |
| Xorb codec and compression | `xorb` | `xet_core_structures/src/xorb_object/` |
| Shard codec and validation | `shard` | `xet_core_structures/src/metadata_shard/` |
| CAS DTOs and HTTP behavior | `api`, `download-protocol`, `upload-protocol` | `xet_client/src/cas_client/`; `xet_client/src/cas_types/` |
| Upload and reconstruction engine | `upload-protocol`, `download-protocol` | `xet_data/src/processing/`; `xet_data/src/file_reconstruction/` |
| Session behavior | protocol data plane | `xet_pkg/src/xet_session/` |

New protocol behavior must add its authoritative source here before it is
implemented.

