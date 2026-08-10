# Implementation sources

Only official Hugging Face sources and general algorithm/library
specifications may define behavior in this module. Third-party Go Xet
implementations are excluded as code sources, fixtures, dependencies, design
references, and conformance oracles.

## Pinned authority

| Source | Revision | Use |
|---|---|---|
| Hugging Face Xet specification | v1.1.0 | Public protocol contract |
| `huggingface/xet-core` | 1.6.0 (`de71453d952bd8b806edaa997c72313051a49050`) | Production semantic oracle and ambiguity resolution |
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
| Canonical server xorb ingestion | `xorb`, `upload-protocol` | `xet_core_structures/src/xorb_object/`; `xet_data/src/processing/file_upload_session.rs` |
| Full/protected shard encoding and registration | `shard`, `upload-protocol` | `xet_core_structures/src/metadata_shard/shard_format.rs`; `streaming_shard.rs`; `xorb_structs.rs` |
| CAS DTOs and HTTP behavior | `api`, `download-protocol`, `upload-protocol` | `xet_client/src/cas_client/`; `xet_client/src/cas_types/` |
| Reconstruction and sparse-delta server planners | `download-protocol`, `upload-protocol`, `hashing` | `xet_client/src/cas_client/simulation/local_client.rs`; `chunk_window_builder.rs`; `xet_data/src/file_reconstruction/` |
| CAS server routes and progress stream | `openapi/cas.openapi.yaml` | `xet_client/src/cas_client/simulation/local_server/handlers.rs`; `remote_client.rs` |
| Adaptive request concurrency | transfer behavior | `xet_client/src/cas_client/adaptive_concurrency/`; `xet_runtime/src/config/groups/client.rs` |
| Sparse delta windows and compact subtrees | `hashing`, `upload-protocol` | `xet_client/src/cas_client/chunk_window_builder.rs`; `xet_core_structures/src/merklehash/merkle_hash_subtree.rs` |
| Upload and reconstruction engine | `upload-protocol`, `download-protocol` | `xet_data/src/processing/`; `xet_data/src/file_reconstruction/` |
| Session behavior | protocol data plane | `xet_pkg/src/xet_session/` |

New protocol behavior must add its authoritative source here before it is
implemented.
