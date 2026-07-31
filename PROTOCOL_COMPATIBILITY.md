# Protocol compatibility

## Baseline

- Hugging Face Xet specification: v1.1.0.
- Official Rust implementation: `huggingface/xet-core` commit
  `7a267506b77b484688654c46079e3aec35394611`.
- Official reference files: `xet-team/xet-spec-reference-files` commit
  `c4aa3a3f15b1395fff5ce934784bf6c8f2d62de8`.

## Compatibility decisions

| Topic | Behavior |
|---|---|
| Hash text | Four little-endian 64-bit limbs rendered as lowercase hexadecimal |
| Network xorb footer | Never emitted; accepted only by explicit cache/full-object decoding |
| Upload shard footer | Omitted and header footer size set to zero |
| Upload verification | One verification entry per reconstruction term |
| Xorb namespace | `default` |
| Dedup namespace | `default-merkledb` by default |
| Reconstruction | v2 preferred; v1 fallback only when the newer route is unsupported |
| Batch reconstruction | Documented POST preferred; legacy GET is an explicit fallback |
| Shard upload | v2 NDJSON preferred; v1 fallback only when unsupported |
| Xorb limits | At most 64 MiB raw input and 8,192 chunks, with serialized-size validation |
| Global protection hash | Keyed BLAKE3, despite historical “HMAC” naming |

The core API contains no Hugging Face repository, revision, path, user token,
commit, Git, or LFS concepts. It accepts only Xet CAS access and protocol
identities.

