#!/usr/bin/env bash
set -euo pipefail

readonly REFERENCE_COMMIT=7a267506b77b484688654c46079e3aec35394611
readonly RUST_TOOLCHAIN=1.95.0
readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
readonly ORACLE_ROOT="${ROOT_DIR}/.oracle"
readonly XET_CORE_DIR="${ORACLE_ROOT}/xet-core"

mkdir -p "${ORACLE_ROOT}/bin"
if [[ ! -d "${XET_CORE_DIR}/.git" ]]; then
  git clone --filter=blob:none https://github.com/huggingface/xet-core.git "${XET_CORE_DIR}"
fi
git -C "${XET_CORE_DIR}" fetch origin "${REFERENCE_COMMIT}"
git -C "${XET_CORE_DIR}" checkout --detach "${REFERENCE_COMMIT}"

mkdir -p "${XET_CORE_DIR}/xet_core_structures/examples"
cp "${ROOT_DIR}/conformance/rust-oracle/blake3_perf.rs" \
  "${XET_CORE_DIR}/xet_core_structures/examples/xet_go_rust_blake3_oracle.rs"
cargo "+${RUST_TOOLCHAIN}" build \
  --manifest-path "${XET_CORE_DIR}/Cargo.toml" \
  --locked \
  --release \
  --package xet-core-structures \
  --example xet_go_rust_blake3_oracle
cp "${XET_CORE_DIR}/target/release/examples/xet_go_rust_blake3_oracle" \
  "${ORACLE_ROOT}/bin/xet-go-rust-blake3-oracle"

printf '%s\n' "${ORACLE_ROOT}/bin/xet-go-rust-blake3-oracle"
