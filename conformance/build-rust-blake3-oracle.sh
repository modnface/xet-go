#!/usr/bin/env bash
set -euo pipefail

readonly REFERENCE_COMMIT=de71453d952bd8b806edaa997c72313051a49050
readonly RUST_TOOLCHAIN=1.95.0
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
readonly ROOT_DIR
readonly ORACLE_ROOT="${ROOT_DIR}/.oracle"
readonly XET_CORE_DIR="${ORACLE_ROOT}/xet-core"

mkdir -p "${ORACLE_ROOT}/bin"
if [[ ! -d "${XET_CORE_DIR}/.git" ]]; then
  git clone --filter=blob:none https://github.com/huggingface/xet-core.git "${XET_CORE_DIR}"
fi
git -C "${XET_CORE_DIR}" fetch origin "${REFERENCE_COMMIT}"
git -C "${XET_CORE_DIR}" checkout --detach "${REFERENCE_COMMIT}"

mkdir -p "${XET_CORE_DIR}/xet_core_structures/examples"
readonly ORACLE_SOURCE="${ROOT_DIR}/conformance/rust-oracle/blake3_perf.rs"
readonly ORACLE_DESTINATION="${XET_CORE_DIR}/xet_core_structures/examples/xet_go_rust_blake3_oracle.rs"
if ! cmp -s "${ORACLE_SOURCE}" "${ORACLE_DESTINATION}"; then
  cp "${ORACLE_SOURCE}" "${ORACLE_DESTINATION}"
fi
cargo "+${RUST_TOOLCHAIN}" build \
  --manifest-path "${XET_CORE_DIR}/Cargo.toml" \
  --locked \
  --release \
  --package xet-core-structures \
  --example xet_go_rust_blake3_oracle
cp "${XET_CORE_DIR}/target/release/examples/xet_go_rust_blake3_oracle" \
  "${ORACLE_ROOT}/bin/xet-go-rust-blake3-oracle"

printf '%s\n' "${ORACLE_ROOT}/bin/xet-go-rust-blake3-oracle"
