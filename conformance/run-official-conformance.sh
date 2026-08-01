#!/usr/bin/env bash
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
readonly FIXTURE_DIR="${XET_REFERENCE_FIXTURES:-${ROOT_DIR}/.cache/xet-spec-reference-files}"
readonly PORT="${XET_LOCAL_CAS_PORT:-18080}"
readonly ENDPOINT="http://127.0.0.1:${PORT}"
readonly LOG_PATH="${ROOT_DIR}/.cache/local-cas.log"

"${ROOT_DIR}/conformance/fetch-reference-fixtures.sh" "${FIXTURE_DIR}"
oracle="$("${ROOT_DIR}/conformance/build-rust-oracle.sh")"

(
  cd "${ROOT_DIR}"
  XET_REFERENCE_FIXTURES="${FIXTURE_DIR}" XET_RUST_ORACLE="${oracle}" \
    go test ./conformance -run 'Test(RustDifferential|OfficialReference)' -count=1 -v
)

cargo +1.95.0 build \
  --manifest-path "${ROOT_DIR}/.oracle/xet-core/Cargo.toml" \
  --locked \
  --release \
  --package xet-client \
  --features simulation \
  --bin local_cas_server

mkdir -p "$(dirname "${LOG_PATH}")"
"${ROOT_DIR}/.oracle/xet-core/target/release/local_cas_server" \
  --in-memory --port "${PORT}" >"${LOG_PATH}" 2>&1 &
server_pid=$!
cleanup() {
  kill "${server_pid}" 2>/dev/null || true
  wait "${server_pid}" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

ready=false
for _ in {1..100}; do
  if ! kill -0 "${server_pid}" 2>/dev/null; then
    printf 'official local CAS exited during startup; log follows:\n' >&2
    sed -n '1,200p' "${LOG_PATH}" >&2
    exit 1
  fi
  if curl --silent --output /dev/null "${ENDPOINT}/"; then
    ready=true
    break
  fi
  sleep 0.1
done
if [[ "${ready}" != true ]]; then
  printf 'official local CAS did not listen at %s; log follows:\n' "${ENDPOINT}" >&2
  sed -n '1,200p' "${LOG_PATH}" >&2
  exit 1
fi

(
  cd "${ROOT_DIR}"
  XET_LOCAL_CAS_ENDPOINT="${ENDPOINT}" \
    go test ./conformance -run TestOfficialRustLocalCASRoundTrip -count=1 -v
)
