#!/usr/bin/env bash
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
readonly FIXTURE_DIR="${ROOT_DIR}/.cache/xet-spec-reference-files"
readonly DEFAULT_INPUT="${FIXTURE_DIR}/Electric_Vehicle_Population_Data_20250917.csv"
readonly INPUT_PATH="${1:-${DEFAULT_INPUT}}"
readonly OUTPUT_DIR="${2:-${ROOT_DIR}/.cache/performance}"
readonly ITERATIONS="${XET_PERF_ITERATIONS:-3}"
readonly SAMPLES="${XET_PERF_SAMPLES:-5}"

if [[ ! -f "${INPUT_PATH}" && "${INPUT_PATH}" == "${DEFAULT_INPUT}" ]]; then
  "${ROOT_DIR}/conformance/fetch-reference-fixtures.sh" "${FIXTURE_DIR}"
fi
if [[ ! -f "${INPUT_PATH}" ]]; then
  printf 'benchmark input does not exist: %s\n' "${INPUT_PATH}" >&2
  exit 1
fi

mkdir -p "${ROOT_DIR}/.oracle/bin" "${OUTPUT_DIR}"
readonly RUST_ORACLE="$("${ROOT_DIR}/conformance/build-rust-oracle.sh")"
readonly GO_BENCHMARK="${ROOT_DIR}/.oracle/bin/xet-go-perf"
readonly COMPARATOR="${ROOT_DIR}/.oracle/bin/xet-perf-compare"

(
  cd "${ROOT_DIR}"
  go build -trimpath -o "${GO_BENCHMARK}" ./conformance/cmd/go-perf
  go build -trimpath -o "${COMPARATOR}" ./conformance/cmd/perf-compare
)

"${COMPARATOR}" \
  -go "${GO_BENCHMARK}" \
  -rust "${RUST_ORACLE}" \
  -input "${INPUT_PATH}" \
  -iterations "${ITERATIONS}" \
  -samples "${SAMPLES}" \
  -json "${OUTPUT_DIR}/latest.json" \
  -markdown "${OUTPUT_DIR}/latest.md"
