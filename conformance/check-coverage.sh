#!/usr/bin/env bash
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
readonly MINIMUM="${XET_COVERAGE_MIN:-95.0}"
readonly PROFILE="${1:-${ROOT_DIR}/coverage.out}"

cd "${ROOT_DIR}"
packages=(./...)
if [[ "${XET_POSTGRES_INTEGRATION:-}" != "1" ]]; then
  if [[ "${CI:-}" == "true" ]]; then
    printf 'coverage gate: PostgreSQL integration is required in CI\n' >&2
    exit 1
  fi
  mapfile -t packages < <(go list ./... | grep -Ev '/(catalog/postgres|xetcas/server/postgresstore)$')
  printf 'core-only coverage gate: PostgreSQL adapters excluded; set XET_POSTGRES_INTEGRATION=1 and XET_POSTGRES_DSN for the complete aggregate\n'
fi
go test -covermode=atomic -coverprofile="${PROFILE}" "${packages[@]}"

coverage="$(go tool cover -func="${PROFILE}" | awk '/^total:/ {gsub(/%/, "", $3); print $3}')"
if [[ -z "${coverage}" ]]; then
  printf 'coverage gate: total coverage was not reported\n' >&2
  exit 1
fi
if ! awk -v actual="${coverage}" -v minimum="${MINIMUM}" 'BEGIN { exit !(actual + 0 >= minimum + 0) }'; then
  printf 'coverage gate: %s%% is below required %s%%\n' "${coverage}" "${MINIMUM}" >&2
  exit 1
fi
printf 'coverage gate: %s%% (required %.1f%%)\n' "${coverage}" "${MINIMUM}"
