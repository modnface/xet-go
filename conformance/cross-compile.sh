#!/usr/bin/env bash
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
readonly OUTPUT_DIR="${ROOT_DIR}/.cache/cross"
readonly TARGET_LIST="${XET_CROSS_TARGETS:-linux/amd64 linux/arm64 linux/386 windows/amd64 windows/arm64 darwin/amd64 darwin/arm64}"

packages=()
while IFS= read -r package; do
  [[ -n "${package}" ]] && packages+=("${package}")
done < <(cd "${ROOT_DIR}" && go list -f '{{if or .TestGoFiles .XTestGoFiles}}{{.ImportPath}}{{end}}' ./...)

read -r -a targets <<< "${TARGET_LIST}"
for target in "${targets[@]}"; do
  IFS=/ read -r goos goarch extra <<< "${target}"
  if [[ -z "${goos}" || -z "${goarch}" || -n "${extra:-}" ]]; then
    printf 'cross compile: invalid target %q (want GOOS/GOARCH)\n' "${target}" >&2
    exit 1
  fi
  target_dir="${OUTPUT_DIR}/${goos}-${goarch}"
  mkdir -p "${target_dir}"
  printf 'cross compile: %s/%s production packages\n' "${goos}" "${goarch}"
  (cd "${ROOT_DIR}" && env CGO_ENABLED=0 GOOS="${goos}" GOARCH="${goarch}" go build ./...)
  for package in "${packages[@]}"; do
    name="$(printf '%s' "${package}" | tr '/.' '__')"
    suffix=.test
    [[ "${goos}" == windows ]] && suffix=.test.exe
    env CGO_ENABLED=0 GOOS="${goos}" GOARCH="${goarch}" \
      go test -c -o "${target_dir}/${name}${suffix}" "${package}"
  done
done
