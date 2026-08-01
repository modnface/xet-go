#!/bin/sh
set -eu

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
destination=${1:-"$repo_root/.cache/xet-spec-reference-files"}

exec go run "$repo_root/conformance/cmd/fetch-reference" \
  -manifest "$repo_root/conformance/reference-manifest.json" \
  -destination "$destination"
