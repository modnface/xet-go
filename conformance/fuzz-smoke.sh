#!/usr/bin/env bash
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
readonly FUZZ_TIME="${XET_FUZZ_TIME:-2s}"

readonly TARGETS=(
  './:FuzzUploadDownload'
  './auth:FuzzCASTokenVerify'
  './chunker:FuzzReaderSegmentation'
  './xethash:FuzzHashTextRoundTrip'
  './xethash:FuzzSubtreeMerge'
  './xorb:FuzzDecode'
  './xorb:FuzzSchemesRoundTrip'
  './shard:FuzzDecode'
  './xetcas:FuzzParseContentRange'
  './xetcas:FuzzDecodeMultipart'
  './xetcas:FuzzDecodeContentEncoding'
  './internal/cache:FuzzEntryRoundTrip'
)

cd "${ROOT_DIR}"
for target in "${TARGETS[@]}"; do
  package="${target%%:*}"
  fuzz="${target#*:}"
  printf 'fuzz smoke: %s %s\n' "${package}" "${fuzz}"
  go test "${package}" -run '^$' -fuzz "^${fuzz}$" -fuzztime "${FUZZ_TIME}"
done
