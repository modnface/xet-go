#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
readonly ROOT_DIR
readonly OUTPUT_DIR="${1:-${ROOT_DIR}/.cache/blake3-matrix}"
readonly TOTAL_BYTES="${XET_BLAKE3_MATRIX_BYTES:-268435456}"
readonly SAMPLES="${XET_BLAKE3_MATRIX_SAMPLES:-7}"
readonly GO_BENCHMARK="${ROOT_DIR}/.oracle/bin/xet-go-blake3-perf"
readonly COMPARATOR="${ROOT_DIR}/.oracle/bin/xet-go-blake3-compare"

mkdir -p "${ROOT_DIR}/.oracle/bin" "${OUTPUT_DIR}"
RUST_BENCHMARK="$("${ROOT_DIR}/conformance/build-rust-blake3-oracle.sh")"
readonly RUST_BENCHMARK
(
	cd "${ROOT_DIR}"
	go build -trimpath -o "${GO_BENCHMARK}" ./conformance/cmd/blake3-perf
	go build -trimpath -o "${COMPARATOR}" ./conformance/cmd/blake3-compare
)

run_case() {
	local scenario="$1"
	local size="$2"
	local workers="${3:-1}"
	local iterations=$((TOTAL_BYTES / size))
	if ((iterations < 1)); then
		iterations=1
	fi
	"${COMPARATOR}" \
		-go "${GO_BENCHMARK}" \
		-rust "${RUST_BENCHMARK}" \
		-scenario "${scenario}" \
		-size "${size}" \
		-iterations "${iterations}" \
		-workers "${workers}" \
		-samples "${SAMPLES}" \
		-json "${OUTPUT_DIR}/${scenario}-${size}-w${workers}.json" \
		>"${OUTPUT_DIR}/${scenario}-${size}-w${workers}.stdout.json"
}

for size in 64 1024 8192 65536 131072 1048576 16777216; do
	run_case one_shot "${size}"
	run_case stream_reuse "${size}"
done

for size in 64 1024; do
	run_case stream_new "${size}"
done

for size in 8192 65536 131072 1048576 16777216; do
	run_case stream_segmented "${size}"
done

for size in 65536 1048576; do
	run_case owned "${size}"
done

for size in 8192 65536 131072; do
	for workers in 1 2 10; do
		run_case caller_parallel "${size}" "${workers}"
		run_case caller_parallel_segmented "${size}" "${workers}"
	 done
done

{
	printf 'scenario\tmessage_bytes\tworkers\tgo_mib_s\trust_mib_s\tgo_over_rust\tgo_mad_percent\trust_mad_percent\tgo_allocated_bytes\tgo_allocations\n'
	for report in "${OUTPUT_DIR}"/*.json; do
		case "${report}" in
			*.stdout.json) continue ;;
		esac
		jq -r '[
			.scenario,
			.message_size,
			.workers,
			(.go.median_bytes_per_second / 1048576),
			(.rust.median_bytes_per_second / 1048576),
			.go_to_rust_throughput_ratio,
			.go.median_absolute_deviation_percent,
			.rust.median_absolute_deviation_percent,
			.go.median_allocated_bytes,
			.go.median_allocations
		] | @tsv' "${report}"
	done | sort -k1,1 -k2,2n -k3,3n
} >"${OUTPUT_DIR}/summary.tsv"

printf '%s\n' "${OUTPUT_DIR}/summary.tsv"
