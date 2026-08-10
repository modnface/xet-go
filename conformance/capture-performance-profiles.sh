#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
readonly ROOT_DIR
readonly FIXTURE_DIR="${ROOT_DIR}/.cache/xet-spec-reference-files"
readonly DEFAULT_INPUT="${FIXTURE_DIR}/Electric_Vehicle_Population_Data_20250917.csv"
readonly INPUT_PATH="${1:-${DEFAULT_INPUT}}"
readonly OUTPUT_DIR="${2:-${ROOT_DIR}/.cache/performance-profiles}"
readonly PROFILE_ITERATIONS="${XET_PROFILE_ITERATIONS:-30}"
readonly CONTEXT_ITERATIONS="${XET_PROFILE_CONTEXT_ITERATIONS:-20}"
readonly CONTEXT_SAMPLES="${XET_PROFILE_CONTEXT_SAMPLES:-7}"
readonly INSPECTION_ITERATIONS="${XET_PROFILE_INSPECTION_ITERATIONS:-200}"
readonly NATIVE_TOOLS="${XET_PROFILE_NATIVE_TOOLS:-1}"
readonly GO_BENCHMARK="${ROOT_DIR}/.oracle/bin/xet-go-perf"

if [[ ! -f "${INPUT_PATH}" && "${INPUT_PATH}" == "${DEFAULT_INPUT}" ]]; then
	"${ROOT_DIR}/conformance/fetch-reference-fixtures.sh" "${FIXTURE_DIR}"
fi
if [[ ! -f "${INPUT_PATH}" ]]; then
	printf 'profile input does not exist: %s\n' "${INPUT_PATH}" >&2
	exit 1
fi

mkdir -p "${ROOT_DIR}/.oracle/bin" "${OUTPUT_DIR}"
RUST_BENCHMARK="$("${ROOT_DIR}/conformance/build-rust-oracle.sh")"
readonly RUST_BENCHMARK
(
	cd "${ROOT_DIR}"
	go build -trimpath -o "${GO_BENCHMARK}" ./conformance/cmd/go-perf
)

{
	date -u '+captured_utc=%Y-%m-%dT%H:%M:%SZ'
	printf 'input=%s\n' "${INPUT_PATH}"
	shasum -a 256 "${INPUT_PATH}"
	printf 'profile_iterations=%s\n' "${PROFILE_ITERATIONS}"
	printf 'context_iterations=%s\n' "${CONTEXT_ITERATIONS}"
	printf 'context_samples=%s\n' "${CONTEXT_SAMPLES}"
	printf 'gomaxprocs=%s\n' "${GOMAXPROCS:-runtime default}"
	uname -a
	sw_vers
	sysctl -n machdep.cpu.brand_string 2>/dev/null || true
	for key in hw.model hw.machine hw.ncpu hw.physicalcpu hw.logicalcpu \
		hw.perflevel0.physicalcpu hw.perflevel0.logicalcpu \
		hw.perflevel1.physicalcpu hw.perflevel1.logicalcpu hw.memsize; do
		printf '%s=' "${key}"
		sysctl -n "${key}" 2>/dev/null || printf 'unavailable\n'
	done
	go version
	rustc +1.95.0 --version --verbose
	cargo +1.95.0 --version
	git -C "${ROOT_DIR}" rev-parse HEAD
	git -C "${ROOT_DIR}/.oracle/xet-core" rev-parse HEAD
	(
		cd "${ROOT_DIR}"
		go list -m all
	)
} >"${OUTPUT_DIR}/environment.txt"

# Keep the CPU and execution-trace captures separate; enabling both changes
# scheduling enough to make either profile harder to interpret.
XET_PERF_CPU_PROFILE="${OUTPUT_DIR}/go.cpu.pprof" \
	"${GO_BENCHMARK}" perf "${INPUT_PATH}" chunk_hash "${PROFILE_ITERATIONS}" \
	>"${OUTPUT_DIR}/go-cpu-target.json"

XET_PERF_ALLOCS_PROFILE="${OUTPUT_DIR}/go.allocs.pprof" \
XET_PERF_HEAP_PROFILE="${OUTPUT_DIR}/go.heap.pprof" \
XET_PERF_BLOCK_PROFILE="${OUTPUT_DIR}/go.block.pprof" \
XET_PERF_MUTEX_PROFILE="${OUTPUT_DIR}/go.mutex.pprof" \
XET_PERF_GOROUTINE_PROFILE="${OUTPUT_DIR}/go.goroutine.pprof" \
	"${GO_BENCHMARK}" perf "${INPUT_PATH}" chunk_hash "${PROFILE_ITERATIONS}" \
	>"${OUTPUT_DIR}/go-runtime-target.json"

XET_PERF_TRACE="${OUTPUT_DIR}/go.trace" \
	"${GO_BENCHMARK}" perf "${INPUT_PATH}" chunk_hash "${PROFILE_ITERATIONS}" \
	>"${OUTPUT_DIR}/go-trace-target.json"

go tool pprof -top "${OUTPUT_DIR}/go.cpu.pprof" >"${OUTPUT_DIR}/go-cpu-top.txt"
go tool pprof -tree "${OUTPUT_DIR}/go.cpu.pprof" >"${OUTPUT_DIR}/go-cpu-tree.txt"
go tool pprof -top -sample_index=alloc_space "${OUTPUT_DIR}/go.allocs.pprof" \
	>"${OUTPUT_DIR}/go-allocs-top.txt"
go tool pprof -top -sample_index=inuse_space "${OUTPUT_DIR}/go.heap.pprof" \
	>"${OUTPUT_DIR}/go-heap-top.txt"
go tool pprof -top -sample_index=delay "${OUTPUT_DIR}/go.block.pprof" \
	>"${OUTPUT_DIR}/go-block-top.txt"
go tool pprof -top -sample_index=delay "${OUTPUT_DIR}/go.mutex.pprof" \
	>"${OUTPUT_DIR}/go-mutex-top.txt"
go tool trace -pprof=sched "${OUTPUT_DIR}/go.trace" >"${OUTPUT_DIR}/go-sched.pprof"
go tool trace -pprof=sync "${OUTPUT_DIR}/go.trace" >"${OUTPUT_DIR}/go-sync.pprof"
go tool pprof -top "${GO_BENCHMARK}" "${OUTPUT_DIR}/go-sched.pprof" \
	>"${OUTPUT_DIR}/go-sched-top.txt"
go tool pprof -top "${GO_BENCHMARK}" "${OUTPUT_DIR}/go-sync.pprof" \
	>"${OUTPUT_DIR}/go-sync-top.txt"

go tool nm "${GO_BENCHMARK}" >"${OUTPUT_DIR}/go-symbols.txt"
go tool objdump -s 'blake3/guts[.]CompressNode' "${GO_BENCHMARK}" \
	>"${OUTPUT_DIR}/go-compress-node.txt"
go tool objdump -s 'blake3/guts[.]compressChunksNEON' "${GO_BENCHMARK}" \
	>"${OUTPUT_DIR}/go-compress-chunks-neon.txt"
xcrun llvm-objdump --disassemble-symbols=_blake3_hash_many_neon "${RUST_BENCHMARK}" \
	>"${OUTPUT_DIR}/rust-blake3-hash-many-neon.txt"

# Record the compiler's decisions for the Xet hashing layer and its BLAKE3
# dependency. These captures are separate from the benchmark binary because
# -m=2 is a diagnostic build flag, not a production optimization setting.
(
	cd "${ROOT_DIR}"
	go test -run '^$' \
		-gcflags='github.com/jmwoliver/xet-go/xethash=-m=2' ./xethash
) >"${OUTPUT_DIR}/go-xethash-escape-inline.txt" 2>&1
(
	cd "${ROOT_DIR}"
	go test -run '^$' \
		-gcflags='github.com/jmwoliver/blake3/...=-m=2' \
		github.com/jmwoliver/blake3/...
) >"${OUTPUT_DIR}/go-blake3-escape-inline.txt" 2>&1

run_timed() {
	local implementation="$1"
	local binary="$2"
	local sample="$3"
	/usr/bin/time -l "${binary}" perf "${INPUT_PATH}" chunk_hash "${CONTEXT_ITERATIONS}" \
		>"${OUTPUT_DIR}/context-${sample}-${implementation}.json" \
		2>"${OUTPUT_DIR}/context-${sample}-${implementation}.time"
}

for ((sample = 1; sample <= CONTEXT_SAMPLES; sample++)); do
	if ((sample % 2 == 1)); then
		run_timed go "${GO_BENCHMARK}" "${sample}"
		run_timed rust "${RUST_BENCHMARK}" "${sample}"
	else
		run_timed rust "${RUST_BENCHMARK}" "${sample}"
		run_timed go "${GO_BENCHMARK}" "${sample}"
	fi
done

if [[ "${NATIVE_TOOLS}" != "1" ]]; then
	printf 'Native Samply, Instruments, sample, and vmmap capture disabled.\n' \
		>"${OUTPUT_DIR}/native-tools-disabled.txt"
	exit 0
fi

if command -v samply >/dev/null; then
	samply record --save-only --cswitch-markers \
		--output "${OUTPUT_DIR}/go-samply.json.gz" -- \
		"${GO_BENCHMARK}" perf "${INPUT_PATH}" chunk_hash "${PROFILE_ITERATIONS}" \
		>"${OUTPUT_DIR}/go-samply.stdout" 2>"${OUTPUT_DIR}/go-samply.stderr"
	samply record --save-only --cswitch-markers \
		--output "${OUTPUT_DIR}/rust-samply.json.gz" -- \
		"${RUST_BENCHMARK}" perf "${INPUT_PATH}" chunk_hash "${PROFILE_ITERATIONS}" \
		>"${OUTPUT_DIR}/rust-samply.stdout" 2>"${OUTPUT_DIR}/rust-samply.stderr"
else
	printf 'samply unavailable\n' >>"${OUTPUT_DIR}/tool-limitations.txt"
fi

record_xctrace() {
	local implementation="$1"
	local binary="$2"
	local template="$3"
	local stem="$4"
	xcrun xctrace record --template "${template}" \
		--output "${OUTPUT_DIR}/${implementation}-${stem}.trace" \
		--target-stdout "${OUTPUT_DIR}/${implementation}-${stem}-target.json" \
		--launch -- "${binary}" perf "${INPUT_PATH}" chunk_hash "${PROFILE_ITERATIONS}"
	xcrun xctrace export --input "${OUTPUT_DIR}/${implementation}-${stem}.trace" \
		--toc --output "${OUTPUT_DIR}/${implementation}-${stem}-toc.xml"
}

if command -v xcrun >/dev/null && xcrun xctrace version >/dev/null 2>&1; then
	record_xctrace go "${GO_BENCHMARK}" 'Time Profiler' time-profiler
	record_xctrace rust "${RUST_BENCHMARK}" 'Time Profiler' time-profiler
	record_xctrace go "${GO_BENCHMARK}" 'System Trace' system
	record_xctrace rust "${RUST_BENCHMARK}" 'System Trace' system
	for implementation in go rust; do
		xcrun xctrace export \
			--input "${OUTPUT_DIR}/${implementation}-time-profiler.trace" \
			--xpath '/trace-toc/run[@number="1"]/data/table[@schema="time-sample"]' \
			--output "${OUTPUT_DIR}/${implementation}-time-samples.xml"
		xcrun xctrace export \
			--input "${OUTPUT_DIR}/${implementation}-system.trace" \
			--xpath '/trace-toc/run[@number="1"]/data/table[@schema="context-switch"]' \
			--output "${OUTPUT_DIR}/${implementation}-context-switches.xml"
		xcrun xctrace export \
			--input "${OUTPUT_DIR}/${implementation}-system.trace" \
			--xpath '/trace-toc/run[@number="1"]/data/table[@schema="syscall"]' \
			--output "${OUTPUT_DIR}/${implementation}-syscalls.xml"
	done
else
	printf 'xctrace unavailable\n' >>"${OUTPUT_DIR}/tool-limitations.txt"
fi

inspect_process() {
	local implementation="$1"
	local binary="$2"
	"${binary}" perf "${INPUT_PATH}" chunk_hash "${INSPECTION_ITERATIONS}" \
		>"${OUTPUT_DIR}/${implementation}-inspection-target.json" &
	local pid=$!
	if command -v sample >/dev/null; then
		sample "${pid}" 1 1 -file "${OUTPUT_DIR}/${implementation}-sample.txt" || true
	fi
	ps -M "${pid}" >"${OUTPUT_DIR}/${implementation}-threads.txt" 2>&1 || true
	if command -v vmmap >/dev/null; then
		vmmap -summary "${pid}" >"${OUTPUT_DIR}/${implementation}-vmmap.txt" 2>&1 || true
	fi
	wait "${pid}"
}

inspect_process go "${GO_BENCHMARK}"
inspect_process rust "${RUST_BENCHMARK}"
