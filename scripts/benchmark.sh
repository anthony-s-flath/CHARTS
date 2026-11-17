#!/usr/bin/env bash

set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd -- "${script_dir}/.." && pwd)"
cd "${repo_root}"

repetitions="${REPETITIONS:-50}"
benchtime="${BENCHTIME:-1x}"
threads="${CHARTS_THREADS:-${BENCH_THREADS:-4}}"
profile="${CHARTS_PROFILE:-${BENCH_PROFILE:-${CHARTS_BENCH_PROFILE:-paper}}}"
pattern="${BENCH_PATTERN:-BenchmarkProtocol}"
# n:b
configs="${CONFIGS:-32:32 64:64 128:128 256:256 128:1 128:16 128:32 128:64}"

timestamp="$(date +%Y%m%d-%H%M%S)"
results_dir="${RESULTS_DIR:-benchmark-results-${timestamp}}"
mkdir -p "${results_dir}/logs"

raw_file="${results_dir}/full-benchmarks.txt"
results_file="${results_dir}/summarized-benchmarks.txt"
: > "${raw_file}"

read -r -a config_list <<< "${configs}"
config_number=0

for config in "${config_list[@]}"; do
	IFS=: read -r n b <<< "${config}"
	if [[ ! "${n}" =~ ^[0-9]+$ || ! "${b}" =~ ^[0-9]+$ ]]; then
		echo "Invalid configuration ${config}; use n:b." >&2
		exit 1
	fi

	config_number=$((config_number + 1))
	log_file="${results_dir}/logs/n${n}-b${b}.log"

	echo
	echo "[configuration ${config_number}/${#config_list[@]}] n=${n}, b=${b}, samples=${repetitions}"

	make benchmark \
		CHARTS_PROFILE="${profile}" \
		CHARTS_N="${n}" \
		CHARTS_B="${b}" \
		BENCH_PATTERN="${pattern}" \
		BENCHTIME="${benchtime}" \
		BENCH_COUNT="${repetitions}" \
		CHARTS_THREADS="${threads}" 2>&1 \
		| tee "${log_file}" \
		| tee -a "${raw_file}"
done

echo
echo "Raw Go benchmark output: ${raw_file}"

python3 "${script_dir}/summarize_benchmarks.py" "${raw_file}" \
	| tee "${results_file}"

echo
echo "Benchmark averages: ${results_file}"
