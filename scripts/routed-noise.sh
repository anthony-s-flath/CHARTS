#!/usr/bin/env bash
set -uo pipefail

# Run from the CHARTS repository root. Override CONFIGS to change the sweep.
read -r -a configs <<< "${CONFIGS:-128:1 128:128}"
log=$(mktemp)
trap 'rm -f "$log"' EXIT
failed=0

for pair in "${configs[@]}"; do
    IFS=: read -r n b <<< "$pair"
    status=0
    make --no-print-directory test-noise \
        CHARTS_N="$n" CHARTS_B="$b" \
        CHARTS_THREADS="${CHARTS_THREADS:-1}" >"$log" 2>&1 || status=$?

    # Print the measurement even if a later correctness check failed.
    if ! awk -v n="$n" -v b="$b" '
        /routed payload n-1:/ {
            printf "n=%s b=%s %s\n", n, b, $0
            found=1
        }
        END { exit !found }
    ' "$log"; then
        printf 'n=%s b=%s: no routed-payload measurement\n' "$n" "$b" >&2
        cat "$log" >&2
        failed=1
    fi
    if (( status != 0 )); then
        printf 'n=%s b=%s: test failed (exit %s)\n' "$n" "$b" "$status" >&2
        failed=1
    fi
done

exit "$failed"
