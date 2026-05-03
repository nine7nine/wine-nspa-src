#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
#
# compare-rt-suite.sh — diff two RT-suite log directories.
#
# Compares numerical metrics between two run dirs and flags regressions.
# Matching strategy is positional, not regex-best-guess: both logs come
# from the same test binary, so the K'th numeric line in baseline maps
# to the K'th numeric line in current.  This eliminates the "Phase A
# max vs Phase B max collide on key" class of bug.
#
# What's compared:
#   - p50 / p90 / p95 / p99 / p99.9 latencies     (lower better)
#   - avg / mean / min latencies                   (lower better)
#   - throughput / ops/sec / msgs/sec / iters/sec  (higher better)
#   - wait_time / wait_us / wait_ns / wait_ms      (lower better)
#   - errors / failures / missed / lost            (lower better)
#   - PASS / FAIL verdict                          (must match)
#
# What's intentionally NOT compared:
#   - max: single-tail outliers are jitter, not regression signal.
#     Use --include-max to opt back in if you want noisy reports.
#   - Iteration counts, parameter echoes, header/banner lines.
#
# Usage:
#   compare-rt-suite.sh <baseline_dir> <current_dir>
#   compare-rt-suite.sh -t 25 baseline current   # FAIL >25%
#   compare-rt-suite.sh --include-max ...        # report max too
#
# Defaults: WARN >10%, FAIL >25% (exit 1 on any FAIL).

set -u

WARN_THRESHOLD=10
FAIL_THRESHOLD=25
INCLUDE_MAX=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        -w) WARN_THRESHOLD=$2; shift 2 ;;
        -t) FAIL_THRESHOLD=$2; shift 2 ;;
        --include-max) INCLUDE_MAX=1; shift ;;
        -h|--help)
            cat <<EOF
usage: $(basename "$0") [-w WARN_PCT] [-t FAIL_PCT] [--include-max] <baseline_dir> <current_dir>

  -w PCT          warn threshold percent (default 10)
  -t PCT          fail threshold percent (default 25)
  --include-max   include max latency in comparison (default: skip — jitter)

Compares numerical metrics positionally between two RT-suite run dirs.
Exit 0 if no FAIL, 1 if any FAIL, 2 on usage / dir errors.
EOF
            exit 2 ;;
        --) shift; break ;;
        -*) echo "unknown flag: $1" >&2; exit 2 ;;
        *) break ;;
    esac
done

if [[ $# -ne 2 ]]; then
    echo "ERROR: need exactly two directories — baseline and current" >&2
    exit 2
fi
BASE=$1
CURR=$2
[[ -d "$BASE" ]] || { echo "ERROR: $BASE is not a directory" >&2; exit 2; }
[[ -d "$CURR" ]] || { echo "ERROR: $CURR is not a directory" >&2; exit 2; }

red()    { printf '\033[31m%s\033[0m' "$*"; }
green()  { printf '\033[32m%s\033[0m' "$*"; }
yellow() { printf '\033[33m%s\033[0m' "$*"; }
bold()   { printf '\033[1m%s\033[0m' "$*"; }

# Extract a positional metric stream from one log file.  Output format:
#   <metric_kind>\t<metric_name>\t<value>\t<source_line>
# where:
#   metric_kind  — one of: latency_lower, latency_higher, throughput,
#                  wait, errors, verdict
#   metric_name  — the matched metric label (e.g. p99, avg, max,
#                  throughput, errors); used for display
#   value        — numeric value (or PASS/FAIL for verdict)
#   source_line  — line number in source file (for traceability)
#
# Each match emits exactly ONE line.  Multiple metrics on the same input
# line are not split.  The OUTPUT order is identical to the source order
# (this is what enables positional diff downstream).
#
# Patterns are AWK-based, deliberate, and tested against the actual test
# output (see nspa_rt_test/main.c print_kv calls and native test
# printfs).  No best-effort guessing.
extract_metrics() {
    local f=$1
    [[ -f "$f" ]] || return
    local include_max=$2

    # awk handles CRLF (PE binary emits Windows endings) — `gsub("\r","")` strip.
    awk -v include_max="$include_max" '
    {
        gsub("\r", "")

        # Verdict line.  Match leading whitespace + bare "PASS"/"FAIL", or
        # "Verdict: PASS", "RESULT: PASS".  Anchored end-of-line so
        # "PASS_THRU" type strings dont match.
        if ($0 ~ /^[[:space:]]+PASS[[:space:]]*$/ || $0 ~ /^[[:space:]]*Verdict:[[:space:]]+PASS([[:space:]]|$)/ || $0 ~ /^[[:space:]]*RESULT:[[:space:]]+PASS([[:space:]]|$)/) {
            print "verdict\tverdict\tPASS\t" NR
            next
        }
        if ($0 ~ /^[[:space:]]+FAIL([[:space:]]|$)/ || $0 ~ /^[[:space:]]*Verdict:[[:space:]]+FAIL([[:space:]]|$)/ || $0 ~ /^[[:space:]]*RESULT:[[:space:]]+FAIL([[:space:]]|$)/) {
            print "verdict\tverdict\tFAIL\t" NR
            next
        }

        # Latency percentiles.  Match: "p50:  90.7" or "p99 = 122.5"
        # Anchored to start-of-line allow leading whitespace.  Captures
        # the metric label (p50/p99/etc) and the numeric value.
        if (match($0, /^[[:space:]]*(p50|p90|p95|p99\.9|p999|p99|min|avg|mean|median)[[:space:]:=]+([0-9]+\.?[0-9]*)/, m)) {
            print "latency_lower\t" m[1] "\t" m[2] "\t" NR
            next
        }

        # max latency: opt-in only (single-tail outliers are jitter).
        if (match($0, /^[[:space:]]*max[[:space:]:=]+([0-9]+\.?[0-9]*)/, m)) {
            if (include_max == "1")
                print "latency_lower\tmax\t" m[1] "\t" NR
            next
        }

        # Throughput.  Match leading-whitespace + label + numeric.
        # Emit kind=throughput so direction is HIGHER-better.
        if (match($0, /^[[:space:]]*(throughput|ops_per_sec|ops\/sec|msgs\/sec|iters\/sec)[[:space:]:=]+([0-9]+\.?[0-9]*)/, m)) {
            print "throughput\t" m[1] "\t" m[2] "\t" NR
            next
        }

        # Throughput in PE banner format: "Throughput:  8978 msgs/sec"
        if (match($0, /^[[:space:]]*Throughput:[[:space:]]+([0-9]+\.?[0-9]*)/, m)) {
            print "throughput\tthroughput\t" m[1] "\t" NR
            next
        }

        # Wait time.  Be specific: leading "wait" word + numeric, not
        # "  wait_for_X    timeout    foo bar 123".  Require the value
        # to be numeric and the line to look like a key: value report.
        if (match($0, /^[[:space:]]*(wait_time|wait_us|wait_ns|wait_ms|wait[[:space:]]+time)[[:space:]:=]+([0-9]+\.?[0-9]*)/, m)) {
            print "wait\t" m[1] "\t" m[2] "\t" NR
            next
        }
        # Bare "wait:" + numeric (some tests emit just "wait")
        if (match($0, /^[[:space:]]*wait[[:space:]:=]+([0-9]+\.?[0-9]*)/, m)) {
            print "wait\twait\t" m[1] "\t" NR
            next
        }

        # Errors / failures / missed / lost — count metrics, lower better.
        if (match($0, /^[[:space:]]*(errors|failures|missed|lost)[[:space:]:=]+([0-9]+)/, m)) {
            print "errors\t" m[1] "\t" m[2] "\t" NR
            next
        }
    }
    ' "$f"
}

# Compute percent delta from two values.  Output form:
#   <classification>\t<delta_str>
# classification: ok / warn / FAIL
classify() {
    local kind=$1 base=$2 curr=$3

    # Verdict comparison: must match exactly.
    if [[ "$kind" == "verdict" ]]; then
        if [[ "$base" == "$curr" ]]; then
            printf 'ok\tboth %s\n' "$base"
        else
            printf 'FAIL\t%s -> %s\n' "$base" "$curr"
        fi
        return
    fi

    # Numeric metrics.  If baseline is 0, any non-zero current is a
    # divide-by-zero — flag as warn since signal is unclear.
    if awk -v b="$base" 'BEGIN { exit !(b == 0 || b == 0.0) }'; then
        if awk -v c="$curr" 'BEGIN { exit !(c == 0 || c == 0.0) }'; then
            printf 'ok\t0 (both)\n'
        else
            printf 'warn\t0 -> %s (zero baseline; cannot compute %%)\n' "$curr"
        fi
        return
    fi

    # Compute signed percent delta (current relative to baseline).
    local pct
    pct=$(awk -v b="$base" -v c="$curr" \
              'BEGIN { printf "%.1f", 100.0 * (c - b) / b }')

    # Decide whether this is a regression (direction varies by kind).
    local regressed=0
    case "$kind" in
        throughput)
            # higher better — regression when curr < base
            awk -v b="$base" -v c="$curr" 'BEGIN { exit !(c < b) }' && regressed=1
            ;;
        latency_lower|wait|errors)
            # lower better — regression when curr > base
            awk -v b="$base" -v c="$curr" 'BEGIN { exit !(c > b) }' && regressed=1
            ;;
        *)
            # unknown kind — flag any change
            awk -v b="$base" -v c="$curr" 'BEGIN { exit !(c != b) }' && regressed=1
            ;;
    esac

    local abs_pct
    abs_pct=$(awk -v p="$pct" 'BEGIN { print (p < 0 ? -p : p) }')

    local cls=ok
    if [[ "$regressed" == "1" ]]; then
        if awk -v a="$abs_pct" -v t="$FAIL_THRESHOLD" 'BEGIN { exit !(a > t) }'; then
            cls=FAIL
        elif awk -v a="$abs_pct" -v t="$WARN_THRESHOLD" 'BEGIN { exit !(a > t) }'; then
            cls=warn
        fi
    fi

    printf '%s\t%s%% (%s -> %s)\n' "$cls" "$pct" "$base" "$curr"
}

# ─── main ──────────────────────────────────────────────────────────────

bold "  COMPARISON: $(basename "$CURR") vs baseline $(basename "$BASE")"
echo
echo "  thresholds: warn >${WARN_THRESHOLD}%, fail >${FAIL_THRESHOLD}%"
[[ "$INCLUDE_MAX" == "1" ]] && echo "  --include-max: max latency included"
echo

declare -A files_curr
for f in "$CURR"/baseline_*.log "$CURR"/rt_*.log; do
    [[ -f "$f" ]] || continue
    files_curr[$(basename "$f")]=1
done

total_warn=0
total_fail=0
total_ok=0

for f_base in "$BASE"/baseline_*.log "$BASE"/rt_*.log; do
    [[ -f "$f_base" ]] || continue
    fname=$(basename "$f_base")
    [[ -n "${files_curr[$fname]:-}" ]] || continue
    f_curr="$CURR/$fname"

    # Extract positional metric streams.
    base_stream=$(extract_metrics "$f_base" "$INCLUDE_MAX")
    curr_stream=$(extract_metrics "$f_curr" "$INCLUDE_MAX")
    [[ -n "$base_stream" ]] || continue

    # Convert streams to indexed arrays for positional comparison.
    mapfile -t base_lines <<< "$base_stream"
    mapfile -t curr_lines <<< "$curr_stream"

    # Length mismatch is a structural change worth surfacing — counts
    # different = test output changed shape, not a stat regression.
    if [[ ${#base_lines[@]} -ne ${#curr_lines[@]} ]]; then
        echo
        bold "  $(basename "${fname%.log}")"; echo
        printf '    %s  metric count mismatch: baseline=%d, current=%d  (test output shape changed)\n' \
            "$(yellow WARN)" "${#base_lines[@]}" "${#curr_lines[@]}"
        total_warn=$((total_warn+1))
        continue
    fi

    # Compare position-by-position.  Skip OK silently; only print
    # warn/FAIL with the source-line annotation so you can map back.
    local_header_printed=0
    label="${fname%.log}"
    for i in "${!base_lines[@]}"; do
        IFS=$'\t' read -r b_kind b_name b_val b_line <<< "${base_lines[$i]}"
        IFS=$'\t' read -r c_kind c_name c_val c_line <<< "${curr_lines[$i]}"
        # Sanity: kinds and metric names should match position-by-position.
        if [[ "$b_kind" != "$c_kind" || "$b_name" != "$c_name" ]]; then
            if [[ "$local_header_printed" == "0" ]]; then
                echo; bold "  $label"; echo; local_header_printed=1
            fi
            printf '    %s  position %d: kind/name mismatch (%s/%s vs %s/%s)\n' \
                "$(yellow WARN)" "$i" "$b_kind" "$b_name" "$c_kind" "$c_name"
            total_warn=$((total_warn+1))
            continue
        fi

        IFS=$'\t' read -r cls delta < <(classify "$b_kind" "$b_val" "$c_val")
        case "$cls" in
            ok)
                total_ok=$((total_ok+1))
                continue ;;
            warn) total_warn=$((total_warn+1)) ;;
            FAIL) total_fail=$((total_fail+1)) ;;
        esac

        if [[ "$local_header_printed" == "0" ]]; then
            echo; bold "  $label"; echo; local_header_printed=1
        fi
        case "$cls" in
            FAIL) printf '    %s  %-14s @line %-3s  %s\n' "$(red FAIL)" "$b_name" "$b_line" "$delta" ;;
            warn) printf '    %s  %-14s @line %-3s  %s\n' "$(yellow WARN)" "$b_name" "$b_line" "$delta" ;;
        esac
    done
done

echo
bold "  totals"; echo
printf '    ok    : %d\n' "$total_ok"
printf '    %s  : %d\n' "$(yellow WARN)" "$total_warn"
printf '    %s  : %d\n' "$(red FAIL)" "$total_fail"

if (( total_fail > 0 )); then
    echo; echo "  $(red OVERALL: FAIL)"
    exit 1
fi
echo; echo "  $(green OVERALL: OK)"
exit 0
