#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
#
# report-rt-suite.sh — render the end-of-run summary tables.
#
# Two tables, in this order:
#   1. Full stats table — every STATS_KEY metric for every test, baseline
#      (NSPA defaults, no RT promotion) and rt (NSPA + RT promotion) side-by-side.
#   2. Deltas table — for each metric, baseline-vs-prior and rt-vs-prior
#      percentage deltas with color coding (green = ok, yellow = warn,
#      red = fail).  Skipped if no prior archive exists.
#
# Usage:
#   report-rt-suite.sh <current_run_dir> [<baseline_run_dir>]
#
# When baseline omitted, only Table 1 (full stats) is rendered.
# Designed to be invoked by run-rt-suite.sh's post_run() — no manual call needed.
#
# Thresholds (color thresholds for deltas):
#   <10%  green / no flag
#   10-25% yellow WARN
#   >25%  red FAIL
#
# Override with WARN_PCT / FAIL_PCT env vars.

set -u

WARN_PCT=${WARN_PCT:-10}
FAIL_PCT=${FAIL_PCT:-25}

if [[ $# -lt 1 || $# -gt 2 ]]; then
    cat <<EOF >&2
usage: $(basename "$0") <current_run_dir> [<baseline_run_dir>]

Renders end-of-run stats summary tables.  Run dir = the v<N>-<ts>/
archive directory containing baseline_*.log and rt_*.log files.
EOF
    exit 2
fi

CURR=$1
BASE=${2:-}
[[ -d "$CURR" ]] || { echo "ERROR: not a directory: $CURR" >&2; exit 2; }
[[ -z "$BASE" || -d "$BASE" ]] || { echo "ERROR: not a directory: $BASE" >&2; exit 2; }

red()    { printf '\033[31m%s\033[0m' "$*"; }
green()  { printf '\033[32m%s\033[0m' "$*"; }
yellow() { printf '\033[33m%s\033[0m' "$*"; }
cyan()   { printf '\033[36m%s\033[0m' "$*"; }
bold()   { printf '\033[1m%s\033[0m' "$*"; }
dim()    { printf '\033[2m%s\033[0m' "$*"; }

# Extract STATS_KEY:name=value lines from a log.  Output: name<TAB>value
# (CRLF stripped — PE binary emits Windows endings).  Skips lines outside
# STATS_BEGIN/STATS_END blocks (defensive — some test output can include
# the literal string elsewhere).
extract_stats() {
    local f=$1
    [[ -f "$f" ]] || return 0
    awk '
        /^STATS_BEGIN/   { in_block = 1; next }
        /^STATS_END/     { in_block = 0; next }
        in_block && /^STATS_KEY:/ {
            gsub(/\r/, "")
            sub(/^STATS_KEY:/, "")
            split($0, kv, "=")
            print kv[1] "\t" kv[2]
        }
    ' "$f"
}

# Compute percent delta between two numeric values.
# Output: <classification><TAB><pct>
# classification first because `read` with IFS=tab swallows leading-empty
# fields — putting cls first keeps the format unambiguous.
# classification: ok | warn | FAIL | nochange | nobaseline
compute_delta() {
    local base=$1 curr=$2
    if [[ -z "$base" || -z "$curr" ]]; then
        printf 'nobaseline\t-\n'; return
    fi
    if awk -v b="$base" 'BEGIN { exit !(b == 0 || b+0 == 0) }'; then
        if awk -v c="$curr" 'BEGIN { exit !(c == 0 || c+0 == 0) }'; then
            printf 'nochange\t0\n'
        else
            printf 'nobaseline\tinf\n'
        fi
        return
    fi
    local pct
    pct=$(awk -v b="$base" -v c="$curr" 'BEGIN { printf "%.1f", 100.0*(c-b)/b }')
    local abs_pct
    abs_pct=$(awk -v p="$pct" 'BEGIN { print (p < 0 ? -p : p) }')
    local cls=ok
    if awk -v a="$abs_pct" -v t="$FAIL_PCT" 'BEGIN { exit !(a > t) }'; then
        cls=FAIL
    elif awk -v a="$abs_pct" -v t="$WARN_PCT" 'BEGIN { exit !(a > t) }'; then
        cls=warn
    fi
    printf '%s\t%s\n' "$cls" "$pct"
}

# Get the test name list (intersection of baseline + rt logs in CURR).
list_tests() {
    local d=$1
    for f in "$d"/baseline_*.log; do
        [[ -f "$f" ]] || continue
        local name=$(basename "$f" .log | sed 's/^baseline_//')
        [[ -f "$d/rt_${name}.log" ]] && echo "$name"
    done
}

# ─── Table layout helpers (Unicode box drawing) ──────────────────────
#
# Each test renders as a self-contained box.  Layout:
#   ┌─ <test name> ────────────────────────────────────────┐
#   │   metric                        baseline           rt │
#   │   ──────                       ────────           ── │
#   │   foo_us                            123          110 │
#   │   bar_ops_per_sec                 45000        47000 │
#   └──────────────────────────────────────────────────────┘
#
# Column widths (visible chars only — ANSI codes don't count).
COL_METRIC=34
COL_VAL=12
INNER_PAD=3                                   # "│  " + ... + "  │"
INNER_W=$(( COL_METRIC + 2 + COL_VAL + 2 + COL_VAL + INNER_PAD * 2 - 2 ))

# Repeat $1 N times — bash loop because `tr ' ' '<multi-byte>'` substitutes
# byte-by-byte and shreds Unicode codepoints (─, ·, etc).
hrule() {
    local ch=$1 n=$2 i
    for ((i = 0; i < n; i++)); do printf '%s' "$ch"; done
}

# Strip ANSI escapes from a string (for visible-width math).
strip_ansi() { printf '%s' "$1" | sed -E $'s/\x1b\\[[0-9;]*m//g'; }

# Outer (full-suite) section banner.
section_banner() {
    local title=$1
    local w=$INNER_W
    printf '╭'; hrule '─' "$w"; printf '╮\n'
    local pad=$(( w - ${#title} - 4 ))
    local lp=$(( pad / 2 )); local rp=$(( pad - lp ))
    printf '│  '; hrule ' ' "$lp"; bold "$title"; hrule ' ' "$rp"; printf '  │\n'
    printf '╰'; hrule '─' "$w"; printf '╯\n'
}

# Per-test box top.  Title appears inline in the top rule.
test_box_top() {
    local title=$1
    local prefix='┌─ '
    local suffix=' '
    local title_visible=$(( ${#title} + ${#prefix} + ${#suffix} ))
    local fill=$(( INNER_W - title_visible + 1 ))   # +1 for the trailing ┐
    [[ $fill -lt 1 ]] && fill=1
    printf '%s' "$prefix"
    bold "$title"
    printf '%s' "$suffix"
    hrule '─' "$fill"
    printf '┐\n'
}

# Per-test box bottom.
test_box_bottom() {
    printf '└'; hrule '─' "$INNER_W"; printf '┘\n'
}

# Print a table row inside a box.  Args: metric, val_baseline, val_rt
# (already-formatted strings; visible width of each val expected = COL_VAL).
box_row() {
    local metric=$1 vbl=$2 vrt=$3
    # Compute inner content visible width and pad to match INNER_W.
    local content
    printf -v content "  %-*s  %s  %s  " "$COL_METRIC" "$metric" "$vbl" "$vrt"
    local visible_len=$(( ${#content} - $(strip_ansi "$content" | wc -c) + $(strip_ansi "$content" | wc -c) ))
    # Simpler: visible len = strlen of stripped content
    local stripped
    stripped=$(strip_ansi "$content")
    local pad=$(( INNER_W - ${#stripped} ))
    [[ $pad -lt 0 ]] && pad=0
    printf '│%s' "$content"
    hrule ' ' "$pad"
    printf '│\n'
}

# Header row inside a box.  Args: col3 col4 (column titles).  Underline
# rule below spans the full COL_VAL width on each side, matching value
# rows for clean visual alignment.
box_header() {
    local c3=$1 c4=$2
    box_row "metric" "$(printf '%*s' "$COL_VAL" "$c3")" "$(printf '%*s' "$COL_VAL" "$c4")"
    local rule_metric=$(hrule '─' "$COL_METRIC")
    local rule_val=$(hrule '─' "$COL_VAL")
    box_row "$rule_metric" "$rule_val" "$rule_val"
}

# ─── Table 1: full stats ──────────────────────────────────────────────

echo
section_banner "Full stats — $(basename "$CURR")"

for t in $(list_tests "$CURR"); do
    bl=$(extract_stats "$CURR/baseline_${t}.log")
    rt=$(extract_stats "$CURR/rt_${t}.log")
    [[ -z "$bl" && -z "$rt" ]] && continue

    echo
    test_box_top "$t"
    box_header "baseline" "rt"

    while IFS=$'\t' read -r key bval; do
        [[ -n "$key" ]] || continue
        rval=$(awk -v k="$key" -F'\t' '$1 == k { print $2; exit }' <<< "$rt")
        box_row "$key" \
            "$(printf '%*s' "$COL_VAL" "${bval:--}")" \
            "$(printf '%*s' "$COL_VAL" "${rval:--}")"
    done <<< "$bl"
    test_box_bottom
done

# ─── Table 2: deltas vs baseline archive ──────────────────────────────

[[ -z "$BASE" ]] && { echo; echo "  $(dim "(no baseline archive given — skipping deltas table)")"; exit 0; }

echo
section_banner "Deltas vs $(basename "$BASE")"

# Format a delta value pre-padded to COL_VAL visible chars + ANSI color.
fmt_delta() {
    local pct=$1 cls=$2
    local raw
    case "$cls" in
        ok|warn|FAIL) raw="${pct}%" ;;
        nochange)     raw="0%" ;;
        nobaseline)   raw="n/a" ;;
        *)            raw="?" ;;
    esac
    local padded
    printf -v padded '%*s' "$COL_VAL" "$raw"
    case "$cls" in
        warn)                 yellow "$padded" ;;
        FAIL)                 red    "$padded" ;;
        nochange|nobaseline)  dim    "$padded" ;;
        *)                    printf '%s' "$padded" ;;
    esac
}

worst_cls=ok
for t in $(list_tests "$CURR"); do
    [[ -f "$BASE/baseline_${t}.log" && -f "$BASE/rt_${t}.log" ]] || continue
    cur_bl=$(extract_stats "$CURR/baseline_${t}.log")
    cur_rt=$(extract_stats "$CURR/rt_${t}.log")
    base_bl=$(extract_stats "$BASE/baseline_${t}.log")
    base_rt=$(extract_stats "$BASE/rt_${t}.log")
    [[ -z "$cur_bl" ]] && continue

    # Pre-collect rows so we can decide whether to emit a box at all
    # (skip tests where every metric is no-change / no-baseline).
    local_rows=""
    while IFS=$'\t' read -r key bval; do
        [[ -n "$key" ]] || continue
        bbase=$(awk -v k="$key" -F'\t' '$1 == k { print $2; exit }' <<< "$base_bl")
        rcur=$(awk -v k="$key" -F'\t'  '$1 == k { print $2; exit }' <<< "$cur_rt")
        rbase=$(awk -v k="$key" -F'\t' '$1 == k { print $2; exit }' <<< "$base_rt")
        IFS=$'\t' read -r bl_cls d_bl < <(compute_delta "$bbase" "$bval")
        IFS=$'\t' read -r rt_cls d_rt < <(compute_delta "$rbase" "$rcur")
        if [[ "$bl_cls" == "nochange"   && "$rt_cls" == "nochange"   ]]; then continue; fi
        if [[ "$bl_cls" == "nobaseline" && "$rt_cls" == "nobaseline" ]]; then continue; fi
        case "$bl_cls $rt_cls" in
            *FAIL*) worst_cls=FAIL ;;
            *warn*) [[ "$worst_cls" != "FAIL" ]] && worst_cls=warn ;;
        esac
        local_rows+="${key}|${d_bl}|${bl_cls}|${d_rt}|${rt_cls}"$'\n'
    done <<< "$cur_bl"

    [[ -z "$local_rows" ]] && continue

    echo
    test_box_top "$t"
    box_header "baseline-Δ" "rt-Δ"
    while IFS='|' read -r key d_bl bl_cls d_rt rt_cls; do
        [[ -n "$key" ]] || continue
        box_row "$key" \
            "$(fmt_delta "$d_bl" "$bl_cls")" \
            "$(fmt_delta "$d_rt" "$rt_cls")"
    done <<< "$local_rows"
    test_box_bottom
done

echo
case "$worst_cls" in
    FAIL) echo "  worst delta: $(red FAIL) (>${FAIL_PCT}%)" ;;
    warn) echo "  worst delta: $(yellow WARN) (>${WARN_PCT}%)" ;;
    *)    echo "  worst delta: $(green OK) (all within ${WARN_PCT}%)" ;;
esac
