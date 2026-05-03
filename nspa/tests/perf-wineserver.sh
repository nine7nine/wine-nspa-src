#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
#
# perf-wineserver.sh — opt-in perf record wrapper for wineserver.
#
# Captures a perf.data on the running wineserver process for the
# specified duration, then prints a `perf report` symbol summary.
# Saves the raw perf.data so you can run `perf report -i perf.data`
# yourself for deeper analysis.
#
# Output:
#   $OUT_DIR/perf.data           — raw perf record output
#   $OUT_DIR/perf-report.txt     — flat symbol summary (top 30)
#   $OUT_DIR/perf-callgraph.txt  — callgraph summary (top 20)
#
# Requires: perf (linux-tools), root (for kernel symbols), wineserver
# already running.
#
# Usage:
#   sudo ./perf-wineserver.sh                    # 30s default
#   sudo ./perf-wineserver.sh -d 60             # 60s window
#   sudo ./perf-wineserver.sh -o /tmp/myperf    # custom output dir
#   sudo ./perf-wineserver.sh -F 4000           # higher sample rate
#
# Environment:
#   OUT_DIR     output directory (default /tmp/nspa-perf-<timestamp>)
#   FREQ        sample frequency in Hz (default 999)
#   DURATION    capture duration in seconds (default 30)

set -u

DURATION=${DURATION:-30}
FREQ=${FREQ:-999}
OUT_DIR=${OUT_DIR:-}

while getopts "d:F:ho:" opt; do
    case "$opt" in
        d) DURATION=$OPTARG ;;
        F) FREQ=$OPTARG ;;
        o) OUT_DIR=$OPTARG ;;
        h|*)
            cat <<EOF
usage: sudo $(basename "$0") [-d SECONDS] [-F HZ] [-o OUT_DIR]

  -d N    capture duration in seconds (default 30)
  -F HZ   sample frequency (default 999)
  -o DIR  output directory (default /tmp/nspa-perf-<timestamp>)

Profiles the running wineserver for N seconds with perf record (call-graph,
DWARF), saves raw perf.data + flat + callgraph reports to OUT_DIR.

This is the OPT-IN profiling entry point.  For continuous observability
with low overhead, use the bpf-*.sh scripts instead.
EOF
            exit 2 ;;
    esac
done

if [[ $EUID -ne 0 ]]; then
    echo "ERROR: must run as root (sudo) — perf needs CAP_SYS_ADMIN" >&2
    exit 2
fi
if ! command -v perf >/dev/null 2>&1; then
    echo "ERROR: perf not installed (try: pacman -S perf or linux-tools)" >&2
    exit 2
fi

WS_PID=$(pgrep -x wineserver | head -1)
if [[ -z "$WS_PID" ]]; then
    echo "ERROR: no wineserver process running. Start your Wine workload first." >&2
    exit 2
fi

if [[ -z "$OUT_DIR" ]]; then
    OUT_DIR=/tmp/nspa-perf-$(date +%Y%m%d-%H%M%S)
fi
mkdir -p "$OUT_DIR"

PERF_DATA="$OUT_DIR/perf.data"
REPORT="$OUT_DIR/perf-report.txt"
CALLGRAPH="$OUT_DIR/perf-callgraph.txt"

echo "[perf-wineserver] target wineserver PID: $WS_PID"
echo "[perf-wineserver] duration: ${DURATION}s @ ${FREQ}Hz"
echo "[perf-wineserver] output: $OUT_DIR"
echo

echo "[perf-wineserver] recording..."
# --call-graph dwarf needs --user-regs=ip,sp,bp on some archs; default
# --call-graph dwarf works on x86_64/glibc with frame info.  -g adds
# stack collection.  -F controls sample rate.  -p attaches to pid.
perf record \
    -F "$FREQ" \
    -p "$WS_PID" \
    --call-graph dwarf \
    -o "$PERF_DATA" \
    -- sleep "$DURATION"
rc=$?
if [[ $rc -ne 0 ]]; then
    echo "[perf-wineserver] WARN: perf record returned $rc; proceeding with what we got"
fi

echo
echo "[perf-wineserver] generating reports..."

# Flat symbol summary (top consumers).  --stdio for non-interactive,
# --no-children for self-time only (excludes callee accumulation).
perf report -i "$PERF_DATA" --stdio --no-children -g none 2>/dev/null \
    | head -80 > "$REPORT" || true

# Callgraph summary (parent -> child relationships).  -g graph,0.5
# folds entries below 0.5% into a parent line.
perf report -i "$PERF_DATA" --stdio -g graph,0.5,callee 2>/dev/null \
    | head -200 > "$CALLGRAPH" || true

echo
echo "=== flat symbol summary (top of $REPORT) ==="
head -40 "$REPORT"

echo
echo "[perf-wineserver] done."
echo "  raw data : $PERF_DATA"
echo "  flat     : $REPORT"
echo "  callgraph: $CALLGRAPH"
echo
echo "for interactive exploration:"
echo "  perf report -i $PERF_DATA"
