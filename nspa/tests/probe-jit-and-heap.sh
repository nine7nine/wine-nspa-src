#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
#
# probe-jit-and-heap.sh — survey JIT-region pressure + heap traffic on a
# Wine PE process (typically Ableton.exe), to expose the Wine/Linux levers
# that influence a closed-source JIT-compiled audio engine's CPU cost.
#
# Captures four pillars in one D-second window:
#
#   1. CPU shape (perf stat -d -d -d):
#        IPC, branch-miss%, iTLB-load-misses, L1-icache-load-misses,
#        dTLB-load-misses, page-faults, ctx-switches, cpu-migrations.
#        Tells you whether the JIT is i-cache/ITLB bound, branch-predict
#        bound, dTLB/working-set bound, or just pure cycle bound.
#
#   2. JIT region inventory (/proc/$pid/{maps,smaps,status} pre+post diff):
#        anon `rwxp` mappings = JIT regions. Snapshot before+after to see
#        size, count, growth, and Rss/Pss/Anon working set deltas.
#        On PREEMPT_RT we expect AnonHugePages=0 (THP disabled).
#
#   3. Wine→kernel interface traffic (single bpftrace program):
#        - mmap with PROT_EXEC      = JIT page allocation rate
#        - mmap without PROT_EXEC   = heap/data/file-map growth rate
#        - mprotect with PROT_EXEC  = RW<->RX flip rate (VMA-split risk)
#        - mprotect without EXEC    = other protection flip rate
#        - munmap                   = page free rate
#        - brk                      = libc heap arena growth (rare path)
#        - futex                    = sync/heap-CS contention proxy
#                                      (count + wait-time histogram)
#        - page_fault_user          = soft-fault rate (incl. JIT first-touch)
#        Uses kprobes (positional args, BTF-free) for mmap/mprotect so it
#        works on PREEMPT_RT kernels built without CONFIG_DEBUG_INFO_BTF.
#        All filtered to the target PID's process tree.
#
#   3b. Per-thread sched-policy + affinity + CPU-time delta:
#        Snapshots /proc/$pid/task/*/{sched,status,stat} pre+post to
#        reveal which threads burned the most user/sys time and whether
#        their CPU affinity allows the migrations seen in pillar 1.
#
#   4. Hot-region attribution (perf record --call-graph dwarf, optional):
#        DWARF-unwound samples; JIT samples appear as `[unknown]` but with
#        the address, cross-referenced against /proc/$pid/maps to identify
#        which JIT region is hot. Off by default on RT (overhead);
#        enable with --record.
#
# Output layout:
#   probe-out-<timestamp>/
#     perf-stat.txt                CPU shape counters + summary
#     maps-pre.txt   maps-post.txt
#     smaps-pre.txt  smaps-post.txt
#     status-pre.txt status-post.txt
#     jit-regions-pre.txt          rwxp-only filtered view + sizes
#     jit-regions-post.txt
#     bpf-output.txt               bpftrace counts + histograms
#     perf.data + perf-report.txt  (only if --record)
#     summary.txt                  human-readable rollup
#
# Usage:
#   sudo ./probe-jit-and-heap.sh -p $(pidof Ableton.exe) -d 30
#   sudo ./probe-jit-and-heap.sh -p 12345 -d 60 --record
#   sudo ./probe-jit-and-heap.sh -p 12345 -d 30 -o /tmp/jit-probe
#
# Requires: perf, bpftrace, awk, root (sudo).

set -u

DURATION=30
TARGET_PID=0
TARGET_TID=0      # if set, scope bpf + perf stat to a single thread
OUTDIR=""
DO_RECORD=0
SAMPLE_HZ=99   # low on RT to minimise audio-thread interference

usage() {
    cat <<EOF
usage: sudo $(basename "$0") -p PID [-t TID] [-d SECONDS] [-o DIR] [--record] [--hi-res]

  -p PID       target Wine PE process (required, e.g. \$(pidof Ableton.exe))
  -t TID       scope bpf counters + perf stat to a single thread (default: all)
  -d N         capture window seconds (default: $DURATION)
  -o DIR       output directory (default: probe-out-<timestamp>)
  --record     also run perf record --call-graph dwarf for hotspot attribution
  --hi-res     sample at 499 Hz instead of 99 Hz (more accurate, more overhead)
  -h           this help

Captures CPU shape, JIT region inventory, Wine->kernel interface traffic,
and (optional) hot-region attribution for a Wine PE process.

bpf counters are also broken down by thread name (comm) so you can see
which thread group (MainThread, AudioCalc, MidiOut, ...) drives each
syscall family. Use -t to drill into one specific thread.

PREEMPT_RT-safe: does not rely on THP, defaults to 99 Hz sampling.
EOF
}

require_value() {
    if [[ -z "${2:-}" ]] || [[ "${2:0:1}" == "-" ]]; then
        echo "ERROR: $1 requires a value" >&2
        usage
        exit 2
    fi
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        -p) require_value "$1" "${2:-}"; TARGET_PID="$2"; shift 2 ;;
        -t) require_value "$1" "${2:-}"; TARGET_TID="$2"; shift 2 ;;
        -d) require_value "$1" "${2:-}"; DURATION="$2"; shift 2 ;;
        -o) require_value "$1" "${2:-}"; OUTDIR="$2"; shift 2 ;;
        --record) DO_RECORD=1; shift ;;
        --hi-res) SAMPLE_HZ=499; shift ;;
        -h|--help) usage; exit 0 ;;
        *) echo "ERROR: unknown arg: $1" >&2; usage; exit 2 ;;
    esac
done

if [[ $EUID -ne 0 ]]; then
    echo "ERROR: must run as root (sudo)" >&2
    exit 2
fi
if [[ "$TARGET_PID" -le 0 ]] || [[ ! -d "/proc/$TARGET_PID" ]]; then
    echo "ERROR: invalid or missing PID: $TARGET_PID" >&2
    usage
    exit 2
fi
if [[ "$TARGET_TID" -gt 0 ]] && [[ ! -d "/proc/$TARGET_PID/task/$TARGET_TID" ]]; then
    echo "ERROR: TID $TARGET_TID is not a thread of PID $TARGET_PID" >&2
    exit 2
fi
if [[ "$TARGET_TID" -gt 0 ]]; then
    BPF_FILTER="tid == $TARGET_TID"
    SCOPE_LABEL="TID=$TARGET_TID (single thread)"
    PERF_STAT_TARGET=(-t "$TARGET_TID")
else
    BPF_FILTER="pid == $TARGET_PID"
    SCOPE_LABEL="PID=$TARGET_PID (all threads)"
    PERF_STAT_TARGET=(-p "$TARGET_PID")
fi
for tool in perf bpftrace awk; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "ERROR: $tool not installed" >&2
        exit 2
    fi
done
if [[ "$DO_RECORD" -eq 1 ]] && [[ ! -r /proc/sys/kernel/perf_event_paranoid ]]; then
    echo "WARN: cannot read perf_event_paranoid; perf record may fail" >&2
fi

if [[ -z "$OUTDIR" ]]; then
    OUTDIR="probe-out-$(date +%Y%m%d-%H%M%S)"
fi
mkdir -p "$OUTDIR"
OUTDIR="$(readlink -f "$OUTDIR")"
echo "[probe] scope: $SCOPE_LABEL  duration=${DURATION}s  outdir=$OUTDIR"

PROC_NAME="$(awk -F/ '{print $NF}' /proc/$TARGET_PID/comm 2>/dev/null || echo unknown)"
echo "[probe] target comm=$PROC_NAME"

# --- pillar 2 pre-snapshot --------------------------------------------------

cp /proc/$TARGET_PID/maps   "$OUTDIR/maps-pre.txt"   2>/dev/null || true
cp /proc/$TARGET_PID/smaps  "$OUTDIR/smaps-pre.txt"  2>/dev/null || true
cp /proc/$TARGET_PID/status "$OUTDIR/status-pre.txt" 2>/dev/null || true

# JIT regions = anonymous mappings with rwxp permissions.
filter_jit_regions() {
    local mapfile="$1" outfile="$2"
    awk '
    {
        perms = $2
        # anon mapping = no path field (NF == 5) OR path starts with [
        is_anon = (NF == 5) || ($NF ~ /^\[/)
        if (perms ~ /rwx/ && is_anon) {
            split($1, r, "-")
            sz = strtonum("0x" r[2]) - strtonum("0x" r[1])
            printf "%-34s  %s  %10d KB  %s\n", $1, perms, sz/1024, ($NF ~ /^\[/ ? $NF : "[anon]")
            total += sz
            count++
        }
    }
    END {
        printf "\n--- %d rwxp anon mappings, total %d KB (%.2f MB) ---\n", count+0, (total+0)/1024, (total+0)/1024/1024
    }' "$mapfile" > "$outfile"
}

filter_jit_regions "$OUTDIR/maps-pre.txt"  "$OUTDIR/jit-regions-pre.txt"

# --- pillar 2.5 pre: per-thread sched-policy + affinity + CPU time ---------

snapshot_threads() {
    local outfile="$1"
    {
        printf "%-7s  %-16s  %-6s  %-3s  %-12s  %-10s  %-10s\n" \
            TID NAME POLICY RT AFFINITY UTIME_TICKS STIME_TICKS
        for tdir in /proc/$TARGET_PID/task/*/; do
            local tid name pol rtp aff utime stime polname
            tid=$(basename "$tdir")
            [[ -r $tdir/stat ]] || continue
            name=$(awk -F'[()]' '{print $2}' "$tdir/stat" 2>/dev/null)
            utime=$(awk '{print $14}' "$tdir/stat" 2>/dev/null)
            stime=$(awk '{print $15}' "$tdir/stat" 2>/dev/null)
            pol=$(awk "/^policy/{print \$3}" "$tdir/sched" 2>/dev/null)
            rtp=$(awk "/^rt_priority/{print \$3}" "$tdir/sched" 2>/dev/null)
            aff=$(awk "/^Cpus_allowed_list/{print \$2}" "$tdir/status" 2>/dev/null)
            case "$pol" in
                0) polname=OTHER ;; 1) polname=FIFO ;; 2) polname=RR ;;
                3) polname=BATCH ;; 5) polname=IDLE ;; 6) polname=DEAD ;;
                *) polname="?" ;;
            esac
            printf "%-7s  %-16s  %-6s  %-3s  %-12s  %-10s  %-10s\n" \
                "$tid" "$name" "$polname" "${rtp:-0}" "${aff:-?}" \
                "${utime:-0}" "${stime:-0}"
        done
    } > "$outfile"
}

snapshot_threads "$OUTDIR/threads-pre.txt"

# --- pillar 3 bpftrace program ---------------------------------------------

# We use a process-tree filter: the target PID, plus any thread of it.
# bpftrace `pid` builtin = TGID, so PID == TARGET_PID matches all threads.

#
# Note on probe choices:
#   mmap/mprotect use kprobes with positional args (arg2 = prot) so we do
#   not need CONFIG_DEBUG_INFO_BTF (PREEMPT_RT often disables it).
#   Sched-switch / preemption-rate is dropped here — perf stat already
#   gives us context-switches + cpu-migrations counters with no overhead.
#
BPF_PROG='
BEGIN
{
    printf("[bpf] tracing '$SCOPE_LABEL' for '$DURATION's\n");
}

/* JIT page allocation: mmap with PROT_EXEC (4).
 * ksys_mmap_pgoff(addr, len, prot, flags, fd, pgoff) -> prot is arg2 */
kprobe:ksys_mmap_pgoff
/ '"$BPF_FILTER"' && (arg2 & 4) /
{
    @mmap_exec_total = count();
    @mmap_exec_by_comm[comm] = count();
    @mmap_exec_bytes = sum(arg1);
    @mmap_exec_size_kb = lhist(arg1 / 1024, 0, 4096, 64);
}

/* mmap without PROT_EXEC = heap arena growth + file maps + data pages */
kprobe:ksys_mmap_pgoff
/ '"$BPF_FILTER"' && !(arg2 & 4) /
{
    @mmap_noexec_total = count();
    @mmap_noexec_by_comm[comm] = count();
    @mmap_noexec_bytes = sum(arg1);
}

/* mprotect with PROT_EXEC = RW->RX flip (VMA-split risk).
 * do_mprotect_pkey(start, len, prot, pkey) -> prot is arg2 */
kprobe:do_mprotect_pkey
/ '"$BPF_FILTER"' && (arg2 & 4) /
{
    @mprotect_exec_total = count();
    @mprotect_exec_by_comm[comm] = count();
    @mprotect_exec_bytes = sum(arg1);
}
kprobe:do_mprotect_pkey
/ '"$BPF_FILTER"' && !(arg2 & 4) /
{
    @mprotect_noexec_total = count();
    @mprotect_noexec_by_comm[comm] = count();
}

tracepoint:syscalls:sys_enter_munmap
/ '"$BPF_FILTER"' /
{
    @munmap_total = count();
    @munmap_by_comm[comm] = count();
}

/* libc heap growth (rare; PE-side heap goes via NtAllocateVirtualMemory) */
tracepoint:syscalls:sys_enter_brk
/ '"$BPF_FILTER"' /
{
    @brk_total = count();
    @brk_by_comm[comm] = count();
}

/* futex = CS contention + ntsync waits + heap CS */
tracepoint:syscalls:sys_enter_futex
/ '"$BPF_FILTER"' /
{
    @futex_total = count();
    @futex_by_comm[comm] = count();
    @futex_entry[tid] = nsecs;
}
tracepoint:syscalls:sys_exit_futex
/ '"$BPF_FILTER"' && @futex_entry[tid] /
{
    $dur = nsecs - @futex_entry[tid];
    @futex_wait_ns = lhist($dur, 0, 1000000, 50000);
    @futex_wait_max = max($dur);
    @futex_wait_by_comm_ns[comm] = sum($dur);
    delete(@futex_entry[tid]);
}

/* user-mode page faults (incl. JIT first-touch + heap first-touch) */
tracepoint:exceptions:page_fault_user
/ '"$BPF_FILTER"' /
{
    @pgflt_total = count();
    @pgflt_by_comm[comm] = count();
}

END
{
    clear(@futex_entry);
}
'

# --- pillar 1 perf stat (full counter set) ---------------------------------

PERF_EVENTS="cycles,instructions,branch-misses,\
iTLB-load-misses,L1-icache-load-misses,dTLB-load-misses,\
page-faults,minor-faults,major-faults,\
context-switches,cpu-migrations"

# --- launch all probes in parallel -----------------------------------------

echo "[probe] launching parallel probes..."

bpftrace -e "$BPF_PROG" > "$OUTDIR/bpf-output.txt" 2>&1 &
BPF_PID=$!

perf stat "${PERF_STAT_TARGET[@]}" -e "$PERF_EVENTS" -- sleep "$DURATION" \
    > "$OUTDIR/perf-stat.txt" 2>&1 &
PSTAT_PID=$!

if [[ "$DO_RECORD" -eq 1 ]]; then
    perf record -p "$TARGET_PID" --call-graph dwarf -F "$SAMPLE_HZ" \
        -o "$OUTDIR/perf.data" -- sleep "$DURATION" \
        > "$OUTDIR/perf-record.log" 2>&1 &
    PREC_PID=$!
fi

# Wait for the perf-stat sleep to complete (it's the canonical timer).
wait "$PSTAT_PID" || true
if [[ "$DO_RECORD" -eq 1 ]]; then
    wait "$PREC_PID" || true
fi

# bpftrace is in steady-state interval mode; stop it now.
kill -INT "$BPF_PID" 2>/dev/null || true
wait "$BPF_PID" 2>/dev/null || true

echo "[probe] window closed; collecting post-snapshot..."

# --- pillar 2 post-snapshot ------------------------------------------------

cp /proc/$TARGET_PID/maps   "$OUTDIR/maps-post.txt"   2>/dev/null || true
cp /proc/$TARGET_PID/smaps  "$OUTDIR/smaps-post.txt"  2>/dev/null || true
cp /proc/$TARGET_PID/status "$OUTDIR/status-post.txt" 2>/dev/null || true
filter_jit_regions "$OUTDIR/maps-post.txt" "$OUTDIR/jit-regions-post.txt"
snapshot_threads "$OUTDIR/threads-post.txt"

# Compute per-thread CPU-time delta and write top consumers.
awk -v pre="$OUTDIR/threads-pre.txt" -v post="$OUTDIR/threads-post.txt" '
BEGIN {
    while ((getline line < pre) > 0) {
        split(line, a)
        if (a[1] == "TID") continue
        u_pre[a[1]] = a[6]; s_pre[a[1]] = a[7]
    }
    close(pre)
    while ((getline line < post) > 0) {
        split(line, a)
        if (a[1] == "TID") { print line; continue }
        du = a[6] - u_pre[a[1]]; ds = a[7] - s_pre[a[1]]
        printf "%-7s  %-16s  %-6s  %-3s  %-12s  +%-9s +%-9s  (Δtot=%d ticks)\n", \
            a[1], a[2], a[3], a[4], a[5], du, ds, du+ds
        tot[a[1]] = du+ds; line_for[a[1]] = sprintf("%-7s  %-16s  %-6s  %-3s  %-12s  +%-9s +%-9s  Δtot=%d", a[1], a[2], a[3], a[4], a[5], du, ds, du+ds)
    }
    close(post)
}
END {
    n = 0
    for (k in tot) { keys[n++] = k }
    for (i = 0; i < n-1; i++) for (j = i+1; j < n; j++) {
        if (tot[keys[j]] > tot[keys[i]]) { t=keys[i]; keys[i]=keys[j]; keys[j]=t }
    }
    print ""
    print "==== top 15 threads by CPU-time delta ===="
    for (i = 0; i < (n<15?n:15); i++) print line_for[keys[i]]
}' > "$OUTDIR/threads-delta.txt"

# perf report (only if recorded)
if [[ "$DO_RECORD" -eq 1 ]] && [[ -s "$OUTDIR/perf.data" ]]; then
    perf report -i "$OUTDIR/perf.data" --stdio --no-children \
        --sort=dso,symbol --max-stack=10 \
        > "$OUTDIR/perf-report.txt" 2>&1 || true
fi

# --- summary ---------------------------------------------------------------

SUMMARY="$OUTDIR/summary.txt"
{
    echo "================ probe summary ================"
    echo "target          : PID=$TARGET_PID comm=$PROC_NAME"
    echo "window          : ${DURATION}s"
    echo "captured at     : $(date -Iseconds)"
    echo
    echo "----------- pillar 1: CPU shape ---------------"
    if [[ -s "$OUTDIR/perf-stat.txt" ]]; then
        awk '/insn per cycle|branch-misses|iTLB-load-misses|L1-icache-load-misses|dTLB-load-misses|page-faults|context-switches|cpu-migrations|cycles$|instructions$|seconds time elapsed/ {print "  " $0}' "$OUTDIR/perf-stat.txt"
    else
        echo "  (no perf-stat output)"
    fi
    echo
    echo "----------- pillar 2: JIT regions -------------"
    echo "  pre : $(awk '/rwxp anon mappings/{print}' "$OUTDIR/jit-regions-pre.txt"  | tr -d -)"
    echo "  post: $(awk '/rwxp anon mappings/{print}' "$OUTDIR/jit-regions-post.txt" | tr -d -)"
    echo "  AnonHugePages (RT should be 0):"
    grep -m1 "AnonHugePages" "$OUTDIR/status-post.txt" 2>/dev/null | sed 's/^/    /' || echo "    (n/a)"
    grep -E "VmRSS|VmData|VmPeak" "$OUTDIR/status-post.txt" 2>/dev/null | sed 's/^/  /'
    echo
    echo "----------- pillar 3: interface traffic -------"
    if [[ -s "$OUTDIR/bpf-output.txt" ]] && grep -q "^@" "$OUTDIR/bpf-output.txt"; then
        awk '/^@/{print "  " $0}' "$OUTDIR/bpf-output.txt"
    elif [[ -s "$OUTDIR/bpf-output.txt" ]]; then
        echo "  (bpftrace produced no @counters — see bpf-output.txt for errors)"
    else
        echo "  (no bpf output)"
    fi
    echo
    echo "----------- pillar 3.5: thread CPU-time top -"
    if [[ -s "$OUTDIR/threads-delta.txt" ]]; then
        sed -n '/top 15/,$p' "$OUTDIR/threads-delta.txt" | sed 's/^/  /'
    fi
    echo
    echo "----------- pillar 4: hot-region attribution --"
    if [[ "$DO_RECORD" -eq 1 ]] && [[ -s "$OUTDIR/perf-report.txt" ]]; then
        echo "  top 15 by self %:"
        awk '/^ *[0-9]+\.[0-9]+%/ {print "    " $0; n++; if (n>=15) exit}' "$OUTDIR/perf-report.txt"
        echo "  (full report: $OUTDIR/perf-report.txt)"
    else
        echo "  (--record not specified)"
    fi
    echo
    echo "================ end summary =================="
} > "$SUMMARY"

cat "$SUMMARY"
echo
echo "[probe] full outputs in: $OUTDIR"
