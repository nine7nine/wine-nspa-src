#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
#
# bpf-gamma.sh — observe NSPA gamma channel dispatcher activity.
#
# The gamma dispatcher (server/nspa/shmem_channel.c::channel_dispatcher)
# is the only NSPA path that uses the kernel ntsync_channel primitive.
# It batches RPC requests through shmem rings + handles delivery.
#
# This probes:
#   - dispatch_channel_entry (per-entry handler) — count + latency hist
#   - channel_dispatcher (the loop body) — overall iteration count
#   - nspa_shmem_channel_reply — reply path latency
#   - nspa_shmem_channel_register_thread / _deregister_thread — churn
#
# Useful for:
#   - "is the dispatcher hot or idle?"
#   - "what's the per-entry processing latency under load?"
#   - "is thread churn meaningful (Ableton restart pattern)?"
#
# Requires: bpftrace, root.
#
# Usage:
#   sudo ./bpf-gamma.sh                # forever
#   sudo ./bpf-gamma.sh -d 30         # 30s window
#   sudo WINESERVER=/path ./bpf-gamma.sh

set -u

WINESERVER=${WINESERVER:-/usr/bin/wineserver}
DURATION=${DURATION:-0}

while getopts "d:hw:" opt; do
    case "$opt" in
        d) DURATION=$OPTARG ;;
        w) WINESERVER=$OPTARG ;;
        h|*)
            cat <<EOF
usage: sudo $(basename "$0") [-d SECONDS] [-w /path/to/wineserver]

Observes the NSPA gamma channel dispatcher in wineserver.
Tracks per-entry latency, dispatch loop iterations, and thread
register/deregister churn.
EOF
            exit 2 ;;
    esac
done

if [[ $EUID -ne 0 ]]; then
    echo "ERROR: must run as root" >&2; exit 2
fi
if ! command -v bpftrace >/dev/null 2>&1; then
    echo "ERROR: bpftrace not installed" >&2; exit 2
fi
if [[ ! -x "$WINESERVER" ]]; then
    echo "ERROR: wineserver missing: $WINESERVER" >&2; exit 2
fi

PROG='
uprobe:'"$WINESERVER"':dispatch_channel_entry
{
    @entry_start[tid] = nsecs;
    @entries = count();
}

uretprobe:'"$WINESERVER"':dispatch_channel_entry
/@entry_start[tid]/
{
    @entry_lat_us = hist((nsecs - @entry_start[tid]) / 1000);
    delete(@entry_start[tid]);
}

uprobe:'"$WINESERVER"':channel_dispatcher
{
    @dispatch_loop_invocations = count();
}

uprobe:'"$WINESERVER"':nspa_shmem_channel_reply
{
    @reply_start[tid] = nsecs;
    @replies = count();
}

uretprobe:'"$WINESERVER"':nspa_shmem_channel_reply
/@reply_start[tid]/
{
    @reply_lat_us = hist((nsecs - @reply_start[tid]) / 1000);
    delete(@reply_start[tid]);
}

uprobe:'"$WINESERVER"':nspa_shmem_channel_register_thread
{
    @register_thread = count();
}

uprobe:'"$WINESERVER"':nspa_shmem_channel_deregister_thread
{
    @deregister_thread = count();
}

interval:s:5
{
    printf("[5s tick] entries=%d replies=%d reg=%d dereg=%d\n",
           @entries, @replies, @register_thread, @deregister_thread);
}

END
{
    printf("\n=== gamma dispatcher ===\n");
    print(@entries);
    print(@replies);
    print(@dispatch_loop_invocations);
    print(@register_thread);
    print(@deregister_thread);
    printf("\n=== entry latency (us) ===\n");
    print(@entry_lat_us);
    printf("\n=== reply latency (us) ===\n");
    print(@reply_lat_us);
    clear(@entry_start);
    clear(@reply_start);
}
'

if [[ "$DURATION" -gt 0 ]]; then
    echo "[bpf-gamma] running for ${DURATION}s..."
    timeout "$DURATION" bpftrace -e "$PROG" || true
else
    echo "[bpf-gamma] running until ctrl-c..."
    bpftrace -e "$PROG"
fi
