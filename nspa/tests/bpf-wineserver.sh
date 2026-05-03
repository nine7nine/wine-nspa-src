#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
#
# bpf-wineserver.sh — wineserver overall observability.
#
# Tracks the dispatcher hot path:
#   - call_req_handler / call_req_handler_shm — total RPC handler calls
#     (with and without latency histogram)
#   - read_request — request read time (the dispatcher's input side)
#   - send_reply — reply marshal+send time (output side)
#   - protocol error path (server_protocol_error / fatal_*) — count
#
# Useful for:
#   - "what's wineserver's per-call latency right now?"
#   - "is there a tail (p99 spike) under load?"
#   - "is the SHM dispatcher path hotter than the legacy socket path?"
#   - "are protocol errors firing (often masked from logs)?"
#
# Requires: bpftrace, root.
#
# Usage:
#   sudo ./bpf-wineserver.sh                # forever
#   sudo ./bpf-wineserver.sh -d 30         # 30s window
#   sudo WINESERVER=/path ./bpf-wineserver.sh

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

Observes overall wineserver activity: handler call rate, request/reply
latency, and protocol error path.
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
uprobe:'"$WINESERVER"':call_req_handler
{
    @handler_socket_start[tid] = nsecs;
    @handler_socket = count();
}

uretprobe:'"$WINESERVER"':call_req_handler
/@handler_socket_start[tid]/
{
    @handler_socket_lat_us = hist((nsecs - @handler_socket_start[tid]) / 1000);
    delete(@handler_socket_start[tid]);
}

uprobe:'"$WINESERVER"':call_req_handler_shm
{
    @handler_shm_start[tid] = nsecs;
    @handler_shm = count();
}

uretprobe:'"$WINESERVER"':call_req_handler_shm
/@handler_shm_start[tid]/
{
    @handler_shm_lat_us = hist((nsecs - @handler_shm_start[tid]) / 1000);
    delete(@handler_shm_start[tid]);
}

uprobe:'"$WINESERVER"':read_request
{
    @read_req = count();
}

uprobe:'"$WINESERVER"':send_reply
{
    @send_reply = count();
}

uprobe:'"$WINESERVER"':fatal_error,
uprobe:'"$WINESERVER"':fatal_protocol_error,
uprobe:'"$WINESERVER"':fatal_perror
{
    @fatal_errors = count();
    printf("FATAL hit: %s tid=%d\n", probe, tid);
}

interval:s:5
{
    printf("[5s tick] socket=%d shm=%d read=%d reply=%d fatal=%d\n",
           @handler_socket, @handler_shm, @read_req, @send_reply,
           @fatal_errors);
}

END
{
    printf("\n=== wineserver totals ===\n");
    print(@handler_socket);
    print(@handler_shm);
    print(@read_req);
    print(@send_reply);
    print(@fatal_errors);
    printf("\n=== handler latency, socket path (us) ===\n");
    print(@handler_socket_lat_us);
    printf("\n=== handler latency, SHM path (us) ===\n");
    print(@handler_shm_lat_us);
    clear(@handler_socket_start);
    clear(@handler_shm_start);
}
'

if [[ "$DURATION" -gt 0 ]]; then
    echo "[bpf-wineserver] running for ${DURATION}s..."
    timeout "$DURATION" bpftrace -e "$PROG" || true
else
    echo "[bpf-wineserver] running until ctrl-c..."
    bpftrace -e "$PROG"
fi
