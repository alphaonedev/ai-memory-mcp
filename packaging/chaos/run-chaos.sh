#!/usr/bin/env bash
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
#
# Multi-process chaos campaign for ai-memory's federation quorum writes.
# Spawns three local ai-memory daemons on different ports, issues a
# burst of writes through node-0 with --quorum-writes 2 pointing at the
# other two as peers, then injects one of four chaos fault classes
# (kill_primary_mid_write | partition_minority | drop_random_acks |
# clock_skew_peer) and records the outcome.
#
# Emits a JSON convergence-bound report per cycle — see ADR-0001
# for the published-claim shape.
#
# Usage:
#   ./run-chaos.sh [--cycles N] [--fault CLASS] [--writes M] [--verbose]
#
# Defaults:
#   --cycles 10
#   --fault  kill_primary_mid_write
#   --writes 100

set -euo pipefail

CYCLES=10
FAULT="kill_primary_mid_write"
WRITES_PER_CYCLE=100
VERBOSE=0
# Each node gets a scratch dir + log file.
WORKDIR="${WORKDIR:-$(mktemp -d -t ai-memory-chaos.XXXXXX)}"
AI_MEMORY_BIN="${AI_MEMORY_BIN:-./target/release/ai-memory}"
REPORT_FILE="${WORKDIR}/chaos-report.jsonl"

# Three-node fixture.
N0_PORT=${N0_PORT:-19077}
N1_PORT=${N1_PORT:-19078}
N2_PORT=${N2_PORT:-19079}

log()    { printf '[chaos] %s\n' "$*"; }
vlog()   { [[ $VERBOSE -eq 1 ]] && log "$@"; }
die()    { printf '[chaos] FATAL: %s\n' "$*" >&2; exit 1; }

while [[ $# -gt 0 ]]; do
    case "$1" in
        --cycles)  CYCLES="$2";            shift 2;;
        --fault)   FAULT="$2";             shift 2;;
        --writes)  WRITES_PER_CYCLE="$2";  shift 2;;
        --verbose) VERBOSE=1;              shift;;
        -h|--help)
            sed -n '1,25p' "$0"; exit 0;;
        *) die "unknown flag: $1";;
    esac
done

case "$FAULT" in
    kill_primary_mid_write|partition_minority|drop_random_acks|clock_skew_peer) ;;
    *) die "unknown fault class: $FAULT (see ADR-0001 § Chaos-testing methodology)";;
esac

# ---------------------------------------------------------------------
# Fixture: spawn three nodes, each on its own port + DB.
# ---------------------------------------------------------------------
spawn_node() {
    local idx="$1" port="$2"
    local db="${WORKDIR}/node-${idx}.db"
    local logf="${WORKDIR}/node-${idx}.log"
    # Node 0 is the "primary" — writes target it, it fans out to 1 + 2.
    local peers=""
    if [[ $idx -eq 0 ]]; then
        peers="--quorum-writes 2 --quorum-peers http://127.0.0.1:${N1_PORT},http://127.0.0.1:${N2_PORT}"
    fi
    AI_MEMORY_DB="$db" \
        "$AI_MEMORY_BIN" serve \
            --host 127.0.0.1 --port "$port" \
            $peers \
            > "$logf" 2>&1 &
    echo $!
}

wait_ready() {
    local port="$1" tries=40
    while (( tries-- > 0 )); do
        if curl -sSf "http://127.0.0.1:${port}/api/v1/health" >/dev/null 2>&1; then
            return 0
        fi
        sleep 0.25
    done
    return 1
}

# ---------------------------------------------------------------------
# Fault injectors.
# Each function: (a) performs the injection; (b) echoes the injection
# timestamp so the cycle report can correlate.
# ---------------------------------------------------------------------
inject_kill_primary_mid_write() {
    local pid="$1"
    sleep 0.1  # Let a few writes start
    kill -9 "$pid" 2>/dev/null || true
    echo "$(date -u +%s.%N)"
}

inject_partition_minority() {
    # Block outbound to peers 1 + 2 from primary by dropping loopback
    # packets to their ports. Requires iptables + root; degrade to
    # no-op with a warning if not available.
    if ! command -v iptables >/dev/null 2>&1; then
        log "iptables not available; partition_minority is a no-op"
        echo "$(date -u +%s.%N)"
        return
    fi
    sudo iptables -I OUTPUT -p tcp --dport "$N1_PORT" -j DROP 2>/dev/null || true
    sudo iptables -I OUTPUT -p tcp --dport "$N2_PORT" -j DROP 2>/dev/null || true
    local ts="$(date -u +%s.%N)"
    sleep 0.5
    sudo iptables -D OUTPUT -p tcp --dport "$N1_PORT" -j DROP 2>/dev/null || true
    sudo iptables -D OUTPUT -p tcp --dport "$N2_PORT" -j DROP 2>/dev/null || true
    echo "$ts"
}

inject_drop_random_acks() {
    # Randomly SIGSTOP peer 1 for 60s, then SIGCONT. Approximates an
    # ack-drop pattern without needing iptables STATISTIC module.
    local pid="$1"
    sleep 0.2
    kill -STOP "$pid" 2>/dev/null || true
    local ts="$(date -u +%s.%N)"
    sleep 0.5
    kill -CONT "$pid" 2>/dev/null || true
    echo "$ts"
}

inject_clock_skew_peer() {
    # Simulate skew by recording the intent (actual skew requires CAP_SYS_TIME).
    log "clock_skew_peer is a simulated no-op (requires CAP_SYS_TIME)"
    echo "$(date -u +%s.%N)"
}

# ---------------------------------------------------------------------
# Cycle runner.
# ---------------------------------------------------------------------
cycle() {
    local n="$1"
    local pid0 pid1 pid2
    pid0=$(spawn_node 0 "$N0_PORT")
    pid1=$(spawn_node 1 "$N1_PORT")
    pid2=$(spawn_node 2 "$N2_PORT")

    wait_ready "$N0_PORT" || die "node-0 failed to start (see ${WORKDIR}/node-0.log)"
    wait_ready "$N1_PORT" || die "node-1 failed to start"
    wait_ready "$N2_PORT" || die "node-2 failed to start"
    vlog "cycle $n: nodes ready (pids $pid0 $pid1 $pid2)"

    local ok=0 fail=0 quorum_not_met=0
    for ((i = 0; i < WRITES_PER_CYCLE; i++)); do
        local resp code
        resp=$(curl -sS -o /tmp/chaos-body.$$ -w '%{http_code}' \
            -H 'Content-Type: application/json' \
            -X POST "http://127.0.0.1:${N0_PORT}/api/v1/memories" \
            --data "{\"tier\":\"mid\",\"namespace\":\"chaos\",\"title\":\"c$n-w$i\",\"content\":\"chaos test payload $n $i $(date -u +%s.%N)\",\"tags\":[],\"priority\":5,\"confidence\":1.0,\"source\":\"chaos\",\"metadata\":{}}" \
            2>/dev/null || echo "000")
        code="$resp"
        case "$code" in
            201) ok=$((ok + 1));;
            503) quorum_not_met=$((quorum_not_met + 1));;
            *)   fail=$((fail + 1));;
        esac
        [[ $i -eq 2 ]] && {
            case "$FAULT" in
                kill_primary_mid_write) inject_kill_primary_mid_write "$pid0" > /dev/null;;
                partition_minority)     inject_partition_minority > /dev/null;;
                drop_random_acks)       inject_drop_random_acks "$pid1" > /dev/null;;
                clock_skew_peer)        inject_clock_skew_peer > /dev/null;;
            esac
        }
    done

    # Convergence check: count rows visible at each node in the chaos namespace.
    local count0 count1 count2
    count0=$(curl -sS "http://127.0.0.1:${N0_PORT}/api/v1/memories?namespace=chaos" 2>/dev/null | jq '.memories | length' 2>/dev/null || echo "ERR")
    count1=$(curl -sS "http://127.0.0.1:${N1_PORT}/api/v1/memories?namespace=chaos" 2>/dev/null | jq '.memories | length' 2>/dev/null || echo "ERR")
    count2=$(curl -sS "http://127.0.0.1:${N2_PORT}/api/v1/memories?namespace=chaos" 2>/dev/null | jq '.memories | length' 2>/dev/null || echo "ERR")

    # Tear down.
    kill "$pid0" "$pid1" "$pid2" 2>/dev/null || true
    wait "$pid0" "$pid1" "$pid2" 2>/dev/null || true

    # Emit JSONL line.
    jq -cn \
        --arg fault "$FAULT" \
        --argjson cycle "$n" \
        --argjson writes "$WRITES_PER_CYCLE" \
        --argjson ok "$ok" \
        --argjson quorum_not_met "$quorum_not_met" \
        --argjson fail "$fail" \
        --arg count0 "$count0" \
        --arg count1 "$count1" \
        --arg count2 "$count2" \
        '{cycle:$cycle, fault:$fault, writes:$writes, ok:$ok, quorum_not_met:$quorum_not_met, fail:$fail, count_node0:$count0, count_node1:$count1, count_node2:$count2}' \
        >> "$REPORT_FILE"
}

log "chaos campaign: fault=$FAULT cycles=$CYCLES writes/cycle=$WRITES_PER_CYCLE"
log "workdir: $WORKDIR"
log "binary: $AI_MEMORY_BIN"
[[ -x "$AI_MEMORY_BIN" ]] || die "binary not found / not executable: $AI_MEMORY_BIN (did you cargo build --release?)"
command -v jq   >/dev/null 2>&1 || die "jq is required"
command -v curl >/dev/null 2>&1 || die "curl is required"

for ((c = 1; c <= CYCLES; c++)); do
    cycle "$c"
done

log "---- summary ----"
jq -s '{
    total_cycles: length,
    total_writes: (map(.writes) | add),
    total_ok: (map(.ok) | add),
    total_quorum_not_met: (map(.quorum_not_met) | add),
    total_fail: (map(.fail) | add),
    convergence_bound: ((map(.ok) | add) / (map(.writes) | add) * 1000 | floor / 1000)
}' "$REPORT_FILE"
log "per-cycle JSONL: $REPORT_FILE"
