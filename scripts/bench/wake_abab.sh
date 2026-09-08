#!/usr/bin/env bash
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
#
# =============================================================================
# wake_abab.sh -- #3473 read/write-path A-B-A-B, wake plane OFF vs ON.
# =============================================================================
#
# The question
# ------------
# Does turning the wake plane on cost the substrate's ordinary read and write
# paths anything? The EPIC's contract says it must not: everything on the bus
# pump is an encode plus a non-blocking enqueue -- no `.await`, no lock held
# across one, no I/O -- and the durable row has already committed before a wake
# fires. This script is that claim's producer.
#
# The design
# ----------
#   A = wake plane OFF. The daemon's config carries NO `[wake_hub]` block, so
#       it starts no forwarder, loads no producer identity and opens no socket.
#       No hub process runs and no agent is attached. This is the shipped
#       default posture, and it is what "off" has to mean -- stopping the hub
#       while leaving the sink configured would measure a reconnect ladder.
#   B = wake plane ON. `[wake_hub].sink_socket` is set, `ai-memory wake-hub`
#       is running, and N agents are ATTACHED to it for the whole leg. An idle
#       hub would answer a question nobody asked: the cost the plane can impose
#       is the cost of fanning a wake out to attached recipients.
#
# A-B-A-B, not A-B, because a single pair cannot tell a real effect from host
# drift. Running A1 B1 A2 B2 and comparing mean(B) against mean(A) cancels any
# monotone drift across the run, and the A1-vs-A2 spread MEASURES the
# instrument's own noise on this host instead of assuming it.
#
# The threshold, stated explicitly
# --------------------------------
#   * PASS         mean(B) is within THRESHOLD_PCT of mean(A), for every op at
#                  every agent count.
#   * REGRESSION   mean(B) is more than THRESHOLD_PCT below mean(A). Exit 1.
#   * INCONCLUSIVE the A1-vs-A2 spread is ITSELF larger than THRESHOLD_PCT.
#                  Exit 3.
#
# The third outcome is the honest one and it is why this is worth running. A
# comparison whose noise floor exceeds the effect it claims to resolve has not
# shown "no regression"; it has shown that this host, on this day, could not
# answer the question. Reporting PASS from such a run would be manufacturing a
# guarantee. The remedy is a longer `--duration`, a quieter host, or both.
#
# 5 % by default because that is the order of the run-to-run spread these
# host-process producers show on a 10-core shared workstation, and because the
# effect being looked for -- one encode plus one `try_send` per committed
# notify, on the commit path only -- should be far below it. Set
# `--threshold-pct` deliberately if you change it; do not tune it until it
# passes.
#
# Usage:
#   scripts/bench/wake_abab.sh --binary target/release/ai-memory \
#       --run-dir <scratch>/3473 --store-url-src ~/.ai-memory-ci-fed-url \
#       --db-name ai_memory_f1_3473 --agent-counts "16 64 128 256"
#
# Exit 0 PASS, 1 REGRESSION, 3 INCONCLUSIVE, 70 setup failure.

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=/dev/null
source "${HERE}/wake_bench_env.sh"

AGENT_COUNTS="${AGENT_COUNTS:-16 64 128 256}"
DURATION="${DURATION:-30}"
CONCURRENCY="${CONCURRENCY:-8}"
COOLDOWN="${COOLDOWN:-5}"
THRESHOLD_PCT="${THRESHOLD_PCT:-5}"
OPS="${OPS:-notify inbox}"
STORE_URL_SRC=""
DB_NAME=""

# WB_* are consumed by the sourced wake_bench_env.sh, not by this file.
# shellcheck disable=SC2034
while [ $# -gt 0 ]; do
  case "$1" in
    --binary) WB_BINARY="$2"; shift 2 ;;
    --run-dir) WB_RUN="$2"; shift 2 ;;
    --store-url-src) STORE_URL_SRC="$2"; shift 2 ;;
    --db-name) DB_NAME="$2"; shift 2 ;;
    --agent-counts) AGENT_COUNTS="$2"; shift 2 ;;
    --duration) DURATION="$2"; shift 2 ;;
    --concurrency) CONCURRENCY="$2"; shift 2 ;;
    --threshold-pct) THRESHOLD_PCT="$2"; shift 2 ;;
    --ops) OPS="$2"; shift 2 ;;
    --port) WB_PORT="$2"; shift 2 ;;
    -h|--help) sed -n '2,60p' "$0"; exit 0 ;;
    *) wb_die "unknown argument $1" ;;
  esac
done

[ -n "$STORE_URL_SRC" ] || wb_die "--store-url-src is required"
[ -n "$DB_NAME" ] || wb_die "--db-name is required (NEVER ai_memory_test)"

wb_init
wb_prewarm_binary
wb_mint_tls
wb_write_store_url "$STORE_URL_SRC" "$DB_NAME"

RESULTS="${WB_RUN}/results/abab"
mkdir -p "$RESULTS"
HOLD_PID=""

cleanup_all() {
  if [ -n "$HOLD_PID" ]; then kill -TERM "$HOLD_PID" 2>/dev/null || true; fi
  wb_cleanup
}
trap cleanup_all EXIT

MAX_AGENTS=0
for n in $AGENT_COUNTS; do [ "$n" -gt "$MAX_AGENTS" ] && MAX_AGENTS="$n"; done

# Both of these run ONCE, before any timed leg. Minting 256 delegations or
# bootstrapping a schema inside a measured window would report a setup cost as
# a substrate latency.
wb_schema_init
wb_enroll_agents "$MAX_AGENTS"

# run_rungs <leg> <agents>
run_rungs() {
  local leg="$1" agents="$2" op
  for op in $OPS; do
    wb_python rate --op "$op" \
      --base-url "$WB_BASE_URL" --tls-ca "$WB_TLS_CERT" \
      --sender "$WB_SENDER" --agents "$agents" \
      --agent-template "ai:wake-bench-{i:04d}" \
      --concurrency "$CONCURRENCY" --duration "$DURATION" \
      --leg "$leg" --label "abab-n${agents}" --host-substrate "${WB_HOST_LABEL:-f1}" \
      --out "${RESULTS}/n${agents}-${leg}-${op}.json" \
      || wb_die "leg ${leg} op ${op} failed"
  done
}

leg_a() {
  local leg="$1" agents="$2"
  wb_log "=== n=${agents} leg ${leg}: wake plane OFF ==="
  wb_start_daemon ""
  run_rungs "$leg" "$agents"
  wb_stop_daemon
  sleep "$COOLDOWN"
}

leg_b() {
  local leg="$1" agents="$2" ready="${WB_RUN}/hold-ready.json"
  wb_log "=== n=${agents} leg ${leg}: wake plane ON, ${agents} attached ==="
  rm -f "$ready"
  wb_start_daemon "$WB_SOCKET"
  wb_start_refresher "$agents"
  wb_start_hub
  wb_python hold --agents "$agents" --arms hub \
    --base-url "$WB_BASE_URL" --tls-ca "$WB_TLS_CERT" \
    --hub-socket "$WB_SOCKET" --bundle-dir "$WB_BUNDLES" --hub-id "$WB_HUB_ID" \
    --agent-template "ai:wake-bench-{i:04d}" --ready-file "$ready" \
    --max-secs 3600 --out "${RESULTS}/n${agents}-${leg}-hold.json" &
  HOLD_PID=$!
  local i=0
  while [ ! -s "$ready" ]; do
    kill -0 "$HOLD_PID" 2>/dev/null || wb_die "the ${agents} hub sessions never attached"
    i=$((i + 1)); [ "$i" -gt 300 ] && wb_die "timed out attaching ${agents} hub sessions"
    sleep 1
  done
  wb_log "  ${agents} sessions attached"
  run_rungs "$leg" "$agents"
  kill -TERM "$HOLD_PID" 2>/dev/null || true
  wait "$HOLD_PID" 2>/dev/null || true
  HOLD_PID=""
  wb_stop_hub
  wb_stop_refresher
  wb_stop_daemon
  sleep "$COOLDOWN"
}

for n in $AGENT_COUNTS; do
  leg_a A1 "$n"
  leg_b B1 "$n"
  leg_a A2 "$n"
  leg_b B2 "$n"
done

# --- verdict ---------------------------------------------------------------
python3 - "$RESULTS" "$THRESHOLD_PCT" "$AGENT_COUNTS" "$OPS" <<'PY'
import json
import pathlib
import sys

results = pathlib.Path(sys.argv[1])
threshold = float(sys.argv[2])
counts = [int(x) for x in sys.argv[3].split()]
ops = sys.argv[4].split()


def ops_per_s(n, leg, op):
    path = results / f"n{n}-{leg}-{op}.json"
    return json.loads(path.read_text(encoding="utf-8"))["point"]["total_ops_per_s"]


rows = []
verdict = "PASS"
for n in counts:
    for op in ops:
        a1, a2 = ops_per_s(n, "A1", op), ops_per_s(n, "A2", op)
        b1, b2 = ops_per_s(n, "B1", op), ops_per_s(n, "B2", op)
        a, b = (a1 + a2) / 2, (b1 + b2) / 2
        # The A-vs-A spread is the instrument's OWN noise on this host, and it
        # is measured rather than assumed. A claim finer than it is not a
        # claim.
        noise = abs(a1 - a2) / a * 100 if a else float("inf")
        delta = (b - a) / a * 100 if a else float("-inf")
        row = {"agents": n, "op": op, "a1": a1, "a2": a2, "b1": b1, "b2": b2,
               "a_mean": round(a, 4), "b_mean": round(b, 4),
               "delta_pct": round(delta, 3), "noise_pct": round(noise, 3)}
        if delta < -threshold:
            row["verdict"] = "REGRESSION"
            verdict = "REGRESSION"
        elif noise > threshold:
            row["verdict"] = "INCONCLUSIVE"
            if verdict != "REGRESSION":
                verdict = "INCONCLUSIVE"
        else:
            row["verdict"] = "PASS"
        rows.append(row)

out = {
    "meta": {
        "issue": 3473,
        "producer": "scripts/bench/wake_abab.sh",
        "threshold_pct": threshold,
        "design": ("A = wake plane OFF (no [wake_hub] block, no hub, nobody attached); "
                   "B = wake plane ON with N agents attached for the whole leg. "
                   "A-B-A-B cancels monotone host drift; the A1-vs-A2 spread measures "
                   "this host's own noise floor."),
        "inconclusive_rule": ("A run whose measured noise floor exceeds the threshold "
                              "has NOT shown 'no regression'; reporting PASS from one "
                              "would manufacture the guarantee. Re-run longer or "
                              "quieter."),
    },
    "verdict": verdict,
    "rows": rows,
}
(results / "verdict.json").write_text(json.dumps(out, indent=2), encoding="utf-8")

head = f"{'agents':>7} {'op':<7} {'A ops/s':>10} {'B ops/s':>10} {'delta%':>8} {'noise%':>8}  verdict"
print(head)
print("-" * len(head))
for row in rows:
    print(f"{row['agents']:>7} {row['op']:<7} {row['a_mean']:>10.3f} "
          f"{row['b_mean']:>10.3f} {row['delta_pct']:>8.2f} "
          f"{row['noise_pct']:>8.2f}  {row['verdict']}")
print(f"\nA-B-A-B verdict: {verdict} (threshold {threshold} %)")
sys.exit({"PASS": 0, "REGRESSION": 1, "INCONCLUSIVE": 3}[verdict])
PY
