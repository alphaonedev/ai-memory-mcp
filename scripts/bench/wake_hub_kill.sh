#!/usr/bin/env bash
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
#
# =============================================================================
# wake_hub_kill.sh -- #3473: SIGKILL the hub under load; lose no inbox row.
# =============================================================================
#
# The claim under test is the EPIC's central one, and it is a DATA-INTEGRITY
# claim rather than a performance one:
#
#   The hub carries no message bodies. The durable truth is the ai-memory
#   inbox row; the wake is a hint; a <=60 s backstop poll stays on; hub loss
#   degrades wake latency ONLY.
#
# So this drill kills the hub -- SIGKILL, no drain, no warning, mid-flight --
# while 128 agents are attached and a producer is committing notifies, and
# then proves two things:
#
#   1. ZERO ROWS LOST. Every notify the substrate ACKNOWLEDGED (`201` plus a
#      receipt id) is still readable through `GET /api/v1/inbox`. This is the
#      pass/fail gate. It is checked from the durable side, because that is
#      the only side that holds truth: a wake that never arrived costs
#      latency, a row that is not there would be loss.
#   2. THE DEGRADE IS THE DOCUMENTED ONE. After the kill, the attached
#      listeners keep reading on the bounded backstop instead of stopping.
#      The `hold` summary reports the signal reasons, so "the hub went away
#      and the backstop took over" is visible as a counter rather than
#      asserted in prose.
#
# SIGKILL, not SIGTERM, deliberately: `wake_hub`'s SIGTERM path is a bounded,
# tested drain, and a drill that used it would be testing the graceful path.
# What has to be survivable is the ungraceful one.
#
# The kill is by the PID THIS SCRIPT STARTED. Never `pkill -f` -- on a shared
# host a pattern kill can reach a process that is not ours, and this drill is
# not permitted to be the outage.
#
# Usage:
#   scripts/bench/wake_hub_kill.sh --binary target/release/ai-memory \
#       --run-dir <scratch>/3473 --store-url-src ~/.ai-memory-ci-fed-url \
#       --db-name ai_memory_f1_3473 --agents 128
#
# Exit 0 no row lost, 1 ROWS LOST, 3 INCONCLUSIVE, 70 setup failure.

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=/dev/null
source "${HERE}/wake_bench_env.sh"

AGENTS="${AGENTS:-128}"
# Rows per recipient must stay clear of the server's `limit` ceiling of 500 on
# `GET /api/v1/inbox`, which exposes no cursor: a reconciliation that read a
# truncated inbox could not tell "lost" from "past the page", and would be
# reported INCONCLUSIVE rather than PASS.
NOTIFIES="${NOTIFIES:-2560}"
PACE_MS="${PACE_MS:-20}"
KILL_AFTER="${KILL_AFTER:-20}"
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
    --agents) AGENTS="$2"; shift 2 ;;
    --notifies) NOTIFIES="$2"; shift 2 ;;
    --kill-after) KILL_AFTER="$2"; shift 2 ;;
    --port) WB_PORT="$2"; shift 2 ;;
    -h|--help) sed -n '2,50p' "$0"; exit 0 ;;
    *) wb_die "unknown argument $1" ;;
  esac
done

[ -n "$STORE_URL_SRC" ] || wb_die "--store-url-src is required"
[ -n "$DB_NAME" ] || wb_die "--db-name is required (NEVER ai_memory_test)"

wb_init
wb_prewarm_binary
wb_mint_tls
wb_write_store_url "$STORE_URL_SRC" "$DB_NAME"

RESULTS="${WB_RUN}/results/hub-kill"
mkdir -p "$RESULTS"
COMMITTED="${RESULTS}/committed.ndjson"
RUN_PID=""

cleanup_all() {
  if [ -n "$RUN_PID" ]; then kill -TERM "$RUN_PID" 2>/dev/null || true; fi
  wb_cleanup
}
trap cleanup_all EXIT

per_agent="$(( (NOTIFIES + AGENTS - 1) / AGENTS ))"
if [ "$per_agent" -ge 500 ]; then
  wb_die "${NOTIFIES} notifies over ${AGENTS} agents is ${per_agent} rows each, at or past the inbox read ceiling of 500; lower --notifies"
fi

wb_schema_init
wb_enroll_agents "$AGENTS"

wb_start_daemon "$WB_SOCKET"
wb_start_refresher "$AGENTS"
wb_start_hub

# ONE process both attaches the listeners and produces. Running a separate
# `hold` alongside it would open a SECOND session per agent — two sessions
# authenticated as the same identity, with the hub free to route a wake to
# either — so the drill would be measuring a topology no fleet runs.
#
# The listeners attach BEFORE the first notify (a wake minted for a recipient
# that had not yet attached is an absent wake, not a slow one), and the ready
# file is written at exactly that moment, so the kill below is timed from
# "load is in place" rather than from process start.
READY="${WB_RUN}/kill-run-ready.json"
rm -f "$READY"
wb_python run --arms hub --ready-file "$READY" \
  --base-url "$WB_BASE_URL" --tls-ca "$WB_TLS_CERT" \
  --hub-socket "$WB_SOCKET" --bundle-dir "$WB_BUNDLES" --hub-id "$WB_HUB_ID" \
  --sender "$WB_SENDER" --agents "$AGENTS" \
  --agent-template "ai:wake-bench-{i:04d}" \
  --notifies "$NOTIFIES" --pace-ms "$PACE_MS" --settle-secs 5 \
  --label "hub-kill-3473" --host-substrate "${WB_HOST_LABEL:-f1}" \
  --committed-out "$COMMITTED" \
  --out "${RESULTS}/latency-around-kill.json" &
RUN_PID=$!

i=0
while [ ! -s "$READY" ]; do
  kill -0 "$RUN_PID" 2>/dev/null || wb_die "the ${AGENTS} hub sessions never attached"
  i=$((i + 1)); [ "$i" -gt 300 ] && wb_die "timed out attaching ${AGENTS} sessions"
  sleep 1
done
wb_log "${AGENTS} sessions attached; producing for ${KILL_AFTER}s before the kill"

sleep "$KILL_AFTER"
if ! kill -0 "$RUN_PID" 2>/dev/null; then
  wb_die "the producer finished before the kill; raise --notifies or lower --kill-after"
fi
KILLED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
wb_kill_hub
wb_log "hub SIGKILLed at ${KILLED_AT}; the producer keeps committing"

# The producer runs to completion THROUGH the outage. Its notifies must keep
# succeeding: a wake the sink cannot push is a dropped HINT and must never be
# backpressure on the notify path.
set +e
wait "$RUN_PID"
RUN_RC=$?
set -e
RUN_PID=""
[ "$RUN_RC" -eq 0 ] || wb_die "the producer failed (rc=${RUN_RC}) during the outage; notifies must survive a dead hub"

# --- the gate: no row lost -------------------------------------------------
set +e
wb_python reconcile --base-url "$WB_BASE_URL" --tls-ca "$WB_TLS_CERT" \
  --committed "$COMMITTED" --label "hub-kill-3473" \
  --out "${RESULTS}/reconcile.json"
RC=$?
set -e

python3 - "$RESULTS" "$KILLED_AT" "$AGENTS" <<'PY'
import json
import pathlib
import sys

results = pathlib.Path(sys.argv[1])
killed_at, agents = sys.argv[2], int(sys.argv[3])
rec = json.loads((results / "reconcile.json").read_text(encoding="utf-8"))
lat = json.loads((results / "latency-around-kill.json").read_text(encoding="utf-8"))
point = lat["points"][0] if lat.get("points") else {}
hub = (point.get("arms") or {}).get("hub", {})
# The run's own hub arm carries the listener bookkeeping, so the degrade is
# read from the SAME sessions that carried the wakes.
reasons = hub.get("signal_reasons") or {}

summary = {
    "meta": {
        "issue": 3473,
        "producer": "scripts/bench/wake_hub_kill.sh",
        "agents": agents,
        "hub_sigkilled_at_utc": killed_at,
        "note": ("The pass/fail gate is row loss, judged from the durable side. "
                 "Wake latency after the kill is EXPECTED to degrade to the "
                 "<=60 s backstop poll: `missing` here means 'no hint arrived', "
                 "which is the documented degrade, not a defect."),
    },
    "verdict": rec["verdict"],
    "committed_rows": rec["committed_rows"],
    "missing_rows": rec["missing_rows"],
    "truncated_inboxes": rec["truncated_inboxes"],
    "wake_hints": {
        "offered": hub.get("offered"),
        "delivered": hub.get("delivered"),
        "missing_after_kill": hub.get("missing"),
        "p50_ms": hub.get("p50_ms"),
        "p99_ms": hub.get("p99_ms"),
    },
    "listener_signal_reasons": reasons,
}
(results / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
print(json.dumps(summary, indent=2))
PY

case "$RC" in
  0) wb_log "VERDICT: PASS -- every committed inbox row survived the hub SIGKILL" ;;
  1) wb_log "VERDICT: ROWS LOST -- this is a data-integrity failure" ;;
  3) wb_log "VERDICT: INCONCLUSIVE -- an inbox came back at the read ceiling" ;;
  *) wb_log "VERDICT: reconcile failed (rc=${RC})" ;;
esac
exit "$RC"
