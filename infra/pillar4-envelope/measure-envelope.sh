#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────
# ai-memory — Pillar-4 4.D per-module envelope (X) measurement harness (#1737).
#
# Measures ONE module's concurrent-agent KNEE against the per-module
# postgres+AGE+PgBouncer backbone shipped in 4.B (infra/pgbouncer/). The knee
# is the empirical X that replaces the GUESSED "1000 agents/module" design
# default (GOAL-EPIC-KICKOFF §104; operator-decision flag (b) §125).
#
# Method (capacity-honest — see infra/pgbouncer/README.md "Scale-out"):
#   - Bring up the 4.B pooled DB stack (postgres+AGE behind PgBouncer on 6432).
#   - schema-init + `serve` the FRESHLY-BUILT ai-memory binary against the
#     pooler (pm-v3.3 recompile-retest discipline — never a stale daemon).
#   - Ramp concurrency over CONCURRENCY_STEPS. At each step, fire a fixed
#     agent-shaped op mix (store / link / recall, incl. the AGE graph path)
#     for STEP_DURATION_SECS and record p50/p95/p99 latency + the
#     admission-control 503 shed-rate (ties into 4.A
#     AI_MEMORY_MAX_INFLIGHT_REQUESTS).
#   - The KNEE = the first step where p95 crosses P95_BUDGET_MS OR the shed
#     rate crosses SHED_RATE_KNEE. That step's concurrency is X.
#
# This harness is DOCKER-GATED (it needs the 4.B container stack), exactly like
# infra/pgbouncer/smoke-test.sh; it is NOT part of the 8-workflow CI gate. Run
# it on a Docker-capable host. The local dev socket is permission-denied.
#
#   cd infra/pillar4-envelope
#   POSTGRES_PASSWORD=secret ./measure-envelope.sh
#
# Exit 0 = a knee was found and printed (the measured X). Exit non-zero = the
# stack failed to come up or no knee was reached within CONCURRENCY_STEPS (X is
# then ">= the last step" — raise MAX concurrency and re-run).
# ─────────────────────────────────────────────────────────────────────────
set -euo pipefail

cd "$(dirname "$0")"

# ── Tunables (env-overridable) ───────────────────────────────────────────
PW="${POSTGRES_PASSWORD:-ai_memory_envelope}"
POOL_COMPOSE="../pgbouncer/docker-compose.yml"
PROJECT="ai-memory-4d-envelope"
DAEMON_PORT="${DAEMON_PORT:-9077}"
DAEMON_HOST="127.0.0.1"
POOLED_URL="postgres://ai_memory:${PW}@127.0.0.1:6432/ai_memory"
# Concurrency ramp. Geometric so the knee is bracketed without 1000 steps.
CONCURRENCY_STEPS="${CONCURRENCY_STEPS:-8 16 32 64 128 256 512 1024}"
STEP_DURATION_SECS="${STEP_DURATION_SECS:-20}"
# Knee thresholds. P95 budget mirrors the recall p95 budget the codebase
# defends elsewhere (35 ms hot-path) plus headroom for the write+AGE mix.
P95_BUDGET_MS="${P95_BUDGET_MS:-250}"
SHED_RATE_KNEE="${SHED_RATE_KNEE:-0.01}"   # 1% of requests shed with 503
# Admission cap: set so the daemon sheds rather than queues unboundedly under
# overload, making the knee observable as 503s (4.A). 0 disables (pure latency
# knee). Default leaves it generous so latency is the primary signal.
ADMISSION_CAP="${AI_MEMORY_MAX_INFLIGHT_REQUESTS:-0}"

RESULTS_DIR="${RESULTS_DIR:-./.local-runs/envelope-$$}"
mkdir -p "$RESULTS_DIR"
DAEMON_PID=""

cleanup() {
  [ -n "$DAEMON_PID" ] && kill "$DAEMON_PID" 2>/dev/null || true
  docker compose -p "$PROJECT" -f "$POOL_COMPOSE" down -v >/dev/null 2>&1 || true
  rm -f "../pgbouncer/.userlist.generated.txt"
}
trap cleanup EXIT

need() { command -v "$1" >/dev/null 2>&1 || { echo "FATAL: '$1' not found on PATH" >&2; exit 69; }; }
need docker
need curl
need cargo
need python3

# ── 1. Build the binary fresh (pm-v3.3) ──────────────────────────────────
echo "[1/5] building ai-memory (release, sal-postgres) ..."
( cd ../.. && cargo build --release --features sal-postgres --quiet )
BIN="$(cd ../.. && echo "$PWD/target/release/ai-memory")"
[ -x "$BIN" ] || { echo "FATAL: built binary not found at $BIN" >&2; exit 70; }

# ── 2. Bring up the 4.B pooled stack ─────────────────────────────────────
echo "[2/5] bringing up postgres+AGE + pgbouncer (4.B stack) ..."
# Render the pooler's md5 userlist from the password (same as 4.B smoke-test).
md5hash="$(printf '%s%s' "$PW" ai_memory | md5sum | cut -d' ' -f1)"
printf '"ai_memory" "md5%s"\n' "$md5hash" > "../pgbouncer/.userlist.generated.txt"
POSTGRES_PASSWORD="$PW" docker compose -p "$PROJECT" -f "$POOL_COMPOSE" up -d --wait

# ── 3. schema-init + serve THROUGH the pooler ────────────────────────────
echo "[3/5] schema-init + serve (admission cap=${ADMISSION_CAP}) through pgbouncer:6432 ..."
"$BIN" schema-init --store-url "$POOLED_URL"
AI_MEMORY_NO_CONFIG=1 AI_MEMORY_MAX_INFLIGHT_REQUESTS="$ADMISSION_CAP" \
  "$BIN" serve --store-url "$POOLED_URL" --host "$DAEMON_HOST" --port "$DAEMON_PORT" \
  >"$RESULTS_DIR/daemon.log" 2>&1 &
DAEMON_PID=$!
# Wait for readiness (/api/v1/health is admission-control EXEMPT — 4.A).
for _ in $(seq 1 30); do
  if curl -fsS "http://${DAEMON_HOST}:${DAEMON_PORT}/api/v1/health" >/dev/null 2>&1; then break; fi
  sleep 1
done
curl -fsS "http://${DAEMON_HOST}:${DAEMON_PORT}/api/v1/health" >/dev/null 2>&1 \
  || { echo "FATAL: daemon did not become healthy; see $RESULTS_DIR/daemon.log" >&2; exit 71; }

# ── 4. One worker = one simulated agent doing the op mix for the duration ─
# A worker loops: store -> link(to a prior id) -> recall, recording each
# request's HTTP code + wall-time (ms) into its own file. The aggregate over
# all concurrent workers at a step is the sample for that concurrency level.
BASE="http://${DAEMON_HOST}:${DAEMON_PORT}/api/v1"
now_ms() { python3 -c 'import time;print(int(time.time()*1000))'; }
worker() {
  local wid="$1" out="$2" deadline="$3" n=0 prev_id="" bodyf="${out}.body"
  while [ "$(date +%s)" -lt "$deadline" ]; do
    n=$((n+1))
    local agent="env-w${wid}" title="w${wid}-m${n}"
    local t0 code t1 cur_id
    # store (capture the created id so the link op has a real edge to write)
    t0=$(now_ms)
    code=$(curl -s -o "$bodyf" -w '%{http_code}' -X POST "$BASE/memories" \
      -H 'content-type: application/json' -H "x-agent-id: $agent" \
      -d "{\"title\":\"$title\",\"content\":\"envelope load $title\",\"namespace\":\"envelope\",\"tier\":\"short\"}" 2>/dev/null || echo "000")
    t1=$(now_ms)
    echo "store $code $((t1-t0))" >> "$out"
    cur_id=$(python3 -c 'import json,sys
try: print(json.load(open(sys.argv[1])).get("id",""))
except Exception: print("")' "$bodyf" 2>/dev/null || echo "")
    # link prev->cur — exercises the AGE graph write path (the 4.D throughput
    # bound; PgBouncer fixes fan-in, NOT AGE write concurrency).
    if [ -n "$prev_id" ] && [ -n "$cur_id" ]; then
      t0=$(now_ms)
      code=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$BASE/links" \
        -H 'content-type: application/json' -H "x-agent-id: $agent" \
        -d "{\"source_id\":\"$prev_id\",\"target_id\":\"$cur_id\",\"relation\":\"related_to\"}" 2>/dev/null || echo "000")
      t1=$(now_ms)
      echo "link $code $((t1-t0))" >> "$out"
    fi
    [ -n "$cur_id" ] && prev_id="$cur_id"
    # recall (read-path; FTS + reranker)
    t0=$(now_ms)
    code=$(curl -s -o /dev/null -w '%{http_code}' "$BASE/recall?q=envelope&namespace=envelope&limit=5" \
      -H "x-agent-id: $agent" 2>/dev/null || echo "000")
    t1=$(now_ms)
    echo "recall $code $((t1-t0))" >> "$out"
  done
  rm -f "$bodyf"
}

# ── 5. Ramp concurrency, find the knee ───────────────────────────────────
echo "[5/5] ramping concurrency ${CONCURRENCY_STEPS// /, } (${STEP_DURATION_SECS}s/step) ..."
printf '%-8s %8s %8s %8s %10s %8s\n' "CONC" "p50ms" "p95ms" "p99ms" "shed%" "reqs"
KNEE=""
for conc in $CONCURRENCY_STEPS; do
  step_out="$RESULTS_DIR/step-${conc}"
  rm -rf "$step_out"; mkdir -p "$step_out"
  deadline=$(( $(date +%s) + STEP_DURATION_SECS ))
  pids=()
  for w in $(seq 1 "$conc"); do
    worker "$w" "$step_out/w${w}.txt" "$deadline" &
    pids+=($!)
  done
  for p in "${pids[@]}"; do wait "$p" 2>/dev/null || true; done

  # Aggregate this step.
  read -r p50 p95 p99 shed reqs < <(cat "$step_out"/w*.txt 2>/dev/null | python3 -c '
import sys
lat=[]; shed=0; tot=0
for line in sys.stdin:
    parts=line.split()
    if len(parts)!=3: continue
    _,code,ms=parts
    tot+=1
    if code=="503": shed+=1
    try: lat.append(int(ms))
    except ValueError: pass
lat.sort()
def pct(p):
    if not lat: return 0
    i=min(len(lat)-1, int(p/100.0*len(lat)))
    return lat[i]
sr = (shed/tot) if tot else 0.0
print(pct(50), pct(95), pct(99), f"{sr:.4f}", tot)
')
  printf '%-8s %8s %8s %8s %10s %8s\n' "$conc" "$p50" "$p95" "$p99" "$shed" "$reqs"

  # Knee test.
  over_p95=$(python3 -c "print(1 if $p95 > $P95_BUDGET_MS else 0)")
  over_shed=$(python3 -c "print(1 if $shed > $SHED_RATE_KNEE else 0)")
  if [ "$over_p95" = "1" ] || [ "$over_shed" = "1" ]; then
    KNEE="$conc"
    echo "── KNEE at concurrency=${conc} (p95=${p95}ms vs budget ${P95_BUDGET_MS}ms; shed=${shed} vs ${SHED_RATE_KNEE}) ──"
    break
  fi
done

echo
if [ -n "$KNEE" ]; then
  echo "MEASURED ENVELOPE X = ${KNEE} concurrent agents/module (this host + this stack)."
  echo "Fold X back into the design default per #1737 (replaces the provisional 1000)."
  echo "Raw per-step samples: $RESULTS_DIR"
  exit 0
else
  last=$(printf '%s\n' $CONCURRENCY_STEPS | tail -1)
  echo "NO KNEE within CONCURRENCY_STEPS — X >= ${last}. Raise the ramp ceiling and re-run." >&2
  exit 72
fi
