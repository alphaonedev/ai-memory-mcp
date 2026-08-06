#!/usr/bin/env bash
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
# ---------------------------------------------------------------------------
# ai-memory -- #2438 distributed capacity ramp driver.
#
# Sibling of measure-envelope.sh. Where measure-envelope.sh finds ONE module's
# knee on a Docker host, THIS script drives the SAME op-mix instrument from the
# #2438 5-droplet load-generator cluster (infra/do-hive, measurement.tfvars),
# sweeping droplet-counts N_d in {1,2,3,5} x an internal per-droplet concurrency
# ramp so the cluster offers 8..512+ concurrent workers against ONE substrate
# module -- enough to drive it PAST its knee. It collects per-op ops/s at each
# offered-concurrency level and emits a machine-readable results JSON that
# usl-fit.py consumes.
#
# It uses the IDENTICAL worker loop + aggregation reducer that the droplets got
# from cloud-init-loadgen.yaml.tpl (which mirrors measure-envelope.sh), so the
# numbers are directly comparable to the already-populated envelope cells.
#
# SAFETY: this script NEVER calls terraform and NEVER spawns droplets. It only
# SSHes into droplets the operator already provisioned via the money-gated
# spawn.sh. Spend is untouched. It is safe to merge and safe to run against an
# empty LOADGEN_IPS (it prints how to derive the IPs and exits non-zero).
#
# Inputs (env):
#   SUBSTRATE_IP      private VPC IP of the substrate droplet (:9077). REQUIRED.
#   LOADGEN_IPS       space-separated PUBLIC IPs of the 5 loadgen droplets. REQUIRED.
#   SSH_USER          ssh user on the loadgen droplets (default: root).
#   SSH_OPTS          extra ssh options (default: batch, no host-key prompt).
#   DROPLET_COUNTS    N_d sweep (default: "1 2 3 5").
#   CONCURRENCY_STEPS per-droplet worker ramp (default: "8 16 32 64").
#   STEP_DURATION_SECS seconds of load per step (default: 20).
#   BACKEND           label recorded in the results meta (default: postgres).
#   CORPUS_SCALE      seed floor recorded in meta (default: 10000).
#   SUBSTRATE_HOST    host label recorded in meta (default: the substrate slug).
#   SEED              1 to seed CORPUS_SCALE rows before the ramp (default: 0).
#   RESULTS_JSON      output path (default: ./.local-runs/capacity-<ts>.json).
#
# Derive the IPs from a spawned cluster:
#   cd infra/do-hive && terraform output -json > outs.json
#   export SUBSTRATE_IP=$(jq -r .memory_private_ip.value outs.json)
#   export LOADGEN_IPS=$(jq -r '.agent_ips.value | join(" ")' outs.json)
#
# Then:
#   infra/pillar4-envelope/measure-capacity-ramp.sh
#   infra/pillar4-envelope/usl-fit.py <RESULTS_JSON>
#
#   measure-capacity-ramp.sh --self-test   # validate the JSON contract, no droplets
# ---------------------------------------------------------------------------
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RESULTS_ROOT="${HERE}/.local-runs"

need() { command -v "$1" >/dev/null 2>&1 || { echo "FATAL: '$1' not found on PATH" >&2; exit 69; }; }

# ---- Aggregate N_d per-droplet JSON blobs (a JSON array on stdin) into one
# ---- point. offered_concurrency and n_d are passed as env. Same reducer shape
# ---- as run-workers.sh / measure-envelope.sh; sums counts for exact ops/s.
merge_droplets_py() {
python3 -c '
import sys, os, json
offered = int(os.environ["OFFERED"])
n_d = int(os.environ["N_D"])
workers = int(os.environ["WPER"])
blobs = json.load(sys.stdin)   # list of per-droplet JSON objects
wall = 0.0
reqs = 0
shed = 0
agg = {}
for b in blobs:
    wall = max(wall, float(b.get("wall_secs", 0)) or 0.0)
    reqs += int(b.get("reqs", 0))
    shed += int(b.get("shed", 0))
    for op, d in (b.get("ops", {}) or {}).items():
        a = agg.setdefault(op, {"count": 0, "p50": 0, "p95": 0, "p99": 0})
        a["count"] += int(d.get("count", 0))
        # Percentiles across droplets: take the max (conservative; the
        # per-droplet reducer already computed exact per-droplet percentiles).
        a["p50"] = max(a["p50"], int(d.get("p50_ms", 0)))
        a["p95"] = max(a["p95"], int(d.get("p95_ms", 0)))
        a["p99"] = max(a["p99"], int(d.get("p99_ms", 0)))
wall = wall or 1.0
total = sum(a["count"] for a in agg.values())
point = {
    "droplets": n_d,
    "workers_per_droplet": workers,
    "offered_concurrency": offered,
    "wall_secs": wall,
    "reqs": reqs,
    "shed": shed,
    "shed_rate": round((shed / reqs) if reqs else 0.0, 6),
    "total_ops_per_s": round(total / wall, 4),
    "ops": {},
}
for op, a in agg.items():
    point["ops"][op] = {
        "count": a["count"],
        "ops_per_s": round(a["count"] / wall, 4),
        "p50_ms": a["p50"], "p95_ms": a["p95"], "p99_ms": a["p99"],
    }
print(json.dumps(point))
'
}

# ---- Synthetic results JSON from a USL ground truth (self-test only) ----
synth_results_py() {
python3 -c '
import json, math
lam, sigma, kappa = 500.0, 0.02, 0.0005
def T(n): return lam*n/(1.0+sigma*(n-1.0)+kappa*n*(n-1.0))
# N_d x per-droplet-worker grid -> offered concurrency.
grid = [(1,8),(1,16),(1,32),(2,16),(2,32),(3,32),(3,64),(5,32),(5,64),(5,96),(5,128)]
pts = []
for nd, w in grid:
    offered = nd*w
    t = T(offered)
    # split the total across the three op classes (store:link:recall ~= 1:1:1)
    per = t/3.0
    pts.append({
        "droplets": nd, "workers_per_droplet": w, "offered_concurrency": offered,
        "wall_secs": 20.0, "reqs": int(t*20), "shed": 0, "shed_rate": 0.0,
        "total_ops_per_s": round(t,4),
        "ops": {op: {"count": int(per*20), "ops_per_s": round(per,4),
                     "p50_ms": 10, "p95_ms": 40, "p99_ms": 90}
                for op in ("store","link","recall")},
    })
print(json.dumps({
    "meta": {"host_substrate": "SELFTEST-synthetic", "backend": "synthetic",
             "corpus_scale": 10000, "step_duration_secs": 20,
             "measured_label": "SYNTHETIC-SELF-TEST"},
    "points": pts,
}, indent=2))
'
}

# ---- self-test: prove the JSON contract into usl-fit.py end-to-end ----
if [ "${1:-}" = "--self-test" ]; then
  need python3
  mkdir -p "$RESULTS_ROOT"
  tmp="$RESULTS_ROOT/ramp-selftest-$$.json"
  synth_results_py > "$tmp"
  echo "[self-test] wrote synthetic results -> $tmp"
  if python3 "$HERE/usl-fit.py" "$tmp" --target 500 | grep -q "USL fit -- #2438"; then
    echo "[self-test] usl-fit.py consumed the ramp JSON contract OK"
    rm -f "$tmp"
    echo "measure-capacity-ramp self-test OK"
    exit 0
  fi
  echo "SELF-TEST FAIL: usl-fit.py did not consume the ramp JSON" >&2
  rm -f "$tmp"
  exit 1
fi

# ---- real run: require an already-provisioned cluster ----
need ssh
need python3
SSH_USER="${SSH_USER:-root}"
SSH_OPTS="${SSH_OPTS:--o BatchMode=yes -o StrictHostKeyChecking=accept-new -o ConnectTimeout=10}"
DROPLET_COUNTS="${DROPLET_COUNTS:-1 2 3 5}"
CONCURRENCY_STEPS="${CONCURRENCY_STEPS:-8 16 32 64}"
STEP_DURATION_SECS="${STEP_DURATION_SECS:-20}"
BACKEND="${BACKEND:-postgres}"
CORPUS_SCALE="${CORPUS_SCALE:-10000}"
SUBSTRATE_HOST="${SUBSTRATE_HOST:-s-2vcpu-4gb}"
SEED="${SEED:-0}"
TS="$(date -u +%Y-%m-%dT%H-%M-%SZ)"
RESULTS_JSON="${RESULTS_JSON:-${RESULTS_ROOT}/capacity-${TS}.json}"

if [ -z "${SUBSTRATE_IP:-}" ] || [ -z "${LOADGEN_IPS:-}" ]; then
  cat >&2 <<'USAGE'
[measure-capacity-ramp] REFUSE: SUBSTRATE_IP and LOADGEN_IPS are required.

This driver only SSHes into an ALREADY-provisioned #2438 cluster (it never
spawns droplets). Provision it first with the money-gated wrapper (operator):

    export AI_MEMORY_OPERATOR_DO_SPEND_APPROVED=1   # operator only
    infra/do-hive/spawn.sh apply -var-file=measurement.tfvars

Then derive the IPs and re-run:

    cd infra/do-hive && terraform output -json > outs.json
    export SUBSTRATE_IP=$(jq -r .memory_private_ip.value outs.json)
    export LOADGEN_IPS=$(jq -r '.agent_ips.value | join(" ")' outs.json)
    infra/pillar4-envelope/measure-capacity-ramp.sh
USAGE
  exit 2
fi

mkdir -p "$RESULTS_ROOT"
# shellcheck disable=SC2206
IPS=($LOADGEN_IPS)
N_AVAIL=${#IPS[@]}
BASE="http://${SUBSTRATE_IP}:9077/api/v1"

echo "[measure-capacity-ramp] substrate=${SUBSTRATE_IP}:9077  loadgen droplets=${N_AVAIL}"
echo "[measure-capacity-ramp] N_d sweep=[${DROPLET_COUNTS}]  per-droplet ramp=[${CONCURRENCY_STEPS}]  ${STEP_DURATION_SECS}s/step"

# Optional corpus seed (runs ON the first loadgen droplet against the substrate).
if [ "$SEED" = "1" ]; then
  echo "[measure-capacity-ramp] seeding ${CORPUS_SCALE} rows via ${IPS[0]} ..."
  ssh $SSH_OPTS "${SSH_USER}@${IPS[0]}" \
    "SEED_N='${CORPUS_SCALE}' BASE='${BASE}' bash -s" <<'SEEDER' || echo "[seed] WARN: seeding returned non-zero (continuing)" >&2
    set -u
    i=0
    while [ "$i" -lt "${SEED_N}" ]; do
      curl -s -o /dev/null -X POST "${BASE}/memories" \
        -H 'content-type: application/json' -H 'x-agent-id: env-seed' \
        -d "{\"title\":\"seed-$i\",\"content\":\"envelope seed corpus row $i\",\"namespace\":\"envelope\",\"tier\":\"short\"}" || true
      i=$((i+1))
    done
    echo "[seed] done $i rows"
SEEDER
fi

WORKDIR="$(mktemp -d "${RESULTS_ROOT}/ramp-${TS}-XXXX")"
POINTS_FILE="${WORKDIR}/points.jsonl"
: > "$POINTS_FILE"

printf '%-9s %-9s %-11s %-14s %-9s\n' "DROPLETS" "W/DROP" "OFFERED" "TOTAL_OPS/S" "SHED%"
for n_d in $DROPLET_COUNTS; do
  if [ "$n_d" -gt "$N_AVAIL" ]; then
    echo "[measure-capacity-ramp] skip N_d=${n_d} (only ${N_AVAIL} droplets available)" >&2
    continue
  fi
  # First n_d IPs offer load for this sweep step.
  sel=("${IPS[@]:0:$n_d}")
  for w in $CONCURRENCY_STEPS; do
    offered=$((n_d * w))
    step_dir="${WORKDIR}/nd${n_d}-w${w}"
    mkdir -p "$step_dir"
    # Fire run-workers.sh on each selected droplet in parallel; capture JSON.
    pids=()
    idx=0
    for ip in "${sel[@]}"; do
      ssh $SSH_OPTS "${SSH_USER}@${ip}" \
        "AI_MEMORY_HTTP='http://${SUBSTRATE_IP}:9077' LOADGEN_WORKERS='${w}' STEP_DURATION_SECS='${STEP_DURATION_SECS}' /opt/loadgen/run-workers.sh" \
        > "${step_dir}/d${idx}.json" 2>"${step_dir}/d${idx}.err" &
      pids+=($!)
      idx=$((idx+1))
    done
    for p in "${pids[@]}"; do wait "$p" 2>/dev/null || true; done
    # Merge the per-droplet JSON blobs into one point.
    point="$(cat "${step_dir}"/d*.json 2>/dev/null \
      | python3 -c 'import sys,json; print(json.dumps([json.loads(l) for l in sys.stdin if l.strip()]))' \
      | OFFERED="$offered" N_D="$n_d" WPER="$w" merge_droplets_py)"
    echo "$point" >> "$POINTS_FILE"
    tops="$(printf '%s' "$point" | python3 -c 'import sys,json;d=json.load(sys.stdin);print(d.get("total_ops_per_s",0))')"
    srate="$(printf '%s' "$point" | python3 -c 'import sys,json;d=json.load(sys.stdin);print(round(d.get("shed_rate",0)*100,2))')"
    printf '%-9s %-9s %-11s %-14s %-9s\n' "$n_d" "$w" "$offered" "$tops" "$srate"
  done
done

# Assemble the final results JSON.
META_HOST="$SUBSTRATE_HOST" META_BACKEND="$BACKEND" META_CORPUS="$CORPUS_SCALE" \
META_STEP="$STEP_DURATION_SECS" META_TS="$TS" \
python3 -c '
import sys, os, json
points = [json.loads(l) for l in open(sys.argv[1]) if l.strip()]
points.sort(key=lambda p: p.get("offered_concurrency", 0))
out = {
    "meta": {
        "host_substrate": os.environ["META_HOST"],
        "backend": os.environ["META_BACKEND"],
        "corpus_scale": int(os.environ["META_CORPUS"]),
        "step_duration_secs": int(os.environ["META_STEP"]),
        "generated_at_utc": os.environ["META_TS"],
        "measured_label": "MEASURED",
        "instrument": "measure-capacity-ramp.sh (op mix identical to measure-envelope.sh)",
    },
    "points": points,
}
json.dump(out, open(sys.argv[2], "w"), indent=2)
' "$POINTS_FILE" "$RESULTS_JSON"

rm -rf "$WORKDIR"
echo
echo "[measure-capacity-ramp] results -> ${RESULTS_JSON}"
echo "[measure-capacity-ramp] fit + project:  infra/pillar4-envelope/usl-fit.py '${RESULTS_JSON}'"
