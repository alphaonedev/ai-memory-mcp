#!/usr/bin/env bash
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
#
# =============================================================================
# run-mesh-scaling.sh -- step an ai-memory federation mesh through N = 2..50
# peers and measure what each step costs (#2921).
# =============================================================================
#
# WHAT THIS PRODUCES, AND WHAT IT HONESTLY IS
# -------------------------------------------
# At each mesh size N it brings up N daemons in a FULL MESH (every node peers
# every other node), writes a fixed corpus into node 1, and measures:
#
#   * time-to-convergence -- when every node in the mesh carries the corpus
#   * accepted write rate at the sender, and the aggregate /sync/push fan-out
#     rate it implies ((N-1) pushes per accepted write)
#   * DLQ depth and the federation fan-out / partial-quorum counters, i.e.
#     whether convergence was CLEAN or merely eventual
#   * per-node CPU% and RSS
#
# This is a SINGLE-HOST, MULTI-CONTAINER measurement. Every node is a real
# process with its own network identity speaking real TCP over a Docker
# bridge, and every push is really signed and really verified -- but all N
# nodes share one kernel, one NIC-less loopback-backed bridge, one page
# cache, and one CPU package. It is NOT a cross-host WAN measurement and any
# number from it must be labelled that way. Network latency, packet loss,
# and per-host memory pressure are all absent; contention for one host's
# cores is present and grows with N.
#
# The mesh runs the CERTIFIED-RELEVANT KNOBS AT THEIR DEFAULTS: peer
# enrollment required, push signatures required, write signatures required --
# all fail-closed by compiled default at v1.0.0, none of them overridden
# here. The two deliberate deviations, both recorded in every results file:
#
#   1. AI_MEMORY_FED_ALLOW_PLAINTEXT_PEERS=1. A Docker bridge is not
#      loopback, so the #2477 peer-scheme guard refuses plaintext peers by
#      default and the mesh would not form. The bridge is private to one host
#      and exists only for measurement. This removes TLS handshake + record
#      cost from the numbers, which makes them an UPPER bound relative to a
#      TLS mesh -- stated in the results doc rather than quietly enjoyed.
#   2. --catchup-interval-secs defaults to 5 here, not the shipped 30. The
#      catch-up poller's period is a fixed, mesh-size-independent constant;
#      leaving it at 30 would make every convergence measurement a multiple
#      of 30 seconds and hide the term that actually scales with N. The value
#      used is recorded in the manifest, and the results doc states what a
#      30s deployment would instead see.
#
# Usage:
#   infra/bench-mesh/run-mesh-scaling.sh \
#       --binary target/release/ai-memory \
#       --out-dir .local-runs/mesh-2921 \
#       --steps "2 5 10 25 50" --corpus 1000
#
# Set BENCH_DOCKER='sudo docker' on hosts where the docker socket needs it.
# Teardown is unconditional: every rung tears its stack down in a trap, so an
# interrupted run does not leave 50 daemons on the host.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "${HERE}/../.." && pwd)"
DOCKER="${BENCH_DOCKER:-docker}"
IMAGE="ai-memory-bench-mesh:2921"
PROJECT="ai-memory-bench-mesh-2921"

BINARY=""
OUT_DIR=""
STEPS="2 5 10 25 50"
CORPUS=1000
WRITE_CONC=8
CATCHUP=5
CONVERGE_TIMEOUT=900
SKIP_BUILD=0
SIGNER=""

while [ $# -gt 0 ]; do
  case "$1" in
    --binary) BINARY="$2"; shift 2 ;;
    --out-dir) OUT_DIR="$2"; shift 2 ;;
    --steps) STEPS="$2"; shift 2 ;;
    --corpus) CORPUS="$2"; shift 2 ;;
    --write-concurrency) WRITE_CONC="$2"; shift 2 ;;
    --catchup-secs) CATCHUP="$2"; shift 2 ;;
    --converge-timeout) CONVERGE_TIMEOUT="$2"; shift 2 ;;
    --signer) SIGNER="$2"; shift 2 ;;
    --skip-build) SKIP_BUILD=1; shift ;;
    -h|--help) sed -n '2,60p' "$0"; exit 0 ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done

[ -n "$BINARY" ] || { echo "FATAL: --binary is required" >&2; exit 2; }
[ -x "$BINARY" ] || { echo "FATAL: $BINARY is not executable" >&2; exit 2; }
[ -n "$OUT_DIR" ] || { echo "FATAL: --out-dir is required" >&2; exit 2; }
# The corpus must be ATTESTED: v1.0.0 refuses an unsigned HTTP-direct write and
# refuses an unsigned third-party relayed write on /sync/push, both fail-closed
# by compiled default. Measuring the shipped posture therefore requires the
# in-tree batch signer. Refuse up front rather than discovering it at rung 1.
SIGNER="${SIGNER:-$(dirname "$BINARY")/examples/attest_sign_batch}"
[ -x "$SIGNER" ] || {
  echo "FATAL: attested-body signer not found at $SIGNER" >&2
  echo "       build it with: cargo build --release --example attest_sign_batch" >&2
  echo "       (an UNSIGNED corpus does not replicate under the v1.0.0 defaults," >&2
  echo "        so this bench refuses to run one and call it a mesh measurement)" >&2
  exit 2; }
SIGNER="$(cd "$(dirname "$SIGNER")" && pwd)/$(basename "$SIGNER")"
BINARY="$(cd "$(dirname "$BINARY")" && pwd)/$(basename "$BINARY")"
mkdir -p "$OUT_DIR"; OUT_DIR="$(cd "$OUT_DIR" && pwd)"

compose_down() {
  local d="$1"
  [ -f "${d}/docker-compose.yml" ] || return 0
  $DOCKER compose -p "$PROJECT" -f "${d}/docker-compose.yml" down -v \
    --remove-orphans >/dev/null 2>&1 || true
}
CURRENT_DIR=""
cleanup() { [ -n "$CURRENT_DIR" ] && compose_down "$CURRENT_DIR"; }
trap cleanup EXIT INT TERM

# --- Build the runtime image ONCE from the host-built binary ---------------
# See infra/bench-mesh/Dockerfile for why the binary is staged rather than
# compiled in-image: every rung must run the same bytes.
if [ "$SKIP_BUILD" -eq 0 ]; then
  echo "[mesh] staging binary + building ${IMAGE}"
  mkdir -p "${HERE}/.build"
  cp "$BINARY" "${HERE}/.build/ai-memory"
  $DOCKER build -q -t "$IMAGE" -f "${HERE}/Dockerfile" "${HERE}" >/dev/null
  rm -f "${HERE}/.build/ai-memory"
fi

echo "[mesh] binary: $("$BINARY" --version)"
"${REPO}/scripts/bench/host-facts.sh" >"${OUT_DIR}/host-facts.json"

for N in $STEPS; do
  RUNG_DIR="${OUT_DIR}/N${N}"
  CURRENT_DIR="$RUNG_DIR"
  echo
  echo "=============================================================="
  echo "[mesh] rung N=${N} (peers/node=$((N - 1)), corpus=${CORPUS})"
  echo "=============================================================="
  rm -rf "$RUNG_DIR"; mkdir -p "$RUNG_DIR"

  python3 "${HERE}/gen-mesh.py" --nodes "$N" --run-dir "$RUNG_DIR" \
    --binary "$BINARY" --catchup-secs "$CATCHUP" --image "$IMAGE" \
    >"${RUNG_DIR}/gen-mesh.json"

  $DOCKER compose -p "$PROJECT" -f "${RUNG_DIR}/docker-compose.yml" up -d \
    >"${RUNG_DIR}/compose-up.log" 2>&1 || {
      echo "[mesh] compose up FAILED at N=${N}; see ${RUNG_DIR}/compose-up.log" >&2
      tail -20 "${RUNG_DIR}/compose-up.log" >&2 || true
      compose_down "$RUNG_DIR"; exit 71; }

  # Mint the attested corpus AFTER compose-up, immediately before the
  # measurement: a signature commits to a `created_at` and the server
  # enforces a bounded freshness window, so a pool has a SHELF LIFE (see
  # make-signed-pool.sh). Minting before the bring-up would spend a large
  # slice of that window on 50 container starts at the top rung.
  AUTHOR="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["author"])' "${RUNG_DIR}/gen-mesh.json")"
  "${REPO}/scripts/bench/make-signed-pool.sh" \
    --signer "$SIGNER" --author "$AUTHOR" \
    --priv "${RUNG_DIR}/author/${AUTHOR}.priv" \
    --namespace mesh2921 --count "$CORPUS" --prefix "mesh-N${N}" \
    --out "${RUNG_DIR}/corpus.ndjson"

  set +e
  python3 "${REPO}/scripts/bench/mesh_probe.py" rung \
    --project "$PROJECT" --run-dir "$RUNG_DIR" --nodes "$N" \
    --corpus "$CORPUS" --write-concurrency "$WRITE_CONC" \
    --api-key-file "${RUNG_DIR}/api-key" \
    --body-pool "${RUNG_DIR}/corpus.ndjson" --author "$AUTHOR" \
    --converge-timeout "$CONVERGE_TIMEOUT" \
    --out "${OUT_DIR}/rung-N${N}.json" 2>&1 | tee "${RUNG_DIR}/probe.log"
  RC=${PIPESTATUS[0]}
  set -e

  # Node logs are the only place a boot-time refusal (#1803 key, #2477 peer
  # scheme, quorum misconfiguration) is visible. Capture them BEFORE teardown
  # regardless of outcome -- a rung that failed is evidence too.
  for i in $(seq 1 "$N"); do
    name=$(printf 'am2921-node-%02d' "$i")
    $DOCKER logs "$name" >"${RUNG_DIR}/${name}.log" 2>&1 || true
  done

  compose_down "$RUNG_DIR"
  CURRENT_DIR=""
  if [ "$RC" -ne 0 ]; then
    echo "[mesh] rung N=${N} did NOT converge (rc=${RC}) -- recorded, continuing" >&2
  fi
done

echo
echo "[mesh] per-rung results: ${OUT_DIR}/rung-N*.json"
python3 - "$OUT_DIR" <<'PY'
import glob, json, os, sys
d = sys.argv[1]
rows = []
for p in sorted(glob.glob(os.path.join(d, "rung-N*.json")),
                key=lambda p: int(os.path.basename(p)[6:-5])):
    r = json.load(open(p))
    c = r["convergence"]
    rows.append((r["nodes"], r["corpus"], r["write"]["accepted"],
                 r["write"]["write_wall_s"], r["write"]["accepted_ops_per_s"],
                 r["aggregate_push_ops_per_s"], c["converged"],
                 c["converged_s"], r["tail_s"], r["dlq_depth_total"]))
hdr = ("N", "corpus", "accepted", "write_s", "wr_ops/s", "push_ops/s",
       "conv", "conv_s", "tail_s", "dlq")
print("| " + " | ".join(hdr) + " |")
print("|" + "---|" * len(hdr))
for r in rows:
    print("| " + " | ".join(str(x) for x in r) + " |")
json.dump({"rows": [dict(zip(hdr, r)) for r in rows]},
          open(os.path.join(d, "summary.json"), "w"), indent=2)
PY
