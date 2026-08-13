#!/usr/bin/env bash
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
#
# =============================================================================
# run-ops-producers.sh -- produce the three ops/s cells docs/enterprise-deployment.md
# §11.1 retired for having no producer (#2921).
# =============================================================================
#
# §11.1's table was removed, not annotated, because "an unproduced number is
# not data". Three cells were named as having NO producer anywhere in the
# tree: `memory_store` ops/s, `memory_recall` ops/s, and `/sync/push` ops/s.
# This script is their producer. It is deliberately:
#
#   * HOST-PROCESS, NOT CONTAINERISED. The mesh-scaling leg
#     (`infra/bench-mesh/run-mesh-scaling.sh`) needs containers to give each
#     node its own network identity; a single-node throughput number does
#     not, and every layer between the load and the daemon is a confounder an
#     operator re-running this on their own hardware would have to reproduce.
#     All an operator needs here is the release binary and python3.
#   * KEYWORD TIER. The read path is measured embedder-independent; a recall
#     figure at `semantic`/`autonomous` measures whichever inference endpoint
#     the host had, which is not a property of this substrate.
#   * SELF-CONTAINED. Every daemon it starts runs against a database, config
#     directory and key directory created fresh under --out-dir. It never
#     reads or writes an operator's real store; `--db` is always explicit and
#     HOME/XDG are redirected so a stray config lookup cannot escape the run
#     directory.
#
# FOUR RUNGS, because the shipped posture and the substrate ceiling are
# different questions and publishing only one of them would mislead:
#
#   1. memory_store  ATTESTED    -- the SHIPPED v1.0.0 default. Every write
#      carries an Ed25519 signature the daemon verifies against the author's
#      bound key. This is the number an operator actually gets.
#   2. memory_store  UNSIGNED    -- the same path with
#      `AI_MEMORY_REQUIRE_AGENT_ATTESTATION=0`. NOT the shipped default; its
#      only purpose is to make the per-write verification cost VISIBLE as the
#      difference between two otherwise identical runs.
#   3. memory_recall KEYWORD     -- the read path, embedder-independent.
#   4. /sync/push    ATTESTED    -- node A configured with node B as its only
#      peer and `--quorum-writes 2`, so every accepted write must be
#      acknowledged by B's `/sync/push`: signature generation, transport,
#      receive-side verification and durable apply included. Confirmed at B by
#      its row-count delta, so the figure is not just the sender's opinion.
#
# The attested rungs post bodies signed AHEAD of the timed window by the
# in-tree `examples/attest_sign_batch` (see make-signed-pool.sh). Client-side
# signing is excluded from every published figure; what is measured is the
# server-side verification + storage (+ relay) cost.
#
# Usage:
#   scripts/bench/run-ops-producers.sh --binary target/release/ai-memory \
#       --out-dir .local-runs/ops-2921
#
# Env overrides: STEPS, DURATION, SEED_CORPUS, COOLDOWN, POOL_SIZE.
# Exit 0 = every producer ran and wrote results JSON.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "${HERE}/../.." && pwd)"

BINARY=""
OUT_DIR=""
SIGNER=""
STEPS="${STEPS:-1 2 4 8 16 32 64}"
DURATION="${DURATION:-20}"
SEED_CORPUS="${SEED_CORPUS:-5000}"
COOLDOWN="${COOLDOWN:-2}"
# One pre-signed body per offered write. Sized above the highest plausible
# rung total; a rung that runs the pool dry reports `pool_exhausted` rather
# than silently reporting a short rung as a low rate.
POOL_SIZE="${POOL_SIZE:-120000}"
# MEASUREMENT-ONLY quota lift, recorded in the results doc as a deviation.
# The shipped per-agent defaults are 1000 memory-writes/day and 100 MiB of
# storage. Every rung here writes as ONE author by construction (the
# attestation gate binds the signing identity), so at the shipped default a
# ramp stops dead at write 1001 with `429` -- which is what the first attempt
# at this bench actually did. Raising the ceiling measures the SUBSTRATE
# rather than the quota; the quota check itself still runs on every write, so
# its per-write cost stays inside the measured path.
BENCH_QUOTA_WRITES="${BENCH_QUOTA_WRITES:-10000000}"
BENCH_QUOTA_BYTES="${BENCH_QUOTA_BYTES:-10737418240}"
PORT_A="${PORT_A:-19091}"
PORT_B="${PORT_B:-19092}"
AUTHOR="ai:bench-author@cap2921"

while [ $# -gt 0 ]; do
  case "$1" in
    --binary) BINARY="$2"; shift 2 ;;
    --out-dir) OUT_DIR="$2"; shift 2 ;;
    --signer) SIGNER="$2"; shift 2 ;;
    --steps) STEPS="$2"; shift 2 ;;
    --duration) DURATION="$2"; shift 2 ;;
    --seed-corpus) SEED_CORPUS="$2"; shift 2 ;;
    --pool-size) POOL_SIZE="$2"; shift 2 ;;
    -h|--help) sed -n '2,58p' "$0"; exit 0 ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done

[ -n "$BINARY" ] || { echo "FATAL: --binary is required" >&2; exit 2; }
[ -x "$BINARY" ] || { echo "FATAL: $BINARY is not executable" >&2; exit 2; }
[ -n "$OUT_DIR" ] || { echo "FATAL: --out-dir is required" >&2; exit 2; }
BINARY="$(cd "$(dirname "$BINARY")" && pwd)/$(basename "$BINARY")"
SIGNER="${SIGNER:-$(dirname "$BINARY")/examples/attest_sign_batch}"
[ -x "$SIGNER" ] || {
  echo "FATAL: attested-body signer not found at $SIGNER" >&2
  echo "       build it with: cargo build --release --example attest_sign_batch" >&2
  exit 2; }
SIGNER="$(cd "$(dirname "$SIGNER")" && pwd)/$(basename "$SIGNER")"
mkdir -p "$OUT_DIR"
OUT_DIR="$(cd "$OUT_DIR" && pwd)"

PIDS=""
cleanup() {
  for p in $PIDS; do kill "$p" 2>/dev/null || true; done
  for p in $PIDS; do wait "$p" 2>/dev/null || true; done
}
trap cleanup EXIT

PRODUCER="${HERE}/ops_producer.py"
HOSTLABEL="${BENCH_HOST_LABEL:-single-host}"

# ---------------------------------------------------------------------------
# keygen <dir> <agent-id>
#
# HERMETIC environment: left alone the CLI resolves `--db` to `ai-memory.db`
# in the CURRENT DIRECTORY and loads the invoking user's real config. A bench
# must not be able to open, create or migrate a live store.
# ---------------------------------------------------------------------------
keygen() {
  local dir="$1" id="$2"
  HOME="$dir" XDG_CONFIG_HOME="${dir}/.config" XDG_DATA_HOME="${dir}/.local/share" \
  AI_MEMORY_NO_CONFIG=1 AI_MEMORY_DB="${dir}/keygen-scratch.db" \
  AI_MEMORY_KEY_DIR="$dir" \
    "$BINARY" identity generate --key-dir "$dir" --agent-id "$id" --json >/dev/null
}

# enroll_author <node-dir> -- register + bind the corpus author's key in the
# node's DB so the local store-path attestation gate can verify a signed
# write (that gate reads the DATABASE agent registry, not the key store), and
# drop the author's PUBLIC key into the key dir so the federation receive path
# can verify a relayed one. Both surfaces, per #1803's lesson that a key which
# exists in the wrong place is the same as no key.
enroll_author() {
  local dir="$1" db="${1}/memories.db"
  cp "${OUT_DIR}/author/${AUTHOR}.pub" "${dir}/keys/${AUTHOR}.pub"
  AI_MEMORY_NO_CONFIG=1 "$BINARY" agents register --db "$db" \
    --agent-id "$AUTHOR" --agent-type system --json >/dev/null
  AI_MEMORY_NO_CONFIG=1 "$BINARY" agents bind-key --db "$db" \
    --agent-id "$AUTHOR" --pubkey "$AUTHOR_PUB_B64" --json >/dev/null
}

# ---------------------------------------------------------------------------
# start_node <name> <port> <peers-csv> <quorum-writes> [attestation]
#
# HOME / XDG_CONFIG_HOME / XDG_DATA_HOME are ALL redirected into the node's
# own directory. Setting only --db would still leave the daemon resolving its
# config and key directory out of the operator's real home; this bench must
# be incapable of touching a live store.
#
# `attestation` is `default` (the shipped fail-closed posture) or `off`
# (`AI_MEMORY_REQUIRE_AGENT_ATTESTATION=0`, used ONLY for the control rung).
# ---------------------------------------------------------------------------
NODE_DIR=""
start_node() {
  local name="$1" port="$2" peers="$3" qw="$4" attest="${5:-default}"
  local dir="${OUT_DIR}/${name}"
  NODE_DIR="$dir"
  mkdir -p "${dir}/.config/ai-memory" "${dir}/keys" "${dir}/.local/share"
  cat >"${dir}/.config/ai-memory/config.toml" <<'TOML'
tier = "keyword"
TOML
  local flags=""
  if [ -n "$peers" ]; then
    flags="--quorum-writes ${qw} --quorum-peers ${peers} --quorum-timeout-ms 5000"
  fi
  # Catch-up polling OFF (0). The push path is what the federation rung
  # measures; a concurrent pull loop would silently supply rows the push path
  # failed to deliver, turning a push-throughput number into a "something
  # eventually replicated" number.
  #
  # The environment is EXPORTED inside a subshell rather than written as a
  # command prefix: a conditional prefix built by parameter expansion
  # (`${v:+NAME=$v}`) is not parsed as an assignment by bash, so the daemon
  # would be launched with a bogus argv[0] and fail to start.
  (
    export HOME="$dir"
    export XDG_CONFIG_HOME="${dir}/.config"
    export XDG_DATA_HOME="${dir}/.local/share"
    export AI_MEMORY_KEY_DIR="${dir}/keys"
    export AI_MEMORY_FED_IDENTITY="host:${name}"
    export AI_MEMORY_MAX_MEMORIES_PER_DAY="$BENCH_QUOTA_WRITES"
    export AI_MEMORY_MAX_STORAGE_BYTES="$BENCH_QUOTA_BYTES"
    if [ "$attest" = "off" ]; then
      export AI_MEMORY_REQUIRE_AGENT_ATTESTATION=0
    fi
    exec "$BINARY" serve --host 127.0.0.1 --port "$port" \
      --db "${dir}/memories.db" --catchup-interval-secs 0 \
      $flags >"${dir}/daemon.log" 2>&1
  ) &
  PIDS="$PIDS $!"
  local i=0
  while [ "$i" -lt 60 ]; do
    if curl -fsS --max-time 3 "http://127.0.0.1:${port}/api/v1/health" >/dev/null 2>&1; then
      echo "[run-ops] ${name} healthy on :${port} (attestation=${attest})"
      return 0
    fi
    i=$((i + 1)); sleep 1
  done
  echo "FATAL: ${name} never became healthy; see ${dir}/daemon.log" >&2
  tail -30 "${dir}/daemon.log" >&2 || true
  exit 70
}

stop_all() {
  for p in $PIDS; do kill "$p" 2>/dev/null || true; done
  for p in $PIDS; do wait "$p" 2>/dev/null || true; done
  PIDS=""
  sleep 2
}

mint_pool() {
  local ns="$1" prefix="$2" count="$3" out="$4"
  "${HERE}/make-signed-pool.sh" --signer "$SIGNER" --author "$AUTHOR" \
    --priv "${OUT_DIR}/author/${AUTHOR}.priv" \
    --namespace "$ns" --prefix "$prefix" --count "$count" --out "$out"
}

echo "[run-ops] binary: $("$BINARY" --version)"
"${HERE}/host-facts.sh" >"${OUT_DIR}/host-facts.json"

# The one attested author every signed rung writes as.
mkdir -p "${OUT_DIR}/author"
keygen "${OUT_DIR}/author" "$AUTHOR"
AUTHOR_PUB_B64="$(python3 -c 'import base64,sys; print(base64.b64encode(open(sys.argv[1],"rb").read()).decode())' "${OUT_DIR}/author/${AUTHOR}.pub")"

# === 1. memory_store, ATTESTED (the shipped v1.0.0 default) ================
echo "[run-ops] === producer 1/4: memory_store ATTESTED (shipped default) ==="
mkdir -p "${OUT_DIR}/store-attested/keys"
keygen "${OUT_DIR}/store-attested/keys" "host:store-attested"
keygen "${OUT_DIR}/store-attested/keys" daemon
AI_MEMORY_NO_CONFIG=1 "$BINARY" agents register --db "${OUT_DIR}/store-attested/memories.db" \
  --agent-id "$AUTHOR" --agent-type system --json >/dev/null
enroll_author "${OUT_DIR}/store-attested"
mint_pool cap2921store store "$POOL_SIZE" "${OUT_DIR}/pool-store.ndjson"
start_node store-attested "$PORT_A" "" 1 default
python3 "$PRODUCER" ramp --op store --label memory_store_attested \
  --base-url "http://127.0.0.1:${PORT_A}" --namespace cap2921store \
  --body-pool "${OUT_DIR}/pool-store.ndjson" --author "$AUTHOR" \
  --duration "$DURATION" --cooldown-secs "$COOLDOWN" \
  --concurrency-steps "$STEPS" --calibrate --host-substrate "$HOSTLABEL" \
  --out "${OUT_DIR}/ops-memory_store-attested.json"
stop_all

# === 2. memory_store, UNSIGNED control (NOT the shipped default) ===========
echo "[run-ops] === producer 2/4: memory_store UNSIGNED control ==="
start_node store-unsigned "$PORT_A" "" 1 off
python3 "$PRODUCER" ramp --op store --label memory_store_unsigned \
  --base-url "http://127.0.0.1:${PORT_A}" --namespace cap2921store \
  --duration "$DURATION" --cooldown-secs "$COOLDOWN" \
  --concurrency-steps "$STEPS" --calibrate --host-substrate "$HOSTLABEL" \
  --out "${OUT_DIR}/ops-memory_store-unsigned.json"
stop_all

# === 3. memory_recall (read path, keyword tier, seeded corpus) =============
# Seeded with attestation OFF: the seed is SETUP, not the measurement, and
# the read path does not consult the write-attestation gate at all. Recorded
# here so the choice is visible rather than inferred.
echo "[run-ops] === producer 3/4: memory_recall (keyword tier) ==="
start_node recall-node "$PORT_A" "" 1 off
python3 "$PRODUCER" ramp --op recall --label memory_recall \
  --base-url "http://127.0.0.1:${PORT_A}" --namespace cap2921recall \
  --seed-corpus "$SEED_CORPUS" \
  --duration "$DURATION" --cooldown-secs "$COOLDOWN" \
  --concurrency-steps "$STEPS" --calibrate --host-substrate "$HOSTLABEL" \
  --out "${OUT_DIR}/ops-memory_recall.json"
stop_all

# === 4. /sync/push (one peer, W=2, attested, end-to-end) ===================
echo "[run-ops] === producer 4/4: /sync/push (1 peer, W=2, attested) ==="
for n in push-a push-b; do
  mkdir -p "${OUT_DIR}/${n}/keys"
  keygen "${OUT_DIR}/${n}/keys" "host:${n}"
  keygen "${OUT_DIR}/${n}/keys" daemon
done
# #1803 -- cross-enroll the two nodes' federation PUBLIC keys. Only public
# material moves; a `.priv` is never copied.
cp "${OUT_DIR}/push-a/keys/host:push-a.pub" "${OUT_DIR}/push-b/keys/"
cp "${OUT_DIR}/push-b/keys/host:push-b.pub" "${OUT_DIR}/push-a/keys/"
for n in push-a push-b; do
  AI_MEMORY_NO_CONFIG=1 "$BINARY" agents register --db "${OUT_DIR}/${n}/memories.db" \
    --agent-id "$AUTHOR" --agent-type system --json >/dev/null
  enroll_author "${OUT_DIR}/${n}"
done
mint_pool cap2921push push "$POOL_SIZE" "${OUT_DIR}/pool-push.ndjson"
start_node push-b "$PORT_B" "" 1 default
start_node push-a "$PORT_A" "http://127.0.0.1:${PORT_B}" 2 default
python3 "$PRODUCER" ramp --op store --label sync_push \
  --base-url "http://127.0.0.1:${PORT_A}" --namespace cap2921push \
  --body-pool "${OUT_DIR}/pool-push.ndjson" --author "$AUTHOR" \
  --duration "$DURATION" --cooldown-secs "$COOLDOWN" \
  --concurrency-steps "$STEPS" --calibrate --host-substrate "$HOSTLABEL" \
  --receiver-db "${OUT_DIR}/push-b/memories.db" --receiver-drain-secs 5 \
  --out "${OUT_DIR}/ops-sync_push.json"
stop_all

echo "[run-ops] results in ${OUT_DIR}"
echo "[run-ops] USL fit (existing, self-tested fitter):"
echo "  ${REPO}/infra/pillar4-envelope/usl-fit.py ${OUT_DIR}/ops-memory_store-attested.json --target 500"
