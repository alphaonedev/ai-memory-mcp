#!/bin/sh
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
#
# infra/bench-mesh — one federation node of the #2921 capacity mesh.
#
# DERIVED FROM `entrypoint.plan-c.sh`, deliberately NOT a copy of it. The
# two hard-won facts that entrypoint carries are reproduced here verbatim
# in intent, because getting either wrong yields a mesh that boots green
# and replicates nothing:
#
#   1. #1803 — the OUTBOUND `/sync/push` signing key is loaded by the
#      RESOLVED FEDERATION IDENTITY (`AI_MEMORY_FED_IDENTITY`), which is a
#      DIFFERENT on-disk file from the fixed `daemon` keypair used for
#      link/audit signing, and `ai-memory serve` has NO auto-generate
#      fallback for it. The receiving side looks up
#      `<sender_agent_id>.pub` in ITS OWN key dir. Both files must exist,
#      under those exact names, in the directory `serve` resolves via
#      `AI_MEMORY_KEY_DIR`.
#   2. #1231 — `AI_MEMORY_AGENT_ID` must never be the reserved sentinel
#      `daemon`; the wire validator rejects every member of
#      `RESERVED_AGENT_IDS` and the container crash-loops.
#
# WHAT IS DIFFERENT, AND WHY:
#
#   * Keys are PRE-PROVISIONED on the measurement host by `gen-mesh.py`
#     and bind-mounted in, instead of minted per-container on first boot
#     with a post-boot cross-copy provisioner (the lan-parity #1803
#     recipe). At N=50 a full mesh needs N*(N-1) = 2450 cross-enrollments;
#     doing that after boot makes enrollment a race the ramp would be
#     measuring. Pre-provisioning makes the mesh enrolled at t=0, so the
#     measured convergence time is replication time and nothing else.
#     This entrypoint therefore REFUSES TO START (fail closed, EX_CONFIG
#     78) when its own keypair is absent, rather than starting a node that
#     would push unsigned and be 401'd by every peer while looking healthy.
#   * No LLM / embedder configuration. The mesh runs `tier = "keyword"`
#     so no node needs an inference endpoint: a capacity number that
#     silently includes a model download or an Ollama round-trip is not a
#     substrate number. (This is also why the recall producer in
#     `scripts/bench/` is keyword-tier — see its header.)
#   * No `/sync` preflight (`AI_MEMORY_SKIP_PEER_PREFLIGHT`): in a full
#     mesh every node is every other node's peer, so a boot-time reach
#     check is a guaranteed deadlock (#926 hit this with only two nodes).
#     The ramp driver waits for the whole fleet's `/api/v1/health` before
#     it offers any load, which is the same guarantee taken at the right
#     layer.
#
# Required env (validated; missing => EX_CONFIG 78, never a silent default):
#   AI_MEMORY_FED_IDENTITY   this node's federation identity + key basename
#   AI_MEMORY_KEY_DIR        pre-provisioned key directory
#   AI_MEMORY_API_KEY        HTTP X-API-Key (the daemon refuses a non-loopback
#                            bind without one -- S5-C1)
#   AI_MEMORY_LISTEN_PORT    listen port
#   BENCH_DATA_DIR           writable dir for the SQLite database + config
#   BENCH_QUORUM_WRITES      W in the W-of-N write
#   BENCH_CATCHUP_SECS       catch-up poll interval, seconds (0 disables)
# Optional:
#   BENCH_PEERS              comma-separated peer base URLs ("" = no peers)
#   BENCH_QUORUM_TIMEOUT_MS  quorum ack deadline (default 2000, the flag default)
set -eu

fatal() { echo "[bench-entrypoint] FATAL: $*" >&2; exit 78; }

# Explicit emptiness tests rather than `${VAR:?}`: in POSIX sh a `:?`
# expansion failure exits the shell immediately, so a trailing
# `|| fatal "..."` never runs and the operator gets the shell's terse
# message instead of the one that says what to do about it.
for v in AI_MEMORY_FED_IDENTITY AI_MEMORY_KEY_DIR AI_MEMORY_API_KEY \
         AI_MEMORY_LISTEN_PORT BENCH_DATA_DIR BENCH_QUORUM_WRITES \
         BENCH_CATCHUP_SECS; do
  eval "val=\${$v:-}"
  [ -n "$val" ] || fatal "required env $v is unset or empty"
done

PEERS="${BENCH_PEERS:-}"
QTIMEOUT="${BENCH_QUORUM_TIMEOUT_MS:-2000}"

# #1803 fail-closed key check -- see the header. Both files, both names.
[ -f "${AI_MEMORY_KEY_DIR}/${AI_MEMORY_FED_IDENTITY}.priv" ] \
  || fatal "federation signing key ${AI_MEMORY_FED_IDENTITY}.priv absent from ${AI_MEMORY_KEY_DIR} -- run gen-mesh.py before compose up"
[ -f "${AI_MEMORY_KEY_DIR}/daemon.priv" ] \
  || fatal "daemon keypair absent from ${AI_MEMORY_KEY_DIR} -- run gen-mesh.py before compose up"

# `serve` reads its config from $HOME/.config/ai-memory/config.toml.
# HOME is pointed at the per-node bind mount by the compose file so the
# rendered config is part of the run's raw evidence.
mkdir -p "${HOME}/.config/ai-memory" "${BENCH_DATA_DIR}"

# Top-level AppConfig fields only. Sections like [memory] / [federation]
# are NOT valid AppConfig keys -- serde silently ignores them and the
# daemon falls through to defaults (the trap entrypoint.plan-c.sh
# documents at its own config heredoc).
cat >"${HOME}/.config/ai-memory/config.toml" <<TOML
tier = "keyword"
api_key = "${AI_MEMORY_API_KEY}"
TOML

QUORUM_FLAGS=""
if [ -n "$PEERS" ]; then
  QUORUM_FLAGS="--quorum-writes ${BENCH_QUORUM_WRITES} --quorum-peers ${PEERS} --quorum-timeout-ms ${QTIMEOUT}"
fi

echo "[bench-entrypoint] identity=${AI_MEMORY_FED_IDENTITY} port=${AI_MEMORY_LISTEN_PORT}"
echo "[bench-entrypoint] peers=$(printf '%s' "$PEERS" | awk -F, '{print NF}') quorum_w=${BENCH_QUORUM_WRITES} catchup=${BENCH_CATCHUP_SECS}s"

exec /usr/local/bin/ai-memory serve \
  --host 0.0.0.0 --port "${AI_MEMORY_LISTEN_PORT}" \
  --db "${BENCH_DATA_DIR}/memories.db" \
  --catchup-interval-secs "${BENCH_CATCHUP_SECS}" \
  $QUORUM_FLAGS
