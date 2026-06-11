#!/usr/bin/env bash
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
#
# Render + push the per-role ai-memory config.toml and the secret API-key
# EnvironmentFile to every node. Config shape follows the canonical autonomous
# deployment (entrypoint.plan-c.sh): cloud OpenAI-compatible chat LLM + local
# CPU Ollama nomic embedder (peers) + cross-encoder reranker.
#
#   peer  -> tier=autonomous; [llm] OpenRouter Gemma; nomic-embed via local
#            Ollama sidecar (legacy flat embed_url — build_embedder reads those,
#            NOT [embeddings].url); cross-encoder; full MCP profile.
#   agent -> tier=keyword (thin grok NHI client; no local embedder to load);
#            [llm] xAI grok for the agent driver's LLM calls.
#   ctrl  -> tier=keyword (loadgen/chaos/orchestration client; no LLM).
#
# Secret handling: api keys are referenced by NAME (api_key_env) in config.toml
# — inline `api_key` is rejected at parse and would leak the secret into a
# world-readable file. The actual key value is written to a mode-0400
# EnvironmentFile, rendered locally into the gitignored secrets dir via shell
# redirection (NEVER committed, NEVER passed on an ssh command line where `ps`
# could see it) and scp'd into place.
source "$(dirname "$0")/lib.sh"

RENDER_DIR="$RUN_DIR/render"; mkdir -p "$RENDER_DIR"
SECRETS_DIR="$RUN_DIR/secrets"; mkdir -p "$SECRETS_DIR"; chmod 700 "$SECRETS_DIR"

# Daemon HTTP api_key (S5-C1 / #1458). The peer `serve` binds 0.0.0.0, and the
# daemon REFUSES a non-loopback bind when its top-level `api_key` is unset
# (default-off auth would expose every privileged write endpoint to any caller
# that can reach the bind address). The top-level `api_key` field has NO
# env-indirection (unlike [llm].api_key_env), so it is rendered INLINE into the
# peer config.toml — the canonical S5-C1 mechanism entrypoint.plan-c.sh uses
# (#845). The file therefore carries a secret and is chmod 0600 on the remote.
# /api/v1/health is exempt and /api/v1/sync/* bypasses under mTLS, so the
# federation health gate (50_federation.sh) and peer quorum POSTs succeed
# WITHOUT presenting the key; only the non-federation privileged surfaces
# require x-api-key (test clients present it in the P3 phase). Generated once
# into the gitignored run dir (mode 0600), never committed, never echoed.
API_PW_FILE="$SECRETS_DIR/api.pw"
if [ ! -s "$API_PW_FILE" ]; then openssl rand -hex 32 > "$API_PW_FILE"; chmod 600 "$API_PW_FILE"; log "generated daemon api_key -> $API_PW_FILE"; fi
API_KEY="$(cat "$API_PW_FILE")"
REMOTE_CFG="/root/.config/ai-memory/config.toml"
REMOTE_ETC_CFG="/etc/ai-memory/config.toml"

# --- render config.toml for one host into $RENDER_DIR/<host>/config.toml ------
render_peer_config() {
  cat <<TOML
schema_version = 2
tier = "autonomous"

# Daemon HTTP API key (S5-C1 / #1458): REQUIRED because this peer binds 0.0.0.0
# — the daemon refuses a non-loopback bind without it. TOP-LEVEL field (the
# [api] subsection is silently ignored by serde; src/config.rs:2283), inline is
# the only mechanism (no top-level api_key_env). /api/v1/health is exempt and
# /api/v1/sync/* bypasses under mTLS, so the federation health gate + peer
# quorum POSTs need not present it; other privileged endpoints require x-api-key
# (test clients supply it in P3). config.toml is chmod 0600 on the remote.
api_key = "$API_KEY"

# Embedder (#1598): API embeddings — no Ollama sidecar on CPU-only peers
# (operator decisions 2026-06-11: USA models, paid tier, Ollama only on GPU
# nodes). build_embedder() consumes the v2 [embeddings] section post-#1598.
# dim is the fleet-wide Matryoshka pin (gemini truncates server-side) keeping
# the PG regions' vector(768) schemas + pgvector ANN indexes (2000-dim cap)
# untouched. The embed key rides the same EnvironmentFile env var as [llm].
cross_encoder = true

[embeddings]
backend = "$PEER_EMBED_BACKEND"
model = "$PEER_EMBED_MODEL"
dim = $PEER_EMBED_DIM
api_key_env = "$PEER_LLM_API_KEY_ENV"

# Chat LLM: cloud OpenAI-compatible (no GPU on peers). The secret is supplied by
# the EnvironmentFile via api_key_env; inline api_key is rejected at parse.
[llm]
backend = "$PEER_LLM_BACKEND"
model = "$PEER_LLM_MODEL"
api_key_env = "$PEER_LLM_API_KEY_ENV"

[reranker]
enabled = true
model = "ms-marco-MiniLM-L-6-v2"

[storage]
default_namespace = "$DEFAULT_NAMESPACE"
archive_on_gc = true

[audit]
enabled = true
path = "/var/log/ai-memory/audit"
redact_content = true
hash_chain = true

[mcp]
profile = "full"

[permissions]
mode = "enforce"
TOML
}

render_agent_config() {
  cat <<TOML
schema_version = 2
# Thin grok NHI client: keyword tier avoids loading a local embedder (no Ollama
# on agents). LLM access is tier-independent once [llm].backend is set (#1067).
tier = "keyword"

[llm]
backend = "xai"
model = "$AGENT_LLM_MODEL"
api_key_env = "XAI_API_KEY"

[storage]
default_namespace = "$DEFAULT_NAMESPACE"

[permissions]
mode = "enforce"
TOML
}

render_ctrl_config() {
  cat <<TOML
schema_version = 2
# Orchestration / loadgen / chaos client. Keyword tier, no LLM, no embedder —
# it drives the peers over their HTTP API, it does not hold a substrate.
tier = "keyword"

[storage]
default_namespace = "$DEFAULT_NAMESPACE"

[permissions]
mode = "enforce"
TOML
}

# --- push config + (role-appropriate) secret env file to a node ---------------
push_node() {
  local ip="$1" host="$2" role="$3"
  local outdir="$RENDER_DIR/$host"; mkdir -p "$outdir"
  case "$role" in
    peer)  render_peer_config  > "$outdir/config.toml" ;;
    agent) render_agent_config > "$outdir/config.toml" ;;
    ctrl)  render_ctrl_config  > "$outdir/config.toml" ;;
    *) die "[$host] unknown role '$role'" ;;
  esac
  # Peer config carries the inline daemon api_key secret; keep it root-only at
  # rest (mirrors the remote 0600 below). Harmless for agent/ctrl (no secret).
  chmod 600 "$outdir/config.toml"

  log "[$host] pushing config.toml (role=$role)"
  ssh_node "$ip" "mkdir -p /root/.config/ai-memory /etc/ai-memory /var/log/ai-memory/audit"
  scp_to "$outdir/config.toml" "$ip" "$REMOTE_CFG"
  ssh_node "$ip" "cp '$REMOTE_CFG' '$REMOTE_ETC_CFG'; chmod 600 '$REMOTE_CFG' '$REMOTE_ETC_CFG'"

  # Secret EnvironmentFile — only the keys this role actually needs.
  local envf="$SECRETS_DIR/$host.env"
  : > "$envf"; chmod 600 "$envf"
  case "$role" in
    peer)
      # Push only the secret the configured backend names ($PEER_LLM_API_KEY_ENV),
      # read indirectly so the provider stays a pure config knob (bash-3.2-safe).
      eval "llm_secret=\${$PEER_LLM_API_KEY_ENV:-}"
      [ -n "$llm_secret" ] || die "[$host] $PEER_LLM_API_KEY_ENV not set in env (peer LLM, backend=$PEER_LLM_BACKEND). Export the key before provisioning."
      printf '%s=%s\n' "$PEER_LLM_API_KEY_ENV" "$llm_secret" >> "$envf"
      ;;
    agent)
      [ -n "${XAI_API_KEY:-}" ] || die "[$host] XAI_API_KEY not set in env (agent grok LLM). Export it before provisioning."
      printf 'XAI_API_KEY=%s\n' "$XAI_API_KEY" >> "$envf"
      ;;
    ctrl) : ;;  # no LLM secret
  esac

  if [ -s "$envf" ]; then
    log "[$host] pushing secret EnvironmentFile (mode 0400)"
    scp_to "$envf" "$ip" "$REMOTE_ENVFILE"
    ssh_node "$ip" "chmod 0400 '$REMOTE_ENVFILE'"
  fi
}

inv_all | while IFS="$(printf '\t')" read -r host role region pub priv; do
  # The pg node runs PostgreSQL only (no ai-memory daemon), so it gets no
  # config.toml / EnvironmentFile — its substrate is provisioned by 20_pg_age.sh.
  [ "$role" = "pg" ] && { log "[$host] role=pg (PostgreSQL substrate, no daemon) — skipping config push"; continue; }
  push_node "$pub" "$host" "$role"
done
log "config + secret env fan-out complete on all nodes"
