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
REMOTE_CFG="/root/.config/ai-memory/config.toml"
REMOTE_ETC_CFG="/etc/ai-memory/config.toml"
REMOTE_ENVFILE="/etc/ai-memory/ai-memory.env"

# --- render config.toml for one host into $RENDER_DIR/<host>/config.toml ------
render_peer_config() {
  cat <<TOML
schema_version = 2
tier = "autonomous"

# Embedder: autonomous-tier nomic-embed-text (768-dim) via the local CPU Ollama
# sidecar (25_ollama_embed.sh). build_embedder() reads these LEGACY FLAT fields,
# NOT the v2 [embeddings] section (src/config.rs::effective_embed_url).
ollama_url = "$EMBED_OLLAMA_URL"
embed_url = "$EMBED_OLLAMA_URL"
embedding_model = "nomic_embed_v15"
cross_encoder = true

# Chat LLM: cloud OpenAI-compatible (no GPU on peers). The secret is supplied by
# the EnvironmentFile via api_key_env; inline api_key is rejected at parse.
[llm]
backend = "openrouter"
model = "$PEER_LLM_MODEL"
api_key_env = "OPENROUTER_API_KEY"

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

  log "[$host] pushing config.toml (role=$role)"
  ssh_node "$ip" "mkdir -p /root/.config/ai-memory /etc/ai-memory /var/log/ai-memory/audit"
  scp_to "$outdir/config.toml" "$ip" "$REMOTE_CFG"
  ssh_node "$ip" "cp '$REMOTE_CFG' '$REMOTE_ETC_CFG'"

  # Secret EnvironmentFile — only the keys this role actually needs.
  local envf="$SECRETS_DIR/$host.env"
  : > "$envf"; chmod 600 "$envf"
  case "$role" in
    peer)
      [ -n "${OPENROUTER_API_KEY:-}" ] || die "[$host] OPENROUTER_API_KEY not set in env (peer LLM). Export the ROTATED key before provisioning."
      printf 'OPENROUTER_API_KEY=%s\n' "$OPENROUTER_API_KEY" >> "$envf"
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
  push_node "$pub" "$host" "$role"
done
log "config + secret env fan-out complete on all nodes"
