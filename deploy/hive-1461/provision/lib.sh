# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
#
# Shared library for the push-based provisioning + validation toolkit.
# Sourced by every provision/*.sh and validate/*.sh script. bash-3.2 safe
# (macOS default): indexed arrays only, no associative arrays, no process
# substitution (the #66 SIGTRAP class), no `mapfile`.

set -euo pipefail

HIVE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# Run-state (inventory, generated TLS, render artifacts) lives in the gitignored
# project-local scratch dir per the no-/tmp hard rule. NEVER under /tmp.
RUN_DIR="${HIVE_RUN_DIR:-$HIVE_ROOT/../../.local-runs/hive-1461}"
mkdir -p "$RUN_DIR"

TF_DIR="$HIVE_ROOT/terraform"
INV_JSON="$RUN_DIR/inventory.json"

# Campaign + pinned-artifact constants (single source of truth for the toolkit).
CAMPAIGN="${CAMPAIGN:-hive-1461}"
FEDERATION_PORT="${FEDERATION_PORT:-9077}"
GOLDEN_SHA256="${GOLDEN_SHA256:-5e86de3ab0be6a19e02f760390651d9c425ba7ca73b9b8c7db0ce3b6f25a0aa7}"
EXPECTED_VERSION="${EXPECTED_VERSION:-0.7.0}"
EXPECTED_SCHEMA="${EXPECTED_SCHEMA:-55}"

# Pinned third-party images / refs (reproducibility anchors).
AGE_IMAGE="${AGE_IMAGE:-apache/age:release_PG16_1.6.0}"
OLLAMA_IMAGE="${OLLAMA_IMAGE:-ollama/ollama:0.6.8}"

# Autonomous-tier substrate model wiring (matches entrypoint.plan-c.sh's
# proven shape: cloud LLM + local CPU Ollama nomic embedder + cross-encoder).
# The peers run NO GPU: the chat LLM is a cloud OpenAI-compatible endpoint
# (OpenRouter Gemma 4 26B) while the 768-dim nomic embedder runs on a pinned
# CPU Ollama sidecar bound to localhost. The embedder is selected by the
# autonomous tier preset (NomicEmbedV15) and pointed at the sidecar via the
# legacy flat `embed_url`/`ollama_url` fields — `build_embedder` reads those,
# NOT the v2 `[embeddings].url` section (src/config.rs::effective_embed_url).
EMBED_MODEL="${EMBED_MODEL:-nomic-embed-text}"          # Ollama-registry id (768-dim)
# Embedding column dimension for the peer pgvector schema. MUST match the
# embedder's output width or every embedding insert fails the vector(N) check.
# nomic-embed-text (v1.5) emits 768; the ai-memory baseline schema defaults to
# 384 (MiniLM), so `schema-init` is invoked with --embedding-dim "$EMBED_DIM"
# to template `vector(768)`. Override in lockstep with EMBED_MODEL for forks.
EMBED_DIM="${EMBED_DIM:-768}"
EMBED_OLLAMA_URL="${EMBED_OLLAMA_URL:-http://127.0.0.1:11434}"
PEER_LLM_MODEL="${PEER_LLM_MODEL:-google/gemma-4-26b-a4b-it}"  # OpenRouter chat id
AGENT_LLM_MODEL="${AGENT_LLM_MODEL:-grok-4.3}"                 # xAI chat id (agent NHI)
DEFAULT_NAMESPACE="${DEFAULT_NAMESPACE:-hive-1461}"

SSH_KEY="${SSH_KEY:-$HOME/.ssh/id_ed25519}"
SSH_OPTS="-i $SSH_KEY -o BatchMode=yes -o StrictHostKeyChecking=accept-new -o ConnectTimeout=15 -o ServerAliveInterval=15 -o ServerAliveCountMax=4"

log()  { printf '[%s] %s\n' "$(date -u +%H:%M:%S)" "$*" >&2; }
die()  { printf 'FATAL: %s\n' "$*" >&2; exit 1; }

# ssh_node <ip> <remote-command-string>
# -n protects stdin so loops over `inv_*` output don't get consumed by ssh.
ssh_node() {
  local ip="$1"; shift
  # shellcheck disable=SC2086
  ssh -n $SSH_OPTS "root@${ip}" "$@"
}

# scp_to <local> <ip> <remote>
scp_to() {
  local src="$1" ip="$2" dst="$3"
  # shellcheck disable=SC2086
  scp $SSH_OPTS "$src" "root@${ip}:${dst}"
}

require_inventory() {
  [ -s "$INV_JSON" ] || die "inventory missing ($INV_JSON) — run provision/00_render_inventory.sh after terraform apply"
}

# Inventory accessors. One node per line where applicable.
inv_all()           { require_inventory; jq -r 'to_entries[] | "\(.key)\t\(.value.role)\t\(.value.region)\t\(.value.public_ip)\t\(.value.private_ip)"' "$INV_JSON"; }
inv_ips_by_role()   { require_inventory; jq -r --arg r "$1" 'to_entries[]|select(.value.role==$r)|.value.public_ip' "$INV_JSON"; }
inv_names_by_role() { require_inventory; jq -r --arg r "$1" 'to_entries[]|select(.value.role==$r)|.key' "$INV_JSON"; }
inv_name_for_ip()   { require_inventory; jq -r --arg ip "$1" 'to_entries[]|select(.value.public_ip==$ip)|.key' "$INV_JSON"; }
inv_all_ips()       { require_inventory; jq -r 'to_entries[]|.value.public_ip' "$INV_JSON"; }
inv_peer_urls()     { require_inventory; jq -r --arg p "$FEDERATION_PORT" 'to_entries[]|select(.value.role=="peer")|"https://\(.value.public_ip):\($p)"' "$INV_JSON"; }
