#!/usr/bin/env bash
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
#
# Stand up the per-peer CPU embedder: a pinned NATIVE Ollama install (no
# container anywhere on the DO fleet, per operator decision), localhost-bound,
# serving the 768-dim nomic-embed-text model the autonomous tier requires.
# Peers run NO GPU, so the chat LLM is a cloud OpenAI-compatible endpoint
# (OpenRouter Gemma, wired in 30_config.sh) while embeddings run locally on CPU
# here — exactly the split the canonical autonomous deployment uses (cloud LLM
# + nomic-embed via Ollama + cross-encoder).
#
# Without this embedder the autonomous tier's NomicEmbedV15 preset has no embed
# host: the daemon logs "EMBEDDER LOAD FAILED" and silently degrades to
# keyword-only (no semantic recall, no HNSW, no sync embedding refresh) — which
# would fail the 100%-validated baseline bar. Peers only.
#
# Install model: the official pinned Ollama release tarball ($OLLAMA_VERSION)
# unpacked to /usr/local, run under a dedicated systemd unit bound to
# 127.0.0.1:11434 (OLLAMA_HOST). Idempotent: re-running re-asserts the pinned
# version, the unit, and the model pull. Mirrors the pinned binary the prior
# container model shipped, minus the container.
source "$(dirname "$0")/lib.sh"

# #1598 (operator GPU policy, 2026-06-11): the Ollama sidecar is provisioned
# ONLY when the fleet's embedding backend is ollama. API-backed fleets
# (PEER_EMBED_BACKEND=openrouter/openai-compatible/...) skip this step
# entirely — CPU-only peers run zero local inference for embeddings; the v2
# [embeddings] section in 30_config.sh carries the API wiring instead.
if [ "${PEER_EMBED_BACKEND:-ollama}" != "ollama" ]; then
  log "25_ollama_embed: SKIP — PEER_EMBED_BACKEND=$PEER_EMBED_BACKEND (API embeddings, #1598); no Ollama sidecar on CPU-only peers"
  exit 0
fi

# Render the localhost-bound systemd unit locally; scp into place (no secret, so
# a plain heredoc render is fine — this is NOT a credential file).
render_ollama_unit() {
  cat <<UNIT
[Unit]
Description=Ollama CPU embedder (do-1461 peer sidecar, pinned $OLLAMA_VERSION)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
# Localhost-bound: the embedder is reachable ONLY by the co-located daemon over
# loopback. It is never exposed on the VPC or public interface.
Environment=OLLAMA_HOST=127.0.0.1:11434
Environment=OLLAMA_MODELS=/var/lib/ollama/models
ExecStart=/usr/local/bin/ollama serve
User=ollama
Group=ollama
Restart=always
RestartSec=3
# Writable model store; everything else read-only.
ReadWritePaths=/var/lib/ollama
ProtectSystem=full
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
UNIT
}

# Idempotent remote installer (no secret inline). Pins the Ollama version,
# installs the dedicated service user + model dir, lays the unit, starts it,
# waits ready, pulls the pinned embed model, and asserts it is present.
render_ollama_install() {
  cat <<INSTALL
#!/usr/bin/env bash
set -euo pipefail
OLLAMA_VERSION="$OLLAMA_VERSION"
EMBED_MODEL="$EMBED_MODEL"

log() { printf '[ollama-install] %s\n' "\$*" >&2; }

# 1) Pinned binary. The official release ships a per-arch tarball that unpacks
#    bin/ollama + lib/ to a prefix. Reinstall only when the pinned version is
#    not already the installed one (idempotent, content-addressed by version).
need_install=1
if command -v ollama >/dev/null 2>&1; then
  cur="\$(ollama --version 2>/dev/null | awk '{print \$NF}' | head -1 || true)"
  [ "\$cur" = "\$OLLAMA_VERSION" ] && need_install=0
fi
if [ "\$need_install" = "1" ]; then
  log "installing pinned ollama \$OLLAMA_VERSION (linux-amd64 tarball)"
  apt-get update -qq
  DEBIAN_FRONTEND=noninteractive apt-get install -y -qq curl ca-certificates
  tmp="\$(mktemp -d /opt/do-1461/ollama.XXXXXX)"
  curl -fsSL "https://github.com/ollama/ollama/releases/download/v\${OLLAMA_VERSION}/ollama-linux-amd64.tgz" \\
    -o "\$tmp/ollama.tgz"
  tar -xzf "\$tmp/ollama.tgz" -C /usr/local
  rm -rf "\$tmp"
  /usr/local/bin/ollama --version >/dev/null
else
  log "ollama \$OLLAMA_VERSION already installed"
fi

# 2) Dedicated service user + writable model store.
id -u ollama >/dev/null 2>&1 || useradd --system --home /var/lib/ollama --shell /usr/sbin/nologin ollama
install -d -o ollama -g ollama -m 0750 /var/lib/ollama /var/lib/ollama/models

# 3) Unit (scp'd alongside this script) -> systemd, enable + (re)start.
install -m 0644 /opt/do-1461/ollama/ollama.service /etc/systemd/system/ollama.service
systemctl daemon-reload
systemctl enable ollama >/dev/null 2>&1 || true
systemctl restart ollama

# 4) Wait ready (the embed pull needs the API up).
for i in \$(seq 1 60); do
  /usr/local/bin/ollama list >/dev/null 2>&1 && break
  sleep 2
  [ "\$i" = "60" ] && { echo 'ollama not ready after 120s' >&2; exit 1; }
done

# 5) Pull the pinned embed model (CPU, content-addressed) + assert present.
log "pulling pinned embed model \$EMBED_MODEL"
OLLAMA_HOST=127.0.0.1:11434 /usr/local/bin/ollama pull "\$EMBED_MODEL" >/dev/null
OLLAMA_HOST=127.0.0.1:11434 /usr/local/bin/ollama list | grep -q "\$EMBED_MODEL" \\
  || { echo "embed model \$EMBED_MODEL missing after pull" >&2; exit 1; }
log "embed model \$EMBED_MODEL present"
INSTALL
}

RENDER_DIR="$RUN_DIR/render"; mkdir -p "$RENDER_DIR"

inv_ips_by_role peer | while read -r ip; do
  host="$(inv_name_for_ip "$ip")"
  outdir="$RENDER_DIR/$host/ollama"; mkdir -p "$outdir"
  render_ollama_unit    > "$outdir/ollama.service"
  render_ollama_install > "$outdir/ollama-install.sh"

  log "[$host] staging native Ollama installer ($OLLAMA_VERSION, localhost:11434)"
  ssh_node "$ip" "mkdir -p /opt/do-1461/ollama"
  scp_to "$outdir/ollama.service"    "$ip" "/opt/do-1461/ollama/ollama.service"
  scp_to "$outdir/ollama-install.sh" "$ip" "/opt/do-1461/ollama/ollama-install.sh"

  log "[$host] installing native Ollama + pulling $EMBED_MODEL (CPU)"
  ssh_node "$ip" "bash /opt/do-1461/ollama/ollama-install.sh"

  log "[$host] embedder ready ($EMBED_MODEL @ $EMBED_OLLAMA_URL)"
done
log "peer native Ollama embedders complete on all peers"
