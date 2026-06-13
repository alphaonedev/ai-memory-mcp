#!/usr/bin/env bash
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
#
# Stand up the per-peer CPU embedder sidecar: a pinned Ollama container,
# localhost-bound, serving the 768-dim nomic-embed-text model the autonomous
# tier requires. Peers run NO GPU, so the chat LLM is a cloud OpenAI-compatible
# endpoint (OpenRouter, wired in 30_config.sh) while embeddings run locally on
# CPU here — exactly the split the canonical entrypoint.plan-c.sh autonomous
# deployment uses (Gemma LLM + nomic-embed via Ollama + cross-encoder).
#
# Without this sidecar the autonomous tier's NomicEmbedV15 preset has no embed
# host: the daemon logs "EMBEDDER LOAD FAILED" and silently degrades to
# keyword-only (no semantic recall, no HNSW, no sync embedding refresh) — which
# would fail the 100%-validated baseline bar. Peers only.
source "$(dirname "$0")/lib.sh"

inv_ips_by_role peer | while read -r ip; do
  host="$(inv_name_for_ip "$ip")"
  log "[$host] (re)starting pinned Ollama embed sidecar ($OLLAMA_IMAGE, localhost:11434)"
  ssh_node "$ip" "docker pull '$OLLAMA_IMAGE' >/dev/null"
  ssh_node "$ip" "docker rm -f hive-ollama 2>/dev/null || true; docker volume create hive-ollama >/dev/null; \
    docker run -d --name hive-ollama --restart unless-stopped \
      -p 127.0.0.1:11434:11434 -v hive-ollama:/root/.ollama \
      '$OLLAMA_IMAGE' >/dev/null"

  log "[$host] waiting for Ollama ready"
  ssh_node "$ip" "for i in \$(seq 1 60); do docker exec hive-ollama ollama list >/dev/null 2>&1 && exit 0; sleep 2; done; echo 'ollama not ready' >&2; exit 1"

  log "[$host] pulling pinned embed model ($EMBED_MODEL) — CPU, content-addressed"
  ssh_node "$ip" "docker exec hive-ollama ollama pull '$EMBED_MODEL' >/dev/null"

  log "[$host] verifying embed model present"
  ssh_node "$ip" "docker exec hive-ollama ollama list | grep -q '$EMBED_MODEL'" \
    || die "[$host] embed model $EMBED_MODEL missing after pull"
  log "[$host] embed sidecar ready ($EMBED_MODEL @ $EMBED_OLLAMA_URL)"
done
log "peer embedder sidecars complete on all peers"
