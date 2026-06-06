#!/usr/bin/env bash
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
#
# docker-1461 provision step 10 — build the two campaign images.
#
#   PG_AGE_VECTOR_IMAGE : PostgreSQL 16 + AGE + pgvector (campaign Dockerfile)
#   DAEMON_IMAGE        : slim release/v0.7.0 ai-memory daemon (sal,sal-postgres)
#
# Both tags + build inputs come from lib.sh (AGE_BASE_IMAGE, CARGO_FEATURES).
# Idempotent via the Docker layer cache; pass FORCE_REBUILD=1 to add --no-cache.

set -euo pipefail
SELF_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
. "$SELF_DIR/lib.sh"

NOCACHE=""
[ "${FORCE_REBUILD:-0}" = "1" ] && NOCACHE="--no-cache"

# --------------------------------------------------------------------------
# 1. PostgreSQL + AGE + pgvector. Context = campaign dir; base pinned in lib.
# --------------------------------------------------------------------------
log "build: $PG_AGE_VECTOR_IMAGE (base $AGE_BASE_IMAGE)"
docker build $NOCACHE \
  --build-arg "AGE_BASE_IMAGE=$AGE_BASE_IMAGE" \
  -f "$CAMPAIGN_ROOT/Dockerfile.pg-age-vector" \
  -t "$PG_AGE_VECTOR_IMAGE" \
  "$CAMPAIGN_ROOT"

# --------------------------------------------------------------------------
# 2. ai-memory daemon (slim, daemon-only). Context = repo root; the shared
#    Dockerfile.tier2-trackb embeds entrypoint.plan-c.sh + peer-preflight.
# --------------------------------------------------------------------------
log "build: $DAEMON_IMAGE (features=$CARGO_FEATURES)"
docker build $NOCACHE \
  --build-arg "CARGO_FEATURES=$CARGO_FEATURES" \
  -f "$REPO_ROOT/Dockerfile.tier2-trackb" \
  -t "$DAEMON_IMAGE" \
  "$REPO_ROOT"

log "build: OK"
# Surface the daemon binary version baked into the image for the record.
docker run --rm --entrypoint "$REMOTE_BINARY" "$DAEMON_IMAGE" --version 2>/dev/null \
  | sed 's/^/[build] daemon /' >&2 || warn "build: could not read --version from image"
