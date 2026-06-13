#!/usr/bin/env bash
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
#
# docker-1461 provision step 50 — bring the mesh up and gate on health.
#
# Sole pusher/starter (mirrors deploy/hive-1461/provision/50_federation.sh).
# Assumes 00_seed, 40_tls, 45_zero_touch have populated the run dir and the
# images exist (10_build). Brings PG + both peers up over the generated
# env-file, then blocks until PG and every peer report `healthy` (the peer
# healthcheck is the real mTLS HTTPS path, so "healthy" proves TLS + the
# X-API-Key auth + the daemon HTTP surface are all live).
#
# Secrets posture: OPENROUTER_API_KEY / AI_MEMORY_API_KEY MUST already be in
# the caller's shell env (the Makefile sources ~/.env). They are passed to
# compose via the environment, never written to any file or command line.

set -euo pipefail
SELF_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
. "$SELF_DIR/lib.sh"

[ -s "$COMPOSE_ENV_FILE" ] || die "up: missing $COMPOSE_ENV_FILE — run 00_seed first"
: "${OPENROUTER_API_KEY:?up: OPENROUTER_API_KEY must be in shell env (source ~/.env)}"

log "up: docker compose up -d ($COMPOSE_PROJECT)"
dc up -d --remove-orphans

# Gate: PG first (peers depend_on it healthy, but assert explicitly).
log "up: waiting for $PG_CONTAINER"
wait_healthy "$PG_CONTAINER" "${DOCKER_1461_PG_WAIT_TICKS:-40}" \
  || die "up: $PG_CONTAINER did not become healthy"
log "up: $PG_CONTAINER healthy"

# Gate: each peer over the real mTLS HTTPS healthcheck.
i=1
while [ "$i" -le "$PEER_COUNT" ]; do
  c="$(peer_name "$i")"
  log "up: waiting for $c (mTLS HTTPS healthcheck)"
  if ! wait_healthy "$c" "${DOCKER_1461_PEER_WAIT_TICKS:-60}"; then
    warn "up: $c did not become healthy — last 40 log lines:"
    docker logs --tail 40 "$c" 2>&1 | sed 's/^/['"$c"'] /' >&2 || true
    die "up: peer $c unhealthy"
  fi
  log "up: $c healthy"
  i=$((i + 1))
done

log "up: OK — mesh live"
dc ps >&2
