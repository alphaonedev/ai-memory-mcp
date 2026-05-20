#!/usr/bin/env bash
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
#
# Runs the SAL-postgres cross-adapter parity tests against the scoped
# LAN-parity PG+AGE container exposed on 127.0.0.1:15432. Captures the
# full log under .local-runs/ for ship-gate audit trail.
#
# Pre-flight:
#   docker compose -f infra/lan-parity-test/docker-compose.yml up -d pg-age
#   (wait for pg-age healthcheck → healthy)
#
# Usage:
#   ./infra/lan-parity-test/run-parity-tests.sh

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$REPO_ROOT"

TIMESTAMP="$(date -u +%Y-%m-%dT%H-%M-%SZ)"
LOG="$REPO_ROOT/.local-runs/lan-parity-${TIMESTAMP}.log"
mkdir -p "$(dirname "$LOG")"

PG_URL="postgres://ai_memory:ai_memory_test@127.0.0.1:15432/ai_memory_test"

echo "[lan-parity] PG URL: ${PG_URL/ai_memory_test@/<redacted>@}"
echo "[lan-parity] Log:    $LOG"
echo "[lan-parity] Pre-flight PG reach check..."
PGPASSWORD=ai_memory_test psql -h 127.0.0.1 -p 15432 -U ai_memory -d ai_memory_test \
    -c "SELECT 'pg+age reachable' AS status;" >/dev/null
echo "[lan-parity] PG+AGE reachable. Running cargo SAL-postgres tests..."
echo ""

AI_MEMORY_TEST_POSTGRES_URL="$PG_URL" \
AI_MEMORY_NO_CONFIG=1 \
cargo test --features sal,sal-postgres --release 2>&1 | tee "$LOG"

EXIT=${PIPESTATUS[0]}
echo ""
echo "[lan-parity] cargo exit code: $EXIT"
echo "[lan-parity] Log preserved at: $LOG"
exit "$EXIT"
