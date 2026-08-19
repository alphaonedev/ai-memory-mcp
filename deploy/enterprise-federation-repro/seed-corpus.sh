#!/usr/bin/env bash
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
#
# enterprise-federation-repro — DETERMINISTIC synthetic seed corpus.
#
# WHY SYNTHETIC. The v1.0.0 enterprise-federation audit ran over a 7,855-row
# Atlas corpus (embedder = local all-MiniLM-L6-v2, 384-d, under loopback-only
# egress). That corpus is proprietary; a PORTABLE reproduction must ship a
# GENERATOR, not the data. This script writes a small, BYTE-DETERMINISTIC
# corpus into a local sqlite DB ($SEED_DB) via `ai-memory store` — every run
# produces the identical rows, so a peer reviewer's substrate is comparable
# to the audit's in SHAPE even though the content is synthetic.
#
# NO EMBEDDINGS ARE COMPUTED HERE. The seed rows carry only their durable
# TEXT (the North-Star source of truth). repro.sh migrates them into the pg
# tier verbatim (#3054/#3060), and the certified daemon RE-DERIVES the
# embedding vectors from that durable text at serve-boot (its list_unembedded
# backfill sweep, under the local MiniLM embedder / loopback-only egress) —
# demonstrating that embedding vectors are DISPOSABLE, regenerable artifacts,
# never durable truth. Semantic recall over the seed (verify.sh check 8)
# exercises the result.
#
# Idempotent: `ai-memory store` upserts by (title, namespace), so a re-run
# rewrites the same rows in place rather than duplicating them. A stale DB
# whose row count differs from $SEED_ROWS is rebuilt from scratch.

set -euo pipefail
SELF_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
. "$SELF_DIR/lib.sh"

BIN="$(resolve_ai_memory_bin)" || die "seed: no ai-memory binary — run repro.sh (it builds one) or set AI_MEMORY_BIN"

mkdir -p "$SEED_DIR"
# A sqlcipher-built binary (the kit default) refuses EVERY sqlite open without
# a passphrase, so the local seed DB is opened with --db-passphrase-file.
ensure_db_passphrase

# A fixed, ordered topic vocabulary. The (i mod N) pick makes each row's
# content a pure function of its index — deterministic across machines.
TOPICS=(
  "federation quorum write acknowledgement"
  "append-only signed_events hash chain"
  "Ed25519 agent attestation on store"
  "witness dual-head audit anchor"
  "recorder judge stopper role separation"
  "cause-binding on privileged actions"
  "content-id BLAKE3 genesis address"
  "peer enrollment and namespace scope"
  "at-rest encryption posture"
  "loopback-only inference egress"
  "semantic recall over the pgvector column"
  "Apache AGE property-graph traversal"
)

_seed_row() {
  # $1 = 1-based index
  local i="$1" t topic title content
  t=$(( (i - 1) % ${#TOPICS[@]} ))
  topic="${TOPICS[$t]}"
  title="$(printf 'audit-fact-%04d' "$i")"
  content="Reproducible audit fact ${i}: the enterprise-federation substrate records ${topic}. This row is synthetic, deterministic, and regenerable from its durable text."
  # --scope collective so the migrated corpus is visible to EVERY recall
  # caller over the mTLS API (verify.sh check 8), not just the storing
  # agent — the default scope is `private`, which the read-path ownership
  # filter would hide from a different X-Agent-Id. The synthetic seed is
  # public audit data, so collective visibility is correct.
  AI_MEMORY_NO_CONFIG=1 "$BIN" store \
    --db "$SEED_DB" \
    --db-passphrase-file "$DB_PASSPHRASE_FILE" \
    --namespace "$SEED_NAMESPACE" \
    --tier mid \
    --scope collective \
    --title "$title" \
    --content "$content" \
    --tags "ef-repro,audit,seed" \
    --source cli \
    >/dev/null
}

_row_count() {
  # Count via the CLI list (JSON-free grep of the human count line is brittle;
  # use sqlite3 when present, else fall back to a store-and-check no-op).
  if command -v sqlite3 >/dev/null 2>&1 && [ -s "$SEED_DB" ]; then
    sqlite3 "$SEED_DB" 'SELECT COUNT(*) FROM memories;' 2>/dev/null || printf '0'
  else
    printf 'unknown'
  fi
}

existing="$(_row_count)"
if [ "$existing" = "$SEED_ROWS" ]; then
  log "seed: $SEED_DB already holds $SEED_ROWS rows — reusing (idempotent)"
  exit 0
fi
if [ "$existing" != "unknown" ] && [ "$existing" != "0" ]; then
  log "seed: rebuilding $SEED_DB (had $existing rows, want $SEED_ROWS)"
  rm -f "$SEED_DB" "$SEED_DB-wal" "$SEED_DB-shm"
fi

log "seed: writing $SEED_ROWS deterministic rows into $SEED_DB (ns=$SEED_NAMESPACE)"
i=1
while [ "$i" -le "$SEED_ROWS" ]; do
  _seed_row "$i"
  i=$((i + 1))
done
log "seed: OK — $SEED_ROWS rows (embeddings deferred to daemon serve-boot backfill)"
