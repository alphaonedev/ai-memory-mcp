#!/usr/bin/env bash
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
#
# CERT GATE — Cluster-A cert-posture armability (#3061 #3016 #3067).
# Sibling to scripts/check-cert-removal-proof.sh: a LOAD-BEARING, end-to-end
# runtime proof driven through the COMPILED `ai-memory` binary (not a source
# grep), with plant-a-violation negative controls.
#
# It proves two properties the cluster exists to guarantee:
#
#   LEG A (#3061) — posture control #15 is BACKEND-AWARE and ARMABLE on a
#   postgres store. A fresh node in the certified pg config
#   (`sslmode=verify-full` DSN + AI_MEMORY_PG_AT_REST_ATTESTED=1) makes
#   `doctor --posture enterprise-federation` reach exit 0 — the whole point
#   of #3061 (pre-#3061 #15 was UNSATISFIABLE on pg, so the #17 boot gate
#   could never arm a pg node). NEGATIVE CONTROLS: dropping the attestation,
#   or weakening the DSN below verify-full, turns the gate RED. `doctor
#   --posture` never opens the DB, so this needs no live postgres.
#
#   LEG B (#3016/#3067) — a store-only-migrated node (empty `signed_events`
#   spine) is born DIRTY and STAYS dirty until the single idempotent
#   `ai-memory audit bootstrap-node` command runs. `verify-audit-trail`
#   exits 1 before bring-up and 0 after; bring-up is idempotent. NEGATIVE
#   CONTROL: a node that skips bring-up stays exit 1 (never self-certifies).
#
# USAGE:
#   scripts/check-bootstrap-cert-gate.sh          # build (if needed) + run
#   AI_MEMORY_BIN=/path/to/ai-memory scripts/check-bootstrap-cert-gate.sh
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"
# Absolute so the `cd "$WORK_B"` bring-up subshells below still resolve it.
EVIDENCE_DIR="$REPO_ROOT/.local-runs/cert-bootstrap-evidence"
mkdir -p "$EVIDENCE_DIR"

FAILED=0
note() { printf '  %s\n' "$*"; }
pass() { printf '[PASS] %s\n' "$*"; }
fail() { printf '[FAIL] %s\n' "$*"; FAILED=1; }

# ── locate / build the binary ──────────────────────────────────────────────
BIN="${AI_MEMORY_BIN:-}"
if [[ -z "$BIN" ]]; then
  echo "building ai-memory (default features)…"
  cargo build --quiet --bin ai-memory || { echo "build failed"; exit 3; }
  BIN="$REPO_ROOT/target/debug/ai-memory"
fi
[[ -x "$BIN" ]] || { echo "binary not executable: $BIN"; exit 3; }
echo "using binary: $BIN"

# A postgres DSN never connected (doctor --posture is env-only): the query
# string is all that #15 machine-checks.
PG_DSN_VERIFY_FULL="postgres://u@db.internal:5432/mem?sslmode=verify-full"
PG_DSN_REQUIRE_ONLY="postgres://u@db.internal:5432/mem?sslmode=require"

# ── LEG A — #3061 backend-aware #15, pg armability ─────────────────────────
echo
echo "== LEG A — #3061 pg posture armability =="

# Shared certified env for a pg backend. asi-hard auto-pins the 21 knobs in
# the binary's pre-runtime phase (src/main.rs); the rest are the federation
# additions the posture requires. A fingerprints file + attestation JSON +
# trust domain satisfy checks #9/#10/#11/#12; append-only + a daemon audit
# signing key satisfy #19.
KEYDIR_A="$(mktemp -d)"
FPFILE_A="$(mktemp)"
printf 'example.org 0000000000000000000000000000000000000000000000000000000000000000\n' > "$FPFILE_A"
# The daemon audit signing key for check #19 (resolve_agent_id honours
# AI_MEMORY_AGENT_ID); generate it into the key dir.
AGENT_A="cert-node-3061"
env AI_MEMORY_KEY_DIR="$KEYDIR_A" AI_MEMORY_AGENT_ID="$AGENT_A" \
  "$BIN" identity generate --agent-id "$AGENT_A" >/dev/null 2>&1 || true

posture_pg_env() {
  # $1 = attestation value ("1" or ""), $2 = DSN
  env \
    AI_MEMORY_SECURITY_PROFILE=asi-hard \
    AI_MEMORY_FED_TRUST_DOMAIN=test-fleet \
    AI_MEMORY_FED_PEER_FINGERPRINTS="$FPFILE_A" \
    AI_MEMORY_FED_PEER_ATTESTATION='{"peer-1":{"allowed_namespaces":["public/*"]}}' \
    AI_MEMORY_STORE_URL="$2" \
    ${1:+AI_MEMORY_PG_AT_REST_ATTESTED=$1} \
    AI_MEMORY_APPEND_ONLY=1 \
    AI_MEMORY_KEY_DIR="$KEYDIR_A" \
    AI_MEMORY_AGENT_ID="$AGENT_A" \
    AI_MEMORY_REQUIRE_ENTERPRISE_FEDERATION_POSTURE=1 \
    "$BIN" doctor --posture enterprise-federation --json
}

# Certified pg config → doctor --posture exits 0, and #15 is the pg
# compensating control (NOT the sqlcipher predicate).
OUT_A="$EVIDENCE_DIR/pg-posture-pass.json"
posture_pg_env 1 "$PG_DSN_VERIFY_FULL" > "$OUT_A" 2>/dev/null
CODE_A=$?
if [[ $CODE_A -eq 0 ]]; then
  pass "fresh pg node in the certified config: doctor --posture exit 0 (#3061 armable)"
else
  fail "certified pg config did NOT reach exit 0 (got $CODE_A) — see $OUT_A"
  grep -o '"control":"[^"]*"[^}]*"pass":false' "$OUT_A" 2>/dev/null | sed 's/^/    FAIL-ROW /' || true
fi
if grep -q 'AI_MEMORY_PG_AT_REST_ATTESTED' "$OUT_A" 2>/dev/null \
   && ! grep -q '"control":"AI_MEMORY_ENCRYPT_AT_REST"' "$OUT_A" 2>/dev/null; then
  pass "control #15 is the pg COMPENSATING control, not the sqlcipher predicate"
else
  fail "control #15 did not resolve to the pg compensating control on a postgres DSN"
fi

# NEGATIVE CONTROL 1 — drop the operator attestation → gate goes RED.
posture_pg_env "" "$PG_DSN_VERIFY_FULL" > "$EVIDENCE_DIR/pg-posture-no-attest.json" 2>/dev/null
if [[ $? -ne 0 ]]; then
  pass "negative control: verify-full WITHOUT AI_MEMORY_PG_AT_REST_ATTESTED refuses (non-zero)"
else
  fail "the pg at-rest attestation is NOT load-bearing — posture passed without it"
fi

# NEGATIVE CONTROL 2 — weaken the DSN below verify-full → gate goes RED.
posture_pg_env 1 "$PG_DSN_REQUIRE_ONLY" > "$EVIDENCE_DIR/pg-posture-weak-tls.json" 2>/dev/null
if [[ $? -ne 0 ]]; then
  pass "negative control: sslmode=require (not verify-full) + attestation refuses (non-zero)"
else
  fail "the sslmode=verify-full TLS half is NOT load-bearing — posture passed without it"
fi

rm -rf "$KEYDIR_A" "$FPFILE_A"

# ── LEG B — #3016/#3067 born-dirty → mechanical bring-up ────────────────────
echo
echo "== LEG B — #3016/#3067 born-dirty bring-up gate =="

WORK_B="$(mktemp -d)"
KEYDIR_B="$WORK_B/keys"
mkdir -p "$KEYDIR_B"
AGENT_B="cert-node-3016"

# HERMETIC db resolution (DATA-INTEGRITY CRITICAL). The `audit` subcommand
# resolves its db from `AppConfig` (config.toml `db` / AGENT-CONFIG), NOT the
# cwd, so a stray `~/.config/ai-memory/config.toml` would point bring-up at a
# REAL operator DB and write a spine row into it. `AI_MEMORY_NO_CONFIG=1` skips
# config loading so `effective_db` falls to the cwd-relative default
# (`./ai-memory.db` in $WORK_B), and `AI_MEMORY_STORE_URL` / `_FILE` are cleared
# so no external store is ever opened. Every leg-B invocation goes through
# `am_b` to guarantee this.
am_b() {
  ( cd "$WORK_B" \
    && env AI_MEMORY_NO_CONFIG=1 \
           AI_MEMORY_STORE_URL= AI_MEMORY_STORE_URL_FILE= \
           AI_MEMORY_KEY_DIR="$KEYDIR_B" \
           "$@" )
}

# A store-only-migrated node: the agent registry is populated, the audit
# spine is empty. All commands operate on ./ai-memory.db in $WORK_B.
am_b "$BIN" identity generate --agent-id "$AGENT_B" >/dev/null 2>&1
am_b "$BIN" identity generate --agent-id "${AGENT_B}-recovery" >/dev/null 2>&1
RECOVERY_B="$(am_b "$BIN" identity export-pub --agent-id "${AGENT_B}-recovery" 2>/dev/null)"
am_b "$BIN" agents register --agent-id "$AGENT_B" --agent-type ai:test >/dev/null 2>&1

# BORN DIRTY — under an armed audit require-mode, the empty spine convicts.
am_b env AI_MEMORY_REQUIRE_IDENTITY_LINEAGE=1 "$BIN" verify-audit-trail >/dev/null 2>&1
if [[ $? -ne 0 ]]; then
  pass "store-only-migrated node (empty spine) is BORN DIRTY under armed require-lineage (exit != 0)"
else
  fail "an empty spine passed verify-audit-trail under armed require-lineage — NOT born dirty"
fi

# BRING UP — the single idempotent command.
am_b env AI_MEMORY_REQUIRE_IDENTITY_LINEAGE=1 \
    "$BIN" audit bootstrap-node --agent-id "$AGENT_B" --key-dir "$KEYDIR_B" \
    --recovery-pubkey "$RECOVERY_B" > "$EVIDENCE_DIR/bring-up.out" 2>&1
BRINGUP_CODE=$?
# Defense-in-depth: PROVE bring-up wrote ONLY the sandbox db, never a real one.
if grep -qE "db: +(\./)?ai-memory\.db" "$EVIDENCE_DIR/bring-up.out" \
   || grep -qF "db:              $WORK_B" "$EVIDENCE_DIR/bring-up.out"; then
  pass "bring-up resolved the SANDBOX db (hermetic — never a config/operator DB)"
else
  fail "bring-up did NOT resolve the sandbox db — refusing to trust the result"
  grep -E "^  db:" "$EVIDENCE_DIR/bring-up.out" | sed 's/^/    /'
fi
if [[ $BRINGUP_CODE -eq 0 ]]; then
  pass "audit bootstrap-node brought the node up: exit 0 (certified-ready)"
else
  fail "bootstrap-node did not certify the node — see $EVIDENCE_DIR/bring-up.out"
fi

# CLEAN AFTER — verify now exits 0.
am_b env AI_MEMORY_REQUIRE_IDENTITY_LINEAGE=1 "$BIN" verify-audit-trail >/dev/null 2>&1
if [[ $? -eq 0 ]]; then
  pass "after bring-up, verify-audit-trail exits 0 (no longer born dirty)"
else
  fail "verify-audit-trail still dirty after bring-up"
fi

# IDEMPOTENT — re-run with NO recovery pubkey stays exit 0.
am_b env AI_MEMORY_REQUIRE_IDENTITY_LINEAGE=1 \
    "$BIN" audit bootstrap-node --agent-id "$AGENT_B" --key-dir "$KEYDIR_B" >/dev/null 2>&1
if [[ $? -eq 0 ]]; then
  pass "bootstrap-node is idempotent: re-run without --recovery-pubkey stays certified"
else
  fail "bootstrap-node re-run was not idempotent"
fi

# NEGATIVE CONTROL — a SECOND fresh node that SKIPS bring-up stays dirty.
WORK_C="$(mktemp -d)"
( cd "$WORK_C" && env AI_MEMORY_NO_CONFIG=1 AI_MEMORY_STORE_URL= AI_MEMORY_STORE_URL_FILE= \
    "$BIN" agents register --agent-id skip-node --agent-type ai:test >/dev/null 2>&1 )
( cd "$WORK_C" && env AI_MEMORY_NO_CONFIG=1 AI_MEMORY_STORE_URL= AI_MEMORY_STORE_URL_FILE= \
    AI_MEMORY_REQUIRE_IDENTITY_LINEAGE=1 "$BIN" verify-audit-trail >/dev/null 2>&1 )
if [[ $? -ne 0 ]]; then
  pass "negative control: a node that SKIPS bring-up stays dirty (never self-certifies)"
else
  fail "a node that skipped bring-up self-certified — the born-dirty gate is not load-bearing"
fi

rm -rf "$WORK_B" "$WORK_C"

echo
if [[ $FAILED -eq 0 ]]; then
  echo "CERT-BOOTSTRAP GATE: PASS"
  exit 0
fi
echo "CERT-BOOTSTRAP GATE: FAIL"
exit 1
