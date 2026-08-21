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
#   spine) is born DIRTY and only reaches CERTIFIED-READY through the single
#   idempotent `ai-memory audit bootstrap-node` command run under the FULL
#   certified asi-hard AUDIT require-mode set (witness + role + lineage all
#   armed) WITH the operator custody keys enrolled (witness + recorder). The
#   success label names EXACTLY which modes were armed (MB1). NEGATIVE
#   CONTROLS: asi-hard armed WITHOUT the custody keys REFUSES and names the
#   unmet ceremonies; certified modes NOT armed REFUSES to claim certified
#   even though the bare verify is clean (the false-green MB1 closes).
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

# ── LEG B — #3016/#3067 born-dirty → mechanical bring-up (asi-hard) ─────────
echo
echo "== LEG B — #3016/#3067 born-dirty bring-up gate (certified asi-hard modes) =="

WORK_B="$(mktemp -d)"
KEYDIR_B="$WORK_B/keys"; WDIR_B="$WORK_B/witness"; RDIR_B="$WORK_B/recorder"
EMPTY_W="$WORK_B/empty-witness"; EMPTY_R="$WORK_B/empty-recorder"
mkdir -p "$KEYDIR_B" "$WDIR_B" "$RDIR_B" "$EMPTY_W" "$EMPTY_R"
AGENT_B="cert-node-3016"

# The certified verdict is gated on the FULL asi-hard AUDIT require-mode set
# (MB1): bootstrap-node reports CERTIFIED-READY only when witness + role +
# lineage are ALL armed AND the verify is clean under them.
CERT_MODES=(AI_MEMORY_REQUIRE_WITNESS=1 AI_MEMORY_REQUIRE_ROLE_SEPARATION=1 AI_MEMORY_REQUIRE_IDENTITY_LINEAGE=1)

# HERMETIC db resolution (DATA-INTEGRITY CRITICAL). The `audit` subcommand
# resolves its db from `AppConfig` (config.toml `db`), NOT the cwd, so a stray
# `~/.config/ai-memory/config.toml` would point bring-up at a REAL operator DB.
# `AI_MEMORY_NO_CONFIG=1` skips config loading so `effective_db` falls to the
# cwd-relative default (`./ai-memory.db` in $WORK_B); `AI_MEMORY_STORE_URL` /
# `_FILE` are cleared so no external store is opened.
am_b() { ( cd "$WORK_B" && env AI_MEMORY_NO_CONFIG=1 AI_MEMORY_STORE_URL= AI_MEMORY_STORE_URL_FILE= "$@" ); }

# Store-only-migrated node: registry populated, spine empty. Enroll the
# operator custody keys bring-up VERIFIES (never mints): witness + recorder.
# NOT judge — a judge pubkey needs a verdict checkpoint no fresh-node CLI mints
# (recorder-only is the correct fresh-node role-separation posture).
am_b "$BIN" identity generate --agent-id "$AGENT_B" --key-dir "$KEYDIR_B" >/dev/null 2>&1
am_b "$BIN" identity generate --agent-id "${AGENT_B}-recovery" --key-dir "$KEYDIR_B" >/dev/null 2>&1
RECOVERY_B="$(am_b "$BIN" identity export-pub --agent-id "${AGENT_B}-recovery" --key-dir "$KEYDIR_B" 2>/dev/null)"
"$BIN" identity generate --agent-id audit-witness --key-dir "$WDIR_B" >/dev/null 2>&1
"$BIN" identity generate --agent-id governance-recorder --key-dir "$RDIR_B" >/dev/null 2>&1
am_b "$BIN" agents register --agent-id "$AGENT_B" --agent-type ai:test >/dev/null 2>&1

# BORN DIRTY — under an armed audit require-mode, the empty spine convicts.
am_b env AI_MEMORY_REQUIRE_IDENTITY_LINEAGE=1 "$BIN" verify-audit-trail >/dev/null 2>&1
if [[ $? -ne 0 ]]; then
  pass "store-only-migrated node (empty spine) is BORN DIRTY under armed require-lineage (exit != 0)"
else
  fail "an empty spine passed verify-audit-trail under armed require-lineage — NOT born dirty"
fi

# CERTIFIED — under the FULL asi-hard modes WITH witness + recorder keys.
am_b env "${CERT_MODES[@]}" AI_MEMORY_WITNESS_KEY_DIR="$WDIR_B" AI_MEMORY_RECORDER_KEY_DIR="$RDIR_B" \
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
if [[ $BRINGUP_CODE -eq 0 ]] && grep -q "CERTIFIED-READY" "$EVIDENCE_DIR/bring-up.out"; then
  pass "audit bootstrap-node CERTIFIED under full asi-hard modes with witness+recorder keys (exit 0)"
else
  fail "bootstrap-node did not certify under asi-hard — see $EVIDENCE_DIR/bring-up.out"
fi
# The success label must NAME the armed modes for the auditor (MB1).
if grep -qE "CERTIFIED-READY.*witness.*role_separation.*identity_lineage" "$EVIDENCE_DIR/bring-up.out"; then
  pass "CERTIFIED-READY names EXACTLY the armed require-modes for the verdict"
else
  fail "CERTIFIED-READY must name the armed modes (auditor seam) — see bring-up.out"
fi

# CLEAN AFTER — verify now exits 0 under the same armed modes.
am_b env "${CERT_MODES[@]}" AI_MEMORY_WITNESS_KEY_DIR="$WDIR_B" AI_MEMORY_RECORDER_KEY_DIR="$RDIR_B" \
    "$BIN" verify-audit-trail >/dev/null 2>&1
if [[ $? -eq 0 ]]; then
  pass "after bring-up, verify-audit-trail exits 0 under the certified modes"
else
  fail "verify-audit-trail still dirty after bring-up under the certified modes"
fi

# IDEMPOTENT — re-run with NO recovery pubkey stays exit 0.
am_b env "${CERT_MODES[@]}" AI_MEMORY_WITNESS_KEY_DIR="$WDIR_B" AI_MEMORY_RECORDER_KEY_DIR="$RDIR_B" \
    "$BIN" audit bootstrap-node --agent-id "$AGENT_B" --key-dir "$KEYDIR_B" >/dev/null 2>&1
if [[ $? -eq 0 ]]; then
  pass "bootstrap-node is idempotent: re-run without --recovery-pubkey stays certified"
else
  fail "bootstrap-node re-run was not idempotent"
fi

# NEGATIVE CONTROL 1 (MB1 core) — asi-hard modes armed but NO custody keys
# (empty dirs) MUST refuse and name the unmet ceremonies. A FRESH node.
WORK_D="$(mktemp -d)"; KEYDIR_D="$WORK_D/keys"; mkdir -p "$KEYDIR_D"
am_d() { ( cd "$WORK_D" && env AI_MEMORY_NO_CONFIG=1 AI_MEMORY_STORE_URL= AI_MEMORY_STORE_URL_FILE= "$@" ); }
am_d "$BIN" identity generate --agent-id nokeys-node --key-dir "$KEYDIR_D" >/dev/null 2>&1
am_d "$BIN" identity generate --agent-id nokeys-recovery --key-dir "$KEYDIR_D" >/dev/null 2>&1
REC_D="$(am_d "$BIN" identity export-pub --agent-id nokeys-recovery --key-dir "$KEYDIR_D" 2>/dev/null)"
am_d "$BIN" agents register --agent-id nokeys-node --agent-type ai:test >/dev/null 2>&1
am_d env "${CERT_MODES[@]}" AI_MEMORY_WITNESS_KEY_DIR="$EMPTY_W" AI_MEMORY_RECORDER_KEY_DIR="$EMPTY_R" \
    AI_MEMORY_WITNESS_PUBKEY= AI_MEMORY_RECORDER_PUBKEY= \
    "$BIN" audit bootstrap-node --agent-id nokeys-node --key-dir "$KEYDIR_D" \
    --recovery-pubkey "$REC_D" > "$EVIDENCE_DIR/refuse-no-keys.out" 2>&1
if [[ $? -eq 1 ]] && grep -q "NOT CERTIFIED" "$EVIDENCE_DIR/refuse-no-keys.out" \
   && grep -q "WITNESS" "$EVIDENCE_DIR/refuse-no-keys.out" \
   && grep -q "ROLE SEPARATION" "$EVIDENCE_DIR/refuse-no-keys.out"; then
  pass "negative control: asi-hard armed WITHOUT custody keys REFUSES and names witness + role"
else
  fail "asi-hard without keys did NOT fail-close correctly — see $EVIDENCE_DIR/refuse-no-keys.out"
fi

# NEGATIVE CONTROL 2 (MB1 core) — certified modes NOT armed MUST refuse to claim
# certified even though the bare verify would be clean. A FRESH node.
WORK_E="$(mktemp -d)"; KEYDIR_E="$WORK_E/keys"; mkdir -p "$KEYDIR_E"
am_e() { ( cd "$WORK_E" && env AI_MEMORY_NO_CONFIG=1 AI_MEMORY_STORE_URL= AI_MEMORY_STORE_URL_FILE= \
    AI_MEMORY_REQUIRE_WITNESS= AI_MEMORY_REQUIRE_ROLE_SEPARATION= AI_MEMORY_REQUIRE_IDENTITY_LINEAGE= "$@" ); }
am_e "$BIN" identity generate --agent-id unarmed-node --key-dir "$KEYDIR_E" >/dev/null 2>&1
am_e "$BIN" identity generate --agent-id unarmed-recovery --key-dir "$KEYDIR_E" >/dev/null 2>&1
REC_E="$(am_e "$BIN" identity export-pub --agent-id unarmed-recovery --key-dir "$KEYDIR_E" 2>/dev/null)"
am_e "$BIN" agents register --agent-id unarmed-node --agent-type ai:test >/dev/null 2>&1
am_e "$BIN" audit bootstrap-node --agent-id unarmed-node --key-dir "$KEYDIR_E" \
    --recovery-pubkey "$REC_E" > "$EVIDENCE_DIR/refuse-unarmed.out" 2>&1
if [[ $? -eq 1 ]] && grep -q "require-modes are NOT all armed" "$EVIDENCE_DIR/refuse-unarmed.out"; then
  pass "negative control: certified modes NOT armed REFUSES the certified claim (no false-green)"
else
  fail "unarmed certified modes did NOT refuse — see $EVIDENCE_DIR/refuse-unarmed.out"
fi

rm -rf "$WORK_B" "$WORK_D" "$WORK_E"

echo
if [[ $FAILED -eq 0 ]]; then
  echo "CERT-BOOTSTRAP GATE: PASS"
  exit 0
fi
echo "CERT-BOOTSTRAP GATE: FAIL"
exit 1
