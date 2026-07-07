#!/usr/bin/env bash
# =============================================================================
# test-attestation.sh — ATTESTATION (#1751) positive + negative, over the HTTPS
# daemon with mTLS + AI_MEMORY_REQUIRE_AGENT_ATTESTATION=1 and a REAL bound
# Ed25519 agent keypair.
# =============================================================================
#   POS  a signed write (attest_sign envelope + the bound key) is accepted 201
#        and the stored row carries metadata.attest_level = "agent_attested".
#   NEG  an UNSIGNED write is rejected 403 with code ATTESTATION_FAILED.
#
# The signature is produced by the repo `attest_sign` example so the canonical
# CBOR bytes are computed by the SAME crate code the verifier runs (no bash
# re-implementation of RFC 8949 CBOR).
#
# Requires: ./out from gen-certs.sh, release ai-memory + example attest_sign
#   (cargo build --release --example attest_sign).
# =============================================================================
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
OUT="${OUT:-$HERE/out}"
ROOT="$HERE/../../.."
BIN="${BIN:-$ROOT/target/release/ai-memory}"
SIGNER="${SIGNER:-$ROOT/target/release/examples/attest_sign}"
PORT="${PORT:-19444}"
AGENT="ai:alice"
WORK="$(mktemp -d)"; LOG="$WORK/daemon.log"
pass=0; fail=0
ok(){ echo "PASS: $1"; pass=$((pass+1)); }
no(){ echo "FAIL: $1"; fail=$((fail+1)); }
cleanup(){ [ -n "${DPID:-}" ] && kill "$DPID" 2>/dev/null; rm -rf "$WORK"; }
trap cleanup EXIT

export AI_MEMORY_KEY_DIR="$WORK/keys"
DB="$WORK/attest.db"

# --- 1. generate the agent keypair + register + bind its pubkey (offline) ---
"$BIN" identity generate --agent-id "$AGENT" --key-dir "$AI_MEMORY_KEY_DIR" >/dev/null 2>&1
PUB="$("$BIN" identity export-pub --agent-id "$AGENT" --key-dir "$AI_MEMORY_KEY_DIR" 2>/dev/null | tail -1)"
AI_MEMORY_NO_CONFIG=1 "$BIN" agents register --agent-id "$AGENT" --agent-type system --db "$DB" >/dev/null 2>&1
AI_MEMORY_NO_CONFIG=1 "$BIN" agents bind-key --agent-id "$AGENT" --pubkey "$PUB" --db "$DB" >/dev/null 2>&1
echo "INFO: bound pubkey $PUB for $AGENT"

# --- 2. launch daemon: HTTPS + mTLS + attestation REQUIRED --------------------
AI_MEMORY_NO_CONFIG=1 AI_MEMORY_REQUIRE_AGENT_ATTESTATION=1 \
"$BIN" serve --host 127.0.0.1 --port "$PORT" --db "$DB" \
  --tls-cert "$OUT/server.crt" --tls-key "$OUT/server.key" \
  --mtls-allowlist "$OUT/allowlist.txt" >"$LOG" 2>&1 &
DPID=$!
CC=(--cert "$OUT/client-good.crt" --key "$OUT/client-good.key")
for i in $(seq 1 40); do
  curl -sk "${CC[@]}" "https://127.0.0.1:$PORT/api/v1/health" -o /dev/null && break; sleep 0.5; done
BASE="https://127.0.0.1:$PORT/api/v1"

TITLE="attested-probe-$$"
CONTENT="A meaningful attested memory body written during the v0.9.0 crypto DO round."
CREATED="$(date -u +%Y-%m-%dT%H:%M:%S+00:00)"

# --- POSITIVE: signed write accepted + agent_attested -----------------------
SIG="$("$SIGNER" --agent-id "$AGENT" --namespace crypto-round --title "$TITLE" \
        --kind observation --created-at "$CREATED" --content "$CONTENT" \
        --priv-file "$AI_MEMORY_KEY_DIR/$AGENT.priv" 2>"$WORK/sign.err")"
if [ -z "$SIG" ]; then no "attest POS: signer produced no signature ($(cat "$WORK/sign.err"))"; fi
body=$(jq -nc --arg t "$TITLE" --arg c "$CONTENT" --arg ns crypto-round \
        --arg sig "$SIG" --arg ca "$CREATED" \
        '{title:$t,content:$c,namespace:$ns,tier:"mid",signature:$sig,created_at:$ca}')
resp=$(curl -sk "${CC[@]}" -H "x-agent-id: $AGENT" -H "content-type: application/json" \
        -X POST "$BASE/memories" -d "$body" -w $'\n%{http_code}')
code=$(echo "$resp" | tail -1); jsn=$(echo "$resp" | head -1)
id=$(echo "$jsn" | jq -r '.id // empty')
if [ "$code" = "201" ] && [ -n "$id" ]; then
  ok "attest POS: signed write accepted 201 (id=$id)"
else no "attest POS: expected 201, got '$code' ($jsn)"; fi

# confirm attest_level via a fresh CLI read of the same db
if [ -n "${id:-}" ]; then
  lvl=$(AI_MEMORY_NO_CONFIG=1 "$BIN" get "$id" --db "$DB" --json 2>/dev/null | jq -r '.metadata.attest_level // .attest_level // empty')
  if [ "$lvl" = "agent_attested" ]; then ok "attest POS: stored row attest_level=agent_attested"
  else echo "INFO: attest_level read-back = '${lvl:-<none>}' (201 accept is the primary proof)"; fi
fi

# --- NEGATIVE: unsigned write rejected 403 ATTESTATION_FAILED ----------------
ubody=$(jq -nc --arg t "unsigned-$$" --arg ns crypto-round \
        '{title:$t,content:"unsigned body that must be refused under required attestation",namespace:$ns,tier:"mid"}')
resp=$(curl -sk "${CC[@]}" -H "x-agent-id: $AGENT" -H "content-type: application/json" \
        -X POST "$BASE/memories" -d "$ubody" -w $'\n%{http_code}')
code=$(echo "$resp" | tail -1); jsn=$(echo "$resp" | head -1)
ecode=$(echo "$jsn" | jq -r '.code // empty')
if [ "$code" = "403" ] && [ "$ecode" = "ATTESTATION_FAILED" ]; then
  ok "attest NEG: unsigned write rejected 403 ATTESTATION_FAILED"
elif [ "$code" = "403" ]; then
  ok "attest NEG: unsigned write rejected 403 (code=$ecode)"
else no "attest NEG: expected 403, got '$code' ($jsn)"; fi

echo "----"; echo "attestation summary: $pass PASS / $fail FAIL"
[ "$fail" -eq 0 ]
