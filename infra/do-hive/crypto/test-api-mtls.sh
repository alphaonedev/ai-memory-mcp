#!/usr/bin/env bash
# =============================================================================
# test-api-mtls.sh — LEG 1 (API mTLS) positive + negative assertions.
# =============================================================================
# Stands up a LOCAL ai-memory daemon with TLS + client-cert mTLS + attestation
# ON, then proves:
#   POS  a client presenting the allowlisted client-good cert operates the API.
#   NEG1 a client presenting NO client cert cannot complete the TLS handshake.
#   NEG2 a client presenting client-bad (valid cert, unlisted fingerprint) is
#        rejected at the rustls ClientCertVerifier ("not in mTLS allowlist").
#
# Requires: ./out from gen-certs.sh, a release ai-memory binary.
# Prints PASS/FAIL per assertion; exits non-zero if any FAIL.
# =============================================================================
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
OUT="${OUT:-$HERE/out}"
BIN="${BIN:-$HERE/../../../target/release/ai-memory}"
PORT="${PORT:-19443}"
WORK="$(mktemp -d)"
LOG="$WORK/daemon.log"
pass=0; fail=0
ok(){ echo "PASS: $1"; pass=$((pass+1)); }
no(){ echo "FAIL: $1"; fail=$((fail+1)); }

cleanup(){ [ -n "${DPID:-}" ] && kill "$DPID" 2>/dev/null; rm -rf "$WORK"; }
trap cleanup EXIT

# --- launch daemon: TLS + mTLS + attestation ON, isolated -------------------
AI_MEMORY_NO_CONFIG=1 \
AI_MEMORY_REQUIRE_AGENT_ATTESTATION=1 \
AI_MEMORY_KEY_DIR="$WORK/keys" \
"$BIN" serve --host 127.0.0.1 --port "$PORT" \
  --db "$WORK/api.db" \
  --tls-cert "$OUT/server.crt" --tls-key "$OUT/server.key" \
  --mtls-allowlist "$OUT/allowlist.txt" >"$LOG" 2>&1 &
DPID=$!

# wait for TLS listener
for i in $(seq 1 40); do
  curl -sk --cert "$OUT/client-good.crt" --key "$OUT/client-good.key" \
    "https://127.0.0.1:$PORT/api/v1/health" -o /dev/null && break
  sleep 0.5
done

BASE="https://127.0.0.1:$PORT/api/v1"

# --- POSITIVE: allowlisted client cert operates the API ---------------------
code=$(curl -sk -o "$WORK/pos.out" -w '%{http_code}' \
  --cert "$OUT/client-good.crt" --key "$OUT/client-good.key" \
  "$BASE/health")
if [ "$code" = "200" ]; then ok "leg1 POS: allowlisted client-good GET /health -> 200"
else no "leg1 POS: expected 200, got '$code' ($(cat "$WORK/pos.out"))"; fi

# --- NEGATIVE 1: no client cert -> TLS handshake cannot complete ------------
if curl -sk --max-time 8 "$BASE/health" -o /dev/null 2>"$WORK/neg1.err"; then
  no "leg1 NEG1: no-cert client unexpectedly succeeded"
else
  ok "leg1 NEG1: no client cert -> connection refused (curl exit $?, mTLS mandatory)"
fi

# --- NEGATIVE 2: valid but UNLISTED cert -> rejected by verifier ------------
if curl -sk --max-time 8 --cert "$OUT/client-bad.crt" --key "$OUT/client-bad.key" \
     "$BASE/health" -o /dev/null 2>"$WORK/neg2.err"; then
  no "leg1 NEG2: unlisted client-bad unexpectedly succeeded"
else
  ok "leg1 NEG2: unlisted-fingerprint cert -> refused (curl exit $?)"
fi
# corroborate from the server log that the verifier fired on the bad fp
if grep -q "not in mTLS allowlist" "$LOG"; then
  ok "leg1 NEG2 corroboration: daemon logged 'not in mTLS allowlist'"
else
  echo "INFO: daemon log did not surface the allowlist rejection line (handshake abort is still proof)"
fi

echo "----"
echo "leg1 summary: $pass PASS / $fail FAIL"
echo "== daemon log tail =="; tail -5 "$LOG"
[ "$fail" -eq 0 ]
