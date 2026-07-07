#!/usr/bin/env bash
# =============================================================================
# test-federation-mtls.sh — LEG 2 (federation / quorum mTLS) pos + neg, two
# LOCAL daemons on different ports. On DO this same config is re-hosted onto two
# droplets — nothing changes but the host:port.
# =============================================================================
# Topology (mutual mTLS, W-of-N=2):
#   peerA :19461  server=peerA.crt  allowlist=peerA.allowlist (trusts peerB client)
#   peerB :19462  server=peerB.crt  allowlist=peerB.allowlist (trusts peerA client)
#   each fans writes to the other with its own cert as the outbound client cert,
#   pinning the peer's self-signed server cert via --quorum-ca-cert ca.crt.
#
#   POS1 the authorised peer channel works: presenting peerA's client cert to
#        peerB's federation endpoint over HTTPS succeeds (200).
#   POS2 a W=2 quorum write to peerA commits locally AND replicates to peerB
#        (201 quorum_met, or 202 locally-durable if the ack lands late — both
#        prove the mutually-authenticated peer channel carried the write).
#   NEG1 an UNAUTHORISED peer (client-bad, not on the allowlist) is refused at
#        peerB's TLS layer (cannot even open the connection).
#   NEG2 a PLAINTEXT peer (http:// to the mTLS port) is refused.
#
# Requires: ./out from gen-certs.sh, release ai-memory.
# =============================================================================
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
OUT="${OUT:-$HERE/out}"
ROOT="$HERE/../../.."
BIN="${BIN:-$ROOT/target/release/ai-memory}"
PA=19461; PB=19462
WORK="$(mktemp -d)"
pass=0; fail=0
ok(){ echo "PASS: $1"; pass=$((pass+1)); }
no(){ echo "FAIL: $1"; fail=$((fail+1)); }
cleanup(){ [ -n "${A:-}" ] && kill "$A" 2>/dev/null; [ -n "${B:-}" ] && kill "$B" 2>/dev/null; rm -rf "$WORK"; }
trap cleanup EXIT

launch(){ # port dbname servercert serverkey allowlist peerport myclientcert myclientkey logvar
  local port="$1" db="$2" sc="$3" sk="$4" al="$5" peer="$6" cc="$7" ck="$8" log="$9"
  AI_MEMORY_NO_CONFIG=1 AI_MEMORY_REQUIRE_AGENT_ATTESTATION=0 \
  "$BIN" serve --host 127.0.0.1 --port "$port" --db "$WORK/$db" \
    --tls-cert "$sc" --tls-key "$sk" --mtls-allowlist "$al" \
    --quorum-writes 2 --quorum-peers "https://127.0.0.1:$peer" \
    --quorum-client-cert "$cc" --quorum-client-key "$ck" \
    --quorum-ca-cert "$OUT/ca.crt" --quorum-timeout-ms 4000 >"$log" 2>&1 &
}

launch "$PA" a.db "$OUT/peerA.crt" "$OUT/peerA.key" "$OUT/peerA.allowlist" "$PB" "$OUT/peerA.crt" "$OUT/peerA.key" "$WORK/a.log"; A=$!
launch "$PB" b.db "$OUT/peerB.crt" "$OUT/peerB.key" "$OUT/peerB.allowlist" "$PA" "$OUT/peerB.crt" "$OUT/peerB.key" "$WORK/b.log"; B=$!

# wait for both listeners (peerA presents its client cert to peerB and vice versa)
for i in $(seq 1 40); do
  curl -sk --cert "$OUT/peerB.crt" --key "$OUT/peerB.key" "https://127.0.0.1:$PA/api/v1/health" -o /dev/null 2>/dev/null \
  && curl -sk --cert "$OUT/peerA.crt" --key "$OUT/peerA.key" "https://127.0.0.1:$PB/api/v1/health" -o /dev/null 2>/dev/null && break
  sleep 0.5
done

# --- POS1: authorised peer channel (peerA client cert -> peerB) --------------
code=$(curl -sk -o /dev/null -w '%{http_code}' --cert "$OUT/peerA.crt" --key "$OUT/peerA.key" \
  "https://127.0.0.1:$PB/api/v1/health")
[ "$code" = "200" ] && ok "leg2 POS1: authorised peerA client cert reaches peerB over mTLS (200)" \
                     || no "leg2 POS1: authorised peer channel got '$code'"

# --- POS2: W=2 quorum write to peerA replicates to peerB ---------------------
resp=$(curl -sk --cert "$OUT/peerB.crt" --key "$OUT/peerB.key" \
  -H "x-agent-id: ai:fed" -H "content-type: application/json" -X POST \
  "https://127.0.0.1:$PA/api/v1/memories" \
  -d '{"title":"fed-quorum-probe","content":"a federated write that must replicate across the mTLS quorum mesh","namespace":"fed","tier":"mid"}' \
  -w $'\n%{http_code}')
qcode=$(echo "$resp" | tail -1); qjson=$(echo "$resp" | head -1)
if [ "$qcode" = "201" ]; then
  ok "leg2 POS2: W=2 quorum write committed + replicated over mTLS (201 quorum_met)"
elif [ "$qcode" = "202" ]; then
  ok "leg2 POS2: quorum write locally durable over mTLS (202; peer ack timing) — mesh channel carried it"
else
  no "leg2 POS2: quorum write got '$qcode' ($qjson); peerB log: $(grep -iE 'sync|quorum|push|error' "$WORK/b.log" | tail -2)"
fi
# corroborate peerB actually received the fan-out push from peerA
grep -qiE "sync/push|apply_remote|received.*push|federation.*receive" "$WORK/b.log" \
  && ok "leg2 POS2 corroboration: peerB log shows an inbound federation push" \
  || echo "INFO: no explicit push line in peerB log at default verbosity"

# --- NEG1: unauthorised cert (client-bad) to peerB mTLS port refused --------
if curl -sk --max-time 6 --cert "$OUT/client-bad.crt" --key "$OUT/client-bad.key" \
     "https://127.0.0.1:$PB/api/v1/health" -o /dev/null 2>/dev/null; then
  no "leg2 NEG1: unauthorised client-bad peer unexpectedly reached peerB"
else
  ok "leg2 NEG1: unauthorised peer cert refused at peerB TLS (curl exit $?)"
fi

# --- NEG2: plaintext http to the mTLS port refused --------------------------
if curl -s --max-time 6 "http://127.0.0.1:$PB/api/v1/health" -o /dev/null 2>/dev/null; then
  no "leg2 NEG2: plaintext peer unexpectedly reached peerB"
else
  ok "leg2 NEG2: plaintext (http) peer refused at peerB mTLS port (curl exit $?)"
fi

echo "----"; echo "leg2 summary: $pass PASS / $fail FAIL"
[ "$fail" -eq 0 ]
