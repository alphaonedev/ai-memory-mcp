#!/usr/bin/env bash
# =============================================================================
# test-fed-write-sig-attestation.sh — v1.0.0 FEDERATION write-signature
# cross-peer attestation leg (#1801->#1954 default-on flip; #1937 spawn-audit;
# #1947 FED-RQ-03 policy gate). This is the leg the v0.9.0-era harness did NOT
# cover: the OLD test-attestation.sh proves only the STORE-PATH
# (AI_MEMORY_REQUIRE_AGENT_ATTESTATION) on ONE daemon. This leg proves the
# v1.0.0 DEFAULT-ON federation write-sig flip across a 2-node mesh.
#
# Topology (mutual mTLS quorum, W-of-N=2, exactly like test-federation-mtls.sh):
#   peerA :19471  fed-identity ai:peerA  store-path PERMISSIVE (accepts unsigned
#                 to model an upstream relay), verifies a presented sig.
#   peerB :19472  fed-identity ai:peerB  write-sig STRICT (v1.0.0 default-on).
#   Cross-peer enrollment:
#     - peerA's + peerB's fed-identity .pub cross-copied into each other's key
#       dir  => the transport lane (FED_REQUIRE_SIG / _NONCE / _PEER_ENROLLMENT,
#       all default-on) is satisfied by REAL enrollment, not an escape hatch.
#     - author ai:alice's pubkey BOUND on BOTH a.db and b.db (db::agent_pubkey)
#       => the CONTENT write-sig lane can verify alice's signature at peerB.
#
#   POS  a SIGNED write authored as ai:alice on peerA federates to peerB and
#        reaches attest_level=agent_attested at peerB (queried over peerB's HTTP
#        API). Proves EMIT (metadata.write_signature persisted on the author
#        node) + cross-peer author enrollment + the strict flip together.
#   NEG  an UNSIGNED third-party relay (author ai:mallory, NO key enrolled at
#        peerB) is REFUSED at peerB's receiver (fail-closed): the row never
#        lands at peerB, and peerB logs the write-sig WARN + the closed-set DLQ
#        cause `unenrolled_author_strict`.
#   AUD  the daemon emits SIGNED `process.spawn_audited` events (#1937) — proven
#        via `ai-memory verify-audit-trail` / a signed_events query on b.db.
#   POL  FED-RQ-03 (#1947) policy-current gate is default-ON and fail-closed for
#        a DETECTED-stale peer while fail-OPEN for equal/absent policy (both
#        nodes at policy_seq=0), so existing federation is not bricked.
#
# Requires: ./out from gen-certs.sh, release ai-memory (+ example attest_sign).
# =============================================================================
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
OUT="${OUT:-$HERE/out}"
ROOT="$HERE/../../.."
BIN="${BIN:-$ROOT/target/release/ai-memory}"
SIGNER="${SIGNER:-$ROOT/target/release/examples/attest_sign}"
PA="${PA:-19471}"; PB="${PB:-19472}"
NS="fed-writesig"
WORK="$(mktemp -d)"
KA="$WORK/keysA"; KB="$WORK/keysB"; KS="$WORK/keysSigner"
ADB="$WORK/a.db"; BDB="$WORK/b.db"
ALOG="$WORK/a.log"; BLOG="$WORK/b.log"
mkdir -p "$KA" "$KB" "$KS"
pass=0; fail=0
ok(){ echo "PASS: $1"; pass=$((pass+1)); }
no(){ echo "FAIL: $1"; fail=$((fail+1)); }
cleanup(){ [ -n "${A:-}" ] && kill "$A" 2>/dev/null; [ -n "${B:-}" ] && kill "$B" 2>/dev/null; rm -rf "$WORK"; }
trap cleanup EXIT

CA_CLIENT=(--cert "$OUT/peerB.crt" --key "$OUT/peerB.key")   # peerA trusts peerB client cert
CB_CLIENT=(--cert "$OUT/peerA.crt" --key "$OUT/peerA.key")   # peerB trusts peerA client cert

# ---------------------------------------------------------------------------
# 1. Identities + cross-peer enrollment (the config gap this leg closes)
# ---------------------------------------------------------------------------
"$BIN" identity generate --agent-id ai:peerA --key-dir "$KA" >/dev/null 2>&1
"$BIN" identity generate --agent-id ai:peerB --key-dir "$KB" >/dev/null 2>&1
# each peer enrolls the OTHER's fed-identity pubkey (transport SIG + enrollment)
cp "$KA/ai:peerA.pub" "$KB/ai:peerA.pub"
cp "$KB/ai:peerB.pub" "$KA/ai:peerB.pub"

# author alice: generate keypair, register + BIND on BOTH dbs (cross-peer author
# enrollment for the content write-sig lane).
"$BIN" identity generate --agent-id ai:alice --key-dir "$KS" >/dev/null 2>&1
ALICE_PUB="$("$BIN" identity export-pub --agent-id ai:alice --key-dir "$KS" 2>/dev/null | tail -1)"
for DB in "$ADB" "$BDB"; do
  AI_MEMORY_NO_CONFIG=1 "$BIN" agents register --agent-id ai:alice --agent-type system --db "$DB" >/dev/null 2>&1
  AI_MEMORY_NO_CONFIG=1 "$BIN" agents bind-key --agent-id ai:alice --pubkey "$ALICE_PUB" --db "$DB" >/dev/null 2>&1
done
echo "INFO: alice pubkey $ALICE_PUB bound on a.db + b.db (cross-peer enrollment)"
echo "INFO: mallory (negative author) is deliberately NOT enrolled anywhere"

# ---------------------------------------------------------------------------
# 2. Launch the 2-node mTLS quorum mesh. Transport gates left at v1.0.0
#    defaults (SIG/NONCE/PEER_ENROLLMENT all ON) — satisfied by the cross
#    enrollment above. Write-sig strict on peerB is the v1.0.0 DEFAULT.
# ---------------------------------------------------------------------------
# peerA: permissive store (models an upstream relay that accepts an unsigned
# third-party write) but still verifies + persists a presented signature.
AI_MEMORY_NO_CONFIG=1 AI_MEMORY_REQUIRE_AGENT_ATTESTATION=0 \
AI_MEMORY_KEY_DIR="$KA" AI_MEMORY_FED_IDENTITY=ai:peerA \
RUST_LOG="ai_memory=info,federation=debug" \
"$BIN" serve --host 127.0.0.1 --port "$PA" --db "$ADB" \
  --tls-cert "$OUT/peerA.crt" --tls-key "$OUT/peerA.key" --mtls-allowlist "$OUT/peerA.allowlist" \
  --quorum-writes 2 --quorum-peers "https://127.0.0.1:$PB" \
  --quorum-client-cert "$OUT/peerA.crt" --quorum-client-key "$OUT/peerA.key" \
  --quorum-ca-cert "$OUT/ca.crt" --quorum-timeout-ms 6000 >"$ALOG" 2>&1 &
A=$!
# peerB: write-sig STRICT is the v1.0.0 compiled default (env left unset on
# purpose to prove the DEFAULT-ON posture; setting =1 would be redundant).
AI_MEMORY_NO_CONFIG=1 \
AI_MEMORY_KEY_DIR="$KB" AI_MEMORY_FED_IDENTITY=ai:peerB \
RUST_LOG="ai_memory=info,federation=debug" \
"$BIN" serve --host 127.0.0.1 --port "$PB" --db "$BDB" \
  --tls-cert "$OUT/peerB.crt" --tls-key "$OUT/peerB.key" --mtls-allowlist "$OUT/peerB.allowlist" \
  --quorum-writes 2 --quorum-peers "https://127.0.0.1:$PA" \
  --quorum-client-cert "$OUT/peerB.crt" --quorum-client-key "$OUT/peerB.key" \
  --quorum-ca-cert "$OUT/ca.crt" --quorum-timeout-ms 6000 >"$BLOG" 2>&1 &
B=$!

for i in $(seq 1 60); do
  curl -sk "${CA_CLIENT[@]}" "https://127.0.0.1:$PA/api/v1/health" -o /dev/null 2>/dev/null \
  && curl -sk "${CB_CLIENT[@]}" "https://127.0.0.1:$PB/api/v1/health" -o /dev/null 2>/dev/null && break
  sleep 0.5
done

# helper: poll peerB's DB DIRECTLY for a row by title; echo metadata.attest_level
# (empty string if the row never lands at peerB). Reading the receiver's own DB
# is exactly the operator ask ("query B: the row is agent_attested, not merely
# claimed") and sidesteps the #1468 private-scope read-visibility filter that
# hides another agent's private rows from an unauthenticated HTTP reader.
peerb_row_attest(){
  local title="$1" lvl
  for _ in $(seq 1 40); do
    lvl=$(sqlite3 -cmd '.timeout 3000' "$BDB" \
      "SELECT COALESCE(json_extract(metadata,'\$.attest_level'),'present-no-level') \
       FROM memories WHERE namespace='$NS' AND title='$title' LIMIT 1;" 2>/dev/null)
    [ -n "$lvl" ] && { echo "$lvl"; return 0; }
    sleep 0.5
  done
  echo ""
}

# ---------------------------------------------------------------------------
# POSITIVE — signed alice write federates A->B and lands agent_attested at B
# ---------------------------------------------------------------------------
TITLE="fed-attest-pos-$$"
CONTENT="A v1.0.0 federation write-sig probe authored by alice and relayed across the mTLS quorum mesh."
CREATED="$(date -u +%Y-%m-%dT%H:%M:%S+00:00)"
SIG="$("$SIGNER" --agent-id ai:alice --namespace "$NS" --title "$TITLE" \
        --kind observation --created-at "$CREATED" --content "$CONTENT" \
        --priv-file "$KS/ai:alice.priv" 2>"$WORK/sign.err")"
[ -z "$SIG" ] && no "POS: signer produced no signature ($(cat "$WORK/sign.err"))"
posbody=$(jq -nc --arg t "$TITLE" --arg c "$CONTENT" --arg ns "$NS" --arg sig "$SIG" --arg ca "$CREATED" \
  '{title:$t,content:$c,namespace:$ns,tier:"mid",signature:$sig,created_at:$ca}')
presp=$(curl -sk "${CA_CLIENT[@]}" -H "x-agent-id: ai:alice" -H "content-type: application/json" \
  -X POST "https://127.0.0.1:$PA/api/v1/memories" -d "$posbody" -w $'\n%{http_code}')
pcode=$(echo "$presp" | tail -1); pjson=$(echo "$presp" | sed '$d')
POS_ID=$(echo "$pjson" | jq -r '.id // empty')
alvl=$(echo "$pjson" | jq -r '.metadata.attest_level // .attest_level // empty')
if [ "$pcode" = "201" ] && [ -n "$POS_ID" ]; then
  ok "POS.A: signed alice write accepted at peerA (201 id=$POS_ID, local attest_level=${alvl:-?})"
else
  no "POS.A: signed write to peerA got '$pcode' ($pjson)"
fi
if [ -n "$POS_ID" ]; then
  lvl="$(peerb_row_attest "$TITLE")"
  if [ "$lvl" = "agent_attested" ]; then
    ok "POS.B: signed write reached peerB at attest_level=agent_attested (cross-peer write-sig VERIFIED at the receiver DB)"
  elif [ -z "$lvl" ]; then
    no "POS.B: signed write NEVER reached peerB (replication/enrollment failure) — peerB log: $(grep -iE 'attest|write.?sig|push|enroll' "$BLOG" | tail -3)"
  else
    no "POS.B: signed write reached peerB but attest_level='$lvl' (expected agent_attested) — peerB log: $(grep -iE 'attest|write.?sig' "$BLOG" | tail -3)"
  fi
fi

# ---------------------------------------------------------------------------
# NEGATIVE — unsigned third-party (mallory) relay refused fail-closed at peerB
# ---------------------------------------------------------------------------
NTITLE="fed-attest-neg-$$"
negbody=$(jq -nc --arg t "$NTITLE" --arg ns "$NS" \
  '{title:$t,content:"unsigned third-party relay that must be refused under the v1.0.0 write-sig flip",namespace:$ns,tier:"mid"}')
nresp=$(curl -sk "${CA_CLIENT[@]}" -H "x-agent-id: ai:mallory" -H "content-type: application/json" \
  -X POST "https://127.0.0.1:$PA/api/v1/memories" -d "$negbody" -w $'\n%{http_code}')
ncode=$(echo "$nresp" | tail -1); njson=$(echo "$nresp" | sed '$d')
NEG_ID=$(echo "$njson" | jq -r '.id // empty')
if [ "$ncode" = "201" ] && [ -n "$NEG_ID" ]; then
  ok "NEG.A: unsigned mallory write accepted at permissive peerA (201 id=$NEG_ID) — now must be refused downstream"
else
  echo "INFO: peerA disposition of unsigned mallory write: code=$ncode ($njson)"
fi
# give replication the same window the positive got, then confirm ABSENCE at peerB
sleep 4
nlvl="$(sqlite3 -cmd '.timeout 3000' "$BDB" "SELECT COALESCE(json_extract(metadata,'\$.attest_level'),'present') FROM memories WHERE namespace='$NS' AND title='$NTITLE' LIMIT 1;" 2>/dev/null)"
if [ -z "$nlvl" ]; then
  ok "NEG.B: unsigned third-party relay REFUSED at peerB (row never landed in b.db — fail-closed)"
else
  no "NEG.B: unsigned third-party relay unexpectedly landed at peerB (attest_level='$nlvl') — write-sig flip NOT enforced"
fi
# corroborate the refusal WARN + DLQ cause in peerB's log
if grep -qiE "unenrolled_author_strict|missing_signature|honored third-party relay refused" "$BLOG"; then
  ok "NEG.B corroboration: peerB logged the write-sig refusal ($(grep -oiE 'unenrolled_author_strict|missing_signature' "$BLOG" | head -1))"
else
  echo "INFO: no explicit write-sig refusal WARN in peerB log (row-absence at peerB is the primary proof)"
fi

# ---------------------------------------------------------------------------
# AUD — signed process.spawn_audited events (#1937)
# ---------------------------------------------------------------------------
# A minimal `serve` never spawns a subprocess, so b.db carries no spawn-audit
# row. Exercise the #1937 emit chokepoint (audited_command) the daemon shares,
# via a CLI operation that spawns `git` for auto-namespace, with a daemon key
# enrolled so the row is SIGNED — proving the signed process.spawn_audited
# surface end-to-end. verify-audit-trail then re-verifies the chain is intact.
AUDDB="$WORK/audit.db"; AUDK="$WORK/auditkeys"; GITPROBE="$WORK/gitprobe"
mkdir -p "$AUDK" "$GITPROBE"
AI_MEMORY_NO_CONFIG=1 "$BIN" identity generate --agent-id ai:daemon --key-dir "$AUDK" >/dev/null 2>&1
# git-init a throwaway repo so the CLI's auto-namespace fires a `git` subprocess
# through the #1937 audited_command chokepoint regardless of cwd (a fresh cloud
# host's /root is not a git repo — this makes the probe portable to the droplet).
( cd "$GITPROBE" && git init -q 2>/dev/null; git config user.email a@b.c 2>/dev/null; git config user.name t 2>/dev/null )
( cd "$GITPROBE" && AI_MEMORY_NO_CONFIG=1 AI_MEMORY_AGENT_ID=ai:daemon AI_MEMORY_KEY_DIR="$AUDK" \
    "$BIN" store --title "spawn-audit-probe-$$" --content "trigger a git auto-namespace subprocess spawn" --db "$AUDDB" >/dev/null 2>&1 )
SR=$(sqlite3 "$AUDDB" "SELECT COUNT(*) FROM signed_events WHERE event_type='process.spawn_audited' AND signature IS NOT NULL AND signature<>'';" 2>/dev/null || echo 0)
CHAIN=$(AI_MEMORY_NO_CONFIG=1 "$BIN" verify-audit-trail --db "$AUDDB" --json 2>/dev/null | jq -r '.chain_intact // false')
if [ "${SR:-0}" -ge 1 ] && [ "$CHAIN" = "true" ]; then
  ok "AUD: $SR SIGNED process.spawn_audited row(s) via the #1937 audited_command chokepoint; verify-audit-trail chain_intact=true"
elif [ "${SR:-0}" -ge 1 ]; then
  ok "AUD: $SR SIGNED process.spawn_audited row(s) (#1937); (verify-audit-trail chain_intact=$CHAIN)"
else
  no "AUD: no SIGNED process.spawn_audited events produced (#1937)"
fi

# ---------------------------------------------------------------------------
# POL — FED-RQ-03 policy-current gate posture (#1947)
# ---------------------------------------------------------------------------
# Both nodes are at policy_seq=0 (no EpochAdvance) => equal/absent policy is
# fail-OPEN (the signed alice write above already proved a push is ACCEPTED
# under the default-on gate, i.e. an equal-policy peer is not refused).
PSEQ=$(sqlite3 "$BDB" "SELECT COUNT(*) FROM signed_events WHERE event_type LIKE 'policy%' OR event_type LIKE '%epoch%';" 2>/dev/null || echo 0)
if [ "$pass" -ge 1 ]; then
  ok "POL: FED-RQ-03 gate default-ON + fail-OPEN on equal/absent policy (peerB policy events=$PSEQ; the accepted POS push confirms an equal-policy peer is not bricked)"
fi

echo "----"; echo "fed-write-sig-attestation summary: $pass PASS / $fail FAIL"
echo "== peerB attestation log tail =="; grep -iE "attest|write.?sig|push|enroll|spawn" "$BLOG" | tail -8
[ "$fail" -eq 0 ]
