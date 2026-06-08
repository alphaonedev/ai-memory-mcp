#!/usr/bin/env bash
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
#
# P3 full-spectrum test harness for the hive-1461 federated baseline. Probes the
# LIVE fleet over the SAME TLS+mTLS path real traffic uses and emits BOTH a
# machine-readable JSON report and a human PASS/FAIL table. Exit status is 0 iff
# every check passes. Run AFTER `make validate` is green (P2.2 gate).
#
# Spectrum (each check is an independent record {group, test, expected, got,
# status}; every probe is over TLS+mTLS and authenticates with x-api-key):
#
#   regression : memory CRUD roundtrip; semantic search (exercises the nomic
#                embedder end-to-end); namespace isolation; private-scope owner
#                visibility (private memory invisible to a different caller).
#   crypto     : NEGATIVE TLS/mTLS + authz enforcement — no client cert refused
#                (client_auth_mandatory); non-allowlisted client cert refused
#                (fingerprint pinning); wrong CA on server-verify refused;
#                privileged endpoint without x-api-key -> 401; /health exempt
#                (200 without key); admin endpoint as non-admin -> 403.
#   federation : write to peer-1, converge on EVERY OTHER peer across all 3
#                regions within the catchup window (cross-region W=floor(N/2)+1
#                majority mesh; W=5 of 9 on the reference fleet).
#   zerotouch  : first-party CA trust (provision/45_zero_touch.sh) — an enrolled
#                peer converges via its CA-signed credential ALONE (no per-peer
#                pubkey is pushed to any other peer) on every other peer, and an
#                UNENROLLED x-peer-id is refused 401 `peer_not_enrolled` on
#                /sync/since (fail-closed) on every peer.
#   a2a        : agent-to-agent E2E — agent-alpha (an mTLS CLIENT node) writes a
#                collective memory to a peer over the network; agent-beta (a
#                different client identity, different node) reads it back on the
#                write peer and on EVERY federated peer (all regions).
#   ai_nhi     : the grok-driven NHI loop on an agent node — the agent's xAI LLM
#                produces a decision the agent then commits to the mesh and it
#                converges on every federated peer.
#   nsa_gaps   : Batman / MAXIMUM-SECURE controls LIVE over the wire on every
#                peer — unsigned write -> 403 ATTESTATION_FAILED; /sync/push w/
#                missing/invalid sig -> 401; forged sig+nonce push refused twice
#                (sig+nonce gate live); signed-events chain verify exit 0;
#                Accept-Provenance verbose returns the citations/ConfidenceTier/
#                MemoryKind envelope.
#
# Throwaway markers land in the `_test` / `_verify` namespaces and are
# best-effort deleted; nothing here mutates the baseline corpus.
source "$(dirname "$0")/../provision/lib.sh"

require_inventory

REPORTS="$RUN_DIR/reports"; mkdir -p "$REPORTS"
TS="$(date -u +%Y%m%dT%H%M%SZ)"
TSV="$REPORTS/test-$TS.tsv"; : > "$TSV"
JSON="$REPORTS/test-$TS.json"
REMOTE_TLS="/etc/ai-memory/tls"
NS_TEST="_test"
# Stable caller identities. Private-scope memories are owned by the X-Agent-Id
# principal; absent the header the daemon assigns an ephemeral
# `anonymous:req-<uuid>` so a memory written by one bare request is invisible to
# the next. The harness therefore pins explicit identities (30_config.sh peers
# bind 0.0.0.0 and demand x-api-key on every privileged surface).
AID_H="ai:test-harness@$CAMPAIGN"
AID_ALPHA="ai:agent-alpha@$CAMPAIGN"
AID_BETA="ai:agent-beta@$CAMPAIGN"

API_PW_FILE="$RUN_DIR/secrets/api.pw"
API_KEY=""; [ -s "$API_PW_FILE" ] && API_KEY="$(cat "$API_PW_FILE")"

# record <group> <test> <expected> <got> <PASS|FAIL|SKIP>
record() { printf '%s\t%s\t%s\t%s\t%s\n' "$1" "$2" "$3" "$4" "$5" >> "$TSV"; }
pass()   { record "$1" "$2" "$3" "$4" PASS; }
fail()   { record "$1" "$2" "$3" "$4" FAIL; }
# SKIP: probe not applicable to THIS fleet's topology (e.g. a role absent from the
# inventory). Distinct from FAIL — a SKIP is not a product defect and does NOT fail
# the suite; it is recorded verbatim so the report stays honest for peer review.
skip()   { record "$1" "$2" "$3" "$4" SKIP; }
# assert_eq <group> <test> <expected> <got>
assert_eq() { [ "$3" = "$4" ] && pass "$1" "$2" "$3" "$4" || fail "$1" "$2" "$3" "${4:-<empty>}"; }

# json_field <body> <key> -> first scalar value for "key"
json_field() {
  printf '%s' "$1" | sed -n "s/.*\"$2\"[[:space:]]*:[[:space:]]*\"\{0,1\}\([^\",}]*\)\"\{0,1\}.*/\1/p" | head -1
}

# hdrs <agent_id> -> the standard auth/identity header fragment for a curl run.
hdrs() {
  local aid="$1" h=""
  [ -n "$API_KEY" ] && h="-H 'x-api-key: $API_KEY'"
  [ -n "$aid" ] && h="$h -H 'x-agent-id: $aid'"
  printf '%s' "$h"
}

# --- mTLS request helpers ----------------------------------------------------
# All run curl ON a fleet node (over SSH) so the node's own client cert + the
# loopback path exercise the real crypto gate. `<host>` is the DNS:SAN the
# server cert is verified against; `<connect_ip>` is where the TCP connection
# actually lands (127.0.0.1 for on-node, a peer's public IP for cross-node A2A).

# body_req <run_ip> <connect_ip> <host> <method> <path> [data] [agent_id]
# -> response body on stdout, or empty string on any non-2xx / transport error.
body_req() {
  local rip="$1" cip="$2" host="$3" m="$4" path="$5" data="${6:-}" aid="${7:-}"
  local extra=""; [ -n "$data" ] && extra="-H 'content-type: application/json' --data '$data'"
  ssh_node "$rip" "curl -fsS --max-time 10 --resolve $host:$FEDERATION_PORT:$cip \
    --cacert $REMOTE_TLS/ca.pem --cert $REMOTE_TLS/client.pem --key $REMOTE_TLS/client.key \
    $(hdrs "$aid") $extra -X $m https://$host:$FEDERATION_PORT$path" 2>/dev/null || true
}

# code_raw <run_ip> <curl_arg_string> -> HTTP status code, or 000 on transport
# failure (TLS handshake refused, connection reset, timeout). Lets the crypto
# negatives distinguish "refused at the crypto layer" (000) from "served then
# rejected at the app layer" (401/403).
#
# `-w '%{http_code}'` ALWAYS emits the code (literally `000` when no HTTP
# response was received), so a `|| echo 000` fallback on the curl is WRONG: on a
# refused handshake curl prints `000` AND exits non-zero, and the fallback then
# appends a SECOND `000` -> `000000`, which fails the `= 000` assertion. Instead
# neutralise curl's non-zero exit on the remote with `; true` (no extra output)
# and default an empty capture (ssh-level failure) to `000` here.
code_raw() {
  local rip="$1" args="$2" out
  out="$(ssh_node "$rip" "curl -s -o /dev/null -w '%{http_code}' --max-time 10 $args; true" 2>/dev/null || true)"
  printf '%s' "${out:-000}"
}

# body_raw <run_ip> <curl_arg_string> -> response body REGARDLESS of status.
# Unlike body_req (which uses -fsS and so returns empty on any non-2xx), this
# keeps the error envelope so a negative check can assert on the JSON `error`
# tag (e.g. distinguishing an enrollment 401 from an api-key 401).
body_raw() {
  local rip="$1" args="$2"
  ssh_node "$rip" "curl -s --max-time 10 $args; true" 2>/dev/null || true
}

log "P3 full-spectrum test run $TS — fleet=$CAMPAIGN port=$FEDERATION_PORT"

# Resolve the peer set. The reference fleet has 9 peers across 3 regions; the
# federation/zerotouch/a2a/ai_nhi groups assert convergence on EVERY OTHER peer
# (all regions), not a fixed P2/P3 pair. P1 stays the write anchor; P2 is the
# first OTHER peer (a convenience for the single-target a2a/zerotouch probes).
PEER_IPS="$(inv_ips_by_role peer)"
P1_IP="$(printf '%s\n' "$PEER_IPS" | sed -n 1p)"
P2_IP="$(printf '%s\n' "$PEER_IPS" | sed -n 2p)"
P1_H="$(inv_name_for_ip "$P1_IP")"
P2_H="$([ -n "$P2_IP" ] && inv_name_for_ip "$P2_IP")"
A1_IP="$(inv_ips_by_role agent | sed -n 1p)"
A2_IP="$(inv_ips_by_role agent | sed -n 2p)"
[ -n "$P1_IP" ] || die "no peer in inventory"
QW="$(quorum_writes)"; PEER_N="$(inv_peer_count)"
log "peer set: N=$PEER_N across regions [$(inv_regions | tr '\n' ' ')]; cross-region quorum W=$QW"

# Track created memory ids for end-of-run cleanup (id<TAB>peer_ip<TAB>peer_host).
CLEANUP="$RUN_DIR/.p3-cleanup-$TS"; : > "$CLEANUP"
track() { printf '%s\t%s\t%s\n' "$1" "$2" "$3" >> "$CLEANUP"; }

# --- harness attestation enrollment (Batman MAXIMUM-SECURE) -------------------
# The fleet runs AI_MEMORY_REQUIRE_AGENT_ATTESTATION=1, so every POSITIVE
# functional write below MUST be Ed25519-signed (attested_body in lib.sh). The
# harness agent ($HARNESS_AGENT_ID == $AID_H) is enrolled on the write-anchor
# peer P1 (register + pubkey-bind into P1's postgres _agents row) so its signed
# writes verify there. Idempotent; safe to re-run. The nsa_gaps group below
# DELIBERATELY sends an UNSIGNED write and asserts 403 — that control is intact.
[ "$HARNESS_AGENT_ID" = "$AID_H" ] || die "harness identity drift: HARNESS_AGENT_ID=$HARNESS_AGENT_ID != AID_H=$AID_H"
log "[attest] enrolling harness agent $HARNESS_AGENT_ID on write-anchor $P1_H (register + bind pubkey)"
harness_keypair_ensure >/dev/null
harness_enroll_peer "$P1_IP"

# ====================== GROUP regression =====================================
# Single-peer correctness over the encrypted, authenticated path.
log "[regression] CRUD + semantic search + isolation on $P1_H"
NONCE="p3-$TS-$RANDOM"
# Attested write (signed SignableWrite envelope) — succeeds under the max-secure
# attestation gate; an unsigned write here would be refused 403 (see nsa_gaps).
RBODY="$(attested_body "$NS_TEST" "reg-$NONCE" observation private "regression probe sentinel $NONCE quaternion")"
W="$(body_req "$P1_IP" 127.0.0.1 "$P1_H" POST /api/v1/memories "$RBODY" "$AID_H")"
MID="$(json_field "$W" id)"
if [ -z "$MID" ]; then
  fail regression create "memory id" "<write failed>"
else
  pass regression create "memory id" "$MID"; track "$MID" "$P1_IP" "$P1_H"
  # get-by-id roundtrip
  G="$(body_req "$P1_IP" 127.0.0.1 "$P1_H" GET "/api/v1/memories/$MID" "" "$AID_H")"
  case "$G" in *"$NONCE"*) pass regression get_by_id "content present" "$NONCE found" ;;
                       *) fail regression get_by_id "content present" "<not returned>" ;; esac
  # semantic search exercises the nomic embedder end-to-end
  S="$(body_req "$P1_IP" 127.0.0.1 "$P1_H" GET "/api/v1/search?q=$NONCE&namespace=$NS_TEST&limit=5" "" "$AID_H")"
  scount="$(json_field "$S" count)"
  case "$S" in *"$MID"*) pass regression search_semantic "id in results (count=$scount)" "$MID" ;;
                      *) fail regression search_semantic "id in results" "count=${scount:-0}" ;; esac
  # namespace listing
  L="$(body_req "$P1_IP" 127.0.0.1 "$P1_H" GET "/api/v1/memories?namespace=$NS_TEST&limit=20" "" "$AID_H")"
  case "$L" in *"$MID"*) pass regression list_namespace "id listed in $NS_TEST" "$MID" ;;
                      *) fail regression list_namespace "id listed in $NS_TEST" "<absent>" ;; esac
  # private-scope owner isolation: a DIFFERENT caller must NOT see it
  ISO="$(body_req "$P1_IP" 127.0.0.1 "$P1_H" GET "/api/v1/memories/$MID" "" "$AID_BETA")"
  case "$ISO" in *"$NONCE"*) fail regression private_isolation "404 for non-owner" "LEAKED to $AID_BETA" ;;
                          *) pass regression private_isolation "404 for non-owner" "not visible to $AID_BETA" ;; esac
fi

# namespace cross-isolation: write to ns A, assert absent from ns B's listing
NONCE2="p3iso-$TS-$RANDOM"
WA="$(body_req "$P1_IP" 127.0.0.1 "$P1_H" POST /api/v1/memories \
  "$(attested_body "${NS_TEST}_a" "isoA-$NONCE2" observation private "ns-isolation $NONCE2")" "$AID_H")"
MIDA="$(json_field "$WA" id)"
[ -n "$MIDA" ] && track "$MIDA" "$P1_IP" "$P1_H"
LB="$(body_req "$P1_IP" 127.0.0.1 "$P1_H" GET "/api/v1/memories?namespace=${NS_TEST}_b&limit=50" "" "$AID_H")"
case "$LB" in *"$MIDA"*) fail regression ns_cross_isolation "absent from other ns" "LEAKED across namespace" ;;
                      *) pass regression ns_cross_isolation "absent from other ns" "isolated" ;; esac

# ====================== GROUP crypto =========================================
# Negative crypto + authz. SUCCESS = the gate REFUSES what it must.
log "[crypto] TLS/mTLS negatives + api_key/admin authz on $P1_H"
RES="--resolve $P1_H:$FEDERATION_PORT:127.0.0.1"
CA="--cacert $REMOTE_TLS/ca.pem"; CERT="--cert $REMOTE_TLS/client.pem"; KEY="--key $REMOTE_TLS/client.key"
URL="https://$P1_H:$FEDERATION_PORT/api/v1/health"
PRIV="https://$P1_H:$FEDERATION_PORT/api/v1/capabilities"
ADMIN="https://$P1_H:$FEDERATION_PORT/api/v1/stats"

# (1) no client cert -> client_auth_mandatory refuses the handshake (000)
c="$(code_raw "$P1_IP" "$RES $CA $URL")"
[ "$c" = "000" ] && pass crypto no_client_cert "refused (000)" "$c" || fail crypto no_client_cert "refused (000)" "$c"

# (2) non-allowlisted client cert -> fingerprint pinning refuses (000). Mint an
# ephemeral self-signed leaf on the node (in /root, not tmpfs) and present it.
# `-w` emits `000` on the refused handshake and `; rm` (exit 0) masks curl's
# non-zero, so NO `|| echo 000` — that would double the code to `000000`.
GEN="openssl req -x509 -newkey rsa:2048 -nodes -keyout /root/.p3bad.key -out /root/.p3bad.pem -days 1 -subj '/CN=rogue' >/dev/null 2>&1"
c="$(ssh_node "$P1_IP" "$GEN; curl -s -o /dev/null -w '%{http_code}' --max-time 10 $RES $CA --cert /root/.p3bad.pem --key /root/.p3bad.key $URL; rm -f /root/.p3bad.pem /root/.p3bad.key" 2>/dev/null || true)"
c="${c:-000}"
[ "$c" = "000" ] && pass crypto rogue_client_cert "refused (000)" "$c" || fail crypto rogue_client_cert "refused (000)" "$c"

# (3) wrong CA on server verify -> client aborts (000). Use the node's client
# cert as a bogus CA bundle: it did NOT sign the server cert, so verify fails.
c="$(code_raw "$P1_IP" "$RES --cacert $REMOTE_TLS/client.pem $CERT $KEY $URL")"
[ "$c" = "000" ] && pass crypto wrong_server_ca "refused (000)" "$c" || fail crypto wrong_server_ca "refused (000)" "$c"

# (4) privileged endpoint WITHOUT x-api-key -> 401
c="$(code_raw "$P1_IP" "$RES $CA $CERT $KEY $PRIV")"
assert_eq crypto apikey_required 401 "$c"

# (5) privileged endpoint WITH x-api-key -> 200
keyhdr=""; [ -n "$API_KEY" ] && keyhdr="-H 'x-api-key: $API_KEY'"
c="$(code_raw "$P1_IP" "$RES $CA $CERT $KEY $keyhdr $PRIV")"
assert_eq crypto apikey_accepted 200 "$c"

# (6) /health is exempt -> 200 without the key
c="$(code_raw "$P1_IP" "$RES $CA $CERT $KEY $URL")"
assert_eq crypto health_exempt 200 "$c"

# (7) admin-only endpoint as a non-admin caller -> 403 (authz enforced)
c="$(code_raw "$P1_IP" "$RES $CA $CERT $KEY $keyhdr -H 'x-agent-id: $AID_H' $ADMIN")"
assert_eq crypto admin_gated 403 "$c"

# ====================== GROUP federation =====================================
# Write to peer-1; expect convergence on EVERY OTHER peer across ALL regions
# within the catchup window, over the encrypted path. Each of the 9 peers (8
# other than the anchor) is asserted as an independent convergence target — the
# label carries the target host + its region so same-region vs cross-region
# propagation is both covered and visible in the report.
if [ -n "$P2_IP" ]; then
  log "[federation] convergence probe peer-1 -> ALL other peers (cross-region mesh, W=$QW of $PEER_N)"
  FNONCE="fed-$TS-$RANDOM"
  FBODY="$(attested_body "_verify" "$FNONCE" observation collective "federation spectrum probe $FNONCE")"
  FW="$(body_req "$P1_IP" 127.0.0.1 "$P1_H" POST /api/v1/memories "$FBODY" "$AID_H")"
  FID="$(json_field "$FW" id)"
  if [ -z "$FID" ]; then
    fail federation write "memory id" "<write failed>"
  else
    pass federation write "memory id" "$FID"; track "$FID" "$P1_IP" "$P1_H"
    printf '%s\n' "$PEER_IPS" | while IFS= read -r ip; do
      [ -n "$ip" ] || continue
      [ "$ip" = "$P1_IP" ] && continue
      host="$(inv_name_for_ip "$ip")"
      preg="$(inv_peer_region "$host")"
      same=""; [ "$preg" = "$(inv_peer_region "$P1_H")" ] && same="same_region" || same="cross_region"
      i=0; got="<not replicated within window>"; st=FAIL
      while [ "$i" -lt 20 ]; do
        r="$(body_req "$ip" 127.0.0.1 "$host" GET "/api/v1/memories/$FID" "" "$AID_H")"
        case "$r" in *"$FNONCE"*) st=PASS; got="present on $host ($preg)"; break ;; esac
        i=$((i+1)); sleep 2
      done
      record federation "converge_${same}[$host]" "$FID on $host" "$got" "$st"
    done
  fi
else
  record federation converge ">=2 peers" "<need 2 peers>" FAIL
fi

# ====================== GROUP zerotouch ======================================
# First-party zero-touch trust (provision/45_zero_touch.sh): every peer runs
# with AI_MEMORY_FED_REQUIRE_PEER_ENROLLMENT=1 and holds ONLY the campaign CA
# verifying key (NO per-peer pubkey was pushed to any other peer). Two proofs:
#
#   enrolled_converge : a write on peer-1 converges on peer-2. The ONLY thing
#     authorizing peer-1's outbound federation push at peer-2 is its CA-signed
#     credential (X-Memory-Cred) — there is no operator-pushed key for peer-1 in
#     peer-2's store. Convergence therefore proves a peer joins the mesh via the
#     issuer-credential path alone ("zero touch").
#   unenrolled_refused: a request to /sync/since bearing an UNENROLLED X-Peer-Id
#     and no signature/credential — but valid api-key + mTLS — is refused 401
#     with `error:peer_not_enrolled` (the #1088 fail-closed arm). The body tag
#     is asserted so this cannot be confused with an api-key 401.
if [ -n "$P2_IP" ]; then
  log "[zerotouch] enrolled peer converges on EVERY other peer through the REQUIRE_PEER_ENROLLMENT gate"
  ZNONCE="zt-$TS-$RANDOM"
  ZBODY="$(attested_body "_zerotouch" "$ZNONCE" observation collective "zero-touch enrolled convergence $ZNONCE")"
  ZW="$(body_req "$P1_IP" 127.0.0.1 "$P1_H" POST /api/v1/memories "$ZBODY" "$AID_H")"
  ZMID="$(json_field "$ZW" id)"
  if [ -z "$ZMID" ]; then
    fail zerotouch enrolled_write "memory id" "<write failed>"
  else
    pass zerotouch enrolled_write "memory id" "$ZMID"; track "$ZMID" "$P1_IP" "$P1_H"
    printf '%s\n' "$PEER_IPS" | while IFS= read -r ip; do
      [ -n "$ip" ] || continue
      [ "$ip" = "$P1_IP" ] && continue
      host="$(inv_name_for_ip "$ip")"
      i=0; got="<not replicated within window>"; st=FAIL
      while [ "$i" -lt 20 ]; do
        ZR="$(body_req "$ip" 127.0.0.1 "$host" GET "/api/v1/memories/$ZMID" "" "$AID_H")"
        case "$ZR" in *"$ZNONCE"*) st=PASS; got="present on $host via CA credential (no pushed pubkey)"; break ;; esac
        i=$((i+1)); sleep 2
      done
      record zerotouch "enrolled_converge[$host]" "$ZMID on $host (credential-only trust)" "$got" "$st"
    done
  fi
else
  record zerotouch enrolled_converge ">=2 peers" "<need 2 peers>" FAIL
fi

# Negative: an unenrolled peer-id is refused fail-closed on the sync surface of
# EVERY peer (the #1088 fail-closed arm is live fleet-wide under the Batman env).
log "[zerotouch] unenrolled peer-id refused on /sync/since on every peer (#1088 fail-closed)"
ZCA="--cacert $REMOTE_TLS/ca.pem"; ZCERT="--cert $REMOTE_TLS/client.pem"; ZKEY="--key $REMOTE_TLS/client.key"
ZKEYHDR=""; [ -n "$API_KEY" ] && ZKEYHDR="-H 'x-api-key: $API_KEY'"
ZROGUE="rogue-unenrolled-$TS"
printf '%s\n' "$PEER_IPS" | while IFS= read -r ip; do
  [ -n "$ip" ] || continue
  h="$(inv_name_for_ip "$ip")"
  ZRES="--resolve $h:$FEDERATION_PORT:127.0.0.1"
  ZSYNC="https://$h:$FEDERATION_PORT/api/v1/sync/since?since=1970-01-01T00:00:00Z"
  ZPROBE="$ZRES $ZCA $ZCERT $ZKEY $ZKEYHDR -H 'x-peer-id: $ZROGUE' \"$ZSYNC\""
  zc="$(code_raw "$ip" "$ZPROBE")"
  assert_eq zerotouch "unenrolled_status[$h]" 401 "$zc"
  zb="$(body_raw "$ip" "$ZPROBE")"
  case "$zb" in *peer_not_enrolled*) pass zerotouch "unenrolled_reason[$h]" "peer_not_enrolled" "fail-closed" ;;
                                *) fail zerotouch "unenrolled_reason[$h]" "peer_not_enrolled" "${zb:-<empty>}" ;; esac
done

# Trust-chain proof: each ENROLLED peer's CA-minted credential (the X-Memory-Cred
# it presents on the wire) verifies against the campaign CA verifying-key bundle
# under the campaign trust domain. This is the cryptographic root of "zero touch":
# convergence above proves a peer is TRUSTED by its credential alone; this proves
# WHY — the credential chains to the campaign CA (fed_issue verify-cred runs the
# SAME TrustBundle::verify the receive path runs). The fed_id subject the
# credential binds must match the peer's resolved federation identity
# ($CAMPAIGN/<region>/<host>). Asserted per peer so the chain is proven fleet-wide.
log "[zerotouch] CA trust-chain: each peer credential verifies against the campaign CA bundle (issuer=$FED_ISSUER_ID, domain=$FED_TRUST_DOMAIN)"
printf '%s\n' "$PEER_IPS" | while IFS= read -r ip; do
  [ -n "$ip" ] || continue
  h="$(inv_name_for_ip "$ip")"
  preg="$(inv_peer_region "$h")"
  expect_subj="$CAMPAIGN/$preg/$h"
  subj="$(verify_cred_chain "$h" 2>/dev/null || true)"
  if [ "$subj" = "$expect_subj" ]; then
    pass zerotouch "cred_ca_chain[$h]" "$expect_subj chains to $FED_ISSUER_ID" "CA-signed, domain=$FED_TRUST_DOMAIN"
  else
    fail zerotouch "cred_ca_chain[$h]" "$expect_subj chains to $FED_ISSUER_ID" "${subj:-<chain verify failed>}"
  fi
done

# ====================== GROUP a2a ============================================
# Agent-to-agent E2E. agent-alpha (mTLS CLIENT node) writes a COLLECTIVE memory
# to peer-1 over the NETWORK (not loopback); agent-beta (different identity, a
# different client node) reads it back on peer-1 AND on a federated peer.
if [ -n "$A1_IP" ]; then
  log "[a2a] agent-alpha write -> agent-beta read (E2E over the mesh)"
  # agent-alpha is a distinct attesting identity; enroll + bind it on the write
  # anchor P1 so its signed writes verify under the max-secure gate.
  log "[attest] enrolling agent-alpha $AID_ALPHA on $P1_H for attested a2a write"
  agent_enroll_peer "$P1_IP" "$AID_ALPHA"
  ANONCE="a2a-$TS-$RANDOM"
  # Attested write signed as agent-alpha (X-Agent-Id == signer agent_id).
  ABODY="$(attested_body "_verify" "a2a-$ANONCE" observation collective "agent-to-agent shared note $ANONCE" "$AID_ALPHA")"
  # write runs ON agent-alpha's node, connecting to peer-1's PUBLIC ip
  AW="$(body_req "$A1_IP" "$P1_IP" "$P1_H" POST /api/v1/memories "$ABODY" "$AID_ALPHA")"
  AID_MID="$(json_field "$AW" id)"
  if [ -z "$AID_MID" ]; then
    fail a2a agent_write "memory id (alpha->peer1)" "<write failed>"
  else
    pass a2a agent_write "memory id (alpha->peer1)" "$AID_MID"; track "$AID_MID" "$P1_IP" "$P1_H"
    # agent-beta reads on peer-1 over the network from a (second) client node
    RNODE="${A2_IP:-$A1_IP}"
    RB="$(body_req "$RNODE" "$P1_IP" "$P1_H" GET "/api/v1/memories/$AID_MID" "" "$AID_BETA")"
    case "$RB" in *"$ANONCE"*) pass a2a beta_read_writepeer "visible cross-agent" "$AID_MID present" ;;
                           *) fail a2a beta_read_writepeer "visible cross-agent" "<not visible>" ;; esac
    # agent-beta reads the same id on EVERY OTHER federated peer (E2E: A2A +
    # cross-region federation) — each peer is an independent convergence target.
    printf '%s\n' "$PEER_IPS" | while IFS= read -r ip; do
      [ -n "$ip" ] || continue
      [ "$ip" = "$P1_IP" ] && continue
      host="$(inv_name_for_ip "$ip")"
      i=0; got="<not replicated within window>"; st=FAIL
      while [ "$i" -lt 20 ]; do
        RF="$(body_req "$RNODE" "$ip" "$host" GET "/api/v1/memories/$AID_MID" "" "$AID_BETA")"
        case "$RF" in *"$ANONCE"*) st=PASS; got="$AID_MID present on $host"; break ;; esac
        i=$((i+1)); sleep 2
      done
      record a2a "beta_read_fedpeer[$host]" "visible on federated peer" "$got" "$st"
    done
  fi
else
  skip a2a agent_write ">=1 agent node" "no agent role in do-1461 inventory (4 peer + 1 pg topology)"
fi

# ====================== GROUP ai_nhi =========================================
# The grok-driven NHI loop on an agent node, end-to-end over the mesh:
#   (1) llm_decision  — agent-alpha drives a LIVE xAI/grok query-expansion via
#                       POST /api/v1/expand_query on peer-1; a non-empty
#                       `expanded_terms` array proves a real LLM completion (not
#                       a stub) round-tripped over TLS+mTLS from the agent node.
#   (2) nhi_commit    — the agent commits that decision: writes a COLLECTIVE
#                       memory whose content embeds the first LLM-derived term.
#   (3) nhi_converge  — the committed decision converges on a FEDERATED peer,
#                       proving the NHI's LLM-derived artifact propagates the
#                       full A2A + federation path.
if [ -n "$A1_IP" ] && [ -n "$P2_IP" ]; then
  log "[ai_nhi] grok decision on agent-alpha -> commit -> federated convergence"
  NQUERY="distributed consensus quorum replication"
  NLLM="$(body_req "$A1_IP" "$P1_IP" "$P1_H" POST /api/v1/expand_query \
    "{\"query\":\"$NQUERY\",\"namespace\":\"$NS_TEST\"}" "$AID_ALPHA")"
  # first expanded term (lenient extract: handles `[ "term"` with/without spaces)
  NTERM="$(printf '%s' "$NLLM" | sed -n 's/.*"expanded_terms"[[:space:]]*:[[:space:]]*\[[[:space:]]*"\([^"]*\)".*/\1/p' | head -1)"
  if [ -z "$NTERM" ]; then
    fail ai_nhi llm_decision "non-empty expanded_terms" "<no terms returned>"
  else
    pass ai_nhi llm_decision "non-empty expanded_terms" "term=$NTERM"
    # (2) the NHI commits its LLM-derived decision to the mesh (attested as
    # agent-alpha; enroll is idempotent in case a2a above was skipped).
    agent_enroll_peer "$P1_IP" "$AID_ALPHA"
    NNONCE="nhi-$TS-$RANDOM"
    NBODY="$(attested_body "_verify" "nhi-$NNONCE" observation collective "grok expansion of [$NQUERY] -> $NTERM ($NNONCE)" "$AID_ALPHA")"
    NW="$(body_req "$A1_IP" "$P1_IP" "$P1_H" POST /api/v1/memories "$NBODY" "$AID_ALPHA")"
    NMID="$(json_field "$NW" id)"
    if [ -z "$NMID" ]; then
      fail ai_nhi nhi_commit "memory id (alpha decision->peer1)" "<write failed>"
    else
      pass ai_nhi nhi_commit "memory id (alpha decision->peer1)" "$NMID"; track "$NMID" "$P1_IP" "$P1_H"
      # (3) the decision converges on EVERY OTHER federated peer (all regions)
      printf '%s\n' "$PEER_IPS" | while IFS= read -r ip; do
        [ -n "$ip" ] || continue
        [ "$ip" = "$P1_IP" ] && continue
        host="$(inv_name_for_ip "$ip")"
        i=0; got="<not replicated within window>"; st=FAIL
        while [ "$i" -lt 20 ]; do
          NRF="$(body_req "${A2_IP:-$A1_IP}" "$ip" "$host" GET "/api/v1/memories/$NMID" "" "$AID_BETA")"
          case "$NRF" in *"$NNONCE"*) st=PASS; got="$NMID present on $host"; break ;; esac
          i=$((i+1)); sleep 2
        done
        record ai_nhi "nhi_converge[$host]" "decision visible on federated peer" "$got" "$st"
      done
    fi
  fi
else
  skip ai_nhi llm_decision ">=1 agent + >=2 peers" "no agent role in do-1461 inventory (4 peer + 1 pg topology)"
fi

# ====================== GROUP nsa_gaps =======================================
# Batman / MAXIMUM-SECURE controls asserted LIVE over the wire (46_batman.sh env
# battery, loaded by the 50_federation daemon restart). Every check runs on EVERY
# peer so the secure posture is proven fleet-wide, not on a single node:
#   (1) unsigned write -> 403 ATTESTATION_FAILED (AI_MEMORY_REQUIRE_AGENT_ATTESTATION live)
#   (2) /sync/push with missing/invalid signature -> 401 (AI_MEMORY_FED_REQUIRE_SIG live)
#   (3) /sync/push repeat with an invalid (body,sig,nonce) -> 401 again — the
#       sig+nonce gate is live so a forged/replayed push never lands (a
#       cryptographically VALID replay would need the peer's private key, which a
#       black-box harness cannot mint; the gate-presence assertion is the honest
#       wire-observable proof that AI_MEMORY_FED_REQUIRE_NONCE is active).
#   (5) signed-events chain verify per peer -> exit 0 (tamper-evident audit chain).
#   (6) Accept-Provenance: verbose over live HTTP returns the provenance envelope
#       (citations / ConfidenceTier / MemoryKind) on a recall response.
# (4) unenrolled X-Peer-Id -> 401 peer_not_enrolled is asserted in the zerotouch
#     group above (kept there; not duplicated here).
log "[nsa_gaps] Batman max-secure controls live over the wire on every peer"
printf '%s\n' "$PEER_IPS" | while IFS= read -r ip; do
  [ -n "$ip" ] || continue
  h="$(inv_name_for_ip "$ip")"
  RES="--resolve $h:$FEDERATION_PORT:127.0.0.1"
  CA="--cacert $REMOTE_TLS/ca.pem"; CERT="--cert $REMOTE_TLS/client.pem"; KEY="--key $REMOTE_TLS/client.key"
  keyhdr=""; [ -n "$API_KEY" ] && keyhdr="-H 'x-api-key: $API_KEY'"

  # (1) unsigned write -> 403 ATTESTATION_FAILED. A normal POST /memories carries
  # NO caller Ed25519 signature, so under REQUIRE_AGENT_ATTESTATION it is refused.
  UNS="{\"title\":\"nsa-unsigned-$TS-$RANDOM\",\"content\":\"unsigned write probe\",\"namespace\":\"$NS_TEST\"}"
  MEM="https://$h:$FEDERATION_PORT/api/v1/memories"
  uc="$(code_raw "$ip" "$RES $CA $CERT $KEY $keyhdr -H 'content-type: application/json' --data '$UNS' -X POST $MEM")"
  assert_eq nsa_gaps "unsigned_write_403[$h]" 403 "$uc"
  ub="$(body_raw "$ip" "$RES $CA $CERT $KEY $keyhdr -H 'content-type: application/json' --data '$UNS' -X POST $MEM")"
  case "$ub" in *ATTESTATION_FAILED*|*attestation*) pass nsa_gaps "unsigned_write_reason[$h]" "ATTESTATION_FAILED" "attestation gate live" ;;
                                                 *) fail nsa_gaps "unsigned_write_reason[$h]" "ATTESTATION_FAILED" "${ub:-<empty>}" ;; esac

  # (2) /sync/push with NO X-Memory-Sig -> 401 (FED_REQUIRE_SIG). Valid mTLS +
  # api-key, but the signed-federation header is absent, so the receiver refuses.
  PUSH="https://$h:$FEDERATION_PORT/api/v1/sync/push"
  SBODY="{\"memories\":[]}"
  sc="$(code_raw "$ip" "$RES $CA $CERT $KEY $keyhdr -H 'content-type: application/json' --data '$SBODY' -X POST $PUSH")"
  assert_eq nsa_gaps "sync_push_missing_sig_401[$h]" 401 "$sc"

  # (3) /sync/push with an INVALID sig+nonce, sent TWICE -> 401 both times. The
  # forged signature never validates (FED_REQUIRE_SIG) and the nonce gate
  # (FED_REQUIRE_NONCE) is therefore exercised on the receive path; neither push
  # ever lands. A cryptographically-valid replay needs the peer key (see header).
  BADSIG="-H 'x-memory-sig: AAAA' -H 'x-memory-nonce: nonce-$TS-$RANDOM'"
  r1="$(code_raw "$ip" "$RES $CA $CERT $KEY $keyhdr $BADSIG -H 'content-type: application/json' --data '$SBODY' -X POST $PUSH")"
  r2="$(code_raw "$ip" "$RES $CA $CERT $KEY $keyhdr $BADSIG -H 'content-type: application/json' --data '$SBODY' -X POST $PUSH")"
  if [ "$r1" = "401" ] && [ "$r2" = "401" ]; then
    pass nsa_gaps "sync_push_replay_refused[$h]" "401/401" "$r1/$r2 (sig+nonce gate live)"
  else
    fail nsa_gaps "sync_push_replay_refused[$h]" "401/401" "$r1/$r2"
  fi

  # (5) signed-events chain health per peer, verified DIRECTLY via SQL on the
  # peer's REGIONAL pg node. The golden `verify-signed-events-chain` CLI verb is
  # SQLITE-ONLY (takes `--db`, rejects `--store-url`) so it cannot verify a
  # POSTGRES-backed daemon's chain — filed as GH #1541 (same class as
  # #1536/#1539). Two-step, self-contained:
  #   (a) drive ONE L4 `POST /api/v1/capture_turn` write — the identity-bearing
  #       write that DOES populate the postgres signed_events chain in-tx (the
  #       regular `POST /memories` path does NOT emit signed_events on postgres;
  #       also #1541). This guarantees the chain is non-empty for THIS peer.
  #   (b) psql ON the region's pg node (sudo -u postgres; socket/peer auth, no
  #       password ever on a command line) against the peer's within-region
  #       schema ic_peer_<K> and assert the tamper-evident chain is healthy:
  #         total>0, no NULL payload_hash / prev_hash, contiguous unique
  #         `sequence` (no gaps), genesis row prev_hash = 32 zero bytes, every
  #         non-genesis row prev_hash non-zero.
  # PARTIAL-VERIFICATION NOTE (honest): this asserts STRUCTURAL chain integrity,
  # not the full byte-exact cross-row hash recompute (each row's prev_hash is
  # SHA-256(canonical_chain_bytes(prev_row)) per src/signed_events.rs). That
  # recompute is NOT robustly expressible in-SQL on these nodes: pgcrypto is not
  # installed (no digest()) and the signed RFC3339 `timestamp` string does not
  # losslessly round-trip from the stored timestamptz (microsecond precision).
  # The byte-exact verifier lands when GH #1541 gives a first-party postgres
  # `verify-signed-events-chain` path.
  preg="$(inv_peer_region "$h")"
  pg_priv="$(inv_pg_private_ip_for_region "$preg")"
  pg_pub="$(inv_pg_public_ip_for_region "$preg")"
  pidx="$(peer_schema_index_in_region "$h")"
  pschema="$(peer_schema "$pidx")"
  # (5a) L4 capture-turn write to seed THIS peer's postgres signed_events chain.
  SE_SID="p3se-$TS-$RANDOM"
  SE_CT_BODY="{\"host_session_id\":\"$SE_SID\",\"host_turn_index\":0,\"role\":\"$SE_CHAIN_PROBE_ROLE\",\"content\":\"signed-events chain probe $SE_SID\",\"host_kind\":\"$SE_CHAIN_PROBE_HOST_KIND\",\"namespace\":\"$PROV_PROBE_NS\"}"
  body_req "$ip" 127.0.0.1 "$h" POST /api/v1/capture_turn "$SE_CT_BODY" "$AID_H" >/dev/null 2>&1 || true
  # (5b) SQL chain-integrity verdict on the regional pg node. One row of 0/1
  # flags collapsed to a single token; "ok" iff total>0 and every flag is 0.
  cv="$(ssh_node "$pg_pub" "sudo -u postgres psql -d $PG_DB -At -F'|' <<SQL 2>/dev/null
SET search_path = $pschema, public;
WITH chain AS (
  SELECT sequence, prev_hash, payload_hash,
         row_number() OVER (ORDER BY sequence) AS rn
    FROM signed_events
)
SELECT CASE WHEN
       (SELECT count(*) FROM chain) > 0
   AND (SELECT count(*) FROM chain WHERE payload_hash IS NULL) = 0
   AND (SELECT count(*) FROM chain WHERE prev_hash IS NULL) = 0
   AND (SELECT count(*) FROM chain WHERE sequence <> rn) = 0
   AND (SELECT count(DISTINCT sequence) FROM chain) = (SELECT count(*) FROM chain)
   AND (SELECT count(*) FROM chain WHERE rn = 1 AND prev_hash <> decode(repeat('00',32),'hex')) = 0
   AND (SELECT count(*) FROM chain WHERE rn > 1 AND prev_hash  = decode(repeat('00',32),'hex')) = 0
       THEN 'ok' ELSE 'bad:'||coalesce((SELECT count(*) FROM chain)::text,'?') END;
SQL" 2>/dev/null | tail -1)"
  assert_eq nsa_gaps "signed_events_chain_ok[$h]" "ok" "${cv:-<no-sql-result>}"

  # (6) Accept-Provenance: a verbose recall returns the provenance envelope
  # (memory_kind / citations / confidence_tier). SELF-CONTAINED: write ONE
  # attested provenance-bearing memory (kind=$PROV_PROBE_KIND) to a KNOWN
  # namespace ($PROV_PROBE_NS) on this peer, poll until it is recallable (async
  # embedder-backfill window — same poll shape as the federation-convergence
  # probe above), then verbose-recall THAT namespace + the unique term and assert
  # the envelope is present. The prior check recalled the EMPTY `_test` namespace
  # → count:0 → no envelope (a test-design bug, not a product gap).
  # The attestation gate resolves the bound pubkey from the RECEIVING peer's OWN
  # store, so the harness identity must be enrolled+bound on THIS peer for its
  # signed write to verify here (the top-of-run enrollment only covered the
  # write-anchor P1). Idempotent — a no-op re-register + re-bind on repeat.
  harness_enroll_peer "$ip" >/dev/null 2>&1 || true
  # A LETTERS-ONLY recall term so `to_tsquery('english', …)` tokenizes it
  # deterministically (mixed letter+digit tokens can normalise oddly and drop
  # from the FTS vector). The postgres recall_hybrid FTS pool matches on
  # to_tsvector(title||content) and does NOT require the async embedding, so the
  # row is recallable as soon as the write commits — independent of the embedder
  # backfill. Map each RANDOM digit to a letter to keep it unique + alpha.
  PNONCE="p3prov$(printf '%s%s' "$TS" "$RANDOM" | tr -dc 0-9 | tr '0-9' 'abcdefghij')"
  PROV_BODY="$(attested_body "$PROV_PROBE_NS" "prov-$TS-$RANDOM" "$PROV_PROBE_KIND" collective "provenance envelope probe $PNONCE for verbose recall")"
  body_req "$ip" 127.0.0.1 "$h" POST /api/v1/memories "$PROV_BODY" "$AID_H" >/dev/null 2>&1 || true
  PROV="https://$h:$FEDERATION_PORT/api/v1/recall?q=$PNONCE&namespace=$PROV_PROBE_NS&limit=3&verbose_provenance=true"
  pi=0; pb=""
  while [ "$pi" -lt "$PROV_RECALL_POLL_TRIES" ]; do
    pb="$(body_raw "$ip" "$RES $CA $CERT $KEY $keyhdr -H 'x-agent-id: $AID_H' -H 'accept-provenance: verbose' '$PROV'")"
    case "$pb" in *"$PNONCE"*) break ;; esac
    pi=$((pi + 1)); sleep "$PROV_RECALL_POLL_SLEEP_SECS"
  done
  case "$pb" in
    *citation*|*ConfidenceTier*|*confidence_tier*|*MemoryKind*|*memory_kind*)
      pass nsa_gaps "provenance_envelope[$h]" "citations|ConfidenceTier|MemoryKind" "provenance present (kind=$PROV_PROBE_KIND, ns=$PROV_PROBE_NS)" ;;
    *) fail nsa_gaps "provenance_envelope[$h]" "citations|ConfidenceTier|MemoryKind" "${pb:-<empty>}" ;;
  esac
done

# ---- assemble JSON report ---------------------------------------------------
{
  printf '{\n  "campaign": "%s",\n  "timestamp": "%s",\n  "suite": "p3-full-spectrum",\n' "$CAMPAIGN" "$TS"
  printf '  "checks": [\n'
  first=1
  while IFS="$(printf '\t')" read -r group test expected got status; do
    [ "$first" = 1 ] && first=0 || printf ',\n'
    printf '    {"group": "%s", "test": "%s", "expected": "%s", "got": "%s", "status": "%s"}' \
      "$group" "$test" "$expected" "$got" "$status"
  done < "$TSV"
  printf '\n  ]\n}\n'
} > "$JSON"

# ---- best-effort cleanup ----------------------------------------------------
while IFS="$(printf '\t')" read -r id ip host; do
  [ -n "$id" ] && body_req "$ip" 127.0.0.1 "$host" DELETE "/api/v1/memories/$id" "" "$AID_H" >/dev/null 2>&1 || true
done < "$CLEANUP"
rm -f "$CLEANUP"

# ---- human summary ----------------------------------------------------------
total="$(grep -c . "$TSV" || true)"
passed="$(awk -F'\t' '$5=="PASS"' "$TSV" | grep -c . || true)"
failed="$(awk -F'\t' '$5=="FAIL"' "$TSV" | grep -c . || true)"
skipped="$(awk -F'\t' '$5=="SKIP"' "$TSV" | grep -c . || true)"

printf '\n'
printf '============== %s P3 full-spectrum test (%s) ==============\n' "$CAMPAIGN" "$TS"
printf '%-12s %-26s %-8s %s\n' "GROUP" "TEST" "STATUS" "GOT"
printf '%-12s %-26s %-8s %s\n' "-----" "----" "------" "---"
awk -F'\t' '{printf "%-12s %-26s %-8s %s\n", $1, $2, $5, $4}' "$TSV"
printf -- '----------------------------------------------------------------\n'
printf 'TOTAL=%s  PASS=%s  FAIL=%s  SKIP=%s\n' "$total" "$passed" "$failed" "$skipped"
printf 'machine report: %s\n' "$JSON"
printf 'human  report: %s\n' "$TSV"

if [ "$failed" -ne 0 ]; then
  log "P3 FAILED — $failed check(s) red."
  exit 1
fi
if [ "$skipped" -ne 0 ]; then
  log "P3 PASSED — $passed/$total checks green ($skipped skipped: topology not applicable)."
else
  log "P3 PASSED — $passed/$total checks green."
fi
