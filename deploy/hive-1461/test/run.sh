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
#   federation : write to peer-1, converge on peer-2 (same region) AND peer-3
#                (cross-region nyc3->sfo2) within the catchup window.
#   zerotouch  : first-party CA trust (provision/45_zero_touch.sh) — an enrolled
#                peer converges via its CA-signed credential ALONE (no per-peer
#                pubkey is pushed to any other peer), and an UNENROLLED x-peer-id
#                is refused 401 `peer_not_enrolled` on /sync/since (fail-closed).
#   a2a        : agent-to-agent E2E — agent-alpha (an mTLS CLIENT node) writes a
#                collective memory to a peer over the network; agent-beta (a
#                different client identity, different node) reads it back BOTH on
#                the write peer and on a federated peer.
#   ai_nhi     : the grok-driven NHI loop on an agent node — the agent's xAI LLM
#                produces a decision the agent then commits to the mesh.
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

# record <group> <test> <expected> <got> <PASS|FAIL>
record() { printf '%s\t%s\t%s\t%s\t%s\n' "$1" "$2" "$3" "$4" "$5" >> "$TSV"; }
pass()   { record "$1" "$2" "$3" "$4" PASS; }
fail()   { record "$1" "$2" "$3" "$4" FAIL; }
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

# Resolve the peer set (need >=2 for federation, 3 expected).
P1_IP="$(inv_ips_by_role peer | sed -n 1p)"
P2_IP="$(inv_ips_by_role peer | sed -n 2p)"
P3_IP="$(inv_ips_by_role peer | sed -n 3p)"
P1_H="$(inv_name_for_ip "$P1_IP")"
P2_H="$([ -n "$P2_IP" ] && inv_name_for_ip "$P2_IP")"
P3_H="$([ -n "$P3_IP" ] && inv_name_for_ip "$P3_IP")"
A1_IP="$(inv_ips_by_role agent | sed -n 1p)"
A2_IP="$(inv_ips_by_role agent | sed -n 2p)"
[ -n "$P1_IP" ] || die "no peer in inventory"

# Track created memory ids for end-of-run cleanup (id<TAB>peer_ip<TAB>peer_host).
CLEANUP="$RUN_DIR/.p3-cleanup-$TS"; : > "$CLEANUP"
track() { printf '%s\t%s\t%s\n' "$1" "$2" "$3" >> "$CLEANUP"; }

# ====================== GROUP regression =====================================
# Single-peer correctness over the encrypted, authenticated path.
log "[regression] CRUD + semantic search + isolation on $P1_H"
NONCE="p3-$TS-$RANDOM"
RBODY="{\"title\":\"reg-$NONCE\",\"content\":\"regression probe sentinel $NONCE quaternion\",\"namespace\":\"$NS_TEST\",\"scope\":\"private\"}"
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
  "{\"title\":\"isoA-$NONCE2\",\"content\":\"ns-isolation $NONCE2\",\"namespace\":\"${NS_TEST}_a\",\"scope\":\"private\"}" "$AID_H")"
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
# Write to peer-1; expect convergence on peer-2 (same region) and peer-3
# (cross-region) within the catchup window, over the encrypted path.
if [ -n "$P2_IP" ]; then
  log "[federation] convergence probe peer-1 -> {peer-2, peer-3}"
  FNONCE="fed-$TS-$RANDOM"
  FBODY="{\"title\":\"$FNONCE\",\"content\":\"federation spectrum probe $FNONCE\",\"namespace\":\"_verify\",\"scope\":\"collective\"}"
  FW="$(body_req "$P1_IP" 127.0.0.1 "$P1_H" POST /api/v1/memories "$FBODY" "$AID_H")"
  FID="$(json_field "$FW" id)"
  if [ -z "$FID" ]; then
    fail federation write "memory id" "<write failed>"
  else
    pass federation write "memory id" "$FID"; track "$FID" "$P1_IP" "$P1_H"
    # converge_target <ip> <host> <label>
    converge_target() {
      local ip="$1" host="$2" label="$3" i=0 got="<not replicated within window>" st=FAIL
      while [ "$i" -lt 20 ]; do
        r="$(body_req "$ip" 127.0.0.1 "$host" GET "/api/v1/memories/$FID" "" "$AID_H")"
        case "$r" in *"$FNONCE"*) st=PASS; got="present on $host"; break ;; esac
        i=$((i+1)); sleep 2
      done
      record federation "$label" "$FID on $host" "$got" "$st"
    }
    converge_target "$P2_IP" "$P2_H" "converge_same_region"
    [ -n "$P3_IP" ] && converge_target "$P3_IP" "$P3_H" "converge_cross_region" \
      || record federation converge_cross_region ">=3 peers" "<only 2 peers>" FAIL
  fi
else
  record federation converge_same_region ">=2 peers" "<need 2 peers>" FAIL
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
  log "[zerotouch] enrolled peer converges through the REQUIRE_PEER_ENROLLMENT gate"
  ZNONCE="zt-$TS-$RANDOM"
  ZBODY="{\"title\":\"$ZNONCE\",\"content\":\"zero-touch enrolled convergence $ZNONCE\",\"namespace\":\"_zerotouch\",\"scope\":\"collective\"}"
  ZW="$(body_req "$P1_IP" 127.0.0.1 "$P1_H" POST /api/v1/memories "$ZBODY" "$AID_H")"
  ZMID="$(json_field "$ZW" id)"
  if [ -z "$ZMID" ]; then
    fail zerotouch enrolled_write "memory id" "<write failed>"
  else
    pass zerotouch enrolled_write "memory id" "$ZMID"; track "$ZMID" "$P1_IP" "$P1_H"
    i=0; got="<not replicated within window>"; st=FAIL
    while [ "$i" -lt 20 ]; do
      ZR="$(body_req "$P2_IP" 127.0.0.1 "$P2_H" GET "/api/v1/memories/$ZMID" "" "$AID_H")"
      case "$ZR" in *"$ZNONCE"*) st=PASS; got="present on $P2_H via CA credential (no pushed pubkey)"; break ;; esac
      i=$((i+1)); sleep 2
    done
    record zerotouch enrolled_converge "$ZMID on $P2_H (credential-only trust)" "$got" "$st"
  fi
else
  record zerotouch enrolled_converge ">=2 peers" "<need 2 peers>" FAIL
fi

# Negative: an unenrolled peer-id is refused fail-closed on the sync surface.
log "[zerotouch] unenrolled peer-id refused on /sync/since (#1088 fail-closed)"
ZRES="--resolve $P1_H:$FEDERATION_PORT:127.0.0.1"
ZCA="--cacert $REMOTE_TLS/ca.pem"; ZCERT="--cert $REMOTE_TLS/client.pem"; ZKEY="--key $REMOTE_TLS/client.key"
ZKEYHDR=""; [ -n "$API_KEY" ] && ZKEYHDR="-H 'x-api-key: $API_KEY'"
ZROGUE="rogue-unenrolled-$TS"
ZSYNC="https://$P1_H:$FEDERATION_PORT/api/v1/sync/since?since=1970-01-01T00:00:00Z"
ZPROBE="$ZRES $ZCA $ZCERT $ZKEY $ZKEYHDR -H 'x-peer-id: $ZROGUE' \"$ZSYNC\""
zc="$(code_raw "$P1_IP" "$ZPROBE")"
assert_eq zerotouch unenrolled_status 401 "$zc"
zb="$(body_raw "$P1_IP" "$ZPROBE")"
case "$zb" in *peer_not_enrolled*) pass zerotouch unenrolled_reason "peer_not_enrolled" "fail-closed" ;;
                              *) fail zerotouch unenrolled_reason "peer_not_enrolled" "${zb:-<empty>}" ;; esac

# ====================== GROUP a2a ============================================
# Agent-to-agent E2E. agent-alpha (mTLS CLIENT node) writes a COLLECTIVE memory
# to peer-1 over the NETWORK (not loopback); agent-beta (different identity, a
# different client node) reads it back on peer-1 AND on a federated peer.
if [ -n "$A1_IP" ]; then
  log "[a2a] agent-alpha write -> agent-beta read (E2E over the mesh)"
  ANONCE="a2a-$TS-$RANDOM"
  ABODY="{\"title\":\"a2a-$ANONCE\",\"content\":\"agent-to-agent shared note $ANONCE\",\"namespace\":\"_verify\",\"scope\":\"collective\"}"
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
    # agent-beta reads the same id on a FEDERATED peer (E2E: A2A + federation)
    if [ -n "$P2_IP" ]; then
      i=0; got="<not replicated within window>"; st=FAIL
      while [ "$i" -lt 20 ]; do
        RF="$(body_req "$RNODE" "$P2_IP" "$P2_H" GET "/api/v1/memories/$AID_MID" "" "$AID_BETA")"
        case "$RF" in *"$ANONCE"*) st=PASS; got="$AID_MID present on $P2_H"; break ;; esac
        i=$((i+1)); sleep 2
      done
      record a2a beta_read_fedpeer "visible on federated peer" "$got" "$st"
    fi
  fi
else
  record a2a agent_write ">=1 agent node" "<no agent in inventory>" FAIL
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
    # (2) the NHI commits its LLM-derived decision to the mesh
    NNONCE="nhi-$TS-$RANDOM"
    NBODY="{\"title\":\"nhi-$NNONCE\",\"content\":\"grok expansion of [$NQUERY] -> $NTERM ($NNONCE)\",\"namespace\":\"_verify\",\"scope\":\"collective\"}"
    NW="$(body_req "$A1_IP" "$P1_IP" "$P1_H" POST /api/v1/memories "$NBODY" "$AID_ALPHA")"
    NMID="$(json_field "$NW" id)"
    if [ -z "$NMID" ]; then
      fail ai_nhi nhi_commit "memory id (alpha decision->peer1)" "<write failed>"
    else
      pass ai_nhi nhi_commit "memory id (alpha decision->peer1)" "$NMID"; track "$NMID" "$P1_IP" "$P1_H"
      # (3) the decision converges on a federated peer
      i=0; got="<not replicated within window>"; st=FAIL
      while [ "$i" -lt 20 ]; do
        NRF="$(body_req "${A2_IP:-$A1_IP}" "$P2_IP" "$P2_H" GET "/api/v1/memories/$NMID" "" "$AID_BETA")"
        case "$NRF" in *"$NNONCE"*) st=PASS; got="$NMID present on $P2_H"; break ;; esac
        i=$((i+1)); sleep 2
      done
      record ai_nhi nhi_converge "decision visible on federated peer" "$got" "$st"
    fi
  fi
else
  record ai_nhi llm_decision ">=1 agent + >=2 peers" "<insufficient fleet>" FAIL
fi

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

printf '\n'
printf '============== %s P3 full-spectrum test (%s) ==============\n' "$CAMPAIGN" "$TS"
printf '%-12s %-26s %-8s %s\n' "GROUP" "TEST" "STATUS" "GOT"
printf '%-12s %-26s %-8s %s\n' "-----" "----" "------" "---"
awk -F'\t' '{printf "%-12s %-26s %-8s %s\n", $1, $2, $5, $4}' "$TSV"
printf -- '----------------------------------------------------------------\n'
printf 'TOTAL=%s  PASS=%s  FAIL=%s\n' "$total" "$passed" "$failed"
printf 'machine report: %s\n' "$JSON"
printf 'human  report: %s\n' "$TSV"

if [ "$failed" -ne 0 ]; then
  log "P3 FAILED — $failed check(s) red."
  exit 1
fi
log "P3 PASSED — $passed/$total checks green."
