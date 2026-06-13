#!/usr/bin/env bash
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
#
# docker-1461 — D6 full-spectrum test harness.
#
# Probes the LIVE 2-peer + PG/AGE mesh over the SAME TLS+mTLS path real traffic
# uses and emits BOTH a machine-readable JSON report and a human PASS/FAIL
# table. Exit status is 0 iff every check passes. Run AFTER `make validate` is
# green (the D5 baseline gate).
#
# This is the Docker analog of deploy/hive-1461/test/run.sh. The hive harness
# drives separate SSH-reachable peer + agent droplets; here the EXTERNAL mTLS
# API client is the host harness itself, reaching each peer container on its
# published loopback port over the campaign CA + client cert. "Agents" are
# therefore distinct X-Agent-Id identities the one host client presents — the
# A2A / AI-NHI groups exercise cross-identity collective visibility + the LLM
# decision loop over that encrypted, authenticated path. No literal
# name/port/path/version/namespace is inlined — all flow from provision/lib.sh.
#
# Spectrum (each check is an independent record {group, test, expected, got,
# status}; every probe is over TLS+mTLS and authenticates with X-API-Key):
#
#   regression : memory CRUD roundtrip; semantic search (exercises the nomic
#                embedder end-to-end); namespace isolation; private-scope owner
#                visibility (private memory invisible to a different caller).
#   crypto     : NEGATIVE TLS/mTLS + authz — no client cert refused
#                (client-auth mandatory); non-allowlisted client cert refused
#                (fingerprint pinning); wrong CA on server-verify refused;
#                privileged endpoint without X-API-Key -> 401; with key -> 200;
#                /health exempt (200 without key); admin endpoint non-admin -> 403;
#                PLUS the daemon->PostgreSQL leg (third encrypted leg): every
#                daemon-owned PG backend negotiated TLS (pg_stat_ssl, >=1 ssl /
#                0 plain) and a plaintext (sslmode=disable) TCP connection is
#                refused pre-auth by the hostssl-only pg_hba.conf.
#   federation : write to peer-1, converge on peer-2 within the catch-up window.
#   zerotouch  : first-party CA trust — an enrolled peer converges via its
#                CA-signed credential ALONE (no per-peer pubkey pushed anywhere),
#                and an UNENROLLED X-Peer-Id is refused 401 `peer_not_enrolled`
#                on /sync/since (the #1088 fail-closed arm).
#   a2a        : agent-to-agent E2E — agent-alpha writes a COLLECTIVE memory to
#                peer-1; agent-beta (a different identity) reads it back on
#                peer-1 AND on the federated peer-2.
#   ai_nhi     : the LLM-driven NHI loop — agent-alpha drives a LIVE OpenRouter
#                query-expansion (POST /expand_query), commits the LLM-derived
#                decision as a collective memory, and that decision converges on
#                the federated peer.
#
# Throwaway markers land in the _test / _verify / _zerotouch namespaces and are
# best-effort deleted; nothing here mutates the baseline corpus.

set -euo pipefail
SELF_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../provision/lib.sh
. "$SELF_DIR/../provision/lib.sh"

mkdir -p "$REPORTS_DIR"
TS="$(date -u +%Y%m%dT%H%M%SZ)"
TSV="$REPORTS_DIR/test-$TS.tsv"; : > "$TSV"
JSON="$REPORTS_DIR/test-$TS.json"

NS_TEST="${DOCKER_1461_TEST_NS:-_test}"
NS_VERIFY="${DOCKER_1461_VERIFY_NS:-_verify}"
NS_ZT="${DOCKER_1461_ZT_NS:-_zerotouch}"
CONVERGE_TICKS="${DOCKER_1461_CONVERGE_TICKS:-20}"   # 20 x 2s = 40s catch-up window

# Stable caller identities. Private-scope memories are owned by the X-Agent-Id
# principal; absent the header the daemon assigns an ephemeral
# `anonymous:req-<uuid>` so a private memory written by one bare request is
# invisible to the next. The harness pins explicit identities; alpha/beta model
# two distinct agents on the shared encrypted client path.
AID_H="ai:test-harness@$CAMPAIGN"
AID_ALPHA="ai:agent-alpha@$CAMPAIGN"
AID_BETA="ai:agent-beta@$CAMPAIGN"

EFFECTIVE_KEY="$(effective_api_key)"

# record/pass/fail/assert_eq -------------------------------------------------
record()    { printf '%s\t%s\t%s\t%s\t%s\n' "$1" "$2" "$3" "$4" "$5" >> "$TSV"; }
pass()      { record "$1" "$2" "$3" "$4" PASS; }
fail()      { record "$1" "$2" "$3" "$4" FAIL; }
assert_eq() { if [ "$3" = "$4" ]; then pass "$1" "$2" "$3" "$4"; else fail "$1" "$2" "$3" "${4:-<empty>}"; fi; }

# Raw host-loopback curl helpers for the crypto negatives + error-envelope
# reads. These bypass the lib.sh mtls_curl_* (which always presents the full
# CA+cert+key+api-key) so a negative can vary exactly ONE crypto/authz factor.
# `<port> <path>` then fully-explicit curl args. `-w '%{http_code}'` ALWAYS
# emits a code (literally `000` on a refused handshake); the `; true` masks
# curl's non-zero exit WITHOUT appending a second code, and an empty capture
# defaults to 000.
_url() { printf 'https://127.0.0.1:%s%s' "$1" "$2"; }
probe_code() {
  local port="$1" path="$2"; shift 2
  local out
  out="$(curl -s -o /dev/null -w '%{http_code}' --max-time 15 "$@" "$(_url "$port" "$path")" 2>/dev/null; true)"
  printf '%s' "${out:-000}"
}
# body REGARDLESS of status (keeps the error envelope so a negative can assert
# on the JSON `error` tag — mtls_curl_body uses -fsS and would drop it).
probe_body_raw() {
  local port="$1" path="$2"; shift 2
  curl -s --max-time 15 "$@" "$(_url "$port" "$path")" 2>/dev/null || true
}

log "D6 full-spectrum test $TS — campaign=$CAMPAIGN peers=$PEER_COUNT"

P1_PORT="$(peer_port 1)"; P1_NAME="$(peer_name 1)"
P2_PORT=""; P2_NAME=""
if [ "$PEER_COUNT" -ge 2 ]; then P2_PORT="$(peer_port 2)"; P2_NAME="$(peer_name 2)"; fi

# Track created ids for end-of-run cleanup (id<TAB>port).
CLEANUP="$RUN_DIR/.d6-cleanup-$TS"; : > "$CLEANUP"
track() { printf '%s\t%s\n' "$1" "$2" >> "$CLEANUP"; }

# converge_wait <port> <id> <marker> -> echoes PASS|FAIL via caller; polls the
# target peer for the id+marker within the catch-up window.
converge_wait() {
  local port="$1" id="$2" marker="$3" aid="$4" i=0 r
  while [ "$i" -lt "$CONVERGE_TICKS" ]; do
    r="$(mtls_curl_body "$port" GET "$API_MEMORIES/$id" "" "$aid")"
    case "$r" in *"$marker"*) return 0 ;; esac
    i=$((i + 1)); sleep 2
  done
  return 1
}

# ====================== GROUP regression =====================================
log "[regression] CRUD + semantic search + isolation on $P1_NAME"
NONCE="d6-$TS-$RANDOM"
RBODY="{\"title\":\"reg-$NONCE\",\"content\":\"regression probe sentinel $NONCE quaternion\",\"namespace\":\"$NS_TEST\",\"scope\":\"private\"}"
W="$(mtls_curl_body "$P1_PORT" POST "$API_MEMORIES" "$RBODY" "$AID_H")"
MID="$(json_field "$W" id)"
if [ -z "$MID" ]; then
  fail regression create "memory id" "<write failed>"
else
  pass regression create "memory id" "$MID"; track "$MID" "$P1_PORT"
  G="$(mtls_curl_body "$P1_PORT" GET "$API_MEMORIES/$MID" "" "$AID_H")"
  case "$G" in *"$NONCE"*) pass regression get_by_id "content present" "$NONCE found" ;;
                        *) fail regression get_by_id "content present" "<not returned>" ;; esac
  # semantic search exercises the nomic embedder end-to-end
  S="$(mtls_curl_body "$P1_PORT" GET "$API_SEARCH?q=$NONCE&namespace=$NS_TEST&limit=5" "" "$AID_H")"
  scount="$(json_field "$S" count)"
  case "$S" in *"$MID"*) pass regression search_semantic "id in results (count=$scount)" "$MID" ;;
                      *) fail regression search_semantic "id in results" "count=${scount:-0}" ;; esac
  # namespace listing
  L="$(mtls_curl_body "$P1_PORT" GET "$API_MEMORIES?namespace=$NS_TEST&limit=20" "" "$AID_H")"
  case "$L" in *"$MID"*) pass regression list_namespace "id listed in $NS_TEST" "$MID" ;;
                      *) fail regression list_namespace "id listed in $NS_TEST" "<absent>" ;; esac
  # private-scope owner isolation: a DIFFERENT caller must NOT see the content
  ISO="$(mtls_curl_body "$P1_PORT" GET "$API_MEMORIES/$MID" "" "$AID_BETA")"
  case "$ISO" in *"$NONCE"*) fail regression private_isolation "hidden from non-owner" "LEAKED to $AID_BETA" ;;
                          *) pass regression private_isolation "hidden from non-owner" "not visible to $AID_BETA" ;; esac
fi

# namespace cross-isolation: write to ns A, assert absent from ns B's listing
NONCE2="d6iso-$TS-$RANDOM"
WA="$(mtls_curl_body "$P1_PORT" POST "$API_MEMORIES" \
  "{\"title\":\"isoA-$NONCE2\",\"content\":\"ns-isolation $NONCE2\",\"namespace\":\"${NS_TEST}_a\",\"scope\":\"private\"}" "$AID_H")"
MIDA="$(json_field "$WA" id)"
[ -n "$MIDA" ] && track "$MIDA" "$P1_PORT"
LB="$(mtls_curl_body "$P1_PORT" GET "$API_MEMORIES?namespace=${NS_TEST}_b&limit=50" "" "$AID_H")"
case "$LB" in *"$MIDA"*) fail regression ns_cross_isolation "absent from other ns" "LEAKED across namespace" ;;
                      *) pass regression ns_cross_isolation "absent from other ns" "isolated" ;; esac

# ====================== GROUP crypto =========================================
# Negative crypto + authz. SUCCESS = the gate REFUSES what it must.
log "[crypto] TLS/mTLS negatives + api_key/admin authz on $P1_NAME"
CA_ARG=(--cacert "$MTLS_CA")
CERT_ARGS=(--cert "$MTLS_CLIENT_CERT" --key "$MTLS_CLIENT_KEY")
KEY_HDR=(-H "X-API-Key: $EFFECTIVE_KEY")

# (1) no client cert -> client-auth mandatory refuses the handshake (000)
c="$(probe_code "$P1_PORT" "$API_HEALTH" "${CA_ARG[@]}")"
assert_eq crypto no_client_cert 000 "$c"

# (2) non-allowlisted client cert -> fingerprint pinning refuses (000). Mint an
# ephemeral self-signed leaf under the gitignored run dir (NEVER tmpfs).
ROGUE_KEY="$RUN_DIR/.crypto-rogue-$TS.key"; ROGUE_CERT="$RUN_DIR/.crypto-rogue-$TS.pem"
( umask 077; openssl req -x509 -newkey rsa:2048 -nodes -keyout "$ROGUE_KEY" -out "$ROGUE_CERT" \
    -days 1 -subj '/CN=rogue-client' >/dev/null 2>&1 ) || true
c="$(probe_code "$P1_PORT" "$API_HEALTH" "${CA_ARG[@]}" --cert "$ROGUE_CERT" --key "$ROGUE_KEY")"
assert_eq crypto rogue_client_cert 000 "$c"
rm -f "$ROGUE_KEY" "$ROGUE_CERT"

# (3) wrong CA on server verify -> client aborts (000). The campaign client cert
# did NOT sign the server cert, so using it as the CA bundle fails verification.
c="$(probe_code "$P1_PORT" "$API_HEALTH" --cacert "$MTLS_CLIENT_CERT" "${CERT_ARGS[@]}")"
assert_eq crypto wrong_server_ca 000 "$c"

# (4) privileged endpoint WITHOUT X-API-Key -> 401
c="$(probe_code "$P1_PORT" "$API_CAPABILITIES" "${CA_ARG[@]}" "${CERT_ARGS[@]}")"
assert_eq crypto apikey_required 401 "$c"

# (5) privileged endpoint WITH X-API-Key -> 200
c="$(probe_code "$P1_PORT" "$API_CAPABILITIES" "${CA_ARG[@]}" "${CERT_ARGS[@]}" "${KEY_HDR[@]}")"
assert_eq crypto apikey_accepted 200 "$c"

# (6) /health is exempt -> 200 without the key
c="$(probe_code "$P1_PORT" "$API_HEALTH" "${CA_ARG[@]}" "${CERT_ARGS[@]}")"
assert_eq crypto health_exempt 200 "$c"

# (7) admin-only endpoint as a non-admin caller -> 403 (authz enforced)
c="$(probe_code "$P1_PORT" "$API_STATS" "${CA_ARG[@]}" "${CERT_ARGS[@]}" "${KEY_HDR[@]}" -H "X-Agent-Id: $AID_H")"
assert_eq crypto admin_gated 403 "$c"

# (8) daemon -> PostgreSQL leg is TLS (third encrypted leg). Join pg_stat_ssl
# to pg_stat_activity INSIDE the PG container: every daemon-owned TCP backend
# must report ssl=true, and there must be >=1 (proving the daemons actually
# hold encrypted pooled connections, not merely "zero plaintext"). The probe's
# own psql is a unix-socket backend (client_addr IS NULL) and is excluded.
pg_ssl_q="select count(*) from pg_stat_ssl s join pg_stat_activity a on s.pid=a.pid where a.usename='$PG_USER' and a.client_addr is not null and a.backend_type='client backend'"
pssl_on="$(node_exec "$PG_CONTAINER" psql -U "$PG_USER" -d "$PG_DB" -tAc "$pg_ssl_q and s.ssl is true" 2>/dev/null | tr -d '[:space:]' || echo x)"
pssl_off="$(node_exec "$PG_CONTAINER" psql -U "$PG_USER" -d "$PG_DB" -tAc "$pg_ssl_q and s.ssl is not true" 2>/dev/null | tr -d '[:space:]' || echo x)"
if [ "$pssl_off" = "0" ] && [ -n "$pssl_on" ] && [ "$pssl_on" != "0" ] && [ "$pssl_on" != "x" ]; then
  pass crypto pg_tls_enforced "all daemon PG backends ssl (>=1)" "ssl=$pssl_on plain=$pssl_off"
else
  fail crypto pg_tls_enforced "all daemon PG backends ssl (>=1)" "ssl=${pssl_on:-?} plain=${pssl_off:-?}"
fi

# (9) plaintext (sslmode=disable) TCP refused pre-auth by the hostssl-only
# pg_hba.conf. SUCCESS = PostgreSQL rejects the non-TLS handshake before any
# password is checked ("no pg_hba.conf entry ... no encryption").
pg_plain_out="$(node_exec "$PG_CONTAINER" psql "host=127.0.0.1 port=$PG_INTERNAL_PORT user=$PG_USER dbname=$PG_DB sslmode=disable connect_timeout=5" -w -tAc 'select 1' 2>&1 || true)"
case "$pg_plain_out" in
  *"no encryption"*|*"no pg_hba.conf entry"*|*"no pg_hba"*)
    pass crypto pg_plaintext_refused "non-TLS TCP refused pre-auth" "rejected (no encryption)" ;;
  *)
    fail crypto pg_plaintext_refused "non-TLS TCP refused pre-auth" "${pg_plain_out:-<empty>}" ;;
esac

# ====================== GROUP federation =====================================
if [ -n "$P2_PORT" ]; then
  log "[federation] convergence probe $P1_NAME -> $P2_NAME"
  FNONCE="fed-$TS-$RANDOM"
  FBODY="{\"title\":\"$FNONCE\",\"content\":\"federation spectrum probe $FNONCE\",\"namespace\":\"$NS_VERIFY\",\"scope\":\"collective\"}"
  FW="$(mtls_curl_body "$P1_PORT" POST "$API_MEMORIES" "$FBODY" "$AID_H")"
  FID="$(json_field "$FW" id)"
  if [ -z "$FID" ]; then
    fail federation write "memory id" "<write failed>"
  else
    pass federation write "memory id" "$FID"; track "$FID" "$P1_PORT"
    if converge_wait "$P2_PORT" "$FID" "$FNONCE" "$AID_H"; then
      pass federation converge "$FID on $P2_NAME" "present on $P2_NAME"
    else
      fail federation converge "$FID on $P2_NAME" "<not replicated within window>"
    fi
  fi
else
  fail federation converge ">=2 peers" "<need 2 peers>"
fi

# ====================== GROUP zerotouch ======================================
# First-party zero-touch trust: every peer runs with
# AI_MEMORY_FED_REQUIRE_PEER_ENROLLMENT=1 and holds ONLY the campaign CA trust
# anchor (no per-peer pubkey was pushed anywhere). Two proofs:
if [ -n "$P2_PORT" ]; then
  log "[zerotouch] enrolled peer converges through the REQUIRE_PEER_ENROLLMENT gate"
  ZNONCE="zt-$TS-$RANDOM"
  ZBODY="{\"title\":\"$ZNONCE\",\"content\":\"zero-touch enrolled convergence $ZNONCE\",\"namespace\":\"$NS_ZT\",\"scope\":\"collective\"}"
  ZW="$(mtls_curl_body "$P1_PORT" POST "$API_MEMORIES" "$ZBODY" "$AID_H")"
  ZMID="$(json_field "$ZW" id)"
  if [ -z "$ZMID" ]; then
    fail zerotouch enrolled_write "memory id" "<write failed>"
  else
    pass zerotouch enrolled_write "memory id" "$ZMID"; track "$ZMID" "$P1_PORT"
    if converge_wait "$P2_PORT" "$ZMID" "$ZNONCE" "$AID_H"; then
      pass zerotouch enrolled_converge "$ZMID on $P2_NAME (credential-only trust)" "present via CA credential"
    else
      fail zerotouch enrolled_converge "$ZMID on $P2_NAME (credential-only trust)" "<not replicated within window>"
    fi
  fi
else
  fail zerotouch enrolled_converge ">=2 peers" "<need 2 peers>"
fi

# Negative: an unenrolled peer-id is refused fail-closed on the sync surface.
log "[zerotouch] unenrolled peer-id refused on /sync/since (#1088 fail-closed)"
ZROGUE="rogue-unenrolled-$TS"
ZSYNC="$API_SYNC_SINCE?since=1970-01-01T00:00:00Z"
zc="$(probe_code "$P1_PORT" "$ZSYNC" "${CA_ARG[@]}" "${CERT_ARGS[@]}" "${KEY_HDR[@]}" -H "X-Peer-Id: $ZROGUE")"
assert_eq zerotouch unenrolled_status 401 "$zc"
zb="$(probe_body_raw "$P1_PORT" "$ZSYNC" "${CA_ARG[@]}" "${CERT_ARGS[@]}" "${KEY_HDR[@]}" -H "X-Peer-Id: $ZROGUE")"
case "$zb" in *peer_not_enrolled*) pass zerotouch unenrolled_reason "peer_not_enrolled" "fail-closed" ;;
                              *) fail zerotouch unenrolled_reason "peer_not_enrolled" "${zb:-<empty>}" ;; esac

# ====================== GROUP a2a ============================================
# Agent-to-agent E2E. agent-alpha writes a COLLECTIVE memory to peer-1;
# agent-beta (different identity) reads it back on peer-1 AND on federated peer-2.
log "[a2a] agent-alpha write -> agent-beta read (E2E over the mesh)"
ANONCE="a2a-$TS-$RANDOM"
ABODY="{\"title\":\"a2a-$ANONCE\",\"content\":\"agent-to-agent shared note $ANONCE\",\"namespace\":\"$NS_VERIFY\",\"scope\":\"collective\"}"
AW="$(mtls_curl_body "$P1_PORT" POST "$API_MEMORIES" "$ABODY" "$AID_ALPHA")"
A_MID="$(json_field "$AW" id)"
if [ -z "$A_MID" ]; then
  fail a2a agent_write "memory id (alpha->peer1)" "<write failed>"
else
  pass a2a agent_write "memory id (alpha->peer1)" "$A_MID"; track "$A_MID" "$P1_PORT"
  RB="$(mtls_curl_body "$P1_PORT" GET "$API_MEMORIES/$A_MID" "" "$AID_BETA")"
  case "$RB" in *"$ANONCE"*) pass a2a beta_read_writepeer "visible cross-agent" "$A_MID present" ;;
                         *) fail a2a beta_read_writepeer "visible cross-agent" "<not visible>" ;; esac
  if [ -n "$P2_PORT" ]; then
    if converge_wait "$P2_PORT" "$A_MID" "$ANONCE" "$AID_BETA"; then
      pass a2a beta_read_fedpeer "visible on federated peer" "$A_MID present on $P2_NAME"
    else
      fail a2a beta_read_fedpeer "visible on federated peer" "<not replicated within window>"
    fi
  fi
fi

# ====================== GROUP ai_nhi =========================================
# The LLM-driven NHI loop, end-to-end over the mesh:
#   (1) llm_decision — agent-alpha drives a LIVE OpenRouter query-expansion via
#                      POST /expand_query; a non-empty `expanded_terms` proves a
#                      real LLM completion round-tripped over TLS+mTLS.
#   (2) nhi_commit   — the agent commits that decision as a collective memory
#                      whose content embeds the first LLM-derived term.
#   (3) nhi_converge — the committed decision converges on the federated peer.
if [ -n "$P2_PORT" ]; then
  log "[ai_nhi] LLM decision on agent-alpha -> commit -> federated convergence"
  NQUERY="distributed consensus quorum replication"
  NLLM="$(MTLS_MAX_TIME=90 mtls_curl_body "$P1_PORT" POST "$API_EXPAND_QUERY" \
    "{\"query\":\"$NQUERY\",\"namespace\":\"$NS_TEST\"}" "$AID_ALPHA")"
  NTERM="$(printf '%s' "$NLLM" | sed -n 's/.*"expanded_terms"[[:space:]]*:[[:space:]]*\[[[:space:]]*"\([^"]*\)".*/\1/p' | head -1)"
  if [ -z "$NTERM" ]; then
    fail ai_nhi llm_decision "non-empty expanded_terms" "<no terms returned>"
  else
    pass ai_nhi llm_decision "non-empty expanded_terms" "term=$NTERM"
    NNONCE="nhi-$TS-$RANDOM"
    NBODY="{\"title\":\"nhi-$NNONCE\",\"content\":\"LLM expansion of [$NQUERY] -> $NTERM ($NNONCE)\",\"namespace\":\"$NS_VERIFY\",\"scope\":\"collective\"}"
    NW="$(mtls_curl_body "$P1_PORT" POST "$API_MEMORIES" "$NBODY" "$AID_ALPHA")"
    NMID="$(json_field "$NW" id)"
    if [ -z "$NMID" ]; then
      fail ai_nhi nhi_commit "memory id (alpha decision->peer1)" "<write failed>"
    else
      pass ai_nhi nhi_commit "memory id (alpha decision->peer1)" "$NMID"; track "$NMID" "$P1_PORT"
      if converge_wait "$P2_PORT" "$NMID" "$NNONCE" "$AID_BETA"; then
        pass ai_nhi nhi_converge "decision visible on federated peer" "$NMID present on $P2_NAME"
      else
        fail ai_nhi nhi_converge "decision visible on federated peer" "<not replicated within window>"
      fi
    fi
  fi
else
  fail ai_nhi llm_decision ">=2 peers" "<insufficient fleet>"
fi

# ---- assemble JSON report ---------------------------------------------------
{
  printf '{\n  "campaign": "%s",\n  "timestamp": "%s",\n  "suite": "d6-full-spectrum",\n' "$CAMPAIGN" "$TS"
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
while IFS="$(printf '\t')" read -r id port; do
  [ -n "$id" ] && mtls_curl_code "$port" DELETE "$API_MEMORIES/$id" "" "$AID_H" >/dev/null 2>&1 || true
done < "$CLEANUP"
rm -f "$CLEANUP"

# ---- human summary ----------------------------------------------------------
total="$(grep -c . "$TSV" || true)"
passed="$(awk -F'\t' '$5=="PASS"' "$TSV" | grep -c . || true)"
failed="$(awk -F'\t' '$5=="FAIL"' "$TSV" | grep -c . || true)"

printf '\n'
printf '============== %s D6 full-spectrum test (%s) ==============\n' "$CAMPAIGN" "$TS"
printf '%-12s %-26s %-8s %s\n' "GROUP" "TEST" "STATUS" "GOT"
printf '%-12s %-26s %-8s %s\n' "-----" "----" "------" "---"
awk -F'\t' '{printf "%-12s %-26s %-8s %s\n", $1, $2, $5, $4}' "$TSV"
printf -- '----------------------------------------------------------------\n'
printf 'TOTAL=%s  PASS=%s  FAIL=%s\n' "$total" "$passed" "$failed"
printf 'machine report: %s\n' "$JSON"
printf 'human  report: %s\n' "$TSV"

if [ "$failed" -ne 0 ]; then
  die "D6 FAILED — $failed check(s) red."
fi
log "D6 PASSED — $passed/$total checks green."
