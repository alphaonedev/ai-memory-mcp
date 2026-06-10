#!/usr/bin/env bash
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
#
# Recursive-frameworks campaign harness (#1546) — exercises the v0.7.0
# recursive LEARNING (memory_reflect / reflection_origin) and recursive
# IMPROVEMENT (curator ReflectionPass+ConsolidationPass / consolidate)
# frameworks against the LIVE max-secure 3-region postgres hive, over the
# SAME TLS+mTLS path real traffic uses. Emits the standard
# {group,test,expected,got,status} TSV + JSON report; exit 0 iff every
# check passes. Run AFTER `make validate` is green.
#
# Postgres SAL coverage (#1548/#1549) is the precondition: reflect /
# reflection_origin / recall_observations are routed through the SAL trait
# on postgres-backed peers, and the curator runs the passes against the
# federated postgres store via --store-url.
#
# Spectrum:
#   rec_learning   : attested base memory; reflect a chain to the namespace
#                    max_reflection_depth cap; depth+1 refused with
#                    REFLECTION_DEPTH_EXCEEDED; reflection_origin walk;
#                    reflects_on edges persisted (one per source); the
#                    deepest reflection converges cross-region.
#   rec_improve    : curator daemon live on every peer; consolidate merges
#                    near-duplicate sources into one memory carrying
#                    derived_from provenance; the consolidated memory
#                    converges cross-region.
#
# Throwaway markers land in the _rec_* namespaces and are best-effort
# deleted; nothing here mutates the baseline corpus.
source "$(dirname "$0")/../provision/lib.sh"

# lib.sh sets `set -euo pipefail`; a test harness must RECORD a failing check
# (fail/skip) and keep going to the summary, not abort on the first non-zero
# (a probe curl/psql returning empty is a recordable FAIL, not a fatal). Drop
# errexit + pipefail here (keep nounset). run.sh stays strict by careful
# construction; this harness opts for record-and-continue.
set +e +o pipefail

require_inventory

REPORTS="$RUN_DIR/reports"; mkdir -p "$REPORTS"
TS="$(date -u +%Y%m%dT%H%M%SZ)"
TSV="$REPORTS/recursive-$TS.tsv"; : > "$TSV"
JSON="$REPORTS/recursive-$TS.json"
REMOTE_TLS="/etc/ai-memory/tls"

# Stable caller identity (the enrolled, attesting harness agent).
AID_H="$HARNESS_AGENT_ID"
API_PW_FILE="$RUN_DIR/secrets/api.pw"
API_KEY=""; [ -s "$API_PW_FILE" ] && API_KEY="$(cat "$API_PW_FILE")"

# Named knobs — NO hardcoded literal at any call site.
# Convergence-checked writes land in the federation-allowlisted `_verify`
# namespace (the same one the full-spectrum federation group converges) so
# cross-region replication is exercised; `_rec_*` underscore namespaces are
# NOT in the per-peer federation namespace allowlist and stay local.
REC_NS_LEARN="${REC_NS_LEARN:-_verify}"          # reflection-chain namespace (federated)
REC_NS_IMPROVE="${REC_NS_IMPROVE:-_verify}"      # consolidation namespace (federated)
REC_MAX_DEPTH="${REC_MAX_DEPTH:-3}"              # compiled GovernancePolicy default
REC_CONVERGE_TRIES="${REC_CONVERGE_TRIES:-30}"   # poll attempts per peer
REC_CONVERGE_SLEEP_SECS="${REC_CONVERGE_SLEEP_SECS:-3}"  # > FED_CATCHUP_INTERVAL_SECS over the loop

# record <group> <test> <expected> <got> <PASS|FAIL|SKIP>
record() { printf '%s\t%s\t%s\t%s\t%s\n' "$1" "$2" "$3" "$4" "$5" >> "$TSV"; }
pass()   { record "$1" "$2" "$3" "$4" PASS; }
fail()   { record "$1" "$2" "$3" "$4" FAIL; }
skip()   { record "$1" "$2" "$3" "$4" SKIP; }
assert_eq() { [ "$3" = "$4" ] && pass "$1" "$2" "$3" "$4" || fail "$1" "$2" "$3" "${4:-<empty>}"; }

# json_field <body> <key> -> first scalar value for "key"
json_field() {
  printf '%s' "$1" | sed -n "s/.*\"$2\"[[:space:]]*:[[:space:]]*\"\{0,1\}\([^\",}]*\)\"\{0,1\}.*/\1/p" | head -1
}
# hdrs <agent_id> -> standard auth/identity header fragment
hdrs() {
  local aid="$1" h=""
  [ -n "$API_KEY" ] && h="-H 'x-api-key: $API_KEY'"
  [ -n "$aid" ] && h="$h -H 'x-agent-id: $aid'"
  printf '%s' "$h"
}
# body_req <run_ip> <connect_ip> <host> <method> <path> [data] [agent_id]
# -> 2xx response body on stdout, empty on any non-2xx/transport error.
body_req() {
  local rip="$1" cip="$2" host="$3" m="$4" path="$5" data="${6:-}" aid="${7:-}"
  local extra=""; [ -n "$data" ] && extra="-H 'content-type: application/json' --data '$data'"
  ssh_node "$rip" "curl -fsS --max-time 10 --resolve $host:$FEDERATION_PORT:$cip \
    --cacert $REMOTE_TLS/ca.pem --cert $REMOTE_TLS/client.pem --key $REMOTE_TLS/client.key \
    $(hdrs "$aid") $extra -X $m https://$host:$FEDERATION_PORT$path" 2>/dev/null || true
}
# body_raw <run_ip> <connect_ip> <host> <method> <path> <data> <agent_id>
# -> response body REGARDLESS of status (keeps the error envelope for
# negative assertions like the depth-exceeded refusal).
body_raw() {
  local rip="$1" cip="$2" host="$3" m="$4" path="$5" data="${6:-}" aid="${7:-}"
  local extra=""; [ -n "$data" ] && extra="-H 'content-type: application/json' --data '$data'"
  ssh_node "$rip" "curl -s --max-time 10 --resolve $host:$FEDERATION_PORT:$cip \
    --cacert $REMOTE_TLS/ca.pem --cert $REMOTE_TLS/client.pem --key $REMOTE_TLS/client.key \
    $(hdrs "$aid") $extra -X $m https://$host:$FEDERATION_PORT$path; true" 2>/dev/null || true
}
# reflect_post <peer_ip> <host> <source_ids_json> <title> <content> -> reflect body (2xx) on stdout
reflect_post() {
  local ip="$1" host="$2" srcs="$3" title="$4" content="$5"
  local data
  data="$(printf '{"source_ids":%s,"title":"%s","content":"%s","namespace":"%s","agent_id":"%s"}' \
    "$srcs" "$title" "$content" "$REC_NS_LEARN" "$AID_H")"
  body_req "$ip" 127.0.0.1 "$host" POST /api/v1/memory_reflect "$data" "$AID_H"
}

# pg SQL on the regional pg node against the peer's within-region schema.
# pg_sql <peer_host> <sql> -> single-line result
pg_sql() {
  local h="$1" sql="$2" region schema pg_pub
  region="$(inv_peer_region "$h")"
  schema="$(peer_schema "$(peer_schema_index_in_region "$h")")"
  pg_pub="$(inv_pg_public_ip_for_region "$region")"
  # `-tAc "SET ...; SELECT ..."` emits the `SET` command tag on its own line
  # before the result, so take the LAST line (the SELECT scalar) and strip
  # whitespace. `|| true` keeps the helper from tripping the inherited
  # `set -e` when a probe row legitimately returns nothing.
  ssh_node "$pg_pub" "sudo -u postgres psql -d $PG_DB -tAc \"SET search_path = $schema, ag_catalog, public; $sql\"" 2>/dev/null | tail -1 | tr -d '[:space:]' || true
}

log "recursive-frameworks run $TS — fleet=$CAMPAIGN port=$FEDERATION_PORT"

PEER_IPS="$(inv_ips_by_role peer)"
P1_IP="$(printf '%s\n' "$PEER_IPS" | sed -n 1p)"
P1_H="$(inv_name_for_ip "$P1_IP")"
[ -n "$P1_IP" ] || die "no peer in inventory"
PEER_N="$(inv_peer_count)"
log "anchor peer $P1_H ($P1_IP); N=$PEER_N peers across [$(inv_regions | tr '\n' ' ')]"

# Cleanup tracking (id<TAB>peer_ip<TAB>peer_host).
CLEANUP="$RUN_DIR/.recursive-cleanup-$TS"; : > "$CLEANUP"
track() { printf '%s\t%s\t%s\n' "$1" "$2" "$3" >> "$CLEANUP"; }

# The fleet runs AI_MEMORY_REQUIRE_AGENT_ATTESTATION=1 — the BASE memory
# writes below are Ed25519-attested (attested_body); reflect/consolidate
# edges are signed by the daemon keypair. Enroll the harness on the anchor.
harness_keypair_ensure >/dev/null
harness_enroll_peer "$P1_IP"

# ====================== GROUP rec_learning ===================================
# Build a reflection chain on the anchor peer, depth 0 -> REC_MAX_DEPTH,
# assert the substrate-computed depth at each hop, then assert the cap
# refuses depth REC_MAX_DEPTH+1.
log "[rec_learning] attested base write + reflection chain to depth $REC_MAX_DEPTH on $P1_H"
NONCE="rec-$TS-$RANDOM"
BASE_BODY="$(attested_body "$REC_NS_LEARN" "rl-base-$NONCE" observation collective "recursive base sentinel $NONCE")"
BW="$(body_req "$P1_IP" 127.0.0.1 "$P1_H" POST /api/v1/memories "$BASE_BODY" "$AID_H")"
M0="$(json_field "$BW" id)"
if [ -n "$M0" ]; then
  pass rec_learning "base_attested_write" "id present" "$M0"
  track "$M0" "$P1_IP" "$P1_H"
else
  fail rec_learning "base_attested_write" "id present" "${BW:-<empty>}"
fi

# Walk the chain. cur holds the id we reflect ON; expect depth = hop.
cur="$M0"; chain_ok=1
declare -a CHAIN_IDS
for hop in $(seq 1 "$REC_MAX_DEPTH"); do
  [ -n "$cur" ] || { chain_ok=0; break; }
  RB="$(reflect_post "$P1_IP" "$P1_H" "[\"$cur\"]" "rl-d$hop-$NONCE" "reflection at depth $hop over $NONCE")"
  rid="$(json_field "$RB" id)"
  rdepth="$(json_field "$RB" reflection_depth)"
  assert_eq rec_learning "reflect_depth[$hop]" "$hop" "${rdepth:-<none>}"
  if [ -n "$rid" ]; then track "$rid" "$P1_IP" "$P1_H"; CHAIN_IDS+=("$rid"); cur="$rid"; else chain_ok=0; cur=""; fi
done

# Deepest reflection id (depth == REC_MAX_DEPTH).
R_DEEP="$cur"

# Depth cap: reflecting on the deepest row would mint depth REC_MAX_DEPTH+1
# -> REFLECTION_DEPTH_EXCEEDED refusal (no row written).
if [ -n "$R_DEEP" ]; then
  XB="$(body_raw "$P1_IP" 127.0.0.1 "$P1_H" POST /api/v1/memory_reflect \
    "$(printf '{"source_ids":["%s"],"title":"rl-over-%s","content":"over cap","namespace":"%s","agent_id":"%s"}' "$R_DEEP" "$NONCE" "$REC_NS_LEARN" "$AID_H")" "$AID_H")"
  case "$XB" in
    *REFLECTION_DEPTH_EXCEEDED*) pass rec_learning "depth_cap_refusal" "REFLECTION_DEPTH_EXCEEDED" "refused at depth $((REC_MAX_DEPTH+1))" ;;
    *) fail rec_learning "depth_cap_refusal" "REFLECTION_DEPTH_EXCEEDED" "${XB:-<empty>}" ;;
  esac
else
  fail rec_learning "depth_cap_refusal" "REFLECTION_DEPTH_EXCEEDED" "<no deepest reflection — chain broke>"
fi

# reflection_origin walk on the deepest reflection: is_reflection=true and
# original_depth == REC_MAX_DEPTH.
if [ -n "$R_DEEP" ]; then
  OB="$(body_req "$P1_IP" 127.0.0.1 "$P1_H" POST /api/v1/memory_reflection_origin \
    "$(printf '{"memory_id":"%s"}' "$R_DEEP")" "$AID_H")"
  assert_eq rec_learning "reflection_origin_is_reflection" "true" "$(json_field "$OB" is_reflection)"
  assert_eq rec_learning "reflection_origin_depth" "$REC_MAX_DEPTH" "$(json_field "$OB" original_depth)"
else
  skip rec_learning "reflection_origin_is_reflection" "true" "<no deepest reflection>"
fi

# reflects_on edges: exactly one signed-or-unsigned edge per chain hop must
# exist on the anchor's postgres schema (the atomic memory+links contract).
if [ "${#CHAIN_IDS[@]}" -gt 0 ]; then
  ids_sql="$(printf "'%s'," "${CHAIN_IDS[@]}")"; ids_sql="${ids_sql%,}"
  edge_n="$(pg_sql "$P1_H" "SELECT count(*) FROM memory_links WHERE relation='reflects_on' AND source_id IN ($ids_sql);")"
  assert_eq rec_learning "reflects_on_edges" "${#CHAIN_IDS[@]}" "${edge_n:-0}"
  # Signed-edge audit: when the daemon carries a signing keypair every edge
  # lands with a non-empty Ed25519 signature. Unsigned (no daemon key) is a
  # documented posture, not a defect — recorded honestly as SKIP.
  unsigned_n="$(pg_sql "$P1_H" "SELECT count(*) FROM memory_links WHERE relation='reflects_on' AND source_id IN ($ids_sql) AND (signature IS NULL OR signature='');")"
  if [ "${unsigned_n:-1}" = "0" ]; then
    pass rec_learning "reflects_on_edges_signed" "0 unsigned" "all $edge_n edges Ed25519-signed"
  else
    skip rec_learning "reflects_on_edges_signed" "0 unsigned" "$unsigned_n unsigned (daemon has no signing keypair — documented posture)"
  fi
else
  fail rec_learning "reflects_on_edges" ">=1" "<chain broke>"
fi

# Cross-region convergence: the deepest reflection replicates to a peer in
# EVERY OTHER region within the catchup window.
if [ -n "$R_DEEP" ]; then
  anchor_region="$(inv_peer_region "$P1_H")"
  for region in $(inv_regions); do
    [ "$region" = "$anchor_region" ] && continue
    tgt_ip="$(inv_ips_by_role peer | while read -r pip; do ph="$(inv_name_for_ip "$pip")"; [ "$(inv_peer_region "$ph")" = "$region" ] && { echo "$pip"; break; }; done)"
    [ -n "$tgt_ip" ] || { skip rec_learning "reflect_converge[$region]" "reflection present" "<no peer in region>"; continue; }
    tgt_h="$(inv_name_for_ip "$tgt_ip")"
    got="MISSING"
    for _ in $(seq 1 "$REC_CONVERGE_TRIES"); do
      r="$(body_req "$tgt_ip" 127.0.0.1 "$tgt_h" GET "/api/v1/memories/$R_DEEP" "" "$AID_H")"
      [ -n "$(json_field "$r" id)" ] && { got="present"; break; }
      sleep "$REC_CONVERGE_SLEEP_SECS"
    done
    assert_eq rec_learning "reflect_converge[$tgt_h]" "present" "$got"
  done
else
  skip rec_learning "reflect_converge" "present" "<no deepest reflection>"
fi

# ====================== GROUP rec_improve ====================================
# Recursive IMPROVEMENT: the curator daemon must be live (ReflectionPass +
# ConsolidationPass running against the federated postgres store), and the
# consolidate primitive must merge near-duplicate sources with provenance.
log "[rec_improve] curator liveness + consolidate merge on $P1_H"
for ip in $PEER_IPS; do
  h="$(inv_name_for_ip "$ip")"
  st="$(ssh_node "$ip" "systemctl is-active ai-memory-curator 2>/dev/null" 2>/dev/null | tr -d '[:space:]')"
  assert_eq rec_improve "curator_active[$h]" active "${st:-unknown}"
done

# Seed two near-duplicate attested sources, then consolidate them.
CN="con-$TS-$RANDOM"
SA_BODY="$(attested_body "$REC_NS_IMPROVE" "ri-src-a-$CN" observation collective "consolidation source alpha $CN shared topic")"
SB_BODY="$(attested_body "$REC_NS_IMPROVE" "ri-src-b-$CN" observation collective "consolidation source beta $CN shared topic")"
SA="$(json_field "$(body_req "$P1_IP" 127.0.0.1 "$P1_H" POST /api/v1/memories "$SA_BODY" "$AID_H")" id)"
SB="$(json_field "$(body_req "$P1_IP" 127.0.0.1 "$P1_H" POST /api/v1/memories "$SB_BODY" "$AID_H")" id)"
if [ -n "$SA" ] && [ -n "$SB" ]; then
  track "$SA" "$P1_IP" "$P1_H"; track "$SB" "$P1_IP" "$P1_H"
  CON_BODY="$(printf '{"ids":["%s","%s"],"title":"ri-merged-%s","namespace":"%s","summary":"merged %s","agent_id":"%s"}' "$SA" "$SB" "$CN" "$REC_NS_IMPROVE" "$CN" "$AID_H")"
  CR="$(body_req "$P1_IP" 127.0.0.1 "$P1_H" POST /api/v1/consolidate "$CON_BODY" "$AID_H")"
  CID="$(json_field "$CR" id)"
  if [ -n "$CID" ]; then
    pass rec_improve "consolidate_merge" "consolidated id present" "$CID"
    track "$CID" "$P1_IP" "$P1_H"
    # Provenance: the consolidated row records derived_from = source ids.
    # jsonb element-membership via the `?` operator (single-quoted text) —
    # NOT `@> '[\"...\"]'::jsonb`, whose embedded double-quotes collide with
    # the `ssh_node "... psql -tAc \"...\""` quoting layers and silently
    # parse-error to empty. `metadata->'derived_from'` is a flat string array
    # written by both SAL backends' consolidate; `? '<id>'` tests membership.
    dn="$(pg_sql "$P1_H" "SELECT count(*) FROM memories WHERE id='$CID' AND metadata->'derived_from' ? '$SA' AND metadata->'derived_from' ? '$SB';")"
    assert_eq rec_improve "consolidate_provenance" "1" "${dn:-0}"
    # Cross-region convergence of the consolidated memory.
    anchor_region="$(inv_peer_region "$P1_H")"
    for region in $(inv_regions); do
      [ "$region" = "$anchor_region" ] && continue
      tgt_ip="$(inv_ips_by_role peer | while read -r pip; do ph="$(inv_name_for_ip "$pip")"; [ "$(inv_peer_region "$ph")" = "$region" ] && { echo "$pip"; break; }; done)"
      [ -n "$tgt_ip" ] || continue
      tgt_h="$(inv_name_for_ip "$tgt_ip")"
      got="MISSING"
      for _ in $(seq 1 "$REC_CONVERGE_TRIES"); do
        r="$(body_req "$tgt_ip" 127.0.0.1 "$tgt_h" GET "/api/v1/memories/$CID" "" "$AID_H")"
        [ -n "$(json_field "$r" id)" ] && { got="present"; break; }
        sleep "$REC_CONVERGE_SLEEP_SECS"
      done
      assert_eq rec_improve "consolidate_converge[$tgt_h]" "present" "$got"
    done
  else
    fail rec_improve "consolidate_merge" "consolidated id present" "${CR:-<empty>}"
  fi
else
  fail rec_improve "consolidate_merge" "two sources written" "SA=${SA:-<none>} SB=${SB:-<none>}"
fi

# ---- assemble JSON report ---------------------------------------------------
{
  printf '{\n  "campaign": "%s",\n  "timestamp": "%s",\n  "suite": "recursive-frameworks",\n' "$CAMPAIGN" "$TS"
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
total="$(wc -l < "$TSV" | tr -d ' ')"
passed="$(grep -c '	PASS$' "$TSV" || true)"
failed="$(grep -c '	FAIL$' "$TSV" || true)"
skipped="$(grep -c '	SKIP$' "$TSV" || true)"
printf '\n'
column -t -s "$(printf '\t')" "$TSV" 2>/dev/null || cat "$TSV"
printf '\nTOTAL=%s  PASS=%s  FAIL=%s  SKIP=%s\n' "$total" "$passed" "$failed" "$skipped"
log "recursive report: $JSON"
if [ "${failed:-0}" -ne 0 ]; then
  log "RECURSIVE FRAMEWORKS FAILED — $failed check(s) red"
  exit 1
fi
log "RECURSIVE FRAMEWORKS PASSED — $passed/$total checks green ($skipped skipped)"
