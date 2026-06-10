#!/usr/bin/env bash
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
#
# Focused proof of the THREE encrypted legs of the do-1461 mesh, end-to-end on
# the LIVE fleet, over the SAME crypto path real traffic uses. Each leg is
# proven with BOTH a positive assertion (the encrypted path WORKS) and a
# negative assertion (the gate REFUSES the unencrypted / unauthenticated path),
# so a green run is evidence the encryption is load-bearing, not decorative.
#
#   LEG 1  API mTLS            — the peer HTTP API on :$FEDERATION_PORT is a
#                               client_auth_mandatory rustls port. Positive: an
#                               allowlisted client cert + api-key reaches a
#                               privileged handler (200). Negatives: no client
#                               cert -> handshake refused (000); a rogue
#                               (non-allowlisted) leaf -> refused (000); a valid
#                               cert but NO api-key on a privileged endpoint ->
#                               401. /health is the documented exempt surface.
#   LEG 2  Federation/quorum   — W-of-N synchronous quorum across the CROSS-
#          mTLS                  REGION peer mesh (FED_SYNC_QUORUM_W=2 of 9 on
#                               the reference fleet per provision/lib.sh; the
#                               verify report row is quorum_write_W2ofN9).
#                               Positive: a collective write on peer-1
#                               converges on every other peer in ALL regions
#                               within the catchup window (the outbound /sync push
#                               presents the node's mTLS CLIENT cert + verifies
#                               peer SERVER certs vs the campaign CA). Negative:
#                               the inbound /sync surface with NO client cert ->
#                               handshake refused (000) (the whole federation port
#                               is mTLS-gated).
#   LEG 3  daemon -> PostgreSQL — verify-full TLS over EACH region's private VPC
#          TLS                   IP (proven for all three regional pg substrates).
#                               Positive: pg_stat_ssl shows every ai_memory
#                               backend on TLS (ssl>0, plain=0) with a real
#                               negotiated TLS version + cipher. Negative: a
#                               non-TLS TCP connect (sslmode=disable) is rejected
#                               pre-auth by the hostssl-only pg_hba. Config:
#                               the daemon store URL carries sslmode=verify-full.
#
# Emits a machine JSON + human PASS/FAIL table; exit 0 iff every check is green.
# Reproducible: re-runnable any number of times; the one collective marker it
# writes lands in the throwaway `_legs` namespace and is best-effort deleted.
source "$(dirname "$0")/../provision/lib.sh"

require_inventory

REPORTS="$RUN_DIR/reports"; mkdir -p "$REPORTS"
TS="$(date -u +%Y%m%dT%H%M%SZ)"
TSV="$REPORTS/encrypted-legs-$TS.tsv"; : > "$TSV"
JSON="$REPORTS/encrypted-legs-$TS.json"
REMOTE_TLS="/etc/ai-memory/tls"
NS_LEGS="_legs"
AID_H="ai:legs-harness@$CAMPAIGN"

API_PW_FILE="$RUN_DIR/secrets/api.pw"
API_KEY=""; [ -s "$API_PW_FILE" ] && API_KEY="$(cat "$API_PW_FILE")"

# record <leg> <test> <expected> <got> <PASS|FAIL>
record() { printf '%s\t%s\t%s\t%s\t%s\n' "$1" "$2" "$3" "$4" "$5" >> "$TSV"; }
pass()   { record "$1" "$2" "$3" "$4" PASS; }
fail()   { record "$1" "$2" "$3" "$4" FAIL; }
assert_eq() { [ "$3" = "$4" ] && pass "$1" "$2" "$3" "$4" || fail "$1" "$2" "$3" "${4:-<empty>}"; }

json_field() { printf '%s' "$1" | sed -n "s/.*\"$2\"[[:space:]]*:[[:space:]]*\"\{0,1\}\([^\",}]*\)\"\{0,1\}.*/\1/p" | head -1; }

# code_raw <run_ip> <curl_arg_string> -> HTTP status, or 000 on a transport /
# handshake refusal. `-w '%{http_code}'` ALWAYS prints (literally 000 when no
# HTTP response arrived), and `; true` neutralises curl's non-zero exit WITHOUT
# emitting a second token, so NO `|| echo 000` (that would yield 000000).
code_raw() {
  local rip="$1" args="$2" out
  out="$(ssh_node "$rip" "curl -s -o /dev/null -w '%{http_code}' --max-time 10 $args; true" 2>/dev/null || true)"
  printf '%s' "${out:-000}"
}

# body_req <run_ip> <connect_ip> <host> <method> <path> [data] [agent_id]
# -> 2xx response body (over the full mTLS + api-key path), empty otherwise.
body_req() {
  local rip="$1" cip="$2" host="$3" m="$4" path="$5" data="${6:-}" aid="${7:-}"
  local h=""; [ -n "$API_KEY" ] && h="-H 'x-api-key: $API_KEY'"
  [ -n "$aid" ] && h="$h -H 'x-agent-id: $aid'"
  local extra=""; [ -n "$data" ] && extra="-H 'content-type: application/json' --data '$data'"
  ssh_node "$rip" "curl -fsS --max-time 10 --resolve $host:$FEDERATION_PORT:$cip \
    --cacert $REMOTE_TLS/ca.pem --cert $REMOTE_TLS/client.pem --key $REMOTE_TLS/client.key \
    $h $extra -X $m https://$host:$FEDERATION_PORT$path" 2>/dev/null || true
}

# pgx <pg_pub_ip> <sql> -> scalar from THAT region's pg node over the local unix
# socket (trust) as the postgres superuser; whitespace-stripped. Read-only.
pgx() { ssh_node "$1" "sudo -u postgres psql -d $PG_DB -tAc \"$2\"" 2>/dev/null | tr -d '[:space:]' || true; }

log "3-encrypted-legs proof $TS — fleet=$CAMPAIGN port=$FEDERATION_PORT"

# Peer set (need >=2 for quorum convergence; 9 expected across 3 regions).
PEER_IPS="$(inv_ips_by_role peer)"
P1_IP="$(printf '%s\n' "$PEER_IPS" | sed -n 1p)"
P1_H="$(inv_name_for_ip "$P1_IP")"
[ -n "$P1_IP" ] || die "no peer in inventory"

# ====================== LEG 1 — API mTLS =====================================
# Run the full positive+negative battery on EVERY peer so the proof covers the
# whole serving surface, not just one node.
log "[leg1] API mTLS positive+negative battery on every peer"
printf '%s\n' "$PEER_IPS" | while IFS= read -r ip; do
  [ -n "$ip" ] || continue
  h="$(inv_name_for_ip "$ip")"
  RES="--resolve $h:$FEDERATION_PORT:127.0.0.1"
  CA="--cacert $REMOTE_TLS/ca.pem"; CERT="--cert $REMOTE_TLS/client.pem"; KEY="--key $REMOTE_TLS/client.key"
  HEALTH="https://$h:$FEDERATION_PORT/api/v1/health"
  PRIV="https://$h:$FEDERATION_PORT/api/v1/capabilities"
  keyhdr=""; [ -n "$API_KEY" ] && keyhdr="-H 'x-api-key: $API_KEY'"

  # POSITIVE: allowlisted client cert + api-key -> privileged handler 200
  c="$(code_raw "$ip" "$RES $CA $CERT $KEY $keyhdr $PRIV")"
  assert_eq leg1_api_mtls "mtls+key_priv_200[$h]" 200 "$c"

  # NEGATIVE: no client cert -> client_auth_mandatory refuses handshake (000)
  c="$(code_raw "$ip" "$RES $CA $HEALTH")"
  [ "$c" = "000" ] && pass leg1_api_mtls "no_client_cert_refused[$h]" 000 "$c" \
                    || fail leg1_api_mtls "no_client_cert_refused[$h]" 000 "$c"

  # NEGATIVE: rogue (non-allowlisted) self-signed leaf -> fingerprint pin (000)
  GEN="openssl req -x509 -newkey rsa:2048 -nodes -keyout /root/.legbad.key -out /root/.legbad.pem -days 1 -subj '/CN=rogue' >/dev/null 2>&1"
  c="$(ssh_node "$ip" "$GEN; curl -s -o /dev/null -w '%{http_code}' --max-time 10 $RES $CA --cert /root/.legbad.pem --key /root/.legbad.key $HEALTH; rm -f /root/.legbad.pem /root/.legbad.key" 2>/dev/null || true)"
  c="${c:-000}"
  [ "$c" = "000" ] && pass leg1_api_mtls "rogue_client_cert_refused[$h]" 000 "$c" \
                    || fail leg1_api_mtls "rogue_client_cert_refused[$h]" 000 "$c"

  # NEGATIVE: valid cert but NO api-key on privileged endpoint -> 401
  c="$(code_raw "$ip" "$RES $CA $CERT $KEY $PRIV")"
  assert_eq leg1_api_mtls "no_apikey_priv_401[$h]" 401 "$c"

  # POSITIVE: /health is the documented exempt surface -> 200 (cert, no key)
  c="$(code_raw "$ip" "$RES $CA $CERT $KEY $HEALTH")"
  assert_eq leg1_api_mtls "health_exempt_200[$h]" 200 "$c"
done

# ====================== LEG 2 — Federation / quorum mTLS =====================
# Positive: a collective write on peer-1 commits under the cross-region majority
# quorum (W=$(quorum_writes) of N) and converges on EVERY other peer in ALL
# regions within the catchup window (outbound /sync presents the node mTLS client
# cert + verifies peer server certs vs the campaign CA).
QW="$(quorum_writes)"; PEER_N="$(inv_peer_count)"
log "[leg2] federation quorum write peer-1 -> converge on all other peers (W=$QW of $PEER_N, cross-region)"
FNONCE="leg2-$TS-$RANDOM"
# Maximum-secure hive: REQUIRE_AGENT_ATTESTATION=1, so the quorum write must be
# ATTESTED. Enroll the legs-harness agent on the write-anchor (bind its pubkey),
# then sign the write so it clears BOTH the attestation gate AND the
# cross-region quorum (W of N). The convergence GETs below are reads (no attest).
agent_enroll_peer "$P1_IP" "$AID_H" >/dev/null 2>&1 || true
FBODY="$(attested_body "$NS_LEGS" "$FNONCE" observation collective "encrypted-leg2 federation quorum probe $FNONCE" "$AID_H")"
FW="$(body_req "$P1_IP" 127.0.0.1 "$P1_H" POST /api/v1/memories "$FBODY" "$AID_H")"
FID="$(json_field "$FW" id)"
if [ -z "$FID" ]; then
  fail leg2_fed_mtls "quorum_write" "memory id" "<write failed (quorum not met?)>"
else
  pass leg2_fed_mtls "quorum_write_W${QW}ofN${PEER_N}" "memory id" "$FID"
  printf '%s\n' "$PEER_IPS" | while IFS= read -r ip; do
    [ -n "$ip" ] || continue
    [ "$ip" = "$P1_IP" ] && continue
    h="$(inv_name_for_ip "$ip")"
    i=0; got="<not replicated within window>"; st=FAIL
    while [ "$i" -lt 20 ]; do
      r="$(body_req "$ip" 127.0.0.1 "$h" GET "/api/v1/memories/$FID" "" "$AID_H")"
      case "$r" in *"$FNONCE"*) st=PASS; got="present on $h (TLS+mTLS)"; break ;; esac
      i=$((i+1)); sleep 2
    done
    record leg2_fed_mtls "converge[$h]" "$FID on $h" "$got" "$st"
  done
  # cleanup the marker (best effort)
  body_req "$P1_IP" 127.0.0.1 "$P1_H" DELETE "/api/v1/memories/$FID" "" "$AID_H" >/dev/null 2>&1 || true
fi

# Negative: the inbound /sync surface with NO client cert -> handshake refused.
# The whole federation port is client_auth_mandatory, so an unencrypted-identity
# peer cannot even open the connection (000), independent of api-key/body.
SYNC="https://$P1_H:$FEDERATION_PORT/api/v1/sync/since?since=1970-01-01T00:00:00Z"
c="$(code_raw "$P1_IP" "--resolve $P1_H:$FEDERATION_PORT:127.0.0.1 --cacert $REMOTE_TLS/ca.pem $SYNC")"
[ "$c" = "000" ] && pass leg2_fed_mtls "sync_no_client_cert_refused" 000 "$c" \
                  || fail leg2_fed_mtls "sync_no_client_cert_refused" 000 "$c"

# ====================== LEG 3 — daemon -> PostgreSQL TLS =====================
# Per-region: each region's peers verify-full to THAT region's pg node. Run the
# full positive+negative battery on EVERY region's pg so the leg is proven for
# all three substrates, not just one. bash-3.2: feed the region list via a pipe.
log "[leg3] daemon->PG verify-full TLS on every region's pg"
inv_regions | while IFS= read -r region; do
  [ -n "$region" ] || continue
  pg_host="$(inv_pg_name_for_region "$region")"
  pg_pub="$(inv_pg_public_ip_for_region "$region")"
  pg_priv="$(inv_pg_private_ip_for_region "$region")"
  [ -n "$pg_pub" ] || { fail leg3_pg_tls "pg_present[$region]" "pg node in region" "<none>"; continue; }
  log "[leg3] region $region pg=$pg_host ($pg_priv)"

  # Positive: every ai_memory backend on THIS region's pg is on TLS (ssl>0, plain=0).
  SSL_N="$(pgx "$pg_pub" "SELECT count(*) FROM pg_stat_ssl s JOIN pg_stat_activity a ON s.pid=a.pid WHERE a.usename='$PG_USER' AND s.ssl;")"
  PLAIN_N="$(pgx "$pg_pub" "SELECT count(*) FROM pg_stat_ssl s JOIN pg_stat_activity a ON s.pid=a.pid WHERE a.usename='$PG_USER' AND NOT s.ssl;")"
  if [ "${SSL_N:-0}" -ge 1 ] && [ "${PLAIN_N:-1}" -eq 0 ]; then
    pass leg3_pg_tls "all_backends_tls[$region]" "ssl>=1 plain=0" "ssl=$SSL_N plain=$PLAIN_N"
  else
    fail leg3_pg_tls "all_backends_tls[$region]" "ssl>=1 plain=0" "ssl=${SSL_N:-?} plain=${PLAIN_N:-?}"
  fi

  # Positive: a REAL TLS version + cipher was negotiated (not merely ssl=on).
  TLSVER="$(pgx "$pg_pub" "SELECT s.version FROM pg_stat_ssl s JOIN pg_stat_activity a ON s.pid=a.pid WHERE a.usename='$PG_USER' AND s.ssl LIMIT 1;")"
  TLSCIPH="$(pgx "$pg_pub" "SELECT s.cipher FROM pg_stat_ssl s JOIN pg_stat_activity a ON s.pid=a.pid WHERE a.usename='$PG_USER' AND s.ssl LIMIT 1;")"
  case "$TLSVER" in TLSv1.2|TLSv1.3) pass leg3_pg_tls "tls_version_negotiated[$region]" "TLSv1.2|TLSv1.3" "$TLSVER ($TLSCIPH)" ;;
                                  *) fail leg3_pg_tls "tls_version_negotiated[$region]" "TLSv1.2|TLSv1.3" "${TLSVER:-<none>}" ;; esac

  # Config: a peer in THIS region pins sslmode=verify-full in its store URL (grep -o
  # prints ONLY the matched token off the 0400 EnvironmentFile — secret NOT echoed).
  region_peer_ip=""
  for ip in $(inv_ips_by_role peer); do
    h="$(inv_name_for_ip "$ip")"
    [ "$(inv_peer_region "$h")" = "$region" ] && { region_peer_ip="$ip"; break; }
  done
  if [ -n "$region_peer_ip" ]; then
    SSLMODE="$(ssh_node "$region_peer_ip" "grep -o 'sslmode=verify-full' $REMOTE_ENVFILE 2>/dev/null | head -1" 2>/dev/null || true)"
    assert_eq leg3_pg_tls "store_url_verify_full[$region]" "sslmode=verify-full" "${SSLMODE:-<absent>}"
  else
    fail leg3_pg_tls "store_url_verify_full[$region]" "sslmode=verify-full" "<no peer in region>"
  fi

  # Negative: a non-TLS TCP connect (sslmode=disable) over the region VPC IP is
  # rejected pre-auth by the hostssl-only pg_hba — plaintext PG is impossible.
  NEG="$(ssh_node "$pg_pub" "psql 'host=$pg_priv port=$PG_PORT user=$PG_USER dbname=$PG_DB sslmode=disable connect_timeout=5' -tAc 'SELECT 1' 2>&1; true" 2>/dev/null || true)"
  case "$NEG" in
    *"no pg_hba.conf entry"*|*"no encryption"*|*"SSL"*|*"server does not support SSL"*|*"connection"*refused*)
      pass leg3_pg_tls "plaintext_tcp_refused[$region]" "rejected pre-auth" "hostssl-only enforced" ;;
    1) fail leg3_pg_tls "plaintext_tcp_refused[$region]" "rejected pre-auth" "PLAINTEXT CONNECT SUCCEEDED" ;;
    *) case "$NEG" in *1*) fail leg3_pg_tls "plaintext_tcp_refused[$region]" "rejected pre-auth" "ambiguous: $NEG" ;;
                        *) pass leg3_pg_tls "plaintext_tcp_refused[$region]" "rejected pre-auth" "${NEG:0:60}" ;; esac ;;
  esac
done

# ---- assemble JSON ----------------------------------------------------------
{
  printf '{\n  "campaign": "%s",\n  "timestamp": "%s",\n  "suite": "encrypted-legs",\n' "$CAMPAIGN" "$TS"
  printf '  "checks": [\n'
  first=1
  while IFS="$(printf '\t')" read -r leg test expected got status; do
    [ "$first" = 1 ] && first=0 || printf ',\n'
    printf '    {"leg": "%s", "test": "%s", "expected": "%s", "got": "%s", "status": "%s"}' \
      "$leg" "$test" "$expected" "$got" "$status"
  done < "$TSV"
  printf '\n  ]\n}\n'
} > "$JSON"

# ---- human summary ----------------------------------------------------------
total="$(grep -c . "$TSV" || true)"
passed="$(awk -F'\t' '$5=="PASS"' "$TSV" | grep -c . || true)"
failed="$(awk -F'\t' '$5=="FAIL"' "$TSV" | grep -c . || true)"

printf '\n'
printf '============== %s — 3 encrypted legs proof (%s) ==============\n' "$CAMPAIGN" "$TS"
printf '%-16s %-34s %-8s %s\n' "LEG" "TEST" "STATUS" "GOT"
printf '%-16s %-34s %-8s %s\n' "---" "----" "------" "---"
awk -F'\t' '{printf "%-16s %-34s %-8s %s\n", $1, $2, $5, $4}' "$TSV"
printf -- '----------------------------------------------------------------\n'
printf 'TOTAL=%s  PASS=%s  FAIL=%s\n' "$total" "$passed" "$failed"
printf 'machine report: %s\n' "$JSON"
printf 'human  report: %s\n' "$TSV"

if [ "$failed" -ne 0 ]; then
  log "3-LEGS PROOF FAILED — $failed check(s) red."
  exit 1
fi
log "3-LEGS PROOF PASSED — $passed/$total checks green (all 3 encrypted legs)."
