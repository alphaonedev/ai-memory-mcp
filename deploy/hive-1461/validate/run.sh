#!/usr/bin/env bash
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
#
# Baseline verification harness. Probes the live fleet over the SAME TLS+mTLS
# path real traffic uses and emits BOTH a machine-readable JSON report and a
# human-readable PASS/FAIL table. Exit status is 0 iff every check passes — so
# this script is the gate for P2.2 (no testing until 100% green).
#
# Every check is an independent record {node, check, expected, got, status};
# nothing here is destructive to the baseline except the federation probe,
# which writes ONE collective-scope marker into the throwaway `_verify`
# namespace and best-effort deletes it.
#
# Checks
#   per node : binary sha256 == golden ; `--version` == EXPECTED_VERSION
#   per peer : /api/v1/health == ok (+ embedder_ready, federation_enabled) ;
#              capabilities.storage_backend == postgres ;
#              capabilities.db_schema_version == EXPECTED_SCHEMA ;
#              exactly ONE `ai-memory serve` process (single-instance) ;
#              systemd unit active
#   fleet    : federation convergence — write to peer-1, read by id on peer-2
#              within the catchup window, over TLS+mTLS.
source "$(dirname "$0")/../provision/lib.sh"

require_inventory

REPORTS="$RUN_DIR/reports"; mkdir -p "$REPORTS"
TS="$(date -u +%Y%m%dT%H%M%SZ)"
TSV="$REPORTS/verify-$TS.tsv"; : > "$TSV"
JSON="$REPORTS/verify-$TS.json"
REMOTE_TLS="/etc/ai-memory/tls"
NS_VERIFY="_verify"

# Daemon HTTP api_key (30_config.sh / S5-C1 #1458). Peers bind 0.0.0.0 and
# therefore run with a top-level `api_key`, so every privileged endpoint
# (/capabilities, POST/GET/DELETE /memories) demands `x-api-key`. /health is
# exempt and /sync/* bypasses under mTLS, so those probes work without it. The
# harness is a legitimate operator-side client: it reads the campaign key from
# the gitignored run dir and presents it — exercising the api-key auth path
# end-to-end. Empty key (keyless single-tenant baseline) → no header sent.
API_PW_FILE="$RUN_DIR/secrets/api.pw"
API_KEY=""; [ -s "$API_PW_FILE" ] && API_KEY="$(cat "$API_PW_FILE")"

# record <node> <check> <expected> <got> <PASS|FAIL>
record() { printf '%s\t%s\t%s\t%s\t%s\n' "$1" "$2" "$3" "$4" "$5" >> "$TSV"; }

# mtls_curl <ip> <host> <method> <path> [data] -> response body on stdout (or empty)
# Connects to the node's own loopback but verifies the DNS:<host> SAN and
# presents the node's allowlisted client cert — exercises the full crypto gate.
mtls_curl() {
  local ip="$1" host="$2" method="$3" path="$4" data="${5:-}"
  local base="--max-time 8 --resolve $host:$FEDERATION_PORT:127.0.0.1 \
    --cacert $REMOTE_TLS/ca.pem --cert $REMOTE_TLS/client.pem --key $REMOTE_TLS/client.key"
  local keyhdr=""; [ -n "$API_KEY" ] && keyhdr="-H 'x-api-key: $API_KEY'"
  if [ "$method" = "POST" ]; then
    ssh_node "$ip" "curl -fsS $base $keyhdr -X POST -H 'content-type: application/json' \
      --data '$data' https://$host:$FEDERATION_PORT$path" 2>/dev/null || true
  else
    ssh_node "$ip" "curl -fsS $base $keyhdr -X $method https://$host:$FEDERATION_PORT$path" 2>/dev/null || true
  fi
}

# json_field <body> <key> -> first scalar value for "key" (string or number)
json_field() {
  printf '%s' "$1" | sed -n "s/.*\"$2\"[[:space:]]*:[[:space:]]*\"\{0,1\}\([^\",}]*\)\"\{0,1\}.*/\1/p" | head -1
}

log "verification run $TS — golden sha=$GOLDEN_SHA256 version=$EXPECTED_VERSION schema=$EXPECTED_SCHEMA"

# ---- per-node: binary integrity (sha + version) -----------------------------
inv_all | while IFS="$(printf '\t')" read -r host role region pub priv; do
  rsha="$(ssh_node "$pub" "sha256sum /usr/local/bin/ai-memory 2>/dev/null | awk '{print \$1}'" || true)"
  [ "$rsha" = "$GOLDEN_SHA256" ] && record "$host" "binary.sha256" "$GOLDEN_SHA256" "$rsha" PASS \
                                 || record "$host" "binary.sha256" "$GOLDEN_SHA256" "${rsha:-<none>}" FAIL
  rver="$(ssh_node "$pub" "/usr/local/bin/ai-memory --version 2>/dev/null" || true)"
  case "$rver" in
    *"$EXPECTED_VERSION"*) record "$host" "binary.version" "*$EXPECTED_VERSION*" "$rver" PASS ;;
    *)                     record "$host" "binary.version" "*$EXPECTED_VERSION*" "${rver:-<none>}" FAIL ;;
  esac
done

# ---- per-peer: health / capabilities / single-instance ----------------------
inv_all | while IFS="$(printf '\t')" read -r host role region pub priv; do
  [ "$role" = "peer" ] || continue

  health="$(mtls_curl "$pub" "$host" GET /api/v1/health)"
  hstatus="$(json_field "$health" status)"
  [ "$hstatus" = "ok" ] && record "$host" "health.status" ok "${hstatus:-<unreachable>}" PASS \
                        || record "$host" "health.status" ok "${hstatus:-<unreachable>}" FAIL
  hver="$(json_field "$health" version)"
  [ "$hver" = "$EXPECTED_VERSION" ] && record "$host" "health.version" "$EXPECTED_VERSION" "$hver" PASS \
                                    || record "$host" "health.version" "$EXPECTED_VERSION" "${hver:-<none>}" FAIL
  emb="$(json_field "$health" embedder_ready)"
  [ "$emb" = "true" ] && record "$host" "health.embedder_ready" true "$emb" PASS \
                      || record "$host" "health.embedder_ready" true "${emb:-<none>}" FAIL
  fed="$(json_field "$health" federation_enabled)"
  [ "$fed" = "true" ] && record "$host" "health.federation_enabled" true "$fed" PASS \
                      || record "$host" "health.federation_enabled" true "${fed:-<none>}" FAIL

  caps="$(mtls_curl "$pub" "$host" GET /api/v1/capabilities)"
  backend="$(json_field "$caps" storage_backend)"
  [ "$backend" = "postgres" ] && record "$host" "caps.storage_backend" postgres "$backend" PASS \
                              || record "$host" "caps.storage_backend" postgres "${backend:-<none>}" FAIL
  dbschema="$(json_field "$caps" db_schema_version)"
  [ "$dbschema" = "$EXPECTED_SCHEMA" ] && record "$host" "caps.db_schema_version" "$EXPECTED_SCHEMA" "$dbschema" PASS \
                                       || record "$host" "caps.db_schema_version" "$EXPECTED_SCHEMA" "${dbschema:-<none>}" FAIL

  active="$(ssh_node "$pub" "systemctl is-active ai-memory.service 2>/dev/null" || true)"
  [ "$active" = "active" ] && record "$host" "systemd.active" active "$active" PASS \
                           || record "$host" "systemd.active" active "${active:-<none>}" FAIL

  # Bracket the first char so the pattern string in THIS pgrep's own remote
  # shell cmdline (`pgrep -fc '[a]i-memory serve'`) does not satisfy the regex
  # `[a]i-memory serve` (which needs a literal `ai-memory serve`) — otherwise
  # `-f` self-matches the matcher's shell and reports one extra instance.
  nproc="$(ssh_node "$pub" "pgrep -fc '[a]i-memory serve' 2>/dev/null" || echo 0)"
  [ "$nproc" = "1" ] && record "$host" "single_instance" 1 "$nproc" PASS \
                     || record "$host" "single_instance" 1 "${nproc:-0}" FAIL
done

# ---- fleet: federation convergence (write peer-1 -> read peer-2) ------------
p1_ip="$(inv_ips_by_role peer | sed -n 1p)"
p2_ip="$(inv_ips_by_role peer | sed -n 2p)"
if [ -n "$p1_ip" ] && [ -n "$p2_ip" ]; then
  p1_host="$(inv_name_for_ip "$p1_ip")"
  p2_host="$(inv_name_for_ip "$p2_ip")"
  marker="verify-$TS-$RANDOM"
  body="{\"title\":\"$marker\",\"content\":\"federation convergence probe $marker\",\"namespace\":\"$NS_VERIFY\",\"scope\":\"collective\"}"
  log "federation probe: writing $marker to $p1_host, expecting it on $p2_host"
  wresp="$(mtls_curl "$p1_ip" "$p1_host" POST /api/v1/memories "$body")"
  mid="$(json_field "$wresp" id)"
  if [ -z "$mid" ]; then
    record "fleet" "federation.write" "memory id" "<write failed>" FAIL
  else
    record "fleet" "federation.write" "memory id" "$mid" PASS
    conv=FAIL; got="<not replicated within window>"
    i=0
    while [ "$i" -lt 20 ]; do
      rresp="$(mtls_curl "$p2_ip" "$p2_host" GET "/api/v1/memories/$mid")"
      case "$rresp" in
        *"$marker"*) conv=PASS; got="$mid present on $p2_host"; break ;;
      esac
      i=$((i+1)); sleep 2
    done
    record "fleet" "federation.convergence" "$mid on $p2_host" "$got" "$conv"
    # best-effort cleanup — keep the baseline pristine
    mtls_curl "$p1_ip" "$p1_host" DELETE "/api/v1/memories/$mid" >/dev/null 2>&1 || true
  fi
else
  record "fleet" "federation.convergence" ">=2 peers" "<need 2 peers>" FAIL
fi

# ---- assemble JSON report ---------------------------------------------------
{
  printf '{\n  "campaign": "%s",\n  "timestamp": "%s",\n' "$CAMPAIGN" "$TS"
  printf '  "expected": {"version": "%s", "schema": %s, "golden_sha256": "%s"},\n' \
    "$EXPECTED_VERSION" "$EXPECTED_SCHEMA" "$GOLDEN_SHA256"
  printf '  "checks": [\n'
  first=1
  while IFS="$(printf '\t')" read -r node check expected got status; do
    [ "$first" = 1 ] && first=0 || printf ',\n'
    printf '    {"node": "%s", "check": "%s", "expected": "%s", "got": "%s", "status": "%s"}' \
      "$node" "$check" "$expected" "$got" "$status"
  done < "$TSV"
  printf '\n  ]\n}\n'
} > "$JSON"

# ---- human summary ----------------------------------------------------------
# `grep -c` already emits 0 on no-match — but it also EXITS 1, which under the
# `set -euo pipefail` inherited from lib.sh would abort this script. Neutralise
# the exit with `|| true` (NOT `|| echo 0`, which would append a second 0 →
# "0\n0" and break the integer test below).
total="$(grep -c . "$TSV" || true)"
passed="$(awk -F'\t' '$5=="PASS"' "$TSV" | grep -c . || true)"
failed="$(awk -F'\t' '$5=="FAIL"' "$TSV" | grep -c . || true)"

printf '\n'
printf '================ %s baseline verification (%s) ================\n' "$CAMPAIGN" "$TS"
printf '%-26s %-28s %-10s %s\n' "NODE" "CHECK" "STATUS" "GOT"
printf '%-26s %-28s %-10s %s\n' "----" "-----" "------" "---"
awk -F'\t' '{printf "%-26s %-28s %-10s %s\n", $1, $2, $5, $4}' "$TSV"
printf -- '----------------------------------------------------------------\n'
printf 'TOTAL=%s  PASS=%s  FAIL=%s\n' "$total" "$passed" "$failed"
printf 'machine report: %s\n' "$JSON"
printf 'human  report: %s\n' "$TSV"

if [ "$failed" -ne 0 ]; then
  log "VERIFICATION FAILED — $failed check(s) red. Baseline is NOT validated."
  exit 1
fi
log "VERIFICATION PASSED — $passed/$total checks green. Baseline validated."
