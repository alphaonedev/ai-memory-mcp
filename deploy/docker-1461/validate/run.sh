#!/usr/bin/env bash
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
#
# docker-1461 — baseline verification harness (D5).
#
# Probes the live 2-peer + PG/AGE mesh over the SAME TLS+mTLS path real
# traffic uses and emits BOTH a machine-readable JSON report and a human
# PASS/FAIL table. Exit status is 0 iff every check passes — so this script
# is the gate before the D6 full-spectrum harness runs (no testing until the
# baseline is 100% green).
#
# This is the Docker analog of deploy/hive-1461/validate/run.sh. The hive
# toolkit reaches DigitalOcean droplets over `ssh` + systemd; here every
# in-container probe goes through `docker exec` (node_exec) and every API
# probe goes through host-loopback `curl` over the campaign CA + client cert
# (mtls_curl_*). No literal name/port/path/version is inlined — all flow from
# the provision/lib.sh SSOT.
#
# Checks
#   per peer (in-container) : `--version` contains EXPECTED_VERSION ;
#                             container reports docker-healthy ;
#                             exactly ONE `ai-memory` process (single-instance)
#   per peer (over mTLS)    : /health status == ok (+ version, embedder_ready,
#                             federation_enabled) ; capabilities.storage_backend
#                             == postgres ; capabilities.db_schema_version ==
#                             EXPECTED_SCHEMA
#   fleet                   : daemon -> PostgreSQL leg is TLS (third encrypted
#                             leg) — every daemon-owned PG backend negotiated
#                             ssl=true (pg_stat_ssl, >=1 ssl / 0 plain) ;
#                             federation convergence — write a collective marker
#                             to peer-1, read it by id on peer-2 within the
#                             catch-up window, best-effort DELETE cleanup.
#
# Every check is an independent record {node, check, expected, got, status};
# nothing here mutates the baseline except the federation probe, which writes
# ONE marker into the throwaway NS_VERIFY namespace and best-effort deletes it.

set -euo pipefail
SELF_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../provision/lib.sh
. "$SELF_DIR/../provision/lib.sh"

mkdir -p "$REPORTS_DIR"
TS="$(date -u +%Y%m%dT%H%M%SZ)"
TSV="$REPORTS_DIR/validate-$TS.tsv"; : > "$TSV"
JSON="$REPORTS_DIR/validate-$TS.json"
NS_VERIFY="${DOCKER_1461_VERIFY_NS:-_verify}"

# record <node> <check> <expected> <got> <PASS|FAIL>
record() { printf '%s\t%s\t%s\t%s\t%s\n' "$1" "$2" "$3" "$4" "$5" >> "$TSV"; }

# rec_eq <node> <check> <expected> <got> [missing-placeholder]
# PASS iff got == expected (exact string), else FAIL. Empty got renders as the
# placeholder (default <none>) in the report. Avoids the A && B || C footgun.
rec_eq() {
  local node="$1" check="$2" expected="$3" got="$4" miss="${5:-<none>}"
  if [ "$got" = "$expected" ]; then
    record "$node" "$check" "$expected" "$got" PASS
  else
    record "$node" "$check" "$expected" "${got:-$miss}" FAIL
  fi
}

log "validate $TS — expecting version=$EXPECTED_VERSION schema=$EXPECTED_SCHEMA peers=$PEER_COUNT pg=$EXPECTED_PG_VERSION age=$EXPECTED_AGE_VERSION"

# --------------------------------------------------------------------------
# Per-peer: in-container integrity + container health + single-instance.
# --------------------------------------------------------------------------
for i in $(seq 1 "$PEER_COUNT"); do
  name="$(peer_name "$i")"

  # Binary version (in-container). The daemon prints a legacy-config WARN to
  # stderr on some invocations — capture stdout only.
  rver="$(node_exec "$name" "$REMOTE_BINARY" --version 2>/dev/null || true)"
  case "$rver" in
    *"$EXPECTED_VERSION"*) record "$name" "binary.version" "*$EXPECTED_VERSION*" "$rver" PASS ;;
    *)                     record "$name" "binary.version" "*$EXPECTED_VERSION*" "${rver:-<none>}" FAIL ;;
  esac

  # Container docker-health (the compose healthcheck is itself an mTLS HTTPS
  # probe, so a healthy container already implies a live TLS listener).
  if node_healthy "$name"; then
    record "$name" "container.health" healthy healthy PASS
  else
    hs="$(docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}' "$name" 2>/dev/null || echo unreachable)"
    record "$name" "container.health" healthy "${hs:-unreachable}" FAIL
  fi

  # Single-instance: the bookworm-slim image has NO pgrep, so scan /proc/*/comm
  # for the daemon's process name. `comm` is the 15-char-truncated command name;
  # "ai-memory" (9 chars) fits. The daemon is pid 1, so exactly one match is
  # expected. The sh/cat/grep helpers carry their own comm names, not the
  # daemon's, so they never self-inflate the count. grep -c exits 1 on zero
  # matches (would trip set -e) — default to 0 via `|| echo`.
  nproc="$(node_exec "$name" sh -c 'cat /proc/[0-9]*/comm 2>/dev/null | grep -c "^ai-memory$"' 2>/dev/null || echo 0)"
  rec_eq "$name" "single_instance" 1 "$nproc" 0
done

# --------------------------------------------------------------------------
# Per-peer: health + capabilities over host-loopback mTLS.
# --------------------------------------------------------------------------
for i in $(seq 1 "$PEER_COUNT"); do
  name="$(peer_name "$i")"
  port="$(peer_port "$i")"

  health="$(mtls_curl_body "$port" GET "$API_HEALTH")"
  rec_eq "$name" "health.status" ok "$(json_field "$health" status)" "<unreachable>"
  rec_eq "$name" "health.version" "$EXPECTED_VERSION" "$(json_field "$health" version)"
  rec_eq "$name" "health.embedder_ready" true "$(json_field "$health" embedder_ready)"
  rec_eq "$name" "health.federation_enabled" true "$(json_field "$health" federation_enabled)"

  caps="$(mtls_curl_body "$port" GET "$API_CAPABILITIES")"
  rec_eq "$name" "caps.storage_backend" postgres "$(json_field "$caps" storage_backend)"
  rec_eq "$name" "caps.db_schema_version" "$EXPECTED_SCHEMA" "$(json_field "$caps" db_schema_version)"
done

# --------------------------------------------------------------------------
# Fleet: store-stack version anchors. The operator directive requires the
# campaign run on PostgreSQL EXACTLY 18.4 + Apache AGE EXACTLY 1.7.0; assert
# the LIVE server reports those upstream versions so every published result
# is peer-verifiable against the pinned stack (lib.sh EXPECTED_PG_VERSION /
# EXPECTED_AGE_VERSION). `server_version` yields the bare minor (e.g. 18.4);
# AGE's installed version comes from pg_extension.extversion.
# --------------------------------------------------------------------------
pg_ver="$(node_exec "$PG_CONTAINER" psql -U "$PG_USER" -d "$PG_DB" -tAc "select current_setting('server_version')" 2>/dev/null | tr -d '[:space:]' || true)"
rec_eq fleet "store.pg_version" "$EXPECTED_PG_VERSION" "$pg_ver" "<unreachable>"
age_ver="$(node_exec "$PG_CONTAINER" psql -U "$PG_USER" -d "$PG_DB" -tAc "select extversion from pg_extension where extname='age'" 2>/dev/null | tr -d '[:space:]' || true)"
rec_eq fleet "store.age_version" "$EXPECTED_AGE_VERSION" "$age_ver" "<not installed>"

# --------------------------------------------------------------------------
# Fleet: the daemon -> PostgreSQL leg is TLS (third encrypted leg). Inspect
# pg_stat_ssl joined to pg_stat_activity INSIDE the PG container: every TCP
# backend owned by the daemon role must report ssl=true, and there must be at
# least one (proving the daemons actually hold encrypted pooled connections,
# not merely "zero plaintext"). The probe's own psql is a unix-socket backend
# (client_addr IS NULL) and is excluded, so only the daemons' TCP connections
# are counted.
# --------------------------------------------------------------------------
pg_ssl_q="select count(*) from pg_stat_ssl s join pg_stat_activity a on s.pid=a.pid where a.usename='$PG_USER' and a.client_addr is not null and a.backend_type='client backend'"
ssl_on="$(node_exec "$PG_CONTAINER" psql -U "$PG_USER" -d "$PG_DB" -tAc "$pg_ssl_q and s.ssl is true" 2>/dev/null | tr -d '[:space:]' || echo x)"
ssl_off="$(node_exec "$PG_CONTAINER" psql -U "$PG_USER" -d "$PG_DB" -tAc "$pg_ssl_q and s.ssl is not true" 2>/dev/null | tr -d '[:space:]' || echo x)"
if [ "$ssl_off" = "0" ] && [ -n "$ssl_on" ] && [ "$ssl_on" != "0" ] && [ "$ssl_on" != "x" ]; then
  record fleet "daemon_pg.tls" "encrypted (>=1 ssl, 0 plain)" "ssl=$ssl_on plain=$ssl_off" PASS
else
  record fleet "daemon_pg.tls" "encrypted (>=1 ssl, 0 plain)" "ssl=${ssl_on:-?} plain=${ssl_off:-?}" FAIL
fi

# --------------------------------------------------------------------------
# Fleet: federation convergence (write peer-1 -> read peer-2 over mTLS).
# --------------------------------------------------------------------------
if [ "$PEER_COUNT" -ge 2 ]; then
  p1_port="$(peer_port 1)"; p1_name="$(peer_name 1)"
  p2_port="$(peer_port 2)"; p2_name="$(peer_name 2)"
  marker="validate-$TS-$RANDOM"
  body="{\"title\":\"$marker\",\"content\":\"federation convergence probe $marker\",\"namespace\":\"$NS_VERIFY\",\"scope\":\"collective\"}"
  log "federation probe: writing $marker to $p1_name, expecting it on $p2_name"
  wresp="$(mtls_curl_body "$p1_port" POST "$API_MEMORIES" "$body" "$(peer_agent_id 1)")"
  mid="$(json_field "$wresp" id)"
  if [ -z "$mid" ]; then
    record "fleet" "federation.write" "memory id" "<write failed>" FAIL
  else
    record "fleet" "federation.write" "memory id" "$mid" PASS
    conv=FAIL; got="<not replicated within window>"
    n=0
    while [ "$n" -lt 20 ]; do
      rresp="$(mtls_curl_body "$p2_port" GET "$API_MEMORIES/$mid" "" "$(peer_agent_id 2)")"
      case "$rresp" in
        *"$marker"*) conv=PASS; got="$mid present on $p2_name"; break ;;
      esac
      n=$((n + 1)); sleep 2
    done
    record "fleet" "federation.convergence" "$mid on $p2_name" "$got" "$conv"
    # best-effort cleanup — keep the baseline pristine
    mtls_curl_code "$p1_port" DELETE "$API_MEMORIES/$mid" "" "$(peer_agent_id 1)" >/dev/null 2>&1 || true
  fi
else
  record "fleet" "federation.convergence" ">=2 peers" "<need 2 peers>" FAIL
fi

# --------------------------------------------------------------------------
# Assemble JSON report.
# --------------------------------------------------------------------------
{
  printf '{\n  "campaign": "%s",\n  "timestamp": "%s",\n' "$CAMPAIGN" "$TS"
  printf '  "expected": {"version": "%s", "schema": %s},\n' "$EXPECTED_VERSION" "$EXPECTED_SCHEMA"
  printf '  "checks": [\n'
  first=1
  while IFS="$(printf '\t')" read -r node check expected got status; do
    [ "$first" = 1 ] && first=0 || printf ',\n'
    printf '    {"node": "%s", "check": "%s", "expected": "%s", "got": "%s", "status": "%s"}' \
      "$node" "$check" "$expected" "$got" "$status"
  done < "$TSV"
  printf '\n  ]\n}\n'
} > "$JSON"

# --------------------------------------------------------------------------
# Human summary. `grep -c` emits 0 on no-match but EXITS 1 — neutralise with
# `|| true` (NOT `|| echo 0`, which would append a second 0 and break the
# integer test below).
# --------------------------------------------------------------------------
total="$(grep -c . "$TSV" || true)"
passed="$(awk -F'\t' '$5=="PASS"' "$TSV" | grep -c . || true)"
failed="$(awk -F'\t' '$5=="FAIL"' "$TSV" | grep -c . || true)"

printf '\n'
printf '================ %s baseline verification (%s) ================\n' "$CAMPAIGN" "$TS"
printf '%-22s %-28s %-8s %s\n' "NODE" "CHECK" "STATUS" "GOT"
printf '%-22s %-28s %-8s %s\n' "----" "-----" "------" "---"
awk -F'\t' '{printf "%-22s %-28s %-8s %s\n", $1, $2, $5, $4}' "$TSV"
printf -- '----------------------------------------------------------------\n'
printf 'TOTAL=%s  PASS=%s  FAIL=%s\n' "$total" "$passed" "$failed"
printf 'machine report: %s\n' "$JSON"
printf 'human  report: %s\n' "$TSV"

if [ "$failed" -ne 0 ]; then
  die "VERIFICATION FAILED — $failed check(s) red. Baseline is NOT validated."
fi
log "VERIFICATION PASSED — $passed/$total checks green. Baseline validated."
