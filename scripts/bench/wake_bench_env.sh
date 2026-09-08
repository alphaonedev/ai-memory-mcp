#!/usr/bin/env bash
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
#
# =============================================================================
# wake_bench_env.sh -- shared lifecycle for the #3473 wake-plane acceptance run.
# SOURCED, never executed. `wake_abab.sh` and `wake_hub_kill.sh` both need the
# same daemon, the same hub, the same enrolled agents and the same teardown,
# and two copies of that would be two things that can drift apart.
# =============================================================================
#
# Everything here is hermetic in the way `run-ops-producers.sh` (#2921) is:
# HOME, XDG_CONFIG_HOME, XDG_DATA_HOME and AI_MEMORY_KEY_DIR are ALL redirected
# into the run directory, so a stray config lookup cannot reach an operator's
# real store, keys or daemon.
#
# Three properties are specific to this lane and are load-bearing:
#
#   * TLS ONLY. The daemon is served with `--tls-cert/--tls-key` from a
#     certificate minted into the run directory, and the harness pins THAT
#     certificate. No unencrypted listener is ever opened, and no operator key
#     material is reused to do it.
#   * THE STORE URL NEVER TOUCHES ARGV. It is written to a 0600 file and passed
#     through `AI_MEMORY_STORE_URL_FILE` (#1927), because a userinfo password
#     on argv is readable by any local uid through `ps auxww`.
#   * THE REFRESHER IS NOT OPTIONAL. `wake_hub::identity` refuses every hello
#     once the allowlist snapshot is older than 60 s, and re-validates every
#     ESTABLISHED session against it once per second. A measurement run without
#     a refresher does not degrade gracefully -- it drops every session about a
#     minute in and reports a hub that "lost" every wake. `wb_start_refresher`
#     republishes every 30 s, half the ceiling, exactly as the shipped
#     systemd/launchd units do.
#
# Identity ceremony, and an honest deviation
# ------------------------------------------
# The agents' v97 key history is established in a LOCAL SQLITE ceremony
# database (`$WB_RUN/ceremony.db`) even when the daemon serves PostgreSQL.
# `agents register` / `agents bind-key` are structurally sqlite-path-only
# (#3418 declares `--store-url` on the api-key verbs and nowhere else), so on a
# postgres tier the bind would otherwise require the admin HTTP ceremony and an
# admin credential.
#
# This does not touch the measured path, and here is exactly why: the hub opens
# NO database on either backend -- it verifies a hello against the allowlist
# SNAPSHOT FILE, and which store the exporter derived that file from is a
# property of the ceremony, not of the wake. The measured surfaces
# (`POST /api/v1/notify`, `GET /api/v1/inbox/stream`, `GET /api/v1/inbox`) all
# run against the served store. The one real consequence is that the
# `identity.hub_allow` / `identity.hub_revoke` audit rows land on the ceremony
# database's signed_events spine rather than the served one; that is recorded
# here rather than left for someone to discover.

set -euo pipefail

WB_HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

WB_BINARY="${WB_BINARY:-}"
WB_RUN="${WB_RUN:-}"
WB_PORT="${WB_PORT:-19473}"
WB_HUB_ID="${WB_HUB_ID:-ai-memory-wake-hub}"
# ONE agent-id vocabulary in two dialects, because `printf` and Python
# format strings cannot share a literal. They are ASSERTED equal at init
# rather than trusted: a silent divergence would enrol one set of agents and
# then measure a different set, and every wake would go missing for a reason
# no counter could name.
WB_AGENT_TEMPLATE_PRINTF="${WB_AGENT_TEMPLATE_PRINTF:-ai:wake-bench-%04d}"
WB_AGENT_TEMPLATE_PY="${WB_AGENT_TEMPLATE_PY:-ai:wake-bench-{i:04d}}"
WB_SENDER="${WB_SENDER:-ai:wake-bench-sender}"
WB_DELEGATION_TTL="${WB_DELEGATION_TTL:-10800}"
WB_MAX_CONNECTIONS="${WB_MAX_CONNECTIONS:-512}"
WB_NOFILE="${WB_NOFILE:-4096}"
WB_REFRESH_SECS="${WB_REFRESH_SECS:-30}"
# MEASUREMENT-ONLY quota lift, recorded as a deviation exactly as #2921's
# producers record theirs. Every notify in a rung is written by ONE sender, so
# at the shipped 1000 writes/day default a 256-agent rung stops dead partway
# through with `429` -- which measures the quota, not the wake plane. The quota
# CHECK still runs on every write, so its per-write cost stays inside the
# measured path.
WB_QUOTA_WRITES="${WB_QUOTA_WRITES:-10000000}"
WB_QUOTA_BYTES="${WB_QUOTA_BYTES:-10737418240}"

WB_DAEMON_PID=""
WB_HUB_PID=""
WB_REFRESHER_PID=""

wb_log() { printf '[wake-bench] %s\n' "$*" >&2; }

wb_die() { printf '[wake-bench] FATAL: %s\n' "$*" >&2; exit 70; }

# --- disk floor ------------------------------------------------------------
# The lane's binding floor. Stop BEFORE producing anything rather than fill a
# host and take the node down mid-run.
#
# POSIX `df -Pk`, never `df -g`. `-g` is a BSD/macOS spelling that GNU
# coreutils does not accept: on f2 (Linux) it makes `df` fail, `$4` come back
# EMPTY, and the guard then compares an empty string — so the floor either
# dies on every run or, worse, reads as satisfied. `-P` guarantees one line
# per filesystem (no wrap on a long device name) and `-k` fixes the unit, so
# the arithmetic is the same on both hosts. A non-numeric result REFUSES
# rather than defaulting: a disk guard that cannot read the disk has not
# cleared anything.
wb_check_disk() {
  local free
  free="$(df -Pk "${WB_RUN}" | awk 'NR==2 {print int($4/1048576)}')"
  case "$free" in
    ''|*[!0-9]*) wb_die "could not read free disk on ${WB_RUN} (df -Pk gave '${free}')" ;;
  esac
  if [ "$free" -lt "${WB_DISK_FLOOR_GB:-100}" ]; then
    wb_die "free disk on ${WB_RUN} is ${free} GB, below the ${WB_DISK_FLOOR_GB:-100} GB floor"
  fi
  wb_log "disk: ${free} GB free"
}

# --- init ------------------------------------------------------------------
wb_init() {
  [ -n "$WB_BINARY" ] || wb_die "WB_BINARY is unset (path to the release ai-memory)"
  [ -x "$WB_BINARY" ] || wb_die "WB_BINARY ${WB_BINARY} is not executable"
  [ -n "$WB_RUN" ] || wb_die "WB_RUN is unset (the run directory)"
  mkdir -p "$WB_RUN"
  WB_RUN="$(cd "$WB_RUN" && pwd)"
  WB_BINARY="$(cd "$(dirname "$WB_BINARY")" && pwd)/$(basename "$WB_BINARY")"
  WB_HOME="${WB_RUN}/home"
  WB_KEYS="${WB_RUN}/keys"
  WB_BUNDLES="${WB_RUN}/bundles"
  WB_SOCKDIR="${WB_RUN}/hub"
  WB_SOCKET="${WB_SOCKDIR}/wake-hub.sock"
  WB_ALLOWLIST="${WB_RUN}/hub-allow.json"
  WB_CEREMONY_DB="${WB_RUN}/ceremony.db"
  WB_TLS_CERT="${WB_RUN}/tls/cert.pem"
  WB_TLS_KEY="${WB_RUN}/tls/key.pem"
  WB_STORE_URL_FILE="${WB_RUN}/store-url"
  WB_BASE_URL="https://127.0.0.1:${WB_PORT}"
  mkdir -p "$WB_HOME" "${WB_HOME}/.config" "${WB_HOME}/.local/share" \
           "$WB_KEYS" "$WB_BUNDLES" "$WB_SOCKDIR" "${WB_RUN}/tls" "${WB_RUN}/results"
  # The hub REFUSES to bind inside a directory another local user could write,
  # and `ai-memory wake-listen` (and this harness's hub arm) refuse to dial one.
  chmod 700 "$WB_SOCKDIR" "$WB_KEYS" "$WB_BUNDLES"
  wb_assert_agent_template_agreement
  wb_check_disk
}

# --- the 48 s first-exec stall --------------------------------------------
# A freshly built binary has been measured stalling ~48 s at 0 % CPU on its
# FIRST exec on f1. Spend it here, once, on `--version`, and PUBLISH the cost.
# It is a host fact about f1 and it is never folded into a measured percentile.
wb_prewarm_binary() {
  local t0 t1 ms ver
  # ONE exec, and it is the timed one. Calling `--version` again to fill the
  # JSON would report the FIRST exec's cost beside the SECOND exec's output,
  # and the second exec is warm by construction — the number and the string
  # would then describe different events.
  t0="$(python3 -c 'import time; print(time.perf_counter())')"
  ver="$("$WB_BINARY" --version 2>/dev/null | head -1)"
  t1="$(python3 -c 'import time; print(time.perf_counter())')"
  [ -n "$ver" ] || wb_die "the binary would not run (${WB_BINARY} --version produced nothing)"
  ms="$(python3 -c "print(round((${t1}-${t0})*1000, 1))")"
  wb_log "binary first-exec warm-up: ${ms} ms (DISCARDED; f1 host effect, never a percentile)"
  python3 -c 'import json,sys; print(json.dumps({"binary_first_exec_ms": float(sys.argv[1]), "binary": sys.argv[2]}))' \
    "$ms" "$ver" >"${WB_RUN}/results/host-effects.json"
}

# --- TLS -------------------------------------------------------------------
# A certificate minted INTO THE RUN DIRECTORY, self-signed, SAN IP:127.0.0.1.
# Deliberately not the host's postgres server certificate: operator key
# material is not a bench input, and a self-signed cert we pin ourselves is
# strictly stronger here than anything in a platform trust store.
wb_mint_tls() {
  if [ -s "$WB_TLS_CERT" ] && [ -s "$WB_TLS_KEY" ]; then
    wb_log "tls: reusing ${WB_TLS_CERT}"
    return 0
  fi
  openssl req -x509 -newkey rsa:2048 -sha256 -days 2 -nodes \
    -keyout "$WB_TLS_KEY" -out "$WB_TLS_CERT" \
    -subj "/CN=127.0.0.1/O=ai-memory wake bench 3473" \
    -addext "subjectAltName=IP:127.0.0.1" >/dev/null 2>&1 \
    || wb_die "could not mint the bench TLS certificate"
  chmod 600 "$WB_TLS_KEY" "$WB_TLS_CERT"
  wb_log "tls: minted ${WB_TLS_CERT} (self-signed, pinned by the harness)"
}

# --- store url -------------------------------------------------------------
# wb_write_store_url <source-url-file> <db-name>
# Swaps ONLY the database name. Refuses `ai_memory_test` outright: that is the
# shared live database on this host, and a bench that migrated it would be a
# data-loss event, not a failed run.
wb_write_store_url() {
  local src="$1" dbname="$2"
  [ -r "$src" ] || wb_die "store URL source ${src} is not readable"
  case "$dbname" in
    ai_memory_test) wb_die "refusing to run against the live ai_memory_test database" ;;
  esac
  python3 - "$src" "$dbname" "$WB_STORE_URL_FILE" <<'PY'
import sys
import urllib.parse

src, dbname, out = sys.argv[1], sys.argv[2], sys.argv[3]
url = open(src, encoding="utf-8").read().strip()
parts = urllib.parse.urlsplit(url)
if dbname == "ai_memory_test":
    raise SystemExit("refusing the live database name")
swapped = urllib.parse.urlunsplit(
    (parts.scheme, parts.netloc, "/" + dbname, parts.query, parts.fragment))
with open(out, "w", encoding="utf-8") as fh:
    fh.write(swapped + "\n")
# The DATABASE name is safe to print; the credential is not.
print(f"store: {parts.scheme}://<redacted>@<host>:{parts.port}/{dbname}")
PY
  chmod 600 "$WB_STORE_URL_FILE"
}

# --- schema ----------------------------------------------------------------
# Idempotent bootstrap of the served store. Run ONCE, before any timed leg: a
# daemon that bootstraps its schema inside a measured window reports the
# bootstrap as latency.
wb_schema_init() {
  HOME="$WB_HOME" XDG_CONFIG_HOME="${WB_HOME}/.config" \
  XDG_DATA_HOME="${WB_HOME}/.local/share" AI_MEMORY_NO_CONFIG=1 \
  AI_MEMORY_KEY_DIR="$WB_KEYS" AI_MEMORY_STORE_URL_FILE="$WB_STORE_URL_FILE" \
    "$WB_BINARY" schema-init --json >"${WB_RUN}/schema-init.json" 2>&1 \
    || { tail -20 "${WB_RUN}/schema-init.json" >&2; wb_die "schema-init failed"; }
  wb_log "schema-init: ok"
}

# --- daemon ----------------------------------------------------------------
# wb_start_daemon <sink-socket|"">
# An EMPTY sink socket is the A leg: no `[wake_hub]` block at all, so the
# daemon starts no forwarder, opens no hub socket and loads no producer
# identity. That is the shipped default posture and it is what "hub off" has
# to mean -- stopping the hub process while leaving the sink configured would
# measure a reconnect ladder rather than a baseline.
wb_start_daemon() {
  local sink="${1:-}"
  local cfg="${WB_HOME}/.config/ai-memory/config.toml"
  mkdir -p "$(dirname "$cfg")"
  {
    echo 'tier = "keyword"'
    if [ -n "$sink" ]; then
      echo ''
      echo '[wake_hub]'
      echo "sink_socket = \"${sink}\""
      echo "hub_id = \"${WB_HUB_ID}\""
    fi
  } >"$cfg"
  (
    export HOME="$WB_HOME"
    export XDG_CONFIG_HOME="${WB_HOME}/.config"
    export XDG_DATA_HOME="${WB_HOME}/.local/share"
    export AI_MEMORY_KEY_DIR="$WB_KEYS"
    export AI_MEMORY_STORE_URL_FILE="$WB_STORE_URL_FILE"
    export AI_MEMORY_MAX_MEMORIES_PER_DAY="$WB_QUOTA_WRITES"
    export AI_MEMORY_MAX_STORAGE_BYTES="$WB_QUOTA_BYTES"
    ulimit -n "$WB_NOFILE" 2>/dev/null || true
    exec "$WB_BINARY" serve --host 127.0.0.1 --port "$WB_PORT" \
      --tls-cert "$WB_TLS_CERT" --tls-key "$WB_TLS_KEY" \
      >"${WB_RUN}/daemon.log" 2>&1
  ) &
  WB_DAEMON_PID=$!
  local i=0
  # 120 attempts: the FIRST loopback round-trip in a fresh process on f1 has
  # been measured above 10 s, and this is the process that pays it.
  while [ "$i" -lt 120 ]; do
    if curl -fsS --cacert "$WB_TLS_CERT" --max-time 5 \
        "${WB_BASE_URL}/api/v1/health" >/dev/null 2>&1; then
      wb_log "daemon healthy on ${WB_BASE_URL} (sink=${sink:-none}) pid=${WB_DAEMON_PID}"
      return 0
    fi
    if ! kill -0 "$WB_DAEMON_PID" 2>/dev/null; then
      tail -40 "${WB_RUN}/daemon.log" >&2 || true
      wb_die "the daemon exited during start-up; see ${WB_RUN}/daemon.log"
    fi
    i=$((i + 1)); sleep 1
  done
  tail -40 "${WB_RUN}/daemon.log" >&2 || true
  wb_die "the daemon never became healthy; see ${WB_RUN}/daemon.log"
}

wb_stop_daemon() {
  [ -n "$WB_DAEMON_PID" ] || return 0
  # SIGTERM, never SIGKILL and never `pkill -f`: the daemon has a drain, and a
  # pattern kill on this host could reach a process that is not ours.
  kill -TERM "$WB_DAEMON_PID" 2>/dev/null || true
  wait "$WB_DAEMON_PID" 2>/dev/null || true
  WB_DAEMON_PID=""
}

# --- agents ----------------------------------------------------------------
wb_agent_id() { printf "$WB_AGENT_TEMPLATE_PRINTF" "$1"; }

# Render the same indices through both dialects and refuse on disagreement.
# Index 0 catches a missing pad; 4095 catches a width that stops padding.
wb_assert_agent_template_agreement() {
  local i sh py
  for i in 0 7 4095; do
    sh="$(printf "$WB_AGENT_TEMPLATE_PRINTF" "$i")"
    py="$(python3 -c 'import sys; print(sys.argv[1].format(i=int(sys.argv[2])))' \
            "$WB_AGENT_TEMPLATE_PY" "$i")"
    [ "$sh" = "$py" ] || wb_die \
      "agent-id templates disagree at index ${i}: printf gave '${sh}', python gave '${py}'"
  done
  wb_log "agent-id template: $(wb_agent_id 0) .. $(wb_agent_id 4095) (both dialects agree)"
}

wb_cli() {
  HOME="$WB_HOME" XDG_CONFIG_HOME="${WB_HOME}/.config" \
  XDG_DATA_HOME="${WB_HOME}/.local/share" AI_MEMORY_NO_CONFIG=1 \
  AI_MEMORY_KEY_DIR="$WB_KEYS" "$WB_BINARY" "$@"
}

# wb_enroll_agents <count>
# Idempotent: an agent whose delegation bundle is already present and still
# inside its window is skipped, so a re-run after a crash costs seconds rather
# than repeating the whole ceremony.
wb_enroll_agents() {
  local count="$1" i id pub
  wb_log "enrolling ${count} agents (generate -> register -> bind-key -> delegate)"
  wb_cli identity generate --key-dir "$WB_KEYS" --agent-id daemon --json >/dev/null 2>&1 || true
  wb_cli identity generate --key-dir "$WB_KEYS" --agent-id "$WB_SENDER" --json >/dev/null 2>&1 || true
  i=0
  while [ "$i" -lt "$count" ]; do
    id="$(wb_agent_id "$i")"
    if [ -s "${WB_BUNDLES}/${id}.a2a-hub.json" ]; then
      i=$((i + 1)); continue
    fi
    wb_cli identity generate --key-dir "$WB_KEYS" --agent-id "$id" --json >/dev/null 2>&1 || true
    pub="$(wb_cli identity export-pub --key-dir "$WB_KEYS" --agent-id "$id")"
    wb_cli agents register --db "$WB_CEREMONY_DB" --agent-id "$id" \
      --agent-type "ai:wake-bench" --json >/dev/null \
      || wb_die "could not register ${id}"
    wb_cli agents bind-key --db "$WB_CEREMONY_DB" --agent-id "$id" \
      --pubkey="$pub" --json >/dev/null \
      || wb_die "could not bind ${id}'s key (proof of possession is done for us: the private key is in ${WB_KEYS})"
    wb_cli identity delegate --db "$WB_CEREMONY_DB" --agent-id "$id" \
      --scope a2a-hub --hub-id "$WB_HUB_ID" --ttl-secs "$WB_DELEGATION_TTL" \
      --out "${WB_BUNDLES}/${id}.a2a-hub.json" --json >/dev/null \
      || wb_die "could not mint ${id}'s a2a-hub delegation"
    i=$((i + 1))
    if [ $((i % 32)) -eq 0 ]; then wb_log "  enrolled ${i}/${count}"; fi
  done
  wb_log "enrolled ${count} agents; bundles in ${WB_BUNDLES}"
}

# --- allowlist snapshot + refresher ----------------------------------------
wb_publish_allowlist() {
  local count="$1" i args=()
  i=0
  while [ "$i" -lt "$count" ]; do
    args+=(--include-agent "$(wb_agent_id "$i")")
    i=$((i + 1))
  done
  wb_cli identity hub-cache --db "$WB_CEREMONY_DB" "${args[@]}" \
    --daemon-producer --out "$WB_ALLOWLIST" --json >"${WB_RUN}/allowlist-publish.json" \
    || wb_die "could not publish the hub allowlist"
  chmod 600 "$WB_ALLOWLIST"
}

# The snapshot expires into REFUSAL at 60 s and every established session is
# re-validated against it once per second. Without this loop a run simply stops
# a minute in and looks like a hub that dropped every agent.
wb_start_refresher() {
  local count="$1"
  wb_publish_allowlist "$count"
  (
    while true; do
      sleep "$WB_REFRESH_SECS"
      wb_publish_allowlist "$count" >/dev/null 2>&1 || true
    done
  ) &
  WB_REFRESHER_PID=$!
  wb_log "allowlist refresher every ${WB_REFRESH_SECS}s (ceiling 60s) pid=${WB_REFRESHER_PID}"
}

wb_stop_refresher() {
  [ -n "$WB_REFRESHER_PID" ] || return 0
  kill -TERM "$WB_REFRESHER_PID" 2>/dev/null || true
  wait "$WB_REFRESHER_PID" 2>/dev/null || true
  WB_REFRESHER_PID=""
}

# --- hub -------------------------------------------------------------------
wb_start_hub() {
  rm -f "$WB_SOCKET"
  (
    export HOME="$WB_HOME"
    export XDG_CONFIG_HOME="${WB_HOME}/.config"
    export XDG_DATA_HOME="${WB_HOME}/.local/share"
    export AI_MEMORY_NO_CONFIG=1
    export AI_MEMORY_KEY_DIR="$WB_KEYS"
    # macOS ships a soft RLIMIT_NOFILE of 256, which is EXACTLY the design
    # target; the shipped launchd plist pins 4096 for this reason and running
    # the hub by hand without it lands EMFILE at 256 agents.
    ulimit -n "$WB_NOFILE" 2>/dev/null || true
    exec "$WB_BINARY" wake-hub --socket "$WB_SOCKET" --hub-id "$WB_HUB_ID" \
      --max-connections "$WB_MAX_CONNECTIONS" --allowlist "$WB_ALLOWLIST" \
      >"${WB_RUN}/hub.log" 2>&1
  ) &
  WB_HUB_PID=$!
  local i=0
  while [ "$i" -lt 60 ]; do
    if wb_cli wake-hub --socket "$WB_SOCKET" --health >/dev/null 2>&1; then
      wb_log "hub healthy on ${WB_SOCKET} pid=${WB_HUB_PID}"
      return 0
    fi
    if ! kill -0 "$WB_HUB_PID" 2>/dev/null; then
      tail -40 "${WB_RUN}/hub.log" >&2 || true
      wb_die "the hub exited during start-up; see ${WB_RUN}/hub.log"
    fi
    i=$((i + 1)); sleep 1
  done
  tail -40 "${WB_RUN}/hub.log" >&2 || true
  wb_die "the hub never became reachable; see ${WB_RUN}/hub.log"
}

wb_stop_hub() {
  [ -n "$WB_HUB_PID" ] || return 0
  kill -TERM "$WB_HUB_PID" 2>/dev/null || true
  wait "$WB_HUB_PID" 2>/dev/null || true
  WB_HUB_PID=""
}

# SIGKILL, by the PID THIS SCRIPT started. Never `pkill -f`, which on a shared
# host can reach a process that is not ours.
wb_kill_hub() {
  [ -n "$WB_HUB_PID" ] || wb_die "no hub to kill"
  wb_log "SIGKILL hub pid=${WB_HUB_PID}"
  kill -KILL "$WB_HUB_PID" 2>/dev/null || true
  wait "$WB_HUB_PID" 2>/dev/null || true
  WB_HUB_PID=""
}

wb_cleanup() {
  wb_stop_refresher
  wb_stop_hub
  wb_stop_daemon
}

wb_python() {
  python3 "${WB_HERE}/wake_latency.py" "$@"
}
