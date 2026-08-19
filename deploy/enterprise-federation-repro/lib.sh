# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
#
# enterprise-federation-repro — shared constants + helpers (SSOT).
#
# This kit stands up the EXACT environment the v1.0.0 enterprise-federation
# audit used, so any AI NHI (or human peer reviewer) can reproduce it 100%
# from committed steps: a PostgreSQL 18.6 + Apache AGE 1.8.0 + pgvector 0.8.6
# data tier over TLS 1.3 (hostssl-only, cleartext refused) + mTLS to the
# store, an ai-memory daemon wired into ONLY that tier over the encrypted
# store link and served on the client<->daemon mTLS API (:9077) under the
# certified enterprise-federation posture.
#
# EXTEND, DO NOT FORK. The PG/AGE/pgvector VERSION PINS are NOT re-declared
# here — they are SOURCED from the canonical docker-1461 provisioning SSOT
# (deploy/docker-1461/provision/lib.sh), the same file
# tests/provisioning_pgvector_pin_parity.rs and scripts/check-docs-vs-ssot.sh
# read. The container image is built from the CANONICAL in-repo Dockerfile
# (deploy/docker-1461/Dockerfile.pg-age-vector) and the hostssl proof reuses
# deploy/docker-1461/pg-hostssl-healthcheck.sh. This kit adds ONLY the
# audit-shaped pieces docker-1461 (a 2-peer federation MESH) does not carry:
# the single-daemon standup, the store TLS + client<->daemon mTLS cert sets,
# the deterministic seed-corpus generator, and the 3x7 verify harness.
#
# Every value below is env-overridable so a fork re-points names/ports/paths
# without editing code. bash-3.2 safe (macOS /bin/bash): no assoc arrays, no
# `mapfile`. Sourced, not executed.
# shellcheck shell=bash
# shellcheck disable=SC2034

set -euo pipefail

# --------------------------------------------------------------------------
# Repo + kit anchoring. KIT_DIR = deploy/enterprise-federation-repro ;
# REPO_ROOT = two levels up.
# --------------------------------------------------------------------------
KIT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$KIT_DIR/../.." && pwd)"

# The canonical docker-1461 provisioning SSOT — the ONE place the PG/AGE/
# pgvector version literals live. Source it read-only to inherit the pins.
DOCKER_1461_LIB="${REPO_ROOT}/deploy/docker-1461/provision/lib.sh"
DOCKER_1461_DOCKERFILE="${REPO_ROOT}/deploy/docker-1461/Dockerfile.pg-age-vector"
DOCKER_1461_HEALTHCHECK="${REPO_ROOT}/deploy/docker-1461/pg-hostssl-healthcheck.sh"

# --------------------------------------------------------------------------
# Logging (declared before we source the pins so a missing SSOT fails loud).
# --------------------------------------------------------------------------
log()  { printf '[%s] %s\n' "$(date -u +%H:%M:%SZ)" "$*" >&2; }
warn() { printf '[%s] WARN %s\n' "$(date -u +%H:%M:%SZ)" "$*" >&2; }
die()  { printf '[%s] FATAL %s\n' "$(date -u +%H:%M:%SZ)" "$*" >&2; exit 1; }

# --------------------------------------------------------------------------
# Inherit the PG/AGE/pgvector pins from the docker-1461 SSOT. We source it in
# a guarded subshell-free way: it is itself `set -euo pipefail` and only
# assigns constants (no side effects on our run dir). If it is ever removed
# or renamed, this kit fails LOUD rather than inventing its own version
# literals (which would be a second SSOT — exactly what the no-hardcoded
# rule forbids).
# --------------------------------------------------------------------------
[ -r "$DOCKER_1461_LIB" ] || die "cannot read the docker-1461 pin SSOT ($DOCKER_1461_LIB) — this kit inherits the PG/AGE/pgvector version pins from it and must NOT re-declare them"
# shellcheck source=/dev/null
. "$DOCKER_1461_LIB"

# The three assertion anchors we inherit (fail loud if the SSOT shape drifts).
: "${EXPECTED_PG_VERSION:?docker-1461 SSOT did not define EXPECTED_PG_VERSION}"
: "${EXPECTED_AGE_VERSION:?docker-1461 SSOT did not define EXPECTED_AGE_VERSION}"
: "${PGVECTOR_APT_VERSION:?docker-1461 SSOT did not define PGVECTOR_APT_VERSION}"
: "${PG_APT_VERSION:?docker-1461 SSOT did not define PG_APT_VERSION}"
: "${AGE_APT_VERSION:?docker-1461 SSOT did not define AGE_APT_VERSION}"
: "${AGE_BASE_IMAGE:?docker-1461 SSOT did not define AGE_BASE_IMAGE}"
: "${PG_MAJOR:?docker-1461 SSOT did not define PG_MAJOR}"
: "${AGE_GRAPH_NAME:?docker-1461 SSOT did not define AGE_GRAPH_NAME}"

# The bare upstream pgvector x.y.z (0.8.6-1.pgdg13+1 -> 0.8.6). Reuses the
# parity-test extraction shape so this kit and check-docs-vs-ssot.sh agree.
EXPECTED_PGVECTOR_VERSION="$(printf '%s' "$PGVECTOR_APT_VERSION" | grep -oE '^[0-9]+\.[0-9]+\.[0-9]+')"

# --------------------------------------------------------------------------
# Campaign identity (distinct from docker-1461 so both can co-exist).
# --------------------------------------------------------------------------
CAMPAIGN="${EF_REPRO_CAMPAIGN:-ef-repro}"

# --------------------------------------------------------------------------
# Host run dir (gitignored — NEVER /tmp, NEVER committed). Holds generated
# TLS material, the pg data volume name, the store-url secret file (0600),
# the seed corpus, the daemon key/witness/recorder/judge/stopper dirs, the
# certified posture env, and the machine/human reports.
# --------------------------------------------------------------------------
RUN_DIR="${EF_REPRO_RUN_DIR:-${REPO_ROOT}/.local-runs/${CAMPAIGN}}"
TLS_DIR="${RUN_DIR}/tls"                 # store TLS + client<->daemon mTLS material
KEYS_DIR="${RUN_DIR}/keys"               # daemon + audit-custody Ed25519 keys
SEED_DIR="${RUN_DIR}/seed"               # deterministic sqlite seed corpus
LOG_DIR="${RUN_DIR}/logs"                # daemon + pg logs
REPORTS_DIR="${RUN_DIR}/reports"         # verify.sh machine/human output
PG_PASSWORD_FILE="${RUN_DIR}/pg_password"          # 0600
STORE_URL_FILE="${RUN_DIR}/store-url"              # 0600 — AI_MEMORY_STORE_URL_FILE
POSTURE_ENV_FILE="${RUN_DIR}/posture.env"          # rendered certified posture env
SEED_DB="${SEED_DIR}/seed.db"                       # sqlite:/// migrate source
DAEMON_PID_FILE="${RUN_DIR}/daemon.pid"
DAEMON_LOG="${LOG_DIR}/daemon.log"

# --------------------------------------------------------------------------
# The certified daemon's own key-custody dirs (DELIBERATELY DISTINCT per the
# certified posture — a mount the daemon READS but a compromised process
# cannot OVERWRITE; here they are separate subdirs under KEYS_DIR).
# --------------------------------------------------------------------------
DAEMON_KEY_DIR="${KEYS_DIR}/daemon"
WITNESS_KEY_DIR="${KEYS_DIR}/witness"
RECORDER_KEY_DIR="${KEYS_DIR}/recorder"
JUDGE_KEY_DIR="${KEYS_DIR}/judge"
STOPPER_KEY_DIR="${KEYS_DIR}/stopper"

# --------------------------------------------------------------------------
# PostgreSQL 18.6 + AGE 1.8.0 + pgvector 0.8.6 container.
# --------------------------------------------------------------------------
PG_CONTAINER="${EF_REPRO_PG_CONTAINER:-${CAMPAIGN}-pg}"
PG_IMAGE="${EF_REPRO_PG_IMAGE:-ai-memory-cert-pg:pg${EXPECTED_PG_VERSION}-age${EXPECTED_AGE_VERSION}-pgv${EXPECTED_PGVECTOR_VERSION}}"
PG_VOLUME="${EF_REPRO_PG_VOLUME:-${CAMPAIGN}-pgdata}"
PG_HOST="${EF_REPRO_PG_HOST:-127.0.0.1}"
PG_PORT="${EF_REPRO_PG_PORT:-15452}"     # host loopback port the daemon dials
PG_USER="${EF_REPRO_PG_USER:-ai_memory}"
PG_DB="${EF_REPRO_PG_DB:-ai_memory}"
# search_path pins the app schema first, then ag_catalog (AGE) + public
# (pgvector). NOTE (audit finding #3055): an unqualified CREATE TABLE lands
# app tables in ag_catalog when ag_catalog precedes the app schema; putting
# `public` first here keeps ai-memory's own tables in `public`.
PG_SEARCH_PATH="${EF_REPRO_PG_SEARCH_PATH:-public,ag_catalog}"
PG_SSL_MODE="${EF_REPRO_PG_SSL_MODE:-verify-full}"

# In-container TLS install path (postgres-owned; a bind-mounted host key
# keeps its host uid and PostgreSQL refuses an ssl_key_file it does not own).
PG_TLS_INSTALL_DIR="/etc/postgresql/tls"
PG_HBA_CONTAINER_PATH="/etc/postgresql/pg_hba.conf"
PG_INIT_SQL_CONTAINER_PATH="/docker-entrypoint-initdb.d/01-extensions.sql"

# --------------------------------------------------------------------------
# Store TLS + mTLS material (leg 1: daemon -> PG, sslmode=verify-full).
#   ca.crt / ca.key                 campaign CA (key 0600)
#   pg-server.crt / pg-server.key   PG leaf (SAN IP:127.0.0.1,DNS:localhost)
#   pg-client.crt / pg-client.key   client leaf (CN = the pg role, mTLS)
# --------------------------------------------------------------------------
CA_CERT="${TLS_DIR}/ca.crt"
CA_KEY="${TLS_DIR}/ca.key"
PG_SERVER_CERT="${TLS_DIR}/pg-server.crt"
PG_SERVER_KEY="${TLS_DIR}/pg-server.key"
PG_CLIENT_CERT="${TLS_DIR}/pg-client.crt"
PG_CLIENT_KEY="${TLS_DIR}/pg-client.key"

# --------------------------------------------------------------------------
# Client<->daemon mTLS material (leg 2: AI NHI -> daemon :9077).
#   daemon-server.crt / .key        daemon TLS leaf (SAN IP:127.0.0.1,DNS:localhost)
#   client-good.crt / .key          an ALLOWED API client identity
#   allowlist.txt                   sha256(DER(client-good)) fingerprint pin
# --------------------------------------------------------------------------
DAEMON_SERVER_CERT="${TLS_DIR}/daemon-server.crt"
DAEMON_SERVER_KEY="${TLS_DIR}/daemon-server.key"
CLIENT_GOOD_CERT="${TLS_DIR}/client-good.crt"
CLIENT_GOOD_KEY="${TLS_DIR}/client-good.key"
MTLS_ALLOWLIST="${TLS_DIR}/allowlist.txt"

# --------------------------------------------------------------------------
# The certified ai-memory daemon (client<->daemon mTLS API).
# --------------------------------------------------------------------------
DAEMON_HOST="${EF_REPRO_DAEMON_HOST:-127.0.0.1}"
DAEMON_PORT="${EF_REPRO_DAEMON_PORT:-9077}"
# The daemon's own signing identity (stamped into signed_events; resolved via
# AI_MEMORY_AGENT_ID — resolve_agent_id(None,None) at the serve boot path).
DAEMON_AGENT_ID="${EF_REPRO_DAEMON_AGENT_ID:-ai:cert-fed-proxy}"
FED_TRUST_DOMAIN="${EF_REPRO_FED_TRUST_DOMAIN:-${CAMPAIGN}.fleet}"

# The ai-memory binary. Prefer an operator-supplied prebuilt binary; else
# repro.sh builds one with the REQUIRED feature set (sal,sal-postgres +
# sqlcipher for the certified at-rest control #15). Never a hardcoded path.
AI_MEMORY_BIN="${AI_MEMORY_BIN:-}"
# The feature set the certified posture requires: sal-postgres (the pg tier),
# sqlcipher (posture control #15 AI_MEMORY_ENCRYPT_AT_REST). See the repro doc
# §"at-rest" for the honest pg-tier caveat (#3061).
CARGO_FEATURES="${EF_REPRO_CARGO_FEATURES:-sal,sal-postgres,sqlcipher}"

# The local embedder used by the audit: all-MiniLM-L6-v2 (384-d) under
# loopback-only egress. schema-init provisions the matching pg column dim.
EMBED_DIM="${EF_REPRO_EMBED_DIM:-384}"

# Deterministic seed corpus size (portable synthetic stand-in for the audit's
# 7,855-row Atlas corpus). Small + reproducible; the SEED is fixed so every
# run stores byte-identical memories.
SEED_ROWS="${EF_REPRO_SEED_ROWS:-64}"
SEED_NAMESPACE="${EF_REPRO_SEED_NAMESPACE:-ef-repro/audit}"

# EC curve + cert lifetime for gen-certs.sh.
EC_CURVE="${EF_REPRO_EC_CURVE:-prime256v1}"
CERT_DAYS="${EF_REPRO_CERT_DAYS:-825}"

# --------------------------------------------------------------------------
# Container runtime (docker or a drop-in like podman).
# --------------------------------------------------------------------------
CONTAINER_RUNTIME="${EF_REPRO_CONTAINER_RUNTIME:-docker}"

# --------------------------------------------------------------------------
# The certified store DSN (postgres over verify-full TLS + client cert mTLS).
# Password read from the 0600 secret file at call time — never echoed, never
# placed on a command line. search_path pins public first (ag_catalog second)
# per the #3055 schema-placement note.
# --------------------------------------------------------------------------
pg_password() { cat "$PG_PASSWORD_FILE"; }

# URL-encode the search_path comma so it survives the DSN query string.
store_dsn() {
  local host="${1:-$PG_HOST}" port="${2:-$PG_PORT}"
  local sp
  sp="$(printf '%s' "$PG_SEARCH_PATH" | sed 's/,/%2C/g')"
  printf 'postgres://%s:%s@%s:%s/%s?sslmode=%s&sslrootcert=%s&sslcert=%s&sslkey=%s&options=-csearch_path%%3D%s' \
    "$PG_USER" "$(pg_password)" "$host" "$port" "$PG_DB" \
    "$PG_SSL_MODE" "$CA_CERT" "$PG_CLIENT_CERT" "$PG_CLIENT_KEY" "$sp"
}

# --------------------------------------------------------------------------
# Resolve the ai-memory binary path (prebuilt override, else the release
# build repro.sh produces). Never invents a path — dies loud if absent.
# --------------------------------------------------------------------------
resolve_ai_memory_bin() {
  if [ -n "$AI_MEMORY_BIN" ] && [ -x "$AI_MEMORY_BIN" ]; then
    printf '%s' "$AI_MEMORY_BIN"; return 0
  fi
  local built="${REPO_ROOT}/target/release/ai-memory"
  if [ -x "$built" ]; then printf '%s' "$built"; return 0; fi
  if command -v ai-memory >/dev/null 2>&1; then command -v ai-memory; return 0; fi
  return 1
}

# --------------------------------------------------------------------------
# Host-loopback mTLS curl against the certified daemon API. Models the AI NHI
# operating the substrate exactly as the audit did (client cert + CA + the
# X-Agent-Id principal). Loopback (127.0.0.1) is exempt from the macOS
# local-network gate. Prints the response body (-fsS; empty on failure).
#
#   api_curl <method> <path> [data] [extra_curl_args...]
# --------------------------------------------------------------------------
api_curl() {
  local method="$1" path="$2" data="${3:-}"; shift 2 || true
  [ "$#" -ge 1 ] && shift || true   # drop consumed data slot when present
  local args=(--silent --show-error --fail
    --max-time "${EF_REPRO_CURL_MAX_TIME:-20}"
    --cacert "$CA_CERT" --cert "$CLIENT_GOOD_CERT" --key "$CLIENT_GOOD_KEY"
    -H "X-Agent-Id: ${DAEMON_AGENT_ID}"
    -X "$method")
  if [ -n "$data" ]; then
    args+=(-H 'Content-Type: application/json' --data "$data")
  fi
  curl "${args[@]}" "$@" "https://${DAEMON_HOST}:${DAEMON_PORT}${path}" 2>/dev/null || printf ''
}
