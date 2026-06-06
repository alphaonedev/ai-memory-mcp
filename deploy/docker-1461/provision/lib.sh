# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
#
# docker-1461 — shared constants + Docker-transport helpers.
#
# This is the single source of truth for the campaign. Every constant is
# env-overridable (so forks/peers can re-point names, ports, images, model
# ids without editing code) and agnostic (no hostname/region/vendor literal
# is baked into a variable name). The provisioning, validation, and test
# harnesses all `source` this file and drive entirely off the values below.
#
# Transport model: unlike the SSH/systemd-coupled deploy/hive-1461 toolkit
# (which reaches DigitalOcean droplets over `ssh`), this campaign runs
# wholly on the local node via Docker. The peer daemons serve HTTPS+mTLS
# inside a private bridge; the harness reaches them two ways:
#   - node_exec  : `docker exec <container> …` for in-container integrity
#                  / process / schema probes (the analog of `ssh_node`).
#   - mtls_curl  : host-loopback `curl` to each peer's published port over
#                  TLS + a client cert (the analog of the hive `mtls_curl`,
#                  modelling an external mTLS API client of the mesh).
#
# bash-3.2 safe (macOS /bin/bash): no associative arrays, no `mapfile`.
# Indexed arrays + process substitution are used (both supported since 3.2);
# only the 4.x-only `mapfile`/assoc-array/`${x,,}` features are avoided.
# Indexable derivations (peer name/port/schema/fed-id) are pure functions of a
# 1-based peer index.

# This file is sourced, not executed — every constant below is the SSOT
# consumed by the sibling provision/validate/test scripts (and rendered into
# campaign.env), so shellcheck cannot see the cross-file usage.
# shellcheck shell=bash
# shellcheck disable=SC2034

set -euo pipefail

# --------------------------------------------------------------------------
# Repo + run-dir anchoring
# --------------------------------------------------------------------------
# LIB_DIR = deploy/docker-1461/provision ; REPO_ROOT = three levels up.
LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CAMPAIGN_ROOT="$(cd "$LIB_DIR/.." && pwd)"
REPO_ROOT="$(cd "$CAMPAIGN_ROOT/../.." && pwd)"

# --------------------------------------------------------------------------
# Campaign identity
# --------------------------------------------------------------------------
CAMPAIGN="${DOCKER_1461_CAMPAIGN:-docker-1461}"
COMPOSE_PROJECT="${DOCKER_1461_PROJECT:-ai-memory-${CAMPAIGN}}"

# --------------------------------------------------------------------------
# Topology (operator-fixed: 2 IronClaw peers + 1 PG/AGE)
# --------------------------------------------------------------------------
PEER_COUNT="${DOCKER_1461_PEER_COUNT:-2}"
PEER_NAME_PREFIX="${DOCKER_1461_PEER_PREFIX:-${CAMPAIGN}-peer}"   # -> docker-1461-peer-1
CONTAINER_HTTPS_PORT="${DOCKER_1461_HTTPS_PORT:-19077}"          # in-container listen
PEER_PUBLISHED_PORT_BASE="${DOCKER_1461_PORT_BASE:-19280}"        # host loopback base
QUORUM_WRITES="${DOCKER_1461_QUORUM_WRITES:-2}"                   # W-of-N synchronous

# --------------------------------------------------------------------------
# PostgreSQL 18 + Apache AGE + pgvector
# --------------------------------------------------------------------------
PG_CONTAINER="${DOCKER_1461_PG_CONTAINER:-${CAMPAIGN}-pg-age}"
PG_HOSTNAME="${DOCKER_1461_PG_HOSTNAME:-pg-age}"                  # intra-bridge DNS
PG_INTERNAL_PORT="${DOCKER_1461_PG_INTERNAL_PORT:-5432}"
PG_PUBLISHED_PORT="${DOCKER_1461_PG_PUBLISHED_PORT:-15433}"       # host loopback
PG_USER="${DOCKER_1461_PG_USER:-ai_memory}"
PG_DB="${DOCKER_1461_PG_DB:-ai_memory}"
PEER_SCHEMA_PREFIX="${DOCKER_1461_SCHEMA_PREFIX:-ic_peer_}"       # ic_peer_1, ic_peer_2
AGE_GRAPH_NAME="${DOCKER_1461_AGE_GRAPH:-memory_graph}"
# daemon -> PostgreSQL transport posture. verify-full = encrypt AND validate the
# PG server cert against the campaign CA AND match its SAN to the dialed host
# (`pg-age`). The third encrypted leg of the mesh (the other two are the API
# mTLS path + the federation/quorum mTLS path).
PG_SSL_MODE="${DOCKER_1461_PG_SSL_MODE:-verify-full}"

# --------------------------------------------------------------------------
# Pinned artifacts (reproducibility anchors — assert these, never drift)
# --------------------------------------------------------------------------
EXPECTED_VERSION="${DOCKER_1461_EXPECTED_VERSION:-0.7.0}"
EXPECTED_SCHEMA="${DOCKER_1461_EXPECTED_SCHEMA:-55}"
EMBED_DIM="${DOCKER_1461_EMBED_DIM:-768}"
EMBED_MODEL="${DOCKER_1461_EMBED_MODEL:-nomic-embed-text}"        # Ollama tag
EMBED_MODEL_CONFIG_ID="${DOCKER_1461_EMBED_CONFIG_ID:-nomic_embed_v15}"
# PostgreSQL + Apache AGE stack pins. The apache/age PG18 base ships AGE
# compiled into the PG18 tree (age.so + age--<ver>.sql + age.control) but
# the server itself at the image's minor (18.1 as of the release_PG18_1.7.0
# digest). We bump the server to the EXACT target minor via a pinned pgdg
# apt --only-upgrade inside Dockerfile.pg-age-vector (ABI-safe within major
# 18 — AGE loads across PG minors). Every literal lives HERE (SSOT), passed
# to the build as --build-arg, asserted by the validate harness; the
# Dockerfile carries no version literal of its own.
AGE_BASE_IMAGE="${DOCKER_1461_AGE_BASE_IMAGE:-apache/age:release_PG18_1.7.0}"
PG_MAJOR="${DOCKER_1461_PG_MAJOR:-18}"                            # server major (apt pkg suffix)
PG_APT_VERSION="${DOCKER_1461_PG_APT_VERSION:-18.4-1.pgdg13+1}"   # pinned exact pgdg .deb
PGVECTOR_APT_VERSION="${DOCKER_1461_PGVECTOR_APT_VERSION:-0.8.2-1.pgdg13+1}"
# Reproducibility assertion anchors (validate harness asserts these exact
# upstream-reported versions — the directive: results must reflect 18.4 + AGE 1.7.0).
EXPECTED_PG_VERSION="${DOCKER_1461_EXPECTED_PG_VERSION:-18.4}"
EXPECTED_AGE_VERSION="${DOCKER_1461_EXPECTED_AGE_VERSION:-1.7.0}"
PG_AGE_VECTOR_IMAGE="${DOCKER_1461_PG_IMAGE:-ai-memory-${CAMPAIGN}-pg-age-vector:latest}"
DAEMON_IMAGE="${DOCKER_1461_DAEMON_IMAGE:-ai-memory-${CAMPAIGN}-daemon:latest}"
CARGO_FEATURES="${DOCKER_1461_CARGO_FEATURES:-sal,sal-postgres}"

# --------------------------------------------------------------------------
# AI NHI brain (LLM) + embedder reach
# --------------------------------------------------------------------------
LLM_BACKEND="${DOCKER_1461_LLM_BACKEND:-openrouter}"
LLM_MODEL="${DOCKER_1461_LLM_MODEL:-google/gemma-4-26b-a4b-it}"
AUTO_TAG_MODEL="${DOCKER_1461_AUTO_TAG_MODEL:-${LLM_MODEL}}"
# Embedder is a host Ollama reachable from containers via host-gateway.
OLLAMA_BASE_URL="${DOCKER_1461_OLLAMA_BASE_URL:-http://host.docker.internal:11434}"
DAEMON_TIER="${DOCKER_1461_TIER:-autonomous}"
DEFAULT_NAMESPACE="${DOCKER_1461_NAMESPACE:-${CAMPAIGN}}"

# --------------------------------------------------------------------------
# Federation identity / zero-touch first-party trust
# --------------------------------------------------------------------------
FEDERATION_PORT="${CONTAINER_HTTPS_PORT}"
FED_TRUST_DOMAIN="${DOCKER_1461_TRUST_DOMAIN:-${CAMPAIGN}.fleet}"
# Issuer id MUST be slash-free (TrustBundle::from_dir is non-recursive — a
# slashed id would nest the published key in a skipped sub-dir). See
# docs/zero-touch-quickstart.md §5.
FED_ISSUER_ID="${DOCKER_1461_ISSUER_ID:-${CAMPAIGN}-ca}"
# Logical "site" segment of the slashed federation identity ($CAMPAIGN/$site/$host).
FED_SITE="${DOCKER_1461_SITE:-local}"
CREDENTIAL_TTL_SECS="${DOCKER_1461_CRED_TTL_SECS:-3600}"

# --------------------------------------------------------------------------
# Private bridge network (distinct subnet from infra/lan-parity .79 and
# infra/plan-c .78 so all three can co-exist on the same Docker host)
# --------------------------------------------------------------------------
MESH_NETWORK="${DOCKER_1461_NETWORK:-${CAMPAIGN}-mesh}"
MESH_SUBNET="${DOCKER_1461_SUBNET:-172.31.80.0/24}"

# --------------------------------------------------------------------------
# In-container (remote) paths — match entrypoint.plan-c.sh contract
# --------------------------------------------------------------------------
REMOTE_BINARY="/usr/local/bin/ai-memory"
REMOTE_TLS_DIR="/etc/ai-memory-a2a/tls"        # AI_MEMORY_TLS_DIR
REMOTE_KEY_DIR="/etc/ai-memory/keys"           # AI_MEMORY_KEY_DIR
REMOTE_TRUST_DIR="/etc/ai-memory/trust"        # AI_MEMORY_FED_TRUST_BUNDLE_DIR
REMOTE_CRED_PATH="/etc/ai-memory/credential"   # AI_MEMORY_FED_CRED_PATH

# --------------------------------------------------------------------------
# Host run dir (gitignored — NEVER /tmp, NEVER committed). Holds generated
# TLS material, zero-touch key/trust/cred material, the secret env file,
# the rendered compose env, and the machine/human reports.
# --------------------------------------------------------------------------
RUN_DIR="${DOCKER_1461_RUN_DIR:-${REPO_ROOT}/.local-runs/${CAMPAIGN}}"
TLS_ROOT="${RUN_DIR}/tls"
ZT_ROOT="${RUN_DIR}/zero-touch"
NODES_ROOT="${RUN_DIR}/nodes"          # per-peer mount trees bound into containers
SECRETS_DIR="${RUN_DIR}/secrets"
REPORTS_DIR="${RUN_DIR}/reports"
COMPOSE_ENV_FILE="${RUN_DIR}/campaign.env"   # generated; --env-file for compose
PG_PASSWORD_FILE="${SECRETS_DIR}/pg_password"
# PG container bind-mount tree (its CA-signed server cert/key) + the rendered
# hostssl-only client-auth map. Both keep the daemon->PG leg encrypted.
PG_NODE_DIR="${NODES_ROOT}/${PG_CONTAINER}"
PG_HBA_FILE="${RUN_DIR}/pg_hba.conf"

# --------------------------------------------------------------------------
# HTTP API surface (single source — harnesses never inline a path literal)
# --------------------------------------------------------------------------
API_BASE="/api/v1"
API_HEALTH="${API_BASE}/health"
API_CAPABILITIES="${API_BASE}/capabilities"
API_MEMORIES="${API_BASE}/memories"
API_SEARCH="${API_BASE}/search"
API_STATS="${API_BASE}/stats"
API_SYNC_SINCE="${API_BASE}/sync/since"
API_EXPAND_QUERY="${API_BASE}/expand_query"

# --------------------------------------------------------------------------
# Logging
# --------------------------------------------------------------------------
log()  { printf '[%s] %s\n' "$(date -u +%H:%M:%SZ)" "$*" >&2; }
warn() { printf '[%s] WARN %s\n' "$(date -u +%H:%M:%SZ)" "$*" >&2; }
die()  { printf '[%s] FATAL %s\n' "$(date -u +%H:%M:%SZ)" "$*" >&2; exit 1; }

# --------------------------------------------------------------------------
# Indexable topology derivations (pure functions of a 1-based peer index)
# --------------------------------------------------------------------------
peer_name()   { printf '%s-%s' "$PEER_NAME_PREFIX" "$1"; }              # docker-1461-peer-1
peer_schema() { printf '%s%s' "$PEER_SCHEMA_PREFIX" "$1"; }            # ic_peer_1
peer_port()   { printf '%s' "$(( PEER_PUBLISHED_PORT_BASE + $1 - 1 ))"; } # 19280, 19281
# Slashed federation identity: $CAMPAIGN/$site/$host (host = container name).
peer_fed_id() { printf '%s/%s/%s' "$CAMPAIGN" "$FED_SITE" "$(peer_name "$1")"; }
# Daemon (non-federation) agent identity: ai:<host>@<campaign>. Distinct from
# the slashed federation wire identity above; MUST NOT be the reserved
# sentinel `daemon` (the wire validator rejects it).
peer_agent_id() { printf 'ai:%s@%s' "$(peer_name "$1")" "$CAMPAIGN"; }

# In-bridge peer URL set for a given peer index's quorum config: every OTHER
# peer, comma-joined, as https://<name>:<port>.
peer_quorum_urls() {
  local self="$1" i urls=""
  for i in $(seq 1 "$PEER_COUNT"); do
    [ "$i" = "$self" ] && continue
    local u
    u="https://$(peer_name "$i"):${CONTAINER_HTTPS_PORT}"
    if [ -z "$urls" ]; then urls="$u"; else urls="${urls},${u}"; fi
  done
  printf '%s' "$urls"
}

# --------------------------------------------------------------------------
# Postgres store URL for a peer schema. Password is read from the gitignored
# secret file at call time and never echoed / never placed on a command line.
# search_path pins the per-peer schema first, then ag_catalog (AGE) + public
# (pgvector) so the SAL adapter resolves both the graph + the vector type.
# --------------------------------------------------------------------------
pg_password() { cat "$PG_PASSWORD_FILE"; }

# The in-container path to the campaign CA the daemon verifies the PG server
# cert against (every peer mounts its tls dir — which carries ca.pem — at
# $REMOTE_TLS_DIR). sqlx (runtime-tokio-rustls) honors sslmode + sslrootcert
# straight off the connection URL, so PG-over-TLS is a pure config choice.
PG_SSL_ROOT_CERT="${REMOTE_TLS_DIR}/ca.pem"

store_url_for_schema() {
  local schema="$1" host="${2:-$PG_HOSTNAME}" port="${3:-$PG_INTERNAL_PORT}"
  printf 'postgres://%s:%s@%s:%s/%s?options=-csearch_path%%3D%s%%2Cag_catalog%%2Cpublic&sslmode=%s&sslrootcert=%s' \
    "$PG_USER" "$(pg_password)" "$host" "$port" "$PG_DB" "$schema" "$PG_SSL_MODE" "$PG_SSL_ROOT_CERT"
}

# --------------------------------------------------------------------------
# Compose driver — single wrapper so every step + the Makefile invoke
# `docker compose` identically (same file + generated env-file). Secrets
# (OPENROUTER_API_KEY / AI_MEMORY_API_KEY) come from the caller's shell
# env and take precedence over the env-file during interpolation.
# --------------------------------------------------------------------------
COMPOSE_FILE="${DOCKER_1461_COMPOSE_FILE:-${CAMPAIGN_ROOT}/docker-compose.yml}"
dc() { docker compose -f "$COMPOSE_FILE" --env-file "$COMPOSE_ENV_FILE" "$@"; }

# The X-API-Key the daemon expects. MUST mirror the compose interpolation
# default (`AI_MEMORY_API_KEY: ${AI_MEMORY_API_KEY:-${OPENROUTER_API_KEY}}`)
# so the host harness presents the same key the container was started with.
effective_api_key() { printf '%s' "${AI_MEMORY_API_KEY:-${OPENROUTER_API_KEY:-}}"; }

# --------------------------------------------------------------------------
# Docker transport helpers
# --------------------------------------------------------------------------
node_exec() { local c="$1"; shift; docker exec "$c" "$@"; }

node_running() {
  [ "$(docker inspect -f '{{.State.Running}}' "$1" 2>/dev/null)" = "true" ]
}

node_healthy() {
  local s
  s="$(docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}' "$1" 2>/dev/null)"
  [ "$s" = "healthy" ]
}

# Block until a container reports healthy (or running, if it has no
# healthcheck) within a bounded number of 2s ticks.
wait_healthy() {
  local c="$1" ticks="${2:-60}" i
  for i in $(seq 1 "$ticks"); do
    if node_healthy "$c"; then return 0; fi
    if ! node_running "$c"; then
      local hc
      hc="$(docker inspect -f '{{if .State.Health}}yes{{else}}no{{end}}' "$c" 2>/dev/null || echo no)"
      [ "$hc" = "no" ] && node_running "$c" && return 0
    fi
    sleep 2
  done
  return 1
}

# --------------------------------------------------------------------------
# Host-loopback mTLS curl — models an external mTLS API client of the mesh.
# Reaches a peer's published port over TLS with the campaign CA + a client
# cert/key. Loopback (127.0.0.1) is exempt from the macOS local-network gate.
#
#   mtls_curl_code  <port> <method> <path> [data] [agent_id] [extra_header...]
#       -> prints HTTP status code only (000 on transport failure)
#   mtls_curl_body  <port> <method> <path> [data] [agent_id] [extra_header...]
#       -> prints response body (-fsS; empty on failure)
#
# Client identity material defaults to the shared API-client cert under
# $TLS_ROOT/client.{pem,key} + the CA at $TLS_ROOT/ca.pem; override via the
# MTLS_CLIENT_CERT / MTLS_CLIENT_KEY / MTLS_CA env vars (the crypto-negative
# tests point these at a rogue/ephemeral cert or omit them entirely).
# --------------------------------------------------------------------------
MTLS_CA="${MTLS_CA:-${TLS_ROOT}/ca.pem}"
MTLS_CLIENT_CERT="${MTLS_CLIENT_CERT:-${TLS_ROOT}/client.pem}"
MTLS_CLIENT_KEY="${MTLS_CLIENT_KEY:-${TLS_ROOT}/client.key}"

_mtls_curl_common() {
  # Emits the shared curl args on stdout, one per line (caller reads into argv).
  local port="$1" method="$2" path="$3" data="$4" aid="$5"; shift 5
  # Per-call timeout override (LLM round-trips can exceed the default budget).
  printf '%s\n' --silent --max-time "${MTLS_MAX_TIME:-15}"
  printf '%s\n' -X "$method"
  # Connect straight to loopback. Every peer's server cert carries an
  # IP:127.0.0.1 SAN (also required by the in-container healthcheck), so
  # one connect host verifies against any peer's cert — no per-peer SAN
  # name coupling, no --resolve.
  [ -f "$MTLS_CA" ]          && printf '%s\n' --cacert "$MTLS_CA"
  [ -f "$MTLS_CLIENT_CERT" ] && printf '%s\n' --cert "$MTLS_CLIENT_CERT"
  [ -f "$MTLS_CLIENT_KEY" ]  && printf '%s\n' --key "$MTLS_CLIENT_KEY"
  printf '%s\n' -H "X-API-Key: $(effective_api_key)"
  [ -n "$aid" ] && printf '%s\n' -H "X-Agent-Id: ${aid}"
  if [ -n "$data" ]; then
    printf '%s\n' -H 'Content-Type: application/json'
    printf '%s\n' --data "$data"
  fi
  local h
  for h in "$@"; do printf '%s\n' -H "$h"; done
}

# Build the https URL against loopback at the given published port. The
# server cert's IP:127.0.0.1 SAN authenticates the endpoint.
_mtls_url() { printf 'https://127.0.0.1:%s%s' "$1" "$2"; }

mtls_curl_code() {
  local port="$1" method="$2" path="$3" data="${4:-}" aid="${5:-}"; shift 5 || true
  local args=() line
  while IFS= read -r line; do args+=("$line"); done < <(_mtls_curl_common "$port" "$method" "$path" "$data" "$aid" "$@")
  curl "${args[@]}" -o /dev/null -w '%{http_code}' "$(_mtls_url "$port" "$path")" 2>/dev/null || printf '000'
}

mtls_curl_body() {
  local port="$1" method="$2" path="$3" data="${4:-}" aid="${5:-}"; shift 5 || true
  local args=() line
  while IFS= read -r line; do args+=("$line"); done < <(_mtls_curl_common "$port" "$method" "$path" "$data" "$aid" "$@")
  curl -fsS "${args[@]}" "$(_mtls_url "$port" "$path")" 2>/dev/null || printf ''
}

# Minimal JSON field extractor (string or scalar) without a jq dependency in
# the hot path. Prefers jq when available for nested/robust extraction.
json_field() {
  local json="$1" key="$2"
  if command -v jq >/dev/null 2>&1; then
    printf '%s' "$json" | jq -r --arg k "$key" '.[$k] // empty' 2>/dev/null
  else
    printf '%s' "$json" | sed -n "s/.*\"${key}\"[[:space:]]*:[[:space:]]*\"\([^\"]*\)\".*/\1/p" | head -1
  fi
}
