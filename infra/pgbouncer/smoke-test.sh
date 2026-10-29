#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────
# ai-memory — PgBouncer pooler infra smoke test (v0.8.0 Pillar-4 4.B, #1736).
#
# Brings up postgres+AGE behind PgBouncer (docker-compose.yml) and proves the
# two properties the pooler MUST provide for ai-memory's postgres+AGE path:
#
#   1. A multi-statement AGE cypher transaction (LOAD 'age' + SET search_path
#      + create_graph + cypher MERGE + cypher MATCH) routed THROUGH the pooler
#      on 6432 succeeds — i.e. transaction-mode pinning keeps every statement
#      on the same backend (statement-mode would shatter this).
#   2. The role-default statement_timeout (role-defaults.sql) is visible
#      through the pooler even after DISCARD ALL between transactions.
#
# Requires docker + docker compose. Run from infra/pgbouncer/:
#   ./smoke-test.sh                       (random password generated)
#   POSTGRES_PASSWORD=<value> ./smoke-test.sh
# Exit codes:
#   0   PASS, the pooler config is validated
#   1   a property failed (the FAIL line names it: AGE, timeout, pool_mode,
#       auth_type), the stack bring-up failed (including the bind failure when
#       another run holds 127.0.0.1:6432) or the teardown failed
#   64  run as root
#   65  bad AI_MEMORY_SMOKE_RUN (outside [a-z0-9_-] or over 64 characters)
#   73  the role has no SCRAM-SHA-256 verifier (refused, never written to the userlist)
#   74  the pooled URL carries a password (refused)
# Any other non-zero status is the failing command's own, under set -e.
# ─────────────────────────────────────────────────────────────────────────
set -euo pipefail

cd "$(dirname "$0")"

# PgBouncer refuses to run as root (#4734). The pooler runs as the invoking
# uid so the owner-only userlist stays readable, so fail fast with a clear
# message instead of a container that exits at start.
if [ "$(id -u)" -eq 0 ]; then
  echo "FATAL: run this script as a non-root user (PgBouncer refuses to run as root)" >&2
  exit 64
fi

# Refuse a password-bearing pooled URL before any password is generated or
# exported and before any container exists (exit 74).
POOLED_URL="postgres://ai_memory@pgbouncer:6432/ai_memory"
# The pooled URL reaches docker exec argv (visible to every local user), so it
# must never carry a password in its userinfo; the password travels as the
# inherited PGPASSWORD variable only.
case "${POOLED_URL#*://}" in
  *:*@*) echo "FATAL: POOLED_URL must not carry a password in its userinfo" >&2; exit 74 ;;
esac

# No fixed fallback (#4734): generate a random per-run password when unset.
PW="${POSTGRES_PASSWORD:-$(python3 -c 'import secrets; print(secrets.token_hex(16))')}"
export POSTGRES_PASSWORD="$PW"
# The pooler runs as the invoking user so the 0600 userlist stays readable.
PGBOUNCER_UID="$(id -u)"
PGBOUNCER_GID="$(id -g)"
export PGBOUNCER_UID PGBOUNCER_GID
# docker exec takes the password by variable NAME (inherited), never by argv.
export PGPASSWORD="$PW"
# Per-run suffix (#4734): the compose project, container names and the userlist
# file are derived from it so two concurrent runs never recreate each other's
# containers and one trap only removes its own project. Override with
# AI_MEMORY_SMOKE_RUN=<[a-z0-9_-]+> (tests); the stable prefix is ai-memory-pgbouncer-.
RUN="${AI_MEMORY_SMOKE_RUN:-$(date +%s)-$$}"
case "$RUN" in
  ''|*[!a-z0-9_-]*) echo "FATAL: AI_MEMORY_SMOKE_RUN must match [a-z0-9_-]+" >&2; exit 65 ;;
esac
if [ "${#RUN}" -gt 64 ]; then
  echo "FATAL: AI_MEMORY_SMOKE_RUN must be at most 64 characters" >&2
  exit 65
fi
export AI_MEMORY_SMOKE_RUN="$RUN"
PROJECT="ai-memory-pgbouncer-smoke-$RUN"
PG_CONTAINER="ai-memory-pgbouncer-$RUN-postgres"
USERLIST=".userlist.generated.$RUN.txt"

# Compose is pinned (#4734 r13): every `docker compose` call passes -f of this one file and
# --project-directory of its directory, so a compose.override file, a compose.yaml, or a
# COMPOSE_FILE set in a .env or inherited is never read. With -f given, compose does not discover
# files and ignores COMPOSE_FILE (tested with Docker Compose v5.6.0). With --project-directory,
# compose still reads a .env in that directory for interpolation (same version); that has no effect
# here, because this script exports every name the compose file interpolates (the environment
# outranks .env) and the guard refuses a tracked .env in the infra directory.
COMPOSE_DIR="$PWD"
COMPOSE_FILE_PINNED="$COMPOSE_DIR/docker-compose.yml"

cleanup() {
  rc=$?
  # POSTGRES_PASSWORD is exported above, so interpolation cannot fail here.
  docker compose -f "$COMPOSE_FILE_PINNED" --project-directory "$COMPOSE_DIR" -p "$PROJECT" down -v >/dev/null || { echo "WARN: compose down failed" >&2; rc=1; }
  if [ -n "$(docker ps -aq --filter "label=com.docker.compose.project=$PROJECT")" ]; then
    echo "FATAL: compose project $PROJECT still running after teardown" >&2
    rc=1
  fi
  rm -f "$USERLIST"
  exit "$rc"
}
trap cleanup EXIT

echo "[1/4] bringing up postgres+AGE, then pgbouncer with a SCRAM userlist ..."
POSTGRES_PASSWORD="$PW" docker compose -f "$COMPOSE_FILE_PINNED" --project-directory "$COMPOSE_DIR" -p "$PROJECT" up -d --wait postgres
# SCRAM end to end (#4732): bring up postgres first (default scram-sha-256
# auth), then render the pooler userlist from the role's own stored SCRAM
# verifier. pgbouncer 1.23 uses SCRAM when the userlist entry is a
# SCRAM secret and passes it through to the backend. The verifier
# (not the password) travels over docker exec stdout straight into a file
# created under umask 077 (#4735); the password never appears in argv.
VERIFIER_ROW="$(docker exec "$PG_CONTAINER" \
  psql -U ai_memory -d ai_memory -tA -c "SELECT format('\"%s\" \"%s\"', rolname, rolpassword) FROM pg_authid WHERE rolname = 'ai_memory'")"
case "$VERIFIER_ROW" in
  '"ai_memory" "SCRAM-SHA-256$'*) ;;
  *) echo "FATAL: role ai_memory has no SCRAM-SHA-256 verifier" >&2; exit 73 ;;
esac
# Remove any leftover file first: umask only applies to a NEW file, so a stale
# 0644 userlist would otherwise keep its mode (N4).
rm -f "$USERLIST"
(umask 077; printf '%s\n' "$VERIFIER_ROW" > "$USERLIST")
POSTGRES_PASSWORD="$PW" docker compose -f "$COMPOSE_FILE_PINNED" --project-directory "$COMPOSE_DIR" -p "$PROJECT" up -d --wait

# psql THROUGH the pooler is run from inside the postgres container (it has
# psql and shares the compose network, so `pgbouncer` resolves).
psql_pooled() {
  docker exec -i -e PGPASSWORD "$PG_CONTAINER" \
    psql "$POOLED_URL" -v ON_ERROR_STOP=1 -tA "$@"
}

echo "[2/4] AGE cypher transaction through the pooler (transaction-mode pinning) ..."
# All statements in ONE -c transaction => one BEGIN/COMMIT => one pooled
# backend. If pool_mode were 'statement' the cypher() call could land on a
# backend where LOAD/SET never ran and fail.
psql_pooled <<'SQL' || { echo "FAIL: AGE cypher transaction through the pooler failed" >&2; exit 1; }
BEGIN;
LOAD 'age';
SET LOCAL search_path = ag_catalog, "$user", public;
SELECT create_graph('pgbouncer_smoke');
SELECT * FROM cypher('pgbouncer_smoke', $$ MERGE (a:N {id:'a'}) MERGE (b:N {id:'b'}) MERGE (a)-[:E]->(b) RETURN a $$) AS (a agtype);
COMMIT;
SQL

path_count="$(psql_pooled <<'SQL'
BEGIN;
LOAD 'age';
SET LOCAL search_path = ag_catalog, "$user", public;
SELECT count(*) FROM cypher('pgbouncer_smoke', $$ MATCH (a:N {id:'a'})-[:E]->(b:N {id:'b'}) RETURN a $$) AS (a agtype);
COMMIT;
SQL
)" || { echo "FAIL: AGE edge lookup through the pooler failed" >&2; exit 1; }
path_count="$(printf '%s' "$path_count" | tr -dc '0-9')"
if [ "${path_count:-0}" -lt 1 ]; then
  echo "FAIL: AGE edge not found through the pooler (count=$path_count) — transaction-mode pinning broken?" >&2
  exit 1
fi
echo "      OK: AGE edge round-tripped through pgbouncer:6432 (count=$path_count)"

echo "[3/4] role-default statement_timeout visible through the pooler ..."
st="$(psql_pooled -c 'SHOW statement_timeout;')" || { echo "FAIL: SHOW statement_timeout through the pooler failed" >&2; exit 1; }
echo "      statement_timeout = ${st}"
if [ "$st" != "30s" ]; then
  echo "FAIL: role-default statement_timeout did not survive the pooler (got '${st}', want '30s'). \
Did you run role-defaults.sql / is it mounted into initdb.d?" >&2
  exit 1
fi
echo "      OK: role-default timeouts survive DISCARD ALL"

echo "[4/4] pooler effective settings (SHOW CONFIG on the admin console) ..."
cfg="$(docker exec -e PGPASSWORD "$PG_CONTAINER" \
  psql "postgres://ai_memory@pgbouncer:6432/pgbouncer" -tA -c 'SHOW CONFIG;')" \
  || { echo "FAIL: SHOW CONFIG on the pooler admin console failed" >&2; exit 1; }
pool_mode="$(printf '%s\n' "$cfg" | awk -F'|' '$1 == "pool_mode" { print $2 }')"
auth_type="$(printf '%s\n' "$cfg" | awk -F'|' '$1 == "auth_type" { print $2 }')"
echo "      pool_mode = ${pool_mode:-<unreported>}"
echo "      auth_type = ${auth_type:-<unreported>}"
if [ "$pool_mode" != "transaction" ]; then
  echo "FAIL: pooler pool_mode is '${pool_mode}', want 'transaction'" >&2
  exit 1
fi
if [ "$auth_type" != "scram-sha-256" ]; then
  echo "FAIL: pooler auth_type is '${auth_type}', want 'scram-sha-256'" >&2
  exit 1
fi

echo "PASS: PgBouncer pooler validated (AGE cypher + role-default timeouts through 6432)."
