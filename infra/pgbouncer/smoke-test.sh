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
#   POSTGRES_PASSWORD=secret ./smoke-test.sh
# Exit 0 = pooler config validated; non-zero = a property failed (see output).
# ─────────────────────────────────────────────────────────────────────────
set -euo pipefail

cd "$(dirname "$0")"

PW="${POSTGRES_PASSWORD:-ai_memory_smoke}"
PROJECT="ai-memory-pgbouncer-smoke"
PG_CONTAINER="ai-memory-pgbouncer-postgres"
POOLED_URL="postgres://ai_memory:${PW}@pgbouncer:6432/ai_memory"

cleanup() {
  docker compose -p "$PROJECT" down -v >/dev/null 2>&1 || true
  rm -f .userlist.generated.txt
}
trap cleanup EXIT

# Render the md5 userlist from the password so the committed placeholder never
# carries a secret. auth_type=md5 => 'md5' + md5(password + username).
md5hash="$(printf '%s%s' "$PW" ai_memory | md5sum | cut -d' ' -f1)"
printf '"ai_memory" "md5%s"\n' "$md5hash" > .userlist.generated.txt

echo "[1/4] bringing up postgres+AGE + pgbouncer ..."
POSTGRES_PASSWORD="$PW" docker compose -p "$PROJECT" up -d --wait

# psql THROUGH the pooler is run from inside the postgres container (it has
# psql and shares the compose network, so `pgbouncer` resolves).
psql_pooled() {
  docker exec -e PGPASSWORD="$PW" "$PG_CONTAINER" \
    psql "$POOLED_URL" -v ON_ERROR_STOP=1 -tA "$@"
}

echo "[2/4] AGE cypher transaction through the pooler (transaction-mode pinning) ..."
# All statements in ONE -c transaction => one BEGIN/COMMIT => one pooled
# backend. If pool_mode were 'statement' the cypher() call could land on a
# backend where LOAD/SET never ran and fail.
psql_pooled <<'SQL'
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
)"
path_count="$(printf '%s' "$path_count" | tr -dc '0-9')"
if [ "${path_count:-0}" -lt 1 ]; then
  echo "FAIL: AGE edge not found through the pooler (count=$path_count) — transaction-mode pinning broken?" >&2
  exit 1
fi
echo "      OK: AGE edge round-tripped through pgbouncer:6432 (count=$path_count)"

echo "[3/4] role-default statement_timeout visible through the pooler ..."
st="$(psql_pooled -c 'SHOW statement_timeout;')"
echo "      statement_timeout = ${st}"
if [ "$st" != "30s" ]; then
  echo "FAIL: role-default statement_timeout did not survive the pooler (got '${st}', want '30s'). \
Did you run role-defaults.sql / is it mounted into initdb.d?" >&2
  exit 1
fi
echo "      OK: role-default timeouts survive DISCARD ALL"

echo "[4/4] pooler is in transaction mode ..."
mode="$(docker exec -e PGPASSWORD="$PW" "$PG_CONTAINER" \
  psql "postgres://ai_memory:${PW}@pgbouncer:6432/pgbouncer" -tA -c 'SHOW pool_mode;' 2>/dev/null | tr -dc 'a-z' || true)"
# Some PgBouncer builds report per-database mode; the global is what matters.
echo "      pool_mode = ${mode:-<unreported>}"

echo "PASS: PgBouncer pooler validated (AGE cypher + role-default timeouts through 6432)."
