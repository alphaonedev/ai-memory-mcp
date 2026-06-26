# ai-memory — PgBouncer per-module pooler (deploy templates)

v0.8.0 Pillar-4 **4.B** (#1736). Copy-deployable templates that front a
postgres+AGE **module backbone** with a transaction-mode PgBouncer pooler.
This materializes the config-only guidance in
[`docs/enterprise-deployment.md`](../../docs/enterprise-deployment.md) §5.6 —
read §5.6 for the full rationale; this directory is the runnable artifact.

PgBouncer is a **config-only external daemon** — there is no ai-memory
application code in this path. It removes the backend connection-count ceiling
for transient/bursty *session* fan-in; it does **not** add AGE write
concurrency (that is bounded by the postgres+AGE backbone — see 4.D).

## Files

| File | Purpose |
|---|---|
| `pgbouncer.ini` | Pooler config. **`pool_mode = transaction` is required**; `max_prepared_statements = 256` (PgBouncer ≥ 1.21) preserves sqlx's prepared statements (Fix #4). Sizing reconciled to `AI_MEMORY_PG_POOL_MAX` (`DEFAULT_MAX_CONNECTIONS = 16`). |
| `userlist.txt` | Auth template (md5). Render from your secret store at deploy (mode 0400); never commit a real credential. |
| `role-defaults.sql` | `ALTER ROLE ai_memory SET statement_timeout = '30s'; SET lock_timeout = '5s';` — the session GUCs ai-memory sets in `after_connect` do **not** survive PgBouncer's inter-transaction `DISCARD ALL`, so they must be role defaults. Values quote `DEFAULT_STATEMENT_TIMEOUT_SECS=30` / `DEFAULT_LOCK_TIMEOUT_SECS=5`. |
| `docker-compose.yml` | postgres+AGE + pgbouncer, wired (clients → `pgbouncer:6432`). |
| `smoke-test.sh` | Infra test: proves an AGE cypher transaction + the role-default timeouts survive transaction-mode pooling. |

## Wire ai-memory at the pooler

Point the daemon's store URL at the pooler's port (`6432`), not postgres (`5432`):

```bash
ai-memory serve --store-url postgres://ai_memory@pgbouncer:6432/ai_memory
```

## Why `pool_mode = transaction` is mandatory

`session` mode forfeits the fan-in benefit; **`statement` mode is forbidden.**
The AGE cypher path issues `LOAD 'age'` + `SET LOCAL search_path` + the
`cypher()` call as multiple statements that **must run on the same backend
within one transaction**. statement-mode pooling can route each statement to a
different backend — the `cypher()` call then lands on a backend where
`search_path`/`LOAD` never ran, breaking graph paths and risking
partially-applied multi-statement graph writes. transaction mode pins the whole
transaction to one backend, which is exactly what AGE needs.

## Validate

```bash
cd infra/pgbouncer
POSTGRES_PASSWORD=secret ./smoke-test.sh
```

The smoke test brings the stack up, runs an AGE cypher MERGE+MATCH **through
the pooler on 6432** in one transaction (asserting transaction-mode pinning
holds), confirms the role-default `statement_timeout` is visible through the
pooler after `DISCARD ALL`, and tears down. Exit 0 = validated.

> **Validation note.** Requires Docker + Docker Compose; the smoke test is not
> part of the 8-workflow CI gate (it needs a container runtime, like the
> `infra/lan-parity-test` harness). Run it on a host/CI runner with Docker
> before adopting the templates. The smoke stack uses the upstream
> `apache/age` image (validating the pooler needs only the AGE path); a
> production module backbone also needs **pgvector** for ai-memory's
> `sal-postgres` adapter — build that from
> `infra/lan-parity-test/Dockerfile.pg-age-vector` and swap `postgres.image`.

## Scale-out

A single module = one postgres+AGE backbone + this pooler. The per-module
agent ceiling is bounded by AGE write throughput and the SQLite hot-tier
memory footprint per agent, not by an unmeasured concurrent-agent number
(the module-model default is a **conservative** 1000 agents/module pending the
v0.8.0 4.D envelope measurement). Scale to thousands by composing **independent
modules**, each its own backbone + pooler — not by raising one daemon's caps.
