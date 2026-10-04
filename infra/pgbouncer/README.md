# ai-memory — PgBouncer per-module pooler (deploy templates)

v0.8.0 Pillar-4 **4.B** (#1736). Copy-deployable templates that front a
postgres+AGE **module backbone** with a **session-mode** PgBouncer pooler.
This materializes the config-only guidance in
[`docs/enterprise-deployment.md`](../../docs/enterprise-deployment.md) §5.6 —
read §5.6 for the full rationale; this directory is the runnable artifact.

PgBouncer is a **config-only external daemon** — there is no ai-memory
application code in this path. In `session` mode every client connection holds
one backend connection, so it does **not** fan connections in (size per
§5.6.5 of the guide) and does **not** add AGE write concurrency (that is
bounded by the postgres+AGE backbone — see 4.D).

> **Pool mode (#4667).** `session` is the only supported mode. `transaction`
> and `statement` are not supported today: the Postgres adapter keeps state on
> the server session, and the executed probe
> [`scripts/probe-pgbouncer-pool-mode.py`](../../scripts/probe-pgbouncer-pool-mode.py)
> exits 1 against both (a second client was granted the migration advisory lock
> and saw the first client's `search_path` and `statement_timeout`) and 0 against
> `session`. Making the adapter safe under transaction pooling is tracked in
> [#4679](https://github.com/alphaonedev/ai-memory-mcp/issues/4679); the guide
> returns to transaction mode only when that probe is green on a
> transaction-mode pooler.

## Files

| File | Purpose |
|---|---|
| `pgbouncer.ini` | Pooler config. **`pool_mode = session` is required** (pinned to the guide by `scripts/check-pgbouncer-pool-mode-claims.py`); `max_prepared_statements = 256` (PgBouncer ≥ 1.21). `default_pool_size = 16` covers one daemon at `DEFAULT_MAX_CONNECTIONS = 16`; for N daemons use the sizing rule in guide §5.6.5. |
| `userlist.txt` | Auth template (SCRAM-SHA-256: the role's `pg_authid` verifier plus the separate `pgbouncer_admin` / `pgbouncer_stats` roles). Render from your secret store at deploy (mode 0600); never commit a real credential. |
| `role-defaults.sql` | `ALTER ROLE ai_memory SET search_path = public, ag_catalog; SET statement_timeout = '30s'; SET lock_timeout = '5s';` — role defaults matching the session GUCs ai-memory sets in `after_connect`; the narrowing step in guide §5.6.7 for deployments that ran transaction mode. Values quote `DEFAULT_STATEMENT_TIMEOUT_SECS=30` / `DEFAULT_LOCK_TIMEOUT_SECS=5` and the path `normalize_app_search_path` computes. |
| `docker-compose.yml` | postgres+AGE + pgbouncer, wired (clients → `pgbouncer:6432`, published on `127.0.0.1` only). TLS on both hops; the password and all keys come from `smoke-test.py`. |
| `docker-compose.host.yml` | Override for hosts where Docker cannot create bridge networks (`--network host`). |
| `smoke-test.py` | Infra test: proves an AGE cypher transaction + the role-default timeouts work through the pooler, that the daemon's pool is in session mode (`SHOW POOLS`, and no `SHOW DATABASES` / `SHOW USERS` override, as the stats role), that both hops are TLS and that the application role cannot use the admin console. |

## Wire ai-memory at the pooler

Point the daemon's store URL at the pooler's port (`6432`), not postgres (`5432`):

```bash
ai-memory serve --store-url postgres://ai_memory@pgbouncer:6432/ai_memory
```

## Why `pool_mode = session`

The adapter holds three kinds of state on the server session: the migration
advisory lock (`pg_try_advisory_lock`), the connect-time `search_path`, and the
connect-time `statement_timeout` / `lock_timeout`
(`src/store/postgres.rs`). Where a pooler lets two clients share a backend
(`transaction`, `statement`), the probe observes all three crossing between
clients. `statement` mode also refuses a transaction block
(`FATAL: transaction blocks not allowed in statement pooling mode`), which the
AGE cypher path (`LOAD 'age'` + `SET LOCAL search_path` + `cypher()` in one
transaction) needs. Full results, the daemon run through the pooler and the
sizing rule: `docs/enterprise-deployment.md` §5.6.

## TLS and authentication

The adapter refuses a store URL that does not pin `sslmode=verify-full`
(#3705), so the pooler serves TLS to its clients and verifies Postgres in turn:
the shipped `pgbouncer.ini` sets `client_tls_sslmode = verify-full` (client
certificates are required) and `server_tls_sslmode = verify-full`, and
`auth_type = scram-sha-256`. Give the daemon
`sslmode=verify-full&sslrootcert=...&sslcert=...&sslkey=...` (guide §5.6.3).
`admin_users` and `stats_users` are separate roles, never the application role.

## Validate

```bash
cd infra/pgbouncer
./smoke-test.py                  # add --network host where Docker cannot create bridges
```

The smoke test generates a throwaway CA, certificates, the SCRAM userlist and a
random password under `./.smoke/` (git-ignored, removed on exit), brings the
stack up, runs an AGE cypher MERGE+MATCH **through the pooler on 6432** in one
transaction, confirms the role-default `statement_timeout`, `lock_timeout` and
`search_path` are visible through the pooler, asserts, as the stats role,
that the daemon's pool runs in session mode in `SHOW POOLS` and that no
`SHOW DATABASES` / `SHOW USERS` row overrides it (#4742; `SHOW CONFIG` is the
global value only), checks that a
plaintext client is refused and the pooler-to-Postgres hop is TLS, and tears
down. Exit 0 = validated. No password appears on any command line.

> **Validation note.** Requires Docker + Docker Compose; the smoke test is not
> part of the 8-workflow CI gate (it needs a container runtime, like the
> `infra/lan-parity-test` harness); it needs `psql` and `openssl` on the host too. Run it on a host/CI runner with Docker
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
