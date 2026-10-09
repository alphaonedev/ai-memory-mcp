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
> the server session, and the executed probe recorded on PR #4710 exits 1
> against both (a second client was granted the migration advisory lock and
> saw the first client's `search_path` and `statement_timeout`) and 0 against
> `session`. Making the adapter safe under transaction pooling is tracked in
> [#4679](https://github.com/alphaonedev/ai-memory-mcp/issues/4679); the guide
> returns to transaction mode only when that probe is green on a
> transaction-mode pooler.

## Files

| File | Purpose |
|---|---|
| `pgbouncer.ini` | Pooler config. **`pool_mode = session` is required**; `max_prepared_statements = 256` (PgBouncer ≥ 1.21). Keep PgBouncer's default `server_reset_query = DISCARD ALL`: in `session` mode a server connection passes to the next client only after this reset. `default_pool_size = 16` covers one daemon at `DEFAULT_MAX_CONNECTIONS = 16`; for N daemons use the sizing rule in guide §5.6.5. |
| `userlist.txt` | Auth template (md5; SCRAM for the template is tracked in [#4732](https://github.com/alphaonedev/ai-memory-mcp/issues/4732)). Render from your secret store at deploy (mode 0400); never commit a real credential. |
| `role-defaults.sql` | `ALTER ROLE ai_memory SET statement_timeout = '30s'; SET lock_timeout = '5s';` — role defaults matching the session GUCs ai-memory sets in `after_connect`. In `session` mode the daemon's own `SET` already holds for the life of its connection, so these are belt-and-braces here; they are the narrowing step in guide §5.6.7 for a deployment that ran transaction mode. Values quote `DEFAULT_STATEMENT_TIMEOUT_SECS=30` / `DEFAULT_LOCK_TIMEOUT_SECS=5`. |
| `docker-compose.yml` | postgres+AGE + pgbouncer, wired (clients → `pgbouncer:6432`). |
| `smoke-test.sh` | Infra test: proves an AGE cypher transaction + the role-default timeouts work through the pooler, and prints the pooler's reported `pool_mode`. |

## Wire ai-memory at the pooler

Point the daemon's store URL at the pooler's port (`6432`), not postgres (`5432`):

```bash
ai-memory serve --store-url postgres://ai_memory@pgbouncer:6432/ai_memory
```

## Why `pool_mode = session`

The adapter holds three kinds of state on the server session: the migration
advisory lock (`pg_try_advisory_lock` on `MIGRATION_ADVISORY_LOCK_KEY`), the
connect-time `search_path` (`set_config('search_path', .., false)`), and the
connect-time `statement_timeout` / `lock_timeout` (plain `SET` in the same
`after_connect` hook) — all in `src/store/postgres.rs`. Where a pooler lets two
clients share a backend (`transaction`, `statement`), the probe observes all
three crossing between clients. `statement` mode also refuses a transaction
block (`FATAL: transaction blocks not allowed in statement pooling mode`),
which the AGE cypher path (`LOAD 'age'` + `SET LOCAL search_path` + `cypher()`
in one transaction) needs. Full results, the daemon run through the pooler and
the sizing rule: `docs/enterprise-deployment.md` §5.6.

## TLS on both hops

There are two hops, and each needs its own verification. **Daemon → pooler:**
the adapter refuses a store URL that does not pin `sslmode=verify-full`
(#3705), so the pooler must serve TLS to its clients and the daemon's URL
carries `sslrootcert=` for the CA that signed the pooler's certificate.
**Pooler → Postgres:** PgBouncer's default `server_tls_sslmode` is `prefer`
(unverified, plaintext if the server offers no TLS), so production must set
`server_tls_sslmode = verify-full` with `server_tls_ca_file` (#4729; the
commented block in `pgbouncer.ini`). The smoke stack ships no certificates, so
those lines are commented out in the template; uncomment them for a real
deployment. Guide §5.6.3 and §14 carry the full checklist.

## Validate

```bash
cd infra/pgbouncer
POSTGRES_PASSWORD=secret ./smoke-test.sh
```

The smoke test brings the stack up, runs an AGE cypher MERGE+MATCH **through
the pooler on 6432** in one transaction, confirms the role-default
`statement_timeout` is visible through the pooler, prints the pooler's
reported `pool_mode`, and tears down. Exit 0 = validated.

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
