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
| `userlist.txt` | Auth template holding the role's **SCRAM-SHA-256** verifier (`pg_authid.rolpassword`). Render from your secret store at deploy (mode 0400); never commit a real credential. `pgbouncer.ini` pins `auth_type = scram-sha-256`: an md5 entry is refused, but the live pooler still accepts a plain-text entry, so the pin does not refuse it. The generator only ever writes the SCRAM verifier and the smoke's verifier check refuses any other row; never store anything but the verifier (guarded). |
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
./smoke-test.sh
```

The script generates a random password for each run (or uses `POSTGRES_PASSWORD`
from your environment if set). `docker-compose.yml` has no default password and
no default pooler user: running `docker compose` directly fails closed unless
`POSTGRES_PASSWORD`, `PGBOUNCER_UID`, `PGBOUNCER_GID` and `AI_MEMORY_SMOKE_RUN` are
exported (`export PGBOUNCER_UID=$(id -u) PGBOUNCER_GID=$(id -g)`; the run suffix is
`[a-z0-9_-]+`, at most 64 characters, and the userlist bind file name follows it:
`.userlist.generated.<AI_MEMORY_SMOKE_RUN>.txt`, render it from the role verifier first, or compose binds a directory). The pooler is published
on `127.0.0.1:6432` only, never on all interfaces (#4734).

Authentication is SCRAM-SHA-256 end to end (#4732). The postgres service keeps
the image default (`scram-sha-256`). The script brings postgres up first, reads
the role's stored SCRAM verifier from `pg_authid` over `docker exec` stdout
(the password is never in argv, logs or the repo), writes it to
`.userlist.generated.<run>.txt` under `umask 077` (mode 0600, removed at teardown; any leftover file is removed before the write so a stale 0644 file never stays world-readable),
then starts the pooler. The pooler runs as the invoking uid
(`user: ${PGBOUNCER_UID}:${PGBOUNCER_GID}`) so the 0600 file stays readable, and
PgBouncer refuses uid 0, so both scripts exit 64 with a clear message when run
as root. The postgres image is pinned to `apache/age:release_PG16_1.6.0` and the
pooler image to `edoburu/pgbouncer:v1.23.1-p2`. Teardown (`down -v`) is loud: a
failed `down` or a leftover compose project makes the script exit non-zero.
`infra/pillar4-envelope/measure-envelope.sh` reuses this stack with the same
rules.

### Concurrent runs and exit codes

Both scripts derive a per-run suffix (`AI_MEMORY_SMOKE_RUN`, default
`$(date +%s)-$$`; override with `[a-z0-9_-]+`, at most 64 characters). The compose project
(`ai-memory-pgbouncer-smoke-<run>` / `ai-memory-pgbouncer-envelope-<run>`), both container
names (`ai-memory-pgbouncer-<run>` and `ai-memory-pgbouncer-<run>-postgres`) and the
userlist file are unique per run, so a trap only removes its own project and two runs never
recreate each other's containers. Other smokes are found by the stable prefix
`ai-memory-pgbouncer-` (`docker ps --filter name=ai-memory-pgbouncer-`). The pooler still publishes
the fixed host port `127.0.0.1:6432`, so a second concurrent run fails closed at the bind
instead of touching the first. `smoke-test.sh` exit codes: 1 a property failed (AGE round trip,
`statement_timeout`, or the `[4/4]` `SHOW CONFIG` check of `pool_mode = transaction` and
`auth_type = scram-sha-256`), the stack bring-up failed (including that concurrent-run bind failure) or the
teardown failed, 64 run as root, 65 bad `AI_MEMORY_SMOKE_RUN` (outside `[a-z0-9_-]` or over 64 characters), 73 no SCRAM-SHA-256
verifier, 74 the pooled URL carries a password (refused; the password only travels as the inherited
`PGPASSWORD`); any other unlisted non-zero status is the exit status of the failing command under `set -e`. The envelope codes are in `infra/pillar4-envelope/README.md`.

History: an earlier revision of this PR re-stored the smoke role as an md5
verifier; that downgrade is gone.

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
