# ai-memory — Pillar-4 4.D per-module envelope (X) measurement

v0.8.0 Pillar-4 **4.D** (#1737). Measures **one module's** concurrent-agent
**knee** — the empirical **X** that replaces the *guessed* "1000 agents/module"
design default (GOAL-EPIC-KICKOFF §104; operator-decision flag (b), §125).

Last strict-order Pillar-4 item: 4.A✅(#1733 admission control) →
4.C✅(#1735 staggered AGE cold-path) → 4.B✅(#1736 PgBouncer pooler) → **4.D**.

## What X is (and is not)

X is the concurrency at which a **single** postgres+AGE+PgBouncer module
backbone reaches its **knee** — where p95 latency crosses budget **or** the
4.A admission controller starts shedding 503s. It is **one module's** ceiling.

X is **not** the fleet ceiling. The 100k–1M-agent target is reached by
composing **independent modules** (each its own backbone + pooler), not by
running X agents on one daemon — see `infra/pgbouncer/README.md` §"Scale-out".
Per spec line 133, the hive claim is *unfalsifiable* without a separate
module-composition track; 4.D measures the per-module knee only.

## Why this needs a Docker host

The measurement's value is the **number**, and producing it requires running
load against a live pooled stack — i.e. the 4.B container backbone. The harness
is therefore **Docker-gated** (like `infra/pgbouncer/smoke-test.sh`) and is
**not** part of the 8-workflow CI gate. The local dev socket is
permission-denied, so the harness ships ready-to-run and the measurement run is
handed to a Docker-capable host (operator/CI). Until X lands, the 1000/module
figure is labelled **PROVISIONAL** in the design docs (operator flag (b)).

## Run it (Docker host)

```bash
cd infra/pillar4-envelope
POSTGRES_PASSWORD=secret ./measure-envelope.sh
```

What it does:

1. **Builds** the release binary fresh (`--features sal-postgres`) — pm-v3.3
   recompile-retest discipline; never measures a stale daemon.
2. Brings up the **4.B pooled stack** (`../pgbouncer/docker-compose.yml`:
   postgres+AGE behind PgBouncer on `6432`, host-mapped).
3. `schema-init` + `serve`s the binary **through the pooler**
   (`postgres://…@127.0.0.1:6432/ai_memory`).
4. Ramps concurrency over `CONCURRENCY_STEPS`. Each worker = one simulated
   agent looping **store → link → recall** (the `link` op drives the **AGE
   graph write path** — the real per-module throughput bound; PgBouncer fixes
   connection fan-in, *not* AGE write concurrency).
5. Per step, records p50/p95/p99 latency + the **503 shed-rate**, and stops at
   the first step that crosses `P95_BUDGET_MS` or `SHED_RATE_KNEE`. That step's
   concurrency is **X**.

Exit 0 prints `MEASURED ENVELOPE X = <n> concurrent agents/module`. Exit 72
means no knee within the ramp (X ≥ last step — raise the ceiling and re-run).

## Tunables (env)

| Env | Default | Meaning |
|---|---|---|
| `POSTGRES_PASSWORD` | `ai_memory_envelope` | DB + pooler password (rendered into the md5 userlist, never committed). |
| `CONCURRENCY_STEPS` | `8 16 32 64 128 256 512 1024` | Geometric ramp (brackets the knee without 1000 linear steps). |
| `STEP_DURATION_SECS` | `20` | Load duration per concurrency step. |
| `P95_BUDGET_MS` | `250` | p95 latency knee (recall hot-path 35 ms + headroom for the write+AGE mix). |
| `SHED_RATE_KNEE` | `0.01` | 503 shed-rate knee (1%). |
| `AI_MEMORY_MAX_INFLIGHT_REQUESTS` | `0` (disabled) | 4.A admission cap. Set it to make the knee show up as 503s rather than unbounded latency. |
| `DAEMON_PORT` | `9077` | Host port the daemon binds. |

For a **pgvector-backed** production backbone (the `sal-postgres` adapter needs
pgvector, which the smoke `apache/age` image lacks), build
`infra/lan-parity-test/Dockerfile.pg-age-vector` and swap `postgres.image` in
`../pgbouncer/docker-compose.yml` before measuring a representative X.

## After you have X (#1737 follow-up)

1. Record X + the host/stack it was measured on (CPU, RAM, disk, pgvector vs
   AGE-only) — X is host-relative.
2. Replace the **PROVISIONAL** 1000/module label in
   `docs/enterprise-deployment.md` §10.1 and
   `docs/v0.7.0/config-driven-pg-pool-prompt.md` with the measured envelope,
   citing the measurement host.
3. Close #1737 with the number + the raw per-step latency table.
