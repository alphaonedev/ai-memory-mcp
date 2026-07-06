# v0.9.0 — DigitalOcean operational evidence: PostgreSQL 16 + Apache AGE + pgvector

> **Status: 3 CONSECUTIVE ROUNDS GREEN (GA Step 2).** The `release/v0.9.0`
> `--features sal-postgres` binary was deployed to a live DigitalOcean droplet
> (NYC3, `s-1vcpu-2gb`) backed by **real PostgreSQL 16.14 + Apache AGE 1.6.0 +
> pgvector 0.8.4** — the SAL postgres+AGE path, NOT sqlite — and exercised over
> its HTTP API (loopback daemon) plus direct `psql` substrate verification, for
> **3 consecutive green rounds**. Torn down to **zero droplets** immediately
> after (`terraform destroy` — 3 destroyed). Operator-authorized spend
> (2026-07-06, "AI NHI 100% approved YES to do digitalocean testing").

## Provisioning

- Droplet `ai-memory-hive-substrate` (id 582642118, public 167.71.175.191,
  private 10.20.0.2), NYC3, `s-1vcpu-2gb`, via `infra/do-hive/spawn.sh apply`
  with `TF_VAR_agent_count=0` (single memory droplet; no agent hive).
- Binary: `release/v0.9.0` HEAD `4c43c783`, built locally
  `cargo build --release --features sal-postgres` (cargo version string `0.8.1`
  is the pre-tag manifest value; the code is v0.9.0 / schema v78), scp'd to the
  droplet. NOT the cloud-init-downloaded `releases/latest` (v0.8.1) binary.
- Substrate: PostgreSQL 16.14 (pgdg) + `postgresql-16-pgvector` (0.8.4) +
  Apache AGE 1.6.0 built from source (PG16 branch), `shared_preload_libraries='age'`.

### ⚠️ Provisioning bug found — #1880 (cloud-init)

`infra/do-hive/cloud-init-memory.yaml.tpl` contains an invalid character
(U+0080) that breaks the cloud-config YAML parse — cloud-init logged
`Failed loading yaml blob. unacceptable character #x0080` and discarded the
whole provisioning block (`empty cloud config`), leaving a **bare Ubuntu
droplet** (cloud-init `degraded done`, no postgres/AGE/pgvector). Worked
around by provisioning the identical recipe manually over SSH. Filed as
**#1880** (not tag-blocking; evidence captured via manual provision).

## The round (each of 3 consecutive, all GREEN)

Driven via the daemon HTTP API (`serve --store-url postgres://…` on loopback,
`tier=keyword`, `permissions.mode=advisory`, admin via `X-Agent-Id` +
`AI_MEMORY_ADMIN_HEADER_TRUST=1`) plus direct `psql`:

| Step | Method | Result |
|------|--------|--------|
| 1. schema-init (idempotent) | `schema-init --store-url … --embedding-dim 768` | `schema_version: 78`, 35 tables, 135 indices, 93 functions, extensions `[age, plpgsql, vector]`, AGE `memory_graph` created |
| 2. store ×3 | `POST /api/v1/memories` | `201` ×3, envelopes returned with v0.9 `cid` (blake3) |
| 3. list (read path) | `GET /api/v1/memories?namespace=…` | `count ≥ 3` — read path sees postgres rows |
| 4. recall | `POST /api/v1/recall` | `200`, `storage_backend: postgres`, `count ≥ 1` matches |
| 5. AGE graph | `cypher('memory_graph', … MATCH (n) …)` | node CRUD (CREATE + MATCH) OK |
| 6. secret-screen | `POST /api/v1/memories` with AWS key | `400` — `content rejected: appears to contain credential material (aws_access_key_id)` |
| 7. forget + tombstone | `POST /api/v1/forget` (admin) | `200 {"deleted":1}`, `forget_tombstones` row count increments |

**Rounds: 3/3 GREEN, 0 RED.**

## Substrate verification (direct `psql`)

- **schema_version 78**; extensions `age 1.6.0`, `plpgsql 1.0`, `vector 0.8.4`.
- v0.9.0 tables present: `agent_lineage`, `confidence_shadow_observations`,
  `forget_tombstones`, `memory_links` (with `source_cid` + `target_cid`),
  `model_attestations`, `recall_observations`, `signed_events`.
- **pgvector**: `vector(384)`/`vector(768)` column type + `<=>` cosine
  distance operator functional.
- **Apache AGE**: `cypher()` CREATE + MATCH on `memory_graph` — created a
  `:Mem` vertex and matched it back.

### ⚠️ Robustness bug found — #1881 (default embedding-dim mismatch)

`schema-init` defaults to `vector(384)` while the daemon's default embedder
is 768-dim, so the daemon runs the issue-#877 in-place 384→768 auto-migration
at **every** startup. The column ALTER invalidates cached prepared statements
on the sqlx pool → intermittent `503 "cached plan must not change result
type"` on `list` until the pool recycles. Settling both at 768
(`schema-init --embedding-dim 768`) eliminates the thrash (12/12 list calls
`200`, 3/3 rounds green). Filed as **#1881** (schema-init/daemon should agree
on a default dim; the pool should reset cached plans after an auto-migrate).

## Behavioral coverage note

The store/recall/forget/graph/secret-screen **code paths** are additionally
exercised every CI build by the `--features sal-postgres` suite against a live
PostgreSQL 16 + AGE + pgvector container (`cov_postgres_*`,
`recall_purity_p01_postgres`, `epoch_apply_s5_pg`, etc.). This DO round proves
the same paths on **real DigitalOcean infrastructure**.

## Teardown

`infra/do-hive/teardown.sh` — **3 destroyed** (droplet + firewall + VPC),
`doctl compute droplet list` → empty. Zero residual spend.
