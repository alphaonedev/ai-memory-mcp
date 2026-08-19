---
layout: doc
---
# PostgreSQL + Apache AGE operator guide (ai-memory v0.9.0)

> **Audience.** Operators running `ai-memory` who want PostgreSQL as the
> live storage backend, with Apache AGE for graph queries and pgvector
> for semantic recall. **As-of v0.7.0**, postgres+AGE is a first-class
> backend — `ai-memory serve --store-url postgres://…` is the supported
> production deployment shape.
>
> If you only want sqlite, you don't need any of this — the default
> `ai-memory serve` continues to work exactly as it did in v0.6.x. The
> postgres path is opt-in.
>
> See also: [`migration-v0.7.0-postgres.md`](migration-v0.7.0-postgres.html)
> for the sqlite → postgres migration runbook, and
> [`RUNBOOK-adapter-selection.md`](RUNBOOK-adapter-selection.html) for
> the adapter-selection design notes.

## Why postgres+AGE

ai-memory's sqlite path is fast, simple, and has zero operational
overhead — for a single workstation or a single daemon, it is the right
choice. Switch to postgres+AGE when one or more of these is true:

- **Multi-tenant scale.** A single sqlite file behind a single
  `Mutex<Connection>` becomes the bottleneck once you cross ~5
  concurrent writers. Postgres' MVCC removes that ceiling.
- **Larger than RAM.** sqlite + HNSW keeps the full vector index in
  memory. pgvector's HNSW lives on disk and pages on demand —
  practical for 10M+ memory corpora.
- **AGE Cypher KG.** ai-memory's KG operations (`kg_query`,
  `kg_timeline`, `kg_invalidate`, `find_paths`) compile to native
  Cypher on AGE, which beats the sqlite recursive-CTE fallback by
  ≥30% at depth=5 on the canonical 1k-entity / 5k-edge corpus
  (S76 perf gate). The deeper the graph, the wider the gap.
- **Multi-daemon A2A.** Two or more `ai-memory serve` processes
  sharing the same store. Postgres is the supported topology;
  sqlite-over-NFS is not.

The two backends have **schema parity at v78**
(`CURRENT_SCHEMA_VERSION = 89` on both ladders — the postgres upgrade
ladder ends at `migrate_v89()`) — every feature that works on sqlite
works on postgres.

## Prerequisites

| Component | Version | Notes |
|---|---|---|
| PostgreSQL | **18.6** (canonical) | The recommended Enterprise Federated substrate. SSOT: `deploy/docker-1461/provision/lib.sh` (`EXPECTED_PG_VERSION=18.6`). PG 16.x + AGE 1.6.0 remains a tested alternate matrix (`infra/lan-parity-test/`). |
| Apache AGE | **1.8.0** (canonical extversion) | Targets PG 18. Installed via the pinned pgdg apt package (`postgresql-18-age=1.8.0~rc0-2.pgdg13+1`, SSOT `EXPECTED_AGE_VERSION=1.8.0`) overlaid on the `apache/age:release_PG18_1.7.0` base — `CREATE EXTENSION age` reports extversion 1.8.0. Use the bundled `deploy/docker-1461/Dockerfile.pg-age-vector` or the pgdg apt package (see below). |
| pgvector | **0.8.6** (canonical) | Faster HNSW; 0.8.3 fixed HNSW-vacuuming index corruption. SSOT: `PGVECTOR_APT_VERSION=0.8.6-1.pgdg13+1`. **Required**: the `sal-postgres` Cargo feature pulls `dep:pgvector` (Rust binding crate `pgvector = "0.4"`) which maps Rust vectors to the Postgres `vector` column type. |
| ai-memory | v0.9.0 with `--features sal-postgres` | The `sal-postgres` feature is **off by default** to keep the no-postgres build hermetic. |

> **CI evidence (#2548 / #2512).** The **one true certified triple** —
> PostgreSQL **18.6** + Apache AGE **1.8.0** + pgvector **0.8.6** — is
> exercised **in-PR on `release/**`** by
> `.github/workflows/cert-postgres-age.yml`, which BUILDS the bundled
> [`deploy/docker-1461/Dockerfile.pg-age-vector`](../deploy/docker-1461/Dockerfile.pg-age-vector)
> to the exact pins declared in `deploy/docker-1461/provision/lib.sh` (the ONE
> declaration source — no literal is re-typed in the workflow), runs the
> `#[ignore]`-gated postgres cells AND the AGE-backed cells against that built
> image, and **hard-fails on ANY drift from the exact pinned minors** —
> PostgreSQL 18.6, Apache AGE 1.8.0, pgvector 0.8.6, not merely "PG 18" or
> "AGE 1.8.x" — so the certified tier is proven by execution, never merely
> claimed (2026-08-01 cutline ruling §5.4(3): "you cannot certify a tier CI
> does not run"; standardized to PG 18.6 / AGE 1.8.0 by operator directive
> 2026-08-18). The `infra/lan-parity-test/` alternate matrix (PG 16 + AGE
> 1.6.0) is what the `coverage.yml` line-coverage measurement runs; that is a
> coverage measurement, not cert evidence.

### Bundled Dockerfile (Apache AGE + pgvector on PG18, #1065)

The upstream `apache/age:release_PG18_1.7.0` image ships AGE but **not**
pgvector. Because the ai-memory v0.7 SAL postgres adapter REQUIRES
pgvector (the `sal-postgres` Cargo feature pulls `dep:pgvector` which
maps Rust vectors to Postgres `vector` columns), the repo ships a
ready-made stacked image at
[`deploy/docker-1461/Dockerfile.pg-age-vector`](../deploy/docker-1461/Dockerfile.pg-age-vector)
(#1065). It layers pgvector `0.8.6` (precompiled .deb from the pgdg apt
repo) onto the `apache/age:release_PG18_1.7.0` base AND upgrades AGE to
`1.8.0` via the pinned pgdg `postgresql-18-age` package — no source build
needed. Use this image for any deployment that backs ai-memory onto
Postgres+AGE. (The `infra/lan-parity-test/` image — PG 16 + AGE 1.6.0 +
pgvector 0.8.2 — remains as a tested alternate matrix.)

> **Cypher parameter binding.** ai-memory's production code interpolates
> parameters into the Cypher string through the AGE-recommended
> `cypher()` SQL-function form, which is portable across AGE releases —
> if you write your own SQL probes, prefer the SQL-function form. (A
> historical AGE 1.5.0 + PG 16 quirk could emit "could not find
> parameter $N" for some bind shapes against the raw `prepare`-path;
> the SQL-function form sidesteps it entirely and AGE 1.8.0 on PG 18 is
> unaffected. Wave 1 Stream C fixed our equivalence test harness to use
> the safe form; production code never needed the fix.)

## Install — Ubuntu 24.04 example

```bash
# 1. PostgreSQL 18 from PGDG.
sudo apt install -y curl ca-certificates gnupg lsb-release
sudo install -d /usr/share/postgresql-common/pgdg
sudo curl -fsSL https://www.postgresql.org/media/keys/ACCC4CF8.asc \
     -o /usr/share/postgresql-common/pgdg/apt.postgresql.org.asc
echo "deb [signed-by=/usr/share/postgresql-common/pgdg/apt.postgresql.org.asc] \
     https://apt.postgresql.org/pub/repos/apt $(lsb_release -cs)-pgdg main" \
     | sudo tee /etc/apt/sources.list.d/pgdg.list
sudo apt update
sudo apt install -y postgresql-18 postgresql-server-dev-18 \
                    postgresql-contrib-18 build-essential bison flex git

# 2. pgvector 0.8.6 from the upstream release tag.
git clone --depth 1 --branch v0.8.6 https://github.com/pgvector/pgvector.git
cd pgvector
sudo make USE_PGXS=1 PG_CONFIG=/usr/lib/postgresql/18/bin/pg_config install
cd ..

# 3. Apache AGE 1.8.0 from the PGDG apt repo (the certified install path —
#    1.8.0 is the newest RELEASED AGE for PG18 and is published as a pinned
#    pgdg .deb; `CREATE EXTENSION age` reports extversion 1.8.0). The pgdg
#    package is the same mechanism the do-1461 native lane + bundled
#    Dockerfile use; there is no stable 1.8.0 source tag (only v1.8.0-rc0).
sudo apt install -y postgresql-18-age=1.8.0~rc0-2.pgdg13+1

# 4. Restart postgres to pick up the shared libraries.
sudo systemctl restart postgresql@18-main
```

For RHEL / Fedora / Amazon Linux: replace the `apt` lines with the
PGDG yum repo equivalents and ensure `postgresql18-devel` /
`postgresql18-contrib` are installed before building AGE.

### Docker — pgvector is required, not optional ([#1065](https://github.com/alphaonedev/ai-memory-mcp/issues/1065))

The popular `apache/age:release_PG18_*` Docker images **do not bundle
pgvector**. The SAL postgres adapter's `init schema` step calls
`CREATE EXTENSION IF NOT EXISTS vector` and fails-fast on missing
extension with the message `extension "vector" is not available` —
restarting the daemon container indefinitely on Plan C and any
Compose / K8s deploy.

The canonical fix is a 2-line Dockerfile that layers pgvector on top
of the upstream Apache AGE image:

```dockerfile
# Dockerfile.pg-age-vector — see deploy/docker-1461/Dockerfile.pg-age-vector
FROM apache/age:release_PG18_1.7.0
USER root
RUN apt-get update \
 && apt-get install -y --no-install-recommends postgresql-18-pgvector \
 && rm -rf /var/lib/apt/lists/*
USER postgres
```

The ai-memory repo ships this Dockerfile at
[`deploy/docker-1461/Dockerfile.pg-age-vector`](../deploy/docker-1461/Dockerfile.pg-age-vector);
the lan-parity compose file uses its PG 16 + AGE 1.6.0 counterpart via:

```yaml
services:
  pg-age:
    build:
      context: .
      dockerfile: Dockerfile.pg-age-vector
```

Plan C operators running on K8s / ECS / Cloud Run build this image
once, tag it (`pg-age-vector:PG18.6-1.8.0-pgvector0.8.6`), and reference
the tag from their workload manifests instead of the bare upstream
image.

## Database setup

```bash
sudo -u postgres psql <<'SQL'
CREATE ROLE aimemory WITH LOGIN PASSWORD 'changeme-please';
CREATE DATABASE aimemory OWNER aimemory;
\c aimemory
CREATE EXTENSION IF NOT EXISTS age;
CREATE EXTENSION IF NOT EXISTS vector;
GRANT USAGE ON SCHEMA ag_catalog TO aimemory;
GRANT ALL ON ALL TABLES IN SCHEMA public TO aimemory;
ALTER DATABASE aimemory SET search_path = ag_catalog, "$user", public;
SQL
```

Notes:

- `aimemory` is the role the daemon runs as. Pick a strong password and
  store it in your secret manager. As of v0.9.0 ([#1927](https://github.com/alphaonedev/ai-memory-mcp/issues/1927)), prefer a
  non-argv channel over `--store-url` for the credential: `AI_MEMORY_STORE_URL`
  (read from the owner-only process environment) or `AI_MEMORY_STORE_URL_FILE`
  (a `0600` file holding the URL) — both were (re-)added specifically to
  keep the password off world-readable `/proc/<pid>/cmdline` and `ps
  auxww`. See "Daemon configuration" below for the resolution order.
- `ag_catalog` must be on the search path so AGE's `cypher()` SQL
  function resolves without a schema prefix on every call.
- The role only needs `USAGE` on `ag_catalog` (read of the AGE
  function definitions); the AGE projection objects ai-memory creates
  live in the `aimemory` schema by default.

## Bootstrap the schema

`ai-memory schema-init` (Wave 1 Stream B deliverable) is the supported
way to bootstrap a fresh postgres backend:

```bash
ai-memory schema-init --store-url postgres://aimemory:changeme-please@localhost:5432/aimemory
```

What it does (see `src/cli/schema_init.rs`):

1. Connects to the `--store-url` via the same `open_store` factory the
   `migrate` verb uses — the open itself runs `INIT_SCHEMA` (the
   bundled `src/store/postgres_schema.sql`, idempotent `CREATE TABLE
   IF NOT EXISTS` throughout) plus the in-process upgrade ladder up to
   schema v89 (the current `CURRENT_SCHEMA_VERSION`) as a side effect. The
   `vector` (pgvector) extension is
   **required** — `CREATE EXTENSION IF NOT EXISTS vector` failing
   aborts the bootstrap.
2. If the `age` extension is installed, additionally bootstraps the
   AGE `memory_graph` projection via `SELECT
   create_graph('memory_graph')` (idempotent — "graph already exists"
   is treated as success). **AGE is opt-in**: a missing extension is
   NOT fatal; the JSON report just carries
   `age_projection_created: false` and KG queries use the
   recursive-CTE fallback.
3. Applies the `--embedding-dim` contract: when the flag is omitted
   the dim resolves from the SAME config-driven source the daemon uses
   for its embedder (the effective tier's embedder dim; 384 for the
   keyword / no-embedder case), so a default deploy provisions exactly
   what `serve` will produce (#1882). A fresh schema is initialised with
   `vector(<dim>)` columns; an existing schema whose dim differs is
   converted in place (HNSW indexes dropped + recreated, existing
   embedding values NULLed — re-embed afterwards; `embedding_dim_migrated:
   true` in the JSON report).
4. Enumerates the resulting catalog and prints the human summary
   (tables / indices / views / functions / extensions /
   `schema_version: 89`) or the `--json` report.

Idempotent on rerun — safe to invoke from a deploy script. Exit code
0 on success, non-zero on connection / bootstrap failure.

There is no `--skip-age` flag — AGE is auto-detected; when absent the
recursive-CTE fallback serves `kg_query`/`kg_timeline`/etc.

## Daemon configuration

`--store-url` on `serve` is still accepted, but as of v0.9.0 ([#1927](https://github.com/alphaonedev/ai-memory-mcp/issues/1927)) two
non-argv channels exist and are preferred, since a password on
`--store-url` is exposed via world-readable `/proc/<pid>/cmdline` and
`ps auxww` to any local UID. `resolve_store_url()` (`src/daemon_runtime.rs`)
resolves the store URL in this order, first hit wins:

1. `AI_MEMORY_STORE_URL_FILE` — a `0600` file whose sole contents are the store URL (the most restrictive channel).
2. `AI_MEMORY_STORE_URL` — the owner-only process environment (`/proc/<pid>/environ` is mode `0400`, strictly better than argv).
3. the `--store-url` CLI argument (unchanged; a userinfo password on this flag emits a warning pointing at the non-argv alternatives).

```bash
# Preferred (v0.9.0+): non-argv channel
export AI_MEMORY_STORE_URL='postgres://aimemory:PASSWORD@HOST:5432/aimemory'
ai-memory serve

# Still accepted, but the password is exposed via /proc/<pid>/cmdline and `ps`
ai-memory serve --store-url postgres://aimemory:PASSWORD@HOST:5432/aimemory
```

URL shapes accepted by `--store-url` (and the env/file channels above):

- `postgres://user:pass@host:port/dbname`
- `postgresql://user:pass@host:port/dbname` (alias)
- `sqlite:///absolute/path/to/file.db` (also valid — same semantics as `--db`)

`--db` and `--store-url` are **mutually exclusive**. Passing both
when `--db` is explicit (set on the command line OR via the
`AI_MEMORY_DB` env var) errors at startup:

```
Error: --db and --store-url are mutually exclusive. Pass exactly one.
       Got --db=/var/lib/ai-memory/db.sqlite and
       --store-url=postgres://aimemory:...@10.20.0.4:5432/aimemory
```

When `--store-url` is **unset**, the daemon falls back to its sqlite
path (`AI_MEMORY_DB` or `--db`'s default). This preserves
byte-for-byte v0.6.x behavior on the default build.

The daemon logs the resolved backend at startup. For postgres:

```
INFO  ai_memory::daemon_runtime: Wave-3: opening Postgres SAL store at postgres://aimemory:...
WARN  ai_memory::daemon_runtime: v0.7.0 Wave-3: postgres-backed daemon — handlers
       that have not yet migrated to the SAL trait surface 501 Not Implemented.
```

A second probe of `/api/v1/capabilities` confirms it:

```bash
curl -s http://HOST:9077/api/v1/capabilities | jq .storage_backend
# "postgres"
```

If AGE is detected, KG queries dispatch through the Cypher path; if
not, the fallback recursive-CTE path runs against the
`memory_links` table on postgres exactly as it does on sqlite.

## HTTPS / mTLS configuration

`ai-memory serve` ships with two-layer transport security:

| Layer | Flag                  | Effect                                         |
|------:|-----------------------|------------------------------------------------|
|     1 | `--tls-cert <path>`   | Server cert (PEM, ECDSA P-256 or RSA)          |
|     1 | `--tls-key <path>`    | Server private key (PKCS#8, RSA, or SEC1 PEM)  |
|     2 | `--mtls-allowlist <path>` | Per-line SHA-256 fingerprint allowlist for client certs |

Layer 1 alone gives you HTTPS — peers verify the server's identity
through the supplied cert chain. Layer 2 layers mTLS on top: the
server requires every client to present a certificate whose SHA-256
DER fingerprint matches an entry in `--mtls-allowlist`. Combined,
they implement the SSH `known_hosts` pin model — the cert chain is
not the trust anchor; the fingerprint pin is.

### Step 1 — generate a CA, server certs, and client certs

The campaign repo ships a one-shot generator at
[`/tmp/a2a-v07-tls/regen.sh`](https://github.com/alphaonedev/ai-memory-a2a-v0.7.0/blob/main/scripts/...);
the underlying openssl invocations look like:

```sh
# 1. test CA (10y, ECDSA P-256). Substitute a stronger key + a real
#    DN for production deployments.
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out ca.key
openssl req -x509 -new -nodes -key ca.key -days 3650 \
    -subj "/CN=my-ai-memory-fleet" -out ca.pem

# 2. server cert. SANs MUST cover every IP/DNS the daemon listens on.
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out server.key
cat > server.cnf <<EOF
[req]
distinguished_name = dn
req_extensions = v3_req
prompt = no
[dn]
CN = ai-memory.internal
[v3_req]
basicConstraints = CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names
[alt_names]
DNS.1 = ai-memory.internal
IP.1 = 10.20.0.2
IP.2 = 127.0.0.1
EOF
openssl req -new -key server.key -out server.csr -config server.cnf
openssl x509 -req -in server.csr -CA ca.pem -CAkey ca.key -CAcreateserial \
    -out server.pem -days 3650 -extfile server.cnf -extensions v3_req

# 3. client cert(s). Repeat per agent identity; the server allowlist
#    pins each client's fingerprint.
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out client-alice.key
# ... same shape as server.cnf with `extendedKeyUsage = clientAuth`.

# 4. compute each client cert's SHA-256 DER fingerprint.
for c in client-*.pem; do
    fp=$(openssl x509 -in "$c" -noout -fingerprint -sha256 \
         | sed 's/.*=//' | tr -d ':' | tr 'A-F' 'a-f')
    echo "$fp"
done > mtls-allowlist.txt
```

Allowlist format (`src/tls.rs::load_fingerprint_allowlist`):

- one fingerprint per line, hex digits, optional `:` separators
- `sha256:` prefix is accepted
- `#` comments (full-line + inline) are stripped before parsing
- empty lines are ignored

### Step 2 — wire the daemon's systemd unit

Edit `/etc/systemd/system/ai-memory.service` (or its drop-in equivalent)
and append the three flags to the `ExecStart=` line:

```ini
[Service]
ExecStart=/usr/local/bin/ai-memory serve \
    --store-url postgres://aimemory:PWD@10.20.0.4:5432/aimemory \
    --tls-cert /etc/ai-memory/tls/server.pem \
    --tls-key  /etc/ai-memory/tls/server.key \
    --mtls-allowlist /etc/ai-memory/tls/mtls-allowlist.txt
```

Reload + restart:

```sh
systemctl daemon-reload
systemctl restart ai-memory
```

The `deploy_wave4.sh` helper in the campaign repo does this
automatically when invoked with `DEPLOY_TLS=1` (and, for mTLS,
`DEPLOY_MTLS=1` which is the default when DEPLOY_TLS=1):

```sh
DEPLOY_TLS=1 DEPLOY_MTLS=1 \
TLS_LOCAL_DIR=/tmp/a2a-v07-tls \
TLS_REMOTE_DIR=/etc/ai-memory-a2a/tls \
scripts/deploy_wave4.sh
```

### Step 3 — verify with curl

```sh
# (from the same VPC; --resolve picks the right SAN)
curl -sS \
    --cacert /etc/ai-memory/tls/ca.pem \
    --cert   /etc/ai-memory/tls/client-alice.pem \
    --key    /etc/ai-memory/tls/client-alice.key \
    https://ai-memory.internal:9077/api/v1/capabilities | jq .storage_backend
# "postgres"
```

A failed handshake (wrong CA, missing client cert, fingerprint not on
allowlist) surfaces as a curl `(35) error:0A000412:SSL routines::sslv3
alert bad certificate` — the server log carries the structured reason.

### Step 4 — wire the campaign harness

The harness picks a per-agent client cert from env vars:

```sh
export TLS_MODE=mtls
export TLS_CA_PEM=/etc/ai-memory-a2a/tls/ca.pem
export TLS_CLIENT_CERT_ALICE=/etc/ai-memory-a2a/tls/client-alice.pem
export TLS_CLIENT_KEY_ALICE=/etc/ai-memory-a2a/tls/client-alice.key
export TLS_CLIENT_CERT_BOB=/etc/ai-memory-a2a/tls/client-bob.pem
export TLS_CLIENT_KEY_BOB=/etc/ai-memory-a2a/tls/client-bob.key
# ... per-agent pairs for every identity the campaign uses.
# Optional process-wide default (used when no per-agent var matches):
export TLS_DEFAULT_CLIENT_CERT=/etc/ai-memory-a2a/tls/client-default.pem
export TLS_DEFAULT_CLIENT_KEY=/etc/ai-memory-a2a/tls/client-default.key
```

The agent suffix is the upper-cased `agent_id` with non-alphanumerics
collapsed to `_` (so `ai:alice@nyc3-droplet-1` becomes
`AI_ALICE_NYC3_DROPLET_1`). The Python campaign harness
(`scripts/a2a_harness.py`, `Harness.client_cert_for`) that implemented
this lookup has been retired from the repo; the live mTLS leg checks
are the shell harness at `deploy/do-1461/test/encrypted_legs.sh`
(`MTLS_CLIENT_CERT` / `MTLS_CLIENT_KEY` convention — see
`deploy/docker-1461/provision/lib.sh`).

Each scenario report now carries a `tls_handshake` block:

```json
{
    "scenario": "20",
    "tls_mode": "mtls",
    "tls_handshake": {
        "count": 17,
        "min_seconds": 0.013,
        "mean_seconds": 0.022,
        "max_seconds": 0.054,
        "total_seconds": 0.379
    }
}
```

Plain-HTTP runs omit the block. The orchestrator's perf-vs-baseline
diff (Phase 7 of the cert closure) reads `tls_handshake.total_seconds`
to compute the per-scenario TLS overhead.

### Cert closure run reference

The Continuation-6 cert closure run (commit `<orchestrator-fills-in>`)
exercises this configuration end-to-end against the wave-4 droplet
fleet. Compare its `runs/<id>/aggregate.json` against the plain-HTTP
baseline at
[`runs/v0.7.0-a2a-wave4r2-r1-20260509-1858/`](https://github.com/alphaonedev/ai-memory-a2a-v0.7.0/tree/main/runs/v0.7.0-a2a-wave4r2-r1-20260509-1858)
to read the perf overhead.

## Operator surfaces that "just work" identically on both backends

The point of the SAL trait is that no caller needs to know which
backend is mounted. As of v0.7.0 Wave-3 + Wave-3 Continuation the
following **HTTP endpoints** route through the SAL trait
identically on sqlite and postgres:

### Core CRUD (Wave-3 Phase 3 — commit `c049500`)

| HTTP method | Path | Trait method |
|---|---|---|
| `POST` | `/api/v1/memories` | `MemoryStore::store` |
| `GET` | `/api/v1/memories/:id` | `MemoryStore::get` + `list_links` |
| `PUT` | `/api/v1/memories/:id` | `MemoryStore::update` |
| `DELETE` | `/api/v1/memories/:id` | `MemoryStore::delete` |
| `GET` | `/api/v1/memories` | `MemoryStore::list` |
| `GET` | `/api/v1/search` | `MemoryStore::search` |
| `POST` | `/api/v1/links` | `MemoryStore::link_signed` |
| `GET` | `/api/v1/memories/{id}` (links are returned inline) | `MemoryStore::list_links` |
| `GET` | `/api/v1/capabilities` | reports `storage_backend` |
| `GET` | `/api/v1/health` | (no storage I/O) |

### Wave-3 Continuation (Phase 4 + 5)

| HTTP method | Path | SAL dispatch |
|---|---|---|
| `POST` | `/api/v1/memories/bulk` | streams each row through `MemoryStore::store` |
| `GET` | `/api/v1/agents` | projects `_agents` namespace via `MemoryStore::list` |
| `POST` | `/api/v1/agents` | `MemoryStore::register_agent` |
| `GET` | `/api/v1/namespaces` | aggregates from `MemoryStore::list` |
| `GET` | `/api/v1/stats` | counts + per-tier histogram via `MemoryStore::list` |
| `GET` | `/api/v1/taxonomy` | flat per-namespace tree via `MemoryStore::list` |
| `GET` | `/api/v1/archive` | projects from `archived_memories` (postgres helper) |
| `GET` | `/api/v1/archive/stats` | aggregates from `archived_memories` (postgres helper) |
| `POST` | `/api/v1/entities` | `MemoryStore::store` with `metadata.kind=entity` |
| `GET` | `/api/v1/entities/by_alias` | walks namespace via `MemoryStore::list` + alias match |
| `GET` | `/api/v1/pending` | empty list with `storage_backend: postgres` note |
| `POST` | `/api/v1/kg/query` | `PostgresStore::kg_query` (AGE Cypher / CTE fallback) |
| `GET` | `/api/v1/kg/timeline` | `PostgresStore::kg_timeline` |
| `POST` | `/api/v1/kg/invalidate` | `PostgresStore::kg_invalidate` |
| `GET` | `/api/v1/inbox` | empty list with structured note |
| `GET` | `/api/v1/subscriptions` | empty list with structured note |
| `POST` | `/api/v1/check_duplicate` | structured no-match envelope (semantic scan is sqlite-only) |

### Wave-3 Continuation 2 (Phase 8 + 9 + 10 + 11)

The four critical surfaces gated for v0.7.0 land here. After
Continuation 2, postgres-backed daemons run as first-class peers in
federation, fire the same audit chain as sqlite, run the full
hybrid recall pipeline, and accept governance write paths.

| HTTP method | Path | SAL dispatch |
|---|---|---|
| `POST` | `/api/v1/sync/push` | per-row `MemoryStore::apply_remote_memory` / `apply_remote_link` / `apply_remote_deletion`. Heterogeneous federation (sqlite ↔ postgres) round-trips. |
| `GET` | `/api/v1/sync/since` | `MemoryStore::list_memories_updated_since` |
| `GET` | `/api/v1/recall` and `POST /api/v1/recall` | `MemoryStore::recall_hybrid` (FTS + pgvector cosine + adaptive blend; mode=hybrid when embedder loaded). Touch ops fire via `MemoryStore::touch_after_recall`. |
| `POST` | `/api/v1/pending/{id}/approve` | (Continuation 3 / Phase 20) full consensus state machine via `MemoryStore::governance_approve_with_consensus` — Human / Agent(required) / Consensus(N) variations + registered-agent gating + threshold transition. |
| `POST` | `/api/v1/pending/{id}/reject` | `MemoryStore::pending_decide(approve=false)` + audit emit. |
| `POST` | `/api/v1/namespaces/{ns}/standard` and `POST /api/v1/namespaces` | auto-seeds placeholder via `MemoryStore::store`, then `MemoryStore::set_namespace_standard` |
| `DELETE` | `/api/v1/namespaces/{ns}/standard` and `DELETE /api/v1/namespaces` | `MemoryStore::clear_namespace_standard` |

### Wave-3 Continuation 3 (Phase 13 + 14 + 15 + 16 + 17 + 18 + 19 + 20)

The eight remaining sqlite-only surfaces land here. After
Continuation 3, **every** HTTP endpoint that works on a sqlite-backed
daemon also works on a postgres-backed daemon — there is no residual
501 envelope on standard endpoints (the route gate keeps the 501
envelope as a safety net for unknown / future endpoints).

| HTTP method | Path | SAL dispatch |
|---|---|---|
| `POST` | `/api/v1/forget` | `MemoryStore::forget` — namespace + ILIKE pattern + tier filters; archive-on-forget moves rows to `archived_memories` with `archive_reason='forget'` before deletion. |
| `POST` | `/api/v1/consolidate` | `MemoryStore::consolidate` — atomic transaction merges sources (tags / metadata / max-priority / sum-access_count), preserves `consolidated_from_agents` provenance, deletes source rows. |
| `GET` | `/api/v1/contradictions` | `MemoryStore::list` + `MemoryStore::list_links` — non-LLM heuristic (pairwise differing-content detection) runs identically on both backends. |
| `POST` | `/api/v1/notify` | `MemoryStore::notify` — lands a memory in `_inbox/<target>` with `metadata.target_agent_id`. |
| `POST` | `/api/v1/gc` | `MemoryStore::run_gc` — deletes (or archives-then-deletes) every row whose `expires_at` is in the past. |
| `POST` | `/api/v1/import` | `MemoryStore::store` per memory + `MemoryStore::link` per link. |
| `GET` | `/api/v1/export` | `MemoryStore::export_memories` + `MemoryStore::export_links`. |
| `POST` | `/api/v1/archive` | `MemoryStore::archive_by_ids` — preserves original tier + expiry + embedding via `original_tier`/`original_expires_at` columns. |
| `DELETE` | `/api/v1/archive` | `MemoryStore::archive_purge`. |
| `POST` | `/api/v1/archive/{id}/restore` | `MemoryStore::archive_restore` — atomic move back to active; rejects (Conflict) when the id already exists in active memories. |
| `POST` | `/api/v1/memories` (writes only) | inheritance-chain walk via `MemoryStore::enforce_governance_action` BEFORE store; Allow/Deny/Pending decisions surface as 201/403/202 respectively. |

### Wave-3 Continuation 6 — F7 closure (S52, S61, S65)

Three new HTTP endpoints close the Wave 4 cert-harness gaps surfaced
post-Continuation-5. Each routes through the SAL trait so postgres-backed
and sqlite-backed daemons project byte-identical wire shapes.

| HTTP method | Path | SAL dispatch |
|---|---|---|
| `POST` | `/api/v1/quota/status` | `MemoryStore::quota_status(agent_id)` (single-agent) or `MemoryStore::quota_status_list()` (operator-facing list). Postgres reads from the `agent_quotas` table directly — no fallthrough to the empty scratch sqlite. Auto-inserts the default row on first call. Body `{agent_id?, namespace?}`; returns the canonical `QuotaStatus` projection (`max_memories_per_day`, `max_storage_bytes`, `max_links_per_day`, `current_*`, `day_started_at`, ...). |
| `POST` | `/api/v1/kg/find_paths` | `MemoryStore::find_paths(source, target, max_depth?, max_results?)`. SQLite uses the recursive CTE in `db::find_paths`; Postgres dispatches AGE Cypher when the extension is installed and falls back to a SQL recursive CTE otherwise. Body `{source_id, target_id, max_depth?, max_results?}`; returns `{paths: [[id, ...], ...], count, source_id, target_id}`. 422 when `max_depth` exceeds the supported ceiling. |
| `POST` | `/api/v1/links/verify` | `MemoryStore::verify_link(VerifyFilter)`. Resolves the `(source, target?, relation?)` triple from the body and re-verifies the canonical-CBOR signature against the enrolled peer key when one is present. Body `{source_id?, target_id?, link_id?}` — at least one of `source_id` or `link_id` is required (`link_id` format is `source_id|target_id|relation`). Returns `{verified, attest_level, signature_present, observed_by, source_id, target_id, relation, findings}`. |

#### Phase 20 — full governance pipeline

Postgres-backed daemons now run the **full** governance pipeline that
sqlite-backed daemons run:

- `MemoryStore::build_namespace_chain` walks `namespace_meta` for
  explicit-parent ancestors (bounded by 8 hops + cycle-safe) +
  `/`-derived hierarchy.
- `MemoryStore::resolve_governance_policy` walks leaf-first and
  returns the most-specific policy with `inherit=true` honored.
- `MemoryStore::enforce_governance_action` evaluates Any /
  Registered / Owner / Approve levels; `Approve` queues a
  `pending_actions` row and returns the canonical pending id.
- `MemoryStore::governance_approve_with_consensus` runs the full
  multi-vote state machine: Human accepts any caller, Agent requires
  the named id, Consensus requires registered-agent voters with
  case-insensitive duplicate-vote dedup; threshold transition stamps
  `decided_by` + `decided_at` and returns Approved.

The post-approval `execute_pending_action` payload-replay path
remains sqlite-only — postgres operators on Approved actions
re-issue the underlying write via the standard CRUD path. This is
the only residual scope difference between sqlite and postgres for
governance.

Federation fanout for governance decisions / archive / restore /
purge stays sqlite-only (the `broadcast_*_quorum` paths use
sqlite-coupled fed-tracker state); postgres operators relying on
multi-node consistency for these subcollections should poll peers
or pin to sqlite for v0.7.0.

The audit module is file-based with no SQLite coupling, so
`ai-memory audit verify --audit-dir <path>` works on a
postgres-backed daemon's log unchanged. The F2 fix
(cross-restart sequence persistence via the chain-tail walk in
`audit::init`) lights up for postgres through the new emit sites
in `create_memory` / `delete_memory` / `create_link` /
`approve_pending` / `reject_pending` / `sync_push`.

The full hybrid recall pipeline mirrors `db::recall_hybrid` (sqlite
path) over pgvector + tsvector + ts_rank: 6-factor FTS sub-score
(priority \* 0.5 + min(access_count, 50) \* 0.1 + confidence \* 2.0
+ tier_bonus + recency_factor), 0.2 cosine gate, adaptive blend
(`semantic_weight = 0.50` for ≤500 chars, lerp to `0.15` at ≥5000
chars), atomic touch ops (++access_count + TTL extension +
mid→long auto-promotion at 5 accesses + ++priority every 10
accesses).

### Postgres route gate

Wave-3 Continuation also installs a route-gate middleware at the
router layer (`handlers::postgres_route_gate`). On a postgres-backed
daemon, any (method, path) tuple **not** in the supported list above
is short-circuited with a structured 501 envelope before reaching
the legacy SQLite handler — closing the silent-corruption gap where
un-migrated handlers would otherwise read from / write to the empty
in-memory scratch SQLite database that `bootstrap_serve` opens
against `--db`. On sqlite-backed daemons the gate is a pure
pass-through.

### What still returns 501 on postgres

Of the **80 unique production URL paths** (over **94 `.route(...)`
registrations in `src/lib.rs`**, surfaced through
`/api/v1/capabilities`), **59 are served on a postgres-backed daemon
and 21 are fully fail-closed** — every HTTP method on those 21 paths
returns a uniform `501 NOT IMPLEMENTED`. The gate FAILS CLOSED by
design: an un-migrated handler can never fall through to the empty
in-memory scratch SQLite database that `bootstrap_serve` opens against
`--db`, so the worst case on Postgres is a loud 501, never a silent
read/write against the wrong database (data-integrity North Star:
degrade, never corrupt). This inventory is pinned against regression by
`tests/pg_supported_route_inventory_gate_2799.rs`, which freezes the
exact 59-supported / 21-fully-501 partition and fails CI if the router
and the `postgres_endpoint_supported()` allow-list ever drift.

**The 21 fully-501 paths (honest v1.0 gaps — do NOT expect these to
work on Postgres; closing them is tracked under the v1.x Postgres
surface-parity EPIC [#2803](https://github.com/alphaonedev/ai-memory-mcp/issues/2803)):**

- **Agent Skills surface** — `/api/v1/skill/*` (8 paths): postgres ships
  no skills table (`migrate_v82` is a version-stamp no-op). *(v1.x:
  postgres skills storage.)*
- **`/api/v1/find_paths`** — the bare legacy alias. Use the supported
  `/api/v1/kg/find_paths` instead.
- **`/api/v1/share`** — the pg source-read `CallerContext` is a T3
  authorization posture choice deferred to a vote. *(v1.x.)*
- **`memory_*` MCP-parity routes with no pg SAL method / app.db binding**
  (11 paths): `memory_atomise`, `memory_smart_load`,
  `memory_export_reflection`, `memory_replay`,
  `memory_subscription_replay`, `memory_subscription_dlq_list`,
  `memory_calibrate_confidence`, `memory_dependents_of_invalidated`,
  and `memory_verify` (compact link-verify is `app.db`-bound;
  `/api/v1/links/verify` **is** the pg-supported link-verify surface).
  `memory_rule_list` + `memory_check_agent_action` 501 only the
  governance **INSPECTION / read** API because postgres ships no
  `governance_rules` table — governance **enforcement** itself works on
  Postgres. *(v1.x: pg SAL methods + governance_rules table.)*

Conversely, several surfaces that once 501'd on Postgres are now
supported: `kg_query` / `kg_invalidate` / `kg_timeline` traverse all 9
relations, `/api/v1/capabilities` reports the `kg_backend` field,
verbose recall carries `latest_link_attest_level`, and
`verify-audit-trail --store-url` verifies the postgres audit chain.

The route gate retains its 501 envelope as a safety net for:

- Unknown / future endpoints not yet in the allow-list.
- Operator-installed handlers (custom plugins) that have not been
  classified.

Two **degraded-mode** behaviors remain documented but do not block
endpoint availability:

- `execute_pending_action` payload-replay (the post-Approved write
  fanout) — sqlite-only. Postgres-backed daemons return 200 +
  `{approved: true, executed: false}` on consensus threshold; the
  approving caller re-issues the underlying write via the standard
  CRUD path. The full state machine runs identically on both
  backends — only the auto-replay step is gated.
- Federation fanout subcollections that ride sqlite-only fed-tracker
  state: archive / restore / purge / pending-decision broadcast.
  Memories / deletions / links / sync_push core round-trip through
  the trait. Postgres operators relying on multi-node consistency
  for these subcollections should poll peers or pin sqlite for v0.7.0.

Schema parity at v78 means `ai-memory migrate` sqlite → postgres
carries every row across cleanly.

The recall **score breakdown** is the same 6-factor formula on both
backends:

```
score = semantic_weight * cosine
      + (1 - semantic_weight) * fts_norm
      + priority * 0.05
      + access_count * 0.01
      + confidence * 0.20
      + tier_bonus
      + recency_factor
```

(Wave 1 Stream A's `tests/recall_scoring_parity.rs` pins this
contract — same query, same top-K, same per-factor breakdown
within FP tolerance.)

## Performance notes

### pgvector HNSW

The postgres adapter creates an HNSW index on `memories.embedding`
during `schema-init`:

```sql
CREATE INDEX IF NOT EXISTS memories_embedding_hnsw
    ON memories USING hnsw (embedding vector_cosine_ops);
```

Default tuning is the pgvector default (`m=16`, `ef_construction=64`).
For corpora >1M memories, raising `ef_construction` to 128 at index
build time and `hnsw.ef_search` to 80 at query time is the standard
recommendation; the v0.7.0 release does not yet expose these as
`ai-memory schema-init` flags — set them via SQL post-bootstrap.

### AGE Cypher vs CTE fallback

The four KG operations dispatch on the `KgBackend` tag the postgres
adapter probes at connect time:

| Op | AGE 1.8.0 (Cypher) | CTE fallback | Speedup at depth=5 |
|---|---|---|---|
| `kg_query` | `MATCH (a)-[*1..d]->(b) WHERE a.id = $1` | recursive `WITH` join | ≥30% (S76 gate) |
| `kg_timeline` | `MATCH ... WHERE valid_from < $1 AND (valid_until IS NULL OR valid_until > $1)` | recursive temporal join | ≥30% |
| `kg_invalidate` | `MATCH ... SET valid_until = $1` | `UPDATE memory_links` | parity |
| `find_paths` | `MATCH p = shortestPath((a)-[*1..d]->(b))` | recursive CTE with cycle detection | 2-5× at depth=5+ |

The S76 perf gate fires if AGE is reported as engaged but the AGE p95
is **not** at least 30% faster than CTE p95 on the canonical 1k-entity
/ 5k-edge corpus. That gate is honest about the AGE-vs-CTE comparison
on the **same** postgres host — comparing AGE-on-postgres to
CTE-on-sqlite is a different question and not the speedup we claim.

### AGE projection mode (sync vs deferred) — #1735

Postgres link writes project edges into the AGE `memory_graph` so Cypher
traversals see them. `AI_MEMORY_AGE_PROJECTION_MODE` selects the posture
(postgres-only; SQLite ignores it):

- `sync` (default) runs the inline `project_link_into_age` Cypher MERGE
  inside the link-write transaction — byte-identical to the
  pre-#1735 behaviour.
- `deferred` enqueues a `kg_projection_outbox` row (schema v69) in the
  same transaction as the relational `memory_links` INSERT and skips the
  inline MERGE; a cold drainer worker (spawned by `serve`, with a
  drain-once boot-recovery pass plus an interval loop) projects the
  pending rows into `memory_graph` out-of-band, taking the synchronous
  AGE round-trips off the link-write hot path. Failed projections retry
  up to `MAX_AGE_PROJECTION_ATTEMPTS` then quarantine.

Under `deferred`, postgres `find_paths` routes through the
always-current relational recursive-CTE so reads stay read-your-own-write
correct during the projection window; `kg_query` / `kg_timeline` may
observe a bounded staleness window until the drainer catches up.
Observability: `ai_memory_age_projection_{pending_depth,failed_total,quarantined_total}`.
Resolved via `AppConfig::resolve_storage()` (env > `[storage].age_projection_mode`
> compiled `sync`).

### Connection pool

The postgres adapter uses sqlx's connection pool. The defaults are
min=2, max=16, with a 30-second connection-acquire timeout. For
high-fanout multi-tenant deployments, raise `max` to 32-64; for
single-daemon deployments the defaults are appropriate. Pool sizing and
the acquire timeout are exposed via three env vars (each resolved by
`AppConfig::resolve_pg_pool()`, env > `[storage]`-adjacent config field
> compiled default):

| Env var | Default | Effect |
|---|---|---|
| `AI_MEMORY_PG_POOL_MAX` | `16` (`DEFAULT_MAX_CONNECTIONS`) | `PgPoolOptions::max_connections` ceiling |
| `AI_MEMORY_PG_POOL_MIN` | `2` (`DEFAULT_MIN_CONNECTIONS`) | `PgPoolOptions::min_connections` warm floor |
| `AI_MEMORY_PG_ACQUIRE_TIMEOUT_SECS` | `30` (`DEFAULT_ACQUIRE_TIMEOUT_SECS`) | `PgPoolOptions::acquire_timeout`, whole seconds |

Non-positive / unparseable values fall through to the compiled default.

## Troubleshooting

### AGE not installed

A missing `age` extension is non-fatal — `ai-memory schema-init`
completes, reports `age_projection_created: false` in its `--json`
output, and the daemon serves KG queries through the recursive-CTE
fallback. Install AGE (see "Install" above) and re-run `schema-init`
to enable the Cypher path. The `vector` extension is **not** optional
— pgvector is required for embeddings, and its absence aborts the
bootstrap.

### Old postgres schema version detected

If you're pointing at a v0.7-alpha postgres database (schema v15),
run `ai-memory schema-init --store-url postgres://…` with a current
(v0.9.0) binary — opening the store applies the upgrade ladder to v78
idempotently. (See `migration-v0.7.0-postgres.md` for the full
migration guide.)

### "could not find parameter $N" against a Cypher query

This is the historical AGE 1.5.0 + PG 16 binding quirk mentioned above
(AGE 1.8.0 on PG 18 is unaffected). ai-memory's production code never
hits it — if you see it, you're running a custom psql probe. Use the
AGE-recommended SQL-function shape:

```sql
SELECT * FROM cypher('memory_graph', $$
  MATCH (a)-[r:RELATED_TO]->(b)
  WHERE a.id = $node_id
  RETURN b
$$, $$ {"node_id": "abc123"} $$) AS (b agtype);
```

### "permission denied for schema ag_catalog"

The `aimemory` role needs `USAGE` on `ag_catalog`. The "Database
setup" section above grants it; if you bootstrapped by hand, run
`GRANT USAGE ON SCHEMA ag_catalog TO aimemory;` as the postgres
superuser.

### Recall scores differ between sqlite and postgres

If you observe this, file an issue and reference
`tests/recall_scoring_parity.rs` (Wave 1 Stream A). The contract is
that the same query returns the same top-K with the same per-factor
score breakdown within FP tolerance. Drift is a regression — the
parity test is the gate that prevents it.

## What's in scope vs out of scope (v0.7.0)

| | sqlite | postgres |
|---|---|---|
| Live daemon | ✓ (default) | ✓ (Wave 3) |
| Schema parity | v78 | v78 (`CURRENT_SCHEMA_VERSION` pinned in lockstep) |
| `link()` | ✓ | ✓ (Wave 1 Stream A) |
| `register_agent()` | ✓ | ✓ (Wave 1 Stream A) |
| Recall 6-factor scoring (SAL `search`) | ✓ | ✓ (Wave 1 Stream A) |
| `kg_query` / `kg_timeline` / `kg_invalidate` / `find_paths` | CTE | AGE Cypher (CTE fallback) — sqlite-bound HTTP handlers in v0.7.0; trait routing in v0.7.x |
| HTTP CRUD on SAL trait (Wave-3 subset) | ✓ | ✓ (8 endpoints — see table above) |
| HTTP read paths (agents/stats/namespaces/taxonomy/archive/entities/inbox/subs) | ✓ | ✓ (Wave-3 Continuation — Phase 4 + 5) |
| HTTP KG handlers (kg_query/kg_timeline/kg_invalidate) | ✓ | ✓ (Wave-3 Continuation — Phase 5) |
| HTTP federation push/pull (sync/push, sync/since) | ✓ | ✓ (Wave-3 Continuation 2 — Phase 8) |
| HTTP audit chain emit + cross-restart sequence persistence | ✓ | ✓ (Wave-3 Continuation 2 — Phase 9) |
| HTTP full hybrid recall pipeline (FTS + pgvector + adaptive blend + touch) | ✓ | ✓ (Wave-3 Continuation 2 — Phase 10) |
| HTTP governance write paths (pending decide, namespace standard) | ✓ | ✓ (Wave-3 Continuation 2 — Phase 11) |
| HTTP full governance pipeline (multi-vote consensus + approver_type + inheritance walk on writes) | ✓ | ✓ (Wave-3 Continuation 3 — Phase 20) |
| HTTP forget / consolidate / contradictions / notify / gc / import / export / archive write paths | ✓ | ✓ (Wave-3 Continuation 3 — Phase 13/14/15/16/17/18/19) |
| `execute_pending_action` payload-replay on Approved | ✓ | sqlite-only — postgres returns `{approved: true, executed: false}`; caller re-issues underlying write |
| Federation fanout subcollections (archive / restore / pending-decision broadcast) | ✓ | sqlite-only fed-tracker state |
| Migration tool both directions | ✓ | ✓ |
| `schema-init` CLI | n/a (auto-create) | ✓ (Wave 1 Stream B) |
| `--store-url <URL>` flag on `serve` | ✓ (sqlite://) | ✓ (postgres://, postgresql://) |
| `--db` and `--store-url` mutual exclusion | ✓ (Wave 3) | ✓ (Wave 3) |
| `/api/v1/capabilities.storage_backend` | ✓ → `"sqlite"` | ✓ → `"postgres"` |
| Cross-backend live replication | ✗ | ✗ (v0.7.1+) |

## References

- Apache AGE 1.8.0 docs: https://age.apache.org/
- pgvector 0.8.6 docs: https://github.com/pgvector/pgvector
- ai-memory v0.7.0 release notes: [`v0.7.0/release-notes.md`](v0.7.0/release-notes.html)
- A2A campaign Pages: https://alphaonedev.github.io/ai-memory-a2a-v0.7.0/
- Adapter-selection design: [`RUNBOOK-adapter-selection.md`](RUNBOOK-adapter-selection.html)
- Migration runbook: [`migration-v0.7.0-postgres.md`](migration-v0.7.0-postgres.html)
- F6 issue (in-flight Wave 1 closure): https://github.com/alphaonedev/ai-memory-mcp/issues/646
