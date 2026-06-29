# v0.8.1 — DigitalOcean operational evidence: PostgreSQL 16 + Apache AGE + pgvector

> **Status: 3 ROUNDS GREEN + AI-NHI dogfood GREEN.** The `release/v0.8.1`
> `--features sal-postgres` binary was deployed to a live DigitalOcean droplet
> (NYC3, `s-2vcpu-4gb`) backed by **real PostgreSQL 16 + Apache AGE 1.6.0 +
> pgvector 0.6.0** — the SAL postgres+AGE path, NOT sqlite — and exercised over
> its HTTP API (SSH-tunnelled to the loopback daemon) plus direct `psql`
> substrate verification. Torn down to **zero droplets** immediately after
> (`terraform destroy` — 3 destroyed; ~30 min, ~$0.02). Operator-authorized
> spend (2026-06-29, "approved yes — make it happen").

## #1842 fixed — the cloud-init now provisions postgres + pgvector + AGE
The prior `cloud-init-memory.yaml.tpl` installed `postgresql-16` but **never
installed pgvector and never built Apache AGE** (AGE is source-only; `CREATE
EXTENSION age` failed) and used the invalid `--bind` flag. The corrected
template + the verified provisioning recipe:
- `apt install postgresql-16 postgresql-16-pgvector postgresql-server-dev-16` + AGE build deps (`flex bison libreadline-dev zlib1g-dev`).
- **Build Apache AGE from source** against pg16 (`git clone -b PG16 apache/age && make && make install`).
- `shared_preload_libraries = 'age'` + restart postgres.
- `CREATE EXTENSION vector; CREATE EXTENSION age;` on the `aimemory` db.
- `ai-memory schema-init --store-url postgres://…` → **32 tables, extensions `[age, plpgsql, vector]`, schema_version 71, embedding_dim 384, AGE graph `memory_graph` created**.
- `serve --host 127.0.0.1 --port 9077 --store-url postgres://…` (correct flags).

Operational note (binary): the daemon must be built `--features sal-postgres`,
and the embed model must match the pgvector column dimension — pinning
`AI_MEMORY_EMBED_MODEL=all-MiniLM-L6-v2` (384-d) aligned the daemon, the local
MiniLM embedder, and the `vector(384)` column (a 768-vs-384 mismatch otherwise
503s every store: *"expected 768 dimensions, not 384"*).

## 3 rounds — ALL GREEN
Each round ran 14 checks against the postgres+AGE+pgvector substrate:

```
ROUND 1: GREEN ✅    ROUND 2: GREEN ✅    ROUND 3: GREEN ✅
  ✅ daemon reachable (postgres-backed)
  ✅ store -> 201 (postgres write + pgvector 384-d embedding)
  ✅ G29 secret-screen REFUSED a credential (400) on postgres
  ✅ recall via pgvector semantic (count=1)
  ✅ search via postgres tsvector (count=1)
  ✅ link write (201)
  ✅ Apache AGE: edge projected into memory_graph (1->2)   # AGE Cypher, sync mode
  ✅ forget (200)
  ✅ G30: forgotten content no longer recalled (count=0)
  ✅ extensions present: age,vector
  ✅ memories.embedding is a pgvector column
  ✅ postgres schema_version = 71 (v0.8.1)
  ✅ AGE graph 'memory_graph' present
```

- **PostgreSQL** — all CRUD + recall + tsvector search + forget land in postgres (verified via `psql` row counts).
- **pgvector** — 384-d MiniLM embeddings stored in the `vector` column; semantic recall returns the row.
- **Apache AGE** — each `link` write projects vertices + edges into `memory_graph` (`_ag_label_vertex` 0→2, `_ag_label_edge` 0→1 per link); confirmed via Cypher-backed catalog.
- **v0.8.1 security** — G29 secret-screen (refuse) and G30 erasure (forget→recall:0) both hold on the postgres backend.

## AI-NHI dogfood — GREEN
Drove the substrate as an NHI agent's memory layer over HTTP (the postgres path
is served via HTTP; MCP stdio is sqlite-only by design):

```
DOGFOOD: GREEN ✅
  ✅ substrate live
  ✅ stored 3 working memories on postgres
  ✅ recall re-grounded the agent (count=1)
  ✅ AGE KG: links projected into memory_graph (edges=3)
  ✅ G29: a pasted AWS key was refused (400) on postgres
  ✅ G30: forgotten memory no longer recalled (count=0)
```

## Known v0.7.x gap surfaced (not a v0.8.1 defect)
`POST /api/v1/find_paths` returns **501** on the postgres-backed daemon
("endpoint not yet implemented for postgres-backed daemon" — the documented
Wave-3 SAL-trait coverage gap, `docs/postgres-age-guide.md`). The AGE graph is
still fully exercised via the `link` **write** path (Cypher projection into
`memory_graph`); only the `find_paths` **read** traversal is unported. KG reads
on postgres route through the relational recursive-CTE / `kg_query`.

🤖 Claude Code (Opus 4.8, 1M context).
