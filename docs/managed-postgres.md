---
layout: doc
title: Managed / non-superuser Postgres
---
# Managed / non-superuser Postgres (CloudNativePG, RDS, Cloud SQL)

ai-memory's Postgres adapter requires the **pgvector** extension (the certified enterprise-federation tier pins PostgreSQL 18.6 + Apache AGE 1.8.0 + pgvector 0.8.6). On managed Postgres the application account is usually **not a superuser**, and some images do not ship pgvector at all. This page explains exactly what happens, why, and the one-time step that makes it work.

## The facts (verified live on the native tier, 2026-08-26)

- **pgvector is not a "trusted" extension** (`vector.control` carries no `trusted` line; neither does `age.control`). A non-superuser role — even the *owner* of the database with `CREATE` privilege — cannot run `CREATE EXTENSION vector`: `ERROR: permission denied to create extension "vector" — HINT: Must be superuser` (SQLSTATE `42501`).
- An image without the extension files reports `ERROR: extension "vector" is not available` (SQLSTATE `0A000`).
- In either case ai-memory's bootstrap **refuses to start** (`schema-init` exit 1, `serve` exit 75). That refusal is deliberate — the daemon never silently degrades its storage. Issue #3264 turns the bare driver string into a classified message that names the remedy and adds the same check to `doctor`, `schema-init --json` and the enterprise-federation posture report.
- `CREATE EXTENSION IF NOT EXISTS vector` on a database where the extension **already exists** is a privilege-free `NOTICE … already exists, skipping` for any role. That is the whole trick.

## The one-time step

Run once, **as a superuser**, in the ai-memory database:

```sql
CREATE EXTENSION IF NOT EXISTS vector;
CREATE EXTENSION IF NOT EXISTS age;                      -- optional: knowledge-graph layer
GRANT USAGE ON SCHEMA ag_catalog TO <your_app_role>;     -- only if you created age
```

Then start ai-memory as the ordinary application role. Verified result with a `NOSUPERUSER` role: `schema-init` exit 0 — `extensions: [age, plpgsql, vector]`, `schema_version: 90`, `memories.embedding vector(384)`, HNSW index present, daemon stays up, `kg_backend = age`. No code changes, no configuration flags.

| Platform | Where the superuser step goes |
|---|---|
| CloudNativePG | `spec.bootstrap.initdb.postInitApplicationSQL`, or the `Database` custom resource's `extensions` list; the Cluster image must bundle pgvector (the stock `ghcr.io/cloudnative-pg/postgresql` image does **not**) |
| Amazon RDS / Aurora | connect as `rds_superuser` and run the statements |
| Google Cloud SQL | run as the `postgres` (cloudsqlsuperuser) account |
| Self-managed / Docker | `deploy/docker-1461/Dockerfile.pg-age-vector` (issue #1065) builds an image with AGE + pgvector; `deploy/enterprise-federation-repro/initdb/01-extensions.sql` shows the pre-create |

## Why the AGE grant matters

With `age` installed but without `USAGE` on `ag_catalog`, `schema-init` reports `age_projection: skipped` while the daemon still advertises `kg_backend = age` (its probe only looks at `pg_extension`). Grant the schema usage and re-run `schema-init`: `age_projection: created`. #3264 adds a preflight row for this too.

## What ai-memory will not do

It will not fall back to a pgvector-less storage mode. A proposal to store embeddings as raw bytes and score in-process (PR #3260) was declined after a 3×7 adversarial vote and a live assessment: any first-boot error would have silently and permanently switched the on-disk format and dropped eight correctness/data-integrity protections. See the [PR #3260 audit record](audit/pr-3260-3x7-vote-and-nhi-assessment-2026-08-26.md).

## Related

- [`postgres-age-guide.md`](postgres-age-guide.md) — the full Postgres + AGE guide ("Database setup", troubleshooting)
- [Enterprise deployment](enterprise.html) · [Enterprise-federation certification](https://github.com/alphaonedev/ai-memory-mcp/blob/release/v1.0.0/docs/compliance/ENTERPRISE-FEDERATION-CERTIFICATION.md) · [Learn · Track 3 §9](learn/engineers.md)
- Issues: #3264 (classified diagnostic + preflight), #2433 (bootstrap creates `vector` but not `age`), #1065 (images without pgvector)
