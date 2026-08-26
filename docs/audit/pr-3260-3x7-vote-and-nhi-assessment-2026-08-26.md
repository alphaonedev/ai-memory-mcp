---
layout: doc
title: PR #3260 — 3×7 vote and AI-NHI assessment record
---
# PR #3260 — 3×7 adversarial vote + AI-NHI live assessment (2026-08-26)

**Subject.** External pull request [#3260](https://github.com/alphaonedev/ai-memory-mcp/pull/3260) proposed a pgvector-less Postgres storage mode (embeddings as raw `BYTEA`, cosine in-process) triggered automatically when `CREATE EXTENSION vector` fails. Author: a first-time contributor from a fork, single unsigned commit. This record is the durable, in-repo copy of the decision; the live discussion is on the PR.

## 1. Method

1. Maintainer review of the diff and the repository state at `release/v1.0.0` (`ef22d020`), with codegraph.
2. **3×7 adversarial vote** run against the codebase with codegraph: 7 independent lenses (data-integrity, security, Postgres-DBA realism, Rust/sqlx correctness, scale, roadmap fit, governance) → 7 adversarial refuters, one per ballot, evidence required → 7 final judges. 21 agents, 606 tool calls, 3.11 M tokens, 27 minutes.
3. **Live AI-NHI assessment**: the current release was compiled (`--features sal-postgres`, then `sal-postgres,sqlcipher`) and run on the project's native PostgreSQL 18.6 + Apache AGE 1.8.0 + pgvector 0.8.6 tier in the certified enterprise-federation configuration (posture 20/20 PASS with the boot gate armed), with the assessing AI wired in through the MCP proxy over mTLS.

## 2. Tally (round 3, deciding)

| Question | Result |
|---|---|
| Underlying need legitimate | PARTIAL 7/7 — mechanism accurately described; need mis-framed |
| Must ai-memory fix/add something | PARTIAL 7/7 — a first-party fail-closed diagnostic + docs, not a storage mode |
| PR as written acceptable | NO 7/7 |
| Findings F1–F7 (space gate absent; recency window not kNN; silent sticky fail-open; unbounded scans; dimension safety lost; process-wide env mutation in test; gate failures) | CONFIRMED 7/7 each |

Round 2 mounted 91 attacks; 16 landed (all ballots stood overall). Notably, round 2 refuted the *reasoning* behind the maintainer's original F7 (the named gates would not have failed as stated); round 3 re-ran the gates and found the four actual mechanical failures (rustfmt, literal ratchet, env-var census, missing CHANGELOG). The verdict stood; the justification was replaced.

## 3. Established facts

- pgvector 0.8.6 and AGE 1.8.0 are **not trusted extensions**; a non-superuser gets SQLSTATE 42501; an image without the files gets 0A000. The daemon aborts (exit 75). Reproduced live (T1 stock Postgres without pgvector; T2 native tier, non-superuser, extension absent).
- **T3**: after a superuser pre-creates the extensions once, the same non-superuser role boots the current daemon unchanged: `schema_version 90`, `vector(384)` column, HNSW index, `kg_backend = age`. Zero code changes.
- "Mirror the AGE path" is not an accurate analogy (AGE detection is a read-only probe; nothing on disk changes).
- The BYTEA paths drop eight landed protections relative to the pgvector twins (#2167 embedding-space gate, kNN, #1834 `valid_at`, #3070 inbox carve-out, #1720 A7 author-bind, #2585 projection, #2383 scan mapper, checked cosine) and leave an unconverted `vector_dims()` site.
- Side findings: #2433 reproduced (bootstrap creates `vector` but not `age`); a non-superuser without `USAGE ON SCHEMA ag_catalog` gets `age_projection: skipped` while `kg_backend` still reports `age`.
- Signed-write path under the certified posture: three `agent_attested` writes with Ed25519 signatures and CIDs accepted; an unsigned write refused (`403 ATTESTATION_FAILED`); semantic recall (score 0.858) with the control memory excluded; query plan `Index Scan using memories_embedding_hnsw`.

## 4. Disposition

- Close #3260 without merging; adopt none of its code (design defect: fail-open, sticky on-disk downgrade inside the certified adapter; plus unsigned commit, no CLA, Sensitive-class change opened non-draft).
- The reporter's need is real → first-party issue [#3264](https://github.com/alphaonedev/ai-memory-mcp/issues/3264): fail-closed, classified `CREATE EXTENSION` diagnostic (42501 → superuser pre-create via CNPG `postInitApplicationSQL` / `Database` CR extensions / RDS `rds_superuser`; 0A000 → pgvector-bearing image, #1065), the same preflight in `doctor`, `schema-init --json` and the enterprise-federation posture (plus the `ag_catalog` USAGE row), and the [managed Postgres](../managed-postgres.md) documentation.
- **Rejected design (v1.0.0):** a pgvector-less BYTEA storage mode or any auto-fallback on `CREATE EXTENSION` failure. Any future revisit is a separate ROADMAP decision with its own vote and certification.
- Controls landed the same day (PR #3263): the external-PR operator-approval gate, self-hosted fork refusal, SHA-pinned actions, Dependabot for actions; see [contributing & security controls](../contributing-external.md).

## 5. Where it is documented

- PR #3260 comments: maintainer assessment · 3×7 notice · 3×7 header + 21 verbatim ballots/refutations/judgments · AI-NHI live assessment and course of action · plain-English synopsis · signed-write/HNSW evidence.
- Repository docs: `docs/AI_DEVELOPER_GOVERNANCE.md` §5.0.1 · `docs/contributing-external.md` · `docs/managed-postgres.md` · `docs/postgres-age-guide.md` ("Managed / non-superuser Postgres", via #3264) · `CHANGELOG.md` · this record.
- GitHub Pages: the same pages under <https://alphaonedev.github.io/ai-memory-mcp/>.
