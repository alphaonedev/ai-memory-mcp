---
layout: doc
---
# Architecture Decision Records (ADR)

This directory holds the **formal, numbered Architecture Decision Records**
for ai-memory: one file per ratified decision, each capturing the context,
the decision, its consequences, and the alternatives that were rejected.

An ADR is the durable, reviewable home for a decision that (a) changes a
public contract or on-disk / signed-bytes representation, (b) is
hard-to-reverse once shipped, or (c) resolves a genuine crossroads between
≥2 viable designs. For new decisions, apply the `CLAUDE.md` crossroads
threshold and the development epic prompt §5 1x3 vote when required, cited as
`3-agent vote (6def5ab6)`, so the tally and decision memory travel with the ADR.
The earlier 2×5 procedure was superseded on 2026-10-10; existing ADR vote
records retain their original ballots and citations.

> **Note on numbering.** These `docs/adr/ADR-00N-*.md` records are the
> v1.0.0-era formal ADR series. The three earlier root-level
> `docs/ADR-000N-*.md` files (quorum replication, KG schema, KG
> invalidation) predate this directory and are retained in place for
> history; new ADRs land here.

## Index

| ADR | Title | Status |
|-----|-------|--------|
| [ADR-001](ADR-001-uuid-cid-dual-identity.md) | UUID / cid dual identity (C dual-binding) — `uuid` = storage/FK/LWW authority, `cid` = signed content-identity; the v2 envelope signs the cid-genesis six-tuple, never the `uuid` | **ACCEPTED + IMPLEMENTED** |
| [ADR-002](ADR-002-fed-rq-02-equivocation-runtime-deferral.md) | FED-RQ-02 equivocation runtime + epoch-manifest-doc federation deferred to v1.x — ship the frozen format + offline verifier only; FED-RQ-03 policy refuse-stale is green; no "federation mature" / "equivocation shipped" claim (C8) | **ACCEPTED** |
| [ADR-003](ADR-003-sdk-python-tls-verify-enforcement.md) | Python SDK TLS verification: exact-type predicate plus post-handshake enforcement; ratifies the CERT_OPTIONAL refusal and per-request hook of 785838d82 | **ACCEPTED + IMPLEMENTED** |

## Statuses

- **Proposed** — design ratified, implementation pending.
- **Accepted** — decision adopted; may or may not be fully implemented yet.
- **Accepted + Implemented** — decision adopted and the code has landed
  (commits cited in the ADR body).
- **Superseded by ADR-NNN** — replaced by a later record.

## Adding an ADR

1. Copy the shape of an existing record (front-matter `layout: doc`, then
   `# ADR-NNN — Title`, `Status:` / `Date:` / `Author:` / `Decision record:` /
   `Related:` / `Spec SSOT:`, then **Context / Decision / Consequences /
   Alternatives rejected**).
2. Number it as the next free `ADR-00N`.
3. Cite the decision memory and, when development epic prompt §5 (docs/v1.0.0/AI-NHI-V1.0.0-DEVELOPMENT-EPIC-PROMPT.md) requires a vote, its workflow id
   plus `3-agent vote (6def5ab6)`; retain earlier vote citations for historical
   decisions. Once the code lands, add the implementing commit SHAs.
4. Add a row to the Index table above.
