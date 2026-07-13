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
≥2 viable designs. ADRs here are minted from the recorded 2×5 adversarial
decision votes (crossroads policy `4d3ea1c5`) so the vote tally and the
decision memory travel with the document.

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
3. Cite the decision memory + the 2×5 vote workflow id, and — once the code
   lands — the implementing commit SHAs.
4. Add a row to the Index table above.
