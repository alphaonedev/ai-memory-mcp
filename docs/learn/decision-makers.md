---
layout: doc
title: Learn ai-memory — for decision makers
---
# Learn ai-memory · Track 2 — for C-level decision makers

*For executives, directors and budget owners. Each section is mapped to a
decision you will have to make. Numbers and guarantees quoted here are the
ones the project publishes and gates in its repository; where something is
scoped or not yet covered, this page says so.*

## Decision 1 — Do we need "AI memory" at all?

**What you are buying.** AI assistants and agents have no continuity: every
session starts from nothing, so people re-explain context, agents repeat work,
and nothing an agent learns compounds. A memory substrate is the layer that
makes AI work **cumulative** — across sessions, across assistants, across
teams — while keeping a record of what was learned, by whom, and on what
basis.

**What ai-memory is.** A single self-hosted, open-source (Apache-2.0)
component that any MCP-capable AI can use. It runs from a laptop to a
multi-node cluster with the *same binary*; the default is a local file
database with no cloud dependency. See [for everyone](../for-everyone.html)
for the picture by organisation size.

**What it is not.** Not a hosted SaaS, not a model, not a vector database
you have to build an application around, and not a place where vendor
telemetry leaves your perimeter.

## Decision 2 — Is it safe enough for our data?

The controls are designed for regulated environments and are enforced in
code, not policy documents:

- **Local-first and model-neutral.** Data stays where you run it; the LLM
  provider used for embeddings/summaries is explicit and can be pinned to
  loopback-only (no egress).
- **Identity and attestation.** Every agent has a cryptographic identity
  (Ed25519); writes can be required to carry a signature, so provenance is
  unforgeable and "which agent wrote this" is always answerable. See
  [agent identity](../agent-identity.html) and [attestation](../attestation.html).
- **Governance.** Rules, modes and hooks decide what an agent may store, in
  which namespace, under what approval; refusals are logged. See
  [governance](../governance.html).
- **Tamper-evident audit.** State changes append to a signed hash chain; an
  append-only mode makes the chain the source of truth.
- **Encryption at rest** (SQLCipher build) and TLS/mTLS in flight.
- **Fail-closed defaults.** v1.0.0's program was "defaults stop lying":
  security knobs that used to ship off or non-functional now ship on, and
  the daemon refuses to start rather than run degraded (a live example is in
  [managed Postgres](../managed-postgres.md)).
- **Independent-style review.** The project reviews itself adversarially
  (multi-agent votes, red-team issues, published audit records) and gates
  every published claim in CI. See [engineering discipline](../engineering-discipline.html)
  and the [decision-maker page](../audience/decision-maker.html).

## Decision 3 — At what scale, and with what assurance?

- **Certified scope (v1.0.0):** the enterprise-federation configuration —
  PostgreSQL + Apache AGE + pgvector data tier, mTLS, attestation, encryption —
  is certified for **500–1000-agent clusters, composed in 500-agent blocks**,
  with a documented peer-federation ceiling. Read the certification, including
  its §6 "not covered" list, before you bet on anything outside that scope:
  [Enterprise-federation certification](https://github.com/alphaonedev/ai-memory-mcp/blob/release/v1.0.0/docs/compliance/ENTERPRISE-FEDERATION-CERTIFICATION.md).
- **Deployment postures:** from a single laptop to multi-data-centre
  federations — [architectures](../architectures.html) and
  [enterprise deployment](../enterprise.html).
- **Cost model:** open source, runs on commodity hardware or your existing
  Postgres estate; the cost is operations and the LLM provider you choose.
  The [decision-maker page](../audience/decision-maker.html) walks through
  "what it costs to run".

## Decision 4 — How do we govern people and agents contributing to it?

The project publishes how it is developed and what it accepts:

- Single accountable authority for merges, AI agents acting under it,
  every commit signed, external contributions welcome but gated at the merge
  boundary by an explicit human approval — see
  [Contributing & security controls](../contributing-external.md).
- Public audit records of consequential decisions, e.g. the
  [PR #3260 record](../audit/pr-3260-3x7-vote-and-nhi-assessment-2026-08-26.md)
  (an external proposal declined on data-integrity grounds, with the
  reporter's real need turned into a first-party fix).

Adopt the same posture internally: name the accountable owner, require
signed changes, keep an audit trail, and treat text from outside the trust
boundary as data rather than instructions to your agents.

## Decision 5 — What should we ask before signing off?

1. Which data tier, and who holds the superuser? (Managed Postgres needs a
   one-time superuser step — [managed Postgres](../managed-postgres.md).)
2. Which LLM provider sees our text, for what, and is loopback-only viable?
3. Which agents get write access, in which namespaces, with what approvals?
4. Is the deployment inside the certified scope? If not, what is the plan?
5. Who owns backups, key custody, and the audit chain?
6. How will we measure value — re-explanation time, repeated work, recall
   precision, incident count?

## Where to go next

- [Decision-maker page](../audience/decision-maker.html) — value, risk, cost, roadmap in depth.
- [At a glance](../at-a-glance.html) — the whole surface on one page.
- [Track 3](engineers.md) — hand this to your architects.
