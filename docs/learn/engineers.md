---
layout: doc
title: Learn ai-memory — for engineers, architects & scientists
---
# Learn ai-memory · Track 3 — for engineers, architects, scientists

*A structured path through the mechanism. Each module names the concept,
the guarantee, and the reference page that carries the normative detail.
Everything here is tested or gated in the repository; nothing is aspirational
unless marked so.*

## Module 0 — Shape of the system

- **One Rust binary, three surfaces:** an MCP server over stdio (what
  assistants use), an HTTP REST API (`/api/v1/*`, what fleets and shims use),
  and a CLI (operators). Same store, same governance, same identity model.
- **Two storage backends behind one Storage Abstraction Layer (SAL):**
  SQLite with FTS5 (default, zero dependencies, single file) and
  PostgreSQL + Apache AGE + pgvector (multi-writer, graph-native, the
  certified enterprise tier). Parity between the two is a first-class,
  tested property. See [data flow](../data-flow.html) and
  [postgres + AGE guide](../postgres-age-guide.md).
- **Local-first, model-neutral:** embeddings and summaries come from a
  pluggable provider (local MiniLM by default; hosted providers optional);
  egress can be pinned to loopback.

## Module 1 — Data model

- `memories`: id, namespace, tier (short/mid/long), kind (observation,
  decision, instruction, goal, plan, step, persona, …), title/content, tags,
  metadata (agent provenance, attestation level, write signature), confidence
  with derivation signals, lifecycle state, bitemporal validity, a content
  identifier (CID) for integrity, and an embedding stamped with its
  **embedding space** (model fingerprint) so vectors from different models
  are never compared — [schema](../schema.html), [types](../types.html).
- `memory_links` with a closed relation taxonomy (derives_from, contradicts,
  supersedes, …) forming a **knowledge graph**; on Postgres the graph is
  projected into Apache AGE for Cypher traversal, with a recursive-CTE
  fallback — [knowledge graph](../knowledge-graph.html), [hierarchies](../hierarchies.html).
- `signed_events`: an append-only, hash-chained, Ed25519-signed ledger of
  state mutations (writes, governance refusals, coordination ops) —
  [lifecycle](../lifecycle.html), [archival](../archival.html).

## Module 2 — Recall

Hybrid retrieval: keyword (FTS5 / `tsvector`) fused with semantic
nearest-neighbour (in-process cosine on SQLite; pgvector HNSW `<=>` on
Postgres), gated by a cosine floor, optionally re-ranked by a cross-encoder,
with adaptive weighting by content length, reflection boosts, tier and
freshness decay, and a token budget. The recall path enforces visibility
(private scopes, inbox carve-outs, author binding), point-in-time validity
(`valid_at`), and the embedding-space gate — the same predicate set on both
backends. See [performance](../performance.html) and [memory tiers](../memory-tiers.html).

## Module 3 — Identity, attestation, provenance

Agents are Non-Human Identities with Ed25519 keypairs; a write may be
required to carry a signature over its canonical fields (`agent_attested`),
bound to a registered public key; sub-key certificates support per-instance
keys under a principal root. The daemon itself has a signing identity for
audit leaves. Unsigned writes are refused under the strict posture.
[agent identity](../agent-identity.html) · [attestation](../attestation.html) · [zero-touch trust](../zero-touch-trust.html).

## Module 4 — Governance

Rules + modes + hooks resolve to a single decision per action; pre-write
hooks are substrate-authoritative (the store refuses, not just the client);
refusals are chain-logged. Namespaces can be governed (owner, quota,
approval). [governance atlas](../governance.html) · [`AI_DEVELOPER_GOVERNANCE.md`](../AI_DEVELOPER_GOVERNANCE.md).

## Module 5 — Federation and coordination

- **Federation:** peers exchange memories over mTLS with enrollment, per-write
  content signatures, nonces, namespace scoping and policy-currency checks;
  peer attestation scopes what each peer may send. The enterprise posture is
  machine-checked by `ai-memory doctor --posture enterprise-federation` and
  can be armed as a boot gate. [enterprise deployment](../enterprise.html) ·
  [certification](https://github.com/alphaonedev/ai-memory-mcp/blob/release/v1.0.0/docs/compliance/ENTERPRISE-FEDERATION-CERTIFICATION.md).
- **Coordination substrate (v0.8+):** actions (a dependency DAG with a state
  machine), leases (single-holder TTL claims), signals (signed inter-agent
  messages), checkpoints (attested gates) and routines (frozen, replayable
  plans) — all chain-logged. [A2A messaging](../a2a-messaging.html) ·
  [coordination](../coordination/).

## Module 6 — Operating it

- `ai-memory doctor` (install/DB/wiring checks, posture reports),
  `schema-init` (Postgres bootstrap with a JSON report), migrations with a
  version ladder and fail-closed downgrade refusal, backups/exports, curator
  daemons (auto-tag, consolidate, contradiction detection, reflection).
- Postgres specifics that bite in production: pgvector is **not a trusted
  extension** — a superuser pre-creates it once, then the ordinary role runs
  the daemon ([managed Postgres](../managed-postgres.md)); AGE needs
  `USAGE` on `ag_catalog`.
- [production deployment](../production-deployment.md) · [INSTALL](../INSTALL.md) · [operator page](../audience/operator.html).

## Module 7 — Extending it

Python and TypeScript SDKs, OpenAI/Anthropic "shims" that record
conversation turns transparently, the HTTP API for custom clients, hooks for
policy integration. [developer page](../audience/developer.html) ·
[integrations](../integrations.html) · [feature matrix](../feature-matrix.html).

## Module 8 — The engineering discipline (why you can trust the above)

- **Fail-closed by construction.** Missing prerequisites abort boot with a
  classified reason; storage never silently degrades. A worked example — an
  external proposal to auto-fall back to a pgvector-less storage mode, and
  why it was declined — is in the
  [PR #3260 audit record](../audit/pr-3260-3x7-vote-and-nhi-assessment-2026-08-26.md).
- **Claims are gated.** CI jobs verify that documented numbers, symbols,
  paths, CI-job names and capacity/benchmark claims match the code and the
  single sources of truth; required checks are themselves proven sound by a
  gate. [engineering discipline](../engineering-discipline.html).
- **Supply chain and contribution controls.** Signed commits, SHA-pinned
  actions, fork code kept off self-hosted runners, external PRs gated by
  explicit human approval — [contributing & security controls](../contributing-external.md).
- **Adversarial self-review.** Consequential decisions go through
  multi-agent adversarial votes with published records; findings become
  issues that are fixed, tested and closed with evidence.

## Module 9 — From one agent to a swarm / hive: the certified enterprise-federation configuration

This module takes the mechanism to its full extent: many agents, many
nodes, one attested memory fabric. It is the configuration that carries the
v1.0.0 **enterprise-federation certification**, so every element below has a
posture check, a test, or a published evidence bundle behind it.

### 9.1 The progression

| Stage | Topology | What changes |
|---|---|---|
| Singleton | one assistant, one SQLite file | Tracks 1–2 |
| Multi-agent node | several agents, one daemon, one store | namespaces, governance, attestation on |
| Cluster | multi-writer store, many daemons | **PostgreSQL + Apache AGE + pgvector** tier; graph projected into AGE; HNSW recall |
| Swarm (T4) | data-centre scale, coordination substrate in use | actions/leases/signals/checkpoints/routines drive agent-to-agent work — [T4](../architectures-t4.html) |
| Hive (T5) | federated clusters, global | peer federation with enrollment, signatures, nonces, scoped attestation — [T5](../architectures-t5.html) |

Certified operating scope for the top stages: **500–1000-agent clusters,
composed in 500-agent blocks**, within the documented peer-federation
ceiling — [certification §1 and §6](https://github.com/alphaonedev/ai-memory-mcp/blob/release/v1.0.0/docs/compliance/ENTERPRISE-FEDERATION-CERTIFICATION.md).

### 9.2 The data tier: PostgreSQL 18.6 + Apache AGE 1.8.0 + pgvector 0.8.6

- **Why this triple:** multi-writer durability and strong consistency
  (Postgres), native graph traversal of `memory_links` via Cypher (AGE) with
  the CTE fallback for parity, and true nearest-neighbour semantic recall
  over an HNSW index (pgvector `<=>`). The daemon detects AGE at connect and
  advertises `kg_backend = age`; it **requires** pgvector and refuses to boot
  without it (fail-closed; never a silent byte-storage fallback — see the
  [PR #3260 record](../audit/pr-3260-3x7-vote-and-nhi-assessment-2026-08-26.md)).
- **Provisioning facts you must know:** pgvector and AGE are not *trusted*
  extensions, so a superuser creates them once and grants `USAGE ON SCHEMA
  ag_catalog` to the application role; the daemon then runs as an ordinary
  LOGIN role — [managed Postgres](../managed-postgres.md), [postgres + AGE guide](../postgres-age-guide.md).
- **Encrypted link to the tier:** the DSN uses `sslmode=verify-full` with a
  client certificate (mTLS to Postgres); the posture check reads this off the
  resolved DSN. At-rest for Postgres is a *compensating* control: the operator
  attests volume/tablespace/TDE encryption (`AI_MEMORY_PG_AT_REST_ATTESTED`).

### 9.3 Encryption in transit — all three legs

1. **Client → daemon:** the HTTP API is served over TLS with an **mTLS client
   allowlist** (only enrolled client certificates are admitted); MCP clients
   reach it through a proxy that presents its client certificate.
2. **Daemon → Postgres:** `sslmode=verify-full` + client cert (above).
3. **Daemon ↔ peer daemons (federation):** TLS with server-certificate
   **pinning** (a `<host> <sha256>` pin file), peer enrollment, per-write
   Ed25519 content signatures, nonces, push-namespace scoping and a
   policy-currency requirement; `AI_MEMORY_FED_CERT_PEER_BINDING=enforce`
   binds each peer to its certificate. Cleartext peers are refused.

### 9.4 Attestation, end to end

Every agent in the swarm holds an Ed25519 keypair; registration binds the
public key; every write carries a signature the daemon verifies
(`agent_attested`), and the daemon's own audit key signs the append-only
`signed_events` chain so federation supersede leaves are signed, never bare.
Witness / recorder / judge / stopper roles have **separate** keys
(role separation), and identity lineage is required for sub-keys. Unsigned
writes are refused with `403 ATTESTATION_FAILED`. [attestation](../attestation.html) ·
[agent identity](../agent-identity.html) · [zero-touch trust](../zero-touch-trust.html).

### 9.5 Batman mode — full-spectrum write-time investment

"Pay at write time, read for free." Batman-**capable** is the default: the
transforms exist but are off. Batman-**active** turns on, in the write path,
online dedup, synchronous atomise-before-embed, multi-step ingest and
fact-provenance stamping — six cognitive transforms before a row hits SQL —
plus freshness decay / shadow mode and per-namespace auto-classification,
with the curator running the matching background sweeps. The activation is
seven explicit steps, verified in one command block, and made reboot-safe;
it can be stepped back to capable. [Batman mode](../batman-active-mode.html).
In a swarm this is what keeps a million writes from becoming a million
near-duplicates.

### 9.6 The certified posture, machine-checked

`ai-memory doctor --posture enterprise-federation` renders every control
(security profile `asi-hard` with its pinned knobs, peer enrollment,
signatures, nonces, namespace scope, trust domain, peer fingerprints, peer
attestation without allow-all globs, permissions `enforce`, at-rest control,
https-only peers, append-only audit spine with a signing key, policy
currency, escalation producer) as PASS/FAIL with a remediation line, and
**exits non-zero on any deviation**. Arming
`AI_MEMORY_REQUIRE_ENTERPRISE_FEDERATION_POSTURE=1` turns that into a **boot
gate**: the daemon refuses to start if any control regresses. The
certification document records the exact PASS/FAIL expectations per leg and
the removal-proof harness that shows each control is load-bearing.

### 9.7 Standing it up, reproducibly

The committed kit `deploy/enterprise-federation-repro/` (`gen-certs.sh`,
`initdb/`, `repro.sh`, `seed-corpus.sh`, `verify.sh`) provisions the exact
substrate the audit used — certificates, the pg + AGE + pgvector tier over
TLS, the seed corpus, the posture env, the mTLS daemon — and re-runs the
verification. Narrated walkthrough:
[enterprise-federation-repro](https://github.com/alphaonedev/ai-memory-mcp/blob/release/v1.0.0/docs/compliance/enterprise-federation-repro.html).
Operational runbook order: keys → tier (superuser pre-create) →
`schema-init --embedding-dim N` → posture (must be all-PASS) → `serve` with
`--tls-cert/--tls-key/--mtls-allowlist` → enroll agents and bind keys →
enroll peers.

### 9.8 Worked, dated evidence

On 2026-08-26 the current `release/v1.0.0` was built and booted in exactly
this configuration on the project's native tier, driven by an AI NHI through
the MCP proxy: posture 20/20 PASS under the armed gate, signed writes
accepted and unsigned refused, HNSW-indexed semantic recall, AGE projection
live. The record, including the three failure modes that were reproduced on
purpose, is the [PR #3260 audit record](../audit/pr-3260-3x7-vote-and-nhi-assessment-2026-08-26.md).

## Suggested reading order

1. [at a glance](../at-a-glance.html) → 2. [data flow](../data-flow.html) →
3. [schema](../schema.html) → 4. [attestation](../attestation.html) →
5. [governance](../governance.html) → 6. [postgres + AGE guide](../postgres-age-guide.md) →
7. [enterprise deployment](../enterprise.html) → 8. [certification](https://github.com/alphaonedev/ai-memory-mcp/blob/release/v1.0.0/docs/compliance/ENTERPRISE-FEDERATION-CERTIFICATION.md) → 9. [Batman mode](../batman-active-mode.html) + [repro kit](https://github.com/alphaonedev/ai-memory-mcp/blob/release/v1.0.0/docs/compliance/enterprise-federation-repro.html) →
9. the source: [github.com/alphaonedev/ai-memory-mcp](https://github.com/alphaonedev/ai-memory-mcp).
