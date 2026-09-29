# ROADMAP v1.1.0 ADDENDUM — mission-critical delivery and test-proven competitive outcomes

> **Status: ADVISED.** The operator decides adoption. This document supplements [ROADMAP-v110.md](ROADMAP-v110.md) and [ROADMAP.md §11.9](../ROADMAP.md#119-v110--the-certification-release); it does not rewrite either roadmap, authorize implementation, or change existing release commitments by itself.
>
> **Date:** 2026-09-27. Prepared from the dated audit series; the binding North Star synthesis and read-only issue refresh were completed on 2026-09-28 UTC. This is an advice date, not a claim that later evidence existed on September 27.
>
> **Provenance:** [#4055](https://github.com/alphaonedev/ai-memory-mcp/issues/4055) competitor 3×7; OpenViking 3×3; US market 3×3; competitive-advantage 3×3; North Star 3×3. All used the operator-designated **Codex gpt-6-astra high** configuration. ai-memory navigation used **CodeGraph on release/v1.0.0**, with authoritative source read through `git show origin/release/v1.0.0:<path>` and compared with code pin **`a1403c742f9d590a08b6fd170deec5f50ca8e940`**. Same-model review ballots are not independent empirical replications.

Review documents: [competitor assessment](reviews/COMPETITOR-ASSESSMENT-3x7-2026-09-27.md), [ai-memory vs OpenViking](reviews/AI-MEMORY-VS-OPENVIKING-3x3-CODE-LEVEL-2026-09-27.md), [US agent-memory market audit](reviews/US-AGENT-MEMORY-MARKET-3x3-AUDIT-2026-09-27.md). Binding inputs: North Star Part III (local evidence: `/ai-scratch/deputy/codex-pool/out/ns3x3/PART-III-NORTH-STAR-AND-V1.1.0.md`), North Star TALLY.json (local evidence: `/ai-scratch/deputy/codex-pool/out/ns3x3/TALLY.json`). Supporting audit: competitive advantages, including downgraded claims (local evidence: `/ai-scratch/deputy/codex-pool/out/adv3x3/AI-MEMORY-COMPETITIVE-ADVANTAGE-CODE-LEVEL-2026-09-27.md#5-not-real--downgraded-claims`) and its binding tally (local evidence: `/ai-scratch/deputy/codex-pool/out/adv3x3/TALLY.json`). Archive-only links are provenance inputs; the three `reviews/` links are relative to this document's intended `docs/` location.

**Decision advised:** complete the binding **41 MUST-V1.1** packages; retain **2 SHOULD-V1.1**, **11 LATER**, **1 NO**, and **15 NO-CONSENSUS** exactly as tallied. These are 70 decision rows, not 134 separate delivery commitments: the 64 source proposals absent from the tally have the ownership crosswalk in Part III §III.5 (local evidence: `/ai-scratch/deputy/codex-pool/out/ns3x3/PART-III-NORTH-STAR-AND-V1.1.0.md#iii5--should-v11-later-no-cut-and-unresolved-decisions`). A missing vote is not adoption. Every proposed acceptance gate in this addendum is **NOT RUN / UNPROVEN**. No new product benchmark or certification was performed for this document.

The observed release ref is `ada47560cc9ec4d8079239b3ca6b7338ff847344`; only two review documents differ from the designated code pin. The read-only issue census is **110 found-in-testing**, **141 ga-blocker**, **158 distinct across those labels**, and **97 open v1.1.0** issues. Labels overlap. Current reports are readiness inputs, not proof that later-branch defects exist at the pin or a comparable competitor defect-rate denominator. Source and corpus receipts (local evidence: `/ai-scratch/deputy/codex-pool/out/ns3x3/N11-evidence/source-doc-receipt.json`), issue snapshots (local evidence: `/ai-scratch/deputy/codex-pool/out/ns3x3/N11-evidence/v1.1.0.json`), defects (local evidence: `/ai-scratch/deputy/codex-pool/out/ns3x3/N11-evidence/found-in-testing.json`), blockers (local evidence: `/ai-scratch/deputy/codex-pool/out/ns3x3/N11-evidence/ga-blocker.json`).

**Any REUSE-CODE import or new dependency requires explicit operator authorization per CLAUDE.md §Sole-authority; this addendum authorizes nothing.** [Authority source](https://github.com/alphaonedev/ai-memory-mcp/blob/a1403c742f9d590a08b6fd170deec5f50ca8e940/CLAUDE.md#L2277)

---

## 1. The standard and v1.1.0 objective

The operator-designated [landing page, “The standard”](https://alphaonedev.github.io/ai-memory-mcp/), states:

> **One North Star: mission-critical.**
>
> Every gate, issue, and test is measured against one bar — that a Fortune 500 or a government could trust it with mission-critical work.
>
> **Data integrity** — No silent loss; no partial or unsigned commit.
>
> **Security** — Operator rules never bypassed; no fail-open.
>
> **Performance** — Bounded, non-DoS-able, live under contention.
>
> **Reliability** — Cross-backend parity, recoverability, no kill-switch.

| Pillar / mandate | Binding criteria |
|---|---|
| DATA INTEGRITY | **DI1** no silent loss; **DI2** no partial commit; **DI3** no unsigned commit |
| SECURITY | **SE1** operator rules never bypassed; **SE2** no fail-open |
| PERFORMANCE | **PF1** bounded; **PF2** non-DoS-able; **PF3** live under contention |
| RELIABILITY | **RL1** cross-backend parity; **RL2** recoverability; **RL3** no kill-switch |
| Co-ranked mandate | **EN1** only encrypted data in transit anywhere in the ecosystem |

EN1's normative wording is: **“only encrypted data in transit. there is to never be any unencrypted data in transit anywhere in the ai-memory architecture.”** There is no loopback, localhost, development, single-node or lab exemption. Authenticated stdio, peer-credential UDS, content-free identity frames and TLS on only the remote legs do not satisfy this literal requirement. [SECURITY.md:194](https://github.com/alphaonedev/ai-memory-mcp/blob/a1403c742f9d590a08b6fd170deec5f50ca8e940/docs/SECURITY.md#L194)

**v1.1.0 objective:** defeat the competition in **test-proven code-level facts, metrics and outcomes**, while meeting every mandatory safety contract in the declared supported boundary. A correct repair is required even when a competitor ties. A competitive claim requires a reproduced strict win; an inaccessible product remains Unmeasured. Source code, issue closure, feature counts and votes do not constitute that win. [Competitor benchmark limits](reviews/COMPETITOR-ASSESSMENT-3x7-2026-09-27.md#benchmark-evidence-is-not-a-shared-leaderboard), Part III protocol G (local evidence: `/ai-scratch/deputy/codex-pool/out/ns3x3/PART-III-NORTH-STAR-AND-V1.1.0.md#shared-test-proven-protocol-g`).

The secondary strategic anchor remains [moonshot synthesis §2](strategy/moonshot-synthesis.md#2-the-seven-properties-that-remain-load-bearing-through-asi): **M1** endpoint-resident; **M2** coherent across sessions and model generations; **M3** stoppable without silent corruption; **M4** improvable across model generations; **M5** attested with cryptographic non-repudiation; **M6** bias-displaced via a verified heterogeneous reflection boundary; **M7** LLM-agnostic at every cognitive boundary. These do not replace the four pillars or EN1. An operator-controlled recoverable stop satisfies M3; vendor entitlement disabling local custody violates RL3.

## 2. North Star scoreboard — TABLE 5 condensed

The following numbers are the binding tally, not a new rating. Scale: 0 absent in inspected scope; 1 fragmentary/documentary/optional; 2 implemented with material gaps; 3 substantial source support without full operational qualification; 4 adversarial evidence with a qualification remaining; 5 fully delivered, default-on and test-proven across the boundary. Unknown remains n/a. Totals sum known evidence, contain overlapping aliases, and do not normalize closed-vendor coverage. Part III TABLE 5 (local evidence: `/ai-scratch/deputy/codex-pool/out/ns3x3/PART-III-NORTH-STAR-AND-V1.1.0.md#iii2--table-5-four-pillar-north-star-ranking`), tally (local evidence: `/ai-scratch/deputy/codex-pool/out/ns3x3/TALLY.json`).

| System / exact tally row | DI1 | DI2 | DI3 | SE1 | SE2 | PF1 | PF2 | PF3 | RL1 | RL2 | RL3 | EN1 | TOTAL |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| ai-memory | 2 | 2 | 2 | 2 | 2 | 2 | 1 | 1 | 1 | 2 | 2 | 2 | 21 |
| KIP / LDC Labs | 2 | 2 | 0 | 2 | 2 | 2 | n/a | 2 | 2 | 2 | 3 | 1 | 20 |
| mem0 / OpenMemory | 2 | 2 | 0 | 2 | 2 | 2 | n/a | 2 | 2 | 2 | 2 | 2 | 20 |
| cognee | 2 | 1 | 0 | 2 | 2 | 2 | 2 | 2 | 1 | 2 | 2.0 | 1.5 | 19.5 |
| OpenViking | 2 | 1 | 0 | 2 | 2 | 2 | 1.5 | 2 | 1 | 2 | 2.0 | 1 | 18.5 |
| Haystack | 1.0 | 1 | 0 | 1 | 1 | 2 | 1 | 2 | 1.0 | 1 | 2.0 | 1.5 | 14.5 |

ai-memory ranks first by the supplied TOTAL, **21**; no primary criterion scores above **2**. Its narrow signed-author, capability-attenuation, identity and wake-admission mechanisms are defensible architectural advantages. They do not close the following defects. The competitive-advantage tally contains **zero NOT-REAL facets** among 182 inventoried mechanisms; the audit separately rejects inflated end-to-end guarantees. Advantage audit §§2,5 (local evidence: `/ai-scratch/deputy/codex-pool/out/adv3x3/AI-MEMORY-COMPETITIVE-ADVANTAGE-CODE-LEVEL-2026-09-27.md`).

| Criterion | Lead / trail in the supplied evidence | v1.1.0 closure / evidence |
|---|---|---|
| DI1 — 2 | Tied maximum, not universal losslessness. Mem0 ADD-only and MemPalace searchable originals expose the failed-summary gap. | P3-08/19/22; [behind table](reviews/COMPETITOR-ASSESSMENT-3x7-2026-09-27.md#where-ai-memory-is-behind); [#4091](https://github.com/alphaonedev/ai-memory-mcp/issues/4091), [#4063](https://github.com/alphaonedev/ai-memory-mcp/issues/4063). |
| DI2 — 2 | Tied maximum with KIP and others. Transactions do not make a semantic replacement safe or a fleet quorum atomic. | P3-01/14/15; advantage audit §5 (local evidence: `/ai-scratch/deputy/codex-pool/out/adv3x3/AI-MEMORY-COMPETITIVE-ADVANTAGE-CODE-LEVEL-2026-09-27.md#5-not-real--downgraded-claims`); [#4053](https://github.com/alphaonedev/ai-memory-mcp/issues/4053), [#4034](https://github.com/alphaonedev/ai-memory-mcp/issues/4034). |
| DI3 — 2 | Above OpenViking/cognee's scored record-signature support; tied maximum with Vestige and ContextLattice. Successful writes can still lack evidence. | P3-06/07/17; [US audit §6](reviews/US-AGENT-MEMORY-MARKET-3x3-AUDIT-2026-09-27.md#6-differentiators-under-adversarial-review); [#4000](https://github.com/alphaonedev/ai-memory-mcp/issues/4000), [#4021](https://github.com/alphaonedev/ai-memory-mcp/issues/4021), [#4086](https://github.com/alphaonedev/ai-memory-mcp/issues/4086). |
| SE1 — 2 | Tied maximum; OpenViking leads enterprise identity/ACL integration. Empty enrollment and private fan-out defeat blanket isolation. | P3-02/03/04; [OpenViking K07/K08](reviews/AI-MEMORY-VS-OPENVIKING-3x3-CODE-LEVEL-2026-09-27.md#identity-and-authorization--k07k08-openviking-stronger-each-33); [#4059](https://github.com/alphaonedev/ai-memory-mcp/issues/4059), [#4069](https://github.com/alphaonedev/ai-memory-mcp/issues/4069), [#4066](https://github.com/alphaonedev/ai-memory-mcp/issues/4066). |
| SE2 — 2 | Tied maximum, with unresolved policy-read/matcher/model-failure paths. No “all fail-closed” claim is earned. | P3-02/08/10, P2-35; [US gaps](reviews/US-AGENT-MEMORY-MARKET-3x3-AUDIT-2026-09-27.md#7-gaps-ai-memory-should-close); [#4043](https://github.com/alphaonedev/ai-memory-mcp/issues/4043), [#4042](https://github.com/alphaonedev/ai-memory-mcp/issues/4042), [#3986](https://github.com/alphaonedev/ai-memory-mcp/issues/3986). |
| PF1 — 2 | Tied maximum. Per-child limits do not bound aggregate fan-out, replies or retention. | P3-30/22; [behind table](reviews/COMPETITOR-ASSESSMENT-3x7-2026-09-27.md#where-ai-memory-is-behind); [#4033](https://github.com/alphaonedev/ai-memory-mcp/issues/4033), [#3287](https://github.com/alphaonedev/ai-memory-mcp/issues/3287). |
| PF2 — 1 | Trails cognee, Hindsight and other score-2 rows. Admission and quotas do not prove resistance to hostile aggregate work. | P3-29/30; Part III P3-30 (local evidence: `/ai-scratch/deputy/codex-pool/out/ns3x3/PART-III-NORTH-STAR-AND-V1.1.0.md#p3-30`); [#4089](https://github.com/alphaonedev/ai-memory-mcp/issues/4089), [#4033](https://github.com/alphaonedev/ai-memory-mcp/issues/4033). |
| PF3 — 1 | Trails OpenViking, Haystack, KIP/LDC Labs and others at 2. The recorded semantic-recall contention collapse remains a direct target. | P3-29; [#3335](https://github.com/alphaonedev/ai-memory-mcp/issues/3335), [#3341](https://github.com/alphaonedev/ai-memory-mcp/issues/3341), [#3342](https://github.com/alphaonedev/ai-memory-mcp/issues/3342); [root roadmap §11.9](../ROADMAP.md#119-v110--the-certification-release). |
| RL1 — 1 | Trails KIP/LDC Labs, mem0/OpenMemory and agentmemory rows at 2. MCP, skills, backup, graph and witness paths differ. | P3-28/27/39; [backend gaps](reviews/COMPETITOR-ASSESSMENT-3x7-2026-09-27.md#where-ai-memory-is-behind); [#4070](https://github.com/alphaonedev/ai-memory-mcp/issues/4070), [#4081](https://github.com/alphaonedev/ai-memory-mcp/issues/4081), [#3425](https://github.com/alphaonedev/ai-memory-mcp/issues/3425). |
| RL2 — 2 | Tied maximum. OpenViking packaging, cognee migration refusal and ruflo backups supply useful narrower mechanisms. | P2-04, P3-21/36/37; [behind table](reviews/COMPETITOR-ASSESSMENT-3x7-2026-09-27.md#where-ai-memory-is-behind); [#4077](https://github.com/alphaonedev/ai-memory-mcp/issues/4077), [#4082](https://github.com/alphaonedev/ai-memory-mcp/issues/4082). |
| RL3 — 2 | Trails KIP/LDC Labs at 3. Endpoint custody is real; full disconnected staging and failure behavior are unqualified. | P3-41; [US endpoint limits](reviews/US-AGENT-MEMORY-MARKET-3x3-AUDIT-2026-09-27.md#6-differentiators-under-adversarial-review); [#3991](https://github.com/alphaonedev/ai-memory-mcp/issues/3991), [#4123](https://github.com/alphaonedev/ai-memory-mcp/issues/4123). |
| EN1 — 2 | Tied maximum; OpenViking comparison favors the inspected network defaults, not universal compliance. Local inference and IPC remain gaps. | P3-11/12; [OpenViking K09](reviews/AI-MEMORY-VS-OPENVIKING-3x3-CODE-LEVEL-2026-09-27.md#encryption-in-transit--k09-ai-memory-stronger-33); [SECURITY.md](SECURITY.md#only-encrypted-data-in-transit-3705). |

**TABLE 5b — secondary anchor, condensed:** ai-memory M1=3, M2=2, M3=2, M4=2, M5=2, M6=1, M7=2; **M_TOTAL=14**. The weakest strategic claim is verified heterogeneous reflection. Model labels, different providers and different signing roles do not prove decorrelated training or errors. Independent role routing remains SHOULD; deterministic destructive clearance remains MUST. Part III TABLE 5b (local evidence: `/ai-scratch/deputy/codex-pool/out/ns3x3/PART-III-NORTH-STAR-AND-V1.1.0.md#table-5b--secondary-moonshot-ranking-evidence`), [moonshot §2.6](strategy/moonshot-synthesis.md#26-bias-displaced-through-architectural-separation-of-powers).

## 3. Reconciliation with ROADMAP-v110.md

Classification is relative to **ROADMAP-v110.md's actual workstreams**, not merely an open issue or a general North Star sentence: **ALREADY-PLANNED** means the same scope and acceptance already exist; **STRENGTHENED** raises a concrete planned bar; **NEW** has no equivalent workstream there; **RE-SCOPED** changes its boundary. Root §11.9 already supplies many certification carriers for rows marked NEW. No retained audit package is unchanged ALREADY-PLANNED: each adds a broader contract or comparative gate. The detailed gate links below are also the per-row evidence and acceptance references.

### Every binding MUST and SHOULD

| Binding ID / priority / acceptance | Reconciliation | ROADMAP-v110.md section and concrete delta |
|---|---|---|
| [P1-05](#p1-05) · MUST-V1.1 | **STRENGTHENED** | w3-boundary-signal; w8 R2/R5 — unsigned origin hints become exact revision-linked, signed GenerationRun evidence. |
| [P1-12](#p1-12) · SHOULD-V1.1 | **STRENGTHENED** | w8 R2/R3 — recorded-origin grouping and calibrated dissent; no hidden-ancestry or universal truth promise. Retains SHOULD. |
| [P2-04](#p2-04) · MUST-V1.1 | **NEW** | No power-loss workstream. Root §11.9 G2/G5 already carries [#3559](https://github.com/alphaonedev/ai-memory-mcp/issues/3559)/[#3561](https://github.com/alphaonedev/ai-memory-mcp/issues/3561); add actual lost-flush trials and ACK semantics. |
| [P2-16](#p2-16) · MUST-V1.1 | **NEW** | No pre-egress protected-span contract; w4 applicability metadata is not confidentiality. Extend [#4103](https://github.com/alphaonedev/ai-memory-mcp/issues/4103)–[#4106](https://github.com/alphaonedev/ai-memory-mcp/issues/4106). |
| [P2-31](#p2-31) · MUST-V1.1 | **STRENGTHENED** | w8 R6 — scoped record-stop becomes a durable cross-process commit fence, including hidden maintenance and signed resume. |
| [P2-34](#p2-34) · SHOULD-V1.1 | **NEW** | No full role-routing workstream. Preserve SHOULD after foundations; it does not block deterministic P2-35 clearance. |
| [P2-35](#p2-35) · MUST-V1.1 | **NEW** | w8 R2 corroboration is not a destructive decision provider. Complete [#3806](https://github.com/alphaonedev/ai-memory-mcp/issues/3806)/[#4102](https://github.com/alphaonedev/ai-memory-mcp/issues/4102) with deterministic clearance and conditional learned-judge evidence. |
| [P2-42](#p2-42) · MUST-V1.1 | **STRENGTHENED** | w5; w8 R1; Measurement — real answerer/judge plus artifact-bound, equal-budget competitor missions and safety oracles. |
| [P3-01](#p3-01) · MUST-V1.1 | **NEW** | No shared atomic apply contract. w8 no-loss constraint is insufficient; bind authority/revision/state/audit/quota/outbox. |
| [P3-02](#p3-02) · MUST-V1.1 | **NEW** | No immutable policy-epoch implementation; Compatibility fail-closed intent gains executable unavailable/absent semantics. |
| [P3-03](#p3-03) · MUST-V1.1 | **NEW** | No universal verified-principal/read capability; applicability origin checks in w4 cover a narrower authoring gate. |
| [P3-04](#p3-04) · MUST-V1.1 | **NEW** | No monotone credential revocation/freshness contract. |
| [P3-06](#p3-06) · MUST-V1.1 | **STRENGTHENED** | w8 R5 — forensic-grade ledger becomes a commit prerequisite for every admitted mutation, with role-correct signatures. |
| [P3-07](#p3-07) · MUST-V1.1 | **NEW** | w8 signed spine does not specify an independently retained completeness anchor across tail loss/restart. |
| [P3-08](#p3-08) · MUST-V1.1 | **NEW** | No failed-summary/source-retirement contract. Add revision-fenced replacement with PreserveAndDefer and searchable originals. |
| [P3-10](#p3-10) · MUST-V1.1 | **NEW** | No semantic-outcome circuit-breaker state machine; repair current model clients before provider expansion. |
| [P3-11](#p3-11) · MUST-V1.1 | **NEW** | No unified admitted-target connection capability for doctor, reembed, downloads, webhooks and export. |
| [P3-12](#p3-12) · MUST-V1.1 | **NEW** | No encrypted local IPC/inference plan. Implement literal EN1 with usable host adapters; no local exception. |
| [P3-13](#p3-13) · MUST-V1.1 | **STRENGTHENED** | w2-compact-metadata; w3 request-schema changes — preserve their wire compatibility while adding strict security DTOs and canonical round trips. |
| [P3-14](#p3-14) · MUST-V1.1 | **NEW** | No convergent bounded merge algebra. w8 shared-truth work does not establish replicated-state convergence. |
| [P3-15](#p3-15) · MUST-V1.1 | **NEW** | No durable replication operation/cursor contract. Root G4/E3/E4 and [#4101](https://github.com/alphaonedev/ai-memory-mcp/issues/4101) already carry measurement. |
| [P3-16](#p3-16) · MUST-V1.1 | **NEW** | No erasure replication epoch. Root §11.9 T18/[#3795](https://github.com/alphaonedev/ai-memory-mcp/issues/3795) supplies the custody-boundary carrier. |
| [P3-17](#p3-17) · MUST-V1.1 | **STRENGTHENED** | w8 R2/R4 — bind attributed evidence and dequarantine to exact bytes/revisions before redaction or merge. |
| [P3-19](#p3-19) · MUST-V1.1 | **NEW** | No derived-index generation/dirty/readiness contract; w6 marker visibility cannot establish projection correctness. |
| [P3-20](#p3-20) · MUST-V1.1 | **STRENGTHENED** | w6; w8 R4/R6 — containment follows authoritative relational edges and a durable bounded frontier even when AGE is stale. |
| [P3-21](#p3-21) · MUST-V1.1 | **RE-SCOPED** | Compatibility “No schema migrations” remains for advisory work; required integrity schemas need explicitly scoped migrations, verified manifests and recovery. |
| [P3-22](#p3-22) · MUST-V1.1 | **NEW** | No immutable GC victim-set contract; w8 implicated-row retention exemptions are retained within exact archive/erasure semantics. |
| [P3-23](#p3-23) · MUST-V1.1 | **NEW** | No approval-to-external-effect durable state machine. Root §11.9 [#3574](https://github.com/alphaonedev/ai-memory-mcp/issues/3574) already names external sink fencing. |
| [P3-24](#p3-24) · MUST-V1.1 | **STRENGTHENED** | w8 R4/R5 push/Alert delivery — persist admitted intent, recheck access and retain truthful counters/audit after unsubscribe. |
| [P3-25](#p3-25) · MUST-V1.1 | **NEW** | No hint-independent inbox deadline/OS socket lifecycle contract. Root measurement [#3473](https://github.com/alphaonedev/ai-memory-mcp/issues/3473) and [#3466](https://github.com/alphaonedev/ai-memory-mcp/issues/3466) are existing carriers. |
| [P3-27](#p3-27) · MUST-V1.1 | **NEW** | No supervised backend-aware shutdown certification. Coordinate with signed spine and root G2/G5. |
| [P3-28](#p3-28) · MUST-V1.1 | **STRENGTHENED** | Compatibility parity; w2/w3/w6 PG premises — replace assumed/helper parity with every required operation/frontend/backend/OS cell. |
| [P3-29](#p3-29) · MUST-V1.1 | **NEW** | No CPU/inference/DB scheduler redesign; root §11.9 [#3335](https://github.com/alphaonedev/ai-memory-mcp/issues/3335) already records the measured contention defect. |
| [P3-30](#p3-30) · MUST-V1.1 | **STRENGTHENED** | w2 boot token ceiling; w6 sweep budget; w8 R5 numeric budgets — one aggregate deadline/bytes/work reservation. |
| [P3-31](#p3-31) · MUST-V1.1 | **NEW** | No immutable runtime/store identity contract; w2 boot changes must consume it rather than ambient cwd. |
| [P3-33](#p3-33) · MUST-V1.1 | **NEW** | w7 prose scanning is not a security boundary. Seal privileged constructors and execute compiler-resolved bypass fixtures. |
| [P3-34](#p3-34) · MUST-V1.1 | **STRENGTHENED** | w7-docs-claims-cert; Measurement — sentence-level truth gates plus actual artifact, negative release, license/notice and complete-cell receipts. |
| [P3-36](#p3-36) · MUST-V1.1 | **NEW** | w8 R6 rewind is not clean-host disaster recovery. Root [#3561](https://github.com/alphaonedev/ai-memory-mcp/issues/3561)/[#3562](https://github.com/alphaonedev/ai-memory-mcp/issues/3562) and [#4107](https://github.com/alphaonedev/ai-memory-mcp/issues/4107)/[#4109](https://github.com/alphaonedev/ai-memory-mcp/issues/4109) retain ownership. |
| [P3-37](#p3-37) · MUST-V1.1 | **NEW** | No interruption-safe installer/package/service publication contract. |
| [P3-38](#p3-38) · MUST-V1.1 | **STRENGTHENED** | w8 R5 forensics/cost; w7 truthful claims — separate canonical evidence, redacted telemetry and explicit unknown health; OTLP breadth is optional. |
| [P3-39](#p3-39) · MUST-V1.1 | **RE-SCOPED** | w4 damp; w6 epistemic weights/default valid_at; w8 R3 — one retrieval plan and honest evidence sufficiency; preserve advisory defaults, qualify any rank/default change. |
| [P3-41](#p3-41) · MUST-V1.1 | **NEW** | No staged disconnected deployment test; root Package B/[#3583](https://github.com/alphaonedev/ai-memory-mcp/issues/3583) supplies a partial carrier. |
| [P3-42](#p3-42) · MUST-V1.1 | **NEW** | w1 skill registration and w2 boot formatting do not prove cross-session host continuity. Add versioned capture/import and actual retrieval/use. |

### Existing workstreams: retained scope and advised cuts / deferrals

Nothing below removes a binding MUST. CUT describes a proposed scope change, not a fifth tally priority. Adoption of this addendum must explicitly resolve the listed conflicts; the existing documents remain unchanged meanwhile. Evidence: Part III §III.5 (local evidence: `/ai-scratch/deputy/codex-pool/out/ns3x3/PART-III-NORTH-STAR-AND-V1.1.0.md#iii5--should-v11-later-no-cut-and-unresolved-decisions`), [existing workstreams](ROADMAP-v110.md#workstreams), [behind table](reviews/COMPETITOR-ASSESSMENT-3x7-2026-09-27.md#where-ai-memory-is-behind).

| Existing item | Advice and reason | Acceptance / competitive claim gate |
|---|---|---|
| w5 MemTrapBench runner | RETAIN harness-first and real/stub separation. CUT any publication-set reselection to force “no-memory > memory.” [#3570](https://github.com/alphaonedev/ai-memory-mcp/issues/3570) requires frozen taxonomy/held-out hashes and null + oracle baselines. Calibrate on a disjoint set; an unexpected direction is a result, not permission to retune the test. | Unknown taxonomy fails; exact 1,050 synthetic cases and 350/150/350/200 split if that fixture is used. Both required backend cells execute for release. Real answerer/judge, frozen held-out test and P2-42 paired competitor gates; a structural harness pass earns no cognitive win. |
| w1 applicability advisory + registered skill | RETAIN optional guidance and unknown-aware counts. DEFER any default flip or claimed trap mitigation until [#3570](https://github.com/alphaonedev/ai-memory-mcp/issues/3570) passes. | Golden outputs unchanged when off; all formats/backends tested when on. OpenViking/Haystack task superiority must pass P2-42, including no-memory/oracle controls. |
| w2 compact metadata | RETAIN seven-column visibility work and empty unknowns. CUT unmeasured token-saving/≤18-token claims; do not build a fourth wire format. | P3-13 digest/round-trip gate plus exact final serialized token accounting under P3-30; compare inline vs handles through [#3571](https://github.com/alphaonedev/ai-memory-mcp/issues/3571) before claiming savings against agentmemory/Haystack. |
| w3 task/session boundary | RE-SCOPE to cross-session/source advice, as its text already qualifies. CUT claims that session inequality detects within-history task changes. | Unknown stamp omits verdict; rank unchanged for advice; both stores agree. Any task benefit must win P2-42 on the relevant within-history subset, not only a cross-session fixture. |
| w4 feedback scope and damp | RETAIN authenticated-origin validation and default identity weights. DEFER tuning/default flip; a self-seeded wiring fixture proves plumbing only. | Full authoring truth table including Observation forgery; known/unknown scope controls; frozen held-out P3-39/P2-42 comparison against OpenViking/cognee/Haystack. |
| w6 contested markers, weights, valid_at, sweep | RETAIN visibility and bounded off-hot-path work. CUT implied Safety-trap immunity; DEFER speculative weighting/sweep expansion before authoritative graph and scoring gates. | P3-20/P3-39 oracles; no LLM on recall hot path; absent contradiction is Unknown, not safe. Strict quality gain versus named retrieval rivals before a mitigation claim. |
| w8 R1–R6 | RETAIN rig, source lineage, containment, stop/resume and forensic visibility. RE-SCOPE already-shipped primitives to residual tests; DEFER automatic truth elevation/default flips until measured. A signed model-family label does not certify independent training. | P2-31/P3-20/P2-42 plus SHOULD P1-12; publish SWARM-BENCH contamination, containment and rewind cost against KIP/ruflo/OpenViking. No code-presence or historical “no swarm rewind” sentence substitutes for rechecking the current pin. |
| w7 docs truth | RETAIN sentence-scoped rule, attribution, normative scope note and enrollment. CUT any suggestion that prose enforcement mitigates runtime traps. | Every uncited/whitewashed/stub-backed claim plant fails; valid cited control passes. P3-34 compares planted-failure rejection against Haystack/OpenViking, explicitly an assurance comparison. |
| Compatibility: additive/default-OFF/no schema migration | KEEP these rules for the existing advisory knobs. RE-SCOPE them for mandatory authority, commit, durability and EN1 contracts. Required repairs cannot ship as knowingly unsafe defaults. | Negative tests must fail in the claimed mission-critical configuration; named schema changes pass P3-21/36. Explicit version refusal and tested recovery replace silent wire/storage breakage. |
| w5 PG soft skip / nightly never-required | KEEP advisory development runs distinct. CUT skip-as-release-pass. The expensive job need not run on every PR, but its digest-bound result must be required for a release claim. | Missing PG, model, competitor or fixture is INCOMPLETE/UNMEASURED; P3-28/P3-34 refuse certification with any missing required cell. |
| Compatibility: “replicated ingest accepts peer rows verbatim” | RE-SCOPE to conservation of peer bytes under authenticated admission. Malformed or unauthorized peers do not bypass SE1/SE2; preserve rejected evidence only in an authorized bounded quarantine with an explicit receipt. | P3-13/15/17: zero accepted malformed security fields, zero silent discard, zero signature laundering; compare the same admitted transform trace against OpenViking/mem0/TencentDB-Agent-Memory. |
| Root §11.9 OTLP and commercial entitlement | DEFER optional exporter breadth behind P3-38; preserve [#3800](https://github.com/alphaonedev/ai-memory-mcp/issues/3800). CUT any vendor remote kill dependency from core custody. Support entitlement remains outside local store/read/export/restore authority. | Optional telemetry overhead ≤5% with exact losses; P3-41 72-hour network denial and expiry/restart fixtures retain local custody. These are advice about release boundaries, not closure of commercial issues. |

Broader scope stays at its binding disposition: OIDC/SCIM (P2-15), external KMS/HSM (P2-38), recipient E2EE (P1-19), standard A2A/framework adapters (P1-36/38), enterprise connectors (P1-40), multimodal ingestion (P1-41), federal authorization (P1-44), console (P1-47), review scheduling (P1-48), observer profiles (P1-49): **LATER**. Optional vector-backend proliferation **P1-50 is NO**. Full remote MCP **P1-35 is NO-CONSENSUS**, not a covert P3-42 dependency. Their individual named-rival re-entry tests remain in Part III §III.5 (local evidence: `/ai-scratch/deputy/codex-pool/out/ns3x3/PART-III-NORTH-STAR-AND-V1.1.0.md#iii5--should-v11-later-no-cut-and-unresolved-decisions`). OpenViking's remote MCP and enterprise integration lead remains until corresponding tests actually pass.

## 4. Measurement contract — applies to every item

Every package below inherits **protocol G** in addition to its individual gate. This separates required correctness from a potential competitive win. Binding protocol (local evidence: `/ai-scratch/deputy/codex-pool/out/ns3x3/PART-III-NORTH-STAR-AND-V1.1.0.md#shared-test-proven-protocol-g`).

1. Freeze comparator product/edition/commit and actual binary digest; ai-memory backend/frontend/OS/feature set; hardware/storage/network; model revision; corpus and split hashes; seeds; operation/sink inventory; all time/byte/token/dollar budgets; sample size, stopping rule and multiple-comparison treatment **before tuning or testing**. Preserve default and strongest applicable competitor configurations as separate arms.
2. Use external expected-state, digest, authorization and useful-task oracles. Inject crash, lost flush, partition, reorder, replay, source revision race, signer failure, malformed input and policy outage at each applicable boundary. Include valid controls: refusing all work cannot win.
3. Compare supported common tasks at equal durability, signing, encryption, authorization, inference cost and quality floors. Count all failures, retries, abstentions, deferred indexing and readiness costs. Unsupported is not corruption; closed internals remain Unknown; inaccessible products are Unmeasured. A missing required ai-memory cell fails release completeness.
4. A correctness win requires zero forbidden ai-memory outcomes and strictly fewer matched violations, or strictly greater externally verifiable coverage without lower useful completion. Equal safety is PARITY. Numeric wins meet the stated margin and paired 95% confidence interval excluding no improvement. Finite zero-failure trials are bounded evidence, not proof of impossibility.
5. Publish raw receipts, denominators, losses and reproduction commands. Each named rival gets PASS-WIN / PARITY / LOSS / UNSUPPORTED / UNMEASURED. Bind results to installed release bytes; invalidate affected receipts after changes. Do not transfer hosted mem0 numbers to OSS, later wake measurements to this pin, or engineering tests to federal authorization.

**Issue discipline:** each package names current carriers, sometimes broader than their present acceptance. Adoption would extend those issue scopes; it does not imply they already authorize the expansion. Do not open duplicate epics for the same contracts. If a genuinely uncovered implementation slice is found, record **“to file”** beneath the existing owner after a fresh issue search. No issue was created or edited for this addendum.

## 5. v1.1.0 MUST-BUILD — new deployable capabilities

The binding MUST set contains IMPROVE/REDESIGN packages rather than standalone NEW-FEATURE votes. The following are the new deployable capabilities advised within those retained packages. They are ordered by dependency stage; foundations in §6 start first. “Competitors to defeat” names a future test target, not a completed victory. All acceptance text below is retained from the binding Part III, including its corrections and useful-work floors.

<a id="p3-12"></a>

### P3-12 — Enforce EN1 with typed encrypted channels, including local IPC

**Problem/evidence.** The pin refuses off-host plaintext inference but permits loopback HTTP; authenticated stdio/UDS metadata is not encrypted transport. [docs/SECURITY.md:194](https://github.com/alphaonedev/ai-memory-mcp/blob/a1403c742f9d590a08b6fd170deec5f50ca8e940/docs/SECURITY.md#L194); [src/transit_encryption.rs:4](https://github.com/alphaonedev/ai-memory-mcp/blob/a1403c742f9d590a08b6fd170deec5f50ca8e940/src/transit_encryption.rs#L4); [O:80](reviews/AI-MEMORY-VS-OPENVIKING-3x3-CODE-LEVEL-2026-09-27.md); N3 §P3-12 (local evidence: `/ai-scratch/deputy/codex-pool/out/ns3x3/N3-PROPOSE-DEFECT-CLASS-REDESIGN.md:301`); N9 §P3-12 (local evidence: `/ai-scratch/deputy/codex-pool/out/ns3x3/N9-VOTE-COMPETITIVE-STRATEGIST.md:816`).

**Design.** Inventory every application-data and identity/control-data hop, then provide authenticated encrypted channels and usable host adapters. Require TLS for local inference or run it in-process; reject incompatible raw IPC before payload. No dev, loopback or optional-profile exception satisfies literal EN1.

**North Star / moonshot criteria:** EN1, SE1, SE2, RL3, M1.

**Competitors to defeat:** OpenViking, agentmemory, mem0; no defeat claimed yet.

**TEST-PROVEN acceptance — NOT RUN:** For every supported network/IPC/control-data leg, run encrypted-positive and plaintext/downgrade/wrong-key/certificate-negative captures. Zero recoverable application canaries, credential or identity frames in plaintext; incompatible clients refuse before payload. At least two actual supported host integrations remain usable offline and remotely as declared. Require 100% EN1 coverage and strictly higher common-leg coverage than each named comparator for a win; no N/A inflation. Capture binary and encoded canaries and inspect authenticated-encryption/key protocols; absence of one text string is not encryption proof.

**Effort/dependencies:** XL; P3-11 channel contract, P3-13.

**Existing issue carriers:** [#4103](https://github.com/alphaonedev/ai-memory-mcp/issues/4103), [#3563](https://github.com/alphaonedev/ai-memory-mcp/issues/3563); extend these scopes and their linked regression issues, do not duplicate them.

<a id="p1-05"></a>

### P1-05 — Complete generation and evidence provenance

**Problem/evidence.** A kind/provenance label does not reconstruct the source revision, generator configuration or complete evidence for a derived artifact. [src/models/memory.rs:64](https://github.com/alphaonedev/ai-memory-mcp/blob/a1403c742f9d590a08b6fd170deec5f50ca8e940/src/models/memory.rs#L64); [C:226](reviews/COMPETITOR-ASSESSMENT-3x7-2026-09-27.md); N1 §P1-05 (local evidence: `/ai-scratch/deputy/codex-pool/out/ns3x3/N1-PROPOSE-COMPETITIVE-GAPS.md:156`); N9 §P1-05 (local evidence: `/ai-scratch/deputy/codex-pool/out/ns3x3/N9-VOTE-COMPETITIVE-STRATEGIST.md:212`).

**Design.** Commit a signed GenerationRun and immutable source-revision links with every existing derivation. Separate Complete from Incomplete/Unknown and retain canonical evidence separately from display redaction. Freeze a role-receipt schema now; the complete role router is not a prerequisite.

**North Star / moonshot criteria:** DI1, DI2, DI3, RL1, M2, M4, M5, M6, M7.

**Competitors to defeat:** TencentDB-Agent-Memory, cognee; no defeat claimed yet.

**TEST-PROVEN acceptance — NOT RUN:** For 10,000 existing derivations under persistence faults, every committed output links to exact retained source revisions and a signed run; missing fields are Incomplete, never Complete. Zero orphaned or falsely complete artifacts. On the identical supported transformation trace, achieve a strictly higher independently verifiable complete-lineage fraction than each named comparator; include all committed outputs in the denominator. Unknown/Incomplete earns no Complete numerator credit; compare equal successful generation yield.

**Effort/dependencies:** M; P3-01, P3-06, P3-13.

**Existing issue carriers:** [#4096](https://github.com/alphaonedev/ai-memory-mcp/issues/4096), [#4104](https://github.com/alphaonedev/ai-memory-mcp/issues/4104), [#3575](https://github.com/alphaonedev/ai-memory-mcp/issues/3575); extend these scopes and their linked regression issues, do not duplicate them.

<a id="p2-35"></a>

### P2-35 — Complete the existing independent decision-provider carrier with fail-closed destructive gates

**Problem/evidence.** At the pin, summary generation and fixed thresholds do not constitute an independent destructive judge. Later decision-provider defects are landing regressions, not pinned capabilities. [src/mcp/tools/store/synthesis.rs:198](https://github.com/alphaonedev/ai-memory-mcp/blob/a1403c742f9d590a08b6fd170deec5f50ca8e940/src/mcp/tools/store/synthesis.rs#L198); [src/synthesis/mod.rs:373](https://github.com/alphaonedev/ai-memory-mcp/blob/a1403c742f9d590a08b6fd170deec5f50ca8e940/src/synthesis/mod.rs#L373); A:15 (local evidence: `/ai-scratch/deputy/codex-pool/out/adv3x3/A5-REFUTE-AI-MEMORY-REALITY.md:15`); N2 §P2-35 (local evidence: `/ai-scratch/deputy/codex-pool/out/ns3x3/N2-PROPOSE-NORTH-STAR-DELIVERY.md:818`); N9 §P2-35 (local evidence: `/ai-scratch/deputy/codex-pool/out/ns3x3/N9-VOTE-COMPETITIVE-STRATEGIST.md:597`).

**Design.** Complete the existing decision carrier with typed Permit/Refuse/Abstain bound to source revisions, proposed effects, policy and role identity. Host Deny remains terminal; malformed, stale, unavailable or unverified evidence preserves sources. Learned heterogeneous review is conditional scope and cannot delay deterministic safety or be called verified training independence.

**North Star / moonshot criteria:** DI1, DI2, SE1, SE2, M3, M4, M6, M7.

**Competitors to defeat:** OpenViking, Mem0, Haystack; no defeat claimed yet.

**TEST-PROVEN acceptance — NOT RUN:** 10,000 malformed/replayed/stale/same-family/unknown-family/timeout judgment cases produce zero unauthorized destructive commits or Deny overrides. Correct permits bind revisions, policy and independently enrolled role identities. A learned-judgment win requires strictly fewer harmful promotions than each named comparator with useful-permit recall at least 90% of the best comparator under equal spend; include always-abstain and oracle controls. Training-error independence remains unproven. The existing implementation carrier is [#3806](https://github.com/alphaonedev/ai-memory-mcp/issues/3806), still OPEN/ga-blocker in the current snapshot; [#4011](https://github.com/alphaonedev/ai-memory-mcp/issues/4011)–[#4013](https://github.com/alphaonedev/ai-memory-mcp/issues/4013) remain landing regressions. If learned heterogeneous judgment ships, run at least 1,000 held-out cases, require at least 20% fewer harmful errors at matched useful yield/spend with a paired 95% interval; the stronger P1-04 claim separately requires its 50% reduction/95%-yield gate. Unknown training lineage cannot satisfy verified M6.

**Effort/dependencies:** L; P3-02, P3-06, P3-08, P3-10.

**Existing issue carriers:** [#4102](https://github.com/alphaonedev/ai-memory-mcp/issues/4102), [#4095](https://github.com/alphaonedev/ai-memory-mcp/issues/4095), [#3570](https://github.com/alphaonedev/ai-memory-mcp/issues/3570), [#3564](https://github.com/alphaonedev/ai-memory-mcp/issues/3564); extend these scopes and their linked regression issues, do not duplicate them.

<a id="p3-23"></a>

### P3-23 — Approval and action execution become a durable state machine with fencing

**Problem/evidence.** Approval can commit without recoverable execution intent; database claim exclusivity does not fence an external effect. [src/actions/mod.rs:281](https://github.com/alphaonedev/ai-memory-mcp/blob/a1403c742f9d590a08b6fd170deec5f50ca8e940/src/actions/mod.rs#L281); [src/federation/receive_auth.rs:66](https://github.com/alphaonedev/ai-memory-mcp/blob/a1403c742f9d590a08b6fd170deec5f50ca8e940/src/federation/receive_auth.rs#L66); [C:34](reviews/COMPETITOR-ASSESSMENT-3x7-2026-09-27.md); N3 §P3-23 (local evidence: `/ai-scratch/deputy/codex-pool/out/ns3x3/N3-PROPOSE-DEFECT-CLASS-REDESIGN.md:477`); N9 §P3-23 (local evidence: `/ai-scratch/deputy/codex-pool/out/ns3x3/N9-VOTE-COMPETITIVE-STRATEGIST.md:995`).

**Design.** Persist approval and execution intent together, then run an explicit retryable state machine that rechecks authority. Participating sinks verify operation idempotency and lease fencing epoch. Receipt loss or nonparticipating sinks remain uncertain/at-least-once, never certified exactly-once.

**North Star / moonshot criteria:** DI1, DI2, SE1, PF3, RL1, RL2, M3.

**Competitors to defeat:** ruflo, MemPalace, Haystack, KIP; no defeat claimed yet.

**TEST-PROVEN acceptance — NOT RUN:** Crash after approval, dequeue, external effect and receipt; expire a paused worker lease and let another worker proceed. No stranded approved operation; every outcome is terminal/retryable/explicitly uncertain. A fencing-aware sink accepts exactly one logical effect and rejects stale fences in 10,000 schedules; an unfenced control exposes the risk. Fewer stranded/stale/duplicate effects than each comparator at the identical participating sink proves a win. Include KIP as a stronger comparator, an unfenced control and at least one production sink adapter in addition to the common reference sink.

**Effort/dependencies:** XL; P3-01, P3-04, P3-06.

**Existing issue carriers:** [#3574](https://github.com/alphaonedev/ai-memory-mcp/issues/3574), [#3576](https://github.com/alphaonedev/ai-memory-mcp/issues/3576), [#3580](https://github.com/alphaonedev/ai-memory-mcp/issues/3580), [#3369](https://github.com/alphaonedev/ai-memory-mcp/issues/3369), [#3377](https://github.com/alphaonedev/ai-memory-mcp/issues/3377); extend these scopes and their linked regression issues, do not duplicate them.

<a id="p3-36"></a>

### P3-36 — Back up an explicit store-and-key recovery boundary and rehearse it

**Problem/evidence.** A corpus-only backup or SQLite sidecar snapshot does not recover the actual PostgreSQL service, keys, erasure floor and pending work. [src/cli/backup.rs:1118](https://github.com/alphaonedev/ai-memory-mcp/blob/a1403c742f9d590a08b6fd170deec5f50ca8e940/src/cli/backup.rs#L1118); [src/cli/backup.rs:1620](https://github.com/alphaonedev/ai-memory-mcp/blob/a1403c742f9d590a08b6fd170deec5f50ca8e940/src/cli/backup.rs#L1620); [C:360](reviews/COMPETITOR-ASSESSMENT-3x7-2026-09-27.md); N3 §P3-36 (local evidence: `/ai-scratch/deputy/codex-pool/out/ns3x3/N3-PROPOSE-DEFECT-CLASS-REDESIGN.md:685`); N9 §P3-36 (local evidence: `/ai-scratch/deputy/codex-pool/out/ns3x3/N9-VOTE-COMPETITIVE-STRATEGIST.md:1161`).

**Design.** Declare a signed recovery inventory and snapshot/WAL cut; orchestrate native backup on the active store, download/verify offsite bytes, restore on a clean host, then verify authority and atomically switch. Separate Restored from SearchReady and missing assets from success.

**North Star / moonshot criteria:** DI1, DI2, DI3, RL1, RL2, RL3, M1, M5.

**Competitors to defeat:** OpenViking, ruflo, MemPalace; no defeat claimed yet.

**TEST-PROVEN acceptance — NOT RUN:** Restore 100,000 records plus graph/policy/identity/queues/erasure floors on clean hosts for both stores from verified offsite bytes; no original disk required. Zero loss inside the declared captured snapshot/WAL boundary, no resurrected erased content, no omitted asset represented complete. Measure preregistered RTO at most 15 min separately from full-search readiness. Greater recovered required-asset coverage or 20% faster verified RTO than each comparator at identical inventory/custody proves a win.

**Effort/dependencies:** XL; P3-07, P3-16, P3-19, P3-21, P3-27.

**Existing issue carriers:** [#4107](https://github.com/alphaonedev/ai-memory-mcp/issues/4107), [#4109](https://github.com/alphaonedev/ai-memory-mcp/issues/4109), [#4110](https://github.com/alphaonedev/ai-memory-mcp/issues/4110), [#3795](https://github.com/alphaonedev/ai-memory-mcp/issues/3795), [#3583](https://github.com/alphaonedev/ai-memory-mcp/issues/3583), [#3561](https://github.com/alphaonedev/ai-memory-mcp/issues/3561), [#3562](https://github.com/alphaonedev/ai-memory-mcp/issues/3562); extend these scopes and their linked regression issues, do not duplicate them.

<a id="p3-41"></a>

### P3-41 — Make disconnected operation a tested deployment mode with no remote kill dependency

**Problem/evidence.** First-run downloads and remote configuration complicate disconnected operation; local packaging alone proves no air-gap or no-kill guarantee. [src/embeddings.rs:1029](https://github.com/alphaonedev/ai-memory-mcp/blob/a1403c742f9d590a08b6fd170deec5f50ca8e940/src/embeddings.rs#L1029); [src/config.rs:9653](https://github.com/alphaonedev/ai-memory-mcp/blob/a1403c742f9d590a08b6fd170deec5f50ca8e940/src/config.rs#L9653); [U:880](reviews/US-AGENT-MEMORY-MARKET-3x3-AUDIT-2026-09-27.md); N3 §P3-41 (local evidence: `/ai-scratch/deputy/codex-pool/out/ns3x3/N3-PROPOSE-DEFECT-CLASS-REDESIGN.md:765`); N9 §P3-41 (local evidence: `/ai-scratch/deputy/codex-pool/out/ns3x3/N9-VOTE-COMPETITIVE-STRATEGIST.md:1229`).

**Design.** Stage and verify binary, identities, schemas, policy and model assets, with encrypted local adapters and local operator recovery. Missing optional models report degradation without disabling governed corpus access. A cloud-only service is Unsupported for this residency requirement, not a measured reliability failure.

**North Star / moonshot criteria:** EN1, RL2, RL3, PF1, M1, M2, M7.

**Competitors to defeat:** OpenViking and agentmemory; Amazon Bedrock AgentCore Memory is a documentary Unsupported comparator for disconnected endpoint residency; no defeat claimed yet.

**TEST-PROVEN acceptance — NOT RUN:** From a clean staged bundle, deny all network/DNS for 72 h and restart 100 times: authorized local store/recall/verify/export/restore works with zero undeclared egress, unsigned writes or vendor-entitlement dependency. Optional model absence reports degradation while required model assets are verified. Complete more shared disconnected missions than locally configured OpenViking/agentmemory at equal staged assets to claim a win. AWS cloud-only incompatibility is a separately labeled residency requirement gap, not an executed reliability defect. An advertised seven-day claim requires the seven-day run in addition to the 72-hour release gate; no cloud federal disadvantage is inferred.

**Effort/dependencies:** L; P3-12, P3-21, P3-36, P3-37.

**Existing issue carriers:** [#3583](https://github.com/alphaonedev/ai-memory-mcp/issues/3583), [#3561](https://github.com/alphaonedev/ai-memory-mcp/issues/3561), [#3562](https://github.com/alphaonedev/ai-memory-mcp/issues/3562), [#4103](https://github.com/alphaonedev/ai-memory-mcp/issues/4103); extend these scopes and their linked regression issues, do not duplicate them.

<a id="p3-42"></a>

### P3-42 — Version host and MCP integration contracts and make capture restart-safe

**Problem/evidence.** Host flag/schema drift, duplicate imports and a boot sentinel alone do not prove retained context is usable across sessions. [src/llm_cli_wrap.rs:94](https://github.com/alphaonedev/ai-memory-mcp/blob/a1403c742f9d590a08b6fd170deec5f50ca8e940/src/llm_cli_wrap.rs#L94); [src/mcp/mod.rs:5180](https://github.com/alphaonedev/ai-memory-mcp/blob/a1403c742f9d590a08b6fd170deec5f50ca8e940/src/mcp/mod.rs#L5180); [C:357](reviews/COMPETITOR-ASSESSMENT-3x7-2026-09-27.md); N3 §P3-42 (local evidence: `/ai-scratch/deputy/codex-pool/out/ns3x3/N3-PROPOSE-DEFECT-CLASS-REDESIGN.md:781`); N9 §P3-42 (local evidence: `/ai-scratch/deputy/codex-pool/out/ns3x3/N9-VOTE-COMPETITIVE-STRATEGIST.md:1246`).

**Design.** Pin finite supported host versions and share command/principal/encrypted-channel contracts. Persist accepted capture/import IDs with records, bind capture signatures to identity/namespace/time, and test actual subsequent retrieval/use. Refuse incompatible clients explicitly; new framework breadth is deferred.

**North Star / moonshot criteria:** DI1, DI3, SE1, EN1, RL1, RL2, M2, M7.

**Competitors to defeat:** OpenViking, agentmemory, mem0, Haystack; no defeat claimed yet.

**TEST-PROVEN acceptance — NOT RUN:** On two actual supported host versions and deliberately incompatible clients, restart after each capture/import record: zero missing/duplicate accepted turns, principal substitution or private-span egress; signed capture binds identity/namespace/time and a boot sentinel confirms delivery. Encrypted compatibility works end-to-end. Strictly higher continuity-task completion than each named comparator at equal semantics/budgets proves a win; native remote-MCP conformance remains unclaimed if deferred. Include a task-level retrieval-and-use oracle; boot sentinel delivery alone is insufficient.

**Effort/dependencies:** XL; P2-16, P3-12, P3-13, P3-28, P3-37.

**Existing issue carriers:** [#4114](https://github.com/alphaonedev/ai-memory-mcp/issues/4114), [#4105](https://github.com/alphaonedev/ai-memory-mcp/issues/4105), [#4106](https://github.com/alphaonedev/ai-memory-mcp/issues/4106), [#3805](https://github.com/alphaonedev/ai-memory-mcp/issues/3805), [#3412](https://github.com/alphaonedev/ai-memory-mcp/issues/3412), [#3375](https://github.com/alphaonedev/ai-memory-mcp/issues/3375), [#3575](https://github.com/alphaonedev/ai-memory-mcp/issues/3575), [#3351](https://github.com/alphaonedev/ai-memory-mcp/issues/3351); extend these scopes and their linked regression issues, do not duplicate them.

<a id="p2-42"></a>

### P2-42 — Gate the mission-critical claim on reproducible continuity and competitor missions

**Problem/evidence.** Stub competitor runners, issue counts and analyst votes do not demonstrate a mission-critical or competitive outcome. [benchmarks/competitive-benchmarks/harness.sh:64](https://github.com/alphaonedev/ai-memory-mcp/blob/a1403c742f9d590a08b6fd170deec5f50ca8e940/benchmarks/competitive-benchmarks/harness.sh#L64); [src/write_receipt.rs:54](https://github.com/alphaonedev/ai-memory-mcp/blob/a1403c742f9d590a08b6fd170deec5f50ca8e940/src/write_receipt.rs#L54); [C:401](reviews/COMPETITOR-ASSESSMENT-3x7-2026-09-27.md); N2 §P2-42 (local evidence: `/ai-scratch/deputy/codex-pool/out/ns3x3/N2-PROPOSE-NORTH-STAR-DELIVERY.md:972`); N9 §P2-42 (local evidence: `/ai-scratch/deputy/codex-pool/out/ns3x3/N9-VOTE-COMPETITIVE-STRATEGIST.md:631`).

**Design.** Extend the existing mission ledger with real pinned adapters, external oracles, five-clock timing and complete failure/cost denominators. Start fixtures immediately; final qualification consumes retained MUST packages. Preserve losses, ties, Unsupported and Unmeasured results.

**North Star / moonshot criteria:** DI1, DI2, DI3, SE1, SE2, PF1, PF2, PF3, RL1, RL2, RL3, EN1, M1, M2, M3, M4, M5, M6, M7.

**Competitors to defeat:** OpenViking, Mem0, Hindsight, KIP, Haystack; no defeat claimed yet.

**TEST-PROVEN acceptance — NOT RUN:** Execute the retained release operation matrix, two GA missions then all 12 required missions with at least 30 independent seeds/arm, 24-hour then 72-hour soak and P2-04 resets. Zero silent-loss, partial, unsigned, unauthorized or plaintext successes; every required cell executed. For each accessible named competitor earn at least one preregistered shared-mission win of 5 accuracy points or 20% cost/latency/goodput improvement with a positive paired 95% interval and no mandatory safety regression. Do not count unsupported or inaccessible products as runtime failures.

**Effort/dependencies:** XL; P3-28, P3-34; final qualification of all retained MUST packages.

**Existing issue carriers:** [#3558](https://github.com/alphaonedev/ai-memory-mcp/issues/3558), [#3559](https://github.com/alphaonedev/ai-memory-mcp/issues/3559), [#3560](https://github.com/alphaonedev/ai-memory-mcp/issues/3560), [#3561](https://github.com/alphaonedev/ai-memory-mcp/issues/3561), [#3562](https://github.com/alphaonedev/ai-memory-mcp/issues/3562), [#3564](https://github.com/alphaonedev/ai-memory-mcp/issues/3564), [#3568](https://github.com/alphaonedev/ai-memory-mcp/issues/3568), [#3569](https://github.com/alphaonedev/ai-memory-mcp/issues/3569), [#3570](https://github.com/alphaonedev/ai-memory-mcp/issues/3570), [#3572](https://github.com/alphaonedev/ai-memory-mcp/issues/3572); extend these scopes and their linked regression issues, do not duplicate them.

## 6. FIX / IMPROVE / REDESIGN — eliminate defect classes

The closure unit is the violated contract across all affected paths, not the individual report. Fix the reported reproducer immediately, then keep its counterexample in the class suite. An open issue is a test seed; source confirmation and a failing regression at the implementation baseline are required before attributing it to that baseline. All suites inherit §4 and their named comparator gates.

| Defect class and structural replacement | Report seeds / existing carriers | Acceptance owner |
|---|---|---|
| Ambient context / wrong active store → immutable runtime and ActiveStore | [#4014](https://github.com/alphaonedev/ai-memory-mcp/issues/4014), [#4080](https://github.com/alphaonedev/ai-memory-mcp/issues/4080), [#4081](https://github.com/alphaonedev/ai-memory-mcp/issues/4081), [#4070](https://github.com/alphaonedev/ai-memory-mcp/issues/4070); [#4108](https://github.com/alphaonedev/ai-memory-mcp/issues/4108) | P3-31/28 |
| Authority treated as optional data → typed policy/principal/revocation epochs | [#3986](https://github.com/alphaonedev/ai-memory-mcp/issues/3986), [#4042](https://github.com/alphaonedev/ai-memory-mcp/issues/4042), [#4043](https://github.com/alphaonedev/ai-memory-mcp/issues/4043), [#4044](https://github.com/alphaonedev/ai-memory-mcp/issues/4044), [#4059](https://github.com/alphaonedev/ai-memory-mcp/issues/4059), [#4066](https://github.com/alphaonedev/ai-memory-mcp/issues/4066), [#4069](https://github.com/alphaonedev/ai-memory-mcp/issues/4069), [#4068](https://github.com/alphaonedev/ai-memory-mcp/issues/4068) | P3-02/03/04 |
| Model/network outcomes treated as authorization → typed outcomes and admitted channels | [#4047](https://github.com/alphaonedev/ai-memory-mcp/issues/4047), [#4011](https://github.com/alphaonedev/ai-memory-mcp/issues/4011), [#4012](https://github.com/alphaonedev/ai-memory-mcp/issues/4012), [#4013](https://github.com/alphaonedev/ai-memory-mcp/issues/4013), [#4018](https://github.com/alphaonedev/ai-memory-mcp/issues/4018), [#4048](https://github.com/alphaonedev/ai-memory-mcp/issues/4048), [#4121](https://github.com/alphaonedev/ai-memory-mcp/issues/4121), [#4122](https://github.com/alphaonedev/ai-memory-mcp/issues/4122), [#4123](https://github.com/alphaonedev/ai-memory-mcp/issues/4123), [#4075](https://github.com/alphaonedev/ai-memory-mcp/issues/4075) | P3-10/11/12; P2-16/35 |
| Parse/coerce then mutate → closed commands and canonical codecs | [#4061](https://github.com/alphaonedev/ai-memory-mcp/issues/4061), [#4064](https://github.com/alphaonedev/ai-memory-mcp/issues/4064), [#4065](https://github.com/alphaonedev/ai-memory-mcp/issues/4065), [#4074](https://github.com/alphaonedev/ai-memory-mcp/issues/4074), [#4076](https://github.com/alphaonedev/ai-memory-mcp/issues/4076); [#3454](https://github.com/alphaonedev/ai-memory-mcp/issues/3454), [#3805](https://github.com/alphaonedev/ai-memory-mcp/issues/3805) | P3-13 |
| Check-then-write / best-effort evidence → one signed atomic apply | [#4034](https://github.com/alphaonedev/ai-memory-mcp/issues/4034), [#4053](https://github.com/alphaonedev/ai-memory-mcp/issues/4053), [#4023](https://github.com/alphaonedev/ai-memory-mcp/issues/4023), [#4000](https://github.com/alphaonedev/ai-memory-mcp/issues/4000), [#3376](https://github.com/alphaonedev/ai-memory-mcp/issues/3376) | P3-01/06; P1-05 |
| Summary success assumed / early source retirement → revision-bound semantic plan | [#4091](https://github.com/alphaonedev/ai-memory-mcp/issues/4091), [#4045](https://github.com/alphaonedev/ai-memory-mcp/issues/4045), [#4046](https://github.com/alphaonedev/ai-memory-mcp/issues/4046), [#4063](https://github.com/alphaonedev/ai-memory-mcp/issues/4063); [#4092](https://github.com/alphaonedev/ai-memory-mcp/issues/4092)–[#4095](https://github.com/alphaonedev/ai-memory-mcp/issues/4095) | P3-08; P2-35 |
| Local success confused with durable/completely witnessed state | [#4009](https://github.com/alphaonedev/ai-memory-mcp/issues/4009), [#4021](https://github.com/alphaonedev/ai-memory-mcp/issues/4021), [#4086](https://github.com/alphaonedev/ai-memory-mcp/issues/4086), [#4062](https://github.com/alphaonedev/ai-memory-mcp/issues/4062), [#4070](https://github.com/alphaonedev/ai-memory-mcp/issues/4070), [#4072](https://github.com/alphaonedev/ai-memory-mcp/issues/4072) | P2-04; P3-07/27 |
| Whole-row clocks / transport nonces confused with operation state | [#4030](https://github.com/alphaonedev/ai-memory-mcp/issues/4030), [#4031](https://github.com/alphaonedev/ai-memory-mcp/issues/4031), [#4032](https://github.com/alphaonedev/ai-memory-mcp/issues/4032), [#4060](https://github.com/alphaonedev/ai-memory-mcp/issues/4060), [#4024](https://github.com/alphaonedev/ai-memory-mcp/issues/4024), [#4026](https://github.com/alphaonedev/ai-memory-mcp/issues/4026) | P3-14/15 |
| Negative state checked outside transaction / fake worker health | [#4029](https://github.com/alphaonedev/ai-memory-mcp/issues/4029), [#4067](https://github.com/alphaonedev/ai-memory-mcp/issues/4067); [#3285](https://github.com/alphaonedev/ai-memory-mcp/issues/3285), [#3795](https://github.com/alphaonedev/ai-memory-mcp/issues/3795) | P3-16 |
| Matching identifier confused with matching signed bytes | [#4027](https://github.com/alphaonedev/ai-memory-mcp/issues/4027), [#4017](https://github.com/alphaonedev/ai-memory-mcp/issues/4017); [#3575](https://github.com/alphaonedev/ai-memory-mcp/issues/3575), [#4096](https://github.com/alphaonedev/ai-memory-mcp/issues/4096) | P3-17 |
| Projection mistaken for authority → versioned rebuildable index and relational safety traversal | [#4036](https://github.com/alphaonedev/ai-memory-mcp/issues/4036), [#4038](https://github.com/alphaonedev/ai-memory-mcp/issues/4038), [#4039](https://github.com/alphaonedev/ai-memory-mcp/issues/4039), [#4078](https://github.com/alphaonedev/ai-memory-mcp/issues/4078), [#4010](https://github.com/alphaonedev/ai-memory-mcp/issues/4010); [#4110](https://github.com/alphaonedev/ai-memory-mcp/issues/4110)/[#4112](https://github.com/alphaonedev/ai-memory-mcp/issues/4112) | P3-19/20 |
| Stamp/count/predicate used as migration or archive proof | [#4037](https://github.com/alphaonedev/ai-memory-mcp/issues/4037), [#4035](https://github.com/alphaonedev/ai-memory-mcp/issues/4035), [#4040](https://github.com/alphaonedev/ai-memory-mcp/issues/4040), [#4041](https://github.com/alphaonedev/ai-memory-mcp/issues/4041), [#4049](https://github.com/alphaonedev/ai-memory-mcp/issues/4049); [#4111](https://github.com/alphaonedev/ai-memory-mcp/issues/4111) | P3-21/22 |
| Volatile accepted work / unfenced effects / hint clock → durable intents and independent read deadlines | [#4025](https://github.com/alphaonedev/ai-memory-mcp/issues/4025), [#4079](https://github.com/alphaonedev/ai-memory-mcp/issues/4079), [#4081](https://github.com/alphaonedev/ai-memory-mcp/issues/4081), [#4056](https://github.com/alphaonedev/ai-memory-mcp/issues/4056), [#4057](https://github.com/alphaonedev/ai-memory-mcp/issues/4057), [#4058](https://github.com/alphaonedev/ai-memory-mcp/issues/4058), [#4120](https://github.com/alphaonedev/ai-memory-mcp/issues/4120), [#4125](https://github.com/alphaonedev/ai-memory-mcp/issues/4125), [#4071](https://github.com/alphaonedev/ai-memory-mcp/issues/4071) | P3-23/24/25 |
| Blocking CPU / global mutex / independently bounded children → fair bounded schedulers and parent budgets | [#4089](https://github.com/alphaonedev/ai-memory-mcp/issues/4089), [#3988](https://github.com/alphaonedev/ai-memory-mcp/issues/3988), [#3335](https://github.com/alphaonedev/ai-memory-mcp/issues/3335), [#3341](https://github.com/alphaonedev/ai-memory-mcp/issues/3341), [#3342](https://github.com/alphaonedev/ai-memory-mcp/issues/3342), [#3284](https://github.com/alphaonedev/ai-memory-mcp/issues/3284), [#3287](https://github.com/alphaonedev/ai-memory-mcp/issues/3287), [#4033](https://github.com/alphaonedev/ai-memory-mcp/issues/4033) | P3-29/30 |
| Textual gate / shared test globals / stale artifact → sealed boundaries and deterministic release receipts | [#4020](https://github.com/alphaonedev/ai-memory-mcp/issues/4020), [#4052](https://github.com/alphaonedev/ai-memory-mcp/issues/4052), [#4054](https://github.com/alphaonedev/ai-memory-mcp/issues/4054), [#3984](https://github.com/alphaonedev/ai-memory-mcp/issues/3984), [#4015](https://github.com/alphaonedev/ai-memory-mcp/issues/4015), [#4016](https://github.com/alphaonedev/ai-memory-mcp/issues/4016), [#4085](https://github.com/alphaonedev/ai-memory-mcp/issues/4085), [#4088](https://github.com/alphaonedev/ai-memory-mcp/issues/4088), [#4090](https://github.com/alphaonedev/ai-memory-mcp/issues/4090), [#4117](https://github.com/alphaonedev/ai-memory-mcp/issues/4117), [#4126](https://github.com/alphaonedev/ai-memory-mcp/issues/4126); [#3798](https://github.com/alphaonedev/ai-memory-mcp/issues/3798)/[#3799](https://github.com/alphaonedev/ai-memory-mcp/issues/3799) | P3-33/34 |
| Corpus-only backup / overwrite install / raw diagnostics → explicit recovery inventory, atomic publish, typed telemetry | [#4077](https://github.com/alphaonedev/ai-memory-mcp/issues/4077), [#4082](https://github.com/alphaonedev/ai-memory-mcp/issues/4082), [#4084](https://github.com/alphaonedev/ai-memory-mcp/issues/4084), [#3990](https://github.com/alphaonedev/ai-memory-mcp/issues/3990), [#4124](https://github.com/alphaonedev/ai-memory-mcp/issues/4124); [#4107](https://github.com/alphaonedev/ai-memory-mcp/issues/4107)/[#4109](https://github.com/alphaonedev/ai-memory-mcp/issues/4109)/[#3800](https://github.com/alphaonedev/ai-memory-mcp/issues/3800) | P3-36/37/38 |
| Rank self-agreement / fake no-match / unbound host capture → external relevance and continuity oracles | [#2425](https://github.com/alphaonedev/ai-memory-mcp/issues/2425), [#3350](https://github.com/alphaonedev/ai-memory-mcp/issues/3350), [#3349](https://github.com/alphaonedev/ai-memory-mcp/issues/3349), [#3412](https://github.com/alphaonedev/ai-memory-mcp/issues/3412), [#3410](https://github.com/alphaonedev/ai-memory-mcp/issues/3410); [#3567](https://github.com/alphaonedev/ai-memory-mcp/issues/3567)/[#3568](https://github.com/alphaonedev/ai-memory-mcp/issues/3568)/[#3570](https://github.com/alphaonedev/ai-memory-mcp/issues/3570) | P3-39/42 |

[#4124](https://github.com/alphaonedev/ai-memory-mcp/issues/4124) cost-metering loss and [#4026](https://github.com/alphaonedev/ai-memory-mcp/issues/4026) replay charging remain explicit pending obligations within atomic quota/evidence and telemetry closure; their original P3-18 priority is NO-CONSENSUS, not silently promoted to a separate MUST. No “exact cost” claim is allowed while reconciliation fails. Likewise, record-stop effect inventory stays with tally-retained P2-31; P3-05's separate vote remains unresolved.

### Foundations: runtime, authority, transport and wire contracts

<a id="p3-31"></a>

### P3-31 — Resolve paths and configuration once into immutable runtime context

**Problem/evidence.** Ambient cwd/environment and late validation can target an unintended database or mutate before rejecting input. [src/cli/boot.rs:194](https://github.com/alphaonedev/ai-memory-mcp/blob/a1403c742f9d590a08b6fd170deec5f50ca8e940/src/cli/boot.rs#L194); [src/config.rs:9171](https://github.com/alphaonedev/ai-memory-mcp/blob/a1403c742f9d590a08b6fd170deec5f50ca8e940/src/config.rs#L9171); [C:360](reviews/COMPETITOR-ASSESSMENT-3x7-2026-09-27.md); N3 §P3-31 (local evidence: `/ai-scratch/deputy/codex-pool/out/ns3x3/N3-PROPOSE-DEFECT-CLASS-REDESIGN.md:605`); N9 §P3-31 (local evidence: `/ai-scratch/deputy/codex-pool/out/ns3x3/N9-VOTE-COMPETITIVE-STRATEGIST.md:1114`).

**Design.** Resolve absolute paths, store identity, configuration source, principal and clock once into RuntimeContext. Validate pure input before side-effectful opens; companions receive the same explicit deployment context. Fix affected entrypoints first.

**North Star / moonshot criteria:** DI1, SE1, SE2, RL1, RL2, M1.

**Competitors to defeat:** agentmemory, OpenViking, KIP; no defeat claimed yet.

**TEST-PROVEN acceptance — NOT RUN:** Invoke affected CLI and companion services from 20 unrelated cwd values and hostile environment/invalid-input fixtures: exactly the configured store changes and pure-invalid inputs trigger no migration/GC. Stable absolute store identity is recorded. Fewer wrong-target/ambient-context failures than each named comparator on equivalent documented workflows proves a win; missing services are not scored as runtime defects.

**Effort/dependencies:** M; None; foundation.

**Existing issue carriers:** [#3438](https://github.com/alphaonedev/ai-memory-mcp/issues/3438), [#3417](https://github.com/alphaonedev/ai-memory-mcp/issues/3417), [#3347](https://github.com/alphaonedev/ai-memory-mcp/issues/3347); extend these scopes and their linked regression issues, do not duplicate them.

<a id="p3-28"></a>

### P3-28 — Route all surfaces through an explicit active-store capability contract

**Problem/evidence.** MCP SQLite affinity, PostgreSQL unsupported skills and sidecar access contradict broad parity claims. [src/store/mod.rs:1216](https://github.com/alphaonedev/ai-memory-mcp/blob/a1403c742f9d590a08b6fd170deec5f50ca8e940/src/store/mod.rs#L1216); [src/mcp/mod.rs:1610](https://github.com/alphaonedev/ai-memory-mcp/blob/a1403c742f9d590a08b6fd170deec5f50ca8e940/src/mcp/mod.rs#L1610); [C:358](reviews/COMPETITOR-ASSESSMENT-3x7-2026-09-27.md); N3 §P3-28 (local evidence: `/ai-scratch/deputy/codex-pool/out/ns3x3/N3-PROPOSE-DEFECT-CLASS-REDESIGN.md:557`); N9 §P3-28 (local evidence: `/ai-scratch/deputy/codex-pool/out/ns3x3/N9-VOTE-COMPETITIVE-STRATEGIST.md:1063`).

**Design.** Freeze required operation/frontend/backend/OS cells and inject immutable ActiveStore identity everywhere. Migrate one operation family at a time and execute the same effect/authority/failure contract. Unsupported refuses before effects and cannot erase a required advertised cell.

**North Star / moonshot criteria:** DI1, RL1, RL2, SE1.

**Competitors to defeat:** OpenViking, KIP, TencentDB-Agent-Memory, Haystack; no defeat claimed yet.

**TEST-PROVEN acceptance — NOT RUN:** Freeze and execute the required operation × backend × current frontend × advertised OS matrix with malformed/allow/deny/conflict/fault cases. Every supported cell has correct normalized effects and zero hidden SQLite sidecar writes in PostgreSQL deployments. Zero skipped required cells. A greater passing fraction on preregistered shared tasks than each named comparator proves a win; Unsupported earns no pass and cannot remove a required release cell.

**Effort/dependencies:** XL; P3-31 and frozen operation contract; qualification follows domain implementations.

**Existing issue carriers:** [#4108](https://github.com/alphaonedev/ai-memory-mcp/issues/4108), [#3425](https://github.com/alphaonedev/ai-memory-mcp/issues/3425), [#3408](https://github.com/alphaonedev/ai-memory-mcp/issues/3408), [#3415](https://github.com/alphaonedev/ai-memory-mcp/issues/3415), [#3351](https://github.com/alphaonedev/ai-memory-mcp/issues/3351), [#3410](https://github.com/alphaonedev/ai-memory-mcp/issues/3410); extend these scopes and their linked regression issues, do not duplicate them.

<a id="p3-30"></a>

### P3-30 — Carry one resource budget through every nested operation

**Problem/evidence.** Per-child bounds do not bound aggregate bytes, work, fan-out, decompression or retry duration. [src/federation/sync.rs:2507](https://github.com/alphaonedev/ai-memory-mcp/blob/a1403c742f9d590a08b6fd170deec5f50ca8e940/src/federation/sync.rs#L2507); [src/federation/receive.rs:283](https://github.com/alphaonedev/ai-memory-mcp/blob/a1403c742f9d590a08b6fd170deec5f50ca8e940/src/federation/receive.rs#L283); [O:155](reviews/AI-MEMORY-VS-OPENVIKING-3x3-CODE-LEVEL-2026-09-27.md); N3 §P3-30 (local evidence: `/ai-scratch/deputy/codex-pool/out/ns3x3/N3-PROPOSE-DEFECT-CLASS-REDESIGN.md:589`); N9 §P3-30 (local evidence: `/ai-scratch/deputy/codex-pool/out/ns3x3/N9-VOTE-COMPETITIVE-STRATEGIST.md:1097`).

**Design.** Carry one consumable parent budget and absolute deadline through nested work. Reserve bytes/CPU/DB/queues/storage, bound decoded responses before allocation, propagate cancellation and reserve control-plane capacity. Exhaustion preserves accepted durable work and never relaxes authority.

**North Star / moonshot criteria:** PF1, PF2, PF3, RL3.

**Competitors to defeat:** OpenViking, Haystack, ruflo; no defeat claimed yet.

**TEST-PROVEN acceptance — NOT RUN:** For 60-minute adversarial response/decompression/frame/fan-out/slow-peer tests, allocations stay within reserved aggregate budget plus measured 10% allocator allowance; children share the parent deadline/bytes/retry budget. Valid trailing frames survive, accepted durable work never disappears and healthy control-plane p99 stays at most 250 ms on the specified rig. Strictly better bound compliance or 20% better benign goodput than each comparator under equal admitted load proves a win.

**Effort/dependencies:** L; Phase-0 budget contract; integrate each producer as it lands.

**Existing issue carriers:** [#3565](https://github.com/alphaonedev/ai-memory-mcp/issues/3565), [#3287](https://github.com/alphaonedev/ai-memory-mcp/issues/3287), [#3298](https://github.com/alphaonedev/ai-memory-mcp/issues/3298); extend these scopes and their linked regression issues, do not duplicate them.

<a id="p3-02"></a>

### P3-02 — Compile immutable policy snapshots with explicit unavailable states

**Problem/evidence.** Policy/lease read failures can become absence, wildcard semantics skip Deny, and mutable policy reads misbind evidence. [src/storage/mod.rs:22791](https://github.com/alphaonedev/ai-memory-mcp/blob/a1403c742f9d590a08b6fd170deec5f50ca8e940/src/storage/mod.rs#L22791); [src/governance/mod.rs:397](https://github.com/alphaonedev/ai-memory-mcp/blob/a1403c742f9d590a08b6fd170deec5f50ca8e940/src/governance/mod.rs#L397); [C:353](reviews/COMPETITOR-ASSESSMENT-3x7-2026-09-27.md); N3 §P3-02 (local evidence: `/ai-scratch/deputy/codex-pool/out/ns3x3/N3-PROPOSE-DEFECT-CLASS-REDESIGN.md:141`); N9 §P3-02 (local evidence: `/ai-scratch/deputy/codex-pool/out/ns3x3/N9-VOTE-COMPETITIVE-STRATEGIST.md:665`).

**Design.** Publish immutable compiled PolicySnapshot epochs and typed Present/AbsentAllowedBySignedPosture/Unavailable results. Reject malformed or rolled-back snapshots; evaluate and sign the same digest. Unavailable refuses; explicit legitimate Allows still work.

**North Star / moonshot criteria:** SE1, SE2, DI3, RL1, M3.

**Competitors to defeat:** OpenViking, KIP, cognee; no defeat claimed yet.

**TEST-PROVEN acceptance — NOT RUN:** Use an independent glob oracle on exhaustive reduced-alphabet cases and 100,000 generated patterns. Inject policy/lease/key failures and reload races: zero unavailable-to-Allow results or wrong policy digests; valid signed Allows work and Deny is terminal. Strictly higher correct decision-table pass rate than each named comparator under matched rules/faults establishes a win, with unsupported vocabulary excluded. AbsentAllowedBySignedPosture is distinct from Unavailable; freeze the reference grammar, reduced alphabet and exhaustive test count before the 100,000 larger cases.

**Effort/dependencies:** L; P3-01 contract; implementation can proceed beside P3-01.

**Existing issue carriers:** [#3794](https://github.com/alphaonedev/ai-memory-mcp/issues/3794), [#3580](https://github.com/alphaonedev/ai-memory-mcp/issues/3580), [#3395](https://github.com/alphaonedev/ai-memory-mcp/issues/3395); extend these scopes and their linked regression issues, do not duplicate them.

<a id="p3-03"></a>

### P3-03 — Make verified principal and visibility capabilities mandatory at every read and fan-out

**Problem/evidence.** Principal strings, privilege booleans, raw reads and fan-out paths bypass a uniform authorization contract; empty enrollment can leave enforcement inert. [src/store/mod.rs:645](https://github.com/alphaonedev/ai-memory-mcp/blob/a1403c742f9d590a08b6fd170deec5f50ca8e940/src/store/mod.rs#L645); [src/handlers/identity_binding.rs:410](https://github.com/alphaonedev/ai-memory-mcp/blob/a1403c742f9d590a08b6fd170deec5f50ca8e940/src/handlers/identity_binding.rs#L410); [C:353](reviews/COMPETITOR-ASSESSMENT-3x7-2026-09-27.md); N3 §P3-03 (local evidence: `/ai-scratch/deputy/codex-pool/out/ns3x3/N3-PROPOSE-DEFECT-CLASS-REDESIGN.md:157`); N9 §P3-03 (local evidence: `/ai-scratch/deputy/codex-pool/out/ns3x3/N9-VOTE-COMPETITIVE-STRATEGIST.md:682`).

**Design.** Require sealed VerifiedPrincipal and AuthorizedReadScope values at all current reads, mutations, counts, scoring, derived views and event sends. Distinguish read authority from peer custody and export. Tenant boot requires an armed authority source; new IdP or field-policy languages are deferred.

**North Star / moonshot criteria:** SE1, SE2, RL1, DI3.

**Competitors to defeat:** OpenViking, cognee, KIP, mem0; no defeat claimed yet.

**TEST-PROVEN acceptance — NOT RUN:** Execute at least 10,000 private/restricted/shared scope cases across every retained surface and both stores, including counts/ranking/derived skills/fan-out and zero-key tenant boot. Zero unauthorized bytes/effects; all valid controls pass and no hidden-row contribution violates the declared query contract. A win requires fewer matched authorization violations than each comparator, not a larger tool catalog.

**Effort/dependencies:** XL; P3-02 contract, P3-13 command schema.

**Existing issue carriers:** [#4097](https://github.com/alphaonedev/ai-memory-mcp/issues/4097), [#4099](https://github.com/alphaonedev/ai-memory-mcp/issues/4099), [#4100](https://github.com/alphaonedev/ai-memory-mcp/issues/4100), [#4102](https://github.com/alphaonedev/ai-memory-mcp/issues/4102); extend these scopes and their linked regression issues, do not duplicate them.

<a id="p3-04"></a>

### P3-04 — Revocation is a monotone epoch, never a replaceable cache snapshot

**Problem/evidence.** Replaceable refresh caches can reinstall revoked credentials or preserve stale authorization indefinitely. [src/handlers/identity_binding.rs:322](https://github.com/alphaonedev/ai-memory-mcp/blob/a1403c742f9d590a08b6fd170deec5f50ca8e940/src/handlers/identity_binding.rs#L322); [src/handlers/monitoring.rs:70](https://github.com/alphaonedev/ai-memory-mcp/blob/a1403c742f9d590a08b6fd170deec5f50ca8e940/src/handlers/monitoring.rs#L70); [O:151](reviews/AI-MEMORY-VS-OPENVIKING-3x3-CODE-LEVEL-2026-09-27.md); N3 §P3-04 (local evidence: `/ai-scratch/deputy/codex-pool/out/ns3x3/N3-PROPOSE-DEFECT-CLASS-REDESIGN.md:173`); N9 §P3-04 (local evidence: `/ai-scratch/deputy/codex-pool/out/ns3x3/N9-VOTE-COMPETITIVE-STRATEGIST.md:699`).

**Design.** Use monotone credential/revocation epochs with bounded freshness leases and CAS publication. Define local revoke ACK after durable visibility and remote-authority expiry separately. Preserve historical signature checking and independently governed local recovery credentials.

**North Star / moonshot criteria:** SE1, SE2, PF2, RL1.

**Competitors to defeat:** OpenViking, mem0; no defeat claimed yet.

**TEST-PROVEN acceptance — NOT RUN:** Pause refresh, revoke, release the old refresh, restart and roll clocks backward; zero reinstalls or post-bound accepts. The same-process revoke ACK fences later requests; cross-process fixtures enforce their configured authority lease, measured from the authoritative change. Allowed local recovery credentials remain usable. Beat each comparator by fewer stale accepts or a strictly shorter measured bound at the same outage-denial semantics. At equal authority leases, use at least 20% faster revocation if both competitors have zero stale accepts.

**Effort/dependencies:** L; P3-03, P3-31.

**Existing issue carriers:** [#4097](https://github.com/alphaonedev/ai-memory-mcp/issues/4097), [#4108](https://github.com/alphaonedev/ai-memory-mcp/issues/4108); extend these scopes and their linked regression issues, do not duplicate them.

<a id="p3-11"></a>

### P3-11 — Route every outbound connection through one admitted-target capability

**Problem/evidence.** Doctor, reembed, artifact downloads and webhook connection construction escape a common egress decision; redirects and DNS can change the actual target. [src/egress.rs:314](https://github.com/alphaonedev/ai-memory-mcp/blob/a1403c742f9d590a08b6fd170deec5f50ca8e940/src/egress.rs#L314); [src/cli/doctor.rs:4087](https://github.com/alphaonedev/ai-memory-mcp/blob/a1403c742f9d590a08b6fd170deec5f50ca8e940/src/cli/doctor.rs#L4087); [C:354](reviews/COMPETITOR-ASSESSMENT-3x7-2026-09-27.md); N3 §P3-11 (local evidence: `/ai-scratch/deputy/codex-pool/out/ns3x3/N3-PROPOSE-DEFECT-CLASS-REDESIGN.md:285`); N9 §P3-11 (local evidence: `/ai-scratch/deputy/codex-pool/out/ns3x3/N9-VOTE-COMPETITIVE-STRATEGIST.md:799`).

**Design.** Permit connections only through an admitted-target client factory binding parsed scheme, effective port, DNS result, policy epoch and TLS identity. Re-admit redirects and explicit proxy hops. Instrument actual connect/write paths, including subprocesses; denied targets receive no payload or credentials.

**North Star / moonshot criteria:** SE1, SE2, EN1, PF2, M1.

**Competitors to defeat:** OpenViking, Haystack, MemPalace; no defeat claimed yet.

**TEST-PROVEN acceptance — NOT RUN:** Enumerate and instrument all connection constructors, including doctor/reembed/download/webhook/telemetry/backup; denied destinations receive zero payload/credential bytes under URL-parser, DNS-rebind, redirect and proxy faults. Admitted controls work. Federation wrong-CA/peer/signing identity fails; valid staged rotation loses no accepted rows. A win requires strictly fewer matched policy-bypass/identity-acceptance cases than each named comparator. Instrument DNS/connect/write, subprocess and proxy operations; publish the DNS/control-metadata policy instead of claiming zero network bytes.

**Effort/dependencies:** L; P3-02, P3-31; shared channel contract with P3-12.

**Existing issue carriers:** [#4103](https://github.com/alphaonedev/ai-memory-mcp/issues/4103), [#4105](https://github.com/alphaonedev/ai-memory-mcp/issues/4105), [#4106](https://github.com/alphaonedev/ai-memory-mcp/issues/4106); extend these scopes and their linked regression issues, do not duplicate them.

<a id="p2-16"></a>

### P2-16 — Enforce privacy before capture, inference, tracing and export

**Problem/evidence.** Credential regexes and filtering after inference cannot enforce private-span confidentiality across capture, diagnostics and export. [src/secret_screen.rs:150](https://github.com/alphaonedev/ai-memory-mcp/blob/a1403c742f9d590a08b6fd170deec5f50ca8e940/src/secret_screen.rs#L150); [src/secret_screen.rs:597](https://github.com/alphaonedev/ai-memory-mcp/blob/a1403c742f9d590a08b6fd170deec5f50ca8e940/src/secret_screen.rs#L597); A:2396 (local evidence: `/ai-scratch/deputy/codex-pool/out/adv3x3/A5-REFUTE-AI-MEMORY-REALITY.md:2396`); N2 §P2-16 (local evidence: `/ai-scratch/deputy/codex-pool/out/ns3x3/N2-PROPOSE-NORTH-STAR-DELIVERY.md:400`); N9 §P2-16 (local evidence: `/ai-scratch/deputy/codex-pool/out/ns3x3/N9-VOTE-COMPETITIVE-STRATEGIST.md:563`).

**Design.** Apply deterministic protected-span screening before any external call. Refuse on screening failure, export secret references, and preserve protected canonical signed bytes while emitting safe diagnostic projections. Universal PII recognition and semantic-poison immunity remain unproved.

**North Star / moonshot criteria:** SE1, SE2, EN1, M1.

**Competitors to defeat:** OpenViking, Haystack, agentmemory; no defeat claimed yet.

**TEST-PROVEN acceptance — NOT RUN:** Across every current capture/embed/model/log/webhook/export sink and every byte/nesting position in bounded inputs, seeded explicitly protected canaries never leave the permitted boundary, including scanner failure; allowed controls remain intact and signed original bytes verify. Fewer leakage cases than each named comparator on the shared canary/fault suite is required for a win. Semantic poisoning success requires its own held-out [#3570](https://github.com/alphaonedev/ai-memory-mcp/issues/3570) results.

**Effort/dependencies:** L; P3-03, P3-11, P3-13.

**Existing issue carriers:** [#4105](https://github.com/alphaonedev/ai-memory-mcp/issues/4105), [#4104](https://github.com/alphaonedev/ai-memory-mcp/issues/4104), [#4106](https://github.com/alphaonedev/ai-memory-mcp/issues/4106), [#4103](https://github.com/alphaonedev/ai-memory-mcp/issues/4103); extend these scopes and their linked regression issues, do not duplicate them.

<a id="p3-13"></a>

### P3-13 — Generate strict request schemas and canonical wire codecs from domain types

**Problem/evidence.** Handwritten schemas and wire codecs silently coerce invalid CAS fields, panic on Unicode, duplicate keys or consume the next valid frame. [src/mcp/tools/update.rs:233](https://github.com/alphaonedev/ai-memory-mcp/blob/a1403c742f9d590a08b6fd170deec5f50ca8e940/src/mcp/tools/update.rs#L233); [src/mcp/tools/skill_export.rs:759](https://github.com/alphaonedev/ai-memory-mcp/blob/a1403c742f9d590a08b6fd170deec5f50ca8e940/src/mcp/tools/skill_export.rs#L759); [O:149](reviews/AI-MEMORY-VS-OPENVIKING-3x3-CODE-LEVEL-2026-09-27.md); N3 §P3-13 (local evidence: `/ai-scratch/deputy/codex-pool/out/ns3x3/N3-PROPOSE-DEFECT-CLASS-REDESIGN.md:317`); N9 §P3-13 (local evidence: `/ai-scratch/deputy/codex-pool/out/ns3x3/N9-VOTE-COMPETITIVE-STRATEGIST.md:833`).

**Design.** Use closed typed commands, explicit Missing/Null/Value and bounded canonical codecs. Reject malformed security fields before effects; preserve the valid frame after an oversized frame. Start with affected security-critical DTOs and exports, without making a universal generator a prerequisite.

**North Star / moonshot criteria:** DI1, DI2, SE1, PF1, RL1, M2.

**Competitors to defeat:** OpenViking, Haystack, TencentDB-Agent-Memory; no defeat claimed yet.

**TEST-PROVEN acceptance — NOT RUN:** 100,000 bounded fuzz/property inputs for affected codecs: zero panics, duplicate output keys or invalid-security-field coercions. Valid frame B after oversized A executes once for every chunk boundary; supported skill/TOON round trips preserve digests. Strictly fewer silent coercions or losses than each comparator on equivalent commands establishes a win. Valid current supported clients remain compatible or get explicit version refusal. Use 100,000 inputs per affected codec, not one pooled count; reject malformed security fields before effects.

**Effort/dependencies:** L; Frozen operation schema; P3-30 budget contract.

**Existing issue carriers:** [#3454](https://github.com/alphaonedev/ai-memory-mcp/issues/3454), [#3396](https://github.com/alphaonedev/ai-memory-mcp/issues/3396), [#3408](https://github.com/alphaonedev/ai-memory-mcp/issues/3408), [#3415](https://github.com/alphaonedev/ai-memory-mcp/issues/3415), [#3417](https://github.com/alphaonedev/ai-memory-mcp/issues/3417), [#3370](https://github.com/alphaonedev/ai-memory-mcp/issues/3370), [#3368](https://github.com/alphaonedev/ai-memory-mcp/issues/3368), [#3369](https://github.com/alphaonedev/ai-memory-mcp/issues/3369), [#3805](https://github.com/alphaonedev/ai-memory-mcp/issues/3805); extend these scopes and their linked regression issues, do not duplicate them.

<a id="p3-10"></a>

### P3-10 — Use epoch-fenced circuit breakers and typed model outcomes

**Problem/evidence.** HTTP success is confused with usable model output; breaker completion races can reopen an obsolete probe. [src/llm.rs:1039](https://github.com/alphaonedev/ai-memory-mcp/blob/a1403c742f9d590a08b6fd170deec5f50ca8e940/src/llm.rs#L1039); [src/llm.rs:1886](https://github.com/alphaonedev/ai-memory-mcp/blob/a1403c742f9d590a08b6fd170deec5f50ca8e940/src/llm.rs#L1886); [C:167](reviews/COMPETITOR-ASSESSMENT-3x7-2026-09-27.md); N3 §P3-10 (local evidence: `/ai-scratch/deputy/codex-pool/out/ns3x3/N3-PROPOSE-DEFECT-CLASS-REDESIGN.md:269`); N9 §P3-10 (local evidence: `/ai-scratch/deputy/codex-pool/out/ns3x3/N9-VOTE-COMPETITIVE-STRATEGIST.md:784`).

**Design.** Represent usable, abstain, invalid, unavailable and cancelled outcomes explicitly. Fence breaker transitions by epoch/probe identity and carry one deadline across retries. Repair existing clients independently of a new router; apply decision-client regressions when that carrier lands.

**North Star / moonshot criteria:** SE2, PF1, PF3, RL3, M7.

**Competitors to defeat:** agentmemory, Haystack, OpenViking; no defeat claimed yet.

**TEST-PROVEN acceptance — NOT RUN:** Model-check epoch/probe/cancel interleavings and 100,000 typed outcomes: exactly one half-open probe, no stale reset, no invalid semantic result treated as usable, deadline plus 100 ms fixture tolerance at most. Valid calls recover after cooldown. Beat each named comparator by fewer wrong admissions/unbounded calls under identical budgets, or record parity.

**Effort/dependencies:** M; P3-30 budget contract.

**Existing issue carriers:** [#4092](https://github.com/alphaonedev/ai-memory-mcp/issues/4092); extend these scopes and their linked regression issues, do not duplicate them.

### Commit, evidence and semantic preservation

<a id="p3-01"></a>

### P3-01 — One transaction owns authorization, revision, lifecycle and mutation

**Problem/evidence.** Authorization, source revision, content, lifecycle, audit, quota and delivery intent cross consistency boundaries; a second writer can deadlock escalation. [src/store/postgres.rs:23860](https://github.com/alphaonedev/ai-memory-mcp/blob/a1403c742f9d590a08b6fd170deec5f50ca8e940/src/store/postgres.rs#L23860); [src/store/sqlite.rs:821](https://github.com/alphaonedev/ai-memory-mcp/blob/a1403c742f9d590a08b6fd170deec5f50ca8e940/src/store/sqlite.rs#L821); [C:358](reviews/COMPETITOR-ASSESSMENT-3x7-2026-09-27.md); N3 §P3-01 (local evidence: `/ai-scratch/deputy/codex-pool/out/ns3x3/N3-PROPOSE-DEFECT-CLASS-REDESIGN.md:125`); N9 §P3-01 (local evidence: `/ai-scratch/deputy/codex-pool/out/ns3x3/N9-VOTE-COMPETITIVE-STRATEGIST.md:648`).

**Design.** Implement one transaction-backed apply operation owning the complete committed tuple. Re-read authority and revisions under transaction locks; use a canonical PostgreSQL lock order and SQLite write serialization. Persist escalation intent within that transaction. Keep model/network calls outside it.

**North Star / moonshot criteria:** DI1, DI2, SE1, SE2, RL1, PF3.

**Competitors to defeat:** OpenViking, TencentDB-Agent-Memory, cognee; no defeat claimed yet.

**TEST-PROVEN acceptance — NOT RUN:** Across both stores and two OS processes, run 10,000 barrier-controlled ownership/CAS/patch/lifecycle/quota/escalation schedules plus fault injection after every persistence boundary. Each acknowledged mutation has one coherent state+revision+signed-evidence+net-quota+outbox tuple; failures have none, except explicit durable pending outcomes. Zero partial or unauthorized effects and fewer violations than each named comparator on supported logical mutations are necessary for a win. Successful safe operations must progress within the fixture deadline. Durable escalation must return within the declared 5 s fixture budget; no lost patch fields or quota charged twice.

**Effort/dependencies:** XL; Frozen policy, signer and operation contracts from phase 0.

**Existing issue carriers:** [#4095](https://github.com/alphaonedev/ai-memory-mcp/issues/4095), [#4097](https://github.com/alphaonedev/ai-memory-mcp/issues/4097), [#3794](https://github.com/alphaonedev/ai-memory-mcp/issues/3794); extend these scopes and their linked regression issues, do not duplicate them.

<a id="p3-06"></a>

### P3-06 — Make signed evidence part of commit, with an explicit signer policy

**Problem/evidence.** Some successful mutations can outlive failed audit append; an optional signature or host witness does not prove the author's action. [src/storage/mod.rs:10159](https://github.com/alphaonedev/ai-memory-mcp/blob/a1403c742f9d590a08b6fd170deec5f50ca8e940/src/storage/mod.rs#L10159); [src/signed_events.rs:2931](https://github.com/alphaonedev/ai-memory-mcp/blob/a1403c742f9d590a08b6fd170deec5f50ca8e940/src/signed_events.rs#L2931); [C:35](reviews/COMPETITOR-ASSESSMENT-3x7-2026-09-27.md); N3 §P3-06 (local evidence: `/ai-scratch/deputy/codex-pool/out/ns3x3/N3-PROPOSE-DEFECT-CLASS-REDESIGN.md:205`); N9 §P3-06 (local evidence: `/ai-scratch/deputy/codex-pool/out/ns3x3/N9-VOTE-COMPETITIVE-STRATEGIST.md:733`).

**Design.** Make role-correct SignedMutationEnvelope persistence a condition of CommitReceipt. Bind principal, operation, policy, before/after digests and effects atomically through P3-01. Refuse unusable signers before mutation; legacy unsigned rows remain explicitly unverified.

**North Star / moonshot criteria:** DI1, DI2, DI3, M5, SE2, RL1.

**Competitors to defeat:** OpenViking, cognee, TencentDB-Agent-Memory; no defeat claimed yet.

**TEST-PROVEN acceptance — NOT RUN:** Every admitted mutating operation on both stores commits a valid role-correct envelope or makes no authoritative change on signer/append failure. Tamper each signed field and substitute host for author credentials: verification must fail. Across 10,000 faulted operations require 100% signed committed-operation coverage and strictly higher coverage than each named comparator on shared operations. Legacy unsigned rows stay unverified.

**Effort/dependencies:** XL; P3-01, P3-02, P3-03.

**Existing issue carriers:** [#3376](https://github.com/alphaonedev/ai-memory-mcp/issues/3376), [#3575](https://github.com/alphaonedev/ai-memory-mcp/issues/3575), [#4096](https://github.com/alphaonedev/ai-memory-mcp/issues/4096); extend these scopes and their linked regression issues, do not duplicate them.

<a id="p2-04"></a>

### P2-04 — Make acknowledgement mean power-loss durability

**Problem/evidence.** SQLite defaults to NORMAL; aborting a process does not exercise loss of unflushed storage writes. [src/storage/connection.rs:542](https://github.com/alphaonedev/ai-memory-mcp/blob/a1403c742f9d590a08b6fd170deec5f50ca8e940/src/storage/connection.rs#L542); [src/write_receipt.rs:54](https://github.com/alphaonedev/ai-memory-mcp/blob/a1403c742f9d590a08b6fd170deec5f50ca8e940/src/write_receipt.rs#L54); [C:360](reviews/COMPETITOR-ASSESSMENT-3x7-2026-09-27.md); N2 §P2-04 (local evidence: `/ai-scratch/deputy/codex-pool/out/ns3x3/N2-PROPOSE-NORTH-STAR-DELIVERY.md:136`); N9 §P2-04 (local evidence: `/ai-scratch/deputy/codex-pool/out/ns3x3/N9-VOTE-COMPETITIVE-STRATEGIST.md:531`).

**Design.** Make the mission-critical durability setting explicit and verified before writes; distinguish local durability, replica acknowledgements and incomplete quorum in receipts. Qualify the actual filesystem/device stack with an external acknowledged-digest ledger and hard resets.

**North Star / moonshot criteria:** DI1, DI2, RL2.

**Competitors to defeat:** agentmemory, TencentDB-Agent-Memory; no defeat claimed yet.

**TEST-PROVEN acceptance — NOT RUN:** Run at least 100 randomized hard-reset trials per admitted backend/storage stack with an independent acknowledged digest/revision oracle; zero acknowledged loss or altered revisions in the declared durable profile. A process abort alone fails this gate. Against agentmemory and TencentDB-Agent-Memory require strictly lower ACK-loss rate at equivalent durability settings; ties are parity. Report local/replica ACK and incomplete quorum separately. The reset fixture must actually discard unflushed writes; otherwise label the outcome VM-reset persistence only and state flush assumptions.

**Effort/dependencies:** L; P3-01, P3-06.

**Existing issue carriers:** [#3559](https://github.com/alphaonedev/ai-memory-mcp/issues/3559), [#3561](https://github.com/alphaonedev/ai-memory-mcp/issues/3561); extend these scopes and their linked regression issues, do not duplicate them.

<a id="p3-07"></a>

### P3-07 — Anchor audit completeness across restart and tail loss

**Problem/evidence.** A hash chain cannot detect deletion of its own tail without an independently retained head; loose sequence checks can certify gaps. [src/audit.rs:282](https://github.com/alphaonedev/ai-memory-mcp/blob/a1403c742f9d590a08b6fd170deec5f50ca8e940/src/audit.rs#L282); [src/audit.rs:826](https://github.com/alphaonedev/ai-memory-mcp/blob/a1403c742f9d590a08b6fd170deec5f50ca8e940/src/audit.rs#L826); [U:872](reviews/US-AGENT-MEMORY-MARKET-3x3-AUDIT-2026-09-27.md); N3 §P3-07 (local evidence: `/ai-scratch/deputy/codex-pool/out/ns3x3/N3-PROPOSE-DEFECT-CLASS-REDESIGN.md:221`); N9 §P3-07 (local evidence: `/ai-scratch/deputy/codex-pool/out/ns3x3/N9-VOTE-COMPETITIVE-STRATEGIST.md:750`).

**Design.** Anchor signed store/epoch/sequence/root checkpoints in an operator-controlled independent witness. Verify continuity and rollback against that expectation, with CompleteToAnchor, UnanchoredTail, Gap and Unavailable states. Bound the unanchored window; do not invent completeness after witness failure.

**North Star / moonshot criteria:** DI1, DI3, M5, RL2.

**Competitors to defeat:** OpenViking, cognee, Vestige; no defeat claimed yet.

**TEST-PROVEN acceptance — NOT RUN:** From a 10,000-event chain delete each interior position and suffix, restart and replay. Detect every deletion at/before the independently retained head; never certify an unknown unanchored tail or stale/rollback checkpoint as Complete. Zero false-complete verdicts and fewer than each comparator under equal retained-anchor assumptions are required for a win. Enforce the configured unanchored-window policy during witness outage. Include reserved-but-unwritten gaps and whole-store rollback, with zero false alarms on valid histories.

**Effort/dependencies:** L; P3-06, P2-04.

**Existing issue carriers:** [#3798](https://github.com/alphaonedev/ai-memory-mcp/issues/3798), [#4109](https://github.com/alphaonedev/ai-memory-mcp/issues/4109); extend these scopes and their linked regression issues, do not duplicate them.

<a id="p2-31"></a>

### P2-31 — Make record-stop a cross-process commit fence with recoverable resume

**Problem/evidence.** A handwritten read-only inventory and process-local checks cannot establish a cross-process stop fence. Point fixes at the pin do not prove complete coverage. [src/storage/record_stop.rs:278](https://github.com/alphaonedev/ai-memory-mcp/blob/a1403c742f9d590a08b6fd170deec5f50ca8e940/src/storage/record_stop.rs#L278); [src/storage/record_stop.rs:345](https://github.com/alphaonedev/ai-memory-mcp/blob/a1403c742f9d590a08b6fd170deec5f50ca8e940/src/storage/record_stop.rs#L345); A:2802 (local evidence: `/ai-scratch/deputy/codex-pool/out/adv3x3/A5-REFUTE-AI-MEMORY-REALITY.md:2802`); N2 §P2-31 (local evidence: `/ai-scratch/deputy/codex-pool/out/ns3x3/N2-PROPOSE-NORTH-STAR-DELIVERY.md:730`); N8 §P2-31 (local evidence: `/ai-scratch/deputy/codex-pool/out/ns3x3/N8-VOTE-CHIEF-ARCHITECT.md:446`).

**Design.** Check a durable monotone stop epoch inside every mutation transaction, including hidden maintenance. Specify separately authorized forensic writes, transactions already linearized, unreachable peers and external effects. Signed resume recovers pending work without making remote vendor permission a dependency.

**North Star / moonshot criteria:** SE1, SE2, DI1, DI2, M3, RL2, RL3.

**Competitors to defeat:** KIP, ruflo, OpenViking; no defeat claimed yet.

**TEST-PROVEN acceptance — NOT RUN:** Pause every mutator before its commit fence, stop from a second process, then release it on both stores: zero ordinary commits after stop linearization. Exhaust the effect registry including read-side maintenance; signed resume preserves every acknowledged operation. Fleet partitions report unacknowledged members. Strictly fewer post-fence writes or lost/duplicated accepted operations than each named rival on supported stop/cancel work; with equal safety, at least 20% lower complete stop/resume p99. Unsupported fleet stop is not an observed corrupt commit. Apply G independently to every named target above; record losses and ties.

**Effort/dependencies:** XL; P3-01, P3-02, P3-06.

**Existing issue carriers:** [#3558](https://github.com/alphaonedev/ai-memory-mcp/issues/3558), [#3569](https://github.com/alphaonedev/ai-memory-mcp/issues/3569); extend these scopes and their linked regression issues, do not duplicate them.

<a id="p3-08"></a>

### P3-08 — Replace destructive summaries with revision-bound semantic mutation plans

**Problem/evidence.** Content-free summaries, stale source snapshots and premature vector retirement can turn failed inference into successful destructive replacement. [src/handlers/power_consolidation.rs:100](https://github.com/alphaonedev/ai-memory-mcp/blob/a1403c742f9d590a08b6fd170deec5f50ca8e940/src/handlers/power_consolidation.rs#L100); [src/mcp/tools/consolidate.rs:172](https://github.com/alphaonedev/ai-memory-mcp/blob/a1403c742f9d590a08b6fd170deec5f50ca8e940/src/mcp/tools/consolidate.rs#L172); [C:354](reviews/COMPETITOR-ASSESSMENT-3x7-2026-09-27.md); N3 §P3-08 (local evidence: `/ai-scratch/deputy/codex-pool/out/ns3x3/N3-PROPOSE-DEFECT-CLASS-REDESIGN.md:237`); N9 §P3-08 (local evidence: `/ai-scratch/deputy/codex-pool/out/ns3x3/N9-VOTE-COMPETITIVE-STRATEGIST.md:767`).

**Design.** Use revision-bound semantic plans with PreserveAndDefer for missing, invalid or failed generation. Commit replacement, lineage, source disposition and projection intents atomically; keep originals searchable under authority. A model-generated summary is never sufficient deletion authority.

**North Star / moonshot criteria:** DI1, DI2, SE2, RL2, M2, M4.

**Competitors to defeat:** OpenViking, MemPalace, mem0, TencentDB-Agent-Memory; no defeat claimed yet.

**TEST-PROVEN acceptance — NOT RUN:** Across HTTP/MCP/CLI/curator and both stores, absent/empty/whitespace/timeout/quota/error/stale-source cases preserve all acknowledged source bytes and authorized recall reachability; no source/vector retirement precedes committed replacement+lineage. Inject every persistence boundary. Fewer lost/unreachable source facts than each comparator on the same transformations, with successful useful consolidation yield at least 95% of its baseline, is required for superiority; ties remain parity. For zero-loss ties with MemPalace/mem0, the alternative win requires at least 20% fewer total context tokens at equal held-out factual accuracy and spend.

**Effort/dependencies:** L; P3-01, P3-06, P3-10.

**Existing issue carriers:** [#4092](https://github.com/alphaonedev/ai-memory-mcp/issues/4092), [#4094](https://github.com/alphaonedev/ai-memory-mcp/issues/4094), [#4095](https://github.com/alphaonedev/ai-memory-mcp/issues/4095), [#3793](https://github.com/alphaonedev/ai-memory-mcp/issues/3793); extend these scopes and their linked regression issues, do not duplicate them.

### Replication, projections and recoverable lifecycle

<a id="p3-14"></a>

### P3-14 — Replace whole-row-clock pseudo-CRDTs with a closed, bounded merge algebra

**Problem/evidence.** Mixed timestamp orderings, whole-row clock inheritance and unbounded unions make merge order-dependent and receiver-invalid. [src/models/crdt_merge.rs:311](https://github.com/alphaonedev/ai-memory-mcp/blob/a1403c742f9d590a08b6fd170deec5f50ca8e940/src/models/crdt_merge.rs#L311); [src/models/crdt_merge.rs:419](https://github.com/alphaonedev/ai-memory-mcp/blob/a1403c742f9d590a08b6fd170deec5f50ca8e940/src/models/crdt_merge.rs#L419); [C:360](reviews/COMPETITOR-ASSESSMENT-3x7-2026-09-27.md); N3 §P3-14 (local evidence: `/ai-scratch/deputy/codex-pool/out/ns3x3/N3-PROPOSE-DEFECT-CLASS-REDESIGN.md:333`); N9 §P3-14 (local evidence: `/ai-scratch/deputy/codex-pool/out/ns3x3/N9-VOTE-COMPETITIVE-STRATEGIST.md:848`).

**Design.** Specify a finite versioned merge algebra with immutable operation identity, per-field causal versions and preserved conflict alternatives. Admit or backpressure before ACK; compact only under a declared causal horizon. Test mixed-version refusal/rebootstrap instead of introducing another general CRDT framework.

**North Star / moonshot criteria:** DI1, DI2, PF1, PF2, RL1, RL2, M2.

**Competitors to defeat:** ruflo, agentmemory, MemPalace; no defeat claimed yet.

**TEST-PROVEN acceptance — NOT RUN:** One million generated triples plus all small counterexample permutations satisfy commutativity, associativity, idempotence and receiver-validation closure; three persisted peers converge after duplicate/reorder/partition histories with no admitted evidence silently discarded. Old incompatible peers refuse or rebootstrap explicitly. Fewer divergent or lost-conflict histories than each named comparator on supported shared semantics is a win; unsupported replication is not a runtime failure.

**Effort/dependencies:** XL; P3-01, P3-13; shared replay/erasure protocol contracts.

**Existing issue carriers:** [#4098](https://github.com/alphaonedev/ai-memory-mcp/issues/4098), [#4101](https://github.com/alphaonedev/ai-memory-mcp/issues/4101); extend these scopes and their linked regression issues, do not duplicate them.

<a id="p3-15"></a>

### P3-15 — Use durable operation acknowledgments and opaque resumable replication cursors

**Problem/evidence.** Null/absent cursors, premature nonce consumption and false no-op ACKs can skip accepted operations or defeat retries. [src/federation/receive.rs:346](https://github.com/alphaonedev/ai-memory-mcp/blob/a1403c742f9d590a08b6fd170deec5f50ca8e940/src/federation/receive.rs#L346); [src/handlers/federation_receive.rs:4153](https://github.com/alphaonedev/ai-memory-mcp/blob/a1403c742f9d590a08b6fd170deec5f50ca8e940/src/handlers/federation_receive.rs#L4153); [C:359](reviews/COMPETITOR-ASSESSMENT-3x7-2026-09-27.md); N3 §P3-15 (local evidence: `/ai-scratch/deputy/codex-pool/out/ns3x3/N3-PROPOSE-DEFECT-CLASS-REDESIGN.md:349`); N9 §P3-15 (local evidence: `/ai-scratch/deputy/codex-pool/out/ns3x3/N9-VOTE-COMPETITIVE-STRATEGIST.md:865`).

**Design.** Persist operation identity and Applied/AlreadyApplied/DurablePending/TerminalRefused outcomes atomically. Use distinct end/resume/legacy cursor states and matching receiver/digest receipts. Separate transport anti-replay from operation idempotency and local ACK from replicated-W.

**North Star / moonshot criteria:** DI1, DI2, RL1, RL2, PF3.

**Competitors to defeat:** MemPalace, ruflo, agentmemory; no defeat claimed yet.

**TEST-PROVEN acceptance — NOT RUN:** Replicate 100,000 operations with 10,000 equal timestamps through three persisted nodes; duplicate, reorder, truncate pages and restart. Zero skipped revisions, false Applied receipts or consumed-retry nonces; every accepted deferred operation is durable and reaches applied or explicit terminal refusal once prerequisites recover. Fewer lost/false-ACK outcomes than each named comparator under equal retry budgets proves a win. Freeze and meet a drain deadline after connectivity, prerequisites and fair retries recover; no indefinitely pending accepted work.

**Effort/dependencies:** L; P3-01, P3-13, P3-14 protocol.

**Existing issue carriers:** [#4101](https://github.com/alphaonedev/ai-memory-mcp/issues/4101), [#3560](https://github.com/alphaonedev/ai-memory-mcp/issues/3560), [#3559](https://github.com/alphaonedev/ai-memory-mcp/issues/3559), [#3572](https://github.com/alphaonedev/ai-memory-mcp/issues/3572); extend these scopes and their linked regression issues, do not duplicate them.

<a id="p3-16"></a>

### P3-16 — Make erasure a transactionally enforced replication epoch

**Problem/evidence.** Tombstone checks outside the write transaction race with inbound/restore; configured workers are mistaken for running erasure service. [src/storage/mod.rs:18304](https://github.com/alphaonedev/ai-memory-mcp/blob/a1403c742f9d590a08b6fd170deec5f50ca8e940/src/storage/mod.rs#L18304); [src/store/postgres.rs:25295](https://github.com/alphaonedev/ai-memory-mcp/blob/a1403c742f9d590a08b6fd170deec5f50ca8e940/src/store/postgres.rs#L25295); [U:899](reviews/US-AGENT-MEMORY-MARKET-3x3-AUDIT-2026-09-27.md); N3 §P3-16 (local evidence: `/ai-scratch/deputy/codex-pool/out/ns3x3/N3-PROPOSE-DEFECT-CLASS-REDESIGN.md:365`); N9 §P3-16 (local evidence: `/ai-scratch/deputy/codex-pool/out/ns3x3/N9-VOTE-COMPETITIVE-STRATEGIST.md:882`).

**Design.** Commit erasure epoch, row/key disposition and outbox together; every apply/restore locks and checks that epoch. Report actual worker leases. Retain negative state until a membership-aware causal floor permits compaction, then require stale-peer rebootstrap. Declare excluded backups/copies.

**North Star / moonshot criteria:** DI1, DI2, SE1, RL1, RL2, PF1.

**Competitors to defeat:** OpenViking, ruflo, agentmemory; no defeat claimed yet.

**TEST-PROVEN acceptance — NOT RUN:** Race erasure/inbound/restore on separate connections in both stores; reconnect stale peers and restore old snapshots. Zero resurrection, no false drainable/fleet-erased status, durable erasure intent survives disabled workers. Compact only behind a tested causal floor; stale peers rebootstrap. A win requires fewer reappearances or greater verified sink coverage than each comparator on the same declared custody inventory; offline excluded copies remain unproven.

**Effort/dependencies:** XL; P3-01, P3-14 and P3-15 protocol contracts.

**Existing issue carriers:** [#3285](https://github.com/alphaonedev/ai-memory-mcp/issues/3285), [#3795](https://github.com/alphaonedev/ai-memory-mcp/issues/3795), [#4101](https://github.com/alphaonedev/ai-memory-mcp/issues/4101); extend these scopes and their linked regression issues, do not duplicate them.

<a id="p3-17"></a>

### P3-17 — Bind provenance to exact bytes before redaction, merge or dequarantine

**Problem/evidence.** Matching IDs do not attest matching bytes; redaction, merge and release can disconnect signature verdicts, content and embeddings. [src/handlers/federation_receive.rs:2989](https://github.com/alphaonedev/ai-memory-mcp/blob/a1403c742f9d590a08b6fd170deec5f50ca8e940/src/handlers/federation_receive.rs#L2989); [src/handlers/federation_signing_check.rs:700](https://github.com/alphaonedev/ai-memory-mcp/blob/a1403c742f9d590a08b6fd170deec5f50ca8e940/src/handlers/federation_signing_check.rs#L700); [C:363](reviews/COMPETITOR-ASSESSMENT-3x7-2026-09-27.md); N3 §P3-17 (local evidence: `/ai-scratch/deputy/codex-pool/out/ns3x3/N3-PROPOSE-DEFECT-CLASS-REDESIGN.md:381`); N9 §P3-17 (local evidence: `/ai-scratch/deputy/codex-pool/out/ns3x3/N9-VOTE-COMPETITIVE-STRATEGIST.md:899`).

**Design.** Verify immutable origin bytes first. Preserve the original verdict, sign transformed derivatives under their actual role, and bind release permission to exact row/digest/revision. Attach vectors only to matching winning content and model space. Later [#4017](https://github.com/alphaonedev/ai-memory-mcp/issues/4017) is a landing test, not assumed baseline code.

**North Star / moonshot criteria:** DI1, DI3, SE1, SE2, M5, RL1.

**Competitors to defeat:** OpenViking, TencentDB-Agent-Memory, mem0; no defeat claimed yet.

**TEST-PROVEN acceptance — NOT RUN:** Run forged, redacted, same-ID/different-bytes, cross-ID and local-winning merge cases on both adapters: zero signature laundering, unjustified release or vector/content mismatch. Valid controls retain independently verifiable attribution. Strictly greater exact-byte provenance coverage than each named comparator on the common transform trace proves a win. No truth claim follows from a valid signature. Compare equal successful import yield; no credit for dropping all transformed records.

**Effort/dependencies:** L; P3-06, P3-13, P3-14.

**Existing issue carriers:** [#3575](https://github.com/alphaonedev/ai-memory-mcp/issues/3575), [#4096](https://github.com/alphaonedev/ai-memory-mcp/issues/4096), [#4104](https://github.com/alphaonedev/ai-memory-mcp/issues/4104); extend these scopes and their linked regression issues, do not duplicate them.

<a id="p3-21"></a>

### P3-21 — Migrations produce verified schema manifests before write service resumes

**Problem/evidence.** Rung-specific trigger reconstruction, counts outside conversion, nested pool acquisition and error-string matching can certify an incomplete migration. [src/store/postgres.rs:10070](https://github.com/alphaonedev/ai-memory-mcp/blob/a1403c742f9d590a08b6fd170deec5f50ca8e940/src/store/postgres.rs#L10070); [src/store/postgres.rs:10130](https://github.com/alphaonedev/ai-memory-mcp/blob/a1403c742f9d590a08b6fd170deec5f50ca8e940/src/store/postgres.rs#L10130); [C:360](reviews/COMPETITOR-ASSESSMENT-3x7-2026-09-27.md); N3 §P3-21 (local evidence: `/ai-scratch/deputy/codex-pool/out/ns3x3/N3-PROPOSE-DEFECT-CLASS-REDESIGN.md:445`); N9 §P3-21 (local evidence: `/ai-scratch/deputy/codex-pool/out/ns3x3/N9-VOTE-COMPETITIVE-STRATEGIST.md:961`).

**Design.** Verify a manifest of tables, triggers, indexes, extensions and invariants before write service. Journal nontransactional phases and run-owned compensation; keep incomplete stores write-blocked but diagnostically recoverable. Use baseline snapshots before migration and test resumed/forward recovery.

**North Star / moonshot criteria:** DI1, DI2, RL1, RL2, PF3.

**Competitors to defeat:** cognee, OpenViking, agentmemory; no defeat claimed yet.

**TEST-PROVEN acceptance — NOT RUN:** Every supported historical schema/feature combination has a fixture. Fault each migration phase, missing trigger/orphan graph/concurrent vector write/pool-size-one case: zero unapproved loss, false-current stamp or write service over incomplete migration. Recover valid upgrades via resume or documented staging restore. Fewer unrecoverable/false-success upgrades than each comparator on equivalent fault boundaries proves a win.

**Effort/dependencies:** L; P3-31; frozen schema manifest and baseline recovery fixture.

**Existing issue carriers:** [#4111](https://github.com/alphaonedev/ai-memory-mcp/issues/4111), [#3477](https://github.com/alphaonedev/ai-memory-mcp/issues/3477), [#3500](https://github.com/alphaonedev/ai-memory-mcp/issues/3500); extend these scopes and their linked regression issues, do not duplicate them.

<a id="p3-19"></a>

### P3-19 — Treat every derived index as a versioned, recoverable projection

**Problem/evidence.** Derived indexes can be stale or corrupted while reporting clean; reordered projection work can resurrect removed edges. [src/storage/mod.rs:22337](https://github.com/alphaonedev/ai-memory-mcp/blob/a1403c742f9d590a08b6fd170deec5f50ca8e940/src/storage/mod.rs#L22337); [src/store/postgres.rs:13519](https://github.com/alphaonedev/ai-memory-mcp/blob/a1403c742f9d590a08b6fd170deec5f50ca8e940/src/store/postgres.rs#L13519); [C:360](reviews/COMPETITOR-ASSESSMENT-3x7-2026-09-27.md); N3 §P3-19 (local evidence: `/ai-scratch/deputy/codex-pool/out/ns3x3/N3-PROPOSE-DEFECT-CLASS-REDESIGN.md:413`); N9 §P3-19 (local evidence: `/ai-scratch/deputy/codex-pool/out/ns3x3/N9-VOTE-COMPETITIVE-STRATEGIST.md:929`).

**Design.** Write revision-bound projection jobs with authoritative commits. Publish only matching generations, expose dirty watermarks and Unverified state, and rebuild then atomically switch validated indexes. Safe fallback or explicit incompleteness precedes readiness; no new backend is required.

**North Star / moonshot criteria:** DI1, DI2, RL1, RL2, PF1, M4.

**Competitors to defeat:** agentmemory, OpenViking, cognee; no defeat claimed yet.

**TEST-PROVEN acceptance — NOT RUN:** On 100,000 rows, corrupt FTS, pause AGE, reorder projection jobs, edit during rebuild and crash reembed: zero false-clean checks, resurrected edges or incompatible-vector comparisons. Every source remains safely discoverable or returns explicit incomplete status; drain/rebuild restores oracle coverage within configured resource budgets. Fewer silent incompleteness failures, or 20% faster verified readiness at equal recall/resources, than each comparator proves a win.

**Effort/dependencies:** L; P3-01, P3-13; schema manifest contract with P3-21.

**Existing issue carriers:** [#4110](https://github.com/alphaonedev/ai-memory-mcp/issues/4110), [#4112](https://github.com/alphaonedev/ai-memory-mcp/issues/4112); extend these scopes and their linked regression issues, do not duplicate them.

<a id="p3-20"></a>

### P3-20 — Keep containment and temporal truth on the authoritative relational graph

**Problem/evidence.** Safety traversal of an asynchronous graph can miss contaminated dependents; wrong-store access and inconsistent locks undermine containment. [src/store/postgres/lineage.rs:370](https://github.com/alphaonedev/ai-memory-mcp/blob/a1403c742f9d590a08b6fd170deec5f50ca8e940/src/store/postgres/lineage.rs#L370); [src/storage/mod.rs:13804](https://github.com/alphaonedev/ai-memory-mcp/blob/a1403c742f9d590a08b6fd170deec5f50ca8e940/src/storage/mod.rs#L13804); [C:355](reviews/COMPETITOR-ASSESSMENT-3x7-2026-09-27.md); N3 §P3-20 (local evidence: `/ai-scratch/deputy/codex-pool/out/ns3x3/N3-PROPOSE-DEFECT-CLASS-REDESIGN.md:429`); N9 §P3-20 (local evidence: `/ai-scratch/deputy/codex-pool/out/ns3x3/N9-VOTE-COMPETITIVE-STRATEGIST.md:946`).

**Design.** Use the authoritative relational graph and one lock order for containment, cycle checks, invalidation and restore. A signed plan records affected revisions and a resumable bounded frontier; AGE may accelerate only when coverage is established. Refuse wrong store identity.

**North Star / moonshot criteria:** DI1, DI2, SE1, RL1, RL2, M3.

**Competitors to defeat:** OpenViking, KIP, ruflo; no defeat claimed yet.

**TEST-PROVEN acceptance — NOT RUN:** Pause AGE and race edge commits/rewind in 10,000 lock schedules. Containment covers every authoritative reachable affected record or reports a durable resumable incomplete frontier; never false success, wrong-store certification or deadlock. Compare completed containment at equal frontier bounds: fewer surviving contaminated dependents, or 20% lower p99 with equal safety, than each named comparator establishes a win.

**Effort/dependencies:** XL; P3-01, P3-03, P3-30; independent of AGE availability.

**Existing issue carriers:** [#3793](https://github.com/alphaonedev/ai-memory-mcp/issues/3793), [#3569](https://github.com/alphaonedev/ai-memory-mcp/issues/3569), [#3349](https://github.com/alphaonedev/ai-memory-mcp/issues/3349), [#3336](https://github.com/alphaonedev/ai-memory-mcp/issues/3336); extend these scopes and their linked regression issues, do not duplicate them.

<a id="p3-22"></a>

### P3-22 — Retention and garbage collection operate on immutable victim sets

**Problem/evidence.** Archiving one predicate snapshot then deleting another loses required revision history; replay can overwrite the useful archive. [src/storage/mod.rs:18607](https://github.com/alphaonedev/ai-memory-mcp/blob/a1403c742f9d590a08b6fd170deec5f50ca8e940/src/storage/mod.rs#L18607); [src/store/postgres.rs:25284](https://github.com/alphaonedev/ai-memory-mcp/blob/a1403c742f9d590a08b6fd170deec5f50ca8e940/src/store/postgres.rs#L25284); [C:354](reviews/COMPETITOR-ASSESSMENT-3x7-2026-09-27.md); N3 §P3-22 (local evidence: `/ai-scratch/deputy/codex-pool/out/ns3x3/N3-PROPOSE-DEFECT-CLASS-REDESIGN.md:461`); N9 §P3-22 (local evidence: `/ai-scratch/deputy/codex-pool/out/ns3x3/N9-VOTE-COMPETITIVE-STRATEGIST.md:978`).

**Design.** Lock exact victim IDs/revisions/digests and archive/delete that immutable set in bounded transactions. Keep operation-keyed immutable archives, make no-op replay archive-neutral, and record authorized erasure explicitly. Source links are part of the recovery contract.

**North Star / moonshot criteria:** DI1, DI2, PF1, PF3, RL1, RL2.

**Competitors to defeat:** MemPalace, OpenViking, TencentDB-Agent-Memory; no defeat claimed yet.

**TEST-PROVEN acceptance — NOT RUN:** Concurrent expiry changes, no-op merge replay and crashes after archive/delete steps preserve exact required archive revisions/links or explicit authorized-erasure receipts. For a preregistered 100-row fixture batch p99 lock hold is at most 100 ms and foreground goodput at least 80% of no-GC baseline. Fewer unrecoverable revisions than each named comparator at equal retention semantics proves a win.

**Effort/dependencies:** L; P3-01, P3-06, P3-30.

**Existing issue carriers:** [#3287](https://github.com/alphaonedev/ai-memory-mcp/issues/3287), [#3793](https://github.com/alphaonedev/ai-memory-mcp/issues/3793), [#4094](https://github.com/alphaonedev/ai-memory-mcp/issues/4094); extend these scopes and their linked regression issues, do not duplicate them.

<a id="p3-24"></a>

### P3-24 — Admit webhook deliveries durably before fan-out and recheck authorization

**Problem/evidence.** Volatile semaphore queues lose accepted deliveries; sidecar counters fabricate health and unsubscribe strands audit ownership. [src/subscriptions.rs:1017](https://github.com/alphaonedev/ai-memory-mcp/blob/a1403c742f9d590a08b6fd170deec5f50ca8e940/src/subscriptions.rs#L1017); [src/subscriptions.rs:1519](https://github.com/alphaonedev/ai-memory-mcp/blob/a1403c742f9d590a08b6fd170deec5f50ca8e940/src/subscriptions.rs#L1519); [C:109](reviews/COMPETITOR-ASSESSMENT-3x7-2026-09-27.md); N3 §P3-24 (local evidence: `/ai-scratch/deputy/codex-pool/out/ns3x3/N3-PROPOSE-DEFECT-CLASS-REDESIGN.md:493`); N9 §P3-24 (local evidence: `/ai-scratch/deputy/codex-pool/out/ns3x3/N9-VOTE-COMPETITIVE-STRATEGIST.md:1012`).

**Design.** Persist delivery intent before admission, lease it on the active store, recheck subscriber authority immediately before send, and preserve ownership metadata after deletion. Every accepted ID has an ACK, durable retry, reasoned cancellation or DLQ disposition.

**North Star / moonshot criteria:** DI1, DI2, SE1, PF1, PF3, RL1, RL2.

**Competitors to defeat:** ruflo, agentmemory, MemPalace, Hindsight (webhook path); no defeat claimed yet.

**TEST-PROVEN acceptance — NOT RUN:** Queue 10,000 deliveries with four permits, interrupt before/after send and ACK, revoke/unsubscribe across replicas. Every admitted ID remains acked/pending/cancelled-with-reason/DLQ, with truthful active-store counters; zero private sends after the stated revoke boundary. Fewer accepted-event losses or unauthorized sends than each named comparator on shared event paths establishes a win. Record network in-flight boundary explicitly. Include Hindsight’s actual webhook path where available; rivals without a corresponding event API remain Unsupported.

**Effort/dependencies:** L; P3-01, P3-03, P3-04, P3-11; worker lifecycle contract.

**Existing issue carriers:** [#3371](https://github.com/alphaonedev/ai-memory-mcp/issues/3371), [#3370](https://github.com/alphaonedev/ai-memory-mcp/issues/3370), [#4101](https://github.com/alphaonedev/ai-memory-mcp/issues/4101); extend these scopes and their linked regression issues, do not duplicate them.

<a id="p3-25"></a>

### P3-25 — Make wake discovery live independently of the hint transport

**Problem/evidence.** Blocking socket probes and reconnect hints can starve durable inbox reads; TTL and ownership behavior differ by backend/OS. [src/wake_hub/startup.rs:328](https://github.com/alphaonedev/ai-memory-mcp/blob/a1403c742f9d590a08b6fd170deec5f50ca8e940/src/wake_hub/startup.rs#L328); [src/wake_client/mod.rs:415](https://github.com/alphaonedev/ai-memory-mcp/blob/a1403c742f9d590a08b6fd170deec5f50ca8e940/src/wake_client/mod.rs#L415); [C:40](reviews/COMPETITOR-ASSESSMENT-3x7-2026-09-27.md); N3 §P3-25 (local evidence: `/ai-scratch/deputy/codex-pool/out/ns3x3/N3-PROPOSE-DEFECT-CLASS-REDESIGN.md:509`); N9 §P3-25 (local evidence: `/ai-scratch/deputy/codex-pool/out/ns3x3/N9-VOTE-COMPETITIVE-STRATEGIST.md:1029`).

**Design.** Track successful inbox-read deadlines independently of hints. Use bounded probes, OS ownership plus socket generation checks, fallible entropy and durable polling. Isolate recipient cursors/metadata; qualify Linux/macOS and both stores. A wake hint discovers work rather than executing an agent.

**North Star / moonshot criteria:** DI1, PF1, PF2, PF3, RL1, RL2, RL3, M2.

**Competitors to defeat:** MemPalace, agentmemory, ruflo; no defeat claimed yet.

**TEST-PROVEN acceptance — NOT RUN:** On Linux/macOS, drop all hints, saturate backlog, repeat empty welcomes, fail entropy and restart 1,000 times. No live socket takeover; startup completes/refuses within 2 s and retained inbox records are discovered within 60 s with a reachable store and admitted capacity. Other-tenant traffic never changes serialized recipient cursors/counters. At 256 recipients beat each comparator by 20% p99 commit-to-durable-discovery at equal encryption/durability, or fewer liveness violations.

**Effort/dependencies:** L; P3-03, P3-12, P3-31; active-store inbox contract.

**Existing issue carriers:** [#3466](https://github.com/alphaonedev/ai-memory-mcp/issues/3466), [#3814](https://github.com/alphaonedev/ai-memory-mcp/issues/3814), [#3486](https://github.com/alphaonedev/ai-memory-mcp/issues/3486); extend these scopes and their linked regression issues, do not duplicate them.

<a id="p3-27"></a>

### P3-27 — Use structured concurrency and backend-aware shutdown certification

**Problem/evidence.** Detached writers and incomplete signal handling allow writes after a final witness or certify the wrong store. [src/daemon_runtime.rs:8250](https://github.com/alphaonedev/ai-memory-mcp/blob/a1403c742f9d590a08b6fd170deec5f50ca8e940/src/daemon_runtime.rs#L8250); [src/daemon_runtime.rs:8572](https://github.com/alphaonedev/ai-memory-mcp/blob/a1403c742f9d590a08b6fd170deec5f50ca8e940/src/daemon_runtime.rs#L8572); [O:179](reviews/AI-MEMORY-VS-OPENVIKING-3x3-CODE-LEVEL-2026-09-27.md); N3 §P3-27 (local evidence: `/ai-scratch/deputy/codex-pool/out/ns3x3/N3-PROPOSE-DEFECT-CLASS-REDESIGN.md:541`); N9 §P3-27 (local evidence: `/ai-scratch/deputy/codex-pool/out/ns3x3/N9-VOTE-COMPETITIVE-STRATEGIST.md:1046`).

**Design.** Own every writer under a runtime supervisor: stop admission, persist intents, drain/join or fence writers, then witness/checkpoint the active store. A deadline yields explicit incomplete shutdown. Design the supervisor interface alongside delivery workers to avoid a dependency cycle.

**North Star / moonshot criteria:** DI1, DI2, DI3, PF1, RL1, RL2, M3.

**Competitors to defeat:** OpenViking, agentmemory, cognee; no defeat claimed yet.

**TEST-PROVEN acceptance — NOT RUN:** SIGINT/SIGTERM at every worker phase: zero writes after a certified final head; active-store receipt matches the final ledger and all accepted work is durable after restart. Deadline 30 s yields complete or explicit incomplete, never false clean. Fewer lost-work/false-complete shutdowns than each named comparator under equal admitted workloads proves a win. Hard-reset evidence is separately required by P2-04.

**Effort/dependencies:** L; P3-01, P3-06, P3-07; delivery-intent and active-store contracts.

**Existing issue carriers:** [#3559](https://github.com/alphaonedev/ai-memory-mcp/issues/3559), [#3561](https://github.com/alphaonedev/ai-memory-mcp/issues/3561); extend these scopes and their linked regression issues, do not duplicate them.

### Performance, release, deployment and truthful observations

<a id="p3-29"></a>

### P3-29 — Partition CPU, inference and database work with bounded schedulers

**Problem/evidence.** Blocking model work on runtime workers/DB locks and global hook serialization cause contention collapse. [src/handlers/create.rs:486](https://github.com/alphaonedev/ai-memory-mcp/blob/a1403c742f9d590a08b6fd170deec5f50ca8e940/src/handlers/create.rs#L486); [src/handlers/recall.rs:485](https://github.com/alphaonedev/ai-memory-mcp/blob/a1403c742f9d590a08b6fd170deec5f50ca8e940/src/handlers/recall.rs#L485); [C:356](reviews/COMPETITOR-ASSESSMENT-3x7-2026-09-27.md); N3 §P3-29 (local evidence: `/ai-scratch/deputy/codex-pool/out/ns3x3/N3-PROPOSE-DEFECT-CLASS-REDESIGN.md:573`); N9 §P3-29 (local evidence: `/ai-scratch/deputy/codex-pool/out/ns3x3/N9-VOTE-COMPETITIVE-STRATEGIST.md:1080`).

**Design.** Separate bounded CPU, remote inference, DB and hook queues with fair per-principal admission. Move inference outside locks and validate revisions at commit. Measure queue/execute/commit/readiness separately; coalesce or batch only when privacy and revision correctness hold.

**North Star / moonshot criteria:** PF1, PF2, PF3, RL3.

**Competitors to defeat:** Haystack, OpenViking, cognee; no defeat claimed yet.

**TEST-PROVEN acceptance — NOT RUN:** At 100k real 768-dimensional rows and 1/16/64/256 clients on a pinned rig, stall inference while health/auth/keyword reads remain live; health p99 at most 250 ms, no tenant starvation beyond the declared 5 s fixture allowance and bounded queues. At admitted load 64-client useful throughput is at least 95% of 16-client throughput. Earn 20% goodput or p99 improvement versus each named comparator at equal quality, signing, durability and completed semantic-readiness work; refusals and late jobs count as failures.

**Effort/dependencies:** XL; P3-01, P3-10, P3-30.

**Existing issue carriers:** [#3335](https://github.com/alphaonedev/ai-memory-mcp/issues/3335), [#3341](https://github.com/alphaonedev/ai-memory-mcp/issues/3341), [#3342](https://github.com/alphaonedev/ai-memory-mcp/issues/3342), [#3284](https://github.com/alphaonedev/ai-memory-mcp/issues/3284), [#3509](https://github.com/alphaonedev/ai-memory-mcp/issues/3509); extend these scopes and their linked regression issues, do not duplicate them.

<a id="p3-39"></a>

### P3-39 — Use a shared retrieval plan with explicit evidence sufficiency and model-space contracts

**Problem/evidence.** Ranking mixes priors with relevance, contradiction semantics differ by backend, and failed candidate generation can report confident no-match. [src/store/postgres.rs:25734](https://github.com/alphaonedev/ai-memory-mcp/blob/a1403c742f9d590a08b6fd170deec5f50ca8e940/src/store/postgres.rs#L25734); [src/storage/mod.rs:21423](https://github.com/alphaonedev/ai-memory-mcp/blob/a1403c742f9d590a08b6fd170deec5f50ca8e940/src/storage/mod.rs#L21423); [C:355](reviews/COMPETITOR-ASSESSMENT-3x7-2026-09-27.md); N3 §P3-39 (local evidence: `/ai-scratch/deputy/codex-pool/out/ns3x3/N3-PROPOSE-DEFECT-CLASS-REDESIGN.md:733`); N9 §P3-39 (local evidence: `/ai-scratch/deputy/codex-pool/out/ns3x3/N9-VOTE-COMPETITIVE-STRATEGIST.md:1212`).

**Design.** Share eligibility and scoring formulas, keep relevance/confidence/contradiction separate, and report evidence sufficiency plus exact token/drop accounting. Compare equal candidates against an external oracle; evaluate native rankers by quality rather than forcing different BM25 functions to identical order.

**North Star / moonshot criteria:** DI1, PF1, PF3, RL1, M2, M4, M7.

**Competitors to defeat:** OpenViking, cognee, Haystack, KIP; no defeat claimed yet.

**TEST-PROVEN acceptance — NOT RUN:** Both backends match eligibility, policy, contradiction and scoring-formula oracles on fixed candidate fixtures; keyword-only backend differences are evaluated against external relevance judgments. Zero confident no-evidence negatives when candidate generation fails; exact token/drop accounting. On frozen held-out sets require at least 5% relative nDCG@10 gain versus each named comparator, paired 95% CI above zero, equal spend and at most 5% p95 regression. Safety/parity fixes ship regardless of whether quality superiority is achieved. At equal candidate sets use a declared score tolerance; production ANN quality uses an external relevance oracle, not self-agreement.

**Effort/dependencies:** XL; P3-03, P3-19, P3-29, P3-30.

**Existing issue carriers:** [#2425](https://github.com/alphaonedev/ai-memory-mcp/issues/2425), [#3350](https://github.com/alphaonedev/ai-memory-mcp/issues/3350), [#3349](https://github.com/alphaonedev/ai-memory-mcp/issues/3349), [#3567](https://github.com/alphaonedev/ai-memory-mcp/issues/3567), [#3565](https://github.com/alphaonedev/ai-memory-mcp/issues/3565), [#3568](https://github.com/alphaonedev/ai-memory-mcp/issues/3568), [#3570](https://github.com/alphaonedev/ai-memory-mcp/issues/3570), [#3571](https://github.com/alphaonedev/ai-memory-mcp/issues/3571), [#3564](https://github.com/alphaonedev/ai-memory-mcp/issues/3564), [#3353](https://github.com/alphaonedev/ai-memory-mcp/issues/3353); extend these scopes and their linked regression issues, do not duplicate them.

<a id="p3-33"></a>

### P3-33 — Replace text-scanning security gates with compiler-resolved enforcement

**Problem/evidence.** Text scanners miss aliasing, multiline SQL, visibility and feature-target variations; broad allowlists suppress real bypasses. [scripts/qc-codegraph-precheck.sh:1](https://github.com/alphaonedev/ai-memory-mcp/blob/a1403c742f9d590a08b6fd170deec5f50ca8e940/scripts/qc-codegraph-precheck.sh#L1); [src/store/mod.rs:645](https://github.com/alphaonedev/ai-memory-mcp/blob/a1403c742f9d590a08b6fd170deec5f50ca8e940/src/store/mod.rs#L645); [C:358](reviews/COMPETITOR-ASSESSMENT-3x7-2026-09-27.md); N3 §P3-33 (local evidence: `/ai-scratch/deputy/codex-pool/out/ns3x3/N3-PROPOSE-DEFECT-CLASS-REDESIGN.md:637`); N9 §P3-33 (local evidence: `/ai-scratch/deputy/codex-pool/out/ns3x3/N9-VOTE-COMPETITIVE-STRATEGIST.md:1129`).

**Design.** Seal privileged constructors and commit permits, add compile-fail fixtures, and execute semantic bypass plants on every supported feature target. Treat unresolved coverage as incomplete. General whole-program analysis remains deferred; scanner success alone cannot certify a boundary.

**North Star / moonshot criteria:** SE1, SE2, DI3, RL1.

**Competitors to defeat:** KIP, Haystack, OpenViking; no defeat claimed yet.

**TEST-PROVEN acceptance — NOT RUN:** All known alias/fn-item/multiline-SQL/visibility/test-filename/adjacent-function bypass plants plus 100 syntax-equivalent variants are rejected in every supported feature target; authorized controls compile/pass. Missing analysis is incomplete, never pass. Require strictly higher caught-bypass fraction than each named comparator on equivalent boundary fixtures for an assurance win; no claim about private CI or arbitrary whole-program soundness.

**Effort/dependencies:** L; P3-01, P3-03, P3-06, P3-13.

**Existing issue carriers:** [#3558](https://github.com/alphaonedev/ai-memory-mcp/issues/3558), [#3298](https://github.com/alphaonedev/ai-memory-mcp/issues/3298); extend these scopes and their linked regression issues, do not duplicate them.

<a id="p3-34"></a>

### P3-34 — Make release gates deterministic, complete and bound to the tested merge artifact

**Problem/evidence.** Locale-dependent comparisons, missing coverage entries and mismatched build/test artifacts can produce false release certification. [coverage/check-thresholds.sh:96](https://github.com/alphaonedev/ai-memory-mcp/blob/a1403c742f9d590a08b6fd170deec5f50ca8e940/coverage/check-thresholds.sh#L96); [scripts/check-required-contexts-live.sh:171](https://github.com/alphaonedev/ai-memory-mcp/blob/a1403c742f9d590a08b6fd170deec5f50ca8e940/scripts/check-required-contexts-live.sh#L171); [C:361](reviews/COMPETITOR-ASSESSMENT-3x7-2026-09-27.md); N3 §P3-34 (local evidence: `/ai-scratch/deputy/codex-pool/out/ns3x3/N3-PROPOSE-DEFECT-CLASS-REDESIGN.md:653`); N9 §P3-34 (local evidence: `/ai-scratch/deputy/codex-pool/out/ns3x3/N9-VOTE-COMPETITIVE-STRATEGIST.md:1144`).

**Design.** Bind required receipts to installed artifact, source/config/feature/backend/OS/fixture digests. Reject missing cells, stale claims, invalid tags, unknown distribution notices and planted bypasses; isolate test fixtures and reproduce declared builds. This owns the merged test-hygiene, claim and supply-chain evidence scopes.

**North Star / moonshot criteria:** SE2, RL1, RL2, DI3.

**Competitors to defeat:** Haystack, OpenViking; no defeat claimed yet.

**TEST-PROVEN acceptance — NOT RUN:** Artifact/config/backend/OS/fixture digests bind every required receipt. Tampered/unsigned tag, unpinned tool, digest drift, unknown distribution license/notice, missing coverage source/prerequisite/context, stale receipt and false power-loss label each block release on Linux/macOS across declared locales. Two builders reproduce declared reproducible artifacts; tests run distributed bytes. Strictly higher planted-failure rejection coverage than each named comparator proves an assurance win, not runtime supremacy. Run 100 shuffled Linux/macOS repetitions across umask/descriptor-limit fixtures; injected false assertions must fail, and every configured gate self-test must execute.

**Effort/dependencies:** L; Evidence scaffold at phase 0; final receipts follow P3-28 and implementation.

**Existing issue carriers:** [#3798](https://github.com/alphaonedev/ai-memory-mcp/issues/3798), [#3799](https://github.com/alphaonedev/ai-memory-mcp/issues/3799), [#3801](https://github.com/alphaonedev/ai-memory-mcp/issues/3801), [#3501](https://github.com/alphaonedev/ai-memory-mcp/issues/3501), [#3298](https://github.com/alphaonedev/ai-memory-mcp/issues/3298); extend these scopes and their linked regression issues, do not duplicate them.

<a id="p3-37"></a>

### P3-37 — Make install, upgrade and service deployment an atomic artifact operation

**Problem/evidence.** Direct executable overwrite and independently maintained package/service manifests make interruption or upgrade destructive. [src/daemon_runtime.rs:1123](https://github.com/alphaonedev/ai-memory-mcp/blob/a1403c742f9d590a08b6fd170deec5f50ca8e940/src/daemon_runtime.rs#L1123); [src/cli/backup.rs:1374](https://github.com/alphaonedev/ai-memory-mcp/blob/a1403c742f9d590a08b6fd170deec5f50ca8e940/src/cli/backup.rs#L1374); [C:357](reviews/COMPETITOR-ASSESSMENT-3x7-2026-09-27.md); N3 §P3-37 (local evidence: `/ai-scratch/deputy/codex-pool/out/ns3x3/N3-PROPOSE-DEFECT-CLASS-REDESIGN.md:701`); N9 §P3-37 (local evidence: `/ai-scratch/deputy/codex-pool/out/ns3x3/N9-VOTE-COMPETITIVE-STRATEGIST.md:1178`).

**Design.** Stage, verify, fsync, atomically publish and directory-sync binaries while preserving the prior executable. Exercise actual unit/Compose/TLS assets and retain data/key/audit volumes. Promise rollback only for compatible schemas; otherwise qualify forward recovery.

**North Star / moonshot criteria:** DI1, RL1, RL2, RL3, M1.

**Competitors to defeat:** OpenViking, agentmemory, ruflo; no defeat claimed yet.

**TEST-PROVEN acceptance — NOT RUN:** Interrupt every copy/fsync/rename/full-disk point: old or complete verified new executable remains runnable. Advertised packages contain working service assets and preserve configured DB/key/audit volumes. Binary rollback only with schema compatibility; otherwise successful forward recovery is required. A higher successful faulted-upgrade fraction or fewer measured recovery steps than each named comparator on equivalent package paths proves a win. Fsync the publication directory as well as staged bytes; safe refusal is reported separately from a completed upgrade.

**Effort/dependencies:** L; P3-31, P3-12; artifact identity contract and P3-21 compatibility.

**Existing issue carriers:** [#4114](https://github.com/alphaonedev/ai-memory-mcp/issues/4114), [#3799](https://github.com/alphaonedev/ai-memory-mcp/issues/3799), [#3563](https://github.com/alphaonedev/ai-memory-mcp/issues/3563); extend these scopes and their linked regression issues, do not duplicate them.

<a id="p3-38"></a>

### P3-38 — Separate durable evidence, confidential telemetry and exact health state

**Problem/evidence.** Raw DSNs/titles can enter logs, optional telemetry can silently fail and unknown active-store counters look like zero. [src/logging.rs:227](https://github.com/alphaonedev/ai-memory-mcp/blob/a1403c742f9d590a08b6fd170deec5f50ca8e940/src/logging.rs#L227); [src/store/postgres.rs:2595](https://github.com/alphaonedev/ai-memory-mcp/blob/a1403c742f9d590a08b6fd170deec5f50ca8e940/src/store/postgres.rs#L2595); [C:181](reviews/COMPETITOR-ASSESSMENT-3x7-2026-09-27.md); N3 §P3-38 (local evidence: `/ai-scratch/deputy/codex-pool/out/ns3x3/N3-PROPOSE-DEFECT-CLASS-REDESIGN.md:717`); N9 §P3-38 (local evidence: `/ai-scratch/deputy/codex-pool/out/ns3x3/N9-VOTE-COMPETITIVE-STRATEGIST.md:1195`).

**Design.** Use typed safe fields and secret references, keep signed evidence in a separately governed canonical sink, and report value/status/last-success/store identity. Bound optional telemetry queues and count drops; mandatory audit failure refuses or persists durably. OTLP breadth is optional.

**North Star / moonshot criteria:** DI1, DI3, SE1, SE2, PF2, RL2, M5.

**Competitors to defeat:** OpenViking, TencentDB-Agent-Memory, Haystack; no defeat claimed yet.

**TEST-PROVEN acceptance — NOT RUN:** Canaries in credentials/content/titles/DSNs never appear in diagnostic/OTLP output across success/error/debug paths; canonical signed evidence remains byte-verifiable. Collector/disk failures yield bounded optional drop counts or durable required evidence/refusal, never false health or fabricated zero counters. Fewer leaks/false-healthy states than each named comparator at equivalent observability configuration proves a win; OTLP overhead must remain at most 5% goodput on the retained workload.

**Effort/dependencies:** L; P2-16, P3-06, P3-07, P3-28 contract.

**Existing issue carriers:** [#3800](https://github.com/alphaonedev/ai-memory-mcp/issues/3800), [#4104](https://github.com/alphaonedev/ai-memory-mcp/issues/4104), [#4106](https://github.com/alphaonedev/ai-memory-mcp/issues/4106); extend these scopes and their linked regression issues, do not duplicate them.

### SHOULD-V1.1 — retained separately from MUST

These two packages follow their mandatory foundations. They are not release prerequisites unless separately adopted as such. Critique recommendations to cut all-role breadth do not override P2-34's binding SHOULD vote. Part III §III.5 (local evidence: `/ai-scratch/deputy/codex-pool/out/ns3x3/PART-III-NORTH-STAR-AND-V1.1.0.md#should-v11-and-later`).

<a id="p1-12"></a>

### P1-12 — Evidence-origin grouping and calibrated contested-belief views

**Priority:** SHOULD-V1.1. **Criteria:** DI1, SE1, SE2, PF2, M2, M4, M6.

**Scope:** Evidence-origin grouping and calibrated contested-belief views. SHOULD: recorded-origin grouping and dissent help contain copied beliefs; hidden-ancestry detection and universal truth calibration are not promised.

**Competitors to defeat:** KIP, ruflo, Graphiti.

**TEST-PROVEN acceptance — NOT RUN:** On 5,000 copied claims with recorded common origin, independent support remains one; zero unknown-origin or read-count promotions. Valid independent controls remain usable. A cognitive win requires the original held-out 500-claim comparison: at least 50% fewer false-consensus outcomes, Brier improvement at least 0.03 and correct coverage loss at most 5 points versus each named comparator. No hidden-ancestry or universal M6 claim.

**Effort / existing carriers / evidence:** L; [#3567](https://github.com/alphaonedev/ai-memory-mcp/issues/3567), [#4102](https://github.com/alphaonedev/ai-memory-mcp/issues/4102); N1 §P1-12 (local evidence: `/ai-scratch/deputy/codex-pool/out/ns3x3/N1-PROPOSE-COMPETITIVE-GAPS.md:282`); N9 §P1-12 (local evidence: `/ai-scratch/deputy/codex-pool/out/ns3x3/N9-VOTE-COMPETITIVE-STRATEGIST.md:274`)

**Dependencies:** P1-05, P3-06, P3-17, P3-20, P3-39; frozen held-out [#3570](https://github.com/alphaonedev/ai-memory-mcp/issues/3570) protocol.

<a id="p2-34"></a>

### P2-34 — Make every cognitive role independently replaceable and observable

**Priority:** SHOULD-V1.1. **Criteria:** M7, M4, M6, SE1, SE2, EN1, PF1.

**Scope:** Make every cognitive role independently replaceable and observable. SHOULD: close actual role-routing gaps after current safety paths; no new modality/provider catalogue or dependency on a full router for deterministic clearance.

**Competitors to defeat:** OpenViking, Haystack, Mastra, Honcho.

**TEST-PROVEN acceptance — NOT RUN:** Route all roles to distinct instrumented mock endpoints, hot-swap one, and verify only its requests change. Run real adapters from at least three model families plus a staged local provider. Unknown config, wrong output dimensions, absent credentials and provider outage produce the declared safe outcome; destructive roles never fall back to permissive generation. COMPETITIVE GATE: Match the rivals’ actual role independence, then require strictly greater verified cognitive-boundary coverage with enforced egress/identity/failure contracts. If all shared roles pass, use G’s provider-swap recovery time or equal-budget task-quality threshold instead of counting aliases. Also require 10,000 interleaved calls with zero wrong tuple deliveries and at least 20% lower role-swap recovery p95 across 30 paired runs when role-coverage correctness ties.

**Effort / existing carriers / evidence:** XL; [#4102](https://github.com/alphaonedev/ai-memory-mcp/issues/4102), [#4114](https://github.com/alphaonedev/ai-memory-mcp/issues/4114); N2 §P2-34 (local evidence: `/ai-scratch/deputy/codex-pool/out/ns3x3/N2-PROPOSE-NORTH-STAR-DELIVERY.md:796`); N9 §P2-34 (local evidence: `/ai-scratch/deputy/codex-pool/out/ns3x3/N9-VOTE-COMPETITIVE-STRATEGIST.md:580`)

**Dependencies:** P3-02/03/10/11/12/13, P2-16 and P1-05 receipt schema; no provider expansion before safe current clients.

## 7. Milestones and sequencing

Milestone labels **MS1–MS3** avoid collision with moonshot IDs M1–M7. Relative effort from the binding 41-package register is **3 M, 23 L, 15 XL**: M is a bounded component; L spans paths/adapters; XL is cross-cutting protocol or qualification. These are not independent additive estimates. N6's 125–216 engineering-week estimate applies to its own narrowed portfolio, not this binding set. Staffing, comparator access, host support and infrastructure are not yet enough to infer a ship date. Part III §III.6 (local evidence: `/ai-scratch/deputy/codex-pool/out/ns3x3/PART-III-NORTH-STAR-AND-V1.1.0.md#iii6--dependency-order-and-critical-path-to-test-proven-wins`).

| Milestone / dependency order | Work and concrete exit gate | Existing owners |
|---|---|---|
| **MS1a — freeze foundations and baseline rigs** | Freeze operation/effects matrix, principal/policy/signer/commit tuple, encrypted channel, merge/cursor/erasure schema, resource budget, worker lifecycle and artifact receipt. Every required cell has an independent oracle and comparator disposition. Provision hard-reset rig, clean-host snapshots and three independent failure domains now. P2-42 starts now, finishes last. | [#3558](https://github.com/alphaonedev/ai-memory-mcp/issues/3558), [#3559](https://github.com/alphaonedev/ai-memory-mcp/issues/3559), [#3561](https://github.com/alphaonedev/ai-memory-mcp/issues/3561), [#3572](https://github.com/alphaonedev/ai-memory-mcp/issues/3572), [#3798](https://github.com/alphaonedev/ai-memory-mcp/issues/3798), [#4108](https://github.com/alphaonedev/ai-memory-mcp/issues/4108) |
| **MS1b — authority and trustworthy local commits** | Complete P3-31/02/03/04/10/11/12/13, P2-16, P3-01/06/07/08, P2-04/31/35 and P1-05. Zero unavailable-to-Allow, unauthorized bytes, plaintext supported legs, partial/unsigned/lost ACKs; 10k commit schedules and 100 hard resets per qualified storage stack pass. Two real encrypted host integrations retain useful operation. | [#3794](https://github.com/alphaonedev/ai-memory-mcp/issues/3794), [#4092](https://github.com/alphaonedev/ai-memory-mcp/issues/4092)–[#4097](https://github.com/alphaonedev/ai-memory-mcp/issues/4097), [#4099](https://github.com/alphaonedev/ai-memory-mcp/issues/4099)/[#4100](https://github.com/alphaonedev/ai-memory-mcp/issues/4100), [#4102](https://github.com/alphaonedev/ai-memory-mcp/issues/4102)–[#4106](https://github.com/alphaonedev/ai-memory-mcp/issues/4106), [#3559](https://github.com/alphaonedev/ai-memory-mcp/issues/3559)/[#3561](https://github.com/alphaonedev/ai-memory-mcp/issues/3561) |
| **MS2a — replication and lifecycle parity-plus** | Complete P3-14/15/16/17/19/20/21/22/23/24/25/27. One million merge triples; 100k replicated operations, 10k equal timestamps; zero false Applied/false clean/resurrection/post-witness writes. All 10k delivery IDs accounted; startup ≤2 s/refusal and hint-loss discovery ≤60 s. Preserve valid useful-work controls. | [#4101](https://github.com/alphaonedev/ai-memory-mcp/issues/4101), [#4098](https://github.com/alphaonedev/ai-memory-mcp/issues/4098), [#3793](https://github.com/alphaonedev/ai-memory-mcp/issues/3793)/[#3795](https://github.com/alphaonedev/ai-memory-mcp/issues/3795), [#4111](https://github.com/alphaonedev/ai-memory-mcp/issues/4111)/[#4112](https://github.com/alphaonedev/ai-memory-mcp/issues/4112), [#3574](https://github.com/alphaonedev/ai-memory-mcp/issues/3574), [#3466](https://github.com/alphaonedev/ai-memory-mcp/issues/3466) |
| **MS2b — usable installed service** | Finish P3-28 required cells, P3-29/30 bounds, P3-36/37 recovery/deployment, P3-38 telemetry and P3-42 continuity. Clean-host restore ≤15 min on the declared 100k fixture; foreground/control budgets hold; faulted install leaves old or complete new binary. No phantom sidecar effects or skipped required backend cell. | [#3335](https://github.com/alphaonedev/ai-memory-mcp/issues/3335)/[#3341](https://github.com/alphaonedev/ai-memory-mcp/issues/3341)/[#3342](https://github.com/alphaonedev/ai-memory-mcp/issues/3342), [#3565](https://github.com/alphaonedev/ai-memory-mcp/issues/3565), [#4107](https://github.com/alphaonedev/ai-memory-mcp/issues/4107)–[#4110](https://github.com/alphaonedev/ai-memory-mcp/issues/4110), [#4114](https://github.com/alphaonedev/ai-memory-mcp/issues/4114), [#3799](https://github.com/alphaonedev/ai-memory-mcp/issues/3799) |
| **MS3 — measured differentiators and release evidence** | Finish P3-39/41, P3-33/34 and P2-42 qualification. Run two GA then all 12 missions, ≥30 independent seeds/arm, 24 h then 72 h soaks and 72 h disconnected/100 restarts. Freeze/execute optional SHOULD arms separately. Each claimed rival victory meets its own strict margin/paired CI. Zero unresolved mandatory fail-open classes; every release receipt binds final distributed bytes. | [#3564](https://github.com/alphaonedev/ai-memory-mcp/issues/3564)/[#3568](https://github.com/alphaonedev/ai-memory-mcp/issues/3568)/[#3569](https://github.com/alphaonedev/ai-memory-mcp/issues/3569)/[#3570](https://github.com/alphaonedev/ai-memory-mcp/issues/3570), [#3559](https://github.com/alphaonedev/ai-memory-mcp/issues/3559)/[#3561](https://github.com/alphaonedev/ai-memory-mcp/issues/3561), [#3798](https://github.com/alphaonedev/ai-memory-mcp/issues/3798)/[#3799](https://github.com/alphaonedev/ai-memory-mcp/issues/3799)/[#3501](https://github.com/alphaonedev/ai-memory-mcp/issues/3501) |

**Critical path:** contracts → usable encrypted authority → atomic signed durable commit → anchored history → replay/erasure/projection closure → active-store shutdown/restore → installed backend/host conformance → matched missions and artifact-bound release. Schema/projection, replay/erasure and worker/shutdown interfaces are frozen together; final implementations are sequenced by the concrete dependencies above, avoiding artificial circular prerequisites. Baseline rigs and comparator adapters proceed alongside design. A safety repair does not wait for a full new router or a broad framework SDK.

The release must not reclassify a missing required cell as Unsupported after a failed test. Narrowing an advertised boundary needs an explicit operator decision and an updated plan before a new campaign. A fair competitor tie closes a safety repair but does not satisfy “defeat.” Unknown private-vendor behavior cannot be turned into a loss. Protocol G (local evidence: `/ai-scratch/deputy/codex-pool/out/ns3x3/PART-III-NORTH-STAR-AND-V1.1.0.md#shared-test-proven-protocol-g`).

## 8. Metrics dashboard — claims require published receipts

All current result cells are **NOT RUN at the proposed v1.1.0 artifact**. Targets below are gates, not measurements. Use an 8-core reference rig with recorded RAM/storage/OS and production 768-dimensional vectors for local load cells; record each peer's resources for fleet cells. Freeze hardware and limits before a run. Separate same-host/cross-host and SQLite/PostgreSQL; do not average away a failing cell.

| Metric / acceptance owner | Required target | How measured / rival win threshold |
|---|---|---|
| Mandatory integrity/authority failures — P3-01/02/03/06 | **0** silent-loss, partial, unsigned, unauthorized or unavailable-to-Allow outcomes across every required cell; ≥10k atomic schedules. **0 open unresolved fail-open classes in the release boundary.** | External committed-state/authority oracle plus current defect-class register. Closure requires executed regression and mutation-negative control, not issue labels. Each package's named-rival lower-violation/coverage test applies. |
| EN1 coverage — P3-12 | **100% supported application/identity/control-data legs encrypted**, zero plaintext/downgrade acceptance; ≥2 real usable host integrations. | Instrument socket/IPC and crypto protocol; plaintext, binary and encoded canaries, wrong-key/cert tests. Strictly higher common-leg coverage than OpenViking/agentmemory/mem0; tied coverage is parity. |
| Physical-reset ACK loss — P2-04 | **0** lost/altered acknowledged digest+revisions over **≥100 randomized lost-flush trials per backend/storage stack**. | Independent external ACK ledger; actual discard of unflushed writes. Compare agentmemory/TencentDB-Agent-Memory at equal flush guarantees. Process abort is not this metric. |
| Generation provenance — P1-05 | **100%** committed derivations in 10k faults have source revisions and signed run; **0 falsely Complete/orphaned** artifacts. | Independently verify exact inputs/config/output lineage; Unknown/Incomplete is excluded from Complete numerator. Strictly higher complete fraction at equal generation yield than TencentDB-Agent-Memory/cognee. |
| Wake discovery p99 — P3-25 | At 256 recipients, **≥20% lower commit→durable-inbox-discovery p99** than each applicable MemPalace/agentmemory/ruflo arm, or fewer liveness violations; **≤60 s** discovery when hints fail; **≤2 s** startup/refusal. | Correlate durable row IDs; separately time notify entry, commit, hint, inbox read, client completion. Report missing/duplicate rows, clock uncertainty and 128/256-recipient cells. No credit from later-fix one-recipient NVMe numbers. |
| Federation convergence / drainage — P3-14/15 | Zero divergent retained state, skipped revision or false Applied ACK in **100k operations / 10k equal timestamps / 3 persisted peers**. Meet frozen `T_drain` after connectivity and prerequisites recover. | Proposed initial fixture target **T_drain ≤60 s**, explicitly additional advice, not inherited measured capacity; freeze link/resources/backlog/admission/retry policy before testing. Inventory all pending operations and compare final digest+revision state. A timing win requires ≥20% lower drain p99 versus applicable ruflo/agentmemory/MemPalace with equal safety; otherwise parity. |
| Useful performance under contention — P3-29 | At 1/16/64/256 clients and 100k 768-d rows: health p99 **≤250 ms**, 64-client useful throughput **≥95%** of 16-client; no tenant starvation past fixture **5 s**. | Measure queue/model/network/embedding/retrieval/rerank/storage separately, including semantic readiness and refusals. **≥20%** goodput or p99 improvement versus Haystack/OpenViking/cognee at equal quality, signing and durability. |
| Aggregate work bounds — P3-30 | 60-minute adversarial runs stay within shared byte/deadline/row budgets; memory reservation + measured **≤10% allocator allowance**; control p99 **≤250 ms**. | Unbounded compressed replies, graph fan-out, slow peers/clients, cancellation; child work spends one parent budget. Strictly better compliance or ≥20% benign goodput over OpenViking/Haystack/ruflo. |
| Recall quality — P3-39 | **≥5% relative nDCG@10 improvement**, paired 95% CI above zero; **≤5% p95 latency regression**, equal model/context/spend; zero unauthorized hits or false confident no-evidence. | Freeze **LongMemEval** and **LoCoMo** adapters plus multilingual/temporal/conflict held-out subsets before tuning. Use graded source/evidence judgments suitable for nDCG; report dataset/version, R@K and downstream answer accuracy separately. Compare OpenViking/cognee/Haystack/KIP only on supported shared tasks; do not relabel a synthetic set as official benchmark results. |
| Downstream task and contamination benefit — P2-42 | For each accessible target OpenViking/mem0/Hindsight/KIP/Haystack: ≥1 preregistered shared-mission gain of **5 accuracy points** or **20% cost/latency/goodput**, positive paired 95% CI, no mandatory safety regression. | **MemTrapBench** taxonomy/frozen held-out set, null+oracle baselines; **SWARM-BENCH** cascade/rewind; all 12 missions, ≥30 independent seeds/arm. Synthetic fixtures labeled; real answerer/judge required. Publish per-trap contamination and correct-completion denominators. |
| Restore / search readiness — P3-36 | Captured snapshot/WAL boundary **RPO=0**, verified restore **RTO≤15 min** for 100k records; no omitted keys/policy/queues/erasure floor reported Complete. | Restore verified offsite bytes on clean host; separately clock Restored and SearchReady. Strictly greater asset coverage or **20% faster verified RTO** than OpenViking/ruflo/MemPalace with identical inventory/custody. No promise of RPO=0 after the captured boundary. |
| Audit / shutdown — P3-07/27 | Zero false Complete through every suffix/interior deletion of a 10k-event chain; zero post-certified-head writes. SIGINT/SIGTERM complete or explicitly incomplete within **30 s**. | Independent operator-controlled retained head; active-store digest oracle; unanchored tail stays unknown. Compare against OpenViking/cognee/Vestige for audit and OpenViking/agentmemory/cognee for shutdown. |
| GC / work accounting — P3-22/24/38 | 100-row GC batch p99 lock **≤100 ms**, foreground goodput **≥80%** of no-GC; all **10k deliveries** accounted with 4 permits; no false-zero counters. | Exact immutable victim/delivery ID sets and active-store accounting; injected SQLITE_BUSY/disk/collector failure. Rival gates in those packages; optional OTLP goodput overhead **≤5%**. |
| Disconnected continuity — P3-41/42 | **72 h** no network/DNS plus **100 restarts**; no undeclared egress/vendor kill dependency, source loss or unsigned mutation; two real host versions usable. | Store/recall/verify/export/restore and subsequent retrieval/use oracles. More completed shared local missions than OpenViking/agentmemory; AWS cloud-only residency is documentary Unsupported, not a measured outage failure. |
| Release evidence — P3-33/34 | Every required cell bound to installed artifact; **100** shuffled OS/umask/fd-limit repetitions; all known bypasses + **100** syntax variants rejected; **0** false release passes. | Two builders reproduce declared artifacts; tampered/unsigned tag, unpinned tool, digest drift, missing PG/context/coverage source, stale evidence, unknown notice and false durability claim all fail. Compare assurance mutation coverage with Haystack/OpenViking/KIP as scoped by package. |

The named benchmark adapters are measurement choices advised here under P3-39/P2-42, not claims that upstream data formats, data rights or competitor adapters are already implemented. Missing official datasets require an explicitly named synthetic lane; unavailable official lanes remain Unmeasured. Freeze the score transformation and relevance annotation protocol before inspecting outcomes. Existing benchmark work is owned by [#3568](https://github.com/alphaonedev/ai-memory-mcp/issues/3568)/[#3570](https://github.com/alphaonedev/ai-memory-mcp/issues/3570), not a duplicate benchmark issue. [ROADMAP-v110 w5](ROADMAP-v110.md#p1--w5-memtrapbench-harness-memtrapbench-benchmark-runner-per-trap-class-claims-audit-numbers), [competitor evidence limits](reviews/COMPETITOR-ASSESSMENT-3x7-2026-09-27.md#benchmark-evidence-is-not-a-shared-leaderboard).

## 9. Risks and non-goals

| Risk / boundary | Advised response and pass/fail guard | Evidence / owner |
|---|---|---|
| Scope exceeds a small point release | Retain binding priorities; freeze interfaces and deliver vertical slices. Do not infer a date from relative effort. Removing a MUST requires a new operator decision; SHOULD expansion cannot consume safety gate capacity. | Part III §III.6; 3 M / 23 L / 15 XL register. |
| EN1 breaks conventional host stdio/UDS or local HTTP model compatibility | Build encrypted adapters or use in-process inference; refuse incompatible clients before payload. Release usability requires two actual supported integrations. Do not silently exempt same-host traffic. | P3-12/42; SECURITY.md:194. |
| Schema, merge and signing changes break old peers or restore | Version contracts explicitly; test mixed-version refusal/rebootstrap and recovery before write service. Preserve legacy unsigned/incomplete status honestly. | P3-13/14/17/21/36. |
| Refusal-heavy safety implementation harms availability | Keep authorized positive controls and goodput/yield floors in every safety campaign. No “win” from refusing all calls or omitting semantic/index work. | Protocol G; P3-29/30. |
| Verified M6 is beyond model-label attestation | Require measured held-out error correlation/calibration for any heterogeneous-judge claim. Unknown model lineage cannot pass verified M6. Independent signing roles remain a narrower assurance. | Moonshot §2.6; P2-35; SHOULD P1-12/P2-34. |
| Reviewer agreement becomes false confidence | Preserve score limitations and failures. This same-model audit series is not independent cross-family replication; vendor-independent assessment remains a root §11.9 process requirement. | TALLY; root §11.9 assessor independence. |
| Closed service or federal authorization mistaken for code-level comparison | Keep documentary scope explicit; seek access before running matched tasks. No claim of FedRAMP, ATO, IL or FIPS follows from cryptographic algorithms, domicile or passing code tests. | US audit §8; LATER P1-44/P2-38. |
| Dependency import mistaken for a voted implementation mandate | Every import/new dependency requires explicit operator authorization; preserve file-origin/license/notice evidence for actual distribution. Source reading alone is not a legal clean-room process. | CLAUDE.md §Sole-authority; [#3850](https://github.com/alphaonedev/ai-memory-mcp/issues/3850), [#4113](https://github.com/alphaonedev/ai-memory-mcp/issues/4113); P3-34. |

**What stays outside the substrate.** Apply [moonshot §0](strategy/moonshot-synthesis.md#0-one-sentence-anchor): a primitive that does not strengthen its endpoint/governance/continuity/stop/improvement/attestation properties belongs in a sibling repository. [Root ROADMAP §§3,13](../ROADMAP.md#13-sibling-repositories--substrate-adjacent-work-scoped-out-per-3) identifies these boundaries:

| Sibling / excluded scope | Interface and acceptance boundary |
|---|---|
| `alphaone-dev-skills` — general knowledge content | Source-URI/public skill interfaces; no new substrate dependency or release coupling. Applicability-guard skill delivery can use existing registration without moving a general knowledge library into core. |
| `ai-memory-viewer` — operator console | Public authorized read/action APIs only. Core owns truthful receipts and enforceable recovery semantics; viewer owns UI. LATER P1-47 stays outside core. |
| `ai-memory-schema-tools` — general code generation/schema methodology | Read-only schema definitions/public interfaces. Core retains mandatory P3-13 domain validation and P3-21 migration manifests; a general generator is not a prerequisite. |
| `ai-memory-eval-panel` (provisional) — heterogeneous assessment tooling | Consumes public evidence and produces assessments; does not become the authority that grants mutation permission. P2-35's enforced decision boundary stays core. |
| `ai-memory-rqgm` (provisional) — evolutionary search / RSI / panel breeding | Sibling → substrate only; no reverse compile/runtime dependency. Draft manifests remain unsigned until operator ceremony; no autonomous sanity-gate rewriting. |
| Agent runtime, standardized A2A payload orchestration, broad framework adapters, multimodal application stacks | Remain external consumers. Core owns durable inbox, fencing, authority and compatible host contracts; wake hints do not execute agents. Broader adapter votes remain LATER/NO-CONSENSUS. |

The sibling boundary passes when core builds and completes its mandatory mission suite without any sibling installed or reachable, all public calls retain the same authority/encryption contracts, and the dependency direction stays one-way. This is a scope-conformance test, not an additional comparative product claim. No sibling implementation is authorized here.

**Delivery evidence.** Corpus manifest (local evidence: `/ai-scratch/deputy/codex-pool/out/ns3x3/N11-evidence/corpus-manifest.json`) records complete-file ingestion of the supplied audit reports, dossiers, sweeps and tallies; review index (local evidence: `/ai-scratch/deputy/codex-pool/out/ns3x3/N11-evidence/corpus-review-index.json`) retains section openings for navigation. Release source checks (local evidence: `/ai-scratch/deputy/codex-pool/out/ns3x3/N11-evidence/release-source-check.json`) compare 81 package-cited anchors across 50 blobs with the designated pin; source excerpts (local evidence: `/ai-scratch/deputy/codex-pool/out/ns3x3/N11-evidence/release-source-excerpts.txt`) and CodeGraph receipt (local evidence: `/ai-scratch/deputy/codex-pool/out/ns3x3/N11-evidence/codegraph.txt`) retain the inspection. Document validation checks the 41 MUST + 2 SHOULD inventory, issue deduplication, score copies and internal anchors. These checks validate this advised document, not future product outcomes.
