# ai-memory v0.8.0 — TRACT Development-Gaps Catalog (Canonical · 32 Gaps)

### The single reconciled gap roadmap — Grok↔Opus adjudicated, CodeGraph-anchored, ROADMAP §5-crosswalked, TRACKED/UNTRACKED-tagged.

> **Method.** Four assessment passes across two decorrelated model families (Grok/xAI + Opus/Anthropic) — two first-party 21-agent councils, two reconciliations, then a final **21-agent adjudication council** — measured **TRACT** (`docs/design/TRACT-the-definitive-endpoint-ai-memory.md`) against ai-memory **`release/v0.8.0`**, CodeGraph as L1 evidence (846 files / 27,062 nodes / 92,578 edges). This is the canonical reduction; it supersedes the prior drafts. Companion: [`TRACT-v0.8.0-CORRECT-NOW-CANONICAL-opus.md`](TRACT-v0.8.0-CORRECT-NOW-CANONICAL-opus.md).

---

## Count contract

**32 canonical development gaps: 4 P0 epics · 11 P1 · 17 P2.** Plus **3 proof-impossible** (TRACT §15 — honesty labels, *not* backlog) and **~20 UNTRACKED** (no ROADMAP home). The count was 27 after the four-pass adjudication (Grok's earlier "52 unique" was granularity inflation — over-split P0, P3 mislabeled as gaps, two already-fixed items — deduped to 27), then **raised to 32 by a separate 21-agent corpus-completeness pass** that diffed the pre-TRACT design corpus against TRACT and recovered five operational/security obligations TRACT had distilled into prose (G28–G32 — see *Corpus-completeness provenance* below; two of them, G29 + G30, are codegraph-verified live v0.8.0 defects). Grok's finer enumeration is preserved as **decimal sub-rungs** so nothing is lost.

**Corrections baked in (codegraph-verified):**
- `crdt_merge` is **`src/models/crdt_merge.rs`** (not `src/federation/`) — `merge_memory:463`, LWW tiebreak `:228`.
- `touch_many` fn is **`src/storage/mod.rs:1520`** (`:1442` is `touch` singular); ranking ORDER BY `:3686`.
- store-path UUID **`src/storage/mod.rs:2083`**.
- federation delete **CALL** site **`src/handlers/federation_receive.rs:1184`** (`:446` is only the comment).
- `SignableWrite` `content_sha256` field **`src/identity/sign.rs:339`**.
- **Dropped as already-FIXED:** `#1672` curator_mode (`config.rs:1264`), `#1674` db_schema_version (`system.rs:112/124`), HTTP `find_paths`/`verify_link` 501 (wired, `lib.rs:983/987`).
- **durability-503 is an API-semantics bug, not "cannot write":** the local row persists (ADR-0001, `create.rs:941-966`); the 503 misreports a durable write.
- **P3 proof-impossibles = exactly 3** (not Grok's 9); the other §15 items are engineering-OPEN.

---

## Executive verdict — *substrate-ready, constitution-incomplete*

Two-axis grade: **trust-spine A− / B+** · **data-model C / C+**; **~75–85% of ROADMAP §2 / ~25–35% of TRACT L1** (bands, no composite). This is the **safety spine shipped first, the data-model spine deferred** — the defensible build order for a substrate that must hold the line against a smarter mind before perfecting its own physics.

**The honest divergence.** The co-located single-daemon TCB + thick UUID-keyed row is correct L3-BODY engineering for the endpoint floor: three air-gapped trust-domain keys and BLAKE3-CID-log-replayed-at-query are **hub/L1** properties an ~18–25 MB endpoint cannot host at <35 ms recall (codegraph confirms `blake3`/three-key = 0 production hits — absent, not half-built). Defensible **on the condition v0.8.0 never advertises L1/CID/three-key conformance.** The one place this does *not* excuse: **G12** (durability-503).

---

## P0 — v0.9.0 blockers (4 epics)

### G1 · Recall purity — kill mutating recall · TRACKED #1706/#1707
`touch_many` (`src/storage/mod.rs:1520`) mutates `access_count`/`expires_at`/promotion on every recall — **and feeds them back into the live ranking** (`:3686`). Goodhart loop + privacy leak (access patterns are content).
- **G1.1** decouple `touch_many` from the read path → lazy pure `S(t)`
- **G1.2** stop reading `access_count` back into the ORDER BY — this is also a **salience / meta-memory-poisoning** vector: access patterns are attacker-controllable content, so feeding them into ranking lets any caller pump a target memory's salience (auto-promote at 5 accesses `:1475`, priority bump every 10 `:1481`) by simply querying it (Goodhart + adversarial-recall amplification)
- **G1.3** CONSUME ledger reshape — async epoch-bucketed, off-budget; distillation → authored RELATE edges (today sqlite-only, on-budget)
- **G1.4** MCP/HTTP/CLI touch parity (MCP inline-touch `recall.rs:1180` vs HTTP #1580 defer)
- **G1.5** skip-memory pre-recall predicate — a `do-not-recall`/quarantine flag honoured *before* the touch+rank stage (stateless one-shot query / window already <40% used / under-review memory), so a flagged memory never contributes salience nor surfaces; the cheapest form of purity

### G2 · Attested decorrelation (N≥3) · TRACKED §5 / #1719 / #1171
Probe advisory-only, enforce INERT (correctly); `model_family` is **claimed** (`src/curator/decorrelation_probe.rs:55`); curator reflection is single-producer monoculture (`reflection_pass.rs:430`).
- **G2.1** attested `model_family` primitive (#1719) — **HARD PREREQUISITE of enforce** (refusing on claimed distinctness is theater)
- **G2.2** write-time N≥3 family-distinct admission gate (#1171 panel)
- **G2.3** behavioral / correlated-error decorrelation rung
- **G2.4** break the single-producer reflection monoculture

### G3 · Secure-default attestation flip · TRACKED #1464
`AI_MEMORY_REQUIRE_AGENT_ATTESTATION` (#48) + `AI_MEMORY_FED_REQUIRE_WRITE_SIG` (#94, `src/federation/receive_auth.rs`) default permissive. **Fix:** flip both secure-default-on (mirror #1789), each with a documented rollout escape hatch; closes distributed verification.

### G4 · Epoch-FREEZE consumer (verify-only) · PARTIAL-TRACKED (RQ-10)
Depth cap fail-closed (`src/storage/reflect.rs:413`); `epoch_freeze`/`stopper` = 0 src hits.
- **G4.1** verify-only `SignableEpochManifest` consumer (**no optimizer**); dominance-threshold trip → write-FREEZE handing direction to a human
- **G4.2** fan-in ≤K + per-epoch budget ≤B *(P1-priority sub-rung — hardening, not a release blocker; fan-in unbounded today `reflect.rs:317-334`)*

---

## P1 — v0.9.x structural hardening (the L1 spine)

- **G5 · Audit chain is a diary, not a witness · UNTRACKED.** `agent_attested` self-signs against its own key (`src/identity/verify.rs:164`); ATTEST binds output (`content_sha256`, `src/identity/sign.rs:339`) not cause; `witness_level` = 0 hits. *Fix:* countersign path (G5.1) · witness_level on recall (G5.2) · batch-Merkle transparency log **with split-view / equivocation detection** — gossip signed tree-heads to mutually-distrusting witnesses so a single writer cannot show two divergent histories to two readers (G5.3) · sign `{input_leaves, causal_roots}` (G5.4).
- **G6 · Append-only broken at write AND erase · UNTRACKED (the spine break).** `storage::update` + `ON CONFLICT DO UPDATE` default; `EditSource::Human` in-place (`src/models/memory.rs:817`); `storage::forget` hard-DELETEs (`:2850`); federation hard-deletes (CALL `src/handlers/federation_receive.rs:1184`). *Fix:* SUPERSEDE-not-UPDATE default (G6.1) · signed FORGET tombstone leaf (G6.2) · no hard-DELETE on federation/autonomy paths (G6.3) · **typed forgetting operators (G6.4)** — replace the single hard-DELETE with a closed verb set **EXPIRE** (TTL-natural, tombstoned) / **EVICT** (capacity GC, recoverable from archive) / **REDACT** (content-scrub, row+lineage retained) / **DISTILL** (superseded-into-summary, RELATE-linked), each emitting a distinct signed leaf so "what kind of forget happened and why" is itself a recallable, attestable Claim.
- **G29 · Secrets / credentials in memory have no write-path screen · P1 · UNTRACKED.** `validate.rs` gates only shape + length (`validate_create`, `src/validate.rs:917`) — no entropy scan, no key-pattern detector (PEM / `AKIA…` / JWT / `xai-…` / Bearer), no high-density screen. A pasted private key, API token, or password lands as ordinary content and then leaks through **every** read surface: recall, forensic-export (`src/forensic/bundle.rs:1114`), and federation push. The substrate classifies its *own* env vars as `secret` yet applies zero screening to caller-supplied content. *Fix:* fail-closed pre-write secret-screen (entropy + key-pattern + denylist) on the SAL write path (G29.1) → REDACT-or-REFUSE policy knob per namespace (G29.2) → screen the forensic-bundle + federation egress as defense-in-depth (G29.3). *(Codegraph-verified live defect.)*
- **G30 · Erasure fanout incomplete — data remanence on forget · P1 · UNTRACKED (the right-to-be-forgotten break).** Bulk `db::forget` (`src/storage/mod.rs:2852`, behind HTTP `forget_memories` + MCP `handle_forget`) correctly purges the row + FTS + embedding columns + `recall_observations`/`memory_links` cascades, but erasure does **not** fan out to three derived channels: **(a)** the **federation push-DLQ** retains the full cleartext body — `payload_json` with a deliberately non-FK `memory_id` (`migrations/sqlite/0041_v07_federation_push_dlq.sql:35-37`), never purged on forget; **(b)** no peer-deletion + **no persisted tombstone** (bulk forget never calls `broadcast_delete_quorum` — the sole caller is the per-row path `handlers/memories.rs:967` — and `federation_receive.rs:446-450` confirms "simple remove (no tombstone row)"), so a re-sync from a retaining peer **resurrects** the forgotten memory via LWW; **(c)** the **HNSW vector survives in RAM** (bulk forget never calls `idx.remove`, cf. the scrubbing sites `handlers/memories.rs:548`, `federation_receive.rs:395/1145/1746`) and still answers nearest-neighbour recall until the next rebuild. *Fix:* scrub DLQ `payload_json` in the forget tx (G30.1) → emit + persist a signed FORGET tombstone the receive path checks before accepting an inbound write (G30.2, pairs with G6.2) → evict the vector from `active`+`warming` graphs synchronously (G30.3). *(Codegraph-verified live defect — `forget` deletes a row; it does not erase content.)*
- **G7 · Contradiction auto-resolved, not conserved · UNTRACKED.** `forget_if_superseded` (`src/autonomy.rs:483`) hard-DELETEs the older contradicted memory (`db::delete`, `:538`). *Fix:* conserved `fork_set` + signed tombstone; curator never adjudicates the winning Claim.
- **G8 · UUID identity, not BLAKE3-CID · UNTRACKED.** `id = uuid::Uuid::new_v4()` (`src/storage/mod.rs:2083`); `blake3` = 0 hits. *Fix:* BLAKE3-CID parallel write path (compute@write, store alongside UUID, migrate reads to prefer).
- **G9 · No three-key Recorder≠Judge≠Stopper · UNTRACKED (hub property).** Single daemon TCB (`src/storage/mod.rs:11825`); `governance.halt` = 0 hits. *Fix (hub):* trust-domain key split + `governance.halt` + M-of-N human Stopper; *(endpoint):* ship the can't-attest capability manifest.
- **G10 · Capability tokens / refusal-as-Claim / promotion-court / namespace-isolation absent · UNTRACKED.** Refusal is an audit row, not a recallable Claim (`src/governance/refusal.rs:41-66`); promotion is automatic on access count (no court); there are **no capability tokens** — no blast-radius scoping, no co-signer fields, no bounded-expiry grant. Critically, **namespace is a tag, not a trust boundary at v0.8.0**: governance defaults are allow-on-silence (`CorePolicy::default()` write/promote = `Any`, `src/models/namespace.rs:555`) and cross-namespace recall is unrestricted (`RecallRequest.namespace` is an optional filter → a caller recalls across every namespace by default), so namespace provides zero isolation. *Fix:* capability-token primitive with blast-radius + co-signer + bounded-expiry fields (G10.1) → refusal-as-recallable-Claim (G10.2) → promotion-court replacing access-count auto-promote (G10.3) → **a bridge-capability making cross-namespace recall an explicit, granted, co-signed capability rather than the default — turning the namespace tag into an enforced isolation boundary (G10.4)**.
- **G11 · Federation LWW, not causal-CRDT; no `fork_set` on recall · PARTIAL-TRACKED (Pillar-3 LWW).** `src/models/crdt_merge.rs` — `merge_memory:463`, LWW `updated_at` tiebreak `:228`; `version_vector` ships-but-doesn't-gate; `fork_set` = 0 hits. *Fix:* causal-order-conserving merge + surface `fork_set`/staleness on recall.
- **G12 · Durability reported as a 503, not a subscription · PARTIAL-TRACKED — the one carve-out exception, an API-SEMANTICS BUG.** On W-of-N miss the handler returns `503 quorum_not_met` (`src/handlers/create.rs:667/672/1018`, `memories.rs:568`) — but the local row already **persisted** and is never rolled back (ADR-0001, `create.rs:941-966`). The node is not blocked from writing; the 503 misreports a locally-durable write as a service failure. *Fix:* return 201/200 with quorum-state in the body (or 202 Accepted) — **never 5xx**; replication becomes an async subscription with a named alarm on un-receipted gaps (push-DLQ exists, `src/federation/push_dlq.rs`).
- **G13 · Identity is string+keypair, not a signed lineage-DAG · UNTRACKED.** Single Ed25519 keypair; `genesis`/`succession`/`dead-man` = 0 hits; `reown` is operator bulk-fix (`src/store/mod.rs:775`); key-loss = death. *Fix:* signed lineage-DAG + genesis + succession (pairs with G17).

---

## P2 — v1.0 / TRACT conformance program

| ID | Gap | Tracked | Anchor |
|----|-----|---------|--------|
| G14 | Server-side at-rest, not mandatory client-side sealing | PARTIAL §6.3 (#1809) | `src/encryption/mod.rs` |
| G15 | TTL-tiers, not a Landauer cost-of-access gradient | UNTRACKED | `src/models/memory.rs:528` |
| G16 | No (n,k) erasure-coded no-primary cold tier | UNTRACKED | erasure/no-primary = 0 hits |
| G17 | No M-of-N threshold key recovery / dead-man succession | UNTRACKED | `shamir`/`threshold_key` = 0 hits |
| G18 | Human↔AI covenant clauses (why_trace, immutable authorship, permanent dissent, signed forget receipt) | UNTRACKED | provenance never a write-gate `src/validate.rs:917` |
| G19 | Closed 9-relation enum, not open-predicate-over-kernel | UNTRACKED | `MemoryLinkRelation` CHECK `src/models/link.rs:239` |
| G20 | Claim-level bitemporal absent (links only) | UNTRACKED | `src/models/link.rs:319-328` |
| G21 | No Rosetta decoder-in-archive (crypto-spine only) | UNTRACKED | `src/forensic/bundle.rs:1114` |
| G22 | RPC-verbs, not the six-verb Claim algebra (L1 core) | UNTRACKED | 27-field thick row `src/models/memory.rs:756` |
| G23 | First-class vector index substrate | TRACKED §23 #G2/#G3 | HNSW disposable cache `src/hnsw.rs:238` |
| **G24** | **CC0 test-vector conformance harness — THE KEYSTONE** | UNTRACKED | converts the L1 delta into falsifiable tests |
| G25 | CC0/MPL split, no-CLA, N-of-M foundation | PARTIAL §7 (operator-decision) | — |
| G26 | Postgres `archived_memory_links` snapshot/restore wiring (v70) | TRACKED | sqlite wired, pg follow-up |
| G27 | Checkpoint/epoch federation holes FED-RQ-02..05 | TRACKED | FED-RQ-01 federates; 02–05 OPEN |
| **G28** | Forbidden-export-class taxonomy absent (biometric/behavioral embeddings, master/threshold keys, signed policy-rules never cross the boundary) | UNTRACKED | forensic bundle + federation export the full row `src/forensic/bundle.rs:1114` |
| G31 | Latency-SLO degrade actuator / ∅·A·B·C degradation manifest absent (fills Pillar 14) | UNTRACKED | degrades only on embedder *failure* (#1593), never on a latency *budget* |
| G32 | Privacy-preserving cross-mind learning primitive (MPC / FHE / DP — shared *statistic*, never shared corpus) | TRACKED §11.7 / v1.0 FED-RQ-AGG (#1707) — horizon, **advertise-banned** | 0 production hits (`mpc`/`fhe`/`differential_privacy`) |

**P2 detail.** **G28** — both export surfaces serialize the full memory row with no class filter (forensic bundle `src/forensic/bundle.rs:1114` + federation push emit biometric/derived embeddings, key material, and signed governance-rule bodies the same as ordinary content); *fix:* a forbidden-export-class taxonomy enforced at both egress points, refused-or-sealed-separately, never bundled in the clear. **G31** — the only honest-degrade today is embedder-*failure* fallback to keyword (#1593) + admission-shed `503` (#1733, load not latency); *fix:* a latency governor reading recall p95 that selects a named degradation tier (∅ full → A drop rerank → B drop semantic → C keyword-only), surfaced in the response. **G32** — `git+rg` shows zero MPC/FHE/DP; this is the *constructive* twin of TRACT's defensive "not a hive mind" — federation MAY compound a **counted statistic** (secure-agg/DP) over decorrelated corpora while every node keeps its corpus private, the aggregate re-entering as a distilled authored Claim; it shares a statistic, **never an objective/gradient/corpus** (that would be the §11-banned compounding), and is **advertise-banned** at v0.8.0.

---

## P3 — proof-impossible (TRACT §15) — *not backlog*

**Exactly 3 genuine proof-impossibles:** (1) **vote-independence** — a substrate sees signed bytes, never the generating process, so it cannot distinguish genuine agreement from N rubber-stamp votes by one model in N hats (0% throughout, architectural limit); (2) **signer ≠ thinker** — cryptography attests key-custody, never cognition; (3) **singleton-ASI no-counterparty** — no peer to attest against, diary reversion. The other §15 items (legibility-anti-ritual, oblivious search, dark-age tombstone reach, migration re-encode, joule economics, deep-archive funding) are engineering-OPEN/CAP-bounded — programs, not perma-bans.

**The self-discipline gap.** ai-memory's *own framing* violates TRACT §16's banned-grandeur rule: the moonshot register ("civilization-scale," "through AI→AGI→ASI→and beyond," "eternity-grade," CLAUDE.md "World-class only / driving toward perfection," commit `fd68550d`) is the exact vocabulary TRACT bans — and TRACT's own council rejected its "Eternal Ledger" name for this. It also lacks a kill-capable benchmark gate, a preserved live DO-NOT-BUILD dissent, and a narrowed irreducible-20% scope.

---

## Crosswalks

**Grok ↔ Opus ↔ Final (representative):** Grok `M-P0-01`+`M-P0-02`+`M-P0-08` & Opus `P0-G1` → **G1**; Grok `M-P0-03/04/06` & Opus `P0-G2` → **G2** (model_family prerequisite); Grok `M-P1-13` & Opus `P1-G7` → **G7**; Grok `M-P1-14` & Opus `P1-G6` → **G6**; Grok `M-P1-09` & Opus `P1-G12` → **G12**. Grok's `M-P2-14` (#1672/#1674/find_paths) → **DROPPED (FIXED)**. Opus-only (no Grok M-ID): G13, G16, G17, G19, G20, G21, G22.

**ROADMAP §5 → TRACT:** N≥3 quorum §7 → G2 · behavioral probes §7 → G2.3 · distributed verification #1464 §5 → G3 · model-signature chain §11.4.D §7 → G2.1 · §23 vector index → G23 · §22 policy audit §6 → G10 · hive E2E #1809 §9 → G14 · FED-RQ-02..05 §10 → G27. *Roughly half the delta has a ROADMAP home; the L1 frozen-core spine (tombstone leaves, three-key, witness tiers, CID, six-verb algebra, CC0 vectors) has no conformance program at all.*

**CodeGraph 0-match index:** `fork_set` · `witness_level` · `governance.halt` · `epoch_freeze` · `epoch_manifest` · `blake3` · `shamir` → 0 production matches each (falsifiable negative evidence the gaps are structural).

---

## Phased sequence (with the §16 kill-test gate)

**Phase A — v0.9.0 (P0):** G1 recall purity → G2 (G2.1 attested model_family ▶ G2.2 N≥3 enforce ▶ G2.3 behavioral rung) → G3 secure-default attestation flip → G4 epoch-freeze consumer.
**Phase B — v0.9.x→v1.0 (P1, spine BEFORE witness):** **G29 secrets-screening + G30 erasure-fanout first** (live data-privacy defects — §24 prime-directive: file+fix, not defer) → G6 SUPERSEDE-not-UPDATE + signed FORGET tombstone (the spine; G30's tombstone is the same primitive) → G7 contradiction-conserve fork_set → G5 witness tiers + countersign + sign-cause → G12 durability-subscription fix → G11 causal-CRDT + fork_set → G8 BLAKE3-CID → G13 lineage-DAG.
**Phase C — v1.x (P2, keystone FIRST):** **G24 CC0 test-vector harness** → G22 six-verb Claim algebra → G14 client-side sealing → G15/G16/G17 cost-gradient/erasure/threshold-key → G18 human-covenant → G19 open-predicate CID → G25 license anti-capture (operator-decision).

**Kill-test gate:** *if recall still mutates and decorrelation is still claimed-only at v0.9.0, the substrate fails its own §16 kill-test against git+ripgrep+RAG.* Phase A is the minimum bar to honestly claim it beats the trivial baseline.

---

## Banned claims until gaps close

**Gap-gated (unlock when the keyed deliverable lands + is codegraph-verifiable):**
- ❌ "reads never write" / "pure recall" — G1 (+ MCP/HTTP/CLI parity G1.4)
- ❌ "decorrelation enforce shipped" / "N independent producers" — G2 (all of model_family + N≥3 + behavioral); until then only *"estimated-decorrelated, CLAIMED"*
- ❌ "secure-by-default attestation" / "distributed verification default-on" — G3
- ❌ "epoch-freeze" / "write-FREEZE stopper" / "bounded reflection (K/B)" — G4
- ❌ "witnessed" / "externally attested" / "countersigned" / "Merkle transparency log" / "signs the cause" — G5
- ❌ "append-only" / "no silent delete" / "immutable record" — G6
- ❌ "contradiction conserved" / "permanent dissent" — G7
- ❌ "content-addressed" / "tamper-evident by construction" / "BLAKE3 identity" — G8
- ❌ "three-key Recorder≠Judge≠Stopper" / "human Stopper <1s HALT" — G9
- ❌ "causal merge" / "conflict-free" / "CRDT-correct" — G11
- ❌ "durability guaranteed" / "quorum-durable writes" — G12 *(this is a BUG, not honest divergence)*
- ❌ "end-to-end encrypted" / "client-side mandatory sealing" — G14
- ❌ "signed lineage / succession / threshold-key recovery" — G13/G17
- ❌ "TRACT-/L1-conformant" / "implements the Claim algebra" — G24 (keystone) + G22
- ⚠️ G29 (v0.8.1 W1, commit `742b5f39`) — **PARTIALLY EARNED.** "best-effort credential screening on write + egress (entropy + key-pattern, default-refuse, both backends)" is now earned and may be claimed *with that qualification*. The absolute forms ❌ **"no credentials in memory" / "credential-safe"** stay BANNED regardless — a heuristic pattern/entropy screen cannot make a universally-quantified negative true (a novel vendor token, a prose passphrase, or a pre-existing row predating the screen can still pass), so unqualified credential-freedom is never earned.
- ❌ "namespace-isolated" / "namespace is a trust boundary" / "cross-namespace isolation" — G10.4
- ⚠️ G30 (v0.8.1 W2, commits `6f382300`/`59fb1729`/`5ad1daec`/`c0d4c66d`/`2287e2f8`) — **PARTIALLY EARNED.** A *hard* forget (`archive=false`) now erases all LOCAL queryable copies — row, FTS, embedding column + the in-RAM HNSW vector, the `federation_push_dlq` cleartext payload, and the `transcript_line_dedup` content-hash oracle — and a signed FORGET tombstone makes the erasure **resurrection-resistant** (a peer's LWW re-push is rejected, both backends). The earned claim is *"local hard-forget erases all queryable copies + resists peer-resync resurrection (signed tombstone)."* STILL QUALIFIED: a recoverable forget (`archive=true`, the default) intentionally retains a restorable `archived_memories` copy; cross-mesh tombstone PROPAGATION (so peers also erase) + owner-authz is the v0.9 federated-erasure layer (#1823); and SQLite freed-page/WAL remanence (`secure_delete` off) + the `signed_events` content-hash residue mean unqualified **"complete erasure / no data remanence / right-to-be-forgotten compliant"** is NOT yet earned.
- ❌ "export-screened" / "biometric-safe export" / "forbidden-class filtered export" — G28
- ❌ "SLO-guaranteed latency" / "latency-bounded recall" / "graceful degradation tiers" — G31
- ❌ "privacy-preserving cross-mind learning" / "federated / MPC / FHE / DP learning" — G32 (advertise-banned horizon)

**Perma-banned (regardless of gap status — TRACT §15/§16):**
- ❌ §15 horizon: singleton-ASI containment, vote-independence, "stops an ASI", signer≠thinker enforcement
- ❌ the grandeur register — "eternal," "∞," "for eternity," "eternity-grade," "civilization-scale," "world-class to infinity," "ASI-ready," "through AI→AGI→ASI→and beyond" — **including ai-memory's own moonshot/house vocabulary** (TRACT §16.13)
- ❌ TRACT-verbatim: "perfect memory," "hive-mind," "implements Red Queen / RQGM," "ZK-synced semantic search," "runs in kilobytes of RAM"

**Allowed now (self-qualified — "half" never "whole," CLAIMED never ATTESTED):** "constitutional / consent-bound / attested-endpoint persistence" · "fail-closed governance substrate" / "capability-cliff-respecting recorder" · "tamper-evident audit chain (single-writer)" · "operational NHI identity layer" / "Ed25519-signed coordination substrate (attestation opt-in)" · "bias-displacement trajectory (advisory, CLAIMED-not-ATTESTED)" · "encrypted local substrate with optional consent-gated replication" · "backend-blind SAL" · "open protocol + reference implementation" · "the strongest existing realization of TRACT's safety/governance **half**" (always paired with the explicit weak-axis disclosure) · "100% OSS, Apache-2.0" *(but not unqualified "free forever" while the G25 CLA capture-vector stands)*.

---

## Corpus-completeness provenance (G28–G32 + the G1/G5/G6/G10 enrichments)

These five gaps did **not** come from the four model-family assessment passes — they surfaced from a separate **21-agent corpus-completeness pass** (3 waves × 7) that diffed the *pre-TRACT design corpus* (the four superseded clean-slate design drafts) against TRACT itself, to confirm whether TRACT — the sole measuring stick used in the v0.8.0 assessment — dropped anything valuable before becoming that stick. **Finding: TRACT is a faithful ~97% superset of the corpus** — no constitutional/concept-level loss, 8 of 15 themes *extended* with net-new resolutions, and the "for infinity / OSS" longevity clause substantively honored (only the grandeur *words* were cut; the mechanisms were kept and several sharpened). The one real cost of TRACT-as-sole-stick was **enumeration attrition**: TRACT distilled several operational/security checklists into prose, which silently dropped five testable obligations (G28–G32) plus the finer sub-rungs folded into G1/G5/G6/G10. **The correct-now scorecard and two-axis grade are unchanged** — these additions deepen the backlog, they do not move the verdict (none was previously claimed-as-done). Full report: [`../reviews/corpus-completeness-21-agent-OPUS.md`](../reviews/corpus-completeness-21-agent-OPUS.md).

---

## Why the convergence matters

This catalog is **not one model's opinion.** Four independent passes across two *decorrelated model families* (Grok/xAI + Opus/Anthropic) — the closest live instance of the N≥3 attested-distinct-producer property the substrate aspires to and cannot yet enforce — converged on the same verdict, the same P0 set (recall purity → attested model_family + N≥3 enforce → secure-default attestation flip → epoch-freeze), the same root divergences, and near-identical readiness bands. They disagreed only on emphasis and a handful of `file:line` anchors — every one code-corrected here. **No pass produced an opposing verdict.** Reported as **estimated-decorrelated / CLAIMED, not ATTESTED** (model-family provenance is not yet cryptographically attested), this is the strongest available evidence the verdict is *true*.

---

*Canonical reduction authored by Claude Opus 4.8 (1M context) from four assessment passes (Grok + Opus first-party → two reconciliations → a 21-agent adjudication council), all CodeGraph-anchored against ai-memory `release/v0.8.0`. Every gap carries a `file:line` touchpoint + a TRACKED/UNTRACKED tag; contested anchors were codegraph-reconciled and corrected. Companion: [`TRACT-v0.8.0-CORRECT-NOW-CANONICAL-opus.md`](TRACT-v0.8.0-CORRECT-NOW-CANONICAL-opus.md). Tracked in ROADMAP.md §26.*
