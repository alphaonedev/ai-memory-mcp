# Grok 3×7 Assessment — ai-memory v0.8.0 Development Gaps

**Assessment date:** 2026-06-28  
**Method:** 21-lens adversarial audit (3 waves × 7 lenses) of `docs/design/TRACT-the-definitive-endpoint-ai-memory.md` against `release/v0.8.0` @ `14a34566`, cross-checked with [main `ROADMAP.md`](https://raw.githubusercontent.com/alphaonedev/ai-memory-mcp/refs/heads/main/ROADMAP.md) and **CodeGraph** structural probes.  
**Analyst:** Grok (xAI) — synthesis round 4 of the TRACT design lineage.  
**Companion:** `Grok-TRACT-v0.8.0-Correct-Now.md`

---

## Executive verdict

v0.8.0 closes ROADMAP §11.4 Pillar 1–4 **implementation scope** and ships honest advisory decorrelation (#1764). The **load-bearing gaps** vs TRACT and ROADMAP §5 are architectural — not polish. Grok classifies **47 tracked gaps** into four priority tiers.

| Tier | Count | Horizon | Theme |
|------|-------|---------|-------|
| **P0** | 8 | v0.9.0 blocker | Recall purity, decorrelation enforce, distributed verification |
| **P1** | 14 | v0.9.x | L1 attestation upgrade, federation semantics, human covenant |
| **P2** | 15 | v1.0 | Claim migration, privacy sovereignty, tier manifests |
| **P3** | 10 | Horizon / proof-impossible | TRACT §15 open problems, singleton ASI |

**Grok bottom line:** The gap between "world-class substrate" and "TRACT L1 constitution" is **~2–3 release cycles** of deliberate migration — not a single refactor. ROADMAP already names most P0/P1 items; this document maps them to TRACT sections with code evidence.

---

## P0 — v0.9.0 blockers (ROADMAP §5 committed)

### G-P0-01 · Recall is not a pure read (TRACT §3 · §10 Landauer)

**TRACT:** RECALL writes nothing; `access_count++`, TTL bump, promote-on-read are forbidden.  
**v0.8.0:** `touch_many` mutates on every recall path.

| Call site | Evidence |
|-----------|----------|
| Storage layer | `src/storage/mod.rs:1442-1483` — `access_count`, `expires_at`, mid→long promotion, priority bump |
| Hybrid recall | `src/storage/mod.rs:10704-10727` — `apply_recall_post_ops` → `touch_many` |
| MCP recall | `src/mcp/tools/recall.rs:1180-1205` — inline touch (no HTTP #1580 split) |
| Ranking formula | `src/storage/mod.rs:3686-3691` — scores live `access_count` + `priority` |

**Downstream:** Goodhart loop (rich-get-richer on read); privacy leak (access patterns = content per TRACT §9).  
**ROADMAP:** #1706 shadow consume-rate vs `access_count` proxy; #1707 conditional live wire — explicitly deferred v0.9.  
**TRACT fix shape:** Kill `touch_many` on recall; lazy pure `S(t)`; async epoch-bucketed CONSUME ledger; distillation → authored `RELATE` edges.

---

### G-P0-02 · CONSUME ledger wrong shape + sync on hot path (TRACT §3)

**TRACT:** Epoch-bucketed counts `(claim_id, epoch_bucket)`; async, batched, off latency budget.  
**v0.8.0:** `recall_observations` per-candidate rows written **at recall time** (`src/observations/mod.rs:65-89`); `mark_consumed` sync on store/link.

**Partial credit:** `recall_id` + cite-back seam is correct (`src/mcp/tools/store/mod.rs:975`).  
**Gap:** Conflates "surfaced" with "used"; no distillation tier; consume signal not input to ranking (`docs/strategy/decentmem-mapping.md:42-44`).

---

### G-P0-03 · N≥3 decorrelation enforce — not shipped (ROADMAP §5 · TRACT §7)

**ROADMAP §5:183,205:** Primary mechanism = multi-reflector N≥3 quorum; committed v0.8/v0.9; enforcement v0.9.0+.  
**TRACT §7:164-170:** `enforce` inert on claimed metadata until attested `model_family`.  
**v0.8.0:** Visibility-only probe (`src/curator/decorrelation_probe.rs:14-33`); `Enforce` degrades to advisory (`config.rs:4983-4984`).

**Blockers:**
- No attested `model_family` primitive (#1719).
- Heterogeneous evaluator panel not wired to write gate (#1171).
- Curator reflection is single-producer monoculture (`reflection_pass.rs:430-433`).

---

### G-P0-04 · Behavioral decorrelation — absent (TRACT §7)

**TRACT:** `decorrelation_grade = min(structural, behavioral)`; beacon-bound challenge sets; correlated-error rate; continuous mandatory rung.  
**v0.8.0:** Producer-dominance on **claimed** `model_family` / `agent_id` only (`decorrelation_probe.rs:92-167`).

**ROADMAP candidate (2)** empirical probes — not implemented beyond dominance counting.

---

### G-P0-05 · Distributed verification — federation writes still claimed (ROADMAP §5 · #1464)

**ROADMAP §5:** Second co-equal gap — per-write federation `agent_id` attestation is *claimed*, not *attested*.  
**v0.8.0:** `AI_MEMORY_FED_REQUIRE_WRITE_SIG` defaults **permissive** (`0`); opt-in strict (#1464). Agent attestation carve-out: `AI_MEMORY_REQUIRE_AGENT_ATTESTATION` defaults off.

**TRACT alignment:** Quarantine inbound → local-verify → promote is **partially** shipped; secure-default flip is the v0.9 hardening lane.

---

### G-P0-06 · Model-family attestation chain (ROADMAP §11.4.D · TRACT §7)

**ROADMAP:** §11.4.D "strategically critical" — foundation for §5 gap.  
**TRACT:** Provenance-attested lineage; decorrelation needs attested distinctness.  
**v0.8.0:** `model_family` is optional **claimed** metadata key (`decorrelation_probe.rs:55`); nothing cryptographically binds producer family.

**Tracked:** #1719, ROADMAP §1173 D3-012 (attested `model_family`) → D3-021 (live enforce).

---

### G-P0-07 · Epoch-freeze brake — unbuilt (TRACT §7 · §11)

**TRACT:** Utility weights frozen within epoch; rotated only by signed manifest at boundary; external optimizer killed.  
**v0.8.0:** Grep `epoch_manifest` / `epoch_freeze` in `src/` → **0 matches**. ROADMAP v0.9 RQ-10 (`SignableEpochManifest`) not landed.

**Note:** Correctly does **not** ship in-substrate optimizer — but freeze **consumer** is also absent.

---

### G-P0-08 · Attestation secure-default flip (ROADMAP §2.3 carve-out)

**ROADMAP §2.3:** Agent attestation + peer enrollment ship permissive at v0.7.0; #1464 tracks v0.8 secure-default flip.  
**v0.8.0 status:** Peer enrollment **flipped** (#1789 ✅). Agent write attestation + `FED_REQUIRE_WRITE_SIG` still **opt-in** ❌.

---

## P1 — v0.9.x structural hardening

### G-P1-01 · L0/L1 Claim object — UUID not BLAKE3 CID (TRACT §2)

| TRACT | v0.8.0 |
|-------|--------|
| `id = BLAKE3-256(dCBOR(content) ‖ provenance)` | UUIDv4 at store (`store/validation.rs:300`) |
| 9-field frozen Claim | 27-field `Memory` + SQL projections |
| Owner outside hash (lineage-DAG) | `namespace` + `metadata.agent_id` |
| Bitemporal provenance in hash | `created_at`/`updated_at` only |
| No UPDATE verb | `storage::update` + `ON CONFLICT DO UPDATE` upsert |

**Migration:** ROADMAP has no named TRACT conformance program; would require CC0 test-vector harness + parallel write path.

---

### G-P1-02 · Sign-cause-not-output (TRACT §5)

**TRACT:** ATTEST binds `{input_leaves, causal_roots, elapsed, signer}`; commit-before-act + VDF.  
**v0.8.0:** `SignableWrite` binds output identity + `content_sha256` (`src/identity/sign.rs:313-339`).

**Risk TRACT names:** "Output-only attestation = non-repudiation of a lie."

---

### G-P1-03 · Countersignature attestation (TRACT §5)

**TRACT:** `attest_level` rises only via countersignatures from different key + trust domain.  
**v0.8.0:** `agent_attested` = self-signature against own enrolled key (`src/identity/verify.rs:164-166`).

---

### G-P1-04 · Batch-Merkle transparency log (TRACT §5)

**TRACT:** Leaves batch into Merkle tree; batch roots hash-chain.  
**v0.8.0:** Flat per-row `prev_hash` chain (`src/signed_events.rs`) — no Merkle batching.

---

### G-P1-05 · `witness_level` tiers (TRACT §5)

**TRACT:** `threshold` · `deferred` · `counter` · `bare` on every recall.  
**v0.8.0:** **Zero code** — spec-only in TRACT doc. No offline-degradation surfacing.

---

### G-P1-06 · FORGET tombstone leaves (TRACT §2 · §5)

**TRACT:** Signed tombstone leaf; erasure witnessed; no silent DELETE.  
**v0.8.0:** `storage::forget` archives optionally then **DELETE** (`src/storage/mod.rs:2850+`); federation sync hard-deletes (`federation_receive.rs:446-451`).

---

### G-P1-07 · Three-key Recorder ≠ Judge ≠ Stopper (TRACT §6)

**TRACT:** L1 TCB — three keys in distinct trust domains; rule-root outside cognition address space.  
**v0.8.0:** Single daemon holds storage + evaluation + audit signing (`src/storage/mod.rs:11825-11933`). No `governance.halt` / Stopper type.

**Exists instead:** K9/K10 governance stack, consensus **approval** votes (≠ emergency Stopper).

---

### G-P1-08 · Capability tokens (TRACT §6)

**TRACT:** `WRITE(scratch) · PROMOTE · RECALL · DELETE · VETO(human-root)` — default-deny, non-transferable.  
**v0.8.0:** **Not implemented** — `GovernanceLevel` + API key + HMAC, not capability tokens.

---

### G-P1-09 · Refusal-as-Claim (TRACT §6)

**TRACT:** `{cause, rule_hash, denied_digest}` as first-class readable data.  
**v0.8.0:** `GovernanceRefusal` typed envelope + audit row — no `rule_hash`, no `denied_digest`, not queryable via RECALL.

---

### G-P1-10 · Promotion court (TRACT §6)

**TRACT:** scratch→durable for sensitive kinds requires provenance + conflict + human gate **before persist**.  
**v0.8.0:** `promote` defaults `GovernanceLevel::Any` (`namespace.rs:877-878`); generic `pending_actions`, not typed court.

---

### G-P1-11 · Federation `fork_set` on recall (TRACT §8)

**TRACT:** Every recall carries `{epoch, staleness, provenance, fork_set}`.  
**v0.8.0:** `fork_set` — **zero** `src/` references. CRDT merge silently converges (`crdt_merge.rs:463-588`).

---

### G-P1-12 · Durability as subscription, not gate (TRACT §8)

**TRACT:** `{observed:1, target:N}`; async `durability_reached`; partitioned node keeps thinking.  
**v0.8.0:** Synchronous `503 quorum_not_met` on create (`create.rs:665-667`); `merge_tier` = max storage rank, not witness count.

---

### G-P1-13 · No forced reconvergence (TRACT §8)

**TRACT:** Forks MAY diverge permanently; merge only via signed `merge` event.  
**v0.8.0:** `merge_inbound` → `merge_memory` collapses to one row; W-of-N pushes merged state cluster-wide.

---

### G-P1-14 · Causal order over wall-clock LWW (TRACT §8)

**TRACT:** No wall-clock LWW; contradiction conserved in `fork_set`.  
**v0.8.0:** `crdt_merge.rs:228-237` — `updated_at` primary tiebreak; `version_vector` ship-but-don't-gate.

---

## P2 — v1.0 / TRACT conformance program

### G-P2-01 · Client-side mandatory sealing (TRACT §9)

Operator reads title/tags/metadata/embeddings/FTS; encryption opt-in on content only (`src/encryption/mod.rs`). TRACT: seal everything including utility signals before boundary crossing.

### G-P2-02 · Tombstone-subscription on replicas (TRACT §9)

No `tombstone_subscription` primitive; `memory_share` / replication descendants don't inherit signed back-edges for FORGET propagation.

### G-P2-03 · Tier ∅/A/B/C capability manifests (TRACT §10)

`memory_capabilities` schema v3 reports compile-time blocks — not per-silicon "what this tier cannot attest." Mobile CI = compile proof, not Tier-A honesty manifest.

### G-P2-04 · Open predicate CID space (TRACT §2)

Closed 9-relation SQL CHECK — no content-addressed predicate definitions.

### G-P2-05 · Signed lineage-DAG identity (TRACT §4)

No `genesis` / `succession_policy` / dead-man heartbeat / contestation window. `ai-memory reown` is operator bulk fix, not ante-mortem consent succession.

### G-P2-06 · Genesis bootstrap block (TRACT §5)

No frozen genesis `{H(constitution), root_key_set M-of-N, external_anchors[≥2]}`.

### G-P2-07 · Human covenant §14 clauses 1–2, 4–5 (TRACT §14)

| Clause | Gap |
|--------|-----|
| Legibility at write (`why_trace` in id) | No `why_trace` field |
| Permanent dissent | `contradicts` exists; no immutability/GC immunity |
| Bilateral anti-coerced SUPERSEDE | Not implemented |
| Export + forget covenant-tiered | Partial — not Rosetta-bundled every export |

### G-P2-08 · TRACT-2026 conformance test-vector harness (TRACT §1)

No CC0 golden vectors executable against reference impl. "Conformant = passes vectors" gate unbuildable.

### G-P2-09 · Reflection bounds K and B (TRACT §11)

Depth cap D ✅; fan-in ≤K and budget ≤B — not enforced (`reflect.rs:317-322` requires non-empty sources only).

### G-P2-10 · Vector index substrate at scale (ROADMAP §23)

HNSW in-memory only; cold-start O(N); silent eviction at 100k (#G2/#G3). v0.9 §23 plan.

### G-P2-11 · End-to-end federation encryption (ROADMAP §6.3)

Federation push/pull plaintext today; E2E encryption deferred hive scale.

### G-P2-12 · Checkpoint / epoch federation holes (ROADMAP FED-RQ)

FED-RQ-02..05 OPEN: epoch manifest federation, `/sync/since` checkpoint catch-up, checkpoint W-of-N outbound.

### G-P2-13 · Postgres snapshot/restore link edges (v70)

`archived_memory_links` table exists; postgres snapshot/restore wiring tracked follow-up.

### G-P2-14 · Capability honesty (#1672–#1674)

`curator_mode` over-reports; HTTP `verify_link`/`find_paths` 501; `db_schema_version` returns 0 on default build.

### G-P2-15 · License divergence (TRACT §13)

TRACT: CC0 wire format + MPL-2.0 reference impl. ai-memory: Apache 2.0 throughout. Format not CC0-released.

---

## P3 — Horizon / proof-impossible (TRACT §15)

Grok records these as **not development backlog** — TRACT §15 honest classification:

| # | TRACT §15 item | Status |
|---|----------------|--------|
| 1 | Vote-independence unprovable | Permanent — make loud, never solve |
| 2 | Signer ≠ thinker | Permanent — cryptography ≠ cognition |
| 3 | Legibility anti-ritual | Open — fix breaks capability cliff |
| 4 | Singleton ASI no counterparty | Deepest — diary reversion |
| 5 | Thin-client oblivious semantic search | Bounded — Phase-2 opt-in |
| 6 | Offline dark-age replica unreachable by tombstone | CAP-opposed |
| 7 | Migration-proof civilization re-encode | Open — no central steward |
| 8 | Unbounded-append joule economics | Open |
| 9 | Cumulative slow-wide drift | Open — human must comprehend epoch-N manifest |
| 10 | Deep-archive infra funding | Open — §13 architecture mitigates |

---

## ROADMAP §5 → TRACT gap crosswalk

| ROADMAP commitment | TRACT section | v0.8.0 | Gap ID |
|--------------------|---------------|--------|--------|
| N≥3 decorrelation quorum (primary) | §7 | Advisory only | G-P0-03 |
| Empirical decorrelation probes (secondary) | §7 | Dominance probe only | G-P0-04 |
| Distributed verification (#1464) | §5 | Opt-in | G-P0-05, G-P0-08 |
| Model signature chain (§11.4.D) | §7 | Unbuilt | G-P0-06 |
| §23 vector index substrate | §10 | In-memory HNSW | G-P2-10 |
| §22 policy engine 100% audit | §6 | PE-1..PE-8 partial | G-P1-09 |
| Hive E2E encryption | §9 | Deferred | G-P2-11 |

---

## CodeGraph gap evidence index

Structural probes confirming gaps are **architectural**, not doc drift:

```
touch_many          → src/storage/mod.rs:1502 (recall mutation — G-P0-01)
record_recall       → sync on hot path, not async CONSUME (G-P0-02)
run_decorrelation_probe → read-only post-curator; no write gate (G-P0-03)
SignableWrite       → output-bound, no causal_roots (G-P1-02)
authorize_remote_transition → authority lane only; memories permissive (G-P0-05)
fork_set            → 0 src/ matches (G-P1-11)
witness_level       → 0 src/ matches (G-P1-05)
governance.halt     → 0 src/ matches (G-P1-07)
```

---

## Grok recommended development sequence

### Phase A — v0.9.0 (close ROADMAP §5 + TRACT §3/§7)

1. **Recall purity refactor** — decouple `touch_many` from recall; ship async CONSUME ledger (#1706/#1707).
2. **Attested `model_family`** (#1719) + secure-default attestation flip (#1464).
3. **N≥3 write-time decorrelation enforce** (gated on #1719; panel #1171).
4. **Epoch-freeze consumer** (RQ-10 `SignableEpochManifest` verify-only, no optimizer).
5. **Behavioral decorrelation probe** (ROADMAP candidate 2 — challenge corpus).

### Phase B — v0.9.x / v1.0 (TRACT L1 migration spine)

6. **Witness_level surfacing** on recall responses.
7. **Countersignature path** for `attest_level` promotion.
8. **Federation fork semantics** — `fork_set` on recall, voluntary merge events.
9. **FORGET tombstone leaves** in `signed_events`.
10. **CC0 test-vector harness** + TRACT-2026 conformance gate.

### Phase C — v1.x (sovereignty + covenant)

11. Client-side mandatory sealing.
12. Tombstone-subscription on replication.
13. Tier manifests ∅/A/B/C.
14. Lineage-DAG identity + succession_policy.
15. Human covenant clauses (dissent immutability, anti-coerced SUPERSEDE).

---

## Banned claims until gaps close (TRACT §16)

Do **not** ship marketing or capabilities text implying these are done:

- "decorrelation enforce shipped"
- "pure recall" / "reads never write"
- "TRACT L1 conformant" / "BLAKE3 Claim identity"
- "client-side mandatory encryption"
- "Merkle transparency log"
- "human Stopper <1s HALT"
- "ZK-synced semantic search"

**Allowed (v0.8.0 honest):** "constitutional endpoint persistence," "bias-displacement trajectory (advisory)," "attested coordination substrate," "open protocol + reference implementation."

---

## Grok verdict — development gaps

v0.8.0 is **substrate-ready, constitution-incomplete**. The P0 gaps are the ones ROADMAP §5 and TRACT both name as load-bearing: **recall purity**, **decorrelation enforce with attested provenance**, and **distributed verification defaults**. Everything else is either v1.0 conformance work or TRACT §15 proof-impossible honesty.

The development path is not "catch up to a competitor" — it is **earn TRACT L1 conformance** while keeping the L3 Reference Profile shippable. Grok recommends Phase A as the v0.9.0 gate: if recall is still mutating and decorrelation is still claimed-only, the substrate fails its own TRACT §16 benchmark against `git + ripgrep + RAG` on the irreducible 20%.

---

*Grok 3×7 assessment · 47 classified gaps · CodeGraph L1 evidence · Companion: `Grok-TRACT-v0.8.0-Correct-Now.md`*