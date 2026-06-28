# ai-memory v0.8.0 — What Is Correct Now (Canonical, vs TRACT)

### The single reconciled correctness record — adjudicated across Grok and Opus, CodeGraph-anchored, 21-agent-council-reduced.

> **Method.** Four independent assessment passes across two decorrelated model families — Grok/xAI and Opus/Anthropic — measured the definitive design **TRACT** (`docs/design/TRACT-the-definitive-endpoint-ai-memory.md`) against ai-memory **`release/v0.8.0`** and the **`main` ROADMAP.md**: two first-party 21-agent councils, two reconciliations, then a final **21-agent adjudication council** that codegraph-verified every contested anchor (846 files / 27,062 nodes / 92,578 edges). This document is the canonical reduction; it supersedes the prior first-party and reconciliation drafts. Companion: [`TRACT-v0.8.0-DEVELOPMENT-GAPS-CANONICAL-opus.md`](TRACT-v0.8.0-DEVELOPMENT-GAPS-CANONICAL-opus.md).

---

## Executive verdict

> **ai-memory v0.8.0 is a credible, honestly-labeled TRACT-2026 L3-BODY Reference Profile** — the strongest existing realization of TRACT's hardest, safety-critical half. It ships the constitution's safety/governance/capability-cliff spine strongly, and diverges, knowingly and documentedly, on the data-model fundamentals (content-addressing, append-only, pure recall, causal-CRDT, three-key separation).

**Deploy posture:** ship as TRACT-2026 L3-BODY with best-in-class governance honesty; **never advertise L1, content-addressed identity, three-key separation, decorrelation-enforce, or pure-recall conformance.**

**Operator one-liner:** *The substrate is correct now on safety, attestation, federation coordination, and honest epistemic labeling — and correctly incomplete on the frozen constitution; ship it for what it is, never for what it isn't.*

---

## The grade — two axes, never one composite

Averaging a strong axis with a weak one describes neither, so the grade is reported on two axes and never collapsed to a single letter or percentage.

| Axis | Grade | Covers |
|------|-------|--------|
| **Trust-spine / safety substrate** | **A− / B+** | capability cliff, V-4 audit chain, read-only signed governance, fail-closed federation quarantine, bounded fail-closed reflection, honest CLAIMED-vs-ATTESTED posture |
| **Data-model / epistemics** | **C+** | UUID-not-CID identity, mutating recall, in-place UPDATE + hard-DELETE, single-writer self-attestation, LWW-not-causal-CRDT |

**Calibration strip (estimates, with denominators — never one bare number):**

- ROADMAP §2 seven structural properties: **~75–85%** (all four passes land here independently)
- TRACT L1 frozen core (Claim + six verbs): **~25–35%**
- §7 N≥3 decorrelation *enforce*: **~30%** (advisory floor only)
- §3 recall purity: **~15%** (measurement seam only)

> A blended ~45–50% "TRACT L0–L1 literal" figure exists **only** as a rough planner number; it blends two non-comparable axes and is **not a grade** — use the two-axis grade for any real decision. These are order-of-magnitude bands, not measurements.

---

## The convergence finding (estimated-decorrelated, CLAIMED-not-ATTESTED)

Four independent passes across **two different model families** converged on the same headline verdict, the same correctness core, the same pillar scorecard, and near-identical readiness bands — disagreeing only on emphasis and a handful of `file:line` anchors, every one of which was code-corrected. **No pass produced an opposing verdict.** This is the closest *live* instance of the N≥3 decorrelated-producer discipline TRACT itself demands and the substrate cannot yet enforce — so it is reported as **estimated-decorrelated / CLAIMED, not ATTESTED** (the producers are distinct by claim, not by cryptographic model-family attestation, #1719). With that caveat, agreement of decorrelated minds on every structural conclusion is the strongest available evidence the verdict is *true*, not merely well-argued.

---

## The scorecard — correctness by TRACT pillar

| # | TRACT pillar | Status | One-line + anchor |
|---|--------------|--------|-------------------|
| 1 | One Claim object, kinds-not-classes | 🟡 **SPLIT** ✅L3 / 🟡L1 | one `Memory` struct, `memory_kind` over **13** kinds — L3-correct (`src/models/memory.rs:51`); L1-incorrect: UUID not BLAKE3-CID, 27-field hash preimage (`:756`), owner outside grammar |
| 2 | Six-verb algebra | 🟡 partial | ASSERT/RELATE ✅; RECALL ⚠️ mutating; ATTEST self-attest; SUPERSEDE opt-in; FORGET archive-not-tombstone |
| 3 | Reads-never-write + CONSUME ledger | 🟡 partial | `recall_observations` ledger wired (sqlite) but recall mutates rows; ranking on live `access_count` (`src/storage/mod.rs:3686`) |
| 4 | Identity (NHI Phase-0) | ✅ CORRECT | Ed25519 binding; dCBOR `SignableWrite` (`src/identity/sign.rs:319`); #1720 durable stamps + reown |
| 5 | Backend-blind core (SAL) | ✅ CORRECT | `MemoryStore` trait (`src/store/mod.rs:615`), sqlite+postgres adapters |
| 6 | Embeddings = disposable cache | ✅ CORRECT | HNSW async double-buffer rebuild (`src/hnsw.rs:238`); index loss ≠ memory loss |
| 7 | Fail-closed threat posture | ✅ CORRECT | secure-by-default matrix; quarantine inbound; no weaponizable badge |
| 8 | V-4 tamper-evident audit chain | ✅ CORRECT (single-writer) | `prev_hash`+`sequence` + `verify_chain` (`src/signed_events.rs:518`); append-only pin test (`:1276`); PE-8 |
| 9 | Governance (read-only signed RuleEngine) | ✅ CORRECT | `RuleEngine` struct (`src/governance/agent_action.rs:707`) / `evaluate` read-only `&self` (`:782`); operator-signed rules; Escalate fail-closed |
| 10 | Decorrelation: advisory + enforce-INERT | ✅ CORRECT (near-verbatim) | probe fn (`src/curator/decorrelation_probe.rs:254`); enforce-INERT (`src/config.rs:4984`); CLAIMED caveat (`decorrelation_probe.rs:72`) |
| 11 | Federation quarantine + fail-closed enrollment | ✅ CORRECT | inbound lands `claimed`; forged rejected vs enrolled key; #1789 secure default |
| 12 | At-rest encryption + per-row visibility | ✅ CORRECT (server-side) | X25519+ChaCha20 envelope (v68); `is_visible_to_caller` (`src/visibility.rs:46-78`) |
| 13 | Capability cliff: attest/count/freeze, never judge | ✅ CORRECT (strong) | recorder-not-judge; proof-by-absence; depth-bounded fail-closed reflect (`src/storage/reflect.rs:413`); optimizer external |
| 14 | Endpoint tiering + degradation | 🟡 partial | feature-tiers-by-RAM, not ∅/A/B/C manifests; keyword fallback; mobile lanes |

**Tally: 10 of 14 pillars CORRECT, 4 partial** (Pillar 1 split-counted partial, plus 2, 3, 14). Deepest correctness is the trust spine (4–13); deepest divergence is the data-model fundamentals (1–3).

---

## Evidence — what is correct, with file:line

### A. Capability cliff — *strong (TRACT's deepest idea)*
- **No "verified-safe" badge anywhere** — `rg "verified.safe|is_safe|safety_score"` over `src/` = zero production hits (only test-fn names). Every `"verified"` is an Ed25519 check, never a safety verdict.
- **Records scores, never maximizes** — `rg "maximize|reward|fitness|gradient|argmax"` = zero production hits (lone hit a `const`-folding code comment). **No in-core optimizer; the RQGM optimizer is kept external.** This proof-by-absence proves a negative the checklist cannot.
- **Reflection bounded + fail-closed PRE-transaction** — depth cap → `ReflectError::DepthExceeded` + signed audit *before* any insert (`src/storage/reflect.rs:413`).
- **`enforce` INERT on CLAIMED metadata** (`src/config.rs:4984`, `decorrelation_probe.rs:72`) — *"a refusal on CLAIMED distinctness would be security theater,"* 5-agent vote `4d3ea1c5`.
- **Signer ≠ thinker** — `AttestLevel` attests key-custody, never content truth (`src/identity/verify.rs:159`).

### B. Operational NHI Phase-0 — *correct, ~1:1*
- Ed25519 keypair (mode-0600); `SignableWrite` struct (`src/identity/sign.rs:319`) + `content_sha256` field (`:339`) + `canonical_cbor_write` deterministic-CBOR (`:358`); `scope=private` attested-before-commit; durable pid-free owner stamps + boot lockout probe + operator-signed re-ownership (#1720 B1/B2/B3; `src/store/mod.rs:775`).

### C. V-4 tamper-evident audit chain — *correct (single-writer)*
- `prev_hash` + monotonic `sequence`; `verify_chain` fail-closed on gaps (`src/signed_events.rs:518`); PE-8 `verify_audit_trail`; append-only enforced by a pinning test (`:1276`). *Caveat (TRACT §5): a self-anchored single-writer chain is the `bare` witness tier — see gap G5.*

### D. Governance — *read-only, signed, fail-closed*
- `RuleEngine::evaluate` read-only `&self`, first-blocking-wins (`src/governance/agent_action.rs:782`); only operator-Ed25519-signed rules enforce; `Decision::Escalate` fail-closed (PE-5); the signing payload commits to `enabled` to defeat the raw `UPDATE...SET enabled=1` gadget.

### E. Decorrelation — *advisory + enforce-INERT (near-verbatim TRACT §7)*
- Visibility-only probe (`src/curator/decorrelation_probe.rs:254`); enforce degrades to advisory (`src/config.rs:4984`); CLAIMED-not-ATTESTED caveat stamped on every advisory (`decorrelation_probe.rs:72`).

### F. Federation — *quarantine + fail-closed enrollment + attested coordination*
- Inbound lands `claimed`; forged third-party authorship re-attributed/rejected against the *enrolled* key (`src/handlers/federation_receive.rs`); fail-closed peer enrollment (#1789); persisted nonce-replay; attested checkpoints federated (receiver does not re-sign).

### G. Privacy — *at-rest encryption + per-row visibility (server-side)*
- Per-agent X25519 ECDH + ChaCha20-Poly1305 + HKDF, zeroized; `encrypted_envelope` on `memories`+`archived_memories` both backends (v68); `is_visible_to_caller` drops other-owner `scope=private`, default-private on absent scope (`src/visibility.rs:46-78`).

### H. Architecture — *backend-blind SAL + embeddings-as-cache + 3 surfaces*
- `MemoryStore` trait backend-agnostic (`src/store/mod.rs:615`); HNSW async double-buffer cache (index loss ≠ memory loss); three surfaces (MCP stdio + HTTP + CLI) = L3-BODY transports.

### I. CONSUME ledger — *partial-correct*
- `record_recall` (`src/observations/mod.rs:65`) + `mark_consumed` (`:108`), modeling "surfaced ≠ used"; wired on sqlite; #1705 identity-binding partial. *(Recall still mutates — gap G1.)*

### J. Durability + forensics — *correct*
- Lossless archive→restore (`archived_memories` v49 + `archived_memory_links` v70); migration round-trip proven on real data (`scripts/dogfood-rebuild.sh`); offline-verifiable forensic bundle (`src/forensic/bundle.rs:1114`).

### K. Claims-discipline — *best-in-class procurement honesty*
- ROADMAP §25.6 binding Allowed-vs-Banned vocabulary (`"implements RQGM"` perma-banned); falsifiable readiness %; the 5-agent adversarial-vote crossroads discipline (`4d3ea1c5`); 100% OSS Apache-2.0 (allowed TRACT license tier).

---

## Recall asymmetry note (concurrency, not purity)

The MCP-vs-HTTP recall difference is real but is a **concurrency/lock-topology** fact, not a purity one. HTTP splits recall into a read-pool phase (`PRAGMA query_only`) + a brief writer phase that runs the authoritative `touch_many` (the #1580 split, needed because Axum runs handlers in parallel); MCP's single-threaded stdio loop touches inline (`src/mcp/tools/recall.rs:1180`). **Both surfaces mutate every recall via `touch_many` (`src/storage/mod.rs:1520`); neither is pure recall.**

---

## Surface-area inventory (v0.8.0 GA) — *operator ledger, SSOT-pinned*

| Surface | Count | SSOT |
|---------|-------|------|
| MCP tools (full / core) | 100 / 7 | `Profile::full().expected_tool_count()` |
| HTTP routes | 91 reg / 77 unique | `src/lib.rs` + `handlers/routes.rs` |
| CLI subcommands (default / sal) | 83 / 85 | `EXPECTED_CLI_SUBCOMMANDS_*` + `tests/cli_subcommand_count_invariant.rs` |
| Schema | v70 | `CURRENT_SCHEMA_VERSION` |
| Hook events | 27 | `src/hooks/events.rs` |

## Pillar 1–4 closure ledger (ROADMAP §11.4) — *codegraph-verified*

Actions+DAG+leases (v59) ✅ · Signed signals (v60) ✅ · Attested checkpoints (v61) ✅ · Routines (v62) ✅ · W-of-N quorum fanout ✅ · CRDT merge primitives (`src/models/crdt_merge.rs`, LWW) ✅ · Push DLQ + adaptive replay ✅ · Compaction + rollback (sqlite+pg) ✅ · Admission control / PgBouncer / AGE deferred projection ✅.

## Six-verb mapping (TRACT §2)

ASSERT `memory_store` ✅ · RELATE `memory_link` (9 signed relations) ✅ · RECALL hybrid FTS+HNSW ⚠️ mutating (G1) · ATTEST write-sig + `signed_events` 🟡 self-attest (G5) · SUPERSEDE `update_with_archive_on_supersede` 🟡 opt-in · FORGET `memory_forget`+archive 🟡 no tombstone leaf (G6).

---

## CodeGraph structural-evidence appendix (reproducible)

```
codegraph query "verify_chain"             → src/signed_events.rs:518 (read-only, fail-closed)
codegraph query "RuleEngine"               → struct agent_action.rs:707 ; evaluate :782 (&self)
codegraph query "run_decorrelation_probe"  → src/curator/decorrelation_probe.rs:254 (advisory)
codegraph callers "SignableWrite"          → 20 production callers (sign.rs:319; content_sha256 :339)
codegraph query "touch_many"               → src/storage/mod.rs:1520 (recall mutation — gap G1)
rg "blake3|fork_set|witness_level"         → 0 production hits (data-model gaps confirmed absent)
```

---

## Honest framing

v0.8.0 **is the strongest existing realization of TRACT's hardest, most safety-critical half** — the capability cliff, the attestation chain, read-only signed governance, the honest decorrelation posture, fail-closed federation, and the complete operational endpoint-identity layer. Where it diverges — content-addressing, append-only, pure recall, lineage-DAG, three-key separation, causal-CRDT, client-side E2E — those are data-model and trust-topology fundamentals, catalogued in the companion gaps doc with file:line evidence and a phased build sequence.

---

*Canonical reduction authored by Claude Opus 4.8 (1M context) from four assessment passes (Grok + Opus first-party → two reconciliations → a 21-agent adjudication council), all CodeGraph-anchored against ai-memory `release/v0.8.0`. Every claim carries a `file:line` touchpoint verified against the working tree. Companion: [`TRACT-v0.8.0-DEVELOPMENT-GAPS-CANONICAL-opus.md`](TRACT-v0.8.0-DEVELOPMENT-GAPS-CANONICAL-opus.md). Tracked in ROADMAP.md §26.*
