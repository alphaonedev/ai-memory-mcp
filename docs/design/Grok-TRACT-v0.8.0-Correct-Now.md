# Grok 3×7 Assessment — What ai-memory v0.8.0 Has Correct Now

**Assessment date:** 2026-06-28  
**Method:** 21-lens adversarial audit (3 waves × 7 lenses) of `docs/design/TRACT-the-definitive-endpoint-ai-memory.md` against `release/v0.8.0` @ `14a34566`, cross-checked with [main `ROADMAP.md`](https://raw.githubusercontent.com/alphaonedev/ai-memory-mcp/refs/heads/main/ROADMAP.md) and **CodeGraph** structural probes (846 files, 27,062 nodes, 92,578 edges).  
**Analyst:** Grok (xAI) — synthesis round 4 of the TRACT design lineage.

---

## Executive verdict

ai-memory v0.8.0 is a **credible L3 Reference Profile** (`TRACT-2026`-shaped: SQLite-WAL + HNSW/FTS + MCP/HTTP/CLI) that **correctly implements** large portions of the ROADMAP moonshot's seven properties (§2) and TRACT's **operational body** — attestation, federation coordination, bounded reflection, governance refusal, and honest epistemic labeling.

It is **not** a L0/L1 TRACT constitution implementation. What is "correct now" means: **shipped, load-bearing, and honestly aligned** with TRACT's *spirit* and ROADMAP's *commitments* — not full TRACT conformance.

| Axis | Correct-now score (Grok estimate) |
|------|-----------------------------------|
| ROADMAP §2 seven properties | **~75–85%** structural primitives present |
| TRACT L3-BODY Reference Profile | **~80%** — real endpoint substrate |
| TRACT L1 frozen core (Claim + six verbs) | **~25–35%** — cousins exist, algebra diverges |
| TRACT §7 epistemics (N≥3 enforce) | **~30%** — advisory floor only |
| TRACT §3 recall purity | **~15%** — measurement seam only |

---

## Assessment method (3×7 + CodeGraph)

### Wave 1 — Constitutional kernel (7 lenses)

| Lens | TRACT section | Primary code anchors |
|------|---------------|---------------------|
| L1 | §0–§2 Claim + six verbs | `src/models/memory.rs`, `src/identity/sign.rs`, `src/storage/mod.rs` |
| L2 | §5 Attestation/audit | `src/signed_events.rs`, `src/governance/deferred_audit.rs` |
| L3 | §6 Governance + §14 covenant | `src/governance/mod.rs`, `src/hooks/decision.rs` |
| L4 | §8 Federation | `src/federation/receive_auth.rs`, `src/actions/`, `src/signals/` |
| L5 | §7 Epistemics + §11 compounding | `src/curator/decorrelation_probe.rs`, `src/storage/reflect.rs` |
| L6 | §3 Recall + CONSUME | `src/storage/mod.rs:touch_many`, `src/observations/mod.rs` |
| L7 | §9–§10 Privacy/tiering | `src/encryption/mod.rs`, `src/visibility.rs`, `src/profile.rs` |

### Wave 2 — ROADMAP property mapping (7 lenses)

Mapped each ROADMAP §2 property to v0.8.0 shipped surfaces + CodeGraph blast-radius on hot paths (`evaluate`, `append_signed_event`, `authorize_remote_transition`, `run_decorrelation_probe`).

### Wave 3 — Surface inventory + gap honesty (7 lenses)

Cross-checked MCP tool count, HTTP routes, CLI subcommands, schema v70 ladder, and ROADMAP §11.4 Pillar 1–4 closure claims against `src/profile.rs`, `src/lib.rs`, `src/store/postgres.rs::CURRENT_SCHEMA_VERSION = 70`.

---

## 1. Endpoint-resident substrate (ROADMAP §2.1 · TRACT §10 L3-BODY)

**Correct now:**

- **Rust + SQLite default**, LLVM-portable; Apache 2.0 license (ROADMAP §7 permanence claim holds).
- **Mobile cross-compile CI gate** — `.github/workflows/ci.yml::mobile-cross-compile` for `aarch64-apple-ios` and `aarch64-linux-android` (ROADMAP §2.1 code anchor verified).
- **Five distribution channels** live per ROADMAP §9 (crates.io, Homebrew, COPR, GHCR, APT).
- **Honest floor sizing** — ~31 MB binary / ~18–25 MB idle RSS; Tier ∅ (MCU) correctly deferred to gateway-held L1 (ROADMAP D-OPUS-5, TRACT §10).
- **MCP profile tiering** (`src/profile.rs`) — `core` (7 tools) vs `full` (100 entries) reduces token/energy surface on constrained endpoints; coordination tools gated in `Family::Power`.

**CodeGraph:** `codegraph status` — 846 indexed files; route registrations discoverable via `kind=route` queries.

---

## 2. Coherent across sessions (ROADMAP §2.2 · TRACT §4 identity partial)

**Correct now:**

- **27-field `Memory` model** with `memory_kind`, `reflection_depth`, `lifecycle_state`, `persona_version`, Form-4 provenance columns (`citations`, `source_uri`, `source_span`).
- **Agent identity ladder** — `metadata.agent_id` with durable `host:` / `ai:` stamps (#1720 B1); `AI_MEMORY_AGENT_ID` opt-in enforcement.
- **Owner visibility** — `src/visibility.rs` + `scope=private` default; `target_agent_id_idx` generated column (#1720 A).
- **Persona-as-artifact** — `src/persona/mod.rs` with signed persona generation and version discipline.
- **L4 turn capture** — `memory_capture_turn` + `transcript_line_dedup` idempotency (#1389) — cross-session rehydration without duplicate writes.
- **Recover previous session** — MCP + CLI `recover-previous-session` (#1389 L2).

**Partial TRACT alignment:** identity is **claimed string + keypair**, not TRACT's signed lineage-DAG; but operational NHI Phase-0 from TRACT §4 is **deployable today**.

---

## 3. Stoppable without silent corruption (ROADMAP §2.3 · TRACT §6 partial)

**Correct now:**

- **Typed refusal vocabulary** — `GovernanceRefusal` struct (`src/governance/refusal.rs:68-78`); `GovernanceDecision::Deny` (`src/models/namespace.rs:250-258`).
- **K9 four-shape combiner** — `Decision { Allow, Deny, Modify, Ask }` with deny-first semantics (`src/governance/mod.rs:256-270`, `:477-625`).
- **Hook veto distinct from depth exceeded** — `ReflectError::HookVeto` vs `ReflectError::DepthExceeded` (`src/storage/reflect.rs:43-79`).
- **Fail-closed defaults** — `permissions.mode = enforce`, SSRF guard, governance fail-closed (#1054 carve-out documented).
- **Deferred audit drainer** — governance refusals chain-log to `signed_events` (#1732 PE-3/PE-4; `src/governance/deferred_audit.rs`).
- **Attested checkpoints** — separation-of-duties gates (#1709 Pillar 1; `src/checkpoints/mod.rs`).
- **PE-1 hooks presence enforcement** — `AI_MEMORY_HOOKS_ENFORCE_MODE` (`src/hooks/enforce.rs`).
- **HTTP admission control** — opt-in overload shed (#1733 Pillar 4.A).

**Honest ceiling (ROADMAP §2.3 precision):** stoppability governs **substrate writes**, not hosted cognition's world actions — correctly scoped.

---

## 4. Improvable across model generations (ROADMAP §2.4 · TRACT §11 partial)

**Correct now:**

- **Episodic → semantic → procedural pipeline** — Observations → Atoms → Reflections → Skills (7 `memory_skill_*` MCP tools).
- **Bounded reflection** — `REFLECTION_DEPTH_EXCEEDED` fail-closed (`src/storage/reflect.rs:400-458`); default cap D=3 (`DEFAULT_REFLECTION_MAX_DEPTH_CAP`).
- **Reflection provenance edges** — `reflects_on` links in atomic tx (`src/storage/reflect.rs:555-584`).
- **Atomisation** — WT-1 engine with partial-failure honesty (`src/atomisation/mod.rs`).
- **Compaction pipeline** — Pillar 2.5 `ConsolidationPass` with operator-tunable cosine threshold (#1750); rollback on sqlite + postgres (#1745/#1748).
- **Typed cognition** — Pillar 2 `lifecycle_state`, extended link relations (9 closed relations).
- **Coordination routines** — parameterized templates (#1709 Pillar 1).

**Correct compounding discipline:** substrate records reflections as **claims**; depth cap blocks unbounded RSI via reflection chain.

---

## 5. Attested with cryptographic non-repudiation (ROADMAP §2.5 · TRACT §5 partial)

**Correct now:**

- **V-4 signed_events chain** — `prev_hash` + monotonic `sequence` (`src/signed_events.rs:51-69`); `verify_chain` fail-closed on gaps.
- **dCBOR canonical signing** — `SignableWrite`, `SignableLink`, `SignableSignal` (RFC 8949 §4.2.1; `src/identity/sign.rs:10-15`).
- **Agent write attestation** — `claimed` → `agent_attested` via `SignableWrite` envelope (`src/identity/attest.rs`).
- **Link-level Ed25519 signatures** — `memory_links.signature` + `attest_level` (`src/models/link.rs:20-65`).
- **Federation envelope** — `X-Memory-Sig` + nonce replay protection (#791/#922); peer enrollment secure default (#1789).
- **Federation write attestation (#1464)** — `apply_inbound_write_attestation` on relayed memories (`src/handlers/federation_receive.rs:288-322`).
- **Authority-lane fail-closed** — `authorize_remote_transition` for action transitions (#1718; `src/federation/receive_auth.rs:66-96`).
- **Recall observations ledger (#1705)** — `record_recall` + identity-bound `mark_consumed` (`src/observations/mod.rs`).
- **Forensic bundle export/verify** — `src/forensic/`.
- **Coverage honesty documented** — `docs/security/audit-trail-coverage.md` names out-of-band gaps (TRACT §5 coverage-gap honesty, partial).

**CodeGraph probes:** `signed_events` → `append` chain; `SignableWrite` → 7+ production callers.

---

## 6. Bias-displaced / decorrelation (ROADMAP §2.6 · TRACT §7 partial)

**Correct now:**

- **LLM-agnostic reflection boundary** — 15+ vendor aliases (#1067); producer/reflector configurable per `[llm]` / `[llm.auto_tag]`.
- **Decorrelation visibility probe (#1764)** — `run_decorrelation_probe` (`src/curator/decorrelation_probe.rs:254`); CodeGraph hit confirmed.
- **CLAIMED-not-ATTESTED caveat** — mandated string on every advisory (`decorrelation_probe.rs:72-74`).
- **`enforce` mode INERT at v0.8.0** — degrades to advisory (`config.rs:4969-4975`) — **correct** per TRACT §7 ("enforce inert on claimed metadata").
- **Reflection pass N≥3 cluster floor** — synthesis quorum on Observations (`reflection_pass.rs:158-161`) — distinct from decorrelation N≥3 but structurally analogous.

**ROADMAP §5 honesty:** structural enforcement committed v0.8/v0.9; v0.8.0 ships the **honest advisory floor**, not a forgeable green checkmark.

---

## 7. LLM-agnostic at every boundary (ROADMAP §2.7)

**Correct now:**

- **Provider-agnostic LLM** (#1067) — chat + embed backends unified under `AI_MEMORY_LLM_*` / `AI_MEMORY_EMBED_*`.
- **Embedding backend migration** — `ai-memory reembed` (#1598).
- **Query expansion** — `memory_expand_query` three-surface parity (#1443).
- **No single-lab coupling** — substrate trademark + Apache 2.0 structural neutrality (ROADMAP §4).

---

## 8. Federation + distributed coordination (ROADMAP §11.4 Pillar 1 · TRACT §8 partial)

**Correct now (Grok CodeGraph-verified):**

| Primitive | Status | Anchor |
|-----------|--------|--------|
| Actions + DAG + leases | ✅ Shipped | `src/actions/mod.rs`, schema v59 |
| Signed signals (Ed25519) | ✅ Shipped | `src/signals/mod.rs:72-96`, schema v60 |
| Attested checkpoints | ✅ Shipped | `src/checkpoints/mod.rs`, schema v61 |
| Routines | ✅ Shipped | `src/routines/`, schema v62 |
| W-of-N quorum fanout | ✅ Shipped | `src/federation/quorum.rs`, `src/replication.rs` |
| Local-first commit | ✅ Shipped | `src/handlers/create.rs:645-647` (503 on quorum miss, no rollback) |
| Peer enrollment #1789 | ✅ Secure default ON | `src/handlers/federation_signing_check.rs:1205-1218` |
| Inbound quarantine | ✅ Shipped | `resolve_inbound_attribution` (#1464) |
| CRDT merge primitives | ✅ Shipped | `src/models/crdt_merge.rs` |
| Federation credential chain | ✅ Shipped | #1512 CA-rooted zero-touch identity |
| Push DLQ + adaptive replay | ✅ Shipped | `src/federation/push_dlq.rs` (#1578/#1579) |

**MCP coordination surface:** `memory_action_*`, `memory_signal_*`, `memory_checkpoint_*`, `memory_lease_*`, `memory_routine_*` — all in `Family::Power` / `full` profile.

---

## 9. Verb algebra — spiritual cousins (TRACT §2)

ai-memory does **not** implement TRACT's frozen six-verb kernel, but the **pragmatic mapping is real and shipped**:

| TRACT verb | v0.8.0 surface | Correct-now? |
|------------|----------------|--------------|
| **ASSERT** | `memory_store` / `storage::insert` | ✅ |
| **RELATE** | `memory_link` / 9 closed relations + signed edges | ✅ |
| **RECALL** | `memory_recall` hybrid FTS+HNSW | ⚠️ Shipped but **mutating** (see gaps doc) |
| **ATTEST** | Write signatures + `signed_events` + link `attest_level` | ✅ Partial (self-attest, not countersign) |
| **SUPERSEDE** | `update_with_archive_on_supersede` for `llm`/`hook` edits | ✅ Partial |
| **FORGET** | `memory_forget` + archive path | ✅ Partial (archive, not signed tombstone leaf) |

**dCBOR signing** on bounded envelopes is **correct now** — TRACT's canonical serialization discipline is partially realized (`src/identity/sign.rs`).

---

## 10. Privacy + encryption (TRACT §9 partial)

**Correct now:**

- **`encrypted_envelope` column** — ChaCha20-Poly1305 + X25519 per-agent keys (`src/encryption/mod.rs`); sqlite + postgres parity (v68).
- **`scope=private` default** — `src/visibility.rs` single canonical predicate (#951).
- **Owner mutation gate** — `caller_owns_for_mutation` (#1786).
- **Recall identity binding** — #1705 cross-agent `recall_id` replay guard.

**Honest posture:** opt-in at-rest encryption on **content column only** — not TRACT's mandatory client-side sovereign sealing.

---

## 11. Surface area inventory (v0.8.0 GA)

Per ROADMAP §9.7 and mechanical invariants:

| Surface | Count | SSOT |
|---------|-------|------|
| MCP tools (`--profile full`) | 100 | `Profile::full().expected_tool_count()` |
| MCP tools (`--profile core`) | 7 | `Profile::core()` |
| HTTP production routes | 91 registrations / 77 unique paths | `src/lib.rs` + `handlers/routes.rs` |
| CLI subcommands (default build) | 83 | `EXPECTED_CLI_SUBCOMMANDS_DEFAULT` |
| CLI subcommands (`--features sal`) | 85 | `EXPECTED_CLI_SUBCOMMANDS_SAL` |
| Schema version | **v70** | `CURRENT_SCHEMA_VERSION` (sqlite + postgres) |
| Hook lifecycle events | 27 | `src/hooks/events.rs` |

---

## 12. ROADMAP §11.4 Pillar closure (v0.8.0 GA 2026-06-25)

**Correct now — landed on `release/v0.8.0`:**

- **Pillar 1** — Actions, leases, signals, checkpoints, routines, federation quorum on transitions.
- **Pillar 2** — Typed cognition + `lifecycle_state`.
- **Pillar 2.5** — Compaction pipeline + curator daemon + rollback.
- **Pillar 3** — CRDT primitives + attested-identity tiebreak (partial LWW — see gaps doc).
- **Pillar 4** — Admission control (#1733), PgBouncer templates (#1736), AGE deferred projection (#1735), envelope harness (#1737).

---

## 13. Epistemic honesty (TRACT §12–§16 alignment)

**Correct now — the substrate refuses grandeur:**

- Decorrelation `enforce` **inert** rather than security theater (`decorrelation_probe.rs:14-33`).
- ROADMAP §2 scope honesty on DeepMind *From AGI to ASI* ([#1698](https://github.com/alphaonedev/ai-memory-mcp/issues/1698)) — leads with attestation, not universal ASI governance.
- Audit coverage gaps **documented**, not hidden (`docs/security/audit-trail-coverage.md`).
- TRACT name discipline adopted in design docs — rejects "eternal/∞" unfalsifiable claims.

---

## 14. CodeGraph structural evidence summary

Probes run during this Grok assessment:

```
codegraph query "run_decorrelation_probe"     → src/curator/decorrelation_probe.rs:254
codegraph query "record_recall"               → src/observations/mod.rs:65 + SAL twins
codegraph query "REFLECTION_DEPTH_EXCEEDED"   → src/storage/reflect.rs:724 + store paths
codegraph query "encrypted_envelope"          → src/encryption/mod.rs:543
codegraph query "authorize_remote_transition" → src/federation/receive_auth.rs:66
codegraph explore "signed_events append"      → V-4 chain + deferred_audit sink
codegraph explore "governance rule evaluate"  → 14 callers, RuleEngine blast radius
codegraph explore "federation attestation"    → #1464 receive path wired
```

---

## Grok verdict — correct now

ai-memory v0.8.0 **correctly ships** a production-grade **endpoint memory and coordination substrate** that:

1. **Matches ROADMAP moonshot properties** at the structural layer (~75–85%).
2. **Implements TRACT's L3 Reference Profile body** — SQLite/HNSW/FTS, MCP/HTTP/CLI, federation, attestation, bounded reflection.
3. **Honors TRACT's epistemic discipline** — advisory decorrelation, inert enforce, documented audit gaps.
4. **Does not pretend** to be L0/L1 TRACT-conformant — UUID identity, mutating recall, and self-attestation are known divergences (see companion gaps document).

The correct posture for operators: **deploy v0.8.0 as TRACT-2026 L3-BODY**, not as the frozen CC0 constitution. The substrate earns its existence on consent-bound identity, cross-agent attestation, and offline continuity — exactly TRACT §16's irreducible 20%.

---

*Grok 3×7 assessment · Wave synthesis · CodeGraph L1 evidence · Companion: `Grok-TRACT-v0.8.0-Development-Gaps.md`*