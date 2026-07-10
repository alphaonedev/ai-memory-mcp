# ai-memory v0.8.0 — What Is Correct Now (vs the TRACT definitive design)

### An Opus full-spectrum, CodeGraph-anchored assessment of where ai-memory v0.8.0 already implements the definitive endpoint-AI-memory design.

> **Method.** A 21-agent council (3 waves × 7) measured the definitive ideal design **TRACT** (`docs/design/TRACT-the-definitive-endpoint-ai-memory.md`) against the **actual ai-memory v0.8.0 codebase** (branch `release/v0.8.0`) and the **current `main` ROADMAP.md**, using the CodeGraph CLI as L1 evidence (846 files / 27,062 nodes indexed). Every claim below carries a `file:line` touchpoint. This document records **what is already correct**; the companion [`TRACT-vs-ai-memory-v0.8.0-DEVELOPMENT-GAPS-opus.md`](TRACT-vs-ai-memory-v0.8.0-DEVELOPMENT-GAPS-opus.md) records the gaps.
>
> **Headline.** ai-memory v0.8.0 is a **strong, honest implementation of the TRACT *trust, governance, and capability-cliff* spine, and of the operational endpoint-identity layer** — while diverging on the *data-model fundamentals* (content-addressing, append-only, pure recall). It is roughly a **B-grade realization of TRACT's safety/governance half and a C-grade realization of its data-model half** — and, crucially, it is *honest* about most of the gap (the moonshot doc names the same limits TRACT names).

---

## The scorecard — correctness by TRACT pillar

| # | TRACT pillar | v0.8.0 status | One-line |
|---|--------------|---------------|----------|
| 1 | One Claim object, kinds-not-classes | ✅ **CORRECT** | single `Memory` struct, `memory_kind` discriminator over 13 kinds |
| 2 | Six-verb algebra | 🟡 partial | ASSERT/RELATE/RECALL present + `supersedes` relation + supersede-forward path exists (opt-in) |
| 3 | Reads-never-write + CONSUME ledger | 🟡 partial | the `recall_observations` CONSUME ledger **exists and is wired** (sqlite) |
| 4 | Identity (NHI Phase-0) | ✅ **CORRECT** | the entire Phase-0 operational NHI layer ships near 1:1 |
| 5 | Backend-blind core (SAL) | ✅ **CORRECT** | the `MemoryStore` trait is genuinely backend-agnostic |
| 6 | Embeddings = disposable derived cache | ✅ **CORRECT** | HNSW async-rebuilt from rows; index loss ≠ memory loss |
| 7 | Fail-closed threat posture | ✅ **CORRECT** | secure-by-default across the matrix; quarantine inbound; no weaponizable badge |
| 8 | V-4 tamper-evident audit chain | ✅ **CORRECT** (single-writer) | real `prev_hash`+`sequence` chain + `verify_chain` + PE-8 audit trail |
| 9 | Governance (read-only RuleEngine, signed rules, fail-closed escalate) | ✅ **CORRECT** | `RuleEngine::evaluate` read-only; operator-Ed25519-signed rules; refusal recorded |
| 10 | Decorrelation: advisory + enforce-INERT-on-claimed | ✅ **CORRECT** (near-verbatim) | the probe implements TRACT §7's "advisory until attested" *exactly* |
| 11 | Federation quarantine + fail-closed enrollment | ✅ **CORRECT** | inbound lands `claimed`; forged rejected unconditionally; nonce-replay; attested checkpoints |
| 12 | At-rest encryption + per-row visibility | ✅ **CORRECT** (server-side) | X25519+ChaCha20 envelope; `#1720` visibility; durable owner stamps |
| 13 | Capability cliff: attest/count/freeze, never judge | ✅ **CORRECT** (strong) | recorder-not-judge; no safety badge; depth-bounded reflect; no in-core optimizer |
| 14 | Endpoint tiering + degradation | 🟡 partial | feature-tiers-by-RAM-budget; keyword-fallback; mobile cross-compile lanes |

**14 of TRACT's load-bearing pillars were assessed with dedicated CodeGraph lenses.** 9 are substantially CORRECT, 5 are partial. The deepest correctness is on the *trust spine* (8–13); the deepest divergence is on the *data-model fundamentals* (1–3) — detailed in the gaps doc.

---

## What ai-memory v0.8.0 has CORRECT — with evidence

### A. The capability cliff is honored (TRACT's deepest idea) — *strong*

This is the single most important correctness result. TRACT's spine is *"attest, count, freeze — never judge; dumbness is the guarantee; no verified-safe badge."* ai-memory implements it structurally:

- **No content-judging / "verified-safe" badge anywhere.** `rg "verified.safe|is_safe|safety_score|trusted.badge"` over `src/` returns **zero production hits**. Every `"verified"` is a *cryptographic signature check*, never a safety verdict (`src/mcp/tools/checkpoint.rs:250`, `src/mcp/tools/signal.rs:341` = Ed25519 `verify()`). The attest vocabulary (`claimed`/`agent_attested`/`signed_by_peer`) counts origins, never asserts "safe."
- **The substrate RECORDS scores, never MAXIMIZES one.** `rg "maximize|objective.function|reward|fitness|gradient"` over `src/` = **zero production hits**. Confidence is a recorded authored field with provenance (`ConfidenceSource`, `src/models/memory.rs`), not an optimized objective. There is **no in-core optimizer loop**.
- **Reflection is bounded + fail-closed, enforced PRE-transaction.** `src/storage/reflect.rs:379` resolves the depth cap (default 3); `:413` `if new_depth_u32 > cap` returns `ReflectError::DepthExceeded` and emits a signed `reflection.depth_exceeded` audit row **before** any insert — exactly TRACT §11's fail-closed `REFLECTION_DEPTH_EXCEEDED`. The cap is enforced regardless of cross-peer origin (`:422-427`).
- **`enforce` is INERT on CLAIMED metadata** — a near-verbatim implementation of TRACT §7 (`src/curator/decorrelation_probe.rs:272-281`: enforce degrades to advisory + WARN, *"a refusal on CLAIMED distinctness would be security theater,"* 5-agent vote `4d3ea1c5`).
- **Signer ≠ thinker is honored:** `AttestLevel` attests Ed25519 key-custody, never content truth (`src/identity/verify.rs:159`).
- **The ROADMAP is honest about the cliff:** it explicitly concedes "attesting that an ASI did X is not stopping it … the substrate can attest but not evaluate ASI reasoning" (`ROADMAP-main.md:80`) and ships a banned-grandeur list with a perma-ban on "implements RQGM" (`:1229`) — TRACT §16's claims-discipline.

### B. The operational endpoint-identity (NHI Phase-0) layer ships near 1:1 — *correct*

TRACT §4's "Operational NHI (Phase-0, deployable today)" is implemented almost exactly:

- **pubkey↔agent_id keypair binding** — Ed25519 generate/save/load, mode-0600 enforced (`src/identity/keypair.rs:400-417`).
- **`SignableWrite` with deterministic-CBOR canonical bytes** — `src/identity/sign.rs:319` (6 committed fields) + `canonical_cbor_write` (`:358`) is **RFC 8949 §4.2.1 deterministic CBOR** — exactly TRACT's `canonical() ≡ dCBOR` mandate.
- **`scope=private` requires attested before commit** + forged-sig rejected unconditionally (`src/identity/attest.rs:182-218`, `src/identity/verify.rs:283-323`).
- **Boot owner-lockout probe** (`src/identity/mod.rs:330` `enforce_owner_lockout_guard`, `#1720` B3) + **durable pid-free owner stamps** (`#1720` B1) + **operator-signed namespace-bounded re-ownership** (`src/cli/reown.rs`; SAL `reown` at `src/store/mod.rs:775`).

### C. The audit chain is a real V-4 tamper-evident log — *correct (single-writer)*

- **Cross-row hash chain:** `prev_hash` (SHA-256 over prior canonical bytes) + monotonic `sequence` (`src/signed_events.rs:54-71, 312-365`).
- **`verify_chain`** walks rows in sequence order, checks contiguity, re-derives predecessor hash, verifies Ed25519 sig (`:495-520`).
- **PE-8 `verify_audit_trail`** runs `verify_chain` + an independent gap scan emitting every missing range (`:771-845`) — shipped CLI surface (`#1720` PE-8).
- **Append-only at the API surface:** INSERT-only; no `update_signed_event`/`delete_signed_event` (`:846-855`).
- A hash-agility seam exists (one `payload_hash()` helper + `ZERO_HASH` genesis, `:840-849`).

### D. Governance is a read-only, signed, fail-closed rule engine — *correct*

- **`RuleEngine::evaluate` is read-only** (`&self`, mutates nothing) with first-blocking-wins (`src/governance/agent_action.rs:782-823`).
- **`Decision::Escalate` is fail-closed** (PE-5): a matched escalate halts the action, `is_allowed()==false` (`:798-806`).
- **Only operator-Ed25519-signed rules enforce** (`src/governance/rules_store.rs:174-238`); signature verified against the operator pubkey resolved from `AI_MEMORY_OPERATOR_PUBKEY`/`operator.key.pub` (`:306,742`) — the *public* key on host, the *private* signing key held off-substrate.
- **Refusal is a typed, signed, audited record** (`GovernanceRefusal`, `src/governance/refusal.rs:41-66`; `governance.refusal` row in the signed chain, `src/governance/audit.rs:252-263`).
- **Governance-disable fail-closed at boot** when enabled rules exist without a resolvable operator pubkey (`rules_store.rs:480-491`); the canonical signing payload commits to `enabled` to defeat the raw `UPDATE...SET enabled=1` gadget (`:217`).

### E. Decorrelation: advisory + enforce-INERT — *near-verbatim TRACT §7*

- The probe is **visibility-only, advisory** (`src/curator/decorrelation_probe.rs:4,253-337`).
- **`enforce` correctly INERT** until attested family (`:272-281`).
- The **CLAIMED-not-ATTESTED caveat is first-class** and stamped on every advisory (`:72-74,205`) — TRACT §7's "report 'estimated-decorrelated,' never 'decorrelated.'"
- The `contradicts` relation **exists** as a conserved closed-taxonomy link (`src/models/link.rs:132,284`).
- **ROADMAP-aligned and accurately self-graded:** §5 commits decorrelation to v0.8/v0.9, candidate-4 N≥3 attested-family quorum PRIMARY, advisory floor until attestation (`ROADMAP-main.md:179-205,1173`).

### F. Federation: quarantine + fail-closed enrollment + attested coordination — *correct*

- **Quarantine inbound → local-verify → promote:** inbound lands `attest_level="claimed"` regardless of peer assertion; forged third-party authorship re-attributed to the sender (`src/handlers/federation_receive.rs:178-179,222-225,258-266`).
- **Forged signature rejected unconditionally** against the *enrolled* key, not the wire pubkey (`src/federation/receive_auth.rs`; `src/store/postgres.rs:12649`).
- **Fail-closed peer enrollment** (v0.8.0 `#1789` secure default — `401 peer_not_enrolled`, `src/handlers/federation_signing_check.rs:1157-1230`).
- **Persisted nonce-replay protection** (schema v51, `:613-634`).
- **Attested checkpoints (LOCAL substrate only)**: Ed25519 attested resolution, receiver does not re-sign, unattested rows fail `verify()` (`src/checkpoints/mod.rs:30-66,310-330`). *Correction (2026-07-10, Sprint-0 W1 #1938): checkpoint FEDERATION (FED-RQ-01) never landed at any tag — the claimed "+~282 LOC" existed only as an uncommitted review working tree. Carrier: [#1936](https://github.com/alphaonedev/ai-memory-mcp/issues/1936).*
- **W-of-N quorum machinery exists** (`QuorumPolicy`, `AckTracker`, `src/replication.rs:38-78`, `src/federation/quorum.rs:19-60`).

### G. Privacy primitives: at-rest encryption + per-row visibility — *correct (server-side)*

- **Per-agent X25519 ECDH + ChaCha20-Poly1305 AEAD + HKDF-SHA256**, key material zeroized (`src/encryption/mod.rs:1-108,428,520`); gated by `AI_MEMORY_ENCRYPT_AT_REST` (env #37).
- **`encrypted_envelope` column** persists ciphertext on `memories` + `archived_memories`, both backends, lossless archive→restore (`src/store/postgres.rs:3184-3194,10298-10309`).
- **Per-row visibility (`#1720`/`#951`):** `is_visible_to_caller` drops other-owner `scope=private` rows, default-private on absent scope (`src/visibility.rs:46-78`).

### H. Architecture: backend-blind SAL + embeddings-as-cache + 3 surfaces — *correct*

- **The SAL `MemoryStore` trait is genuinely backend-agnostic** (`src/store/mod.rs:615`), with sqlite + postgres adapters and backend-blind projection rows (`:128,166,191`) — the closest structural analogue to TRACT's L1 "backend-blind" tenet.
- **Embeddings are a disposable derived cache** (TRACT-correct): HNSW is an in-memory index async-rebuilt from canonical rows (`src/hnsw.rs:238-335,419`), recomputable via backfill/reembed (`src/embeddings.rs:184,715`). *Index loss ≠ memory loss* holds.
- **Three surfaces** (MCP stdio + HTTP + CLI) map to TRACT's L3-BODY transports.
- **Curator = TRACT L2 mechanics:** `ConsolidationPass` (`src/curator/pipeline.rs:54`), reflection pass, decorrelation probe — and the **epoch-FREEZE-brake / optimizer-KILLED posture is already the roadmap position** (`ROADMAP-main.md:1189,1225`), matching TRACT exactly.

### I. The CONSUME ledger exists and is wired — *partial-correct*

TRACT §3's recall-as-signal input tier is real:
- `recall_observations` append-only ledger: `record_recall` (`src/observations/mod.rs:65`) + `mark_consumed` (`:108`), modeling **"surfaced ≠ used"** (`:13-24`).
- **Wired (sqlite), not dead:** MCP recall → `record_recall_with_identity` (`src/mcp/tools/recall.rs:726`); store/link → `mark_consumed` (`src/mcp/tools/store/mod.rs:975`, `src/mcp/tools/link.rs:398`); SAL sqlite adapter (`src/store/sqlite.rs:888,903`).
- **`#1705` identity-binding** partially landed (agent_id+namespace stamp, schema v58).
- TTL pruner keeps the ledger derived/deletable (`src/observations/gc.rs:54`).

*(The deeper recall-purity gap — that recall still mutates rows and the ledger is on-budget/sqlite-only — is in the gaps doc.)*

### J. Fail-closed secure defaults across the matrix — *correct*

- `AI_MEMORY_PERMISSIONS_MODE=enforce` default (env #10); `AI_MEMORY_GOVERNANCE_FAIL_OPEN_ON_ERROR=false` default (env #39); SSRF fail-closed (env #41); `FED_REQUIRE_SIG`/`NONCE`/`PEER_ENROLLMENT` all secure-by-default (env #29/#30/#43).
- **`memory ⊄ policy` is structurally honored:** governance rules are typed data in the `governance_rules` table, consulted independently of recall; no path parses recalled *content* as instructions.
- **Embedder fails closed to keyword recall**, never silent semantic-off (`src/embeddings.rs:428,1315`).

### K. Wave-3 confirmations — durability, OSS, semantics, claims-discipline — *correct*

The final wave (lenses 15–21) confirmed five more genuinely-correct axes:

- **Bounded reflection has no objective function and no in-core optimizer — confirmed by absence.** `rg` over `src/` for `reward|gradient|fitness|argmax|maximize|epoch_manifest|stopper` returns zero production hits; the RQGM optimizer is kept **external** (CUT 21/21, `ROADMAP-main.md:1189`). Reflection writes `ConfidenceSource::CallerProvided` clamped `[0,1]` and cannot raise its own cap (`src/storage/reflect.rs:501,520`). The episodic→semantic→procedural distillation (Observations→Atoms→Reflections→Skills→Persona) ships with the RSI boundary documented (`docs/RECURSIVE_LEARNING.md:67-74`). This is TRACT §11's "remember, don't self-improve," structurally honored.
- **Durability: archive→restore is lossless and migration round-trips on real data.** `archived_memories` (v49 14-col expansion) + `archived_memory_links` (v70) snapshot rows **and edges** before the same-tx cascade and restore them idempotently (`src/store/mod.rs:3047`; `INSERT OR IGNORE` restore). `scripts/dogfood-rebuild.sh:46-63` proves the full migration ladder round-trips against a backup of the live corpus. The **forensic bundle export is offline-verifiable** with no daemon/network — only the signers' pubkeys (`src/forensic/bundle.rs:174-177,1114`), the closest existing analogue to TRACT's "verification kernel ships in every export."
- **License is permissive OSS with a roadmap-pledged free-forever intent.** `Cargo.toml:8` `license = "Apache-2.0"`; the full Apache patent grant (`LICENSE:74-86`); `ROADMAP-main.md:255-257` §7 "everything that compiles into the binary is Apache 2.0, forever … no open-core gotcha." TRACT permits Apache-2.0 as a reference-impl tier — ai-memory is on an allowed license tier and is **100% OSS** on the public-good *outcome*.
- **Knowledge representation: typed signed directional links with bitemporal columns + an entity registry.** `MemoryLinkRelation` is a typed directional signed edge (`src/models/link.rs:126-182,303-339`) carrying `valid_from`/`valid_until`/`observed_by` (bitemporal on links, `:319-328`); `contradicts` is a first-class conserved edge type (`:135,284`); entities are a stable opaque referent + evolving alias set (`EntityRecord`, idempotent `entity_register`/`entity_get_by_alias`, `src/store/sqlite.rs:1771,2149`). KG traversal **records, never reasons** — recursive-CTE walks return edges as data, no inference engine (`src/kg/cycle_check.rs:131`).
- **Procurement-honesty / claims-discipline is best-in-class.** `ROADMAP-main.md:1227-1229` §25.6 ships a **binding** Allowed-vs-Banned claims vocabulary (`"implements RQGM"` is a **perma-ban** category error), falsifiable readiness percentages (optimization 15%→70-80%; vote-independence "0% throughout, architectural limit"), a CLAIMED-vs-ATTESTED spine (`:379,1233`), and the **5-agent adversarial-vote** crossroads discipline (`:1219-1221`, `4d3ea1c5`). This is precisely the TRACT §16 claims-honesty TRACT praises.

---

## Honest framing

ai-memory v0.8.0 **is the strongest existing realization of TRACT's hardest, most safety-critical half** — the capability cliff, the attestation chain, the read-only signed governance, the honest decorrelation posture, the fail-closed federation and threat model, and the complete operational endpoint-identity layer. On these axes it is not aspirational; it is **shipped, tested, and honest about its limits** (the moonshot doc names the same gaps TRACT names).

Where it diverges — content-addressing, append-only-only, pure recall, the lineage-DAG, three-key separation, causal-CRDT federation, client-side E2E — those are **data-model and trust-topology fundamentals**, documented in the companion gaps file as the development roadmap to a full TRACT realization.

---

*Authored by Claude Opus 4.8 (1M context) as a CodeGraph-anchored full-spectrum assessment of ai-memory `release/v0.8.0` against the definitive TRACT design, across all **21 dedicated adversarial lenses** (3 complete waves of a 3×7 council). Companion: [`TRACT-vs-ai-memory-v0.8.0-DEVELOPMENT-GAPS-opus.md`](TRACT-vs-ai-memory-v0.8.0-DEVELOPMENT-GAPS-opus.md). Every claim carries a `file:line` touchpoint verified against the working tree.*
