# W3-A3 — P0 Chain Ordering Audit (TRACT §26.2)

**Role:** P0 chain ordering auditor · **Scope:** validate `P0-1→P0-2→P0-3→P0-4` against **v0.9.0 code**, propose **v1.0.0** ordered gates.  
**Anchors:** `ROADMAP.md` §26.2; `docs/design/TRACT-v0.8.0-DEVELOPMENT-GAPS-CANONICAL-opus.md` Phase A; `docs/v0.9.0/V0.9.0-AI-NHI-AUTONOMOUS-DEVELOPMENT-EPIC.md` §1.1/§1.5; code at schema **v78**.

---

## VERDICT

**HOLD** the §26.2 *epistemic* order for signal purity and model-family attestation (`P0-1 → P0-2a`).  
**SPLIT** P0-2 into **P0-2a** (attested `model_family` substrate) vs **P0-2b** (N≥3 enforce-as-**default**).  
**REORDER** P0-3 off the critical path after full P0-2: store-path agent attestation is **orthogonal** to family decorrelation and correctly shipped in parallel.  
**HOLD** P0-4 after **P0-2a** (not after P0-2b): epoch freeze must not launder unattested diversity; it does **not** require live-default enforce.  

At v0.9.0: **P0-1 shipped**, **P0-2a shipped**, **P0-2b NOT held** (enforce-CAPABLE, default `off` — correct), **P0-3 store-path shipped / federation half open**, **P0-4 shipped**. Kill-test bar met under the `856f5bd6` reading (enforce-capable, not enforce-default). The claim `"decorrelation enforced"` remains correctly **BANNED**.

---

## CONFIDENCE

**0.88** — high on code state (schema v77/v78, env defaults, epic claims-discipline). Medium residual on whether G1.2 (ranking still consumes `access_count`) should gate v1.0 before enforce-default (recommend parallel P1, not hard-block).

---

## ORDERING TABLE (v0.9.0 code truth)

| Gate | §26.2 intent | Issue / ID | v0.9.0 code state | Default posture | Claim status | Hard deps |
|------|--------------|------------|-------------------|-----------------|--------------|-----------|
| **P0-1** recall purity | Clean the signal; kill silent memory mutation on read | #1869 (G1) | **SHIPPED** — schema **v77** `recall_observations.folded`; pure path HTTP/MCP/CLI/shell/SAL both backends; FOLD job `db::fold_recall_accesses` / `MemoryStore::fold_recall_accesses`; tests `tests/recall_purity_p01.rs` (+ postgres twin) | Pure default; `AI_MEMORY_RECALL_TOUCH_SYNC=1` legacy opt-in (**deprecated, removal v1.0**) | `"pure recall"` **scoped-allowed** (ledger write only; eventual fold) | none (spine root) |
| **P0-2a** attested model_family | CLAIMED ≠ ATTESTED keystone | D3-012 / #1870 / #1719 | **SHIPPED** — schema **v78** `model_attestations` TOFU; `src/identity/model_family.rs` + storage model_attest; loader-observed / operator-signed; ~40% hard cap | Table present; coverage process-lifetime loader / OOB only | `"attests model family (loader-attested, ~40% hard cap)"` **claimable** | none structural (should follow P0-1 for clean metrics) |
| **P0-2b** N≥3 decorrelation ENFORCE | Refuse monoculture on **attested** evidence | D3-021 / #1767 / #1171 (+ D3-060) | **PARTIAL** — write-gate wired both backends (`run_decorrelation_write_gate` / `decorrelation_write_gate_pg`); pure core `evaluate_write_quorum` + `decorrelation_write_action`; refuse **only** on `AttestedMonoculture` | `AI_MEMORY_REFLECT_DECORRELATION_MODE` compiled **`off`**; enforce flag-gated; **live-flip = v1.0** | `"decorrelation enforced"` **BANNED** until default-on + D3-060 | **P0-2a** (never enforce on CLAIMED) |
| **P0-3** secure-default attestation flip | claimed → agent_attested by default | #1751 store; #1464 / FED write-sig | **PARTIAL** — store-path `require_agent_attestation_enabled` default **true** (`src/identity/attest.rs`); federation `AI_MEMORY_FED_REQUIRE_WRITE_SIG` still **permissive** default | Store required; fed write-sig opt-in | `"secure-by-default attestation"` **scoped store-path only** — do not claim network boundary | **none on P0-2b**; independent of family quorum |
| **P0-4** epoch-FREEZE consumer | verify-only freeze; no in-src optimizer | RQ-10 / #1878 / #1853 | **SHIPPED** — `SignableEpochManifest`; `ai-memory epoch-apply`; V-4 `epoch.manifest_applied`; git-tracked `docs/contracts/epoch_manifest.schema.json`; no RQGM optimizer in `src/` | Verify-only CLI consumer | `"epoch closure shipped"` **claimable** (verify-only scope) | **P0-2a** + F-41 policy_version (manifest must not launder unattested diversity); **not** P0-2b |

### Dependency graph (validated)

```
P0-1 ─────────────────────────────┐
                                  ▼
P0-2a (model_attestations) ──► P0-2b (enforce-as-default)   [v1.0 residual]
        │
        ├──► P0-4 (epoch-apply)     [shipped; dep = 2a, not 2b]
        │
P0-3 store (#1751) ── parallel ──┘   [shipped; orthogonal]
P0-3 fed write-sig ──────────────────► v1.0 residual (G3 remainder)
```

### Kill-test (§16 / §26.2) vs code

| Criterion | v0.9 bar | Status |
|-----------|----------|--------|
| Recall still mutates *memory state* silently? | No | **PASS** (pure default; ledger is sanctioned, not silent memory mutation) |
| Decorrelation still claimed-only? | No — enforce must be capable on **attested** metadata (`856f5bd6`) | **PASS** (enforce path test-pinned; default still off — does **not** unlock "enforced" claim) |

---

## REORDER PROPOSALS

### R1 — Split P0-2 (mandatory narrative fix)

Original `"P0-2 attested model_family ▶ N≥3 ENFORCE"` bundles two ship states that **diverged at v0.9**. Track:

- **P0-2a DONE** at v0.9 (D3-012 / v78).
- **P0-2b OPEN** for v1.0 (compiled default → `enforce` after soak; + **D3-060** invariants gate).

Without the split, ROADMAP prose still reads as if ENFORCE is a single v0.9 atomic — contradicted by epic §1.5 and `reflect_decorrelation_mode()` default `Off`.

### R2 — Demote P0-3 from “after full P0-2”

§26.2 linear chain `…P0-2 → P0-3 → P0-4` is **not** a data dependency. Agent write-attestation (`SignableWrite` / store 403) ≠ model-family TOFU. Evidence: #1751 shipped while P0-2b remains off-by-default — **correct**, not a process violation.

**Proposal:** P0-3 ∥ P0-2a in the DAG. Remaining work = **federation** secure-default (`AI_MEMORY_FED_REQUIRE_WRITE_SIG` flip + escape hatch), not re-gating store-path.

### R3 — P0-4 after P0-2a only

Epic hard dep `F-41 + D3-012 → RQ-10` is right; `D3-021 default-on → RQ-10` is **not**. Epoch consumer already shipped under that weaker gate. Do not re-open RQ-10 as blocked on enforce-default.

### R4 — P0-1 residual before or parallel to P0-2b

| Residual | Why order | v1.0 placement |
|----------|-----------|----------------|
| Remove `AI_MEMORY_RECALL_TOUCH_SYNC` | Escape hatch re-admits mutating recall; claim purity incomplete if flag lives forever | **V10-G0** (early, low risk) |
| Ranking still reads `access_count` (G1.2) | Salience Goodhart; orthogonal to fold purity | **P1 parallel** — do not hard-block enforce-default |
| #1706 shadow → #1707 live utility | Hot path still unwired (epic honesty note) | **After** shadow proves divergence; never before |

### R5 — Proposed **v1.0.0 epic ordered gates**

| Order | Gate ID | Deliverable | Blocks claim | Predecessors |
|------:|---------|-------------|--------------|--------------|
| 0 | **V10-G0** | Delete / hard-refuse `AI_MEMORY_RECALL_TOUCH_SYNC`; CI pin pure-only | Completes P0-1 permanence | P0-1 shipped |
| 1 | **V10-G1** | **P0-2b live-flip:** compiled default `enforce` (or one-cycle `advisory` soak → `enforce`); migration WARN | Unlocks path to `"decorrelation enforced"` | P0-2a; G0 recommended |
| 2 | **V10-G2** | **D3-060** enforce-invariants ship-gate (dual dominance metrics + CI) | With G1: full P0-2 claim | V10-G1 |
| 3 | **V10-G3** | **P0-3 federation half:** `AI_MEMORY_FED_REQUIRE_WRITE_SIG` secure default + documented opt-out | Full `"secure-by-default attestation"` (store+relay data lane) | none hard; schedule after G1 soak |
| 4 | **V10-G4** | RQ-PARITY-02 (#1875) full curator/SAL unification | Honest multi-backend L2 | RQ-PARITY-01 done |
| 5 | **V10-G5** | #1706 production wire → conditional #1707 | Live utility ranking | shadow divergence proof |
| 6 | **V10-G6** | FED-RQ-02..05 epoch/policy federation | Cluster epoch closure | P0-4 shipped |
| 7 | **V10-G7** | G17 recovery-VERIFY / key-loss (not rotation-only G13) | Key-loss resilience claim | G13 rotation shipped |
| 8 | **V10-G8** | G24 CC0 vectors (TRACT L1 keystone) | `"TRACT-/L1-conformant"` | independent keystone |

**v1.0 P0 spine (tag-blocking, narrowed):** `V10-G0 → V10-G1 → V10-G2` (complete original P0-2).  
**v1.0 P0-adjacent:** `V10-G3` (finish original P0-3).  
**Not P0:** G24/FED-RQ/G17 unless release marketing claims them.

---

## KILLER_OBJECTION

**"P0 chain complete at v0.9" is false if P0-2 means ENFORCE-as-shipped.**  
v0.9 correctly ships **enforce-CAPABLE** on attested families with default `off`. Treating that as §26.2 P0-2 closed would re-ban-flip `"decorrelation enforced"` while monocultures still write under stock config — the exact security-theater §25.3 forbids, just one flag layer up.

---

## TOP_RISK

**Evasion asymmetry under enforce-default + ~40% loader attestation cap.**  
`evaluate_write_quorum` refuses only `AttestedMonoculture` with `attested_rows ≥ MIN_REFLECTIONS_FLOOR`; unattested-heavy corpora stay `InsufficientAttested` → advise, never refuse. Flipping default to `enforce` without operator education + attestation coverage metrics will produce **false confidence** ("we enforce diversity") while writers avoid TOFU enrollment. Mitigate: ship coverage gauges + D3-060 before marketing the claim; keep anti-theater docs in release notes.

Secondary: ranking still folds access signal into ORDER BY — pure *write* path does not equal pure *salience*.

---

## VOTE

| Motion | Ballot |
|--------|--------|
| Keep P0-1 before P0-2a | **AYE** |
| Split P0-2a / P0-2b; hold 2b as v1.0 P0 | **AYE** |
| Decouple P0-3 from post-P0-2 critical path | **AYE** |
| Keep P0-4 dep on P0-2a only (not 2b) | **AYE** |
| Require D3-060 before un-ban `"decorrelation enforced"` | **AYE** |
| Hard-block v1.0 on G1.2 ranking purity | **NAY** (P1 parallel) |
| Claim original 4-gate chain fully closed at v0.9 | **NAY** |

**Synthesis vote:** **ACCEPT-WITH-SPLIT** — original chain was the right *build story*; v0.9 execution correctly parallelized P0-3 and deferred P0-2b; v1.0 epic must list **enforce-as-default + D3-060 + fed write-sig flip + RECALL_TOUCH_SYNC removal** as the residual ordered P0 spine, not re-walk P0-1/2a/4.

---

## Code anchors (load-bearing)

| Fact | Anchor |
|------|--------|
| Schema ladder | `CURRENT_SCHEMA_VERSION = 78` (`src/storage/migrations.rs`) |
| Pure recall default | `recall_touch_sync_enabled()`; handlers/storage fold gates |
| FOLD | `src/background/access_fold.rs`; `fold_recall_accesses` |
| model_attestations | migrate v78; `src/storage/model_attest.rs` |
| Write quorum / anti-theater | `src/curator/decorrelation_probe.rs::evaluate_write_quorum` |
| Decorrelation default Off | `reflect_decorrelation_mode()` → `Off` |
| Store attestation default true | `src/identity/attest.rs::parse_require_agent_attestation` |
| Fed write-sig permissive | `AI_MEMORY_FED_REQUIRE_WRITE_SIG` / `require_write_sig_enabled` |
| Epoch consumer | `cli::epoch_apply`; `SignableEpochManifest`; `EPOCH_APPLIED` |

---

*W3-A3 · TRACT §26.2 · v0.9.0 code · <350 lines · not a claims flip — audit only.*
