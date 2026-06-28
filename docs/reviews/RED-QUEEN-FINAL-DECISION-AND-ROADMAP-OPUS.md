# Red Queen / RQGM — FINAL Decision + Development Roadmap (OPUS, eternity-grade)

> **This is the project's final, locked decision point on Red Queen / RQGM.** It is the canonical artifact folded into `ROADMAP.md` §25. It supersedes the placement debate in all prior review docs; those remain as the audit-trail lineage.

**Author:** Claude Opus 4.8 (1M context) · orchestrator of a 21-lens / 3-wave × 7-subagent final convergence round (the third adversarial round; rounds 1–2 produced the four `*-OPUS.md` review docs)
**Date:** 2026-06-28
**Codebase:** `release/v0.8.0` @ `ead3da0c` (working tree; carries uncommitted FED-RQ-01)
**Paper:** [The Red Queen Gödel Machine (arXiv:2606.26294)](https://arxiv.org/abs/2606.26294) — [PDF](https://arxiv.org/pdf/2606.26294) (Iacob et al., 24 Jun 2026). **Provenance:** surfaced to the project by **Nick Jensen** ([X post](https://x.com/howtoprompt__/status/2070824205663273175)).
**Method:** CodeGraph CLI (`/Users/fate/.grok/bin/codegraph`, warm index 846 files) as L1 evidence + `rg`/`Read`/`git`. Every load-bearing claim carries a `file:line` anchor.
**Tracking issue:** [#1820](https://github.com/alphaonedev/ai-memory-mcp/issues/1820).
**Companions:** [`RED-QUEEN-21-AGENT-VOTE-OPUS.md`](RED-QUEEN-21-AGENT-VOTE-OPUS.md) (placement authority) · [`RQGM-2606.26294-vs-v0.8.0-OPUS.md`](RQGM-2606.26294-vs-v0.8.0-OPUS.md) (mechanism map) · [`RED-QUEEN-11-AGENT-VOTE-OPUS.md`](RED-QUEEN-11-AGENT-VOTE-OPUS.md) · [`RED-QUEEN-AGENT-11-ISOLATED-SIBLING-REPO-FUTURE-OPUS.md`](RED-QUEEN-AGENT-11-ISOLATED-SIBLING-REPO-FUTURE-OPUS.md).

---

## 0. THE FINAL DECISION (ratified 21/21 + 7-agent red-team)

ai-memory adopts the Red Queen **principles** — frozen-within-epoch evaluation, decorrelated **N≥3 *attested*-family quorum**, and adversarial bias-checking — while keeping the evolutionary **search engine permanently external** in a dependency-clean `ai-memory-rqgm` sibling that reads substrate telemetry and writes **exactly one operator-signed epoch artifact** the in-repo **L2 curator** verifies and anchors to the **V-4 audit chain**. Welding the optimizer into `src/` is a **category error** — the verifier becomes a player — that would falsify the §0 moonshot anchor, and is **CUT 21/21, for eternity**. RQGM optimizes **agents**; ai-memory governs **persistence**. The substrate's §2.6 bias-displacement advantage over an internal RQGM is **more ASI-durable but conditional** on two predicates the substrate has not yet built — **attested family-distinctness (~5% today)** and **vote-independence (0% today, likely permanently un-*attestable*, only empirically *estimable*)** — so the binding rules are **attestation-before-enforce** and **shadow-before-live**, and `enforce` on CLAIMED metadata stays correctly **INERT** until those predicates exist.

**This decision is final.** What remains is execution (the v0.9.0/v1.0.0 roadmap below) and one bounded open design fork (the epoch-manifest↔Checkpoint binding shape, §3) that is itself routed to a 5-agent vote before any irreversible commit.

**Composite grade:** moonshot-§0 substrate-fitness **B+ today → A− after the full v0.9.0 P0 spine**; **C−/D+ if internal RQGM ever ships in `src/`**. (Two distinct axes — never conflate substrate-fitness with the **~15% RQGM-optimization-readiness** / **~5% family-verify** metrics.)

---

## 1. The L1/L2/L3 placement (the contract)

```
L3 — ai-memory-rqgm / operator runner   (EXTERNAL — HARD LINE, sibling repo, v0.9.1+)
     evolutionary search · evaluator-population breeding · adversarial bias objectives
     READS  : recall_observations ledger, confidence-shadow, decorrelation/dominance exports (read-only, aggregate)
     WRITES : exactly ONE unsigned epoch_manifest.json draft  →  operator signs out-of-band
            │  operator Ed25519 signature
            ▼
L2 — ai-memory curator (IN REPO, separate process — v0.9.0)
     verify signed manifest → bind to an EpochAdvance Checkpoint → write V-4 epoch.manifest_applied
     epoch tick · stamp metadata.epoch_id · decorrelation EVERY cycle · panel slots from manifest
            │  SAL trait / hooks
            ▼
L1 — ai-memory substrate (MCP / HTTP / CLI — v0.9.0 spine)
     persist · gate · bounded depth-capped reflect · N≥3 ATTESTED-family quorum refuse
     record_recall ledger · STATIC operator-signed RuleEngine · V-4 chain · federation checkpoints · visibility
```

**Dependency direction is grep-provable** (`rg -i 'rqgm|epoch_manifest|red.?queen' src/` = **0 hits**): sibling → substrate only, never the reverse. The substrate has **zero compile dependency** on any L3 runner.

**Category boundary (the §0 line in the sand):** the substrate **verifies, it does not optimize**. An internal Agent-as-Judge is the substrate trusting its own trained grader — you cannot be verifier and player at one layer. The optimizer lives on the far side of a signed wire.

---

## 2. Why §2.6 quorum+epoch is the ASI-durable answer — and its two honest conditions

The mechanism is **capability-orthogonal**: substrate "agreement" is a vote-COUNT + a registration check (`src/store/mod.rs:2395,3116`), so verifying "N families agreed" never requires out-thinking the cognition audited — it holds when the audited cognition exceeds the auditor. **But** the claim "N *distinct attested* families agreed" smuggles in two predicates:

| Predicate | Today | Buildability | Home |
|-----------|-------|--------------|------|
| **P1 — family-distinctness** | ~5% (CLAIMED free strings; `SignableWrite` has no model_family, `src/identity/sign.rs:319-340`; `producer_signal` fallback forgeable, `src/curator/decorrelation_probe.rs:99-117`) | Engineering gap — **buildable** via loader-digest TOFU (D3-012). Hard cap: attests *which weights ran*, not RLHF/training-overlap distance. | v0.9.0 |
| **P2 — vote-independence** | **0%** — the substrate sees only signed bytes; it cannot distinguish genuine decorrelated agreement from **N rubber-stamp votes by one model in N hats** | **Architectural/epistemic limit** — independence is a property of the *generating process*, invisible to the substrate. At best an **empirical estimator** (advisory, capability-coupled), **never a hard attestation**. | research-horizon (document the ceiling; do not promise an attestation the architecture cannot produce) |

**The measurability cliff is a split, not a wall** (which signals survive ASI):
- **Survive** (substrate-computed, no model-in-loop): structural-invariant violation COUNTs (`src/storage/connection.rs:183-200`), `federation_partial_quorum_total` (`src/metrics.rs`), depth-exceeded refusal (`src/models/namespace.rs:963-970`).
- **Do not survive** (capability-coupled): contradiction-density — `detect_contradiction` is an LLM verdict (`src/llm.rs:2076`), measuring the judge's capability, not ground truth.

---

## 3. The epoch contract — RESOLVED design (one open vote)

An epoch is **three complementary artifacts bound by one SHA-256**, not a single net-new file (the prior "duplicates the Checkpoint" framing was a false dichotomy — the Checkpoint resolution signature *excludes* `condition`/`metadata`, `src/identity/sign.rs:650-678`, so it physically cannot carry the epoch payload):

```
content-signed epoch_manifest.json   ── signs the WHAT ──►  panel.slots[] · utility weights (frozen_within_epoch=true) · policy_version · prior_epoch_id · provenance.content_hash
        │ provenance.content_hash  (SHA-256 over canonical_signed_bytes(manifest sans signature))
        ▼
EpochAdvance Checkpoint               ── attests WHEN+WHO ──►  resolution = content_hash (a SIGNED field); reuses FED-RQ-01 federation transport
        │ same content_hash
        ▼
V-4 epoch.manifest_applied row        ── anchors the apply ──►  payload_hash == content_hash; tamper-evident, replayed by verify_audit_trail
```

- `ConditionType::EpochAdvance` is **migration-free** (SAL-enforced, not a SQL CHECK — `src/models/checkpoint.rs:13-32`).
- The V-4 writer mirrors `governance::rules_store::remove_signed` (~40 LOC, `src/governance/rules_store.rs:540`); `SignableEpochManifest` mirrors `SignableRoutineFreeze` (`src/identity/sign.rs:770`).
- **The schema needs one additive field** (`epoch_advance_checkpoint_id`) so the manifest→Checkpoint link is bidirectional.

**OPEN VOTE (T1+T4):** the exact manifest↔Checkpoint shape + `git add docs/contracts/epoch_manifest.schema.json` is a **public-contract + hard-to-reverse-layout crossroads**. Resolve via a `5-agent vote (4d3ea1c5)` **before** tracking the schema. Until then it stays **git-untracked, zero `src/` consumer** — and the claim "RQ-01 shipped / epoch contract committed" is **BANNED**.

---

## 4. Master deliverable table

Layer: **L1** substrate · **L2** curator · **L3** sibling. Effort: **S** ≤0.5 session/≤50 LOC · **M** ~1 session/50–150 LOC · **L** 2–3 sessions/new module or cross-surface.

### Sprint 0 — honesty & contract hygiene (immediate)

| ID | Title | Layer | Epic | Eff | Acceptance | Anchor / Issue |
|----|-------|-------|------|-----|-----------|----------------|
| D-OPUS-2 | Fix `reflect.rs` docstring falsely claiming PreReflect fires "today" | L1 | v0.8.0 hotfix | S | docstring reads "PostReflect only; PreReflect unreached pending D1-001" | `src/storage/reflect.rs:105-112` / #1820 |
| D-OPUS-5 | Re-word §2.1 "kilobytes of RAM" (~1000× overclaim) in BOTH files | docs | v0.8.0 hotfix | S | "tens-of-MB endpoints; MCUs hold L1 via gateway" | `docs/strategy/moonshot-synthesis.md:33` + `ROADMAP.md:35` / #1820 |
| D4-036 | `honest-limitations.md` Red Queen + ASI addendum | docs | v0.8.0 hotfix | S | shadow≠live, CLAIMED≠ATTESTED, P1≈5%, P2=0%, no AGI-safety claim | `docs/honest-limitations.md` / #1820 |
| RQ-02 | `RECURSIVE_LEARNING.md` L1/L2/L3 boundary section | docs | v0.8.0 hotfix | S | names the external-L3 hard line | `docs/RECURSIVE_LEARNING.md` |

### v0.9.0 P0 — substrate spine (BLOCKING the tag)

| ID | Title | Layer | Epic | Depends | Eff | Acceptance | Anchor / Issue |
|----|-------|-------|------|---------|-----|-----------|----------------|
| **D3-012** ⭐ | Attested `model_family` (the §11.4.D `model_attestations` v71 table + loader-digest TOFU + extend `SignableWrite` 6→7 + `AttestLevel::FamilyAttested`) | L1 | v0.9.0 | §11.4.D (absent) | L | enrolled digest → `FamilyAttested`; legacy 6-field sigs still verify; `producer_signal` reads attested digest first | `src/identity/sign.rs:319-340`; `src/identity/verify.rs:159-167` / **#1719** |
| D3-002 | #1171 heterogeneous panel synthesis (adjudicates §5 mechanism) | L1 | v0.9.0 | — | M | synthesis doc committed | `docs/v0.9.0/heterogeneous-ai-nhi-assessment/` / **#1171** |
| **D1-001** ⭐ | Wire MCP `PreReflect` veto (close `ReflectHooks::empty()`; mirror the wired `PreSignalSend` gate) | L1 | v0.9.0 | — | M | MCP `memory_reflect` Deny → `REFLECTION_HOOK_VETO`; no memory written | `src/mcp/tools/reflect.rs:496`; precedent `src/mcp/mod.rs:1454` / **#655** |
| D1-003 | Pre/PostReflect parity on HTTP + SAL reflect (T1 → vote) | L1 | v0.9.0 | D1-001 | L | postgres + HTTP reflect fire the veto; parity test green | `src/store/{sqlite.rs:843,postgres.rs:7906}` / #655 |
| **RQ-10** ⭐ | `SignableEpochManifest` + `EVENT_EPOCH_MANIFEST_APPLIED` + apply writer | L1/L2 | v0.9.0 | F-41, D3-012, §3 vote | M | epoch apply writes a V-4 row; `verify_audit_trail` replays it; `content_hash` triple-anchor | `src/signed_events.rs:227`; template `src/governance/rules_store.rs:540` / #1820 |
| EpochAdvance-bind | `ConditionType::EpochAdvance` (migration-free) + `resolution=content_hash` | L1/L2 | v0.9.0 | §3 vote | M | manifest hash signed into Checkpoint resolution; reuses FED-RQ-01 transport | `src/models/checkpoint.rs:13-32,115` / #1820 |
| **RQ-PARITY-01** ⭐ | Unify curator (`run_once` ⊋ `store_backed_reflection_sweep` → port 6 extras to SAL trait) | L2 | v0.9.0 | — | L | sqlite + postgres run the SAME epoch+decorrelation path; no third stack | `src/cli/curator.rs:201-206` / #1820 |
| **F-40** | Governance silent-disable: signed+audited `set_enabled` + `GOVERNANCE_RULE_DISABLED` event | L1 | v0.9.0 | — | S | ON→OFF disable emits a signed V-4 row; no silent neuter | `src/governance/rules_store.rs:593` (clone `:540`) / **D-OPUS-1** |
| **F-41** | `policy_version` / ruleset-digest (per-namespace SHA-256 of enabled signed rules; boot-checked) | L1 | v0.9.0 | F-40 | M | concept exists; stale-manifest refused; manifest binds via JOIN key | new `src/governance/policy_version.rs` / #1820 |
| RQ-11 | Decorrelation probe EVERY curator cycle (hoist out of `--reflect`) | L2 | v0.9.0 | RQ-PARITY-01 | S→M | probe runs in unified sweep on both backends; advisory under v0.9 | `src/curator/decorrelation_probe.rs:254`; `src/cli/curator.rs:786` / **#1764** |
| #1705 | Wire consume flip to a prod surface (HTTP store/link, agent_id-bound) + route MCP LIST through SAL | L1 | v0.9.0 | — | M | a prod surface sets `consumed`; cross-agent replay blocked; LIST single-impl | `src/store/sqlite.rs:894`,`postgres.rs:14176` / **#1705** (D-OPUS-6/7) |
| D-OPUS-3 | Wire PE-1 `enforce_required_event_presence` into dispatch OR stop `doctor` asserting "WILL DENY" | L1 | v0.9.0 | — | S | `Deny{503}` reachable, or doctor string corrected | `src/hooks/enforce.rs:260-356`; `src/cli/doctor.rs:384-389` / #1734 |
| RQ-12 | Manifest panel injection (panel slots from signed artifact, not env) | L2 | v0.9.0 | RQ-10 | M | curator judge panel sourced from `manifest.panel.slots[]` | `src/cli/curator.rs:114` / #1820 |
| RQ-13 | Epoch stamps (`metadata.epoch_id` on epoch-scoped writes) | L2 | v0.9.0 | RQ-10 | S | curator stamps `epoch_id`; readable downstream | `src/curator/mod.rs` / #1820 |
| epoch-freeze | Utility-epoch freeze LOOP (`utility_epochs` table, clone `routine_freeze`; curator-enforced) | L2 | v0.9.0 | RQ-10, RQ-12 | M | mid-epoch utility swap REFUSED (`EPOCH_FROZEN`); advance needs signed manifest + resolved Checkpoint | pattern `src/store/postgres.rs:2907,15133` / #1820 |
| #1706 / D4-015 | Shadow recall-utility sweep (aggregate `consumed`→rate, distinct from `access_count`, WEIGHT 0) | L2 | v0.9.0 | #1705 | M | offline sweep emits a utility gauge; recall ORDER BY byte-identical (weight-0 proof) | new `src/curator/recall_utility_probe.rs` / **#1706** |
| D3-050 | Federation sender `write_signature` emit (content attestation on relay) | fed | v0.9.0 | D3-012 | M | sender emits; receive upgrades to `agent_attested` | `src/handlers/federation_receive.rs` / #1464 |
| **FED-RQ-01** | Commit checkpoint federation on `SyncPushBody` (fail-closed both backends) | fed | v0.9.0 (lands v0.8.x) | — | DONE (in-flight) | +~282 LOC/4 files `M`; COMMIT with `5-agent vote (4d3ea1c5)` cite (T1/T3) | `src/handlers/federation_receive.rs:1583-1641` / #1718 |

### v0.9.0 P1/P2 — enforcement (gated within-epic)

| ID | Title | Layer | Epic | Depends | Eff | Acceptance | Anchor / Issue |
|----|-------|-------|------|---------|-----|-----------|----------------|
| D3-021 | `enforce` non-inert: N≥3 distinct-**attested**-family reflect REFUSAL (`DecorrelationRefused`); env ladder `_MODE`/`_QUORUM_N`/`_AGREEMENT` | L1/L2 | v0.9.0 | **D3-012** | M | monoculture-of-attested-families → 100% refused; **monoculture of CLAIMED → still advisory** (anti-theater) | `src/curator/decorrelation_probe.rs:272-281` / #1764 |
| D3-031 | Consolidation-time attested corpus-dominance gate | L2 | v0.9.0 | D3-012, D3-021 | M | single-attested-family cluster refused at consolidate | `src/cli/curator.rs:481`; reuse `decorrelation_probe.rs:139` / #1764 |
| D3-060 | Decorrelation enforcement-invariants ship-gate + dual dominance metrics | tests | v0.9.0 | D3-021, D3-031 | M | `tests/decorrelation_enforcement_invariants.rs` green | tests (new) / #1698 |

### v1.0.0 — federation maturity + audit

| ID | Title | Layer | Epic | Depends | Eff | Acceptance | Anchor / Issue |
|----|-------|-------|------|---------|-----|-----------|----------------|
| FED-RQ-02 | Federated content-signed epoch manifest (Checkpoint-bound) | fed | v1.0.0 | EpochAdvance-bind, FED-RQ-01 | L | manifest propagates cluster-wide, fail-closed | `src/handlers/federation_receive.rs:521` / #1718 |
| FED-RQ-03 | Cross-node `policy_version` gate (refuse stale manifest) | fed | v1.0.0 | F-41, FED-RQ-02 | M | stale-manifest push rejected | `src/handlers/federation_signing_check.rs` / #1718 |
| FED-RQ-AGG | Privacy-preserving AGGREGATE utility attestation (signed, quantized — **NEVER raw rates**) | fed | v1.0.0 (GATE) | #1706 | L | no per-row `consumed`/utility on the wire; aggregate signed + verified | `src/handlers/federation_sync_since.rs:244` / #1464 |
| #1707 | Live recall-utility wire (utility_rate weight > 0) | L2 | v1.0.0 | #1706 proves signal | M | enabled ONLY after shadow proves divergence from `access_count` | `src/storage/mod.rs:3688` / **#1707** |
| F-53/#1809 | Federation E2E (eliminate decrypt→plaintext→reseal) | fed | v1.0.0 | — | L | no transient plaintext on relay | `src/encryption/mod.rs:11-16` / #1809 |
| RQ-VI-01 | Vote-independence empirical estimator (advisory; documented un-attestable) | L2 | v1.0.0 / horizon | D3-012 | M | estimator published; honest-limitations names the ceiling | `src/store/mod.rs:2395` / #1820 |

### Federation parity (checkpoint-only, no epoch dep — eligible v0.9)

| ID | Title | Epic | Anchor |
|----|-------|------|--------|
| FED-RQ-04 | Checkpoint catch-up on `/sync/since` (close push/pull asymmetry — pull has 0 checkpoint refs today) | v0.9 eligible | `src/handlers/federation_sync_since.rs` / #1718 |
| FED-RQ-05 | HTTP W-of-N quorum fanout for checkpoint create/resolve | v0.9 eligible | `src/checkpoints/mod.rs:330` / #1718 |

### Sibling — `ai-memory-rqgm` (v0.9.1+, NEVER blocks the v0.9.0 tag)

| ID | Title | Layer | Anchor |
|----|-------|-------|--------|
| RQ-20 | Ledger reader (read-only L1 exports) | L3 | `src/observations/mod.rs:239` |
| RQ-20.1 | Decorrelation export — **substrate half** (v0.9 opt-P0, read-only `DominanceReport` CLI/HTTP) **vs sibling half** (recompute) | L3/L1 | `src/curator/decorrelation_probe.rs:139,254` (curator-locked today) / #1698 |
| RQ-21 | Panel breeder → `panel.slots[]` | L3 | `docs/contracts/epoch_manifest.schema.json` |
| RQ-22 | Unsigned manifest writer (operator signs out-of-band; cannot self-sign) | L3 | schema signature block |
| RQ-23 | RQGM reference harness vs fixture corpus | L3 | arXiv:2606.26294 |

---

## 5. The DAG, critical path, and sequencing gates

```
Sprint 0 (parallel): D-OPUS-2 · D-OPUS-5 · D4-036 · RQ-02 · F-40 · F-41
S1: D1-001 ──► D1-003
S2: D3-012 (KEYSTONE, L) ──► D3-021 ──► D3-031 ──► D3-060
    RQ-PARITY-01 (L) ──► RQ-11 ──► D3-021[cycle-enforce]
    #1705 ──► #1706 ──► (#1707 DEFERRED v1.0)
S3: F-41 + D3-012 ──► RQ-10 + EpochAdvance-bind ──► RQ-12 · RQ-13 · epoch-freeze
```

**Non-negotiable ordering gates (theater-prevention, already encoded as code edges):**
1. **D3-012 → D3-021** — enforce on CLAIMED metadata is security theater. The `enforce`-INERT degrade (`decorrelation_probe.rs:272-281`) is the CORRECT v0.8.0 posture and must NOT flip until attested families exist.
2. **#1706 → #1707** — wiring a feedback signal before measuring its distribution is the Goodhart trap `access_count` already embodies.
3. **RQ-PARITY-01 → RQ-11** — hoisting decorrelation before curator unification lands it sqlite-only, blinding postgres fleets (the shared-corpus monoculture risk, `ROADMAP.md:183`).
4. **F-41 + D3-012 → RQ-10** — signing a manifest whose `panel.slots[]`/`policy_version` are unattested/undefined *launders CLAIMED diversity into a signed artifact* — worse than no ledger.

**Critical path:** `RQ-PARITY-01 (L) → RQ-11 → D3-021` converging with `D3-012 (L) → D3-021`. **D3-012 is the single keystone** — it co-gates D3-021 enforce AND RQ-10 panel semantics.

**Top-3 highest-leverage first moves:** (1) **D3-012** — the §2.6 keystone; (2) **RQ-10 + EpochAdvance-bind** — ~40 LOC makes "epoch applied" falsifiable + resolves the untracked-schema fork; (3) **D1-001** — ~80% pre-built, closes the dead MCP veto + the D-OPUS-2 docstring lie.

---

## 6. The CUT list — enforceable ship-gate invariants (mechanical, not prose)

Each CUT becomes a CI gate modeled on the existing `scripts/check-vendor-literals.sh` self-test pattern. **Six are already at a 0-hit baseline** — land them as ratchets in v0.8.0 CI to freeze the baseline before the v0.9 work begins.

| CUT | Mechanical gate | Ship-block? |
|-----|-----------------|-------------|
| No RQGM / population genetics in `src/` | `scripts/check-rqgm-quarantine.sh`: `rg 'epoch_manifest\|RQGM\|co.?evolv\|evolutionary\|genetic\|\bfitness\b\|SignableEpochManifest' src/` = 0 (allowlist `docs/contracts/`) | v0.8.0 ratchet |
| No governance auto-mutation | precheck: no `&mut self.rules` / no `governance_rules` write outside the signed-load path + test that non-operator-signed rule cannot enforce | **v0.9.0 BLOCKER** |
| No enforce on CLAIMED metadata | test pinning `enforce` degrades to advisory until attested | **v0.9.0 BLOCKER** |
| No #1707 live before #1706 shadow | static assert: recall ORDER BY stays exactly **6 factors**; no consume-rate term | **v0.9.0 BLOCKER** |
| No epoch-as-MCP-tools / `--rqgm` flag | grep `registered_tools()` + `Command` enum for `epoch`/`rqgm`/`evolve` | v0.8.0 ratchet |
| No cross-node raw utility leaderboards | grep `src/federation/` for `leaderboard`/`utility_rank`/`raw_utility` wire fields | v0.8.0 ratchet |

**Separation-of-powers invariant (the static-law guarantee):** `RuleEngine::evaluate(&self, …)` is read-only (`src/governance/agent_action.rs:782`); a rule enforces only when `enforced_rule_passes` confirms `operator_signed` + a verified Ed25519 sig (`src/governance/rules_store.rs:205`); `sign.rs` has **no `SignableEpochManifest`** that could attest a self-authored governance mutation. The gates *pin* an existing structural property.

---

## 7. Performance ship-gates

The single load-bearing perf invariant: **the live recall ORDER BY stays exactly 6 factors through v0.9** (`src/storage/mod.rs:3686-3691`; `access_count` is factor 6, `MIN(access_count,50)*0.1` — the real Goodhart proxy, which is *why* the external runner needs zero new instrumentation). The three "0-cost" claims compose: decorrelation (cold path, single curator caller), shadow #1706 (weight-0/offline), external L3 runner (reads existing telemetry). p95 budgets: `memory_recall` semantic ≤35 ms / autonomous ≤90 ms, v0.9 ceiling ≤50 ms, no regression — enforced by the existing `bench --baseline` CI guard. New gates: static assert on ORDER-BY factor count + codegraph assert that the decorrelation probe's callers ⊆ `{src/cli/curator.rs}`.

---

## 8. Endpoint tiering (RQGM is Tier C only)

| Tier | Hardware | Layer | Red Queen deliverables |
|------|----------|-------|------------------------|
| ∅ | Cortex-M MCU ("kilobyte" sensors) | none on-device | none — L1 held by a **gateway** on the sensor's behalf |
| A | Field sensor / phone (<256 MB budget → Keyword tier, `llm_model:None`, `src/config.rs:239,277`) | **L1 only** | **none** — no curator/decorrelation/epoch/RQGM (needs an LLM Tier A doesn't have) |
| B | Hub / Pi / Jetson (≥1 GB) | **L1 + L2** | decorrelation probe + N≥3 quorum + epoch-manifest apply run HERE |
| C | Operator fleet / server | **L1 + L2 + optional L3** | **RQGM search (external `ai-memory-rqgm`) Tier C ONLY** |

**§2.1 doc fix (D-OPUS-5):** the moonshot "IoT sensors with kilobytes of RAM" overclaims ~1000× (real floor ≈31 MB binary / ≈18–25 MB idle RSS, `docs/mobile-iot-deployment.md:319-327`). Re-word to "tens-of-MB endpoints (phones, Pi-class boards, robotics controllers); kilobyte-RAM MCUs hold L1 via a gateway." Lives in **both** `docs/strategy/moonshot-synthesis.md:33` AND `ROADMAP.md:35` — patch both.

---

## 9. Claims discipline (binding for v0.8.0 / v0.9.0 / v1.0.0 release surfaces)

**Allowed today (v0.8.0, each caveated):** "Red-Queen-*principles*-aligned substrate (~15% optimization-readiness)" · "advisory visibility-only decorrelation probe (CLAIMED, enforce INERT)" · "Ed25519 + V-4 attestation of operations (the *agent key*, not the model family)" · "observation ledger with dual-backend *record* parity (consume flip is dead code, C-1)" · "signed epoch-boundary contract *spec* (git-untracked, no consumer)" · "FED-RQ-01 checkpoint federation (in-flight)."

**Banned → unlock condition (AND, not OR):**

| Banned claim | Unlocks only when… | Milestone |
|--------------|--------------------|-----------|
| "decorrelation enforced" / "bias-displaced structurally" | D3-012 + D3-021 + D3-060 green AND `attest_level ≥ family_attested` | v0.9.0 |
| "attests model family" | D3-012 lands — and even then only "**loader-attested**" (which weights ran), NEVER training/RLHF family distance | v0.9.0 partial; true family = v1.x+ (needs industry standard) |
| "closed recursive self-improvement loop" | D2-001 + #1706 **shadow** (NOT #1707 live) | v0.9.0 (shadow only) |
| "epoch closure shipped" / "RQ-01 shipped" | RQ-10 V-4 writer + a wired `SignableEpochManifest` consumer + schema git-tracked | v0.9.0 → v1.0 |
| "federation-attested reflection chains" | D3-050 sender emit + unsigned ratio = 0 on test mesh | v0.9.0 → v1.0 |
| **"implements RQGM" / "co-evolving evaluators shipped"** | **NEVER in-repo** (category error) — only an external sibling runner | **perma-ban** |

**Readiness trajectory:** optimization-readiness 15% (v0.8) → ~50–60% (v0.9 P0) → ~70–80% (v1.0); family-verify 5% → ~40% loader-attested (hard cap) → ~40%; vote-independence 0% throughout (architectural limit).

---

## 10. Defect annex (first-party findings — flagged for operator authorization to file, per sole-authority policy)

| ID | Defect | Anchor | Fix |
|----|--------|--------|-----|
| D-OPUS-1 | Governance silent-disable (ON→OFF rule disable, no sig/audit; per-row sig can't catch it because `WHERE enabled=1` filters before verify; no `policy_version`) | `src/governance/rules_store.rs:593` | F-40 + F-41 (one coupled fix) |
| D-OPUS-2 | `reflect.rs` docstring falsely claims PreReflect fires "today" | `src/storage/reflect.rs:105-112` | Sprint 0 |
| D-OPUS-3 | `doctor --hooks` prints "WILL DENY" for a PE-1 path with zero production callers | `src/hooks/enforce.rs:260-356` | wire guard or correct string |
| D-OPUS-4 | `epoch_manifest.schema.json` git-untracked | `git ls-files docs/contracts/` empty | git-track after §3 vote |
| D-OPUS-5 | §2.1 "kilobytes of RAM" ~1000× overclaim (two files) | `moonshot-synthesis.md:33` + `ROADMAP.md:35` | Sprint 0 |
| D-OPUS-6 | `recall_observations` consume flip = dead code (no prod surface; postgres column permanently 0) | `mark_recall_consumed` callers test-only | #1705 |
| D-OPUS-7 | `recall_observations` LIST split-brain (MCP sqlite free-fn vs HTTP SAL) | `src/handlers/route_1111.rs:305` | #1705 |

Plus one **doc-vs-code drift defect** (Lens 9): the epoch schema's **required** `policy_version` field has **zero substrate backing** — closed by F-41.

---

## 11. Release gates

**v0.9.0 tag (all green):** four cargo gates clean · D3-012 attested family lands · D1-001/003 PreReflect veto reachable (MCP+HTTP+SAL) + D-OPUS-2 fixed · RQ-10 + EpochAdvance-bind with a cited 5-agent vote before schema git-add · RQ-PARITY-01 curator unified · F-40 + F-41 closed · RQ-11 every cycle + D-OPUS-3 fixed · #1705 consume wired + LIST via SAL · FED-RQ-01 committed with crossroads cite · claims-discipline + CUT gates enforced · honest-limitations addendum live · epoch loop is shadow (#1706), #1707 DEFERRED.

**v1.0.0 tag (all green):** v0.9.0 sustained on the unified curator · D3-021/031/060 enforce live on attested family + vote-independence estimator shipped/documented · `ai-memory-rqgm` sibling operational with grep-provable zero compile dependency · #1706 proves signal → #1707 enabled · FED-RQ-02..05 + FED-RQ-AGG (aggregate-only) + F-53/#1809 E2E · utility-epoch freeze loop enforced with a within-epoch-frozen invariant test.

---

## 12. Final one-paragraph verdict

The Red Queen analysis is **closed**: adopt the principles, keep the algorithm external for eternity, and build the v0.9.0 substrate spine (attested family → reachable veto → V-4 epoch writer bound to a Checkpoint → unified curator → governance integrity → shadow feedback) as the blocking, eternity-grade path that earns A− and preserves the endpoint-substrate moonshot value through AGI→ASI **by counting signatures and freezing windows rather than out-thinking the cognition it audits** — honest that two attestation predicates (family-distinctness, vote-independence) gate the bias-displacement claim, that one is buildable and one may be permanently only estimable, and that the optimizer never crosses the signed wire into `src/`.

---

**AI involvement:** Final convergence round — 21 isolated subagent lenses across 3 sequential waves of 7 (Claude Code 7-concurrent cap honored), plus the prior 7-agent self-red-team, authored/synthesized by **Claude Opus 4.8 (1M context)**, CodeGraph CLI as L1 evidence, against `release/v0.8.0` @ `ead3da0c`. Operator directive 2026-06-28 (provenance: Nick Jensen). Crossroads cite: `5-agent vote (4d3ea1c5)` pattern scaled to 21 lenses. Tracking: #1820.
