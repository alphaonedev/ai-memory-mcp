# v0.9.0 Development Roadmap — Recursive Learning & Self-Improvement A+

**Status:** FINAL (11-agent adversarial vote synthesis)  
**Vote record:** 5-agent crossroads protocol `4d3ea1c5` + 11 adversarial lenses (2026-06-26)  
**Base:** `release/v0.8.0` @ `c85b9c56`  
**Detail:** [`RECURSIVE-LEARNING-A-PLUS-DEVELOPMENT-PATH.md`](RECURSIVE-LEARNING-A-PLUS-DEVELOPMENT-PATH.md)

---

## Executive verdict

| Lens cluster | Verdict | Confidence |
|--------------|---------|------------|
| Architecture (1–3) | **REVISE sequencing** — right gaps, wrong DAG | 78–85% |
| Testability / Security / Ops / Federation (4–7) | **CONDITIONAL SHIP** — shadow-only feedback; sender emit before strict flags | 72–85% |
| Procurement / Perf / Parity / Claims (8–11) | **CONDITIONAL A+** — evidence stack required; CUT enforce theater | 84% |

**Unanimous finding:** v0.9.0 **can** deliver A+ on all four dimensions **only if** attested model-family provenance (D3-012) precedes decorrelation enforce (D3-021), federation sender signing (D3-050) precedes #1751 default flip, and live recall-utility wire (#1707) stays **deferred** unless shadow (#1706) proves signal.

**Rejected for v0.9.0 A+ tag (CUT):**

- `D3-001` / `D3-022` — `enforce` on CLAIMED `model_family` (security theater)
- `D2-009` — curator weighting from unauthenticated outcomes
- `D2-012` / `D4-027` — live recall ranking mutation without shadow proof
- `D4-021` — coordination scope bleed (stabilize in v0.9.1)
- `D4-026` — swarm reflect before attestation + panel

---

## Target grades (v0.9.0 tag-cut)

| Dimension | v0.8.0 | v0.9.0 Target | Ship gate |
|-----------|--------|---------------|-----------|
| **D1** Primitive | A− | **A+** | Hooks + postgres audit + three-surface parity |
| **D2** Autonomous loop | B | **A+** | Unified curator + governance + benchmark |
| **D3** Decorrelation | C+ | **A+** | Attested family + enforce + N≥3 + sender sig |
| **D4** AGI-scale RSI | C | **A+** | Manifests + shadow feedback + integrity rules + honesty docs |

---

## 11-agent vote tally (selected tasks)

Vote scale: **MUST** / **SHOULD** / **DEFER** / **CUT**

| Task | L1-3 | L4-7 | L8-11 | **Final** |
|------|------|------|-------|-----------|
| V09-RL-D1-001 hooks MCP | MUST | MUST | MUST | **MUST P0** |
| V09-RL-D1-004 shared hook bundle | MUST | — | — | **MUST P0** |
| V09-RL-D1-006 postgres audit tests | MUST | MUST | — | **MUST P0** |
| V09-RL-D1-010 ledger SAL promotion | — | — | MUST | **MUST P1** |
| V09-RL-D1-011 authenticated consume | — | — | MUST | **MUST P1** |
| V09-RL-D1-012 ledger HTTP/MCP both backends | — | — | MUST | **MUST P1** |
| V09-RL-D2-001 unify curator reflection | MUST | MUST | — | **MUST P1** |
| V09-RL-D2-007 compaction autonomous default | SHOULD | — | MUST | **SHOULD P2** |
| V09-RL-D2-009 link rollback #1771 | DEFER | CUT | — | **MUST before default compaction** |
| V09-RL-D2-011 reflect write=approve | — | MUST | — | **MUST P1** |
| V09-RL-D2-012 curator governance | — | — | — | **MUST P1** |
| V09-RL-D3-001 enforce stub | CUT | — | — | **CUT** |
| V09-RL-D3-012 family attestation | MUST | — | MUST† | **MUST P0** |
| V09-RL-D3-021 reflect enforce gate | DEFER | — | — | **MUST P2** (after 012) |
| V09-RL-D3-031 consolidate gate | — | — | — | **MUST P2** |
| V09-RL-D3-050 federation sender sig | — | MUST | — | **MUST P2** |
| V09-RL-D3-060 enforcement invariants | — | MUST | — | **MUST P3** |
| V09-RL-D3-002 #1171 panel | MUST | — | — | **MUST P0** |
| V09-RL-D4-001 composition manifest | MUST | — | SHOULD | **MUST P2** |
| V09-RL-D4-015 shadow feedback #1706 | MUST | MUST | MUST | **MUST P2** |
| V09-RL-D4-017 live recall wire #1707 | CUT | DEFER | DEFER | **DEFER v0.9.1** |
| V09-RL-D4-029 paradigm-shift runbook | — | — | MUST | **MUST P3** |
| V09-RL-D4-030 perf p95 gates | — | — | MUST | **MUST P3** |
| V09-RL-D4-036 honest-limitations | — | — | MUST | **MUST P0** |
| V09-RL-D4-038 marketing scrub | — | — | MUST | **MUST P3** |

†L11: MUST as blocker for decorrelation enforce, not optional polish.

---

## Phased execution plan (voted)

### Sprint 0 — Honesty & adjudication (Week 1)

**Goal:** Close process gates before code claims.

| Task | Output |
|------|--------|
| V09-RL-D3-001 / 002 / 003 | `#1171` Phase 1+2 complete; `docs/v0.9.0/heterogeneous-ai-nhi-assessment/synthesis.md` |
| V09-RL-D4-036 | `honest-limitations.md` RL addendum (shadow≠live, CLAIMED≠ATTESTED, no AGI safety) |
| V09-RL-D4-038 | Ban list for release surfaces (see §Marketing discipline) |

**Exit:** Panel synthesis merged; ROADMAP §5 stale text fixed.

---

### Sprint 1 — D1 spine (Weeks 2–3)

**Goal:** D1 A− → A+

| Order | Task | Acceptance |
|-------|------|------------|
| 1 | V09-RL-D1-001 | MCP `PreReflect` fires `hooks.toml`; veto → `REFLECTION_HOOK_VETO` |
| 2 | V09-RL-D1-002 | `PostReflect` observer best-effort post-commit |
| 3 | V09-RL-D1-004 | `build_reflect_hooks_bundle()` shared |
| 4 | V09-RL-D1-003 | HTTP + SAL parity |
| 5 | V09-RL-D1-005 | PE-1 `pre_reflect` required-event enforcement |
| 6 | V09-RL-D1-006 / 007 / 008 | Postgres audit + SAL coverage + repro script |
| 7 | V09-RL-D1-015 | `reflection.hook_veto` audit channel |

**Exit:** `./scripts/reproduce-recursive-learning.sh` asserts audit; `three_surface_parity_reflect_hooks` green.

---

### Sprint 2 — Ledger & provenance (Weeks 3–5)

**Goal:** Unblock D4 shadow + D3 enforce

| Order | Task | Acceptance |
|-------|------|------------|
| 1 | V09-RL-D1-010 / 011 / 012 | Postgres daemon populates `recall_observations`; authenticated consume |
| 2 | V09-RL-D3-010 / 011 | `model_attestations` v71; loader digest on LLM init |
| 3 | V09-RL-D3-012 / 013 / 014 | Family stamp on reflect; federation sanitize; CLI evidence |
| 4 | V09-RL-D4-035 | Schema parity test green |

**Exit:** `doctor` reports attested family on test reflect; ledger rows on postgres recall.

---

### Sprint 3 — D3 enforcement (Weeks 5–7)

**Goal:** D3 C+ → A+

| Order | Task | Acceptance |
|-------|------|------------|
| 1 | V09-RL-D3-020 | Quorum knobs + panel-adjudicated agreement semantics |
| 2 | V09-RL-D3-021 / 022 | `enforce` non-inert; `DecorrelationRefused` on reflect |
| 3 | V09-RL-D3-030 / 031 | Consolidation-time attested dominance gate |
| 4 | V09-RL-D3-050 / 052 | Federation sender `write_signature`; trust policy documented |
| 5 | V09-RL-D3-060 / 062 | Ship-gate invariants; dual dominance metrics |

**Exit:** Monoculture reflect refused under `enforce`; mesh emits signatures; `tests/decorrelation_enforcement_invariants.rs` green.

---

### Sprint 4 — D2 loop closure (Weeks 6–8, parallel with Sprint 3)

**Goal:** D2 B → A+

| Order | Task | Acceptance |
|-------|------|------------|
| 1 | V09-RL-D2-001 / 002 | Default curator runs reflection for enabled namespaces |
| 2 | V09-RL-D2-011 / 012 | Reflect + curator governance parity with `capture_turn` |
| 3 | V09-RL-D2-003 / 013 / 017 | Invalidation triage + postgres parity + idempotency |
| 4 | V09-RL-D2-005 / 016 | Transcript classify + hooks in curator pass |
| 5 | V09-RL-D2-009 | Link rollback **before** D2-007 default flip |
| 6 | V09-RL-D2-007 / 008 | Autonomous tier compaction default + capabilities honesty |
| 7 | V09-RL-D2-014 / 018 / 019 | Reflection boost resolver + docs + LongMemEval row |

**Exit:** `[curator.autonomous_loop]` ladder shipped; soak test produces reflections without `--reflect`.

---

### Sprint 5 — D4 envelope (Weeks 8–10)

**Goal:** D4 C → A+

| Order | Task | Acceptance |
|-------|------|------------|
| 1 | V09-RL-D4-001 / 002 / 004 / 005 | Composition manifest + verifier + attestation |
| 2 | V09-RL-D4-009 / 010 / 011 | Integrity rules R005+; governance mutate action |
| 3 | V09-RL-D4-015 / 016 | Shadow sweep #1706; bridge to Form-5 (no live wire) |
| 4 | V09-RL-D4-021 / 022 | Optional lease + checkpoint on reflect/promote |
| 5 | V09-RL-D4-026 | Opt-in cascade rollback |
| 6 | V09-RL-D4-029 / 030 | Paradigm-shift + audit-not-storage docs |

**Deferred to v0.9.1:** V09-RL-D4-017 (live #1707 wire), `memory_reflect_swarm`, #1751 default flip.

**Exit:** `memory_composition_verify` green; shadow metrics published; integrity bypass tests green.

---

### Sprint 6 — Release gate (Weeks 10–11)

| Task | Gate |
|------|------|
| V09-RL-D4-001-matrix | Extend `grand_slam_recursive_learning.rs` with v0.9 phases |
| V09-RL-D4-029-packet | Procurement evidence packet + NSA mapping cross-ref |
| V09-RL-D4-030-perf | `PERFORMANCE.md` p95 rows (shadow=0-cost; live=veto) |
| NHI-D4-1..7 | Multi-agent reflect→manifest→verify playbook |
| V09-RL-D4-036 panel | #1171 sign-off on A+ claim |

**Four cargo gates + ship-gate:**

```bash
cargo fmt --check
cargo clippy -- -D warnings -D clippy::all -D clippy::pedantic
AI_MEMORY_NO_CONFIG=1 cargo test
cargo test --test decorrelation_enforcement_invariants
cargo test --test grand_slam_recursive_learning
./scripts/reproduce-recursive-learning.sh
scripts/qc-codegraph-precheck.sh
```

---

## Marketing discipline (v0.9.0 — voted ban list)

Do **not** claim in release notes, Pages, or procurement packets unless the paired task is green:

| Banned claim | Required evidence |
|--------------|-------------------|
| "Bias-displaced structurally" | D3-012 + D3-021 + D3-060 |
| "Substrate refuses AGI/ASI unsafe ideas" | Not in v0.9 scope — horizon only |
| "Closed recursive self-improvement loop" | D2-001 + D4-015 shadow (not #1707 live) |
| "Decorrelation enforced" | Attested `model_family_attest_level >= loader_attested` |
| "Federation-attested reflection chains" | D3-050 sender emit + D4-024 unsigned ratio = 0 on test mesh |

**Approved v0.9.0 framing:**

> ai-memory v0.9.0 ships **bounded, provenance-pinned, decorrelation-gated recursive refinement** with shadow-first recall feedback, composition manifest verification, and an autonomous curator loop — while honestly documenting substrate boundaries (no weight updates, no intra-session hallucination prevention, paradigm-shift degradation path).

---

## Configuration migration (operator guide)

### New environment variables (v0.9.0)

| Variable | Default | Purpose |
|----------|---------|---------|
| `AI_MEMORY_REFLECT_DECORRELATION_QUORUM_N` | `3` | N≥3 attested-family quorum |
| `AI_MEMORY_REFLECT_DECORRELATION_AGREEMENT` | panel-adjudicated | Quorum agreement semantics |
| `AI_MEMORY_CURATOR_AUTONOMOUS_LOOP` | `off` | `off` \| `supervised` \| `autonomous` |
| `AI_MEMORY_RECALL_CONSUMPTION_SHADOW` | `1` | Enable #1706 offline sweep |
| `AI_MEMORY_RECALL_CONSUMPTION_WEIGHT` | `0` | **v0.9.0: stay 0** (live wire v0.9.1) |

### Recommended upgrade path

1. Upgrade binary; schema auto-migrates v70 → v71+
2. Run `ai-memory doctor --rl-readiness` (new; ships Sprint 2)
3. Enable `advisory` decorrelation; monitor `reflection.decorrelation.advisory`
4. Enroll federation sender keys; verify `write_signature` emit
5. Configure `[curator.reflection_namespaces]` + `autonomous_loop=supervised`
6. Only then flip `AI_MEMORY_REFLECT_DECORRELATION_MODE=enforce`

---

## Issue tracker mapping

| GitHub | Roadmap sprint |
|--------|----------------|
| #655 | Sprint 1 (D1 completion) |
| #666 / #1671 | Sprint 4 (D2 curator) |
| #1171 | Sprint 0 (panel) |
| #1464 | Sprint 3 (sender emit) |
| #1698 / #1764 | Sprint 3 (enforce) |
| #1705 / #1706 / #1707 | Sprint 2 + 5 (ledger + shadow; 1707 deferred) |
| #1719 | Sprint 2 (attestation) |
| #1771 | Sprint 4 (link rollback) |

---

## Success metrics (A+ certification)

| Metric | Target |
|--------|--------|
| D1: Hook veto reachable in MCP | Integration test green |
| D1: Postgres depth-refusal audit | Row in `signed_events` per refusal |
| D2: Curator daemon reflection rate | ≥1 reflection/namespace/cycle when enabled |
| D2: LongMemEval R@5 delta | ≤0.5% vs v0.8 autonomous baseline |
| D3: Enforce refusal rate (monoculture fixture) | 100% refused |
| D3: Federation signed ratio (test mesh) | 100% |
| D4: Manifest verify round-trip | SHA-256 stable |
| D4: Shadow consumption utility signal | Published; distinct from `access_count` |
| Perf: `memory_recall` p95 | ≤50ms (no regression from v0.8) |

---

## Document lineage

| Artifact | Role |
|----------|------|
| This file | **Canonical v0.9.0 execution roadmap** (operator + agent SSOT) |
| `RECURSIVE-LEARNING-A-PLUS-DEVELOPMENT-PATH.md` | Full task inventory + file paths |
| `docs/RECURSIVE_LEARNING.md` | Primitive reference |
| `ROADMAP.md` §5 | Strategic commitment |
| `docs/v0.8.0/GOAL-EPIC-KICKOFF.md` | Effort baseline |

**Vote citation:** `5-agent vote (4d3ea1c5)` + 11-agent adversarial assessment 2026-06-26.

---

*Operator gate: tag-cut `v0.9.0` only when Sprint 6 gates green and #1171 synthesis approves A+ claims.*