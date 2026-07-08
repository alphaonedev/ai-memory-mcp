# W2-A2 — Decorrelation & Bias-Displacement (§2.6)

> **Agent:** W2-A2 (Decorrelation & Bias-Displacement Assessor)  
> **Date:** 2026-07-08  
> **Scope:** v0.9.0 distance-to-ontology for ROADMAP §2.6 / §25.3  
> **Sources:** `src/curator/decorrelation_probe.rs`, `src/identity/model_family.rs`, `src/storage/model_attest.rs`, `src/storage/reflect.rs` (write gate), postgres twin, env resolvers, ROADMAP §5/§25.3–§25.7, Wave-1 synthesis `w1-a7-synthesis.md`

---

## VERDICT

**§2.6 is TARGET LAW, NOT HELD.** v0.9.0 ships real substrate **machinery** (S1 table + S2 pure quorum + opt-in write-time refuse path + visibility probe), but the property “no unilateral self enters durable bias-displaced identity without N≥3 **attested** distinct families” is **not structurally held** on default deployments.

Three short answers:

| Question | Answer |
|---|---|
| **Is enforce inert?** | **Split.** Visibility probe enforce is **still inert** (degrades to advisory). Write-time gate enforce is **code-live** under `MODE=enforce` (Refuse + signed `reflection.decorrelation_refused`). **Default mode `off`** → whole gate **inert-by-default**. |
| **Is family attestation loader-only ~40% cap real?** | **YES.** Documented + coded as hard cap (process-lifetime loader self-report at LLM construction sites; external reflections never pass the boundary). |
| **Is N≥3 live?** | **Logic default N=3 when mode is active; not live by default.** Compiled `AI_MEMORY_REFLECT_DECORRELATION_MODE=off`. Even under `enforce`, refusal requires ≥3 **attested** rows + `<N` distinct families — claimed-only monocultures never refuse. |

---

## CONFIDENCE

**0.88** — dual-backend write gate + pure-core tests + explicit ROADMAP claims + grep-proven absence of D3-031 and production `model_family_attest` stamp writers.

| Factor | Δ |
|---|---|
| Integration tests `tests/decorrelation_enforce_s2{,_pg}.rs` pin Refuse path | + |
| `evaluate_write_quorum` / `decorrelation_write_action` pure + unit-tested | + |
| Probe still sets `enforce_degraded_to_advisory = true` (v0.8 wording) | + |
| No production stamp of reflection metadata with `loader_observed` (only table TOFU + tests) | − (large) |
| ROADMAP §24 still frames full enforce as v1.0; §25.3 P1 has D3-021 partial | mixed |

---

## SHIPPED

1. **Visibility probe (#1764 / RQ-11)** — `run_decorrelation_probe`: CLAIMED producer dominance (`model_family` → nested → `agent_id` → `source`), threshold default 0.8, floor 3, `CLAIMED_NOT_ATTESTED_CAVEAT`, curator-cycle wiring, scan-cap honesty, SQLite↔PG parity.
2. **S1 model-attestation substrate (#1870 / D3-012)** — schema v78 `model_attestations` TOFU table; `loader_observed` + `operator_signed` levels; `family_of` conservative normalizer; `family_row_exists` / `attested_family_of` forgery gate (stamp without row → CLAIMED); caller-mutation **downgrade** of `loader_observed` → `claimed` on update; CLI `ai-memory model-attest`.
3. **S2 write-time quorum pure core (#1767 / D3-021 partial)** — `evaluate_write_quorum` over **ATTESTED families only**; default `quorum_n=3` (`AI_MEMORY_REFLECT_DECORRELATION_QUORUM_N`, floor clamp 2); outcomes `MeetsQuorum` / `AttestedMonoculture` / `InsufficientAttested`.
4. **Write-gate wiring (both backends)** — `run_decorrelation_write_gate` (sqlite `reflect.rs`) + `decorrelation_write_gate_pg`; mode `off` early-return (byte-identical); `advisory` WARN; `enforce` → `WriteGateAction::Refuse` + audit event + `ReflectError::DecorrelationRefused`.
5. **Anti-theater rules** — enforce refuses **only** on evidence-backed attested monoculture; claimed-only / below-floor → Advise, never Refuse; unattested incoming contributes nothing to distinct count.
6. **Env surface** — `AI_MEMORY_REFLECT_DECORRELATION_MODE` (`off`/`advisory`/`enforce`, default **off**); `…_DOMINANCE_THRESHOLD` (0.8); `…_QUORUM_N` (3).
7. **RQGM correctly external** — no `rqgm` / epoch_manifest / red-queen in `src/` (L3 sibling posture preserved for §2.6 separation).

---

## GAPS

| ID | Gap | Severity for §2.6 |
|---|---|---|
| **G1** | **Default mode OFF** — property held only if operator opts in | High |
| **G2** | **No production reflection stamp** of `model_family` + `model_family_attest=loader_observed` on substrate-authored reflects — only `capture_loader_attestation` fills the **table**; gate predicate needs **per-row metadata**. Without stamps, corpora stay `InsufficientAttested` forever → enforce never fires in the field | **Critical** |
| **G3** | **Visibility-probe enforce still inert** (`enforce_degraded_to_advisory`; stale “v0.8.0 INERT” WARN) — dual story confuses claims | Medium |
| **G4** | **D3-031 consolidation-time gate missing** — shared corpus re-correlates regardless of write-time family diversity (ROADMAP §5 explicit) | High |
| **G5** | **D3-060** enforcement-invariants ship-gate not a default-on structural hold | Medium |
| **G6** | **Loader-only ~40% hard cap** — external / MCP / foreign reflections unattestable at S1 boundary; process-lifetime self-report ≠ per-write crypto provenance | Structural |
| **G7** | **Evasion asymmetry** (documented): keep attested count &lt; floor via unattested writes → never refuse | By design / incompleteness |
| **G8** | **P2 vote-independence = 0%** — substrate cannot distinguish N genuine families from N rubber-stamps (ROADMAP §25.7) | Permanent estimability cliff |
| **G9** | Predicate counts `loader_observed` stamps only; `operator_signed` table rows alone do not make a memory “attested” without matching metadata | Medium |
| **G10** | Enforce-as-default deferred to **v1.0** (code + config comments) | Product posture |

Wave-1 binding: **2.6 = target; not held until attested N≥3 is structural** — still true at v0.9.0 HEAD for default and for end-to-end production reflect stamping.

---

## SCORE 0–100 §2.6

**34 / 100**

| Subscore | Pts | Note |
|---|---|---|
| Ontology alignment (N≥3 attested primary, claimed≠enforced) | 8/10 | Design correct; anti-theater preserved |
| Visibility / advisory floor | 8/10 | Probe shipped; CLAIMED caveat honest |
| Attestation substrate (S1) | 6/20 | Table + normalizer + forgery gate; **~40% loader cap**; no per-write crypto; stamp-on-reflect incomplete |
| Write-time N≥3 enforce | 10/25 | Live under opt-in + test monocultures; default off; field stamp gap |
| Consolidation-time gate | 0/15 | D3-031 absent |
| Default / D3-060 structural hold | 2/10 | Opt-in only |
| P2 independence | 0/10 | Architectural 0% |

Distance narrative: **~⅓ of the bias-displacement *scaffold***; **~0 of the default-held *property***.

---

## KILLER_OBJECTION

**Calling this “decorrelation enforced” launders a gate that (a) is off by default, (b) only refuses when ≥3 rows already carry forgery-gated loader stamps the production reflect path does not appear to mint, and (c) never touches consolidation — so a monoculture still compounds via shared corpus.** The honest claim is: *opt-in write-time refuse of evidence-backed attested monoculture + claimed-only visibility probe*, not separation-of-powers.

---

## TOP_RISK

**False “family-verify ~40%” marketing without the reflection stamp wire:** operators enable `enforce`, see only advisories (`InsufficientAttested`), and believe the substrate is “enforcing decorrelation” while every unstamped reflect proceeds — security theater via **coverage hole**, not via CLAIMED refusal (which code correctly avoids).

Secondary: probe docs still say “enforce INERT at v0.8.0” while write-path enforce is non-inert under env — claim drift.

---

## VOTE: ban claims "decorrelation enforced"

**YES — HARD BAN remains (unanimous with Wave-1 A2 / ROADMAP §25.6 unlock conditions).**

Unlock requires at minimum: D3-012 **end-to-end** (stamp-on-substrate-reflect + table) + D3-021 **default-live or operator-advertised with coverage truth** + D3-031 consolidation + D3-060 invariants — still incomplete. Allowed caveated language only, e.g.:

- “advisory CLAIMED producer-dominance probe”
- “opt-in write-time refuse of *attested* monoculture (N default 3; mode default off)”
- “loader-attested model_family TOFU (~40% hard cap)”

**Banned:** “decorrelation enforced”, “N independent producers”, “bias-displaced by architecture” (as a held claim), “attests model family” without “loader-attested / process-lifetime” qualifier.

---

## RATIONALE

Wave-1 frozen ontology: §2.6 is **CONFIRM AS TARGET LAW; NOT HELD** until N≥3 **attested** families at **write-time and consolidation-time**, with enforce-on-CLAIMED forbidden as theater. Code audit shows v0.9.0 advanced the **keystone and pure core** (S1 table, S2 pure quorum, dual-backend chokepoint, signed refuse event) and correctly refused to refuse on claimed-only evidence. That is engineering progress, not property attainment.

- **Enforce inert?** Not a single boolean: probe yes-inert; write-gate no-when-opted-in; default yes-inert.
- **~40% cap?** Real structural limit of loader-only observation; ROADMAP §25.6 and `model_family.rs` / `model_attest.rs` / curator capture comments agree.
- **N≥3 live?** Default `quorum_n=3` exists; liveness of the *property* requires mode activation **and** attested row density the stamp path does not yet guarantee in production.

Score **34** places §2.6 in “scaffold, not guarantee” — consistent with moonshot honesty: *necessary-but-not-sufficient integrity substructure when attested; not held as default architecture.*

---

*W2-A2 complete. Absolute path: `/Users/fate/Downloads/ai-memory-mcp/.local-runs/perfect-endpoint-assessment/waves/w2-a2-decorrelation.md`*
