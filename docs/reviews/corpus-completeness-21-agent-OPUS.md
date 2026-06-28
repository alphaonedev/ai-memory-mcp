# Corpus-Completeness Pass: Did TRACT Drop Anything Valuable Before Becoming the Measuring Stick?

> **21-agent (3×7) council** — an independent corpus diff of the four pre-TRACT clean-slate design documents against the definitive **TRACT** design, then a re-assessment against ai-memory `release/v0.8.0` and the current §26 ROADMAP. CodeGraph-anchored (846 files / 27,062 nodes). Sibling to the RQGM/Red-Queen and the TRACT-vs-v0.8.0 adjudication councils — this pass audits the *input* to the v0.8.0 assessment (was the measuring stick faithful?) rather than the substrate.

## Why this pass exists

The v0.8.0 assessment used **TRACT alone** as its measuring stick — not the entire corpus of clean-slate design docs that preceded it (`PERFECT-ENDPOINT-MEMORY-21-AGENT`, `eternal-endpoint-ai-memory-substrate`, `GROK-FINAL-ENDPOINT-MEMORY`, `endpoint-ai-memory-grok-vs-opus-21-agent-synthesis`). TRACT was the convergent synthesis of that corpus, so assessing it is *transitively* assessing what survived — but anything the distillation dropped before TRACT became the stick would never have been measured against the code. This pass closes that seam.

## Executive verdict

**TRACT is a faithful ~97% superset of the corpus. No constitutional or concept-level idea was lost. Assessing TRACT-only did NOT corrupt the v0.8.0 verdict — it only under-counted five gaps.** The gap count rises **27 → 32**; the scorecard (**10 of 14 CORRECT**) and two-axis grade (**A− / C+**) are **unchanged**. The "correct-now" verdict survives intact.

The one material cost of using TRACT as the sole stick was **enumeration attrition**: TRACT distilled several operational/security checklists from the corpus into prose, and prose-level distillation silently dropped five testable obligations — recovered here as gaps **G28–G32**, **two of which are codegraph-verified live v0.8.0 defects**.

## Method

- **Inputs (4 pre-TRACT docs)** diffed idea-by-idea against the definitive TRACT design.
- **Wave 1 (diff):** extract every distinctive idea per doc + a cross-corpus thematic map + an adversarial silent-drop hunt + an infinity/OSS-clause audit. Each idea tagged **CARRIED / EXTENDED / DROPPED-CORRECTLY / DROPPED-VALUABLE**.
- **Wave 2 (triage + verify):** each DROPPED-VALUABLE item re-tested against v0.8.0 via CodeGraph — is it a live defect, an enrichment of an existing gap, or already covered?
- **Wave 3 (re-assess + synthesize):** re-verify the defects, re-assess the new gaps against the current §26 ROADMAP, fold the delta into the canonical docs.
- **Falsifiability rule:** a finding counts as "loss" only if a distinctive idea has *no* surviving expression in TRACT. Rewording, consolidation, and honest demotion to an OPEN problem do **not** count as loss.

## Faithful-superset matrix (15 themes)

| Theme | Disposition in TRACT |
|-------|----------------------|
| Identity / succession | **EXTENDED** (net-new succession + dead-man + contestation window) |
| Attestation / witness | **EXTENDED** (`witness_level` ladder) |
| Recall purity / lifecycle | **EXTENDED** (CONSUME two-tier seam closed) |
| Bootstrap / cold-start | **EXTENDED** (genesis trust block) |
| License / funding | **EXTENDED** (AGPL→MPL ruling + foundation-funds-bytes-never-infra) |
| Crypto spine | **EXTENDED** (crypto-spine caveat made explicit) |
| Decorrelation | **EXTENDED** (structural ∧ behavioral `min()`) |
| Tone / governance | **EXTENDED** (self-grandeur ban codified) |
| Recall / ranking | PRESERVED |
| Federation / quorum | PRESERVED (durability-as-tier-not-gate) |
| Schema / migration | PRESERVED (immortality over-claims honestly demoted to OPEN) |
| Erasure / right-to-forget | DISTILLED → recovered (**G30**) |
| Secrets / ingestion safety | DISTILLED → recovered (**G29**) |
| Operational enumerations | DISTILLED → recovered (**G28 / G31 / G32**) |
| Self-grade / killer-risk table | **DROPPED** (a TRACT self-contradiction — see below) |

**8 of 15 themes were EXTENDED with net-new resolutions; 0 lost a constitutional idea.**

## The "for infinity / OSS to infinity" clause

The corpus's longevity/permanence clause — the operator's original "world-class epic value … for infinity … 100% OSS to infinity" requirement — is **substantively honored in TRACT**. Only the *grandeur language* was cut, never the *mechanisms*:

- **Kept and sharpened:** Reference-Profile-as-conformance-vectors (longevity becomes *testable*, not aspirational); AGPL→MPL relicensing; foundation-funds-bytes-never-infra; CC0 format + patent non-aggression + no-CLA + N-of-M cross-jurisdiction governance + weekend-reimplement anti-capture test.
- **Honestly demoted, not silently dropped:** the sub-linear immortal index and migration-proof re-encode *over-claims* were moved to OPEN problems rather than asserted as solved — the correct engineering posture, counted as integrity, not loss.

Verdict: the immortality/OSS intent survives in **mechanism** form; only the unfalsifiable rhetoric was removed — consistent with the very self-grandeur ban TRACT itself adopted.

## Recovered gaps (G28–G32)

| Gap | Theme | Status | Note |
|-----|-------|--------|------|
| **G29** | Secrets ingestion screening | **DEFECT (codegraph-verified)** · P1 · UNTRACKED | No write-path screen; a pasted key/token persists, is FTS-indexed, embedded, federated, and surfaced verbatim |
| **G30** | Erasure data-remanence | **DEFECT (codegraph-verified)** · P1 · UNTRACKED | `forget` leaves content in the push-DLQ + the HNSW vector in RAM + emits no tombstone → re-sync resurrection |
| **G28** | Forbidden-export-class taxonomy | P2 · UNTRACKED | forensic bundle + federation export the full row (incl. biometric embeddings, key material, policy rules) |
| **G31** | Latency-SLO degrade actuator | P2 · UNTRACKED | degrades only on embedder *failure*, never on a latency *budget* (fills Pillar 14) |
| **G32** | Cross-mind learning (MPC/FHE/DP) | P2 · **TRACKED** §11.7 / FED-RQ-AGG #1707 — horizon, advertise-banned | the constructive twin of "not a hive mind": a shared *statistic*, never a shared corpus |

Plus **enrichments** (not new gaps) to existing **G1** (salience-poisoning framing + skip-predicate), **G5** (split-view/equivocation detection = the witness tier), **G6** (typed forgetting operators EXPIRE/EVICT/REDACT/DISTILL), **G10** (capability-token blast-radius/co-signer fields + the namespace-isolation bridge — *namespace is a tag, not a trust boundary at v0.8.0; cross-namespace recall is unrestricted*).

### The two live defects, in one line each
- **G29:** `validate.rs` checks shape/length only (`src/validate.rs:917`) — zero credential/entropy screening on caller content; it leaks through recall, forensic export (`src/forensic/bundle.rs:1114`), and federation push.
- **G30:** bulk `db::forget` (`src/storage/mod.rs:2852`) purges the row + FTS + embedding columns + `recall_observations`/`memory_links` cascades, but leaves (a) the push-DLQ `payload_json` cleartext (non-FK `memory_id`, `migrations/sqlite/0041_*.sql:35-37`), (b) no peer-deletion/tombstone (`federation_receive.rs:446-450` "no tombstone row" → re-sync resurrection), (c) the HNSW vector resident in RAM (never calls `idx.remove`).

## TRACT self-consistency note

TRACT's commandment 13 / §16 mandates a **falsifiable self-grade** and the synthesis mandated a **ranked killer-risk → mitigation table** — yet the final TRACT ships **neither**. This is a self-contradiction *internal to TRACT*, independent of the corpus diff (the corpus supplied the template TRACT failed to apply to itself). Both are recovered into TRACT §16 (a self-grade-of-the-design + a deployment killer-risk register promoting COMPLEXITY-TAX and CATEGORY-ERROR to first-class ranked rows) so the measuring stick stops under-representing its own source.

## Bottom line — did assessing TRACT-only cost us anything?

**Almost nothing constitutional; a measurable but bounded enumeration cost.**

- **Did NOT cost:** any distinctive idea, any constitutional principle, the scorecard, the grade, or the "correct-now" verdict. TRACT-as-sole-stick was validated — a ~97% faithful superset, so the assessment built on it inherits **no concept-level blind spot**.
- **DID cost:** five under-counted gaps (27→32), two of which are *live v0.8.0 defects* (G29 secrets-screening, G30 erasure remanence) that the corpus would have surfaced and TRACT's distillation masked. These are now filed, anchored, and slotted into Phase B (§24 prime-directive: fix, don't defer).

**Net:** using TRACT as the sole measuring stick was *safe at the concept level and slightly lossy at the enumeration level.* The fix is additive — file G28–G32, apply the G1/G5/G6/G10 enrichments, and have TRACT publish its own self-grade — not a re-grade. **The v0.8.0 assessment stands; we now have true 100% corpus coverage.**

---

*Authored by Claude Opus 4.8 (1M context) as a 21-agent (3×7) corpus-completeness council diffing the pre-TRACT design corpus against the definitive TRACT design and re-assessing against ai-memory `release/v0.8.0` + the §26 ROADMAP. CodeGraph-anchored; the two recovered defects (G29, G30) carry fresh-probe `file:line` evidence. Canonical companions: [`../design/TRACT-v0.8.0-CORRECT-NOW-CANONICAL-opus.md`](../design/TRACT-v0.8.0-CORRECT-NOW-CANONICAL-opus.md), [`../design/TRACT-v0.8.0-DEVELOPMENT-GAPS-CANONICAL-opus.md`](../design/TRACT-v0.8.0-DEVELOPMENT-GAPS-CANONICAL-opus.md). Tracked in ROADMAP.md §26.6.*
