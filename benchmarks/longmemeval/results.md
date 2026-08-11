# LongMemEval Results — Binary-Faithful Full-500 Disclosure

> Methodology and reproducibility pins live in
> [`methodology.md`](./methodology.md). See [`README.md`](./README.md) for
> harness descriptions. Raw per-run CSVs + logs for the v0.7.0 runs below
> are captured under `.local-runs/bench-v070-20260531-151813/` for audit
> provenance (results-keyword / results-semantic / results-autonomous /
> expand-openrouter).
>
> **v1.0.0 keyword re-measurement (2026-08-11, #2888).** The
> binary-faithful **keyword** row below was RE-MEASURED on the v1.0.0
> release binary (`ai-memory 1.0.0`, commit `811ce105`) via `harness.py`
> (one real `ai-memory recall` subprocess per question), full 500
> questions — to satisfy the bet-the-farm rule that a figure PUBLISHED for
> v1.0.0 must be MEASURED on v1.0.0 (the earlier row was measured on the
> v0.7.0 binary, 2026-05-31). The run set `AI_MEMORY_SECRET_SCREEN_MODE=off`
> + `AI_MEMORY_NO_CONFIG=1` to reproduce the v0.7.0 INGEST baseline:
> secret-screening is a v0.8.1 WRITE-path control (env #95) that did not
> exist at v0.7.0 and is orthogonal to keyword recall QUALITY; left at its
> `refuse` default it drops LongMemEval-S sessions carrying synthetic
> credential-like strings and measures the screen, not the FTS5 ranker.
> The 18 sessions still refused are the pre-existing `validate_content`
> control-char rejections (`is_clean_string`, `src/validate.rs:148`) that
> v0.7.0 dropped identically — the corpus is apples-to-apples. Result: R@1
> **86.6%** (433/500), R@5 **96.4%** (482/500), R@10 **98.4%** (492/500),
> R@20 **99.6%** (498/500) — byte-identical to the 2026-05-31 v0.7.0
> keyword figures at R@1/R@5/R@10 and at EVERY per-category cell EXCEPT
> `temporal-reasoning` R@20, where the v1.0.0 binary retrieves ONE more
> question at rank ≤20 (131/133 → 132/133), lifting Overall R@20 from
> 99.4% (497/500) to 99.6% (498/500). The `semantic` and `autonomous`
> rows remain the 2026-05-31 v0.7.0 measurements — the #2888 pass re-ran
> the keyword tier only (the LLM-independent, load-bearing floor). Raw log
> + per-category CSV: `.local-runs/2888-bench/`
> (`keyword-v1.0.0-screenoff.log`, `results_keyword.csv`).

This document publishes ai-memory's recall numbers on **LongMemEval-S
(cleaned), 500 questions**. The v0.6.3.1 matrix carried `PENDING-RUN`
cells; this revision fills them with **real, measured v0.7.0 runs** and
labels each row with the harness that produced it, because two harnesses
with different fidelity are in play and conflating them would be
dishonest.

---

## Two harnesses — read this first

| Harness | What it drives | Fidelity | Used for |
|---|---|---|---|
| `harness.py` | spawns the real `ai-memory recall` subprocess per question | **binary-faithful** (the shipped recall pipeline: embed + HNSW ANN + FTS5 fusion + optional cross-encoder rerank) | keyword / semantic / autonomous rows |
| `harness_99.py` | in-process SQLite FTS5 with a hand-written BM25-ish scoring SQL + threaded LLM query-expansion | **shadow** (re-implements scoring outside the binary) | the published 97.8% anchor + the OpenRouter-expansion reproduction |

The shadow harness is faster and was how the original 97.8% R@5 headline
was produced, but it is **not** the shipped code path. The binary-faithful
rows are the stricter, more honest measure of what an operator actually
gets from `ai-memory recall`. Numbers are only comparable **within** a
harness, never across.

---

## Headline matrix

### Binary-faithful (`harness.py`, drives the shipped binary)

| # | Variant | Tier | Embedder | Reranker | LLM expand | R@1 | R@5 | R@10 | R@20 |
|--:|---|---|---|---|---|---:|---:|---:|---:|
| 1 | keyword-baseline | `keyword` | — (FTS5 only) | — | no | 86.6% | 96.4% | 98.4% | 99.6% |
| 2 | semantic | `semantic` | MiniLM-L6 384d (local Candle) | off | no | **88.2%** | 96.8% | 99.0% | 99.8% |
| 3 | autonomous | `autonomous` | nomic-embed 768d (Ollama) | ms-marco MiniLM cross-encoder | no | 86.2% | 95.8% | 98.2% | 99.2% |

R@K = fraction where the correct source session id appears in the top-K
returned memories, full 500 questions. **Row 1 (keyword) was re-measured
on the v1.0.0 release binary (`811ce105`) on 2026-08-11 (#2888)** — see
the v1.0.0 re-measurement note at the top of this file for the exact
protocol and the single per-category delta vs the v0.7.0 run. Rows 2
(semantic) and 3 (autonomous) are the 2026-05-31 v0.7.0 runs (schema v53),
not re-run in the keyword-tier #2888 pass.

### Shadow harness (`harness_99.py`, LLM query-expansion + FTS5)

| # | Variant | Recall path | LLM expand backend | R@1 | R@5 | R@10 | R@20 |
|--:|---|---|---|---:|---:|---:|---:|
| 4 | keyword + expansion (compiled-default model, historical headline) | shadow FTS5 | Ollama `gemma3:4b` | 86.8% | 97.8% | 99.0% | 99.8% |
| 5 | keyword + expansion (**current-generation anchor**) | shadow FTS5 | OpenRouter `google/gemma-4-26b-a4b-it` | 86.0% | **97.2%** | 99.6% | 99.8% |

Row 5 was run 2026-05-31 (500 questions, 0 expansion failures, 57,501
OpenRouter tokens, 138.8s expansion + 1.7s recall).

> **Anchor change (2026-07-10, #1975 ruling — 2×5 vote `wf_8ac90aca`).**
> The 97.8% row-4 figure is **retired as the headline**: it was measured
> with `gemma3:4b`, which remains the *compiled* default expansion model
> (`src/config.rs::backend_default_model`) but is no longer what
> Gemma-4-era production deployments run. Row 5 — the measured
> current-generation Gemma-4 number — is promoted to the published
> expansion anchor, venue honestly labeled (cloud API). **No
> local-Ollama Gemma-4 number exists**: the reference host is CPU-only,
> where a valid full-protocol run is infeasible (~1 tok/s; see #1983 for
> the harness-defect post-mortem that a first re-run attempt surfaced —
> thinking-default models silently returned empty expansions, which the
> harness now detects and refuses to publish). A local GPU re-run stays
> reopenable post-v1.0. The keyword-tier numbers are LLM-independent and
> unaffected.

---

## What the numbers say (honest reading)

**1. On LongMemEval-S, the cross-encoder reranker does not help.** The
autonomous tier (embed + rerank, row 3) scores **below** both the semantic
tier (row 2) and the keyword baseline at every K (R@5 95.8% vs 96.8% vs
96.4%). The 0.6×original + 0.4×ce_score blend reorders a candidate set
that FTS5 already ranks well for this lexical-match-dominated dataset, and
the reranker's reordering net-loses a few questions (notably
`single-session-preference` R@5: 90.0% semantic → 83.3% autonomous). This
is the expected "narrow spread" the v0.6.3.1 disclosure predicted, now
measured: **paying for embeddings + rerank buys nothing on this dataset.**

**2. Query expansion is the only lever that beats the FTS5 floor.** The
sole configuration that clears the keyword baseline's R@5 is LLM
query-expansion (rows 4–5: 97.8% / 97.2% vs 96.4% binary-faithful keyword,
+1.4 / +0.8pp). Expansion broadens lexical coverage before recall — which
is exactly where this dataset rewards effort.

**3. The cheapest tier that meets a 96%+ R@5 target is `keyword`.** A
reader budgeting compute should pick `keyword` (no embedding cost, no
Ollama) and add LLM expansion if they want the last point of R@5, rather
than buying `autonomous` for a number that is actually lower here.

> Caveat: LongMemEval-S is lexical-match-heavy. Embedding + rerank wins are
> expected to be larger on paraphrase-heavy / out-of-distribution corpora.
> These rows disclose the LongMemEval-S range honestly; they are not a
> claim about all workloads.

---

## Per-category breakdown — binary-faithful tiers

### keyword (`harness.py`) — v1.0.0 binary, 2026-08-11 (#2888)

Per-category breakdown of the v1.0.0 keyword re-measurement (500 questions,
commit `811ce105`). Identical to the 2026-05-31 v0.7.0 keyword run at every
cell EXCEPT `temporal-reasoning` R@20 (v0.7.0 98.5% = 131/133 → v1.0.0
99.2% = 132/133), which lifts Overall R@20 to 99.6% (498/500).

| Category | R@1 | R@5 | R@10 | R@20 |
|---|---:|---:|---:|---:|
| **Overall** | **86.6%** | **96.4%** | **98.4%** | **99.6%** |
| knowledge-update | 96.2% | 100.0% | 100.0% | 100.0% |
| multi-session | 86.5% | 96.2% | 97.7% | 99.2% |
| single-session-assistant | 100.0% | 100.0% | 100.0% | 100.0% |
| single-session-preference | 50.0% | 90.0% | 96.7% | 100.0% |
| single-session-user | 90.0% | 98.6% | 100.0% | 100.0% |
| temporal-reasoning | 82.0% | 93.2% | 97.0% | 99.2% |

### semantic (`harness.py`)

| Category | R@1 | R@5 | R@10 | R@20 |
|---|---:|---:|---:|---:|
| **Overall** | **88.2%** | **96.8%** | **99.0%** | **99.8%** |
| knowledge-update | 97.4% | 100.0% | 100.0% | 100.0% |
| multi-session | 88.7% | 97.0% | 99.2% | 100.0% |
| single-session-assistant | 100.0% | 100.0% | 100.0% | 100.0% |
| single-session-preference | 50.0% | 90.0% | 100.0% | 100.0% |
| single-session-user | 91.4% | 98.6% | 100.0% | 100.0% |
| temporal-reasoning | 84.2% | 94.0% | 97.0% | 99.2% |

### autonomous (`harness.py`)

| Category | R@1 | R@5 | R@10 | R@20 |
|---|---:|---:|---:|---:|
| **Overall** | **86.2%** | **95.8%** | **98.2%** | **99.2%** |
| knowledge-update | 94.9% | 100.0% | 100.0% | 100.0% |
| multi-session | 87.2% | 96.2% | 98.5% | 99.2% |
| single-session-assistant | 100.0% | 100.0% | 100.0% | 100.0% |
| single-session-preference | 50.0% | 83.3% | 96.7% | 96.7% |
| single-session-user | 88.6% | 98.6% | 100.0% | 100.0% |
| temporal-reasoning | 81.2% | 92.5% | 95.5% | 98.5% |

### keyword + OpenRouter expansion (`harness_99.py`, shadow)

| Category | R@1 | R@5 | R@10 | R@20 |
|---|---:|---:|---:|---:|
| **Overall** | **86.0%** | **97.2%** | **99.6%** | **99.8%** |
| knowledge-update | 93.6% | 100.0% | 100.0% | 100.0% |
| multi-session | 87.2% | 98.5% | 99.2% | 100.0% |
| single-session-assistant | 98.2% | 100.0% | 100.0% | 100.0% |
| single-session-preference | 70.0% | 100.0% | 100.0% | 100.0% |
| single-session-user | 85.7% | 100.0% | 100.0% | 100.0% |
| temporal-reasoning | 78.9% | 91.0% | 99.2% | 99.2% |

---

## Anti-goals reaffirmed

- We do **not** modify recall scoring to chase a higher number. The rows
  disclose the existing range, including the finding that the reranker
  net-loses on this dataset.
- We do **not** present the shadow-harness 97.8% as the binary-faithful
  number — it is explicitly labelled as the shadow path, sitting beside the
  binary-faithful keyword 96.4%.
- We do **not** publish an oracle row. The harness never sees the
  ground-truth session id during recall.
- Raw per-question CSVs + run logs are retained under `.local-runs/` for
  audit; the headline cells are reproducible from them.
