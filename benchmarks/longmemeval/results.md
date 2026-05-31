# LongMemEval Results — v0.7.0 Full-500 Disclosure

> Methodology and reproducibility pins live in
> [`methodology.md`](./methodology.md). See [`README.md`](./README.md) for
> harness descriptions. Raw per-run CSVs + logs for the v0.7.0 runs below
> are captured under `.local-runs/bench-v070-20260531-151813/` for audit
> provenance (results-keyword / results-semantic / results-autonomous /
> expand-openrouter).

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
| 1 | keyword-baseline | `keyword` | — (FTS5 only) | — | no | 86.6% | 96.4% | 98.4% | 99.4% |
| 2 | semantic | `semantic` | MiniLM-L6 384d (local Candle) | off | no | **88.2%** | 96.8% | 99.0% | 99.8% |
| 3 | autonomous | `autonomous` | nomic-embed 768d (Ollama) | ms-marco MiniLM cross-encoder | no | 86.2% | 95.8% | 98.2% | 99.2% |

All three: full 500 questions, R@K = fraction where the correct source
session id appears in the top-K returned memories. Run 2026-05-31 against
the installed v0.7.0 binary (schema v53).

### Shadow harness (`harness_99.py`, LLM query-expansion + FTS5)

| # | Variant | Recall path | LLM expand backend | R@1 | R@5 | R@10 | R@20 |
|--:|---|---|---|---:|---:|---:|---:|
| 4 | keyword + expansion (published anchor) | shadow FTS5 | Ollama `gemma3:4b` | 86.8% | **97.8%** | 99.0% | 99.8% |
| 5 | keyword + expansion (OpenRouter reproduction) | shadow FTS5 | OpenRouter `google/gemma-4-26b-a4b-it` | 86.0% | **97.2%** | 99.6% | 99.8% |

Row 5 was run 2026-05-31 (500 questions, 0 expansion failures, 57,501
OpenRouter tokens, 138.8s expansion + 1.7s recall). It reproduces the
published anchor **within 0.6pp R@5** using a cloud LLM backend in place
of local Ollama — confirming the expansion methodology is LLM-portable and
the 97.8% headline holds with an entirely Ollama-free configuration.

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

### keyword (`harness.py`)

| Category | R@1 | R@5 | R@10 | R@20 |
|---|---:|---:|---:|---:|
| **Overall** | **86.6%** | **96.4%** | **98.4%** | **99.4%** |
| knowledge-update | 96.2% | 100.0% | 100.0% | 100.0% |
| multi-session | 86.5% | 96.2% | 97.7% | 99.2% |
| single-session-assistant | 100.0% | 100.0% | 100.0% | 100.0% |
| single-session-preference | 50.0% | 90.0% | 96.7% | 100.0% |
| single-session-user | 90.0% | 98.6% | 100.0% | 100.0% |
| temporal-reasoning | 82.0% | 93.2% | 97.0% | 98.5% |

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
