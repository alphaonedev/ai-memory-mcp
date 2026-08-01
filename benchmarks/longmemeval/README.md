# LongMemEval Benchmark

Evaluates ai-memory's recall engine against the [LongMemEval](https://github.com/xiaowu0162/LongMemEval) dataset (ICLR 2025 -- "LongMemEval: Benchmarking Chat Assistants on Long-Term Interactive Memory"). The benchmark measures whether the correct source session appears in the top K recalled memories for 500 questions across 6 categories.

## Results

### Parallel FTS5 (keyword tier, 10 cores) -- 2.2s, 232 q/s

| Category | R@1 | R@5 | R@10 | R@20 |
|---|---|---|---|---|
| **Overall** | **86.2%** | **97.0%** | **98.2%** | **99.4%** |

### LLM-expanded + parallel FTS5 -- 3.5s recall, 142 q/s

> **Historical row (gemma3:4b).** These are the `gemma3:4b`-expansion
> numbers, retired as the published headline by the
> [#1975](https://github.com/alphaonedev/ai-memory-mcp/issues/1975)
> ruling (2026-07-10). The current-generation published anchor is the
> OpenRouter Gemma-4 run: **97.2% R@5 / 99.6% R@10 / 99.8% R@20**
> (see [results.md](./results.md), row 5).

| Category | R@1 | R@5 | R@10 | R@20 |
|---|---|---|---|---|
| **Overall** | **86.8%** | **97.8%** | **99.0%** | **99.8%** |
| knowledge-update | -- | 100.0% | -- | 100.0% |
| multi-session | -- | 97.7% | -- | 100.0% |
| single-session-assistant | -- | 100.0% | -- | 100.0% |
| single-session-preference | -- | 93.3% | -- | 100.0% |
| single-session-user | -- | 98.6% | -- | 100.0% |
| temporal-reasoning | -- | 96.2% | -- | 99.2% |

## Harnesses

Four harnesses are provided, each building on the last:

> **Throughput attributions corrected 2026-08-01 (CERT GATE 2).** This
> table previously shifted every speed figure **up one row** — it credited
> `harness.py` with 57 q/s (which is `harness_fast.py`'s number) and
> `harness_fast.py` with 232 q/s (which is `harness_99.py --no-expand`'s).
> The corrected values below are each cross-checked against the elapsed
> time for the full 500-question run: published q/s == 500 / elapsed.
> `docs/DEVELOPER_GUIDE.md` carried the correct attribution throughout.

| Harness | Strategy | Speed (500 q) | Peak R@5 |
|---|---|---|---|
| `harness.py` | CLI subprocess per operation — **binary-faithful** | **1.2 q/s** (414 s) | 96.4% keyword / 96.8% semantic / 95.8% autonomous |
| `harness_fast.py` | Native Python+SQLite, zero subprocesses — **shadow** | 57 q/s (8.8 s) | 96.2% |
| `harness_blazing.py` | Multi-strategy FTS5 with enhanced titles — **shadow** | -- | ~96% |
| `harness_99.py --no-expand` | Parallel FTS5, 10 cores — **shadow** | 232 q/s (2.2 s) | 97.0% |
| `harness_99.py` | LLM query expansion + parallel FTS5 — **shadow** | 142 q/s (3.5 s) | 97.2% (Gemma 4 anchor; `gemma3:4b` historical 97.8%) |

**Read the Speed column with the harness shape in mind.** `harness.py`'s
1.2 q/s is **subprocess-spawn dominated, not recall dominated** — it forks
a fresh `ai-memory recall` process for every one of the 500 questions. It
is the cost of this harness's shape, not a property of the recall path an
integrator hits: an MCP-stdio or HTTP client pays no per-query process
spawn. Conversely the 232 q/s row is a 10-core parallel Python
reimplementation of scoring that never enters the shipped binary. **Numbers
are comparable only WITHIN a harness, never across** — and only the
`harness.py` row describes the shipped code path.

### harness.py -- Original CLI harness

Shells out to the `ai-memory` binary for every store and recall operation. Faithful end-to-end test of the shipped binary, but subprocess overhead limits throughput.

### harness_fast.py -- Native Python+SQLite

Directly opens the SQLite database and uses FTS5 queries in-process. Eliminates all subprocess overhead. Supports `--parallel` for multi-core recall.

### harness_blazing.py -- Multi-strategy FTS5

Enhances recall by trying multiple FTS5 query formulations (exact phrases, keyword combinations, relaxed matches) and merging results. Also enriches stored titles for better FTS5 hit rates.

### harness_99.py -- LLM query expansion

Uses a local LLM (via Ollama) to expand each query into multiple search variants before running parallel FTS5. Achieves the highest recall at the cost of LLM inference time per query.

## Metrics

**R@K (Recall at K)**: For each question, check whether the ground-truth session ID appears among the top K recalled memories. The score is the fraction of questions where it does. Higher K is more lenient -- R@5 means "correct answer in the top 5 results."

The six question categories test different memory capabilities:

- **single-session-user** -- facts stated by the user in a single session
- **single-session-assistant** -- facts stated by the assistant in a single session
- **single-session-preference** -- user preferences expressed in a single session
- **multi-session** -- information that spans multiple sessions
- **temporal-reasoning** -- queries requiring awareness of when events occurred
- **knowledge-update** -- information that was corrected or updated over time

## Replication

### Prerequisites

```bash
# Clone the dataset
git clone https://github.com/xiaowu0162/LongMemEval /tmp/LongMemEval

# Build ai-memory (only needed for harness.py)
cd /path/to/ai-memory-mcp
cargo build --release

# Install Python dependencies
pip install tabulate
```

For `harness_99.py`, you also need [Ollama](https://ollama.com) running locally with a model available (e.g. `ollama pull llama3`).

### Running each configuration

```bash
# Original CLI harness (keyword tier)
python harness.py --dataset-path /tmp/LongMemEval --variant S --tier keyword

# Original CLI harness (all tiers comparison)
python harness.py --dataset-path /tmp/LongMemEval --variant S --all-tiers

# Fast native harness (single-threaded)
python harness_fast.py --dataset-path /tmp/LongMemEval --variant S

# Fast native harness (parallel, 10 cores -- reproduces 232 q/s result)
python harness_fast.py --dataset-path /tmp/LongMemEval --variant S --parallel

# Blazing multi-strategy FTS5
python harness_blazing.py --dataset-path /tmp/LongMemEval --variant S

# LLM-expanded queries (historical gemma3:4b 97.8% row; current anchor is results.md row 5 per #1975)
python harness_99.py --dataset-path /tmp/LongMemEval --variant S
```

### Common options

```bash
# Custom K values
python harness_fast.py --dataset-path /tmp/LongMemEval --variant S -k 1 -k 5 -k 10 -k 20

# Verbose per-question progress
python harness_fast.py --dataset-path /tmp/LongMemEval --variant S --verbose
```

### Output

Results are printed as tables to stdout and saved as CSV files in `results/`.
