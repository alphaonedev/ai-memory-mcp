# LongMemEval Benchmark

Evaluates ai-memory's recall engine against the [LongMemEval](https://github.com/xiaowu0162/LongMemEval) dataset (ICLR 2025).

## Setup

```bash
# Clone the dataset
git clone https://github.com/xiaowu0162/LongMemEval /tmp/LongMemEval

# Build ai-memory
cd /path/to/ai-memory-mcp
cargo build --release

# Install Python dependency
pip install tabulate
```

## Run

```bash
# Single tier
python harness.py --dataset-path /tmp/LongMemEval --variant S --tier keyword

# All tiers comparison
python harness.py --dataset-path /tmp/LongMemEval --variant S --all-tiers

# Custom K values
python harness.py --dataset-path /tmp/LongMemEval --variant S --tier semantic -k 1 -k 5 -k 10 -k 20

# Verbose (per-question progress)
python harness.py --dataset-path /tmp/LongMemEval --variant S --tier keyword --verbose
```

## Metrics

- **R@K (Recall at K)**: Whether the ground truth session appears in the top K recalled memories
- Results are broken down by question category:
  - `single-session-user` / `single-session-assistant` / `single-session-preference` — information extraction
  - `multi-session` — cross-session reasoning
  - `temporal-reasoning` — time-aware queries
  - `knowledge-update` — handling updated information
  - `abstention` — correctly returning no result when no answer exists

## Output

Results are printed as tables and saved as CSV files in `results/`.
