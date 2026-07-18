#!/usr/bin/env python3
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""#1987 — build a self-describing `bench --baseline` file from N `bench --json`
runs by taking the per-operation MEDIAN p95 (stable across shared-runner noise).

Usage: median_baseline.py <binary_rev> <run1.json> [run2.json ...] > baseline.json

The output is a superset of what `ai_memory::bench::load_baseline` consumes
(`{results: [{operation, measured_p95_ms}, ...]}`); the extra top-level fields
(`runner_class`, `bootstrap`, `generated_at_binary_rev`, ...) are self-describing
metadata that `load_baseline` ignores. `runner_class` defaults to the
`RUNNER_BASELINE_CLASS` env (set to `ubuntu-latest` by the workflow) and
`bootstrap` is `false` — this is a REAL, CI-runner baseline, unlike the committed
dev bootstrap.
"""
import json
import os
import statistics
import sys


def main() -> int:
    if len(sys.argv) < 3:
        sys.stderr.write("usage: median_baseline.py <binary_rev> <run1.json> [run2.json ...]\n")
        return 2
    rev = sys.argv[1]
    runs = [json.load(open(p)) for p in sys.argv[2:]]

    # Collect p95 samples per operation across the N runs.
    p95_samples: dict[str, list[float]] = {}
    label: dict[str, str] = {}
    meta = runs[0]
    for run in runs:
        for r in run["results"]:
            op = r["operation"]
            p95_samples.setdefault(op, []).append(float(r["measured_p95_ms"]))
            label[op] = r.get("label", op)

    results = [
        {
            "operation": op,
            "label": label[op],
            "measured_p95_ms": round(statistics.median(samples), 6),
        }
        for op, samples in sorted(p95_samples.items())
    ]

    out = {
        "_schema": "ai-memory bench --json baseline (#1987)",
        "_note": (
            "Median-of-%d baseline captured on the CI runner class. Refresh every "
            "minor release (a baseline older than one minor should be regenerated)." % len(runs)
        ),
        "bootstrap": False,
        "runner_class": os.environ.get("RUNNER_BASELINE_CLASS", "ubuntu-latest"),
        "generated_at_binary_rev": rev,
        "regression_threshold_pct_default": 50,
        "runs": len(runs),
        "iterations": meta.get("iterations"),
        "warmup": meta.get("warmup"),
        "scale": meta.get("scale"),
        "results": results,
    }
    sys.stdout.write(json.dumps(out, indent=2) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
