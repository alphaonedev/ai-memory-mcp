---
layout: doc
---
# Reproducible native graph latency baseline

The tracked producer `scripts/evidence/graph_baseline.py` builds and addresses
`benches/graph_native_baseline.rs`, emits all raw samples, computes independent
nearest-rank p50/p95/p99, and validates a repository evidence bundle. Its entry
in `scripts/evidence/producer-map.json` owns every published figure. This is a
descriptive baseline, not an SLA or claim that either engine is always faster.
The bundle therefore uses `NOT_APPLICABLE` for an SLA verdict and explicitly
labels its oracle as descriptive measurement.

With the E5 native admin environment, explicit own CARGO_TARGET_DIR/TMPDIR,
CACHEDIR.TAG, jobs2, and no other heavy local work:

```sh
PYTHONDONTWRITEBYTECODE=1 timeout 60 python3 -m unittest discover \
  -s scripts/evidence -p test_graph_baseline.py -v
timeout 180 bash scripts/check-evidence-bundle.sh --self-test
timeout 9000 python3 scripts/evidence/graph_baseline.py \
  --psql /absolute/path/to/psql
```

The unconditional required-contexts job in `c8-precheck.yml` runs the Python
producer controls on every covered PR. It requires at least eight listed and
executed tests, with no failures, skips or expected failures. This certifies
the producer's synthetic controls; the native benchmark remains a separately
measured run on the final source and native cluster.

The tree must be clean and committed. First, E1 conformance must pass on that
source in a separate throwaway database. Destructive relationship controls must also pass in isolated throwaway databases;
the producer requires both named tests, listed/executed equality and no skips.
Next, the optimized `graph-bench`
profile builds the benchmark (opt-level3, LTO off, 16 codegen units, debug0).
This profile deliberately avoids fat-LTO memory pressure; it is not the
shipping release profile. It inherits release's `strip=true`; with `debug=0`
this removes DWARF/source-line and symbolized-backtrace detail. Diagnostic
rebuilds may preserve symbols, but have a different executable/profile and
cannot replace the measured run or supply its latency figures. Compare later
runs using this same profile.
All stages use PostgreSQL18.6/AGE1.8.0/vector0.8.6 and verify-full, including
E5's certificate-hostname rejection control. All databases are dropped and
their absence checked; no fixture is placed in the operator's database.

The benchmark declares its compiled source SHA and waits. The producer checks
that SHA and PID, independently hashes its live executable via the repository
process-binding helper, matches the Cargo artifact file hash, and only then
starts work. The executable is hashed again afterwards. The bundle includes
source/tree commits, both executable hashes, run ID and SHA256 of raw.json.
Host metadata includes the hostname; also name that host in the PR body alongside
the measured profile and percentiles.
The readiness deadline is30 seconds for the complete line, including a child
that writes only a partial line. The measurement phase has a1300-second
deadline, and the shared32MiB diagnostic-output budget bounds both phases
together. Exceeding either bound fails the producer; it does not truncate a
sample set into a publishable result. Cleanup closes pipes before terminating
the owned process group, tolerates broken-pipe errors, and sends a final kill
even when the leader has already exited. It never targets unrelated groups.
The process tests use real synthetic children and stub executable hashing;
they prove the lifecycle boundaries, while the native producer run must still
prove actual source/PID/executable binding and all measurement scenarios.

Raw samples and sanitized logs remain in a fresh UUID directory under
`.local-runs/graph-baseline/`; no DSN/password is persisted.

| Operation | Engine | Rows per measured operation |
|---|---|---|
| kg_query, depth1 | Direct relational / direct AGE | 4 |
| kg_query, depth2 | Direct relational / direct AGE | 20 |
| kg_query, depth3 | Direct relational / direct AGE | 84 |
| kg_timeline | Direct relational / direct AGE | 4 |
| Projection drain | Actual AGE outbox reconciler | 64 new leaf projections |

Each run uses a deterministic four-child directed tree: 1,024 memories and
1,023 links, under one synthetic namespace. SQL cardinalities and all1,024 AGE vertices plus1,023 AGE relationships are
checked independently. A missing deep edge outside the measured read prefix
must refuse the baseline. Direct engine methods prevent a hidden fallback
from supplying an AGE timing. Query results are below the existing 200-row cap;
this baseline measures depth/corpus traversal, not cap-pressure behavior.

Every scenario discards10 warm-ups and retains200 sequential wall-clock
microsecond samples, measured around the complete awaited store operation.
Fixture setup, cardinality assertions and JSON serialization are outside the
timer. No concurrency or WAN latency is added. All read scenarios precede drain
measurements. Each drain preparation removes exactly64 leaf projections and
re-enqueues the existing64 durable links outside timing. The measured call
must report64 successes; independent post-call SQL and AGE checks require
zero pending rows,64 restored vertices and64 restored incoming relationships.
A deliberately removed relationship with its vertices intact must fail this check. The next sample resets those same
leaves, keeping corpus size stationary instead of measuring a growing graph.

For each operation/engine, sort its200 raw samples and select rank
`ceil(percentile * n / 100)`: p50 rank100, p95 rank190, p99 rank198.
Never average per-run p99s. The producer refuses missing/duplicate scenarios,
wrong row counts, nonpositive/noninteger samples or an incomplete sample set.
No fabricated empty-result timings are accepted.

These are warm, single-client client-side latencies on a shared native host.
They include database round trips, decoding and hydration; they exclude model
inference and E3's scheduling sleep. CPU contention, filesystem/database cache,
thermal state and other users can affect results. Store the host/profile/run
metadata and raw samples with the published percentiles; do not compare these
numbers with another profile or infer a capacity/concurrency limit from them.
