---
layout: doc
---
# Raw evidence — capacity envelope (#2921)

Machine-readable output from the runs published in
[`../capacity-envelope-2921.md`](../capacity-envelope-2921.html). Every
number in that document traces to a file here.

Staged by `scripts/bench/collect-evidence.sh`, which is a **filter, not a
copy**: absolute home paths are rewritten to `<scratch>`, credential-shaped
content causes the publish to be **refused outright** (never silently
redacted), only an allowlist of artifact shapes is copied, and each daemon
log is capped head+tail with the elision announced inline.

## `mesh/` — single-host N-peer federation ramp

| file | contents |
|---|---|
| `rung-N<N>.json` | the full rung record: per-write HTTP codes + latency percentiles, per-node convergence times, **final per-node row counts**, every node's federation counters, three `docker stats` samples |
| `summary.json` | the five-rung roll-up |
| `N<N>_mesh-manifest.json`, `N<N>_gen-mesh.json` | the exact topology, quorum width, catch-up interval, quota ceiling and image the rung ran with |
| `N<N>_am2921-node-01.log`, `…-node-02.log` | container logs for the write-entry node and its first peer. The head carries the boot banner — the fail-closed federation posture, the resolved quorum, the enabled DLQ replay worker |
| `host-facts.json` | CPU / RAM / storage of the measurement host |

**Read `rung-N50.json` for the honest-instrument example**:
`dlq_depth_total` is `null` with `metrics_scrape_failures: 9`, because nine
of fifty `/metrics` sweeps failed after retries and an unavailable metric is
not a zero.

## `ops/` — single-node throughput producers

| file | contents |
|---|---|
| `ops-memory_store-attested.json` | the shipped-default write path (per-write Ed25519 attestation required) |
| `ops-memory_store-unsigned.json` | the unsigned control — **not a supported posture**; exists only to bound the verification cost |
| `ops-memory_recall.json` | keyword-tier read path over a 5,000-row seeded corpus |
| `ops-sync_push.json` | end-to-end federated write (1 peer, `W=2`), with the receiver-side row-count confirmation under `meta.receiver` |
| `usl-*.txt` | verbatim `infra/pillar4-envelope/usl-fit.py` output per series, including its own `MEASURED` / `ESTIMATED-not-MEASURED` labelling |
| `host-facts.json` | as above |

Each results JSON carries, in `meta`: the producing argv, the host facts,
the tier and backend, the attestation posture, and the **instrument
calibration** (the driver's own ceiling measured against `/api/v1/health`).
A figure approaching that calibration would be instrument-bound; none is.

## What is deliberately NOT here

Node key directories, SQLite databases, the generated compose files (they
embed the run's API key), and the pre-signed body pools. None of them is
evidence and all of them are either secret-bearing or large.
