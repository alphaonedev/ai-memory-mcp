# `scripts/bench/` — capacity producers (#2921)

Re-runnable producers for the throughput cells
[`docs/enterprise-deployment.md`](../../docs/enterprise-deployment.md) §11.1
retired for having none. Results and the honest-limitations section live in
[`docs/bench/capacity-envelope-2921.md`](../../docs/bench/capacity-envelope-2921.md).

§11.1's rule governs everything here: **an unproduced number is not data.**
Every number this directory emits carries, in the same JSON object, the
argv that produced it, the host it ran on, the tier, the backend, and the
instrument's own measured ceiling.

## What is here

| file | role |
|---|---|
| `benchlib.py` | shared primitives — keep-alive HTTP client, nearest-rank percentiles, host-fact capture. Stdlib only. |
| `ops_producer.py` | the §11.1 producer: concurrency ramps for `memory_store`, `memory_recall` (keyword tier) and `/sync/push`. Emits the results JSON `infra/pillar4-envelope/usl-fit.py` already consumes. `--self-test`. |
| `run-ops-producers.sh` | runs all three producers end to end against freshly-started, self-contained daemons. Host processes, no Docker. |
| `mesh_probe.py` | drives + measures one rung of the multi-node mesh ramp (`infra/bench-mesh/`). `--self-test`. |
| `host-facts.sh` | CPU / RAM / storage capture; `--check` fails when a required fact is missing. |

## What is NOT here, on purpose

* **A second USL fitter.** `infra/pillar4-envelope/usl-fit.py` already fits
  and projects, is self-tested against a known ground truth, and labels
  every projected number `ESTIMATED-not-MEASURED`. These producers emit its
  input contract instead of duplicating it.
* **A replacement for `benches/`.** The seven Criterion benches measure
  in-process **latency** distributions. These measure **end-to-end
  throughput over the HTTP surface**. Different instrument, different
  question; §11.1's table was always the latter and `benches/` was never
  its producer.
* **An agent-count claim.** One worker is a zero-think-time loop. Workers
  bound the agents a host could carry from above; they are not agents.

## Running

```sh
cargo build --release --bin ai-memory
scripts/bench/run-ops-producers.sh \
  --binary target/release/ai-memory \
  --out-dir <scratch-dir>/ops-2921

# fit + project with the existing fitter
infra/pillar4-envelope/usl-fit.py <scratch-dir>/ops-2921/ops-memory_store.json --target 500
```

Contract checks, no daemon needed:

```sh
python3 scripts/bench/ops_producer.py --self-test
python3 scripts/bench/mesh_probe.py --self-test
python3 infra/bench-mesh/gen-mesh.py --self-test
scripts/bench/host-facts.sh --check
```

## Safety properties

* Every daemon started here runs with `HOME`, `XDG_CONFIG_HOME`,
  `XDG_DATA_HOME`, `AI_MEMORY_KEY_DIR` and `--db` all redirected into the
  run directory. The producers cannot reach an operator's real store even
  through a stray config lookup.
* Row-count observation opens the watched database `file:…?mode=ro`. It
  cannot write to, lock out, or migrate a live daemon's database.
* Throughput counts **succeeded** operations only. Admission-control 503s
  are reported separately as a shed rate; folding them into throughput is
  how an overloaded daemon reports its best number.
* A rung that does not converge reports `converged_s: null`. There is no
  code path that estimates a completion time that was not observed.
