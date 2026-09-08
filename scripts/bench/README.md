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

---

# The wake-plane acceptance run (#3473, EPIC #3466)

`#3473` is the acceptance leg of the wake-plane EPIC. Three questions, three
producers, one shared lifecycle:

| file | question |
|---|---|
| `wake_latency.py` | wake latency p50/p95/p99/max at 16/64/128/256 agents, `ai-memory wake-hub` versus `GET /api/v1/inbox/stream` |
| `wake_abab.sh` | does turning the wake plane ON cost the substrate's read/write paths anything? (A-B-A-B, hub off / on / off / on) |
| `wake_hub_kill.sh` | SIGKILL the hub mid-run at 128 agents — does any committed inbox row go missing? |
| `wake_bench_env.sh` | the shared lifecycle both shell drivers source (TLS, store URL, daemon, agents, hub, refresher, teardown). SOURCED, never executed. |

## The two scripts the issue names do not exist

`#3473` names `.local-runs/read-path-throughput.py` and
`write-path-throughput.py`. **They are not in this repository.** Searched
three ways and found nothing: the working tree
(`find . -name '*throughput*'` returns only `benches/reranker_throughput.rs`),
every branch's history (`git log --all --diff-filter=A -- '*throughput*'`,
same single hit), and GitHub code search across the whole repo
(`throughput.py in:path` -> 0 results). `.local-runs/` is gitignored and
holds only `.gitkeep` at the release tip, so if such scripts ever existed
they existed on one host and were never committed. No provenance is
invented for them here; the read/write-path legs are built on the
conventions this directory already has (`benchlib.py`, `ops_producer.py`).

## What each arm measures, and what it refuses to claim

* **`t0` is the notify RESPONSE**, not the request: the plane's promise
  starts at "the durable inbox row has committed", and folding the
  substrate's own write cost into a wake number would measure the wrong
  thing.
* Both arms are stamped in the SAME place — in the subscriber thread, right
  after the frame is decoded — so the hub-vs-SSE comparison cannot be biased
  by where the clock is read, and both observe the SAME notify.
* A notify that did not return `201` is an ERROR, never a latency. A wake
  that never arrived is `missing`, counted and named, never imputed.
* A quantile with no observations behind it is `null`, never `0` — the same
  rule `wake_hub::metrics` applies to its own histograms.
* **The two f1 host effects are published, never folded in.** The first
  loopback round-trip in a fresh process has been measured above 10 s and a
  freshly built binary stalls ~48 s at 0 % CPU on its first exec. Every HTTP
  session spends a discarded warm-up request before the timed window
  (`meta.warmup`), and the shell drivers spend the binary's first exec on
  `--version` (`results/host-effects.json`). Neither is ever subtracted
  from, averaged into, or hidden inside a percentile.

## Prerequisites

1. A release build: `cargo build --release --features sal,sal-postgres`.
2. `python3` (3.10+) and the `cryptography` package — the hub arm loads the
   tree's own client, `sdk/python/ai_memory/wake.py`, which needs Ed25519 to
   sign its hello. Everything else is stdlib.
3. A raised file-descriptor budget. macOS ships a soft `RLIMIT_NOFILE` of
   **256**, which is exactly the agent count #3466 designs for: run
   `ulimit -n 4096` in the shell that drives the run. `wake_latency.py`
   raises its own soft limit where it can and REFUSES to start a ramp it
   could not finish, rather than dying of `EMFILE` mid-sample.
4. A PostgreSQL store the run owns. **Never `ai_memory_test`** — that is the
   shared live database, and both shell drivers refuse the name outright.
   Create the run's own:

   ```sh
   psql "$(sed 's#/[^/?]*?#/postgres?#' ~/.ai-memory-ci-fed-url)" \
     -c 'CREATE DATABASE ai_memory_f1_3473'        # f2 uses its own names
   psql "$(sed 's#/[^/?]*?#/postgres?#' ~/.ai-memory-ci-fed-url)" \
     -c 'CREATE DATABASE ai_memory_f1_3473_kill'
   ```

   The URL is then passed as a FILE (`--store-url-src`), swapped to that
   database name, written 0600 and handed to the daemon through
   `AI_MEMORY_STORE_URL_FILE` — never on argv, where `ps auxww` would show
   the password.

   **The hub-kill drill needs a FRESH database of its own** — the second
   name above, or the first one dropped and recreated between steps. The
   row-loss gate reads `GET /api/v1/inbox`, which the daemon caps at 500
   rows with no cursor, while the A-B-A-B legs write thousands of rows to
   the SAME recipient ids. Sharing one database does not make the gate
   fail; it makes it UNPROVABLE, which is worse, because a truncated read
   cannot distinguish "no row was lost" from "the rows that were lost are
   past the cap". `wake_hub_kill.sh` therefore runs
   `wake_latency.py preflight` before its first notify and REFUSES (exit
   70) unless every target inbox is empty.

5. `openssl` with `req -addext` support — **OpenSSL >= 1.1.1** or
   **LibreSSL >= 3.1**. `wb_mint_tls` uses `-addext
   "subjectAltName=IP:127.0.0.1"` to put the SAN on the self-signed
   certificate the harness pins; an older `openssl` rejects the flag and
   the run stops there rather than falling back to a SAN-less certificate
   the client would refuse anyway. macOS ships LibreSSL 3.3+ in
   `/usr/bin/openssl`; on a host with an older one, put a newer
   `openssl` first on `PATH`.

## Transport

The daemon is served over **TLS only**. `wake_bench_env.sh` mints a
self-signed certificate for `127.0.0.1` into the run directory (never
reusing operator key material) and the harness PINS it. There is no
`--insecure`, no verification-skipping flag, and no unencrypted listener.
An `https` base URL REQUIRES `--tls-ca`; a plaintext `http://` base URL is
**refused outright, with no flag that opens it** — the earlier
`--allow-plaintext-loopback` exception was removed at Master's phase-2
review, so a plaintext figure cannot be produced at all rather than merely
being labelled after the fact. `--self-test` walks every subparser and
fails if any `insecure` / `plaintext` / `allow` option is ever added back.

## Identity ceremony — an honest deviation

Agent key history is established in a LOCAL SQLITE ceremony database
(`<run-dir>/ceremony.db`) even when the daemon serves PostgreSQL, because
`agents register` / `agents bind-key` are structurally sqlite-path-only
(#3418 declares `--store-url` on the api-key verbs and nowhere else).

This does not touch the measured path: the hub opens NO database on either
backend — it verifies a hello against the allowlist SNAPSHOT FILE, so which
store the exporter derived that file from is a property of the ceremony, not
of the wake. `POST /api/v1/notify`, `GET /api/v1/inbox/stream` and
`GET /api/v1/inbox` all run against the served PostgreSQL store. The one
real consequence: the `identity.hub_allow` / `identity.hub_revoke` audit
rows land on the ceremony database's `signed_events` spine rather than the
served one.

## The refresher is not optional

`wake_hub::identity` refuses every hello once the allowlist snapshot is
older than 60 s, and re-validates every ESTABLISHED session against it once
per second. `wb_start_refresher` republishes every 30 s — half the ceiling,
exactly as the shipped systemd/launchd units do. A run without it does not
degrade gracefully: it drops every session about a minute in and reports a
hub that "lost" every wake.

## Running it

```sh
ulimit -n 4096
export TMPDIR=/private/tmp/ai-memory-f1-3473        # f2 uses its own
RUN=<repo>/.local-runs/wake-3473

# 1. latency, hub arm vs SSE arm, across the four rungs
#    (wake_bench_env.sh is SOURCED by the two drivers below; never run it)
python3 scripts/bench/wake_latency.py run \
  --base-url https://127.0.0.1:19473 --tls-ca "$RUN/tls/cert.pem" \
  --arms hub,sse --agents "16 64 128 256" \
  --hub-socket "$RUN/hub/wake-hub.sock" --bundle-dir "$RUN/bundles" \
  --sender ai:wake-bench-sender --notifies 512 --pace-ms 25 \
  --host-substrate f1 --out "$RUN/results/wake-latency.json"

# 2. read/write-path A-B-A-B (starts and stops its own daemon + hub)
scripts/bench/wake_abab.sh --binary target/release/ai-memory \
  --run-dir "$RUN" --store-url-src ~/.ai-memory-ci-fed-url \
  --db-name ai_memory_f1_3473 --agent-counts "16 64 128 256"

# 3. hub SIGKILL under load at 128 agents
#    NOTE the SEPARATE database: the reconciliation read is capped at 500
#    rows per inbox, so a database the A-B-A-B legs already wrote to can
#    only answer INCONCLUSIVE. The pre-flight refuses that run outright.
scripts/bench/wake_hub_kill.sh --binary target/release/ai-memory \
  --run-dir "$RUN" --store-url-src ~/.ai-memory-ci-fed-url \
  --db-name ai_memory_f1_3473_kill --agents 128
```

Step 1 needs a daemon + hub already up; the simplest order is to run step 2
or 3 first (each brings the whole lifecycle up and tears it down), or to
source `wake_bench_env.sh` in a shell and call `wb_init` / `wb_mint_tls` /
`wb_write_store_url` / `wb_schema_init` / `wb_enroll_agents` /
`wb_start_daemon "$WB_SOCKET"` / `wb_start_refresher` / `wb_start_hub` by
hand.

Contract checks, no daemon needed:

```sh
python3 scripts/bench/wake_latency.py --self-test     # alias: --dry-run
python3 scripts/bench/wake_latency.py --help
bash -n scripts/bench/wake_bench_env.sh scripts/bench/wake_abab.sh \
        scripts/bench/wake_hub_kill.sh
```

## Reading the output

**`wake-latency.json`** — `points[]`, one per agent count, each with an
`arms` object per arm:

| field | meaning |
|---|---|
| `offered` / `delivered` / `missing` | notifies committed, wakes matched, wakes that never arrived |
| `p50_ms` / `p95_ms` / `p99_ms` / `max_ms` | nearest-rank over the delivered set; `null` when nothing was delivered |
| `complete` | `true` only when nothing is missing and no delta was negative |
| `signal_reasons` (hub) | `wake` / `gap` / `backstop` / `welcome` counts — a run delivered by the BACKSTOP is not a hub latency |
| `events` (sse) | SSE event names seen, including `lagged` |

A `missing` count on the hub arm is the honest description of what an
operator would have observed: the hint did not arrive inside the settle
window. It is never converted into a latency.

**`results/abab/verdict.json`** — one row per (agent count, op):

* `PASS` — mean(B) within the threshold of mean(A).
* `REGRESSION` — mean(B) more than the threshold below mean(A). Exit 1.
* `INCONCLUSIVE` — the A1-vs-A2 spread is itself larger than the threshold.
  Exit 3. The run measured its own noise floor and it exceeded the effect
  being claimed; that is not "no regression", it is "this host could not
  answer today". Re-run longer or quieter — do not tune the threshold until
  it passes.

Threshold defaults to 5 %: the order of the run-to-run spread these
host-process producers show on a shared workstation, and far above the
effect being looked for (one encode plus one non-blocking enqueue per
committed notify, on the commit path only).

**`results/hub-kill/summary.json`** — the pass/fail gate is `verdict`:

* `PASS` — every committed row is still readable through the inbox.
* `LOST` — at least one is not. Exit 1. A data-integrity failure.
* `INCONCLUSIVE` — an inbox came back at the server's `limit` ceiling of
  500, so the read may have been truncated. Exit 3: a truncated read cannot
  tell "lost" from "past the page", and reporting PASS from one would invent
  the guarantee the drill exists to test.

`wake_hints.missing_after_kill` in the same file is EXPECTED to be non-zero:
after the SIGKILL the hub is gone and delivery degrades to the `<=60 s`
backstop poll. That is the documented degrade, not a defect — the gate is
row loss, judged from the durable side.

## Deviations recorded with every run

* **Quota lift.** Every notify in a rung is written by ONE sender, so at the
  shipped 1000 writes/day default a 256-agent rung stops partway through
  with `429` — which measures the quota, not the wake plane.
  `AI_MEMORY_MAX_MEMORIES_PER_DAY` / `AI_MEMORY_MAX_STORAGE_BYTES` are
  lifted for the run exactly as `run-ops-producers.sh` lifts them; the quota
  CHECK still runs on every write, so its per-write cost stays inside the
  measured path.
* **`ops_producer.py` is not reused.** `benchlib.HttpSession` refuses any
  scheme but `http` by construction, so it cannot reach a TLS daemon, and
  widening it would change an instrument three other producers are
  calibrated against. `wake_latency.py rate` is the sibling: same reducers,
  same succeeded-ops-only counting, same shed accounting, plus TLS.
* **The A-B-A-B read path is `GET /api/v1/inbox`, not `memory_recall`.**
  "Wake, then read once" means the read that matters is the inbox read, and
  it needs no seeded corpus or attested-write ceremony, so it measures the
  same thing on any host. `--ops "notify inbox recall"` adds the recall leg
  when a corpus has been seeded.
