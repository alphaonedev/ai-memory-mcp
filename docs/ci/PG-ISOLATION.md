# Per-binary Postgres isolation (#6383 / #6386)

Status: **opt-in, off on every CI leg.** The lane runs only when
`AI_MEMORY_TEST_PG_ISOLATE` is `1` in the job environment, and
`.github/workflows/ci.yml` sets it on no leg (the invariant
`G1-opt-in` in `scripts/ci/check_pg_isolate_invariants.py` fails the build if
it ever does). This was decided by GOD in review r1 (M4): the first sharded
carrier run goes with isolation off. Making it the default, and raising
in-binary `--test-threads` above 1, wait for two green sharded carrier runs and
a 5-agent vote (`4d3ea1c5`). The repository variable `CI_PG_ISOLATE_OFF=1` is
an extra hard kill switch that wins over the flag.

## What changes when it is on

Before, every test binary on an enterprise-fed leg shared one ephemeral
database, so the class (a) binaries (Postgres, `#[serial]`, `federat*`) ran one
after another. With the lane on (flag `1`, kill switch not `1`, tier
`enterprise-fed`):

1. **Configure** runs `pg_isolated_binary.py setup --emit-env`. It checks the
   live connection budget: `max_connections` minus the reserved slots minus the
   sessions open right now (`pg_stat_activity`) must cover
   `jobs * (18 + 1) + 20` (172 for width 8), or the step fails. It builds
   `<CI_FED_DB>_tpl` with the `age` and `vector` extensions and marks it
   `IS_TEMPLATE true ALLOW_CONNECTIONS false`, so `CREATE DATABASE ... TEMPLATE`
   only hits SQLSTATE 55006 under a stray session, which the mint retries. It
   exports `AI_MEMORY_TEST_PG_TEMPLATE` and `AI_MEMORY_TEST_PG_RUN_ID` to
   `$GITHUB_ENV`.
2. **Run.** The test step fails with `::error::` when the lane is on but the
   template or run id is missing; it never skips. `run_isolated_lane` prebuilds
   only the targets in `iso_targets.txt`, then calls
   `pg_isolated_binary.py run` under the #1492 watchdog. For each
   `--test`/`--bin` it mints `ai_memory_t_<run id>_<unix seconds>_<8 hex>`,
   holds a keepalive session on it, points `AI_MEMORY_TEST_POSTGRES_URL` (and
   `AI_MEMORY_TEST_AGE_URL` when set) at it, runs
   `cargo test --no-fail-fast --test <bin> -- --test-threads=1`, then releases
   the hold and drops the clone. The width is 8, reduced to what the live
   budget allows. Each binary writes its own log under
   `$RUNNER_TEMP/ci-shard/iso-logs/<bin>.log`. A failing binary's last 200
   lines are echoed in a `::group::`, and the step
   `Upload isolated-lane per-binary logs (#6383)` uploads the directory with
   `if: always()`.
   Binaries named in `scripts/ci/pg_isolate_serial_residual.txt`, binaries
   that bind a fixed loopback port or use a shared path, and binaries with no
   readable source (`scripts/ci/pg_isolate_split.py`) run last, one at a time,
   on the shared database. The flag is stripped from their environment, so the
   Rust helper does not mint for them.
3. **Cleanup** runs `pg_isolated_binary.py teardown --run-id <this run>`, which
   drops this run's leftover clones and the template.

On SIGTERM (the watchdog) or SIGINT, the wrapper stops dispatching, sends TERM
to every running `cargo` process group and KILL 5 s later, drops the clones in
flight, and exits 143. All of this finishes inside the 60 s `--kill-after`
window.

The Rust helper `tests/common/pg_isolate.rs` gives the same isolation to a
local run: `postgres_url()`/`age_url()` mint once per process when the flag is
on. It does nothing when the URL already names an `ai_memory_t_*` database,
which is what the CI wrapper hands out. It requires `AI_MEMORY_TEST_PG_TEMPLATE`
and never falls back to cloning the shared database. It uses
`AI_MEMORY_TEST_PG_RUN_ID`, or generates a run id per process when that is
unset.

## Safety properties

* Flag off (or the kill switch on) is today's behaviour, byte for byte.
* Fail closed: with the flag on, a clone that cannot be made, held or named is
  a failure. Nothing silently falls back to the shared database.
  That includes the Rust helper's in-process publish: if the shared env lock
  stays busy past its bound, the mint fails (the test panics with the reason)
  instead of running with the URL still naming the shared database (#6571).
  The wait defaults to 30 s; tests may shorten it with
  `AI_MEMORY_TEST_PG_ENV_LOCK_WAIT_MS` (a non-number keeps the default), which
  the caller-side cell for #6889 uses.
* **Own clone, own cleanup.** A clone the Rust helper mints for its own process
  (no wrapper) is released and dropped by an exit hook, best effort, never a
  panic (#6570). A clone the wrapper minted is dropped by the wrapper.
  The hook is `libc::atexit`: it runs on a normal return and on
  `process::exit` (the libtest failure exit) but not on `abort`, a fatal signal
  or SIGKILL (for example a CI job-timeout kill). After those the clone is
  dropped by the run teardown (`--run-id`) or the stale admin sweep (#6888).
* **Run-scoped.** Every clone name carries its run id (`[a-z0-9]{1,20}`).
  Teardown, and the Rust helper's sweep of its own stale clones, only ever
  touch clones of their own run.
* **No FORCE drops.** A database with a live session cannot be dropped, so a
  race with another binary fails the drop instead of terminating that binary.
* **Admin-only cross-run sweep.**
  `pg_isolated_binary.py sweep --older-than N` (N at least 600 s) drops idle
  clones of any run. CI never calls it (invariant `G2-no-ci-sweep`).
* **No secrets in argv.** `psql` gets the connection through libpq environment
  variables (`PGHOST`, `PGPORT`, `PGUSER`, `PGPASSWORD`, `PGDATABASE`,
  `PGSSLMODE`, ...). ci.yml passes the URL through the environment, never with
  `--url` (invariant `G3-no-url-argv`). A URL query key the wrapper does not
  know fails closed.

## Budgets left unchanged

`WATCHDOG_SECS` and the matrix `timeout-minutes` are not touched by this
change. Lower them only after two consecutive green runs show the margin.
