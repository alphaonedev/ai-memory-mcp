# Per-binary Postgres isolation (#6383 / #6386 / #9592)

Status: **on in one step of one leg.** Since #9592 (`3-agent vote (71472661)`,
decision A, step-scoped opt-in) the flag `AI_MEMORY_TEST_PG_ISOLATE=1` is set
in exactly one place: the env of the step
`Serial shard isolated binaries (linux-fed enterprise-fed, issue 9592)` in the
`check` job of `.github/workflows/ci.yml`, guarded to `matrix.node == 'linux-fed'`
and `matrix.tier == 'enterprise-fed'`. The invariant `G1-opt-in` in
`scripts/ci/check_pg_isolate_invariants.py` is red on a second site, on any
other value form, on another job or on a changed guard. The wrapper default
(off), in-binary `--test-threads=1` and the partition
(`scripts/ci/partition_test_binaries.py`) are unchanged. The repository
variable `CI_PG_ISOLATE_OFF=1` is the hard kill switch: it selects the exact
serial path.

## How the leg runs

1. **Run tests (impact-aware)** exports `AI_MEMORY_TEST_PG_ISOLATE=0` and runs
   the three shards as before. On linux-fed enterprise-fed with the kill
   switch off, `scripts/ci/pg_isolate_split.py` splits the serial shard: its
   `--test` binaries are deferred (`$RUNNER_TEMP/ci-shard/iso_targets.txt`,
   the residual subset in `iso_residual.txt`) and the mode file
   `$RUNNER_TEMP/ci-iso-mode.txt` says `deferred`; the `--bin`, `--example`
   and `--bench` selectors keep their in-line serial run. On every other leg,
   or with the kill switch on, nothing is deferred and the mode file says
   `none`.
2. **Serial shard isolated binaries** runs
   `scripts/ci/pg_isolate_serial_step.py run`. Mode `none` is a no-op. With
   the kill switch on it runs the deferred binaries itself on the exact serial
   path (`cargo test --no-fail-fast --test ... -- --test-threads=1`, flag `0`).
   Otherwise it prebuilds the targets, runs `pg_isolated_binary.py setup`
   (age+vector template `<CI_FED_DB>_tpl`, `IS_TEMPLATE true
   ALLOW_CONNECTIONS false`, a fresh run id), then `pg_isolated_binary.py run
   --jobs 8` under the job-time watchdog. For each binary the wrapper mints
   `ai_memory_t_<run id>_<unix seconds>_<8 hex>`, holds a keepalive session on
   it, points `AI_MEMORY_TEST_POSTGRES_URL` (and `AI_MEMORY_TEST_AGE_URL` when
   set) at it and runs `cargo test --no-fail-fast --test <bin> --
   --test-threads=1 --show-output`. Admission re-reads the live connection
   budget on every acquire and reserves the sessions of every binary in flight
   (PR 8230 defect 1 closed by construction), so the width falls to what the
   budget allows instead of overcommitting it. Each binary writes
   `$RUNNER_TEMP/ci-shard/iso-logs/<bin>.log` and its first line is the
   evidence line `# [pg_isolated_binary] current_database=<db> mode=isolated`
   (or `mode=residual`); no URL or credential is ever logged.
   The residual binaries (named in `scripts/ci/pg_isolate_serial_residual.txt`,
   or detected by `pg_isolate_split.py`: a fixed loopback port, a shared path,
   no readable source) run last, one at a time, on the shared database. The
   residual file holds every binary that the I-7 audit
   (`scripts/ci/pg_isolate_cluster_audit.py`) finds with a cluster-global
   operation or a wall-time assert (the load-sensitive class of PR 8230
   defect 2, issue 6796), so those never run beside the pool.
3. **Fail closed.** The step is red on a missing log, a zero-test binary, a
   log without its evidence line, two binaries on one database, a
   self-skipped Postgres test, a clone mint failure, a teardown failure and
   any clone or template of the run left after teardown. Teardown runs in a
   `finally` and on SIGTERM, passing `AI_MEMORY_TEST_PG_TEMPLATE`, the run id
   and a `--db` equal to the URL database explicitly; no decision reads the
   text of a refusal message.
4. **Upload isolated-lane per-binary logs (#6383)** uploads the log directory
   with `if: always()`.
5. **Cleanup enterprise-fed ephemeral db** runs
   `scripts/ci/pg_isolate_serial_step.py cleanup` with `always()`: a cancel or
   job-cap kill that stopped the step's own teardown is torn down again, and a
   clone or template still left fails the step.

**Never re-run an isolation red (I-12).** After landing, a red of the isolated
step is not re-run to pass: the conductor sets `CI_PG_ISOLATE_OFF=1` and files
an issue with the failing binary and its log line.

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
* **Caller SQL guard.** `psql()` refuses SQL it cannot read the way the server
  does. That includes an octal escape above `\377` in an E-string and in a
  plain literal such as '\563': whether a backslash escapes inside a plain
  literal depends on `standard_conforming_strings`, which the wrapper does not
  control, and PostgreSQL keeps only the low byte of an octal escape. The error
  text says "an E-string" or "a plain-literal" to match the literal (#7703,
  #7717).

## Budgets left unchanged

`WATCHDOG_SECS` and the matrix `timeout-minutes` are not touched by this
change. Lower them only after two consecutive green runs show the margin.
