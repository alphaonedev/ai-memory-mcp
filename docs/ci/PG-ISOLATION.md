# Per-binary Postgres isolation (#6383 / #6386)

Status: opt-in. `AI_MEMORY_TEST_PG_ISOLATE=1` is exported only by the
`Configure enterprise-fed tier` step of `.github/workflows/ci.yml`; the sqlite
legs never see it. Making it the repo-wide default is a T3/T6 decision that
needs the 5-agent vote (`4d3ea1c5`), as does raising in-binary
`--test-threads` above 1.

## What changes

Before, every test binary on an enterprise-fed leg shared one ephemeral
database, so the class (a) binaries (Postgres, `#[serial]`, `federat*`) ran one
after another. With the flag on:

1. **Configure** sweeps orphans, asserts `SHOW max_connections >= jobs*18+20`
   (164 for width 8; fails closed), and builds `<CI_FED_DB>_tpl` with the `age`
   and `vector` extensions, then marks it `IS_TEMPLATE true ALLOW_CONNECTIONS
   false`. Nothing ever connects to it, so `CREATE DATABASE ... TEMPLATE` never
   hits SQLSTATE 55006 except under a stray session, which the mint retries
   three times.
2. **Run** (`run_isolated_lane`, a sibling of `run_tests`) calls
   `scripts/test/pg_isolated_binary.py run`, which for each `--test`/`--bin`
   in the serial shard mints `ai_memory_t_<unix seconds>_<8 hex>`, points
   `AI_MEMORY_TEST_POSTGRES_URL` (and `AI_MEMORY_TEST_AGE_URL` when set) at it,
   runs `cargo test --no-fail-fast --test <bin> -- --test-threads=1`, and drops
   the clone. Width is 8. Binaries named in
   `scripts/ci/pg_isolate_serial_residual.txt`, or that bind a fixed loopback
   port, use a shared path, or have no readable source
   (`scripts/ci/pg_isolate_split.py`), run last, serially, on the shared
   database.
3. **Cleanup** un-marks and drops the template and any idle leftover clones.

The Rust helper `tests/common/pg_isolate.rs` gives the same isolation to a
local run (`postgres_url()`/`age_url()` mint once per process when the flag is
on). It does nothing when the URL already names an `ai_memory_t_*` database,
which is what the CI wrapper hands out.

## Safety properties

* Flag off is today's behaviour, byte for byte.
* Fail closed: flag on and the clone cannot be made is a failure, never a
  silent fall back to the shared database.
* The sweep drops only databases whose whole name matches the exact shape, are
  older than 600 s (clones) or one day (`ai_memory_test_ci_*`), and have no live
  session, so a concurrent run's long binary is never dropped.
* Kill switch: set the repository variable `CI_PG_ISOLATE_OFF=1`.

## Budgets left unchanged

`WATCHDOG_SECS` and the matrix `timeout-minutes` are not touched by this
change. Lower them only after two consecutive green runs show the margin.
