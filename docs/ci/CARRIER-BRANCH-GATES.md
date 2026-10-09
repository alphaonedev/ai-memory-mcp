# CI hang-watchdog budgets by tier (#1492, #6202)

The full-suite step in `.github/workflows/ci.yml` ("full suite (cargo test)")
runs `cargo test --no-fail-fast` under GNU `timeout --signal=TERM
--kill-after=60 $WATCHDOG_SECS`. The watchdog exists to catch a hung test and
name it; it is NOT a cap on total suite duration. The job-level
`timeout-minutes` (matrix `timeout`) is the outer backstop and must sit at
least 15 minutes above the watchdog so that the named watchdog, not a nameless
job-level cancel, is what fires. Compile runs outside the watchdog (`cargo test
--no-run`, #1989/#2657).

| Tier / leg | Watchdog (`WATCHDOG_SECS`) | Job `timeout-minutes` | Measured uncontended | Measured contended |
|---|---|---|---|---|
| `ubuntu-latest,sqlite` | 2100 s (35 min) | 95 | see #3538 | see #3538 |
| `macos-fed,sqlite` | 2400 s (40 min) | 80 | about 27 min (#3461) | n/a |
| `linux-fed,enterprise-fed` | 14400 s (240 min) | 270 | suite 4007-4750 s (67-79 min) | ~13,900-14,100 s extrapolated (232-235 min) |
| `macos-fed,enterprise-fed` | 14400 s (240 min) | 270 | n/a | n/a |

Ratio rule: job `timeout-minutes` >= watchdog minutes + 15. All four rows meet it.

## Why enterprise-fed moved from 8100 s to 14400 s (#6202)

The suite is 1,005 test executables run serially (`--test-threads=1`). From
live job logs, the uncontended suite took 4007 s and 4750 s, and it reached the
`federation_write_ns_scope_2447` binary at 2303 s and 2767 s. (The 88-92 min
figures earlier quoted were job wall time including compile and setup, not the
suite.) The `linux-fed` label is served by two runners (`f2-linux-fed`,
`f2-linux-fed-2`) on one 14-core host. In run 37944916554 (PR #6160,
2026-10-09) both slots were busy and the same point was reached only at about
8100 s, about 3.5x slower, where the 8100 s watchdog killed a healthy,
still-progressing run (exit 124). The 143-150 min figure earlier quoted was the
wall time of that killed run, not what the suite needs.

Extrapolated, a contended serial suite needs about 13,900-14,100 s. 14400 s
leaves about 300-500 s (2-4 %) of margin over that. This is the serial budget
until the #6344 shards land (expected critical path about 3,900 s); it is not a
comfortable margin, and a contended serial run can still reach it. The job
limit is 270 min: watchdog (240) plus about 30 min for compile (6-12 min) and
ephemeral-database setup/teardown (about 970 s measured).

## Reading the margin

Every green run now emits `::notice::[#6202] ... suite wall <s>s of the
<budget>s watchdog budget (<n>% used, <m> min margin ...)`. Re-derive the
budget whenever a measured full run comes within 20 % of it.

## Not done here

A per-test-binary budget (for example 1200 s per binary) was proposed in #6202
item 2. It needs the suite split into one `cargo test` call per binary, which
breaks the single `cargo test --no-fail-fast "$@"` shape the #2500/#2657
invariant gates pin, so it is tracked separately.

## Sharded enterprise-fed suite (#6344)

The serial full suite (about 13,100 s measured/extrapolated over 1,005 test
executables) outgrew every watchdog raise, so tier `enterprise-fed` now builds
once and runs three concurrent shards inside the same `Run tests
(impact-aware)` step (job names, matrix legs and the step name are unchanged):

| Shard | Holds | Threads |
|---|---|---|
| serial | class (a): Postgres, `#[serial]`, `federat*` names, binaries with unknown source, the lib tests matching `scripts/ci/lib_pg_prefixes.txt`, doc tests | 1 |
| parallel_1 | lib tests with `--skip` of those prefixes, plus a balanced share of self-contained binaries | 3 |
| parallel_2 | the remaining self-contained binaries | 3 |

`scripts/ci/partition_test_binaries.py` reads the `cargo test --no-run
--message-format=json-render-diagnostics` artifact list, classifies each binary
by its source, balances class (b) by the measured seconds in
`scripts/ci/test_binary_weights.json` (class mean for unmeasured binaries) and
fails if the three sets are not disjoint and complete. A new `tests/*.rs` is
picked up automatically; an unreadable or unclassifiable source goes to the
serial shard. Only the serial shard touches the per-job Postgres database.

Each shard is a chain of `run_tests` calls, so the #1492 watchdog, `--no-fail-fast`
(#2500) and the prebuild (#2657) invariants hold. The step waits on each shard
PID separately and fails if any shard failed.

Estimated wall time (ideal, from the measured weights): serial 3,891 s,
parallel 1,620 s and 1,516 s, so about 65 min against about 218 min before. The
federation-name rule keeps 47 binaries (about 437 s) in the serial shard on
purpose. Real wall time is not verified until a CI run completes; refresh the
weights when it does.
