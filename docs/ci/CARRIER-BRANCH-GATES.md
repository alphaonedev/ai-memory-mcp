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
| `linux-fed,enterprise-fed` | 14400 s (240 min) | 270 | 88-92 min | 143-150 min |
| `macos-fed,enterprise-fed` | 14400 s (240 min) | 270 | n/a | n/a |

Ratio rule: job `timeout-minutes` >= watchdog minutes + 15. All four rows meet it.

## Why enterprise-fed moved from 8100 s to 14400 s (#6202)

The serial 371-binary suite takes 88-92 min of job wall time on an idle host.
The `linux-fed` label is served by two runners (`f2-linux-fed`,
`f2-linux-fed-2`) on one 14-core host, so two suites routinely run at once and
take 143-150 min. Run 37944916554 (PR #6160, 2026-10-09) was killed with exit
124 at 8100 s while still progressing. 14400 s is more than 1.5x the contended
worst case. The job limit is 270 min: watchdog (240) plus about 30 min for
compile (6-12 min) and ephemeral-database setup/teardown (about 970 s measured).

## Reading the margin

Every green run now emits `::notice::[#6202] ... suite wall <s>s of the
<budget>s watchdog budget (<n>% used, <m> min margin ...)`. Re-derive the
budget whenever a measured full run comes within 20 % of it.

## Not done here

A per-test-binary budget (for example 1200 s per binary) was proposed in #6202
item 2. It needs the suite split into one `cargo test` call per binary, which
breaks the single `cargo test --no-fail-fast "$@"` shape the #2500/#2657
invariant gates pin, so it is tracked separately.
