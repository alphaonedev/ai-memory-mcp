# CI hang-watchdog budgets by tier (#1492, #6202, #6344)

The full-suite step in `.github/workflows/ci.yml` ("full suite (cargo test)")
runs `cargo test --no-fail-fast` under GNU `timeout --signal=TERM
--kill-after=60 $WATCHDOG_SECS`. On tier `enterprise-fed` the suite runs as
three concurrent shards and `$WATCHDOG_SECS` bounds each shard's whole chain
(see [Sharded enterprise-fed suite (#6344)](#sharded-enterprise-fed-suite-6344)). The watchdog exists to catch a hung test and
name it; it is NOT a cap on total suite duration. The job-level
`timeout-minutes` (matrix `timeout`) is the outer backstop and must sit at
least 15 minutes above the watchdog, and on a sharded tier at least the watchdog
plus the pre-watchdog compile and database phase (about 28 min) plus 2 min, so
that the named watchdog, not a nameless job-level cancel, is what fires (#6411). Compile runs outside the watchdog (`cargo test
--no-run`, #1989/#2657).

| Tier / leg | Watchdog (`WATCHDOG_SECS`) | Job `timeout-minutes` | Measured uncontended | Measured contended |
|---|---|---|---|---|
| `ubuntu-latest,sqlite` | 2100 s (35 min) | 95 | see #3538 | see #3538 |
| `macos-fed,sqlite` | 2400 s (40 min) | 80 | about 27 min (#3461) | n/a |
| `linux-fed,enterprise-fed` | 7800 s (130 min) per shard | 160 | longest shard estimate 3,913 s (serial) | not yet measured (first green sharded run) |
| `macos-fed,enterprise-fed` | 7800 s (130 min) per shard | 160 | n/a | n/a |

Ratio rule: job `timeout-minutes` >= watchdog minutes + 15. On the sharded
`enterprise-fed` legs the stricter rule applies: job `timeout-minutes` >=
watchdog minutes + 28 (pre-watchdog compile and database setup) + 2 (teardown)
= 160. All four rows meet both.

## Why enterprise-fed moved from 8100 s to 14400 s (#6202)

> Superseded by [Sharded enterprise-fed suite (#6344)](#sharded-enterprise-fed-suite-6344):
> the serial 14400 s / 270 min budget below applied only while the suite ran
> serially. It is kept as the measured record the shard budget was derived
> from.

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

The serial full suite (about 13,900-14,100 s contended, extrapolated over 1,005
test executables; see the superseded #6202 section above) outgrew every watchdog raise, so tier `enterprise-fed` now builds
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

Classification reads the union of every file a target compiles: `mod name;`
(`name.rs`, `name/mod.rs`, inline-mod nesting), `#[path = "..."] mod name;` and
`include!`, recursively; a `mod` that resolves to no file sends the target to
the serial shard. A file two or more targets compile (`tests/common/`) counts
per item: a binary inherits a helper's Postgres or `#[serial]` evidence only
when its own code names that helper, and a test declared in a shared file
moves every includer when its code uses Postgres. The lib gate fails the step
when a lib code site that names `AI_MEMORY_TEST_POSTGRES_URL` (directly, in a
string, or through a const/static) sits at a test path no prefix in
`lib_pg_prefixes.txt` occurs in (the libtest substring rule).

Each shard is a chain of `run_tests` calls, so the #1492 watchdog, `--no-fail-fast`
(#2500) and the prebuild (#2657) invariants hold. The step waits on each shard
PID separately and fails if any shard failed. Each shard's log, list file and
the partition `manifest.json` are uploaded as the `shard-logs-<node>-<tier>`
artifact on every outcome, including a cancel or the job cap.

Estimated wall time (from the measured weights, 1,006 executables): serial
3,913 s (lib Postgres prefixes 84 s, doc tests 16 s, 388 class-(a) binaries),
parallel about 1,620 s and 1,812 s. The parallel figures divide each binary's
seconds by min(its test count, 3) threads; the ideal at a flat
`--test-threads=3` is 1,620 s and 1,515 s, and a single-test binary gets no
speedup, so the true figure lies between the two. The federation-name rule keeps
47 binaries (about 437 s) in the serial shard on purpose.

Budget: `WATCHDOG_SECS` = 7800 s (130 min) per shard and job `timeout-minutes` =
160 min on both `enterprise-fed` legs (the watchdog plus 28 min of pre-watchdog
compile and database setup plus 2 min, meeting the ratio rule, #6411). This is 2x the longest-shard estimate (3,913 s), set for the first
measured run (#6344 review r2 F1; it was 5400 s / 120 min, 1.38x). The estimate
is soft: 56 % of it is class averages (217 of the 388 serial binaries have no
measured weight; the weights come from run 6160, which had 2 serial processes),
and the contention between shards (two jobs of three shards on one 14-core host)
is unmeasured. Real wall time is not verified until a CI run completes: after
the first green sharded run, read the per-shard `::notice::` lines, refresh the
weights, and re-derive the budget (the 20 % rule: raise it when a shard comes
within 20 % of the watchdog; lower it toward 1.4x the measured longest shard
once the figure is known). These numbers are pinned by
`scripts/ci/tests/test_ci_shard_wiring_6344.py`.

# Carrier-branch gates (#6143)

`chain/**` and `rehearsal/**` are `pull_request` base branches of the gating
workflows (for example `.github/workflows/c8-precheck.yml`). GitHub does not
re-run `pull_request` workflows when the base branch moves, so a green gate is
a verdict on the merge ref as it was built. On a base with no up-to-date-head
rule, a pull request can merge after the base moved without any gate judging
the tree that actually lands (#6143, found in the #6137/#6138 review).

## Repo-side control (this change)

`Carrier-base freshness gate (#6143)` (job `carrier-base-fresh-gate`,
`scripts/check_carrier_base_fresh.py`) fails closed when the merge commit the
job checked out is not built on the live tip of the carrier base. It fetches
the tip on every run, so re-running a stale green turns it red. Remedy printed
by the gate: `gh pr update-branch <PR>`, then wait for the new run.

It cannot close the window between job completion and the merge action; only a
ruleset with strict required status checks can.

## Ruleset the repository settings must carry (settings change, relayed)

A branch ruleset, enforcement `active`, separate from `signed-attested-branches`
(17752665), with:

- target `refs/heads/chain/**` and `refs/heads/rehearsal/**`;
- `required_status_checks` listing at least
  `Enterprise-federation cert-expiry gate (cert §7 / F7)` and
  `Carrier-base freshness gate (#6143)`, plus the carrier-applicable contexts
  in `scripts/qc-allowlists/required-contexts-release.txt`;
- `strict_required_status_checks_policy: true` (up-to-date head required).

Landing order follows the #3554 lockstep: ruleset first, then
`bash scripts/check-required-contexts-live.sh --pin-from-live`, then move the
job name from `required-contexts-not-required.txt` into
`required-contexts-release.txt` in the same commit as the pin.

Until the ruleset exists, the landing step must refuse a pull request whose
`mergeStateStatus` is `BEHIND` and run `gh pr update-branch` first.

## Verifying the live ruleset (read-only)

`python3 -I scripts/check_carrier_ruleset_live.py` reads the live rulesets
(never writes) and fails closed unless an active branch ruleset covers both
carrier patterns with strict required status checks and the contexts above. It
is not wired into pull-request CI while the ruleset does not exist (it would
fail every PR); run it after the ruleset is applied, then wire it.
