# CI hang-watchdog budgets by tier (#1492, #6202, #6344)

The full-suite step in `.github/workflows/ci.yml` ("full suite (cargo test)")
runs `cargo test --no-fail-fast` under GNU `timeout --signal=TERM
--kill-after=60 $WATCHDOG_SECS`. On tier `enterprise-fed` the suite runs as
three concurrent shards and `$WATCHDOG_SECS` bounds each shard's whole chain
(see [Sharded enterprise-fed suite (#6344)](#sharded-enterprise-fed-suite-6344)). On tier `sqlite` the
full suite runs as four sequential invocations, each under the same
`$WATCHDOG_SECS` and the suite margin gate (see [Sqlite suite margin gate and
shards (#9229)](#sqlite-suite-margin-gate-and-shards-9229)). The watchdog exists to catch a hung test and
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
| `linux-fed,enterprise-fed` | 7800 s (130 min) per shard | 300 (#7914) | longest shard estimate 3,913 s (serial) | not yet measured (first green sharded run) |
| `macos-fed,enterprise-fed` | 7800 s (130 min) per shard | 160 | n/a | n/a |

Ratio rule: job `timeout-minutes` >= watchdog minutes + 15. On the sharded
`enterprise-fed` legs the stricter rule applies: job `timeout-minutes` >=
watchdog minutes + 28 (pre-watchdog compile and database setup) + 2 (teardown)
= 160 (the linux-fed leg is 300 since #7914: it waits for a host-local semaphore slot, scripts/ci/host_semaphore.py, 2 slots, wait up to 600 s since #9231 (was 3600 s), counted against the cap; no slot ends as the named outcome `infra-no-slot` with exit code 82 (83 `infra-unknown-runner`, also for a `--name` that is not a plain gate name or not a gate of scripts/ci/host_slots.json, a repeated `--name`, a gate without a `serving_runners` list of strings, and a slot configuration that cannot be read or gives one key twice in an object, refused before any slot (#9846, #9851), 84 a command that exited with a reserved code, 85 `infra-wait-refused`: a wait above the 900 s ceiling of scripts/ci/host_slot_limits.py from any source, a repeated flag, or an empty, non-integer, 0 or negative wait, refused before any slot or command), the job and the gate stay red; identity: cap 18000 s >= load-gate wait 1200 + semaphore wait 600 + cold compile 4100 + safety 300 + serial shard 7800 (= 14000 s); the workflow call is a canonical form that scripts/ci/host_slots_check.py checks by allowlist (#9851): the token `host_semaphore` (searched with every character outside the canonical set deleted, so a name split by a quote or a backslash still counts) may appear, apart from the listed `HOST_SEMAPHORE_SLOTS`, `HOST_SEMAPHORE_MAX_WAIT_SECS` and `HOST_SEMAPHORE_HELD` names, only on a content line of a `run: |` literal block of a .yml or .yaml file; that line holds only letters, digits, space and `_ . / = : , -` (any other character, named by its code point, is a finding, so no quote, expansion, glob, comment, operator, escape or non-ASCII character reaches the grammar); its words, split on spaces, are `[exec] python3 [no-argument flags] scripts/ci/host_semaphore.py`, then only `--name`, `--max-wait-secs`, `--slots`, `--label` and `--poll-secs`, each with one word as its value (a next word that starts with `-` is never a value), then ` -- ` and a command; the checker judges what the runner executes (#9847): the parsed YAML `run` values (escapes such as `\x5f`, `\u005f` and `\U0000005f` decoded, block scalars folded, every backslash-newline continuation joined) must hold the same call lines, a joined line that holds the token is a finding, a decoded key or value that holds the token where no raw line does is a finding, and a file the YAML subset parser cannot read is a finding. Known limit: a script path the shell computes at run time is not text, so no text scan reads it; review is the defence there). All four rows meet both.

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
On tier `sqlite` that 20 % is enforced, not advisory: see the #9229 section
below.

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

### Load gate, serial-shard budget and cargo cap (#6795)

The 7800 s budget was measured on an idle host. On f1 at load ~100 (run
38015742119) the single-threaded serial shard ran 5-6x slower and the #1492
watchdog killed it, while `parallel_1` and `parallel_2` passed.

- **Load gate.** The `Load gate (#6795)` step runs immediately before `Run tests
  (impact-aware)` on the self-hosted legs only (`contains(matrix.runner,
  'self-hosted')`). `scripts/ci/load_gate.py` waits while the 1-minute load
  average exceeds 1.5 x cores (`--max-ratio`), for at most 1200 s
  (`--max-wait-secs`), polling every 30 s, and prints the measured load in a
  `::notice::`. It never fails on load alone: after the wait it warns and
  proceeds. Unit tests: `scripts/ci/tests/test_load_gate_6795.py`.
- **Job start anchor.** The first step of the `check` job (`Record job start
  (#6795)`) writes `JOB_T0` (epoch seconds) to `$GITHUB_ENV`, so every budget
  counts the real time since the job started, including the load-gate wait.
- **Serial shard budget.** The serial shard is the only shard that cannot be
  split further, so `SERIAL_BUDGET_SECS` = job `timeout-minutes` x 60 - (now -
  `JOB_T0`) - 300 s safety (floor 60 s). It is printed in a `[#6795] serial
  shard budget` notice. `parallel_1` and `parallel_2` keep `WATCHDOG_SECS` =
  7800 s.
- **Job-cap clamp.** Every shard budget and every non-sharded watchdog is
  clamped to min(its value, job time left - 300 s), so the named #1492
  watchdog always fires before GitHub's job cancel, whatever the gate waited.
  The matrix `timeout` values are not raised for the gate. Pinned by
  `scripts/ci/tests/test_ci_load_gate_wiring_6795.py`.
- **Operational cap.** Run at most 2 concurrent cargo lanes per host (f1 had 9
  cargo / 17 rustc processes during the failing run). This is a fleet rule for
  Modules, not enforced by the workflow.

### Manifest-inventoried paths (#8050)

- **Owning pin test.** Every file path inventoried by a
  `tests/fixtures/**/*.json` manifest (searched recursively; for example
  `sdk/typescript/src/wake.ts`) is gated by that manifest's `tests/qual_*.rs`
  test, even when the diff contains no Rust. The gate inventories every string
  in the manifest, object keys included. Each string is normalised: backslashes
  become `/`, surrounding whitespace is trimmed, `//` collapses, a leading `./`
  or `/` and a trailing `/` are stripped, literal `..` segments are resolved,
  and a string that leaves the repo root is ignored; matching is case-sensitive.
  A changed path is normalised the same way and
  matches when it equals the string or lies under it as a directory prefix, so a
  deleted or renamed path and a deleted directory are still gated. A diff that
  edits the manifest itself names its owning test. A lane and a reviewer must run
  `python3 scripts/ci/manifest_owned_paths.py --diff-file <changed files>` and
  then run and quote every `cargo test --test <qual>` it names before claiming
  gates green. Exit 0 means nothing inventoried changed, exit 1 means tests are
  named, exit 2 is a gate defect (unparseable manifest, manifest without an
  owning test, unreadable fixtures folder, a `.json` fixture a qual test includes
  that the walk never read, bad root or any internal error) and
  fails the check. Unit tests:
  `scripts/ci/tests/test_manifest_owned_paths_8050.py`.

## Sqlite suite margin gate and shards (#9229)

Invariant (ruling 17183e98): every sqlite test invocation of `Run tests
(impact-aware)` ends with at least 20 percent (`MARGIN_PCT`) of its per-invocation
watchdog budget left, and an invocation that loses the margin is a named red
before the watchdog kills it. The 2100 s budget is not raised: a raised
constant hides the growth.

- **Gate.** `run_tests` and `run_doc_tests` run the gate when the caller
  prefixes `SUITE_MARGIN_GATE=1` (every sqlite dispatch call; never
  `run_shard`, whose chains share one shrinking budget). `python3
  scripts/ci/suite_budget.py timer`, started beside the watchdogged `cargo
  test`, prints `::error::[#9229 margin] '<label>' lost the suite margin while
  still running: ...` (exit 3) once the wall passes 80 percent of the budget
  (at 1681 s of 2100 s: 1680 s still holds). The timer and the gate share one
  predicate, `margin_lost` (elapsed over the 1680 s deadline), so the two can
  never disagree at the boundary. After the invocation the step passes the
  timer's exit code to `suite_budget.py gate --timer-rc`: 3 (the timer fired)
  is the one red verdict and never a held notice, a killed timer is judged by
  the wall, and any other code is exit 2. Otherwise the gate prints `margin
  held: ...` as a notice, or fails the step with `::error::[#9229 margin]
  '<label>' lost the suite margin: ...` (exit 3) when the wall used more than
  80 percent even though every test passed, or when the watchdog killed it.
  The invocation's own non-zero exit (101, 124) wins over the gate's. The
  #1492 notice prints on every path that reaches the timed run, and the #6202
  notice only for a passing `run_tests` invocation (never in `run_doc_tests`);
  both print before either exit is returned. A failed prebuild (`cargo test
  --no-run`) returns its own code before the timer, the gate and the notices.
  Every such red carries
  `this red is issue #9229 (the cost of the sqlite suite), not a failure of the
  change under test` and then the binary still running and the slowest
  binaries of that invocation (`slowest binaries: none profiled` without a
  log), so a lane whose PR it fails on does not read it as its own defect. The
  gate covers the two impact-selected sqlite invocations as well. Every
  subcommand ends 0, 2 or 3 with a named reason for any input (invalid dates,
  overflow digits, NUL bytes, empty or 100K+ line logs, malformed arguments);
  malformed input is exit 2 with a named error, never a traceback or a pass.
  Each reason is the gate's own fixed text, with no exception class name,
  standard-library message or argparse wording, so a line reads the same on
  every runner image: an unreadable file is `cannot be opened or read` or
  `unreadable or not UTF-8`, a bad cargo metadata file is `unreadable, not
  UTF-8, or not JSON within the decoder's depth`, a bad argument is one line
  per kind (`argument --elapsed: not an integer of at most 18 ASCII digits`,
  `argument cmd: missing, or not one of its allowed values`, or `the argument
  list is not a suite_budget command line`) and an unforeseen exception is
  `internal error`. No `#9229` annotation contains a percent sign (the 9365 escaper turns it
  into `\x25`), so every percentage is written as `N percent`.
- **Whole-suite ceiling** (ruling cdfe800f). Four budgets of 2100 s must not
  become a silent 8400 s suite: the sum of the full suite's invocations is
  checked against one constant, `WHOLE_SUITE_CEILING_SECS` (3600 s). Before
  the first invocation `suite_budget.py suite-plan` reads the timeout of job
  `check` for the running leg from `ci.yml` (`timeout-minutes`, or the
  matrix leg's `timeout`) and requires the ceiling plus the same 20 percent margin
  to fit it (at most 4560 s of the 95-minute ubuntu-latest leg, 3840 s of the
  80-minute macos-fed leg); a ceiling that cannot fit is a named red (exit 3)
  before any test runs, never a job kill, and an absent or unreadable timeout
  is exit 2. Each gated invocation appends `<seconds><TAB><label>` to the
  bash array `SUITE_SECONDS` of the step shell (no file: a test process can
  write anything under `RUNNER_TEMP`, so no file there is an input of the
  verdict); after the last one `suite_budget.py suite-sum --expect N -- <rows>`
  prints the sum and each invocation's seconds, and a sum over the ceiling is
  a named red (exit 3). N is the number of invocations the step ran (4 for the
  shards, 1 for the fallback); a row count other than N, an empty, non-numeric
  or negative seconds value, or a duplicated label is exit 2 with a named
  reason. The unsharded fallback is checked the same way. An invocation that
  ended before its gate (a failed prebuild) keeps no row: when the step's
  exit code is already non-zero and fewer than N rows were kept, the sum is
  not judged and the step prints one notice, `::notice::[#9229 margin] whole
  sqlite suite: not judged, an invocation ended before its gate (rc <rc>);
  <k> of <N> invocation rows kept (#9229)`, and ends with the first failing
  code unchanged; with exit code 0 a short count stays the exit-2 red.
- **Shards.** The full suite runs as four sequential invocations of the same
  test set as one `cargo test`, each with its own budget: `--lib` (lib unit
  tests), then every other target of cargo's default test selection (bins,
  `tests/*.rs`, examples with `test = true`) in two round-robin parts
  (`shard-args --part 1/2` and `--part 2/2`, disjoint and complete), then
  `--doc`. The target list is derived from `cargo metadata --no-deps` by
  `suite_budget.py shard-args`, so a new `tests/*.rs` is never missed; a target with unmet `required-features` is
  skipped exactly as cargo's default selection skips it. A manifest it cannot
  judge (a part that selects nothing, no single default member, not exactly one lib with test and doctest
  on, an unknown target kind, a name outside `[A-Za-z0-9_-]` or with a leading
  dash, a dependency feature) prints a `::warning::` and the step runs the one
  unsharded invocation, still gated; a failed `cargo metadata` prints
  `::warning::[#9229 margin] cargo metadata failed (rc N); the full suite runs
  unsharded, gated (#9229)` before that fallback. A failed shard does not stop the later
  ones (#2500); the step fails if any did. Job names, check names, matrix legs
  and every ceiling are unchanged.
- **Estimate.** From the per-binary seconds of run 44041202670 (the killed
  run, 2097 s summed): lib 629 s (30 percent of 2100 s), part 1/2 577 s
  (27 percent), part 2/2 867 s (41 percent), doc tests a few seconds. With the
  measured 30 percent hosted variance the largest invocation reaches about
  54 percent, inside the 80 percent line. A single non-lib invocation would
  have been 1444 s (69 percent), which that variance pushes past 80 percent.
- **Per-binary profile.** `suite_budget.py profile --log <job log>` ranks the
  binaries of a saved job log by wall seconds (timestamped lines) or by
  libtest's `finished in`.

Unit tests: `scripts/ci/tests/test_suite_budget_9229.py` (judge table and
boundary, CLI texts, timer, profile with a 200k-line time bound, shard
derivation and its two parts over the real manifest, the whole-suite ceiling
and plan, the step executed with a stub cargo, wiring pins) and
`scripts/ci/tests/test_suite_budget_9229_integrity.py` (a table of every exit
code propagation site of the step, each mutant proven red; each shard failing
in turn ends the step with 101; sum completeness; a hostile input corpus with a
time bound; the one boundary at 1679 / 1680 / 1681 s and 3600 / 3601 s; no
percent sign in any annotation; the #1492 notice on every path that reaches
the timed run). The stub cargo of both files advances a clock file by a fixed
number of seconds per timed run, so the tests assert exact non-zero walls.
