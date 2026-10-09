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

## Per-test-binary result cache (#6384)

`scripts/ci/test_binary_cache.py` skips a test executable when it provably
would run the same code against the same inputs as a binary that already
passed. It sits between the partitioner and the three shards (and before the
Postgres isolation split), inside the existing `Run tests (impact-aware)` step
(tier `enterprise-fed` only; no job, leg or step name changed).

**Key.** sha256 over: the sorted (repo-relative path, content sha256) of every
file in the executable's own cargo dep-info (`target/<profile>/deps/<name>-<hash>.d`,
including its `# env-dep:` lines with the checkout path normalised); the same
for the shared closure, the dep-info of every local lib, bin and build-script
unit (a test target's dep-info lists only its own sources, but it links the
lib, so a `src/` edit must invalidate every dependent); the cfgs, env and
`output` file of every local build-script run; `Cargo.lock`; the
`rustc -Vv` text the workflow writes; the feature/profile string; the
behaviour-affecting environment (every `AI_MEMORY_*`, `RUST_TEST_*`,
`CARGO_PROFILE_*`, `CARGO_BUILD_*` and `PROPTEST_*` variable plus `CI`,
`RUSTFLAGS`, `RUST_LOG`, `TZ` and a few more: the value's sha256 for a plain
setting, only set or empty for a name containing `URL`, `PASSWORD`, `SECRET`,
`TOKEN`, `KEY` and similar); the Postgres server identity (`SELECT version()`
and the installed `age` and `vector` extension versions, or `none` when no
`AI_MEMORY_TEST_POSTGRES_URL` is set; a failed query disables the cache for
the run); and a digest of every file in the repository a test could read at
run time. That digest leaves out `.git`, `target`, `.local-runs`, the `.rs`
files under `src/` and `tests/` that some dep-info of the build names (an
orphan or cfg-off `.rs` file stays in), and `changelog.d/`, `docs/` and every
`*.md` file. Those documentation files are in the key only of a binary whose
own code (not a `//` comment) names `changelog`, `docs` or `.md`. An
integration test whose own sources look like a tree scanner (`read_dir`,
`walkdir`, `glob`, a `tests` path) is keyed on the whole tree, so a
source-scanning test is never skipped because some other file changed. The
walk never opens a FIFO, socket or device, and the whole plan has a 120 s
deadline; on expiry, or on any other failure, the full lists run.

**Who reads and who writes.**

* `pull_request`: lookup only, under `github.base_ref`. A pull request
  never writes the manifest: its test code is unmerged.
* `push` to `release/**`: the seeding run. Lookup is off (every binary runs)
  and the results of a fully green step are recorded under the branch name.
* Every other event, `chain/**` pushes included: no lookup, no record.

Lookup needs two flags: `CI_TEST_BINARY_CACHE=1` and
`CI_TEST_BINARY_CACHE_LOOKUP=1`. `ci.yml` sets the second one for
`pull_request` only, so it is `0` on every push to `release/**`, and the
script itself grants lookup on `pull_request` only.

**Decision.** A binary is skipped only if its key equals the recorded key AND
the recorded result is `pass` AND the entry is for the same tier and base ref
AND it is less than 7 days old. `plan` rewrites the three shard lists
(originals kept as `*.txt.full`), prints `::notice::[#6384] skipped N of M
binaries (cache hits), running K`, and prints every hit with the recorded
`run_id`, `sha` and time inside a `::group::` so a reviewer can audit it. The
lib counts as one binary and leaves both lib invocations when it hits. Doc
tests always run. If `plan` fails or is killed, `restore` puts the
`*.txt.full` lists back; a failed restore fails the step.

**Record.** After all three shards of a `release/**` push exit 0, `record`
writes every computed key with result `pass` and that run's `run_id` and
`sha`. A binary without a computable key loses its old entry. A failed or
partial run records nothing.

**Safety rules (enforced in the script).**

1. The cache is consulted only when `CI_TEST_BINARY_CACHE=1`; lookup also
   needs `CI_TEST_BINARY_CACHE_LOOKUP=1` and a `pull_request` event.
2. No run both looks up and records, so a recorded `pass` always comes from a
   run that executed that binary.
3. A binary whose key cannot be computed (missing or unparsable `.d`, unreadable
   input) always runs; if the shared inputs cannot be computed, everything runs.
   Any internal error leaves the full lists untouched.
4. A manifest or entry older than 7 days, from another tier or base ref, or
   dated in the future is ignored.
5. Every hit is printed with its recorded run and sha.
6. `record` refuses unless the step exit code is exactly 0.

**Storage.** A per-runner directory (`$CI_TEST_MANIFEST_DIR`, default
`$HOME/.cache/ai-memory-ci/test-manifest`), one JSON file per node, tier and
base ref, written atomically under an advisory lock. `ci.yml` has no
`actions/cache` precedent (only `Swatinem/rust-cache`, hosted legs only), the
enterprise-fed legs are self-hosted, and GitHub's cache scoping rules differ
per base. The repository already documents why archive restores onto
self-hosted trees are unsafe (#3128). Linux and macOS never share a manifest
(different hosts, and the node is part of the file name).

**Expected effect.** Hits happen only for a pull request into a `release/**`
branch, and only for binaries whose inputs equal those of the last green push
to that branch on the same node and tier within 7 days. A pull request that
changes only `changelog.d/`, `docs/` or `*.md` files skips every binary whose
code does not name them. A pull request that edits one `tests/*.rs` file
reruns that binary plus every tree-scanning binary. A pull request that edits
`src/`, `Cargo.lock`, the toolchain, the environment or the Postgres server
reruns everything. Pull requests into `chain/**` and pushes never skip.

**Known limit.** A test that reads, at run time, a `.rs` file under `tests/`
or `src/` through a path the scanner heuristic does not recognise would not be
re-run when only that file changes. Add the marker string to its source (or
extend `TREE_SENSITIVE_RE`) when one is found. The same applies to a test that
reads documentation through a path that names none of `changelog`, `docs` or
`.md` (extend `DOC_READER_RE`).
