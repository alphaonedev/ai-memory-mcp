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
passed. It sits between the partitioner and the three shards, inside the
existing `Run tests (impact-aware)` step (tier `enterprise-fed` only; no job,
leg or step name changed).

**Key.** sha256 over: the sorted (repo-relative path, content sha256) of every
file in the executable's own cargo dep-info (`target/<profile>/deps/<name>-<hash>.d`,
including its `# env-dep:` lines with the checkout path normalised); the same
for the shared closure, the dep-info of every local lib, bin and build-script
unit (a test target's dep-info lists only its own sources, but it links the
lib, so a `src/` edit must invalidate every dependent); `Cargo.lock`; the
`rustc -Vv` text the workflow writes; the feature/profile string;
`AI_MEMORY_NO_CONFIG`, `RUSTFLAGS` and the presence (not the value) of
`AI_MEMORY_TEST_POSTGRES_URL`; and a digest of every file in the repository a
test could read at run time (everything except `.git`, `target`, `.local-runs`
and the compiled `.rs` under `src/` and `tests/`). An integration test whose
own sources look like a tree scanner (`read_dir`, `walkdir`, `glob`, a
`tests` path) is keyed on the whole tree including `.rs`, so a source-scanning
test is never skipped because some other file changed.

**Decision.** A binary is skipped only if its key equals the prior key AND the
prior result is `pass` AND the entry is for the same tier and base ref AND it
is less than 7 days old. `plan` rewrites the three shard lists (originals kept
as `*.txt.full`), prints `::notice::[#6384] skipped N of M binaries (cache hits),
running K`, and prints every hit with the prior `run_id`, `sha` and recorded
time inside a `::group::` so a reviewer can audit it. The lib counts as one
binary and leaves both lib invocations when it hits. Doc tests always run.

**Record.** After all three shards exit 0, `record` merges the new keys with
result `pass`. A skipped binary is carried forward unchanged (original
`run_id`, `sha`, `recorded_at`), so provenance stays traceable and a chain of
cache hits cannot extend a pass beyond 7 days. A binary without a computable
key loses its old entry. A failed or partial run records nothing.

**Safety rules (enforced in the script).**

1. The cache is consulted only when `CI_TEST_BINARY_CACHE=1`.
2. Never on `push` to `release/**` (the post-promotion run stays a full run);
   only on `pull_request` and `push` to `chain/**`.
3. A binary whose key cannot be computed (missing or unparsable `.d`, unreadable
   input) always runs; if the shared inputs cannot be computed, everything runs.
   Any internal error leaves the full lists untouched.
4. A manifest or entry older than 7 days, from another tier or base ref, or
   dated in the future is ignored.
5. Every hit is printed with its prior run and sha.
6. `record` refuses unless the step exit code is exactly 0.

**Storage.** A per-runner directory (`$CI_TEST_MANIFEST_DIR`, default
`$HOME/.cache/ai-memory-ci/test-manifest`), one JSON file per node, tier and
base ref, written atomically under an advisory lock. `ci.yml` has no
`actions/cache` precedent (only `Swatinem/rust-cache`, hosted legs only), the
enterprise-fed legs are self-hosted, and GitHub's cache scoping would hide an
entry saved by a push to `chain/x` from a pull request on another base. The
repository already documents why archive restores onto self-hosted trees are
unsafe (#3128). Linux and macOS never share a manifest (different hosts, and
the node is part of the file name).

**Expected effect.** A carrier PR whose merge tree equals a green chain tip
(same base ref manifest) skips nearly every binary and runs only the doc tests
and binaries without a computable key. A PR that edits `src/` invalidates every
key and runs the full suite. A PR that edits one `tests/*.rs` file reruns that
binary plus any tree-scanning binary. The base ref is `github.base_ref` for a
pull request and the branch name for a push, so a chain push and a PR only
share a manifest when they name the same base.

**Known limit.** A test that reads, at run time, a `.rs` file under `tests/`
or `src/` through a path the scanner heuristic does not recognise would not be
re-run when only that file changes. Add the marker string to its source (or
extend `TREE_SENSITIVE_RE`) when one is found.
