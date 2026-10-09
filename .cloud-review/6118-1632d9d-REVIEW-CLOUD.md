# Cloud review fix/6118-promo6-ssh head 1632d9d29: VERDICT APPROVE

Reviewer: cloud lane `rev-6118` (Claude Code sandbox, 4 cores / 15 GiB, rustc 1.98.0, python 3.11/3.12/3.13, sqlite only).
Subject: `fix/6118-promo6-ssh` head `1632d9d295407b048d86bacd0b7827ea8147001e`, eight commits on base
`chain/promo6-ssh` = `fa6b588e6b5dfa97370b4f073e60e66cb1ed1fa7`. Diff: 9 files, +1103 / -19; no `.rs`, `Cargo.toml` or
`Cargo.lock` change (verified: `git diff <base>..HEAD --stat -- '*.rs' Cargo.toml Cargo.lock` is empty).

Verdict rationale. The branch does what issue #6118 asks: every self-hosted cargo job pins debuginfo `0` (DEV + TEST
pair) and ends with an `always()` prune step; the prune script is fail-closed on non-cargo dirs, keeps the warm cache,
and never left the resolved target dir in any adversarial tree I built. The measurement claim reproduces within noise
(see §Measurement). The 20 tests are red on the base and green on the tip, and every mutation in the brief is caught
by a named rule. Nothing found is a blocker; the findings below are a porous closed-world census (F1, the one I would
fold in before merge), one dead code path plus docs claim on example executables (F2), one docs-truth defect on symlink
following (F3), and ops/evidence gaps (F4-F7).

## Findings

Ranked. Severity scale: High (blocks), Medium (fold in before merge), Low (fix in a follow-up commit on the same
branch), Info (record).

### F1 Medium — the R-CENSUS closed-world claim is porous: six self-hosted-cargo shapes evade the reader
- File: `scripts/test/test_ci_runner_target_hygiene_6118.py:82` (`CARGO_RE`), `:117-127` (`self_hosted`,
  `can_be_hosted`), `:249-255` (strategy reader collects only the `runner:` key).
- What: the docstring (lines 15-19) promises "a new self-hosted cargo job cannot appear without being pinned here".
  Ad-hoc mutations (`.local-runs/rev-6118/mutate2.py`, a synthetic `fleet.yml` added to the live set) show the census
  does not see:
  1. `runs-on: [linux-fed]` or `runs-on: macos-fed` (a bare fleet label without the literal `self-hosted` word; GitHub
     accepts custom labels alone) — MISSED.
  2. `runs-on:` in mapping form (`labels: [self-hosted, linux-fed]` or `group: fleet`) — MISSED (`runs_on` reads "").
  3. `runs-on: ${{ matrix.os }}` with the label list under any matrix key other than `runner` — MISSED.
  4. `cargo +nightly test`, `"$CARGO" test`, `cargo run --bin` — MISSED (`CARGO_RE` requires `cargo\s+(test|build|...)`
     and omits `run`).
  5. cargo reached through a wrapper (`bash scripts/x.sh`, e.g. `scripts/coverage.sh` runs `cargo llvm-cov`) — MISSED.
  6. cargo inside a composite action (`uses: ./.github/actions/cargo` + `with: args:`) — MISSED.
  Caught (for the record): `timeout 600 cargo test`, `cargo  test` (double space), `cargo llvm-cov`, the `runner:`
  matrix key convention, and a plain `runs-on: [self-hosted, linux-fed]` job.
- How reproduced: `python3 -I .local-runs/rev-6118/mutate2.py` (output in §Evidence 5).
- Fix size: ~15 lines in the test. Treat any of `self-hosted|linux-fed|macos-fed` in the raw `runs-on` text, in any
  matrix-include value, or in a `labels:` row as self-hosted; widen `CARGO_RE` to `cargo(\s+\+\S+)?\s+(test|build|run|
  llvm-cov|bench|nextest)` and to `\$CARGO`; and count any `scripts/` or `uses: ./` invocation in a self-hosted job as
  cargo-capable (require the pin). Add one mutant per shape.

### F2 Low — example executables are never pruned on a real cargo tree; the "examples executable" category and the
docs claim are dead
- File: `scripts/ci/prune-runner-target.py:114-120` (`_is_hard_linked`), `:135` (scans `examples`);
  `docs/DEV-CI-ENVIRONMENT.md:125`; `changelog.d/6118.fixed.md:9`; the test fixture
  `scripts/test/test_ci_runner_target_hygiene_6118.py:503` (`debug/examples/demo-1e1e` with nlink 1).
- What: cargo uplifts every example by hard-linking `examples/<name>-<hash>` to `examples/<name>`, so both names have
  nlink 2 and the hard-link keep rule (commit 370738bb) keeps both. `cargo test` builds all 7 examples of this crate
  (`Cargo.toml:450`, `examples/*.rs`), so on the fleet the `examples executable` category can only ever be empty, while
  the runbook and changelog say "deletes the test/example executables". The fixture models a non-uplifted example that
  cargo never produces.
- How reproduced: fake tree (`.local-runs/rev-6118/fake_tree.py`): `examples/demo2-2e2e` + `examples/demo2` (nlink 2)
  both survive the default scope with the message `kept hard-linked uplift source examples/demo2`; non-uplifted
  `examples/demo-1e1e` is deleted. Real tree (`td-zero`, `cargo build --example atomise_roundtrip`):
  `examples/atomise_roundtrip` and `examples/atomise_roundtrip-c05d61ed98a7794c` are both 29,336,360 B with nlink 2,
  and the prune dry-run prints `kept hard-linked uplift source examples/atomise_roundtrip` for each — confirmed.
- Fix size: either 3 lines of docs (drop "example" from the claim; the examples are small at `0`) or ~10 lines in the
  script to delete the `examples/<name>` + `examples/<name>-<hash>` pair together (cargo re-uplifts on the next build).
  Either way, change the fixture to the real nlink-2 layout so the test pins the real behaviour.

### F3 Low — docs say "never follows a symlink"; a symlinked target root is followed
- File: `scripts/ci/prune-runner-target.py:221` (`root = raw.resolve(strict=True)`), docstring `:38-40`;
  `docs/DEV-CI-ENVIRONMENT.md:131-132`; `changelog.d/6118.fixed.md:11-12`.
- What: the host security review's Low #2 as a docs-truth defect: three published sentences state the script never
  follows a symlink, and the root is followed. The fail-closed intent is cheap to make true.
- How reproduced: `ROOT-IS-SYMLINK` case in `.local-runs/rev-6118/fake_tree.py`: `target -> real-target`, run default
  scope: rc 0, `real-target/debug/deps/test-exe-1234` deleted, real tree hash changed. (For contrast, a symlinked
  `debug/` or `debug/deps` is correctly skipped: rc 0, `freed_bytes=0`/`5`, outside hash unchanged.)
- Fix size: 2 lines (`if raw.is_symlink(): return _refuse(...)` before `resolve`) + 1 test; then the three sentences
  become true without edits.

### F4 Low — no guard against a shared or out-of-workspace `CARGO_TARGET_DIR`
- File: `.github/workflows/ci.yml:1550` (and the three sibling steps): `--target-dir "${CARGO_TARGET_DIR:-target}"`.
- What: the step honours a runner-side `CARGO_TARGET_DIR` verbatim. The f2 host runs two runners; the moment an
  operator points both at one shared target dir (the obvious "halve the 164 GB" optimisation the issue text invites),
  runner A's end-of-job prune deletes the test executables runner B's in-flight `cargo test` is about to execute
  (`cargo test` links first, then runs; the harness binaries are opened by path at run time). Today each runner has its
  own `_work/.../target`, so this is latent, not live.
- How reproduced: by reading; the script has no notion of workspace. `_inside` only protects against leaving the
  given dir.
- Fix size: ~6 lines in the script (`--workspace "$GITHUB_WORKSPACE"`; refuse when the resolved target dir is not under
  it unless `--allow-outside-workspace`) + 1 test, and the four step lines.

### F5 Low — migration: the previous-level rlib trees are not removed by the default scope; the runbook does not say so
- File: `docs/DEV-CI-ENVIRONMENT.md:102-108` ("one level means one tree"), `changelog.d/6118.fixed.md:14-18`.
- What: the claim holds going forward only. The default scope keeps every rlib/rmeta/build/fingerprint tree,
  including the `line-tables-only` tree the `check` job wrote on linux-fed and macos-fed and the cargo-default tree
  `session-boot-lifetime` wrote on macos-fed. The issue's mitigation wiped both linux-fed runners
  (`runner_target_prune.py --days 0`); the macos-fed (f1) `target/` was not named in the issue and keeps two stale
  trees (3.4 GB + 6.2 GB of `deps` by the branch's own table) until someone runs `--scope all` once.
- How reproduced: by reading `_candidates_test_bins` (keeps everything with a KEEP suffix regardless of hash) and the
  issue text (mitigation scoped to f2).
- Fix size: 3 lines in the runbook ("one-time per fleet runner after this lands: `python3 scripts/ci/
  prune-runner-target.py --target-dir <...> --scope all`") and the operator one-liner on the macos-fed node.

### F6 Low — the issue's acceptance step "Verify with a before/after du on one runner job" has no fleet evidence yet
- File: issue #6118 proposed-fix text; the branch's numbers are sandbox measurements (`docs/DEV-CI-ENVIRONMENT.md:
  109-115`).
- What: the prune step prints `freed_bytes=<n>` into the step log only. There is no `::notice::` line, so the first
  fleet run's evidence has to be dug out of a 1000-line step log.
- Fix size: 1 line in the script (`print("::notice::prune-runner-target freed %s ..." % ...)`) or f1 captures the
  first run's `freed_bytes=` line into the issue close comment.

### F7 Info — `changelog.d/3461.fixed.md:9-10` still states the `check` job declares `line-tables-only`
- What: if #3461 and #6118 ship in the same release, the compiled changelog says both `line-tables-only` and `"0"` for
  the same env pair. The 6118 fragment does say the level moved; the 3461 fragment does not point forward.
- Fix size: 1 parenthetical in the 3461 fragment ("superseded by #6118: `"0"`").

### F8 Info — a same-commit re-run now re-pays the lib unit-test harness compile (~280 s single-threaded here)
- File: design of the default scope (`scripts/ci/prune-runner-target.py:17-24`).
- What: the lib unit-test binary is one rustc compile+link unit of the whole crate with `cfg(test)`; deleting it
  means the next `cargo test` on an UNCHANGED commit (re-run of a flaky job) recompiles it (280 s on 4 sandbox cores,
  1 `Compiling` line, 530 dependency units warm). The ~1000 integration binaries relink in ~2 s each. On a new commit
  the lib changes anyway, so the steady-state cost is nil; this is the quantified price of re-runs. Not a defect;
  recorded so the number is on file if the #1492 watchdog margins are revisited.

### Host-review Lows, re-checked (not re-counted above)
- TOCTOU on delete-by-path: confirmed by reading; `_delete` uses `os.remove`/`shutil.rmtree` on a path classified
  earlier. Accepted at this blast radius (the runner user owns the tree).
- Uncaught `OSError` fails the `always()` step: confirmed by reading (`_delete` has no `try`). Could not reproduce
  under the sandbox's uid 0 (a read-only parent does not block root; see §Evidence 3).
- Prune runs on legs where checkout was refused: confirmed by reading `ci.yml:1548` — the fork-PR refusal step (`:817`)
  fails the job, `always()` still fires, and `python3 scripts/ci/prune-runner-target.py` then fails with "No such
  file" on an empty workspace. The job is already red, so the only cost is a misleading second failure line.

## Evidence

### 1. Measurement reproduction (lens 1)
Command per level, fresh `CARGO_TARGET_DIR` each, `AI_MEMORY_NO_CONFIG=1`, only `CARGO_PROFILE_DEV_DEBUG` set (TEST
left unset on purpose, see lens 2):
```
cargo test --no-run -p ai-memory --lib -v        # CARGO_TARGET_DIR=.local-runs/rev-6118/td-{default,zero,lto}
```
Wall clock (4 cores): default 483 s, `0` 372 s, `line-tables-only` 392 s; 530 rustc invocations each. Then one
integration test binary was linked into each tree (`cargo test --no-run -p ai-memory --test
mcp_input_schema_no_false_strict_1052`, the same binary the author measured). All three dirs fit (11G + 6.5G + 5.4G).

| level (`CARGO_PROFILE_DEV_DEBUG`) | `du -sb debug/deps` | `du -sb debug` | largest file in `deps` | lib unit-test binary | integration test binary |
|---|---:|---:|---|---:|---:|
| unset (cargo default, `-C debuginfo=2`) | 5,784,226,023 | 10,219,051,104 | `libai_memory.a` 1,659,180,372 | `ai_memory-975e3f84…` 920,589,296 | 511,033,296 |
| `line-tables-only` | 3,142,149,377 | 6,461,036,652 | `libai_memory.a` 818,606,912 | `ai_memory-60839f7e…` 411,426,664 | 130,165,008 |
| `0` (no `-C debuginfo` flag emitted) | 2,328,806,878 | 5,121,225,811 | `libai_memory.a` 627,977,980 | `ai_memory-bda7e1f5…` 257,919,368 | 11,582,112 |

Ratios: integration binary `line-tables-only`/`0` = 11.24x (author: 130,090,392 → 11,606,440 B, 11.2x — reproduced
to 0.1 %); default/`0` = 44.1x; lib unit-test binary 1.60x; `debug/deps` 1.35x (default/`0` 2.48x). The author's
table (`docs/DEV-CI-ENVIRONMENT.md:112-115`: 484 MB / 130 MB / 11.6 MB; 889 / 411 / 258 MB; 6.2 / 3.4 / 2.4 GB) agrees
within the sandbox-to-sandbox noise of the `--test` set (this run: 511 / 130 / 11.6 MB; 921 / 411 / 258 MB;
5.8 / 3.1 / 2.3 GB). The largest file in `deps` at every level is `libai_memory.a` (the `staticlib` crate-type,
`Cargo.toml:675`), which the prune keeps by suffix; it is rewritten in place per commit (metadata hash is stable), so
it does not accumulate.
Link / relink cost at `0`: the integration binary links in 3 s and relinks in 2 s after a prune-style delete (same at
the other two levels); the lib unit-test harness is one rustc compile+link unit and takes 280 s single-threaded to
rebuild after the prune (`post-prune cargo test --no-run --lib`: 1 `Compiling` line, the 530 dependency units stayed
warm). That is the price a same-commit re-run now pays; a new commit paid it already.

### 2. Env semantics (lens 2)
Proof from the `-v` logs (`.local-runs/rev-6118/build-{default,zero,lto}.log`), with ONLY `CARGO_PROFILE_DEV_DEBUG`
set (TEST deliberately unset):
```
default : rustc --crate-name ai_memory … --test … -C debuginfo=2            (only flag value in the whole log)
lto     : rustc --crate-name ai_memory … --test … -C debuginfo=line-tables-only
zero    : rustc --crate-name ai_memory … --test …   (no -C debuginfo flag anywhere in the log: cargo omits it at 0)
```
So the `test` profile's harness compile (`--test`) took the level from `CARGO_PROFILE_DEV_DEBUG` alone — the env
applies to `cargo test` through `test.inherits = dev`, and the `TEST` pair member in the workflows is belt-and-braces
(per the #3461 pair rule), not load-bearing today.
Cargo book, quoted verbatim:
- config.md, "Environment variables": "Environment variables will take precedence over TOML configuration files."
- config.md, `[profile]`: "The `[profile]` table can be used to globally change profile settings, and override settings
  specified in `Cargo.toml`." Entry `profile.<name>.debug` — "Environment: `CARGO_PROFILE_<name>_DEBUG`".
- profiles.md: "The `test` profile is the default profile used by `cargo test`." with `[profile.test] inherits = "dev"`;
  "Specifying a profile in a config file or environment variable will override the settings from `Cargo.toml`."
- profiles.md `debug` values: "`0`, `false`, or `"none"`: no debug info at all"; "`"line-tables-only"`: line tables
  only. Generates the minimal amount of debug info for backtraces with filename/line number info"; "`2`, `true`, or
  `"full"`: full debug info, default for `dev`".
Repo side: `.cargo/` exists but holds no `config.toml` (`ls -la .cargo` → empty); `Cargo.toml` declares only
`[profile.release]` (`:576`) and `[profile.coverage]` (`:634`, `inherits = "dev"`, `debug = 1`), so nothing in the
manifest sets `dev.debug` or `test.debug`, and even if it did the env would win per the quotes above. The `coverage`
profile pins its own `debug = 1` and runs hosted only, so the env does not touch it.

### 3. Prune script on adversarial fake trees (lens 3)
`python3 -I .local-runs/rev-6118/fake_tree.py` (full log: `.local-runs/rev-6118/fake.out`). Outside-tree sha256 is
taken before and after every run.

| tree / mode | rc | deleted | survived (notable) | outside hash |
|---|---|---|---|---|
| MAIN `--dry-run` | 0 | nothing (24/24 survive); `freed_bytes=32550` listed | all | unchanged |
| MAIN default | 0 | `deps/foo-0123abcd`, `.d`, `.dSYM/` (whole), `deps/baz-9876` (its `.d` is a symlink → skipped), `examples/demo-1e1e` + `.d`, `incremental/foo-abc/` ; `freed_bytes=32550` | `deps/ai_memory-aaaa1111` (nlink 2) + `debug/ai-memory`, `libbar-ffff.rlib` (exec bit, kept by suffix), `libpm-1234.so` (exec bit, kept), `deps/plain-noexec-5555`, `deps/evil-link` (symlink, skipped), `incremental/evil-dir-link` (symlink, skipped), `build/xyz-9999/build-script-build`, `.fingerprint/`, `release/deps/ai_memory-rrrr`, `examples/demo2` + `demo2-2e2e` (nlink 2) | unchanged |
| MAIN `--scope all` | 0 | all 21 entries under `debug/{deps,build,incremental,examples,.fingerprint}` incl. the two symlinks (removed as links); `freed_bytes=59977` | `CACHEDIR.TAG`, `debug/.cargo-lock`, `debug/ai-memory` (uplift, nlink→1), `release/…` | unchanged |
| `debug/deps` is a symlink, default | 0 | `incremental/x/` only (`freed_bytes=5`) | the `deps` symlink and everything behind it | unchanged |
| `debug/deps` is a symlink, `--scope all` | 0 | `incremental/` only | the `deps` symlink (skipped, not even unlinked) | unchanged |
| `debug/` is a symlink, default and all | 0 | nothing (`freed_bytes=0`) | all (`_inside` rejects the resolved parent) | unchanged |
| `target` is a symlink, default | 0 | `real-target/debug/deps/test-exe-1234` | — | real tree hash CHANGED (F3) |
| non-cargo dir, all three modes | 2 | nothing | all; stderr `refusing: … has neither CACHEDIR.TAG nor debug/.cargo-lock` | unchanged |
| relative `--target-dir target` (cwd = tree parent), dry-run | 0 | — | resolves against cwd, same 32550 bytes listed | — |
| `--target-dir <base>/outside/../target`, dry-run | 0 | — | resolved, same listing | — |
| `--target-dir ../relpath/target` (cwd = sibling), default | 0 | same 7 entries as MAIN default | — | unchanged |
| `--profile ..` / `--profile ../outside` | 2 | nothing | stderr `--profile must be one path component` | — |
| `--profile release` (has `CACHEDIR.TAG`, no `release/.cargo-lock`) dry-run | 0 | would delete `release/deps/ai_memory-rrrr` | — | — |
| read-only `.dSYM/Contents` parent (OSError probe) | 0 | everything, as uid 0 ignores mode bits | — | inconclusive as root |

Nothing outside the given directory was touched in any run except the symlinked-root case, where the given
directory *is* the real tree after `resolve`.

### 4. Executable classification (lens 4)
Rule (`prune-runner-target.py:105-120`): regular file AND not a symlink AND name does not end in one of
`.rlib .rmeta .so .dylib .dll .a .d .o .dwo .dwp .pdb` AND any of `S_IXUSR|S_IXGRP|S_IXOTH` set AND `st_nlink == 1`.
No name regex, no magic bytes.
- False positive constructed: an uplifted bin whose `debug/<bin>` copy is gone (nlink falls to 1) is classified as a
  test executable and deleted. Reproduced on `td-zero`: after `rm debug/ai-memory`, `--dry-run` lists
  `debug/deps/ai_memory-df6f38b7df65bee3` (174,152,440 B, the bin, nlink now 1) next to the genuine test executables;
  `cargo build --bin ai-memory` afterwards recreated the uplift in 144 s. Benign: cargo's fingerprint sees the missing
  output and relinks; the only cost is that link.
- False negative constructed: a test executable with nlink > 1 is kept (the rule cannot tell an uplift from a `cp -l`
  copy); and every uplifted example (F2). Also outside the rule by design: binaries under any profile dir other than
  `--profile debug` (`target/release`, `target/coverage`, `target/llvm-cov-target`), and a `.d` orphaned by an earlier
  partial run (40 B, never reclaimed).
- Real-tree check (`td-zero`): lib unit-test binary nlink 1 (deleted), integration test binary nlink 1 (deleted),
  `debug/ai-memory` ↔ `deps/ai_memory-df6f…` nlink 2 (kept), `examples/atomise_roundtrip` ↔ `…-c05d…` nlink 2 (kept).
  Real prune run: `deps executable 3  423.1 MiB` (lib test 258 MB + the stale bin 174 MB + integration 11.6 MB),
  `deps dep-info 3`, `incremental 9  3.5 GiB` (sandbox default `incremental = true`; the fleet sets
  `CARGO_INCREMENTAL=0`, so this category is empty there), `freed_bytes=4222496308`; `du -sb debug` before/after
  delta 4,222,426,700 (the 69,608 B gap is directory inodes). Second run frees 0. `.rlib`/`.rmeta`/`.a`/`build/`/
  `.fingerprint/` untouched, and the next `cargo test --no-run --lib` recompiled only the `ai-memory` test harness.

### 5. Red-on-base, green-on-tip, mutations (lens 5)
```
# base worktree at fa6b588e with the test file copied in
$ python3 -I scripts/test/test_ci_runner_target_hygiene_6118.py   → Ran 20 tests ; FAILED (failures=17)
```
Failing on base: `test_6118_live_workflows_clean`, `test_6118_control_unmutated_is_clean`, `m01`…`m05`,
`test_6118_default_scope_prunes_test_bins_and_keeps_the_warm_cache`, `_dry_run_deletes_nothing_and_reports_bytes`,
`_hardlinked_uplift_copy_is_kept_and_not_counted`, `_missing_profile_subdirs_are_not_an_error`,
`_refuses_missing_dir`, `_refuses_non_target_dir`, `_relative_target_dir_resolves_against_cwd`,
`_scope_all_wipes_the_five_dirs_only`, `_script_exists_and_is_python3_stdlib`. The three that pass on base
(`census_matches_live_runs_on`, `m06`, `m07`) exercise the reader only and are expected to be base-independent.
```
$ python3 -I scripts/test/test_ci_runner_target_hygiene_6118.py -v   (tip, 3.13)  → Ran 20 tests ; OK
$ python3.11 -I scripts/test/test_ci_runner_target_hygiene_6118.py    (tip, 3.11)  → OK
```
Brief mutations, each applied to EVERY one of the four workflows (`.local-runs/rev-6118/mutate.py`), rule that fires:
| mutation | ci.yml | cert-postgres-age | postgres-ignored | session-boot-lifetime |
|---|---|---|---|---|
| remove `CARGO_PROFILE_DEV_DEBUG` row | R-DEBUG `is None` | same | same | same |
| remove `CARGO_PROFILE_TEST_DEBUG` row | R-DEBUG `is None` | same | same | same |
| `"0"` → `"1"` | R-DEBUG `is '1'` | same | same | same |
| `"0"` → `line-tables-only` | R-DEBUG | same | same | same |
| `"0"` → unquoted `0` | accepted (correct: same env string) | same | same | same |
| delete the prune step | R-PRUNE `last step is 'Cleanup enterprise-fed ephemeral db'` | same | same | `'Run lifetime suite'` |
| drop `always()` | R-PRUNE `lacks always()` | same | same | same |
| drop `--target-dir` | R-PRUNE `does not run … --target-dir` | same | same | same |
| step appended after the prune | R-PRUNE (m05 form) | R-PRUNE | R-PRUNE | R-PRUNE |
| cargo moved into a wrapper script + env + prune removed | — | — | — | R-CENSUS `expected … not found` |
Named tests covering the brief's four: env removed → `m02b` (TEST half) and `m02` (value); prune step removed →
`m01`/`m05` (rename / not-last); `0`→`1` → `m02` pattern; `if: always()` dropped → `m03`. Evasions: §F1.

### 6. Workflow coverage (lens 6)
`grep -n "runs-on" .github/workflows/*.yml` → 95 rows; every self-hosted placement:
| workflow:line | job | label(s) | cargo | env `"0"` pair | prune step (last, `always()`) |
|---|---|---|---|---|---|
| `cert-postgres-age.yml:145` | `cert-postgres-age` | `[self-hosted, linux-fed]` | `:388,:392,:414` | `:127-128` (workflow env) | `:456-459` ✓ |
| `postgres-ignored.yml:57` | `postgres-ignored` | `[self-hosted, linux-fed]` | `:121,:124` | `:51-52` | `:161-163` ✓ |
| `ci.yml:615` | `check` | matrix `runner` `:782` linux-fed, `:792` `:797` macos-fed (+ hosted `ubuntu-latest` legs) | `:1369,:1384,:1386,:1012` (t0 tool, own `--target-dir .local-runs/ci-prebuilt-t0`, release), `:1493` (release, `once` leg) | `:705-706` (job env) | `:1548-1550` ✓ hosted-guarded + docs_only-guarded |
| `session-boot-lifetime.yml:70` | `lifetime-tests` | matrix `runner` `:69` macos-fed (+ hosted ubuntu) | `:93` | `:50-51` | `:102-104` ✓ hosted-guarded |
No self-hosted job is missed. Two self-hosted cargo outputs the prune does not cover, both small and by design:
`target/release/` from `cargo build --release` on the `once` leg (`strip = true`, one bin) and the t0 orchestrator's
own `.local-runs/ci-prebuilt-t0` (release). Hosted jobs that run cargo (`ci.yml:434/1587/1657/1766/1826`,
coverage, bench, fuzz, codeql, release) are on ephemeral VMs and out of the rule by its own terms.

### 7. Hygiene (lens 7)
```
python3.11 -I -m py_compile scripts/ci/prune-runner-target.py scripts/test/test_ci_runner_target_hygiene_6118.py → ok (also 3.12, 3.13; 3.9/3.10 are not installed in the sandbox)
grep -nE "shell=True|^\s*match |\| None" <both files> → only the test's own assertNotIn("shell=True") string
bash scripts/test/test-ci-workflow-invariants.sh → PASS G: … (#6118) ; ci.yml invariants: 39/39 PASS
bash scripts/check-required-contexts.sh → check-required-contexts: OK (… every needs-classify step guarded …)
bash scripts/check-count-assertion-declared.sh --range fa6b588e…..HEAD → count-assertion-declared: clean
python3 -I scripts/test/test_workflow_pr_triggers_5447.py → OK
.local-runs/bin/actionlint 1.7.7 -shellcheck= -pyflakes= <4 workflows> → rc=0, 0 lines, on tip AND on base (no new warning)
git diff <base>..HEAD --stat -- '*.rs' Cargo.toml Cargo.lock → empty
```
Script facts: `scripts/ci/` is a new directory (absent on base); `prune-runner-target.py` is mode 100755 with a
`python3` shebang; the test file is 100644 like the other 3 python tests in `scripts/test/`; both stdlib-only
(`argparse`, `subprocess.run([...])` argument lists, `pathlib`); `from __future__ import annotations` + `typing`
generics, no `match`, no `X | None`. Section G is reached by `c8-precheck.yml:915`. Commit trailers: all eight carry
`Refs #3308`, `Base: fa6b588e…`, `Co-Authored-By:` (seven Fable 5.1, the last Sonnet 5.5).

### 8. Docs drift (lens 8)
- `docs/DEV-CI-ENVIRONMENT.md:102-103` states "`One debuginfo level, 0`"; `:114-115` table names `line-tables-only`
  only as the measured alternative; `:125-127` states the exact default scope ("test/example executables (plus their
  `.d` and `.dSYM` companions) and `incremental/`"). ✓ (`0`), ✓ (scope) — modulo F2 ("example") and F3 ("never
  follows a symlink", `:131-132`).
- `changelog.d/6118.fixed.md:14` states the pair `= "0"`; `:9-11` states the default scope. ✓ / ✓, same two caveats.
- `grep -rn "target/debug/deps|CARGO_PROFILE_DEV_DEBUG|prune-runner-target|line-tables-only" docs/ changelog.d/`:
  outside the two 6118 files only `changelog.d/3461.fixed.md:9-10` (F7) and historical cert-54 evidence logs
  (`.local-runs-target/debug/deps/...`, not claims).
- `ci.yml:681` comment "no workflow, script or test sets RUST_BACKTRACE" — verified: the only two hits for
  `RUST_BACKTRACE` under `.github/workflows` and `scripts/` are that comment and the test docstring.

## Issue requirements

From the literal "Proposed fix" text of #6118:
| requirement | status | evidence |
|---|---|---|
| (1) `CARGO_PROFILE_DEV_DEBUG=line-tables-only` (or `0`) in the test workflows' env for the self-hosted matrix legs | MET (`0`, the stronger option the issue allows) | `ci.yml:705-706`, `cert-postgres-age.yml:127-128`, `postgres-ignored.yml:51-52`, `session-boot-lifetime.yml:50-51`; R-DEBUG |
| (1) "expected 3-5x smaller test binaries; backtraces keep line numbers" | MET on size (11x measured by author; 11.24x here); line numbers in `RUST_BACKTRACE` backtraces are given up by choosing `0`, and nothing in CI sets `RUST_BACKTRACE` (lens 8) | §Measurement |
| (2) `post` cleanup step `if: always()` removing `target/debug/deps` test binaries (or per-job `CARGO_TARGET_DIR`) | MET (deletes all test executables at job end, a superset of "older than the current job") | the four `Prune runner target dir (#6118)` steps; R-PRUNE |
| (3) "consider `-C split-debuginfo` / `strip=debuginfo` for test profile" | MET as moot (at `debug = 0` there is no debuginfo to split or strip); not recorded anywhere in the branch. The one remaining lever is `strip = true` (symbols): measured `strip -s` on the `0` integration binary 11,582,112 → 6,537,832 B (−44 %), at the price of symbol names in backtraces; not worth it at a ~12 GB peak | `.local-runs/rev-6118/postbuild.out` |
| "Verify with a before/after `du` on one runner job" | NOT MET yet (F6): sandbox numbers only, no fleet run | §Measurement |
| root cause: "no post-job step removes them" | MET | prune step last in every self-hosted cargo job |

## Measurement

Three fresh `CARGO_TARGET_DIR`s, `cargo test --no-run -p ai-memory --lib` (+ one `--test` binary), sandbox 4 cores:

| `du -sb` | default (`debuginfo=2`) | `line-tables-only` | `0` |
|---|---:|---:|---:|
| `debug/deps` | 5,784,226,023 B (5.4 GiB) | 3,142,149,377 B (2.9 GiB) | 2,328,806,878 B (2.2 GiB) |
| `debug` (whole profile, incl. sandbox `incremental/`) | 10,219,051,104 B | 6,461,036,652 B | 5,121,225,811 B |
| integration test binary | 511,033,296 B | 130,165,008 B | 11,582,112 B |
| lib unit-test binary | 920,589,296 B | 411,426,664 B | 257,919,368 B |

Judgement on `0` vs `line-tables-only`: the difference is 11.24x on the one artifact class that fills the disk.
Scaled to the fleet's ~1000 integration binaries, `line-tables-only` is ~130 GB per runner (consistent with the
164 GB observed at ~170 MB each with the fleet's larger feature set) and `0` is ~12 GB. The prune step only reclaims
at job END; the ENOSPC risk in the issue is the PEAK during the job, and two linux-fed runners at `line-tables-only`
peak at ~260-330 GB against a 224 GB root — so `0` is load-bearing for the fix, not a tuning choice; the prune step
alone would not have closed #6118. What `0` gives up: `file:line` frames in `RUST_BACKTRACE=1` backtraces (symbol
names remain; the panic message's `src/x.rs:NN:MM` location is a compile-time string and is unaffected). Nothing in
`.github/workflows` or `scripts/` sets `RUST_BACKTRACE` (lens 8), and the hosted sqlite leg and both postgres jobs have
run at `0` since #3461/#3274, so no CI consumer loses anything it reads today. Verdict on the choice: justified.

## REPORT

```
REPORT lane=rev-6118 branch=cloud/f1/rev-6118 base=fa6b588e6b5dfa97370b4f073e60e66cb1ed1fa7 head=<this commit> pushed=yes
COMMITS
<this commit> review(#6118): cloud adversarial review of fix/6118-promo6-ssh head 1632d9d29
ITEMS
#6118 | reviewed | APPROVE | 7 findings (0 High, 1 Medium F1, 5 Low F2-F6, 1 Info F7) + 1 recorded trade-off (F8)
GATES
python3 -I scripts/test/test_ci_runner_target_hygiene_6118.py (base worktree fa6b588e) -> Ran 20 tests ; FAILED (failures=17)
python3 -I scripts/test/test_ci_runner_target_hygiene_6118.py -v (tip 1632d9d2, python 3.13) -> Ran 20 tests ; OK
python3.11 -I scripts/test/test_ci_runner_target_hygiene_6118.py (tip) -> OK
python3.11 -I -m py_compile scripts/ci/prune-runner-target.py scripts/test/test_ci_runner_target_hygiene_6118.py -> ok (3.12, 3.13 ok too)
bash scripts/test/test-ci-workflow-invariants.sh -> ci.yml invariants: 39/39 PASS
bash scripts/check-required-contexts.sh -> check-required-contexts: OK
bash scripts/check-count-assertion-declared.sh --range fa6b588e6b5dfa97370b4f073e60e66cb1ed1fa7..1632d9d2 -> count-assertion-declared: clean
python3 -I scripts/test/test_workflow_pr_triggers_5447.py -> OK
.local-runs/bin/actionlint -shellcheck= -pyflakes= <4 workflows> (tip and base) -> rc=0, no output
cargo test --no-run -p ai-memory --lib -v x3 (CARGO_PROFILE_DEV_DEBUG unset / 0 / line-tables-only) -> rc=0 483 s / 372 s / 392 s
DECISIONS
Verdict APPROVE not REJECT: every finding is Low/Info except F1 (Medium, ~15 test lines); the fix meets the issue's literal requirements and the measurement reproduces (precedent: host security APPROVE with Lows on the same head).
Lens 1 ran all three levels (disk allowed: 11G + 6.5G + 5.4G of 30G) and added one `--test` link per tree to reproduce the author's integration-binary ratio directly, since `--lib` alone cannot show it.
Lens 2 set only CARGO_PROFILE_DEV_DEBUG (TEST unset) so the `-v` log proves `test` inherits `dev` rather than assuming it.
Lens 7 py_compile ran on python3.11 as the oldest interpreter present (3.9/3.10 absent in the sandbox).
Reviewed as a single committed file on cloud/f1/rev-6118 only; no PR comment, no issue edit, no other branch (brief).
FOUND-NOT-FIXED
scripts/test/test_ci_runner_target_hygiene_6118.py:82,117-127,249-255 F1 census misses bare fleet labels, runs-on mapping form, non-`runner` matrix keys, `cargo +toolchain`/`cargo run`/`$CARGO`, wrapper scripts, composite actions
scripts/ci/prune-runner-target.py:114-120 + docs/DEV-CI-ENVIRONMENT.md:125 + changelog.d/6118.fixed.md:9 + test fixture :503 F2 uplifted example executables (nlink 2) are never pruned; docs claim they are; fixture models a layout cargo never produces
scripts/ci/prune-runner-target.py:221 + docs/DEV-CI-ENVIRONMENT.md:131-132 + changelog.d/6118.fixed.md:11-12 F3 symlinked target root is followed while three sentences say "never follows a symlink"
.github/workflows/ci.yml:1550 (+3 sibling steps) F4 no guard against a shared / out-of-workspace CARGO_TARGET_DIR (two runners, one dir: A's prune deletes B's in-flight test binaries)
docs/DEV-CI-ENVIRONMENT.md:102-108 F5 stale previous-level rlib trees survive the default scope; one-time `--scope all` per fleet runner (macos-fed f1 not covered by the issue's mitigation) is undocumented
scripts/ci/prune-runner-target.py:258 F6 `freed_bytes=` is not surfaced as `::notice::`; issue's "before/after du on one runner job" has no fleet evidence yet
changelog.d/3461.fixed.md:9-10 F7 still states the check job declares `line-tables-only`
```
