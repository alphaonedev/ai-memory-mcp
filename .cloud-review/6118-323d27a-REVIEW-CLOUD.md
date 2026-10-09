# Cloud review fix/6118-promo6-ssh head 323d27aec (round 4): VERDICT APPROVE

Reviewer: cloud lane `rev-6118-r4` (Claude Code sandbox, Linux x86_64, 4 cores / 15 GiB, uid 0, ext4, rustc 1.98.0,
python 3.11/3.12/3.13, sqlite only). Subject: `fix/6118-promo6-ssh` head `323d27aeccddfb68163309c16aab9be96701d381`,
24 commits on base `chain/promo6-ssh` = `fa6b588e6b5dfa97370b4f073e60e66cb1ed1fa7`. Whole series: 10 files,
+2760 / -24; round-4 delta `3d3f26b6b..323d27aec`: 4 files, +502 / -48. No `.rs`, `Cargo.toml` or `Cargo.lock`
change (`git diff <base>..HEAD --stat -- '*.rs' Cargo.toml Cargo.lock` is empty).

Verdict rationale. Every round-3 host finding the lane claims closed is closed, with the fix reproduced on real
Linux hard links, not only on the fake tree: a probe crate (one lib, one bin, one example `my-demo`, one integration
test, `cargo test --no-run`) pruned in default scope loses exactly its four test/example executables, keeps the bin's
`deps/<bin>-<hash>` twin (nlink 2), `cargo build -v` then prints `Fresh`, and `cargo test --no-run -v` relinks only
the three `--test` harnesses plus the example while the lib rlib keeps its mtime. The two red commits reproduce
exactly as claimed (`FAILED (failures=6, errors=2)` for the tip tests on the 3d3f26b6b script; 8 guard mutants red on
ea06d8ca6), the tip is `Ran 75 tests OK` as an unprivileged user, lens 9 found no way for a file name or a CLI
argument to start a `::` or `##[` line, and the adversarial trees never touched a byte outside the target dir. Nothing
blocks. The three findings below are a uid-0 portability defect in three tests that turns Section G of the
invariants gate red for any root shell (R4-F1, fold in before merge), a bounded false negative in the new
name+size uplift rule (R4-F2), and commit-message trailer drift (R4-F3).

## Findings

Severity scale: High (blocks), Medium (fold in before merge), Low (fix on the same branch), Info (record).

### R4-F1 Low — three prune-script tests depend on DAC refusal and fail under uid 0; Section G of the invariants gate goes red for a root shell
- File: `scripts/test/test_ci_runner_target_hygiene_6118.py:1317` (`dwarf.chmod(0o500)`), `:1397`
  (`deps.chmod(0)`), `:1436` (`inner.chmod(0o500)`); gate: `scripts/test/test-ci-workflow-invariants.sh:811-814`.
- What: `test_6118_unremovable_entry_warns_continues_and_exits_1`, `test_6118_scan_unreadable_subdir_warns_and_prunes_the_rest`
  and `test_6118_newline_in_entry_name_cannot_inject_a_workflow_command` make a directory unreadable or unwritable
  with mode bits and expect EACCES. uid 0 ignores mode bits on Linux (CAP_DAC_OVERRIDE), so the entries are removed,
  the expected rc 1 is rc 0, the expected `::warning::` never prints, and the `addCleanup(chmod)` then raises
  `FileNotFoundError` on the removed path: 3 failures + 2 errors, deterministic. `c8-precheck.yml:100` runs Section G
  on `ubuntu-latest` as the `runner` user, so CI is green; the same gate run by a developer in a root container
  (this sandbox, any `docker run` without `--user`) is red for a reason unrelated to the workflows it checks.
- How reproduced:
  `python3 -m unittest scripts/test/test_ci_runner_target_hygiene_6118.py` as uid 0 -> `Ran 75 tests ... FAILED (failures=3, errors=2)`;
  `bash scripts/test/test-ci-workflow-invariants.sh` as uid 0 -> `FAIL  G: runner target-dir hygiene failed (#6118)`,
  `ci.yml invariants: 1 FAILED, 38 passed`;
  the same suite as `nobody` (`setpriv --reuid=65534 --regid=65534 --clear-groups`, mini root built from the tip tree)
  -> `Ran 75 tests in 3.746s OK`.
- Fix size: ~6 lines in the test file: a module-level `UID0 = hasattr(os, "geteuid") and os.geteuid() == 0` and
  `if UID0: self.skipTest("uid 0 ignores mode bits; the EACCES paths need an unprivileged user")` at the top of the
  three tests, the precedent being the APFS `skipTest` at `:1598`. (Alternative, ~15 lines: when uid 0 and a
  `nobody` account exists, re-run the script under `setpriv` for those three tests, keeping the coverage.)

### R4-F2 Low — the name+size uplift rule keeps any `deps/<bin>-<hex16>` whose size equals `<profile>/<bin>`, with no inode check where one is available
- File: `scripts/ci/prune-runner-target.py:405-417` (`_profile_bins`, keyed by normalised name and size), `:436-444`
  (the partner lookup keeps the entry before the nlink branch at `:445`).
- What: R3-F1 moved the rule from nlink to name+size so the APFS clone (nlink 1) is kept. On Linux the real twin
  is a hard link, so a stronger test is available and is not used: any executable `deps/<bin>-<16 hex>` of the
  bin's exact size is kept, whether it is the twin, a unit-test harness of the bin crate that happens to land on
  the same size, or a stale twin from an earlier build of identical size (the uplift now points at the new inode).
  It is a false negative only (one extra file kept per collision, never a wrong delete), bounded to a handful of
  files, and realistic only when two builds of one bin have the same byte size.
- How reproduced: lens-3 MAIN tree, default scope: `deps/probe_bin-1111222233334444` (4096 B, nlink 1, a fabricated
  test executable) survives with `kept deps/probe_bin-1111222233334444: uplift source of debug/probe-bin (same name
  and size); pruning it forces a relink`, next to the genuine `deps/probe_bin-cff58677ac0f78dc`. On the real probe
  crate the harness `deps/probe_bin-5c012c636919f148` is 7,195,048 B against the bin's 4,520,280 B, so it is
  pruned as intended.
- Fix size: ~10 lines + 1 test: record `(st_dev, st_ino, st_nlink)` of each `<profile>/<bin>` in `_profile_bins`;
  when the partner has `st_nlink > 1` (Linux hard-link uplift) keep the deps entry only if its `(st_dev, st_ino)`
  equals the partner's, so a stale or colliding nlink-1 file of the same size is pruned; fall back to name+size only
  when the partner itself has nlink 1 (the APFS clone).

### R4-F3 Info — commit trailers: 9 of 24 commits carry no `Refs #6118` body line; the tip commit's subject is `docs(ci):`
- File: `git log fa6b588e..323d27aec`: `37958476c`, `6287b19b3`, `7049d44af`, `16b327c1b`, `09d553a7c`, `e8b71e86c`,
  `370738bbd`, `1632d9d29` (the eight round-1 commits) and `323d27aec` have no `Refs #6118` line in the body
  (`323d27aec` carries it in the subject as `(Refs #6118)` and is titled `docs(ci):` rather than `docs(#6118):`).
  All 24 carry `Base: fa6b588e6b5dfa97370b4f073e60e66cb1ed1fa7` and a `Co-Authored-By:` trailer.
- What: the common brief's commit format asks for `<type>(#<child>): ...` and a `Refs #<umbrella>` trailer; the
  round-1 commits predate the brief and are untouched (correctly: no history rewrite after a push), so this is a
  record for f1's re-sign pass, not a branch change.
- Fix size: none on this branch.

## Round-1 findings

Status of each finding in `.cloud-review/6118-1632d9d-REVIEW-CLOUD.md` (branch `cloud/f1/rev-6118`) at `323d27aec`.

| round-1 finding | status at 323d27aec | evidence (file:line, test) |
|---|---|---|
| F1 Medium — R-CENSUS closed-world claim porous (six evading shapes) | MET | `test_ci_runner_target_hygiene_6118.py:165` `EXPECTED_SELF_HOSTED_JOBS`, `:529` `self_hosted_jobs` reads inline / flow / block / `matrix.<k>` / `fromJSON(matrix.<k>)` and raises `Unparsed` on any other form; every self-hosted job is censused cargo or not; mutants `m06`, `m08`, `m09`, `m09b`, `m10`, `m12`, `m15`, `m20`-`m23` green on tip |
| F2 Low — example executables never pruned on a real tree; docs claim | MET | `prune-runner-target.py:445-462` (nlink-2 pair in `examples/` goes together), `:381-402` (`-`/`_` one name); probe crate: `examples executable 2 4.3 MiB` pruned, `examples/my-demo` + `my_demo-fa7fec1562fad22d` gone, bytes counted once |
| F3 Low — symlinked target root followed; docs said never | MET | `prune-runner-target.py:540-541` refuses `S_ISLNK`; lens 3 `ROOT-SYMLINK default` -> rc 2 `is a symlink; a target dir is never followed through a link`, real tree hash unchanged; `test_6118_refuses_symlinked_target_root` |
| F4 Low — no guard against a shared / out-of-workspace `CARGO_TARGET_DIR` | MET | `prune-runner-target.py:507-517` `_inside_workspace`, `:545-548`; flag `--allow-outside-workspace` only with the exported `CARGO_TARGET_DIR`; no workflow passes it (`m24`); lens 3 `WORKSPACE outside` rc 2, `+ flag, no CARGO_TARGET_DIR` rc 2, `+ flag + CARGO_TARGET_DIR` rc 0 |
| F5 Low — migration of the previous-level trees not in the runbook | MET | `docs/DEV-CI-ENVIRONMENT.md:198-201` "One-time per fleet runner after #6118 lands: ... `--scope all` while the runner is idle" |
| F6 Low — no `::notice::` line; no fleet before/after `du` | PARTLY MET | notice line `prune-runner-target.py:676`, `test_6118_notice_line_carries_the_totals`; fleet evidence still absent: issue #6118 has zero comments and no fleet number is in the branch (needs the first fleet run; the notice line now makes it a one-line capture) |
| F7 Info — `changelog.d/3461.fixed.md` still says `line-tables-only` | MET | `changelog.d/3461.fixed.md:10` "(superseded by #6118: `0`)" |
| F8 Info — same-commit re-run re-pays the lib unit-test harness compile | NOT MET | no sentence in `docs/DEV-CI-ENVIRONMENT.md` §3.3 or `changelog.d/6118.fixed.md` names the cost (`grep -n "re-run\|same commit"` -> none); Info, design-level, record only |
| host Low — delete-by-path TOCTOU when `deps` is swapped for a symlink | MET | `prune-runner-target.py:70-73` docstring, `:256-315` fd-relative `_remove` with `fstat` identity check at `:282-285`; `test_6118_symlink_swap_of_deps_between_scan_and_delete_cannot_escape`, `..._profile_under_scope_all_...` |
| host Low — symlinked `target` root followed | MET | as F3 |
| host Low — uncaught OSError fails the `always()` step | MET | `prune-runner-target.py:76-79`, `_warn` `:152-155`, every scan / remove error path warns and continues, exit 1; lens 3 and lens 9 runs: no traceback in any case |
| host Low — prune runs on legs where checkout was refused | MET | `ci.yml:1555`, `session-boot-lifetime.yml:109` (`steps.checkout.outcome == 'success'`), `cert-postgres-age.yml:459`, `postgres-ignored.yml:163`; `m13` |

## Round-3 host findings

Each one the lane claims closed in round 4, verified on this head.

| finding | claim | verified at 323d27aec | evidence |
|---|---|---|---|
| R3-F1 APFS clone (nlink 1) twin pruned -> bin relinked | matched by name+size | CLOSED (see R4-F2 for the residual) | `prune-runner-target.py:405-417`, `:436-444`; probe (Linux, nlink 2): `kept deps/probe_bin-20c2b040e419c7ac: uplift source of debug/probe-bin (same name and size)`; `cargo build -v` -> `Fresh probe v0.1.0`; clone-shaped fixture `test_6118_r4_r3_f1_clone_shaped_bin_source_is_kept_by_name_and_size` red on 3d3f26b6b, green on tip |
| R3-F2 R-DEBUG guard missed inline table, lowercase `build.rustflags`, YAML `\x1f`; false positives `git log -g`, `debug=false|none` | fixed | CLOSED | `test_ci_runner_target_hygiene_6118.py:113-161` (`LEVEL_OFF`, `INLINE_DEBUG_RE`, `CARGO_CONFIG_ARG_RE`, `CARGO_PROFILE_ARG_RE`, `RUSTFLAGS_ASSIGN_RE`, `RUSTFLAGS_HEREDOC_RE`, `YAML_HEX_ESCAPE_RE`), `_level_spellings` `:552-584`; `m25`-`m32` all FAIL on ea06d8ca6 (`FAILED (failures=8)`), all pass on tip |
| R3-F3 non-UTF-8 name -> `UnicodeEncodeError` traceback | `\xNN` + `backslashreplace` streams | CLOSED | `prune-runner-target.py:139-149`, `:637-640`; lens 9: `\xff-0123456789abcdef` and a 255-byte name mixing `\xff`, `#`, LF and `%` under `LC_ALL=C` and `C.UTF-8`, dry-run and real: no traceback, no raw byte in the output; `test_6118_r4_r3_f3_*` (2) red on 3d3f26b6b, green on tip (not skipped on ext4) |
| R3-F4 dashed example `my-demo` / `my_demo-<hash>` leaked | paired via `-`=`_` | CLOSED | `prune-runner-target.py:381-402`; probe crate shows cargo really writes `examples/my_demo-fa7fec1562fad22d` + uplift `examples/my-demo` (nlink 2) and both are pruned; `test_6118_r4_r3_f4_*` red/green |
| R3-F5 misleading kept message for examples | each kept line names its reason | CLOSED | `prune-runner-target.py:204`, `:442-443`, `:449-450`, `:461-462`, `:670-671`; `test_6118_r4_r3_f5_*` red/green |
| SR3-1 legacy `##[cmd]` forgery via file names under `GITHUB_ACTIONS` | `#` -> `%23` | CLOSED | `prune-runner-target.py:149`; lens 9: names `##[cmd]`, `##[error]`, a bin named `##[error]bin` with its deps twin: zero lines containing `##[` in stdout or stderr, kept line prints `k-%23%23[cmd]`; `test_6118_r4_sr3_1_*` red/green |
| SR3-2 scandir failure / 400-deep tree crash | warning + `MAX_REMOVE_DEPTH` | CLOSED | `prune-runner-target.py:128`, `:270-272`, `:286-291`; `test_6118_r4_sr3_2a_*` (EMFILE mock) and `_2b_*` (1100-deep tree, rc 1, warning, totals printed) red on 3d3f26b6b, green on tip |
| SR3-3 guard gaps | as R3-F2 | CLOSED | as R3-F2 |
| lane claim: red on 3d3f26b6b script `FAILED (failures=6, errors=2)` | | CONFIRMED | tip test file on the 3d3f26b6b tree, as `nobody`: `Ran 75 tests in 3.839s FAILED (failures=6, errors=2)` (the 8 `r4_` prune tests); the red commit 85796870b on its own tree: `Ran 66 tests FAILED (failures=6, errors=1)` (`_main_survives_a_stdout_*` was added later) |
| lane claim: tip `Ran 75 tests OK (skipped=1)` | | CONFIRMED as non-root, with 0 skips on ext4 | `Ran 75 tests in 3.746s OK` as `nobody`; the APFS skip at `:1598` does not fire on ext4. As uid 0: `FAILED (failures=3, errors=2)` (R4-F1) |
| lane claim: docs say freed_bytes exact on Linux / upper bound on APFS; examples hard link on Linux / clone on macOS | | CONFIRMED | `docs/DEV-CI-ENVIRONMENT.md:153-162`, `:177-182`; `changelog.d/6118.fixed.md:62-79`; script docstring `:27-39`, `:91-95` |

## Evidence

### 1. Measurement reproduction (lens 1)
`cargo test --no-run -p ai-memory --lib` into one fresh `CARGO_TARGET_DIR` per level under
`.local-runs/rev-6118-r4/` (`measure.py`; each dir removed after measuring to keep the 30 GB sandbox disk bounded, so
two levels, the pair the branch's decision rests on; the cargo-default row is round 1's number).

| level (`CARGO_PROFILE_DEV_DEBUG`) | `debug/deps` bytes | largest file in `deps` | lib unit-test binary | build wall time |
|---|---:|---|---:|---:|
| `0` | 2,328,813,595 | `libai_memory.a` 627,977,980 | `ai_memory-bda7e1f59d48170e` 257,919,368 | 408 s |
| `line-tables-only` | 3,142,160,155 | `libai_memory.a` 818,606,920 | `ai_memory-60839f7e1d7ead1e` 411,426,672 | 404 s |
| cargo default (round 1) | 5,784,226,023 | `libai_memory.a` 1,659,180,372 | 920,589,296 | — |

Level `0` reproduces round 1 (2,328,806,878 B) to 7 KB and `line-tables-only` (3,142,149,377 B) to 11 KB. Ratios
`line-tables-only` / `0`: `debug/deps` 1.35x, lib unit-test harness 1.60x, `libai_memory.a` 1.30x; build wall time is
the same (404 s vs 408 s), so the level costs nothing in compile time. The integration-binary ratio
(the 11x that fills the disk) is round 1's 130,165,008 -> 11,582,112 B (11.24x), reproduced there against the
author's 130,090,392 -> 11,606,440 B; the `--lib` set measured here does not link an integration binary. Judgement
unchanged: `0` is the right level; nothing in CI reads line tables (lens 8), and the lib harness is one compile unit
either way.

### 2. Env semantics (lens 2)
Probe crate, `cargo test --no-run -v`, one fresh target dir per level, rustc flags per unit:
```
CARGO_PROFILE_DEV_DEBUG=0                : probe, probe --test, probe_bin, probe_bin --test, t1 --test, my_demo  -> no -C debuginfo flag on any unit
unset                                    : every unit -> -C debuginfo=2
CARGO_PROFILE_DEV_DEBUG=line-tables-only : every unit -> -C debuginfo=line-tables-only
```
So the `--test` units (profile `test`) follow `CARGO_PROFILE_DEV_DEBUG` through inheritance; the branch also pins
`CARGO_PROFILE_TEST_DEBUG` so an override of DEV cannot split the pair. Manifest: `Cargo.toml` has only
`[profile.release]` (`:576`) and `[profile.coverage]` (`:634`, `debug = 1`, a custom profile the hosted coverage job
selects); there is no `.cargo/config.toml` (only `.cargo/audit.toml`). Cargo book, reference/profiles.html: "Specifying
a profile in a config file or environment variable will override the settings from `Cargo.toml`." and
reference/config.html: "Environment variables will take precedence over TOML configuration files." and "Configuration
values specified this way [`--config`] take precedence over environment variables, which take precedence over
configuration files." (the last is why the guard flags `cargo --config`). Valid level-0 spellings per the book:
"`0`, `false`, or `"none"`: no debug info at all" — matching `LEVEL_OFF`.

### 3. Prune script on adversarial fake trees (lens 3)
`.local-runs/rev-6118-r4/lens3.py` builds a fresh tree per (variant, mode) with: Linux uplift pair
`deps/ai_memory-aaaa1111aaaa1111` <-> `debug/ai-memory` (nlink 2); clone-shaped `deps/probe_bin-cff58677ac0f78dc` +
`debug/probe-bin` (4096 B each, nlink 1); a colliding `deps/probe_bin-1111222233334444` (4096 B); `deps/foo-0123abcd`
+ `.d` + `.dSYM/Contents/Resources/DWARF/foo`; `libbar-1234.rlib` WITH the exec bit; `libpm-5678.so`; `loose-9999.o`;
a non-exec suffix-less `noexec-abcd1234abcd1234`; a symlink `deps/link-out-0123456789abcdef` -> `outside/secret`;
`build/xyz-1/build-script-build`; `.fingerprint/`; `incremental/`; examples `demo` pair and `my-demo`/`my_demo-<hash>`
pair. The `outside/` tree is sha256-hashed (path, mode, link target, content) before and after every run.

| tree / mode | rc | deleted | survived (notable) | outside |
|---|---|---|---|---|
| MAIN `--dry-run` | 0 | nothing | all | unchanged |
| MAIN default | 0 | `deps/foo-0123abcd` + `.d` + whole `.dSYM/`, `deps/ai_memory-0ld0ld0ld0ld0ld0` (not hex: a plain nlink-1 exe), `examples/{demo,demo-0123456789abcdef,demo-...d,my-demo,my_demo-228f4a433534936b}`, `incremental/foo-abc/**`; `freed_bytes=5082` | `deps/ai_memory-aaaa1111aaaa1111` (kept: uplift source), `deps/probe_bin-cff58677ac0f78dc` (kept), `deps/probe_bin-1111222233334444` (kept: R4-F2), `libbar-1234.rlib` (exec bit, kept by suffix), `.so`, `.o`, `.d`, `noexec-*`, the symlink (skipped), `build/`, `.fingerprint/`, `debug/ai-memory`, `debug/probe-bin` | unchanged |
| MAIN `--scope all` | 0 | the five dirs wholesale, symlink removed as a link | `CACHEDIR.TAG`, `debug/.cargo-lock`, `debug/ai-memory`, `debug/probe-bin` | unchanged |
| `debug/deps` is a symlink to `outside/deps-real`: dry-run / default / all | 0 / 0 / 0 | nothing / examples + incremental only / `build`, `.fingerprint`, `examples`, `incremental` (the `deps` link itself is skipped) | `skipped debug/deps: a symlink or not a directory (never followed)`; `outside/deps-real/victim-*` intact | unchanged |
| `target` is a symlink, default | 2 | nothing | `refusing: ... is a symlink; a target dir is never followed through a link` | unchanged |
| non-cargo dir: dry-run / default / all | 2 / 2 / 2 | nothing | `has neither a cargo CACHEDIR.TAG (signature checked) nor debug/.cargo-lock` | unchanged |
| relative `--target-dir target` (cwd = tree parent), dry-run | 0 | — | same listing as MAIN dry-run | unchanged |
| `--target-dir <base>/outside/../target`, dry-run | 0 | — | resolved, same listing | unchanged |
| `--target-dir ../target` (cwd = `outside/`), default | 0 | same set as MAIN default | — | unchanged |
| `--profile ..` / `--profile ../outside` | 2 / 2 | nothing | `--profile must be one path component` | unchanged |
| `GITHUB_WORKSPACE` elsewhere: no flag / flag without `CARGO_TARGET_DIR` / flag + `CARGO_TARGET_DIR` (dry-run) | 2 / 2 / 0 | nothing | refusal names the workspace and the flag rule | unchanged |

Full output: `.local-runs/rev-6118-r4/lens3.out` (204 lines). Nothing outside the given dir changed in any run.

### 4. Executable classification (lens 4)
`_is_test_executable` (`prune-runner-target.py:318-320`): regular file (lstat, so a symlink is never one), any exec
bit, name not ending in `KEEP_SUFFIXES` (`:121`: `.rlib .rmeta .so .dylib .dll .a .d .o .dwo .dwp .pdb`); no magic
bytes. Then (`:436-451`) the bin-twin and nlink exemptions.
- False positive (a non-test artefact the rule deletes): none found that cargo writes under `deps/` or `examples/`;
  an rlib or dylib with the exec bit is kept by suffix (lens 3 `libbar-1234.rlib`, `libpm-5678.so`), the bin twin by
  name+size, build scripts live under `build/` (untouched by default scope). The example executables and the bin
  crate's unit-test harness are deleted by design and relinked by the next `cargo test` (probe: 4 relinks, 0.47 s).
- False negatives (a test binary it keeps): (a) R4-F2, a test harness or stale twin of the bin crate whose size
  equals `<profile>/<bin>` (lens 3 `probe_bin-1111222233334444`); (b) any executable with nlink > 1 that is not an
  `examples/` pair (by design, frees nothing); (c) a test binary with no exec bit (`noexec-*`; cargo never writes
  one). None of them is a wrong delete; (a) is the one worth a line of code.

### 5. Red-on-base, green-on-tip, mutations (lens 5)
All runs as `nobody` from a mini root (`.github/workflows`, `scripts/ci`, `scripts/test` from the named tree,
`nonroot_run.py`), because uid 0 trips R4-F1:
```
tip 323d27aec, own tree                       : Ran 75 tests in 3.746s  OK
3d3f26b6b tree + tip test file                : Ran 75 tests in 3.839s  FAILED (failures=6, errors=2)   # the 8 r4_ prune tests, as the lane claims
85796870b (test red commit), own tree         : Ran 66 tests in 3.308s  FAILED (failures=6, errors=1)
ea06d8ca6 (guard red commit), own tree        : Ran 75 tests in 3.415s  FAILED (failures=8)             # m25..m32
base fa6b588e + tip test file                 : Ran 75 tests in 2.321s  FAILED (failures=55, errors=7)  # no script, no env, no prune step
tip as uid 0                                   : Ran 75 tests in 4.721s  FAILED (failures=3, errors=2)   # R4-F1
```
Failing names on 3d3f26b6b: `r4_r3_f1_clone_shaped_bin_source_is_kept_by_name_and_size`, `r4_r3_f3_non_utf8_name_is_escaped_not_a_traceback`,
`r4_r3_f4_dashed_example_pair_is_pruned_together`, `r4_r3_f5_kept_line_names_the_real_reason`,
`r4_sr3_1_legacy_v1_command_prefix_cannot_forge_a_command`, `r4_sr3_2b_a_very_deep_tree_warns_instead_of_crashing`
(FAIL); `r4_r3_f3_main_survives_a_stdout_that_cannot_encode_a_name`, `r4_sr3_2a_scandir_failure_inside_remove_warns_and_continues` (ERROR).
Round-1 mutation set (env row removed -> `m02b`/`m02`; prune step removed -> `m01`/`m05`; `0` -> `1` -> `m02`;
`always()` dropped -> `m03`) is unchanged and green on tip; the round-4 mutants `m25`-`m32` add the inline table,
lowercase `build.rustflags`, `\x1f`/`\u001f` escapes, the config-file and heredoc writes, `--config <file>`,
`--profile ci`, and the benign-lines control.

### 6. Workflow coverage (lens 6)
`grep -n "runs-on" .github/workflows/*.yml` -> 95 rows. Every placement that can resolve to a self-hosted label:

| workflow:line | job | label(s) | env `"0"` pair | prune step (last, `always()`, checkout-guarded) |
|---|---|---|---|---|
| `cert-postgres-age.yml:145` | `cert-postgres-age` | `[self-hosted, linux-fed]` | `:127-128` (workflow env) | `:458-460` |
| `postgres-ignored.yml:57` | `postgres-ignored` | `[self-hosted, linux-fed]` | `:51-52` (workflow env) | `:162-164` |
| `ci.yml:615` `${{ fromJSON(matrix.runner) }}` | `check` | include rows `:787` `["self-hosted","linux-fed"]`, `:797` and `:802` `["self-hosted","macos-fed"]` (+ hosted `["ubuntu-latest"]` `:733`) | `:710-711` (job env) | `:1554-1557`, hosted- and docs_only-guarded |
| `session-boot-lifetime.yml:75` `${{ fromJSON(matrix.runner) }}` | `lifetime-tests` | include `:74` `["self-hosted","macos-fed"]` (+ hosted ubuntu) | `:55-56` | `:108-110`, hosted-guarded |

`ci.yml:1663` `${{ matrix.os }}` (`mobile-cross-compile`) resolves to `macos-latest` / `ubuntu-latest` only (hosted);
every other row is a literal hosted image. `test_6118_census_matches_live_runs_on` pins the set; no job is missed.
`coverage.yml:238` also sets `CARGO_PROFILE_DEV_DEBUG: "0"` on a hosted job (harmless, outside the rule).

### 7. Hygiene (lens 7)
```
python3.11 -I -m py_compile scripts/ci/prune-runner-target.py scripts/test/test_ci_runner_target_hygiene_6118.py -> ok (also 3.12, 3.13; 3.9/3.10 not installed here)
grep -nE "shell=True|^\s*match |\| None|os\.system" <both files> -> only the test's own assertNotIn("shell=True") string
bash scripts/test/test-ci-workflow-invariants.sh (as uid 0) -> FAIL  G: runner target-dir hygiene failed (#6118); ci.yml invariants: 1 FAILED, 38 passed   # R4-F1; Section G's suite is 75 OK as nobody
bash scripts/check-required-contexts.sh -> check-required-contexts: OK (...)
bash scripts/check-count-assertion-declared.sh --range origin/chain/promo6-ssh..HEAD -> count-assertion-declared: clean (origin/chain/promo6-ssh..HEAD)
python3 -I scripts/test/test_workflow_pr_triggers_5447.py -> OK
.local-runs/bin/actionlint 1.7.7 -shellcheck= -pyflakes= ci.yml cert-postgres-age.yml postgres-ignored.yml session-boot-lifetime.yml -> rc=0, no output
git diff fa6b588e..HEAD --stat -- '*.rs' Cargo.toml Cargo.lock -> empty
```

### 8. Docs drift (lens 8)
`grep -rn "target/debug/deps\|CARGO_PROFILE_DEV_DEBUG\|prune-runner-target\|line-tables-only" docs/ changelog.d/`
(excluding `docs/reviews`, `docs/bench`, `docs/compliance/evidence` log captures): `docs/DEV-CI-ENVIRONMENT.md:93-207`,
`changelog.d/6118.fixed.md`, `changelog.d/3461.fixed.md:9-10`. The runbook and changelog state `0` (not
`line-tables-only`) as the pinned level (`DEV-CI-ENVIRONMENT.md:102-105`, `changelog.d/6118.fixed.md:14`), name the
exact default scope (test executables in `deps/` + `.d`/`.dSYM`, `incremental/`, the example pair; `.o` kept;
`build/`, `.fingerprint/`, rlib/rmeta/proc-macro kept) at `DEV-CI-ENVIRONMENT.md:146-184`, and the round-4 paragraph
(`changelog.d/6118.fixed.md:62-79`) matches the code: `%23`, `\xNN`, `backslashreplace`, scandir warning, 100-level
cap (`MAX_REMOVE_DEPTH = 100`, `:128`), name+size twin, exact-on-Linux / upper-bound-on-APFS, dashed example, kept
reasons, the seven new guard spellings and the three dropped false alarms. The `cargo build -v` "Dirty" -> "Fresh"
sentence is what the probe reproduced. No drift found in the round-4 delta.

### 9. Hostile names under `GITHUB_ACTIONS=1` (lens 9)
`.local-runs/rev-6118-r4/lens9.py`: under `deps/`, for each of `##[cmd]`, `##[error]`, `::error::x`,
`%0A::warning::`, `\r::error::`, `a\n::error::injected`, `\xff-0123456789abcdef`: one prunable copy (`p-`, nlink 1,
with `.d` and `.dSYM/`), one kept copy (`k-`, hard-linked outside so it prints as kept); a bin `debug/##[error]bin`
with its deps twin; an `incremental/::error::inc\n::error::more/` dir; dry-run and real mode, `LC_ALL=C.UTF-8` and
`LC_ALL=C`; stdout and stderr captured as bytes. Checks: a line starting with `::` other than the script's own
`::notice::prune-runner-target ` / `::warning::prune-runner-target: `, any `##[` anywhere, any raw CR, any line
whose start is not one of the script's prefixes (a raw LF inside a name would create one), any `Traceback`.
```
mode=dry-run LC_ALL=C.UTF-8 : rc=0 stdout 38 lines, stderr 0 lines, findings 0
mode=dry-run LC_ALL=C       : rc=0 stdout 38 lines, stderr 0 lines, findings 0
mode=real    LC_ALL=C.UTF-8 : rc=0 stdout 16 lines, findings 0; survivors in deps: the 7 k- copies + the ##[error]bin twin
mode=real    LC_ALL=C       : rc=0 stdout 16 lines, findings 0
255-byte name (\xff + 100 x '#' + 50 x LF + 50 x '%' + 54 x 'x'), kept and pruned, dry-run and real: rc 0, kept line 736 B on one line, no raw CR/LF/##[/0xff byte in the output, no traceback
CLI: --profile $'\n::error::forged' -> rc 0 "nothing to prune: ...%0A::error::forged does not exist"; --target-dir $'\n::error::forged/target' -> same; --scope $'\n::error::forged' -> rc 2, argparse prints the value repr-quoted on the "error:" line (no raw LF); --target-dir <deps>/p-##[cmd] -> rc 2 refused (not a directory), no ##[ in stderr
64 KiB name: the kernel refuses it at creation (ENAMETOOLONG, NAME_MAX 255), so it cannot exist on the fleet's ext4/APFS either; the 255-byte maximum is the case above
```
Zero findings: `_escape` (`:139-149`) covers `%`, `#`, CR, LF and undecodable bytes, every printed name sits
behind a fixed prefix, and the only lines that start with `::` are the script's own two.

### 10. Real-tree freshness proof (round-4 preface)
Probe crate `.local-runs/rev-6118-r4/probe` (lib `probe`, bin `probe-bin`, example `my-demo`, test `tests/t1.rs`),
`cargo test --no-run`, then the tip script in default scope:
```
deps/probe_bin-20c2b040e419c7ac  4,520,280 B  nlink 2  <-> debug/probe-bin (same inode 614815)
examples/my_demo-fa7fec1562fad22d / examples/my-demo  4,520,272 B  nlink 2 (one inode 614803)
prune: deps executable 3 (20.6 MiB), examples executable 2 (4.3 MiB, counted once), incremental 6, .d twins 5; kept deps/probe_bin-20c2b040e419c7ac: uplift source of debug/probe-bin (same name and size); freed_bytes=28062854 deleted=16
cargo build -v        -> Fresh probe v0.1.0 ... Finished `dev` profile
cargo test --no-run -v -> Dirty probe v0.1.0: couldn't read metadata for file `target/debug/deps/probe_bin-5c012c636919f148`; rustc units: probe_bin --test, probe --test, my_demo (example bin), t1 --test; libprobe-34529b7639c99b74.rlib mtime unchanged (19:31:59 before and after)
```
So the prune costs exactly the four relinks and nothing from the warm cache. Name+size collision: see R4-F2 (kept,
never deleted).

## Issue requirements

| requirement (issue #6118 text) | status | evidence |
|---|---|---|
| (1) `CARGO_PROFILE_DEV_DEBUG=line-tables-only` (or `0`) in the test workflows' env for the self-hosted matrix legs | MET (`0`, the stronger option the issue allows, DEV + TEST pair) | lens 6 table; `test_6118_live_workflows_clean` |
| (1) "expected 3-5x smaller test binaries; backtraces keep line numbers" | MET on size (11x on the integration binary, round 1 + author); line numbers in `RUST_BACKTRACE` traces are given up by choosing `0`, nothing in CI sets `RUST_BACKTRACE` (lens 8, `DEV-CI-ENVIRONMENT.md:127-129`) | §Measurement |
| (2) `post` cleanup step `if: always()` removing `target/debug/deps` test binaries older than the current job, or a per-job `CARGO_TARGET_DIR` | MET (all test/example executables at job end, after a successful checkout) | the four `Prune runner target dir (#6118)` steps; lens 3/9/10 |
| (3) consider `-C split-debuginfo` / `strip=debuginfo` for the test profile | MET as moot at `debug = 0` (nothing to split or strip) | lens 2 flags |
| "Verify with a before/after `du` on one runner job" | NOT MET yet (round-1 F6 carried): no fleet run, zero issue comments | `::notice::prune-runner-target freed_bytes=<n>` makes the capture one line on the first fleet job |
| root cause "no post-job step removes them" | MET | prune step last in every self-hosted cargo job |

## Measurement

| `du -sb`-equivalent (sum of `st_size`) | `0` | `line-tables-only` | cargo default (round 1) |
|---|---:|---:|---:|
| `debug/deps` | 2,328,813,595 B (2.17 GiB) | 3,142,160,155 B (2.93 GiB) | 5,784,226,023 B |
| largest file (`libai_memory.a`) | 627,977,980 B | 818,606,920 B | 1,659,180,372 B |
| lib unit-test binary | 257,919,368 B | 411,426,672 B | 920,589,296 B |

## REPORT

```
REPORT lane=rev-6118-r4 branch=cloud/f1/rev-6118-r4 base=fa6b588e6b5dfa97370b4f073e60e66cb1ed1fa7 head=<the commit carrying this file; SHA quoted in the lane's chat report> pushed=yes
COMMITS
<head> review(#6118): cloud adversarial review round 4 of fix/6118-promo6-ssh head 323d27aec
ITEMS
#6118 | reviewed round 4 | APPROVE | 3
GATES
cargo fmt --all --check -> rc=0, no output (rustfmt component installed first: `rustup component add rustfmt`)
cargo clippy --all-targets -- -D warnings -D clippy::all -D clippy::pedantic -> Finished `dev` profile [unoptimized + debuginfo] target(s) in 5m 05s ; rc=0, 0 warnings (clippy component installed first: `rustup component add clippy`)
AI_MEMORY_NO_CONFIG=1 cargo test --lib -> run 1: test result: FAILED. 8971 passed; 3 failed; 2 ignored (618 s) ; run 2: test result: FAILED. 8972 passed; 2 failed; 2 ignored; 0 measured; 0 filtered out; finished in 631.22s ; rc=101 both. The branch changes no Rust; all three failures are base code under this sandbox's uid 0: audit::tail_loss_4086_tests::init_with_an_existing_mark_needs_no_new_file_4086 (src/audit/tail_loss_4086_tests.rs:243 "a new file could be created in a 0500 directory (running as root?)") and log_paths::tests::is_writable_dir_returns_false_when_parent_is_readonly (src/log_paths.rs:883) fail in both runs for the same CAP_DAC_OVERRIDE reason as R4-F1; cli::doctor::tests::llm_reachability_selector_gate_blocks_credentials_3860 failed in run 1 only and passed in run 2.
python3 -m unittest scripts/test/test_ci_runner_target_hygiene_6118.py (as nobody) -> Ran 75 tests in 3.746s OK ; (as uid 0) -> FAILED (failures=3, errors=2) [R4-F1]
bash scripts/test/test-ci-workflow-invariants.sh (as uid 0) -> ci.yml invariants: 1 FAILED, 38 passed [Section G = R4-F1; same suite 75 OK as nobody]
bash scripts/check-required-contexts.sh -> check-required-contexts: OK (...)
bash scripts/check-count-assertion-declared.sh --range origin/chain/promo6-ssh..HEAD -> count-assertion-declared: clean (origin/chain/promo6-ssh..HEAD)
python3 -I scripts/test/test_workflow_pr_triggers_5447.py -> OK
.local-runs/bin/actionlint -shellcheck= -pyflakes= <4 workflows> -> rc=0
DECISIONS
Branch: pushed cloud/f1/rev-6118-r4 only, per the lane brief's explicit "push ONLY that branch"; the harness-designated claude/cloud-lane-rev-6118-r4-22no5x was not pushed (brief precedence; stated here).
Memory L1 rule: ToolSearch "+memory store" returned no mcp__memory tool in this sandbox, so the CLAUDE.md memory_store-first step was recorded in this file instead of the substrate.
Root sandbox: the suite was re-run as `nobody` from a mini root (setpriv) rather than altering file modes in the repo; the uid-0 result is reported as R4-F1, not hidden.
Measurement: two levels (0, line-tables-only) with each target dir removed after measuring (30 GB free); the cargo-default row is quoted from round 1.
Gates: no .rs/Cargo change on the subject branch (verified), so clippy and `cargo test --lib` exercise the base; both were run and quoted as the brief asks.
FOUND-NOT-FIXED
scripts/test/test_ci_runner_target_hygiene_6118.py:1317,1397,1436 three tests rely on mode-bit refusal and fail under uid 0 (3 failures + 2 errors); Section G of scripts/test/test-ci-workflow-invariants.sh:811 goes red in any root shell (R4-F1; read-only lane, not fixed here)
scripts/ci/prune-runner-target.py:436-444 name+size uplift match keeps any nlink-1 deps/<bin>-<hex16> of the bin's size (stale twin or same-size harness); inode check unused on Linux (R4-F2)
git log fa6b588e..323d27aec: 9 commits without a `Refs #6118` body trailer; 323d27aec subject `docs(ci):` not `docs(#6118):` (R4-F3)
src/audit/tail_loss_4086_tests.rs:227 and src/log_paths.rs:874 (base code, not this branch): two lib tests rely on a 0500 / read-only directory refusing writes and fail under uid 0 (cargo test --lib: 2 failed in both runs); same class as R4-F1, same skip-under-uid-0 remedy
src/cli/doctor.rs:8848 (base code, not this branch): llm_reachability_selector_gate_blocks_credentials_3860 failed in one of two cargo test --lib runs and passed in the other; one-run flake, root cause not established here
```
