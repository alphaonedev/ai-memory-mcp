# Cloud review PR #6183 head 9a2827cc3 (round 2): VERDICT REJECT

Lane `rev-6183-r2` (cloud sandbox, read-only adversarial review for ai:god-f1).
Subject: draft PR #6183 `fix(#6157): negotiate MCP protocolVersion against
SUPPORTED_PROTOCOL_REVISIONS`, head `9a2827cc39e906e173b0655b1835a831318f71ec`
(round-1 head `6945b38c6` + 7 commits `1fe8a8929 ccb99f607 ec44b244b c0f8908b0
a12d1f57c 107087eef 9a2827cc3`), base `chain/promo6-ssh` =
`fa6b588e6b5dfa97370b4f073e60e66cb1ed1fa7` (`git merge-base --is-ancestor` ->
ancestor), 29 files +608/-31 against the base, 18 files +209/-38 since round 1.
Round-1 file read first: `origin/cloud/f1/rev-6183:.cloud-review/6183-6945b38-REVIEW-CLOUD.md`.

Verdict rationale: every finding from the round-1 cloud file and from both host
reviews that the seven commits claim to close IS closed at this head, with an
executed command per row (table below). The production change is sound and
unchanged in wire behaviour (base and tip answer `2024-11-05` to every client;
the only delta is one bounded, escaped stderr line). The REJECT rests on two
in-diff defects the round-2 delta introduced, both small (about 12 lines, no
`src/` change): F1, the shipped changelog fragment claims "a failing stderr can
no longer panic the stdio loop" while the same head still exits 101 with a
closed stderr (one `eprintln!` remains INSIDE the request loop at
`src/mcp/mod.rs:5300` plus 32 more in `run_mcp_server`); F2, the widened SSOT
walk is not hermetic: it reads gitignored local artefacts (`.claude/worktrees/`,
`clients/*/.venv/`, `clients/*/dist/`) and a sibling worktree at the
Promotion-6 base turns the pin red on the main checkout (executed). Round 3 is
one changelog sentence and one exclusion-list edit.

## Round-1 findings

Every finding from the round-1 cloud file (`cloud-*`), the host code review
(`code-*`), the host security review (`sec-*`) and the findings named in the
seven commit bodies, verified at `9a2827cc3`.

| finding | closed at 9a2827cc3 | evidence command -> result line |
|---|---|---|
| cloud-F1 / code-F1 / sec-F1: SSOT walk stopped at `tests src docs scripts`, no `ts`/`mjs`; 14 shipped literals still sent `2025-03-26` | Y | `git grep -nE 'protocolVersion\|Protocol version\|speaks MCP' \| grep -E '2025-03-26\|2025-06-18\|2026-07-28'` -> no hits (exit 1); `git grep -ohE 'protocolVersion...[0-9]{4}-[0-9]{2}-[0-9]{2}' \| sort \| uniq -c` -> `46 2024-11-05`, `1 1999-01-01` (the test's deliberate bad value); independent walk `python3 -I .local-runs/rev-6183-r2/count_uses.py $PWD` -> `files=3302 uses=48 offenders=0 non_utf8=0 symlinks_skipped=0` (clients 8 uses, cookbook 11, tests 23, docs 4, scripts 2); red-on-base: `git checkout 6945b38c6 -- clients cookbook benches/harness_bench.rs && cargo test --test mcp_protocol_revision_ssot_6157` -> `FAILED. 0 passed; 1 failed` listing exactly the 14 sites (`benches/harness_bench.rs:210`, 8 `clients/*`, 5 `cookbook/*`), restored with `git checkout HEAD -- ...` |
| cloud-FNF: `clients/host-adapter-shim/tests/envelopes.py:165` fake server answered `2025-03-26` | Y | `sed -n 165p clients/host-adapter-shim/tests/envelopes.py` -> `{"jsonrpc": "2.0", "id": 1, "result": {"protocolVersion": "2024-11-05"}}` |
| code-F1 (second part) / sec-F3: unreadable or non-UTF-8 file skipped silently (fail-open) | Y | planted `docs/zz_6157_badutf8.md` (`\xff\xfe protocolVersion 2025-03-26`) -> `FAILED. 0 passed; 1 failed` with `the pin cannot see these paths ... docs/zz_6157_badutf8.md: not UTF-8: invalid utf-8 sequence of 1 bytes from index 0`; removed, `git status --short` empty |
| sec-F2: walk followed symlinks (`Path::is_dir`) | Y | planted `docs/zz_6157_loop -> ..` -> `ok. 1 passed`, `finished in 1.39s` (clean run `1.36s`, so the link was not entered); code: `fs::symlink_metadata` at `tests/mcp_protocol_revision_ssot_6157.rs:81`, `is_symlink() -> continue` at `:89-91` |
| code-F2: public `PROTOCOL_REVISION` removed (semver) | Y | `grep -n 'pub const PROTOCOL_REVISION' src/mcp/jsonrpc.rs` -> `:68` under `#[deprecated(note = "use NEWEST_PROTOCOL_REVISION (#6157)")]` (`:67`); red: `git checkout ec44b244b -- src/mcp/jsonrpc.rs && cargo test --lib issue_6157_deprecated` -> `error[E0425]: cannot find value PROTOCOL_REVISION in this scope` (x2), `could not compile ai-memory (lib test)`, restored; green: `cargo test --lib -- jsonrpc::tests_6157` -> `issue_6157_deprecated_protocol_revision_alias_is_the_negotiated_default ... ok` |
| code-F3: 64-char clip and `{:?}` escaping unpinned | Y | `src/mcp/jsonrpc.rs:179-198` (clip, exact: 64 `A` must be followed by the closing quote, so 63 or 65 both fail) and `:203-221` (escape, one line); green: `..._clips_long_value_to_first_64_chars ... ok`, `..._escapes_control_and_bidi_chars ... ok` (`4 passed; 0 failed; 8975 filtered out`); teeth: scratch `take(DIAGNOSTIC_ECHO_MAX_CHARS + 8)` -> `issue_6157_downgrade_diagnostic_clips_long_value_to_first_64_chars ... FAILED` (`panicked at src/mcp/jsonrpc.rs:189:9`, `2 passed; 1 failed`); scratch `{clipped:?}` -> `clipped` -> `issue_6157_downgrade_diagnostic_escapes_control_and_bidi_chars ... FAILED` (`panicked at src/mcp/jsonrpc.rs:208:13: raw '\u{1b}' reached the diagnostic`) plus the clip test (the quotes vanish), `1 passed; 2 failed`; both reverted with `git checkout HEAD -- src/mcp/jsonrpc.rs` |
| code-F4 / cloud-F2 (in-diff site): new `eprintln!` in the initialize arm panics on a failing stderr | Y for the site, N for the class | `sed -n 3563,3573p src/mcp/mod.rs` -> `let _ = writeln!(io::stderr(), ...)` with the ERRORS-19 comment; `io` and `Write` imported at `src/mcp/mod.rs:18`. Class still open (pre-existing, #6191): probe `stderr_closed_pipe_supported: rc=101 stdout=b''`, `stderr_closed_pipe_unsupported: rc=101`, `stderr_dev_full_*: rc=101` on the tip AND on the base; the site cannot be isolated end to end because 33 `eprintln!` sites in `run_mcp_server` (`src/mcp/mod.rs:4511-5509`) fire first; see F1 below for the changelog consequence |
| cloud-F3: batch array refused with the serde-internal `-32700` message | N (outside the PR, listed by round 1 for filing) | probe `batch_array` -> `-32700 'parse error: invalid type: map, expected a string at line 1 column 1'` on tip and base (unchanged) |
| cloud-FNF: residual of #6157's headline, `2025-06-18` / `2026-07-28` unaudited | N (by design: list stays truthful) | probe `rev_2025_06_18` / `rev_2026_07_28` -> `protocolVersion='2024-11-05' downgrade_lines=1`; `src/mcp/jsonrpc.rs:52` still says "likewise unaudited" |
| commit `9a2827cc3`: changelog + SSOT doc describe the repository-wide scan | Y for the scan text, but the same hunk adds a false claim | `changelog.d/6157.fixed.md:10-15` matches `EXCLUDED_DIRS` (`:42-50`), the no-symlink rule (`:89`) and the fail-closed read (`:161-171`); `:17-18` "a failing stderr can no longer panic the stdio loop" is contradicted by the closed-stderr probe (F1) |
| commit `1fe8a8929`: red pin, floors 2000 / 40 | Y | independent count `files=3302 uses=48` -> `floors: files>=2000 -> True | uses>=40 -> True`; the red reproduced (row 1) |
| commit `ccb99f607`: 14 callers ask for `2024-11-05`, bench reads the SSOT | Y | `sed -n 210p benches/harness_bench.rs` -> `"protocolVersion": ai_memory::mcp::jsonrpc::NEWEST_PROTOCOL_REVISION,`; rows 1-2 |
| commits `ec44b244b` / `c0f8908b0`: alias red then green | Y | row 5 |
| commit `a12d1f57c`: clip and escape pins; `Count-Declared` trailers carried on `9a2827cc3` | Y | row 6; `bash scripts/check-count-assertion-declared.sh --range origin/chain/promo6-ssh..HEAD` -> `count-assertion-declared: clean (origin/chain/promo6-ssh..HEAD)` |
| commit `107087eef`: `writeln!` instead of `eprintln!` | Y | row 7 |

## Findings

Ranked by severity. Severity scale: HIGH = wrong behaviour on the wire;
MEDIUM = shipped artefact drifts from the fix / a gate whose verdict depends on
state it should not see; LOW = hygiene or pre-existing, outside the diff.

### F1 (MEDIUM, in-diff, docs drift) — `changelog.d/6157.fixed.md:17-18` claims "a failing stderr can no longer panic the stdio loop"; the head still panics (exit 101) with a closed stderr, and an `eprintln!` remains inside the request loop

- Where: `changelog.d/6157.fixed.md:16-18` ("The downgrade diagnostic echoes at most 64 escaped characters of the client value and a failing stderr can no longer panic the stdio loop."), introduced by `9a2827cc3`.
- What: the sentence states a property of the stdio loop, not of the one write `107087eef` changed. On this head the stdio loop still contains `eprintln!("ai-memory MCP server stopped (drain ceiling exceeded)")` at `src/mcp/mod.rs:5300` (inside the per-line loop that starts after `:5224`), the loop's own startup and shutdown banners (`:4511-5509`: 33 `eprintln!` sites), and `handle_request`-reachable sites (`:3956`, `:3969`, `:4035-4051`, `:4265-4306`). Every one of them panics on a write error exactly as the replaced site did. The commit body of `107087eef` says so itself ("the server exits before initialize because earlier startup `eprintln!` sites ... panic first"); the changelog says the opposite. A release-notes reader will conclude #6191 is fixed.
- How reproduced: `python3 -I .local-runs/rev-6183-r2/probe.py --binary .local-runs/rev-6183-r2/ai-memory-tip ...` -> `stderr_closed_pipe_supported: rc=101 stdout=b''`, `stderr_closed_pipe_unsupported: rc=101 stdout=b''`, `stderr_dev_full_supported: rc=101`, `stderr_dev_full_unsupported: rc=101` (tip, head `9a2827cc3`). `awk 'NR>=5224 && NR<=5509 && /eprintln!/' src/mcp/mod.rs` -> `5300`, `5507`.
- Fix size: one sentence. "The downgrade diagnostic echoes at most 64 escaped characters of the client value, and its stderr write is non-panicking (`let _ = writeln!`); the pre-existing `eprintln!` sites that exit the server at boot on a closed stderr are tracked in #6191." Same correction to the `jsonrpc.rs` doc comment is not needed (it makes no such claim). The PR body's round-2 table row ("`eprintln!` in the initialize arm panics on a failing stderr") is accurate and needs no change.

### F2 (MEDIUM, in-diff, test hermeticity) — the repository-root walk reads gitignored local artefacts; a sibling worktree at the Promotion-6 base, a `.venv`, or a stale `dist/` turns the pin red on the main checkout

- Where: `tests/mcp_protocol_revision_ssot_6157.rs:42-50` (`EXCLUDED_DIRS`, seven names) and `:145-148` (`walk(root, ...)` from `CARGO_MANIFEST_DIR`).
- What: the walk's input is "everything on disk under the repo root minus seven directory names", not "the files the repository ships". Three paths the repository itself documents as local artefacts are inside the walk:
  - `.claude/worktrees/<name>/` (gitignored at `.gitignore:42` `.claude/*`): the Claude Code `EnterWorktree` location and the CLAUDE.md "Multi-agent worktree discipline" workflow. A sibling worktree checked out at the base `fa6b588e6` carries the 14 pre-fix `2025-03-26` literals, so the pin on the MAIN checkout fails while the main checkout is clean.
  - `clients/anthropic-shim-py/.venv/`, `clients/openai-shim-py/.venv/` (gitignored at `clients/anthropic-shim-py/.gitignore:8`, `clients/openai-shim-py/.gitignore:8`): a virtualenv's `site-packages` is scanned line by line (`.py`, `.json`, `.md` all in `EXTENSIONS`); the Python MCP SDK ships newer revision strings.
  - `clients/anthropic-shim-ts/dist/`, `clients/openai-shim-ts/dist/` (gitignored at `clients/*-shim-ts/.gitignore:2`, produced by `npm run build` = `tsc` with `outDir: dist`, `tsconfig.json:8`): a `dist/index.js` built before `ccb99f607` still says `2025-03-26`.
  CI is unaffected (clean checkout), so this is a deterministic false red on developer and agent machines, plus wasted scan time; it cannot produce a false green (extra files only add offenders or non-UTF-8 failures).
- How reproduced (each plant removed afterwards; `git status --short` empty):
  - `git show fa6b588e6:clients/host-adapter-shim/python/capture_turn.py > .claude/worktrees/agent-x/clients/shim/capture_turn.py` (`git check-ignore -v` -> `.gitignore:42:.claude/*`), run the built test binary `target/debug/deps/mcp_protocol_revision_ssot_6157-c7294bd907205ce5 issue_6157_every_protocol_version_use_is_a_supported_revision` -> `.claude/worktrees/agent-x/clients/shim/capture_turn.py:133: 2025-03-26`, `FAILED. 0 passed; 1 failed`.
  - `clients/anthropic-shim-py/.venv/lib/python3.12/site-packages/mcp/zz.py` with `DEFAULT = {"protocolVersion": "2025-06-18"}` (`git check-ignore -v` -> `clients/anthropic-shim-py/.gitignore:8:.venv/`) -> `clients/anthropic-shim-py/.venv/.../mcp/zz.py:1: 2025-06-18`, `FAILED`.
  - `clients/anthropic-shim-ts/dist/index.js` with `protocolVersion: "2025-03-26"` (`git check-ignore -v` -> `clients/anthropic-shim-ts/.gitignore:2:dist/`) -> `clients/anthropic-shim-ts/dist/index.js:1: 2025-03-26`, `FAILED`.
- Fix size: copy the precedent the test already sets (`EXCLUDED_DIRS`, `:42-50`, one justified name per line) and add `.claude` (or `worktrees`), `.venv`, `venv`, `dist`, `build`, `__pycache__`, `.mypy_cache`, `.pytest_cache`, `.ruff_cache`: about 10 lines, no tracked directory carries any of those names (`git ls-files | grep -E '(^|/)(dist|build|worktrees|\.venv|venv|__pycache__)/'` -> none). The stronger alternative, enumerating `git ls-files -z` so the walk equals the CI checkout exactly, has no precedent in `tests/` (`grep -rln ls-files tests/` -> none) and needs `git` at test time; `Cargo.toml:19-30` `include` omits `tests/`, so a crates.io tarball never runs this test either way. Either fix keeps the fail-closed read and the floors.

### F3 (LOW, pre-existing, not introduced by this PR, carried from round 1) — a JSON-RPC batch array is refused with a serde-internal `-32700` message

- Where: `src/mcp/mod.rs` pre-dispatch decode (`serde_json::from_str::<RpcRequest>` error text goes straight into the response).
- What / how reproduced: probe `batch_array` -> `-32700 'parse error: invalid type: map, expected a string at line 1 column 1'`, identical on base and tip. The PR's decision record rests on this behaviour; the message names serde's expectation, not "batch not supported".
- Fix size: one guard arm before the decode + one test, ~15 lines. Separate issue (round 1 listed it; the host code review filed only #6191 for the `eprintln!` class).

### Observations that are not findings

- `#[allow(deprecated)]` on `issue_6157_deprecated_protocol_revision_alias_is_the_negotiated_default` (`src/mcp/jsonrpc.rs:158`) is the only `#[allow]` the PR adds; its justification is the doc comment two lines above (`:154-156`), inside `#[cfg(test)]` (`:150`).
- `SUPPORTED_PROTOCOL_REVISIONS[0]` and `pair[0] > pair[1]` (`src/mcp/mod.rs:8763`, `tests/integration.rs:2142`, `tests/mcp_protocol_revision_ssot_6157.rs:213,217`) are the only index-by-position sites and all sit in test code (`mod tests` opens at `src/mcp/mod.rs:5511`).
- Floors: 3302 files / 48 uses against 2000 / 40. Removing the whole `clients/` tree (8 uses) lands exactly on 40 and still passes; the floor guards a broken walk, not a deleted tree. Adequate.
- `vendor/` is a documented blind spot (`tests/mcp_protocol_revision_ssot_6157.rs:40-41`): a planted `vendor/zz_6157.md` with `protocolVersion 2025-03-26` -> `ok. 1 passed`. `vendor/paste` carries no MCP code (`git ls-files vendor` -> the `paste` crate only). By design; the F2 fix should keep it.
- A `chmod 000` directory could not be shown to fail the pin because the sandbox runs as uid 0 (permission bits are not enforced for root); the `read_dir` error path at `:65-70` is reached only by inspection.
- Two `initialize` requests in one session are both answered and both downgraded (probe `two_initializes`: `stdout_lines=2 downgrade_lines=2`); the spec only says `initialize` MUST be the first interaction; unchanged from base.
- The 64-char clip is char-based, so escaped bytes can exceed 64 (`combining_200` -> diag len 577, `max_codepoint_200` -> 775); bounded at 64 x 10 bytes + fixed text, as round 1 noted.
- Signature state: `git log --format=%G?` prints `N` in this sandbox only because `gpg.ssh.allowedSignersFile` is not configured here; GitHub reports `verified=true reason=valid` for all seven commits (`gh api repos/alphaonedev/ai-memory-mcp/commits/<sha> --jq .commit.verification`), author and committer `alphaonedev@users.noreply.github.com`. `git diff 6945b38c6..HEAD -- Cargo.toml Cargo.lock | wc -l` -> `0`.
- CI on the head at review time (`gh api .../commits/9a2827cc3/check-runs`): `total=73 success=64 skipped=1 in_progress=4 queued=4`, no failure; pending: the four `Check (...)` cells, `SAL-only feature gate`, `Per-Module Coverage Thresholds`, `Certified pg+AGE cells`, `Postgres ignored tests`. The coverage sticky comment on the PR already reports `PASS` at 92.58 % global.

## Evidence

Sandbox: 4 cores, 15 GiB, rustc 1.98.0 via rustup (`rustfmt` and `clippy` components absent again and installed with `rustup component add --toolchain 1.98.0-x86_64-unknown-linux-gnu rustfmt clippy`), SQLite only, uid 0. All scratch under `.local-runs/rev-6183-r2/` (probe script `probe.py`, walk counter `count_uses.py`, logs). `.cloud-review/` is not gitignored (`git check-ignore` exit 1) and is in `EXCLUDED_DIRS`, so this file never trips the pin.

### 1. Spec conformance

- `WebFetch https://modelcontextprotocol.io/specification/2024-11-05/basic/lifecycle`, `.../2025-03-26/basic/lifecycle`, `.../2025-06-18/basic/lifecycle`: the "Version Negotiation" paragraph is word-for-word identical in all three (quoted in §Spec citation).
- Result: CONFORMANT, unchanged from round 1. Echo on member (`src/mcp/jsonrpc.rs:92-97`), another supported version otherwise, the latest the server supports (`NEWEST_PROTOCOL_REVISION`, list asserted strictly newest-first at `tests/mcp_protocol_revision_ssot_6157.rs:211-217`). The `-32602` block on every revision's page is an "Example initialization error" under "Error Handling", not a requirement.
- 2025-06-18 delta that matters for later listing: Operation phase "Both parties **MUST** respect the negotiated protocol version" (was SHOULD) and the HTTP-only `MCP-Protocol-Version` header; nothing changes for stdio negotiation.

### 2. Issue conformance

- Issue body read with `gh api repos/alphaonedev/ai-memory-mcp/issues/6157` (REST; `gh issue view --json` fails with "GraphQL is not available from Claude Code sessions"). PR body, both host reviews and the author's round-2 comment read with `gh api .../pulls/6183` and `.../issues/6183/comments`. Table in §Issue requirements; vote in §Vote assessment.

### 3. Hostile input on the wire

- Build: `cargo build --bin ai-memory` -> `Finished dev profile [unoptimized + debuginfo] target(s)` (exit 0; binary copied to `.local-runs/rev-6183-r2/ai-memory-tip`).
- `python3 -I .local-runs/rev-6183-r2/probe.py --binary .local-runs/rev-6183-r2/ai-memory-tip --sandbox .local-runs/rev-6183-r2/probe-sandbox` (full output `.local-runs/rev-6183-r2/probe-tip.out`; one fresh child, fresh DB and sandboxed HOME/config/key dir per case, `mcp --profile full --tier keyword`). Every case `rc=0`, `panic=False`, exactly one stdout line (two for the two-request case), exactly one downgrade line when a downgrade happened, zero forged lines:

| case | `protocolVersion` / error | downgrade lines | diagnostic (len, clipped) |
|---|---|---|---|
| `2024-11-05` | `2024-11-05` | 0 | none (6 baseline stderr lines) |
| `2025-03-26`, `2025-06-18`, `2026-07-28` | `2024-11-05` | 1 each | len 145: `client protocolVersion "2025-03-26" is not supported; responding with 2024-11-05 (supported: ["2024-11-05"])` |
| 1 MiB string | `2024-11-05` | 1 | len 199, exactly 64 `A` |
| control + ANSI `\x1b[31mRED\x1b[0m\x07\x00\x7f\x08` | `2024-11-05` | 1 | len 175: `"\u{1b}[31mRED\u{1b}[0m\u{7}\0\u{7f}\u{8}"`, `raw_ESC=False` |
| newline forge `x\nai-memory: FORGED second line\r\nfake` | `2024-11-05` | 1 | len 175, one line, `forged_lines=0`, `raw_CR=False` |
| bidi RLO `2024‮50-11-40` | `2024-11-05` | 1 | `"2024\u{202e}50-11-40"` escaped |
| `null`, number, `true`, array, object | `2024-11-05` | 1 each | `<non-string>` |
| field missing, `params` missing, `params` string, `params` null | `2024-11-05` | 1 each | `<missing>` |
| 63 astral + `Z` + 200 `T` | `2024-11-05` | 1 | len 199, clip is char-based, ends `...😀Z"` |
| 200 combining marks / 200 x U+10FFFF | `2024-11-05` | 1 | len 577 / 775 (bounded by 64 x 10 escape bytes) |
| invalid UTF-8 bytes in the line | `-32700 parse error: invalid UTF-8 ...` | 0 | pre-dispatch |
| lone `\ud800` escape | `-32700 parse error: unexpected end of hex escape ...` | 0 | pre-dispatch |
| batch array | `-32700 parse error: invalid type: map, expected a string at line 1 column 1` | 0 | F3 |
| two initializes `2099-01-01`, `2098-01-01` | `2024-11-05` x2 | 2 | both answered |
| stderr = closed pipe, supported / unsupported | no stdout | n/a | `rc=101` both (pre-existing, #6191) |
| stderr = `/dev/full`, supported / unsupported | no stdout | n/a | `rc=101` both |

### 4. Red-on-base and green-on-tip

- Tip: `AI_MEMORY_NO_CONFIG=1 cargo test --no-fail-fast --test mcp_protocol_revision_ssot_6157 --test mcp_protocol_negotiation_6157` -> `test result: ok. 7 passed; 0 failed ... finished in 2.17s` (negotiation: 4 issue tests + 3 `mcp_wait` leaf tests) and `test result: ok. 3 passed; 0 failed ... finished in 1.36s` (SSOT), `real 3m0.804s` including compile.
- Tip lib pins: `AI_MEMORY_NO_CONFIG=1 cargo test --lib -- jsonrpc::tests_6157 jsonrpc_handles_initialize` -> `test mcp::jsonrpc::tests_6157::issue_6157_deprecated_protocol_revision_alias_is_the_negotiated_default ... ok`, `..._downgrade_diagnostic_clips_long_value_to_first_64_chars ... ok`, `..._downgrade_diagnostic_escapes_control_and_bidi_chars ... ok`, `test mcp::tests::test_jsonrpc_handles_initialize ... ok`, `test result: ok. 4 passed; 0 failed; 0 ignored; 0 measured; 8975 filtered out; finished in 0.12s` (`real 3m55s` including the lib-test build).
- Round-2 red 1 (`1fe8a8929`, the 14 sites): restore the round-1 files, `git checkout 6945b38c6 -- clients cookbook benches/harness_bench.rs && cargo test --test mcp_protocol_revision_ssot_6157 issue_6157_every_protocol_version_use_is_a_supported_revision` -> `FAILED. 0 passed; 1 failed`, 14 offender lines exactly matching the commit body's list; `git checkout HEAD -- clients cookbook benches/harness_bench.rs` restored.
- Round-2 red 2 (`ec44b244b`, alias absent): `git checkout ec44b244b -- src/mcp/jsonrpc.rs && cargo test --lib issue_6157_deprecated` -> `error[E0425]: cannot find value PROTOCOL_REVISION in this scope` (2x), `error: could not compile ai-memory (lib test) due to 2 previous errors`, exit 101; `git checkout HEAD -- src/mcp/jsonrpc.rs` restored.
- Round-1 red (`ce1066061`) was reproduced in round 1 (`FAILED. 4 passed; 3 failed` on base src with the red commit's fixture) and is not re-run here; the base-src build for lens 6 below confirms the base still emits no diagnostic.
- Integration: `AI_MEMORY_NO_CONFIG=1 cargo test --no-fail-fast --test integration --test mcp_integration initialize` -> `test test_mcp_initialize ... ok`, `test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 218 filtered out` (integration) and `test mcp_initialize_handshake_succeeds ... ok`, `test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 5 filtered out` (mcp_integration).

### 5. Vacuity of the SSOT walk

- Static: `MIN_FILES_WALKED = 2000` (`:58`), `MIN_PROTOCOL_VERSION_USES = 40` (`:59`), asserted at `:149-153` and `:189-192`; `unreadable.is_empty()` asserted at `:184-188` before the floors, so a walk that cannot read something fails before it can look vacuous.
- Independent count: `python3 -I .local-runs/rev-6183-r2/count_uses.py $PWD` -> `files=3302 uses=48 offenders=0 non_utf8=0 symlinks_skipped=0`, `floors: files>=2000 -> True | uses>=40 -> True`, `excluded dirs met: ['.git', '.local-runs', 'target', 'vendor']`.
- Mutations (`AI_MEMORY_NO_CONFIG=1 cargo test -q --test mcp_protocol_revision_ssot_6157 issue_6157_every_protocol_version_use_is_a_supported_revision` after each plant; every plant removed; `git status --short` empty at the end):
  - a) non-UTF-8 `docs/zz_6157_badutf8.md` -> `FAILED`, `not UTF-8: invalid utf-8 sequence of 1 bytes from index 0`
  - b) symlink loop `docs/zz_6157_loop -> ..` -> `ok. 1 passed`, `finished in 1.39s`
  - c) gitignored `clients/anthropic-shim-py/.venv/.../mcp/zz.py` with `2025-06-18` -> `FAILED` (F2)
  - d) gitignored `clients/anthropic-shim-ts/dist/index.js` with `2025-03-26` -> `FAILED` (F2)
  - e) `vendor/zz_6157.md` with `2025-03-26` -> `ok. 1 passed` (documented blind spot)
  - f) `docs/zz_6157_probe.md` with `{"protocolVersion":"2025-03-26"}` -> `FAILED`, `docs/zz_6157_probe.md:1: 2025-03-26`
  - g) `chmod 000 docs/zz_6157_noperm` -> `ok` (uid 0, not enforceable here)
  - h) the 14 round-1 files restored from `6945b38c6` -> `FAILED`, 14 offenders (lens 4)
  - i) `.claude/worktrees/agent-x/clients/shim/capture_turn.py` from the base revision -> `FAILED`, `...capture_turn.py:133: 2025-03-26` (F2; run on the built test binary while the cargo lock was held)

### 6. Behaviour change for real clients

- Base binary: `git checkout fa6b588e6 -- src && cargo build --bin ai-memory` -> `Finished dev profile ... in 54.52s`; `python3 -I probe.py --binary ai-memory-base ...` -> `supported_2024_11_05 ... protocolVersion='2024-11-05' stderr_lines=6 downgrade_lines=0`; `rev_2025_03_26 ... protocolVersion='2024-11-05' downgrade_lines=0`; `rev_2026_07_28 ... '2024-11-05' downgrade_lines=0`; `null` / `field_missing` -> `'2024-11-05' downgrade_lines=0`; `batch_array` -> same `-32700` text; `stderr_closed_pipe_supported: rc=101`, `stderr_dev_full_supported: rc=101`. `git checkout HEAD -- src` restored (`git status --short` empty).
- Tip: identical wire answers on every case; the only delta is the one stderr line per downgrade (lens 3).
- Shipped clients still sending a revision the tip does not echo: none. `git grep` over the whole tree (row 1 of the round-1 table) finds only `2024-11-05` (46 sites). No client validates the response `protocolVersion` (`grep -rn protocolVersion clients/` -> only the request builders and the `envelopes.py` fake-server line). `clients/*/README.md` name no revision.

### 7. Production code hygiene

- `git diff -U0 fa6b588e6..HEAD -- src | grep '^+' | grep -nE 'unwrap\(|\.expect\(|panic!|unreachable!|todo!|\[[0-9]+\]| as (u|i)(8|16|32|64|size)'` -> one hit, `jsonrpc::SUPPORTED_PROTOCOL_REVISIONS[0]` at `src/mcp/mod.rs:8763`, inside `mod tests`. Production hunks (`src/mcp/jsonrpc.rs:40-118`, `src/mcp/mod.rs:3559-3581`) are total: `Option` matching, `.chars().take()`, `let _ = writeln!`.
- `git diff -U0 fa6b588e6..HEAD | grep '^+.*#\[allow'` -> one, `#[allow(deprecated)]` in `#[cfg(test)]` (observation above).
- `cargo fmt --all --check` -> exit 0.
- `cargo clippy --all-targets -- -D warnings -D clippy::all -D clippy::pedantic` -> `Finished dev profile [unoptimized + debuginfo] target(s) in 4m 16s`, exit 0, zero `warning`/`error` lines (default features).
- `bash scripts/qc-codegraph-precheck.sh` -> `check-sqlite-write-txn-immediate: ok (2 allowlisted read-only site(s))`, `C8 precheck OK (for_agent: 0 sites, for_admin: 25 sites).`, exit 0.
- `bash scripts/check-count-assertion-declared.sh --range origin/chain/promo6-ssh..HEAD` -> `count-assertion-declared: clean (origin/chain/promo6-ssh..HEAD)`, exit 0 (the two `.count()` assertions added by `a12d1f57c` are declared on `9a2827cc3`).

### 8. Docs drift

- `docs/DEVELOPER_GUIDE.md:111`: negotiation against `SUPPORTED_PROTOCOL_REVISIONS`, current `["2024-11-05"]`, echo-if-member, newest-on-downgrade, stderr diagnostic, batch reason for the next revision. Matches `src/mcp/jsonrpc.rs:87-118`. No mention of the pin's roots, so the round-2 widening needed no change here. OK.
- `docs/integration-guide.md:301-305`: "speaks MCP 2024-11-05 protocol (the full supported set is `SUPPORTED_PROTOCOL_REVISIONS` ...; unsupported or missing `protocolVersion` is answered with the newest supported revision and a stderr downgrade diagnostic)". Matches. OK.
- `src/mcp/jsonrpc.rs:52-55` (doc comment, changed by `9a2827cc3`): "walks the whole repository (clients, cookbooks, benches, docs, tests, scripts)". Matches `EXCLUDED_DIRS`. OK.
- `changelog.d/6157.fixed.md:10-15`: scan description matches the test. `:17-18`: FALSE claim, F1.
- `grep -rn '2025-03-26\|2025-06-18\|2026-07-28' docs/ --include='*.md' --include='*.html' | grep -v '^docs/reviews/'` -> one unrelated audit-register row (`docs/audit/3x7-issue-register-2026-08-01.md:275`, a date, not a revision). No doc claims a newer revision is supported.
- Prose citations of "MCP 2025-03-26 §Tool result" in `src/mcp/mod.rs:3689,3872`, `src/mcp/tools/{verify.rs:95,atomise.rs:53,capture_turn.rs:268}` and `CHANGELOG.md:3547` name the convention, not a supported revision; deliberately outside the pin (`tests/mcp_protocol_revision_ssot_6157.rs:15-17`). Not drift.

## Issue requirements

Source: #6157 body ("Proposed fix" and "Why this is a defect"), re-read at round 2.

| # | Literal requirement in #6157 | Status at 9a2827cc3 | Evidence |
|---|---|---|---|
| R1 | Replace the single const with `SUPPORTED_PROTOCOL_REVISIONS: &[&str]` | MET | `src/mcp/jsonrpc.rs:56`; old name kept as a deprecated alias `:67-68` |
| R2 | List "at minimum `2024-11-05`" | MET | `src/mcp/jsonrpc.rs:56,61`; `tests/mcp_protocol_revision_ssot_6157.rs:219` |
| R3 | "plus `2025-03-26` once the tool-result convention ... is verified end to end" | MET (condition not triggered) | audit recorded at `src/mcp/jsonrpc.rs:48-51`; batch MUST confirmed against the 2025-03-26 spec in round 1 |
| R4 | `2025-06-18` / `2026-07-28` "only behind a verified behaviour audit" | MET (not added, not audited) | `src/mcp/jsonrpc.rs:52`; residual in FOUND-NOT-FIXED |
| R5 | initialize arm reads `req.params["protocolVersion"]`; echo if supported | MET | `src/mcp/mod.rs:3563`, `src/mcp/jsonrpc.rs:87-100`; probe `supported_2024_11_05` |
| R6 | else respond with the newest supported revision | MET | `src/mcp/jsonrpc.rs:98`; probe cases 2-15 |
| R7 | Emit a stderr diagnostic on downgrade | MET | `src/mcp/mod.rs:3564-3573`; exactly one line per downgrade in every probe case |
| R8 | Red-first test per branch: exact echo / unsupported / missing | MET | `tests/mcp_protocol_negotiation_6157.rs:75,85,106` (+ non-string `:116`); red `ce1066061` (round 1) |
| R9 | SSOT pin over every `tests/**/*.rs` and `docs/**/*.md` revision string | MET and widened to the repository root | `tests/mcp_protocol_revision_ssot_6157.rs:145-148`; lens 5 |
| R10 | Docs `DEVELOPER_GUIDE.md:111`, `integration-guide.md:301` list the supported set | MET | lens 8 |
| R11 | `changelog.d/<N>.fixed.md` | MET, with one false sentence | `changelog.d/6157.fixed.md`; F1 |
| R12 | Headline defect 1: a `2026-07-28`-only client "terminates the session after initialize" | NOT MET by this PR (explicitly left open, per the issue's own R4 condition) | probe `rev_2026_07_28` -> downgraded to `2024-11-05` |
| R13 | Headline defect 2: server "silently accepts any client revision ... without downgrading explicitly" | MET | explicit on the wire and on stderr |
| R14 | Headline defect 3: 21-file duplication with no SSOT test | MET (round 1: walked roots only; round 2: whole repository, 46 sites pinned) | lens 5; F2 is about what else the walk sees, not about coverage of shipped files |

Is advertising only `2024-11-05` what the issue asked for? Yes, unchanged from round 1: the issue makes every newer revision conditional on a verified audit and says "keep the list truthful and no vote is needed".

## Spec citation

MCP specification, revisions 2024-11-05, 2025-03-26 and 2025-06-18, "Lifecycle" > "Initialization" > "Version Negotiation" (identical in all three; fetched 2026-10-09 from `modelcontextprotocol.io/specification/<rev>/basic/lifecycle`):

> In the `initialize` request, the client **MUST** send a protocol version it supports. This **SHOULD** be the *latest* version supported by the client.
>
> If the server supports the requested protocol version, it **MUST** respond with the same version. Otherwise, the server **MUST** respond with another protocol version it supports. This **SHOULD** be the *latest* version supported by the server.
>
> If the client does not support the version in the server's response, it **SHOULD** disconnect.

PR behaviour against each sentence: echo on member (MUST, `src/mcp/jsonrpc.rs:92-97`); another supported version otherwise (MUST, `:98`); the latest the server supports (SHOULD, `NEWEST_PROTOCOL_REVISION` pinned to index 0, list strictly newest-first at `tests/mcp_protocol_revision_ssot_6157.rs:211-217`). No revision requires an error response for an unsupported client version; the `-32602` block is an "Example initialization error" under "Error Handling" on every page. CONFORMANT.

Revision 2025-03-26, "Overview" > "Messages" > "Batching" (round 1): "MCP implementations **MAY** support sending JSON-RPC batches, but **MUST** support receiving JSON-RPC batches." The tip answers a batch array with `-32700` (probe `batch_array`), so not listing `2025-03-26` is correct. The 2025-03-26 lifecycle page adds "The initialize request **MUST NOT** be part of a JSON-RPC batch", which the stdio loop satisfies trivially.

## Vote assessment

Was a 5-agent crossroads vote due (CLAUDE.md `4d3ea1c5` triggers)? **No**, unchanged from round 1, and the round-2 delta removes the one borderline:

- T1: the host code review flagged removing public `PROTOCOL_REVISION` as borderline T1; `c0f8908b0` keeps it as a `#[deprecated]` alias (precedent `src/lib.rs` #1558 crate-root aliases), so no public item is removed. The wire field is unchanged in name, type, position and value (base vs tip probe).
- T2: not touched. T3: downgrade-not-error is the spec's MUST; the diagnostic is bounded and escaped; the `let _ = writeln!` discards only an advisory write (precedent `src/audit.rs`). T4: no persisted bytes. T5: the issue's acceptance text is conditional and says no vote is needed. T6: single spec-prescribed path; walk-exclusion list, deprecated alias and non-panicking stderr write each copy a named precedent (`EXCLUDED_DIRS` doc, #1558, `src/audit.rs`).

The PR body's "no T1 vote" decision record stands.

---

REPORT lane=rev-6183-r2 branch=cloud/f1/rev-6183-r2 base=fa6b588e6b5dfa97370b4f073e60e66cb1ed1fa7 head=<the commit carrying this file; sha in the lane's final REPORT> pushed=yes
COMMITS
<sha> review(#6157): cloud adversarial review round 2 of PR #6183 head 9a2827cc3
ITEMS
#6157 | reviewed | REJECT | 3 findings (F1 MEDIUM changelog overclaims the stderr fix; F2 MEDIUM SSOT walk reads gitignored local artefacts; F3 LOW pre-existing batch message); all 13 round-1 / host findings verified closed except the two pre-existing classes (#6191 stderr `eprintln!`, batch message) that were never in scope
GATES
cargo fmt --all --check -> exit 0 (clean)
cargo clippy --all-targets -- -D warnings -D clippy::all -D clippy::pedantic -> `Finished dev profile [unoptimized + debuginfo] target(s) in 4m 16s`, exit 0, zero warnings (default features)
AI_MEMORY_NO_CONFIG=1 cargo test --no-fail-fast --test mcp_protocol_revision_ssot_6157 --test mcp_protocol_negotiation_6157 -> `test result: ok. 7 passed; 0 failed` (negotiation) and `test result: ok. 3 passed; 0 failed` (ssot)
AI_MEMORY_NO_CONFIG=1 cargo test --lib -- jsonrpc::tests_6157 jsonrpc_handles_initialize -> `test result: ok. 4 passed; 0 failed; 0 ignored; 0 measured; 8975 filtered out; finished in 0.12s`
AI_MEMORY_NO_CONFIG=1 cargo test --no-fail-fast --test integration --test mcp_integration initialize -> `test result: ok. 1 passed; 0 failed; 218 filtered out` (`test_mcp_initialize`) and `test result: ok. 1 passed; 0 failed; 5 filtered out` (`mcp_initialize_handshake_succeeds`)
bash scripts/qc-codegraph-precheck.sh -> `C8 precheck OK (for_agent: 0 sites, for_admin: 25 sites).`, exit 0
bash scripts/check-count-assertion-declared.sh --range origin/chain/promo6-ssh..HEAD -> `count-assertion-declared: clean (origin/chain/promo6-ssh..HEAD)`, exit 0
DECISIONS
Branch name: the harness pre-created `claude/cloud-lane-rev-6183-r2-wqfoft`; the lane brief names `cloud/f1/rev-6183-r2` as the only branch to push, so the review branch and push target follow the brief (precedent: round-1 lane, same choice, `origin/cloud/f1/rev-6183`).
L1 memory_store rule (CLAUDE.md): no `mcp__memory__*` tool is attached to this sandbox session (ToolSearch "+memory store" -> no match; only the `github` MCP server is attached), so the directive could not be stored in the substrate; this file is the durable record.
Verdict bar: REJECT rather than APPROVE-with-notes because both F1 and F2 are inside the round-2 delta, each reproduced with an executed command on this head, and the prime directive treats a false release-notes claim as a defect; the host reviews applied the same bar in round 1 (REJECT on in-diff MEDIUM findings with the production code sound). Round 3 is ~12 lines, no `src/` change.
Review-only lane: no production, test or doc file was modified; every plant and every `git checkout <sha> -- <path>` was reverted (`git status --short` empty before this commit).
Full `cargo test --lib` not run: the lane brief scopes lens 4 to the two new test files, the lib pins and the integration initialize tests; the sandbox's cargo budget went to clippy pedantic (`--all-targets`), the lib-test build for the unit pins and two debug binary builds (tip + base).
FOUND-NOT-FIXED
changelog.d/6157.fixed.md:17-18 "a failing stderr can no longer panic the stdio loop" is false on this head (`src/mcp/mod.rs:5300` `eprintln!` inside the request loop; closed-stderr probe rc=101); one-sentence fix in F1 (in-PR).
tests/mcp_protocol_revision_ssot_6157.rs:42-50 the walk reads gitignored local artefacts (`.claude/worktrees/`, `clients/*/.venv/`, `clients/*/dist/`); a sibling worktree at the Promotion-6 base or a stale TS build turns the pin red on a clean main checkout; fix in F2 (in-PR, ~10 lines).
src/mcp/mod.rs pre-dispatch decode: a JSON-RPC batch array is refused with `-32700 "invalid type: map, expected a string"` instead of a message naming batching as unsupported (F3, pre-existing, carried from round 1; still unfiled as far as the PR thread shows).
src/mcp/mod.rs:4511-5509 (33 `eprintln!` sites incl. `:5300` inside the loop) the MCP server exits 101 at boot and in-loop when stderr is closed or full (#6191, filed by the host code review; this PR only stops adding a site).
src/mcp/jsonrpc.rs:52 residual of #6157's headline: a client that only speaks `2025-06-18` or `2026-07-28` still gets `2024-11-05`; 2025-06-18 drops the batch MUST but raises "respect the negotiated protocol version" to MUST and adds structured content / elicitation / `title` / `_meta`; its server-side audit is the next step toward listing a newer revision.
