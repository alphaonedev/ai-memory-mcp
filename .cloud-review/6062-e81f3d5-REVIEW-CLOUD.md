# Cloud review fix/6062-promo6-ssh-r3 head e81f3d5a6: VERDICT REJECT

Lane `rev-6062-r3`, read-only adversarial review of round 3 (`86410f7e4..e81f3d5a6`, 18 commits) on top of the full
branch (`6025dd3cd..e81f3d5a6`, 75 commits). Subject head `e81f3d5a6218bc0f25f35331c9375612eb69bdb3`, fork point
`6025dd3cd5c1a0f3ef64ab567a074c25b7e160ea`, target chain `chain/promo6-ssh-r2` = `574740a31716c60349937baeef3b60d9dfb08ea5`.
No cargo was run (no Rust, `Cargo.toml` or `Cargo.lock` is touched). The sandbox has python3 3.11, 3.12 and 3.13
(`/usr/bin/python3` = 3.13.16), git, gzip 1.12 and dpkg-deb. It has no python3 3.9, no actionlint/shellcheck and no
nfpm. All scratch is under `.local-runs/` (gitignored). The probe scripts are `lens1.py`, `lens1b.py`, `lens2.py`,
`lens2b.py`, `lens3.py`, `lens3b.py`, `lens4.py` and `lens5.py`.

`git merge-tree --write-tree 574740a31 e81f3d5a6` -> rc=0, tree `86306c006e4f38d28902d1e98c4329fd8d3bebc9`, no conflicts.

Reason for REJECT: one High finding defeats the #6909 impact statement on the tip (F1). One issue (#6904) is NOT MET
against its own proposed-fix text (F2). The #7018 "only checked bytes are published" guarantee has a post-check window
(F3).

## Findings

| # | Severity | file:line | What | How reproduced | Fix size |
|---|---|---|---|---|---|
| F1 | High | `.github/workflows/release.yml:694`; `scripts/release/reproducible_build.py:156-162` | The two-build proof still runs a toolchain that the job chooses. `env -i` passes the job `PATH` through (step-persistent `GITHUB_PATH` entries included), and `build_once` overrides neither `RUSTC`/`build.rustc`, `CARGO_TARGET_<T>_LINKER`/`target.<triple>.linker` nor the `[env]` table of `$CARGO_HOME/config.toml` (which is passed through) or of the workspace `.cargo/config.toml`. Both builds also share one `$CARGO_HOME/registry/src`, and cargo does not re-verify that extracted source. A stateful `cargo`/`rustc`/linker can replay build 1 into build 2. The proof then reports a build that is not reproducible as proven and writes a chosen `sha256=` to `$GITHUB_OUTPUT`, which is the exact #6909 impact. Issue #6909 proposed `PATH=/usr/bin:/bin` plus an absolute `--cargo`. The fix deviated with an inline `decision:` and no vote (T5). | `lens4.py` (b) runs the exact release.yml:694 statement with a cargo on `PATH` that writes `os.urandom` on its first call and replays it on the second: `rc=0 ... OK (two builds ... are byte-identical: 19004d28...)`, and `$GITHUB_OUTPUT got: sha256=19004d28...`. Control with a stateless random cargo: `rc=1` (mismatch). `lens4.py` (a) shows the build env keys: `CARGO_HOME HOME PATH RUSTUP_HOME TMPDIR` passed through, with no `RUSTC`/linker override. | ~15 lines: resolve the toolchain's absolute `cargo`/`rustc` before `env -i` (pass `--cargo` and set `RUSTC` in `build_once`); `PATH=<toolchain bin>:/usr/bin:/bin`; set `CARGO_TARGET_<T>_LINKER` explicitly; give each build its own `CARGO_HOME` (a copy of nothing but the toolchain-independent config); guard pin and a `proof_runtime` form "stateful cargo on PATH" |
| F2 | Medium | `scripts/check_release_features.py:2105,2329` | #6904 is NOT MET. The issue says `check_uses_pinned` must walk every `uses:` "in all three workflows" and be called from "the publish-ci path". It is called only for `release.yml` and `release-shape.yml`, so a tag ref in `publish-ci-image.yml` passes the guard. | `lens3.py`: `uses: publish-ci-image checkout -> @v4` gives rc=0 OK (SURVIVOR); `publish-ci-image build-push -> @v6` gives rc=0 OK (SURVIVOR). | ~3 lines (call it from the CI-image check near `:2005`) + 2 guard cases |
| F3 | Medium | `.github/workflows/release.yml:545,595,599` | `--verify-dist` (:545) is not the last step before publication. "Re-assert the release tag has not moved" runs `bash scripts/release/assert-tag-unmoved.sh` (:595) in the job shell before `softprops/action-gh-release` uploads `dist/ai-memory*` (:599-602). That script is not in `BIND_SUMMED` (`check_release_features.py:264`) and no step binds its content, so under the branch's own threat model (an earlier step rewrites a checked-out file) it can rewrite `dist/` after the strict check. The sbom, mobile-ios and mobile-android jobs run the same unbound script (:792, :964, :1161) before their own release step and have no strict reader at all (F10). | Read: `grep -n assert-tag-unmoved` finds it only as a pinned step body (`check_release_features.py:703`), not as a bound digest. The step order is pinned by `RELEASE_STEPS`. | ~8 lines: add the script to `BIND_SUMMED` and bind it in the step, or move the re-assert ahead of the sweep and keep `--verify-dist` immediately before the release action; guard pin |
| F4 | Medium | `scripts/release/reproducible_build.py:593-600` (`_decompress`), used by `_strict_tar` :398 and `_rpm_payload` :678 | The gzip layer is not read strictly. Python `gzip.decompress` accepts any header mtime, OS byte, XFL, FNAME, FEXTRA, FCOMMENT, a wrong FHCRC, trailing NUL bytes and extra members. A wrong FHCRC is a live parser differential (#7019 class): the strict reader accepts the package and dpkg refuses it. This contradicts `changelog.d/7019.security.md` ("the same strictness as dpkg and rpm") and the round-3 brief's "gzip header pin", which is pinned only on the writer side (`pack_binary` self-test, e81f3d5a6), never in the reader. | `lens2.py`: 11 gzip-framing survivors on the tarball and 6 on deb members (e.g. `ACCEPTED tarball gzip FHCRC with a wrong CRC16`, `ACCEPTED deb data.tar second gzip member (zeros)`). `lens2b.py`: `strict reader: ACCEPTED deb with bad data.tar.gz FHCRC`, but `dpkg-deb -c ... rc=2 ... header crc mismatch` and `gzip -t bad FHCRC: rc=1 ... header checksum 0xadde != computed`. | ~25 lines: one `_strict_gzip` that requires the exact 10-byte header nfpm/`pack_*` write (no flags, mtime 0, fixed OS), inflates one raw-deflate member with `zlib.decompressobj(-15)`, checks the CRC32/ISIZE trailer and refuses any trailing byte; red cases for each form |
| F5 | Medium | `scripts/check_release_features.py:4660` | The fast condition-anchor check refuses only `count > 1`. A missing anchor (0 occurrences), or one that sits only in a comment or below the marker, passes. The comment at :5027 says "Each anchor must occur exactly once", and the #6280 closure comment says "requires every condition-mutant anchor to occur exactly once". A removed anchor is reported only by the ~60-minute sweep, which is the delay #6280/#6954 set out to remove. | `lens5.py`: `0 refusals (want >=1) fixture: missing anchor (0 occurrences) <== SURVIVOR`; `live: first condition anchor removed from the guard text ... <== SURVIVOR` (4/9 survivors). | 1 line (`!= 1`) + 1 fixture |
| F6 | Low | `reproducible_build.py:418-433,458-483,657-659,603-647` | Header fields that are never checked: tar `mtime` and `devmajor`/`devminor`; ar `mtime`/`uid`/`gid`/`mode`; rpm lead `archnum`/`osnum`; cpio `mtime`/`dev`/`check`. A tarball member spelled `./ai-memory` is also normalised and accepted, where the writer emits `ai-memory`. None changes the installed file, but each is a byte that ships unchecked. | `lens2.py`: `ACCEPTED deb ar header uid field 'x'`, `ACCEPTED deb control.tar member mtime, chksum fixed`, `ACCEPTED rpm lead archnum low byte`, `ACCEPTED tarball member name './ai-memory'` | ~15 lines |
| F7 | Low | `scripts/check_release_features.py:2081-2082` | `USES_PINNED_RE` admits `..` path segments (`actions/checkout/../../evil/act@<40hex>`). | `lens3.py`: `uses: path traversal ...` gives rc=0 OK (SURVIVOR) | 1 line + 1 case |
| F8 | Medium (process) | `docs/adr/ADR-003-release-proof-6062-crossroads.md:75-77`, `changelog.d/6908.security.md` | #6908 (a T3 decision) was settled by a "3-agent vote (6def5ab6)". The tracked CLAUDE.md §Crossroads requires exactly 5 concurrent adversarial agents. The #6909 PATH deviation from the issue's proposed fix (T5) was settled inline, with no vote (see F1). | Read: ADR D4 heading and the ea9bb20a / 5d9cf8e9 bodies. | Re-run both as 5-agent votes and record them in ADR-003 |
| F9 | Low (process) | commits 22a5b456, baeb12d7, 5935681b, 116de5b3, 12bd3ded, 5fb97c15 | 22a5b456 and baeb12d7 (#6904 #7010 #6905) and 5935681b and 116de5b3 (#7018 #7019) each bundle child issues; the rule is one item per commit. The subject of 12bd3ded (`docs(changelog):`) carries no `(#N)`. The red commit 5fb97c15 for #6954 is green on `--self-test` (rc 0), and its red evidence lives only in the uncommitted `u_mutants.py` (`r_mutants.py` for #6955 a5d6a978, and the e81f3d5a6 pin likewise). This review reproduced all three (Evidence 1). | `lens1.out` row `5fb97c15 guard rc=0 fails=0` | Forward-only: state it in the PR body; no history rewrite |
| F10 | Low (docs) | `docs/adr/ADR-003-release-proof-6062-crossroads.md:89-91`; `reproducible_build.py:93,147`; `changelog.d/6904.security.md`; commit 116de5b3 subject | ADR D4 says the runner-trust boundary is "tracked as a residual issue" but cites no issue number. Commit 5d9cf8e9 says the `env -i` variables "are the build allowlist BUILD_ENV_ALLOWLIST", but the allowlist also holds `RUSTUP_TOOLCHAIN`, which release.yml:694 does not pass. That is harmless today because both jobs and `rust-toolchain.toml` pin 1.98.0, but it is drift. The `build_once` docstring promises "an allowlisted environment only", yet CPython's PEP 538 coercion adds `LC_CTYPE=C.UTF-8` (`lens4.py` (a)). The 6904 fragment says "every `uses:` of the release workflows" while `publish-ci-image.yml` is not covered (F2). The 116de5b3 subject says "every published release byte", while the sbom, mobile-ios and mobile-android jobs publish without a strict reader (`subject-path`/`files:` at release.yml:780/799, :952/971, :1149/1168). | Read and `lens4.out` | Text-only, ~6 lines |
| F11 | Low | `reproducible_build.py:331,337` | `pack_binary` calls `os.chmod(copy_to, ...)` by path after the `O_EXCL\|O_NOFOLLOW` create, which follows a symlink swapped in meanwhile. It returns the digest of a re-read of `out`, not of the bytes it wrote. | Read | ~4 lines (`os.fchmod(fd)`; hash the in-memory archive) |

## Evidence

1. **Red-on-base / green-on-tip (lens 1).** `lens1.py` ran `reproducible_build.py --self-test`, `check_release_features.py --self-test` and the static guard in a worktree per commit (`.local-runs/lens1.out`). Base `86410f7e4`: all three rc=0 (616 guard cases). Each red commit fails for the stated reason, with no Traceback/ImportError/SyntaxError (`tb=0` everywhere):
   `0edc07fa guard rc=1 fails=35 ... release-shape proof bind PASSED with scripts/release-shape-pg-proof.sh rewritten after checkout (symlinked .git to a decoy store)` (body claims 35);
   `13c0a1ed guard rc=1 fails=5 ... shipped bytes the strict assert never checked (dist binary rewritten before nfpm)` (claims five);
   `e5a2b402 guard rc=1 fails=2 ... proved a non-reproducible build (user site-packages usercustomize, rc 0 ...)` (claims two);
   `22a5b456 guard rc=1 fails=12 ... '6905 final stage USER aimem twice' wanted fail, got pass` (claims twelve);
   `5935681b repro rc=1 fails=18 ... 6907b deb member past a corrupt tar header is refused: accepted, wanted refused` (claims 18);
   `02ef7853 repro rc=1 fails=17 ... 7032 dist deb and rpm of different versions are refused: accepted` (claims 17).
   Each paired fix commit and every later commit: all three rc=0. Tip `e81f3d5a6`: packer `self-test OK`; guard `self-test OK (... 651 guard cases, 6 advisory cases, 9 message cases, 16 parity cases, 7 scalar cases, 9 entry-point cases)`; static `check_release_features: OK (release features: sal,sal-postgres)`. The packer self-test is also rc=0 on python3.11 and python3.12. For the test-only pins (`lens1b.py`), each mutant SURVIVED at the pin's parent and was KILLED at the tip:
   6954 U1 and U2 (`5fb97c15` rc=0 -> tip rc=1 `condition anchor fixture 'duplicate anchor' gave 0 refusals, want 1`);
   6955 R5 and R8 (`f2b007d3` rc=0 -> tip rc=1 `6955 a build.rustc-wrapper in .cargo/config.toml does not wrap the builds`);
   four pack_binary mutants (`8cc19243` rc=0 -> tip rc=1 `6907 pack_binary: the gzip header carries a timestamp or a file name` / `the member carries a build-host mtime or owner`).
   The repo has no unittest modules for these scripts; the self-tests are the test runner.
2. **Strict-reader differential (lens 2).** `lens2.py` built fixtures with the packer's own `_synthetic_package` / `_synthetic_tar` and ran 58 cases, 25 of which were not as wanted. Refused as wanted: trailing garbage after a gzip member; a byte after the last ar member; rpm lead magic, major, type, signature type, reserved byte and name; `..` paths in tar and cpio; symlink entries; nlink 2; non-root cpio; a symlinked dist artifact (ELOOP); an extra symlink, subdirectory or hard link in `dist/`; a CRLF or `../` sidecar. Accepted (survivors): every gzip-framing form (F4); tar mtime and devmajor; ar mtime, uid and mode; rpm lead archnum and osnum; `./ai-memory` (F6). Differential: `lens2b.py` gives `strict reader: ACCEPTED deb with bad data.tar.gz FHCRC` and `dpkg-deb -c bad-FHCRC deb: rc=2 ... internal gzip read error: '<fd:4>: header crc mismatch'`.
3. **Pin-the-pin (lens 3).** `lens3.py` used the guard's own `mk_root` and ran 31 mutants: control rc=0, 3 survivors. Refused: a `uses:` tag, branch, 39-hex, UPPER-hex or quoted tag in release.yml and release-shape.yml; a bind pin off by one hex digit (first occurrence or every occurrence; this holds for the features pin too); a bind without `-c`; a duplicated pin line; `USER aimem` removed, `USER root`, lower-case `user aimem`, `USER 0` after it, `USER aimem:root`, USER moved; a grant spelled across three lines with a comment (`line outside the subset grammar ...: write`); a flow-map grant; `write-all`; nfpm.yaml with an extra `depends` / `scripts.postinstall` / `rpm.compression` key or a comment. Survivors: the two `publish-ci-image.yml` refs (F2) and the `..` uses path (F7). `lens3b.py` (#6280): ARG before the first FROM, ARG/ENV/lower-case `arg` in the builder and `RUN --mount=...from=` are all refused, rc=1 (6/6).
4. **Two-build proof (lens 4).** `lens4.py` ran the exact release.yml:694 statement. Dropped by `env -i`: `CARGO_ENCODED_RUSTFLAGS`, `RUSTC`, `CARGO_BUILD_RUSTC`, `CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER`, `LD_PRELOAD`, `PYTHONPATH`, `TZ`, `LANG`, `LC_ALL`, `RUSTUP_TOOLCHAIN`, `CARGO_PROFILE_RELEASE_DEBUG`, `RUSTC_BOOTSTRAP`, `CARGO_NET_OFFLINE`. Overridden by `build_once`: `RUSTFLAGS`, `SOURCE_DATE_EPOCH`, `CARGO_TARGET_DIR`, `CARGO_INCREMENTAL`, `RUSTC_WRAPPER`, `RUSTC_WORKSPACE_WRAPPER`. Passed through: `PATH`, `HOME`, `CARGO_HOME`, `RUSTUP_HOME`, `TMPDIR`. Added by the interpreter: `LC_CTYPE`. Channels that still influence build 2 differently from build 1: a stateful executable on `PATH` (proven, rc=0 with a forged digest); `build.rustc`, `target.<triple>.linker` and `[env]` from `$CARGO_HOME/config.toml` or `.cargo/config.toml`, which nothing in the build env overrides; and the shared `$CARGO_HOME/registry/src` (F1).
5. **Condition-anchor check (lens 5).** `lens5.py`: the shipped fixtures pass. Duplicated anchor: 1 refusal. A replacement equal to its own anchor: 1 refusal. A live anchor duplicated in a comment: 1 refusal. Missing anchor, comment-only anchor, below-marker anchor and a live anchor removed from the guard: 0 refusals each (F5).
6. **Hygiene.** `python3 -I -m py_compile` passes on both touched .py files, as does `ast.parse(feature_version=(3,9))`. The diff has no `shell=True`, no `os.system` and no `/tmp`, and adds no `.sh` file. Every f-string inside `subprocess.run` is an argv element, not shell text. No `match` statement (one `match =` variable at `reproducible_build.py:774`) and no `X | None` annotations. Local `%G?` cannot verify the signatures (no allowed-signers file, and the user-keys endpoint is blocked in the sandbox). Instead `GET /repos/alphaonedev/ai-memory-mcp/commits/<sha>` for all 75 returns `75 True valid alphaonedev@users.noreply.github.com`. 75/75 commits carry `gpgsig`, `Base:` and `Co-Authored-By:` and a `Refs` trailer; none carries `Claude-Session`; 18 (round 3) cite a parent `Refs: #N` and not `#6062`. Each changelog.d fragment names its issue. Fragment-vs-commit mismatches are in F4 (7019), F2/F10 (6904) and F8 (6908's 3-agent vote).
7. **Docs drift.** Round 3 changes only `docs/adr/ADR-003-release-proof-6062-crossroads.md` (+18, D4) among docs. D4 matches the workflow text: each bind pipes `echo "<sha256> *<file>"` to `/usr/bin/shasum -a 256 -c -` with `HEAD == PREFLIGHT_SHA` (release.yml:368, :395, :434, :478, :544, :691, :940, :1113; release-shape.yml:110, :177). Mismatches are listed in F8 and F10. Earlier-round claims rechecked: `scripts/release/verify-tag.sh` and `scripts/qc-allowlists/release-tag-signers.txt` exist and release.yml:157 runs them; the toolchain claim is true (`toolchain: 1.98.0` at :334 and :668; `rust-toolchain.toml` `channel = "1.98.0"`).
8. **Issue requirements.** The issue text was read with `curl -s https://api.github.com/repos/alphaonedev/ai-memory-mcp/issues/<N>` (and `/comments`; `gh issue view` gives HTTP 403 because GraphQL is blocked here). See the table below.

## Issue requirements

| Issue | Acceptance line (from the issue's proposed fix / impact) | Status | Proving command |
|---|---|---|---|
| #6907 | Packer reads the binary once, hashes that buffer, refuses on mismatch and writes the tarball and copy from it | MET | `read_once`/`pack_binary` (`reproducible_build.py:271,301`); packer `--self-test` OK |
| #6907 | Asserted digest computed in the sanitized shell; no PATH `cp`/`shasum` compare; x86_64 REPRO tied to the packed bytes | MET | release.yml assert step (`env -i ... python3 -I ... --sha256`), package step `--pack-binary ... --expect-sha256 "$ASSERTED_SHA256"` after `REPRO_SHA256 = ASSERTED_SHA256` |
| #6907 | Guard pins + package tamper forms + refusal of a pack line without the expectation | MET | guard `--self-test` OK; red `13c0a1ed` 5 FAIL -> green |
| #6908 | Expected digest from a source the job cannot write; same in release-shape.yml | MET (option A by a 3-agent vote, see F8) | `lens3.py` pin off-by-one refused; release-shape.yml:110,177 bind |
| #6908 | Tamper forms: forged loose tree, exploded pack, alternates, symlinked .git, gitfile | MET | `0edc07fa` 35 FAIL -> `ea9bb20a` guard OK (10 STORE_FORMS) |
| #6909 | Proof under `env -i` with `-I` | MET | release.yml:694; red `e5a2b402` 2 FAIL -> green |
| #6909 | `PATH=/usr/bin:/bin` and an absolute `--cargo` (proposed fix); impact "proof can report reproducible ... without the two builds agreeing" closed | NOT MET | `lens4.py` (b): stateful PATH cargo -> rc=0, forged `sha256=` (F1) |
| #6909 | Refusal case for a proof line without `-I` | MET | `6909 ...` guard cases; guard `--self-test` OK |
| #6904 | `check_uses_pinned` walks every `uses:` in all three workflows, called from the publish-ci path | NOT MET | `lens3.py`: 2 `publish-ci-image.yml` survivors (F2) |
| #6904 | Self-test: mutable checkout in preflight and in crates-io refused | MET | `check_release_features.py:3323,3332`; `lens3.py` preflight `@v4` refused |
| #7010 | Every step of every job in release.yml and release-shape.yml refuses a non-40-lowercase-hex ref; cases for `@stable`, tag, 39-hex, branch | MET | `lens3.py` (`@stable`, `@v5`, 39-hex, UPPER refused); cases at `:3319-3334` |
| #7010 | Rule's refusal call in the mutation sweep | MET (the sweep neutralises every `rep.bad` call site) | `check_uses_pinned` refusal is a `rep.bad` site (`:2092`) |
| #6905 | Final stage holds `USER aimem` exactly once; cases for removed and `USER root` | MET | `lens3.py` removed / root / twice refused; `:3336-3338` |
| #7018 | Control member set and field allowlist, md5sums, empty conffiles, data dir/owner allowlist, rpm tag allowlist | MET | `5935681b` 18 FAIL -> green; packer `--self-test` OK |
| #7018 | `--verify-dist`: dist is exactly the checked tarball, deb and rpm plus their sidecars | MET for the inventory; dist can still change after the check (F3) | `lens2.py` dist cases refused; release.yml:545 vs :595/:599 |
| #7019 | Strict tar reader (checksums, no extension headers, zero tail); rpm header agrees with the payload; strict cpio names | MET | `lens2.py` pax/link/`..`/uid cases refused; `6907b` cases |
| #7019 | (defect class) no parser differential with dpkg/rpm | NOT MET at the gzip layer | `lens2b.py` bad FHCRC: strict ACCEPTED, dpkg-deb rc=2 (F4) |
| #7032 | rpm payload gzip only; strict lead; signature header {62,273,1000,1007} tied to header/payload; NAME ai-memory, RELEASE 1; dist name/metadata and deb-vs-rpm compare; trailing-`/` file names refused; both workspaces resolved | MET (lead archnum/osnum unchecked, F6) | `02ef7853` 17 FAIL -> `074152ad` OK; `lens2.py` lead cases |
| #6954 | `condition_anchor_failures(src, table)`; fixtures dup -> 1, clash -> 1, clean -> 0; both mutants in `CONDITION_MUTANTS` | MET (missing-anchor gap, F5) | `lens1b.py` U1/U2 killed at tip; `:5079-5080` |
| #6955 | Fixture with `.cargo/config.toml` `rustc-wrapper`, same for the workspace wrapper | MET | `lens1b.py` R5/R8 survive at `f2b007d3`, killed at tip |
| #6280 | Refuse ARG before the first FROM, ARG/ENV in the builder before the build RUN, `RUN --mount=...,from=`; anchors exactly once | MET for the Dockerfile lines; the "exactly once" anchor claim is not enforced for 0 occurrences (F5) | `lens3b.py` 6/6 refused; `lens5.py` |

```
REPORT lane=rev-6062-r3 branch=cloud/f1/rev-6062-r3 base=e81f3d5a6218bc0f25f35331c9375612eb69bdb3 head=<this commit> pushed=yes
COMMITS
<this commit> review(#6062): cloud adversarial review of fix/6062-promo6-ssh-r3 head e81f3d5a6
ITEMS
#6907 | reviewed | MET | 2 (F4 reader-side gzip framing, F11)
#6908 | reviewed | MET | 1 (F8 3-agent vote)
#6909 | reviewed | NOT MET | 2 (F1 High, F8)
#6904 | reviewed | NOT MET | 2 (F2, F10)
#7010 | reviewed | MET | 1 (F7)
#6905 | reviewed | MET | 0
#7018 | reviewed | MET | 2 (F3, F10)
#7019 | reviewed | NOT MET | 2 (F4, F6)
#7032 | reviewed | MET | 1 (F6)
#6954 | reviewed | MET | 2 (F5, F9)
#6955 | reviewed | MET | 1 (F9)
#6280 | reviewed | MET | 1 (F5)
GATES
git merge-tree --write-tree 574740a31 e81f3d5a6 -> rc=0 86306c006e4f38d28902d1e98c4329fd8d3bebc9
python3 -I scripts/release/reproducible_build.py --self-test (tip) -> rc=0
python3 -I scripts/check_release_features.py --self-test (tip) -> self-test OK (651 guard cases, ...)
python3 -I scripts/check_release_features.py (tip) -> check_release_features: OK (release features: sal,sal-postgres)
bash scripts/check-count-assertion-declared.sh --range origin/chain/promo6-ssh..HEAD -> count-assertion-declared: clean
python3 scripts/test/test_workflow_pr_triggers_5447.py -> OK
bash scripts/test/test-ci-workflow-invariants.sh -> ci.yml invariants: 38/38 PASS
cargo fmt/clippy/test -> not run (no Rust touched; lane brief: run NO cargo)
DECISIONS
#6280 reviewed against its literal Dockerfile-ARG text plus the round-3 anchor-uniqueness follow-up named in its closure comment
signatures verified through GitHub REST commit verification (repo-scoped) because the user-keys endpoint is blocked in the sandbox
the commit's Base: trailer names e81f3d5a6 (the branch point this lane brief prescribes), not the common-brief fa6b588e6
gzip-framing and header-field gaps split into F4 (live dpkg differential) and F6 (no installed-file effect), per the #7019/#7032 split precedent
FOUND-NOT-FIXED
.github/workflows/release.yml:694 + scripts/release/reproducible_build.py:156-162 two-build proof runs a job-chosen toolchain (PATH, CARGO_HOME config, shared registry/src) (F1)
scripts/check_release_features.py:2105,2329 check_uses_pinned not applied to publish-ci-image.yml (F2)
.github/workflows/release.yml:595 unbound assert-tag-unmoved.sh runs after --verify-dist (:545) and before release upload (:599) (F3)
scripts/release/reproducible_build.py:593-600 gzip framing not strict; bad FHCRC accepted where dpkg refuses (F4)
scripts/check_release_features.py:4660 fast anchor check accepts a missing anchor (F5)
scripts/release/reproducible_build.py:418-433,458-483,657-659 tar/ar/lead/cpio header fields unchecked (F6)
scripts/check_release_features.py:2081 USES_PINNED_RE accepts `..` segments (F7)
docs/adr/ADR-003-release-proof-6062-crossroads.md:75 #6908 decided by a 3-agent vote, not the mandated 5 (F8)
docs/adr/ADR-003-release-proof-6062-crossroads.md:91 residual issue cited without a number (F10)
scripts/release/reproducible_build.py:331,337 chmod by path after create; digest of a re-read (F11)
```
