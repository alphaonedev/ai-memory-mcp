# Cloud review fix/6062-promo6-ssh head c4b7332c3: VERDICT REJECT

Reviewer: cloud lane `rev-6062` (Claude Code sandbox, 4 cores / 15 GiB, sqlite only, rustc 1.98.0) for ai:god-f1.
Subject: `origin/fix/6062-promo6-ssh` head `c4b7332c3d42b093775033cd04b105cd02a281a8`, 18 commits on base
`chain/promo6-ssh` = `fa6b588e6b5dfa97370b4f073e60e66cb1ed1fa7`. Umbrella #6062 (WP-B3). Read-only review: this lane
changed no production code; every probe below ran on scratch roots or throwaway worktrees under `.local-runs/`.

Branch shape verified: `git diff --stat fa6b588e6..HEAD -- '*.rs' Cargo.toml Cargo.lock` is empty (cargo-free by
design); 14 files, +1406/-167. Every gate the author cites is green on the tip (see Evidence 7). The REJECT is not
about what the branch pins; it is about what the branch *claims* the pins buy. Two of the ten children (#3613,
#4768) are NOT MET on the literal issue text, and the branch's own new control (the reproducible-build proof) is
not wired into anything that publishes.

## Findings

Ranked by severity. "Fix size" is the estimate for the author's follow-up commit on this branch.

### F1 — HIGH — #3613: the reproducible-build proof gates nothing; a mismatch cannot stop a publish

- **Where:** `.github/workflows/release.yml:576-601` (`reproducible:` job, `needs: [preflight, qualify, supply-chain]`);
  `release.yml:274`, `:1045`, `:1105`, `:1257`, `:1321` (every build/publish job's `needs:`).
- **What:** no job in release.yml needs `reproducible`. The release legs, sbom, docker, crates-io, homebrew and copr
  all run in parallel with the proof and, on `dry_run=false`, attach assets, push the GHCR image and publish the
  crate whether the proof passes, fails, or is still building. The commit body (7635aa771) and the workflow banner
  (`release.yml:561`) say "a mismatch fails the run"; true for the run's colour, false for the artifacts. The
  issue's stated purpose ("so the soaked binary is the tagged binary", #3546 D5) is a *gate*, not a report.
- **Reproduced:** `grep -n -E '^  [a-z-]+:$|^    needs:' .github/workflows/release.yml` → every `needs:` list is
  `[preflight, qualify, supply-chain]` or `[preflight, qualify, release]`; `grep -n reproducible release.yml | grep needs`
  → nothing.
- **Fix (~8 lines + REPRO_JOB / RELEASE_JOB_PERMISSIONS pin updates):** add `reproducible` to the `needs:` of every
  job that publishes (`release`, `sbom`, `mobile-*`, `docker`; the three that already need `release` inherit it).
  Cost: the proof (two cacheless fat-LTO builds) then sits on the critical path; the sandbox measured one such build
  at 23 minutes on 4 cores from a cold crates.io cache (Evidence 4), so two builds plus the worktree checkout land near 45-50 minutes, so `timeout-minutes: 120` on a 4-vCPU `ubuntu-latest` runner is
  tight and should be re-measured on a real run before the gate is trusted.

### F2 — HIGH — #3613: the proof's digest is never compared with the binary that ships, and the shipped build still restores a shared cache

- **Where:** `release.yml:326` (`Swatinem/rust-cache` step in the release job, pinned by `RELEASE_STEPS[2]` in
  `scripts/check_release_features.py:373`); `release.yml:390-391` (`steps.assert.outputs.sha256`); `release.yml:593-601`
  (proof step, no output); `scripts/release/reproducible_build.py:170-178` (prints the digests, exposes nothing).
- **What:** the x86_64 artifact that is packaged, attested and uploaded is built in the `release` job with a restored
  `target/` + `~/.cargo/bin` cache (an input the guard never reads; `~/.cargo/bin` is first on the runner's PATH), while
  the proof job builds twice *without* a cache and compares only its own two outputs. Nothing compares the proof's
  digest with `steps.assert.outputs.sha256`, so the proof shows "two cacheless builds agree" and says nothing about the
  bytes that were dogfooded or published. Since #3613's build step now exports `RUSTFLAGS` inside the step (after the
  cache action ran), the cache key does not include them and cargo's fingerprint invalidates every restored unit: the
  cache step is dead weight for the binary and a live PATH input for `git`/`bash`/`shasum`.
- **Reproduced:** read of the two jobs; no `outputs:` on `reproducible`, no artifact download anywhere.
- **Fix (~20 lines + REPRO_STEPS / RELEASE_STEPS updates):** (a) drop the rust-cache step from the release job (the
  shipped build becomes as independent as the proof build); (b) `reproducible` needs `release`, downloads the
  `ai-memory-x86_64-unknown-linux-gnu` artifact, and `reproducible_build.py --expect-sha256 <hash of dist/ai-memory>`
  refuses unless both of its builds equal the shipped binary's digest. Then F1's gating makes the proof mean what the
  issue asks.

### F3 — MEDIUM — #4935: the cross-workflow `packages: write` sweep is a per-line regex; three valid YAML spellings of the grant pass

- **Where:** `scripts/check_release_features.py:575-576` (`PACKAGES_WRITE_RE`, `WRITE_ALL_RE`), `:1482-1486`
  (`for n, line in code_lines(text)` — one line at a time).
- **What:** YAML plain scalars may continue on the next line and block scalars may fold. A decoy workflow with
  `permissions:\n  packages:\n    write`, with `permissions:\n    write-all`, or with `packages: >-\n  write` is a
  `packages: write` grant to GitHub and passes the guard; actionlint accepts all three as valid workflows.
- **Reproduced:** `.local-runs/rev-6062/yaml_probes.txt` — Y1, Y2, Y3: `guard SURVIVED rc=0 | actionlint rc=0`.
  (Y4, an expression-built image name, also survives; the author documents that limit at
  `check_release_features.py:573-574` and in the changelog, so it is not counted here.)
- **Fix (~4 lines):** run the two regexes over the comment-stripped text of the whole file (join `code_lines` with
  `\n`) and let `\s*` span the newline, with an optional block indicator: `packages\s*:\s*(?:[>|]-?\s*)?['"]?write(?![\w-])`
  and the same for `write-all`; add the three decoys as refusal cases so the sweep kills them.

### F4 — MEDIUM — #4752: `nfpm.yaml` is an unpinned input; the deb/rpm payload is bound to the asserted binary by a file the guard never reads

- **Where:** `nfpm.yaml:14-17` (`src: dist/ai-memory`); `release.yml:433-434` (`nfpm package -p deb -f nfpm.yaml`);
  `scripts/check_release_features.py:1743-1749` (`run_guard` loads release.yml, release-shape.yml, Dockerfile,
  INSTALL.md, release-features.sh — not nfpm.yaml).
- **What:** the hash bind covers `dist/ai-memory` and the tarball. The deb and rpm (checksummed, attested and uploaded
  by the same job) take their payload path, maintainer scripts and file modes from `nfpm.yaml`, which the guard does not
  pin: `src:` pointed at any other tracked file, or a `scripts: postinstall:` entry, ships inside a signed package with
  every guard green.
- **Reproduced:** `.local-runs/rev-6062/mutants.txt` M33 (`src: vendor/paste/ai-memory`): `SURVIVED rc=0`.
- **Fix (~12 lines):** load `nfpm.yaml` in `run_guard` and compare it whole to a pinned `NFPM_YAML` constant (the
  same shape as `DOCKER_RUN_LINES`); one refusal case; one mutation anchor.

### F5 — MEDIUM — #4752 / #4768: the Dockerfile's final stage can execute a file the runtime assert never checked

- **Where:** `scripts/check_release_features.py:1607-1636` (final-stage checks: exactly one binary COPY, no other
  `--from`, nothing after the runtime assert RUN); `Dockerfile:103-104` (`ENTRYPOINT ["ai-memory"]` — a bare name
  resolved through PATH).
- **What:** the final stage may `COPY <context file> /usr/local/bin/entry` *before* the binary COPY (no `--from`, so
  the `--from` loop ignores it) and point `ENTRYPOINT` at it; or keep `ENTRYPOINT ["ai-memory"]` and add
  `ENV PATH=/opt/evil:$PATH` after the assert (ENV is "metadata" per `:1636`). The runtime assert on
  `/usr/local/bin/ai-memory` still passes; the container runs something else.
- **Reproduced:** mutants.txt M17 (context COPY + ENTRYPOINT swap): `SURVIVED rc=0`; M38 (final-stage `ENV PATH`):
  `SURVIVED rc=0`.
- **Fix (~10 lines):** in the final stage refuse every `COPY`/`ADD` other than the two pinned `--from=<builder>` lines,
  refuse `ENV PATH`, and pin `ENTRYPOINT ["/usr/local/bin/ai-memory"]` (absolute) + the `CMD` line as constants.

### F6 — MEDIUM — #4768: the builder's environment and base image are still unbound (the classes the issue thread listed on 2026-10-03 are untouched)

- **Where:** `scripts/check_release_features.py:1643-1658` (builder checks: no `--from`, lock COPY, asserter/decl COPY
  order, canonical RUN last); `:1636-1642` (build-tool word scan); `check_matrix` `:1172-1200` (`os:` pattern only).
- **What:** inside the builder stage, before the pinned tail, the guard accepts `ENV PATH=/opt/evil:$PATH`,
  `ENV RUSTC_WRAPPER=/opt/evil/wrap`, `ENV CARGO_BUILD_RUSTC_WRAPPER=/opt/evil/wrap`, `ENV CARGO_HOME=/opt/evil`,
  `ENV ENV=...`, `COPY .cargo/ .cargo/` (a cargo config can set `build.rustc-wrapper`, `[env]`, target linkers) and a
  swapped `FROM` image; in release.yml the x86_64 leg's `os:` may be `self-hosted`. Each changes what the pinned
  `cargo build` and `bash scripts/assert-compiled-features.sh` resolve to, which is the issue's definition of the
  defect ("the step environment / command lookup path"). The one variant the guard did catch (M19,
  `ENV CARGO_BUILD_RUSTC_WRAPPER=/opt/evil/rustc`) was caught by the word `rustc` in the *value*, not by design: M19b
  with `/opt/evil/wrap` passes. The docstring's own exclusion note (`:185-187`) names only PATH-replacing actions.
- **Reproduced:** mutants.txt M18, M19b, M19c, M19d, M20, M27, M28, M36: all `SURVIVED rc=0`; M19, M37 caught (by the
  value's tool word).
- **Fix (~25 lines):** pin the builder `FROM` reference (digest-pinned constant), refuse `ARG`/`ENV` in the builder
  and `COPY`/`ADD` of any path outside the allowlisted sources (`Cargo.toml Cargo.lock src/ benches/ tests/ examples/
  migrations/ vendor/ scripts/...`), pin the matrix `os:` set beside `RELEASE_TARGETS`.

### F7 — MEDIUM — #4768: the `git diff --quiet HEAD` bind is anchored to the working tree's index flags and to `HEAD`, not to the verified sha's bytes

- **Where:** `release.yml:351`, `:374`, `:598` (`git diff --quiet HEAD -- ...`); `scripts/check_release_features.py:221`
  (`BIND_INPUTS`), `:515` (`REPRO_BIND`).
- **What:** `git diff HEAD` trusts the index: a file marked `--assume-unchanged` or `--skip-worktree` reports clean
  with a narrowed declaration on disk; a local commit moves HEAD so the narrowed file *is* HEAD's; `git replace` of
  the checked-out commit redirects HEAD and `rev-parse <sha>:path` alike. The check also never names
  `needs.preflight.outputs.sha`, so it binds to whatever HEAD is at that moment. Reach: only a step that runs before
  the build in the same job can set these, and the job is whole-pinned, so today that means the three SHA-pinned
  actions (checkout, toolchain, rust-cache) or a restored `~/.cargo/bin`; this is why it is MEDIUM, not HIGH. The
  brief's "modify, build, restore" sequence is NOT reachable: the bind and the build are one bash script (probe P7).
- **Reproduced:** `.local-runs/rev-6062/bind_probe.txt`: P2 (assume-unchanged), P3 (skip-worktree), P4 (local
  commit), P5 (git replace) → `BIND rc=0 (PASSES)` with the narrowed file on disk; P1, P6 refused. A stronger bind,
  `test "$(git hash-object scripts/release-features.sh)" = "$(git --no-replace-objects rev-parse "$SHA:scripts/release-features.sh")"`
  (bytes on disk vs the verified sha's blob, replace refs ignored), refuses P1–P6 and passes P0/P7.
- **Fix (3 statements per site, `BIND_INPUTS`/`REPRO_BIND` constants + `SHA: ${{ needs.preflight.outputs.sha }}` in
  the steps' `env:`):** the hash-object form above for both files; keep `git diff --quiet` if wanted, it costs nothing.

### F8 — MEDIUM — #3613 Required 1 / Required 3 / Acceptance: three literal requirements are not met

- **Where:** issue #3613 body; `release.yml:412-438` (deb/rpm step: no `SOURCE_DATE_EPOCH` in its `env:` — the build
  step's `export` does not survive the step boundary); `release.yml:745-1038` (mobile jobs: no epoch, no remap);
  `release.yml:1255-1317` (docker job: no `SOURCE_DATE_EPOCH` build-arg); `release.yml:568-572` ("each a tracked
  #3613 item" — #3613 is closed and no item numbers exist); `docs/compliance/MISSION-CRITICAL-CERTIFICATION-STANDARD-v1.md:320`
  (the checklist row the issue says must record coverage: unchanged on this branch).
- **What:** "Every release artifact job pins SOURCE_DATE_EPOCH" → only the release build step and the SBOM step do.
  "Each 'not yet' gets a tracked item" → none filed. "The release checklist (#3308) records which artifacts are
  covered" → not touched.
- **Fix:** deb/rpm step `env: SOURCE_DATE_EPOCH: ${{ steps.<epoch>.outputs.epoch }}` via a step output from the build
  step (~6 lines + RELEASE_STEPS); f1 files five tracked items (aarch64, macOS x2, deb/rpm, xcframework, Docker) and
  the workflow banner cites them; one row in the checklist.

### F9 — LOW — #4720: the issue's literal trigger ("first green run on main") never happened and the deviation is not flagged

- **Where:** issue #4720 title/body; `release-shape.yml:37-44` (`pull_request.branches` includes `main`, `push`
  only `release/**`); commit da63b8c58 body.
- **What:** the public Actions API shows 89 `release-shape.yml` runs, 0 with `head_branch == main` and 0 PRs into
  `main` (`actions/workflows/release-shape.yml/runs?per_page=100`: 67+5+2+1 success, 13 cancelled, 1 other; "latest 25"
  = 24 success + 1 cancelled, not "all success" as the commit says). The author substituted "green on pull_request
  events into chain/release branches", which is defensible, but it is a T5 deviation from the written condition and
  the commit does not say so.
- **Fix:** one sentence in the changelog fragment and the workflow banner naming the substituted criterion.

### F10 — LOW — #4768 Proposed fix 1: absolute interpreter path and sanitised environment were not done, and the Dockerfile item 3 was replaced by COPY ordering

- **Where:** `release.yml:374-386` (`bash scripts/assert-compiled-features.sh ...`, PATH-resolved `bash`, `git`,
  `shasum`); `Dockerfile:53-61`.
- **What:** the issue asks to "invoke the asserter with an absolute interpreter path and a sanitized environment
  (unset BASH_ENV/ENV)" and, in the Dockerfile, to "verify the copied declaration and asserter checksums against
  values the guard pins". Neither landed; the COPY-ordering pin is a reasonable substitute for the second, the first
  is simply absent. With F6 and F7 open, the asserter still runs through PATH.
- **Fix:** `/usr/bin/env -i PATH=/usr/bin:/bin /bin/bash scripts/assert-compiled-features.sh ...` (and `/usr/bin/git`)
  in the two units (~2 statements + constants), or state the deviation in the fragment.

### F11 — LOW — missing `changelog.d` fragments for #4768 and #3613 (author admits)

- **Fix:** `changelog.d/4768.security.md`: "**[release][supply-chain] The strict feature assert's inputs are bound to
  the checked-out commit (#4768, umbrella #6062).** The release build and assert steps open with
  `git diff --quiet HEAD -- scripts/release-features.sh scripts/assert-compiled-features.sh`, the Dockerfile pins the
  asserter COPY immediately before the declaration COPY, and `scripts/check_release_features.py` refuses either
  missing." `changelog.d/3613.fixed.md`: "**Release workflow builds the x86_64 Linux binary twice from the verified
  commit and fails on any byte difference (#3613, umbrella #6062).** New `reproducible` job +
  `scripts/release/reproducible_build.py`; the release build pins `SOURCE_DATE_EPOCH` and remaps runner paths. Linux
  x86_64 only; nothing else is claimed reproducible yet."

### F12 — LOW — docs drift (each line must match tip behaviour)

- `docs/release-pipeline.html:532` — the sentence this branch edited still ends "the GPG-signed tag"; tags are
  SSH-signed (`release.yml:14`, `:146`; `scripts/release/verify-tag.sh:121-130`). Fix: "SSH-signed tag".
- `docs/encryption.html:287` "Every release tag is GPG-signed" → "SSH-signed"; `:441` "Bit-for-bit reproducible builds
  are NOT claimed — a same-runner rebuild cannot detect a compromised runner" → add the #3613 proof clause used on
  release-pipeline.html.
- `docs/audience/decision-maker.html:130` "reproducible builds are on the v1.0 roadmap" → "a two-build byte-identity
  proof runs on the x86_64 Linux release binary (#3613); no artifact is claimed reproducible until it passes on a
  release run".
- `docs/handoff/READY-TO-TAG-v1.0.0-CERT-NOTE.md:46` "`sal-postgres` is not on every multi-OS release binary" →
  contradicts `scripts/release-features.sh` (sal,sal-postgres on every leg since #4480); pre-existing, one sentence.
- `.github/workflows/release.yml:26` "The 5 jobs below mirror the historical release fanout" → there are 12 jobs; this
  branch added one without touching the sentence. Fix: "The jobs below ...".

### F13 — LOW — `reproducible_build.py` accepts a pre-existing `--workspace-b` as-is outside `--self-test`

- **Where:** `scripts/release/reproducible_build.py:121-126`.
- **What:** on a runner where `$RUNNER_TEMP/reproducible-b` already exists (self-hosted, re-run), the second build
  reuses that directory and its `target/`; the "two independent builds" premise silently weakens. Fail closed:
  refuse an existing directory unless a `--reuse-workspace-b` flag (used by the self-test) is given (~5 lines).

### F14 — LOW — the #3613 red commit's 13th red line is a missing-file error, not the defect

- **Where:** e1680e206; `red_on_base.txt` line "`scripts/release/reproducible_build.py --self-test exited 2:
  /usr/bin/python3: can't open file`".
- **What:** twelve of the thirteen reds are guard cases that fail for the defect; the thirteenth fails because the
  script does not exist yet (the brief's "import error on a symbol the fix adds" class). The author states this in
  the commit body, so it is disclosed; recorded for completeness.

### F15 — LOW (pre-existing, FOUND-NOT-FIXED) — the bare `dist/ai-memory` asset is uploaded by all four legs under one name

- **Where:** `release.yml:457-462` (comment: "Tracked separately"), `:497` (`path: dist/ai-memory*`), `:508`
  (`subject-path: 'dist/ai-memory*'`), `:545` (`files: dist/ai-memory*`).
- **What:** the un-arch-qualified binary is attested by every leg and attached to the release by every leg (last
  writer wins), and is excluded from the checksum sweep. A GitHub search for the comment's phrase
  ("non-arch-qualified") finds no issue. #4752's "the shipped artifact is bound to the asserted binary" is true for
  the tarball and false for this asset.

### F16 — LOW — #3613: the "perturbed SOURCE_DATE_EPOCH" negative fixture is proven only against a stub cargo; the real binary ignores the epoch

- **Where:** `scripts/release/reproducible_build.py:182-202` (stub cargo writes the epoch into the fake binary), `:234`
  (the fixture); Evidence 4.
- **What:** the issue's acceptance asks for "a negative fixture [that] shows the comparison fails when one build is
  perturbed (for example a changed SOURCE_DATE_EPOCH)". In the sandbox the two builds were, by accident of a restart,
  made under two different epochs and still matched byte for byte: nothing in this crate reads `SOURCE_DATE_EPOCH`
  (no `build.rs`, no `vergen`/`built`/`shadow-rs` in Cargo.lock), so a real perturbed epoch would NOT be detected and
  the fixture proves the comparator, not the determinism lever. Harmless today (the lever is inert), misleading as
  evidence; the fixture that does bite on the real binary is the unremapped path (`RUSTFLAGS`), which the self-test
  also carries.
- **Fix:** say so in the banner and the fragment ("SOURCE_DATE_EPOCH is pinned for the SBOM and for any future
  build-time stamp; it does not currently affect the binary"), or add a real-binary negative fixture on the remap flag
  to the `reproducible` job's dry-run path (~6 lines).

## Evidence

Commands ran from the repo root on the tip unless stated; full outputs under `.local-runs/rev-6062/` (not committed).

1. **Red-on-base per child** (`red_on_base.py` → `red_on_base.txt`): each `test(#N)` commit's
   `scripts/check_release_features.py` run with `--self-test` on a worktree at that commit's parent (which already
   holds the earlier children's fixes), then `--self-test` on the child's last fix commit.
   - #4937 69b644e35 on fa6b588e6: rc=1, 2 FAIL (`'4937 supply-chain job inherits the top-level contents: write'`,
     `'4937 crates-io job inherits ...'`); c574a7db4: rc=0, 359 guard cases. Same two reds on the TRUE base.
   - #4720 c1dc63ccd on c574a7db4: rc=1, 1 FAIL (`'4720 release-shape job carries continue-on-error'`); da63b8c58: rc=0, 360.
   - #4936 afa4483fd on da63b8c58: rc=1, 10 FAIL (`'4936 release.yml on: gains workflow_call'` ...); d7c90cbf0: rc=0, 370.
   - #4935 41a2ef234 on d7c90cbf0: rc=1, 10 FAIL; 663a73424: rc=0, 420.
   - #4752 240871ac0 on f5e47baef: rc=1, 4 FAIL (`'4752 a step between the assert and the package replaces the binary'`,
     `'4752 nfpm step body copies another binary into dist'`, `'4752 checksum step body replaces the tarball'`,
     `'4752 Dockerfile final stage copies over the shipped binary'`); 8c07586d1: rc=0, 420.
   - #4768 af711f021 on 8c07586d1: rc=1, 11 FAIL (7 guard cases + 4 runtime "`the build/assert unit PASSED with
     ... rewritten after checkout (#4768): fail-open`"); 8593d1664: rc=0, 427.
   - #3613 e1680e206 on 8593d1664: rc=1, 13 FAIL (12 guard cases + the missing-script line, F14); c4b7332c3: rc=0, 439.
2. **Mutation sweep.** `python3 scripts/check_release_features.py` → `check_release_features: OK (release features: sal,sal-postgres)`.
   `python3 scripts/check_release_features.py --self-test` → `self-test OK (... 439 guard cases, 6 advisory cases, 7 message cases, 16 parity cases, 7 scalar cases, 9 entry-point cases)` (17 s).
   `python3 scripts/check_release_features.py --mutation-sweep` → `check_release_features: mutation sweep: 92 refusal mutants + 44 condition mutants = 136 mutants, 0 survivors (14 m 31 s wall on 4 cores, run concurrently with the two-build trial)`.
   **New mutants** (`mutants.py` → `mutants.txt`, 39 mutants the self-test does not contain, each applied to a scratch
   root built like the guard's `mk_root`): CAUGHT — M1 reorder (RELEASE_STEPS slot), M2 earlier step rewriting the
   declaration (step count 14≠13), M3 `|| true` on the assert (WF_ASSERT), M4 `continue-on-error` on the assert step
   (KEYS_ASSERT), M5 job `env:` (JOB_KEYS), M6 second `cargo build` after the assert (one build-tool line), M7
   `--locked` removed (WF_BUILD), M8 per-build `SOURCE_DATE_EPOCH` (WF_BUILD), M9a proof `|| true` (REPRO_STEPS), M10
   hash compare `|| true` (WF_PACKAGE), M11 job `continue-on-error` (JOB_KEYS), M12 `--no-default-features`, M13
   `FEATURES=` reassigned, M14 `--locked` in a trailing comment, M15 Dockerfile RUN reassignment (continuation
   refused), M16 assert step `if:`, M19/M37 wrapper env whose value contains a tool word, M22 top-level `env:`
   (TOP_KEYS), M23 `defaults:` (JOB_KEYS), M24 checkout at `github.sha` (RELEASE_STEPS), M29 `toolchain: stable`, M30
   proof workspace-b = workspace-a, M31 declaration drops sal-postgres, M32 package copies another file, M34
   rust-cache `with:`, M35 earlier step writing GITHUB_ENV. SURVIVED — M17, M18, M19b, M19c, M19d, M20, M27, M28, M33,
   M36, M38 (F4, F5, F6) and M9b (the proof script's compare neutralised passes the plain guard; `--self-test` catches
   it because the guard runs the script's self-test — acceptable since c8-precheck runs both).
3. **#4768 binding** (`bind_probe.py` → `bind_probe.txt`, throwaway worktree of the tip): P1 plain rewrite refused;
   P2 `--assume-unchanged`, P3 `--skip-worktree`, P4 local commit, P5 `git replace`: `BIND rc=0 (PASSES)` with the
   narrowed file on disk; P6 asserter deleted refused; P7 rewrite+restore before the step: on-disk restored, nothing to
   catch. The `git hash-object` vs `git --no-replace-objects rev-parse <sha>:path` form refuses P1–P6 (P5 only with
   `--no-replace-objects`: confirmed by hand, `STRONG --no-replace-objects rc=1`). The check is anchored to the working
   tree's `HEAD`, not to `needs.preflight.outputs.sha`. `.github/workflows/*.yml` itself is bound only at PR time
   (c8-precheck runs the guard on the PR tree; the release run executes `github.sha`'s copy, an ancestor-checked
   release branch tip). The Dockerfile binding covers the builder tail and the two runtime COPYs; it does not cover
   `ENTRYPOINT`/`CMD` or final-stage `ENV PATH` (F5).
4. **#3613 reproducibility trial.** `python3 scripts/release/reproducible_build.py --target x86_64-unknown-linux-gnu
   --features sal,sal-postgres --workspace-b .local-runs/rev-6062/reproducible-b` (the exact workflow command; the
   script sets `SOURCE_DATE_EPOCH=1791573133` = HEAD's `%ct` and
   `RUSTFLAGS='--remap-path-prefix=/home/user/ai-memory-mcp=/src --remap-path-prefix=/root/.cargo=/cargo'`, workspace B a
   detached worktree). Result: **byte-identical**, both `sha256 f80c2e936cfc693f3d8aa2ec4b274793e5c0da5b48ef5bf2b56c1dacefde3a84`, 47 645 352 bytes; `reproducible-build: OK (two builds of ai-memory for x86_64-unknown-linux-gnu are byte-identical: f80c2e93...)`, exit 0. Timing on 4 cores: build A 23 min from a cold crates.io cache (20:20:22 → 20:43:48); build B was interrupted by a sandbox restart while compiling the final crate and resumed with the identical command (A a fingerprint no-op in 11 s, B's last crate + fat-LTO link 7 m 05 s). Caveat recorded honestly: after the restart workspace A's HEAD was this review's own commit, so the script derived `SOURCE_DATE_EPOCH=1791578753` for the resumed run while A's binary had been built under 1791573133; the digests still match, which shows the epoch does not reach this binary at all (no `build.rs`, no stamping crate) — see F16. Flags match the workflow leg verbatim (`release.yml:356-359`); the
   remaining unpinned determinism inputs are the ones in F2/F6 (restored cache, builder env), not the flags.
   `python3 scripts/release/reproducible_build.py --self-test` → `reproducible_build: self-test OK (identical builds
   pass; perturbed epoch, unremapped path, empty feature set and missing build tool are refused)`. No `build.rs`, no
   `vergen`/`built`/`shadow-rs` in Cargo.lock (no build-time stamping crate).
5. **#4752 artifact binding trace.** `release.yml:390-391`: the assert step hashes `target/<t>/release/ai-memory`
   *after* `bash scripts/assert-compiled-features.sh "$bin" --strict` and writes `sha256=` to `GITHUB_OUTPUT`
   (`id: assert`). `:400-410`: the package step takes it through `env: ASSERTED_SHA256`, copies to `dist/ai-memory`,
   hashes the copy, refuses on empty or unequal, then tars. `:412-438`: nfpm packages `dist/ai-memory` per `nfpm.yaml`
   (unpinned, F4). `:464-491`: the checksum sweep hashes every file then in `dist/` except the bare binary. `:493-508`:
   upload + attestation of `dist/ai-memory*`. The binary is stripped at link (`Cargo.toml:578` `strip = true`) and
   macOS legs are ad-hoc-signed by the linker, so the hashed bytes are the final bytes; no later strip/sign step. The
   asserted hash is published only through the `.sha256` files (derived from the same `dist/` files) and the Sigstore
   attestation; the `GITHUB_OUTPUT` value itself appears only in the job log. The published hash cannot be computed
   from a different file than the uploaded one within this job (all steps pinned), except the deb/rpm payload (F4) and
   the bare-binary asset (F15).
6. **#4719 / #5037.** `git log --oneline fa6b588e6 -- scripts/check-release-features.sh scripts/check_release_features.py`
   → 15 commits ending `6e2d55cd fix(#4737): CONTROL_RE as a raw string (CodeQL ..., #6110)`; the merge
   `7c3ea7527` (PR #6110) carries `scripts/check_release_features.py` +2467 and deletes the shell guard. Executed probes
   on the tip (mutants.txt): M13 later `FEATURES=` reassignment → CAUGHT; M14 `--locked` only in a trailing comment →
   CAUGHT; M12 `--no-default-features` → CAUGHT; M15 reassignment inside the Dockerfile RUN → CAUGHT; M16 assert step
   with an `if:` (the cross-built-leg skip) → CAUGHT; matrix `os: macos-15-intel` runs the strict assert natively
   (`release.yml:300-305`, `:367-391`). #4719 is fixed on the base. #5037: `git ls-files | grep -i bundle` → 9 files, none
   named `build_bundle`; `grep -rn build_bundle` across the tree (excluding target/.local-runs/.git) → nothing;
   `git log --all -S build_bundle` → nothing; no workflow or script depends on it. The author's found-not-fixed is accurate
   and the issue thread (2026-10-04) already re-scoped it to `/ai-scratch/f2h/cert7/build_bundle.py:203`.
7. **Hygiene.** `ast.parse(..., feature_version=(3, 9))` on both changed scripts → parses as 3.9;
   `python3.11 -m py_compile` → ok (3.11 is the oldest interpreter in the sandbox); no `match`, no `X | None`
   annotation (the one `|` is in a comment at `check_release_features.py:1782`), no `shell=True`/`os.system`, no new
   `.sh` file in the diff. `bash scripts/test/test-ci-workflow-invariants.sh` → `ci.yml invariants: 38/38 PASS`.
   `bash scripts/check-required-contexts.sh` → `check-required-contexts: OK (... release-shape.yml declared required or
   dated-and-tracked as not-required)`. `bash scripts/check-count-assertion-declared.sh --range fa6b588e6b5dfa97370b4f073e60e66cb1ed1fa7..HEAD`
   → `count-assertion-declared: clean`. `python3 scripts/release/check-release-workflow.py --workflow .github/workflows/release.yml`
   → `check-release-workflow: OK — .github/workflows/release.yml satisfies R1-R12`. actionlint v1.7.7 (installed into
   `.local-runs/bin`) on all workflows → rc=0. `changelog.d/`: 4720, 4752, 4935, 4936, 4937 present; 4768 and 3613
   missing (F11); 4719's fragment is on the base.
8. **Docs drift.** `grep -rn -i -E 'SOURCE_DATE_EPOCH|reproducib|release-features|assert-compiled-features|macos-15-intel|MANIFEST\.sha256' docs/`
   → 202 lines, of which the release-pipeline claims are the five listed in F12; `macos-15-intel` appears only in
   release.yml; `MANIFEST.sha256` only in compliance evidence `SANITIZATION.md` files (about the cert bundles, not the
   release). `docs/release-pipeline.html:532` (touched by this branch) is accurate about the proof and wrong about the
   tag signature scheme.

## Issue requirements

Per child, against the literal issue text (bodies fetched via the public REST API; `gh` is unauthenticated here).

| Child | Requirement (literal) | Status | Note |
|---|---|---|---|
| #3613 | 1. every release artifact job pins SOURCE_DATE_EPOCH, `--locked`, pinned toolchain, remap | NOT MET | release build + SBOM only; deb/rpm, mobile, Docker do not (F8) |
| #3613 | 2. a job builds twice in two workspaces, compares SHA-256, fails on difference, diffoscope summary | MET in letter | job exists and fails the run; gates nothing (F1), digest unbound to the shipped binary (F2) |
| #3613 | 3. scope stated; each "not yet" gets a tracked item; nothing claimed without proof | PARTIAL | scope stated in the banner; no tracked items (F8); claim wording correct |
| #3613 | Acceptance: run link with identical digests + negative fixture; checklist (#3308) records coverage | NOT MET | no release run yet (author says so); checklist untouched (F8) |
| #4719 | four drift forms refused; strict assert on every target incl. darwin x86_64; dead self-test lines removed | MET (on base, 7c3ea7527) | Evidence 6 |
| #4720 | drop `continue-on-error` after first green run on main; COVERED_WORKFLOWS + branch protection; header + CHANGELOG | PARTIAL | key dropped, COVERED_WORKFLOWS + ledger + fragment done; "on main" never happened (F9); branch protection held back by the repo's own lockstep rule, stated |
| #4752 | 1. record asserted sha256, verify in package step; 2. refuse any other build/writer after the assert; 3. runtime assert in the image on the shipped path, case-insensitive instruction parse incl. heredoc bodies | MET for 1 and 3; PARTIAL for 2 | deb/rpm payload via unpinned nfpm.yaml (F4); final-stage ENTRYPOINT/PATH (F5); heredocs are refused outright rather than parsed (acceptable, fail-closed) |
| #4768 | 1. verify both files unmodified vs checked-out commit, absolute interpreter path, sanitised env, same in build step; 2. guard refuses writers of the two paths / GITHUB_ENV / PATH files, Dockerfile ENV BASH_ENV/ENV/SHELL and touches to scripts/ between COPY and RUN; 3. Dockerfile checksums of the copied files | PARTIAL | bind present but index/HEAD-anchored (F7); no absolute path / sanitised env (F10); builder ENV/ARG/COPY classes open (F6); Dockerfile item 3 replaced by COPY ordering (disclosed) |
| #4770 | choose and implement one of three options before Aug 2027, keep the strict assert, guard keeps refusing a skip | NOT MET | decision-needed; nothing landed; the guard does keep refusing a skip (M16) |
| #4935 | gate red on `packages: write`/`write-all` in any other workflow or job and on the release image name outside release.yml; publish-ci-image grant moved to the job | PARTIAL | moved + pinned; per-line regex bypassed by multi-line scalars (F3); expression-built names documented as out of reach |
| #4936 | pin `on:` and `concurrency:` values of release.yml and release-shape.yml's concurrency; refusal cases + mutation coverage; changelog | MET | 10 red → green cases; fragment present |
| #4937 | `contents: read` on supply-chain and crates-io; guard refuses widening | MET | both blocks declared; widening cases present |
| #5037 | one-line total sort key + Fatal on case collision in build_bundle.py | NOT MET (not in tree) | file is untracked; nothing in the repo depends on it (Evidence 6) |

Verdict: REJECT. F1 and F2 turn the branch's headline control into a report; F3–F7 are bypasses of the controls the
branch claims to add, each reproduced with a one-command probe; F8–F10 are literal-text gaps the commits do not flag.

REPORT lane=rev-6062 branch=cloud/f1/rev-6062 base=fa6b588e6b5dfa97370b4f073e60e66cb1ed1fa7 head=(the commit carrying this file; sha in the lane's chat report) pushed=yes
COMMITS
(this commit) review(#6062): cloud adversarial review of fix/6062-promo6-ssh head c4b7332c3
ITEMS
#3613 | reviewed | NOT MET | 7 (F1, F2, F8, F11, F13, F14, F16)
#4719 | reviewed | MET | 0
#4720 | reviewed | PARTIAL | 1 (F9)
#4752 | reviewed | PARTIAL | 3 (F4, F5, F15)
#4768 | reviewed | PARTIAL | 4 (F6, F7, F10, F11)
#4770 | reviewed | NOT MET | 0 (decision-needed; nothing landed)
#4935 | reviewed | PARTIAL | 1 (F3)
#4936 | reviewed | MET | 0
#4937 | reviewed | MET | 0
#5037 | reviewed | NOT MET | 0 (untracked file; found-not-fixed confirmed)
GATES
python3 scripts/check_release_features.py -> check_release_features: OK (release features: sal,sal-postgres)
python3 scripts/check_release_features.py --self-test -> check_release_features: self-test OK (a failing or empty declaration fails the build step and the Dockerfile RUN; 439 guard cases, 6 advisory cases, 7 message cases, 16 parity cases, 7 scalar cases, 9 entry-point cases)
python3 scripts/check_release_features.py --mutation-sweep -> check_release_features: mutation sweep: 92 refusal mutants + 44 condition mutants = 136 mutants, 0 survivors (14 m 31 s wall on 4 cores, run concurrently with the two-build trial)
python3 scripts/release/reproducible_build.py --self-test -> reproducible_build: self-test OK (identical builds pass; perturbed epoch, unremapped path, empty feature set and missing build tool are refused)
python3 scripts/release/reproducible_build.py --target x86_64-unknown-linux-gnu --features sal,sal-postgres --workspace-b .local-runs/rev-6062/reproducible-b -> reproducible-build: OK (two builds of ai-memory for x86_64-unknown-linux-gnu are byte-identical: f80c2e936cfc693f3d8aa2ec4b274793e5c0da5b48ef5bf2b56c1dacefde3a84) [exit 0; A 23 min cold, B resumed after a sandbox restart, 7 m 05 s for the final crate + LTO]
python3 scripts/release/check-release-workflow.py --workflow .github/workflows/release.yml -> check-release-workflow: OK — .github/workflows/release.yml satisfies R1-R12
bash scripts/test/test-ci-workflow-invariants.sh -> ci.yml invariants: 38/38 PASS
bash scripts/check-required-contexts.sh -> check-required-contexts: OK (release/v1.0.0: every mirrored required context maps to a reporting job; ...; every job in ci.yml c8-precheck.yml coverage.yml cert-postgres-age.yml postgres-ignored.yml release-shape.yml declared required or dated-and-tracked as not-required)
bash scripts/check-count-assertion-declared.sh --range fa6b588e6b5dfa97370b4f073e60e66cb1ed1fa7..HEAD -> count-assertion-declared: clean (fa6b588e6b5dfa97370b4f073e60e66cb1ed1fa7..HEAD)
.local-runs/bin/actionlint (all workflows) -> rc=0
cargo fmt --all --check / cargo clippy -> not run: the branch and this review change no Rust and no Cargo file (git diff --stat fa6b588e6..HEAD -- '*.rs' Cargo.toml Cargo.lock is empty)
DECISIONS
Red-on-base was measured on each test commit's PARENT tree (which already holds the earlier children's fixes) so each child's reds are isolated; the first child was also run on the true base (same result). Precedent: the author's own commit bodies quote the same per-parent reds.
The review file is committed under .cloud-review/ as the brief names it; the harness's designated branch (claude/cloud-lane-rev-6062-ph9ea0) was not pushed because the brief forbids pushing any branch but cloud/f1/rev-6062.
Dockerfile mutants that survive by a value spelling (M19b/M19c/M19d) are counted under F6 with the builder-env class rather than as separate findings; same root cause (no builder ENV/ARG/COPY allowlist, check_release_features.py:1643-1658).
FOUND-NOT-FIXED
.github/workflows/release.yml:576-601 the reproducible job is not in any publish job's needs (F1)
.github/workflows/release.yml:326 + :593-601 proof digest never compared with steps.assert.outputs.sha256; release job still restores a shared rust-cache (F2)
scripts/check_release_features.py:1482-1486 per-line packages: write / write-all sweep bypassed by multi-line and folded YAML scalars (F3)
nfpm.yaml:14-17 unpinned by the guard; deb/rpm payload source and maintainer scripts unbound (F4)
scripts/check_release_features.py:1607-1636 final stage: context COPY before the binary COPY + ENTRYPOINT/ENV PATH swap passes (F5)
scripts/check_release_features.py:1643-1658 builder ENV PATH / RUSTC_WRAPPER / CARGO_HOME / ENV, COPY .cargo/, FROM image and matrix os label unpinned (F6)
.github/workflows/release.yml:351,:374,:598 git diff --quiet HEAD bind bypassed by assume-unchanged, skip-worktree, local commit, git replace; not anchored to preflight sha (F7)
.github/workflows/release.yml:412-438,:745-1317 SOURCE_DATE_EPOCH not pinned in the deb/rpm, mobile and docker jobs; no tracked "not yet" items; checklist row untouched (F8)
.github/workflows/release-shape.yml:37-44 / commit da63b8c58 "first green run on main" substituted by PR-event runs without saying so; 0 of 89 runs on main (F9)
.github/workflows/release.yml:374-386 asserter invoked through PATH-resolved bash/git/shasum, no sanitised env (F10)
changelog.d/4768.security.md and changelog.d/3613.fixed.md missing (F11)
docs/release-pipeline.html:532, docs/encryption.html:287,:441, docs/audience/decision-maker.html:130, docs/handoff/READY-TO-TAG-v1.0.0-CERT-NOTE.md:46, .github/workflows/release.yml:26 drift (F12)
scripts/release/reproducible_build.py:121-126 pre-existing --workspace-b reused as-is outside --self-test (F13)
scripts/release/reproducible_build.py:234 epoch negative fixture proven with a stub only; the real binary ignores SOURCE_DATE_EPOCH (F16)
.github/workflows/release.yml:457-462,:497,:508,:545 bare dist/ai-memory asset uploaded/attested by all four legs under one name, no tracking issue found (F15)
