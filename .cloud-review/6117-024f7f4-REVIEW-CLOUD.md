# Cloud review fix/6117-promo6-ssh head 024f7f41e: VERDICT REJECT

Reviewed: `origin/fix/6117-promo6-ssh` at `024f7f41e0f3b1b242c75d427eb60be2bb5dcabd` (8 commits)
against base `origin/chain/promo6-ssh` = `fa6b588e6b5dfa97370b4f073e60e66cb1ed1fa7`
(unchanged at review time; `origin/release/v1.0.0` = `26785a5918f02b5cdded6f038fe17e1b9d407da0`).
Read-only review lane `cloud/f1/rev-6117`; nothing in the subject branch was changed.
Diff: 16 files, +1410/-75; no `.rs`, `Cargo.toml` or `Cargo.lock` change
(`git diff fa6b588e..024f7f41e --name-only | grep -E '\.rs$|Cargo\.'` → no match, exit 1).

The production behaviour is correct everywhere I could drive it (lenses 1, 2, 3, 6 all
green). The verdict is REJECT because the branch's central safety claim, "a carrier push
verdict is never narrower than the promotion-PR verdict on the same sha", is NOT pinned:
7 of 21 hand-written mutants that remove exactly that behaviour survive the 264-case
suite AND `scripts/test/test-ci-workflow-invariants.sh` AND
`scripts/check-required-contexts.sh` (Findings 1 and 2), the security gate step can be
neutralised without a red test (Finding 2), and a T3/T6 crossroads shipped with no
5-agent vote (Finding 3). Every fix is small (tests + two doc sentences + one vote record);
the branch does not need a re-design.

## Findings

Ranked. Severity / file:line / what / how reproduced / fix size.

### F1 — HIGH — the "never narrower" carrier arms and all four range-start consumers are unpinned

- `.github/workflows/ci.yml:322-330` (classify: carrier push ⇒ full pipeline),
  `.github/workflows/coverage.yml:147-151` (classify: carrier push ⇒ full sweep),
  `.github/workflows/c8-precheck.yml:619` (`DECLARATION_GATE_BASE`),
  `:1231` (cert-expiry `GITHUB_EVENT_BEFORE`), `:1450` (stale-contract), `:1516`
  (count-assertion): the six places where a carrier push is widened to the whole carrier.
- Reproduced with `.local-runs/rev-6117/mutants.py` (worktree at the tip, one mutation,
  full suite):
  - `ci-classify-carrier-arm-removed` (`if … chain/ …` → `if false`): **SURVIVED**
    (`Ran 264 tests … OK`; `test-ci-workflow-invariants.sh` 38/38 PASS;
    `check-required-contexts.sh` OK).
  - `coverage-classify-carrier-arm-removed`: **SURVIVED** (same three gates green).
  - `cert-expiry-range-start-reverted` (`steps.carrier.outputs.before || github.event.before`
    → `github.event.before`): **SURVIVED** (all three gates green).
  - `declaration-gate-base-reverted`: **SURVIVED**.
  - `all-four-before-consumers-reverted` (every consumer back to `github.event.before`,
    the carrier step left in place): **SURVIVED** (`Ran 264 tests … OK`).
- Consequence of the unpinned ci.yml arm: a docs-only lane PR merged onto the carrier
  would classify `docs_only=true` on the push run, every `needs.classify` job
  (`Lint`, `MSRV`, `Check (…)`, feature gates, `Per-Module Coverage Thresholds`) reports
  `skipped`, and GitHub documents "A job that is skipped will report its status as
  'Success' … It will not prevent a pull request from merging, even if it is a required
  check" (docs.github.com, about-status-checks). That is the exact #6193-class masking
  this branch exists to close, re-openable by a one-line edit with every gate green.
  The round-2 tests pin that the carrier STEP exists (`CarrierRangeStep6117`,
  `test_workflow_pr_triggers_5447.py:3070-3216`) and that the release ref has one source,
  but never that anything CONSUMES `steps.carrier.outputs.before`, nor that either
  classify step has the carrier arm.
- Fix: ~40 lines in `scripts/test/test_workflow_pr_triggers_5447.py`: for each of the
  four gate steps assert the env line reads
  `${{ steps.carrier.outputs.before || github.event.before }}` (declaration:
  `pull_request.base.sha || steps.carrier.outputs.before || github.event.before`); for
  ci.yml / coverage.yml assert the classify `run:` contains the
  `"$EVENT_NAME" = "push"` + `refs/heads/chain/` arm that writes `docs_only=false`
  (ci.yml also `test_impact=__ALL__`). Add the five mutants above to the kill list.

### F2 — MEDIUM — the External-PR approval STEP can be neutralised with no red test

- `.github/workflows/c8-precheck.yml:1371-1374` (`- name: Evaluate external-PR approval
  requirement`).
- `test_6117_r2_sf1_workflow_runs_the_evaluator_on_every_event`
  (`test_workflow_pr_triggers_5447.py:3265`) asserts `assertNotRegex(job,
  r"(?m)^    (needs|if):")` — four-space, JOB-level only. Reproduced:
  - `approval-step-continue-on-error` (adds `continue-on-error: true` to the Evaluate
    step): **SURVIVED** all three gates.
  - `approval-step-if-pull_request-only` (adds `if: github.event_name == 'pull_request'`
    to the Evaluate step, the #6193 defect re-expressed one level down): **SURVIVED**
    all three gates. (The job-level form IS killed:
    `approval-job-if-pull_request-only` → `FAILED (failures=1)` by that test.)
- A `continue-on-error` step turns a `::error::` exit 1 into a green job; a step `if:`
  skips it on push/merge_group and the job is green by construction. Both are
  one-line edits to the required security context.
- Fix: ~6 lines: extend the sf1 test to the step scope
  (`assertNotRegex(step_text, r"(?m)^\s+(if|continue-on-error|timeout-minutes: 0):")`
  on the Evaluate step and on the Self-test step) and add both mutants.

### F3 — MEDIUM — T3/T6 crossroads shipped without the 5-agent vote

- Commits `01520f4b` and `83b44cb0`; `.github/workflows/c8-precheck.yml:67-82`
  ("precedent copied from scripts/check_promotion_geometry.py, no vote").
- The thing copied from `check_promotion_geometry.py:58-77` is the FACT "base ancestor
  of head ⇒ merge tree == head tree" (line 76 already printed it). That fact was never
  the decision. The decision was WHICH mechanism makes a push run's check-runs safe to
  stand beside a promotion PR's under the same required names: (a) make the push run
  provably equivalent (measure geometry on push, widen the ranges, judge PRs heading the
  sha — chosen), or (b) make the push run DISTINGUISHABLE (report under per-event
  context names so no push run ever carries a required name; this also erases the #6213
  residual and the whole rule-(d) class). Two mutually exclusive paths, no precedent in
  the codebase for either on a push lane ⇒ **T6**. The #6193 arm is a new gate boundary
  on push/merge_group runs with an explicit fail-open choice ("no open PR heads this
  sha: pass", `check_external_pr_approval.py:152-154`) ⇒ **T3** ("a new gate … fail-open
  vs fail-closed"). CLAUDE.md §"Crossroads decision protocol": "Run the vote BEFORE
  acting whenever ANY condition Tn holds … Shipping a Tn-matching change WITHOUT a vote is
  a self-flagged process violation the agent must surface to the operator."
- Fix: run the 5-agent vote on (a) vs (b) now, `memory_store` the tally, cite
  `5-agent vote (4d3ea1c5)` in the PR body / issue comment. If (a) stands, nothing in
  the code changes; if (b) wins, the branch shrinks.

### F4 — LOW — approval script relays `gh` stderr and unvalidated API strings into `::error::` lines

- `scripts/check_external_pr_approval.py:71` (`proc.stderr.strip()[:300]` into the
  GateError that becomes the `::error::` line) and `:115-129` (`user.login`,
  `author_association`, `head.repo.full_name` printed unvalidated on the `::error::` line).
- Reproduced with the fake `gh` shim (`.local-runs/rev-6117/shim/gh`): scenario
  `rate-limit-403` whose stderr carries the token value → the token value appears
  verbatim in the script's stdout (`token_leak=True`, exit 1). Scenario
  `metachar-names` (login and full_name = `"x\n::error::forged\n::set-output …"`) →
  printed verbatim, two extra lines beginning `::error::forged` and `::set-output` land
  in the Actions log (exit 1, verdict still correct). Subprocess argv is safe: the only
  API-derived argv pieces are `repo` (validated by `REPO_RE`, `:136`) and `number`
  (validated int, `:80`); a `GITHUB_SHA` of `"a"*39+";"` is refused before any `gh`
  call (`gh_calls=0`, exit 1).
- Reality check: the real `gh` never prints the token, Actions masks `${{ github.token }}`,
  and GitHub logins / repo names cannot contain `\n` or `:`; the paths are not reachable
  today. The script validates sha, number and repo but not the two strings it echoes,
  which is inconsistent with its own fail-closed shape.
- Fix: ~8 lines: validate `login` against `[A-Za-z0-9-]{1,39}` and `full_name` against
  `REPO_RE` (else GateError), keep only the first stderr line and strip
  `gh[pousr]_[A-Za-z0-9]{20,}` before echoing.

### F5 — LOW — two doc sentences overclaim against the #6213 residual the branch itself records

- `docs/AI_DEVELOPER_GOVERNANCE.md:690-693`: "so a push run never reports a pass where
  the PR run would fail"; `docs/contributing-external.md:17`: "so a push run cannot report
  a pass beside a failing PR run".
- `changelog.d/6117.security.md:11-12` (same branch): "A PR opened after a push run
  already judged its sha is tracked in #6213" — i.e. a passing push run CAN sit beside a
  failing PR run. `never` / `cannot` are false as written.
- Fix: 2 sentences ("… on every PR open when the push run judged the sha; a PR opened
  later is #6213").

### F6 — LOW — `scripts/check-claude-md-size.py:1606` comment states the pre-#6117 rule

- `# push must NOT name rehearsal/** or chain/** (#5447 R-PUSH, #5659, #6105): the carrier
  and the chain branches get the guard on their pull_request runs.` The pin itself is
  correct (it guards `claude-md-guard.yml`, which is not in the required set and keeps
  `push: [main, develop, "release/**"]`), but the comment asserts a repo-wide rule
  #6117 just reversed for the required set. Issue #6117's own text lists this file among
  the pins to touch.
- Fix: 1 line: "… chain/** is admitted on push ONLY in the required-set workflows under an
  event-distinct key (#6117); this guard stays off chain pushes."

## Evidence

Executed in the sandbox (4 cores, 15 GiB, git 2.43.0, python 3.11/3.12/3.13, rustc
present; `gh` REST works, GraphQL is blocked; clone unshallowed with
`git fetch --unshallow origin` → `--is-shallow-repository` = `false`).

1. **Merge-tree claim.** Real refs: `git rev-list --count` release..carrier = 245,
   carrier..release = 0; `git merge-tree --write-tree 26785a59 fa6b588e` →
   `257908ad1712e8f63815a1e679d411938b7dc302` == `git rev-parse fa6b588e^{tree}`
   (EQUAL). Synthetic histories (`.local-runs/rev-6117/syn`):
   (A) release has a commit not in carrier → `ahead=1 behind=1`, merge-tree ≠ carrier
   tree, script exit 1 `FAIL #3872: candidate is BEHIND release`;
   (B) carrier merged release, then release gains an EMPTY commit → `behind=1` but
   merge-tree == carrier tree, script exit 1 (refuses; conservative);
   (C) carrier merged release → `behind=0`, merge-tree == carrier tree, exit 0
   `PASS #3872: base is an ancestor of candidate; merge tree equals candidate tree`.
   "behind=0 by rev-list" is `base ∈ ancestors(head)`, which makes the merge a
   fast-forward and the merge tree the head tree: sufficient, not necessary (B). The
   brief's "not behind but release has a commit not in carrier" cannot be constructed:
   that commit is counted by `rev-list head..base` by definition (replace objects and
   grafts are refused at `check_promotion_geometry.py:43,61-65`). Vote judgement: the
   fact is a precedent copy; the mechanism choice is T3+T6 — Finding 3.
2. **Approval script.** `python3 .local-runs/rev-6117/run_shim_cases.py` →
   `shim cases: 21 passed, 1 failed` (the one failure is the deliberate token-in-stderr
   probe, Finding 4). Exit / last line per case:
   zero-prs 0 `no open pull request heads this sha; nothing to approve (pass)`;
   unapproved fork PR 1 `::error::External-PR operator-approval gate FAILED for PR #7 …`;
   approved 0 `PR #7: APPROVED review by @alphaonedev found for head aaaa… (pass)`;
   approved-by-author 1; dismissed 1; approved-on-old-head 1; reviews paginated
   (101 reviews, approval on page 2) 0; 150 open PRs over two concatenated pages with
   the match last 1 (`… FAILED for PR #150`); 403 rate limit 1 (`… exited 1: gh: API
   rate limit exceeded …`); 5xx 1; malformed JSON 1 (`API output is not JSON at offset
   0`); error object 1 (`API page is a dict, not an array`); head moved after the run
   started 0 (`nothing to approve (pass)` — correct: the check run is on the old sha,
   which no PR heads); team same-repo 0; MEMBER from a fork 1; deleted head repo 1
   (`from 'None'`); two PRs, one approved 1; boolean `number` 1 (`has no valid
   number`); merge_group unapproved 1; workflow_dispatch zero PRs 0;
   `GITHUB_SHA` with `;` → exit 1 before any gh call. `--self-test` →
   `external-pr-approval self-test: 0 failed`.
3. **Geometry script against real origin** (`--github-event`, `--event-name push`,
   `ref=refs/heads/chain/promo6-ssh`): after=carrier tip → exit 0 (`ahead=245 behind=0`,
   PASS); after=release tip → exit 0 (`behind=0`); after=release^ → exit 1
   (`FAIL #3872: candidate is BEHIND release`); after=`dddd…` (unreachable) → exit 2
   (`ERROR #3872 (fail closed): git rev-parse exited 128`); `ref=refs/heads/main` →
   exit 0 `INAPPLICABLE #3872: push to 'refs/heads/main' is not a promotion carrier`.
   `--depth 1` clone → exit 2 `ERROR #3872 (fail closed): shallow history: fetch full
   history before measuring ancestry` (never narrows). Workflow carrier step replayed
   with `origin` = `https://127.0.0.1:9/nonexistent.git` → `::error::carrier push:
   cannot fetch origin/release/v1.0.0; refusing to judge the carrier over an unknown
   range`, exit 1, `$GITHUB_OUTPUT` empty. `--self-test` → `promotion-geometry
   self-test: 25 passed; 0 failed`.
4. **Workflow triggers.** Tip: `python3 scripts/test/test_workflow_pr_triggers_5447.py`
   → `Ran 264 tests in 4.645s` / `OK`. Tip test file in a worktree at
   `d1dd55163e481f55a3eee1f20dc491f6dcd46ce1` → `Ran 264 tests` /
   `FAILED (failures=16)` (CarrierPushGeometry6117 ×7, CarrierRangeStep6117 ×3,
   ExternalPrApprovalOnPush6117 ×5, RoundTwoDocTruth6117 ×1). Mutants
   (`.local-runs/rev-6117/mutants.py`, 21 total): KILLED 14 —
   `pin-release-at-job-env` (ci.yml+c8) and `pin-release-at-step-env` by
   `test_6117_r2_sf4_release_ref_has_one_source`; `pin-release-in-all-range-steps` by
   that + `…hardcoded_release_in_a_range_step_is_killed`; `drop-persist-credentials-false`
   and `approval-job-if-pull_request-only` by `…sf1_workflow_runs_the_evaluator_on_every_event`;
   `drop-approval-self-test-step` by `…sf1_self_test_passes`; `narrow-chain-glob-all-six`
   (10 failures) and `narrow-chain-glob-ci-only` (5) by
   `test_6117_live_required_set_lists_chain_on_push` et al.; `drop-event_name-from-ci-group`
   (6) by `test_6117_live_chain_push_workflows_key_per_event`; `geometry-script-no-carrier-arm`
   (4 cf1 tests); `approval-script-unconditional-pass` by `…sf1_decision_table`;
   `geometry-step-fetch-guard-removed` by `…cf1_unfetchable_release_fails_even_with_a_stale_local_ref`;
   `merge-base-guard-dropped` by `…sf3_unrelated_history_fails_with_an_error_annotation`.
   SURVIVED 7 — Findings 1 and 2. (`stale-contract-range-start-reverted` was not applied:
   my anchor did not match the step body; it is covered by `all-four-before-consumers-reverted`.)
5. **Required-check naming.** Declared set: `scripts/qc-allowlists/required-contexts-release.txt`
   (43 contexts, includes `External-PR operator-approval gate (author outside team =>
   @alphaonedev review)`, `Required-context + classify-base soundness gate
   (#2494/#2496/#2508)`, `Coverage classify (docs-only short-circuit)`, `Per-Module
   Coverage Thresholds`, `Classify changes`, `Check (…)` ×4);
   `bash scripts/check-required-contexts.sh` → `check-required-contexts: OK (…)`;
   `python3 scripts/check_release_features.py --self-test` → `self-test OK (… 356 guard
   cases …)`. GitHub docs (troubleshooting-required-status-checks, fetched 2026-10-09):
   "Required checks must pass on the latest commit SHA." and "Successful check statuses
   are `success`, `skipped`, and `neutral`."; about-status-checks: "A job that is skipped
   will report its status as 'Success'. It will not prevent a pull request from merging,
   even if it is a required check." No GitHub doc sentence defines a tie-break between
   two check runs of one name on one sha; the only documented ordering is the REST
   `filter` parameter on `GET /repos/{o}/{r}/commits/{ref}/check-runs`: "latest returns
   the most recent check runs." So: a passing push run CAN mask a failing PR run on the
   same sha whenever it is the later one to complete, and with the per-event cancel
   groups both now complete. Under this branch that masking is harmless only while
   every required context is at least as strict on push as on pull_request — which is
   precisely what Findings 1 and 2 leave unpinned. The #6213 residual (PR opened after
   the push run judged the sha) is outside this branch's control under design (a); it
   would not exist under design (b) (Finding 3). Ruleset check: `signed-attested-branches`
   (17752665) `ref_name.include = [refs/heads/main, refs/heads/develop,
   refs/heads/release/*]` — `chain/*` carries no `required_signatures` /
   `non_fast_forward` (FOUND-NOT-FIXED, #6193 names a companion issue).
6. **Concurrency.** ci.yml:416 `group: ci-${{ github.workflow }}-${{ github.event_name }}-${{
   github.event.pull_request.head.repo.full_name == github.repository &&
   github.event.pull_request.head.ref || github.event.pull_request.number ||
   github.ref_name }}`; c8-precheck.yml:45 `c8-precheck-${{ github.event_name }}-…`;
   coverage.yml:495 `cov-${{ github.workflow }}-${{ github.event_name }}-…`;
   release-shape.yml:58 `release-shape-${{ github.event_name }}-${{
   github.event.pull_request.number || github.ref_name }}`; cert-postgres-age.yml:105
   `cert-pg-age-${{ github.event_name }}-…`; postgres-ignored.yml:44
   `pg-ignored-${{ github.event_name }}-…`. For one push to `chain/promo6-ssh` the
   groups are `…-push-chain/promo6-ssh` (push run) and `…-pull_request-chain/promo6-ssh`
   (#6160 synchronize): distinct, neither cancels the other; a lane PR INTO the carrier
   keys on its own head ref. Same-event re-pushes still cancel their predecessor (by
   design). `scripts/test/test-ci-workflow-invariants.sh` C4 and
   `check-required-contexts.sh` rule (d) both admit `chain/**` on push only with
   `github.event_name` in the group (verified by `drop-event_name-from-ci-group` KILLED
   and the gate self-test lines `[d] #6117: … CAUGHT under the house key and PASSES under
   the event-distinct key`).
7. **Hygiene.** `python3.11/3.12/3.13 -m py_compile` both scripts → OK ×3 (3.11 is the
   oldest python3 in the sandbox; no 3.9 available — the scripts use no `match`, no
   `X | None`, no `shell=True`, argv lists only, stdlib imports only: argparse, json, os,
   re, subprocess, sys, pathlib, tempfile). `bash scripts/test/test-ci-workflow-invariants.sh`
   → `ci.yml invariants: 38/38 PASS`. `bash scripts/check-required-contexts.sh` → OK.
   `python3 scripts/check_release_features.py --self-test` → `self-test OK`.
   `bash scripts/check-count-assertion-declared.sh --range fa6b588e…..HEAD` →
   `count-assertion-declared: clean`. actionlint 1.7.7 (installed to `.local-runs/bin`)
   over the six touched workflows (`-shellcheck= -pyflakes=`) → exit 0, no findings.
   No `.rs` / `Cargo.*` change (verified above).
8. **Docs drift.** `grep -rn 'check_promotion_geometry\|check_external_pr_approval\|CARRIER_RELEASE_REF' docs/`
   → no hit outside the two edited paragraphs; `chain/` in docs/ → only unrelated
   (chain/next history, hash-chain). changelog.d/6117.fixed.md claims verified line by
   line: six workflows list `chain/**` on push (grep: ci, c8-precheck, coverage,
   release-shape, cert-postgres-age, postgres-ignored — true); "three workflows whose
   cancel group was not yet keyed per event (ci, coverage, c8-precheck)" — true (the
   other three already had `github.event_name`); "four carrier range-start steps" — true
   (c8-precheck.yml:581, 1192, 1413, 1479); `--print-release` as the one source — true
   (sf4 test). Overclaims: Finding 5 (two sentences) and Finding 6 (one comment).
   `docs/mobile-iot-deployment.md:196,632` "every push to release/**" remain true (a
   superset now runs).

## Issue requirements

| Issue | Literal requirement | Status | Evidence |
|---|---|---|---|
| #6117 | "(a) adding `chain/**` to `on.push.branches` of the required-set workflows (Check matrix, coverage, cert-expiry, release-shape) so every signed merge into a carrier gets a verdict" | MET | ci.yml:384, c8-precheck.yml:27, coverage.yml:477, release-shape.yml:549, cert-postgres-age.yml:354, postgres-ignored.yml:530; R-CHAIN tests green |
| #6117 | "plus the pins in scripts/check-claude-md-size.py and scripts/test/test_workflow_pr_triggers_5447.py" | MET (test file: 264 cases) / comment stale (claude-md-size: F6) | `check-claude-md-size.py:1606-1608` untouched; pin is correct for claude-md-guard.yml, comment is not |
| #6117 | "Must land after #6105 (same files)" | MET | base fa6b588e contains #6105 |
| #6117 (implied by the title) | a carrier-only defect surfaces on the carrier push, with the same verdict shape as the promotion PR | MET in code / NOT MET in pins | F1: 5 "narrower push verdict" mutants survive every gate |
| #6193 | "1. List the open PRs whose head is the judged commit … Also query the base repo's open PRs and filter head.sha == GITHUB_SHA, because the commits endpoint omits fork PRs" | MET | `check_external_pr_approval.py:149-150` uses only the `pulls?state=open` superset path (covers forks; the commits endpoint is not needed); shim case `paginated-150` |
| #6193 | "2. For each open PR from an author outside OWNER/MEMBER/COLLABORATOR or from a head repo other than this one, require the same operator APPROVED review on commit_id == GITHUB_SHA" | MET | `:90-108`; shim cases unapproved/approved/dismissed/approved-old-head/team-from-fork |
| #6193 | "3. Fail closed: an API error, or a non-numeric or empty count, exits 1. It must never pass." | MET | shim cases 403/5xx/malformed/error-object/bool-number all exit 1; `parse_pages` refuses `""` |
| #6193 | "4. Self-test … a push event whose sha heads an unapproved external PR fails, and the same sha with an approved review passes. Retest: the new self-test is red on the current gate and green on the fix." | MET | `--self-test` 0 failed; `test_6117_r2_sf1_m01_unconditional_non_pr_pass_is_killed` FAIL on d1dd5516, OK on tip |
| #6193 | gate holds "whichever branch runs it" (step cannot be bypassed) | NOT MET in pins | F2: step-level `if:` and `continue-on-error` survive |

```
REPORT lane=rev-6117 branch=cloud/f1/rev-6117 base=024f7f41e0f3b1b242c75d427eb60be2bb5dcabd head=<filled in the final message> pushed=<filled in the final message>
COMMITS
<filled in the final message>
ITEMS
#6117 | reviewed | REJECT | 6 findings (F1 HIGH, F2 MEDIUM, F3 MEDIUM, F4 LOW, F5 LOW, F6 LOW)
#6193 | reviewed | REJECT | 2 findings bear on it (F2 MEDIUM, F4 LOW); the four literal requirements are MET in code
GATES
see Evidence 4 and 7 above
DECISIONS
see the final message
FOUND-NOT-FIXED
scripts/check-claude-md-size.py:1606 stale rule comment (F6; subject branch, read-only lane)
docs/AI_DEVELOPER_GOVERNANCE.md:690-693 and docs/contributing-external.md:17 overclaim vs #6213 (F5)
ruleset 17752665 excludes refs/heads/chain/*: no required_signatures / non_fast_forward on the carrier a push lane now trusts (#6193 names a companion issue)
```
