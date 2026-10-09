# Cloud review fix/6117-promo6-ssh head 2515d26b8 (round 2): VERDICT REJECT

Reviewed: `origin/fix/6117-promo6-ssh` at `2515d26b885f419b5fb00298e5dcad6f1e9d4611` (16 commits:
the 8 of round 1 + `dddd9ba8 066366c9 b6a48626 e40f9321 90d87eb4 59be78f1 36959f7e 2515d26b`)
against base `origin/chain/promo6-ssh` = `fa6b588e6b5dfa97370b4f073e60e66cb1ed1fa7` (unchanged since
round 1; `origin/release/v1.0.0` = `26785a5918f02b5cdded6f038fe17e1b9d407da0`, unchanged).
Read-only review lane `cloud/f1/rev-6117-r2`; nothing in the subject branch was changed.
Full diff: 17 files, +1849/-77; round-2 delta `024f7f41e..2515d26b8`: 7 files, +468/-31
(`c8-precheck.yml`, `6117.security.md`, two docs, `check-claude-md-size.py`,
`check_external_pr_approval.py`, `test_workflow_pr_triggers_5447.py`). No `.rs`, `Cargo.toml`
or `Cargo.lock` change (`git diff fa6b588e..2515d26b8 --name-only | grep -E '\.rs$|Cargo\.'` → exit 1).

Every round-1 finding is closed at the new head (table below): the seven round-1 survivors are
KILLED by named tests, the vote was run and is cited, the docs and the comment are fixed. The
verdict is REJECT because the round-2 delta introduced one behavioural regression on a live PR
class (Finding 1: the new login validator rejects GitHub's `name[bot]` logins, so the open
dependabot PR #4127 can never pass the required gate even with the operator's APPROVED review)
and because 7 of 33 mutants still survive all three local gates, four of them one-line
neutralisers of the same required security context the round-1 F2 fix was meant to pin
(`|| true` on the run line, a job-level `continue-on-error`, a re-pointed `OPERATOR_LOGIN`, a
spaced `if :` key) plus a by-file hole in the vote-mandated closed-world pin. Every fix is small
(one regex character class, ~20 lines of test assertions, one comment); no re-design.

## Round-1 findings

| finding | closed at sha | evidence command | result |
|---|---|---|---|
| F1 HIGH unpinned carrier arms + 4 range-start consumers | `e40f9321` | `python3 .local-runs/rev-6117-r2/mutants.py ci-classify-carrier-arm-removed coverage-classify-carrier-arm-removed cert-expiry-range-start-reverted declaration-gate-base-reverted all-four-before-consumers-reverted` (worktree at 2515d26b8, one mutation, three gates each) | all five **KILLED**: trigger suite `FAILED (failures=3/3/6/6/7)` by `test_6117_r3_f1_*` (live_tree_is_intact + the per-mutant kill test; the three c8 mutants also trip `CarrierBeforeClosedWorld6117`); `test-ci-workflow-invariants.sh` 1 FAILED, 37 passed on each |
| F1 mutant `ci-classify-carrier-arm-removed` | `e40f9321` | as above | KILLED: `test_6117_r3_f1_ci_classify_carrier_arm_removed_is_killed`, `..._live_tree_is_intact`, `..._all_four_before_consumers_reverted_is_killed` |
| F1 mutant `coverage-classify-carrier-arm-removed` | `e40f9321` | as above | KILLED: `test_6117_r3_f1_coverage_classify_carrier_arm_removed_is_killed`, `..._live_tree_is_intact` |
| F1 mutant `cert-expiry-range-start-reverted` | `e40f9321` | as above | KILLED: `test_6117_r3_f1_cert_expiry_range_start_reverted_is_killed`, `..._every_github_event_before_has_the_carrier_fallback`, +4 |
| F1 mutant `declaration-gate-base-reverted` | `e40f9321` | as above | KILLED: `test_6117_r3_f1_declaration_gate_base_reverted_is_killed`, +5 |
| F1 mutant `all-four-before-consumers-reverted` | `e40f9321` | as above | KILLED: `FAILED (failures=7)` |
| F2 MEDIUM approval STEP neutralisable | `90d87eb4` | `mutants.py approval-step-continue-on-error approval-step-if-pull_request-only` | both **KILLED** by `test_6117_r3_f2_approval_steps_cannot_be_neutralised` (`FAILED (failures=1)` each). NOT closed for the sibling shapes `run: … \|\| true`, job-level `continue-on-error`, `if :` (Findings 2, 5, 6 below) |
| F3 MEDIUM T3/T6 crossroads without the vote | vote run (memory `7c8538f6`, 3-2 for option (a)); cited in `e40f9321` body: "Item 10, the testability lens of the 5-agent vote (4d3ea1c5)" | `git log -1 --format=%B e40f9321 \| grep -n '5-agent vote (4d3ea1c5)'` | line 66 of the concatenated bodies; vote conditions checked in Evidence 9 (nine pins: MET; closed-world pin: MET in substance, by-file hole Finding 4; F5 docs: MET; #6213/#6223 not closed: MET; cited in commit: MET; cited in PR body: no PR exists yet, pending) |
| F4 LOW gh stderr + API strings echoed unvalidated | `59be78f1` | `python3 -I .local-runs/rev-6117-r2/run_shim_cases.py` cases `rate-limit-403`, `metachar-login-and-repo`; `mutants.py script-stderr-token-not-redacted` | `rate-limit-403`: exit 1, `token_leak=False`, only the first stderr line relayed; `metachar-login-and-repo`: exit 1 "has an invalid author login", `forged=False`; redaction mutant KILLED by `test_6117_r3_f4_rate_limit_stderr_is_not_relayed_with_a_token`. Closed, but the login regex it added is Finding 1 and the validator itself is unpinned (`script-login-validation-dropped` SURVIVED, Finding 10) |
| F5 LOW docs "never"/"cannot" overclaim | `36959f7e` | `grep -n 'never reports a pass\|cannot report a pass' docs/AI_DEVELOPER_GOVERNANCE.md docs/contributing-external.md` → no match; `test_6117_r3_f5_docs_do_not_say_never_or_cannot` in the 287-case run | closed; both paragraphs now scope the guarantee to PRs open at judgement time and cite #6213 and #6227 |
| F6 LOW stale `check-claude-md-size.py:1606` comment | `2515d26b` | `sed -n 1606,1608p scripts/check-claude-md-size.py`; `test_6117_r3_f6_claude_md_size_comment_states_the_current_rule` | closed; comment states the post-#6117 rule |

Commit-body items of the eight new commits, each verified:

| commit | item | result |
|---|---|---|
| `dddd9ba8` #6226 | `--paginate` pinned; unreadable-payload exit pinned | `mutants.py script-drop-paginate` KILLED (`test_6226_m01_dropping_paginate_is_killed`, `test_6226_push_lists_open_prs_with_paginate_and_judges_page_two`); `script-payload-read-fail-passes` KILLED (`FAILED (failures=4)`: `test_6226_pull_request_payload_unreadable_fails_closed` ×3 subtests + `test_6227_merge_group_payload_unreadable_fails_closed`). Shim `150-open-prs-match-last` exit 1 "FAILED for PR #150" |
| `066366c9` python3 -I | seven invocations isolated | `grep -c 'python3 -I scripts/check_' .github/workflows/c8-precheck.yml` → 7; `mutants.py evaluate-step-python-not-isolated` KILLED (`test_6117_r3_n2_gate_scripts_run_with_isolated_python`) |
| `b6a48626` #6227 | merge_group judges the PR named by `head_ref` | shim: `merge-group-unapproved` 1, `merge-group-approved` 0, `merge-group-pr-closed` 1 ("not an open pull request"), `merge-group-unparsable-ref` 1 (0 gh calls), `merge-group-empty-payload` 1, `merge-group-team-pr` 0, nested base `release/v1.0.0` parses; `mutants.py script-merge-group-arm-dropped` KILLED (3 tests), `script-merge-group-not-open-passes` KILLED. The job-header comment was NOT updated (Finding 8); the one-PR limit is filed as #6229 |
| `e40f9321` F1 + closed world | nine pins + closed-world scan | nine assertions in `_carrier_consumption_problems` (4 env lines + 3 ci arm wants + 2 coverage arm wants); closed-world scan reports the c8 and release-shape bare occurrences but not one in a non-classify job of ci.yml / coverage.yml (Finding 4) |
| `90d87eb4` F2 | step-scope pin | killed for `continue-on-error`, `if:`, `timeout-minutes: 0`; not for `\|\| true`, `if :`, job-level `continue-on-error` (Findings 2, 5, 6) |
| `59be78f1` F4 | sanitiser | closed as F4; introduces Finding 1 |
| `36959f7e` F5, `2515d26b` F6 | docs/comment | closed |

## Findings

Ranked. Severity / file:line / what / how reproduced / fix size.

### F1 — HIGH — `LOGIN_RE` rejects GitHub App logins (`name[bot]`), so a bot-authored PR can never pass the required gate, approval or not

- `scripts/check_external_pr_approval.py:40` `LOGIN_RE = re.compile(r"[A-Za-z0-9-]{1,39}")`,
  `:130-131` `raise GateError(f"PR #{number} has an invalid author login")` (added by `59be78f1`).
- GitHub Apps author PRs under logins of the shape `dependabot[bot]`, `github-actions[bot]`,
  `copilot-swe-agent[bot]`. This repository has `.github/dependabot.yml` and six dependabot PRs;
  **#4127 is open now** (`search_pull_requests author:app/dependabot` → `"login": "dependabot[bot]"`,
  `"author_association": "NONE"`, base `main`, same-repo head). `c8-precheck.yml:60-63` runs on
  `pull_request` into `main`, so the required context `External-PR operator-approval gate …` runs
  on that PR.
- Reproduced (`.local-runs/rev-6117-r2/bot_login.py`, `run_gate` with a fake api that returns an
  APPROVED review by `alphaonedev` on the exact head): `dependabot[bot] pull_request → exit 1
  "PR #4127 has an invalid author login"`; same on `push`; same for `github-actions[bot]` and
  `copilot-swe-agent[bot]`; `alphaonedev → exit 0`. Shim cases through the real entry point:
  `bot-login-dependabot-operator-approved` exit 1 (want 0), `bot-login-dependabot-pull_request-operator-approved`
  exit 1 (want 0). **Regression proof:** the same probe against the round-1 script
  (`git show 024f7f41e:scripts/check_external_pr_approval.py`) → `exit 0 … APPROVED review by
  @alphaonedev found … (pass)` for `dependabot[bot]` on both events.
- Consequence: the #3591 policy's merge path for a non-team PR ("a native GitHub review submitted
  by the human operator", `docs/contributing-external.md:17`) is closed for every bot-authored PR.
  The gate is fail-closed, so this is availability, not bypass; it is HIGH because it is a new
  unconditional red on a required context for a PR class that exists in the repository today, no
  test caught it, and the `--self-test` and the 287-case suite only ever use the login `x`.
- Fix: 1 line + 1 cell: `LOGIN_RE = re.compile(r"[A-Za-z0-9-]{1,39}(?:\[bot\])?")` and a
  decision-table cell `pull-request-bot-author-operator-approved-passes` with
  `user.login = "dependabot[bot]"`. Add the `script-login-validation-dropped` mutant to the kill
  list while there (Finding 10).

### F2 — MEDIUM — `run: python3 -I scripts/check_external_pr_approval.py || true` survives every gate

- `.github/workflows/c8-precheck.yml:1376` (the Evaluate step's `run:` line);
  `scripts/test/test_workflow_pr_triggers_5447.py:3288` `self.assertIn("python3 -I scripts/check_external_pr_approval.py", runs)`
  is a substring pin.
- Reproduced: `mutants.py approval-step-run-or-true` → **SURVIVED** (`Ran 287 tests … OK`;
  `ci.yml invariants: 38/38 PASS`; `check-required-contexts: OK`); `actionlint` exit 0 on the
  mutant too. The job is green on every event, including a fork PR with no approval.
- Same class as round-1 F2 (one-line neutraliser of the required security context), one token
  to the right of what `90d87eb4` pinned.
- Fix: ~2 lines: assert the Evaluate step's run body is exactly
  `python3 -I scripts/check_external_pr_approval.py\n` (and the Self-test step's exactly
  `… --self-test\n`); add the mutant.

### F3 — MEDIUM — `OPERATOR_LOGIN` is not pinned; the gate can be re-pointed at any login

- `.github/workflows/c8-precheck.yml:1375` `OPERATOR_LOGIN: alphaonedev`. The required
  context's NAME, `docs/AI_DEVELOPER_GOVERNANCE.md:689` and `docs/contributing-external.md:17` all
  promise an `@alphaonedev` review; nothing checks that the workflow still says so.
- Reproduced: `mutants.py operator-login-changed` (`alphaonedev` → `mallory`) → **SURVIVED** all
  three gates (`grep -n OPERATOR_LOGIN scripts/test/test_workflow_pr_triggers_5447.py` → only the
  test's own env, lines 3379 and 3443). An approval by `mallory` then satisfies the gate; the
  operator's approval no longer does.
- Fix: 1 assertion: the Evaluate step block contains `OPERATOR_LOGIN: alphaonedev`; or derive it
  from the context name in `required-contexts-release.txt:291`.

### F4 — MEDIUM — the vote-mandated closed-world pin exempts `${{ github.event.before }}` by FILE, not by occurrence

- `scripts/test/test_workflow_pr_triggers_5447.py:3568-3570`:
  `if expr in BEFORE_CLASSIFY_OK.get(name, ()) and _job_text(text, "classify").find(expr) >= 0: continue`.
  For `ci.yml` and `coverage.yml` the classify job contains `${{ github.event.before }}` (true
  today), so EVERY bare `${{ github.event.before }}` anywhere in those two files is exempt,
  whichever job it is in. The test `test_6117_r3_f1_bare_consumer_outside_classify_is_killed`
  only exercises `release-shape.yml`, which has no exemption.
- Reproduced: direct scratch probe on copies of the six workflows: one bare `X: ${{ github.event.before }}`
  added to the `lint` job env of `ci.yml` → `_bare_before_consumers` → `[]` (and
  `_job_text(ci, "classify").find(…) >= 0` → `False`: the occurrence is NOT in classify). Full
  gates: `mutants.py closed-world-bare-before-ci-nonclassify-job` → **SURVIVED** (`OK`, 38/38,
  required OK; actionlint exit 0). The c8 (`+1 bare` → 1 reported) and release-shape mutants are
  KILLED, as the commit body claims. (My coverage.yml mutant also survived but duplicated an `env`
  key — actionlint `syntax-check` — so only the ci.yml case is load-bearing; the code path is the
  same.)
- Consequence: a fifth range consumer added to a non-classify job of ci.yml or coverage.yml with
  the bare push `before` narrows a carrier push with every gate green: exactly the condition the
  5-agent vote attached to option (a).
- Fix: ~3 lines: compute the classify job's `[start, end)` offsets in the file and exempt only
  occurrences whose `m.start()` lies inside it; add the ci.yml lint-job mutant.

### F5 — MEDIUM — a job-level `continue-on-error: true` on the approval job survives

- `.github/workflows/c8-precheck.yml:1343` (job `external-pr-operator-approval-gate`).
  `test_6117_r2_sf1_workflow_runs_the_evaluator_on_every_event` forbids job-level `needs`/`if`
  (`assertNotRegex(job, r"(?m)^    (needs|if):")`); `test_6117_r3_f2_*` covers step scope only;
  `check-required-contexts.sh` rule (f) checks `needs`/`if`/`paths`.
- Reproduced: `mutants.py approval-job-continue-on-error` → **SURVIVED** all three gates;
  actionlint exit 0. GitHub (workflow-syntax, fetched 2026-10-09): "`jobs.<job_id>.continue-on-error`
  Prevents a workflow run from failing when a job fails. Set to true to allow a workflow run to
  pass when this job fails." The check-run conclusion of such a job is not documented; a
  required context whose failure is declared ignorable is not a gate either way.
- Fix: extend the sf1 regex to `(needs|if|continue-on-error)` at 4-space indent (1 token) and
  add rule (f) coverage in `check-required-contexts.sh` for the required set; add the mutant.

### F6 — LOW — the step-scope neutraliser regex is shape-bound: `if : …` (space before the colon) survives

- `scripts/test/test_workflow_pr_triggers_5447.py:3299` `STEP_NEUTRALISER = r"(?m)^\s+(?:- )?(?:if|continue-on-error):|…"`.
- `if : ${{ github.event_name == 'pull_request' }}` is valid YAML (`yaml.safe_load` →
  `{'if': '${{ a }}'}`) and a valid step key (actionlint exit 0, no findings) and skips the step
  on push / merge_group. `mutants.py approval-step-flow-if-key` → **SURVIVED** all three gates.
  (`"if":` quoted is KILLED, but by 16 unrelated regex-reader tests erroring, not by the F2 pin.)
- Fix: `(?:if|continue-on-error)\s*:` and `"?if"?` in the regex (1 line), or parse the step with
  the YAML reader the file already has for `load_all()`.

### F7 — LOW — the carrier step's `id: carrier` binding is not pinned by the trigger suite (actionlint, a required context, does catch it)

- `.github/workflows/c8-precheck.yml:582` (`id: carrier`, ×4). `CarrierRangeConsumed6117` pins the
  consumer text `steps.carrier.outputs.before || …` and `CarrierRangeStep6117` pins the step body,
  but nothing binds the id to the step.
- Reproduced: `mutants.py carrier-step-id-renamed-all` (`id: carrier` → `id: carrier0` ×4) →
  **SURVIVED** the trigger suite, invariants and required-contexts; `steps.carrier.outputs.before`
  is then empty on every run and all four consumers silently fall back to `github.event.before`,
  i.e. the round-1 F1 narrowing. actionlint on the mutant: exit 1
  `c8-precheck.yml:619:76: property "carrier" is not defined in object type {carrier0: …}`, and
  `actionlint (workflow-injection guard)` is a required context
  (`required-contexts-release.txt:129`, job `ci.yml:585`), so CI would go red. LOW for that
  reason; the local suite should still pin it so the kill does not depend on a different gate.
- Fix: 2 lines in `_carrier_consumption_problems`: the step block named `CARRIER_RANGE_STEP` in
  each of the four jobs must contain `id: carrier`.

### F8 — LOW — the approval job's header comment still describes the pre-#6227 merge_group behaviour

- `.github/workflows/c8-precheck.yml:1333-1337`: "A push or merge_group run … lists the open PRs
  whose head is GITHUB_SHA and applies the rule above to each (none: pass)". The step comment at
  `:1360-1363` and `changelog.d/6117.security.md` were updated by `b6a48626` ("The changelog and
  the workflow comment now say what is judged"); this second comment, 25 lines above, was not.
  `MergeGroupDocTruth6227` checks the changelog and the script docstring, not the workflow.
- Fix: 2 lines of comment.

### F9 — LOW — `TOKEN_RE` does not match fine-grained PATs (`github_pat_…`)

- `scripts/check_external_pr_approval.py:42` `TOKEN_RE = re.compile(r"gh[pousr]_[A-Za-z0-9]{20,}")`.
- Shim case `github-pat-in-stderr` (fake `gh` echoes `$GH_TOKEN` = `github_pat_` + 82 chars on
  its first stderr line) → exit 1, `token_leak=True`: the value reaches stdout. Not reachable
  today: the step sets `GH_TOKEN: ${{ github.token }}` (always `ghs_`), Actions masks it, and the
  real `gh` never prints it. Consistency gap in the sanitiser the branch added for exactly this.
- Fix: `r"(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})"` (1 line) + 1 shim cell.

### F10 — LOW — the round-1 F4 login validation is not pinned in isolation

- `mutants.py script-login-validation-dropped` (delete lines 130-131) → **SURVIVED**:
  `test_6117_r3_f4_metachar_names_cannot_forge_annotations` still passes because the
  `author_association` and `head.repo.full_name` validators reject the same fixture. Fixing
  Finding 1 touches this regex; the regression it introduced is the reason a dedicated cell
  (valid `x`, valid `dependabot[bot]`, invalid `x\n::error::`) is needed.
- Fix: 3 cells in `_approval_cases`.

Equivalent mutant (not a finding): `script-queue-ref-regex-any-number` (`number <= 0` → `< 0`)
SURVIVED because a parsed `pr-0-<sha>` then fails closed one line later ("not an open pull
request"); both paths exit 1.

## Evidence

Executed in the sandbox (4 cores, 15 GiB, git 2.43, python 3.11/3.12/3.13, rustc present;
`gh` on PATH but `gh auth status` → "Failed to log in"; the GitHub MCP tools and the public REST
API worked for issue and PR reads; `git fetch --unshallow origin` →
`--is-shallow-repository` = `false`). Scratch under `.local-runs/rev-6117-r2/` (drivers
`mutants.py`, `run_shim_cases.py`, `bot_login.py`; worktree `wt` at the tip, restored clean
after every mutant: `git -C wt status --short` → empty).

1. **Merge-tree claim.** Real refs: `git rev-list --count origin/release/v1.0.0..origin/chain/promo6-ssh`
   = 314, `…promo6-ssh..release/v1.0.0` = 0; `git merge-tree --write-tree 26785a59 fa6b588e` →
   `257908ad1712e8f63815a1e679d411938b7dc302` == `git rev-parse fa6b588e^{tree}` (EQUAL).
   Synthetic (`.local-runs/rev-6117-r2/syn/r`): (A) release gains a real commit not in carrier →
   `rev-list carrier..release=1`, merge-tree `d211b557…` ≠ carrier tree `3a247983…`, script exit 1
   `FAIL #3872: candidate is BEHIND release`; (C) carrier merges release → behind=0, merge-tree ==
   carrier tree, exit 0 `PASS #3872`; (B) release then gains an EMPTY commit → behind=1,
   merge-tree == carrier tree, exit 1 (refuses; conservative). "behind=0" ⇒ base ∈ ancestors(head)
   ⇒ fast-forward ⇒ merge tree == head tree: sufficient, not necessary (B). Judgement unchanged
   from round 1: the fact is a precedent copy; the mechanism choice was T3+T6 and the vote has
   now been run (round-1 F3 closed).
2. **Approval script.** `python3 -I .local-runs/rev-6117-r2/run_shim_cases.py` → `shim cases: 27
   passed, 3 failed` (the three: the two `dependabot[bot]` cells, Finding 1; `github-pat-in-stderr`,
   Finding 9). Exit / last line: zero-open-prs 0 `nothing to approve (pass)`; unapproved-fork-pr 1
   `::error::… FAILED for PR #7 …`; approved 0; approved-by-pr-author 1; dismissed-approval 1;
   approval-on-old-head 1; reviews paginated (approval 101st) 0; 150 open PRs over two pages,
   match last 1 (`PR #150`); rate-limit-403 1 (`token_leak=False`, second stderr line dropped);
   server-5xx 1; malformed-json 1 (`not JSON at offset 0`); error-object 1 (`a dict, not an
   array`); head-moved-after-run-started 0; team-same-repo 0; member-from-fork 1;
   deleted-head-repo 1 (`from 'None'`); two-prs-one-approved 1 (`PR #11`); bool-number 1;
   workflow_dispatch zero PRs 0; metachar login/assoc/repo 1 `invalid author login`
   (`forged=False`, no line starts `::error::forged` / `::set-output`); merge_group ×6 as in the
   #6227 row above; `GITHUB_SHA` = 39×`a`+`;` → exit 1, `gh_calls=0`. Subprocess argv: only
   `repo` (REPO_RE, `:168`) and `number` (validated int, `:94`) are API-derived. `--self-test` →
   `external-pr-approval self-test: 0 failed`.
3. **Geometry script against the real origin** (`--github-event`, `--event-name push`,
   `ref=refs/heads/chain/promo6-ssh`): after=carrier tip → exit 0 PASS; after=release tip → exit 0;
   after=release^ (`6da16a771c`) → exit 1 `FAIL #3872: candidate is BEHIND release`;
   after=`dddd…` → exit 2 (`CARRIER #6117 …` then fail closed); `ref=refs/heads/main` → exit 0
   `INAPPLICABLE #3872`. `git clone --depth 1` → `ERROR #3872 (fail closed): shallow history:
   fetch full history before measuring ancestry`, exit 2. Carrier step body replayed
   (`_step_runs(c8, CARRIER_RANGE_STEP)[0]`, clone with `origin` = `https://127.0.0.1:9/nonexistent.git`)
   → exit 1, `::error::carrier push: cannot fetch origin/release/v1.0.0; refusing to judge the
   carrier over an unknown range`, `$GITHUB_OUTPUT` empty. `--self-test` → `25 passed; 0 failed`.
   `--print-release` → `release/v1.0.0`. (Script unchanged since round 1: `git diff 024f7f41e..2515d26b8 --stat` lists no `check_promotion_geometry.py`.)
4. **Workflow triggers and mutants.** Tip: `python3 scripts/test/test_workflow_pr_triggers_5447.py`
   → `Ran 287 tests in 6.351s` / `OK` (264 in round 1). Mutants (33, `.local-runs/rev-6117-r2/mutants.log`):
   **KILLED 25** — the 5 round-1 F1 and 2 round-1 F2 mutants (table above); round-1 kill set
   re-run: `pin-release-at-job-env-c8` (`sf4_release_ref_has_one_source`),
   `drop-persist-credentials-false` and `approval-job-if-pull_request-only` (`sf1_workflow_runs_the_evaluator_on_every_event`;
   the latter also `check-required-contexts.sh` rc=1), `drop-approval-self-test-step` (3 tests),
   `narrow-chain-glob-c8-only` (5), `drop-event_name-from-ci-group` (6 + invariants 2 FAILED +
   required rc=1); new: `evaluate-step-python-not-isolated` (`r3_n2`), `carrier-step-always-empty`
   (`sf3` ×2), `cert-expiry-env-line-deleted` (3), `closed-world-bare-before-c8` (3),
   `closed-world-bare-before-release-shape` (14), `approval-step-quoted-if-key` (16, collateral),
   `script-merge-group-arm-dropped` (3), `script-merge-group-not-open-passes` (`sf1_decision_table`),
   `script-drop-paginate` (2), `script-payload-read-fail-passes` (4), `script-stderr-token-not-redacted`
   (`r3_f4_rate_limit…`). **SURVIVED 8** — `approval-step-run-or-true` (F2), `approval-step-flow-if-key`
   (F6), `approval-job-continue-on-error` (F5), `operator-login-changed` (F3),
   `carrier-step-id-renamed-all` (F7; actionlint catches it), `closed-world-bare-before-ci-nonclassify-job`
   (F4), `closed-world-bare-before-coverage-nonclassify-job` (F4; malformed, see F4),
   `script-login-validation-dropped` (F10); plus the equivalent `script-queue-ref-regex-any-number`.
   Every survivor: `Ran 287 tests … OK`, `ci.yml invariants: 38/38 PASS`, `check-required-contexts: OK`.
   Red-on-previous-head was shown in round 1 (`d1dd5516` → `FAILED (failures=16)`) and the delta
   adds only tests + fixes; the new tests' load-bearing-ness is shown by the kills above
   (e.g. `test_6226_m01_dropping_paginate_is_killed` asserts the mutant passes vacuously).
5. **Required-check naming.** `scripts/qc-allowlists/required-contexts-release.txt` (394 lines)
   declares `External-PR operator-approval gate (author outside team => @alphaonedev review)`
   (:291), `Classify changes` (:122), `Coverage classify (docs-only short-circuit)` (:223),
   `actionlint (workflow-injection guard)` (:129). `bash scripts/check-required-contexts.sh` →
   `check-required-contexts: OK (…)`; `python3 scripts/check_release_features.py --self-test` →
   `self-test OK (… 356 guard cases …)`. GitHub docs (fetched 2026-10-09): about-status-checks
   "A job that is skipped will report its status as "Success"."; troubleshooting-required-status-checks
   "Required checks must pass on the latest commit SHA." No sentence defines a tie-break between
   two check runs of one name on one sha, so a passing push run can mask a failing PR run; under
   this branch that is harmless only while every required context is at least as strict on push
   as on pull_request — Findings 2, 3, 5, 6 are the one-line edits that break that, each with every
   gate green. The #6213 residual is outside this branch under design (a) and stays open (checked:
   no close keyword for #6213 / #6223 in any of the eight bodies or the changelog; both say
   "tracked in #6213"). Rulesets (public REST, HTTP 200): `signed-attested-branches` (17752665)
   `include = [refs/heads/main, refs/heads/develop, refs/heads/release/*]`, rules
   `required_signatures, deletion, non_fast_forward`; `archive-refs-frozen (branches)` includes
   `refs/heads/chain/promo6` (not `promo6-ssh`). `chain/promo6-ssh` still has no
   `required_signatures` / `non_fast_forward` (FOUND-NOT-FIXED, carried from round 1).
6. **Concurrency.** `ci.yml:166` `group: ci-${{ github.workflow }}-${{ github.event_name }}-${{ … || github.ref_name }}`;
   `c8-precheck.yml:112` `c8-precheck-${{ github.event_name }}-…`; `coverage.yml:87`
   `cov-${{ github.workflow }}-${{ github.event_name }}-…`; `postgres-ignored.yml:44`
   `pg-ignored-${{ github.event_name }}-…`; `release-shape.yml:58` `release-shape-${{ github.event_name }}-…`;
   `cert-postgres-age.yml:100` (event-keyed, round 1). Push and pull_request runs on one carrier
   sha key `…-push-chain/promo6-ssh` vs `…-pull_request-chain/promo6-ssh`: neither cancels the
   other. `drop-event_name-from-ci-group` KILLED by 6 tests + invariants + required-contexts.
7. **Hygiene.** `python3.11/3.12/3.13 -m py_compile` both scripts → OK ×3 (3.11 is the oldest
   available; `grep 'shell=True\|match \|| None'` → no hit; imports: argparse, json, os, re,
   subprocess, sys, pathlib, tempfile). `bash scripts/test/test-ci-workflow-invariants.sh` →
   `ci.yml invariants: 38/38 PASS`. `bash scripts/check-required-contexts.sh` → OK.
   `python3 scripts/check_release_features.py --self-test` → OK. `bash scripts/check-count-assertion-declared.sh --range origin/chain/promo6-ssh..HEAD`
   → `count-assertion-declared: clean`. actionlint 1.7.7 (downloaded into
   `.local-runs/rev-6117-r2/bin`) over the six workflows `-shellcheck= -pyflakes=` → exit 0.
   No `.rs` / `Cargo.*` change.
8. **Docs drift.** `grep -rn 'check_promotion_geometry\|check_external_pr_approval\|CARRIER_RELEASE_REF' docs/`
   → no hit outside the two edited paragraphs; `chain/` in docs/ → unrelated history only.
   `changelog.d/6117.fixed.md` claims re-verified (six workflows, three re-keyed groups, four
   range-start steps at c8:581/1192/1413/1479, one release source). `6117.security.md` now
   describes the merge_group arm correctly. Residual drift: Finding 8 (job-header comment).
9. **Vote conditions (memory 7c8538f6, option (a) 3-2).** (i) nine site pins:
   `_carrier_consumption_problems` = 4 consumer env lines + 3 ci.yml arm wants + 2 coverage.yml
   arm wants = 9 — MET. (ii) closed-world pin: `grep -n 'github\.event\.before'` over the six
   workflows → 6 `${{ }}` expressions: `c8-precheck.yml:619,1231,1451,1517` carrier form (4),
   `ci.yml:263` and `coverage.yml:155` bare, both inside the classify job and read after the
   carrier arm exits (`ci.yml:322-330` before `:338`; `coverage.yml:147-151` before `:155`); the
   exemption is documented in the `e40f9321` body. Scratch copy with one bare occurrence in c8 →
   `['c8-precheck.yml:1232: ${{ github.event.before }}']` (reported). Literal condition ("every
   `github.event.before` … in the carrier form") is MET by exemption, and the exemption is
   implemented by file (Finding 4). (iii) F5 docs — MET. (iv) #6213 / #6223 stay open — MET.
   (v) vote cited in the cloud-F1 commit — MET (`e40f9321`); in the PR body — no PR exists yet.

## Issue requirements

| Issue | Literal requirement | Status | Evidence |
|---|---|---|---|
| #6117 | "(a) adding `chain/**` to `on.push.branches` of the required-set workflows" | MET | six workflows (c8-precheck.yml:61 etc.); `narrow-chain-glob-c8-only` KILLED |
| #6117 | "plus the pins in scripts/check-claude-md-size.py and scripts/test/test_workflow_pr_triggers_5447.py" | MET | comment fixed (`2515d26b`, `r3_f6`); 287 cases |
| #6117 | "Must land after #6105 (same files)" | MET | base fa6b588e contains #6105 |
| #6117 (title) | a carrier-only defect surfaces on the carrier push with the PR run's verdict shape | MET in code; pins now kill the 5 round-1 mutants; residual F7 (id binding, caught only by actionlint) | Evidence 4 |
| #6193 | "1. List the open PRs whose head is the judged commit … filter head.sha == GITHUB_SHA" | MET | `:188-189`; shim `150-open-prs-match-last` |
| #6193 | "2. … require the same operator APPROVED review on commit_id == GITHUB_SHA" | MET for human logins / **NOT MET for bot logins** | F1: `dependabot[bot]` + APPROVED on head → exit 1 |
| #6193 | "3. Fail closed: an API error, or a non-numeric or empty count, exits 1" | MET | shim 403/5xx/malformed/error-object/bool-number all 1 |
| #6193 | "4. Self-test … red on the current gate and green on the fix" | MET | `--self-test` 0 failed; `sf1_m01` kill; round-1 red on d1dd5516 |
| #6193 | gate holds "whichever branch runs it" (the required context cannot be neutralised) | NOT MET in pins | F2 `\|\| true`, F3 `OPERATOR_LOGIN`, F5 job `continue-on-error`, F6 `if :` all SURVIVED |
| #6227 | merge_group judges the PR named by `head_ref`; unparsable / not open fails closed | MET | shim merge-group ×6; two script mutants KILLED; F8 comment drift |
| #6226 | `--paginate` and unreadable-payload exit pinned | MET | two mutants KILLED |

```
REPORT lane=rev-6117-r2 branch=cloud/f1/rev-6117-r2 base=2515d26b885f419b5fb00298e5dcad6f1e9d4611 head=<filled in the final message> pushed=<filled in the final message>
COMMITS
<filled in the final message>
ITEMS
#6117 | reviewed | REJECT | 10 findings (F1 HIGH, F2-F5 MEDIUM, F6-F10 LOW); all 6 round-1 findings closed
#6193 | reviewed | REJECT | F1 HIGH, F2, F3, F5 MEDIUM, F6, F9, F10 LOW bear on it; literal requirements 1, 3, 4 MET, 2 MET for human logins only
#6227 | reviewed | APPROVE (fix verified) | 1 finding (F8 LOW comment drift)
#6226 | reviewed | APPROVE (fix verified) | 0 findings
GATES
see Evidence 4 and 7 above
DECISIONS
see the final message
FOUND-NOT-FIXED
scripts/check_external_pr_approval.py:40 LOGIN_RE rejects `name[bot]` logins (F1; subject branch, read-only lane)
.github/workflows/c8-precheck.yml:1376 Evaluate run line pinned by substring only (F2)
.github/workflows/c8-precheck.yml:1375 OPERATOR_LOGIN unpinned (F3)
scripts/test/test_workflow_pr_triggers_5447.py:3568-3570 classify exemption by file (F4)
.github/workflows/c8-precheck.yml:1343 job-level continue-on-error unpinned (F5)
scripts/test/test_workflow_pr_triggers_5447.py:3299 STEP_NEUTRALISER shape-bound (F6)
.github/workflows/c8-precheck.yml:582 `id: carrier` binding unpinned locally (F7)
.github/workflows/c8-precheck.yml:1333-1337 stale merge_group comment (F8)
scripts/check_external_pr_approval.py:42 TOKEN_RE misses github_pat_ (F9)
scripts/check_external_pr_approval.py:130-131 login validator unpinned in isolation (F10)
ruleset 17752665 excludes refs/heads/chain/*: no required_signatures / non_fast_forward on chain/promo6-ssh (carried from round 1; #6193 names a companion issue)
```
