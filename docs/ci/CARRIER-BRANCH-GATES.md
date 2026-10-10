# CI hang-watchdog budgets by tier (#1492, #6202, #6344)

The full-suite step in `.github/workflows/ci.yml` ("full suite (cargo test)")
runs `cargo test --no-fail-fast` under GNU `timeout --signal=TERM
--kill-after=60 $WATCHDOG_SECS`. On tier `enterprise-fed` the suite runs as
three concurrent shards and `$WATCHDOG_SECS` bounds each shard's whole chain
(see [Sharded enterprise-fed suite (#6344)](#sharded-enterprise-fed-suite-6344)). The watchdog exists to catch a hung test and
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
| `linux-fed,enterprise-fed` | 7800 s (130 min) per shard | 160 | longest shard estimate 3,913 s (serial) | not yet measured (first green sharded run) |
| `macos-fed,enterprise-fed` | 7800 s (130 min) per shard | 160 | n/a | n/a |

Ratio rule: job `timeout-minutes` >= watchdog minutes + 15. On the sharded
`enterprise-fed` legs the stricter rule applies: job `timeout-minutes` >=
watchdog minutes + 28 (pre-watchdog compile and database setup) + 2 (teardown)
= 160. All four rows meet both.

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

# Carrier-branch gates (#6143)

`chain/**` and `rehearsal/**` are `pull_request` base branches of the gating
workflows (for example `.github/workflows/c8-precheck.yml`). GitHub does not
re-run `pull_request` workflows when the base branch moves, so a green gate is
a verdict on the merge ref as it was built. On a base with no up-to-date-head
rule, a pull request can merge after the base moved without any gate judging
the tree that actually lands (#6143, found in the #6137/#6138 review).

**Status: the defect is still open.** Until the carrier ruleset below is live
(tracking issue #6182), nothing on `chain/**` or `rehearsal/**` requires a
status check or an up-to-date head. The two jobs in this document report, but
neither blocks a merge.

## Repo-side controls

| Job (context) | Script | What it reports | Required? |
|---|---|---|---|
| `Carrier-base freshness gate (#6143)` (`carrier-base-fresh-gate`) | `scripts/check_carrier_base_fresh.py` | RED when the merge commit the job checked out is not built on the live tip of the carrier base. It fetches the tip on every run, so re-running a stale green turns it red. Remedy printed by the gate: `gh pr update-branch <PR>`, then wait for the new run. | Advisory. Carrier ruleset context once #6182 lands; never a release/v1.0.0 context. |
| `Carrier-ruleset live verifier (#6143)` (`carrier-ruleset-live-gate`) | `scripts/check_carrier_ruleset_live.py` | Read-only (GET) comparison of the live repository rulesets with the committed payload. | Advisory until the #6182 promotion. |

## The carrier ruleset (exact payload, applied by ai:god-f2)

The exact POST body is committed at `docs/ci/carrier-ruleset.json`:

- name `carrier-branches-strict-checks`, target `branch`, enforcement `active`;
- `conditions.ref_name.include` = `refs/heads/chain/**`, `refs/heads/rehearsal/**`;
  `exclude` = `[]`;
- `bypass_actors` = `[]` (no actor, role, team or app can skip it);
- one `required_status_checks` rule with
  `strict_required_status_checks_policy: true` (the head must be up to date
  with the base before merge) and `do_not_enforce_on_create: true` (creating a
  new `chain/**` branch by push is allowed; without it the push is refused,
  because its commits have not yet passed the checks on another ref);
- the contexts are exactly `scripts/qc-allowlists/required-contexts-carrier.txt`:
  every context of `scripts/qc-allowlists/required-contexts-release.txt`
  (including `Enterprise-federation cert-expiry gate (cert §7 / F7)`, the gate
  whose stale-merge-ref case surfaced #6143) plus
  `Carrier-base freshness gate (#6143)`, each pinned to `integration_id`
  15368 (GitHub Actions), so a commit status posted under the same name by any
  other app or token does not satisfy the rule.

Precondition: apply the ruleset only after this change is on every carrier
that is not frozen and still takes pull requests. On 2026-10-09
(`git ls-remote origin 'refs/heads/chain/*' 'refs/heads/rehearsal/*'`) these
are `chain/promo6-ssh` and `rehearsal/audit-wip-ssh`. `chain/promo6` and
`rehearsal/audit-wip` are frozen by ruleset 24733250. The ruleset requires
`Carrier-base freshness gate (#6143)` on every `chain/**` and `rehearsal/**`
base. On a carrier whose tip lacks that job, the context never reports, so no
pull request into that carrier can merge. The pre-apply check below enforces
this precondition; it does not rely on this list.

Apply it from a checkout of a carrier tip that contains this change. These are
repository-settings writes, held by ai:god-f2. Use an admin-scoped token, which
can see `bypass_actors`:

```
python3 -I scripts/check_carrier_ruleset_live.py --pre-apply
gh api -X POST repos/alphaonedev/ai-memory-mcp/rulesets --input docs/ci/carrier-ruleset.json
python3 -I scripts/check_carrier_ruleset_live.py --require-full-view
```

- `--pre-apply` must return rc 0 (`PRE-APPLY OK`) before the `POST`. It reads
  every live `refs/heads/chain/**` and `refs/heads/rehearsal/**` branch
  (GET only). It skips a carrier only when an active ruleset with an `update`
  rule names that carrier exactly, does not exclude it, and shows
  `bypass_actors: []`. For every other carrier it reads
  `.github/workflows/c8-precheck.yml` at the tip and fails unless both #6143
  jobs are defined there and the workflow triggers on `pull_request` for that
  carrier's base (`on.pull_request.branches` covers `chain/**` or
  `rehearsal/**`, with no `paths`/`paths-ignore` filter and no `types` list that
  drops `opened`, `synchronize` or `reopened`, no flow-mapping form, no
  `branches` together with `branches-ignore`, and no `?`, `+` or `[...]` in a
  branch pattern, which the verifier does not translate); a tip
  that defines the jobs but does not trigger for every pull request would never
  report the required context. Any carrier it cannot read is RED. It checks the
  jobs, the trigger and, in the `applied` state, the release tip (step 3
  precondition); it does not compare the tip's payload or declaration files.
- Expected after the `POST`: rc 1, `carrier ruleset <id> ('<name>') is live and
  matches; flip carrier-ruleset-state.json to "applied"`. The promotion (step 3
  below) flips the state and promotes the verifier job.
- The ruleset `<id>` for the later `PUT` is the `id` field of the POST
  response, confirmed before use by `gh api repos/alphaonedev/ai-memory-mcp/rulesets/<id>`
  showing `name == carrier-branches-strict-checks`. It is never taken from a CI
  log: under `pull_request` the log line comes from the pull request's own copy
  of the verifier (the #6140 class). The verifier names a ruleset as a match, and
  so as a `PUT` target, only when it carries the payload name, exactly the two
  include patterns (no `~ALL`, `~DEFAULT_BRANCH` or other pattern), exactly the
  payload's rule types and no repeated context; two matching rulesets are
  reported as ambiguous (#6436).

Effects to expect once the ruleset is live:

- A new carrier (`chain/**` or `rehearsal/**`) must be cut from a tip that
  already contains both #6143 jobs; otherwise its pull requests cannot merge.
  Run `--pre-apply` after cutting one. It is RED for a carrier that lacks the
  jobs.

- A direct push that moves an existing carrier is refused unless its commits
  have already passed every required check on another ref. Carriers move by
  merging pull requests. There is deliberately no bypass actor: any bypass
  would let the same stale-head merge through.
- Ruleset 24733250 `archive-refs-frozen (branches)` already applies `update`,
  `deletion` and `non_fast_forward` to `refs/heads/rehearsal/audit-wip` and
  `refs/heads/chain/promo6`. Rules from several rulesets stack; the carrier
  ruleset adds required checks and does not loosen the freeze.
- Ruleset 17752665 `signed-attested-branches` (main, develop, release/*) is a
  separate object and is not changed.

## Verifier states (5-agent vote (4d3ea1c5), memory a03dd15d)

`scripts/qc-allowlists/carrier-ruleset-state.json` holds
`{"state": "pending-apply" | "applied", "tracking_issue": 6182}`. Any other
value is RED, including any tracking issue other than #6182 (the number is
pinned in the verifier).

The state is coupled to the promotion of the verifier's own context,
`Carrier-ruleset live verifier (#6143)`:

- `applied` requires that context in `required-contexts-release.txt`, in
  `required-contexts-carrier.txt` and in the payload, and requires no
  `carrier-ruleset-live-gate` line in `required-contexts-not-required.txt`.
- `pending-apply` requires the reverse in every place.
- A half promotion is RED. For example, a commit that only flips the state
  cannot leave the removed-rule detector advisory.

- Always, offline: the payload must match the description above and
  `required-contexts-carrier.txt`, and the carrier declaration must contain
  every release-required context.
- Candidates: every active branch ruleset that has a `required_status_checks`
  rule and covers a carrier ref, or that has the payload's name. Each one is
  judged in full: include, `exclude` empty, `bypass_actors` empty, strict,
  `do_not_enforce_on_create`, the exact context set, `integration_id`.
- `applied`: a matching candidate is OK; no candidate, or drift, is RED. This
  is how a removed or weakened carrier rule is detected (#6143 item 3).
- `pending-apply`: no candidate and #6182 OPEN gives a WARN
  `UNPROTECTED ...` with the apply command, rc 0. #6182 closed or unreadable is
  RED. A drifting candidate is RED. A matching candidate is RED until the state
  is flipped to `applied`.
- The rulesets API unreadable: RED in every state. An empty response body
  also counts as unreadable; zero rulesets is the body `[]`.
- `bypass_actors` is hidden from the Actions `GITHUB_TOKEN`. A hidden field is
  reported as `UNVERIFIED` (WARN), and `--require-full-view` makes it RED. Only
  an actual empty JSON list counts as verified empty. `null`, a non-list or a
  non-empty list is always RED.
- The job is granted `contents: read` and `issues: read` at job level. The
  issue read therefore does not depend on the repository being public.

## Landing order (#6182)

1. This change lands on every unfrozen carrier that still takes pull
   requests: `chain/promo6-ssh` and `rehearsal/audit-wip-ssh` (2026-10-09).
   Both jobs are in `required-contexts-not-required.txt`.
   Today the live `--pre-apply` fails for two reasons, not one: the carrier tips
   lack the two #6143 jobs, and `rehearsal/audit-wip-ssh` does not run the
   workflow on pull requests into itself. It needs the commits that add that
   trigger (`9f4fc4208`, `20eadf8b1`) as well as the jobs.
2. ai:god-f2 runs `--pre-apply` (rc 0 required), applies the payload (`POST`,
   command above) and runs the verifier with `--require-full-view`. The
   expected result is rc 1 with "flip".
3. Promotion. Update the ruleset first, then merge.

   Precondition: `release/v1.0.0` defines `carrier-ruleset-live-gate` (and its
   workflow triggers on `pull_request` for that base). The #3554 lockstep below
   makes the verifier a required context on `release/v1.0.0` classic
   protection. Until the release tip carries the job, every open pull request
   into `release/v1.0.0` whose head is not a carrier (for example #5391, #5053
   and #5044) would never report it and could not merge. The job reaches
   `release/v1.0.0` when the carrier carrying this change merges into it
   (today #6160). Do not touch the release protection before that.
   `--pre-apply` enforces this: in the `applied` state it also reads
   `.github/workflows/c8-precheck.yml` at the `release/v1.0.0` tip and is RED
   unless the verifier job is defined there and the workflow triggers on it.

   1. Prepare the promotion pull request on top of step 1, in one commit:
      - set the state in `carrier-ruleset-state.json` to `applied`;
      - take the verifier context through the #3554 lockstep, after the
        precondition above and a `--pre-apply` rc 0 with the promoted state:
        add it to the release/v1.0.0 protection, then
        `bash scripts/check-required-contexts-live.sh --pin-from-live`, then
        `required-contexts-release.txt`;
      - add the context to `required-contexts-carrier.txt` and to the payload;
      - remove the `carrier-ruleset-live-gate` ledger line.

      The verifier refuses any partial version of this commit.
   2. ai:god-f2 runs `--pre-apply` again (with the promoted state, so the
      release tip is read), then updates the live ruleset from the promotion
      pull request's payload:
      `gh api -X PUT repos/alphaonedev/ai-memory-mcp/rulesets/<id> --input docs/ci/carrier-ruleset.json`,
      where `<id>` is the `id` field of the POST response, cross-checked
      against the id of a verifier run made locally from the landed tree and
      confirmed with `gh api repos/alphaonedev/ai-memory-mcp/rulesets/<id>`
      showing `name == carrier-branches-strict-checks` immediately before the
      `PUT` (the `PUT` replaces the whole ruleset body, so a wrong id would
      narrow some other ruleset; never take the id from a CI log, #6436).
   3. Re-run the promotion pull request's checks. Its verifier is now green
      (`OK`), and it merges.

   The order matters. If the promotion merges before the `PUT`, its own
   verifier run is RED (`required contexts drift: missing ['Carrier-ruleset
   live verifier (#6143)']`). Every carrier pull request stays RED the same
   way until the `PUT`. After the `PUT`, a pull request that does not yet
   contain the promotion fails its verifier (the live ruleset has one more
   context than its payload) until it updates its branch. The strict
   up-to-date rule forces that update anyway. Land the promotion on
   `rehearsal/audit-wip-ssh` too.
4. #6182 and #6143 close with the verifier output as evidence.

The freshness job is never moved into `required-contexts-release.txt`:
`check-required-contexts-live.sh` compares that file with release/v1.0.0
classic branch protection, which a carrier ruleset never reaches. Its context
is declared in `required-contexts-carrier.txt` instead, and its ledger line
says so permanently.

A context added to `required-contexts-release.txt` later must be added to
`required-contexts-carrier.txt` and the payload in the same commit (the
verifier fails otherwise), and the live carrier ruleset updated with the
`PUT` command above.

## Limits

- Advisory until required. Neither job blocks a merge until the carrier
  ruleset requires it (#6182).
- Self-judged. Under `pull_request` both jobs run the pull request's own copy
  of the script, the declaration files and the job definition (`contents:
  read`). A pull request that edits them is judged by its own edit. This is the
  #6140 class; the trusted base-copy posture tracked there must also cover
  these two jobs before their verdict is load-bearing.
- The freshness gate cannot close the window between job completion and the
  merge click. Only the ruleset's strict up-to-date rule can.
- The workflow pins are read through one fail-closed YAML-subset reader
  (`scripts/workflow_yaml_subset.py`, shared with the #5447 trigger test), not
  by regex (#6481, #6482, #6542, #6543, #6545). A construct the reader does not
  model (anchor, alias, `<<:`, tab, `---`, duplicate key, BOM, U+2028, NEL)
  makes the gate exit non-zero and name the construct and the line. The pins
  cover workflow-level `env`, `defaults` and `permissions`, `needs`, flow-style
  and quoted keys, trigger respellings, and the triggers `pull_request_target`,
  `workflow_run` and `workflow_call`.
- A run with the Actions token cannot prove `bypass_actors` is empty; the
  admin verification in step 2 above is the evidence for that field.
