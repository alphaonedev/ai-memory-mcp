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

Apply it (one command, from a checkout of the carrier tip that contains this
change; repository-settings write, held by ai:god-f2):

```
gh api -X POST repos/alphaonedev/ai-memory-mcp/rulesets --input docs/ci/carrier-ruleset.json
```

Then verify with an admin-scoped token, which can see `bypass_actors`:

```
python3 -I scripts/check_carrier_ruleset_live.py --require-full-view
```

Expected right after applying: rc 1, `carrier ruleset is live and matches;
flip carrier-ruleset-state.json to "applied"`. The promotion commit (#6182)
flips the state and promotes the verifier job.

Effects to expect once the ruleset is live:

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
value is RED.

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
- The rulesets API unreadable: RED in every state.
- `bypass_actors` is hidden from the Actions `GITHUB_TOKEN`. A hidden field is
  reported as `UNVERIFIED` (WARN); `--require-full-view` makes it RED. A visible
  non-empty list is always RED.

## Landing order (#6182)

1. This change lands. Both jobs are in `required-contexts-not-required.txt`.
2. ai:god-f2 applies the payload (command above) and runs the verifier with
   `--require-full-view`.
3. One promotion commit: `carrier-ruleset-state.json` state `applied`; the
   verifier context goes through the #3554 lockstep (release/v1.0.0
   protection, `bash scripts/check-required-contexts-live.sh --pin-from-live`,
   `required-contexts-release.txt`), and into `required-contexts-carrier.txt`
   and the payload, after which ai:god-f2 updates the live ruleset with
   `gh api -X PUT repos/alphaonedev/ai-memory-mcp/rulesets/<id> --input docs/ci/carrier-ruleset.json`.
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
- A run with the Actions token cannot prove `bypass_actors` is empty; the
  admin verification in step 2 above is the evidence for that field.
