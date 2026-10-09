# Carrier-branch gates (#6143)

`chain/**` and `rehearsal/**` are `pull_request` base branches of the gating
workflows (for example `.github/workflows/c8-precheck.yml`). GitHub does not
re-run `pull_request` workflows when the base branch moves, so a green gate is
a verdict on the merge ref as it was built. On a base with no up-to-date-head
rule, a pull request can merge after the base moved without any gate judging
the tree that actually lands (#6143, found in the #6137/#6138 review).

## Repo-side control (this change)

`Carrier-base freshness gate (#6143)` (job `carrier-base-fresh-gate`,
`scripts/check_carrier_base_fresh.py`) fails closed when the merge commit the
job checked out is not built on the live tip of the carrier base. It fetches
the tip on every run, so re-running a stale green turns it red. Remedy printed
by the gate: `gh pr update-branch <PR>`, then wait for the new run.

It cannot close the window between job completion and the merge action; only a
ruleset with strict required status checks can.

## Ruleset the repository settings must carry (settings change, relayed)

A branch ruleset, enforcement `active`, separate from `signed-attested-branches`
(17752665), with:

- target `refs/heads/chain/**` and `refs/heads/rehearsal/**`;
- `required_status_checks` listing at least
  `Enterprise-federation cert-expiry gate (cert §7 / F7)` and
  `Carrier-base freshness gate (#6143)`, plus the carrier-applicable contexts
  in `scripts/qc-allowlists/required-contexts-release.txt`;
- `strict_required_status_checks_policy: true` (up-to-date head required).

Landing order follows the #3554 lockstep: ruleset first, then
`bash scripts/check-required-contexts-live.sh --pin-from-live`, then move the
job name from `required-contexts-not-required.txt` into
`required-contexts-release.txt` in the same commit as the pin.

Until the ruleset exists, the landing step must refuse a pull request whose
`mergeStateStatus` is `BEHIND` and run `gh pr update-branch` first.

## Verifying the live ruleset (read-only)

`python3 -I scripts/check_carrier_ruleset_live.py` reads the live rulesets
(never writes) and fails closed unless an active branch ruleset covers both
carrier patterns with strict required status checks and the contexts above. It
is not wired into pull-request CI while the ruleset does not exist (it would
fail every PR); run it after the ruleset is applied, then wire it.
