# Promotion geometry (#3872)

Before using cut-only landing evidence to promote a candidate to `release/v1.0.0`,
the candidate must contain every commit of the pinned release base:

```sh
git fetch origin
bash scripts/check-promotion-geometry.sh
# Or measure an explicitly pinned cut:
bash scripts/check-promotion-geometry.sh --base refs/remotes/origin/release/v1.0.0 --head <candidate-sha>
bash scripts/check-promotion-geometry.sh --self-test
```

The default base is the fully qualified `refs/remotes/origin/release/v1.0.0`,
so a similarly named local branch cannot shadow it; ambiguous explicit refs fail.
The self-test creates disposable repositories under this checkout’s `.local-runs/`,
never the system temporary directory; on f1 the checkout and scratch live on f1dev.
The check reports both resolved SHAs and AHEAD/BEHIND counts. AHEAD is harmless;
BEHIND must be zero. When base is an ancestor of candidate, the merge tree equals
the candidate tree. A missing base commit refuses promotion even when a merge
would be conflict-free or the commits happen to have equivalent trees. Integrate
the base through the ordinary reviewed/signed process, then remeasure the new
candidate. This check does not merge or modify either branch.

The existing required-context/classify-base soundness job in `c8-precheck.yml`
runs this check with full history. On a PR targeting `release/v1.0.0`, it selects
the event's **original head SHA and base SHA**, never the synthetic merge checkout
or `GITHUB_SHA`. Other events and PR base branches report `INAPPLICABLE`; the
self-test still runs. Exit codes are 0 (PASS or explicit INAPPLICABLE), 1 (BEHIND),
and 2 (cannot prove, including shallow history or missing objects). Replacement
objects cannot alter the proof; legacy grafts are refused.

The external landing-chain driver is not in this repository. Its operator must
run the local check before relying on a cut table; the required CI step enforces
the same ancestry precondition at promotion. This implements the conservative
zero-BEHIND alternative recorded in #3872, not the synthetic-two-tree wrapper.
The check does not fetch, continuously watch a moving base, test the code, or
replace required PR CI. A later base update requires refreshed promotion checks;
strict base-up-to-date branch protection remains part of that enforcement.
