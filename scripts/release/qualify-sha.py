#!/usr/bin/env python3
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""qualify-sha.py — refuse to release a commit that CI did not qualify (#3546).

Before #3546 nothing in release.yml looked at CI results for the SHA being
released: any tag on any commit built and published. This script asks the
GitHub API what actually ran on that exact commit and refuses unless every
context declared in scripts/qc-allowlists/required-contexts-release.txt
passed. The verdict rules, fail-closed throughout:

  * A declared context with no check-run on the SHA refuses (missing).
  * Only a COMPLETED run with conclusion `success` counts. `skipped`,
    `neutral`, `cancelled`, `timed_out`, `action_required`, `failure` and
    `stale` never count as success. Branch protection treats `skipped` as
    satisfied; a release does not, because the docs-only classifier that
    produces `skipped` has already been wrong once (#2496).
  * Within one workflow run only the LATEST attempt counts, so an old
    success cannot mask a re-run that failed.
  * Across runs (push event, pull_request event, a manual re-dispatch), a
    `skipped` run neither passes nor vetoes; any latest-attempt failure
    vetoes. So a docs-only push run on the same SHA cannot hide a full run
    that succeeded, and a full run that failed cannot be hidden by a
    success elsewhere.
  * Attribution: a check-run counts only when it was created by the GitHub
    Actions app AND its check suite belongs to a workflow run whose file is
    one of the gating workflows (the COVERED_WORKFLOWS of
    scripts/check-required-contexts.sh). Any workflow holding
    `checks: write` can post a check-run with any name; one posted outside
    a gating workflow run is ignored, never counted.
  * Pagination is explicit (per_page=100, walked until a short page), so a
    required context on page two is seen, and a truncated read cannot pass.

Modes:
  --fetch --repo OWNER/NAME --sha SHA      query the API through `gh api`
  --check-runs FILE --workflow-runs FILE   evaluate canned JSON (fixtures)
Common: --contexts FILE and one of
  --carriers "ci.yml c8-precheck.yml ..."   explicit carrier workflow files
  --carriers-from scripts/check-required-contexts.sh
                                          read COVERED_WORKFLOWS from the gate,
                                          so the two can never disagree

Exit codes: 0 qualified · 1 refused · 2 usage / API error (also a refusal).
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys

GITHUB_ACTIONS_APP_SLUG = "github-actions"
GITHUB_ACTIONS_APP_ID = 15368
PAGE_SIZE = 100
SUCCESS = "success"
COMPLETED = "completed"
# Conclusions that are neither a pass nor a failure: they cannot satisfy a
# context, and they cannot veto a success from another run either.
NON_VETO = {"skipped", "neutral"}


COVERED_RE = re.compile(r'^COVERED_WORKFLOWS="\$\{RQC_COVERED_WORKFLOWS:-([^}]*)\}"', re.M)


def carriers_from_gate(path: str) -> set[str]:
    """COVERED_WORKFLOWS from check-required-contexts.sh (no second SSOT)."""
    with open(path, encoding="utf-8") as fh:
        match = COVERED_RE.search(fh.read())
    if not match:
        raise SystemExit(f"qualify-sha: REFUSED — no COVERED_WORKFLOWS default found in {path} (fail-closed)")
    return set(match.group(1).split())


def load_contexts(path: str) -> list[str]:
    contexts = []
    with open(path, encoding="utf-8") as fh:
        for raw in fh:
            line = raw.strip()
            if line and not line.startswith("#"):
                contexts.append(line)
    if not contexts:
        raise SystemExit(f"qualify-sha: REFUSED — {path} declares zero required contexts (fail-closed)")
    return contexts


def gh_pages(endpoint: str, key: str) -> list[dict]:
    """Walk `gh api` pages explicitly until a short page."""
    items: list[dict] = []
    page = 1
    while True:
        sep = "&" if "?" in endpoint else "?"
        url = f"{endpoint}{sep}per_page={PAGE_SIZE}&page={page}"
        proc = subprocess.run(["gh", "api", url], capture_output=True, text=True, check=False)
        if proc.returncode != 0:
            print(f"qualify-sha: REFUSED — gh api {url} failed: {proc.stderr.strip()}", file=sys.stderr)
            raise SystemExit(2)
        batch = json.loads(proc.stdout).get(key, [])
        items.extend(batch)
        if len(batch) < PAGE_SIZE:
            return items
        page += 1


def evaluate(contexts, check_runs, workflow_runs, carriers, sha):
    """Return (ok, rows, ignored): rows are (context, verdict, detail)."""
    suite_to_run = {}
    for run in workflow_runs:
        if run.get("head_sha") and run["head_sha"] != sha:
            continue
        path = run.get("path", "")
        wf_file = path.rsplit("/", 1)[-1]
        suite_to_run[run.get("check_suite_id")] = (wf_file, run.get("event", ""), run.get("id"))

    # context -> {check_suite_id: (attempt order, conclusion, run)}; one entry
    # per workflow run, holding that run's latest attempt only.
    per_context: dict[str, dict] = {c: {} for c in contexts}
    ignored = 0
    for cr in check_runs:
        name = cr.get("name")
        if name not in per_context:
            continue
        if cr.get("head_sha") and cr["head_sha"] != sha:
            ignored += 1
            continue
        app = cr.get("app") or {}
        if app.get("slug") != GITHUB_ACTIONS_APP_SLUG or app.get("id") != GITHUB_ACTIONS_APP_ID:
            ignored += 1
            continue
        suite_id = (cr.get("check_suite") or {}).get("id")
        run = suite_to_run.get(suite_id)
        if run is None or run[0] not in carriers:
            ignored += 1
            continue
        # Latest attempt within one workflow run wins; ties broken by id.
        order = (cr.get("started_at") or "", cr.get("id") or 0)
        prev = per_context[name].get(suite_id)
        if prev is None or order > prev[0]:
            status = cr.get("status")
            conclusion = cr.get("conclusion") if status == COMPLETED else f"incomplete:{status}"
            per_context[name][suite_id] = (order, conclusion, run)

    rows = []
    ok = True
    for ctx in contexts:
        latest = [v[1] for v in per_context[ctx].values()]
        successes = sum(1 for c in latest if c == SUCCESS)
        vetoes = [c for c in latest if c != SUCCESS and c not in NON_VETO]
        if not latest:
            rows.append((ctx, "REFUSE", "no check-run from a gating workflow on this SHA"))
            ok = False
        elif vetoes:
            rows.append((ctx, "REFUSE", f"latest attempt not successful: {', '.join(sorted(set(vetoes)))}"))
            ok = False
        elif successes == 0:
            rows.append((ctx, "REFUSE", f"only {', '.join(sorted(set(latest)))} — never ran to success on this SHA"))
            ok = False
        else:
            rows.append((ctx, "PASS", f"{successes} successful run(s)"))
    return ok, rows, ignored


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--contexts", required=True)
    carrier_src = ap.add_mutually_exclusive_group(required=True)
    carrier_src.add_argument("--carriers")
    carrier_src.add_argument("--carriers-from")
    ap.add_argument("--sha", required=True)
    ap.add_argument("--fetch", action="store_true")
    ap.add_argument("--repo")
    ap.add_argument("--check-runs")
    ap.add_argument("--workflow-runs")
    args = ap.parse_args()

    carriers = carriers_from_gate(args.carriers_from) if args.carriers_from else set(args.carriers.split())
    if not carriers:
        print("qualify-sha: REFUSED — empty carrier workflow set (fail-closed)", file=sys.stderr)
        return 2
    contexts = load_contexts(args.contexts)

    if args.fetch:
        if not args.repo:
            ap.error("--fetch needs --repo")
        check_runs = gh_pages(f"repos/{args.repo}/commits/{args.sha}/check-runs?filter=all", "check_runs")
        workflow_runs = gh_pages(f"repos/{args.repo}/actions/runs?head_sha={args.sha}", "workflow_runs")
    else:
        if not (args.check_runs and args.workflow_runs):
            ap.error("give --fetch or both --check-runs and --workflow-runs")
        with open(args.check_runs, encoding="utf-8") as fh:
            check_runs = json.load(fh).get("check_runs", [])
        with open(args.workflow_runs, encoding="utf-8") as fh:
            workflow_runs = json.load(fh).get("workflow_runs", [])

    ok, rows, ignored = evaluate(contexts, check_runs, workflow_runs, carriers, args.sha)
    width = max(len(r[0]) for r in rows)
    print(f"qualify-sha: {args.sha} against {len(contexts)} declared context(s); {ignored} check-run(s) ignored (wrong app, SHA or carrier)")
    for ctx, verdict, detail in rows:
        print(f"  {verdict:6}  {ctx:<{width}}  {detail}")
    if not ok:
        print(
            "qualify-sha: REFUSED — this commit was not qualified by CI. Pushing the tag starts a full "
            "ci.yml run on this SHA (a new tag ref has no base, so classify runs everything). While the "
            "release branch tip is this SHA, coverage.yml, cert-postgres-age.yml and postgres-ignored.yml "
            "can be dispatched with `gh workflow run <file> --ref <release branch>`; a dispatch also "
            "classifies docs_only=false. Re-run any failed workflow, then re-dispatch the release.",
            file=sys.stderr,
        )
        return 1
    print("qualify-sha: OK — every declared required context succeeded on this SHA")
    return 0


if __name__ == "__main__":
    sys.exit(main())
