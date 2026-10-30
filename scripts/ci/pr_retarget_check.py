#!/usr/bin/env python3
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""Refuse to land a PR whose base changed after its latest CI run (#8332, #7072).

ci.yml and coverage.yml do not list ``edited`` (a body edit would cancel the running
required checks, #8332), so a base retarget fires no run by itself. Policy: a PR whose
base changed is landed only after a new head push, because a push fires an ordinary
``pull_request`` run that classifies against the new base. This script is that check;
the landing tool calls it.

Rule: no ``base_ref_changed`` timeline event -> exit 0. Otherwise take the latest base
change time T; when BOTH ci.yml and coverage.yml have a ``pull_request``-event run on
``--head`` created after T, exit 0; else exit 65 with a REFUSE line.

Exit codes: 0 ok, 65 refuse, 70 tool error (gh failure, bad JSON, missing fixture).

decision (round 3, REVIEW-8332-code-r2 I1): the REST timeline carries no ref names (``current_ref`` is
GraphQL-only), so the old compare-against-the-current-base branch was dead and is removed; the rule
above is the whole check. A run created in the same second as the retarget is NOT newer (``>``), which
refuses: the fail-closed direction.

``--json-dir DIR`` reads ``timeline.json`` (a JSON list of events) and ``runs.json``
(``{"ci.yml": [...], "coverage.yml": [...]}``) instead of calling gh. The unit test also runs the
live path (no ``--json-dir``) through a stub ``gh`` placed first on PATH.
"""
import argparse
import json
from datetime import datetime
import os
import subprocess
import sys
from pathlib import Path

EX_OK, EX_REFUSE, EX_TOOL = 0, 65, 70
WORKFLOWS = ("ci.yml", "coverage.yml")
PAGE = 100
MAX_PAGES_DEFAULT = 200


def resolve_max_pages(raw):
    """Page cap from a raw ``PR_RETARGET_MAX_PAGES`` value; it may only LOWER the default (test hook, fails closed).

    ``int()`` accepts surrounding whitespace, so ``" 2 "`` lowers the cap to 2; kept on purpose (round 6,
    REVIEW-8332-code-r5 I1): a lowered cap only refuses sooner, and the test pins it.

    decision (round 4, REVIEW-8332-security-r3 S6): the cap branch is tested through this override
    instead of generating 20,000 events. A larger, non-positive or unparsable value is ignored, so the
    override can only make the check refuse sooner, never read past the default cap.
    """
    try:
        value = int(raw)
    except (TypeError, ValueError):
        return MAX_PAGES_DEFAULT
    return value if 1 <= value < MAX_PAGES_DEFAULT else MAX_PAGES_DEFAULT


def _max_pages():
    return resolve_max_pages(os.environ.get("PR_RETARGET_MAX_PAGES", ""))


MAX_PAGES = _max_pages()
RUN_LIMIT = 100
STAMP_FORMAT = "%Y-%m-%dT%H:%M:%SZ"


class ToolError(Exception):
    """gh or fixture input failed; the caller exits 70."""


def gh_json(args):
    try:
        proc = subprocess.run(["gh"] + args, capture_output=True, text=True, check=False)
    except OSError as exc:
        raise ToolError(f"cannot run gh: {exc}")
    if proc.returncode != 0:
        raise ToolError(f"gh {' '.join(args[:2])} failed rc={proc.returncode}: {proc.stderr.strip()[:300]}")
    try:
        return json.loads(proc.stdout)
    except ValueError as exc:
        raise ToolError(f"gh returned invalid JSON: {exc}")


def load_fixture(json_dir, name, required=True):
    path = Path(json_dir) / name
    if not path.is_file():
        if required:
            raise ToolError(f"fixture missing: {name}")
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except ValueError as exc:
        raise ToolError(f"fixture {name} is not JSON: {exc}")


def fetch_timeline(repo, pr, json_dir):
    if json_dir:
        events = load_fixture(json_dir, "timeline.json")
        if not isinstance(events, list):
            raise ToolError("timeline.json must be a list")
        return events
    events = []
    for page in range(1, MAX_PAGES + 1):
        chunk = gh_json(["api", f"repos/{repo}/issues/{pr}/timeline?per_page={PAGE}&page={page}"])
        if not isinstance(chunk, list):
            raise ToolError("timeline page is not a list")
        events.extend(chunk)
        if len(chunk) < PAGE:
            return events
    raise ToolError("timeline exceeds the page cap")


def fetch_runs(repo, head, workflow, json_dir):
    if json_dir:
        data = load_fixture(json_dir, "runs.json")
        runs = data.get(workflow) if isinstance(data, dict) else None
        if not isinstance(runs, list):
            raise ToolError(f"runs.json has no list for {workflow}")
        return runs
    runs = gh_json(["run", "list", "--repo", repo, "--commit", head, "--event", "pull_request",
                    "--workflow", workflow, "--limit", str(RUN_LIMIT), "--json", "databaseId,createdAt,conclusion,status"])
    if not isinstance(runs, list):
        raise ToolError("gh run list did not return a list")
    return runs


def parse_stamp(raw, what):
    """A GitHub ISO-8601 UTC stamp as a datetime; anything else is a ToolError (exit 70).

    decision (round 6, REVIEW-8332-code-r5 F2, REVIEW-8332-security-r5 S11): stamps are parsed and
    compared as datetimes, never as strings, so a padded or space-separated stamp cannot sort below a
    canonical one and be ignored. An unparsable stamp refuses; it is never skipped.
    """
    if not isinstance(raw, str) or not raw:
        raise ToolError(f"{what} has no created_at")
    try:
        return datetime.strptime(raw, STAMP_FORMAT)
    except ValueError:
        raise ToolError(f"{what} has an unparsable created_at {raw!r}")


def check(repo, pr, head, json_dir):
    events = fetch_timeline(repo, pr, json_dir)
    changes = [e for e in events if isinstance(e, dict) and e.get("event") == "base_ref_changed"]
    if not changes:
        print("retarget-check: no base change")
        return EX_OK
    # decision (round 5, REVIEW-8332-code-r4 F1, REVIEW-8332-security-r4 S8): ANY base change without a
    # usable created_at refuses (exit 70); dropping it would compare the runs against an older retarget.
    latest = max(parse_stamp(e.get("created_at"), "base_ref_changed event") for e in changes)
    stamp = latest.strftime(STAMP_FORMAT)
    stale = False
    ids = []
    for workflow in WORKFLOWS:
        runs = [r for r in fetch_runs(repo, head, workflow, json_dir) if isinstance(r, dict)]
        newer = [r for r in runs if parse_stamp(r.get("createdAt"), f"{workflow} run") > latest]
        if not newer:
            print(f"REFUSE: base retargeted at {stamp} after the latest pull_request run of {workflow}; "
                  "push a new head so CI classifies against the current base (#7072, #8332)")
            stale = True
        else:
            ids.append(f"{workflow}={','.join(str(r.get('databaseId')) for r in newer)}")
    if stale:
        return EX_REFUSE
    print(f"retarget-check: base changed at {stamp}; newer runs: {' '.join(ids)}")
    return EX_OK


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--repo", required=True)
    ap.add_argument("--pr", required=True, type=int)
    ap.add_argument("--head", required=True)
    ap.add_argument("--json-dir", default=None, help="fixture directory instead of gh")
    args = ap.parse_args(argv)
    try:
        return check(args.repo, args.pr, args.head, args.json_dir)
    except ToolError as exc:
        print(f"retarget-check: tool error: {exc}", file=sys.stderr)
        return EX_TOOL


if __name__ == "__main__":
    sys.exit(main())
