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

``--json-dir DIR`` reads ``timeline.json`` (a JSON list of events) and ``runs.json``
(``{"ci.yml": [...], "coverage.yml": [...]}``) instead of calling gh, and optionally
``pr.json`` (``{"baseRefName": ...}``); this is how the unit test runs offline.
"""
import argparse
import json
import subprocess
import sys
from pathlib import Path

EX_OK, EX_REFUSE, EX_TOOL = 0, 65, 70
WORKFLOWS = ("ci.yml", "coverage.yml")
PAGE = 100
MAX_PAGES = 200


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
                    "--workflow", workflow, "--json", "databaseId,createdAt,conclusion,status"])
    if not isinstance(runs, list):
        raise ToolError("gh run list did not return a list")
    return runs


def current_base(repo, pr, json_dir):
    if json_dir:
        data = load_fixture(json_dir, "pr.json", required=False)
        return data.get("baseRefName") if isinstance(data, dict) else None
    data = gh_json(["pr", "view", str(pr), "--repo", repo, "--json", "baseRefName"])
    return data.get("baseRefName") if isinstance(data, dict) else None


def check(repo, pr, head, json_dir):
    events = fetch_timeline(repo, pr, json_dir)
    changes = [e for e in events if isinstance(e, dict) and e.get("event") == "base_ref_changed"]
    if not changes:
        print("retarget-check: no base change")
        return EX_OK
    latest = max(changes, key=lambda e: str(e.get("created_at", "")))
    stamp = str(latest.get("created_at", ""))
    if not stamp:
        raise ToolError("base_ref_changed event has no created_at")
    wanted = latest.get("current_ref")
    if wanted:
        actual = current_base(repo, pr, json_dir)
        if actual and actual != wanted:
            print(f"REFUSE: timeline base {wanted} differs from the current base {actual}; "
                  "push a new head so CI classifies against the current base (#7072, #8332)")
            return EX_REFUSE
    stale = False
    ids = []
    for workflow in WORKFLOWS:
        runs = fetch_runs(repo, head, workflow, json_dir)
        newer = [r for r in runs if isinstance(r, dict) and str(r.get("createdAt", "")) > stamp]
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
