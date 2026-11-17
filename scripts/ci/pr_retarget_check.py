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
import re
import subprocess
import sys
from pathlib import Path


def _load_workflow_annotation():
    """The shared module at WA_RELATIVE_PATH from this file's real directory, by path only, never through
    sys.path; every name in WA_REQUIRED must be a callable of it (#9365, one shape in every script)."""
    import importlib.util
    import os
    path = os.path.normpath(os.path.join(os.path.dirname(os.path.realpath(__file__)), WA_RELATIVE_PATH))
    loaded = sys.modules.get("workflow_annotation")
    if loaded is not None and os.path.realpath(getattr(loaded, "__file__", None) or "") == path:
        module = loaded
    else:
        spec = importlib.util.spec_from_file_location("workflow_annotation", path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)  # absent, unreadable or broken: it raises here, the try below catches it
    missing = [name for name in WA_REQUIRED if not callable(getattr(module, name, None))]
    if missing:
        raise AttributeError("workflow_annotation.py lacks " + ", ".join(missing))
    if loaded is None:
        sys.modules["workflow_annotation"] = module
    return module


# The one shared-module load shape of scripts/ (#9365, ruling bcd0a15c; LoaderShape pins it).
WA_PROG = "pr_retarget_check"
WA_RELATIVE_PATH = "workflow_annotation.py"
WA_REQUIRED = ("err", "out")
WA_EXIT_LOAD_REFUSED = 3  # a failed shared-module load; no other meaning in this script
WA_ERROR_TO_STDERR = False

try:
    wa = _load_workflow_annotation()
except (Exception, SystemExit) as exc:  # any failed load: one fixed line built without the module, then exit
    wa_cause = type(exc).__name__
    print("%s: refused: shared module workflow_annotation.py next to the script cannot be loaded (%s)"
          % (WA_PROG, wa_cause if wa_cause.isidentifier() else "BaseException"), file=sys.stderr, flush=True)
    print("::error title=pr_retarget_check refused::pr_retarget_check: refused: shared module workflow_annotation.py"
          " next to the script cannot be loaded",
          file=sys.stderr if WA_ERROR_TO_STDERR else sys.stdout, flush=True)
    sys.exit(WA_EXIT_LOAD_REFUSED)

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
STAMP_RE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z")


class ToolError(Exception):
    """gh or fixture input failed; the caller exits 70."""


def gh_json(args):
    try:
        proc = subprocess.run(["gh"] + args, capture_output=True, text=True, check=False)
    except OSError as exc:
        raise ToolError(f"cannot run gh: {exc}") from exc
    if proc.returncode != 0:
        raise ToolError(f"gh {' '.join(args[:2])} failed rc={proc.returncode}: {proc.stderr.strip()[:300]}")
    try:
        return json.loads(proc.stdout)
    except ValueError as exc:
        raise ToolError(f"gh returned invalid JSON: {exc}") from exc


def load_fixture(json_dir, name, required=True):
    path = Path(json_dir) / name
    if not path.is_file():
        if required:
            raise ToolError(f"fixture missing: {name}")
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except ValueError as exc:
        raise ToolError(f"fixture {name} is not JSON: {exc}") from exc


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

    decision (round 7, REVIEW-8332-code-r6 INFO-1, REVIEW-8332-security-r6 INFO): ``strptime`` alone
    accepts a lowercase ``t``/``z``, single-digit fields and non-ASCII digits, so the exact GitHub shape
    is checked first (ASCII digits, a full match); anything else refuses. A non-string value is named
    by its kind instead of being reported as missing.
    """
    if raw is None or raw == "":
        raise ToolError(f"{what} has no created_at")
    if not isinstance(raw, str):
        raise ToolError(f"{what} has a created_at of kind {type(raw).__name__}, not a string")
    if not STAMP_RE.fullmatch(raw):
        raise ToolError(f"{what} has an unparsable created_at {raw!r}")
    try:
        return datetime.strptime(raw, STAMP_FORMAT)
    except ValueError as exc:
        raise ToolError(f"{what} has an unparsable created_at {raw!r}") from exc


def check(repo, pr, head, json_dir):
    events = fetch_timeline(repo, pr, json_dir)
    changes = [e for e in events if isinstance(e, dict) and e.get("event") == "base_ref_changed"]
    if not changes:
        wa.out("retarget-check: no base change")
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
            wa.out(f"REFUSE: base retargeted at {stamp} after the latest pull_request run of {workflow}; "
                  "push a new head so CI classifies against the current base (#7072, #8332)")
            stale = True
        else:
            ids.append(f"{workflow}={','.join(str(r.get('databaseId')) for r in newer)}")
    if stale:
        return EX_REFUSE
    wa.out(f"retarget-check: base changed at {stamp}; newer runs: {' '.join(ids)}")
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
        wa.err(f"retarget-check: tool error: {exc}")
        return EX_TOOL


if __name__ == "__main__":
    sys.exit(main())
