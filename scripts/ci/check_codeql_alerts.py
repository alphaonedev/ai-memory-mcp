#!/usr/bin/env python3
"""Fail closed unless CodeQL clearance is correlated with an exact open PR head.

Python 3.9+ and authenticated gh are sufficient. All requests are read-only.
The language/check/category contract follows .github/workflows/codeql-rust.yml.
"""

import argparse
from datetime import datetime
import json
from pathlib import Path
import re
import subprocess
import sys
from urllib.parse import urlencode


PAGE_SIZE = 100
MAX_PAGES = 100
API_TIMEOUT_SECONDS = 60
MAX_RESPONSE_CHARS = 16 * 1024 * 1024
MAX_ERROR_CHARS = 2000
LANGUAGES = ("rust", "javascript-typescript", "python", "actions")
ANALYSIS_KEY = ".github/workflows/codeql-rust.yml:analyze"
AGGREGATE_NAME = "CodeQL"
AGGREGATE_APP = "github-advanced-security"
JOB_APP = "github-actions"
CLEAR_TITLES = frozenset(("No new alerts",
                          "No new alerts in code changed by this pull request"))
SHA_PATTERN = re.compile(r"[0-9a-f]{40}")
REPO_PATTERN = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+")


class GateError(Exception):
    """Clearance could not be established; callers must not treat this as green."""


def require(condition, message):
    """Turn malformed or uncleared inputs into an explicit refusal."""
    if not condition:
        raise GateError(message)


def field(value, key, kind):
    """Read required JSON fields without accepting booleans as integer counts."""
    require(isinstance(value, dict), "malformed API object")
    result = value.get(key)
    require(type(result) is kind, "missing or malformed " + key)
    return result


def stamp(value, key):
    """Parse required timezone-aware GitHub timestamps."""
    raw = field(value, key, str)
    try:
        result = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError as error:
        raise GateError("malformed " + key) from error
    require(result.tzinfo is not None, "missing timezone in " + key)
    return result


def json_object(pairs):
    """Reject ambiguous duplicate fields rather than choosing a clearance value."""
    result = {}
    for key, value in pairs:
        require(key not in result, "duplicate API JSON field: " + key)
        result[key] = value
    return result


def invalid_constant(value):
    """NaN and Infinity are not JSON values."""
    raise GateError("invalid API JSON constant: " + value)


class GhApi:
    """Bound each gh GET, retain its diagnostic on failure, never invoke a shell."""

    def __init__(self, cwd):
        self.cwd = Path(cwd).resolve()

    def __call__(self, endpoint):
        try:
            result = subprocess.run(
                ["gh", "api", "--method", "GET", endpoint], cwd=self.cwd,
                stdin=subprocess.DEVNULL, capture_output=True, text=True,
                timeout=API_TIMEOUT_SECONDS, check=False,
            )
        except (OSError, UnicodeError, subprocess.TimeoutExpired) as error:
            raise GateError("gh API request failed: " + str(error)) from error
        require(result.returncode == 0,
                "gh API request failed (exit " + str(result.returncode) + "): "
                + result.stderr[:MAX_ERROR_CHARS].strip())
        require(len(result.stdout) <= MAX_RESPONSE_CHARS, "API response exceeds bound")
        try:
            return json.loads(result.stdout, object_pairs_hook=json_object,
                              parse_constant=invalid_constant)
        except (ValueError, RecursionError) as error:
            raise GateError("malformed API JSON for " + endpoint) from error


def pages(api, endpoint, params=None, key=None):
    """Enumerate explicit pages, compatible with gh versions lacking --slurp."""
    collected = []
    expected_total = None
    for page in range(1, MAX_PAGES + 1):
        query = {"page": page, "per_page": PAGE_SIZE, **(params or {})}
        response = api(endpoint + "?" + urlencode(query))
        if key is not None:
            total = field(response, "total_count", int)
            require(total >= 0, "malformed total_count")
            require(expected_total is None or total == expected_total,
                    "paginated check count changed")
            expected_total = total
            batch = field(response, key, list)
        else:
            batch = response
        require(type(batch) is list and len(batch) <= PAGE_SIZE,
                "malformed API page")
        require(all(isinstance(item, dict) for item in batch), "malformed API row")
        collected.extend(batch)
        if len(batch) < PAGE_SIZE:
            require(expected_total is None or len(collected) == expected_total,
                    "incomplete check pagination")
            return collected
    raise GateError("API pagination exceeds bound")


def completed(check, head):
    """A successful workflow is necessary but not sufficient for clearance."""
    require(field(check, "head_sha", str) == head, "check head mismatch")
    require(field(check, "status", str) == "completed"
            and field(check, "conclusion", str) == "success",
            "check must be completed with success")
    start = stamp(check, "started_at")
    end = stamp(check, "completed_at")
    require(start <= end, "invalid check time interval")
    return start, end


def aggregate(check, head, check_id):
    """Validate the actual code-scanning aggregate, not an Actions job."""
    require(field(check, "id", int) == check_id, "aggregate check id mismatch")
    require(field(check, "name", str) == AGGREGATE_NAME
            and field(field(check, "app", dict), "slug", str) == AGGREGATE_APP,
            "wrong aggregate check identity")
    completed(check, head)
    output = field(check, "output", dict)
    require(field(output, "title", str) in CLEAR_TITLES,
            "aggregate title must be No new alerts")
    require(field(output, "annotations_count", int) == 0,
            "aggregate annotations must be integer zero")


def checks(api, prefix, head, check_id):
    """Require latest aggregate and every configured language job to be green."""
    rows = pages(api, prefix + "commits/" + head + "/check-runs",
                 {"filter": "latest"}, "check_runs")
    selected = {}
    for name in (AGGREGATE_NAME,) + tuple("CodeQL analysis (" + lang + ")"
                                         for lang in LANGUAGES):
        matching = [row for row in rows if field(row, "name", str) == name]
        require(len(matching) == 1, "missing or ambiguous check: " + name)
        check = matching[0]
        if name == AGGREGATE_NAME:
            aggregate(check, head, check_id)
        else:
            require(field(field(check, "app", dict), "slug", str) == JOB_APP,
                    "wrong analysis job identity")
            completed(check, head)
            require(field(check, "id", int) > 0, "invalid job id")
        selected[name] = check
    return selected


def pr_state(value, pr, head):
    """Snapshot only the PR identity fields relevant to clearance."""
    require(field(value, "number", int) == pr, "PR number mismatch")
    require(field(value, "state", str) == "open", "PR must be open")
    current_head = field(field(value, "head", dict), "sha", str)
    require(current_head == head, "PR head mismatch")
    base = field(field(value, "base", dict), "sha", str)
    merge = field(value, "merge_commit_sha", str)
    require(SHA_PATTERN.fullmatch(base) and SHA_PATTERN.fullmatch(merge),
            "missing or malformed current base/merge commit")
    return current_head, base, merge


def analyses(api, prefix, ref, commit, jobs, required):
    """Use newest analysis per category; historical alerts never prove coverage."""
    rows = pages(api, prefix + "code-scanning/analyses",
                 {"ref": ref, "tool_name": AGGREGATE_NAME})
    latest = {}
    for row in rows:
        require(field(row, "ref", str) == ref, "analysis ref mismatch")
        require(field(field(row, "tool", dict), "name", str) == AGGREGATE_NAME,
                "analysis tool mismatch")
        require(field(row, "analysis_key", str) == ANALYSIS_KEY,
                "unexpected analysis workflow; reconcile configured coverage")
        category = field(row, "category", str)
        require(category in {"/language:" + lang for lang in LANGUAGES},
                "unexpected analysis category; reconcile configured coverage")
        rank = (stamp(row, "created_at"), field(row, "id", int))
        if category not in latest or rank > latest[category][0]:
            latest[category] = (rank, row)
    if required:
        require(len(latest) == len(LANGUAGES), "missing current merge analysis coverage")
    for category, (_, row) in latest.items():
        require(field(row, "commit_sha", str) == commit, "stale analysis on " + ref)
        require(field(row, "error", str) == "" and field(row, "warning", str) == "",
                "analysis error/warning on " + ref)
        language = category.removeprefix("/language:")
        start, end = completed(jobs["CodeQL analysis (" + language + ")"],
                               field(jobs[AGGREGATE_NAME], "head_sha", str))
        require(start <= stamp(row, "created_at") <= end,
                "analysis is outside current job interval on " + ref)


def check_clearance(api, repo, pr, head, check_id):
    """Read both refs and recheck PR/jobs before returning snapshot clearance."""
    require(REPO_PATTERN.fullmatch(repo) is not None, "invalid repository")
    require(SHA_PATTERN.fullmatch(head) is not None, "expected exact lowercase head SHA")
    require(type(pr) is int and pr > 0 and type(check_id) is int and check_id > 0,
            "PR and check id must be positive integers")
    prefix = "repos/" + repo + "/"
    pull_endpoint = prefix + "pulls/" + str(pr)
    state = pr_state(api(pull_endpoint), pr, head)
    _, base, merge = state
    aggregate(api(prefix + "check-runs/" + str(check_id)), head, check_id)
    jobs = checks(api, prefix, head, check_id)
    commit = api(prefix + "commits/" + merge)
    require(field(commit, "sha", str) == merge, "merge commit mismatch")
    parents = field(commit, "parents", list)
    require([field(parent, "sha", str) for parent in parents] == [base, head],
            "merge parents do not match current base and expected head")
    for suffix, sha in (("head", head), ("merge", merge)):
        ref = "refs/pull/" + str(pr) + "/" + suffix
        alerts = pages(api, prefix + "code-scanning/alerts",
                       {"ref": ref, "state": "open", "tool_name": AGGREGATE_NAME})
        require(not alerts, "open alerts on " + ref)
        analyses(api, prefix, ref, sha, jobs, required=suffix == "merge")
    require(pr_state(api(pull_endpoint), pr, head) == state,
            "PR base/merge changed during clearance read")
    require(checks(api, prefix, head, check_id) == jobs,
            "CodeQL checks changed during clearance read")


def main(argv=None):
    """Exit zero only for a complete, correlated clearance snapshot."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("check_run_id", type=int, help="aggregate CodeQL check id")
    parser.add_argument("--repo", required=True, help="GitHub OWNER/REPO")
    parser.add_argument("--pr", required=True, type=int, help="open PR number")
    parser.add_argument("--head", required=True, help="expected full PR head SHA")
    args = parser.parse_args(argv)
    try:
        check_clearance(GhApi(Path.cwd()), args.repo, args.pr, args.head, args.check_run_id)
    except GateError as error:
        print("CodeQL clearance refused: " + str(error), file=sys.stderr)
        return 1
    print("CodeQL clear: head " + args.head
          + "; No new alerts; annotations=0; open alerts=0 on head and merge; "
          + "current merge analyses=" + str(len(LANGUAGES)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
