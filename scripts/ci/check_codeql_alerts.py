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
WORKFLOW_PATH = ".github/workflows/codeql-rust.yml"
WORKFLOW_FILE = "codeql-rust.yml"
API_ROOT = "https://api.github.com/"
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


def positive(value, key):
    """Require positive GitHub identifiers, ordinals and attempt numbers."""
    result = field(value, key, int)
    require(result > 0, "invalid " + key)
    return result


def workflow_identity(run, workflow_id, head):
    """Check workflow ownership before using its monotonic run number."""
    require(field(run, "workflow_id", int) == workflow_id
            and field(run, "path", str) == WORKFLOW_PATH
            and field(run, "event", str) == "pull_request"
            and field(run, "head_sha", str) == head, "workflow identity mismatch")
    for key in ("id", "run_number", "run_attempt", "check_suite_id"):
        positive(run, key)
    pulls = field(run, "pull_requests", list)
    require(pulls, "missing workflow PR ownership")
    numbers = []
    for pull in pulls:
        numbers.append(positive(pull, "number"))
        require(field(field(pull, "head", dict), "sha", str) == head,
                "workflow PR head mismatch")
    require(len(set(numbers)) == len(numbers), "ambiguous workflow PR ownership")
    return numbers


def workflow_snapshot(run, workflow_id, head, pr):
    """Snapshot current execution, including queued attempts with no jobs yet."""
    require(pr in workflow_identity(run, workflow_id, head), "workflow PR mismatch")
    require(field(run, "status", str) == "completed"
            and field(run, "conclusion", str) == "success",
            "current workflow attempt must be completed with success")
    start, end = stamp(run, "run_started_at"), stamp(run, "updated_at")
    require(stamp(run, "created_at") <= start <= end, "invalid workflow interval")
    keys = ("id", "workflow_id", "path", "event", "head_sha", "run_number",
            "run_attempt", "check_suite_id", "status", "conclusion",
            "created_at", "run_started_at", "updated_at")
    return {key: run[key] for key in keys}


def current_workflow(api, prefix, head, pr):
    """Resolve the latest PR run and its exact current attempt, never a green fallback."""
    workflow = api(prefix + "actions/workflows/" + WORKFLOW_FILE)
    require(field(workflow, "path", str) == WORKFLOW_PATH, "wrong workflow path")
    workflow_id = positive(workflow, "id")
    runs = pages(api, prefix + "actions/workflows/" + str(workflow_id) + "/runs",
                 {"head_sha": head, "event": "pull_request"}, "workflow_runs")
    applicable = [run for run in runs
                  if pr in workflow_identity(run, workflow_id, head)]
    require(applicable, "missing current workflow run")
    require(len({run["run_number"] for run in applicable}) == len(applicable)
            and len({run["id"] for run in applicable}) == len(applicable),
            "ambiguous workflow runs")
    # run_number increases for each new run of this authenticated workflow;
    # run_attempt increases within a run. Check IDs and timestamps do not rank runs.
    run = max(applicable, key=lambda item: item["run_number"])
    snapshot = workflow_snapshot(run, workflow_id, head, pr)
    endpoint = prefix + "actions/runs/" + str(run["id"])
    require(workflow_snapshot(api(endpoint), workflow_id, head, pr) == snapshot,
            "workflow changed during clearance read")
    attempt_endpoint = endpoint + "/attempts/" + str(run["run_attempt"])
    require(workflow_snapshot(api(attempt_endpoint), workflow_id, head, pr) == snapshot,
            "workflow attempt mismatch")
    jobs = pages(api, attempt_endpoint + "/jobs", key="jobs")
    return snapshot, jobs


def checks(api, prefix, head, check_id, pr):
    """Require the aggregate and language checks owned by the current workflow attempt."""
    rows = pages(api, prefix + "commits/" + head + "/check-runs",
                 {"filter": "latest"}, "check_runs")
    aggregates = [row for row in rows if field(row, "name", str) == AGGREGATE_NAME]
    require(len(aggregates) == 1, "missing or ambiguous check: " + AGGREGATE_NAME)
    aggregate(aggregates[0], head, check_id)
    run, jobs = current_workflow(api, prefix, head, pr)
    selected = {AGGREGATE_NAME: aggregates[0], "workflow_run": run}
    for lang in LANGUAGES:
        name = "CodeQL analysis (" + lang + ")"
        matching = [job for job in jobs if field(job, "name", str) == name]
        require(len(matching) == 1, "missing or ambiguous attempt job: " + name)
        job = matching[0]
        job_id = positive(job, "id")
        require(field(job, "run_id", int) == run["id"]
                and field(job, "run_attempt", int) == run["run_attempt"],
                "job run/attempt ownership mismatch")
        require(field(job, "check_run_url", str)
                == API_ROOT + prefix + "check-runs/" + str(job_id),
                "job check ownership mismatch")
        start, end = completed(job, head)
        require(stamp(run, "run_started_at") <= start <= end <= stamp(run, "updated_at"),
                "job outside current workflow attempt interval")
        matching = [row for row in rows if field(row, "name", str) == name
                    and field(field(row, "check_suite", dict), "id", int)
                    == run["check_suite_id"]]
        require(len(matching) == 1, "missing or ambiguous check in current suite: " + name)
        check = matching[0]
        require(field(check, "id", int) == job_id, "check ownership mismatch")
        require(field(field(check, "app", dict), "slug", str) == JOB_APP,
                "wrong analysis job identity")
        require(completed(check, head) == (start, end), "job/check interval mismatch")
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
    jobs = checks(api, prefix, head, check_id, pr)
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
    require(checks(api, prefix, head, check_id, pr) == jobs,
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
