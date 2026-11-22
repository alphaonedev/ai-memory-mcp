#!/usr/bin/env python3
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""Order and trim the queue of the self-hosted CI runner pool (issue 9821, PR 9838).

Class: queue admission and order for a fixed runner pool.  The queued runs of
the named workflow(s) that wait on self-hosted runners are ordered by one total
function; with --execute the runs below the free slots are recorded, taken out
of the queue and started again later in the same order.  Planning (pure
functions of data) is separate from the gh input and output layer, so the tests
drive the planner and the judge with tables.

Invariants (held for all inputs):

  I1 order     one list holds the live queued runs and the recorded runs.  A
               record that waited MAX_WAIT_CYCLES calls comes first (older
               first); then a run whose PR carries the label `ci-fix`, then
               non-draft before draft, then older before newer, then the lower
               run id.  The order is total and does not depend on input order.
  I2 nothing   a run is recorded in the state file (bound to its run id, head
     lost      sha and run attempt; same-directory temp file, fsync, rename)
               BEFORE it is cancelled.  A recorded run is started again exactly
               once, into a free slot, or dropped with a printed reason (PR
               closed, newer head, newer run of the PR, finished, gone, the
               record does not match the live run, or a run that started
               although its cancel was seen to land).  A cancel that has not
               been seen to land keeps its record (phase cancelling), and so
               does a run whose job started inside the window before the
               cancel call (`cancel raced a start`): restarted once after the
               cancel lands, or dropped when it finishes.  A record waits at most
               MAX_WAIT_CYCLES calls behind newer arrivals.
  I3 fail      an unreadable, partial or unstable run list, an unknown status,
     closed    conclusion, label or draft state, a gh failure (classified from
               the parsed HTTP status line, never from a text match), a bad
               state file or an unclassifiable input cancels NOTHING and exits
               non-zero with an exact reason.  Without --execute nothing is
               changed (not the queue, not the state file).
  I4 scope     only queued runs of the named workflow(s) of this repository that
               wait on the self-hosted labels, of a pull_request event whose
               head branch is not protected.  Every cancel and every restart
               goes through one function each (cancel_checked, restart_checked)
               that re-reads the run just before the action and acts only when
               it is still bound to what was planned: never a push run, never
               another workflow, never a fork.  No cancel is sent unless every
               job was queued at the re-read made immediately before the call;
               GitHub has no conditional cancel, so a start inside that window
               is possible and is handled: the run and its jobs are read again
               after the call and such a run is recorded for restart (I2).
  I5 skip      a run in the listing with no PR, with more than one PR, from a
               fork or with an unknown head repository is skipped and named;
               the other runs are still planned.

Usage:
  queue_order.py                       print the plan (read only)
  queue_order.py --execute             record, cancel below the free slots, start recorded
  queue_order.py --execute --resume    only start recorded runs again

Exit codes: 0 ok, 2 usage, 3 refused (input cannot be classified), 4 state file
problem, 5 gh failure (API error, rate limit), 6 another call holds the lock.

No workflow runs this tool with --execute; it is run by hand as the conductor
decides.  The default state file lives outside the repository tree.
Python 3.12+, standard library only.
"""

from __future__ import annotations

import argparse
import enum
import errno
import fcntl
import json
import os
import re
import stat
import subprocess
import sys
import tempfile
from dataclasses import dataclass, replace
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Iterable, NamedTuple, Sequence

DEFAULT_REPO = "alphaonedev/ai-memory-mcp"
DEFAULT_WORKFLOWS = ("CI",)
DEFAULT_KEEP = 4  # two Linux and two macOS runners
CI_FIX_LABEL = "ci-fix"
SELF_HOSTED_LABEL = "self-hosted"
IN_SCOPE_EVENT = "pull_request"
QUEUED = "queued"
COMPLETED = "completed"
CANCELLED = "cancelled"
PROTECTED_BRANCH_PREFIXES = ("chain/", "release/", "rehearsal/")
PROTECTED_BRANCHES = ("main", "develop")
KNOWN_STATUSES = frozenset({"queued", "in_progress", "completed", "waiting", "requested", "pending"})
QUEUE_STATUSES = frozenset({"queued", "waiting", "requested", "pending"})  # a run that has no runner yet
KNOWN_CONCLUSIONS = frozenset({
    "success", "failure", "neutral", "cancelled", "skipped", "timed_out",
    "action_required", "stale", "startup_failure",
})
SHA_RE = re.compile(r"[0-9a-f]{40}")
PAGE_SIZE = 100
MAX_PAGES = 100  # 10,000 runs; a longer list is a cut list and refuses
LIST_ATTEMPTS = 3  # listings taken until two in a row agree
JOBS_PAGE_SIZE = 100
GH_TIMEOUT_SECS = 120
MAX_RESPONSE_BYTES = 8 * 1024 * 1024
STATUS_LINE_RE = re.compile(r"HTTP/[0-9.]+ (\d{3})(?: [^\r\n]*)?\r?\n")
HEADER_END_RE = re.compile(r"\r?\n\r?\n")
STATE_VERSION = 2
MAX_STATE_ENTRIES = 1000
MAX_STATE_BYTES = 262144
MAX_WAIT_CYCLES = 5
STATE_KEYS = frozenset({"run_id", "pr", "head_sha", "attempt", "phase", "waited"})
DEFAULT_STATE_PATH = Path.home() / ".local" / "state" / "ai-memory-ci" / "queue_order_state.json"
LOCK_SUFFIX = ".lock"
TEMP_INFIX = ".tmp."
OPEN_MODE_BITS = stat.S_IWGRP | stat.S_IWOTH
STATE_DIR_MODE = 0o700

EXIT_OK = 0
EXIT_REFUSED = 3
EXIT_STATE = 4
EXIT_GH = 5
EXIT_LOCK = 6

REASON_LIST_UNREADABLE = "run list unreadable"
REASON_LIST_PARTIAL = "run list partial"
REASON_LIST_UNSTABLE = "run list unstable"
REASON_UNKNOWN_STATUS = "unknown status"
REASON_UNKNOWN_CONCLUSION = "unknown conclusion"
REASON_UNKNOWN_LABELS = "unknown label state"
REASON_UNKNOWN_DRAFT = "unknown draft state"
REASON_NO_PR = "run has no pull request"
REASON_MULTI_PR = "run has more than one pull request"
REASON_FORK = "run is from a fork"
REASON_REPO_UNKNOWN = "head repository unknown"
REASON_UNCLASSIFIABLE = "unclassifiable input"
REASON_JOBS_UNREADABLE = "job list unreadable"
REASON_STATE_UNREADABLE = "state file unreadable"
REASON_STATE_CORRUPT = "state file corrupt"
REASON_STATE_UNWRITABLE = "state file unwritable"
REASON_STATE_FULL = "state file full"
REASON_LOCK_HELD = "another call holds the state lock"
REASON_GH_FAILED = "gh call failed"
REASON_GONE = "run no longer exists"
REASON_JOB_STARTED = "a job has started"
REASON_NO_SELF_HOSTED = "does not wait on a self-hosted runner"
REASON_CANCEL_PENDING = "cancel pending"
REASON_STARTED_AGAIN = "started again (status %s, attempt %d)"
REASON_CANCEL_RACED = "cancel raced a start"
REASON_CANCEL_UNCONFIRMED = "cancel not confirmed"
REASON_RESTART_PENDING = "restart pending"


class Refusal(Exception):
    """The input cannot be classified (or a step failed): nothing more is changed."""

    def __init__(self, exit_code: int, reason: str) -> None:
        super().__init__(reason)
        self.exit_code = exit_code
        self.reason = reason


# ------------------------------------------------------------ gh failures ----


class GhFailure(enum.Enum):
    """The class of a failed gh call, from the parsed HTTP status line or the process result."""

    NOT_FOUND = "not found"
    FORBIDDEN_OR_RATE_LIMITED = "forbidden or rate limited"
    CLIENT = "client error"
    SERVER = "server error"
    NO_STATUS = "no HTTP status"
    TRANSPORT = "gh did not run"
    BAD_BODY = "response body unreadable"
    UNEXPECTED_STATUS = "unexpected status"


class GhError(Exception):
    """A gh call failed.  The text carries the class and status only, never response text."""

    def __init__(self, kind: GhFailure, status: int | None = None, detail: str = "") -> None:
        self.kind = kind
        self.status = status
        self.detail = detail
        super().__init__(str(self))

    def __str__(self) -> str:
        if self.detail:
            return self.detail
        if self.status is None:
            return "gh failed (%s)" % self.kind.value
        return "HTTP %d (%s)" % (self.status, self.kind.value)


def classify_status(status: int) -> GhFailure:
    """The failure class of an HTTP status that is not a success."""
    if status == 404:
        return GhFailure.NOT_FOUND
    if status in (403, 429):
        return GhFailure.FORBIDDEN_OR_RATE_LIMITED
    if 400 <= status < 500:
        return GhFailure.CLIENT
    if 500 <= status < 600:
        return GhFailure.SERVER
    return GhFailure.UNEXPECTED_STATUS


def parse_gh_response(returncode: int, stdout: str, stderr: str) -> Any:
    """Parse the output of `gh api -i`: an anchored status line, headers, a blank line, a JSON body.

    stderr is never read: a failure is classified from the status line alone, so a
    run id or a body that happens to contain "404" cannot change the class.
    """
    del stderr  # deliberately unused (see the docstring)
    if len(stdout.encode("utf-8", "surrogatepass")) > MAX_RESPONSE_BYTES:
        raise GhError(GhFailure.BAD_BODY)
    line = STATUS_LINE_RE.match(stdout)
    if line is None:
        raise GhError(GhFailure.BAD_BODY if returncode == 0 else GhFailure.NO_STATUS)
    status = int(line.group(1))
    success = 200 <= status < 300
    if returncode != 0:
        raise GhError(GhFailure.UNEXPECTED_STATUS if success else classify_status(status), status)
    if not success:
        raise GhError(classify_status(status), status)
    end = HEADER_END_RE.search(stdout, line.start())
    if end is None:
        raise GhError(GhFailure.BAD_BODY, status)
    body = stdout[end.end():]
    if not body.strip():
        return {}
    try:
        return json.loads(body)
    except ValueError:
        raise GhError(GhFailure.BAD_BODY, status) from None


# ------------------------------------------------------------------ data ----


class Phase(enum.Enum):
    CANCELLING = "cancelling"  # recorded before the cancel; the cancel has not been seen to land
    CANCELLED = "cancelled"  # the re-read after the cancel saw it land; waits to be started again
    RESTARTED = "restarted"  # started again once; attempt is the new attempt


class Disposition(enum.Enum):
    DROP = "drop"  # the record goes, with its reason
    PENDING = "pending"  # the record stays; its run is not planned this call
    REQUEUED = "requeued"  # started again and queued: holds a slot, never cancelled again
    RESTARTABLE = "restartable"  # takes part in the order as a record


@dataclass(frozen=True)
class BoundEntry:
    """A recorded run, bound to the live run by run id, PR, head sha and run attempt."""

    run_id: int
    pr: int
    head_sha: str
    attempt: int
    phase: Phase
    waited: int


@dataclass(frozen=True)
class PrFacts:
    open: bool
    head_sha: str
    draft: bool
    ci_fix: bool


@dataclass(frozen=True)
class Scope:
    workflows: tuple[str, ...]
    repo: str


@dataclass(frozen=True)
class Judgment:
    kind: Disposition
    reason: str


@dataclass(frozen=True)
class ListedRun:
    """An in-scope queued run of the listing, as listed (the binding for its cancel)."""

    run_id: int
    pr: int
    head_sha: str
    created_at: datetime
    attempt: int


@dataclass(frozen=True)
class QueuedRun:
    run_id: int
    pr: int
    head_sha: str
    created_at: datetime
    draft: bool
    ci_fix: bool
    attempt: int
    waited: int
    record: bool  # a recorded run (start or wait), not a live queued run (keep or cancel)


class QueuePlan(NamedTuple):
    keep: tuple[QueuedRun, ...]  # live runs that keep their place
    start: tuple[QueuedRun, ...]  # records started again into free slots
    cancel: tuple[QueuedRun, ...]  # live runs taken out of the queue
    wait: tuple[QueuedRun, ...]  # records that wait for a free slot


# --------------------------------------------------------------- planner ----


def order_key(run: QueuedRun) -> tuple:
    """I1: aged records first (older first), then ci-fix, non-draft, older, lower run id."""
    if run.waited >= MAX_WAIT_CYCLES:
        return (0, run.created_at, run.run_id)
    return (1, not run.ci_fix, run.draft, run.created_at, run.run_id)


def plan_order(items: Iterable[QueuedRun], keep: int, started: int) -> QueuePlan:
    """One ordered list; the first free slots keep (live) or start (record), the rest cancel or wait."""
    ordered = sorted(items, key=order_key)
    slots = max(0, keep - started)
    head, tail = ordered[:slots], ordered[slots:]
    return QueuePlan(
        tuple(r for r in head if not r.record),
        tuple(r for r in head if r.record),
        tuple(r for r in tail if not r.record),
        tuple(r for r in tail if r.record),
    )


# ------------------------------------------------------ input -> records ----


def _unclassifiable(what: str, value: Any) -> Refusal:
    return Refusal(EXIT_REFUSED, "%s: %s: %r" % (REASON_UNCLASSIFIABLE, what, value))


def _int(value: Any, what: str, floor: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < floor:
        raise _unclassifiable(what, value)
    return value


def _str(value: Any, what: str) -> str:
    if not isinstance(value, str) or not value:
        raise _unclassifiable(what, value)
    return value


def _sha(value: Any, what: str) -> str:
    if not isinstance(value, str) or SHA_RE.fullmatch(value) is None:
        raise _unclassifiable(what, value)
    return value


def parse_time(value: Any, what: str) -> datetime:
    text = _str(value, what)
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        raise _unclassifiable(what, text) from None
    if parsed.tzinfo is None:
        raise Refusal(EXIT_REFUSED, "%s: %s has no zone: %r" % (REASON_UNCLASSIFIABLE, what, text))
    return parsed


def check_status(raw: dict[str, Any]) -> tuple[str, str | None]:
    run_id = raw.get("id")
    status = raw.get("status")
    if status not in KNOWN_STATUSES:
        raise Refusal(EXIT_REFUSED, "%s %r in run %s" % (REASON_UNKNOWN_STATUS, status, run_id))
    conclusion = raw.get("conclusion")
    if conclusion is not None and conclusion not in KNOWN_CONCLUSIONS:
        raise Refusal(EXIT_REFUSED, "%s %r in run %s" % (REASON_UNKNOWN_CONCLUSION, conclusion, run_id))
    return status, conclusion


def is_protected_branch(branch: str) -> bool:
    return branch in PROTECTED_BRANCHES or branch.startswith(PROTECTED_BRANCH_PREFIXES)


def run_pr_numbers(raw: dict[str, Any], run_id: int) -> list[int]:
    prs = raw.get("pull_requests")
    if not isinstance(prs, list):
        raise _unclassifiable("pull_requests of run %d" % run_id, prs)
    return [_int(p.get("number") if isinstance(p, dict) else None, "pull request number of run %d" % run_id, 1) for p in prs]


def repo_reason(raw: dict[str, Any], repo: str) -> str:
    """'' when the run's head repository is this repository, else the skip reason."""
    head = raw.get("head_repository")
    name = head.get("full_name") if isinstance(head, dict) else None
    if not isinstance(name, str) or not name:
        return REASON_REPO_UNKNOWN
    return "" if name == repo else REASON_FORK


def scan_listing(raw_runs: Sequence[Any], scope: Scope) -> tuple[list[ListedRun], list[tuple[int, str]]]:
    """I3, I4, I5: check every run's shape; return the in-scope queued runs and the named skips.

    Out of scope and left alone without a line: a run that is not queued, of
    another workflow, of another event, or of a protected branch.
    """
    found: list[ListedRun] = []
    skips: list[tuple[int, str]] = []
    seen: set[int] = set()
    for raw in raw_runs:
        if not isinstance(raw, dict):
            raise Refusal(EXIT_REFUSED, "%s: run entry is not an object" % REASON_UNCLASSIFIABLE)
        run_id = _int(raw.get("id"), "run id", 1)
        if run_id in seen:
            raise Refusal(EXIT_REFUSED, "%s: run %d listed twice" % (REASON_UNCLASSIFIABLE, run_id))
        seen.add(run_id)
        status, _ = check_status(raw)
        if status != QUEUED or raw.get("name") not in scope.workflows or raw.get("event") != IN_SCOPE_EVENT:
            continue
        if is_protected_branch(_str(raw.get("head_branch"), "head_branch of run %d" % run_id)):
            continue
        skip = repo_reason(raw, scope.repo)
        prs = run_pr_numbers(raw, run_id)
        if not skip and not prs:
            skip = REASON_NO_PR
        elif not skip and len(prs) > 1:
            skip = REASON_MULTI_PR
        if skip:
            skips.append((run_id, skip))
            continue
        found.append(ListedRun(
            run_id, prs[0], _sha(raw.get("head_sha"), "head_sha of run %d" % run_id),
            parse_time(raw.get("created_at"), "created_at of run %d" % run_id),
            _int(raw.get("run_attempt"), "run_attempt of run %d" % run_id, 1),
        ))
    return found, skips


def pr_facts(raw_pr: Any, number: int) -> PrFacts:
    """The facts of a pull request payload; any unknown form refuses."""
    if not isinstance(raw_pr, dict):
        raise Refusal(EXIT_REFUSED, "%s: pr %d payload" % (REASON_UNCLASSIFIABLE, number))
    draft = raw_pr.get("draft")
    if not isinstance(draft, bool):
        raise Refusal(EXIT_REFUSED, "%s for pr %d: %r" % (REASON_UNKNOWN_DRAFT, number, draft))
    labels = raw_pr.get("labels")
    if not isinstance(labels, list) or not all(isinstance(x, dict) and isinstance(x.get("name"), str) for x in labels):
        raise Refusal(EXIT_REFUSED, "%s for pr %d" % (REASON_UNKNOWN_LABELS, number))
    state = raw_pr.get("state")
    if state not in ("open", "closed"):
        raise Refusal(EXIT_REFUSED, "%s: pr %d state %r" % (REASON_UNCLASSIFIABLE, number, state))
    head = raw_pr.get("head")
    sha = _sha(head.get("sha") if isinstance(head, dict) else None, "head sha of pr %d" % number)
    return PrFacts(state == "open", sha, draft, any(x["name"] == CI_FIX_LABEL for x in labels))


def job_facts(raw_jobs: Any, run_id: int) -> tuple[bool, bool]:
    """(waits on a self-hosted runner, a job has started) of a run's job list."""
    if not isinstance(raw_jobs, dict) or not isinstance(raw_jobs.get("jobs"), list) or not isinstance(raw_jobs.get("total_count"), int):
        raise Refusal(EXIT_REFUSED, "%s: run %d" % (REASON_JOBS_UNREADABLE, run_id))
    jobs = raw_jobs["jobs"]
    if len(jobs) < raw_jobs["total_count"]:
        raise Refusal(EXIT_REFUSED, "%s: run %d has %d of %d jobs" % (REASON_JOBS_UNREADABLE, run_id, len(jobs), raw_jobs["total_count"]))
    waits = started = False
    for job in jobs:
        if not isinstance(job, dict) or job.get("status") not in KNOWN_STATUSES or not isinstance(job.get("labels"), list):
            raise Refusal(EXIT_REFUSED, "%s: run %d job shape" % (REASON_JOBS_UNREADABLE, run_id))
        if job["status"] != QUEUED:
            started = True
        elif SELF_HOSTED_LABEL in job["labels"]:
            waits = True
    return waits, started


# ------------------------------------------------------------- the judge ----


def scope_reason(run: dict[str, Any], run_id: int, scope: Scope) -> str:
    """'' when a live run is in scope, else why it is not."""
    event = run.get("event")
    if event != IN_SCOPE_EVENT:
        return "event %s" % event
    name = run.get("name")
    if name not in scope.workflows:
        return "workflow %r" % name
    branch = _str(run.get("head_branch"), "head_branch of run %d" % run_id)
    if is_protected_branch(branch):
        return "protected branch %s" % branch
    reason = repo_reason(run, scope.repo)
    if reason:
        return reason
    if not run_pr_numbers(run, run_id):
        return REASON_NO_PR
    return ""


def judge(entry: BoundEntry, run: Any, scope: Scope, pr_facts_fn: Callable[[int], PrFacts],
          find_newer_fn: Callable[[BoundEntry, str], int | None]) -> Judgment:
    """What happens to a record, from the record and the live run (None: the run is gone).

    The binding (run id, head sha, PR, attempt) is checked before the scope, so a
    record never acts on a run it was not written for.
    """
    if run is None:
        return Judgment(Disposition.DROP, REASON_GONE)
    if not isinstance(run, dict):
        raise Refusal(EXIT_REFUSED, "%s: run %d payload" % (REASON_UNCLASSIFIABLE, entry.run_id))
    rid = entry.run_id
    status, conclusion = check_status(run)
    attempt = _int(run.get("run_attempt"), "run_attempt of run %d" % rid, 1)
    restart_landing = entry.phase is Phase.RESTARTED and attempt == entry.attempt - 1
    mismatch = ""
    if run.get("id") != rid:
        mismatch = "run id"
    elif _sha(run.get("head_sha"), "head_sha of run %d" % rid) != entry.head_sha:
        mismatch = "head sha"
    elif (prs := run_pr_numbers(run, rid)) and prs != [entry.pr]:
        mismatch = "pr"
    elif attempt < entry.attempt and not restart_landing:
        mismatch = "attempt"
    if mismatch:
        return Judgment(Disposition.DROP, "record does not match run %d: %s" % (rid, mismatch))
    out_of_scope = scope_reason(run, rid, scope)
    if out_of_scope:
        return Judgment(Disposition.DROP, "record out of scope: %s" % out_of_scope)
    if attempt > entry.attempt:
        return Judgment(Disposition.DROP, REASON_STARTED_AGAIN % (status, attempt))
    if entry.phase is Phase.RESTARTED:
        if restart_landing:
            if status == COMPLETED and conclusion == CANCELLED:
                return Judgment(Disposition.PENDING, REASON_RESTART_PENDING)
            return Judgment(Disposition.DROP, "record does not match run %d: attempt" % rid)
        if status in QUEUE_STATUSES:
            return Judgment(Disposition.REQUEUED, "")
        return Judgment(Disposition.DROP, "restarted run left the queue (status %s)" % status)
    if status in QUEUE_STATUSES:
        # the cancel was accepted and has not landed
        return Judgment(Disposition.PENDING, REASON_CANCEL_PENDING)
    if status != COMPLETED and entry.phase is Phase.CANCELLING:
        # a job started inside the window before the cancel call; the cancel still lands on it (I4)
        return Judgment(Disposition.PENDING, REASON_CANCEL_RACED)
    if status != COMPLETED:
        # CANCELLED is written only once the cancel was seen to land, so a run that runs now has nothing to restart
        return Judgment(Disposition.DROP, REASON_STARTED_AGAIN % (status, attempt))
    if conclusion != CANCELLED:
        return Judgment(Disposition.DROP, "finished (conclusion %s)" % conclusion)
    facts = pr_facts_fn(entry.pr)
    if not facts.open:
        return Judgment(Disposition.DROP, "pr %d closed" % entry.pr)
    if facts.head_sha != entry.head_sha:
        return Judgment(Disposition.DROP, "superseded by a newer head of pr %d" % entry.pr)
    newer = find_newer_fn(entry, run["name"])
    if newer is not None:
        return Judgment(Disposition.DROP, "newer run of pr %d exists: run %d" % (entry.pr, newer))
    return Judgment(Disposition.RESTARTABLE, "")


# -------------------------------------------------------------- gh layer ----


class GhCli:
    """The gh input and output layer (the tests use a double with the same methods)."""

    def __init__(self, repo: str) -> None:
        self.repo = repo

    def _api(self, path: str, method: str = "GET") -> Any:
        cmd = ["gh", "api", "-i", "--method", method, "repos/%s/%s" % (self.repo, path)]
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, errors="replace", timeout=GH_TIMEOUT_SECS, check=False,
                                  stdin=subprocess.DEVNULL)
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise GhError(GhFailure.TRANSPORT, None, "gh did not run (%s)" % type(exc).__name__) from None
        return parse_gh_response(proc.returncode, proc.stdout or "", proc.stderr or "")

    def list_runs(self, page: int) -> Any:
        return self._api("actions/runs?status=queued&per_page=%d&page=%d" % (PAGE_SIZE, page))

    def list_runs_for_sha(self, sha: str) -> Any:
        return self._api("actions/runs?head_sha=%s&per_page=%d" % (_sha(sha, "head sha"), PAGE_SIZE))

    def run_jobs(self, run_id: int) -> Any:
        return self._api("actions/runs/%d/jobs?per_page=%d" % (run_id, JOBS_PAGE_SIZE))

    def get_run(self, run_id: int) -> Any:
        return self._api("actions/runs/%d" % run_id)

    def get_pull(self, number: int) -> Any:
        return self._api("pulls/%d" % number)

    def cancel(self, run_id: int) -> None:
        self._api("actions/runs/%d/cancel" % run_id, "POST")

    def rerun(self, run_id: int) -> None:
        self._api("actions/runs/%d/rerun" % run_id, "POST")


def gh_call(refusal_reason: str, fn: Callable[..., Any], *args: Any) -> Any:
    try:
        return fn(*args)
    except GhError as exc:
        raise Refusal(EXIT_GH, "%s: %s" % (refusal_reason, exc)) from None


def fetch_all_runs(gh: Any) -> list[Any]:
    """Every queued run, page by page; a cut or failed list refuses (I3)."""
    runs: list[Any] = []
    total = 0
    for page in range(1, MAX_PAGES + 1):
        body = gh_call(REASON_LIST_UNREADABLE, gh.list_runs, page)
        if not isinstance(body, dict) or not isinstance(body.get("workflow_runs"), list) or not isinstance(body.get("total_count"), int):
            raise Refusal(EXIT_REFUSED, "%s: unexpected response shape" % REASON_LIST_UNREADABLE)
        total = body["total_count"]
        runs.extend(body["workflow_runs"])
        if len(body["workflow_runs"]) < PAGE_SIZE:
            break
    else:
        raise Refusal(EXIT_REFUSED, "%s: more than %d pages" % (REASON_LIST_PARTIAL, MAX_PAGES))
    if len(runs) < total:
        raise Refusal(EXIT_REFUSED, "%s: %d of %d runs" % (REASON_LIST_PARTIAL, len(runs), total))
    return runs


def _fingerprint(runs: Sequence[Any]) -> list[str]:
    keys = ("id", "status", "conclusion", "run_attempt", "head_sha")
    return sorted(repr(tuple(r.get(k) for k in keys)) if isinstance(r, dict) else repr(r) for r in runs)


def stable_listing(gh: Any) -> list[Any]:
    """Two listings in a row that agree, within LIST_ATTEMPTS listings, or a refusal."""
    previous = fetch_all_runs(gh)
    for _ in range(LIST_ATTEMPTS - 1):
        current = fetch_all_runs(gh)
        if _fingerprint(current) == _fingerprint(previous):
            return current
        previous = current
    raise Refusal(EXIT_REFUSED, "%s: %d listings disagree" % (REASON_LIST_UNSTABLE, LIST_ATTEMPTS))


def read_run(gh: Any, run_id: int) -> Any:
    """The live run, or None when GitHub answers 404 (classified from the status line)."""
    try:
        return gh.get_run(run_id)
    except GhError as exc:
        if exc.kind is GhFailure.NOT_FOUND:
            return None
        raise Refusal(EXIT_GH, "%s: run %d: %s" % (REASON_GH_FAILED, run_id, exc)) from None


class Facts:
    """PR facts and newer-run lookups for the judge, read through gh."""

    def __init__(self, gh: Any, cache: bool) -> None:
        self.gh = gh
        self.cache: dict[int, PrFacts] | None = {} if cache else None

    def pr(self, number: int) -> PrFacts:
        if self.cache is not None and number in self.cache:
            return self.cache[number]
        facts = pr_facts(gh_call(REASON_GH_FAILED, self.gh.get_pull, number), number)
        if self.cache is not None:
            self.cache[number] = facts
        return facts

    def newer_run(self, entry: BoundEntry, workflow: str) -> int | None:
        """The lowest id of a newer run of the same workflow, PR and head sha, or None."""
        body = gh_call(REASON_GH_FAILED, self.gh.list_runs_for_sha, entry.head_sha)
        if not isinstance(body, dict) or not isinstance(body.get("workflow_runs"), list) or not isinstance(body.get("total_count"), int):
            raise Refusal(EXIT_REFUSED, "%s: unexpected response shape" % REASON_LIST_UNREADABLE)
        runs = body["workflow_runs"]
        if len(runs) < body["total_count"]:
            raise Refusal(EXIT_REFUSED, "%s: %d of %d runs" % (REASON_LIST_PARTIAL, len(runs), body["total_count"]))
        newer: list[int] = []
        for raw in runs:
            if not isinstance(raw, dict):
                raise Refusal(EXIT_REFUSED, "%s: run entry is not an object" % REASON_UNCLASSIFIABLE)
            run_id = _int(raw.get("id"), "run id", 1)
            if run_id <= entry.run_id or raw.get("name") != workflow or raw.get("event") != IN_SCOPE_EVENT:
                continue
            if entry.pr in run_pr_numbers(raw, run_id):
                newer.append(run_id)
        return min(newer) if newer else None


# ----------------------------------------------------- the two mutations ----


class CancelOutcome(NamedTuple):
    """What cancel_checked did.  sent: the cancel call was made; reason: why not, or what the re-read after it saw
    ('' when the cancel landed); phase: the record's phase from here on; error: a failed re-read after the cancel."""

    sent: bool
    reason: str
    phase: Phase | None = None
    error: Refusal | None = None


def cancel_checked(gh: Any, listed: QueuedRun) -> CancelOutcome:
    """The only caller of the cancel API.  Re-reads the run and its jobs and cancels only a bound run whose jobs are
    all queued; then reads the run and its jobs again, because GitHub has no conditional cancel (a job can start
    between the re-read and the call)."""
    why = cancel_refusal(gh, listed)
    if why:
        return CancelOutcome(False, why)
    try:
        gh.cancel(listed.run_id)
    except GhError as exc:
        raise Refusal(EXIT_GH, "%s: cancel run %d: %s" % (REASON_GH_FAILED, listed.run_id, exc)) from None
    try:
        run = read_run(gh, listed.run_id)
        if run is None:
            return CancelOutcome(True, "", Phase.CANCELLED)  # gone after the cancel: the next call drops the record
        if not isinstance(run, dict):
            raise Refusal(EXIT_REFUSED, "%s: run %d payload" % (REASON_UNCLASSIFIABLE, listed.run_id))
        status, _ = check_status(run)
        if status == COMPLETED:
            return CancelOutcome(True, "", Phase.CANCELLED)
        _waits, started = job_facts(gh_call(REASON_JOBS_UNREADABLE, gh.run_jobs, listed.run_id), listed.run_id)
    except Refusal as exc:
        return CancelOutcome(True, REASON_CANCEL_UNCONFIRMED, Phase.CANCELLING, exc)
    if status not in QUEUE_STATUSES or started:
        return CancelOutcome(True, REASON_CANCEL_RACED, Phase.CANCELLING)
    return CancelOutcome(True, REASON_CANCEL_PENDING, Phase.CANCELLING)


def cancel_refusal(gh: Any, listed: QueuedRun) -> str:
    """Why the run is not cancelled ('' when it may be): the re-read immediately before the cancel call."""
    run = read_run(gh, listed.run_id)
    if run is None:
        return REASON_GONE
    if not isinstance(run, dict):
        raise Refusal(EXIT_REFUSED, "%s: run %d payload" % (REASON_UNCLASSIFIABLE, listed.run_id))
    status, _ = check_status(run)
    changed = ""
    if run.get("id") != listed.run_id:
        changed = "run id"
    elif run.get("head_sha") != listed.head_sha:
        changed = "head sha"
    elif run.get("run_attempt") != listed.attempt:
        changed = "attempt"
    elif run_pr_numbers(run, listed.run_id) != [listed.pr]:
        changed = "pr"
    if changed:
        return "run changed since the listing: %s" % changed
    if status != QUEUED:
        return "run is no longer queued (status %s)" % status
    _waits, started = job_facts(gh_call(REASON_JOBS_UNREADABLE, gh.run_jobs, listed.run_id), listed.run_id)
    if started:
        return REASON_JOB_STARTED
    return ""


def restart_checked(gh: Any, entry: BoundEntry, scope: Scope) -> Judgment:
    """The only caller of the rerun API.  Re-reads and re-judges the record; starts it only when RESTARTABLE."""
    facts = Facts(gh, cache=False)
    verdict = judge(entry, read_run(gh, entry.run_id), scope, facts.pr, facts.newer_run)
    if verdict.kind is not Disposition.RESTARTABLE:
        return verdict
    try:
        gh.rerun(entry.run_id)
    except GhError as exc:
        raise Refusal(EXIT_GH, "%s: start run %d: %s" % (REASON_GH_FAILED, entry.run_id, exc)) from None
    return verdict


# ------------------------------------------------------------ state file ----


def _state_refusal(reason: str, why: str) -> Refusal:
    return Refusal(EXIT_STATE, "%s: %s" % (reason, why))


def _check_directory(directory: Path, reason: str) -> bool:
    """False when the directory does not exist; refuses a foreign owner or an open mode."""
    try:
        info = os.stat(directory)
    except FileNotFoundError:
        return False
    except OSError as exc:
        raise _state_refusal(reason, "directory %s" % type(exc).__name__) from None
    if not stat.S_ISDIR(info.st_mode):
        raise _state_refusal(reason, "directory is not a directory")
    if info.st_uid != os.geteuid():
        raise _state_refusal(reason, "directory not owned by this user")
    if info.st_mode & OPEN_MODE_BITS:
        raise _state_refusal(reason, "directory group or world writable")
    return True


def _plain_int(value: Any, floor: int, ceiling: int | None = None) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < floor or (ceiling is not None and value > ceiling):
        raise ValueError("int")
    return value


def parse_entry(raw: Any) -> BoundEntry:
    """Strict: exactly the six keys, each of its one type and range."""
    if not isinstance(raw, dict) or set(raw) != STATE_KEYS:
        raise ValueError("keys")
    sha = raw["head_sha"]
    if not isinstance(sha, str) or SHA_RE.fullmatch(sha) is None:
        raise ValueError("sha")
    return BoundEntry(_plain_int(raw["run_id"], 1), _plain_int(raw["pr"], 1), sha, _plain_int(raw["attempt"], 1),
                      Phase(raw["phase"]), _plain_int(raw["waited"], 0, MAX_WAIT_CYCLES))


class StateStore:
    """The durable record: O_NOFOLLOW read bound to the opened file, atomic replace in the same directory."""

    def __init__(self, path: Path, hook: Callable[[str], None] | None = None) -> None:
        self.path = Path(path)
        self.hook = hook

    def _hook(self, step: str) -> None:
        if self.hook is not None:
            self.hook(step)

    def read(self) -> list[BoundEntry]:
        if not _check_directory(self.path.parent, REASON_STATE_UNREADABLE):
            return []
        try:
            fd = os.open(self.path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
        except FileNotFoundError:
            return []
        except OSError as exc:
            why = "is a symlink" if exc.errno == errno.ELOOP else type(exc).__name__
            raise _state_refusal(REASON_STATE_UNREADABLE, why) from None
        try:
            self._hook("opened")
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode):
                raise _state_refusal(REASON_STATE_UNREADABLE, "not a regular file")
            if info.st_uid != os.geteuid():
                raise _state_refusal(REASON_STATE_UNREADABLE, "not owned by this user")
            if info.st_mode & OPEN_MODE_BITS:
                raise _state_refusal(REASON_STATE_UNREADABLE, "group or world writable")
            if info.st_size > MAX_STATE_BYTES:
                raise _state_refusal(REASON_STATE_UNREADABLE, "larger than %d bytes" % MAX_STATE_BYTES)
            chunks: list[bytes] = []
            size = 0
            while size <= MAX_STATE_BYTES:
                chunk = os.read(fd, MAX_STATE_BYTES + 1 - size)
                if not chunk:
                    break
                chunks.append(chunk)
                size += len(chunk)
            if size > MAX_STATE_BYTES:
                raise _state_refusal(REASON_STATE_UNREADABLE, "larger than %d bytes" % MAX_STATE_BYTES)
        except OSError as exc:
            raise _state_refusal(REASON_STATE_UNREADABLE, type(exc).__name__) from None
        finally:
            os.close(fd)
        try:
            doc = json.loads(b"".join(chunks).decode("utf-8"))
            if not isinstance(doc, dict) or set(doc) != {"version", "entries"} or doc["version"] != STATE_VERSION:
                raise ValueError("shape")
            if not isinstance(doc["entries"], list) or len(doc["entries"]) > MAX_STATE_ENTRIES:
                raise ValueError("entries")
            entries = [parse_entry(e) for e in doc["entries"]]
            if len({e.run_id for e in entries}) != len(entries):
                raise ValueError("duplicate run id")
        except (ValueError, KeyError, TypeError, UnicodeDecodeError, RecursionError):
            raise _state_refusal(REASON_STATE_CORRUPT, self.path.name) from None
        return entries

    def write(self, entries: Sequence[BoundEntry]) -> None:
        ordered = sorted(entries, key=lambda e: e.run_id)
        if len(ordered) > MAX_STATE_ENTRIES:
            raise _state_refusal(REASON_STATE_UNWRITABLE, "more than %d entries" % MAX_STATE_ENTRIES)
        doc = {"version": STATE_VERSION, "entries": [
            {"run_id": e.run_id, "pr": e.pr, "head_sha": e.head_sha, "attempt": e.attempt, "phase": e.phase.value, "waited": e.waited}
            for e in ordered]}
        data = (json.dumps(doc, separators=(",", ":"), sort_keys=True) + "\n").encode("utf-8")
        if len(data) > MAX_STATE_BYTES:
            raise _state_refusal(REASON_STATE_UNWRITABLE, "larger than %d bytes" % MAX_STATE_BYTES)
        tmp: str | None = None
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True, mode=STATE_DIR_MODE)
            _check_directory(self.path.parent, REASON_STATE_UNWRITABLE)
            fd, tmp = tempfile.mkstemp(prefix=self.path.name + TEMP_INFIX, dir=self.path.parent)  # O_EXCL, mode 0600
            try:
                view = memoryview(data)
                while view:
                    view = view[os.write(fd, view):]
                os.fsync(fd)
            finally:
                os.close(fd)
            self._hook("temp-written")
            os.replace(tmp, self.path)
            tmp = None
            self._hook("renamed")
            dir_fd = os.open(self.path.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(dir_fd)
            finally:
                os.close(dir_fd)
        except OSError as exc:
            raise _state_refusal(REASON_STATE_UNWRITABLE, type(exc).__name__) from None
        finally:
            if tmp is not None:
                try:
                    os.unlink(tmp)
                except OSError:
                    pass


class StateLock:
    """Non-blocking exclusive lock beside the state file; a second call refuses; never follows a symlink."""

    def __init__(self, path: Path) -> None:
        path = Path(path)
        self.path = path.with_name(path.name + LOCK_SUFFIX)
        self.fd: int | None = None

    def __enter__(self) -> "StateLock":
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True, mode=STATE_DIR_MODE)
            self.fd = os.open(self.path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
            fcntl.flock(self.fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            self._close()
            raise Refusal(EXIT_LOCK, REASON_LOCK_HELD) from None
        except OSError as exc:
            self._close()
            why = "lock is a symlink" if exc.errno == errno.ELOOP else "lock %s" % type(exc).__name__
            raise _state_refusal(REASON_STATE_UNWRITABLE, why) from None
        return self

    def _close(self) -> None:
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None

    def __exit__(self, *exc: object) -> None:
        self._close()


# -------------------------------------------------------------- the call ----


def gather(gh: Any, listed: Sequence[ListedRun], facts: Facts) -> tuple[list[QueuedRun], list[ListedRun], list[tuple[int, str]]]:
    """(live runs to order, runs with a job started (they hold a slot), [(run id, reason) left alone])."""
    live: list[QueuedRun] = []
    started: list[ListedRun] = []
    left_out: list[tuple[int, str]] = []
    for run in listed:
        waits, has_started = job_facts(gh_call(REASON_JOBS_UNREADABLE, gh.run_jobs, run.run_id), run.run_id)
        if not waits:
            left_out.append((run.run_id, REASON_NO_SELF_HOSTED))
            continue
        pr = facts.pr(run.pr)
        if not pr.open:
            left_out.append((run.run_id, "pr %d closed" % run.pr))
        elif pr.head_sha != run.head_sha:
            left_out.append((run.run_id, "superseded by a newer head of pr %d" % run.pr))
        elif has_started:
            started.append(run)
        else:
            live.append(QueuedRun(run.run_id, run.pr, run.head_sha, run.created_at, pr.draft, pr.ci_fix, run.attempt, 0, False))
    return live, started, left_out


def run_once(gh: Any, store: StateStore, keep: int, scope: Scope, execute: bool, resume_only: bool, out: Callable[[str], None]) -> None:
    entries = store.read()
    listed, skips = scan_listing(stable_listing(gh), scope)
    facts = Facts(gh, cache=True)

    kept: dict[int, BoundEntry] = {}
    records: list[QueuedRun] = []
    record_lines: list[str] = []
    held = 0
    for entry in entries:
        run = read_run(gh, entry.run_id)
        verdict = judge(entry, run, scope, facts.pr, facts.newer_run)
        match verdict.kind:
            case Disposition.DROP:
                record_lines.append("drop record run %d: %s" % (entry.run_id, verdict.reason))
            case Disposition.PENDING:
                kept[entry.run_id] = entry
                record_lines.append("record kept run %d: %s" % (entry.run_id, verdict.reason))
            case Disposition.REQUEUED:
                kept[entry.run_id] = entry
                held += 1
                record_lines.append("record kept run %d: restarted, queued again" % entry.run_id)
            case Disposition.RESTARTABLE:
                kept[entry.run_id] = entry
                pr = facts.pr(entry.pr)
                created = parse_time(run.get("created_at"), "created_at of run %d" % entry.run_id)
                records.append(QueuedRun(entry.run_id, entry.pr, entry.head_sha, created, pr.draft, pr.ci_fix, entry.attempt, entry.waited, True))
            case _:
                raise AssertionError(verdict.kind)

    live, started, left_out = gather(gh, [r for r in listed if r.run_id not in kept], facts)
    keep_runs, start_runs, cancel_runs, wait_runs = plan_order(live + records, keep, len(started) + held)
    if resume_only:
        cancel_runs = ()
    room = max(0, MAX_STATE_ENTRIES - len(kept))
    cancel_runs, full_runs = cancel_runs[:room], cancel_runs[room:]

    for pos, run in enumerate(keep_runs, 1):
        out("keep %d run %d pr %d" % (pos, run.run_id, run.pr))
    for run in started:
        out("keep run %d pr %d: %s" % (run.run_id, run.pr, REASON_JOB_STARTED))
    for run in cancel_runs:
        out("cancel run %d pr %d" % (run.run_id, run.pr))
    for run in full_runs:
        out("left alone run %d: %s" % (run.run_id, REASON_STATE_FULL))
    for run_id, reason in left_out:
        out("left alone run %d: %s" % (run_id, reason))
    for run_id, reason in skips:
        out("skip run %d: %s" % (run_id, reason))
    if skips:
        out("skipped %d runs" % len(skips))
    for line in record_lines:
        out(line)
    for run in start_runs:
        out("start again run %d" % run.run_id)
    for run in wait_runs:
        out("record kept run %d: waits for a free slot" % run.run_id)
    if not execute:
        return

    for run in wait_runs:
        entry = kept[run.run_id]
        kept[run.run_id] = replace(entry, waited=min(MAX_WAIT_CYCLES, entry.waited + 1))
    for run in cancel_runs:
        kept[run.run_id] = BoundEntry(run.run_id, run.pr, run.head_sha, run.attempt, Phase.CANCELLING, 0)
    store.write(list(kept.values()))  # I2: durable before the first cancel (also proves the file is writable)
    sent: set[int] = set()
    landed: list[int] = []
    unconfirmed: Refusal | None = None
    for run in reversed(cancel_runs):
        outcome = cancel_checked(gh, run)
        if not outcome.sent:
            out("left alone run %d: %s" % (run.run_id, outcome.reason))
            continue
        sent.add(run.run_id)
        if outcome.phase is Phase.CANCELLED:
            landed.append(run.run_id)
        out("cancelled run %d%s" % (run.run_id, ": " + outcome.reason if outcome.reason else ""))
        if outcome.error is not None:
            unconfirmed = outcome.error  # the record stays CANCELLING: the next call judges the run again
            break
    # One write for the whole loop (one fsync, not one per run).  A crash before it leaves every record CANCELLING,
    # the state the judge already reads fail-closed (pending while queued, restartable once the cancel landed).
    unsent = [run.run_id for run in cancel_runs if run.run_id not in sent]  # left alone, or not reached after a failure
    for run_id in landed:
        kept[run_id] = replace(kept[run_id], phase=Phase.CANCELLED)
    for run_id in unsent:
        del kept[run_id]
    if landed or unsent:
        store.write(list(kept.values()))
    if unconfirmed is not None:
        raise unconfirmed
    for run in start_runs:
        entry = kept[run.run_id]
        verdict = restart_checked(gh, entry, scope)
        if verdict.kind is Disposition.RESTARTABLE:
            kept[run.run_id] = replace(entry, phase=Phase.RESTARTED, attempt=entry.attempt + 1, waited=0)
            store.write(list(kept.values()))
            out("started run %d" % run.run_id)
        elif verdict.kind is Disposition.DROP:
            del kept[run.run_id]
            store.write(list(kept.values()))
            out("drop record run %d: %s" % (run.run_id, verdict.reason))
        else:
            out("record kept run %d: %s" % (run.run_id, verdict.reason or verdict.kind.value))


def main(argv: Sequence[str] | None = None, gh: Any = None, hook: Callable[[str], None] | None = None, out: Callable[[str], None] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Order and trim the self-hosted CI queue (issue 9821).")
    parser.add_argument("--repo", default=DEFAULT_REPO)
    parser.add_argument("--workflow", action="append", dest="workflows", help="workflow name (repeatable; default %s)" % ", ".join(DEFAULT_WORKFLOWS))
    parser.add_argument("--keep", type=int, default=DEFAULT_KEEP, help="queued runs that stay (default %d)" % DEFAULT_KEEP)
    parser.add_argument("--state-file", type=Path, default=DEFAULT_STATE_PATH, help="restart record (default outside the repository tree)")
    parser.add_argument("--execute", action="store_true", help="cancel and start runs; without it nothing is changed")
    parser.add_argument("--resume", action="store_true", help="with --execute: only start recorded runs, cancel nothing")
    args = parser.parse_args(argv)
    if args.keep < 1:
        parser.error("--keep must be at least 1")
    if args.resume and not args.execute:
        parser.error("--resume needs --execute")
    emit = out or print
    client = gh or GhCli(args.repo)
    store = StateStore(args.state_file, hook)
    scope = Scope(tuple(args.workflows or DEFAULT_WORKFLOWS), args.repo)
    try:
        if args.execute:
            with StateLock(args.state_file):
                run_once(client, store, args.keep, scope, True, args.resume, emit)
        else:
            run_once(client, store, args.keep, scope, False, False, emit)
    except Refusal as refusal:
        print("queue_order: refused: %s" % refusal.reason, file=sys.stderr)
        return refusal.exit_code
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
