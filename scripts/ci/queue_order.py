#!/usr/bin/env python3
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""Order and trim the queue of the self-hosted CI runner pool (issue 9821).

Class: queue admission and order for a fixed runner pool.  The queued runs of
the named workflow(s) that wait on self-hosted runners are ordered by one total
function and, with --execute, the runs below the first KEEP are taken out of the
queue and started again later.  Planning (pure functions of data) is separate
from the gh input and output layer, so the tests drive the planner with tables.

Invariants (held for all inputs):

  I1 order     a run whose PR carries the label `ci-fix` comes first, then
               non-draft before draft, then older before newer, then the lower
               run id (a total, deterministic order).
  I2 nothing   a run is recorded in the state file (atomic write, fsync, rename)
     lost      BEFORE it is cancelled; a later call starts it again, in order,
               once the kept runs have their runners.  A run that finished, was
               superseded by a newer head of its PR, or whose PR closed is
               dropped from the record with a printed reason, never restarted.
               One lock file per state file serialises two calls at once.
  I3 fail      an unreadable or partial run list, an unknown status, conclusion,
     closed    label or draft state, a run with no PR or more than one PR, a bad
               state file or an unclassifiable input cancels NOTHING and exits
               non-zero with an exact reason.  Without --execute nothing is
               ever changed (not the queue, not the state file).
  I4 scope     only queued runs of the named workflow(s) of this repository that
               wait on the self-hosted labels, of a pull_request event whose head
               branch is not a protected branch; never an in-progress run, never
               a push run, never another workflow.

Usage:
  queue_order.py                       print the plan (read only)
  queue_order.py --execute             record, cancel below --keep, start recorded
  queue_order.py --execute --resume    only start recorded runs again

Exit codes: 0 ok, 2 usage, 3 refused (input cannot be classified), 4 state file
problem, 5 gh failure (API error, rate limit), 6 another call holds the lock.

The default state file lives outside the repository tree.  Never run --execute
against the live repository except as the conductor decides.
Python 3.12+, standard library only.
"""

from __future__ import annotations

import argparse
import fcntl
import json
import os
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Iterable, Sequence

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
KNOWN_CONCLUSIONS = frozenset({
    "success", "failure", "neutral", "cancelled", "skipped", "timed_out",
    "action_required", "stale", "startup_failure",
})
PAGE_SIZE = 100
MAX_PAGES = 100  # 10,000 runs; a full last page is a cut list and refuses
JOBS_PAGE_SIZE = 100
GH_TIMEOUT_SECS = 120
ERR_TAIL_CHARS = 200
STATE_VERSION = 1
DEFAULT_STATE_PATH = Path.home() / ".local" / "state" / "ai-memory-ci" / "queue_order_state.json"
LOCK_SUFFIX = ".lock"

EXIT_OK = 0
EXIT_REFUSED = 3
EXIT_STATE = 4
EXIT_GH = 5
EXIT_LOCK = 6

REASON_LIST_UNREADABLE = "run list unreadable"
REASON_LIST_PARTIAL = "run list partial"
REASON_UNKNOWN_STATUS = "unknown status"
REASON_UNKNOWN_CONCLUSION = "unknown conclusion"
REASON_UNKNOWN_LABELS = "unknown label state"
REASON_UNKNOWN_DRAFT = "unknown draft state"
REASON_NO_PR = "run has no pull request"
REASON_MULTI_PR = "run has more than one pull request"
REASON_UNCLASSIFIABLE = "unclassifiable input"
REASON_JOBS_UNREADABLE = "job list unreadable"
REASON_STATE_UNREADABLE = "state file unreadable"
REASON_STATE_CORRUPT = "state file corrupt"
REASON_STATE_UNWRITABLE = "state file unwritable"
REASON_LOCK_HELD = "another call holds the state lock"
REASON_GH_FAILED = "gh call failed"


class Refusal(Exception):
    """The input cannot be classified (or a step failed): nothing more is changed."""

    def __init__(self, exit_code: int, reason: str) -> None:
        super().__init__(reason)
        self.exit_code = exit_code
        self.reason = reason


class GhError(Exception):
    """A gh call failed; `not_found` marks a 404."""

    def __init__(self, detail: str, not_found: bool = False) -> None:
        super().__init__(detail)
        self.not_found = not_found


# ---------------------------------------------------------------- data ----


@dataclass(frozen=True)
class QueuedRun:
    run_id: int
    pr: int
    head_sha: str
    created_at: datetime
    draft: bool
    ci_fix: bool
    attempt: int


@dataclass(frozen=True)
class Entry:
    """A run recorded for restart."""

    run_id: int
    pr: int
    head_sha: str
    attempt: int


@dataclass(frozen=True)
class Live:
    """Live data of a recorded run (None run fields mean the run is gone)."""

    status: str
    conclusion: str | None
    attempt: int
    pr_open: bool
    pr_head_sha: str
    created_at: datetime
    draft: bool
    ci_fix: bool


@dataclass(frozen=True)
class QueuePlan:
    keep: tuple[QueuedRun, ...]
    cancel: tuple[QueuedRun, ...]


@dataclass(frozen=True)
class RestartPlan:
    start: tuple[int, ...]  # run ids, in order
    wait: tuple[int, ...]  # restartable, no free slot yet
    still_queued: tuple[int, ...]
    drops: tuple[tuple[int, str], ...]  # (run id, printed reason)


# -------------------------------------------------------------- planner ----


def order_key(run: QueuedRun) -> tuple[int, int, datetime, int]:
    """I1: ci-fix first, non-draft before draft, older first, run id last."""
    return (0 if run.ci_fix else 1, 1 if run.draft else 0, run.created_at, run.run_id)


def plan_queue(runs: Iterable[QueuedRun], keep: int) -> QueuePlan:
    ordered = sorted(runs, key=order_key)
    return QueuePlan(keep=tuple(ordered[:keep]), cancel=tuple(ordered[keep:]))


def plan_restart(entries: Sequence[Entry], live: dict[int, Live | None], queued_after: int, keep: int) -> RestartPlan:
    """Decide for each recorded run: drop (with reason), still queued, start or wait.

    `queued_after` is the number of in-scope runs still queued after this call's
    cancels; a recorded run starts again only into a free slot (queued < keep).
    """
    drops: list[tuple[int, str]] = []
    still: list[int] = []
    candidates: list[tuple[Entry, Live]] = []
    for entry in entries:
        state = live.get(entry.run_id)
        if state is None:
            drops.append((entry.run_id, "run no longer exists"))
        elif state.attempt > entry.attempt or state.status not in (QUEUED, COMPLETED):
            drops.append((entry.run_id, "started again (status %s, attempt %d)" % (state.status, state.attempt)))
        elif state.status == QUEUED:
            still.append(entry.run_id)
        elif state.conclusion != CANCELLED:
            drops.append((entry.run_id, "finished (conclusion %s)" % state.conclusion))
        elif not state.pr_open:
            drops.append((entry.run_id, "pr %d closed" % entry.pr))
        elif state.pr_head_sha != entry.head_sha:
            drops.append((entry.run_id, "superseded by a newer head of pr %d" % entry.pr))
        else:
            candidates.append((entry, state))
    candidates.sort(key=lambda c: (0 if c[1].ci_fix else 1, 1 if c[1].draft else 0, c[1].created_at, c[0].run_id))
    free = max(0, keep - queued_after)
    ids = [c[0].run_id for c in candidates]
    return RestartPlan(tuple(ids[:free]), tuple(ids[free:]), tuple(still), tuple(drops))


# ----------------------------------------------------- input -> records ----


def _int(value: Any, what: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise Refusal(EXIT_REFUSED, "%s: %s: %r" % (REASON_UNCLASSIFIABLE, what, value))
    return value


def _str(value: Any, what: str) -> str:
    if not isinstance(value, str) or not value:
        raise Refusal(EXIT_REFUSED, "%s: %s: %r" % (REASON_UNCLASSIFIABLE, what, value))
    return value


def parse_time(value: Any, what: str) -> datetime:
    text = _str(value, what)
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        raise Refusal(EXIT_REFUSED, "%s: %s: %r" % (REASON_UNCLASSIFIABLE, what, text)) from None
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


def candidate_runs(raw_runs: Sequence[Any], workflows: Sequence[str]) -> list[dict[str, Any]]:
    """I3 + I4: check every run's shape, return the raw runs that are in scope.

    In scope: a queued run of a named workflow, of a pull_request event, whose
    head branch is not protected.  Everything else is left alone (never an
    in-progress run, a push run or another workflow).
    """
    found: list[dict[str, Any]] = []
    seen: set[int] = set()
    for raw in raw_runs:
        if not isinstance(raw, dict):
            raise Refusal(EXIT_REFUSED, "%s: run entry is not an object" % REASON_UNCLASSIFIABLE)
        run_id = _int(raw.get("id"), "run id")
        if run_id in seen:
            raise Refusal(EXIT_REFUSED, "%s: run %d listed twice" % (REASON_UNCLASSIFIABLE, run_id))
        seen.add(run_id)
        status, _ = check_status(raw)
        if status != QUEUED or raw.get("name") not in workflows or raw.get("event") != IN_SCOPE_EVENT:
            continue
        if is_protected_branch(_str(raw.get("head_branch"), "head_branch of run %d" % run_id)):
            continue
        prs = raw.get("pull_requests")
        if not isinstance(prs, list) or not prs:
            raise Refusal(EXIT_REFUSED, "%s: run %d" % (REASON_NO_PR, run_id))
        if len(prs) > 1:
            raise Refusal(EXIT_REFUSED, "%s: run %d" % (REASON_MULTI_PR, run_id))
        found.append(raw)
    return found


def pr_number(raw_run: dict[str, Any]) -> int:
    pr = raw_run["pull_requests"][0]
    return _int(pr.get("number") if isinstance(pr, dict) else None, "pull request number of run %s" % raw_run["id"])


def pr_facts(raw_pr: Any, number: int) -> tuple[bool, str, bool, bool]:
    """Return (open, head sha, draft, ci_fix) of a pull request payload."""
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
    sha = head.get("sha") if isinstance(head, dict) else None
    return state == "open", _str(sha, "head sha of pr %d" % number), draft, any(x["name"] == CI_FIX_LABEL for x in labels)


def waits_on_self_hosted(raw_jobs: Any, run_id: int) -> bool:
    if not isinstance(raw_jobs, dict) or not isinstance(raw_jobs.get("jobs"), list) or not isinstance(raw_jobs.get("total_count"), int):
        raise Refusal(EXIT_REFUSED, "%s: run %d" % (REASON_JOBS_UNREADABLE, run_id))
    jobs = raw_jobs["jobs"]
    if len(jobs) < raw_jobs["total_count"]:
        raise Refusal(EXIT_REFUSED, "%s: run %d has %d of %d jobs" % (REASON_JOBS_UNREADABLE, run_id, len(jobs), raw_jobs["total_count"]))
    for job in jobs:
        if not isinstance(job, dict) or job.get("status") not in KNOWN_STATUSES or not isinstance(job.get("labels"), list):
            raise Refusal(EXIT_REFUSED, "%s: run %d job shape" % (REASON_JOBS_UNREADABLE, run_id))
        if job["status"] == QUEUED and SELF_HOSTED_LABEL in job["labels"]:
            return True
    return False


def build_queue(raw_runs: Sequence[dict[str, Any]], waits: dict[int, bool], pulls: dict[int, Any]) -> tuple[list[QueuedRun], list[tuple[int, str]]]:
    """Return (queued runs to order, [(run id, reason) left out of the order])."""
    runs: list[QueuedRun] = []
    left_out: list[tuple[int, str]] = []
    for raw in raw_runs:
        run_id = raw["id"]
        if not waits[run_id]:
            left_out.append((run_id, "does not wait on a self-hosted runner"))
            continue
        number = pr_number(raw)
        is_open, head, draft, ci_fix = pr_facts(pulls[number], number)
        run_head = _str(raw.get("head_sha"), "head_sha of run %d" % run_id)
        if not is_open:
            left_out.append((run_id, "pr %d closed" % number))
        elif run_head != head:
            left_out.append((run_id, "superseded by a newer head of pr %d" % number))
        else:
            attempt = _int(raw.get("run_attempt", 1), "run_attempt of run %d" % run_id)
            runs.append(QueuedRun(run_id, number, run_head, parse_time(raw.get("created_at"), "created_at of run %d" % run_id), draft, ci_fix, attempt))
    return runs, left_out


# ------------------------------------------------------------ gh layer ----


class GhCli:
    """The gh input and output layer (the tests use a double with the same methods)."""

    def __init__(self, repo: str) -> None:
        self.repo = repo

    def _api(self, path: str, method: str = "GET") -> Any:
        cmd = ["gh", "api", "--method", method, "repos/%s/%s" % (self.repo, path)]
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=GH_TIMEOUT_SECS, check=False)
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise GhError(type(exc).__name__) from None
        if proc.returncode != 0:
            tail = (proc.stderr or "").strip()[-ERR_TAIL_CHARS:]
            raise GhError(tail or "exit %d" % proc.returncode, not_found="404" in tail or "Not Found" in tail)
        if not proc.stdout.strip():
            return {}
        try:
            return json.loads(proc.stdout)
        except ValueError:
            raise GhError("response is not JSON") from None

    def list_runs(self, page: int) -> Any:
        return self._api("actions/runs?status=queued&per_page=%d&page=%d" % (PAGE_SIZE, page))

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


def fetch_all_runs(gh: Any) -> list[Any]:
    """Every queued run, page by page; a cut or failed list refuses (I3)."""
    runs: list[Any] = []
    total = None
    for page in range(1, MAX_PAGES + 1):
        try:
            body = gh.list_runs(page)
        except GhError as exc:
            raise Refusal(EXIT_GH, "%s: %s" % (REASON_LIST_UNREADABLE, exc)) from None
        if not isinstance(body, dict) or not isinstance(body.get("workflow_runs"), list) or not isinstance(body.get("total_count"), int):
            raise Refusal(EXIT_REFUSED, "%s: unexpected response shape" % REASON_LIST_UNREADABLE)
        total = body["total_count"]
        runs.extend(body["workflow_runs"])
        if len(body["workflow_runs"]) < PAGE_SIZE:
            break
    else:
        raise Refusal(EXIT_REFUSED, "%s: more than %d pages" % (REASON_LIST_PARTIAL, MAX_PAGES))
    if total is None or len(runs) < total:
        raise Refusal(EXIT_REFUSED, "%s: %d of %d runs" % (REASON_LIST_PARTIAL, len(runs), total or 0))
    return runs


def gh_call(refusal_reason: str, fn: Callable[..., Any], *args: Any) -> Any:
    try:
        return fn(*args)
    except GhError as exc:
        raise Refusal(EXIT_GH, "%s: %s" % (refusal_reason, exc)) from None


# ----------------------------------------------------------- state file ----


class StateStore:
    """The durable record: atomic write (same-directory temp, fsync, rename)."""

    def __init__(self, path: Path, hook: Callable[[str], None] | None = None) -> None:
        self.path = path
        self.hook = hook

    def _hook(self, step: str) -> None:
        if self.hook is not None:
            self.hook(step)

    def read(self) -> list[Entry]:
        try:
            text = self.path.read_text(encoding="utf-8")
        except FileNotFoundError:
            return []
        except (OSError, UnicodeDecodeError) as exc:
            raise Refusal(EXIT_STATE, "%s: %s" % (REASON_STATE_UNREADABLE, type(exc).__name__)) from None
        try:
            doc = json.loads(text)
            if not isinstance(doc, dict) or doc.get("version") != STATE_VERSION or not isinstance(doc.get("entries"), list):
                raise ValueError("shape")
            entries = [Entry(_plain_int(e["run_id"]), _plain_int(e["pr"]), _plain_str(e["head_sha"]), _plain_int(e["attempt"])) for e in doc["entries"]]
            if len({e.run_id for e in entries}) != len(entries):
                raise ValueError("duplicate run id")
        except (ValueError, KeyError, TypeError):
            raise Refusal(EXIT_STATE, "%s: %s" % (REASON_STATE_CORRUPT, self.path.name)) from None
        return entries

    def write(self, entries: Sequence[Entry]) -> None:
        doc = {"version": STATE_VERSION, "entries": [{"run_id": e.run_id, "pr": e.pr, "head_sha": e.head_sha, "attempt": e.attempt} for e in entries]}
        data = (json.dumps(doc, indent=1, sort_keys=True) + "\n").encode("utf-8")
        tmp = self.path.with_name(self.path.name + ".tmp.%d" % os.getpid())
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            try:
                os.write(fd, data)
                os.fsync(fd)
            finally:
                os.close(fd)
            self._hook("temp-written")
            os.replace(tmp, self.path)
            self._hook("renamed")
            dir_fd = os.open(self.path.parent, os.O_RDONLY)
            try:
                os.fsync(dir_fd)
            finally:
                os.close(dir_fd)
        except OSError as exc:
            try:
                tmp.unlink()
            except OSError:
                pass
            raise Refusal(EXIT_STATE, "%s: %s" % (REASON_STATE_UNWRITABLE, type(exc).__name__)) from None
        except BaseException:
            try:
                tmp.unlink()
            except OSError:
                pass
            raise


def _plain_int(value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError("int")
    return value


def _plain_str(value: Any) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError("str")
    return value


class StateLock:
    """Non-blocking exclusive lock beside the state file; a second call refuses."""

    def __init__(self, path: Path) -> None:
        self.path = path.with_name(path.name + LOCK_SUFFIX)
        self.fd: int | None = None

    def __enter__(self) -> "StateLock":
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self.fd = os.open(self.path, os.O_RDWR | os.O_CREAT, 0o600)
            fcntl.flock(self.fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            self._close()
            raise Refusal(EXIT_LOCK, REASON_LOCK_HELD) from None
        except OSError as exc:
            self._close()
            raise Refusal(EXIT_STATE, "%s: lock %s" % (REASON_STATE_UNWRITABLE, type(exc).__name__)) from None
        return self

    def _close(self) -> None:
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None

    def __exit__(self, *exc: object) -> None:
        self._close()


# ------------------------------------------------------------ the call ----


def gather(gh: Any, workflows: Sequence[str]) -> tuple[list[QueuedRun], list[tuple[int, str]]]:
    raw_runs = candidate_runs(fetch_all_runs(gh), workflows)
    waits = {r["id"]: waits_on_self_hosted(gh_call(REASON_JOBS_UNREADABLE, gh.run_jobs, r["id"]), r["id"]) for r in raw_runs}
    pulls = {}
    for raw in raw_runs:
        number = pr_number(raw)
        if waits[raw["id"]] and number not in pulls:
            pulls[number] = gh_call(REASON_GH_FAILED, gh.get_pull, number)
    return build_queue(raw_runs, waits, pulls)


def live_state(gh: Any, entry: Entry) -> Live | None:
    try:
        run = gh.get_run(entry.run_id)
    except GhError as exc:
        if exc.not_found:
            return None
        raise Refusal(EXIT_GH, "%s: run %d: %s" % (REASON_GH_FAILED, entry.run_id, exc)) from None
    status, conclusion = check_status(run if isinstance(run, dict) else {})
    pull = gh_call(REASON_GH_FAILED, gh.get_pull, entry.pr)
    is_open, head, draft, ci_fix = pr_facts(pull, entry.pr)
    return Live(status, conclusion, _int(run.get("run_attempt", 1), "run_attempt"), is_open, head, parse_time(run.get("created_at"), "created_at"), draft, ci_fix)


def run_once(gh: Any, store: StateStore, keep: int, workflows: Sequence[str], execute: bool, resume_only: bool, out: Callable[[str], None]) -> None:
    entries = store.read()
    runs, left_out = gather(gh, workflows)
    plan = plan_queue(runs, keep)
    live = {e.run_id: live_state(gh, e) for e in entries}
    queued_after = len(plan.keep)
    restart = plan_restart(entries, live, queued_after, keep)
    cancel = () if resume_only else plan.cancel
    cancel_ids = {r.run_id for r in cancel}
    dropped = {run_id for run_id, _ in restart.drops} | set(restart.still_queued)
    by_id = {e.run_id: e for e in entries}

    for pos, run in enumerate(plan.keep, 1):
        out("keep %d run %d pr %d" % (pos, run.run_id, run.pr))
    for run in cancel:
        out("cancel run %d pr %d" % (run.run_id, run.pr))
    for run_id, reason in left_out:
        out("left alone run %d: %s" % (run_id, reason))
    for run_id, reason in restart.drops:
        out("drop record run %d: %s" % (run_id, reason))
    for run_id in restart.still_queued:
        out("drop record run %d: still queued" % run_id)
    for run_id in restart.start:
        out("start again run %d" % run_id)
    for run_id in restart.wait:
        out("record kept run %d: waits for a free slot" % run_id)
    if not execute:
        return

    with_new = [e for e in entries if e.run_id not in dropped] + [Entry(r.run_id, r.pr, r.head_sha, r.attempt) for r in cancel if r.run_id not in by_id or r.run_id in dropped]
    store.write(with_new)  # I2: durable before the first cancel (also proves the file is writable)
    for run in reversed(cancel):
        try:
            gh.cancel(run.run_id)
        except GhError as exc:
            raise Refusal(EXIT_GH, "%s: cancel run %d: %s" % (REASON_GH_FAILED, run.run_id, exc)) from None
        out("cancelled run %d" % run.run_id)
    remaining = list(with_new)
    for run_id in restart.start:
        try:
            gh.rerun(run_id)
        except GhError as exc:
            raise Refusal(EXIT_GH, "%s: start run %d: %s" % (REASON_GH_FAILED, run_id, exc)) from None
        remaining = [e for e in remaining if e.run_id != run_id]
        store.write(remaining)
        out("started run %d" % run_id)


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
    try:
        if args.execute:
            with StateLock(args.state_file):
                run_once(client, store, args.keep, tuple(args.workflows or DEFAULT_WORKFLOWS), True, args.resume, emit)
        else:
            run_once(client, store, args.keep, tuple(args.workflows or DEFAULT_WORKFLOWS), False, False, emit)
    except Refusal as refusal:
        print("queue_order: refused: %s" % refusal.reason, file=sys.stderr)
        return refusal.exit_code
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
