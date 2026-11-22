#!/usr/bin/env python3
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""Tests for scripts/ci/queue_order.py (issue 9821, PR 9838): invariants I1 to I5.

Class: queue order and admission for a fixed runner pool.  Expected plans,
reasons and classifications are written out by hand below, never computed from
the code under test.  Run by CI as
`python3 -m unittest discover -s scripts/ci/tests`.  Stdlib only.

PR 9838 round 1 classes pinned here:
  B  no run with a started job is cancelled, for any interleaving of listing,
     pickup and cancel; no action is taken from a record that is not bound to
     the live run (run id, head sha, attempt) and re-read just before the action;
     a restart never races a newer run of the same PR (Interleaving, RecordTable).
  C  a recorded run is restarted once or dropped with a named reason, never lost
     by timing, by an error text or by newer arrivals (RecordTable, GhResponseTable,
     AgingBound, NothingLost); the state file refuses a symlink, a foreign owner,
     a group or world writable mode, an oversize file (StateFileSecurity).
  D  one stray run (no PR, two PRs, a fork) is skipped and named; the other N-1
     runs are still planned (SkipNamed).
"""

from __future__ import annotations

import ast
import importlib.util
import io
import os
import random
import sys
import tempfile
import time
import unittest
from contextlib import redirect_stderr
from pathlib import Path
from unittest import mock

TOOL = Path(os.environ.get("QUEUE_ORDER_UNDER_TEST") or Path(__file__).resolve().parent.parent / "queue_order.py")
SCRATCH = Path(__file__).resolve().parents[3] / ".local-runs"

SEED = 9821
SEQUENCE_COUNT = 150
MAX_CALLS = 6
KEEP = 2
BIG_QUEUE = 5000
BIG_QUEUE_CEILING_SECS = 20.0
SHA_A = "a" * 40
SHA_B = "b" * 40
REPO = "alphaonedev/ai-memory-mcp"
FORK_REPO = "someone/ai-memory-mcp"
STATE_ENTRY_CAP = 1000  # written out: the cap the tool must hold (MAX_STATE_ENTRIES)
STATE_BYTE_CAP = 262144  # written out: MAX_STATE_BYTES
WAIT_CYCLE_BOUND = 5  # written out: MAX_WAIT_CYCLES


def load_tool():
    spec = importlib.util.spec_from_file_location("queue_order", TOOL)
    if spec is None or spec.loader is None:
        raise ImportError("cannot load %s" % TOOL)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module  # dataclasses resolve string annotations through sys.modules
    spec.loader.exec_module(module)
    return module


qo = load_tool()


def stamp(minutes: int) -> str:
    return "2026-11-21T%02d:%02d:00Z" % (10 + minutes // 60, minutes % 60)


def gh_error(status: int):
    """A gh failure with a parsed HTTP status, classified by the tool's own table."""
    return qo.GhError(qo.classify_status(status), status)


class FakeGh:
    """gh double.  Runs are dicts as the API returns them; cancel and rerun mutate them.

    later_run[id]  fields applied at the FIRST get_run of that run (None deletes it):
                   a change between the listing and the cancel.
    later_jobs[id] jobs used from the SECOND run_jobs call of that run on.
    async_cancel   a cancel lands only at tick(), as GitHub's cancel is asynchronous.
    start_at_cancel  runs whose job starts inside the window between the last re-read and the
                   cancel call: the run is picked up first, then the cancel is accepted and lands at tick().
    fail_after_cancel  failures that begin once a cancel call was accepted (the re-read after it).
    """

    def __init__(self) -> None:
        self.runs: dict[int, dict] = {}
        self.jobs: dict[int, list] = {}
        self.pulls: dict[int, dict] = {}
        self.cancels: list[int] = []
        self.reruns: list[int] = []
        self.fail: dict[str, object] = {}
        self.total_override: int | None = None
        self.raw_override = None
        self.async_cancel = False
        self.pending_cancels: list[int] = []
        self.later_run: dict[int, dict | None] = {}
        self.later_jobs: dict[int, list] = {}
        self.jobs_calls: dict[int, int] = {}
        self.start_at_cancel: set[int] = set()
        self.fail_after_cancel: dict[str, object] = {}
        self.on_list = None
        self.list_calls = 0

    def add_pr(self, number: int, draft: bool = False, labels: tuple[str, ...] = (), state: str = "open", sha: str = SHA_A) -> None:
        self.pulls[number] = {"number": number, "draft": draft, "labels": [{"name": n} for n in labels], "state": state, "head": {"sha": sha}}

    def add_run(self, run_id: int, pr: int | None = None, minutes: int = 0, status: str = "queued", conclusion=None, name: str = "CI",
                event: str = "pull_request", branch: str = "fix/x", labels: tuple[str, ...] = ("self-hosted", "linux-fed"), sha: str = SHA_A,
                attempt: int = 1, repo: str | None = REPO) -> None:
        prs = [] if pr is None else [{"number": pr}]
        head_repo = None if repo is None else {"full_name": repo}
        self.runs[run_id] = {"id": run_id, "name": name, "event": event, "head_branch": branch, "head_sha": sha, "status": status, "conclusion": conclusion,
                             "created_at": stamp(minutes), "run_attempt": attempt, "pull_requests": prs, "head_repository": head_repo}
        self.jobs[run_id] = [{"status": "queued", "labels": list(labels)}]

    def _maybe_fail(self, what: str) -> None:
        if what in self.fail:
            raise self.fail[what]

    def tick(self) -> None:
        """The asynchronous cancels land."""
        for run_id in self.pending_cancels:
            if run_id in self.runs and self.runs[run_id]["status"] != "completed":
                self.runs[run_id]["status"] = "completed"
                self.runs[run_id]["conclusion"] = "cancelled"
        self.pending_cancels = []

    def list_runs(self, page: int):
        self._maybe_fail("list_runs")
        if page == 1:
            self.list_calls += 1
            if self.on_list is not None:
                self.on_list(self)
        if self.raw_override is not None:
            return self.raw_override
        # the API filter is status=queued; the double leaks every unfinished run so the tool's own scope check is what is tested
        queued = [r for r in sorted(self.runs.values(), key=lambda r: r["id"]) if r["status"] != "completed"]
        chunk = queued[(page - 1) * qo.PAGE_SIZE:page * qo.PAGE_SIZE]
        total = self.total_override if self.total_override is not None else len(queued)
        return {"total_count": total, "workflow_runs": chunk}

    def list_runs_for_sha(self, sha: str):
        self._maybe_fail("list_runs_for_sha")
        found = [r for r in sorted(self.runs.values(), key=lambda r: r["id"]) if r["head_sha"] == sha]
        return {"total_count": len(found), "workflow_runs": found}

    def run_jobs(self, run_id: int):
        self._maybe_fail("run_jobs")
        self.jobs_calls[run_id] = self.jobs_calls.get(run_id, 0) + 1
        if self.jobs_calls[run_id] >= 2 and run_id in self.later_jobs:
            self.jobs[run_id] = self.later_jobs.pop(run_id)
        jobs = self.jobs[run_id]
        return {"total_count": len(jobs), "jobs": jobs}

    def get_run(self, run_id: int):
        self._maybe_fail("get_run")
        if run_id in self.later_run:
            change = self.later_run.pop(run_id)
            if change is None:
                self.runs.pop(run_id, None)
            else:
                self.runs[run_id].update(change)
        if run_id not in self.runs:
            raise gh_error(404)
        return self.runs[run_id]

    def get_pull(self, number: int):
        self._maybe_fail("get_pull")
        return self.pulls[number]

    def cancel(self, run_id: int) -> None:
        self._maybe_fail("cancel")
        self.cancels.append(run_id)
        self.fail.update(self.fail_after_cancel)
        if run_id in self.start_at_cancel:
            self.runs[run_id]["status"] = "in_progress"
            self.jobs[run_id] = [{"status": "in_progress", "labels": ["self-hosted", "linux-fed"]}]
            self.pending_cancels.append(run_id)
            return
        if self.async_cancel:
            self.pending_cancels.append(run_id)
            return
        self.runs[run_id]["status"] = "completed"
        self.runs[run_id]["conclusion"] = "cancelled"

    def rerun(self, run_id: int) -> None:
        self._maybe_fail("rerun")
        self.reruns.append(run_id)
        run = self.runs[run_id]
        run["status"] = "queued"
        run["conclusion"] = None
        run["run_attempt"] += 1
        self.jobs[run_id] = [{"status": "queued", "labels": ["self-hosted", "linux-fed"]}]


def call(gh: FakeGh, state: Path, *args: str, hook=None) -> tuple[int, list[str], str]:
    lines: list[str] = []
    err = io.StringIO()
    with redirect_stderr(err):
        code = qo.main(["--state-file", str(state), "--keep", str(KEEP), *args], gh=gh, hook=hook, out=lines.append)
    return code, lines, err.getvalue()


def finish(gh: FakeGh, *run_ids: int) -> None:
    for run_id in run_ids:
        gh.runs[run_id]["status"] = "completed"
        gh.runs[run_id]["conclusion"] = "success"


def recorded(state: Path) -> dict[int, object]:
    return {e.run_id: e for e in qo.StateStore(state).read()}


class TestBase(unittest.TestCase):
    def setUp(self) -> None:
        SCRATCH.mkdir(exist_ok=True)
        self._tmp = tempfile.TemporaryDirectory(dir=SCRATCH)
        self.addCleanup(self._tmp.cleanup)
        os.chmod(self._tmp.name, 0o700)
        self.state = Path(self._tmp.name) / "state.json"

    def queue(self, count: int = 5) -> FakeGh:
        gh = FakeGh()
        for i in range(1, count + 1):
            gh.add_pr(i)
            gh.add_run(i, pr=i, minutes=i)
        return gh


def item(run_id: int, ci_fix: bool, draft: bool, minutes: int, waited: int = 0, record: bool = False):
    return qo.QueuedRun(run_id, run_id, SHA_A, qo.parse_time(stamp(minutes), "t"), draft, ci_fix, 1, waited, record)


class OrderTable(unittest.TestCase):
    """I1: hand-written expected orders, one list for live runs and records."""

    def order(self, rows):
        runs = [item(*row) for row in rows]
        plan = qo.plan_order(runs, len(runs), 0)
        return [r.run_id for r in plan.keep + plan.start]

    def test_order_table_i1(self) -> None:
        # (run id, ci_fix, draft, minutes[, waited]) -> expected order, written by hand
        table = [
            ([(1, False, False, 5), (2, True, True, 9)], [2, 1]),                  # ci-fix beats everything, even draft and newer
            ([(1, False, True, 1), (2, False, False, 9)], [2, 1]),                  # non-draft beats older draft
            ([(1, False, False, 9), (2, False, False, 1)], [2, 1]),                 # older first
            ([(7, False, False, 3), (4, False, False, 3)], [4, 7]),                 # tie on age: lower run id
            ([(1, True, True, 4), (2, True, False, 9)], [2, 1]),                    # within ci-fix: non-draft first
            ([(1, True, False, 9), (2, True, False, 2), (3, False, False, 1)], [2, 1, 3]),
            ([(5, False, True, 1), (6, False, True, 1), (3, True, True, 8)], [3, 5, 6]),
            ([(1, True, False, 1), (2, False, True, 9, 5)], [2, 1]),                # aged (waited 5) beats ci-fix
            ([(1, False, True, 1, 5), (2, False, False, 0, 5)], [2, 1]),            # among aged: older first, draft ignored
            ([(1, True, False, 1), (2, False, True, 9, 4)], [1, 2]),                # waited 4 is not aged yet
        ]
        for rows, expected in table:
            with self.subTest(rows=rows):
                self.assertEqual(self.order(rows), expected)

    def test_aging_bound_constant(self) -> None:
        self.assertEqual(qo.MAX_WAIT_CYCLES, WAIT_CYCLE_BOUND)

    def test_order_is_total_and_input_order_independent(self) -> None:
        rng = random.Random(SEED)
        rows = [(i, rng.random() < 0.3, rng.random() < 0.5, rng.randrange(0, 5), rng.randrange(0, 7)) for i in range(1, 40)]
        base = self.order(rows)
        for _ in range(20):
            shuffled = rows[:]
            rng.shuffle(shuffled)
            self.assertEqual(self.order(shuffled), base)

    def test_one_list_split(self) -> None:
        # live 1 and record 2 share the head; live 3 is cancelled, record 4 waits; one job started takes a slot
        runs = [item(1, False, False, 1), item(2, False, False, 2, record=True), item(3, False, False, 3), item(4, False, False, 4, record=True)]
        plan = qo.plan_order(runs, 3, 1)
        self.assertEqual(([r.run_id for r in plan.keep], [r.run_id for r in plan.start]), ([1], [2]))
        self.assertEqual(([r.run_id for r in plan.cancel], [r.run_id for r in plan.wait]), ([3], [4]))
        plan = qo.plan_order(runs, 1, 5)  # more started than slots: no slot, never negative
        self.assertEqual((plan.keep, plan.start), ((), ()))


class GhResponseTable(unittest.TestCase):
    """C (M5): a gh failure is classified from the parsed HTTP status line, never from a substring."""

    ROWS = (
        # (name, returncode, stdout, stderr, expected kind or None for success, expected status)
        ("200 json", 0, "HTTP/2.0 200 OK\r\nContent-Type: application/json\r\n\r\n{\"a\": 1}", "", None, 200),
        ("200 empty body", 0, "HTTP/2.0 204 No Content\r\n\r\n", "", None, 204),
        ("404 status", 1, "HTTP/2.0 404 Not Found\r\n\r\n{\"message\": \"Not Found\"}", "gh: Not Found (HTTP 404)", "NOT_FOUND", 404),
        ("502 with 404 in the run id", 1, "HTTP/2.0 502 Bad Gateway\r\n\r\n", "HTTP 502: Bad Gateway (https://api.github.com/repos/o/r/actions/runs/44044012345)", "SERVER", 502),
        ("502 with Not Found in the body", 1, "HTTP/1.1 502 Bad Gateway\n\n{\"message\": \"Not Found 404\"}", "", "SERVER", 502),
        ("no status, 404 in stderr", 1, "", "HTTP 404: Not Found", "NO_STATUS", None),
        ("no status, 404 in stdout", 1, "{\"message\": \"Not Found\", \"status\": \"404\"}", "", "NO_STATUS", None),
        ("status not at the start", 1, "x HTTP/2.0 404 Not Found\r\n\r\n", "", "NO_STATUS", None),
        ("403", 1, "HTTP/2.0 403 Forbidden\r\n\r\n", "", "FORBIDDEN_OR_RATE_LIMITED", 403),
        ("429", 1, "HTTP/2.0 429 Too Many Requests\r\n\r\n", "", "FORBIDDEN_OR_RATE_LIMITED", 429),
        ("418", 1, "HTTP/2.0 418 I'm a teapot\r\n\r\n", "", "CLIENT", 418),
        ("302", 1, "HTTP/2.0 302 Found\r\n\r\n", "", "UNEXPECTED_STATUS", 302),
        ("200 but gh failed", 1, "HTTP/2.0 200 OK\r\n\r\n{}", "", "UNEXPECTED_STATUS", 200),
        ("200 bad json", 0, "HTTP/2.0 200 OK\r\n\r\nnot json", "", "BAD_BODY", 200),
        ("rc 0 without status", 0, "{\"a\": 1}", "", "BAD_BODY", None),
    )

    def test_rows(self) -> None:
        for name, rc, stdout, stderr, kind, status in self.ROWS:
            with self.subTest(row=name):
                if kind is None:
                    got = qo.parse_gh_response(rc, stdout, stderr)
                    self.assertEqual(got, {"a": 1} if "{\"a\"" in stdout else {})
                    continue
                with self.assertRaises(qo.GhError) as caught:
                    qo.parse_gh_response(rc, stdout, stderr)
                self.assertIs(caught.exception.kind, qo.GhFailure[kind])
                self.assertEqual(caught.exception.status, status)

    def test_message_carries_no_body_text(self) -> None:
        with self.assertRaises(qo.GhError) as caught:
            qo.parse_gh_response(1, "HTTP/2.0 502 Bad Gateway\r\n\r\n{\"message\": \"token ghp_canary\"}", "ghp_canary")
        self.assertEqual(str(caught.exception), "HTTP 502 (server error)")

    def test_oversize_body_refused(self) -> None:
        body = "HTTP/2.0 200 OK\r\n\r\n" + "x" * (qo.MAX_RESPONSE_BYTES + 1)
        with self.assertRaises(qo.GhError) as caught:
            qo.parse_gh_response(0, body, "")
        self.assertIs(caught.exception.kind, qo.GhFailure.BAD_BODY)

    def test_502_on_get_run_keeps_the_record(self) -> None:
        with tempfile.TemporaryDirectory(dir=SCRATCH) as tmp:
            os.chmod(tmp, 0o700)
            state = Path(tmp) / "state.json"
            gh = FakeGh()
            for i in range(1, 4):
                gh.add_pr(i)
                gh.add_run(i, pr=i, minutes=i)
            call(gh, state, "--execute")  # cancels 3
            gh.fail["get_run"] = qo.GhError(qo.GhFailure.SERVER, 502, "HTTP 502: Bad Gateway (runs/44044012345)")
            code, lines, err = call(gh, state, "--execute")
            self.assertEqual(code, qo.EXIT_GH)
            self.assertIn("queue_order: refused: gh call failed: run 3: HTTP 502: Bad Gateway (runs/44044012345)", err)
            self.assertEqual(list(recorded(state)), [3])
            self.assertNotIn("drop record run 3: run no longer exists", lines)


class FailClosedTable(TestBase):
    """I3: one row per malformed form: exit code, exact reason, zero cancels, even with --execute."""

    def test_rows(self) -> None:
        def unknown_status(gh): gh.runs[2]["status"] = "bogus"
        def unknown_conclusion(gh): gh.runs[2]["conclusion"] = "weird"
        def draft_unknown(gh): gh.pulls[2]["draft"] = None
        def labels_unknown(gh): gh.pulls[2]["labels"] = None
        def api_error(gh): gh.fail["list_runs"] = gh_error(500)
        def rate_limit(gh): gh.fail["list_runs"] = gh_error(403)
        def cut_page(gh): gh.total_override = 7
        def bad_shape(gh): gh.raw_override = {"workflow_runs": "x"}
        def jobs_error(gh): gh.fail["run_jobs"] = gh_error(502)
        def pull_error(gh): gh.fail["get_pull"] = gh_error(502)
        def bad_time(gh): gh.runs[2]["created_at"] = "yesterday"
        def pr_state_unknown(gh): gh.pulls[2]["state"] = "merged"
        def bad_branch(gh): gh.runs[2]["head_branch"] = None

        def unstable(gh):
            def grow(fake):
                new_id = 100 + fake.list_calls
                fake.add_pr(new_id)
                fake.add_run(new_id, pr=new_id, minutes=50)
            gh.on_list = grow

        rows = [
            ("unknown status", unknown_status, qo.EXIT_REFUSED, "unknown status 'bogus' in run 2"),
            ("unknown conclusion", unknown_conclusion, qo.EXIT_REFUSED, "unknown conclusion 'weird' in run 2"),
            ("draft unknown", draft_unknown, qo.EXIT_REFUSED, "unknown draft state for pr 2: None"),
            ("labels unknown", labels_unknown, qo.EXIT_REFUSED, "unknown label state for pr 2"),
            ("api error", api_error, qo.EXIT_GH, "run list unreadable: HTTP 500 (server error)"),
            ("rate limit", rate_limit, qo.EXIT_GH, "run list unreadable: HTTP 403 (forbidden or rate limited)"),
            ("pagination cut", cut_page, qo.EXIT_REFUSED, "run list partial: 5 of 7 runs"),
            ("bad shape", bad_shape, qo.EXIT_REFUSED, "run list unreadable: unexpected response shape"),
            ("jobs error", jobs_error, qo.EXIT_GH, "job list unreadable: HTTP 502 (server error)"),
            ("pull error", pull_error, qo.EXIT_GH, "gh call failed: HTTP 502 (server error)"),
            ("bad time", bad_time, qo.EXIT_REFUSED, "unclassifiable input: created_at of run 2: 'yesterday'"),
            ("pr state", pr_state_unknown, qo.EXIT_REFUSED, "unclassifiable input: pr 2 state 'merged'"),
            ("bad branch", bad_branch, qo.EXIT_REFUSED, "unclassifiable input: head_branch of run 2: None"),
            ("listing never stable", unstable, qo.EXIT_REFUSED, "run list unstable: 3 listings disagree"),
        ]
        for label, mutate, code, reason in rows:
            for flags in ((), ("--execute",)):
                with self.subTest(row=label, flags=flags):
                    gh = self.queue()
                    mutate(gh)
                    got, _lines, err = call(gh, self.state, *flags)
                    self.assertEqual(got, code)
                    self.assertIn("queue_order: refused: " + reason, err)
                    self.assertEqual(gh.cancels, [])
                    self.assertFalse(self.state.exists())

    def test_corrupt_state_file(self) -> None:
        good = '{"run_id": 1, "pr": 1, "head_sha": "%s", "attempt": 1, "phase": "cancelled", "waited": 0}' % SHA_A
        texts = (
            "not json", "[]", '{"version": 9, "entries": []}',
            '{"version": 1, "entries": [{"run_id": 1, "pr": 1, "head_sha": "%s", "attempt": 1}]}' % SHA_A,  # version 1 has no binding phase
            '{"version": 2, "entries": [{"run_id": 1}]}',
            '{"version": 2, "entries": [%s]}' % good.replace(SHA_A, "A" * 40),  # sha not lower hex
            '{"version": 2, "entries": [%s]}' % good.replace('"cancelled"', '"done"'),
            '{"version": 2, "entries": [%s]}' % good.replace('"attempt": 1', '"attempt": 0'),
            '{"version": 2, "entries": [%s]}' % good.replace('"waited": 0', '"waited": 0, "extra": 1'),
            '{"version": 2, "entries": [%s, %s]}' % (good, good),
        )
        for text in texts:
            with self.subTest(text=text[:60]):
                self.state.write_text(text)
                os.chmod(self.state, 0o600)
                gh = self.queue()
                got, _lines, err = call(gh, self.state, "--execute")
                self.assertEqual(got, qo.EXIT_STATE)
                self.assertIn("state file corrupt: state.json", err)
                self.assertEqual(gh.cancels, [])

    def test_unreadable_state_file(self) -> None:
        self.state.mkdir()  # a directory where a file belongs
        gh = self.queue()
        got, _lines, err = call(gh, self.state)
        self.assertEqual(got, qo.EXIT_STATE)
        self.assertIn("queue_order: refused: state file unreadable: not a regular file", err)
        self.assertEqual(gh.cancels, [])

    def test_unwritable_state_file_cancels_nothing(self) -> None:
        blocker = Path(self._tmp.name) / "blocker"
        blocker.write_text("x")
        gh = self.queue()
        got, _lines, err = call(gh, blocker / "state.json", "--execute")
        self.assertEqual(got, qo.EXIT_STATE)
        self.assertIn("state file unwritable", err)
        self.assertEqual(gh.cancels, [])


class SkipNamed(TestBase):
    """D: one stray run among N is skipped and named; the other N-1 are planned."""

    def test_one_stray_run_among_n(self) -> None:
        def no_pr(gh): gh.runs[2]["pull_requests"] = []
        def two_prs(gh): gh.runs[2]["pull_requests"] = [{"number": 1}, {"number": 2}]
        def fork(gh): gh.runs[2]["head_repository"] = {"full_name": FORK_REPO}
        def fork_unknown(gh): gh.runs[2]["head_repository"] = None

        rows = (
            ("no pr", no_pr, "run has no pull request"),
            ("two prs", two_prs, "run has more than one pull request"),
            ("fork", fork, "run is from a fork"),
            ("head repository unknown", fork_unknown, "head repository unknown"),
        )
        for label, mutate, reason in rows:
            with self.subTest(row=label):
                gh = self.queue(5)
                mutate(gh)
                state = Path(self._tmp.name) / ("%s.json" % label.replace(" ", "-"))
                code, lines, err = call(gh, state, "--execute")
                self.assertEqual((code, err), (0, ""))
                self.assertIn("skip run 2: " + reason, lines)
                self.assertIn("skipped 1 runs", lines)
                self.assertEqual(lines[:2], ["keep 1 run 1 pr 1", "keep 2 run 3 pr 3"])
                self.assertEqual(sorted(gh.cancels), [4, 5])
                self.assertNotIn(2, gh.cancels)
                self.assertEqual(sorted(recorded(state)), [4, 5])


class ScopeAndReadOnly(TestBase):
    """I4 and the read-only default."""

    def test_scope_rows(self) -> None:
        gh = FakeGh()
        for i in range(1, 8):
            gh.add_pr(i)
        gh.add_run(1, pr=1, minutes=1)
        gh.add_run(2, pr=2, minutes=2, status="in_progress")
        gh.add_run(3, pr=3, minutes=3, name="Other workflow")
        gh.add_run(4, pr=4, minutes=4, event="push", branch="chain/promo6-ssh-r2")
        gh.add_run(5, pr=5, minutes=5, branch="release/v1.0.0")
        gh.add_run(6, pr=6, minutes=6, labels=("ubuntu-latest",))
        gh.add_run(7, pr=7, minutes=7)
        code, lines, _ = call(gh, self.state, "--execute")
        self.assertEqual(code, 0)
        self.assertEqual(gh.cancels, [])  # only runs 1 and 7 are in scope and both are kept (keep 2)
        self.assertIn("keep 1 run 1 pr 1", lines)
        self.assertIn("keep 2 run 7 pr 7", lines)
        self.assertIn("left alone run 6: does not wait on a self-hosted runner", lines)

    def test_in_progress_never_cancelled_with_many_queued(self) -> None:
        gh = self.queue(6)
        gh.add_pr(90)
        gh.add_run(90, pr=90, minutes=0, status="in_progress")
        code, _, _ = call(gh, self.state, "--execute")
        self.assertEqual(code, 0)
        self.assertNotIn(90, gh.cancels)
        self.assertEqual(sorted(gh.cancels), [3, 4, 5, 6])

    def test_plan_without_execute_changes_nothing(self) -> None:
        gh = self.queue(5)
        code, lines, _ = call(gh, self.state)
        self.assertEqual(code, 0)
        self.assertEqual(gh.cancels, [])
        self.assertEqual(gh.reruns, [])
        self.assertFalse(self.state.exists())
        self.assertIn("cancel run 5 pr 5", lines)

    def test_closed_and_superseded_left_out_of_order(self) -> None:
        gh = FakeGh()
        gh.add_pr(1, state="closed")
        gh.add_pr(2, sha=SHA_B)
        gh.add_pr(3)
        gh.add_run(1, pr=1, minutes=1)
        gh.add_run(2, pr=2, minutes=2)
        gh.add_run(3, pr=3, minutes=3)
        _, lines, _ = call(gh, self.state)
        self.assertIn("left alone run 1: pr 1 closed", lines)
        self.assertIn("left alone run 2: superseded by a newer head of pr 2", lines)
        self.assertIn("keep 1 run 3 pr 3", lines)


class Interleaving(TestBase):
    """B (M2, M3, MEDIUM-2, MEDIUM-3): every interleaving of listing, pickup and cancel; exact reasons."""

    def test_cancel_interleavings(self) -> None:
        # (name, change to run 3 after the listing, expected line, run 3 cancelled?)
        rows = (
            ("a job starts after the listing", {"jobs": [{"status": "in_progress", "labels": ["self-hosted", "linux-fed"]}]},
             "left alone run 3: a job has started", False),
            ("a hosted job starts after the listing", {"jobs": [{"status": "in_progress", "labels": ["ubuntu-latest"]},
                                                                {"status": "queued", "labels": ["self-hosted", "linux-fed"]}]},
             "left alone run 3: a job has started", False),
            ("the run is picked up", {"run": {"status": "in_progress"}}, "left alone run 3: run is no longer queued (status in_progress)", False),
            ("the run is re-attempted", {"run": {"run_attempt": 2}}, "left alone run 3: run changed since the listing: attempt", False),
            ("the run head moves", {"run": {"head_sha": SHA_B}}, "left alone run 3: run changed since the listing: head sha", False),
            ("the run is deleted", {"run": None}, "left alone run 3: run no longer exists", False),
            ("nothing changes", {}, "cancelled run 3", True),
        )
        for name, change, line, cancelled in rows:
            with self.subTest(row=name):
                gh = self.queue(3)
                if "jobs" in change:
                    gh.later_jobs[3] = change["jobs"]
                if "run" in change:
                    gh.later_run[3] = change["run"]
                state = Path(self._tmp.name) / ("%d.json" % len(name))
                code, lines, err = call(gh, state, "--execute")
                self.assertEqual((code, err), (0, ""))
                self.assertIn(line, lines)
                self.assertEqual(3 in gh.cancels, cancelled)
                self.assertEqual(3 in recorded(state), cancelled)

    def test_a_started_hosted_job_keeps_the_run(self) -> None:
        # M2 probe P1: run 3 has a hosted job in progress and a self-hosted job queued from the start
        gh = self.queue(4)
        gh.jobs[3] = [{"status": "in_progress", "labels": ["ubuntu-latest"]}, {"status": "queued", "labels": ["self-hosted", "linux-fed"]}]
        code, lines, _ = call(gh, self.state, "--execute")
        self.assertEqual(code, 0)
        self.assertIn("keep run 3 pr 3: a job has started", lines)
        self.assertNotIn(3, gh.cancels)
        self.assertEqual(lines[:1], ["keep 1 run 1 pr 1"])  # the started run takes one of the two slots
        self.assertEqual(sorted(gh.cancels), [2, 4])

    def test_restart_never_races_a_newer_run_of_the_pr(self) -> None:
        # M3: record of run 3 (cancelled); PR 3 is marked ready, run 9 starts on the same sha
        gh = self.queue(3)
        call(gh, self.state, "--execute")
        self.assertEqual(gh.cancels, [3])
        finish(gh, 1, 2)
        gh.add_run(9, pr=3, minutes=40, status="in_progress")
        code, lines, _ = call(gh, self.state, "--execute")
        self.assertEqual(code, 0)
        self.assertIn("drop record run 3: newer run of pr 3 exists: run 9", lines)
        self.assertEqual(gh.reruns, [])
        self.assertEqual(recorded(self.state), {})

    def test_forged_or_stale_record_rows(self) -> None:
        # MEDIUM-2: a record is acted on only when it is bound to the live run and the run is in scope
        def entry(**kw):
            base = {"run_id": 7, "pr": 50, "head_sha": SHA_A, "attempt": 1, "phase": qo.Phase.CANCELLED, "waited": 0}
            base.update(kw)
            return qo.BoundEntry(**base)

        rows = (
            ("push run of another workflow, other sha", dict(name="Release", event="push", branch="release/v1.0.0", sha=SHA_B, pr=None),
             entry(), "drop record run 7: record does not match run 7: head sha"),
            ("push run, same sha", dict(name="CI", event="push", branch="fix/x", pr=None), entry(), "drop record run 7: record out of scope: event push"),
            ("other workflow, same sha", dict(name="Release", pr=50), entry(), "drop record run 7: record out of scope: workflow 'Release'"),
            ("protected branch", dict(branch="release/v1.0.0", pr=50), entry(), "drop record run 7: record out of scope: protected branch release/v1.0.0"),
            ("other pr", dict(pr=51), entry(), "drop record run 7: record does not match run 7: pr"),
            ("fork run", dict(pr=50, repo=FORK_REPO), entry(), "drop record run 7: record out of scope: run is from a fork"),
            ("attempt went back", dict(pr=50, attempt=1), entry(attempt=2), "drop record run 7: record does not match run 7: attempt"),
            ("attempt moved on", dict(pr=50, attempt=2, status="queued", conclusion=None), entry(),
             "drop record run 7: started again (status queued, attempt 2)"),
        )
        for name, run_kw, bound, line in rows:
            with self.subTest(row=name):
                gh = FakeGh()
                gh.add_pr(50)
                gh.add_pr(51)
                kw = dict(status="completed", conclusion="cancelled")
                kw.update(run_kw)
                gh.add_run(7, **kw)
                state = Path(self._tmp.name) / ("%d.json" % len(name))
                qo.StateStore(state).write([bound])
                code, lines, err = call(gh, state, "--execute")
                self.assertEqual((code, err), (0, ""))
                self.assertIn(line, lines)
                self.assertEqual(gh.reruns, [])
                self.assertEqual(recorded(state), {})


class RecordTable(TestBase):
    """C (M4, M6): what happens to a record, from the record and the live run; hand-written."""

    def entry(self, phase, attempt=1, waited=0):
        return qo.BoundEntry(3, 3, SHA_A, attempt, phase, waited)

    def live_run(self, status="completed", conclusion="cancelled", attempt=1):
        return {"id": 3, "name": "CI", "event": "pull_request", "head_branch": "fix/x", "head_sha": SHA_A, "status": status, "conclusion": conclusion,
                "created_at": stamp(3), "run_attempt": attempt, "pull_requests": [{"number": 3}], "head_repository": {"full_name": REPO}}

    def test_judge_rows(self) -> None:
        cancelled, restarted = qo.Phase.CANCELLED, qo.Phase.RESTARTED
        open_pr = qo.PrFacts(True, SHA_A, False, False)
        rows = (
            # (name, entry, live run or None, pr facts, newer run, disposition, reason)
            ("gone", self.entry(cancelled), None, open_pr, None, "DROP", "run no longer exists"),
            ("cancel pending", self.entry(cancelled), self.live_run("queued", None), open_pr, None, "PENDING", "cancel pending"),
            ("cancel never landed, run started", self.entry(cancelled), self.live_run("in_progress", None), open_pr, None, "DROP",
             "started again (status in_progress, attempt 1)"),
            ("finished", self.entry(cancelled), self.live_run("completed", "success"), open_pr, None, "DROP", "finished (conclusion success)"),
            ("pr closed", self.entry(cancelled), self.live_run(), qo.PrFacts(False, SHA_A, False, False), None, "DROP", "pr 3 closed"),
            ("superseded", self.entry(cancelled), self.live_run(), qo.PrFacts(True, SHA_B, False, False), None, "DROP", "superseded by a newer head of pr 3"),
            ("newer run", self.entry(cancelled), self.live_run(), open_pr, 9, "DROP", "newer run of pr 3 exists: run 9"),
            ("restartable", self.entry(cancelled), self.live_run(), open_pr, None, "RESTARTABLE", ""),
            ("restarted, queued again", self.entry(restarted, 2), self.live_run("queued", None, 2), open_pr, None, "REQUEUED", ""),
            ("restarted, running", self.entry(restarted, 2), self.live_run("in_progress", None, 2), open_pr, None, "DROP",
             "restarted run left the queue (status in_progress)"),
            ("restarted, finished", self.entry(restarted, 2), self.live_run("completed", "success", 2), open_pr, None, "DROP",
             "restarted run left the queue (status completed)"),
            ("restarted, re-run again", self.entry(restarted, 2), self.live_run("queued", None, 3), open_pr, None, "DROP",
             "started again (status queued, attempt 3)"),
        )
        scope = qo.Scope(("CI",), REPO)
        for name, bound, live, facts, newer, kind, reason in rows:
            with self.subTest(row=name):
                got = qo.judge(bound, live, scope, lambda _n, facts=facts: facts, lambda _e, _name, newer=newer: newer)
                self.assertEqual((got.kind, got.reason), (qo.Disposition[kind], reason))

    def test_cancel_that_lands_after_the_next_call_keeps_its_record(self) -> None:
        # M4 probe P2: an asynchronous cancel
        gh = self.queue(3)
        gh.async_cancel = True
        call(gh, self.state, "--execute")
        self.assertEqual(gh.cancels, [3])
        code, lines, _ = call(gh, self.state, "--execute")  # the cancel has not landed yet
        self.assertEqual(code, 0)
        self.assertIn("record kept run 3: cancel pending", lines)
        self.assertNotIn("keep 2 run 3 pr 3", lines)
        self.assertEqual(gh.cancels, [3])  # never cancelled twice
        self.assertEqual(list(recorded(self.state)), [3])
        gh.tick()
        finish(gh, 1, 2)
        call(gh, self.state, "--execute")
        self.assertEqual(gh.reruns, [3])
        self.assertIs(recorded(self.state)[3].phase, qo.Phase.RESTARTED)

    def test_cancel_failure_keeps_record(self) -> None:
        gh = self.queue(4)
        gh.fail["cancel"] = gh_error(500)
        code, _, err = call(gh, self.state, "--execute")
        self.assertEqual(code, qo.EXIT_GH)
        self.assertIn("queue_order: refused: gh call failed: cancel run 4: HTTP 500 (server error)", err)
        self.assertEqual(set(recorded(self.state)), {3, 4})  # recorded before the cancel that failed


class CancelWindow(TestBase):
    """G (9860): the check-then-cancel window.  GitHub has no conditional cancel, so a job can start between the
    re-read and the call; the re-read after the call finds it and the record restarts the run exactly once.
    Every interleaving is driven by the fake gh (no sleep); reasons are exact."""

    def test_interleavings(self) -> None:
        # (name, setup of run 3, expected line, cancel sent?, recorded phase or None)
        rows = (
            ("start before the re-read", lambda gh: gh.later_jobs.update({3: [{"status": "in_progress", "labels": ["self-hosted", "linux-fed"]}]}),
             "left alone run 3: a job has started", False, None),
            ("start between re-read and cancel", lambda gh: gh.start_at_cancel.add(3), "cancelled run 3: cancel raced a start", True, "CANCELLING"),
            ("no start", lambda gh: None, "cancelled run 3", True, "CANCELLED"),
            ("no start, the cancel lands later", lambda gh: setattr(gh, "async_cancel", True), "cancelled run 3: cancel pending", True, "CANCELLING"),
        )
        for pos, (name, setup, line, sent, phase) in enumerate(rows):
            with self.subTest(row=name):
                gh = self.queue(3)
                setup(gh)
                state = Path(self._tmp.name) / ("w%d.json" % pos)
                code, lines, err = call(gh, state, "--execute")
                self.assertEqual((code, err), (0, ""))
                self.assertIn(line, lines)
                self.assertEqual(gh.cancels, [3] if sent else [])
                got = recorded(state)
                self.assertEqual(got[3].phase if 3 in got else None, None if phase is None else qo.Phase[phase])

    def test_raced_run_restarts_exactly_once(self) -> None:
        gh = self.queue(3)
        gh.start_at_cancel.add(3)
        call(gh, self.state, "--execute")
        code, lines, _ = call(gh, self.state, "--execute")  # the run is running and the cancel has not landed
        self.assertEqual(code, 0)
        self.assertIn("record kept run 3: cancel raced a start", lines)
        self.assertEqual((gh.cancels, gh.reruns), ([3], []))
        gh.tick()
        finish(gh, 1, 2)
        _, lines, _ = call(gh, self.state, "--execute")
        self.assertIn("started run 3", lines)
        self.assertEqual(gh.reruns, [3])
        self.assertIs(recorded(self.state)[3].phase, qo.Phase.RESTARTED)
        for _ in range(3):
            call(gh, self.state, "--execute")
        self.assertEqual((gh.cancels, gh.reruns), ([3], [3]))

    def test_re_read_after_the_cancel_fails(self) -> None:
        gh = self.queue(4)  # cancels 4 first, then 3
        gh.fail_after_cancel["get_run"] = gh_error(500)
        code, lines, err = call(gh, self.state, "--execute")
        self.assertEqual(code, qo.EXIT_GH)
        self.assertIn("cancelled run 4: cancel not confirmed", lines)
        self.assertIn("queue_order: refused: gh call failed: run 4: HTTP 500 (server error)", err)
        self.assertEqual(gh.cancels, [4])
        state = recorded(self.state)
        self.assertEqual(sorted(state), [4])  # run 3 was never cancelled, so it has no record
        self.assertIs(state[4].phase, qo.Phase.CANCELLING)

    def test_judge_rows_of_an_unconfirmed_cancel(self) -> None:
        open_pr = qo.PrFacts(True, SHA_A, False, False)
        rows = (
            # (name, live run status, conclusion, newer run, disposition, reason)
            ("cancel not landed", "queued", None, None, "PENDING", "cancel pending"),
            ("cancel raced a start", "in_progress", None, None, "PENDING", "cancel raced a start"),
            ("raced run finished", "completed", "success", None, "DROP", "finished (conclusion success)"),
            ("cancel landed", "completed", "cancelled", None, "RESTARTABLE", ""),
            ("cancel landed, newer run", "completed", "cancelled", 9, "DROP", "newer run of pr 3 exists: run 9"),
        )
        scope = qo.Scope(("CI",), REPO)
        for name, status, conclusion, newer, kind, reason in rows:
            with self.subTest(row=name):
                gh = FakeGh()
                gh.add_run(3, pr=3, minutes=3, status=status, conclusion=conclusion)
                entry = qo.BoundEntry(3, 3, SHA_A, 1, qo.Phase.CANCELLING, 0)
                got = qo.judge(entry, gh.runs[3], scope, lambda _n: open_pr, lambda _e, _name, newer=newer: newer)
                self.assertEqual((got.kind, got.reason), (qo.Disposition[kind], reason))


class AgingBound(TestBase):
    """C (M6): newer arrivals never starve a record; it starts within MAX_WAIT_CYCLES + 1 calls."""

    def test_record_starts_within_the_bound_under_constant_arrivals(self) -> None:
        gh = FakeGh()
        gh.add_pr(1)
        gh.add_pr(2)
        gh.add_pr(3, draft=True)
        for i in (1, 2, 3):
            gh.add_run(i, pr=i, minutes=i)
        call(gh, self.state, "--execute")
        self.assertEqual(gh.cancels, [3])
        next_id = 10
        for cycle in range(1, WAIT_CYCLE_BOUND + 2):
            for run_id in [i for i, r in gh.runs.items() if r["status"] == "queued" and i not in gh.reruns]:
                finish(gh, run_id)  # the kept runs got runners and finished
            for _ in range(KEEP):  # newer ci-fix arrivals every cycle, more than the free slots
                gh.add_pr(next_id, labels=("ci-fix",))
                gh.add_run(next_id, pr=next_id, minutes=100 + next_id)
                next_id += 1
            call(gh, self.state, "--execute")
            if gh.reruns:
                break
        self.assertEqual(gh.reruns, [3])
        self.assertLessEqual(cycle, WAIT_CYCLE_BOUND + 1)


class Execution(TestBase):
    """I1 end to end, I2 sequencing, idempotence and the lock."""

    def test_ci_fix_first_in_execute(self) -> None:
        gh = self.queue(4)
        gh.add_pr(4, labels=("ci-fix",))  # the newest run carries the label
        code, lines, _ = call(gh, self.state, "--execute")
        self.assertEqual(code, 0)
        self.assertEqual(lines[:2], ["keep 1 run 4 pr 4", "keep 2 run 1 pr 1"])
        self.assertEqual(sorted(gh.cancels), [2, 3])

    def test_record_written_before_every_cancel(self) -> None:
        gh = self.queue(4)
        seen: list[int] = []
        original = gh.cancel

        def watching(run_id: int) -> None:
            self.assertIn(run_id, recorded(self.state), "cancel before the durable record")
            seen.append(run_id)
            original(run_id)

        gh.cancel = watching
        call(gh, self.state, "--execute")
        self.assertEqual(sorted(seen), [3, 4])

    def test_idempotent_repeat(self) -> None:
        gh = self.queue(4)
        call(gh, self.state, "--execute")
        first = sorted(gh.cancels)
        call(gh, self.state, "--execute", "--resume")
        call(gh, self.state, "--execute")
        self.assertEqual(sorted(set(gh.cancels)), first)
        self.assertEqual(len(gh.cancels), len(first))

    def test_restart_in_order_into_free_slots(self) -> None:
        gh = self.queue(4)
        call(gh, self.state, "--execute")  # keeps 1 and 2, cancels 3 and 4
        self.assertEqual(gh.reruns, [])
        finish(gh, 1, 2)
        code, lines, _ = call(gh, self.state, "--execute", "--resume")
        self.assertEqual(code, 0)
        self.assertEqual(gh.reruns, [3, 4])
        self.assertEqual(lines[-2:], ["started run 3", "started run 4"])
        state = recorded(self.state)
        self.assertEqual([(e.run_id, e.phase, e.attempt) for e in state.values()], [(3, qo.Phase.RESTARTED, 2), (4, qo.Phase.RESTARTED, 2)])
        gh.runs[3]["status"] = "in_progress"
        finish(gh, 4)
        _, lines, _ = call(gh, self.state, "--execute")
        self.assertIn("drop record run 3: restarted run left the queue (status in_progress)", lines)
        self.assertIn("drop record run 4: restarted run left the queue (status completed)", lines)
        self.assertEqual(gh.reruns, [3, 4])  # restarted exactly once
        self.assertEqual(recorded(self.state), {})

    def test_resume_never_cancels(self) -> None:
        gh = self.queue(5)
        call(gh, self.state, "--execute", "--resume")
        self.assertEqual(gh.cancels, [])

    def test_drops_with_printed_reason(self) -> None:
        gh = self.queue(5)
        call(gh, self.state, "--execute")  # cancels 3, 4, 5
        finish(gh, 1, 2)
        gh.pulls[3]["state"] = "closed"
        gh.pulls[4]["head"]["sha"] = SHA_B
        gh.runs[5]["run_attempt"] = 2
        gh.runs[5]["status"] = "in_progress"
        code, lines, _ = call(gh, self.state, "--execute", "--resume")
        self.assertEqual(code, 0)
        self.assertIn("drop record run 3: pr 3 closed", lines)
        self.assertIn("drop record run 4: superseded by a newer head of pr 4", lines)
        self.assertIn("drop record run 5: started again (status in_progress, attempt 2)", lines)
        self.assertEqual(gh.reruns, [])
        self.assertEqual(recorded(self.state), {})

    def test_deleted_run_dropped(self) -> None:
        gh = self.queue(3)
        call(gh, self.state, "--execute")
        del gh.runs[3]
        _, lines, _ = call(gh, self.state, "--execute", "--resume")
        self.assertIn("drop record run 3: run no longer exists", lines)

    def test_restart_re_reads_the_run(self) -> None:
        # the run is deleted between the plan and the restart: dropped, never rerun
        gh = self.queue(3)
        call(gh, self.state, "--execute")
        finish(gh, 1, 2)
        real_get = gh.get_run
        calls = {"n": 0}

        def second_read_404(run_id):
            calls["n"] += 1
            if run_id == 3 and calls["n"] >= 2:
                raise gh_error(404)
            return real_get(run_id)

        gh.get_run = second_read_404
        _, lines, _ = call(gh, self.state, "--execute")
        self.assertIn("start again run 3", lines)
        self.assertIn("drop record run 3: run no longer exists", lines)
        self.assertEqual(gh.reruns, [])

    def test_lock_refuses_second_call(self) -> None:
        gh = self.queue(4)
        with qo.StateLock(self.state):
            code, _, err = call(gh, self.state, "--execute")
        self.assertEqual(code, qo.EXIT_LOCK)
        self.assertIn("another call holds the state lock", err)
        self.assertEqual(gh.cancels, [])


class StateFileSecurity(TestBase):
    """C (LOW-2, LOW-6): symlink, owner, mode, size, TOCTOU and the temp name."""

    def good_state(self) -> None:
        qo.StateStore(self.state).write([qo.BoundEntry(3, 3, SHA_A, 1, qo.Phase.CANCELLED, 0)])

    def refused(self, *flags: str) -> str:
        gh = self.queue(3)
        code, _lines, err = call(gh, self.state, *flags)
        self.assertEqual(code, qo.EXIT_STATE)
        self.assertEqual(gh.cancels, [])
        return err

    def test_symlinked_state_file_refused(self) -> None:
        target = Path(self._tmp.name) / "target.json"
        qo.StateStore(target).write([])
        self.state.symlink_to(target)
        for flags in ((), ("--execute",)):
            with self.subTest(flags=flags):
                self.assertIn("queue_order: refused: state file unreadable: is a symlink", self.refused(*flags))
        self.assertTrue(self.state.is_symlink())

    def test_symlinked_lock_refused(self) -> None:
        victim = Path(self._tmp.name) / "victim"
        victim.write_text("keep")
        Path(str(self.state) + qo.LOCK_SUFFIX).symlink_to(victim)
        self.assertIn("queue_order: refused: state file unwritable: lock is a symlink", self.refused("--execute"))
        self.assertEqual(victim.read_text(), "keep")

    def test_group_or_world_writable_refused(self) -> None:
        for mode in (0o620, 0o602, 0o666):
            with self.subTest(mode=oct(mode)):
                self.good_state()
                os.chmod(self.state, mode)
                self.assertIn("queue_order: refused: state file unreadable: group or world writable", self.refused())

    def test_foreign_owner_refused(self) -> None:
        self.good_state()
        with mock.patch.object(qo.os, "geteuid", return_value=os.geteuid() + 1):
            self.assertIn("queue_order: refused: state file unreadable: directory not owned by this user", self.refused())

    def test_open_directory_refused(self) -> None:
        self.good_state()
        os.chmod(self._tmp.name, 0o777)
        try:
            self.assertIn("queue_order: refused: state file unreadable: directory group or world writable", self.refused())
        finally:
            os.chmod(self._tmp.name, 0o700)

    def test_oversize_refused(self) -> None:
        self.state.write_bytes(b" " * (STATE_BYTE_CAP + 1))
        os.chmod(self.state, 0o600)
        self.assertIn("queue_order: refused: state file unreadable: larger than %d bytes" % STATE_BYTE_CAP, self.refused())

    def test_too_many_entries_refused(self) -> None:
        entry = '{"run_id": %d, "pr": 1, "head_sha": "%s", "attempt": 1, "phase": "cancelled", "waited": 0}'
        body = ", ".join(entry % (i, SHA_A) for i in range(1, STATE_ENTRY_CAP + 2))
        self.state.write_text('{"version": 2, "entries": [%s]}' % body)
        os.chmod(self.state, 0o600)
        self.assertEqual(qo.MAX_STATE_ENTRIES, STATE_ENTRY_CAP)
        self.assertEqual(qo.MAX_STATE_BYTES, STATE_BYTE_CAP)
        self.assertIn("queue_order: refused: state file corrupt: state.json", self.refused())

    def test_read_is_bound_to_the_opened_file(self) -> None:
        # TOCTOU: the path is swapped for a symlink after the open; the read still uses the opened file
        self.good_state()
        other = Path(self._tmp.name) / "other.json"
        qo.StateStore(other).write([])

        def swap(step: str) -> None:
            if step == "opened":
                self.state.unlink()
                self.state.symlink_to(other)

        entries = qo.StateStore(self.state, swap).read()
        self.assertEqual([e.run_id for e in entries], [3])

    def test_write_never_follows_a_planted_temp_name(self) -> None:
        victim = Path(self._tmp.name) / "victim"
        victim.write_text("keep")
        for name in ("state.json.tmp.%d" % os.getpid(), "state.json.tmp"):
            (Path(self._tmp.name) / name).symlink_to(victim)
        self.good_state()
        self.assertEqual(victim.read_text(), "keep")
        self.assertEqual(os.stat(self.state).st_mode & 0o777, 0o600)
        self.assertFalse(self.state.is_symlink())

    def test_crash_during_write_leaves_old_record(self) -> None:
        store = qo.StateStore(self.state)
        store.write([qo.BoundEntry(1, 1, SHA_A, 1, qo.Phase.CANCELLED, 0)])

        def crash(step: str) -> None:
            if step == "temp-written":
                raise RuntimeError("crash")

        store.hook = crash
        with self.assertRaises(RuntimeError):
            store.write([qo.BoundEntry(2, 2, SHA_A, 1, qo.Phase.CANCELLED, 0)])
        self.assertEqual([e.run_id for e in qo.StateStore(self.state).read()], [1])
        self.assertEqual([p.name for p in self.state.parent.iterdir() if ".tmp" in p.name], [])


class NothingLost(TestBase):
    """I2: generated call sequences with injected failures and asynchronous cancels at every step."""

    def present(self, gh: FakeGh, state: Path) -> set[int]:
        queued = {i for i, r in gh.runs.items() if r["status"] == "queued"}
        kept = set(recorded(state)) if state.exists() else set()
        running = {i for i, r in gh.runs.items() if r["status"] == "in_progress"}
        finished = {i for i, r in gh.runs.items() if r["status"] == "completed" and r["conclusion"] != "cancelled"}
        return queued | kept | running | finished

    def test_property_no_run_lost(self) -> None:
        rng = random.Random(SEED)
        steps = ("list_runs", "run_jobs", "get_pull", "cancel", "rerun", "get_run", "list_runs_for_sha")
        for seq in range(SEQUENCE_COUNT):
            with self.subTest(seq=seq):
                gh = FakeGh()
                gh.async_cancel = rng.random() < 0.5
                count = rng.randrange(3, 9)
                for i in range(1, count + 1):
                    gh.add_pr(i, draft=rng.random() < 0.4, labels=("ci-fix",) if rng.random() < 0.2 else ())
                    gh.add_run(i, pr=i, minutes=rng.randrange(0, 30))
                initial = set(gh.runs)
                state = Path(self._tmp.name) / ("s%d.json" % seq)
                for _ in range(rng.randrange(2, MAX_CALLS + 1)):
                    gh.fail = {}
                    if rng.random() < 0.5:
                        gh.fail[rng.choice(steps)] = gh_error(rng.choice((500, 502, 403)))
                    crash_at = rng.choice([None, "temp-written", "renamed"])

                    def hook(step: str, crash_at=crash_at) -> None:
                        if step == crash_at:
                            raise RuntimeError("crash")

                    flags = ["--execute"] + (["--resume"] if rng.random() < 0.3 else [])
                    try:
                        call(gh, state, *flags, hook=hook)
                    except RuntimeError:
                        pass
                    if rng.random() < 0.5:
                        gh.tick()
                    if rng.random() < 0.4:  # a kept run starts on a runner
                        waiting = [i for i, r in gh.runs.items() if r["status"] == "queued"]
                        if waiting:
                            gh.runs[rng.choice(waiting)]["status"] = "in_progress"
                    gh.tick() if rng.random() < 0.2 else None
                    self.assertEqual(initial - self.present(gh, state), set(), "runs lost after a call")

    def test_crash_between_record_and_cancel(self) -> None:
        gh = self.queue(4)

        def crash(step: str) -> None:
            if step == "renamed":
                raise RuntimeError("crash after the record became durable")

        with self.assertRaises(RuntimeError):
            call(gh, self.state, "--execute", hook=crash)
        self.assertEqual(gh.cancels, [])
        self.assertEqual(set(recorded(self.state)), {3, 4})
        code, lines, _ = call(gh, self.state, "--execute")
        self.assertEqual(code, 0)
        # the records of the cancels that never went out are pending; the runs are still queued, nothing is lost
        self.assertIn("record kept run 3: cancel pending", lines)
        self.assertEqual(gh.cancels, [])


class SingleCaller(unittest.TestCase):
    """B: one function is the only caller of each mutating gh API (an allowlist over the whole module)."""

    ALLOWED = {"cancel": ["cancel_checked"], "rerun": ["restart_checked"]}

    def test_cancel_and_rerun_have_one_caller(self) -> None:
        tree = ast.parse(TOOL.read_text(encoding="utf-8"))
        callers: dict[str, list[str]] = {"cancel": [], "rerun": []}
        names_used: list[str] = []

        def walk(node: ast.AST, owner: str) -> None:
            for child in ast.iter_child_nodes(node):
                here = child.name if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)) else owner
                if isinstance(child, ast.Call) and isinstance(child.func, ast.Attribute) and child.func.attr in callers:
                    callers[child.func.attr].append(owner)
                if isinstance(child, ast.Attribute) and child.attr in callers and not isinstance(getattr(child, "_parent_call", None), ast.Call):
                    names_used.append("%s:%s" % (owner, child.attr))
                if isinstance(child, ast.Call) and isinstance(child.func, ast.Name) and child.func.id == "getattr":
                    names_used.append("%s:getattr" % owner)
                walk(child, here)

        walk(tree, "<module>")
        self.assertEqual(callers, self.ALLOWED)
        # every attribute reference to cancel/rerun is the one call (no alias such as `c = gh.cancel`), and no getattr
        self.assertEqual(sorted(names_used), ["cancel_checked:cancel", "restart_checked:rerun"])


class Size(TestBase):
    def test_big_queue_under_ceiling(self) -> None:
        runs = [item(i, i % 17 == 0, i % 3 == 0, i % 600, i % 7) for i in range(1, BIG_QUEUE + 1)]
        started = time.monotonic()
        plan = qo.plan_order(runs, 4, 0)
        elapsed = time.monotonic() - started
        self.assertEqual(len(plan.keep) + len(plan.cancel), BIG_QUEUE)
        self.assertLess(elapsed, BIG_QUEUE_CEILING_SECS)

    def test_big_execute_under_ceiling_and_state_cap(self) -> None:
        gh = FakeGh()
        for i in range(1, BIG_QUEUE + 1):
            gh.add_pr(i)
            gh.add_run(i, pr=i, minutes=i % 600)
        started = time.monotonic()
        code, lines, _ = call(gh, self.state, "--execute")
        elapsed = time.monotonic() - started
        self.assertEqual(code, 0)
        self.assertEqual(len(gh.cancels), STATE_ENTRY_CAP)
        self.assertEqual(len(recorded(self.state)), STATE_ENTRY_CAP)
        self.assertEqual(sum(1 for line in lines if line.endswith(": state file full")), BIG_QUEUE - KEEP - STATE_ENTRY_CAP)
        self.assertLessEqual(self.state.stat().st_size, STATE_BYTE_CAP)
        self.assertLess(elapsed, BIG_QUEUE_CEILING_SECS)


if __name__ == "__main__":
    unittest.main()
