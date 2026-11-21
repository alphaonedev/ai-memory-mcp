#!/usr/bin/env python3
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""Tests for scripts/ci/queue_order.py (issue 9821): invariants I1 to I4.

Class: queue order and admission for a fixed runner pool.  Expected plans are
written out by hand below, never computed from the code under test.  Run by CI
as `python3 -m unittest discover -s scripts/ci/tests`.  Stdlib only.
"""

from __future__ import annotations

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


class FakeGh:
    """gh double.  Runs are dicts as the API returns them; cancel and rerun mutate them."""

    def __init__(self) -> None:
        self.runs: dict[int, dict] = {}
        self.jobs: dict[int, list] = {}
        self.pulls: dict[int, dict] = {}
        self.cancels: list[int] = []
        self.reruns: list[int] = []
        self.fail: dict[str, qo.GhError] = {}
        self.total_override: int | None = None
        self.raw_override = None

    def add_pr(self, number: int, draft: bool = False, labels: tuple[str, ...] = (), state: str = "open", sha: str = SHA_A) -> None:
        self.pulls[number] = {"number": number, "draft": draft, "labels": [{"name": n} for n in labels], "state": state, "head": {"sha": sha}}

    def add_run(self, run_id: int, pr: int | None = None, minutes: int = 0, status: str = "queued", conclusion=None, name: str = "CI",
                event: str = "pull_request", branch: str = "fix/x", labels: tuple[str, ...] = ("self-hosted", "linux-fed"), sha: str = SHA_A, attempt: int = 1) -> None:
        prs = [] if pr is None else [{"number": pr}]
        self.runs[run_id] = {"id": run_id, "name": name, "event": event, "head_branch": branch, "head_sha": sha, "status": status, "conclusion": conclusion,
                             "created_at": stamp(minutes), "run_attempt": attempt, "pull_requests": prs}
        self.jobs[run_id] = [{"status": "queued", "labels": list(labels)}]

    def _maybe_fail(self, what: str) -> None:
        if what in self.fail:
            raise self.fail[what]

    def list_runs(self, page: int):
        self._maybe_fail("list_runs")
        if self.raw_override is not None:
            return self.raw_override
        # the API filter is status=queued; the double leaks every unfinished run so the tool's own scope check is what is tested
        queued = [r for r in sorted(self.runs.values(), key=lambda r: r["id"]) if r["status"] != "completed"]
        chunk = queued[(page - 1) * qo.PAGE_SIZE:page * qo.PAGE_SIZE]
        total = self.total_override if self.total_override is not None else len(queued)
        return {"total_count": total, "workflow_runs": chunk}

    def run_jobs(self, run_id: int):
        self._maybe_fail("run_jobs")
        jobs = self.jobs[run_id]
        return {"total_count": len(jobs), "jobs": jobs}

    def get_run(self, run_id: int):
        self._maybe_fail("get_run")
        if run_id not in self.runs:
            raise qo.GhError("HTTP 404 Not Found", not_found=True)
        return self.runs[run_id]

    def get_pull(self, number: int):
        self._maybe_fail("get_pull")
        return self.pulls[number]

    def cancel(self, run_id: int) -> None:
        self._maybe_fail("cancel")
        self.cancels.append(run_id)
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


class TestBase(unittest.TestCase):
    def setUp(self) -> None:
        SCRATCH.mkdir(exist_ok=True)
        self._tmp = tempfile.TemporaryDirectory(dir=SCRATCH)
        self.addCleanup(self._tmp.cleanup)
        self.state = Path(self._tmp.name) / "state.json"


class OrderTable(unittest.TestCase):
    """I1: hand-written expected orders."""

    def run_of(self, run_id: int, ci_fix: bool, draft: bool, minutes: int):
        return qo.QueuedRun(run_id, run_id, SHA_A, qo.parse_time(stamp(minutes), "t"), draft, ci_fix, 1)

    def order(self, rows):
        runs = [self.run_of(*row) for row in rows]
        plan = qo.plan_queue(runs, len(runs))
        return [r.run_id for r in plan.keep]

    def test_order_table_i1(self) -> None:
        # (run id, ci_fix, draft, minutes after the base time) -> expected order, written by hand
        table = [
            ([(1, False, False, 5), (2, True, True, 9)], [2, 1]),                  # ci-fix beats everything, even draft and newer
            ([(1, False, True, 1), (2, False, False, 9)], [2, 1]),                  # non-draft beats older draft
            ([(1, False, False, 9), (2, False, False, 1)], [2, 1]),                 # older first
            ([(7, False, False, 3), (4, False, False, 3)], [4, 7]),                 # tie on age: lower run id
            ([(1, True, True, 4), (2, True, False, 9)], [2, 1]),                    # within ci-fix: non-draft first
            ([(1, True, False, 9), (2, True, False, 2), (3, False, False, 1)], [2, 1, 3]),
            ([(5, False, True, 1), (6, False, True, 1), (3, True, True, 8)], [3, 5, 6]),
        ]
        for rows, expected in table:
            with self.subTest(rows=rows):
                self.assertEqual(self.order(rows), expected)

    def test_order_is_total_and_input_order_independent(self) -> None:
        rng = random.Random(SEED)
        rows = [(i, rng.random() < 0.3, rng.random() < 0.5, rng.randrange(0, 5)) for i in range(1, 40)]
        base = self.order(rows)
        for _ in range(20):
            shuffled = rows[:]
            rng.shuffle(shuffled)
            self.assertEqual(self.order(shuffled), base)

    def test_keep_and_cancel_split(self) -> None:
        runs = [self.run_of(1, False, False, 1), self.run_of(2, False, False, 2), self.run_of(3, False, False, 3)]
        plan = qo.plan_queue(runs, 2)
        self.assertEqual([r.run_id for r in plan.keep], [1, 2])
        self.assertEqual([r.run_id for r in plan.cancel], [3])


class FailClosedTable(TestBase):
    """I3: one row per form: exit code, exact reason, zero cancels, even with --execute."""

    def base(self) -> FakeGh:
        gh = FakeGh()
        for i in range(1, 6):
            gh.add_pr(i)
            gh.add_run(i, pr=i, minutes=i)
        return gh

    def test_rows(self) -> None:
        def unknown_status(gh): gh.runs[2]["status"] = "bogus"
        def unknown_conclusion(gh): gh.runs[2]["conclusion"] = "weird"
        def no_pr(gh): gh.runs[2]["pull_requests"] = []
        def two_prs(gh): gh.runs[2]["pull_requests"] = [{"number": 1}, {"number": 2}]
        def draft_unknown(gh): gh.pulls[2]["draft"] = None
        def labels_unknown(gh): gh.pulls[2]["labels"] = None
        def api_error(gh): gh.fail["list_runs"] = qo.GhError("HTTP 500")
        def rate_limit(gh): gh.fail["list_runs"] = qo.GhError("HTTP 403 rate limit exceeded")
        def cut_page(gh): gh.total_override = 7
        def bad_shape(gh): gh.raw_override = {"workflow_runs": "x"}
        def jobs_error(gh): gh.fail["run_jobs"] = qo.GhError("HTTP 502")
        def pull_error(gh): gh.fail["get_pull"] = qo.GhError("HTTP 502")
        def bad_time(gh): gh.runs[2]["created_at"] = "yesterday"
        def pr_state_unknown(gh): gh.pulls[2]["state"] = "merged"

        rows = [
            ("unknown status", unknown_status, qo.EXIT_REFUSED, "unknown status 'bogus' in run 2"),
            ("unknown conclusion", unknown_conclusion, qo.EXIT_REFUSED, "unknown conclusion 'weird' in run 2"),
            ("no pr", no_pr, qo.EXIT_REFUSED, "run has no pull request: run 2"),
            ("two prs", two_prs, qo.EXIT_REFUSED, "run has more than one pull request: run 2"),
            ("draft unknown", draft_unknown, qo.EXIT_REFUSED, "unknown draft state for pr 2: None"),
            ("labels unknown", labels_unknown, qo.EXIT_REFUSED, "unknown label state for pr 2"),
            ("api error", api_error, qo.EXIT_GH, "run list unreadable: HTTP 500"),
            ("rate limit", rate_limit, qo.EXIT_GH, "run list unreadable: HTTP 403 rate limit exceeded"),
            ("pagination cut", cut_page, qo.EXIT_REFUSED, "run list partial: 5 of 7 runs"),
            ("bad shape", bad_shape, qo.EXIT_REFUSED, "run list unreadable: unexpected response shape"),
            ("jobs error", jobs_error, qo.EXIT_GH, "job list unreadable: HTTP 502"),
            ("pull error", pull_error, qo.EXIT_GH, "gh call failed: HTTP 502"),
            ("bad time", bad_time, qo.EXIT_REFUSED, "unclassifiable input: created_at of run 2: 'yesterday'"),
            ("pr state", pr_state_unknown, qo.EXIT_REFUSED, "unclassifiable input: pr 2 state 'merged'"),
        ]
        for label, mutate, code, reason in rows:
            for flags in ((), ("--execute",)):
                with self.subTest(row=label, flags=flags):
                    gh = self.base()
                    mutate(gh)
                    got, _lines, err = call(gh, self.state, *flags)
                    self.assertEqual(got, code)
                    self.assertIn("queue_order: refused: " + reason, err)
                    self.assertEqual(gh.cancels, [])
                    self.assertFalse(self.state.exists())

    def test_corrupt_state_file(self) -> None:
        for text in ("not json", "[]", '{"version": 9, "entries": []}', '{"version": 1, "entries": [{"run_id": 1}]}'):
            with self.subTest(text=text):
                self.state.write_text(text)
                gh = self.base()
                got, _lines, err = call(gh, self.state, "--execute")
                self.assertEqual(got, qo.EXIT_STATE)
                self.assertIn("state file corrupt: state.json", err)
                self.assertEqual(gh.cancels, [])

    def test_unreadable_state_file(self) -> None:
        self.state.mkdir()  # a directory where a file belongs
        gh = self.base()
        got, _lines, err = call(gh, self.state)
        self.assertEqual(got, qo.EXIT_STATE)
        self.assertIn("state file unreadable", err)
        self.assertEqual(gh.cancels, [])

    def test_unwritable_state_file_cancels_nothing(self) -> None:
        blocker = Path(self._tmp.name) / "blocker"
        blocker.write_text("x")
        gh = self.base()
        got, _lines, err = call(gh, blocker / "state.json", "--execute")
        self.assertEqual(got, qo.EXIT_STATE)
        self.assertIn("state file unwritable", err)
        self.assertEqual(gh.cancels, [])


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
        gh = FakeGh()
        for i in range(1, 7):
            gh.add_pr(i)
            gh.add_run(i, pr=i, minutes=i)
        gh.add_pr(90)
        gh.add_run(90, pr=90, minutes=0, status="in_progress")
        code, _, _ = call(gh, self.state, "--execute")
        self.assertEqual(code, 0)
        self.assertNotIn(90, gh.cancels)
        self.assertEqual(sorted(gh.cancels), [3, 4, 5, 6])

    def test_plan_without_execute_changes_nothing(self) -> None:
        gh = FakeGh()
        for i in range(1, 6):
            gh.add_pr(i)
            gh.add_run(i, pr=i, minutes=i)
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


class Execution(TestBase):
    """I1 end to end, I2 sequencing, idempotence and the lock."""

    def queue(self, count: int = 5) -> FakeGh:
        gh = FakeGh()
        for i in range(1, count + 1):
            gh.add_pr(i)
            gh.add_run(i, pr=i, minutes=i)
        return gh

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
            ids = [e.run_id for e in qo.StateStore(self.state).read()]
            self.assertIn(run_id, ids, "cancel before the durable record")
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
        for run_id in (1, 2):  # the kept runs finish
            gh.runs[run_id]["status"] = "completed"
            gh.runs[run_id]["conclusion"] = "success"
        code, _lines, _ = call(gh, self.state, "--execute", "--resume")
        self.assertEqual(code, 0)
        self.assertEqual(gh.reruns, [3, 4])
        self.assertEqual([e.run_id for e in qo.StateStore(self.state).read()], [])

    def test_resume_never_cancels(self) -> None:
        gh = self.queue(5)
        call(gh, self.state, "--execute", "--resume")
        self.assertEqual(gh.cancels, [])

    def test_drops_with_printed_reason(self) -> None:
        gh = self.queue(5)
        call(gh, self.state, "--execute")  # cancels 3, 4, 5
        for run_id in (1, 2):
            gh.runs[run_id]["status"] = "completed"
            gh.runs[run_id]["conclusion"] = "success"
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
        self.assertEqual(qo.StateStore(self.state).read(), [])

    def test_deleted_run_dropped(self) -> None:
        gh = self.queue(3)
        call(gh, self.state, "--execute")
        del gh.runs[3]
        _, lines, _ = call(gh, self.state, "--execute", "--resume")
        self.assertIn("drop record run 3: run no longer exists", lines)

    def test_lock_refuses_second_call(self) -> None:
        gh = self.queue(4)
        with qo.StateLock(self.state):
            code, _, err = call(gh, self.state, "--execute")
        self.assertEqual(code, qo.EXIT_LOCK)
        self.assertIn("another call holds the state lock", err)
        self.assertEqual(gh.cancels, [])

    def test_cancel_failure_keeps_record(self) -> None:
        gh = self.queue(4)
        gh.fail["cancel"] = qo.GhError("HTTP 500")
        code, _, err = call(gh, self.state, "--execute")
        self.assertEqual(code, qo.EXIT_GH)
        self.assertIn("cancel run", err)
        recorded = {e.run_id for e in qo.StateStore(self.state).read()}
        self.assertEqual(recorded, {3, 4})  # recorded before the cancel that failed


class NothingLost(TestBase):
    """I2: generated call sequences with injected failures at every step."""

    def present(self, gh: FakeGh, state: Path) -> set[int]:
        queued = {i for i, r in gh.runs.items() if r["status"] == "queued"}
        recorded = {e.run_id for e in qo.StateStore(state).read()} if state.exists() else set()
        running = {i for i, r in gh.runs.items() if r["status"] == "in_progress"}
        finished = {i for i, r in gh.runs.items() if r["status"] == "completed" and r["conclusion"] != "cancelled"}
        return queued | recorded | running | finished

    def test_property_no_run_lost(self) -> None:
        rng = random.Random(SEED)
        steps = ("list_runs", "run_jobs", "get_pull", "cancel", "rerun", "get_run")
        for seq in range(SEQUENCE_COUNT):
            with self.subTest(seq=seq):
                gh = FakeGh()
                count = rng.randrange(3, 9)
                for i in range(1, count + 1):
                    gh.add_pr(i, draft=rng.random() < 0.4, labels=("ci-fix",) if rng.random() < 0.2 else ())
                    gh.add_run(i, pr=i, minutes=rng.randrange(0, 30))
                initial = set(gh.runs)
                state = Path(self._tmp.name) / ("s%d.json" % seq)
                for _ in range(rng.randrange(2, MAX_CALLS + 1)):
                    gh.fail = {}
                    if rng.random() < 0.5:
                        gh.fail[rng.choice(steps)] = qo.GhError("HTTP 500 injected")
                    crash_at = rng.choice([None, "temp-written", "renamed"])

                    def hook(step: str, crash_at=crash_at) -> None:
                        if step == crash_at:
                            raise RuntimeError("crash")

                    flags = ["--execute"] + (["--resume"] if rng.random() < 0.3 else [])
                    try:
                        call(gh, state, *flags, hook=hook)
                    except RuntimeError:
                        pass
                    if rng.random() < 0.4:  # a kept run starts on a runner
                        waiting = [i for i, r in gh.runs.items() if r["status"] == "queued"]
                        if waiting:
                            gh.runs[rng.choice(waiting)]["status"] = "in_progress"
                    self.assertEqual(initial - self.present(gh, state), set(), "runs lost after a call")

    def test_crash_between_record_and_cancel(self) -> None:
        gh = FakeGh()
        for i in range(1, 5):
            gh.add_pr(i)
            gh.add_run(i, pr=i, minutes=i)

        def crash(step: str) -> None:
            if step == "renamed":
                raise RuntimeError("crash after the record became durable")

        with self.assertRaises(RuntimeError):
            call(gh, self.state, "--execute", hook=crash)
        self.assertEqual(gh.cancels, [])
        recorded = {e.run_id for e in qo.StateStore(self.state).read()}
        self.assertEqual(recorded, {3, 4})
        code, _, _ = call(gh, self.state, "--execute")
        self.assertEqual(code, 0)
        self.assertEqual(sorted(gh.cancels), [3, 4])

    def test_crash_during_write_leaves_old_record(self) -> None:
        store = qo.StateStore(self.state)
        store.write([qo.Entry(1, 1, SHA_A, 1)])

        def crash(step: str) -> None:
            if step == "temp-written":
                raise RuntimeError("crash")

        store.hook = crash
        with self.assertRaises(RuntimeError):
            store.write([qo.Entry(2, 2, SHA_A, 1)])
        self.assertEqual([e.run_id for e in qo.StateStore(self.state).read()], [1])
        self.assertEqual([p.name for p in self.state.parent.iterdir() if ".tmp." in p.name], [])


class Size(TestBase):
    def test_big_queue_under_ceiling(self) -> None:
        runs = [qo.QueuedRun(i, i, SHA_A, qo.parse_time(stamp(i % 600), "t"), i % 3 == 0, i % 17 == 0, 1) for i in range(1, BIG_QUEUE + 1)]
        started = time.monotonic()
        plan = qo.plan_queue(runs, 4)
        elapsed = time.monotonic() - started
        self.assertEqual(len(plan.keep) + len(plan.cancel), BIG_QUEUE)
        self.assertLess(elapsed, BIG_QUEUE_CEILING_SECS)

    def test_big_execute_under_ceiling(self) -> None:
        gh = FakeGh()
        for i in range(1, BIG_QUEUE + 1):
            gh.add_pr(i)
            gh.add_run(i, pr=i, minutes=i % 600)
        started = time.monotonic()
        code, _, _ = call(gh, self.state, "--execute")
        elapsed = time.monotonic() - started
        self.assertEqual(code, 0)
        self.assertEqual(len(gh.cancels), BIG_QUEUE - KEEP)
        self.assertLess(elapsed, BIG_QUEUE_CEILING_SECS)


if __name__ == "__main__":
    unittest.main()
