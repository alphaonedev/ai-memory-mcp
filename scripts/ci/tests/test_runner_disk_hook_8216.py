# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""Pin scripts/ci/runner_disk_hook.py and runner_disk_hook.sh (#8216, PR 9812 round 1).

Defect classes (one invariant each, checked for all inputs of its table):
  state-report   decision, reason, removed, byte figures and exit code come from the state after the action
                 (one ``decide`` over the ``Action`` enum); a refusal never prints as ``enough-free`` or ``clear``.
  start-floor    at job-started a free space still under the floor after the clear exits EXIT_BELOW_FLOOR with the
                 fixed line; job-completed, a dry run and a switched-off ENFORCE_START_FLOOR never do (3-agent vote
                 71472661, conditions V-1 and V-2).
  untrusted text no byte of a path, name or environment value reaches stderr or the log unescaped.
  guards         the work-root guard and the allocated-bytes measure are exactly as wide as the docs say.
  wiring         the runner's ``.sh`` hook path starts the Python hook and names the event.

Every expected value is a literal written by hand, never taken from the code under test. All trees live under
<clone>/.local-runs/. The removal engine has its own tests in test_safe_remove_8216.py.

Run: python3.12 -I -m unittest discover -s scripts/ci/tests -p test_runner_disk_hook_8216.py
Python 3.12+, standard library only.
"""

import datetime
import errno
import importlib.util
import io
import json
import os
import random
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import types
import unittest
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parents[3]
CI_DIR = REPO_ROOT / "scripts" / "ci"
HOOK_PATH = CI_DIR / "runner_disk_hook.py"
WRAPPER_PATH = CI_DIR / "runner_disk_hook.sh"
LOCAL_RUNS = REPO_ROOT / ".local-runs"

GIB = 1024**3
MIB = 1024**2
START_FLOOR_BYTES = 64_424_509_440  # 60 GiB
COMPLETED_FLOOR_BYTES = 161_061_273_600  # 150 GiB
SIGNATURE = "Signature: 8a477f597d28d172789f06886806bc55"
NOW = datetime.datetime(2026, 11, 21, 12, 0, 0, tzinfo=datetime.timezone.utc)
STAMP = "2026-11-21T12:00:00Z"
RUNNER = "r1"
REPO_NAME = "repo"
STDERR_PREFIX = "runner-disk-hook: "
WALL_CLOCK_CEILING_SECS = 30.0
BIG_WALK_ENTRIES = 100_000
WRAPPER_PYTHON = Path("/opt/homebrew/bin/python3.12")


def load_hook():
    spec = importlib.util.spec_from_file_location("runner_disk_hook_8216", HOOK_PATH)
    module = importlib.util.module_from_spec(spec)
    sys.modules["runner_disk_hook_8216"] = module
    spec.loader.exec_module(module)
    return module


hook = load_hook()


def force_remove(path: Path) -> None:
    """Test cleanup under .local-runs only: restore owner bits, then remove."""
    assert str(path).startswith(str(LOCAL_RUNS)), path
    for root, dirs, _files in os.walk(path):
        for name in dirs:
            try:
                os.chmod(os.path.join(root, name), 0o700)
            except OSError:
                pass
    shutil.rmtree(path, ignore_errors=True)


class FakeDisk:
    """Returns the given readings in order; the last one repeats."""

    def __init__(self, *readings):
        self.readings = list(readings)
        self.calls = 0

    def __call__(self, _path):
        index = min(self.calls, len(self.readings) - 1)
        self.calls += 1
        value = self.readings[index]
        if isinstance(value, BaseException):
            raise value
        return value


class Base(unittest.TestCase):
    def setUp(self):
        LOCAL_RUNS.mkdir(exist_ok=True)
        self.scratch = Path(tempfile.mkdtemp(prefix="runner-disk-hook-8216-", dir=LOCAL_RUNS))
        self.addCleanup(force_remove, self.scratch)
        self.home = self.scratch / "home"
        self.home.mkdir()
        self.work_root = self.scratch / "runner" / "_work" / REPO_NAME
        self.work_root.mkdir(parents=True)
        self.repo = self.work_root / REPO_NAME
        self.repo.mkdir()
        self.log = self.scratch / "hook.log"

    def target(self, kind: str) -> Path:
        target = self.repo / "target"
        match kind:
            case "none":
                (self.repo / "src.txt").write_text("x")
            case "tagged" | "partial":
                target.mkdir()
                (target / "CACHEDIR.TAG").write_text(SIGNATURE + "\n# cache\n")
                (target / "file.bin").write_text("x")
                if kind == "partial":
                    (target / "sub").mkdir()
                    (target / "sub" / "inner.bin").write_text("y")
            case "untagged":
                target.mkdir()
                (target / "file.bin").write_text("x")
            case _:
                raise AssertionError(kind)
        return target

    def call(self, argv, *, disk, env=None, ceiling=None, max_walk=None, free_env=True):
        stderr = io.StringIO()
        environ = {} if env is None else dict(env)
        if free_env:
            environ.setdefault("RUNNER_NAME", RUNNER)
            environ.setdefault("RUNNER_WORKSPACE", str(self.work_root))
        kwargs = {}
        if ceiling is not None:
            kwargs["ceiling_bytes"] = ceiling
        if max_walk is not None:
            kwargs["max_walk_entries"] = max_walk
        code = hook.main(
            list(argv), environ, home=self.home, disk_free=disk, stderr=stderr, now=lambda: NOW, **kwargs
        )
        return code, stderr.getvalue()

    def started(self, *extra, disk, **kwargs):
        return self.call(["--event", "job-started", "--log", str(self.log), *extra], disk=disk, **kwargs)

    def completed(self, *extra, disk, **kwargs):
        return self.call(["--event", "job-completed", "--log", str(self.log), *extra], disk=disk, **kwargs)

    def log_lines(self):
        return self.log.read_text().splitlines()


def fields(line: str) -> dict:
    """key=value fields of a log line (reason and paths are JSON, so they are cut by their own prefix)."""
    reason = line.split(" reason=", 1)[1]
    head = line.split(" paths=", 1)[0]
    out = dict(item.split("=", 1) for item in head.split(" ")[1:] if "=" in item)
    out["reason"] = reason
    return out


# ----------------------------------------------------------------------------------------------------------------
# The exhaustive table: event x free x target x dry-run.  Expected column written by hand.
# (decision, exit, removed, target still present afterwards)
# ----------------------------------------------------------------------------------------------------------------
ENOUGH = ("enough-free", 0, 0, True)
UNDER_ONE_BYTE = {
    # event job-started: floor 60 GiB, the after-clear reading is above the floor
    ("job-started", "none", False): ("below-floor", 75, 0, None),
    ("job-started", "none", True): ("no-target", 0, 0, None),
    ("job-started", "tagged", False): ("clear", 0, 1, False),
    ("job-started", "tagged", True): ("would-remove", 0, 0, True),
    ("job-started", "untagged", False): ("below-floor", 75, 0, True),
    ("job-started", "untagged", True): ("refused-target", 0, 0, True),
    ("job-started", "partial", False): ("partial", 0, 0, True),
    ("job-started", "partial", True): ("would-remove", 0, 0, True),
    # event job-completed: floor 150 GiB, never a non-zero exit
    ("job-completed", "none", False): ("no-target", 0, 0, None),
    ("job-completed", "none", True): ("no-target", 0, 0, None),
    ("job-completed", "tagged", False): ("clear", 0, 1, False),
    ("job-completed", "tagged", True): ("would-remove", 0, 0, True),
    ("job-completed", "untagged", False): ("refused-target", 0, 0, True),
    ("job-completed", "untagged", True): ("refused-target", 0, 0, True),
    ("job-completed", "partial", False): ("partial", 0, 0, True),
    ("job-completed", "partial", True): ("would-remove", 0, 0, True),
}
FLOORS = {"job-started": START_FLOOR_BYTES, "job-completed": COMPLETED_FLOOR_BYTES}


class ExhaustiveTable(Base):
    def run_row(self, event, free_kind, kind, dry):
        floor = FLOORS[event]
        before = {"above": floor + GIB, "at": floor, "under": floor - 1}[free_kind]
        after = floor + 10 * GIB
        target = self.target(kind)
        argv = ["--event", event, "--log", str(self.log)] + (["--dry-run"] if dry else [])
        disk = FakeDisk(before, after)
        patches = []
        if kind == "partial" and not dry:
            real = os.rmdir

            def failing(path, *args, **kwargs):
                if path == "sub" and kwargs.get("dir_fd") is not None:
                    raise OSError(errno.EACCES, "Permission denied")
                return real(path, *args, **kwargs)

            patches.append(mock.patch.object(os, "rmdir", side_effect=failing))
        for item in patches:
            item.start()
            self.addCleanup(item.stop)
        code, _err = self.call(argv, disk=disk)
        for item in patches:
            item.stop()
        return code, self.log_lines(), target

    def test_every_row(self):
        for event in ("job-started", "job-completed"):
            for free_kind in ("above", "at", "under"):
                for kind in ("none", "tagged", "untagged", "partial"):
                    for dry in (False, True):
                        with self.subTest(event=event, free=free_kind, target=kind, dry=dry):
                            self.setUp()
                            expected = ENOUGH if free_kind != "under" else UNDER_ONE_BYTE[(event, kind, dry)]
                            decision, exit_code, removed, present = expected
                            code, lines, target = self.run_row(event, free_kind, kind, dry)
                            row = fields(lines[0])
                            self.assertEqual(row["decision"], decision)
                            self.assertEqual(code, exit_code)
                            self.assertEqual(row["removed"], str(removed))
                            if present is not None and kind != "none":
                                self.assertEqual(target.exists(), present)
                            self.assertEqual(lines[0].endswith(" dry-run"), dry)

    def test_every_action_has_a_row_in_the_unit_table(self):
        self.assertEqual(
            {action.name for action in hook.Action},
            {"NOT_NEEDED", "CLEARED", "WOULD_CLEAR", "PARTIAL", "NO_TARGET", "REFUSED_TARGET"},
        )
        self.assertEqual(set(DECIDE_ROWS), {action for action in hook.Action})


# ----------------------------------------------------------------------------------------------------------------
# decide(): one function over the Action enum
# ----------------------------------------------------------------------------------------------------------------
def facts(**overrides):
    base = dict(
        event=hook.Event.JOB_COMPLETED, dry_run=False, floor_bytes=COMPLETED_FLOOR_BYTES, free_before=149 * GIB,
        free_after=None, free_is_input=False, free_reason="", folder_state=hook.FolderState.NOT_MEASURED,
        folder_before=None, folder_after=None, folder_reason="", over_ceiling=False, ceiling_bytes=40 * GIB,
        action=hook.Action.NOT_NEEDED, completed=(), partial=(), would=(), entries=0, notes=(),
    )
    base.update(overrides)
    return hook.Facts(**base)


A = hook.Action
DECIDE_ROWS = {
    A.NOT_NEEDED: (
        dict(free_before=150 * GIB),
        hook.Decision.ENOUGH_FREE, "free space 150.00 GiB is at or above the 150 GiB floor", 0, 0,
    ),
    A.CLEARED: (
        dict(action=A.CLEARED, completed=("p",), free_after=151 * GIB, entries=4),
        hook.Decision.CLEAR, "free space 149.00 GiB is under the 150 GiB floor", 0, 1,
    ),
    A.WOULD_CLEAR: (
        dict(action=A.WOULD_CLEAR, would=("p", "q")),
        hook.Decision.WOULD_REMOVE, "free space 149.00 GiB is under the 150 GiB floor", 0, 0,
    ),
    A.PARTIAL: (
        dict(action=A.PARTIAL, partial=("p",), free_after=149 * GIB, entries=3),
        hook.Decision.PARTIAL,
        "free space 149.00 GiB is under the 150 GiB floor; removal stopped part way after 3 entries removed", 0, 0,
    ),
    A.NO_TARGET: (
        dict(action=A.NO_TARGET),
        hook.Decision.NO_TARGET, "free space 149.00 GiB is under the 150 GiB floor; no cargo target directory found",
        0, 0,
    ),
    A.REFUSED_TARGET: (
        dict(action=A.REFUSED_TARGET, notes=("note one",)),
        hook.Decision.REFUSED_TARGET, "free space 149.00 GiB is under the 150 GiB floor; note one", 0, 0,
    ),
}


class DecideUnit(unittest.TestCase):
    def test_each_action_gives_its_own_decision_reason_and_exit(self):
        for action, (overrides, decision, reason, exit_code, removed) in DECIDE_ROWS.items():
            with self.subTest(action=action.name):
                verdict = hook.decide(facts(**overrides))
                self.assertEqual(verdict.decision, decision)
                self.assertEqual(verdict.reason, reason)
                self.assertEqual(verdict.exit_code, exit_code)
                self.assertEqual(verdict.removed, removed)

    def test_unreadable_free_space_is_refused_measure_with_its_reason_and_exit_zero(self):
        verdict = hook.decide(facts(free_before=None, free_reason="free-space read returned nothing"))
        self.assertEqual(
            (verdict.decision, verdict.reason, verdict.exit_code, verdict.removed),
            (hook.Decision.REFUSED_MEASURE, "free-space read returned nothing", 0, 0),
        )

    def test_an_unknown_action_or_folder_state_raises_never_falls_through(self):
        with self.assertRaises(ValueError) as action:
            hook.decide(facts(action="bogus"))
        self.assertEqual(str(action.exception), "unknown action 'bogus'")
        with self.assertRaises(ValueError) as folder:
            hook.decide(facts(folder_state="odd"))
        self.assertEqual(str(folder.exception), "unknown folder state 'odd'")

    def test_below_floor_rows(self):
        started = dict(event=hook.Event.JOB_STARTED, floor_bytes=START_FLOOR_BYTES)
        under = 60 * GIB - 1
        rows = (
            # (overrides, decision, exit)
            (dict(free_before=under, action=A.NO_TARGET), "below-floor", 75),
            (dict(free_before=under, action=A.REFUSED_TARGET), "below-floor", 75),
            (dict(free_before=under, action=A.CLEARED, completed=("p",), free_after=under), "below-floor", 75),
            (dict(free_before=under, action=A.CLEARED, completed=("p",), free_after=60 * GIB), "clear", 0),
            (dict(free_before=under, action=A.CLEARED, completed=("p",), free_after=None), "below-floor", 75),
            (dict(free_before=under, action=A.PARTIAL, partial=("p",), free_after=under), "below-floor", 75),
            (dict(free_before=under, action=A.WOULD_CLEAR, would=("p",)), "would-remove", 0),
            (dict(free_before=under, action=A.NO_TARGET, dry_run=True), "no-target", 0),
            (dict(free_before=60 * GIB, action=A.NOT_NEEDED), "enough-free", 0),
        )
        for overrides, decision, exit_code in rows:
            with self.subTest(overrides=overrides):
                verdict = hook.decide(facts(**started, **overrides))
                self.assertEqual((verdict.decision.value, verdict.exit_code), (decision, exit_code))

    def test_job_completed_never_exits_non_zero_for_the_floor(self):
        for action in hook.Action:
            for after in (None, 0, 149 * GIB, 150 * GIB):
                with self.subTest(action=action.name, after=after):
                    verdict = hook.decide(facts(action=action, free_after=after, free_before=1))
                    self.assertEqual(verdict.exit_code, 0)

    def test_switch_off_never_exits_non_zero(self):
        with mock.patch.object(hook, "ENFORCE_START_FLOOR", False):
            verdict = hook.decide(
                facts(event=hook.Event.JOB_STARTED, floor_bytes=START_FLOOR_BYTES, free_before=1, action=A.NO_TARGET)
            )
        self.assertEqual((verdict.decision, verdict.exit_code), (hook.Decision.NO_TARGET, 0))

    def test_floor_text_is_truncated_never_rounded_up(self):
        under = 60 * GIB - 1
        verdict = hook.decide(
            facts(event=hook.Event.JOB_STARTED, floor_bytes=START_FLOOR_BYTES, free_before=under, action=A.NO_TARGET)
        )
        self.assertIn("free space 59.99 GiB is under the 60 GiB floor", verdict.reason)
        self.assertNotIn("60.00", verdict.reason)

    def test_gib_text_boundaries(self):
        rows = (
            (0, "0.00"), (1, "0.00"), (GIB // 100 - 1, "0.00"), (GIB // 100 + 1, "0.01"), (GIB, "1.00"),
            (60 * GIB - 1, "59.99"), (60 * GIB, "60.00"), (150 * GIB - 1, "149.99"), (10_000 * GIB, "10000.00"),
        )
        for value, text in rows:
            with self.subTest(value=value):
                self.assertEqual(hook._gib_text(value), text)

    def test_constants_are_the_documented_literals(self):
        self.assertEqual(hook.GIB, 1_073_741_824)
        self.assertEqual(hook.CLEAR_BELOW_GIB_AFTER_JOB, 150)
        self.assertEqual(hook.START_FLOOR_GIB, 60)
        self.assertEqual(hook.WORK_FOLDER_CEILING_GIB, 40)
        self.assertEqual(hook.WORK_FOLDER_CEILING_BYTES, 42_949_672_960)
        self.assertEqual(hook.MAX_WALK_ENTRIES, 5_000_000)
        self.assertEqual(hook.EXIT_BELOW_FLOOR, 75)
        self.assertIs(hook.ENFORCE_START_FLOOR, True)
        self.assertEqual(hook.SAFE_TEXT_MAX, 512)

    def test_floor_gib_is_one_value_per_event(self):
        self.assertEqual({event.value: hook.floor_gib(event) for event in hook.Event},
                         {"job-started": 60, "job-completed": 150})


# ----------------------------------------------------------------------------------------------------------------
# start-floor enforcement: V-1 and V-2 of the vote
# ----------------------------------------------------------------------------------------------------------------
class StartFloor(Base):
    UNDER = START_FLOOR_BYTES - 1

    def test_v2_the_below_floor_line_is_one_fixed_form_on_stderr_and_in_the_log(self):
        self.target("none")
        code, err = self.started(disk=FakeDisk(self.UNDER))
        fixed = "decision=below-floor event=job-started free_bytes=64424509439 floor_bytes=64424509440 runner=r1"
        self.assertEqual(code, 75)
        self.assertIn(STDERR_PREFIX + fixed + "\n", err)
        lines = self.log_lines()
        self.assertEqual(len(lines), 2)
        self.assertEqual(lines[1], f"{STAMP} {fixed}")

    def test_v1_job_completed_one_byte_under_exits_zero_with_no_below_floor_line(self):
        self.target("none")
        code, err = self.completed(disk=FakeDisk(COMPLETED_FLOOR_BYTES - 1))
        self.assertEqual(code, 0)
        self.assertNotIn("below-floor", err)
        self.assertEqual(len(self.log_lines()), 1)

    def test_v1_job_completed_after_a_clear_still_under_exits_zero(self):
        self.target("tagged")
        code, _err = self.completed(disk=FakeDisk(COMPLETED_FLOOR_BYTES - 1, COMPLETED_FLOOR_BYTES - 1))
        self.assertEqual(code, 0)

    def test_switch_on_exits_75_and_off_exits_0_with_the_same_state(self):
        self.target("none")
        with mock.patch.object(hook, "ENFORCE_START_FLOOR", True):
            on, _ = self.started(disk=FakeDisk(self.UNDER))
        force_remove(self.log) if self.log.is_dir() else self.log.unlink()
        with mock.patch.object(hook, "ENFORCE_START_FLOOR", False):
            off, err = self.started(disk=FakeDisk(self.UNDER))
        self.assertEqual((on, off), (75, 0))
        self.assertNotIn("below-floor", err)
        self.assertEqual(len(self.log_lines()), 1)

    def test_dry_run_never_exits_non_zero(self):
        self.target("none")
        code, err = self.started("--dry-run", disk=FakeDisk(self.UNDER))
        self.assertEqual(code, 0)
        self.assertNotIn("below-floor", err)

    def test_clear_that_brings_the_volume_to_the_floor_starts_the_job(self):
        self.target("tagged")
        code, _ = self.started(disk=FakeDisk(self.UNDER, START_FLOOR_BYTES))
        self.assertEqual(code, 0)
        self.assertEqual(fields(self.log_lines()[0])["decision"], "clear")

    def test_clear_that_leaves_the_volume_one_byte_under_refuses_the_start(self):
        self.target("tagged")
        code, err = self.started(disk=FakeDisk(self.UNDER, self.UNDER))
        self.assertEqual(code, 75)
        self.assertIn("free_bytes=64424509439", err)

    def test_a_failed_read_after_the_clear_refuses_the_start_with_free_bytes_unknown(self):
        target = self.target("tagged")
        code, err = self.started(disk=FakeDisk(self.UNDER, OSError("boom")))
        self.assertEqual(code, 75)
        self.assertFalse(target.exists())
        self.assertIn(
            STDERR_PREFIX + "decision=below-floor event=job-started free_bytes=unknown floor_bytes=64424509440 runner=r1\n",
            err,
        )
        reason = fields(self.log_lines()[0])["reason"]
        self.assertIn("free space after the removal could not be read, so the floor is not proven", reason)

    def test_a_refused_free_read_at_job_started_is_refused_measure_exit_zero(self):
        self.target("tagged")
        code, _ = self.started(disk=FakeDisk(OSError("boom")))
        self.assertEqual(code, 0)
        self.assertEqual(fields(self.log_lines()[0])["decision"], "refused-measure")

    def test_exit_code_pin(self):
        self.assertEqual(hook.EXIT_OK, 0)
        self.assertEqual(hook.EXIT_BELOW_FLOOR, 75)


# ----------------------------------------------------------------------------------------------------------------
# exact lines
# ----------------------------------------------------------------------------------------------------------------
class ExactLines(Base):
    def test_enough_free_line(self):
        self.target("tagged")
        code, err = self.completed(disk=FakeDisk(150 * GIB))
        self.assertEqual(code, 0)
        self.assertEqual(err, "")
        self.assertEqual(
            self.log_lines(),
            [
                f"{STAMP} runner=r1 event=job-completed free_before_gib=150.00 free_after_gib=150.00 "
                "folder_bytes_before=unknown folder_bytes_after=unknown decision=enough-free removed=0 entries=0 "
                'paths=[] reason="free space 150.00 GiB is at or above the 150 GiB floor"'
            ],
        )

    def test_clear_line_with_the_remeasured_after_figure(self):
        target = self.target("tagged")
        code, err = self.completed(disk=FakeDisk(150 * GIB - 1, 200 * GIB))
        self.assertEqual(code, 0)
        self.assertEqual(err, "")
        self.assertFalse(target.exists())
        self.assertEqual(
            self.log_lines(),
            [
                f"{STAMP} runner=r1 event=job-completed free_before_gib=149.99 free_after_gib=200.00 "
                "folder_bytes_before=unknown folder_bytes_after=unknown decision=clear removed=1 entries=2 "
                f'paths=["{target}"] reason="free space 149.99 GiB is under the 150 GiB floor"'
            ],
        )

    def test_dry_run_line_says_would_remove_and_removed_zero(self):
        target = self.target("tagged")
        code, _ = self.completed("--dry-run", disk=FakeDisk(100 * GIB))
        self.assertEqual(code, 0)
        self.assertTrue(target.exists())
        self.assertEqual(
            self.log_lines(),
            [
                f"{STAMP} runner=r1 event=job-completed free_before_gib=100.00 free_after_gib=100.00 "
                "folder_bytes_before=unknown folder_bytes_after=unknown decision=would-remove removed=0 entries=0 "
                f'paths=["{target}"] reason="free space 100.00 GiB is under the 150 GiB floor" dry-run'
            ],
        )

    def test_partial_line_counts_the_entries_and_remeasures(self):
        target = self.target("partial")
        real = os.rmdir

        def failing(path, *args, **kwargs):
            if path == "sub" and kwargs.get("dir_fd") is not None:
                raise OSError(errno.EACCES, "Permission denied")
            return real(path, *args, **kwargs)

        with mock.patch.object(os, "rmdir", side_effect=failing):
            code, err = self.completed(disk=FakeDisk(100 * GIB, 120 * GIB))
        self.assertEqual(code, 0)
        line = self.log_lines()[0]
        self.assertEqual(
            line,
            f"{STAMP} runner=r1 event=job-completed free_before_gib=100.00 free_after_gib=120.00 "
            "folder_bytes_before=unknown folder_bytes_after=unknown decision=partial removed=0 entries=2 "
            f'paths=["{target}"] reason="free space 100.00 GiB is under the 150 GiB floor; removal stopped part way '
            f'after 2 entries removed; {target}: partial, 2 entries removed: remove failed: Permission denied"',
        )
        self.assertIn(f"partial: {target}: partial, 2 entries removed: remove failed: Permission denied\n", err)
        self.assertTrue((target / "CACHEDIR.TAG").exists())

    def test_refused_target_line_carries_the_exact_reason(self):
        target = self.target("untagged")
        code, err = self.completed(disk=FakeDisk(100 * GIB))
        self.assertEqual(code, 0)
        note = f"{target}: CACHEDIR.TAG is missing"
        self.assertEqual(
            self.log_lines(),
            [
                f"{STAMP} runner=r1 event=job-completed free_before_gib=100.00 free_after_gib=100.00 "
                "folder_bytes_before=unknown folder_bytes_after=unknown decision=refused-target removed=0 entries=0 "
                f'paths=[] reason="free space 100.00 GiB is under the 150 GiB floor; {note}"'
            ],
        )
        self.assertEqual(err, f"{STDERR_PREFIX}refused-target: {note}\n")

    def test_no_target_line(self):
        self.target("none")
        code, _ = self.completed(disk=FakeDisk(100 * GIB))
        self.assertEqual(code, 0)
        self.assertEqual(
            self.log_lines(),
            [
                f"{STAMP} runner=r1 event=job-completed free_before_gib=100.00 free_after_gib=100.00 "
                "folder_bytes_before=unknown folder_bytes_after=unknown decision=no-target removed=0 entries=0 "
                'paths=[] reason="free space 100.00 GiB is under the 150 GiB floor; no cargo target directory found"'
            ],
        )

    def test_job_started_line_carries_both_folder_figures(self):
        self.target("tagged")
        code, _ = self.started(disk=FakeDisk(100 * GIB))
        self.assertEqual(code, 0)
        row = fields(self.log_lines()[0])
        self.assertEqual(row["decision"], "enough-free")
        self.assertRegex(row["folder_bytes_before"], r"^\d+$")
        self.assertEqual(row["folder_bytes_after"], row["folder_bytes_before"])

    def test_free_gib_input_is_marked_and_the_disk_is_not_read(self):
        self.target("tagged")
        disk = FakeDisk(1)
        code, _ = self.completed("--free-gib", "10", disk=disk)
        self.assertEqual(code, 0)
        self.assertEqual(disk.calls, 0)
        row = fields(self.log_lines()[0])
        self.assertEqual((row["free_before_gib"], row["free_after_gib"]), ("input:10.00", "input:10.00"))
        self.assertEqual(row["decision"], "clear")


# ----------------------------------------------------------------------------------------------------------------
# free-space reading refusals
# ----------------------------------------------------------------------------------------------------------------
class FreeRead(Base):
    ROWS = (
        (None, "free-space read returned nothing"),
        (True, "free-space read returned a bool: True"),
        (False, "free-space read returned a bool: False"),
        ("5", "free-space read returned a str, not an integer"),
        (1.5, "free-space read returned a float, not an integer"),
        (-1, "free-space read returned a negative value: -1"),
        (OSError("boom"), "free-space read failed: boom"),
    )

    def test_each_bad_reading_is_refused_by_kind_for_both_events(self):
        for event in ("job-started", "job-completed"):
            for value, reason in self.ROWS:
                with self.subTest(event=event, value=repr(value)):
                    self.setUp()
                    target = self.target("tagged")
                    code, err = self.call(["--event", event, "--log", str(self.log)], disk=FakeDisk(value))
                    self.assertEqual(code, 0)
                    self.assertTrue(target.exists())
                    self.assertEqual(
                        self.log_lines(),
                        [
                            f"{STAMP} runner=r1 event={event} free_before_gib=unknown free_after_gib=unknown "
                            "folder_bytes_before=unknown folder_bytes_after=unknown decision=refused-measure "
                            f'removed=0 entries=0 paths=[] reason="{reason}"'
                        ],
                    )
                    self.assertEqual(err, f"{STDERR_PREFIX}refused-measure: {reason}\n")

    def test_zero_free_is_a_reading_not_a_refusal(self):
        self.target("tagged")
        code, _ = self.completed(disk=FakeDisk(0, 0))
        self.assertEqual(code, 0)
        self.assertEqual(fields(self.log_lines()[0])["decision"], "clear")

    def test_crash_in_the_run_is_a_logged_refusal(self):
        self.target("tagged")
        with mock.patch.object(hook, "clear_targets", side_effect=RuntimeError("boom")):
            code, err = self.completed(disk=FakeDisk(1))
        self.assertEqual(code, 0)
        self.assertEqual(
            self.log_lines(),
            [
                f"{STAMP} runner=r1 event=job-completed free_before_gib=unknown free_after_gib=unknown "
                "folder_bytes_before=unknown folder_bytes_after=unknown decision=refused removed=0 entries=0 "
                'paths=[] reason="internal error: RuntimeError: boom"'
            ],
        )
        self.assertEqual(err, f"{STDERR_PREFIX}refused: internal error: RuntimeError: boom\n")


# ----------------------------------------------------------------------------------------------------------------
# argument and environment refusals
# ----------------------------------------------------------------------------------------------------------------
class Refusals(Base):
    def refuse(self, argv, *, env=None, reason, runner="r1", event="unknown"):
        self.target("tagged")
        disk = FakeDisk(1)
        code, err = self.call(argv, disk=disk, env=env)
        self.assertEqual(code, 0)
        self.assertEqual(disk.calls, 0, "a refusal reads no disk")
        self.assertTrue((self.repo / "target").exists(), "a refusal removes nothing")
        line = self.log_lines()[0]
        self.assertEqual(
            line,
            f"{STAMP} runner={runner} event={event} free_before_gib=unknown free_after_gib=unknown "
            "folder_bytes_before=unknown folder_bytes_after=unknown decision=refused removed=0 entries=0 "
            f'paths=[] reason="{reason}"',
        )
        self.assertEqual(err, f"{STDERR_PREFIX}refused: {reason}\n")
        self.log.unlink()

    def test_event_is_required_and_has_no_default(self):
        self.refuse(
            ["--log", str(self.log)],
            reason="invalid arguments: one of the arguments --event --invoked-as is required",
        )

    def test_event_and_invoked_as_together(self):
        self.refuse(
            ["--event", "job-started", "--invoked-as", "runner_disk_hook_job-started.sh", "--log", str(self.log)],
            reason="invalid arguments: argument --invoked-as: not allowed with argument --event",
        )

    def test_event_spelling_is_exact(self):
        for bad in ("JOB-STARTED", " job-started", "job-started ", "Job-Completed", "job_started", "started", ""):
            with self.subTest(event=bad):
                self.setUp()
                self.refuse(
                    ["--event", bad, "--log", str(self.log)],
                    reason=f"invalid arguments: argument --event: invalid event {bad!r} "
                    "(choose from job-started, job-completed)",
                )

    def test_invoked_as_names_are_exact(self):
        message = (
            "invoked as {name!r}: no event (start it as runner_disk_hook_job-started.sh or "
            "runner_disk_hook_job-completed.sh)"
        )
        for bad in (
            "evil.sh", "", "RUNNER_DISK_HOOK_JOB-STARTED.SH", "runner_disk_hook_job-started.sh ",
            "/x/runner_disk_hook_job-started.sh", "runner_disk_hook.sh", "runner_disk_hook_job-started.py",
        ):
            with self.subTest(name=bad):
                self.setUp()
                self.refuse(
                    ["--invoked-as", bad, "--log", str(self.log)],
                    reason=message.format(name=bad),
                )

    def test_invoked_as_maps_each_name_to_its_event(self):
        for name, event, floor in (
            ("runner_disk_hook_job-started.sh", "job-started", START_FLOOR_BYTES),
            ("runner_disk_hook_job-completed.sh", "job-completed", COMPLETED_FLOOR_BYTES),
        ):
            with self.subTest(name=name):
                self.setUp()
                code, _ = self.call(["--invoked-as", name, "--log", str(self.log)], disk=FakeDisk(floor))
                self.assertEqual(code, 0)
                self.assertEqual(fields(self.log_lines()[0])["event"], event)

    def test_free_gib_must_be_finite(self):
        for bad, text in (("nan", "'nan'"), ("inf", "'inf'"), ("-inf", "'-inf'")):
            with self.subTest(value=bad):
                self.setUp()
                self.refuse(
                    ["--event", "job-started", "--free-gib=" + bad, "--log", str(self.log)],
                    reason=f"invalid arguments: argument --free-gib: not a finite number: {text}",
                )
        self.setUp()
        self.refuse(
            ["--event", "job-started", "--free-gib", "x", "--log", str(self.log)],
            reason="invalid arguments: argument --free-gib: not a number: 'x'",
        )

    def test_unknown_argument_and_abbreviation_are_refused(self):
        self.refuse(
            ["--event", "job-started", "--bogus", "--log", str(self.log)],
            reason="invalid arguments: unrecognized arguments: --bogus",
        )
        self.setUp()
        self.refuse(
            ["--event", "job-started", "--dry", "--log", str(self.log)],
            reason="invalid arguments: unrecognized arguments: --dry",
        )

    def test_runner_name_missing_and_invalid_are_logged_with_their_marker(self):
        self.target("tagged")
        for env_name, runner_marker, reason in (
            (None, "unknown", "runner name is not set"),
            ("", "unknown", "runner name is not set"),
            ("bad name", "invalid", "runner name is invalid"),
            ("a/b", "invalid", "runner name is invalid"),
            ("x" * 65, "invalid", "runner name is invalid"),
            ("r\n::error::pwn", "invalid", "runner name is invalid"),
        ):
            with self.subTest(runner=env_name):
                environ = {"RUNNER_WORKSPACE": str(self.work_root)}
                if env_name is not None:
                    environ["RUNNER_NAME"] = env_name
                code, _ = self.call(
                    ["--event", "job-started", "--log", str(self.log)], disk=FakeDisk(1), env=environ, free_env=False
                )
                self.assertEqual(code, 0)
                lines = self.log_lines()
                self.assertEqual(len(lines), 1)
                self.assertTrue(lines[0].startswith(f"{STAMP} runner={runner_marker} event=job-started "), lines[0])
                self.assertTrue(lines[0].endswith(f'decision=refused removed=0 entries=0 paths=[] reason="{reason}"'))
                self.log.unlink()

    def test_argument_refusal_logs_the_real_runner_name_from_the_environment(self):
        self.refuse(["--event", "nope", "--log", str(self.log)], env={"RUNNER_NAME": "fed-3"}, runner="fed-3",
                    reason="invalid arguments: argument --event: invalid event 'nope' "
                           "(choose from job-started, job-completed)")

    def test_a_relative_log_is_a_named_refusal_logged_at_the_default_path(self):
        self.target("tagged")
        code, err = self.call(["--event", "job-started", "--log", "rel.log"], disk=FakeDisk(1))
        default = self.home / "ai-tmp" / "runner-disk-hook.log"
        self.assertEqual(code, 0)
        self.assertEqual(err, f"{STDERR_PREFIX}refused: --log is not an absolute path\n")
        self.assertFalse((Path.cwd() / "rel.log").exists())
        self.assertTrue(default.read_text().rstrip().endswith('decision=refused removed=0 entries=0 paths=[] reason="--log is not an absolute path"'))
        self.assertTrue((self.repo / "target").exists())

    def test_a_relative_log_from_the_environment_is_a_named_refusal(self):
        self.target("tagged")
        code, err = self.call(
            ["--event", "job-completed"], disk=FakeDisk(1), env={"RUNNER_DISK_HOOK_LOG": "rel.log"}
        )
        self.assertEqual(code, 0)
        self.assertEqual(err, f"{STDERR_PREFIX}refused: RUNNER_DISK_HOOK_LOG is not an absolute path\n")

    def test_the_environment_log_is_used_when_absolute(self):
        self.target("tagged")
        code, _ = self.call(
            ["--event", "job-completed"], disk=FakeDisk(150 * GIB), env={"RUNNER_DISK_HOOK_LOG": str(self.log)}
        )
        self.assertEqual(code, 0)
        self.assertEqual(len(self.log_lines()), 1)


# ----------------------------------------------------------------------------------------------------------------
# work-root guard
# ----------------------------------------------------------------------------------------------------------------
def fake_lstat(table):
    """table: path string -> (mode, dev) or an exception."""

    def lstat(path):
        entry = table[str(path)]
        if isinstance(entry, BaseException):
            raise entry
        mode, dev = entry
        return types.SimpleNamespace(st_mode=mode, st_dev=dev)

    return lstat


class WorkRootGuard(unittest.TestCase):
    HOME = Path("/Users/example")
    ROOT = "/Users/example/runner/_work/repo"
    PARENT = "/Users/example/runner/_work"

    def refusal(self, root, table=None, home=None):
        return hook.work_root_refusal(root, home or self.HOME, lstat=fake_lstat(table or {}))

    def test_lexical_rows(self):
        rows = (
            (None, "work root is not set"),
            ("", "work root is empty"),
            ("   ", "work root is empty"),
            ("relative/_work/repo", "work root is not an absolute path"),
            ("/a/b/../_work/repo", "work root contains a '..' component"),
            ("/", "work root is the filesystem root"),
            ("/Users/example", "work root is the home directory"),
            ("/Users/example/", "work root is the home directory"),
            ("//Users//example/.", "work root is the home directory"),
            ("/System/" "Volumes/Data", "work root is on the forbidden volume path /System/" "Volumes/Data"),
            ("/System/" "Volumes/Data/x/_work/repo", "work root is on the forbidden volume path /System/" "Volumes/Data"),
            ("//System/" "Volumes/Data/x/_work/repo", "work root is on the forbidden volume path /System/" "Volumes/Data"),
            ("/System/./" "Volumes//Data/x/_work/repo", "work root is on the forbidden volume path /System/" "Volumes/Data"),
            ("/system/" "volumes/data/x/_work/repo", "work root is on the forbidden volume path /System/" "Volumes/Data"),
            ("/" "Volumes/_work", "work root has fewer than 3 path parts"),
            ("/a/_work", "work root has fewer than 3 path parts"),
            ("/Users/example/runner/work/repo", "work root is not <runner root>/_work/<repo>"),
            ("/a/b/c", "work root is not <runner root>/_work/<repo>"),
        )
        for root, reason in rows:
            with self.subTest(root=root):
                self.assertEqual(self.refusal(root), reason)

    def test_system_volumes_data_prefix_lookalike_is_not_forbidden(self):
        table = {self.ROOT: (stat.S_IFDIR, 7), self.PARENT: (stat.S_IFDIR, 7)}
        self.assertIsNone(self.refusal("/System/" "Volumes/Datax/runner/_work/repo", {
            "/System/" "Volumes/Datax/runner/_work/repo": (stat.S_IFDIR, 7),
            "/System/" "Volumes/Datax/runner/_work": (stat.S_IFDIR, 7),
        }))
        self.assertIsNone(self.refusal(self.ROOT, table))

    def test_file_system_rows(self):
        parent_ok = (stat.S_IFDIR, 7)
        rows = (
            ({self.ROOT: FileNotFoundError()}, "work root does not exist"),
            ({self.ROOT: PermissionError(errno.EACCES, "Permission denied")},
             "work root cannot be examined: Permission denied"),
            ({self.ROOT: (stat.S_IFLNK, 7), self.PARENT: parent_ok}, "work root is a symlink"),
            ({self.ROOT: (stat.S_IFREG, 7), self.PARENT: parent_ok}, "work root is not a directory"),
            ({self.ROOT: (stat.S_IFDIR, 8), self.PARENT: parent_ok}, "work root is a volume root"),
            ({self.ROOT: (stat.S_IFDIR, 7), self.PARENT: PermissionError(errno.EACCES, "Permission denied")},
             "work root parent cannot be examined: Permission denied"),
            ({self.ROOT: (stat.S_IFDIR, 7), self.PARENT: parent_ok}, None),
        )
        for table, reason in rows:
            with self.subTest(reason=reason):
                self.assertEqual(self.refusal(self.ROOT, table), reason)

    def test_real_tree_is_accepted_and_a_real_symlink_is_not(self):
        LOCAL_RUNS.mkdir(exist_ok=True)
        scratch = Path(tempfile.mkdtemp(prefix="work-root-8216-", dir=LOCAL_RUNS))
        self.addCleanup(force_remove, scratch)
        root = scratch / "runner" / "_work" / "repo"
        root.mkdir(parents=True)
        self.assertIsNone(hook.work_root_refusal(root, scratch / "home"))
        link = scratch / "runner" / "_work" / "link"
        link.symlink_to(root)
        self.assertEqual(hook.work_root_refusal(link, scratch / "home"), "work root is a symlink")


class WorkRootThroughMain(Base):
    def test_refused_roots_remove_nothing_and_log_the_reason(self):
        self.target("tagged")
        other = self.scratch / "elsewhere"
        other.mkdir()
        for root, reason in (
            (str(self.home), "work root is the home directory"),
            (str(other), "work root is not <runner root>/_work/<repo>"),
            ("/System/" "Volumes/Data/x/_work/r", "work root is on the forbidden volume path /System/" "Volumes/Data"),
        ):
            with self.subTest(root=root):
                code, err = self.call(
                    ["--event", "job-completed", "--log", str(self.log), "--work-root", root], disk=FakeDisk(1)
                )
                self.assertEqual(code, 0)
                self.assertEqual(err, f"{STDERR_PREFIX}refused: {reason}\n")
                self.assertTrue(self.log_lines()[-1].endswith(f'decision=refused removed=0 entries=0 paths=[] reason="{reason}"'))
                self.assertTrue((self.repo / "target").exists())


# ----------------------------------------------------------------------------------------------------------------
# untrusted text
# ----------------------------------------------------------------------------------------------------------------
class SafeText(unittest.TestCase):
    ROWS = (
        ("plain", "plain"),
        ("a\nb", "a\\x0ab"),
        ("a\rb", "a\\x0db"),
        ("tab\there", "tab\\x09here"),
        ("::error::boom", ":\\x3aerror:\\x3aboom"),
        ("::add-mask::secret", ":\\x3aadd-mask:\\x3asecret"),
        ("::set-output name=x::y", ":\\x3aset-output name=x:\\x3ay"),
        (":::", ":\\x3a:"),
        ("::", ":\\x3a"),
        (":", ":"),
        ("%0A", "%250A"),
        ("100%", "100%25"),
        ("\x1b[31mred", "\\x1b[31mred"),
        ("\x00", "\\x00"),
        ("\x7f", "\\x7f"),
        ("\x85", "\\x85"),
        ("\x9f", "\\x9f"),
        ("\xa0", "\xa0"),
        ("\\", "\\\\"),
        ("\\x0a", "\\\\x0a"),
        ("\n::error::x", "\\x0a:\\x3aerror:\\x3ax"),
        ("caf\u00e9", "caf\u00e9"),
        ("a" * 512, "a" * 512),
        ("a" * 513, "a" * 512 + "...(+1 chars)"),
        ("a" * 10_000, "a" * 512 + "...(+9488 chars)"),
    )

    def test_table(self):
        for value, expected in self.ROWS:
            with self.subTest(value=value[:20]):
                self.assertEqual(hook.safe_text(value), expected)

    def test_generated_corpus_never_leaks_a_control_character_or_a_command_prefix(self):
        rng = random.Random(8216)
        alphabet = ["a", "Z", "0", ":", "::", "%", "\n", "\r", "\x1b", "\x7f", "\x85", "\\", " ", "é", "\u2028", "="]
        for _ in range(2_000):
            value = "".join(rng.choice(alphabet) for _ in range(rng.randint(0, 40)))
            out = hook.safe_text(value)
            self.assertNotIn("::", out)
            self.assertFalse(out.startswith("::"))
            for char in out:
                code = ord(char)
                self.assertFalse(code < 0x20 or code == 0x7F or 0x80 <= code < 0xA0, (value, out))

    def test_cost_is_linear_on_a_large_input(self):
        started = time.monotonic()
        out = hook.safe_text(":" * 1_000_000 + "\n" * 1_000_000)
        self.assertLess(time.monotonic() - started, WALL_CLOCK_CEILING_SECS)
        self.assertTrue(out.endswith(" chars)"))


class UntrustedTextThroughMain(Base):
    def test_hostile_repo_name_reaches_neither_stderr_nor_the_log_unescaped(self):
        hostile = self.work_root / "r\n::error::pwn %0A"
        (hostile / "target").mkdir(parents=True)
        (hostile / "target" / "f").write_text("x")
        code, err = self.completed(disk=FakeDisk(100 * GIB))
        self.assertEqual(code, 0)
        lines = self.log_lines()
        self.assertEqual(len(lines), 1, "no raw newline inside the log line")
        for line in err.splitlines() + lines:
            self.assertFalse(line.startswith("::"), line)
        for line in err.splitlines():
            self.assertTrue(line.startswith(STDERR_PREFIX), line)
        self.assertNotIn("\x0a::", err)
        self.assertIn("r\\\\x0a:\\\\x3aerror:\\\\x3apwn %250A", lines[0])

    def test_hostile_invalid_event_text_is_one_stderr_line(self):
        code, err = self.call(
            ["--event", "x\n::error::pwn", "--log", str(self.log)], disk=FakeDisk(1)
        )
        self.assertEqual(code, 0)
        self.assertEqual(len(err.splitlines()), 1)
        self.assertTrue(err.startswith(STDERR_PREFIX))
        self.assertNotIn("\n::", err)
        self.assertEqual(len(self.log_lines()), 1)

    def test_hostile_runner_name_from_the_environment_is_marked_invalid(self):
        code, err = self.call(
            ["--event", "job-started", "--log", str(self.log)],
            disk=FakeDisk(1),
            env={"RUNNER_NAME": "r\n::error::x", "RUNNER_WORKSPACE": str(self.work_root)}, free_env=False,
        )
        self.assertEqual(code, 0)
        self.assertEqual(err, f"{STDERR_PREFIX}refused: runner name is invalid\n")
        self.assertIn(" runner=invalid ", self.log_lines()[0])

    def test_hostile_log_path_in_a_write_failure_is_escaped(self):
        bad = self.scratch / "dir\n::error::x"
        bad.mkdir()
        code, err = self.call(["--event", "job-completed", "--log", str(bad)], disk=FakeDisk(150 * GIB))
        self.assertEqual(code, 0)
        self.assertEqual(len(err.splitlines()), 1)
        self.assertTrue(err.startswith(f"{STDERR_PREFIX}log write failed: "))
        self.assertIn("dir\\x0a:\\x3aerror:\\x3ax: Is a directory", err)


# ----------------------------------------------------------------------------------------------------------------
# the allocated-bytes measure
# ----------------------------------------------------------------------------------------------------------------
class AllocatedBytes(Base):
    def test_a_real_file_counts_its_allocated_bytes(self):
        (self.repo / "data.bin").write_bytes(os.urandom(MIB))
        measured = hook.measure_folder_bytes(self.work_root)
        self.assertGreaterEqual(measured, 1_048_576)
        self.assertLessEqual(measured, 1_048_576 + 65_536)

    def test_a_sparse_file_counts_what_it_allocates_not_its_size(self):
        with open(self.repo / "sparse.bin", "wb") as handle:
            handle.truncate(GIB)
        self.assertLess(hook.measure_folder_bytes(self.work_root), 1_048_576)

    def test_hard_links_count_once(self):
        (self.repo / "data.bin").write_bytes(os.urandom(MIB))
        os.link(self.repo / "data.bin", self.repo / "second.bin")
        os.link(self.repo / "data.bin", self.work_root / "third.bin")
        measured = hook.measure_folder_bytes(self.work_root)
        self.assertGreaterEqual(measured, 1_048_576)
        self.assertLessEqual(measured, 1_048_576 + 65_536)

    def test_a_symlink_is_not_followed(self):
        outside = self.scratch / "outside.bin"
        outside.write_bytes(os.urandom(MIB))
        (self.repo / "link").symlink_to(outside)
        (self.repo / "dirlink").symlink_to(self.scratch)
        self.assertLess(hook.measure_folder_bytes(self.work_root), 65_536)

    def test_a_directory_on_another_device_is_not_entered(self):
        (self.repo / "mount").mkdir()
        (self.repo / "mount" / "big.bin").write_bytes(os.urandom(MIB))
        real = os.fstat
        mount_ino = (self.repo / "mount").stat().st_ino

        def fake(fd):
            info = real(fd)
            if info.st_ino == mount_ino:
                return types.SimpleNamespace(st_dev=info.st_dev + 1, st_mode=info.st_mode, st_ino=info.st_ino)
            return info

        with mock.patch.object(os, "fstat", side_effect=fake):
            self.assertLess(hook.measure_folder_bytes(self.work_root), 65_536)

    def test_entry_cap_is_exact_for_files_and_directories(self):
        for index in range(3):
            (self.repo / f"d{index}").mkdir()
        # work root holds repo (1) + d0 d1 d2 (3) = 4 entries
        self.assertIsInstance(hook.measure_folder_bytes(self.work_root, 4), int)
        with self.assertRaises(hook.MeasureError) as caught:
            hook.measure_folder_bytes(self.work_root, 3)
        self.assertEqual((caught.exception.reason, caught.exception.state), ("more than 3 entries", hook.FolderState.CAP))

    def test_directories_alone_exceed_the_cap(self):
        for index in range(4):
            (self.repo / f"d{index}").mkdir()
        # 1 repo dir + 4 empty directories = 5 names, no file among them
        with self.assertRaises(hook.MeasureError) as caught:
            hook.measure_folder_bytes(self.work_root, 4)
        self.assertEqual(caught.exception.reason, "more than 4 entries")

    def test_depth_over_the_cap_is_unreadable_with_its_reason(self):
        fd = os.open(self.repo, hook.DIR_OPEN_FLAGS)
        try:
            for index in range(258):
                os.mkdir(f"d{index}", dir_fd=fd)
                child = os.open(f"d{index}", hook.DIR_OPEN_FLAGS, dir_fd=fd)
                os.close(fd)
                fd = child
        finally:
            os.close(fd)
        with self.assertRaises(hook.MeasureError) as caught:
            hook.measure_folder_bytes(self.work_root)
        self.assertEqual(
            (caught.exception.reason, caught.exception.state),
            ("tree deeper than 256 levels", hook.FolderState.UNREADABLE),
        )
        deep = self.repo / "d0"
        self.addCleanup(
            lambda: hook.safe_remove.check_and_remove(
                os.open(self.repo, hook.DIR_OPEN_FLAGS), "d0", tag=None, max_depth=10_000
            )
        )
        self.assertTrue(deep.exists())

    def test_100k_entries_are_walked_inside_the_ceiling(self):
        for index in range(BIG_WALK_ENTRIES):
            (self.repo / f"f{index}").write_bytes(b"")
        started = time.monotonic()
        measured = hook.measure_folder_bytes(self.work_root)
        elapsed = time.monotonic() - started
        self.assertEqual(measured, 0)
        self.assertLess(elapsed, WALL_CLOCK_CEILING_SECS)
        with self.assertRaises(hook.MeasureError) as caught:
            hook.measure_folder_bytes(self.work_root, BIG_WALK_ENTRIES)
        self.assertEqual(caught.exception.reason, "more than 100000 entries")

    def test_unreadable_subdirectory_is_unreadable_with_its_cause(self):
        sealed = self.repo / "sealed"
        sealed.mkdir()
        sealed.chmod(0)
        with self.assertRaises(hook.MeasureError) as caught:
            hook.measure_folder_bytes(self.work_root)
        self.assertEqual(caught.exception.state, hook.FolderState.UNREADABLE)
        self.assertEqual(
            caught.exception.reason, f"work folder size read failed under {self.work_root}: Permission denied"
        )

    def test_missing_root_is_unreadable(self):
        with self.assertRaises(hook.MeasureError) as caught:
            hook.measure_folder_bytes(self.scratch / "nope")
        self.assertEqual(
            caught.exception.reason,
            f"work folder size read failed under {self.scratch / 'nope'}: No such file or directory",
        )


class FolderThroughRun(Base):
    def test_cap_hit_with_enough_free_is_entry_cap_and_exit_zero(self):
        self.target("tagged")
        code, err = self.started(disk=FakeDisk(100 * GIB), max_walk=2)
        self.assertEqual(code, 0)
        row = fields(self.log_lines()[0])
        self.assertEqual(row["decision"], "entry-cap")
        self.assertEqual(row["reason"], '"free space 100.00 GiB is at or above the 60 GiB floor; more than 2 entries"')
        self.assertEqual((row["folder_bytes_before"], row["folder_bytes_after"]), ("unknown", "unknown"))
        self.assertTrue((self.repo / "target").exists())
        self.assertEqual(err, f"{STDERR_PREFIX}entry-cap: more than 2 entries\n")

    def test_the_cap_is_exact_through_run(self):
        self.target("tagged")  # repo, target, CACHEDIR.TAG, file.bin = 4 entries under the work root
        code, _ = self.started(disk=FakeDisk(100 * GIB), max_walk=4)
        self.assertEqual(fields(self.log_lines()[0])["decision"], "enough-free")
        self.log.unlink()
        code, _ = self.started(disk=FakeDisk(100 * GIB), max_walk=3)
        self.assertEqual(fields(self.log_lines()[0])["decision"], "entry-cap")

    def test_unreadable_folder_with_enough_free_is_refused_measure_exit_zero(self):
        self.target("tagged")
        sealed = self.work_root / "sealed"
        sealed.mkdir()
        sealed.chmod(0)
        code, err = self.started(disk=FakeDisk(100 * GIB))
        self.assertEqual(code, 0)
        row = fields(self.log_lines()[0])
        self.assertEqual(row["decision"], "refused-measure")
        self.assertEqual(
            row["reason"],
            f'"free space 100.00 GiB is at or above the 60 GiB floor; work folder size read failed under '
            f'{self.work_root}: Permission denied; {self.work_root}/sealed: test-tmp not cleared, directory cannot be opened: Permission denied"',
        )

    def test_over_the_ceiling_clears_although_free_is_above_the_floor(self):
        target = self.target("tagged")
        (target / "big.bin").write_bytes(os.urandom(MIB))
        code, _ = self.started(disk=FakeDisk(100 * GIB, 100 * GIB), ceiling=1_000_000)
        self.assertEqual(code, 0)
        self.assertFalse(target.exists())
        row = fields(self.log_lines()[0])
        self.assertEqual(row["decision"], "clear")
        self.assertRegex(
            row["reason"], r'^"work folder \d+ allocated bytes is over the 1000000 byte ceiling"$'
        )
        self.assertGreater(int(row["folder_bytes_before"]), 1_000_000)
        self.assertLess(int(row["folder_bytes_after"]), 1_000_000)

    def test_the_ceiling_boundary_is_strict(self):
        target = self.target("tagged")
        (target / "big.bin").write_bytes(os.urandom(MIB))
        measured = hook.measure_folder_bytes(self.work_root)
        code, _ = self.started(disk=FakeDisk(100 * GIB), ceiling=measured)
        self.assertEqual(fields(self.log_lines()[0])["decision"], "enough-free")
        self.assertTrue(target.exists())
        self.log.unlink()
        code, _ = self.started(disk=FakeDisk(100 * GIB, 100 * GIB), ceiling=measured - 1)
        self.assertEqual(fields(self.log_lines()[0])["decision"], "clear")

    def test_job_completed_does_not_measure_the_folder(self):
        self.target("tagged")
        with mock.patch.object(hook, "measure_folder_bytes", side_effect=AssertionError("measured")):
            code, _ = self.completed(disk=FakeDisk(150 * GIB))
        self.assertEqual(code, 0)


# ----------------------------------------------------------------------------------------------------------------
# the log
# ----------------------------------------------------------------------------------------------------------------
class LogFile(Base):
    def test_the_log_file_is_created_0600(self):
        self.target("tagged")
        old = os.umask(0)
        try:
            self.completed(disk=FakeDisk(150 * GIB))
        finally:
            os.umask(old)
        self.assertEqual(stat.S_IMODE(self.log.stat().st_mode), 0o600)

    def test_the_default_log_directory_is_created_0700_and_the_file_0600(self):
        self.target("tagged")
        old = os.umask(0)
        try:
            code, _ = self.call(["--event", "job-completed"], disk=FakeDisk(150 * GIB))
        finally:
            os.umask(old)
        default_dir = self.home / "ai-tmp"
        self.assertEqual(code, 0)
        self.assertEqual(stat.S_IMODE(default_dir.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE((default_dir / "runner-disk-hook.log").stat().st_mode), 0o600)

    def test_an_explicit_log_directory_is_not_created(self):
        missing = self.scratch / "no-such-dir" / "hook.log"
        code, err = self.call(["--event", "job-completed", "--log", str(missing)], disk=FakeDisk(150 * GIB))
        self.assertEqual(code, 0)
        self.assertFalse(missing.parent.exists())
        self.assertTrue(err.startswith(f"{STDERR_PREFIX}log write failed: {missing}: No such file or directory; line: "))

    def test_log_lines_append(self):
        self.target("tagged")
        self.completed(disk=FakeDisk(150 * GIB))
        self.completed(disk=FakeDisk(150 * GIB))
        self.assertEqual(len(self.log_lines()), 2)

    def test_a_log_write_failure_does_not_stop_the_removal_and_prints_the_line(self):
        target = self.target("tagged")
        self.log.mkdir()
        code, err = self.completed(disk=FakeDisk(100 * GIB, 200 * GIB))
        self.assertEqual(code, 0)
        self.assertFalse(target.exists())
        self.assertTrue(err.startswith(f"{STDERR_PREFIX}log write failed: {self.log}: Is a directory; line: {STAMP} runner=r1 "))
        self.assertIn("decision=clear removed=1", err)

    def test_a_symlink_log_is_not_followed(self):
        victim = self.scratch / "victim.txt"
        victim.write_text("keep")
        self.log.symlink_to(victim)
        code, err = self.completed(disk=FakeDisk(150 * GIB))
        self.assertEqual(code, 0)
        self.assertEqual(victim.read_text(), "keep")
        self.assertIn("log write failed", err)

    def test_the_below_floor_line_is_also_written_when_the_log_is_the_default(self):
        self.target("none")
        code, _ = self.call(["--event", "job-started"], disk=FakeDisk(START_FLOOR_BYTES - 1))
        self.assertEqual(code, 75)
        lines = (self.home / "ai-tmp" / "runner-disk-hook.log").read_text().splitlines()
        self.assertEqual(
            lines[1],
            f"{STAMP} decision=below-floor event=job-started free_bytes=64424509439 floor_bytes=64424509440 runner=r1",
        )


# ----------------------------------------------------------------------------------------------------------------
# what is cleared, and what is kept
# ----------------------------------------------------------------------------------------------------------------
class Targets(Base):
    def test_only_tagged_targets_of_this_work_root_are_removed(self):
        tagged = self.target("tagged")
        other_repo = self.work_root / "other"
        (other_repo / "target").mkdir(parents=True)
        (other_repo / "target" / "f").write_text("x")  # untagged: kept
        nested = self.repo / "sub" / "target"
        nested.mkdir(parents=True)
        (nested / "CACHEDIR.TAG").write_text(SIGNATURE + "\n")  # not <work root>/<repo>/target: kept
        code, err = self.completed(disk=FakeDisk(100 * GIB, 200 * GIB))
        self.assertEqual(code, 0)
        self.assertFalse(tagged.exists())
        self.assertTrue((other_repo / "target" / "f").exists())
        self.assertTrue(nested.exists())
        self.assertEqual(err, f"{STDERR_PREFIX}clear: {other_repo}/target: CACHEDIR.TAG is missing\n")
        self.assertEqual(fields(self.log_lines()[0])["decision"], "clear")

    def test_a_symlinked_target_is_refused_and_its_destination_untouched(self):
        outside = self.scratch / "outside"
        outside.mkdir()
        (outside / "CACHEDIR.TAG").write_text(SIGNATURE + "\n")
        (outside / "precious").write_text("keep")
        (self.repo / "target").symlink_to(outside)
        code, err = self.completed(disk=FakeDisk(100 * GIB))
        self.assertEqual(code, 0)
        self.assertEqual((outside / "precious").read_text(), "keep")
        self.assertEqual(fields(self.log_lines()[0])["decision"], "refused-target")
        self.assertIn(f"{self.repo}/target: directory is a symlink", err)

    def test_a_symlinked_repo_directory_is_not_entered(self):
        outside = self.scratch / "outside"
        (outside / "target").mkdir(parents=True)
        (outside / "target" / "CACHEDIR.TAG").write_text(SIGNATURE + "\n")
        (self.work_root / "linked").symlink_to(outside)
        code, err = self.completed(disk=FakeDisk(100 * GIB))
        self.assertEqual(code, 0)
        self.assertTrue((outside / "target" / "CACHEDIR.TAG").exists())
        self.assertIn(f"{self.work_root}/linked: repo directory is a symlink, not entered", err)

    def test_every_tag_state_has_its_exact_reason_through_the_hook(self):
        target = self.repo / "target"
        target.mkdir()
        rows = (
            (None, "CACHEDIR.TAG is missing"),
            (b"Signature: 00000000000000000000000000000000\n", "CACHEDIR.TAG first line is not the expected signature"),
            (b"", "CACHEDIR.TAG first line is not the expected signature"),
        )
        for content, reason in rows:
            with self.subTest(reason=reason, content=content):
                tag = target / "CACHEDIR.TAG"
                if tag.exists():
                    tag.unlink()
                if content is not None:
                    tag.write_bytes(content)
                code, err = self.completed(disk=FakeDisk(100 * GIB))
                self.assertEqual(code, 0)
                self.assertIn(f"{target}: {reason}", err)
                self.assertTrue(target.exists())
                self.log.unlink()


# ----------------------------------------------------------------------------------------------------------------
# the one-line .sh wiring
# ----------------------------------------------------------------------------------------------------------------
class Wrapper(unittest.TestCase):
    def lines(self):
        return WRAPPER_PATH.read_text().splitlines()

    def test_the_wrapper_is_one_exec_line_and_the_only_sh_file_in_scripts_ci(self):
        code = [line for line in self.lines() if line.strip() and not line.lstrip().startswith("#")]
        self.assertEqual(len(code), 1, code)
        self.assertTrue(code[0].startswith("exec /opt/homebrew/bin/python3.12 -I "), code[0])
        self.assertEqual(self.lines()[0], "#!/bin/bash")
        self.assertTrue(os.access(WRAPPER_PATH, os.X_OK))
        self.assertEqual(sorted(p.name for p in CI_DIR.rglob("*.sh")), ["runner_disk_hook.sh"])

    @unittest.skipUnless(
        WRAPPER_PYTHON.exists(), "the wrapper starts the macOS Homebrew interpreter /opt/homebrew/bin/python3.12"
    )
    def test_the_wrapper_starts_the_hook_under_each_symlink_name(self):
        LOCAL_RUNS.mkdir(exist_ok=True)
        scratch = Path(tempfile.mkdtemp(prefix="wrapper-8216-", dir=LOCAL_RUNS))
        self.addCleanup(force_remove, scratch)
        install = scratch / "hooks"
        install.mkdir()
        (install / "runner_disk_hook.py").symlink_to(HOOK_PATH)
        names = ("runner_disk_hook_job-started.sh", "runner_disk_hook_job-completed.sh", "evil.sh")
        for name in names:
            (install / name).symlink_to(WRAPPER_PATH)
        work_root = scratch / "runner" / "_work" / "repo"
        (work_root / "repo").mkdir(parents=True)
        home = scratch / "home"
        home.mkdir()
        elsewhere = scratch / "elsewhere"
        elsewhere.mkdir()
        log = scratch / "hook.log"
        env = {
            "RUNNER_WORKSPACE": str(work_root), "RUNNER_NAME": "r1", "RUNNER_DISK_HOOK_LOG": str(log),
            "HOME": str(home), "PATH": "/usr/bin:/bin",
        }
        expected = {
            "runner_disk_hook_job-started.sh": "job-started",
            "runner_disk_hook_job-completed.sh": "job-completed",
            "evil.sh": "unknown",
        }
        for name in names:
            with self.subTest(name=name):
                if log.exists():
                    log.unlink()
                done = subprocess.run(
                    [str(install / name)], cwd=elsewhere, env=env, capture_output=True, text=True, timeout=60,
                    check=False,
                )
                row = log.read_text().splitlines()[0]
                self.assertIn(f" runner=r1 event={expected[name]} ", row)
                if name == "evil.sh":
                    self.assertEqual(done.returncode, 0)
                    self.assertTrue(
                        row.endswith(
                            "reason=\"invoked as 'evil.sh': no event (start it as runner_disk_hook_job-started.sh "
                            "or runner_disk_hook_job-completed.sh)\""
                        ),
                        row,
                    )
                elif name == "runner_disk_hook_job-completed.sh":
                    self.assertEqual(done.returncode, 0, done.stderr)
                else:
                    self.assertEqual(done.returncode == 75, "decision=below-floor" in row, (done.returncode, row))


class TestTmpPort(Base):
    """The old shell hook's .local-runs/test-tmp cleanup (#8216), through descriptors and the same removal engine."""

    def make_test_tmp(self, base: Path) -> Path:
        test_tmp = base / ".local-runs" / "test-tmp"
        (test_tmp / "sub").mkdir(parents=True)
        (test_tmp / "a.txt").write_text("a")
        (test_tmp / "sub" / "b.txt").write_text("b")
        return test_tmp

    def reason(self) -> str:
        return json.loads(fields(self.log_lines()[0])["reason"].removesuffix(" dry-run"))

    def test_job_started_removes_the_work_root_and_the_checkout_test_tmp_with_exact_notes(self):
        at_root = self.make_test_tmp(self.work_root)
        at_repo = self.make_test_tmp(self.repo)
        code, err = self.started(disk=FakeDisk(100 * GIB))
        self.assertEqual(code, 0)
        self.assertFalse(at_root.exists())
        self.assertFalse(at_repo.exists())
        self.assertTrue((self.work_root / ".local-runs").is_dir())
        reason = self.reason()
        self.assertIn(f"test-tmp removed: {at_root} (3 entries)", reason)
        self.assertIn(f"test-tmp removed: {at_repo} (3 entries)", reason)
        row = fields(self.log_lines()[-1])
        self.assertEqual(row["decision"], "enough-free")
        self.assertEqual((row["removed"], row["entries"]), ("0", "0"))

    def test_job_completed_leaves_test_tmp_alone(self):
        at_repo = self.make_test_tmp(self.repo)
        code, _ = self.completed(disk=FakeDisk(500 * GIB))
        self.assertEqual(code, 0)
        self.assertTrue(at_repo.is_dir())
        self.assertNotIn("test-tmp", self.reason())

    def test_dry_run_lists_and_removes_nothing(self):
        at_repo = self.make_test_tmp(self.repo)
        code, _ = self.started("--dry-run", disk=FakeDisk(100 * GIB))
        self.assertEqual(code, 0)
        self.assertTrue((at_repo / "sub" / "b.txt").exists())
        self.assertIn(f"test-tmp would be removed: {at_repo} (3 entries)", self.reason())

    def test_failed_free_read_clears_no_test_tmp(self):
        at_repo = self.make_test_tmp(self.repo)
        code, _ = self.started(disk=FakeDisk(OSError("boom")))
        self.assertEqual(code, 0)
        self.assertTrue((at_repo / "sub" / "b.txt").exists())
        self.assertEqual(fields(self.log_lines()[-1])["decision"], "refused-measure")

    def test_symlinked_test_tmp_is_not_followed(self):
        outside = self.scratch / "outside"
        outside.mkdir()
        (outside / "keep.txt").write_text("k")
        local_runs = self.repo / ".local-runs"
        local_runs.mkdir()
        (local_runs / "test-tmp").symlink_to(outside)
        code, _ = self.started(disk=FakeDisk(100 * GIB))
        self.assertEqual(code, 0)
        self.assertTrue((outside / "keep.txt").exists())
        self.assertTrue((local_runs / "test-tmp").is_symlink())
        self.assertIn(f"{local_runs}/test-tmp: test-tmp not cleared, directory is a symlink", self.reason())

    def test_symlinked_local_runs_is_not_followed(self):
        outside = self.scratch / "outside"
        (outside / "test-tmp").mkdir(parents=True)
        (outside / "test-tmp" / "keep.txt").write_text("k")
        (self.repo / ".local-runs").symlink_to(outside)
        code, _ = self.started(disk=FakeDisk(100 * GIB))
        self.assertEqual(code, 0)
        self.assertTrue((outside / "test-tmp" / "keep.txt").exists())
        self.assertIn(f"{self.repo}/.local-runs/test-tmp: test-tmp not cleared, directory is a symlink", self.reason())

    def test_symlinked_checkout_directory_is_not_entered(self):
        outside = self.scratch / "outside"
        victim = self.make_test_tmp(outside)
        (self.work_root / "linked").symlink_to(outside)
        code, _ = self.started(disk=FakeDisk(100 * GIB))
        self.assertEqual(code, 0)
        self.assertTrue((victim / "sub" / "b.txt").exists())
        self.assertNotIn("linked", self.reason())

    def test_read_only_subdirectory_is_removed_without_a_chmod_subprocess(self):
        at_repo = self.make_test_tmp(self.repo)
        (at_repo / "sub").chmod(0o500)
        code, _ = self.started(disk=FakeDisk(100 * GIB))
        self.assertEqual(code, 0)
        self.assertFalse(at_repo.exists())

    def test_absent_test_tmp_adds_no_note(self):
        code, _ = self.started(disk=FakeDisk(100 * GIB))
        self.assertEqual(code, 0)
        self.assertNotIn("test-tmp", self.reason())

    def test_test_tmp_cleared_and_targets_cleared_below_the_floor_keep_the_exit_code(self):
        at_repo = self.make_test_tmp(self.repo)
        target = self.target("tagged")
        code, _ = self.started(disk=FakeDisk(10 * GIB, 100 * GIB))
        self.assertEqual(code, 0)
        self.assertFalse(at_repo.exists())
        self.assertFalse(target.exists())
        self.assertEqual(fields(self.log_lines()[-1])["decision"], "clear")

    def test_test_tmp_cleared_does_not_lift_a_below_floor_exit(self):
        self.make_test_tmp(self.repo)
        code, _ = self.started(disk=FakeDisk(1 * GIB))
        self.assertEqual(code, 75)
        self.assertEqual(fields(self.log_lines()[0])["decision"], "below-floor")


if __name__ == "__main__":
    unittest.main()
