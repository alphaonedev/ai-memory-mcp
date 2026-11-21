# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""Pin scripts/ci/runner_disk_hook.py (#8216, umbrella: CI shard budget, load wait and watchdog scripts).

Defect class: unbounded cost (disk) with a destructive remedy, so also matcher
bypass and fail-open on the remove path. Invariant, for all inputs: the hook
removes a directory only when the work root is proven, the candidate is named
exactly ``target`` at ``<work root>/<repo>/target``, is a real directory
inside the resolved work root on the same device, and holds cargo's
CACHEDIR.TAG with the cache directory signature on its first line; every other
case is a refusal with its own exact reason and nothing is removed. A free-space
read that fails, returns nothing or is negative is a refusal to decide. The hook
exits 0 on every path.

Class cells, each over a named corpus: EVENT_FREE_TABLE (event x free space at
floor-1, floor, floor+1 of both floors), WORK_ROOT_FORMS (every way the work root
can be wrong), CANDIDATE_FORMS (every way a target can fail the proof),
FREE_READ_FORMS (every way the disk read can fail). The expected column of every
table is written out by hand.

All trees live under <clone>/.local-runs/ and the tests remove nothing outside it.

Run: python3.12 -I -m unittest discover -s scripts/ci/tests -p test_runner_disk_hook_8216.py
Python 3.12+, standard library only.
"""

import contextlib
import errno
import importlib.util
import io
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
HOOK_PATH = REPO_ROOT / "scripts" / "ci" / "runner_disk_hook.py"
LOCAL_RUNS = REPO_ROOT / ".local-runs"

GIB = 1024**3
RUNNER = "runner-test-1"
SIGNATURE_LINE = "Signature: 8a477f597d28d172789f06886806bc55"
BIG_TREE_DIRS = 20
BIG_TREE_FILES_PER_DIR = 1000  # 20K files in all
BIG_TREE_CEILING_SECS = 30.0
SUBPROCESS_TIMEOUT_SECS = 60

LINE_RE = re.compile(
    r"^(?P<ts>\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ) runner=(?P<runner>\S+) event=(?P<event>\S+) "
    r"free_before_gib=(?P<before>\S+) free_after_gib=(?P<after>\S+) decision=(?P<decision>\S+) "
    r"removed=(?P<removed>\d+) paths=(?P<rest>.*)$"
)


def load_hook():
    spec = importlib.util.spec_from_file_location("runner_disk_hook_8216", HOOK_PATH)
    module = importlib.util.module_from_spec(spec)
    sys.modules["runner_disk_hook_8216"] = module
    spec.loader.exec_module(module)
    return module


hook = load_hook()


def parse_line(line):
    """Split one log line into a dict; paths and reason are JSON values."""
    assert "\n" not in line.rstrip("\n"), "log line must be exactly one line"
    match = LINE_RE.match(line.rstrip("\n"))
    assert match, f"log line does not match the format: {line!r}"
    fields = match.groupdict()
    decoder = json.JSONDecoder()
    rest = fields.pop("rest")
    fields["paths"], end = decoder.raw_decode(rest)
    rest = rest[end:]
    assert rest.startswith(" reason="), rest
    rest = rest[len(" reason="):]
    fields["reason"], end = decoder.raw_decode(rest)
    tail = rest[end:]
    assert tail in ("", " dry-run"), tail
    fields["dry_run"] = tail == " dry-run"
    return fields


class HookCase(unittest.TestCase):
    def setUp(self):
        LOCAL_RUNS.mkdir(exist_ok=True)
        self.tmp = Path(tempfile.mkdtemp(prefix="hook8216-", dir=str(LOCAL_RUNS)))
        self.addCleanup(self._cleanup)
        # <tmp>/runner-1/_work/ai-memory-mcp is the work root (RUNNER_WORKSPACE).
        self.work_root = self.tmp / "runner-1" / "_work" / "ai-memory-mcp"
        self.work_root.mkdir(parents=True)
        self.repo = self.work_root / "ai-memory-mcp"
        self.repo.mkdir()
        self.log = self.tmp / "hook.log"
        self.outside = self.tmp / "outside"
        self.outside.mkdir()
        self.canary = self.outside / "canary.txt"
        self.canary.write_text("keep")

    def _cleanup(self):
        resolved = self.tmp.resolve()
        assert str(resolved).startswith(str(LOCAL_RUNS.resolve()) + os.sep), resolved
        for path in self.tmp.rglob("*"):
            with contextlib.suppress(OSError):
                path.chmod(0o755) if path.is_dir() and not path.is_symlink() else None
        shutil.rmtree(self.tmp, ignore_errors=True)

    def make_target(self, repo=None, tag=True, files=2, name="target"):
        repo = repo or self.repo
        target = repo / name
        (target / "debug" / "deps").mkdir(parents=True)
        for index in range(files):
            (target / "debug" / "deps" / f"f{index}.o").write_text("x" * 16)
        if tag is True:
            (target / "CACHEDIR.TAG").write_text(SIGNATURE_LINE + "\nrest\n")
        elif tag is not False:
            (target / "CACHEDIR.TAG").write_text(tag)
        return target

    def run_hook(self, event, free_gib=None, root="default", extra=(), env=None, home=None,
                 disk_free=None, run_cmd=None, runner=RUNNER, log="default"):
        argv = ["--event", event, "--log", str(self.log if log == "default" else log)]
        if root == "default":
            root = self.work_root
        if root is not None:
            argv += ["--work-root", str(root)]
        if runner is not None:
            argv += ["--runner-name", runner]
        if free_gib is not None:
            argv += ["--free-gib", str(free_gib)]
        argv += list(extra)
        commands = []

        def recorder(cmd):
            commands.append(list(cmd))
            return 0

        err = io.StringIO()
        rc = hook.main(
            argv, env={} if env is None else env,
            home=home or (self.tmp / "no-such-home"),
            disk_free=disk_free, run_cmd=run_cmd or recorder, stderr=err,
        )
        line = None
        if self.log.exists():
            lines = self.log.read_text().splitlines()
            self.assertEqual(len(lines), 1, lines)
            line = parse_line(lines[0] + "\n")
        return rc, line, err.getvalue(), commands


class EventFreeTable(HookCase):
    """EVENT_FREE_TABLE: every event x free space at floor-1, floor, floor+1 of both floors."""

    def test_constants(self):
        self.assertEqual(hook.CLEAR_BELOW_GIB_AFTER_JOB, 150)
        self.assertEqual(hook.START_FLOOR_GIB, 60)
        self.assertEqual(hook.TARGET_DIR_NAME, "target")
        self.assertEqual(hook.MARKER_FILE_NAME, "CACHEDIR.TAG")
        self.assertEqual(hook.DEFAULT_LOG_PATH, "/Users/fate/ai-tmp/runner-disk-hook.log")

    def test_event_free_table(self):
        after_job = hook.CLEAR_BELOW_GIB_AFTER_JOB
        start = hook.START_FLOOR_GIB
        # (event, free GiB, decision value, target removed)
        rows = [
            ("job-started", start - 1, "clear", True),
            ("job-started", start, "enough-free", False),
            ("job-started", start + 1, "enough-free", False),
            ("job-started", after_job - 1, "enough-free", False),
            ("job-started", after_job, "enough-free", False),
            ("job-started", after_job + 1, "enough-free", False),
            ("job-completed", start - 1, "clear", True),
            ("job-completed", start, "clear", True),
            ("job-completed", start + 1, "clear", True),
            ("job-completed", after_job - 1, "clear", True),
            ("job-completed", after_job, "enough-free", False),
            ("job-completed", after_job + 1, "enough-free", False),
        ]
        for event, free, decision, removed in rows:
            with self.subTest(event=event, free=free):
                target = self.make_target()
                self.log.unlink(missing_ok=True)
                rc, line, err, _ = self.run_hook(event, free_gib=free)
                self.assertEqual(rc, 0)
                self.assertEqual(line["decision"], decision)
                self.assertEqual(line["event"], event)
                self.assertEqual(line["runner"], RUNNER)
                self.assertEqual(line["before"], f"{free:.2f}")
                self.assertFalse(line["dry_run"])
                self.assertEqual(target.exists(), not removed)
                if removed:
                    self.assertEqual(line["removed"], "1")
                    self.assertEqual(line["paths"], [str(target)])
                    self.assertEqual(line["reason"], "")
                else:
                    floor = 60 if event == "job-started" else 150
                    self.assertEqual(line["removed"], "0")
                    self.assertEqual(line["paths"], [])
                    self.assertEqual(
                        line["reason"],
                        f"free space {free:.2f} GiB is at or above the {floor} GiB floor",
                    )
                shutil.rmtree(target, ignore_errors=True)

    def test_log_line_time_is_utc_and_one_line_per_call(self):
        self.make_target()
        self.run_hook("job-completed", free_gib=10)
        self.run_hook("job-completed", free_gib=10)
        lines = self.log.read_text().splitlines()
        self.assertEqual(len(lines), 2)
        for line in lines:
            parse_line(line + "\n")

    def test_free_after_is_remeasured(self):
        target = self.make_target()
        reads = iter([10 * GIB, 200 * GIB])
        rc, line, _, _ = self.run_hook("job-completed", disk_free=lambda path: next(reads))
        self.assertEqual(rc, 0)
        self.assertEqual((line["before"], line["after"]), ("10.00", "200.00"))
        self.assertFalse(target.exists())


class WorkRootForms(HookCase):
    """WORK_ROOT_FORMS: every way the work root can be wrong ends in a named refusal."""

    def assert_refused(self, root, reason, env=None, home=None, free=10):
        target = self.make_target()
        self.log.unlink(missing_ok=True)
        rc, line, err, cmds = self.run_hook("job-started", free_gib=free, root=root, env=env, home=home)
        self.assertEqual(rc, 0)
        self.assertEqual(line["decision"], "refused")
        self.assertEqual(line["reason"], reason)
        self.assertEqual(line["removed"], "0")
        self.assertIn(reason, err)
        self.assertEqual(cmds, [])
        self.assertTrue(target.exists())
        return line

    def test_unset(self):
        self.assert_refused(None, "work root is not set")

    def test_unset_env_does_not_fall_back_to_workspace(self):
        self.assert_refused(None, "work root is not set", env={"GITHUB_WORKSPACE": str(self.repo)})

    def test_empty_and_blank(self):
        self.assert_refused("", "work root is empty")
        self.assert_refused("   ", "work root is empty")

    def test_relative(self):
        self.assert_refused("relative/work", "work root is not an absolute path")

    def test_dotdot_component(self):
        self.assert_refused(f"{self.work_root}/../ai-memory-mcp", "work root contains a '..' component")

    def test_filesystem_root(self):
        self.assert_refused("/", "work root is the filesystem root")

    def test_missing(self):
        self.assert_refused(self.tmp / "nope" / "a" / "b", "work root does not exist")

    def test_symlinked(self):
        link = self.tmp / "runner-link" / "x" / "y"
        link.parent.mkdir(parents=True)
        link.symlink_to(self.work_root)
        self.assert_refused(link, "work root is a symlink")

    def test_not_a_directory(self):
        plain = self.tmp / "a" / "b" / "file"
        plain.parent.mkdir(parents=True)
        plain.write_text("x")
        self.assert_refused(plain, "work root is not a directory")

    def test_home_directory(self):
        home = self.tmp / "home" / "u" / "v"
        home.mkdir(parents=True)
        self.assert_refused(home, "work root is the home directory", home=home)

    def test_volume_root(self):
        with self._mounted(self.work_root):
            self.assert_refused(self.work_root, "work root is a volume root")

    @contextlib.contextmanager
    def _mounted(self, path):
        real = os.path.ismount
        original = str(path)

        def fake(candidate):
            return str(candidate) == original or real(candidate)

        os.path.ismount = fake
        try:
            yield
        finally:
            os.path.ismount = real

    def test_fewer_than_three_parts(self):
        # the depth rule is lexical and checked before the file system, so it holds on every host.
        self.assertEqual(
            hook.work_root_refusal(Path("/Volumes/f1dev"), home=Path("/nonexistent-home-dir")),
            "work root has fewer than 3 path parts",
        )

    def test_env_input_is_used_when_no_argument(self):
        target = self.make_target()
        env = {"RUNNER_WORKSPACE": str(self.work_root), "RUNNER_NAME": RUNNER}
        err = io.StringIO()
        rc = hook.main(["--event", "job-completed", "--log", str(self.log), "--free-gib", "5"],
                       env=env, home=self.tmp / "h", stderr=err, run_cmd=lambda c: 0)
        self.assertEqual(rc, 0)
        self.assertFalse(target.exists())
        self.assertEqual(parse_line(self.log.read_text())["runner"], RUNNER)

    def test_runner_name_unset_and_invalid(self):
        target = self.make_target()
        rc, line, _, _ = self.run_hook("job-completed", free_gib=5, runner=None)
        self.assertEqual((rc, line["decision"], line["reason"], line["runner"]),
                         (0, "refused", "runner name is not set", "unknown"))
        self.log.unlink()
        rc, line, _, _ = self.run_hook("job-completed", free_gib=5, runner="bad name/../x")
        self.assertEqual((rc, line["decision"], line["reason"], line["runner"]),
                         (0, "refused", "runner name is invalid", "invalid"))
        self.assertTrue(target.exists())

    def test_bad_arguments_exit_zero_with_reason(self):
        target = self.make_target()
        err = io.StringIO()
        rc = hook.main(["--event", "job-finished", "--log", str(self.log)], env={},
                       home=self.tmp / "h", stderr=err, run_cmd=lambda c: 0)
        self.assertEqual(rc, 0)
        line = parse_line(self.log.read_text())
        self.assertEqual(line["decision"], "refused")
        self.assertTrue(line["reason"].startswith("invalid arguments: "), line["reason"])
        self.assertTrue(target.exists())

    def test_non_finite_free_gib_refused(self):
        target = self.make_target()
        for value in ("nan", "inf", "-inf"):
            with self.subTest(value=value):
                self.log.unlink(missing_ok=True)
                rc, line, _, _ = self.run_hook("job-completed", free_gib=value)
                self.assertEqual(rc, 0)
                self.assertEqual(line["decision"], "refused")
                self.assertTrue(line["reason"].startswith("invalid arguments: "), line["reason"])
                self.assertTrue(target.exists())


class CandidateForms(HookCase):
    """CANDIDATE_FORMS: every way a target can fail the proof is kept, with its own reason."""

    def refused_once(self, target, reason, event="job-completed"):
        self.log.unlink(missing_ok=True)
        rc, line, err, _ = self.run_hook(event, free_gib=1)
        self.assertEqual(rc, 0)
        self.assertEqual(line["decision"], "refused")
        self.assertEqual(line["reason"], reason)
        self.assertEqual(line["removed"], "0")
        self.assertIn(reason, err)
        return line

    def test_target_without_tag_is_kept(self):
        target = self.make_target(tag=False)
        self.refused_once(target, f"{target}: target has no CACHEDIR.TAG")
        self.assertTrue((target / "debug" / "deps" / "f0.o").exists())

    def test_tag_with_other_first_line_is_kept(self):
        for content in ("Signature: 00000000000000000000000000000000\n", "\n" + SIGNATURE_LINE + "\n", ""):
            with self.subTest(content=content):
                target = self.make_target(tag=content)
                self.refused_once(
                    target, f"{target}: CACHEDIR.TAG first line is not the cache directory signature")
                self.assertTrue(target.exists())
                shutil.rmtree(target)

    def test_tag_that_is_a_symlink_is_kept(self):
        target = self.make_target(tag=False)
        real = self.outside / "tag"
        real.write_text(SIGNATURE_LINE + "\n")
        (target / "CACHEDIR.TAG").symlink_to(real)
        self.refused_once(target, f"{target}: target has no CACHEDIR.TAG")
        self.assertTrue(target.exists())

    def test_target_symlink_to_outside_directory(self):
        victim = self.outside / "victim"
        (victim / "sub").mkdir(parents=True)
        (victim / "CACHEDIR.TAG").write_text(SIGNATURE_LINE + "\n")
        (victim / "sub" / "keep.txt").write_text("keep")
        link = self.repo / "target"
        link.symlink_to(victim)
        self.refused_once(link, f"{link}: target is a symlink")
        self.assertTrue((victim / "sub" / "keep.txt").exists())
        self.assertTrue((victim / "CACHEDIR.TAG").exists())
        self.assertTrue(link.is_symlink())

    def test_target_that_is_a_file(self):
        target = self.repo / "target"
        target.write_text("x")
        self.refused_once(target, f"{target}: target is not a directory")
        self.assertTrue(target.exists())

    def test_resolves_outside_root_direct_call(self):
        victim = self.outside / "target"
        victim.mkdir()
        (victim / "CACHEDIR.TAG").write_text(SIGNATURE_LINE + "\n")
        reason = hook.classify_candidate(self.work_root, victim)
        self.assertEqual(reason, f"{victim}: target resolves outside the work root")
        self.assertTrue(victim.exists())

    def test_classify_accepts_a_proven_target(self):
        target = self.make_target()
        self.assertIsNone(hook.classify_candidate(self.work_root, target))

    def test_other_names_and_depths_are_kept(self):
        kept = []
        for repo_name, dir_name in (("a", "Target"), ("b", "target2"), ("c", "targets"), ("d", "mytarget")):
            repo = self.work_root / repo_name
            repo.mkdir()
            kept.append(self.make_target(repo=repo, name=dir_name))
        # nested target at another depth: <root>/<repo>/sub/target and <root>/target
        nested_repo = self.work_root / "e"
        (nested_repo / "sub").mkdir(parents=True)
        kept.append(self.make_target(repo=nested_repo / "sub"))
        kept.append(self.make_target(repo=self.work_root))
        rc, line, _, _ = self.run_hook("job-completed", free_gib=1)
        self.assertEqual(rc, 0)
        self.assertEqual(line["decision"], "clear")
        self.assertEqual(line["removed"], "0")
        self.assertEqual(line["reason"], "no cargo target directory found")
        for path in kept:
            self.assertTrue((path / "CACHEDIR.TAG").exists(), path)

    def test_repo_directory_symlink_is_not_entered(self):
        victim_repo = self.outside / "repo"
        self.make_target(repo=victim_repo)
        link = self.work_root / "linked"
        link.symlink_to(victim_repo)
        self.refused_once(link, f"{link}: repo directory is a symlink, not entered")
        self.assertTrue((victim_repo / "target" / "CACHEDIR.TAG").exists())

    def test_symlink_inside_target_is_unlinked_not_followed(self):
        target = self.make_target()
        outside_dir = self.outside / "tree"
        outside_dir.mkdir()
        (outside_dir / "inner.txt").write_text("keep")
        (target / "debug" / "dir-link").symlink_to(outside_dir)
        (target / "debug" / "file-link").symlink_to(self.canary)
        (target / "debug" / "dangling").symlink_to(self.tmp / "missing")
        rc, line, _, _ = self.run_hook("job-completed", free_gib=1)
        self.assertEqual((rc, line["decision"], line["removed"]), (0, "clear", "1"))
        self.assertFalse(target.exists())
        self.assertEqual(self.canary.read_text(), "keep")
        self.assertEqual((outside_dir / "inner.txt").read_text(), "keep")

    def test_two_repos_both_removed_and_listed(self):
        second = self.work_root / "other-repo"
        second.mkdir()
        first_target = self.make_target()
        second_target = self.make_target(repo=second)
        rc, line, _, _ = self.run_hook("job-completed", free_gib=1)
        self.assertEqual((rc, line["removed"]), (0, "2"))
        self.assertEqual(sorted(line["paths"]), sorted([str(first_target), str(second_target)]))

    def test_another_runners_work_folder_is_untouched(self):
        other = self.tmp / "runner-2" / "_work" / "ai-memory-mcp" / "ai-memory-mcp"
        other.mkdir(parents=True)
        other_target = self.make_target(repo=other)
        mine = self.make_target()
        self.run_hook("job-completed", free_gib=1)
        self.assertFalse(mine.exists())
        self.assertTrue(other_target.exists())

    def test_dry_run_removes_nothing_and_says_so(self):
        target = self.make_target()
        rc, line, _, _ = self.run_hook("job-completed", free_gib=1, extra=["--dry-run"])
        self.assertEqual(rc, 0)
        self.assertTrue(line["dry_run"])
        self.assertEqual((line["decision"], line["removed"], line["paths"]), ("clear", "1", [str(target)]))
        self.assertEqual((line["before"], line["after"]), ("1.00", "1.00"))
        self.assertTrue((target / "debug" / "deps" / "f0.o").exists())
        self.assertTrue(self.log.read_text().rstrip("\n").endswith(" dry-run"))

    def test_removal_failure_is_one_reason_and_exit_zero(self):
        target = self.make_target()
        locked = target / "debug"
        locked.chmod(0o500)
        try:
            rc, line, err, _ = self.run_hook("job-completed", free_gib=1)
        finally:
            locked.chmod(0o755)
        self.assertEqual(rc, 0)
        if os.geteuid() == 0:
            self.skipTest("root ignores directory permissions")
        self.assertEqual((line["decision"], line["removed"]), ("refused", "0"))
        self.assertTrue(line["reason"].startswith(f"{target}: remove failed: "), line["reason"])
        self.assertIn("remove failed", err)

    def test_big_tree_in_bounded_time(self):
        target = self.make_target(files=0)
        for dir_index in range(BIG_TREE_DIRS):
            sub = target / "debug" / f"d{dir_index}"
            sub.mkdir(parents=True)
            for file_index in range(BIG_TREE_FILES_PER_DIR):
                (sub / f"f{file_index}").write_bytes(b"")
        started = time.monotonic()
        rc, line, _, _ = self.run_hook("job-completed", free_gib=1)
        elapsed = time.monotonic() - started
        self.assertEqual((rc, line["removed"]), (0, "1"))
        self.assertFalse(target.exists())
        self.assertLess(elapsed, BIG_TREE_CEILING_SECS)

    def test_deep_tree_is_removed(self):
        target = self.make_target()
        deep = target
        for index in range(100):
            deep = deep / "d"
        deep.mkdir(parents=True)
        rc, line, _, _ = self.run_hook("job-completed", free_gib=1)
        self.assertEqual((rc, line["removed"]), (0, "1"))
        self.assertFalse(target.exists())


class FreeReadForms(HookCase):
    """FREE_READ_FORMS: a failed, empty or negative read is a refusal to decide, never 0 and never plenty."""

    def test_forms(self):
        def raises_oserror(path):
            raise OSError(errno.EIO, "boom")

        def raises_other(path):
            raise RuntimeError("odd")

        rows = [
            (raises_oserror, "free-space read failed: [Errno 5] boom"),
            (lambda path: None, "free-space read returned nothing"),
            (lambda path: -1, "free-space read returned a negative value: -1"),
            (lambda path: -(5 * GIB), f"free-space read returned a negative value: {-(5 * GIB)}"),
            (raises_other, "internal error: RuntimeError: odd"),
        ]
        for reader, reason in rows:
            for event in ("job-started", "job-completed"):
                with self.subTest(reason=reason, event=event):
                    target = self.make_target()
                    self.log.unlink(missing_ok=True)
                    rc, line, err, cmds = self.run_hook(event, disk_free=reader)
                    self.assertEqual(rc, 0)
                    self.assertEqual(line["decision"], "refused")
                    self.assertEqual(line["reason"], reason)
                    self.assertEqual((line["before"], line["after"], line["removed"]), ("unknown", "unknown", "0"))
                    self.assertIn(reason, err)
                    self.assertEqual(cmds, [])
                    self.assertTrue(target.exists())
                    shutil.rmtree(target)

    def test_zero_free_is_a_real_zero(self):
        target = self.make_target()
        rc, line, _, _ = self.run_hook("job-completed", disk_free=lambda path: 0)
        self.assertEqual((rc, line["decision"], line["before"]), (0, "clear", "0.00"))
        self.assertFalse(target.exists())

    def test_default_reader_reads_the_work_root_volume(self):
        seen = []
        real = shutil.disk_usage

        def spy(path):
            seen.append(str(path))
            return real(path)

        shutil.disk_usage = spy
        try:
            self.make_target()
            rc, line, _, _ = self.run_hook("job-completed")
        finally:
            shutil.disk_usage = real
        self.assertEqual(rc, 0)
        self.assertIn(str(self.work_root), seen)
        self.assertRegex(line["before"], r"^\d+\.\d\d$")


class LogForms(HookCase):
    def test_unwritable_log_still_removes_and_says_so(self):
        # decision: a failing audit log does not stop the remedy. A full disk is the usual reason
        # the log cannot be written, and refusing to clear then would keep the disk full.
        target = self.make_target()
        bad = self.tmp / "no-such-dir" / "hook.log"
        rc, line, err, _ = self.run_hook("job-completed", free_gib=1, log=bad)
        self.assertEqual(rc, 0)
        self.assertIsNone(line)
        self.assertFalse(target.exists())
        self.assertIn("log write failed: ", err)
        self.assertIn("decision=clear", err)
        self.assertIn(str(bad), err)

    def test_log_that_is_a_directory(self):
        target = self.make_target()
        rc, _, err, _ = self.run_hook("job-completed", free_gib=1, log=self.tmp)
        self.assertEqual(rc, 0)
        self.assertIn("log write failed: ", err)
        self.assertFalse(target.exists())

    def test_hostile_runner_name_cannot_forge_a_line(self):
        self.make_target()
        rc, line, _, _ = self.run_hook("job-completed", free_gib=1, runner="a\nb decision=forged")
        self.assertEqual((rc, line["runner"], line["decision"]), (0, "invalid", "refused"))

    def test_hostile_path_names_stay_on_one_line(self):
        weird = self.work_root / "re po\nx"
        weird.mkdir()
        target = self.make_target(repo=weird)
        rc, line, _, _ = self.run_hook("job-completed", free_gib=1)
        self.assertEqual((rc, line["removed"]), (0, "1"))
        self.assertEqual(line["paths"], [str(target)])


class TestTmpPort(HookCase):
    """The job-started event also does what the old shell hook did, through an injected command runner."""

    def make_test_tmp(self):
        test_tmp = self.repo / ".local-runs" / "test-tmp"
        (test_tmp / "a" / "b").mkdir(parents=True)
        (test_tmp / "a" / "b" / "f").write_text("x")
        return test_tmp

    def started(self, **kw):
        return self.run_hook("job-started", extra=["--workspace", str(self.repo)], **kw)

    def test_started_strips_acls_then_removes_with_argument_lists(self):
        test_tmp = self.make_test_tmp()
        target = self.make_target()
        rc, line, _, cmds = self.started(free_gib=500)
        self.assertEqual(rc, 0)
        self.assertEqual(cmds, [["chmod", "-RN", str(test_tmp)], ["chmod", "-R", "u+rwx", str(test_tmp)]])
        self.assertFalse(test_tmp.exists())
        self.assertTrue(target.exists())
        self.assertEqual((line["decision"], line["removed"], line["paths"]), ("enough-free", "1", [str(test_tmp)]))
        self.assertEqual(line["reason"], "free space 500.00 GiB is at or above the 60 GiB floor")

    def test_started_below_floor_clears_both(self):
        test_tmp = self.make_test_tmp()
        target = self.make_target()
        rc, line, _, _ = self.started(free_gib=1)
        self.assertEqual((rc, line["decision"], line["removed"]), (0, "clear", "2"))
        self.assertEqual(sorted(line["paths"]), sorted([str(target), str(test_tmp)]))
        self.assertFalse(test_tmp.exists() or target.exists())

    def test_completed_leaves_test_tmp(self):
        test_tmp = self.make_test_tmp()
        rc, line, _, cmds = self.run_hook("job-completed", free_gib=500, extra=["--workspace", str(self.repo)])
        self.assertEqual(rc, 0)
        self.assertEqual(cmds, [])
        self.assertTrue(test_tmp.exists())

    def test_runner_workspace_base_is_also_searched(self):
        test_tmp = self.work_root / ".local-runs" / "test-tmp"
        test_tmp.mkdir(parents=True)
        rc, line, _, cmds = self.started(free_gib=500)
        self.assertEqual(rc, 0)
        self.assertEqual(cmds[0], ["chmod", "-RN", str(test_tmp)])
        self.assertFalse(test_tmp.exists())

    def test_dry_run_keeps_test_tmp_and_runs_no_command(self):
        test_tmp = self.make_test_tmp()
        rc, line, _, cmds = self.run_hook("job-started", free_gib=1,
                                          extra=["--workspace", str(self.repo), "--dry-run"])
        self.assertEqual((rc, cmds, line["dry_run"], line["removed"]), (0, [], True, "1"))
        self.assertTrue(test_tmp.exists())

    def test_symlinked_test_tmp_is_refused(self):
        victim = self.outside / "tt"
        victim.mkdir()
        (victim / "keep").write_text("keep")
        runs = self.repo / ".local-runs"
        runs.mkdir()
        (runs / "test-tmp").symlink_to(victim)
        rc, line, _, cmds = self.started(free_gib=500)
        self.assertEqual(rc, 0)
        reason = f"{runs / 'test-tmp'}: test-tmp path has a symlink component"
        self.assertEqual((line["decision"], line["removed"]), ("refused", "0"))
        self.assertIn(reason, line["reason"])
        self.assertEqual(cmds, [])
        self.assertTrue((victim / "keep").exists())

    def test_symlinked_local_runs_is_refused(self):
        victim = self.outside / "runs"
        (victim / "test-tmp").mkdir(parents=True)
        (self.repo / ".local-runs").symlink_to(victim)
        rc, line, _, cmds = self.started(free_gib=500)
        self.assertIn(f"{self.repo / '.local-runs' / 'test-tmp'}: test-tmp path has a symlink component",
                      line["reason"])
        self.assertEqual(cmds, [])
        self.assertTrue((victim / "test-tmp").exists())

    def test_workspace_outside_root_is_refused(self):
        foreign = self.outside / "ws"
        (foreign / ".local-runs" / "test-tmp").mkdir(parents=True)
        rc, line, _, cmds = self.run_hook("job-started", free_gib=500, extra=["--workspace", str(foreign)])
        self.assertEqual(rc, 0)
        self.assertIn(f"{foreign}: workspace is outside the work root", line["reason"])
        self.assertEqual(cmds, [])
        self.assertTrue((foreign / ".local-runs" / "test-tmp").exists())

    def test_command_failure_does_not_stop_removal(self):
        test_tmp = self.make_test_tmp()

        def failing(cmd):
            raise OSError(errno.ENOENT, "no chmod")

        rc, line, _, _ = self.started(free_gib=500, run_cmd=failing)
        self.assertEqual(rc, 0)
        self.assertFalse(test_tmp.exists())

    @unittest.skipUnless(platform.system() == "Darwin",
                         "macOS only: the deny-only ACL that blocks rmdir exists only on macOS (chmod +a)")
    def test_real_macos_acl_directory_is_removed(self):
        test_tmp = self.make_test_tmp()
        subprocess.run(["chmod", "+a", "everyone deny delete", str(test_tmp / "a")], check=True)
        err = io.StringIO()
        rc = hook.main(["--event", "job-started", "--work-root", str(self.work_root), "--runner-name", RUNNER,
                        "--workspace", str(self.repo), "--free-gib", "500", "--log", str(self.log)],
                       env={}, home=self.tmp / "h", stderr=err)
        self.assertEqual(rc, 0)
        self.assertFalse(test_tmp.exists(), err.getvalue())


class CliForms(HookCase):
    def test_subprocess_exit_zero_and_stderr_reason(self):
        env = {k: v for k, v in os.environ.items() if k not in ("RUNNER_WORKSPACE", "GITHUB_WORKSPACE", "RUNNER_NAME")}
        done = subprocess.run(
            [sys.executable, "-I", str(HOOK_PATH), "--event", "job-completed", "--log", str(self.log),
             "--runner-name", RUNNER, "--free-gib", "1"],
            env=env, capture_output=True, text=True, timeout=SUBPROCESS_TIMEOUT_SECS, check=False,
        )
        self.assertEqual(done.returncode, 0)
        self.assertIn("work root is not set", done.stderr)
        self.assertEqual(parse_line(self.log.read_text())["reason"], "work root is not set")

    def test_subprocess_removes_with_env_inputs(self):
        target = self.make_target()
        env = {"RUNNER_WORKSPACE": str(self.work_root), "RUNNER_NAME": RUNNER,
               "GITHUB_WORKSPACE": str(self.repo), "PATH": os.environ.get("PATH", "")}
        done = subprocess.run(
            [sys.executable, "-I", str(HOOK_PATH), "--event", "job-completed", "--log", str(self.log),
             "--free-gib", "1"],
            env=env, capture_output=True, text=True, timeout=SUBPROCESS_TIMEOUT_SECS, check=False,
        )
        self.assertEqual((done.returncode, done.stderr), (0, ""))
        self.assertFalse(target.exists())

    def test_help_marks_free_gib_as_a_test_input(self):
        done = subprocess.run([sys.executable, "-I", str(HOOK_PATH), "--help"], capture_output=True, text=True,
                              timeout=SUBPROCESS_TIMEOUT_SECS, check=False)
        self.assertEqual(done.returncode, 0)
        self.assertIn("test input", " ".join(done.stdout.split()))

    def test_no_forbidden_constructs_in_the_script(self):
        source = HOOK_PATH.read_text()
        self.assertTrue(source.startswith("#!/opt/homebrew/bin/python3.12\n"))
        for forbidden in ("shell=True", "os.system", "except:", "sudo"):
            # sudo may only appear in the docstring decision line, never as a command
            if forbidden == "sudo":
                self.assertNotIn('"sudo"', source)
                continue
            self.assertNotIn(forbidden, source)


if __name__ == "__main__":
    unittest.main()
