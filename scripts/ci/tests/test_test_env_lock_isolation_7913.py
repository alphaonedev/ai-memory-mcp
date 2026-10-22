#!/usr/bin/env python3
"""#7913: the Test-env HOME-lock gate census is isolated from its self-tests."""

import contextlib
import errno
import importlib.util
import io
import os
import re
from pathlib import Path
import shutil
import signal
import subprocess
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[3]
HELPER = ROOT / "scripts/ci/check_test_env_lock_harness.py"
PROBE = "src/check_test_env_arm_e_probe_3523.rs"
PROBE_BODY = "// planted self-test fixture\n"


def load():
    spec = importlib.util.spec_from_file_location("harness_7913", str(HELPER))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def git(cwd, *args):
    subprocess.run(
        ["git", "-C", str(cwd), "-c", "user.name=t", "-c", "user.email=t@invalid",
         "-c", "commit.gpgsign=false"] + list(args),
        check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def census(root):
    """The real gate in a tree; returns (rc, output)."""
    res = subprocess.run(["bash", "scripts/check-test-env-lock.sh"], cwd=str(root),
                         stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=False)
    return res.returncode, res.stdout.decode()


class TreeCase(unittest.TestCase):
    def setUp(self):
        self.h = load()
        base = ROOT / ".local-runs"
        base.mkdir(exist_ok=True)
        self.tmp = Path(tempfile.mkdtemp(prefix="isolation-7913-", dir=str(base)))
        self.addCleanup(shutil.rmtree, str(self.tmp), True)
        self.root = self.tmp / "tree"
        for rel in ("scripts/check-test-env-lock.sh",):
            self._copy(rel)
        for sub in ("scripts/lib", "scripts/qc-allowlists"):
            for p in (ROOT / sub).rglob("*"):
                if p.is_file():
                    self._copy(str(p.relative_to(ROOT)))
        (self.root / "src").mkdir(parents=True, exist_ok=True)
        (self.root / "src/lib.rs").write_text("pub fn clean() {}\n")
        (self.root / "tests").mkdir()
        (self.root / "tests/.keep").write_text("")
        git(self.root, "init", "-q")
        git(self.root, "add", "-A")
        git(self.root, "commit", "-q", "-m", "scratch")

    def _copy(self, rel):
        dest = self.root / rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(str(ROOT / rel), str(dest))


class IsolationTest(TreeCase):
    def test_probe_in_scratch_tree_does_not_affect_clean_census(self):
        rc0, out0 = census(self.root)
        self.assertEqual(rc0, 0, out0[-400:])
        scratch = self.h.make_copy(self.root, self.tmp / "scratch")
        (scratch / PROBE).write_text(PROBE_BODY)
        self.assertTrue((scratch / PROBE).exists())
        rc1, out1 = census(self.root)
        self.assertEqual((rc1, out1), (rc0, out0))
        self.assertFalse((self.root / PROBE).exists())

    def test_preexisting_probe_in_census_tree_exits_3_with_message(self):
        (self.root / PROBE).write_text(PROBE_BODY)
        res = subprocess.run(
            ["python3", str(HELPER), "census", "--root", str(self.root)],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
        self.assertEqual(res.returncode, 3)
        self.assertEqual(res.stderr.decode().strip(),
                         "self-test fixture present: " + PROBE)
        self.assertEqual((self.root / PROBE).read_text(), PROBE_BODY)

    def test_clean_tree_census_passes_through_the_helper(self):
        res = subprocess.run(
            ["python3", str(HELPER), "census", "--root", str(self.root)],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=False)
        self.assertEqual(res.returncode, 0, res.stdout.decode()[-400:])

    def test_selftest_copy_removed_after_simulated_failure(self):
        seen = []

        def failing(copy):
            seen.append(copy)
            self.assertTrue(copy.is_dir())
            (copy / PROBE).write_text(PROBE_BODY)
            return ["bash", "-c", "exit 7"]

        rc = self.h.run_isolated(self.root, failing, "failcase")
        self.assertEqual(rc, 7)
        self.assertEqual(len(seen), 1)
        self.assertFalse(seen[0].exists())
        self.assertFalse((self.root / self.h.SELFTEST_DIR).exists())
        self.assertFalse((self.root / PROBE).exists())

    def test_selftest_copy_removed_when_the_runner_raises(self):
        def boom(copy):
            raise OSError("simulated launch failure")

        with self.assertRaises(OSError):
            self.h.run_isolated(self.root, boom, "raisecase")
        self.assertFalse((self.root / self.h.SELFTEST_DIR).exists())

    def test_copy_never_inherits_a_source_fixture(self):
        (self.root / PROBE).write_text(PROBE_BODY)
        copy = self.h.make_copy(self.root, self.tmp / "copy")
        self.assertFalse((copy / PROBE).exists())


class PrecheckGlobTest(TreeCase):
    """#7921: the exit-3 pre-check matches exactly the probes the census counts."""

    DOT_PROBES = (
        "src/.check_home_lock_violation_probe.rs",
        "src/.check_passphrase_window_probe_3539.rs",
    )

    def test_dot_prefixed_probe_exits_3_with_exact_message(self):
        for probe in self.DOT_PROBES:
            with self.subTest(probe=probe):
                (self.root / probe).write_text(PROBE_BODY)
                res = subprocess.run(
                    ["python3", str(HELPER), "census", "--root", str(self.root)],
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
                (self.root / probe).unlink()
                self.assertEqual(res.returncode, 3)
                self.assertEqual(res.stderr.decode().strip(),
                                 "self-test fixture present: " + probe)

    def test_every_probe_the_gate_plants_is_matched(self):
        text = (ROOT / "scripts/check-test-env-lock.sh").read_text()
        names = re.findall(r'^\s*probe_\w+="\$\{ROOT\}/src/([^"]+\.rs)"', text, re.M)
        self.assertGreaterEqual(len(names), 16, names)
        for name in names:
            with self.subTest(name=name):
                self.assertTrue(self.h.is_fixture_name(name), name)
        # Product files that merely look similar must not be treated as fixtures.
        for name in ("config.rs", "check_test_env_lock.rs", "lib.rs"):
            self.assertFalse(self.h.is_fixture_name(name), name)


SLEEP_GATE = "scripts/sleep-selftest-gate.sh"


class SignalCleanupTest(TreeCase):
    """#7922: SIGTERM and SIGINT mid-selftest still remove the private copy."""

    def _interrupt(self, sig):
        marker = self.tmp / "started"
        gate = self.root / SLEEP_GATE
        gate.write_text('#!/usr/bin/env bash\necho "$$" > "%s"\nsleep 60\n' % marker)
        git(self.root, "add", "-A")
        git(self.root, "commit", "-q", "-m", "sleep gate")
        proc = subprocess.Popen(
            ["python3", str(HELPER), "selftest", "--root", str(self.root),
             "--gate", SLEEP_GATE], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            deadline = time.time() + 60
            while not marker.exists() and time.time() < deadline:
                time.sleep(0.05)
            self.assertTrue(marker.exists(), "self-test never started")
            parent = self.root / self.h.SELFTEST_DIR
            self.assertTrue(parent.is_dir(), "private copy was not created")
            proc.send_signal(sig)
            rc = proc.wait(timeout=60)
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.wait()
        self.assertEqual(rc, 128 + int(sig))
        self.assertFalse(parent.exists(), "private copy left behind after %s" % sig)

    def test_sigterm_mid_selftest_removes_the_copy(self):
        self._interrupt(signal.SIGTERM)

    def test_sigint_mid_selftest_removes_the_copy(self):
        self._interrupt(signal.SIGINT)


class ParentRmdirNoteTest(TreeCase):
    """#7930: a failed parent.rmdir() is noted on stderr, never swallowed or masking."""

    def _run_with_sibling(self):
        def runner(copy):
            (copy.parent / "sibling-run").mkdir()  # another run still uses the parent
            return ["bash", "-c", "exit 7"]

        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            rc = self.h.run_isolated(self.root, runner, "rmdircase")
        return rc, err.getvalue()

    def test_nonempty_parent_is_noted_and_keeps_the_exit_code(self):
        rc, note = self._run_with_sibling()
        self.assertEqual(rc, 7)
        self.assertIn("NOTE:", note)
        self.assertIn(str(self.root / self.h.SELFTEST_DIR), note)
        self.assertIn("errno %d" % errno.ENOTEMPTY, note)
        self._other_errors_are_not_swallowed()

    def _other_errors_are_not_swallowed(self):
        real = Path.rmdir

        def denied(path):
            raise PermissionError(errno.EACCES, os.strerror(errno.EACCES))

        Path.rmdir = denied
        self.addCleanup(setattr, Path, "rmdir", real)
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            with self.assertRaises(PermissionError):
                self.h.run_isolated(self.root, lambda copy: ["true"], "denycase")
        self.assertIn("errno %d" % errno.EACCES, err.getvalue())


class KillGroupFailureTest(unittest.TestCase):
    """#7926: a failed killpg is recorded on stderr, never swallowed or masking."""

    def _run(self, kill_error):
        h = load()

        class FakeProc:
            pid = 424242

            def __init__(self):
                self.calls = 0

            def wait(self):
                self.calls += 1
                if self.calls == 1:
                    raise h.Interrupted(143)
                return 0

        def failing_killpg(pgid, sig):
            raise kill_error

        h.subprocess = type("S", (), {"Popen": staticmethod(lambda *a, **k: FakeProc())})
        h.os = type("O", (), {"killpg": staticmethod(failing_killpg)})
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            with self.assertRaises(h.Interrupted) as ctx:
                h._run_child(["true"], ".")
        return ctx.exception.code, err.getvalue()

    def test_killpg_failure_is_noted_and_keeps_the_exit_code(self):
        code, note = self._run(OSError(errno.EPERM, os.strerror(errno.EPERM)))
        self.assertEqual(code, 143)
        self.assertIn("424242", note)
        self.assertIn("errno %d" % errno.EPERM, note)

    def test_already_exited_group_is_noted_too(self):
        code, note = self._run(ProcessLookupError(errno.ESRCH, os.strerror(errno.ESRCH)))
        self.assertEqual(code, 143)
        self.assertIn("errno %d" % errno.ESRCH, note)


FAKE_GATE = "scripts/fake-selftest-gate.sh"
# Stands in for ``check-test-env-lock.sh --self-test``: plants the plain and the
# dot-prefixed probes in ITS working tree, records where it ran, and leaves
# them behind (a real run removes them; the private copy is deleted anyway).
FAKE_GATE_BODY = """#!/usr/bin/env bash
set -u
mkdir -p src
: > src/check_test_env_arm_e_probe_9999.rs
: > src/.check_home_lock_violation_probe.rs
pwd > "@RECORD@"
"""


class SelftestIsolationTest(TreeCase):
    """#7919, #7925: observe WHERE every isolated mode runs, not just that helpers exist."""

    def _script_for(self, mode):
        """Path (relative to the tree) of the script ``mode`` executes."""
        return {"selftest": FAKE_GATE, "interrupt": self.h.INTERRUPT_HARNESS}[mode]

    def _fake_scripts(self, mode):
        record = str(self.tmp / ("record-" + mode))
        for rel in {FAKE_GATE, self._script_for(mode)}:
            path = self.root / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(FAKE_GATE_BODY.replace("@RECORD@", record))
        git(self.root, "add", "-A")
        git(self.root, "commit", "-q", "-m", "fake scripts " + mode)
        return Path(record)

    def _snapshot(self):
        return sorted(str(p.relative_to(self.root)) for p in self.root.rglob("*")
                      if p.is_file() and ".git" not in p.parts)

    def observe(self, mode):
        """Run ``mode`` through ``main`` on the census tree; return violations."""
        record = self._fake_scripts(mode)
        before = self._snapshot()
        rc = self.h.main([mode, "--root", str(self.root), "--gate", FAKE_GATE])
        problems = []
        if rc != 0:
            problems.append("%s rc=%d" % (mode, rc))
        ran_in = Path(record.read_text().strip()).resolve()
        if ran_in == self.root.resolve():
            problems.append("self-test ran in the census checkout %s" % ran_in)
        leaked = sorted(p.name for p in (self.root / "src").glob("*probe*.rs"))
        leaked += sorted(p.name for p in (self.root / "src").glob(".*probe*.rs"))
        if leaked:
            problems.append("probe files in the census checkout: %s" % leaked)
        if self._snapshot() != before:
            problems.append("census tree changed during the self-test")
        return problems

    def test_every_isolated_mode_is_covered(self):
        """A new isolated mode in the helper must get a script mapping here."""
        for mode in self.h.ISOLATED_MODES:
            self.assertTrue(self._script_for(mode), mode)

    def test_modes_never_touch_the_census_checkout(self):
        for mode in self.h.ISOLATED_MODES:
            with self.subTest(mode=mode):
                self.assertEqual(self.observe(mode), [])

    def test_in_place_helper_is_caught_by_the_observation(self):
        """Red proof: a helper that runs ANY mode in place must FAIL here."""
        def in_place(root, argv_for, tag):
            return subprocess.run(argv_for(Path(root)), cwd=str(root),
                                  check=False).returncode

        for mode in self.h.ISOLATED_MODES:
            with self.subTest(mode=mode):
                self.h.run_isolated = in_place
                problems = self.observe(mode)
                self.assertTrue(any("ran in the census checkout" in p for p in problems),
                                problems)
                self.assertTrue(any("probe files" in p for p in problems), problems)
                self.h = load()  # restore the real run_isolated


if __name__ == "__main__":
    unittest.main()
