#!/usr/bin/env python3
"""Issue 7920: an interrupted gate --self-test must die of the signal.

check-hardcoded-literals.sh installed one handler for EXIT INT TERM that
cleaned up and RETURNED, so an interrupted self-test resumed and could exit 0
(harness check 41 of test-gate-selftest-interrupt-cleanup.sh).

The self-test is held mid-run by an awk wrapper placed first on PATH: the gate
enumerates `command -v awk` and runs a child per awk, so the wrapper blocks the
child (marker file) while the probe files are planted. The signal is sent to
the gate while the child is STILL HELD (it is not released before the wait):
the gate must stop that child and die of the signal on its own, in well under
a gate scan (8242, 8244). bash is launched directly by Popen, so a real death
by the re-raised signal is returncode -signal; 128+N is reachable only by an
exit 130 / exit 143 handler and is rejected (8245).

A dangling symlink planted at a probe path must be refused like any existing
name, with nothing written through the link (8243).
"""

import os
import shutil
import signal
import stat
import subprocess
import tempfile
import time
import unittest
from pathlib import Path
import sys


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
WA_PROG = "test_gate_selftest_interrupt_7920"
WA_RELATIVE_PATH = "../workflow_annotation.py"
WA_REQUIRED = ("out",)
WA_EXIT_LOAD_REFUSED = 3  # a failed shared-module load; no other meaning in this script
WA_ERROR_TO_STDERR = False

try:
    wa = _load_workflow_annotation()
except (Exception, SystemExit) as exc:  # any failed load: one fixed line built without the module, then exit
    wa_cause = type(exc).__name__
    print("%s: refused: shared module workflow_annotation.py next to the script cannot be loaded (%s)"
          % (WA_PROG, wa_cause if wa_cause.isidentifier() else "BaseException"), file=sys.stderr, flush=True)
    print("::error title=test_gate_selftest_interrupt_7920 refused::test_gate_selftest_interrupt_7920: refused: shared module workflow_annotation.py"
          " next to the script cannot be loaded",
          file=sys.stderr if WA_ERROR_TO_STDERR else sys.stdout, flush=True)
    sys.exit(WA_EXIT_LOAD_REFUSED)

ROOT = Path(__file__).resolve().parents[3]
LOCAL_RUNS = ROOT / ".local-runs"
POLL_CEILING_SECS = 60.0
POLL_STEP_SECS = 0.05
# Signal-to-exit ceiling. With the child stopped by the trap the exit takes
# about a second; the old foreground child took a whole gate scan.
SIGNAL_TO_EXIT_CEILING_SECS = 5.0
REFUSE_CEILING_SECS = 120.0
REFUSE_EXIT_CODE = 2
VICTIM_TEXT = "victim-original\n"

# gate script -> probe paths the self-test plants (relative to ROOT)
GATES = {
    "check-hardcoded-literals.sh": (
        "src/.hardcoded_literal_gate_probe.rs",
        "src/.hardcoded_literal_gate_probe_mb.rs",
    ),
}

WRAPPER = """#!/usr/bin/env python3
import os, sys, time
real = {real!r}
blocked = {blocked!r}
release = {release!r}
probes = {probes!r}
# Block only while a probe exists (the earlier #3623 sub-test also calls awk).
if any(os.path.exists(q) for q in probes) and not (len(sys.argv) > 1 and sys.argv[1] == "--version"):
    open(blocked, "w").close()
    deadline = time.monotonic() + {ceiling}
    while not os.path.exists(release) and time.monotonic() < deadline:
        time.sleep(0.05)
    sys.exit(3)
os.execv(real, [real] + sys.argv[1:])
"""


class GateSelfTestInterrupt7920(unittest.TestCase):
    def run_interrupt(self, gate, sig):
        probes = [ROOT / p for p in GATES[gate]]
        for p in probes:
            self.assertFalse(p.exists(), "stale probe " + str(p))
        LOCAL_RUNS.mkdir(exist_ok=True)
        work = Path(tempfile.mkdtemp(prefix="selftest-7920-", dir=str(LOCAL_RUNS)))
        self.addCleanup(shutil.rmtree, str(work), True)
        for p in probes:
            self.addCleanup(lambda q=p: q.exists() and q.unlink())
        real_awk = shutil.which("awk")
        self.assertIsNotNone(real_awk)
        blocked, release = work / "blocked", work / "release"
        binroot = work / "bin"
        binroot.mkdir()
        wrapper = binroot / "awk"
        wrapper.write_text(WRAPPER.format(
            real=real_awk, blocked=str(blocked), release=str(release),
            ceiling=POLL_CEILING_SECS, probes=[str(p) for p in probes]))
        wrapper.chmod(wrapper.stat().st_mode | stat.S_IXUSR)
        env = dict(os.environ, TMPDIR=str(work),
                   PATH=str(binroot) + os.pathsep + os.environ["PATH"])
        proc = subprocess.Popen(
            ["bash", str(ROOT / "scripts" / gate), "--self-test"],
            cwd=str(ROOT), env=env, stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL)
        rc = None
        try:
            deadline = time.monotonic() + POLL_CEILING_SECS
            while time.monotonic() < deadline:
                if blocked.exists() and all(p.exists() for p in probes):
                    break
                self.assertIsNone(proc.poll(), "self-test ended before probes")
                time.sleep(POLL_STEP_SECS)
            else:
                self.fail("probes never planted within %ss" % POLL_CEILING_SECS)
            sent_at = time.monotonic()
            proc.send_signal(sig)
            try:
                rc = proc.wait(timeout=SIGNAL_TO_EXIT_CEILING_SECS)
            except subprocess.TimeoutExpired:
                rc = None
            elapsed = time.monotonic() - sent_at
        finally:
            release.touch()
            if proc.poll() is None:
                proc.kill()
                proc.wait()
        self.assertIsNotNone(
            rc, "%s still running %ss after %s with the gate child held"
            % (gate, SIGNAL_TO_EXIT_CEILING_SECS, sig.name))
        self.assertEqual(rc, -int(sig),
                         "%s exited %d after %s; must die of the signal" % (gate, rc, sig.name))
        self.assertLess(elapsed, SIGNAL_TO_EXIT_CEILING_SECS)
        wa.out("signal-to-exit %s: %.2fs" % (sig.name, elapsed))
        for p in probes:
            self.assertFalse(p.exists(), "probe left behind: " + str(p))

    def run_dangling_link(self, gate, probe_index):
        probes = [ROOT / p for p in GATES[gate]]
        for p in probes:
            self.assertFalse(p.exists() or p.is_symlink(), "stale probe " + str(p))
        LOCAL_RUNS.mkdir(exist_ok=True)
        work = Path(tempfile.mkdtemp(prefix="selftest-8243-", dir=str(LOCAL_RUNS)))
        self.addCleanup(shutil.rmtree, str(work), True)
        victim = work / "victim"
        link = probes[probe_index]
        os.symlink(str(victim), str(link))
        env = dict(os.environ, TMPDIR=str(work))
        try:
            done = subprocess.run(
                ["bash", str(ROOT / "scripts" / gate), "--self-test"],
                cwd=str(ROOT), env=env, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, timeout=REFUSE_CEILING_SECS)
            self.check_refused(done, link, victim, probes, probe_index)
        finally:
            if link.is_symlink():
                link.unlink()

    def check_refused(self, done, link, victim, probes, probe_index):
        self.assertEqual(done.returncode, REFUSE_EXIT_CODE,
                         "dangling link at %s must be refused" % link.name)
        self.assertIn("already exists", done.stderr.decode("utf-8", "replace"))
        self.assertTrue(link.is_symlink(), "link was removed")
        self.assertEqual(os.readlink(str(link)), str(victim), "link was retargeted")
        self.assertFalse(victim.exists(), "write went through the dangling link")
        for index, p in enumerate(probes):
            if index != probe_index:
                self.assertFalse(p.exists() or p.is_symlink(), "probe written: " + str(p))

    def run_race_link(self, gate, probe_index):
        """A link that appears AFTER the guard and BEFORE the write (8243).

        The guard is run for real. The race is simulated in a copy of the
        scripts tree under .local-runs: the copied selftest_probes_arm, which
        the gate calls between the guard and the first write, also plants a
        symlink at the probe path. The link points at a victim file in the
        work dir; a write that follows it changes the victim.
        """
        LOCAL_RUNS.mkdir(exist_ok=True)
        work = Path(tempfile.mkdtemp(prefix="selftest-8243r-", dir=str(LOCAL_RUNS)))
        self.addCleanup(shutil.rmtree, str(work), True)
        tree = work / "tree"
        shutil.copytree(str(ROOT / "scripts"), str(tree / "scripts"),
                        ignore=shutil.ignore_patterns(".local-runs"))
        (tree / "src").mkdir()
        (tree / "tools").mkdir()
        link = tree / GATES[gate][probe_index]
        victim = work / "victim"
        victim.write_text(VICTIM_TEXT)
        lib = tree / "scripts" / "lib" / "selftest-probes.sh"
        text = lib.read_text()
        anchor = '    _selftest_probes+=("$@")\n'
        self.assertIn(anchor, text, "hook anchor missing from selftest-probes.sh")
        lib.write_text(text.replace(
            anchor, anchor + '    ln -s "%s" "%s"\n' % (victim, link), 1))
        env = dict(os.environ, TMPDIR=str(work), LC_ALL="C")
        done = subprocess.run(
            ["bash", str(tree / "scripts" / gate), "--self-test"],
            cwd=str(tree), env=env, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, timeout=REFUSE_CEILING_SECS)
        err = done.stderr.decode("utf-8", "replace")
        self.assertNotEqual(done.returncode, 0, "write through a late link must fail")
        self.assertIn("cannot overwrite existing file", err)
        self.assertEqual(victim.read_text(), VICTIM_TEXT,
                         "write went through a link created after the guard")
        self.assertFalse(link.is_symlink(), "late link left behind")

    def test_late_symlink_not_followed_8243(self):
        for gate in GATES:
            for index in range(len(GATES[gate])):
                self.run_race_link(gate, index)

    def test_dangling_symlink_refused_8243(self):
        for gate in GATES:
            for index in range(len(GATES[gate])):
                with self.subTest(gate=gate, probe=index):
                    self.run_dangling_link(gate, index)

    def test_sigint_kills_self_test_7920(self):
        for gate in GATES:
            with self.subTest(gate=gate):
                self.run_interrupt(gate, signal.SIGINT)

    def test_sigterm_kills_self_test_7920(self):
        for gate in GATES:
            with self.subTest(gate=gate):
                self.run_interrupt(gate, signal.SIGTERM)


if __name__ == "__main__":
    unittest.main()
