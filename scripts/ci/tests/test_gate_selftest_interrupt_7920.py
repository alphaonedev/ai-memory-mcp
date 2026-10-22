#!/usr/bin/env python3
"""Issue 7920: an interrupted gate --self-test must die of the signal.

check-hardcoded-literals.sh installed one handler for EXIT INT TERM that
cleaned up and RETURNED, so an interrupted self-test resumed and could exit 0
(harness check 41 of test-gate-selftest-interrupt-cleanup.sh).

The self-test is held mid-run by an awk wrapper placed first on PATH: the gate
enumerates `command -v awk` and runs a child per awk, so the wrapper blocks the
child (marker file) while the probe files are planted. The signal is sent to
the gate, then the wrapper is released so bash can run its trap.

A bash killed by the re-raised signal reports Popen returncode -signal (what
these gates produce); 128+N is accepted for a wrapped shell.
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

ROOT = Path(__file__).resolve().parents[3]
LOCAL_RUNS = ROOT / ".local-runs"
POLL_CEILING_SECS = 60.0
POLL_STEP_SECS = 0.05
WAIT_CEILING_SECS = 60.0

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
        try:
            deadline = time.monotonic() + POLL_CEILING_SECS
            while time.monotonic() < deadline:
                if blocked.exists() and all(p.exists() for p in probes):
                    break
                self.assertIsNone(proc.poll(), "self-test ended before probes")
                time.sleep(POLL_STEP_SECS)
            else:
                self.fail("probes never planted within %ss" % POLL_CEILING_SECS)
            proc.send_signal(sig)
            release.touch()
            rc = proc.wait(timeout=WAIT_CEILING_SECS)
        finally:
            release.touch()
            if proc.poll() is None:
                proc.kill()
                proc.wait()
        self.assertIn(rc, (-int(sig), 128 + int(sig)),
                      "%s exited %d after %s; must die of the signal" % (gate, rc, sig.name))
        for p in probes:
            self.assertFalse(p.exists(), "probe left behind: " + str(p))

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
