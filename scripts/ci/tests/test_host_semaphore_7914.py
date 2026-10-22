"""Pin tests for scripts/ci/host_semaphore.py (#7914).

Real subprocesses against a scratch lock root; nothing here touches the
operator's ~/.cache. Python 3.9+, standard library only.
"""
import os
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / 'host_semaphore.py'
SCRATCH = os.environ.get('TMPDIR') or None
SLEEPER = [sys.executable, '-c', 'import time; time.sleep(60)']


def start(root, args, child, **kw):
    cmd = [sys.executable, '-I', str(SCRIPT), '--root', str(root), '--label', 'T'] + args + ['--'] + child
    return subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, **kw)


def wait_for_line(proc, needle, limit=15.0):
    end = time.time() + limit
    seen = []
    while time.time() < end:
        line = proc.stdout.readline()
        if not line:
            break
        seen.append(line)
        if needle in line:
            return seen
    raise AssertionError('did not see %r in %r' % (needle, seen))


class Semaphore(unittest.TestCase):
    def setUp(self):
        self._td = tempfile.TemporaryDirectory(dir=SCRATCH)
        self.root = Path(self._td.name)

    def tearDown(self):
        self._td.cleanup()

    def test_acquire_notice_and_exit_code_passthrough(self):
        p = start(self.root, ['--name', 'n', '--slots', '2'], [sys.executable, '-c', 'import sys; sys.exit(7)'])
        out, _ = p.communicate(timeout=30)
        self.assertEqual(p.returncode, 7, out)
        self.assertIn("[#7914 semaphore] 'T': slot 0 of 2 acquired after 0s", out)
        self.assertIn('load=', out)
        self.assertIn("[#7914 semaphore] 'T': slot 0 of 2 released", out)

    def test_defaults_are_named_constants(self):
        sys.path.insert(0, str(SCRIPT.parent))
        try:
            import host_semaphore as hs
        finally:
            sys.path.pop(0)
        self.assertEqual(hs.SEMAPHORE_SLOTS_DEFAULT, 2)
        self.assertEqual(hs.SEMAPHORE_MAX_WAIT_SECS_DEFAULT, 3600)
        self.assertEqual(hs.SEMAPHORE_POLL_SECS_DEFAULT, 30)

    def test_extra_waiter_times_out_with_exit_3(self):
        a = start(self.root, ['--name', 'n', '--slots', '1'], SLEEPER)
        b = None
        try:
            wait_for_line(a, 'acquired')
            b = start(self.root, ['--name', 'n', '--slots', '1', '--max-wait-secs', '1', '--poll-secs', '1'],
                      [sys.executable, '-c', 'print("must not run")'])
            out, _ = b.communicate(timeout=30)
            self.assertEqual(b.returncode, 3, out)
            self.assertIn("[#7914 semaphore] 'T': no slot free after 1s", out)
            self.assertNotIn('must not run', out)
        finally:
            a.terminate()
            a.communicate(timeout=30)
            if b is not None and b.poll() is None:
                b.terminate()
                b.communicate(timeout=60)

    def test_two_slots_admit_two_and_a_waiter_gets_the_freed_slot(self):
        a = start(self.root, ['--name', 'n', '--slots', '2'], SLEEPER)
        b = start(self.root, ['--name', 'n', '--slots', '2'], SLEEPER)
        c = None
        try:
            wait_for_line(a, 'acquired')
            wait_for_line(b, 'acquired')
            c = start(self.root, ['--name', 'n', '--slots', '2', '--poll-secs', '1'],
                      [sys.executable, '-c', 'print("ran")'])
            time.sleep(1.5)
            self.assertIsNone(c.poll())
            a.terminate()
            a.communicate(timeout=30)
            out, _ = c.communicate(timeout=30)
            self.assertEqual(c.returncode, 0, out)
            self.assertIn('acquired after', out)
            self.assertIn('ran', out)
        finally:
            for p in (a, b, c):
                if p is not None and p.poll() is None:
                    p.terminate()
                    p.communicate(timeout=60)

    def test_sigterm_kills_child_and_frees_the_slot(self):
        pidfile = self.root / 'child.pid'
        code = 'import os,time; open(%r,"w").write(str(os.getpid())); time.sleep(60)' % str(pidfile)
        a = start(self.root, ['--name', 'n', '--slots', '1'], [sys.executable, '-c', code])
        wait_for_line(a, 'acquired')
        end = time.time() + 10
        while not pidfile.exists() and time.time() < end:
            time.sleep(0.1)
        child = int(pidfile.read_text())
        a.send_signal(signal.SIGTERM)
        a.communicate(timeout=30)
        self.assertNotEqual(a.returncode, 0)
        end = time.time() + 10
        alive = True
        while alive and time.time() < end:
            try:
                os.kill(child, 0)
                time.sleep(0.1)
            except ProcessLookupError:
                alive = False
        self.assertFalse(alive, 'child survived the wrapper SIGTERM')
        b = start(self.root, ['--name', 'n', '--slots', '1', '--max-wait-secs', '1', '--poll-secs', '1'],
                  [sys.executable, '-c', 'pass'])
        out, _ = b.communicate(timeout=30)
        self.assertEqual(b.returncode, 0, out)

    def test_bad_arguments_exit_2(self):
        p = start(self.root, ['--name', 'n', '--slots', '0'], ['true'])
        p.communicate(timeout=30)
        self.assertEqual(p.returncode, 2)
        p = start(self.root, ['--name', '../x', '--slots', '1'], ['true'])
        p.communicate(timeout=30)
        self.assertEqual(p.returncode, 2)


if __name__ == '__main__':
    unittest.main()
