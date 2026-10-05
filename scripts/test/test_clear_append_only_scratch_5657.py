#!/usr/bin/env python3
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""#5657 — a leftover append-only audit.log must not poison the next CI job.

Run: python3 scripts/test/test_clear_append_only_scratch_5657.py

Flag mechanisms: `chflags uappnd` (macOS/BSD, owner may set and clear) and
`chattr +a` (Linux, needs CAP_LINUX_IMMUTABLE, so `sudo -n` when not root). When
the mechanism is unavailable on the host the flag-dependent tests are SKIPPED
with a message; the workflow pin tests always run.
"""
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "clear-append-only-scratch.py"
WORKFLOWS = [
    ROOT / ".github" / "workflows" / "ci.yml",
    ROOT / ".github" / "workflows" / "session-boot-lifetime.yml",
]
STEP_NAME = "- name: Clear stale append-only scratch (#5657)"
CHECKOUT = "uses: actions/checkout@"
IS_BSD = hasattr(os, "lchflags")


def _priv():
    return [] if os.geteuid() == 0 else ["sudo", "-n"]


def set_flag(path):
    """Set the append-only flag on path; raise unittest.SkipTest if impossible."""
    if IS_BSD:
        os.lchflags(path, os.lstat(path).st_flags | stat.UF_APPEND)
        return
    r = subprocess.run(_priv() + ["chattr", "+a", str(path)], capture_output=True, text=True)
    if r.returncode != 0:
        raise unittest.SkipTest("cannot set append-only on this host: %s" % r.stderr.strip())


def drop_flag(path):
    """Test-teardown only: always clear the flag so the scratch dir can go."""
    if IS_BSD:
        os.lchflags(path, os.lstat(path).st_flags & ~stat.UF_APPEND)
    else:
        subprocess.run(_priv() + ["chattr", "-a", str(path)], capture_output=True)


def run_clear(root):
    """Run the script; on Linux it needs the same privilege that set the flag."""
    cmd = ([] if IS_BSD else _priv()) + [sys.executable, str(SCRIPT), "--root", str(root)]
    return subprocess.run(cmd, capture_output=True, text=True)


class ScratchTreeCase(unittest.TestCase):
    def setUp(self):
        base = ROOT / ".local-runs"
        base.mkdir(exist_ok=True)
        self.ws = Path(tempfile.mkdtemp(prefix=".ws5657-", dir=base))
        self.log = self.ws / ".local-runs" / ".tmpAbC123" / "audit" / "audit.log"
        self.log.parent.mkdir(parents=True)
        self.log.write_text("{}\n")
        self.addCleanup(self._teardown)

    def _teardown(self):
        for p in self.ws.rglob("*"):
            if not p.is_symlink():
                try:
                    drop_flag(p)
                except OSError:
                    pass
        shutil.rmtree(self.ws, ignore_errors=True)

    def test_flagged_leftover_blocks_removal_then_clear_makes_it_removable_5657(self):
        set_flag(self.log)
        with self.assertRaises(PermissionError):  # the macOS leg's EPERM on unlink
            shutil.rmtree(self.ws / ".local-runs")
        self.assertTrue(self.log.exists(), "flagged file must survive a failed clean")
        r = run_clear(self.ws)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("cleared append-only", r.stdout)
        shutil.rmtree(self.ws / ".local-runs")
        self.assertFalse((self.ws / ".local-runs").exists())

    def test_clear_is_idempotent_5657(self):
        set_flag(self.log)
        for _ in range(2):
            r = run_clear(self.ws)
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        r = run_clear(self.ws)
        self.assertIn("0 cleared, 0 failed", r.stdout)

    def test_unflagged_and_missing_tree_are_noops_5657(self):
        self.assertEqual(run_clear(self.ws).returncode, 0)
        shutil.rmtree(self.ws / ".local-runs")
        r = run_clear(self.ws)
        self.assertEqual(r.returncode, 0)
        self.assertIn("nothing to do", r.stdout)

    def test_flag_outside_scratch_tree_is_never_touched_5657(self):
        live = self.ws / "audit.log"  # a LIVE log: not under .local-runs
        live.write_text("{}\n")
        set_flag(live)
        r = run_clear(self.ws)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        with self.assertRaises(PermissionError):
            live.unlink()  # still append-only: the forensic control is intact

    def test_symlink_is_not_followed_5657(self):
        target = self.ws / "outside.log"
        target.write_text("{}\n")
        set_flag(target)
        link = self.ws / ".local-runs" / "link.log"
        link.symlink_to(target)
        r = run_clear(self.ws)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        with self.assertRaises(PermissionError):
            target.unlink()


def _steps_before_checkout(text):
    """Return (clear_step_index, checkout_index) in the workflow text, by line."""
    lines = text.splitlines()
    clear_idx = [i for i, l in enumerate(lines) if l.strip() == STEP_NAME]
    return lines, clear_idx


class WorkflowPinCase(unittest.TestCase):
    def test_every_self_hosted_macos_job_clears_before_checkout_5657(self):
        for wf in WORKFLOWS:
            text = wf.read_text()
            lines, clear_idx = _steps_before_checkout(text)
            self.assertEqual(len(clear_idx), 1, "%s needs exactly one clear step" % wf.name)
            i = clear_idx[0]
            first_checkout_after_job_start = None
            for j in range(i, len(lines)):
                if CHECKOUT in lines[j]:
                    first_checkout_after_job_start = j
                    break
            self.assertIsNotNone(first_checkout_after_job_start)
            # The step must precede the checkout of ITS job: no other `- uses:`
            # checkout between the step and the next checkout, and every earlier
            # checkout in the file belongs to a different job (a `jobs` key).
            prior = [k for k in range(i) if CHECKOUT in lines[k]]
            for k in prior:
                between = "\n".join(lines[k:i])
                self.assertRegex(between, r"(?m)^  [A-Za-z0-9_-]+:\s*$",
                                 "%s: a checkout at line %d precedes the clear step in the same job" % (wf.name, k + 1))
            self.assertIn("contains(matrix.runner, 'self-hosted')", "\n".join(lines[i:i + 3]))
            self.assertIn("shell: python3 {0}", "\n".join(lines[i:i + 5]))

    def test_inline_copy_is_byte_identical_to_the_script_5657(self):
        want = SCRIPT.read_text().rstrip("\n")
        for wf in WORKFLOWS:
            lines = wf.read_text().splitlines()
            i = next(k for k, l in enumerate(lines) if l.strip() == STEP_NAME)
            r = next(k for k in range(i, len(lines)) if lines[k].strip() == "run: |")
            body = []
            for l in lines[r + 1:]:
                if l.strip() and not l.startswith(" " * 10):
                    break
                body.append(l[10:] if l.strip() else "")
            while body and not body[-1]:
                body.pop()
            self.assertEqual("\n".join(body), want, "%s inline copy drifted from the script" % wf.name)

    def test_live_audit_flag_is_still_set_5657(self):
        src = (ROOT / "src" / "audit.rs").read_text()
        self.assertIn("libc::UF_APPEND", src)
        self.assertIn("FS_APPEND_FL", src)

    def test_every_self_hosted_macos_workflow_is_covered_5657(self):
        covered = {w.name for w in WORKFLOWS}
        for wf in (ROOT / ".github" / "workflows").glob("*.yml"):
            if re.search(r'"self-hosted"\s*,\s*"macos', wf.read_text()):
                self.assertIn(wf.name, covered, "%s runs on self-hosted macOS without the #5657 clear step" % wf.name)


if __name__ == "__main__":
    unittest.main(verbosity=2)
