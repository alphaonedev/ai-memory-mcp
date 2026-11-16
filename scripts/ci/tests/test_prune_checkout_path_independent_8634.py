#!/usr/bin/env python3
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""#8634 class B: the #7188 prune cell must not depend on the checkout path.

A test whose verdict depends on the absolute path of the checkout fails on
every self-hosted runner whose checkout directory is named `runner-<n>`.
This cell copies exactly the files the #7188 cell needs into a directory
named `runner-x` inside its own temporary directory, runs the #7188 cell
there as a child process, and requires it to pass.

Run: python3 -m unittest scripts/ci/tests/test_prune_checkout_path_independent_8634.py
Python 3.12+, standard library only.
"""
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
# The sibling-runner marker the #7188 cell must tolerate in its own path.
RUNNER_DIR_NAME = "runner-x"
CELL_7188 = "test_prune_runner_artifacts_7188"
# Repo-relative files the #7188 cell imports or reads.
NEEDED_FILES = (
    "scripts/ci/prune_runner_artifacts.py",
    "scripts/ci/shared_cargo_target.py",
    "scripts/ci/tests/test_prune_runner_artifacts_7188.py",
    ".github/workflows/ci.yml",
)
CHILD_TIMEOUT_SECS = 300


def scratch_base() -> Path:
    """TMPDIR when set (the lane scratch), else a gitignored in-repo directory."""
    env_tmp = os.environ.get("TMPDIR")
    base = Path(env_tmp) if env_tmp else REPO / ".local-runs"
    base.mkdir(parents=True, exist_ok=True)
    return base


class CheckoutPathIndependence(unittest.TestCase):
    def test_7188_cell_passes_from_a_checkout_named_runner(self):
        with tempfile.TemporaryDirectory(prefix="prune-8634-", dir=scratch_base()) as tmp:
            checkout = Path(tmp) / RUNNER_DIR_NAME
            for rel in NEEDED_FILES:
                dest = checkout / rel
                dest.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(REPO / rel, dest)
            self.assertIn("runner-", str(checkout))
            proc = subprocess.run(
                [sys.executable, "-m", "unittest", CELL_7188],
                cwd=checkout / "scripts" / "ci" / "tests",
                capture_output=True,
                text=True,
                timeout=CHILD_TIMEOUT_SECS,
                check=False,
                env={**os.environ, "PYTHONPATH": str(checkout / "scripts" / "ci" / "tests")},
            )
            tail = "\n".join(proc.stderr.splitlines()[-40:])
            self.assertEqual(
                proc.returncode,
                0,
                "the #7188 cell failed from %s:\n%s" % (checkout, tail),
            )
            self.assertIn("OK", proc.stderr)


if __name__ == "__main__":
    unittest.main()
