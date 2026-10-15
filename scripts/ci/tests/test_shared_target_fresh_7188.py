#!/usr/bin/env python3
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""Cross-checkout artifact reuse in a shared cargo target (#7188, HIGH-1).

cargo decides freshness of workspace (path) crates by source mtime versus the
artifact mtime. With one shared CARGO_TARGET_DIR and a separate checkout per
runner, a checkout whose files are older than the last build's artifacts is
treated as fresh and links ANOTHER checkout's compiled code. The CI step
scripts/ci/touch_workspace_sources.py runs after checkout and bumps every
tracked file's mtime so workspace crates always rebuild.

This test reproduces the reviewers' recipe with a dependency-free toy crate
(two checkouts, one shared target, ``cargo build --lib`` only, through
cargo-slot.py). Everything lives under <repo>/.local-runs/, never a tmp path.
Skipped only when cargo is absent.

Run: python3 -m unittest discover -s scripts/ci/tests
Python 3.9+, standard library only.
"""
import os
import shutil
import subprocess
import sys
import time
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
SCRATCH = REPO / ".local-runs" / "shared-fresh-7188"
TOUCH = REPO / "scripts" / "ci" / "touch_workspace_sources.py"
CARGO_SLOT = Path("/ai-scratch/deputy/cargo-slot.py")
MARK_A = "MARK_A_7188"
MARK_B = "MARK_B_7188"
PAST_A = 200  # seconds before now: checkout A is the OLDER checkout
PAST_B = 100
CARGO_JOBS = "1"


def cargo_cmd(*args):
    base = [sys.executable, str(CARGO_SLOT)] if CARGO_SLOT.exists() else []
    return base + ["cargo"] + list(args) + ["-j", CARGO_JOBS]


def make_checkout(root, mark, age_secs):
    (root / "src").mkdir(parents=True)
    (root / "Cargo.toml").write_text(
        '[package]\nname = "toyshared"\nversion = "0.0.0"\nedition = "2021"\n'
        "[dependencies]\n",
        encoding="utf-8",
    )
    (root / "src" / "lib.rs").write_text(
        'pub static MARK: &str = "%s";\n' % mark, encoding="utf-8"
    )
    subprocess.run(["git", "init", "-q", str(root)], check=True)
    subprocess.run(["git", "-C", str(root), "add", "-A"], check=True)
    stamp = time.time() - age_secs
    for path in root.rglob("*"):
        if ".git" not in path.parts:
            os.utime(path, (stamp, stamp))


@unittest.skipUnless(shutil.which("cargo"), "cargo not installed")
class SharedTargetFreshness(unittest.TestCase):
    def setUp(self):
        shutil.rmtree(SCRATCH, ignore_errors=True)
        self.target = SCRATCH / "shared-target"
        self.a = SCRATCH / "checkout-a"
        self.b = SCRATCH / "checkout-b"
        make_checkout(self.a, MARK_A, PAST_A)
        make_checkout(self.b, MARK_B, PAST_B)
        # The toy target is a few KiB; the slot wrapper's 120 GiB volume floor is
        # meant for the repository workspace, so it is skipped for this crate.
        self.env = dict(
            os.environ, CARGO_TARGET_DIR=str(self.target), CARGO_INCREMENTAL="0",
            CARGO_SLOT_SKIP_DISK_FLOOR="1", CARGO_SLOT_NO_CACHE_ENV="1",
        )

    def tearDown(self):
        shutil.rmtree(SCRATCH, ignore_errors=True)

    def build(self, checkout):
        subprocess.run(
            cargo_cmd("build", "--lib"), cwd=str(checkout), env=self.env, check=True,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )

    def marks_in_target(self):
        found = set()
        for rlib in self.target.rglob("libtoyshared*.rlib"):
            data = rlib.read_bytes()
            for mark in (MARK_A, MARK_B):
                if mark.encode() in data:
                    found.add(mark)
        return found

    def prepare(self, checkout):
        subprocess.run(
            [sys.executable, str(TOUCH), "--root", str(checkout)], check=True,
            stdout=subprocess.DEVNULL,
        )

    def test_both_prepared_before_either_builds_each_runs_its_own_code(self):
        # The lock-wait race: both jobs bump at checkout, then build in turn.
        self.prepare(self.a)
        self.prepare(self.b)
        self.build(self.b)
        self.assertEqual(self.marks_in_target(), {MARK_B})
        self.build(self.a)
        self.assertEqual(self.marks_in_target(), {MARK_A})
        self.build(self.b)
        self.assertEqual(self.marks_in_target(), {MARK_B})

    def test_control_unprepared_checkout_reuses_the_other_checkouts_artifact(self):
        self.build(self.b)
        self.build(self.a)
        self.assertEqual(self.marks_in_target(), {MARK_B})

    def test_prepared_checkout_always_runs_its_own_code(self):
        self.build(self.b)
        self.prepare(self.a)
        self.build(self.a)
        self.assertEqual(self.marks_in_target(), {MARK_A})


if __name__ == "__main__":
    unittest.main()
