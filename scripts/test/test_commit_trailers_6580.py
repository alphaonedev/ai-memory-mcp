#!/usr/bin/env python3
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""#6580: commits in a checked range must not carry a `Claude-Session:` trailer.

The check is scripts/check_commit_trailers.py. These tests build a throwaway
repository and pin that the check fails on a range holding such a trailer (any
case of the key), names each offending commit, passes on a clean range, and
fails closed on a range git cannot resolve. A further test pins that the commit
rules in docs/AI_DEVELOPER_WORKFLOW.md §5.2 name the check.
"""

import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
CHECK = ROOT / "scripts/check_commit_trailers.py"
WORKFLOW_DOC = ROOT / "docs/AI_DEVELOPER_WORKFLOW.md"


class CommitTrailerCheck6580(unittest.TestCase):
    def setUp(self):
        self.scratch = tempfile.TemporaryDirectory(prefix="trailers-6580-")
        self.addCleanup(self.scratch.cleanup)
        self.repo = Path(self.scratch.name)
        self.env = {
            **os.environ,
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_AUTHOR_NAME": "Trailer fixture",
            "GIT_AUTHOR_EMAIL": "fixture@example.invalid",
            "GIT_COMMITTER_NAME": "Trailer fixture",
            "GIT_COMMITTER_EMAIL": "fixture@example.invalid",
        }
        self.git("init", "-q")
        self.base = self.commit("base\n\nCo-Authored-By: Fixture <fixture@example.invalid>\n")

    def git(self, *args):
        done = subprocess.run(["git", *args], cwd=self.repo, env=self.env,
                              capture_output=True, text=True, check=True)
        return done.stdout.strip()

    def commit(self, message):
        self.git("commit", "-q", "--allow-empty", "--no-gpg-sign", "-m", message)
        return self.git("rev-parse", "HEAD")

    def check(self, rng):
        return subprocess.run([sys.executable, "-I", str(CHECK), "--repo", str(self.repo),
                               "--range", rng], capture_output=True, text=True)

    def test_clean_range_passes(self):
        self.commit("fix: one\n\nRefs: #1\nCo-Authored-By: Fixture <fixture@example.invalid>\n")
        self.commit("fix: two\n\nBase: abc\n")
        done = self.check(f"{self.base}..HEAD")
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        self.assertIn("2 commits checked, 0 carry a Claude-Session trailer", done.stdout)

    def test_session_trailer_fails_and_is_named(self):
        for key in ("Claude-Session", "claude-session", "CLAUDE-SESSION"):
            with self.subTest(key=key):
                clean = self.commit("fix: clean\n\nRefs: #1\n")
                bad = self.commit(f"fix: bad\n\nRefs: #1\n{key}: https://example.invalid/s\n")
                done = self.check(f"{clean}^..HEAD")
                self.assertEqual(done.returncode, 1, done.stdout + done.stderr)
                self.assertIn(bad, done.stdout)
                self.assertNotIn(clean, done.stdout)
                self.assertIn("2 commits checked, 1 carry a Claude-Session trailer", done.stdout)

    def test_body_mention_is_not_a_trailer(self):
        # Only the trailer block counts; prose that names the key passes.
        self.commit("docs: explain\n\nA Claude-Session: line is refused by the check.\n\n"
                    "Refs: #6580\n")
        done = self.check(f"{self.base}..HEAD")
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)

    def test_unresolvable_range_fails_closed(self):
        done = self.check("no-such-ref..HEAD")
        self.assertEqual(done.returncode, 2, done.stdout + done.stderr)
        self.assertIn("cannot list", done.stderr)

    def test_empty_range_fails_closed(self):
        done = self.check("HEAD..HEAD")
        self.assertEqual(done.returncode, 2, done.stdout + done.stderr)
        self.assertIn("no commits", done.stderr)

    def test_self_test(self):
        done = subprocess.run([sys.executable, "-I", str(CHECK), "--self-test"],
                              capture_output=True, text=True)
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        self.assertIn("commit-trailers self-test: 0 failed", done.stdout)


class WorkflowDocNamesCheck6580(unittest.TestCase):
    def test_section_5_2_names_the_check(self):
        text = WORKFLOW_DOC.read_text()
        start = text.index("### 5.2 Co-authorship trailer")
        section = text[start:text.index("### 5.3", start)]
        self.assertIn("Claude-Session:", section)
        self.assertIn("scripts/check_commit_trailers.py --range", section)


if __name__ == "__main__":
    unittest.main()
