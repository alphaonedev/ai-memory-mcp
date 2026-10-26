#!/usr/bin/env python3
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""LOW7733: count content resembling file headers using actual Git patches."""
import subprocess
import sys
import unittest

from test_evidence_generator_5040_5042 import EVIDENCE, ScratchCase, load
from test_evidence_generator_r2_7393 import GIT

FED_PATH = "src/federation/"
DASH_PATH = FED_PATH + "dash.rs"
OTHER_PATH = FED_PATH + "other.rs"
IDENTIFIER_PATH = "src/identifiers.rs"
CONTEXT = "keep_one();\nkeep_two();\nkeep_three();\n"


class DiffHunks7733(ScratchCase):
    def setUp(self):
        super().setUp()
        self.repo = self.dir / "repo"
        self.repo.mkdir()
        self.git("init", "-q")
        self.write(IDENTIFIER_PATH, "AI_MEMORY_FED_HUNK_FIXTURE\n")

    def git(self, *args):
        result = subprocess.run([*GIT, "--literal-pathspecs", "-C", str(self.repo), *args],
                                check=True, capture_output=True, text=True)
        return result.stdout.strip()

    def write(self, path, body):
        destination = self.repo / path
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(body)

    def commit(self, subject, *paths):
        self.git("add", "--", IDENTIFIER_PATH, *paths)
        self.git("commit", "-q", "-m", subject)
        return self.git("rev-parse", "HEAD")

    def test_report_counts_header_like_content_7733(self):
        self.write(DASH_PATH, "--y;\n")
        base = self.commit("base", DASH_PATH)
        self.write(DASH_PATH, "++x;\nz;\n")
        tip = self.commit("change", DASH_PATH)
        result = subprocess.run([sys.executable, "-I", str(EVIDENCE / "prep.py"),
                                 "--repo", str(self.repo), "--base", base, "--tip", tip],
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(f"WATCHED {DASH_PATH} +2/-1 code=3", result.stdout.splitlines())
        self.assertIn("WATCHED_TOTAL files=1 lines=3 code=3", result.stdout.splitlines())

    def test_multiple_hunks_and_files_7733(self):
        self.write(DASH_PATH, "--y;\n" + CONTEXT + "-- a/old.rs\n")
        self.write(OTHER_PATH, "old();\n")
        base = self.commit("base", DASH_PATH, OTHER_PATH)
        self.write(DASH_PATH, "++x;\n" + CONTEXT + "++ b/new.rs\n")
        self.write(OTHER_PATH, "new();\n")
        tip = self.commit("change", DASH_PATH, OTHER_PATH)
        patch = self.git("diff", "-U0", "--no-renames", base, tip, "--", FED_PATH)
        self.assertEqual(sum(line.startswith("@@ ") for line in patch.splitlines()), 3)
        self.assertEqual(sum(line.startswith("diff --git ") for line in patch.splitlines()), 2)
        self.assertEqual(load("prep").code_lines(self.repo, base, tip, FED_PATH), 6)

    def test_file_headers_and_comments_are_excluded_7733(self):
        self.write(DASH_PATH, "// old\n\nold();\n")
        base = self.commit("base", DASH_PATH)
        self.write(DASH_PATH, "// new\n \nnew();\n")
        tip = self.commit("change", DASH_PATH)
        self.assertEqual(load("prep").code_lines(self.repo, base, tip, DASH_PATH), 2)

    def test_created_and_deleted_files_7733(self):
        self.write(DASH_PATH, "-- a/removed.rs")
        base = self.commit("base", DASH_PATH)
        (self.repo / DASH_PATH).unlink()
        self.write(OTHER_PATH, "++ b/created.rs")
        tip = self.commit("change", DASH_PATH, OTHER_PATH)
        self.assertEqual(load("prep").code_lines(self.repo, base, tip, FED_PATH), 2)

    def test_metadata_only_file_after_hunk_7733(self):
        self.write(DASH_PATH, "old();\n")
        self.write(OTHER_PATH, "unchanged();\n")
        base = self.commit("base", DASH_PATH, OTHER_PATH)
        self.write(DASH_PATH, "new();\n")
        self.git("update-index", "--chmod=+x", OTHER_PATH)
        tip = self.commit("change", DASH_PATH)
        self.assertEqual(load("prep").code_lines(self.repo, base, tip, FED_PATH), 2)
        self.assertEqual(load("prep").code_lines(self.repo, base, tip, OTHER_PATH), 0)


if __name__ == "__main__":
    unittest.main()
