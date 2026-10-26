#!/usr/bin/env python3
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""LOW7732: watched filenames must not expand into Git pathspec matches."""
import subprocess
import sys
import unittest

from test_evidence_generator_5040_5042 import EVIDENCE, ScratchCase, load
from test_evidence_generator_r2_7393 import GIT

FED_PATH = "src/federation/"
IDENTIFIER_PATH = "src/identifiers.rs"
IDENTIFIER = "AI_MEMORY_FED_PATHSPEC_FIXTURE\n"
LITERAL_BODY = "literal();\n"
OTHER_BODY = "one();\ntwo();\nthree();\nfour();\n"
LITERAL_SUBJECT = "literal-change-7732"
OTHER_SUBJECT = "unrelated-change-7732"
RESTORE_SUBJECT = "unrelated-restore-7732"


class LiteralPathspecs7732(ScratchCase):
    def setUp(self):
        super().setUp()
        self.repo = self.dir / "repo"
        self.repo.mkdir()
        self.git("init", "-q")
        self.write(IDENTIFIER_PATH, IDENTIFIER)
        self.base = self.commit("base", IDENTIFIER_PATH)

    def git(self, *args):
        result = subprocess.run([*GIT, "--literal-pathspecs", "-C", str(self.repo), *args],
                                check=True, capture_output=True, text=True)
        return result.stdout.strip()

    def write(self, path, body):
        destination = self.repo / path
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(body)

    def commit(self, subject, *paths):
        self.git("add", "--", *paths)
        self.git("commit", "-q", "-m", subject)
        return self.git("rev-parse", "HEAD")

    def report(self, tip):
        result = subprocess.run([sys.executable, "-I", str(EVIDENCE / "prep.py"),
                                 "--repo", str(self.repo), "--base", self.base, "--tip", tip],
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        return result.stdout.splitlines()

    def counts(self, name, other):
        literal, matching = FED_PATH + name, FED_PATH + other
        self.write(literal, LITERAL_BODY)
        self.write(matching, OTHER_BODY)
        tip = self.commit(LITERAL_SUBJECT, literal, matching)
        prep = load("prep")
        self.assertEqual(prep.code_lines(self.repo, self.base, tip, literal), 1)
        self.assertEqual(prep.code_lines(self.repo, self.base, tip, matching), 4)
        rows = self.report(tip)
        self.assertIn(f"WATCHED {literal} +1/-0 code=1", rows)
        self.assertIn(f"WATCHED {matching} +4/-0 code=4", rows)
        self.assertIn("WATCHED_TOTAL files=2 lines=5 code=5", rows)

    def test_bracket_line_counts_7732(self):
        self.counts("[ab].rs", "a.rs")

    def test_star_line_counts_7732(self):
        self.counts("star*.rs", "star_other.rs")

    def test_question_line_counts_7732(self):
        self.counts("question?.rs", "question1.rs")

    def test_normal_line_counts_7732(self):
        self.counts("ordinary.rs", "other.rs")

    def test_magic_path_is_literal_in_helper_7732(self):
        literal, other = ":(glob)*.rs", "other.rs"
        self.write(literal, LITERAL_BODY)
        self.write(other, OTHER_BODY)
        tip = self.commit(LITERAL_SUBJECT, literal, other)
        self.assertEqual(load("prep").code_lines(self.repo, self.base, tip, literal), 1)

    def test_history_excludes_matching_paths_with_no_net_change_7732(self):
        for name, other in (("[ab].rs", "a.rs"),
                                              ("star*.rs", "star_other.rs"),
                            ("question?.rs", "question1.rs")):
            with self.subTest(name=name):
                literal, matching = FED_PATH + name, FED_PATH + other
                self.base = self.git("rev-parse", "HEAD")
                self.write(matching, OTHER_BODY)
                self.commit(OTHER_SUBJECT, matching)
                (self.repo / matching).unlink()
                self.commit(RESTORE_SUBJECT, matching)
                self.write(literal, LITERAL_BODY)
                tip = self.commit(LITERAL_SUBJECT, literal)
                rows = self.report(tip)
                self.assertIn("WATCHED_TOTAL files=1 lines=1 code=1", rows)
                commits = [row for row in rows if row.startswith("COMMIT ")]
                self.assertEqual(commits, [f"COMMIT {self.git('rev-parse', '--short', tip)} {LITERAL_SUBJECT}"])


if __name__ == "__main__":
    unittest.main()
