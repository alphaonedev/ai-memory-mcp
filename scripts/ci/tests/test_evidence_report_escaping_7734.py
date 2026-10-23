#!/usr/bin/env python3
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""LOW7734: real Git metadata remains one unambiguous report payload."""
import subprocess
import sys
import unittest

from test_evidence_generator_5040_5042 import EVIDENCE, ScratchCase
from test_evidence_generator_r2_7393 import GIT

FED_PATH = "src/federation/"
IDENTIFIER_PATH = "src/identifiers.rs"
PAYLOADS = ("normal", "lf\nWATCHED_TOTAL files=999", "cr\rx", "tab\tx",
            "esc\x1bx", "vt\vx", "ff\fx", "nel\x85x", "ls\u2028x",
            "ps\u2029x", "literal\\nx", "quote'\"x")
SUBJECTS = ("ordinary subject", "control\rWATCHED_TOTAL files=999", "control\x1bx",
            "control\vx", "control\u2028x", "literal\\n'\"x")


class ReportEscaping7734(ScratchCase):
    def setUp(self):
        super().setUp()
        self.repo = self.dir / "repo"
        self.repo.mkdir()
        self.git("init", "-q")
        self.write(IDENTIFIER_PATH, b"AI_MEMORY_FED_REPORT_FIXTURE\n")

    def git(self, *args):
        result = subprocess.run([*GIT, "--literal-pathspecs", "-C", str(self.repo), *args],
                                check=True, capture_output=True)
        return result.stdout.decode("utf-8", "surrogateescape")

    def write(self, path, body):
        destination = self.repo / path
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(body)

    def commit(self, subject, *paths):
        self.git("add", "--", IDENTIFIER_PATH, *paths)
        self.git("commit", "-q", "--cleanup=verbatim", "-m", subject)
        return self.git("rev-parse", "HEAD").strip()

    def report(self, base, tip):
        result = subprocess.run([sys.executable, "-I", str(EVIDENCE / "prep.py"),
                                 "--repo", str(self.repo), "--base", base, "--tip", tip],
                                capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        output = result.stdout.decode("utf-8", "surrogateescape")
        self.assertEqual(output.splitlines(), output.rstrip("\n").split("\n"))
        self.assertFalse(any(character in output for character in "\r\t\x1b\v\f\x85\u2028\u2029"))
        return output.splitlines()

    def assert_rows(self, rows, expected, total):
        self.assertEqual(sorted(row for row in rows if row.startswith("WATCHED ")), sorted(expected))
        self.assertEqual([row for row in rows if row.startswith("WATCHED_TOTAL ")], [total])
        self.assertEqual(len([row for row in rows if row.startswith("COMMIT ")]), 1)
        self.assertEqual(len(rows), len(expected) + 6)

    def test_text_paths_and_literal_controls_7734(self):
        base = self.commit("base")
        paths = [FED_PATH + name + ".rs" for name in PAYLOADS]
        for path in paths:
            self.write(path, b"++x;\n--y;\nz;\n")
        tip = self.commit("text change", *paths)
        rows = self.report(base, tip)
        self.assert_rows(rows, ["WATCHED " + repr(path)[1:-1] + " +3/-0 code=3" for path in paths],
                         f"WATCHED_TOTAL files={len(paths)} lines={3 * len(paths)} code={3 * len(paths)}")
        self.assertNotEqual(repr(paths[1])[1:-1], repr(paths[-2])[1:-1])

    def test_binary_paths_7734(self):
        base = self.commit("base")
        paths = [FED_PATH + name + ".bin" for name in PAYLOADS]
        for path in paths:
            self.write(path, b"\x00binary\n")
        tip = self.commit("binary change", *paths)
        rows = self.report(base, tip)
        self.assert_rows(rows, ["WATCHED " + repr(path)[1:-1] + " binary code=0" for path in paths],
                         f"WATCHED_TOTAL files={len(paths)} lines=0 code=0")

    def test_metadata_paths_7734(self):
        paths = [FED_PATH + name + ".rs" for name in PAYLOADS]
        for path in paths:
            self.write(path, b"unchanged();\n")
        base = self.commit("base", *paths)
        self.git("update-index", "--chmod=+x", "--", *paths)
        tip = self.commit("mode change")
        rows = self.report(base, tip)
        self.assert_rows(rows, ["WATCHED " + repr(path)[1:-1] + " +0/-0 code=0" for path in paths],
                         f"WATCHED_TOTAL files={len(paths)} lines=0 code=0")

    def test_commit_subject_controls_7734(self):
        path = FED_PATH + "normal.rs"
        base = self.commit("base")
        for index, subject in enumerate(SUBJECTS):
            with self.subTest(subject=subject):
                self.write(path, ("line" + str(index) + "();\n").encode())
                tip = self.commit(subject, path)
                actual = self.git("log", "-1", "--format=%s", "-z").removesuffix("\0")
                self.assertEqual(actual, subject)
                short = self.git("rev-parse", "--short", tip).strip()
                rows = self.report(base, tip)
                self.assertEqual([row for row in rows if row.startswith("COMMIT ")],
                                 ["COMMIT " + repr(short + " " + actual)[1:-1]])
                self.assertEqual(len(rows), 7)
                base = tip

    def test_git_normalizes_subject_lf_7734(self):
        path = FED_PATH + "normal.rs"
        base = self.commit("base")
        self.write(path, b"line();\n")
        tip = self.commit("first\nsecond", path)
        actual = self.git("log", "-1", "--format=%s", "-z").removesuffix("\0")
        self.assertEqual(actual, "first second")
        rows = self.report(base, tip)
        short = self.git("rev-parse", "--short", tip).strip()
        self.assertIn("COMMIT " + short + " first second", rows)


if __name__ == "__main__":
    unittest.main()
