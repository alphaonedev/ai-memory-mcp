#!/usr/bin/env python3
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""LOW7867: only LF ends a Git diff record; other separators inside a source line are content."""
import subprocess
import unittest

from test_evidence_generator_5040_5042 import ScratchCase, load
from test_evidence_generator_r2_7393 import GIT

WATCHED_PATH = "src/federation/separators.rs"
IDENTIFIER_PATH = "src/identifiers.rs"
# Every separator str.splitlines() honours besides LF itself.
EMBEDDED_SEPARATORS = {
    "CR": "\r", "VT": "\x0b", "FF": "\x0c", "FS": "\x1c", "GS": "\x1d", "RS": "\x1e",
    "NEL": "\x85", "LS": " ", "PS": " ",
}


class ContentSeparators7867(ScratchCase):
    def setUp(self):
        super().setUp()
        self.checkout = self.dir / "repo"
        self.checkout.mkdir()
        self.git("init", "-q")
        self.write(IDENTIFIER_PATH, "AI_MEMORY_FED_SEPARATOR_FIXTURE\n")

    def git(self, *args):
        result = subprocess.run([*GIT, "--literal-pathspecs", "-C", str(self.checkout), *args],
                                check=True, capture_output=True)
        return result.stdout.decode("utf-8", "surrogateescape").strip()

    def write(self, path, body):
        destination = self.checkout / path
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(body.encode("utf-8"))

    def commit(self, subject):
        self.git("add", "--", IDENTIFIER_PATH, WATCHED_PATH)
        self.git("commit", "-q", "-m", subject)
        return self.git("rev-parse", "HEAD")

    def changed(self, base_body, tip_body):
        self.write(WATCHED_PATH, base_body)
        base = self.commit("base")
        self.write(WATCHED_PATH, tip_body)
        return base, self.commit("change")

    def test_embedded_separator_is_not_a_record_boundary_7867(self):
        for label, separator in EMBEDDED_SEPARATORS.items():
            with self.subTest(separator=label):
                base, tip = self.changed("old();\n", f"let a = 1;{separator}+let b = 2;\nz();\n")
                self.assertEqual(load("prep").code_lines(self.checkout, base, tip, WATCHED_PATH), 3)

    def test_crlf_line_endings_count_one_row_per_line_7867(self):
        base, tip = self.changed("old();\r\n", "new();\r\nmore();\r\n")
        self.assertEqual(load("prep").code_lines(self.checkout, base, tip, WATCHED_PATH), 3)

    def test_separator_inside_comment_keeps_comment_row_excluded_7867(self):
        for label, separator in EMBEDDED_SEPARATORS.items():
            with self.subTest(separator=label):
                base, tip = self.changed("old();\n", f"// note{separator}+fn added() {{}}\n")
                self.assertEqual(load("prep").code_lines(self.checkout, base, tip, WATCHED_PATH), 1)


if __name__ == "__main__":
    unittest.main()
