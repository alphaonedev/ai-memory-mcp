#!/usr/bin/env python3
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""Issue #9813: the strict standard-library workflow reader of ``workflow_text`` refuses what it cannot read.

Class: a CI guard that reads a workflow file must fail (never skip, never pass, never return a guessed value) on a
file it cannot read or a value it cannot parse, and it must do that with the standard library alone so the guard
loads on a fleet node that has no PyYAML.

Invariant, for every input: ``workflow_text.read_document`` returns exactly what the shared subset parser
(``taint_boundary.parse_yaml``) returns for a readable UTF-8 file, or raises ``WorkflowReadError`` naming the file,
and for a parse refusal the line. ``workflow_text.read_all_steps`` returns the ``(job id, step)`` pairs of a document
whose shape it can read and refuses every other shape with its reason. Each row below asserts the exact value or the
exact refusal.

Run: /opt/homebrew/bin/python3.12 -I scripts/ci/tests/test_workflow_text_yaml_9813.py
"""

from __future__ import annotations

import sys
import tempfile
import time
import unittest
from pathlib import Path

TESTS_DIR = Path(__file__).resolve().parent
REPO = TESTS_DIR.parents[2]
SCRATCH_PARENT = REPO / ".local-runs"
sys.path.insert(0, str(TESTS_DIR))

import workflow_text as wt  # noqa: E402

BIG_FILE_LINES = 100_000
BIG_FILE_CEILING_SECS = 20.0
UTF8 = "utf-8"


class ReaderCase(unittest.TestCase):
    """A scratch directory per test, under the repository's own ``.local-runs``."""

    def setUp(self) -> None:
        SCRATCH_PARENT.mkdir(exist_ok=True)
        holder = tempfile.TemporaryDirectory(dir=SCRATCH_PARENT, prefix="wt9813-")
        self.addCleanup(holder.cleanup)
        self.dir = Path(holder.name)

    def write(self, text: str | bytes, name: str = "w.yml") -> Path:
        path = self.dir / name
        path.write_bytes(text if isinstance(text, bytes) else text.encode(UTF8))
        return path

    def refusal(self, path: Path) -> str:
        with self.assertRaises(wt.WorkflowReadError) as ctx:
            wt.read_document(path)
        return str(ctx.exception)


class ReadDocumentRows(ReaderCase):
    def test_9813_tab_indented_key_is_refused_with_its_line(self) -> None:
        path = self.write("jobs:\n\tbuild:\n    steps: []\n")
        self.assertEqual(self.refusal(path), "%s: line 2: tab in indentation" % path)

    def test_9813_duplicate_key_is_refused_with_its_line(self) -> None:
        path = self.write("jobs:\n  a: 1\n  a: 2\n")
        self.assertEqual(self.refusal(path), "%s: line 3: duplicate key 'a'" % path)

    def test_9813_a_key_inside_a_block_scalar_is_text_not_a_key(self) -> None:
        path = self.write("run: |\n  shell: bash\n  jobs: x\nshell: sh\n")
        self.assertEqual(wt.read_document(path), {"run": "shell: bash\njobs: x\n", "shell": "sh"})

    def test_9813_a_commented_out_key_is_absent(self) -> None:
        path = self.write("# shell: bash\nname: x\n")
        self.assertEqual(wt.read_document(path), {"name": "x"})

    def test_9813_a_trailing_comment_is_not_part_of_the_value(self) -> None:
        path = self.write("shell: bash  # trailing\n")
        self.assertEqual(wt.read_document(path), {"shell": "bash"})

    def test_9813_a_quoted_value_keeps_hash_and_colon(self) -> None:
        path = self.write("run: \"a # b: c\"\nother: 'x: y # z'\n")
        self.assertEqual(wt.read_document(path), {"run": "a # b: c", "other": "x: y # z"})

    def test_9813_crlf_line_ends_read_like_lf(self) -> None:
        path = self.write("a: 1\r\nb: two\r\nrun: |\r\n  x\r\n  y\r\n")
        self.assertEqual(wt.read_document(path), {"a": 1, "b": "two", "run": "x\ny\n"})

    def test_9813_an_empty_file_is_refused(self) -> None:
        path = self.write("")
        self.assertEqual(self.refusal(path), "%s: line 1: empty file" % path)

    def test_9813_a_comment_only_file_is_refused_as_an_empty_document(self) -> None:
        path = self.write("# nothing\n")
        self.assertEqual(self.refusal(path), "%s: line 3: empty document" % path)

    def test_9813_a_missing_file_is_refused_naming_the_path(self) -> None:
        path = self.dir / "absent.yml"
        self.assertEqual(self.refusal(path), "%s: cannot read: No such file or directory" % path)

    def test_9813_a_directory_is_refused_naming_the_path(self) -> None:
        self.assertEqual(self.refusal(self.dir), "%s: cannot read: Is a directory" % self.dir)

    def test_9813_bad_utf8_is_refused_with_its_byte_offset(self) -> None:
        path = self.write(b"a: \xff\n")
        self.assertEqual(self.refusal(path), "%s: not valid UTF-8: invalid start byte at byte 3" % path)

    def test_9813_each_form_the_subset_does_not_parse_is_refused_with_its_line(self) -> None:
        forms = {
            "tag": ("a: !!str x\n", "line 1: scalar form outside the subset: '!!str x'"),
            "anchor": ("a: &x 1\n", "line 1: scalar form outside the subset: '&x 1'"),
            "multi_line_quoted": ('a: "x\n  y"\n', "line 2: unterminated or multi-line quoted scalar"),
        }
        for name, (text, reason) in forms.items():
            with self.subTest(form=name):
                path = self.write(text)
                self.assertEqual(self.refusal(path), "%s: %s" % (path, reason))

    def test_9813_a_100k_line_file_reads_inside_the_ceiling(self) -> None:
        lines = ["key%d: value%d" % (n, n) for n in range(BIG_FILE_LINES)]
        path = self.write("\n".join(lines) + "\n")
        start = time.monotonic()
        document = wt.read_document(path)
        elapsed = time.monotonic() - start
        self.assertEqual(len(document), BIG_FILE_LINES)
        self.assertEqual(document["key0"], "value0")
        self.assertEqual(document["key%d" % (BIG_FILE_LINES - 1)], "value%d" % (BIG_FILE_LINES - 1))
        self.assertLess(elapsed, BIG_FILE_CEILING_SECS)


class ReadAllStepsRows(ReaderCase):
    GOOD = (
        "name: w\n"
        "jobs:\n"
        "  first:\n"
        "    steps:\n"
        "      - name: one\n"
        "        run: echo 1\n"
        "      - uses: actions/checkout@v4\n"
        "  caller:\n"
        "    uses: ./.github/workflows/x.yml\n"
        "  second:\n"
        "    steps:\n"
        "      - name: two\n"
        "        shell: bash\n"
        "        run: |\n"
        "          echo 2\n"
        "          - name: not-a-step\n"
    )

    def refusal(self, path: Path) -> str:  # type: ignore[override]
        with self.assertRaises(wt.WorkflowReadError) as ctx:
            wt.read_all_steps(path)
        return str(ctx.exception)

    def test_9813_steps_come_back_in_file_order_with_their_job(self) -> None:
        path = self.write(self.GOOD)
        self.assertEqual(
            wt.read_all_steps(path),
            [
                ("first", {"name": "one", "run": "echo 1"}),
                ("first", {"uses": "actions/checkout@v4"}),
                ("second", {"name": "two", "shell": "bash", "run": "echo 2\n- name: not-a-step\n"}),
            ],
        )

    def test_9813_each_unreadable_shape_is_refused_with_its_reason(self) -> None:
        shapes = {
            "root_list": ("- a\n- b\n", "top level is not a mapping"),
            "no_jobs": ("name: w\n", "`jobs` is missing or not a mapping"),
            "jobs_text": ("jobs: x\n", "`jobs` is missing or not a mapping"),
            "job_text": ("jobs:\n  a: x\n", "job 'a' is not a mapping"),
            "steps_text": ("jobs:\n  a:\n    steps: x\n", "job 'a': `steps` is not a list"),
            "step_text": ("jobs:\n  a:\n    steps:\n      - x\n", "job 'a': step 0 is not a mapping"),
            "run_number": ("jobs:\n  a:\n    steps:\n      - run: 5\n", "job 'a': step 0: `run` is not text"),
            "run_list": ("jobs:\n  a:\n    steps:\n      - run: [x]\n", "job 'a': step 0: `run` is not text"),
        }
        for name, (text, reason) in shapes.items():
            with self.subTest(shape=name):
                path = self.write(text)
                self.assertEqual(self.refusal(path), "%s: %s" % (path, reason))

    def test_9813_a_parse_refusal_passes_through_with_its_line(self) -> None:
        path = self.write("jobs:\n  a:\n    steps:\n\t- run: x\n")
        self.assertEqual(self.refusal(path), "%s: line 4: tab in indentation" % path)

    def test_9813_a_missing_file_is_refused(self) -> None:
        path = self.dir / "absent.yml"
        self.assertEqual(self.refusal(path), "%s: cannot read: No such file or directory" % path)


if __name__ == "__main__":
    unittest.main()
