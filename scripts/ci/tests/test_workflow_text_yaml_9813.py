#!/usr/bin/env python3
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""Issue #9813, PR 9817 round 1: the strict standard-library reader of ``workflow_text`` refuses what it cannot read.

Class: a CI guard that reads a workflow, action or compose file must see the value the consumer (GitHub Actions,
docker compose) uses, or refuse with one exact reason. A document or a key it cannot classify is a refusal that turns
the guard red, never a pass; a job field can never be present in the text and absent from what the classifier sees.

Invariant, for every input: ``workflow_text.read_document`` / ``parse_text`` return the document only when the file
check, the character scan, the closed-grammar prescan, the subset parser and the independent reader
(``yaml_line_oracle``) all accept it and the two readers agree on every key path and scalar; otherwise they raise
``WorkflowReadError`` whose ``reason`` is one named constant and whose message is ``<file>: line <n>: <reason>`` (or
``<file>: <reason>``), never document text. Each row below asserts the exact reason and line.

Run: /opt/homebrew/bin/python3.12 -I scripts/ci/tests/test_workflow_text_yaml_9813.py
"""

from __future__ import annotations

import os
import stat
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

TESTS_DIR = Path(__file__).resolve().parent
REPO = TESTS_DIR.parents[2]
SCRATCH_PARENT = REPO / ".local-runs"
sys.path.insert(0, str(TESTS_DIR))

import workflow_text as wt  # noqa: E402

UTF8 = "utf-8"
BIG_FILE_LINES = 100_000
BIG_FILE_CEILING_SECS = 20.0
LONG_LINE_BYTES = 1024 * 1024
LONG_LINE_CEILING_SECS = 10.0
FIFO_CEILING_SECS = 5.0
NESTING_PAST_LIMIT = 70
LABEL = "<t>"

# The reason texts, written out by hand (not read from the module): a constant whose text changes, or a branch that
# raises another constant, turns a row red.
REASON_TEXTS = {
    "MISSING": "missing file",
    "SYMLINK": "a symbolic link (not followed)",
    "DIRECTORY": "a directory, not a file",
    "FIFO": "a FIFO, not a regular file",
    "DEVICE": "a device, not a regular file",
    "NOT_REGULAR": "not a regular file",
    "UNREADABLE": "cannot be opened or read",
    "OVER_CAP": "larger than 8388608 bytes",
    "UTF8": "not valid UTF-8",
    "BOM": "byte order mark",
    "EMPTY": "empty file",
    "BLANK_ONLY": "no content (blank or comment lines only)",
    "BARE_CR": "carriage return not followed by a line feed",
    "LINE_BREAK": "line break other than LF or CR LF (NEL, LS or PS)",
    "TAB": "tab character",
    "CONTROL": "control or format character",
    "NONASCII_SPACE": "non-ASCII space character",
    "DOCUMENT_MARKER": "document marker (`---` or `...`)",
    "DIRECTIVE": "YAML directive",
    "QUOTED_KEY": "quoted key",
    "TRAILING_SPACE_KEY": "blank before the `:` of a key",
    "NONASCII_KEY": "non-ASCII key",
    "MERGE_KEY": "merge key `<<`",
    "ANCHOR": "anchor",
    "ALIAS": "alias",
    "TAG": "tag",
    "COMPLEX_KEY": "complex key `?`",
    "FLOW_BLOCK": "flow collection where a block is read (`jobs`, a job, or `steps`), or as a block item",
    "BLOCK_SCALAR": "block scalar header outside the subset",
    "DUPLICATE_KEY": "duplicate key",
    "INDENT": "indentation outside the subset (a multi-line plain scalar or a second document)",
    "KEY_FORM": "key form outside the subset",
    "QUOTED_SCALAR": "quoted scalar outside the subset",
    "FLOW": "flow collection outside the subset",
    "PLAIN": "plain scalar outside the subset",
    "OUTSIDE_SUBSET": "form outside the subset",
    "AMBIGUOUS_SCALAR": "plain scalar whose type differs between YAML 1.1 and 1.2",
    "KEY_NOT_TEXT": "key that does not read as text",
    "ORACLE_REFUSED": "form the independent reader does not read",
    "ORACLE_DIFFERS": "the subset parser and the independent reader disagree",
    "TOP_NOT_MAPPING": "top level is not a mapping",
    "JOBS_MISSING": "`jobs` is missing",
    "JOBS_NOT_MAPPING": "`jobs` is not a mapping",
}
NESTING_TEXT = "nesting deeper than 64 levels"


def reason(name: str) -> str:
    """The module's constant `name`; a marker when it is absent, so a missing constant is a red row, not an error."""
    return getattr(wt, name, "<absent constant %s>" % name)


# A privileged workflow (pull_request_target, write token) whose checkout step hides `with: ref:` behind a line
# break that the subset parser does not split on: GitHub Actions reads the key, a reader that misses it does not.
H1_VISIBLE = (
    "on: pull_request_target\n"
    "permissions:\n"
    "  contents: write\n"
    "jobs:\n"
    "  build:\n"
    "    runs-on: ubuntu-latest\n"
    "    steps:\n"
    "      - uses: actions/checkout@v4{BREAK}"
    "        with:{BREAK}"
    "          ref: ${{{{ github.event.pull_request.head.sha }}}}\n"
    "      - run: make\n"
)
H1_BREAKS = {"bare_cr": ("\r", "BARE_CR"), "nel": ("\x85", "LINE_BREAK"), "ls": ("\u2028", "LINE_BREAK"),
             "ps": ("\u2029", "LINE_BREAK")}
H1_LINE = 8

# (text, reason constant name, line) for every form the closed grammar refuses.
HOSTILE_FORMS = {
    "duplicate_key": ("a: 1\na: 2\n", "DUPLICATE_KEY", 2),
    "duplicate_job_field": ("jobs:\n  b:\n    runs-on: x\n    runs-on: y\n    steps:\n      - run: z\n",
                            "DUPLICATE_KEY", 4),
    "anchor_value": ("a: &x 1\n", "ANCHOR", 1),
    "anchor_block": ("a: &x\n  b: 1\n", "ANCHOR", 1),
    "anchor_item": ("a:\n  - &x 1\n", "ANCHOR", 2),
    "anchor_in_flow": ("a: [&x 1]\n", "ANCHOR", 1),
    "alias_value": ("a: 1\nb: *x\n", "ALIAS", 2),
    "alias_item": ("a:\n  - *x\n", "ALIAS", 2),
    "alias_in_flow": ("a: [1, *x]\n", "ALIAS", 1),
    "merge_key": ("a:\n  <<: {b: 1}\n", "MERGE_KEY", 2),
    "merge_key_in_flow": ("a: {<<: b}\n", "MERGE_KEY", 1),
    "tag_value": ("a: !!str x\n", "TAG", 1),
    "tag_key": ("!!str a: 1\n", "TAG", 1),
    "tag_in_flow": ("a: [!!str x]\n", "TAG", 1),
    "flow_jobs": ("jobs: {build: {steps: [{run: x}]}}\n", "FLOW_BLOCK", 1),
    "flow_job": ("jobs:\n  b: {steps: [{run: x}]}\n", "FLOW_BLOCK", 2),
    "flow_steps": ("jobs:\n  b:\n    steps: [{run: x}]\n", "FLOW_BLOCK", 3),
    "zero_jobs": ("jobs: {}\n", "FLOW_BLOCK", 1),
    "zero_steps": ("jobs:\n  b:\n    steps: []\n", "FLOW_BLOCK", 3),
    "flow_mapping_item": ("a:\n  - {run: x}\n", "FLOW_BLOCK", 2),
    "flow_sequence_item": ("a:\n  - [x]\n", "FLOW_BLOCK", 2),
    "double_quoted_key": ('"a": 1\n', "QUOTED_KEY", 1),
    "single_quoted_key": ("'a': 1\n", "QUOTED_KEY", 1),
    "quoted_key_in_item": ("a:\n  - 'b': 1\n", "QUOTED_KEY", 2),
    "tab_indented_key": ("a:\n\tb: 1\n", "TAB", 2),
    "tab_in_value": ("a: b\tc\n", "TAB", 1),
    "blank_before_colon": ("a : 1\n", "TRAILING_SPACE_KEY", 1),
    "complex_key": ("? a\n: 1\n", "COMPLEX_KEY", 1),
    "second_document": ("a: 1\n---\nb: 2\n", "DOCUMENT_MARKER", 2),
    "document_start": ("---\na: 1\n", "DOCUMENT_MARKER", 1),
    "document_end": ("a: 1\n...\n", "DOCUMENT_MARKER", 2),
    "directive": ("%YAML 1.2\na: 1\n", "DIRECTIVE", 1),
    "bare_cr": ("a: 1\rb: 2\n", "BARE_CR", 1),
    "nel": ("a: 1\x85b: 2\n", "LINE_BREAK", 1),
    "line_separator": ("a: 1\u2028b: 2\n", "LINE_BREAK", 1),
    "paragraph_separator": ("a: 1\u2029b: 2\n", "LINE_BREAK", 1),
    "nul": ("a: 1\x00\n", "CONTROL", 1),
    "escape": ("a: \x1b[31m\n", "CONTROL", 1),
    "delete": ("a: 1\x7f\n", "CONTROL", 1),
    "zero_width_space": ("a\u200b: 1\n", "CONTROL", 1),
    "bom_inside_text": ("a: 1\n\ufeffb: 2\n", "CONTROL", 2),
    "nbsp_indentation": ("a:\n\u00a0 b: 1\n", "NONASCII_SPACE", 2),
    "nbsp_in_key": ("a\u00a0b: 1\n", "NONASCII_SPACE", 1),
    "ideographic_space": ("a:\u3000b\n", "NONASCII_SPACE", 1),
    "nonascii_key": ("\u00e9: 1\n", "NONASCII_KEY", 1),
    "block_header_indent_digit": ("a: |2\n  x\n", "BLOCK_SCALAR", 1),
    "block_header_text": ("a: |x\n  y\n", "BLOCK_SCALAR", 1),
    "multi_line_plain": ("a: b\n  c\n", "INDENT", 2),
    "multi_line_quoted": ('a: "x\n  y"\n', "QUOTED_SCALAR", 1),
    "unterminated_quote_second_line": ("a: 1\nb: 'x\n\n\nc: 2\n", "QUOTED_SCALAR", 2),
    "bad_escape_second_line": ('a: 1\nb: "x\\q"\nc: 2\n', "QUOTED_SCALAR", 2),
    "unterminated_quote_in_item_mapping": ("a:\n  - b: 'x\n", "QUOTED_SCALAR", 2),
    "text_after_quote": ("a: 'x' y\n", "QUOTED_SCALAR", 1),
    "yaml11_bool_value": ("a: yes\n", "AMBIGUOUS_SCALAR", 1),
    "yaml11_off_value": ("a: Off\n", "AMBIGUOUS_SCALAR", 1),
    "leading_zero": ("a: 010\n", "AMBIGUOUS_SCALAR", 1),
    "hex": ("a: 0x1f\n", "AMBIGUOUS_SCALAR", 1),
    "exponent": ("a: 1e3\n", "AMBIGUOUS_SCALAR", 1),
    "underscore": ("a: 1_000\n", "AMBIGUOUS_SCALAR", 1),
    "sexagesimal": ("a: 1:30\n", "AMBIGUOUS_SCALAR", 1),
    "infinity": ("a: .inf\n", "AMBIGUOUS_SCALAR", 1),
    "date": ("a: 2026-11-21\n", "AMBIGUOUS_SCALAR", 1),
    "yaml11_key": ("yes: 1\n", "KEY_NOT_TEXT", 1),
    "null_key": ("null: 1\n", "KEY_NOT_TEXT", 1),
    "int_key": ("1: a\n", "KEY_NOT_TEXT", 1),
    "keep_chomp_trailing_blank": ("a: x\nb: |+\n  y\n\n", "ORACLE_DIFFERS", 2),
    "folded_leading_blank": ("a: >\n\n  x\n", "ORACLE_REFUSED", 2),
    "comment_only": ("# x\n\n", "BLANK_ONLY", 1),
}

# Texts both readers accept: the value the consumer reads.
VALUE_ROWS = {
    "block_scalar_hides_keys": ("run: |\n  shell: bash\n  jobs: x\nshell: sh\n",
                                {"run": "shell: bash\njobs: x\n", "shell": "sh"}),
    "commented_key_is_absent": ("# shell: bash\nname: x\n", {"name": "x"}),
    "trailing_comment": ("shell: bash  # trailing\n", {"shell": "bash"}),
    "quoted_hash_and_colon": ("run: \"a # b: c\"\nother: 'x: y # z'\n", {"run": "a # b: c", "other": "x: y # z"}),
    "crlf": ("a: 1\r\nb: two\r\nrun: |\r\n  x\r\n  y\r\n", {"a": 1, "b": "two", "run": "x\ny\n"}),
    "on_key_is_text": ("on: push\n", {"on": "push"}),
    "needs_flow_list": ("jobs:\n  b:\n    needs: [a, c]\n    steps:\n      - run: x\n",
                        {"jobs": {"b": {"needs": ["a", "c"], "steps": [{"run": "x"}]}}}),
    "nonascii_value": ("name: caf\u00e9 \u2014 ok\n", {"name": "caf\u00e9 \u2014 ok"}),
    "typed_scalars": ("a: 1\nb: 1.5\nc: true\nd: null\ne: ~\nf: '010'\n",
                      {"a": 1, "b": 1.5, "c": True, "d": None, "e": None, "f": "010"}),
}

# Ten secrets-looking canaries, built at run time so no scanner matches this file.
CANARIES = (
    "gh" + "p_" + "Q" * 36,
    "AK" + "IA" + "Q" * 16,
    "xo" + "xb-" + "1" * 10 + "-" + "Q" * 24,
    "-----BEGIN " + "PRIVATE KEY-----",
    "pass" + "word=hunter2canary",
    "postgres://u:" + "s3cretcanary" + "@db.invalid/x",
    "s" + "k-" + "Q" * 40,
    "gl" + "pat-" + "Q" * 20,
    "ey" + "J" + "hbGciOiJIUzI1NiJ9.canary.sig",
    "AI" + "za" + "Q" * 35,
)
# (template with {S} for the canary, reason constant name, line) for every text-level refusal branch.
CANARY_TEMPLATES = {
    "duplicate_key": ("k: '{S}'\nk: '{S}'\n", "DUPLICATE_KEY", 2),
    "anchor": ("a: &x '{S}'\n", "ANCHOR", 1),
    "alias": ("a: '{S}'\nb: *x\n", "ALIAS", 2),
    "tag": ("a: !t '{S}'\n", "TAG", 1),
    "tab_value": ("a: '{S}'\tb\n", "TAB", 1),
    "merge_key": ("a:\n  b: '{S}'\n  <<: x\n", "MERGE_KEY", 3),
    "quoted_key": ("'{S}': 1\n", "QUOTED_KEY", 1),
    "blank_before_colon": ("a : '{S}'\n", "TRAILING_SPACE_KEY", 1),
    "nonascii_key": ("\u00e9: '{S}'\n", "NONASCII_KEY", 1),
    "complex_key": ("? '{S}'\n", "COMPLEX_KEY", 1),
    "flow_block": ("jobs: ['{S}']\n", "FLOW_BLOCK", 1),
    "document_marker": ("a: '{S}'\n---\n", "DOCUMENT_MARKER", 2),
    "directive": ("%TAG '{S}'\na: 1\n", "DIRECTIVE", 1),
    "bare_cr": ("a: '{S}'\rb: 1\n", "BARE_CR", 1),
    "line_break": ("a: '{S}'\x85b: 1\n", "LINE_BREAK", 1),
    "control": ("a: '{S}'\x00\n", "CONTROL", 1),
    "nonascii_space": ("a: '{S}'\u3000\n", "NONASCII_SPACE", 1),
    "block_header": ("a: |9x\n  '{S}'\n", "BLOCK_SCALAR", 1),
    "indent": ("a: x{S}\n  y{S}\n", "INDENT", 2),
    "key_form": ("a: 1\nx{S}\n", "KEY_FORM", 2),
    "quoted_scalar": ("a: \"{S}\\q\"\n", "QUOTED_SCALAR", 1),
    "multi_line_quoted": ("a: \"{S}\n  y\"\n", "QUOTED_SCALAR", 1),
    "flow": ("a: [b, '{S}'\n", "FLOW", 1),
    "ambiguous": ("a: '{S}'\nb: yes\n", "AMBIGUOUS_SCALAR", 2),
    "key_not_text": ("a: '{S}'\nnull: 1\n", "KEY_NOT_TEXT", 2),
    "oracle_differs": ("a: '{S}'\nb: |+\n  x\n\n", "ORACLE_DIFFERS", 2),
    "oracle_refused": ("a: '{S}'\nb: >\n\n  x\n", "ORACLE_REFUSED", 3),
}
# (template, exact refusal text after the label) for every read_all_steps shape branch.
SHAPE_ROWS = {
    "top_not_mapping": ("- '{S}'\n- b\n", "top level is not a mapping"),
    "jobs_missing": ("name: '{S}'\n", "`jobs` is missing"),
    "jobs_not_mapping": ("jobs: '{S}'\n", "`jobs` is not a mapping"),
    "job_not_mapping": ("jobs:\n  a: '{S}'\n", "job 1 is not a mapping"),
    "job_no_steps": ("jobs:\n  a:\n    runs-on: '{S}'\n", "job 1 has neither `steps` nor `uses`"),
    "steps_null": ("jobs:\n  a:\n    name: '{S}'\n    steps:\n", "job 1: `steps` is null"),
    "steps_not_list": ("jobs:\n  a:\n    steps: '{S}'\n", "job 1: `steps` is not a list"),
    "step_not_mapping": ("jobs:\n  a:\n    steps:\n      - '{S}'\n", "job 1: step 1 is not a mapping"),
    "run_null": ("jobs:\n  a:\n    steps:\n      - name: '{S}'\n        run:\n", "job 1: step 1: `run` is null"),
    "run_number": ("jobs:\n  a:\n    steps:\n      - name: '{S}'\n        run: 5\n", "job 1: step 1: `run` is not text"),
    "run_list": ("jobs:\n  a:\n    steps:\n      - run: ['{S}']\n", "job 1: step 1: `run` is not text"),
    "second_job_second_step": ("jobs:\n  a:\n    uses: ./x.yml\n  b:\n    steps:\n      - run: x\n      - '{S}'\n",
                               "job 2: step 2 is not a mapping"),
}


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

    def refused(self, call, *args) -> Exception:
        with self.assertRaises(wt.WorkflowReadError) as ctx:
            call(*args)
        return ctx.exception

    def assert_refusal(self, exc: Exception, label: str, line: int | None, reason_text: str) -> None:
        self.assertEqual((exc.label, exc.line, exc.reason), (label, line, reason_text))
        where = "%s: line %d" % (label, line) if line is not None else label
        self.assertEqual(str(exc), "%s: %s" % (where, reason_text))


class ReasonConstants(unittest.TestCase):
    def test_9817_every_reason_constant_has_its_written_text(self) -> None:
        for name, text in REASON_TEXTS.items():
            with self.subTest(constant=name):
                self.assertEqual(reason(name), text)
        self.assertEqual(getattr(wt, "NESTING", None), "nesting deeper than %d levels")

    def test_9817_the_read_cap_equals_the_classifier_cap(self) -> None:
        self.assertEqual(getattr(wt, "MAX_DOCUMENT_BYTES", None), wt.load_taint_boundary().MAX_YAML_BYTES)

    def test_9817_every_parser_refusal_maps_to_a_reason_constant(self) -> None:
        boundary = wt.load_taint_boundary()
        rows = {
            "a:\n\tb: 1\n": "TAB",
            "a: 1\n  b: 2\n": "INDENT",
            "a: 'x\n": "QUOTED_SCALAR",
            "a: [b\n": "FLOW",
        }
        for text, name in rows.items():
            with self.subTest(text=text):
                with self.assertRaises(boundary.YamlError) as ctx:
                    boundary.parse_yaml(text, "<document>")
                _, mapped = wt._parser_reason(str(ctx.exception))
                self.assertEqual(mapped, reason(name))
        self.assertEqual(wt._parser_reason("<document>: line 3: nesting deeper than 64")[1], NESTING_TEXT)
        self.assertEqual(wt._parser_reason("<document>: line 2: an unknown refusal"), (2, reason("OUTSIDE_SUBSET")))


class HostileForms(ReaderCase):
    def test_9817_every_form_outside_the_grammar_is_refused_with_its_reason_and_line(self) -> None:
        for name, (text, constant, line) in HOSTILE_FORMS.items():
            with self.subTest(form=name):
                exc = self.refused(wt.parse_text, text, LABEL)
                self.assert_refusal(exc, LABEL, line, REASON_TEXTS[constant])

    def test_9817_nesting_past_the_limit_is_refused(self) -> None:
        text = "".join("%sk%d:\n" % ("  " * depth, depth) for depth in range(NESTING_PAST_LIMIT)) + \
            "%sv: 1\n" % ("  " * NESTING_PAST_LIMIT)
        exc = self.refused(wt.parse_text, text, LABEL)
        self.assertEqual(exc.reason, NESTING_TEXT)

    def test_9817_h1_hidden_key_not_seen_is_a_refusal(self) -> None:
        """The reviewer's probe: `with: ref:` behind a line break the subset parser keeps inside one line."""
        for name, (brk, constant) in H1_BREAKS.items():
            with self.subTest(line_break=name):
                path = self.write(H1_VISIBLE.format(BREAK=brk))
                exc = self.refused(wt.read_document, path)
                self.assert_refusal(exc, str(path), H1_LINE, REASON_TEXTS[constant])

    def test_9817_h1_visible_key_is_seen(self) -> None:
        document = wt.parse_text(H1_VISIBLE.format(BREAK="\n"), LABEL)
        step = document["jobs"]["build"]["steps"][0]
        self.assertEqual(step["with"], {"ref": "${{ github.event.pull_request.head.sha }}"})

    def test_9817_each_value_row_reads_the_consumer_value(self) -> None:
        for name, (text, expected) in VALUE_ROWS.items():
            with self.subTest(row=name):
                self.assertEqual(wt.parse_text(text, LABEL), expected)


class FileChecks(ReaderCase):
    def test_9817_a_missing_file_is_refused(self) -> None:
        path = self.dir / "absent.yml"
        self.assert_refusal(self.refused(wt.read_document, path), str(path), None, REASON_TEXTS["MISSING"])

    def test_9817_a_directory_is_refused(self) -> None:
        self.assert_refusal(self.refused(wt.read_document, self.dir), str(self.dir), None, REASON_TEXTS["DIRECTORY"])

    def test_9817_a_symlink_to_a_good_file_is_refused(self) -> None:
        target = self.write("a: 1\n", "target.yml")
        link = self.dir / "link.yml"
        os.symlink(target, link)
        self.assert_refusal(self.refused(wt.read_document, link), str(link), None, REASON_TEXTS["SYMLINK"])

    def test_9817_a_fifo_is_refused_inside_its_time_limit(self) -> None:
        fifo = self.dir / "pipe.yml"
        os.mkfifo(fifo)
        outcome: list = []

        def read() -> None:
            try:
                wt.read_document(fifo)
                outcome.append("returned")
            except wt.WorkflowReadError as exc:
                outcome.append(exc)
            except BaseException as exc:  # noqa: BLE001 - the row reports any other outcome
                outcome.append(repr(exc))

        worker = threading.Thread(target=read, daemon=True)
        worker.start()
        worker.join(FIFO_CEILING_SECS)
        if worker.is_alive():
            with open(fifo, "wb"):  # release the blocked open so the daemon thread can end
                pass
            self.fail("reading a FIFO did not return within %.0f s" % FIFO_CEILING_SECS)
        self.assertEqual(len(outcome), 1)
        self.assertIsInstance(outcome[0], wt.WorkflowReadError)
        self.assert_refusal(outcome[0], str(fifo), None, REASON_TEXTS["FIFO"])

    def test_9817_a_character_device_is_refused(self) -> None:
        for device in ("/dev/null", "/dev/zero"):
            with self.subTest(device=device):
                self.assertTrue(stat.S_ISCHR(os.stat(device).st_mode))
                exc = self.refused(wt.read_document, Path(device))
                self.assert_refusal(exc, device, None, REASON_TEXTS["DEVICE"])

    def test_9817_each_other_file_type_seen_by_fstat_is_refused(self) -> None:
        """A socket or a block device cannot be opened here as a file to read, so fstat is given its mode."""
        path = self.write("a: 1\n")
        real_fstat = os.fstat
        for kind, (mode, constant) in {"socket": (stat.S_IFSOCK, "NOT_REGULAR"),
                                       "block_device": (stat.S_IFBLK, "DEVICE")}.items():
            with self.subTest(kind=kind):
                def fake_fstat(fd, mode=mode):
                    real = real_fstat(fd)
                    return os.stat_result((mode | 0o600,) + tuple(real)[1:])

                with unittest.mock.patch.object(wt.os, "fstat", fake_fstat):
                    exc = self.refused(wt.read_document, path)
                self.assert_refusal(exc, str(path), None, REASON_TEXTS[constant])

    def test_9817_an_unreadable_file_is_refused(self) -> None:
        if os.geteuid() == 0:
            self.skipTest("root reads a mode-000 file; the row needs an unprivileged user")
        path = self.write("a: 1\n")
        path.chmod(0)
        self.addCleanup(path.chmod, 0o600)
        self.assert_refusal(self.refused(wt.read_document, path), str(path), None, REASON_TEXTS["UNREADABLE"])

    def test_9817_a_file_over_the_cap_is_refused_and_one_at_the_cap_reads(self) -> None:
        cap = wt.MAX_DOCUMENT_BYTES
        head = "a: 1\n#"
        at_cap = self.write(head + "x" * (cap - len(head) - 1) + "\n", "at.yml")
        self.assertEqual(at_cap.stat().st_size, cap)
        self.assertEqual(wt.read_document(at_cap), {"a": 1})
        over = self.write(head + "x" * (cap - len(head)) + "\n", "over.yml")
        self.assertEqual(over.stat().st_size, cap + 1)
        self.assert_refusal(self.refused(wt.read_document, over), str(over), None, REASON_TEXTS["OVER_CAP"])

    def test_9817_the_read_cap_is_checked_before_the_bytes_are_decoded(self) -> None:
        over = self.write(b"\xff" * (wt.MAX_DOCUMENT_BYTES + 1), "over-binary.yml")
        self.assert_refusal(self.refused(wt.read_document, over), str(over), None, REASON_TEXTS["OVER_CAP"])

    def test_9817_parse_text_caps_the_text_in_utf8_bytes_before_any_other_check(self) -> None:
        """The cap counts UTF-8 bytes, not characters, and comes first: the over-cap text also holds a tab."""
        cap = wt.MAX_DOCUMENT_BYTES
        head = "a: 1\n#"
        at_cap = head + "x" * (cap - len(head) - 1) + "\n"
        self.assertEqual(wt.parse_text(at_cap, LABEL), {"a": 1})
        prefix = "\ta: 1\n#"
        body_bytes = cap + 1 - len(prefix) - 1
        wide = prefix + "é" * (body_bytes // 2) + "x" * (body_bytes % 2) + "\n"
        self.assertEqual(len(wide.encode("utf-8")), cap + 1)
        self.assertLess(len(wide), cap)
        self.assert_refusal(self.refused(wt.parse_text, wide, LABEL), LABEL, None, REASON_TEXTS["OVER_CAP"])

    def test_9817_invalid_utf8_is_refused_with_its_line(self) -> None:
        path = self.write(b"a: 1\nb: \xff\n")
        self.assert_refusal(self.refused(wt.read_document, path), str(path), 2, REASON_TEXTS["UTF8"])

    def test_9817_a_byte_order_mark_is_refused(self) -> None:
        path = self.write(b"\xef\xbb\xbfa: 1\n")
        self.assert_refusal(self.refused(wt.read_document, path), str(path), 1, REASON_TEXTS["BOM"])

    def test_9817_an_empty_file_is_refused(self) -> None:
        path = self.write("")
        self.assert_refusal(self.refused(wt.read_document, path), str(path), 1, REASON_TEXTS["EMPTY"])

    def test_9817_a_blank_only_file_is_refused(self) -> None:
        for name, text in {"blank": "\n  \n", "comment": "# x\n", "crlf_blank": "\r\n\r\n"}.items():
            with self.subTest(file=name):
                path = self.write(text)
                exc = self.refused(wt.read_document, path)
                self.assert_refusal(exc, str(path), 1, REASON_TEXTS["BLANK_ONLY"])

    def test_9817_the_check_and_the_read_use_one_descriptor(self) -> None:
        path = self.write("a: 1\n")
        calls: list = []
        real_open, real_fstat, real_read = os.open, os.fstat, os.read

        def spy_open(*args, **kwargs):
            fd = real_open(*args, **kwargs)
            calls.append(("open", fd, args[1] if len(args) > 1 else kwargs.get("flags")))
            return fd

        def spy_fstat(fd):
            calls.append(("fstat", fd))
            return real_fstat(fd)

        def spy_read(fd, n):
            calls.append(("read", fd))
            return real_read(fd, n)

        with unittest.mock.patch.object(wt.os, "open", spy_open), \
                unittest.mock.patch.object(wt.os, "fstat", spy_fstat), \
                unittest.mock.patch.object(wt.os, "read", spy_read):
            self.assertEqual(wt.read_document(path), {"a": 1})
        opens = [c for c in calls if c[0] == "open"]
        self.assertEqual(len(opens), 1)
        fd, flags = opens[0][1], opens[0][2]
        self.assertEqual(flags & (os.O_NOFOLLOW | os.O_NONBLOCK), os.O_NOFOLLOW | os.O_NONBLOCK)
        self.assertEqual({c[1] for c in calls}, {fd})
        self.assertEqual([c[0] for c in calls][:2], ["open", "fstat"])


class Canaries(ReaderCase):
    def test_9817_no_text_refusal_quotes_the_document(self) -> None:
        for name, (template, constant, line) in CANARY_TEMPLATES.items():
            for secret in CANARIES:
                with self.subTest(branch=name, canary=secret[:4]):
                    exc = self.refused(wt.parse_text, template.replace("{S}", secret), LABEL)
                    self.assertNotIn(secret, str(exc))
                    self.assert_refusal(exc, LABEL, line, REASON_TEXTS[constant])

    def test_9817_no_shape_refusal_quotes_the_document(self) -> None:
        for name, (template, text) in SHAPE_ROWS.items():
            for secret in CANARIES:
                with self.subTest(shape=name, canary=secret[:4]):
                    path = self.write(template.replace("{S}", secret))
                    exc = self.refused(wt.read_all_steps, path)
                    self.assertNotIn(secret, str(exc))
                    self.assert_refusal(exc, str(path), None, text)

    def test_9817_no_file_refusal_quotes_the_document(self) -> None:
        joined = "\n".join("k%d: '%s'" % (n, s) for n, s in enumerate(CANARIES))
        rows = {
            "utf8": (joined.encode(UTF8) + b"\n\xff\n", 11, "UTF8"),
            "bom": (b"\xef\xbb\xbf" + joined.encode(UTF8), 1, "BOM"),
            "over_cap": ((joined + "\n#" + "x" * wt.MAX_DOCUMENT_BYTES + "\n").encode(UTF8), None, "OVER_CAP"),
            "nesting": (("".join("%sk%d:\n" % ("  " * d, d) for d in range(NESTING_PAST_LIMIT)) +
                         "%sv: '%s'\n" % ("  " * NESTING_PAST_LIMIT, CANARIES[0])).encode(UTF8), "any", None),
        }
        for name, (data, line, constant) in rows.items():
            with self.subTest(file=name):
                path = self.write(data)
                exc = self.refused(wt.read_document, path)
                for secret in CANARIES:
                    self.assertNotIn(secret, str(exc))
                if constant is not None:
                    self.assert_refusal(exc, str(path), line, REASON_TEXTS[constant])
                else:
                    self.assertEqual(exc.reason, NESTING_TEXT)


class ReadAllSteps(ReaderCase):
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

    def test_9817_each_unreadable_shape_is_refused_with_its_ordinal_reason(self) -> None:
        for name, (template, text) in SHAPE_ROWS.items():
            with self.subTest(shape=name):
                path = self.write(template.replace("{S}", "v"))
                self.assert_refusal(self.refused(wt.read_all_steps, path), str(path), None, text)

    def test_9817_a_grammar_refusal_passes_through_read_all_steps(self) -> None:
        path = self.write("jobs:\n  a:\n    steps:\n\t- run: x\n")
        self.assert_refusal(self.refused(wt.read_all_steps, path), str(path), 4, REASON_TEXTS["TAB"])


class Cost(ReaderCase):
    def test_9817_a_100k_line_document_reads_inside_its_ceiling(self) -> None:
        lines = ["key%d: value%d" % (n, n) for n in range(BIG_FILE_LINES)]
        path = self.write("\n".join(lines) + "\n")
        start = time.monotonic()
        document = wt.read_document(path)
        elapsed = time.monotonic() - start
        self.assertEqual(len(document), BIG_FILE_LINES)
        self.assertEqual(document["key%d" % (BIG_FILE_LINES - 1)], "value%d" % (BIG_FILE_LINES - 1))
        self.assertLess(elapsed, BIG_FILE_CEILING_SECS)

    def test_9817_a_1mb_line_reads_inside_its_ceiling(self) -> None:
        for name, value in {"plain": "x" * LONG_LINE_BYTES, "quoted": "'%s'" % ("x" * LONG_LINE_BYTES),
                            "flow": "[%s]" % ", ".join(["x"] * (LONG_LINE_BYTES // 3))}.items():
            with self.subTest(form=name):
                path = self.write("a: %s\n" % value)
                start = time.monotonic()
                document = wt.read_document(path)
                elapsed = time.monotonic() - start
                self.assertIn("a", document)
                self.assertLess(elapsed, LONG_LINE_CEILING_SECS)


# PR 9817 L1: the character sweep. YAML 1.2 (section 5.1) defines c-printable as exactly these ranges; the set the
# reader must never read is their complement over every code point, generated here from the definition, not listed.
CODE_POINT_END = 0x110000
C_PRINTABLE_RANGES = ((0x09, 0x09), (0x0A, 0x0A), (0x0D, 0x0D), (0x20, 0x7E), (0x85, 0x85), (0xA0, 0xD7FF),
                      (0xE000, 0xFFFD), (0x10000, 0x10FFFF))
# Printable code points the reader still refuses before any grammar, each with its reason constant.
PRINTABLE_REFUSED = {"\t": "TAB", "\r": "BARE_CR", "\x85": "LINE_BREAK", "\u2028": "LINE_BREAK",
                     "\u2029": "LINE_BREAK"}
# Every non-c-printable code point is a C0 or C1 control (Cc), a surrogate (Cs) or a noncharacter (Cn): CONTROL.
NON_PRINTABLE_REASON = "CONTROL"
# The character reasons a value-position sweep may raise; the only grammar reason is the line feed's KEY_FORM
# ("a: x\ny" leaves "y" as a line with no key).
SWEEP_REASONS = frozenset({"CONTROL", "NONASCII_SPACE", "LINE_BREAK", "TAB", "BARE_CR", "KEY_FORM"})
# Every modelled position: (template with {c}, line of the character, document read when the character is "z").
SWEEP_POSITIONS = {
    "key": ("a{c}b: 1\n", 1, {"azb": 1}),
    "plain_value": ("a: x{c}y\n", 1, {"a": "xzy"}),
    "single_quoted_value": ("a: 'x{c}y'\n", 1, {"a": "xzy"}),
    "double_quoted_value": ('a: "x{c}y"\n', 1, {"a": "xzy"}),
    "comment": ("a: 1  # x{c}y\n", 1, {"a": 1}),
    "indentation": ("a:\n{c}  b: 1\n", 2, None),
    "block_scalar_body": ("a: |\n  x{c}y\n", 2, {"a": "xzy\n"}),
    "sequence_item": ("a:\n  - x{c}y\n", 2, {"a": ["xzy"]}),
    "flow_item": ("a: [x{c}y]\n", 1, {"a": ["xzy"]}),
}
SWEEP_VALUE_TEMPLATE = "a: x%sy\n"
CHARACTER_SWEEP_CEILING_SECS = 60.0


def non_printable_code_points() -> list[str]:
    """Every code point outside the YAML 1.2 c-printable ranges, in order."""
    printable = [False] * CODE_POINT_END
    for low, high in C_PRINTABLE_RANGES:
        printable[low:high + 1] = [True] * (high + 1 - low)
    return [chr(cp) for cp in range(CODE_POINT_END) if not printable[cp]]


class CharacterSweep(ReaderCase):
    """PR 9817 L1. Dimensions: (1) every code point outside YAML 1.2 c-printable (2,111 of them: C0 except TAB, LF
    and CR; DEL and C1 except NEL; the 2,048 surrogates; U+FFFE and U+FFFF) plus the five printable code points the
    reader refuses (TAB, bare CR, NEL, LS, PS), each at every position of SWEEP_POSITIONS (key, plain, single- and
    double-quoted value, comment, indentation, block scalar body, sequence item, flow item): each is refused with
    its exact reason and line; (2) every code point U+0000 to U+10FFFF at the plain value position: each is refused
    with one named reason or read exactly as written, and no code point outside c-printable is ever read. Zero
    crashes in both; the whole sweep inside CHARACTER_SWEEP_CEILING_SECS."""

    def test_9817_l1_the_generated_set_matches_the_yaml_definition(self) -> None:
        refused = non_printable_code_points()
        self.assertEqual(len(refused), 29 + 32 + 2048 + 2)  # C0, DEL and C1, surrogates, U+FFFE and U+FFFF
        self.assertEqual([c for c in refused if c < "\x80"], [chr(c) for c in (*range(0x09), 0x0B, 0x0C,
                                                                              *range(0x0E, 0x20), 0x7F)])
        self.assertEqual(refused[-2:], ["\ufffe", "\uffff"])
        self.assertNotIn("\x85", refused)
        self.assertNotIn("\xa0", refused)

    def test_9817_l1_each_refused_code_point_at_each_position_has_its_reason_and_line(self) -> None:
        cases = [(c, NON_PRINTABLE_REASON) for c in non_printable_code_points()] + list(PRINTABLE_REFUSED.items())
        start = time.monotonic()
        for position, (template, line, readable) in SWEEP_POSITIONS.items():
            if readable is not None:  # the position reads with a plain letter, so a refusal is the character's
                with self.subTest(position=position, control="z"):
                    self.assertEqual(wt.parse_text(template.format(c="z"), LABEL), readable)
            wrong = []
            for ch, name in cases:
                try:
                    got = wt.parse_text(template.format(c=ch), LABEL)
                    wrong.append((hex(ord(ch)), "read", repr(got)[:40]))
                except wt.WorkflowReadError as exc:
                    if (exc.line, exc.reason) != (line, reason(name)):
                        wrong.append((hex(ord(ch)), exc.line, exc.reason))
                except Exception as exc:  # noqa: BLE001 - a crash is the finding this row exists for
                    wrong.append((hex(ord(ch)), "crash", type(exc).__name__))
            with self.subTest(position=position):
                self.assertEqual((len(wrong), wrong[:10]), (0, []))
        self.assertLess(time.monotonic() - start, CHARACTER_SWEEP_CEILING_SECS)

    def test_9817_l1_every_code_point_at_the_value_is_refused_by_name_or_read_as_written(self) -> None:
        named = {reason(name) for name in SWEEP_REASONS}
        non_printable = set(non_printable_code_points())
        wrong = []
        start = time.monotonic()
        for cp in range(CODE_POINT_END):
            ch = chr(cp)
            try:
                got = wt.parse_text(SWEEP_VALUE_TEMPLATE % ch, LABEL)
            except wt.WorkflowReadError as exc:
                if exc.reason not in named or (ch in non_printable and exc.reason != reason(NON_PRINTABLE_REASON)):
                    wrong.append((hex(cp), exc.reason))
                continue
            except Exception as exc:  # noqa: BLE001 - a crash is the finding this row exists for
                wrong.append((hex(cp), "crash", type(exc).__name__))
                continue
            if ch in non_printable or ch in PRINTABLE_REFUSED or got != {"a": "x%sy" % ch}:
                wrong.append((hex(cp), "read", repr(got)[:40]))
        elapsed = time.monotonic() - start
        self.assertEqual((len(wrong), wrong[:10]), (0, []))
        self.assertLess(elapsed, CHARACTER_SWEEP_CEILING_SECS)


import unittest.mock  # noqa: E402  (used by the one-descriptor row)

if __name__ == "__main__":
    unittest.main()
