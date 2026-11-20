#!/usr/bin/env python3
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""Name the failing tests of a red CI test job in its step summary and as annotations (#9709).

A red test job used to leave its cause in a log nobody opens first.  This step runs after the test step of every
test job (``if: failure()``, ``continue-on-error: true``), reads the cargo test output the job already wrote and
prints what a reader needs: the failing test binaries, the failing test names and the ``test result: FAILED`` lines.
It is deterministic: no secret, no network, no LLM.  It never changes the job result.

Input: files, or directories (every ``*.log`` below them, sorted), given as arguments.  The parser reads libtest output:

* ``Running ... (target/debug/deps/<binary>-<hash>)`` and ``Doc-tests <crate>`` open a binary section;
* ``test <name> ... FAILED`` and the indented names under ``failures:`` are failing tests;
* ``test result: FAILED. ...`` is the result line of a failing binary;
* a binary section that ends (next binary or end of input) without any ``test result:`` line is reported as its own
  row with the reason ``ended without a test result line (crash, timeout or signal)``.

Output: ``GITHUB_STEP_SUMMARY`` (appended) and ``::error`` annotations on stdout.  Every value is cut to a byte
bound, passed through the redaction of ``scripts/cert_gate_evidence.py`` and then through the shared escape of
``workflow_annotation.py``; Markdown cells also escape ``&``, ``<``, ``|``, a backtick and ``[``.  Each bound is a
named constant; over a bound the output carries an exact count line, never a silent cut.

Exit code: 0 on every internal error (missing or unreadable input, missing or unwritable summary file, a bad
argument, any exception) after printing one ``::notice`` line with the exact reason.  The one exception is the
shared-module load refusal of the repository-wide loader shape (exit 4, one fixed ``::error`` line); the step's
``continue-on-error`` keeps even that from changing the job result.  Python 3.12, standard library only.
"""

import argparse
import hashlib
import importlib.util
import os
import re
import stat
import sys
from pathlib import Path


def _load_workflow_annotation():
    """The shared module at WA_RELATIVE_PATH from this file's real directory, by path only, never through
    sys.path; every name in WA_REQUIRED must be a callable of it (#9365, one shape in every script)."""
    import importlib.util
    import os
    path = os.path.normpath(os.path.join(os.path.dirname(os.path.realpath(__file__)), WA_RELATIVE_PATH))
    loaded = sys.modules.get("workflow_annotation")
    if loaded is not None and os.path.realpath(getattr(loaded, "__file__", None) or "") == path:
        module = loaded
    else:
        spec = importlib.util.spec_from_file_location("workflow_annotation", path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)  # absent, unreadable or broken: it raises here, the try below catches it
    missing = [name for name in WA_REQUIRED if not callable(getattr(module, name, None))]
    if missing:
        raise AttributeError("workflow_annotation.py lacks " + ", ".join(missing))
    if loaded is None:
        sys.modules["workflow_annotation"] = module
    return module


EXIT_OK = 0
EXIT_LOAD_REFUSED = 4

# The one shared-module load shape of scripts/ (#9365, ruling bcd0a15c; LoaderShape pins it).
WA_PROG = "red_cause_summary"
WA_RELATIVE_PATH = "workflow_annotation.py"
WA_REQUIRED = ("annotation", "safe_text")
WA_EXIT_LOAD_REFUSED = EXIT_LOAD_REFUSED
WA_ERROR_TO_STDERR = False

try:
    wa = _load_workflow_annotation()
except (Exception, SystemExit) as exc:  # any failed load: one fixed line built without the module, then exit
    wa_cause = type(exc).__name__
    print("%s: refused: shared module workflow_annotation.py next to the script cannot be loaded (%s)"
          % (WA_PROG, wa_cause if wa_cause.isidentifier() else "BaseException"), file=sys.stderr, flush=True)
    print("::error title=red_cause_summary refused::red_cause_summary: refused: shared module workflow_annotation.py"
          " next to the script cannot be loaded",
          file=sys.stderr if WA_ERROR_TO_STDERR else sys.stdout, flush=True)
    sys.exit(WA_EXIT_LOAD_REFUSED)


ISSUE = "#9709"

# The bounds, each held from both sides by a test (at the bound, one above).
MAX_FAILING_TESTS = 50  # failing tests listed in the summary
MAX_LINE_BYTES = 300  # bytes of one input line that are read; the rest is cut and counted
MAX_SUMMARY_BYTES = 32768  # bytes of the summary this step appends, escapes included
MAX_ANNOTATIONS = 10  # ::error lines (GitHub shows 10 per step)
MAX_FILE_BYTES = 16 * 1024 * 1024  # bytes read per input file
MAX_INPUT_FILES = 64  # input files read
SUMMARY_OMIT_RESERVE = 160  # bytes kept free for the omission line of a summary over its bound
ANNOTATION_MAX_CHARS = 4000  # an annotation line is never cut by the shared module: 2 x MAX_LINE_BYTES x 4 fits
DETAIL_MAX_CHARS = 200

UNKNOWN_BINARY = "(unknown binary)"
NO_RESULT_REASON = "ended without a test result line (crash, timeout or signal)"
NO_PATHS_REASON = "no input paths given"
EMPTY_PATH_REASON = "input path is empty"
NO_SUMMARY_FILE_REASON = "GITHUB_STEP_SUMMARY is not set, summary not written"
NO_FINDINGS_NOTICE = "no failing test or test binary found in %d input file(s)"
REDACTION_FILE = "cert_gate_evidence.py"
REDACTION_FAILED = "<redaction failed>"
SUMMARY_ENV = "GITHUB_STEP_SUMMARY"

NOTICE_TITLE = "red cause summary"
TITLE_BINARY = "failing test binary"
TITLE_TEST = "failing test"

TEST_PREFIX = "test "
FAILED_SUFFIX = " ... FAILED"
FAILED_SUFFIX_BYTES = FAILED_SUFFIX.encode("ascii")
RESULT_PREFIX = "test result:"
RESULT_FAILED_PREFIX = "test result: FAILED"
FAILURES_HEADER = "failures:"
LIST_INDENT = "    "
RUNNING_PREFIX = "Running "
DOC_TESTS_PREFIX = "Doc-tests "
DOC_TESTS_LABEL = "doc-tests "
CRASH_MARKER = "process didn't exit successfully"
HASH_SUFFIX = re.compile(r"-[0-9a-f]{8,}$")
ANSI = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]")
INPUT_SUFFIX = ".log"
MD_ESCAPES = (("&", "&amp;"), ("<", "&lt;"), ("|", "&#124;"), ("`", "&#96;"), ("[", "&#91;"))


class UsageProblem(Exception):
    """A bad command line; reported as one notice, exit 0."""


class NotRegular(Exception):
    """An input that is not a regular file (a FIFO, a device, a directory reached through a race)."""


class Parser(argparse.ArgumentParser):
    def error(self, message):  # argparse would exit 2; this step never fails the job
        raise UsageProblem(message)


def build_parser():
    parser = Parser(
        prog=WA_PROG,
        description="Write the failing tests of a red CI test job to GITHUB_STEP_SUMMARY and as ::error annotations "
                    "(%s). Exit 0 on every internal error." % ISSUE)
    parser.add_argument("paths", nargs="*", help="cargo test output files, or directories holding *.log files")
    return parser


_redact_line = None


def load_redaction():
    """The redaction of scripts/cert_gate_evidence.py, loaded by path (never through sys.path)."""
    global _redact_line
    path = Path(__file__).resolve().parent.parent / REDACTION_FILE
    spec = importlib.util.spec_from_file_location("cert_gate_evidence", str(path))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    _redact_line = module.redact_line


def clean(text):
    """``text`` cut to the line bound and redacted; a redaction that fails yields a fixed marker, never the raw text."""
    if _redact_line is None:
        return REDACTION_FAILED
    shown = text if len(text) <= MAX_LINE_BYTES else text[:MAX_LINE_BYTES]
    try:
        return _redact_line(shown)
    except Exception:
        return REDACTION_FAILED


def md_cell(text):
    """``text`` for a Markdown table cell: no HTML, no pipe, no backtick, no link bracket."""
    for raw, replacement in MD_ESCAPES:
        text = text.replace(raw, replacement)
    return text


def binary_label(text):
    """The binary of a ``Running`` line: the file name in its trailing parentheses without the hash, else the text."""
    text = text.strip()
    if text.endswith(")") and " (" in text:
        inner = text[text.rindex(" (") + 2:-1]
        name = inner.rsplit("/", 1)[-1]
        return HASH_SUFFIX.sub("", name) or text
    return text


class Findings:
    """What the parse found: failing binaries, failing tests, and the exact counts of every cut."""

    def __init__(self):
        self.binaries = []  # (binary, reason) in encounter order, unique
        self.binary_keys = set()
        self.tests = []  # (binary, name): the first MAX_FAILING_TESTS only
        self.test_count = 0  # every distinct failing test
        self.test_keys = set()
        self.files_read = 0
        self.cut_lines = 0
        self.truncated_files = []  # (name, size)
        self.files_found = 0

    def add_binary(self, binary, reason):
        key = (binary, reason)
        if key not in self.binary_keys:
            self.binary_keys.add(key)
            self.binaries.append(key)

    def add_test(self, binary, name):
        digest = hashlib.blake2b((binary + "\x00" + name).encode("utf-8", "replace"), digest_size=16).digest()
        if digest in self.test_keys:
            return
        self.test_keys.add(digest)
        self.test_count += 1
        if len(self.tests) < MAX_FAILING_TESTS:
            self.tests.append((binary, name))


class Section:
    """One binary section of one file while it is parsed."""

    def __init__(self, binary):
        self.binary = binary
        self.has_result = False
        self.detail = ""


def parse_data(data, findings):
    """Parse the bytes of one input file into ``findings``: one pass, linear in the input size."""
    section = Section(UNKNOWN_BINARY)
    opened = False
    in_list = False
    list_names = 0

    def close_section():
        if opened and not section.has_result:
            reason = NO_RESULT_REASON
            if section.detail:
                reason = reason + "; " + section.detail
            findings.add_binary(section.binary, clean(reason))

    for raw in data.split(b"\n"):
        if raw.endswith(b"\r"):
            raw = raw[:-1]
        if len(raw) > MAX_LINE_BYTES:
            findings.cut_lines += 1
            if raw.endswith(FAILED_SUFFIX_BYTES):  # a long failing test name is cut, never its FAILED verdict
                raw = raw[:MAX_LINE_BYTES - len(FAILED_SUFFIX_BYTES)] + FAILED_SUFFIX_BYTES
            else:
                raw = raw[:MAX_LINE_BYTES]
        line = ANSI.sub("", raw.decode("utf-8", "replace"))
        stripped = line.strip()
        if in_list:
            if line.startswith(LIST_INDENT) and stripped:
                findings.add_test(clean(section.binary), clean(stripped))
                list_names += 1
                continue
            if not stripped and list_names == 0:
                continue
            in_list = False
        if stripped == FAILURES_HEADER:
            in_list = True
            list_names = 0
            continue
        if stripped.startswith(RUNNING_PREFIX) or stripped.startswith(DOC_TESTS_PREFIX):
            close_section()
            if stripped.startswith(RUNNING_PREFIX):
                label = binary_label(stripped[len(RUNNING_PREFIX):])
            else:
                label = DOC_TESTS_LABEL + stripped[len(DOC_TESTS_PREFIX):].strip()
            section = Section(label)
            opened = True
            continue
        if stripped.startswith(RESULT_PREFIX):
            section.has_result = True
            if stripped.startswith(RESULT_FAILED_PREFIX):
                findings.add_binary(clean(section.binary), clean(stripped))
            continue
        if stripped.startswith(TEST_PREFIX) and stripped.endswith(FAILED_SUFFIX):
            findings.add_test(clean(section.binary), clean(stripped[len(TEST_PREFIX):-len(FAILED_SUFFIX)]))
            continue
        if opened and CRASH_MARKER in stripped and not section.detail:
            section.detail = clean(stripped)
    close_section()


def read_input(path):
    """(bytes, size, truncated) of one regular file, read through one descriptor: no symlink is followed, a FIFO is
    refused after fstat, at most MAX_FILE_BYTES + 1 bytes are read."""
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    fd = os.open(path, flags)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise NotRegular(path)
        with os.fdopen(fd, "rb", closefd=False) as handle:
            data = handle.read(MAX_FILE_BYTES + 1)
    finally:
        os.close(fd)
    truncated = len(data) > MAX_FILE_BYTES
    return (data[:MAX_FILE_BYTES] if truncated else data), info.st_size, truncated


def input_problem(path, exc):
    """The exact reason text for an input that cannot be read."""
    if isinstance(exc, NotRegular):
        return "input %s is not a regular file" % (clean(str(path)),)
    return "cannot read input %s: %s" % (clean(str(path)), exc.strerror or type(exc).__name__)


def collect_inputs(paths, problems):
    """The input files in argument order; a directory contributes its ``*.log`` files below it, sorted."""
    files = []
    for path in paths:
        if path == "":
            problems.append(EMPTY_PATH_REASON)
            continue
        try:
            mode = os.lstat(path).st_mode
        except OSError as exc:
            problems.append(input_problem(path, exc))
            continue
        if not stat.S_ISDIR(mode):
            files.append(path)
            continue

        def on_error(exc):
            problems.append(input_problem(exc.filename or path, exc))

        for root, dirs, names in os.walk(path, onerror=on_error):
            dirs.sort()
            files.extend(os.path.join(root, name) for name in sorted(names) if name.endswith(INPUT_SUFFIX))
    return files


def scan(paths, problems):
    """Read and parse every input; returns the findings."""
    findings = Findings()
    files = collect_inputs(paths, problems)
    findings.files_found = len(files)
    for path in files[:MAX_INPUT_FILES]:
        try:
            data, size, truncated = read_input(path)
        except (OSError, NotRegular) as exc:
            problems.append(input_problem(path, exc))
            continue
        findings.files_read += 1
        if truncated:
            findings.truncated_files.append((clean(os.path.basename(path)), size))
        parse_data(data, findings)
    return findings


def summary_lines(findings):
    """The summary as raw lines (escaped when written); counts are exact, every bound has its own count line."""
    lines = ["**Red cause (%s)**" % ISSUE]
    if not findings.binaries and not findings.test_count:
        lines.append(NO_FINDINGS_NOTICE % findings.files_read)
    if findings.binaries:
        lines.append("")
        lines.append("failing test binaries: %d" % len(findings.binaries))
        lines.append("")
        lines.append("| Binary | Reason |")
        lines.append("| --- | --- |")
        for binary, reason in findings.binaries:
            lines.append("| %s | %s |" % (md_cell(binary), md_cell(reason)))
    if findings.test_count:
        lines.append("")
        lines.append("failing tests: %d" % findings.test_count)
        lines.append("")
        lines.append("| Binary | Test |")
        lines.append("| --- | --- |")
        for binary, name in findings.tests:
            lines.append("| %s | %s |" % (md_cell(binary), md_cell(name)))
        if findings.test_count > len(findings.tests):
            append_note(lines, "failing tests not listed: %d (limit %d)"
                        % (findings.test_count - len(findings.tests), MAX_FAILING_TESTS))
    if findings.files_found > MAX_INPUT_FILES:
        append_note(lines, "input files over the limit: %d found, first %d read, %d skipped"
                    % (findings.files_found, MAX_INPUT_FILES, findings.files_found - MAX_INPUT_FILES))
    for name, size in findings.truncated_files:
        append_note(lines, "input file over the limit: %s has %d bytes, first %d read" % (md_cell(name), size, MAX_FILE_BYTES))
    if findings.cut_lines:
        append_note(lines, "input lines over %d bytes cut: %d" % (MAX_LINE_BYTES, findings.cut_lines))
    return lines


def append_note(lines, text):
    """A plain line after the tables: a blank line first when the last line is a table row, so it is not a row."""
    if lines and lines[-1].startswith("|"):
        lines.append("")
    lines.append(text)


def annotation_items(findings):
    """(title, message) of every finding, failing binaries first: the annotation candidates."""
    items = [(TITLE_BINARY, "%s: %s" % (binary, reason)) for binary, reason in findings.binaries]
    items.extend((TITLE_TEST, "%s: %s" % (binary, name)) for binary, name in findings.tests)
    return items


def escaped_size(line):
    """Bytes the line takes in the summary file: escaped text plus its newline."""
    return len(wa.safe_text(line).encode("utf-8")) + 1


def fit_lines(lines, limit):
    """``lines`` that fit in ``limit`` escaped bytes; over the limit a prefix and one exact omission line."""
    total = sum(escaped_size(line) for line in lines)
    if total <= limit:
        return list(lines)
    kept = []
    used = 0
    for line in lines:
        size = escaped_size(line)
        if used + size > limit - SUMMARY_OMIT_RESERVE:
            break
        kept.append(line)
        used += size
    kept.append("summary over the limit: %d lines omitted (limit %d bytes)" % (len(lines) - len(kept), limit))
    return kept


def notice(reason):
    """One ``::notice`` line; ``reason`` is a fixed text or already cleaned."""
    print(wa.annotation("notice", reason, title=NOTICE_TITLE), flush=True)


def describe(exc):
    """``Type: text`` of an exception, redacted; the type alone when redaction is unavailable."""
    name = type(exc).__name__
    if _redact_line is None:
        return name
    return clean("%s: %s" % (name, str(exc)[:DETAIL_MAX_CHARS]))


def write_summary(lines, problems):
    """Append the fitted summary to the file named by GITHUB_STEP_SUMMARY."""
    github_summary_path = os.environ.get(SUMMARY_ENV, "")
    if not github_summary_path:
        problems.append(NO_SUMMARY_FILE_REASON)
        return
    try:
        with open(github_summary_path, "a", encoding="utf-8") as handle:
            for line in fit_lines(lines, MAX_SUMMARY_BYTES):
                handle.write(wa.safe_text(line) + "\n")
    except OSError as exc:
        problems.append("cannot write summary %s: %s" % (clean(github_summary_path), exc.strerror or type(exc).__name__))


def run(argv):
    args = build_parser().parse_args(argv)
    try:
        load_redaction()
    except Exception as exc:
        notice("cannot load redaction module: " + type(exc).__name__)
        return EXIT_OK
    problems = []
    if not args.paths:
        problems.append(NO_PATHS_REASON)
    findings = scan(args.paths, problems)
    lines = summary_lines(findings)
    items = annotation_items(findings)
    shown = items[:MAX_ANNOTATIONS]
    if len(items) > len(shown):
        append_note(lines, "annotations: %d of %d findings printed (limit %d), %d omitted"
                    % (len(shown), len(items), MAX_ANNOTATIONS, len(items) - len(shown)))
    write_summary(lines, problems)
    for title, message in shown:
        print(wa.annotation("error", message, max_chars=ANNOTATION_MAX_CHARS, title=title), flush=True)
    if len(items) > len(shown):
        notice("annotations: %d of %d findings printed (limit %d), %d omitted"
               % (len(shown), len(items), MAX_ANNOTATIONS, len(items) - len(shown)))
    if problems:
        notice(problems[0] if len(problems) == 1 else "%s (and %d more problems)" % (problems[0], len(problems) - 1))
    elif not items:
        notice(NO_FINDINGS_NOTICE % findings.files_read)
    return EXIT_OK


def main(argv=None):
    try:
        return run(sys.argv[1:] if argv is None else argv)
    except UsageProblem as exc:
        try:
            load_redaction()
        except Exception:
            pass  # clean() then yields the fixed marker, never the raw text
        notice("usage error: " + clean(str(exc)))
    except Exception as exc:  # the step never fails the job: one notice with the exact reason
        notice("internal error: " + describe(exc))
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
