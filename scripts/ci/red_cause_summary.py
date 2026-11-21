#!/usr/bin/env python3
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""Name the cause of a red CI test job in its step summary and as annotations (#9709).

A red test job used to leave its cause in a log nobody opens first.  This step runs after the test step of every
test job (``if: failure() || cancelled()``, ``continue-on-error: true``, ``timeout-minutes``), reads the output the
job already wrote and prints what a reader needs: the failing test binaries, the failing test names and the
``test result: FAILED`` lines.  When no test failed it names the cause another way: the LAST ``error[``/``error:``
line of the failing step, shown as ``last error line (a candidate cause): ``, or ``cause not identified`` plus the
failing step's name.  It is deterministic: no secret, no network, no LLM.  It never changes the job result.

Input: files, or directories (every ``*.log`` below them, sorted), given as arguments, plus one ``--step LOG NAME``
per step of the job that writes a log, in step order.  The failing step is the last one whose log exists (a step
that never started wrote no log); a failing step log that is not a regular file or cannot be read is a problem
line.  The parser reads libtest output, one pass, linear in the input:

* a binary section opens only on cargo's exact shapes, anchored on the whole line (trailing blanks aside):
  ``     Running <source> (<path>)`` (five spaces, no backtick or parenthesis in either part) or
  ``   Doc-tests <crate>`` (three spaces, one identifier).  Before the first such line nothing is read; there is no
  implicit section.  Limit: a test that prints a line of exactly that shape on its own output opens a section;
* failing test names come from their own section only: the last non-empty ``failures:`` list (four-space indent),
  else the column-0 ``test <name> ... FAILED`` lines; libtest's mode suffixes (`` - should panic``,
  `` - compile fail``, `` - compile``) and padding are removed; a name the token-safe line cut drops whole (one
  long token run) is kept as ``<redacted>``, so its test still counts.  ``---- <name> stdout ----`` (or ``stderr``) starts
  a captured-output block that is skipped up to the next ``failures:`` line;
* the names are committed only by the section's column-0 ``test result: FAILED`` line, which is also a failing
  binary row (every distinct such line is one row); ``test result: ok`` commits nothing;
* a section that ends without any ``test result:`` line is a row with the reason ``ended without a test result line
  (crash, timeout or signal)`` and the first crash detail; a crash detail after a passing result line is a row
  ``crashed after a passing test result line; <detail>``.

Every shown value is a ``Cleaned``, which only ``clean()`` and ``render_name()`` make; ``Findings`` refuses anything
else.  ``clean()`` cuts first and redacts what is shown: a value over MAX_LINE_BYTES is cut on a character boundary,
a token the cut went through is dropped whole, ``...`` marks the cut and every such cut is counted (``shown values
cut: N``); then the redaction of ``scripts/cert_gate_evidence.py`` runs on at most MAX_LINE_BYTES (a raising
redaction yields ``<redaction failed>``, never the raw text), and format characters (Unicode Cf, bidi controls
among them) are shown as ``\\uXXXX``.  The redaction runs only for shown values, at most REDACTION_BUDGET_CALLS per
run.  A crash detail whose path makes it too long loses leading path components behind ``.../`` first, so its
signal stays.  Counting and de-duplication run on the raw values, so N failing tests always print ``failing tests:
N``: a test is keyed on its binary and the first NAME_KEY_BYTES UTF-8 bytes of its name.  ``render_name`` shows a
name as written only when it has the plain Rust path shape and no token shape.

Output: annotations pass the shared escape of ``workflow_annotation.py``.  The summary file has its own escape
(``\\`` doubled, control characters as ``\\xNN``, U+2028/U+2029 and surrogates as ``\\uXXXX``; ``::``, ``%`` and
``#`` stay); Markdown cells also escape ``&``, ``#``, ``<``, ``|``, a backtick, ``[``, ``*``, ``_`` and ``~`` and
break GFM autolinks, @mentions, ``GH-<n>`` and 7+ hex digit runs with a zero-width space.  Each bound is a named
constant; over a bound the output carries an exact count line, never a silent cut, and the count lines stay after
the omission line of a summary over MAX_SUMMARY_BYTES.  The annotation total counts every failing binary and test.
A log over the file bound is read from its tail (cargo prints the verdict last); a tail without a complete line is
reported as not parsed.

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
import unicodedata
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
MAX_FAILING_BINARIES = 50  # failing test binary rows listed in the summary
MAX_LINE_BYTES = 300  # bytes of one input line that are read, and of one shown value; the rest is cut and counted
MAX_SUMMARY_BYTES = 32768  # bytes of the summary this step appends, escapes included
MAX_ANNOTATIONS = 10  # ::error lines (GitHub shows 10 per step)
MAX_FILE_BYTES = 16 * 1024 * 1024  # bytes read per input file: the whole file, or its last MAX_FILE_BYTES
MAX_INPUT_FILES = 64  # input files read
MAX_WALK_ENTRIES = 10000  # directory entries looked at per directory argument
MAX_TOTAL_BYTES = 64 * 1024 * 1024  # bytes read over all input files
REDACTION_BUDGET_CALLS = 256  # redaction calls per run: shown values only (2 x 50 rows, 2 x 50 tests, the rest)
SUMMARY_OMIT_RESERVE = 160  # bytes kept free for the omission line of a summary over its bound
# An annotation line is never cut by the shared module: two shown values of MAX_LINE_BYTES, each byte at most
# 7/3 characters after the Cf escape and the shared escape, plus the title, fit.
ANNOTATION_MAX_CHARS = 4000
DETAIL_MAX_CHARS = 200

NO_RESULT_REASON = "ended without a test result line (crash, timeout or signal)"
CRASH_AFTER_OK_REASON = "crashed after a passing test result line; "
NO_PATHS_REASON = "no input paths given"
EMPTY_PATH_REASON = "input path is empty"
NO_SUMMARY_FILE_REASON = "GITHUB_STEP_SUMMARY is not set, summary not written"
NOT_IDENTIFIED = "cause not identified"
NO_FINDINGS_NOTICE = NOT_IDENTIFIED + "; no failing test or test binary found in %d input file(s)"
LAST_STEP_CAUSE = NOT_IDENTIFIED + "; failing step: %s (the last step whose log exists)"
NO_STEP_CAUSE = NOT_IDENTIFIED + "; failing step: a step before %s (no step log exists)"
STEP_NOT_REGULAR = "step log %s is not a regular file (NotRegular)"
STEP_UNREADABLE = "cannot read step log %s: %s (%s)"
CAUSE_PREFIX = "last error line (a candidate cause): "
REDACTION_FILE = "cert_gate_evidence.py"
REDACTION_FAILED = "<redaction failed>"
REDACTION_SPENT = "<redaction budget spent>"
SUMMARY_ENV = "GITHUB_STEP_SUMMARY"
CUT_MARK = "..."
CUT_MARK_BYTES = CUT_MARK.encode("ascii")
PATH_CUT_MARK = ".../"

NOTICE_TITLE = "red cause summary"
TITLE_BINARY = "failing test binary"
TITLE_TEST = "failing test"
TITLE_CAUSE = "red cause"

TEST_PREFIX = "test "
FAILED_SUFFIX = " ... FAILED"
FAILED_SUFFIX_BYTES = FAILED_SUFFIX.encode("ascii")
TEST_PREFIX_BYTES = TEST_PREFIX.encode("ascii")
# The name shown when the line cut dropped a whole name (one token run): the run is never shown in part.
DROPPED_NAME_BYTES = b"<redacted>"
# A name is keyed on at most this many UTF-8 bytes, cut on a character boundary: the most a cut FAILED line keeps, so
# the same long name in its FAILED line and in the failures list is one key (both lines are cut in bytes).
NAME_KEY_BYTES = MAX_LINE_BYTES - len(TEST_PREFIX) - len(FAILED_SUFFIX)
# UTF-8 continuation bytes are 10xxxxxx; a character has at most 3 of them, so a cut backs up at most 3 bytes.
UTF8_CONTINUATION_MASK = 0xC0
UTF8_CONTINUATION_TAG = 0x80
UTF8_MAX_BACKUP = 3
# The bytes a token is made of (the redaction masks such a run whole): a cut through a run drops the run.
TOKEN_BYTES = frozenset(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-+/=.~")
RESULT_PREFIX = "test result:"
RESULT_FAILED_PREFIX = "test result: FAILED"
FAILURES_HEADER = "failures:"
LIST_INDENT = "    "
LIST_INDENT_BYTES = LIST_INDENT.encode("ascii")
# cargo's exact section lines, matched on the whole line after its trailing blanks are removed.
RUNNING_LINE = re.compile(r"     Running ([^`()\s][^`()]*?) \(([^`()\s]+)\)\Z")
DOC_TESTS_LINE = re.compile(r"   Doc-tests ([A-Za-z_][A-Za-z0-9_-]*)\Z")
CAPTURE_LINE = re.compile(r"---- .+ (?:stdout|stderr) ----\Z")
MODE_SUFFIX = re.compile(r" - (?:should panic|compile fail|compile)\Z")
DOC_TESTS_LABEL = "doc-tests "
UNITTESTS_PREFIX = "unittests "
LIB_SOURCE = "src/lib.rs"
CRASH_MARKER = "process didn't exit successfully"
CRASH_PATH = re.compile(r"`([^`]*)`")
ERROR_LINE_PREFIXES = ("error[", "error:")
HASH_SUFFIX = re.compile(r"-[0-9a-f]{8,}$")
ANSI = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]")
INPUT_SUFFIX = ".log"
FORMAT_CATEGORY = "Cf"
BMP_LAST = 0xFFFF
MD_ESCAPES = (("&", "&amp;"), ("#", "&#35;"), ("<", "&lt;"), ("|", "&#124;"), ("`", "&#96;"), ("[", "&#91;"),
              ("*", "&#42;"), ("_", "&#95;"), ("~", "&#126;"))
ZWSP = "​"
MD_AUTOLINKS = ((re.compile(r"@"), "@" + ZWSP), (re.compile(r":(?=//)"), ":" + ZWSP),
                (re.compile(r"(?i)(www)(?=\.)"), "\\1" + ZWSP),
                (re.compile(r"\b([0-9a-fA-F])([0-9a-fA-F]{6,})\b"), "\\1" + ZWSP + "\\2"),
                (re.compile(r"\b([Gg])([Hh]-[0-9])"), "\\1" + ZWSP + "\\2"))
# The summary file escape: a backslash, C0, DEL and C1 controls, line and paragraph separators and surrogates.
SUMMARY_ESCAPE = re.compile("[\\\\\x00-\x1f\x7f-\x9f  \ud800-\udfff]")
C1_LAST = 0x9F

# render_name: a name is shown as written only in the plain Rust path shape, with no token prefix, no JWT header and
# no 32+ hex or base64 run inside one segment.
# decision: the base64 run excludes "_" over base64url because snake_case names of 32+ characters must stay readable
# (C-M1 census); an underscore-joined token still goes through clean() by its prefix or its hex/base64 parts.
NAME_GRAMMAR = re.compile(r"[a-z_][a-z0-9_]*(?:::[A-Za-z_][A-Za-z0-9_]*)*")
NAME_TOKEN_MARKERS = ("ghp_", "gho_", "ghs_", "ghu_", "ghr_", "github_pat_", "sk-", "eyJ")
NAME_SECRET_RUN = re.compile(r"[0-9A-Fa-f]{32,}|[A-Za-z0-9+/=]{32,}")


class UsageProblem(Exception):
    """A bad command line; reported as one notice, exit 0."""


class NotRegular(Exception):
    """An input that is not a regular file (a FIFO, a device, a directory reached through a race)."""


class OverBudget(Exception):
    """An input that would take the bytes read over MAX_TOTAL_BYTES; it and every later input stay unread."""


class Parser(argparse.ArgumentParser):
    def error(self, message):  # argparse would exit 2; this step never fails the job
        raise UsageProblem(message)


def build_parser():
    parser = Parser(
        prog=WA_PROG,
        description="Write the cause of a red CI test job to GITHUB_STEP_SUMMARY and as ::error annotations "
                    "(%s). Exit 0 on every internal error." % ISSUE)
    parser.add_argument("--step", nargs=2, action="append", default=[], metavar=("LOG", "NAME"),
                        help="a step of the job that writes LOG, in step order; the last one whose log exists failed")
    parser.add_argument("paths", nargs="*", help="cargo test output files, or directories holding *.log files")
    return parser


_redact_line = None
_MINT = object()
# Per-run counters, reset by run(): redaction calls made, shown values cut, shown values over the redaction budget.
_redaction_calls = 0
_shown_cuts = 0
_budget_spent = 0


class Cleaned:
    """A value that is safe to show: made only by clean() and render_name() (#9709 r1, invariant 1)."""

    __slots__ = ("text",)

    def __init__(self, text, key):
        if key is not _MINT or not isinstance(text, str):
            raise TypeError("Cleaned is made only by clean() or render_name()")
        self.text = text


def load_redaction():
    """The redaction of scripts/cert_gate_evidence.py, loaded by path (never through sys.path)."""
    global _redact_line
    path = Path(__file__).resolve().parent.parent / REDACTION_FILE
    spec = importlib.util.spec_from_file_location("cert_gate_evidence", str(path))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    _redact_line = module.redact_line


def reset_counters():
    """The per-run counters at zero (one run of main() is one count)."""
    global _redaction_calls, _shown_cuts, _budget_spent
    _redaction_calls = 0
    _shown_cuts = 0
    _budget_spent = 0


def cut_bytes(data, limit):
    """``data`` (UTF-8 bytes) cut to at most ``limit`` bytes without splitting a character: a cut that falls inside a
    multi-byte character backs up to that character's first byte, so nothing cut decodes to U+FFFD."""
    if len(data) <= limit:
        return data
    end = limit
    for _ in range(UTF8_MAX_BACKUP):
        if end > 0 and data[end] & UTF8_CONTINUATION_MASK == UTF8_CONTINUATION_TAG:
            end -= 1
    return data[:end]


def cut_token_safe(data, limit):
    """``cut_bytes(data, limit)``, and when the cut goes through a run of token bytes the whole run is dropped, so no
    shown text holds a fragment of a token the redaction would not recognise any more."""
    head = cut_bytes(data, limit)
    end = len(head)
    if end == len(data) or end == 0 or data[end] not in TOKEN_BYTES or head[end - 1] not in TOKEN_BYTES:
        return head
    while end > 0 and head[end - 1] in TOKEN_BYTES:
        end -= 1
    return head[:end]


def visible(text):
    """``text`` with every format character (Unicode Cf: bidi controls, zero-width joiners) as a literal escape."""
    if text.isascii():
        return text
    shown = []
    for char in text:
        if unicodedata.category(char) == FORMAT_CATEGORY:
            shown.append(("\\u%04x" if ord(char) <= BMP_LAST else "\\U%08x") % ord(char))
        else:
            shown.append(char)
    return "".join(shown)


def _clean(text, count_cut):
    """The one maker of a shown value from raw text: cut, then redact, then make format characters visible."""
    global _redaction_calls, _shown_cuts, _budget_spent
    if _redact_line is None:
        return Cleaned(REDACTION_FAILED, _MINT)
    data = text.encode("utf-8", "replace")
    if len(data) > MAX_LINE_BYTES:
        data = cut_token_safe(data, MAX_LINE_BYTES - len(CUT_MARK_BYTES)) + CUT_MARK_BYTES
        if count_cut:
            _shown_cuts += 1
    if _redaction_calls >= REDACTION_BUDGET_CALLS:
        _budget_spent += 1
        return Cleaned(REDACTION_SPENT, _MINT)
    _redaction_calls += 1
    try:
        shown = _redact_line(data.decode("utf-8", "replace"))
    except Exception:
        return Cleaned(REDACTION_FAILED, _MINT)
    if not isinstance(shown, str):
        return Cleaned(REDACTION_FAILED, _MINT)
    data = shown.encode("utf-8", "replace")
    if len(data) > MAX_LINE_BYTES:  # a redaction marker longer than what it masked
        shown = (cut_token_safe(data, MAX_LINE_BYTES - len(CUT_MARK_BYTES)) + CUT_MARK_BYTES).decode("utf-8")
    return Cleaned(visible(shown), _MINT)


def clean(text):
    """``text`` to show: cut to MAX_LINE_BYTES on a character boundary (a token the cut went through dropped whole, the
    cut marked and counted), then redacted (a failing redaction yields a fixed marker, never the raw text)."""
    return _clean(text, True)


def shorter_path(reason):
    """``reason`` with leading components of its backtick path replaced by ``.../`` until it fits MAX_LINE_BYTES, so a
    crash detail keeps its signal; None when no such shortening makes it fit."""
    match = CRASH_PATH.search(reason)
    if match is None:
        return None
    path = match.group(1)
    head, tail = reason[:match.start(1)], reason[match.end(1):]
    at = path.find("/", 1)
    while at >= 0:
        shown = head + PATH_CUT_MARK + path[at + 1:] + tail
        if len(shown.encode("utf-8", "replace")) <= MAX_LINE_BYTES:
            return shown
        at = path.find("/", at + 1)
    return None


def clean_reason(reason):
    """A row reason to show: a crash path is shortened first, else the cut of clean(); either is one counted cut."""
    global _shown_cuts
    if len(reason.encode("utf-8", "replace")) <= MAX_LINE_BYTES:
        return clean(reason)
    shown = shorter_path(reason)
    if shown is None:
        return clean(reason)
    _shown_cuts += 1
    return _clean(shown, False)


def render_name(raw):
    """A test or binary name to show: as written when it has the plain Rust path shape and no token shape (no redaction
    call), else ``clean(raw)``."""
    if (_redact_line is not None and len(raw) <= MAX_LINE_BYTES and NAME_GRAMMAR.fullmatch(raw)
            and not any(marker in raw for marker in NAME_TOKEN_MARKERS) and not NAME_SECRET_RUN.search(raw)):
        return Cleaned(raw, _MINT)
    return clean(raw)


def md_cell(text):
    """``text`` for a Markdown table cell: format characters visible, no HTML, no pipe, no emphasis, no backtick, no
    link bracket, no heading or issue reference, no autolink, mention or commit link."""
    text = visible(text)
    for raw, replacement in MD_ESCAPES:
        text = text.replace(raw, replacement)
    for pattern, replacement in MD_AUTOLINKS:
        text = pattern.sub(replacement, text)
    return text


def summary_char(match):
    char = match.group(0)
    if char == "\\":
        return "\\\\"
    if ord(char) <= C1_LAST:
        return "\\x%02x" % ord(char)
    return "\\u%04x" % ord(char)


def summary_text(line):
    """``line`` as written to the summary file: workflow commands cannot start there, so ``::``, ``%`` and ``#`` stay;
    a backslash, controls, line separators and surrogates are escaped."""
    return SUMMARY_ESCAPE.sub(summary_char, line)


def binary_label(source, path):
    """The binary of a ``Running`` line: the file name of its path without the hash; a unittests binary of a source
    other than src/lib.rs (a bin target) carries its source."""
    name = path.rsplit("/", 1)[-1]
    label = HASH_SUFFIX.sub("", name) or path
    if source.startswith(UNITTESTS_PREFIX) and source[len(UNITTESTS_PREFIX):] != LIB_SOURCE:
        label = "%s (%s)" % (label, source[len(UNITTESTS_PREFIX):])
    return label


def section_label(line):
    """The binary label when ``line`` (trailing blanks removed) is one of cargo's exact section lines, else None."""
    match = RUNNING_LINE.match(line)
    if match is not None:
        return binary_label(match.group(1), match.group(2))
    match = DOC_TESTS_LINE.match(line)
    if match is not None:
        return DOC_TESTS_LABEL + match.group(1)
    return None


def test_name(text):
    """A libtest name without its padding and mode suffix (`` - should panic``, `` - compile fail``, ``- compile``)."""
    return MODE_SUFFIX.sub("", text.strip()).rstrip()


def require_cleaned(*values):
    for value in values:
        if not isinstance(value, Cleaned):
            raise TypeError("a shown value must be a Cleaned, not %s" % type(value).__name__)


def raw_key(*parts):
    return hashlib.blake2b(b"\x00".join(part.encode("utf-8", "replace") for part in parts), digest_size=16).digest()


class Findings:
    """What the parse found: failing binaries, failing tests, and the exact counts of every cut.  Keys and counts are
    raw values; the shown values are made only for the rows listed, and only Cleaned values are stored."""

    def __init__(self):
        self.binaries = []  # (shown binary, shown reason): the first MAX_FAILING_BINARIES only
        self.binary_count = 0  # every distinct failing binary row
        self.binary_keys = set()
        self.tests = []  # (shown binary, shown name): the first MAX_FAILING_TESTS only
        self.test_count = 0  # every distinct failing test
        self.test_keys = set()
        self.files_read = 0
        self.cut_lines = 0
        self.truncated_files = []  # (shown name, size)
        self.unparsed_files = []  # shown names of truncated files whose tail holds no complete line
        self.files_found = 0
        self.walks_over = []  # shown directory arguments whose walk hit MAX_WALK_ENTRIES
        self.files_over_budget = 0

    def note_binary(self, raw_binary, raw_reason, show):
        """Count a failing binary row once; ``show()`` makes its (shown binary, shown reason) only when it is listed."""
        key = raw_key(raw_binary, raw_reason)
        if key in self.binary_keys:
            return
        self.binary_keys.add(key)
        self.binary_count += 1
        if len(self.binaries) < MAX_FAILING_BINARIES:
            shown_binary, shown_reason = show()
            require_cleaned(shown_binary, shown_reason)
            self.binaries.append((shown_binary.text, shown_reason.text))

    def note_test(self, raw_binary, raw_name, show):
        """Count a failing test once (keyed on its first NAME_KEY_BYTES bytes); ``show()`` runs only when listed."""
        key = raw_binary.encode("utf-8", "replace") + b"\x00" + cut_bytes(raw_name.encode("utf-8", "replace"),
                                                                          NAME_KEY_BYTES)
        digest = hashlib.blake2b(key, digest_size=16).digest()
        if digest in self.test_keys:
            return
        self.test_keys.add(digest)
        self.test_count += 1
        if len(self.tests) < MAX_FAILING_TESTS:
            shown_binary, shown_name = show()
            require_cleaned(shown_binary, shown_name)
            self.tests.append((shown_binary.text, shown_name.text))

    def add_binary(self, raw_binary, raw_reason, shown_binary, shown_reason):
        require_cleaned(shown_binary, shown_reason)
        self.note_binary(raw_binary, raw_reason, lambda: (shown_binary, shown_reason))

    def add_test(self, raw_binary, raw_name, shown_binary, shown_name):
        require_cleaned(shown_binary, shown_name)
        self.note_test(raw_binary, raw_name, lambda: (shown_binary, shown_name))


class Section:
    """One binary section of one file while it is parsed; every field holds the raw value."""

    __slots__ = ("binary", "shown", "result", "detail", "after_ok", "names", "listed")

    def __init__(self, binary):
        self.binary = binary
        self.shown = None  # render_name(binary), made once when a row of this section is listed
        self.result = None  # None, or the kind of the first result line: "failed" or "ok"
        self.detail = ""  # the first crash detail before any result line
        self.after_ok = ""  # the first crash detail after a passing result line
        self.names = []  # column-0 FAILED names since the last result line
        self.listed = []  # the last non-empty failures list since the last result line

    def shown_binary(self):
        if self.shown is None:
            self.shown = render_name(self.binary)
        return self.shown


def close_section(section, findings):
    """The row of a section that ended without a result line, or that crashed after a passing one."""
    if section is None:
        return
    if section.result is None:
        reason = NO_RESULT_REASON + ("; " + section.detail if section.detail else "")
    elif section.result == "ok" and section.after_ok:
        reason = CRASH_AFTER_OK_REASON + section.after_ok
    else:
        return
    findings.note_binary(section.binary, reason, lambda: (section.shown_binary(), clean_reason(reason)))


def commit_result(section, line, findings):
    """A column-0 result line: FAILED commits the section's names and is a row; ok commits nothing."""
    names = section.listed or section.names
    section.listed = []
    section.names = []
    if not line.startswith(RESULT_FAILED_PREFIX):
        if section.result is None:
            section.result = "ok"
        return
    section.result = "failed"
    for name in names:
        findings.note_test(section.binary, name, lambda: (section.shown_binary(), render_name(name)))
    findings.note_binary(section.binary, line, lambda: (section.shown_binary(), clean(line)))


def keep_dropped_name(raw, kept, prefix):
    """``kept``, unless the token-safe cut dropped the whole name after ``prefix`` (a name that is one long token run):
    then ``prefix`` and a fixed marker, so a failing test is never lost by the cut (#9759 r1, fail closed)."""
    if raw.startswith(prefix) and not kept[len(prefix):].strip():
        return prefix + DROPPED_NAME_BYTES
    return kept


def read_line(raw, findings):
    """One input line as text: carriage return removed, cut to MAX_LINE_BYTES (a FAILED verdict kept, a token the cut
    went through dropped whole, the cut counted), colour removed, trailing blanks removed."""
    if raw.endswith(b"\r"):
        raw = raw[:-1]
    if len(raw) > MAX_LINE_BYTES:
        findings.cut_lines += 1
        if raw.endswith(FAILED_SUFFIX_BYTES):  # a long failing test name is cut, never its FAILED verdict
            kept = cut_token_safe(raw[:-len(FAILED_SUFFIX_BYTES)], MAX_LINE_BYTES - len(FAILED_SUFFIX_BYTES))
            raw = keep_dropped_name(raw, kept, TEST_PREFIX_BYTES) + FAILED_SUFFIX_BYTES
        else:
            raw = keep_dropped_name(raw, cut_token_safe(raw, MAX_LINE_BYTES), LIST_INDENT_BYTES)
    return ANSI.sub("", raw.decode("utf-8", "replace")).rstrip()


def parse_data(data, findings):
    """Parse the bytes of one input file into ``findings``: one pass, linear in the input size."""
    section = None
    in_list = False
    listing = []
    skipping = False
    for raw in data.split(b"\n"):
        line = read_line(raw, findings)
        if skipping:  # a captured-output block: nothing in it is libtest's own output
            if line == FAILURES_HEADER:
                skipping = False
                in_list = True
                listing = []
            continue
        if in_list:
            if line.startswith(LIST_INDENT) and line.strip():
                listing.append(test_name(line))
                continue
            if not line and not listing:
                continue
            in_list = False
            if listing:
                section.listed = listing
        label = section_label(line)
        if label is not None:
            close_section(section, findings)
            section = Section(label)
            continue
        if section is None:  # no implicit section: nothing before cargo's first section line is read
            continue
        if line == FAILURES_HEADER:
            in_list = True
            listing = []
        elif CAPTURE_LINE.match(line):
            skipping = True
        elif line.startswith(RESULT_PREFIX):
            commit_result(section, line, findings)
        elif line.startswith(TEST_PREFIX) and line.endswith(FAILED_SUFFIX):
            name = test_name(line[len(TEST_PREFIX):-len(FAILED_SUFFIX)])
            if name:
                section.names.append(name)
        elif CRASH_MARKER in line:
            if section.result is None and not section.detail:
                section.detail = line.strip()
            elif section.result == "ok" and not section.after_ok:
                section.after_ok = line.strip()
    if in_list and listing and section is not None:
        section.listed = listing
    close_section(section, findings)


def read_input(path, budget):
    """(bytes, size, truncated) of one regular file, read through one descriptor: no symlink is followed, a FIFO is
    refused after fstat.  A file over MAX_FILE_BYTES is read from its tail: its last MAX_FILE_BYTES without the
    partial first line (empty when the tail holds no line break).  A file whose read would pass ``budget`` bytes
    raises OverBudget unread."""
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    fd = os.open(path, flags)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise NotRegular(path)
        truncated = info.st_size > MAX_FILE_BYTES
        if min(info.st_size, MAX_FILE_BYTES) > budget:
            raise OverBudget(path)
        if truncated:
            # One byte before the tail too, so a tail that starts on a line boundary keeps its first line.
            os.lseek(fd, info.st_size - MAX_FILE_BYTES - 1, os.SEEK_SET)
        with os.fdopen(fd, "rb", closefd=False) as handle:
            data = handle.read(MAX_FILE_BYTES + 1 if truncated else info.st_size)
    finally:
        os.close(fd)
    if truncated:
        first_break = data.find(b"\n")
        data = data[first_break + 1:] if first_break >= 0 else b""
    return data, info.st_size, truncated


def input_problem(path, exc):
    """The exact reason text for an input that cannot be read."""
    if isinstance(exc, NotRegular):
        return "input %s is not a regular file" % (clean(str(path)).text,)
    return "cannot read input %s: %s" % (clean(str(path)).text, exc.strerror or type(exc).__name__)


def walk_logs(top, problems, findings):
    """The ``*.log`` files below the directory ``top``, sorted, depth first like ``os.walk`` (top down, symlinks not
    followed); at most MAX_WALK_ENTRIES directory entries are looked at, the rest is skipped and noted."""
    files = []
    entries = 0
    stack = [top]
    while stack:
        root = stack.pop()
        dirs = []
        names = []
        over = False
        try:
            with os.scandir(root) as listing:
                for entry in listing:
                    entries += 1
                    if entries > MAX_WALK_ENTRIES:
                        over = True
                        break
                    try:
                        is_dir = entry.is_dir(follow_symlinks=False)
                    except OSError:
                        is_dir = False
                    (dirs if is_dir else names).append(entry.name)
        except OSError as exc:
            problems.append(input_problem(exc.filename or root, exc))
            continue
        files.extend(os.path.join(root, name) for name in sorted(names) if name.endswith(INPUT_SUFFIX))
        if over:
            findings.walks_over.append(clean(str(top)).text)
            return files
        stack.extend(os.path.join(root, name) for name in sorted(dirs, reverse=True))
    return files


def collect_inputs(paths, problems, findings):
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
        files.extend(walk_logs(path, problems, findings))
    return files


def scan(paths, problems):
    """Read and parse every input; returns the findings."""
    findings = Findings()
    files = collect_inputs(paths, problems, findings)
    findings.files_found = len(files)
    budget = MAX_TOTAL_BYTES
    chosen = files[:MAX_INPUT_FILES]
    for index, path in enumerate(chosen):
        try:
            data, size, truncated = read_input(path, budget)
        except OverBudget:
            findings.files_over_budget = len(chosen) - index
            break
        except (OSError, NotRegular) as exc:
            problems.append(input_problem(path, exc))
            continue
        budget -= len(data)
        findings.files_read += 1
        if truncated and not data:
            findings.unparsed_files.append(clean(os.path.basename(path)).text)
            continue
        if truncated:
            findings.truncated_files.append((clean(os.path.basename(path)).text, size))
        parse_data(data, findings)
    return findings


def last_error_line(data):
    """The last ``error[``/``error:`` line of a step log (cut like an input line, colour removed), or None."""
    global _shown_cuts
    found = None
    for chunk in data.split(b"\n"):
        if chunk.endswith(b"\r"):
            chunk = chunk[:-1]
        head = cut_token_safe(chunk, MAX_LINE_BYTES)
        text = ANSI.sub("", head.decode("utf-8", "replace")).strip()
        if text.startswith(ERROR_LINE_PREFIXES):
            found = (text, len(head) < len(chunk))
    if found is None:
        return None
    if found[1]:
        _shown_cuts += 1
    return found[0]


def name_cause(steps, problems):
    """(Cleaned cause text, named) for a red job with no failing test: the last error line of the failing step (the
    last whose log exists), else "cause not identified" with that step's name; a failing step log that is not a
    regular file or cannot be read is a problem line.  None without ``--step``."""
    if not steps:
        return None
    failing = None
    for log, name in steps:
        if log == "":
            continue
        try:
            mode = os.lstat(log).st_mode
        except OSError:
            continue
        failing = (log, name, mode)
    if failing is None:
        return clean(NO_STEP_CAUSE % steps[0][1]), False
    log, name, mode = failing
    unnamed = clean(LAST_STEP_CAUSE % name), False
    if not stat.S_ISREG(mode):
        problems.append(STEP_NOT_REGULAR % clean(log).text)
        return unnamed
    try:
        data, _size, _truncated = read_input(log, MAX_FILE_BYTES)
    except NotRegular:
        problems.append(STEP_NOT_REGULAR % clean(log).text)
        return unnamed
    except OSError as exc:
        problems.append(STEP_UNREADABLE % (clean(log).text, exc.strerror or type(exc).__name__, type(exc).__name__))
        return unnamed
    error = last_error_line(data)
    if error is None:
        return unnamed
    return clean("%s: %s" % (name, error)), True


def summary_lines(findings, cause):
    """The summary as raw lines (escaped when written); counts are exact and come from the full lists."""
    lines = ["**Red cause (%s)**" % ISSUE]
    if not findings.binary_count and not findings.test_count:
        if cause is None:
            lines.append(NO_FINDINGS_NOTICE % findings.files_read)
        else:
            shown, named = cause
            lines.append((CAUSE_PREFIX if named else "") + md_cell(shown.text))
    if findings.binary_count:
        lines.append("")
        lines.append("failing test binaries: %d" % findings.binary_count)
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
    return lines


def summary_notes(findings):
    """The count lines of every bound the input reached; they are kept after an omission line too."""
    notes = []
    if findings.binary_count > len(findings.binaries):
        notes.append("failing test binaries not listed: %d (limit %d)"
                     % (findings.binary_count - len(findings.binaries), MAX_FAILING_BINARIES))
    if findings.test_count > len(findings.tests):
        notes.append("failing tests not listed: %d (limit %d)"
                     % (findings.test_count - len(findings.tests), MAX_FAILING_TESTS))
    if findings.files_found > MAX_INPUT_FILES:
        notes.append("input files over the limit: %d found, first %d read, %d skipped"
                     % (findings.files_found, MAX_INPUT_FILES, findings.files_found - MAX_INPUT_FILES))
    for name in findings.walks_over:
        notes.append("directory walk over the limit: %s has more than %d entries, rest skipped"
                     % (md_cell(name), MAX_WALK_ENTRIES))
    if findings.files_over_budget:
        notes.append("input bytes over the limit: %d file(s) not read (limit %d bytes)"
                     % (findings.files_over_budget, MAX_TOTAL_BYTES))
    for name, size in findings.truncated_files:
        notes.append("input file over the limit: %s has %d bytes, last %d read" % (md_cell(name), size, MAX_FILE_BYTES))
    for name in findings.unparsed_files:
        notes.append("input file %s: no complete line found in the last %d bytes, not parsed"
                     % (md_cell(name), MAX_FILE_BYTES))
    if findings.cut_lines:
        notes.append("input lines over %d bytes cut: %d" % (MAX_LINE_BYTES, findings.cut_lines))
    return notes


def counter_notes():
    """The count lines of the shown-value cuts and of the redaction budget of this run."""
    notes = []
    if _shown_cuts:
        notes.append("shown values cut: %d (limit %d bytes)" % (_shown_cuts, MAX_LINE_BYTES))
    if _budget_spent:
        notes.append("redaction budget spent: %d shown values replaced by %s (limit %d calls)"
                     % (_budget_spent, REDACTION_SPENT, REDACTION_BUDGET_CALLS))
    return notes


def append_note(lines, text):
    """A plain line after the tables: a blank line first when the last line is a table row, so it is not a row."""
    if lines and lines[-1].startswith("|"):
        lines.append("")
    lines.append(text)


def annotation_items(findings):
    """(title, message) of every listed finding, failing binaries first: the annotation candidates."""
    items = [(TITLE_BINARY, "%s: %s" % (binary, reason)) for binary, reason in findings.binaries]
    items.extend((TITLE_TEST, "%s: %s" % (binary, name)) for binary, name in findings.tests)
    return items


def escaped_size(line):
    """Bytes the line takes in the summary file: escaped text plus its newline."""
    return len(summary_text(line).encode("utf-8", "replace")) + 1


def fit_lines(lines, limit, notes=()):
    """``lines`` and then ``notes`` when they fit in ``limit`` escaped bytes; over the limit a prefix of ``lines``, a
    blank line, one exact omission line and the notes (the notes that fit, and a count of the rest)."""
    notes = list(notes)
    full = list(lines)
    for note in notes:
        append_note(full, note)
    if sum(escaped_size(line) for line in full) <= limit:
        return full
    kept_notes = []
    notes_size = 0
    for note in notes:
        size = escaped_size(note)
        if notes_size + size > (limit - 2 * SUMMARY_OMIT_RESERVE) // 2:
            break
        kept_notes.append(note)
        notes_size += size
    if len(kept_notes) < len(notes):
        kept_notes.append("notes over the limit: %d omitted" % (len(notes) - len(kept_notes)))
        notes_size += SUMMARY_OMIT_RESERVE
    kept = []
    used = 0
    for line in lines:
        size = escaped_size(line)
        if used + size > limit - SUMMARY_OMIT_RESERVE - notes_size:
            break
        kept.append(line)
        used += size
    omitted = len(lines) - len(kept)
    kept.append("")
    kept.append("summary over the limit: %d lines omitted (limit %d bytes)" % (omitted, limit))
    return kept + kept_notes


def notice(reason):
    """One ``::notice`` line; ``reason`` is a fixed text or already cleaned."""
    print(wa.annotation("notice", reason, title=NOTICE_TITLE), flush=True)


def describe(exc):
    """``Type: text`` of an exception, redacted; the type alone when redaction is unavailable."""
    name = type(exc).__name__
    if _redact_line is None:
        return name
    return clean("%s: %s" % (name, str(exc)[:DETAIL_MAX_CHARS])).text


def write_summary(lines, problems, notes=()):
    """Append the fitted summary to the file named by GITHUB_STEP_SUMMARY."""
    github_summary_path = os.environ.get(SUMMARY_ENV, "")
    if not github_summary_path:
        problems.append(NO_SUMMARY_FILE_REASON)
        return
    try:
        with open(github_summary_path, "a", encoding="utf-8") as handle:
            for line in fit_lines(lines, MAX_SUMMARY_BYTES, notes):
                handle.write(summary_text(line) + "\n")
    except OSError as exc:
        problems.append("cannot write summary %s: %s"
                        % (clean(github_summary_path).text, exc.strerror or type(exc).__name__))


def run(argv):
    args = build_parser().parse_args(argv)
    reset_counters()
    try:
        load_redaction()
    except Exception as exc:
        notice("cannot load redaction module: " + type(exc).__name__)
        return EXIT_OK
    problems = []
    if not args.paths:
        problems.append(NO_PATHS_REASON)
    findings = scan(args.paths, problems)
    items = annotation_items(findings)
    total = findings.binary_count + findings.test_count
    cause = None if total else name_cause(args.step, problems)
    lines = summary_lines(findings, cause)
    notes = summary_notes(findings)
    shown = items[:MAX_ANNOTATIONS]
    omitted = None
    if total > len(shown):
        omitted = ("annotations: %d of %d findings printed (limit %d), %d omitted"
                   % (len(shown), total, MAX_ANNOTATIONS, total - len(shown)))
        notes.append(omitted)
    write_summary(lines, problems, notes + counter_notes())
    for title, message in shown:
        print(wa.annotation("error", message, max_chars=ANNOTATION_MAX_CHARS, title=title), flush=True)
    if cause is not None and cause[1]:
        print(wa.annotation("error", cause[0].text, max_chars=ANNOTATION_MAX_CHARS, title=TITLE_CAUSE), flush=True)
    if omitted is not None:
        notice(omitted)
    if problems:
        notice(problems[0] if len(problems) == 1 else "%s (and %d more problems)" % (problems[0], len(problems) - 1))
    elif not total and cause is None:
        notice(NO_FINDINGS_NOTICE % findings.files_read)
    elif not total and not cause[1]:
        notice(cause[0].text)
    return EXIT_OK


def main(argv=None):
    try:
        return run(sys.argv[1:] if argv is None else argv)
    except UsageProblem as exc:
        try:
            load_redaction()
        except Exception:
            pass  # clean() then yields the fixed marker, never the raw text
        notice("usage error: " + clean(str(exc)).text)
    except Exception as exc:  # the step never fails the job: one notice with the exact reason
        notice("internal error: " + describe(exc))
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
