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
line.

The parser (#9831) reads libtest output in one pass, linear in the input, as a state machine per binary section:

* a section opens only on cargo's exact shapes, anchored on the whole line (trailing blanks aside):
  ``     Running <source> (<path>)`` (five spaces, no backtick or parenthesis in either part) or
  ``   Doc-tests <crate>`` (three spaces, one identifier).  Before the first such line nothing is read; there is no
  implicit section.
* PROGRESS, from the section line to the first column-0 ``failures:`` line: failing test names come only from the
  runner's own progress lines, the whole line ``test <name> ... FAILED`` (mode suffixes `` - should panic``,
  `` - compile fail``, `` - compile`` removed); the result is the last column-0 ``test result:`` line, a FAILED
  one winning; a ``process didn't exit successfully`` line is the crash detail.
* OPAQUE, from that ``failures:`` line on: the captured output of the failing tests and the failures list.  Nothing
  in it is read as a name, a list, a section label, a ``Running`` line or a crash detail; only column-0 ``test
  result:`` lines count, the last one kept with a FAILED one winning, and it replaces the progress result when the
  section closes.  The region has no exit inside the input (any "this line ends the capture" rule can be forged by
  the captured text itself), so it runs to the end of the input file: a later section of the same file
  (``--no-fail-fast``) is not read (#9870).  A section line after a kept FAILED result of the region does end its
  attribution: no later block's result line is ever this section's (#9870, the misattribution half).
* At its close a section gives at most one binary row: a FAILED result commits the section's progress names and is
  the row; a FAILED result without a name is ``failed, names not available; <result line>``, and so is an ``ok``
  result inside OPAQUE (a failures block with a passing verdict); no result is ``ended without a test result line
  (crash, timeout or signal)`` with the first crash detail; a crash detail after a passing result line is
  ``crashed after a passing test result line; <detail>``.

So no byte of captured test output can add a failing binary, a failing test name or a section, or change a count.
The residual: text a test prints under ``--nocapture`` or ``--show-output`` lands in PROGRESS, so no workflow may pass
either (CaptureResidual pins it).

Shown text (#9830): every value from a log, a path or an exception reaches the output only as a ``Redacted``, which
one funnel makes: ``redact_shown()``.  A raw line over PRE_CAP_BYTES is never redacted or shown: it is the fixed
marker ``<line not shown: N bytes>``.  Otherwise the WHOLE line goes through the redaction of
``scripts/cert_gate_evidence.py`` (a raising redaction yields ``<redaction failed>``, never the raw text; at most
REDACTION_BUDGET_CALLS calls per run, then ``<redaction budget spent>``), then the cut: over MAX_LINE_BYTES the
redacted text is cut on a character boundary and ``...`` marks it, and every cut is counted (``shown values cut:
N``).  Format characters (Unicode Cf, bidi controls among them) are then shown as ``\\uXXXX``, so a shown value can
be longer than MAX_LINE_BYTES.  The cut and every writer (``md_cell``, ``notice``, ``compose``) refuse a plain str,
and the tests keep the slice, cut and funnel sites as allowlists.  With ``SHOW_LOG_TEXT = False`` (the pre-armed
split) no text taken from a log is shown at all: binaries and tests are numbered, reasons are fixed texts and the
step cause names the step only.  Counting and de-duplication run on the raw values, so N failing tests always print
``failing tests: N``.

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
MAX_LINE_BYTES = 300  # bytes of one shown value after the redaction; the rest is cut, marked and counted
PRE_CAP_BYTES = 400  # bytes of one raw value that is redacted at all; a longer one is a fixed marker, never shown
MAX_SUMMARY_BYTES = 32768  # bytes of the summary this step appends, escapes included
MAX_ANNOTATIONS = 10  # ::error lines (GitHub shows 10 per step)
MAX_FILE_BYTES = 16 * 1024 * 1024  # bytes read per input file: the whole file, or its last MAX_FILE_BYTES
MAX_INPUT_FILES = 64  # input files read
MAX_WALK_ENTRIES = 10000  # directory entries looked at per directory argument
MAX_TOTAL_BYTES = 64 * 1024 * 1024  # bytes read over all input files
REDACTION_BUDGET_CALLS = 256  # redaction calls per run: shown values only (2 x 50 rows, 50 tests, the rest)
SUMMARY_OMIT_RESERVE = 160  # bytes kept free for the omission line of a summary over its bound
# An annotation line is never cut by the shared module: two shown values of MAX_LINE_BYTES, each byte at most
# 7/3 characters after the Cf escape and the shared escape, plus the title, fit.
ANNOTATION_MAX_CHARS = 4000

# Fixed texts and templates.  Every shown text is one of these, filled only with Redacted parts or ints by compose().
NO_RESULT_REASON = "ended without a test result line (crash, timeout or signal)"
NO_RESULT_DETAIL = NO_RESULT_REASON + "; %s"
CRASH_AFTER_OK_REASON = "crashed after a passing test result line; "
CRASH_AFTER_OK_DETAIL = CRASH_AFTER_OK_REASON + "%s"
NAMES_NOT_AVAILABLE = "failed, names not available"
NAMES_NOT_AVAILABLE_REASON = NAMES_NOT_AVAILABLE + "; %s"
NO_PATHS_REASON = "no input paths given"
EMPTY_PATH_REASON = "input path is empty"
NO_SUMMARY_FILE_REASON = "GITHUB_STEP_SUMMARY is not set, summary not written"
NOT_IDENTIFIED = "cause not identified"
NO_FINDINGS_NOTICE = NOT_IDENTIFIED + "; no failing test or test binary found in %d input file(s)"
LAST_STEP_CAUSE = NOT_IDENTIFIED + "; failing step: %s (the last step whose log exists)"
NO_STEP_CAUSE = NOT_IDENTIFIED + "; failing step: a step before %s (no step log exists)"
STEP_NOT_REGULAR = "step log %s is not a regular file (NotRegular)"
STEP_UNREADABLE = "cannot read step log %s: %s (%s)"
STEP_CAUSE = "%s: %s"
CAUSE_PREFIX = "last error line (a candidate cause): "
INPUT_NOT_REGULAR = "input %s is not a regular file"
INPUT_UNREADABLE = "cannot read input %s: %s"
SUMMARY_UNWRITABLE = "cannot write summary %s: %s"
USAGE_ERROR = "usage error: %s"
INTERNAL_ERROR = "internal error: %s"
LOAD_FAILED = "cannot load redaction module: %s"
PROBLEMS_MORE = "%s (and %d more problems)"
ANNOTATIONS_OMITTED = "annotations: %d of %d findings printed (limit %d), %d omitted"
BASE_EXCEPTION_NAME = "BaseException"
REDACTION_FILE = "cert_gate_evidence.py"
REDACTION_FAILED = "<redaction failed>"
REDACTION_SPENT = "<redaction budget spent>"
LINE_NOT_SHOWN = "<line not shown: %d bytes>"
LABEL_NOT_SHOWN = "<binary name not shown>"
SUMMARY_ENV = "GITHUB_STEP_SUMMARY"
CUT_MARK = "..."

# The pre-armed split (#9830): False shows no text taken from a log, only counts, numbers and step names.
SHOW_LOG_TEXT = True
BINARY_N = "binary %d"
TEST_N = "test %d"
HIDDEN_FAILED = "failed"
HIDDEN_NO_RESULT = "no result line (crash, timeout or signal)"
HIDDEN_CRASH_AFTER_OK = "crashed after a passing result line"

NOTICE_TITLE = "red cause summary"
TITLE_BINARY = "failing test binary"
TITLE_TEST = "failing test"
TITLE_CAUSE = "red cause"

# UTF-8 continuation bytes are 10xxxxxx; a character has at most 3 of them, so a cut backs up at most 3 bytes.
UTF8_CONTINUATION_MASK = 0xC0
UTF8_CONTINUATION_TAG = 0x80
UTF8_MAX_BACKUP = 3
RESULT_PREFIX = "test result:"
RESULT_FAILED_PREFIX = "test result: FAILED"
FAILURES_HEADER = "failures:"
# The runner's own progress line of a failing test, matched on the whole line.
FAILED_LINE = re.compile(r"test (.*) \.\.\. FAILED\Z")
# cargo's exact section lines, matched on the whole line after its trailing blanks are removed.
RUNNING_LINE = re.compile(r"     Running ([^`()\s][^`()]*?) \(([^`()\s]+)\)\Z")
DOC_TESTS_LINE = re.compile(r"   Doc-tests ([A-Za-z_][A-Za-z0-9_-]*)\Z")
# The hash of a binary path at the end of a section line, removed before the line is redacted (it is no secret,
# and a 16-hex run would otherwise be masked with the binary name).
LINE_HASH = re.compile(r"-[0-9a-f]{8,}(?=\)\Z)")
# A label read from a redacted section line whose path the redaction masked: the source file name, when plain.
SOURCE_LABEL = re.compile(r"     Running tests/([a-z_][a-z0-9_]*)\.rs ")
# A binary name shown as written when the redaction itself failed: short and plain, no token can have this shape.
PLAIN_LABEL = re.compile(r"[a-z_][a-z0-9_]{0,30}")
MODE_SUFFIX = re.compile(r" - (?:should panic|compile fail|compile)\Z")
DOC_TESTS_LABEL = "doc-tests "
UNITTESTS_PREFIX = "unittests "
LIB_SOURCE = "src/lib.rs"
CRASH_MARKER = "process didn't exit successfully"
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

FUNNEL_ONLY = "Redacted is made only by redact_shown(), compose() or fixed()"
NEEDS_STR = "redact_shown takes a str"
NEEDS_REDACTED = "a shown value must be a Redacted"
NEEDS_PART = "a template part must be a Redacted or an int"


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


class Redacted:
    """Text that is safe to show: made only by the funnel (redact_shown, compose, fixed); every writer and the cut
    refuse anything else (#9830).  The error texts are fixed, so a refusal never carries the refused value."""

    __slots__ = ("text",)

    def __init__(self, text, key=None):
        if key is not _MINT or not isinstance(text, str):
            raise TypeError(FUNNEL_ONLY)
        self.text = text


def require_redacted(*values):
    for value in values:
        if type(value) is not Redacted:
            raise TypeError(NEEDS_REDACTED)


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


def cut_bytes(text, limit):
    """``text`` cut to at most ``limit`` UTF-8 bytes without splitting a character: a cut that falls inside a
    multi-byte character backs up to that character's first byte, so nothing cut decodes to U+FFFD."""
    data = text.encode("utf-8", "replace")
    if len(data) <= limit:
        return text
    for _ in range(UTF8_MAX_BACKUP):
        if limit > 0 and data[limit] & UTF8_CONTINUATION_MASK == UTF8_CONTINUATION_TAG:
            limit -= 1
    return data[:limit].decode("utf-8", "replace")


def cut_redacted(value):
    """The one cut: a Redacted over MAX_LINE_BYTES cut on a character boundary, marked with ``...`` and counted."""
    global _shown_cuts
    if type(value) is not Redacted:
        raise TypeError(NEEDS_REDACTED)
    if len(value.text.encode("utf-8", "replace")) <= MAX_LINE_BYTES:
        return value
    _shown_cuts += 1
    return Redacted(cut_bytes(value.text, MAX_LINE_BYTES - len(CUT_MARK)) + CUT_MARK, _MINT)


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


def redact_shown(raw):
    """The one funnel from raw text to shown text: a raw value over PRE_CAP_BYTES is a fixed marker with its size
    (counted); else the whole value is redacted, then cut to MAX_LINE_BYTES, then its format characters made
    visible.  A failing or spent redaction yields a fixed marker, never the raw text."""
    global _redaction_calls, _shown_cuts, _budget_spent
    if not isinstance(raw, str):
        raise TypeError(NEEDS_STR)
    if _redact_line is None:
        return Redacted(REDACTION_FAILED, _MINT)
    size = len(raw.encode("utf-8", "replace"))
    if size > PRE_CAP_BYTES:
        _shown_cuts += 1
        return Redacted(LINE_NOT_SHOWN % size, _MINT)
    if _redaction_calls >= REDACTION_BUDGET_CALLS:
        _budget_spent += 1
        return Redacted(REDACTION_SPENT, _MINT)
    _redaction_calls += 1
    try:
        redacted = _redact_line(raw)
    except Exception:
        return Redacted(REDACTION_FAILED, _MINT)
    if not isinstance(redacted, str):
        return Redacted(REDACTION_FAILED, _MINT)
    shown = cut_redacted(Redacted(redacted, _MINT))
    return Redacted(visible(shown.text), _MINT)


def shown_arg(text):
    """A path, a step name, an error text or a type name to show: through the funnel."""
    return redact_shown(text)


def compose(template, *parts):
    """``template`` (a fixed text) filled with Redacted parts and ints only."""
    texts = []
    for part in parts:
        if type(part) is Redacted:
            texts.append(part.text)
        elif type(part) is int:
            texts.append(part)
        else:
            raise TypeError(NEEDS_PART)
    return Redacted(template % tuple(texts), _MINT)


def fixed(text):
    """A fixed text of this script as a Redacted."""
    return Redacted(text, _MINT)


def type_name(exc):
    """The type name of an exception to show without the redaction: an identifier, else a fixed name."""
    name = type(exc).__name__
    if name.isidentifier():
        return Redacted(name, _MINT)
    return fixed(BASE_EXCEPTION_NAME)


def md_cell(value):
    """A Redacted for a Markdown table cell: format characters visible, no HTML, no pipe, no emphasis, no backtick,
    no link bracket, no heading or issue reference, no autolink, mention or commit link."""
    require_redacted(value)
    text = visible(value.text)
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
    a backslash, controls, line separators and surrogates are escaped.  Every value in ``line`` came through
    md_cell or compose; this is the file escape only."""
    return SUMMARY_ESCAPE.sub(summary_char, line)


def binary_label(source, path):
    """The binary of a ``Running`` line: the file name of its path without the hash; a unittests binary of a source
    other than src/lib.rs (a bin target) carries its source."""
    name = path.rsplit("/", 1)[-1]
    label = HASH_SUFFIX.sub("", name) or path
    if source.startswith(UNITTESTS_PREFIX) and source.removeprefix(UNITTESTS_PREFIX) != LIB_SOURCE:
        label = "%s (%s)" % (label, source.removeprefix(UNITTESTS_PREFIX))
    return label


def is_section_line(line):
    """True when ``line`` (colour and trailing blanks removed) is one of cargo's exact section lines."""
    return RUNNING_LINE.match(line) is not None or DOC_TESTS_LINE.match(line) is not None


def section_label(raw_line):
    """The shown binary label of a section line: the line without its path hash is redacted whole, and the label is
    read from the redacted text; a plain identifier name when the redaction failed or is spent; else a fixed
    marker."""
    raw_line = LINE_HASH.sub("", raw_line)
    shown = redact_shown(raw_line)
    match = RUNNING_LINE.match(shown.text)
    if match is not None:
        return Redacted(binary_label(match.group(1), match.group(2)), _MINT)
    match = DOC_TESTS_LINE.match(shown.text)
    if match is not None:
        return Redacted(DOC_TESTS_LABEL + match.group(1), _MINT)
    if shown.text in (REDACTION_FAILED, REDACTION_SPENT):
        match = RUNNING_LINE.match(raw_line)
        if match is not None:
            name = binary_label(match.group(1), match.group(2))
            if PLAIN_LABEL.fullmatch(name):
                return Redacted(name, _MINT)
    match = SOURCE_LABEL.match(shown.text)
    if match is not None:
        return Redacted(match.group(1), _MINT)
    return fixed(LABEL_NOT_SHOWN)


def progress_name(raw_line):
    """The shown name of a progress line: the whole line redacted, the name read from the redacted text; the whole
    redacted line when the redaction changed its shape."""
    shown = redact_shown(raw_line)
    match = FAILED_LINE.fullmatch(shown.text)
    if match is not None:
        return Redacted(test_name(match.group(1)), _MINT)
    return shown


def test_name(text):
    """A libtest name without its padding and mode suffix (`` - should panic``, `` - compile fail``, ``- compile``)."""
    return MODE_SUFFIX.sub("", text.strip()).rstrip()


def raw_key(*parts):
    return hashlib.blake2b(b"\x00".join(part.encode("utf-8", "replace") for part in parts), digest_size=16).digest()


class Findings:
    """What the parse found: failing binaries, failing tests, and the exact counts of every cut.  Keys and counts are
    raw values; the shown values are made only for the rows listed, and only Redacted values are stored."""

    def __init__(self):
        self.binaries = []  # (Redacted binary, Redacted reason): the first MAX_FAILING_BINARIES only
        self.binary_count = 0  # every distinct failing binary row
        self.binary_keys = set()
        self.tests = []  # (Redacted binary, Redacted name): the first MAX_FAILING_TESTS only
        self.test_count = 0  # every distinct failing test
        self.test_keys = set()
        self.sections = 0  # sections opened, numbering the binaries when SHOW_LOG_TEXT is False
        self.files_read = 0
        self.cut_lines = 0
        self.truncated_files = []  # (Redacted name, size)
        self.unparsed_files = []  # Redacted names of truncated files whose tail holds no complete line
        self.files_found = 0
        self.walks_over = []  # Redacted directory arguments whose walk hit MAX_WALK_ENTRIES
        self.files_over_budget = 0

    def note_binary(self, key, show):
        """Count a failing binary row once; ``show()`` makes its (binary, reason) only when it is listed."""
        if key in self.binary_keys:
            return
        self.binary_keys.add(key)
        self.binary_count += 1
        if len(self.binaries) < MAX_FAILING_BINARIES:
            shown_binary, shown_reason = show()
            require_redacted(shown_binary, shown_reason)
            self.binaries.append((shown_binary, shown_reason))

    def note_test(self, key, show):
        """Count a failing test once; ``show()`` makes its (binary, name) only when it is listed."""
        if key in self.test_keys:
            return
        self.test_keys.add(key)
        self.test_count += 1
        if len(self.tests) < MAX_FAILING_TESTS:
            shown_binary, shown_name = show()
            require_redacted(shown_binary, shown_name)
            self.tests.append((shown_binary, shown_name))


class Section:
    """One binary section of one file while it is parsed; every field holds the raw value."""

    __slots__ = ("raw", "number", "label", "opaque", "result_raw", "failed", "opaque_result", "opaque_closed",
                 "crash_raw", "crash_after_ok", "names")

    def __init__(self, raw, number):
        self.raw = raw  # the section line (colour and trailing blanks removed)
        self.number = number
        self.label = None  # the shown label, made once when a row of this section is listed
        self.opaque = False  # True from the first column-0 failures: line to the end of the input
        self.result_raw = None  # the kept test result line
        self.failed = False  # the kept result line is FAILED
        self.opaque_result = False  # the kept result line came from the opaque region
        self.opaque_closed = False  # a section line after a kept opaque FAILED result: later result lines are not ours
        self.crash_raw = None  # the crash detail: the first before any result, or the first after a passing one
        self.crash_after_ok = False
        self.names = []  # the progress lines of failing tests, whole

    def shown_label(self):
        if self.label is None:
            self.label = section_label(self.raw) if SHOW_LOG_TEXT else compose(BINARY_N, self.number)
        return self.label


def close_section(section, findings):
    """The one row (at most) of a section, and its failing tests, when the section ends."""
    if section is None:
        return
    if section.result_raw is not None and section.failed and section.names:
        for line in section.names:
            findings.note_test(raw_key(section.raw, line), lambda line=line: (
                section.shown_label(),
                progress_name(line) if SHOW_LOG_TEXT else compose(TEST_N, findings.test_count)))
        kind = "failed"
        show = (lambda: redact_shown(section.result_raw)) if SHOW_LOG_TEXT else (lambda: fixed(HIDDEN_FAILED))
    elif section.result_raw is not None and (section.failed or section.opaque_result):
        kind = "names"
        show = ((lambda: compose(NAMES_NOT_AVAILABLE_REASON, redact_shown(section.result_raw))) if SHOW_LOG_TEXT
                else (lambda: fixed(NAMES_NOT_AVAILABLE)))
    elif section.result_raw is None:
        kind = "none"
        if not SHOW_LOG_TEXT:
            show = lambda: fixed(HIDDEN_NO_RESULT)  # noqa: E731
        elif section.crash_raw is None:
            show = lambda: fixed(NO_RESULT_REASON)  # noqa: E731
        else:
            show = lambda: compose(NO_RESULT_DETAIL, redact_shown(section.crash_raw))  # noqa: E731
    elif section.crash_after_ok:
        kind = "after-ok"
        show = ((lambda: compose(CRASH_AFTER_OK_DETAIL, redact_shown(section.crash_raw))) if SHOW_LOG_TEXT
                else (lambda: fixed(HIDDEN_CRASH_AFTER_OK)))
    else:
        return
    reason_raw = section.result_raw if kind in ("failed", "names") else (section.crash_raw or "")
    findings.note_binary(raw_key(section.raw, kind, reason_raw), lambda: (section.shown_label(), show()))


def read_line(raw):
    if not raw.endswith(b"\r"):
        return raw
    return raw[:-1]


def parse_data(data, findings):
    """Parse the bytes of one input file into ``findings``: one pass, linear in the input size."""
    section = None
    for raw in data.split(b"\n"):
        raw = read_line(raw)
        if len(raw) > MAX_LINE_BYTES:
            findings.cut_lines += 1
        line = ANSI.sub("", raw.decode("utf-8", "replace")).rstrip()
        if section is not None and section.opaque:
            # The captured output and the failures list: only result lines count, nothing else is read.  A FAILED
            # one is kept over any later passing one (as before the header), so no line here turns a red section green.
            # A section line after a kept FAILED result of this region starts a later block of a --no-fail-fast log:
            # no result line after it is this section's (#9870; its rows stay unread here).  Before that a section
            # line is captured output, so it closes nothing and cannot drop the section's own FAILED result (a forged
            # passing result before it would otherwise hide the own one and drop the failing names).
            if section.opaque_result and section.failed and is_section_line(line):
                section.opaque_closed = True
            elif (not section.opaque_closed and line.startswith(RESULT_PREFIX)
                  and (line.startswith(RESULT_FAILED_PREFIX) or not section.failed)):
                section.result_raw = line
                section.failed = line.startswith(RESULT_FAILED_PREFIX)
                section.opaque_result = True
            continue
        if is_section_line(line):
            close_section(section, findings)
            findings.sections += 1
            section = Section(line, findings.sections)
            continue
        if section is None:  # no implicit section: nothing before cargo's first section line is read
            continue
        if line == FAILURES_HEADER:
            section.opaque = True
        elif line.startswith(RESULT_PREFIX):
            if line.startswith(RESULT_FAILED_PREFIX):
                section.result_raw = line
                section.failed = True
            elif not section.failed:
                section.result_raw = line
        elif FAILED_LINE.fullmatch(line):
            section.names.append(line)
        elif CRASH_MARKER in line:
            if section.result_raw is None and section.crash_raw is None:
                section.crash_raw = line.strip()
            elif section.result_raw is not None and not section.failed and not section.crash_after_ok:
                section.crash_raw = line.strip()
                section.crash_after_ok = True
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
        newline = data.find(b"\n")
        data = data[newline + 1:] if newline >= 0 else b""
    return data, info.st_size, truncated


def error_text(exc):
    """The OS error text of ``exc``, else its type name (raw: it goes through shown_arg)."""
    return exc.strerror or type(exc).__name__


def input_problem(path, exc):
    """The exact reason for an input that cannot be read."""
    if isinstance(exc, NotRegular):
        return compose(INPUT_NOT_REGULAR, shown_arg(str(path)))
    return compose(INPUT_UNREADABLE, shown_arg(str(path)), shown_arg(error_text(exc)))


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
            findings.walks_over.append(shown_arg(str(top)))
            return files
        stack.extend(os.path.join(root, name) for name in sorted(dirs, reverse=True))
    return files


def collect_inputs(paths, problems, findings):
    """The input files in argument order; a directory contributes its ``*.log`` files below it, sorted."""
    files = []
    for path in paths:
        if path == "":
            problems.append(fixed(EMPTY_PATH_REASON))
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
    chosen = min(len(files), MAX_INPUT_FILES)
    for index, path in enumerate(files):
        if index == chosen:
            break
        try:
            data, size, truncated = read_input(path, budget)
        except OverBudget:
            findings.files_over_budget = chosen - index
            break
        except (OSError, NotRegular) as exc:
            problems.append(input_problem(path, exc))
            continue
        budget -= len(data)
        findings.files_read += 1
        if truncated and not data:
            findings.unparsed_files.append(shown_arg(os.path.basename(path)))
            continue
        if truncated:
            findings.truncated_files.append((shown_arg(os.path.basename(path)), size))
        parse_data(data, findings)
    return findings


def last_error_line(data):
    """The last ``error[``/``error:`` line of a step log (colour removed), redacted whole, or None."""
    raw_line = None
    for chunk in data.split(b"\n"):
        text = ANSI.sub("", read_line(chunk).decode("utf-8", "replace")).strip()
        if text.startswith(ERROR_LINE_PREFIXES):
            raw_line = text
    if raw_line is None:
        return None
    return redact_shown(raw_line)


def name_cause(steps, problems):
    """(Redacted cause, named) for a red job with no failing test: the last error line of the failing step (the
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
        return compose(NO_STEP_CAUSE, shown_arg(steps[0][1])), False
    log, name, mode = failing
    unnamed = compose(LAST_STEP_CAUSE, shown_arg(name)), False
    if not stat.S_ISREG(mode):
        problems.append(compose(STEP_NOT_REGULAR, shown_arg(log)))
        return unnamed
    try:
        data, _size, _truncated = read_input(log, MAX_FILE_BYTES)
    except NotRegular:
        problems.append(compose(STEP_NOT_REGULAR, shown_arg(log)))
        return unnamed
    except OSError as exc:
        problems.append(compose(STEP_UNREADABLE, shown_arg(log), shown_arg(error_text(exc)),
                                shown_arg(type(exc).__name__)))
        return unnamed
    if not SHOW_LOG_TEXT:
        return unnamed
    error = last_error_line(data)
    if error is None:
        return unnamed
    return compose(STEP_CAUSE, shown_arg(name), error), True


def summary_lines(findings, cause):
    """The summary as lines (escaped when written); counts are exact and come from the full lists."""
    lines = ["**Red cause (%s)**" % ISSUE]
    if not findings.binary_count and not findings.test_count:
        if cause is None:
            lines.append(md_cell(compose(NO_FINDINGS_NOTICE, findings.files_read)))
        else:
            shown, named = cause
            lines.append((CAUSE_PREFIX if named else "") + md_cell(shown))
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
    items = [(TITLE_BINARY, compose(STEP_CAUSE, binary, reason).text) for binary, reason in findings.binaries]
    items.extend((TITLE_TEST, compose(STEP_CAUSE, binary, name).text) for binary, name in findings.tests)
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
    """One ``::notice`` line of a Redacted reason."""
    require_redacted(reason)
    print(wa.annotation("notice", reason.text, title=NOTICE_TITLE), flush=True)


def describe(exc):
    """``Type: text`` of an exception through the funnel; the type alone when the redaction is unavailable."""
    if _redact_line is None:
        return type_name(exc)
    text = type(exc).__name__ + ": " + str(exc)
    return redact_shown(text)


def write_summary(lines, problems, notes=()):
    """Append the fitted summary to the file named by GITHUB_STEP_SUMMARY."""
    github_summary_path = os.environ.get(SUMMARY_ENV, "")
    if not github_summary_path:
        problems.append(fixed(NO_SUMMARY_FILE_REASON))
        return
    try:
        with open(github_summary_path, "a", encoding="utf-8") as handle:
            for line in fit_lines(lines, MAX_SUMMARY_BYTES, notes):
                handle.write(summary_text(line) + "\n")
    except OSError as exc:
        problems.append(compose(SUMMARY_UNWRITABLE, shown_arg(github_summary_path), shown_arg(error_text(exc))))


def run(argv):
    args = build_parser().parse_args(argv)
    reset_counters()
    try:
        load_redaction()
    except Exception as exc:
        notice(compose(LOAD_FAILED, type_name(exc)))
        return EXIT_OK
    problems = []
    if not args.paths:
        problems.append(fixed(NO_PATHS_REASON))
    findings = scan(args.paths, problems)
    items = annotation_items(findings)
    total = findings.binary_count + findings.test_count
    cause = None if total else name_cause(args.step, problems)
    lines = summary_lines(findings, cause)
    notes = summary_notes(findings)
    printed = min(len(items), MAX_ANNOTATIONS)
    omitted = None
    if total > printed:
        omitted = compose(ANNOTATIONS_OMITTED, printed, total, MAX_ANNOTATIONS, total - printed)
        notes.append(omitted.text)
    write_summary(lines, problems, notes + counter_notes())
    for index, (title, message) in enumerate(items):
        if index == printed:
            break
        print(wa.annotation("error", message, max_chars=ANNOTATION_MAX_CHARS, title=title), flush=True)
    if cause is not None and cause[1]:
        print(wa.annotation("error", cause[0].text, max_chars=ANNOTATION_MAX_CHARS, title=TITLE_CAUSE), flush=True)
    if omitted is not None:
        notice(omitted)
    if problems:
        notice(problems[0] if len(problems) == 1 else compose(PROBLEMS_MORE, problems[0], len(problems) - 1))
    elif not total and cause is None:
        notice(compose(NO_FINDINGS_NOTICE, findings.files_read))
    elif not total and not cause[1]:
        notice(cause[0])
    return EXIT_OK


def main(argv=None):
    if argv is None:
        argv = list(sys.argv)
        del argv[0]  # the program name (an index, so the slice allowlist stays the three framing sites)
    try:
        return run(argv)
    except UsageProblem as exc:
        try:
            load_redaction()
        except Exception:
            pass  # the funnel then yields the fixed marker, never the raw text
        notice(compose(USAGE_ERROR, shown_arg(str(exc))))
    except Exception as exc:  # the step never fails the job: one notice with the exact reason
        notice(compose(INTERNAL_ERROR, describe(exc)))
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
