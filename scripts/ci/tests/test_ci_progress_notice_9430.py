#!/usr/bin/env python3
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""Pin the shard progress notice of ci.yml against workflow-command injection (#9430, class of #9365).

Class: text a pull request controls (the last line of a shard test log) is echoed into a runner
workflow-command line. A line break inside that text ends the notice and the runner parses the rest as a
new command made of pull-request data (``::warning::``, ``::add-mask::``, ``::stop-commands::``, ``##[...]``).

Invariant for all inputs: whatever the three shard log paths hold (any bytes, any size, a missing or unreadable file,
a directory, a FIFO, a device), the progress heartbeat writes exactly one line the runner can parse as a command,
never blocks and never ends the loop; the line starts with the fixed ``::notice::`` prefix, holds no ``%`` (nothing
the runner percent-decodes), and after one unescape of the ``scripts/ci/workflow_annotation.py`` escapes each data
field equals, byte for byte, the bounded last line of its log cut to CUT_BYTES (``bounded_field``):

- the reader reads back at most READ_BOUND bytes from the end of a regular file (opened ``rb`` with ``O_NONBLOCK``,
  ``fstat`` + ``S_ISREG`` on the open file; anything else is an empty field);
- last line = the bytes after the last line feed that is not the final byte; when the line starts inside the window
  (or the window starts at byte 0) the field is its first CUT_BYTES bytes, otherwise (the window holds no line feed
  before the final byte) the field is the last CUT_BYTES bytes of the window, its final line feed dropped;
- NUL, CR and every other byte are kept and escaped (no shell command substitution is on the path any more).

The oracle is computed in Python from the whole log bytes (``bounded_field``), never by a host tool, and every
heartbeat cell runs with a PATH that holds only ``python3``, so the notice cannot depend on a host text tool. The
host text tools met while this class was open (#9430, each named with its evidence line):

- GNU coreutils on f2: ``tail (GNU coreutils) 9.4`` / ``cut (GNU coreutils) 9.4``; ``tail -n 1`` returned every probe
  case whole and ``cut -c`` cut bytes in every locale.
- uutils coreutils on the ubuntu-26.04 runner image: ``tail (uutils coreutils) 0.10.0`` / ``cut (uutils coreutils)
  0.10.0``; ``tail -n 1`` of a one-line file of exactly 65536 bytes printed 0 bytes and of a 1 MiB one-line file with
  no final newline 983040 bytes; ``printf 'aaaa\\xc3\\xa9z\\n' | LC_ALL=C.UTF-8 cut -c1-5`` printed
  ``a a a a 303 251`` (characters, not bytes).
- BSD text_cmds on f1 (macOS 27.0.1): ``what /usr/bin/cut`` -> ``PROGRAM:cut  PROJECT:text_cmds-199`` (tail the same
  project); ``printf 'aaaa\\303\\251z\\n' | LC_ALL=en_US.UTF-8 cut -c1-5`` printed ``a a a a é`` (characters);
  ``tail -n 1`` of a one-line 65536-byte file printed 65536 bytes.

Host-tool differences found, the reason the notice reads the logs itself (conductor word a3ff9997):

=============================  ==========================  =============================================================
difference                     implementation              evidence line
=============================  ==========================  =============================================================
``cut -c`` cuts characters     uutils 0.10.0 (runner)      ``printf 'aaaa\\xc3\\xa9z\\n' | LC_ALL=C.UTF-8 cut -c1-5`` ->
                                                           ``a a a a 303 251`` (6 bytes, not 5)
``cut -c`` cuts characters     BSD text_cmds-199 (f1)      ``printf 'aaaa\\303\\251z\\n' | LC_ALL=en_US.UTF-8 cut -c1-5`` ->
                                                           ``a a a a é``
``tail -n 1`` loses bytes      uutils 0.10.0 (runner)      one-line 65536-byte file -> 0 bytes; 1 MiB one-line file, no
at 64 KiB                                                  final newline -> 983040 bytes
=============================  ==========================  =============================================================

``test_9430_fix_no_host_text_tool_between_call_and_args`` holds that the step text from the ``python3 -I`` call to the
end of its arguments names no host text tool; the 90-byte cut is the named constant CUT_BYTES inside the python call.

The test reads ci.yml with the strict standard-library reader of workflow_text.py (#9813; it refuses what it
cannot parse, naming the line, and needs no PyYAML), takes the
``run`` text of the one step that holds the ``[#6344] progress`` heartbeat, cuts the body of its
``( while true; do ... done ) &`` loop (without the ``sleep``) and runs that body with bash against synthetic
logs in a scratch directory. Lines are split with ``str.splitlines`` (a superset of the runner's CR / LF /
CRLF split); a line is a command when it starts with ``::`` after leading whitespace (runner TryParseV2) or
holds ``##[`` anywhere (runner TryParse).

Byte class (cells a-c, the generative cell, under the C.UTF-8, C, POSIX, unset and a Latin-1 locale): every byte
string of a log tail gives exit 0, an empty stderr and exactly one valid UTF-8 ``::notice::`` line; a byte that is
not part of a whole UTF-8 character shows as the escape ``\\udcXX``. Cell d runs the step's own heartbeat lines under
the step's shell options (``bash --noprofile --norc -eo pipefail`` + ``set -euo pipefail``) once per failure form of
the notice command (python3 exits 1, is killed by a signal, is missing, stderr is closed, stdout is closed) and asserts
the loop keeps going, the step's exit code is unchanged and the fallback writes to stderr only, never a command. The
lifecycle cells count loop passes with the stubbed ``sleep`` (one per pass), with only stubs on PATH.

Fix-r1 cells: the exact heartbeat text (one ``python3 -I -c`` call whose argv is the three log paths, the named read
bound and cut constants, ``rb`` + ``O_NONBLOCK`` + ``S_ISREG``, ``scripts/ci`` the only added path, no host text tool,
the fallback that cannot fail); hostile ``tail`` / ``cut`` / ``sed`` / ... stubs first on PATH are never run; the
reader cells (sizes 0, 1, 65535-65537, READ_BOUND - 1 .. + 1, 1 MiB, each with and without a final line feed; missing,
unreadable, FIFO with and without a writer, directory, character device, a log that grows between ticks,
CRLF, a ``::error::`` line, NUL bytes, a cut inside a multi-byte sequence at either end, a sparse 2 GiB log under an
address-space ceiling, which the kernel may not apply on macOS); planted ``sitecustomize``, ``usercustomize``, ``os`` and ``workflow_annotation`` modules on
PYTHONPATH, in the user site and in the working directory that ``-I`` keeps out; the exact worst-case line length.

Run: python3 -m unittest scripts/ci/tests/test_ci_progress_notice_9430.py
"""

import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

import importlib.util
import resource
import signal
import stat

REPO = Path(__file__).resolve().parents[3]
WORKFLOW_TEXT = Path(__file__).resolve().parent / "workflow_text.py"
CI_YML = REPO / ".github" / "workflows" / "ci.yml"
SCRATCH_PARENT = REPO / ".local-runs"
WORKFLOW_ANNOTATION = REPO / "scripts" / "ci" / "workflow_annotation.py"
WORKFLOW_ANNOTATION_REL = Path("scripts") / "ci" / "workflow_annotation.py"


def load_workflow_annotation():
    """The repository's workflow_annotation module, loaded from its file (sys.path and sys.modules untouched)."""
    spec = importlib.util.spec_from_file_location("workflow_annotation_9430_oracle", WORKFLOW_ANNOTATION)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def load_workflow_text():
    """The shared strict workflow reader (#9813), loaded from its file (sys.path untouched)."""
    spec = importlib.util.spec_from_file_location("workflow_text_9430_reader", WORKFLOW_TEXT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


wa = load_workflow_annotation()
wt = load_workflow_text()

HEARTBEAT_MARKER = "[#6344] progress"
LOOP_OPEN = "( while true; do"
LOOP_CLOSE = "done ) &"
SLEEP_PREFIX = "sleep "
SHARD_LOGS = ("serial", "parallel_1", "parallel_2")
NOTICE_PREFIX = "::notice::[#6344] progress | serial: "
NOTICE_RE = re.compile(
    r"::notice::\[#6344\] progress \| serial: (?P<serial>[^:]*) \| parallel_1: (?P<parallel_1>[^:]*)"
    r" \| parallel_2: (?P<parallel_2>[^:]*)"
)
V2_COMMAND = "::"
V1_COMMAND = "##["
RUNNER_PERCENT = "%"
CUT_BYTES = 90  # the reader keeps 90 bytes of each last line (CUT_BYTES in the step's python call)
READ_BOUND = 8192  # the reader reads back at most this many bytes from the end of each log (READ_BYTES in the step)
ESCAPE_RE = re.compile(r"\\(?:(\\)|x([0-9a-f]{2})|u([0-9a-f]{4}))")

RUN_CEILING_SECS = 10.0  # one heartbeat run, every input size below included
BIG_LINE_BYTES = 1024 * 1024
BENIGN_HEAD = "test store::tests::a ... "
BENIGN_TAIL = "ok"

# Line ends the runner splits on (CR, LF, CRLF; a lone CR included) plus the other splitlines breaks.
LINE_BREAKS = {
    "LF": "\n",
    "CR": "\r",
    "CRLF": "\r\n",
    "LFCR": "\n\r",
    "CRCR": "\r\r",
    "VT": "\x0b",
    "FF": "\x0c",
    "NEL": "\x85",
    "LS": " ",
    "PS": " ",
}
COMMAND_FORMS = {
    "warning": "::warning::forged-by-test-output",
    "error": "::error file=src/lib.rs,line=1::forged-by-test-output",
    "add_mask": "::add-mask::forged-by-test-output",
    "stop_commands": "::stop-commands::forgedtoken",
    "set_output": "::set-output name=forged::forged-by-test-output",
    "lead_space_warning": "  ::warning::forged-by-test-output",
    "v1_error": "##[error]forged-by-test-output",
    "v1_set_output": "##[set-output name=forged;]forged-by-test-output",
    "v1_add_mask": "##[add-mask]forged-by-test-output",
}
POSITIONS = ("start", "middle", "end")
PERCENT_FORMS = {
    "pct_lf": "test a ... %0A::warning::forged-by-test-output",
    "pct_cr": "test a ... %0D::error::forged-by-test-output",
    "pct_crlf": "test a ... %0D%0A##[error]forged-by-test-output",
    "pct_25": "test a ... %25 100% %%0A",
}
OTHER_LINES = {
    "benign": (BENIGN_HEAD + BENIGN_TAIL).encode(),
    "nul_then_cr": b"test a ... \x00ok\r::warning::forged-by-test-output",
    "invalid_utf8": b"test a ... \xff\xfe\r::error::forged-by-test-output",
    "split_multibyte": ("a" * (CUT_BYTES - 1) + "éé").encode(),
    "payload_at_cut": ("a" * (CUT_BYTES - 6) + "\r::warning::forged").encode(),
    "colons_hashes_backslash": b"a::b ## #[ ##[ \\x0a \\ C# issue #",
    "escape_lookalike": b"\\x0d::warning::forged \\u2028",
}

# Byte class (#9430 bytes lane): `cut -c` cuts BYTES, so a tail can end inside a UTF-8 character and a test can
# print any byte. The python call re-reads argv as UTF-8 with surrogateescape and writes UTF-8 whatever the
# locale, so a byte that is not part of a whole UTF-8 character reaches the notice in the ESCAPED form
# ``\udcXX`` (its surrogateescape code point, written by workflow_annotation.safe_text); control bytes are
# escaped as ``\xHH``; a whole UTF-8 character is written as itself.
LATIN1_LOCALE = "en_US.ISO-8859-1"  # a non-UTF-8 locale, built with localedef into the scratch directory
LOCALEDEF_SOURCE = ("-i", "en_US", "-f", "ISO-8859-1")
UNSET_LOCALE = "unset"  # LANG, LANGUAGE and every LC_* removed from the environment
LOCALES = ("C.UTF-8", "C", "POSIX", UNSET_LOCALE, LATIN1_LOCALE)
GENERATIVE_LOCALES = ("C.UTF-8", LATIN1_LOCALE)
LOCALE_ENV_KEYS = ("LANG", "LANGUAGE", "LOCPATH")
SURROGATE_ESCAPE = "\\udc%02x"
BYTE_FILLER = "test store tests a ... ok"  # no ':', '#', '%', '\\' or control byte: kept verbatim by render
MULTIBYTE_CHARS = {"2byte_U+00E9": "é", "3byte_U+20AC": "€", "4byte_U+1F600": "\U0001f600"}
WHOLE_CHAR_LEAD = 10  # a whole character this far before the cut is written as itself
LONE_BYTE = 0xFF
CONTINUATION_BYTE = 0x80
BYTE_VALUES = 256  # every byte value, NUL included: the reader gets bytes from the file, never through argv
PRINTABLE_ASCII = range(0x20, 0x7F)
EXPECTED_LINES = 1

# Fix-r1 (class A, B, C): the exact heartbeat text. The log PATHS are the argv of the one python3 call; no host text
# tool is on the notice path (uutils tail 0.10.0 loses bytes at 64 KiB, uutils and BSD cut -c cut characters).
LOG_ARGV = " ".join('"$sd/%s.log"' % shard for shard in SHARD_LOGS)
READ_BOUND_RE = re.compile(r"^\s*READ_BYTES = ([0-9]+)\s*(?:#.*)?$", re.MULTILINE)
CUT_BYTES_RE = re.compile(r"^\s*CUT_BYTES = ([0-9]+)\s*(?:#.*)?$", re.MULTILINE)
READER_FORMS = ('"rb"', "os.O_NONBLOCK", "os.fstat(", "stat.S_ISREG(", "except OSError:")
ADDED_PATH = 'sys.path.insert(0, "scripts/ci")'
SYS_PATH = "sys.path"
COMMAND_SUBSTITUTION = "$("
HOST_TEXT_TOOLS = ("tail", "cut", "sed", "head", "awk", "grep", "cat", "tr", "dd", "od", "perl", "xargs")
PYTHON_ISOLATED = "python3 -I -c '"
PYTHON_NOT_ISOLATED = "python3 -c '"
FALLBACK_TEXT = '|| { echo "[#6344] progress notice not written: python3 exited $?" >&2 || true; }'
FALLBACK_STDERR = ">&2"
NOTICE_TEMPLATE = "[#6344] progress | serial: {s} | parallel_1: {p1} | parallel_2: {p2}"
NOTICE_MAX_CHARS_TEXT = "max_chars=2 * wa.MAX_ANNOTATION_CHARS"
NOTICE_MAX_CHARS = 2 * wa.MAX_ANNOTATION_CHARS  # the bound the heartbeat passes to annotation()

# Class D: the exact worst case. Each field is CUT_BYTES of the byte whose escape is longest; the line is the empty
# template plus that growth for every field, and must stay under NOTICE_MAX_CHARS with no cut mark.
BYTE_ESCAPE_CHARS = {value: len(wa.safe_value(bytes([value]).decode("utf-8", "surrogateescape")))
                     for value in range(BYTE_VALUES)}
MAX_ESCAPE_CHARS = max(BYTE_ESCAPE_CHARS.values())
WORST_BYTE = min(value for value, chars in BYTE_ESCAPE_CHARS.items() if chars == MAX_ESCAPE_CHARS)
TEMPLATE_LINE_CHARS = len(wa.annotation("notice", wa.render(NOTICE_TEMPLATE, s="", p1="", p2=""),
                                        max_chars=NOTICE_MAX_CHARS))
WORST_LINE_CHARS = TEMPLATE_LINE_CHARS + len(SHARD_LOGS) * CUT_BYTES * MAX_ESCAPE_CHARS

# Cell (d): the heartbeat loop under the step's own shell options, with a python3 stub that fails.
STEP_SHELL = "bash"
BASH = shutil.which(STEP_SHELL)  # resolved on the host PATH; the heartbeat runs get a PATH with only python3
STEP_SHELL_COMMAND = ("bash", "--noprofile", "--norc", "-eo", "pipefail")  # GitHub's command for `shell: bash`
STEP_OPTIONS_LINE = "set -euo pipefail"  # first line of the step's run text
HB_PID_LINE = "hb=$!"
HB_KILL_LINE = 'kill "$hb" 2>/dev/null || true'
HB_WAIT_LINE = 'wait "$hb" 2>/dev/null || true'
MIN_ITERATIONS = 3
# Each loop pass starts with one (stubbed) sleep; await-ticks waits for the sleep of one pass past MIN_ITERATIONS: the
# loop is sequential, so pass k + 1 sleeps only after the python3 call and fallback of pass k are done, and passes
# completed = sleeps - 1.
AWAIT_ITERATIONS = MIN_ITERATIONS + 1
FAILING_STUB_RC = 1
PASSING_STUB_RC = 0
SHELL_SIGNAL_RC_BASE = 128  # bash reports a child killed by signal N as 128 + N
COMMAND_NOT_FOUND_RC = 127
STUB_TICK_SECS = 0.02  # the stub sleep, for `sleep 300`
AWAIT_DEADLINE_SECS = 5.0
STEP_END_MARKER = "step-reached-end"
FALLBACK_RE = re.compile(r"\[#6344\] progress notice not written: python3 exited (?P<rc>\d+)")
# Every python3 call writes one line to HB_CALLS; the sleep stub counts loop passes in every form, python3 missing
# included.
PYTHON3_STUB = """#!{exe} -I
import os, signal, sys
with open(os.environ["HB_CALLS"], "a") as calls:
    calls.write("call\\n")
if os.environ["HB_STUB_MODE"] == "signal":
    os.kill(os.getpid(), signal.SIGKILL)
sys.exit(int(os.environ["HB_STUB_RC"]))
"""
# python3 per failure form: "stub" (PYTHON3_STUB), "absent" (no python3 on PATH), "real" (the interpreter itself).
PY_STUB = "stub"
PY_ABSENT = "absent"
PY_REAL = "real"
CLOSE_NONE = ""
CLOSE_STDERR = "2>&-"
CLOSE_STDOUT = ">&-"
# name: (python3, stub mode, stub rc, redirect on the heartbeat call, fallback rc on stderr or None, other stderr ok)
FAILURE_FORMS = {
    "exit_1": (PY_STUB, "exit", FAILING_STUB_RC, CLOSE_NONE, FAILING_STUB_RC, False),
    "killed_by_signal": (PY_STUB, "signal", FAILING_STUB_RC, CLOSE_NONE, SHELL_SIGNAL_RC_BASE + signal.SIGKILL, True),
    "python3_missing": (PY_ABSENT, "exit", FAILING_STUB_RC, CLOSE_NONE, COMMAND_NOT_FOUND_RC, True),
    "stderr_closed": (PY_STUB, "exit", FAILING_STUB_RC, CLOSE_STDERR, None, False),
    "stdout_closed": (PY_REAL, "exit", FAILING_STUB_RC, CLOSE_STDOUT, FAILING_STUB_RC, True),
}

# Class A: a hostile host text tool. Each stub records that it ran and prints a forged command; the notice must not
# run any of them (every heartbeat cell has only python3 on PATH; this cell puts the stubs first).
HOST_TOOL_STUB = """#!{exe} -I
import os, sys
with open(os.path.join(os.environ["HB_TOOL_MARKERS"], "ran-" + os.path.basename(sys.argv[0])), "w") as marker:
    marker.write("ran\\n")
sys.stdout.write("::warning::forged-by-host-tool\\n")
"""

# Reader cells (RULING b2bb1090 section B). Sizes of a one-line log, each with and without a final line feed.
SIZE_CELLS = (0, 1, 65535, 65536, 65537, READ_BOUND - 1, READ_BOUND, READ_BOUND + 1, BIG_LINE_BYTES)
# A header line before a last line that fills the window to within a byte of the bound (the line-start edge).
EDGE_SIZES = (READ_BOUND - 2, READ_BOUND - 1, READ_BOUND, READ_BOUND + 1)
EDGE_HEADER = b"running 3 tests\n"
SIZE_PATTERN = bytes(range(0x21, 0x7F))  # printable, no line feed, a distinct byte at every offset mod 94
SPARSE_LOG_BYTES = 2 * 1024 * 1024 * 1024
SPARSE_TAIL = b"\ntest sparse::tail ... ok\n"
ADDRESS_SPACE_CEILING = 512 * 1024 * 1024  # RLIMIT_AS of the heartbeat run on the sparse log (reading it whole fails)
CHAR_DEVICE = Path("/dev/zero")  # an endless character device behind a log path
UNREADABLE_MODE = 0o000
FIFO_DATA = b"::error::forged-through-a-fifo\n"
GROW_STEPS = (b"test a ... ok\n", b"::error::forged-mid-line", b" ok\n::warning::next\n", b"x" * (2 * READ_BOUND))
CRLF_LOG = b"running 3 tests\r\ntest a ... ok\r\n"
ERROR_ONLY_LOG = b"running 3 tests\n::error::forged-by-test-output\n"
NUL_LOG = b"running 3 tests\n\x00test\x00a ... \x00ok\x00\n"
LONG_MULTIBYTE_LOG = b"a" * READ_BOUND + "é".encode() + b"b" * (CUT_BYTES - 1)  # the last-90 window cuts the é

# Class C: modules -I must keep out. Each writes a marker named after itself when it runs.
PLANT_SOURCE = """import os as _os
with open(_os.path.join({marker_dir!r}, "ran-" + __name__), "w") as _marker:
    _marker.write(__name__)
"""
PLANTED_ON_PYTHONPATH = ("sitecustomize", "workflow_annotation", "os")
PLANTED_IN_USER_SITE = ("usercustomize",)
PLANTED_IN_CWD = ("workflow_annotation", "sitecustomize", "os")
# The plants the interpreter runs at startup when it is not isolated (positive control: they are live).
PLANTS_LIVE_WITHOUT_ISOLATION = ("sitecustomize", "usercustomize")
SLEEP_STUB = """#!{exe} -I
import os, time
with open(os.environ["HB_SLEEPS"], "a") as sleeps:
    sleeps.write("sleep\\n")
time.sleep(float(os.environ["HB_TICK"]))
"""
AWAIT_STUB = """#!{exe} -I
import os, time
deadline = time.monotonic() + float(os.environ["HB_DEADLINE"])
while time.monotonic() < deadline:
    try:
        with open(os.environ["HB_CALLS_WAIT"]) as calls:
            if calls.read().count("\\n") >= int(os.environ["HB_MIN"]):
                break
    except FileNotFoundError:
        pass
    time.sleep(0.01)
"""


def multibyte_cases():
    """(name, last-line bytes, expected serial field) for a 2-, 3- and 4-byte character straddling byte 90."""
    cases = []
    for char_name, char in MULTIBYTE_CHARS.items():
        encoded = char.encode()
        for kept in range(1, len(encoded)):
            line = ("a" * (CUT_BYTES - kept) + char + "zz").encode()
            field = "a" * (CUT_BYTES - kept) + "".join(SURROGATE_ESCAPE % byte for byte in encoded[:kept])
            cases.append(("%s/kept_%d_of_%d" % (char_name, kept, len(encoded)), line, field))
        whole = "a" * WHOLE_CHAR_LEAD + char + "zz"
        cases.append(("%s/whole" % char_name, whole.encode(), whole))
    return cases


def lone_byte_cases(value):
    """(name, last-line bytes, expected serial field) for one byte at the start, middle and end of the filler."""
    raw = bytes([value])
    escaped = SURROGATE_ESCAPE % value
    mid = len(BYTE_FILLER) // 2
    filler = BYTE_FILLER.encode()
    return [
        ("start", raw + filler, escaped + BYTE_FILLER),
        ("middle", filler[:mid] + raw + filler[mid:], BYTE_FILLER[:mid] + escaped + BYTE_FILLER[mid:]),
        ("end", filler + raw, BYTE_FILLER + escaped),
    ]


def hostile_line(form, brk, position):
    """One last log line: a line break and a command form at the start, middle or end of a test line."""
    payload = brk + form
    if position == "start":
        return (payload + " " + BENIGN_HEAD + BENIGN_TAIL).encode()
    if position == "middle":
        return (BENIGN_HEAD + payload + " " + BENIGN_TAIL).encode()
    return (BENIGN_HEAD + BENIGN_TAIL + payload).encode()


def corpus():
    """(case name, last-line bytes) for every hostile form; each log gets a whole log with that last line."""
    cases = []
    for brk_name, brk in LINE_BREAKS.items():
        for form_name, form in COMMAND_FORMS.items():
            for position in POSITIONS:
                cases.append(("%s/%s/%s" % (brk_name, form_name, position), hostile_line(form, brk, position)))
    for name, text in PERCENT_FORMS.items():
        cases.append((name, text.encode()))
    cases.extend(OTHER_LINES.items())
    return cases


def heartbeat_body(run_text):
    """The heartbeat loop body (without its sleep) in the run text of the step ``heartbeat_step`` finds."""
    lines = run_text.split("\n")
    for start, line in enumerate(lines):
        if line.strip() != LOOP_OPEN:
            continue
        end = next(i for i in range(start + 1, len(lines)) if lines[i].strip() == LOOP_CLOSE)
        body = [body_line for body_line in lines[start + 1:end] if not body_line.strip().startswith(SLEEP_PREFIX)]
        if any(HEARTBEAT_MARKER in body_line for body_line in body):
            return "\n".join(body)
    raise AssertionError("no heartbeat loop holds %r" % HEARTBEAT_MARKER)


def heartbeat_step():
    """The one ci.yml step that holds the progress heartbeat, as read by the strict stdlib reader.

    An unreadable or oddly shaped ci.yml raises ``WorkflowReadError`` (a failure, never a skip).
    """
    steps = [step for _job, step in wt.read_all_steps(CI_YML) if HEARTBEAT_MARKER in (step.get("run") or "")]
    if len(steps) != 1:
        raise AssertionError("expected one ci.yml step with %r, found %d" % (HEARTBEAT_MARKER, len(steps)))
    return steps[0]


def heartbeat_lifecycle(run_text):
    """The step's own lines that start, kill and reap the heartbeat: the whole loop (sleep included) + `hb=$!`, then
    the kill and wait lines. Each is taken verbatim from the run text."""
    lines = run_text.split("\n")
    stripped = [line.strip() for line in lines]
    for start, line in enumerate(stripped):
        if line != LOOP_OPEN:
            continue
        end = stripped.index(LOOP_CLOSE, start)
        if not any(HEARTBEAT_MARKER in body_line for body_line in lines[start:end]):
            continue
        if stripped[end + 1] != HB_PID_LINE:
            raise AssertionError("the heartbeat loop is not followed by %r" % HB_PID_LINE)
        kill = stripped.index(HB_KILL_LINE, end)
        reap = stripped.index(HB_WAIT_LINE, kill)
        return "\n".join(lines[start:end + 2]), lines[kill], lines[reap]
    raise AssertionError("no heartbeat loop holds %r" % HEARTBEAT_MARKER)


def unescape(text):
    """Undo the workflow_annotation escapes once (``\\\\``, ``\\xHH``, ``\\uHHHH``) and return the bytes."""
    def one(match):
        if match.group(1):
            return "\\"
        return chr(int(match.group(2) or match.group(3), 16))
    return ESCAPE_RE.sub(one, text).encode("utf-8", "surrogateescape")


def last_line(data):
    """The bytes `tail -n 1` prints for a file holding `data`, without its line feed."""
    lines = data.split(b"\n")
    if data.endswith(b"\n"):
        lines.pop()
    return lines[-1] if lines else b""


def bounded_field(data):
    """Oracle, from the WHOLE log bytes (not a re-implementation of the reader's window walk): the field the reader
    gives for a regular file holding `data`. The last line (without its final line feed) is whole in the read-back
    window when the file fits the window or the line feed before the line lies inside it; then the field is its first
    CUT_BYTES bytes. Otherwise the window holds no line feed before its final byte and the field is the last
    CUT_BYTES bytes of the line. Every byte is kept (NUL and CR included)."""
    line = last_line(data)
    final_newline = int(data.endswith(b"\n"))
    if len(data) <= READ_BOUND or len(line) + final_newline + 1 <= READ_BOUND:
        return line[:CUT_BYTES]
    return line[-CUT_BYTES:]


def oracle_field(log_path):
    """The expected field for one log path: empty for a missing, unreadable or non-regular path (a directory, a
    FIFO, a device), else ``bounded_field`` of its bytes."""
    try:
        info = os.stat(log_path)
    except OSError:
        return b""
    if not stat.S_ISREG(info.st_mode) or not os.access(log_path, os.R_OK):
        return b""
    return bounded_field(log_path.read_bytes())


def size_line(size):
    """A one-line log body of `size` bytes with no line feed and a distinct byte at every offset."""
    return (SIZE_PATTERN * (size // len(SIZE_PATTERN) + 1))[:size]


def address_space_ceiling():
    """preexec_fn of the sparse-log run: cap the address space (setrlimit failure tolerated, see the module doc)."""
    try:
        resource.setrlimit(resource.RLIMIT_AS, (ADDRESS_SPACE_CEILING, ADDRESS_SPACE_CEILING))
    except (OSError, ValueError):
        # A kernel that refuses the ceiling still runs the cell: the field assertions hold, only the cap is unproven.
        return


def command_lines(output):
    """Every line the runner could parse as a workflow command (v2 after leading whitespace, v1 anywhere)."""
    text = output.decode("utf-8", "surrogateescape")
    return [line for line in text.splitlines() if line.lstrip().startswith(V2_COMMAND) or V1_COMMAND in line]


class ProgressNotice(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.step = heartbeat_step()
        cls.body = heartbeat_body(cls.step["run"])
        SCRATCH_PARENT.mkdir(exist_ok=True)
        cls.scratch = Path(tempfile.mkdtemp(prefix="progress-notice-9430-", dir=str(SCRATCH_PARENT)))
        # The PATH of every heartbeat run: python3 only, so a host text tool on the notice path fails on every host.
        cls.python_bin = cls.scratch / "python-only-bin"
        cls.python_bin.mkdir()
        (cls.python_bin / "python3").symlink_to(sys.executable)

    @classmethod
    def tearDownClass(cls):
        if str(cls.scratch).startswith(str(SCRATCH_PARENT)):
            for path in cls.scratch.rglob("*"):
                if path.is_dir() and not path.is_symlink():
                    path.chmod(0o755)
                elif path.is_file() and not path.is_symlink():
                    path.chmod(0o644)
            shutil.rmtree(cls.scratch, ignore_errors=True)

    def locale_env(self, locale):
        """The environment for one locale cell; the Latin-1 locale is built once with localedef (fails, never skips)."""
        env = {key: value for key, value in os.environ.items()
               if key not in LOCALE_ENV_KEYS and not key.startswith("LC_")}
        if locale == UNSET_LOCALE:
            return env
        env["LC_ALL"] = locale
        if locale == LATIN1_LOCALE:
            locpath = self.scratch / "locales"
            if not (locpath / LATIN1_LOCALE).is_dir():
                locpath.mkdir(exist_ok=True)
                built = subprocess.run(["localedef", *LOCALEDEF_SOURCE, str(locpath / LATIN1_LOCALE)],
                                       capture_output=True, text=True, check=False)
                self.assertEqual(built.returncode, 0, "localedef %s: %s" % (" ".join(LOCALEDEF_SOURCE), built.stderr))
            env["LOCPATH"] = str(locpath)
        return env

    def shard_dir(self, name):
        """A new, empty shard directory for one cell."""
        shard_dir = self.scratch / re.sub(r"[^A-Za-z0-9_]", "_", name)
        shard_dir.mkdir()
        return shard_dir

    def run_bounded(self, name, argv, cwd, env, preexec_fn=None):
        """Run `argv` in its own session under the wall ceiling; on a timeout kill the whole group and fail."""
        started = time.monotonic()
        with subprocess.Popen(argv, cwd=str(cwd), env=env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, start_new_session=True, preexec_fn=preexec_fn) as process:
            try:
                stdout, stderr = process.communicate(timeout=RUN_CEILING_SECS)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.communicate()
                raise self.failureException(
                    "%s: the heartbeat run passed the %.0f s wall ceiling (blocked)" % (name, RUN_CEILING_SECS)
                ) from None
        self.assertLess(time.monotonic() - started, RUN_CEILING_SECS, name)
        return subprocess.CompletedProcess(argv, process.returncode, stdout, stderr)

    def run_in(self, name, shard_dir, locale="C.UTF-8", body=None, cwd=REPO, extra_env=None, expected=None,
               preexec_fn=None):
        """Run the loop body once against `shard_dir` (PATH = python3 only unless `extra_env` sets it).

        Returns (result, expected); `expected` defaults to the oracle field of each log path at the end of the run."""
        env = self.locale_env(locale)
        env["PATH"] = str(self.python_bin)
        env.update(extra_env or {})
        script = "sd=%s\n%s\n" % (shlex.quote(str(shard_dir)), self.body if body is None else body)
        result = self.run_bounded(name, [BASH, "-c", script], cwd, env, preexec_fn)
        if expected is None:
            expected = {shard: oracle_field(shard_dir / ("%s.log" % shard)) for shard in SHARD_LOGS}
        return result, expected

    def run_heartbeat(self, name, logs, locale="C.UTF-8", body=None, cwd=REPO, extra_env=None):
        """Write `logs` ({shard: bytes or None for a missing file}), run the loop body once, return the output.

        `body` defaults to the step's own loop body; `extra_env` is merged over the locale environment."""
        shard_dir = self.shard_dir(name)
        for shard, content in logs.items():
            if content is not None:
                (shard_dir / ("%s.log" % shard)).write_bytes(content)
        return self.run_in(name, shard_dir, locale, body, cwd, extra_env)

    def assert_one_notice(self, name, result, expected):
        output = result.stdout + result.stderr
        commands = command_lines(output)
        self.assertEqual(len(commands), 1, "%s: command lines %r" % (name, commands))
        line = commands[0]
        self.assertTrue(line.startswith(NOTICE_PREFIX), "%s: %r" % (name, line))
        self.assertNotIn(RUNNER_PERCENT, line, "%s: %r" % (name, line))
        match = NOTICE_RE.fullmatch(line)
        self.assertIsNotNone(match, "%s: %r" % (name, line))
        for shard in SHARD_LOGS:
            self.assertEqual(unescape(match.group(shard)), expected[shard], "%s: %s field of %r" % (name, shard, line))

    def test_hostile_corpus_one_command_line_and_exact_data(self):
        cases = corpus()
        # Three cases per run, one per shard log, so every data field sees every form.
        for index in range(0, len(cases), len(SHARD_LOGS)):
            group = cases[index:index + len(SHARD_LOGS)]
            while len(group) < len(SHARD_LOGS):
                group.append(("benign_fill", OTHER_LINES["benign"]))
            name = "+".join(case_name for case_name, _ in group)
            logs = {shard: b"running 3 tests\n" + text + b"\n" for shard, (_, text) in zip(SHARD_LOGS, group)}
            with self.subTest(name):
                result, expected = self.run_heartbeat("c%03d" % index, logs)
                self.assert_one_notice(name, result, expected)

    def test_oracle_matches_python_cut_for_ascii(self):
        line = hostile_line(COMMAND_FORMS["warning"], LINE_BREAKS["CR"], "middle")
        result, expected = self.run_heartbeat("oracle", {shard: line + b"\n" for shard in SHARD_LOGS})
        self.assertEqual(expected["serial"], line[:CUT_BYTES])
        self.assert_one_notice("oracle", result, expected)

    def test_9430_fix_reader_field_is_locale_independent(self):
        # The cut is by bytes in Python: the same logs give the same notice bytes in every locale, equal to the oracle.
        lines = [case[1] for case in multibyte_cases()] + [bytes([LONE_BYTE]) * (2 * CUT_BYTES), LONG_MULTIBYTE_LOG]
        for index, line in enumerate(lines):
            logs = {shard: b"running 3 tests\n" + line + b"\n" for shard in SHARD_LOGS}
            outputs = {}
            for locale in LOCALES:
                name = "locale_%s_%03d" % (locale, index)
                with self.subTest(name):
                    result, expected = self.run_heartbeat(name, logs, locale)
                    self.byte_notice(name, result, expected)
                    outputs[locale] = result.stdout
            self.assertEqual(len(set(outputs.values())), 1, "line %d: %r" % (index, outputs))

    def test_one_megabyte_single_line_within_ceiling(self):
        unit = b"\r::warning::forged-by-test-output ##[error]x %0A "
        big = (unit * (BIG_LINE_BYTES // len(unit) + 1))[:BIG_LINE_BYTES]
        self.assertGreaterEqual(len(big), BIG_LINE_BYTES)
        result, expected = self.run_heartbeat("big", {shard: big for shard in SHARD_LOGS})
        self.assert_one_notice("big", result, expected)

    def test_worst_case_escape_growth_is_not_cut(self):
        # Each byte of an invalid UTF-8 run becomes a 6-char surrogate escape: the longest growth there is.
        worst = {"serial": b"\xff" * (2 * CUT_BYTES), "parallel_1": b"\x80" * (2 * CUT_BYTES),
                 "parallel_2": b":" * (2 * CUT_BYTES)}
        result, expected = self.run_heartbeat("worst", worst)
        self.assert_one_notice("worst", result, expected)

    def test_9430_fix_worst_case_reaches_exact_bound(self):
        # Class D: every field at the longest escape reaches WORST_LINE_CHARS exactly (below NOTICE_MAX_CHARS, no cut
        # mark); one byte more per field (bound + 1 input byte) changes nothing, because the reader keeps CUT_BYTES.
        self.assertLess(WORST_LINE_CHARS, NOTICE_MAX_CHARS)
        for extra in (0, 1):
            logs = {shard: bytes([WORST_BYTE]) * (CUT_BYTES + extra) + b"\n" for shard in SHARD_LOGS}
            name = "bound_plus_%d" % extra
            with self.subTest(name):
                result, expected = self.run_heartbeat(name, logs)
                match = self.byte_notice(name, result, expected)
                line = result.stdout.decode("utf-8")[:-1]
                self.assertEqual(len(line), WORST_LINE_CHARS, name)
                self.assertFalse(line.endswith(wa.ANNOTATION_CUT_MARK), name)
                for shard in SHARD_LOGS:
                    self.assertEqual(len(match.group(shard)), CUT_BYTES * MAX_ESCAPE_CHARS, name)

    def test_empty_and_missing_logs(self):
        result, expected = self.run_heartbeat("empty", {"serial": b"", "parallel_1": None, "parallel_2": b"\n"})
        self.assertEqual(expected, {shard: b"" for shard in SHARD_LOGS})
        self.assert_one_notice("empty", result, expected)

    # ---- byte class (#9430 bytes lane) ----

    def byte_notice(self, name, result, expected):
        """rc 0, empty stderr, stdout exactly one valid UTF-8 line with the fixed prefix; return the parsed match."""
        self.assertEqual(result.returncode, 0, "%s: rc, stderr %r" % (name, result.stderr))
        self.assertEqual(result.stderr, b"", "%s: stderr must be empty (no traceback, no fallback)" % name)
        try:
            text = result.stdout.decode("utf-8")
        except UnicodeDecodeError as error:
            raise self.failureException(
                "%s: stdout is not valid UTF-8 (%s): %r" % (name, error, result.stdout)
            ) from error
        self.assertTrue(text.endswith("\n"), "%s: %r" % (name, text))
        self.assertEqual(text.count("\n"), EXPECTED_LINES, "%s: %r" % (name, text))
        self.assertEqual(len(text.splitlines()), EXPECTED_LINES, "%s: %r" % (name, text))
        line = text[:-1]
        self.assertTrue(line.startswith(NOTICE_PREFIX), "%s: %r" % (name, line))
        match = NOTICE_RE.fullmatch(line)
        self.assertIsNotNone(match, "%s: %r" % (name, line))
        for shard in SHARD_LOGS:
            self.assertEqual(unescape(match.group(shard)), expected[shard], "%s: %s data of %r" % (name, shard, line))
        return match

    def run_byte_cells(self, cell, cases, locales):
        """Run `cases` ([(name, last-line bytes, expected serial field or None)]) three per run, under each locale."""
        for locale in locales:
            for index in range(0, len(cases), len(SHARD_LOGS)):
                group = cases[index:index + len(SHARD_LOGS)]
                while len(group) < len(SHARD_LOGS):
                    group.append(("filler", BYTE_FILLER.encode(), BYTE_FILLER))
                name = "%s/%s/%s" % (cell, locale, "+".join(case[0] for case in group))
                logs = {shard: b"running 3 tests\n" + case[1] + b"\n" for shard, case in zip(SHARD_LOGS, group)}
                with self.subTest(name):
                    result, expected = self.run_heartbeat("%s_%s_%03d" % (cell, locale, index), logs, locale)
                    match = self.byte_notice(name, result, expected)
                    for shard, case in zip(SHARD_LOGS, group):
                        if case[2] is not None:
                            self.assertEqual(match.group(shard), case[2], "%s: %s field" % (name, shard))
                        else:
                            outside = [char for char in match.group(shard) if ord(char) not in PRINTABLE_ASCII]
                            self.assertEqual(outside, [], "%s: %s field %r" % (name, shard, match.group(shard)))

    def test_9430_bytes_a_multibyte_cut_at_byte_90(self):
        # The dangling lead bytes of a cut character appear escaped as \udcXX; a whole character as itself.
        self.run_byte_cells("a", multibyte_cases(), LOCALES)

    def test_9430_bytes_b_lone_ff(self):
        self.run_byte_cells("b", lone_byte_cases(LONE_BYTE), LOCALES)

    def test_9430_bytes_c_continuation_run(self):
        run = bytes([CONTINUATION_BYTE]) * CUT_BYTES
        self.assertNotIn(b"\x00", run)
        self.assertEqual(len(run), CUT_BYTES)
        cases = [("run_0x80_x90", run, (SURROGATE_ESCAPE % CONTINUATION_BYTE) * CUT_BYTES)]
        self.run_byte_cells("c", cases, LOCALES)

    def test_9430_bytes_generative_every_single_byte(self):
        # Every byte value, NUL included (the reader takes the bytes from the file, not through argv), at the start,
        # middle and end of a line. Exact data round trip, and every character of the field is printable ASCII: a lone
        # byte is never written raw.
        cases = []
        for value in range(BYTE_VALUES):
            for position, line, _field in lone_byte_cases(value):
                cases.append(("0x%02x_%s" % (value, position), line, None))
        self.assertEqual(len(cases), BYTE_VALUES * len(POSITIONS))
        self.run_byte_cells("g", cases, GENERATIVE_LOCALES)

    def run_lifecycle(self, name, stub_rc, python3=PY_STUB, stub_mode="exit", redirect=CLOSE_NONE):
        """Run the step's heartbeat start/kill/reap lines under the step's shell options with stubbed python3/sleep.

        PATH holds only the stub directory (python3 per `python3`, a sleep that counts loop passes, await-ticks).
        `redirect` is applied to the call of the heartbeat function (closed stderr or stdout reach the loop and the
        notice command). Returns (step, result, python3 calls, completed loop passes)."""
        step = self.step
        loop, kill_line, wait_line = heartbeat_lifecycle(step["run"])
        cell_dir = self.scratch / name
        stub_dir = cell_dir / "bin"
        stub_dir.mkdir(parents=True)
        stubs = [("sleep", SLEEP_STUB), ("await-ticks", AWAIT_STUB)]
        if python3 == PY_STUB:
            stubs.append(("python3", PYTHON3_STUB))
        for stub_name, source in stubs:
            stub = stub_dir / stub_name
            stub.write_text(source.format(exe=sys.executable))
            stub.chmod(0o755)
        if python3 == PY_REAL:
            (stub_dir / "python3").symlink_to(sys.executable)
        calls = cell_dir / "calls"
        sleeps = cell_dir / "sleeps"
        script = cell_dir / "step.sh"
        script.write_text("\n".join([
            STEP_OPTIONS_LINE,
            "heartbeat_cell() {",
            "  local sd=\"$1\" hb",
            loop,
            "  await-ticks",
            kill_line,
            wait_line,
            "}",
            "heartbeat_cell %s %s" % (shlex.quote(str(cell_dir)), redirect),
            "echo %s" % STEP_END_MARKER,
            "",
        ]))
        env = dict(os.environ, PATH=str(stub_dir), HB_CALLS=str(calls), HB_SLEEPS=str(sleeps),
                   HB_STUB_RC=str(stub_rc), HB_STUB_MODE=stub_mode, HB_TICK=str(STUB_TICK_SECS),
                   HB_DEADLINE=str(AWAIT_DEADLINE_SECS), HB_MIN=str(AWAIT_ITERATIONS))
        env["HB_CALLS_WAIT"] = env["HB_SLEEPS"]
        result = self.run_bounded(name, [shutil.which(STEP_SHELL_COMMAND[0]), *STEP_SHELL_COMMAND[1:], str(script)],
                                  REPO, env)
        count = calls.read_text().count("\n") if calls.exists() else 0
        iterations = max(0, (sleeps.read_text().count("\n") if sleeps.exists() else 0) - 1)
        return step, result, count, iterations

    def test_9430_bytes_d_failed_call_keeps_loop_and_step_rc(self):
        step, control, control_calls, _ = self.run_lifecycle("d_control", PASSING_STUB_RC)
        self.assertEqual(step.get("shell"), STEP_SHELL)
        self.assertEqual(step["run"].split("\n")[0], STEP_OPTIONS_LINE)
        self.assertEqual(control.returncode, 0, control.stderr)
        self.assertEqual(control.stdout.decode().splitlines(), [STEP_END_MARKER])
        self.assertEqual(control.stderr, b"")
        self.assertGreaterEqual(control_calls, MIN_ITERATIONS)
        _step, failing, failing_calls, _ = self.run_lifecycle("d_failing", FAILING_STUB_RC)
        self.assertGreaterEqual(failing_calls, MIN_ITERATIONS,
                                "a failing python3 call ended the heartbeat loop after %d call(s)" % failing_calls)
        self.assertEqual(failing.returncode, control.returncode, failing.stderr)
        self.assertEqual(failing.stdout, control.stdout)
        errors = failing.stderr.decode().splitlines()
        self.assertGreaterEqual(len(errors), MIN_ITERATIONS - 1, errors)
        for error in errors:
            match = FALLBACK_RE.fullmatch(error)
            self.assertIsNotNone(match, "stderr line %r" % error)
            self.assertEqual(match.group("rc"), str(FAILING_STUB_RC))
        self.assertEqual(command_lines(failing.stdout + failing.stderr), [])


    # ---- fix-r1 cells (class A, B, C) ----

    def notice_command(self):
        """(the whole notice command, its python program): from ``python3 -I -c '`` to the end of the fallback."""
        self.assertEqual(self.body.count(PYTHON_ISOLATED), 1, "one isolated python3 call in the loop")
        command = self.body[self.body.index(PYTHON_ISOLATED):]
        tail = "' %s %s" % (LOG_ARGV, FALLBACK_TEXT)
        self.assertTrue(command.rstrip().endswith(tail), command[-200:])
        command = command.rstrip()
        program = command[len(PYTHON_ISOLATED):len(command) - len(tail)]
        return command, program

    def test_9430_fix_heartbeat_text_pins_reader_isolated_python_and_fallback(self):
        # Exact strings: the log PATHS are the argv of the one `python3 -I` call; a host text tool, a command
        # substitution, a python3 without -I, an unnamed bound or a fallback that can fail is red here on every host.
        command, program = self.notice_command()
        self.assertNotIn("'", program)
        self.assertNotIn(COMMAND_SUBSTITUTION, command)
        self.assertEqual([int(value) for value in READ_BOUND_RE.findall(program)], [READ_BOUND])
        self.assertEqual([int(value) for value in CUT_BYTES_RE.findall(program)], [CUT_BYTES])
        self.assertLess(CUT_BYTES, READ_BOUND)
        for form in READER_FORMS:
            self.assertIn(form, program)
        self.assertEqual(program.count(ADDED_PATH), 1)
        self.assertEqual(program.count(SYS_PATH), 1, "scripts/ci is the only added path")
        self.assertIn(NOTICE_TEMPLATE, program)
        self.assertEqual(program.count(NOTICE_MAX_CHARS_TEXT), 1)
        code_lines = [line for line in self.body.split("\n") if not line.strip().startswith("#")]
        for tool in HOST_TEXT_TOOLS:
            pattern = re.compile(r"(?<![\w./-])%s(?![\w-])" % re.escape(tool))
            self.assertEqual([line for line in code_lines if pattern.search(line)], [], tool)
        fallback = command[-len(FALLBACK_TEXT):]
        self.assertEqual(fallback, FALLBACK_TEXT)
        self.assertEqual(fallback.count(FALLBACK_STDERR), 1)
        self.assertNotIn(V2_COMMAND, fallback)
        self.assertNotIn(V1_COMMAND, fallback)

    def test_9430_fix_no_host_text_tool_between_call_and_args(self):
        # Conductor word a3ff9997, addition (1): the text from `python3 -I` to the end of its three arguments (the
        # program and the log paths, fallback excluded) names no host text tool and holds no pipe or substitution.
        command, program = self.notice_command()
        call = command[:len(command) - len(FALLBACK_TEXT)].rstrip()
        self.assertTrue(call.endswith(LOG_ARGV), call[-120:])
        for tool in HOST_TEXT_TOOLS:
            self.assertIsNone(re.search(r"(?<![\w./-])%s(?![\w-])" % re.escape(tool), call), tool)
        self.assertEqual(call[len(PYTHON_ISOLATED) + len(program):], "' " + LOG_ARGV)  # no shell pipe after it
        self.assertNotIn("`", call)
        self.assertNotIn(COMMAND_SUBSTITUTION, call)

    def test_9430_fix_hostile_host_text_tools_first_on_path_never_run(self):
        # Class A: hostile tail / cut / sed / ... stubs first on PATH (each prints a forged command and records that it
        # ran): none runs, and every multibyte cell keeps its exact bytes, in every locale.
        stub_dir = self.scratch / "host_tool_bin"
        markers = self.scratch / "host_tool_markers"
        stub_dir.mkdir()
        markers.mkdir()
        for tool in HOST_TEXT_TOOLS:
            stub = stub_dir / tool
            stub.write_text(HOST_TOOL_STUB.format(exe=sys.executable))
            stub.chmod(0o755)
        extra_env = {"PATH": "%s:%s" % (stub_dir, self.python_bin), "HB_TOOL_MARKERS": str(markers)}
        cases = multibyte_cases()
        for locale in LOCALES:
            for index in range(0, len(cases), len(SHARD_LOGS)):
                group = cases[index:index + len(SHARD_LOGS)]
                while len(group) < len(SHARD_LOGS):
                    group.append(("filler", BYTE_FILLER.encode(), BYTE_FILLER))
                name = "hosttool/%s/%s" % (locale, "+".join(case[0] for case in group))
                logs = {shard: b"running 3 tests\n" + case[1] + b"\n" for shard, case in zip(SHARD_LOGS, group)}
                with self.subTest(name):
                    result, expected = self.run_heartbeat("hosttool_%s_%03d" % (locale, index), logs, locale,
                                                          extra_env=extra_env)
                    match = self.byte_notice(name, result, expected)
                    for shard, case in zip(SHARD_LOGS, group):
                        self.assertEqual(match.group(shard), case[2], "%s: %s field" % (name, shard))
        self.assertEqual(sorted(path.name for path in markers.iterdir()), [])

    # ---- reader cells (RULING b2bb1090 section B) ----

    def test_9430_reader_oracle_fixed_points(self):
        # The oracle against hand-written values, so it is not only checked against the reader.
        self.assertEqual(bounded_field(b""), b"")
        self.assertEqual(bounded_field(b"\n"), b"")
        self.assertEqual(bounded_field(b"a\nb"), b"b")
        self.assertEqual(bounded_field(b"a\nb\n"), b"b")
        self.assertEqual(bounded_field(b"a\n\n"), b"")
        self.assertEqual(bounded_field(b"a\r\nb\r\n"), b"b\r")
        line = size_line(READ_BOUND + 1)
        self.assertEqual(bounded_field(line), line[-CUT_BYTES:])
        self.assertEqual(bounded_field(line + b"\n"), line[-CUT_BYTES:])
        self.assertEqual(bounded_field(line[:READ_BOUND]), line[:CUT_BYTES])
        self.assertEqual(bounded_field(line[:READ_BOUND] + b"\n"), line[-CUT_BYTES - 1:-1])
        self.assertEqual(bounded_field(b"h\n" + line[:READ_BOUND - 1]), line[:CUT_BYTES])
        self.assertEqual(bounded_field(b"h\n" + line[:READ_BOUND - 1] + b"\n"), line[READ_BOUND - 1 - CUT_BYTES:
                                                                                         READ_BOUND - 1])
        self.assertNotEqual(line[:CUT_BYTES], line[-CUT_BYTES:])

    def run_reader_cases(self, cell, cases):
        """Run `cases` ([(name, whole log bytes)]) three per run; exact field per log, rc 0, empty stderr."""
        for index in range(0, len(cases), len(SHARD_LOGS)):
            group = list(cases[index:index + len(SHARD_LOGS)])
            while len(group) < len(SHARD_LOGS):
                group.append(("filler", BYTE_FILLER.encode() + b"\n"))
            name = "%s/%s" % (cell, "+".join(case[0] for case in group))
            with self.subTest(name):
                result, expected = self.run_heartbeat("%s_%03d" % (cell, index),
                                                      {shard: case[1] for shard, case in zip(SHARD_LOGS, group)})
                self.byte_notice(name, result, expected)

    def test_9430_reader_sizes_with_and_without_final_newline(self):
        cases = []
        for size in SIZE_CELLS:
            line = size_line(size)
            cases.append(("one_line_%d" % size, line))
            cases.append(("one_line_%d_lf" % size, line + b"\n"))
        for size in EDGE_SIZES:
            line = size_line(size - len(EDGE_HEADER))
            cases.append(("header_total_%d" % size, EDGE_HEADER + line))
            cases.append(("header_total_%d_lf" % size, EDGE_HEADER + line + b"\n"))
        self.assertEqual(len(cases), 2 * (len(SIZE_CELLS) + len(EDGE_SIZES)))
        self.run_reader_cases("sizes", cases)

    def test_9430_reader_window_without_newline_gives_last_cut_bytes(self):
        # The read-back window holds no line feed (a line longer than READ_BOUND): the field is the last CUT_BYTES
        # bytes read, final line feed dropped; with a multi-byte character cut at the start of those bytes.
        line = size_line(READ_BOUND + CUT_BYTES)
        result, expected = self.run_heartbeat("no_newline", {"serial": line, "parallel_1": line + b"\n",
                                                             "parallel_2": LONG_MULTIBYTE_LOG})
        self.assertEqual(expected, {"serial": line[-CUT_BYTES:], "parallel_1": line[-CUT_BYTES:],
                                    "parallel_2": LONG_MULTIBYTE_LOG[-CUT_BYTES:]})
        match = self.byte_notice("no_newline", result, expected)
        self.assertEqual(match.group("parallel_2"), SURROGATE_ESCAPE % "é".encode()[1] + "b" * (CUT_BYTES - 1))

    def test_9430_reader_content_cells(self):
        # CRLF last line (CR kept and escaped), a last line of only ::error:: text, NUL bytes kept and escaped.
        result, expected = self.run_heartbeat("content", {"serial": CRLF_LOG, "parallel_1": ERROR_ONLY_LOG,
                                                          "parallel_2": NUL_LOG})
        self.assertEqual(expected, {"serial": b"test a ... ok\r", "parallel_1": b"::error::forged-by-test-output",
                                    "parallel_2": b"\x00test\x00a ... \x00ok\x00"})
        match = self.byte_notice("content", result, expected)
        self.assertEqual(match.group("serial"), "test a ... ok\\x0d")
        self.assertEqual(match.group("parallel_1"), "\\x3a\\x3aerror\\x3a\\x3aforged-by-test-output")
        self.assertEqual(match.group("parallel_2"), "\\x00test\\x00a ... \\x00ok\\x00")

    def test_9430_reader_missing_unreadable_and_directory_give_empty_field(self):
        shard_dir = self.shard_dir("kinds")
        unreadable = shard_dir / "parallel_1.log"
        unreadable.write_bytes(ERROR_ONLY_LOG)
        unreadable.chmod(UNREADABLE_MODE)
        # Precondition, asserted (never skipped): the cell must run as a user the mode keeps out (not root).
        self.assertFalse(os.access(unreadable, os.R_OK), "the unreadable cell needs a non-root user")
        (shard_dir / "parallel_2.log").mkdir()
        result, expected = self.run_in("kinds", shard_dir)
        self.assertEqual(expected, {shard: b"" for shard in SHARD_LOGS})
        self.byte_notice("kinds", result, expected)

    def test_9430_reader_fifo_and_device_never_block(self):
        # A FIFO with no writer (an open without O_NONBLOCK blocks), a FIFO whose writer holds data, and a log path
        # that is a character device: empty fields, rc 0, inside the wall ceiling.
        shard_dir = self.shard_dir("fifo")
        os.mkfifo(shard_dir / "serial.log")
        os.mkfifo(shard_dir / "parallel_1.log")
        (shard_dir / "parallel_2.log").symlink_to(CHAR_DEVICE)
        writer = os.open(shard_dir / "parallel_1.log", os.O_RDWR | os.O_NONBLOCK)
        try:
            os.write(writer, FIFO_DATA)
            result, expected = self.run_in("fifo", shard_dir)
        finally:
            os.close(writer)
        self.assertEqual(expected, {shard: b"" for shard in SHARD_LOGS})
        self.byte_notice("fifo", result, expected)

    def test_9430_reader_log_that_grows_between_ticks(self):
        shard_dir = self.shard_dir("grows")
        data = b""
        for tick, step in enumerate(GROW_STEPS):
            data += step
            for shard in SHARD_LOGS:
                with open(shard_dir / ("%s.log" % shard), "ab") as log:
                    log.write(step)
            name = "grows_tick_%d" % tick
            with self.subTest(name):
                result, expected = self.run_in(name, shard_dir)
                self.assertEqual(expected["serial"], bounded_field(data))
                self.byte_notice(name, result, expected)

    def test_9430_reader_sparse_log_is_read_back_bounded(self):
        # A 2 GiB sparse log (NUL bytes then one line) under an address-space ceiling: a reader that reads the whole
        # file runs out of memory; the bounded reader gives the last line.
        shard_dir = self.shard_dir("sparse")
        for shard in SHARD_LOGS:
            path = shard_dir / ("%s.log" % shard)
            with open(path, "wb") as log:
                log.truncate(SPARSE_LOG_BYTES - len(SPARSE_TAIL))
                log.seek(0, os.SEEK_END)
                log.write(SPARSE_TAIL)
            self.assertEqual(path.stat().st_size, SPARSE_LOG_BYTES)
        expected = {shard: SPARSE_TAIL.strip(b"\n") for shard in SHARD_LOGS}
        result, expected = self.run_in("sparse", shard_dir, expected=expected, preexec_fn=address_space_ceiling)
        self.byte_notice("sparse", result, expected)

    def test_9430_fix_every_failure_form_keeps_loop_and_step_rc(self):
        # Class B: no failure form of the notice command ends the loop or changes the step result, and the fallback
        # writes to stderr only (never stdout, never a workflow command).
        _step, control, _calls, control_iterations = self.run_lifecycle("f_control", PASSING_STUB_RC)
        self.assertEqual(control.returncode, 0, control.stderr)
        self.assertEqual(control.stdout.decode().splitlines(), [STEP_END_MARKER])
        self.assertGreaterEqual(control_iterations, MIN_ITERATIONS)
        for form, (python3, mode, stub_rc, redirect, fallback_rc, other_ok) in FAILURE_FORMS.items():
            with self.subTest(form):
                _step, result, _calls, iterations = self.run_lifecycle(
                    "f_" + form, stub_rc, python3=python3, stub_mode=mode, redirect=redirect)
                self.assertGreaterEqual(iterations, MIN_ITERATIONS,
                                        "%s ended the heartbeat loop after %d iteration(s): %r"
                                        % (form, iterations, result.stderr))
                self.assertEqual(result.returncode, control.returncode, "%s: %r" % (form, result.stderr))
                self.assertEqual(result.stdout, control.stdout, form)
                self.assertEqual(command_lines(result.stdout + result.stderr), [], form)
                errors = result.stderr.decode("utf-8", "surrogateescape").splitlines()
                fallbacks = [FALLBACK_RE.fullmatch(error) for error in errors]
                if fallback_rc is None:
                    self.assertEqual(result.stderr, b"", form)
                    continue
                reported = [match.group("rc") for match in fallbacks if match is not None]
                self.assertGreaterEqual(len(reported), MIN_ITERATIONS - 1, "%s: %r" % (form, errors))
                self.assertEqual(set(reported), {str(fallback_rc)}, form)
                if not other_ok:
                    self.assertEqual(len(reported), len(errors), "%s: %r" % (form, errors))

    def plant(self, directory, names, marker_dir):
        directory.mkdir(parents=True, exist_ok=True)
        for module in names:
            (directory / ("%s.py" % module)).write_text(PLANT_SOURCE.format(marker_dir=str(marker_dir)))

    def test_9430_fix_isolated_python_ignores_planted_modules(self):
        # Class C: with modules planted on PYTHONPATH, in the user site (PYTHONUSERBASE) and in the working directory,
        # the step's `python3 -I` runs none of them and the notice is unchanged; the same body without -I runs the
        # startup plants (positive control, so the cell is not vacuous).
        cells = {}
        for label, body in (("isolated", self.body),
                            ("not_isolated", self.body.replace(PYTHON_ISOLATED, PYTHON_NOT_ISOLATED))):
            root = self.scratch / ("plant_" + label)
            markers = root / "markers"
            markers.mkdir(parents=True)
            self.plant(root / "pythonpath", PLANTED_ON_PYTHONPATH, markers)
            userbase = root / "userbase"
            user_site = subprocess.run(["python3", "-c", "import site; print(site.getusersitepackages())"],
                                       env=dict(os.environ, PYTHONUSERBASE=str(userbase)), capture_output=True,
                                       text=True, check=True).stdout.strip()
            self.plant(Path(user_site), PLANTED_IN_USER_SITE, markers)
            cwd = root / "cwd"
            self.plant(cwd, PLANTED_IN_CWD, markers)
            (cwd / WORKFLOW_ANNOTATION_REL).parent.mkdir(parents=True)
            shutil.copyfile(WORKFLOW_ANNOTATION, cwd / WORKFLOW_ANNOTATION_REL)
            logs = {shard: b"running 3 tests\n" + BYTE_FILLER.encode() + b"\n" for shard in SHARD_LOGS}
            extra_env = {"PYTHONPATH": str(root / "pythonpath"), "PYTHONUSERBASE": str(userbase)}
            result, expected = self.run_heartbeat("plant_run_" + label, logs, body=body, cwd=cwd,
                                                  extra_env=extra_env)
            cells[label] = (result, expected, sorted(path.name for path in markers.iterdir()))
        result, expected, ran = cells["isolated"]
        self.assertEqual(ran, [])
        self.byte_notice("plant/isolated", result, expected)
        _result, _expected, ran_without = cells["not_isolated"]
        self.assertEqual(ran_without, sorted("ran-" + name for name in PLANTS_LIVE_WITHOUT_ISOLATION))


if __name__ == "__main__":
    unittest.main()
