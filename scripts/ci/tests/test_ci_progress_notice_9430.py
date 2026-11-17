#!/usr/bin/env python3
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""Pin the shard progress notice of ci.yml against workflow-command injection (#9430, class of #9365).

Class: text a pull request controls (the last line of a shard test log) is echoed into a runner
workflow-command line. A line break inside that text ends the notice and the runner parses the rest as a
new command made of pull-request data (``::warning::``, ``::add-mask::``, ``::stop-commands::``, ``##[...]``).

Invariant for all inputs: whatever bytes the three shard logs hold, the progress heartbeat writes exactly one
line the runner can parse as a command; it starts with the fixed ``::notice::`` prefix, holds no ``%`` (nothing
the runner percent-decodes), and after one unescape of the ``scripts/ci/workflow_annotation.py`` escapes each
data field equals, byte for byte, the first 90 bytes of the log's last line (``tail -n 1 <log> | cut -b1-90``; bash
command substitution drops NUL bytes and trailing newlines, so the oracle does too). The oracle is computed in Python
from the log bytes (``last_line[:CUT_BYTES]``), never by running the host's ``cut``: uutils ``cut`` (the ubuntu-26.04
runner) and BSD ``cut`` cut characters for ``-c`` in a UTF-8 locale, so only ``-b`` gives the same bytes everywhere.

The test parses ci.yml with PyYAML (required, as in test_pgbouncer_smoke_compose_4734.py), takes the
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
the loop keeps going, the step's exit code is unchanged and the fallback writes to stderr only, never a command.

Fix-r1 cells: the exact heartbeat text (``cut -b1-90`` on each of the three tails, ``python3 -I -c``, the fallback
that cannot fail); a ``cut`` stub that cuts characters for ``-c`` in a UTF-8 locale (uutils / BSD behaviour) placed
first on PATH; planted ``sitecustomize``, ``usercustomize``, ``os`` and ``workflow_annotation`` modules on
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
import signal

import yaml  # required: the guard fails, never skips, without it

REPO = Path(__file__).resolve().parents[3]
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


wa = load_workflow_annotation()

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
CUT_BYTES = 90  # the heartbeat keeps the first 90 bytes of each last line (`cut -b1-90`: bytes on GNU, uutils, BSD)
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
NUL_BYTE = 0x00  # excluded from the generative cell: argv is a C string, it cannot carry NUL
BYTE_VALUES = 256
PRINTABLE_ASCII = range(0x20, 0x7F)
EXPECTED_LINES = 1

# Fix-r1 (class A, B, C): the exact heartbeat text. A `-c` cut is byte-exact only on GNU cut, so a `-c` mutant would
# survive on a GNU host without the exact-string cell; the char-cut stub cell kills it on any host.
TAIL_CUT = '"$(tail -n 1 "$sd/%%s.log" 2>/dev/null | cut -b1-%d)"' % CUT_BYTES
CHAR_CUT = "cut -c"
PYTHON_ISOLATED = "python3 -I -c '"
PYTHON_NOT_ISOLATED = "python3 -c '"
FALLBACK_TEXT = '|| { echo "[#6344] progress notice not written: python3 exited $?" >&2 || true; }'
FALLBACK_STDERR = ">&2"
NOTICE_TEMPLATE = "[#6344] progress | serial: {s} | parallel_1: {p1} | parallel_2: {p2}"
NOTICE_MAX_CHARS_TEXT = "max_chars=2 * wa.MAX_ANNOTATION_CHARS"
NOTICE_MAX_CHARS = 2 * wa.MAX_ANNOTATION_CHARS  # the bound the heartbeat passes to annotation()

# Class D: the exact worst case. Each field is CUT_BYTES of the byte whose escape is longest; the line is the empty
# template plus that growth for every field, and must stay under NOTICE_MAX_CHARS with no cut mark.
FIRST_NON_NUL_BYTE = 0x01
BYTE_ESCAPE_CHARS = {value: len(wa.safe_value(bytes([value]).decode("utf-8", "surrogateescape")))
                     for value in range(FIRST_NON_NUL_BYTE, BYTE_VALUES)}
MAX_ESCAPE_CHARS = max(BYTE_ESCAPE_CHARS.values())
WORST_BYTE = min(value for value, chars in BYTE_ESCAPE_CHARS.items() if chars == MAX_ESCAPE_CHARS)
TEMPLATE_LINE_CHARS = len(wa.annotation("notice", wa.render(NOTICE_TEMPLATE, s="", p1="", p2=""),
                                        max_chars=NOTICE_MAX_CHARS))
WORST_LINE_CHARS = TEMPLATE_LINE_CHARS + len(SHARD_LOGS) * CUT_BYTES * MAX_ESCAPE_CHARS

# Cell (d): the heartbeat loop under the step's own shell options, with a python3 stub that fails.
STEP_SHELL = "bash"
STEP_SHELL_COMMAND = ("bash", "--noprofile", "--norc", "-eo", "pipefail")  # GitHub's command for `shell: bash`
STEP_OPTIONS_LINE = "set -euo pipefail"  # first line of the step's run text
HB_PID_LINE = "hb=$!"
HB_KILL_LINE = 'kill "$hb" 2>/dev/null || true'
HB_WAIT_LINE = 'wait "$hb" 2>/dev/null || true'
MIN_ITERATIONS = 3
# await-ticks waits for the tails of one iteration past MIN_ITERATIONS: the loop is sequential, so the tails of
# iteration k + 1 start only after the python3 call and fallback of iteration k are done, and the kill cannot
# land between the last counted tail and its python3 call.
AWAIT_ITERATIONS = MIN_ITERATIONS + 1
FAILING_STUB_RC = 1
PASSING_STUB_RC = 0
SHELL_SIGNAL_RC_BASE = 128  # bash reports a child killed by signal N as 128 + N
COMMAND_NOT_FOUND_RC = 127
STUB_TICK_SECS = 0.02  # the stub sleep, for `sleep 300`
AWAIT_DEADLINE_SECS = 5.0
STEP_END_MARKER = "step-reached-end"
FALLBACK_RE = re.compile(r"\[#6344\] progress notice not written: python3 exited (?P<rc>\d+)")
# Every python3 call writes one line to HB_CALLS; the tail wrapper counts loop iterations (3 tails each) in every
# form, python3 missing included.
PYTHON3_STUB = """#!{exe} -I
import os, signal, sys
with open(os.environ["HB_CALLS"], "a") as calls:
    calls.write("call\\n")
if os.environ["HB_STUB_MODE"] == "signal":
    os.kill(os.getpid(), signal.SIGKILL)
sys.exit(int(os.environ["HB_STUB_RC"]))
"""
TAIL_STUB = """#!{exe} -I
import os, sys
with open(os.environ["HB_TAILS"], "a") as tails:
    tails.write("tail\\n")
os.execv(os.environ["HB_REAL_TAIL"], ["tail", *sys.argv[1:]])
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
PATH_TOOLS = ("cut",)  # linked into the stub PATH; tail is wrapped, sleep stubbed, the rest are bash builtins

# Class A: a cut that behaves like uutils / BSD cut (characters for -c in a UTF-8 locale, bytes for -b).
CHAR_CUT_STUB = """#!{exe} -I
import os, re, signal, sys
# A native cut dies silently on SIGPIPE when its reader is gone (the killed heartbeat loop); Python ignores it.
signal.signal(signal.SIGPIPE, signal.SIG_DFL)
match = re.fullmatch(r"-([bc])1-([0-9]+)", sys.argv[1]) if len(sys.argv) == 2 else None
if match is None:
    sys.stderr.write("cut stub: unsupported arguments %r\\n" % (sys.argv[1:],))
    sys.exit(2)
mode, width = match.group(1), int(match.group(2))
# LC_ALL, then LANG: the stub interpreter itself sets LC_CTYPE=C.UTF-8 under a C or unset locale (PEP 538 coercion).
locale = os.environ.get("LC_ALL") or os.environ.get("LANG") or ""
utf8 = re.search(r"utf-?8", locale, re.IGNORECASE) is not None
data = sys.stdin.buffer.read()
lines = data.split(b"\\n")
if data.endswith(b"\\n"):
    lines.pop()
for line in lines:
    if mode == "c" and utf8:
        line = line.decode("utf-8", "surrogateescape")[:width].encode("utf-8", "surrogateescape")
    else:
        line = line[:width]
    sys.stdout.buffer.write(line + b"\\n")
"""

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
    """The one ci.yml step that holds the progress heartbeat, as parsed by PyYAML."""
    workflow = yaml.safe_load(CI_YML.read_text())
    steps = [step for job in workflow["jobs"].values() for step in job.get("steps", [])
             if HEARTBEAT_MARKER in (step.get("run") or "")]
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


def selected_text(log_path):
    """Oracle, in Python from the bytes: what `$(tail -n 1 <log> | cut -b1-90)` hands the heartbeat, i.e. the first
    CUT_BYTES bytes of the last line with NUL bytes and trailing LFs dropped. A missing log selects nothing."""
    data = log_path.read_bytes() if log_path.exists() else b""
    return last_line(data)[:CUT_BYTES].replace(b"\x00", b"").rstrip(b"\n")


def host_cut(data, locale_env):
    """What the host's `tail -n 1 | cut -b1-90` selects for `data` in one locale (cross-check, never the oracle)."""
    tail = subprocess.run(["tail", "-n", "1"], input=data, env=locale_env, capture_output=True, check=True).stdout
    cut = subprocess.run(["cut", "-b1-%d" % CUT_BYTES], input=tail, env=locale_env, capture_output=True,
                         check=True).stdout
    return cut.replace(b"\x00", b"").rstrip(b"\n")


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

    @classmethod
    def tearDownClass(cls):
        if str(cls.scratch).startswith(str(SCRATCH_PARENT)):
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

    def run_heartbeat(self, name, logs, locale="C.UTF-8", body=None, cwd=REPO, extra_env=None):
        """Write `logs` ({shard: bytes or None for a missing file}), run the loop body once, return the output.

        `body` defaults to the step's own loop body; `extra_env` is merged over the locale environment."""
        shard_dir = self.scratch / re.sub(r"[^A-Za-z0-9_]", "_", name)
        shard_dir.mkdir()
        for shard, content in logs.items():
            if content is not None:
                (shard_dir / ("%s.log" % shard)).write_bytes(content)
        env = self.locale_env(locale)
        env.update(extra_env or {})
        script = "sd=%s\n%s\n" % (shlex.quote(str(shard_dir)), self.body if body is None else body)
        started = time.monotonic()
        result = subprocess.run(["bash", "-c", script], cwd=str(cwd), env=env, capture_output=True,
                                timeout=RUN_CEILING_SECS, check=False)
        elapsed = time.monotonic() - started
        self.assertLess(elapsed, RUN_CEILING_SECS, name)
        expected = {shard: selected_text(shard_dir / ("%s.log" % shard)) for shard in SHARD_LOGS}
        return result, expected

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

    def test_9430_fix_host_cut_b_agrees_with_python_oracle_in_every_locale(self):
        # Cross-check only: the oracle is Python; the host's `cut -b` must select the same bytes in every locale.
        lines = [case[1] for case in multibyte_cases()] + [bytes([LONE_BYTE]) * (2 * CUT_BYTES)]
        for locale in LOCALES:
            env = self.locale_env(locale)
            for index, line in enumerate(lines):
                data = b"running 3 tests\n" + line + b"\n"
                with self.subTest(locale=locale, line=index):
                    self.assertEqual(host_cut(data, env), last_line(data)[:CUT_BYTES])

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
        # mark); one byte more per field (bound + 1 input byte) changes nothing, because only CUT_BYTES reach python.
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
            self.fail("%s: stdout is not valid UTF-8 (%s): %r" % (name, error, result.stdout))
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
        # Every byte value but NUL (argv is a C string and cannot carry it; bash drops NUL from a command
        # substitution, covered by OTHER_LINES["nul_then_cr"]) at the start, middle and end of a line. Exact data
        # round trip, and every character of the field is printable ASCII: a lone byte is never written raw.
        cases = []
        for value in range(BYTE_VALUES):
            if value == NUL_BYTE:
                continue
            for position, line, _field in lone_byte_cases(value):
                cases.append(("0x%02x_%s" % (value, position), line, None))
        self.assertEqual(len(cases), (BYTE_VALUES - 1) * len(POSITIONS))
        self.run_byte_cells("g", cases, GENERATIVE_LOCALES)

    def run_lifecycle(self, name, stub_rc, python3=PY_STUB, stub_mode="exit", redirect=CLOSE_NONE):
        """Run the step's heartbeat start/kill/reap lines under the step's shell options with stubbed python3/sleep.

        PATH holds only the stub directory (python3 per `python3`, a counting tail wrapper, sleep, await-ticks and
        a link to the host cut). `redirect` is applied to the call of the heartbeat function (closed stderr or
        stdout reach the loop and the notice command). Returns (step, result, python3 calls, loop iterations)."""
        step = self.step
        loop, kill_line, wait_line = heartbeat_lifecycle(step["run"])
        cell_dir = self.scratch / name
        stub_dir = cell_dir / "bin"
        stub_dir.mkdir(parents=True)
        stubs = [("sleep", SLEEP_STUB), ("await-ticks", AWAIT_STUB), ("tail", TAIL_STUB)]
        if python3 == PY_STUB:
            stubs.append(("python3", PYTHON3_STUB))
        for stub_name, source in stubs:
            stub = stub_dir / stub_name
            stub.write_text(source.format(exe=sys.executable))
            stub.chmod(0o755)
        if python3 == PY_REAL:
            (stub_dir / "python3").symlink_to(sys.executable)
        for tool in PATH_TOOLS:
            (stub_dir / tool).symlink_to(shutil.which(tool))
        calls = cell_dir / "calls"
        tails = cell_dir / "tails"
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
        env = dict(os.environ, PATH=str(stub_dir), HB_CALLS=str(calls), HB_TAILS=str(tails),
                   HB_REAL_TAIL=shutil.which("tail"), HB_STUB_RC=str(stub_rc), HB_STUB_MODE=stub_mode,
                   HB_TICK=str(STUB_TICK_SECS), HB_DEADLINE=str(AWAIT_DEADLINE_SECS),
                   HB_MIN=str(AWAIT_ITERATIONS * len(SHARD_LOGS)))
        env["HB_CALLS_WAIT"] = env["HB_TAILS"]
        result = subprocess.run([shutil.which(STEP_SHELL_COMMAND[0]), *STEP_SHELL_COMMAND[1:], str(script)],
                                cwd=str(REPO), env=env, capture_output=True, timeout=RUN_CEILING_SECS, check=False)
        count = calls.read_text().count("\n") if calls.exists() else 0
        iterations = (tails.read_text().count("\n") if tails.exists() else 0) // len(SHARD_LOGS)
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

    def test_9430_fix_heartbeat_text_pins_cut_b_isolated_python_and_fallback(self):
        # Exact strings: a `-c` cut, a python3 without -I or a fallback that can fail is red here on every host.
        notice_lines = [line.strip() for line in self.body.split("\n") if HEARTBEAT_MARKER in line
                        and not line.strip().startswith("#")]
        self.assertEqual(len(notice_lines), 1, notice_lines)
        line = notice_lines[0]
        self.assertTrue(line.startswith(PYTHON_ISOLATED), line[:40])
        self.assertIn(NOTICE_TEMPLATE, line)
        self.assertIn(NOTICE_MAX_CHARS_TEXT, line)
        for shard in SHARD_LOGS:
            self.assertEqual(line.count(TAIL_CUT % shard), 1, shard)
        self.assertNotIn(CHAR_CUT, self.body)
        self.assertTrue(line.endswith(FALLBACK_TEXT), line[-120:])
        fallback = line[-len(FALLBACK_TEXT):]
        self.assertEqual(fallback.count(FALLBACK_STDERR), 1)
        self.assertNotIn(V2_COMMAND, fallback)
        self.assertNotIn(V1_COMMAND, fallback)

    def test_9430_fix_char_cutting_cut_first_on_path(self):
        # Class A: with a cut that cuts characters for -c in a UTF-8 locale (uutils on ubuntu-26.04, BSD on macOS)
        # first on PATH, every multibyte cell keeps exactly the first CUT_BYTES bytes, in every locale.
        stub_dir = self.scratch / "char_cut_bin"
        stub_dir.mkdir()
        stub = stub_dir / "cut"
        stub.write_text(CHAR_CUT_STUB.format(exe=sys.executable))
        stub.chmod(0o755)
        extra_env = {"PATH": "%s:%s" % (stub_dir, os.environ["PATH"])}
        cases = multibyte_cases()
        for locale in LOCALES:
            for index in range(0, len(cases), len(SHARD_LOGS)):
                group = cases[index:index + len(SHARD_LOGS)]
                while len(group) < len(SHARD_LOGS):
                    group.append(("filler", BYTE_FILLER.encode(), BYTE_FILLER))
                name = "charcut/%s/%s" % (locale, "+".join(case[0] for case in group))
                logs = {shard: b"running 3 tests\n" + case[1] + b"\n" for shard, case in zip(SHARD_LOGS, group)}
                with self.subTest(name):
                    result, expected = self.run_heartbeat("charcut_%s_%03d" % (locale, index), logs, locale,
                                                          extra_env=extra_env)
                    match = self.byte_notice(name, result, expected)
                    for shard, case in zip(SHARD_LOGS, group):
                        self.assertEqual(match.group(shard), case[2], "%s: %s field" % (name, shard))

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
