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
data field equals, byte for byte, the text ``tail -n 1 <log> | cut -c1-90`` selects (bash command substitution
drops NUL bytes and trailing newlines, so the oracle does too).

The test parses ci.yml with PyYAML (required, as in test_pgbouncer_smoke_compose_4734.py), takes the
``run`` text of the one step that holds the ``[#6344] progress`` heartbeat, cuts the body of its
``( while true; do ... done ) &`` loop (without the ``sleep``) and runs that body with bash against synthetic
logs in a scratch directory. Lines are split with ``str.splitlines`` (a superset of the runner's CR / LF /
CRLF split); a line is a command when it starts with ``::`` after leading whitespace (runner TryParseV2) or
holds ``##[`` anywhere (runner TryParse).

Run: python3 -m unittest scripts/ci/tests/test_ci_progress_notice_9430.py
"""

import os
import re
import shlex
import shutil
import subprocess
import tempfile
import time
import unittest
from pathlib import Path

import yaml  # required: the guard fails, never skips, without it

REPO = Path(__file__).resolve().parents[3]
CI_YML = REPO / ".github" / "workflows" / "ci.yml"
SCRATCH_PARENT = REPO / ".local-runs"

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
CUT_BYTES = 90  # the heartbeat keeps the first 90 bytes of each last line (`cut -c1-90`, GNU byte semantics)
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


def heartbeat_body():
    """The heartbeat loop body (without its sleep) of the one ci.yml step that holds the progress notice."""
    workflow = yaml.safe_load(CI_YML.read_text())
    runs = [
        step["run"]
        for job in workflow["jobs"].values()
        for step in job.get("steps", [])
        if HEARTBEAT_MARKER in (step.get("run") or "")
    ]
    if len(runs) != 1:
        raise AssertionError("expected one ci.yml step with %r, found %d" % (HEARTBEAT_MARKER, len(runs)))
    lines = runs[0].split("\n")
    for start, line in enumerate(lines):
        if line.strip() != LOOP_OPEN:
            continue
        end = next(i for i in range(start + 1, len(lines)) if lines[i].strip() == LOOP_CLOSE)
        body = [body_line for body_line in lines[start + 1:end] if not body_line.strip().startswith(SLEEP_PREFIX)]
        if any(HEARTBEAT_MARKER in body_line for body_line in body):
            return "\n".join(body)
    raise AssertionError("no heartbeat loop holds %r" % HEARTBEAT_MARKER)


def unescape(text):
    """Undo the workflow_annotation escapes once (``\\\\``, ``\\xHH``, ``\\uHHHH``) and return the bytes."""
    def one(match):
        if match.group(1):
            return "\\"
        return chr(int(match.group(2) or match.group(3), 16))
    return ESCAPE_RE.sub(one, text).encode("utf-8", "surrogateescape")


def selected_text(log_path):
    """Oracle: what `$(tail -n 1 <log> | cut -c1-90)` hands the heartbeat (NUL bytes and trailing LFs dropped)."""
    tail = subprocess.run(["tail", "-n", "1", str(log_path)], capture_output=True, check=False).stdout
    cut = subprocess.run(["cut", "-c1-%d" % CUT_BYTES], input=tail, capture_output=True, check=False).stdout
    return cut.replace(b"\x00", b"").rstrip(b"\n")


def command_lines(output):
    """Every line the runner could parse as a workflow command (v2 after leading whitespace, v1 anywhere)."""
    text = output.decode("utf-8", "surrogateescape")
    return [line for line in text.splitlines() if line.lstrip().startswith(V2_COMMAND) or V1_COMMAND in line]


class ProgressNotice(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.body = heartbeat_body()
        SCRATCH_PARENT.mkdir(exist_ok=True)
        cls.scratch = Path(tempfile.mkdtemp(prefix="progress-notice-9430-", dir=str(SCRATCH_PARENT)))

    @classmethod
    def tearDownClass(cls):
        if str(cls.scratch).startswith(str(SCRATCH_PARENT)):
            shutil.rmtree(cls.scratch, ignore_errors=True)

    def run_heartbeat(self, name, logs):
        """Write `logs` ({shard: bytes or None for a missing file}), run the loop body once, return the output."""
        shard_dir = self.scratch / re.sub(r"[^A-Za-z0-9_]", "_", name)
        shard_dir.mkdir()
        for shard, content in logs.items():
            if content is not None:
                (shard_dir / ("%s.log" % shard)).write_bytes(content)
        env = dict(os.environ, LC_ALL="C.UTF-8")
        script = "sd=%s\n%s\n" % (shlex.quote(str(shard_dir)), self.body)
        started = time.monotonic()
        result = subprocess.run(["bash", "-c", script], cwd=str(REPO), env=env, capture_output=True,
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

    def test_empty_and_missing_logs(self):
        result, expected = self.run_heartbeat("empty", {"serial": b"", "parallel_1": None, "parallel_2": b"\n"})
        self.assertEqual(expected, {shard: b"" for shard in SHARD_LOGS})
        self.assert_one_notice("empty", result, expected)


if __name__ == "__main__":
    unittest.main()
