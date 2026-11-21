#!/usr/bin/env python3
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""Pin the CI workflow-command escape class (#9365, same class as #9278 and #8634).

Class: a CI script prints a path, name, label or exception text into a workflow-command line
(``::error::``, ``::warning::``, ``::notice::``, ``::group::``) or writes it into a ``$GITHUB_OUTPUT`` /
``$GITHUB_ENV`` file without escaping.

Invariant for all inputs: no byte of a variable value can start a new workflow command, end the annotation
line, alter the command's properties or add a second entry to an output/env file; every annotation is exactly
one line, bounded by ``LINE_BOUND_CHARS``, and built through the one shared module
``scripts/ci/workflow_annotation.py``.

Two arms:

* ``RatchetTests`` parse every ``.py`` under ``scripts`` and ``.github`` (and every ``python3 ... <<`` heredoc
  in the workflow YAML) with ``ast``. A string that begins a workflow command (``::error`` ...) must be a pure
  literal, or every variable field in it must come out of the shared module. The allowlist is empty.
  Blind spots (stated, not hidden): a command built in another module and passed in; a command prefix kept in a
  named constant is itself a failure (it cannot be traced), as is every unrecognised way of building the
  string (``str.join``, a dict ``%`` operand, ``bytes``); stdout piped into ``>> $GITHUB_ENV`` by the shell;
  shell ``echo "::error::$var"`` lines (listed on the issue, not python); ``exec``/``eval`` text.
* ``Behaviour`` cells run each script the way the workflow does (``python3 -I <file>``) or call the real
  function in-process, with the hostile corpus below, and assert that exactly the expected number of output
  lines start with ``::`` (counted with ``str.splitlines``, the strictest line break set), that each is bounded,
  and that no variable byte reached a second ``::``.

The oracle for the escape rule is written out here independently of the shared module.

Run: python3 -m unittest scripts/ci/tests/test_ci_annotation_escape_9365.py
"""

import ast
import contextlib
import errno
import importlib.util
import io
import os
import re
import shutil
import subprocess
import sys
import tempfile
import textwrap
import time
import unittest
from pathlib import Path
from unittest import mock

REPO = Path(__file__).resolve().parents[3]
CI_DIR = REPO / "scripts" / "ci"
SCRATCH_ROOT = REPO / ".local-runs" / "ci-annotation-escape-9365"
SCAN_ROOTS = (REPO / "scripts", REPO / ".github")
SHARED_MODULE_NAME = "workflow_annotation.py"
# single_line is the base-selector's own copy of env_file_value (see test_single_line_matches_env_file_value_9365);
# version_text is prune_runner_tmp's own copy of safe_value for the version refusal, which runs before the shared
# module is loaded (see test_local_version_escape_equals_safe_value_for_every_code_point_9365)
SHARED_FIELD_FUNCTIONS = frozenset({"safe_text", "property_value", "annotation", "log_line", "env_file_value", "single_line",
                                    "version_text"})
# v2 form: "::name" at a line start; v1 form: "##[" anywhere in a line (actions/runner ActionCommand.TryParse uses
# message.IndexOf("##[") with no trim; TryParseV2 uses message.TrimStart().StartsWith("::"))
COMMAND_RE = re.compile(r"(?m)^::[a-z][a-z-]*|##\[")
HEREDOC_RE = re.compile(r"python3?[^\n<]*<<-?\s*'?(\w+)'?[^\n]*\n(.*?)\n\s*\1\s*$", re.S | re.M)

LINE_BOUND_CHARS = 1000
HUGE_VALUE_CHARS = 100_001
HUGE_WALL_CLOCK_SECS = 20.0
SUBPROCESS_TIMEOUT_SECS = 60

# #9705: a file system may refuse a name that is not UTF-8 (APFS: errno 92, ``errno.EILSEQ``); these are the bytes of
# that row. Its escaped text is written out by hand below (``NON_UTF8_NAME_ESCAPED``), never computed from the code.
NON_UTF8_NAME_BYTES = b"bad\xff\xfe::x"
HOSTILE = {
    "command": "::error::x",
    "set_output": "%0A::set-output name=pwn::1",
    "percent_cr": "a%0Db",
    "raw_newline": "a\n::error::injected",
    "raw_cr": "a\r::error::injected",
    "colons": "a::b",
    "percent": "100%25",
    "long_name": "n" * 4096,
    "non_utf8": os.fsdecode(NON_UTF8_NAME_BYTES),
    "separators": "a\u2028::error::b\x85::error::c",
}
FILE_NAME_CORPUS = ("command", "raw_newline", "raw_cr", "colons", "percent", "non_utf8")
FILE_NAME_CORPUS_UTF8 = frozenset(FILE_NAME_CORPUS) - {"non_utf8"}  # the rows every file system takes
# ``\udcff``/``\udcfe`` are the surrogate-escaped bytes 0xff/0xfe, ``::`` keeps its second colon and escapes the first
NON_UTF8_NAME_ESCAPED = "bad\\udcff\\udcfe\\x3a:x"
INTERPRETER_PLACEHOLDER = "<interpreter>"
PRUNE_WARNING_FLOOR_GIB = 100000000
# #9705 (review r1, L1): the whole warning line of every row, written out by hand. The prefix and suffix are the fixed
# text of the warning in ``prune_runner_artifacts.py`` with the floor above; the middle is the escaped root name.
PRUNE_WARNING_PREFIX = "::warning::free space under "
PRUNE_WARNING_SUFFIX = " is below the 100000000 GiB floor and no idle sibling target is left to evict"
PRUNE_WARNING_ROOT_ESCAPED = {
    "command": "home-\\x3a:error\\x3a:x",
    "raw_newline": "home-a\\x0a\\x3a:error\\x3a:injected",
    "raw_cr": "home-a\\x0d\\x3a:error\\x3a:injected",
    "colons": "home-a\\x3a:b",
    "percent": "home-100\\x2525",
    "non_utf8": "home-" + NON_UTF8_NAME_ESCAPED,
}
# #9705 (review r1, L2): the three spellings of an interpreter and the text a hand-written table masks (see
# ``HostProbePins9705``); all invented paths, so the table does not depend on the host.
FAKE_EXECUTABLE = "/opt/h/bin/python3.12"
FAKE_REAL_EXECUTABLE = "/opt/h/Cellar/3.12.16/bin/python3.12.16"
FAKE_REAL_DIRECTORY = "/opt/h/Cellar/3.12.16/bin"
FAKE_DIRECTORY_SPELLING = "/opt/h/Cellar/3.12.16/bin/python3.12"
FAKE_COLON_EXECUTABLE = "/opt/a\\x3a:b/bin/python3.12"
FAKE_SPELLINGS = frozenset({FAKE_EXECUTABLE, FAKE_REAL_EXECUTABLE, FAKE_DIRECTORY_SPELLING, FAKE_COLON_EXECUTABLE})


def oracle_escape(text):
    """The escape rule of #8634 (finding L4), restated: what a variable value must look like in a message.

    #9365 r3: a ``:`` followed by ``:`` (so no run of colons keeps a ``::``), a ``#`` that precedes ``#`` or ``[``, and
    a ``[`` that follows ``#`` (so no ``##[`` forms inside) are escaped; a ``#`` that is the last character is NOT (``C#``
    stays ``C#``). A leading ``[`` stays (``[Errno 13]``); a ``##[`` that forms across a boundary is broken where the
    line is finished (annotation, render, join, log_line), and the stream ratchet keeps literals ending in ``##`` out.
    """
    out = []
    text = str(text)
    for index, char in enumerate(text):
        code = ord(char)
        after = text[index + 1:index + 2]
        before = text[index - 1:index] if index else ""
        if char == ":" and after == ":":
            out.append("\\x3a")
        elif char == "#" and after in ("#", "["):
            out.append("\\x23")
        elif char == "[" and before == "#":
            out.append("\\x5b")
        elif char == "\\":
            out.append("\\\\")
        elif char == "%":
            out.append("\\x25")
        elif code < 0x20 or 0x7F <= code <= 0x9F:
            out.append("\\x%02x" % code)
        elif 0xD800 <= code <= 0xDFFF or code in (0x2028, 0x2029):
            out.append("\\u%04x" % code)
        else:
            out.append(char)
    return "".join(out)


def scratch_dir(label):
    SCRATCH_ROOT.mkdir(parents=True, exist_ok=True)
    return Path(tempfile.mkdtemp(prefix=label + "-", dir=str(SCRATCH_ROOT)))


def fs_accepts_non_utf8_names(directory, mkdir=os.mkdir, rmdir=os.rmdir):
    """Probe once whether ``directory`` takes a directory name that is not UTF-8 (#9705); the probe leaves nothing.

    False only for ``errno.EILSEQ`` (what APFS raises, errno 92); every other ``OSError`` propagates, so a host that
    takes the name but fails for another reason (permission, space) does not silently pick the weaker form. ``mkdir``
    and ``rmdir`` are parameters so a test can inject each outcome."""
    probe = os.path.join(os.fsencode(str(directory)), NON_UTF8_NAME_BYTES)
    try:
        mkdir(probe)
    except OSError as err:
        if err.errno == errno.EILSEQ:
            return False
        raise
    rmdir(probe)
    return True


def row_forms(accepts):
    """For each row of ``FILE_NAME_CORPUS``: True when the row runs on a made directory (the form before #9705), False
    when the file system refuses the row's name and the row runs without a directory."""
    return {key: accepts or key != "non_utf8" for key in FILE_NAME_CORPUS}


def interpreter_spellings(executable=None, realpath=os.path.realpath):
    """The spellings of the interpreter path a child run can print: ``executable`` (default ``sys.executable``), its
    realpath, and its directory's realpath with the file name kept (a ``-S`` child reports that under Homebrew),
    each raw and as the oracle escapes it."""
    executable = sys.executable if executable is None else executable
    directory, file_name = os.path.split(executable)
    spellings = {executable, realpath(executable), os.path.join(realpath(directory), file_name)}
    return spellings | {oracle_escape(spelling) for spelling in spellings}


EXECUTABLE_FIELD_RE = re.compile(r"((?:^|\s)executable=)([^\r\n]*)", re.M)


def mask_interpreter(text, spellings=None):
    """``text`` with the value of each ``executable=`` field (the field ``prune_runner_tmp.py`` prints, whose value runs
    to the end of the line) replaced by one placeholder when the whole value is one of ``spellings`` (default
    ``interpreter_spellings()``); every other byte is untouched (#9705)."""
    spellings = interpreter_spellings() if spellings is None else spellings

    def replace(match):
        return match.group(1) + INTERPRETER_PLACEHOLDER if match.group(2) in spellings else match.group(0)

    return EXECUTABLE_FIELD_RE.sub(replace, text)


def load_module(path, name):
    spec = importlib.util.spec_from_file_location(name, str(path))
    module = importlib.util.module_from_spec(spec)
    sys.path.insert(0, str(Path(path).parent))
    try:
        spec.loader.exec_module(module)
    finally:
        sys.path.pop(0)
    return module


def run_script(script, args, env=None, timeout=SUBPROCESS_TIMEOUT_SECS, isolated=True):
    """Run ``python3 -I script args`` the way the workflows do; return (rc, stdout, stderr) decoded losslessly."""
    full_env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "LANG": "C.UTF-8"}
    full_env.update(env or {})
    flags = ["-I"] if isolated else []
    proc = subprocess.run([sys.executable, *flags, str(script), *args], capture_output=True, env=full_env,
                          timeout=timeout, check=False)
    return (proc.returncode, proc.stdout.decode("utf-8", "surrogateescape"),
            proc.stderr.decode("utf-8", "surrogateescape"))


class CommandAssertions(unittest.TestCase):
    def command_lines(self, text):
        return [line for line in text.splitlines() if line.startswith("::")]

    def assert_commands(self, text, kinds, hostile_oracle=None):
        """Exactly ``kinds`` commands, each one line, bounded, no second ``::``, escaped value present."""
        commands = self.command_lines(text)
        self.assertEqual(len(commands), len(kinds), text[:3000])
        for line, kind in zip(commands, kinds):
            self.assertTrue(line.startswith("::" + kind), line[:300])
            self.assertLessEqual(len(line), LINE_BOUND_CHARS, len(line))
            self.assertEqual(line.count("::"), 2, line[:300])  # the command's own two, nothing else
            self.assertNotRegex(line, r"%[0-9A-Fa-f]{2}")
        if hostile_oracle is not None:
            self.assertIn(hostile_oracle, commands[0])


class RatchetTests(unittest.TestCase):
    """No workflow-command string carries a variable field that did not come out of the shared module."""

    @staticmethod
    def python_files():
        for root in SCAN_ROOTS:
            for path in sorted(root.rglob("*.py")):
                parts = set(path.relative_to(REPO).parts)
                if parts & {"tests", "fixtures", "__pycache__", "node_modules", ".local-runs"}:
                    continue
                if path.name.startswith("test_") or path.name == SHARED_MODULE_NAME:
                    continue
                yield path

    @staticmethod
    def yaml_heredocs():
        for path in sorted((REPO / ".github").rglob("*.y*ml")):
            text = path.read_text(encoding="utf-8", errors="replace")
            for match in HEREDOC_RE.finditer(text):
                yield path, text[: match.start(2)].count("\n") + 1, textwrap.dedent(match.group(2))

    @staticmethod
    def is_shared_call(node):
        if not isinstance(node, ast.Call):
            return False
        func = node.func
        name = func.id if isinstance(func, ast.Name) else func.attr if isinstance(func, ast.Attribute) else None
        return name in SHARED_FIELD_FUNCTIONS

    def field_ok(self, node):
        return isinstance(node, ast.Constant) or self.is_shared_call(node)

    def violations(self, tree, label, line_offset=0):
        parents = {}
        for parent in ast.walk(tree):
            for child in ast.iter_child_nodes(parent):
                parents[child] = parent
        found = []

        def bad(node, why):
            found.append("%s:%d %s" % (label, node.lineno + line_offset, why))

        for node in ast.walk(tree):
            if not (isinstance(node, ast.Constant) and isinstance(node.value, str)
                    and COMMAND_RE.search(node.value)):
                continue
            parent = parents.get(node)
            if isinstance(parent, ast.Expr):
                continue  # a docstring or a bare statement
            if isinstance(parent, ast.JoinedStr):
                for part in parent.values:
                    if isinstance(part, ast.FormattedValue) and not self.field_ok(part.value):
                        bad(part, "f-string field %s is not a shared-module call" % ast.dump(part.value)[:60])
            elif isinstance(parent, ast.BinOp) and isinstance(parent.op, ast.Mod) and parent.left is node:
                right = parent.right
                fields = right.elts if isinstance(right, ast.Tuple) else [right]
                for field in fields:
                    if not self.field_ok(field):
                        bad(field, "%% operand %s is not a shared-module call" % ast.dump(field)[:60])
            elif isinstance(parent, ast.BinOp) and isinstance(parent.op, ast.Add):
                other = parent.right if parent.left is node else parent.left
                if not self.field_ok(other):
                    bad(other, "concatenated operand is not a shared-module call")
            elif (isinstance(parent, ast.Attribute) and parent.attr == "format"
                  and isinstance(parents.get(parent), ast.Call)):
                call = parents[parent]
                for field in list(call.args) + [kw.value for kw in call.keywords]:
                    if not self.field_ok(field):
                        bad(field, ".format argument is not a shared-module call")
            elif isinstance(parent, (ast.Call, ast.Return, ast.Tuple, ast.List, ast.keyword, ast.Compare)):
                continue  # a whole literal handed on, returned, compared or listed: no variable field
            else:
                bad(node, "command literal in an unrecognised form (%s)" % type(parent).__name__)
        return found

    def test_no_unescaped_workflow_command_9365(self):
        found = []
        for path in self.python_files():
            try:
                tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            except SyntaxError as exc:
                found.append("%s: unparseable (%s)" % (path.relative_to(REPO), exc))
                continue
            found.extend(self.violations(tree, str(path.relative_to(REPO))))
        for path, first_line, body in self.yaml_heredocs():
            if not COMMAND_RE.search(body) and "GITHUB_" not in body:
                continue
            try:
                tree = ast.parse(body)
            except SyntaxError as exc:
                found.append("%s:%d inline python unparseable (%s)" % (path.relative_to(REPO), first_line, exc))
                continue
            found.extend(self.violations(tree, str(path.relative_to(REPO)), first_line - 1))
        self.assertEqual(found, [], "\n".join(found))

    def github_file_writes(self, tree, label):
        """Every ``.write(...)`` inside ``with open(<something mentioning github>, ...)`` must use the shared module."""
        found = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.With):
                continue
            for item in node.items:
                call = item.context_expr
                if not (isinstance(call, ast.Call) and isinstance(call.func, ast.Name) and call.func.id == "open"
                        and call.args and "github" in ast.unparse(call.args[0]).lower()
                        and isinstance(item.optional_vars, ast.Name)):
                    continue
                handle = item.optional_vars.id
                for stmt in ast.walk(node):
                    if (isinstance(stmt, ast.Call) and isinstance(stmt.func, ast.Attribute)
                            and stmt.func.attr == "write" and isinstance(stmt.func.value, ast.Name)
                            and stmt.func.value.id == handle):
                        arg = stmt.args[0]
                        if isinstance(arg, ast.Constant):
                            continue
                        if not any(self.is_shared_call(sub) for sub in ast.walk(arg)):
                            found.append("%s:%d write to a github file without the shared module" % (label, stmt.lineno))
        return found

    def test_github_file_writes_use_shared_module_9365(self):
        found = []
        for path in self.python_files():
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            found.extend(self.github_file_writes(tree, str(path.relative_to(REPO))))
        self.assertEqual(found, [], "\n".join(found))

    def test_ratchet_sees_a_renamed_variable_9365(self):
        sample = ast.parse('def f(exc):\n    renamed = exc\n    print("::error::x: %s" % renamed)\n')
        self.assertEqual(len(self.violations(sample, "sample")), 1)
        sample = ast.parse('def f(exc):\n    print(f"::warning::{exc}")\n    PREFIX = "::error::"\n')
        self.assertEqual(len(self.violations(sample, "sample")), 2)
        sample = ast.parse('def f(exc):\n    print("::error::x" + safe_text(exc))\n    print("::notice::fixed")\n')
        self.assertEqual(self.violations(sample, "sample"), [])
        # the v1 form anywhere in a literal is a command too (#9365 r2 finding 1)
        sample = ast.parse('def f(exc):\n    print("x ##[error]%s" % exc)\n    print(f"y ##[warning]{exc}")\n')
        self.assertEqual(len(self.violations(sample, "sample")), 2)


class ScriptBehaviour(CommandAssertions):
    def setUp(self):
        self.tmp = scratch_dir("cell")
        self.addCleanup(shutil.rmtree, str(self.tmp), True)

    def hostile_values(self, names=None):
        return [(key, HOSTILE[key]) for key in (names or HOSTILE)]

    def test_host_semaphore_notice_9365(self):
        for key, value in self.hostile_values():
            with self.subTest(key):
                started = time.monotonic()
                rc, out, err = run_script(CI_DIR / "host_semaphore.py", [
                    "--name", "sem", "--slots", "1", "--max-wait-secs", "0", "--label", value,
                    "--root", str(self.tmp / ("root-" + key)), "--", "true"])
                self.assertEqual(rc, 0, err[-500:])
                self.assert_commands(out + err, ["notice"])
                self.assertLess(time.monotonic() - started, HUGE_WALL_CLOCK_SECS)

    def test_host_semaphore_no_slot_error_9365(self):
        root = self.tmp / "busy"
        holder = subprocess.Popen([sys.executable, "-I", str(CI_DIR / "host_semaphore.py"), "--name", "sem",
                                   "--slots", "1", "--root", str(root), "--label", "holder", "--",
                                   sys.executable, "-c", "import time; time.sleep(8)"],
                                  stdout=subprocess.PIPE, text=True)
        self.addCleanup(holder.wait)
        self.addCleanup(holder.kill)
        self.assertTrue(holder.stdout.readline().startswith("::notice::"))  # the holder owns the only slot
        for key, value in self.hostile_values():
            with self.subTest(key):
                rc, out, err = run_script(CI_DIR / "host_semaphore.py", [
                    "--name", "sem", "--slots", "1", "--max-wait-secs", "0", "--label", value,
                    "--root", str(root), "--", "true"])
                self.assertNotEqual(rc, 0, err[-300:])
                self.assert_commands(out + err, ["error"])

    def test_load_gate_cli_9365(self):
        for key, value in self.hostile_values():
            with self.subTest(key):
                rc, out, err = run_script(CI_DIR / "load_gate.py", ["--label", value, "--max-ratio", "100000"])
                self.assertEqual(rc, 0, err[-500:])
                self.assert_commands(out + err, ["notice", "notice"])

    def test_load_gate_warning_paths_in_process_9365(self):
        module = load_module(CI_DIR / "load_gate.py", "load_gate_9365")
        for key, value in self.hostile_values():
            with self.subTest(key):
                def unreadable(value=value):
                    raise OSError(value)

                buf = io.StringIO()
                with contextlib.redirect_stdout(buf):
                    module.run(value, 1.0, 0, 1, 1, unreadable, lambda secs: None)
                self.assert_commands(buf.getvalue(), ["warning"])
                readings = iter([100.0, 100.0])

                def high(readings=readings):
                    return next(readings)

                buf = io.StringIO()
                with contextlib.redirect_stdout(buf):
                    module.run(value, 1.0, 0, 1, 1, high, lambda secs: None)
                self.assert_commands(buf.getvalue(), ["notice", "warning", "notice"])
                calls = []

                def flaky(calls=calls, value=value):
                    calls.append(1)
                    if len(calls) > 1:
                        raise OSError(value)
                    return 100.0

                buf = io.StringIO()
                with contextlib.redirect_stdout(buf):
                    module.run(value, 1.0, 5, 1, 1, flaky, lambda secs: None)
                self.assert_commands(buf.getvalue(), ["notice", "warning"])

    def test_load_gate_huge_label_is_fast_and_bounded_9365(self):
        module = load_module(CI_DIR / "load_gate.py", "load_gate_huge_9365")
        value = "h" * HUGE_VALUE_CHARS
        started = time.monotonic()
        buf = io.StringIO()

        def unreadable():
            raise OSError(value)

        with contextlib.redirect_stdout(buf):
            module.run(value, 1.0, 0, 1, 1, unreadable, lambda secs: None)
        self.assertLess(time.monotonic() - started, HUGE_WALL_CLOCK_SECS)
        self.assert_commands(buf.getvalue(), ["warning"])

    def test_pg_isolate_split_error_9365(self):
        for key in FILE_NAME_CORPUS:
            value = HOSTILE[key]
            with self.subTest(key):
                missing = self.tmp / ("in-" + value)
                rc, out, err = run_script(CI_DIR / "pg_isolate_split.py", [
                    "--build-json", str(missing), "--serial-file", str(self.tmp / "s"),
                    "--out-dir", str(self.tmp / "o")])
                self.assertEqual(rc, 2, err[-500:])
                self.assert_commands(out + err, ["error"], oracle_escape(repr(str(missing))))  # the OSError text carries the repr

    def test_partition_test_binaries_error_9365(self):
        for key in FILE_NAME_CORPUS:
            value = HOSTILE[key]
            with self.subTest(key):
                build = self.tmp / "build.jsonl"
                build.write_text("")
                weights = self.tmp / ("w-" + value)
                rc, out, err = run_script(CI_DIR / "partition_test_binaries.py", [
                    "--build-json", str(build), "--repo-root", str(REPO), "--out-dir", str(self.tmp / "o"),
                    "--weights", str(weights)])
                self.assertEqual(rc, 2, (out + err)[-500:])
                self.assert_commands(out + err, ["error"])

    def prune_warning_row(self, key, on_disk):
        """One row of the prune warning: ``(command lines printed, the one line expected)``. ``on_disk``: the fixture
        directory is made and the script is run (the only form before #9705), and the expected root text is the
        oracle's escape of the made path; otherwise the warning of ``evict_idle_targets`` is made for a root named by
        the row's bytes without a directory, so the row asserts on a file system that refuses the name, and the
        expected line is the hand-written ``PRUNE_WARNING_ROOT_ESCAPED`` row."""
        value = HOSTILE[key]
        if on_disk:
            home = self.tmp / ("home-" + value)
            base = home / ".cache" / "ai-memory-ci" / "cargo-target"
            base.mkdir(parents=True)
            work = home / "work"
            work.mkdir(exist_ok=True)
            rc, out, err = run_script(CI_DIR / "prune_runner_artifacts.py", [
                "--work-root", str(work), "--workspace", str(work / "ws"), "--protected-root", str(base),
                "--evict-root", str(base), "--runner-name", "me", "--home", str(home),
                "--free-floor-gib", str(PRUNE_WARNING_FLOOR_GIB)], isolated=False)
            self.assertEqual(rc, 0, (out + err)[-800:])
            self.assert_commands(out + err, ["warning"], oracle_escape(str(base))[:200])
            return (self.command_lines(out + err),
                    PRUNE_WARNING_PREFIX + oracle_escape(str(base)) + PRUNE_WARNING_SUFFIX)
        name = "home-" + value

        class RootNamedByBytes:
            """Stands for the eviction root: a directory with no entries whose text is ``name``."""

            def is_dir(self):
                return True

            def iterdir(self):
                return iter(())

            def __str__(self):
                return name

        module = load_module(CI_DIR / "prune_runner_artifacts.py", "prune_runner_artifacts_9705_" + key)
        module.eviction_problem = lambda *_args: None
        module.resolve = lambda _path: RootNamedByBytes()
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
            module.evict_idle_targets("unused", "me", "unused", 1, PRUNE_WARNING_FLOOR_GIB, time.time(),
                                      free_bytes=lambda _path: 0)
        self.assert_commands(buf.getvalue(), ["warning"], oracle_escape(name)[:200])
        return (self.command_lines(buf.getvalue()),
                PRUNE_WARNING_PREFIX + PRUNE_WARNING_ROOT_ESCAPED[key] + PRUNE_WARNING_SUFFIX)

    def assert_prune_warning_row(self, key, on_disk):
        """The command lines the row printed are exactly the one expected line: a branch that returned without calling
        the function under test, or an assertion weakened to a substring, is red."""
        lines, expected = self.prune_warning_row(key, on_disk)
        self.assertEqual(lines, [expected], key)

    def test_prune_runner_artifacts_warning_9365(self):
        forms = row_forms(fs_accepts_non_utf8_names(self.tmp))
        for key in FILE_NAME_CORPUS:
            with self.subTest(key):
                self.assert_prune_warning_row(key, on_disk=forms[key])

    def test_prune_warning_without_a_directory_asserts_every_row_9705(self):
        """The probe-false branch, on every host: the same escaping of every row of the corpus, no directory made."""
        for key in FILE_NAME_CORPUS:
            with self.subTest(key):
                self.assert_prune_warning_row(key, on_disk=False)

    def test_prune_warning_with_a_directory_asserts_every_utf8_row_9705(self):
        """The probe-true branch, on every host: every row the file system takes runs the script on a made directory."""
        for key in sorted(FILE_NAME_CORPUS_UTF8):
            with self.subTest(key):
                self.assert_prune_warning_row(key, on_disk=True)

    def test_prune_warning_expected_table_is_the_oracle_text_9705(self):
        """The hand-written whole-line table agrees with the oracle for every row (two independent sources)."""
        self.assertEqual(sorted(PRUNE_WARNING_ROOT_ESCAPED), sorted(FILE_NAME_CORPUS))
        for key in FILE_NAME_CORPUS:
            with self.subTest(key):
                self.assertEqual(PRUNE_WARNING_ROOT_ESCAPED[key], oracle_escape("home-" + HOSTILE[key]))

    def test_prune_warning_row_check_compares_the_whole_line_9705(self):
        """The check every row goes through is red for a line that is not exactly the expected one (L1)."""
        expected = PRUNE_WARNING_PREFIX + PRUNE_WARNING_ROOT_ESCAPED["colons"] + PRUNE_WARNING_SUFFIX
        self.assertEqual(expected, "::warning::free space under home-a\\x3a:b is below the 100000000 GiB floor and no "
                                   "idle sibling target is left to evict")
        near_misses = (
            [],
            ["::warning::skipped"],
            [expected + "x"],
            ["x" + expected],
            [expected[:-1]],
            [expected.replace("warning", "error", 1)],
            [expected, expected],
            [expected, "::notice::extra"],
        )
        for lines in near_misses:
            with self.subTest(lines=lines):
                with mock.patch.object(self, "prune_warning_row", return_value=(lines, expected)):
                    with self.assertRaises(AssertionError):
                        self.assert_prune_warning_row("colons", on_disk=False)
        with mock.patch.object(self, "prune_warning_row", return_value=([expected], expected)):
            self.assert_prune_warning_row("colons", on_disk=False)

    def test_prune_warning_row_forms_choose_the_on_disk_form_when_the_probe_accepts_9705(self):
        every_row_on_disk = {"command": True, "raw_newline": True, "raw_cr": True, "colons": True, "percent": True,
                             "non_utf8": True}
        self.assertEqual(row_forms(True), every_row_on_disk)
        self.assertEqual(row_forms(False), {**every_row_on_disk, "non_utf8": False})

    def test_tier_cred_preflight_error_9365(self):
        for key, value in self.hostile_values(FILE_NAME_CORPUS):
            with self.subTest(key):
                url_file = self.tmp / ("url-" + value)
                rc, out, err = run_script(CI_DIR / "tier_cred_preflight.py", [
                    "--url-file", str(url_file)], env={"RUNNER_NAME": value, "HOME": str(self.tmp)})
                self.assertNotEqual(rc, 0)
                self.assert_commands(out + err, ["error"], oracle_escape(value)[:200])

    def test_pg_env_preflight_label_9365(self):
        for key, value in self.hostile_values():
            with self.subTest(key):
                rc, out, err = run_script(CI_DIR / "pg_env_preflight.py", [
                    "--label", value, "--psql", str(self.tmp / "no-such-psql"), "--wait-seconds", "0"])
                self.assertNotEqual(rc, 0, out[-300:])
                self.assert_commands(out + err, ["error"])

    def test_sweep_target_warning_9365(self):
        module = load_module(REPO / "scripts" / "ci-sweep-target.py", "ci_sweep_target_9365")
        for key, value in self.hostile_values():
            with self.subTest(key):
                buf = io.StringIO()
                with contextlib.redirect_stdout(buf):
                    module.annotate_warning(value)
                self.assert_commands(buf.getvalue(), ["warning"])

    def test_pg_isolated_binary_group_9365(self):
        module = load_module(REPO / "scripts" / "test" / "pg_isolated_binary.py", "pg_isolated_binary_9365")
        for key, value in self.hostile_values():
            with self.subTest(key):
                log_path = self.tmp / "log.txt"
                log_path.write_text("fine\n" + value + "\nlast\n", encoding="utf-8", errors="surrogateescape")
                runner = object.__new__(module.Runner)
                buf = io.StringIO()
                with contextlib.redirect_stdout(buf):
                    runner._report(value, 1, log_path)
                self.assert_commands(buf.getvalue(), ["group", "endgroup"])

    def test_env_files_get_one_entry_per_key_9365(self):
        out_file = self.tmp / "github_output"
        base_sha = load_module(CI_DIR / "impact" / "base_sha.py", "base_sha_9365")
        for key, value in self.hostile_values():
            with self.subTest(key):
                out_file.write_text("")
                with contextlib.redirect_stdout(io.StringIO()):
                    base_sha.emit("0" * 40, value, str(out_file))
                lines = out_file.read_text(errors="surrogateescape").splitlines()
                self.assertEqual(len(lines), 2, lines)
                self.assertTrue(lines[0].startswith("sha=") and lines[1].startswith("reason="), lines)
        nightly = load_module(CI_DIR / "ci_full_nightly.py", "ci_full_nightly_9365")
        for key, value in self.hostile_values():
            with self.subTest("nightly-" + key):
                out_file.write_text("")
                nightly.write_output(str(out_file), {"conclusion": value})
                self.assertEqual(len(out_file.read_text(errors="surrogateescape").splitlines()), 1)

    def test_single_line_matches_env_file_value_9365(self):
        common = load_module(CI_DIR / "impact" / "common.py", "impact_common_9365")
        shared = load_module(CI_DIR / SHARED_MODULE_NAME, "workflow_annotation_9365")
        for key, value in self.hostile_values():
            with self.subTest(key):
                self.assertEqual(common.single_line(value), shared.env_file_value(value))
                self.assertEqual(len(common.single_line(value).splitlines()), 1)

    def test_shared_cargo_target_env_file_9365(self):
        for key in ("raw_newline", "raw_cr", "command"):
            with self.subTest(key):
                home = self.tmp / ("h-" + HOSTILE[key])
                home.mkdir()
                env_file = self.tmp / ("env-" + key)
                rc, out, err = run_script(CI_DIR / "shared_cargo_target.py", [
                    "--home", str(home), "--runner-name", "r1", "--github-env", str(env_file),
                    "--lock-timeout", "1"])
                self.assertEqual(rc, 0, err[-500:])
                lines = env_file.read_text(errors="surrogateescape").splitlines()
                self.assertEqual(len(lines), 2, lines)


class HostProbePins9705(unittest.TestCase):
    """The host-dependent helpers of #9705 (the non-UTF-8 probe, the interpreter mask), pinned by hand-written rows."""

    PROBE_DIRECTORY = "/probe-dir"
    PROBE_PATH = b"/probe-dir/bad\xff\xfe::x"

    def test_probe_reports_refused_for_eilseq_and_leaves_nothing_9705(self):
        """APFS raises errno 92 (``errno.EILSEQ`` on darwin) for the name: the one errno the probe was built for."""
        removed = []

        def refuse(path):
            raise OSError(errno.EILSEQ, "Illegal byte sequence")

        self.assertIs(fs_accepts_non_utf8_names(self.PROBE_DIRECTORY, mkdir=refuse, rmdir=removed.append), False)
        self.assertEqual(removed, [])

    def test_probe_accepts_when_the_directory_is_made_and_removes_it_9705(self):
        made, removed = [], []
        self.assertIs(fs_accepts_non_utf8_names(self.PROBE_DIRECTORY, mkdir=made.append, rmdir=removed.append), True)
        self.assertEqual(made, [self.PROBE_PATH])
        self.assertEqual(removed, [self.PROBE_PATH])

    def test_probe_raises_every_other_oserror_with_its_type_and_errno_9705(self):
        rows = ((errno.EACCES, PermissionError), (errno.ENOSPC, OSError), (errno.EROFS, OSError),
                (errno.EEXIST, FileExistsError), (errno.ENOENT, FileNotFoundError), (errno.EIO, OSError),
                (errno.EILSEQ + 1, OSError))
        for code, error_type in rows:
            with self.subTest(errno=code):
                removed = []

                def fail(path, code=code):
                    raise OSError(code, "injected")

                with self.assertRaises(OSError) as caught:
                    fs_accepts_non_utf8_names(self.PROBE_DIRECTORY, mkdir=fail, rmdir=removed.append)
                self.assertIs(type(caught.exception), error_type)
                self.assertEqual(caught.exception.errno, code)
                self.assertEqual(removed, [])

    def test_probe_raises_an_oserror_without_an_errno_9705(self):
        def fail(path):
            raise OSError("no errno")

        with self.assertRaises(OSError) as caught:
            fs_accepts_non_utf8_names(self.PROBE_DIRECTORY, mkdir=fail, rmdir=lambda path: None)
        self.assertIsNone(caught.exception.errno)

    def test_probe_raises_when_the_directory_cannot_be_removed_9705(self):
        def fail(path):
            raise PermissionError(errno.EACCES, "injected")

        with self.assertRaises(PermissionError):
            fs_accepts_non_utf8_names(self.PROBE_DIRECTORY, mkdir=lambda path: None, rmdir=fail)

    def test_probe_on_this_host_leaves_the_directory_as_it_found_it_9705(self):
        directory = scratch_dir("probe")
        self.addCleanup(shutil.rmtree, str(directory), True)
        before = sorted(os.listdir(directory))
        self.assertIn(fs_accepts_non_utf8_names(directory), (True, False))
        self.assertEqual(sorted(os.listdir(directory)), before)

    def test_interpreter_spellings_are_exactly_the_three_and_their_escapes_9705(self):
        """``sys.executable``, its realpath and its directory's realpath with the file name kept; nothing else."""
        real = {FAKE_EXECUTABLE: FAKE_REAL_EXECUTABLE, "/opt/h/bin": FAKE_REAL_DIRECTORY}
        self.assertEqual(interpreter_spellings(FAKE_EXECUTABLE, realpath=real.__getitem__),
                         {FAKE_EXECUTABLE, FAKE_REAL_EXECUTABLE, FAKE_DIRECTORY_SPELLING})
        colon_real = {"/opt/a::b/bin/python3.12": "/opt/a::b/bin/python3.12", "/opt/a::b/bin": "/opt/a::b/bin"}
        self.assertEqual(interpreter_spellings("/opt/a::b/bin/python3.12", realpath=colon_real.__getitem__),
                         {"/opt/a::b/bin/python3.12", FAKE_COLON_EXECUTABLE})

    def test_mask_replaces_only_a_whole_executable_field_9705(self):
        rows = (
            ("executable=" + FAKE_EXECUTABLE, "executable=<interpreter>"),
            ("executable=" + FAKE_REAL_EXECUTABLE, "executable=<interpreter>"),
            ("executable=" + FAKE_DIRECTORY_SPELLING, "executable=<interpreter>"),
            ("executable=" + FAKE_COLON_EXECUTABLE, "executable=<interpreter>"),
            ("tmpdir=/x python=3.12 executable=" + FAKE_EXECUTABLE, "tmpdir=/x python=3.12 executable=<interpreter>"),
            ("a\nexecutable=" + FAKE_EXECUTABLE + "\nb\nexecutable=" + FAKE_REAL_EXECUTABLE + "\n",
             "a\nexecutable=<interpreter>\nb\nexecutable=<interpreter>\n"),
            # the directory alone is not a spelling
            ("executable=" + FAKE_REAL_DIRECTORY, "executable=" + FAKE_REAL_DIRECTORY),
            ("executable=/opt/h/bin", "executable=/opt/h/bin"),
            # the bare file name is not a spelling, in the field or elsewhere
            ("python=python3.12 executable=python3.12", "python=python3.12 executable=python3.12"),
            ("tmpdir=/x/python3.12 executable=/x/python3.12", "tmpdir=/x/python3.12 executable=/x/python3.12"),
            # a spelling in another field is not replaced
            ("tmpdir=" + FAKE_EXECUTABLE + " resolved=" + FAKE_REAL_EXECUTABLE,
             "tmpdir=" + FAKE_EXECUTABLE + " resolved=" + FAKE_REAL_EXECUTABLE),
            ("tmpdir=" + FAKE_EXECUTABLE + " executable=" + FAKE_EXECUTABLE,
             "tmpdir=" + FAKE_EXECUTABLE + " executable=<interpreter>"),
            # only a complete value counts
            ("executable=" + FAKE_EXECUTABLE + "-extra", "executable=" + FAKE_EXECUTABLE + "-extra"),
            ("executable=" + FAKE_EXECUTABLE + " ", "executable=" + FAKE_EXECUTABLE + " "),
            ("executable=x" + FAKE_EXECUTABLE, "executable=x" + FAKE_EXECUTABLE),
            ("notexecutable=" + FAKE_EXECUTABLE, "notexecutable=" + FAKE_EXECUTABLE),
            # no path at all
            ("::notice::nothing to mask here", "::notice::nothing to mask here"),
            ("executable=", "executable="),
            ("", ""),
        )
        for text, expected in rows:
            with self.subTest(text=text):
                self.assertEqual(mask_interpreter(text, FAKE_SPELLINGS), expected)

    def test_mask_default_spellings_are_this_interpreters_9705(self):
        spellings = interpreter_spellings()
        self.assertIn(sys.executable, spellings)
        self.assertIn(os.path.realpath(sys.executable), spellings)
        for spelling in spellings:
            with self.subTest(spelling=spelling):
                self.assertEqual(mask_interpreter("python=3 executable=" + spelling), "python=3 executable=<interpreter>")


class TemplateRendering(unittest.TestCase):
    """``render`` / ``join`` / ``SafeText``: the template's own colons stay, every value colon is escaped (#9365, #8634)."""

    HOSTILE_VALUES = ("a:b", "::error::x", ":::", "%0A", "line\nbreak", "back\\slash", "\udc80")

    def test_render_escapes_every_value_and_keeps_the_template_9365(self):
        shared = load_module(CI_DIR / SHARED_MODULE_NAME, "workflow_annotation_9365_render")
        for value in self.HOSTILE_VALUES:
            with self.subTest(value=value):
                text = shared.render("prog: refused: {value}", value=value)
                self.assertIsInstance(text, shared.SafeText)
                self.assertTrue(text.startswith("prog: refused: "), text)
                tail = text[len("prog: refused: "):]
                self.assertNotIn(":", tail)
                self.assertNotIn("\n", tail)
                self.assertEqual(tail, shared.safe_value(value))

    def test_plain_str_is_escaped_and_safetext_is_not_escaped_twice_9365(self):
        shared = load_module(CI_DIR / SHARED_MODULE_NAME, "workflow_annotation_9365_twice")
        inner = shared.render("{v}", v="a\\b")
        self.assertEqual(shared.annotation("warning", inner), "::warning::a\\\\b")
        self.assertEqual(shared.annotation("warning", "a\\b"), "::warning::a\\\\b")
        self.assertEqual(shared.render("{v}", v=inner), inner)
        self.assertEqual(shared.join(", ", [inner, "x:y"]), "a\\\\b, x\\x3ay")


# ---------------------------------------------------------------------------------------------------------------
# Load invariant (#9365 load lane): a script runs exactly the ``workflow_annotation.py`` next to its own real file.
#
# Class: a tool (here first of all a deleting tool) loads code by NAME through a search path. Invariant for all
# inputs: whatever the cwd, TMPDIR, PYTHONPATH, a relative or symlinked invocation path, the module the script runs
# is the file next to the script's real path; for prune_runner_tmp a sibling that is absent, unreadable or fails to
# load is one loud refusal (exit 0, one fixed ``::warning`` line built without the module) that prunes nothing.
# A module of the same name already in ``sys.modules`` cannot reach a subprocess, so the subprocess cells do not
# model it; the in-process cells below pin that the load neither reads nor writes ``sys.modules``/``sys.path``.
# decision: cells live in this file over test_prune_runner_tmp_8634.py because that file's diff against 32eca860
# stays empty and the class (load by name) spans every 9365 sibling, not only the prune tool.
# ---------------------------------------------------------------------------------------------------------------

PRUNE_SCRIPT_NAME = "prune_runner_tmp.py"
REAL_RUNNER_ROOT_LINE = 'F2_RUNNER_ROOT = "/ai-scratch/runner-tmp"'
REAL_RUNNER_ROOT_LITERAL = '"/ai-scratch/runner-tmp"'
FIXTURE_RUNNER_NAME = "runner-1"
OLD_ENTRY_AGE_SECS = 3 * 86400
HOSTILE_ENTRY_NAME = "old::entry%0A"  # escaped only by the real safe_value; the plant's identity escaper leaves it
LOAD_REFUSAL_ANNOTATION = ("::warning title=prune_runner_tmp refused::prune_runner_tmp: refused: shared module "
                           "workflow_annotation.py next to the script cannot be loaded")
LOAD_REFUSAL_STDERR = ("prune_runner_tmp: refused: shared module workflow_annotation.py next to the script cannot be "
                       "loaded ({cause})")
PRUNE_USED_NAMES = ("safe_value", "render", "join", "annotation", "log_line")
PLANT_EXIT_CODE = 97
EXIT_OK_CODE = 0  # every prune refusal exits 0 (ruling f23a9ae4)


def plant_source(marker, functional):
    """A planted ``workflow_annotation``: it records that it ran; functional plants also escape nothing."""
    head = f"with open({str(marker)!r}, 'a') as _marker_file:\n    _marker_file.write('planted module ran\\n')\n"
    if not functional:
        return head + f"raise SystemExit({PLANT_EXIT_CODE})\n"
    return head + textwrap.dedent("""\
        def safe_value(text):
            return str(text)
        safe_text = safe_value
        def render(template, **values):
            return template.format(**values)
        def join(separator, parts):
            return separator.join(str(part) for part in parts)
        def annotation(command, message, max_chars=1000, **properties):
            props = ",".join(f"{key}={value}" for key, value in properties.items())
            return f"::{command}{' ' + props if props else ''}::{message}"
        def property_value(text):
            return str(text)
        def log_line(text):
            return str(text)
        def env_file_value(value):
            return str(value)
        def end_group_line():
            return "::endgroup::"
        """)


def set_old(path):
    stamp = time.time() - OLD_ENTRY_AGE_SECS
    os.utime(path, (stamp, stamp), follow_symlinks=False)


class PruneFixture:
    """A fixture checkout (scripts/ci) whose prune copy only knows the fixture root, plus canaries."""

    def __init__(self, base, sibling="real"):
        self.base = base
        self.root = base / "root"
        self.runner = self.root / FIXTURE_RUNNER_NAME
        self.runner.mkdir(parents=True)
        self.inside = self.runner / "old-canary"
        self.hostile = self.runner / HOSTILE_ENTRY_NAME
        self.outside = self.root / "outside-canary"
        for canary in (self.inside, self.hostile, self.outside):
            canary.write_text("canary\n")
            set_old(canary)
        self.repo = base / "repo"
        self.ci = self.repo / "scripts" / "ci"
        self.ci.mkdir(parents=True)
        source = (CI_DIR / PRUNE_SCRIPT_NAME).read_text(encoding="utf-8")
        if source.count(REAL_RUNNER_ROOT_LINE) != 1:
            raise AssertionError("the prune script's root line moved; the fixture refuses to run it")
        source = source.replace(REAL_RUNNER_ROOT_LINE, f"F2_RUNNER_ROOT = {str(self.root)!r}")
        if REAL_RUNNER_ROOT_LITERAL in source:  # HARD SAFETY: the copy must not know any real runner root
            raise AssertionError("the prune copy still names the real runner root")
        self.script = self.ci / PRUNE_SCRIPT_NAME
        self.script.write_text(source, encoding="utf-8")
        self.sibling = self.ci / SHARED_MODULE_NAME
        if sibling == "real":
            shutil.copyfile(CI_DIR / SHARED_MODULE_NAME, self.sibling)
        self.cwd = base / "cwd"
        self.cwd.mkdir()
        self.plants = base / "plants"
        self.plants.mkdir()
        self.marker = base / "planted-module-ran"

    def run(self, argv0=None, args=("--dry-run",), cwd=None, pythonpath=None, isolated=False, flags=None):
        env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "LANG": "C.UTF-8", "TMPDIR": str(self.runner),
               "PYTHONDONTWRITEBYTECODE": "1"}
        if pythonpath is not None:
            env["PYTHONPATH"] = str(pythonpath)
        flags = list(flags) if flags is not None else ["-I"] if isolated else []
        proc = subprocess.run([sys.executable, *flags, str(argv0 or self.script), *args], capture_output=True,
                              env=env, cwd=str(cwd or self.cwd), timeout=SUBPROCESS_TIMEOUT_SECS, check=False)
        return (proc.returncode, proc.stdout.decode("utf-8", "surrogateescape"),
                proc.stderr.decode("utf-8", "surrogateescape"))

    def plant(self, directory, functional=True):
        path = Path(directory) / SHARED_MODULE_NAME
        path.write_text(plant_source(self.marker, functional), encoding="utf-8")
        return path

    def canaries_present(self):
        return all(path.exists() for path in (self.inside, self.hostile, self.outside))


class PruneLoadInvariant(unittest.TestCase):
    """prune_runner_tmp runs only the sibling next to its real file; a failed load refuses and prunes nothing."""

    def fixture(self, sibling="real"):
        base = scratch_dir("prune-load")
        self.addCleanup(shutil.rmtree, str(base), True)
        return PruneFixture(base, sibling)

    def assert_clean_dry_run(self, result, fix):
        rc, out, err = result
        self.assertEqual(rc, EXIT_OK_CODE, err[-2000:])
        shared = load_module(CI_DIR / SHARED_MODULE_NAME, "workflow_annotation_9365_load_oracle")
        self.assertNotEqual(shared.safe_value(HOSTILE_ENTRY_NAME), HOSTILE_ENTRY_NAME)
        self.assertIn("would-remove " + shared.safe_value(HOSTILE_ENTRY_NAME), out.splitlines(), out[-2000:])
        self.assertFalse(fix.marker.exists(), "the planted module ran")
        self.assertTrue(fix.canaries_present())

    def assert_plant_ignored(self, fix, plant_dir, **run):
        """Clean run, then the same run with a functional plant: no marker, byte-identical output."""
        placeholder = Path(plant_dir) / SHARED_MODULE_NAME
        placeholder.write_text("# inert placeholder of the planted module, same name and age class\n")
        clean = fix.run(**run)
        self.assert_clean_dry_run(clean, fix)
        fix.plant(plant_dir)
        planted = fix.run(**run)
        self.assertFalse(fix.marker.exists(), "the planted module ran: " + planted[1][-2000:])
        self.assertEqual(planted, clean)

    def test_plant_in_cwd_is_never_loaded_9365(self):
        fix = self.fixture()
        self.assert_plant_ignored(fix, fix.cwd)

    def test_plant_in_tmpdir_is_never_loaded_9365(self):
        fix = self.fixture()
        self.assert_plant_ignored(fix, fix.runner)

    def test_plant_on_pythonpath_is_never_loaded_9365(self):
        fix = self.fixture()
        self.assert_plant_ignored(fix, fix.plants, pythonpath=fix.plants)

    def test_relative_invocation_from_script_dir_loads_the_sibling_9365(self):
        fix = self.fixture()
        self.assert_plant_ignored(fix, fix.plants, argv0=PRUNE_SCRIPT_NAME, cwd=fix.ci, pythonpath=fix.plants)

    def test_relative_invocation_from_repo_root_with_cwd_plant_9365(self):
        fix = self.fixture()
        self.assert_plant_ignored(fix, fix.repo, argv0="scripts/ci/" + PRUNE_SCRIPT_NAME, cwd=fix.repo,
                                  pythonpath=fix.repo)

    def test_workflow_form_isolated_with_cwd_plant_9365(self):
        fix = self.fixture()
        self.assert_plant_ignored(fix, fix.cwd, isolated=True)

    def test_symlinked_invocation_loads_only_the_real_files_sibling_9365(self):
        # decision: the real file's directory is the only source over a refusal for a symlinked path because the
        # action may legitimately reach the script through a symlinked checkout and the real sibling is the vetted one
        fix = self.fixture()
        link_dir = fix.base / "linkdir"
        link_dir.mkdir()
        (link_dir / PRUNE_SCRIPT_NAME).symlink_to(fix.script)
        for label, argv0, cwd in (("absolute link", link_dir / PRUNE_SCRIPT_NAME, fix.cwd),
                                  ("relative link", PRUNE_SCRIPT_NAME, link_dir)):
            with self.subTest(label):
                fix.marker.unlink(missing_ok=True)
                self.assert_plant_ignored(fix, link_dir, argv0=argv0, cwd=cwd)
                (link_dir / SHARED_MODULE_NAME).unlink()

    def test_isolated_and_no_site_runs_match_the_plain_run_9365(self):
        """b29 ruling 3c1d3cbb: ``-I`` and ``-S`` behave as the plain run (exit, lines, pruned set); cwd plant inert."""
        results = {}
        for label, flags in (("plain", []), ("-I", ["-I"]), ("-S", ["-S"])):
            fix = self.fixture()
            fix.plant(fix.cwd)
            rc, out, err = fix.run(args=(), flags=flags)  # a real prune of the fixture runner dir
            self.assertFalse(fix.marker.exists(), f"{label}: the planted module ran")
            left = sorted(path.relative_to(fix.root).as_posix() for path in fix.root.rglob("*"))
            # #9705: under Homebrew a child prints sys.executable, its realpath or its directory's realpath; the value
            # of the executable= field (and only that) becomes one placeholder
            results[label] = (rc, mask_interpreter(out.replace(str(fix.base), "<base>")).splitlines(), left)
        self.assertEqual(results["plain"][0], EXIT_OK_CODE, results["plain"])
        self.assertEqual(results["plain"][2], sorted([FIXTURE_RUNNER_NAME, "outside-canary"]), "the old entries are pruned")
        facts = [line for line in results["plain"][1] if "executable=" in line]
        self.assertTrue(facts, results["plain"])
        for line in facts:  # the mask found the interpreter path in every facts line; it did not match nothing
            self.assertTrue(line.endswith(" executable=" + INTERPRETER_PLACEHOLDER), line)
        self.assertEqual(results["-I"], results["plain"])
        self.assertEqual(results["-S"], results["plain"])

    def assert_load_refusal(self, fix, cause, **run):
        rc, out, err = fix.run(args=(), **run)  # a real prune: a refusal that went on would remove the canaries
        self.assertEqual(rc, EXIT_OK_CODE, err[-2000:])
        self.assertEqual(out, LOAD_REFUSAL_ANNOTATION + "\n")
        self.assertEqual(err, LOAD_REFUSAL_STDERR.format(cause=cause) + "\n")
        self.assertTrue(fix.canaries_present(), "the refusal pruned")
        self.assertFalse(fix.marker.exists(), "the planted module ran")
        self.assertEqual(sorted(p.name for p in fix.runner.iterdir()), sorted([fix.inside.name, fix.hostile.name]))

    def test_absent_sibling_is_a_loud_refusal_9365(self):
        fix = self.fixture(sibling="absent")
        self.assert_load_refusal(fix, "cannot be read")
        self.assert_load_refusal(fix, "cannot be read", isolated=True)

    def test_absent_sibling_with_pythonpath_plant_is_a_refusal_not_the_plant_9365(self):
        fix = self.fixture(sibling="absent")
        fix.plant(fix.plants)
        fix.plant(fix.cwd)
        self.assert_load_refusal(fix, "cannot be read", pythonpath=fix.plants)

    def test_unreadable_sibling_is_a_loud_refusal_9365(self):
        fix = self.fixture()
        fix.sibling.chmod(0)
        self.addCleanup(fix.sibling.chmod, 0o600)
        if os.access(str(fix.sibling), os.R_OK):
            self.skipTest("running as a user who reads mode-0 files")
        self.assert_load_refusal(fix, "cannot be read")

    def test_sibling_that_is_a_directory_is_a_loud_refusal_9365(self):
        fix = self.fixture(sibling="absent")
        fix.sibling.mkdir()
        self.assert_load_refusal(fix, "cannot be read")

    def test_sibling_raising_at_load_is_a_loud_refusal_9365(self):
        bodies = {
            "exception": "raise RuntimeError('boom')\n",
            "system exit 0": "import sys\nsys.exit(0)\n",
            "syntax error": "def broken(:\n",
            "null byte": "x = 1\0\n",
            "non utf-8": "x = '\udcff'\n",
        }
        for label, body in bodies.items():
            with self.subTest(label):
                fix = self.fixture(sibling="absent")
                fix.sibling.write_bytes(body.encode("utf-8", "surrogateescape"))
                self.assert_load_refusal(fix, "raised while loading")

    def test_sibling_missing_a_used_attribute_is_a_loud_refusal_9365(self):
        real = (CI_DIR / SHARED_MODULE_NAME).read_text(encoding="utf-8")
        for name in PRUNE_USED_NAMES:
            with self.subTest(name):
                fix = self.fixture(sibling="absent")
                fix.sibling.write_text(real + f"\ndel {name}\n", encoding="utf-8")
                self.assert_load_refusal(fix, "lacks " + name)

    def test_load_leaves_sys_path_and_sys_modules_alone_in_process_9365(self):
        fix = self.fixture()
        fix.plant(fix.plants)
        before_path, before_modules = list(sys.path), set(sys.modules)
        spec = importlib.util.spec_from_file_location("prune_runner_tmp_load_9365", str(fix.script))
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        self.assertEqual(sys.path, before_path)
        self.assertEqual(set(sys.modules) - before_modules, set())
        self.assertEqual(os.path.realpath(module.wa.__file__), os.path.realpath(str(fix.sibling)))
        self.assertFalse(fix.marker.exists())

    def test_main_in_process_with_absent_sibling_refuses_and_prunes_nothing_9365(self):
        fix = self.fixture(sibling="absent")
        spec = importlib.util.spec_from_file_location("prune_runner_tmp_absent_9365", str(fix.script))
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        out, err = io.StringIO(), io.StringIO()
        rc = module.main([], {"TMPDIR": str(fix.runner)}, out, err)
        self.assertEqual(rc, EXIT_OK_CODE)
        self.assertEqual(out.getvalue(), LOAD_REFUSAL_ANNOTATION + "\n")
        self.assertEqual(err.getvalue(), LOAD_REFUSAL_STDERR.format(cause="cannot be read") + "\n")
        self.assertTrue(fix.canaries_present())


# The 9365 siblings: every script whose sys.path/import lines for the shared module the 9365 commits added, with
# the sibling modules (loaded by name, present at base 32eca860) its fixture copy needs.
SIBLING_SCRIPTS = {
    "scripts/ci-sweep-target.py": (),
    "scripts/ci/ci_full_nightly.py": (),
    "scripts/ci/host_semaphore.py": (),
    "scripts/ci/impact/base_sha.py": (),
    "scripts/ci/load_gate.py": (),
    "scripts/ci/partition_test_binaries.py": (),
    "scripts/ci/pg_env_preflight.py": (),
    "scripts/ci/shared_cargo_target.py": (),
    "scripts/ci/tier_cred_preflight.py": ("scripts/ci/ensure-age-extension.py",),
    "scripts/ci/pg_isolate_split.py": ("scripts/ci/partition_test_binaries.py", "scripts/ci/pg_isolate_serial_residual.txt"),
    "scripts/ci/prune_runner_artifacts.py": ("scripts/ci/shared_cargo_target.py",),
    "scripts/ci/sccache_env.py": ("scripts/ci/shared_cargo_target.py",),
    "scripts/ci/suite_budget.py": (),  # #9229 suite margin gate
}
SHARED_MODULE_PATH = "scripts/ci/" + SHARED_MODULE_NAME


class SiblingLoadInvariant(unittest.TestCase):
    """Every 9365 sibling loads the shared module by its file path next to the real script, never by name."""

    def layout(self, rel_script, with_shared):
        base = scratch_dir("sibling-load")
        self.addCleanup(shutil.rmtree, str(base), True)
        repo = base / "repo"
        for rel in (rel_script, *SIBLING_SCRIPTS.get(rel_script, ()), *((SHARED_MODULE_PATH,) if with_shared else ())):
            (repo / rel).parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(REPO / rel, repo / rel)
        plants = base / "plants"
        plants.mkdir()
        marker = base / "planted-module-ran"
        (plants / SHARED_MODULE_NAME).write_text(plant_source(marker, functional=False), encoding="utf-8")
        return base, repo, plants, marker

    @staticmethod
    def run_help(argv0, cwd, pythonpath):
        env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "LANG": "C.UTF-8", "PYTHONPATH": str(pythonpath),
               "PYTHONDONTWRITEBYTECODE": "1", "TMPDIR": str(cwd)}
        proc = subprocess.run([sys.executable, str(argv0), "--help"], capture_output=True, env=env, cwd=str(cwd),
                              timeout=SUBPROCESS_TIMEOUT_SECS, check=False)
        return proc.returncode, proc.stdout.decode("utf-8", "replace"), proc.stderr.decode("utf-8", "replace")

    def test_absent_shared_module_never_falls_through_to_a_pythonpath_plant_9365(self):
        for rel in SIBLING_SCRIPTS:
            with self.subTest(rel):
                base, repo, plants, marker = self.layout(rel, with_shared=False)
                rc, out, err = self.run_help(repo / rel, plants, plants)
                self.assertFalse(marker.exists(), f"{rel} ran the planted module (rc {rc})")
                self.assertNotEqual(rc, PLANT_EXIT_CODE)
                self.assertNotEqual(rc, EXIT_OK_CODE, "a missing shared module is a loud failure")

    def test_symlinked_invocation_never_loads_a_plant_next_to_the_link_9365(self):
        for rel in SIBLING_SCRIPTS:
            with self.subTest(rel):
                base, repo, plants, marker = self.layout(rel, with_shared=True)
                link = plants / Path(rel).name
                link.symlink_to(repo / rel)
                rc, out, err = self.run_help(link, plants, base)
                self.assertFalse(marker.exists(), f"{rel} through a symlink ran the planted module (rc {rc})")
                self.assertEqual(rc, EXIT_OK_CODE, err[-2000:])

    def test_pg_isolated_binary_loads_by_path_and_leaves_sys_path_alone_9365(self):
        rel = "scripts/test/pg_isolated_binary.py"
        base, repo, plants, marker = self.layout(rel, with_shared=False)
        spec = importlib.util.spec_from_file_location("pg_isolated_binary_load_9365", str(repo / rel))
        module = importlib.util.module_from_spec(spec)
        sys.path.insert(0, str(plants))  # what a PYTHONPATH plant looks like in-process
        try:
            before_path, before_modules = list(sys.path), set(sys.modules)
            # eager since ruling bcd0a15c: the absent module ends the import with the fixed refusal, never a plant
            with contextlib.redirect_stdout(io.StringIO()) as out, contextlib.redirect_stderr(io.StringIO()) as err, \
                    self.assertRaises(SystemExit) as raised:
                spec.loader.exec_module(module)
            self.assertEqual(raised.exception.code, NON_GATE_LOAD_EXIT_CODES[rel])
            self.assertEqual(out.getvalue(), "")
            self.assertEqual(err.getvalue(), sibling_load_lines(rel, "FileNotFoundError")[1])
            self.assertEqual(sys.path, before_path)
            self.assertNotIn(SHARED_MODULE_NAME[:-3], set(sys.modules) - before_modules)
        finally:
            sys.path.remove(str(plants))
            if marker.exists():  # the plant ran (red): drop whatever it left so later cells see the real module
                sys.modules.pop(SHARED_MODULE_NAME[:-3], None)
        self.assertFalse(marker.exists(), "pg_isolated_binary ran the planted module")


# ---------------------------------------------------------------------------------------------------------------
# Floor order (#9365, conductor ruling 598d069e): below MIN_PYTHON the prune tool runs nothing but its own top lines
# and the version refusal (no sibling load, no ``__import__``, no os lookup); at or above the floor the load runs
# after the check and an os.py planted in the cwd, the script's directory or on PYTHONPATH never runs (plain, -I, -S).
# decision: the version is forced the way the 8634 suite forces it (``sys.version_info`` replaced in a guard process,
# test_python_floor_refusal_is_a_warning_and_exit_zero_in_the_process_guard) over a real old interpreter because no
# Python below 3.12 is installed on the fleet nodes; the guard runs the file with ``exec`` instead of runpy so
# runpy's own imports do not hide an os lookup of the script under -S.
# ---------------------------------------------------------------------------------------------------------------

FLOOR_GUARD = textwrap.dedent("""\
    import builtins, sys
    path, version = sys.argv[1], eval(sys.argv[2])
    sys.argv[1:] = []
    sys.version_info = version
    seen = []
    real_import = builtins.__import__
    def recording_import(name, *args, **kwargs):
        seen.append(name)
        return real_import(name, *args, **kwargs)
    builtins.__import__ = recording_import
    with open(path, "rb") as handle:
        code = compile(handle.read(), path, "exec", dont_inherit=True)
    try:
        exec(code, {"__name__": "__main__", "__file__": path, "__builtins__": builtins})
    except SystemExit as exc:
        builtins.__import__ = real_import
        print("exit", exc.code)
    builtins.__import__ = real_import
    print("imports", ",".join(seen))
    print("os loaded", "os" in sys.modules)
    """)
VERSION_ANNOTATION_HEAD = "::warning title=prune_runner_tmp refused::prune_runner_tmp: refused: "
VERSION_STDERR_HEAD = "prune_runner_tmp: refused: "
FLOOR_TEXT = " is older than 3.12"
LONG_VERSION_DIGITS = 1200
# The version refusal at 0f1ec1b7 (captured through the 8634 process guard, python3 -I): stdout annotation, stderr.
VERSION_REFUSAL_AT_0F1EC1B7 = {
    (2, 7, 18, "final", 0): (VERSION_ANNOTATION_HEAD + "python 2.7.18" + FLOOR_TEXT,
                             VERSION_STDERR_HEAD + "python 2.7.18" + FLOOR_TEXT),
    (3, 8, 0, "final", 0): (VERSION_ANNOTATION_HEAD + "python 3.8.0" + FLOOR_TEXT,
                            VERSION_STDERR_HEAD + "python 3.8.0" + FLOOR_TEXT),
    (3, 11, 9, "final", 0): (VERSION_ANNOTATION_HEAD + "python 3.11.9" + FLOOR_TEXT,
                             VERSION_STDERR_HEAD + "python 3.11.9" + FLOOR_TEXT),
    # hostile parts (only a forced version_info can hold them): every ':', '%', control, '\\' and U+2028 escaped
    (3, 11, "9::x%0A\n\\ ", "final", 0): (
        VERSION_ANNOTATION_HEAD + "python 3.11.9\\x3a\\x3ax\\x250A\\x0a\\\\\\u2028" + FLOOR_TEXT,
        VERSION_STDERR_HEAD + "python 3.11.9::x%0A\n\\ " + FLOOR_TEXT),
    # longer than the 1000-char line bound: cut at 997 characters plus "..."
    (3, 11, "9" * LONG_VERSION_DIGITS, "final", 0): (
        (VERSION_ANNOTATION_HEAD + "python 3.11." + "9" * LONG_VERSION_DIGITS)[:LINE_BOUND_CHARS - 3] + "...",
        VERSION_STDERR_HEAD + "python 3.11." + "9" * LONG_VERSION_DIGITS + FLOOR_TEXT),
}
NORMAL_VERSIONS = ((2, 7, 18, "final", 0), (3, 8, 0, "final", 0), (3, 11, 9, "final", 0))
OS_PLANT_NAME = "os.py"
PYTHON_FLAG_SETS = (("plain", ()), ("-I", ("-I",)), ("-S", ("-S",)))
OS_PLANT_PLACES = ("cwd", "script dir", "PYTHONPATH")
ALL_CODEPOINTS = 0x110000
# Present at base 32eca860: these import shared_cargo_target by name through sys.path[0], so under -I (no script
# directory on sys.path) even the clean run fails; that load site is issue 9399's. The os.py cell still holds for them:
# the planted run equals the clean run and the plant never runs.
SIBLINGS_LOADING_A_SIBLING_BY_NAME = frozenset({"scripts/ci/prune_runner_artifacts.py", "scripts/ci/sccache_env.py"})


def os_plant_source(marker):
    """A planted ``os``: it records that it ran and stops the process; it never imports anything."""
    return (f"with open({str(marker)!r}, 'a') as _marker_file:\n    _marker_file.write('planted os ran\\n')\n"
            f"raise SystemExit({PLANT_EXIT_CODE})\n")


class PruneFloorOrder(unittest.TestCase):
    """Below the floor nothing but the top lines and the version refusal runs; the bytes are those of 0f1ec1b7."""

    def fixture(self, sibling="real"):
        base = scratch_dir("prune-floor")
        self.addCleanup(shutil.rmtree, str(base), True)
        return PruneFixture(base, sibling)

    def run_floor(self, fix, version, flags=("-I",)):
        proc = subprocess.run([sys.executable, *flags, "-c", FLOOR_GUARD, str(fix.script), repr(version)],
                              capture_output=True, cwd=str(fix.cwd), timeout=SUBPROCESS_TIMEOUT_SECS, check=False,
                              env={"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "LANG": "C.UTF-8",
                                   "TMPDIR": str(fix.runner), "PYTHONDONTWRITEBYTECODE": "1"})
        return proc.returncode, proc.stdout.decode("utf-8", "surrogateescape"), proc.stderr.decode("utf-8", "surrogateescape")

    def test_old_version_never_loads_the_sibling_or_looks_up_os_9365(self):
        """Order cell: a marker-writing sibling stays unexecuted; the only import is sys; os is never loaded (-S)."""
        for flags in (("-I",), ("-I", "-S")):
            with self.subTest(flags=flags):
                fix = self.fixture(sibling="absent")
                fix.sibling.write_text(plant_source(fix.marker, functional=True), encoding="utf-8")
                rc, out, err = self.run_floor(fix, (3, 11, 9, "final", 0), flags)
                annotation, stderr_line = VERSION_REFUSAL_AT_0F1EC1B7[(3, 11, 9, "final", 0)]
                self.assertFalse(fix.marker.exists(), "the old-version path executed the sibling module")
                self.assertEqual(err, stderr_line + "\n")
                want = [annotation, "exit 0", "imports sys"]
                if "-S" in flags:  # without site nothing has loaded os before the script: the script must not either
                    want.append("os loaded False")
                self.assertEqual(out.splitlines()[:len(want)], want, out[-2000:])
                self.assertEqual(rc, EXIT_OK_CODE)
                self.assertTrue(fix.canaries_present(), "the refusal pruned")

    def test_load_and_every_dunder_import_follow_the_floor_check_9365(self):
        """Static cell (ast, by line number): the load call and every ``__import__(`` sit after the floor check."""
        source = (CI_DIR / PRUNE_SCRIPT_NAME).read_text(encoding="utf-8")
        tree = ast.parse(source, feature_version=(3, 8))
        floor = next(node for node in tree.body if isinstance(node, ast.If) and "python_refusal" in ast.unparse(node.test))
        calls = [node for node in ast.walk(tree) if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)]
        loads = [node.lineno for node in calls if node.func.id == "load_shared_module"]
        dunder = [node.lineno for node in calls if node.func.id == "__import__"]
        self.assertEqual(len(loads), 1, loads)
        self.assertTrue(dunder, "the os fallback is kept behind the floor (ruling 598d069e), not removed")
        late = [line for line in loads + dunder if line <= floor.end_lineno]
        self.assertEqual(late, [], f"floor check ends at line {floor.end_lineno}; these run before it: {late}")
        early = [inner.lineno for node in tree.body[:tree.body.index(floor) + 1] for inner in ast.walk(node)
                 if isinstance(inner, ast.Name) and inner.id == "wa"]
        self.assertEqual(early, [], "the version refusal path uses the shared module at these lines")

    def test_version_refusal_bytes_match_0f1ec1b7_with_and_without_the_sibling_9365(self):
        for sibling in ("real", "absent"):
            for version, (annotation, stderr_line) in VERSION_REFUSAL_AT_0F1EC1B7.items():
                with self.subTest(sibling=sibling, version=version[:2] + (str(version[2])[:20],)):
                    fix = self.fixture(sibling=sibling)
                    rc, out, err = self.run_floor(fix, version)
                    self.assertEqual(rc, EXIT_OK_CODE, err[-2000:])
                    self.assertEqual(err, stderr_line + "\n")
                    self.assertEqual(out.splitlines()[:2], [annotation, "exit 0"], out[-2000:])
                    self.assertLessEqual(len(out.splitlines()[0]), LINE_BOUND_CHARS)
                    self.assertTrue(fix.canaries_present(), "the refusal pruned")

    def test_8634_process_guard_form_still_prints_the_refusal_9365(self):
        """The runpy guard of the 8634 suite (with the sibling absent): the same line, exit 0."""
        fix = self.fixture(sibling="absent")
        guard = ("import sys, runpy\nsys.version_info = (3, 11, 9, 'final', 0)\ntry:\n"
                 "    runpy.run_path(sys.argv[1], run_name='__main__')\nexcept SystemExit as exc:\n    print('exit', exc.code)\n")
        done = subprocess.run([sys.executable, "-I", "-c", guard, str(fix.script)], capture_output=True, text=True,
                              check=False, timeout=SUBPROCESS_TIMEOUT_SECS)
        annotation, stderr_line = VERSION_REFUSAL_AT_0F1EC1B7[(3, 11, 9, "final", 0)]
        self.assertEqual((done.stdout, done.stderr), (annotation + "\nexit 0\n", stderr_line + "\n"))

    def test_local_version_escape_equals_safe_value_for_every_code_point_9365(self):
        """The refusal's own escaper is byte-equal to the shared ``safe_value`` over all code points, in bounded time."""
        prune = load_module(CI_DIR / PRUNE_SCRIPT_NAME, "prune_runner_tmp_floor_9365")
        shared = load_module(CI_DIR / SHARED_MODULE_NAME, "workflow_annotation_floor_9365")
        corpus = "".join(chr(code) for code in range(ALL_CODEPOINTS)) + "::" * HUGE_VALUE_CHARS
        started = time.monotonic()
        mine = prune.version_text(corpus)
        self.assertLess(time.monotonic() - started, HUGE_WALL_CLOCK_SECS)
        self.assertEqual(mine, shared.safe_value(corpus))
        for value in HOSTILE.values():
            self.assertEqual(prune.version_text(value), shared.safe_value(value))
        for version in VERSION_REFUSAL_AT_0F1EC1B7:
            reason = prune.python_refusal(version)
            via_module = shared.annotation("warning", shared.render("{prog}: refused: {reason}", prog="prune_runner_tmp",
                                                                    reason=reason), title="prune_runner_tmp refused")
            self.assertEqual(prune.version_refusal_annotation(reason), via_module)


class OsPlantNeverRuns(unittest.TestCase):
    """At or above the floor an os.py in the cwd, the script's directory or on PYTHONPATH never runs (ruling 598d069e)."""

    def prune_fixture(self):
        base = scratch_dir("prune-os-plant")
        self.addCleanup(shutil.rmtree, str(base), True)
        return PruneFixture(base)

    @staticmethod
    def place(fix, where):
        return {"cwd": fix.cwd, "script dir": fix.ci, "PYTHONPATH": fix.plants}[where]

    def prune_run(self, where, flags, planted):
        fix = self.prune_fixture()
        if planted:
            (self.place(fix, where) / OS_PLANT_NAME).write_text(os_plant_source(fix.marker), encoding="utf-8")
        rc, out, err = fix.run(args=(), flags=flags, pythonpath=fix.plants if where == "PYTHONPATH" else None)
        left = sorted(path.relative_to(fix.root).as_posix() for path in fix.root.rglob("*"))
        return fix.marker.exists(), (rc, out.replace(str(fix.base), "<base>").splitlines(), left)

    def test_prune_os_plant_nine_runs_9365(self):
        for where in OS_PLANT_PLACES:
            for label, flags in PYTHON_FLAG_SETS:
                with self.subTest(where=where, flags=label):
                    _, clean = self.prune_run(where, flags, planted=False)
                    ran, planted = self.prune_run(where, flags, planted=True)
                    self.assertFalse(ran, f"os.py in the {where} ran ({label}): {planted}")
                    self.assertEqual(clean[0], EXIT_OK_CODE, clean)
                    self.assertEqual(clean[2], sorted([FIXTURE_RUNNER_NAME, "outside-canary"]), "old entries pruned")
                    self.assertEqual(planted, clean)

    def test_sibling_scripts_os_plant_table_9365(self):
        """Table over the 14 sibling scripts (the 13 of 0f1ec1b7 plus suite_budget of #9229): ``--help`` with an os.py plant equals the clean run."""
        scripts = (*SIBLING_SCRIPTS, "scripts/test/pg_isolated_binary.py")
        self.assertEqual(len(scripts), 14)
        layout = SiblingLoadInvariant.layout
        for rel in scripts:
            for where in OS_PLANT_PLACES:
                for label, flags in PYTHON_FLAG_SETS:
                    with self.subTest(script=rel, where=where, flags=label):
                        results = []
                        for planted in (False, True):
                            base, repo, plants, marker = layout(self, rel, with_shared=True)
                            (plants / SHARED_MODULE_NAME).unlink()
                            cwd = base / "cwd"
                            cwd.mkdir()
                            target = {"cwd": cwd, "script dir": (repo / rel).parent, "PYTHONPATH": plants}[where]
                            if planted:
                                (target / OS_PLANT_NAME).write_text(os_plant_source(marker), encoding="utf-8")
                            env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "LANG": "C.UTF-8",
                                   "PYTHONDONTWRITEBYTECODE": "1", "TMPDIR": str(cwd), "PYTHONPATH": str(plants)}
                            proc = subprocess.run([sys.executable, *flags, str(repo / rel), "--help"],
                                                  capture_output=True, env=env, cwd=str(cwd),
                                                  timeout=SUBPROCESS_TIMEOUT_SECS, check=False)
                            self.assertFalse(marker.exists(), f"os.py in the {where} ran for {rel} ({label})")
                            results.append((proc.returncode, proc.stdout.replace(str(base).encode(), b"<base>"),
                                            proc.stderr.replace(str(base).encode(), b"<base>")))
                        if not (label == "-I" and rel in SIBLINGS_LOADING_A_SIBLING_BY_NAME):
                            self.assertEqual(results[0][0], EXIT_OK_CODE, results[0])
                        self.assertEqual(results[1], results[0])


# The gates (the five of ruling 0011e5e0, plus suite_budget of #9229): a failed load of the shared module fails the step with the gate's fail-closed
# exit code, one fixed ::error line built without the module and one stderr line naming the cause; nothing else.
GATE_LOAD_EXIT_CODES = {
    "scripts/ci/load_gate.py": 3,  # EXIT_LOAD_REFUSED (0 = proceed, 2 = bad arguments)
    "scripts/ci/pg_env_preflight.py": 3,  # EXIT_PG_ENV
    "scripts/ci/tier_cred_preflight.py": 1,  # EXIT_UNAVAILABLE
    "scripts/ci/host_semaphore.py": 4,  # EXIT_LOAD_REFUSED (82 = no slot, 83 = unknown runner, 84 = a child that exited with a reserved code; any other code is the child's)
    "scripts/ci/partition_test_binaries.py": 2,  # EXIT_FAIL_CLOSED
    "scripts/ci/suite_budget.py": 4,  # EXIT_LOAD_REFUSED (2 = malformed input, 3 = margin lost) #9229
}
GATE_LOAD_ERROR_LINE = ("::error title={prog} refused::{prog}: refused: shared module workflow_annotation.py next to "
                        "the script cannot be loaded")
GATE_LOAD_STDERR_LINE = ("{prog}: refused: shared module workflow_annotation.py next to the script cannot be loaded "
                         "({cause})")
GATE_LOAD_BREAKS = {  # break name -> (how the fixture copy of the shared module is broken, the cause named)
    "absent": (None, "FileNotFoundError"),
    "unreadable": ("", "PermissionError"),
    "syntax error": ("def broken(:\n", "SyntaxError"),
    "sys.exit(0) in it": ("import sys\nsys.exit(0)\n", "SystemExit"),
}
GATE_PASS_MARKERS = ("usage:", "::notice", "::warning")


class GateLoadFailsClosed(unittest.TestCase):
    """A gate whose shared module cannot be loaded exits non-zero with one loud ::error line (ruling 0011e5e0)."""

    def gate_run(self, rel, broken, cause_source, flags):
        base = scratch_dir("gate-load")
        self.addCleanup(shutil.rmtree, str(base), True)
        repo = base / "repo"
        for item in (rel, *SIBLING_SCRIPTS[rel], SHARED_MODULE_PATH):
            (repo / item).parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(REPO / item, repo / item)
        shared = repo / SHARED_MODULE_PATH
        if cause_source is None:
            shared.unlink()
        elif broken == "unreadable":
            shared.chmod(0)
            self.addCleanup(shared.chmod, 0o600)
        else:
            shared.write_text(cause_source, encoding="utf-8")
        cwd = base / "cwd"
        cwd.mkdir()
        env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "LANG": "C.UTF-8", "PYTHONDONTWRITEBYTECODE": "1",
               "TMPDIR": str(cwd)}
        proc = subprocess.run([sys.executable, *flags, str(repo / rel), "--help"], capture_output=True, env=env,
                              cwd=str(cwd), timeout=SUBPROCESS_TIMEOUT_SECS, check=False)
        return proc.returncode, proc.stdout.decode("utf-8", "replace"), proc.stderr.decode("utf-8", "replace")

    def test_failed_load_fails_each_gate_closed_9365(self):
        if os.geteuid() == 0:
            self.skipTest("root reads a mode-0 file")
        for rel, code in GATE_LOAD_EXIT_CODES.items():
            prog = Path(rel).stem
            for broken, (source, cause) in GATE_LOAD_BREAKS.items():
                for label, flags in PYTHON_FLAG_SETS:
                    with self.subTest(gate=prog, broken=broken, flags=label):
                        rc, out, err = self.gate_run(rel, broken, source, flags)
                        self.assertNotEqual(rc, EXIT_OK_CODE, (out, err[-2000:]))
                        self.assertEqual(rc, code, err[-2000:])
                        self.assertEqual(out, GATE_LOAD_ERROR_LINE.format(prog=prog) + "\n")
                        self.assertEqual(err, GATE_LOAD_STDERR_LINE.format(prog=prog, cause=cause) + "\n")
                        for marker in GATE_PASS_MARKERS:
                            self.assertNotIn(marker, out + err)


# ---------------------------------------------------------------------------------------------------------------
# The 8 non-gate siblings (conductor ruling bcd0a15c): a failed load of ANY kind ends the process non-zero with one
# fixed ::error literal built without the module, and the script does none of its work. Each code is the script's
# WA_EXIT_LOAD_REFUSED; the comment says what the other codes mean to the calling step, so the new one collides with
# none of them. "at 55b6a5d2" is what the same cell gave on the base of this lane (plain python3, every kind).
# ---------------------------------------------------------------------------------------------------------------
# At 55b6a5d2, unless a script's comment says otherwise ("BASE"): absent, unreadable, syntax error and raises ended the
# process by raw traceback, rc 1, last line e.g. "FileNotFoundError: [Errno 2] No such file or directory: '<path>'";
# sys.exit(0) at load ended it rc 0 with NO output; sys.exit(3) rc 3 with no output; nothing checked the attributes.
NON_GATE_LOAD_EXIT_CODES = {
    # 0 ok, 2 refused, 3 bad cap, 4 unreadable, 5 usage. BASE; a missing attribute ran on to the sweep
    # (rc 2 "refused: <target> ...")
    "scripts/ci-sweep-target.py": 6,
    # 0 green, 1 cannot dispatch or a red nightly (the report step files the issue), 2 argparse usage.
    # BASE; a missing attribute gave rc 0 with no output (report)
    "scripts/ci/ci_full_nightly.py": 3,
    # 0 resolved, 1 base rejected, 2 argparse usage. BASE; a missing attribute gave rc 1
    # "AttributeError: module 'workflow_annotation' has no attribute 'env_file_value'"
    "scripts/ci/impact/base_sha.py": 3,
    # 0 ok, 2 usage or a refused home. BASE; a missing attribute gave rc 1 "AttributeError: module
    # 'workflow_annotation' has no attribute 'env_file_value'" AFTER it had created the target directories
    "scripts/ci/shared_cargo_target.py": 3,
    # 0 ok, 2 usage, 3 sccache missing, 4 wrong cache. BASE; a missing attribute RAN sccache from PATH, then rc 4
    # "sccache_env: sccache --show-stats names no cache location (port 4227); refusing"
    "scripts/ci/sccache_env.py": 5,
    # 0 ok, 2 fail closed or argparse usage. Not BASE: its by-name partition_test_binaries import loaded first, so six
    # kinds gave rc 2 "partition_test_binaries: refused: shared module workflow_annotation.py next to the script cannot
    # be loaded (<cause>)" (another script's line); a missing attribute gave rc 0, no output, the split files WRITTEN
    "scripts/ci/pg_isolate_split.py": 3,
    # 0 ok, 2 usage. BASE; a missing attribute gave rc 1
    # "AttributeError: module 'workflow_annotation' has no attribute 'log_line'"
    "scripts/ci/prune_runner_artifacts.py": 3,
    # 0 ok, 2 usage, 3 mint, 143 terminated, 124/137 the watchdog (ci.yml), else cargo's own code (101, 1, 128+n);
    # the load runs before any child, so 4 is never a cargo code here. Not BASE: the load was lazy (_wa() :152-172), so
    # this cell gave rc 2 "pg_isolated_binary: set AI_MEMORY_TEST_POSTGRES_URL (or pass --url for local admin use)"
    # for every kind; a failed load surfaced only at the first annotation, by traceback or a silent sys.exit(0)
    "scripts/test/pg_isolated_binary.py": 4,
}
# setup --emit-env sends stdout into $GITHUB_ENV: the refusal goes to stderr there, never into the env file
SIBLING_LOAD_ERROR_TO_STDERR = frozenset({"scripts/test/pg_isolated_binary.py"})
SIBLING_LOAD_BREAKS = {  # failure kind -> (the planted shared module, None = absent and "" = mode 0; the cause named)
    "absent": (None, "FileNotFoundError"),
    "unreadable": ("", "PermissionError"),
    "syntax error": ("def broken(:\n", "SyntaxError"),
    "raises at load": ("raise RuntimeError('planted load failure')\n", "RuntimeError"),
    "sys.exit(0) at load": ("import sys\nsys.exit(0)\n", "SystemExit"),
    "sys.exit(3) at load": ("import sys\nsys.exit(3)\n", "SystemExit"),
    "required attribute missing": ("UNRELATED_NAME = 1\n", "AttributeError"),
}
GATE_ONLY_NEW_BREAKS = ("raises at load", "sys.exit(3) at load", "required attribute missing")
HOSTILE_CAUSE_SOURCE = "raise type('x\\n::error::pwn', (Exception,), {})()\n"
FALLBACK_CAUSE = "BaseException"
WORK_RUNNER_NAME = "runner-9365"
WORK_FAKE_TOOL = "sccache"  # a PATH stand-in that only records that it ran: a run after a failed load is work
WORK_BUILD_JSON_LINE = ('{"reason": "compiler-artifact", "executable": "/fx/deps/t9365", "profile": {"test": true},'
                        ' "target": {"kind": ["test"], "name": "t9365", "src_path": "tests/t9365.rs"}}')
WORK_SWEEP_CAP_BYTES = "1"  # below the 5-byte canary: a sweep that runs removes it


def sibling_load_lines(rel, cause):
    """(stdout, stderr) a failed load of ``rel`` must print: the cause line, then the one fixed ::error line."""
    prog = Path(rel).stem
    cause_line = GATE_LOAD_STDERR_LINE.format(prog=prog, cause=cause) + "\n"
    error_line = GATE_LOAD_ERROR_LINE.format(prog=prog) + "\n"
    if rel in SIBLING_LOAD_ERROR_TO_STDERR:
        return "", cause_line + error_line
    return error_line, cause_line


def sibling_work_argv(rel, fx):
    """Arguments under which ``rel`` does observable work (files under ``fx``) when its load passes; no network."""
    out = str(fx / "github-file")
    home, target, work = fx / "home", fx / "target", fx / "work"
    return {
        "scripts/ci-sweep-target.py": ["--target", str(target), "--max-bytes", WORK_SWEEP_CAP_BYTES],
        "scripts/ci/ci_full_nightly.py": ["report", "--repo", "owner/name", "--ref", "main", "--job-result", "success",
                                          "--conclusion", "success"],
        "scripts/ci/impact/base_sha.py": ["--repo", str(home), "--github-output", out],
        "scripts/ci/shared_cargo_target.py": ["--home", str(home), "--runner-name", WORK_RUNNER_NAME, "--github-env",
                                              out],
        "scripts/ci/sccache_env.py": ["--home", str(home), "--github-env", out],
        "scripts/ci/pg_isolate_split.py": ["--build-json", str(fx / "build.json"), "--serial-file",
                                           str(fx / "serial.txt"), "--out-dir", str(fx / "split-out")],
        "scripts/ci/prune_runner_artifacts.py": ["--work-root", str(work), "--workspace", str(work / "ws"),
                                                 "--protected-root", str(fx / "protected"), "--dry-run"],
        "scripts/test/pg_isolated_binary.py": ["setup", "--emit-env", "--db", "ai_memory_9365"],
    }.get(rel, ["--help"])


def tree_state(root, skip):
    """Every path under ``root`` (outside ``skip``) with its bytes, so any file the script writes shows up."""
    state = {}
    for path in sorted(root.rglob("*")):
        if skip in path.parents or path == skip:
            continue
        state[path.relative_to(root).as_posix()] = path.read_bytes() if path.is_file() else b"<dir>"
    return state


def sibling_load_run(base, rel, source, flags, script_root=None):
    """Run a fixture copy of ``rel`` with its shared module planted as ``source``; (rc, out, err, before, after)."""
    repo = base / "repo"
    for item in (rel, *SIBLING_SCRIPTS.get(rel, ()), SHARED_MODULE_PATH):
        (repo / item).parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile((script_root or REPO) / item if item != SHARED_MODULE_PATH else REPO / item, repo / item)
    shared = repo / SHARED_MODULE_PATH
    if source is None:
        shared.unlink()
    elif source == "":
        shared.chmod(0)
    else:
        shared.write_text(source, encoding="utf-8")
    fx = base / "fx"
    for sub in ("home", "target", "work/ws", "protected", "cwd", "bin"):
        (fx / sub).mkdir(parents=True, exist_ok=True)
    (fx / "target" / "canary").write_text("kept\n", encoding="utf-8")
    (fx / "github-file").write_text("", encoding="utf-8")
    (fx / "build.json").write_text(WORK_BUILD_JSON_LINE + "\n", encoding="utf-8")
    (fx / "serial.txt").write_text("", encoding="utf-8")
    fake_tool = fx / "bin" / WORK_FAKE_TOOL
    fake_tool.write_text("#!%s\nopen(%r, 'a').write('ran\\n')\n" % (sys.executable, str(fx / "tool-ran")),
                         encoding="utf-8")
    fake_tool.chmod(0o755)
    env = {"PATH": str(fx / "bin"), "LANG": "C.UTF-8", "PYTHONDONTWRITEBYTECODE": "1", "TMPDIR": str(fx / "cwd"),
           "HOME": str(fx / "home"), "GITHUB_ENV": str(fx / "github-file"), "GITHUB_OUTPUT": str(fx / "github-file")}
    before = tree_state(fx, fx / "cwd")
    proc = subprocess.run([sys.executable, *flags, str(repo / rel), *sibling_work_argv(rel, fx)], capture_output=True,
                          env=env, cwd=str(fx / "cwd"), timeout=SUBPROCESS_TIMEOUT_SECS, check=False)
    after = tree_state(fx, fx / "cwd")
    if source == "":
        shared.chmod(0o600)
    return (proc.returncode, proc.stdout.decode("utf-8", "replace"), proc.stderr.decode("utf-8", "replace"), before,
            after)


class SiblingLoadFailsClosed(unittest.TestCase):
    """Table: 8 non-gate siblings x 7 failure kinds x (plain, -I, -S) on fixture copies (ruling bcd0a15c)."""

    def cell(self, rel, kind, flags):
        base = scratch_dir("sibling-fail-closed")
        self.addCleanup(shutil.rmtree, str(base), True)
        source, cause = SIBLING_LOAD_BREAKS[kind]
        rc, out, err, before, after = sibling_load_run(base, rel, source, flags)
        want_out, want_err = sibling_load_lines(rel, cause)
        code = NON_GATE_LOAD_EXIT_CODES.get(rel, GATE_LOAD_EXIT_CODES.get(rel))
        self.assertNotEqual(rc, EXIT_OK_CODE, (out, err[-2000:]))
        self.assertEqual(rc, code, err[-2000:])
        self.assertEqual(out, want_out)
        self.assertEqual(err, want_err)
        self.assertEqual(after, before, "the script did work after a failed load")

    def test_failed_load_of_any_kind_fails_each_sibling_closed_9365(self):
        if os.geteuid() == 0:
            self.skipTest("root reads a mode-0 file")
        self.assertEqual(len(NON_GATE_LOAD_EXIT_CODES), 8)
        for rel in NON_GATE_LOAD_EXIT_CODES:
            for kind in SIBLING_LOAD_BREAKS:
                for label, flags in PYTHON_FLAG_SETS:
                    with self.subTest(script=rel, kind=kind, flags=label):
                        self.cell(rel, kind, flags)

    def test_the_one_shape_gives_the_gates_the_new_kinds_too_9365(self):
        """Every gate under the kinds its load table lacks: same exit code, same two lines."""
        if os.geteuid() == 0:
            self.skipTest("root reads a mode-0 file")
        for rel in GATE_LOAD_EXIT_CODES:
            for kind in GATE_ONLY_NEW_BREAKS:
                for label, flags in PYTHON_FLAG_SETS:
                    with self.subTest(script=rel, kind=kind, flags=label):
                        self.cell(rel, kind, flags)

    def test_a_hostile_exception_name_never_reaches_a_line_start_9365(self):
        """An exception class named with a newline and '::error::' is named as BaseException, never printed."""
        for rel in (*GATE_LOAD_EXIT_CODES, *NON_GATE_LOAD_EXIT_CODES):
            with self.subTest(script=rel):
                base = scratch_dir("sibling-hostile-cause")
                self.addCleanup(shutil.rmtree, str(base), True)
                rc, out, err, before, after = sibling_load_run(base, rel, HOSTILE_CAUSE_SOURCE, ())
                want_out, want_err = sibling_load_lines(rel, FALLBACK_CAUSE)
                self.assertEqual((rc, out, err), (NON_GATE_LOAD_EXIT_CODES.get(rel, GATE_LOAD_EXIT_CODES.get(rel)),
                                                  want_out, want_err))
                self.assertEqual(after, before)


# ---------------------------------------------------------------------------------------------------------------
# One loader shape (ruling bcd0a15c). decision: the inlined loader in every script over a shared helper because the
# helper would itself have to be loaded by path with the same code, which moves the shape without removing it.
# Detection method: ast. The walk covers every .py under scripts/ (tests and the shared module itself excluded); a
# script REFERENCES the module when an import, a name, an attribute or a string that is not a docstring contains
# ``workflow_annotation``. Such a script must hold the WA_* settings, exactly one ``_load_workflow_annotation`` and
# exactly one module-level ``try`` whose ast equals the canonical source below (the ::error literal is compared
# separately, against the script's WA_PROG), no other reference to the module, no other call of the loader, no
# non-stdlib import and no ``sys.path`` use before that ``try``, and every ``wa.<name>`` it uses in WA_REQUIRED.
# ---------------------------------------------------------------------------------------------------------------
LOADER_SCAN_ROOT = REPO / "scripts"
SHARED_STEM = SHARED_MODULE_NAME[:-3]
LOADER_NAME = "_load_workflow_annotation"
ERROR_LINE_PLACEHOLDER = "WA_ERROR_LINE"
REQUIRE_NAME = "require_workflow_annotation"
DEFERRED_SUPPORT_CLASSES = frozenset({"SharedModuleNotLoadedError", "_NotLoaded"})
TAINT_BOUNDARY_REL = "scripts/ci/taint_boundary.py"
LOADER_SHAPE_EXCEPTIONS = {
    # The first named exception: its floor check (Python >= 3.12) runs before every import, so its load is a
    # function called after the check, executes a fresh module object never put in sys.modules and checks
    # SHARED_MODULE_USED; by ruling bcd0a15c a failed load stays a ::warning, exit 0, nothing pruned.
    "scripts/ci/prune_runner_tmp.py": "floor check first; warning, exit 0, prunes nothing (ruling bcd0a15c)",
    # Issue 9561: the operand of the one open row of the python module form in ci.yml / check / "Run tests
    # (impact-aware)"; the script names the module as row text and never loads it. This entry leaves with the
    # row when 9561 closes.
    TAINT_BOUNDARY_REL: "the operand of the open row of issue 9561, row text only (leaves when 9561 closes)",
}
# An entry named here covers exactly one string constant whose whole value is this text; every other reference
# to the module in that file (an import, a name, an attribute, a second such string, a longer string) is still
# read as a load and must have the one shape.
LOADER_SHAPE_EXCEPTION_TEXTS = {TAINT_BOUNDARY_REL: SHARED_STEM}
# The exception count only goes down: a third entry needs its own ruling.
LOADER_SHAPE_EXCEPTION_COUNT = 2
WA_SETTINGS = ("WA_PROG", "WA_RELATIVE_PATH", "WA_REQUIRED", "WA_EXIT_LOAD_REFUSED", "WA_ERROR_TO_STDERR")
CANONICAL_LOADER_SOURCE = textwrap.dedent('''\
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


    try:
        wa = _load_workflow_annotation()
    except (Exception, SystemExit) as exc:  # any failed load: one fixed line built without the module, then exit
        wa_cause = type(exc).__name__
        print("%s: refused: shared module workflow_annotation.py next to the script cannot be loaded (%s)"
              % (WA_PROG, wa_cause if wa_cause.isidentifier() else "BaseException"), file=sys.stderr, flush=True)
        print(WA_ERROR_LINE, file=sys.stderr if WA_ERROR_TO_STDERR else sys.stdout, flush=True)
        sys.exit(WA_EXIT_LOAD_REFUSED)
    ''')


def _docstring_ids(tree):
    ids = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) and node.body:
            first = node.body[0]
            if isinstance(first, ast.Expr) and isinstance(first.value, ast.Constant) and isinstance(first.value.value, str):
                ids.add(id(first.value))
    return ids


def shared_module_references(tree):
    """Nodes that name the shared module: imports, names, attributes, non-docstring strings."""
    docstrings = _docstring_ids(tree)
    found = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import) and any(SHARED_STEM in alias.name for alias in node.names):
            found.append(node)
        elif isinstance(node, ast.ImportFrom) and (SHARED_STEM in (node.module or "")
                                                   or any(SHARED_STEM in alias.name for alias in node.names)):
            found.append(node)
        elif isinstance(node, ast.Name) and SHARED_STEM in node.id:
            found.append(node)
        elif isinstance(node, ast.Attribute) and SHARED_STEM in node.attr:
            found.append(node)
        elif (isinstance(node, ast.Constant) and isinstance(node.value, str) and SHARED_STEM in node.value
              and id(node) not in docstrings):
            found.append(node)
    return found


def references_outside_exception_text(references, text):
    """``references`` less the first string constant whose whole value is ``text``; a second one stays."""
    for index, node in enumerate(references):
        if isinstance(node, ast.Constant) and node.value == text:
            return references[:index] + references[index + 1:]
    return references


def _canonical_nodes():
    tree = ast.parse(CANONICAL_LOADER_SOURCE)
    return ast.dump(tree.body[0]), ast.dump(tree.body[1])


def _is_load_try(node):
    return (isinstance(node, ast.Try) and len(node.body) == 1 and isinstance(node.body[0], ast.Assign)
            and isinstance(node.body[0].value, ast.Call) and isinstance(node.body[0].value.func, ast.Name)
            and node.body[0].value.func.id == LOADER_NAME)


def loader_shape_violations(rel, source):
    """Every way ``source`` (at scripts-relative ``rel``) departs from the one shape; [] when it conforms or never
    references the shared module."""
    tree = ast.parse(source)
    references = shared_module_references(tree)
    if rel in LOADER_SHAPE_EXCEPTIONS:
        if rel not in LOADER_SHAPE_EXCEPTION_TEXTS:
            return []
        references = references_outside_exception_text(references, LOADER_SHAPE_EXCEPTION_TEXTS[rel])
    if not references:
        return []
    problems = []
    canonical_def, canonical_try = _canonical_nodes()
    defs = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == LOADER_NAME]
    tries = [node for node in tree.body if _is_load_try(node)]
    container = None  # the importable scripts load inside require_workflow_annotation(), which main calls first
    requires = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == REQUIRE_NAME]
    if not tries and len(requires) == 1:
        inner = [node for node in requires[0].body if _is_load_try(node)]
        shaped = (len(requires[0].body) == 3 and isinstance(requires[0].body[1], ast.Global)
                  and requires[0].body[1].names == ["wa"] and requires[0].body[2] is (inner[0] if inner else None))
        if len(inner) == 1 and shaped:
            tries, container = inner, requires[0]
    if len(defs) != 1:
        problems.append(f"{rel}: {len(defs)} module-level {LOADER_NAME} definitions (want 1)")
    elif ast.dump(defs[0]) != canonical_def:
        problems.append(f"{rel}:{defs[0].lineno}: {LOADER_NAME} differs from the canonical loader")
    if len(tries) != 1:
        problems.append(f"{rel}: {len(tries)} module-level load try blocks (want 1)")
        return problems
    load_try = tries[0]
    settings = {}
    anchor = container if container is not None else load_try
    for node in tree.body[:tree.body.index(anchor)]:
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            settings[node.targets[0].id] = node.value
    for name in WA_SETTINGS:
        if name not in settings:
            problems.append(f"{rel}: {name} is not set before the load try")
    # the loader, the load try and the WA_RELATIVE_PATH value are the only places that may name the module
    roots = [*defs, load_try, *([settings["WA_RELATIVE_PATH"]] if "WA_RELATIVE_PATH" in settings else [])]
    if container is not None:
        mains = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "main"]
        first = mains[0].body[0] if len(mains) == 1 and mains[0].body else None
        if not (isinstance(first, ast.Expr) and isinstance(first.value, ast.Call)
                and isinstance(first.value.func, ast.Name) and first.value.func.id == REQUIRE_NAME):
            problems.append(f"{rel}: main does not call {REQUIRE_NAME}() as its first statement")
        else:
            roots.append(first)
        roots += [node for node in tree.body if isinstance(node, ast.ClassDef) and node.name in DEFERRED_SUPPORT_CLASSES]
        roots += [node for node in tree.body if isinstance(node, ast.Assign) and len(node.targets) == 1
                  and isinstance(node.targets[0], ast.Name) and node.targets[0].id == "wa"
                  and ast.dump(node.value) == ast.dump(ast.parse("_NotLoaded()").body[0].value)]
        roots.append(container)
        if sum(1 for node in ast.walk(tree) if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
               and node.func.id == REQUIRE_NAME) != 1:
            problems.append(f"{rel}: {REQUIRE_NAME}() is not called exactly once")
    inside = {id(node) for root in roots for node in ast.walk(root)}
    error_literal = None
    handler = load_try.handlers[0] if len(load_try.handlers) == 1 else None
    try:
        call = handler.body[2].value
        if isinstance(call.args[0], ast.Constant) and isinstance(call.args[0].value, str):
            error_literal = call.args[0].value
            call.args[0] = ast.Name(id=ERROR_LINE_PLACEHOLDER, ctx=ast.Load())
    except (AttributeError, IndexError, TypeError):
        problems.append(f"{rel}:{load_try.lineno}: the load try has no readable ::error line")
    if ast.dump(load_try) != canonical_try:
        problems.append(f"{rel}:{load_try.lineno}: the load try differs from the canonical one")
    prog = settings.get("WA_PROG")
    if not (isinstance(prog, ast.Constant) and prog.value == Path(rel).stem):
        problems.append(f"{rel}: WA_PROG is not the literal {Path(rel).stem!r}")
    elif error_literal != GATE_LOAD_ERROR_LINE.format(prog=prog.value):
        problems.append(f"{rel}: the ::error line is not the fixed literal for {prog.value}")
    rel_path = settings.get("WA_RELATIVE_PATH")
    if not (isinstance(rel_path, ast.Constant) and isinstance(rel_path.value, str)
            and os.path.normpath(os.path.join(os.path.dirname(rel), rel_path.value)) == SHARED_MODULE_PATH):
        problems.append(f"{rel}: WA_RELATIVE_PATH does not name {SHARED_MODULE_PATH}")
    required = settings.get("WA_REQUIRED")
    names = ([elt.value for elt in required.elts if isinstance(elt, ast.Constant)]
             if isinstance(required, ast.Tuple) else [])
    if not names or len(names) != len(required.elts):
        problems.append(f"{rel}: WA_REQUIRED is not a non-empty tuple of literal names")
    used = {node.attr for node in ast.walk(tree) if isinstance(node, ast.Attribute)
            and isinstance(node.value, ast.Name) and node.value.id == "wa"}
    if used - set(names):
        problems.append(f"{rel}: wa.{', wa.'.join(sorted(used - set(names)))} not in WA_REQUIRED")
    to_stderr = settings.get("WA_ERROR_TO_STDERR")
    if not (isinstance(to_stderr, ast.Constant) and isinstance(to_stderr.value, bool)):
        problems.append(f"{rel}: WA_ERROR_TO_STDERR is not a literal bool")
    for node in references:
        if id(node) not in inside:
            problems.append(f"{rel}:{node.lineno}: references the shared module outside the one loader")
    for node in ast.walk(tree):
        if (isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == LOADER_NAME
                and id(node) not in inside):
            problems.append(f"{rel}:{node.lineno}: calls {LOADER_NAME} outside the load try")
    for node in tree.body[:tree.body.index(anchor)]:
        for inner in ast.walk(node):
            if isinstance(inner, ast.Import):
                modules = [alias.name for alias in inner.names]
            elif isinstance(inner, ast.ImportFrom):
                modules = [inner.module or ""]
            else:
                modules = []
            for module in modules:
                if module.split(".")[0] not in sys.stdlib_module_names and module != "__future__":
                    problems.append(f"{rel}:{inner.lineno}: imports {module} before the load try")
            if (isinstance(inner, ast.Attribute) and inner.attr == "path" and isinstance(inner.value, ast.Name)
                    and inner.value.id == "sys"):
                problems.append(f"{rel}:{inner.lineno}: uses sys.path before the load try")
    return problems


def loader_scan_files(root):
    """Every script under ``root`` the one-shape rule covers (tests and the shared module itself excluded)."""
    return [path for path in sorted(root.rglob("*.py"))
            if "tests" not in path.relative_to(root).parts and path.name != SHARED_MODULE_NAME]


class LoaderShape(unittest.TestCase):
    """Structural cell: every script under scripts/ that names the shared module loads it by the one shape."""

    def test_every_script_naming_the_shared_module_has_the_one_shape_9365(self):
        problems, conforming = [], set()
        for path in loader_scan_files(LOADER_SCAN_ROOT):
            rel = path.relative_to(REPO).as_posix()
            source = path.read_text(encoding="utf-8")
            found = loader_shape_violations(rel, source)
            problems.extend(found)
            if not found and shared_module_references(ast.parse(source)) and rel not in LOADER_SHAPE_EXCEPTIONS:
                conforming.add(rel)
        self.assertEqual(problems, [])
        self.assertEqual(conforming, set(GATE_LOAD_EXIT_CODES) | set(NON_GATE_LOAD_EXIT_CODES))

    def test_the_shape_check_flags_every_other_way_to_load_9365(self):
        """Mutants of a conforming script: each other load form is a violation (the check is not vacuous)."""
        rel = "scripts/ci/shared_cargo_target.py"
        source = (REPO / rel).read_text(encoding="utf-8")
        self.assertEqual(loader_shape_violations(rel, source), [])
        mutants = {
            "import by name": source + "\nimport workflow_annotation\n",
            "sys.path insert": source.replace("import argparse\n", "import argparse\nimport sys\n"
                                              "sys.path.insert(0, '.')\n", 1),
            "dunder import": source + "\nwa = __import__('workflow_annotation')\n",
            "second loader call": source + "\nwa = _load_workflow_annotation()\n",
            "exit 0 on failure": source.replace("sys.exit(WA_EXIT_LOAD_REFUSED)", "sys.exit(0)", 1),
            "no required check": source.replace("    if missing:\n", "    if False:\n", 1),
            "load at import time": source + "\nrequire_workflow_annotation()\n",
            "main without the load": source.replace("def main(argv=None):\n    require_workflow_annotation()\n",
                                                    "def main(argv=None):\n", 1),
            "interpolated error line": source.replace(
                'print("::error title=shared_cargo_target refused::', 'print("::error title=%s refused::' % "x", 1),
        }
        for label, mutant in mutants.items():
            with self.subTest(mutant=label):
                self.assertNotEqual(mutant, source, "the mutant did not change the script")
                self.assertNotEqual(loader_shape_violations(rel, mutant), [])
        no_references = "import os\nprint(os.sep)\n"
        self.assertEqual(loader_shape_violations("scripts/ci/new_tool.py", no_references), [])
        self.assertNotEqual(loader_shape_violations("scripts/ci/new_tool.py", "import workflow_annotation\n"), [])

    def test_prune_runner_tmp_is_the_whole_file_exception_9365(self):
        self.assertIn("scripts/ci/" + PRUNE_SCRIPT_NAME, LOADER_SHAPE_EXCEPTIONS)
        self.assertNotIn("scripts/ci/" + PRUNE_SCRIPT_NAME, LOADER_SHAPE_EXCEPTION_TEXTS)
        source = (CI_DIR / PRUNE_SCRIPT_NAME).read_text(encoding="utf-8")
        self.assertTrue(shared_module_references(ast.parse(source)), "the exception must still name the module")

    def test_the_exception_count_is_pinned_and_the_9561_entry_is_one_string_9561(self):
        """Two exceptions, no more; the 9561 entry covers the one row string of taint_boundary.py and nothing else."""
        self.assertEqual(len(LOADER_SHAPE_EXCEPTIONS), LOADER_SHAPE_EXCEPTION_COUNT)
        self.assertEqual(set(LOADER_SHAPE_EXCEPTIONS), {"scripts/ci/" + PRUNE_SCRIPT_NAME, TAINT_BOUNDARY_REL})
        self.assertEqual(LOADER_SHAPE_EXCEPTION_TEXTS, {TAINT_BOUNDARY_REL: SHARED_STEM})
        source = (REPO / TAINT_BOUNDARY_REL).read_text(encoding="utf-8")
        references = shared_module_references(ast.parse(source))
        # The entry leaves with the row: the file names the module exactly once, as that one whole string.
        self.assertEqual([(type(node).__name__, node.value) for node in references], [("Constant", SHARED_STEM)])
        self.assertEqual(loader_shape_violations(TAINT_BOUNDARY_REL, source), [])
        row_line = f'"{SHARED_STEM}"'
        self.assertEqual(source.count(row_line), 1)
        mutants = {
            "import by name elsewhere": source + f"\nimport {SHARED_STEM}\n",
            "a second row string": source + f"\nSECOND = {row_line}\n",
            "a longer string": source.replace(row_line, f'"{SHARED_MODULE_NAME}"', 1),
            "a name": source + f"\n{SHARED_STEM} = None\n",
            "an attribute": source + f"\nsys.{SHARED_STEM}\n",
            "dunder import": source + f"\nwa = __import__({row_line})\n",
        }
        for label, mutant in mutants.items():
            with self.subTest(mutant=label):
                self.assertNotEqual(mutant, source, "the mutant did not change the script")
                self.assertEqual(loader_shape_violations(TAINT_BOUNDARY_REL, mutant)[:2], [
                    f"{TAINT_BOUNDARY_REL}: 0 module-level {LOADER_NAME} definitions (want 1)",
                    f"{TAINT_BOUNDARY_REL}: 0 module-level load try blocks (want 1)"])
        # The entry is load-bearing: without it the row string alone is read as a load.
        entry = LOADER_SHAPE_EXCEPTIONS.pop(TAINT_BOUNDARY_REL)
        try:
            self.assertNotEqual(loader_shape_violations(TAINT_BOUNDARY_REL, source), [])
        finally:
            LOADER_SHAPE_EXCEPTIONS[TAINT_BOUNDARY_REL] = entry


# ---------------------------------------------------------------------------------------------------------------
# v1 workflow-command form (#9365 r2, finding 1 of REVIEW-9400-combined-r1).
#
# Runner rule (actions/runner src/Runner.Common/ActionCommand.cs, read 2026-11-16; ActionCommandManager tries
# TryParseV2 first, then TryParse): v2 = ``message.TrimStart()`` then ``StartsWith("::")``; v1 = ``message.IndexOf("##[")``
# ANYWHERE in the line, no trim, then ``IndexOf(']')``. The runner reads stdout and stderr lines alike, so both count.
# Invariant for every value v: every line a public emitting function of the module returns for v (a) starts a
# workflow command only with the fixed head the module wrote, (b) holds no ``##[`` at all (the module never intends
# a v1 command) and no ``::`` that came from v at the trimmed line start, (c) is one line by ``str.splitlines``.
# ---------------------------------------------------------------------------------------------------------------

V1_PREFIX = "##["
V1_HOSTILE = {
    "v1_start": "##[error]x",
    "v1_mid": "a ##[warning]b",
    "v1_after_space": " \t\u00a0##[error]x",
    "v1_triple_hash": "###[error]x",
    "v1_quad_hash_double_bracket": "####[[error]x",
    "v1_lead_bracket": "[error]x",
    "v1_tail_hash": "abc#",
    "v1_tail_double_hash": "abc##",
    "v1_with_v2": "::##[error]::x",
    "v1_v2_inside": "##[error]::error::x",
    "v1_percent": "%23%23[error]%0A##[error]",
    "v1_cr": "a\r##[error]x",
    "v1_lf": "a\n##[error]x",
    "v1_u2028": "a\u2028##[error]x\u2029##[warning]y",
    "v1_nul": "a\x00##[error]x",
    "v1_backslash": "\\##[error]x",
    "colon_run": "::::x:::",
    "benign_hash": "PR #9365 [ok]",
}
V1_SPLIT_PAIRS = (("#", "#[error]x"), ("##", "[error]x"), ("a#", "#["), ("#", "["), ("x##", "[y"), ("", "##[e]"))
V1_HUGE_CHARS = 120_000  # the 100K+ size cell
V1_HUGE_WALL_CLOCK_SECS = 5.0
# exact outputs, written out by hand from the rule (escape the "#" that precedes "#"/"[", the "[" that
# follows "#", the ":" that precedes ":"), independent of the module's code
V1_SAFE_TEXT_EXACT = {
    "##[error]x": "\\x23\\x23\\x5berror]x",
    "a ##[warning]b": "a \\x23\\x23\\x5bwarning]b",
    "###[error]x": "\\x23\\x23\\x23\\x5berror]x",
    "####[[error]x": "\\x23\\x23\\x23\\x23\\x5b[error]x",
    "[error]x": "[error]x",
    "[Errno 13] denied": "[Errno 13] denied",
    "abc#": "abc#",
    "::::x:::": "\\x3a\\x3a\\x3a:x\\x3a\\x3a:",
    "a\n##[error]x": "a\\x0a\\x23\\x23\\x5berror]x",
    "%23%23[error]": "\\x2523\\x2523[error]",
    "PR #9365 [ok]": "PR #9365 [ok]",
}
V1_SAFE_VALUE_EXACT = {"##[e]:x": "\\x23\\x23\\x5be]\\x3ax", "a::b#": "a\\x3a\\x3ab#"}
V1_PROPERTY_EXACT = {"a,b:##[": "a\\x2cb\\x3a\\x23\\x23\\x5b"}
V1_LOG_LINE_EXACT = {
    "##[error]x": "##\\x5berror]x",
    "removed /w/a ##[warning]b": "removed /w/a ##\\x5bwarning]b",
    "###[e]": "###\\x5be]",
    "  ::##[e]": "  \\x3a:##\\x5be]",
    "a\n##[e]": "a\\x0a##\\x5be]",
    "##[a]##[b]": "##\\x5ba]##\\x5bb]",
    "PR #9365 [ok]": "PR #9365 [ok]",
}
V1_ANNOTATION_EXACT = (
    (("warning", "##[error]x"), {}, "::warning::\\x23\\x23\\x5berror]x"),
    (("error", "m"), {"title": "##[e]"}, "::error title=\\x23\\x23\\x5be]::m"),
    (("error", "[coverage-pg] PG-ENV x"), {}, "::error::[coverage-pg] PG-ENV x"),
    (("notice", "[#7914 semaphore] 'T': slot"), {}, "::notice::[#7914 semaphore] 'T': slot"),
)
V1_JOIN_EXACT = ((("", ["#", "#", "[x"]), "##\\x5bx"), ((", ", ["a#", "[b"]), "a#, [b"))
V1_RENDER_EXACT = (
    (("{a}{b}", {"a": "#", "b": "#[x"}), "#\\x23\\x5bx"),
    (("{p}: {why}", {"p": "p", "why": "[Errno 13] denied"}), "p: [Errno 13] denied"),
    (("##{v}", {"v": "[error]"}), "##\\x5berror]"),
    (("{v}[e]", {"v": "##"}), "\\x23#[e]"),
    (("##[{v}", {"v": "x"}), "##\\x5bx"),
)
V1_ENV_FILE_EXACT = {"##[error]x\n": "##[error]x "}  # a KEY=value file line keeps the bytes (data, not a log line)
# which public functions emit a log or annotation line and which only build a $GITHUB_* file value
V1_FILE_ONLY_FUNCTIONS = frozenset({"env_file_value"})


def runner_would_parse(line):
    """True when the runner rule above reads ``line`` as a workflow command (v2 by Python's wider lstrip set)."""
    return line.lstrip().startswith("::") or V1_PREFIX in line


class V1FormNeutralised(unittest.TestCase):
    """Every public emitting function of the module, over the v1 corpus, exact and by property (#9365 r2)."""

    @classmethod
    def setUpClass(cls):
        import inspect
        cls.wa = load_module(CI_DIR / SHARED_MODULE_NAME, "workflow_annotation_9365_v1")
        cls.public = sorted(name for name, obj in vars(cls.wa).items()
                            if not name.startswith("_") and inspect.isfunction(obj))

    def cells(self):
        """name -> (value -> list of emitted lines, the fixed command head the module may write or None)."""
        wa = self.wa
        return {
            "safe_text": (lambda v: [wa.safe_text(v)], None),
            "safe_value": (lambda v: [wa.safe_value(v)], None),
            "property_value": (lambda v: [wa.property_value(v)], None),
            "log_line": (lambda v: [wa.log_line(v)], None),
            "render": (lambda v: [wa.render("{prog}: refused: {v}", prog="p", v=v), wa.render("{v}", v=v)], None),
            "join": (lambda v: [wa.join(", ", [v, v]), wa.join("", [v, "x", v])], None),
            "annotation": (lambda v: [wa.annotation("warning", v, title=v),
                                      wa.annotation("error", wa.render("##{v}", v=v))], ("::warning", "::error")),
            "end_group_line": (lambda v: [wa.end_group_line()], ("::endgroup::",)),
            "env_file_value": (lambda v: [wa.env_file_value(v)], None),
        }

    def corpus(self):
        values = list(V1_HOSTILE.values()) + list(HOSTILE.values())
        values += [a + b for a, b in V1_SPLIT_PAIRS]
        return values

    def test_every_public_function_has_a_cell_9365(self):
        self.assertEqual(self.public, sorted(self.cells()), "a new public function needs a v1 cell")

    def assert_line_safe(self, name, line, heads):
        self.assertEqual(len(line.splitlines()), 1 if line else 0, (name, line[:200]))
        if name in V1_FILE_ONLY_FUNCTIONS:
            return
        self.assertNotIn(V1_PREFIX, line, (name, line[:200]))
        if line.lstrip().startswith("::"):
            self.assertTrue(heads and any(line.startswith(head) for head in heads), (name, line[:200]))
            second = line.find("::", 2)  # the command's own second "::" (absent when a long property was cut)
            if heads != ("::endgroup::",) and second != -1:
                self.assertFalse(runner_would_parse(line[second + 2:]), (name, line[:200]))

    def test_no_value_starts_a_command_through_any_function_9365(self):
        for name, (emit, heads) in self.cells().items():
            for value in self.corpus():
                with self.subTest(function=name, value=value[:40]):
                    for line in emit(value):
                        self.assert_line_safe(name, line, heads)

    def test_split_values_joined_by_the_module_never_build_the_v1_form_9365(self):
        wa = self.wa
        for left, right in V1_SPLIT_PAIRS:
            with self.subTest(pair=(left, right)):
                for line in (wa.join("", [left, right]), wa.render("{a}{b}", a=left, b=right),
                             wa.safe_text(left) + wa.safe_text(right), wa.annotation("notice", left + right),
                             wa.log_line(left + right)):
                    self.assertNotIn(V1_PREFIX, line)

    def test_exact_outputs_9365(self):
        wa = self.wa
        for function, table in ((wa.safe_text, V1_SAFE_TEXT_EXACT), (wa.safe_value, V1_SAFE_VALUE_EXACT),
                                (wa.property_value, V1_PROPERTY_EXACT), (wa.log_line, V1_LOG_LINE_EXACT),
                                (wa.env_file_value, V1_ENV_FILE_EXACT)):
            for value, expected in table.items():
                with self.subTest(function=function.__name__, value=value):
                    self.assertEqual(function(value), expected)
        for args, kwargs, expected in V1_ANNOTATION_EXACT:
            with self.subTest(annotation=args):
                self.assertEqual(wa.annotation(*args, **kwargs), expected)
        for (separator, parts), expected in V1_JOIN_EXACT:
            with self.subTest(join=parts):
                self.assertEqual(wa.join(separator, parts), expected)
        for (template, values), expected in V1_RENDER_EXACT:
            with self.subTest(render=template):
                self.assertEqual(wa.render(template, **values), expected)
        self.assertEqual(wa.end_group_line(), "::endgroup::")

    def test_safe_text_leaves_no_double_colon_9365(self):
        """The docstring's claim (finding 2): no ``::`` survives ``safe_text`` for any run of colons."""
        for count in range(1, 12):
            with self.subTest(colons=count):
                self.assertNotIn("::", self.wa.safe_text(":" * count))
                self.assertNotIn("::", self.wa.safe_text("a" + ":" * count + "b"))

    def test_huge_v1_input_is_linear_and_bounded_9365(self):
        wa = self.wa
        value = (V1_PREFIX * (V1_HUGE_CHARS // len(V1_PREFIX) + 1))[:V1_HUGE_CHARS]
        started = time.monotonic()
        lines = [wa.safe_text(value), wa.log_line(value), wa.annotation("warning", value),
                 wa.join("", [value, value]), wa.render("{v}", v=value)]
        self.assertLess(time.monotonic() - started, V1_HUGE_WALL_CLOCK_SECS)
        for line in lines:
            self.assertNotIn(V1_PREFIX, line)
        self.assertLessEqual(len(lines[2]), LINE_BOUND_CHARS)


# ---------------------------------------------------------------------------------------------------------------
# Stream ratchet (#9365 r2): in the 14 scripts every print()/sys.std*.write() argument is a literal, a shared-module
# call, or a value the AST can trace to one. The runner parses ``##[`` anywhere in a stdout or stderr line, so a raw
# variable in any printed line is a command carrier. Exempt: the canonical load try (it runs before the module
# exists; LoaderShape pins its exact AST and its only variable is an identifier-checked type name).
# Blind spots (stated): a value written to a stream through another module; ``exec``/``eval``; output of a child
# process the script lets through unchanged (cargo, psql: the child's own lines, not the script's text).
# ---------------------------------------------------------------------------------------------------------------

STREAM_SCRIPTS = tuple(sorted(set(GATE_LOAD_EXIT_CODES) | set(NON_GATE_LOAD_EXIT_CODES) | {"scripts/ci/" + PRUNE_SCRIPT_NAME}))
STREAM_SHARED_CALLS = SHARED_FIELD_FUNCTIONS | {"safe_value", "render", "join", "end_group_line"}
STREAM_NUMBER_CALLS = frozenset({"len", "int", "float", "round", "abs"})  # return a number for any argument
STREAM_TRACE_DEPTH = 6
STREAM_SCRIPT_COUNT = 15  # 14 + suite_budget (#9229)
STREAM_MODULE_VARS = frozenset({"wa"})  # the name every script binds the loaded module to
# Runs before the shared module exists, so it cannot use it; each output is fixed text pinned by its own test:
# prune_runner_tmp's floor check (VERSION_REFUSAL_AT_0F1EC1B7 cells) and load refusal (SiblingLoadFailsClosed, P1).
STREAM_PRELOAD_FUNCTIONS = {"scripts/ci/prune_runner_tmp.py": frozenset({"load_refused"}),
                            "scripts/ci/partition_test_binaries.py": frozenset({"require_workflow_annotation"}),
                            "scripts/ci/shared_cargo_target.py": frozenset({"require_workflow_annotation"})}
STREAM_PRELOAD_GUARD_CALL = "python_refusal"  # a module-level ``if`` that calls it is the floor check


class StreamTracer:
    """Decide, from one file's AST alone, whether an expression's text can only come from literals or the module."""

    def __init__(self, tree, rel=""):
        self.tree = tree
        self.parents = {}
        for parent in ast.walk(tree):
            for child in ast.iter_child_nodes(parent):
                self.parents[child] = parent
        self.functions = {}
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                self.functions.setdefault(node.name, []).append(node)
        self.exempt = set()
        preload = STREAM_PRELOAD_FUNCTIONS.get(rel, frozenset())
        for node in tree.body:
            is_floor = isinstance(node, ast.If) and any(
                isinstance(sub, ast.Call) and isinstance(sub.func, ast.Name) and sub.func.id == STREAM_PRELOAD_GUARD_CALL
                for sub in ast.walk(node.test))
            is_preload = isinstance(node, ast.FunctionDef) and node.name in preload
            if _is_load_try(node) or is_floor or is_preload:
                self.exempt.update(id(sub) for sub in ast.walk(node))
        # a bare name bound at module level to ``getattr(wa, "<shared function>", ...)`` is that shared function
        self.shared_aliases = set()
        for node in tree.body:
            if (isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name)
                    and isinstance(node.value, ast.Call) and isinstance(node.value.func, ast.Name)
                    and node.value.func.id == "getattr" and len(node.value.args) >= 2
                    and isinstance(node.value.args[0], ast.Name) and node.value.args[0].id in STREAM_MODULE_VARS
                    and isinstance(node.value.args[1], ast.Constant)
                    and node.value.args[1].value in STREAM_SHARED_CALLS):
                self.shared_aliases.add(node.targets[0].id)

    def enclosing_function(self, node):
        node = self.parents.get(node)
        while node is not None and not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            node = self.parents.get(node)
        return node

    @staticmethod
    def call_name(call):
        func = call.func
        return func.id if isinstance(func, ast.Name) else func.attr if isinstance(func, ast.Attribute) else None

    def ok(self, node, depth=0):
        if depth > STREAM_TRACE_DEPTH:
            return False
        nxt = depth + 1
        if isinstance(node, ast.Constant):
            return True
        if isinstance(node, ast.JoinedStr):
            return all(self.ok(part.value if isinstance(part, ast.FormattedValue) else part, nxt) for part in node.values)
        if isinstance(node, ast.BinOp):
            return self.ok(node.left, nxt) and self.ok(node.right, nxt)
        if isinstance(node, ast.UnaryOp):
            return self.ok(node.operand, nxt)
        if isinstance(node, (ast.Tuple, ast.List)):
            return all(self.ok(elt, nxt) for elt in node.elts)
        if isinstance(node, ast.BoolOp):
            return all(self.ok(value, nxt) for value in node.values)
        if isinstance(node, ast.IfExp):
            return self.ok(node.body, nxt) and self.ok(node.orelse, nxt)
        if isinstance(node, ast.Compare):
            return True  # a bool
        if isinstance(node, ast.Call):
            return self.call_ok(node, nxt)
        if isinstance(node, ast.Name):
            return self.name_ok(node, nxt)
        return False

    def call_ok(self, call, depth):
        name = self.call_name(call)
        func = call.func
        if (isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name) and func.value.id in STREAM_MODULE_VARS
                and name in STREAM_SHARED_CALLS):
            return True
        if isinstance(func, ast.Name) and name in self.shared_aliases:
            return True
        if isinstance(call.func, ast.Name) and name in STREAM_NUMBER_CALLS:
            return True
        if (name == "format" and isinstance(call.func, ast.Attribute) and self.ok(call.func.value, depth)
                and all(self.ok(arg, depth) for arg in call.args) and all(self.ok(kw.value, depth) for kw in call.keywords)):
            return True
        defs = self.functions.get(name)
        if not defs or not (isinstance(call.func, ast.Name) or (isinstance(call.func, ast.Attribute)
                                                                 and isinstance(call.func.value, ast.Name)
                                                                 and call.func.value.id == "self")):
            return False
        for func in defs:
            returns = [node for node in ast.walk(func) if isinstance(node, ast.Return)]
            if not returns or not all(ret.value is None or self.ok(ret.value, depth) for ret in returns):
                return False
        return True

    def bindings(self, scope, name):
        """Every node that binds ``name`` in ``scope`` (a function, or the module): values, or None for a form we cannot trace."""
        found = []
        body = scope.body if isinstance(scope, ast.Module) else [scope]
        for root in body:
            for node in ast.walk(root):
                if node is not scope and isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
                    if isinstance(scope, ast.Module):
                        continue
                if isinstance(node, ast.Assign):
                    for target in node.targets:
                        if isinstance(target, ast.Name) and target.id == name:
                            found.append(node.value)
                        elif any(isinstance(sub, ast.Name) and sub.id == name for sub in ast.walk(target)):
                            found.append(None)
                elif isinstance(node, (ast.AnnAssign, ast.AugAssign)) and isinstance(node.target, ast.Name) \
                        and node.target.id == name:
                    found.append(node.value if isinstance(node, ast.AnnAssign) else None)
                elif isinstance(node, (ast.For, ast.comprehension, ast.With, ast.ExceptHandler, ast.NamedExpr)):
                    targets = ([node.target] if isinstance(node, (ast.For, ast.comprehension, ast.NamedExpr))
                               else [item.optional_vars for item in node.items] if isinstance(node, ast.With)
                               else [])
                    if isinstance(node, ast.ExceptHandler) and node.name == name:
                        found.append(None)
                    for target in targets:
                        if target is not None and any(isinstance(sub, ast.Name) and sub.id == name
                                                      for sub in ast.walk(target)):
                            found.append(None)
        return found

    def name_ok(self, node, depth):
        func = self.enclosing_function(node)
        if func is not None:
            params = [arg.arg for arg in func.args.posonlyargs + func.args.args + func.args.kwonlyargs]
            if node.id in params:
                return self.param_ok(func, node.id, depth)
            local = self.bindings(func, node.id)
            if local:
                return all(value is not None and self.ok(value, depth) for value in local)
        module_level = self.bindings(self.tree, node.id)
        return bool(module_level) and all(value is not None and self.ok(value, depth) for value in module_level)

    def param_ok(self, func, param, depth):
        """Every in-file call of ``func`` passes a traceable value for ``param`` (no caller in the file: not traceable)."""
        positional = [arg.arg for arg in func.args.posonlyargs + func.args.args]
        if positional and positional[0] == "self":
            positional = positional[1:]
        index = positional.index(param) if param in positional else None
        default = None
        defaults = func.args.defaults
        all_args = func.args.posonlyargs + func.args.args
        if param in [arg.arg for arg in all_args[len(all_args) - len(defaults):]]:
            default = defaults[[arg.arg for arg in all_args[len(all_args) - len(defaults):]].index(param)]
        calls = [node for node in ast.walk(self.tree) if isinstance(node, ast.Call) and self.call_name(node) == func.name]
        if not calls:
            return False
        for call in calls:
            given = [kw.value for kw in call.keywords if kw.arg == param]
            if not given and index is not None and index < len(call.args):
                given = [call.args[index]]
            if any(isinstance(arg, ast.Starred) for arg in call.args):
                return False
            if not given:
                if default is None or not self.ok(default, depth):
                    return False
                continue
            if not self.ok(given[0], depth):
                return False
        return True


def stream_violations(rel, source):
    """Every print()/sys.stdout.write()/sys.stderr.write() argument in ``source`` that is not traceable."""
    tree = ast.parse(source)
    tracer = StreamTracer(tree, rel)
    found = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or id(node) in tracer.exempt:
            continue
        func = node.func
        is_print = isinstance(func, ast.Name) and func.id == "print"
        is_write = (isinstance(func, ast.Attribute) and func.attr == "write" and isinstance(func.value, ast.Attribute)
                    and func.value.attr in ("stdout", "stderr") and isinstance(func.value.value, ast.Name)
                    and func.value.value.id == "sys")
        if not (is_print or is_write):
            continue
        for arg in node.args:
            if isinstance(arg, ast.Starred) or not tracer.ok(arg):
                found.append("%s:%d %s" % (rel, node.lineno, ast.unparse(arg)[:80]))
    return found


class StreamRatchet(unittest.TestCase):
    def test_the_fifteen_scripts_print_only_traceable_text_9365(self):
        self.assertEqual(len(STREAM_SCRIPTS), STREAM_SCRIPT_COUNT)
        found = []
        for rel in STREAM_SCRIPTS:
            found.extend(stream_violations(rel, (REPO / rel).read_text(encoding="utf-8")))
        self.assertEqual(found, [], "\n".join(found))

    def test_the_ratchet_catches_a_raw_print_in_every_script_9365(self):
        """Mutant per script: one raw print of a variable carrying ``##[`` is a violation in each of the 14."""
        for rel in STREAM_SCRIPTS:
            source = (REPO / rel).read_text(encoding="utf-8")
            for label, extra in (("print", "\ndef _mut9365(value):\n    print(value)\n\n_mut9365('##[error]x')\n"
                                           "_mut9365(str(object()))\n"),
                                 ("format", "\ndef _mut9365(value):\n    print('x %s' % value, file=sys.stderr)\n\n"
                                            "_mut9365(sys.argv[0])\n"),
                                 ("write", "\nsys.stdout.write(sys.argv[0] + '\\n')\n")):
                with self.subTest(script=rel, mutant=label):
                    self.assertNotEqual(stream_violations(rel, source + extra), [])

    def test_the_ratchet_accepts_module_built_and_literal_lines_9365(self):
        sample = ("PROG = 'p'\n"
                  "def out(line):\n    print(line)\n"
                  "def note(n):\n    return wa.log_line('n=%s' % n)\n"
                  "out(wa.annotation('warning', 'x'))\nout(note(3))\n"
                  "print('%s: %d items' % (PROG, len([])))\nsys.stderr.write(wa.log_line(PROG) + '\\n')\n")
        self.assertEqual(stream_violations("sample", sample), [])

    def test_no_literal_ends_in_a_double_hash_9365(self):
        """The left edge of ``safe_text``: a value keeps a leading ``[``, so no script literal may end in ``##``."""
        found = []
        for rel in STREAM_SCRIPTS:
            found.extend(double_hash_literals(rel, (REPO / rel).read_text(encoding="utf-8")))
        self.assertEqual(found, [], "\n".join(found))
        self.assertEqual(double_hash_literals("m", "print(f'x ##{wa.safe_text(v)}')\n"), ["m:1 literal ends in ##"])
        self.assertEqual(double_hash_literals("m", "print('PR #' + wa.safe_text(v))\n"), [])


def double_hash_literals(rel, source):
    """Every constant string part (f-string parts too) that ends in ``##``: it would meet a value's leading ``[``."""
    return ["%s:%d literal ends in ##" % (rel, node.lineno) for node in ast.walk(ast.parse(source))
            if isinstance(node, ast.Constant) and isinstance(node.value, str) and node.value.endswith(DOUBLE_HASH)]


DOUBLE_HASH = "##"


# ---------------------------------------------------------------------------------------------------------------
# r3 (#9365, REVIEW-9400-combined-r2 finding 1): the left edge is held where the line is finished, not by the last
# character of a value. Two invariants, one named predicate (``finished_line_command_count``) used by every cell:
#   INV-A clean bytes: a value with no workflow-command piece (no ``##``, ``#[``, ``::``, line break, ``%``,
#         backslash or control character) prints byte for byte as at 70fee6a4 through every public function and
#         every script path. The expected bytes are FROZEN constants (``CLEAN_BASELINE_70FEE6A4``), computed once at
#         authoring time from the saved 70fee6a4 module and tree: the old module is not in the tree, so a test that
#         loaded it could not run, and a frozen table cannot drift with the code under test.
#   INV-B no command across a boundary: a value ending in ``#`` or ``##`` followed by a literal or a value that
#         starts with ``[`` or ``#[``, at line start and mid line, through every finishing function (annotation,
#         render, join, log_line): zero finished lines parse as a workflow command.
# ---------------------------------------------------------------------------------------------------------------

R3_SEED = 9_365_003  # the seeded mixer below (a named constant; the corpus is reproducible from it)
R3_FUZZ_VALUES = 400
R3_FUZZ_MAX_FRAGMENTS = 12
R3_FUZZ_FRAGMENTS = ("#", "##", "[", "]", "::", ":", "\n", "\r", " ", "\x85", "a", " ", "error", "%0A", "\\")
R3_E2E_VALUE_COUNT = 60
R3_E2E_PATHS = ("shared_cargo_target --runner-name", "shared_cargo_target --home", "sccache_env --home")
R3_HOME_PREFIX = "rel-"  # a relative home is refused before any work, so a value there never touches a disk
R3_TAILS = ("#", "##", "##[", "")
R3_HEADS = ("#[{c}]x", "[{c}]x", "##[{c}]x", "{c}]x", "::{c}::x", ":{c}::x")
R3_BREAKS = ("\n", "\r", "\r\n", " ", "\x85")
R3_COMMANDS = ("error", "warning", "group", "endgroup", "add-mask", "set-output", "stop-commands")
R3_PROBE1_VALUE_COUNT = len(R3_TAILS) * len(R3_HEADS) * len(R3_BREAKS) * len(R3_COMMANDS) * 3  # 2520
R3_PROBE1_PAIR_COUNT = len(R3_TAILS) * 2 * len(R3_HEADS) * len(R3_COMMANDS)  # 336
R3_BOUNDARY_VALUE_TAILS = ("#", "##")
R3_BOUNDARY_LITERALS = ("[x]", "#[x]")
R3_BOUNDARY_PREFIXES = ("", "note: ")  # line start and mid line
R3_BOUNDARY_LITERAL_TAILS = ("#", "##")
R3_BOUNDARY_VALUES = ("[x]", "#[x]", "[x]#")
R3_CLEAN_EQUAL_CELLS = 168  # 14 clean values x (9 module functions + 3 script paths)
R3_HAZARD_CELLS = 24  # 2 hazard-piece values x 12
R3_CLEAN_TABLE_CELLS = 192  # the reviewer's table: 16 values x 12
R3_PROBE1_CELLS = 26880  # 2520 values x 10 emissions + 336 pairs x 5
R3_BOUNDARY_CELLS = 100  # 2 prefixes x (2 tails x 2 literals + 2 literal tails x 3 values) x 5 functions
R3_FUZZ_CELLS = 4000  # 400 values x 10 emissions
R3_E2E_RUNS = 180  # 60 values x 3 script paths

CLEAN_BASELINE_70FEE6A4 = {'C#': {'module': {'safe_text': 'C#',
                   'safe_value': 'C#',
                   'property_value': 'C#',
                   'log_line': 'C#',
                   'render': 'p: refused: C#',
                   'join': 'C#, C#',
                   'annotation': '::warning title=C#::C#',
                   'end_group_line': '::endgroup::',
                   'env_file_value': 'C#'},
        'scripts': {'shared_cargo_target --runner-name': (2,
                                                          '',
                                                          'shared_cargo_target: refusing: invalid runner name '
                                                          "'C#'\n"),
                    'shared_cargo_target --home': (2, '', "shared_cargo_target: refusing home 'rel-C#'\n"),
                    'sccache_env --home': (2, '', "sccache_env: refusing home 'rel-C#'\n")}},
 'C# and F#': {'module': {'safe_text': 'C# and F#',
                          'safe_value': 'C# and F#',
                          'property_value': 'C# and F#',
                          'log_line': 'C# and F#',
                          'render': 'p: refused: C# and F#',
                          'join': 'C# and F#, C# and F#',
                          'annotation': '::warning title=C# and F#::C# and F#',
                          'end_group_line': '::endgroup::',
                          'env_file_value': 'C# and F#'},
               'scripts': {'shared_cargo_target --runner-name': (2,
                                                                 '',
                                                                 'shared_cargo_target: refusing: invalid runner name '
                                                                 "'C# and F#'\n"),
                           'shared_cargo_target --home': (2,
                                                          '',
                                                          "shared_cargo_target: refusing home 'rel-C# and F#'\n"),
                           'sccache_env --home': (2, '', "sccache_env: refusing home 'rel-C# and F#'\n")}},
 'issue #': {'module': {'safe_text': 'issue #',
                        'safe_value': 'issue #',
                        'property_value': 'issue #',
                        'log_line': 'issue #',
                        'render': 'p: refused: issue #',
                        'join': 'issue #, issue #',
                        'annotation': '::warning title=issue #::issue #',
                        'end_group_line': '::endgroup::',
                        'env_file_value': 'issue #'},
             'scripts': {'shared_cargo_target --runner-name': (2,
                                                               '',
                                                               'shared_cargo_target: refusing: invalid runner name '
                                                               "'issue #'\n"),
                         'shared_cargo_target --home': (2, '', "shared_cargo_target: refusing home 'rel-issue #'\n"),
                         'sccache_env --home': (2, '', "sccache_env: refusing home 'rel-issue #'\n")}},
 'PR #123': {'module': {'safe_text': 'PR #123',
                        'safe_value': 'PR #123',
                        'property_value': 'PR #123',
                        'log_line': 'PR #123',
                        'render': 'p: refused: PR #123',
                        'join': 'PR #123, PR #123',
                        'annotation': '::warning title=PR #123::PR #123',
                        'end_group_line': '::endgroup::',
                        'env_file_value': 'PR #123'},
             'scripts': {'shared_cargo_target --runner-name': (2,
                                                               '',
                                                               'shared_cargo_target: refusing: invalid runner name '
                                                               "'PR #123'\n"),
                         'shared_cargo_target --home': (2, '', "shared_cargo_target: refusing home 'rel-PR #123'\n"),
                         'sccache_env --home': (2, '', "sccache_env: refusing home 'rel-PR #123'\n")}},
 '[Errno 13] x': {'module': {'safe_text': '[Errno 13] x',
                             'safe_value': '[Errno 13] x',
                             'property_value': '[Errno 13] x',
                             'log_line': '[Errno 13] x',
                             'render': 'p: refused: [Errno 13] x',
                             'join': '[Errno 13] x, [Errno 13] x',
                             'annotation': '::warning title=[Errno 13] x::[Errno 13] x',
                             'end_group_line': '::endgroup::',
                             'env_file_value': '[Errno 13] x'},
                  'scripts': {'shared_cargo_target --runner-name': (2,
                                                                    '',
                                                                    'shared_cargo_target: refusing: invalid runner '
                                                                    "name '[Errno 13] x'\n"),
                              'shared_cargo_target --home': (2,
                                                             '',
                                                             "shared_cargo_target: refusing home 'rel-[Errno 13] "
                                                             "x'\n"),
                              'sccache_env --home': (2, '', "sccache_env: refusing home 'rel-[Errno 13] x'\n")}},
 '[coverage-pg]': {'module': {'safe_text': '[coverage-pg]',
                              'safe_value': '[coverage-pg]',
                              'property_value': '[coverage-pg]',
                              'log_line': '[coverage-pg]',
                              'render': 'p: refused: [coverage-pg]',
                              'join': '[coverage-pg], [coverage-pg]',
                              'annotation': '::warning title=[coverage-pg]::[coverage-pg]',
                              'end_group_line': '::endgroup::',
                              'env_file_value': '[coverage-pg]'},
                   'scripts': {'shared_cargo_target --runner-name': (2,
                                                                     '',
                                                                     'shared_cargo_target: refusing: invalid runner '
                                                                     "name '[coverage-pg]'\n"),
                               'shared_cargo_target --home': (2,
                                                              '',
                                                              'shared_cargo_target: refusing home '
                                                              "'rel-[coverage-pg]'\n"),
                               'sccache_env --home': (2, '', "sccache_env: refusing home 'rel-[coverage-pg]'\n")}},
 'a#b': {'module': {'safe_text': 'a#b',
                    'safe_value': 'a#b',
                    'property_value': 'a#b',
                    'log_line': 'a#b',
                    'render': 'p: refused: a#b',
                    'join': 'a#b, a#b',
                    'annotation': '::warning title=a#b::a#b',
                    'end_group_line': '::endgroup::',
                    'env_file_value': 'a#b'},
         'scripts': {'shared_cargo_target --runner-name': (2,
                                                           '',
                                                           'shared_cargo_target: refusing: invalid runner name '
                                                           "'a#b'\n"),
                     'shared_cargo_target --home': (2, '', "shared_cargo_target: refusing home 'rel-a#b'\n"),
                     'sccache_env --home': (2, '', "sccache_env: refusing home 'rel-a#b'\n")}},
 'x[0]': {'module': {'safe_text': 'x[0]',
                     'safe_value': 'x[0]',
                     'property_value': 'x[0]',
                     'log_line': 'x[0]',
                     'render': 'p: refused: x[0]',
                     'join': 'x[0], x[0]',
                     'annotation': '::warning title=x[0]::x[0]',
                     'end_group_line': '::endgroup::',
                     'env_file_value': 'x[0]'},
          'scripts': {'shared_cargo_target --runner-name': (2,
                                                            '',
                                                            'shared_cargo_target: refusing: invalid runner name '
                                                            "'x[0]'\n"),
                      'shared_cargo_target --home': (2, '', "shared_cargo_target: refusing home 'rel-x[0]'\n"),
                      'sccache_env --home': (2, '', "sccache_env: refusing home 'rel-x[0]'\n")}},
 '/home/runner/work/ai-memory/x y': {'module': {'safe_text': '/home/runner/work/ai-memory/x y',
                                                'safe_value': '/home/runner/work/ai-memory/x y',
                                                'property_value': '/home/runner/work/ai-memory/x y',
                                                'log_line': '/home/runner/work/ai-memory/x y',
                                                'render': 'p: refused: /home/runner/work/ai-memory/x y',
                                                'join': '/home/runner/work/ai-memory/x y, '
                                                        '/home/runner/work/ai-memory/x y',
                                                'annotation': '::warning title=/home/runner/work/ai-memory/x '
                                                              'y::/home/runner/work/ai-memory/x y',
                                                'end_group_line': '::endgroup::',
                                                'env_file_value': '/home/runner/work/ai-memory/x y'},
                                     'scripts': {'shared_cargo_target --runner-name': (2,
                                                                                       '',
                                                                                       'shared_cargo_target: '
                                                                                       'refusing: invalid runner '
                                                                                       'name '
                                                                                       "'/home/runner/work/ai-memory/x "
                                                                                       "y'\n"),
                                                 'shared_cargo_target --home': (2,
                                                                                '',
                                                                                'shared_cargo_target: refusing home '
                                                                                "'rel-/home/runner/work/ai-memory/x "
                                                                                "y'\n"),
                                                 'sccache_env --home': (2,
                                                                        '',
                                                                        'sccache_env: refusing home '
                                                                        "'rel-/home/runner/work/ai-memory/x y'\n")}},
 'C:\\Users\\runner\\_work': {'module': {'safe_text': 'C:\\\\Users\\\\runner\\\\_work',
                                         'safe_value': 'C\\x3a\\\\Users\\\\runner\\\\_work',
                                         'property_value': 'C\\x3a\\\\Users\\\\runner\\\\_work',
                                         'log_line': 'C:\\Users\\runner\\_work',
                                         'render': 'p: refused: C\\x3a\\\\Users\\\\runner\\\\_work',
                                         'join': 'C\\x3a\\\\Users\\\\runner\\\\_work, '
                                                 'C\\x3a\\\\Users\\\\runner\\\\_work',
                                         'annotation': '::warning '
                                                       'title=C\\x3a\\\\Users\\\\runner\\\\_work::C:\\\\Users\\\\runner\\\\_work',
                                         'end_group_line': '::endgroup::',
                                         'env_file_value': 'C:\\Users\\runner\\_work'},
                              'scripts': {'shared_cargo_target --runner-name': (2,
                                                                                '',
                                                                                'shared_cargo_target: refusing: '
                                                                                'invalid runner name '
                                                                                "'C:\\\\Users\\\\runner\\\\_work'\n"),
                                          'shared_cargo_target --home': (2,
                                                                         '',
                                                                         'shared_cargo_target: refusing home '
                                                                         "'rel-C:\\\\Users\\\\runner\\\\_work'\n"),
                                          'sccache_env --home': (2,
                                                                 '',
                                                                 'sccache_env: refusing home '
                                                                 "'rel-C:\\\\Users\\\\runner\\\\_work'\n")}},
 'café 日本語 😀': {'module': {'safe_text': 'café 日本語 😀',
                           'safe_value': 'café 日本語 😀',
                           'property_value': 'café 日本語 😀',
                           'log_line': 'café 日本語 😀',
                           'render': 'p: refused: café 日本語 😀',
                           'join': 'café 日本語 😀, café 日本語 😀',
                           'annotation': '::warning title=café 日本語 😀::café 日本語 😀',
                           'end_group_line': '::endgroup::',
                           'env_file_value': 'café 日本語 😀'},
                'scripts': {'shared_cargo_target --runner-name': (2,
                                                                  '',
                                                                  'shared_cargo_target: refusing: invalid runner '
                                                                  "name 'café 日本語 😀'\n"),
                            'shared_cargo_target --home': (2,
                                                           '',
                                                           "shared_cargo_target: refusing home 'rel-café 日本語 😀'\n"),
                            'sccache_env --home': (2, '', "sccache_env: refusing home 'rel-café 日本語 😀'\n")}},
 'issue #9365 [ok]': {'module': {'safe_text': 'issue #9365 [ok]',
                                 'safe_value': 'issue #9365 [ok]',
                                 'property_value': 'issue #9365 [ok]',
                                 'log_line': 'issue #9365 [ok]',
                                 'render': 'p: refused: issue #9365 [ok]',
                                 'join': 'issue #9365 [ok], issue #9365 [ok]',
                                 'annotation': '::warning title=issue #9365 [ok]::issue #9365 [ok]',
                                 'end_group_line': '::endgroup::',
                                 'env_file_value': 'issue #9365 [ok]'},
                      'scripts': {'shared_cargo_target --runner-name': (2,
                                                                        '',
                                                                        'shared_cargo_target: refusing: invalid '
                                                                        "runner name 'issue #9365 [ok]'\n"),
                                  'shared_cargo_target --home': (2,
                                                                 '',
                                                                 "shared_cargo_target: refusing home 'rel-issue "
                                                                 "#9365 [ok]'\n"),
                                  'sccache_env --home': (2,
                                                         '',
                                                         "sccache_env: refusing home 'rel-issue #9365 [ok]'\n")}},
 'label: value': {'module': {'safe_text': 'label: value',
                             'safe_value': 'label\\x3a value',
                             'property_value': 'label\\x3a value',
                             'log_line': 'label: value',
                             'render': 'p: refused: label\\x3a value',
                             'join': 'label\\x3a value, label\\x3a value',
                             'annotation': '::warning title=label\\x3a value::label: value',
                             'end_group_line': '::endgroup::',
                             'env_file_value': 'label: value'},
                  'scripts': {'shared_cargo_target --runner-name': (2,
                                                                    '',
                                                                    'shared_cargo_target: refusing: invalid runner '
                                                                    "name 'label: value'\n"),
                              'shared_cargo_target --home': (2,
                                                             '',
                                                             "shared_cargo_target: refusing home 'rel-label: "
                                                             "value'\n"),
                              'sccache_env --home': (2, '', "sccache_env: refusing home 'rel-label: value'\n")}},
 '50% done': {'module': {'safe_text': '50\\x25 done',
                         'safe_value': '50\\x25 done',
                         'property_value': '50\\x25 done',
                         'log_line': '50% done',
                         'render': 'p: refused: 50\\x25 done',
                         'join': '50\\x25 done, 50\\x25 done',
                         'annotation': '::warning title=50\\x25 done::50\\x25 done',
                         'end_group_line': '::endgroup::',
                         'env_file_value': '50% done'},
              'scripts': {'shared_cargo_target --runner-name': (2,
                                                                '',
                                                                'shared_cargo_target: refusing: invalid runner name '
                                                                "'50% done'\n"),
                          'shared_cargo_target --home': (2,
                                                         '',
                                                         "shared_cargo_target: refusing home 'rel-50% done'\n"),
                          'sccache_env --home': (2, '', "sccache_env: refusing home 'rel-50% done'\n")}}}

HAZARD_PIECE_EXPECTED = {'a##b': {'module': {'safe_text': 'a\\x23#b',
                     'safe_value': 'a\\x23#b',
                     'property_value': 'a\\x23#b',
                     'log_line': 'a##b',
                     'render': 'p: refused: a\\x23#b',
                     'join': 'a\\x23#b, a\\x23#b',
                     'annotation': '::warning title=a\\x23#b::a\\x23#b',
                     'end_group_line': '::endgroup::',
                     'env_file_value': 'a##b'},
          'scripts': {'shared_cargo_target --runner-name': (2,
                                                            '',
                                                            'shared_cargo_target: refusing: invalid runner name '
                                                            "'a##b'\n"),
                      'shared_cargo_target --home': (2, '', "shared_cargo_target: refusing home 'rel-a##b'\n"),
                      'sccache_env --home': (2, '', "sccache_env: refusing home 'rel-a##b'\n")}},
 'x#[0]': {'module': {'safe_text': 'x\\x23\\x5b0]',
                      'safe_value': 'x\\x23\\x5b0]',
                      'property_value': 'x\\x23\\x5b0]',
                      'log_line': 'x#[0]',
                      'render': 'p: refused: x\\x23\\x5b0]',
                      'join': 'x\\x23\\x5b0], x\\x23\\x5b0]',
                      'annotation': '::warning title=x\\x23\\x5b0]::x\\x23\\x5b0]',
                      'end_group_line': '::endgroup::',
                      'env_file_value': 'x#[0]'},
           'scripts': {'shared_cargo_target --runner-name': (2,
                                                             '',
                                                             'shared_cargo_target: refusing: invalid runner name '
                                                             "'x#[0]'\n"),
                       'shared_cargo_target --home': (2, '', "shared_cargo_target: refusing home 'rel-x#[0]'\n"),
                       'sccache_env --home': (2, '', "sccache_env: refusing home 'rel-x#[0]'\n")}}}


def finished_line_command_count(line):
    """The ONE predicate of every r3 cell: how many workflow commands the runner reads in a finished line.

    Strict reading of actions/runner ActionCommand.cs: v1 = every ``##[`` anywhere (no trim); v2 = every piece
    (Python ``splitlines``, wider than the runner's \\r \\n set) whose left-stripped text starts with ``::``.
    """
    return line.count(V1_PREFIX) + sum(1 for piece in line.splitlines() if piece.lstrip().startswith("::"))


def probe1_values():
    """The reviewer's probe-1 corpus as values: tail x head x break x command, in three placements."""
    for tail in R3_TAILS:
        for head in R3_HEADS:
            for brk in R3_BREAKS:
                for command in R3_COMMANDS:
                    text = head.format(c=command)
                    yield "t%r-h%s-b%r-c%s-start" % (tail, head[:3], brk, command), tail + text
                    yield "t%r-h%s-b%r-c%s-mid" % (tail, head[:3], brk, command), "a" + brk + tail + text
                    yield "t%r-h%s-b%r-c%s-split" % (tail, head[:3], brk, command), tail + brk + text


def probe1_pairs():
    for tail in R3_TAILS:
        for prefix in ("", "a"):
            for head in R3_HEADS:
                for command in R3_COMMANDS:
                    yield "pair-t%r-p%r-h%s-c%s" % (tail, prefix, head[:3], command), prefix + tail, head.format(c=command)


def fuzz_values():
    import random
    rng = random.Random(R3_SEED)
    for index in range(R3_FUZZ_VALUES):
        yield "fuzz-%d" % index, "".join(rng.choice(R3_FUZZ_FRAGMENTS) for _ in range(rng.randint(1, R3_FUZZ_MAX_FRAGMENTS)))


def boundary_cells():
    """Value-then-literal and literal-then-value at line start and mid line: (cell id, finishing function, thunk)."""
    wa = load_module(CI_DIR / SHARED_MODULE_NAME, "workflow_annotation_9365_r3_boundary")
    for prefix in R3_BOUNDARY_PREFIXES:
        for tail in R3_BOUNDARY_VALUE_TAILS:
            for lit in R3_BOUNDARY_LITERALS:
                base = "b-v%r-l%s-p%r" % (tail, lit, prefix)
                value = "x" + tail
                yield base + "-render", "render", lambda prefix=prefix, lit=lit, value=value: wa.render(prefix + "{v}" + lit, v=value)
                yield base + "-join", "join", lambda prefix=prefix, lit=lit, value=value: wa.join(lit, [prefix + value, "y"])
                yield base + "-annotation", "annotation", lambda lit=lit, value=value: wa.annotation("warning", wa.render("{v}" + lit, v=value))
                yield base + "-annotation-title", "annotation", lambda lit=lit, value=value: wa.annotation("warning", "m", title=value + lit)
                yield base + "-log", "log_line", lambda prefix=prefix, lit=lit, value=value: wa.log_line(prefix + value + lit)
        for tail in R3_BOUNDARY_LITERAL_TAILS:
            for value in R3_BOUNDARY_VALUES:
                base = "b-l%r-v%s-p%r" % (tail, value, prefix)
                yield base + "-render", "render", lambda prefix=prefix, tail=tail, value=value: wa.render(prefix + "x" + tail + "{v}", v=value)
                yield base + "-join", "join", lambda prefix=prefix, tail=tail, value=value: wa.join("x" + tail, [prefix + "a", value])
                yield base + "-annotation", "annotation", lambda tail=tail, value=value: wa.annotation("warning", wa.render("x" + tail + "{v}", v=value))
                yield base + "-annotation-title", "annotation", lambda tail=tail, value=value: wa.annotation("warning", "m", title="x" + tail + value)
                yield base + "-log", "log_line", lambda prefix=prefix, tail=tail, value=value: wa.log_line(prefix + "x" + tail + value)


class CleanBytesAndBoundary(unittest.TestCase):
    """INV-A and INV-B over the reviewer's corpora; every failure message carries a cell id, never a value dump."""

    @classmethod
    def setUpClass(cls):
        cls.wa = load_module(CI_DIR / SHARED_MODULE_NAME, "workflow_annotation_9365_r3")

    def module_cells(self, value):
        wa = self.wa
        return {"safe_text": wa.safe_text(value), "safe_value": wa.safe_value(value),
                "property_value": wa.property_value(value), "log_line": wa.log_line(value),
                "render": wa.render("{prog}: refused: {v}", prog="p", v=value), "join": wa.join(", ", [value, value]),
                "annotation": wa.annotation("warning", value, title=value), "end_group_line": wa.end_group_line(),
                "env_file_value": wa.env_file_value(value)}

    def script_cells(self, value):
        scratch = scratch_dir("r3-clean")
        argv = {"shared_cargo_target --runner-name": ("shared_cargo_target.py", ["--home", str(scratch / "no-home"), "--runner-name", value], True),
                "shared_cargo_target --home": ("shared_cargo_target.py", ["--home", R3_HOME_PREFIX + value], True),
                "sccache_env --home": ("sccache_env.py", ["--home", R3_HOME_PREFIX + value], False)}
        return {name: run_script(CI_DIR / script, args, isolated=iso) for name, (script, args, iso) in argv.items()}

    def test_clean_values_are_byte_equal_to_70fee6a4_9365(self):
        """The 16-value x (9 functions + 3 script paths) table: 14 clean values equal the frozen baseline."""
        cells = 0
        for value, baseline in CLEAN_BASELINE_70FEE6A4.items():
            got_module, got_scripts = self.module_cells(value), self.script_cells(value)
            for name, expected in baseline["module"].items():
                cells += 1
                self.assertEqual(got_module[name], expected, "clean cell %s/%s" % (name, ascii(value)))
            for name, expected in baseline["scripts"].items():
                cells += 1
                self.assertEqual(tuple(got_scripts[name]), tuple(expected), "clean cell %s/%s" % (name, ascii(value)))
        self.assertEqual(cells, R3_CLEAN_EQUAL_CELLS)

    def test_hazard_piece_values_change_exactly_as_designed_9365(self):
        """``a##b`` and ``x#[0]`` hold a ``##``/``#[`` piece, so they are escaped: 24 cells with their exact bytes."""
        cells = 0
        for value, expected in HAZARD_PIECE_EXPECTED.items():
            got_module, got_scripts = self.module_cells(value), self.script_cells(value)
            for name, want in expected["module"].items():
                cells += 1
                self.assertEqual(got_module[name], want, "hazard cell %s/%s" % (name, ascii(value)))
            for name, want in expected["scripts"].items():
                cells += 1
                self.assertEqual(tuple(got_scripts[name]), tuple(want), "hazard cell %s/%s" % (name, ascii(value)))
        self.assertEqual(cells, R3_HAZARD_CELLS)
        self.assertEqual(R3_CLEAN_EQUAL_CELLS + R3_HAZARD_CELLS, R3_CLEAN_TABLE_CELLS)

    def test_trailing_hash_is_not_escaped_9365(self):
        for value in ("C#", "C# and F#", "issue #", "abc##", "#"):
            with self.subTest(value=value):
                self.assertFalse(self.wa.safe_text(value).endswith("\\x23"), ascii(value))
        self.assertEqual(self.wa.safe_text("C#"), "C#")
        self.assertEqual(self.wa.annotation("warning", "C#", title="C#"), "::warning title=C#::C#")
        self.assertEqual(self.wa.safe_text("abc##"), "abc\\x23#")

    def emissions(self, value):
        wa = self.wa
        return [("safe_text", wa.safe_text(value), 0), ("safe_value", wa.safe_value(value), 0),
                ("property_value", wa.property_value(value), 0), ("log_line", wa.log_line(value), 0),
                ("render1", wa.render("{prog}: refused: {v}", prog="p", v=value), 0), ("render2", wa.render("{v}", v=value), 0),
                ("join1", wa.join(", ", [value, value]), 0), ("join2", wa.join("", [value, "x", value]), 0),
                ("annotation-msg", wa.annotation("warning", value), 1),
                ("annotation-title", wa.annotation("error", "m", title=value), 1)]

    def check_emissions(self, cell, emissions):
        bad = []
        for name, line, expected in emissions:
            if finished_line_command_count(line) != expected or len(line.splitlines()) > 1:
                bad.append("%s/%s" % (cell, name))
        return bad

    def test_probe1_corpus_through_every_finishing_function_parses_no_command_9365(self):
        """Values: 2520 x 10 emissions; pairs: 336 x 5 emissions. Zero finished lines parse as a command."""
        wa, bad, values, pairs, cells = self.wa, [], 0, 0, 0
        for cell, value in probe1_values():
            values += 1
            emissions = self.emissions(value)
            cells += len(emissions)
            bad += self.check_emissions(cell, emissions)
        for cell, left, right in probe1_pairs():
            pairs += 1
            emissions = [("join", wa.join("", [left, right]), 0), ("render", wa.render("{a}{b}", a=left, b=right), 0),
                         ("safe+safe", wa.safe_text(left) + wa.safe_text(right), 0),
                         ("annotation", wa.annotation("notice", left + right), 1), ("log_line", wa.log_line(left + right), 0)]
            cells += len(emissions)
            bad += self.check_emissions(cell, emissions)
        self.assertEqual((values, pairs, cells), (R3_PROBE1_VALUE_COUNT, R3_PROBE1_PAIR_COUNT, R3_PROBE1_CELLS))
        self.assertEqual(bad, [], bad[:10])

    def test_boundary_table_parses_no_command_9365(self):
        bad, cells = [], 0
        for cell, function, thunk in boundary_cells():
            cells += 1
            line = thunk()
            expected = 1 if function == "annotation" else 0
            if finished_line_command_count(line) != expected or len(line.splitlines()) > 1:
                bad.append(cell)
        self.assertEqual(cells, R3_BOUNDARY_CELLS)
        self.assertEqual(bad, [], bad[:10])

    def test_seeded_fuzz_through_every_finishing_function_parses_no_command_9365(self):
        bad, count, cells = [], 0, 0
        for cell, value in fuzz_values():
            count += 1
            emissions = self.emissions(value)
            cells += len(emissions)
            bad += self.check_emissions(cell, emissions)
        self.assertEqual((count, cells), (R3_FUZZ_VALUES, R3_FUZZ_CELLS))
        self.assertEqual(bad, [], bad[:10])

    def test_the_predicate_reads_what_the_runner_reads_9365(self):
        for line, count in (("plain", 0), ("a ##[error]x", 1), ("##[a]##[b]", 2), ("  ::error::x", 1), (" ::x", 1),
                            ("a\n::error::x", 1), ("a ::error::x", 1), ("a::b", 0), ("x#[e]", 0), ("##\\x5be]", 0)):
            with self.subTest(line=line):
                self.assertEqual(finished_line_command_count(line), count)

    def test_end_to_end_scripts_print_no_command_for_the_seeded_corpus_9365(self):
        """3 script paths x 60 seeded probe-1 values: no stdout/stderr line holds ``##[`` or starts ``::``."""
        import random
        pool = [value for _, value in probe1_values()]
        sample = random.Random(R3_SEED).sample(pool, R3_E2E_VALUE_COUNT)
        runs, bad = 0, []
        for index, value in enumerate(sample):
            for name, (rc, out, err) in self.script_cells(value).items():
                runs += 1
                if finished_line_command_count(out) or finished_line_command_count(err):
                    bad.append("e2e-%d/%s" % (index, name))
        self.assertEqual(runs, R3_E2E_RUNS)
        self.assertEqual(bad, [], bad[:10])

    def test_huge_hash_runs_stay_linear_9365(self):
        wa = self.wa
        value = "#" * HUGE_VALUE_CHARS
        started = time.monotonic()
        lines = [wa.safe_text(value), wa.log_line(value + "[x]"), wa.annotation("warning", value + "[x]"),
                 wa.join("", [value, "[x]"]), wa.render("{v}[x]", v=value)]
        self.assertLess(time.monotonic() - started, HUGE_WALL_CLOCK_SECS)
        for index, line in enumerate(lines):
            self.assertEqual(finished_line_command_count(line), 1 if index == 2 else 0, "huge-%d" % index)


# ---------------------------------------------------------------------------------------------------------------
# PR 9400 CodeQL alerts (ruling 96789bdf, fixed by code, never dismissed). Four shapes: py/loop-variable-capture,
# py/empty-except, py/unused-import, py/print-during-import. The ast check below finds the four shapes in the files
# of this PR that CodeQL reads; the table cells prove every boundary cell runs with the values of its own iteration.
# ---------------------------------------------------------------------------------------------------------------
R3_BOUNDARY_DISTINCT_FLOOR = 51  # distinct finished lines of the 100 boundary cells, measured with each cell called in place
CODEQL_SCOPE_FILES = ("scripts/ci/tests/test_ci_annotation_escape_9365.py", "scripts/ci/partition_test_binaries.py",
                      "scripts/ci/shared_cargo_target.py")
CODEQL_SHAPES = ("unused-import", "empty-except", "loop-variable-capture", "print-during-import",
                 "unexpected-raise-in-special-method")
# py/unexpected-raise-in-special-method (alerts 892, 893): the exception a special method may raise, by method.
SPECIAL_METHOD_RAISES = {"__getattr__": "AttributeError", "__getattribute__": "AttributeError",
                         "__eq__": "TypeError", "__ne__": "TypeError", "__hash__": "TypeError",
                         "__bool__": "TypeError", "__lt__": "TypeError", "__le__": "TypeError",
                         "__gt__": "TypeError", "__ge__": "TypeError"}
CODEQL_SYNTHETIC = {  # shape -> a source that must be found
    "unused-import": "import threading\n",
    "empty-except": "try:\n    pass\nexcept ValueError:\n    pass\n",
    "loop-variable-capture": "def make():\n    for n in range(3):\n        yield lambda: n\n",
    "print-during-import": "import sys\nprint('x', file=sys.stderr)\n",
    "unexpected-raise-in-special-method": "class C:\n    def __getattr__(self, name):\n        raise RuntimeError(name)\n",
}
CODEQL_CLEAN_SYNTHETIC = ("import os\n\n\ndef f():\n    for n in range(3):\n        yield lambda n=n: os.sep + str(n)\n"
                        "\n\ndef g():\n    try:\n        return 1\n    except ValueError:\n        return 2\n")


def _stored_names(node):
    return {n.id for n in ast.walk(node) if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Store)}


def codeql_shape_findings(source):
    """(line, shape) for each of the four CodeQL alert shapes in ``source`` (a deterministic stand-in for the suite)."""
    tree = ast.parse(source)
    found = []
    imported = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                imported[(alias.asname or alias.name).split(".")[0]] = node.lineno
        elif isinstance(node, ast.ImportFrom):
            for alias in node.names:
                imported[alias.asname or alias.name] = node.lineno
    used = {n.id for n in ast.walk(tree) if isinstance(n, ast.Name)}
    found += [(line, "unused-import") for name, line in imported.items() if name not in used and name != "annotations"]
    found += [(node.lineno, "empty-except") for node in ast.walk(tree)
              if isinstance(node, ast.ExceptHandler) and all(isinstance(stmt, ast.Pass) for stmt in node.body)]

    def visit(node, loop_names):
        for child in ast.iter_child_nodes(node):
            names = loop_names
            if isinstance(child, (ast.For, ast.AsyncFor)):
                names = names | _stored_names(child.target) | {n for stmt in child.body for n in _stored_names(stmt)}
            if isinstance(child, (ast.ListComp, ast.SetComp, ast.GeneratorExp, ast.DictComp)):
                names = names | {n for gen in child.generators for n in _stored_names(gen.target)}
            if isinstance(child, (ast.Lambda, ast.FunctionDef)) and loop_names:
                args = child.args
                bound = {a.arg for a in args.posonlyargs + args.args + args.kwonlyargs}
                body = child.body if isinstance(child.body, list) else [child.body]
                reads = {n.id for stmt in body for n in ast.walk(stmt) if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Load)}
                if (reads & loop_names) - bound:
                    found.append((child.lineno, "loop-variable-capture"))
                visit(child, set())
                continue
            visit(child, names)

    visit(tree, set())
    for cls in (n for n in ast.walk(tree) if isinstance(n, ast.ClassDef)):
        for method in (m for m in cls.body if isinstance(m, ast.FunctionDef) and m.name in SPECIAL_METHOD_RAISES):
            for stmt in (n for n in ast.walk(method) if isinstance(n, ast.Raise) and n.exc is not None):
                exc = stmt.exc.func if isinstance(stmt.exc, ast.Call) else stmt.exc
                if not (isinstance(exc, ast.Name) and exc.id == SPECIAL_METHOD_RAISES[method.name]):
                    found.append((stmt.lineno, "unexpected-raise-in-special-method"))
    for stmt in tree.body:
        if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            continue
        if isinstance(stmt, ast.If) and "__main__" in ast.dump(stmt.test):
            continue
        for node in ast.walk(stmt):
            if isinstance(node, (ast.FunctionDef, ast.Lambda, ast.ClassDef)):
                break
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "print":
                found.append((node.lineno, "print-during-import"))
    return sorted(found)


class CodeqlAlertShapes(unittest.TestCase):
    """The class lock for the 16 alerts of PR 9400: none of the four shapes in a file this PR touches."""

    def test_the_check_finds_each_shape_and_passes_clean_code_9365(self):
        for shape, source in CODEQL_SYNTHETIC.items():
            with self.subTest(shape=shape):
                self.assertIn(shape, [kind for _, kind in codeql_shape_findings(source)])
        self.assertEqual(codeql_shape_findings(CODEQL_CLEAN_SYNTHETIC), [])

    def test_the_files_of_the_pr_hold_none_of_the_four_alert_shapes_9365(self):
        for rel in CODEQL_SCOPE_FILES:
            with self.subTest(file=rel):
                self.assertEqual(codeql_shape_findings((REPO / rel).read_text(encoding="utf-8")), [])


class BoundaryTableBinding(unittest.TestCase):
    """Every cell of the boundary table runs with the values of its own iteration, whatever the consumer does."""

    def test_collecting_the_table_first_gives_the_lines_of_calling_each_cell_in_place_9365(self):
        in_place = [(cell, function, thunk()) for cell, function, thunk in boundary_cells()]
        collected = list(boundary_cells())
        after_collect = [(cell, function, thunk()) for cell, function, thunk in collected]
        self.assertEqual(len(collected), R3_BOUNDARY_CELLS)
        self.assertEqual(after_collect, in_place)

    def test_the_boundary_table_has_at_least_the_floor_of_distinct_outputs_9365(self):
        collected = list(boundary_cells())
        outputs = [thunk() for _, _, thunk in collected]
        self.assertGreaterEqual(len(set(outputs)), R3_BOUNDARY_DISTINCT_FLOOR, "distinct boundary outputs")


# The two scripts other scripts and tests import (partition_test_binaries, shared_cargo_target): importing one prints
# nothing and never exits; running one with a shared module that cannot be loaded refuses with the SAME bytes and
# exit code as at ae6967af, before any work; a caller that skips require_workflow_annotation() meets a named error.
DEFERRED_SCRIPTS = {"scripts/ci/partition_test_binaries.py": (2, ["--out-dir", "OUT"]),
                    "scripts/ci/shared_cargo_target.py": (3, ["--home", "rel-home", "--runner-name", "a"])}
DEFERRED_BREAKS = {"absent": None, "unreadable": "", "syntax error": "def broken(:\n",
                   "sys.exit(0) in it": "import sys\nsys.exit(0)\n", "raises at load": "raise ValueError('x')\n",
                   "required attribute missing": "def other():\n    pass\n"}
DEFERRED_ERROR_NAME = "SharedModuleNotLoadedError"
DEFERRED_REQUIRE_NAME = "require_workflow_annotation"
DEFERRED_LOAD_AT_AE6967AF = {('partition_test_binaries', 'absent', 'help'): (2,
                                                 '::error title=partition_test_binaries '
                                                 'refused::partition_test_binaries: refused: shared module '
                                                 'workflow_annotation.py next to the script cannot be loaded\n',
                                                 'partition_test_binaries: refused: shared module '
                                                 'workflow_annotation.py next to the script cannot be loaded '
                                                 '(FileNotFoundError)\n'),
 ('partition_test_binaries', 'absent', 'work'): (2,
                                                 '::error title=partition_test_binaries '
                                                 'refused::partition_test_binaries: refused: shared module '
                                                 'workflow_annotation.py next to the script cannot be loaded\n',
                                                 'partition_test_binaries: refused: shared module '
                                                 'workflow_annotation.py next to the script cannot be loaded '
                                                 '(FileNotFoundError)\n'),
 ('partition_test_binaries', 'raises at load', 'help'): (2,
                                                         '::error title=partition_test_binaries '
                                                         'refused::partition_test_binaries: refused: shared module '
                                                         'workflow_annotation.py next to the script cannot be '
                                                         'loaded\n',
                                                         'partition_test_binaries: refused: shared module '
                                                         'workflow_annotation.py next to the script cannot be loaded '
                                                         '(ValueError)\n'),
 ('partition_test_binaries', 'raises at load', 'work'): (2,
                                                         '::error title=partition_test_binaries '
                                                         'refused::partition_test_binaries: refused: shared module '
                                                         'workflow_annotation.py next to the script cannot be '
                                                         'loaded\n',
                                                         'partition_test_binaries: refused: shared module '
                                                         'workflow_annotation.py next to the script cannot be loaded '
                                                         '(ValueError)\n'),
 ('partition_test_binaries', 'required attribute missing', 'help'): (2,
                                                                     '::error title=partition_test_binaries '
                                                                     'refused::partition_test_binaries: refused: '
                                                                     'shared module workflow_annotation.py next to '
                                                                     'the script cannot be loaded\n',
                                                                     'partition_test_binaries: refused: shared '
                                                                     'module workflow_annotation.py next to the '
                                                                     'script cannot be loaded (AttributeError)\n'),
 ('partition_test_binaries', 'required attribute missing', 'work'): (2,
                                                                     '::error title=partition_test_binaries '
                                                                     'refused::partition_test_binaries: refused: '
                                                                     'shared module workflow_annotation.py next to '
                                                                     'the script cannot be loaded\n',
                                                                     'partition_test_binaries: refused: shared '
                                                                     'module workflow_annotation.py next to the '
                                                                     'script cannot be loaded (AttributeError)\n'),
 ('partition_test_binaries', 'syntax error', 'help'): (2,
                                                       '::error title=partition_test_binaries '
                                                       'refused::partition_test_binaries: refused: shared module '
                                                       'workflow_annotation.py next to the script cannot be loaded\n',
                                                       'partition_test_binaries: refused: shared module '
                                                       'workflow_annotation.py next to the script cannot be loaded '
                                                       '(SyntaxError)\n'),
 ('partition_test_binaries', 'syntax error', 'work'): (2,
                                                       '::error title=partition_test_binaries '
                                                       'refused::partition_test_binaries: refused: shared module '
                                                       'workflow_annotation.py next to the script cannot be loaded\n',
                                                       'partition_test_binaries: refused: shared module '
                                                       'workflow_annotation.py next to the script cannot be loaded '
                                                       '(SyntaxError)\n'),
 ('partition_test_binaries', 'sys.exit(0) in it', 'help'): (2,
                                                            '::error title=partition_test_binaries '
                                                            'refused::partition_test_binaries: refused: shared '
                                                            'module workflow_annotation.py next to the script cannot '
                                                            'be loaded\n',
                                                            'partition_test_binaries: refused: shared module '
                                                            'workflow_annotation.py next to the script cannot be '
                                                            'loaded (SystemExit)\n'),
 ('partition_test_binaries', 'sys.exit(0) in it', 'work'): (2,
                                                            '::error title=partition_test_binaries '
                                                            'refused::partition_test_binaries: refused: shared '
                                                            'module workflow_annotation.py next to the script cannot '
                                                            'be loaded\n',
                                                            'partition_test_binaries: refused: shared module '
                                                            'workflow_annotation.py next to the script cannot be '
                                                            'loaded (SystemExit)\n'),
 ('partition_test_binaries', 'unreadable', 'help'): (2,
                                                     '::error title=partition_test_binaries '
                                                     'refused::partition_test_binaries: refused: shared module '
                                                     'workflow_annotation.py next to the script cannot be loaded\n',
                                                     'partition_test_binaries: refused: shared module '
                                                     'workflow_annotation.py next to the script cannot be loaded '
                                                     '(PermissionError)\n'),
 ('partition_test_binaries', 'unreadable', 'work'): (2,
                                                     '::error title=partition_test_binaries '
                                                     'refused::partition_test_binaries: refused: shared module '
                                                     'workflow_annotation.py next to the script cannot be loaded\n',
                                                     'partition_test_binaries: refused: shared module '
                                                     'workflow_annotation.py next to the script cannot be loaded '
                                                     '(PermissionError)\n'),
 ('shared_cargo_target', 'absent', 'help'): (3,
                                             '::error title=shared_cargo_target refused::shared_cargo_target: '
                                             'refused: shared module workflow_annotation.py next to the script '
                                             'cannot be loaded\n',
                                             'shared_cargo_target: refused: shared module workflow_annotation.py '
                                             'next to the script cannot be loaded (FileNotFoundError)\n'),
 ('shared_cargo_target', 'absent', 'work'): (3,
                                             '::error title=shared_cargo_target refused::shared_cargo_target: '
                                             'refused: shared module workflow_annotation.py next to the script '
                                             'cannot be loaded\n',
                                             'shared_cargo_target: refused: shared module workflow_annotation.py '
                                             'next to the script cannot be loaded (FileNotFoundError)\n'),
 ('shared_cargo_target', 'raises at load', 'help'): (3,
                                                     '::error title=shared_cargo_target '
                                                     'refused::shared_cargo_target: refused: shared module '
                                                     'workflow_annotation.py next to the script cannot be loaded\n',
                                                     'shared_cargo_target: refused: shared module '
                                                     'workflow_annotation.py next to the script cannot be loaded '
                                                     '(ValueError)\n'),
 ('shared_cargo_target', 'raises at load', 'work'): (3,
                                                     '::error title=shared_cargo_target '
                                                     'refused::shared_cargo_target: refused: shared module '
                                                     'workflow_annotation.py next to the script cannot be loaded\n',
                                                     'shared_cargo_target: refused: shared module '
                                                     'workflow_annotation.py next to the script cannot be loaded '
                                                     '(ValueError)\n'),
 ('shared_cargo_target', 'required attribute missing', 'help'): (3,
                                                                 '::error title=shared_cargo_target '
                                                                 'refused::shared_cargo_target: refused: shared '
                                                                 'module workflow_annotation.py next to the script '
                                                                 'cannot be loaded\n',
                                                                 'shared_cargo_target: refused: shared module '
                                                                 'workflow_annotation.py next to the script cannot '
                                                                 'be loaded (AttributeError)\n'),
 ('shared_cargo_target', 'required attribute missing', 'work'): (3,
                                                                 '::error title=shared_cargo_target '
                                                                 'refused::shared_cargo_target: refused: shared '
                                                                 'module workflow_annotation.py next to the script '
                                                                 'cannot be loaded\n',
                                                                 'shared_cargo_target: refused: shared module '
                                                                 'workflow_annotation.py next to the script cannot '
                                                                 'be loaded (AttributeError)\n'),
 ('shared_cargo_target', 'syntax error', 'help'): (3,
                                                   '::error title=shared_cargo_target refused::shared_cargo_target: '
                                                   'refused: shared module workflow_annotation.py next to the script '
                                                   'cannot be loaded\n',
                                                   'shared_cargo_target: refused: shared module '
                                                   'workflow_annotation.py next to the script cannot be loaded '
                                                   '(SyntaxError)\n'),
 ('shared_cargo_target', 'syntax error', 'work'): (3,
                                                   '::error title=shared_cargo_target refused::shared_cargo_target: '
                                                   'refused: shared module workflow_annotation.py next to the script '
                                                   'cannot be loaded\n',
                                                   'shared_cargo_target: refused: shared module '
                                                   'workflow_annotation.py next to the script cannot be loaded '
                                                   '(SyntaxError)\n'),
 ('shared_cargo_target', 'sys.exit(0) in it', 'help'): (3,
                                                        '::error title=shared_cargo_target '
                                                        'refused::shared_cargo_target: refused: shared module '
                                                        'workflow_annotation.py next to the script cannot be '
                                                        'loaded\n',
                                                        'shared_cargo_target: refused: shared module '
                                                        'workflow_annotation.py next to the script cannot be loaded '
                                                        '(SystemExit)\n'),
 ('shared_cargo_target', 'sys.exit(0) in it', 'work'): (3,
                                                        '::error title=shared_cargo_target '
                                                        'refused::shared_cargo_target: refused: shared module '
                                                        'workflow_annotation.py next to the script cannot be '
                                                        'loaded\n',
                                                        'shared_cargo_target: refused: shared module '
                                                        'workflow_annotation.py next to the script cannot be loaded '
                                                        '(SystemExit)\n'),
 ('shared_cargo_target', 'unreadable', 'help'): (3,
                                                 '::error title=shared_cargo_target refused::shared_cargo_target: '
                                                 'refused: shared module workflow_annotation.py next to the script '
                                                 'cannot be loaded\n',
                                                 'shared_cargo_target: refused: shared module workflow_annotation.py '
                                                 'next to the script cannot be loaded (PermissionError)\n'),
 ('shared_cargo_target', 'unreadable', 'work'): (3,
                                                 '::error title=shared_cargo_target refused::shared_cargo_target: '
                                                 'refused: shared module workflow_annotation.py next to the script '
                                                 'cannot be loaded\n',
                                                 'shared_cargo_target: refused: shared module workflow_annotation.py '
                                                 'next to the script cannot be loaded (PermissionError)\n')}  # (script, break, arguments) -> (rc, stdout, stderr)


FORGOT_PROBE = textwrap.dedent("""\
    import sys
    sys.path.insert(0, sys.argv[1])
    import {mod} as m
    try:
        m.wa.log_line("x")
    except Exception as exc:
        print("before:", type(exc).__name__)
    m.{require}()
    print("after:", m.wa.log_line("x"))
    """)
MAIN_PROBE = textwrap.dedent("""\
    import sys
    sys.path.insert(0, sys.argv[1])
    import {mod} as m
    print("imported-ok")
    try:
        m.main(sys.argv[2:])
    except SystemExit as exc:
        print("exit:", exc.code)
    """)


class DeferredLoadOfImportedScripts(unittest.TestCase):
    def fixture(self, rel, source):
        base = scratch_dir("deferred-load")
        self.addCleanup(shutil.rmtree, str(base), True)
        repo = base / "repo"
        for item in (rel, SHARED_MODULE_PATH):
            (repo / item).parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(REPO / item, repo / item)
        shared = repo / SHARED_MODULE_PATH
        if source is None:
            shared.unlink()
        elif source == "":
            shared.chmod(0)
            self.addCleanup(shared.chmod, 0o600)
        else:
            shared.write_text(source, encoding="utf-8")
        cwd = base / "cwd"
        cwd.mkdir()
        return repo, cwd

    def run_py(self, args, cwd, flags=("-I",)):
        env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "LANG": "C.UTF-8", "PYTHONDONTWRITEBYTECODE": "1",
               "TMPDIR": str(cwd)}
        proc = subprocess.run([sys.executable, *flags, *args], capture_output=True, env=env, cwd=str(cwd),
                              stdin=subprocess.DEVNULL, timeout=SUBPROCESS_TIMEOUT_SECS, check=False)
        return proc.returncode, proc.stdout.decode("utf-8", "replace"), proc.stderr.decode("utf-8", "replace")

    def test_importing_prints_nothing_and_never_exits_for_every_break_9365(self):
        if os.geteuid() == 0:
            self.skipTest("root reads a mode-0 file")
        for rel in DEFERRED_SCRIPTS:
            stem = Path(rel).stem
            for label, source in {"present": (REPO / SHARED_MODULE_PATH).read_text(encoding="utf-8"), **DEFERRED_BREAKS}.items():
                with self.subTest(script=stem, shared=label):
                    repo, cwd = self.fixture(rel, source)
                    code = "import sys\nsys.path.insert(0, %r)\nimport %s\nprint('imported-ok')\n" % (str(repo / "scripts" / "ci"), stem)
                    self.assertEqual(self.run_py(["-c", code], cwd), (0, "imported-ok\n", ""))

    def test_running_with_a_broken_shared_module_refuses_with_the_bytes_of_ae6967af_9365(self):
        if os.geteuid() == 0:
            self.skipTest("root reads a mode-0 file")
        for (stem, label, kind), expected in DEFERRED_LOAD_AT_AE6967AF.items():
            rel = "scripts/ci/%s.py" % stem
            with self.subTest(script=stem, shared=label, args=kind):
                repo, cwd = self.fixture(rel, DEFERRED_BREAKS[label])
                args = ["--help"] if kind == "help" else [a.replace("OUT", str(cwd / "o")) for a in DEFERRED_SCRIPTS[rel][1]]
                got = self.run_py([str(repo / rel), *args], cwd, flags=())
                self.assertEqual(got, expected)
                self.assertEqual(got[0], DEFERRED_SCRIPTS[rel][0])

    def test_main_called_in_process_loads_before_any_work_and_refuses_9365(self):
        for rel, (code, args) in DEFERRED_SCRIPTS.items():
            stem = Path(rel).stem
            with self.subTest(script=stem):
                repo, cwd = self.fixture(rel, None)
                probe = MAIN_PROBE.format(mod=stem)
                rc, out, err = self.run_py(["-c", probe, str(repo / "scripts" / "ci"), *[a.replace("OUT", str(cwd / "o")) for a in args]], cwd)
                self.assertEqual(rc, 0, err)
                self.assertEqual(out.splitlines()[0], "imported-ok")
                self.assertEqual(out.splitlines()[-1], "exit: %d" % code)
                self.assertFalse((cwd / "o").exists(), "work ran before the refusal")
                self.assertIn("cannot be loaded (FileNotFoundError)", err)

    def test_a_caller_that_skips_the_load_meets_a_named_error_not_an_unloaded_helper_9365(self):
        for rel in DEFERRED_SCRIPTS:
            stem = Path(rel).stem
            with self.subTest(script=stem):
                repo, cwd = self.fixture(rel, (REPO / SHARED_MODULE_PATH).read_text(encoding="utf-8"))
                probe = FORGOT_PROBE.format(mod=stem, require=DEFERRED_REQUIRE_NAME)
                rc, out, err = self.run_py(["-c", probe, str(repo / "scripts" / "ci")], cwd)
                self.assertEqual(rc, 0, err)
                self.assertEqual(out.splitlines()[0], "before: " + DEFERRED_ERROR_NAME)
                self.assertTrue(out.splitlines()[1].startswith("after: "), out)


# The not-loaded sentinel (alerts 892 and 893 of PR 9400, py/unexpected-raise-in-special-method). The sentinel has one
# explicit member per name the script uses from the shared module, each raising the named error with the wanted name;
# no class of the two scripts defines __getattr__ or __getattribute__ (an AttributeError subclass would be swallowed
# by hasattr and by getattr with a default, a silent fallback after a forgotten load).
SENTINEL_CLASS_NAME = "_NotLoaded"
SENTINEL_VARIABLE = "wa"
SENTINEL_SCRIPTS = {"scripts/ci/partition_test_binaries.py": frozenset({"annotation", "log_line"}),
                    "scripts/ci/shared_cargo_target.py": frozenset({"env_file_value", "log_line"})}
SENTINEL_MEMBER_KIND = "method"  # every use of ``wa.<name>`` in both scripts is a call, so every member is a method
SENTINEL_MESSAGE = ("workflow_annotation.py is not loaded; call require_workflow_annotation() first (wanted %s)")
SENTINEL_ABSENT_NAME = "no_such_name_9365"
SENTINEL_FORBIDDEN_METHODS = frozenset({"__getattr__", "__getattribute__"})
SENTINEL_CALLS = ((), ("error", "text"), ("value",))


def sentinel_uses(tree):
    """{name: kind} of every ``wa.<name>``: kind is ``method`` when it is the callee of a call, else ``value``."""
    callees = {id(node.func) for node in ast.walk(tree) if isinstance(node, ast.Call)}
    uses = {}
    for node in ast.walk(tree):
        if (isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name) and node.value.id == SENTINEL_VARIABLE):
            kind = "method" if id(node) in callees else "value"
            uses[node.attr] = kind if uses.get(node.attr, kind) == kind else "value"
    return uses


def sentinel_members(tree):
    """{name: kind} of the public members of the sentinel class: ``method``, ``property`` or ``value``."""
    classes = [n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == SENTINEL_CLASS_NAME]
    members = {}
    for node in classes[0].body if classes else []:
        if isinstance(node, ast.FunctionDef) and not node.name.startswith("_"):
            props = any(isinstance(d, ast.Name) and d.id == "property" for d in node.decorator_list)
            members[node.name] = "property" if props else "method"
        elif isinstance(node, ast.Assign):
            members.update({t.id: "value" for t in node.targets if isinstance(t, ast.Name) and not t.id.startswith("_")})
    return members


def classes_defining(tree, names):
    """(line, class, method) for every method of every class in ``tree`` whose name is in ``names``."""
    return [(m.lineno, cls.name, m.name) for cls in ast.walk(tree) if isinstance(cls, ast.ClassDef)
            for m in cls.body if isinstance(m, (ast.FunctionDef, ast.AsyncFunctionDef)) and m.name in names]


class NotLoadedSentinel(unittest.TestCase):
    """Using the shared module before require_workflow_annotation() fails loudly for every name, never a fallback."""

    def tree(self, rel):
        return ast.parse((REPO / rel).read_text(encoding="utf-8"))

    def fresh_module(self, rel):
        spec = importlib.util.spec_from_file_location("sentinel_cell_" + Path(rel).stem, str(REPO / rel))
        module = importlib.util.module_from_spec(spec)
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer), contextlib.redirect_stderr(buffer):
            spec.loader.exec_module(module)
        self.assertEqual(buffer.getvalue(), "")
        return module

    def test_every_member_raises_the_named_error_with_the_wanted_name_before_the_load_9365(self):
        for rel, names in SENTINEL_SCRIPTS.items():
            module = self.fresh_module(rel)
            for name in sorted(names):
                for args in SENTINEL_CALLS:
                    with self.subTest(script=Path(rel).stem, member=name, args=args):
                        with self.assertRaises(module.SharedModuleNotLoadedError) as caught:
                            getattr(module.wa, name)(*args)
                        self.assertIs(type(caught.exception), module.SharedModuleNotLoadedError)
                        self.assertEqual(str(caught.exception), SENTINEL_MESSAGE % name)

    def test_the_sentinel_member_set_equals_the_ast_set_of_wa_uses_of_each_script_9365(self):
        for rel, names in SENTINEL_SCRIPTS.items():
            with self.subTest(script=Path(rel).stem):
                tree = self.tree(rel)
                uses = sentinel_uses(tree)
                self.assertEqual(set(uses), set(names), "the table and the ast uses differ")
                self.assertEqual(sentinel_members(tree), uses, "a use without a member of its kind")
                self.assertEqual({SENTINEL_MEMBER_KIND}, set(uses.values()))
                module = self.fresh_module(rel)
                self.assertEqual(set(module.WA_REQUIRED), set(names))

    def test_no_class_of_the_two_scripts_defines_getattr_or_getattribute_9365(self):
        for rel in SENTINEL_SCRIPTS:
            with self.subTest(script=Path(rel).stem):
                self.assertEqual(classes_defining(self.tree(rel), SENTINEL_FORBIDDEN_METHODS), [])
        planted = "class C:\n    def __getattr__(self, n):\n        raise AttributeError(n)\n"
        self.assertEqual(classes_defining(ast.parse(planted), SENTINEL_FORBIDDEN_METHODS), [(2, "C", "__getattr__")])

    def test_hasattr_and_getattr_with_a_default_cannot_hide_a_forgotten_load_9365(self):
        shared = self.fresh_module("scripts/ci/workflow_annotation.py")
        public = sorted(n for n, v in vars(shared).items() if not n.startswith("_") and type(v).__name__ == "function"
                        and getattr(v, "__module__", None) == shared.__name__)
        for rel, names in SENTINEL_SCRIPTS.items():
            module = self.fresh_module(rel)
            for name in [SENTINEL_ABSENT_NAME, *[n for n in public if n not in names]]:
                with self.subTest(script=Path(rel).stem, unused=name):
                    self.assertFalse(hasattr(module.wa, name))
                    self.assertIsNone(getattr(module.wa, name, None))
            for name in sorted(names):
                with self.subTest(script=Path(rel).stem, used=name):
                    member = getattr(module.wa, name, None)
                    self.assertIsNotNone(member)
                    with self.assertRaises(module.SharedModuleNotLoadedError):
                        member()


if __name__ == "__main__":
    unittest.main()
