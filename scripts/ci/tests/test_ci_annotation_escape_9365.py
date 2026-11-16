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
import importlib.util
import io
import os
import re
import shutil
import subprocess
import sys
import tempfile
import textwrap
import threading
import time
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
CI_DIR = REPO / "scripts" / "ci"
SCRATCH_ROOT = REPO / ".local-runs" / "ci-annotation-escape-9365"
SCAN_ROOTS = (REPO / "scripts", REPO / ".github")
SHARED_MODULE_NAME = "workflow_annotation.py"
SHARED_FIELD_FUNCTIONS = frozenset({"safe_text", "property_value", "annotation", "log_line", "env_file_value"})
COMMAND_RE = re.compile(r"(?m)^::[a-z][a-z-]*")
HEREDOC_RE = re.compile(r"python3?[^\n<]*<<-?\s*'?(\w+)'?[^\n]*\n(.*?)\n\s*\1\s*$", re.S | re.M)

LINE_BOUND_CHARS = 1000
HUGE_VALUE_CHARS = 100_001
HUGE_WALL_CLOCK_SECS = 20.0
SUBPROCESS_TIMEOUT_SECS = 60

HOSTILE = {
    "command": "::error::x",
    "set_output": "%0A::set-output name=pwn::1",
    "percent_cr": "a%0Db",
    "raw_newline": "a\n::error::injected",
    "raw_cr": "a\r::error::injected",
    "colons": "a::b",
    "percent": "100%25",
    "long_name": "n" * 4096,
    "non_utf8": os.fsdecode(b"bad\xff\xfe::x"),
    "separators": "a ::error::b\x85::error::c",
}
FILE_NAME_CORPUS = ("command", "raw_newline", "raw_cr", "colons", "percent", "non_utf8")


def oracle_escape(text):
    """The escape rule of #8634 (finding L4), restated: what a variable value must look like in a message."""
    out = []
    for char in str(text):
        code = ord(char)
        if char == "\\":
            out.append("\\\\")
        elif char == "%":
            out.append("\\x25")
        elif code < 0x20 or 0x7F <= code <= 0x9F:
            out.append("\\x%02x" % code)
        elif 0xD800 <= code <= 0xDFFF or code in (0x2028, 0x2029):
            out.append("\\u%04x" % code)
        else:
            out.append(char)
    return "".join(out).replace("::", "\\x3a:")


def scratch_dir(label):
    SCRATCH_ROOT.mkdir(parents=True, exist_ok=True)
    return Path(tempfile.mkdtemp(prefix=label + "-", dir=str(SCRATCH_ROOT)))


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
                def unreadable():
                    raise OSError(value)

                buf = io.StringIO()
                with contextlib.redirect_stdout(buf):
                    module.run(value, 1.0, 0, 1, 1, unreadable, lambda secs: None)
                self.assert_commands(buf.getvalue(), ["warning"])
                readings = iter([100.0, 100.0])

                def high():
                    return next(readings)

                buf = io.StringIO()
                with contextlib.redirect_stdout(buf):
                    module.run(value, 1.0, 0, 1, 1, high, lambda secs: None)
                self.assert_commands(buf.getvalue(), ["notice", "warning", "notice"])
                calls = []

                def flaky():
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
                self.assert_commands(out + err, ["error"], oracle_escape(str(missing))[:200])

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

    def test_prune_runner_artifacts_warning_9365(self):
        for key in FILE_NAME_CORPUS:
            value = HOSTILE[key]
            with self.subTest(key):
                home = self.tmp / ("home-" + key)
                base = home / ("targets-" + value)
                base.mkdir(parents=True)
                work = home / "work"
                work.mkdir(exist_ok=True)
                rc, out, err = run_script(CI_DIR / "prune_runner_artifacts.py", [
                    "--work-root", str(work), "--workspace", str(work / "ws"), "--protected-root", str(base),
                    "--evict-root", str(base), "--runner-name", "me", "--home", str(home),
                    "--free-floor-gib", "100000000"], isolated=False)
                self.assertEqual(rc, 0, (out + err)[-800:])
                self.assert_commands(out + err, ["warning"], oracle_escape(str(base))[:200])

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


if __name__ == "__main__":
    unittest.main()
