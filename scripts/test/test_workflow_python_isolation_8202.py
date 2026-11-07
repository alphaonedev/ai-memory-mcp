#!/usr/bin/env python3
"""Isolation policy regressions for #8202; fixtures never execute shell text."""
import importlib.util
import os
import re
import subprocess
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
CHECKER = ROOT / "scripts/ci/check_workflow_python_isolation.py"


def load_checker():
    """Load by file location so isolated unittest discovery works."""
    if not CHECKER.is_file():
        raise AssertionError("workflow Python isolation checker is missing")
    spec = importlib.util.spec_from_file_location("check_workflow_python_isolation", CHECKER)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class ScriptArguments6389(unittest.TestCase):
    def test_quoted_script_path_without_isolation_6389(self):
        self.assertEqual(len(load_checker().scan_shell('python3 "scripts/x.py"')), 1)

    def test_interleaved_flag_without_isolation_6389(self):
        self.assertEqual(len(load_checker().scan_shell("python3 -u scripts/x.py")), 1)

    def test_quoted_paths_and_interleaved_flags_6389(self):
        checker = load_checker()
        for args in (
            "scripts/x.py", "-u scripts/x.py", '-B "scripts/x.py"',
            '"scripts/x.py"', "-O -u 'scripts/x.py'", "-W ignore scripts/x.py",
            "-X dev scripts/x.py",
        ):
            with self.subTest(args=args):
                self.assertEqual(len(checker.scan_shell("python3 " + args)), 1)
                self.assertEqual(checker.scan_shell("python3 -I " + args), [])

    def test_isolation_must_precede_program_6389(self):
        checker = load_checker()
        for text in (
            "python3 scripts/x.py -I",
            'python3 -W "-I" scripts/x.py',
            "python3 -X -I scripts/x.py",
        ):
            with self.subTest(text=text):
                self.assertEqual(len(checker.scan_shell(text)), 1)
        self.assertEqual(checker.scan_shell("python3 -u -I scripts/x.py"), [])


class ModuleMode6799(unittest.TestCase):
    def test_module_execution_requires_interpreter_isolation_6799(self):
        checker = load_checker()
        for program in ("unittest discover -s scripts/ci/tests", "pip --version", "pytest"):
            with self.subTest(program=program):
                self.assertEqual(len(checker.scan_shell("python3 -m " + program)), 1)
                self.assertEqual(checker.scan_shell("python3 -I -m " + program), [])
                self.assertEqual(len(checker.scan_shell("python3 -m " + program + " -I")), 1)

    def test_ci_discovery_is_isolated_and_mutant_is_rejected_6799(self):
        checker = load_checker()
        lines = (ROOT / ".github/workflows/ci.yml").read_text().splitlines()
        discovery = [line.strip().removeprefix("run: ") for line in lines
                     if line.lstrip().startswith("run:")
                     and "unittest discover -s scripts/ci/tests" in line]
        self.assertEqual(len(discovery), 1)
        self.assertEqual(checker.scan_shell(discovery[0]), [])
        mutant = discovery[0].replace(" -I", "", 1)
        self.assertNotEqual(mutant, discovery[0])
        self.assertEqual(len(checker.scan_shell(mutant)), 1)


class CommandAndWrapper6330(unittest.TestCase):
    def test_called_wrappers_are_isolated_6330(self):
        checker = load_checker()
        wrappers = checker.wrapper_files(ROOT)
        self.assertGreater(len(wrappers), 0)
        for path in wrappers:
            with self.subTest(path=path.relative_to(ROOT)):
                self.assertEqual(checker.scan_shell(path.read_text()), [])

    def test_transitive_wrapper_and_workflow_modes_6330(self):
        checker = load_checker()
        scratch = ROOT / ".local-runs"
        scratch.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(dir=scratch) as directory:
            root = Path(directory)
            workflow = root / ".github/workflows/check.yml"
            workflow.parent.mkdir(parents=True)
            scripts = root / "scripts/ci"
            scripts.mkdir(parents=True)
            workflow.write_text("jobs:\n  check:\n    steps:\n"
                                "      - run: bash scripts/ci/first.sh\n")
            (scripts / "first.sh").write_text("bash scripts/ci/second.sh\n")
            (scripts / "second.sh").write_text("python3 -c 'print(1)'\n")
            findings = checker.scan_repository(root)
            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0][0].name, "second.sh")
            (scripts / "second.sh").write_text("python3 -I -c 'print(1)'\n")
            self.assertEqual(checker.scan_repository(root), [])

    def test_heredoc_in_substitution_and_script_path_arguments_6330(self):
        checker = load_checker()
        self.assertEqual(len(checker.scan_shell(
            "v=$(python3 - <<'PY'\nprint(1)\nPY\n)\n")), 1)
        self.assertEqual(checker.scan_shell("mkdir -p sdk/python sdk/typescript"), [])

    def test_command_and_stdin_modes_6330(self):
        checker = load_checker()
        for command in ("python3 -c 'print(1)'", "python3 - <<'PY'\nprint(1)\nPY\n",
                        "python3 <<PY\nprint(1)\nPY\n", "python3 --version"):
            with self.subTest(command=command):
                self.assertEqual(len(checker.scan_shell(command)), 1)
                isolated = command.replace("python3", "python3 -I", 1)
                self.assertEqual(checker.scan_shell(isolated), [])

    def test_nested_shell_execution_6330(self):
        checker = load_checker()
        for command in (
            'value="$(python3 -c \'print(1)\')"',
            'value="`python3 scripts/x.py`"',
            'echo "result=$(python3 scripts/x.py)"',
            "trap 'python3 scripts/x.py' EXIT",
            "bash -c 'python3 scripts/x.py'",
            "env FLAG=1 python3 scripts/x.py",
            "exec python3 scripts/x.py",
            'assert "result" "python3 scripts/x.py"',
        ):
            with self.subTest(command=command):
                self.assertEqual(len(checker.scan_shell(command)), 1)

    def test_comments_data_and_python_source_are_not_commands_6330(self):
        checker = load_checker()
        for command in (
            "# python3 scripts/x.py\n",
            "echo 'python3 scripts/x.py'",
            "command -v python3",
            "python3 -I - <<'PY'\ntext = \"python3 scripts/x.py\"\nPY\n",
        ):
            with self.subTest(command=command):
                self.assertEqual(checker.scan_shell(command), [])


class PostgresInvocations6997(unittest.TestCase):
    def test_all_five_postgres_wrapper_calls_are_isolated_6997(self):
        checker = load_checker()
        workflow = (ROOT / ".github/workflows/ci.yml").read_text()
        program = re.compile(r"python3 .*scripts/(?:test|ci)/pg_isolat(?:ed_binary|e_split)\.py")
        calls = [line.strip().removesuffix("\\").rstrip() for line in workflow.splitlines()
                 if program.search(line)]
        self.assertEqual(len(calls), 5)
        for call in calls:
            with self.subTest(call=call):
                self.assertEqual(checker.scan_shell(call), [])
                mutant = call.replace("python3 -I", "python3", 1)
                self.assertNotEqual(mutant, call)
                self.assertEqual(len(checker.scan_shell(mutant)), 1)


class RepositoryPolicy6814(unittest.TestCase):
    def test_runner_helpers_start_without_cwd_imports_6814(self):
        scratch = ROOT / ".local-runs"
        scratch.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(dir=scratch) as directory:
            poison = Path(directory) / "shared_cargo_target.py"
            poison.write_text("raise RuntimeError('cwd helper must not load')\n")
            env = dict(os.environ, PYTHONPATH=directory)
            for name in ("sccache_env.py", "prune_runner_artifacts.py", "pg_isolate_split.py"):
                with self.subTest(name=name):
                    result = subprocess.run(
                        [sys.executable, "-I", str(ROOT / "scripts/ci" / name), "--help"],
                        cwd=directory, env=env, capture_output=True, text=True, check=False)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertIn("usage:", result.stdout)

    def test_cli_prints_every_honoured_exception_6814(self):
        scratch = ROOT / ".local-runs"
        scratch.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(dir=scratch) as directory:
            source = Path(directory) / "commands.txt"
            source.write_text("python3 -c pass # isolation: exempt #6814\n")
            result = subprocess.run([sys.executable, "-I", str(CHECKER), str(source)],
                                    capture_output=True, text=True, check=False)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("EXEMPT ", result.stdout)
            self.assertIn("findings=0 exemptions=1", result.stdout)
            source.write_text("python3 -c pass\n")
            result = subprocess.run([sys.executable, "-I", str(CHECKER), str(source)],
                                    capture_output=True, text=True, check=False)
            self.assertEqual(result.returncode, 1)
            self.assertIn("findings=1 exemptions=0", result.stdout)

    def test_python_shell_template_requires_isolation_6814(self):
        checker = load_checker()
        scratch = ROOT / ".local-runs"
        scratch.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(dir=scratch) as directory:
            root = Path(directory)
            path = root / ".github/workflows/python.yml"
            path.parent.mkdir(parents=True)
            template = "jobs:\n  test:\n    steps:\n      - run: print(1)\n        shell: %s\n"
            path.write_text(template % "python3 {0}")
            self.assertEqual(len(checker.scan_repository(root)), 1)
            path.write_text(template % '"python3 -I {0}"')
            self.assertEqual(checker.scan_repository(root), [])

    def test_only_real_same_line_issue_comments_exempt_6814(self):
        checker = load_checker()
        unsafe, exempt = checker.scan_source("python3 scripts/x.py # isolation: exempt #6814\n")
        self.assertEqual(unsafe, [])
        self.assertEqual(exempt, [(1, "6814")])
        for command in (
            'python3 -c "# isolation: exempt #6814"',
            "python3 scripts/x.py # isolation: exempt later",
            "# isolation: exempt #6814\npython3 scripts/x.py",
        ):
            with self.subTest(command=command):
                unsafe, exempt = checker.scan_source(command)
                self.assertEqual(len(unsafe), 1)
                self.assertEqual(exempt, [])

    def test_every_workflow_and_called_wrapper_is_isolated_6814(self):
        checker = load_checker()
        self.assertEqual(checker.scan_repository(ROOT), [])

    def test_classify_runs_the_checker_without_a_skip_6814(self):
        workflow = (ROOT / ".github/workflows/ci.yml").read_text()
        job = workflow.split("\n  classify:", 1)[1].split("\n  lint:", 1)[0]
        step = ("      - name: Workflow Python isolation (#8202)\n"
                "        run: |\n"
                "          python3 -I -m unittest discover -s scripts/test "
                "-p test_workflow_python_isolation_8202.py\n"
                "          python3 -I scripts/ci/check_workflow_python_isolation.py\n")
        self.assertEqual(job.count(step), 1)

    def test_interpreter_flag_grammar_6814(self):
        checker = load_checker()
        for executable in ("python", "python3", "python3.12", "/usr/bin/python3"):
            for flags in ("", "-u ", "-B -W ignore ", "-X dev "):
                for program in ("scripts/x.py", '"scripts/x.py"', "-m unittest", "-c 'pass'", "-"):
                    with self.subTest(executable=executable, flags=flags, program=program):
                        command = executable + " " + flags + program
                        self.assertEqual(len(checker.scan_shell(command)), 1)
                        isolated = executable + " -I " + flags + program
                        self.assertEqual(checker.scan_shell(isolated), [])


class RoundFourIsolation8202(unittest.TestCase):
    """Review regressions execute fixtures, never workflow shell commands."""

    def test_python_named_dynamic_commands_are_findings(self):
        checker = load_checker()
        for interpreter in ("$PYTHON", "$pythonLocation/bin/python3",
                            "${PYTHON_HOME}/bin/python3", "$BIN/python3",
                            "${{ steps.x.outputs.PYTHON-path }}", "py -3.12"):
            for flags in ("", "-I "):
                with self.subTest(interpreter=interpreter, flags=flags):
                    self.assertEqual(len(checker.scan_shell(
                        interpreter + " " + flags + "scripts/x.py")), 1)

    def test_non_python_dynamic_commands_stay_outside_the_name_scan(self):
        checker = load_checker()
        for command in ("$BIN run scripts/x.py", "$PSQL -c query",
                        "$TIMEOUT_BIN 60 command", "${BIN} run python",
                        "${{ steps.x.outputs.binary }} python"):
            with self.subTest(command=command):
                self.assertEqual(checker.scan_shell(command), [])

    def test_first_step_key_python_shell(self):
        checker = load_checker()
        scratch = ROOT / ".local-runs"
        scratch.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(dir=scratch) as directory:
            root = Path(directory)
            path = root / ".github/workflows/python.yml"
            path.parent.mkdir(parents=True)
            template = "jobs:\n  test:\n    steps:\n      - shell: %s\n        run: pass\n"
            for shell in ("python", "python3 {0}"):
                with self.subTest(shell=shell):
                    path.write_text(template % shell)
                    self.assertEqual(len(checker.scan_repository(root)), 1)
                    isolated = shell.replace("python", "python -I", 1)
                    if shell.startswith("python3"):
                        isolated = shell.replace("python3", "python3 -I", 1)
                    path.write_text(template % isolated)
                    self.assertEqual(checker.scan_repository(root), [])

    def test_console_entrypoints_require_isolated_module_form(self):
        checker = load_checker()
        for command, isolated in (
            ("pip install example", "python3 -I -m pip install example"),
            ("pip3 install example", "python3 -I -m pip install example"),
            ("pytest tests/", "python3 -I -m pytest tests/"),
            ("pipx run example", "python3 -I -m pipx run example"),
            ("uv run example.py", "python3 -I -m uv run example.py"),
        ):
            with self.subTest(command=command):
                self.assertEqual(len(checker.scan_shell(command)), 1)
                self.assertEqual(checker.scan_shell(isolated), [])

    def test_dynamic_interpreters_require_an_issue_exemption(self):
        checker = load_checker()
        for interpreter in ("$PYTHON", "${PYTHON:-python3}",
                            "${{ steps.x.outputs.python-path }}", "py -3"):
            with self.subTest(interpreter=interpreter):
                command = interpreter + " -I scripts/x.py"
                self.assertEqual(len(checker.scan_shell(command)), 1)
                unsafe, exempt = checker.scan_source(
                    command + " # isolation: exempt #8202\n")
                self.assertEqual(unsafe, [])
                self.assertEqual(exempt, [(1, "8202")])

    def test_bundled_and_continued_isolation(self):
        checker = load_checker()
        for command in ("python3 -Ic pass", "python3 -IB scripts/x.py",
                        "python3 \\\n  -I scripts/x.py"):
            with self.subTest(command=command):
                self.assertEqual(checker.scan_shell(command), [])
        self.assertEqual(len(checker.scan_shell("python3 -cI pass")), 1)

    def test_malformed_exemption_is_not_honoured(self):
        checker = load_checker()
        for suffix in ("exempt", "exempt 8202", "exempt #abc"):
            with self.subTest(suffix=suffix):
                unsafe, exempt = checker.scan_source(
                    "python3 scripts/x.py # isolation: " + suffix + "\n")
                self.assertEqual(len(unsafe), 1)
                self.assertEqual(unsafe[0].line, 1)
                self.assertEqual(exempt, [])

    def test_unreadable_and_non_utf8_inputs_are_reported_without_traceback(self):
        scratch = ROOT / ".local-runs"
        scratch.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(dir=scratch) as directory:
            root = Path(directory)
            workflow = root / ".github/workflows/check.yml"
            workflow.parent.mkdir(parents=True)
            wrapper = root / "scripts/ci/fixture.sh"
            wrapper.parent.mkdir(parents=True)
            source = root / "commands.txt"
            for kind, target in (("workflow", workflow), ("wrapper", wrapper),
                                 ("positional", source)):
                for fault in ("encoding", "permissions"):
                    with self.subTest(kind=kind, fault=fault):
                        workflow.write_text("jobs:\n  test:\n    steps:\n"
                                            "      - run: bash scripts/ci/fixture.sh\n")
                        wrapper.write_text("python3 -I -c pass\n")
                        source.write_text("python3 -I -c pass\n")
                        if fault == "encoding":
                            target.write_bytes(b"\xff\n")
                        else:
                            target.chmod(0)
                        try:
                            args = [str(source)] if kind == "positional" else ["--root", str(root)]
                            result = subprocess.run(
                                [sys.executable, "-I", str(CHECKER), *args],
                                capture_output=True, text=True, check=False)
                            output = result.stdout + result.stderr
                            self.assertEqual(result.returncode, 2, output)
                            self.assertIn(str(target), output)
                            self.assertNotIn("Traceback", output)
                            self.assertEqual(len(output.splitlines()), 1, output)
                        finally:
                            target.chmod(0o600)

    def test_failed_sibling_import_drops_the_partial_module(self):
        # Exercise the real consumers, intercepting only the intentional sibling.
        from unittest import mock

        scratch = ROOT / ".local-runs"
        scratch.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(dir=scratch) as directory:
            failing = Path(directory) / "failing.py"
            failing.write_text("raise RuntimeError('fixture sibling import stopped')\n")
            original_spec = importlib.util.spec_from_file_location

            def fixture_spec(name, location, *args, **kwargs):
                selected = failing if name == "shared_cargo_target" else location
                return original_spec(name, selected, *args, **kwargs)

            for consumer in ("sccache_env.py", "prune_runner_artifacts.py"):
                with self.subTest(consumer=consumer):
                    prior = sys.modules.pop("shared_cargo_target", None)
                    try:
                        spec = original_spec("review_consumer", ROOT / "scripts/ci" / consumer)
                        module = importlib.util.module_from_spec(spec)
                        with mock.patch.object(importlib.util, "spec_from_file_location", fixture_spec):
                            with self.assertRaisesRegex(RuntimeError, "fixture sibling import stopped"):
                                spec.loader.exec_module(module)
                        self.assertFalse("shared_cargo_target" in sys.modules,
                                         "partial sibling survived its import failure")
                    finally:
                        sys.modules.pop("shared_cargo_target", None)
                        if prior is not None:
                            sys.modules["shared_cargo_target"] = prior


if __name__ == "__main__":
    unittest.main()
