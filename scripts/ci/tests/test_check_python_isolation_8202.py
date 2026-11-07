#!/usr/bin/env python3
"""Isolation policy regressions for #8202; fixtures never execute shell text."""
import importlib.util
import re
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[3]
CHECKER = ROOT / "scripts/ci/check_python_isolation.py"


def load_checker():
    """Load by file location so isolated unittest discovery works."""
    if not CHECKER.is_file():
        raise AssertionError("workflow Python isolation checker is missing")
    spec = importlib.util.spec_from_file_location("check_python_isolation", CHECKER)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class ScriptArguments6389(unittest.TestCase):
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
                self.assertEqual(checker.scan_shell(command.replace("python3", "python3 -I", 1)), [])

    def test_nested_shell_execution_6330(self):
        checker = load_checker()
        for command in (
            'value="$(python3 -c \'print(1)\')"',
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
        calls = [line.strip().removesuffix("\\").rstrip() for line in workflow.splitlines()
                 if re.search(r"python3 .*scripts/(?:test|ci)/pg_isolat(?:ed_binary|e_split)\.py", line)]
        self.assertEqual(len(calls), 5)
        for call in calls:
            with self.subTest(call=call):
                self.assertEqual(checker.scan_shell(call), [])
                mutant = call.replace("python3 -I", "python3", 1)
                self.assertNotEqual(mutant, call)
                self.assertEqual(len(checker.scan_shell(mutant)), 1)


class RepositoryPolicy6814(unittest.TestCase):
    def test_every_workflow_and_called_wrapper_is_isolated_6814(self):
        checker = load_checker()
        self.assertEqual(checker.scan_repository(ROOT), [])

    def test_classify_runs_the_checker_without_a_skip_6814(self):
        workflow = (ROOT / ".github/workflows/ci.yml").read_text()
        job = workflow.split("\n  classify:", 1)[1].split("\n  lint:", 1)[0]
        step = ("      - name: Workflow Python isolation (#8202)\n"
                "        run: python3 -I scripts/ci/check_python_isolation.py\n")
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


if __name__ == "__main__":
    unittest.main()
