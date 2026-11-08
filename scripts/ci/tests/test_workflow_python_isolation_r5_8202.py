#!/usr/bin/env python3
"""Round-five isolation grammar regressions; shell fixtures are never executed."""
import importlib.util
from pathlib import Path
import sys
import subprocess
import tempfile
import types
import unittest

ROOT = Path(__file__).resolve().parents[3]
CHECKER = ROOT / "scripts/ci/check_workflow_python_isolation.py"


def load_checker():
    spec = importlib.util.spec_from_file_location("isolation_round_five", CHECKER)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class PrefixDynamicN1(unittest.TestCase):
    def test_dynamic_interpreters_after_prefix_arguments(self):
        checker = load_checker()
        for prefix in ("timeout 60", "sudo -u u", "nice -n 10", "xargs", "env -u X",
                       "env FOO=1", "sudo --user=u nice --adjustment=10 timeout -s TERM 60",
                       "xargs -I {}", "env --unset=X", "/usr/bin/timeout 60"):
            for interpreter in ("$PYTHON", "${PYTHON:-python3}", "py -3",
                                "${{ steps.x.outputs.python-path }}"):
                with self.subTest(prefix=prefix, interpreter=interpreter):
                    findings = checker.scan_shell(f"{prefix} {interpreter} x.py")
                    self.assertEqual(len(findings), 1, "prefixed dynamic interpreter escaped")
                    self.assertIn("dynamic interpreter", findings[0].reason)
                    unsafe, exempt = checker.scan_source(
                        f"{prefix} {interpreter} x.py # isolation: exempt #8202")
                    self.assertEqual(unsafe, [])
                    self.assertEqual(exempt, [(1, "8202")])

    def test_prefix_arguments_and_non_python_variables_are_not_interpreters(self):
        checker = load_checker()
        for command in ("sudo -u python3 echo ready", "env -u PYTHON python3 -I x.py",
                        "timeout 60 $BIN x.py", "nice -n 10 $PSQL -c query",
                        "timeout 60 python3 -I x.py", "$TIMEOUT_BIN 60 python3 -I x.py"):
            with self.subTest(command=command):
                self.assertEqual(checker.scan_shell(command), [])


class PrefixLaunchersN2(unittest.TestCase):
    def test_console_launchers_after_wrappers(self):
        checker = load_checker()
        for command in ("xargs pip install x", "nohup pytest", "poetry run pytest",
                        "pyenv exec pip install x", "uv tool run pytest", "uvx pytest",
                        "pip3.12 install x", "pip3.x install x",
                        "sudo -u u nohup poetry run pytest", "nice -n 10 pip3.12 install x"):
            with self.subTest(command=command):
                findings = checker.scan_shell(command)
                self.assertEqual(len(findings), 1, "console launcher escaped")
                self.assertIn("console launcher", findings[0].reason)
                unsafe, exempt = checker.scan_source(command + " # isolation: exempt #8202")
                self.assertEqual(unsafe, [])
                self.assertEqual(exempt, [(1, "8202")])

    def test_wrapper_controls_keep_isolated_module_calls(self):
        checker = load_checker()
        for prefix in ("xargs", "nohup", "poetry run", "pyenv exec", "sudo -u u nohup"):
            with self.subTest(prefix=prefix):
                self.assertEqual(checker.scan_shell(f"{prefix} python3 -I -m pytest"), [])
        for data in ("echo pip3.12 install x", "poetry show pytest", "pyenv versions"):
            with self.subTest(data=data):
                self.assertEqual(checker.scan_shell(data), [])


class WorkflowShellN3(unittest.TestCase):
    def test_path_case_and_expression_shell_declarations(self):
        checker = load_checker()
        scratch = ROOT / ".local-runs"
        scratch.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(dir=scratch) as directory:
            root = Path(directory)
            workflow = root / ".github/workflows/python.yml"
            workflow.parent.mkdir(parents=True)
            template = "jobs:\n  test:\n    steps:\n      - shell: %s\n        run: pass\n"
            for shell in ("/usr/bin/python3 {0}", "Python3 {0}",
                          "${{ matrix.python }} {0}", '"/usr/bin/python3 {0}"'):
                with self.subTest(shell=shell):
                    workflow.write_text(template % shell)
                    found = checker.scan_repository(root)
                    self.assertEqual(len(found), 1, "Python shell declaration escaped")
                    self.assertEqual(found[0][1].line, 4)
            for shell in ("/usr/bin/python3 -I {0}", "Python3 -I {0}", "bash -e {0}"):
                with self.subTest(clean=shell):
                    workflow.write_text(template % shell)
                    self.assertEqual(checker.scan_repository(root), [])
            workflow.write_text(template % (
                "${{ matrix.python }} {0} # isolation: exempt #8202"))
            exemptions = []
            findings = checker.scan_repository(root, exemptions)
            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0][1].line, 4)
            self.assertEqual(exemptions, [])  # S6: YAML removes this comment.


class ShellProgramsN4(unittest.TestCase):
    def test_shell_c_option_clusters_reenter_the_scan(self):
        checker = load_checker()
        for shell in ("sh", "bash", "zsh", "dash", "/bin/bash"):
            for option in ("-c", "-ec", "-lc", "-xec", "-ce"):
                with self.subTest(shell=shell, option=option):
                    command = f"{shell} {option} 'python3 x.py'"
                    self.assertEqual(len(checker.scan_shell(command)), 1,
                                     "shell command string escaped")
                    self.assertEqual(checker.scan_shell(command.replace("python3", "python3 -I")), [])
        self.assertEqual(len(checker.scan_shell("env X=1 bash -lc 'python3 x.py'")), 1)

    def test_shell_heredocs_are_program_text_with_source_lines(self):
        checker = load_checker()
        for shell in ("sh", "bash", "zsh", "dash", "nice -n 10 bash"):
            for redirect in ("<<EOF", "<<'EOF'", "<<-EOF"):
                with self.subTest(shell=shell, redirect=redirect):
                    command = f"{shell} {redirect}\n\tpython3 x.py\nEOF\n"
                    findings = checker.scan_shell(command)
                    self.assertEqual(len(findings), 1, "shell heredoc program escaped")
                    self.assertEqual(findings[0].line, 2)
                    self.assertEqual(checker.scan_shell(command.replace("python3", "python3 -I")), [])

    def test_data_heredocs_and_nested_data_remain_data(self):
        checker = load_checker()
        for header in ("cat <<EOF", "cat > output <<EOF", "python3 -I - <<EOF",
                       "bash script.sh <<EOF"):
            with self.subTest(header=header):
                self.assertEqual(checker.scan_shell(f"{header}\npython3 x.py\nEOF\n"), [])
        nested = ("bash <<OUTER\ncat <<INNER\npython3 data.py\nINNER\n"
                  "python3 program.py\nOUTER\n")
        findings = checker.scan_shell(nested)
        self.assertEqual(len(findings), 1, "nested shell program escaped or data scanned")
        self.assertEqual(findings[0].line, 5)


class InterpreterCaseN5(unittest.TestCase):
    def test_literal_python_names_are_case_insensitive(self):
        checker = load_checker()
        for interpreter in ("Python", "Python3", "PYTHON3.12", "/usr/bin/Python3"):
            with self.subTest(interpreter=interpreter):
                findings = checker.scan_shell(f"{interpreter} x.py")
                self.assertEqual(len(findings), 1, "case variant escaped")
                self.assertEqual(checker.scan_shell(f"{interpreter} -I x.py"), [])


class CodeReviewRoundFive(unittest.TestCase):
    def test_debug_and_case_interpreter_names_c1(self):
        checker = load_checker()
        for name in ("python3-dbg", "python3.12d", "Python3"):
            with self.subTest(name=name):
                self.assertEqual(len(checker.scan_shell(f"{name} x.py")), 1,
                                 "Python executable suffix escaped")
                self.assertEqual(checker.scan_shell(f"{name} -I x.py"), [])

    def test_malformed_workflow_keeps_line_and_all_findings_c4(self):
        scratch = ROOT / ".local-runs"
        scratch.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(dir=scratch) as directory:
            root = Path(directory)
            path = root / ".github/workflows/malformed.yml"
            path.parent.mkdir(parents=True)
            path.write_text("jobs:\n  test:\n    steps:\n      - run: |\n"
                            "          python3 x.py\n          echo ready\n"
                            "          echo 'unterminated\n")
            result = subprocess.run([sys.executable, "-I", str(CHECKER), "--root", str(root)],
                                    text=True, capture_output=True, check=False)
            output = result.stdout + result.stderr
            self.assertEqual(result.returncode, 2, output)
            self.assertIn(f"{path}:7: unparseable shell command", output)
            self.assertIn(f"{path}:5: Python interpreter requires -I", output)
            self.assertIn("python isolation: findings=2 exemptions=0", output)
            self.assertNotIn("Traceback", output)

    def test_malformed_constructs_keep_prior_findings_and_real_line_c4(self):
        checker = load_checker()
        for malformed in ("echo 'unterminated", "echo $(unterminated",
                          "echo `unterminated", "bash <<EOF"):
            with self.subTest(malformed=malformed):
                findings = checker.scan_shell("python3 x.py\necho ready\n" + malformed + "\n")
                self.assertEqual([(item.line, item.malformed) for item in findings],
                                 [(1, False), (3, True)])

    def test_sibling_mismatch_names_module_and_both_paths_c5(self):
        spec = importlib.util.spec_from_file_location(
            "sibling_round_five", ROOT / "scripts/ci/sibling_import.py")
        loader = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(loader)
        name = "fixture_sibling_8202"
        caller = ROOT / ".local-runs/expected/caller.py"
        expected = caller.with_name(name + ".py")
        actual = ROOT / ".local-runs/elsewhere/fixture.py"
        prior = sys.modules.get(name)
        module = types.ModuleType(name)
        module.__file__ = str(actual)
        sys.modules[name] = module
        try:
            with self.assertRaises(ImportError) as raised:
                loader.load_sibling(name, caller)
            for detail in (name, str(expected), str(actual)):
                with self.subTest(detail=detail):
                    self.assertIn(detail, str(raised.exception))
            self.assertIs(sys.modules[name], module)
        finally:
            sys.modules.pop(name, None)
            if prior is not None:
                sys.modules[name] = prior


if __name__ == "__main__":
    unittest.main()
