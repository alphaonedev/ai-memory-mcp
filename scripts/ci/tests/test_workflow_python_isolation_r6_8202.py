"""Round-six isolation regressions; shell fixture text is never executed."""
import importlib.util
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[3]
CHECKER = ROOT / "scripts/ci/check_workflow_python_isolation.py"


def load_checker():
    spec = importlib.util.spec_from_file_location("isolation_round_six", CHECKER)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class InterpreterNamesS2(unittest.TestCase):
    def test_free_threaded_pypy_and_executable_suffix_s2(self):
        checker = load_checker()
        for name in ("python3.13t", "Python3.13t.exe", "pypy", "pypy3", "PYPY3.exe",
                     "python.exe", "python3.exe", "C:/Python312/python.exe",
                     "python3.12d", "python3-dbg"):
            with self.subTest(name=name):
                found = checker.scan_shell(f"{name} x.py")
                self.assertEqual(len(found), 1, "interpreter variant escaped")
                self.assertFalse(found[0].malformed)
                self.assertEqual(checker.scan_shell(f"{name} -I x.py"), [])


class ExecutableResolutionS1S3S4(unittest.TestCase):
    def test_command_substitution_executable_is_dynamic_s1(self):
        checker = load_checker()
        for program in ('$(which python3)', '`which python3`', '$(command -v python3)',
                        '"$(which python3)"', 'timeout 60 $(which python3)'):
            with self.subTest(program=program):
                text = f'{program} x.py'
                found = checker.scan_shell(text)
                self.assertEqual(len(found), 1, "substitution interpreter escaped")
                self.assertEqual(found[0].reason, checker.DYNAMIC_REASON)
                self.assertEqual(checker.scan_source(text + ' # isolation: exempt #8202'),
                                 ([], [(1, '8202')]))
        for data in ('echo $(which python3)', '$BIN run', '${{ matrix.interp }} x.py'):
            self.assertEqual(checker.scan_shell(data), [])

    def test_relative_interpreter_at_resolved_index_s3(self):
        checker = load_checker()
        for prefix in ('timeout 60', 'nohup', 'nice -n 10', 'sudo -u u'):
            for program in ('./python3', 'venv/python3', '.venv/Scripts/python'):
                with self.subTest(prefix=prefix, program=program):
                    self.assertEqual(len(checker.scan_shell(f'{prefix} {program} x.py')), 1,
                                     "relative interpreter escaped")
                    self.assertEqual(checker.scan_shell(f'{prefix} {program} -I x.py'), [])

    def test_additional_prefixes_resolve_dynamic_and_launcher_s4(self):
        checker = load_checker()
        for prefix in ('stdbuf -oL', 'setsid', 'flock lockfile', 'ionice -c3',
                       'chrt -i 0', 'taskset -c 0', 'taskset 0x1', 'nice -n 10 setsid'):
            for program in ('$PYTHON', 'py -3', 'pip', 'pytest'):
                with self.subTest(prefix=prefix, program=program):
                    found = checker.scan_shell(f'{prefix} {program} x.py')
                    self.assertEqual(len(found), 1, "wrapped interpreter escaped")
                    self.assertFalse(found[0].malformed)
            self.assertEqual(checker.scan_shell(f'{prefix} python3 -I x.py'), [])

    def test_env_split_program_is_relexed_s4(self):
        checker = load_checker()
        for prefix in ('env -S ', 'env --split-string=', 'sudo -u u env -u X -S '):
            for program in ('python3 x.py', '$PYTHON x.py', 'pip install x'):
                with self.subTest(prefix=prefix, program=program):
                    self.assertEqual(len(checker.scan_shell(f"{prefix}'{program}'")), 1,
                                     "env split program escaped")
            self.assertEqual(checker.scan_shell(f"{prefix}'python3 -I x.py'"), [])

    def test_substitutions_in_arithmetic_and_array_assignments_are_data_s1(self):
        checker = load_checker()
        for text in ('local left=$(( LIMIT - $(date +%s) ))',
                     'values=($(printf word)); echo ready',
                     'mode=$(( $(id -u) + 1 ))'):
            with self.subTest(text=text):
                self.assertEqual(checker.scan_shell(text), [], "data substitution became executable")
        self.assertEqual(len(checker.scan_shell('values=($(python3 x.py))')), 1)
        self.assertEqual(len(checker.scan_shell('number=$(( $(python3 x.py) + 1 ))')), 1)


if __name__ == "__main__":
    unittest.main()
