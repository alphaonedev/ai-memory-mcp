"""Round-six isolation regressions; shell fixture text is never executed."""
import importlib.util
import ast
from pathlib import Path
import sys
import subprocess
import tempfile
import unittest
import types

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
                     'mode=$(( $(id -u) + 1 ))',
                     'if (($(count one) % 2 || $(count two) % 2)); then echo ready; fi'):
            with self.subTest(text=text):
                self.assertEqual(checker.scan_shell(text), [], "data substitution became executable")
        self.assertEqual(len(checker.scan_shell('values=($(python3 x.py))')), 1)
        self.assertEqual(len(checker.scan_shell('number=$(( $(python3 x.py) + 1 ))')), 1)
        self.assertEqual(len(checker.scan_shell('(( $(python3 x.py) > 0 ))')), 1)


class WorkflowScalarsS5S6R1S8(unittest.TestCase):
    def setUp(self):
        scratch = ROOT / '.local-runs'
        scratch.mkdir(exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(dir=scratch)
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.workflow = self.root / '.github/workflows/check.yml'
        self.workflow.parent.mkdir(parents=True)

    def scan(self, steps):
        self.workflow.write_text('jobs:\n  test:\n    steps:\n' + steps)
        exemptions = []
        return load_checker().scan_repository(self.root, exemptions), exemptions

    def test_yaml_run_forms_s5(self):
        for steps, line in (
            ('      - run: echo ready &&\n          python3 x.py\n', 5),
            ('      - run:\n          python3 x.py\n', 5),
            ('      - {name: check, run: python3 x.py}\n', 4),
            ('      - "run": python3 x.py\n', 4),
            ("      - 'run': python3 x.py\n", 4),
            ("      - run: 'python3 x.py' # ordinary YAML comment\n", 4),
            ('      - run: >-\n          python3\n          x.py\n', 5),
        ):
            with self.subTest(steps=steps):
                findings, exemptions = self.scan(steps)
                self.assertEqual(len(findings), 1, 'workflow scalar escaped')
                self.assertFalse(findings[0][1].malformed)
                self.assertEqual(findings[0][1].line, line)
                self.assertEqual(exemptions, [])
                isolated = steps.replace('python3', 'python3 -I')
                self.assertEqual(self.scan(isolated)[0], [])

    def test_yaml_comments_do_not_exempt_shell_s6(self):
        for steps in ('      - run: python3 x.py # isolation: exempt #8202\n',
                      '      - shell: python3 {0} # isolation: exempt #8202\n'
                      '        run: pass\n'):
            with self.subTest(steps=steps):
                findings, exemptions = self.scan(steps)
                self.assertEqual(len(findings), 1, 'YAML comment exempted an invocation')
                self.assertEqual(exemptions, [])
        for steps in ('      - run: "python3 x.py # isolation: exempt #8202"\n',
                      '      - run: |\n          python3 x.py # isolation: exempt #8202\n'):
            with self.subTest(shell_comment=steps):
                findings, exemptions = self.scan(steps)
                self.assertEqual(findings, [])
                self.assertEqual(len(exemptions), 1)

    def test_bad_scalar_retains_real_line_and_other_findings_r1(self):
        steps = ('      - run: "bad\\q"\n'
                 '      - run: python3 x.py\n'
                 '      - run: "also\\q"\n')
        self.scan(steps)
        result = subprocess.run([sys.executable, '-I', str(CHECKER), '--root', str(self.root)],
                                capture_output=True, text=True, check=False)
        self.assertEqual(result.returncode, 2)
        for line in (4, 5, 6):
            self.assertIn(f'{self.workflow}:{line}:', result.stdout)
        self.assertIn('findings=3 exemptions=0', result.stdout)
        self.assertNotIn('Traceback', result.stderr)

    def test_missing_or_empty_repository_is_input_error_s8(self):
        for root in (self.root / 'missing', self.root):
            with self.subTest(root=root):
                result = subprocess.run([sys.executable, '-I', str(CHECKER), '--root', str(root)],
                                        capture_output=True, text=True, check=False)
                self.assertEqual(result.returncode, 2, 'empty repository scan reported success')
                self.assertIn(str(root), result.stdout + result.stderr)
                self.assertIn('python isolation:', result.stdout)
                self.assertNotIn('Traceback', result.stderr)


class HeredocLexingS7R2(unittest.TestCase):
    def test_quoted_and_arithmetic_shifts_are_not_heredocs_s7(self):
        checker = load_checker()
        for prefix in ("printf '%s' '<<EOF'", 'echo "<<EOF"',
                       'value=$((left<<right))', 'value=$((1<<bits))'):
            with self.subTest(prefix=prefix):
                found = checker.scan_shell(prefix + '\npython3 x.py\n')
                self.assertEqual([(item.line, item.malformed) for item in found], [(2, False)])
        self.assertEqual(checker.scan_shell('cat <<EOF\npython3 x.py\nEOF\n'), [])
        found = checker.scan_shell('bash <<EOF\npython3 x.py\nEOF\n')
        self.assertEqual([(item.line, item.malformed) for item in found], [(2, False)])
        for text in ('value="$(python3 -I - <<EOF\nprint(1)\nEOF\n)"',
                     'value="$(\npython3 -I - <<EOF\nprint(1)\nEOF\n)"'):
            self.assertEqual(checker.scan_shell(text), [])

    def test_malformed_heredoc_prefix_retains_line_and_later_findings_r2(self):
        checker = load_checker()
        found = checker.scan_shell("echo first\necho second\necho 'bad <<EOF\npython3 x.py\n")
        self.assertEqual([(item.line, item.malformed) for item in found],
                         [(3, True), (4, False)])


class ContinuationQuotesR5(unittest.TestCase):
    def test_single_quoted_continuation_is_literal_r5(self):
        checker = load_checker()
        literal = "printf '%s' 'first\\\nsecond'\npython3 x.py\n"
        self.assertEqual(checker.join_continuations(literal), literal,
                         'single-quoted continuation was rewritten')
        for text in ('python3 \\\n-I x.py', 'echo "first\\\nsecond"'):
            self.assertEqual(checker.join_continuations(text), text.replace('\\\n', '  '))
        self.assertEqual(checker.scan_shell('python3 \\\n-I x.py'), [])


class GrammarConstantsR4(unittest.TestCase):
    def test_named_grammar_tokens_have_no_function_local_copies_r4(self):
        tree = ast.parse(CHECKER.read_text())
        tokens = {'SUBSTITUTION', '${{', '}}', '/bin/'}
        for function in (node for node in ast.walk(tree) if isinstance(node, ast.FunctionDef)):
            for node in ast.walk(function):
                if isinstance(node, ast.Constant) and isinstance(node.value, str):
                    self.assertNotIn(node.value, tokens, f'inline grammar token in {function.name}')


class SiblingOriginR6(unittest.TestCase):
    def test_registered_module_without_file_has_explicit_origin_r6(self):
        path = ROOT / 'scripts/ci/sibling_import.py'
        spec = importlib.util.spec_from_file_location('r6_sibling_loader', path)
        loader = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(loader)
        name = 'r6_no_file_fixture'
        self.assertNotIn(name, sys.modules)
        sys.modules[name] = types.ModuleType(name)
        self.addCleanup(sys.modules.pop, name, None)
        with self.assertRaisesRegex(ImportError, '<no __file__>') as error:
            loader.load_sibling(name, str(path))
        self.assertIn(name, str(error.exception))
        self.assertIn(str(path.with_name(name + '.py')), str(error.exception))


if __name__ == "__main__":
    unittest.main()
