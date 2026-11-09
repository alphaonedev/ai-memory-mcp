"""Round-seven isolation invariants (#8202, option B: fail closed by construction).

Class invariant: every shell or workflow form the checker cannot fully classify is a
finding that tells the author to write python3 -I; no input, however large or deeply
nested, ends in a traceback or a silent pass. Fixture text is never executed.
"""
import ast
import importlib.util
import itertools
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
CHECKER = ROOT / "scripts/ci/check_workflow_python_isolation.py"

# Expected reasons are pinned here as literals so a reworded message is a red test.
REASON_ISOLATION = "Python interpreter requires -I before the program"
REASON_DYNAMIC = "dynamic interpreter requires an issue exemption"
REASON_LAUNCHER = "console launcher requires isolated Python -m"
REASON_UNCLASSIFIED = "unclassifiable shell form: write python3 -I explicitly"
REASON_NESTING = "nesting too deep to classify: write python3 -I explicitly"
REASON_RECOVERY = "too many malformed commands to classify: write python3 -I explicitly"
REASON_STALE = "stale isolation exemption matches no finding"
REASON_WORKFLOW = "unsupported workflow run scalar"
REASON_MALFORMED = "unparseable shell command"
UNSAFE_REASONS = frozenset((REASON_ISOLATION, REASON_DYNAMIC, REASON_LAUNCHER,
                            REASON_UNCLASSIFIED))

# Corpus constants: wrapper x form x context. Named so the class is auditable.
WRAPPERS = ("", "timeout 60 ", "nohup ", "unknownwrap ", "unknownwrap --flag ",
            "sudo -u u ", "env FOO=1 ", "nice -n 5 unknownwrap ")
UNSAFE_FORMS = ("python3 x.py", "${PY:-python3} x.py", "$PYTHON x.py", "py -3 x.py", "pip install x",
                "pytest -q", "$(which python3) x.py", "`which python3` x.py",
                "${{ matrix.python }} x.py")
SAFE_FORMS = ("python3 -I x.py", "$BIN run", "${BIN} run", "git status",
              "echo $PYTHON", "ssh host ls")
CONTEXTS = ("{cmd}", "bash -c '{cmd}'", 'sh -c "{cmd}"', "eval '{cmd}'",
            "if true; then {cmd}; fi", "echo $({cmd})")
UNCLASSIFIED_FORMS = (
    "{python3,pypy3} x.py", "python{3,} x.py", "/usr/bin/{python3,python} x.py",
    "/usr/bin/pyth* x.py", "./py?hon3 x.py", "/usr/bin/python3.[0-9]* x.py",
    "ksh -c 'python3 x.py'", "fish -c 'echo hi'", "mksh -c 'echo hi'",
    "busybox sh -c 'echo hi'", "pwsh -c Get-Date", "bash -c \"$CMD\"",
    "sh -c \"$(cat run.sh)\"", "eval \"$CMD\"", "eval $(make-cmd)",
    "${!NAME} x.py", "${PYTHON%/*} x.py")
UNSUPPORTED_YAML_STEPS = {
    "alias": "      - &a\n        run: echo hi\n      - run: *a",
    "space-before-colon": "      - run : python3 x.py",
    "flow-seq-steps": "    steps: [{run: python3 x.py}]",
    "decorated-flow-step": "      - !!map {run: python3 x.py}",
    "complex-key": "      - ? run\n        : python3 x.py",
    "escaped-key": "      - \"\\u0072un\": python3 x.py",
    "tagged-value": "      - run: !!str python3 x.py",
    "anchored-value": "      - run: &cmd python3 x.py",
    "merge-key": "      - <<: *base\n        name: x",
    "flow-jobs": "  jobs: {a: {steps: [{run: python3 x.py}]}}",
}
NEST_DEPTH_OVER_LIMIT = 80
MALFORMED_LINES = 2500
RECOVERY_PASSES = 80
GROWTH_CEILING = 2.2
WALL_CEILING_SECONDS = 20.0
RECOVERY_LIMIT_CEILING = 256
INPUT_EXIT = 2
FINDINGS_EXIT = 1


def load_checker():
    spec = importlib.util.spec_from_file_location("isolation_round_seven", CHECKER)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def run_cli(*args, cwd=None):
    return subprocess.run([sys.executable, "-I", str(CHECKER), *args],
                          capture_output=True, text=True, check=False, cwd=cwd)


def workflow_repo(steps):
    directory = tempfile.TemporaryDirectory()
    root = Path(directory.name)
    (root / ".github/workflows").mkdir(parents=True)
    (root / ".github/workflows/ci.yml").write_text(
        "name: t\non: push\njobs:\n  a:\n    runs-on: x\n" + steps + "\n")
    return directory, root


class UnclassifiedShellIsFindingR7(unittest.TestCase):
    def test_unsafe_forms_never_pass_in_any_wrapper_or_context(self):
        checker = load_checker()
        for wrapper, form, context in itertools.product(WRAPPERS, UNSAFE_FORMS, CONTEXTS):
            text = context.format(cmd=wrapper + form)
            with self.subTest(text=text):
                found = checker.scan_shell(text)
                self.assertTrue(found, "unclassified input passed silently")
                for item in found:
                    self.assertIn(item.reason, UNSAFE_REASONS)

    def test_safe_forms_stay_clean_in_every_wrapper_and_context(self):
        checker = load_checker()
        for wrapper, form, context in itertools.product(WRAPPERS, SAFE_FORMS, CONTEXTS):
            text = context.format(cmd=wrapper + form)
            with self.subTest(text=text):
                self.assertEqual(checker.scan_shell(text), [])

    def test_every_unclassifiable_form_is_one_exact_finding(self):
        checker = load_checker()
        for form, wrapper in itertools.product(UNCLASSIFIED_FORMS, WRAPPERS[:3]):
            text = wrapper + form
            with self.subTest(text=text):
                found = checker.scan_shell(text)
                self.assertEqual([item.reason for item in found], [REASON_UNCLASSIFIED])
                self.assertFalse(found[0].malformed)

    def test_env_split_program_is_reported_once_f7(self):
        checker = load_checker()
        for text in ("env -S 'python3 x.py'", "env --split-string='python3 x.py'",
                     "env -S python3 x.py", "env -uX -S 'python3 x.py'",
                     "env -S '$PYTHON x.py'"):
            with self.subTest(text=text):
                self.assertEqual(len(checker.scan_shell(text)), 1)


class StaleExemptionR7(unittest.TestCase):
    def test_exemption_that_matches_nothing_is_a_finding(self):
        checker = load_checker()
        for text, expected in (
                ("echo hi # isolation: exempt #8202", [(1, REASON_STALE)]),
                ("python3 -I x.py # isolation: exempt #8202", [(1, REASON_STALE)]),
                ("echo a\necho b # isolation: exempt #1", [(2, REASON_STALE)])):
            with self.subTest(text=text):
                findings, exempt = checker.scan_source(text)
                self.assertEqual([(i.line, i.reason) for i in findings], expected)
                self.assertEqual(exempt, [])

    def test_live_exemption_still_suppresses_and_is_not_stale(self):
        checker = load_checker()
        self.assertEqual(checker.scan_source("python3 x.py # isolation: exempt #8202"),
                         ([], [(1, "8202")]))

    def test_stale_exemption_fails_the_repository_scan(self):
        directory, root = workflow_repo(
            "    steps:\n      - run: |\n          echo hi # isolation: exempt #8202")
        with directory:
            result = run_cli("--root", str(root))
        self.assertEqual(result.returncode, FINDINGS_EXIT, result.stdout)
        self.assertIn(REASON_STALE, result.stdout)


class UnsupportedYamlFormsR7(unittest.TestCase):
    def test_every_unsupported_run_form_is_a_located_input_finding(self):
        checker = load_checker()
        for name, steps in UNSUPPORTED_YAML_STEPS.items():
            block = steps if name == "flow-jobs" else (
                steps if steps.lstrip().startswith("steps:") else "    steps:\n" + steps)
            directory, root = workflow_repo(block)
            with self.subTest(form=name), directory:
                found = checker.scan_repository(root)
                self.assertTrue(found, "unsupported YAML run form passed silently")
                self.assertTrue(any(item.reason == REASON_WORKFLOW and item.malformed
                                    for _, item in found))
                result = run_cli("--root", str(root))
                self.assertEqual(result.returncode, INPUT_EXIT, result.stdout)
                self.assertIn("python isolation: findings=", result.stdout)

    def test_supported_forms_stay_clean(self):
        for steps in ("    steps:\n      - run: echo hi",
                      "    steps:\n      - run: |\n          python3 -I x.py",
                      "    steps:\n      - run: 'python3 -I x.py'",
                      "    steps:\n      - name: x\n        script: |\n"
                      "          run: not a step"):
            directory, root = workflow_repo(steps)
            with self.subTest(steps=steps), directory:
                result = run_cli("--root", str(root))
                self.assertEqual(result.returncode, 0, result.stdout)


class BoundedCostR7(unittest.TestCase):
    def test_nesting_past_the_limit_is_a_located_finding_not_a_traceback(self):
        checker = load_checker()
        substitution = "echo " + "$(" * NEST_DEPTH_OVER_LIMIT + "python3 x.py" \
            + ")" * NEST_DEPTH_OVER_LIMIT
        heredocs = "".join(f"bash <<E{i}\n" for i in range(NEST_DEPTH_OVER_LIMIT)) \
            + "python3 x.py\n" + "".join(
                f"E{i}\n" for i in reversed(range(NEST_DEPTH_OVER_LIMIT)))
        for name, text in (("substitution", substitution), ("heredoc", heredocs)):
            with self.subTest(form=name):
                found = checker.scan_shell(text)
                self.assertIn(REASON_NESTING, [item.reason for item in found])
                self.assertTrue(all(item.malformed for item in found
                                    if item.reason == REASON_NESTING))

    def test_many_malformed_lines_exit_two_with_summary_in_linear_work(self):
        for line in ("echo $(\n", "cat <<EOF\n"):
            text = line * MALFORMED_LINES
            directory, root = workflow_repo(
                "    steps:\n      - run: |\n"
                + "".join("          " + part + "\n" for part in text.splitlines()))
            with self.subTest(line=line), directory:
                started = time.monotonic()
                result = run_cli("--root", str(root))
                elapsed = time.monotonic() - started
                self.assertEqual(result.returncode, INPUT_EXIT, result.stderr[-400:])
                self.assertNotIn("Traceback", result.stderr)
                self.assertIn("python isolation: findings=", result.stdout)
                self.assertIn(REASON_RECOVERY, result.stdout)
                self.assertLess(elapsed, WALL_CEILING_SECONDS)
                reported = result.stdout.count(REASON_MALFORMED)
                self.assertLessEqual(reported, RECOVERY_LIMIT_CEILING)

    def test_scan_work_is_bounded_by_the_input_size(self):
        checker = load_checker()

        def work(text):
            sizes = []
            originals = {name: getattr(checker, name)
                         for name in ("substitutions", "mask_heredocs")}

            def counting(name):
                def wrapper(chunk, *args, **kwargs):
                    sizes.append(len(chunk))
                    return originals[name](chunk, *args, **kwargs)
                return wrapper

            for name in originals:
                setattr(checker, name, counting(name))
            try:
                self.assertTrue(checker.scan_shell(text))
            finally:
                for name, function in originals.items():
                    setattr(checker, name, function)
            return sum(sizes)

        for line in ("echo $(\n", "cat <<EOF\n"):
            with self.subTest(line=line):
                small = work(line * MALFORMED_LINES)
                large = work(line * MALFORMED_LINES * 2)
                self.assertLessEqual(small, RECOVERY_PASSES * len(line) * MALFORMED_LINES,
                                     "recovery re-lexes the input quadratically")
                self.assertLessEqual(large, small * GROWTH_CEILING,
                                     "work grows faster than the input")

    def test_no_recursion_error_at_any_malformed_count(self):
        checker = load_checker()
        for count in (1, 10, 100, 1000, MALFORMED_LINES):
            with self.subTest(count=count):
                found = checker.scan_shell("echo $(\n" * count)
                self.assertTrue(any(item.malformed for item in found))


class GrammarConstantsR7(unittest.TestCase):
    def test_no_function_local_copy_of_any_module_string_token(self):
        tree = ast.parse(CHECKER.read_text())
        tokens = set()
        for node in tree.body:
            if (isinstance(node, ast.Assign) and isinstance(node.value, ast.Constant)
                    and isinstance(node.value.value, str) and len(node.value.value) >= 2
                    and all(isinstance(t, ast.Name) and t.id.isupper() for t in node.targets)):
                tokens.add(node.value.value)
        missing = {value for value in ("$(", "((") if value not in tokens}
        self.assertEqual(missing, set(), "grammar tokens lack a named constant")
        for function in (n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)):
            for node in ast.walk(function):
                if isinstance(node, ast.Constant) and isinstance(node.value, str):
                    self.assertNotIn(node.value, tokens,
                                     f"inline grammar token {node.value!r} in {function.name}")

    def test_run_and_shell_keys_come_from_one_tuple(self):
        checker = load_checker()
        keys = checker.WORKFLOW_KEYS
        self.assertEqual(set(keys), {"run", "shell"})
        for key in keys:
            self.assertTrue(checker.WORKFLOW_FIELD.match(f"  - {key}: x"))
            self.assertTrue(checker.FLOW_FIELD.match(f"{key}: x"))


class DocstringR7(unittest.TestCase):
    def test_docstring_states_input_error_behaviour_f6(self):
        checker = load_checker()
        doc = " ".join(checker.__doc__.split())
        self.assertNotIn("Input errors retain other findings and the summary", doc)
        self.assertIn("Unreadable files stop the scan with a path message and no summary",
                      doc)
        self.assertIn("malformed constructs are located findings that keep every other "
                      "finding and the summary", doc)


# Shell shapes that once produced false findings on the live wrapper scripts.
LEXER_CLEAN_CASES = {
    "hash-in-braces": 'for ((i = 0; i < ${#pat}; i++)); do\n  echo "$i"\ndone\n',
    "quoted-paren-case-pattern": "case \"$c\" in\n  '.' | '(' | ')' | '\\') x+=1 ;;\n  *) x+=2 ;;\nesac\n",
    "blank-in-braced-parameter": "loc=${hit%%  *}; key=${hit##*  }\n",
    "python-named-path-operand": 'mkdir -p "$FIX/sdk/python/ai_memory"\n',
    "test-regex": '[[ "$ref" =~ ^${rx}$ ]]\n',
}
LIVE_FINDING_COUNT = 0


class LiveRepositoryR7(unittest.TestCase):
    def test_lexer_shapes_are_not_findings(self):
        checker = load_checker()
        for name, text in LEXER_CLEAN_CASES.items():
            with self.subTest(name=name):
                self.assertEqual(checker.scan_shell(text), [])

    def test_python_named_operand_of_unknown_wrapper_is_still_dynamic(self):
        checker = load_checker()
        found = checker.scan_shell("unknownwrap $PYTHON x.py\n")
        self.assertEqual([item.reason for item in found], [REASON_DYNAMIC])

    def test_repository_has_the_measured_finding_count(self):
        checker = load_checker()
        self.assertEqual(len(checker.scan_repository(ROOT)), LIVE_FINDING_COUNT)


if __name__ == "__main__":
    unittest.main()
