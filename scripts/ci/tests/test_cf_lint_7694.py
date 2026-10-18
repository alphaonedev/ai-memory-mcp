"""#7694: the CodeQL findings 529-532 (an unused import and three empty `except` blocks) and every other site of the same
shape in the Python this change adds. An ast lint, so the next one fails here and not in a scan after the push:

  * no import whose name is never used in the module (py/unused-import);
  * no `except` whose whole body is `pass` or a bare constant (py/empty-except): a swallowed error needs a logged or
    returned reason."""
import ast
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
TESTS = Path(__file__).resolve().parent


def linted_files():
    files = sorted(TESTS.glob("cf_*.py")) + sorted(TESTS.glob("test_cf_*.py"))
    files += sorted((REPO / "infra" / "cf-dashboard").glob("*.py"))
    files += [REPO / "scripts" / "evidence" / "mcp-tools-state.py", TESTS / "fixtures" / "regen_whatwg_origin_cases_7313.py"]
    return [f for f in files if f.exists()]


def unused_imports(tree):
    imported = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                imported[(alias.asname or alias.name).split(".")[0]] = node.lineno
        elif isinstance(node, ast.ImportFrom):
            for alias in node.names:
                imported[alias.asname or alias.name] = node.lineno
    used = {n.id for n in ast.walk(tree) if isinstance(n, ast.Name)}
    used |= {n.value.id for n in ast.walk(tree) if isinstance(n, ast.Attribute) and isinstance(n.value, ast.Name)}
    exported = set()
    for node in ast.walk(tree):  # names listed in __all__ count as used
        if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == "__all__" for t in node.targets):
            exported |= {e.value for e in ast.walk(node.value) if isinstance(e, ast.Constant) and isinstance(e.value, str)}
    return sorted((line, name) for name, line in imported.items() if name not in used and name not in exported
                  and name != "annotations")


def empty_excepts(tree):
    found = []
    for node in ast.walk(tree):
        if isinstance(node, ast.ExceptHandler):
            body = [s for s in node.body if not (isinstance(s, ast.Expr) and isinstance(s.value, ast.Constant))]
            if all(isinstance(s, ast.Pass) for s in body):
                found.append(node.lineno)
    return sorted(found)


class Lint7694(unittest.TestCase):
    def test_the_lint_covers_the_files_codeql_flagged(self):
        names = {f.name for f in linted_files()}
        for expected in ("cf_cdp_7313.py", "test_cf_browser_7634.py", "hostscrub.py", "cfcommon.py"):
            self.assertIn(expected, names)

    def test_no_module_has_an_unused_import(self):
        for path in linted_files():
            tree = ast.parse(path.read_text(encoding="utf-8"), str(path))
            self.assertEqual(unused_imports(tree), [], path.name)

    def test_no_module_swallows_an_exception_with_an_empty_except(self):
        for path in linted_files():
            tree = ast.parse(path.read_text(encoding="utf-8"), str(path))
            self.assertEqual(empty_excepts(tree), [], path.name)

    def test_the_lint_itself_sees_the_shapes(self):
        tree = ast.parse("import os\nimport sys as s\nfrom a import b\ntry:\n    pass\nexcept OSError:\n    pass\n"
                         "try:\n    pass\nexcept OSError:\n    '''why'''\n    pass\nprint(b)\n")
        self.assertEqual(unused_imports(tree), [(1, "os"), (2, "s")])
        self.assertEqual(empty_excepts(tree), [6, 10])


if __name__ == "__main__":
    unittest.main()
