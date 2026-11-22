#!/usr/bin/env python3
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""PR 9817 round 2 (M1): no tracked Python file under scripts/ reads a name a repository module does not define.

Class: a PR removes names from a repository test module (here ``pyyaml`` and ``PYYAML_IMPORT_ERROR`` from
``test_ci_tainted_job_boundary``) while a sibling module still reads them, so a required CI job goes red with an
``AttributeError`` that no local run of the changed module shows.

Scope: every file ``git ls-files -- scripts`` lists that ends in ``.py`` or has a python ``#!`` line (the scope of
``test_ci_stdlib_imports_9813``, whose helpers this test loads from its file).

Invariant, for every file in scope and every repository module it binds (a module, never a package directory):

1. a binding is ``import X`` / ``import X as Y`` (at any depth) where ``X`` resolves to a tracked ``.py`` module in
   the file's import roots (its own directory first, then each directory above it up to ``scripts``, then
   ``scripts/ci``); or ``Y = f(...)`` where ``f`` is a module-level loader function of the same file: its body calls
   ``spec_from_file_location`` and the path argument (an expression, or the module-level constant it names) holds
   exactly one string literal ending in ``.py``, whose file name resolves the same way.
2. every ``Y.name`` read (``ast.Load``), ``getattr(Y, "name")`` with two arguments and ``patch.object(Y, "name")``,
   and every ``from X import name`` names a name the module defines: a module-level assignment, ``def``,
   ``class``, import or ``global`` assignment (at any depth of ``if`` / ``try`` / ``with`` / ``for`` / ``while`` /
   ``match``), or a module attribute every module has (``__name__``, ``__file__``, ...).
3. a module that defines names it cannot be read for (``from x import *``, a module ``__getattr__``, a
   ``globals()`` call) is the finding ``<open module>`` for each read, never a pass.

Every finding names ``file:line``, the read and the module. A file or module that cannot be read or parsed is a
failure with its reason. Forms not covered: a read through another name (``m = Y; m.name``), ``getattr`` with a
non-literal name or with a default (a probe that does not fail), a module bound by assignment inside a class or
an instance attribute (``self.m = f()``), a loader whose path is computed without a ``.py`` literal, a package
member (``import a.b``), and names set from outside the module (``Y.name = 1`` in another file).

Run: /opt/homebrew/bin/python3.12 -I scripts/ci/tests/test_ci_module_attribute_reads_9817.py
"""

from __future__ import annotations

import ast
import importlib.util
import shutil
import time
import types
import unittest
from pathlib import Path

TESTS_DIR = Path(__file__).resolve().parent
REPO = TESTS_DIR.parents[2]
RATCHET_PATH = TESTS_DIR / "test_ci_stdlib_imports_9813.py"

PY_SUFFIX = ".py"
LOADER_CALL = "spec_from_file_location"
SCAN_CEILING_SECS = 30.0  # the whole tree, parse included
OPEN = "<open module>"
# Attributes every module object has, written out by hand; checked against the interpreter below.
MODULE_ATTRS = frozenset({
    "__name__", "__doc__", "__package__", "__loader__", "__spec__", "__file__", "__cached__", "__builtins__",
    "__dict__", "__annotations__",
})

MSG_UNDEFINED = "%s:%d: %s.%s is not defined in %s"
MSG_FROM = "%s:%d: from %s import %s: not defined in %s"
MSG_OPEN = "%s:%d: %s.%s cannot be decided: %s defines names dynamically"
MSG_READ = "%s: cannot read as UTF-8: %s"
MSG_PARSE = "%s: cannot parse: %s"
MSG_EMPTY = "no tracked Python file under scripts: the scan would pass on nothing"


def _load_ratchet():
    spec = importlib.util.spec_from_file_location("stdlib_imports_9813_for_9817", RATCHET_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


ratchet = _load_ratchet()


# --- checker implementation ---
_COMPOUND = (ast.If, ast.Try, ast.With, ast.For, ast.While, ast.AsyncFor, ast.AsyncWith, ast.Match)
if hasattr(ast, "TryStar"):
    _COMPOUND = _COMPOUND + (ast.TryStar,)


def _target_names(target: ast.expr) -> list[str]:
    if isinstance(target, ast.Name):
        return [target.id]
    if isinstance(target, (ast.Tuple, ast.List)):
        return [name for elt in target.elts for name in _target_names(elt)]
    if isinstance(target, ast.Starred):
        return _target_names(target.value)
    return []


def _statement_names(stmt: ast.stmt) -> list[str]:
    if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
        return [stmt.name]
    if isinstance(stmt, ast.Assign):
        return [name for target in stmt.targets for name in _target_names(target)]
    if isinstance(stmt, (ast.AnnAssign, ast.AugAssign)):
        return _target_names(stmt.target)
    if isinstance(stmt, (ast.For, ast.AsyncFor)):
        return _target_names(stmt.target)
    if isinstance(stmt, (ast.With, ast.AsyncWith)):
        return [name for item in stmt.items if item.optional_vars is not None
                for name in _target_names(item.optional_vars)]
    if isinstance(stmt, ast.Import):
        return [alias.asname or alias.name.split(".")[0] for alias in stmt.names]
    if isinstance(stmt, ast.ImportFrom):
        return [alias.asname or alias.name for alias in stmt.names if alias.name != "*"]
    return []


def _module_statements(body: list[ast.stmt]):
    """Every statement that runs at module level, through compound statements, never into def or class bodies."""
    for stmt in body:
        yield stmt
        if isinstance(stmt, _COMPOUND):
            for field in ("body", "orelse", "finalbody"):
                yield from _module_statements(getattr(stmt, field, []) or [])
            for handler in getattr(stmt, "handlers", []) or []:
                yield from _module_statements(handler.body)
            for case in getattr(stmt, "cases", []) or []:
                yield from _module_statements(case.body)


def defined_names(tree: ast.Module) -> tuple[frozenset[str], bool]:
    """``(names the module defines, open)``; open when it defines names the AST cannot list."""
    names: set[str] = set(MODULE_ATTRS)
    is_open = False
    for stmt in _module_statements(tree.body):
        names.update(_statement_names(stmt))
        if isinstance(stmt, ast.ImportFrom) and any(alias.name == "*" for alias in stmt.names):
            is_open = True
        if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)) and stmt.name == "__getattr__":
            is_open = True
        names.update(handler.name for handler in getattr(stmt, "handlers", []) or [] if handler.name)
    for node in ast.walk(tree):
        if isinstance(node, ast.NamedExpr):
            names.update(_target_names(node.target))
        elif isinstance(node, ast.Global):
            names.update(node.names)
        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "globals":
            is_open = True
    return frozenset(names), is_open


def resolve_module(rel: str, name: str, by_dir: dict[str, dict[str, str]]) -> str | None:
    """The tracked ``.py`` module ``import name`` reaches from ``rel``; None for stdlib, a package or no match."""
    for root in ratchet.import_roots(rel):
        path = by_dir.get(root, {}).get(name)
        if path is not None:
            return path if path.endswith(PY_SUFFIX) else None
    return None


def _py_literals(node: ast.AST) -> list[str]:
    return [sub.value for sub in ast.walk(node)
            if isinstance(sub, ast.Constant) and isinstance(sub.value, str) and sub.value.endswith(PY_SUFFIX)]


def loader_functions(tree: ast.Module, rel: str, by_dir: dict[str, dict[str, str]]) -> dict[str, str]:
    """``{function name: module path}`` for each module-level loader of one repository file (rule 1)."""
    constants: dict[str, ast.expr] = {}
    for stmt in tree.body:
        if isinstance(stmt, ast.Assign):
            for target in stmt.targets:
                if isinstance(target, ast.Name):
                    constants[target.id] = stmt.value
        elif isinstance(stmt, ast.AnnAssign) and isinstance(stmt.target, ast.Name) and stmt.value is not None:
            constants[stmt.target.id] = stmt.value
    loaders: dict[str, str] = {}
    for stmt in tree.body:
        if not isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        calls = [node for node in ast.walk(stmt) if isinstance(node, ast.Call)
                 and isinstance(node.func, (ast.Name, ast.Attribute))
                 and (node.func.id if isinstance(node.func, ast.Name) else node.func.attr) == LOADER_CALL]
        if len(calls) != 1 or len(calls[0].args) < 2:
            continue
        path_arg = calls[0].args[1]
        literals = _py_literals(path_arg)
        if not literals:
            for sub in ast.walk(path_arg):
                if isinstance(sub, ast.Name) and sub.id in constants:
                    literals.extend(_py_literals(constants[sub.id]))
            if not literals:
                for sub in ast.walk(stmt):
                    if isinstance(sub, ast.Assign) and any(isinstance(t, ast.Name) and isinstance(path_arg, ast.Name)
                                                           and t.id == path_arg.id for t in sub.targets):
                        literals.extend(_py_literals(sub.value))
        if len(literals) != 1:
            continue
        stem = literals[0].rsplit("/", 1)[-1][: -len(PY_SUFFIX)]
        target = resolve_module(rel, stem, by_dir)
        if target is not None:
            loaders[stmt.name] = target
    return loaders


def module_bindings(tree: ast.Module, rel: str, by_dir: dict[str, dict[str, str]]) -> dict[str, str]:
    """``{bound name: module path}`` for every repository module the file binds (rule 1)."""
    loaders = loader_functions(tree, rel, by_dir)
    bound: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if "." in alias.name:
                    continue
                target = resolve_module(rel, alias.name, by_dir)
                if target is not None:
                    bound[alias.asname or alias.name] = target
        elif isinstance(node, (ast.Assign, ast.AnnAssign)) and isinstance(node.value, ast.Call):
            func = node.value.func
            if isinstance(func, ast.Name) and func.id in loaders:
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                for target in targets:
                    if isinstance(target, ast.Name):
                        bound[target.id] = loaders[func.id]
    return bound


def _literal(node: ast.expr) -> str | None:
    return node.value if isinstance(node, ast.Constant) and isinstance(node.value, str) else None


def attribute_reads(tree: ast.Module, bound: dict[str, str]) -> list[tuple[int, str, str]]:
    """``(line, bound name, attribute)`` of every read of rule 2 on a bound name."""
    reads: list[tuple[int, str, str]] = []
    for node in ast.walk(tree):
        if (isinstance(node, ast.Attribute) and isinstance(node.ctx, ast.Load) and isinstance(node.value, ast.Name)
                and node.value.id in bound):
            reads.append((node.lineno, node.value.id, node.attr))
        elif isinstance(node, ast.Call) and len(node.args) >= 2 and isinstance(node.args[0], ast.Name) \
                and node.args[0].id in bound:
            func = node.func
            is_getattr = isinstance(func, ast.Name) and func.id == "getattr" and len(node.args) == 2
            is_patch = isinstance(func, ast.Attribute) and func.attr == "object" \
                and isinstance(func.value, (ast.Name, ast.Attribute)) \
                and (func.value.id if isinstance(func.value, ast.Name) else func.value.attr) == "patch"
            name = _literal(node.args[1])
            if (is_getattr or is_patch) and name is not None:
                reads.append((node.lineno, node.args[0].id, name))
    return reads


def from_imports(tree: ast.Module, rel: str, by_dir: dict[str, dict[str, str]]) -> list[tuple[int, str, str, str]]:
    """``(line, module name, imported name, module path)`` of every ``from X import name`` of a repository module."""
    found: list[tuple[int, str, str, str]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.level == 0 and node.module and "." not in node.module:
            target = resolve_module(rel, node.module, by_dir)
            if target is None:
                continue
            for alias in node.names:
                if alias.name != "*":
                    found.append((node.lineno, node.module, alias.name, target))
    return found


def _parse(repo: Path, rel: str, cache: dict[str, object]) -> object:
    """The parsed module of ``rel``, or the problem line (a str) when it cannot be read or parsed."""
    if rel not in cache:
        try:
            source = (repo / rel).read_bytes().decode("utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            cache[rel] = MSG_READ % (rel, type(exc).__name__)
        else:
            try:
                cache[rel] = ast.parse(source, filename=rel)
            except (SyntaxError, ValueError) as exc:
                cache[rel] = MSG_PARSE % (rel, type(exc).__name__)
    return cache[rel]


def scan_tree(repo: Path, files: list[str]) -> list[str]:
    """One problem line per read of a name a bound repository module does not define (rules 1-3)."""
    if not files:
        return [MSG_EMPTY]
    by_dir = ratchet.module_names_by_dir(files)
    trees: dict[str, object] = {}
    definitions: dict[str, tuple[frozenset[str], bool]] = {}
    problems: list[str] = []

    def defined(target: str) -> tuple[frozenset[str], bool] | None:
        parsed = _parse(repo, target, trees)
        if isinstance(parsed, str):
            return None
        if target not in definitions:
            definitions[target] = defined_names(parsed)
        return definitions[target]

    for rel in files:
        parsed = _parse(repo, rel, trees)
        if isinstance(parsed, str):
            problems.append(parsed)
            continue
        bound = module_bindings(parsed, rel, by_dir)
        for line, alias, attr in attribute_reads(parsed, bound):
            target = bound[alias]
            names = defined(target)
            if names is None:
                continue  # the target's own read or parse problem is reported once, as a file in scope
            if names[1]:
                problems.append(MSG_OPEN % (rel, line, alias, attr, target))
            elif attr not in names[0]:
                problems.append(MSG_UNDEFINED % (rel, line, alias, attr, target))
        for line, module, name, target in from_imports(parsed, rel, by_dir):
            names = defined(target)
            if names is None:
                continue
            if names[1]:
                problems.append(MSG_OPEN % (rel, line, module, name, target))
            elif name not in names[0]:
                problems.append(MSG_FROM % (rel, line, module, name, target))
    return list(dict.fromkeys(problems))
# --- end checker implementation ---


def scratch_tree(test: unittest.TestCase, name: str, files: dict[str, str]) -> Path:
    """A scratch repository under .local-runs holding ``files``; removed when the test ends."""
    root = REPO / ".local-runs" / name
    if root.exists():
        shutil.rmtree(root)
    for rel, text in files.items():
        (root / rel).parent.mkdir(parents=True, exist_ok=True)
        (root / rel).write_text(text, encoding="utf-8")
    test.addCleanup(shutil.rmtree, root, True)
    return root


TARGET = (
    "import os\n"
    "A = 1\n"
    "B: int = 2\n"
    "C, (D, *E) = 1, (2, 3)\n"
    "def f():\n"
    "    global G\n"
    "    G = 1\n"
    "    local_only = 2\n"
    "class K:\n"
    "    member = 1\n"
    "try:\n"
    "    import json as J\n"
    "except ImportError as exc_name:\n"
    "    J = None\n"
    "if A:\n"
    "    H = 1\n"
    "with open(__file__) as W:\n"
    "    pass\n"
    "for L in ():\n"
    "    pass\n"
    "if (N := 1):\n"
    "    pass\n"
)


class Checker(unittest.TestCase):
    """The checker on synthetic trees, each expected line written out by hand."""

    def test_9817_module_attrs_are_attributes_of_every_module(self) -> None:
        module = types.ModuleType("probe_9817")
        module.__file__ = "probe.py"
        module.__cached__ = None
        module.__annotations__ = {}
        for name in MODULE_ATTRS - {"__builtins__"}:
            with self.subTest(name=name):
                self.assertTrue(hasattr(module, name))

    def test_9817_each_defining_form_is_a_defined_name(self) -> None:
        names, is_open = defined_names(ast.parse(TARGET))
        self.assertFalse(is_open)
        for name in ("os", "A", "B", "C", "D", "E", "f", "G", "K", "J", "exc_name", "H", "W", "L", "N", "__file__"):
            with self.subTest(name=name):
                self.assertIn(name, names)
        for name in ("local_only", "member", "pyyaml"):
            with self.subTest(name=name):
                self.assertNotIn(name, names)

    def test_9817_each_read_form_of_an_undefined_name_is_found_with_its_line(self) -> None:
        reader = (
            "import os\n"
            "import target\n"
            "import target as t2\n"
            "from target import A, missing_from\n"
            "def cell():\n"
            "    import target as main_cells\n"
            "    return main_cells.pyyaml is None, main_cells.PYYAML_IMPORT_ERROR\n"
            "x = target.A + target.gone\n"
            "y = t2.K.member + t2.nope\n"
            "z = getattr(target, 'by_getattr')\n"
            "probe = getattr(target, 'probe', None)\n"
            "with mock.patch.object(target, 'patched'):\n"
            "    pass\n"
            "target.assigned = 1\n"
            "w = os.not_checked\n"
        )
        files = {"scripts/ci/tests/target.py": TARGET, "scripts/ci/tests/reader.py": reader}
        root = scratch_tree(self, "attribute-reads-9817-forms", files)
        tgt = "scripts/ci/tests/target.py"
        rdr = "scripts/ci/tests/reader.py"
        self.assertEqual(sorted(scan_tree(root, sorted(files))), sorted([
            MSG_FROM % (rdr, 4, "target", "missing_from", tgt),
            MSG_UNDEFINED % (rdr, 7, "main_cells", "pyyaml", tgt),
            MSG_UNDEFINED % (rdr, 7, "main_cells", "PYYAML_IMPORT_ERROR", tgt),
            MSG_UNDEFINED % (rdr, 8, "target", "gone", tgt),
            MSG_UNDEFINED % (rdr, 9, "t2", "nope", tgt),
            MSG_UNDEFINED % (rdr, 10, "target", "by_getattr", tgt),
            MSG_UNDEFINED % (rdr, 12, "target", "patched", tgt),
        ]))

    def test_9817_a_loader_function_binds_its_module(self) -> None:
        reader = (
            "import importlib.util\n"
            "from pathlib import Path\n"
            "TARGET_PATH = Path(__file__).resolve().parent / 'target.py'\n"
            "def load_by_constant():\n"
            "    spec = importlib.util.spec_from_file_location('t', TARGET_PATH)\n"
            "    return spec\n"
            "def load_by_local():\n"
            "    path = Path(__file__).parent / 'target.py'\n"
            "    spec = importlib.util.spec_from_file_location('t', path)\n"
            "    return spec\n"
            "def load_inline():\n"
            "    return importlib.util.spec_from_file_location('t', Path(__file__).parent / 'target.py')\n"
            "a = load_by_constant()\n"
            "def cell(case):\n"
            "    b = load_by_local()\n"
            "    return a.A, a.gone_a, b.gone_b, c.gone_c\n"
            "c: object = load_inline()\n"
        )
        files = {"scripts/ci/tests/target.py": TARGET, "scripts/ci/tests/reader.py": reader}
        root = scratch_tree(self, "attribute-reads-9817-loader", files)
        tgt = "scripts/ci/tests/target.py"
        rdr = "scripts/ci/tests/reader.py"
        self.assertEqual(sorted(scan_tree(root, sorted(files))), sorted([
            MSG_UNDEFINED % (rdr, 16, "a", "gone_a", tgt),
            MSG_UNDEFINED % (rdr, 16, "b", "gone_b", tgt),
            MSG_UNDEFINED % (rdr, 16, "c", "gone_c", tgt),
        ]))

    def test_9817_resolution_follows_the_import_roots_and_skips_packages_and_stdlib(self) -> None:
        files = {
            "scripts/ci/shared.py": "S = 1\n",
            "scripts/ci/tests/near.py": "N = 1\n",
            "scripts/ci/tests/reader.py": ("import shared, near, json\nimport pkg\n"
                                           "x = shared.S + shared.no_s + near.no_n + json.anything + pkg.anything\n"),
            "scripts/ci/tests/pkg/__init__.py": "",
            "scripts/other/near.py": "OTHER = 1\n",
        }
        root = scratch_tree(self, "attribute-reads-9817-roots", files)
        rdr = "scripts/ci/tests/reader.py"
        self.assertEqual(sorted(scan_tree(root, sorted(files))), sorted([
            MSG_UNDEFINED % (rdr, 3, "shared", "no_s", "scripts/ci/shared.py"),
            MSG_UNDEFINED % (rdr, 3, "near", "no_n", "scripts/ci/tests/near.py"),
        ]))

    def test_9817_an_open_module_is_a_finding_never_a_pass(self) -> None:
        files = {
            "scripts/ci/star.py": "from os.path import *\n",
            "scripts/ci/dyn.py": "def __getattr__(name):\n    return 1\n",
            "scripts/ci/glob.py": "globals()['X'] = 1\n",
            "scripts/ci/reader.py": "import star, dyn, glob\nx = star.join, dyn.X, glob.X\n",
        }
        root = scratch_tree(self, "attribute-reads-9817-open", files)
        rdr = "scripts/ci/reader.py"
        self.assertEqual(sorted(scan_tree(root, sorted(files))), sorted([
            MSG_OPEN % (rdr, 2, "star", "join", "scripts/ci/star.py"),
            MSG_OPEN % (rdr, 2, "dyn", "X", "scripts/ci/dyn.py"),
            MSG_OPEN % (rdr, 2, "glob", "X", "scripts/ci/glob.py"),
        ]))

    def test_9817_unreadable_and_unparsable_files_are_failures(self) -> None:
        files = {"scripts/ci/syntax.py": "def (:\n", "scripts/ci/reader.py": "import syntax\nx = syntax.A\n"}
        root = scratch_tree(self, "attribute-reads-9817-parse", files)
        (root / "scripts/ci/latin1.py").write_bytes(b"# \xe9\n")
        self.assertEqual(sorted(scan_tree(root, sorted(files) + ["scripts/ci/latin1.py"])), sorted([
            MSG_PARSE % ("scripts/ci/syntax.py", "SyntaxError"),
            MSG_READ % ("scripts/ci/latin1.py", "UnicodeDecodeError"),
        ]))

    def test_9817_an_empty_scope_is_a_failure(self) -> None:
        self.assertEqual(scan_tree(REPO, []), [MSG_EMPTY])


class RepositoryReadsResolve(unittest.TestCase):
    """The repository tree itself."""

    def test_9817_scope_and_bindings_cover_the_modules_the_pr_changed(self) -> None:
        files = ratchet.tracked_python_files(REPO)
        by_dir = ratchet.module_names_by_dir(files)
        closed = "scripts/ci/tests/test_ci_tainted_job_boundary_closed.py"
        self.assertIn(closed, files)
        tree = ast.parse((REPO / closed).read_text(encoding="utf-8"))
        self.assertEqual(module_bindings(tree, closed, by_dir).get("main_cells"),
                         "scripts/ci/tests/test_ci_tainted_job_boundary.py")
        main = "scripts/ci/tests/test_ci_tainted_job_boundary.py"
        tree = ast.parse((REPO / main).read_text(encoding="utf-8"))
        self.assertEqual(loader_functions(tree, main, by_dir).get("_load_workflow_text"),
                         "scripts/ci/tests/workflow_text.py")

    def test_9817_every_read_of_a_repository_module_names_a_defined_name(self) -> None:
        start = time.monotonic()
        problems = scan_tree(REPO, ratchet.tracked_python_files(REPO))
        elapsed = time.monotonic() - start
        self.assertEqual(problems, [], "\n".join(problems))
        self.assertLess(elapsed, SCAN_CEILING_SECS)


if __name__ == "__main__":
    unittest.main()
