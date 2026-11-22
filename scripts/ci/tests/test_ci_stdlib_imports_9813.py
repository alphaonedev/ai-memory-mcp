#!/usr/bin/env python3
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""Issue #9813: every tracked Python file under scripts/ loads on a fleet node with the standard library alone.

Class: a CI guard module that cannot load on a fleet node (here: ``import yaml`` where PyYAML is not installed
for the Homebrew ``python3.12``), so its red cannot be told from a missing import.

Scope: every file ``git ls-files -- scripts`` lists that ends in ``.py`` or whose first line is a ``#!`` line naming
python (tests, fixtures and stub programs included). A file that cannot be read, decoded or parsed is a failure
with its exact reason, never skipped; an empty scope or a failed ``git ls-files`` is a failure.

Invariant, for every file in scope, at any depth (a function, a ``try`` / ``except ImportError``, a class body):

1. every ``import a.b as c`` / ``from a import b`` names a top-level module that is in
   ``sys.stdlib_module_names`` or resolves to the repository: a tracked module or package directory in one of the
   file's import roots (its own directory, each directory above it up to ``scripts``, and ``scripts/ci``, the root
   the guard tests insert). A relative import is the repository itself.
2. a call to ``__import__``, ``import_module``, ``find_spec`` or ``run_module`` (any receiver, or a name bound by
   ``from importlib import import_module as x``) counts as an import of its first argument when that argument is a
   string literal (or a conditional of two literals); any other argument is the finding ``<non-literal NAME()>``.
3. a call to ``exec`` or ``eval`` with a string literal is scanned as source by the same rules (its findings carry
   the call's line); text that does not parse is ``<unparsable NAME() text>``; any other argument is
   ``<non-literal NAME()>``.
4. no tracked module or package directory under ``scripts`` has a standard-library name or a name in
   ``THIRD_PARTY_NAMES`` (a planted ``yaml.py`` would make ``import yaml`` resolve to the repository).

Every finding names ``file:line`` and the module or the marker. ``THIRD_PARTY_ALLOW`` rows name a file, a module or
marker, the exact number of findings it covers, a reason and an issue; a row that matches no finding, or a
different number of findings, is a failure. ``SHADOW_ALLOW`` rows work the same way for rule 4.

Forms the AST cannot decide, and so not covered by this check: a callee reached through ``getattr``,
``globals()``, ``vars()`` or ``sys.modules``; ``importlib.util.spec_from_file_location`` / a loader on a path (it
loads a file, not a module name); ``compile()`` output passed on through a variable (rule 3 reports the call as
non-literal, not what the text imports); text run in a child process (``python -c``, ``subprocess``); ``pkgutil``,
``zipimport``, ``.pth`` files, ``PYTHONPATH`` and ``sys.path`` entries other than the import roots above;
third-party names missing from ``THIRD_PARTY_NAMES`` (rule 4); tracked files outside ``scripts`` and files that are
neither ``.py`` nor have a python ``#!`` line.

Run: /opt/homebrew/bin/python3.12 -I scripts/ci/tests/test_ci_stdlib_imports_9813.py
"""

from __future__ import annotations

import ast
import re
import shutil
import subprocess
import sys
import time
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]

# --- ratchet implementation ---
SCRIPTS_DIR = "scripts"
EXTRA_IMPORT_ROOTS = ("scripts/ci",)  # the directory the guard tests put on sys.path
PY_SUFFIX = ".py"
INIT_STEM = "__init__"
PYTHON_SHEBANG_RE = re.compile(rb"\A#![^\n]*python")
SHEBANG_READ_BYTES = 256
GIT_TIMEOUT_SECS = 60
SCAN_CEILING_SECS = 30.0  # the whole tree scan, parse included
BIG_SOURCE_LINES = 100_000
BIG_SOURCE_CEILING_SECS = 20.0

IMPORT_CALLS = frozenset({"__import__", "import_module", "find_spec", "run_module"})
CODE_CALLS = frozenset({"exec", "eval"})
ALIAS_SOURCES = frozenset({"importlib", "importlib.util", "runpy", "builtins"})
NONLITERAL = "<non-literal %s()>"
UNPARSABLE = "<unparsable %s() text>"

# Import names of third-party distributions a fleet script could reach for. Rule 4 refuses a repository module
# or package directory of any of these names. Hand-written; not derived from the running interpreter.
THIRD_PARTY_NAMES = frozenset({
    "attr", "attrs", "boto3", "botocore", "bs4", "certifi", "chardet", "charset_normalizer", "click", "cryptography",
    "dateutil", "docker", "git", "github", "hypothesis", "idna", "jinja2", "jsonschema", "lxml", "markdown", "mypy",
    "nacl", "numpy", "packaging",
    "pip", "pkg_resources", "psycopg", "psycopg2", "pydantic", "pytest", "requests", "rich", "ruamel", "setuptools",
    "six", "toml", "typer", "urllib3", "yaml",
})

MSG_IMPORT = "%s:%d: import of %r is neither standard library nor a repository module"
MSG_MARKER = "%s:%d: %s is not decidable as a standard-library or repository import"
MSG_SHADOW = "%s: repository module %r shadows a standard-library or third-party name"
MSG_READ = "%s: cannot read as UTF-8: %s"
MSG_PARSE = "%s: cannot parse: %s"
MSG_STALE = "allow row %r matches no finding (stale row)"
MSG_COUNT = "allow row %r covers %d finding(s), found %d at line(s) %s"
MSG_SHADOW_STALE = "shadow allow row %r matches no repository module (stale row)"
MSG_GIT = "cannot list the tracked files: %s"
MSG_EMPTY = "no tracked Python file under %s: the scan would pass on nothing"

# (file relative to the repository, module or marker) -> (findings covered, reason, issue).
THIRD_PARTY_ALLOW: dict[tuple[str, str], tuple[int, str, int]] = {
    ("scripts/test/test_workflow_edited_cancel_8332.py", "yaml"): (
        4, "the two PyYAML differential-oracle cells (find_spec skip guard and the import inside each cell); the "
           "cells skip where PyYAML is absent and compare the scanner with PyYAML where it is present", 8332),
    ("scripts/ci/tests/test_ci_tainted_job_boundary.py", "yaml"): (
        2, "oracle two: the PyYAML full-document compare (find_spec and the import inside the cell); it fails loudly "
           "on build-script-vetting and skips with its reason elsewhere", 9813),
    ("scripts/ci/prune_runner_tmp.py", NONLITERAL % "exec"): (
        1, "runs the shared module's source, read from its repository file", 9813),
    ("scripts/ci/tests/test_ci_base_selector_8240.py", NONLITERAL % "exec"): (
        1, "runs the materialise step snippet read from the repository's ci.yml", 9813),
    ("scripts/ci/tests/test_ci_base_selector_8240.py", NONLITERAL % "import_module"): (
        1, "imports the module names of the test's own spec table (repository modules)", 9813),
    ("scripts/ci/tests/test_ci_tainted_job_boundary_prescan_uses.py", NONLITERAL % "exec"): (
        1, "runs a mutated copy of the repository's taint_boundary.py source", 9813),
    ("scripts/ci/tests/test_evidence_generator_5040_5042.py", NONLITERAL % "import_module"): (
        1, "imports scripts/evidence modules by name", 9813),
    ("scripts/ci/tests/test_evidence_generator_r7_7393.py", NONLITERAL % "exec"): (
        1, "runs the test's own spelling-corpus rows", 9813),
    ("scripts/ci/tests/test_impact_cargo_skip_8328.py", NONLITERAL % "exec"): (
        1, "runs the repository's sed shim source", 9813),
    ("scripts/claude-md-rule-compare.py", NONLITERAL % "exec"): (
        1, "runs a trusted-base module compiled from its repository file", 9813),
    ("scripts/ci/tests/tmp_runtime_guard_7393.py", "run_cert"): (
        1, "scripts/evidence/run_cert.py, reached through the sys.path insert of scripts/evidence just above it", 9813),
    ("scripts/recapture-cert-3607-posture.py", "cryptography"): (
        2, "operator-run fixture writer; the import sits inside write_fixtures(), so the module loads without it and "
           "no CI job runs it", 3607),
    ("scripts/render-a2a-integration.py", "markdown"): (
        1, "operator-run docs renderer whose docstring states it requires Python-Markdown; no CI job runs it", 3636),
}

# Repository module path (a .py file, or a package directory with a trailing "/") -> (reason, issue).
SHADOW_ALLOW: dict[str, tuple[str, int]] = {
    "scripts/ci/impact/select.py": (
        "imported only as the package member impact.select; no file in scripts/ci/impact imports the top-level "
        "name select, and scripts/ci/impact is not an import root of any other file", 9813),
}


def is_python_file(repo: Path, rel: str) -> bool:
    """A ``.py`` file, or a file whose first line is a ``#!`` line naming python."""
    if rel.endswith(PY_SUFFIX):
        return True
    try:
        with open(repo / rel, "rb") as handle:
            head = handle.read(SHEBANG_READ_BYTES)
    except OSError:
        return False
    return bool(PYTHON_SHEBANG_RE.match(head))


def tracked_python_files(repo: Path) -> list[str]:
    """Every tracked Python file under ``scripts`` (``git ls-files``). Raises RuntimeError when git cannot list."""
    git = shutil.which("git")
    if git is None:
        raise RuntimeError(MSG_GIT % "git not found")
    try:
        proc = subprocess.run([git, "-C", str(repo), "ls-files", "-z", "--", SCRIPTS_DIR], capture_output=True,
                              timeout=GIT_TIMEOUT_SECS, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise RuntimeError(MSG_GIT % type(exc).__name__) from exc
    if proc.returncode != 0:
        raise RuntimeError(MSG_GIT % ("git ls-files rc %d" % proc.returncode))
    names = [name for name in proc.stdout.decode("utf-8", "surrogateescape").split("\0") if name]
    return sorted(rel for rel in names if is_python_file(repo, rel))


def module_names_by_dir(files: list[str]) -> dict[str, dict[str, str]]:
    """``{directory: {top-level name: module path}}`` for every ``.py`` module and package directory in ``files``."""
    by_dir: dict[str, dict[str, str]] = {}
    for rel in files:
        if not rel.endswith(PY_SUFFIX):
            continue
        parts = rel.split("/")
        parent = "/".join(parts[:-1])
        stem = parts[-1][: -len(PY_SUFFIX)]
        if stem != INIT_STEM:
            by_dir.setdefault(parent, {}).setdefault(stem, rel)
        for depth in range(1, len(parts) - 1):
            above = "/".join(parts[:depth])
            by_dir.setdefault(above, {}).setdefault(parts[depth], "/".join(parts[: depth + 1]) + "/")
    return by_dir


def import_roots(rel: str) -> list[str]:
    """The directories a file's top-level imports resolve in: its own, each one above it up to scripts, scripts/ci."""
    parts = rel.split("/")[:-1]
    roots = ["/".join(parts[:depth]) for depth in range(len(parts), 0, -1)]
    roots = [root for root in roots if root == SCRIPTS_DIR or root.startswith(SCRIPTS_DIR + "/")]
    return roots + [root for root in EXTRA_IMPORT_ROOTS if root not in roots]


def local_names(rel: str, by_dir: dict[str, dict[str, str]]) -> frozenset[str]:
    """Top-level names that resolve to the repository for the file ``rel``."""
    names: set[str] = set()
    for root in import_roots(rel):
        names.update(by_dir.get(root, {}))
    return frozenset(names)


def _callee(func: ast.expr, aliases: dict[str, str]) -> str | None:
    if isinstance(func, ast.Name):
        return aliases.get(func.id, func.id)
    if isinstance(func, ast.Attribute):
        return func.attr
    return None


def _literal_strings(node: ast.expr | None) -> list[str] | None:
    """The string values a literal (or a conditional of literals) can take; None for anything else."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return [node.value]
    if isinstance(node, ast.IfExp):
        body, orelse = _literal_strings(node.body), _literal_strings(node.orelse)
        if body is not None and orelse is not None:
            return body + orelse
    return None


def _aliases(tree: ast.AST) -> dict[str, str]:
    """Names bound by ``from importlib import import_module as x`` (and the like) -> the function they name."""
    found: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.level == 0 and node.module in ALIAS_SOURCES:
            for alias in node.names:
                if alias.name in IMPORT_CALLS | CODE_CALLS:
                    found[alias.asname or alias.name] = alias.name
    return found


def _findings(tree: ast.AST, local: frozenset[str], at_line: int | None) -> list[tuple[int, str]]:
    aliases = _aliases(tree)
    found: list[tuple[int, str]] = []

    def check(line: int, module: str) -> None:
        if not module or module.startswith("."):
            return  # a relative import is the repository itself
        top = module.split(".")[0]
        if top not in sys.stdlib_module_names and top not in local:
            found.append((at_line or line, top))

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                check(node.lineno, alias.name)
        elif isinstance(node, ast.ImportFrom):
            if node.level == 0 and node.module:
                check(node.lineno, node.module)
        elif isinstance(node, ast.Call):
            name = _callee(node.func, aliases)
            if name not in IMPORT_CALLS and name not in CODE_CALLS:
                continue
            values = _literal_strings(node.args[0] if node.args else None)
            if values is None:
                found.append((at_line or node.lineno, NONLITERAL % name))
            elif name in IMPORT_CALLS:
                for value in values:
                    check(node.lineno, value)
            else:
                for value in values:
                    try:
                        inner = ast.parse(value)
                    except (SyntaxError, ValueError):
                        found.append((at_line or node.lineno, UNPARSABLE % name))
                        continue
                    found.extend(_findings(inner, local, at_line or node.lineno))
    return found


def foreign_imports(source: str, filename: str, local: frozenset[str]) -> list[tuple[int, str]]:
    """``(line, module or marker)`` of every finding of rules 1-3 in ``source``.

    Raises SyntaxError / ValueError for source that does not parse: the caller turns that into a failure.
    """
    return sorted(_findings(ast.parse(source, filename=filename), local, None))


def shadow_findings(by_dir: dict[str, dict[str, str]]) -> dict[str, str]:
    """Rule 4: ``{module path: name}`` for every repository module or package directory with a refused name."""
    shadows: dict[str, str] = {}
    for directory, names in by_dir.items():
        if directory != SCRIPTS_DIR and not directory.startswith(SCRIPTS_DIR + "/"):
            continue
        for name, path in names.items():
            if name in sys.stdlib_module_names or name in THIRD_PARTY_NAMES:
                shadows[path] = name
    return shadows


def scan_tree(repo: Path, files: list[str], allow: dict[tuple[str, str], tuple[int, str, int]],
              shadow_allow: dict[str, tuple[str, int]]) -> list[str]:
    """One problem line per finding of rules 1-4, unreadable or unparsable file, and stale or miscounted row."""
    problems: list[str] = []
    if not files:
        return [MSG_EMPTY % SCRIPTS_DIR]
    by_dir = module_names_by_dir(files)
    covered: dict[tuple[str, str], list[int]] = {}
    for rel in files:
        try:
            source = (repo / rel).read_bytes().decode("utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            problems.append(MSG_READ % (rel, type(exc).__name__))
            continue
        try:
            findings = foreign_imports(source, rel, local_names(rel, by_dir))
        except (SyntaxError, ValueError) as exc:
            problems.append(MSG_PARSE % (rel, type(exc).__name__))
            continue
        for line, top in findings:
            if (rel, top) in allow:
                covered.setdefault((rel, top), []).append(line)
            elif top.startswith("<"):
                problems.append(MSG_MARKER % (rel, line, top))
            else:
                problems.append(MSG_IMPORT % (rel, line, top))
    for key, (count, _reason, _issue) in sorted(allow.items()):
        lines = covered.get(key)
        if not lines:
            problems.append(MSG_STALE % (key,))
        elif len(lines) != count:
            problems.append(MSG_COUNT % (key, count, len(lines), ",".join(map(str, lines))))
    shadows = shadow_findings(by_dir)
    for path, name in sorted(shadows.items()):
        if path not in shadow_allow:
            problems.append(MSG_SHADOW % (path, name))
    for path in sorted(set(shadow_allow) - set(shadows)):
        problems.append(MSG_SHADOW_STALE % (path,))
    return problems
# --- end ratchet implementation ---


LOCAL = frozenset({"impact", "workflow_text"})


def found(source: str) -> list[tuple[int, str]]:
    return foreign_imports(source, "synthetic.py", LOCAL)


def scratch_tree(test: unittest.TestCase, name: str, files: dict[str, bytes]) -> Path:
    """A scratch repository under .local-runs holding ``files``; removed when the test ends."""
    root = REPO / ".local-runs" / name
    if root.exists():
        shutil.rmtree(root)
    for rel, data in files.items():
        (root / rel).parent.mkdir(parents=True, exist_ok=True)
        (root / rel).write_bytes(data)
    test.addCleanup(shutil.rmtree, root, True)
    return root


class ForeignImportDetector(unittest.TestCase):
    """The detector itself, on synthetic sources (each form a third-party import can take)."""

    def test_9813_each_third_party_form_is_found_with_its_line(self) -> None:
        forms = {
            "import": ("import yaml\n", [(1, "yaml")]),
            "import_comment": ("import yaml  # required\n", [(1, "yaml")]),
            "import_as": ("import yaml as pyyaml\n", [(1, "yaml")]),
            "dotted": ("import yaml.constructor\n", [(1, "yaml")]),
            "from": ("from yaml import safe_load\n", [(1, "yaml")]),
            "from_dotted": ("from yaml.nodes import Node\n", [(1, "yaml")]),
            "comma_list": ("import os, yaml\n", [(1, "yaml")]),
            "try_except": ("try:\n    import yaml\nexcept ImportError:\n    yaml = None\n", [(2, "yaml")]),
            "in_function": ("def f():\n    import yaml\n", [(2, "yaml")]),
            "in_class": ("class C:\n    import yaml\n", [(2, "yaml")]),
            "two": ("import yaml\nimport requests\n", [(1, "yaml"), (2, "requests")]),
        }
        for name, (source, expected) in forms.items():
            with self.subTest(form=name):
                self.assertEqual(found(source), expected)

    def test_9813_each_dynamic_import_form_is_found_with_its_line(self) -> None:
        """L3 / F2: the call forms the first ratchet missed, one row per form."""
        forms = {
            "dunder_import": ("x = __import__('yaml')\n", [(1, "yaml")]),
            "dunder_import_dotted": ("x = __import__('yaml.nodes')\n", [(1, "yaml")]),
            "builtins_dunder_import": ("import builtins\nx = builtins.__import__('yaml')\n", [(2, "yaml")]),
            "import_module": ("import importlib\nx = importlib.import_module('yaml')\n", [(2, "yaml")]),
            "import_module_alias": ("from importlib import import_module as im\nx = im('yaml')\n", [(2, "yaml")]),
            "import_module_bare": ("from importlib import import_module\nx = import_module('yaml')\n",
                                   [(2, "yaml")]),
            "find_spec": ("import importlib.util\nx = importlib.util.find_spec('yaml')\n", [(2, "yaml")]),
            "find_spec_alias": ("from importlib.util import find_spec as fs\nx = fs('yaml')\n", [(2, "yaml")]),
            "run_module": ("import runpy\nrunpy.run_module('yaml')\n", [(2, "yaml")]),
            "conditional_literal": ("x = __import__('yaml' if a else 'os')\n", [(1, "yaml")]),
            "exec_literal": ("exec('import yaml')\n", [(1, "yaml")]),
            "exec_nested": ("def f():\n    exec(\"exec('import yaml')\")\n", [(2, "yaml")]),
            "eval_literal": ("x = eval(\"__import__('yaml')\")\n", [(1, "yaml")]),
            "exec_unparsable": ("exec('import (')\n", [(1, UNPARSABLE % "exec")]),
            "import_module_variable": ("import importlib\nx = importlib.import_module(name)\n",
                                       [(2, NONLITERAL % "import_module")]),
            "dunder_import_variable": ("x = __import__(name)\n", [(1, NONLITERAL % "__import__")]),
            "find_spec_variable": ("import importlib.util\nx = importlib.util.find_spec(n)\n",
                                   [(2, NONLITERAL % "find_spec")]),
            "exec_variable": ("exec(code)\n", [(1, NONLITERAL % "exec")]),
            "eval_variable": ("x = eval(text)\n", [(1, NONLITERAL % "eval")]),
            "exec_no_argument": ("exec()\n", [(1, NONLITERAL % "exec")]),
        }
        for name, (source, expected) in forms.items():
            with self.subTest(form=name):
                self.assertEqual(found(source), expected)

    def test_9813_stdlib_relative_and_repository_imports_are_allowed(self) -> None:
        allowed = {
            "stdlib": "import os\nimport importlib.util\nfrom pathlib import Path\n",
            "future": "from __future__ import annotations\n",
            "relative": "from . import sibling\nfrom .sibling import x\n",
            "repo_module": "import workflow_text\nfrom impact import gate\n",
            "repo_dotted": "import impact.gate\n",
            "dynamic_stdlib": "import importlib\nx = importlib.import_module('json')\ny = __import__('os')\n",
            "dynamic_relative": "import importlib\nx = importlib.import_module('.gate', 'impact')\n",
            "dynamic_repository": "x = __import__('workflow_text')\n",
            "conditional_stdlib": "x = __import__('posix' if a else 'nt')\n",
            "exec_stdlib": "exec('import json')\nx = eval('1 + 1')\n",
        }
        for name, source in allowed.items():
            with self.subTest(form=name):
                self.assertEqual(found(source), [])

    def test_9813_unparsable_source_raises_never_passes(self) -> None:
        with self.assertRaises(SyntaxError):
            found("import yaml (\n")

    def test_9813_import_roots_are_the_file_directory_its_parents_and_scripts_ci(self) -> None:
        self.assertEqual(import_roots("scripts/test/fixtures/x/a.py"),
                         ["scripts/test/fixtures/x", "scripts/test/fixtures", "scripts/test", "scripts", "scripts/ci"])
        self.assertEqual(import_roots("scripts/ci/tests/a.py"), ["scripts/ci/tests", "scripts/ci", "scripts"])

    def test_9813_a_100k_line_source_is_scanned_inside_the_ceiling(self) -> None:
        source = "x = 1\n" * BIG_SOURCE_LINES + "import yaml\nexec('import requests')\n"
        start = time.monotonic()
        result = found(source)
        elapsed = time.monotonic() - start
        self.assertEqual(result, [(BIG_SOURCE_LINES + 1, "yaml"), (BIG_SOURCE_LINES + 2, "requests")])
        self.assertLess(elapsed, BIG_SOURCE_CEILING_SECS)


class ScanTree(unittest.TestCase):
    """``scan_tree`` on scratch repositories: scope, shadows, rows."""

    def test_9813_scan_names_file_line_module_and_refuses_unreadable_files(self) -> None:
        files = {
            "scripts/ci/ok.py": b"import os\n",
            "scripts/ci/bad.py": b"import os\nimport yaml\n",
            "scripts/ci/latin1.py": b"# \xe9\nimport os\n",
            "scripts/ci/syntax.py": b"def (:\n",
            "scripts/ci/dyn.py": b"import importlib\nm = importlib.import_module(name)\n",
        }
        root = scratch_tree(self, "stdlib-imports-9813-scan", files)
        self.assertEqual(scan_tree(root, sorted(files), {}, {}), [
            MSG_IMPORT % ("scripts/ci/bad.py", 2, "yaml"),
            MSG_MARKER % ("scripts/ci/dyn.py", 2, NONLITERAL % "import_module"),
            MSG_READ % ("scripts/ci/latin1.py", "UnicodeDecodeError"),
            MSG_PARSE % ("scripts/ci/syntax.py", "SyntaxError"),
        ])

    def test_9813_a_file_outside_scripts_ci_is_scanned(self) -> None:
        files = {"scripts/test/t.py": b"import yaml\n", "scripts/evidence/e.py": b"x = __import__('requests')\n"}
        root = scratch_tree(self, "stdlib-imports-9813-scope", files)
        self.assertEqual(scan_tree(root, sorted(files), {}, {}), [
            MSG_IMPORT % ("scripts/evidence/e.py", 1, "requests"),
            MSG_IMPORT % ("scripts/test/t.py", 1, "yaml"),
        ])

    def test_9813_a_planted_yaml_module_is_refused_and_does_not_whitelist_other_trees(self) -> None:
        """L3 / F2: a yaml.py anywhere under scripts used to make every ``import yaml`` pass."""
        files = {
            "scripts/zz/yaml.py": b"x = 1\n",
            "scripts/zz/near.py": b"import yaml\n",
            "scripts/ci/far.py": b"import yaml\n",
            "scripts/qq/requests/__init__.py": b"",
        }
        root = scratch_tree(self, "stdlib-imports-9813-plant", files)
        self.assertEqual(scan_tree(root, sorted(files), {}, {}), [
            MSG_IMPORT % ("scripts/ci/far.py", 1, "yaml"),
            MSG_SHADOW % ("scripts/qq/requests/", "requests"),
            MSG_SHADOW % ("scripts/zz/yaml.py", "yaml"),
        ])

    def test_9813_a_stdlib_named_module_is_refused_unless_allowed(self) -> None:
        files = {"scripts/ci/sub/select.py": b"x = 1\n", "scripts/ci/sub/json/__init__.py": b""}
        root = scratch_tree(self, "stdlib-imports-9813-stdlib-shadow", files)
        self.assertEqual(scan_tree(root, sorted(files), {}, {}), [
            MSG_SHADOW % ("scripts/ci/sub/json/", "json"),
            MSG_SHADOW % ("scripts/ci/sub/select.py", "select"),
        ])
        allow = {"scripts/ci/sub/select.py": ("r", 1), "scripts/ci/sub/json/": ("r", 1), "scripts/ci/gone.py": ("r", 1)}
        self.assertEqual(scan_tree(root, sorted(files), {}, allow), [MSG_SHADOW_STALE % ("scripts/ci/gone.py",)])

    def test_9813_an_allow_row_covers_its_exact_count_and_a_stale_row_fails(self) -> None:
        files = {"scripts/ci/bad.py": b"import yaml\nimport yaml.nodes\n"}
        root = scratch_tree(self, "stdlib-imports-9813-allow", files)
        key = ("scripts/ci/bad.py", "yaml")
        self.assertEqual(scan_tree(root, sorted(files), {key: (2, "reason", 1)}, {}), [])
        self.assertEqual(scan_tree(root, sorted(files), {key: (1, "reason", 1)}, {}), [MSG_COUNT % (key, 1, 2, "1,2")])
        ghost = ("scripts/ci/bad.py", "ghost")
        self.assertEqual(scan_tree(root, sorted(files), {key: (2, "r", 1), ghost: (1, "r", 1)}, {}),
                         [MSG_STALE % (ghost,)])

    def test_9813_an_empty_scope_is_a_failure(self) -> None:
        self.assertEqual(scan_tree(REPO, [], {}, {}), [MSG_EMPTY % SCRIPTS_DIR])


class ScriptsLoadWithStdlibOnly(unittest.TestCase):
    """The repository tree itself."""

    def test_9813_allow_rows_carry_a_count_a_reason_and_an_issue(self) -> None:
        for key, (count, reason, issue) in THIRD_PARTY_ALLOW.items():
            with self.subTest(row=key):
                self.assertGreater(count, 0)
                self.assertTrue(reason.strip())
                self.assertGreater(issue, 0)
        for key, (reason, issue) in SHADOW_ALLOW.items():
            with self.subTest(row=key):
                self.assertTrue(reason.strip())
                self.assertGreater(issue, 0)

    def test_9813_scope_is_every_tracked_python_file_under_scripts(self) -> None:
        files = tracked_python_files(REPO)
        for rel in ("scripts/test/test_workflow_edited_cancel_8332.py", "scripts/claude-md-rule-compare.py",
                    "scripts/ci/tests/test_ci_stdlib_imports_9813.py",
                    "scripts/test/fixtures/pr_retarget_check_8332/stub_bin/gh"):
            with self.subTest(rel=rel):
                self.assertIn(rel, files)
        self.assertTrue(all(rel.startswith(SCRIPTS_DIR + "/") for rel in files))

    def test_9813_every_tracked_python_file_imports_only_stdlib_or_the_repository(self) -> None:
        start = time.monotonic()
        problems = scan_tree(REPO, tracked_python_files(REPO), THIRD_PARTY_ALLOW, SHADOW_ALLOW)
        elapsed = time.monotonic() - start
        self.assertEqual(problems, [], "\n".join(problems))
        self.assertLess(elapsed, SCAN_CEILING_SECS)


if __name__ == "__main__":
    unittest.main()
