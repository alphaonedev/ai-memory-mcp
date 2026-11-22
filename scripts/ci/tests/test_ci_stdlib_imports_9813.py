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
SCRIPTS_ROOT = REPO / "scripts"
SCAN_ROOT = SCRIPTS_ROOT / "ci"
PY_SUFFIX = ".py"
SKIP_DIR_NAMES = frozenset({"__pycache__"})
SCAN_CEILING_SECS = 30.0  # the whole tree scan, parse included
BIG_SOURCE_LINES = 100_000
BIG_SOURCE_CEILING_SECS = 20.0

# (file relative to the repository, top-level module) -> (reason, issue number). Empty by rule (#9813).
THIRD_PARTY_ALLOW: dict[tuple[str, str], tuple[str, int]] = {}


def repo_local_modules() -> frozenset[str]:
    """Top-level names the repository itself provides under scripts: every module stem and package directory."""
    names: set[str] = set()
    for path in SCRIPTS_ROOT.rglob("*" + PY_SUFFIX):
        if SKIP_DIR_NAMES & set(path.parts):
            continue
        names.add(path.stem)
        names.update(path.relative_to(SCRIPTS_ROOT).parts[:-1])
    return frozenset(names)


def foreign_imports(source: str, filename: str, local: frozenset[str]) -> list[tuple[int, str]]:
    """``(line, top-level module)`` of every import in ``source`` that is neither stdlib nor repository-local.

    Raises SyntaxError / ValueError for source that does not parse: the caller turns that into a failure.
    """
    tree = ast.parse(source, filename=filename)
    found: list[tuple[int, str]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            tops = [alias.name.split(".")[0] for alias in node.names]
        elif isinstance(node, ast.ImportFrom):
            if node.level > 0 or not node.module:
                continue  # a relative import is the repository itself
            tops = [node.module.split(".")[0]]
        else:
            continue
        for top in tops:
            if top not in sys.stdlib_module_names and top not in local:
                found.append((node.lineno, top))
    return sorted(found)


def scan_tree(root: Path, local: frozenset[str], allow: dict[tuple[str, str], tuple[str, int]]) -> list[str]:
    """One problem line per foreign import, unreadable file or unparsable file under ``root``."""
    problems: list[str] = []
    used: set[tuple[str, str]] = set()
    for path in sorted(root.rglob("*" + PY_SUFFIX)):
        if SKIP_DIR_NAMES & set(path.parts):
            continue
        rel = path.relative_to(REPO).as_posix() if REPO in path.parents else path.as_posix()
        try:
            source = path.read_bytes().decode("utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            problems.append("%s: cannot read as UTF-8: %r" % (rel, exc))
            continue
        try:
            imports = foreign_imports(source, rel, local)
        except (SyntaxError, ValueError) as exc:
            problems.append("%s: cannot parse: %r" % (rel, exc))
            continue
        for line, top in imports:
            if (rel, top) in allow:
                used.add((rel, top))
                continue
            problems.append("%s:%d: import of %r is neither standard library nor a repository module" % (rel, line, top))
    for key in sorted(set(allow) - used):
        problems.append("allow row %r matches no import (stale row)" % (key,))
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
