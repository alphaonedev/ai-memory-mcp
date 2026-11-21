#!/usr/bin/env python3
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""Issue #9813: every module under scripts/ci loads on a fleet node with the standard library alone.

Class: a CI guard module that cannot load on a fleet node (here: ``import yaml`` where PyYAML is not installed
for the Homebrew ``python3.12``), so its red cannot be told from a missing import.

Invariant, for every ``.py`` file under ``scripts/ci`` (tests included): every import, at any depth (a function, a
``try`` / ``except ImportError``, a class body, ``import a.b as c``, ``from a import b``), names a top-level module
that is in ``sys.stdlib_module_names`` or is a module or package of the repository itself (a ``.py`` file or a
package directory under ``scripts``). A relative import is the repository itself. Anything else is a failure
that names ``file:line`` and the module; a file that cannot be read, decoded or parsed is a failure with its exact
reason, never skipped. The allow table ``THIRD_PARTY_ALLOW`` is empty: a row is allowed only with a reason and an
issue number, and a row that matches no import is a failure (a stale row).

Run: /opt/homebrew/bin/python3.12 -I scripts/ci/tests/test_ci_stdlib_imports_9813.py
"""

from __future__ import annotations

import ast
import sys
import time
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
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


class ForeignImportDetector(unittest.TestCase):
    """The detector itself, on synthetic sources (each form a third-party import can take)."""

    LOCAL = frozenset({"impact", "workflow_text"})

    def found(self, source: str) -> list[tuple[int, str]]:
        return foreign_imports(source, "synthetic.py", self.LOCAL)

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
                self.assertEqual(self.found(source), expected)

    def test_9813_stdlib_relative_and_repository_imports_are_allowed(self) -> None:
        allowed = {
            "stdlib": "import os\nimport importlib.util\nfrom pathlib import Path\n",
            "future": "from __future__ import annotations\n",
            "relative": "from . import sibling\nfrom .sibling import x\n",
            "repo_module": "import workflow_text\nfrom impact import gate\n",
            "repo_dotted": "import impact.gate\n",
        }
        for name, source in allowed.items():
            with self.subTest(form=name):
                self.assertEqual(self.found(source), [])

    def test_9813_unparsable_source_raises_never_passes(self) -> None:
        with self.assertRaises(SyntaxError):
            self.found("import yaml (\n")

    def test_9813_scan_names_file_line_module_and_refuses_unreadable_files(self) -> None:
        scratch = REPO / ".local-runs" / "stdlib-imports-9813"
        scratch.mkdir(parents=True, exist_ok=True)
        try:
            (scratch / "ok.py").write_text("import os\n", encoding="utf-8")
            (scratch / "bad.py").write_text("import os\nimport yaml\n", encoding="utf-8")
            (scratch / "latin1.py").write_bytes(b"# \xe9\nimport os\n")
            (scratch / "syntax.py").write_text("def (:\n", encoding="utf-8")
            problems = scan_tree(scratch, self.LOCAL, {})
            rel = scratch.relative_to(REPO).as_posix()
            self.assertEqual(len(problems), 3, problems)
            self.assertIn("%s/bad.py:2: import of 'yaml' is neither standard library nor a repository module" % rel,
                          problems)
            self.assertTrue(any(p.startswith("%s/latin1.py: cannot read as UTF-8" % rel) for p in problems), problems)
            self.assertTrue(any(p.startswith("%s/syntax.py: cannot parse" % rel) for p in problems), problems)
        finally:
            for item in scratch.iterdir():
                item.unlink()
            scratch.rmdir()

    def test_9813_an_allow_row_passes_one_import_and_a_stale_row_fails(self) -> None:
        scratch = REPO / ".local-runs" / "stdlib-imports-9813-allow"
        scratch.mkdir(parents=True, exist_ok=True)
        try:
            (scratch / "bad.py").write_text("import yaml\n", encoding="utf-8")
            rel = scratch.relative_to(REPO).as_posix() + "/bad.py"
            self.assertEqual(scan_tree(scratch, self.LOCAL, {(rel, "yaml"): ("reason", 1)}), [])
            stale = scan_tree(scratch, self.LOCAL, {(rel, "yaml"): ("reason", 1), (rel, "ghost"): ("reason", 1)})
            self.assertEqual(stale, ["allow row %r matches no import (stale row)" % ((rel, "ghost"),)])
        finally:
            for item in scratch.iterdir():
                item.unlink()
            scratch.rmdir()

    def test_9813_a_100k_line_source_is_scanned_inside_the_ceiling(self) -> None:
        source = "x = 1\n" * BIG_SOURCE_LINES + "import yaml\n"
        start = time.monotonic()
        found = self.found(source)
        elapsed = time.monotonic() - start
        self.assertEqual(found, [(BIG_SOURCE_LINES + 1, "yaml")])
        self.assertLess(elapsed, BIG_SOURCE_CEILING_SECS)


class ScriptsCiLoadWithStdlibOnly(unittest.TestCase):
    """The repository tree itself."""

    def test_9813_allow_table_rows_carry_a_reason_and_an_issue(self) -> None:
        for key, (reason, issue) in THIRD_PARTY_ALLOW.items():
            with self.subTest(row=key):
                self.assertTrue(reason.strip())
                self.assertIsInstance(issue, int)
                self.assertGreater(issue, 0)

    def test_9813_allow_table_is_empty(self) -> None:
        self.assertEqual(THIRD_PARTY_ALLOW, {})

    def test_9813_scan_root_holds_python_files(self) -> None:
        count = sum(1 for _ in SCAN_ROOT.rglob("*" + PY_SUFFIX))
        self.assertGreater(count, 0, "no .py file under %s: the scan would pass on nothing" % SCAN_ROOT)

    def test_9813_every_module_under_scripts_ci_imports_only_stdlib_or_the_repository(self) -> None:
        start = time.monotonic()
        problems = scan_tree(SCAN_ROOT, repo_local_modules(), THIRD_PARTY_ALLOW)
        elapsed = time.monotonic() - start
        self.assertEqual(problems, [], "\n".join(problems))
        self.assertLess(elapsed, SCAN_CEILING_SECS)


if __name__ == "__main__":
    unittest.main()
