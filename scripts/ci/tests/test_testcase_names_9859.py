#!/usr/bin/env python3
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""Every written test executes: no TestCase class switches its own tests off by a name (issue 9859, PR 9838 class F).

Class: a test that is written but never executes.  A TestCase subclass that
defines a name unittest.TestCase itself defines (`run`, `debug`, `__call__`,
`countTestCases`, `id`, `subTest`, `skipTest`, `fail`, an `assert*` name, ...)
replaces the machinery that runs its tests; its module still prints OK.

Invariant (held for every class of every test module under SCANNED_ROOTS):
a name in the class's own namespace that unittest.TestCase (or a class of its
MRO other than object) defines is either a name every class body gets
automatically or on PERMITTED_OVERRIDES, which is written out by hand: the
names the test modules really use.  Each other name is one finding, printed
with OVERRIDE_MESSAGE.  The check reads the classes as the loader sees them
(the module is imported), so every form of the definition counts the same: a
def, an assignment, a lambda, a nested class, a decorator result.  Each root is
scanned in its own interpreter so module names of two roots never collide.

For COUNTED_MODULE it also holds that the set of tests that execute equals the
set of `test_*` methods written in its TestCase classes, counted from the source
with ast (never from the loader).  The bodies are replaced by a recording stub
that keeps the original's attributes (a skip still skips), so the check costs
the setUp and tearDown of each test, not the bodies.

LEFT_OUT pins, by path and issue number, a module of another PR that shows the
same defect; it is empty: the walk at the round-3 head found only the one
instance this PR fixes.  Stdlib only.
"""

from __future__ import annotations

import ast
import functools
import importlib
import inspect
import io
import json
import subprocess
import sys
import unittest
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parents[3]
SCANNED_ROOTS = ("scripts/ci/tests", "scripts/test")
COUNTED_MODULE = "scripts/ci/tests/test_queue_order.py"
PERMITTED_OVERRIDES = frozenset({"setUp", "tearDown", "setUpClass", "tearDownClass", "maxDiff"})
LEFT_OUT: tuple[tuple[str, int], ...] = ()
OVERRIDE_MESSAGE = "TestCase class overrides a unittest.TestCase name: %s %s.%s"
IMPORT_MESSAGE = "test module does not import: %s (%s)"
SCAN_FLAG = "--scan"
SCAN_TIMEOUT_SECS = 600
MIN_CLASSES_PER_ROOT = 10
TEST_PREFIX = "test"
TESTCASE_BASES = frozenset({"TestCase", "IsolatedAsyncioTestCase"})


class _Empty(unittest.TestCase):
    """The names every TestCase class body gets without writing them."""


AUTOMATIC_NAMES = frozenset(vars(_Empty))
TESTCASE_NAMES = frozenset(name for klass in unittest.TestCase.__mro__ if klass is not object for name in vars(klass))


def overrides_of(cls: type, left_out: frozenset[str] = frozenset()) -> list[str]:
    """The names of cls's own namespace that replace a unittest.TestCase name and are not permitted."""
    own = set(vars(cls)) & TESTCASE_NAMES
    return sorted(own - AUTOMATIC_NAMES - PERMITTED_OVERRIDES - left_out)


def scan_root(root: Path) -> dict:
    """Import every module of root (as discover does) and list every finding; runs in its own interpreter."""
    sys.path.insert(0, str(root))
    findings: list[str] = []
    classes = 0
    left = {path for path, _issue in LEFT_OUT}
    for path in sorted(root.glob("*.py")):
        rel = path.relative_to(REPO_ROOT).as_posix()
        try:
            module = importlib.import_module(path.stem)
        except Exception as exc:  # every failure to import is a finding, never a skip
            findings.append(IMPORT_MESSAGE % (rel, type(exc).__name__))
            continue
        for name, cls in sorted(vars(module).items()):
            if not (inspect.isclass(cls) and issubclass(cls, unittest.TestCase) and cls.__module__ == module.__name__):
                continue
            classes += 1
            if rel in left:
                continue
            findings.extend(OVERRIDE_MESSAGE % (rel, name, attr) for attr in overrides_of(cls))
    return {"classes": classes, "findings": findings}


def run_scan(root: str) -> dict:
    proc = subprocess.run([sys.executable, str(Path(__file__).resolve()), SCAN_FLAG, str(REPO_ROOT / root)], capture_output=True,
                          text=True, timeout=SCAN_TIMEOUT_SECS, check=False, stdin=subprocess.DEVNULL, cwd=REPO_ROOT)
    if proc.returncode != 0:
        raise AssertionError("scan of %s exited %d: %s" % (root, proc.returncode, proc.stderr[-2000:]))
    return json.loads(proc.stdout.splitlines()[-1])


def written_tests(source: str) -> set[tuple[str, str]]:
    """(class, method) of every `test_*` def a TestCase class of the source carries, its local bases' included (ast only)."""
    tree = ast.parse(source)
    classes = {node.name: node for node in tree.body if isinstance(node, ast.ClassDef)}

    def base_names(node: ast.ClassDef) -> list[str]:
        out = []
        for base in node.bases:
            if isinstance(base, ast.Attribute):
                out.append(base.attr)
            elif isinstance(base, ast.Name):
                out.append(base.id)
        return out

    derived: set[str] = set()
    changed = True
    while changed:
        changed = False
        for name, node in classes.items():
            if name not in derived and any(b in TESTCASE_BASES or b in derived for b in base_names(node)):
                derived.add(name)
                changed = True

    def own(name: str) -> set[str]:
        return {n.name for n in classes[name].body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name.startswith(TEST_PREFIX)}

    def inherited(name: str, seen: frozenset[str] = frozenset()) -> set[str]:
        names = own(name)
        for base in base_names(classes[name]):
            if base in derived and base not in seen:
                names |= inherited(base, seen | {name})
        return names

    return {(name, method) for name in derived for method in inherited(name)}


def executed_tests(module) -> tuple[set[tuple[str, str]], int]:
    """(class, method) of every test that executes when the module's suite runs, with each body replaced by a stub."""
    ran: set[tuple[str, str]] = set()
    patches = []
    for cls in vars(module).values():
        if not (inspect.isclass(cls) and issubclass(cls, unittest.TestCase) and cls.__module__ == module.__name__):
            continue
        for attr, value in list(vars(cls).items()):
            if attr.startswith(TEST_PREFIX) and inspect.isfunction(value):

                @functools.wraps(value)
                def stub(self, _key=(cls.__name__, attr)) -> None:
                    ran.add(_key)

                patches.append(mock.patch.object(cls, attr, stub))
    for patch in patches:
        patch.start()
    try:
        suite = unittest.defaultTestLoader.loadTestsFromModule(module)
        result = unittest.TextTestRunner(stream=io.StringIO(), verbosity=0).run(suite)
    finally:
        for patch in patches:
            patch.stop()
    return ran, result.testsRun


class NoTestCaseNameOverridden(unittest.TestCase):
    """9859: an allowlist of the TestCase names a class may define, over every module of every scanned root."""

    def test_permitted_names_are_testcase_names(self) -> None:
        # the allowlist names real TestCase attributes; a typo would permit nothing and hide nothing, but is still drift
        self.assertEqual(sorted(PERMITTED_OVERRIDES - TESTCASE_NAMES), [])

    def test_left_out_table_is_pinned(self) -> None:
        self.assertEqual(LEFT_OUT, ())

    def test_every_root_has_no_override(self) -> None:
        for root in SCANNED_ROOTS:
            with self.subTest(root=root):
                report = run_scan(root)
                self.assertEqual(report["findings"], [])
                self.assertGreaterEqual(report["classes"], MIN_CLASSES_PER_ROOT)

    def test_each_override_form_is_a_finding(self) -> None:
        # (form, class body as built at runtime, expected names); written out by hand
        rows = (
            ("def run", {"run": lambda self, status="x": status}, ["run"]),
            ("def debug", {"debug": lambda self: None}, ["debug"]),
            ("countTestCases returns 0", {"countTestCases": lambda self: 0}, ["countTestCases"]),
            ("__call__ assigned", {"__call__": lambda self, *a: None}, ["__call__"]),
            ("id as a constant", {"id": "x"}, ["id"]),
            ("subTest as a nested class", {"subTest": type("subTest", (), {})}, ["subTest"]),
            ("an assert name", {"assertEqual": staticmethod(lambda *a: None)}, ["assertEqual"]),
            ("fail and skipTest", {"fail": None, "skipTest": None}, ["fail", "skipTest"]),
            ("permitted only", {"setUp": lambda self: None, "maxDiff": None, "helper": lambda self: None}, []),
        )
        for form, body, expected in rows:
            with self.subTest(form=form):
                cls = type("Probe", (unittest.TestCase,), dict(body))
                self.assertEqual(overrides_of(cls), expected)
                if expected:
                    self.assertEqual(OVERRIDE_MESSAGE % ("m.py", "Probe", expected[0]),
                                     "TestCase class overrides a unittest.TestCase name: m.py Probe.%s" % expected[0])


class WrittenEqualsRun(unittest.TestCase):
    """9859: every `test_*` method written in test_queue_order.py executes (written counted with ast, run counted by execution)."""

    def test_written_equals_run(self) -> None:
        path = REPO_ROOT / COUNTED_MODULE
        written = written_tests(path.read_text(encoding="utf-8"))
        sys.path.insert(0, str(path.parent))
        try:
            module = importlib.import_module(path.stem)
        finally:
            sys.path.remove(str(path.parent))
        ran, count = executed_tests(module)
        self.assertEqual(sorted(written - ran), [])
        self.assertEqual(sorted(ran - written), [])
        self.assertEqual(count, len(written))

    def test_ast_count_sees_inheritance_and_ignores_plain_classes(self) -> None:
        source = (
            "import unittest\n"
            "class Base(unittest.TestCase):\n    def test_a(self): pass\n"
            "class Child(Base):\n    def test_b(self): pass\n"
            "class Plain:\n    def test_c(self): pass\n"
        )
        self.assertEqual(written_tests(source), {("Base", "test_a"), ("Child", "test_a"), ("Child", "test_b")})


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == SCAN_FLAG:
        print(json.dumps(scan_root(Path(sys.argv[2]))))
        sys.exit(0)
    unittest.main()
