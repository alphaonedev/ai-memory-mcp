"""Ratchet: no handler under scripts/ swallows an exception without saying why (#8219, py/empty-except).

A handler whose body is only ``pass`` (or ``...``) hides a failure from the reader; CodeQL's py/empty-except
accepts one only when a comment on the handler states why nothing needs doing. ``except:`` with no type is
refused outright (it also swallows KeyboardInterrupt and SystemExit). The tree is walked, not listed, so a new
file is covered the day it lands.

``KNOWN_SITES`` is the shrink-only baseline of the sites in files this PR does not otherwise touch, each one an
item on the #8219 umbrella (https://github.com/alphaonedev/ai-memory-mcp/issues/8219#issuecomment-6939792101).
A row whose handler is gone fails the test, so the baseline can only get smaller.
"""
import ast
import os
import re
import time
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
SCRIPTS_ROOT = REPO / "scripts"
SILENT_BODIES = (ast.Pass,)
LINE_BREAK_RE = re.compile(r"\r\n|\r|\n")
SCAN_SECONDS_CEILING = 2.0
BIG_SOURCE_HANDLERS = 6000  # about 100K bytes of handlers below

# (scripts-relative file, enclosing function, handler type source) -> the umbrella item that owns it
KNOWN_SITES = {
    ("scripts/bench/benchlib.py", "host_facts", "(OSError, subprocess.SubprocessError)"): "#8219",
    ("scripts/bench/benchlib.py", "host_facts", "(OSError, subprocess.SubprocessError, ValueError)"): "#8219",
}

RED_CELLS = {
    "bare except": ("try:\n    f()\nexcept:  # why\n    pass\n", "except with no type"),
    "silent pass": ("try:\n    f()\nexcept OSError:\n    pass\n", "silent handler"),
    "silent ellipsis": ("try:\n    f()\nexcept OSError:\n    ...\n", "silent handler"),
    "two silent statements": ("try:\n    f()\nexcept OSError:\n    pass\n    pass\n", "silent handler"),
    "comment after the handler": ("try:\n    f()\nexcept OSError:\n    pass\n# later\n", "silent handler"),
    # str.splitlines() also breaks on \x0c, \x1c and \u2028 inside a string, which shifts the comment window
    # off the AST line numbers: an earlier comment must not excuse a silent handler.
    "form feeds before a silent handler": ("s = '\x0c\x0c\x0c'  # c\ntry:\n    f()\nexcept OSError:\n    pass\n",
                                           "silent handler"),
}
GREEN_CELLS = {
    "comment on the pass": "try:\n    f()\nexcept OSError:\n    pass  # absent is fine\n",
    "comment on the except line": "try:\n    f()\nexcept OSError:  # absent is fine\n    pass\n",
    "comment between": "try:\n    f()\nexcept OSError:\n    # absent is fine\n    pass\n",
    "handler that acts": "try:\n    f()\nexcept OSError as exc:\n    log(exc)\n",
    "line separator before a commented handler": "s = '\u2028'\ntry:\n    f()\nexcept OSError:\n    pass  # fine\n",
}


def _silent(body):
    return all(isinstance(stmt, SILENT_BODIES) or (isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Constant)
                                                    and stmt.value.value is Ellipsis) for stmt in body)


def _scopes(tree):
    owner = {}

    def visit(node, name):
        for child in ast.iter_child_nodes(node):
            inner = child.name if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)) else name
            owner[id(child)] = inner
            visit(child, inner)

    visit(tree, "<module>")
    return owner


def handler_findings(rel, source):
    """[(rel, function, type source, line, form)] for every silent or untyped handler in ``source``."""
    tree = ast.parse(source)
    # The tokenizer ends a line only at \r\n, \r or \n; str.splitlines() also splits at \x0c, \x1c and \u2028,
    # which would move the comment window away from the AST line numbers.
    lines = LINE_BREAK_RE.split(source)
    owner = _scopes(tree)
    found = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.ExceptHandler):
            continue
        kind = ast.unparse(node.type) if node.type is not None else ""
        if node.type is None:
            found.append((rel, owner.get(id(node), "<module>"), kind, node.lineno, "except with no type"))
        elif _silent(node.body) and not any("#" in line for line in lines[node.lineno - 1:node.body[-1].end_lineno]):
            found.append((rel, owner.get(id(node), "<module>"), kind, node.lineno, "silent handler"))
    return found


def tree_findings():
    found = []
    for directory, subdirs, files in os.walk(SCRIPTS_ROOT):
        subdirs[:] = sorted(d for d in subdirs if d != "__pycache__")
        for name in sorted(files):
            if name.endswith(".py"):
                path = Path(directory) / name
                found.extend(handler_findings(path.relative_to(REPO).as_posix(), path.read_text(errors="replace")))
    return found


class EmptyExceptRatchet(unittest.TestCase):
    def test_no_new_silent_handler_under_scripts_8219(self):
        new = ["%s:%d: %s (%s)" % (rel, line, form, kind or "bare")
               for rel, func, kind, line, form in tree_findings() if (rel, func, kind) not in KNOWN_SITES]
        self.assertEqual(new, [])

    def test_every_known_site_still_exists_8219(self):
        present = {finding[:3] for finding in tree_findings()}
        self.assertEqual(sorted(set(KNOWN_SITES) - present), [])

    def test_the_prune_probe_unlink_handler_states_why_8219(self):
        rel = "scripts/ci/prune_runner_tmp.py"
        found = handler_findings(rel, (REPO / rel).read_text())
        self.assertEqual(found, [])

    def test_red_cells_8219(self):
        for label, (source, form) in RED_CELLS.items():
            with self.subTest(label):
                self.assertEqual([finding[4] for finding in handler_findings("cell.py", source)], [form])

    def test_green_cells_8219(self):
        for label, source in GREEN_CELLS.items():
            with self.subTest(label):
                self.assertEqual(handler_findings("cell.py", source), [])

    def test_a_100k_source_is_scanned_within_the_bound_8219(self):
        source = "try:\n    f()\nexcept OSError:\n    pass  # fine\n" * BIG_SOURCE_HANDLERS
        self.assertGreaterEqual(len(source), 100_000)
        started = time.monotonic()
        self.assertEqual(handler_findings("big.py", source), [])
        self.assertLess(time.monotonic() - started, SCAN_SECONDS_CEILING)


if __name__ == "__main__":
    unittest.main()
