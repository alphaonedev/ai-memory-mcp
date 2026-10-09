#!/usr/bin/env python3
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""Every inline ``mod tests`` under ``src/`` carries ``#[cfg(test)]`` (#4755).

THE DEFECT (#4755). ``src/bench.rs`` declared ``mod tests {`` with only an
``#[allow(clippy::wildcard_imports)]`` above it. Without ``#[cfg(test)]`` the
module's helpers (``fresh_conn``, ``small_config``, ...) compile into the
production library, ``#[allow(dead_code)]`` hides that, and every gate built on
the #3623 production-lines boundary (``scripts/lib/production-lines.awk``)
classes the module's 28 ``#[test]`` functions as PRODUCTION: test-only gates
skip them and production-only gates scan them.

THE RULE. A ``mod tests`` declaration (inline ``{`` or out-of-line ``;``) is
preceded, with only attributes, comments and blank lines in between, by a
``#[cfg(test)]`` / ``#[cfg(all(test, ...))]`` / ``#[cfg(any(test, ...))]``
attribute. A file whose first line is ``#![cfg(test)]`` is test-only as a
whole and is exempt, as is a file the awk boundary already treats as a test
file by name (``*_test.rs``, ``*_tests.rs``, ``test_*.rs``, ``tests.rs``).

Run: ``python3 scripts/test/test_inline_mod_tests_cfg_4755.py``
"""

from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[2]
SRC = ROOT / "src"

MOD_TESTS_DECL = re.compile(r"^\s*(?:pub(?:\([^)]*\))?\s+)?mod\s+tests\s*(?:\{|;)")
CFG_TEST_ATTR = re.compile(r"^\s*#\[cfg\((?:test\b|all\(test\b|any\(test\b)")
WHOLE_FILE_CFG_TEST = re.compile(r"^\s*#!\[cfg\(test\)\]")
# Mirrors the stem rule in scripts/lib/production-lines.sh (#3623).
TEST_FILE_STEM = re.compile(r"(^|_)tests?(_|$)")


def unguarded_mod_tests(path):
    """Return ``line_no`` (1-based) of every ``mod tests`` in ``path`` without a
    ``cfg(test)`` attribute above it; an empty list when the file is clean."""
    if TEST_FILE_STEM.search(path.stem):
        return []
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    if any(WHOLE_FILE_CFG_TEST.match(line) for line in lines):
        return []
    offenders = []
    for index, line in enumerate(lines):
        if not MOD_TESTS_DECL.match(line):
            continue
        guarded = False
        cursor = index - 1
        while cursor >= 0:
            above = lines[cursor]
            stripped = above.strip()
            if CFG_TEST_ATTR.match(above):
                guarded = True
                break
            if stripped == "" or stripped.startswith("#[") or stripped.startswith("//"):
                cursor -= 1
                continue
            break
        if not guarded:
            offenders.append(index + 1)
    return offenders


def scan(src):
    """Return ``[(relative_path, line_no), ...]`` across every ``.rs`` file."""
    found = []
    for path in sorted(src.rglob("*.rs")):
        for line_no in unguarded_mod_tests(path):
            found.append((str(path.relative_to(src.parent)), line_no))
    return found


class InlineModTestsCfg(unittest.TestCase):
    def test_every_inline_mod_tests_is_cfg_test(self):
        found = scan(SRC)
        self.assertEqual(
            found,
            [],
            "inline `mod tests` without #[cfg(test)] (#4755): "
            + ", ".join("%s:%d" % item for item in found),
        )

    def test_bench_module_is_cfg_test(self):
        # The #4755 site, pinned by name so the failure names the file.
        self.assertEqual(unguarded_mod_tests(SRC / "bench.rs"), [])

    # --- self-tests of the scanner on synthetic sources ---------------------

    def _probe(self, text, stem="probe"):
        import tempfile

        with tempfile.TemporaryDirectory(dir=str(ROOT / ".local-runs")) as scratch:
            path = Path(scratch) / (stem + ".rs")
            path.write_text(text, encoding="utf-8")
            return unguarded_mod_tests(path)

    def test_scanner_red_on_bare_mod_tests(self):
        self.assertEqual(self._probe("fn a() {}\n\nmod tests {\n}\n"), [3])

    def test_scanner_red_when_only_allow_attribute(self):
        text = "#[allow(clippy::wildcard_imports)]\nmod tests {\n}\n"
        self.assertEqual(self._probe(text), [2])

    def test_scanner_green_with_cfg_test_above_other_attributes(self):
        text = "#[cfg(test)]\n#[allow(clippy::wildcard_imports)]\nmod tests {\n}\n"
        self.assertEqual(self._probe(text), [])

    def test_scanner_green_with_comment_between(self):
        text = "#[cfg(test)]\n// helpers below\nmod tests {\n}\n"
        self.assertEqual(self._probe(text), [])

    def test_scanner_green_for_cfg_all_and_out_of_line(self):
        self.assertEqual(self._probe("#[cfg(all(test, feature = \"x\"))]\nmod tests;\n"), [])

    def test_scanner_red_for_out_of_line_without_cfg(self):
        self.assertEqual(self._probe("mod tests;\n"), [1])

    def test_scanner_green_for_whole_file_cfg_test(self):
        self.assertEqual(self._probe("#![cfg(test)]\n\nmod tests {\n}\n"), [])

    def test_scanner_green_for_test_file_stem(self):
        self.assertEqual(self._probe("mod tests {\n}\n", stem="foo_tests"), [])

    def test_scanner_ignores_other_modules(self):
        self.assertEqual(self._probe("mod testsuite {\n}\nmod helpers;\n"), [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
