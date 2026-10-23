# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""Regression tests for the manifest-owned paths gate (#8050)."""

from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

GATE = Path(__file__).resolve().parents[1] / "manifest_owned_paths.py"
SCRATCH = Path(__file__).resolve().parents[3] / ".local-runs"
SDK_PATH = "sdk/typescript/src/wake.ts"
OTHER_PATH = "sdk/python/ai_memory/wake.py"
EXIT_OK = 0
EXIT_MATCH = 1
EXIT_DEFECT = 2
TIMEOUT_SECONDS = 30


def write(path, text):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


class ManifestOwnedPathsTest(unittest.TestCase):
    def setUp(self):
        SCRATCH.mkdir(exist_ok=True)
        self.root = Path(tempfile.mkdtemp(dir=str(SCRATCH)))
        self.addCleanup(shutil.rmtree, str(self.root), True)
        for rel in (SDK_PATH, OTHER_PATH, "README.md"):
            write(self.root / rel, "x\n")
        write(
            self.root / "tests/fixtures/m1.json",
            '[{"path": "%s", "sha256": "0"}, {"nested": {"p": "%s"}}]' % (SDK_PATH, OTHER_PATH),
        )
        write(
            self.root / "tests/qual_m1.rs",
            'const M: &str = include_str!("fixtures/m1.json");\n',
        )

    def run_gate(self, diff, extra=(), use_stdin=False):
        argv = [sys.executable, "-I", str(GATE), "--root", str(self.root)] + list(extra)
        stdin = None
        if use_stdin:
            stdin = diff
        else:
            diff_file = self.root / "diff.txt"
            write(diff_file, diff)
            argv += ["--diff-file", str(diff_file)]
        return subprocess.run(
            argv, input=stdin, capture_output=True, text=True, timeout=TIMEOUT_SECONDS
        )

    def test_inventoried_path_names_owner(self):
        res = self.run_gate(SDK_PATH + "\n")
        self.assertEqual(res.returncode, EXIT_MATCH, res.stderr)
        self.assertIn(SDK_PATH, res.stdout)
        self.assertIn("run: cargo test --test qual_m1", res.stdout)

    def test_nested_manifest_key_is_caught(self):
        res = self.run_gate(OTHER_PATH + "\n")
        self.assertEqual(res.returncode, EXIT_MATCH, res.stderr)

    def test_uninventoried_path_is_ok(self):
        res = self.run_gate("README.md\n")
        self.assertEqual(res.returncode, EXIT_OK, res.stderr)
        self.assertIn("ok", res.stdout)

    def test_stdin_input(self):
        res = self.run_gate(SDK_PATH + "\n", use_stdin=True)
        self.assertEqual(res.returncode, EXIT_MATCH, res.stderr)
        self.assertIn("qual_m1", res.stdout)

    def test_path_normalisation(self):
        res = self.run_gate("./" + SDK_PATH + "\n")
        self.assertEqual(res.returncode, EXIT_MATCH, res.stderr)

    def test_manifest_without_owner_fails_closed(self):
        write(self.root / "tests/fixtures/orphan.json", '["README.md"]')
        res = self.run_gate("README.md\n")
        self.assertEqual(res.returncode, EXIT_DEFECT)
        self.assertIn("orphan.json", res.stderr + res.stdout)

    def test_unparseable_manifest_fails_closed(self):
        write(self.root / "tests/fixtures/bad.json", "not json {")
        res = self.run_gate("README.md\n")
        self.assertEqual(res.returncode, EXIT_DEFECT)
        self.assertIn("bad.json", res.stderr + res.stdout)

    def test_missing_root_fails_closed(self):
        res = subprocess.run(
            [sys.executable, "-I", str(GATE), "--root", str(self.root / "nope")],
            input="", capture_output=True, text=True, timeout=TIMEOUT_SECONDS,
        )
        self.assertEqual(res.returncode, EXIT_DEFECT)


if __name__ == "__main__":
    unittest.main()
