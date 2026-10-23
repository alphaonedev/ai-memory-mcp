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

    def run_raw(self, argv_tail, data=b""):
        argv = [sys.executable, "-I", str(GATE)] + list(argv_tail)
        return subprocess.run(argv, input=data, capture_output=True, timeout=TIMEOUT_SECONDS)

    def test_missing_root_fails_closed_8072(self):
        missing = self.root / "nope"
        res = self.run_raw(["--root", str(missing)])
        self.assertEqual(res.returncode, EXIT_DEFECT)
        self.assertEqual(res.stderr.decode(), "gate defect: root not found: %s\n" % missing)
        self.assertNotIn(b"Traceback", res.stderr)

    def test_internal_errors_exit_defect_8072(self):
        deep = self.root / "tests/fixtures/deep.json"
        write(deep, "[" * 200000)
        write(self.root / "tests/qual_deep.rs", 'include_str!("fixtures/deep.json");\n')
        res = self.run_raw(["--root", str(self.root)], b"README.md\n")
        self.assertEqual(res.returncode, EXIT_DEFECT, res.stderr)
        self.assertTrue(res.stderr.decode().startswith("gate defect: "), res.stderr)
        self.assertEqual(len(res.stderr.decode().splitlines()), 1)
        deep.unlink()
        absent = self.root / "absent.txt"
        res = self.run_raw(["--root", str(self.root), "--diff-file", str(absent)])
        self.assertEqual(res.returncode, EXIT_DEFECT, res.stderr)
        self.assertTrue(res.stderr.decode().startswith("gate defect: "), res.stderr)
        self.assertNotIn(b"Traceback", res.stderr)

    def test_deleted_inventoried_path_is_caught_8071(self):
        (self.root / SDK_PATH).unlink()
        res = self.run_gate(SDK_PATH + "\n")
        self.assertEqual(res.returncode, EXIT_MATCH, res.stderr)
        self.assertIn("qual_m1", res.stdout)

    def test_non_path_strings_are_not_inventoried_8071(self):
        write(
            self.root / "tests/fixtures/m4.json",
            '["https://example.com/a/b", "/etc/passwd", "sha256", "0"]',
        )
        write(self.root / "tests/qual_m4.rs", 'include_str!("fixtures/m4.json");\n')
        for diff in ("sha256\n", "etc/passwd\n", "example.com/a/b\n"):
            res = self.run_gate(diff)
            self.assertEqual(res.returncode, EXIT_OK, (diff, res.stdout))

    def test_bom_and_crlf_diff_list_8073(self):
        data = b"\xef\xbb\xbf" + SDK_PATH.encode() + b"\r\n"
        diff_file = self.root / "bom.txt"
        diff_file.write_bytes(data)
        res = self.run_raw(["--root", str(self.root), "--diff-file", str(diff_file)])
        self.assertEqual(res.returncode, EXIT_MATCH, res.stderr)
        res = self.run_raw(["--root", str(self.root)], data)
        self.assertEqual(res.returncode, EXIT_MATCH, res.stderr)

    def test_nested_fixture_manifest_is_walked_8074(self):
        write(self.root / "tests/fixtures/sub/m5.json", '["README.md"]')
        res = self.run_gate("README.md\n")
        self.assertEqual(res.returncode, EXIT_DEFECT)
        self.assertIn("sub/m5.json", res.stderr)
        write(self.root / "tests/qual_m5.rs", 'include_str!("fixtures/sub/m5.json");\n')
        res = self.run_gate("README.md\n")
        self.assertEqual(res.returncode, EXIT_MATCH, res.stderr)
        self.assertIn("qual_m5", res.stdout)

    def test_directory_string_covers_children_8075(self):
        write(self.root / "tests/fixtures/m3.json", '["sdk/dirpkg/", "sdk/dirx"]')
        write(self.root / "tests/qual_m3.rs", 'include_str!("fixtures/m3.json");\n')
        (self.root / "sdk/dirx").mkdir(parents=True)
        for diff in ("sdk/dirpkg/a/b.py\n", "sdk/dirx/c.ts\n"):
            res = self.run_gate(diff)
            self.assertEqual(res.returncode, EXIT_MATCH, (diff, res.stderr))
            self.assertIn("qual_m3", res.stdout)
        res = self.run_gate("sdk/dirpkg2/a.py\n")
        self.assertEqual(res.returncode, EXIT_OK, res.stdout)

    def test_manifest_edit_names_owner_8076(self):
        res = self.run_gate("tests/fixtures/m1.json\n")
        self.assertEqual(res.returncode, EXIT_MATCH, res.stderr)
        self.assertIn("run: cargo test --test qual_m1", res.stdout)

if __name__ == "__main__":
    unittest.main()
