# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""Test-impact selection honours manifest-owned qual_* pins (#8077)."""

import importlib.util
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

REPO = Path(__file__).resolve().parents[3]
SCRATCH = REPO / ".local-runs"
SELECTOR = REPO / "scripts/ci/test_impact.py"
GATE = REPO / "scripts/ci/manifest_owned_paths.py"
GATE_REL = "scripts/ci/manifest_owned_paths.py"
SDK_PATH = "sdk/typescript/src/wake.ts"
PIN = "qual_wake_content_boundary_3578"
STUB_PRINT = 'import sys\nprint("p  m  run: cargo test --test %s")\nsys.exit(1)\n'
STUB_SLEEP = "import time\ntime.sleep(30)\n"
SHORT_TIMEOUT = 1
STUB_RAW = "import sys\nsys.stdout.buffer.write(%r)\nsys.exit(1)\n"
DEFECT_GATE ='import sys\nprint("gate defect: forced by test", file=sys.stderr)\nsys.exit(2)\n'


class OwnedPathsSelectionTest(unittest.TestCase):
    def setUp(self):
        SCRATCH.mkdir(exist_ok=True)
        self.repo = Path(tempfile.mkdtemp(dir=str(SCRATCH)))
        self.addCleanup(shutil.rmtree, str(self.repo), True)
        self.env = {
            **os.environ, "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_AUTHOR_NAME": "F", "GIT_AUTHOR_EMAIL": "fixture",
            "GIT_COMMITTER_NAME": "F", "GIT_COMMITTER_EMAIL": "fixture",
            "GITHUB_OUTPUT": str(self.repo / "output"),
        }
        self.git("init", "-q")
        self.commit({
            "tests/cli_subcommand_count_invariant.rs": "// fixture\n",
            "tests/fixtures/wake_manifest.json": '[{"path": "%s", "sha256": "0"}]' % SDK_PATH,
            "tests/%s.rs" % PIN: 'const M: &str = include_str!("fixtures/wake_manifest.json");\n',
            GATE_REL: GATE.read_text(encoding="utf-8"),
            SDK_PATH: "a\n",
        })
        self.base = self.git("rev-parse", "HEAD").strip()
        self.commit({SDK_PATH: "b\n"})
        self.round = 0

    def git(self, *args):
        return subprocess.run(["git"] + list(args), cwd=str(self.repo), env=self.env, check=True,
                              capture_output=True, text=True).stdout

    def commit(self, files):
        for name, text in files.items():
            path = self.repo / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text, encoding="utf-8")
        self.git("add", "-f", "--", *sorted(files))
        self.git("-c", "commit.gpgsign=false", "commit", "-qm", "fixture")

    def select(self):
        subprocess.run([sys.executable, "-I", str(SELECTOR), self.base, "HEAD"], cwd=str(self.repo),
                       env=self.env, check=True, capture_output=True, text=True)
        lines = (self.repo / "output").read_text(encoding="utf-8").splitlines()
        return dict(line.split("=", 1) for line in lines)

    def test_manifest_owned_pin_is_selected(self):
        result = self.select()
        self.assertIn(PIN, result["test_impact"].split())
        self.assertIn("manifest-owned", result["test_impact_reason"])

    def test_gate_defect_fails_closed_to_all(self):
        (self.repo / GATE_REL).write_text(DEFECT_GATE, encoding="utf-8")
        self.git("add", "-f", "--", GATE_REL)
        self.git("-c", "commit.gpgsign=false", "commit", "-qm", "break gate")
        self.base = self.git("rev-parse", "HEAD").strip()
        self.commit({SDK_PATH: "c\n"})
        result = self.select()
        self.assertEqual(result["test_impact"], "__ALL__")
        self.assertIn("manifest-owned-paths gate defect", result["test_impact_reason"])

    def break_gate(self, text):
        """Replace the gate in the fixture repo (None removes it) and re-base."""
        if text is None:
            self.git("rm", "-q", "--", GATE_REL)
        else:
            (self.repo / GATE_REL).write_text(text, encoding="utf-8")
            self.git("add", "-f", "--", GATE_REL)
        self.git("-c", "commit.gpgsign=false", "commit", "-qm", "break gate")
        self.base = self.git("rev-parse", "HEAD").strip()
        self.round += 1
        self.commit({SDK_PATH: "round %d\n" % self.round})

    def assert_closed(self, result, text):
        self.assertEqual(result["test_impact"], "__ALL__")
        reason = result["test_impact_reason"]
        self.assertTrue(reason.startswith("manifest-owned-paths gate defect: "), reason)
        self.assertIn(text, reason)

    def test_unexpected_exit_code_fails_closed(self):
        self.break_gate("import sys\nsys.exit(3)\n")
        self.assert_closed(self.select(), "exit 3")

    def test_missing_gate_fails_closed(self):
        self.break_gate(None)
        self.assert_closed(self.select(), "script missing")

    def test_exit_one_without_stem_line_fails_closed(self):
        self.break_gate("import sys\nsys.exit(1)\n")
        self.assert_closed(self.select(), "no stem line")

    def test_invalid_stems_fail_closed(self):
        for stem in ("qual_a*b", "qual_--nocapture", "qual_x y", "--help", ""):
            with self.subTest(stem=stem):
                self.break_gate(STUB_PRINT % stem)
                self.assert_closed(self.select(), "invalid stem")

    def raw_stub(self, payload):
        self.break_gate(STUB_RAW % payload)

    def test_carriage_return_inside_stem_fails_closed(self):
        # R4/S4: `qual_a\rqual_b` must not be cut to `qual_a`.
        self.raw_stub(b"p  m  run: cargo test --test qual_a\rqual_b\n")
        self.assert_closed(self.select(), "control character")

    def test_trailing_carriage_return_fails_closed(self):
        # R4/S4: `qual_cr\r` must not be cleaned to `qual_cr`.
        self.raw_stub(b"p  m  run: cargo test --test qual_cr\r\n")
        self.assert_closed(self.select(), "control character")

    def test_hidden_separator_between_two_stems_fails_closed(self):
        # Two stems on one gate line, split by separators str.splitlines would hide.
        for sep in (b"\x0b", b"\x0c", b"\x1c", b"\r", b"\xc2\x85", b"\xe2\x80\xa8"):
            with self.subTest(sep=sep):
                self.raw_stub(b"p  m  run: cargo test --test qual_a" + sep + b"qual_b\n")
                self.assert_closed(self.select(), "")

    def test_invalid_utf8_gate_output_fails_closed(self):
        self.raw_stub(b"p  m  run: cargo test --test qual_\xff\n")
        self.assert_closed(self.select(), "UTF-8")

    def add_test_file(self, name):
        self.commit({"tests/" + name: "// fixture\n"})
        self.base = self.git("rev-parse", "HEAD").strip()

    def test_newline_test_file_name_fails_closed_and_output_is_clean(self):
        # R4/S4: a trailing newline in a Rust test file stem passed `$`; fullmatch rejects it.
        self.add_test_file("qual_nl\n.rs")
        self.commit({"src/qual_nl.rs": "// x\n"})
        subprocess.run([sys.executable, "-I", str(SELECTOR), self.base, "HEAD"], cwd=str(self.repo),
                       env=self.env, check=True, capture_output=True, text=True)
        raw = (self.repo / "output").read_bytes().decode("utf-8")
        self.assertNotIn("\r", raw)
        self.assertIn("test_impact=__ALL__\n", raw)
        for line in raw.split("\n")[:-1]:
            self.assertRegex(line, r"\A[a-z_]+=[^\r\n]*\Z")
        result = dict(line.split("=", 1) for line in raw.splitlines())
        self.assertTrue(result["test_impact_reason"].startswith("test-impact stem defect: "), result)

    def test_rust_derived_invalid_stem_fails_closed(self):
        # S5: the validation of stems derived from tests/*.rs is live (names the stem).
        for name in ("evil stem.rs", "x*y.rs"):
            with self.subTest(name=name):
                self.add_test_file(name)
                self.commit({"tests/" + name: "// changed %s\n" % self.round})
                self.round += 1
                result = self.select()
                self.assertEqual(result["test_impact"], "__ALL__")
                reason = result["test_impact_reason"]
                self.assertTrue(reason.startswith("test-impact stem defect: "), reason)
                self.assertIn(name[:-3], reason)
                self.base = self.git("rev-parse", "HEAD").strip()
                self.commit({SDK_PATH: "next %d\n" % self.round})

    def test_valid_stem_from_stub_is_selected(self):
        self.break_gate(STUB_PRINT % "qual_stub_ok")
        self.assertIn("qual_stub_ok", self.select()["test_impact"].split())

    def test_gate_change_forces_full_suite(self):
        # S2: a diff touching only the gate must force __ALL__.
        self.base = self.git("rev-parse", "HEAD").strip()
        self.commit({GATE_REL: GATE.read_text(encoding="utf-8") + "\n# edit\n"})
        result = self.select()
        self.assertEqual(result["test_impact"], "__ALL__")
        self.assertIn("foundational:" + GATE_REL, result["test_impact_reason"])


class GateRunnerBranchTest(unittest.TestCase):
    """Direct calls of owned_paths_gate for the crash and timeout branches."""

    def setUp(self):
        SCRATCH.mkdir(exist_ok=True)
        self.repo = Path(tempfile.mkdtemp(dir=str(SCRATCH)))
        self.addCleanup(shutil.rmtree, str(self.repo), True)
        spec = importlib.util.spec_from_file_location("test_impact_under_test", str(SELECTOR))
        self.module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.module)
        (self.repo / GATE_REL).parent.mkdir(parents=True)

    def test_timeout_fails_closed(self):
        (self.repo / GATE_REL).write_text(STUB_SLEEP, encoding="utf-8")
        stems, defect = self.module.owned_paths_gate(self.repo, [SDK_PATH], timeout=SHORT_TIMEOUT)
        self.assertEqual(stems, [])
        self.assertIn("gate did not run", defect)

    def test_oserror_fails_closed(self):
        (self.repo / GATE_REL).write_text("pass\n", encoding="utf-8")
        with mock.patch.object(self.module.subprocess, "run", side_effect=OSError("boom")):
            stems, defect = self.module.owned_paths_gate(self.repo, [SDK_PATH])
        self.assertEqual(stems, [])
        self.assertIn("gate did not run", defect)


if __name__ == "__main__":
    unittest.main(verbosity=2)
