# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""Test-impact selection honours manifest-owned qual_* pins (#8077)."""

import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

REPO = Path(__file__).resolve().parents[3]
SCRATCH = REPO / ".local-runs"
SELECTOR = REPO / "scripts/ci/test_impact.py"
GATE = REPO / "scripts/ci/manifest_owned_paths.py"
GATE_REL = "scripts/ci/manifest_owned_paths.py"
SDK_PATH = "sdk/typescript/src/wake.ts"
PIN = "qual_wake_content_boundary_3578"
DEFECT_GATE = 'import sys\nprint("gate defect: forced by test", file=sys.stderr)\nsys.exit(2)\n'


class OwnedPathsSelectionTest(unittest.TestCase):
    def setUp(self):
        SCRATCH.mkdir(exist_ok=True)
        self.repo = Path(tempfile.mkdtemp(dir=str(SCRATCH)))
        self.addCleanup(shutil.rmtree, str(self.repo), True)
        self.env = {
            **os.environ, "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_AUTHOR_NAME": "F", "GIT_AUTHOR_EMAIL": "f@example.invalid",
            "GIT_COMMITTER_NAME": "F", "GIT_COMMITTER_EMAIL": "f@example.invalid",
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


if __name__ == "__main__":
    unittest.main(verbosity=2)
