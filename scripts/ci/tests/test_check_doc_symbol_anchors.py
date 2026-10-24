# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""Regression tests for the doc-symbol-anchors gate (#8171).

The gate must verify cited paths under scripts/ (and tests/, docs/, .github/),
not only src/ paths. Set DOC_ANCHOR_GATE to run an alternative gate (used to
prove the red result against the former shell gate).
"""

import os
import shutil
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
GATE = Path(os.environ.get("DOC_ANCHOR_GATE") or ROOT / "scripts" / "check-doc-symbol-anchors.py")
SCRATCH = ROOT / ".local-runs"

CLEAN = (
    "See `src/mcp/tools/recall.rs::decorate_memory_many` for the decorator.\n"
    "Module doc: [`recall`](src/mcp/tools/recall.rs).\n"
)


class DocAnchors8171Tests(unittest.TestCase):
    def setUp(self):
        SCRATCH.mkdir(exist_ok=True)
        self.fix = SCRATCH / ("test-doc-anchors-%d-%s" % (os.getpid(), self.id().split(".")[-1]))
        shutil.rmtree(str(self.fix), ignore_errors=True)
        for d in ("src/mcp/tools", "docs/reference", "scripts/ci", "scripts/qc-allowlists"):
            (self.fix / d).mkdir(parents=True)
        ref = self.fix / "docs" / "reference"
        (ref / "ARCHITECTURE_REFERENCE.md").write_text("# Arch (fixture)\nBody line.\n")
        (ref / "CODE_STYLE.md").write_text("# Style (fixture)\nBody line.\n")
        (self.fix / "src/mcp/tools/recall.rs").write_text(
            "pub struct RecallTool;\npub fn decorate_memory_many() {}\n")
        (self.fix / "scripts/ci/real_tool.py").write_text("# fixture\n")
        (self.fix / "scripts/qc-allowlists/doc-symbol-anchors-allow.txt").write_text("")
        self.addCleanup(shutil.rmtree, str(self.fix), True)

    def run_gate(self, readme_extra):
        (self.fix / "README.md").write_text(CLEAN + readme_extra)
        cmd = ["bash", str(GATE)] if GATE.suffix == ".sh" else [sys.executable, str(GATE)]
        env = dict(os.environ, AI_MEMORY_SYMBOL_GATE_ROOT=str(self.fix))
        p = subprocess.run(cmd, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                           universal_newlines=True)
        return p.returncode, p.stdout

    def test_8171_missing_scripts_path_fails(self):
        rc, out = self.run_gate("Run `scripts/ci/check_test_env_mutation.py` first.\n")
        self.assertNotEqual(rc, 0, out)
        self.assertIn("scripts/ci/check_test_env_mutation.py", out)
        self.assertIn("README.md:3", out)

    def test_8171_existing_scripts_path_passes(self):
        rc, out = self.run_gate("Run `scripts/ci/real_tool.py` first.\n")
        self.assertEqual(rc, 0, out)

    def test_8171_src_behaviour_unchanged(self):
        rc, out = self.run_gate("")
        self.assertEqual(rc, 0, out)
        rc, out = self.run_gate("Old: `src/mcp/tools/recall.rs::decorate_memory`.\n")
        self.assertNotEqual(rc, 0, out)
        self.assertIn("decorate_memory", out)
        rc, out = self.run_gate("Old: `src/handlers.rs` lives.\n")
        self.assertNotEqual(rc, 0, out)
        self.assertIn("src/handlers.rs", out)

    def test_8171_src_missing_path_not_exempted_by_unrelated_planned(self):
        rc, out = self.run_gate("Feature X is (planned).\nHandlers live in `src/handlers.rs`.\n")
        self.assertNotEqual(rc, 0, out)
        self.assertIn("src/handlers.rs", out)

    def test_8171_same_line_planned_marker_after_scripts_path_passes(self):
        rc, out = self.run_gate("Needs `scripts/ci/not_yet.py` (planned) later.\n")
        self.assertEqual(rc, 0, out)

    def test_8171_planned_on_line_above_does_not_exempt(self):
        rc, out = self.run_gate("Work is (planned).\nRun `scripts/ci/not_yet.py` now.\n")
        self.assertNotEqual(rc, 0, out)
        self.assertIn("scripts/ci/not_yet.py", out)

    def test_8171_broad_absent_word_does_not_exempt_new_rule(self):
        rc, out = self.run_gate("Run `scripts/ci/not_yet.py` now.\nThe list is split below.\n")
        self.assertNotEqual(rc, 0, out)

    def test_8171_dotdot_segment_rejected_even_if_target_exists(self):
        (self.fix / "Cargo.toml").write_text("[package]\n")
        rc, out = self.run_gate("See `scripts/../Cargo.toml`.\n")
        self.assertNotEqual(rc, 0, out)
        self.assertIn("scripts/../Cargo.toml", out)

    def test_8171_absolute_path_rejected(self):
        rc, out = self.run_gate("See `/scripts/ci/real_tool.py`.\n")
        self.assertNotEqual(rc, 0, out)

    def test_8171_symlink_treated_as_missing(self):
        outside = self.fix.parent / (self.fix.name + "-outside.py")
        outside.write_text("# outside\n")
        self.addCleanup(outside.unlink)
        (self.fix / "scripts/ci/link.py").symlink_to(outside)
        rc, out = self.run_gate("See `scripts/ci/link.py`.\n")
        self.assertNotEqual(rc, 0, out)
        self.assertIn("scripts/ci/link.py", out)

    def test_8171_command_form_citation_checks_the_path(self):
        rc, out = self.run_gate("Run `scripts/ci/no_such.py --flag` now.\n")
        self.assertNotEqual(rc, 0, out)
        self.assertIn("scripts/ci/no_such.py", out)
        rc, out = self.run_gate("Run `scripts/ci/real_tool.py --flag` now.\n")
        self.assertEqual(rc, 0, out)


if __name__ == "__main__":
    unittest.main()
