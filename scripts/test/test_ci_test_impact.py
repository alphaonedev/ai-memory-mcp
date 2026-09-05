#!/usr/bin/env python3
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""Exercise the real selector and CI classifier against committed fixture diffs."""

import os
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
SELECTOR = ROOT / "scripts/ci-test-impact.sh"


class TestCiTestImpact(unittest.TestCase):
    def setUp(self):
        self.scratch = tempfile.TemporaryDirectory(prefix="ci-impact-3503-")
        self.addCleanup(self.scratch.cleanup)
        self.repo = Path(self.scratch.name)
        self.env = {
            **os.environ,
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_AUTHOR_NAME": "Selector fixture",
            "GIT_AUTHOR_EMAIL": "fixture@example.invalid",
            "GIT_COMMITTER_NAME": "Selector fixture",
            "GIT_COMMITTER_EMAIL": "fixture@example.invalid",
            "GITHUB_OUTPUT": str(self.repo / "output"),
        }
        self.run_command("git", "init", "-q")
        # Token overlap would miss this explicitly named acceptance target.
        self.commit({
            ".gitignore": "output\nci-test-impact.out\n",
            "Cargo.toml": '[[test]]\nname = "acceptance_nhi_sqlite"\n'
                          'path = "tests/acceptance/acceptance_nhi_sqlite.rs"\n',
            "tests/acceptance/acceptance_nhi_sqlite.rs": "// fixture\n",
            "tests/cli_subcommand_count_invariant.rs": "// fixture\n",
            "scripts/ci-test-impact.sh": SELECTOR.read_text(),
        })
        self.base = self.run_command("git", "rev-parse", "HEAD").strip()

    def run_command(self, *args, env=None):
        return subprocess.run(
            args, cwd=self.repo, env=env or self.env, check=True,
            text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        ).stdout

    def commit(self, files):
        for name, content in files.items():
            path = self.repo / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content)
        self.run_command("git", "add", ".")
        self.run_command("git", "-c", "commit.gpgsign=false", "commit", "-qm", "fixture")

    def select(self, *args):
        output = self.repo / "output"
        output.unlink(missing_ok=True)
        self.run_command("bash", str(SELECTOR), *args)
        return dict(line.split("=", 1) for line in output.read_text().splitlines())

    def test_pubkey_bind_diff_runs_full_suite_including_acceptance(self):
        self.commit({"src/identity/pubkey_bind.rs": "// binding change\n"})
        result = self.select(self.base, "HEAD")
        self.assertEqual(result["test_impact"], "__ALL__")
        self.assertEqual(result["test_impact_count"], "ALL")

    def test_every_security_surface_runs_full_suite(self):
        paths = (
            "src/identity/nested/proof.rs", "src/handlers/admin.rs",
            "src/handlers/identity_binding.rs", "src/storage/pubkey_history.rs",
            "src/federation/sync.rs", "src/federation/identity/proof.rs",
            "src/store/mod.rs", "src/store/sqlite.rs", "src/store/postgres.rs",
            "src/store/nested/adapter.rs", "src/storage/migrations.rs",
            "migrations/nested/schema.sql", "src/visibility.rs",
            "scripts/qc-codegraph-allowlists/caller-context-literals.txt",
            "scripts/qc-codegraph-allowlists/for-admin-bypass.txt",
        )
        for path in paths:
            with self.subTest(path=path):
                base = self.run_command("git", "rev-parse", "HEAD").strip()
                self.commit({path: "// security change\n"})
                result = self.select(base, "HEAD")
                self.assertEqual(result["test_impact"], "__ALL__")
                self.assertEqual(result["test_impact_reason"], f"foundational:{path}")

    def test_docs_only_still_short_circuits(self):
        self.commit({"docs/guide.txt": "docs\n", "README.md": "docs\n"})
        result = self.select(self.base, "HEAD")
        self.assertEqual(result["test_impact"], "__SKIP__")
        self.assertEqual(result["test_impact_count"], "0")
        self.assertEqual(result["test_impact_reason"], "docs-only")

    def test_nonsecurity_diff_still_selects_tests(self):
        self.commit({"src/handlers/memories.rs": "// ordinary change\n"})
        result = self.select(self.base, "HEAD")
        self.assertEqual(result["test_impact"], "cli_subcommand_count_invariant")
        self.assertEqual(result["test_impact_count"], "1")

    def test_unreachable_foundational_base_fails_closed(self):
        self.commit({"src/handlers/memories.rs": "// ordinary change\n"})
        result = self.select(self.base, "HEAD", "missing-base")
        self.assertEqual(result["test_impact"], "__ALL__")
        self.assertEqual(result["test_impact_reason"], "foundational-diff-failed")

    def test_incremental_security_revert_runs_full_suite(self):
        self.commit({"src/identity/pubkey_bind.rs": "// binding change\n"})
        previous = self.run_command("git", "rev-parse", "HEAD").strip()
        self.run_command("git", "rm", "src/identity/pubkey_bind.rs")
        self.commit({"scripts/ordinary-helper.sh": "# unrelated follow-up\n"})
        result = self.select(previous, "HEAD", self.base)
        self.assertEqual(result["test_impact"], "__ALL__")

    def test_rename_out_of_security_directory_runs_full_suite(self):
        self.commit({"src/identity/pubkey_bind.rs": "// binding change\n"})
        previous = self.run_command("git", "rev-parse", "HEAD").strip()
        self.base = previous
        (self.repo / "docs").mkdir()
        self.run_command("git", "mv", "src/identity/pubkey_bind.rs", "docs/proof.md")
        self.commit({})
        result = self.select(previous, "HEAD")
        self.assertEqual(result["test_impact"], "__ALL__")
        result = self.classify(previous)
        self.assertEqual(result["docs_only"], "false")
        self.assertEqual(result["test_impact"], "__ALL__")

    def test_workflow_retains_full_suite_after_incremental_followup(self):
        self.commit({"src/identity/pubkey_bind.rs": "// binding change\n"})
        previous = self.run_command("git", "rev-parse", "HEAD").strip()
        self.commit({"scripts/ordinary-helper.sh": "# unrelated follow-up\n"})
        result = self.classify(previous)
        self.assertEqual(result["docs_only"], "false")
        self.assertEqual(result["test_impact"], "__ALL__")

    def test_workflow_docs_only_still_short_circuits(self):
        self.commit({"docs/guide.md": "docs\n"})
        result = self.classify(self.base)
        self.assertEqual(result["docs_only"], "true")
        self.assertEqual(result["test_impact"], "__SKIP__")

    def test_workflow_nonsecurity_followup_still_selects_tests(self):
        self.commit({"src/handlers/memories.rs": "// ordinary change\n"})
        previous = self.run_command("git", "rev-parse", "HEAD").strip()
        self.commit({"scripts/ordinary-helper.sh": "# unrelated follow-up\n"})
        result = self.classify(previous)
        self.assertEqual(result["docs_only"], "false")
        self.assertEqual(result["test_impact"], "cli_subcommand_count_invariant")

    def classify(self, previous):
        (self.repo / "output").unlink(missing_ok=True)
        workflow = (ROOT / ".github/workflows/ci.yml").read_text()
        step = workflow.split("      - id: cls\n", 1)[1]
        body = step.split("        run: |\n", 1)[1]
        lines = []
        for line in body.splitlines():
            if line and not line.startswith("          "):
                break
            lines.append(line[10:])
        self.assertTrue(lines, "classifier extraction must not be vacuous")
        self.run_command("bash", "-e", "-o", "pipefail", "-c", "\n".join(lines), env={
            **self.env, "EVENT_NAME": "pull_request", "PR_ACTION": "synchronize",
            "PR_BEFORE": previous, "PR_BASE_SHA": self.base,
            "RUNNER_TEMP": str(self.repo),
        })
        return dict(line.split("=", 1) for line in (self.repo / "output").read_text().splitlines())


if __name__ == "__main__":
    unittest.main(verbosity=2)
