# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""Parity of scripts/ci/test_impact.py with the retired shell selector (#8077).

The shell selector is kept OUT of the tree at .local-runs/ci-test-impact.sh
(git show 7f9df22e11bb6aa16495b5408a1f557e79327e43:scripts/ci-test-impact.sh,
chmod 755). When that copy is absent the suite skips, so it stays green once the
shell file is gone. The cases mirror scripts/test/test_ci_test_impact.py; no diff
touches a manifest-inventoried path.
"""

import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

REPO = Path(__file__).resolve().parents[3]
SCRATCH = REPO / ".local-runs"
SHELL_COPY = SCRATCH / "ci-test-impact.sh"
PY_SELECTOR = REPO / "scripts/ci/test_impact.py"
GATE = REPO / "scripts/ci/manifest_owned_paths.py"
KEYS = ("test_impact", "test_impact_count", "test_impact_total", "test_impact_reason")
BASE_FILES = {
    ".gitignore": "output\n",
    "Cargo.toml": '[[test]]\nname = "acceptance_nhi_sqlite"\n',
    "tests/acceptance/acceptance_nhi_sqlite.rs": "// fixture\n",
    "tests/cli_subcommand_count_invariant.rs": "// fixture\n",
    "tests/memories_query.rs": "// fixture\n",
}
SECURITY_PATHS = (
    "src/identity/nested/proof.rs", "src/handlers/admin.rs", "src/storage/pubkey_history.rs",
    "src/federation/sync.rs", "src/store/sqlite.rs", "migrations/nested/schema.sql",
    "scripts/qc-codegraph-allowlists/for-admin-bypass.txt",
)
# Each case: list of commits (dict path -> text); last commit is the diff under test.
CASES = {
    "pubkey_bind": [{"src/identity/pubkey_bind.rs": "// x\n"}],
    "docs_only": [{"docs/guide.txt": "d\n", "README.md": "d\n"}],
    "nonsecurity": [{"src/handlers/memories.rs": "// x\n"}],
    "token_overlap": [{"src/handlers/memories_query.rs": "// x\n"}],
    "direct_test_edit": [{"tests/memories_query.rs": "// y\n"}],
    "no_src_match": [{"scripts/helper.sh": "# x\n"}],
    "followup": [{"src/handlers/memories.rs": "// x\n"}, {"scripts/helper.sh": "# y\n"}],
}
for _path in SECURITY_PATHS:
    CASES["security:" + _path] = [{_path: "// s\n"}]


class ParityTest(unittest.TestCase):
    def setUp(self):
        if not SHELL_COPY.is_file():
            raise unittest.SkipTest("shell selector copy absent: " + str(SHELL_COPY))
        SCRATCH.mkdir(exist_ok=True)
        self.addCleanup(shutil.rmtree, str(SCRATCH / "parity-8077"), True)
        self.env = {
            **os.environ, "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_AUTHOR_NAME": "Parity", "GIT_AUTHOR_EMAIL": "p@example.invalid",
            "GIT_COMMITTER_NAME": "Parity", "GIT_COMMITTER_EMAIL": "p@example.invalid",
        }

    def git(self, repo, *args):
        return subprocess.run(["git"] + list(args), cwd=str(repo), env=self.env, check=True,
                              capture_output=True, text=True).stdout.strip()

    def commit(self, repo, files):
        for name, text in files.items():
            path = repo / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text, encoding="utf-8")
        self.git(repo, "add", "-f", "--", *sorted(files))
        self.git(repo, "-c", "commit.gpgsign=false", "commit", "-qm", "fixture")

    def build(self, name, commits):
        parent = SCRATCH / "parity-8077"
        parent.mkdir(exist_ok=True)
        repo = Path(tempfile.mkdtemp(dir=str(parent)))
        self.git(repo, "init", "-q")
        self.commit(repo, BASE_FILES)
        base = self.git(repo, "rev-parse", "HEAD")
        for files in commits:
            self.commit(repo, files)
        return repo, base

    def select(self, repo, argv):
        results = []
        for cmd in (["bash", str(SHELL_COPY)], [sys.executable, "-I", str(PY_SELECTOR)]):
            out = repo / "output"
            out.unlink() if out.exists() else None
            env = {**self.env, "GITHUB_OUTPUT": str(out)}
            subprocess.run(cmd + argv, cwd=str(repo), env=env, check=True, capture_output=True, text=True)
            results.append(dict(l.split("=", 1) for l in out.read_text().splitlines()))
        return results

    def test_cases_match_shell(self):
        for name, commits in sorted(CASES.items()):
            with self.subTest(case=name):
                repo, base = self.build(name, commits)
                shell, py = self.select(repo, [base, "HEAD"])
                for key in KEYS:
                    self.assertEqual(shell[key], py[key], key)

    def test_edge_arguments_match_shell(self):
        repo, base = self.build("edge", [{"src/handlers/memories.rs": "// x\n"}])
        for argv in ([], ["no-such-ref", "HEAD"], [base, "HEAD", "missing-base"], [base, "HEAD", base],
                     [base, "no-such-head"]):
            with self.subTest(argv=argv):
                shell, py = self.select(repo, argv)
                for key in KEYS:
                    self.assertEqual(shell[key], py[key], key)

    def test_incremental_revert_and_rename_match_shell(self):
        repo, base = self.build("rev", [{"src/identity/pubkey_bind.rs": "// b\n"}])
        previous = self.git(repo, "rev-parse", "HEAD")
        self.git(repo, "rm", "-q", "src/identity/pubkey_bind.rs")
        self.commit(repo, {"scripts/helper.sh": "# u\n"})
        shell, py = self.select(repo, [previous, "HEAD", base])
        self.assertEqual(shell, py)
        (repo / "docs").mkdir(exist_ok=True)
        self.commit(repo, {"src/handlers/zz.rs": "// z\n"})
        self.git(repo, "mv", "src/handlers/zz.rs", "docs/zz.md")
        self.git(repo, "-c", "commit.gpgsign=false", "commit", "-qm", "rename")
        shell, py = self.select(repo, [self.git(repo, "rev-parse", "HEAD~2"), "HEAD"])
        self.assertEqual(shell, py)


if __name__ == "__main__":
    unittest.main(verbosity=2)
