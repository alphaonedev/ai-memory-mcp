#!/usr/bin/env python3
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""Pin #8174: the two Postgres workflows run on EITHER fed node.

``postgres-ignored.yml`` and ``cert-postgres-age.yml`` used to pin their job to
``[self-hosted, linux-fed]`` while the macos-fed tier idled. The custom label
``fed`` is carried by every runner on both nodes, so ``[self-hosted, fed]``
lets whichever node is free take the job. Properties pinned (stdlib only,
Python 3.9+; workflows are read by line because PyYAML is not guaranteed on
every node):

  (a) the single job of each workflow has ``runs-on: [self-hosted, fed]``;
  (b) no ``run:`` block contains a GNU-only token (a macOS runner has BSD tools);
  (c) each workflow self-heals the hand-built macOS AGE install through
      ``scripts/ci/ensure-age-extension.py`` behind a ``$RUNNER_OS`` check, the
      same branch ci.yml takes for its macos-fed enterprise-fed leg.

Run: python3 -m unittest discover -s scripts/ci/tests -p 'test_pg_workflows_fed_label_8174.py'
"""
import re
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
WORKFLOWS = (
    REPO / ".github" / "workflows" / "postgres-ignored.yml",
    REPO / ".github" / "workflows" / "cert-postgres-age.yml",
)
EXPECTED_RUNS_ON = ["self-hosted", "fed"]
HEAL_SCRIPT = "scripts/ci/ensure-age-extension.py"
HEAL_GUARD = 'if [ "$RUNNER_OS" = "macOS" ]; then'
# GNU-only invocations (name, regex). Each is absent or different on macOS.
GNU_ONLY_TOKENS = (
    ("gtimeout", re.compile(r"\bgtimeout\b")),
    ("timeout", re.compile(r"(?<![-\w])timeout\s")),
    ("du -b", re.compile(r"\bdu\s+-\w*b")),
    ("stat -c", re.compile(r"\bstat\s+-c\b")),
    ("sed -i without suffix", re.compile(r"\bsed\s+(-\w*i\b|--in-place)")),
    ("readlink -f", re.compile(r"\breadlink\s+-f\b")),
    ("date -d", re.compile(r"\bdate\s+-d\b")),
    ("grep -P", re.compile(r"\bgrep\s+-\w*P")),
    ("xargs -r", re.compile(r"\bxargs\s+-\w*r\b")),
    ("sort -V", re.compile(r"\bsort\s+-\w*V")),
)


def lines_of(path):
    return path.read_text(encoding="utf-8").splitlines()


def runs_on_lists(path):
    found = []
    for ln in lines_of(path):
        m = re.match(r"^    runs-on:\s*\[(.*)\]\s*$", ln)
        if m:
            found.append([x.strip() for x in m.group(1).split(",")])
    return found


def run_blocks(path):
    """Each ``run:`` body as a list of non-comment lines."""
    lines = lines_of(path)
    blocks = []
    i = 0
    while i < len(lines):
        m = re.match(r"^(\s*)(?:- )?run:\s*(.*)$", lines[i])
        if not m:
            i += 1
            continue
        indent = len(m.group(1))
        rest = m.group(2).strip()
        body = []
        if rest and rest not in ("|", ">", "|-", ">-"):
            body.append(rest)
        i += 1
        while i < len(lines) and (not lines[i].strip() or len(lines[i]) - len(lines[i].lstrip()) > indent):
            if lines[i].strip() and not lines[i].lstrip().startswith("#"):
                body.append(lines[i])
            i += 1
        blocks.append(body)
    return blocks


class PgWorkflowsRunOnEitherFedNode(unittest.TestCase):
    def test_runs_on_is_the_shared_fed_label(self):
        for path in WORKFLOWS:
            with self.subTest(workflow=path.name):
                self.assertEqual(runs_on_lists(path), [EXPECTED_RUNS_ON])

    def test_no_gnu_only_token_in_any_run_block(self):
        for path in WORKFLOWS:
            blocks = run_blocks(path)
            self.assertGreaterEqual(len(blocks), 4, path.name)
            for body in blocks:
                for ln in body:
                    for name, rx in GNU_ONLY_TOKENS:
                        with self.subTest(workflow=path.name, token=name):
                            self.assertIsNone(rx.search(ln), ln.strip())

    def test_macos_age_self_heal_is_behind_a_runner_os_check(self):
        for path in WORKFLOWS:
            with self.subTest(workflow=path.name):
                text = "\n".join("\n".join(b) for b in run_blocks(path))
                self.assertIn(HEAL_GUARD, text)
                guard_at = text.index(HEAL_GUARD)
                heal_at = text.index(HEAL_SCRIPT)
                create_at = text.index("CREATE EXTENSION IF NOT EXISTS age")
                self.assertLess(guard_at, heal_at)
                self.assertLess(heal_at, create_at)


if __name__ == "__main__":
    unittest.main()
