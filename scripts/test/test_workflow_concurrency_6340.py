#!/usr/bin/env python3
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""Pin the concurrency semantics #6340 introduced, and their documentation.

THE CHANGE (#6340). ci.yml, coverage.yml, postgres-ignored.yml and
cert-postgres-age.yml set ``cancel-in-progress`` to
``${{ github.event_name == 'pull_request' }}``: only a pull_request run cancels
an in-progress run in its group, so a push to release/**, main or develop is not
cancelled by a later push while it is IN PROGRESS.

WHAT IT DOES NOT DO (GitHub semantics, pinned so the docs cannot overclaim):
  * A PENDING (queued) run is still replaced when a newer run queues in the same
    group, whatever ``cancel-in-progress`` says.
  * ci.yml and coverage.yml key the group by ref WITHOUT ``github.event_name``
    (deliberate: an internal PR's pull_request run and its head-branch push run
    coalesce, so one sha is not tested twice). A pull_request run on the same
    branch can therefore still cancel an in-progress push run there.
    postgres-ignored.yml and cert-postgres-age.yml include ``github.event_name``
    and cannot.

Stdlib only; the top-level ``concurrency:`` block is read by line, closed-world:
a block this reader cannot parse is a failure.
"""
import argparse
import re
import sys
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
WF = REPO / ".github" / "workflows"
CANCEL_EXPR = "${{ github.event_name == 'pull_request' }}"
FORK_SAFE_TAIL = (
    "${{ github.event.pull_request.head.repo.full_name == github.repository "
    "&& github.event.pull_request.head.ref || github.event.pull_request.number "
    "|| github.ref_name }}"
)
# file -> whether its group key is event-distinct (contains github.event_name)
EXPECTED = {
    "ci.yml": False,
    "coverage.yml": False,
    "postgres-ignored.yml": True,
    "cert-postgres-age.yml": True,
}
CHANGELOG = REPO / "changelog.d" / "6340.fixed.md"


def read_concurrency(path):
    """Return (group, cancel) of the top-level concurrency block, or raise."""
    lines = path.read_text(encoding="utf-8").splitlines()
    starts = [i for i, ln in enumerate(lines) if ln == "concurrency:"]
    if len(starts) != 1:
        raise ValueError("%s: expected exactly one top-level 'concurrency:' line, found %d"
                         % (path.name, len(starts)))
    out = {}
    for ln in lines[starts[0] + 1:]:
        if not ln.strip() or ln.lstrip().startswith("#"):
            continue
        if not ln.startswith("  "):
            break
        m = re.match(r"^  (group|cancel-in-progress): (.+)$", ln)
        if not m:
            raise ValueError("%s: unreadable concurrency row: %r" % (path.name, ln))
        if m.group(1) in out:
            raise ValueError("%s: duplicate key %s" % (path.name, m.group(1)))
        out[m.group(1)] = m.group(2).strip()
    if set(out) != {"group", "cancel-in-progress"}:
        raise ValueError("%s: concurrency block keys %s" % (path.name, sorted(out)))
    return out["group"], out["cancel-in-progress"]


class ConcurrencyInvariants6340(unittest.TestCase):
    def test_cancel_in_progress_is_pull_request_only(self):
        for name in EXPECTED:
            _, cancel = read_concurrency(WF / name)
            self.assertEqual(cancel, CANCEL_EXPR, name)

    def test_group_keys_stay_fork_safe(self):
        for name in EXPECTED:
            group, _ = read_concurrency(WF / name)
            self.assertTrue(group.endswith(FORK_SAFE_TAIL),
                            "%s: group key lost the fork-PR-safe chained ref: %s" % (name, group))

    def test_event_distinct_matrix_matches_documentation(self):
        # Changing a file here changes what can cancel an in-progress push run;
        # update this table, the module docstring and changelog.d/6340.fixed.md together.
        for name, distinct in EXPECTED.items():
            group, _ = read_concurrency(WF / name)
            self.assertEqual("github.event_name" in group, distinct, name)

    def test_changelog_does_not_overclaim(self):
        text = CHANGELOG.read_text(encoding="utf-8")
        self.assertNotIn("never cancelled", text)
        self.assertIn("in progress", text)
        self.assertIn("queued", text)
        self.assertIn("pull_request run", text)


class ReaderRejects(unittest.TestCase):
    def _write(self, tmp, body):
        p = tmp / "wf.yml"
        p.write_text(body, encoding="utf-8")
        return p

    def test_reader_fails_closed(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            for body in (
                "on: push\n",
                "concurrency:\n  group: a\n",
                "concurrency:\n  group: a\n  cancel-in-progress: true\n  extra: 1\n",
                "concurrency:\n  group: a\nconcurrency:\n  group: b\n",
            ):
                with self.assertRaises(ValueError, msg=body):
                    read_concurrency(self._write(tmp, body))


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args()
    suite = unittest.defaultTestLoader.loadTestsFromModule(sys.modules[__name__])
    res = unittest.TextTestRunner(verbosity=2 if args.verbose else 1).run(suite)
    return 0 if res.wasSuccessful() else 1


if __name__ == "__main__":
    sys.exit(main())
