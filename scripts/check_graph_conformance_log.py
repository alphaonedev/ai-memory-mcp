#!/usr/bin/env python3
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""Fail-closed result/plan validation for the dedicated #3573 cert leg."""
import pathlib
import re
import sys
import tempfile
import unittest


CELLS = {f"query-{engine}-{depth}" for engine in ("cte", "age") for depth in (1, 2, 3)}
CELLS |= {f"lineage-{engine}-{direction}" for engine in ("cte", "age") for direction in ("true", "false")}
CELLS |= {"paths-on-age", "paths-invalidated", "timeline-cte", "timeline-age", "invalidate-cte",
          "invalidate-age", "divergence-timeline-cte", "divergence-timeline-age"}


def verify(root):
    listed = sum(line.endswith(": test") for line in (root / "list.log").read_text().splitlines())
    log = (root / "run.log").read_text()
    result = re.findall(r"test result: ok\. (\d+) passed; 0 failed; 0 ignored;", log)
    if len(result) != 1 or int(result[0]) != listed or listed < 5:
        raise ValueError("missing/partial test execution")
    if re.search(r"\bskip(?:ped)?\s*:", log, re.I):
        raise ValueError("skip in mandatory cert leg")
    if log.count("GRAPH_CASE declared-present") != 2:
        raise ValueError("both native tests must declare actual AGE")
    cells = re.findall(r"GRAPH_CELL ([\w-]+) plans=(\d+)", log)
    if {cell for cell, _ in cells} != CELLS or len(cells) != len(CELLS):
        raise ValueError("missing or duplicate matrix cell")
    for cell, count in cells:
        plans = (root / f"{cell}.jsonl").read_text().splitlines()
        if len(plans) != int(count) or not plans or any(not p.startswith(f"PLAN {cell} ") for p in plans):
            raise ValueError("missing plan evidence")
    return f"GRAPH_COMPLETE tests={listed} cells={len(cells)}"


class GateTests(unittest.TestCase):
    """Each rejection starts with a valid control over the same sink."""
    def setUp(self):
        scratch = pathlib.Path(__file__).resolve().parents[1] / ".local-runs"
        scratch.mkdir(exist_ok=True)
        self.tmp = tempfile.TemporaryDirectory(prefix="graph-gate-", dir=scratch)
        self.addCleanup(self.tmp.cleanup)
        self.root = pathlib.Path(self.tmp.name)
        (self.root / "list.log").write_text("".join(f"test_{n}: test\n" for n in range(5)))
        self.log = "GRAPH_CASE declared-present\n" * 2
        self.log += "".join(f"GRAPH_CELL {cell} plans=1\n" for cell in sorted(CELLS))
        self.log += "test result: ok. 5 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out\n"
        (self.root / "run.log").write_text(self.log)
        for cell in CELLS:
            (self.root / f"{cell}.jsonl").write_text(f"PLAN {cell} synthetic-test-only\n")
        self.assertEqual(verify(self.root), "GRAPH_COMPLETE tests=5 cells=18")

    def test_rejects_vacuous_summary(self):
        (self.root / "run.log").write_text(self.log.replace("5 passed", "0 passed"))
        with self.assertRaisesRegex(ValueError, "partial test execution"):
            verify(self.root)

    def test_rejects_missing_summary(self):
        (self.root / "run.log").write_text(self.log.split("test result:")[0])
        with self.assertRaisesRegex(ValueError, "partial test execution"):
            verify(self.root)

    def test_rejects_hidden_skip(self):
        (self.root / "run.log").write_text(self.log + "skip: AGE absent\n")
        with self.assertRaisesRegex(ValueError, "skip in mandatory"):
            verify(self.root)

    def test_rejects_missing_cell_even_with_stale_plan_file(self):
        (self.root / "run.log").write_text(self.log.replace("GRAPH_CELL invalidate-age plans=1\n", ""))
        with self.assertRaisesRegex(ValueError, "matrix cell"):
            verify(self.root)

    def test_rejects_empty_plan(self):
        (self.root / "invalidate-age.jsonl").write_text("")
        with self.assertRaisesRegex(ValueError, "plan evidence"):
            verify(self.root)

    def test_rejects_undeclared_engine(self):
        (self.root / "run.log").write_text(self.log.replace("declared-present", "undeclared"))
        with self.assertRaisesRegex(ValueError, "declare actual AGE"):
            verify(self.root)


if __name__ == "__main__":
    if sys.argv[1:] == ["--self-test"]:
        unittest.main(argv=[sys.argv[0]], verbosity=2)
    else:
        print(verify(pathlib.Path(sys.argv[1])))
