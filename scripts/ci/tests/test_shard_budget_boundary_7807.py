#!/usr/bin/env python3
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""Keep fractional calibrated overruns from passing the shard gate (#7807)."""
import io
import json
import math
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
import shard_budget as sb  # noqa: E402

REPO = HERE.parents[2]
SCRATCH = REPO / '.local-runs' / 'shard-budget-boundary-7807'
RAW_EQUAL = 1000
SHARD_BUDGETS = {'serial': 660, 'parallel_1': 1760, 'parallel_2': 2630}
OVER_ESTIMATES = (1000.1, math.nextafter(RAW_EQUAL, math.inf))
UNDER_ESTIMATES = (999.9, math.nextafter(math.nextafter(RAW_EQUAL, -math.inf), -math.inf))


class ShardBudgetBoundary7807(unittest.TestCase):
    def setUp(self):
        SCRATCH.mkdir(parents=True, exist_ok=True)
        self.temp = tempfile.TemporaryDirectory(dir=SCRATCH)
        self.addCleanup(self.temp.cleanup)
        self.manifest = Path(self.temp.name) / 'manifest.json'
        self.argv = ['gate', '--manifest', str(self.manifest)]
        for shard, budget in SHARD_BUDGETS.items():
            self.argv.extend(['--budget', '%s=%d' % (shard, budget)])

    def invoke(self, shard, raw, cli=False):
        estimates = {key: 0 for key in sb.MANIFEST_KEY.values()}
        estimates[sb.MANIFEST_KEY[shard]] = raw
        self.manifest.write_text(json.dumps({'estimate_seconds': estimates}))
        if cli:
            proc = subprocess.run([sys.executable, str(HERE.parent / 'shard_budget.py')]
                                  + self.argv, capture_output=True, text=True, check=False)
            return proc.returncode, proc.stdout, proc.stderr
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            rc = sb.main(self.argv)
        return rc, out.getvalue(), err.getvalue()

    def test_7807_each_shard_exact_equality_passes(self):
        for shard in sb.SHARDS:
            with self.subTest(shard=shard):
                self.assertEqual(RAW_EQUAL * sb.ESTIMATE_SCALE[shard], SHARD_BUDGETS[shard])
                rc, out, err = self.invoke(shard, RAW_EQUAL)
                self.assertEqual(rc, sb.RC_OK)
                self.assertEqual(err, '')
                self.assertIn('shard %s estimate' % shard, out)

    def test_7807_each_shard_fractional_overrun_fails_with_ceiling_diagnostic(self):
        for shard in sb.SHARDS:
            for raw in OVER_ESTIMATES:
                with self.subTest(shard=shard, raw=raw):
                    self.assertGreater(raw * sb.ESTIMATE_SCALE[shard], SHARD_BUDGETS[shard])
                    rc, out, err = self.invoke(shard, raw)
                    self.assertEqual(rc, sb.RC_BAD)
                    self.assertIn('::error::[#7343 fail-fast] shard %s' % shard, err)
                    self.assertIn('estimate %ds' % (SHARD_BUDGETS[shard] + 1), err)
                    self.assertIn('budget %ds' % SHARD_BUDGETS[shard], err)
                    self.assertIn('ceiling', err)
                    self.assertNotIn('shard %s estimate' % shard, out)

    def test_7807_each_shard_fractional_under_budget_passes(self):
        for shard in sb.SHARDS:
            for raw in UNDER_ESTIMATES:
                with self.subTest(shard=shard, raw=raw):
                    self.assertLess(raw * sb.ESTIMATE_SCALE[shard], SHARD_BUDGETS[shard])
                    rc, _, err = self.invoke(shard, raw)
                    self.assertEqual(rc, sb.RC_OK)
                    self.assertEqual(err, '')

    def test_7807_cli_each_shard_preserves_all_three_boundary_verdicts(self):
        for shard in sb.SHARDS:
            for raw, expected in ((RAW_EQUAL, sb.RC_OK), (OVER_ESTIMATES[0], sb.RC_BAD),
                                  (UNDER_ESTIMATES[0], sb.RC_OK)):
                with self.subTest(shard=shard, raw=raw):
                    rc, _, err = self.invoke(shard, raw, cli=True)
                    self.assertEqual(rc, expected)
                    if expected == sb.RC_BAD:
                        self.assertIn('::error::[#7343 fail-fast] shard %s' % shard, err)
                    else:
                        self.assertEqual(err, '')


if __name__ == '__main__':
    unittest.main()
