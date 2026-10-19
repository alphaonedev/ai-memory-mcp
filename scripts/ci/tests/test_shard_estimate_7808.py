#!/usr/bin/env python3
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""Reject unusable manifest estimates through the gate and CLI (#7808)."""
import argparse
import io
import json
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
SCRATCH = REPO / '.local-runs' / 'shard-estimate-7808'
INVALID_VALUES = (None, True, False, '', '123', 'bad', 'nan', 'inf', [], {},
                  -1, -0.25, float('nan'), float('inf'), -float('inf'), 10 ** 1000)
INVALID_CONTAINERS = (None, True, 1, 'bad', [], [{}])
BUDGET = 1000


class ShardEstimate7808(unittest.TestCase):
    def setUp(self):
        SCRATCH.mkdir(parents=True, exist_ok=True)
        self.temp = tempfile.TemporaryDirectory(dir=SCRATCH)
        self.addCleanup(self.temp.cleanup)
        self.manifest = Path(self.temp.name) / 'manifest.json'
        self.argv = ['gate', '--manifest', str(self.manifest)]
        for shard in sb.SHARDS:
            self.argv.extend(['--budget', '%s=%d' % (shard, BUDGET)])

    def valid(self, value=0):
        return {'estimate_seconds': {key: value for key in sb.MANIFEST_KEY.values()}}

    def invoke(self, payload):
        self.manifest.write_text(json.dumps(payload))
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            rc = sb.main(self.argv)
        return rc, out.getvalue(), err.getvalue()

    def test_7808_each_shard_rejects_invalid_values_as_budget_error(self):
        args = argparse.Namespace(manifest=str(self.manifest),
                                  budget=['%s=%d' % (s, BUDGET) for s in sb.SHARDS])
        for shard, key in sb.MANIFEST_KEY.items():
            for value in INVALID_VALUES:
                with self.subTest(shard=shard, value=value):
                    payload = self.valid()
                    payload['estimate_seconds'][key] = value
                    self.manifest.write_text(json.dumps(payload))
                    with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                        with self.assertRaises(sb.BudgetError):
                            sb.gate(args)

    def test_7808_malformed_shapes_and_missing_keys_return_structured_error(self):
        payloads = list(INVALID_CONTAINERS) + [{}]
        payloads += [{'estimate_seconds': value} for value in INVALID_CONTAINERS]
        for key in sb.MANIFEST_KEY.values():
            missing = self.valid()
            del missing['estimate_seconds'][key]
            payloads.append(missing)
        for payload in payloads:
            with self.subTest(payload=payload):
                rc, out, err = self.invoke(payload)
                self.assertEqual(rc, sb.RC_BAD)
                self.assertIn('::error::[#7343 shard-budget]', err)
                self.assertEqual(out, '')

    def test_7808_zero_and_finite_numeric_values_remain_valid(self):
        for value in (0, 0.0, -0.0, 1, 1.25):
            with self.subTest(value=value):
                rc, out, err = self.invoke(self.valid(value))
                self.assertEqual(rc, sb.RC_OK)
                self.assertEqual(err, '')
                for shard in sb.SHARDS:
                    self.assertIn('shard %s estimate' % shard, out)

    def test_7808_calibration_overflow_returns_structured_error(self):
        payload = self.valid()
        payload['estimate_seconds'][sb.MANIFEST_KEY['parallel_2']] = 1e308
        rc, out, err = self.invoke(payload)
        self.assertEqual(rc, sb.RC_BAD)
        self.assertIn('::error::[#7343 shard-budget]', err)
        self.assertEqual(out, '')

    def test_7808_cli_invalid_values_and_containers_exit_two_without_traceback(self):
        payloads = list(INVALID_CONTAINERS) + [{}]
        payloads += [{'estimate_seconds': value} for value in INVALID_CONTAINERS]
        for key in sb.MANIFEST_KEY.values():
            missing = self.valid()
            del missing['estimate_seconds'][key]
            payloads.append(missing)
            for value in INVALID_VALUES + (1e308,):
                payload = self.valid()
                payload['estimate_seconds'][key] = value
                payloads.append(payload)
        # Serial's scale is below one, so 1e308 is finite and fails its budget
        # normally; the parallel scales overflow and must fail as bad input.
        for payload in payloads:
            with self.subTest(payload=payload):
                self.manifest.write_text(json.dumps(payload))
                proc = subprocess.run([sys.executable, str(HERE.parent / 'shard_budget.py')]
                                      + self.argv, capture_output=True, text=True, check=False)
                self.assertEqual(proc.returncode, sb.RC_BAD)
                self.assertIn('::error::', proc.stderr)
                self.assertNotIn('Traceback', proc.stderr)
                serial = payload.get('estimate_seconds', {}) if isinstance(payload, dict) else {}
                if isinstance(serial, dict) and serial.get(sb.MANIFEST_KEY['serial']) == 1e308:
                    self.assertIn('[#7343 fail-fast]', proc.stderr)
                else:
                    self.assertIn('[#7343 shard-budget]', proc.stderr)
                    self.assertEqual(proc.stdout, '')


if __name__ == '__main__':
    unittest.main()
