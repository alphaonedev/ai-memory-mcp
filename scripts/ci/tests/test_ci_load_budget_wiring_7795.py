#!/usr/bin/env python3
"""Budget admission must surround builds without changing CI coverage (#7795)."""
import unittest
import os
import subprocess
import tempfile
import textwrap
import time
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
CI = (REPO / '.github/workflows/ci.yml').read_text()
IGNORED = (REPO / '.github/workflows/postgres-ignored.yml').read_text()


class Wiring7795(unittest.TestCase):
    def test_7795_full_suite_reserves_are_conditional_on_full_impact(self):
        self.assertIn("test_impact == '__ALL__' || needs.classify.outputs.test_impact == '') && (matrix.tier == 'enterprise-fed' && 3913 || 1500) || 0", CI)
        self.assertIn('--job-timeout-minutes "${{ matrix.timeout }}"', CI)

    def test_7795_shard_recheck_after_build_and_before_launch(self):
        body = CI[CI.index('          run_sharded() {'):]
        build = body.index('cargo test --no-run')
        check = body.index('check_suite_budget || return "$?"')
        launch = body.index('( run_shard serial')
        self.assertLess(build, check)
        self.assertLess(check, launch)
        self.assertEqual(body[:launch].count('check_suite_budget'), 1)
        shard = CI[CI.index('          run_shard() {'):CI.index('          run_sharded() {')]
        self.assertNotIn('check_suite_budget', shard)

    def test_7795_recheck_is_zero_wait_using_job_cap(self):
        check = CI[CI.index('          check_suite_budget() {'):].split('\n          }', 1)[0]
        self.assertIn('--max-wait-secs 0', check)
        self.assertIn('--job-timeout-minutes "$JOB_TIMEOUT_MIN"', check)
        self.assertIn('LOAD_GATE_SELF_HOSTED', check)

    def test_7795_ignored_anchors_start_before_checkout(self):
        self.assertLess(IGNORED.index('JOB_T0=$(date +%s)'), IGNORED.index('actions/checkout@'))
        self.assertIn('timeout-minutes: 60', IGNORED)
        self.assertEqual(IGNORED.count('--job-timeout-minutes 60'), 2)
        self.assertIn('LOAD_GATE_MIN_SUITE_SECS: "400"', IGNORED)

    def test_7795_ignored_budget_checks_surround_prebuild(self):
        gate = IGNORED.index('- name: Load gate (#7795)')
        build = IGNORED.index('cargo test --features sal-postgres -- --ignored --list |')
        check = IGNORED.index('--max-wait-secs 0')
        execute = IGNORED.index('cargo test --features sal-postgres -- --ignored --test-threads=1')
        self.assertLess(gate, build)
        self.assertLess(build, check)
        self.assertLess(check, execute)
        self.assertIn('bash scripts/check-cert-leg-nonvacuity.sh', IGNORED)

    def test_7795_ignored_prebuild_cannot_launch_underfunded_execution(self):
        body = IGNORED.split('      - name: cargo test --features sal-postgres -- --ignored\n', 1)[1]
        body = textwrap.dedent(body.split('        run: |\n', 1)[1].split('\n      - name:', 1)[0])
        body = body.replace('scripts/ci/load_gate.py', str(REPO / 'scripts/ci/load_gate.py'))
        scratch = REPO / '.local-runs'
        scratch.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(dir=scratch) as directory:
            root = Path(directory)
            cargo = root / 'cargo'
            cargo.write_text('#!/bin/sh\nprintf "%s\\n" "$*" >> "$CALLS"\necho "sample: test"\n')
            cargo.chmod(0o755)
            env = dict(os.environ, PATH=str(root) + os.pathsep + os.environ['PATH'],
                       CALLS=str(root / 'calls'), JOB_T0=str(int(time.time()) - 3600 + 500),
                       LOAD_GATE_MIN_SUITE_SECS='400')
            result = subprocess.run(['bash', '-c', body], cwd=root, env=env,
                                    capture_output=True, text=True, timeout=30)
            self.assertEqual(result.returncode, 3, result.stdout + result.stderr)
            self.assertEqual((root / 'calls').read_text().splitlines(),
                             ['test --features sal-postgres -- --ignored --list'])
            self.assertIn('configured suite reserve 400', result.stdout)


if __name__ == '__main__':
    unittest.main()
