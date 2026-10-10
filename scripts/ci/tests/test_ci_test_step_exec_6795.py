#!/usr/bin/env python3
"""Executes the `Run tests (impact-aware)` step script of ci.yml with a stub cargo (#6795 r3).

Text pins cannot catch shell scoping faults (a `local WATCHDOG_SECS` shadowing the
outer value under `set -u` aborted every sqlite leg before cargo ran). This runs
the extracted script with bash, TIER=sqlite, a fresh JOB_T0 and a stub `cargo`.

Run: python3 -m unittest discover -s scripts/ci/tests
Python 3.9+, standard library only; the step script is bash 3.2 compatible.
"""
import os
import re
import subprocess
import tempfile
import textwrap
import time
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
CI = (REPO / '.github' / 'workflows' / 'ci.yml').read_text()


def step_script():
    m = re.search(r'      - name: Run tests \(impact-aware\)\n(.*?)\n        run: \|\n(.*?)\n      (?:#|- )', CI, re.S)
    if not m:
        raise AssertionError('Run tests step not found')
    return textwrap.dedent(m.group(2))


class StepExec(unittest.TestCase):
    def run_step(self, job_t0, impact='__ALL__', tier='sqlite'):
        with tempfile.TemporaryDirectory(dir=str(REPO / '.local-runs') if (REPO / '.local-runs').is_dir() else None) as d:
            d = Path(d)
            calls = d / 'cargo.calls'
            stub = d / 'bin' / 'cargo'
            stub.parent.mkdir()
            stub.write_text('#!/bin/sh\necho "$@" >> "%s"\nexit 0\n' % calls)
            stub.chmod(0o755)
            script = d / 'step.sh'
            script.write_text('#!/bin/bash\n' + step_script() + '\n')
            env = dict(os.environ)
            env.update({
                'PATH': '%s:%s' % (stub.parent, env.get('PATH', '')),
                'AI_MEMORY_NO_CONFIG': '1', 'TIER': tier, 'CI_NODE': 'ubuntu-latest',
                'TEST_IMPACT': impact, 'JOB_TIMEOUT_MIN': '95', 'JOB_T0': job_t0,
                'RUNNER_TEMP': str(d), 'GITHUB_ENV': str(d / 'env'),
                'TEST_RESULT_LOG': str(d / 'result.log'),
            })
            r = subprocess.run(['bash', str(script)], cwd=str(REPO), env=env,
                               capture_output=True, text=True, timeout=120)
            n = len(calls.read_text().splitlines()) if calls.exists() else 0
            return r, n

    def test_sqlite_full_suite_runs_cargo_with_fresh_job_start(self):
        r, n = self.run_step(str(int(time.time())))
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertGreaterEqual(n, 1)
        self.assertNotIn('unbound variable', r.stderr)

    def test_sqlite_impact_selected_runs_cargo(self):
        r, n = self.run_step(str(int(time.time())), impact='some_test')
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertGreaterEqual(n, 1)

    def test_non_numeric_job_start_falls_back_to_flat_watchdog(self):
        # #6834: leading-zero values are octal to bash arithmetic; '0' is no epoch.
        for bogus in ('bogus', '', '089', '0', '00', 'abc', '12abc'):
            r, n = self.run_step(bogus)
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
            self.assertGreaterEqual(n, 1)
            self.assertIn('::warning::[#6795] JOB_T0', r.stdout + r.stderr)
            self.assertIn('2100s', r.stdout)

    def test_clamp_applies_when_job_is_nearly_over(self):
        r, n = self.run_step(str(int(time.time()) - 95 * 60 + 100))
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn('60s per-invocation watchdog budget', r.stdout)


if __name__ == '__main__':
    unittest.main()
