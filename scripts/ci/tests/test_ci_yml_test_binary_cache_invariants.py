#!/usr/bin/env python3
"""ci.yml invariants for the per-test-binary result cache (#6384 r2).

Text checks only (standard library, no YAML parser), so they run anywhere:

* r1 M5: lookup has its own flag, CI_TEST_BINARY_CACHE_LOOKUP, which is '1'
  only for pull_request and therefore '0' for every push to release/**; the
  script requires it as well as CI_TEST_BINARY_CACHE.
* r1 M2: the cache flag is never on for chain/** pushes, and the workflow
  comment states that a pull_request never writes the manifest.

Run: python3 -m unittest discover -s scripts/ci/tests -p 'test_*.py'
"""
import re
import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

import test_binary_cache as tbc  # noqa: E402

CI_YML = HERE.parents[2] / '.github' / 'workflows' / 'ci.yml'


def env_lines(text, name):
    return re.findall(r'^\s+%s:\s*(.+)$' % re.escape(name), text, re.M)


class LookupFlag6384M5(unittest.TestCase):
    def setUp(self):
        self.text = CI_YML.read_text()

    def test_lookup_flag_is_pull_request_only(self):
        vals = env_lines(self.text, 'CI_TEST_BINARY_CACHE_LOOKUP')
        self.assertEqual(len(vals), 1, vals)
        expr = vals[0]
        self.assertIn("github.event_name == 'pull_request'", expr)
        self.assertNotIn('release', expr)
        self.assertNotIn('push', expr)
        self.assertNotIn('chain', expr)
        self.assertTrue(expr.rstrip().endswith("&& '1' || '0' }}"), expr)

    def test_cache_flag_never_covers_chain_pushes(self):
        vals = env_lines(self.text, 'CI_TEST_BINARY_CACHE')
        self.assertEqual(len(vals), 1, vals)
        self.assertNotIn('chain/', vals[0])
        self.assertIn("startsWith(github.ref, 'refs/heads/release/')", vals[0])

    def test_both_flags_sit_in_the_same_step_env(self):
        i = self.text.index('CI_TEST_BINARY_CACHE:')
        j = self.text.index('CI_TEST_BINARY_CACHE_LOOKUP:')
        between = self.text[min(i, j):max(i, j)]
        self.assertNotIn('- name:', between)

    def test_comment_states_pull_request_never_writes(self):
        self.assertIn('lookup only; it NEVER writes the manifest', self.text)

    def test_script_guard_needs_both_flags(self):
        pr = 'refs/pull/1/merge'
        self.assertFalse(tbc.cache_policy({'CI_TEST_BINARY_CACHE': '1'}, 'pull_request', pr)[0])
        self.assertFalse(tbc.cache_policy({'CI_TEST_BINARY_CACHE': '1', 'CI_TEST_BINARY_CACHE_LOOKUP': '0'},
                                          'pull_request', pr)[0])
        self.assertFalse(tbc.cache_policy({'CI_TEST_BINARY_CACHE_LOOKUP': '1'}, 'pull_request', pr)[0])
        self.assertTrue(tbc.cache_policy({'CI_TEST_BINARY_CACHE': '1', 'CI_TEST_BINARY_CACHE_LOOKUP': '1'},
                                         'pull_request', pr)[0])

    def test_script_never_looks_up_on_release_push_even_with_the_flag_forced(self):
        env = {'CI_TEST_BINARY_CACHE': '1', 'CI_TEST_BINARY_CACHE_LOOKUP': '1'}
        for ref in ('refs/heads/release/v1.0.0', 'release/v1.0.0'):
            self.assertEqual(tbc.cache_policy(env, 'push', ref)[:2], (False, True))


class PlanDeadline6384M3(unittest.TestCase):
    """r1 M3: ci.yml bounds the plan and restores the full lists if it fails."""

    def setUp(self):
        self.text = CI_YML.read_text()

    def test_plan_has_a_timeout_and_a_restore_fallback(self):
        i = self.text.index('test_binary_cache.py plan')
        j = self.text.index('pg_isolate_split.py', i)
        block = self.text[i:j]
        self.assertIn('--timeout-seconds 120', block)
        self.assertIn('test_binary_cache.py restore --shard-dir "$sd"', block)
        self.assertIn('|| return', block[block.index('test_binary_cache.py restore'):])

    def test_plan_runs_under_the_outer_watchdog_when_available(self):
        i = self.text.index('cache_plan_to=(')
        self.assertIn('"$TIMEOUT_BIN"', self.text[i:i + 200])


if __name__ == '__main__':
    unittest.main()
