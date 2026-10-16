#!/usr/bin/env python3
"""Pins for .config/nextest.toml and the nextest wiring in ci.yml (#7259).

Run: python3 -m unittest discover -s scripts/ci/tests -p test_nextest_config_7259.py

Text-level checks (no TOML or YAML parser is available on every node):
the ci profile keeps cargo-test parity (no retries, no fail-fast), keeps a
per-test timeout no looser than the watchdog it replaces, claims no JUnit file, and
serialises exactly the lib Postgres prefixes that the sharded run keeps
serial. ci.yml runs every non-doc test leg through nextest, installed from
crates.io at one pinned version.
"""
import re
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
CONFIG = (REPO / '.config' / 'nextest.toml').read_text(encoding='utf-8')
CI_YML = (REPO / '.github' / 'workflows' / 'ci.yml').read_text(encoding='utf-8')
PREFIXES = REPO / 'scripts' / 'ci' / 'lib_pg_prefixes.txt'
# The per-invocation watchdog floor in ci.yml (sqlite leg); a single test must
# never be allowed longer than a whole invocation.
SMALLEST_WATCHDOG_SECS = 2100


def profile(name):
    """Text of ``[profile.<name>]`` up to the next top-level table."""
    match = re.search(r'^\[profile\.%s\]\n(.*?)(?=^\[|\Z)' % re.escape(name), CONFIG, re.M | re.S)
    assert match, 'profile %s missing' % name
    return match.group(1)


def secs(text):
    return int(re.search(r'(\d+)s', text).group(1))


class CiProfile(unittest.TestCase):
    def test_no_retries_and_no_fail_fast_keep_cargo_test_parity(self):
        body = profile('ci')
        self.assertRegex(body, r'(?m)^retries\s*=\s*0\b')
        self.assertRegex(body, r'(?m)^fail-fast\s*=\s*false\b')

    def test_per_test_timeout_is_defined_and_stricter_than_the_watchdog(self):
        body = profile('ci')
        match = re.search(r'slow-timeout\s*=\s*\{\s*period\s*=\s*"(\d+)s"\s*,\s*terminate-after\s*=\s*(\d+)\s*\}', body)
        self.assertIsNotNone(match, body)
        self.assertLess(int(match.group(1)) * int(match.group(2)), SMALLEST_WATCHDOG_SECS)

    def test_pass_lines_are_printed_so_the_log_can_be_compared(self):
        self.assertRegex(profile('ci'), r'(?m)^status-level\s*=\s*"pass"')

    def test_ci_profile_makes_no_junit_claim_and_its_header_matches_the_settings(self):
        self.assertNotIn('[profile.ci.junit]', CONFIG)
        self.assertNotIn('machine-readable twin', CONFIG)
        header = re.search(r'(?m)^#\s+ci\s+[^\n]*$', CONFIG).group(0)
        retries = re.search(r'(?m)^retries\s*=\s*(\d+)', profile('ci')).group(1)
        self.assertIn('retries=%s' % retries, header)


class PostgresTestGroup(unittest.TestCase):
    def test_group_is_single_threaded(self):
        self.assertRegex(CONFIG, r'(?m)^\[test-groups\]\npg-lib-serial\s*=\s*\{\s*max-threads\s*=\s*1\s*\}')

    def test_override_maps_the_group_by_the_lib_postgres_prefixes(self):
        match = re.search(r'\[\[profile\.ci\.overrides\]\]\nfilter\s*=\s*\'([^\']+)\'\ntest-group\s*=\s*["\']pg-lib-serial["\']', CONFIG)
        self.assertIsNotNone(match)
        self.assertIn('kind(lib)', match.group(1))
        in_filter = re.findall(r'test\(~([^)]+)\)', match.group(1))
        expected = [ln.strip() for ln in PREFIXES.read_text(encoding='utf-8').splitlines()
                    if ln.strip() and not ln.startswith('#')]
        self.assertEqual(sorted(in_filter), sorted(expected))


class WorkflowWiring(unittest.TestCase):
    def test_the_version_is_pinned_once_in_a_workflow_level_env(self):
        pins = re.findall(r'(?m)^  NEXTEST_VERSION: "(\d+\.\d+\.\d+)"$', CI_YML)
        self.assertEqual(len(pins), 1, 'exactly one workflow-level NEXTEST_VERSION')
        self.assertEqual(CI_YML.count(pins[0]), 1, 'the version literal appears once in ci.yml')

    def test_every_install_goes_through_the_per_job_helper_from_crates_io(self):
        steps = re.findall(r'(?m)^        run: python3 -I scripts/ci/install_nextest\.py$', CI_YML)
        self.assertGreaterEqual(len(steps), 3)
        self.assertNotIn('cargo install cargo-nextest', CI_YML)
        self.assertNotIn('cargo nextest --version', CI_YML)
        self.assertNotRegex(CI_YML, r'(?i)uses:\s*\S*nextest')
        helper = (REPO / 'scripts' / 'ci' / 'install_nextest.py').read_text(encoding='utf-8')
        self.assertIn("'--locked'", helper)
        self.assertIn('RUNNER_TEMP', helper)

    def test_hosted_runs_restore_the_installed_root_through_the_existing_cache_action(self):
        self.assertGreaterEqual(CI_YML.count('cache-directories: ${{ runner.temp }}/cargo-nextest'), 3)

    def test_timed_runs_use_nextest_with_the_ci_profile_and_no_fail_fast(self):
        lines = [ln for ln in CI_YML.splitlines() if 'cargo nextest run' in ln and not ln.lstrip().startswith('#')]
        self.assertGreaterEqual(len(lines), 3)
        for line in lines:
            self.assertIn('--profile ci', line)
        timed = [ln for ln in lines if 'TIMEOUT_BIN' in ln or '--no-fail-fast' in ln]
        for line in timed:
            self.assertIn('--no-fail-fast', line)

    def test_doc_tests_stay_on_cargo_test(self):
        self.assertIn('cargo test --doc --no-fail-fast "$@"', CI_YML)
        self.assertNotRegex(CI_YML, r'nextest run[^\n]*--doc')

    def test_the_translator_is_used_for_the_libtest_tail(self):
        self.assertIn('scripts/ci/nextest_args.py', CI_YML)


if __name__ == '__main__':
    unittest.main()
