#!/usr/bin/env python3
"""Invariants of the sharded enterprise-fed test step in .github/workflows/ci.yml (#6344).

Pins what review r1 (B3, B4, B5, B6) found unpinned: the shard watchdog and job
cap derived for the shards, three shard invocations each waited on separately
with every exit code propagated, quoted target arrays, the partition call, the
shard-log upload on failure, and the docs marking the old serial budget as
superseded.

Run: python3 -m unittest discover -s scripts/ci/tests
Python 3.9+, standard library only (the workflow is read as text).
"""
import re
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
CI = REPO / '.github' / 'workflows' / 'ci.yml'
DOC = REPO / 'docs' / 'ci' / 'CARRIER-BRANCH-GATES.md'
UPLOAD_PIN = 'actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02'

# Longest shard estimate (serial, scripts/ci/partition_test_binaries.py on the
# 1,006-executable target list with the run-6160 contended weights).
SHARD_ESTIMATE_SECS = 3913
SHARD_WATCHDOG_SECS = 5400
JOB_TIMEOUT_MIN = 120


def ci_text():
    return CI.read_text()


def function_body(text, name):
    """Body of a bash function `name() {` ... matching closing brace line."""
    m = re.search(r'^(\s*)%s\(\) \{\n' % re.escape(name), text, re.M)
    if not m:
        raise AssertionError('function %s() not found in ci.yml' % name)
    indent = m.group(1)
    end = text.index('\n%s}\n' % indent, m.end())
    return text[m.end():end]


def enterprise_fed_watchdog(text):
    m = re.search(r'if \[ "\$\{TIER:-sqlite\}" = "enterprise-fed" \]; then\n(.*?)\n\s*else\n', text, re.S)
    if not m:
        raise AssertionError('enterprise-fed tier block not found')
    vals = re.findall(r'^\s*WATCHDOG_SECS=(\d+)\s*$', m.group(1), re.M)
    if len(vals) != 1:
        raise AssertionError('expected exactly one WATCHDOG_SECS in the enterprise-fed block, got %r' % vals)
    return int(vals[0]), m.group(1)


def enterprise_fed_timeouts(text):
    out = {}
    for m in re.finditer(r'- leg: ([^\n]+)\n(.*?)\n\s*timeout: (\d+)\n', text, re.S):
        if 'tier: enterprise-fed' in m.group(2):
            out[m.group(1).strip()] = int(m.group(3))
    return out


class ShardBudgetTests(unittest.TestCase):
    """B3: watchdog and job cap re-derived for the shards."""

    def test_shard_watchdog_is_5400_and_covers_the_longest_shard(self):
        secs, block = enterprise_fed_watchdog(ci_text())
        self.assertEqual(secs, SHARD_WATCHDOG_SECS)
        self.assertGreaterEqual(secs, int(SHARD_ESTIMATE_SECS * 1.3))
        self.assertIn('3,9', block, 'the derivation (longest shard ~3,900 s) must be in the comment')

    def test_both_enterprise_fed_legs_cap_at_120_min_and_keep_the_ratio_rule(self):
        text = ci_text()
        secs, _ = enterprise_fed_watchdog(text)
        caps = enterprise_fed_timeouts(text)
        self.assertEqual(sorted(caps), ['linux-fed,enterprise-fed', 'macos-fed,enterprise-fed'])
        for leg, cap in caps.items():
            self.assertEqual(cap, JOB_TIMEOUT_MIN, leg)
            self.assertGreaterEqual(cap, secs // 60 + 15, '%s: job limit >= watchdog + 15 min (#6202)' % leg)

    def test_shards_share_one_budget_each(self):
        body = function_body(ci_text(), 'run_shard')
        self.assertIn('remaining=$(shard_left "$t0")', body)
        self.assertEqual(body.count('WATCHDOG_SECS="$remaining"'), 3)


class ShardWiringTests(unittest.TestCase):
    """B6: three shards, separate waits, OR'd exit codes, quoted arrays."""

    def setUp(self):
        self.body = function_body(ci_text(), 'run_sharded')

    def test_three_backgrounded_shards_with_logs(self):
        calls = re.findall(r'\( run_shard (\w+) "\$sd" (\d) (pg|skip) ("\$with_doc"|0) \) > "\$sd/(\w+)\.log" 2>&1 &',
                           self.body)
        self.assertEqual([(c[0], c[1], c[2], c[4]) for c in calls],
                         [('serial', '1', 'pg', 'serial'), ('parallel_1', '3', 'skip', 'parallel_1'),
                          ('parallel_2', '3', 'skip', 'parallel_2')])
        self.assertEqual(calls[0][3], '"$with_doc"', 'doc tests run in the serial shard only')

    def test_each_pid_is_waited_on_and_every_rc_propagates(self):
        for v in ('s', '1', '2'):
            self.assertIn('wait "$pid_%s" || rc_%s=$?' % (v, v), self.body)
        self.assertNotRegex(self.body, r'^\s*wait\s*$', 'a bare wait discards exit codes')
        self.assertIn('for n in "$rc_s" "$rc_1" "$rc_2"; do', self.body)
        self.assertIn('if [ "$n" -ne 0 ]; then rc="$n"; fi', self.body)
        self.assertTrue(self.body.rstrip().endswith('return "$rc"'))

    def test_partition_runs_with_the_doc_flag_and_fails_closed(self):
        self.assertRegex(self.body, r'python3 scripts/ci/partition_test_binaries\.py --build-json "\$sd/build\.jsonl"'
                                    r' --repo-root \. --out-dir "\$sd" --with-doc "\$with_doc" \|\| return "\$\?"')

    def test_watchdog_is_on_every_shard_run(self):
        text = ci_text()
        run_tests = function_body(text, 'run_tests')
        self.assertIn('"$TIMEOUT_BIN" --signal=TERM --kill-after=60 "$WATCHDOG_SECS" cargo test', run_tests)
        shard = function_body(text, 'run_shard')
        self.assertEqual(len(re.findall(r'run_(?:doc_)?tests "\[\$\{name\}\]', shard)), 3)

    def test_no_unquoted_array_expansion(self):
        text = ci_text()
        self.assertNotRegex(text, r'\+=\(\$\w+\)', 'unquoted word-split into an array (SC2206)')
        shard = function_body(text, 'run_shard')
        self.assertIn('read -r tflag tname <<< "$l"', shard)
        self.assertIn('itargs+=("$tflag" "$tname")', shard)


class ShardLogUploadTests(unittest.TestCase):
    """B5: shard logs survive a red, cancelled or capped job."""

    def test_shard_logs_are_uploaded_always_with_the_pinned_action(self):
        text = ci_text()
        m = re.search(r'- name: Upload shard logs \(#6344\)\n(.*?)(?=\n      - |\n  \w|\Z)', text, re.S)
        self.assertIsNotNone(m, 'shard-log upload step missing')
        step = m.group(1)
        self.assertRegex(step, r"if: .*always\(\)")
        self.assertIn("matrix.tier == 'enterprise-fed'", step)
        self.assertIn('uses: %s # v4' % UPLOAD_PIN, step)
        for pat in ('ci-shard/*.log', 'ci-shard/*.txt', 'ci-shard/manifest.json'):
            self.assertIn('${{ runner.temp }}/' + pat, step)
        self.assertNotIn('build.jsonl', step)
        self.assertIn('if-no-files-found: ignore', step)
        self.assertEqual(text.count('actions/upload-artifact@'), text.count(UPLOAD_PIN))

    def test_shard_dir_is_the_uploaded_dir(self):
        self.assertIn('local sd="${RUNNER_TEMP:-$PWD/.local-runs}/ci-shard"', function_body(ci_text(), 'run_sharded'))


class ShardDocsTests(unittest.TestCase):
    """B4: one consistent set of numbers; the serial budget is marked superseded."""

    def test_serial_budget_is_marked_superseded_by_the_shard_section(self):
        doc = DOC.read_text()
        self.assertIn('## Sharded enterprise-fed suite (#6344)', doc)
        self.assertIn('Superseded by [Sharded enterprise-fed suite (#6344)]', doc)
        row = [l for l in doc.splitlines() if l.startswith('| `linux-fed,enterprise-fed`')]
        self.assertEqual(len(row), 1)
        self.assertIn('5400 s (90 min)', row[0])
        self.assertIn('| 120 |', row[0])

    def test_docs_and_workflow_agree_on_the_shard_budget(self):
        doc = DOC.read_text()
        shard = doc[doc.index('## Sharded enterprise-fed suite (#6344)'):]
        for needle in ('5400 s', '120 min', '3,913 s'):
            self.assertIn(needle, shard)


if __name__ == '__main__':
    unittest.main()
