#!/usr/bin/env python3
"""Unit tests for scripts/ci/check_pg_isolate_invariants.py (#6383 / #6386 r2).

Run: python3 -m unittest scripts/ci/tests/test_check_pg_isolate_invariants.py

The checker replaces the r1 shell Section G of
scripts/test/test-ci-workflow-invariants.sh (review r1 L1). Every check is
proven twice: the real ci.yml passes, and a mutant that breaks exactly that
invariant fails with that check's id.
"""
import importlib.util
import subprocess
import sys
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
CHECKER = REPO / 'scripts' / 'ci' / 'check_pg_isolate_invariants.py'
SPEC = importlib.util.spec_from_file_location('check_pg_isolate_invariants', CHECKER)
chk = importlib.util.module_from_spec(SPEC)
sys.modules['check_pg_isolate_invariants'] = chk
SPEC.loader.exec_module(chk)

CI_YML = (REPO / '.github' / 'workflows' / 'ci.yml').read_text()


def failed_ids(text):
    return {cid for cid, _ in chk.static_failures(text, REPO)}


class RealWorkflow(unittest.TestCase):
    def test_real_ci_yml_passes_every_check(self):
        self.assertEqual(chk.static_failures(CI_YML, REPO), [])

    def test_run_help_executes(self):
        # Review r1 C1: the CLI is executed, not grepped from the docstring.
        self.assertIsNone(chk.run_help_failure(REPO))

    def test_cli_exit_codes(self):
        done = subprocess.run([sys.executable, str(CHECKER), '--root', str(REPO)],
                              capture_output=True, text=True)
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        self.assertIn('ok', done.stdout)


class Mutants(unittest.TestCase):
    """Each mutant must be caught by the named check."""

    def assert_caught(self, mutant, cid):
        self.assertNotEqual(mutant, CI_YML, 'the mutation must change the text')
        self.assertIn(cid, failed_ids(mutant))

    def test_flag_exported_to_github_env_is_caught(self):
        # Review r1 M4: isolation is opt-in; ci.yml never turns it on.
        self.assert_caught(CI_YML + '\n          echo "AI_MEMORY_TEST_PG_ISOLATE=1" >> "$GITHUB_ENV"\n',
                           'G1-opt-in')

    def test_flag_as_yaml_env_key_is_caught(self):
        self.assert_caught(CI_YML.replace('          AI_MEMORY_NO_CONFIG: "1"\n',
                                          '          AI_MEMORY_NO_CONFIG: "1"\n'
                                          "          AI_MEMORY_TEST_PG_ISOLATE: '1'\n", 1),
                           'G1-opt-in')

    def test_flag_from_a_repo_variable_is_caught(self):
        self.assert_caught(CI_YML.replace('          AI_MEMORY_NO_CONFIG: "1"\n',
                                          '          AI_MEMORY_NO_CONFIG: "1"\n'
                                          '          AI_MEMORY_TEST_PG_ISOLATE: ${{ vars.X }}\n', 1),
                           'G1-opt-in')

    def test_ci_sweep_call_is_caught(self):
        # Review r1 H2: the cross-run sweep is admin-only.
        self.assert_caught(CI_YML + '\n          python3 scripts/test/pg_isolated_binary.py sweep --older-than 600\n',
                           'G2-no-ci-sweep')

    def test_url_in_wrapper_argv_is_caught(self):
        # Review r1 L3: the URL never travels in argv.
        self.assert_caught(CI_YML.replace('pg_isolated_binary.py teardown',
                                          'pg_isolated_binary.py teardown --url "$base_url"', 1),
                           'G3-no-url-argv')

    def test_missing_teardown_is_caught(self):
        self.assert_caught(CI_YML.replace('pg_isolated_binary.py teardown', 'pg_isolated_binary.py tear'),
                           'G4-setup-teardown')

    def test_unselected_prebuild_is_caught(self):
        # Review r1 H1: the prebuild builds only the selected binaries.
        self.assert_caught(CI_YML.replace('cargo test --no-run "$@" "${sel[@]}"', 'cargo test --no-run "$@"'),
                           'G5-prebuild-selection')

    def test_lost_watchdog_is_caught(self):
        self.assert_caught(CI_YML.replace('"$TIMEOUT_BIN" --signal=TERM --kill-after=60 "$WATCHDOG_SECS" '
                                          'python3 scripts/test/pg_isolated_binary.py run',
                                          'python3 scripts/test/pg_isolated_binary.py run'),
                           'G6-watchdog')

    def test_missing_log_upload_is_caught(self):
        # Review r1 M3: per-binary logs are uploaded with if: always().
        self.assert_caught(CI_YML.replace('ci-shard/iso-logs', 'ci-shard/elsewhere'), 'G7-log-upload')

    def test_missing_kill_switch_is_caught(self):
        self.assert_caught(CI_YML.replace('vars.CI_PG_ISOLATE_OFF', 'vars.SOMETHING_ELSE'), 'G8-kill-switch')

    def test_missing_template_guard_is_caught(self):
        # Review r1 M1/M6: lane on without the template fails closed.
        self.assert_caught(CI_YML.replace('${AI_MEMORY_TEST_PG_TEMPLATE:-}', '${UNRELATED:-}'),
                           'G9-template-guard')


SPLIT_LINE = ('              python3 -I scripts/ci/pg_isolate_split.py --build-json "$sd/build.jsonl" '
              '--serial-file "$sd/serial.txt" --out-dir "$sd" || return "$?"\n')
SPLIT_BLOCK = '            if [ "$PG_ISO_LANE" = "1" ]; then\n' + SPLIT_LINE + '            fi\n'
PARTITION_LINE_START = '            python3 scripts/ci/partition_test_binaries.py --build-json'
SERIAL_LAUNCH_END = '            pid_s=$!\n'


class SplitWiring(unittest.TestCase):
    """#7052: the PG_ISO_LANE split block is pinned (G10-split-wired)."""

    def assert_caught(self, mutant):
        self.assertNotEqual(mutant, CI_YML, 'the mutation must change the text')
        self.assertIn('G10-split-wired', failed_ids(mutant))

    def moved(self, anchor, before):
        """The block removed from its place and re-inserted before/after ``anchor``."""
        self.assertEqual(CI_YML.count(anchor), 1, anchor)
        without = CI_YML.replace(SPLIT_BLOCK, '', 1)
        return without.replace(anchor, (SPLIT_BLOCK + anchor) if before else (anchor + SPLIT_BLOCK), 1)

    def test_real_block_is_present_once_and_passes(self):
        self.assertEqual(CI_YML.count(SPLIT_BLOCK), 1)
        self.assertIsNone(chk.split_failure(CI_YML))

    def test_dropped_block_is_caught(self):
        self.assert_caught(CI_YML.replace(SPLIT_BLOCK, '', 1))

    def test_disabled_condition_is_caught(self):
        self.assert_caught(CI_YML.replace(SPLIT_BLOCK, SPLIT_BLOCK.replace(
            'if [ "$PG_ISO_LANE" = "1" ]; then', 'if false; then', 1), 1))

    def test_lost_isolated_mode_flag_is_caught(self):
        # #6956 posture: every python3 run in the step uses -I.
        self.assert_caught(CI_YML.replace('python3 -I scripts/ci/pg_isolate_split.py',
                                          'python3 scripts/ci/pg_isolate_split.py', 1))

    def test_lost_fail_closed_return_is_caught(self):
        self.assert_caught(CI_YML.replace(SPLIT_LINE, SPLIT_LINE.replace(' || return "$?"', '', 1), 1))

    def test_moved_after_first_shard_launch_is_caught(self):
        # After `( run_shard serial ... ) &` the serial shard has already read
        # iso_other.txt / iso_targets.txt: the split ran too late.
        self.assert_caught(self.moved(SERIAL_LAUNCH_END, before=False))

    def test_moved_before_partition_is_caught(self):
        # Before partition_test_binaries.py there is no serial.txt to split.
        self.assert_caught(self.moved(PARTITION_LINE_START, before=True))

    def test_moved_out_of_run_sharded_is_caught(self):
        self.assert_caught(self.moved('          run_sharded() {\n', before=True))

    def test_duplicate_call_is_caught(self):
        self.assert_caught(CI_YML.replace(SPLIT_BLOCK, SPLIT_BLOCK + SPLIT_BLOCK, 1))

    def test_unguarded_call_is_caught(self):
        self.assert_caught(CI_YML.replace(SPLIT_BLOCK, SPLIT_LINE, 1))


class SourceChecks(unittest.TestCase):
    def test_force_drop_in_the_wrapper_is_caught(self):
        wrapper = (REPO / 'scripts' / 'test' / 'pg_isolated_binary.py').read_text()
        self.assertIsNone(chk.source_failure('wrapper', wrapper))
        self.assertIsNotNone(chk.source_failure('wrapper', wrapper + "\nX = 'DROP DATABASE x WITH (FORCE)'\n"))
        self.assertIsNotNone(chk.source_failure('wrapper', wrapper.replace('pg_stat_activity', 'pg_x')))

    def test_force_drop_in_the_helper_is_caught(self):
        helper = (REPO / 'tests' / 'common' / 'pg_isolate.rs').read_text()
        self.assertIsNone(chk.source_failure('helper', helper))
        self.assertIsNotNone(chk.source_failure('helper', helper + '\n// WITH (FORCE)\n'))


if __name__ == '__main__':
    unittest.main()
