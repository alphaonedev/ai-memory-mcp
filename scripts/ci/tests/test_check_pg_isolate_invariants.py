#!/usr/bin/env python3
"""Unit tests for scripts/ci/check_pg_isolate_invariants.py (#6383 / #6386 r2).

Run: python3 -m unittest scripts/ci/tests/test_check_pg_isolate_invariants.py

The checker replaces the r1 shell Section G of
scripts/test/test-ci-workflow-invariants.sh (review r1 L1). Every check is
proven twice: the real ci.yml passes, and a mutant that breaks exactly that
invariant fails with that check's id.
"""
import importlib.util
import re
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

# Decision 919f1943 (3-agent vote 6def5ab6, 2026-10-24, supersedes 4d3ea1c5): the flag
# is ON by default for the enterprise-fed tier of the two fed legs and nowhere else.
FED_EXPR = "${{ matrix.tier == 'enterprise-fed' && '1' || '0' }}"
FED_LINE = '      AI_MEMORY_TEST_PG_ISOLATE: ' + FED_EXPR + '\n'
KILL_ECHO = 'echo "AI_MEMORY_TEST_PG_ISOLATE=0" >> "$GITHUB_ENV"'
RUN_GUARD = ('if [ "${AI_MEMORY_TEST_PG_ISOLATE:-0}" = "1" ] && [ "${CI_PG_ISOLATE_OFF:-}" != "1" ] '
             '&& [ "${TIER:-}" = "enterprise-fed" ]; then')


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


class DefaultOn(unittest.TestCase):
    """#6383 default-on for the enterprise-fed legs (decision 919f1943)."""

    def assert_caught(self, mutant, cid):
        self.assertNotEqual(mutant, CI_YML, 'the mutation must change the text')
        self.assertIn(cid, failed_ids(mutant))

    def test_check_job_env_enables_the_flag_for_enterprise_fed_only(self):
        self.assertEqual(CI_YML.count(FED_LINE), 1)
        self.assertIn('leg: linux-fed,enterprise-fed', CI_YML)
        self.assertIn('leg: macos-fed,enterprise-fed', CI_YML)

    def test_kill_switch_branch_still_forces_zero(self):
        self.assertRegex(CI_YML, r'elif \[ "\$\{CI_PG_ISOLATE_OFF:-\}" = "1" \]; then\n\s+' + re.escape(KILL_ECHO))

    def test_missing_default_on_is_caught(self):
        self.assert_caught(CI_YML.replace(FED_LINE, ''), 'G1-default-on')

    def test_unconditional_flag_is_caught(self):
        self.assert_caught(CI_YML.replace(FED_EXPR, "'1'"), 'G1-default-on')

    def test_widened_tier_expression_is_caught(self):
        self.assert_caught(CI_YML.replace("matrix.tier == 'enterprise-fed' && '1'", "matrix.tier != 'x' && '1'"),
                           'G1-default-on')

    def test_flag_enabled_outside_the_check_job_is_caught(self):
        self.assert_caught(CI_YML.replace(FED_LINE, '') + '\n' + FED_LINE, 'G1-default-on')

    def test_r1_1a_quoted_yaml_key_is_caught(self):
        # Review r2 R1-1 (a): a quoted YAML key is still the flag.
        self.assert_caught(CI_YML.replace('          AI_MEMORY_NO_CONFIG: "1"\n',
                                          '          AI_MEMORY_NO_CONFIG: "1"\n'
                                          "          \"AI_MEMORY_TEST_PG_ISOLATE\": '1'\n", 1),
                           'G1-default-on')

    def test_r1_1b_flow_style_env_map_is_caught(self):
        # R1-1 (b): a flow-style env map on a step.
        self.assert_caught(CI_YML + '\n        env: {AI_MEMORY_TEST_PG_ISOLATE: 1, OTHER: x}\n', 'G1-default-on')

    def test_r1_1c_quote_split_github_env_write_is_caught(self):
        # R1-1 (c): the flag name split across adjacent quotes.
        self.assert_caught(CI_YML + '\n          echo "AI_MEMORY_TEST_PG_""ISOLATE=1" >> "$GITHUB_ENV"\n',
                           'G1-default-on')

    def test_r1_1d_removed_run_step_guard_is_caught(self):
        # R1-1 (d): the run step must keep its own kill-switch and tier guard.
        self.assertIn(RUN_GUARD, CI_YML)
        self.assert_caught(CI_YML.replace(RUN_GUARD, 'if [ "${AI_MEMORY_TEST_PG_ISOLATE:-0}" = "1" ]; then'),
                           'G1-default-on')

    def test_r2_1a_commented_guard_does_not_satisfy_g1(self):
        # Review r2 R2-1 (a): a commented-out copy of the guard must not count; the live
        # `if` here has lost the kill-switch and tier conditions.
        weak = 'if [ "${AI_MEMORY_TEST_PG_ISOLATE:-0}" = "1" ]; then'
        self.assert_caught(CI_YML.replace(RUN_GUARD, weak) + '\n          # ' + RUN_GUARD + '\n',
                           'G1-default-on')

    def test_r2_1b_second_assignment_on_one_line_is_caught(self):
        # R2-1 (b): every assignment on a line is checked, not only the first.
        self.assert_caught(CI_YML + '\n          AI_MEMORY_TEST_PG_ISOLATE=0; AI_MEMORY_TEST_PG_ISOLATE=1\n',
                           'G1-default-on')
        self.assert_caught(CI_YML + '\n          AI_MEMORY_TEST_PG_ISOLATE=0 || AI_MEMORY_TEST_PG_ISOLATE=1\n',
                           'G1-default-on')

    def test_r2_1c_zero_prefix_expression_is_not_zero(self):
        # R2-1 (c): `0${...}` is an expression that can expand to 10, not the literal 0.
        self.assert_caught(CI_YML + '\n          AI_MEMORY_TEST_PG_ISOLATE=0${{ matrix.x }}\n', 'G1-default-on')

    def test_removed_kill_switch_force_zero_is_caught(self):
        self.assert_caught(CI_YML.replace(KILL_ECHO, 'true', 1), 'G1-default-on')


class Mutants(unittest.TestCase):
    """Each mutant must be caught by the named check."""

    def assert_caught(self, mutant, cid):
        self.assertNotEqual(mutant, CI_YML, 'the mutation must change the text')
        self.assertIn(cid, failed_ids(mutant))

    def test_flag_exported_to_github_env_is_caught(self):
        # Review r1 M4: a non-default assignment of the flag is rejected (G1-default-on).
        self.assert_caught(CI_YML + '\n          echo "AI_MEMORY_TEST_PG_ISOLATE=1" >> "$GITHUB_ENV"\n',
                           'G1-default-on')

    def test_flag_as_yaml_env_key_is_caught(self):
        self.assert_caught(CI_YML.replace('          AI_MEMORY_NO_CONFIG: "1"\n',
                                          '          AI_MEMORY_NO_CONFIG: "1"\n'
                                          "          AI_MEMORY_TEST_PG_ISOLATE: '1'\n", 1),
                           'G1-default-on')

    def test_flag_from_a_repo_variable_is_caught(self):
        self.assert_caught(CI_YML.replace('          AI_MEMORY_NO_CONFIG: "1"\n',
                                          '          AI_MEMORY_NO_CONFIG: "1"\n'
                                          '          AI_MEMORY_TEST_PG_ISOLATE: ${{ vars.X }}\n', 1),
                           'G1-default-on')

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
