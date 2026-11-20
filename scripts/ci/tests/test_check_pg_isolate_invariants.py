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

    # #9592: the G3 / G4 / G5 / G6 / G9 mutants of the r1 lane moved to EntryChecks,
    # because ci.yml no longer calls the wrapper itself (the step entry does).

    def test_missing_log_upload_is_caught(self):
        # Review r1 M3: per-binary logs are uploaded with if: always().
        self.assert_caught(CI_YML.replace('ci-shard/iso-logs', 'ci-shard/elsewhere'), 'G7-log-upload')

    def test_missing_kill_switch_is_caught(self):
        self.assert_caught(CI_YML.replace('vars.CI_PG_ISOLATE_OFF', 'vars.SOMETHING_ELSE'), 'G8-kill-switch')


FLAG = 'AI_MEMORY_TEST_PG_ISOLATE'
CI_REL = '.github/workflows/ci.yml'
ENTRY_PATH = REPO / 'scripts' / 'ci' / 'pg_isolate_serial_step.py'
ALLOWED_STEP = 'Serial shard isolated binaries (linux-fed enterprise-fed, issue 9592)'
ALLOWED_IF = ("${{ !cancelled() && steps.run-tests.outcome != 'skipped' && "
              "needs.classify.outputs.cargo_skip != 'true' && matrix.node == 'linux-fed' && "
              "matrix.tier == 'enterprise-fed' }}")
ALLOWED_RUN = 'python3 scripts/ci/pg_isolate_serial_step.py run'
SITE = '          %s: "1"\n' % FLAG

# A minimal workflow with exactly the one allowed site (#9592, vote 71472661 I-1 / I-3).
WORKFLOW = ('name: ci\n'
            'on:\n'
            '  push:\n'
            'jobs:\n'
            '  check:\n'
            '    runs-on: ubuntu-latest\n'
            '    strategy:\n'
            '      matrix:\n'
            '        include:\n'
            '          - node: linux-fed\n'
            '            tier: enterprise-fed\n'
            '    steps:\n'
            '      - name: Run tests (impact-aware)\n'
            '        id: run-tests\n'
            '        env:\n'
            '          AI_MEMORY_NO_CONFIG: "1"\n'
            '        run: echo serial\n'
            '      - name: ' + ALLOWED_STEP + '\n'
            '        if: ' + ALLOWED_IF + '\n'
            '        env:\n'
            + SITE +
            '          AI_MEMORY_NO_CONFIG: "1"\n'
            '        run: ' + ALLOWED_RUN + '\n')


class OneSiteG1(unittest.TestCase):
    """I-3: G1 allows exactly the one serial-shard step on linux-fed enterprise-fed."""

    def reasons(self, text, extra=None):
        files = {CI_REL: text}
        files.update(extra or {})
        return chk.g1_reasons(files)

    def mutate(self, old, new):
        mutant = WORKFLOW.replace(old, new, 1)
        self.assertNotEqual(mutant, WORKFLOW, 'the mutation must change the text')
        return self.reasons(mutant)

    def test_the_allowed_site_passes(self):
        self.assertEqual(self.reasons(WORKFLOW), [])

    def test_the_real_workflows_have_exactly_the_allowed_site(self):
        self.assertEqual([m for cid, m in chk.static_failures(CI_YML, REPO) if cid.startswith('G1')], [])
        self.assertEqual(CI_YML.count(SITE), 1)

    def test_a_second_site_fails(self):
        reasons = self.mutate('          AI_MEMORY_NO_CONFIG: "1"\n        run: echo serial\n',
                              SITE + '          AI_MEMORY_NO_CONFIG: "1"\n        run: echo serial\n')
        self.assertEqual(reasons, [
            "step 'Run tests (impact-aware)' sets %s (allowed: %r)" % (FLAG, ALLOWED_STEP),
            '%s is set at 2 sites (allowed: exactly one)' % FLAG])

    def test_no_site_fails(self):
        reasons = self.mutate(SITE, '')
        self.assertEqual(reasons, ['no step sets %s (allowed: exactly one, %r)' % (FLAG, ALLOWED_STEP)])

    def test_the_same_step_on_another_leg_fails(self):
        other = ALLOWED_IF.replace("matrix.node == 'linux-fed'", "matrix.node == 'macos-fed'")
        self.assertEqual(self.mutate(ALLOWED_IF, other),
                         ['the allowed step runs on another leg: if is %r' % other])

    def test_the_step_without_a_leg_condition_fails(self):
        self.assertEqual(self.mutate('        if: ' + ALLOWED_IF + '\n', ''),
                         ['the allowed step runs on another leg: if is None'])

    def test_the_step_running_something_else_fails(self):
        self.assertEqual(self.mutate(ALLOWED_RUN, 'cargo test --features sal-postgres'),
                         ['the allowed step does not run %r' % ALLOWED_RUN])

    def test_a_renamed_step_fails(self):
        reasons = self.mutate('- name: ' + ALLOWED_STEP, '- name: Serial shard (renamed)')
        self.assertEqual(reasons, ["step 'Serial shard (renamed)' sets %s (allowed: %r)" % (FLAG, ALLOWED_STEP),
                                   'no step sets %s (allowed: exactly one, %r)' % (FLAG, ALLOWED_STEP)])

    def test_a_step_in_another_job_fails(self):
        self.assertEqual(self.mutate('  check:\n', '  lint:\n')[0],
                         'step env sets %s in job lint (allowed: check)' % FLAG)

    def test_job_level_env_fails(self):
        reasons = self.mutate('    runs-on: ubuntu-latest\n',
                              '    runs-on: ubuntu-latest\n    env:\n      %s: "1"\n' % FLAG)
        self.assertEqual(reasons, ['job-level env sets %s in %s job check' % (FLAG, CI_REL)])

    def test_workflow_level_env_fails(self):
        reasons = self.mutate('jobs:\n', 'env:\n  %s: "1"\njobs:\n' % FLAG)
        self.assertEqual(reasons, ['workflow-level env sets %s in %s' % (FLAG, CI_REL)])

    def test_every_other_value_form_fails(self):
        for raw in ("'1'", '1', 'true', 'yes', '${{ vars.X }}', '"true"', '"0"', '${{ matrix.iso }}'):
            with self.subTest(raw=raw):
                reasons = self.mutate(SITE, '          %s: %s\n' % (FLAG, raw))
                self.assertEqual(reasons, ['the allowed step sets %s to %s (allowed: "1")' % (FLAG, raw)])

    def test_a_run_export_fails(self):
        reasons = self.mutate('        run: echo serial\n',
                              '        run: |\n          export %s=1\n          echo serial\n' % FLAG)
        self.assertEqual(reasons, ["a run: script assigns %s in %s job check step 'Run tests (impact-aware)'"
                                   % (FLAG, CI_REL)])

    def test_a_github_env_write_fails(self):
        reasons = self.mutate('        run: echo serial\n',
                              '        run: echo "%s=1" >> "$GITHUB_ENV"\n' % FLAG)
        self.assertEqual(reasons, ["a run: script assigns %s in %s job check step 'Run tests (impact-aware)'"
                                   % (FLAG, CI_REL)])

    def test_a_matrix_include_fails(self):
        reasons = self.mutate('            tier: enterprise-fed\n',
                              '            tier: enterprise-fed\n            %s: "1"\n' % FLAG)
        self.assertEqual(reasons, ['matrix sets %s in %s job check' % (FLAG, CI_REL)])

    def test_a_with_input_fails(self):
        reasons = self.mutate('        run: echo serial\n',
                              '        uses: ./.github/actions/x\n        with:\n          %s: "1"\n' % FLAG)
        self.assertEqual(reasons, ['%s is not set through a step env key in %s at jobs/check/steps/0/with'
                                   % (FLAG, CI_REL)])

    def test_a_reusable_workflow_fails(self):
        other = '.github/workflows/reusable.yml'
        reasons = self.reasons(WORKFLOW, {other: 'on:\n  workflow_call:\nenv:\n  %s: "1"\n' % FLAG})
        self.assertEqual(reasons, ['%s outside the allowed step: %s' % (FLAG, other)])

    def test_a_composite_action_fails(self):
        action = '.github/actions/pg/action.yml'
        text = ('runs:\n  using: composite\n  steps:\n    - shell: bash\n'
                '      run: export %s=1\n' % FLAG)
        self.assertEqual(self.reasons(WORKFLOW, {action: text}),
                         ['%s outside the allowed step: %s' % (FLAG, action)])

    def test_an_unparseable_workflow_fails(self):
        other = '.github/workflows/broken.yml'
        reasons = self.reasons(WORKFLOW, {other: 'jobs: [unclosed\n'})
        self.assertEqual(len(reasons), 1)
        self.assertTrue(reasons[0].startswith('unparseable workflow %s: ' % other), reasons)

    def test_static_failures_reads_the_other_workflows(self):
        # The repo argument is used: a site in another real workflow file is G1.
        self.assertTrue(any(rel.endswith('ci.yml') for rel in chk.workflow_files(REPO)))
        self.assertTrue(all(rel.startswith('.github/') for rel in chk.workflow_files(REPO)))


class EntryChecks(unittest.TestCase):
    """G2-G6 and G9 moved with the wrapper calls from ci.yml into the step entry (#9592)."""

    ENTRY = ENTRY_PATH.read_text() if ENTRY_PATH.is_file() else ''

    def caught(self, mutant, cid):
        self.assertNotEqual(mutant, self.ENTRY, 'the mutation must change the text')
        self.assertIn(cid, {c for c, _ in chk.entry_failures(mutant)})

    def test_the_real_entry_passes(self):
        self.assertTrue(self.ENTRY, 'scripts/ci/pg_isolate_serial_step.py is missing')
        self.assertEqual(chk.entry_failures(self.ENTRY), [])

    def test_a_sweep_in_the_entry_is_caught(self):
        self.caught(self.ENTRY + "\nX = [WRAPPER, 'sweep']\n", 'G2-no-ci-sweep')

    def test_a_url_in_the_entry_argv_is_caught(self):
        self.caught(self.ENTRY + "\nX = [WRAPPER, 'teardown', '--url', 'u']\n", 'G3-no-url-argv')

    def test_a_missing_teardown_in_the_entry_is_caught(self):
        self.caught(self.ENTRY.replace("'teardown'", "'tear'"), 'G4-setup-teardown')

    def test_an_unselected_prebuild_is_caught(self):
        self.caught(self.ENTRY.replace("'--no-run'", "'--all'"), 'G5-prebuild-selection')

    def test_a_lost_watchdog_is_caught(self):
        self.caught(self.ENTRY.replace("'--kill-after=60'", "'--kill-after=6'"), 'G6-watchdog')

    def test_a_lost_template_guard_is_caught(self):
        self.caught(self.ENTRY.replace('setup emitted no', 'setup emitted'), 'G9-template-guard')

    def test_ci_yml_must_run_the_entry_and_its_cleanup(self):
        self.assertIn('G4-setup-teardown', failed_ids(CI_YML.replace('pg_isolate_serial_step.py cleanup',
                                                                     'pg_isolate_serial_step.py clean')))

    def test_a_url_on_a_direct_wrapper_call_in_ci_yml_is_caught(self):
        self.assertIn('G3-no-url-argv', failed_ids(
            CI_YML + '\n#\n        run: python3 scripts/test/pg_isolated_binary.py teardown --url x\n'))


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
