#!/usr/bin/env python3
"""Unit tests for scripts/ci/check_pg_isolate_invariants.py (#6383 / #6386 r2).

Run: python3 -m unittest scripts/ci/tests/test_check_pg_isolate_invariants.py

The checker replaces the r1 shell Section G of
scripts/test/test-ci-workflow-invariants.sh (review r1 L1). Every check is
proven twice: the real ci.yml passes, and a mutant that breaks exactly that
invariant fails with that check's id.
"""
import importlib.util
import os
import shutil
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


RUN_TESTS_STEP = 'Run tests (impact-aware)'
ISO_STEP = 'Serial shard isolated binaries (linux-fed enterprise-fed, issue 9592)'
CLEANUP_STEP = 'Cleanup enterprise-fed ephemeral db'
REDACT_STEP = 'Redact isolated-lane per-binary logs (issue 9592)'
UPLOAD_STEP = 'Upload isolated-lane per-binary logs (#6383)'
KILL_LINE = '          CI_PG_ISOLATE_OFF: ${{ vars.CI_PG_ISOLATE_OFF }}\n'


def step_span(text, name):
    """(start, end) of the step named ``name`` in the workflow text: its ``- name:`` line to the next sibling."""
    marker = '      - name: %s\n' % name
    start = text.index(marker)
    nxt = text.find('\n      - name: ', start + len(marker))
    return start, (len(text) if nxt < 0 else nxt + 1)


def mutate_step(name, old, new, text=None):
    """Replace ``old`` by ``new`` once inside one named step of ci.yml (the mutation must change it)."""
    text = CI_YML if text is None else text
    start, end = step_span(text, name)
    block = text[start:end]
    if old not in block:
        raise AssertionError('%r not in step %r' % (old, name))
    return text[:start] + block.replace(old, new, 1) + text[end:]


def failures_of(text, cid):
    return [msg for c, msg in chk.static_failures(text, REPO) if c == cid]


class StepWiring9592(unittest.TestCase):
    """#9592 r1 SA / C-M1 / C-M2 / SB / SD / SG: the gate checks that the halves agree, step by step."""

    def caught(self, mutant, cid, reason=None):
        self.assertNotEqual(mutant, CI_YML, 'the mutation must change the text')
        found = failures_of(mutant, cid)
        self.assertTrue(found, 'no %s failure for the mutant' % cid)
        if reason is not None:
            self.assertIn(reason, found)

    # G8: the exact kill-switch env line on Run tests AND on the isolated step (C-M1, K1).
    def test_kill_switch_dropped_from_run_tests_is_caught(self):
        self.caught(mutate_step(RUN_TESTS_STEP, KILL_LINE, ''), 'G8-kill-switch',
                    "step %r does not set CI_PG_ISOLATE_OFF: ${{ vars.CI_PG_ISOLATE_OFF }}" % RUN_TESTS_STEP)

    def test_kill_switch_dropped_from_the_isolated_step_is_caught(self):
        self.caught(mutate_step(ISO_STEP, KILL_LINE, ''), 'G8-kill-switch',
                    "step %r does not set CI_PG_ISOLATE_OFF: ${{ vars.CI_PG_ISOLATE_OFF }}" % ISO_STEP)

    def test_kill_switch_from_another_variable_is_caught(self):
        self.caught(mutate_step(ISO_STEP, KILL_LINE, '          CI_PG_ISOLATE_OFF: ${{ vars.OTHER }}\n'),
                    'G8-kill-switch')

    def test_kill_switch_dropped_from_both_steps_is_caught(self):
        both = mutate_step(ISO_STEP, KILL_LINE, '', mutate_step(RUN_TESTS_STEP, KILL_LINE, ''))
        self.assertEqual(len(failures_of(both, 'G8-kill-switch')), 2)

    # G10: the deferral and the kill switch are decided in Run tests by the pinned lines.
    def test_every_deferral_pin_is_required(self):
        for pin in chk.DEFER_PINS:
            with self.subTest(pin=pin):
                self.caught(mutate_step(RUN_TESTS_STEP, pin, pin + ' # changed'), 'G10-deferral',
                            'Run tests lost the deferral pin %r' % pin)

    def test_the_deferral_leg_matches_the_isolated_step_if(self):
        self.assertIn("matrix.node == '%s' && matrix.tier == '%s'" % (chk.DEFER_NODE, chk.DEFER_TIER),
                      chk.ALLOWED_IF)
        for pin in chk.DEFER_PINS[1:3]:
            self.assertIn('"%s"' % chk.DEFER_NODE, pin)
            self.assertIn('"%s"' % chk.DEFER_TIER, pin)

    # G11: Cleanup runs the entry first, and every exit carries its exit code.
    def test_cleanup_exit_zero_is_caught(self):
        self.caught(mutate_step(CLEANUP_STEP, 'exit "$iso_rc"', 'exit 0'), 'G11-cleanup',
                    'the Cleanup step exits with %r (allowed: %r)' % ('exit 0', chk.CLEANUP_EXIT))

    def test_cleanup_call_after_an_exit_is_caught(self):
        call = '          %s\n' % chk.CLEANUP_CALL
        moved = mutate_step(CLEANUP_STEP, call, '')
        moved = mutate_step(CLEANUP_STEP, '          export PATH\n', '          export PATH\n' + call, moved)
        self.caught(moved, 'G11-cleanup', 'the Cleanup step does not run %r before its first exit' % chk.CLEANUP_CALL)

    def test_cleanup_without_always_is_caught(self):
        self.caught(mutate_step(CLEANUP_STEP, 'if: always() && ', 'if: '), 'G11-cleanup',
                    'the Cleanup step is not always()')

    def test_cleanup_without_the_entry_is_caught(self):
        self.caught(mutate_step(CLEANUP_STEP, chk.CLEANUP_CALL, 'true'), 'G11-cleanup')

    # G12: continue-on-error is banned on the steps of the handshake and on job check.
    def test_continue_on_error_is_caught_on_every_step(self):
        for name in (RUN_TESTS_STEP, ISO_STEP, CLEANUP_STEP, REDACT_STEP):
            with self.subTest(step=name):
                marker = '      - name: %s\n' % name
                self.caught(CI_YML.replace(marker, marker + '        continue-on-error: true\n', 1),
                            'G12-continue-on-error', 'continue-on-error on step %r' % name)

    def test_continue_on_error_on_job_check_is_caught(self):
        self.caught(CI_YML.replace('\n  check:\n', '\n  check:\n    continue-on-error: true\n', 1),
                    'G12-continue-on-error', 'continue-on-error on job check')

    # G13: the isolated step never runs on a fork pull request (SG).
    def test_a_missing_fork_guard_is_caught(self):
        self.caught(mutate_step(ISO_STEP, ' && ' + FORK_GUARD, ''), 'G13-fork-guard',
                    'the isolated step has no fork guard %r' % FORK_GUARD)

    # G14: the isolated step runs inside the #7914 host semaphore (C-M2).
    def test_the_isolated_step_outside_the_semaphore_is_caught(self):
        self.caught(mutate_step(ISO_STEP, ALLOWED_RUN, 'python3 scripts/ci/pg_isolate_serial_step.py run'),
                    'G14-host-semaphore', 'the isolated step does not run %r' % ALLOWED_RUN)

    def test_the_run_line_is_the_semaphore_wrapper(self):
        self.assertTrue(chk.ALLOWED_RUN.startswith('python3 -I scripts/ci/host_semaphore.py --name linux-fed-tests '))
        self.assertIn('--label "${CI_NODE}/${TIER}/iso"', chk.ALLOWED_RUN)
        self.assertTrue(chk.ALLOWED_RUN.endswith(' -- python3 scripts/ci/pg_isolate_serial_step.py run'))

    def test_semaphore_env_that_differs_from_run_tests_is_caught(self):
        for key in chk.SEMAPHORE_ENV:
            with self.subTest(key=key):
                start, end = step_span(CI_YML, ISO_STEP)
                block = CI_YML[start:end]
                line = next(ln for ln in block.splitlines() if ln.strip().startswith(key + ':'))
                mutant = mutate_step(ISO_STEP, line + '\n', '          %s: "9"\n' % key)
                self.caught(mutant, 'G14-host-semaphore',
                            'the isolated step env %s differs from Run tests' % key)

    # G7: the per-binary logs are redacted by an always() step before they are uploaded (SD).
    def test_a_missing_redact_step_is_caught(self):
        self.caught(mutate_step(REDACT_STEP, chk.REDACT_RUN, 'true'), 'G7-log-upload',
                    'no always() step runs %r before the %s upload' % (chk.REDACT_RUN, chk.LOG_PATH))

    def test_a_redact_step_without_always_is_caught(self):
        self.caught(mutate_step(REDACT_STEP, 'if: always() && ', 'if: '), 'G7-log-upload')

    def test_a_redact_step_after_the_upload_is_caught(self):
        start, end = step_span(CI_YML, REDACT_STEP)
        block = CI_YML[start:end]
        without = CI_YML[:start] + CI_YML[end:]
        u_start, u_end = step_span(without, UPLOAD_STEP)
        moved = without[:u_end] + block + without[u_end:]
        self.caught(moved, 'G7-log-upload')

    def test_the_real_workflow_has_every_step(self):
        for name in (RUN_TESTS_STEP, ISO_STEP, CLEANUP_STEP, REDACT_STEP, UPLOAD_STEP):
            self.assertIn('      - name: %s\n' % name, CI_YML)
        for cid in ('G7-log-upload', 'G8-kill-switch', 'G10-deferral', 'G11-cleanup', 'G12-continue-on-error',
                    'G13-fork-guard', 'G14-host-semaphore'):
            self.assertEqual(failures_of(CI_YML, cid), [], cid)


FLAG = 'AI_MEMORY_TEST_PG_ISOLATE'
CI_REL = '.github/workflows/ci.yml'
ENTRY_PATH = REPO / 'scripts' / 'ci' / 'pg_isolate_serial_step.py'
ALLOWED_STEP = 'Serial shard isolated binaries (linux-fed enterprise-fed, issue 9592)'
FORK_GUARD = ("(github.event_name != 'pull_request' || "
              "github.event.pull_request.head.repo.full_name == github.repository)")
ALLOWED_IF = ("${{ !cancelled() && steps.run-tests.outcome != 'skipped' && "
              "needs.classify.outputs.cargo_skip != 'true' && matrix.node == 'linux-fed' && "
              "matrix.tier == 'enterprise-fed' && " + FORK_GUARD + " }}")
# #9592 C-M2: the isolated step runs inside the #7914 host semaphore, like Run tests.
ALLOWED_RUN = ('python3 -I scripts/ci/host_semaphore.py --name linux-fed-tests --slots "$HOST_SEMAPHORE_SLOTS" '
               '--max-wait-secs "$HOST_SEMAPHORE_MAX_WAIT_SECS" --label "${CI_NODE}/${TIER}/iso" '
               '-- python3 scripts/ci/pg_isolate_serial_step.py run')
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

    # #9592 C-L5: an expression-valued env: mapping can carry the flag past every key check.
    def test_an_expression_valued_env_fails(self):
        for where, mutant in (
                ('jobs/check/steps/0/env', WORKFLOW.replace(
                    '        env:\n          AI_MEMORY_NO_CONFIG: "1"\n        run: echo serial\n',
                    '        env: ${{ fromJSON(vars.X) }}\n        run: echo serial\n', 1)),
                ('jobs/check/env', WORKFLOW.replace('    runs-on: ubuntu-latest\n',
                                                    '    runs-on: ubuntu-latest\n    env: ${{ fromJSON(vars.X) }}\n', 1)),
                ('env', WORKFLOW.replace('jobs:\n', 'env: ${{ fromJSON(vars.X) }}\njobs:\n', 1))):
            with self.subTest(where=where):
                self.assertNotEqual(mutant, WORKFLOW)
                self.assertEqual(self.reasons(mutant),
                                 ['an expression-valued env: in %s at %s' % (CI_REL, where)])

    def test_an_expression_valued_env_in_another_workflow_fails(self):
        other = '.github/workflows/other.yml'
        text = 'on:\n  push:\njobs:\n  x:\n    runs-on: a\n    env: ${{ fromJSON(vars.X) }}\n'
        self.assertEqual(self.reasons(WORKFLOW, {other: text}),
                         ['an expression-valued env: in %s at jobs/x/env' % other])

    def test_the_real_workflows_have_no_expression_valued_env(self):
        files = {rel: (REPO / rel).read_text() for rel in chk.workflow_files(REPO)}
        self.assertEqual([r for r in chk.g1_reasons(files) if 'expression-valued' in r], [])

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


FLAG_NEAR_ENV_CASES = (
    # (name, text, expected reasons for path scripts/x.py)
    ('flag on the GITHUB_ENV line', 'open(os.environ["GITHUB_ENV"], "a").write("%s=1")\n' % FLAG,
     ['%s within %d lines of GITHUB_ENV: scripts/x.py:1' % (FLAG, 3)]),
    ('flag three lines above', 'X = "%s"\n\n\nwith open(os.environ["GITHUB_ENV"]) as f: f.write(X)\n' % FLAG,
     ['%s within %d lines of GITHUB_ENV: scripts/x.py:1' % (FLAG, 3)]),
    ('flag four lines above', 'X = "%s"\n\n\n\nos.environ["GITHUB_ENV"]\n' % FLAG, []),
    ('a longer name is not the flag', 'X = "%s_OFF"\nos.environ["GITHUB_ENV"]\n' % FLAG, []),
    ('no GITHUB_ENV', 'X = "%s"\n' % FLAG, []),
)


class ScriptsFlagScan(unittest.TestCase):
    """#9592 C-L5: a script outside .github that writes the flag to GITHUB_ENV is a G1 site."""

    def test_the_table(self):
        self.assertEqual(chk.FLAG_ENV_WINDOW, 3)
        for name, text, expected in FLAG_NEAR_ENV_CASES:
            with self.subTest(case=name):
                self.assertEqual(chk.script_flag_reasons({'scripts/x.py': text}), expected)

    def test_tests_and_the_gate_are_excluded(self):
        text = 'X = "%s"\nos.environ["GITHUB_ENV"]\n' % FLAG
        self.assertEqual(chk.script_flag_reasons({'scripts/ci/tests/test_x.py': text,
                                                  'scripts/ci/check_pg_isolate_invariants.py': text}), [])

    def test_the_real_scripts_are_clean(self):
        self.assertEqual(chk.script_flag_reasons(chk.script_files(REPO)), [])

    def test_a_script_site_is_a_static_failure(self):
        self.assertTrue(chk.script_files(REPO))
        self.assertIn('scripts/ci/pg_isolate_serial_step.py', chk.script_files(REPO))

    def test_a_large_script_scans_in_linear_time(self):
        import time
        text = ('y = 1\n' * 200000) + 'os.environ["GITHUB_ENV"]\n'
        started = time.monotonic()
        self.assertEqual(chk.script_flag_reasons({'scripts/big.py': text}), [])
        self.assertLess(time.monotonic() - started, 5.0)


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


WORKFLOW_TEXT = REPO / 'scripts' / 'ci' / 'tests' / 'workflow_text.py'
MODE_BLOCK_FIRST = 'PG_ISO_KILL="$(python3 scripts/ci/pg_isolate_serial_step.py killswitch)"'
MODE_BLOCK_LAST = 'echo "$PG_ISO_MODE" > "$PG_ISO_MODE_FILE"'
MODE_SCRATCH = REPO / '.local-runs' / 'test-pg-isolate-mode-9753'
# The full domain of the mode decision, and the expected (mode file, defer flag) per row, written by hand:
# only the linux-fed enterprise-fed leg defers (kill switch off) or runs in-line (kill switch on).
MODE_TABLE_9753 = (
    ('linux-fed', 'enterprise-fed', '1', 'killswitch', '0'),
    ('linux-fed', 'enterprise-fed', '', 'none', '1'),
    ('linux-fed', 'sqlite', '1', 'none', '0'),
    ('linux-fed', 'sqlite', '', 'none', '0'),
    ('macos-fed', 'enterprise-fed', '1', 'none', '0'),
    ('macos-fed', 'enterprise-fed', '', 'none', '0'),
    ('macos-fed', 'sqlite', '1', 'none', '0'),
    ('macos-fed', 'sqlite', '', 'none', '0'),
    ('linux', 'enterprise-fed', '1', 'none', '0'),
    ('linux', 'enterprise-fed', '', 'none', '0'),
    ('linux', 'sqlite', '1', 'none', '0'),
    ('linux', 'sqlite', '', 'none', '0'),
)


def mode_block():
    """The lines of the Run tests step body that decide the kill switch, the deferral and the mode file."""
    spec = importlib.util.spec_from_file_location('workflow_text_9753', WORKFLOW_TEXT)
    wt = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(wt)
    (step,) = [s for s in wt.read_steps(REPO / CI_REL, 'check') if s['name'] == RUN_TESTS_STEP]
    lines = step['run'].split('\n')
    first = [i for i, line in enumerate(lines) if line.strip() == MODE_BLOCK_FIRST]
    last = [i for i, line in enumerate(lines) if line.strip() == MODE_BLOCK_LAST]
    if len(first) != 1 or len(last) != 1 or last[0] < first[0]:
        raise LookupError('the mode block of %r is not one span' % RUN_TESTS_STEP)
    return '\n'.join(lines[first[0]:last[0] + 1]) + '\necho "defer=$PG_ISO_DEFER"\n'


class KillSwitchMode9753(unittest.TestCase):
    """#9753 (V04): the ci.yml mode block, executed, writes the mode each leg and kill-switch value implies."""

    def test_every_leg_and_kill_switch_value_writes_its_mode(self):
        block = mode_block()
        for node, tier, kill, want_mode, want_defer in MODE_TABLE_9753:
            with self.subTest(node=node, tier=tier, kill=kill):
                temp = MODE_SCRATCH / ('%s-%s-%s' % (node, tier, kill or 'off'))
                if temp.exists():
                    shutil.rmtree(temp)
                temp.mkdir(parents=True)
                env = {'PATH': os.environ.get('PATH', '/usr/bin:/bin'), 'CI_NODE': node, 'TIER': tier,
                       'CI_PG_ISOLATE_OFF': kill, 'RUNNER_TEMP': str(temp)}
                done = subprocess.run(['bash', '-c', block], cwd=str(REPO), env=env, capture_output=True,
                                      text=True, timeout=60)
                self.assertEqual(done.returncode, 0, done.stderr)
                self.assertEqual((temp / 'ci-iso-mode.txt').read_text(), want_mode + '\n')
                self.assertEqual(done.stdout.strip().splitlines()[-1], 'defer=' + want_defer)
                shutil.rmtree(temp)


if __name__ == '__main__':
    unittest.main()
