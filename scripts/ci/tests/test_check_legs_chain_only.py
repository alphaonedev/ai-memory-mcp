#!/usr/bin/env python3
"""Pins for the chain-only enterprise-fed ``Check`` legs (#8174).

Topic-branch pull requests run only the sqlite legs of the ``Check`` job; the
two enterprise-fed legs run on chain carrier PRs, pushes, merge groups. This suite pins (1) the decision script
``scripts/ci/check_legs.py``, (2) the ``.github/workflows/ci.yml`` wiring that
consumes it (all four legs and their names unchanged, runner rerouted for an
inactive tier, every guarded step carrying the tier guard) and (3) a mutation
table: each deliberate break must make the pins fail.

Run: python3 -m unittest discover -s scripts/ci/tests
Python 3.9+, standard library only (the workflow is read as text).
"""
import importlib.util
import re
import subprocess
import sys
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
SCRIPT = REPO / 'scripts' / 'ci' / 'check_legs.py'
CI_YML = REPO / '.github' / 'workflows' / 'ci.yml'

TIER_GUARD = 'contains(needs.classify.outputs.check_tiers, matrix.tier)'
DOCS_GUARD = "needs.classify.outputs.docs_only != 'true'"
NOTICE_STEP_NAME = 'name: Enterprise-fed leg inactive on this run (#8174)'
# Steps of `check` that may run without the tier guard, named exactly as ci.yml spells
# them: the checkout, the docs-only short-circuit and the inactive-leg notice.
TIER_GUARD_EXEMPT_STEPS = (
    'uses: actions/checkout@',
    'name: docs-only short-circuit',
    NOTICE_STEP_NAME,
)
RUNS_ON = ("runs-on: ${{ fromJSON(contains(needs.classify.outputs.check_tiers, matrix.tier)"
           " && matrix.runner || '[\"ubuntu-latest\"]') }}")

# The four legs, in order, exactly as `.github/workflows/ci.yml` at the base
# afbcd9729696 carries them (`git show afbcd9729696:.github/workflows/ci.yml`):
#   leg: ubuntu-latest,sqlite      runner: '["ubuntu-latest"]'              node: ubuntu-latest tier: sqlite         timeout: 95  once: true
#   leg: linux-fed,enterprise-fed  runner: '["self-hosted","linux-fed"]'    node: linux-fed     tier: enterprise-fed timeout: 160 shared_target: true
#   leg: macos-fed,sqlite          runner: '["self-hosted","macos-fed"]'    node: macos-fed     tier: sqlite         timeout: 80
#   leg: macos-fed,enterprise-fed  runner: '["self-hosted","macos-fed"]'    node: macos-fed     tier: enterprise-fed timeout: 160
LEGS = (
    {'leg': 'ubuntu-latest,sqlite', 'runner': '["ubuntu-latest"]', 'node': 'ubuntu-latest',
     'tier': 'sqlite', 'timeout': '95', 'once': 'true'},
    {'leg': 'linux-fed,enterprise-fed', 'runner': '["self-hosted","linux-fed"]', 'node': 'linux-fed',
     'tier': 'enterprise-fed', 'timeout': '160', 'shared_target': 'true'},
    {'leg': 'macos-fed,sqlite', 'runner': '["self-hosted","macos-fed"]', 'node': 'macos-fed',
     'tier': 'sqlite', 'timeout': '80'},
    {'leg': 'macos-fed,enterprise-fed', 'runner': '["self-hosted","macos-fed"]', 'node': 'macos-fed',
     'tier': 'enterprise-fed', 'timeout': '160'},
)
INSTALL_RUST_STEP = '      - name: Install Rust 1.98.0 (matches rust-toolchain.toml pin)\n'
INSTALL_RUST_IF = ('        if: needs.classify.outputs.docs_only != \'true\' && '
                   'contains(needs.classify.outputs.check_tiers, matrix.tier)\n')
STRAY_NO_IF = '      - name: stray cargo build\n        run: cargo build\n'
STRAY_IF_FIRST = ("      - if: needs.classify.outputs.docs_only != 'true'\n"
                  '        run: cargo build\n')
LEG_KEYS = ('leg', 'runner', 'node', 'tier', 'timeout', 'once', 'shared_target')


def load_module(source, name='check_legs_under_test'):
    """Exec ``source`` as a module (lets the mutation table run mutated copies in memory)."""
    spec = importlib.util.spec_from_loader(name, loader=None)
    module = importlib.util.module_from_spec(spec)
    exec(compile(source, name, 'exec'), module.__dict__)
    return module


CHAIN_BASE = 'chain/promo6-ssh-r2'
NON_CHAIN_BASES = ('release/v1.0.0', 'main', 'develop', 'rehearsal/audit-wip-ssh')


def behaviour_problems(module):
    """Every way the decision function deviates from the base-and-head rule (#8174)."""
    problems = []
    both = ('sqlite', 'enterprise-fed')
    topic = tuple(module.active_tiers('pull_request', 'fix/x', CHAIN_BASE))
    if topic != ('sqlite',):
        problems.append('topic pull_request into a chain base must run only sqlite, got %r' % (topic,))
    for event, head, base in (('pull_request', 'chain/promo6-ssh-r2', CHAIN_BASE), ('push', '', ''),
                              ('workflow_dispatch', '', ''), ('merge_group', '', ''), ('schedule', '', ''),
                              ('something_new', 'fix/x', CHAIN_BASE)):
        got = tuple(module.active_tiers(event, head, base))
        if got != both:
            problems.append('%s/%s/%s must run both tiers, got %r' % (event, head, base, got))
    for base in NON_CHAIN_BASES:
        for head in ('fix/x', 'dependabot/x', 'chain/promo6-ssh-r2'):
            got = tuple(module.active_tiers('pull_request', head, base))
            if got != both:
                problems.append('pull_request %s -> %s must run both tiers, got %r' % (head, base, got))
    nested = tuple(module.active_tiers('pull_request', 'fix/chain/x', CHAIN_BASE))
    if nested != ('sqlite',):
        problems.append('chain/ must be a prefix match on the head, fix/chain/x got %r' % (nested,))
    nested_base = tuple(module.active_tiers('pull_request', 'fix/x', 'fix/chain/y'))
    if nested_base != both:
        problems.append('chain/ must be a prefix match on the base, fix/chain/y got %r' % (nested_base,))
    return problems


def job_text(ci, job):
    m = re.search(r'^  %s:\n(.*?)(?=^  [a-z][a-z0-9_-]*:\n)' % re.escape(job), ci, re.S | re.M)
    return m.group(1) if m else ''


def step_blocks(job):
    # Every list item at the step indent starts a step, whatever its first key is.
    parts = re.split(r'^      - ', job, flags=re.M)
    return parts[1:]


def is_exempt(block):
    return any(block.startswith(prefix) for prefix in TIER_GUARD_EXEMPT_STEPS)


def matrix_legs(check_job):
    legs = []
    for block in re.split(r'^          - (?=leg: )', check_job, flags=re.M)[1:]:
        entry = {}
        for line in block.split('\n'):
            m = re.match(r'^(?:leg: |            )(\w+): ?(.*)$', line) or re.match(r'^(leg): (.*)$', line)
            if m and m.group(1) in LEG_KEYS and not line.lstrip().startswith('#'):
                entry[m.group(1)] = m.group(2).strip().strip("'")
        if 'timeout' in entry or 'leg' in entry:
            legs.append(entry)
    return legs


def workflow_problems(ci):
    """Every way the workflow wiring deviates from the chain-only design."""
    problems = []
    check = job_text(ci, 'check')
    classify = job_text(ci, 'classify')
    if not check or not classify:
        return ['check or classify job not found']
    legs = matrix_legs(check)
    if len(legs) != len(LEGS):
        problems.append('Check matrix must keep %d legs, found %d' % (len(LEGS), len(legs)))
    for want, got in zip(LEGS, legs):
        for key in LEG_KEYS:
            if want.get(key) != got.get(key):
                problems.append('leg %s key %s: want %r got %r' % (want['leg'], key, want.get(key), got.get(key)))
    if '    name: Check (${{ matrix.leg }})' not in check:
        problems.append('Check job name must stay `Check (${{ matrix.leg }})`')
    if '    ' + RUNS_ON not in check:
        problems.append('Check runs-on must reroute an inactive tier to a hosted runner')
    guarded = [b for b in step_blocks(check) if DOCS_GUARD in b]
    if len(guarded) < 30:
        problems.append('expected >= 30 docs-only guarded steps in Check, found %d' % len(guarded))
    for block in step_blocks(check):
        if not is_exempt(block) and TIER_GUARD not in block:
            problems.append('step without the tier guard: %s' % block.split('\n')[0][:80])
    if "needs.classify.outputs.docs_only == 'true'" not in check or 'check_tiers' not in check:
        problems.append('Check needs a docs-only no-op notice and a tier-skip notice')
    notice = [b for b in step_blocks(check) if b.startswith(NOTICE_STEP_NAME)]
    if len(notice) != 1:
        problems.append('exactly one loud inactive-leg notice step is required, found %d' % len(notice))
    else:
        block = notice[0]
        if ("if: " + DOCS_GUARD + " && !" + TIER_GUARD) not in block:
            problems.append('inactive-leg notice must run exactly when the tier is inactive')
        for needle in ('::notice::', '$GITHUB_STEP_SUMMARY', 'LEG: ${{ matrix.leg }}',
                       'EVENT_NAME: ${{ github.event_name }}', 'HEAD_REF: ${{ github.head_ref }}',
                       'BASE_REF: ${{ github.base_ref }}', 'chain/*) ;;', 'exit 1',
                       'cert-postgres-age.yml', 'postgres-ignored.yml',
                       'chain/* pull requests, push, merge_group and any pull request whose base is not chain/*'):
            if needle not in block:
                problems.append('inactive-leg notice missing %r' % needle)
    if 'check_tiers: ${{ steps.legs.outputs.check_tiers }}' not in classify:
        problems.append('classify must export check_tiers from steps.legs')
    m = re.search(r'      - id: legs\n(.*?)(?=\n      - |\n      # |\Z)', classify, re.S)
    if not m:
        problems.append('classify step `id: legs` not found')
    else:
        body = m.group(1)
        for needle in ('EVENT_NAME: ${{ github.event_name }}', 'HEAD_REF: ${{ github.head_ref }}',
                       'BASE_REF: ${{ github.base_ref }}', 'python3 -I scripts/ci/check_legs.py', '--github-output "$GITHUB_OUTPUT"'):
            if needle not in body:
                problems.append('classify legs step missing %r' % needle)
        if re.search(r'run:[^\n]*\$\{\{', body.split('env:')[0] if 'env:' in body else body):
            problems.append('github context must not be inlined into the legs script body')
    return problems


class DecisionScript(unittest.TestCase):
    def setUp(self):
        self.source = SCRIPT.read_text()
        self.mod = load_module(self.source)

    def test_topic_pr_runs_only_the_two_sqlite_legs(self):
        self.assertEqual(self.mod.active_tiers('pull_request', 'fix/x', CHAIN_BASE), ('sqlite',))
        legs = [l['leg'] for l in LEGS if l['tier'] in self.mod.active_tiers('pull_request', 'fix/x', CHAIN_BASE)]
        self.assertEqual(legs, ['ubuntu-latest,sqlite', 'macos-fed,sqlite'])

    def test_chain_carrier_pr_runs_all_four_legs_in_order(self):
        tiers = self.mod.active_tiers('pull_request', 'chain/promo6-ssh-r2', CHAIN_BASE)
        legs = [l['leg'] for l in LEGS if l['tier'] in tiers]
        self.assertEqual(legs, [l['leg'] for l in LEGS])

    def test_push_and_dispatch_run_all_four(self):
        for event in ('push', 'workflow_dispatch', 'merge_group'):
            self.assertEqual(len([l for l in LEGS if l['tier'] in self.mod.active_tiers(event, '', '')]), 4)

    def test_behaviour_has_no_problems(self):
        self.assertEqual(behaviour_problems(self.mod), [])

    def test_cli_prints_and_appends_output_line(self):
        out = REPO / '.local-runs' / 'check_legs_output.txt'
        out.parent.mkdir(exist_ok=True)
        out.write_text('')
        try:
            res = subprocess.run(
                [sys.executable, '-I', str(SCRIPT), '--event-name', 'pull_request', '--head-ref', 'fix/x',
                 '--base-ref', CHAIN_BASE, '--github-output', str(out)], capture_output=True, text=True, check=False)
            self.assertEqual(res.returncode, 0)
            self.assertEqual(res.stdout.strip(), 'check_tiers=sqlite')
            self.assertEqual(out.read_text(), 'check_tiers=sqlite\n')
        finally:
            out.unlink()

    def test_cli_empty_event_is_a_usage_error(self):
        res = subprocess.run([sys.executable, '-I', str(SCRIPT), '--event-name', ''],
                             capture_output=True, text=True, check=False)
        self.assertEqual(res.returncode, 2)

    def test_cli_pull_request_with_empty_head_ref_is_malformed(self):
        # #8174 code r1 F1: a pull_request without a head ref must be loud (rc 2, no
        # check_tiers line), never a silent drop of the enterprise-fed tier.
        res = subprocess.run([sys.executable, '-I', str(SCRIPT), '--event-name', 'pull_request',
                              '--head-ref', '', '--base-ref', CHAIN_BASE], capture_output=True, text=True, check=False)
        self.assertEqual(res.returncode, 2)
        self.assertNotIn('check_tiers', res.stdout)
        self.assertIn('head ref', res.stderr)

    def test_cli_base_rows(self):
        # #8174 security F1: only a PR that lands on a chain/ carrier may get the hosted no-op.
        for base in NON_CHAIN_BASES:
            res = subprocess.run([sys.executable, '-I', str(SCRIPT), '--event-name', 'pull_request',
                                  '--head-ref', 'fix/x', '--base-ref', base],
                                 capture_output=True, text=True, check=False)
            self.assertEqual((res.returncode, res.stdout.strip()), (0, 'check_tiers=sqlite,enterprise-fed'), base)
        res = subprocess.run([sys.executable, '-I', str(SCRIPT), '--event-name', 'pull_request',
                              '--head-ref', 'fix/x', '--base-ref', CHAIN_BASE],
                             capture_output=True, text=True, check=False)
        self.assertEqual((res.returncode, res.stdout.strip()), (0, 'check_tiers=sqlite'))

    def test_cli_pull_request_with_empty_base_ref_is_malformed(self):
        res = subprocess.run([sys.executable, '-I', str(SCRIPT), '--event-name', 'pull_request',
                              '--head-ref', 'fix/x', '--base-ref', ''], capture_output=True, text=True, check=False)
        self.assertEqual(res.returncode, 2)
        self.assertNotIn('check_tiers', res.stdout)
        self.assertIn('base ref', res.stderr)

    def test_output_line_round_trips(self):
        line = self.mod.output_line(self.mod.active_tiers('push', '', ''))
        key, value = line.split('=', 1)
        self.assertEqual((key, value.split(',')), ('check_tiers', ['sqlite', 'enterprise-fed']))


class WorkflowWiring(unittest.TestCase):
    def test_workflow_has_no_problems(self):
        self.assertEqual(workflow_problems(CI_YML.read_text()), [])


class MutationTable(unittest.TestCase):
    """Each deliberate break must make the pins fail (run against in-memory copies)."""

    def script_mutants(self):
        src = SCRIPT.read_text()
        return {
            'drop a tier (leg)': src.replace('ALL_TIERS = (TIER_SQLITE, TIER_ENTERPRISE_FED)', 'ALL_TIERS = (TIER_SQLITE,)'),
            'rename the tier': src.replace("TIER_ENTERPRISE_FED = 'enterprise-fed'", "TIER_ENTERPRISE_FED = 'enterprise'"),
            'flip the tier condition': src.replace('return (TIER_SQLITE,)', 'return (TIER_ENTERPRISE_FED,)'),
            'remove the chain/ carve-out': src.replace(
                ' and not head_ref.startswith(CHAIN_BRANCH_PREFIX)', ''),
            'ignore the base': src.replace(' and base_ref.startswith(CHAIN_BRANCH_PREFIX)', ''),
            'carve-out matches anywhere': src.replace(
                'not head_ref.startswith(CHAIN_BRANCH_PREFIX)', 'CHAIN_BRANCH_PREFIX not in head_ref'),
        }

    def workflow_mutants(self):
        ci = CI_YML.read_text()
        return {
            'drop a leg from the matrix': ci.replace('          - leg: macos-fed,enterprise-fed\n', '          - leg: macos-fed,enterprise-fed-x\n', 1),
            'rename a leg': ci.replace('- leg: linux-fed,enterprise-fed', '- leg: linux-fed,enterprise', 1),
            'drop a step tier guard': ci.replace(' && ' + TIER_GUARD, '', 1),
            'plain runs-on': ci.replace(RUNS_ON, 'runs-on: ${{ fromJSON(matrix.runner) }}', 1),
            'drop the inactive-leg notice step': ci.replace(NOTICE_STEP_NAME, 'name: Renamed step', 1),
            'notice forgets the postgres workflows': ci.replace('cert-postgres-age.yml and postgres-ignored.yml"', 'elsewhere"', 1),
            'drop BASE_REF env from the legs step': ci.replace(
                '          BASE_REF: ${{ github.base_ref }}\n        run: python3', '        run: python3', 1),
            'notice stops refusing a non-chain base': ci.replace('chain/*) ;;', 'chain/*|*) ;;', 1),
            # #8174 security r1 F3: edits to the guard wiring and the injection rule.
            'guard joined with || instead of &&': ci.replace(
                "docs_only != 'true' && " + TIER_GUARD, "docs_only != 'true' || " + TIER_GUARD, 1),
            'negated tier guard on a step': ci.replace(
                "docs_only != 'true' && " + TIER_GUARD, "docs_only != 'true' && !" + TIER_GUARD, 1),
            'continue-on-error on the legs step': ci.replace(
                '        name: Decide the Check tiers (#8174)\n',
                '        name: Decide the Check tiers (#8174)\n        continue-on-error: true\n', 1),
            'if on the legs step': ci.replace(
                '        name: Decide the Check tiers (#8174)\n',
                "        name: Decide the Check tiers (#8174)\n        if: github.event_name == 'pull_request'\n", 1),
            'head_ref inlined in the legs run': ci.replace(
                'run: python3 -I scripts/ci/check_legs.py --github-output',
                'run: python3 -I scripts/ci/check_legs.py --head-ref ${{ github.head_ref }} --github-output', 1),
            'head_ref inlined in the notice run': ci.replace(
                'head ref ${HEAD_REF}, base ref', 'head ref ${{ github.head_ref }}, base ref', 1),
            'drop HEAD_REF env': ci.replace('HEAD_REF: ${{ github.head_ref }}', 'HEAD_REF: ""', 1),
            # #8174 code r1 F2 (X1, X2, X4): a step with no tier guard at all must fail the pin.
            'X1 delete the whole if of Install Rust': ci.replace(
                INSTALL_RUST_STEP + INSTALL_RUST_IF, INSTALL_RUST_STEP, 1),
            'X2 new cargo build step with no if': ci.replace(
                '      - ' + NOTICE_STEP_NAME, STRAY_NO_IF + '      - ' + NOTICE_STEP_NAME, 1),
            'X4 new if-first step after a guarded step': ci.replace(
                '      - name: Fork-PR refusal', STRAY_IF_FIRST + '      - name: Fork-PR refusal', 1),
        }

    def test_every_script_mutant_fails_the_behaviour_pins(self):
        for name, src in self.script_mutants().items():
            with self.subTest(name):
                self.assertTrue(src != SCRIPT.read_text(), 'mutation did not apply')
                self.assertNotEqual(behaviour_problems(load_module(src)), [], name)

    def test_every_workflow_mutant_fails_the_wiring_pins(self):
        for name, ci in self.workflow_mutants().items():
            with self.subTest(name):
                self.assertTrue(ci != CI_YML.read_text(), 'mutation did not apply')
                self.assertNotEqual(workflow_problems(ci), [], name)


if __name__ == '__main__':
    unittest.main()
