#!/usr/bin/env python3
"""Pin the push and pull_request triggers of session-boot-lifetime.yml (#7246).

Run with: python3 -I -m unittest discover -s scripts/ci/tests
The suite must run on release lines (push) and on PRs into release, rehearsal
and chain bases; a versioned release literal is the defect class pinned here.
"""
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[3]
WORKFLOW = ROOT / '.github' / 'workflows' / 'session-boot-lifetime.yml'
SCRATCH = ROOT / '.local-runs' / 'session-boot-7246'
PUSH_BRANCHES = ['main', 'release/**']
PR_BRANCHES = ['release/**', 'rehearsal/**', 'chain/**']
PR_TYPES = ['opened', 'synchronize', 'reopened']
TYPES_LINE = '    types: [opened, synchronize, reopened]'
CONCURRENCY_CANCEL = "cancel-in-progress: ${{ github.event_name == 'pull_request' }}"
REQUIRED_PATHS = ('.github/workflows/session-boot-lifetime.yml', 'src/cli/boot.rs')
VERSIONED_RELEASE = 'release/v'
OLD_PUSH_LINE = '    branches: [release/v0.6.3.1, main]'


def read_triggers(text):
    """Return {trigger: {'branches': [...], 'paths': [...]}} for push and pull_request."""
    found = {}
    trigger = key = None
    for line in text.splitlines():
        if re.match(r'^\S', line):
            trigger = key = None
            continue
        if re.match(r'^  (push|pull_request):\s*$', line):
            trigger = line.strip()[:-1]
            found[trigger] = {'branches': [], 'paths': [], 'types': []}
            key = None
        elif re.match(r'^  \S', line):
            trigger = key = None
        elif trigger and re.match(r'^    paths:\s*$', line):
            key = 'paths'
        elif trigger and line.startswith('    branches:'):
            body = line.split(':', 1)[1].strip()
            if body.startswith('[') and body.endswith(']'):
                found[trigger]['branches'] = [i.strip().strip('"\'') for i in body[1:-1].split(',')]
            key = None
        elif trigger and line.startswith('    types:'):
            body = line.split(':', 1)[1].strip()
            if body.startswith('[') and body.endswith(']'):
                found[trigger]['types'] = [i.strip().strip('"\'') for i in body[1:-1].split(',')]
            key = None
        elif trigger and key == 'paths' and re.match(r'^      - ', line):
            found[trigger]['paths'].append(line.strip()[2:].strip().strip('"\''))
        elif trigger and re.match(r'^    \S', line):
            key = None
    return found


def glob_match(pattern, ref):
    """Model of the filter glob: '**' is any run, '*' is any run without '/'."""
    parts = re.split(r'(\*\*|\*)', pattern)
    rx = ''.join('.*' if p == '**' else '[^/]*' if p == '*' else re.escape(p) for p in parts)
    return re.fullmatch(rx, ref) is not None


def check_triggers(text):
    """Return a list of problems with the push and pull_request triggers."""
    found = read_triggers(text)
    push, pr = found.get('push'), found.get('pull_request')
    problems = []
    if push is None or sorted(push['branches']) != sorted(PUSH_BRANCHES):
        problems.append('push.branches is %r, want %r' % (push and push['branches'], PUSH_BRANCHES))
    if any(VERSIONED_RELEASE in line for line in text.splitlines() if not line.lstrip().startswith('#')):
        problems.append('versioned release literal present')
    if pr is None or sorted(pr['branches']) != sorted(PR_BRANCHES):
        problems.append('pull_request.branches is %r, want %r' % (pr and pr['branches'], PR_BRANCHES))
    if push and pr and (push['paths'] != pr['paths'] or not push['paths']):
        problems.append('push and pull_request paths differ')
    for need in REQUIRED_PATHS:
        if push and need not in push['paths']:
            problems.append('push.paths lacks ' + need)
    return problems


REFUSAL_NAME = 'Fork-PR refusal (self-hosted legs never run fork code)'
REFUSAL_NEEDLES = (
    "github.event_name == 'pull_request'",
    'head.repo.full_name != github.repository',
    'self-hosted',
)
REFUSAL_RUN_NEEDLES = ('::error::', 'exit 1')


def refusal_problems(text):
    """Return problems with the fork-PR refusal step (must precede checkout, guard self-hosted)."""
    lines = text.splitlines()
    named = [i for i, l in enumerate(lines) if l.strip() == '- name: ' + REFUSAL_NAME]
    checkout = [i for i, l in enumerate(lines) if 'uses: actions/checkout@' in l]
    if not named or not checkout:
        return ['refusal step or checkout step missing']
    problems = []
    if named[0] > checkout[0]:
        problems.append('refusal step does not precede checkout')
    cond = lines[named[0] + 1].strip() if named[0] + 1 < len(lines) else ''
    if not cond.startswith('if: '):
        problems.append('refusal step has no if')
    problems += ['if lacks ' + n for n in REFUSAL_NEEDLES if n not in cond]
    end = named[0] + 1
    while end < len(lines) and not lines[end].startswith('      - '):
        end += 1
    block = '\n'.join(lines[named[0]:end])
    problems += ['run lacks ' + n for n in REFUSAL_RUN_NEEDLES if n not in block]
    return problems


def concurrency_problems(text):
    """Return problems with the top-level concurrency block (fork-safe, event-distinct, PR-only cancel)."""
    lines = text.splitlines()
    starts = [i for i, l in enumerate(lines) if l == 'concurrency:']
    if len(starts) != 1:
        return ['want exactly one top-level concurrency block, found %d' % len(starts)]
    body = []
    for line in lines[starts[0] + 1:]:
        if not line.startswith('  '):
            break
        body.append(line.strip())
    group = [l for l in body if l.startswith('group:')]
    cancel = [l for l in body if l.startswith('cancel-in-progress:')]
    problems = []
    if len(group) != 1 or 'github.event_name' not in group[0]:
        problems.append('group lacks github.event_name')
    if len(group) != 1 or 'github.event.pull_request.head.repo.full_name == github.repository' not in group[0]:
        problems.append('group lacks the fork-safe key')
    if cancel != [CONCURRENCY_CANCEL]:
        problems.append('cancel-in-progress is %r, want %r' % (cancel, CONCURRENCY_CANCEL))
    return problems


class SessionBootLifetimeTriggers7246(unittest.TestCase):
    def setUp(self):
        self.text = WORKFLOW.read_text(encoding='utf-8')
        self.found = read_triggers(self.text)

    def test_a_push_branches_are_main_and_release_glob(self):
        self.assertEqual(self.found['push']['branches'], PUSH_BRANCHES)
        for line in self.text.splitlines():
            if not line.lstrip().startswith('#'):
                self.assertNotIn(VERSIONED_RELEASE, line)

    def test_b_pull_request_branches_are_release_rehearsal_chain(self):
        self.assertEqual(self.found['pull_request']['branches'], PR_BRANCHES)

    def test_c_both_triggers_list_the_same_boot_paths(self):
        self.assertEqual(self.found['push']['paths'], self.found['pull_request']['paths'])
        for need in REQUIRED_PATHS:
            self.assertIn(need, self.found['push']['paths'])

    def test_d_globs_match_the_real_branches(self):
        self.assertTrue(glob_match('release/**', 'release/v1.0.0'))
        self.assertTrue(glob_match('chain/**', 'chain/promo6-ssh-r2'))
        self.assertFalse(glob_match('release/**', 'main'))

    def test_e_mutation_old_push_list_is_rejected(self):
        self.assertEqual(check_triggers(self.text), [])
        mutant = re.sub(r'(?m)^    branches: \[main, "release/\*\*"\]$', OLD_PUSH_LINE, self.text, count=1)
        self.assertNotEqual(mutant, self.text)
        SCRATCH.mkdir(parents=True, exist_ok=True)
        copy = SCRATCH / 'session-boot-lifetime.mutant.yml'
        copy.write_text(mutant, encoding='utf-8')
        problems = check_triggers(copy.read_text(encoding='utf-8'))
        self.assertTrue(any('push.branches' in p for p in problems), problems)
        self.assertTrue(any('versioned release' in p for p in problems), problems)


    def test_f_fork_pr_refusal_precedes_checkout(self):
        self.assertEqual(refusal_problems(self.text), [])
        lines = self.text.splitlines()
        start = lines.index('      - name: ' + REFUSAL_NAME)
        end = start + 1
        while not lines[end].startswith('      - uses:'):
            end += 1
        mutant = '\n'.join(lines[:start] + lines[end:])
        SCRATCH.mkdir(parents=True, exist_ok=True)
        copy = SCRATCH / 'session-boot-lifetime.no-refusal.yml'
        copy.write_text(mutant, encoding='utf-8')
        self.assertTrue(refusal_problems(copy.read_text(encoding='utf-8')))

    def test_g_pull_request_types_exclude_edited(self):
        self.assertEqual(self.found['pull_request']['types'], PR_TYPES)
        self.assertIn(TYPES_LINE, self.text)
        mutant = self.text.replace(TYPES_LINE, TYPES_LINE[:-1] + ', edited]', 1)
        self.assertNotEqual(mutant, self.text)
        self.assertNotEqual(read_triggers(mutant)['pull_request']['types'], PR_TYPES)

    def test_h_concurrency_block_is_fork_safe_and_cancels_only_prs(self):
        self.assertEqual(concurrency_problems(self.text), [])
        lines = self.text.splitlines()
        start = lines.index('concurrency:')
        mutant = '\n'.join(lines[:start] + lines[start + 3:])
        self.assertTrue(concurrency_problems(mutant))
        always = self.text.replace(CONCURRENCY_CANCEL, 'cancel-in-progress: true', 1)
        self.assertNotEqual(always, self.text)
        self.assertTrue(concurrency_problems(always))

    def test_i_refusal_guard_mutations_are_rejected(self):
        guard = "github.event_name == 'pull_request' && "
        self.assertIn(guard, self.text)
        self.assertTrue(refusal_problems(self.text.replace(guard, '', 1)))
        refusal = self.text.index(REFUSAL_NAME)
        exit_at = self.text.index('exit 1', refusal)
        mutant = self.text[:exit_at] + 'exit 0' + self.text[exit_at + len('exit 1'):]
        self.assertTrue(refusal_problems(mutant))


if __name__ == '__main__':
    unittest.main()
