#!/usr/bin/env python3
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""PR #7088 review r1: changelog fragments and the PG-ISOLATION doc match the shipped wrapper.

Every issue the PR closes carries a fragment, the #7113 fragment pair does not
contradict itself, and step 1 of the isolation doc names every variable that
``setup --emit-env`` exports (code review F-D / F-E, security review M1).
"""
import importlib.util
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
FRAGMENTS = ROOT / 'changelog.d'
DOC = ROOT / 'docs' / 'ci' / 'PG-ISOLATION.md'
SCRIPT = ROOT / 'scripts' / 'test' / 'pg_isolated_binary.py'
CLOSED_BY_7088 = (6848, 7114, 7115, 7124, 7125, 7152, 7153, 7156, 7157, 7158, 7159, 7161, 7180)
HELD_PHRASE = 'Implementation remains held'


def load_wrapper():
    spec = importlib.util.spec_from_file_location('pib_changelog_7088', SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class ChangelogFragments7088(unittest.TestCase):
    def test_every_closed_issue_has_a_fragment_that_names_it(self):
        for number in CLOSED_BY_7088:
            with self.subTest(issue=number):
                found = sorted(FRAGMENTS.glob('%d.*.md' % number))
                self.assertTrue(found, 'changelog.d/%d.<kind>.md is missing' % number)
                text = ''.join(p.read_text(encoding='utf-8') for p in found)
                self.assertIn('#%d' % number, text)

    def test_7115_fragment_headline_matches_the_issue(self):
        # Issue #7115: the audit head-hash fixture silently passed without
        # reaching its watermark assertions.
        text = (FRAGMENTS / '7115.fixed.md').read_text(encoding='utf-8')
        match = re.match(r'\*\*(.+?)\*\*', text)
        self.assertIsNotNone(match, 'fragment must open with a bold headline')
        headline = match.group(1).lower()
        self.assertIn('head-hash', headline)
        self.assertIn('watermark', headline)

    def test_7113_fragments_do_not_contradict_the_shipped_reduced_option_b(self):
        fragments = sorted(FRAGMENTS.glob('7113.*.md'))
        self.assertTrue(fragments)
        for path in fragments:
            self.assertNotIn(HELD_PHRASE, path.read_text(encoding='utf-8'), path.name)
            self.assertNotIn('does not fix or close #7113', path.read_text(encoding='utf-8'), path.name)

    def test_fragment_names_follow_the_repo_shape(self):
        for number in CLOSED_BY_7088:
            for path in FRAGMENTS.glob('%d.*.md' % number):
                self.assertRegex(path.name, r'^\d+\.(fixed|changed|added|security|removed|deprecated)\.md$')


class PgIsolationDoc7088(unittest.TestCase):
    def test_step_1_names_every_variable_setup_emits(self):
        wrapper = load_wrapper()
        text = DOC.read_text(encoding='utf-8')
        step1 = text[text.index('1. **Configure**'):text.index('2. **Run.**')]
        for var in (wrapper.TEMPLATE_VAR, wrapper.RUN_ID_VAR, wrapper.BASE_VAR):
            self.assertIn(var, step1)
        self.assertIn('--emit-env-unmasked', step1)
        self.assertIsNone(re.search(r'exports\s+`AI_MEMORY_TEST_PG_TEMPLATE`\s+and\s+`AI_MEMORY_TEST_PG_RUN_ID`\s+to', step1))

    def test_step_3_documents_teardown_of_a_minted_base(self):
        # #7180: after a masked --emit-env the URL still names the maintenance
        # database, so teardown must be told (or find) the minted base.
        wrapper = load_wrapper()
        text = DOC.read_text(encoding='utf-8')
        step3 = text[text.index('3. **Cleanup**'):text.index('On SIGTERM (the watchdog)')]
        self.assertIn(wrapper.BASE_VAR, step3)
        self.assertRegex(step3, r'(?is)minted.{0,300}(template|`_tpl`|<base>_tpl)')

    def test_step_1_documents_the_masked_mode_url_behaviour(self):
        wrapper = load_wrapper()
        text = DOC.read_text(encoding='utf-8')
        step1 = text[text.index('1. **Configure**'):text.index('2. **Run.**')]
        self.assertIn(wrapper.URL_VAR, step1)
        self.assertRegex(step1, r'(?is)masked.{0,200}(not emit|no\b.{0,20}URL|omit)')


if __name__ == '__main__':
    unittest.main()
