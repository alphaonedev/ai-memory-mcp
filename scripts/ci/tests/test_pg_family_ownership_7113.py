#!/usr/bin/env python3
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""Native #7113 ownership regressions; opt in with H7113_NATIVE=1.

Only exact databases successfully created by this test are cleaned. The sweep
listing is restricted to that set; no foreign resource is ever a candidate.
Credentials come exclusively from AI_MEMORY_TEST_POSTGRES_URL in the environment.
"""
import importlib.util
import os
from pathlib import Path
import time
import unittest
import uuid
from unittest import mock
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[3]
SCRIPT = ROOT / "scripts/test/pg_isolated_binary.py"
SPEC = importlib.util.spec_from_file_location("ownership_regression_wrapper", SCRIPT)
pib = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(pib)
NATIVE_VAR = "H7113_NATIVE"
NATIVE_PORT = 5445
AGE_SECONDS = 7200
SWEEP_SECONDS = 3600


@unittest.skipUnless(os.environ.get(NATIVE_VAR) == "1", "native ownership acceptance requires H7113_NATIVE=1")
class ActiveFamilyNative(unittest.TestCase):
    def test_active_aged_family_preserves_template_and_next_clone(self):
        source = os.environ[pib.URL_VAR]
        self.assertEqual(urlsplit(source).port, NATIVE_PORT)
        admin = pib.with_database(source, pib.MAINTENANCE_DB)
        stamp = int(time.time()) - AGE_SECONDS
        token = uuid.uuid4().hex[:8]
        base = "ci_base_%d_%d_%s" % (os.getpid(), stamp, token)
        control = "ci_base_%d_%d_%s" % (os.getpid(), int(time.time()), uuid.uuid4().hex[:8])
        run = "h7113" + token
        control_run = "h7113c" + token
        owned = []
        holds = []
        observations = {}

        def exists(name):
            return pib.psql(admin, "SELECT EXISTS (SELECT 1 FROM pg_database WHERE datname = '%s')" % name, True).strip() == 't'

        def make_family(name, family_run):
            with mock.patch.object(pib, 'mint_base_name', return_value=name):
                url = pib.mint_base(admin)
            owned.append(name)
            tpl = pib.setup(url, name, jobs=1)
            owned.append(tpl)
            clone_url, clone = pib.mint(admin, tpl, family_run, now=stamp)
            owned.append(clone)
            hold = pib.open_hold(clone_url)
            holds.append(hold)
            pib.wait_for_hold(admin, clone, hold)
            self.assertEqual(pib.psql(clone_url, 'SELECT 1', True).strip(), '1')
            return tpl, clone_url, clone

        try:
            tpl, clone_url, clone = make_family(base, run)
            control_tpl, control_url, control_clone = make_family(control, control_run)
            original_names = pib._names

            def owned_names(url, statement):
                return [name for name in original_names(url, statement) if name in owned]

            with mock.patch.object(pib, '_names', side_effect=owned_names):
                dropped = pib.sweep(admin, SWEEP_SECONDS)
            observations['active_clone_query'] = pib.psql(clone_url, 'SELECT 1', True).strip() == '1'
            observations['healthy_concurrent_family'] = all(exists(n) for n in (control, control_tpl, control_clone))
            observations['healthy_control_query'] = pib.psql(control_url, 'SELECT 1', True).strip() == '1'
            observations['active_base_preserved'] = exists(base)
            observations['active_template_preserved'] = exists(tpl)
            try:
                next_url, next_clone = pib.mint(admin, tpl, run)
                owned.append(next_clone)
                observations['next_clone_query'] = pib.psql(next_url, 'SELECT 1', True).strip() == '1'
            except pib.WrapperError:
                observations['next_clone_query'] = False
            self.assertTrue(observations['active_clone_query'])
            self.assertTrue(observations['healthy_concurrent_family'])
            self.assertTrue(observations['healthy_control_query'])
            self.assertTrue(all(observations.values()), 'active family destroyed: %r; dropped=%r' % (observations, dropped))
        finally:
            for hold in holds:
                pib.close_hold(hold)
            for name in reversed(owned):
                if exists(name):
                    pib.psql(admin, pib.SQL_RELEASE_TEMPLATE % pib.quote_ident(name))
                    pib.psql(admin, pib.SQL_DROP_DATABASE % pib.quote_ident(name))
            remaining = [name for name in owned if exists(name)]
            print('H7113_NATIVE observations=%r remaining_owned=%r' % (observations, remaining), flush=True)
            self.assertEqual(remaining, [])


if __name__ == '__main__':
    unittest.main()
