#!/usr/bin/env python3
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""Native #7113 ownership regressions; opt in with H7113_NATIVE=1.

Only exact databases successfully created by this test are cleaned. The sweep
listing is restricted to that set; no foreign resource is ever a candidate.
Credentials come exclusively from AI_MEMORY_TEST_POSTGRES_URL in the environment.
"""
import contextlib
import importlib.util
import io
import os
from pathlib import Path
import time
import unittest.mock
import uuid
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
LOCK_REFIND_7130 = "failed to re-find shared lock object"
RETRIES_7130 = 2


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
            with unittest.mock.patch.object(pib, 'mint_base_name', return_value=name):
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

            with unittest.mock.patch.object(pib, '_names', side_effect=owned_names):
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


@unittest.skipUnless(os.environ.get(NATIVE_VAR) == "1", "native ownership acceptance requires H7113_NATIVE=1")
class FamilyLifecycleNative(unittest.TestCase):
    """CLI lifecycle: setup marks ACTIVE, teardown/revoke mark TERMINAL, sweep
    reaps only TERMINAL families. Every database touched is minted here."""

    def setUp(self):
        source = os.environ[pib.URL_VAR]
        self.assertEqual(urlsplit(source).port, NATIVE_PORT)
        self.admin = pib.with_database(source, pib.MAINTENANCE_DB)
        self.owned = []
        self.holds = []
        self.addCleanup(self.cleanup_owned)

    def exists(self, name):
        sql = "SELECT EXISTS (SELECT 1 FROM pg_database WHERE datname = '%s')" % name
        return pib.psql(self.admin, sql, True).strip() == 't'

    def cleanup_owned(self):
        for hold in self.holds:
            pib.close_hold(hold)
        for name in reversed(self.owned):
            if self.exists(name):
                pib.psql(self.admin, pib.SQL_RELEASE_TEMPLATE % pib.quote_ident(name))
                pib.psql(self.admin, pib.SQL_DROP_DATABASE % pib.quote_ident(name))
        remaining = [name for name in self.owned if self.exists(name)]
        print('H7113_NATIVE lifecycle remaining_owned=%r' % remaining, flush=True)
        self.assertEqual(remaining, [])

    def cli(self, argv, base=None):
        env = {k: v for k, v in os.environ.items() if not k.startswith('AI_MEMORY_TEST_PG_')}
        env[pib.URL_VAR] = self.admin if base is None else pib.with_database(self.admin, base)
        if base is not None:
            env[pib.BASE_VAR] = base
        out, err = io.StringIO(), io.StringIO()
        with unittest.mock.patch.dict(os.environ, env, clear=True), \
                contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            rc = pib.main(argv)
        return rc, out.getvalue(), err.getvalue()

    def family(self, stamp, run):
        """Auto-mint a family through ``setup`` (the managed path)."""
        name = "ci_base_%d_%d_%s" % (os.getpid(), stamp, uuid.uuid4().hex[:8])
        self.owned.append(name)
        self.owned.append(name + pib.TEMPLATE_SUFFIX)
        with unittest.mock.patch.object(pib, 'mint_base_name', return_value=name):
            rc, out, err = self.cli(['setup', '--jobs', '1', '--run-id', run, '--emit-env'])
        self.assertEqual(rc, 0, err)
        emitted = dict(line.split('=', 1) for line in out.split())
        self.assertEqual(emitted[pib.BASE_VAR], name)
        return name, emitted[pib.TEMPLATE_VAR]

    def clone(self, tpl, run, hold=False):
        clone_url, clone = pib.mint(self.admin, tpl, run)
        self.owned.append(clone)
        if hold:
            proc = pib.open_hold(clone_url)
            self.holds.append(proc)
            pib.wait_for_hold(self.admin, clone, proc)
        return clone_url, clone

    def sweep_owned(self, skew=0):
        original_names = pib._names

        def owned_names(url, statement):
            return [name for name in original_names(url, statement) if name in self.owned]
        real_now = int(time.time())
        with unittest.mock.patch.object(pib, '_names', side_effect=owned_names), \
                unittest.mock.patch.object(pib, '_server_now', return_value=real_now + skew, create=True):
            return pib.sweep(self.admin, SWEEP_SECONDS)

    def test_active_family_in_an_interbinary_gap_survives_sweep(self):
        token = uuid.uuid4().hex[:8]
        run = "h7113g" + token
        base, tpl = self.family(int(time.time()) - AGE_SECONDS, run)
        # Between binaries: no clone, no session on base or template.
        dropped = self.sweep_owned()
        self.assertTrue(self.exists(base), 'ACTIVE aged base destroyed; dropped=%r' % dropped)
        self.assertTrue(self.exists(tpl), 'ACTIVE aged template destroyed; dropped=%r' % dropped)
        clone_url, _ = self.clone(tpl, run)
        self.assertEqual(pib.psql(clone_url, 'SELECT 1', True).strip(), '1')
        rc, _, err = self.cli(['teardown', '--run-id', run], base=base)
        self.assertEqual(rc, 0, err)
        self.assertFalse(self.exists(base) or self.exists(tpl), 'teardown removes the whole family')

    def test_revoked_abandoned_family_is_reaped_and_active_control_kept(self):
        token = uuid.uuid4().hex[:8]
        run, control_run = "h7113r" + token, "h7113k" + token
        base, tpl = self.family(int(time.time()), run)
        control, control_tpl = self.family(int(time.time()), control_run)
        _, idle_clone = self.clone(tpl, run)
        control_url, _ = self.clone(control_tpl, control_run, hold=True)
        rc, _, err = self.cli(['revoke', '--db', base, '--run-id', run, '--reason', 'abandoned by #7113 test'])
        self.assertEqual(rc, 0, err)
        self.assertEqual(self.sweep_owned(), [], 'a fresh TERMINAL family waits for the age delay')
        dropped = self.sweep_owned(skew=AGE_SECONDS)
        self.assertEqual(sorted(dropped), sorted([idle_clone, tpl, base]))
        self.assertTrue(self.exists(control) and self.exists(control_tpl), 'ACTIVE control family untouched')
        self.assertEqual(pib.psql(control_url, 'SELECT 1', True).strip(), '1')

    def teardown_retrying_7130(self, run, base):
        """Run teardown; retry only the exact #7130 server error (XX000 lock
        re-find) that aborts before the family is terminalized."""
        for attempt in range(RETRIES_7130 + 1):
            with unittest.mock.patch.object(pib.time, 'sleep'):
                rc, _, err = self.cli(['teardown', '--run-id', run], base=base)
            if rc == 0 or LOCK_REFIND_7130 not in err or attempt == RETRIES_7130:
                return rc, err
        return rc, err

    def test_failed_teardown_exits_nonzero_and_sweep_finishes_it(self):
        token = uuid.uuid4().hex[:8]
        run = "h7113f" + token
        base, tpl = self.family(int(time.time()), run)
        _, held = self.clone(tpl, run, hold=True)
        rc, err = self.teardown_retrying_7130(run, base)
        self.assertNotEqual(rc, 0, 'a teardown that left %s behind must not report success: %s' % (held, err))
        # #7159: assert the cause, not just a non-zero rc. Any error returns non-zero,
        # including a transient server error before the family is terminalized.
        self.assertIn(held, err, 'stderr must name the held clone: %s' % err)
        oid, comment = pib.read_family(self.admin, base)
        found = pib.parse_family_marker(comment, base, oid)
        self.assertIsNotNone(found, 'family marker unreadable after the failed teardown: %s' % err)
        self.assertEqual((found['phase'], found['intent']), (pib.PHASE_TERMINAL, pib.INTENT_TEARDOWN),
                         'teardown must terminalize before it drops; stderr: %s' % err)
        self.assertTrue(self.exists(base), 'base kept as the TERMINAL authority while a member remains')
        for hold in self.holds:
            pib.close_hold(hold)
        self.holds = []
        dropped = self.sweep_owned(skew=AGE_SECONDS)
        self.assertIn(base, dropped)
        self.assertFalse(self.exists(base) or self.exists(tpl) or self.exists(held))


if __name__ == '__main__':
    unittest.main()
