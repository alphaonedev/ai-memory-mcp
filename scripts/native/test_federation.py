# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
import contextlib
import io
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import tracemalloc
import unittest
from unittest.mock import patch
import federation as native

URL = 'postgresql://fixture:synthetic-secret@127.0.0.1:5445/control?sslmode=verify-full'
SUMMARY = 'test result: ok. 35 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.10s\n'

class HarnessTests(unittest.TestCase):
    def test_configuration_accepts_only_declared_verified_loopback(self):
        parsed = native.configuration(URL)
        self.assertEqual(parsed.hostname, '127.0.0.1')
        for bad in [URL.replace('verify-full','require'), URL.replace('127.0.0.1','remote.example'), URL+'&sslmode=require', URL+'&host=remote.example']:
            with self.subTest(bad=bad), self.assertRaises(native.Failure):
                native.configuration(bad)

    def test_redaction_removes_urls_and_raw_and_encoded_passwords(self):
        clean = native.redact(URL+' synthetic-secret', [URL])
        self.assertNotIn('synthetic-secret', clean)
        self.assertNotIn('postgresql://', clean)
        self.assertIn('ordinary diagnostic', native.redact('ordinary diagnostic',[URL]))

    def test_completeness_has_a_positive_and_rejects_every_vacuity(self):
        self.assertEqual(native.complete(SUMMARY,35),35)
        for text in ['',SUMMARY.replace('35 passed','0 passed'),SUMMARY.replace('0 failed','1 failed'),SUMMARY.replace('0 ignored','1 ignored'),SUMMARY+'skip: missing cluster\n',SUMMARY+'SKIP test: env unset\n']:
            with self.subTest(text=text), self.assertRaises(native.Failure):
                native.complete(text,35)

    def test_versions_and_tls_are_pinned(self):
        native.certify('t|18.6|1.8.0|0.8.6')
        for value in ['f|18.6|1.8.0|0.8.6','t|16.4|1.8.0|0.8.6','t|18.6|1.6.0|0.8.6','t|18.6|1.8.0|0.8.5']:
            with self.subTest(value=value), self.assertRaises(native.Failure):
                native.certify(value)

    def test_database_cleanup_on_success_and_body_failure(self):
        for fail in [False,True]:
            cluster = native.Cluster(URL,'psql')
            calls=[]
            def sql(url,statement):
                calls.append(statement)
                return 't' if 'NOT EXISTS' in statement else ''
            with patch.object(cluster,'sql',side_effect=sql), contextlib.redirect_stdout(io.StringIO()):
                try:
                    with cluster.database() as url:
                        self.assertIn('/astra_native_',url)
                        if fail: raise native.Failure('injected child failure')
                except native.Failure:
                    self.assertTrue(fail)
            self.assertTrue(any(s.startswith('CREATE DATABASE') for s in calls))
            self.assertTrue(any(s.startswith('DROP DATABASE') for s in calls))
            self.assertTrue('NOT EXISTS' in calls[-1])

    def test_cleanup_failure_is_never_reported_complete(self):
        cluster=native.Cluster(URL,'psql')
        def sql(url,statement):
            if statement.startswith('DROP DATABASE'): raise native.Failure('drop failed')
            return ''
        with patch.object(cluster,'sql',side_effect=sql),contextlib.redirect_stdout(io.StringIO()),self.assertRaises(native.Failure):
            with cluster.database(): pass

    def test_command_output_is_bounded_with_a_small_positive_control(self):
        with patch.object(native,'MAX_COMMAND_OUTPUT',1024):
            code,text=native.command([sys.executable,'-c','print("small")'],os.environ.copy(),10)
            self.assertEqual((code,text),(0,'small\n'))
            with self.assertRaises(native.Failure):
                native.command([sys.executable,'-c','print("x"*2048)'],os.environ.copy(),10)

    def test_absent_url_is_an_explicit_countable_skip(self):
        stream=io.StringIO()
        with patch.dict(native.os.environ,{},clear=True),contextlib.redirect_stdout(stream):
            code=native.main([])
        self.assertEqual(code,77)
        self.assertIn('skip: native-federation',stream.getvalue())
        with self.assertRaises(native.Failure):native.complete(stream.getvalue(),35)

    def test_over_budget_cleanup_does_not_buffer_termination_output(self):
        child = ('import signal,sys,time\n'
                 'def stop(*args):\n'
                 ' sys.stdout.write("x" * (2 * 1024 * 1024)); sys.stdout.flush(); sys.exit(0)\n'
                 'signal.signal(signal.SIGTERM,stop)\n'
                 'print("x" * 2048,flush=True)\n'
                 'time.sleep(20)\n')
        tracemalloc.start()
        try:
            with patch.object(native,'MAX_COMMAND_OUTPUT',1024),self.assertRaises(native.Failure):
                native.command([sys.executable,'-c',child],os.environ.copy(),5)
            _,peak = tracemalloc.get_traced_memory()
        finally:
            tracemalloc.stop()
        # A 1KiB diagnostic limit must not retain a 2MiB termination payload.
        self.assertLess(peak,512 * 1024)

    def test_timeout_kills_descendant_after_group_leader_exits(self):
        code, text = native.command([sys.executable, '-c', 'print("control")'], os.environ.copy(), 5)
        self.assertEqual((code, text), (0, 'control\n'))
        with tempfile.TemporaryDirectory(dir=os.environ['TMPDIR']) as scratch:
            pid_file = Path(scratch) / 'owned-child.pid'
            env = dict(os.environ, OWNED_CHILD_PID_FILE=str(pid_file))
            child = ('import os,signal,time\nfrom pathlib import Path\n'
                     'signal.signal(signal.SIGTERM,signal.SIG_IGN)\n'
                     'Path(os.environ["OWNED_CHILD_PID_FILE"]).write_text(str(os.getpid()))\n'
                     'time.sleep(60)\n')
            leader = ('import subprocess,sys,time\n'
                      f'subprocess.Popen([sys.executable,"-c",{child!r}],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)\n'
                      'time.sleep(60)\n')
            descendant = None
            try:
                with self.assertRaises(native.Failure):
                    native.command([sys.executable, '-c', leader], env, 3)
                self.assertTrue(pid_file.is_file(), 'descendant must install SIGTERM refusal before timeout')
                descendant = int(pid_file.read_text())
                deadline = time.monotonic() + 2
                while True:
                    state = subprocess.run(['ps', '-o', 'stat=', '-p', str(descendant)],
                                           capture_output=True, text=True, timeout=2)
                    self.assertIn(state.returncode, (0, 1), 'process census must succeed')
                    # An orphan awaiting reaping is dead; a sleeping child is a leak.
                    if not state.stdout.strip() or state.stdout.strip().startswith('Z'):
                        break
                    if time.monotonic() >= deadline:
                        self.fail('owned SIGTERM-ignoring descendant survived group cleanup')
                    time.sleep(0.02)
            finally:
                # The RED test must not leave its deliberately stubborn child behind.
                if descendant is None and pid_file.is_file():
                    descendant = int(pid_file.read_text())
                if descendant is not None:
                    try:
                        os.kill(descendant, signal.SIGKILL)
                    except ProcessLookupError:
                        pass

if __name__ == '__main__':
    unittest.main()
