# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
import copy
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
from unittest.mock import patch
import unittest
import graph_baseline as baseline

class BaselineTests(unittest.TestCase):
    def records(self):
        return [dict(operation=operation,engine=engine,rows=rows,nodes=1024,
                     edges=1023,warmup=10,samples_us=list(range(1,201)))
                for (operation,engine),rows in baseline.EXPECTED.items()]

    def test_nearest_rank_percentiles_use_raw_samples(self):
        result=baseline.summarize(self.records())
        self.assertEqual(len(result),9)
        for row in result:
            self.assertEqual((row['n'],row['p50_us'],row['p95_us'],row['p99_us']),(200,100,190,198))
        data=self.records();data[0]['samples_us'].reverse()
        self.assertEqual(baseline.summarize(data)[0],result[0])

    def test_incomplete_or_duplicate_scenario_cannot_publish(self):
        baseline.summarize(self.records())
        for data in [[],self.records()[:-1],self.records()+[self.records()[0]]]:
            with self.subTest(count=len(data)),self.assertRaises(baseline.Failure):
                baseline.summarize(data)

    def test_empty_wrong_count_and_invalid_samples_cannot_publish(self):
        baseline.summarize(self.records())
        for key,value in [('rows',0),('nodes',0),('edges',0),('warmup',0),('samples_us',[]),('samples_us',[0]*200),('samples_us',[True]*200),('samples_us',[float('nan')]*200)]:
            data=copy.deepcopy(self.records());data[0][key]=value
            with self.subTest(key=key),self.assertRaises(baseline.Failure):
                baseline.summarize(data)

class FixtureControlTests(unittest.TestCase):
    def test_named_native_controls_cannot_be_vacuous(self):
        names=sorted(baseline.FIXTURE_TESTS)
        listing=''.join(f'{name}: test\n' for name in names)
        output=''.join(f'test {name} ... ok\n' for name in names)
        output+='test result: ok. 2 passed; 0 failed; 0 ignored;\n'
        self.assertEqual(baseline.complete_fixture_controls(listing,output),2)
        for listed,result in [('',output),(listing,''),(listing,output.replace(names[0],'unrelated_test')),
                (listing,output.replace('2 passed','0 passed')),(listing,output+'skip: database unavailable\n'),
                (listing+listing,output),(listing,output.replace('0 ignored','1 ignored'))]:
            with self.subTest(listing=listed,output=result),self.assertRaises(baseline.Failure):
                baseline.complete_fixture_controls(listed,result)

class EvidenceCleanupTests(unittest.TestCase):
    def test_cleanup_refuses_root_links_and_preserves_child_targets(self):
        scratch=baseline.ROOT/'.local-runs'
        scratch.mkdir(exist_ok=True)
        source=(baseline.ROOT/'scripts/check-evidence-bundle.sh').read_text()
        start=source.index('cleanup_evidence_selftest() {')
        end=source.index('\n}\n\nrun_self_test()',start)+2
        function=source[start:end]
        def clean(path):
            return subprocess.run(['bash','-c',function+'\ncleanup_evidence_selftest "$1"',
                                   '--',str(path)],capture_output=True,text=True,timeout=15)
        with tempfile.TemporaryDirectory(prefix='e6-cleanup-test-',dir=scratch) as tmp:
            root=Path(tmp)
            positive=root/'positive';positive.mkdir()
            (positive/'fixture.json').write_text('{}')
            self.assertEqual(clean(positive).returncode,0)
            self.assertFalse(positive.exists())
            target=root/'target';target.mkdir()
            kept=target/'must-survive.json';kept.write_text('{}')
            alias=root/'alias';alias.symlink_to(target,target_is_directory=True)
            with self.subTest(boundary='root symlink'):
                self.assertNotEqual(clean(alias).returncode,0)
                self.assertTrue(kept.exists(),'cleanup followed its root symlink')
            # Restore this independent positive control after a deliberately destructive RED.
            kept.write_text('{}')
            self.assertTrue(kept.exists())
            child_links=root/'child-links';child_links.mkdir()
            (child_links/'link').symlink_to(target,target_is_directory=True)
            with self.subTest(boundary='child symlink'):
                self.assertEqual(clean(child_links).returncode,0)
                self.assertFalse(child_links.exists())
                self.assertTrue(kept.exists(),'cleanup followed a child symlink')
            nested=root/'nested';nested.mkdir()
            (nested/'child').mkdir()
            marker=nested/'fixture.json';marker.write_text('{}')
            with self.subTest(boundary='unexpected directory'):
                self.assertNotEqual(clean(nested).returncode,0)
                self.assertTrue(marker.exists(),'refusal partially deleted fixtures')
                self.assertTrue((nested/'child').is_dir())

class ProcessTests(unittest.TestCase):
    """Real owned children; live executable hashing is stubbed for Python fixtures."""
    def setUp(self):
        scratch=baseline.ROOT/'.local-runs'
        scratch.mkdir(exist_ok=True)
        self.tmp=tempfile.TemporaryDirectory(prefix='e6-process-test-',dir=scratch)
        self.addCleanup(self.tmp.cleanup)
        self.out=Path(self.tmp.name)
        self.sha='a'*40
        self.env=os.environ.copy()
        self.env['AI_MEMORY_TEST_AGE_URL']='postgresql://fixture:synthetic@localhost/test'
        self.children=[]
        self.real_popen=subprocess.Popen
        def launch(*args,**kwargs):
            child=self.real_popen(*args,**kwargs)
            if kwargs.get('start_new_session'):self.children.append(child)
            return child
        self.addCleanup(self.cleanup_groups)
        self.enterContext(patch.object(baseline.subprocess,'Popen',side_effect=launch))
        self.enterContext(patch.object(baseline,'READY_SECONDS',2))
        self.enterContext(patch.object(baseline,'RUN_SECONDS',2))
        self.enterContext(patch.object(baseline,'STOP_SECONDS',0.15))
        self.enterContext(patch.object(baseline,'MAX_COMMAND_OUTPUT',1024))

    def cleanup_groups(self):
        # Only sessions created by this test, with cwd fixed to our checkout.
        for child in self.children:
            try:os.killpg(child.pid,signal.SIGKILL)
            except ProcessLookupError:pass
            child.wait(timeout=2)
            for stream in (child.stdin,child.stdout):
                if stream:
                    try:stream.close()
                    except OSError:pass

    def invoke(self,body):
        binary=self.out/'fixture.py'
        binary.write_text('#!'+sys.executable+'\nimport json,os,signal,sys,time\n'+body)
        binary.chmod(0o700)
        with patch.object(baseline,'command',return_value=(0,baseline.digest(binary))):
            return baseline.execute_bound(str(binary),self.env,self.sha,self.out)

    def ready(self):
        return 'line="GRAPH_READY "+json.dumps({"pid":os.getpid(),"source_commit":'+repr(self.sha)+'})+"\\n"\n'

    def positive(self):
        _,text=self.invoke(self.ready()+
            'sys.stdout.write(line);sys.stdout.flush()\nassert input()=="RUN"\nprint("fixture complete")\n')
        self.assertIn('fixture complete',text)

    def test_partial_readiness_line_obeys_the_deadline(self):
        self.positive()
        with self.assertRaisesRegex(baseline.Failure,'readiness timed out'):
            self.invoke(self.ready()+
                'sys.stdout.write(line[:1]);sys.stdout.flush()\ntime.sleep(3)\n'
                'sys.stdout.write(line[1:]);sys.stdout.flush()\ninput()\n')

    def test_success_terminates_descendants_after_leader_exit(self):
        self.positive()
        pidfile=self.out/'descendant.pid'
        self.invoke('child=os.fork()\nif child==0:\n'
            ' signal.signal(signal.SIGTERM,signal.SIG_IGN)\n'
            ' for fd in (0,1,2): os.dup2(os.open(os.devnull,os.O_RDWR),fd)\n'
            ' with open('+repr(str(pidfile)+'.tmp')+',"w") as f: f.write(str(os.getpid()))\n'
            ' os.replace('+repr(str(pidfile)+'.tmp')+','+repr(str(pidfile))+')\n'
            ' time.sleep(10)\n os._exit(0)\n'
            'deadline=time.monotonic()+2\n'
            'while not os.path.exists('+repr(str(pidfile))+'):\n'
            ' assert time.monotonic()<deadline\n time.sleep(0.01)\n'+self.ready()+
            'sys.stdout.write(line);sys.stdout.flush()\ninput()\n')
        self.assert_stopped(int(pidfile.read_text()))

    def assert_stopped(self,pid):
        deadline=time.monotonic()+1
        while time.monotonic()<deadline:
            try:os.kill(pid,0)
            except ProcessLookupError:return
            state=subprocess.run(['ps','-o','stat=','-p',str(pid)],capture_output=True,text=True,timeout=2).stdout.strip()
            if state.startswith('Z'):return  # A dead orphan awaits the OS reaper.
            time.sleep(0.01)
        self.fail('owned process survived cleanup')

    def test_closed_stdin_does_not_bypass_owned_cleanup(self):
        self.positive()
        with self.assertRaises(BrokenPipeError):
            self.invoke(self.ready()+
                'os.close(0)\nsys.stdout.write(line);sys.stdout.flush()\ntime.sleep(10)\n')
        self.assert_stopped(self.children[-1].pid)

    def test_output_budget_rejects_a_large_payload(self):
        self.positive()
        with self.assertRaisesRegex(baseline.Failure,'output.*budget'):
            self.invoke(self.ready()+
                'sys.stdout.write(line);sys.stdout.flush()\ninput()\nprint("x"*2048)\n')

if __name__=='__main__':unittest.main()
