#!/usr/bin/env python3
"""No host test slot (#7914) is held while a test binary compiles or links (#9511, #9733).

Runs the WHOLE `Run tests (impact-aware)` step of ci.yml with bash, as the linux-fed
enterprise-fed leg (HOST_SEMAPHORE_SLOTS > 0), in a scratch tree under .local-runs with:
the real scripts/ci/host_semaphore.py (its slot locks under the scratch HOME), a fake
partition script and a fake `cargo` that, on every call, probes each slot lock with a
shared non-blocking flock and records which semaphores were held at that moment.

The class invariant, checked over every recorded call:
* the union build (`--message-format=json-render-diagnostics`) and every doc-test call
  (`--doc`: rustdoc compiles each doctest at run time) run with no test slot held;
* a `--no-run` prebuild inside the hold names only targets the union build already
  compiled, with the same features (a cargo no-op), never a new selection;
* the test runs still hold a slot (the run phase stays bounded, #7914);
* exactly one union build.

Plus: a build failure fails red with the compiler output and no slot taken; the run phase
fails closed without the build record; the build has its own timeout; waits are recorded in
the job summary; the build semaphore's bound behaviour; the sibling table.

Run: python3 -m unittest discover -s scripts/ci/tests
Python 3.12+, standard library only.
"""
import fcntl
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
CI_YML = REPO / '.github' / 'workflows' / 'ci.yml'
WORKFLOWS = REPO / '.github' / 'workflows'
SCRATCH_PARENT = REPO / '.local-runs'
TESTS_SLOT = 'linux-fed-tests'
UNION_FLAG = '--message-format=json-render-diagnostics'
STEP_TIMEOUT_SECS = 120
COPIED_SCRIPTS = ('scripts/ci/host_semaphore.py', 'scripts/ci/workflow_annotation.py',
                  'scripts/ci/load_gate.py')
TEST_NAMES = ('alpha_test', 'beta_test', 'gamma_test')
COMPILER_ERROR = 'error[E0425]: fake compile error from the #9511 stub'

FAKE_CARGO = r'''#!%(py)s -I
import fcntl, glob, json, os, sys, time
argv = sys.argv[1:]
root = os.path.join(os.environ["HOME"], ".cache", "ai-memory-ci", "semaphore")
held = []
for path in sorted(glob.glob(os.path.join(root, "*", "slot-*.lock"))):
    fd = os.open(path, os.O_RDONLY)
    try:
        fcntl.flock(fd, fcntl.LOCK_SH | fcntl.LOCK_NB)
        fcntl.flock(fd, fcntl.LOCK_UN)
    except OSError:
        held.append(os.path.basename(os.path.dirname(path)))
    finally:
        os.close(fd)
with open(%(log)r, "a") as log:
    log.write(json.dumps({"argv": argv, "held": sorted(set(held))}) + "\n")
if "%(union)s" in argv:
    time.sleep(float(os.environ.get("FAKE_CARGO_UNION_SLEEP", "0")))
    rc = int(os.environ.get("FAKE_CARGO_UNION_RC", "0"))
    if rc:
        print("%(err)s", file=sys.stderr)
        sys.exit(rc)
    print('{"reason":"build-finished","success":true}')
    sys.exit(0)
if "--doc" in argv:
    print("test result: ok. 1 passed; 0 failed (doc)")
    sys.exit(int(os.environ.get("FAKE_CARGO_DOC_RC", "0")))
if "--no-run" not in argv:
    print("test result: ok. 1 passed; 0 failed")
sys.exit(0)
'''

FAKE_PARTITION = r'''#!/usr/bin/env python3
"""Fake partition (#9511 test): fixed shard lists from an existing build record."""
import argparse, os, sys
p = argparse.ArgumentParser()
p.add_argument("--build-json", required=True)
p.add_argument("--repo-root")
p.add_argument("--out-dir", required=True)
p.add_argument("--with-doc")
a = p.parse_args()
if not os.path.isfile(a.build_json) or os.path.getsize(a.build_json) == 0:
    print("fake partition: no build record", file=sys.stderr)
    sys.exit(2)
files = {"serial.txt": "--lib\n--test alpha_test\n", "parallel_1.txt": "--lib\n--test beta_test\n",
         "parallel_2.txt": "--test gamma_test\n", "lib_pg_filters.txt": "store::postgres\n"}
for name, body in files.items():
    with open(os.path.join(a.out_dir, name), "w") as fh:
        fh.write(body)
'''


def step_parts(ci_text):
    """Return (env constants of the step, the step script) of `Run tests (impact-aware)`."""
    m = re.search(r'      - name: Run tests \(impact-aware\)\n(.*?)\n        run: \|\n(.*?)\n      (?:#|- )',
                  ci_text, re.S)
    if not m:
        raise AssertionError('Run tests step not found')
    consts = dict(re.findall(r"^\s+([A-Z][A-Z0-9_]*): '(\d+)'$", m.group(1), re.M))
    lines = m.group(2).split('\n')
    script = '\n'.join(line[10:] if line.startswith(' ' * 10) else line.lstrip() for line in lines)
    return consts, script


def scratch_dir():
    SCRATCH_PARENT.mkdir(exist_ok=True)
    return Path(tempfile.mkdtemp(prefix='ci-9511-', dir=str(SCRATCH_PARENT)))


def run_step(ci_text, impact='__ALL__', node='linux-fed', slots='2', extra_env=None, consts_override=None):
    """Run the step; return (rc, calls, output, summary text)."""
    work = scratch_dir()
    try:
        (work / 'tests').mkdir()
        for name in TEST_NAMES:
            (work / 'tests' / ('%s.rs' % name)).write_text('')
        (work / 'scripts' / 'ci').mkdir(parents=True)
        for rel in COPIED_SCRIPTS:
            shutil.copyfile(str(REPO / rel), str(work / rel))
        (work / 'scripts' / 'ci' / 'partition_test_binaries.py').write_text(FAKE_PARTITION)
        (work / 'bin').mkdir()
        (work / 'home').mkdir()
        calls_log = work / 'cargo-calls.jsonl'
        fake = work / 'bin' / 'cargo'
        fake.write_text(FAKE_CARGO % {'py': sys.executable, 'log': str(calls_log), 'union': UNION_FLAG,
                                      'err': COMPILER_ERROR})
        fake.chmod(0o755)
        consts, script = step_parts(ci_text)
        consts.update(consts_override or {})
        step = work / 'step.sh'
        step.write_text(script + '\n')
        summary = work / 'summary.md'
        env = {k: v for k, v in os.environ.items()
               if not k.startswith(('HOST_SEMAPHORE', 'CI_', 'BUILD_', 'TEST_IMPACT', 'GITHUB_', 'AI_MEMORY_TEST'))}
        env.update(consts)
        env.update(PATH='%s%s%s' % (work / 'bin', os.pathsep, os.environ.get('PATH', '')),
                   HOME=str(work / 'home'), AI_MEMORY_NO_CONFIG='1', TIER='enterprise-fed', CI_NODE=node,
                   TEST_IMPACT=impact, DOCS_ONLY='false', JOB_TIMEOUT_MIN='300', JOB_T0=str(int(time.time())),
                   HOST_SEMAPHORE_SLOTS=slots, RUNNER_TEMP=str(work), GITHUB_ENV=str(work / 'github-env'),
                   GITHUB_STEP_SUMMARY=str(summary))
        env.update(extra_env or {})
        res = subprocess.run(['bash', '--noprofile', '--norc', '-eo', 'pipefail', str(step)], cwd=str(work),
                             env=env, capture_output=True, text=True, timeout=STEP_TIMEOUT_SECS)
        calls = [json.loads(line) for line in calls_log.read_text().splitlines()] if calls_log.exists() else []
        return res.returncode, calls, res.stdout + res.stderr, summary.read_text() if summary.exists() else ''
    finally:
        shutil.rmtree(str(work), ignore_errors=True)


def call_kind(argv):
    if UNION_FLAG in argv:
        return 'union'
    if '--doc' in argv:
        return 'doc'
    if '--no-run' in argv:
        return 'prebuild'
    return 'run'


def selection(argv):
    """(features, set of target selectors) of the cargo words before `--`."""
    words = argv[:argv.index('--')] if '--' in argv else list(argv)
    feats, targets, i = [], set(), 0
    while i < len(words):
        w = words[i]
        if w == '--features':
            feats.append(words[i + 1])
            i += 2
            continue
        if w in ('--test', '--bin', '--example', '--bench'):
            targets.add((w, words[i + 1]))
            i += 2
            continue
        if w == '--lib':
            targets.add(('--lib', ''))
        i += 1
    return tuple(feats), targets


def violations(calls):
    """Every way the recorded cargo calls break the #9511 invariant (empty = sound)."""
    out = []
    unions = [c for c in calls if call_kind(c['argv']) == 'union']
    if len(unions) != 1:
        out.append('expected exactly one union build, got %d' % len(unions))
    for c in calls:
        kind = call_kind(c['argv'])
        in_hold = TESTS_SLOT in c['held']
        if kind in ('union', 'doc') and in_hold:
            out.append('%s compile inside the test slot hold: cargo %s' % (kind, ' '.join(c['argv'])))
        if kind == 'prebuild' and in_hold:
            if not unions:
                out.append('prebuild inside the hold with no union build: cargo %s' % ' '.join(c['argv']))
                continue
            u_feats, u_targets = selection(unions[0]['argv'])
            feats, targets = selection(c['argv'])
            if feats != u_feats or (u_targets and not targets <= u_targets):
                out.append('prebuild inside the hold compiles beyond the union build: cargo %s'
                           % ' '.join(c['argv']))
    runs = [c for c in calls if call_kind(c['argv']) == 'run']
    if not runs:
        out.append('no test run happened')
    elif not all(TESTS_SLOT in c['held'] for c in runs):
        out.append('a test run happened without the test slot (run phase no longer bounded)')
    return out


class BuildOutsideSlot(unittest.TestCase):
    """The linux-fed enterprise-fed leg: build first, then the slot for the run only."""

    def setUp(self):
        self.ci = CI_YML.read_text()

    def test_full_suite_compiles_outside_the_slot(self):
        rc, calls, out, _ = run_step(self.ci)
        self.assertEqual(rc, 0, out[-3000:])
        self.assertEqual(violations(calls), [], out[-2000:])

    def test_impact_selected_compiles_outside_the_slot(self):
        rc, calls, out, _ = run_step(self.ci, impact='alpha_test beta_test')
        self.assertEqual(rc, 0, out[-3000:])
        self.assertEqual(violations(calls), [], out[-2000:])

    def test_build_failure_is_red_with_compiler_output_and_no_slot(self):
        rc, calls, out, _ = run_step(self.ci, extra_env={'FAKE_CARGO_UNION_RC': '101'})
        self.assertEqual(rc, 101, out[-3000:])
        self.assertIn(COMPILER_ERROR, out)
        self.assertEqual([c for c in calls if call_kind(c['argv']) == 'run'], [])
        self.assertFalse(any(TESTS_SLOT in c['held'] for c in calls), calls)
        self.assertNotIn("[#7914 semaphore] 'linux-fed/enterprise-fed': slot", out)

    def test_doc_test_failure_is_red_and_the_shards_still_run(self):
        rc, calls, out, _ = run_step(self.ci, extra_env={'FAKE_CARGO_DOC_RC': '101'})
        self.assertNotEqual(rc, 0, out[-3000:])
        self.assertTrue([c for c in calls if call_kind(c['argv']) == 'run'], 'the shards must still run (#2500)')
        self.assertEqual([v for v in violations(calls) if 'compile inside' in v], [])

    def test_run_phase_fails_closed_without_the_build_record(self):
        rc, calls, out, _ = run_step(self.ci, extra_env={'CI_SHARD_PHASE': 'run', 'HOST_SEMAPHORE_HELD': '1'})
        self.assertEqual(rc, 2, out[-3000:])
        self.assertIn('[#9511] run phase refused: no build record', out)
        self.assertEqual([c for c in calls if call_kind(c['argv']) in ('union', 'run')], [])

    def test_build_has_its_own_timeout(self):
        consts, _ = step_parts(self.ci)
        self.assertIn('BUILD_PHASE_TIMEOUT_SECS', consts, 'the build timeout must be one named env constant')
        rc, calls, out, _ = run_step(self.ci, extra_env={'FAKE_CARGO_UNION_SLEEP': '20'},
                                     consts_override={'BUILD_PHASE_TIMEOUT_SECS': '2'})
        self.assertEqual(rc, 124, out[-3000:])
        self.assertIn('[#9511] build phase exceeded the 2s build timeout', out)
        self.assertEqual([c for c in calls if call_kind(c['argv']) == 'run'], [])

    def test_waits_are_recorded_in_the_job_summary(self):
        rc, _, out, summary = run_step(self.ci)
        self.assertEqual(rc, 0, out[-3000:])
        self.assertRegex(summary, r"\| linux-fed-build \| linux-fed/enterprise-fed \| \d+ \| slot \d of \d+ \|")
        self.assertRegex(summary, r"\| linux-fed-tests \| linux-fed/enterprise-fed \| \d+ \| slot \d of \d+ \|")


class BuildSemaphoreBound(unittest.TestCase):
    """The build semaphore's bound: proceed-with-record (decision in ci.yml), the test slot unchanged."""

    def setUp(self):
        self.work = scratch_dir()
        self.addCleanup(shutil.rmtree, str(self.work), True)

    def _hold_all(self, name, slots):
        slot_dir = self.work / 'root' / name
        slot_dir.mkdir(parents=True)
        fds = []
        for i in range(slots):
            fd = os.open(str(slot_dir / ('slot-%d.lock' % i)), os.O_RDWR | os.O_CREAT, 0o600)
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            fds.append(fd)
        for fd in fds:
            self.addCleanup(os.close, fd)

    def _run(self, *flags):
        marker = self.work / 'ran'
        summary = self.work / 'summary.md'
        env = dict(os.environ, GITHUB_STEP_SUMMARY=str(summary))
        cmd = [sys.executable, '-I', str(REPO / 'scripts' / 'ci' / 'host_semaphore.py'), '--name', 'linux-fed-build',
               '--slots', '1', '--max-wait-secs', '0', '--poll-secs', '1', '--label', 'l/t', '--root',
               str(self.work / 'root')] + list(flags) + [
               '--', sys.executable, '-c',
               'import os, pathlib; pathlib.Path(%r).write_text(os.environ.get("HOST_SEMAPHORE_OVERFLOW", "-"))'
               % str(marker)]
        res = subprocess.run(cmd, env=env, capture_output=True, text=True, timeout=60)
        return res, (marker.read_text() if marker.exists() else None), (summary.read_text()
                                                                       if summary.exists() else '')

    def test_bound_reached_proceeds_with_record(self):
        self._hold_all('linux-fed-build', 1)
        res, ran, summary = self._run('--on-timeout', 'proceed')
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
        self.assertEqual(ran, '1', 'the command runs, marked as an overflow run')
        self.assertIn('::warning', res.stdout)
        self.assertIn('bound reached', summary)

    def test_default_bound_still_fails_with_3(self):
        self._hold_all('linux-fed-build', 1)
        res, ran, summary = self._run()
        self.assertEqual(res.returncode, 3, res.stdout + res.stderr)
        self.assertIsNone(ran)
        self.assertIn('no slot', summary)

    def test_bound_constants_are_named_and_short(self):
        consts, _ = step_parts(CI_YML.read_text())
        for name in ('BUILD_SEMAPHORE_SLOTS', 'BUILD_SEMAPHORE_MAX_WAIT_SECS', 'BUILD_PHASE_TIMEOUT_SECS'):
            self.assertIn(name, consts)
        self.assertLess(int(consts['BUILD_SEMAPHORE_MAX_WAIT_SECS']), int(consts['HOST_SEMAPHORE_MAX_WAIT_SECS']))
        self.assertIn('--on-timeout proceed', CI_YML.read_text())


class LoadGateRecord(unittest.TestCase):
    """#9733: the gate's wait lands in the job summary; no long wait where the build semaphore gates."""

    def test_gate_wait_is_written_to_the_summary(self):
        work = scratch_dir()
        self.addCleanup(shutil.rmtree, str(work), True)
        summary = work / 'summary.md'
        env = dict(os.environ, GITHUB_STEP_SUMMARY=str(summary))
        res = subprocess.run([sys.executable, '-I', str(REPO / 'scripts' / 'ci' / 'load_gate.py'), '--label', 'l/t',
                              '--max-ratio', '1000', '--max-wait-secs', '0'], env=env, capture_output=True,
                             text=True, timeout=60)
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
        self.assertRegex(summary.read_text() if summary.exists() else '',
                         r'\| load gate \| l/t \| 0 \| condition \|')

    def test_linux_fed_enterprise_gate_does_not_wait_long(self):
        ci = CI_YML.read_text()
        m = re.search(r'      - name: Load gate \(#6795\)\n(.*?)\n      - name: Run tests', ci, re.S)
        self.assertIsNotNone(m)
        wait = re.search(r"LOAD_GATE_MAX_WAIT_SECS: \$\{\{ (.+?) \}\}", m.group(1))
        self.assertIsNotNone(wait, 'the gate wait must be one named expression on the gate step')
        self.assertIn("matrix.node == 'linux-fed' && matrix.tier == 'enterprise-fed' && '0'", wait.group(1))
        self.assertIn('--max-wait-secs "$LOAD_GATE_MAX_WAIT_SECS"', m.group(1))


class Siblings(unittest.TestCase):
    """Every workflow leg and wrapper that could take the host slot (the sibling table of READY)."""

    def test_only_the_run_tests_step_calls_the_semaphore(self):
        for path in sorted(WORKFLOWS.glob('*.y*ml')):
            text = path.read_text()
            if path.name != 'ci.yml':
                self.assertNotIn('host_semaphore', text, path.name)
                continue
            _, script = step_parts(text)
            calls = re.findall(r'host_semaphore\.py --name (\S+)', text)
            self.assertEqual(sorted(calls), ['linux-fed-build', 'linux-fed-tests'], calls)
            self.assertEqual(len(re.findall(r'host_semaphore\.py --name', script)), 2,
                             'every semaphore call sits in the Run tests step')

    def test_postgres_legs_never_take_the_slot(self):
        for name in ('postgres-ignored.yml', 'cert-postgres-age.yml'):
            self.assertNotIn('host_semaphore', (WORKFLOWS / name).read_text(), name)

    def test_pg_isolated_wrapper_never_takes_the_slot(self):
        self.assertNotIn('host_semaphore', (REPO / 'scripts' / 'test' / 'pg_isolated_binary.py').read_text())

    def test_slots_are_zero_on_every_other_leg(self):
        consts_expr = re.search(r"HOST_SEMAPHORE_SLOTS: \$\{\{ (.+?) \}\}", CI_YML.read_text()).group(1)
        self.assertEqual(consts_expr, "matrix.node == 'linux-fed' && matrix.tier == 'enterprise-fed' && '2' || '0'")

    def test_macos_fed_enterprise_leg_takes_no_slot_and_keeps_one_pass(self):
        rc, calls, out, _ = run_step(CI_YML.read_text(), node='macos-fed', slots='0')
        self.assertEqual(rc, 0, out[-3000:])
        self.assertFalse(any(c['held'] for c in calls), calls)
        self.assertEqual(len([c for c in calls if call_kind(c['argv']) == 'union']), 1)
        self.assertEqual(len([c for c in calls if call_kind(c['argv']) == 'doc']), 1)

    def test_run_sharded_has_two_callers(self):
        _, script = step_parts(CI_YML.read_text())
        self.assertEqual(len(re.findall(r'^\s*run_sharded "', script, re.M)), 2)


if __name__ == '__main__':
    unittest.main()
