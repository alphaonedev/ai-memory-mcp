#!/usr/bin/env python3
"""Issue #5038: the #3607 posture recapture stamps the run date, not a template date.

`posture-legs-exit-codes.txt` is the header of every cert evidence bundle the
recapture script produces. Its first line used to hardcode `2026-09-11`, so each
re-issue recorded a stale date beside a current git sha. These tests run the
recapture against stub `ai-memory` binaries in a throwaway sandbox repo under
`.local-runs/` (never a tmpfs) and pin: the header date is the UTC run date, the
short sha is kept, the four leg exit codes are recorded, the sanitizer labels are
byte-stable (the 12/12 cross-re-issue fixture comparison depends on them), and a
header whose date disagrees with the run date is refused.

Run: python3 -m unittest scripts/ci/tests/test_recapture_cert_3607_5038.py
"""
import datetime
import importlib.util
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
SCRIPT_NAME = 'recapture-cert-3607-posture.py'
GATE_NAME = 'check-posture-ladder.py'
SCRATCH = REPO / '.local-runs'
OUT_REL = Path('docs') / 'compliance' / 'evidence' / 'cert-3607'
HEADER_RE = re.compile(
    r'^# posture-legs transcript — recorded exit codes '
    r'\((\d{4}-\d{2}-\d{2}) #3607 re-issue recapture \(22 checks\) @ ([0-9a-f]+)\)$')
TEMPLATE_DATE = '2026-09-11'
SANITIZED_FIXTURE_LABEL = '<repo-root>/.local-runs/cert-3607-fixtures'

# A stub `ai-memory`: `rules keygen` writes the operator key pair, `stats` is a
# no-op, `doctor --posture ...` prints check rows that embed the repo and fixture
# paths (so the sanitizer is exercised) and exits with a value keyed on the env.
STUB = '''#!%(python)s
import os, sys
args = sys.argv[1:]
env = os.environ
if args[:2] == ['rules', 'keygen']:
    kd = env['AI_MEMORY_KEY_DIR']
    open(os.path.join(kd, 'operator.key'), 'w').write('k\\n')
    open(os.path.join(kd, 'operator.key.pub'), 'w').write('PUBKEY\\n')
    sys.exit(0)
if args[:1] == ['stats']:
    sys.exit(0)
hard = env.get('AI_MEMORY_SECURITY_PROFILE') == 'asi-hard'
armed = env.get('AI_MEMORY_REQUIRE_ENTERPRISE_FEDERATION_POSTURE') == '1'
sqlcipher = 'sqlcipher' in sys.argv[0]
# The certified ladder (#5036): bare 12 PASS / 10 FAIL, hardened 20/2, sqlcipher 22/0.
# A `<stub>.mode` file beside the binary switches the stub to a posture regression.
try:
    mode = open(sys.argv[0] + '.mode').read().strip()
except OSError:
    mode = 'healthy'
if args[:1] == ['doctor'] and '--posture' not in args:
    if mode == 'bypass':
        print('[PASS] boot gate never refuses')
        sys.exit(0)
    print('Error: certified posture refuses to boot - 1 required control(s) missing or below floor:')
    print('  - AI_MEMORY_ENCRYPT_AT_REST: needs sqlcipher, key dir ' + env['AI_MEMORY_KEY_DIR'])
    sys.exit(1)
if mode == 'bypass':
    passes, fails = 22, 0
elif not hard:
    passes, fails = 12, 10
elif sqlcipher:
    passes, fails = 22, 0
else:
    passes, fails = (19, 3) if mode == 'drift' else (20, 2)
print('[PASS] sample ' + env['AI_MEMORY_KEY_DIR'] + ' HOME=' + env['HOME'])
for i in range(passes - 1):
    print('[PASS] check %%d' %% i)
for i in range(fails):
    print('[FAIL] check %%d' %% i)
print('overall: ' + ('FAIL' if fails else 'PASS'))
sys.exit(2 if fails else 0)
''' % {'python': sys.executable}


# Hermetic stand-in for the `cryptography` Ed25519 calls the fixture writer makes,
# so the test does not depend on the runner having that package.
CRYPTO_STUB = {
    'cryptography/__init__.py': '',
    'cryptography/hazmat/__init__.py': '',
    'cryptography/hazmat/primitives/__init__.py': '',
    'cryptography/hazmat/primitives/asymmetric/__init__.py': '',
    'cryptography/hazmat/primitives/asymmetric/ed25519.py': (
        'import os\n'
        'class _Pub:\n'
        '    def __init__(self, raw): self.raw = raw\n'
        '    def public_bytes(self, enc, fmt): return self.raw\n'
        'class Ed25519PrivateKey:\n'
        '    def __init__(self): self.raw = os.urandom(32)\n'
        '    @classmethod\n'
        '    def generate(cls): return cls()\n'
        '    def private_bytes(self, enc, fmt, enc_alg): return self.raw\n'
        '    def public_key(self): return _Pub(self.raw[::-1])\n'),
    'cryptography/hazmat/primitives/serialization.py': (
        'class Encoding: Raw = 1\n'
        'class PublicFormat: Raw = 1\n'
        'class PrivateFormat: Raw = 1\n'
        'def NoEncryption(): return None\n'),
}


class RecaptureBase(unittest.TestCase):
    """Builds a sandbox repo with the script, stub binaries and a signed-free commit."""

    maxDiff = None

    def setUp(self):
        SCRATCH.mkdir(exist_ok=True)
        self.root = Path(tempfile.mkdtemp(prefix='recapture-5038-', dir=str(SCRATCH)))
        self.addCleanup(shutil.rmtree, str(self.root), True)
        (self.root / 'scripts').mkdir()
        for name in (SCRIPT_NAME, GATE_NAME):
            shutil.copy2(str(REPO / 'scripts' / name), str(self.root / 'scripts' / name))
        self.git('init', '-q')
        (self.root / 'seed.txt').write_text('seed\n')
        self.git('add', 'seed.txt')
        self.git('-c', 'user.name=t', '-c', 'user.email=sandbox@localhost',
                 '-c', 'commit.gpgsign=false', 'commit', '-q', '-m', 'seed')
        self.sha = self.git('rev-parse', '--short', 'HEAD').strip()
        self.default_bin = self.make_stub('ai-memory-default')
        self.sqlcipher_bin = self.make_stub('ai-memory-sqlcipher')
        self.home = Path(tempfile.mkdtemp(prefix='recapture-5038-home-', dir=str(SCRATCH)))
        self.addCleanup(shutil.rmtree, str(self.home), True)
        self.pystubs = self.root / 'pystubs'
        for rel, body in CRYPTO_STUB.items():
            target = self.pystubs / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(body)

    def git(self, *args):
        done = subprocess.run(['git', '-C', str(self.root)] + list(args),
                              capture_output=True, text=True, check=True)
        return done.stdout

    def make_stub(self, name):
        path = self.root / name
        # Distinct bytes per build: the ladder gate requires distinct binaries (#5036).
        path.write_text(STUB + '# build: ' + name + '\n')
        path.chmod(0o755)
        return path

    def run_recapture(self, sqlcipher_bin=None):
        env = {
            'PATH': os.environ.get('PATH', '/usr/bin:/bin'),
            'HOME': str(self.home),
            'PYTHONPATH': str(self.pystubs),
            'DEFAULT_BIN': str(self.default_bin),
            'SQLCIPHER_BIN': str(sqlcipher_bin or self.sqlcipher_bin),
        }
        script = self.root / 'scripts' / SCRIPT_NAME
        cmd = ['bash', str(script)] if script.suffix == '.sh' else [sys.executable, str(script)]
        before = datetime.datetime.now(datetime.timezone.utc).date().isoformat()
        done = subprocess.run(cmd, env=env, cwd=str(self.root), capture_output=True, text=True)
        after = datetime.datetime.now(datetime.timezone.utc).date().isoformat()
        return done, {before, after}

    def out(self, name):
        return (self.root / OUT_REL / name).read_text()


class HeaderDate5038(RecaptureBase):
    def test_header_date_is_the_utc_run_date(self):
        done, run_dates = self.run_recapture()
        self.assertEqual(done.returncode, 0, done.stderr)
        header = self.out('posture-legs-exit-codes.txt').splitlines()[0]
        match = HEADER_RE.match(header)
        self.assertIsNotNone(match, header)
        self.assertIn(match.group(1), run_dates, 'header date is not the run date: ' + header)
        self.assertNotEqual(match.group(1), TEMPLATE_DATE)

    def test_header_keeps_the_short_sha(self):
        done, _ = self.run_recapture()
        self.assertEqual(done.returncode, 0, done.stderr)
        header = self.out('posture-legs-exit-codes.txt').splitlines()[0]
        match = HEADER_RE.match(header)
        self.assertIsNotNone(match, header)
        self.assertEqual(match.group(2), self.sha)

    def test_leg_exit_codes_are_recorded(self):
        done, _ = self.run_recapture()
        self.assertEqual(done.returncode, 0, done.stderr)
        text = self.out('posture-legs-exit-codes.txt')
        self.assertEqual(re.findall(r'^exit: (\S+)$', text, re.M), ['2', '2', '1', '0'])
        self.assertIn('exits e1=2 e2=2 e3=1 e4=0', done.stdout)

    def test_missing_sqlcipher_binary_records_missing_and_fails_closed(self):
        # #5036: a skipped leg 4 is still recorded, but the ladder cannot be
        # asserted, so the run exits non-zero (it used to exit 0).
        done, _ = self.run_recapture(sqlcipher_bin=self.root / 'no-such-binary')
        self.assertNotEqual(done.returncode, 0, done.stdout)
        text = self.out('posture-legs-exit-codes.txt')
        self.assertEqual(re.findall(r'^exit: (\S+)$', text, re.M), ['2', '2', '1', 'missing'])
        self.assertIn('leg4 skipped', done.stdout)
        self.assertIn('SKIPPED', done.stdout)


class PostureLadder5036(RecaptureBase):
    """The recapture asserts the ladder: a wrong shape must not exit 0 (#5036)."""

    def set_mode(self, mode, *binaries):
        for binary in binaries:
            Path(str(binary) + '.mode').write_text(mode + '\n')

    def test_healthy_ladder_is_asserted_green(self):
        done, _ = self.run_recapture()
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        self.assertIn('LADDER ASSERTED GREEN', done.stdout)

    def test_posture_bypassed_ladder_exits_nonzero(self):
        self.set_mode('bypass', self.default_bin, self.sqlcipher_bin)
        done, _ = self.run_recapture()
        self.assertEqual(done.returncode, 1, done.stdout + done.stderr)
        self.assertIn('LADDER VIOLATED', done.stdout)
        self.assertEqual(re.findall(r'^exit: (\S+)$', self.out('posture-legs-exit-codes.txt'), re.M),
                         ['0', '0', '0', '0'])

    def test_drifted_counts_exit_nonzero(self):
        self.set_mode('drift', self.default_bin, self.sqlcipher_bin)
        done, _ = self.run_recapture()
        self.assertEqual(done.returncode, 1, done.stdout + done.stderr)
        self.assertIn('posture-hardened-env.out PASS=19 FAIL=3', done.stdout)

    def test_identical_default_and_sqlcipher_binaries_exit_nonzero(self):
        # leg 4's exit 0 must come from a distinct sqlcipher build.
        same = self.root / 'ai-memory-sqlcipher-copy'
        same.write_bytes(self.default_bin.read_bytes())
        same.chmod(0o755)
        done, _ = self.run_recapture(sqlcipher_bin=same)
        self.assertEqual(done.returncode, 1, done.stdout + done.stderr)
        self.assertIn('share sha256', done.stdout)

    def test_evidence_is_kept_when_the_ladder_is_violated(self):
        self.set_mode('bypass', self.default_bin, self.sqlcipher_bin)
        self.run_recapture()
        self.assertTrue((self.root / OUT_REL / 'posture-legs-exit-codes.txt').is_file())

    def test_gate_self_test_rejects_every_mutant(self):
        done, _ = self.run_recapture()
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        gate = self.root / 'scripts' / GATE_NAME
        scratch = self.root / 'selftest'
        scratch.mkdir()
        shutil.copytree(str(self.root / OUT_REL), str(scratch / 'evidence'))
        result = subprocess.run([sys.executable, str(gate), str(scratch / 'evidence'), '--self-test'],
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn('6/6 mutants rejected', result.stdout)


def load_script_module():
    """Import the hyphen-named script as a module (its main() is not run)."""
    spec = importlib.util.spec_from_file_location(
        'recapture_cert_3607_posture', str(REPO / 'scripts' / SCRIPT_NAME))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class HeaderSelfCheck5038(unittest.TestCase):
    """The script refuses a transcript whose header date is not the run date."""

    def setUp(self):
        SCRATCH.mkdir(exist_ok=True)
        self.dir = Path(tempfile.mkdtemp(prefix='recapture-5038-check-', dir=str(SCRATCH)))
        self.addCleanup(shutil.rmtree, str(self.dir), True)
        self.module = load_script_module()

    def write(self, first_line):
        path = self.dir / 'posture-legs-exit-codes.txt'
        path.write_text(first_line + '\n# each leg\n')
        return path

    def test_matching_date_is_accepted(self):
        path = self.write(self.module.header_line('2026-10-17', 'abc1234'))
        self.assertIsNone(self.module.check_header_date(path, '2026-10-17'))

    def test_template_date_is_refused(self):
        path = self.write(self.module.header_line(TEMPLATE_DATE, 'abc1234'))
        problem = self.module.check_header_date(path, '2026-10-17')
        self.assertIsNotNone(problem)
        self.assertIn(TEMPLATE_DATE, problem)
        self.assertIn('2026-10-17', problem)

    def test_malformed_header_is_refused(self):
        path = self.write('# something else entirely')
        self.assertIsNotNone(self.module.check_header_date(path, '2026-10-17'))

    def test_run_date_is_an_iso_utc_date(self):
        today = datetime.datetime.now(datetime.timezone.utc).date().isoformat()
        self.assertIn(self.module.utc_run_date(), {today})


class SanitizerBytes5038(RecaptureBase):
    """The sanitizer output is certified byte-identical across re-issues: pin it."""

    def test_repo_home_and_fixture_paths_are_collapsed(self):
        done, _ = self.run_recapture()
        self.assertEqual(done.returncode, 0, done.stderr)
        bare = self.out('posture-bare-env.out')
        self.assertIn('[PASS] sample ' + SANITIZED_FIXTURE_LABEL + '/keys HOME=<home>', bare)
        self.assertNotIn(str(self.root), bare)
        self.assertNotIn(str(self.home), bare)
        self.assertEqual(bare.count('[FAIL]'), 10)
        refusal = self.out('posture-hardened-boot-refusal.out')
        self.assertIn(SANITIZED_FIXTURE_LABEL + '/keys', refusal)

    def test_fixture_copies_and_no_raw_leftovers(self):
        done, _ = self.run_recapture()
        self.assertEqual(done.returncode, 0, done.stderr)
        out_dir = self.root / OUT_REL
        names = sorted(p.name for p in out_dir.iterdir())
        self.assertFalse([n for n in names if n.endswith('.raw')], names)
        self.assertIn('peer-fingerprints.txt', names)
        self.assertIn('peer-attestation.json', names)
        self.assertIn('posture-sqlcipher-pass.out', names)


if __name__ == '__main__':
    unittest.main()
