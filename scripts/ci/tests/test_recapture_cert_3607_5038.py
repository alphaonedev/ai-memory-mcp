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
if args[:1] == ['doctor'] and '--posture' not in args:
    print('refusing boot: control missing in ' + env['AI_MEMORY_KEY_DIR'])
    sys.exit(1)
fails = 10 if not hard else (0 if sqlcipher else 2)
print('[PASS] sample ' + env['AI_MEMORY_KEY_DIR'] + ' HOME=' + env['HOME'])
for i in range(fails):
    print('[FAIL] check %%d' %% i)
tail = 'overall: ' + ('FAIL' if fails else 'PASS')
if os.path.exists(os.path.join(os.path.dirname(os.path.abspath(sys.argv[0])), 'no-final-newline')):
    sys.stdout.write(tail)
else:
    print(tail)
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
        shutil.copy2(str(REPO / 'scripts' / SCRIPT_NAME), str(self.root / 'scripts' / SCRIPT_NAME))
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
        path.write_text(STUB)
        path.chmod(0o755)
        return path

    def run_recapture(self, sqlcipher_bin=None, args=None, extra_env=None, default_bin=None):
        env = {
            'PATH': os.environ.get('PATH', '/usr/bin:/bin'),
            'HOME': str(self.home),
            'PYTHONPATH': str(self.pystubs),
            'DEFAULT_BIN': str(default_bin or self.default_bin),
            'SQLCIPHER_BIN': str(sqlcipher_bin or self.sqlcipher_bin),
        }
        env.update(extra_env or {})
        script = self.root / 'scripts' / SCRIPT_NAME
        cmd = ['bash', str(script)] if script.suffix == '.sh' else [sys.executable, str(script)]
        cmd += list(args or [])
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

    def test_missing_sqlcipher_binary_records_missing(self):
        done, _ = self.run_recapture(sqlcipher_bin=self.root / 'no-such-binary')
        self.assertEqual(done.returncode, 0, done.stderr)
        text = self.out('posture-legs-exit-codes.txt')
        self.assertEqual(re.findall(r'^exit: (\S+)$', text, re.M), ['2', '2', '1', 'missing'])
        self.assertIn('leg4 skipped', done.stdout)


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


SED_SCRIPT = ['-e', 's|%(root)s|<repo-root>|g', '-e', 's|%(fix)s|%(label)s|g']


class FixtureMode7394(RecaptureBase):
    """#7394: no fixture key file is group or world accessible."""

    def test_public_key_fixture_is_owner_only(self):
        done, _ = self.run_recapture()
        self.assertEqual(done.returncode, 0, done.stderr)
        keys = self.root / '.local-runs' / 'cert-3607-fixtures' / 'keys'
        for name in ('ai-memory.priv', 'ai-memory.pub'):
            mode = (keys / name).stat().st_mode & 0o777
            self.assertEqual(mode, 0o600, '%s is %o' % (name, mode))


class Argparse7402(RecaptureBase):
    """#7402: --help and unknown arguments exit before any directory or file is touched."""

    def snapshot(self):
        return sorted(str(p.relative_to(self.root)) for p in self.root.rglob('*')
                      if '.git' not in p.parts and 'pystubs' not in p.parts)

    def test_help_prints_usage_and_has_no_side_effects(self):
        before = self.snapshot()
        done, _ = self.run_recapture(args=['--help'])
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertIn('usage:', done.stdout)
        self.assertIn('DEFAULT_BIN', done.stdout)
        self.assertEqual(self.snapshot(), before)

    def test_unknown_argument_exits_2_with_no_side_effects(self):
        before = self.snapshot()
        done, _ = self.run_recapture(args=['--bogus'])
        self.assertEqual(done.returncode, 2, done.stderr)
        self.assertIn('usage:', done.stderr)
        self.assertEqual(self.snapshot(), before)

    def test_existing_evidence_bytes_survive_help(self):
        done, _ = self.run_recapture()
        self.assertEqual(done.returncode, 0, done.stderr)
        out_dir = self.root / OUT_REL
        before = {p.name: p.read_bytes() for p in out_dir.iterdir()}
        done, _ = self.run_recapture(args=['--help'])
        self.assertEqual(done.returncode, 0, done.stderr)
        done, _ = self.run_recapture(args=['--bogus'])
        self.assertEqual(done.returncode, 2, done.stderr)
        self.assertEqual({p.name: p.read_bytes() for p in out_dir.iterdir()}, before)


class BinaryPreflight7397(RecaptureBase):
    """#7397: a bad DEFAULT_BIN is refused up front; no .raw capture survives any exit."""

    def assert_refused(self, binary):
        done, _ = self.run_recapture(default_bin=binary)
        self.assertEqual(done.returncode, 1, done.stderr)
        self.assertIn('DEFAULT_BIN', done.stderr)
        self.assertIn(str(binary), done.stderr)
        self.assertNotIn('Traceback', done.stderr)
        self.assertFalse((self.root / 'docs').exists(), 'evidence dir was created')
        self.assertEqual(list(self.root.rglob('*.raw')), [])

    def test_missing_default_bin_is_refused(self):
        self.assert_refused(self.root / 'no-such-default')

    def test_non_executable_default_bin_is_refused(self):
        plain = self.root / 'not-executable'
        plain.write_text('x\n')
        plain.chmod(0o644)
        self.assert_refused(plain)

    def test_directory_default_bin_is_refused(self):
        self.assert_refused(self.root)

    def test_missing_default_bin_with_prekeyed_fixtures_leaves_no_raw(self):
        done, _ = self.run_recapture()
        self.assertEqual(done.returncode, 0, done.stderr)
        done, _ = self.run_recapture(default_bin=self.root / 'no-such-default')
        self.assertEqual(done.returncode, 1, done.stderr)
        self.assertEqual(list(self.root.rglob('*.raw')), [])

    def test_raw_capture_is_removed_when_sanitizing_fails(self):
        module = load_script_module()
        raw = self.root / 'leg.out.raw'

        def boom(_raw):
            raise RuntimeError('sanitizer failed')

        module.sanitize = boom
        with self.assertRaises(RuntimeError):
            module.run_capture(self.default_bin, ['doctor'], {'PATH': os.environ.get('PATH', '')},
                               raw, self.root / 'leg.out')
        self.assertFalse(raw.exists())

    def test_raw_capture_is_removed_when_the_binary_cannot_start(self):
        module = load_script_module()
        raw = self.root / 'leg.out.raw'
        with self.assertRaises(OSError):
            module.run_capture(self.root / 'nope', [], {}, raw, self.root / 'leg.out')
        self.assertFalse(raw.exists())


class TmpdirOverride7398(RecaptureBase):
    """#7398: TMPDIR is honoured only under <repo-root>/.local-runs; foreign dirs keep their mode."""

    def test_directory_outside_local_runs_is_refused_and_untouched(self):
        outside = self.home / 'shared-tmp'
        outside.mkdir()
        outside.chmod(0o755)
        done, _ = self.run_recapture(extra_env={'TMPDIR': str(outside)})
        self.assertEqual(done.returncode, 1, done.stderr)
        self.assertIn('TMPDIR', done.stderr)
        self.assertIn('.local-runs', done.stderr)
        self.assertEqual(outside.stat().st_mode & 0o777, 0o755)
        self.assertFalse((self.root / 'docs').exists())

    def test_symlink_escaping_local_runs_is_refused(self):
        outside = self.home / 'shared-tmp'
        outside.mkdir()
        outside.chmod(0o755)
        (self.root / '.local-runs').mkdir()
        (self.root / '.local-runs' / 'link').symlink_to(outside)
        done, _ = self.run_recapture(extra_env={'TMPDIR': str(self.root / '.local-runs' / 'link')})
        self.assertEqual(done.returncode, 1, done.stderr)
        self.assertEqual(outside.stat().st_mode & 0o777, 0o755)

    def test_new_directory_under_local_runs_is_created_private(self):
        target = self.root / '.local-runs' / 'my-tmp'
        done, _ = self.run_recapture(extra_env={'TMPDIR': str(target)})
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertEqual(target.stat().st_mode & 0o777, 0o700)

    def test_existing_directory_under_local_runs_keeps_its_mode(self):
        target = self.root / '.local-runs' / 'existing-tmp'
        target.mkdir(parents=True)
        target.chmod(0o755)
        done, _ = self.run_recapture(extra_env={'TMPDIR': str(target)})
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertEqual(target.stat().st_mode & 0o777, 0o755)


class SedParity7404(RecaptureBase):
    """#7404: sanitize() is byte-identical to GNU sed, including the missing final newline."""

    CASES = (
        b'', b'plain', b'plain\n', b'two\nlines', b'two\nlines\n', b'\n', b'a\n\n',
    )

    def test_sanitize_adds_no_final_newline(self):
        module = load_script_module()
        for raw in self.CASES:
            self.assertEqual(module.sanitize(raw), raw, raw)

    def test_sanitize_collapses_paths_without_touching_line_endings(self):
        module = load_script_module()
        raw = (str(module.ROOT) + '/x\n' + str(module.FIX) + '/y').encode()
        self.assertEqual(module.sanitize(raw),
                         b'<repo-root>/x\n' + SANITIZED_FIXTURE_LABEL.encode() + b'/y')

    @unittest.skipUnless(shutil.which('sed'), 'sed not available')
    def test_matches_sed_bytes(self):
        module = load_script_module()
        sed_args = [a % {'root': str(module.ROOT), 'fix': str(module.FIX),
                         'label': SANITIZED_FIXTURE_LABEL} for a in SED_SCRIPT]
        for raw in self.CASES + ((str(module.ROOT) + '/p').encode(),
                                 (str(module.FIX) + '/q\n').encode()):
            done = subprocess.run(['sed'] + sed_args, input=raw, capture_output=True, check=True)
            self.assertEqual(module.sanitize(raw), done.stdout, raw)

    def test_captured_output_without_final_newline_stays_without_one(self):
        (self.root / 'no-final-newline').write_text('')
        done, _ = self.run_recapture()
        self.assertEqual(done.returncode, 0, done.stderr)
        data = (self.root / OUT_REL / 'posture-bare-env.out').read_bytes()
        self.assertTrue(data.endswith(b'overall: FAIL'), data[-40:])


if __name__ == '__main__':
    unittest.main()
