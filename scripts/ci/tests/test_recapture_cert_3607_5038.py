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
import ast
import contextlib
import datetime
import hashlib
import importlib.util
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import unicodedata
import unittest.mock
import urllib.parse
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
    open('ai-memory.db', 'w').write('store made by keygen\\n')  # the real one does (#7648)
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
# like the real doctor: any ai-memory.db in the cwd is "observed" (#7648)
print('live PRAGMA synchronous agrees' if os.path.exists('ai-memory.db')
      else 'live pragma not observed')
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

    def make_logging_stub(self, path, log):
        """A stub that appends the path it was executed as to log."""
        path.parent.mkdir(parents=True, exist_ok=True)
        head, rest = STUB.split('\n', 1)
        path.write_text(head + '\nimport sys as _s\nopen(%r, "a").write(_s.argv[0] + "\\n")\n' % str(log)
                        + rest)
        path.chmod(0o755)
        return path

    def make_broken_stub(self, path):
        """An executable file whose interpreter does not exist (exec fails with ENOENT)."""
        path.write_text('#!/nonexistent/interpreter-7432\n')
        path.chmod(0o755)
        return path

    def base_env(self, sqlcipher_bin=None, extra_env=None, default_bin=None):
        env = {
            'PATH': os.environ.get('PATH', '/usr/bin:/bin'),
            'HOME': str(self.home),
            'PYTHONPATH': str(self.pystubs),
            'DEFAULT_BIN': str(default_bin or self.default_bin),
            'SQLCIPHER_BIN': str(sqlcipher_bin or self.sqlcipher_bin),
        }
        env.update(extra_env or {})
        return env

    def popen_recapture(self, sqlcipher_bin=None, extra_env=None, default_bin=None, cwd=None):
        """Start the script in its own session so a test can SIGKILL it mid-run."""
        env = self.base_env(sqlcipher_bin, extra_env, default_bin)
        script = self.root / 'scripts' / SCRIPT_NAME
        return subprocess.Popen([sys.executable, str(script)], env=env,
                                cwd=str(cwd or self.root), stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, text=True, start_new_session=True)

    def run_recapture(self, sqlcipher_bin=None, args=None, extra_env=None, default_bin=None,
                      cwd=None, script_root=None):
        env = self.base_env(sqlcipher_bin, extra_env, default_bin)
        script = (script_root or self.root) / 'scripts' / SCRIPT_NAME
        cmd = ['bash', str(script)] if script.suffix == '.sh' else [sys.executable, str(script)]
        cmd += list(args or [])
        before = datetime.datetime.now(datetime.timezone.utc).date().isoformat()
        done = subprocess.run(cmd, env=env, cwd=str(cwd or script_root or self.root),
                              capture_output=True, text=True)
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
        status = module.run_capture(self.root / 'nope', [], {}, raw, self.root / 'leg.out')
        self.assertEqual(status, 127)
        self.assertFalse(raw.exists())
        self.assertIn('nope', (self.root / 'leg.out').read_text())


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
        b'crlf\r\n', b'crlf\r\nlast', b'\r\n', b'a\r\n\r\nb\r\n',
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


class BinaryResolution7431(RecaptureBase):
    """#7431: the binary that is checked is the binary that is executed."""

    NAME = 'ai-memory-r4probe'

    def ran(self, log):
        return sorted(set(log.read_text().split())) if log.exists() else []

    def test_bare_name_runs_the_child_path_binary_not_the_cwd_lookalike(self):
        log = self.root / 'ran.log'
        on_path = self.make_logging_stub(self.home / '.cargo' / 'bin' / self.NAME, log)
        self.make_logging_stub(self.root / self.NAME, log)
        done, _ = self.run_recapture(default_bin=self.NAME)
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertEqual(self.ran(log), [str(on_path)])

    def test_bare_name_only_in_cwd_is_refused(self):
        log = self.root / 'ran.log'
        self.make_logging_stub(self.root / self.NAME, log)
        done, _ = self.run_recapture(default_bin=self.NAME)
        self.assertEqual(done.returncode, 1, done.stderr)
        self.assertIn('DEFAULT_BIN', done.stderr)
        self.assertIn(self.NAME, done.stderr)
        self.assertEqual(self.ran(log), [])

    def test_slash_value_is_relative_to_the_repo_root_not_the_cwd(self):
        log = self.root / 'ran.log'
        in_root = self.make_logging_stub(self.root / 'sub' / self.NAME, log)
        self.make_logging_stub(self.home / 'sub' / self.NAME, log)
        done, _ = self.run_recapture(default_bin='sub/' + self.NAME, cwd=self.home)
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertEqual(self.ran(log), [str(in_root)])

    def test_sqlcipher_bare_name_runs_the_child_path_binary(self):
        log = self.root / 'ran.log'
        name = 'ai-memory-sqlcipher-r4probe'
        on_path = self.make_logging_stub(self.home / '.cargo' / 'bin' / name, log)
        self.make_logging_stub(self.root / name, log)
        done, _ = self.run_recapture(sqlcipher_bin=name)
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertEqual(self.ran(log), [str(on_path)])
        self.assertEqual(re.findall(r'^exit: (\S+)$', self.out('posture-legs-exit-codes.txt'), re.M),
                         ['2', '2', '1', '0'])


class ExecFailure7432(RecaptureBase):
    """#7432: a binary that passes the check but cannot start records exit 127 (the shell did)."""

    def exits(self):
        return re.findall(r'^exit: (\S+)$', self.out('posture-legs-exit-codes.txt'), re.M)

    def test_unstartable_sqlcipher_leg_records_127_and_finishes(self):
        broken = self.make_broken_stub(self.root / 'broken-sqlcipher')
        done, _ = self.run_recapture(sqlcipher_bin=broken)
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertNotIn('Traceback', done.stderr)
        self.assertEqual(self.exits(), ['2', '2', '1', '127'])
        self.assertEqual(list((self.root / OUT_REL).glob('*.raw')), [])

    def test_unstartable_default_bin_refreshes_the_whole_bundle(self):
        done, _ = self.run_recapture()
        self.assertEqual(done.returncode, 0, done.stderr)
        broken = self.make_broken_stub(self.root / 'broken-default')
        done, _ = self.run_recapture(default_bin=broken)
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertNotIn('Traceback', done.stderr)
        self.assertEqual(self.exits(), ['127', '127', '127', '0'])
        self.assertIn('broken-default', self.out('posture-bare-env.out'))

    def test_unstartable_default_bin_fails_keygen_without_a_traceback(self):
        broken = self.make_broken_stub(self.root / 'broken-default')
        done, _ = self.run_recapture(default_bin=broken)
        self.assertEqual(done.returncode, 1)
        self.assertIn('operator keygen failed', done.stderr)
        self.assertNotIn('Traceback', done.stderr)
        self.assertFalse((self.root / OUT_REL / 'posture-legs-exit-codes.txt').exists())

    def test_non_not_found_exec_error_maps_to_126(self):
        module = load_script_module()
        raw = self.root / 'leg.out.raw'
        cwd = self.root / 'sbx'  # the child's cwd must exist
        cwd.mkdir()
        status = module.run_capture(self.root, [], {}, raw, self.root / 'leg.out', cwd)
        self.assertEqual(status, 126)
        self.assertFalse(raw.exists())


class FixtureDirMode7433(RecaptureBase):
    """#7433: the fixtures directory (passphrase, keys, store) is tightened on every run."""

    def test_pre_existing_loose_fixture_dir_ends_0700(self):
        fix = self.root / '.local-runs' / 'cert-3607-fixtures'
        fix.mkdir(parents=True)
        fix.chmod(0o755)
        done, _ = self.run_recapture()
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertEqual(fix.stat().st_mode & 0o777, 0o700)


class LocalRunsSymlink7434(RecaptureBase):
    """#7434: a symlinked .local-runs cannot launder out-of-tree scratch past the containment check."""

    def link_local_runs(self):
        outside = self.home / 'outside'
        outside.mkdir()
        (self.root / '.local-runs').symlink_to(outside)
        return outside

    def test_symlinked_local_runs_is_refused_with_tmpdir_unset(self):
        outside = self.link_local_runs()
        done, _ = self.run_recapture()
        self.assertEqual(done.returncode, 1, done.stderr)
        self.assertIn('symlink', done.stderr)
        self.assertEqual(list(outside.iterdir()), [])

    def test_symlinked_local_runs_is_refused_with_tmpdir_set(self):
        outside = self.link_local_runs()
        done, _ = self.run_recapture(extra_env={'TMPDIR': str(outside / 't')})
        self.assertEqual(done.returncode, 1, done.stderr)
        self.assertEqual(list(outside.iterdir()), [])
        self.assertFalse((self.root / 'docs').exists())


class TmpdirMessage7435(RecaptureBase):
    """#7435: the refusal names the real scratch path, never `None`."""

    def test_default_scratch_dir_refusal_names_the_default_and_its_target(self):
        outside = self.home / 'outside'
        outside.mkdir()
        (self.root / '.local-runs').mkdir()
        (self.root / '.local-runs' / 'tmp').symlink_to(outside)
        done, _ = self.run_recapture()
        self.assertEqual(done.returncode, 1, done.stderr)
        self.assertNotIn('None', done.stderr)
        self.assertIn('default', done.stderr)
        self.assertIn(str(outside), done.stderr)
        self.assertIn('.local-runs', done.stderr)

    def test_explicit_tmpdir_refusal_names_the_value_and_its_target(self):
        outside = self.home / 'shared-tmp'
        outside.mkdir()
        done, _ = self.run_recapture(extra_env={'TMPDIR': str(outside)})
        self.assertEqual(done.returncode, 1, done.stderr)
        self.assertNotIn('None', done.stderr)
        self.assertIn(str(outside), done.stderr)


class SedLiteral7436(RecaptureBase):
    """#7436: the replacement is literal; it equals the sed for paths without regex metacharacters."""

    def dotted(self):
        module = load_script_module()
        module.ROOT = Path('/x.y/repo')
        module.FIX = module.ROOT / '.local-runs' / 'cert-3607-fixtures'
        return module

    def test_root_containing_a_dot_is_replaced_literally(self):
        module = self.dotted()
        raw = b'/x.y/repo/a /xAy/repo/b\r\n'
        self.assertEqual(module.sanitize(raw), b'<repo-root>/a /xAy/repo/b\r\n')

    @unittest.skipUnless(shutil.which('sed'), 'sed not available')
    def test_dotted_root_matches_sed_with_the_dot_escaped(self):
        module = self.dotted()
        sed_args = ['-e', r's|/x\.y/repo|<repo-root>|g',
                    '-e', r's|/x\.y/repo/\.local-runs/cert-3607-fixtures|%s|g' % SANITIZED_FIXTURE_LABEL]
        for raw in (b'/x.y/repo/a\r\n', b'/x.y/repo/.local-runs/cert-3607-fixtures/k', b'plain\r\n'):
            done = subprocess.run(['sed'] + sed_args, input=raw, capture_output=True, check=True)
            self.assertEqual(module.sanitize(raw), done.stdout, raw)

    def test_docstrings_do_not_claim_unqualified_sed_identity(self):
        module = load_script_module()
        self.assertIn('literal', module.sanitize.__doc__)
        self.assertIn('near-miss', module.sanitize.__doc__)


class SqlcipherMissing7459(RecaptureBase):
    """#7459: a bare SQLCIPHER_BIN off the child PATH is `missing`, never run by name."""

    def test_bare_name_only_in_cwd_records_missing(self):
        log = self.root / 'ran.log'
        self.make_logging_stub(self.root / 'ai-memory-sqlcipher-r5probe', log)
        done, _ = self.run_recapture(sqlcipher_bin='ai-memory-sqlcipher-r5probe')
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertEqual(re.findall(r'^exit: (\S+)$', self.out('posture-legs-exit-codes.txt'), re.M),
                         ['2', '2', '1', 'missing'])
        self.assertFalse(log.exists())
        self.assertIn('ai-memory-sqlcipher-r5probe', done.stderr)


class ChildPathEntries7460(RecaptureBase):
    """#7460: only absolute, non-empty child PATH entries are searched."""

    NAME = 'ai-memory-r5probe'

    def test_colon_home_does_not_search_the_cwd(self):
        log = self.root / 'ran.log'
        self.make_logging_stub(self.root / self.NAME, log)
        done, _ = self.run_recapture(default_bin=self.NAME, extra_env={'HOME': ':'})
        self.assertEqual(done.returncode, 1, done.stderr)
        self.assertFalse(log.exists())

    def test_relative_home_does_not_search_a_relative_entry(self):
        log = self.root / 'ran.log'
        self.make_logging_stub(self.root / 'rel' / '.cargo' / 'bin' / self.NAME, log)
        done, _ = self.run_recapture(default_bin=self.NAME, extra_env={'HOME': 'rel'})
        self.assertEqual(done.returncode, 1, done.stderr)
        self.assertFalse(log.exists())

    def test_home_containing_a_colon_still_resolves_an_absolute_entry(self):
        log = self.root / 'ran.log'
        self.make_logging_stub(self.root / 'abs-dir' / self.NAME, log)
        module = load_script_module()
        module.CHILD_PATH = ':rel/x::%s:%s' % (self.root / 'abs-dir', '.')
        found = module.resolve_binary(self.NAME)
        self.assertEqual(found, str(self.root / 'abs-dir' / self.NAME))
        self.assertTrue(os.path.isabs(found))

    def test_relative_and_empty_entries_never_resolve(self):
        module = load_script_module()
        self.make_logging_stub(self.root / self.NAME, self.root / 'ran.log')
        module.CHILD_PATH = ':.:rel'
        previous = os.getcwd()
        os.chdir(str(self.root))
        try:
            self.assertIsNone(module.resolve_binary(self.NAME))
        finally:
            os.chdir(previous)


class EmptyBinarySetting7461(RecaptureBase):
    """#7461: an empty DEFAULT_BIN or SQLCIPHER_BIN takes the default, as `:-` did."""

    def test_empty_settings_take_the_repo_defaults(self):
        log = self.root / 'ran.log'
        default = self.make_logging_stub(self.root / 'target' / 'release' / 'ai-memory', log)
        cipher = self.make_logging_stub(
            self.root / 'target-sqlcipher' / 'release' / 'ai-memory', log)
        done, _ = self.run_recapture(extra_env={'DEFAULT_BIN': '', 'SQLCIPHER_BIN': ''})
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertEqual(sorted(set(log.read_text().split())), sorted([str(default), str(cipher)]))
        self.assertEqual(re.findall(r'^exit: (\S+)$', self.out('posture-legs-exit-codes.txt'), re.M),
                         ['2', '2', '1', '0'])


class FixtureSymlinks7462(RecaptureBase):
    """#7462: a symlink between ROOT and a fixture file is refused before anything is written."""

    def outside(self):
        outside = self.home / 'outside-fix'
        outside.mkdir()
        return outside

    def assert_refused(self, outside):
        done, _ = self.run_recapture()
        self.assertEqual(done.returncode, 1, done.stderr)
        self.assertIn('symlink', done.stderr)
        self.assertEqual(list(outside.iterdir()), [])
        self.assertFalse((self.root / 'docs').exists())

    def test_symlinked_fixture_dir_is_refused(self):
        outside = self.outside()
        (self.root / '.local-runs').mkdir()
        (self.root / '.local-runs' / 'cert-3607-fixtures').symlink_to(outside)
        self.assert_refused(outside)

    def test_symlinked_keys_dir_is_refused(self):
        outside = self.outside()
        fix = self.root / '.local-runs' / 'cert-3607-fixtures'
        fix.mkdir(parents=True)
        (fix / 'keys').symlink_to(outside)
        self.assert_refused(outside)

    def test_symlinked_fixture_file_is_refused(self):
        outside = self.outside()
        fix = self.root / '.local-runs' / 'cert-3607-fixtures'
        fix.mkdir(parents=True)
        (fix / 'db-passphrase').symlink_to(outside / 'target-file')
        self.assert_refused(outside)


class StaleLeg4Capture7463(RecaptureBase):
    """#7463: a missing leg 4 never leaves the previous run's capture in the bundle."""

    def test_second_run_without_sqlcipher_removes_the_stale_capture(self):
        done, _ = self.run_recapture()
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertTrue((self.root / OUT_REL / 'posture-sqlcipher-pass.out').exists())
        done, _ = self.run_recapture(sqlcipher_bin=self.root / 'no-such-binary')
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertFalse((self.root / OUT_REL / 'posture-sqlcipher-pass.out').exists())
        self.assertIn('posture-sqlcipher-pass.out MISSING', done.stdout)
        self.assertEqual(re.findall(r'^exit: (\S+)$', self.out('posture-legs-exit-codes.txt'), re.M),
                         ['2', '2', '1', 'missing'])


class Enoexec7464(RecaptureBase):
    """#7464: an executable with no shebang is refused and recorded as 126, not run via /bin/sh."""

    def make_no_shebang(self, name):
        path = self.root / name
        path.write_text('echo hi\n')
        path.chmod(0o755)
        return path

    def test_no_shebang_sqlcipher_records_126(self):
        done, _ = self.run_recapture(sqlcipher_bin=self.make_no_shebang('no-shebang-sqlcipher'))
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertEqual(re.findall(r'^exit: (\S+)$', self.out('posture-legs-exit-codes.txt'), re.M),
                         ['2', '2', '1', '126'])

    def test_no_shebang_default_bin_fails_keygen(self):
        done, _ = self.run_recapture(default_bin=self.make_no_shebang('no-shebang-default'))
        self.assertEqual(done.returncode, 1)
        self.assertIn('operator keygen failed', done.stderr)
        self.assertNotIn('Traceback', done.stderr)

    def test_docstrings_state_the_refusal(self):
        module = load_script_module()
        self.assertIn('ENOEXEC', module.__doc__)
        self.assertIn('/bin/sh', module.__doc__)


class SanitizeDocstring7465(unittest.TestCase):
    def test_docstring_states_the_facts(self):
        doc = load_script_module().sanitize.__doc__
        self.assertIn('near-miss', doc)
        self.assertIn('literal occurrence', ' '.join(doc.split()))
        self.assertNotIn('certified runs', doc)
        self.assertIn('`.`', doc)


class SymlinkBase(RecaptureBase):
    """Helpers for the fixture-symlink classes: an outside dir and a swapping stub."""

    def outside(self):
        outside = self.home / 'outside-fix'
        outside.mkdir()
        return outside

    def fix(self):
        return self.root / '.local-runs' / 'cert-3607-fixtures'

    def make_swap_stub(self, path, trigger, outside):
        """A stub that, on the trigger invocation, plants db-passphrase as a symlink."""
        head, rest = STUB.split('\n', 1)
        hook = (
            '\nimport os as _o, sys as _s\n'
            'def _swap():\n'
            '    _t = _o.path.join(_o.environ["AI_MEMORY_KEY_DIR"], "..", "db-passphrase")\n'
            '    _o.symlink(%r, _t)\n'
            'if %s:\n'
            '    _swap()\n' % (str(outside / 'stolen'), trigger))
        path.write_text(head + hook + rest)
        path.chmod(0o755)
        return path

    def assert_failed_closed(self, done, outside):
        self.assertEqual(done.returncode, 1, done.stderr)
        self.assertIn('symlink', done.stderr)
        self.assertEqual(list(outside.iterdir()), [])


class OperatorKeySymlinks7508(SymlinkBase):
    """#7508: the operator key pair that keygen writes is covered by the symlink check."""

    def test_symlinked_operator_key_is_refused(self):
        for name in ('operator.key', 'operator.key.pub'):
            with self.subTest(name=name):
                outside = self.outside()
                keys = self.fix() / 'keys'
                keys.mkdir(parents=True, exist_ok=True)
                (keys / name).symlink_to(outside / name)
                done, _ = self.run_recapture()
                self.assert_failed_closed(done, outside)
                (keys / name).unlink()
                outside.rmdir()

    def test_any_symlink_below_the_fixture_dir_is_refused(self):
        outside = self.outside()
        keys = self.fix() / 'keys'
        keys.mkdir(parents=True)
        (keys / 'extra-entry').symlink_to(outside / 'x')
        done, _ = self.run_recapture()
        self.assert_failed_closed(done, outside)


class SwapDuringRun7509(SymlinkBase):
    """#7509: a symlink swapped in at a protected path fails closed with exit 1; one at a
    replaceable path is removed and never followed (#7539)."""

    def test_swap_during_keygen_does_not_leak_the_passphrase(self):
        outside = self.outside()
        swap = self.make_swap_stub(self.root / 'swap-default',
                                   '_s.argv[1:3] == ["rules", "keygen"]', outside)
        done, _ = self.run_recapture(default_bin=swap)
        self.assert_failed_closed(done, outside)

    def test_swap_during_a_posture_leg_does_not_leak_the_passphrase(self):
        outside = self.outside()
        swap = self.make_swap_stub(self.root / 'swap-default',
                                   '_s.argv[1:2] == ["doctor"] and "--posture" not in _s.argv', outside)
        done, _ = self.run_recapture(default_bin=swap)
        self.assert_failed_closed(done, outside)

    def test_write_file_replaces_a_final_symlink_and_refuses_a_symlinked_parent(self):
        module = load_script_module()
        module.ROOT = self.root
        outside = self.outside()
        (self.root / 'd').mkdir()
        (self.root / 'd' / 'link').symlink_to(outside / 'f')
        (self.root / 'plink').symlink_to(outside)
        module.write_file(self.root / 'd' / 'link', b'secret')  # the link is replaced, not followed
        self.assertFalse((self.root / 'd' / 'link').is_symlink())
        self.assertEqual((self.root / 'd' / 'link').read_bytes(), b'secret')
        with self.assertRaises(OSError):
            module.write_file(self.root / 'plink' / 'f', b'secret')
        self.assertEqual(list(outside.iterdir()), [])

    def test_write_file_replaces_a_regular_file_with_the_requested_mode(self):
        module = load_script_module()
        module.ROOT = self.root
        target = self.root / 'a' / 'f'
        target.parent.mkdir()
        target.write_bytes(b'old')
        module.write_file(target, b'new')
        self.assertEqual(target.read_bytes(), b'new')
        self.assertEqual(target.stat().st_mode & 0o777, 0o600)

    def test_create_only_never_replaces_or_follows(self):
        module = load_script_module()
        module.ROOT = self.root
        outside = self.outside()
        existing = self.root / 'pass'
        existing.write_bytes(b'keep')
        with self.assertRaises(OSError):
            module.write_file(existing, b'new', replace=False)
        self.assertEqual(existing.read_bytes(), b'keep')
        (self.root / 'dangling').symlink_to(outside / 'f')
        with self.assertRaises(OSError):
            module.write_file(self.root / 'dangling', b'new', replace=False)
        self.assertEqual(list(outside.iterdir()), [])

    def test_read_file_refuses_a_symlink(self):
        module = load_script_module()
        module.ROOT = self.root
        (self.root / 'real').write_bytes(b'x')
        (self.root / 'ln').symlink_to(self.root / 'real')
        self.assertEqual(module.read_file(self.root / 'real'), b'x')
        with self.assertRaises(OSError):
            module.read_file(self.root / 'ln')


class HomeValidation7510(RecaptureBase):
    """#7510: HOME must be absolute and non-empty; the sanitizer replaces whole path components."""

    def test_unusable_home_is_refused_before_any_write(self):
        for value in ('.', 'rel', '', '/', 'a:b', '/abs:/other', '/.', '/..', '/./', '/home/a/',
                      '/home//a', '/home/a/.', '/home/a/../b', '//', '/home/./a',
                      '//home/a', '///home/a', '//home//a', '/home/a//', '/home/a\n',
                      '/home/a\t', '/home/a\x01', '/home/a\x1f', '/home/a\x7f',
                      '\n/home/a', '/home\n/a', '/home/a\r', '/home/a\x85', '/home/a\u2028',
                      '/home/a\u2029', '/home/a\x0b', '/home/a\x0c', '/home/a\x1c',
                      '/home/a\u200b', '/home/\u00e9', '/home/a\ufeff'):
            with self.subTest(home=value):
                done, _ = self.run_recapture(extra_env={'HOME': value})
                self.assertEqual(done.returncode, 1, done.stderr)
                self.assertIn('HOME', done.stderr)
                self.assertFalse((self.root / 'docs').exists())
                self.assertFalse((self.root / '.local-runs').exists())

    def test_help_does_not_need_a_usable_home(self):
        done, _ = self.run_recapture(args=['--help'], extra_env={'HOME': 'rel'})
        self.assertEqual(done.returncode, 0, done.stderr)

    def patched(self, home):
        module = load_script_module()
        module.ROOT = Path('/mnt/x/repo')
        module.FIX = module.ROOT / '.local-runs' / 'cert-3607-fixtures'
        module.HOME = home
        return module

    def test_home_is_replaced_at_every_occurrence(self):
        module = self.patched('/home/a')
        raw = (b"/home/a/k /home/ab/y /home/a /home/a. 'open /home/a' x/home/a/z "
               b"/home/a.txt path=/home/a/q")
        want = (b"<home>/k <home>b/y <home> <home>. 'open <home>' x<home>/z "
                b"<home>.txt path=<home>/q")
        self.assertEqual(module.sanitize(raw), want)

    def test_trailing_slash_home_is_normalised(self):
        module = self.patched('/home/a/')
        self.assertEqual(module.sanitize(b'/home/a/k /home/ab'), b'<home>/k <home>b')

    def test_repo_root_is_replaced_at_every_occurrence(self):
        module = self.patched('/home/a')
        self.assertEqual(module.sanitize(b'/mnt/x/repo/a /mnt/x/repo-other/b /mnt/x/repo'),
                         b'<repo-root>/a <repo-root>-other/b <repo-root>')

    def test_docstring_and_usage_state_the_home_rule(self):
        module = load_script_module()
        self.assertIn('absolute', ' '.join(module.USAGE_EPILOG.split()))
        self.assertIn('HOME', module.USAGE_EPILOG)
        self.assertIn('HOME', module.__doc__)
        self.assertIn('every occurrence', ' '.join(module.sanitize.__doc__.split()))

    def test_docstring_and_usage_state_the_new_home_refusals(self):
        module = load_script_module()
        doc = ' '.join(module.__doc__.split())
        self.assertIn("not starting with `//`", doc)
        self.assertIn('control byte', doc)
        self.assertIn('0x00-0x1f, 0x7f', doc)
        self.assertIn("starting with '//'", module.USAGE_EPILOG)
        self.assertIn('control byte', module.USAGE_EPILOG)

    def test_home_problem_unit_table(self):
        module = load_script_module()
        for value in ('//home/a', '///home/a', '/home//a', '/home/a\n', '/home/a\x00',
                      '/home/a\x1f', '/home/a\x7f', '/ho\tme/a', '/home/a\x85',
                      '/home/a\u2028', '/home/a\u2029', '/home/a\x0b', '/home/a\x0c',
                      '/home/a\x1c', '/home/a\x1d', '/home/a\x1e', '/home/a\u200b',
                      '/home/a\ufeff', '/home/a\u00ad', '/home/\u00e9', '/h\u00f6me/a',
                      '/home/\U0001f600', '/home/a\ud800', '/home/a\u00a0'):
            with self.subTest(home=value):
                self.assertIsNotNone(module.home_problem(value))
        for value in ('/home/a', '/home/a b', '/Users/x.y', '/a', '/home/a_b-c.d+e@f'):
            with self.subTest(home=value):
                self.assertIsNone(module.home_problem(value))


def value_forms(value):
    """Every form a sensitive path takes in captured output: raw, JSON-escaped (with and
    without the `\\/` slash escape, once and twice) and percent-encoded (upper and lower hex)."""
    forms = {value, value.replace('/', '\\/')}
    once = json.dumps(value)[1:-1]
    twice = json.dumps(once)[1:-1]
    for text in (once, twice):
        forms.update({text, text.replace('/', '\\/')})
    for safe in ('', '/'):
        quoted = urllib.parse.quote(value, safe=safe)
        forms.update({quoted, re.sub(r'%[0-9A-F]{2}', lambda m: m.group(0).lower(), quoted)})
    return forms


class SanitizerEveryOccurrence7651(RecaptureBase):
    """#7538 #7571 #7572 #7573 #7612 #7651: every occurrence of HOME, the repo root and the
    fixtures root is replaced, longest value first, in its raw, JSON-escaped and percent-encoded
    forms. There is no delimiter allowlist; a longer path that shares the prefix is over-redacted."""

    MARK = '\u00a7'  # stands for the path in a form
    ROOTS = (
        ('home', '/home/probeuser', '<home>'),
        ('root', '/mnt/x/repo', '<repo-root>'),
        ('fix', '/mnt/x/repo/.local-runs/cert-3607-fixtures',
         '<repo-root>/.local-runs/cert-3607-fixtures'),
    )
    # 66 forms: the r9 probe shapes plus pipe, backslash, quotes, brackets and escapes.
    PROBE_FORMS = (
        '\u00a7', '\u00a7/x', '"\u00a7"', "'\u00a7'", '`\u00a7`', '(\u00a7)', '[\u00a7]', '<\u00a7>',
        '=\u00a7', ':\u00a7', '\u00a7:', ',\u00a7', '{\u00a7}', '${\u00a7}', 'a,\u00a7', '\u00a7,\u00a7',
        '[\u00a7,\u00a7]', '--dirs=\u00a7,\u00a7/x', '{"p":"\u00a7"}', '{"p": "\u00a7"}', '|\u00a7',
        '\u00a7|', 'x|\u00a7|y', '&\u00a7', '\u00a7&', 'a&&\u00a7', '!\u00a7', '\u00a7!', '#\u00a7',
        '\u00a7#', '?\u00a7', '\u00a7?', '*\u00a7', '\u00a7*', '%\u00a7', '\u00a7%', '\u00a7=', '=\u00a7=',
        '\u00a7..', '..\u00a7', '\u00a7...', '\u00a7.txt', '\u00a7.', '\u00a7\\', '\\\u00a7', '\\"\u00a7\\"',
        '\u00a7\\n', '\u00a7\\"', '$(\u00a7)', '$\u00a7', '~\u00a7', '@\u00a7', '^\u00a7', '\u00a7^', ';\u00a7;',
        '\u00a7\t', '\t\u00a7', '\u00a7\r\n', '\u00a7+x', 'x+\u00a7', '\u00a7-x', '\u00a7_x', '\u00a70',
        '0\u00a7', '\u00a7\u00a7', '\u00a7 \u00a7', '\u00a7/\u00a7', '\u00a7/../\u00a7',
    )

    def patched(self, home='/home/probeuser'):
        module = load_script_module()
        module.ROOT = Path('/mnt/x/repo')
        module.FIX = module.ROOT / '.local-runs' / 'cert-3607-fixtures'
        module.HOME = home
        return module

    def test_the_probe_table_has_at_least_55_forms(self):
        self.assertGreaterEqual(len(self.PROBE_FORMS), 55)
        self.assertEqual(len(set(self.PROBE_FORMS)), len(self.PROBE_FORMS))

    def test_every_probe_form_is_rewritten_for_every_root(self):
        module = self.patched()
        for name, path, label in self.ROOTS:
            for form in self.PROBE_FORMS:
                with self.subTest(root=name, form=form):
                    raw = form.replace(self.MARK, path)
                    got = module.sanitize(raw.encode()).decode()
                    self.assertEqual(got, form.replace(self.MARK, label))
                    self.assertNotIn(path, got)

    def test_every_printable_character_before_and_after_the_path(self):
        module = self.patched()
        for name, path, label in self.ROOTS:
            for code in range(0x20, 0x7f):
                char = chr(code)
                for raw, want in ((char + path, char + label), (path + char, label + char)):
                    with self.subTest(root=name, raw=raw):
                        self.assertEqual(module.sanitize(raw.encode()).decode(), want)

    def test_json_escaped_and_percent_encoded_forms_are_rewritten(self):
        for home in ('/home/probeuser', '/home/a\\b"c', '/home/a b', "/home/a'b&c|d"):
            module = self.patched(home)
            for name, path, label in self.ROOTS if home == '/home/probeuser' else self.ROOTS[:1]:
                value = home if name == 'home' else path
                for form in sorted(value_forms(value)):
                    for template in ('%s', '"p":"%s"', '{"p":"%s/x"}', '\\/%s', '%s\\/x', 'a|%s|b',
                                     '?u=%s&v=1', '%s\\u0026', 'x\\\\%s'):
                        raw = template % form
                        with self.subTest(root=name, raw=raw):
                            got = module.sanitize(raw.encode()).decode()
                            for leaked in value_forms(value):
                                self.assertNotIn(leaked.lower(), got.lower())

    def test_the_slash_escape_and_doubled_backslashes_are_rewritten(self):
        module = self.patched('/home/a\\b')
        self.assertEqual(module.sanitize(b'{"h":"\\/home\\/a\\\\b"}'), b'{"h":"<home>"}')
        self.assertEqual(module.sanitize(b'{"h":"/home/a\\\\b"}'), b'{"h":"<home>"}')
        self.assertEqual(module.sanitize(b'/home/a\\b'), b'<home>')
        self.assertEqual(module.sanitize(b'%2Fhome%2Fa%5Cb'), b'<home>')
        self.assertEqual(module.sanitize(b'%2fhome%2fa%5cb/x'), b'<home>/x')

    def test_percent_encoded_roots_are_rewritten(self):
        module = self.patched()
        self.assertEqual(module.sanitize(b'file%3A%2F%2F%2Fmnt%2Fx%2Frepo%2Fa'),
                         b'file%3A%2F%2F<repo-root>%2Fa')
        self.assertEqual(module.sanitize(b'%2Fhome%2Fprobeuser'), b'<home>')

    def test_longer_paths_that_share_the_prefix_are_over_redacted(self):
        module = self.patched()
        self.assertEqual(module.sanitize(b'/home/probeuser2/x'), b'<home>2/x')
        self.assertEqual(module.sanitize(b'/mnt/x/repo-other/y'), b'<repo-root>-other/y')
        self.assertEqual(module.sanitize(b'x/home/probeuser/z'), b'x<home>/z')

    def test_longest_value_goes_first(self):
        module = self.patched('/mnt/x')  # HOME is a prefix of the repo root
        self.assertEqual(module.sanitize(b'/mnt/x/repo/a /mnt/x/b'), b'<repo-root>/a <home>/b')
        self.assertEqual(
            module.sanitize(b'/mnt/x/repo/.local-runs/cert-3607-fixtures/k'),
            b'<repo-root>/.local-runs/cert-3607-fixtures/k')

    def test_child_homes_are_rewritten_to_home(self):
        module = self.patched()
        child = module.SANDBOX / 'leg1' / 'home'
        module.CHILD_HOMES.append(child)
        self.assertEqual(module.sanitize(('HOME=%s/.cache' % child).encode()), b'HOME=<home>/.cache')

    def test_a_document_with_every_form_has_no_residue(self):
        module = self.patched()
        document = '\n'.join(form.replace(self.MARK, path)
                             for _, path, _ in self.ROOTS for form in self.PROBE_FORMS)
        document += '\n' + '\n'.join(sorted(value_forms('/home/probeuser')))
        got = module.sanitize(document.encode()).decode()
        for _, path, _ in self.ROOTS:
            for leaked in value_forms(path):
                self.assertNotIn(leaked.lower(), got.lower())

    def test_leakscan_over_a_sanitized_bundle_exits_zero(self):
        leakscan = Path(os.environ.get('LEAKSCAN_PY', 'leakscan-not-installed.py'))
        if not leakscan.is_file():
            self.skipTest('set LEAKSCAN_PY to the leak scanner to run this check')
        home, root = '/home/' + 'fate' + '_two', '/mnt/' + 't9' + '/v07/repo'
        module = self.patched(home)
        module.ROOT = Path(root)
        module.FIX = module.ROOT / '.local-runs' / 'cert-3607-fixtures'
        document = '\n'.join(form.replace(self.MARK, path)
                             for path in (home, root) for form in self.PROBE_FORMS)
        document += '\n' + '\n'.join(sorted(value_forms(home) | value_forms(root)))
        bundle = self.root / 'leakscan-bundle.txt'
        bundle.write_bytes(module.sanitize(document.encode()))
        done = subprocess.run([sys.executable, str(leakscan), 'probe', str(bundle)],
                              capture_output=True, text=True)
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)

    def test_docstring_states_every_occurrence_and_over_redaction(self):
        module = load_script_module()
        doc = ' '.join(module.sanitize.__doc__.split())
        self.assertIn('every occurrence', doc)
        self.assertIn('longest value first', doc)
        self.assertIn('JSON-escaped', doc)
        self.assertIn('percent-encoded', doc)
        self.assertIn('over-redact', doc)
        self.assertIn('fails closed', doc)
        source = (REPO / 'scripts' / SCRIPT_NAME).read_text()
        self.assertNotIn('PATH_START', source)
        self.assertNotIn('PATH_END', source)


def walk_modes(base):
    """(files, dirs) under base as {relative path: permission bits}, without following links."""
    files, dirs = {}, {}
    for path in sorted(base.rglob('*')):
        mode = path.lstat().st_mode
        rel = str(path.relative_to(base))
        if path.is_symlink():
            continue
        (dirs if path.is_dir() else files)[rel] = mode & 0o777
    return files, dirs


class EvidenceModes7568(SymlinkBase):
    """#7568 #7569: the bundle is local operator evidence: every file the script creates is
    0600 and every directory it creates is 0700, whatever the umask."""

    UMASKS = (0, 0o022, 0o077, 0o002)

    def test_public_file_mode_is_gone_and_the_file_mode_is_owner_only(self):
        module = load_script_module()
        self.assertFalse(hasattr(module, 'PUBLIC_FILE_MODE'))
        self.assertEqual(module.FILE_MODE, 0o600)
        text = (REPO / 'scripts' / SCRIPT_NAME).read_text()
        self.assertNotIn('0o644', text)
        self.assertNotIn('PUBLIC_FILE_MODE', text)

    def test_write_file_is_0600_under_every_umask(self):
        module = load_script_module()
        module.ROOT = self.root
        for umask in self.UMASKS:
            with self.subTest(umask=oct(umask)):
                old = os.umask(umask)
                try:
                    target = self.root / ('f%o' % umask)
                    module.write_file(target, b'x')
                finally:
                    os.umask(old)
                self.assertEqual(target.stat().st_mode & 0o777, 0o600)

    def test_whole_run_creates_only_0600_files_and_0700_dirs_under_every_umask(self):
        for umask in self.UMASKS:
            with self.subTest(umask=oct(umask)):
                # a fresh sandbox per umask: no directory survives from an earlier subTest, so
                # every directory is created under THIS umask (#7614)
                for top in ('docs', '.local-runs'):
                    shutil.rmtree(str(self.root / top), True)
                    self.assertFalse((self.root / top).exists(), top)
                old = os.umask(umask)
                try:
                    done, _ = self.run_recapture()
                finally:
                    os.umask(old)
                self.assertEqual(done.returncode, 0, done.stderr)
                seen = 0
                for top in ('docs', '.local-runs'):
                    files, dirs = walk_modes(self.root / top)
                    for rel, mode in dirs.items():
                        seen += 1
                        self.assertEqual(mode, 0o700, '%s/%s dir %o' % (top, rel, mode))
                    for rel, mode in files.items():
                        # operator.key and operator.key.pub are written by the child binary
                        # (the stub), not by the script
                        if rel.rsplit('/', 1)[-1].startswith('operator.key'):
                            continue
                        seen += 1
                        self.assertEqual(mode, 0o600, '%s/%s file %o' % (top, rel, mode))
                for top in ('docs', 'docs/compliance', 'docs/compliance/evidence',
                            'docs/compliance/evidence/cert-3607', '.local-runs'):
                    mode = (self.root / top).stat().st_mode & 0o777
                    self.assertEqual(mode, 0o700, '%s is %o' % (top, mode))
                self.assertGreater(seen, 15)

    def test_a_directory_that_exists_is_not_retightened_except_the_fixtures_dir(self):
        (self.root / 'docs').mkdir()
        (self.root / 'docs').chmod(0o755)
        done, _ = self.run_recapture()
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertEqual((self.root / 'docs').stat().st_mode & 0o777, 0o755)
        self.assertEqual((self.root / 'docs' / 'compliance').stat().st_mode & 0o777, 0o700)

    def test_ensure_dirs_makes_every_missing_level_0700_under_umask_zero(self):
        module = load_script_module()
        module.ROOT = self.root
        old = os.umask(0)
        self.addCleanup(os.umask, old)
        module.ensure_dirs(self.root / 'a' / 'b' / 'c')
        for rel in ('a', 'a/b', 'a/b/c'):
            self.assertEqual((self.root / rel).stat().st_mode & 0o777, 0o700, rel)

    def test_ensure_dirs_refuses_a_symlinked_level(self):
        module = load_script_module()
        module.ROOT = self.root
        outside = self.outside()
        (self.root / 'ln').symlink_to(outside)
        with self.assertRaises(OSError):
            module.ensure_dirs(self.root / 'ln' / 'sub')
        self.assertEqual(list(outside.iterdir()), [])

    def test_a_world_writable_existing_directory_is_refused_before_any_write(self):
        for rel in ('.local-runs', '.local-runs/cert-3607-fixtures', 'docs/compliance/evidence/cert-3607'):
            with self.subTest(directory=rel):
                target = self.root / rel
                target.mkdir(parents=True, exist_ok=True)
                target.chmod(0o777)
                done, _ = self.run_recapture()
                self.assertEqual(done.returncode, 1, done.stderr)
                self.assertIn('writable', done.stderr)
                self.assertIn(rel.rsplit('/', 1)[-1], done.stderr)
                self.assertFalse((self.root / 'docs' / 'compliance' / 'evidence' / 'cert-3607'
                                  / 'posture-bare-env.out').exists())
                shutil.rmtree(str(self.root / '.local-runs'), True)
                shutil.rmtree(str(self.root / 'docs'), True)

    def test_a_group_writable_existing_directory_is_accepted(self):
        runs = self.root / '.local-runs'
        runs.mkdir()
        runs.chmod(0o775)
        done, _ = self.run_recapture()
        self.assertEqual(done.returncode, 0, done.stderr)

    def test_a_directory_owned_by_another_uid_is_refused(self):
        module = load_script_module()
        module.ROOT = self.root
        module.LOCAL_RUNS = self.root / '.local-runs'
        module.LOCAL_RUNS.mkdir()
        real = os.geteuid
        try:
            os.geteuid = lambda: real() + 1
            self.assertIn('owned', module.dir_problem(module.LOCAL_RUNS))
        finally:
            os.geteuid = real
        self.assertIsNone(module.dir_problem(module.LOCAL_RUNS))
        self.assertIsNone(module.dir_problem(self.root / 'absent'))

    def test_docstring_states_the_modes_and_the_refusal(self):
        module = load_script_module()
        doc = ' '.join(module.__doc__.split())
        self.assertIn('every file the script creates is 0600', doc)
        self.assertIn('every directory it creates', doc)
        self.assertIn('is 0700', doc)
        self.assertIn('world writable or owned by another uid is refused', doc)


class StagedBundle7574(SymlinkBase):
    """#7574: a run never leaves a mixed bundle: the previous bundle survives a failed run
    byte-identical and no staging directory is left."""

    def evidence(self):
        return self.root / OUT_REL

    def snapshot(self):
        return {str(p.relative_to(self.evidence())): (p.read_bytes(), p.stat().st_mode & 0o777)
                for p in sorted(self.evidence().rglob('*')) if p.is_file()}

    def make_failing_stub(self, path, marker):
        """Prints marker in every posture leg and plants a symlink in the key dir at leg 3."""
        head, rest = STUB.split('\n', 1)
        hook = (
            '\nimport os as _o, sys as _s\n'
            'if _s.argv[1:2] == ["doctor"] and "--posture" in _s.argv:\n'
            '    print(%r)\n'
            'if _s.argv[1:2] == ["doctor"] and "--posture" not in _s.argv:\n'
            '    _t = _o.path.join(_o.environ["AI_MEMORY_KEY_DIR"], "planted")\n'
            '    if not _o.path.lexists(_t):\n'
            '        _o.symlink("/nonexistent-7574", _t)\n' % marker)
        path.write_text(head + hook + rest)
        path.chmod(0o755)
        return path

    def assert_no_staging(self):
        names = sorted(p.name for p in self.evidence().parent.iterdir())
        self.assertEqual([n for n in names if n != 'cert-3607'], [], names)

    def test_a_run_that_fails_at_leg_four_leaves_the_previous_bundle_untouched(self):
        done, _ = self.run_recapture()
        self.assertEqual(done.returncode, 0, done.stderr)
        before = self.snapshot()
        self.assertIn('posture-sqlcipher-pass.out', before)
        failing = self.make_failing_stub(self.root / 'failing-default', 'run-two-marker')
        done, _ = self.run_recapture(default_bin=failing)
        self.assertEqual(done.returncode, 1, done.stderr)
        self.assertIn('symlink', done.stderr)
        self.assertEqual(self.snapshot(), before)
        self.assertNotIn(b'run-two-marker', b''.join(data for data, _ in self.snapshot().values()))
        self.assert_no_staging()

    def test_a_failed_first_run_creates_no_bundle_and_no_staging_directory(self):
        failing = self.make_failing_stub(self.root / 'failing-default', 'run-one-marker')
        done, _ = self.run_recapture(default_bin=failing)
        self.assertEqual(done.returncode, 1, done.stderr)
        self.assertFalse(self.evidence().exists())
        self.assert_no_staging()

    def test_a_successful_run_replaces_the_bundle_and_keeps_other_files(self):
        done, _ = self.run_recapture()
        self.assertEqual(done.returncode, 0, done.stderr)
        (self.evidence() / 'SANITIZATION.md').write_bytes(b'kept\n')
        (self.evidence() / 'sub').mkdir()
        (self.evidence() / 'sub' / 'n.txt').write_bytes(b'nested\n')
        (self.evidence() / 'stale.raw').write_bytes(b'raw leftover\n')
        marker = self.make_logging_stub(self.root / 'marker-default', self.home / 'calls.log')
        done, _ = self.run_recapture(default_bin=marker)
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertEqual((self.evidence() / 'SANITIZATION.md').read_bytes(), b'kept\n')
        self.assertEqual((self.evidence() / 'sub' / 'n.txt').read_bytes(), b'nested\n')
        self.assertFalse((self.evidence() / 'stale.raw').exists())
        self.assertEqual(self.evidence().stat().st_mode & 0o777, 0o700)
        self.assert_no_staging()

    def test_a_symlink_in_the_previous_bundle_is_not_copied_into_the_new_one(self):
        done, _ = self.run_recapture()
        self.assertEqual(done.returncode, 0, done.stderr)
        outside = self.outside()
        (self.evidence() / 'leak').symlink_to(outside)
        done, _ = self.run_recapture()
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertFalse((self.evidence() / 'leak').exists())
        self.assertFalse((self.evidence() / 'leak').is_symlink())
        self.assertEqual(list(outside.iterdir()), [])
        self.assert_no_staging()

    def test_docstring_describes_the_staging(self):
        module = load_script_module()
        doc = ' '.join(module.__doc__.split())
        self.assertIn('staging directory', doc)
        self.assertIn('never mixes legs of two runs', doc)


def sha256_hex(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def write_manifest(bundle):
    """Write MANIFEST.sha256 over every regular file of bundle (the shape the cert uses)."""
    lines = ['%s  %s\n' % (sha256_hex(p), p.name) for p in sorted(Path(bundle).iterdir())
             if p.is_file() and p.name != 'MANIFEST.sha256']
    (Path(bundle) / 'MANIFEST.sha256').write_text(''.join(lines))


def manifest_problems(bundle):
    """[] when MANIFEST.sha256 exists and every file it lists is present and matches."""
    manifest = Path(bundle) / 'MANIFEST.sha256'
    if not manifest.is_file():
        return ['MANIFEST.sha256 missing']
    problems = []
    for line in manifest.read_text().splitlines():
        digest, name = line.split('  ', 1)
        target = Path(bundle) / name
        if not target.is_file() or sha256_hex(target) != digest:
            problems.append(name)
    return problems


def tree_names(base, predicate):
    """Every path under base (links not followed) whose basename satisfies predicate."""
    found = []
    for directory, names, files in os.walk(str(base)):
        found.extend(os.path.join(directory, n) for n in names + files if predicate(n))
    return found


CWD_HOOK = (
    '\nimport json as _j, os as _o, sys as _s\n'
    'open(%(log)r, "a").write(_j.dumps({"argv": _s.argv[1:], "cwd": _o.getcwd(),\n'
    '    "ls": sorted(_o.listdir(".")), "mode": _o.stat(".").st_mode & 0o777,\n'
    '    "home": _o.environ["HOME"], "noconfig": _o.environ.get("AI_MEMORY_NO_CONFIG"),\n'
    '    "store": _o.path.exists("ai-memory.db")}) + "\\n")\n')


class ChildCwd7608(SymlinkBase):
    """#7608: every child runs in a fresh empty 0700 sandbox directory under .local-runs with
    HOME inside it and AI_MEMORY_NO_CONFIG=1, so no leg can open a database it did not create."""

    def make_cwd_stub(self, name, log):
        head, rest = STUB.split('\n', 1)
        path = self.root / name
        path.write_text(head + CWD_HOOK % {'log': str(log)} + rest)
        path.chmod(0o755)
        return path

    def test_every_leg_runs_in_an_empty_private_sandbox_and_ignores_a_planted_store(self):
        log = self.home / 'cwd.log'
        planted = self.home / 'planted-cwd'
        planted.mkdir()
        (planted / 'ai-memory.db').write_bytes(b'a live store')
        default = self.make_cwd_stub('cwd-default', log)
        sqlcipher = self.make_cwd_stub('cwd-sqlcipher', log)
        done, _ = self.run_recapture(default_bin=default, sqlcipher_bin=sqlcipher, cwd=planted)
        self.assertEqual(done.returncode, 0, done.stderr)
        records = [json.loads(line) for line in log.read_text().splitlines()]
        kinds = [r['argv'][:1] for r in records]
        self.assertEqual(kinds.count(['doctor']), 4, kinds)
        self.assertIn(['rules'], kinds)
        self.assertIn(['stats'], kinds)
        runs = (self.root / '.local-runs').resolve()
        for record in records:
            with self.subTest(argv=record['argv']):
                cwd = Path(record['cwd']).resolve()
                self.assertNotEqual(cwd, planted.resolve())
                self.assertIn(runs, cwd.parents)
                self.assertEqual(record['ls'], [])
                self.assertEqual(record['mode'], 0o700)
                self.assertFalse(record['store'])
                self.assertEqual(record['noconfig'], '1')
                self.assertIn(runs, Path(record['home']).resolve().parents)
                self.assertNotEqual(record['home'], str(self.home))
        self.assertEqual(sorted(p.name for p in planted.iterdir()), ['ai-memory.db'])
        self.assertEqual((planted / 'ai-memory.db').read_bytes(), b'a live store')

    def test_the_evidence_does_not_depend_on_the_callers_cwd(self):
        outputs = []
        for index in range(2):
            caller = self.home / ('caller%d' % index)
            caller.mkdir()
            if index:
                (caller / 'ai-memory.db').write_bytes(b'x')
            done, _ = self.run_recapture(cwd=caller)
            self.assertEqual(done.returncode, 0, done.stderr)
            outputs.append({n: self.out(n) for n in (
                'posture-bare-env.out', 'posture-hardened-env.out',
                'posture-hardened-boot-refusal.out', 'posture-sqlcipher-pass.out')})
        self.assertEqual(outputs[0], outputs[1])

    def test_the_sandbox_is_fresh_every_run_and_removed_afterwards(self):
        runs = self.root / '.local-runs'
        stale = runs / 'cert-3607-sandbox' / 'cwd'
        stale.mkdir(parents=True)
        (stale / 'ai-memory.db').write_bytes(b'left by someone')
        log = self.home / 'cwd.log'
        default = self.make_cwd_stub('cwd-default', log)
        done, _ = self.run_recapture(default_bin=default)
        self.assertEqual(done.returncode, 0, done.stderr)
        for line in log.read_text().splitlines():
            self.assertEqual(json.loads(line)['ls'], [])
        self.assertFalse((runs / 'cert-3607-sandbox').exists())

    def test_the_sandbox_home_is_labelled_home_in_the_evidence(self):
        done, _ = self.run_recapture()
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertIn('HOME=<home>', self.out('posture-bare-env.out'))
        self.assertNotIn('cert-3607-sandbox', self.out('posture-bare-env.out'))

    def test_every_subprocess_call_names_a_cwd(self):
        tree = ast.parse((REPO / 'scripts' / SCRIPT_NAME).read_text())
        calls = [node for node in ast.walk(tree) if isinstance(node, ast.Call)
                 and ast.unparse(node.func).startswith('subprocess.')]
        self.assertGreaterEqual(len(calls), 4)
        missing = [node.lineno for node in calls
                   if 'cwd' not in {keyword.arg for keyword in node.keywords}]
        self.assertEqual(missing, [])

    def test_docstring_states_the_sandbox(self):
        module = load_script_module()
        doc = ' '.join(module.__doc__.split())
        self.assertIn('sandbox', doc)
        self.assertIn('AI_MEMORY_NO_CONFIG=1', doc)
        self.assertIn('cwd', doc)
        self.assertIn('sandbox', module.USAGE_EPILOG)


class WorkDirs7609(SymlinkBase):
    """#7609 #7610 #7611: the staging directory, the aside directory and every raw capture
    live under .local-runs; nothing temporary is ever created under docs/."""

    def evidence(self):
        return self.root / OUT_REL

    def work(self):
        return self.root / '.local-runs' / 'cert-3607-work'

    def make_probe_stub(self, name, log):
        head, rest = STUB.split('\n', 1)
        hook = (
            '\nimport json as _j, os as _o, sys as _s\n'
            'if _s.argv[1:2] == ["doctor"]:\n'
            '    _r = _o.path.dirname(_o.path.dirname(_o.environ["TMPDIR"]))\n'
            '    _docs, _raws = [], []\n'
            '    for _d, _ns, _fs in _o.walk(_o.path.join(_r, "docs")):\n'
            '        _docs.extend(_o.path.join(_d, _n) for _n in _ns + _fs)\n'
            '    for _d, _ns, _fs in _o.walk(_o.path.join(_r, ".local-runs")):\n'
            '        _raws.extend(_o.path.join(_d, _n) for _n in _fs if _n.endswith(".raw"))\n'
            '    open(%r, "a").write(_j.dumps({"docs": _docs, "raws": _raws}) + "\\n")\n'
            % str(log))
        path = self.root / name
        path.write_text(head + hook + rest)
        path.chmod(0o755)
        return path

    def seed(self):
        """A first run, then SANITIZATION.md and a MANIFEST.sha256 over the bundle."""
        done, _ = self.run_recapture()
        self.assertEqual(done.returncode, 0, done.stderr)
        (self.evidence() / 'SANITIZATION.md').write_bytes(b'kept note\n')
        (self.evidence() / 'named-tests.txt').write_bytes(b'original named tests\n')
        write_manifest(self.evidence())
        return self.snapshot()

    def snapshot(self):
        return {str(p.relative_to(self.evidence())): p.read_bytes()
                for p in sorted(self.evidence().rglob('*')) if p.is_file()}

    def assert_complete_and_clean(self):
        evidence = self.evidence()
        self.assertEqual(manifest_problems(evidence), [])
        self.assertEqual((evidence / 'SANITIZATION.md').read_bytes(), b'kept note\n')
        self.assertTrue((evidence / 'posture-bare-env.out').is_file())
        self.assertRegex(self.out('posture-legs-exit-codes.txt').split('\n', 1)[0], HEADER_RE)
        self.assertEqual(sorted(p.name for p in evidence.parent.iterdir()), ['cert-3607'])
        left = [p.name for p in self.work().iterdir()] if self.work().is_dir() else []
        self.assertEqual([n for n in left if n != '.lock'], [], left)
        self.assertEqual(tree_names(self.root / 'docs', lambda n: n.endswith('.raw')
                                    or n.startswith('.cert-3607.')), [])
        self.assertEqual(tree_names(self.root / '.local-runs', lambda n: n.endswith('.raw')
                                    or n.startswith('old-') or n.startswith('staging-')
                                    or n.startswith('raw-')), [])
        self.assertFalse((self.root / '.local-runs' / 'cert-3607-sandbox').exists())

    def test_nothing_temporary_is_created_under_docs_and_raws_live_under_local_runs(self):
        log = self.home / 'probe.log'
        default = self.make_probe_stub('probe-default', log)
        sqlcipher = self.make_probe_stub('probe-sqlcipher', log)
        for _ in range(2):  # the second run has a previous bundle to copy
            done, _ = self.run_recapture(default_bin=default, sqlcipher_bin=sqlcipher)
            self.assertEqual(done.returncode, 0, done.stderr)
        records = [json.loads(line) for line in log.read_text().splitlines()]
        self.assertEqual(len(records), 8)
        evidence = str(self.evidence())
        for record in records:
            for entry in record['docs']:
                base = os.path.basename(entry)
                self.assertFalse(base.startswith('.cert-3607.') or base.endswith('.raw'), entry)
                self.assertTrue(entry == evidence or entry.startswith(evidence + os.sep)
                                or entry in {str(self.root / 'docs'),
                                             str(self.root / 'docs' / 'compliance'),
                                             str(self.root / 'docs' / 'compliance' / 'evidence')},
                                entry)
            self.assertEqual(len(record['raws']), 1, record)
        self.assertEqual(sorted(p.name for p in self.evidence().parent.iterdir()), ['cert-3607'])

    def test_the_device_check_is_a_function_and_refuses_a_cross_device_pair(self):
        module = load_script_module()
        self.assertIsNone(module.device_problem(self.root, self.home))
        real = os.stat

        class Fake:
            def __init__(self, dev):
                self.st_dev = dev

        calls = []

        def fake(path, *args, **kwargs):
            calls.append(path)
            return Fake(len(calls))

        with unittest.mock.patch.object(module.os, 'stat', fake):
            self.assertIn('filesystem', module.device_problem(self.root, self.home))
        self.assertIs(os.stat, real)

    def test_a_cross_device_work_directory_is_refused_before_any_bundle_write(self):
        prelude = "m.device_problem = lambda first, second: 'forced: not the same filesystem'"
        done = self.run_driver(prelude)
        self.assertEqual(done.returncode, 1, done.stderr)
        self.assertIn('same filesystem', done.stderr)
        self.assertFalse(self.evidence().exists())

    def run_driver(self, prelude):
        driver = self.home / 'driver.py'
        driver.write_text(DRIVER)
        script = self.root / 'scripts' / SCRIPT_NAME
        return subprocess.run([sys.executable, str(driver), str(script), prelude],
                              env=self.base_env(), cwd=str(self.root), capture_output=True,
                              text=True)

    def test_the_gitignore_belt_covers_the_dot_cert_names(self):
        ignore = REPO / 'docs' / 'compliance' / 'evidence' / '.gitignore'
        self.assertIn('.cert-3607.*', ignore.read_text().split())
        done = subprocess.run(['git', '-C', str(REPO), 'check-ignore', '-q',
                               'docs/compliance/evidence/.cert-3607.staging-0123/x.raw'],
                              check=False)
        self.assertEqual(done.returncode, 0)

    # ---- recovery from a leftover aside / staging / raw directory (#7610)

    def new_work(self):
        self.work().mkdir(parents=True, exist_ok=True)
        self.work().chmod(0o700)
        return self.work()

    def test_an_aside_with_a_missing_bundle_is_restored(self):
        for where in ('work', 'legacy'):
            with self.subTest(aside=where):
                shutil.rmtree(str(self.root / 'docs'), True)
                shutil.rmtree(str(self.root / '.local-runs'), True)
                self.seed()
                aside = (self.new_work() / 'old-0123456789abcdef' if where == 'work'
                         else self.evidence().parent / '.cert-3607.old-0123456789abcdef')
                os.rename(str(self.evidence()), str(aside))
                done, _ = self.run_recapture()
                self.assertEqual(done.returncode, 0, done.stderr)
                self.assert_complete_and_clean()
                self.assertEqual(self.out('named-tests.txt'), 'original named tests\n')

    def test_an_aside_replaces_an_incomplete_bundle(self):
        self.seed()
        shutil.copytree(str(self.evidence()), str(self.new_work() / 'old-0123456789abcdef'))
        (self.evidence() / 'named-tests.txt').unlink()  # listed in the manifest: incomplete
        done, _ = self.run_recapture()
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assert_complete_and_clean()
        self.assertEqual(self.out('named-tests.txt'), 'original named tests\n')

    def test_an_aside_is_dropped_when_the_bundle_is_complete(self):
        self.seed()
        shutil.copytree(str(self.evidence()), str(self.new_work() / 'old-0123456789abcdef'))
        (self.evidence() / 'newer.txt').write_bytes(b'newer\n')
        write_manifest(self.evidence())
        done, _ = self.run_recapture()
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assert_complete_and_clean()
        self.assertEqual(self.out('newer.txt'), 'newer\n')

    def test_two_asides_are_refused_and_left_alone(self):
        self.seed()
        work = self.new_work()
        for name in ('old-0000000000000001', 'old-0000000000000002'):
            shutil.copytree(str(self.evidence()), str(work / name))
        before = self.snapshot()
        done, _ = self.run_recapture()
        self.assertEqual(done.returncode, 1, done.stderr)
        self.assertIn('old-', done.stderr)
        self.assertEqual(self.snapshot(), before)
        self.assertEqual(sorted(p.name for p in work.iterdir() if p.name.startswith('old-')),
                         ['old-0000000000000001', 'old-0000000000000002'])

    def test_leftover_staging_and_raw_directories_are_removed(self):
        self.seed()
        work = self.new_work()
        (work / 'staging-aaaaaaaaaaaaaaaa').mkdir()
        (work / 'staging-aaaaaaaaaaaaaaaa' / 'x').write_bytes(b'half a bundle')
        (work / 'raw-bbbbbbbbbbbbbbbb').mkdir()
        (work / 'raw-bbbbbbbbbbbbbbbb' / 'posture-bare-env.out.raw').write_bytes(
            str(self.home).encode())
        legacy = self.evidence().parent / '.cert-3607.staging-cccccccccccccccc'
        legacy.mkdir()
        (legacy / 'posture-bare-env.out.raw').write_bytes(str(self.home).encode())
        done, _ = self.run_recapture()
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assert_complete_and_clean()

    def test_a_leftover_staging_directory_on_a_first_run_is_removed(self):
        work = self.new_work()
        (work / 'staging-aaaaaaaaaaaaaaaa').mkdir()
        done, _ = self.run_recapture()
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertEqual(sorted(p.name for p in work.iterdir() if p.name != '.lock'), [])

    def test_a_leftover_that_is_a_symlink_is_unlinked_never_followed(self):
        outside = self.outside()
        (outside / 'precious').write_bytes(b'keep')
        work = self.new_work()
        (work / 'staging-aaaaaaaaaaaaaaaa').symlink_to(outside)
        (work / 'raw-bbbbbbbbbbbbbbbb').symlink_to(outside)
        done, _ = self.run_recapture()
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertEqual((outside / 'precious').read_bytes(), b'keep')
        self.assertEqual(sorted(p.name for p in work.iterdir() if p.name != '.lock'), [])

    def test_a_second_concurrent_run_is_refused(self):
        marker = self.home / 'marker'
        hang = self.make_hang_stub(self.root / 'hang-default', marker, 1)
        proc = self.popen_recapture(default_bin=hang)
        try:
            self.wait_for(marker)
            done, _ = self.run_recapture()
            self.assertEqual(done.returncode, 1, done.stderr)
            self.assertIn('another', done.stderr)
        finally:
            self.kill(proc, marker)

    # ---- SIGKILL at each step, then a rerun (#7609 #7610)

    def make_hang_stub(self, path, marker, nth):
        """Hangs, after printing a line, in its nth `doctor` invocation (counted in a file)."""
        head, rest = STUB.split('\n', 1)
        counter = self.home / ('count-' + path.name)
        hook = (
            '\nimport os as _o, sys as _s, time as _t\n'
            'if _s.argv[1:2] == ["doctor"]:\n'
            '    _c = %r\n'
            '    _n = (int(open(_c).read()) if _o.path.exists(_c) else 0) + 1\n'
            '    open(_c, "w").write(str(_n))\n'
            '    if _n == %d:\n'
            '        print("pending capture " + _o.environ["HOME"])\n'
            '        _s.stdout.flush()\n'
            '        open(%r, "w").write(str(_o.getpid()))\n'
            '        _t.sleep(120)\n' % (str(counter), nth, str(marker)))
        path.write_text(head + hook + rest)
        path.chmod(0o755)
        return path

    def wait_for(self, marker):
        deadline = time.time() + 60
        while not marker.exists() or not marker.read_text():
            self.assertLess(time.time(), deadline, 'the hanging leg never started')
            time.sleep(0.05)

    def kill(self, proc, marker):
        with contextlib.suppress(OSError, ValueError):
            os.kill(int(marker.read_text()), signal.SIGKILL)
        with contextlib.suppress(OSError):
            os.kill(proc.pid, signal.SIGKILL)
        proc.communicate()

    def test_sigkill_during_each_leg_then_a_rerun_leaves_a_complete_bundle(self):
        for leg in (1, 2, 3, 4):
            with self.subTest(leg=leg):
                shutil.rmtree(str(self.root / 'docs'), True)
                shutil.rmtree(str(self.root / '.local-runs'), True)
                before = self.seed()
                marker = self.home / ('marker%d' % leg)
                if leg < 4:
                    hang = self.make_hang_stub(self.root / ('hang-default%d' % leg), marker, leg)
                    proc = self.popen_recapture(default_bin=hang)
                else:
                    hang = self.make_hang_stub(self.root / 'hang-sqlcipher', marker, 1)
                    proc = self.popen_recapture(sqlcipher_bin=hang)
                self.wait_for(marker)
                # the capture so far is on disk somewhere: never under docs
                self.assertEqual(tree_names(self.root / 'docs', lambda n: n.endswith('.raw')
                                            or n.startswith('.cert-3607.')), [])
                self.kill(proc, marker)
                self.assertEqual(proc.returncode, -signal.SIGKILL)
                self.assertEqual(self.snapshot(), before)
                done, _ = self.run_recapture()
                self.assertEqual(done.returncode, 0, done.stderr)
                self.assert_complete_and_clean()

    def test_sigkill_at_each_publish_step_then_a_rerun_leaves_a_complete_bundle(self):
        steps = {
            'after the previous bundle is copied': (
                "real = m.copy_bundle\n"
                "def hook(*a, **k):\n"
                "    real(*a, **k)\n"
                "    os.kill(os.getpid(), signal.SIGKILL)\n"
                "m.copy_bundle = hook\n"),
            'after the old bundle is moved aside': self.replace_hook(1),
            'after the staged bundle is renamed in': self.replace_hook(2),
            'before the aside is removed': (
                "real = m.remove_tree\n"
                "def hook(path):\n"
                "    if os.path.basename(str(path)).startswith('old-'):\n"
                "        os.kill(os.getpid(), signal.SIGKILL)\n"
                "    real(path)\n"
                "m.remove_tree = hook\n"),
        }
        for step, prelude in steps.items():
            with self.subTest(step=step):
                shutil.rmtree(str(self.root / 'docs'), True)
                shutil.rmtree(str(self.root / '.local-runs'), True)
                self.seed()
                done = self.run_driver(prelude)
                self.assertEqual(done.returncode, -signal.SIGKILL, done.stderr)
                done, _ = self.run_recapture()
                self.assertEqual(done.returncode, 0, done.stderr)
                self.assert_complete_and_clean()

    def replace_hook(self, nth):
        return ("real = os.replace\n"
                "count = [0]\n"
                "def hook(*a, **k):\n"
                "    real(*a, **k)\n"
                "    count[0] += 1\n"
                "    if count[0] == %d:\n"
                "        os.kill(os.getpid(), signal.SIGKILL)\n"
                "os.replace = hook\n" % nth)

    def test_a_kill_between_the_two_renames_leaves_the_aside_the_next_run_restores(self):
        self.seed()
        done = self.run_driver(self.replace_hook(1))
        self.assertEqual(done.returncode, -signal.SIGKILL, done.stderr)
        self.assertFalse(self.evidence().exists())
        self.assertEqual([p.name for p in self.work().iterdir() if p.name.startswith('old-')][:1],
                         [p.name for p in self.work().iterdir() if p.name.startswith('old-')])
        self.assertEqual(len([p for p in self.work().iterdir() if p.name.startswith('old-')]), 1)
        done, _ = self.run_recapture()
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assert_complete_and_clean()


class WorldWritableAncestors7611(SymlinkBase):
    """#7611: the world-writable and foreign-uid refusal covers every directory the script
    reads or writes through, evidence parents and the repo root included."""

    def test_a_world_writable_directory_on_any_written_path_is_refused(self):
        for rel in ('', 'docs', 'docs/compliance', 'docs/compliance/evidence',
                    '.local-runs/cert-3607-work', '.local-runs/cert-3607-fixtures/keys',
                    '.local-runs/tmp'):
            with self.subTest(directory=rel or '<repo root>'):
                shutil.rmtree(str(self.root / 'docs'), True)
                shutil.rmtree(str(self.root / '.local-runs'), True)
                target = self.root / rel if rel else self.root
                target.mkdir(parents=True, exist_ok=True)
                target.chmod(0o777)
                try:
                    done, _ = self.run_recapture()
                    self.assertEqual(done.returncode, 1, done.stderr)
                    self.assertIn('writable', done.stderr)
                    if rel:
                        self.assertIn(rel.rsplit('/', 1)[-1], done.stderr)
                    self.assertFalse((self.root / OUT_REL / 'posture-bare-env.out').exists())
                finally:
                    target.chmod(0o700)

    def test_a_sticky_world_writable_directory_is_accepted(self):
        evidence = self.root / 'docs' / 'compliance' / 'evidence'
        evidence.mkdir(parents=True)
        evidence.chmod(0o1777)
        done, _ = self.run_recapture()
        self.assertEqual(done.returncode, 0, done.stderr)

    def test_dir_problem_sticky_and_ancestor_units(self):
        module = load_script_module()
        module.ROOT = self.root
        module.OUT = self.root / OUT_REL
        module.LOCAL_RUNS = self.root / '.local-runs'
        module.FIX = module.LOCAL_RUNS / 'cert-3607-fixtures'
        module.WORK = module.LOCAL_RUNS / 'cert-3607-work'
        names = [str(p) for p in module.guarded_dirs(self.root / '.local-runs' / 'tmp')]
        for rel in ('', 'docs', 'docs/compliance', 'docs/compliance/evidence', OUT_REL.as_posix(),
                    '.local-runs', '.local-runs/cert-3607-fixtures', '.local-runs/cert-3607-work',
                    '.local-runs/tmp'):
            self.assertIn(str(self.root / rel) if rel else str(self.root), names, rel)
        sticky = self.root / 'sticky'
        sticky.mkdir()
        sticky.chmod(0o1777)
        self.assertIsNone(module.dir_problem(sticky))
        sticky.chmod(0o777)
        self.assertIn('writable', module.dir_problem(sticky))

    def test_docstring_states_the_ancestor_refusal(self):
        module = load_script_module()
        doc = ' '.join(module.__doc__.split())
        self.assertIn('every directory the script reads or writes through', doc)
        self.assertIn('sticky', doc)


class BraceComma7612(RecaptureBase):
    """#7612: a path after `,` or `{` and before `}` is rewritten like any other whole path."""

    HOME_PATH = '/home/probeuser'

    def patched(self):
        module = load_script_module()
        module.ROOT = Path('/mnt/x/repo')
        module.FIX = module.ROOT / '.local-runs' / 'cert-3607-fixtures'
        module.HOME = self.HOME_PATH
        return module

    FORMS = (
        '{k: P}', '${P}', '${P}/x', '{P}', '{P/x}', '{P, Q}', 'P,P', 'a,P', '[P,P]',
        '--dirs=P,P/x', '{"p":"P"}', '{"p": "P"}', '<home>,P', '{{P}}', '{[P]}', '{P}}',
        '{k: P, j: P}', '{(P)}', 'x={P},y={P}', '${P}:${P}/bin', '${HOME}=P', '{P};', '{P}.',
    )

    def test_table_of_brace_and_comma_forms(self):
        module = self.patched()
        for form in self.FORMS:
            with self.subTest(form=form):
                raw = form.replace('Q', '/home/other').replace('P', self.HOME_PATH)
                got = module.sanitize(raw.encode()).decode()
                self.assertNotIn(self.HOME_PATH, got)
                self.assertIn('<home>', got)

    def test_a_bundle_with_the_path_in_every_form_has_no_residue(self):
        module = self.patched()
        document = '\n'.join(form.replace('Q', '/home/other').replace('P', self.HOME_PATH)
                             for form in self.FORMS)
        got = module.sanitize(document.encode()).decode()
        self.assertEqual(got.count(self.HOME_PATH), 0, got)
        self.assertEqual(got.count('/home/other'), 1, got)

    def test_forms_that_continue_the_path_are_over_redacted(self):
        module = self.patched()
        for form in ('{P-x}', '{Px}', '{P.txt}', '$P', 'xP', '{P+x}', '{P@x}', '{P%x}'):
            raw = form.replace('P', self.HOME_PATH)
            with self.subTest(raw=raw):
                got = module.sanitize(raw.encode()).decode()
                self.assertNotIn(self.HOME_PATH, got)
                self.assertEqual(got, form.replace('P', '<home>'))


class HomeCharacters7613(unittest.TestCase):
    """#7613: HOME may hold only printable ASCII: no character str.splitlines splits on, no
    Cc/Cf/Zl/Zp character, no non-ASCII character at all."""

    def test_every_character_splitlines_splits_on_is_refused(self):
        module = load_script_module()
        splitters = [cp for cp in range(0x110000)
                     if len(('a' + chr(cp) + 'b').splitlines()) > 1]
        self.assertIn(0x85, splitters)
        self.assertIn(0x2028, splitters)
        self.assertIn(0x1C, splitters)
        for cp in splitters:
            self.assertIsNotNone(module.home_problem('/home/a' + chr(cp) + 'b'), hex(cp))

    def test_every_control_format_and_separator_character_is_refused(self):
        module = load_script_module()
        for cp in range(0x110000):
            if unicodedata.category(chr(cp)) in ('Cc', 'Cf', 'Zl', 'Zp'):
                self.assertIsNotNone(module.home_problem('/home/a' + chr(cp)), hex(cp))

    def test_every_non_ascii_character_is_refused(self):
        module = load_script_module()
        for cp in list(range(0x80, 0x3000)) + [0xD7FF, 0xD800, 0xDFFF, 0xE000, 0xFFFD, 0x10000,
                                               0x1F600, 0x10FFFF]:
            self.assertIsNotNone(module.home_problem('/home/a' + chr(cp)), hex(cp))

    def test_printable_ascii_stays_usable(self):
        module = load_script_module()
        for cp in range(0x20, 0x7F):
            char = chr(cp)
            if char in ':/':  # a colon is refused; a trailing slash is not normal form
                continue
            self.assertIsNone(module.home_problem('/home/a' + char), hex(cp))

    def test_the_docstring_states_the_choice(self):
        module = load_script_module()
        doc = ' '.join(module.__doc__.split())
        self.assertIn('non-ASCII', doc)
        self.assertIn('splitlines', doc)
        self.assertIn('ASCII', module.USAGE_EPILOG)


DRIVER = '''
import importlib.util, os, signal, sys
spec = importlib.util.spec_from_file_location('recapture_driver', sys.argv[1])
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
exec(sys.argv[2])
sys.exit(m.main([]))
'''


class EmptyExcept7537(unittest.TestCase):
    def test_open_new_has_no_empty_except_clause(self):
        text = (REPO / 'scripts' / SCRIPT_NAME).read_text()
        empty = [node.lineno for node in ast.walk(ast.parse(text))
                 if isinstance(node, ast.ExceptHandler)
                 and ast.unparse(node.type) == 'FileNotFoundError'
                 and all(isinstance(stmt, ast.Pass) for stmt in node.body)]
        self.assertEqual(empty, [])
        self.assertIn('contextlib.suppress(FileNotFoundError)', text)


class SwapReplaceDocs7539(SymlinkBase):
    def test_a_link_at_a_replaceable_path_is_replaced_and_the_run_succeeds(self):
        outside = self.outside()
        head, rest = STUB.split('\n', 1)
        swap = self.root / 'swap-replaceable'
        swap.write_text(
            head + '\nimport os as _o, sys as _s\n'
            'if _s.argv[1:2] == ["doctor"] and "--posture" in _s.argv:\n'
            '    _r = _o.path.dirname(_o.path.dirname(_o.environ["TMPDIR"]))\n'
            '    _t = _o.path.join(_r, "docs", "compliance", "evidence", "cert-3607",\n'
            '                      "posture-bare-env.out")\n'
            '    _o.makedirs(_o.path.dirname(_t), exist_ok=True)\n'
            '    if not _o.path.lexists(_t):\n'
            '        _o.symlink(%r, _t)\n'
            '        open(%r, "w").close()\n' % (str(outside / 'stolen'), str(self.home / 'planted'))
            + rest)
        swap.chmod(0o755)
        done, _ = self.run_recapture(default_bin=swap)
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertTrue((self.home / 'planted').exists())
        target = self.root / OUT_REL / 'posture-bare-env.out'
        self.assertFalse(target.is_symlink())
        self.assertEqual(list(outside.iterdir()), [])

    def test_docstring_describes_replace_versus_fail_closed(self):
        module = load_script_module()
        doc = ' '.join(module.__doc__.split())
        self.assertIn('A symlink at a replaceable path is removed and replaced, never followed', doc)
        self.assertNotIn('so a link swapped in mid-run fails closed with exit 1', doc)
        self.assertIn('symlinked parent, a symlink at the passphrase', doc)


if __name__ == '__main__':
    unittest.main()


class ChildCwd7648(SymlinkBase):
    """#7648: every child (keygen, the seed, each leg, git) runs in its OWN fresh empty 0700
    cwd with HOME inside the same per-child sandbox; keygen creates ai-memory.db in its cwd
    (as the real one does) and no leg ever sees it, so a rerun gives byte-identical captures."""

    BUNDLE_OUT = ('posture-bare-env.out', 'posture-hardened-env.out',
                  'posture-hardened-boot-refusal.out', 'posture-sqlcipher-pass.out')

    def make_cwd_stub(self, name, log):
        head, rest = STUB.split('\n', 1)
        path = self.root / name
        path.write_text(head + CWD_HOOK % {'log': str(log)} + rest)
        path.chmod(0o755)
        return path

    def bundle(self):
        evidence = self.root / OUT_REL
        return {p.name: p.read_bytes() for p in sorted(evidence.iterdir()) if p.is_file()}

    def test_every_child_has_its_own_fresh_empty_cwd_and_home(self):
        log = self.home / 'cwd.log'
        default = self.make_cwd_stub('cwd-default', log)
        sqlcipher = self.make_cwd_stub('cwd-sqlcipher', log)
        done, _ = self.run_recapture(default_bin=default, sqlcipher_bin=sqlcipher)
        self.assertEqual(done.returncode, 0, done.stderr)
        records = [json.loads(line) for line in log.read_text().splitlines()]
        self.assertEqual(len(records), 6, [r['argv'] for r in records])  # keygen, 4 legs, seed
        cwds = [record['cwd'] for record in records]
        self.assertEqual(len(set(cwds)), len(cwds), 'a cwd was shared: %s' % cwds)
        homes = [record['home'] for record in records]
        self.assertEqual(len(set(homes)), len(homes), 'a HOME was shared: %s' % homes)
        runs = (self.root / '.local-runs').resolve()
        for record in records:
            with self.subTest(argv=record['argv']):
                self.assertEqual(record['ls'], [], 'the cwd was not empty')
                self.assertFalse(record['store'])
                self.assertEqual(record['mode'], 0o700)
                self.assertIn(runs, Path(record['home']).resolve().parents)
                self.assertEqual(Path(record['home']).resolve().parent,
                                 Path(record['cwd']).resolve().parent)

    def test_keygen_store_is_made_in_keygens_own_cwd_and_no_capture_names_a_store(self):
        done, _ = self.run_recapture()
        self.assertEqual(done.returncode, 0, done.stderr)
        for name in self.BUNDLE_OUT:
            text = (self.root / OUT_REL / name).read_text()
            with self.subTest(file=name):
                self.assertNotIn('agrees', text)
                self.assertNotIn('ai-memory.db', text)
                self.assertIn('live pragma not observed', text)

    def test_a_leg_never_finds_a_store_through_its_cwd(self):
        done, _ = self.run_recapture()
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertFalse((self.root / '.local-runs' / 'cert-3607-sandbox').exists())
        stray = [p for p in self.root.rglob('ai-memory.db')]
        self.assertEqual(stray, [])  # keygen's store died with its sandbox

    def test_two_consecutive_runs_give_byte_identical_bundles(self):
        first, _ = self.run_recapture()
        self.assertEqual(first.returncode, 0, first.stderr)
        before = self.bundle()
        self.assertTrue((self.root / '.local-runs' / 'cert-3607-fixtures' / 'keys'
                         / 'operator.key').is_file())  # the second run skips keygen
        second, _ = self.run_recapture()
        self.assertEqual(second.returncode, 0, second.stderr)
        after = self.bundle()
        self.assertEqual(sorted(after), sorted(before))
        for name in before:
            with self.subTest(file=name):
                self.assertEqual(after[name], before[name])

    def test_a_run_with_the_key_present_matches_a_run_that_makes_it(self):
        done, _ = self.run_recapture()
        self.assertEqual(done.returncode, 0, done.stderr)
        made = self.bundle()
        keys = self.root / '.local-runs' / 'cert-3607-fixtures' / 'keys'
        for name in ('operator.key', 'operator.key.pub'):
            (keys / name).unlink()  # the third run makes the pair again
        done, _ = self.run_recapture()
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertEqual(self.bundle(), made)

    def test_every_subprocess_runs_in_a_per_child_directory(self):
        tree = ast.parse((REPO / 'scripts' / SCRIPT_NAME).read_text())
        text = (REPO / 'scripts' / SCRIPT_NAME).read_text()
        self.assertNotIn('SANDBOX_CWD', text)
        self.assertNotIn('SANDBOX_HOME', text)
        calls = [node for node in ast.walk(tree) if isinstance(node, ast.Call)
                 and ast.unparse(node.func).startswith('subprocess.')]
        for node in calls:
            keywords = {keyword.arg: ast.unparse(keyword.value) for keyword in node.keywords}
            with self.subTest(line=node.lineno):
                self.assertIn('cwd', keywords)
                self.assertNotIn('SANDBOX', keywords['cwd'])

    def test_docstring_states_exactly_what_holds(self):
        doc = ' '.join(load_script_module().__doc__.split())
        self.assertIn('its own fresh empty 0700 cwd', doc)
        self.assertIn('byte-identical', doc)
        self.assertIn('explicit path', doc)
        self.assertNotIn('one cwd', doc)


class ManifestVerify7649(RecaptureBase):
    """#7649: an existing bundle is verified against its committed manifest before anything is
    published, and a mismatch refuses the run; a new manifest is computed only over the files
    this run freshly captured, every other line is kept verbatim."""

    def evidence(self):
        return self.root / OUT_REL

    def snapshot(self):
        return {str(p.relative_to(self.evidence())): p.read_bytes()
                for p in sorted(self.evidence().rglob('*')) if p.is_file()}

    def seed(self):
        done, _ = self.run_recapture()
        self.assertEqual(done.returncode, 0, done.stderr)
        (self.evidence() / 'test-results.txt').write_bytes(b'test result: ok. 3 passed\n')
        (self.evidence() / 'SANITIZATION.md').write_bytes(b'note\n')
        write_manifest(self.evidence())
        return self.snapshot()

    def lines(self):
        return {line.split('  ', 1)[1]: line for line in
                (self.evidence() / 'MANIFEST.sha256').read_text().splitlines()}

    def assert_untouched(self, before):
        self.assertEqual(self.snapshot(), before)
        work = self.root / '.local-runs' / 'cert-3607-work'
        left = [p.name for p in work.iterdir()] if work.is_dir() else []
        self.assertEqual([n for n in left if n != '.lock'], [], left)

    def test_a_clean_rerun_passes_and_the_manifest_verifies(self):
        before = self.seed()
        old_lines = self.lines()
        done, _ = self.run_recapture()
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertEqual(manifest_problems(self.evidence()), [])
        new_lines = self.lines()
        for name in ('test-results.txt', 'SANITIZATION.md'):
            self.assertEqual(new_lines[name], old_lines[name])
            self.assertEqual((self.evidence() / name).read_bytes(), before[name])
        self.assertEqual(sorted(new_lines), sorted(old_lines))

    def test_an_edited_test_results_file_makes_the_run_refuse(self):
        self.seed()
        log = self.home / 'ran.log'
        default = self.make_logging_stub(self.root / 'logging-default', log)
        with open(str(self.evidence() / 'test-results.txt'), 'ab') as handle:
            handle.write(b'test result: ok. 999 passed\n')
        before = self.snapshot()
        done, _ = self.run_recapture(default_bin=default)
        self.assertNotEqual(done.returncode, 0)
        self.assertEqual(done.returncode, 1, done.stderr)
        self.assertIn('test-results.txt', done.stderr)
        self.assertNotIn('Traceback', done.stderr)
        self.assertFalse(log.exists(), 'a binary ran although the bundle failed verification')
        self.assert_untouched(before)

    def test_an_edited_captured_file_makes_the_run_refuse(self):
        self.seed()
        with open(str(self.evidence() / 'posture-bare-env.out'), 'ab') as handle:
            handle.write(b'tampered\n')
        before = self.snapshot()
        done, _ = self.run_recapture()
        self.assertEqual(done.returncode, 1, done.stderr)
        self.assertIn('posture-bare-env.out', done.stderr)
        self.assert_untouched(before)

    def test_a_missing_listed_file_makes_the_run_refuse(self):
        self.seed()
        (self.evidence() / 'SANITIZATION.md').unlink()
        before = self.snapshot()
        done, _ = self.run_recapture()
        self.assertEqual(done.returncode, 1, done.stderr)
        self.assertIn('SANITIZATION.md', done.stderr)
        self.assert_untouched(before)

    def test_a_manifest_line_that_does_not_parse_makes_the_run_refuse(self):
        self.seed()
        with open(str(self.evidence() / 'MANIFEST.sha256'), 'a') as handle:
            handle.write('not a manifest line\n')
        before = self.snapshot()
        done, _ = self.run_recapture()
        self.assertEqual(done.returncode, 1, done.stderr)
        self.assertIn('MANIFEST.sha256', done.stderr)
        self.assert_untouched(before)

    def test_a_listed_name_with_a_slash_makes_the_run_refuse(self):
        self.seed()
        with open(str(self.evidence() / 'MANIFEST.sha256'), 'a') as handle:
            handle.write('%s  ../escape\n' % ('0' * 64))
        done, _ = self.run_recapture()
        self.assertEqual(done.returncode, 1, done.stderr)
        self.assertIn('../escape', done.stderr)

    def test_the_manifest_after_a_missing_leg_lists_no_stale_capture(self):
        self.seed()
        done, _ = self.run_recapture(sqlcipher_bin=self.root / 'no-such-binary')
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertNotIn('posture-sqlcipher-pass.out', self.lines())
        self.assertEqual(manifest_problems(self.evidence()), [])
        self.assertIn('test-results.txt', self.lines())

    def test_a_first_run_without_a_manifest_writes_none(self):
        done, _ = self.run_recapture()
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertFalse((self.evidence() / 'MANIFEST.sha256').exists())

    def test_refresh_manifest_never_rehashes_a_file_it_did_not_write(self):
        module = load_script_module()
        bundle = self.root / 'bundle'
        bundle.mkdir()
        (bundle / 'foreign.txt').write_bytes(b'original\n')
        (bundle / 'mine.out').write_bytes(b'v1\n')
        write_manifest(bundle)
        old = (bundle / 'MANIFEST.sha256').read_text()
        (bundle / 'foreign.txt').write_bytes(b'tampered\n')
        (bundle / 'mine.out').write_bytes(b'v2\n')
        module.refresh_manifest(bundle, {'mine.out'})
        new = {line.split('  ', 1)[1]: line.split('  ', 1)[0]
               for line in (bundle / 'MANIFEST.sha256').read_text().splitlines()}
        old_lines = {line.split('  ', 1)[1]: line.split('  ', 1)[0] for line in old.splitlines()}
        self.assertEqual(new['foreign.txt'], old_lines['foreign.txt'])  # verbatim, not re-hashed
        self.assertEqual(new['mine.out'], sha256_hex(bundle / 'mine.out'))

    def test_docstring_states_the_verification(self):
        doc = ' '.join(load_script_module().__doc__.split())
        self.assertIn('verified against its committed manifest', doc)
        self.assertIn('never re-hashes', doc)


class RealPaths7650(RecaptureBase):
    """#7650: every guarded path is resolved with os.path.realpath before any relative_to or
    parent walk, no ValueError is suppressed, and a path that cannot be placed fails closed."""

    def world_writable(self, relative):
        path = self.root / '.local-runs' / relative
        path.mkdir(parents=True)
        path.chmod(0o777)
        return path

    def test_the_real_root_refuses_a_world_writable_tmpdir(self):
        target = self.world_writable('r9ww')
        done, _ = self.run_recapture(extra_env={'TMPDIR': str(target)})
        self.assertEqual(done.returncode, 1, done.stderr)
        self.assertIn('world writable', done.stderr)

    def test_a_symlinked_repo_root_refuses_a_world_writable_tmpdir(self):
        link = self.home / 'rootlink'
        link.symlink_to(self.root)
        self.world_writable('r9ww')
        done, _ = self.run_recapture(extra_env={'TMPDIR': str(link / '.local-runs' / 'r9ww')},
                                     script_root=link)
        self.assertEqual(done.returncode, 1, done.stderr)
        self.assertIn('world writable', done.stderr)
        self.assertIn('r9ww', done.stderr)
        self.assertFalse((self.root / OUT_REL).exists())

    def test_a_symlinked_repo_root_refuses_a_world_writable_tmpdir_ancestor(self):
        link = self.home / 'rootlink2'
        link.symlink_to(self.root)
        self.world_writable('ww-parent')
        child = self.root / '.local-runs' / 'ww-parent' / 'inner'
        child.mkdir()
        child.chmod(0o700)
        done, _ = self.run_recapture(
            extra_env={'TMPDIR': str(link / '.local-runs' / 'ww-parent' / 'inner')},
            script_root=link)
        self.assertEqual(done.returncode, 1, done.stderr)
        self.assertIn('ww-parent', done.stderr)

    def test_a_symlinked_tmpdir_parent_refuses_a_world_writable_target(self):
        runs = self.root / '.local-runs'
        runs.mkdir(exist_ok=True)
        real = runs / 'realdir'
        real.mkdir()
        real.chmod(0o700)
        (runs / 'alias').symlink_to(real)
        sub = real / 'sub'
        sub.mkdir()
        sub.chmod(0o777)
        done, _ = self.run_recapture(extra_env={'TMPDIR': str(runs / 'alias' / 'sub')})
        self.assertEqual(done.returncode, 1, done.stderr)
        self.assertIn('world writable', done.stderr)

    def test_a_symlinked_repo_root_with_safe_directories_still_succeeds(self):
        link = self.home / 'rootlink3'
        link.symlink_to(self.root)
        done, _ = self.run_recapture(script_root=link)
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertTrue((self.root / OUT_REL / 'posture-bare-env.out').is_file())

    def test_a_path_that_cannot_be_placed_fails_closed(self):
        module = load_script_module()
        elsewhere = Path(tempfile.mkdtemp(prefix='recapture-5038-elsewhere-', dir=str(SCRATCH)))
        self.addCleanup(shutil.rmtree, str(elsewhere), True)
        with self.assertRaises(OSError):
            module.guarded_dirs(elsewhere)

    def test_no_value_error_is_suppressed_in_the_script(self):
        tree = ast.parse((REPO / 'scripts' / SCRIPT_NAME).read_text())
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and ast.unparse(node.func).endswith('suppress'):
                with self.subTest(line=node.lineno):
                    self.assertNotIn('ValueError', ast.unparse(node))
            if isinstance(node, ast.ExceptHandler) and node.type is not None:
                with self.subTest(line=node.lineno):
                    handled = ast.unparse(node.type)
                    if 'ValueError' in handled:
                        body = [ast.unparse(item) for item in node.body]
                        self.assertNotEqual(body, ['pass'])

    def test_the_script_does_not_use_resolve_on_guarded_paths(self):
        text = (REPO / 'scripts' / SCRIPT_NAME).read_text()
        self.assertNotIn('.resolve()', text)
        self.assertIn('os.path.realpath', text)


class ImportStyle7652(unittest.TestCase):
    """#7652 (CodeQL py/import-and-import-from): no module is imported both ways."""

    def test_no_test_or_script_module_imports_a_module_both_ways(self):
        for path in (REPO / 'scripts' / SCRIPT_NAME,
                     REPO / 'scripts' / 'ci' / 'tests' / Path(__file__).name):
            tree = ast.parse(path.read_text())
            plain, named = set(), set()
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    plain.update(alias.name.split('.')[0] for alias in node.names)
                elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                    named.add(node.module.split('.')[0])
            with self.subTest(path=path.name):
                self.assertEqual(sorted(plain & named), [])
