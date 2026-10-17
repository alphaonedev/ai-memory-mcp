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

    def run_recapture(self, sqlcipher_bin=None, args=None, extra_env=None, default_bin=None,
                      cwd=None):
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
        done = subprocess.run(cmd, env=env, cwd=str(cwd or self.root), capture_output=True,
                              text=True)
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
        status = module.run_capture(self.root, [], {}, raw, self.root / 'leg.out')
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
                      '\n/home/a', '/home\n/a', '/home/a\r'):
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

    def test_home_is_replaced_only_on_component_boundaries(self):
        module = self.patched('/home/a')
        raw = (b"/home/a/k /home/ab/y /home/a /home/a. 'open /home/a' x/home/a/z "
               b"/home/a.txt path=/home/a/q")
        want = (b"<home>/k /home/ab/y <home> <home>. 'open <home>' x/home/a/z "
                b"/home/a.txt path=<home>/q")
        self.assertEqual(module.sanitize(raw), want)

    def test_trailing_slash_home_is_normalised(self):
        module = self.patched('/home/a/')
        self.assertEqual(module.sanitize(b'/home/a/k /home/ab'), b'<home>/k /home/ab')

    def test_repo_root_is_replaced_only_on_component_boundaries(self):
        module = self.patched('/home/a')
        self.assertEqual(module.sanitize(b'/mnt/x/repo/a /mnt/x/repo-other/b /mnt/x/repo'),
                         b'<repo-root>/a /mnt/x/repo-other/b <repo-root>')

    def test_docstring_and_usage_state_the_home_rule(self):
        module = load_script_module()
        self.assertIn('absolute', ' '.join(module.USAGE_EPILOG.split()))
        self.assertIn('HOME', module.USAGE_EPILOG)
        self.assertIn('HOME', module.__doc__)
        self.assertIn('component', module.sanitize.__doc__)

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
                      '/home/a\x1f', '/home/a\x7f', '/ho\tme/a'):
            with self.subTest(home=value):
                self.assertIsNotNone(module.home_problem(value))
        for value in ('/home/a', '/home/a b', '/home/\u00e9', '/Users/x.y', '/a'):
            with self.subTest(home=value):
                self.assertIsNone(module.home_problem(value))


class SanitizerBoundaries7538(RecaptureBase):
    """#7538 #7571 #7572 #7573: a HOME, repo-root or fixtures path is rewritten only when BOTH
    ends are a boundary from an explicit allowlist of delimiter characters."""

    ROOTS = (
        # name, path, label, what the path looks like after the repo-root rewrite alone
        ('home', b'/home/a', b'<home>', b'/home/a'),
        ('root', b'/mnt/x/repo', b'<repo-root>', b'/mnt/x/repo'),
        ('fix', b'/mnt/x/repo/.local-runs/cert-3607-fixtures',
         b'<repo-root>/.local-runs/cert-3607-fixtures',
         b'<repo-root>/.local-runs/cert-3607-fixtures'),
    )
    REWRITTEN = (
        b'{P}', b'{P}/x', b'"{P}"', b"'{P}'", b'`{P}`', b'({P})', b'[{P}]', b'<{P}>',
        b'={P}', b':{P}', b'{P}:', b'{P};', b'{P},', b'{P} x', b'a {P}', b'{P}\n', b'{P}\t',
        b'{P}.', b'{P}. x', b'{P}.\n', b'KEY={P}:/bin', b'{P}) x', b'{P}] x', b'{P}> x',
        b'{P}, x', b'{P}: x', b'{P}; x', b'\t{P}', b'\n{P}', b' {P}/y z',
    )
    KEPT_END = (
        b'./x', b'..b', b'..', b'.txt', b'.b', b'.+', b'.)', b'.:x', b'.;', b'.,', b'.]',
        b'+b', b'~', b'@x', b'%20', b'#1', b'$x', b'&b', b'|b', b'!', b'(x', b'{x', b'}',
        b'[x', b'ab', b'_b', b'-b', b'=1', b'*', b'?', b'^', b'\\x', b'\xc3\xa9', b'\xc3\xa9/x',
        b'\xe2\x80\xa8', b'\x00', b'<x', b'\x01',
    )
    KEPT_START = (
        b'~', b'x+', b'x', b',', b'@', b'%', b'+', b'#', b'$', b'&', b'|', b'!', b'{', b'}',
        b'\\', b'.', b'-', b'_', b'\xc3\xa9', b'*', b'?', b'^', b';', b')', b']', b'>',
        b'/', b'a.', b'\x00', b'\xe2\x80\xa8', b'a,', b'1',
    )

    def patched(self):
        module = load_script_module()
        module.ROOT = Path('/mnt/x/repo')
        module.FIX = module.ROOT / '.local-runs' / 'cert-3607-fixtures'
        module.HOME = '/home/a'
        return module

    def test_rewrite_table_for_every_root(self):
        module = self.patched()
        for name, path, label, _ in self.ROOTS:
            for template in self.REWRITTEN:
                with self.subTest(root=name, raw=template):
                    raw = template.replace(b'{P}', path)
                    want = template.replace(b'{P}', label)
                    self.assertEqual(module.sanitize(raw), want)

    def test_end_boundary_kept_table_for_every_root(self):
        module = self.patched()
        for name, path, _, after_root in self.ROOTS:
            for suffix in self.KEPT_END:
                with self.subTest(root=name, suffix=suffix):
                    self.assertEqual(module.sanitize(path + suffix), after_root + suffix)

    def test_start_boundary_kept_table_for_every_root(self):
        module = self.patched()
        for name, path, _, _ in self.ROOTS:
            for prefix in self.KEPT_START:
                for tail in (b'', b'/x', b' y'):
                    with self.subTest(root=name, prefix=prefix, tail=tail):
                        raw = prefix + path + tail
                        self.assertEqual(module.sanitize(raw), raw)

    def test_reviewer_shapes_for_every_root(self):
        module = self.patched()
        for name, path, label, after_root in self.ROOTS:
            with self.subTest(root=name):
                self.assertEqual(module.sanitize(path + b'./x'), after_root + b'./x')
                self.assertEqual(module.sanitize(b'~' + path + b'/x'), b'~' + path + b'/x')
                self.assertEqual(module.sanitize(b'x+' + path + b'/x'), b'x+' + path + b'/x')
                self.assertEqual(module.sanitize(b',' + path), b',' + path)
                self.assertEqual(module.sanitize(b'@' + path), b'@' + path)
                self.assertEqual(module.sanitize(b'%' + path), b'%' + path)
                self.assertEqual(module.sanitize(path), label)
                self.assertEqual(module.sanitize(path + b'/x'), label + b'/x')
                self.assertEqual(module.sanitize(b'"' + path + b'"'), b'"' + label + b'"')
                self.assertEqual(module.sanitize(b'(' + path + b')'), b'(' + label + b')')
                self.assertEqual(module.sanitize(b'=' + path), b'=' + label)
                self.assertEqual(module.sanitize(path + b'.'), label + b'.')

    def test_two_paths_in_one_line_are_each_decided_on_their_own(self):
        module = self.patched()
        self.assertEqual(module.sanitize(b'/home/a,/home/a x/home/a /home/a'),
                         b'<home>,/home/a x/home/a <home>')

    def test_docstring_describes_an_explicit_allowlist(self):
        module = load_script_module()
        doc = ' '.join(module.sanitize.__doc__.split())
        self.assertIn('BOTH ends', doc)
        self.assertIn('explicit allowlist of delimiter characters', doc)
        self.assertIn('not a list of illegal filename bytes', doc)
        self.assertIn('Start boundary', doc)
        self.assertIn('End boundary', doc)
        self.assertIn('comma', doc)
        source = (REPO / 'scripts' / SCRIPT_NAME).read_text()
        self.assertNotIn('legal filename character', source)


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

    UMASKS = (0, 0o022, 0o077)

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
                shutil.rmtree(str(self.root / 'docs'))
                shutil.rmtree(str(self.root / '.local-runs'))

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
            '    _t = _o.path.join(_o.getcwd(), "docs", "compliance", "evidence", "cert-3607",\n'
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
