#!/usr/bin/env python3
"""Issues #4829 #4830 #4882 #4886: the cert recapture scripts, ported to Python.

`scripts/recapture-cert-{55,9220,eba96b307,f32c}-posture.sh` were four copies of
one shell script. They never exported `FIX` (the embedded fixture writer fell
back to `Path.cwd()`), and they put the leg-4 DB passphrase on the `env` argv.
Standing rule 3 ports a touched shell script, so the four now live behind
`scripts/recapture-cert-3607-posture.py --cert <id>`. These tests run the port
against stub `ai-memory` binaries in a throwaway sandbox repo under
`.local-runs/` (never a tmpfs) and pin, per cert: its own bundle and fixture
directory, the header shape, no dependence on the working directory or on a
`FIX` variable, the 20-check versus 22-check differences, and the leg-4
passphrase absent from every argv the script builds. They also pin the evidence
copy `cert-385da3a05/recapture-posture.sh` (kept as shell, attested) and the
SANITIZATION.md / MANIFEST.sha256 record of its amendment.

Run: python3 -m unittest scripts/ci/tests/test_recapture_cert_ports_4829.py
"""
import hashlib
import importlib.util
import os
import re
import shutil
import subprocess
import sys
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
TESTS_DIR = Path(__file__).resolve().parent
SCRIPT_NAME = 'recapture-cert-3607-posture.py'
EVIDENCE_REL = Path('docs') / 'compliance' / 'evidence'
EVIDENCE_COPY_BUNDLE = 'cert-385da3a05'
EVIDENCE_COPY_REL = EVIDENCE_REL / EVIDENCE_COPY_BUNDLE / 'recapture-posture.sh'
BUNDLE_FILES = (
    'posture-bare-env.out', 'posture-hardened-env.out', 'posture-hardened-boot-refusal.out',
    'posture-sqlcipher-pass.out', 'posture-legs-exit-codes.txt',
    'peer-fingerprints.txt', 'peer-attestation.json')
RUN_DATE_RE = r'(\d{4}-\d{2}-\d{2})'
HEADER_PREFIX = r'^# posture-legs transcript — recorded exit codes \(' + RUN_DATE_RE + ' '

# cert id -> (bundle dir, header label regex, 22-check generation)
CERTS = {
    '55': ('cert-55', r'recapture @ ([0-9a-f]+)\)$', False),
    '92209ad91': ('cert-92209ad91', r'92209ad91 re-issue recapture \(22 checks\) @ ([0-9a-f]+)\)$', True),
    'eba96b307': ('cert-eba96b307', r'#3607 re-issue recapture \(22 checks\) @ ([0-9a-f]+)\)$', True),
    'f32c18dad': ('cert-f32c18dad', r'f32c18dad re-issue recapture \(22 checks\) @ ([0-9a-f]+)\)$', True),
}
OLD_SCRIPT_NAMES = (
    'recapture-cert-55-posture.sh', 'recapture-cert-9220-posture.sh',
    'recapture-cert-eba96b307-posture.sh', 'recapture-cert-f32c-posture.sh')
PORT_NOTE = 'since ported to `scripts/recapture-cert-3607-posture.py --cert %s`'
# Docs that cite an old script by name -> (old script name, cert id it ports to).
CITING_DOCS = {
    'docs/compliance/ENTERPRISE-FEDERATION-CERTIFICATION.md': (
        ('recapture-cert-eba96b307-posture.sh', 'eba96b307'),
        ('recapture-cert-f32c-posture.sh', 'f32c18dad')),
    'docs/compliance/evidence/cert-92209ad91/SANITIZATION.md': (
        ('recapture-cert-9220-posture.sh', '92209ad91'),
        ('recapture-cert-f32c-posture.sh', 'f32c18dad')),
    'docs/compliance/evidence/cert-eba96b307/SANITIZATION.md': (
        ('recapture-cert-eba96b307-posture.sh', 'eba96b307'),),
    'docs/compliance/evidence/cert-f32c18dad/SANITIZATION.md': (
        ('recapture-cert-f32c-posture.sh', 'f32c18dad'),),
}
TOUCHED_BUNDLES = ('cert-385da3a05', 'cert-92209ad91', 'cert-eba96b307', 'cert-f32c18dad')


def load_base_module():
    """Import the 5038 test module by path (scripts/ci/tests is not a package)."""
    path = TESTS_DIR / 'test_recapture_cert_3607_5038.py'
    spec = importlib.util.spec_from_file_location('recapture_5038_base', str(path))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


BASE = load_base_module()
RecaptureBase = BASE.RecaptureBase


class CertSandbox(RecaptureBase):
    """RecaptureBase plus per-cert helpers (no tests of its own)."""

    def run_cert(self, cert_id, **kwargs):
        return self.run_recapture(extra_args=('--cert', cert_id), **kwargs)

    def bundle(self, cert_id):
        return self.root / EVIDENCE_REL / CERTS[cert_id][0]

    def fixtures(self, cert_id):
        return self.root / '.local-runs' / (CERTS[cert_id][0] + '-fixtures')

    def reset_logs(self):
        for binary in (self.default_bin, self.sqlcipher_bin):
            log = Path(str(binary) + '.log')
            if log.exists():
                log.unlink()

    def stub_log(self, binary):
        log = Path(str(binary) + '.log')
        return log.read_text().splitlines() if log.is_file() else []


class PerCertBundle4829(CertSandbox):
    def test_each_cert_writes_its_own_bundle_and_fixtures(self):
        for cert_id, (bundle_dir, header_tail, _rev22) in sorted(CERTS.items()):
            with self.subTest(cert=cert_id):
                done, run_dates = self.run_cert(cert_id)
                self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
                bundle = self.bundle(cert_id)
                for name in BUNDLE_FILES:
                    self.assertTrue((bundle / name).is_file(), cert_id + ': ' + name)
                header = (bundle / 'posture-legs-exit-codes.txt').read_text().splitlines()[0]
                match = re.match(HEADER_PREFIX + header_tail, header)
                self.assertIsNotNone(match, header)
                self.assertIn(match.group(1), run_dates, header)
                self.assertEqual(match.group(2), self.sha)
                self.assertEqual(
                    re.findall(r'^exit: (\S+)$', (bundle / 'posture-legs-exit-codes.txt').read_text(), re.M),
                    ['2', '2', '1', '0'])
                self.assertTrue((self.fixtures(cert_id) / 'peer-attestation.json').is_file())
                bare = (bundle / 'posture-bare-env.out').read_text()
                self.assertIn('<repo-root>/.local-runs/' + bundle_dir + '-fixtures/keys', bare)
                self.assertNotIn(str(self.root), bare)
                self.assertFalse(list(bundle.glob('*.raw')))

    def test_other_certs_are_not_touched(self):
        done, _ = self.run_cert('92209ad91')
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        self.assertFalse((self.root / EVIDENCE_REL / 'cert-3607').exists())
        self.assertFalse((self.root / EVIDENCE_REL / 'cert-55').exists())

    def test_the_default_cert_is_still_3607(self):
        done, _ = self.run_recapture()
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        self.assertTrue((self.root / BASE.OUT_REL / 'posture-bare-env.out').is_file())

    def test_unknown_cert_is_refused_and_writes_nothing(self):
        done, _ = self.run_cert('no-such-cert')
        self.assertEqual(done.returncode, 2, done.stdout + done.stderr)
        self.assertIn('no-such-cert', done.stderr)
        self.assertFalse((self.root / EVIDENCE_REL).exists())
        self.assertFalse((self.root / '.local-runs').exists())

    def test_old_script_names_are_accepted_as_aliases(self):
        for alias, cert_id in (('9220', '92209ad91'), ('f32c', 'f32c18dad')):
            with self.subTest(alias=alias):
                done, _ = self.run_cert(alias)
                self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
                self.assertTrue((self.bundle(cert_id) / 'posture-bare-env.out').is_file())


class Fixtures4829(CertSandbox):
    """#4829: no FIX variable and no working-directory fallback."""

    def test_fixtures_land_under_the_repo_whatever_the_cwd_and_fix(self):
        for cert_id in sorted(CERTS):
            with self.subTest(cert=cert_id):
                foreign = self.home / ('cwd-' + cert_id)
                foreign.mkdir()
                bogus = self.home / ('bogus-fix-' + cert_id)
                done, _ = self.run_cert(cert_id, cwd=foreign, extra_env={'FIX': str(bogus)})
                self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
                self.assertTrue((self.fixtures(cert_id) / 'peer-attestation.json').is_file())
                self.assertTrue((self.bundle(cert_id) / 'posture-hardened-env.out').is_file())
                self.assertFalse((foreign / '.local-runs').exists(), 'fixtures leaked into the cwd')
                self.assertFalse(bogus.exists(), 'the FIX variable was honoured')

    def test_source_has_no_cwd_fallback_and_reads_no_fix_variable(self):
        source = (REPO / 'scripts' / SCRIPT_NAME).read_text()
        self.assertNotIn('Path.cwd', source)
        self.assertNotIn('os.getcwd', source)
        self.assertNotRegex(source, r'environ(\.get\(|\[)["\']FIX["\']')

    def test_the_four_shell_scripts_are_gone(self):
        for name in OLD_SCRIPT_NAMES:
            with self.subTest(script=name):
                self.assertFalse((REPO / 'scripts' / name).exists(), name)


class Generations4829(CertSandbox):
    """The 20-check cert (55) differs from the 22-check certs in steps and env."""

    def test_22_check_certs_run_keygen_synchronous_and_the_encrypted_store(self):
        for cert_id in sorted(c for c in CERTS if CERTS[c][2]):
            with self.subTest(cert=cert_id):
                self.reset_logs()
                done, _ = self.run_cert(cert_id)
                self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
                default_log = self.stub_log(self.default_bin)
                self.assertIn("ARGV ['rules', 'keygen']", default_log)
                self.assertTrue([x for x in default_log if x.startswith('ENVSEEN sync=FULL')])
                cipher_log = self.stub_log(self.sqlcipher_bin)
                self.assertTrue([x for x in cipher_log if x.startswith('ENVSEEN sync=FULL db=')
                                 and x.endswith('leg4-sqlcipher.db')], cipher_log)

    def test_the_20_check_cert_has_none_of_them(self):
        done, _ = self.run_cert('55')
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        default_log = self.stub_log(self.default_bin)
        self.assertNotIn("ARGV ['rules', 'keygen']", default_log)
        cipher_log = self.stub_log(self.sqlcipher_bin)
        for line in default_log + cipher_log:
            self.assertFalse(line.startswith('ENVSEEN sync=FULL'), line)
            self.assertFalse(line.startswith('PASSENV'), line)
        self.assertEqual(cipher_log[-1], 'ENVSEEN sync=- db=-')
        self.assertFalse((self.fixtures('55') / 'db-passphrase').exists())

    def test_the_22_check_certs_assert_the_ladder_and_the_20_check_cert_does_not(self):
        self.set_bypass()
        done, _ = self.run_cert('92209ad91')
        self.assertEqual(done.returncode, 1, done.stdout + done.stderr)
        self.assertIn('LADDER VIOLATED', done.stdout)
        done, _ = self.run_cert('55')
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        self.assertNotIn('LADDER', done.stdout)

    def set_bypass(self):
        for binary in (self.default_bin, self.sqlcipher_bin):
            Path(str(binary) + '.mode').write_text('bypass\n')


class Passphrase4829(CertSandbox):
    """The leg-4 passphrase reaches the child through its environment, never its argv."""

    def test_passphrase_is_on_no_argv_the_script_builds(self):
        for cert_id in sorted(c for c in CERTS if CERTS[c][2]):
            with self.subTest(cert=cert_id):
                self.reset_logs()
                done, _ = self.run_cert(cert_id)
                self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
                passphrase = (self.fixtures(cert_id) / 'db-passphrase').read_text().strip()
                self.assertEqual(len(passphrase), 64)
                cipher_log = self.stub_log(self.sqlcipher_bin)
                argv_lines = [x for x in cipher_log if x.startswith('ARGV ')]
                self.assertEqual(len(argv_lines), 2, cipher_log)  # the seed, then leg 4
                for line in argv_lines:
                    self.assertNotIn(passphrase, line)
                passenv = [x for x in cipher_log if x.startswith('PASSENV ')]
                self.assertEqual(passenv, ['PASSENV ' + passphrase] * 2)
                self.assertEqual(oct((self.fixtures(cert_id) / 'db-passphrase').stat().st_mode & 0o777),
                                 oct(0o600))
                self.assertNotIn(passphrase, ''.join(
                    p.read_text() for p in self.bundle(cert_id).iterdir() if p.is_file()))

    def test_an_empty_passphrase_file_exits_70_before_the_child_runs(self):
        fixtures = self.fixtures('92209ad91')
        fixtures.mkdir(parents=True)
        (fixtures / 'db-passphrase').write_text('')
        done, _ = self.run_cert('92209ad91')
        self.assertEqual(done.returncode, 70, done.stdout + done.stderr)
        self.assertEqual(self.stub_log(self.sqlcipher_bin), [])


class EvidenceCopy4829(CertSandbox):
    """The attested copy stays shell; only the issue-named fixes are applied."""

    def run_copy(self, cwd=None):
        target = self.root / EVIDENCE_COPY_REL
        target.parent.mkdir(parents=True)
        shutil.copy2(str(REPO / EVIDENCE_COPY_REL), str(target))
        env = {
            'PATH': os.environ.get('PATH', '/usr/bin:/bin'), 'HOME': str(self.home),
            'PYTHONPATH': str(self.pystubs), 'DEFAULT_BIN': str(self.default_bin),
            'SQLCIPHER_BIN': str(self.sqlcipher_bin),
        }
        return subprocess.run(['bash', str(target)], env=env, cwd=str(cwd or self.root),
                              capture_output=True, text=True)

    def test_copy_runs_in_place_from_the_repo_root(self):
        done = self.run_copy()
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        self.assertIn('exits e1=2 e2=2 e3=1 e4=0', done.stdout)
        self.assertTrue((self.root / '.local-runs' / 'cert-385da3a05-fixtures'
                         / 'peer-attestation.json').is_file())
        self.assertFalse((self.root / '.local-runs' / 'cert-3607-fixtures').exists())

    def test_copy_runs_in_place_from_any_directory(self):
        elsewhere = self.home / 'elsewhere'
        elsewhere.mkdir()
        done = self.run_copy(cwd=elsewhere)
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        self.assertFalse((elsewhere / '.local-runs').exists())

    def test_copy_exports_fix_and_has_no_cwd_fallback(self):
        text = (REPO / EVIDENCE_COPY_REL).read_text()
        self.assertRegex(text, r'(?m)^export FIX="\$ROOT/\.local-runs/cert-385da3a05-fixtures"$')
        self.assertIn('fix = Path(os.environ["FIX"])', text)
        self.assertNotIn('Path.cwd', text)

    def test_copy_puts_the_passphrase_on_no_env_argv_word(self):
        text = (REPO / EVIDENCE_COPY_REL).read_text()
        self.assertNotIn('AI_MEMORY_DB_PASSPHRASE="$(cat', text)
        self.assertIn('POSTURE_PASSFILE="$FIX/db-passphrase"', text)
        self.assertIn('|| exit 70', text)  # a failed read never runs the child with an empty secret


class Records4829(unittest.TestCase):
    """The amendments are recorded and every touched bundle still verifies."""

    def read(self, rel):
        return (REPO / rel).read_text()

    def test_citing_docs_name_the_ported_script(self):
        for rel, citations in sorted(CITING_DOCS.items()):
            text = self.read(rel)
            for old_name, cert_id in citations:
                with self.subTest(doc=rel, script=old_name):
                    for match in re.finditer(re.escape(old_name), text):
                        window = text[match.end():match.end() + 400]
                        self.assertIn(PORT_NOTE % cert_id, window.replace('\n', ' '))

    def test_manifests_verify_for_every_touched_bundle(self):
        for bundle in TOUCHED_BUNDLES:
            directory = REPO / EVIDENCE_REL / bundle
            lines = [x for x in (directory / 'MANIFEST.sha256').read_text().splitlines() if x.strip()]
            self.assertTrue(lines, bundle)
            for line in lines:
                digest, name = line.split('  ', 1)
                with self.subTest(bundle=bundle, file=name):
                    actual = hashlib.sha256((directory / name).read_bytes()).hexdigest()
                    self.assertEqual(actual, digest)

    def test_sanitization_row_records_the_amendment_and_what_was_compared(self):
        text = self.read('docs/compliance/evidence/cert-385da3a05/SANITIZATION.md')
        rows = [x for x in text.splitlines() if x.startswith('| `recapture-posture.sh`')]
        self.assertEqual(len(rows), 1)
        row = rows[0]
        for phrase in ('Amended 2026-10-17', '#4829', '#4830', '#4882', '#4886',
                       'is on no argv', 'FIX` is now exported', 'default build only',
                       'leg 4 needs a sqlcipher build', 'was not re-run',
                       'The script as captured is commit 126ba717e'):
            self.assertIn(phrase, row)
        self.assertNotIn('no number changed', row)

    def test_certification_doc_points_at_the_amendment(self):
        text = self.read('docs/compliance/ENTERPRISE-FEDERATION-CERTIFICATION.md')
        self.assertIn('The recapture script was amended after this issue', text)
        self.assertIn('`recapture-posture.sh` row of `cert-385da3a05/SANITIZATION.md`', text)


if __name__ == '__main__':
    unittest.main()
