#!/usr/bin/env python3
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""Offline packaging contracts and real installer fault injection (#4077–#4084)."""
from contextlib import ExitStack
import hashlib
import io
import os
from pathlib import Path
import shlex
import subprocess
import tarfile
import tempfile
import unittest

ROOT = Path(__file__).resolve().parent.parent


class PackagingContract(unittest.TestCase):
    def test_plan_c_upgrade_keeps_volumes(self):
        text = (ROOT / 'infra/plan-c/docker-compose.yml').read_text()
        section = text.split('# Operator recreate', 1)[1].split('\n\n', 1)[0]
        recipe = '\n'.join(line for line in section.splitlines() if line.startswith('#   docker '))
        self.assertNotIn('down -v', recipe, 'upgrade must preserve signing keys, audit and TLS')
        self.assertNotIn('--volumes', recipe)
        self.assertIn('up -d --build', recipe)

    def test_plan_c_runbook_never_recommends_volume_deletion(self):
        text = (ROOT / 'docs/plan-c-deployment.md').read_text()
        section = text.split('## Routine recreate', 1)[1].split('\n## ', 1)[0]
        fences = []
        inside = False
        for line in section.splitlines():
            if line.startswith('```'):
                inside = not inside
            elif inside:
                fences.append(line)
        recipe = '\n'.join(fences)
        self.assertNotIn('down -v', recipe)
        self.assertNotIn('--volumes', recipe)
        self.assertIn('up -d --build --force-recreate', recipe)
        self.assertIn('NEW random keypair', section, 'the runbook must say why')

    def test_backup_unit_comment_does_not_claim_migration(self):
        unit = (ROOT / 'packaging/systemd/ai-memory-backup.service').read_text()
        self.assertIn('never migrates', unit)

    def test_companions_use_main_database(self):
        main = (ROOT / 'packaging/systemd/ai-memory.service').read_text().splitlines()
        database = next(line for line in main if line.startswith('Environment=AI_MEMORY_DB='))
        working = next(line for line in main if line.startswith('WorkingDirectory='))
        state_dir = working.split('=', 1)[1]
        for name in ('backup', 'sync', 'curator'):
            with self.subTest(unit=name):
                text = (ROOT / f'packaging/systemd/ai-memory-{name}.service').read_text()
                self.assertIn(database, text.splitlines())
                self.assertIn(working, text.splitlines())
        backup = (ROOT / 'packaging/systemd/ai-memory-backup.service').read_text()
        self.assertIn('ReadWritePaths=' + state_dir, backup.splitlines())
        self.assertNotIn('ReadOnlyPaths=' + database.split('=', 2)[2], backup.splitlines())

    # #4401 — the primary unit's sandbox is the reference; every shipped
    # companion unit carries the same hardening directives, line for line.
    # systemd is not available where this runs (no `systemd-analyze verify`),
    # so the parsed unit text is the evidence.
    HARDENING_DIRECTIVES = (
        'NoNewPrivileges', 'ProtectSystem', 'ProtectHome', 'PrivateTmp',
        'PrivateDevices', 'ProtectKernelTunables', 'ProtectKernelModules',
        'ProtectKernelLogs', 'ProtectControlGroups', 'ProtectHostname',
        'ProtectClock', 'ProtectProc', 'RestrictAddressFamilies',
        'RestrictNamespaces', 'RestrictRealtime', 'RestrictSUIDSGID',
        'LockPersonality', 'MemoryDenyWriteExecute', 'SystemCallArchitectures',
        'SystemCallFilter', 'CapabilityBoundingSet', 'AmbientCapabilities',
    )
    COMPANION_UNITS = ('backup', 'sync', 'curator')

    @staticmethod
    def _unit_lines(name):
        return (ROOT / f'packaging/systemd/{name}.service').read_text().splitlines()

    def test_companion_units_share_the_primary_hardening_set(self):
        main = self._unit_lines('ai-memory')
        reference = [line for line in main if line.split('=', 1)[0] in self.HARDENING_DIRECTIVES]
        self.assertEqual(len({line.split('=', 1)[0] for line in reference}),
                         len(self.HARDENING_DIRECTIVES),
                         'the primary unit must set every directive this test mirrors')
        for name in self.COMPANION_UNITS:
            with self.subTest(unit=name):
                lines = self._unit_lines(f'ai-memory-{name}')
                missing = [line for line in reference if line not in lines]
                self.assertEqual(missing, [], f'ai-memory-{name}.service lacks hardening lines')

    def test_backup_unit_cannot_write_the_key_store(self):
        # #4325 — under ProtectSystem=strict the service user's HOME is the
        # state dir, so `ReadWritePaths=<state_dir>` (needed for the WAL/SHM
        # sidecars, #3522) also exposed `<state_dir>/.config` — the operator
        # signing key and the local TLS CA — to the hourly backup job. The
        # backup only READS the signing key; the nested read-only grant wins
        # over the enclosing read-write one (deeper paths are applied later).
        main = self._unit_lines('ai-memory')
        working = next(line for line in main if line.startswith('WorkingDirectory='))
        state_dir = working.split('=', 1)[1]
        backup = self._unit_lines('ai-memory-backup')
        self.assertIn(f'ReadOnlyPaths=-{state_dir}/.config', backup,
                      'the backup unit must grant the key store read-only')
        # #6230 — the `-` lets hosts without the directory still run, so the
        # manual install recipe must create `.config` as the unit's own User=
        # (never root) before the backup timer is enabled.
        owner = next(line for line in backup if line.startswith('User=')).split('=', 1)[1]
        readme = (ROOT / 'packaging/systemd/README.md').read_text()
        recipe = f'sudo install -d -o {owner} -g {owner} -m 0700 {state_dir}/.config'
        self.assertIn(recipe, readme, 'README must create the key-store parent as the service user')
        self.assertLess(readme.index(recipe), readme.index('systemctl enable --now ai-memory-backup.timer'),
                        'the key-store parent must exist before the backup timer is enabled')

    def test_companions_restart_with_the_primary(self):
        # #4326 — curator and sync open the live database through the
        # migrating `db::open`. After an in-place binary replacement the
        # daemon keeps running the old binary; a companion that restarts
        # first (crash, OOM, `systemctl restart` of only that unit) would run
        # the NEW migration ladder on the live primary under the OLDER
        # daemon — the schema-ahead state #2445 refuses. PartOf= makes a
        # restart of the primary propagate, and the README tells the operator
        # that replacing the binary means restarting the primary first.
        for name in ('curator', 'sync'):
            with self.subTest(unit=name):
                lines = self._unit_lines(f'ai-memory-{name}')
                self.assertIn('PartOf=ai-memory.service', lines)
                self.assertLess(lines.index('PartOf=ai-memory.service'), lines.index('[Service]'),
                                'PartOf= belongs to the [Unit] section')
        readme = (ROOT / 'packaging/systemd/README.md').read_text()
        self.assertIn('## Upgrading the binary', readme)
        self.assertIn('systemctl restart ai-memory.service', readme)

    # Optional directories: absent on a fresh host, so the `-` form must be used
    # or the unit fails to start. Mandatory paths (the database file, #4325
    # step 2 / #6203) must NOT carry `-`: a missing database has to fail the
    # unit, not be skipped silently.
    OPTIONAL_READ_ONLY_DIRECTORIES = ('/etc/ai-memory', '/var/lib/ai-memory/.config')
    MANDATORY_READ_ONLY_PATHS = ('/var/lib/ai-memory/ai-memory.db',)

    def test_read_only_paths_mark_optional_directories(self):
        for name in ('ai-memory',) + tuple(f'ai-memory-{n}' for n in self.COMPANION_UNITS):
            with self.subTest(unit=name):
                for line in self._unit_lines(name):
                    if not line.startswith('ReadOnlyPaths='):
                        continue
                    for token in line.split('=', 1)[1].split():
                        bare = token.lstrip('-')
                        if bare in self.OPTIONAL_READ_ONLY_DIRECTORIES:
                            self.assertTrue(token.startswith('-'),
                                            f'{name}.service: optional {token!r} lacks the - prefix')
                        elif bare in self.MANDATORY_READ_ONLY_PATHS:
                            self.assertFalse(token.startswith('-'),
                                             f'{name}.service: mandatory {token!r} must not carry -')
                        else:
                            self.fail(f'{name}.service: ReadOnlyPaths entry {token!r} is not classified '
                                      'as optional or mandatory in this test')

    def test_binary_only_package_documentation(self):
        payload = (ROOT / 'nfpm.yaml').read_text()
        readme = (ROOT / 'packaging/systemd/README.md').read_text()
        if '/systemd/system/' not in payload:
            self.assertNotIn('Shipped by the Debian', readme)
            self.assertNotIn('Distro packages install', readme)
            self.assertIn('binary-only', readme)


class InstallerUpgrade(unittest.TestCase):
    def run_upgrade(self, mode):
        with tempfile.TemporaryDirectory(prefix='install-upgrade-') as scratch, ExitStack() as processes:
            root = Path(scratch)
            stubs = root / 'stubs'
            dest = root / 'installed'
            stubs.mkdir()
            dest.mkdir()
            old = b'#!/bin/sh\necho old-working-binary\n'
            installed = dest / 'ai-memory'
            installed.write_bytes(old)
            installed.chmod(0o755)
            if mode == 'running':
                # A native fixture also covers Linux ETXTBSY behavior. Compile
                # locally: copied macOS system binaries can be killed by AMFI.
                native = ('#include <stdio.h>\nint main(void) { '
                          'puts("old-working-binary"); fflush(stdout); '
                          'if (getchar() == EOF) return 1; '
                          'puts("old-still-running"); return 0; }\n')
                subprocess.run(['cc', '-x', 'c', '-', '-o', str(installed)],
                               input=native, text=True, check=True, capture_output=True)
                old = installed.read_bytes()
            payload = (b'#!/no/such/loader\n' if mode == 'bad-loader' else
                       b'#!/bin/sh\n[ "$1" = "--version" ] || exit 42\necho ai-memory-new\n')
            asset = root / 'release.tar.gz'
            with tarfile.open(asset, 'w:gz') as archive:
                member = tarfile.TarInfo('ai-memory')
                member.size = len(payload)
                member.mode = 0o755
                archive.addfile(member, io.BytesIO(payload))
            digest = hashlib.sha256(asset.read_bytes()).hexdigest()
            checksum = root / 'release.sha256'
            checksum.write_text(digest + '\n')
            (stubs / 'curl').write_text(
                '#!/bin/sh\nurl=\noutput=\nwhile [ "$#" -gt 0 ]; do\n'
                'case "$1" in -o) shift; output=$1;; https:*) url=$1;; esac\nshift\ndone\n'
                f'case "$url" in *.sha256) /bin/cp {shlex.quote(str(checksum))} "$output";;\n'
                f'*) /bin/cp {shlex.quote(str(asset))} "$output";; esac\n')
            if mode == 'dir-target':
                installed.unlink()
                installed.mkdir()
            if mode == 'copy-failure':
                (stubs / 'cp').write_text(
                    '#!/bin/sh\nfor arg do dest=$arg; done\n'
                    'printf partial > "$dest"\necho "injected ENOSPC after first write" >&2\nexit 1\n')
            for stub in stubs.iterdir():
                stub.chmod(0o755)
            env = dict(os.environ, PATH=str(stubs) + os.pathsep + os.environ['PATH'])
            running = None
            if mode == 'running':
                running = processes.enter_context(subprocess.Popen(
                    [str(installed)], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True))
                self.assertEqual(running.stdout.readline().strip(), 'old-working-binary')
            result = subprocess.run(['sh', str(ROOT / 'install.sh'), '--version', 'v-test',
                                     '--dir', str(dest)], env=env, text=True, capture_output=True, timeout=120)
            output = result.stdout + result.stderr
            if running:
                remaining, _ = running.communicate('old-still-running\n', timeout=5)
                self.assertEqual(running.returncode, 0)
                self.assertIn('old-still-running', remaining)
            if mode == 'dir-target':
                self.assertNotEqual(result.returncode, 0, output)
                self.assertTrue(installed.is_dir())
                self.assertEqual(list(installed.iterdir()), [], 'candidate moved into the directory')
                self.assertEqual(sorted(p.name for p in dest.iterdir()), ['ai-memory'], 'staging leak')
                return
            if mode in ('copy-failure', 'bad-loader'):
                self.assertNotEqual(result.returncode, 0, output)
                self.assertEqual(installed.read_bytes(), old, 'failed upgrade destroyed old executable\n' + output)
                self.assertNotIn('Installed successfully', output)
            else:
                self.assertEqual(result.returncode, 0, output)
                self.assertEqual(installed.read_bytes(), payload)
            self.assertEqual(sorted(p.name for p in dest.iterdir()), ['ai-memory'], 'staging leak')

    def test_partial_copy_preserves_old_binary(self):
        self.run_upgrade('copy-failure')

    def test_loader_failure_preserves_old_binary(self):
        self.run_upgrade('bad-loader')

    def test_directory_at_target_is_refused(self):
        self.run_upgrade('dir-target')

    def test_running_old_process_survives_upgrade(self):
        self.run_upgrade('running')

    def test_valid_binary_installs_without_database(self):
        self.run_upgrade('success')


if __name__ == '__main__':
    unittest.main(verbosity=2)
