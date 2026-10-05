#!/usr/bin/env python3
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""Run the real scripts/postgres-droplet-reinit.sh against stubbed binaries.

The stubs (ssh, psql, pg_dump, sudo and the ai-memory binary) are small Python
programs placed first on PATH. Each one appends its argv, plus a few booleans
about its environment, to a JSON-lines call log, so a case can assert the order
of the steps (no DROP before a refusal) and that the database password never
reaches any argv. The stub ssh runs its remote command with bash -c in a clean
environment, so the remote side sees only what the script sends over stdin.

Cases:
  #5143  the dry-run store URL pins sslmode=verify-full and sslrootcert, and
         the password is printed 0 times;
  #5402  the live pg_dump carries sslmode=verify-full and the CA in its
         connection string and in PGSSLMODE/PGSSLROOTCERT, with PGSERVICE
         unset; a missing CA file is refused (exit 7) before any pg_dump;
  #5600  with AI_MEMORY_SSH_HOST set, a verify-full psql connection from the
         remote host, with the same host, port, user, database and CA path
         schema-init uses, must succeed before the backup and the DROP; a
         failing probe exits 7 with no pg_dump and no DROP. The stub psql
         stands in for libpq: the case proves the order and the arguments,
         not real TLS verification.

Scratch lives under <repo>/.local-runs (the repository forbids /tmp).
"""

import json
import os
from pathlib import Path
import secrets
import shutil
import stat
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/postgres-droplet-reinit.sh"

STUB_COMMON = r'''#!/usr/bin/env python3
import json, os, sys
def log(rec):
    rec["argv0"] = os.path.basename(sys.argv[0])
    rec["argv"] = sys.argv[1:]
    with open(os.environ["STUB_LOG"], "a", encoding="utf-8") as fh:
        fh.write(json.dumps(rec) + "\n")
'''

STUBS = {
    "ssh": STUB_COMMON + r'''
import subprocess
log({})
args = sys.argv[1:]
remote = args[-1]
env = {
    "PATH": os.environ["STUB_BIN"] + ":/usr/bin:/bin",
    "STUB_LOG": os.environ["STUB_LOG"],
    "STUB_BIN": os.environ["STUB_BIN"],
    "STUB_PW_FILE": os.environ["STUB_PW_FILE"],
    "STUB_PSQL_RC": os.environ.get("STUB_PSQL_RC", "0"),
}
sys.exit(subprocess.run(["bash", "-c", remote], env=env).returncode)
''',
    "psql": STUB_COMMON + r'''
with open(os.environ["STUB_PW_FILE"], encoding="utf-8") as fh:
    pw = fh.read().strip()
log({
    "pgpassword_ok": os.environ.get("PGPASSWORD") == pw,
    "pgsslmode": os.environ.get("PGSSLMODE"),
    "pgsslrootcert": os.environ.get("PGSSLROOTCERT"),
    "pgservice": "PGSERVICE" in os.environ or "PGSERVICEFILE" in os.environ,
})
sys.exit(int(os.environ.get("STUB_PSQL_RC", "0")))
''',
    "pg_dump": STUB_COMMON + r'''
log({
    "pgsslmode": os.environ.get("PGSSLMODE"),
    "pgsslrootcert": os.environ.get("PGSSLROOTCERT"),
    "pgservice": "PGSERVICE" in os.environ or "PGSERVICEFILE" in os.environ,
})
out = sys.argv[sys.argv.index("-f") + 1]
with open(out, "w", encoding="utf-8") as fh:
    fh.write("stub dump\n")
''',
    "sudo": STUB_COMMON + r'''
log({})
''',
    "ai-memory": STUB_COMMON + r'''
log({"store_url_env": "AI_MEMORY_STORE_URL" in os.environ})
print("{}")
''',
}


class ReinitHarness(unittest.TestCase):
    def setUp(self):
        local_runs = ROOT / ".local-runs"
        local_runs.mkdir(exist_ok=True)
        self.dir = Path(tempfile.mkdtemp(prefix="reinit-test-", dir=str(local_runs)))
        self.addCleanup(shutil.rmtree, str(self.dir), True)
        self.bin = self.dir / "bin"
        self.bin.mkdir()
        for name, body in STUBS.items():
            path = self.bin / name
            path.write_text(body, encoding="utf-8")
            path.chmod(path.stat().st_mode | stat.S_IXUSR)
        self.password = "pw-" + secrets.token_hex(8)
        self.pw_file = self.dir / "pw.txt"
        self.pw_file.write_text(self.password + "\n", encoding="utf-8")
        self.pw_file.chmod(0o600)
        self.ca = self.dir / "ca.pem"
        self.ca.write_text("stub CA\n", encoding="utf-8")
        self.log = self.dir / "calls.jsonl"
        self.backups = self.dir / "backups"

    def run_script(self, args, **extra):
        env = {
            "PATH": str(self.bin) + ":/usr/bin:/bin",
            "HOME": str(self.dir),
            "STUB_LOG": str(self.log),
            "STUB_BIN": str(self.bin),
            "STUB_PW_FILE": str(self.pw_file),
            "PG_HOST": "db.example.invalid",
            "PG_PASSWORD_FILE": str(self.pw_file),
            "PG_SSLROOTCERT": str(self.ca),
            "BACKUP_DIR": str(self.backups),
            "SCHEMA_INIT_JSON": str(self.dir / "schema-init.json"),
            "AI_MEMORY_BIN": str(self.bin / "ai-memory"),
        }
        env.update(extra)
        proc = subprocess.run(
            ["bash", str(SCRIPT)] + list(args),
            env=env,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=60,
        )
        return proc

    def calls(self):
        if not self.log.exists():
            return []
        return [json.loads(line) for line in self.log.read_text(encoding="utf-8").splitlines()]

    def drops(self):
        return [c for c in self.calls() if c["argv0"] == "sudo" and any("DROP DATABASE" in a for a in c["argv"])]

    def assert_password_off_argv(self, proc):
        for call in self.calls():
            for arg in call["argv"]:
                self.assertNotIn(self.password, arg, "password on the argv of " + call["argv0"])
        self.assertNotIn(self.password, proc.stdout)
        self.assertNotIn(self.password, proc.stderr)


class TestReinitDryRunUrl5143(ReinitHarness):
    def test_dry_run_store_url_pins_verify_full_and_hides_password_5143(self):
        proc = self.run_script(["--dry-run", "--skip-disposable"])
        self.assertEqual(proc.returncode, 0, proc.stderr)
        lines = [l for l in proc.stdout.splitlines() if "DRY-RUN: schema-init --json for aimemory" in l]
        self.assertEqual(len(lines), 1, proc.stdout)
        line = lines[0]
        self.assertIn("?sslmode=verify-full&sslrootcert=" + str(self.ca) + ")", line)
        self.assertIn("postgres://aimemory:***@db.example.invalid:5432/aimemory?", line)
        self.assertEqual((proc.stdout + proc.stderr).count(self.password), 0)
        self.assertEqual(self.calls(), [], "a dry run must call no binary")

    def test_dry_run_disposable_urls_pin_verify_full_5143(self):
        proc = self.run_script(["--dry-run"])
        self.assertEqual(proc.returncode, 0, proc.stderr)
        lines = [l for l in proc.stdout.splitlines() if "DRY-RUN: schema-init --json for " in l]
        self.assertEqual(len(lines), 9, proc.stdout)
        for line in lines:
            self.assertIn("sslmode=verify-full&sslrootcert=" + str(self.ca), line)
            self.assertIn(":***@", line)
        self.assertEqual((proc.stdout + proc.stderr).count(self.password), 0)


class TestReinitPgDump5402(ReinitHarness):
    def test_live_pg_dump_pins_verify_full_and_ca_5402(self):
        proc = self.run_script(["--yes", "--skip-disposable"], PGSERVICE="evil", PGSERVICEFILE="/nonexistent")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        dumps = [c for c in self.calls() if c["argv0"] == "pg_dump"]
        self.assertEqual(len(dumps), 1)
        dump = dumps[0]
        conninfo = dump["argv"][dump["argv"].index("-d") + 1]
        self.assertIn("sslmode=verify-full", conninfo)
        self.assertIn("sslrootcert=" + str(self.ca), conninfo)
        self.assertEqual(dump["pgsslmode"], "verify-full")
        self.assertEqual(dump["pgsslrootcert"], str(self.ca))
        self.assertFalse(dump["pgservice"], "PGSERVICE/PGSERVICEFILE must be unset for pg_dump")
        names = [c["argv0"] for c in self.calls()]
        self.assertLess(names.index("pg_dump"), names.index("sudo"), "backup before the DROP")
        self.assert_password_off_argv(proc)

    def test_missing_ca_file_refused_before_pg_dump_5402(self):
        proc = self.run_script(["--yes", "--skip-disposable"], PG_SSLROOTCERT=str(self.dir / "missing-ca.pem"))
        self.assertEqual(proc.returncode, 7, proc.stderr)
        self.assertEqual(self.calls(), [], "no pg_dump, no DROP after a refusal")

    def test_missing_dump_ca_file_refused_before_pg_dump_5402(self):
        proc = self.run_script(
            ["--yes", "--skip-disposable"],
            AI_MEMORY_SSH_HOST="h1",
            PG_DUMP_SSLROOTCERT=str(self.dir / "missing-ca.pem"),
        )
        self.assertEqual(proc.returncode, 7, proc.stderr)
        names = [c["argv0"] for c in self.calls()]
        self.assertNotIn("pg_dump", names)
        self.assertEqual(self.drops(), [])


class TestReinitSshProbe5600(ReinitHarness):
    def ssh_env(self, **extra):
        env = {"AI_MEMORY_SSH_HOST": "h1", "PG_DUMP_SSLROOTCERT": str(self.ca)}
        env.update(extra)
        return env

    def test_failing_remote_verify_full_probe_refuses_before_drop_5600(self):
        proc = self.run_script(["--yes", "--skip-disposable"], **self.ssh_env(STUB_PSQL_RC="2"))
        self.assertEqual(proc.returncode, 7, proc.stdout + proc.stderr)
        self.assertEqual(self.drops(), [], "no DROP after a failed verify-full probe")
        names = [c["argv0"] for c in self.calls()]
        self.assertNotIn("pg_dump", names)
        self.assertNotIn("ai-memory", names)
        self.assert_password_off_argv(proc)

    def test_remote_probe_is_verify_full_with_the_schema_init_ca_5600(self):
        proc = self.run_script(["--yes", "--skip-disposable"], **self.ssh_env())
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        calls = self.calls()
        probes = [c for c in calls if c["argv0"] == "psql"]
        self.assertEqual(len(probes), 1, calls)
        probe = probes[0]
        conninfo = " ".join(probe["argv"])
        self.assertIn("sslmode=verify-full", conninfo)
        self.assertIn("sslrootcert=" + str(self.ca), conninfo)
        self.assertIn("host='db.example.invalid'", conninfo)
        self.assertIn("user='aimemory'", conninfo)
        self.assertIn("dbname=aimemory", conninfo)
        self.assertIn("port=5432", conninfo)
        self.assertEqual(probe["pgsslmode"], "verify-full")
        self.assertEqual(probe["pgsslrootcert"], str(self.ca))
        self.assertFalse(probe["pgservice"])
        self.assertTrue(probe["pgpassword_ok"], "the probe reads the password from ssh stdin")
        names = [c["argv0"] for c in calls]
        self.assertLess(names.index("psql"), names.index("pg_dump"), "probe before the backup")
        self.assertLess(names.index("pg_dump"), names.index("sudo"), "backup before the DROP")
        self.assert_password_off_argv(proc)

    def test_dry_run_runs_no_remote_probe_5600(self):
        proc = self.run_script(["--dry-run", "--skip-disposable"], **self.ssh_env())
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(self.calls(), [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
