#!/usr/bin/env python3
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""Tests for scripts/ci/tier_credential.py, the one non-echoing tier credential loader (#8187).

Covers #6172 (no credential on the argv of a child, libpq variables instead), #6180 (a group- or world-accessible
URL file is refused, naming path and mode and never the content), #6672 / #7971 (no output carries the URL, a URL
component or an exception text) and the ``github-env`` hand-off.  A fake ``psql`` records its argv and environment.
Stdlib only.
"""

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/ci/tier_credential.py"
PASSWORD = "q7Zr-Lm2_Xv9Kd4TgPw8Hn3Bs6Jc1Yf5AeUo0iRt"
USER = "tier_role_8187"
URL = f"postgres://{USER}:{PASSWORD}@10.9.8.7:5445/ai_memory_test?sslmode=verify-full&sslrootcert=/etc/ssl/tier-ca.pem"
FAKE_PSQL = """#!{python}
import json, os, sys
with open(os.environ["FAKE_OUT"], "w") as handle:
    json.dump({{"argv": sys.argv[1:], "env": dict(os.environ)}}, handle)
sys.exit(int(os.environ.get("FAKE_RC", "0")))
"""


class TierCredentialCase(unittest.TestCase):
    def setUp(self):
        scratch = ROOT / ".local-runs" / "tmp"
        scratch.mkdir(parents=True, exist_ok=True)
        self._dir = tempfile.TemporaryDirectory(dir=scratch, prefix="tiercred-8187-")
        self.addCleanup(self._dir.cleanup)
        self.dir = Path(self._dir.name)
        self.url_file = self.dir / "url"
        self.out = self.dir / "fake-out.json"
        self.github_env = self.dir / "github-env"
        bindir = self.dir / "bin"
        bindir.mkdir()
        psql = bindir / "psql"
        psql.write_text(FAKE_PSQL.format(python=sys.executable))
        psql.chmod(0o755)
        self.bindir = bindir

    def write_url(self, text=URL, mode=0o600, newline=True):
        self.url_file.unlink(missing_ok=True)
        self.url_file.write_text(text + ("\n" if newline else ""))
        self.url_file.chmod(mode)

    def env(self, **extra):
        base = {"PATH": f"{self.bindir}{os.pathsep}{os.environ.get('PATH', '')}", "FAKE_OUT": str(self.out),
                "GITHUB_ENV": str(self.github_env)}
        base.update(extra)
        return base

    def helper(self, *args, **extra):
        return subprocess.run([sys.executable, "-I", str(SCRIPT), *args], capture_output=True, text=True,
                              check=False, env=self.env(**extra))

    def run_psql(self, *tail, **extra):
        return self.helper("run", "--url-file", str(self.url_file), *tail, "--", "psql", "-v", "ON_ERROR_STOP=1",
                           "-c", "SELECT 1", **extra)

    def recorded(self):
        return json.loads(self.out.read_text())


class TestRunHandsOverThroughTheEnvironment(TierCredentialCase):
    def test_the_connection_reaches_the_child_as_libpq_variables_6172(self):
        self.write_url()
        r = self.run_psql()
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        seen = self.recorded()
        self.assertEqual(seen["argv"], ["-v", "ON_ERROR_STOP=1", "-c", "SELECT 1"])
        env = seen["env"]
        self.assertEqual({k: env[k] for k in ("PGHOST", "PGPORT", "PGUSER", "PGPASSWORD", "PGDATABASE", "PGSSLMODE",
                                              "PGSSLROOTCERT")},
                         {"PGHOST": "10.9.8.7", "PGPORT": "5445", "PGUSER": USER, "PGPASSWORD": PASSWORD,
                          "PGDATABASE": "ai_memory_test", "PGSSLMODE": "verify-full",
                          "PGSSLROOTCERT": "/etc/ssl/tier-ca.pem"})
        for arg in seen["argv"]:
            for secret in (PASSWORD, USER, "10.9.8.7", "postgres://"):
                self.assertNotIn(secret, arg, "no credential or URL part may reach the child argv")
        self.assertNotIn("AI_MEMORY_TEST_POSTGRES_URL", env, "the URL is exported only on request")

    def test_a_successful_run_prints_nothing(self):
        self.write_url()
        r = self.run_psql()
        self.assertEqual((r.stdout, r.stderr), ("", ""))

    def test_the_database_option_replaces_the_database_and_keeps_the_query(self):
        self.write_url()
        self.assertEqual(self.run_psql("--database", "ai_memory_test_ci_7_1_linux").returncode, 0)
        env = self.recorded()["env"]
        self.assertEqual((env["PGDATABASE"], env["PGSSLMODE"], env["PGPASSWORD"]),
                         ("ai_memory_test_ci_7_1_linux", "verify-full", PASSWORD))

    def test_export_url_sets_the_url_variable_for_the_child_only(self):
        self.write_url()
        self.assertEqual(self.run_psql("--database", "ai_memory_test_ci_9", "--export-url").returncode, 0)
        exported = self.recorded()["env"]["AI_MEMORY_TEST_POSTGRES_URL"]
        self.assertEqual(exported, URL.replace("/ai_memory_test?", "/ai_memory_test_ci_9?"))

    def test_inherited_libpq_variables_are_dropped(self):
        self.write_url()
        r = self.run_psql(PGSERVICE="evil", PGPASSFILE="/x", PGOPTIONS="-c x=1", PGHOSTADDR="1.2.3.4")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        env = self.recorded()["env"]
        for name in ("PGSERVICE", "PGPASSFILE", "PGOPTIONS", "PGHOSTADDR"):
            self.assertNotIn(name, env)

    def test_the_child_exit_status_passes_through(self):
        self.write_url()
        self.assertEqual(self.run_psql(FAKE_RC="3").returncode, 3)

    def test_a_missing_command_is_reported_by_class_only(self):
        self.write_url()
        r = self.helper("run", "--url-file", str(self.url_file), "--", "no-such-command-8187")
        self.assertEqual(r.returncode, 127)
        self.assertIn("cannot start the command (FileNotFoundError)", r.stderr)
        self.assertNotIn("no-such-command-8187", r.stderr)

    def test_a_multi_host_url_maps_to_host_and_port_lists(self):
        self.write_url(f"postgres://{USER}:{PASSWORD}@h1:5445,[::1]:5446,h3/db")
        self.assertEqual(self.run_psql().returncode, 0)
        env = self.recorded()["env"]
        self.assertEqual((env["PGHOST"], env["PGPORT"]), ("h1,::1,h3", "5445,5446,"))


class TestRefusals(TierCredentialCase):
    def assert_quiet_refusal(self, r, code, *must):
        out = r.stdout + r.stderr
        self.assertEqual(r.returncode, code, out)
        self.assertIn("::error::tier_credential:", out)
        for text in must:
            self.assertIn(text, out)
        for secret in (PASSWORD, USER, "10.9.8.7", "postgres://", "tier-ca"):
            self.assertNotIn(secret, out, "a refusal must never print the file text")
        self.assertFalse(self.out.exists(), "the child must not run after a refusal")

    def test_a_group_or_world_accessible_file_is_refused_6180(self):
        for mode in (0o644, 0o640, 0o604, 0o660, 0o666, 0o610, 0o601, 0o750):
            with self.subTest(mode=oct(mode)):
                self.write_url(mode=mode)
                self.assert_quiet_refusal(self.run_psql(), 3, str(self.url_file), format(mode, "04o"), "chmod 600")

    def test_an_owner_only_file_is_accepted_6180(self):
        for mode in (0o600, 0o400, 0o700):
            with self.subTest(mode=oct(mode)):
                self.write_url(mode=mode)
                self.assertEqual(self.run_psql().returncode, 0)
                self.out.unlink()

    def test_the_mode_is_checked_before_the_file_is_read(self):
        # a permissive file with unreadable content: the refusal is the mode, not the content
        self.write_url("not a url \xff", mode=0o644)
        self.assert_quiet_refusal(self.run_psql(), 3, "0644")

    def test_github_env_refuses_a_permissive_file_too_6180(self):
        self.write_url(mode=0o644)
        r = self.helper("github-env", "--url-file", str(self.url_file), "--database", "ai_memory_test_ci_1")
        self.assert_quiet_refusal(r, 3, "0644")
        self.assertFalse(self.github_env.exists())

    def test_a_directory_and_a_missing_file_are_refused_by_class_only(self):
        for path, name in ((self.dir, "IsADirectoryError"), (self.dir / "absent-8187", "FileNotFoundError")):
            with self.subTest(name=name):
                r = self.helper("run", "--url-file", str(path), "--", "psql")
                self.assert_quiet_refusal(r, 2, f"cannot read the tier URL file ({name})")
                self.assertNotIn("absent-8187", r.stderr)

    def test_a_malformed_or_unsupported_url_is_refused_without_its_text(self):
        cases = {
            "not a url": "something-else://u:" + PASSWORD + "@h/db",
            "two lines": URL + "\nsecond",
            "unknown query key": f"postgres://{USER}:{PASSWORD}@h:5445/db?evil_key=1",
            "no password": f"postgres://{USER}@h:5445/db",
            "unbalanced brackets": f"postgres://{USER}:{PASSWORD}@[::1:5445/db",
        }
        for name, text in cases.items():
            with self.subTest(case=name):
                self.write_url(text, newline=False)
                r = self.run_psql()
                self.assertEqual(r.returncode, 2, r.stdout + r.stderr)
                self.assertIn("::error::tier_credential:", r.stderr)
                for secret in (PASSWORD, USER, "evil_key", "something-else"):
                    self.assertNotIn(secret, r.stdout + r.stderr)

    def test_a_non_utf8_file_names_only_the_exception_class(self):
        self.url_file.write_bytes(b"postgres://u:ab\xffcd@h/db\n")
        self.url_file.chmod(0o600)
        r = self.run_psql()
        self.assertEqual(r.returncode, 2)
        self.assertIn("cannot read the tier URL file (UnicodeDecodeError)", r.stderr)
        for needle in ("0x", "xff", "position", "codec", "abcd", "postgres://"):
            self.assertNotIn(needle, r.stderr)

    def test_a_bad_database_name_is_refused(self):
        self.write_url()
        for name in ("Upper", "a-b", "a b", "", "x" * 64, 'a"; DROP DATABASE x; --'):
            with self.subTest(name=name[:12]):
                r = self.run_psql("--database", name)
                self.assertEqual(r.returncode, 2, r.stdout + r.stderr)
                self.assertFalse(self.out.exists())


class TestGithubEnv(TierCredentialCase):
    def test_the_url_for_the_database_is_appended_to_github_env_and_nothing_is_printed(self):
        self.write_url()
        self.github_env.write_text("EXISTING=1\n")
        r = self.helper("github-env", "--url-file", str(self.url_file), "--database", "ai_memory_test_ci_9")
        self.assertEqual((r.returncode, r.stdout, r.stderr), (0, "", ""))
        self.assertEqual(self.github_env.read_text(),
                         "EXISTING=1\nAI_MEMORY_TEST_POSTGRES_URL="
                         + URL.replace("/ai_memory_test?", "/ai_memory_test_ci_9?") + "\n")

    def test_a_missing_github_env_is_refused(self):
        self.write_url()
        env = {k: v for k, v in self.env().items() if k != "GITHUB_ENV"}
        r = subprocess.run([sys.executable, "-I", str(SCRIPT), "github-env", "--url-file", str(self.url_file),
                            "--database", "ai_memory_test_ci_9"], capture_output=True, text=True, check=False, env=env)
        self.assertEqual(r.returncode, 2, r.stdout + r.stderr)
        self.assertNotIn(PASSWORD, r.stdout + r.stderr)


class TestSource(unittest.TestCase):
    def test_no_shell_true_no_tmp_and_one_helper(self):
        source = SCRIPT.read_text(encoding="utf-8")
        self.assertNotIn("shell=True", source)
        self.assertNotIn("/tmp", source)
        self.assertTrue(source.startswith("#!/usr/bin/env python3"))
        self.assertEqual(sorted(p.name for p in (ROOT / "scripts/ci").glob("tier_cred*")), ["tier_credential.py"])

    def test_no_message_is_built_from_exception_text_or_a_credential_variable(self):
        source = SCRIPT.read_text(encoding="utf-8")
        for needle in ("{exc}", "{password}", "{url}", "%r"):
            self.assertNotIn(needle, source)
        self.assertEqual(source.count("str(exc)"), 1, "only the fixed-sentence refusal is reported")
        self.assertEqual(source.count("type(exc).__name__"), 1, "class names come from the one fixed list")


if __name__ == "__main__":
    sys.exit(unittest.main())
