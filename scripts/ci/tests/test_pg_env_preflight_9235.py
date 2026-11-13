# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""Pin scripts/ci/pg_env_preflight.py (#9235).

Invariant: a hosted-runner PostgreSQL that cannot load plpgsql.so (or cannot
create the vector / age extensions, or is unreachable, or has no psql) fails
the preflight with a non-zero exit and EXACTLY ONE class line
``::error::[coverage-pg] PG-ENV <reason>`` whose reason text is asserted
verbatim; a healthy server exits 0 and prints no class line.
"""

import contextlib
import importlib.util
import io
import subprocess
import sys
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "pg_env_preflight.py"
SPEC = importlib.util.spec_from_file_location("pg_env_preflight", SCRIPT)
PRE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = PRE
SPEC.loader.exec_module(PRE)

PLPGSQL_STDERR = (
    'ERROR:  could not load library "/usr/lib/postgresql/16/lib/plpgsql.so": '
    "undefined symbol: heap_datum_update_type\n"
)
CLASS_PREFIX = "::error::[coverage-pg] PG-ENV "
SERVER_VERSION = "16.16 (Debian 16.16-1.pgdg13+1)"
IMAGE_VERSION = "20261111.196.1"
PKG_OUT = "postgresql-16 16.16-1.pgdg13+1\npostgresql-16-pgvector 0.8.7-1.pgdg13+2\n"
SECRET = "s3cr3t-pw-do-not-print"


def done(returncode=0, stdout="", stderr=""):
    return subprocess.CompletedProcess([], returncode, stdout, stderr)


class FakeRunner:
    """Fake psql/docker: `failing` maps a SQL needle to the stderr it returns."""

    def __init__(self, failing=None, missing_psql=False, restart_rc=0, dpkg_rc=0, connect_fails=0):
        self.failing = failing or {}
        self.missing_psql = missing_psql
        self.restart_rc = restart_rc
        self.dpkg_rc = dpkg_rc
        self.connect_fails = connect_fails
        self.calls = []

    def __call__(self, argv):
        self.calls.append(list(argv))
        if argv[0] == "docker" and argv[1] == "restart":
            return done(self.restart_rc)
        if "dpkg-query" in argv:
            return done(self.dpkg_rc, PKG_OUT if self.dpkg_rc == 0 else "")
        if self.missing_psql:
            raise FileNotFoundError(argv[0])
        sql = argv[-1]
        if sql == PRE.SQL_CONNECT:
            if self.connect_fails > 0:
                self.connect_fails -= 1
                return done(2, "", "connection refused")
            return done(0, SERVER_VERSION + "\n")
        for needle, stderr in self.failing.items():
            if needle in sql:
                return done(1, "", stderr)
        return done(0)


def run_main(argv, runner, env=None):
    out = io.StringIO()
    sleeps = []
    with contextlib.redirect_stdout(out):
        rc = PRE.main(argv, runner=runner, sleep=sleeps.append)
    return rc, out.getvalue(), sleeps


def class_lines(text):
    return [ln for ln in text.splitlines() if "PG-ENV" in ln]


class PreflightTests(unittest.TestCase):
    def test_success_exits_zero_with_no_class_line(self):
        runner = FakeRunner()
        rc, out, _ = run_main([], runner)
        self.assertEqual(rc, 0)
        self.assertEqual(class_lines(out), [])
        self.assertIn(f"server_version={SERVER_VERSION}", out)
        for name in ("plpgsql", "vector", "age"):
            self.assertIn(f"probe {name}: ok", out)

    def test_plpgsql_failure_exact_reason_and_single_class_line(self):
        runner = FakeRunner(failing={"LANGUAGE plpgsql": PLPGSQL_STDERR})
        rc, out, _ = run_main([], runner)
        self.assertEqual(rc, 3)
        self.assertEqual(
            class_lines(out),
            [CLASS_PREFIX + "plpgsql.so cannot load (server binary and library packages do not match)"],
        )
        self.assertIn("undefined symbol: heap_datum_update_type", out)

    def test_plpgsql_failure_stops_before_extension_probes(self):
        runner = FakeRunner(failing={"LANGUAGE plpgsql": PLPGSQL_STDERR})
        run_main([], runner)
        sqls = [c[-1] for c in runner.calls if c[0] == "psql"]
        self.assertNotIn(PRE.SQL_VECTOR, sqls)
        self.assertNotIn(PRE.SQL_AGE, sqls)

    def test_vector_failure_has_its_own_reason(self):
        runner = FakeRunner(failing={"EXTENSION IF NOT EXISTS vector": "ERROR: no vector.control"})
        rc, out, _ = run_main([], runner)
        self.assertEqual(rc, 3)
        self.assertEqual(class_lines(out), [CLASS_PREFIX + "CREATE EXTENSION vector failed"])

    def test_age_failure_has_its_own_reason(self):
        runner = FakeRunner(failing={"EXTENSION IF NOT EXISTS age": "ERROR: no age.control"})
        rc, out, _ = run_main([], runner)
        self.assertEqual(rc, 3)
        self.assertEqual(class_lines(out), [CLASS_PREFIX + "CREATE EXTENSION age failed"])

    def test_psql_missing_emits_class_line(self):
        rc, out, _ = run_main([], FakeRunner(missing_psql=True))
        self.assertEqual(rc, 3)
        self.assertEqual(class_lines(out), [CLASS_PREFIX + "psql not found on the runner"])

    def test_psql_missing_real_subprocess(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            rc = PRE.main(["--psql", "/nonexistent-dir-9235/psql"])
        self.assertEqual(rc, 3)
        self.assertEqual(class_lines(out.getvalue()), [CLASS_PREFIX + "psql not found on the runner"])

    def test_unreachable_server_reason(self):
        rc, out, _ = run_main([], FakeRunner(connect_fails=99))
        self.assertEqual(rc, 3)
        self.assertEqual(class_lines(out), [CLASS_PREFIX + "postgres server unreachable"])

    def test_timeout_is_a_failure_not_a_pass(self):
        def runner(argv):
            raise subprocess.TimeoutExpired(argv, 1)

        rc, out, _ = run_main([], runner)
        self.assertEqual(rc, 3)
        self.assertEqual(class_lines(out), [CLASS_PREFIX + "postgres server unreachable"])

    def test_restart_waits_then_passes(self):
        runner = FakeRunner(connect_fails=3)
        rc, out, sleeps = run_main(["--container", "pg-age", "--restart"], runner)
        self.assertEqual(rc, 0)
        self.assertEqual(class_lines(out), [])
        self.assertEqual(sleeps, [PRE.WAIT_INTERVAL_SECS] * 3)
        self.assertEqual(runner.calls[1], ["docker", "restart", "pg-age"])

    def test_restart_wait_is_bounded(self):
        runner = FakeRunner(connect_fails=10**6)
        rc, out, sleeps = run_main(
            ["--container", "pg-age", "--restart", "--wait-seconds", "10"], runner
        )
        self.assertEqual(rc, 3)
        self.assertEqual(class_lines(out), [CLASS_PREFIX + "postgres server unreachable"])
        self.assertEqual(len(sleeps), 4)

    def test_restart_failure_reason(self):
        rc, out, _ = run_main(["--container", "pg-age", "--restart"], FakeRunner(restart_rc=1))
        self.assertEqual(rc, 3)
        self.assertEqual(class_lines(out), [CLASS_PREFIX + "postgres container restart failed"])

    def test_restart_without_container_is_a_failure(self):
        rc, out, _ = run_main(["--restart"], FakeRunner())
        self.assertEqual(rc, 3)
        self.assertEqual(class_lines(out), [CLASS_PREFIX + "postgres container restart failed"])

    def test_prints_image_version_and_package_versions(self):
        import os

        old = os.environ.get("ImageVersion")
        os.environ["ImageVersion"] = IMAGE_VERSION
        try:
            rc, out, _ = run_main(["--container", "pg-age"], FakeRunner())
        finally:
            if old is None:
                del os.environ["ImageVersion"]
            else:
                os.environ["ImageVersion"] = old
        self.assertEqual(rc, 0)
        self.assertIn(f"runner ImageVersion={IMAGE_VERSION}", out)
        self.assertIn("pkg (container pg-age): postgresql-16 16.16-1.pgdg13+1", out)
        self.assertIn("pkg (container pg-age): postgresql-16-pgvector 0.8.7-1.pgdg13+2", out)

    def test_package_listing_failure_is_reported_not_fatal(self):
        rc, out, _ = run_main(["--container", "pg-age"], FakeRunner(dpkg_rc=1))
        self.assertEqual(rc, 0)
        self.assertIn("pkg (container pg-age): unavailable", out)

    def test_custom_label_changes_only_the_label(self):
        runner = FakeRunner(failing={"LANGUAGE plpgsql": PLPGSQL_STDERR})
        rc, out, _ = run_main(["--label", "other-pg"], runner)
        self.assertEqual(rc, 3)
        self.assertEqual(
            class_lines(out),
            ["::error::[other-pg] PG-ENV " + PRE.REASON_PLPGSQL],
        )

    def test_connection_data_never_on_argv_and_credential_urls_redacted(self):
        stderr = f"FATAL: bad dsn postgres://ai_memory:{SECRET}@localhost:5432/db failed\n"
        runner = FakeRunner(failing={"LANGUAGE plpgsql": stderr})
        rc, out, _ = run_main([], runner)
        self.assertEqual(rc, 3)
        self.assertNotIn(SECRET, out)
        self.assertIn("<redacted>", out)
        for call in runner.calls:
            self.assertFalse(any(a.startswith("-h") or a.startswith("-U") for a in call[1:3]))
            self.assertNotIn("postgres://", " ".join(call))

    def test_exactly_one_class_line_for_every_failure_mode(self):
        modes = [
            FakeRunner(failing={"LANGUAGE plpgsql": PLPGSQL_STDERR}),
            FakeRunner(failing={"EXTENSION IF NOT EXISTS vector": "x"}),
            FakeRunner(failing={"EXTENSION IF NOT EXISTS age": "x"}),
            FakeRunner(missing_psql=True),
            FakeRunner(connect_fails=99),
        ]
        for runner in modes:
            rc, out, _ = run_main([], runner)
            self.assertEqual(rc, 3)
            self.assertEqual(len(class_lines(out)), 1, out)
            self.assertEqual(out.count("::error::"), 1, out)


if __name__ == "__main__":
    unittest.main()
