#!/usr/bin/env python3
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""Pin scripts/ci/ensure-age-extension.py (#6161).

The macos-fed runner keeps Apache AGE in the Homebrew-managed postgresql@18
trees; a ``brew upgrade`` relinks them and drops the AGE files.  The helper
restores them from a node-local directory.  These tests drive the REAL script
as a subprocess against a fake sharedir/pkglibdir and a fake psql/pg_config
(Python stubs), so no live Postgres is needed.  Scratch lives under the repo's
``.local-runs`` (never /tmp).
"""

import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/ci/ensure-age-extension.py"
SECRET = "s3cr3t-pw-6161"

FAKE_PG_CONFIG = """#!{py}
import sys
base = {base!r}
print({{"--sharedir": base + "/share", "--pkglibdir": base + "/lib"}}[sys.argv[1]])
"""

# Fake psql: reports 1 row when the fake sharedir holds age.control AND the
# fake pkglibdir holds age.dylib, else 0 (mirrors "CREATE EXTENSION age" needs).
FAKE_PSQL = """#!{py}
import os
base = {base!r}
ok = os.path.isfile(base + "/share/extension/age.control") and os.path.isfile(base + "/lib/age.dylib")
print(1 if ok else 0)
"""


def write_exe(path, text):
    path.write_text(text)
    path.chmod(path.stat().st_mode | stat.S_IXUSR)


class TestEnsureAgeExtension6161(unittest.TestCase):
    def setUp(self):
        scratch_root = ROOT / ".local-runs" / "tmp"
        scratch_root.mkdir(parents=True, exist_ok=True)
        self.tmp = tempfile.TemporaryDirectory(prefix="age-6161-", dir=str(scratch_root))
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        (self.base / "share/extension").mkdir(parents=True)
        (self.base / "lib").mkdir(parents=True)
        self.age = self.base / "age-src"
        (self.age / "share").mkdir(parents=True)
        (self.age / "lib").mkdir(parents=True)
        for name in ("age.control", "age--1.8.0.sql", "age--1.7.0--1.8.0.sql", "age--1.6.0--1.7.0.sql"):
            (self.age / "share" / name).write_text("src " + name)
        (self.age / "lib/age.dylib").write_bytes(b"\x00dylib")
        self.pg_config = self.base / "pg_config"
        self.psql = self.base / "psql"
        write_exe(self.pg_config, FAKE_PG_CONFIG.format(py=sys.executable, base=str(self.base)))
        write_exe(self.psql, FAKE_PSQL.format(py=sys.executable, base=str(self.base)))
        self.url_file = self.base / "url"
        self.url_file.write_text(f"postgres://u:{SECRET}@127.0.0.1:1/db\n")

    def run_script(self, age_dir=None):
        return subprocess.run(
            [
                sys.executable, str(SCRIPT),
                "--url-file", str(self.url_file),
                "--age-dir", str(age_dir if age_dir is not None else self.age),
                "--pg-config", str(self.pg_config),
                "--psql", str(self.psql),
            ],
            capture_output=True, text=True, check=False,
        )

    def test_missing_extension_is_restored(self):
        r = self.run_script()
        self.assertEqual(r.returncode, 0, r.stderr)
        ext = self.base / "share/extension"
        for name in ("age.control", "age--1.8.0.sql", "age--1.7.0--1.8.0.sql", "age--1.6.0--1.7.0.sql"):
            self.assertEqual((ext / name).read_text(), "src " + name)
        self.assertEqual((self.base / "lib/age.dylib").read_bytes(), b"\x00dylib")
        self.assertNotIn(SECRET, r.stdout + r.stderr)

    def test_present_extension_is_a_noop(self):
        (self.base / "share/extension/age.control").write_text("installed")
        (self.base / "lib/age.dylib").write_bytes(b"installed")
        r = self.run_script()
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual((self.base / "share/extension/age.control").read_text(), "installed")
        self.assertEqual((self.base / "lib/age.dylib").read_bytes(), b"installed")
        self.assertFalse((self.base / "share/extension/age--1.8.0.sql").exists())

    def test_missing_source_dir_fails_closed(self):
        r = self.run_script(age_dir=self.base / "nope")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("age", r.stderr.lower())
        self.assertNotIn(SECRET, r.stdout + r.stderr)
        self.assertFalse((self.base / "share/extension/age.control").exists())

    def test_incomplete_source_dir_fails_closed(self):
        (self.age / "lib/age.dylib").unlink()
        r = self.run_script()
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("age.dylib", r.stderr)

    def test_missing_url_file_fails_closed(self):
        self.url_file.unlink()
        r = self.run_script()
        self.assertNotEqual(r.returncode, 0)


if __name__ == "__main__":
    unittest.main()
