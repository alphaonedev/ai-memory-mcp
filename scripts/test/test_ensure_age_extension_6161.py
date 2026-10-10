#!/usr/bin/env python3
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""Pin scripts/ci/ensure-age-extension.py (#6161).

The macos-fed runner keeps Apache AGE in the Homebrew-managed postgresql@18
trees; a ``brew upgrade`` relinks them and drops the AGE files.  The helper
restores exactly five sha256-pinned files from a node-local directory.

These tests drive the script as a subprocess against a fake sharedir/pkglibdir
and a fake psql/pg_config (Python stubs), so no live Postgres is needed.  The
fake psql models the real ``pg_available_extensions`` view: it lists ``age``
when ``age.control`` exists and never looks at ``age.dylib``.

Most tests run the script through a small harness that loads it as a module and
swaps ``MANIFEST`` for pins of the fake files (the real pins name the node's
real AGE build).  ``test_real_script_*`` run the unmodified script.  Scratch
lives under the repo's ``.local-runs`` (never /tmp).
"""

import argparse
import errno
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/ci/ensure-age-extension.py"
PW_MARKER = "marker-6161-pw"
PREFIX = "ensure-age-extension: "
SHARE_FILES = ("age--1.6.0--1.7.0.sql", "age--1.7.0--1.8.0.sql", "age--1.8.0.sql", "age.control")
DYLIB = b"\x7fAGE-dylib-6161" * 64

FAKE_PG_CONFIG = """#!{py}
import sys
base = {base!r}
print({{"--sharedir": base + "/share", "--pkglibdir": base + "/lib"}}[sys.argv[1]])
"""

# Fake psql with real-view semantics: only the control file decides the row.
# It records its argv and whether PGPASSWORD carried the marker value.
FAKE_PSQL = """#!{py}
import json, os, sys
base = {base!r}
with open(base + "/psql.log", "a") as fh:
    fh.write(json.dumps({{"argv": sys.argv, "env_marker_ok": os.environ.get("PGPASSWORD") == {marker!r}}}) + "\\n")
print(1 if os.path.isfile(base + "/share/extension/age.control") else 0)
"""

# Loads the script as a module, swaps MANIFEST (and optionally the uid check),
# then runs main() with the remaining argv.
HARNESS = """import importlib.util, json, sys
spec = importlib.util.spec_from_file_location("ensure_age_extension", sys.argv[1])
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
with open(sys.argv[2]) as fh:
    cfg = json.load(fh)
mod.MANIFEST = tuple(tuple(row) for row in cfg["manifest"])
if cfg.get("uid") is not None:
    mod.running_uid = lambda: cfg["uid"]
sys.exit(mod.main(sys.argv[3:]))
"""


def write_exe(path, text):
    path.write_text(text)
    path.chmod(0o755)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def load_module():
    spec = importlib.util.spec_from_file_location("ensure_age_extension", str(SCRIPT))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class TestEnsureAgeExtension6161(unittest.TestCase):
    def setUp(self):
        scratch_root = ROOT / ".local-runs" / "tmp"
        scratch_root.mkdir(parents=True, exist_ok=True)
        self.tmp = tempfile.TemporaryDirectory(prefix="age-6161-", dir=str(scratch_root))
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.ext = self.base / "share/extension"
        self.lib = self.base / "lib"
        self.ext.mkdir(parents=True)
        self.lib.mkdir(parents=True)
        self.age = self.base / "age-src"
        for d in (self.age, self.age / "share", self.age / "lib"):
            d.mkdir(parents=True, exist_ok=True)
            d.chmod(0o755)
        self.src = {("lib", "age.dylib"): DYLIB}
        for name in SHARE_FILES:
            self.src[("share", name)] = ("src " + name).encode()
        for (sub, name), data in self.src.items():
            p = self.age / sub / name
            p.write_bytes(data)
            p.chmod(0o755 if sub == "lib" else 0o644)
        self.pg_config = self.base / "pg_config"
        self.psql = self.base / "psql"
        write_exe(self.pg_config, FAKE_PG_CONFIG.format(py=sys.executable, base=str(self.base)))
        write_exe(self.psql, FAKE_PSQL.format(py=sys.executable, base=str(self.base), marker=PW_MARKER))
        self.url_file = self.base / "url"
        self.url_file.write_text(f"postgres://ciuser:{PW_MARKER}@127.0.0.1:5445/cidb?sslmode=disable\n")
        self.harness = self.base / "harness.py"
        self.harness.write_text(HARNESS)
        self.uid = None

    # ---- helpers -------------------------------------------------------
    def manifest(self):
        order = [("lib", "age.dylib")] + [("share", n) for n in SHARE_FILES]
        return [[sub, name, sha(self.src[(sub, name)])] for sub, name in order]

    def cmd(self, age_dir=None):
        cfg = self.base / "cfg.json"
        cfg.write_text(json.dumps({"manifest": self.manifest(), "uid": self.uid}))
        return [
            sys.executable, "-I", str(self.harness), str(SCRIPT), str(cfg),
            "--url-file", str(self.url_file),
            "--age-dir", str(age_dir if age_dir is not None else self.age),
            "--pg-config", str(self.pg_config),
            "--psql", str(self.psql),
        ]

    def run_script(self, age_dir=None):
        return subprocess.run(self.cmd(age_dir), capture_output=True, text=True, check=False)

    def install_good(self):
        for (sub, name), data in self.src.items():
            (self.lib if sub == "lib" else self.ext).joinpath(name).write_bytes(data)

    def assert_restored(self):
        for (sub, name), data in self.src.items():
            dest = (self.lib if sub == "lib" else self.ext) / name
            self.assertFalse(dest.is_symlink(), dest)
            self.assertEqual(dest.read_bytes(), data, dest)

    def assert_no_temp_files(self):
        left = [p.name for d in (self.lib, self.ext) for p in d.iterdir() if p.name.endswith(".age-restore")]
        self.assertEqual(left, [])

    def assert_fails(self, r, code, message):
        self.assertEqual(r.returncode, code, r.stdout + r.stderr)
        self.assertTrue(r.stderr.startswith(PREFIX + message), r.stderr)
        self.assertEqual(len(r.stderr.strip().splitlines()), 1, r.stderr)
        self.assertNotIn("Traceback", r.stderr)
        self.assertNotIn(PW_MARKER, r.stdout + r.stderr)

    def assert_nothing_installed(self):
        self.assertEqual(sorted(p.name for p in self.ext.iterdir()), [])
        self.assertEqual(sorted(p.name for p in self.lib.iterdir()), [])

    # ---- restore / no-op -----------------------------------------------
    def test_missing_extension_is_restored(self):
        r = self.run_script()
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("restored", r.stdout)
        self.assert_restored()
        self.assert_no_temp_files()
        self.assertNotIn(PW_MARKER, r.stdout + r.stderr)

    def test_present_extension_is_a_noop(self):
        self.install_good()
        before = {p: p.stat().st_ino for p in list(self.lib.iterdir()) + list(self.ext.iterdir())}
        r = self.run_script()
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("no restore needed", r.stdout)
        self.assertEqual({p: p.stat().st_ino for p in before}, before)

    def test_control_present_dylib_missing_is_restored(self):
        self.install_good()
        (self.lib / "age.dylib").unlink()
        r = self.run_script()
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("restored", r.stdout)
        self.assert_restored()

    def test_control_present_wrong_hash_dylib_is_restored(self):
        self.install_good()
        (self.lib / "age.dylib").write_bytes(b"stale build")
        r = self.run_script()
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("restored", r.stdout)
        self.assert_restored()

    def test_missing_sql_file_is_restored(self):
        self.install_good()
        (self.ext / "age--1.8.0.sql").unlink()
        r = self.run_script()
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assert_restored()

    def test_run_twice_is_idempotent(self):
        first = self.run_script()
        self.assertEqual(first.returncode, 0, first.stderr)
        inodes = {p: p.stat().st_ino for p in list(self.lib.iterdir()) + list(self.ext.iterdir())}
        second = self.run_script()
        self.assertEqual(second.returncode, 0, second.stderr)
        self.assertIn("no restore needed", second.stdout)
        self.assertEqual({p: p.stat().st_ino for p in inodes}, inodes)
        self.assert_restored()

    def test_concurrent_restores_all_succeed(self):
        big = DYLIB * 16384  # ~16 MB widens the race window
        self.src[("lib", "age.dylib")] = big
        (self.age / "lib/age.dylib").write_bytes(big)
        cmd = self.cmd()
        for round_no in range(4):  # 3 runners at once, repeated: the race must never be lost
            for d in (self.lib, self.ext):
                for f in d.iterdir():
                    f.unlink()
            procs = [subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                     for _ in range(3)]
            results = [p.communicate(timeout=120) for p in procs]
            codes = [p.returncode for p in procs]
            self.assertEqual(codes, [0, 0, 0], (round_no, results))
            self.assert_restored()
            self.assert_no_temp_files()

    # ---- secrets ---------------------------------------------------------
    def test_password_never_on_psql_argv(self):
        r = self.run_script()
        self.assertEqual(r.returncode, 0, r.stderr)
        calls = [json.loads(line) for line in (self.base / "psql.log").read_text().splitlines()]
        self.assertTrue(calls)
        for call in calls:
            argv = " ".join(call["argv"])
            self.assertNotIn(PW_MARKER, argv)
            self.assertIn("postgres://ciuser@127.0.0.1:5445/cidb?sslmode=disable", call["argv"])
            self.assertTrue(call["env_marker_ok"], "PGPASSWORD must carry the password")

    def test_password_in_query_moves_to_env(self):
        self.url_file.write_text(f"postgres://ciuser@127.0.0.1:5445/cidb?password={PW_MARKER}&sslmode=disable\n")
        r = self.run_script()
        self.assertEqual(r.returncode, 0, r.stderr)
        for line in (self.base / "psql.log").read_text().splitlines():
            call = json.loads(line)
            self.assertNotIn(PW_MARKER, " ".join(call["argv"]))
            self.assertTrue(call["env_marker_ok"])

    def test_keyword_dsn_is_rejected(self):
        self.url_file.write_text(f"host=127.0.0.1 user=ciuser password={PW_MARKER}\n")
        self.assert_fails(self.run_script(), 2, "tier URL file does not hold a postgres:// URL")
        self.assertFalse((self.base / "psql.log").exists())

    def test_sslpassword_is_rejected(self):
        # libpq has no env var for sslpassword, so it cannot be moved off argv: refuse it.
        self.install_good()  # a healthy tier would reach psql if the URL were accepted
        self.url_file.write_text(
            f"postgres://ciuser@127.0.0.1:5445/cidb?sslmode=verify-full&sslpassword={PW_MARKER}\n")
        self.assert_fails(self.run_script(), 2,
                          "tier URL file carries sslpassword; use a key without a passphrase")
        self.assertFalse((self.base / "psql.log").exists(), "psql must never be called")

    # ---- URL shapes libpq parses differently from urllib (R3-F1, F-R3-1) --
    def assert_url_refused(self, url, names=()):
        """The URL is refused with exit 2 before psql runs, and the value never prints."""
        self.install_good()  # a healthy tier would reach psql if the URL were accepted
        (self.base / "psql.log").unlink(missing_ok=True)  # each subTest starts without a psql call
        self.url_file.write_text(url + "\n")
        r = self.run_script()
        self.assert_fails(r, 2, "tier URL file ")
        for name in names:
            self.assertIn(name, r.stderr)
        self.assertNotIn("marker_6161_bare", r.stderr)
        self.assertFalse((self.base / "psql.log").exists(), "psql must never be called")

    def test_password_key_case_variants_are_rejected(self):
        # libpq matches query keys case-sensitively; a PASSWORD= key would stay on argv.
        for key in ("PASSWORD", "Password"):
            with self.subTest(key=key):
                self.assert_url_refused(f"postgres://ciuser@127.0.0.1:5445/cidb?{key}={PW_MARKER}", (key,))

    def test_fragment_credentials_are_rejected(self):
        # libpq has no fragment: it reads keys after a '#' as query parameters.
        for url in (
            f"postgres://ciuser@127.0.0.1:5445/cidb?sslmode=require#&password={PW_MARKER}",
            f"postgres://ciuser@127.0.0.1:5445/cidb?sslmode=require#&sslpassword={PW_MARKER}",
            f"postgres://ciuser@127.0.0.1:5445/cidb#sslpassword={PW_MARKER}",
        ):
            with self.subTest(url=url.replace(PW_MARKER, "<M>")):
                self.assert_url_refused(url)

    def test_raw_hash_or_question_mark_in_password_is_rejected(self):
        # libpq ends the userinfo at the first '@' before '/', urllib at '?' or '#'.
        for sep in ("#", "?"):
            with self.subTest(sep=sep):
                self.assert_url_refused(f"postgres://ciuser:{PW_MARKER}{sep}z@127.0.0.1:5445/cidb")

    def test_libpq_secret_keys_without_env_var_are_rejected(self):
        for key in ("oauth_client_secret", "scram_client_key", "scram_server_key"):
            with self.subTest(key=key):
                self.assert_url_refused(
                    f"postgres://ciuser@127.0.0.1:5445/cidb?sslmode=require&{key}={PW_MARKER}", (key,))

    def test_unknown_query_key_is_rejected_without_its_value(self):
        self.assert_url_refused(f"postgres://ciuser@127.0.0.1:5445/cidb?not_a_libpq_key={PW_MARKER}",
                                ("not_a_libpq_key",))

    def test_query_segment_without_equals_is_rejected_unnamed(self):
        # A bare segment is a value, not a key: it must never be printed as a key name.
        bare = "marker_6161_bare"
        self.assert_url_refused(f"postgres://ciuser@127.0.0.1:5445/cidb?sslmode=require&{bare}")
        self.assertFalse((self.base / "psql.log").exists())

    def test_allowlisted_query_keys_are_accepted(self):
        self.install_good()
        url = ("postgres://ciuser@127.0.0.1:5445/cidb?sslmode=require&application_name=ci"
               "&connect_timeout=10&target_session_attrs=any")
        self.url_file.write_text(url + "\n")
        r = self.run_script()
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("no restore needed", r.stdout)
        calls = [json.loads(line) for line in (self.base / "psql.log").read_text().splitlines()]
        self.assertTrue(calls)
        for call in calls:
            self.assertIn(url, call["argv"])

    # ---- bad input -------------------------------------------------------
    def test_missing_source_dir_fails_closed(self):
        r = self.run_script(age_dir=self.base / "nope")
        self.assert_fails(r, 2, "age source incomplete: ")
        self.assert_nothing_installed()

    def test_incomplete_source_dir_fails_closed(self):
        (self.age / "lib/age.dylib").unlink()
        r = self.run_script()
        self.assert_fails(r, 2, "age source incomplete: ")
        self.assertIn("age.dylib", r.stderr)
        self.assert_nothing_installed()

    def test_missing_url_file_fails_closed(self):
        self.url_file.unlink()
        self.assert_fails(self.run_script(), 2, "tier URL file ")
        self.assert_nothing_installed()

    def test_non_utf8_url_file_fails_closed(self):
        self.url_file.write_bytes(b"\xff\xfepostgres://u:" + PW_MARKER.encode() + b"@h/db")
        self.assert_fails(self.run_script(), 2, "tier URL file ")
        self.assert_nothing_installed()

    # ---- source integrity -----------------------------------------------
    def test_hash_mismatch_is_rejected(self):
        manifest_cmd = self.cmd()  # pins computed from the good bytes
        (self.age / "share/age--1.8.0.sql").write_bytes(b"tampered")
        r = subprocess.run(manifest_cmd, capture_output=True, text=True, check=False)
        self.assert_fails(r, 2, "age source rejected: ")
        self.assertIn("pinned sha256", r.stderr)
        self.assert_nothing_installed()

    def test_symlinked_source_file_is_rejected(self):
        outside = self.base / "outside.bin"
        outside.write_bytes(DYLIB)
        (self.age / "lib/age.dylib").unlink()
        os.symlink(str(outside), str(self.age / "lib/age.dylib"))
        r = self.run_script()
        self.assert_fails(r, 2, "age source rejected: ")
        self.assertIn("symlink", r.stderr)
        self.assert_nothing_installed()

    def test_symlinked_source_dir_is_rejected(self):
        real = self.base / "real-lib"
        (self.age / "lib").rename(real)
        os.symlink(str(real), str(self.age / "lib"))
        r = self.run_script()
        self.assert_fails(r, 2, "age source rejected: ")
        self.assertIn("symlink", r.stderr)
        self.assert_nothing_installed()

    def test_foreign_owner_is_rejected(self):
        self.uid = os.geteuid() + 4242
        r = self.run_script()
        self.assert_fails(r, 2, "age source rejected: ")
        self.assertIn("not owned by the running user", r.stderr)
        self.assert_nothing_installed()

    def test_group_writable_source_dir_is_rejected(self):
        (self.age / "lib").chmod(0o775)
        r = self.run_script()
        self.assert_fails(r, 2, "age source rejected: ")
        self.assertIn("group- or world-writable", r.stderr)
        self.assert_nothing_installed()

    def test_world_writable_source_file_is_rejected(self):
        (self.age / "share/age.control").chmod(0o646)
        r = self.run_script()
        self.assert_fails(r, 2, "age source rejected: ")
        self.assertIn("group- or world-writable", r.stderr)
        self.assert_nothing_installed()

    def test_extra_source_files_are_never_copied(self):
        (self.lib / "vector.dylib").write_bytes(b"REAL-PGVECTOR")
        (self.age / "lib/vector.dylib").write_bytes(b"FOREIGN")
        (self.age / "share/evil.sql").write_bytes(b"FOREIGN")
        r = self.run_script()
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual((self.lib / "vector.dylib").read_bytes(), b"REAL-PGVECTOR")
        self.assertFalse((self.ext / "evil.sql").exists())
        self.assert_restored()

    # ---- destination safety ----------------------------------------------
    def test_preplaced_temp_symlink_is_not_followed(self):
        victim = self.base / "victim.txt"
        victim.write_text("ORIG")
        os.symlink(str(victim), str(self.lib / ".age.dylib.age-restore"))
        r = self.run_script()
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(victim.read_text(), "ORIG")
        self.assert_restored()

    def test_preplaced_dest_symlink_is_replaced_not_followed(self):
        victim = self.base / "victim.txt"
        victim.write_text("ORIG")
        os.symlink(str(victim), str(self.lib / "age.dylib"))
        r = self.run_script()
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(victim.read_text(), "ORIG", "the install wrote through a planted symlink")
        dest = self.lib / "age.dylib"
        self.assertFalse(dest.is_symlink())
        self.assertTrue(stat.S_ISREG(os.lstat(str(dest)).st_mode))
        self.assert_restored()
        self.assert_no_temp_files()

    def test_dest_symlink_to_good_bytes_is_not_healthy(self):
        self.install_good()
        good_copy = self.base / "good-copy.dylib"
        good_copy.write_bytes(DYLIB)
        (self.lib / "age.dylib").unlink()
        os.symlink(str(good_copy), str(self.lib / "age.dylib"))
        r = self.run_script()
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("restored", r.stdout, "a symlink to correct bytes must not count as healthy")
        self.assertFalse((self.lib / "age.dylib").is_symlink())
        self.assertEqual(good_copy.read_bytes(), DYLIB)
        self.assert_restored()

    def test_unwritable_lib_dir_fails_without_partial_state(self):
        self.lib.chmod(0o555)
        self.addCleanup(self.lib.chmod, 0o755)
        r = self.run_script()
        self.assert_fails(r, 1, "age restore failed: ")
        self.assertFalse((self.ext / "age.control").exists(), "control must never precede its module")
        self.lib.chmod(0o755)
        self.assert_no_temp_files()
        again = self.run_script()
        self.assertEqual(again.returncode, 0, again.stderr)
        self.assert_restored()

    def test_share_failure_keeps_pinned_lib_file(self):
        self.ext.chmod(0o555)
        self.addCleanup(self.ext.chmod, 0o755)
        r = self.run_script()
        self.assert_fails(r, 1, "age restore failed: ")
        # Every written file carries the pinned bytes, so a failed run leaves it in place.
        self.assertEqual((self.lib / "age.dylib").read_bytes(), DYLIB)
        self.assertFalse((self.ext / "age.control").exists(), "control must never precede its module")
        self.ext.chmod(0o755)
        self.assert_no_temp_files()
        again = self.run_script()
        self.assertEqual(again.returncode, 0, again.stderr)
        self.assertIn("restored", again.stdout)
        self.assert_restored()

    def test_failed_run_never_removes_a_concurrently_verified_file(self):
        # R2-F1: runner B fails on a share file after replacing the dylib runner A wrote;
        # A then completes and verifies the tier. B's failure must not undo A's restore.
        dests = {"lib": self.lib, "share": self.ext}
        manifest = tuple(tuple(row) for row in self.manifest())

        def load():
            mod = load_module()
            mod.MANIFEST = manifest
            mod.dest_dirs = lambda pg_config: dests
            mod.read_url = lambda url_file: "postgres://u@h/db"
            mod.probe_lists_age = lambda psql, url: (self.ext / "age.control").is_file()
            return mod

        a, b = load(), load()
        sources = a.load_sources(self.age)
        real_b_write = b.write_atomic

        def b_write(data, mode, dest):
            if dest.name == "age.dylib":
                a.write_atomic(data, mode, dest)  # A writes after B's existence check ...
                return real_b_write(data, mode, dest)  # ... and B replaces it
            raise OSError(errno.ENOSPC, "No space left on device (injected for B)")

        b.write_atomic = b_write
        real_b_healthy = b.healthy
        checks, a_verified = [], []

        def b_healthy(args, d, url):
            result = real_b_healthy(args, d, url)
            checks.append(result)
            if len(checks) == 2:  # B's post-failure re-check: A finishes and verifies now
                for sub, name, data, mode in sources[1:]:
                    a.write_atomic(data, mode, dests[sub] / name)
                a_verified.append(a.healthy(args, dests, url))
            return result

        b.healthy = b_healthy
        args = argparse.Namespace(url_file=None, pg_config=None, psql=None, age_dir=self.age)
        with self.assertRaises(b.HelperError) as ctx:
            b.run(args)
        self.assertEqual(ctx.exception.code, 1)
        self.assertEqual(a_verified, [True], "runner A must have verified the tier")
        self.assertTrue(a.installed_ok(dests), "B's failure removed a file A had verified")
        self.assert_restored()
        self.assert_no_temp_files()

    # ---- the unmodified script -------------------------------------------
    def real_script(self, extra_env=None, age_dir=True):
        env = dict(os.environ)
        env.update(extra_env or {})
        argv = [sys.executable, "-I", str(SCRIPT), "--url-file", str(self.url_file),
                "--pg-config", str(self.pg_config), "--psql", str(self.psql)]
        if age_dir:
            argv += ["--age-dir", str(self.age)]
        return subprocess.run(argv, capture_output=True, text=True, check=False, env=env)

    def test_real_script_rejects_unpinned_source(self):
        r = self.real_script()
        self.assert_fails(r, 2, "age source rejected: ")
        self.assertIn("pinned sha256", r.stderr)
        self.assert_nothing_installed()

    def test_real_script_ignores_env_source_override(self):
        home = self.base / "home"
        home.mkdir()
        r = self.real_script({"HOME": str(home), "AI_MEMORY_CI_AGE_DIR": str(self.age)}, age_dir=False)
        self.assert_fails(r, 2, "age source incomplete: ")
        self.assertIn(str(home / "pg-age-stack" / "age-1.8.0"), r.stderr)
        self.assert_nothing_installed()

    def test_manifest_pins_exactly_the_five_age_files(self):
        mod = load_module()
        rows = list(mod.MANIFEST)
        self.assertEqual(
            sorted((sub, name) for sub, name, _ in rows),
            [("lib", "age.dylib")] + [("share", n) for n in SHARE_FILES],
        )
        self.assertEqual(rows[0][:2], ("lib", "age.dylib"), "lib must be installed before share")
        for _, _, pin in rows:
            self.assertRegex(pin, r"\A[0-9a-f]{64}\Z")
        self.assertEqual(dict(((s, n), p) for s, n, p in rows)[("lib", "age.dylib")],
                         "8ecfc082a55b667ed2773d622d726bbc4ca299c0b44248a8ec7d27b1460ed927")


if __name__ == "__main__":
    unittest.main()
