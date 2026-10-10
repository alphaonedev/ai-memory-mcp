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
import ctypes
import ctypes.util
import errno
import hashlib
import importlib.util
import json
import os
import random
from pathlib import Path
import re
import stat
import shutil
import signal
import subprocess
import sys
import tempfile
import time
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
    fh.write(json.dumps({{"argv": sys.argv, "env_marker_ok": os.environ.get("PGPASSWORD") == {marker!r},
                         "pgpassword": os.environ.get("PGPASSWORD"),
                         "pgpassword_hex": os.environb.get(b"PGPASSWORD", b"").hex(),
                         "connect_timeout_env": os.environ.get("PGCONNECT_TIMEOUT"),
                         "pgservice": os.environ.get("PGSERVICE"),
                         "pgservicefile": os.environ.get("PGSERVICEFILE")}}) + "\\n")
print(1 if os.path.isfile(base + "/share/extension/age.control") else 0)
"""

# Fake psql that never answers a connect: records its pid and its parent pid, then sleeps.
SLEEPING_PSQL = """#!{py}
import os, time
with open({base!r} + "/sleep.ppid", "w") as fh:
    fh.write(str(os.getppid()))
with open({base!r} + "/sleep.pid", "w") as fh:
    fh.write(str(os.getpid()))
time.sleep(120)
"""

# Like psql 18.6 after authentication: it catches the signals a naive timeout would use (#6517).
STUBBORN_PSQL = """#!{py}
import os, signal, time
for name in ("SIGTERM", "SIGHUP", "SIGINT", "SIGALRM", "SIGQUIT", "SIGUSR1", "SIGUSR2"):
    signal.signal(getattr(signal, name), signal.SIG_IGN)
with open({base!r} + "/sleep.ppid", "w") as fh:
    fh.write(str(os.getppid()))
with open({base!r} + "/sleep.pid", "w") as fh:
    fh.write(str(os.getpid()))
time.sleep(120)
"""

# Signals the helper does not turn into an interrupt: default-ignored (CHLD, URG, WINCH, INFO, CONT),
# job control (TSTP, TTIN, TTOU), PIPE (Python ignores it), the synchronous faults (SEGV, BUS, ILL, FPE) and the
# two nothing can catch (KILL, STOP).  Every other signal valid on this platform must end in `interrupted` (#6504).
NOT_INTERRUPT_SIGNALS = (
    "SIGKILL", "SIGSTOP", "SIGCHLD", "SIGCLD", "SIGURG", "SIGWINCH", "SIGINFO", "SIGCONT", "SIGTSTP", "SIGTTIN",
    "SIGTTOU", "SIGPIPE", "SIGSEGV", "SIGBUS", "SIGILL", "SIGFPE",
)

# Every libpq 18.6 connection keyword (PQconndefaults, 50 entries).
LIBPQ_18_KEYWORDS = (
    "service user password passfile channel_binding connect_timeout dbname host hostaddr port client_encoding "
    "options application_name fallback_application_name keepalives keepalives_idle keepalives_interval "
    "keepalives_count tcp_user_timeout sslmode sslnegotiation sslcompression sslcert sslkey sslcertmode "
    "sslpassword sslrootcert sslcrl sslcrldir sslsni requirepeer require_auth min_protocol_version "
    "max_protocol_version ssl_min_protocol_version ssl_max_protocol_version gssencmode krbsrvname gsslib "
    "gssdelegation replication target_session_attrs load_balance_hosts scram_client_key scram_server_key "
    "oauth_issuer oauth_client_id oauth_client_secret oauth_scope sslkeylogfile"
).split()

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


# Delivers a signal to the helper's own pid right after the real Popen returns (the spawn window).
# argv: script, signum, pid-file, then the helper's own arguments.
WINDOW_HARNESS = """import importlib.util, os, subprocess, sys
spec = importlib.util.spec_from_file_location("ensure_age_extension", sys.argv[1])
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
mod.installed_ok = lambda dests: True
mod.dest_dirs = lambda pg_config: {}
signum, pid_file = int(sys.argv[2]), sys.argv[3]
real_popen = subprocess.Popen


class WindowPopen(real_popen):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        with open(pid_file, "w") as fh:
            fh.write(str(self.pid))
        os.kill(os.getpid(), signum)


subprocess.Popen = WindowPopen
sys.exit(mod.main(sys.argv[4:]))
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

    def run_script(self, age_dir=None, env=None):
        return subprocess.run(self.cmd(age_dir), capture_output=True, text=True, check=False, env=env)

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

    def test_sslpassword_case_variants_get_the_sslpassword_message(self):
        # R6-F2 (mutant rev_drop_sslpassword_lower): a case variant is a secret, not "an unlisted key".
        self.install_good()
        for key in ("SSLPassword", "SSLPASSWORD", "sslPassword"):
            with self.subTest(key=key):
                self.url_file.write_text(f"postgres://ciuser@127.0.0.1:5445/cidb?{key}={PW_MARKER}\n")
                self.assert_fails(self.run_script(), 2,
                                  "tier URL file carries sslpassword; use a key without a passphrase")
                self.assertFalse((self.base / "psql.log").exists(), "psql must never be called")

    # ---- URL shapes libpq parses differently from urllib (R3-F1, F-R3-1) --
    def assert_url_refused(self, url, names=(), absent=()):
        """The URL is refused with exit 2 before psql runs, and the value never prints.

        ``names`` must appear in stderr; ``absent`` strings (R5-F1: identifier-shaped
        password fragments) must not.
        """
        self.install_good()  # a healthy tier would reach psql if the URL were accepted
        (self.base / "psql.log").unlink(missing_ok=True)  # each subTest starts without a psql call
        self.url_file.write_text(url + "\n")
        r = self.run_script()
        log = self.base / "psql.log"
        self.assertNotIn(PW_MARKER, log.read_text() if log.exists() else "", "marker reached psql's argv")
        self.assert_fails(r, 2, "tier URL file ")
        for name in names:
            self.assertIn(name, r.stderr)
        for fragment in absent + ("marker_6161_bare",):
            self.assertNotIn(fragment, r.stderr)
        self.assertFalse((self.base / "psql.log").exists(), "psql must never be called")

    def test_password_key_case_variants_are_rejected(self):
        # libpq matches query keys case-sensitively; a PASSWORD= key would stay on argv.
        for key in ("PASSWORD", "Password"):
            with self.subTest(key=key):
                self.assert_url_refused(f"postgres://ciuser@127.0.0.1:5445/cidb?{key}={PW_MARKER}",
                                        ("password",), (key,))

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
        # R4-F3: only the '@'-after-host guard refuses these two (no '#', one '=').
        for url in (
            f"postgres://ciuser:{PW_MARKER}/z@127.0.0.1:5445/cidb",
            f"postgres://ciuser:{PW_MARKER}?sslmode=require@127.0.0.1/cidb",
        ):
            with self.subTest(url=url.replace(PW_MARKER, "<M>")):
                self.assert_url_refused(url)

    def test_libpq_secret_keys_without_env_var_are_rejected(self):
        for key in ("oauth_client_secret", "scram_client_key", "scram_server_key"):
            with self.subTest(key=key):
                self.assert_url_refused(
                    f"postgres://ciuser@127.0.0.1:5445/cidb?sslmode=require&{key}={PW_MARKER}", (key,))

    def test_unknown_query_key_is_rejected_without_its_value(self):
        # R5-F1: an unlisted key may be a password tail, so it is never named.
        self.assert_url_refused(f"postgres://ciuser@127.0.0.1:5445/cidb?not_a_libpq_key={PW_MARKER}",
                                ("unlisted query key",), ("not_a_libpq_key",))

    def test_unlisted_key_that_is_a_password_tail_is_not_echoed(self):
        # R5-F1: a query-form password holding a raw '&' leaves its tail as a "key".
        tail = "Ident6161tail"
        for url in (
            f"postgres://ciuser@127.0.0.1:5445/cidb?password=Tr0ub&{tail}or3=x",
            f"postgres://ciuser@127.0.0.1:5445/cidb?sslmode=require&password=Tr0ub&{tail}=x",
        ):
            with self.subTest(url=url.replace(tail, "<T>")):
                self.assert_url_refused(url, ("unlisted query key",), (tail,))

    def test_known_refused_key_names_still_print(self):
        # R5-F1: only known libpq keywords are named; the message stays useful for them.
        self.assert_url_refused(f"postgres://ciuser@127.0.0.1:5445/cidb?sslkeylogfile={PW_MARKER}",
                                ("sslkeylogfile",))

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

    # ---- round 5 (R4-F1..R4-F3, F-R4-2, F-R4-3) ---------------------------
    def test_query_segment_with_second_equals_is_rejected(self):
        # R4-F2: parse_qsl reads the remainder as the value of an allowlisted key, so the
        # password would stay on argv; libpq refuses these only after psql has started.
        for url in (
            f"postgres://ciuser@127.0.0.1:5445/cidb?sslmode=require;password={PW_MARKER}",
            f"postgres://ciuser@127.0.0.1:5445/cidb?sslmode=require?password={PW_MARKER}",
            f"postgres://ciuser@127.0.0.1:5445/cidb?application_name=ci=password={PW_MARKER}",
            # R5-F3: the extra '=' sits in a later segment (a first-segment-only check misses it).
            f"postgres://ciuser@127.0.0.1:5445/cidb?sslmode=require&application_name=ci;password={PW_MARKER}",
            f"postgres://ciuser@127.0.0.1:5445/cidb?sslmode=require&connect_timeout=5&application_name=ci=x=y",
        ):
            with self.subTest(url=url.replace(PW_MARKER, "<M>")):
                self.assert_url_refused(url)

    def test_control_characters_in_url_are_rejected(self):
        # R4-F2 / F-R4-2: urlsplit silently drops TAB/CR/LF (joining a two-line URL file),
        # and a NUL makes subprocess raise; both are refused before parsing.
        for label, url in (
            ("two-line file", f"postgres://ciuser@127.0.0.1:5445/cidb?sslmode=require\npassword={PW_MARKER}"),
            ("CR", f"postgres://ciuser@127.0.0.1:5445/cidb?sslmode=require\rpassword={PW_MARKER}"),
            ("TAB", f"postgres://ciuser:{PW_MARKER}@127.0.0.1:5445/cidb?application_name=c\ti"),
            ("NUL in password", f"postgres://ciuser:{PW_MARKER}\x00@127.0.0.1:5445/cidb"),
            ("NUL in host", f"postgres://ciuser:{PW_MARKER}@127.0.0.1\x00:5445/cidb"),
        ):
            with self.subTest(shape=label):
                self.assert_url_refused(url)

    def test_percent_encoded_nul_in_password_is_rejected(self):
        # F-R4-2: unquote/parse_qsl decode %00 into PGPASSWORD, which subprocess refuses.
        for url in (
            f"postgres://ciuser:{PW_MARKER}%00@127.0.0.1:5445/cidb",
            f"postgres://ciuser@127.0.0.1:5445/cidb?password={PW_MARKER}%00",
        ):
            with self.subTest(url=url.replace(PW_MARKER, "<M>")):
                self.assert_url_refused(url)

    def test_psql_value_error_is_a_one_line_refusal(self):
        # F-R4-2 belt and braces: a ValueError from subprocess becomes HelperError exit 2.
        mod = load_module()
        with self.assertRaises(mod.HelperError) as cm:
            mod.probe_lists_age(str(self.psql) + "\x00", f"postgres://ciuser:{PW_MARKER}@127.0.0.1:5445/cidb")
        self.assertEqual(cm.exception.code, mod.EXIT_BAD_INPUT)
        self.assertNotIn(PW_MARKER, str(cm.exception))
        self.assertEqual(len(str(cm.exception).splitlines()), 1)
        self.assertFalse((self.base / "psql.log").exists())

    def test_more_than_one_at_in_authority_is_rejected(self):
        # R4-F1: urllib splits the userinfo at the last '@', libpq at the first.
        for url in (
            f"postgres://ciuser:{PW_MARKER}@x@127.0.0.1:5445/cidb",
            f"postgres://ci@user:{PW_MARKER}@127.0.0.1/cidb",
            f"postgres://a:{PW_MARKER}@b:c@127.0.0.1/cidb",
        ):
            with self.subTest(url=url.replace(PW_MARKER, "<M>")):
                self.assert_url_refused(url, ("percent-encode",))

    def test_empty_host_part_gets_a_clear_refusal(self):
        # F-R4-3 / R5-F4: an empty authority is refused and named as such; the message
        # must not claim that socket-directory URLs are unsupported (host=%2F... works).
        self.assert_url_refused(
            f"postgres:///cidb?host=/var/run/postgresql&password={PW_MARKER}", ("empty host part",))
        self.assertNotIn("not supported", self.run_script().stderr)

    def test_socket_directory_forms_with_a_host_part_are_accepted(self):
        # R5-F4: the encoded-directory forms carry a host part or key and are not refused.
        mod = load_module()
        for url in (
            "postgres://ciuser@%2Fvar%2Frun%2Fpostgresql/cidb",
            "postgres://ciuser@/cidb?host=%2Fvar%2Frun%2Fpostgresql",
        ):
            with self.subTest(url=url):
                # R6-F2: must return (no HelperError), with no password and the URL unchanged.
                self.assertEqual(mod.psql_target(url), (url, None))

    def test_password_only_userinfo_keeps_the_authority_slashes(self):
        # Cloud F2: urlunsplit dropped '//' for an empty netloc ('postgres:/db'), which libpq rejects.
        mod = load_module()
        self.assertEqual(mod.psql_target("postgres://:pw@/db?host=%2Ftmp"), ("postgres:///db?host=%2Ftmp", "pw"))
        self.assertEqual(mod.psql_target("postgres://:pw@/db?host=%2Ftmp&password=q"),
                         ("postgres:///db?host=%2Ftmp", "q"))
        self.assertEqual(mod.psql_target("postgresql://:pw@h/db"), ("postgresql://h/db", "pw"))

    # ---- round 6 (R5-F2 / #6221): libpq percent-decodes only, '+' is literal --
    def test_plus_in_query_password_is_literal(self):
        mod = load_module()
        for raw, want in (("ab+cd", "ab+cd"), ("ab%2Bcd", "ab+cd"), ("a%20b+c", "a b+c")):
            with self.subTest(raw=raw):
                target, password = mod.psql_target(f"postgres://ciuser@127.0.0.1:5445/cidb?password={raw}")
                self.assertEqual(password, want)
                self.assertNotIn(raw, target)

    def test_plus_in_query_password_reaches_pgpassword_unchanged(self):
        self.install_good()
        pw = PW_MARKER + "+x"
        self.url_file.write_text(f"postgres://ciuser@127.0.0.1:5445/cidb?password={pw}\n")
        r = self.run_script()
        self.assertEqual(r.returncode, 0, r.stderr)
        calls = [json.loads(line) for line in (self.base / "psql.log").read_text().splitlines()]
        self.assertTrue(calls)
        for call in calls:
            self.assertEqual(call["pgpassword"], pw)

    # ---- round 7 (R6-F1 / #6251, R6-F2): libpq URI parity, byte-exact password -----
    def test_invalid_percent_escape_is_refused(self):
        # libpq: 'invalid percent-encoded token'. The helper used to accept the literal.
        host = "127.0.0.1:5445/cidb"
        for label, url in (
            ("query password %zz", f"postgres://ciuser@{host}?password={PW_MARKER}%zzb"),
            ("userinfo password %zz", f"postgres://ciuser:{PW_MARKER}%zzb@{host}"),
            ("query password %2", f"postgres://ciuser@{host}?password={PW_MARKER}%2"),
            ("query password lone %", f"postgres://ciuser@{host}?password={PW_MARKER}%"),
            ("userinfo password lone %", f"postgres://ciuser:{PW_MARKER}%@{host}"),
            ("options %zz without a password", f"postgres://ciuser@{host}?options=-c%zzx"),
            ("options % plus a password", f"postgres://ciuser@{host}?options=%&password={PW_MARKER}"),
            ("password plus options %", f"postgres://ciuser@{host}?password={PW_MARKER}&options=%"),
            ("key %zz", f"postgres://ciuser@{host}?pass%zzword={PW_MARKER}"),
            ("path %zz", f"postgres://ciuser:{PW_MARKER}@127.0.0.1:5445/ci%zzdb"),
        ):
            with self.subTest(shape=label):
                self.assert_url_refused(url, ("percent-encoded",))

    def test_percent_encoded_nul_anywhere_is_refused(self):
        # libpq: 'forbidden value %00 in percent-encoded value' in every URI component.
        host = "127.0.0.1:5445/cidb"
        for label, url in (
            ("user", f"postgres://ci%00user:{PW_MARKER}@{host}"),
            ("host", f"postgres://ciuser:{PW_MARKER}@127.0.0.1%00:5445/cidb"),
            ("path", f"postgres://ciuser:{PW_MARKER}@127.0.0.1:5445/ci%00db"),
            ("kept value", f"postgres://ciuser:{PW_MARKER}@{host}?options=a%00b"),
        ):
            with self.subTest(shape=label):
                self.assert_url_refused(url, ("%00",))

    def test_raw_space_is_refused(self):
        # libpq: 'unexpected spaces found ... use percent-encoded spaces (%20)'.
        host = "127.0.0.1:5445/cidb"
        for label, url in (
            ("query password", f"postgres://ciuser@{host}?password={PW_MARKER} b"),
            ("userinfo password", f"postgres://ciuser:{PW_MARKER} b@{host}"),
            ("options", f"postgres://ciuser@{host}?options=-c x"),
            ("options plus password", f"postgres://ciuser@{host}?options=-c x&password={PW_MARKER}"),
        ):
            with self.subTest(shape=label):
                self.assert_url_refused(url, ("space",))

    def test_empty_query_segment_is_refused(self):
        # libpq: 'missing key/value separator "="' for '?&&k=v', '?k=v&&' and '?&'.
        host = "127.0.0.1:5445/cidb"
        for label, url in (
            ("leading &&", f"postgres://ciuser@{host}?&&password={PW_MARKER}"),
            ("leading &", f"postgres://ciuser@{host}?&password={PW_MARKER}"),
            ("middle &&", f"postgres://ciuser@{host}?password={PW_MARKER}&&sslmode=require"),
            ("double trailing &&", f"postgres://ciuser@{host}?password={PW_MARKER}&sslmode=require&&"),
            ("only &", f"postgres://ciuser:{PW_MARKER}@{host}?&"),
            ("no password &&", f"postgres://ciuser@{host}?application_name=a&&sslmode=require"),
        ):
            with self.subTest(shape=label):
                self.assert_url_refused(url, ("empty query segment",))

    def test_single_trailing_ampersand_and_empty_query_are_accepted(self):
        # libpq accepts '?k=v&' and a bare '?'; the helper keeps accepting both.
        mod = load_module()
        host = "127.0.0.1:5445/cidb"
        target, password = mod.psql_target(f"postgres://ciuser@{host}?password=pw&")
        self.assertEqual((target, password), (f"postgres://ciuser@{host}", "pw"))
        target, password = mod.psql_target(f"postgres://ciuser@{host}?password=pw&sslmode=require&")
        self.assertEqual((target, password), (f"postgres://ciuser@{host}?sslmode=require", "pw"))
        url = f"postgres://ciuser@{host}?"
        self.assertEqual(mod.psql_target(url), (url, None))

    def test_percent_ff_reaches_pgpassword_byte_exact(self):
        # R6-F1 / #6251: %FF is the single byte 0xFF in libpq, not U+FFFD (EF BF BD).
        mod = load_module()
        for url in (
            "postgres://ciuser@127.0.0.1:5445/cidb?password=a%FFb",
            "postgres://ciuser:a%FFb@127.0.0.1:5445/cidb",
            "postgres://ciuser:a%ffb@127.0.0.1:5445/cidb",
        ):
            with self.subTest(url=url):
                _, password = mod.psql_target(url)
                self.assertEqual(os.fsencode(password), b"a\xffb")
        self.install_good()
        self.url_file.write_text("postgres://ciuser@127.0.0.1:5445/cidb?password=a%FFb\n")
        r = self.run_script()
        self.assertEqual(r.returncode, 0, r.stderr)
        calls = [json.loads(line) for line in (self.base / "psql.log").read_text().splitlines()]
        self.assertTrue(calls)
        for call in calls:
            self.assertEqual(call["pgpassword_hex"], b"a\xffb".hex())
            self.assertNotIn("a%FFb", " ".join(call["argv"]))

    def test_percent_encoded_query_key_is_decoded(self):
        # R6-F2: libpq decodes keys too, so %70assword is the password key.
        mod = load_module()
        for key in ("%70assword", "pass%77ord", "p%61ssword"):
            with self.subTest(key=key):
                target, password = mod.psql_target(f"postgres://ciuser@127.0.0.1:5445/cidb?{key}=pw&sslmode=require")
                self.assertEqual((target, password), ("postgres://ciuser@127.0.0.1:5445/cidb?sslmode=require", "pw"))
        # an encoded allowlisted key is kept as written
        url = "postgres://ciuser@127.0.0.1:5445/cidb?%73slmode=require"
        self.assertEqual(mod.psql_target(url), (url, None))
        # an encoded key never loosens the allowlist: %68ost is host, req%75ire_auth is refused
        self.assert_url_refused("postgres://ciuser@127.0.0.1:5445/cidb?req%75ire_auth=scram-sha-256", ("require_auth",))

    def test_plus_in_userinfo_password_is_literal(self):
        # R6-F2: the CI form is user:pass@host; '+' stays a plus there too.
        mod = load_module()
        target, password = mod.psql_target("postgres://ciuser:ab+cd@127.0.0.1:5445/cidb?sslmode=disable")
        self.assertEqual(password, "ab+cd")
        self.assertEqual(target, "postgres://ciuser@127.0.0.1:5445/cidb?sslmode=disable")
        _, password = mod.psql_target("postgres://ciuser:a%20b+c%2Bd@127.0.0.1:5445/cidb")
        self.assertEqual(password, "a b+c+d")
        self.install_good()
        self.url_file.write_text(f"postgres://ciuser:{PW_MARKER}+x@127.0.0.1:5445/cidb\n")
        r = self.run_script()
        self.assertEqual(r.returncode, 0, r.stderr)
        calls = [json.loads(line) for line in (self.base / "psql.log").read_text().splitlines()]
        self.assertTrue(calls)
        for call in calls:
            self.assertEqual(call["pgpassword"], PW_MARKER + "+x")

    def test_scheme_is_matched_exactly_as_libpq_does(self):
        # Cloud F4: urlsplit lower-cases the scheme, so 'Postgres://' (not a URI to libpq) was rewritten.
        for url in (f"Postgres://ciuser:{PW_MARKER}@127.0.0.1:5445/cidb",
                    f"POSTGRESQL://ciuser:{PW_MARKER}@127.0.0.1:5445/cidb"):
            with self.subTest(url=url.replace(PW_MARKER, "<M>")):
                self.assert_url_refused(url, ("postgres://",))

    def test_non_secret_libpq_keywords_are_allowed(self):
        # Cloud F5: nine non-secret libpq 18 keywords were refused as "unlisted".
        mod = load_module()
        for key in ("fallback_application_name", "sslnegotiation", "sslcompression", "sslcertmode", "sslcrldir",
                    "min_protocol_version", "max_protocol_version", "ssl_min_protocol_version",
                    "ssl_max_protocol_version"):
            with self.subTest(key=key):
                url = f"postgres://ciuser@127.0.0.1:5445/cidb?{key}=x"
                self.assertEqual(mod.psql_target(url), (url, None))

    def test_remaining_libpq_keywords_are_refused_and_named(self):
        # Cloud F5: keywords that change the auth mechanism or the session mode stay refused, by name.
        for key in ("gsslib", "gssdelegation", "replication", "oauth_issuer", "oauth_client_id", "oauth_scope",
                    "ssl"):
            with self.subTest(key=key):
                self.assert_url_refused(f"postgres://ciuser@127.0.0.1:5445/cidb?{key}=x", (f"query key {key}",))

    def test_every_libpq_keyword_is_classified(self):
        # Cloud F5: allowed, refused-by-name, or the password keyword: none falls through to "unlisted".
        mod = load_module()
        for key in LIBPQ_18_KEYWORDS:
            with self.subTest(key=key):
                self.assertIn(key, mod.ALLOWED_QUERY_KEYS | mod.REFUSED_KNOWN_KEYS)
        self.assertEqual(mod.ALLOWED_QUERY_KEYS & mod.REFUSED_KNOWN_KEYS, set())

    # ---- #6345: a pg_service.conf password must never beat the moved PGPASSWORD ----------
    def test_service_key_in_url_is_refused_by_name(self):
        # libpq fills unset options from the service file BEFORE it reads PGPASSWORD, so a service
        # entry carrying a password beats the moved password (the URL password beat it originally).
        for url in ("postgres://ciuser:pw@127.0.0.1:5445/cidb?service=svc",
                    "postgres://ciuser@127.0.0.1:5445/cidb?service=svc",
                    "postgres://ciuser:pw@127.0.0.1:5445/cidb?sslmode=disable&%73ervice=svc"):
            with self.subTest(url=url.split("@", 1)[1]):
                self.assert_url_refused(url, ("query key service",))

    def test_pgservice_env_is_not_passed_to_psql(self):
        self.install_good()
        env = dict(os.environ, PGSERVICE="svc-6345", PGSERVICEFILE=str(self.base / "pg_service.conf"))
        r = self.run_script(env=env)
        self.assertEqual(r.returncode, 0, r.stderr)
        calls = [json.loads(line) for line in (self.base / "psql.log").read_text().splitlines()]
        self.assertTrue(calls)
        for call in calls:
            self.assertIsNone(call["pgservice"], "PGSERVICE reached psql (service-file password would win)")
            self.assertIsNone(call["pgservicefile"], "PGSERVICEFILE reached psql")
            self.assertTrue(call["env_marker_ok"], "the moved password must still reach psql")

    # ---- #6346 / #6348: the docs say what the code does ------------------------------
    @staticmethod
    def collapsed(path):
        return " ".join(Path(path).read_text(encoding="utf-8").split())

    def test_docs_name_every_refused_by_name_key(self):
        # #6346: sslkeylogfile and require_auth were refused by name but missing from the docstring and docs.
        mod = load_module()
        docstring = " ".join(mod.__doc__.split())
        docs = self.collapsed(ROOT / "docs/DEV-CI-ENVIRONMENT.md")
        changelog = self.collapsed(ROOT / "changelog.d/6161.fixed.md")
        for key in sorted(mod.REFUSED_KNOWN_KEYS):
            pattern = r"(?<![A-Za-z0-9_])" + key + r"(?![A-Za-z0-9_])"
            with self.subTest(key=key):
                self.assertTrue(re.search(pattern, docstring), f"{key} missing from the module docstring")
                self.assertTrue(re.search(pattern, docs), f"{key} missing from docs/DEV-CI-ENVIRONMENT.md")
        for key in ("sslkeylogfile", "require_auth"):
            with self.subTest(changelog_key=key):
                self.assertTrue(key in changelog, f"{key} missing from changelog.d/6161.fixed.md")

    def test_docstring_states_the_real_reason_ssl_true_is_refused(self):
        # #6346: libpq 18.6 DOES know ssl=true (it maps it to sslmode=require); the helper refuses it on purpose.
        doc = " ".join(load_module().__doc__.split())
        self.assertFalse("libpq does not know" in doc, "docstring still says libpq does not know ssl=true")
        self.assertTrue("maps to ``sslmode=require``" in doc, "docstring does not say ssl=true maps to sslmode=require")

    def test_docs_state_the_exact_control_character_refusal(self):
        # #6348: only TAB, CR, LF and NUL are refused; VT, FF, SOH, DEL and NBSP pass (libpq accepts them too).
        for path in ("docs/DEV-CI-ENVIRONMENT.md", "changelog.d/6161.fixed.md"):
            with self.subTest(path=path):
                text = self.collapsed(ROOT / path)
                self.assertFalse("control character" in text, "overstates the refusal as any control character")
                self.assertTrue("TAB, CR, LF or NUL" in text, "does not list TAB, CR, LF or NUL")

    # ---- #6252 / cloud F6: signals and the connect timeout --------------------
    def start_sleeping_helper(self, psql_template=SLEEPING_PSQL, hosts="127.0.0.1:5445"):
        write_exe(self.psql, psql_template.format(py=sys.executable, base=str(self.base)))
        self.install_good()
        for stale in ("sleep.pid", "sleep.ppid"):  # a previous subTest's pid must not be read as this one's
            if (self.base / stale).exists():
                (self.base / stale).unlink()
        self.url_file.write_text(f"postgres://ciuser:{PW_MARKER}@{hosts}/cidb\n")
        proc = subprocess.Popen(self.cmd(), stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        pid_file = self.base / "sleep.pid"
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline and not (pid_file.exists() and pid_file.read_text()):
            time.sleep(0.05)
        child = int(pid_file.read_text())

        def reap():
            try:
                os.kill(child, signal.SIGKILL)
            except ProcessLookupError:
                pass
            proc.kill()
            proc.communicate()

        self.addCleanup(reap)
        return proc, child

    def assert_gone(self, pid):
        deadline = time.monotonic() + 8
        while time.monotonic() < deadline:
            try:
                os.kill(pid, 0)
            except ProcessLookupError:
                return
            time.sleep(0.05)
        self.fail(f"psql child {pid} outlived the helper (orphan holding PGPASSWORD)")

    def test_sigterm_mid_connect_terminates_the_psql_child(self):
        proc, child = self.start_sleeping_helper()
        proc.send_signal(signal.SIGTERM)
        out, err = proc.communicate(timeout=15)
        self.assertEqual(proc.returncode, 1, out + err)
        self.assertEqual(err.strip(), PREFIX + "interrupted")
        self.assertNotIn(PW_MARKER, out + err)
        self.assert_gone(child)

    def test_sigint_mid_connect_is_one_line_and_terminates_the_psql_child(self):
        proc, child = self.start_sleeping_helper()
        proc.send_signal(signal.SIGINT)
        out, err = proc.communicate(timeout=15)
        self.assertEqual(proc.returncode, 1, out + err)
        self.assertEqual(err.strip(), PREFIX + "interrupted")
        self.assertNotIn("Traceback", err)
        self.assertNotIn(PW_MARKER, out + err)
        self.assert_gone(child)

    def test_sighup_mid_connect_is_one_line_and_terminates_the_psql_child(self):
        # #6338: SIGHUP kept its default action, so the helper died and psql was reparented with PGPASSWORD.
        proc, child = self.start_sleeping_helper()
        proc.send_signal(signal.SIGHUP)
        out, err = proc.communicate(timeout=15)
        self.assertEqual(proc.returncode, 1, out + err)
        self.assertEqual(err.strip(), PREFIX + "interrupted")
        self.assertNotIn("Traceback", err)
        self.assertNotIn(PW_MARKER, out + err)
        self.assert_gone(child)

    def run_signal_in_spawn_window(self, signum):
        """Deliver ``signum`` to the helper's own pid right after the real Popen returns (#6337).

        This is the window a runner's signal can hit: the psql child exists, but the guard around
        ``communicate`` has not been entered.  The wrapper records the child pid first, so the
        assertion on the child's fate does not depend on timing.
        """
        write_exe(self.psql, SLEEPING_PSQL.format(py=sys.executable, base=str(self.base)))
        self.install_good()
        pid_file = self.base / "window.pid"
        harness = self.base / "window_harness.py"
        harness.write_text(WINDOW_HARNESS)
        cmd = [sys.executable, "-I", str(harness), str(SCRIPT), str(int(signum)), str(pid_file),
               "--url-file", str(self.url_file), "--age-dir", str(self.age),
               "--pg-config", str(self.pg_config), "--psql", str(self.psql)]
        r = subprocess.run(cmd, capture_output=True, text=True, check=False, timeout=60)
        # The Popen child is the supervisor; psql is the process that wrote sleep.pid (when it got that far).
        children = [int(pid_file.read_text())]
        psql_pid = self.base / "sleep.pid"
        if psql_pid.exists() and psql_pid.read_text():
            children.append(int(psql_pid.read_text()))

        def reap():
            for pid in children:
                try:
                    os.kill(pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass

        self.addCleanup(reap)
        return r, children

    def test_signal_in_the_psql_spawn_window_terminates_the_psql_child(self):
        # #6337: a handled signal between Popen() and the communicate() guard escaped the guard.
        for signum in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
            with self.subTest(signal=signum.name):
                r, children = self.run_signal_in_spawn_window(signum)
                self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
                self.assertEqual(r.stderr.strip(), PREFIX + "interrupted")
                self.assertNotIn(PW_MARKER, r.stdout + r.stderr)
                for child in children:
                    self.assert_gone(child)

    # ---- #6504 / #6517 / #6505 / #6506 / #6518 / #6507: containment of the psql child ---------------
    def interrupt_signals(self):
        skip = {getattr(signal, name) for name in NOT_INTERRUPT_SIGNALS if hasattr(signal, name)}
        return sorted((s for s in signal.valid_signals() if s not in skip), key=int)

    def test_every_catchable_signal_mid_connect_terminates_the_psql_child(self):
        # #6504: SIGQUIT, SIGUSR1, SIGUSR2, SIGALRM and every other signal kept the default action, so the helper
        # died and psql was re-parented with PGPASSWORD.  Each signal is sent to a real helper process.
        signums = self.interrupt_signals()
        self.assertGreaterEqual(len(signums), 15, signums)
        for name in ("SIGQUIT", "SIGUSR1", "SIGUSR2", "SIGALRM", "SIGTERM", "SIGINT", "SIGHUP"):
            self.assertIn(getattr(signal, name), signums)
        for signum in signums:
            with self.subTest(signal=int(signum)):
                proc, child = self.start_sleeping_helper()
                proc.send_signal(signum)
                out, err = proc.communicate(timeout=15)
                self.assertEqual(proc.returncode, 1, out + err)
                self.assertEqual(err.strip(), PREFIX + "interrupted")
                self.assertNotIn(PW_MARKER, out + err)
                self.assert_gone(child)

    def assert_gone_within(self, pid, seconds, why):
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            try:
                os.kill(pid, 0)
            except ProcessLookupError:
                return
            time.sleep(0.02)
        self.fail(f"psql {pid} still alive {seconds} s after {why} (orphan holding PGPASSWORD)")

    def test_psql_does_not_outlive_a_sigkilled_helper_after_authentication(self):
        # #6517: SIGKILL cannot be caught.  connect_timeout bounds only the connect phase, and psql 18.6 catches
        # SIGALRM, so a psql that stalls after authentication lived on without bound.  The stand-in ignores
        # every catchable signal, as a stalled authenticated session does.
        proc, child = self.start_sleeping_helper(STUBBORN_PSQL)
        proc.send_signal(signal.SIGKILL)
        proc.communicate(timeout=15)
        self.assert_gone_within(child, 3, "the helper was SIGKILLed")

    def test_orphan_bound_does_not_scale_with_the_host_count(self):
        # #6505: libpq tries every host in turn, each for connect_timeout; the bound was hosts x timeout.
        four = ",".join(f"127.0.0.{n}:5445" for n in (1, 2, 3, 4))
        for hosts in ("127.0.0.1:5445", four):
            with self.subTest(hosts=hosts.count(",") + 1):
                proc, child = self.start_sleeping_helper(STUBBORN_PSQL, hosts=hosts)
                proc.send_signal(signal.SIGKILL)
                proc.communicate(timeout=15)
                self.assert_gone_within(child, 3, "the helper was SIGKILLed")

    def test_uncatchable_and_fault_signals_leave_no_psql_child(self):
        # Signals the helper cannot or does not turn into an interrupt still end psql: the supervisor sees
        # the helper's pipe close.
        for name in ("SIGKILL", "SIGSEGV", "SIGBUS", "SIGILL", "SIGFPE"):
            with self.subTest(signal=name):
                proc, child = self.start_sleeping_helper(STUBBORN_PSQL)
                proc.send_signal(getattr(signal, name))
                proc.communicate(timeout=15)
                self.assert_gone_within(child, 3, f"the helper got {name}")

    def test_psql_is_killed_when_the_supervisor_itself_is_sigkilled(self):
        # The supervisor is a process too: killing it must not leave psql behind while the helper lives.
        proc, child = self.start_sleeping_helper(STUBBORN_PSQL)
        supervisor = int((self.base / "sleep.ppid").read_text())
        os.kill(supervisor, signal.SIGKILL)
        out, err = proc.communicate(timeout=15)
        self.assertEqual(proc.returncode, 1, out + err)
        self.assertEqual(len(err.strip().splitlines()), 1, err)
        self.assertNotIn(PW_MARKER, out + err)
        self.assert_gone_within(child, 3, "the supervisor was SIGKILLed")

    def run_supervisor(self, deadline, psql_template=STUBBORN_PSQL, keep_pipe=True):
        """Run the supervisor mode directly; returns (process, write end of the pipe or None, psql pid)."""
        write_exe(self.psql, psql_template.format(py=sys.executable, base=str(self.base)))
        for stale in ("sleep.pid", "sleep.ppid"):
            if (self.base / stale).exists():
                (self.base / stale).unlink()
        mod = load_module()
        r, w = os.pipe()
        proc = subprocess.Popen(
            [sys.executable, "-I", str(SCRIPT), mod.SUPERVISE_FLAG, str(r), str(deadline), "--", str(self.psql)],
            pass_fds=(r,), stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        os.close(r)
        if not keep_pipe:
            os.close(w)
            w = None
        pid_file = self.base / "sleep.pid"
        end = time.monotonic() + 15
        while time.monotonic() < end and not (pid_file.exists() and pid_file.read_text()):
            time.sleep(0.05)
        child = int(pid_file.read_text())

        def reap():
            for pid in (child, proc.pid):
                try:
                    os.kill(pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            if w is not None:
                os.close(w)
            proc.communicate()

        self.addCleanup(reap)
        return proc, child

    def test_supervisor_kills_psql_when_the_helper_pipe_closes(self):
        proc, child = self.run_supervisor(600, keep_pipe=False)
        proc.communicate(timeout=15)
        self.assert_gone_within(child, 3, "the pipe closed")

    def test_supervisor_enforces_its_own_deadline(self):
        # A helper that is SIGSTOPped keeps the pipe open and cannot enforce the probe limit.
        proc, child = self.run_supervisor(1)
        t0 = time.monotonic()
        proc.communicate(timeout=15)
        self.assertLess(time.monotonic() - t0, 6)
        self.assert_gone_within(child, 3, "the supervisor deadline passed")

    def test_supervisor_kills_psql_on_a_signal_sent_to_itself(self):
        for signum in (signal.SIGTERM, signal.SIGHUP, signal.SIGINT, signal.SIGUSR1):
            with self.subTest(signal=int(signum)):
                proc, child = self.run_supervisor(600)
                proc.send_signal(signum)
                proc.communicate(timeout=15)
                self.assert_gone_within(child, 3, f"the supervisor got signal {int(signum)}")

    def test_supervisor_passes_psql_output_and_exit_code_through(self):
        write_exe(self.psql, FAKE_PSQL.format(py=sys.executable, base=str(self.base), marker=PW_MARKER))
        self.install_good()
        mod = load_module()
        r, w = os.pipe()
        try:
            done = subprocess.run(
                [sys.executable, "-I", str(SCRIPT), mod.SUPERVISE_FLAG, str(r), "30", "--", str(self.psql)],
                pass_fds=(r,), capture_output=True, text=True, timeout=30)
        finally:
            os.close(r)
            os.close(w)
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertEqual(done.stdout.strip(), "1")

    def test_overall_deadline_stops_a_stalled_psql_6506(self):
        # #6506: the 60 s limit is the only bound on a psql that connects and then stalls.  The supervisor
        # deadline is held far away so only the helper's own limit and stop_child can end psql here (#6518).
        write_exe(self.psql, STUBBORN_PSQL.format(py=sys.executable, base=str(self.base)))
        mod = load_module()
        mod.PROBE_TIMEOUT_SECONDS = 1
        mod.SUPERVISOR_GRACE_SECONDS = 600
        t0 = time.monotonic()
        with self.assertRaises(mod.HelperError) as ctx:
            mod.probe_lists_age(str(self.psql), f"postgres://ciuser:{PW_MARKER}@127.0.0.1:5445/cidb")
        self.assertLess(time.monotonic() - t0, 8)
        self.assertEqual(ctx.exception.code, mod.EXIT_UNAVAILABLE)
        self.assertEqual(str(ctx.exception), "age probe could not run psql (TimeoutExpired)")
        self.assertNotIn(PW_MARKER, str(ctx.exception))
        child = int((self.base / "sleep.pid").read_text())

        def reap():
            try:
                os.kill(child, signal.SIGKILL)
            except ProcessLookupError:
                pass

        self.addCleanup(reap)
        self.assert_gone_within(child, 3, "the overall deadline passed (stop_child)")

    def test_a_signal_recorded_while_psql_runs_is_raised_when_the_guard_exits(self):
        # #6507: the interrupt is held as a flag inside the guard and must surface when the guard ends.
        mod = load_module()
        with self.assertRaises(KeyboardInterrupt):
            with mod.deferred_interrupts():
                mod.note_interrupt(signal.SIGTERM, None)
        with mod.deferred_interrupts():  # the flag does not leak into the next guard
            pass
        with self.assertRaises(KeyboardInterrupt):
            mod.note_interrupt(signal.SIGTERM, None)  # outside the guard it raises at once

    def test_main_installs_a_handler_for_every_interrupt_signal(self):
        mod = load_module()
        saved = {s: signal.getsignal(s) for s in signal.valid_signals() if s not in (signal.SIGKILL, signal.SIGSTOP)}
        self.addCleanup(lambda: [signal.signal(s, h) for s, h in saved.items() if h is not None])
        mod.install_interrupt_handlers()
        handled = {s for s in saved if signal.getsignal(s) == mod.note_interrupt}
        wanted = set(self.interrupt_signals())
        self.assertTrue(wanted <= handled, sorted(int(s) for s in wanted - handled))
        for name in NOT_INTERRUPT_SIGNALS:
            if hasattr(signal, name) and getattr(signal, name) in saved:
                self.assertNotEqual(signal.getsignal(getattr(signal, name)), mod.note_interrupt, name)

    def test_docs_state_the_true_orphan_bound(self):
        # #6504/#6517/#6505/#6520: no document claims a bound that only holds while psql connects.
        mod = load_module()
        texts = {
            "docstring": " ".join(mod.__doc__.split()),
            "docs": " ".join((ROOT / "docs/DEV-CI-ENVIRONMENT.md").read_text().split()),
            "changelog": " ".join((ROOT / "changelog.d/6161.fixed.md").read_text().split()),
        }
        for where, text in texts.items():
            with self.subTest(where=where):
                self.assertIn("supervisor", text.lower())
                self.assertNotIn("15 s per host", text)
                self.assertNotIn("Every catchable signal", text)
        self.assertIn("SIGKILL", texts["docstring"])
        self.assertIn("SIGSTOP", texts["docstring"])

    def test_connect_timeout_width_and_decoded_value_6509(self):
        # #6509: two digits at most, and the rule applies to the percent-DECODED value.
        for value in ("060", "015", "001", "0015", "%30%36%30"):
            with self.subTest(refused=value):
                self.assert_url_refused(
                    f"postgres://ciuser:pw@127.0.0.1:5445/cidb?connect_timeout={value}", ("connect_timeout",))
        mod = load_module()
        for value in ("%31%35", "%36%30", "%35"):
            with self.subTest(accepted=value):
                url = f"postgres://ciuser@127.0.0.1:5445/cidb?connect_timeout={value}"
                self.assertEqual(mod.psql_target(url), (url, None))
        self.assert_url_refused(
            "postgres://ciuser@127.0.0.1:5445/cidb?connect_timeout=%36%31", ("connect_timeout",))

    def test_docstring_names_the_oracle_that_pins_the_claim(self):
        # #6519: a docstring check needs no libpq, so it lives outside LibpqOracleTests (which skips without one).
        doc = " ".join(load_module().__doc__.split())
        self.assertIn("LibpqOracleTests", doc, "the parity claim must name the test class that pins it")

    def test_connect_timeout_must_be_a_bounded_positive_integer(self):
        # #6338: libpq reads connect_timeout=0 as "wait forever", which removes the orphan bound.
        for value in ("0", "00", "61", "100", "-1", "+5", "5s", "", "1e1", "%30"):
            with self.subTest(value=value):
                self.assert_url_refused(
                    f"postgres://ciuser:pw@127.0.0.1:5445/cidb?connect_timeout={value}", ("connect_timeout",))
        self.assert_url_refused("postgres://ciuser@127.0.0.1:5445/cidb?%63onnect_timeout=0", ("connect_timeout",))
        mod = load_module()
        for value in ("1", "15", "60", "05"):
            with self.subTest(accepted=value):
                url = f"postgres://ciuser@127.0.0.1:5445/cidb?connect_timeout={value}"
                self.assertEqual(mod.psql_target(url), (url, None))

    def test_psql_gets_a_bounded_connect_timeout(self):
        self.install_good()
        r = self.run_script()
        self.assertEqual(r.returncode, 0, r.stderr)
        calls = [json.loads(line) for line in (self.base / "psql.log").read_text().splitlines()]
        self.assertTrue(calls)
        for call in calls:
            self.assertEqual(call["connect_timeout_env"], "15")

    def test_kept_query_segments_are_not_re_encoded(self):
        mod = load_module()
        url = ("postgres://ciuser@127.0.0.1:5445/cidb?options=-c%20statement_timeout%3D5"
               "&password=pw&application_name=a+b&sslmode=require")
        target, password = mod.psql_target(url)
        self.assertEqual(password, "pw")
        self.assertEqual(target, "postgres://ciuser@127.0.0.1:5445/cidb"
                                 "?options=-c%20statement_timeout%3D5&application_name=a+b&sslmode=require")

    def test_query_without_password_is_passed_through_as_written(self):
        mod = load_module()
        url = "postgres://ciuser:pw@127.0.0.1:5445/cidb?options=-c%20x&application_name=a+b"
        target, password = mod.psql_target(url)
        self.assertEqual(password, "pw")
        self.assertEqual(target, "postgres://ciuser@127.0.0.1:5445/cidb?options=-c%20x&application_name=a+b")
        # Segments (even libpq's single trailing '&') are never rebuilt when no password was removed.
        url = "postgres://ciuser@127.0.0.1:5445/cidb?application_name=a&sslmode=require&"
        self.assertEqual(mod.psql_target(url), (url, None))

    def test_allowlist_excludes_every_libpq_secret_key(self):
        # R4-F3: adding any of these to ALLOWED_QUERY_KEYS would put a secret on argv.
        mod = load_module()
        secrets = {"password", "sslpassword", "oauth_client_secret", "scram_client_key",
                   "scram_server_key", "sslkeylogfile", "require_auth"}
        self.assertEqual(set(mod.ALLOWED_QUERY_KEYS) & secrets, set())

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
        # F7: a regular file where the directory belongs fails mkdir for root and non-root alike.
        shutil.rmtree(str(self.lib))
        self.lib.write_bytes(b"")
        r = self.run_script()
        self.assert_fails(r, 1, "age restore failed: ")
        self.assertFalse((self.ext / "age.control").exists(), "control must never precede its module")
        self.lib.unlink()
        self.lib.mkdir()
        self.assert_no_temp_files()
        again = self.run_script()
        self.assertEqual(again.returncode, 0, again.stderr)
        self.assert_restored()

    def test_share_failure_keeps_pinned_lib_file(self):
        shutil.rmtree(str(self.ext))  # F7: a file where the share dir belongs, uid-independent
        self.ext.write_bytes(b"")
        r = self.run_script()
        self.assert_fails(r, 1, "age restore failed: ")
        # Every written file carries the pinned bytes, so a failed run leaves it in place.
        self.assertEqual((self.lib / "age.dylib").read_bytes(), DYLIB)
        self.ext.unlink()
        self.ext.mkdir()
        self.assertFalse((self.ext / "age.control").exists(), "control must never precede its module")
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


# ---- #6347: the libpq oracle behind the docstring claim "a URL the helper accepts is read the same way by libpq" --
LIBPQ_CANDIDATES = (
    "/opt/homebrew/opt/libpq/lib/libpq.5.dylib",
    "/opt/homebrew/opt/postgresql@18/lib/postgresql/libpq.5.dylib",
    "/usr/local/opt/libpq/lib/libpq.5.dylib",
    "/usr/lib/x86_64-linux-gnu/libpq.so.5",
    "/usr/lib/aarch64-linux-gnu/libpq.so.5",
)


class _ConninfoOption(ctypes.Structure):
    _fields_ = [("keyword", ctypes.c_char_p), ("envvar", ctypes.c_char_p), ("compiled", ctypes.c_char_p),
                ("val", ctypes.c_char_p), ("label", ctypes.c_char_p), ("dispchar", ctypes.c_char_p),
                ("dispsize", ctypes.c_int)]


def load_libpq():
    """Return the libpq CDLL with PQconninfoParse, or None when no libpq is installed."""
    names = list(LIBPQ_CANDIDATES)
    found = ctypes.util.find_library("pq")
    if found:
        names.insert(0, found)
    for name in names:
        try:
            lib = ctypes.CDLL(name)
            lib.PQconninfoParse.restype = ctypes.POINTER(_ConninfoOption)
            lib.PQconninfoParse.argtypes = [ctypes.c_char_p, ctypes.POINTER(ctypes.c_char_p)]
            lib.PQconninfoFree.argtypes = [ctypes.POINTER(_ConninfoOption)]
            return lib
        except (OSError, AttributeError):
            continue
    return None


def libpq_keywords(lib):
    """Every connection keyword the installed libpq defines (PQconndefaults)."""
    lib.PQconndefaults.restype = ctypes.POINTER(_ConninfoOption)
    lib.PQconndefaults.argtypes = []
    res = lib.PQconndefaults()
    out, i = [], 0
    while res and res[i].keyword:
        out.append(res[i].keyword.decode())
        i += 1
    if res:
        lib.PQconninfoFree(res)
    return out


def libpq_options(lib, url):
    """PQconninfoParse(url) -> {keyword: value bytes}, or None when libpq refuses the URL."""
    err = ctypes.c_char_p()
    res = lib.PQconninfoParse(os.fsencode(url), ctypes.byref(err))
    if not res:
        return None
    out, i = {}, 0
    while res[i].keyword:
        if res[i].val is not None:
            out[res[i].keyword.decode()] = res[i].val
        i += 1
    lib.PQconninfoFree(res)
    return out


def oracle_divergences(lib, psql_target, helper_error, url):
    """Why a URL the helper ACCEPTS is not read the same way by libpq (empty list = parity holds)."""
    try:
        target, pw = psql_target(url)
    except helper_error:
        return []  # a refusal is never a parity break (the helper may be stricter)
    orig, rew = libpq_options(lib, url), libpq_options(lib, target)
    if orig is None:
        return ["libpq refuses the original URL the helper accepted"]
    if rew is None:
        return ["libpq refuses the password-free argv URL"]
    bad = []
    rest_o = {k: v for k, v in orig.items() if k != "password"}
    rest_r = {k: v for k, v in rew.items() if k != "password"}
    if rest_o != rest_r:
        bad.append("non-password options differ")
    want = orig.get("password") or None
    have = os.fsencode(pw) if pw else None
    if want != have:
        bad.append("PGPASSWORD differs from libpq's password")
    if rew.get("password"):
        bad.append("the argv URL still carries a password per libpq")
    return bad


ORACLE_URLS = (
    "postgres://u:Fk3Pw0rd@h:5432/db?sslmode=require",
    "postgres://:Fk3Pw0rd@/db?host=%2Fvar%2Frun",
    "postgres://u:Fk3:Pw0rd@h/db",
    "postgres://u:Fk3%40Pw0rd@h/db",
    "postgres://u:Fk3%FFPw0rd@h/db",
    "postgres://u:Fk3+Pw0rd@h/db",
    "postgres://u:Fk3Pw0rd@[::1]:5432/db",
    "postgres://u:Fk3Pw0rd@h1:5432,h2:5433/db",
    "postgres://u@h/db?password=Fk3Pw0rd&application_name=a%26b",
    "postgres://u@h/db?application_name=a&password=Fk3Pw0rd&",
    "postgres://u:Fk3Pw0rd@h/db?password=Other9pw",
    "postgres://u:Fk3Pw0rd@h/d%40b?connect_timeout=7",
    "postgres://u:Fk3\x0bPw0rd@h/db",
    "postgres://u:Fk3\x0cPw0rd@h/db",
    "postgres://u:Fk3\x7fPw0rd@h/db",
    "postgres://u:Fk3 Pw0rd@h/db",
    "postgres://u@h/db?password=Fk3Pw0rd&sslmode=disable",
    "postgres://u@h/db?password=Fk3%0D%0APw0rd",
    "postgres://u@h/db?pass%77ord=Fk3Pw0rd",
    "postgres://u@h/db?PASSWORD=Fk3Pw0rd",
    "postgresql://u:Fk3Pw0rd@h/db",
)

ORACLE_FUZZ_PIECES = ("%", "%2", "%41", "%40", "%3A", "%2F", "%26", "%3D", "%00", "%FF", "%C0%AF", "%25", "%23",
                      "@", ":", "/", "?", "&", "=", "#", "+", "[", "]", ",", " ", "\\", ";", "a", "Fk3", "Pw0", "9",
                      "é", "＠", "／", "\x0b")
ORACLE_FUZZ_KEYS = ("password", "%70assword", "Password", "sslmode", "%73slmode", "host", "hostaddr", "port", "user",
                    "dbname", "options", "passfile", "ssl", "application_name", "x", "", "p%00")


def oracle_fuzz_urls(seed, count):
    rnd = random.Random(seed)
    for _ in range(count):
        pw = "Fk3" + "".join(rnd.choice(ORACLE_FUZZ_PIECES) for _ in range(rnd.randint(0, 5)))
        user = "".join(rnd.choice(ORACLE_FUZZ_PIECES) for _ in range(rnd.randint(0, 3)))
        host = rnd.choice(["h", "h:5432", "", "h1,h2", "[::1]", "%2Fs", "h" + rnd.choice(ORACLE_FUZZ_PIECES)])
        path = rnd.choice(["/db", "", "/", "/d" + rnd.choice(ORACLE_FUZZ_PIECES) + "b"])
        segs = [rnd.choice(ORACLE_FUZZ_KEYS) + rnd.choice(["=", "=", "==", ""]) +
                "".join(rnd.choice(ORACLE_FUZZ_PIECES) for _ in range(rnd.randint(0, 3)))
                for _ in range(rnd.randint(0, 3))]
        if rnd.random() < 0.5:
            segs.append("password=" + pw)
        userinfo = rnd.choice([f"{user}:{pw}@", f"{user}@", "", f":{pw}@"])
        yield (rnd.choice(["postgres://", "postgresql://"]) + userinfo + host + path +
               ("?" + "&".join(segs) if segs or rnd.random() < 0.1 else ""))


class LibpqOracleTests(unittest.TestCase):
    """#6347: a URL the helper accepts is read the same way by libpq (checked against the real libpq)."""

    @classmethod
    def setUpClass(cls):
        cls.lib = load_libpq()
        if cls.lib is None:
            raise unittest.SkipTest("no libpq with PQconninfoParse on this host")
        cls.mod = load_module()

    def divergences(self, urls):
        found = []
        for url in urls:
            for why in oracle_divergences(self.lib, self.mod.psql_target, self.mod.HelperError, url):
                found.append(f"{why}: {url!r}")
        return found

    def test_hostile_table_has_parity_with_libpq(self):
        self.assertEqual(self.divergences(ORACLE_URLS), [])

    def test_seeded_fuzz_has_parity_with_libpq(self):
        for seed in (6161, 90210):
            with self.subTest(seed=seed):
                self.assertEqual(self.divergences(oracle_fuzz_urls(seed, 1500)), [])

    def test_oracle_accepts_urls_and_is_not_vacuous(self):
        accepted = 0
        for url in ORACLE_URLS:
            try:
                self.mod.psql_target(url)
            except self.mod.HelperError:
                continue
            accepted += 1
        self.assertGreaterEqual(accepted, 15, "the oracle table must exercise accepted URLs")

    def test_fuzz_exercises_accepted_urls(self):
        accepted = 0
        for url in oracle_fuzz_urls(6161, 1500):
            try:
                self.mod.psql_target(url)
                accepted += 1
            except self.mod.HelperError:
                continue
        self.assertGreaterEqual(accepted, 100, "the fuzz must reach accepted URLs, not only refusals")

    def test_keyword_table_covers_the_installed_libpq(self):
        # #6347 (a): every keyword the installed libpq defines is in LIBPQ_18_KEYWORDS (subset, since an older
        # libpq on a runner defines fewer).  Dropping a keyword from the table, or a newer libpq adding one the
        # helper has not classified, fails here.
        real = libpq_keywords(self.lib)
        self.assertGreaterEqual(len(real), 30, sorted(real))
        self.assertEqual(sorted(set(real) - set(LIBPQ_18_KEYWORDS)), [])
        self.assertTrue(set(real) & set(self.mod.ALLOWED_QUERY_KEYS), "the allowlist must overlap libpq")

    def test_keyword_table_check_detects_a_dropped_keyword(self):
        real = libpq_keywords(self.lib)
        dropped = [k for k in LIBPQ_18_KEYWORDS if k != "user"]
        self.assertIn("user", real)
        self.assertEqual(sorted(set(real) - set(dropped)), ["user"])

    def test_oracle_detects_a_password_left_on_argv(self):
        def leaky(url):
            return url, "Fk3Pw0rd"
        self.assertTrue(oracle_divergences(self.lib, leaky, self.mod.HelperError,
                                           "postgres://u:Fk3Pw0rd@h/db"))

    def test_oracle_detects_a_wrong_password(self):
        real = self.mod.psql_target

        def wrong(url):
            target, _ = real(url)
            return target, "not-the-password"
        self.assertTrue(oracle_divergences(self.lib, wrong, self.mod.HelperError,
                                           "postgres://u:Fk3Pw0rd@h/db"))

    def test_oracle_detects_a_dropped_option(self):
        def drops(url):
            return "postgres://u@h/db", None
        self.assertTrue(oracle_divergences(self.lib, drops, self.mod.HelperError,
                                           "postgres://u@h/db?application_name=a"))


if __name__ == "__main__":
    unittest.main()
