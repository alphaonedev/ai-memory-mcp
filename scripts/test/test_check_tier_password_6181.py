#!/usr/bin/env python3
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""Tests for scripts/ci/check-tier-password.py (#6181).

The enterprise-fed tier URL carries the role password.  A password that is empty, short, or equal to (or
contained in) the user, host or database name is not a secret in practice: those components are shown on every
psql argv and in the process table.  The helper fails closed with a ``::error::`` line that names the rule and
never a value.  Stdlib only.
"""

import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/ci/check-tier-password.py"
GOOD = "q7Zr-Lm2_Xv9Kd4TgPw8Hn3Bs6Jc1Yf5AeUo0iRt"  # 40 chars, distinct from every component below


class TestCheckTierPassword6181(unittest.TestCase):
    def setUp(self):
        scratch = ROOT / ".local-runs" / "tmp"
        scratch.mkdir(parents=True, exist_ok=True)
        self._dir = tempfile.TemporaryDirectory(dir=scratch, prefix="tierpw-6181-")
        self.addCleanup(self._dir.cleanup)
        self.url_file = Path(self._dir.name) / "url"

    def run_check(self, url, raw=False):
        self.url_file.write_text(url if raw else url + "\n")
        return subprocess.run([sys.executable, "-I", str(SCRIPT), "--url-file", str(self.url_file)],
                              capture_output=True, text=True, check=False, env={"PATH": os.environ.get("PATH", "")})

    def assert_refused(self, url, rule, secrets=()):
        r = self.run_check(url)
        out = r.stdout + r.stderr
        self.assertEqual(r.returncode, 1, out)
        self.assertIn("::error::", out)
        self.assertIn(rule, out)
        for secret in secrets:
            self.assertNotIn(secret, out, "the diagnostic must never print a URL value")
        return out

    def test_a_random_long_distinct_password_passes(self):
        r = self.run_check(f"postgres://ai_memory:{GOOD}@127.0.0.1:5445/ai_memory_test?sslmode=disable")
        self.assertEqual((r.returncode, r.stdout.count("::error::")), (0, 0), r.stdout + r.stderr)
        self.assertNotIn(GOOD, r.stdout + r.stderr)

    def test_an_empty_or_missing_password_is_refused(self):
        for url in ("postgres://u@h:5445/db", "postgres://u:@h:5445/db", "postgres://u@h/db?password=",
                    "postgres://u:@h/db?password="):
            with self.subTest(url=url):
                self.assert_refused(url, "empty")

    def test_a_password_shorter_than_16_is_refused(self):
        self.assert_refused("postgres://u:" + "x7Qz" * 3 + "abc@h/db", "shorter than 16", ["x7Qz"])
        r = self.run_check("postgres://u:" + "x7Qz" * 4 + "@h/db")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)  # exactly 16 passes

    def test_length_counts_the_percent_decoded_password(self):
        # 16 encoded bytes ("%41" x 5 + "b") are 6 characters once decoded
        self.assert_refused("postgres://u:" + "%41" * 5 + "b@h/db", "shorter than 16")

    def test_a_password_equal_to_a_component_is_refused(self):
        long_name = "ai_memory_test_ci_user_long"
        for label, url in {
            "user": f"postgres://{long_name}:{long_name}@h:5445/db",
            "host": f"postgres://u:{long_name}@{long_name}:5445/db",
            "database": f"postgres://u:{long_name}@h:5445/{long_name}",
            "query host": f"postgres://u:{long_name}@/db?host={long_name}",
        }.items():
            with self.subTest(equal_to=label):
                self.assert_refused(url, label.split()[-1], [long_name])

    def test_a_password_contained_in_a_component_is_refused(self):
        pw = "ai_memory_test_ci_"  # 18 chars
        for label, url in {
            "user": f"postgres://{pw}role:{pw}@h:5445/db",
            "host": f"postgres://u:{pw}@db.{pw}example:5445/db",
            "database": f"postgres://u:{pw}@h:5445/{pw}run_17",
        }.items():
            with self.subTest(contained_in=label):
                self.assert_refused(url, label, [pw])

    def test_a_password_that_contains_a_long_component_is_refused(self):
        db = "ai_memory_test"  # 14 chars
        self.assert_refused(f"postgres://u:Zx9{db}Qv4Lm8Wt2Rn@h:5445/{db}", "contains the database", [db])
        # a short component can occur in a random password by chance: only components of 8+ characters count
        r = self.run_check(f"postgres://ai:{GOOD}ai@h:5445/db")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)

    def test_the_contained_component_boundary_is_8_characters_6645(self):
        # MIN_CONTAINED_COMPONENT = 8: an 8-character user inside a 32-character password is refused, a 7-character
        # one passes (it can occur in a random password by chance)
        for user, refused in (("tierUs8x", True), ("tierU7x", False)):
            pw = "Kq3Vb9Wm" + user + "Hz2Ld6Rp" + "Tj5Nc1Gy"[: 16 - len(user)] + "Fs4Xa8Ye"
            self.assertGreaterEqual(len(pw), 31)
            with self.subTest(user_length=len(user)):
                if refused:
                    self.assert_refused(f"postgres://{user}:{pw}@h:5445/db", "contains the user", [user, pw])
                else:
                    r = self.run_check(f"postgres://{user}:{pw}@h:5445/db")
                    self.assertEqual(r.returncode, 0, r.stdout + r.stderr)

    def test_percent_encoded_components_are_compared_decoded(self):
        pw = "ai_memory_test_ci_"
        enc = "".join(f"%{ord(c):02X}" for c in pw)
        self.assert_refused(f"postgres://u:{enc}@h:5445/{pw}", "database")
        self.assert_refused(f"postgres://u:{pw}@h:5445/{enc}", "database")

    def test_the_password_query_form_is_checked_too(self):
        pw = "ai_memory_test_ci_"
        self.assert_refused(f"postgres://u@h:5445/{pw}?password={pw}", "database")
        r = self.run_check(f"postgres://u@h:5445/db?password={GOOD}")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)

    def test_query_keys_that_name_a_component_are_checked_6640(self):
        # libpq reads user=, dbname=, hostaddr= (and every other key) from the query string; #6181 says the
        # password may match NO URL component, so a password equal to or contained in any query value is refused
        long_name = "ai_memory_test_ci_user_long"
        for key, rule in (("user", "user"), ("dbname", "database"), ("hostaddr", "host"), ("host", "host"),
                          ("application_name", "query"), ("options", "query"), ("%75ser", "user")):
            with self.subTest(equal_to=key):
                self.assert_refused(f"postgres://u:{long_name}@h:5445/db?{key}={long_name}", rule, [long_name])
            with self.subTest(contained_in=key):
                self.assert_refused(f"postgres://u:{long_name}@h:5445/db?sslmode=disable&{key}=x{long_name}y",
                                    rule, [long_name])
        # a long query value inside the password is refused too, and an unrelated query value still passes
        self.assert_refused(f"postgres://u:Zx9{long_name}Qv4@h:5445/db?dbname={long_name}", "contains the database",
                            [long_name])
        r = self.run_check(f"postgres://u:{GOOD}@h:5445/db?user=ai_memory&dbname=ai_memory_test&sslmode=disable")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)

    def test_no_value_is_ever_printed(self):
        user, db, pw = "tierroleXq93", "tierdbXq93zw", "tierpwXq93"
        for url in (f"postgres://{user}:{pw}@h:5445/{db}",  # short
                    f"postgres://{user}:{db}{db}@h:5445/{db}",  # contained
                    f"postgres://{user}:@h:5445/{db}"):  # empty
            r = self.run_check(url)
            self.assertEqual(r.returncode, 1)
            for value in (user, db, pw):
                self.assertNotIn(value, r.stdout + r.stderr)

    def test_a_missing_or_malformed_url_file_fails_closed(self):
        r = subprocess.run([sys.executable, "-I", str(SCRIPT), "--url-file", str(self.url_file) + ".absent"],
                           capture_output=True, text=True, check=False)
        self.assertEqual(r.returncode, 2, r.stdout + r.stderr)
        self.assertIn("::error::", r.stdout + r.stderr)
        for bad in ("not-a-url", "host=h dbname=d password=" + GOOD, "", "postgres://u:" + GOOD + "@h/db\nsecond"):
            with self.subTest(bad=bad[:16]):
                r = self.run_check(bad, raw=True)
                self.assertEqual(r.returncode, 2, r.stdout + r.stderr)
                self.assertIn("::error::", r.stdout + r.stderr)
                self.assertNotIn(GOOD, r.stdout + r.stderr)


if __name__ == "__main__":
    sys.exit(unittest.main())
