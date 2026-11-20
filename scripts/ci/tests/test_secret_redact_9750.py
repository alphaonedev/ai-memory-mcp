#!/usr/bin/env python3
"""#9750: every CI output sink that can carry PostgreSQL connection data redacts every credential form.

Class: a credential reached a job log in a form the URL pattern alone does not cover (the keyword form
``password=...``, the environment form ``PGPASSWORD=...``, a quoted value with a blank in it).
Invariant: for every form in FORMS, each sink prints the exact redacted text written out below (no byte
of the made-up secret survives), and redaction is linear: a 100K-line input and a 100K-character line
each finish under BOUND_SECS.

Sinks (one funnel, scripts/ci/secret_redact.py, behind each):
* pg_isolate_serial_step.redact (every step line, every per-binary log), URL label ``<redacted-url>``;
* pg_env_preflight._detail (the psql stderr detail of a failed probe), URL label ``<redacted>``;
* pg_isolated_binary.log / _stderr_note / the log-tail lines (wrapper diagnostics), ``<redacted-url>``.

Every value here is made up (FAKE); no real host, user or password appears.

Run: python3 -m unittest discover -s scripts/ci/tests -p test_secret_redact_9750.py
"""
import contextlib
import importlib.util
import io
import subprocess
import time
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
CI = HERE.parent
REPO = HERE.parents[2]
STEP = CI / "pg_isolate_serial_step.py"
PREFLIGHT = CI / "pg_env_preflight.py"
WRAPPER = REPO / "scripts" / "test" / "pg_isolated_binary.py"
FUNNEL = CI / "secret_redact.py"
FAKE = "fakepw9750"
BIG_LINES = 100_000
BIG_CHARS = 100_000
BOUND_SECS = 5.0
URL = "<redacted-url>"
VAL = "<redacted>"

# (label, input line, expected with the URL label written as {u}); one row per form, written out by hand.
FORMS = (
    ("url bare", "connect postgresql://u:%s@db.invalid:5432/x failed" % FAKE, "connect {u} failed"),
    ("url quoted with a blank", 'url="postgresql://u:fake %s@db.invalid/x" next' % FAKE, 'url="{u}" next'),
    ("url single quote unclosed", "dsn 'postgresql://u:%s@db.invalid/x" % FAKE, "dsn '{u}'"),
    ("keyword", "FATAL: password=%s host=db.invalid" % FAKE, "FATAL: password=%s host=db.invalid" % VAL),
    ("keyword spaced single-quoted", "password = 'fake %s' user=u" % FAKE, "password = %s user=u" % VAL),
    ("keyword escaped quote", "password='fa\\'%s' x" % FAKE, "password=%s x" % VAL),
    ("keyword unclosed double quote", 'password="fake %s' % FAKE, "password=%s" % VAL),
    ("keyword colon any case", "Password: %s" % FAKE, "Password: %s" % VAL),
    ("keyword option", "--password=%s --host=db.invalid" % FAKE, "--password=%s --host=db.invalid" % VAL),
    ("keyword passwd", "passwd=%s" % FAKE, "passwd=%s" % VAL),
    ("keyword in a longer word", "db_password=%s" % FAKE, "db_password=%s" % VAL),
    ("json key", '{"password": "%s", "user": "u"}' % FAKE, '{"password": %s, "user": "u"}' % VAL),
    ("env", "PGPASSWORD=%s psql -X" % FAKE, "PGPASSWORD=%s psql -X" % VAL),
    ("env export double-quoted", 'export PGPASSWORD="fake %s"' % FAKE, "export PGPASSWORD=%s" % VAL),
    ("env export single-quoted", "export PGPASSWORD='%s'" % FAKE, "export PGPASSWORD=%s" % VAL),
    ("clean line unchanged", "test alpha_9750 ... ok", "test alpha_9750 ... ok"),
    ("key without a value unchanged", "password= ", "password= "),
)


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, str(path))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


STEP_MOD = load("pg_isolate_serial_step_9750", STEP)
PREFLIGHT_MOD = load("pg_env_preflight_9750", PREFLIGHT)
WRAPPER_MOD = load("pg_isolated_binary_9750", WRAPPER)


def wrapper_stderr(call, *args):
    buf = io.StringIO()
    with contextlib.redirect_stderr(buf):
        call(*args)
    return buf.getvalue()


class EveryFormEverySink(unittest.TestCase):
    def test_serial_step_redact(self):
        for label, raw, expected in FORMS:
            self.assertEqual(STEP_MOD.redact(raw), expected.format(u=URL), label)

    def test_preflight_detail(self):
        for label, raw, expected in FORMS:
            proc = subprocess.CompletedProcess(["psql"], 2, stdout="", stderr=raw + "\nsecond line\n")
            self.assertEqual(PREFLIGHT_MOD._detail(proc), expected.format(u=VAL), label)

    def test_wrapper_log(self):
        wa = WRAPPER_MOD.wa
        for label, raw, expected in FORMS:
            got = wrapper_stderr(WRAPPER_MOD.log, raw)
            self.assertEqual(got, wa.log_line("[pg_isolated_binary] " + expected.format(u=URL)) + "\n", label)

    def test_wrapper_stderr_note(self):
        wa = WRAPPER_MOD.wa
        for label, raw, expected in FORMS:
            got = wrapper_stderr(WRAPPER_MOD._stderr_note, raw)
            self.assertEqual(got, wa.log_line(expected.format(u=URL)) + "\n", label)

    def test_no_sink_keeps_the_fake_secret(self):
        for label, raw, _ in FORMS:
            proc = subprocess.CompletedProcess(["psql"], 2, stdout="", stderr=raw)
            outs = (STEP_MOD.redact(raw), PREFLIGHT_MOD._detail(proc), wrapper_stderr(WRAPPER_MOD.log, raw),
                    wrapper_stderr(WRAPPER_MOD._stderr_note, raw))
            for out in outs:
                self.assertNotIn(FAKE, out, label)


class LinearBound(unittest.TestCase):
    def assert_fast(self, text):
        start = time.monotonic()
        out = STEP_MOD.redact(text)
        elapsed = time.monotonic() - start
        self.assertLess(elapsed, BOUND_SECS, "%d chars took %.2fs" % (len(text), elapsed))
        self.assertFalse(FAKE in out, "the made-up secret survived in a %d-char input" % len(text))

    def test_100k_lines_of_every_form(self):
        rows = [raw for _, raw, _ in FORMS]
        text = "\n".join(rows[i % len(rows)] for i in range(BIG_LINES))
        self.assert_fast(text)

    def test_100k_char_pathological_lines(self):
        for line in ("a" * BIG_CHARS + " password=" + FAKE,
                     "password=" * (BIG_CHARS // 9) + FAKE,
                     "'" * BIG_CHARS + " PGPASSWORD=" + FAKE,
                     "a://" * (BIG_CHARS // 4) + " password=" + FAKE,
                     "x=" * (BIG_CHARS // 2) + " password=" + FAKE,
                     'password="' + "\\" * BIG_CHARS + FAKE):
            with self.subTest(prefix=line[:12]):
                self.assert_fast(line)


if __name__ == "__main__":
    unittest.main()
