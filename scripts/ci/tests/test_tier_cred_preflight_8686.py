#!/usr/bin/env python3
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""Pin scripts/ci/tier_cred_preflight.py and its ci.yml wiring (#8686).

Invariant: every enterprise-fed runner authenticates to the native CI tier with
the credential source the workflow reads (``$HOME/.ai-memory-ci-fed-url``)
BEFORE the leg's ``CREATE DATABASE``; a rejected credential fails the leg with
the distinct reason ``tier credential mismatch``, never a generic CREATE
DATABASE failure.  Every other failure has its own distinct reason, and no
output line carries the password, the URL or psql's stderr.

The helper is driven against a fake psql (a Python stub) so no live Postgres is
needed.  Scratch lives under the repo's ``.local-runs`` (never /tmp).

Run: python3 -m unittest discover -s scripts/ci/tests
"""

import importlib.util
import io
import os
import re
import shutil
import signal
import stat
import subprocess
import sys
import time
import unittest
import uuid
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
HELPER_PATH = REPO / "scripts" / "ci" / "tier_cred_preflight.py"
CI_YML = REPO / ".github" / "workflows" / "ci.yml"
SCRATCH_ROOT = REPO / ".local-runs" / "tier-cred-preflight-8686"

PASSWORD = "Zq8-preflight-8686-secret-Kx"  # fixture only; asserted absent from every output
USER = "ai_memory"
DATABASE = "ai_memory_test"
CA_NAME = "ca.crt"

# Exit codes the workflow relies on (pinned against the helper's own constants below).
EXIT_OK = 0
EXIT_UNAVAILABLE = 1
EXIT_BAD_INPUT = 2
EXIT_MISMATCH = 3

MISMATCH_REASON = "tier credential mismatch"
UNREACHABLE_REASON = "tier unreachable"
TLS_REASON = "tier TLS verification failed"
TIMEOUT_REASON = "tier pre-flight timed out"
OTHER_REASON = "tier pre-flight failed"

# Real libpq / server stderr shapes, one per class (table-driven corpus).
MISMATCH_CORPUS = (
    'psql: error: connection to server at "127.0.0.1", port 5445 failed: FATAL:  password authentication failed '
    'for user "ai_memory"',
    'psql: error: connection to server at "127.0.0.1", port 5445 failed: fe_sendauth: no password supplied',
    'psql: error: connection to server at "127.0.0.1", port 5445 failed: FATAL:  role "ai_memory" does not exist',
    "FATAL:  password authentication failed for user \"ai_memory\"\r\nFATAL:  password authentication failed",
)
UNREACHABLE_CORPUS = (
    'psql: error: connection to server at "127.0.0.1", port 5445 failed: Connection refused\n'
    "\tIs the server running on that host and accepting TCP/IP connections?",
    'psql: error: connection to server at "127.0.0.1", port 5445 failed: timeout expired',
    'psql: error: could not translate host name "nohost.invalid" to address: nodename nor servname provided',
    'psql: error: connection to server at "127.0.0.1", port 5445 failed: FATAL:  the database system is starting up',
    'psql: error: connection to server at "127.0.0.1", port 5445 failed: FATAL:  the database system is shutting down',
    'psql: error: connection to server at "10.1.2.3", port 5445 failed: No route to host',
    'psql: error: connection to server at "10.1.2.3", port 5445 failed: Network is unreachable',
    'psql: error: connection to server on socket "/run/postgresql/.s.PGSQL.5432" failed: No such file or directory',
)
TLS_CORPUS = (
    'psql: error: connection to server at "127.0.0.1", port 5445 failed: SSL error: certificate verify failed',
    'psql: error: connection to server at "127.0.0.1", port 5445 failed: server certificate for "x" does not match '
    'host name "127.0.0.1"',
    'psql: error: connection to server at "127.0.0.1", port 5445 failed: root certificate file "/x/ca.crt" does not '
    "exist",
    'psql: error: connection to server at "127.0.0.1", port 5445 failed: SSL SYSCALL error: EOF detected',
    'psql: error: connection to server at "127.0.0.1", port 5445 failed: certificate verify failed',
    'psql: error: connection to server at "127.0.0.1", port 5445 failed: SSL error: unexpected eof',
    # S4: a missing client certificate or key file is a TLS failure, not "tier unreachable"
    'psql: error: could not open certificate file "/x/client.crt": No such file or directory',
    'psql: error: could not load private key file "/x/client.key": No such file or directory',
    'psql: error: could not stat private key file "/x/client.key": No such file or directory',
    'psql: error: could not open private key file "/x/client.key": No such file or directory',
)

# Every marker the helper matches, pinned here independently of the helper (removing one from the helper turns
# test_every_marker_alone_gets_its_class red; adding one without a row turns test_marker_set_is_pinned red).
EXPECTED_MARKERS = (
    (MISMATCH_REASON, "password authentication failed"),
    (MISMATCH_REASON, "no password supplied"),
    (TLS_REASON, "certificate verify failed"),
    (TLS_REASON, "server certificate for"),
    (TLS_REASON, "root certificate file"),
    (TLS_REASON, "SSL error"),
    (TLS_REASON, "SSL SYSCALL error"),
    (TLS_REASON, "could not open certificate file"),
    (TLS_REASON, "could not load private key file"),
    (TLS_REASON, "could not stat private key file"),
    (TLS_REASON, "could not open private key file"),
    (UNREACHABLE_REASON, "Connection refused"),
    (UNREACHABLE_REASON, "timeout expired"),
    (UNREACHABLE_REASON, "could not translate host name"),
    (UNREACHABLE_REASON, "No route to host"),
    (UNREACHABLE_REASON, "Network is unreachable"),
    (UNREACHABLE_REASON, "the database system is starting up"),
    (UNREACHABLE_REASON, "the database system is shutting down"),
    (UNREACHABLE_REASON, "No such file or directory"),
)
EXPECTED_CODE = {MISMATCH_REASON: EXIT_MISMATCH, TLS_REASON: EXIT_UNAVAILABLE, UNREACHABLE_REASON: EXIT_UNAVAILABLE}
# Check order the helper's comment claims: mismatch, then TLS, then unreachable.
CLASS_ORDER = (MISMATCH_REASON, TLS_REASON, UNREACHABLE_REASON)
INTERRUPTED_REASON = "tier pre-flight interrupted"
SIGNAL_DEATH_RC = 137  # the supervisor reports a psql killed by signal 9 as 128+9
PID_POLL_SECONDS = 10.0
OTHER_CORPUS = (
    "",
    'psql: error: connection to server at "127.0.0.1", port 5445 failed: FATAL:  database "ai_memory_test" does not '
    "exist",
    "psql: error: out of memory",
)

LARGE_INPUT_BYTES = 400_000  # an input scanner gets a 100K+ input with a wall-clock ceiling
LARGE_INPUT_CEILING_SECONDS = 1.0
FAKE_TIMEOUT_SECONDS = 2  # the helper's timeout in the hang test; the fake sleeps longer

FAKE_PSQL = """#!{py}
import os, sys, time, json
mode = {mode!r}
with open({record!r}, "w") as fh:
    json.dump({{"argv": sys.argv[1:], "pgpassword": os.environ.get("PGPASSWORD"),
               "pgdatabase": os.environ.get("PGDATABASE"),
               "lc_all": os.environ.get("LC_ALL"),
               "service": [k for k in os.environ if k in ("PGSERVICE", "PGSERVICEFILE", "PGPASSFILE", "PGUSER")]}}, fh)
pw = os.environ.get("PGPASSWORD", "")
if mode == "ok":
    print("1")
    sys.exit(0)
if mode == "garbage":
    print("not-one " + pw)
    sys.exit(0)
if mode == "one-then-fail":
    print("1")
    sys.stderr.write({stderr!r} + "\\n")
    sys.exit(2)
if mode == "one-then-signal":
    print("1", flush=True)
    os.kill(os.getpid(), 9)
if mode == "hang":
    with open({record!r} + ".pid", "w") as fh:
        fh.write(str(os.getpid()))
    time.sleep(60)
    sys.exit(0)
# every failure echoes the password and the argv URL into stderr: the helper must never relay it
sys.stderr.write({stderr!r} + " pw=" + pw + " argv=" + " ".join(sys.argv[1:]) + "\\n")
sys.exit(2)
"""


def load_helper():
    spec = importlib.util.spec_from_file_location("tier_cred_preflight", HELPER_PATH)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def read_pid(record):
    return int(Path(str(record) + ".pid").read_text())


def is_alive(pid):
    """True while the process exists and is not a zombie (``ps`` works on Linux and macOS)."""
    state = subprocess.run(["ps", "-o", "stat=", "-p", str(pid)], capture_output=True, text=True).stdout.strip()
    return bool(state) and not state.startswith("Z")


def wait_gone(pid, seconds=PID_POLL_SECONDS):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if not is_alive(pid):
            return True
        time.sleep(0.05)
    return not is_alive(pid)


def kill_quietly(pid):
    try:
        os.kill(pid, signal.SIGKILL)
    except OSError:
        pass


def write_exe(path, text):
    path.write_text(text)
    path.chmod(stat.S_IRWXU)


def configure_step(text):
    """The lines of the `Configure enterprise-fed tier` step."""
    lines = text.splitlines()
    start = next(i for i, ln in enumerate(lines) if ln.strip().startswith("- name: Configure enterprise-fed tier"))
    indent = len(lines[start]) - len(lines[start].lstrip())
    end = start + 1
    while end < len(lines) and not (lines[end].strip() and len(lines[end]) - len(lines[end].lstrip()) <= indent
                                    and lines[end].lstrip().startswith("- ")):
        end += 1
    return [ln.strip() for ln in lines[start:end]]


PREFLIGHT_CALL = 'if ! python3 -I scripts/ci/tier_cred_preflight.py --url-file "$url_file"; then'
CREATE_DB = 'if ! psql "$base_url" -v ON_ERROR_STOP=1 -c "CREATE DATABASE \\"$CI_FED_DB\\";"; then'
URL_FILE_LINE = 'url_file="$HOME/.ai-memory-ci-fed-url"'
STEP_IF = "if: needs.classify.outputs.cargo_skip != 'true' && matrix.tier == 'enterprise-fed'"

# shell compound commands: a command word that opens one, and the word that closes it
_START = r"(?:^|[;&|(]\s*|\bthen\s+|\bdo\s+|\belse\s+|\belif\s+[^;]*;\s*then\s+)"
OPENERS = re.compile(_START + r"(if|case|for|while|until|select)\b")
CLOSERS = re.compile(_START + r"(fi|esac|done)\b")
BRACE_OPEN = re.compile(r"(?:^|\s)\{\s*$|\)\s*\{\s*$")
BRACE_CLOSE = re.compile(r"^\}")
SKIPPERS = re.compile(r"(?:^|[;&|(]\s*|\bthen\s+|\bdo\s+|\belse\s+)(exit|return|break|continue)\b(?!\s+1\b)")
CONTINUATION = re.compile(r"(?:&&|\|\||\\|\|)\s*$")


def run_block(step):
    """The lines of the step's ``run: |`` script (comments and blanks dropped)."""
    start = next(i for i, ln in enumerate(step) if ln.startswith("run:"))
    return [ln for ln in step[start + 1:] if ln and not ln.startswith("#")]


def skip_problems(block, call):
    """Everything above the call that can make a leg skip it, by shell structure, at any distance."""
    found, depth = [], 0
    for line in block[:call]:
        code = re.sub(r"\s+#.*$", "", line)
        depth += len(OPENERS.findall(code)) - len(CLOSERS.findall(code))
        depth += (1 if BRACE_OPEN.search(code) else 0) - (1 if BRACE_CLOSE.match(code) else 0)
        if SKIPPERS.search(code):
            found.append("a line above the pre-flight can leave the step early: `%s`" % line)
        if CONTINUATION.search(code):
            found.append("a line above the pre-flight continues into the next one: `%s`" % line)
        if "|| true" in code or "|| :" in code:
            found.append("a line above the pre-flight swallows a failure: `%s`" % line)
    if depth != 0:
        found.append("the pre-flight sits inside %d open compound command(s) (if/case/for/while/brace); it must be "
                     "top-level so no leg can skip it" % depth)
    return found


def wiring_problems(text):
    """Every way the ci.yml pre-flight could be skipped, moved after CREATE DATABASE or made to pass on failure."""
    found = []
    try:
        step = configure_step(text)
    except StopIteration:
        return ["the Configure enterprise-fed tier step is gone"]
    body = "\n".join(step)
    if STEP_IF not in step:
        found.append("the step's `if:` must stay exactly `%s`: no leg may be excluded from the pre-flight" % STEP_IF)
    block = run_block(step)
    calls = [i for i, s in enumerate(block) if "tier_cred_preflight.py" in s]
    if len(calls) != 1 or block[calls[0]] != PREFLIGHT_CALL:
        return found + ["the pre-flight must run exactly once as `%s`" % PREFLIGHT_CALL]
    i = calls[0]
    if block[i + 1] != "exit 1" or block[i + 2] != "fi":
        found.append("the pre-flight failure branch must be exactly `exit 1` then `fi`")
    if URL_FILE_LINE not in block or block.index(URL_FILE_LINE) > i:
        found.append("the pre-flight must read the same url_file the step reads, after it is set")
    if CREATE_DB not in block or block.index(CREATE_DB) < i:
        found.append("the pre-flight must run before CREATE DATABASE")
    found.extend(skip_problems(block, i))
    if "continue-on-error" in body:
        found.append("the step sets continue-on-error")
    return found


class Scratch(unittest.TestCase):
    def setUp(self):
        self.dir = SCRATCH_ROOT / uuid.uuid4().hex
        self.dir.mkdir(parents=True)
        self.addCleanup(shutil.rmtree, self.dir, True)
        self.ca = self.dir / CA_NAME
        self.ca.write_text("fixture")
        self.url_file = self.dir / "fed-url"
        self.record = self.dir / "record.json"
        self.psql = self.dir / "psql"
        self.write_url(f"postgres://{USER}:{PASSWORD}@127.0.0.1:5445/{DATABASE}"
                       f"?sslmode=verify-full&sslrootcert={self.ca}")
        self.mod = load_helper()

    def write_url(self, url):
        self.url_file.write_text(url + "\n")
        self.url_file.chmod(0o600)

    def fake(self, mode, stderr=""):
        write_exe(self.psql, FAKE_PSQL.format(py=sys.executable, mode=mode, record=str(self.record), stderr=stderr))

    def run_main(self, *extra):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = self.mod.main(["--url-file", str(self.url_file), "--psql", str(self.psql), *extra])
        return code, out.getvalue(), err.getvalue()

    def assert_no_secret(self, *texts):
        for t in texts:
            self.assertNotIn(PASSWORD, t)
            self.assertNotIn("://" + USER, t)  # no URL (the scheme name alone may appear in a refusal)
            self.assertNotIn("@127.0.0.1", t)
            self.assertNotIn("pw=", t)  # the fake's stderr is never relayed


class TestClassify(unittest.TestCase):
    def setUp(self):
        self.mod = load_helper()

    def test_exit_codes_are_pinned(self):
        self.assertEqual((self.mod.EXIT_OK, self.mod.EXIT_UNAVAILABLE, self.mod.EXIT_BAD_INPUT, self.mod.EXIT_MISMATCH),
                         (EXIT_OK, EXIT_UNAVAILABLE, EXIT_BAD_INPUT, EXIT_MISMATCH))

    def test_every_corpus_line_gets_its_class(self):
        table = ([(s, MISMATCH_REASON, EXIT_MISMATCH) for s in MISMATCH_CORPUS]
                 + [(s, UNREACHABLE_REASON, EXIT_UNAVAILABLE) for s in UNREACHABLE_CORPUS]
                 + [(s, TLS_REASON, EXIT_UNAVAILABLE) for s in TLS_CORPUS]
                 + [(s, OTHER_REASON, EXIT_UNAVAILABLE) for s in OTHER_CORPUS])
        for stderr, reason, code in table:
            with self.subTest(stderr=stderr[:70]):
                self.assertEqual(self.mod.classify(2, stderr), (reason, code))

    def test_mismatch_wins_over_other_text_in_the_same_stderr(self):
        # a multi-host attempt can print a refused host first and the auth failure second
        stderr = UNREACHABLE_CORPUS[0] + "\n" + MISMATCH_CORPUS[0]
        self.assertEqual(self.mod.classify(2, stderr), (MISMATCH_REASON, EXIT_MISMATCH))

    def test_marker_set_is_pinned(self):
        got = tuple((reason, marker) for reason, _code, markers in self.mod.CLASSES for marker in markers)
        self.assertEqual(sorted(got), sorted(EXPECTED_MARKERS))
        self.assertEqual(tuple(reason for reason, _c, _m in self.mod.CLASSES), CLASS_ORDER)

    def test_every_marker_alone_gets_its_class(self):
        for reason, marker in EXPECTED_MARKERS:
            with self.subTest(marker=marker):
                self.assertEqual(self.mod.classify(2, f"psql: error: {marker}"), (reason, EXPECTED_CODE[reason]))

    def test_role_missing_alone_is_a_mismatch(self):
        stderr = 'FATAL:  role "ai_memory" does not exist'
        self.assertEqual(self.mod.classify(2, stderr), (MISMATCH_REASON, EXIT_MISMATCH))

    def test_check_order_is_mismatch_then_tls_then_unreachable(self):
        by_reason = {MISMATCH_REASON: MISMATCH_CORPUS[0], TLS_REASON: TLS_CORPUS[0],
                     UNREACHABLE_REASON: UNREACHABLE_CORPUS[0]}
        for i, early in enumerate(CLASS_ORDER):
            for late in CLASS_ORDER[i + 1:]:
                for first, second in ((early, late), (late, early)):  # the winner is independent of print order
                    with self.subTest(early=early, late=late, printed=first):
                        stderr = by_reason[first] + "\n" + by_reason[second]
                        self.assertEqual(self.mod.classify(2, stderr), (early, EXPECTED_CODE[early]))
        # a missing client certificate also prints "No such file or directory": TLS wins over unreachable
        both = TLS_CORPUS[-4] + "\n" + UNREACHABLE_CORPUS[-1]
        self.assertEqual(self.mod.classify(2, both), (TLS_REASON, EXIT_UNAVAILABLE))
        # role_missing is the mismatch class too, ahead of TLS
        role = 'FATAL:  role "ai_memory" does not exist\n' + TLS_CORPUS[0]
        self.assertEqual(self.mod.classify(2, role), (MISMATCH_REASON, EXIT_MISMATCH))

    def test_classify_is_linear_on_a_large_input(self):
        filler = "x" * LARGE_INPUT_BYTES
        for stderr, want in ((filler + MISMATCH_CORPUS[0], MISMATCH_REASON), (filler, OTHER_REASON),
                             ("FATAL: " * (LARGE_INPUT_BYTES // 7), OTHER_REASON)):
            t0 = time.monotonic()
            got = self.mod.classify(2, stderr)
            self.assertLess(time.monotonic() - t0, LARGE_INPUT_CEILING_SECONDS)
            self.assertEqual(got[0], want)

    def test_reason_lines_name_no_secret_shape(self):
        for reason in (MISMATCH_REASON, UNREACHABLE_REASON, TLS_REASON, TIMEOUT_REASON, OTHER_REASON):
            line = self.mod.reason_line(reason, Path("/u/.ai-memory-ci-fed-url"), "runner-x", 2)
            self.assertIn(reason, line)
            self.assertTrue(line.startswith("::error::"), line)
            self.assertNotIn("postgres://", line)


class TestMain(Scratch):
    def test_ok_when_the_tier_accepts_the_credential(self):
        self.fake("ok")
        code, out, err = self.run_main()
        self.assertEqual(code, EXIT_OK)
        self.assertIn("tier credential ok", out)
        self.assert_no_secret(out, err)

    def test_auth_failure_is_a_distinct_credential_mismatch(self):
        self.fake("fail", stderr=MISMATCH_CORPUS[0])
        code, out, err = self.run_main()
        self.assertEqual(code, EXIT_MISMATCH)
        self.assertIn("::error::", out)
        self.assertIn(MISMATCH_REASON, out)
        self.assertIn(str(self.url_file), out)
        self.assertNotIn("CREATE DATABASE", out)
        self.assert_no_secret(out, err)

    def test_each_failure_class_end_to_end(self):
        for stderr, reason, want in ((UNREACHABLE_CORPUS[0], UNREACHABLE_REASON, EXIT_UNAVAILABLE),
                                     (TLS_CORPUS[0], TLS_REASON, EXIT_UNAVAILABLE),
                                     (OTHER_CORPUS[1], OTHER_REASON, EXIT_UNAVAILABLE)):
            with self.subTest(reason=reason):
                self.fake("fail", stderr=stderr)
                code, out, err = self.run_main()
                self.assertEqual(code, want)
                self.assertIn(reason, out)
                self.assertNotIn(MISMATCH_REASON, out)
                self.assert_no_secret(out, err)

    def test_a_zero_exit_without_the_answer_is_not_ok(self):
        self.fake("garbage")
        code, out, err = self.run_main()
        self.assertEqual(code, EXIT_UNAVAILABLE)
        self.assertIn(OTHER_REASON, out)
        self.assert_no_secret(out, err)

    def test_a_hung_psql_times_out(self):
        self.fake("hang")
        t0 = time.monotonic()
        code, out, err = self.run_main("--timeout", str(FAKE_TIMEOUT_SECONDS))
        self.assertLess(time.monotonic() - t0, FAKE_TIMEOUT_SECONDS + 10)
        self.assertEqual(code, EXIT_UNAVAILABLE)
        self.assertIn(TIMEOUT_REASON, out)
        self.assert_no_secret(out, err)

    def test_a_nonzero_exit_that_printed_the_answer_is_never_ok(self):
        # S2: stdout "1" with a non-zero psql exit is a failure; only exit 0 AND the answer pass
        self.fake("one-then-fail", stderr=OTHER_CORPUS[2])
        code, out, err = self.run_main()
        self.assertEqual(code, EXIT_UNAVAILABLE)
        self.assertIn(OTHER_REASON, out)
        self.assertNotIn("tier credential ok", out)
        self.assert_no_secret(out, err)

    def test_a_nonzero_exit_that_printed_the_answer_keeps_its_class(self):
        self.fake("one-then-fail", stderr=MISMATCH_CORPUS[0])
        code, out, err = self.run_main()
        self.assertEqual(code, EXIT_MISMATCH)
        self.assertIn(MISMATCH_REASON, out)
        self.assertNotIn("tier credential ok", out)
        self.assert_no_secret(out, err)

    def test_a_psql_killed_by_a_signal_is_never_ok(self):
        self.fake("one-then-signal")
        code, out, err = self.run_main()
        self.assertEqual(code, EXIT_UNAVAILABLE)
        self.assertIn(OTHER_REASON, out)
        self.assertIn(f"psql exited {SIGNAL_DEATH_RC}", out)
        self.assertNotIn("tier credential ok", out)
        self.assert_no_secret(out, err)

    def test_a_timed_out_psql_does_not_survive(self):
        self.fake("hang")
        code, out, _err = self.run_main("--timeout", str(FAKE_TIMEOUT_SECONDS))
        self.assertEqual(code, EXIT_UNAVAILABLE)
        self.assertIn(TIMEOUT_REASON, out)
        self.assertTrue(wait_gone(read_pid(self.record)), "psql outlived the pre-flight timeout")

    def _run_and_signal(self, signum):
        """Start the helper as a process, wait for the fake psql to run, send ``signum``; return (rc, stdout, pid)."""
        self.fake("hang")
        env = {k: v for k, v in os.environ.items() if k in ("PATH", "HOME", "LANG")}
        env["RUNNER_NAME"] = "runner-x"
        proc = subprocess.Popen([sys.executable, "-I", str(HELPER_PATH), "--url-file", str(self.url_file),
                                 "--psql", str(self.psql)], env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                text=True, start_new_session=True)
        self.addCleanup(lambda: proc.poll() is None and os.killpg(proc.pid, signal.SIGKILL))
        pid_file = Path(str(self.record) + ".pid")
        deadline = time.monotonic() + PID_POLL_SECONDS
        while not pid_file.exists() and time.monotonic() < deadline:
            time.sleep(0.05)
        self.assertTrue(pid_file.exists(), "the fake psql never started")
        time.sleep(0.2)  # the pid file is written first; let the helper reach its wait
        pid = read_pid(self.record)
        self.addCleanup(kill_quietly, pid)
        proc.send_signal(signum)
        out, err = proc.communicate(timeout=PID_POLL_SECONDS * 2)
        return proc.returncode, out, err, pid

    def test_sigterm_and_sigint_leave_no_psql_behind(self):
        # S1: an interrupted pre-flight must not orphan a psql that holds PGPASSWORD (sibling of #6252 / #6337)
        for signum in (signal.SIGTERM, signal.SIGINT):
            with self.subTest(signal=signum.name):
                rc, out, err, pid = self._run_and_signal(signum)
                self.assertEqual(rc, EXIT_UNAVAILABLE)
                self.assertIn(INTERRUPTED_REASON, out)
                self.assertTrue(wait_gone(pid), f"psql {pid} survived {signum.name}")
                self.assert_no_secret(out, err)
                for leftover in self.dir.glob("record.json*"):
                    leftover.unlink()

    def test_the_password_travels_in_pgpassword_never_argv(self):
        import json
        os.environ["PGSERVICE"] = "x"  # a caller PG* variable must not reach psql
        self.addCleanup(os.environ.pop, "PGSERVICE", None)
        self.fake("ok")
        self.assertEqual(self.run_main()[0], EXIT_OK)
        rec = json.loads(self.record.read_text())
        self.assertEqual(rec["pgpassword"], PASSWORD)
        self.assertEqual(rec["pgdatabase"], DATABASE)
        self.assertEqual(rec["service"], [])
        self.assertEqual(rec["lc_all"], "C")  # libpq messages are classified in the C locale
        self.assertFalse(any(PASSWORD in a for a in rec["argv"]), rec["argv"])
        self.assertFalse(any(DATABASE in a for a in rec["argv"]), rec["argv"])

    def test_bad_url_files_are_refused_before_psql(self):
        self.fake("ok")
        cases = {
            "missing": None,
            "empty": "",
            "no-tls": f"postgres://{USER}:{PASSWORD}@127.0.0.1:5445/{DATABASE}",
            "keyword-dsn": f"host=127.0.0.1 password={PASSWORD} dbname={DATABASE}",
        }
        for name, url in cases.items():
            with self.subTest(case=name):
                if self.record.exists():
                    self.record.unlink()
                if url is None:
                    self.url_file.unlink(missing_ok=True)
                else:
                    self.write_url(url)
                code, out, err = self.run_main()
                self.assertEqual(code, EXIT_BAD_INPUT)
                self.assertFalse(self.record.exists(), "psql ran on a refused URL file")
                self.assertIn("tier URL file", out)
                self.assert_no_secret(out, err)

    def test_missing_psql_is_unavailable(self):
        code, out, err = self.run_main()  # no fake written
        self.assertEqual(code, EXIT_UNAVAILABLE)
        self.assertIn("psql", out)
        self.assert_no_secret(out, err)


class TestWiring(unittest.TestCase):
    def test_ci_runs_the_preflight_before_create_database(self):
        self.assertEqual(wiring_problems(CI_YML.read_text()), [])

    def test_the_wiring_check_rejects_each_mutant(self):
        text = CI_YML.read_text()
        call_block = "          if ! python3 -I scripts/ci/tier_cred_preflight.py --url-file \"$url_file\"; then\n" \
                     "            exit 1\n          fi\n"
        self.assertIn(call_block, text)
        wrap = lambda head, tail="fi": head + "\n" + call_block + "          " + tail + "\n"  # noqa: E731
        first_line = "          url_file=\"$HOME/.ai-memory-ci-fed-url\"\n"
        self.assertIn(first_line, text)
        mutants = {
            "removed": text.replace(call_block, ""),
            "or-true": text.replace(call_block, call_block.replace("exit 1", "true")),
            "no-isolation": text.replace("python3 -I scripts/ci/tier_cred_preflight.py",
                                         "python3 scripts/ci/tier_cred_preflight.py"),
            "after-create": text.replace(call_block, "").replace(
                "          # Rewrite the base URL's db-name", call_block + "          # Rewrite the base URL's db-name", 1),
            "node-guarded": text.replace(call_block, wrap('          if [ "${CI_NODE:-}" = "macos-fed" ]; then')),
            "os-guarded": text.replace(call_block, wrap('          if [ "${RUNNER_OS:-}" = "macOS" ]; then')),
            "leg-guarded": text.replace(call_block, wrap('          if [ "$LEG" = "linux-fed" ]; then')),
            "runner-guarded": text.replace(call_block, wrap('          if [ -n "${RUNNER_NAME:-}" ]; then')),
            "else-branch": text.replace(call_block, wrap('          if [ -z "${CI_PG_ISOLATE_OFF:-}" ]; then\n'
                                                         "            :\n          else")),
            "case-wrapped": text.replace(call_block, wrap('          case "$LEG" in\n            *) ', "  ;;\n          esac")),
            "for-wrapped": text.replace(call_block, wrap('          for _ in 1; do', "done")),
            "brace-wrapped": text.replace(call_block, wrap("          {", "}")),
            "guard-far-above": text.replace(first_line, '          if [ "${CI_PG_ISOLATE_OFF:-}" != "1" ]; then\n'
                                            + first_line).replace(call_block, call_block + "          fi\n"),
            "early-exit-above": text.replace(call_block, '          if [ "$LEG" = "x" ]; then\n            exit 0\n'
                                             "          fi\n" + call_block),
            "and-exit-above": text.replace(call_block, '          [ "$LEG" = "x" ] && exit 0\n' + call_block),
            "return-above": text.replace(call_block, '          if [ "$LEG" = "x" ]; then\n            return 0\n'
                                         "          fi\n" + call_block),
            "step-if-narrowed": text.replace(
                "if: needs.classify.outputs.cargo_skip != 'true' && matrix.tier == 'enterprise-fed'\n        shell: bash",
                "if: needs.classify.outputs.cargo_skip != 'true' && matrix.tier == 'enterprise-fed' && "
                "matrix.node != 'macos-fed'\n        shell: bash"),
            "continue-on-error": text.replace("        shell: bash\n        env:\n          # matrix.leg via env",
                                              "        shell: bash\n        continue-on-error: true\n        env:\n"
                                              "          # matrix.leg via env"),
        }
        for name, mutant in mutants.items():
            with self.subTest(mutant=name):
                self.assertNotEqual(mutant, text)
                self.assertNotEqual(wiring_problems(mutant), [], name)


if __name__ == "__main__":
    unittest.main()
