# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""CLI regression tests for the opt-in PR-body suspicion check (#7339)."""

import contextlib
import array
import fcntl
import importlib.util
import io
import os
from pathlib import Path
import select
import signal
import subprocess
import sys
import tempfile
import termios
import time
import unittest

HELPER = Path(__file__).resolve().parents[1] / "check_pr_body_ids.py"
SCRATCH = Path(__file__).resolve().parents[3] / ".local-runs"
TIMEOUT_SECONDS = 10
PENDING_CHECK_SECONDS = 0.1
STDIN_BOUNDARY_BYTES = 4096
LARGE_REPORT_BYTES = 16000
PARSER_TERMINALS = (("-h",), ("--help",), ("--unknown",), ("--file",))
PARSER_BOOTSTRAP = (
    "import runpy,sys; "
    "sys.stdout.reconfigure(line_buffering=False,write_through=False); "
    "sys.stderr.reconfigure(line_buffering=False,write_through=False); "
    "sys.argv=sys.argv[1:]; runpy.run_path(sys.argv[0],run_name='__main__')"
)


class BodyIds7339Tests(unittest.TestCase):
    def invoke(self, body=b"", *args, env=None):
        return subprocess.run(
            [sys.executable, str(HELPER), *args], input=body,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=TIMEOUT_SECONDS, env=env,
        )

    def check_body(self, body, hits, lines, details=""):
        result = self.invoke(body.encode("utf-8"))
        self.assertEqual(result.returncode, 1 if hits else 0, result.stderr)
        self.assertEqual(result.stderr, b"")
        self.assertEqual(result.stdout.decode("utf-8"),
                         details + f"suspected_ids={hits} offending_lines={lines}\n")

    def test_7339_single_run_stdin(self):
        self.check_body("run 38725221324", 1, 1, "1: run 38725221324\n")

    def test_7339_documented_twelve_digit_job(self):
        self.check_body("job 117259933896\n", 1, 1, "1: job 117259933896\n")

    def test_7339_multiple_hits_and_lines(self):
        self.check_body("clean\n38725221324 / 38725194568\njob 117259933896\n",
                        3, 2, "2: 38725221324 / 38725194568\n3: job 117259933896\n")

    def test_7339_empty_and_short_numbers(self):
        for body in ("", "No runs; issue #7339; 1234567890\n"):
            with self.subTest(body=body):
                self.check_body(body, 0, 0)

    def test_7339_exact_cap_assignment(self):
        self.check_body("+  SELF_HOSTED_TARGET_CAP_BYTES: 42949672960\n", 0, 0)

    def test_7339_same_cap_as_run(self):
        self.check_body("run 42949672960", 1, 1, "1: run 42949672960\n")

    def test_7339_cap_does_not_hide_other_occurrence(self):
        body = "+  SELF_HOSTED_TARGET_CAP_BYTES: 42949672960 # run 42949672960"
        self.check_body(body, 1, 1, "1: " + body + "\n")

    def test_7339_cap_near_misses(self):
        for body in ("SELF_HOSTED_TARGET_CAP_BYTES: 42949672961",
                     "OTHER_BYTES: 42949672960", "SELF_HOSTED_TARGET_CAP_BYTES=42949672960",
                     "XSELF_HOSTED_TARGET_CAP_BYTES: 42949672960",
                     "SELF_HOSTED_TARGET_CAP_BYTES: 429496729600"):
            with self.subTest(body=body):
                self.check_body(body, 1, 1, "1: " + body + "\n")

    def test_7339_sha_and_alphanumeric_boundaries(self):
        self.check_body("a38725221324 38725221324b _38725221324 38725221324_ "
                        "a123456789012345678901234567890123456789 "
                        "é38725221324 38725221324é", 0, 0)

    def test_7339_punctuation_and_long_tokens(self):
        body = "(38725221324), /117259933896; 12345678901234567890"
        self.check_body(body, 3, 1, "1: " + body + "\n")

    def test_7339_utf8_output_independent_of_locale(self):
        env = dict(os.environ, PYTHONIOENCODING="ascii", PYTHONUTF8="0")
        result = self.invoke("résumé 38725221324\n".encode("utf-8"), env=env)
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertEqual(result.stdout.decode("utf-8"),
                         "1: résumé 38725221324\nsuspected_ids=1 offending_lines=1\n")

    def test_7339_file_input(self):
        SCRATCH.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(dir=SCRATCH) as directory:
            body = Path(directory) / "body.txt"
            body.write_bytes(b"job 117259933896\n")
            result = self.invoke(b"ignored 38725221324", "--file", str(body))
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertEqual(result.stdout, b"1: job 117259933896\nsuspected_ids=1 offending_lines=1\n")

    def test_7339_missing_or_directory_input(self):
        for path in (HELPER.parent / "absent-7339-body", HELPER.parent):
            with self.subTest(path=path):
                result = self.invoke(b"", "--file", str(path))
                self.assertEqual(result.returncode, 2)
                self.assertEqual(result.stdout, b"")
                self.assertIn(b"input error", result.stderr)
                self.assertNotIn(b"Traceback", result.stderr)

    def test_7339_malformed_utf8_stdin_and_file(self):
        result = self.invoke(b"\xff")
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, b"")
        self.assertIn(b"input error", result.stderr)
        SCRATCH.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(dir=SCRATCH) as directory:
            body = Path(directory) / "bad.txt"
            body.write_bytes(b"\xff")
            result = self.invoke(b"", "--file", str(body))
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, b"")
        self.assertIn(b"input error", result.stderr)
        self.assertNotIn(b"Traceback", result.stderr)


class OutputStatus7837Tests(unittest.TestCase):
    def invoke(self, stdout, stderr=subprocess.PIPE, body=b""):
        return subprocess.run(
            [sys.executable, str(HELPER)], input=body,
            stdout=stdout, stderr=stderr, timeout=TIMEOUT_SECONDS,
        )

    def assert_output_error(self, result):
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertEqual(result.stderr, b"check_pr_body_ids: output error\n")

    @unittest.skipUnless(Path("/dev/full").exists(), "requires failing device")
    def test_7837_failing_sink_final_status(self):
        with open("/dev/full", "wb", buffering=0) as sink:
            self.assert_output_error(self.invoke(sink))

    def test_7837_closed_pipe_final_status(self):
        reader, writer = os.pipe()
        os.close(reader)  # No consumer exists before the child is started.
        with os.fdopen(writer, "wb", buffering=0) as sink:
            self.assert_output_error(self.invoke(sink))

    @unittest.skipUnless(Path("/dev/full").exists(), "requires failing device")
    def test_7837_output_and_diagnostic_sink_fail(self):
        with open("/dev/full", "wb", buffering=0) as sink:
            result = self.invoke(sink, stderr=sink)
        self.assertEqual(result.returncode, 2)

    @unittest.skipUnless(Path("/dev/full").exists(), "requires failing device")
    def test_7837_input_diagnostic_sink_fails(self):
        with open("/dev/full", "wb", buffering=0) as sink:
            result = self.invoke(subprocess.PIPE, stderr=sink, body=b"\xff")
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, b"")

    def test_7837_normal_stream_controls(self):
        for body, status, output, error in (
            (b"", 0, b"suspected_ids=0 offending_lines=0\n", b""),
            (b"12345678901", 1,
             b"1: 12345678901\nsuspected_ids=1 offending_lines=1\n", b""),
            (b"\xff", 2, b"",
             b"check_pr_body_ids: input error (expected readable UTF-8 body)\n"),
        ):
            with self.subTest(status=status):
                result = self.invoke(subprocess.PIPE, body=body)
                self.assertEqual(result.returncode, status, result.stderr)
                self.assertEqual(result.stdout, output)
                self.assertEqual(result.stderr, error)


class ParserOutput7840Tests(unittest.TestCase):
    def invoke(self, args, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
               immediate=False):
        options = ["-u"] if immediate else []
        return subprocess.run(
            [sys.executable, *options, "-c", PARSER_BOOTSTRAP, str(HELPER), *args],
            input=b"", stdout=stdout, stderr=stderr, timeout=TIMEOUT_SECONDS,
        )

    def check_failed_sink(self, sink):
        for args in PARSER_TERMINALS:
            for immediate in (False, True):
                for both in (False, True):
                    with self.subTest(args=args, immediate=immediate, both=both):
                        help_output = args[0] in ("-h", "--help")
                        result = self.invoke(
                            args, stdout=sink if help_output or both else subprocess.PIPE,
                            stderr=sink if not help_output or both else subprocess.PIPE,
                            immediate=immediate,
                        )
                        self.assertEqual(result.returncode, 2, result.stderr)
                        for captured in (result.stdout, result.stderr):
                            if captured is not None:
                                self.assertNotIn(b"Traceback", captured)
                                self.assertNotIn(b"Exception ignored", captured)

    @unittest.skipUnless(Path("/dev/full").exists(), "requires failing device")
    def test_7840_all_parser_terminals_failing_device(self):
        with open("/dev/full", "wb", buffering=0) as sink:
            self.check_failed_sink(sink)

    def test_7840_all_parser_terminals_closed_pipe(self):
        reader, writer = os.pipe()
        os.close(reader)
        with os.fdopen(writer, "wb", buffering=0) as sink:
            self.check_failed_sink(sink)

    def test_7840_long_usage_write_failure(self):
        reader, writer = os.pipe()
        os.close(reader)
        with os.fdopen(writer, "wb", buffering=0) as sink:
            result = self.invoke(("--unknown-" + "x" * 20000,), stderr=sink)
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, b"")

    def test_7840_normal_parser_controls(self):
        for args in PARSER_TERMINALS:
            with self.subTest(args=args):
                result = self.invoke(args)
                help_output = args[0] in ("-h", "--help")
                self.assertEqual(result.returncode, 0 if help_output else 2)
                self.assertIn(b"usage:", result.stdout if help_output else result.stderr)
                self.assertEqual(result.stderr if help_output else result.stdout, b"")

    def test_7840_reusable_main_preserves_healthy_streams(self):
        spec = importlib.util.spec_from_file_location("body_ids_7840", HELPER)
        helper = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(helper)
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            for args in PARSER_TERMINALS:
                self.assertEqual(helper.main(list(args)), 0 if args[0] in ("-h", "--help") else 2)
        self.assertFalse(stdout.closed)
        self.assertFalse(stderr.closed)
        self.assertIn("usage:", stdout.getvalue())
        self.assertIn("error:", stderr.getvalue())

    def test_7840_reusable_main_closes_only_failed_streams(self):
        spec = importlib.util.spec_from_file_location("body_ids_7840", HELPER)
        helper = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(helper)

        class FailedStream(io.StringIO):
            def write(self, message):
                if stage == "write":
                    raise OSError("unavailable output")
                return super().write(message)

            def flush(self):
                raise OSError("unavailable output")

        for stage in ("write", "flush"):
            for args in PARSER_TERMINALS:
                with self.subTest(stage=stage, args=args):
                    failed, healthy = FailedStream(), io.StringIO()
                    help_output = args[0] in ("-h", "--help")
                    stdout, stderr = (failed, healthy) if help_output else (healthy, failed)
                    with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                        self.assertEqual(helper.main(list(args)), 2)
                    self.assertTrue(failed.closed)
                    self.assertFalse(healthy.closed)


class UnavailableStreams7842Tests(unittest.TestCase):
    def invoke(self, setup, args=(), body=b"", stdout=subprocess.PIPE,
               stderr=subprocess.PIPE):
        code = "import os,runpy,sys; " + setup
        return subprocess.run(
            [sys.executable, "-c", code, str(HELPER), *args], input=body,
            stdout=stdout, stderr=stderr, timeout=TIMEOUT_SECONDS,
        )

    def check_unavailable(self, kind):
        for stream, args, body, status in (
            ("stdin", (), b"", 2), ("stdout", (), b"", 2),
            ("stdout", (), b"12345678901", 2),
            *(("stdout" if args[0] in ("-h", "--help") else "stderr",
               args, b"", 2) for args in PARSER_TERMINALS),
            ("stderr", (), b"\xff", 2),
            ("stderr", (), b"", 0), ("stdin", ("--help",), b"", 0),
        ):
            with self.subTest(kind=kind, stream=stream, args=args, body=body):
                if kind == "startup":
                    descriptor = {"stdin": 0, "stdout": 1, "stderr": 2}[stream]
                    setup = (f"os.close({descriptor}); "
                             "os.execv(sys.executable,[sys.executable,*sys.argv[1:]])")
                else:
                    setup = (f"sys.{stream}.close(); "
                             "sys.argv=sys.argv[1:]; "
                             "runpy.run_path(sys.argv[0],run_name='__main__')")
                result = self.invoke(setup, args, body)
                self.assertEqual(result.returncode, status, result.stderr)
                for output in (result.stdout, result.stderr):
                    self.assertNotIn(b"Traceback", output)
                    self.assertNotIn(b"Exception ignored", output)
                if stream == "stderr" and status == 2:
                    self.assertEqual(result.stdout, b"")
                if status == 0:
                    self.assertEqual(result.stderr, b"")
                    self.assertIn(b"usage:" if args else b"suspected_ids=0", result.stdout)

    def test_7842_actual_startup_closed_descriptors(self):
        self.check_unavailable("startup")

    def test_7842_closed_wrappers_at_io_boundaries(self):
        self.check_unavailable("wrapper")

    def check_repeated_failure(self, sink):
        for args in ((), *PARSER_TERMINALS):
            with self.subTest(args=args):
                help_or_body = not args or args[0] in ("-h", "--help")
                setup = ("helper=runpy.run_path(sys.argv[1]); "
                         "assert helper['main'](sys.argv[2:]) == 2; "
                         "sys.exit(helper['main'](sys.argv[2:]))")
                result = self.invoke(
                    setup, args, stdout=sink if help_or_body else subprocess.PIPE,
                    stderr=subprocess.PIPE if help_or_body else sink,
                )
                self.assertEqual(result.returncode, 2, result.stderr)
                for output in (result.stdout, result.stderr):
                    if output is not None:
                        self.assertNotIn(b"Traceback", output)
                        self.assertNotIn(b"Exception ignored", output)

    @unittest.skipUnless(Path("/dev/full").exists(), "requires failing device")
    def test_7842_repeat_after_failing_device(self):
        with open("/dev/full", "wb", buffering=0) as sink:
            self.check_repeated_failure(sink)

    def test_7842_repeat_after_closed_pipe(self):
        reader, writer = os.pipe()
        os.close(reader)
        with os.fdopen(writer, "wb", buffering=0) as sink:
            self.check_repeated_failure(sink)


class Encoding7845Tests(unittest.TestCase):
    def invoke(self, code, *args, body=b""):
        return subprocess.run(
            [sys.executable, "-c", "import runpy,sys; " + code, str(HELPER), *args],
            input=body, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=TIMEOUT_SECONDS,
        )

    def assert_clean(self, result, status):
        self.assertEqual(result.returncode, status, result.stderr)
        for output in (result.stdout, result.stderr):
            self.assertNotIn(b"Traceback", output)
            self.assertNotIn(b"Exception ignored", output)

    def test_7845_non_ascii_cli_help(self):
        SCRATCH.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(dir=SCRATCH) as directory:
            alias = Path(directory) / "résumé.py"
            alias.symlink_to(HELPER)
            for option in ("-h", "--help"):
                with self.subTest(option=option):
                    result = subprocess.run(
                        [sys.executable, str(alias), option], input=b"",
                        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                        env=dict(os.environ, PYTHONIOENCODING="ascii:strict"),
                        timeout=TIMEOUT_SECONDS,
                    )
                    self.assert_clean(result, 2)
                    self.assertEqual(result.stdout, b"")
                    self.assertEqual(result.stderr, b"check_pr_body_ids: output error\n")

    def test_7845_usage_encoding_and_repeated_main(self):
        for non_ascii_prog in (False, True):
            with self.subTest(non_ascii_prog=non_ascii_prog):
                result = self.invoke(
                    "h=runpy.run_path(sys.argv[1]); "
                    "sys.stderr.reconfigure(encoding='ascii',errors='strict'); "
                    + ("sys.argv[0]='résumé'; " if non_ascii_prog else "")
                    + "status=h['main'](['--résumé']); "
                    "assert sys.stderr.closed and not sys.stdout.closed; "
                    "assert h['main'](['--résumé']) == 2; sys.exit(status)"
                )
                self.assert_clean(result, 2)
                self.assertEqual(result.stdout, b"")
                self.assertEqual(result.stderr.count(b"usage:"), 0 if non_ascii_prog else 1)
                self.assertNotIn(b"output error", result.stderr)

    def test_7845_help_failure_and_diagnostic_encoding(self):
        # The stdlib undefined codec rejects even the ASCII fallback diagnostic.
        for diagnostic_encoding in ("ascii", "undefined"):
            with self.subTest(diagnostic_encoding=diagnostic_encoding):
                result = self.invoke(
                    "h=runpy.run_path(sys.argv[1]); sys.argv[0]='résumé'; "
                    "sys.stdout.reconfigure(encoding='ascii',errors='strict'); "
                    f"sys.stderr.reconfigure(encoding={diagnostic_encoding!r},errors='strict'); "
                    "status=h['main'](['--help']); "
                    "assert sys.stdout.closed; "
                    f"assert sys.stderr.closed == {diagnostic_encoding == 'undefined'}; "
                    "assert h['main'](['--help']) == 2; sys.exit(status)"
                )
                self.assert_clean(result, 2)
                self.assertEqual(result.stdout, b"")
                self.assertEqual(result.stderr, b"check_pr_body_ids: output error\n" * 2
                                 if diagnostic_encoding == "ascii" else b"")

    def test_7845_input_diagnostic_encoding(self):
        result = self.invoke(
            "h=runpy.run_path(sys.argv[1]); "
            "sys.stderr.reconfigure(encoding='undefined',errors='strict'); "
            "status=h['main']([]); assert sys.stderr.closed; "
            "assert not sys.stdin.closed and not sys.stdout.closed; sys.exit(status)",
            body=b"\xff",
        )
        self.assert_clean(result, 2)
        self.assertEqual((result.stdout, result.stderr), (b"", b""))

    def test_7845_restrictive_encoding_healthy_controls(self):
        for args, body, status in ((["--help"], b"", 0), (["--file"], b"", 2),
                                   ([], b"", 0), ([], "résumé 12345678901".encode(), 1)):
            with self.subTest(args=args, status=status):
                result = self.invoke(
                    "h=runpy.run_path(sys.argv[1]); "
                    "sys.stdout.reconfigure(encoding='ascii',errors='strict'); "
                    "sys.stderr.reconfigure(encoding='ascii',errors='strict'); "
                    "status=h['main'](sys.argv[2:]); "
                    "assert not any(s.closed for s in (sys.stdin,sys.stdout,sys.stderr)); "
                    "sys.exit(status)", *args, body=body,
                )
                self.assert_clean(result, status)
                if not args:
                    self.assertEqual(result.stderr, b"")
                    self.assertEqual(result.stdout, ("1: résumé 12345678901\n"
                                     "suspected_ids=1 offending_lines=1\n").encode()
                                     if status == 1 else b"suspected_ids=0 offending_lines=0\n")


class InputCompletion7848Tests(unittest.TestCase):
    def test_7848_unbuffered_fileio_caller_control(self):
        code = (
            "import io,runpy,sys; h=runpy.run_path(sys.argv[1]); "
            "original=sys.stdin; sys.stdin=io.TextIOWrapper(io.FileIO(0,closefd=False)); "
            "assert h['main']([])==1; assert h['main']([])==0; "
            "assert not any(s.closed for s in (sys.stdin,sys.stdout,sys.stderr))"
        )
        result = subprocess.run(
            [sys.executable, "-c", code, str(HELPER)], input=b"12345678901\n",
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=TIMEOUT_SECONDS,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stderr, b"")
        self.assertEqual(result.stdout, b"1: 12345678901\nsuspected_ids=1 offending_lines=1\n"
                         b"suspected_ids=0 offending_lines=0\n")

    def pipe_result(self, body, *, pending=False, blocking=False):
        reader, writer = os.pipe()
        try:
            os.set_blocking(reader, blocking)
            os.write(writer, body)
            if not pending:
                os.close(writer)
                writer = None
            return subprocess.run(
                [sys.executable, str(HELPER)], stdin=reader,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                timeout=TIMEOUT_SECONDS,
            )
        finally:
            os.close(reader)
            if writer is not None:
                os.close(writer)

    def test_7848_pending_pipe_never_reports_content(self):
        for body in (b"", b"clean prefix\n", b"12345", b"12345678901\n"):
            with self.subTest(body=body):
                result = self.pipe_result(body, pending=True)
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertEqual(result.stdout, b"")
                self.assertEqual(result.stderr,
                                 b"check_pr_body_ids: input error (expected readable UTF-8 body)\n")

    def test_7848_pipe_eof_controls(self):
        for blocking in (False, True):
            for body, status in ((b"", 0), (b"clean\n", 0), (b"12345678901\n", 1)):
                with self.subTest(blocking=blocking, body=body):
                    result = self.pipe_result(body, blocking=blocking)
                    self.assertEqual(result.returncode, status, result.stderr)
                    self.assertEqual(result.stderr, b"")
                    self.assertIn(b"suspected_ids=" + str(status).encode(), result.stdout)

    def test_7848_blocking_split_token_waits_for_eof(self):
        reader, writer = os.pipe()
        child = None
        try:
            os.write(writer, b"12345")
            child = subprocess.Popen(
                [sys.executable, str(HELPER)], stdin=reader,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            )
            with self.assertRaises(subprocess.TimeoutExpired):
                child.communicate(timeout=PENDING_CHECK_SECONDS)
            os.write(writer, b"678901\n")
            os.close(writer)
            writer = None
            stdout, stderr = child.communicate(timeout=TIMEOUT_SECONDS)
            self.assertEqual(child.returncode, 1, stderr)
            self.assertEqual(stdout, b"1: 12345678901\nsuspected_ids=1 offending_lines=1\n")
            self.assertEqual(stderr, b"")
        finally:
            os.close(reader)
            if writer is not None:
                os.close(writer)
            if child is not None:
                if child.poll() is None:
                    child.kill()
                child.communicate()

    @unittest.skipUnless(hasattr(os, "openpty"), "requires a POSIX terminal")
    def test_7848_terminal_single_eof_and_pending_controls(self):
        for blocking in (True, False):
            for body, status in ((b"", 0), (b"clean\n", 0), (b"12345678901\n", 1)):
                with self.subTest(blocking=blocking, body=body):
                    master, slave = os.openpty()
                    try:
                        os.set_blocking(slave, blocking)
                        # One canonical EOF after the final newline must suffice.
                        os.write(master, body + (b"\x04" if blocking else b""))
                        result = subprocess.run(
                            [sys.executable, str(HELPER)], stdin=slave,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            timeout=TIMEOUT_SECONDS,
                        )
                    finally:
                        os.close(master)
                        os.close(slave)
                    self.assertEqual(result.returncode, status if blocking else 2,
                                     result.stderr)
                    if blocking:
                        self.assertEqual(result.stderr, b"")
                        self.assertIn(b"suspected_ids=", result.stdout)
                    else:
                        self.assertEqual(result.stdout, b"")
                        self.assertIn(b"input error", result.stderr)

    def test_7848_buffered_utf8_and_repeated_caller_ownership(self):
        spec = importlib.util.spec_from_file_location("body_ids_7848", HELPER)
        helper = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(helper)
        body = (" " * (STDIN_BOUNDARY_BYTES - 1) + "é 12345678901\n").encode("utf-8")
        stdin = io.TextIOWrapper(io.BufferedReader(io.BytesIO(b"!" + body)))
        stdout, stderr = io.TextIOWrapper(io.BytesIO()), io.StringIO()
        original_stdin = sys.stdin
        try:
            # Populate BufferedReader before main; remaining bytes belong to the body.
            self.assertEqual(stdin.buffer.read(1), b"!")
            sys.stdin = stdin
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                self.assertEqual(helper.main([]), 1)
                self.assertEqual(helper.main([]), 0)
            self.assertFalse(stdin.closed)
            self.assertFalse(stdout.closed)
            self.assertFalse(stderr.closed)
            self.assertEqual(stderr.getvalue(), "")
            self.assertEqual(stdout.buffer.getvalue(), b"1: " + body
                             + b"suspected_ids=1 offending_lines=1\n"
                             + b"suspected_ids=0 offending_lines=0\n")
        finally:
            sys.stdin = original_stdin
            stdin.close()
            stdout.close()
            stderr.close()


class OutputCompletion7851Tests(unittest.TestCase):
    @contextlib.contextmanager
    def output_pipe(self, free_bytes=0, blocking=False):
        reader, writer = os.pipe()
        try:
            os.set_blocking(writer, False)
            capacity = 0
            while True:
                try:
                    capacity += os.write(writer, b"!" * select.PIPE_BUF)
                except BlockingIOError:
                    break
            filled = capacity - min(free_bytes, capacity)
            if free_bytes:
                self.assertEqual(len(os.read(reader, capacity - filled)), capacity - filled)
            os.set_blocking(writer, blocking)
            with os.fdopen(writer, "wb", buffering=0) as sink:
                yield reader, sink, capacity, filled
        finally:
            os.close(reader)

    def pipe_result(self, body=b"", args=(), *, immediate=True, free_bytes=0,
                    blocking=False, diagnostic=False, ownership=False):
        with self.output_pipe(free_bytes, blocking) as (reader, writer, capacity, filled):
            options = ["-u"] if immediate else []
            code = "import runpy,sys; h=runpy.run_path(sys.argv[1]); "
            code += "status=h['main'](sys.argv[2:]); "
            if ownership:
                code += ("assert not sys.stdin.closed; "
                         + ("assert status != 2 or (not sys.stdout.closed and sys.stderr.closed); "
                            if diagnostic else
                            "assert status != 2 or (sys.stdout.closed and not sys.stderr.closed); "))
            code += "sys.exit(status)"
            result = subprocess.run(
                [sys.executable, *options, "-c", code, str(HELPER), *args], input=body,
                stdout=subprocess.PIPE if diagnostic else writer,
                stderr=writer if diagnostic else subprocess.PIPE, timeout=TIMEOUT_SECONDS,
            )
            # The live reader stays idle until the child has exited. Measure only
            # bytes already delivered, without a consumer draining during writes.
            writer.close()
            delivered = bytearray()
            while True:
                chunk = os.read(reader, capacity)
                if not chunk:
                    break
                delivered.extend(chunk)
            self.assertEqual(delivered[:filled], b"!" * filled)
            return result, bytes(delivered[filled:])

    def test_7851_full_output_pipe_requires_operational_status(self):
        for immediate in (False, True):
            for body, args in ((b"", ()), (b"12345678901", ()), (b"", ("--help",))):
                with self.subTest(immediate=immediate, body=body, args=args):
                    result, output = self.pipe_result(body, args, immediate=immediate,
                                                      ownership=True)
                    self.assertEqual(result.returncode, 2, result.stderr)
                    self.assertEqual(output, b"")
                    self.assertEqual(result.stderr, b"check_pr_body_ids: output error\n")

    def test_7851_partial_capacity_large_report_requires_operational_status(self):
        for immediate in (False, True):
            with self.subTest(immediate=immediate):
                result, output = self.pipe_result(
                    b"12345678901 " + b"x" * LARGE_REPORT_BYTES,
                    immediate=immediate, free_bytes=select.PIPE_BUF,
                )
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertNotIn(b"suspected_ids=", output)
                self.assertEqual(result.stderr, b"check_pr_body_ids: output error\n")

    def test_7851_actual_raw_write_outcomes(self):
        with self.output_pipe() as (reader, writer, capacity, filled):
            self.assertEqual(filled, capacity)
            self.assertIsNone(writer.write(b"positive payload"))
            self.assertEqual(writer.write(b""), 0)
            self.assertEqual(len(os.read(reader, select.PIPE_BUF)), select.PIPE_BUF)
            self.assertEqual(writer.write(b"x" * max(LARGE_REPORT_BYTES, capacity * 2)),
                             select.PIPE_BUF)

    def test_7851_failed_diagnostics_preserve_status_and_unused_stdout(self):
        for immediate in (False, True):
            for body, args in ((b"\xff", ()), (b"", ("--unknown",)), (b"", ("--file",))):
                with self.subTest(immediate=immediate, body=body, args=args):
                    result, output = self.pipe_result(body, args, immediate=immediate,
                                                      diagnostic=True, ownership=True)
                    self.assertEqual(result.returncode, 2)
                    self.assertEqual(result.stdout, b"")
                    self.assertEqual(output, b"")

    def test_7851_blocking_buffered_and_unbuffered_controls(self):
        for immediate in (False, True):
            for body, args, status in ((b"", (), 0), (b"12345678901", (), 1),
                                       (b"", ("--help",), 0)):
                with self.subTest(immediate=immediate, body=body, args=args):
                    result, output = self.pipe_result(body, args, immediate=immediate,
                                                      blocking=True, free_bytes=LARGE_REPORT_BYTES)
                    self.assertEqual(result.returncode, status, result.stderr)
                    self.assertEqual(result.stderr, b"")
                    if args:
                        self.assertIn(b"usage:", output)
                        self.assertTrue(output.endswith(b"instead of stdin\n"))
                    else:
                        expected = (b"1: 12345678901\n" if status else b"")
                        expected += f"suspected_ids={status} offending_lines={status}\n".encode()
                        self.assertEqual(output, expected)

    def test_7851_unused_nonblocking_streams_remain_caller_owned(self):
        for stream, body, args, status in (("stderr", b"", (), 0),
                                          ("stderr", b"12345678901", (), 1),
                                          ("stderr", b"", ("--help",), 0),
                                          ("stdout", b"\xff", (), 2),
                                          ("stdout", b"", ("--unknown",), 2)):
            with self.subTest(stream=stream, args=args, status=status):
                code = ("import os,runpy,sys; h=runpy.run_path(sys.argv[1]); "
                        f"os.set_blocking(sys.{stream}.fileno(),False); "
                        "status=h['main'](sys.argv[2:]); "
                        "assert not any(s.closed for s in (sys.stdin,sys.stdout,sys.stderr)); "
                        "sys.exit(status)")
                result = subprocess.run(
                    [sys.executable, "-u", "-c", code, str(HELPER), *args], input=body,
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=TIMEOUT_SECONDS,
                )
                self.assertEqual(result.returncode, status, result.stderr)
                self.assertNotIn(b"Traceback", result.stderr)


class InterruptedOutput7855Tests(unittest.TestCase):
    output_pipe = OutputCompletion7851Tests.output_pipe

    def command(self, case, ready=None):
        code = (
            "import os,runpy,signal,sys; h=runpy.run_path(sys.argv[1]); "
            "signal.signal(signal.SIGUSR1,lambda *_:None); "
            "sys.argv[0]='résumé'+'x'*20000; "
        )
        if ready is not None:
            code += f"os.write({ready},b'R'); os.close({ready}); "
        if case == "diagnostic":
            code += ("h['report_error']('diagnostic '+sys.argv[0]); "
                     "assert not sys.stdout.closed; "
                     + ("sys.exit(2 if sys.stderr.closed else 1)" if ready is not None else
                        "sys.exit(2)"))
        else:
            args = {"help": ["--help"], "usage": ["--unknown"], "binary": []}[case]
            code += f"status=h['main']({args!r}); assert not sys.stdin.closed; "
            code += ("assert not sys.stdout.closed; " if case == "usage" else
                     "assert not sys.stderr.closed; ")
            code += "sys.exit(status)"
        options = ["-u"] if getattr(self, "immediate", True) else []
        return [sys.executable, *options, "-c", code, str(HELPER)]

    def test_7855_buffered_interrupted_outputs(self):
        self.immediate = False
        self.test_7855_interrupted_blocking_outputs()

    def test_7855_preserves_caller_encoder_newlines_and_pending_output(self):
        spec = importlib.util.spec_from_file_location("body_ids_7855", HELPER)
        helper = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(helper)
        SCRATCH.mkdir(exist_ok=True)
        for encoding, errors in (("utf-16", "strict"), ("iso2022_jp", "xmlcharrefreplace"),
                                 ("ascii", "xmlcharrefreplace"), ("latin-1", "replace")):
            with self.subTest(encoding=encoding), tempfile.TemporaryDirectory(dir=SCRATCH) as directory:
                outputs = []
                for checked in (False, True):
                    path = Path(directory) / str(checked)
                    raw = io.FileIO(path, "w")
                    stream = io.TextIOWrapper(io.BufferedWriter(raw), encoding=encoding,
                                              errors=errors, newline="\r\n")
                    try:
                        stream.write("caller 日本\n")  # Remains buffered before the boundary.
                        for text in ("help résumé\n", "usage 日本\n", "diagnostic é\n"):
                            if checked:
                                helper.write_output(stream, text)
                            else:
                                stream.write(text)
                                stream.flush()
                            self.assertFalse(stream.closed)
                            self.assertNotIn("write", raw.__dict__)
                        stream.write("caller tail 日本\n")
                    finally:
                        stream.close()
                    outputs.append(path.read_bytes())
                self.assertEqual(outputs[0], outputs[1])

    def test_7855_interrupted_blocking_outputs(self):
        body = b"12345678901 " + b"z" * LARGE_REPORT_BYTES
        for case in ("help", "usage", "diagnostic", "binary"):
            with self.subTest(case=case):
                diagnostic = case in ("usage", "diagnostic")
                normal = subprocess.run(self.command(case), input=body,
                                        capture_output=True, timeout=TIMEOUT_SECONDS)
                expected = normal.stderr if diagnostic else normal.stdout
                self.assertEqual(normal.returncode, 0 if case == "help" else
                                 1 if case == "binary" else 2, normal.stderr)
                self.assertGreater(len(expected), select.PIPE_BUF)
                with self.output_pipe(select.PIPE_BUF, True) as (reader, sink, capacity, filled):
                    ready_reader, ready_writer = os.pipe()
                    child = None
                    try:
                        child = subprocess.Popen(
                            self.command(case, ready_writer), stdin=subprocess.PIPE,
                            stdout=subprocess.PIPE if diagnostic else sink,
                            stderr=sink if diagnostic else subprocess.PIPE,
                            pass_fds=(ready_writer,),
                        )
                        os.close(ready_writer)
                        ready_writer = None
                        child.stdin.write(body if case == "binary" else b"")
                        child.stdin.close()
                        child.stdin = None
                        self.assertTrue(select.select([ready_reader], [], [], TIMEOUT_SECONDS)[0])
                        self.assertEqual(os.read(ready_reader, 1), b"R")
                        deadline = time.monotonic() + TIMEOUT_SECONDS
                        while True:
                            available = array.array("i", [0])
                            fcntl.ioctl(reader, termios.FIONREAD, available, True)
                            if available[0] == capacity:
                                break
                            self.assertLess(time.monotonic(), deadline, "no measured progress")
                            time.sleep(0.01)
                        self.assertIsNone(child.poll())
                        os.kill(child.pid, signal.SIGUSR1)
                        try:
                            stdout, stderr = child.communicate(timeout=TIMEOUT_SECONDS)
                        except subprocess.TimeoutExpired:
                            self.fail("interrupted output did not terminate within the bound")
                        sink.close()  # No reader drained until the child exited.
                        delivered = bytearray()
                        while True:
                            chunk = os.read(reader, capacity)
                            if not chunk:
                                break
                            delivered.extend(chunk)
                        self.assertEqual(delivered[:filled], b"!" * filled)
                        self.assertEqual(bytes(delivered[filled:]), expected[:select.PIPE_BUF])
                        self.assertLess(len(delivered) - filled, len(expected))
                        self.assertEqual(child.returncode, 2, (stdout, stderr))
                        self.assertEqual(stdout if diagnostic else stderr,
                                         b"" if diagnostic else b"check_pr_body_ids: output error\n")
                    finally:
                        os.close(ready_reader)
                        if ready_writer is not None:
                            os.close(ready_writer)
                        if child is not None:
                            if child.poll() is None:
                                child.kill()
                            child.communicate()


if __name__ == "__main__":
    unittest.main()
