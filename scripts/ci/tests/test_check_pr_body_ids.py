# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""CLI regression tests for the opt-in PR-body suspicion check (#7339)."""

import contextlib
import importlib.util
import io
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

HELPER = Path(__file__).resolve().parents[1] / "check_pr_body_ids.py"
SCRATCH = Path(__file__).resolve().parents[3] / ".local-runs"
TIMEOUT_SECONDS = 10
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


if __name__ == "__main__":
    unittest.main()
