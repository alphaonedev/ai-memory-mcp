#!/usr/bin/env python3
"""#7730: actual evidence entry points isolate before imports and keep CLI behavior.

Only disposable test fixtures are published; none is certification evidence.
Run with unittest discovery on this file under each supported interpreter.
"""
import os
from pathlib import Path
import shutil
import subprocess
import sys
import unittest

from test_evidence_generator_5040_5042 import EVIDENCE, REPO, ScratchCase
from test_evidence_generator_r5_7393 import BundleFixture

ENTRYPOINTS = ("run_cert.py", "build_bundle.py", "prep.py")
IMPORT_NAMES = ("argparse", "datetime", "shlex")
STARTUP_FLAGS = ((), ("-I",), ("-S",))
MARKER = "ENTRYPOINT-7730-PLANT-RAN"
PLANT_EXIT = 86
PLANT_SOURCE = "print({!r}, flush=True)\nraise SystemExit({})\n".format(MARKER, PLANT_EXIT)
CHILD_TIMEOUT = 30
FIXTURE_DATE = "2026-10-19"


def invoke(script, flags, arguments):
    """Use the selected test interpreter and an unrelated caller directory."""
    return subprocess.run([sys.executable, *flags, str(script), *arguments], cwd=Path.cwd(),
                          capture_output=True, text=True, timeout=CHILD_TIMEOUT)


class DirectEntry7730(ScratchCase):
    def setUp(self):
        super().setUp()
        self.evidence = self.dir / "checkout with spaces" / "scripts" / "evidence"
        self.evidence.mkdir(parents=True)
        for name in ENTRYPOINTS:
            shutil.copyfile(EVIDENCE / name, self.evidence / name)
        shutil.copyfile(REPO / "scripts/check_cert_expiry.py", self.evidence.parent / "check_cert_expiry.py")

    def test_plain_entrypoints_reject_script_directory_imports_7730(self):
        for entry in ENTRYPOINTS:
            for module in IMPORT_NAMES:
                with self.subTest(entry=entry, module=module):
                    plant = self.evidence / (module + ".py")
                    plant.write_text(PLANT_SOURCE)
                    try:
                        result = invoke(self.evidence / entry, (), ["--help"])
                        self.assertNotIn(MARKER, result.stdout + result.stderr)
                        self.assertEqual(result.returncode, 0, result.stderr)
                        self.assertIn("usage:", result.stdout)
                    finally:
                        plant.unlink()

    def test_isolated_sibling_loading_does_not_restore_import_directory_7730(self):
        for entry in ENTRYPOINTS:
            for module in IMPORT_NAMES:
                with self.subTest(entry=entry, module=module):
                    plant = self.evidence / (module + ".py")
                    plant.write_text(PLANT_SOURCE)
                    try:
                        result = invoke(self.evidence / entry, ("-I",), ["--help"])
                        self.assertNotIn(MARKER, result.stdout + result.stderr)
                        self.assertEqual(result.returncode, 0, result.stderr)
                    finally:
                        plant.unlink()

    def test_no_site_bootstrap_does_not_import_os_from_script_directory_7730(self):
        # os is neither cached by site nor frozen on Python 3.9 with -S.
        # argparse additionally proves that the later imports run in isolation.
        for module in ("os", "argparse"):
            plant = self.evidence / (module + ".py")
            plant.write_text(PLANT_SOURCE)
            try:
                for entry in ENTRYPOINTS:
                    with self.subTest(entry=entry, module=module):
                        result = invoke(self.evidence / entry, ("-S",), ["--help"])
                        self.assertNotIn(MARKER, result.stdout + result.stderr)
                        self.assertEqual(result.returncode, 0, result.stderr)
            finally:
                plant.unlink()

    def test_positive_controls_detect_each_uncached_plant_7730(self):
        control = self.evidence / "control.py"
        names = IMPORT_NAMES + (("os",) if sys.version_info < (3, 11) else ())
        for module in names:
            with self.subTest(module=module):
                plant = self.evidence / (module + ".py")
                plant.write_text(PLANT_SOURCE)
                control.write_text("import " + module + "\n")
                try:
                    result = invoke(control, ("-S",), [])
                    self.assertEqual(result.returncode, PLANT_EXIT, result.stderr)
                    self.assertIn(MARKER, result.stdout)
                finally:
                    plant.unlink()

    def test_help_and_argument_errors_are_preserved_7730(self):
        for entry in ENTRYPOINTS:
            for flags in STARTUP_FLAGS:
                with self.subTest(entry=entry, flags=flags):
                    help_result = invoke(self.evidence / entry, flags, ["--help"])
                    self.assertEqual(help_result.returncode, 0, help_result.stderr)
                    self.assertIn("usage: " + entry, help_result.stdout)
                    bad = invoke(self.evidence / entry, flags, ["--unknown-7730"])
                    self.assertEqual(bad.returncode, 2, bad.stderr)
                    self.assertIn("error:", bad.stderr)

    def test_prep_normal_measurement_preserves_paths_and_arguments_7730(self):
        for flags in STARTUP_FLAGS:
            with self.subTest(flags=flags):
                result = invoke(self.evidence / "prep.py", flags,
                                ["--repo", str(REPO), "--base", "HEAD", "--tip", "HEAD"])
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn("RANGE commits=0 non-merge=0", result.stdout)
                self.assertIn("WATCHED_TOTAL files=0 lines=0 code=0", result.stdout)
                self.assertIn("added=[] removed=[]", result.stdout)

    def test_runner_reaches_preflight_and_records_refusal_7730(self):
        # An explicit missing wrapper stops before any Cargo invocation or disk floor.
        for index, flags in enumerate(STARTUP_FLAGS):
            outd = self.dir / ("runner output " + str(index))
            result = invoke(self.evidence / "run_cert.py", flags,
                            ["battery", "--tip", "a" * 40, "--wt", str(REPO), "--outd", str(outd),
                             "--targets", str(self.dir / "targets"), "--tmpdir", str(self.dir / "scratch"),
                             "--cargo-slot", str(self.dir / "missing-wrapper")])
            with self.subTest(flags=flags):
                self.assertEqual(result.returncode, 64, result.stderr)
                log = (outd / "legs.log").read_text()
                self.assertIn("PLAN leg=battery legs=battery", log)
                self.assertIn("EXIT=64 leg=battery aggregate_failures=1", log)
                self.assertIn("is not an executable file", log)


class BundleEntry7730(BundleFixture):
    def test_normal_bundle_command_publishes_fixture_and_keeps_no_overwrite_7730(self):
        destination = self.wt / "docs/compliance/evidence" / ("cert-" + self.tip[:9])
        for flags in STARTUP_FLAGS:
            with self.subTest(flags=flags):
                arguments = ["--tip", self.tip, "--wt", str(self.wt), "--outd", str(self.outd),
                             "--sanitization", str(self.san), "--date", FIXTURE_DATE]
                result = invoke(EVIDENCE / "build_bundle.py", flags, arguments)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn("BUNDLE OK", result.stdout)
                self.assertIn(FIXTURE_DATE, (destination / "test-results.txt").read_text())
                before = {path.name: path.read_bytes() for path in destination.iterdir()}
                self.assertIn("MANIFEST.sha256", before)
                repeat = invoke(EVIDENCE / "build_bundle.py", flags, arguments)
                self.assertEqual(repeat.returncode, 1, repeat.stderr)
                self.assertIn("already exists; refusing to overwrite", repeat.stderr)
                self.assertEqual(before, {path.name: path.read_bytes() for path in destination.iterdir()})
                shutil.rmtree(destination)


if __name__ == "__main__":
    unittest.main()
