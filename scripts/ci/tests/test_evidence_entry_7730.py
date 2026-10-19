#!/usr/bin/env python3
"""#7730: actual evidence entry points isolate before imports and keep CLI behavior.

Only disposable test fixtures are published; none is certification evidence.
Run with unittest discovery on this file under each supported interpreter.
"""
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
CACHE_PROBE = """
import importlib
import importlib.util
from pathlib import Path
import sys
import types

directory, scenario, first, sibling = Path(sys.argv[1]), *sys.argv[2:]
before = list(sys.path)

def load(name):
    spec = importlib.util.spec_from_file_location(name, directory / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module

if scenario == 'identity':
    load(first)
    rc = importlib.import_module('run_cert')
    bb = sys.modules.get('build_bundle') or load('build_bundle')
    prep = sys.modules.get('prep') or load('prep')
    assert bb.open_scratch is rc.open_scratch
    assert bb.run_tmpdir is rc.run_tmpdir
    assert prep.anchored is rc.anchored
    assert prep.is_watched_path is sys.modules['check_cert_expiry'].is_watched_path
    rc.REPO_ROOT = directory / 'shared-global'
    assert prep.anchored('child') == rc.REPO_ROOT / 'child'
    def refused(value):
        raise rc.ConfigError('shared-class')
    rc.anchored = refused
    try:
        bb.run_tmpdir()
    except rc.ConfigError as error:
        assert str(error) == 'shared-class'
    else:
        raise AssertionError('shared globals/exception class were lost')
    assert load('build_bundle').open_scratch is rc.open_scratch
elif scenario in ('wrong-file', 'wrong-spec'):
    trusted = directory / 'run_cert.py' if sibling == 'run_cert' else directory.parent / 'check_cert_expiry.py'
    foreign = str(directory / 'untrusted-source.py')
    fake = types.ModuleType(sibling)
    fake.__file__ = foreign if scenario == 'wrong-file' else str(trusted)
    fake.__spec__ = importlib.util.spec_from_file_location(sibling, foreign if scenario == 'wrong-spec' else trusted)
    sys.modules[sibling] = fake
    try:
        load(first)
    except ImportError as error:
        assert 'expected sibling source' in str(error), str(error)
    else:
        raise AssertionError('wrong-origin module was accepted')
elif scenario == 'failure-cleanup':
    try:
        load(first)
    except RuntimeError as error:
        assert str(error) == 'fixture-import-failure'
        assert sibling not in sys.modules
    else:
        raise AssertionError('failed import was accepted')
else:
    raise AssertionError(scenario)
assert before == sys.path, (before, sys.path)
print('CACHE-7730-OK')
"""


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

    def probe(self, scenario, first, sibling="run_cert"):
        result = subprocess.run([sys.executable, "-I", "-c", CACHE_PROBE, str(self.evidence),
                                 scenario, first, sibling], cwd=Path.cwd(), capture_output=True,
                                text=True, timeout=CHILD_TIMEOUT)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), "CACHE-7730-OK")

    def test_explicit_imports_preserve_shared_globals_and_exception_identity_7730(self):
        for first in ("run_cert", "build_bundle", "prep"):
            with self.subTest(first=first):
                self.probe("identity", first)

    def test_wrong_origin_cached_siblings_are_refused_7730(self):
        for scenario in ("wrong-file", "wrong-spec"):
            for first, sibling in (("build_bundle", "run_cert"), ("prep", "run_cert"),
                                   ("prep", "check_cert_expiry")):
                with self.subTest(scenario=scenario, first=first, sibling=sibling):
                    self.probe(scenario, first, sibling)

    def test_failed_sibling_imports_do_not_leave_partial_cache_entries_7730(self):
        for first, sibling in (("build_bundle", "run_cert"), ("prep", "run_cert"),
                               ("prep", "check_cert_expiry")):
            path = (self.evidence / "run_cert.py" if sibling == "run_cert"
                    else self.evidence.parent / "check_cert_expiry.py")
            source = path.read_text()
            try:
                path.write_text("raise RuntimeError('fixture-import-failure')\n")
                with self.subTest(first=first, sibling=sibling):
                    self.probe("failure-cleanup", first, sibling)
            finally:
                path.write_text(source)

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
