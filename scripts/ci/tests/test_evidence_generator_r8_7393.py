#!/usr/bin/env python3
"""PR #7393 round 8: gate fixtures for the r7 review findings (#7661-#7672) on the vendored certification evidence
generator.

  #7661  the tests pass on a hosted runner: the runner's disk floor is lifted for every test in one shared setUp, the
         floor still trips in a dedicated low-disk test, and the gates leg (no cargo) is not subject to it
  #7662  one scratch guard (run_cert.open_scratch) for run_cert and build_bundle: a scratch directory owned by this user
         that is group writable but not world writable is accepted (umask 0002 checkouts); a world-writable directory,
         a foreign owner, a symlink and a regular file are refused; the umask is set before the first mkdir
  #7663  #7665  every child process runs in a fresh empty 0700 directory under the scratch root with a scrubbed Python
         environment, so a stdlib-named file planted in the checkout root, scripts/ or .local-runs is never imported
  #7664  #7669  prep.py reads `git diff --numstat -z`: non-ASCII and space paths are counted, a binary file is counted
  #7666  the in-memory loader runs the script in a fresh globals dict
  #7667  the bundle publish never replaces a destination that appeared after the exists check
  #7668  build_bundle uses the shared scratch guard
  #7670  the runtime audit hook also covers os.symlink, os.link, sqlite3.connect, socket.bind and Popen cwd
  #7671  the exact scratch-root prefix is pinned again (test_evidence_generator_5040_5042)
  #7672  CodeQL 525 (unused global), 526 and 527 (file not closed) and the same patterns across the PR's Python files

Scratch lives under .local-runs/ (never a tmpfs). The tmp-root name this file needs is built from character codes.

Run: python3 -m unittest discover -s scripts/ci/tests -p test_evidence_generator_r8_7393.py
"""
import argparse
import ast
import codecs
import contextlib
import io
import os
import socket
import sqlite3
import stat
import subprocess
import sys
import tempfile
import types
import unittest
import unittest.mock as mock
from pathlib import Path

import tmp_runtime_guard_7393 as guard
from test_evidence_generator_5040_5042 import ScratchCase, load
from test_evidence_generator_r2_7393 import GIT, make_repo
from test_evidence_generator_r5_7393 import BundleFixture, GatesRun
from test_evidence_generator_r7_7393 import GATE_FILE, PLANTED, REAL_GATE, RECAPTURE_SH, write_empty

TESTS = Path(__file__).resolve().parent
EVIDENCE_DIR = TESTS.parent.parent / "evidence"
EVIDENCE_SCRIPTS = ("run_cert.py", "build_bundle.py", "prep.py")
GATE_SCRIPTS = (
    "check-cert-removal-proof", "check-docs-vs-ssot", "check-doc-symbol-anchors", "check-ci-job-claims",
    "check-hardcoded-literals", "check-vendor-literals", "qc-codegraph-precheck", "check-test-env-lock",
    "check-count-assertion-declared", "check-foreign-text-to-caller")
# What a repository gate looks like to the runner: it prints where it started, then does what the real ones do (cd to
# its own root and start python3), so an inner python3 sees the checkout as its working directory unless the
# environment stops it.
PROBE_GATE = (
    "#!/usr/bin/env bash\n"
    'echo "START $(pwd -P) COUNT $(ls -A | wc -l) MODE $(stat -c %a .)"\n'
    'echo "ENV PP=${PYTHONPATH-unset} HOME=${PYTHONHOME-unset} STARTUP=${PYTHONSTARTUP-unset} '
    'UB=${PYTHONUSERBASE-unset} SAFE=${PYTHONSAFEPATH-unset} NOUSER=${PYTHONNOUSERSITE-unset}"\n'
    'cd "$(dirname "$0")/.." || exit 2\n'
    "python3 - <<'PY'\n"
    "import base64, json\n"
    "print('B64', base64.__file__)\n"
    "print('JSON', json.__file__)\n"
    "PY\n"
    "python3 -c \"import base64; print('B64C', base64.__file__)\"\n")
PLANT_NAMES = ("base64.py", "json.py", "sitecustomize.py", "usercustomize.py")


def fake_statvfs(free_bytes):
    """os.statvfs standing in for a nearly full disk: block size 4096, `free_bytes` available."""
    def fn(_path):
        return types.SimpleNamespace(f_bavail=free_bytes // 4096, f_frsize=4096)
    return fn


class RunnerCase(GatesRun):
    """GatesRun plus a driver for the whole `gates` leg through main() and a helper that plants stdlib-named files."""

    def drive(self, wt, tip, outd="o2", extra=()):
        argv = ["run_cert.py", "gates", "--tip", tip, "--wt", str(wt), "--outd", str(self.dir / outd),
                "--targets", str(self.dir / "t"), "--tmpdir", str(self.dir / "tmp"), *extra]
        rc = load("run_cert")
        out, err = io.StringIO(), io.StringIO()
        with mock.patch.object(sys, "argv", argv), contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = rc.main()
        return code, out.getvalue() + err.getvalue(), (self.dir / outd / "gates.log").read_text()

    def plant(self, wt):
        for where in (wt, wt / "scripts", wt / ".local-runs"):
            where.mkdir(exist_ok=True)
            for name in PLANT_NAMES:
                (where / name).write_text(PLANTED)

    def gate_logs(self, outd="o2"):
        return {p.name: p.read_text(errors="replace") for p in sorted((self.dir / outd).glob("g.*.log"))}


class DiskFloor7661(RunnerCase):
    def test_a_test_runs_a_command_on_a_nearly_full_disk_7661(self):
        """The shared setUp lifts the floor: a hosted runner with little free disk still runs the in-process tests."""
        rc = load("run_cert")
        wt, tip = make_repo(self.dir / "repo", {})
        r = rc.Run(argparse.Namespace(tip=tip, wt=str(wt), outd=str(self.dir / "o"), leg="battery",
                                      targets=str(self.dir / "t"), tmpdir=str(self.dir / "tmp")))
        with mock.patch("os.statvfs", fake_statvfs(1 << 20)):
            self.assertEqual(r.run(["true"], self.dir / "true.out"), 0)
        self.assertFalse(r.floor_tripped)

    def test_the_floor_still_trips_when_the_test_asks_for_it_7661(self):
        rc = load("run_cert")
        wt, tip = make_repo(self.dir / "repo", {})
        r = rc.Run(argparse.Namespace(tip=tip, wt=str(wt), outd=str(self.dir / "o"), leg="battery",
                                      targets=str(self.dir / "t"), tmpdir=str(self.dir / "tmp")))
        with mock.patch.object(rc, "FLOOR_BUILD_GIB", 120), mock.patch.object(rc, "FLOOR_ROOT_GIB", 60), \
                mock.patch("os.statvfs", fake_statvfs(1 << 20)):
            code = r.run(["true"], self.dir / "true.out")
        self.assertEqual(code, 75)
        self.assertTrue(r.floor_tripped)
        self.assertIn("DISK-FLOOR STOP", (self.dir / "o" / "legs.log").read_text())
        self.assertIn("NOT RUN: disk floor tripped", (self.dir / "true.out").read_text())

    def test_the_gates_leg_runs_no_cargo_so_the_floor_never_gates_it_7661(self):
        rc, r, wt, tip = self.make({GATE_FILE: REAL_GATE})
        calls = []
        real = r.run

        def spy(argv, out, extra_env=None, **kw):
            calls.append(kw.get("gate", True))
            return real(argv, out, extra_env, **kw)

        with mock.patch.object(r, "run", side_effect=spy):
            r.gates("0" * 40, "")
        self.assertGreaterEqual(len(calls), 10)
        self.assertEqual(set(calls), {False}, "the gates leg starts no cargo; the disk floor guards cargo legs")

    def test_a_cargo_leg_is_still_gated_by_the_floor_7661(self):
        rc = load("run_cert")
        wt, tip = make_repo(self.dir / "repo", {})
        r = rc.Run(argparse.Namespace(tip=tip, wt=str(wt), outd=str(self.dir / "o"), leg="battery",
                                      targets=str(self.dir / "t"), tmpdir=str(self.dir / "tmp")))
        with mock.patch.object(rc, "FLOOR_BUILD_GIB", 120), mock.patch.object(rc, "FLOOR_ROOT_GIB", 60), \
                mock.patch("os.statvfs", fake_statvfs(1 << 20)):
            bad = r.battery()
        self.assertGreaterEqual(bad, 1)
        self.assertIn("DISK-FLOOR STOP", (self.dir / "o" / "legs.log").read_text())


class SandboxedChildren7663(RunnerCase):
    def gates_with_probes(self, plant=True):
        files = {GATE_FILE: REAL_GATE}
        files.update({f"scripts/{g}.sh": PROBE_GATE for g in GATE_SCRIPTS})
        rc, r, wt, tip = self.make(files)
        (wt / ".local-runs").mkdir(exist_ok=True)
        (wt / ".local-runs").chmod(0o700)
        if plant:
            self.plant(wt)
        return rc, r, wt, tip

    def test_every_subprocess_call_of_the_generator_names_its_cwd_7663(self):
        """A child with no cwd= inherits the caller's working directory, which may be the checkout."""
        missing = []
        for name in EVIDENCE_SCRIPTS:
            tree_ = ast.parse((EVIDENCE_DIR / name).read_text())
            for node in ast.walk(tree_):
                if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
                    continue
                if isinstance(node.func.value, ast.Name) and node.func.value.id == "subprocess" and \
                        node.func.attr in ("run", "Popen", "check_output", "check_call", "call"):
                    if "cwd" not in {k.arg for k in node.keywords}:
                        missing.append(f"{name}:{node.lineno} subprocess.{node.func.attr}")
        self.assertEqual(missing, [])

    def test_planted_stdlib_names_are_never_imported_by_a_gate_leg_7665(self):
        rc, r, wt, tip = self.gates_with_probes()
        self.drive(wt, tip)
        logs = self.gate_logs()
        self.assertGreaterEqual(len(logs), 10)
        for name, text in logs.items():
            with self.subTest(gate=name):
                self.assertNotIn("PLANTED-MODULE-RAN", text)
        for name in (f"g.{g}.log" for g in ("docs-vs-ssot", "doc-anchors", "hardcoded", "c8")):
            self.assertIn("B64 ", logs[name])
            for line in logs[name].splitlines():
                if line.startswith(("B64", "JSON")):
                    self.assertFalse(line.split(" ", 1)[1].startswith(str(wt)), line)

    def test_planted_stdlib_names_are_never_imported_by_the_shell_recapture_7663(self):
        body = RECAPTURE_SH + ("python3 - <<'PY' > \"$OUT/b64.txt\"\n"
                               "import base64, json\n"
                               "print('B64', base64.__file__)\n"
                               "PY\n")
        rc = load("run_cert")
        wt, tip = make_repo(self.dir / "repo", {"scripts/recapture-cert-3607-posture.sh": body})
        self.plant(wt)
        r = rc.Run(argparse.Namespace(tip=tip, wt=str(wt), outd=str(self.dir / "o"), leg="battery",
                                      targets=str(self.dir / "t"), tmpdir=str(self.dir / "tmp")))
        r.posture(Path("d-bin"), Path("s-bin"))
        text = (self.dir / "o" / "evidence" / "b64.txt").read_text()
        self.assertTrue(text.startswith("B64 "), text)
        self.assertNotIn("PLANTED", text)
        self.assertFalse(text.split(" ", 1)[1].startswith(str(wt)), text)
        self.assertEqual(r.bad, 0)

    def test_each_child_starts_in_a_fresh_empty_private_directory_under_the_scratch_root_7663(self):
        rc, r, wt, tip = self.gates_with_probes()
        self.drive(wt, tip)
        starts = []
        for name, text in self.gate_logs().items():
            if not name.startswith("g.cert-expiry"):
                line = next(l for l in text.splitlines() if l.startswith("START "))
                starts.append(line)
        self.assertGreaterEqual(len(starts), 9)
        dirs = []
        for line in starts:
            _tag, cwd, _c, count, _m, mode = line.split()
            self.assertEqual((count, mode), ("0", "700"), line)
            self.assertTrue(cwd.startswith(str((self.dir / "tmp").resolve()) + os.sep), line)
            dirs.append(cwd)
        self.assertEqual(len(set(dirs)), len(dirs), "a fresh directory for every child")
        self.assertEqual([p for p in (self.dir / "tmp").iterdir()], [], "the sandboxes are removed afterwards")

    def test_the_python_environment_is_scrubbed_for_every_child_7663(self):
        env = {"PYTHONPATH": str(self.dir), "PYTHONHOME": "/nonexistent", "PYTHONSTARTUP": str(self.dir / "s.py"),
               "PYTHONUSERBASE": str(self.dir)}
        with mock.patch.dict(os.environ, env):
            rc, r, wt, tip = self.gates_with_probes(plant=False)
            self.drive(wt, tip)
        for name, text in self.gate_logs().items():
            if name.startswith("g.cert-expiry"):
                continue
            line = next(l for l in text.splitlines() if l.startswith("ENV "))
            self.assertEqual(line, "ENV PP=unset HOME=unset STARTUP=unset UB=unset SAFE=1 NOUSER=1", name)

    def test_a_cargo_free_child_never_runs_in_the_checkout_7663(self):
        """Every Run.run call without an explicit checkout cwd is handed a directory that is not the checkout."""
        rc, r, wt, tip = self.gates_with_probes(plant=False)
        seen = []
        real = subprocess.run

        def spy(argv, *a, **kw):
            if argv and argv[0] in ("bash", sys.executable):
                seen.append(Path(kw["cwd"]).resolve() if kw.get("cwd") else None)
            return real(argv, *a, **kw)

        with mock.patch("subprocess.run", side_effect=spy):
            r.gates("0" * 40, "")
        self.assertGreaterEqual(len(seen), 10)
        self.assertNotIn(None, seen)
        self.assertNotIn(wt.resolve(), seen)
        self.assertNotIn(wt.resolve() / "scripts", seen)


class ScratchGuard7662(RunnerCase):
    def scratch(self, wt, mode):
        (wt / ".local-runs").mkdir(exist_ok=True)
        (wt / ".local-runs").chmod(mode)

    def test_a_group_writable_scratch_directory_is_accepted_7662(self):
        rc, r, wt, tip = self.make({GATE_FILE: REAL_GATE})
        self.scratch(wt, 0o775)
        code, out, log = self.drive(wt, tip)
        self.assertNotIn("RED scratch", out)
        self.assertIn("cert-expiry-upstream", log)

    def test_the_tracked_scratch_directory_of_a_umask_0002_checkout_runs_the_gates_7662(self):
        """A real repository whose .local-runs is tracked (a .gitkeep) and checked out 0775 under umask 0002."""
        old = os.umask(0o002)
        try:
            wt, tip = make_repo(self.dir / "repo", {GATE_FILE: REAL_GATE, ".local-runs/.gitkeep": ""})
        finally:
            os.umask(old)
        self.assertEqual(stat.S_IMODE((wt / ".local-runs").stat().st_mode), 0o775)
        code, out, log = self.drive(wt, tip)
        self.assertNotIn("RED scratch", out)
        self.assertIn("cert-expiry-upstream", log)
        self.assertEqual(stat.S_IMODE((wt / ".local-runs").stat().st_mode), 0o775, "no chmod is needed or done")

    def test_a_world_writable_scratch_directory_is_refused_with_a_mode_message_7662(self):
        rc, r, wt, tip = self.make({GATE_FILE: REAL_GATE})
        self.scratch(wt, 0o777)
        code, out, log = self.drive(wt, tip)
        self.assertEqual(code, 1)
        self.assertIn("RED scratch", out)
        self.assertIn("world writable", out)
        self.assertNotIn("owned by uid", out)

    def test_a_foreign_owner_is_refused_with_an_owner_message_7662(self):
        rc, r, wt, tip = self.make({GATE_FILE: REAL_GATE})
        self.scratch(wt, 0o755)
        foreign_uid = os.geteuid() + 1
        def foreign_scratch():
            # #7731: keep the simulated owner mismatch on the legacy gate-scratch surface alone.
            with mock.patch("os.geteuid", return_value=foreign_uid):
                return rc.open_scratch(wt / ".local-runs")
        with mock.patch.object(rc.Run, "open_scratch", side_effect=foreign_scratch):
            code, out, log = self.drive(wt, tip)
        self.assertEqual(code, 1)
        self.assertIn("owned by uid", out)
        self.assertNotIn("world writable", out)

    def test_the_umask_is_set_before_the_first_directory_is_made_7662(self):
        rc = load("run_cert")
        wt, tip = make_repo(self.dir / "repo", {})
        old = os.umask(0)
        try:
            rc.Run(argparse.Namespace(tip=tip, wt=str(wt), outd=str(self.dir / "fresh" / "o"), leg="gates",
                                      targets=str(self.dir / "fresh" / "t"), tmpdir=str(self.dir / "fresh" / "tmp")))
        finally:
            os.umask(old)
        for sub in ("o", "t", "tmp"):
            self.assertEqual(stat.S_IMODE((self.dir / "fresh" / sub).stat().st_mode), 0o755, sub)

    def test_the_scratch_guard_is_one_function_used_by_both_scripts_7668(self):
        rc, bb = load("run_cert"), load("build_bundle")
        self.assertTrue(callable(getattr(rc, "open_scratch", None)))
        self.assertIs(bb.open_scratch, rc.open_scratch)
        calls = [n for n in ast.walk(ast.parse((EVIDENCE_DIR / "build_bundle.py").read_text()))
                 if isinstance(n, ast.Call) and getattr(n.func, "id", None) == "open_scratch"]
        self.assertTrue(calls, "build_bundle.publish_bundle calls the shared guard")


class BundleScratchGuard7668(BundleFixture):
    def test_a_world_writable_scratch_directory_refuses_the_bundle_7668(self):
        (self.wt / ".local-runs").mkdir(exist_ok=True)
        (self.wt / ".local-runs").chmod(0o777)
        code, text = self.build()
        self.assertEqual(code, 1, text)
        self.assertIn("BUNDLE FAILED", text)
        self.assertIn("world writable", text)
        self.assertFalse((self.wt / "docs/compliance/evidence").exists())

    def test_a_scratch_symlink_refuses_the_bundle_7668(self):
        (self.dir / "elsewhere").mkdir()
        os.symlink(self.dir / "elsewhere", self.wt / ".local-runs")
        code, text = self.build()
        self.assertEqual(code, 1, text)
        self.assertIn("BUNDLE FAILED", text)
        self.assertEqual(list((self.dir / "elsewhere").iterdir()), [], "nothing is staged through the link")

    def test_a_foreign_owner_refuses_the_bundle_7668(self):
        (self.wt / ".local-runs").mkdir(exist_ok=True)
        with mock.patch("os.geteuid", return_value=os.geteuid() + 1):
            code, text = self.build()
        self.assertEqual(code, 1, text)
        self.assertIn("owned by uid", text)

    def test_a_group_writable_scratch_directory_builds_the_bundle_7668(self):
        (self.wt / ".local-runs").mkdir(exist_ok=True)
        (self.wt / ".local-runs").chmod(0o775)
        code, text = self.build()
        self.assertEqual(code, 0, text)
        self.assertIn("BUNDLE OK", text)


class PublishNoReplace7667(BundleFixture):
    def setUp(self):
        super().setUp()
        self.files = {"a.txt": b"one\n", "b.txt": b"two\n"}
        self.manifest = self.bb.manifest_text(self.files)
        self.dest = self.wt / "docs" / "compliance" / "evidence" / "cert-x"
        (self.wt / ".local-runs").mkdir(exist_ok=True)
        (self.wt / ".local-runs").chmod(0o755)

    def racing_verify(self):
        """stage_verify that creates the empty destination right after the exists check would have run."""
        real = self.bb.stage_verify

        def verify(stage, files, *args, **kwargs):
            out = real(stage, files, *args, **kwargs)
            self.dest.mkdir(parents=True, exist_ok=True)
            return out
        return mock.patch.object(self.bb, "stage_verify", side_effect=verify)

    def assert_refused(self):
        with self.racing_verify(), self.assertRaises(self.bb.Fatal):
            self.bb.publish_bundle(self.wt, self.dest, self.files, self.manifest)
        self.assertEqual(list(self.dest.iterdir()), [], "the destination that appeared is left exactly as it was")
        self.assertEqual([p.name for p in (self.wt / ".local-runs").iterdir() if p.name.startswith("bundle-stage-")], [])

    def test_a_destination_created_after_the_exists_check_is_refused_by_the_kernel_7667(self):
        if self.bb.rename_noreplace_native is None:
            self.skipTest("renameat2 is not available on this platform")
        self.assert_refused()

    def test_a_destination_created_after_the_exists_check_is_refused_without_renameat2_7667(self):
        with mock.patch.object(self.bb, "rename_noreplace_native", None):
            self.assert_refused()

    def test_the_bundle_is_published_with_either_path_7667(self):
        for native in (self.bb.rename_noreplace_native, None):
            with self.subTest(native=native is not None), mock.patch.object(self.bb, "rename_noreplace_native", native):
                dest = self.dest.parent / f"cert-{native is None}"
                listing = self.bb.publish_bundle(self.wt, dest, self.files, self.manifest)
                self.assertEqual(listing, ["MANIFEST.sha256", "a.txt", "b.txt"])
                self.assertEqual((dest / "a.txt").read_bytes(), b"one\n")

    def test_a_destination_that_is_not_the_staged_directory_is_refused_7667(self):
        def swap(stage, dest, **kwargs):
            """A rename that publishes a different directory with the right bytes."""
            self.dest.mkdir(parents=True)
            for name, data in self.files.items():
                (self.dest / name).write_bytes(data)
            (self.dest / "MANIFEST.sha256").write_text(self.manifest)
        with mock.patch.object(self.bb, "rename_noreplace", side_effect=swap), self.assertRaises(self.bb.Fatal) as cm:
            self.bb.publish_bundle(self.wt, self.dest, self.files, self.manifest)
        self.assertIn("not the staged", str(cm.exception))

    def test_a_published_directory_whose_manifest_no_longer_matches_is_refused_7667(self):
        real = self.bb.rename_noreplace

        def tamper(stage, dest, **kwargs):
            real(stage, dest, **kwargs)
            (self.dest / "a.txt").write_bytes(b"changed\n")
        with mock.patch.object(self.bb, "rename_noreplace", side_effect=tamper), self.assertRaises(self.bb.Fatal) as cm:
            self.bb.publish_bundle(self.wt, self.dest, self.files, self.manifest)
        self.assertIn("manifest", str(cm.exception))


class LoaderGlobals7666(ScratchCase):
    SCRIPT = ("print('NAMES', sorted(globals()))\n"
              "import sys\n"
              "print('ARGV', sys.argv)\n"
              "print('FILE', __file__)\n"
              "print('SPEC', __spec__)\n"
              "print('MAIN', sys.modules['__main__'].__file__ == __file__)\n"
              "import dataclasses\n"
              "@dataclasses.dataclass\n"
              "class P:\n"
              "    x: int = 1\n"
              "print('DATACLASS', P().x)\n")

    def run_loader(self):
        rc = load("run_cert")
        target = self.dir / "scripts" / "g.py"
        r = subprocess.run([sys.executable, "-I", "-c", rc.PY_LOADER, str(target), "--flag"], input=self.SCRIPT.encode(),
                           capture_output=True, cwd=str(self.dir))
        return r, str(target)

    def test_the_script_sees_only_the_four_names_of_a_fresh_namespace_7666(self):
        r, target = self.run_loader()
        text = r.stdout.decode()
        self.assertEqual(r.returncode, 0, r.stderr.decode())
        self.assertIn("NAMES ['__builtins__', '__file__', '__name__', '__spec__']", text)
        for leaked in ("path", "src", "main", "sys", "types"):
            self.assertNotIn(f"'{leaked}'", text.split("\n", 1)[0])

    def test_the_script_keeps_the_identity_of_a_script_run_by_path_7666(self):
        r, target = self.run_loader()
        text = r.stdout.decode()
        self.assertIn(f"ARGV ['{target}', '--flag']", text)
        self.assertIn(f"FILE {target}", text)
        self.assertIn("SPEC None", text)
        self.assertIn("MAIN True", text)
        self.assertIn("DATACLASS 1", text)


class PrepZ7664(ScratchCase):
    WATCHED = ("src/federation/caf\u00e9.rs", "src/federation/a b.rs", "src/federation/blob.bin")

    def make(self):
        repo = self.dir / "prep-repo"
        repo.mkdir()
        run = lambda *a: subprocess.run([*GIT, *a], cwd=repo, check=True, capture_output=True)
        run("init", "-q")
        (repo / "src" / "federation").mkdir(parents=True)
        (repo / "src" / "federation" / "a.rs").write_text("const X: &str = \"AI_MEMORY_FED_ONE\";\n")
        run("add", "src/federation/a.rs")
        run("commit", "-q", "-m", "base")
        base = subprocess.run(["git", "rev-parse", "HEAD"], cwd=repo, capture_output=True, text=True).stdout.strip()
        (repo / self.WATCHED[0]).write_text("fn a() {}\nfn b() {}\n")
        (repo / self.WATCHED[1]).write_text("// c\nfn c() {}\n")
        (repo / self.WATCHED[2]).write_bytes(b"\x00\x01\x02binary\x00")
        (repo / "src" / "other.rs").write_text("fn other() {}\n")
        run("add", "src")
        run("commit", "-q", "-m", "tip")
        tip = subprocess.run(["git", "rev-parse", "HEAD"], cwd=repo, capture_output=True, text=True).stdout.strip()
        return repo, base, tip

    def prep(self):
        repo, base, tip = self.make()
        r = subprocess.run([sys.executable, "-I", str(EVIDENCE_DIR / "prep.py"), "--repo", str(repo), "--base", base,
                            "--tip", tip], capture_output=True, text=True, cwd=str(self.dir), stdin=subprocess.DEVNULL)
        return r

    def test_a_non_ascii_and_a_space_path_are_counted_7664(self):
        r = self.prep()
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("WATCHED src/federation/caf\u00e9.rs +2/-0 code=2", r.stdout)
        self.assertIn("WATCHED src/federation/a b.rs +2/-0 code=1", r.stdout)
        self.assertNotIn("src/other.rs", r.stdout)

    def test_a_binary_watched_file_is_counted_without_a_traceback_7669(self):
        r = self.prep()
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertNotIn("Traceback", r.stderr)
        self.assertIn("WATCHED src/federation/blob.bin binary code=0", r.stdout)
        self.assertIn("WATCHED_TOTAL files=3 lines=4 code=3", r.stdout)

    def test_the_watched_predicate_is_the_gates_predicate_7664(self):
        prep_src = (EVIDENCE_DIR / "prep.py").read_text()
        self.assertIn("is_watched_path", prep_src)
        self.assertNotIn("def is_watched(", prep_src, "one predicate: scripts/check_cert_expiry.py is_watched_path")


class HookEvents7670(ScratchCase):
    def setUp(self):
        super().setUp()
        self.fake = self.dir / "fakeroot"
        self.fake.mkdir()

    def raises(self, call):
        with guard.captured(self.fake) as sink:
            with self.assertRaises(guard.TmpRootViolation):
                call()
        self.assertTrue(sink)
        return sink

    def test_the_hook_lists_the_new_events_7670(self):
        for event in ("os.symlink", "os.link", "sqlite3.connect", "socket.bind", "subprocess.Popen"):
            self.assertIn(event, guard.CHECKED_EVENTS, event)

    def test_a_symlink_made_under_the_root_is_caught_7670(self):
        self.raises(lambda: os.symlink(self.dir / "t", self.fake / "link"))
        self.assertEqual(list(self.fake.iterdir()), [])

    def test_a_symlink_pointing_into_the_root_is_caught_7670(self):
        self.raises(lambda: os.symlink(self.fake / "target", self.dir / "link"))
        self.assertFalse((self.dir / "link").is_symlink())

    def test_a_hard_link_under_the_root_is_caught_7670(self):
        src = self.dir / "src.txt"
        src.write_text("x\n")
        self.raises(lambda: os.link(src, self.fake / "hard"))
        self.assertEqual(list(self.fake.iterdir()), [])

    def test_a_sqlite_database_under_the_root_is_caught_7670(self):
        self.raises(lambda: sqlite3.connect(str(self.fake / "db.sqlite")))
        self.assertEqual(list(self.fake.iterdir()), [])

    def test_a_unix_socket_bound_under_the_root_is_caught_7670(self):
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.addCleanup(sock.close)
        self.raises(lambda: sock.bind(str(self.fake / "s.sock")))
        self.assertEqual(list(self.fake.iterdir()), [])

    def test_a_child_started_with_its_cwd_under_the_root_is_caught_7670(self):
        self.raises(lambda: subprocess.run(["true"], cwd=str(self.fake), stdin=subprocess.DEVNULL))

    def test_ordinary_use_outside_the_root_passes_7670(self):
        with guard.captured(self.fake) as sink:
            os.symlink(self.dir / "t", self.dir / "ok-link")
            sqlite3.connect(str(self.dir / "ok.sqlite")).close()
            subprocess.run(["true"], cwd=str(self.dir), stdin=subprocess.DEVNULL)
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
                sock.bind(str(self.dir / "ok.sock"))
            (self.dir / "ok.sock").unlink()
        self.assertEqual(sink, [])


class AstMissedSpellings7670(ScratchCase):
    """The eight spellings the AST guard cannot fold, each built at run time and caught by the audit hook."""

    def setUp(self):
        super().setUp()
        self.fake = self.dir / "fakeroot"
        self.fake.mkdir()
        self.name = str(self.fake)

    def caught(self, build_path):
        path = build_path()
        with guard.captured(self.fake) as sink:
            with self.assertRaises(guard.TmpRootViolation):
                write_empty(path + "/probe.txt")
        self.assertTrue(sink)
        self.assertEqual(list(self.fake.iterdir()), [])

    def test_a_bytes_list_decoded_at_run_time_7670(self):
        self.caught(lambda: bytes(list(os.fsencode(self.name))).decode())

    def test_percent_c_characters_7670(self):
        self.caught(lambda: "".join("%c" % c for c in os.fsencode(self.name)))

    def test_lower_applied_to_an_upper_case_constant_7670(self):
        self.caught(lambda: self.name.upper().lower())

    def test_rot13_applied_twice_7670(self):
        self.caught(lambda: codecs.encode(codecs.encode(self.name, "rot13"), "rot13"))

    def test_a_copy_of_the_environment_7670(self):
        def build():
            env = os.environ.copy()
            env["WORKDIR"] = self.name
            return env["WORKDIR"]
        self.caught(build)

    def test_a_dict_of_the_environment_7670(self):
        def build():
            env = dict(os.environ, WORKDIR=self.name)
            return env["WORKDIR"]
        self.caught(build)

    def test_the_private_default_tempdir_lookup_7670(self):
        with mock.patch.dict(os.environ, {"TMPDIR": self.name}), mock.patch.object(tempfile, "tempdir", None):
            with guard.captured(self.fake) as sink:
                with self.assertRaises(guard.TmpRootViolation):
                    tempfile._get_default_tempdir()
        self.assertTrue(sink)

    def test_mkdtemp_with_dir_bound_to_none_7670(self):
        d = None
        with mock.patch.dict(os.environ, {"TMPDIR": self.name}), mock.patch.object(tempfile, "tempdir", None):
            with guard.captured(self.fake) as sink:
                with self.assertRaises(guard.TmpRootViolation):
                    tempfile.mkdtemp(dir=d)
        self.assertTrue(sink)

    def test_the_ast_guard_docstring_claims_only_static_cases_7670(self):
        from test_evidence_generator_r6_7393 import tmp_root_findings
        doc = tmp_root_findings.__doc__
        self.assertIn("STATIC", doc)
        self.assertIn("cannot", doc)
        for phrase in ("bytes", "%c", "lower", "rot13", "environ.copy", "_get_default_tempdir"):
            self.assertIn(phrase, doc, f"the docstring names {phrase} as a case it cannot see")


class ScratchRootPin7671(ScratchCase):
    def test_the_exact_scratch_root_is_pinned_in_the_leak_scan_prefixes_7671(self):
        text = (TESTS / "test_evidence_generator_5040_5042.py").read_text()
        self.assertNotIn('startswith("/ai-")', text)
        self.assertIn('"/" + "ai-" + "scratch"', text)


def python_files():
    return sorted(set(EVIDENCE_DIR.glob("*.py")) | set(TESTS.glob("test_evidence_generator_*.py"))
                  | {TESTS / "tmp_runtime_guard_7393.py"})


class CodeQlClasses7672(guard.GuardedCase):
    def test_no_open_call_outside_a_with_statement_7672(self):
        """py/file-not-closed (alerts 526, 527): every builtin open() is a with-item."""
        bad = []
        for f in python_files():
            tree_ = ast.parse(f.read_text())
            with_items = {id(item.context_expr) for n in ast.walk(tree_) if isinstance(n, (ast.With, ast.AsyncWith))
                          for item in n.items}
            for node in ast.walk(tree_):
                if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "open" \
                        and id(node) not in with_items:
                    bad.append(f"{f.name}:{node.lineno}")
        self.assertEqual(bad, [])

    def test_every_os_open_is_closed_in_a_finally_7672(self):
        """py/file-not-closed for descriptors: a function that calls os.open has an os.close in a finally block."""
        bad = []
        for f in python_files():
            tree_ = ast.parse(f.read_text())
            for fn in ast.walk(tree_):
                if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    continue
                opens = [n for n in ast.walk(fn) if isinstance(n, ast.Call) and ast.unparse(n.func) == "os.open"]
                if not opens:
                    continue
                closes = [n for t in ast.walk(fn) if isinstance(t, ast.Try) for s in t.finalbody for n in ast.walk(s)
                          if isinstance(n, ast.Call) and ast.unparse(n.func) == "os.close"]
                if not closes:
                    bad.append(f"{f.name}:{fn.name}:{fn.lineno}")
        self.assertEqual(bad, [])

    def test_no_global_is_assigned_and_never_read_7672(self):
        """py/unused-global-variable (alert 525): a module global that functions assign through `global` and nothing reads."""
        bad = []
        for f in python_files():
            tree_ = ast.parse(f.read_text())
            declared = {n for g in ast.walk(tree_) if isinstance(g, ast.Global) for n in g.names}
            loads = {n.id for n in ast.walk(tree_) if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Load)}
            for name in sorted(declared - loads):
                bad.append(f"{f.name}:{name}")
        self.assertEqual(bad, [])


if __name__ == "__main__":
    unittest.main()
