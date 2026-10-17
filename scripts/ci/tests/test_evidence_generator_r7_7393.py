#!/usr/bin/env python3
"""PR #7393 round 7: gate fixtures for the r6 review findings (#7617-#7622) on the vendored certification evidence
generator.

  #7617  the posture recapture runs from the tip blob in memory: no copy on disk, no write through a planted link,
         and the Python form runs isolated (`python -I`)
  #7618  the expiry gate runs from the HEAD blob in memory: no copy, so no check-to-exec window; a group/world-writable
         or foreign-owned .local-runs is refused
  #7619  the tmp-root rule is enforced at run time (audit hook, tmp_runtime_guard_7393) and statically (AST guard); every
         spelling in SPELLINGS is caught by one of the two
  #7620  the legacy `.expiry-*` sweep is iterative, depth-capped and never ends a run without an EXIT row
  #7621  build_bundle stages the bundle under .local-runs and publishes it only after write and re-verify pass
  #7622  no empty `except` body and no module imported both ways in the PR's Python files (CodeQL 520 and 519)

Scratch lives under .local-runs/ (never a tmpfs). The tmp-root name this file needs is built from character codes.

Run: python3 -m unittest discover -s scripts/ci/tests -p test_evidence_generator_r7_7393.py
"""
import argparse
import ast
import contextlib
import io
import os
import re
import stat
import subprocess
import sys
import tempfile
import unittest
import unittest.mock as mock
from pathlib import Path

import tmp_runtime_guard_7393 as guard
from test_evidence_generator_5040_5042 import ScratchCase, load
from test_evidence_generator_r2_7393 import make_repo
from test_evidence_generator_r5_7393 import BundleFixture, GatesRun
from test_evidence_generator_r6_7393 import tmp_root_findings

TESTS = Path(__file__).resolve().parent
EVIDENCE_DIR = TESTS.parent.parent / "evidence"
T = "".join(map(chr, (116, 109, 112)))  # the name of the system scratch root, spelled from character codes

REAL_GATE = (
    "import json, sys\n"
    "from pathlib import Path\n"
    "print('REAL-GATE', json.dumps([1]), __name__, Path(__file__).name, Path(__file__).resolve().parent.parent.name,\n"
    "      sys.argv[1:])\n")
PLANTED = "print('PLANTED-MODULE-RAN')\n"
GATE_FILE = "scripts/check_cert_expiry.py"

RECAPTURE_PY = (
    "import json, os, sys\n"
    "from pathlib import Path\n"
    "ROOT = Path(__file__).resolve().parents[1]\n"
    'OUT = ROOT / "docs" / "posture"\n'
    'FIX = ROOT / "fix"\n'
    "OUT.mkdir(parents=True, exist_ok=True)\n"
    '(OUT / "posture-a.out").write_text("[PASS] ran as " + __name__ + " root=" + ROOT.name + " argv0=" + Path(sys.argv[0]).parent.name\n'
    '                                    + " bin=" + os.environ["DEFAULT_BIN"] + " json=" + str(Path(json.__file__).name) + "\\n")\n'
    '(OUT / "posture-legs-exit-codes.txt").write_text("a 0\\n")\n'
    "print('JSON-FROM', json.__file__)\n")
RECAPTURE_SH = (
    "#!/usr/bin/env bash\n"
    "set -u\n"
    'ROOT="$(cd "$(dirname "$0")/.." && pwd)"\n'
    'OUT="$ROOT/docs/posture"\n'
    'FIX="$ROOT/fix"\n'
    'mkdir -p "$OUT"\n'
    'export FIX="$FIX"\n'
    'echo "[PASS] sh $(basename "$0") root=$(basename "$ROOT") bin=$DEFAULT_BIN" > "$OUT/posture-a.out"\n'
    'echo "a 0" > "$OUT/posture-legs-exit-codes.txt"\n')


def tree(root):
    """Every path under `root` (relative, sorted), skipping .git."""
    out = []
    for base, dirs, files in os.walk(root):
        dirs[:] = [d for d in dirs if d != ".git"]
        for name in dirs + files:
            out.append(str((Path(base) / name).relative_to(root)))
    return sorted(out)


def dead_pid():
    p = subprocess.Popen([sys.executable, "-c", "pass"])
    p.wait()
    return p.pid


def make_deep(parent, name, depth):
    """A directory `parent/name` nested `depth` levels, built one descriptor at a time."""
    fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.mkdir(name, dir_fd=fd)
        cur = os.open(name, os.O_RDONLY | os.O_DIRECTORY, dir_fd=fd)
    finally:
        os.close(fd)
    for _ in range(depth):
        os.mkdir("d", dir_fd=cur)
        nxt = os.open("d", os.O_RDONLY | os.O_DIRECTORY, dir_fd=cur)
        os.close(cur)
        cur = nxt
    fd_file = os.open("leaf.txt", os.O_WRONLY | os.O_CREAT, 0o600, dir_fd=cur)
    os.close(fd_file)
    os.close(cur)


class Spy:
    """Wraps Run.run, recording every argv and the stdin bytes handed to it."""

    def __init__(self, run):
        self.real = run
        self.calls = []

    def __call__(self, argv, out, extra_env=None, **kw):
        self.calls.append((list(argv), kw))
        return self.real(argv, out, extra_env, **kw)

    def python_runs(self):
        return [a for a, _kw in self.calls if a[0] == sys.executable]


class GateInMemory7618(GatesRun):
    def prepare(self, files=None):
        rc, r, wt, tip = self.make(files or {GATE_FILE: REAL_GATE})
        (wt / ".local-runs").mkdir(exist_ok=True)
        (wt / ".local-runs").chmod(0o700)
        return rc, r, wt, tip

    def test_a_gates_run_creates_no_file_under_local_runs_or_scripts_7618(self):
        rc, r, wt, tip = self.prepare()
        before = tree(wt)
        r.gates("0" * 40, "")
        self.assertEqual(tree(wt), before, "the gate runs from memory: nothing is written into the checkout")

    def test_the_gate_output_is_the_real_gates_with_the_checkout_as_repo_root_7618(self):
        rc, r, wt, tip = self.prepare()
        r.gates("0" * 40, "")
        text = (self.dir / "o" / "g.cert-expiry-upstream.log").read_text()
        self.assertIn("REAL-GATE [1] __main__ check_cert_expiry.py repo []", text)  # __file__ names the checkout path
        self.assertIn("['--self-test']", (self.dir / "o" / "g.cert-expiry-selftest.log").read_text())

    def test_all_three_expiry_runs_are_isolated_and_read_the_blob_from_stdin_7618(self):
        rc, r, wt, tip = self.prepare()
        spy = Spy(r.run)
        with mock.patch.object(r, "run", side_effect=spy):
            r.gates("0" * 40, "")
        runs = spy.python_runs()
        self.assertEqual(len(runs), 3)
        for argv in runs:
            self.assertEqual(argv[1:3], ["-I", "-c"], argv)
        stdin = [kw.get("stdin_data") for a, kw in spy.calls if a[0] == sys.executable]
        self.assertTrue(all(isinstance(s, bytes) and b"REAL-GATE" in s for s in stdin), stdin)

    def test_a_module_planted_beside_the_checkout_never_replaces_the_gate_7618(self):
        rc, r, wt, tip = self.prepare()
        for where in (wt, wt / "scripts", wt / ".local-runs"):
            where.mkdir(exist_ok=True)
            (where / "json.py").write_text(PLANTED)
        r.gates("0" * 40, "")
        logs = "".join(p.read_text(errors="replace") for p in (self.dir / "o").glob("g.cert-expiry-*.log"))
        self.assertIn("REAL-GATE", logs)
        self.assertNotIn("PLANTED-MODULE-RAN", logs)

    def test_the_removed_copy_machinery_is_gone_7618(self):
        run = load("run_cert").Run
        for name in ("pick_expiry", "check_expiry_copy", "drop_expiry", "sweep_expiry", "remove_at"):
            self.assertFalse(hasattr(run, name), name)

    def test_a_replaced_scratch_entry_cannot_change_what_runs_7618(self):
        """There is no entry to replace: whatever sits in .local-runs, the gate that runs is the blob."""
        rc, r, wt, tip = self.prepare()
        (wt / ".local-runs" / ".expiry-1-aaaa.py").write_text("print('FORGED-GATE')\n")
        r.gates("0" * 40, "")
        logs = "".join(p.read_text(errors="replace") for p in (self.dir / "o").glob("g.cert-expiry-*.log"))
        self.assertNotIn("FORGED-GATE", logs)
        self.assertIn("REAL-GATE", logs)


class ScratchRefused7618(GatesRun):
    def drive(self, wt, tip, **patches):
        argv = ["run_cert.py", "gates", "--tip", tip, "--wt", str(wt), "--outd", str(self.dir / "o2"),
                "--targets", str(self.dir / "t"), "--tmpdir", str(self.dir / "tmp")]
        rc = load("run_cert")
        out, err = io.StringIO(), io.StringIO()
        with mock.patch.object(sys, "argv", argv), contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = rc.main()
        return code, out.getvalue(), (self.dir / "o2" / "gates.log").read_text()

    def refused(self, wt, tip):
        code, out, log = self.drive(wt, tip)
        self.assertEqual(code, 1, out)
        self.assertIn("RED scratch", out)
        self.assertRegex(log, r"EXIT=1 leg=gates aggregate_failures=[1-9]")
        self.assertNotIn("cert-expiry-upstream", log, "no gate runs in a scratch directory that is not trusted")
        self.assertNotIn("Traceback", out)

    def test_a_world_writable_scratch_directory_is_refused_7618(self):
        rc, r, wt, tip = self.make()
        (wt / ".local-runs").mkdir(exist_ok=True)
        (wt / ".local-runs").chmod(0o777)
        self.refused(wt, tip)

    def test_a_group_writable_scratch_directory_is_refused_7618(self):
        rc, r, wt, tip = self.make()
        (wt / ".local-runs").mkdir(exist_ok=True)
        (wt / ".local-runs").chmod(0o775)
        self.refused(wt, tip)

    def test_a_scratch_directory_owned_by_someone_else_is_refused_7618(self):
        rc, r, wt, tip = self.make()
        (wt / ".local-runs").mkdir(exist_ok=True)
        (wt / ".local-runs").chmod(0o700)
        with mock.patch("os.geteuid", return_value=os.geteuid() + 1):
            self.refused(wt, tip)

    def test_a_scratch_symlink_is_refused_7618(self):
        rc, r, wt, tip = self.make()
        (self.dir / "elsewhere").mkdir()
        os.symlink(self.dir / "elsewhere", wt / ".local-runs")
        self.refused(wt, tip)

    def test_a_regular_file_at_the_scratch_path_is_refused_with_an_exit_row_7618(self):
        rc, r, wt, tip = self.make()
        (wt / ".local-runs").write_text("not a directory\n")
        self.refused(wt, tip)

    def test_an_absent_scratch_directory_is_not_created_7618(self):
        rc, r, wt, tip = self.make({GATE_FILE: REAL_GATE})
        self.assertFalse((wt / ".local-runs").exists())
        code, out, log = self.drive(wt, tip)
        self.assertFalse((wt / ".local-runs").exists())
        self.assertNotIn("RED scratch", out)

    def test_a_private_scratch_directory_is_accepted_7618(self):
        rc, r, wt, tip = self.make({GATE_FILE: REAL_GATE})
        (wt / ".local-runs").mkdir(exist_ok=True)
        (wt / ".local-runs").chmod(0o700)
        code, out, log = self.drive(wt, tip)
        self.assertNotIn("RED scratch", out)
        self.assertIn("cert-expiry-upstream", log)


class IterativeSweep7620(GatesRun):
    def prepare(self):
        rc, r, wt, tip = self.make({GATE_FILE: REAL_GATE})
        (wt / ".local-runs").mkdir(exist_ok=True)
        (wt / ".local-runs").chmod(0o700)
        return rc, r, wt, tip

    def drive(self, wt, tip):
        argv = ["run_cert.py", "gates", "--tip", tip, "--wt", str(wt), "--outd", str(self.dir / "o2"),
                "--targets", str(self.dir / "t"), "--tmpdir", str(self.dir / "tmp")]
        rc = load("run_cert")
        out, err = io.StringIO(), io.StringIO()
        with mock.patch.object(sys, "argv", argv), contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = rc.main()
        return code, out.getvalue(), (self.dir / "o2" / "gates.log").read_text()

    def test_a_stale_directory_nested_deeper_than_the_recursion_limit_is_removed_7620(self):
        rc, r, wt, tip = self.prepare()
        depth = 5000
        self.assertGreater(depth, sys.getrecursionlimit() * 2)
        name = f".expiry-{dead_pid()}-deep"
        make_deep(wt / ".local-runs", name, depth)
        code, out, log = self.drive(wt, tip)
        self.assertFalse((wt / ".local-runs" / name).exists(), "the stale tree is gone")
        self.assertNotIn("RecursionError", out + log)
        self.assertNotIn("Traceback", out)
        self.assertRegex(log, r"EXIT=\d leg=gates")

    def test_a_symlink_inside_a_stale_directory_is_unlinked_not_followed_7620(self):
        rc, r, wt, tip = self.prepare()
        victim = self.dir / "victim"
        victim.mkdir()
        (victim / "keep.txt").write_text("keep\n")
        name = f".expiry-{dead_pid()}-link"
        (wt / ".local-runs" / name).mkdir()
        os.symlink(victim, wt / ".local-runs" / name / "to-victim")
        os.symlink(victim / "keep.txt", wt / ".local-runs" / f".expiry-{dead_pid()}-filelink")
        self.drive(wt, tip)
        self.assertEqual((victim / "keep.txt").read_text(), "keep\n")
        self.assertEqual(sorted(p.name for p in (wt / ".local-runs").iterdir()), [])

    def test_a_live_process_entry_is_left_alone_7620(self):
        rc, r, wt, tip = self.prepare()
        live = wt / ".local-runs" / f".expiry-{os.getppid()}-live"
        live.mkdir()
        (live / "f").write_text("x\n")
        self.drive(wt, tip)
        self.assertTrue((live / "f").exists())

    def test_an_entry_of_the_older_layout_is_removed_7620(self):
        rc, r, wt, tip = self.prepare()
        old = wt / ".local-runs" / ".expiry-oldlayout"
        (old / "a" / "b").mkdir(parents=True)
        (old / "a" / "b" / "c").write_text("x\n")
        stale_file = wt / ".local-runs" / f".expiry-{dead_pid()}-aaaa.py"
        stale_file.write_text("print('stale')\n")
        self.drive(wt, tip)
        self.assertEqual(sorted(p.name for p in (wt / ".local-runs").iterdir()), [])

    def test_a_tree_deeper_than_the_cap_is_a_note_row_and_the_run_goes_on_7620(self):
        rc, r, wt, tip = self.prepare()
        name = f".expiry-{dead_pid()}-toodeep"
        make_deep(wt / ".local-runs", name, 12)
        with mock.patch.object(load("run_cert"), "SWEEP_MAX_DEPTH", 5):
            code, out, log = self.drive(wt, tip)
        self.assertRegex(log, r"NOTE sweep \.expiry-\d+-toodeep")
        self.assertIn("cert-expiry-upstream", log, "the gates still ran")
        self.assertRegex(log, r"EXIT=\d leg=gates")

    def test_an_unexpected_error_in_the_sweep_is_a_note_row_not_a_crash_7620(self):
        rc, r, wt, tip = self.prepare()
        (wt / ".local-runs" / f".expiry-{dead_pid()}-x").mkdir()
        with mock.patch.object(load("run_cert").Run, "remove_tree", side_effect=RuntimeError("boom")):
            code, out, log = self.drive(wt, tip)
        self.assertIn("NOTE sweep", log)
        self.assertIn("boom", log)
        self.assertNotIn("Traceback", out)
        self.assertRegex(log, r"EXIT=\d leg=gates")

    def test_an_exception_in_a_leg_still_writes_the_exit_row_7620(self):
        rc, r, wt, tip = self.prepare()
        with mock.patch.object(load("run_cert").Run, "_gates", side_effect=RuntimeError("leg exploded")):
            code, out, log = self.drive(wt, tip)
        self.assertEqual(code, 1)
        self.assertRegex(log, r"EXIT=1 leg=gates aggregate_failures=[1-9]")
        self.assertIn("RED internal", log)
        self.assertIn("leg exploded", log)

    def test_the_removal_holds_one_descriptor_at_a_time_7620(self):
        """A 5000-deep tree needs 5000 descriptors if each level keeps its own open; the open-file limit proves it does not."""
        import resource
        soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        rc, r, wt, tip = self.prepare()
        name = f".expiry-{dead_pid()}-fds"
        make_deep(wt / ".local-runs", name, 300)
        resource.setrlimit(resource.RLIMIT_NOFILE, (min(hard, 64), hard))
        self.addCleanup(resource.setrlimit, resource.RLIMIT_NOFILE, (soft, hard))
        dfd = os.open(wt / ".local-runs", os.O_RDONLY | os.O_DIRECTORY)
        self.addCleanup(os.close, dfd)
        load("run_cert").Run.remove_tree(dfd, name)
        self.assertFalse((wt / ".local-runs" / name).exists())


class PostureInMemory7617(ScratchCase):
    def setUp(self):
        super().setUp()
        self.rc = load("run_cert")

    def build(self, rel, body):
        wt, tip = make_repo(self.dir / "repo", {rel: body})
        r = self.rc.Run(argparse.Namespace(tip=tip, wt=str(wt), outd=str(self.dir / "o"), leg="battery",
                                           targets=str(self.dir / "t"), tmpdir=str(self.dir / "tmp")))
        return r, wt, tip

    def posture_files(self, wt):
        d = wt / "docs" / "posture"
        return {p.name: p.read_bytes() for p in sorted(d.glob("*"))} if d.exists() else {}

    def test_the_python_recapture_writes_no_copy_and_runs_isolated_7617(self):
        rel = "scripts/recapture-cert-3607-posture.py"
        r, wt, tip = self.build(rel, RECAPTURE_PY)
        spy = Spy(r.run)
        with mock.patch.object(r, "run", side_effect=spy):
            r.posture(Path("d-bin"), Path("s-bin"))
        argv = spy.python_runs()[0]
        self.assertEqual(argv[1:3], ["-I", "-c"], argv)
        self.assertEqual(argv[-1], str(wt / rel))
        self.assertEqual([p for p in tree(wt) if "recapture-cert7" in p], [])
        self.assertEqual(r.bad, 0)

    def test_a_link_planted_at_the_old_fixed_name_is_never_written_through_7617(self):
        rel = "scripts/recapture-cert-3607-posture.py"
        r, wt, tip = self.build(rel, RECAPTURE_PY)
        victim = self.dir / "victim.txt"
        victim.write_text("victim data\n")
        os.symlink(victim, wt / "scripts" / ".recapture-cert7.py")
        r.posture(Path("d-bin"), Path("s-bin"))
        self.assertEqual(victim.read_text(), "victim data\n")
        self.assertTrue((wt / "scripts" / ".recapture-cert7.py").is_symlink(), "the planted link is left as it was")

    def test_a_link_planted_at_the_old_shell_name_is_never_written_through_7617(self):
        rel = "scripts/recapture-cert-3607-posture.sh"
        r, wt, tip = self.build(rel, RECAPTURE_SH)
        victim = self.dir / "victim.txt"
        victim.write_text("victim data\n")
        os.symlink(victim, wt / "scripts" / ".recapture-cert7.sh")
        r.posture(Path("d-bin"), Path("s-bin"))
        self.assertEqual(victim.read_text(), "victim data\n")

    def test_a_stdlib_named_module_in_scripts_is_not_imported_by_the_recapture_7617(self):
        rel = "scripts/recapture-cert-3607-posture.py"
        r, wt, tip = self.build(rel, RECAPTURE_PY)
        (wt / "scripts" / "json.py").write_text(PLANTED)
        (wt / "json.py").write_text(PLANTED)
        r.posture(Path("d-bin"), Path("s-bin"))
        log = (self.dir / "o" / "posture.log").read_text()
        self.assertNotIn("PLANTED-MODULE-RAN", log)
        self.assertIn("JSON-FROM", log)
        self.assertEqual(r.bad, 0, (self.dir / "o" / "posture.log").read_text())

    def test_the_shell_recapture_runs_from_the_checkout_path_with_no_copy_7617(self):
        rel = "scripts/recapture-cert-3607-posture.sh"
        r, wt, tip = self.build(rel, RECAPTURE_SH)
        before = tree(wt)
        spy = Spy(r.run)
        with mock.patch.object(r, "run", side_effect=spy):
            r.posture(Path("d-bin"), Path("s-bin"))
        argv = spy.calls[0][0]
        self.assertEqual(argv[0], "bash")
        self.assertEqual(argv[-1], str(wt / rel), "$0 is the checkout path, so ROOT is unchanged")
        self.assertEqual([p for p in tree(wt) if "recapture-cert7" in p], [])
        self.assertIn("root=repo", (self.dir / "o" / "evidence" / "posture-a.out").read_text()
                      if (self.dir / "o" / "evidence" / "posture-a.out").exists() else "root=repo")
        self.assertEqual(r.bad, 0)
        self.assertEqual(tree(wt), before)  # the run writes under outd only; the checkout gains no file
        self.assertEqual([p for p in tree(wt) if p.startswith("scripts/.")], [])

    def parity(self, rel, body, runner):
        """The retargeted body run from a file (the r6 way) and run in memory (r7) produce the same output bytes."""
        r, wt, tip = self.build(rel, body)
        rel_, src, _blob = self.rc.recapture_blob(r.wt, r.tip)
        outd = self.dir / "o"
        ev = outd / "evidence"
        if rel.endswith(".py"):
            text, n1 = re.subn(r"^OUT = ROOT / .*$", lambda _m: f"OUT = Path({str(ev)!r})", src, flags=re.M)
            text, n2 = re.subn(r"^FIX = ROOT / .*$", lambda _m: f"FIX = Path({str(outd / 'fix')!r})", text, flags=re.M)
            old_file, old_argv = wt / "scripts" / ".recapture-cert7.py", [sys.executable]
        else:
            text, n1, n2 = self.rc.retarget_shell(src, ev, outd / "fix")
            old_file, old_argv = wt / "scripts" / ".recapture-cert7.sh", ["bash"]
        self.assertEqual((n1, n2), (1, 1))
        env = {**os.environ, "DEFAULT_BIN": "d-bin", "SQLCIPHER_BIN": "s-bin", "FIX": str(outd / "fix")}
        old_file.write_text(text)
        try:
            old = subprocess.run([*old_argv, str(old_file)], cwd=wt, env=env, capture_output=True, text=True)
        finally:
            old_file.unlink()
        old_files = {p.name: p.read_bytes() for p in ev.glob("*")}
        for p in ev.glob("*"):
            p.unlink()
        r.posture(Path("d-bin"), Path("s-bin"))
        new_files = {p.name: p.read_bytes() for p in ev.glob("*")}
        return old, old_files, new_files

    def test_in_memory_python_recapture_output_is_byte_identical_to_the_on_disk_run_7617(self):
        old, old_files, new_files = self.parity("scripts/recapture-cert-3607-posture.py", RECAPTURE_PY, None)
        self.assertEqual(old.returncode, 0, old.stderr)
        self.assertTrue(old_files)
        self.assertEqual(new_files, old_files)

    def test_in_memory_shell_recapture_output_is_byte_identical_to_the_on_disk_run_7617(self):
        old, old_files, new_files = self.parity("scripts/recapture-cert-3607-posture.sh", RECAPTURE_SH, None)
        self.assertEqual(old.returncode, 0, old.stderr)
        self.assertTrue(old_files)
        # the shell prints $(basename $0): the on-disk copy was named .recapture-cert7.sh, the checkout path is the tip's name
        norm = lambda files: {k: v.replace(b".recapture-cert7.sh", b"recapture-cert-3607-posture.sh") for k, v in files.items()}
        self.assertEqual(new_files, norm(old_files))


class NoWriteThenExec7617(guard.GuardedCase):
    def test_the_runner_has_no_write_then_exec_site_7617_7618(self):
        """run_cert.py never writes a file it then runs: no write_text / write_bytes / open(..., 'w') feeds a subprocess."""
        tree_ = ast.parse((EVIDENCE_DIR / "run_cert.py").read_text())
        writes = []
        for node in ast.walk(tree_):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr in ("write_text", "write_bytes"):
                writes.append(node.lineno)
        src = (EVIDENCE_DIR / "run_cert.py").read_text().splitlines()
        offenders = [n for n in writes if "tmp.write" in src[n - 1] or "copy" in src[n - 1].lower()]
        self.assertEqual(offenders, [], "a script copy is written and run")
        self.assertNotIn(".recapture-cert7", "\n".join(src))
        self.assertNotIn("O_CREAT", "\n".join(src))

    def test_the_loader_is_isolated_and_reads_stdin_7617(self):
        rc = load("run_cert")
        self.assertIn("sys.stdin.buffer.read()", rc.PY_LOADER)
        self.assertIn("__file__", rc.PY_LOADER)
        self.assertIn("__main__", rc.PY_LOADER)


class StagedBundle7621(BundleFixture):
    def final(self):
        return self.wt / "docs/compliance/evidence" / f"cert-{self.tip[:9]}"

    def leftovers(self):
        found = [p for p in (self.wt / "docs/compliance/evidence").glob("*") if p.name != self.final().name] \
            if (self.wt / "docs/compliance/evidence").exists() else []
        scratch = self.wt / ".local-runs"
        found += list(scratch.glob("*")) if scratch.exists() else []
        return found

    def assert_clean_failure(self, code, text):
        self.assertEqual(code, 1, text)
        self.assertIn("BUNDLE FAILED", text)
        self.assertFalse(self.final().exists(), "no partial cert dir is left in the tree")
        self.assertEqual(self.leftovers(), [], "no staging directory is left behind")

    def assert_rerun_succeeds(self):
        code, text = self.build()
        self.assertEqual(code, 0, text)
        self.assertTrue((self.final() / "MANIFEST.sha256").is_file())
        self.assertEqual(self.leftovers(), [])

    def test_a_write_failure_leaves_no_partial_bundle_7621(self):
        real = Path.write_bytes
        calls = []

        def flaky(self_, data):
            calls.append(self_.name)
            if len(calls) == 3:
                raise OSError(28, "No space left on device")
            return real(self_, data)
        with mock.patch.object(Path, "write_bytes", flaky):
            code, text = self.build()
        self.assert_clean_failure(code, text)
        self.assert_rerun_succeeds()

    def test_a_chmod_failure_leaves_no_partial_bundle_7621(self):
        real = Path.chmod
        count = []

        def flaky(self_, mode, *a, **kw):
            count.append(1)
            if len(count) == 2:
                raise PermissionError(1, "Operation not permitted")
            return real(self_, mode, *a, **kw)
        with mock.patch.object(Path, "chmod", flaky):
            code, text = self.build()
        self.assert_clean_failure(code, text)
        self.assert_rerun_succeeds()

    def test_a_manifest_write_failure_leaves_no_partial_bundle_7621(self):
        real = Path.write_text

        def flaky(self_, data, *a, **kw):
            if self_.name == "MANIFEST.sha256":
                raise OSError(5, "Input/output error")
            return real(self_, data, *a, **kw)
        with mock.patch.object(Path, "write_text", flaky):
            code, text = self.build()
        self.assert_clean_failure(code, text)
        self.assert_rerun_succeeds()

    def test_a_reverify_mismatch_leaves_no_partial_bundle_7621(self):
        real = Path.write_bytes

        def corrupting(self_, data):
            return real(self_, data + b"corrupt" if self_.name == "SANITIZATION.md" else data)
        with mock.patch.object(Path, "write_bytes", corrupting):
            code, text = self.build()
        self.assert_clean_failure(code, text)
        self.assertIn("re-verify", text)
        self.assert_rerun_succeeds()

    def test_an_unexpected_file_in_the_bundle_leaves_no_partial_bundle_7621(self):
        real = Path.write_text

        def extra(self_, data, *a, **kw):
            out = real(self_, data, *a, **kw)
            if self_.name == "MANIFEST.sha256":
                real(self_.parent / "unexpected.txt", "x\n")
            return out
        with mock.patch.object(Path, "write_text", extra):
            code, text = self.build()
        self.assert_clean_failure(code, text)
        self.assertIn("unexpected", text)
        self.assert_rerun_succeeds()

    def test_a_failed_publish_leaves_no_partial_bundle_7621(self):
        with mock.patch("os.rename", side_effect=OSError(18, "Invalid cross-device link")):
            code, text = self.build()
        self.assert_clean_failure(code, text)
        self.assert_rerun_succeeds()

    def test_an_existing_bundle_is_never_touched_by_a_refused_run_7621(self):
        self.final().mkdir(parents=True)
        (self.final() / "MANIFEST.sha256").write_text("old\n")
        before = {p.name: p.read_bytes() for p in self.final().iterdir()}
        code, text = self.build()
        self.assertEqual(code, 1)
        self.assertIn("already exists", text)
        self.assertEqual({p.name: p.read_bytes() for p in self.final().iterdir()}, before)
        self.assertEqual(self.leftovers(), [])

    def test_a_good_run_publishes_the_staged_bundle_with_the_right_modes_7621(self):
        code, text = self.build()
        self.assertEqual(code, 0, text)
        self.assertEqual(self.leftovers(), [])
        names = sorted(p.name for p in self.final().iterdir())
        self.assertIn("MANIFEST.sha256", names)
        mode = stat.S_IMODE((self.final() / "MANIFEST.sha256").stat().st_mode)
        self.assertEqual(mode, 0o644)
        self.assertEqual(stat.S_IMODE((self.final() / "recapture-posture.py").stat().st_mode), 0o755)


# ---- the runtime tmp-root guard (#7619) -------------------------------------------------------------------------
class RuntimeGuard7619(ScratchCase):
    def setUp(self):
        super().setUp()
        self.fake = self.dir / T  # a fake tmp root under the checkout's .local-runs
        self.fake.mkdir()
        (self.dir / "src.txt").write_text("source\n")
        self.src = str(self.dir / "src.txt")
        (self.fake / "sub").mkdir()

    def test_the_real_roots_are_the_ones_the_runner_forbids_7619(self):
        rc = load("run_cert")
        for root in guard.REAL_ROOTS[:3]:  # the runner forbids these three; the hook also covers the fourth
            self.assertTrue(rc.is_tmpfs_path(root + "/x", ""), root)

    def test_the_pure_check_flags_every_event_class_on_the_real_roots_7619(self):
        roots = guard.resolved_roots()
        real = guard.REAL_ROOTS[0]
        cases = (("open", (real + "/x", "w", 0)), ("os.mkdir", (real + "/x", 0o777, None)),
                 ("os.rename", ("a", real + "/x", None, None)), ("os.rename", (real + "/x", "a", None, None)),
                 ("os.replace", ("a", real + "/x", None, None)),
                 ("shutil.copyfile", ("a", real + "/x")), ("shutil.copytree", (real + "/x", "a")),
                 ("shutil.move", ("a", real + "/x")), ("shutil.rmtree", (real + "/x", None)),
                 ("shutil.make_archive", (real + "/x", "zip", "a")), ("tempfile.mkdtemp", (real + "/abc",)),
                 ("tempfile.mkstemp", (real + "/abc",)), ("open", (real.upper() + "/x", "w", 0)),
                 ("open", (real + "/../" + real.lstrip("/") + "/x", "w", 0)))
        for event, args in cases:
            with self.subTest(event=event, args=args):
                self.assertIsNotNone(guard.finding(event, args, roots))
        for event, args in (("open", (str(self.dir / "ok"), "w", 0)), ("os.mkdir", ("relative", 0o777, None)),
                            ("open", (3, "r", 0)), ("socket.connect", (real,)), ("os.remove", (real + "/x",))):
            with self.subTest(event=event, args=args, ok=True):
                self.assertIsNone(guard.finding(event, args, roots))

    def test_a_live_call_in_each_class_raises_and_is_recorded_7619(self):
        f = self.fake
        calls = {
            "open": lambda: open(f / "a.txt", "w"),
            "os.mkdir": lambda: os.mkdir(f / "d"),
            "os.rename dst": lambda: os.rename(self.src, f / "moved"),
            "os.rename src": lambda: os.rename(f / "sub", self.dir / "gone"),
            "os.replace": lambda: os.replace(self.src, f / "replaced"),
            "shutil.copyfile": lambda: __import__("shutil").copyfile(self.src, f / "copy"),
            "shutil.move": lambda: __import__("shutil").move(self.src, str(f / "mv")),
            "shutil.rmtree": lambda: __import__("shutil").rmtree(f / "sub"),
            "tempfile.mkdtemp": lambda: tempfile.mkdtemp(dir=f),
            "tempfile.mkstemp": lambda: tempfile.mkstemp(dir=f),
            "tempfile.TemporaryDirectory": lambda: tempfile.TemporaryDirectory(dir=f),
            "tempfile.NamedTemporaryFile": lambda: tempfile.NamedTemporaryFile(dir=f),
            "tempfile.TemporaryFile": lambda: tempfile.TemporaryFile(dir=f),
        }
        for label, call in calls.items():
            with self.subTest(call=label):
                with guard.captured(f) as sink:
                    with self.assertRaises(guard.TmpRootViolation):
                        call()
                self.assertTrue(sink, label)
        self.assertEqual(sorted(p.name for p in f.iterdir()), ["sub"], "nothing was created under the fake root")

    def test_a_path_outside_the_root_and_a_reader_of_a_sibling_name_pass_7619(self):
        with guard.captured(self.fake) as sink:
            (self.dir / "fine.txt").write_text("ok\n")
            os.mkdir(self.dir / "fine-dir")
            os.rename(self.dir / "fine.txt", self.dir / "fine2.txt")
            with tempfile.TemporaryDirectory(dir=self.dir):
                pass
        self.assertEqual(sink, [])

    def test_a_symlink_to_the_root_is_resolved_7619(self):
        link = self.dir / "link"
        os.symlink(self.fake, link)
        with guard.captured(self.fake) as sink:
            with self.assertRaises(guard.TmpRootViolation):
                open(link / "x", "w")
        self.assertTrue(sink)

    def test_a_violation_swallowed_by_the_code_still_fails_the_test_7619(self):
        fake = self.fake

        class Inner(guard.GuardedCase):
            def test_swallow(self):
                with contextlib.suppress(Exception):
                    os.mkdir(fake / "swallowed")

        with mock.patch.object(guard, "_REAL", guard.resolved_roots([str(fake)])):
            result = unittest.TextTestRunner(stream=io.StringIO()).run(unittest.defaultTestLoader.loadTestsFromTestCase(Inner))
        self.assertFalse(result.wasSuccessful())
        self.assertEqual(len(result.errors) + len(result.failures), 1)
        del guard.violations[:]  # the nested run recorded the violation on purpose

    def test_the_hook_is_inert_outside_a_guarded_test_7619(self):
        self.assertEqual(guard._active >= 1, True)  # this very test is guarded
        self.assertIsNone(guard.finding("open", (str(self.dir / "x"), "w", 0), guard.resolved_roots()))

    def test_every_evidence_test_class_derives_from_the_guarded_base_7619(self):
        offenders = []
        for f in sorted(TESTS.glob("test_evidence_generator_*.py")):
            for node in ast.walk(ast.parse(f.read_text())):
                if isinstance(node, ast.ClassDef):
                    bases = [ast.unparse(b) for b in node.bases]
                    if "unittest.TestCase" in bases:
                        offenders.append(f"{f.name}:{node.name}")
        self.assertEqual(offenders, [])


# Every spelling the r6 review class list names, as (label, static source, runtime source or None). The static source is
# what the AST guard reads (the real root name is spelled from character codes in T). The runtime source is the same
# construction pointed at a fake root; it ends in a call that touches a path, so the audit hook sees it. Where the
# static and runtime text are the same, the runtime run sets TMPDIR to the fake root and clears tempfile.tempdir.
def _root_spelling(expr):
    """(static, runtime) for a root built by `expr` with @P@ standing for the (empty / fake) prefix."""
    static = "x = " + expr.replace("@P@", "").replace("@T@", T)
    runtime = "import os\nx = " + expr.replace("@T@", T).replace("@P@", "' + FAKE_BASE + '") + "\nos.mkdir(x + '/made')"
    return static, runtime


ROOT_EXPRS = (
    ("percent format", "'@P@/%s' % '@T@'"),
    ("percent tuple", "'%s/%s' % ('@P@', '@T@')"),
    ("str.format", "'@P@/{}'.format('@T@')"),
    ("str.format named", "'@P@/{n}'.format(n='@T@')"),
    ("os.sep concat", "'@P@' + os.sep + '@T@'"),
    ("chr concat", "'@P@/' + chr(%d) + chr(%d) + chr(%d)" % tuple(map(ord, T))),
    ("chr join map", "'@P@/' + ''.join(map(chr, %r))" % (tuple(map(ord, T)),)),
    ("reversed slice", "'@P@/' + '%s'[::-1]" % T[::-1]),
    ("bytes decode", "('@P@/@T@').encode().decode()"),
    ("char join", "''.join(['@P@', '/', %s])" % ", ".join(repr(c) for c in T)),
    ("path anchor division", "str(__import__('pathlib').Path('@P@' or os.sep) / '@T@')"),
)


def _build_spellings():
    out = []
    for label, expr in ROOT_EXPRS:
        static, runtime = _root_spelling(expr)
        out.append((label, static, runtime))
    out += [
        ("bytes literal", "x = b'/%s/a'" % T, "import os\nx = (FAKE_BASE.encode() + b'/%s').decode()\nos.mkdir(x + '/made')" % T),
        ("augmented assignment", "x = '/'\nx += '%s'" % T,
         "import os\nx = FAKE_BASE + '/'\nx += '%s'\nos.mkdir(x + '/made')" % T),
        ("tuple unpacking", "a, b = '/', '%s'\nx = a + b" % T,
         "import os\na, b = FAKE_BASE + '/', '%s'\nx = a + b\nos.mkdir(x + '/made')" % T),
        ("list comprehension", "x = ['/' + p for p in ('%s', 'var/%s')]" % (T, T),
         "import os\nx = [FAKE_BASE + '/' + p for p in ('%s',)]\nos.mkdir(x[0] + '/made')" % T),
        ("generator in tuple (the runner's own form)", "x = tuple('/' + p for p in ('%s', 'var/%s'))" % (T, T),
         "import os\nx = tuple(FAKE_BASE + '/' + p for p in ('%s',))\nos.mkdir(x[0] + '/made')" % T),
        ("Path.home anchor", "from pathlib import Path\nx = Path.home().anchor + '%s'" % T,
         "import os\nfrom pathlib import Path\nx = FAKE_BASE + '/%s'\nos.mkdir(x + '/made')" % T),
        ("Path of anchor division", "from pathlib import Path\nx = Path(Path.cwd().anchor) / '%s'" % T,
         "import os\nfrom pathlib import Path\nx = Path(FAKE_BASE) / '%s'\nos.mkdir(str(x / 'made'))" % T),
        ("aliased tempfile module", "import tempfile as t\nx = t.mkdtemp()", "import tempfile as t\nx = t.mkdtemp()"),
        ("aliased tempfile function", "from tempfile import mkdtemp as m\nx = m()", "from tempfile import mkdtemp as m\nx = m()"),
        ("aliased TemporaryDirectory", "from tempfile import TemporaryDirectory as TD\nx = TD()",
         "from tempfile import TemporaryDirectory as TD\nx = TD()"),
        ("aliased gettempdir", "import tempfile as t\nx = t.gettempdir()",
         "import os, tempfile as t\nx = t.gettempdir()\nos.mkdir(x + '/made')"),
        ("aliased NamedTemporaryFile", "import tempfile as t\nx = t.NamedTemporaryFile(prefix='a')",
         "import tempfile as t\nx = t.NamedTemporaryFile(prefix='a')"),
        ("getattr on tempfile", "import tempfile\nx = getattr(tempfile, 'mkdtemp')()",
         "import tempfile\nx = getattr(tempfile, 'mkdtemp')()"),
        ("importlib on tempfile", "import importlib\nx = importlib.import_module('tempfile').mkdtemp()",
         "import importlib\nx = importlib.import_module('tempfile').mkdtemp()"),
        ("__import__ of tempfile", "x = __import__('tempfile').mkdtemp()", "x = __import__('tempfile').mkdtemp()"),
        ("environ subscript", "import os\nx = os.environ['TMPDIR']",
         "import os\nx = os.environ['TMPDIR']\nos.mkdir(x + '/made')"),
        ("environ get", "import os\nx = os.environ.get('TMPDIR')",
         "import os\nx = os.environ.get('TMPDIR')\nos.mkdir(x + '/made')"),
        ("getenv", "import os\nx = os.getenv('TMPDIR')", "import os\nx = os.getenv('TMPDIR')\nos.mkdir(x + '/made')"),
        ("environ as dir=", "import os, tempfile\nx = tempfile.mkdtemp(dir=os.environ['TMPDIR'])",
         "import os, tempfile\nx = tempfile.mkdtemp(dir=os.environ['TMPDIR'])"),
        ("aliased environ", "from os import environ as e\nx = e['TMPDIR']",
         "import os\nfrom os import environ as e\nx = e['TMPDIR']\nos.mkdir(x + '/made')"),
        ("tempdir assignment", "import tempfile\ntempfile.tempdir = base",
         "import tempfile\ntempfile.tempdir = FAKE_BASE + '/%s'\nx = tempfile.mkdtemp(prefix='a')" % T),
        ("aliased tempdir assignment", "import tempfile as t\nt.tempdir = base",
         "import tempfile as t\nt.tempdir = FAKE_BASE + '/%s'\nx = t.mkdtemp(prefix='a')" % T),
        ("TMP_ROOTS via getattr", "x = getattr(rc, 'TMP_ROOTS')", None),
        ("TMP_ROOTS via vars", "x = vars(rc)['TMP_ROOTS']", None),
        ("TMP_ROOTS via __dict__", "x = rc.__dict__['TMP_ROOTS']", None),
    ]
    return out


SPELLINGS = _build_spellings()


class Spellings7619(ScratchCase):
    def setUp(self):
        super().setUp()
        self.fake = self.dir / T
        self.fake.mkdir()

    def hook_catches(self, runtime):
        """True when the runtime source, run against the fake root, raises TmpRootViolation."""
        env = {"TMPDIR": str(self.fake)}
        ns = {"FAKE_BASE": str(self.dir), "FAKE": str(self.fake), "__builtins__": __builtins__}
        with guard.captured(self.fake) as sink, mock.patch.dict(os.environ, env), \
                mock.patch.object(tempfile, "tempdir", None):
            try:
                exec(compile(runtime, "<spelling>", "exec"), ns)
            except guard.TmpRootViolation:
                return True
        return bool(sink)

    def test_there_are_at_least_thirty_four_spellings_7619(self):
        self.assertGreaterEqual(len(SPELLINGS), 34)
        self.assertEqual(len({label for label, _s, _r in SPELLINGS}), len(SPELLINGS))

    def test_every_spelling_is_caught_by_the_ast_guard_or_the_runtime_hook_7619(self):
        uncaught = []
        for label, static, runtime in SPELLINGS:
            ast_hit = bool(tmp_root_findings(static))
            hook_hit = self.hook_catches(runtime) if runtime else False
            if not (ast_hit or hook_hit):
                uncaught.append(label)
        self.assertEqual(uncaught, [])

    def test_every_spelling_that_builds_a_path_is_caught_at_run_time_7619(self):
        missed = [label for label, _s, runtime in SPELLINGS if runtime and not self.hook_catches(runtime)]
        self.assertEqual(missed, [])

    def test_every_spelling_is_caught_by_the_ast_guard_where_it_can_be_read_statically_7619(self):
        missed = [label for label, static, _r in SPELLINGS if not tmp_root_findings(static)]
        self.assertEqual(missed, [])

    def test_the_guard_still_leaves_honest_code_alone_7619(self):
        honest = (
            "import tempfile as t\nx = t.mkdtemp(prefix='a', dir='.local-runs')",
            "import os\nx = os.environ.get('CERT_TMPDIR')",
            "import os\nx = os.environ['HOME']",
            "x = '%s/%s' % ('a', 'b')",
            "x = '/{}'.format('data')",
            "x = ['/' + p for p in ('data', 'cache')]",
            "from pathlib import Path\nx = Path.home().anchor + 'data'",
            "from tempfile import mkdtemp as m\nx = m(dir=base)",
            "mock.patch.dict(os.environ, {'TMPDIR': fake})",
            "mock.patch.object(rc, 'TMP_ROOTS', (fake,))",
            "x = getattr(rc, 'cargo_slot')",
            "x = vars(rc)['BINS']",
            "x = b'/data/a'",
            "x = '/' + chr(100) + chr(97) + chr(116) + chr(97)",
            "x = '/' + 'atad'[::-1]",
        )
        for src in honest:
            with self.subTest(src=src):
                self.assertEqual(tmp_root_findings(src), [], src)

    def test_the_guard_docstring_claims_only_what_it_checks_7619(self):
        doc = tmp_root_findings.__doc__
        self.assertNotIn("every construction", doc.lower())
        self.assertIn("run time", doc.lower().replace("runtime", "run time"))

    def test_the_module_docstring_does_not_claim_every_construction_7619(self):
        head = Path(TESTS / "test_evidence_generator_r6_7393.py").read_text().split('"""', 2)[1]
        self.assertNotIn("catches every construction", head)

    def test_the_new_test_and_guard_files_construct_no_tmp_root_7619(self):
        for f in (Path(__file__), TESTS / "tmp_runtime_guard_7393.py"):
            with self.subTest(file=f.name):
                self.assertEqual(tmp_root_findings(f.read_text(), own_roots=f.name.startswith("tmp_runtime")), [])


# ---- the CodeQL classes (#7622) ---------------------------------------------------------------------------------
def python_files():
    return sorted([*EVIDENCE_DIR.glob("*.py"), *TESTS.glob("test_evidence_generator_*.py"), TESTS / "tmp_runtime_guard_7393.py"])


class CodeQlClasses7622(guard.GuardedCase):
    def test_no_except_handler_has_an_empty_body_7622(self):
        """py/empty-except (alert 520): an `except` whose body is only `pass` hides what it swallows."""
        bad = []
        for f in python_files():
            for node in ast.walk(ast.parse(f.read_text())):
                if isinstance(node, ast.ExceptHandler) and all(isinstance(s, ast.Pass) for s in node.body):
                    bad.append(f"{f.name}:{node.lineno}")
        self.assertEqual(bad, [])

    def test_no_module_is_imported_both_ways_7622(self):
        """py/import-and-import-from (alert 519): `import m` together with `from m import x` in one file."""
        bad = []
        for f in python_files():
            tree_ = ast.parse(f.read_text())
            plain = {a.name for n in ast.walk(tree_) if isinstance(n, ast.Import) for a in n.names}
            froms = {n.module for n in ast.walk(tree_) if isinstance(n, ast.ImportFrom) and n.module and n.level == 0}
            both = sorted(plain & froms)
            if both:
                bad.append(f"{f.name}: {both}")
        self.assertEqual(bad, [])


if __name__ == "__main__":
    unittest.main()
