#!/usr/bin/env python3
"""PR #7393 round 6: gate fixtures for the delta r5 review findings (#7581-#7586) on the vendored certification
evidence generator.

  #7581  the expiry gate copy runs in isolated mode (`python -I`), so a module planted beside it never replaces the gate
  #7582  the sweep, the identity check and the removal of the copy go through the scratch directory fd, never a path
  #7583  the tmp-root AST guard catches every construction: literals, f-strings, joins, TMP_ROOTS reads, tempfile calls
  #7584  an OSError from the posture recapture is a counted failure with a RED row
  #7585  the tmp-root comparison also resolves each configured root (a root that is itself a symlink)
  #7586  the check_run / check_block docstrings describe the rules the code enforces

Scratch lives under .local-runs/ (never a tmpfs). The tmp-root names this file needs are built from character codes.

Run: python3 -m unittest discover -s scripts/ci/tests -p test_evidence_generator_r6_7393.py
"""
import argparse
import ast
import contextlib
import io
import os
import posixpath
import re
import subprocess
import sys
import unittest
from pathlib import Path
from unittest import mock

from test_evidence_generator_5040_5042 import CHAIN_SECTION, PASSING_GATES, ScratchCase, load
from test_evidence_generator_r3_7393 import GREEN_CHAIN
from test_evidence_generator_r5_7393 import GatesRun

TESTS = Path(__file__).resolve().parent
EVIDENCE_DIR = TESTS.parent.parent / "evidence"
T = "".join(map(chr, (116, 109, 112)))  # the name of the system scratch root, spelled from character codes

REAL_GATE = "import json\nprint('REAL-GATE', json.dumps([1]))\n"
PLANTED = "print('PLANTED-MODULE-RAN')\n"


def dead_pid():
    p = subprocess.Popen([sys.executable, "-c", "pass"])
    p.wait()
    return p.pid


class IsolatedGate7581(GatesRun):
    def test_the_argv_carries_the_isolated_flag_7581(self):
        rc, r, wt, tip = self.make()
        argv = r.pick_expiry()
        r.drop_expiry()
        self.assertEqual(argv[:2], [sys.executable, "-I"], "CI runs the gate as `python3 -I`; so must the runner")
        self.assertEqual(len(argv), 3)

    def test_a_stdlib_named_module_beside_the_copy_does_not_replace_the_gate_7581(self):
        rc, r, wt, tip = self.make({"scripts/check_cert_expiry.py": REAL_GATE})
        (wt / ".local-runs").mkdir(exist_ok=True)
        (wt / ".local-runs" / "json.py").write_text(PLANTED)
        argv = r.pick_expiry()
        out = subprocess.run(argv, cwd=wt, capture_output=True, text=True)
        r.drop_expiry()
        self.assertIn("REAL-GATE", out.stdout, out.stderr)
        self.assertNotIn("PLANTED-MODULE-RAN", out.stdout)

    def test_the_gates_leg_runs_the_gate_isolated_end_to_end_7581(self):
        rc, r, wt, tip = self.make({"scripts/check_cert_expiry.py": REAL_GATE})
        (wt / ".local-runs").mkdir(exist_ok=True)
        (wt / ".local-runs" / "json.py").write_text(PLANTED)
        seen = []
        real = r.run

        def spy(argv, out, extra=None):
            if "-I" in argv or any(str(a).endswith(".py") for a in argv):
                seen.append(list(argv))
            return real(argv, out, extra or {})
        with mock.patch.object(r, "run", side_effect=spy):
            r.gates("0" * 40, "")
        expiry_runs = [a for a in seen if a[0] == sys.executable]
        self.assertEqual(len(expiry_runs), 3)
        self.assertTrue(all(a[1] == "-I" for a in expiry_runs))
        self.assertNotIn("PLANTED-MODULE-RAN", "".join(p.read_text(errors="replace") for p in (self.dir / "o").rglob("*.log")))


class CopyIdentity7581(GatesRun):
    def test_a_copy_replaced_after_creation_is_refused_before_exec_7581(self):
        rc, r, wt, tip = self.make()
        argv = r.pick_expiry()
        r.check_expiry_copy()  # the untouched copy passes
        copy = Path(argv[-1])
        copy.unlink()
        copy.write_text("print('SWAPPED')\n")
        with self.assertRaises(ValueError):
            r.check_expiry_copy()
        r.drop_expiry()

    def test_the_gates_leg_reports_a_replaced_copy_as_red_and_does_not_run_it_7581(self):
        rc = load("run_cert")
        wt, tip = self._repo()
        real_pick = rc.Run.pick_expiry

        def pick_then_swap(self_):
            argv = real_pick(self_)
            Path(argv[-1]).unlink()
            Path(argv[-1]).write_text("print('SWAPPED-RAN')\n")
            return argv
        argv = ["run_cert.py", "gates", "--tip", tip, "--wt", str(wt), "--outd", str(self.dir / "o2"),
                "--targets", str(self.dir / "t"), "--tmpdir", str(self.dir / "tmp")]
        out = io.StringIO()
        with mock.patch.object(rc.Run, "pick_expiry", pick_then_swap), mock.patch.object(sys, "argv", argv), \
                contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
            code = rc.main()
        self.assertEqual(code, 1)
        self.assertIn("RED expiry gate copy", out.getvalue())
        self.assertNotIn("SWAPPED-RAN", out.getvalue())
        self.assertNotIn("Traceback", out.getvalue())

    def _repo(self):
        from test_evidence_generator_r2_7393 import make_repo
        return make_repo(self.dir / "repo2", {"scripts/check_cert_expiry.py": "BLOB = 1\n"})


class FdRelativeWork7582(GatesRun):
    def swap_scratch_for_link(self, wt, victim):
        """Move the real scratch directory aside and put a symlink to `victim` at its path."""
        real = wt / ".local-runs"
        real.rename(wt / ".local-runs-real")
        os.symlink(victim, real)

    def test_a_scratch_path_swapped_for_a_symlink_mid_sweep_deletes_nothing_outside_7582(self):
        rc, r, wt, tip = self.make()
        scratch = wt / ".local-runs"
        scratch.mkdir(exist_ok=True)
        gone = dead_pid()
        name = f".expiry-{gone}-aaaa"
        (scratch / name).mkdir()
        (scratch / name / "inner.txt").write_text("real stale\n")
        victim = self.dir / "victim"
        (victim / name).mkdir(parents=True)
        (victim / name / "keep.txt").write_text("victim data\n")
        (victim / f"{name}.py").write_text("victim file\n")
        swapped = []
        real_kill = os.kill

        def kill_and_swap(pid, sig):
            if not swapped:
                swapped.append(1)
                self.swap_scratch_for_link(wt, victim)
            return real_kill(pid, sig)
        with mock.patch("os.kill", side_effect=kill_and_swap):
            with self.assertRaises(ValueError):  # the path no longer names the directory the fd holds
                r.pick_expiry()
        self.assertEqual((victim / name / "keep.txt").read_text(), "victim data\n")
        self.assertEqual((victim / f"{name}.py").read_text(), "victim file\n")
        self.assertEqual(sorted(p.name for p in victim.iterdir()), sorted([name, f"{name}.py"]))
        self.assertFalse((wt / ".local-runs-real" / name).exists(), "the stale entry of the real directory is removed through the fd")
        self.assertEqual(sorted(p.name for p in (wt / ".local-runs-real").iterdir()), [], "no copy left behind")

    def test_a_stale_directory_with_a_symlink_inside_is_removed_without_following_it_7582(self):
        rc, r, wt, tip = self.make()
        scratch = wt / ".local-runs"
        scratch.mkdir(exist_ok=True)
        outside = self.dir / "outside"
        outside.mkdir()
        (outside / "precious.txt").write_text("keep\n")
        stale = scratch / ".expiry-oldlayout"
        (stale / "sub").mkdir(parents=True)
        (stale / "sub" / "f.txt").write_text("x\n")
        os.symlink(outside, stale / "link")
        os.symlink(outside / "precious.txt", stale / "filelink")
        r.pick_expiry()
        r.drop_expiry()
        self.assertFalse(stale.exists())
        self.assertEqual((outside / "precious.txt").read_text(), "keep\n")

    def test_dropping_the_copy_after_a_path_swap_removes_only_the_real_copy_7582(self):
        rc, r, wt, tip = self.make()
        argv = r.pick_expiry()
        name = Path(argv[-1]).name
        victim = self.dir / "victim2"
        victim.mkdir()
        (victim / name).write_text("victim file\n")
        self.swap_scratch_for_link(wt, victim)
        r.drop_expiry()
        self.assertEqual((victim / name).read_text(), "victim file\n")
        self.assertFalse((wt / ".local-runs-real" / name).exists())

    def test_a_scratch_path_swapped_before_the_run_is_not_followed_7582(self):
        rc, r, wt, tip = self.make()
        (self.dir / "elsewhere").mkdir()
        os.symlink(self.dir / "elsewhere", wt / ".local-runs")
        with self.assertRaises(ValueError):
            r.pick_expiry()
        self.assertEqual(list((self.dir / "elsewhere").iterdir()), [])

    def test_the_docstring_claims_only_what_is_enforced_7581_7582(self):
        doc = load("run_cert").Run.pick_expiry.__doc__
        self.assertIn("-I", doc)
        self.assertIn("same directory", doc)
        self.assertNotIn("at any point", doc)


class PosturePermissionError7584(GatesRun):
    def test_a_permission_error_from_the_recapture_is_a_counted_red_row_7584(self):
        rc, r, wt, tip = self.make()
        out = io.StringIO()
        with mock.patch.object(rc, "recapture_blob", side_effect=PermissionError("denied")), \
                contextlib.redirect_stdout(out):
            r.posture(self.dir / "a", self.dir / "b")  # an uncaught PermissionError would raise here
        self.assertEqual(r.bad, 1)
        self.assertIn("RED posture recapture script", out.getvalue())
        self.assertIn("denied", out.getvalue())
        self.assertNotIn("Traceback", out.getvalue())


class TmpRootRealpath7585(ScratchCase):
    def setUp(self):
        super().setUp()
        self.rc = load("run_cert")
        self.target = os.path.realpath(self.dir / "real-root")
        os.mkdir(self.target)
        self.link = self.dir / "link-to-root"
        os.symlink(self.target, self.link)

    def test_a_path_under_the_target_of_a_symlinked_tmp_root_is_refused_7585(self):
        with mock.patch.object(self.rc, "TMP_ROOTS", (str(self.link),)):
            self.assertTrue(self.rc.is_tmpfs_path(self.target + "/x", ""))
            self.assertTrue(self.rc.is_tmpfs_path(self.target, ""))
            for field in ("targets", "tmpdir"):
                with self.subTest(field=field), self.assertRaises(self.rc.ConfigError):
                    self.rc.Run(argparse.Namespace(tip="a" * 40, wt=str(self.dir), outd=str(self.dir / "o"), leg="chain",
                                                   **{field: self.target + "/x"}))

    def test_the_symlink_spelling_is_still_refused_7585(self):
        with mock.patch.object(self.rc, "TMP_ROOTS", (str(self.link),)):
            self.assertTrue(self.rc.is_tmpfs_path(str(self.link) + "/x", ""))


class CheckRunDocstrings7586(ScratchCase):
    def setUp(self):
        super().setUp()
        self.bb = load("build_bundle")

    def test_check_run_does_not_claim_a_passing_gates_row_never_refuses_7586(self):
        doc = self.bb.check_run.__doc__
        self.assertNotIn("never does", doc)
        self.assertIn("after its EXIT", doc)
        self.assertIn("plan order", doc)
        self.assertIn("legacy", doc)

    def test_check_block_names_the_exit_ordering_rules_7586(self):
        doc = self.bb.check_block.__doc__
        self.assertIn("EXIT", doc)
        self.assertIn("nothing after", doc)
        self.assertIn("plan order", doc)

    def test_the_documented_refusal_and_the_documented_acceptance_hold_7586(self):
        with self.assertRaises(self.bb.Fatal) as cm:
            self.bb.check_run(self.legs(GREEN_CHAIN + "GATES head=abc fails=0\n"))
        self.assertIn("after its EXIT row", str(cm.exception))
        self.assertEqual(len(self.bb.check_run(self.legs(CHAIN_SECTION + PASSING_GATES))), 1)  # a log with no CONFIG row


# ---- the tmp-root AST guard (#7534, #7583) -----------------------------------------------------------------------
TEMPFILE_DIR_POS = {"mkdtemp": 2, "mkstemp": 2, "TemporaryDirectory": 2, "NamedTemporaryFile": 6,
                    "SpooledTemporaryFile": 7, "TemporaryFile": 6}
TEMPFILE_ALWAYS = ("gettempdir", "gettempdirb")
FORBIDDEN_ROOTS = tuple("/".join(["", *p.split(".")]) for p in (T, f"var.{T}", "dev.shm", "run"))
UNKNOWN = "\x00"


def _is_pathjoin(func):
    if isinstance(func, ast.Name):
        return func.id == "join"
    return isinstance(func, ast.Attribute) and func.attr == "join" and (
        (isinstance(func.value, ast.Name) and func.value.id in ("posixpath", "ntpath", "path"))
        or (isinstance(func.value, ast.Attribute) and func.value.attr == "path"))


def fold(node, env):
    """The constant string an expression spells, or None. Folds literals, f-strings, `+`, pathlib `/`, Path(...) with
    several parts, str(...), os.path.join / posixpath.join, joinpath and "<sep>".join([constants])."""
    if isinstance(node, ast.Constant):
        return node.value if isinstance(node.value, str) else None
    if isinstance(node, ast.Name):
        return env.get(node.id)
    if isinstance(node, ast.JoinedStr):
        parts = []
        for v in node.values:
            if isinstance(v, ast.Constant):
                parts.append(str(v.value))
            else:
                inner = fold(v.value, env) if isinstance(v, ast.FormattedValue) else None
                parts.append(UNKNOWN if inner is None else inner)
        return "".join(parts)
    if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Div)):
        left, right = fold(node.left, env), fold(node.right, env)
        if left is None or right is None:
            return None
        return left + right if isinstance(node.op, ast.Add) else posixpath.join(left, right)
    if isinstance(node, ast.Call):
        func, args = node.func, node.args
        if any(isinstance(a, ast.Starred) for a in args) or node.keywords:
            return None
        if isinstance(func, ast.Name) and func.id in ("Path", "PurePath", "PurePosixPath", "str", "fspath") or \
                (isinstance(func, ast.Attribute) and func.attr == "fspath"):
            parts = [fold(a, env) for a in args]
            return None if not parts or None in parts else posixpath.join(*parts)
        if _is_pathjoin(func):
            parts = [fold(a, env) for a in args]
            return None if not parts or None in parts else posixpath.join(*parts)
        if isinstance(func, ast.Attribute) and func.attr == "joinpath":
            base = fold(func.value, env)
            parts = [fold(a, env) for a in args]
            return None if base is None or None in parts else posixpath.join(base, *parts)
        if isinstance(func, ast.Attribute) and func.attr == "join" and len(args) == 1 and isinstance(args[0], (ast.List, ast.Tuple)):
            sep = fold(func.value, env)
            items = [fold(e, env) for e in args[0].elts]
            return None if sep is None or None in items else sep.join(items)
    return None


def names_a_tmp_root(value):
    if not value or not (value.startswith("/") or value.startswith("$")):
        return False
    if re.match(r"\$\{?TMPDIR\}?(/|$)", value):
        return True
    norm = posixpath.normpath("/" + value.lower().lstrip("/"))
    if norm.startswith("/private/"):
        norm = norm[len("/private"):]
    return any(norm == r or norm.startswith(r + "/") for r in FORBIDDEN_ROOTS)


def _tempfile_name(func):
    if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name) and func.value.id == "tempfile":
        return func.attr
    if isinstance(func, ast.Name):
        return func.id
    return None


def tmp_root_findings(source, own_roots=False):
    """Every construction in `source` of a tmp-root path or of a call that defaults to one: a folded string (literal,
    f-string, join, concatenation) naming a tmp root or starting with $TMPDIR, any read of TMP_ROOTS (name, attribute
    or subscript), tempfile.gettempdir / gettempdirb / tempdir, and a mkdtemp / mkstemp / TemporaryDirectory /
    NamedTemporaryFile / SpooledTemporaryFile / TemporaryFile call without a dir= argument (#7534, #7583). The runner
    itself (own_roots=True) owns TMP_ROOTS and may read it; a test may only name it inside mock.patch.object."""
    tree = ast.parse(source)
    env = {}
    for _ in range(3):  # a name bound from another name settles in a few passes
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
                value = fold(node.value, env)
                if value is not None:
                    env[node.targets[0].id] = value
    found = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.Constant, ast.JoinedStr, ast.BinOp, ast.Name, ast.Call)):
            value = fold(node, env)
            if names_a_tmp_root(value):
                found.append(f"path {value!r}")
        if own_roots:
            pass
        elif isinstance(node, ast.Attribute) and isinstance(node.ctx, ast.Load) and node.attr == "TMP_ROOTS":
            found.append("TMP_ROOTS read")
        elif isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load) and node.id == "TMP_ROOTS":
            found.append("TMP_ROOTS read")
        if isinstance(node, ast.Attribute) and isinstance(node.ctx, ast.Load) and node.attr == "tempdir" and \
                isinstance(node.value, ast.Name) and node.value.id == "tempfile":
            found.append("tempfile.tempdir read")
        if isinstance(node, ast.Call):
            name = _tempfile_name(node.func)
            if name in TEMPFILE_ALWAYS:
                found.append(f"{name}()")
            elif name in TEMPFILE_DIR_POS:
                kw = {k.arg: k.value for k in node.keywords if k.arg}
                dirv = kw.get("dir")
                if dirv is None and len(node.args) > TEMPFILE_DIR_POS[name]:
                    dirv = node.args[TEMPFILE_DIR_POS[name]]
                if dirv is None or (isinstance(dirv, ast.Constant) and dirv.value is None):
                    found.append(f"{name}() without dir=")
    return found


def _src(*lines):
    return "\n".join(lines)


# the twelve spellings the r5 review planted, then each form added for #7583
MUST_FLAG = (
    ("literal", f'x = "/{T}/a"'),
    ("bare root", f'x = "/{T}"'),
    ("trailing slash", f'x = "/{T}/"'),
    ("double slash", f'x = "//{T}/a"'),
    ("upper case", f'x = "/{T.upper()}/a"'),
    ("macos private", f'x = "/private/{T}/a"'),
    ("var root", f'x = "/var/{T}/a"'),
    ("dot-dot", f'x = "/a/../{T}/a"'),
    ("dot segment", f'x = "/{T}/./a"'),
    ("parts join", f'x = "/".join(["", "{T}", "cert"])'),
    ("os.path.join", f'import os\nx = os.path.join("/", "{T}", "cert")'),
    ("TMP_ROOTS subscript", 'x = rc.TMP_ROOTS[0] + "/cert"'),
    ("gettempdir", 'import tempfile\nx = tempfile.gettempdir()'),
    ("mkdtemp no dir", 'import tempfile\nx = tempfile.mkdtemp()'),
    ("TemporaryDirectory no dir", 'import tempfile\nx = tempfile.TemporaryDirectory()'),
    ("f-string", f'a = "{T}"\nx = f"/{{a}}/cert"'),
    ("f-string literal", f'x = f"/{T}/{{y}}"'),
    ("name via concatenation", f'R = "/" + "{T}"\ny = R + "/a"'),
    ("pathlib div", f'from pathlib import Path\np = Path("/") / "{T}" / "a"'),
    ("Path with parts", f'from pathlib import Path\np = Path("/", "{T}", "a")'),
    ("joinpath", f'from pathlib import Path\np = Path("/").joinpath("{T}", "a")'),
    ("str of Path", f'from pathlib import Path\np = str(Path("/{T}") / "a")'),
    ("posixpath.join", f'import posixpath\np = posixpath.join("/", "{T}")'),
    ("tuple join", f'p = "/".join(("", "{T}"))'),
    ("join through a name", f'parts = "{T}"\np = "/".join(["", parts])'),
    ("TMP_ROOTS attribute", 'import run_cert\nx = run_cert.TMP_ROOTS'),
    ("TMP_ROOTS name", 'from run_cert import TMP_ROOTS\nx = TMP_ROOTS'),
    ("TMP_ROOTS name subscript", 'x = TMP_ROOTS[0]'),
    ("gettempdirb", 'import tempfile\nx = tempfile.gettempdirb()'),
    ("tempdir attribute", 'import tempfile\nx = tempfile.tempdir'),
    ("mkstemp no dir", 'import tempfile\nx = tempfile.mkstemp()'),
    ("NamedTemporaryFile no dir", 'import tempfile\nx = tempfile.NamedTemporaryFile()'),
    ("SpooledTemporaryFile no dir", 'import tempfile\nx = tempfile.SpooledTemporaryFile()'),
    ("TemporaryFile no dir", 'import tempfile\nx = tempfile.TemporaryFile()'),
    ("mkdtemp prefix only", 'import tempfile\nx = tempfile.mkdtemp(prefix="a")'),
    ("mkdtemp dir=None", 'import tempfile\nx = tempfile.mkdtemp(dir=None)'),
    ("imported mkdtemp", 'from tempfile import mkdtemp\nx = mkdtemp()'),
    ("imported TemporaryDirectory", 'from tempfile import TemporaryDirectory\nx = TemporaryDirectory(prefix="a")'),
    ("TMPDIR variable", 'x = "$TMPDIR/a"'),
    ("TMPDIR braces", 'x = "${TMPDIR}/a"'),
    ("shm", 'x = "/dev/shm/a"'),
    ("run", 'x = "/run/user/1"'),
)
MUST_KEEP = (
    ("honest path", 'x = "/home/a/tmp-notes"'),
    ("sibling name", f'x = "/data/{T}"'),
    ("prefix sibling", f'x = "/{T}x/a"'),
    ("relative", 'x = ".local-runs/a"'),
    ("mkdtemp with dir=", 'import tempfile\nx = tempfile.mkdtemp(prefix="a", dir=".local-runs")'),
    ("mkdtemp positional dir", 'import tempfile\nx = tempfile.mkdtemp("s", "p", ".local-runs")'),
    ("TemporaryDirectory with dir=", 'import tempfile\nx = tempfile.TemporaryDirectory(dir=base)'),
    ("NamedTemporaryFile positional dir", 'import tempfile\nx = tempfile.NamedTemporaryFile("w+b", -1, None, None, "", "", ".local-runs")'),
    ("patching TMP_ROOTS by name", 'mock.patch.object(rc, "TMP_ROOTS", (fake,))'),
    ("join of honest parts", 'import os\nx = os.path.join("/data", "run", "cert")'),
    ("a string join", 'x = ", ".join(["a", "b"])'),
    ("run in the middle", 'x = "/data/run"'),
)


class AstGuard7534(unittest.TestCase):
    def test_no_evidence_test_file_constructs_a_tmp_root_7583(self):
        files = sorted(TESTS.glob("test_evidence_generator_*.py"))
        self.assertGreaterEqual(len(files), 6)
        for f in files:
            with self.subTest(file=f.name):
                self.assertEqual(tmp_root_findings(f.read_text()), [])

    def test_no_evidence_script_constructs_a_tmp_root_7583(self):
        files = sorted(EVIDENCE_DIR.glob("*.py"))
        self.assertGreaterEqual(len(files), 5)
        for f in files:
            with self.subTest(file=f.name):
                self.assertEqual(tmp_root_findings(f.read_text(), own_roots=True), [])

    def test_a_test_reading_tmp_roots_is_flagged_but_the_runner_may_7583(self):
        self.assertTrue(tmp_root_findings("x = rc.TMP_ROOTS[0]"))
        self.assertEqual(tmp_root_findings("x = TMP_ROOTS", own_roots=True), [])

    def test_the_guard_flags_every_construction_it_must_7583(self):
        self.assertGreaterEqual(len(MUST_FLAG), 12 + 8)
        for label, src in MUST_FLAG:
            with self.subTest(spelling=label):
                self.assertTrue(tmp_root_findings(src), src)

    def test_the_guard_leaves_honest_code_alone_7583(self):
        for label, src in MUST_KEEP:
            with self.subTest(case=label):
                self.assertEqual(tmp_root_findings(src), [], src)

    def test_the_guard_does_not_flag_itself_7583(self):
        self.assertEqual(tmp_root_findings(Path(__file__).read_text()), [])


if __name__ == "__main__":
    unittest.main()
