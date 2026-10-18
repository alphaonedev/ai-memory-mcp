#!/usr/bin/env python3
"""PR #7393 round 6: gate fixtures for the delta r5 review findings (#7581-#7586) on the vendored certification
evidence generator.

  #7581, #7582  (the expiry gate copy and its sweep: superseded in r7, which runs the gate from memory)
  #7583  the tmp-root AST guard flags the static constructions it lists (see tmp_root_findings; r7 widened it, #7619)
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

from tmp_runtime_guard_7393 import GuardedCase
import unittest.mock as mock

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


# ---- the tmp-root AST guard (#7534, #7583, #7619) ----------------------------------------------------------------
TEMPFILE_DIR_POS = {"mkdtemp": 2, "mkstemp": 2, "TemporaryDirectory": 2, "NamedTemporaryFile": 6,
                    "SpooledTemporaryFile": 7, "TemporaryFile": 6}
TEMPFILE_ALWAYS = ("tempfile.gettempdir", "tempfile.gettempdirb")
ENV_NAMES = ("TMPDIR", "TMP", "TEMP")
FORBIDDEN_ROOTS = tuple("/".join(["", *p.split(".")]) for p in (T, f"var.{T}", "dev.shm", "run"))
UNKNOWN = "\x00"
PATH_CLASSES = ("Path", "PurePath", "PurePosixPath", "PosixPath", "str", "fspath")
SEQ_BUILDERS = ("tuple", "list", "set", "frozenset", "sorted", "reversed")
CHR_NAMES = ("chr", "builtins.chr")
PATH_JOINS = ("os.path.join", "posixpath.join", "ntpath.join", "path.join")
SEP_NAMES = ("os.sep", "os.path.sep", "posixpath.sep")
MISSING = object()


def leaf(func):
    if isinstance(func, ast.Name):
        return func.id
    return func.attr if isinstance(func, ast.Attribute) else None


class Names:
    """Import aliases and plain name aliases of one module. `canon(node)` resolves a Name, an Attribute chain, a
    getattr(x, "name") call or an importlib.import_module("m") / __import__("m") call to its dotted real name."""

    def __init__(self, tree):
        self.alias = {}
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for a in node.names:
                    if a.asname:
                        self.alias[a.asname] = a.name
            elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
                for a in node.names:
                    self.alias[a.asname or a.name] = f"{node.module}.{a.name}"
        for _ in range(3):  # `m = tempfile.mkdtemp` makes m an alias too
            for node in ast.walk(tree):
                if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
                    real = self.canon(node.value)
                    if real and real != node.targets[0].id and "." in real:
                        self.alias[node.targets[0].id] = real

    def canon(self, node):
        if isinstance(node, ast.Name):
            return self.alias.get(node.id, node.id)
        if isinstance(node, ast.Attribute):
            base = self.canon(node.value)
            return f"{base}.{node.attr}" if base else None
        if isinstance(node, ast.Call) and node.args and not node.keywords:
            real = self.canon(node.func)
            first = node.args[0]
            if real in ("getattr", "builtins.getattr") and len(node.args) >= 2:
                base, attr = self.canon(first), node.args[1]
                if base and isinstance(attr, ast.Constant) and isinstance(attr.value, str):
                    return f"{base}.{attr.value}"
            if real in ("importlib.import_module", "__import__", "builtins.__import__"):
                if isinstance(first, ast.Constant) and isinstance(first.value, str):
                    return first.value
        return None


class Folder:
    """Folds an expression to the constant string it spells (or None): literals, bytes, f-strings, `+`, pathlib `/`,
    `%` and str.format, chr(), "".join over constants, comprehensions over constants, reversed slices, .encode() /
    .decode(), os.sep, Path anchors, Path(...) / str(...) / os.path.join / joinpath, names bound by `=`, `+=` and
    tuple unpacking."""

    def __init__(self, names):
        self.names = names
        self.env = {}

    def num(self, node):
        if isinstance(node, ast.Constant) and isinstance(node.value, int) and not isinstance(node.value, bool):
            return node.value
        if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.USub):
            inner = self.num(node.operand)
            return None if inner is None else -inner
        if isinstance(node, ast.Name) and isinstance(self.env.get(node.id), int):
            return self.env[node.id]
        return None

    def raw(self, node):
        number = self.num(node)
        return number if number is not None else self.fold(node)

    def values(self, node):
        """The list of constants a sequence expression yields, or None."""
        if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
            items = [self.raw(e) for e in node.elts]
            return None if any(i is None for i in items) else items
        if isinstance(node, ast.Call) and not node.keywords and not any(isinstance(a, ast.Starred) for a in node.args):
            name = leaf(node.func)
            if name == "range" and node.args and all(self.num(a) is not None for a in node.args):
                return list(range(*[self.num(a) for a in node.args]))
            if name == "map" and len(node.args) == 2 and self.names.canon(node.args[0]) in CHR_NAMES:
                nums = self.values(node.args[1])
                return None if nums is None or not all(isinstance(n, int) for n in nums) else [chr(n) for n in nums]
            if name in SEQ_BUILDERS and len(node.args) == 1:
                inner = self.values(node.args[0])
                if inner is None:
                    return None
                return inner[::-1] if name == "reversed" else (sorted(inner) if name == "sorted" else inner)
        if isinstance(node, (ast.ListComp, ast.GeneratorExp, ast.SetComp)) and len(node.generators) == 1:
            gen = node.generators[0]
            if gen.ifs or gen.is_async or not isinstance(gen.target, ast.Name):
                return None
            source = self.values(gen.iter)
            if source is None:
                return None
            saved, out = self.env.get(gen.target.id, MISSING), []
            try:
                for item in source:
                    self.env[gen.target.id] = item
                    value = self.raw(node.elt)
                    if value is None:
                        return None
                    out.append(value)
            finally:
                if saved is MISSING:
                    self.env.pop(gen.target.id, None)
                else:
                    self.env[gen.target.id] = saved
            return out
        return None

    def strings(self, node):
        items = self.values(node)
        return None if items is None or not all(isinstance(i, str) for i in items) else items

    def fold(self, node):
        if isinstance(node, ast.Constant):
            if isinstance(node.value, bytes):
                return node.value.decode("latin-1")
            return node.value if isinstance(node.value, str) else None
        if isinstance(node, ast.Name):
            value = self.env.get(node.id)
            if isinstance(value, str):
                return value
            return "/" if self.names.canon(node) in SEP_NAMES else None
        if isinstance(node, ast.Attribute):
            if node.attr in ("anchor", "root") and isinstance(node.value, ast.Call):
                return "/"  # an absolute path's anchor
            return "/" if self.names.canon(node) in SEP_NAMES else None
        if isinstance(node, ast.JoinedStr):
            parts = []
            for v in node.values:
                if isinstance(v, ast.Constant):
                    parts.append(str(v.value))
                else:
                    inner = self.fold(v.value) if isinstance(v, ast.FormattedValue) else None
                    parts.append(UNKNOWN if inner is None else inner)
            return "".join(parts)
        if isinstance(node, ast.BoolOp) and isinstance(node.op, ast.Or):
            last = None
            for v in node.values:
                last = self.fold(v)
                if last is None:
                    return None
                if last:
                    return last
            return last
        if isinstance(node, ast.Subscript) and isinstance(node.slice, ast.Slice):
            base = self.fold(node.value)
            given = (node.slice.lower, node.slice.upper, node.slice.step)
            bounds = [None if p is None else self.num(p) for p in given]
            if base is None or any(b is None and p is not None for b, p in zip(bounds, given)):
                return None
            return base[slice(*bounds)]
        if isinstance(node, ast.BinOp):
            left = self.fold(node.left)
            if left is None:
                return None
            if isinstance(node.op, ast.Mod):
                if isinstance(node.right, ast.Tuple):
                    items = [self.fold(e) for e in node.right.elts]
                    operand = None if any(i is None for i in items) else tuple(items)
                else:
                    operand = self.fold(node.right)
                try:
                    return None if operand is None else left % operand
                except (TypeError, ValueError):
                    return None
            if isinstance(node.op, (ast.Add, ast.Div)):
                right = self.fold(node.right)
                if right is None:
                    return None
                return left + right if isinstance(node.op, ast.Add) else posixpath.join(left, right)
            return None
        if isinstance(node, ast.Call):
            return self.fold_call(node)
        return None

    def fold_call(self, node):
        func, args = node.func, node.args
        name, real = leaf(func), self.names.canon(func)
        if any(isinstance(a, ast.Starred) for a in args):
            return None
        if real in CHR_NAMES and len(args) == 1 and self.num(args[0]) is not None:
            try:
                return chr(self.num(args[0]))
            except (ValueError, OverflowError):
                return None
        if isinstance(func, ast.Attribute) and name in ("encode", "decode") and not args:
            return self.fold(func.value)
        if isinstance(func, ast.Attribute) and name == "format":
            fmt = self.fold(func.value)
            pos = [self.fold(a) for a in args]
            kw = {k.arg: self.fold(k.value) for k in node.keywords}
            if fmt is None or None in pos or None in kw or any(v is None for v in kw.values()):
                return None
            try:
                return fmt.format(*pos, **kw)
            except (IndexError, KeyError, ValueError):
                return None
        if node.keywords:
            return None
        if name in PATH_CLASSES or real in PATH_JOINS:
            parts = [self.fold(a) for a in args]
            return None if not parts or None in parts else posixpath.join(*parts)
        if isinstance(func, ast.Attribute) and name == "joinpath":
            base = self.fold(func.value)
            parts = [self.fold(a) for a in args]
            return None if base is None or None in parts else posixpath.join(base, *parts)
        if isinstance(func, ast.Attribute) and name == "join" and len(args) == 1:
            sep, items = self.fold(func.value), self.strings(args[0])
            return None if sep is None or items is None else sep.join(items)
        return None

    def bind(self, stmt):
        if isinstance(stmt, ast.AugAssign):
            if isinstance(stmt.op, ast.Add) and isinstance(stmt.target, ast.Name):
                cur, add = self.env.get(stmt.target.id), self.fold(stmt.value)
                if isinstance(cur, str) and add is not None:
                    self.env[stmt.target.id] = cur + add
            return
        if len(stmt.targets) != 1:
            return
        target = stmt.targets[0]
        if isinstance(target, ast.Name):
            value = self.raw(stmt.value)
            if value is not None:
                self.env[target.id] = value
        elif isinstance(target, ast.Tuple) and isinstance(stmt.value, (ast.Tuple, ast.List)) and \
                len(target.elts) == len(stmt.value.elts):
            for t, v in zip(target.elts, stmt.value.elts):
                value = self.raw(v)
                if isinstance(t, ast.Name) and value is not None:
                    self.env[t.id] = value


def names_a_tmp_root(value):
    if not value or not (value.startswith("/") or value.startswith("$")):
        return False
    if re.match(r"\$\{?TMPDIR\}?(/|$)", value):
        return True
    norm = posixpath.normpath("/" + value.lower().lstrip("/"))
    if norm.startswith("/private/"):
        norm = norm[len("/private"):]
    return any(norm == r or norm.startswith(r + "/") for r in FORBIDDEN_ROOTS)


def tmp_root_findings(source, own_roots=False):
    """A STATIC check of one Python source for the constructions that name a tmp root or default to one. It reports:
    a string the file spells as a tmp-root path or `$TMPDIR/...` (constants only: literals, bytes, f-strings, `+`,
    `/`, `%` and str.format, chr, join and comprehensions over constants, reversed slices, os.sep, Path anchors, `=`,
    `+=` and tuple unpacking); a read of TMP_ROOTS by name, attribute, subscript or getattr; a read of the TMPDIR /
    TMP / TEMP environment variable; a use or an assignment of tempfile.tempdir; tempfile.gettempdir / gettempdirb;
    and a mkdtemp / mkstemp / TemporaryDirectory / NamedTemporaryFile / SpooledTemporaryFile / TemporaryFile call
    without a dir= argument, through import aliases, `x = tempfile.f`, getattr, importlib.import_module and
    __import__. With own_roots=True (the runner, which builds TMP_ROOTS) reads of TMP_ROOTS and comprehensions are
    allowed. It claims only these STATIC literal cases. It cannot see a value known only at run time: bytes(list(...)).decode(),
    "%c" joins, str.lower() of an upper-case constant, codecs rot13 applied twice, os.environ.copy() or dict(os.environ)
    lookups, tempfile._get_default_tempdir(), mkdtemp(dir=<a name bound to None>), an argument, a file or another
    process's output. The audit hook in tmp_runtime_guard_7393 covers those while the tests run, and only for the
    events that module lists."""
    tree = ast.parse(source)
    names = Names(tree)
    folder = Folder(names)
    stmts = sorted((n for n in ast.walk(tree) if isinstance(n, (ast.Assign, ast.AugAssign))),
                   key=lambda n: (n.lineno, n.col_offset))
    for _ in range(3):  # a name bound from another name settles in a few passes
        for st in stmts:
            if isinstance(st, ast.Assign):
                folder.bind(st)
    for st in stmts:  # then source order, for `+=`
        folder.bind(st)
    found = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.Constant, ast.JoinedStr, ast.BinOp, ast.Name, ast.Call, ast.Subscript, ast.Attribute)):
            value = folder.fold(node)
            if names_a_tmp_root(value):
                found.append(f"path {value!r}")
        if isinstance(node, (ast.ListComp, ast.GeneratorExp, ast.SetComp)) and not own_roots:
            for item in folder.strings(node) or []:
                if names_a_tmp_root(item):
                    found.append(f"comprehension path {item!r}")
        if not own_roots:
            if isinstance(node, ast.Attribute) and isinstance(node.ctx, ast.Load) and node.attr == "TMP_ROOTS":
                found.append("TMP_ROOTS read")
            elif isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load) and node.id == "TMP_ROOTS":
                found.append("TMP_ROOTS read")
            elif isinstance(node, ast.Subscript) and folder.fold(node.slice) == "TMP_ROOTS":
                found.append("TMP_ROOTS subscript")
        if isinstance(node, (ast.Attribute, ast.Name)):
            real = names.canon(node)
            if real == "tempfile.tempdir":
                found.append("tempfile.tempdir used")
            elif real in TEMPFILE_ALWAYS:
                found.append(f"{real}")
        if isinstance(node, ast.Subscript) and isinstance(node.ctx, ast.Load) and \
                names.canon(node.value) == "os.environ" and folder.fold(node.slice) in ENV_NAMES:
            found.append(f"environ[{folder.fold(node.slice)!r}] read")
        if isinstance(node, ast.Call):
            real = names.canon(node.func)
            first = folder.fold(node.args[0]) if node.args else None
            if real in ("os.environ.get", "os.getenv", "os.environ.__getitem__") and first in ENV_NAMES:
                found.append(f"{real}({first!r})")
            if real in ("getattr", "builtins.getattr") and len(node.args) >= 2:
                second = folder.fold(node.args[1])
                if second == "TMP_ROOTS" and not own_roots:
                    found.append("TMP_ROOTS via getattr")
                if second == "tempdir" and names.canon(node.args[0]) == "tempfile":
                    found.append("tempfile.tempdir via getattr")
            if real in ("setattr", "builtins.setattr") and len(node.args) >= 2 and \
                    names.canon(node.args[0]) == "tempfile" and folder.fold(node.args[1]) == "tempdir":
                found.append("tempfile.tempdir via setattr")
            if real and real.startswith("tempfile.") and real[len("tempfile."):] in TEMPFILE_DIR_POS:
                name = real[len("tempfile."):]
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


class AstGuard7534(GuardedCase):
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
