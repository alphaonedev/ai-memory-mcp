#!/usr/bin/env python3
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""A script loads a sibling module from one exact file, never by name through the import search path (#9399).

Class: a script under scripts/ that needs a module from its own folder. The invariant for every such script, for every
way it is started (by path from another working directory, through a symlink, under ``python3 -I``, with a same-named
decoy module on PYTHONPATH and in the working directory and beside the symlink):

* the sibling comes from ``realpath(__file__)``'s folder, loaded by the one loader whose text is
  scripts/ci/sibling_load.py (every script holds that text byte for byte);
* an absent, unreadable, non-regular or out-of-folder sibling ends the script with ONE exact stderr line naming the
  path and the script's own exit code, and no decoy is ever imported;
* ``sys.path`` after the load equals ``sys.path`` before it, and ``sys.modules`` holds the module under the stated name.

The expected values are written out below by hand: SITES (script, prog, exit code, siblings) and the loader outcomes.
Run: python3 -m unittest discover -s scripts/ci/tests -p test_sibling_load_9399.py
"""
import ast
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
SCRIPTS = REPO / "scripts"
CANON_FILE = SCRIPTS / "ci" / "sibling_load.py"
BLOCK_BEGIN = "# >>> sibling-load 9399"
BLOCK_END = "# <<< sibling-load 9399"
PYTHON = sys.executable
SUBPROCESS_TIMEOUT_S = 120
FIFO_TIMEOUT_S = 20
EXIT_REFUSED_DEFAULT = 3
EXIT_REFUSED_SCCACHE = 5  # sccache_env.py already spends 2, 3 and 4 on its own outcomes
MARKER_ENV = "DECOY_MARKER_9399"
DECOY_SOURCE = (
    "import os\n"
    "with open(os.environ[%r], 'a') as handle:\n"
    "    handle.write(__name__ + '\\n')\n"
    "raise RuntimeError('a decoy of the sibling was imported')\n"
) % MARKER_ENV
DRIVER_SOURCE = (
    "import json, runpy, sys\n"
    "script, names = sys.argv[1], sys.argv[2].split(',')\n"
    "before = list(sys.path)\n"
    "runpy.run_path(script, run_name='site_check_9399')\n"
    "print(json.dumps({'path_same': sys.path == before,\n"
    "                  'mods': {n: getattr(sys.modules.get(n), '__file__', None) for n in names}}))\n"
)

# One hand-written row per (script, siblings it loads): (script under scripts/, prog printed in the refusal line,
# exit code of a refused load, ((sibling file, name it is registered under in sys.modules), ...), python flags CI uses).
SITES = (
    ("ci/impact/build_index.py", "build_index", 3, (("common.py", "impact.common"),), ("-I",)),
    ("ci/impact/cargo_skip.py", "cargo_skip", 3, (("common.py", "impact.common"),), ("-I",)),
    ("ci/impact/gate.py", "gate", 3, (("common.py", "impact.common"),), ("-I",)),
    ("ci/impact/read_set.py", "read_set", 3, (("common.py", "impact.common"),), ("-I",)),
    ("ci/impact/select.py", "select", 3, (("common.py", "impact.common"),), ("-I",)),
    ("ci/pg_isolate_split.py", "pg_isolate_split", EXIT_REFUSED_DEFAULT,
     (("partition_test_binaries.py", "partition_test_binaries"),), ()),
    ("ci/prune_runner_artifacts.py", "prune_runner_artifacts", EXIT_REFUSED_DEFAULT,
     (("shared_cargo_target.py", "shared_cargo_target"),), ()),
    ("ci/sccache_env.py", "sccache_env", EXIT_REFUSED_SCCACHE,
     (("shared_cargo_target.py", "shared_cargo_target"),), ()),
    ("bench/mesh_probe.py", "mesh_probe", 3,
     (("benchlib.py", "benchlib"), ("ops_producer.py", "ops_producer")), ()),
    ("bench/ops_producer.py", "ops_producer", 3, (("benchlib.py", "benchlib"),), ()),
    ("bench/wake_latency.py", "wake_latency", 3, (("benchlib.py", "benchlib"),), ()),
    ("bench/host-facts.py", "host-facts", 3, (("benchlib.py", "benchlib"),), ()),
    ("evidence/continuity-cycle.py", "continuity-cycle", 3, (("predicates.py", "predicates"),), ()),
)
SITE_FILES = frozenset(row[0] for row in SITES)
CENSUS_EXCLUDED_PARTS = frozenset({"tests", "test", "__pycache__"})
MIN_FILES_SCANNED = 50


def canon_text():
    return CANON_FILE.read_text(encoding="utf-8")


def block_of(text):
    """The marker-delimited loader block of ``text``, markers included, or None."""
    lines = text.splitlines(keepends=True)
    begin = [i for i, line in enumerate(lines) if line.startswith(BLOCK_BEGIN)]
    end = [i for i, line in enumerate(lines) if line.startswith(BLOCK_END)]
    if len(begin) != 1 or len(end) != 1 or end[0] < begin[0]:
        return None
    return "".join(lines[begin[0]:end[0] + 1])


def run(argv, cwd, env_extra=None, timeout=SUBPROCESS_TIMEOUT_S):
    env = {k: v for k, v in os.environ.items() if not k.startswith("PYTHON")}
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    env.update(env_extra or {})
    return subprocess.run([PYTHON, *argv], cwd=str(cwd), env=env, capture_output=True, text=True, timeout=timeout)


class Scratch(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(prefix="sibling-load-9399-")
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(os.path.realpath(self._tmp.name))

    def make_decoys(self, parent, files, impact):
        """Decoy modules (they write DECOY_MARKER_9399 when imported) for every sibling name, plus an ``impact``
        package when the site is an impact script."""
        parent.mkdir(parents=True, exist_ok=True)
        for name in files:
            (parent / name).write_text(DECOY_SOURCE, encoding="utf-8")
        if impact:
            (parent / "impact").mkdir(exist_ok=True)
            (parent / "impact" / "__init__.py").write_text(DECOY_SOURCE, encoding="utf-8")
            (parent / "impact" / "common.py").write_text(DECOY_SOURCE, encoding="utf-8")


def decoy_names(script_rel):
    row = next(r for r in SITES if r[0] == script_rel)
    names = {sibling for sibling, _ in row[3]}
    if script_rel.startswith("bench/mesh_probe") or script_rel.startswith("bench/ops_producer"):
        names.add("benchlib.py")
    return sorted(names)


class SiteMatrix(Scratch):
    """Every site, started the ways CI and a developer start it, with decoys: the real sibling runs, no decoy."""

    def start_cells(self, row):
        script_rel, prog, code, siblings, flags = row
        real = SCRIPTS / script_rel
        impact = script_rel.startswith("ci/impact/")
        names = decoy_names(script_rel)
        decoy_path = self.root / "decoy-pythonpath"
        decoy_cwd = self.root / "decoy-cwd"
        self.make_decoys(decoy_path, names, impact)
        self.make_decoys(decoy_cwd, names, impact)
        linkdir = self.root / "link" / real.parent.name
        self.make_decoys(linkdir, names, impact)
        link = linkdir / real.name
        os.symlink(real, link)
        (self.root / "driver.py").write_text(DRIVER_SOURCE, encoding="utf-8")
        return real, link, decoy_path, decoy_cwd

    def check_row(self, row):
        script_rel, prog, code, siblings, flags = row
        real, link, decoy_path, decoy_cwd = self.start_cells(row)
        names_csv = ",".join(name for _, name in siblings)
        for mode in ((), ("-I",)):
            for label, start in (("direct", real), ("symlink", link)):
                marker = self.root / ("marker-%s-%s-%s" % (script_rel.replace("/", "_"), label, "-".join(mode) or "plain"))
                with self.subTest(script=script_rel, mode=mode or "plain", start=label):
                    got = run([*mode, str(self.root / "driver.py"), str(start), names_csv], decoy_cwd,
                              {"PYTHONPATH": str(decoy_path), MARKER_ENV: str(marker)})
                    self.assertEqual(got.returncode, 0, got.stderr)
                    self.assertFalse(marker.exists(), "a decoy was imported: " + marker.read_text() if marker.exists() else "")
                    report = json.loads(got.stdout.strip().splitlines()[-1])
                    self.assertTrue(report["path_same"], "sys.path changed by the load")
                    for sibling, module_name in siblings:
                        self.assertEqual(report["mods"][module_name], os.path.realpath(real.parent / sibling))
        marker = self.root / ("marker-help-" + script_rel.replace("/", "_"))
        with self.subTest(script=script_rel, start="ci-shaped --help"):
            got = run([*flags, str(real), "--help"], decoy_cwd, {"PYTHONPATH": str(decoy_path), MARKER_ENV: str(marker)})
            self.assertEqual(got.returncode, 0, got.stderr)
            self.assertFalse(marker.exists())

    def test_every_site_loads_the_real_sibling(self):
        for row in SITES:
            try:
                self.check_row(row)
            finally:
                for leftover in ("link", "decoy-pythonpath", "decoy-cwd"):
                    shutil.rmtree(self.root / leftover, ignore_errors=True)


class AbsentSibling(Scratch):
    """A copy of the script folder without the sibling, decoys of it on PYTHONPATH and in the cwd: one exact message,
    the script's own exit code, no decoy."""

    def check_absent(self, row, sibling):
        script_rel, prog, code, siblings, flags = row
        folder_rel = Path(script_rel).parent
        copy_dir = self.root / "scripts" / folder_rel
        shutil.copytree(SCRIPTS / folder_rel, copy_dir, ignore=shutil.ignore_patterns("tests", "__pycache__", sibling))
        impact = script_rel.startswith("ci/impact/")
        decoy_path = self.root / "decoy-pythonpath"
        decoy_cwd = self.root / "decoy-cwd"
        for parent in (decoy_path, decoy_cwd):
            self.make_decoys(parent, decoy_names(script_rel), impact)
        marker = self.root / ("marker-absent-" + script_rel.replace("/", "_") + "-" + sibling)
        script = copy_dir / Path(script_rel).name
        got = run([*flags, str(script), "--help"], decoy_cwd, {"PYTHONPATH": str(decoy_path), MARKER_ENV: str(marker)})
        expected = "%s: refused: sibling module %s at %s cannot be loaded (absent)\n" % (
            prog, sibling, os.path.join(os.path.realpath(copy_dir), sibling))
        self.assertEqual(got.stderr, expected)
        self.assertEqual(got.returncode, code)
        self.assertEqual(got.stdout, "")
        self.assertFalse(marker.exists(), "a decoy of the absent sibling was imported")

    def test_every_site_refuses_an_absent_sibling(self):
        for row in SITES:
            for sibling, _ in row[3]:
                with self.subTest(script=row[0], sibling=sibling):
                    try:
                        self.check_absent(row, sibling)
                    finally:
                        for leftover in ("scripts", "decoy-pythonpath", "decoy-cwd"):
                            shutil.rmtree(self.root / leftover, ignore_errors=True)


class LoaderAlone(Scratch):
    """The loader text of sibling_load.py, run in a namespace whose ``__file__`` is a scratch script."""

    def setUp(self):
        super().setUp()
        block = block_of(canon_text())
        self.assertIsNotNone(block, "sibling_load.py has no single marker-delimited block")
        self.folder = self.root / "scripts" / "ci"
        self.folder.mkdir(parents=True)
        self.script = self.folder / "tool.py"
        self.script.write_text("# the loading script\n", encoding="utf-8")
        self.ns = {"__file__": str(self.script), "__name__": "tool_9399"}
        exec(compile(block, str(CANON_FILE), "exec"), self.ns)
        self.names = []
        self.addCleanup(self.forget)

    def forget(self):
        for name in self.names:
            sys.modules.pop(name, None)

    def load(self, filename, name):
        self.names.append(name)
        before = list(sys.path)
        try:
            return self.ns["_load_sibling"](filename, name)
        finally:
            self.assertEqual(sys.path, before, "sys.path changed across the call")

    def refused(self, filename, name, reason):
        before = dict(sys.modules)
        with self.assertRaises(self.ns["SiblingLoadError"]) as caught:
            self.load(filename, name)
        self.assertEqual(caught.exception.reason, reason)
        self.assertEqual(dict(sys.modules), before, "a refused load left a registration")

    def write(self, name, text, mode="w"):
        path = self.folder / name
        if isinstance(text, bytes):
            path.write_bytes(text)
        else:
            path.write_text(text, encoding="utf-8")
        return path

    def test_a_present_sibling_loads_registers_and_is_reused(self):
        self.write("helper.py", "VALUE = 7\n")
        module = self.load("helper.py", "helper_9399_a")
        self.assertEqual(module.VALUE, 7)
        self.assertEqual(module.__file__, os.path.realpath(self.folder / "helper.py"))
        self.assertIs(sys.modules["helper_9399_a"], module)
        self.assertIs(self.load("helper.py", "helper_9399_a"), module)

    def test_a_dataclass_in_the_sibling_works(self):
        self.write("dc.py", "from dataclasses import dataclass\n@dataclass\nclass P:\n    x: int = 1\nVALUE = P().x\n")
        self.assertEqual(self.load("dc.py", "dc_9399").VALUE, 1)

    def test_absent(self):
        self.refused("missing.py", "missing_9399", "absent")

    def test_a_path_through_a_regular_file_is_unreadable(self):
        self.write("plain.txt", "x")
        self.refused("plain.txt/inner.py", "inner_9399", "unreadable")

    def test_a_file_without_read_permission_is_unreadable(self):
        path = self.write("locked.py", "VALUE = 1\n")
        path.chmod(0)
        self.addCleanup(path.chmod, stat.S_IRUSR | stat.S_IWUSR)
        if os.geteuid() == 0:
            self.assertEqual(self.load("locked.py", "locked_9399").VALUE, 1)  # root reads it: the row is the same load
        else:
            self.refused("locked.py", "locked_9399", "unreadable")

    def test_a_directory_is_not_a_regular_file(self):
        (self.folder / "adir.py").mkdir()
        self.refused("adir.py", "adir_9399", "not a regular file")

    def test_a_fifo_is_refused_without_blocking(self):
        os.mkfifo(self.folder / "pipe.py")
        started = time.monotonic()
        self.refused("pipe.py", "pipe_9399", "not a regular file")
        self.assertLess(time.monotonic() - started, FIFO_TIMEOUT_S)

    def test_a_symlink_inside_the_folder_is_followed(self):
        self.write("real_target.py", "VALUE = 3\n")
        os.symlink(self.folder / "real_target.py", self.folder / "alias.py")
        module = self.load("alias.py", "alias_9399")
        self.assertEqual(module.VALUE, 3)
        self.assertEqual(module.__file__, os.path.realpath(self.folder / "real_target.py"))

    def test_a_symlink_leaving_the_folder_is_refused(self):
        outside = self.root / "outside.py"
        outside.write_text("VALUE = 9\n", encoding="utf-8")
        os.symlink(outside, self.folder / "escape.py")
        self.refused("escape.py", "escape_9399", "symlink leaves the script folder")

    def test_a_dotdot_name_is_refused(self):
        (self.root / "scripts" / "up.py").write_text("VALUE = 2\n", encoding="utf-8")
        self.refused("../up.py", "up_9399", "symlink leaves the script folder")

    def test_a_final_component_swapped_for_a_symlink_after_the_resolve_is_refused(self):
        self.write("target.py", "VALUE = 1\n")
        os.symlink(self.folder / "target.py", self.folder / "swapped.py")
        real = os.path.realpath

        def unresolved(path, *args, **kwargs):
            return path if str(path).endswith("swapped.py") else real(path, *args, **kwargs)

        from unittest import mock
        with mock.patch.object(os.path, "realpath", unresolved):
            self.refused("swapped.py", "swapped_9399", "unreadable")

    def test_a_name_taken_by_another_file_is_refused_and_left_alone(self):
        self.write("one.py", "VALUE = 1\n")
        sentinel = type(sys)("taken_9399")
        sentinel.__file__ = str(self.root / "elsewhere.py")
        sys.modules["taken_9399"] = sentinel
        self.addCleanup(sys.modules.pop, "taken_9399", None)
        with self.assertRaises(self.ns["SiblingLoadError"]) as caught:
            self.load("one.py", "taken_9399")
        self.assertEqual(caught.exception.reason, "module name taken")
        self.assertIs(sys.modules["taken_9399"], sentinel)

    def test_bad_utf8_reaches_the_caller_with_its_own_type(self):
        self.write("bad.py", b"VALUE = '\xff\xfe'\n")
        with self.assertRaises(SyntaxError):
            self.load("bad.py", "bad_9399")
        self.assertNotIn("bad_9399", sys.modules)

    def test_an_error_at_import_reaches_the_caller_with_its_own_type(self):
        self.write("boom.py", "raise ZeroDivisionError('boom')\n")
        with self.assertRaises(ZeroDivisionError):
            self.load("boom.py", "boom_9399")
        self.assertNotIn("boom_9399", sys.modules)

    def test_a_system_exit_at_import_reaches_the_caller(self):
        self.write("quit.py", "raise SystemExit(7)\n")
        with self.assertRaises(SystemExit) as caught:
            self.load("quit.py", "quit_9399")
        self.assertEqual(caught.exception.code, 7)
        self.assertNotIn("quit_9399", sys.modules)

    def test_sys_path_is_restored_whatever_the_sibling_did(self):
        for index, body in enumerate((
            "import sys\nsys.path.insert(0, '/nonexistent-9399')\n",
            "import sys\nsys.path.append('/nonexistent-9399')\n",
            "import sys\nsys.path[:] = []\n",
            "import sys\nsys.path.insert(0, '/nonexistent-9399')\nraise KeyError('x')\n",
        )):
            name = "pathy%d_9399" % index
            self.write(name + ".py", body)
            try:
                self.load(name + ".py", name)
            except KeyError:
                pass

    def test_the_refusal_line_is_exact(self):
        import io
        from contextlib import redirect_stderr
        cases = (
            (self.ns["SiblingLoadError"]("absent"), "absent"),
            (ZeroDivisionError("secret value"), "ZeroDivisionError"),
            (SystemExit(4), "SystemExit"),
        )
        for exc, why in cases:
            captured = io.StringIO()
            with redirect_stderr(captured):
                self.ns["_sibling_refusal"]("tool", "helper.py", exc)
            self.assertEqual(captured.getvalue(), "tool: refused: sibling module helper.py at %s cannot be loaded (%s)\n"
                             % (os.path.join(os.path.realpath(self.folder), "helper.py"), why))

    def test_a_hostile_exception_name_cannot_forge_the_line(self):
        import io
        from contextlib import redirect_stderr
        hostile = type("Bad\nname", (Exception,), {})("x")
        captured = io.StringIO()
        with redirect_stderr(captured):
            self.ns["_sibling_refusal"]("tool", "helper.py", hostile)
        self.assertEqual(captured.getvalue().count("\n"), 1)
        self.assertTrue(captured.getvalue().endswith("(BaseException)\n"))

    def test_a_control_character_in_the_folder_name_cannot_start_a_second_line(self):
        """The path in the line comes from the checkout: a newline or ESC in a folder name is printed as its escape."""
        import io
        from contextlib import redirect_stderr
        for raw, shown in (("a\n::error::x", "a\\n::error::x"), ("b\r##[error]y", "b\\r##[error]y"),
                           ("c\x1b[2Kz", "c\\x1b[2Kz"), ("d e", "d\\u2028e")):
            with self.subTest(folder=shown):
                folder = self.root / raw
                folder.mkdir()
                ns = {"__file__": str(folder / "tool.py"), "__name__": "tool_ctl_9399"}
                exec(compile(block_of(canon_text()), str(CANON_FILE), "exec"), ns)
                captured = io.StringIO()
                with redirect_stderr(captured):
                    ns["_sibling_refusal"]("tool", "helper.py", ns["SiblingLoadError"]("absent"))
                line = captured.getvalue()
                self.assertEqual(line.count("\n"), 1)
                self.assertEqual(line, "tool: refused: sibling module helper.py at %s cannot be loaded (absent)\n"
                                 % (os.path.join(os.path.realpath(self.root), shown, "helper.py")))


class CopiesMatchTheLoader(unittest.TestCase):
    def test_every_site_holds_the_canonical_block_byte_for_byte(self):
        canon = block_of(canon_text())
        self.assertIsNotNone(canon)
        for script_rel in sorted(SITE_FILES):
            with self.subTest(script=script_rel):
                path = SCRIPTS / script_rel
                self.assertTrue(path.is_file(), script_rel + " does not exist")
                self.assertEqual(block_of(path.read_text(encoding="utf-8")), canon)

    def test_no_other_script_holds_a_loader_block(self):
        holders = {str(p.relative_to(SCRIPTS)) for p in SCRIPTS.rglob("*.py")
                   if any(line.startswith(BLOCK_BEGIN) for line in p.read_text(encoding="utf-8").splitlines())}
        self.assertEqual(holders - SITE_FILES, {"ci/sibling_load.py"})

    def test_every_site_calls_the_loader_once_per_sibling_with_its_own_exit_code(self):
        for script_rel, prog, code, siblings, _flags in SITES:
            with self.subTest(script=script_rel):
                text = (SCRIPTS / script_rel).read_text(encoding="utf-8")
                for sibling, module_name in siblings:
                    self.assertEqual(text.count('_load_sibling("%s", "%s")' % (sibling, module_name)), 1)
                self.assertIn('SIBLING_PROG = "%s"' % prog, text)
                self.assertIn("SIBLING_EXIT_LOAD_REFUSED = %d" % code, text)


def scripts_tree_names(path):
    """Names a file in the scripts tree can import from its own folder or an ancestor folder up to scripts/."""
    names = set()
    folder = path.parent
    while True:
        names |= {p.stem for p in folder.glob("*.py")} | {p.name for p in folder.iterdir() if p.is_dir()}
        if folder == SCRIPTS:
            break
        folder = folder.parent
    return names - set(sys.stdlib_module_names)


def census_findings(path):
    """Findings of one file: sys.path changes, same-tree imports by name, relative imports, by-name dynamic imports."""
    text = path.read_text(encoding="utf-8")
    block = block_of(text)
    if block is not None:
        # The loader block restores sys.path by design; its text is pinned byte for byte to the canonical file by
        # CopiesMatchTheLoader, so blank it (keeping the line numbers) instead of reading it as a violation.
        text = text.replace(block, "\n" * block.count("\n"))
    tree = ast.parse(text, filename=str(path))
    tree_names = scripts_tree_names(path)
    found = []

    def is_sys_path(node):
        return (isinstance(node, ast.Attribute) and node.attr == "path"
                and isinstance(node.value, ast.Name) and node.value.id == "sys")

    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and is_sys_path(node.func.value):
            found.append((node.lineno, "sys.path." + node.func.attr))
        elif isinstance(node, (ast.Assign, ast.AugAssign, ast.AnnAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            for target in targets:
                inner = target.value if isinstance(target, ast.Subscript) else target
                if is_sys_path(inner):
                    found.append((node.lineno, "sys.path assignment"))
        elif isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.split(".")[0] in tree_names:
                    found.append((node.lineno, "import " + alias.name))
        elif isinstance(node, ast.ImportFrom):
            if node.level > 0:
                found.append((node.lineno, "relative import"))
            elif node.module and node.module.split(".")[0] in tree_names:
                found.append((node.lineno, "from " + node.module + " import"))
        elif isinstance(node, ast.Call):
            callee = node.func
            name = callee.attr if isinstance(callee, ast.Attribute) else getattr(callee, "id", "")
            if name in ("import_module", "__import__") and node.args:
                arg = node.args[0]
                if isinstance(arg, ast.Constant) and isinstance(arg.value, str) \
                        and arg.value.split(".")[0] in tree_names:
                    found.append((node.lineno, name + "(" + arg.value + ")"))
    return found


class Census(unittest.TestCase):
    def test_no_script_changes_sys_path_or_imports_a_sibling_by_name(self):
        scanned = 0
        problems = []
        for path in sorted(SCRIPTS.rglob("*.py")):
            rel = path.relative_to(SCRIPTS)
            if CENSUS_EXCLUDED_PARTS & set(rel.parts) or path.name.startswith("test_"):
                continue
            scanned += 1
            findings = census_findings(path)
            if not findings:
                continue
            if str(rel) in SITE_FILES:
                problems.append("%s still loads by name: %s" % (rel, findings))
            else:
                problems.append("%s is not on the hand-written SITES list: %s" % (rel, findings))
        self.assertGreaterEqual(scanned, MIN_FILES_SCANNED, "the census scanned %d files" % scanned)
        self.assertEqual(problems, [])

    def test_the_census_sees_each_form(self):
        with tempfile.TemporaryDirectory(prefix="census-9399-") as raw:
            folder = Path(os.path.realpath(raw))
            (folder / "peer.py").write_text("X = 1\n", encoding="utf-8")
            probe = folder / "probe.py"
            expected = {
                "import sys\nsys.path.insert(0, '.')\n": "sys.path.insert",
                "import sys\nsys.path.append('.')\n": "sys.path.append",
                "import sys\nsys.path[0] = '.'\n": "sys.path assignment",
                "import sys\nsys.path += ['.']\n": "sys.path assignment",
                "import peer\n": "import peer",
                "from peer import X\n": "from peer import",
                "from . import peer\n": "relative import",
                "import importlib\nimportlib.import_module('peer')\n": "import_module(peer)",
                "__import__('peer')\n": "__import__(peer)",
            }
            real_scripts = globals()["SCRIPTS"]
            globals()["SCRIPTS"] = folder
            try:
                for source, label in expected.items():
                    probe.write_text(source, encoding="utf-8")
                    with self.subTest(form=label):
                        self.assertEqual([what for _, what in census_findings(probe)], [label])
                probe.write_text("import json\nimport os\n", encoding="utf-8")
                self.assertEqual(census_findings(probe), [])
            finally:
                globals()["SCRIPTS"] = real_scripts


if __name__ == "__main__":
    unittest.main()
