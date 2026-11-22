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
import fnmatch
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

REPO = Path(__file__).resolve().parents[3]
SCRIPTS = REPO / "scripts"
CANON_FILE = SCRIPTS / "ci" / "sibling_load.py"
BLOCK_BEGIN = "# >>> sibling-load 9399"
BLOCK_END = "# <<< sibling-load 9399"
PYTHON = sys.executable
SUBPROCESS_TIMEOUT_S = 120
FD_FOLDER = "/dev/fd"  # the open descriptors of this process, on Linux and macOS alike
FIFO_TIMEOUT_S = 20  #a FIFO open that blocks (O_NONBLOCK dropped) fails the row at this ceiling instead of hanging
DEGENERATE_TIMEOUT_S = 20  # wall-clock ceiling of one site run against one degenerate or broken sibling
# The reason words of the refusal line, written out by hand (never read from the loader under test).
REASON_ABSENT = "absent"
REASON_UNREADABLE = "unreadable"
REASON_NOT_REGULAR = "not a regular file"
REASON_LEAVES = "symlink leaves the script folder"
REASON_EMPTY = "empty"
REASON_TAKEN = "module name taken"
EXIT_REFUSED_DEFAULT = 3
EXIT_REFUSED_DOCS_GATE = 5  # docs_only_gate.py spends 0, 2, 3 (docs only: skips work) and 4 itself
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
    # A refused load must never end with EXIT_DOCS_ONLY (3), the one exit code that lets a job skip its work (#9683).
    ("ci/impact/docs_only_gate.py", "docs_only_gate", EXIT_REFUSED_DOCS_GATE,
     (("common.py", "impact.common"), ("cargo_skip.py", "impact.cargo_skip")), ("-I",)),
    ("ci/impact/gate.py", "gate", 3, (("common.py", "impact.common"),), ("-I",)),
    ("ci/impact/read_set.py", "read_set", 3, (("common.py", "impact.common"),), ("-I",)),
    ("ci/impact/select.py", "select", 3, (("common.py", "impact.common"),), ("-I",)),
    ("ci/pg_isolate_split.py", "pg_isolate_split", EXIT_REFUSED_DEFAULT,
     (("workflow_annotation.py", "workflow_annotation"),
      ("partition_test_binaries.py", "partition_test_binaries")), ()),
    ("ci/prune_runner_artifacts.py", "prune_runner_artifacts", EXIT_REFUSED_DEFAULT,
     (("workflow_annotation.py", "workflow_annotation"), ("shared_cargo_target.py", "shared_cargo_target")), ()),
    ("ci/sccache_env.py", "sccache_env", EXIT_REFUSED_SCCACHE,
     (("workflow_annotation.py", "workflow_annotation"), ("shared_cargo_target.py", "shared_cargo_target")), ()),
    ("bench/mesh_probe.py", "mesh_probe", 3,
     (("benchlib.py", "benchlib"), ("ops_producer.py", "ops_producer")), ()),
    ("bench/ops_producer.py", "ops_producer", 3, (("benchlib.py", "benchlib"),), ()),
    ("bench/wake_latency.py", "wake_latency", 3, (("benchlib.py", "benchlib"),), ()),
    ("bench/host-facts.py", "host-facts", 3, (("benchlib.py", "benchlib"),), ()),
    ("evidence/continuity-cycle.py", "continuity-cycle", 3, (("predicates.py", "predicates"),), ()),
)
SITE_FILES = frozenset(row[0] for row in SITES)
MIN_FILES_SCANNED = 150  # the whole tree holds about 200 Python files; fewer means the walk lost a folder
MIN_REASON_CHARS = 20
SHEBANG_READ_BYTES = 256
SHEBANG_FIXTURE = "test/fixtures/pr_retarget_check_8332/stub_bin/gh"  # a python shebang file with no .py suffix
CENSUS_SYS_SEARCH_ATTRS = frozenset({"path", "meta_path", "path_hooks", "path_importer_cache"})
CENSUS_DYNAMIC_IMPORTS = frozenset({"import_module", "__import__", "find_spec", "find_loader"})
CENSUS_BY_PATH_LOADERS = frozenset({"spec_from_file_location", "spec_from_loader", "SourceFileLoader",
                                    "SourcelessFileLoader", "ExtensionFileLoader", "FileFinder", "run_path",
                                    "run_module", "load_source", "load_module"})
CENSUS_EXEC_CALLS = frozenset({"exec", "eval", "execfile"})


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


# One hand-written row per degenerate or broken sibling object: (kind, the reason the refusal line prints). Every row
# runs at every (site, sibling) of SITES. A device node cannot be made in a checkout without root (mknod), so the site
# row reaches a device through a symlink (/dev/null, outside the folder); LoaderAlone opens a real device in place.
DEGENERATE_ROWS = (
    ("fifo", REASON_NOT_REGULAR),
    ("device", REASON_LEAVES),
    ("directory", REASON_NOT_REGULAR),
    ("out-of-tree symlink", REASON_LEAVES),
    ("empty", REASON_EMPTY),
    ("unreadable", REASON_UNREADABLE),
)
# A sibling that is a regular file but broken: the site's except clause must catch every kind (L1, #9399).
BROKEN_ROWS = (
    ("syntax error", "def broken(:\n", "SyntaxError"),
    ("exit 0", "raise SystemExit(0)\n", "SystemExit"),
    ("exit 3", "raise SystemExit(3)\n", "SystemExit"),
    ("raises", "raise RuntimeError('broken')\n", "RuntimeError"),
)
EVIL_SOURCE = "open(%r, 'w').close()\n"


class SiteRefusesEachObject(Scratch):
    """Every (site, sibling) of SITES, the sibling replaced by each degenerate or broken object in a copy of the
    script folder: the run ends within DEGENERATE_TIMEOUT_S with ONE exact stderr line, empty stdout and the site's own
    exit code, and nothing outside the folder runs."""

    def folder_copy(self, script_rel):
        folder_rel = Path(script_rel).parent
        copy_dir = self.root / ("copy-" + "-".join(folder_rel.parts)) / "scripts" / folder_rel
        if not copy_dir.exists():
            shutil.copytree(SCRIPTS / folder_rel, copy_dir, ignore=shutil.ignore_patterns("tests", "__pycache__"))
        return copy_dir

    def place(self, kind, target, body):
        target.unlink()
        if kind == "fifo":
            os.mkfifo(target)
        elif kind == "device":
            os.symlink(os.devnull, target)
        elif kind == "directory":
            target.mkdir()
        elif kind == "out-of-tree symlink":
            outside = self.root / ("outside-" + target.name)
            outside.write_text(body, encoding="utf-8")
            os.symlink(outside, target)
        elif kind == "empty":
            target.write_bytes(b"")
        elif kind == "unreadable":
            target.write_text("VALUE = 1\n", encoding="utf-8")
            target.chmod(0)
        else:
            target.write_text(body, encoding="utf-8")

    def restore(self, target, original):
        if target.is_dir() and not target.is_symlink():
            target.rmdir()
        else:
            if not target.is_symlink() and target.exists():
                target.chmod(stat.S_IRUSR | stat.S_IWUSR)
            target.unlink()
        shutil.copy2(original, target)

    def check(self, row, sibling, kind, body, why):
        script_rel, prog, code, _siblings, flags = row
        copy_dir = self.folder_copy(script_rel)
        target = copy_dir / sibling
        marker = self.root / "evil-ran"
        marker.unlink(missing_ok=True)
        self.place(kind, target, body if body is not None else EVIL_SOURCE % str(marker))
        try:
            try:
                got = run([*flags, str(copy_dir / Path(script_rel).name), "--help"], self.root,
                          timeout=DEGENERATE_TIMEOUT_S)
            except subprocess.TimeoutExpired:
                self.fail("%s with a %s %s did not end within %d s" % (script_rel, kind, sibling, DEGENERATE_TIMEOUT_S))
            expected = "%s: refused: sibling module %s at %s cannot be loaded (%s)\n" % (
                prog, sibling, os.path.join(os.path.realpath(copy_dir), sibling), why)
            self.assertEqual(got.stderr, expected)
            self.assertEqual(got.returncode, code)
            self.assertEqual(got.stdout, "")
            self.assertFalse(marker.exists(), "the file outside the script folder ran")
        finally:
            self.restore(target, SCRIPTS / Path(script_rel).parent / sibling)

    def test_every_site_refuses_each_degenerate_sibling_within_the_ceiling(self):
        for row in SITES:
            for sibling, _ in row[3]:
                for kind, why in DEGENERATE_ROWS:
                    with self.subTest(script=row[0], sibling=sibling, kind=kind):
                        self.check(row, sibling, kind, None, why)

    def test_every_site_refuses_each_broken_sibling_with_its_own_exit_code(self):
        for row in SITES:
            for sibling, _ in row[3]:
                for kind, body, why in BROKEN_ROWS:
                    with self.subTest(script=row[0], sibling=sibling, kind=kind):
                        self.check(row, sibling, kind, body, why)


CHILD_LOAD_SOURCE = (
    "import sys\n"
    "block, script, filename = sys.argv[1:4]\n"
    "ns = {'__file__': script, '__name__': 'child_9399'}\n"
    "with open(block, encoding='utf-8') as handle:\n"
    "    exec(compile(handle.read(), block, 'exec'), ns)\n"
    "try:\n"
    "    ns['_load_sibling'](filename, 'child_sibling_9399')\n"
    "except ns['SiblingLoadError'] as exc:\n"
    "    print('refused: ' + exc.reason)\n"
    "else:\n"
    "    print('loaded')\n"
)


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

    def child_load(self, script, filename):
        """Run the canonical block in a fresh child (``__file__`` = ``script``) loading ``filename``, bounded by
        FIFO_TIMEOUT_S: an open that blocks fails the row instead of hanging the suite (L2)."""
        block_file = self.root / "block.py"
        block_file.write_text(block_of(canon_text()), encoding="utf-8")
        child = self.root / "child.py"
        child.write_text(CHILD_LOAD_SOURCE, encoding="utf-8")
        try:
            got = run([str(child), str(block_file), str(script), filename], self.root, timeout=FIFO_TIMEOUT_S)
        except subprocess.TimeoutExpired:
            self.fail("loading %s did not end within %d s" % (filename, FIFO_TIMEOUT_S))
        self.assertEqual(got.stderr, "")
        return got.stdout

    def test_a_fifo_is_refused_without_blocking(self):
        os.mkfifo(self.folder / "pipe.py")
        started = time.monotonic()
        self.assertEqual(self.child_load(self.script, "pipe.py"), "refused: " + REASON_NOT_REGULAR + "\n")
        self.assertLess(time.monotonic() - started, FIFO_TIMEOUT_S)

    def test_a_device_in_the_script_folder_is_not_a_regular_file(self):
        """A script whose folder is /dev (nothing is written there): the sibling ``null`` is a character device."""
        self.assertEqual(self.child_load(os.path.join(os.path.dirname(os.devnull), "tool_9399.py"),
                                         os.path.basename(os.devnull)), "refused: " + REASON_NOT_REGULAR + "\n")

    def test_an_empty_file_is_refused(self):
        self.write("blank.py", b"")
        self.refused("blank.py", "blank_9399", REASON_EMPTY)

    def test_a_read_error_on_the_checked_descriptor_is_unreadable(self):
        """An OSError from the read (an EIO on a failing disk) is the refusal "unreadable", never a traceback (M08)."""
        self.write("eio.py", "VALUE = 1\n")

        class FailingRead:
            def __init__(self, *_args, **_kwargs):
                pass

            def __enter__(self):
                return self

            def __exit__(self, *_exc):
                return False

            def read(self):
                raise OSError(5, "Input/output error")

        with mock.patch("os.fdopen", FailingRead):
            self.refused("eio.py", "eio_9399", REASON_UNREADABLE)

    def open_fds(self):
        return set(os.listdir(FD_FOLDER))

    def test_every_descriptor_is_closed_on_every_outcome(self):
        """The folder and file descriptors are closed whether the load succeeds or is refused after the open (M21)."""
        (self.folder / "sub").mkdir()
        (self.folder / "sub" / "deep.py").write_text("VALUE = 3\n", encoding="utf-8")
        (self.folder / "adir2.py").mkdir()
        self.write("eio2.py", "VALUE = 1\n")
        before = self.open_fds()
        self.assertEqual(self.load("sub/deep.py", "deep_9399").VALUE, 3)
        self.refused("adir2.py", "adir2_9399", REASON_NOT_REGULAR)
        with mock.patch("os.fdopen", side_effect=OSError(5, "Input/output error")):
            self.refused("eio2.py", "eio2_9399", REASON_UNREADABLE)
        self.assertEqual(self.open_fds(), before, "a descriptor stayed open")

    def test_no_descriptor_is_inheritable_while_open(self):
        """Every descriptor the loader opens is non-inheritable (PEP 446): a child started while the load runs holds
        none of them (M10). Each is checked just before the loader closes it."""
        (self.folder / "sub2").mkdir()
        (self.folder / "sub2" / "deep.py").write_text("VALUE = 4\n", encoding="utf-8")
        seen = []
        real_close = os.close

        def checking_close(fd):
            seen.append(os.get_inheritable(fd))
            real_close(fd)

        with mock.patch("os.close", checking_close):
            self.assertEqual(self.load("sub2/deep.py", "deep2_9399").VALUE, 4)
        self.assertEqual(seen, [False, False, False], "folder, sub2 and deep.py descriptors")

    def test_the_module_is_registered_before_its_code_runs(self):
        """The sibling finds itself in sys.modules while it runs (a dataclass, pickle and typing need that) (M14)."""
        self.write("selfref.py", "import sys\nSELF = sys.modules[__name__]\n")
        module = self.load("selfref.py", "selfref_9399")
        self.assertIs(module.SELF, module)

    def test_a_folder_swapped_for_a_symlink_after_the_check_is_refused(self):
        """F2: the containment check resolves the path, the open walks the same folders by descriptor. A folder
        swapped for a symlink to outside between the check and the open is refused and the outside file never runs.
        The swap happens inside the first ``os.open`` call, so no timing is involved."""
        sub = self.folder / "sub"
        sub.mkdir()
        (sub / "mod.py").write_text("VALUE = 1\n", encoding="utf-8")
        outside = self.root / "outside"
        outside.mkdir()
        marker = self.root / "evil-ran"
        (outside / "mod.py").write_text(EVIL_SOURCE % str(marker), encoding="utf-8")
        real_open = os.open
        swapped = []

        def swap_then_open(path, flags, *args, **kwargs):
            if not swapped:
                swapped.append(path)
                os.rename(sub, self.root / "sub-moved")
                os.symlink(outside, sub)
            return real_open(path, flags, *args, **kwargs)

        with mock.patch.object(os, "open", swap_then_open):
            self.refused("sub/mod.py", "swapdir_9399", REASON_UNREADABLE)
        self.assertEqual(len(swapped), 1)
        self.assertFalse(marker.exists(), "the file outside the script folder ran")

    def test_the_script_folder_swapped_after_the_check_is_refused(self):
        """The script's own folder (the last component of the resolved folder) swapped for a symlink before the
        first open: the folder itself is opened without following a symlink."""
        moved = self.root / "scripts" / "ci-moved"
        outside = self.root / "outside"
        outside.mkdir()
        marker = self.root / "evil-ran"
        (outside / "mod.py").write_text(EVIL_SOURCE % str(marker), encoding="utf-8")
        self.write("mod.py", "VALUE = 1\n")
        real_open = os.open
        swapped = []

        def swap_then_open(path, flags, *args, **kwargs):
            if not swapped:
                swapped.append(path)
                os.rename(self.folder, moved)
                os.symlink(outside, self.folder)
            return real_open(path, flags, *args, **kwargs)

        with mock.patch.object(os, "open", swap_then_open):
            self.refused("mod.py", "swaphere_9399", REASON_UNREADABLE)
        self.assertFalse(marker.exists(), "the file outside the script folder ran")

    def test_an_ancestor_folder_swapped_for_a_symlink_after_the_resolve_is_refused(self):
        """#9888: a folder ABOVE the script folder swapped for a symlink to a tree that holds a real folder of the
        same name. ``O_NOFOLLOW`` covers only the last component, so the open of the script folder reaches the
        other folder; its device and inode differ from the ones recorded after the resolve, so it is refused."""
        scripts = self.root / "scripts"
        other = self.root / "other"
        (other / "ci").mkdir(parents=True)
        marker = self.root / "evil-ran"
        (other / "ci" / "mod.py").write_text(EVIL_SOURCE % str(marker), encoding="utf-8")
        self.write("mod.py", "VALUE = 1\n")
        real_open = os.open
        swapped = []

        def swap_then_open(path, flags, *args, **kwargs):
            if not swapped:
                swapped.append(path)
                os.rename(scripts, self.root / "scripts-moved")
                os.symlink(other, scripts)
            return real_open(path, flags, *args, **kwargs)

        with mock.patch.object(os, "open", swap_then_open):
            self.refused("mod.py", "swapancestor_9399", REASON_UNREADABLE)
        self.assertEqual(len(swapped), 1)
        self.assertFalse(marker.exists(), "the file in the other tree ran")

    def test_the_script_folder_renamed_and_replaced_by_a_real_folder_is_refused(self):
        """#9888: the script folder renamed away and a real folder (not a symlink) made at its path before the
        first open. ``O_NOFOLLOW`` passes a real folder, so only the recorded identity tells the two apart."""
        marker = self.root / "evil-ran"
        self.write("mod.py", "VALUE = 1\n")
        real_open = os.open
        swapped = []

        def swap_then_open(path, flags, *args, **kwargs):
            if not swapped:
                swapped.append(path)
                os.rename(self.folder, self.root / "scripts" / "ci-moved")
                self.folder.mkdir()
                (self.folder / "mod.py").write_text(EVIL_SOURCE % str(marker), encoding="utf-8")
            return real_open(path, flags, *args, **kwargs)

        with mock.patch.object(os, "open", swap_then_open):
            self.refused("mod.py", "swaprename_9399", REASON_UNREADABLE)
        self.assertEqual(len(swapped), 1)
        self.assertFalse(marker.exists(), "the file in the replacement folder ran")

    def test_a_script_folder_that_cannot_be_examined_is_unreadable(self):
        """#9888: the identity record of the script folder fails (the folder vanished or is not searchable): the
        load is refused as unreadable, never a traceback and never a load without the record."""
        self.write("mod.py", "VALUE = 1\n")
        here = os.path.realpath(self.folder)
        real_stat = os.stat

        real_open = os.open
        opened = []

        def failing_stat(path, *args, **kwargs):
            if os.fspath(path) == here:
                raise PermissionError(13, "Permission denied", path)
            return real_stat(path, *args, **kwargs)

        def recording_open(path, flags, *args, **kwargs):
            opened.append(path)
            return real_open(path, flags, *args, **kwargs)

        with mock.patch.object(os, "stat", failing_stat), mock.patch.object(os, "open", recording_open):
            self.refused("mod.py", "statfail_9399", REASON_UNREADABLE)
        self.assertEqual(opened, [], "the loader opened a path without the identity record of the script folder")

    def test_a_script_folder_on_another_device_with_the_same_inode_is_refused(self):
        """#9888: the identity is the pair (device, inode); a folder opened with the recorded inode number on another
        device is another folder, refused as unreadable."""
        marker = self.root / "evil-ran"
        self.write("mod.py", EVIL_SOURCE % str(marker))
        real_fstat = os.fstat
        first = []

        def other_device_fstat(fd, *args, **kwargs):
            result = real_fstat(fd, *args, **kwargs)
            if first or not stat.S_ISDIR(result.st_mode):
                return result
            first.append(fd)
            fields = list(result)
            fields[stat.ST_DEV] = result.st_dev + 1
            return os.stat_result(fields)

        with mock.patch.object(os, "fstat", other_device_fstat):
            self.refused("mod.py", "otherdev_9399", REASON_UNREADABLE)
        self.assertEqual(len(first), 1)
        self.assertFalse(marker.exists(), "the file in the folder of the other device ran")

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


class DocsGateRefusalNeverSkips(unittest.TestCase):
    def test_the_refusal_exit_is_not_the_docs_only_exit(self):
        """#9683: only exit 3 of docs_only_gate.py lets a heavy job skip, so a refused sibling load ends otherwise."""
        text = (SCRIPTS / "ci" / "impact" / "docs_only_gate.py").read_text(encoding="utf-8")
        docs_only = int(re.search(r"^EXIT_DOCS_ONLY = ([0-9]+)$", text, re.M).group(1))
        refused = int(re.search(r"^SIBLING_EXIT_LOAD_REFUSED = ([0-9]+)$", text, re.M).group(1))
        self.assertEqual(docs_only, 3)
        self.assertNotIn(refused, (0, docs_only))
        self.assertEqual(refused, EXIT_REFUSED_DOCS_GATE)


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


# The census is an ALLOWLIST over the whole scripts tree (#9399 r1, F3): every Python file under scripts/ is read, and
# every file with a finding is a hand-written row (its exact finding labels and the reason it may keep them). A new
# finding anywhere, a new form in a listed file, or a stale row is red. The paths the walk leaves out are the rules
# below, each with its reason.
CENSUS_SKIPPED_RULES = {
    "__pycache__": "bytecode caches a test run writes; untracked, and the census reads source, not bytecode",
    "symlink": "a link is never followed out of the tree by the census; none is tracked under scripts/ (pinned 0)",
    "folder": "the walk descends into every folder; a folder itself holds no source",
    "special file": "a FIFO, socket or device could block the read; none sits under scripts/ (pinned 0)",
    "not Python": "neither a .py file nor a file whose first line is a python shebang (shell, JSON, text, fixtures)",
}
CENSUS_RULES_THAT_MUST_BE_EMPTY = ("symlink", "special file")
REASON_LEFT_TO_9857 = (
    "left to #9857: loads a sibling by path through an older loader (the #9365 workflow_annotation loader, the "
    "ensure_age_extension loader or its own spec_from_file_location) with no descriptor check; #9857 moves it to the "
    "one checked loader")
REASON_OUTSIDE_FILE_9857 = (
    "loads a tracked file outside its own folder by path (wake_latency: sdk/python/ai_memory/wake.py; "
    "claude-md-rule-compare: scripts/check-claude-md-size.py of the base checkout and of the tree) with a path "
    "check only; the same unchecked open, left to #9857 (checklist comment "
    "https://github.com/alphaonedev/ai-memory-mcp/issues/9857#issuecomment-7074437416)")
REASON_POSIX_REEXEC = (
    "__import__ of 'posix' or 'nt' (a conditional of two constants), builtin modules of sys.builtin_module_names, to "
    "re-exec under -I before anything else loads; never a file")
REASON_TEST_MODULE = (
    "unittest module: loads the script under test or a shared test helper, by name or by path, from the PR tree it "
    "tests; run by the build-script-vetting job, never as a CI decision step")
REASON_TEST_HELPER = (
    "shared unittest helper of scripts/ci/tests: puts scripts/ci on sys.path for the tests that import it; never run "
    "as a CI decision step")
# The ONE written rule over test modules (#8213 N1): a file directly in scripts/ci/tests/ whose name matches the
# pattern is a unittest module, and its findings are allowed by this rule instead of one row each, so a new chain
# test cannot turn the census red. Everything else stays a row: a helper in that folder, a test module in another
# folder, a file in a folder below it.
CENSUS_TEST_MODULE_FOLDER = "ci/tests"
CENSUS_TEST_MODULE_NAME = "test_*.py"
CENSUS_TEST_MODULE_RULE = (CENSUS_TEST_MODULE_FOLDER + "/" + CENSUS_TEST_MODULE_NAME, REASON_TEST_MODULE)
# One row per construct form, written out by hand: (source of a probe file beside peer.py and select.py, its exact
# finding labels in walk order). Each is one way to load a module other than through the one checked loader.
CENSUS_FORMS = (
    ("import sys\nsys.path.insert(0, '.')\n", ["sys.path.insert"]),
    ("import sys\nsys.path.append('.')\n", ["sys.path.append"]),
    ("import sys\nsys.path[0] = '.'\n", ["sys.path assignment"]),
    ("import sys\nsys.path += ['.']\n", ["sys.path assignment"]),
    ("import sys\nsys.path = ['.']\n", ["sys.path assignment"]),
    ("import sys\ndel sys.path[0]\n", ["sys.path deletion"]),
    ("import sys as _s\n_s.path.insert(0, '.')\n", ["sys.path.insert"]),
    ("from sys import path\npath.insert(0, '.')\n", ["from sys import path"]),
    ("from sys import path as search\n", ["from sys import path"]),
    ("from sys import *\n", ["from sys import *"]),
    ("import sys\nsys.meta_path.append(None)\n", ["sys.meta_path.append"]),
    ("import sys\nsetattr(sys, 'path', [])\n", ["setattr(sys.path)"]),
    ("import sys\nsetattr(sys, name, [])\n", ["setattr(sys, non-constant)"]),
    ("import peer\n", ["import peer"]),
    ("import peer as other\n", ["import peer"]),
    ("from peer import X\n", ["from peer import"]),
    ("import select\n", ["import select"]),
    ("from . import peer\n", ["relative import"]),
    ("import importlib\nimportlib.import_module('peer')\n", ["import_module(peer)"]),
    ("import importlib\nimportlib.import_module(name)\n", ["import_module(non-constant)"]),
    ("import importlib\nimportlib.import_module('pe' + 'er')\n", ["import_module(non-constant)"]),
    ("__import__('peer')\n", ["__import__(peer)"]),
    ("__import__(name)\n", ["__import__(non-constant)"]),
    ("from importlib import import_module as load\nload('peer')\n", ["import_module(peer)"]),
    ("import importlib.util\nimportlib.util.find_spec('peer')\n", ["find_spec(peer)"]),
    ("import importlib.util\nimportlib.util.spec_from_file_location('p', 'peer.py')\n", ["spec_from_file_location"]),
    ("from importlib.util import spec_from_file_location as at\nat('p', 'peer.py')\n", ["spec_from_file_location"]),
    ("from importlib.machinery import SourceFileLoader\nSourceFileLoader('p', 'peer.py').load_module()\n",
     ["load_module", "SourceFileLoader"]),
    ("import runpy\nrunpy.run_path('peer.py')\n", ["run_path"]),
    ("import runpy\nrunpy.run_module('peer')\n", ["run_module"]),
    ("exec(open('peer.py').read())\n", ["exec"]),
    ("import builtins\nbuiltins.exec('pass')\n", ["exec"]),
    ("eval('1')\n", ["eval"]),
    ("import importlib.util\ngetattr(importlib.util, 'spec_from_file_location')\n",
     ["getattr(spec_from_file_location)"]),
    ("import importlib\nload = getattr(importlib, 'import_module')\n", ["getattr(import_module)"]),
    ("def broken(:\n", ["unparsable (SyntaxError)"]),
    ("import json\nimport os\nimport sys\nprint(sys.path)\n", []),
)
CENSUS_ALLOWLIST = {
    'bench/wake_latency.py': (('spec_from_file_location',), REASON_OUTSIDE_FILE_9857),
    'ci-sweep-target.py': (('spec_from_file_location',), REASON_LEFT_TO_9857),
    'ci/ci_full_nightly.py': (('spec_from_file_location',), REASON_LEFT_TO_9857),
    'ci/host_semaphore.py': (('spec_from_file_location',), REASON_LEFT_TO_9857),
    'ci/impact/base_sha.py': (('spec_from_file_location',), REASON_LEFT_TO_9857),
    'ci/load_gate.py': (('spec_from_file_location',), REASON_LEFT_TO_9857),
    'ci/partition_test_binaries.py': (('spec_from_file_location',), REASON_LEFT_TO_9857),
    'ci/pg_env_preflight.py': (('spec_from_file_location',), REASON_LEFT_TO_9857),
    'ci/prune_runner_tmp.py': (('exec',), REASON_LEFT_TO_9857),
    'ci/shared_cargo_target.py': (('spec_from_file_location',), REASON_LEFT_TO_9857),
    'ci/suite_budget.py': (('spec_from_file_location',), REASON_LEFT_TO_9857),
    'ci/tests/impact_fixture.py': (('from impact import', 'sys.path.insert'), REASON_TEST_HELPER),
    'ci/tests/tmp_runtime_guard_7393.py': (('sys.path.insert',), REASON_TEST_HELPER),
    'ci/tier_cred_preflight.py': (('spec_from_file_location',), REASON_LEFT_TO_9857),
    'claude-md-rule-compare.py': (('exec', 'spec_from_file_location'), REASON_OUTSIDE_FILE_9857),
    'evidence/build_bundle.py': (('__import__(non-constant)', 'spec_from_file_location'), REASON_LEFT_TO_9857),
    'evidence/prep.py': (('__import__(non-constant)', 'spec_from_file_location'), REASON_LEFT_TO_9857),
    'evidence/run_cert.py': (('__import__(non-constant)',), REASON_POSIX_REEXEC),
    'test/pg_isolated_binary.py': (('spec_from_file_location',), REASON_LEFT_TO_9857),
    'test/test_cert_gate_evidence_7181.py': (('spec_from_file_location',), REASON_TEST_MODULE),
    'test/test_ci_sweep_target.py': (('spec_from_file_location',), REASON_TEST_MODULE),
    'test/test_ensure_age_extension_6161.py': (('load_module', 'spec_from_file_location'), REASON_TEST_MODULE),
    'test/test_pr_retarget_check_8332.py': (('spec_from_file_location',), REASON_TEST_MODULE),
}


def is_python_source(path):
    """True for a ``.py`` file and for a file whose first line is a python shebang (``stub_bin/gh`` and the like)."""
    if path.suffix == ".py":
        return True
    try:
        with open(path, "rb") as handle:
            first = handle.readline(SHEBANG_READ_BYTES)
    except OSError:
        return False
    return first.startswith(b"#!") and b"python" in first


def census_files():
    """Every Python source under scripts/ (the whole tree: tests/, test/ and fixtures included), with the paths the
    walk leaves out by a written rule (CENSUS_SKIPPED_RULES) counted per rule."""
    files, skipped = [], {rule: 0 for rule in CENSUS_SKIPPED_RULES}
    for path in sorted(SCRIPTS.rglob("*")):
        rel = path.relative_to(SCRIPTS)
        if "__pycache__" in rel.parts:
            skipped["__pycache__"] += 1
        elif path.is_symlink():
            skipped["symlink"] += 1
        elif path.is_dir():
            skipped["folder"] += 1
        elif not path.is_file():
            skipped["special file"] += 1
        elif not is_python_source(path):
            skipped["not Python"] += 1
        else:
            files.append(path)
    return files, skipped


def scripts_tree_names(path):
    """Names a file in the scripts tree can import from its own folder or an ancestor folder up to scripts/.

    A stdlib name is kept: ``import select`` in scripts/ci/impact/ loads impact/select.py whenever the script folder
    is sys.path[0] (every start without -I), so a same-named file makes the name a sibling name."""
    names = set()
    folder = path.parent
    while True:
        names |= {p.stem for p in folder.glob("*.py")} | {p.name for p in folder.iterdir() if p.is_dir()}
        if folder == SCRIPTS:
            break
        folder = folder.parent
    return names


def census_findings(path):
    """The finding labels of one file (one per occurrence, in walk order): every change of the import search path,
    every import of a same-tree name, every relative import, every dynamic import that is by name or not a constant,
    and every by-path load (CENSUS_BY_PATH_LOADERS, exec, eval). Unreadable or unparsable source is a finding."""
    try:
        text = path.read_text(encoding="utf-8")
        block = block_of(text)
        if block is not None:
            # The loader block restores sys.path and execs the checked bytes by design; its text is pinned byte for
            # byte to the canonical file by CopiesMatchTheLoader, so blank it (keeping the line numbers).
            text = text.replace(block, "\n" * block.count("\n"))
        tree = ast.parse(text, filename=str(path))
    except (OSError, UnicodeDecodeError, SyntaxError, ValueError) as exc:
        return ["unparsable (%s)" % type(exc).__name__]
    tree_names = scripts_tree_names(path)
    sys_names = {"sys"}  # every name bound to the sys module in this file
    aliases = {}  # a local name bound by ``from <module> import <loader>`` -> the loader's own name
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name == "sys":
                    sys_names.add(alias.asname or "sys")
        elif isinstance(node, ast.ImportFrom) and node.level == 0:
            for alias in node.names:
                if alias.name in CENSUS_DYNAMIC_IMPORTS | CENSUS_BY_PATH_LOADERS:
                    aliases[alias.asname or alias.name] = alias.name
    found = []

    def is_sys_attr(node):
        return (isinstance(node, ast.Attribute) and node.attr in CENSUS_SYS_SEARCH_ATTRS
                and isinstance(node.value, ast.Name) and node.value.id in sys_names)

    def callee_name(func):
        name = func.attr if isinstance(func, ast.Attribute) else getattr(func, "id", "")
        return aliases.get(name, name) if isinstance(func, ast.Name) else name

    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and is_sys_attr(node.func.value):
            found.append("sys.%s.%s" % (node.func.value.attr, node.func.attr))
        elif isinstance(node, (ast.Assign, ast.AugAssign, ast.AnnAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            for target in targets:
                inner = target.value if isinstance(target, ast.Subscript) else target
                if is_sys_attr(inner):
                    found.append("sys.%s assignment" % inner.attr)
        elif isinstance(node, ast.Delete):
            for target in node.targets:
                inner = target.value if isinstance(target, ast.Subscript) else target
                if is_sys_attr(inner):
                    found.append("sys.%s deletion" % inner.attr)
        elif isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.split(".")[0] in tree_names:
                    found.append("import " + alias.name)
        elif isinstance(node, ast.ImportFrom):
            if node.level > 0:
                found.append("relative import")
            elif node.module == "sys":
                found.extend("from sys import " + a.name for a in node.names
                             if a.name in CENSUS_SYS_SEARCH_ATTRS or a.name == "*")
            elif node.module and node.module.split(".")[0] in tree_names:
                found.append("from " + node.module + " import")
        if isinstance(node, ast.Call):
            name = callee_name(node.func)
            if name in CENSUS_DYNAMIC_IMPORTS:
                arg = node.args[0] if node.args else None
                if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                    if arg.value.split(".")[0] in tree_names:
                        found.append(name + "(" + arg.value + ")")
                else:
                    found.append(name + "(non-constant)")
            elif name in CENSUS_BY_PATH_LOADERS | CENSUS_EXEC_CALLS:
                found.append(name)
            elif name in ("getattr", "setattr", "delattr") and len(node.args) >= 2:
                target, attr = node.args[0], node.args[1]
                if not (isinstance(attr, ast.Constant) and isinstance(attr.value, str)):
                    if isinstance(target, ast.Name) and target.id in sys_names:
                        found.append(name + "(sys, non-constant)")
                elif attr.value in CENSUS_DYNAMIC_IMPORTS | CENSUS_BY_PATH_LOADERS:
                    found.append(name + "(" + attr.value + ")")
                elif attr.value in CENSUS_SYS_SEARCH_ATTRS and isinstance(target, ast.Name) \
                        and target.id in sys_names:
                    found.append(name + "(sys." + attr.value + ")")
    return found


def census_table():
    """{scripts-relative path: sorted finding labels} for every file of the whole tree with a finding."""
    files, skipped = census_files()
    table = {}
    for path in files:
        labels = census_findings(path)
        if labels:
            table[path.relative_to(SCRIPTS).as_posix()] = tuple(sorted(set(labels)))
    return table, len(files), skipped


def census_rule_covers(rel):
    """True only for a scripts-relative path directly in CENSUS_TEST_MODULE_FOLDER whose name matches
    CENSUS_TEST_MODULE_NAME (case-sensitive, whatever the file system does)."""
    folder, _sep, name = rel.rpartition("/")
    return folder == CENSUS_TEST_MODULE_FOLDER and fnmatch.fnmatchcase(name, CENSUS_TEST_MODULE_NAME)


def census_verdict(table):
    """(unexpected, stale) of a census table against the written allowlist: every file outside the test-module rule
    whose findings are not exactly its row, and every row that names a file without findings."""
    expected = {rel: tuple(sorted(labels)) for rel, (labels, _reason) in CENSUS_ALLOWLIST.items()}
    unexpected = {rel: labels for rel, labels in table.items()
                  if not census_rule_covers(rel) and expected.get(rel) != labels}
    stale = sorted(rel for rel in expected if rel not in table)
    return unexpected, stale


# One probe per tree position (#8213 N1): a path under the scripts root of a scratch tree, and whether a file there
# that changes sys.path must be a census finding. Written out by hand, not derived from the rule under test.
CENSUS_PROBE_SOURCE = "import sys\nsys.path.insert(0, '.')\n"
CENSUS_PROBE_ROWS = (
    ("ci/tests/test_new_chain_module_9999.py", False),  # a test module the allowlist has never seen
    ("ci/tests/test_x.py", False),
    ("ci/tool_9999.py", True),  # a non-test script outside the rule
    ("ci/test_tool_9999.py", True),  # a test-named file outside the rule's folder
    ("test/test_other_9999.py", True),  # a test module in another test folder: its own row
    ("ci/tests/helper_9999.py", True),  # a helper in the rule's folder that is not a test module
    ("ci/tests/tests_helper_9999.py", True),
    ("ci/tests/Test_upper_9999.py", True),
    ("ci/tests/test_no_suffix_9999", True),  # a python shebang file without .py: not a test module
    ("ci/tests/sub/test_nested_9999.py", True),  # a test-named file in a folder below the rule's folder
    ("ci/tests_more/test_near_9999.py", True),
    ("bench/ci/tests/test_elsewhere_9999.py", True),  # the rule's folder name under another folder
)


class Census(unittest.TestCase):
    def test_every_finding_in_the_whole_tree_is_a_written_allowlist_row(self):
        table, scanned, skipped = census_table()
        self.assertGreaterEqual(scanned, MIN_FILES_SCANNED, "the census scanned %d files" % scanned)
        self.assertEqual(set(skipped), set(CENSUS_SKIPPED_RULES))
        for rule in CENSUS_RULES_THAT_MUST_BE_EMPTY:
            self.assertEqual(skipped[rule], 0, "the census does not read a %s; none may sit under scripts/" % rule)
        unexpected, stale = census_verdict(table)
        self.assertEqual(unexpected, {}, "a file loads a module another way than through the one checked loader")
        self.assertEqual(stale, [], "an allowlist row names a file that no longer has those findings")

    def test_each_tree_position_is_a_finding_exactly_when_written(self):
        """A probe that changes sys.path at each position of a scratch scripts tree: a test module of
        scripts/ci/tests/ is not a finding (the one written rule), every other position is (#8213 N1)."""
        folder = Path(os.path.realpath(tempfile.mkdtemp(prefix="census-tree-9399-")))
        self.addCleanup(shutil.rmtree, folder)
        for rel, _finding in CENSUS_PROBE_ROWS:
            probe = folder / rel
            probe.parent.mkdir(parents=True, exist_ok=True)
            shebang = "" if probe.suffix == ".py" else "#!/usr/bin/env python3\n"
            probe.write_text(shebang + CENSUS_PROBE_SOURCE, encoding="utf-8")
        real_scripts = globals()["SCRIPTS"]
        globals()["SCRIPTS"] = folder
        try:
            table, scanned, _skipped = census_table()
        finally:
            globals()["SCRIPTS"] = real_scripts
        self.assertEqual(scanned, len(CENSUS_PROBE_ROWS))
        unexpected, _stale = census_verdict(table)
        for rel, finding in CENSUS_PROBE_ROWS:
            with self.subTest(rel=rel):
                self.assertEqual(rel in unexpected, finding)

    def test_every_allowlist_row_and_skip_rule_has_a_reason(self):
        self.assertGreaterEqual(len(CENSUS_TEST_MODULE_RULE[1].strip()), MIN_REASON_CHARS)
        for rel, (labels, reason) in CENSUS_ALLOWLIST.items():
            with self.subTest(rel=rel):
                self.assertFalse(census_rule_covers(rel), rel + " is covered by the test-module rule; a row is dead")
                self.assertTrue(labels, rel + " has no labels")
                self.assertGreaterEqual(len(reason.strip()), MIN_REASON_CHARS, rel + " has no written reason")
                if rel in SITE_FILES:
                    # A SITES script loads every sibling through the one loader; the only other load it may keep is
                    # of a tracked file in another tree (wake_latency's SDK client), never of a sibling.
                    self.assertEqual((labels, reason), (("spec_from_file_location",), REASON_OUTSIDE_FILE_9857))
        for rule, reason in CENSUS_SKIPPED_RULES.items():
            with self.subTest(rule=rule):
                self.assertGreaterEqual(len(reason.strip()), MIN_REASON_CHARS)

    def test_the_walk_reads_a_python_shebang_file_without_a_suffix(self):
        files, _skipped = census_files()
        self.assertIn(SHEBANG_FIXTURE, {p.relative_to(SCRIPTS).as_posix() for p in files})

    def test_the_census_sees_each_form(self):
        folder = Path(os.path.realpath(tempfile.mkdtemp(prefix="census-9399-")))
        self.addCleanup(shutil.rmtree, folder)
        (folder / "peer.py").write_text("X = 1\n", encoding="utf-8")
        (folder / "select.py").write_text("X = 1\n", encoding="utf-8")
        probe = folder / "probe.py"
        real_scripts = globals()["SCRIPTS"]
        globals()["SCRIPTS"] = folder
        try:
            for source, labels in CENSUS_FORMS:
                probe.write_text(source, encoding="utf-8")
                with self.subTest(form=source):
                    self.assertEqual(census_findings(probe), labels)
            shebang = folder / "tool"
            shebang.write_text("#!/usr/bin/env python3\nimport peer\n", encoding="utf-8")
            self.assertTrue(is_python_source(shebang))
            (folder / "notes").write_text("#!/bin/sh\nimport peer\n", encoding="utf-8")
            self.assertFalse(is_python_source(folder / "notes"))
        finally:
            globals()["SCRIPTS"] = real_scripts


if __name__ == "__main__":
    unittest.main()
