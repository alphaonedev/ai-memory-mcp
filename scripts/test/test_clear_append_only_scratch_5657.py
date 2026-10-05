#!/usr/bin/env python3
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""#5657 - a leftover append-only audit.log must not poison the next CI job.

Run: python3 scripts/test/test_clear_append_only_scratch_5657.py

The janitor's contract has two halves that pull against each other, and this
file pins BOTH at once (#5747 round 2):

* a permission problem on an UNFLAGGED leftover must not red a leg that
  `actions/checkout` would have cleaned by itself - the janitor chmods its way
  in and puts the mode back; and
* a flag that is still set when the janitor finishes must be reported and must
  exit non-zero - "0 cleared, 0 failed" while a flag survives is the worst
  possible outcome, because it hands a poisoned runner to the next job with a
  green tick.

The script runs as the UNPRIVILEGED runner user in CI, so these tests run it
unprivileged too. Only the FIXTURES escalate: `chflags uappnd` (macOS/BSD, owner
may set and clear) needs nothing, `chattr +a` (Linux) needs CAP_LINUX_IMMUTABLE
and therefore `sudo -n`. When a mechanism is unavailable the test that needs it
SKIPS with a message; the workflow pin tests always run.

The workflow pins parse the YAML and evaluate the step `if:` expressions with a
small GitHub-expression evaluator, so a guard that is rewritten to skip the step
is caught by meaning rather than by string match. `PyYAML` is required for those
(it ships on the GitHub `ubuntu-latest` image and on both fleet nodes); its
absence FAILS those tests rather than skipping them.
"""
import ast
import contextlib
import errno
import importlib.util
import io
import itertools
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "clear-append-only-scratch.py"
WF_DIR = ROOT / ".github" / "workflows"
WORKFLOWS = [WF_DIR / "ci.yml", WF_DIR / "session-boot-lifetime.yml"]
CLEAR_STEP = "Clear stale append-only scratch (#5657)"
SELFTEST_REL = "scripts/test/test_clear_append_only_scratch_5657.py"
CHECKOUT_PREFIX = "actions/checkout@"
CLASSIFY_JOB = "classify"
IS_BSD = hasattr(os, "lchflags")


# --------------------------------------------------------------------------
# fixtures
# --------------------------------------------------------------------------
def _priv():
    return [] if os.geteuid() == 0 else ["sudo", "-n"]


def _sudo_available():
    if os.geteuid() == 0:
        return True
    return subprocess.run(["sudo", "-n", "true"], capture_output=True).returncode == 0


def set_flag(path, immutable=False):
    """Set append-only (or immutable) on path; SkipTest when impossible."""
    if IS_BSD:
        bit = stat.UF_IMMUTABLE if immutable else stat.UF_APPEND
        os.lchflags(str(path), os.lstat(str(path)).st_flags | bit)
        return
    r = subprocess.run(_priv() + ["chattr", "+i" if immutable else "+a", str(path)],
                       capture_output=True, text=True)
    if r.returncode != 0:
        raise unittest.SkipTest("cannot set an inode flag on this host: %s" % r.stderr.strip())


def drop_flags(path):
    """Test-teardown only: always clear the flags so the scratch dir can go."""
    if IS_BSD:
        os.lchflags(str(path), 0)
    else:
        subprocess.run(_priv() + ["chattr", "-a", "-i", str(path)], capture_output=True)


def is_flagged(path):
    """True when an append-only / immutable flag is still set on path."""
    if IS_BSD:
        return bool(os.lstat(str(path)).st_flags & (stat.UF_APPEND | stat.UF_IMMUTABLE))
    r = subprocess.run(_priv() + ["lsattr", "-d", str(path)], capture_output=True, text=True)
    if r.returncode != 0 or not r.stdout.strip():
        raise unittest.SkipTest("cannot read inode flags on this host: %s" % r.stderr.strip())
    return any(c in r.stdout.split()[0] for c in "ai")


def load_script_module():
    """Import the janitor as a module so a single platform seam can be made to
    fail. A subprocess cannot be given an unreadable flag state on demand."""
    spec = importlib.util.spec_from_file_location("clear_append_only_scratch_5657", SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def run_clear(root, privileged=False):
    """Run the janitor. Unprivileged by default: that is how CI runs it."""
    cmd = ([] if (IS_BSD or not privileged) else _priv()) + [sys.executable, str(SCRIPT), "--root", str(root)]
    return subprocess.run(cmd, capture_output=True, text=True)


class ScratchTreeCase(unittest.TestCase):
    """Every case gets `<repo>/.local-runs/.ws5657-*/` as a fake workspace whose
    own `.local-runs/.tmpAbC123/audit/audit.log` is the poisoned leftover."""

    def setUp(self):
        base = ROOT / ".local-runs"
        base.mkdir(exist_ok=True)
        self.ws = Path(tempfile.mkdtemp(prefix=".ws5657-", dir=base))
        self.scratch = self.ws / ".local-runs"
        self.audit = self.scratch / ".tmpAbC123" / "audit"
        self.audit.mkdir(parents=True)
        self.log = self.audit / "audit.log"
        self.log.write_text("{}\n")
        self.addCleanup(self._teardown)

    def _teardown(self):
        # `a+rwX`, not `u+rwX`: a root-owned fixture is not ours to widen for
        # the OWNER, and the flags must come off before anything can be removed.
        subprocess.run(_priv() + ["chmod", "-R", "a+rwX", str(self.ws)], capture_output=True)
        try:
            for path in self.ws.rglob("*"):
                if not path.is_symlink():
                    drop_flags(path)
        except OSError:
            pass
        subprocess.run(_priv() + ["rm", "-rf", str(self.ws)], capture_output=True)
        shutil.rmtree(self.ws, ignore_errors=True)

    # -- the defect itself -------------------------------------------------
    def test_flagged_leftover_blocks_removal_then_clear_makes_it_removable_5657(self):
        set_flag(self.log)
        with self.assertRaises(PermissionError):  # the macOS leg's EPERM on unlink
            shutil.rmtree(self.scratch)
        self.assertTrue(self.log.exists(), "flagged file must survive a failed clean")
        r = run_clear(self.ws, privileged=True)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("cleared append-only", r.stdout)
        self.assertIn("1 cleared, 0 failed", r.stdout)
        shutil.rmtree(self.scratch)
        self.assertFalse(self.scratch.exists())

    def test_clear_is_idempotent_5657(self):
        set_flag(self.log)
        for _ in range(2):
            r = run_clear(self.ws, privileged=True)
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("0 cleared, 0 failed", run_clear(self.ws).stdout)

    def test_unflagged_and_missing_tree_are_noops_5657(self):
        r = run_clear(self.ws)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("0 cleared, 0 failed", r.stdout)
        shutil.rmtree(self.scratch)
        r = run_clear(self.ws)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("nothing to do", r.stdout)

    # -- CODE-F1: a permission problem is not a verdict --------------------
    def test_unflagged_unreadable_leftover_is_not_a_failure_5657(self):
        """mode-000 / mode-0200 / unreadable-dir leftovers carry NO flag, so
        `actions/checkout` would delete them unaided. The janitor must widen,
        look, put the mode back, and exit 0."""
        zero = self.audit / "unreadable.key"
        zero.write_text("k")
        os.chmod(zero, 0o000)
        wo = self.audit / "writeonly.log"
        wo.write_text("w")
        os.chmod(wo, 0o200)
        shut = self.scratch / ".tmpShut"
        shut.mkdir()
        (shut / "inner.log").write_text("{}\n")
        os.chmod(shut, 0o000)
        r = run_clear(self.ws)
        self.assertEqual(r.returncode, 0, "an unflagged leftover must not red the leg:\n" + r.stdout + r.stderr)
        self.assertIn("0 cleared, 0 failed", r.stdout)
        self.assertEqual(stat.S_IMODE(os.lstat(zero).st_mode), 0o000, "original mode must be restored")
        self.assertEqual(stat.S_IMODE(os.lstat(wo).st_mode), 0o200, "original mode must be restored")
        self.assertEqual(stat.S_IMODE(os.lstat(shut).st_mode), 0o000, "original mode must be restored")

    def test_unsearchable_directory_is_widened_not_reported_5657(self):
        """mode-0400 opens but cannot be stat'ed through: the janitor owns it,
        so it widens on the descriptor instead of calling it a failure."""
        d = self.scratch / ".tmpR"
        d.mkdir()
        (d / "inner.log").write_text("{}\n")
        os.chmod(d, 0o400)
        r = run_clear(self.ws)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("0 cleared, 0 failed", r.stdout)
        self.assertEqual(stat.S_IMODE(os.lstat(d).st_mode), 0o400, "original mode must be restored")

    # -- SEC-F1: a surviving flag is never reported as success -------------
    def test_flagged_file_under_unreadable_directory_is_not_silently_skipped_5657(self):
        """The round-1 script walked with `os.walk` and no `onerror`, so this
        tree printed `0 cleared, 0 failed`, exited 0, and left the flag set."""
        set_flag(self.log)
        os.chmod(self.audit, 0o000)
        r = run_clear(self.ws)
        os.chmod(self.audit, 0o700)
        still = is_flagged(self.log)
        self.assertFalse(r.returncode == 0 and still,
                         "reported success while the flag survived:\n" + r.stdout + r.stderr)
        self.assertFalse("0 cleared, 0 failed" in r.stdout and still,
                         "counted a surviving flag as nothing to do:\n" + r.stdout + r.stderr)
        if still:
            self.assertIn("::error::", r.stderr)
            self.assertIn(str(self.log), r.stderr)

    def test_immutable_leftover_fails_closed_5657(self):
        """`uchg` / `chattr +i` is not a flag ai-memory sets, so the janitor
        never removes it - but it DOES block unlink, so it must exit 1 and name
        the path. Run WITH privilege so the refusal is policy, not permission."""
        imm = self.audit / "locked.log"
        imm.write_text("{}\n")
        set_flag(imm, immutable=True)
        r = run_clear(self.ws, privileged=True)
        self.assertNotEqual(r.returncode, 0, "an immutable leftover must red the leg:\n" + r.stdout + r.stderr)
        self.assertIn("::error::", r.stderr)
        self.assertIn(str(imm), r.stderr)
        self.assertIn("0 cleared, 1 failed", r.stdout)
        self.assertIn("still un-unlinkable after the clear", r.stderr,
                      "the verdict must come from a POST-clear re-read of the descriptor")
        self.assertTrue(is_flagged(imm), "the janitor must not strip an immutable flag")

    def test_append_plus_immutable_reports_the_surviving_flag_5657(self):
        """The append bit comes off, the immutable bit does not: the post-clear
        re-read is what turns a half-success into an honest failure."""
        both = self.audit / "both.log"
        both.write_text("{}\n")
        set_flag(both)
        set_flag(both, immutable=True)
        r = run_clear(self.ws, privileged=True)
        self.assertNotEqual(r.returncode, 0, "a surviving immutable bit must red the leg:\n" + r.stdout + r.stderr)
        self.assertIn("::error::", r.stderr)
        self.assertIn(str(both), r.stderr)
        self.assertTrue(is_flagged(both))
        if IS_BSD:
            # Linux refuses FS_IOC_SETFLAGS outright on an immutable inode, so
            # there the failure is the EPERM; on BSD the append bit does come
            # off and only the POST-clear re-read notices the leftover.
            self.assertIn("still un-unlinkable after the clear", r.stderr)

    def test_hardlinked_flagged_file_is_refused_5657(self):
        """A second link outside the scratch tree means clearing the flag here
        also unprotects an inode the janitor was never pointed at."""
        outside = self.ws / "second-link.log"
        os.link(str(self.log), str(outside))
        set_flag(self.log)
        r = run_clear(self.ws, privileged=True)
        self.assertNotEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("links", r.stderr)
        self.assertIn(str(self.log), r.stderr)
        self.assertTrue(is_flagged(outside), "the out-of-tree link must stay protected")

    # -- SEC-F2 / SEC-F4: containment --------------------------------------
    def test_flag_outside_scratch_tree_is_never_touched_5657(self):
        live = self.ws / "audit.log"  # a LIVE log: not under .local-runs
        live.write_text("{}\n")
        set_flag(live)
        r = run_clear(self.ws, privileged=True)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertTrue(is_flagged(live), "the forensic control on a live log must be intact")

    def test_symlinked_scratch_root_is_refused_5657(self):
        """`.local-runs` itself a symlink = somebody redirected the scratch.
        The janitor refuses the tree outright instead of operating through it."""
        elsewhere = self.ws / "elsewhere"
        elsewhere.mkdir()
        victim = elsewhere / "audit.log"
        victim.write_text("{}\n")
        set_flag(victim)
        shutil.rmtree(self.scratch)
        self.scratch.symlink_to(elsewhere, target_is_directory=True)
        r = run_clear(self.ws, privileged=True)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("nothing to do", r.stdout)
        self.assertTrue(is_flagged(victim), "nothing beyond the symlink may be touched")

    def test_symlinked_subdirectory_is_not_descended_5657(self):
        elsewhere = self.ws / "elsewhere"
        elsewhere.mkdir()
        victim = elsewhere / "audit.log"
        victim.write_text("{}\n")
        set_flag(victim)
        (self.scratch / "link").symlink_to(elsewhere, target_is_directory=True)
        r = run_clear(self.ws, privileged=True)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("0 cleared, 0 failed", r.stdout)
        self.assertTrue(is_flagged(victim), "a symlinked subdirectory must not be descended")

    @unittest.skipUnless(IS_BSD, "only BSD/macOS can flag the symlink itself")
    def test_flagged_symlink_is_reported_not_cleared_5657(self):
        """A flagged symlink blocks unlink too, and a clear would have to go
        back through a path - so it is reported, never cleared."""
        link = self.scratch / "link.log"
        link.symlink_to(self.log)
        os.lchflags(str(link), os.lstat(str(link)).st_flags | stat.UF_APPEND)
        r = run_clear(self.ws)
        self.assertNotEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("never", r.stderr)
        self.assertIn(str(link), r.stderr)
        self.assertTrue(bool(os.lstat(str(link)).st_flags & stat.UF_APPEND))

    # -- ownership: "I could not tell" is a failure, not a pass ------------
    def test_an_unreadable_flag_state_is_a_failure_not_an_absence_5657(self):
        """A GET that fails for a reason OTHER than "this filesystem has no
        flags" must not be read as "no flag here": that is the #5747 SEC-F1
        silent skip, and it exits 0 with the flag still set."""
        mod = load_script_module()

        def unreadable(fd):
            # Directories read normally, so the walk reaches the leftover and
            # the verdict is about the LEAF, not an abort at the scratch root.
            if stat.S_ISDIR(os.fstat(fd).st_mode):
                return 0
            raise OSError(errno.EIO, "injected: the flag state cannot be read")

        mod._raw_flags = unreadable
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            rc = mod.main(["--root", str(self.ws)])
        self.assertNotEqual(rc, 0, "an unreadable flag state is not a pass:\n" + out.getvalue() + err.getvalue())
        self.assertIn("::error::", err.getvalue())
        self.assertIn(str(self.log), err.getvalue())
        self.assertNotIn("0 cleared, 0 failed", out.getvalue())

    def test_a_flagless_filesystem_is_still_a_noop_5657(self):
        """The other half of the same seam: the NAMED no-flag-support errnos
        stay tolerated, so this janitor does not red a tmpfs/overlay leg."""
        mod = load_script_module()
        tolerated = sorted(mod.NO_FLAG_SUPPORT)
        self.assertTrue(tolerated, "no errno is tolerated at all")

        def flagless(fd):
            raise OSError(tolerated[0], "injected: no inode-flag concept here")

        mod._raw_flags = flagless
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            rc = mod.main(["--root", str(self.ws)])
        self.assertEqual(rc, 0, out.getvalue() + err.getvalue())
        self.assertIn("0 cleared, 0 failed", out.getvalue())

    def test_foreign_owned_unreadable_directory_is_reported_5657(self):
        if not _sudo_available():
            raise unittest.SkipTest("no passwordless sudo to build a foreign-owned fixture")
        if os.geteuid() == 0:
            raise unittest.SkipTest("running as root: every inode is ownable")
        d = self.scratch / ".tmpForeign"
        subprocess.run(_priv() + ["mkdir", "-p", str(d)], check=True, capture_output=True)
        subprocess.run(_priv() + ["chmod", "000", str(d)], check=True, capture_output=True)
        r = run_clear(self.ws)
        self.assertNotEqual(r.returncode, 0, "an inode we cannot inspect is not a pass:\n" + r.stdout + r.stderr)
        self.assertIn("not the owner", r.stderr)
        self.assertIn(str(d), r.stderr)

    def test_foreign_owned_unsearchable_directory_is_reported_5657(self):
        if not _sudo_available():
            raise unittest.SkipTest("no passwordless sudo to build a foreign-owned fixture")
        if os.geteuid() == 0:
            raise unittest.SkipTest("running as root: every inode is ownable")
        d = self.scratch / ".tmpForeignRO"
        subprocess.run(_priv() + ["mkdir", "-p", str(d)], check=True, capture_output=True)
        subprocess.run(_priv() + ["touch", str(d / "inner.log")], check=True, capture_output=True)
        subprocess.run(_priv() + ["chmod", "444", str(d)], check=True, capture_output=True)
        r = run_clear(self.ws)
        self.assertNotEqual(r.returncode, 0, "an entry we cannot stat is not a pass:\n" + r.stdout + r.stderr)
        self.assertIn("cannot be ruled out", r.stderr)
        self.assertIn(str(d / "inner.log"), r.stderr)


# --------------------------------------------------------------------------
# structural pins: the containment primitives the behaviour tests cannot race
# --------------------------------------------------------------------------
_BANNED_CALLS = frozenset({
    "os.walk", "os.fwalk", "os.chflags", "os.lchflags", "os.stat", "os.readlink",
    "os.path.realpath", "os.path.abspath", "os.unlink", "os.remove", "os.rmdir",
    "shutil.rmtree",
})
_DIR_FD_FUNCS = frozenset({"os.open", "os.lstat", "os.chmod"})


def _named_def(tree, name):
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == name:
            return node
    raise AssertionError("%s defines no %s()" % (SCRIPT.name, name))


def _carries_open_flags(tree, call):
    """True when `call`'s flags argument is _OPEN_FLAGS, directly or through a
    local binding every assignment of which derives from _OPEN_FLAGS."""
    arg = ast.unparse(call.args[1])
    if "_OPEN_FLAGS" in arg:
        return True
    if not isinstance(call.args[1], ast.Name):
        return False
    local = call.args[1].id
    for func in ast.walk(tree):
        if not isinstance(func, ast.FunctionDef):
            continue
        if not any(node is call for node in ast.walk(func)):
            continue
        bindings = [
            ast.unparse(node.value)
            for node in ast.walk(func)
            if isinstance(node, ast.Assign)
            and any(isinstance(target, ast.Name) and target.id == local for target in node.targets)
        ]
        return bool(bindings) and all("_OPEN_FLAGS" in b for b in bindings)
    return False


def _module_assign(tree, name):
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(
            isinstance(t, ast.Name) and t.id == name for t in node.targets
        ):
            return ast.unparse(node.value)
    raise AssertionError("%s has no module-level %s" % (SCRIPT.name, name))


class StructuralPinCase(unittest.TestCase):
    """A dir-swap race is not reproducible on demand, so the primitives that
    make it unwinnable are pinned by shape instead of by behaviour."""

    def setUp(self):
        self.tree = ast.parse(SCRIPT.read_text())

    def test_script_never_follows_a_symlink_or_reresolves_a_path_5657(self):
        self.assertIn("O_NOFOLLOW", _module_assign(self.tree, "_OPEN_FLAGS"))
        opens = 0
        for node in ast.walk(self.tree):
            if not isinstance(node, ast.Call):
                continue
            name = ast.unparse(node.func)
            self.assertNotIn(name, _BANNED_CALLS,
                             "%s() re-resolves or follows a path; the walk descends by fd" % name)
            if name == "os.open":
                opens += 1
                self.assertGreaterEqual(len(node.args), 2, "os.open needs explicit flags")
                self.assertTrue(_carries_open_flags(self.tree, node),
                                "os.open(%s) may not carry O_NOFOLLOW" % ast.unparse(node.args[1]))
        self.assertGreater(opens, 0, "the walk must open something")
        # A symlink must be dispatched out of the walk before anything opens
        # it, and the dispatch must be the FIRST thing _visit does.
        first = _named_def(self.tree, "_visit").body[0]
        self.assertIsInstance(first, ast.If, "_visit must test for a symlink first")
        self.assertEqual(ast.unparse(first.test), "stat.S_ISLNK(st.st_mode)",
                         "_visit's first test is not the symlink test")
        body = [ast.unparse(n) for n in first.body]
        self.assertIn("self._symlink(path, st)", body, "a symlink is not reported")
        self.assertIsInstance(first.body[-1], ast.Return, "a symlink must not fall through the walk")
        for fname in ("_open_at", "_walk"):
            for node in ast.walk(_named_def(self.tree, fname)):
                if not isinstance(node, ast.Call):
                    continue
                name = ast.unparse(node.func)
                if name in _DIR_FD_FUNCS:
                    self.assertIn("dir_fd", [kw.arg for kw in node.keywords],
                                  "%s in %s() resolves a path instead of a (dirfd, name) pair" % (name, fname))

    def test_reopen_after_widening_is_checked_against_the_scanned_inode_5657(self):
        body = ast.unparse(_named_def(self.tree, "_open_at"))
        self.assertIn("os.fstat", body)
        self.assertIn("st_dev", body)
        self.assertIn("st_ino", body)

    def test_flags_are_reread_from_the_descriptor_after_the_clear_5657(self):
        body = ast.unparse(_named_def(self.tree, "_clear_fd"))
        self.assertGreaterEqual(body.count("get_flags("), 2,
                                "the clear must be PROVEN, not assumed")
        self.assertIn("st_nlink", body, "a multiply-linked inode must be refused")

    def test_the_janitor_only_ever_removes_the_append_bit_5657(self):
        clearable = _module_assign(self.tree, "CLEARABLE")
        blocking = _module_assign(self.tree, "BLOCKING")
        for immutable in ("UF_IMMUTABLE", "FS_IMMUTABLE_FL", "UF_NOUNLINK", "SF_IMMUTABLE"):
            self.assertNotIn(immutable, clearable, "CLEARABLE must not strip %s" % immutable)
        for blocker in ("UF_IMMUTABLE", "FS_IMMUTABLE_FL", "UF_APPEND", "FS_APPEND_FL"):
            self.assertIn(blocker, blocking, "BLOCKING must notice %s" % blocker)

    def test_platform_errnos_are_named_not_numbered_5657(self):
        """95 is ENOTSUP on Linux and EMULTIHOP on macOS (#5747 SEC-F5)."""
        src = SCRIPT.read_text()
        self.assertNotRegex(src, r"errno\s*(==|!=|in)\s*\(?\s*\d", "compare errno to a NAMED constant")
        tolerated = _module_assign(self.tree, "NO_FLAG_SUPPORT")
        for name in ("ENOTTY", "EOPNOTSUPP", "ENOTSUP"):
            self.assertIn(name, tolerated)
        self.assertNotRegex(tolerated, r"\b\d{2,}\b", "tolerate errnos by NAME, not by number")


# --------------------------------------------------------------------------
# GitHub Actions expression evaluator (the `if:` guards, by meaning)
# --------------------------------------------------------------------------
_TOKEN = re.compile(
    r"""\s*(?:(?P<op>&&|\|\||==|!=|!|\(|\)|,)
           |(?P<str>'(?:[^']|'')*')
           |(?P<num>-?\d+(?:\.\d+)?)
           |(?P<name>[A-Za-z_][A-Za-z0-9_-]*(?:\.[A-Za-z_*][A-Za-z0-9_-]*)*))""",
    re.X,
)


def _tokenize(text):
    out, pos = [], 0
    while pos < len(text):
        if text[pos].isspace():
            pos += 1
            continue
        m = _TOKEN.match(text, pos)
        if not m:
            raise AssertionError("cannot tokenize GitHub expression at %r" % text[pos:])
        kind = m.lastgroup
        out.append((kind, m.group(kind)))
        pos = m.end()
    return out


def gh_truthy(value):
    if isinstance(value, bool):
        return value
    if value is None:
        return False
    if isinstance(value, str):
        return value != ""
    if isinstance(value, (int, float)):
        return value != 0
    return True


def _gh_eq(left, right):
    if isinstance(left, bool) or isinstance(right, bool):
        return gh_truthy(left) == gh_truthy(right)
    if isinstance(left, str) or isinstance(right, str):
        return str(left).lower() == str(right).lower()
    return left == right


class GhExpr:
    """Evaluator for the GitHub-expression subset this repo's `if:` guards use.

    An identifier or function it does not know raises, so a guard that drifts
    into unparsed syntax FAILS the pin instead of quietly evaluating true."""

    def __init__(self, text, context):
        self.toks = _tokenize(text)
        self.pos = 0
        self.ctx = context
        self.text = text

    def evaluate(self):
        value = self._or()
        if self.pos != len(self.toks):
            raise AssertionError("trailing tokens in %r" % self.text)
        return value

    def _peek(self):
        return self.toks[self.pos] if self.pos < len(self.toks) else None

    def _accept(self, kind, text):
        if self._peek() == (kind, text):
            self.pos += 1
            return True
        return False

    def _expect(self, kind, text):
        if not self._accept(kind, text):
            raise AssertionError("expected %r in %r" % (text, self.text))

    def _or(self):
        value = self._and()
        while self._accept("op", "||"):
            right = self._and()
            value = value if gh_truthy(value) else right
        return value

    def _and(self):
        value = self._cmp()
        while self._accept("op", "&&"):
            right = self._cmp()
            value = right if gh_truthy(value) else value
        return value

    def _cmp(self):
        value = self._unary()
        tok = self._peek()
        if tok is not None and tok[0] == "op" and tok[1] in ("==", "!="):
            self.pos += 1
            right = self._unary()
            equal = _gh_eq(value, right)
            return equal if tok[1] == "==" else not equal
        return value

    def _unary(self):
        if self._accept("op", "!"):
            return not gh_truthy(self._unary())
        return self._primary()

    def _primary(self):
        tok = self._peek()
        if tok is None:
            raise AssertionError("expression ended early: %r" % self.text)
        if tok == ("op", "("):
            self.pos += 1
            value = self._or()
            self._expect("op", ")")
            return value
        kind, raw = tok
        self.pos += 1
        if kind == "str":
            return raw[1:-1].replace("''", "'")
        if kind == "num":
            return float(raw) if "." in raw else int(raw)
        if kind != "name":
            raise AssertionError("unexpected token %r in %r" % (raw, self.text))
        if self._accept("op", "("):
            args = []
            if not self._accept("op", ")"):
                args.append(self._or())
                while self._accept("op", ","):
                    args.append(self._or())
                self._expect("op", ")")
            return self._call(raw, args)
        return self._lookup(raw)

    def _call(self, name, args):
        if name == "contains" and len(args) == 2:
            haystack, needle = args
            if isinstance(haystack, (list, tuple)):
                return any(_gh_eq(item, needle) for item in haystack)
            return str(needle).lower() in str(haystack).lower()
        if name == "startsWith" and len(args) == 2:
            return str(args[0]).lower().startswith(str(args[1]).lower())
        if name == "endsWith" and len(args) == 2:
            return str(args[0]).lower().endswith(str(args[1]).lower())
        if name == "fromJSON" and len(args) == 1:
            return json.loads(args[0])
        if name == "always" and not args:
            return True
        raise AssertionError("unsupported GitHub function %s/%d in %r" % (name, len(args), self.text))

    def _lookup(self, name):
        low = name.lower()
        if low in ("true", "false"):
            return low == "true"
        if low == "null":
            return None
        if name in self.ctx:
            return self.ctx[name]
        raise AssertionError("unknown context value %r in %r" % (name, self.text))


# --------------------------------------------------------------------------
# workflow pins
# --------------------------------------------------------------------------
def _yaml():
    try:
        import yaml
    except ImportError as err:  # fail, never skip: these pins are the gate
        raise AssertionError(
            "PyYAML is required for the #5657 workflow pins (pip install pyyaml): %s" % err
        )
    return yaml


def load_workflow(path):
    return _yaml().safe_load(path.read_text())


def _as_labels(value):
    """Runner labels from a `runs-on` / matrix `runner` value."""
    if isinstance(value, str):
        text = value.strip()
        if text.startswith("["):
            try:
                return [str(x) for x in json.loads(text)]
            except ValueError:
                return []
        return [text]
    if isinstance(value, (list, tuple)):
        labels = []
        for item in value:
            labels.extend(_as_labels(item))
        return labels
    return []


def matrix_legs(job):
    """Every concrete matrix leg of `job`, as dicts of matrix key -> value."""
    matrix = (job.get("strategy") or {}).get("matrix") or {}
    if not isinstance(matrix, dict) or not matrix:
        return [{}]
    include = matrix.get("include") or []
    dims = {k: v for k, v in matrix.items() if k not in ("include", "exclude") and isinstance(v, list)}
    legs = []
    if dims:
        keys = sorted(dims)
        for combo in itertools.product(*[dims[k] for k in keys]):
            legs.append(dict(zip(keys, combo)))
    if not legs:
        legs = [dict(entry) for entry in include] or [{}]
    elif include:
        merged = []
        for leg in legs:
            row = dict(leg)
            for entry in include:
                if all(row.get(k) == v for k, v in entry.items() if k in row):
                    row.update(entry)
            merged.append(row)
        legs = merged
    return legs


def job_runner_labels(job):
    """Every runner label `job` can run on, resolving a matrix-driven runs-on."""
    runs_on = job.get("runs-on")
    text = runs_on if isinstance(runs_on, str) else ""
    if "${{" not in text:
        return set(_as_labels(runs_on))
    labels = set()
    keys = set(re.findall(r"matrix\.([A-Za-z0-9_-]+)", text))
    for leg in matrix_legs(job):
        for key in keys:
            labels.update(_as_labels(leg.get(key)))
    return labels


def step_index(steps, predicate):
    for i, step in enumerate(steps):
        if isinstance(step, dict) and predicate(step):
            return i
    return None


def is_checkout(step):
    return str(step.get("uses") or "").startswith(CHECKOUT_PREFIX)


def is_clear_step(step):
    return step.get("name") == CLEAR_STEP


def leg_context(leg, docs_only):
    ctx = {"matrix.%s" % k: v for k, v in leg.items()}
    ctx["needs.%s.outputs.docs_only" % CLASSIFY_JOB] = docs_only
    ctx["github.event_name"] = "pull_request"
    return ctx


class WorkflowPinCase(unittest.TestCase):
    def test_inline_copy_is_byte_identical_to_the_script_5657(self):
        want = SCRIPT.read_text().rstrip("\n")
        for path in WORKFLOWS:
            doc = load_workflow(path)
            found = 0
            for job_id, job in (doc.get("jobs") or {}).items():
                for step in job.get("steps") or []:
                    if not is_clear_step(step):
                        continue
                    found += 1
                    self.assertEqual(step.get("shell"), "python3 {0}",
                                     "%s/%s must run the copy as a python3 script" % (path.name, job_id))
                    self.assertEqual(str(step.get("run", "")).rstrip("\n"), want,
                                     "%s/%s inline copy drifted from %s" % (path.name, job_id, SCRIPT.name))
            self.assertEqual(found, 1, "%s needs exactly one #5657 clear step" % path.name)

    def test_clear_step_condition_runs_on_every_self_hosted_leg_5657(self):
        """Evaluated, not grepped: a guard rewritten to `== 'true'`, to
        `false && ...`, or to anything else that skips a self-hosted leg is a
        poisoned runner on the next job."""
        for path in WORKFLOWS:
            doc = load_workflow(path)
            for job_id, job in (doc.get("jobs") or {}).items():
                steps = job.get("steps") or []
                idx = step_index(steps, is_clear_step)
                if idx is None:
                    continue
                condition = steps[idx].get("if")
                self.assertIsNotNone(condition, "%s/%s clear step needs an `if:`" % (path.name, job_id))
                legs = matrix_legs(job)
                self.assertTrue(legs, "%s/%s has no resolvable legs" % (path.name, job_id))
                self_hosted = 0
                for leg in legs:
                    labels = set()
                    for value in leg.values():
                        labels.update(_as_labels(value))
                    want = "self-hosted" in labels
                    self_hosted += 1 if want else 0
                    for docs_only in ("true", "false", ""):
                        got = gh_truthy(GhExpr(str(condition), leg_context(leg, docs_only)).evaluate())
                        if want and docs_only != "":
                            self.assertTrue(got, "%s/%s: leg %r with docs_only=%r SKIPS the clear step"
                                            % (path.name, job_id, leg, docs_only))
                        if not want:
                            self.assertFalse(got, "%s/%s: hosted leg %r runs the clear step"
                                             % (path.name, job_id, leg))
                self.assertGreater(self_hosted, 0, "%s/%s has no self-hosted leg" % (path.name, job_id))

    def test_every_self_hosted_macos_job_clears_before_checkout_5657(self):
        """Repo-wide: ANY job that can land on the self-hosted macOS node and
        checks out the repo must clear the dead scratch first."""
        checked = 0
        for path in sorted(WF_DIR.glob("*.yml")) + sorted(WF_DIR.glob("*.yaml")):
            doc = load_workflow(path)
            if not isinstance(doc, dict):
                continue
            for job_id, job in (doc.get("jobs") or {}).items():
                if not isinstance(job, dict):
                    continue
                labels = job_runner_labels(job)
                if "self-hosted" not in labels or not any(l.startswith("macos") for l in labels):
                    continue
                steps = job.get("steps") or []
                checkout_at = step_index(steps, is_checkout)
                if checkout_at is None:
                    continue
                checked += 1
                clear_at = step_index(steps, is_clear_step)
                self.assertIsNotNone(
                    clear_at,
                    "%s/%s runs on self-hosted macOS and checks out, with no #5657 clear step"
                    % (path.name, job_id))
                self.assertLess(clear_at, checkout_at,
                                "%s/%s clears the scratch AFTER actions/checkout, which is where it dies"
                                % (path.name, job_id))
        self.assertGreaterEqual(checked, 2, "expected at least the ci.yml and session-boot macOS jobs")

    def test_classify_job_runs_these_tests_5657(self):
        doc = load_workflow(WF_DIR / "ci.yml")
        job = (doc.get("jobs") or {}).get(CLASSIFY_JOB)
        self.assertIsNotNone(job, "ci.yml has no %s job" % CLASSIFY_JOB)
        runs = [str(s.get("run") or "") for s in job.get("steps") or [] if not is_clear_step(s)]
        self.assertTrue(any(SELFTEST_REL in r for r in runs),
                        "ci.yml/%s no longer runs %s" % (CLASSIFY_JOB, SELFTEST_REL))

    def test_macos_ci_leg_runs_these_tests_5657(self):
        """SEC-F3: the BSD branch of the janitor is the one that matters on the
        poisoned node, and `ubuntu-latest` never executes it."""
        doc = load_workflow(WF_DIR / "ci.yml")
        found = []
        for job_id, job in (doc.get("jobs") or {}).items():
            steps = job.get("steps") or []
            # the inline janitor copy NAMES this file in its docstring, so the
            # match has to exclude it or every clear step looks like a self-test
            idx = step_index(steps, lambda s: not is_clear_step(s) and SELFTEST_REL in str(s.get("run") or ""))
            if idx is None:
                continue
            checkout_at = step_index(steps, is_checkout)
            for leg in matrix_legs(job):
                labels = set()
                for value in leg.values():
                    labels.update(_as_labels(value))
                if "self-hosted" not in labels or not any(l.startswith("macos") for l in labels):
                    continue
                condition = steps[idx].get("if")
                runs = condition is None or gh_truthy(
                    GhExpr(str(condition), leg_context(leg, "false")).evaluate())
                if not runs:
                    continue
                self.assertIsNotNone(checkout_at, "%s needs a checkout before running the suite" % job_id)
                self.assertGreater(idx, checkout_at,
                                   "ci.yml/%s runs the suite before checkout" % job_id)
                found.append((job_id, leg.get("leg")))
        self.assertTrue(found, "no self-hosted macOS leg in ci.yml runs %s" % SELFTEST_REL)

    def test_live_audit_flag_is_still_set_5657(self):
        src = (ROOT / "src" / "audit.rs").read_text()
        self.assertIn("libc::UF_APPEND", src)
        self.assertIn("FS_APPEND_FL", src)


if __name__ == "__main__":
    unittest.main(verbosity=2)
