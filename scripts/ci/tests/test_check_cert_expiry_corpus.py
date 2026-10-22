#!/usr/bin/env python3
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""External corpus for scripts/check_cert_expiry.py (cert section 7 expiry gate).

Run with `python3 -I -m unittest scripts/ci/tests/test_check_cert_expiry_corpus.py`
or through `python3 -I scripts/check_cert_expiry.py --self-test`, which is a thin
runner over this file (#6445).

ISOLATION. Every case builds its OWN scratch git repository under a
private directory of its own (`CorpusBase.setUp`), so no case can lean on a
commit, ref, branch or file an earlier case left behind, and the cases pass in
any order. `case_6445_cell_isolation` pins that.

NAMED FAILURES (#6445). A case that calls a production helper the gate under
test does not have fails with a named error, never a traceback that hides every
later case: unittest records the error against the case and the rest still run.
`case_6445_base_nameerror` pins that end to end on a gate copy missing a helper.

MANIFEST AND GUARD (V6). `MANIFEST` names every case with its expected verdict:

  * `cell_*`  the plant-a-violation cells of the former in-script self-test.
  * `case_<issue>_<slug>`  one case per member of the cert-expiry defect class.

GREEN means the case must pass. RED means the gate does not yet do what the
issue asks, so the case is wrapped in `unittest.expectedFailure`: it FAILS the
run if it unexpectedly passes (flip it to GREEN in the commit that fixes it) and
it fails the run if it is missing. `scripts/qc-allowlists/cert-expiry-corpus-
manifest.txt` is the committed copy; `test_manifest_ratchet` fails when a name
is deleted from the corpus, when a GREEN entry is flipped to RED, or when the
corpus and the committed file disagree on the set of names (growth is recorded).

Cases for gate behaviour that does not exist on the chain tip yet (the section 7
lexer shapes, the generator under scripts/evidence, the per-file FED multiset)
are real callable cases: a lexer-shape case runs its Rust patch through the
current section 7 drift check and asserts the verdict the finished design gives.
"""
import ast
import importlib.util
import inspect
import io
import os
import posixpath
import re
import shutil
import subprocess
import sys
import tempfile
import types
import unittest
from pathlib import Path

HARNESS_ROOT = Path(__file__).resolve().parents[3]
GATE_PATH = HARNESS_ROOT / "scripts" / "check_cert_expiry.py"
MANIFEST_FILE = HARNESS_ROOT / "scripts" / "qc-allowlists" / "cert-expiry-corpus-manifest.txt"
SCRATCH_ROOT = HARNESS_ROOT / ".local-runs"
CASE_SCRATCH_PREFIX = "cert-expiry-selftest."  # same length as the former in-script scratch dir
NESTED_ENV = "CERT_CORPUS_NESTED"  # set for the child run of case_6445: no further spawning
GREEN = "GREEN"
RED = "RED"
SELF_TEST_FAIL_RC = 2
CHILD_TIMEOUT_S = 900
SENTENCE = (
    "federation-wire surface changed → the enterprise-federation certification "
    "expires per its §7"
)
MOD_RS = "src/federation/mod.rs"
UNRELATED_RS = "src/unrelated.rs"
LIVE_ID = "AI_MEMORY_FED_REQUIRE_SIG"


def _load_gate():
    spec = importlib.util.spec_from_file_location("cert_expiry_gate", str(GATE_PATH))
    module = importlib.util.module_from_spec(spec)
    sys.modules["cert_expiry_gate"] = module
    spec.loader.exec_module(module)
    return module


cert = _load_gate()
# The plant-a-violation helpers below were written as module-level code of the gate and
# call its production names unqualified; give them the gate's namespace.
globals().update({k: v for k, v in vars(cert).items() if not k.startswith("__")})


# ---------------------------------------------------------------------------
# Helpers moved verbatim from the gate former in-script self-test
# ---------------------------------------------------------------------------


class Fixture:
    """A throwaway repository the self-test plants violations in."""

    def __init__(self, repo):
        self.repo = repo

    def g(self, *args):
        proc = run_git(self.repo, *args)
        if proc.returncode != 0:
            err = proc.stderr.decode("utf-8", "replace").strip()
            raise GateError(f"fixture git {args} failed: {err}")
        return proc.stdout.decode("utf-8", "replace").strip()

    def write(self, rel, text, append=False):
        path = self.repo / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "a" if append else "w", encoding="utf-8") as fh:
            fh.write(text)

    def commit(self, paths, msg):
        self.g("add", "--", *paths)
        self.g("commit", "-q", "-m", msg)
        return self.g("rev-parse", "HEAD")

    def reset(self, sha):
        self.g("reset", "-q", "--hard", sha)

    def banner(self, status, binds, extra=""):
        """The cert doc in its real shape (the gate READS the banner)."""
        self.write(
            CERT_DOC,
            "# Enterprise federation certification (fixture)\n\n"
            f"**Binds to:** `{binds}` (fixture bind)\n\n"
            f"> ## STATUS — **{status} as of 2026-01-01** (fixture)\n\n"
            f"Body prose.\n{extra}",
        )

    def prepend(self, rel, line):
        path = self.repo / rel
        path.write_text(line + "\n" + path.read_text(encoding="utf-8"), encoding="utf-8")

    def merge(self, other, msg):
        self.g("merge", "-q", "--no-ff", "-m", msg, other)
        return self.g("rev-parse", "HEAD")


class SelfTest:
    def __init__(self):
        self.failed = False

    def fail(self, msg, out=None):
        print(f"self-test FAILED {msg}", file=sys.stderr)
        if out:
            print(out, file=sys.stderr)
        self.failed = True

    def expect_red(self, label, desc, repo, base, head, needles, tip=None):
        ok, out = check_change(repo, base, head, tip)
        if ok:
            self.fail(f"({label}): {desc} was NOT rejected", out)
            return out
        for needle, why in needles:
            if needle not in out:
                self.fail(f"({label}): rejection {why}:", out)
        return out

    def expect_green(self, label, desc, repo, base, head, needles=(), tip=None):
        ok, out = check_change(repo, base, head, tip)
        if not ok:
            self.fail(f"({label}): {desc} was REJECTED:", out)
            return out
        for needle, why in needles:
            if needle not in out:
                self.fail(f"({label}): pass output {why}:", out)
        return out


    def gate(self, label, why, repo, env, needle=None):
        """Run the whole gate. needle None: it must pass. Else it must fail
        closed (rc 1) AND say `needle` (a fail-closed for the wrong reason, or
        a wrong remedy, is a defect too)."""
        rc, out, err = run_gate(repo, env)
        text = out + err
        if needle is None:
            if rc != 0:
                self.fail(f"({label}): {why} was REJECTED:", text)
        elif rc == 0:
            self.fail(f"({label}): {why} did not fail closed", text)
        elif needle not in text:
            self.fail(f"({label}): {why} failed for the wrong reason (wanted {needle!r}):", text)
        return text


GIT_SHIM = """#!{python} -I
import os, sys
real, argv = {real!r}, sys.argv[1:]
if argv == ["--shim-isolation-probe"]:
    try:
        import gitshim_canary_6145
        planted = True
    except ImportError:
        planted = False
    print(sys.flags.isolated, planted)
    sys.exit(0)
if "--version" in argv and {version!r}:
    print({version!r})
    sys.exit(0)
if {fail!r} and {fail!r} in argv:
    sys.stderr.write("fatal: shim refuses " + {fail!r} + chr(10))
    sys.exit(128)
os.execv(real, [real] + argv)
"""


SHEBANG_MAX = 255  # Linux truncates the interpreter line at 256 bytes (newline included)
MKDTEMP_NAME_LEN = len("gitshim-long.") + 8  # tempfile.mkdtemp appends 8 random characters
# Longest absolute scratch path under which the 255-byte boundary cell still fits:
# 255 - '#!' - ' -I' - '/gitshim-long.XXXXXXXX' - the pad's 1 byte - a 1-byte file name.
SCRATCH_PATH_LIMIT = 255 - len("#!") - len(" -I") - (1 + MKDTEMP_NAME_LEN) - 2


def write_git_shim(shim_dir, real, version="", fail="", interpreter=None):
    """Write the executable `git` PATH shim into shim_dir (#6145: its interpreter
    line is `python3 -I`, like the gate itself in c8-precheck.yml, so the shim's
    own directory is never on its sys.path). Fails closed with GateError when the
    interpreter line cannot carry `-I` intact: whitespace or a NUL byte in the
    interpreter path splits it, a path that is not valid UTF-8 cannot be written, and
    a line over SHEBANG_MAX (255) bytes is truncated by the kernel, which silently
    drops `-I` (a 255-byte line is accepted, a 256-byte line refused).

    Self-test limit (#6145 R5-F3): the `shim-interpreter` cell builds 255/256-byte
    interpreter lines under its scratch dir, so that dir's absolute path must be at
    most SCRATCH_PATH_LIMIT (226) bytes, i.e. the checkout path at most 184 bytes
    (CI uses 44); the checkout-depth cell pins that no other cell needs more (R8-F1).
    A deeper checkout fails the cell with a message naming both
    lengths; it is a property of the environment, not a defect in the gate."""
    python = sys.executable if interpreter is None else str(interpreter)
    line = f"#!{python} -I"
    if not python or "\x00" in python or any(ch.isspace() for ch in python):
        raise GateError(f"the shim interpreter path {python!r} is empty or contains "
                        "whitespace or a NUL byte; its '-I' flag would not survive the shebang")
    try:
        line_bytes = len(line.encode("utf-8"))
    except UnicodeEncodeError as exc:
        raise GateError(f"the shim interpreter path {python!r} is not valid UTF-8 ({exc.reason}); "
                        "the shim is written as UTF-8, so its '-I' flag cannot be guaranteed") from exc
    if line_bytes > SHEBANG_MAX:
        raise GateError(f"the shim interpreter line is {line_bytes} bytes, over "
                        f"{SHEBANG_MAX}; the kernel would truncate it and drop '-I'")
    shim = shim_dir / "git"
    shim.write_text(GIT_SHIM.format(python=python, real=real, version=version,
                                    fail=fail), encoding="utf-8")
    shim.chmod(0o755)
    return shim


def shim_interpreter_violation(tmp):
    """None when write_git_shim refuses every unsafe interpreter path and accepts
    the longest safe one (#6145 S-F1), else a description. The boundary is sized to
    the LITERAL 255/256 byte lines the kernel allows/truncates, never to SHEBANG_MAX,
    so changing that constant to 256 fails here (#6145 R3-F1). Needs the scratch dir's
    absolute path to be at most SCRATCH_PATH_LIMIT (226) bytes, i.e. a checkout path
    of at most 184 bytes; deeper, it reports the lengths instead of building (R5-F3)."""
    fixed = len("#!") + len(" -I")
    deep = None
    try:
        deep = Path(tempfile.mkdtemp(prefix="gitshim-long.", dir=str(tmp)))
        pad = 255 - fixed - len(os.fsencode(str(deep))) - 1
        if pad < 1:
            have = len(os.fsencode(str(tmp)))
            return (f"the scratch path is too deep to build the boundary cases (pad {pad}): "
                    f"the scratch path is {have} bytes but the 255-byte shebang boundary cell "
                    f"needs it at most {SCRATCH_PATH_LIMIT} bytes (checkout path at most "
                    f"{SCRATCH_PATH_LIMIT - have + len(os.fsencode(str(REPO_ROOT)))} bytes); "
                    "run the self-test from a shallower checkout")
        long_dir = deep / ("d" * 200)
        long_dir.mkdir()
        too_long = long_dir / ("p" * 60)
        too_long.symlink_to(sys.executable)
        spaced = deep / "with space" / "python3"
        longest_ok = deep / ("q" * pad)
        one_over = deep / ("q" * (pad + 1))
        for want, interp in ((255, longest_ok), (256, one_over)):
            got = len(os.fsencode(f"#!{interp} -I"))
            if got != want:
                return f"the {want}-byte boundary case is {got} bytes"
        non_utf8 = deep / "py\udcff"
        cases = [("an over-long interpreter path", too_long, True),
                 ("an interpreter path with whitespace", spaced, True),
                 ("the longest in-limit interpreter path", longest_ok, False),
                 ("a 256-byte interpreter line", one_over, True),
                 ("a non-UTF-8 (surrogate-escaped) interpreter path", non_utf8, True),
                 ("an interpreter path with a NUL byte", deep / "py\x00x", True)]
        for label, interp, must_raise in cases:
            try:
                write_git_shim(deep, "git", interpreter=interp)
            except GateError:
                if not must_raise:
                    return f"{label} was refused"
                continue
            except Exception as exc:  # noqa: BLE001 - report any non-GateError as a violation
                return f"{label} raised {type(exc).__name__}, not GateError: {exc}"
            if must_raise:
                return f"{label} was accepted (the kernel would drop '-I')"
        return None
    except OSError as exc:
        return f"could not build the boundary cases: {exc}"
    finally:
        if deep is not None:
            shutil.rmtree(deep, ignore_errors=True)


def shim_boundary_robustness_violation(tmp):
    """None when shim_interpreter_violation reports (never raises) on a scratch dir
    that is missing or sits just under PATH_MAX (#6145 R3-F2), else a description.
    The near-PATH_MAX path is sized from the platform's PATH_MAX (R4-F1) and the cell
    asserts the 200-byte directory build would overflow it (R4-F2), so moving the
    'too deep' check after the build turns this cell red."""
    missing = shim_interpreter_violation(tmp / "no-such-scratch-6145")
    if missing is None or not missing.startswith("could not build the boundary cases"):
        return f"a missing scratch dir gave {missing!r}, not a 'could not build' violation"
    limit = path_max(tmp)
    target = limit - 1 - (MKDTEMP_NAME_LEN + 1) - 1
    try:
        base, near_max = deep_scratch(tmp, target)
    except OSError as exc:
        return f"could not build the near-PATH_MAX scratch: {exc}"
    try:
        if len(os.fsencode(str(near_max))) + MKDTEMP_NAME_LEN + 1 + 201 < limit:
            return (f"the near-PATH_MAX scratch ({target} bytes) is too short for the 200-byte "
                    f"build to overflow PATH_MAX {limit}")
        try:
            deep = shim_interpreter_violation(near_max)
        except OSError as exc:
            return f"a near-PATH_MAX scratch dir raised {type(exc).__name__}: {exc}"
        if deep is None or not deep.startswith("the scratch path is too deep"):
            return f"a near-PATH_MAX scratch dir gave {deep!r}, not a 'too deep' violation"
        left = [p.name for p in near_max.iterdir()] if near_max.is_dir() else []
        if left:
            return f"a near-PATH_MAX scratch dir was left with {left!r}"
    finally:
        shutil.rmtree(base, ignore_errors=True)
    return None


def deep_scratch_base_len(tmp):
    """Length of the shortest path deep_scratch(tmp, ...) can return: the scratch dir,
    a separator, the `gitshim-deep.` prefix and the 8-byte mkdtemp suffix (#6145 R7-F2)."""
    return len(os.fsencode(str(tmp))) + 1 + len("gitshim-deep.") + 8


def deep_scratch_violation(tmp):
    """None when deep_scratch lands on the exact length, cleans up after itself on
    failure and the robustness cell turns a build failure into a named violation
    (#6145 R4-F1/F2/F3), else a description. The two targets are relative to the scratch
    path length (+300 and +600 bytes past the deep_scratch base) and capped below
    PATH_MAX, so they stay valid on a deep checkout (R5-F3)."""
    cap = path_max(tmp) - 1
    base_len = deep_scratch_base_len(tmp)
    if base_len + 2 > cap:  # deep_scratch cannot extend a path by one byte (R6-F2)
        return (f"the scratch path is {len(os.fsencode(str(tmp)))} bytes; deep_scratch needs "
                f"room below the {cap + 1}-byte PATH_MAX")
    for want in (min(base_len + 300, cap), min(base_len + 600, cap)):
        base = None
        try:
            base, cur = deep_scratch(tmp, want)
            got = len(os.fsencode(str(cur)))
            if got != want:
                return f"deep_scratch({want}) built a {got}-byte path, not the exact length"
        except OSError as exc:
            return f"deep_scratch({want}) raised {type(exc).__name__}: {exc}"
        finally:
            if base is not None:
                shutil.rmtree(base, ignore_errors=True)
    try:
        deep_scratch(tmp, 10)
    except OSError:
        pass
    else:
        return "deep_scratch with a target shorter than its base did not fail"
    left = sorted(p.name for p in tmp.glob("gitshim-deep.*"))
    if left:
        return f"a failed deep_scratch left {left!r} behind"
    real, boom = globals()["deep_scratch"], OSError(28, "No space left on device")

    def failing(_tmp, _target):
        raise boom
    globals()["deep_scratch"] = failing
    try:
        res = shim_boundary_robustness_violation(tmp)
    except Exception as exc:  # noqa: BLE001 - the cell must report, never raise
        return f"a deep_scratch build failure raised {type(exc).__name__}: {exc}"
    finally:
        globals()["deep_scratch"] = real
    if res is None or not res.startswith("could not build the near-PATH_MAX scratch"):
        return f"a deep_scratch build failure gave {res!r}, not a named violation"
    return None


FALLBACK_PLATFORMS = (("darwin", 1024), ("freebsd14", 1024), ("openbsd7", 1024),
                      ("netbsd10", 1024), ("linux", 4096))


def path_max_fallback_violation(tmp):
    """None when path_max falls back to the platform's PATH_MAX (1024 on darwin and the
    BSDs, 4096 elsewhere) when os.pathconf raises or answers nonsense, else a
    description (#6145 R5-F1). os.pathconf and sys.platform are patched in place and
    restored."""
    real_pathconf, real_platform = os.pathconf, sys.platform

    def raising(_path, _name):
        raise OSError(errno.EINVAL, "PC_PATH_MAX unavailable")
    # the host's own platform first (False sorts first), so the last patch applied is never the host's and
    # a leaked sys.platform patch is visible on every host (R6-F3)
    plans = sorted(FALLBACK_PLATFORMS, key=lambda entry: entry[0] != real_platform)
    try:
        for plat, want in plans:
            for label, patch in (("raises", raising), ("answers 0", lambda _p, _n: 0),
                                 ("answers None", lambda _p, _n: None)):
                os.pathconf, sys.platform = patch, plat
                got = path_max(tmp)
                if got != want:
                    return (f"path_max fell back to {got} on {plat} when os.pathconf {label}, "
                            f"not the platform limit {want}")
    finally:
        os.pathconf, sys.platform = real_pathconf, real_platform
    return None


PATH_MAX_LEAK_PREFIX = "path_max_fallback_violation leaked"
PATH_MAX_FALLBACK_PLANT = "planted fallback failure 6145"


def path_max_restore_violation(tmp, fallback=path_max_fallback_violation):
    """None when the fallback check (path_max_fallback_violation unless a caller passes
    another) hands os.pathconf and sys.platform back exactly as it found them AND
    passes, else a description (#6145 R6-F3). It is the only caller of
    path_max_fallback_violation and runs first in the cell list, so the snapshot is the
    true entry state and a leak names the real host platform (R7-F1). The patch list
    ends on a platform that is not the host's, so a dropped restore is visible on Linux
    too. The check is a parameter, not a patched global, so the diagnostic can hand in
    a leaking one without anything to put back (R8-F2)."""
    saved_pathconf, saved_platform = os.pathconf, sys.platform
    try:
        res = fallback(tmp)
    finally:
        leaked = []
        if os.pathconf is not saved_pathconf:
            leaked.append("os.pathconf")
        if sys.platform != saved_platform:
            leaked.append(f"sys.platform ({sys.platform!r}, not {saved_platform!r})")
        os.pathconf, sys.platform = saved_pathconf, saved_platform
    if leaked:
        return f"{PATH_MAX_LEAK_PREFIX} a patched {', '.join(leaked)}"
    return res


def path_max_restore_diagnostic_violation(tmp):
    """None when the path-max-restore cell, handed a fallback check that leaks its
    patches (what a dropped `finally` does), fails with a leak message naming the REAL
    host platform and puts os.pathconf and sys.platform back, and, handed a fallback
    check that fails without leaking, fails as `(path-max-fallback, #6145)`, else a
    description (#6145 R7-F1, R8-F1, R8-F2, R9-F3). Only that one cell runs (once per
    planted check), through the same run_cells loop as _self_test, with the planted
    check passed as its `fallback` argument: no global is patched, no other cell
    re-runs and no scratch dir is created, so the diagnostic adds no checkout depth
    (the 184-byte limit holds)."""
    host, real_pathconf = sys.platform, os.pathconf

    def leaking(_tmp):
        for plat, _want in sorted(FALLBACK_PLATFORMS, key=lambda entry: entry[0] != sys.platform):
            os.pathconf, sys.platform = (lambda _p, _n: 0), plat
        return None
    def planted(_tmp):
        return PATH_MAX_FALLBACK_PLANT
    err, fb_err = io.StringIO(), io.StringIO()
    try:
        with contextlib.redirect_stderr(err):
            rc = run_cells(SelfTest(), (("path-max-restore", path_max_restore_violation, (tmp, leaking)),))
        put_back = os.pathconf is real_pathconf and sys.platform == host
        with contextlib.redirect_stderr(fb_err):
            fb_rc = run_cells(SelfTest(), (("path-max-restore", path_max_restore_violation, (tmp, planted)),))
    finally:
        os.pathconf, sys.platform = real_pathconf, host
    out, fb_out = err.getvalue().strip(), fb_err.getvalue().strip()
    if not put_back:
        return ("the path-max-restore cell did not put os.pathconf and sys.platform back "
                "after a leaking fallback check")
    if rc != 2:
        return f"a leaking fallback check was not reported (rc {rc}): {out[-300:]!r}"
    if f"(path-max-restore, #6145): {PATH_MAX_LEAK_PREFIX}" not in out:
        return f"a leaking fallback check was reported as another failure: {out[-300:]!r}"
    if f"not {host!r}" not in out:
        return (f"the leak message does not name the real host platform {host!r}: "
                f"{out[-300:]!r}")
    if fb_rc != 2 or f"(path-max-fallback, #6145): {PATH_MAX_FALLBACK_PLANT}" not in fb_out:
        return (f"a failing (not leaking) fallback check was not reported as path-max-fallback "
                f"(rc {fb_rc}): {fb_out[-300:]!r}")
    return None


def guarded_violation():
    """None when guarded() turns an Exception into '<cell> raised <Type>: <msg>',
    returns None for a passing cell and lets KeyboardInterrupt propagate, else a
    description (#6145 R5-F2)."""
    def boom():
        raise RuntimeError("x")

    def fine():
        return None

    def interrupted():
        raise KeyboardInterrupt
    try:
        got = guarded(boom)
    except Exception as exc:  # noqa: BLE001 - an unguarded crash is the defect under test
        return f"guarded let a RuntimeError escape: {exc}"
    if got != "boom raised RuntimeError: x":
        return f"guarded gave {got!r} for a raising cell, not 'boom raised RuntimeError: x'"
    if guarded(fine) is not None:
        return "guarded changed the result of a passing cell"
    try:
        guarded(interrupted)
    except KeyboardInterrupt:
        return None
    return "guarded swallowed a KeyboardInterrupt"


def scratch_limit_message_violation(tmp):
    """None when the 'scratch path is too deep' violation names the actual scratch path
    length and the limit, else a description (#6145 R5-F3). The limit is derived here
    independently of the code under test: 255 - '#!' - ' -I' - '/gitshim-long.XXXXXXXX'
    - the pad's 1 byte and the 1-byte file name."""
    limit = 255 - len("#!") - len(" -I") - (1 + MKDTEMP_NAME_LEN) - 2
    base, deepest = deep_scratch(tmp, limit + 40)
    try:
        msg = shim_interpreter_violation(deepest)
    finally:
        shutil.rmtree(base, ignore_errors=True)
    if msg is None or not msg.startswith("the scratch path is too deep"):
        return f"a {limit + 40}-byte scratch gave {msg!r}, not a 'too deep' violation"
    for need in (f"{limit + 40} bytes", f"{limit} bytes"):
        if need not in msg:
            return f"the 'too deep' message {msg!r} does not state {need!r}"
    return None


def deep_scratch_relative_violation(tmp):
    """None when deep_scratch_violation stays valid on a deep scratch dir (its targets
    are relative to the scratch path length and capped below PATH_MAX), else a
    description (#6145 R5-F3)."""
    limit = path_max(tmp)
    base, deepest = deep_scratch(tmp, max(limit - 700, len(os.fsencode(str(tmp))) + 100))
    try:
        res = deep_scratch_violation(deepest)
    finally:
        shutil.rmtree(base, ignore_errors=True)
    return res


def deep_scratch_cap_violation(tmp):
    """None when deep_scratch_violation keeps its two targets inside
    [deep_scratch_base_len, PATH_MAX-1] on a scratch dir 400 bytes under PATH_MAX (where
    the +600 target hits the cap) and reports a named 'needs room' violation at 24 bytes
    under PATH_MAX (base 2 bytes under it) but not at 25 (R6-F1, R6-F2, R7-F2), else a
    description (#6145)."""
    limit = path_max(tmp)
    cap = limit - 1
    seen = []
    real = globals()["deep_scratch"]

    def spy(spy_tmp, target):
        seen.append(target)
        return real(spy_tmp, target)
    base, deepest = deep_scratch(tmp, limit - 400)
    globals()["deep_scratch"] = spy
    try:
        res = deep_scratch_violation(deepest)
    finally:
        globals()["deep_scratch"] = real
        shutil.rmtree(base, ignore_errors=True)
    if res is not None:
        return f"deep_scratch_violation failed on a scratch {limit - 400} bytes long: {res}"
    low = deep_scratch_base_len(deepest)
    targets = seen[:2]  # the two build targets come before the too-short probe
    if len(targets) != 2 or cap not in targets:
        return f"the deep_scratch targets {seen!r} never reached the cap {cap}"
    if any(t > cap or t < low for t in targets):
        return f"the deep_scratch targets {targets!r} leave [{low}, {cap}]"
    if targets != [min(low + 300, cap), min(low + 600, cap)]:
        return f"the deep_scratch targets {targets!r} are not base+300 and base+600 capped at {cap}"
    for room, want_room in ((limit - 24, True), (limit - 25, False)):
        base, deepest = deep_scratch(tmp, room)
        try:
            res = deep_scratch_violation(deepest)
        finally:
            shutil.rmtree(base, ignore_errors=True)
        if want_room:
            need = f"the scratch path is {room} bytes; deep_scratch needs room"
            if res is None or not res.startswith(need):
                return f"a {room}-byte scratch gave {res!r}, not a violation starting {need!r}"
        elif res is not None:
            return f"a {room}-byte scratch gave {res!r}, not None"
    return None


CHECKOUT_DEPTH_PREFIX = "cert-expiry-depth."


def checkout_depth_cells():
    """The cells checkout_depth_violation runs in its 226-byte scratch dir (#6145 R10-F1)."""
    return (shim_isolation_violation, shim_interpreter_violation,
            shim_boundary_robustness_violation, deep_scratch_violation,
            path_max_restore_diagnostic_violation, deep_scratch_cap_violation,
            scratch_limit_message_violation, deep_scratch_relative_violation,
            shim_unexecutable_violation)


# Cells whose scratch path or shim interpreter line grows with the scratch depth; each
# must run in checkout_depth_violation's 226-byte scratch dir (#6145 R10-F1).
CHECKOUT_DEPTH_REQUIRED = ("shim_unexecutable_violation",)


def checkout_depth_coverage_violation():
    """None when checkout_depth_cells() names every cell in CHECKOUT_DEPTH_REQUIRED, else
    a description (#6145 R10-F1): the shim-unexecutable cell's interpreter line is 251
    bytes at a 226-byte scratch dir, so a cell left out of checkout-depth lets a deeper
    one pass from a shallow checkout."""
    have = {cell.__name__ for cell in checkout_depth_cells()}
    missing = [name for name in CHECKOUT_DEPTH_REQUIRED if name not in have]
    if missing:
        return f"checkout-depth does not run {', '.join(missing)}"
    return None


def checkout_depth_violation(tmp):
    """None when every #6145 shim and scratch cell passes in a scratch dir exactly
    SCRATCH_PATH_LIMIT (226) bytes long, the scratch a 184-byte checkout gets, else a
    description (#6145 R8-F1, R9-F2). No cell may need more depth than shim-interpreter
    itself, so a cell that nests the self-test (or any of its cells) deeper than its
    own scratch dir fails here (checkout_depth_cells lists them; the checkout-depth-coverage
    cell pins shim_unexecutable_violation in it). path_max_restore_violation builds no
    path and is not in the list; the diagnostic still runs it, but only with planted
    fallbacks, so the real fallback check runs once per self-test (R9-F1); the gate-run
    fixtures build one `gitshim.*` level under the scratch dir and fit within it. The
    dir is a sibling of tmp (tmp itself is 226 bytes at a 184-byte checkout) and is
    removed afterwards."""
    parent = tmp.parent
    pad = SCRATCH_PATH_LIMIT - len(os.fsencode(str(parent))) - 1 - len(CHECKOUT_DEPTH_PREFIX) - 8
    if pad < 0:
        return (f"the scratch root {str(parent)!r} is too deep to build a "
                f"{SCRATCH_PATH_LIMIT}-byte scratch dir")
    deep = Path(tempfile.mkdtemp(prefix=CHECKOUT_DEPTH_PREFIX + "d" * pad, dir=str(parent)))
    try:
        got = len(os.fsencode(str(deep)))
        if got != SCRATCH_PATH_LIMIT:
            return f"the depth scratch dir is {got} bytes, not {SCRATCH_PATH_LIMIT}"
        for cell in checkout_depth_cells():
            res = guarded(cell, deep)
            if res is not None:
                return f"{cell.__name__} failed in a {got}-byte scratch dir: {res}"
    finally:
        shutil.rmtree(deep, ignore_errors=True)
    return None


def shim_isolation_violation(tmp, interpreter=None):
    """None when the git shim is isolated, else a description (#6145). Plants an
    empty `gitshim_canary_6145.py` beside the shim and runs the shim's own probe,
    which reports `sys.flags.isolated` and whether the canary imported (without
    -I the script directory is sys.path[0], so a planted module imports). The
    real import system decides, so a symlinked scratch path cannot fool it."""
    real = shutil.which("git")
    if real is None:
        raise GateError("git is not on PATH")
    shim_dir = Path(tempfile.mkdtemp(prefix="gitshim-iso.", dir=str(tmp)))
    try:
        shim = write_git_shim(shim_dir, real, interpreter=interpreter)
        (shim_dir / "gitshim_canary_6145.py").write_text("", encoding="utf-8")
        first = shim.read_text(encoding="utf-8").splitlines()[0]
        if not first.startswith("#!") or first.split()[1:] != ["-I"]:
            return f"shim interpreter line {first!r} is not '<python> -I'"
        try:
            res = subprocess.run([str(shim), "--shim-isolation-probe"], capture_output=True,
                                 text=True, cwd=str(shim_dir), check=False)
        except OSError as exc:
            return f"the shim could not be executed: {exc}"
        if res.returncode != 0 or res.stdout.split() != ["1", "False"]:
            return ("the shim is not isolated: probe printed "
                    f"{res.stdout.strip()!r} (want '1 False'), rc {res.returncode}: {res.stderr}")
        return None
    finally:
        shutil.rmtree(shim_dir, ignore_errors=True)


def run_gate_shimmed(tmp, repo, env, version="", fail=""):
    """run_gate with a PATH shim `git` that reports `version` for --version
    and exits 128 on any call whose argv contains `fail`, and otherwise
    delegates to the real git (R2-F2: pins the guarded branches)."""
    real = shutil.which("git")
    if real is None:
        raise GateError("git is not on PATH")
    shim_dir = Path(tempfile.mkdtemp(prefix="gitshim.", dir=str(tmp)))
    write_git_shim(shim_dir, real, version, fail)
    saved = os.environ.get("PATH")
    os.environ["PATH"] = f"{shim_dir}{os.pathsep}{saved or ''}"
    try:
        return run_gate(repo, dict(env, PATH=os.environ["PATH"]))
    finally:
        if saved is None:
            os.environ.pop("PATH", None)
        else:
            os.environ["PATH"] = saved
        shutil.rmtree(shim_dir, ignore_errors=True)


def _gate_env(**kw):
    return {k: v for k, v in kw.items() if v is not None}


def guarded(cell, *args, **kwargs):
    """Run a self-test cell; a crash becomes a named violation string, not a traceback
    (#6145 security O1)."""
    try:
        return cell(*args, **kwargs)
    except Exception as exc:  # noqa: BLE001 - report any crash as a named failure
        return f"{cell.__name__} raised {type(exc).__name__}: {exc}"


def run_cells(t, cells):
    """Run (tag, cell, args) self-test cells in order (#6145 R8-F1). The first violation
    is reported through t.fail as `(<tag>, #6145): <violation>` and returns 2; None when
    every cell passes. A path-max-restore violation that is not a leak is tagged
    path-max-fallback, since the fallback check runs inside that cell."""
    for tag, cell, cell_args in cells:
        try:
            res = guarded(cell, *cell_args)
        except Exception as exc:  # noqa: BLE001 - guarded itself must never leak a crash
            res = f"{cell.__name__} escaped guarded: {type(exc).__name__}: {exc}"
        if res is not None:
            if tag == "path-max-restore" and not res.startswith(PATH_MAX_LEAK_PREFIX):
                tag = "path-max-fallback"  # the fallback check runs inside the restore cell
            t.fail(f"({tag}, #6145): {res}")
            print("check-cert-expiry self-test: FAIL", file=sys.stderr)
            return 2
    return None


def shim_unexecutable_violation(tmp):
    """None when a shim whose interpreter does not exist is reported as 'the shim could
    not be executed', else a description (#6145 R10-F1). The interpreter line is 251
    bytes at a 226-byte scratch dir, so checkout-depth runs this cell too."""
    unexec = guarded(shim_isolation_violation, tmp, interpreter=tmp / "no-such-python-6145")
    if unexec is None or not unexec.startswith("the shim could not be executed"):
        return (f"an unexecutable shim gave {unexec!r}, "
                "not a 'the shim could not be executed' violation")
    return None


def shim_isolation_result(tmp, check=shim_isolation_violation):
    """The shim-isolation verdict for _self_test: None when `check(tmp)` passes, else a
    description. A GateError is the description itself; any other crash becomes the
    `guarded` form, so a crash is a named failure and not a traceback (#6145 R10-F2)."""
    try:
        return check(tmp)
    except GateError as exc:
        return str(exc)
    except Exception as exc:  # noqa: BLE001 - report any crash as a named failure
        return f"shim_isolation_violation raised {type(exc).__name__}: {exc}"


def shim_isolation_crash_violation():
    """None when shim_isolation_result turns an OSError, a ValueError and a class defined
    here raised by the check into `shim_isolation_violation raised <Type>: ...`, else a
    description. The private class derives from Exception only, so no narrower tuple of
    builtin types catches it: the three plants pin the handler at Exception. Decoding the
    probe output of non-UTF-8 bytes raises UnicodeDecodeError, a ValueError (#6145 R10-F2,
    R11-F1, R12-F1)."""
    class _Planted6145(Exception):
        pass

    for exc_type in (OSError, ValueError, _Planted6145):
        def crashing(_tmp, exc_type=exc_type):
            raise exc_type("planted 6145")
        got = shim_isolation_result(None, crashing)
        want = f"shim_isolation_violation raised {exc_type.__name__}: planted 6145"
        if got != want:
            return f"{exc_type.__name__} raised in the isolation cell gave {got!r}, not {want!r}"
    return None


# ---------------------------------------------------------------------------
# Case plumbing: manifest, scenes, base class
# ---------------------------------------------------------------------------

MANIFEST = {}
REASONS = {}
SPAWNING = set()  # cases that start a child self-test; skipped in the nested child run


def expect(verdict, reason=""):
    """Register the case in MANIFEST. RED wraps it in expectedFailure (V6)."""
    def decorate(fn):
        if fn.__name__ in MANIFEST:
            raise RuntimeError(f"duplicate corpus case {fn.__name__}")
        MANIFEST[fn.__name__] = verdict
        REASONS[fn.__name__] = reason
        return unittest.expectedFailure(fn) if verdict == RED else fn
    return decorate


def spawning(fn):
    SPAWNING.add(fn.__name__)
    return fn


class CaseJudge(SelfTest):
    """SelfTest whose failures are collected for the owning unittest case."""

    def __init__(self):
        super().__init__()
        self.failures = []

    def fail(self, msg, out=None):
        self.failed = True
        self.failures.append(msg + (("\n" + out) if out else ""))


class Scene:
    """A private repository: `genesis` (watched and unwatched sources, one FED
    id) then `base` (cert doc LIVE bound to genesis). Nothing is shared."""

    def __init__(self, root, name="repo"):
        self.repo = root / name
        self.repo.mkdir()
        fx = self.fx = Fixture(self.repo)
        fx.g("init", "-q", "-b", "main")
        fx.g("config", "user.name", "Cert Expiry Selftest")
        fx.g("config", "user.email", "selftest@localhost")
        fx.g("config", "commit.gpgsign", "false")
        fx.write(MOD_RS, "fn federation_mod() {}\n")
        fx.write("src/handlers/federation_receive.rs", "fn receive() {}\n")
        fx.write("src/handlers/federation_signing_check.rs", "fn signing_check() {}\n")
        fx.write("src/config.rs", f'pub const X: &str = "{LIVE_ID}";\n')
        fx.write(UNRELATED_RS, "fn other() {}\n")
        self.genesis = fx.commit(["src"], "genesis")
        fx.banner("LIVE", self.genesis)
        self.base = fx.commit([CERT_DOC], "base: certification LIVE bound to genesis")

    def edit(self, rel, text, msg, append=False):
        self.fx.write(rel, text, append=append)
        return self.fx.commit([rel], msg)

    def point_origin(self, sha):
        self.fx.g("update-ref", "refs/remotes/origin/main", sha)


class CorpusBase(unittest.TestCase):
    def setUp(self):
        SCRATCH_ROOT.mkdir(parents=True, exist_ok=True)
        self.tmp = Path(tempfile.mkdtemp(prefix=CASE_SCRATCH_PREFIX, dir=str(SCRATCH_ROOT)))
        self.addCleanup(shutil.rmtree, str(self.tmp), True)
        self.t = CaseJudge()
        self.scenes = []

    def scene(self, name=None):
        scene = Scene(self.tmp, name or f"repo{len(self.scenes)}")
        self.scenes.append(scene)
        return scene

    def settle(self):
        """Fail this case with every message the judge collected."""
        self.assertEqual(self.t.failures, [], "\n".join(self.t.failures))

    def gate_over(self, edits, removes=(), name=None):
        """(ok, text, scene, head): the gate over base..head where head applies
        `edits` (path -> text) and deletes `removes` on top of a fresh scene."""
        s = self.scene(name)
        for rel, text in edits.items():
            s.fx.write(rel, text)
        for rel in removes:
            s.fx.g("rm", "-q", rel)
        head = s.fx.commit(sorted(set(edits) | set(removes)), "patch under test")
        ok, text = check_change(s.repo, s.base, head)
        return ok, text, s, head

    def assert_gate_rejects(self, edits, removes=(), why=""):
        ok, text, _s, _head = self.gate_over(edits, removes)
        self.assertFalse(ok, f"the section 7 gate PASSED this change {why}: {text[:300]}")
        return text

    def require_path(self, rel, why):
        self.assertTrue((HARNESS_ROOT / rel).exists(), f"{rel} is absent: {why}")

    def pr_history(self, s):
        """The #6137 history: a stale-LIVE branch merged over a base that healed."""
        fx = s.fx
        stale_tip = s.edit(MOD_RS, "// W: wire change, banner not re-issued\n",
                           "carrier before the banner fix", append=True)
        fx.g("checkout", "-q", "-b", "feature", stale_tip)
        feature = s.edit(UNRELATED_RS, "// feature work\n", "feature: unrelated", append=True)
        fx.g("checkout", "-q", "main")
        fx.banner("EXPIRED", s.genesis)
        healed_base = fx.commit([CERT_DOC], "carrier banner fix: record EXPIRED")
        s.point_origin(healed_base)
        pr_merge = fx.merge("feature", "Merge feature into main")
        env = _gate_env(GITHUB_EVENT_NAME="pull_request", PR_HEAD_SHA=feature,
                        GITHUB_BASE_REF="main", GITHUB_SHA=pr_merge,
                        PATH=os.environ.get("PATH", ""))
        return types.SimpleNamespace(stale_tip=stale_tip, feature=feature,
                                     healed_base=healed_base, pr_merge=pr_merge, env=env)

    def run_cell(self, cell, *args):
        res = guarded(cell, *args)
        self.assertIsNone(res, res)


# ---------------------------------------------------------------------------
# The plant-a-violation cells (the former in-script self-test), one repo each
# ---------------------------------------------------------------------------


class Cells(CorpusBase):
    @expect(GREEN)
    def cell_a_watched_path_red(self):
        s = self.scene()
        viol = s.edit(MOD_RS, "// mutate\n", "violate: touch src/federation", append=True)
        self.t.expect_red("a", "watched-path violation", s.repo, s.base, viol, [
            (SENTENCE, "did not carry the required §7 expiry sentence"),
            (MOD_RS, "did not name the watched path"),
        ])
        self.settle()

    @expect(GREEN)
    def cell_b_watched_path_with_reissue_green(self):
        s = self.scene()
        viol = s.edit(MOD_RS, "// mutate\n", "violate", append=True)
        s.fx.banner("LIVE", viol)
        satisfied = s.fx.commit([CERT_DOC], "satisfy: re-issue cert doc")
        self.t.expect_green("b", "cert-doc-touching variant", s.repo, s.base, satisfied, [
            ("cert doc re-issued/voided", "did not name the cert-doc satisfy path"),
        ])
        self.settle()

    @expect(GREEN)
    def cell_c_identifier_add_red(self):
        s = self.scene()
        id_sha = s.edit("src/config.rs", f'pub const X: &str = "{LIVE_ID}";\n'
                        'pub const Y: &str = "AI_MEMORY_FED_NEW_KNOB";\n', "violate: add id")
        self.t.expect_red("c", "identifier-add violation", s.repo, s.base, id_sha, [
            ("AI_MEMORY_FED_NEW_KNOB", "did not name the added identifier"),
            (SENTENCE, "did not carry the required §7 expiry sentence"),
        ])
        self.settle()

    @expect(GREEN)
    def cell_d_identifier_add_with_reissue_green(self):
        s = self.scene()
        id_sha = s.edit("src/config.rs", f'pub const X: &str = "{LIVE_ID}";\n'
                        'pub const Y: &str = "AI_MEMORY_FED_NEW_KNOB";\n', "violate: add id")
        s.fx.banner("LIVE", id_sha)
        id_ok = s.fx.commit([CERT_DOC], "satisfy: re-issue alongside identifier add")
        self.t.expect_green("d", "identifier-add + cert-doc variant", s.repo, s.base, id_ok)
        self.settle()

    @expect(GREEN)
    def cell_e_unrelated_src_edit_green(self):
        s = self.scene()
        clean = s.edit(UNRELATED_RS, "// unrelated\n", "clean", append=True)
        self.t.expect_green("e", "unrelated src edit", s.repo, s.base, clean, [
            ("federation-wire surface unchanged", "did not say the surface was unchanged"),
        ])
        self.settle()

    @expect(GREEN)
    def cell_f_cert_doc_only_green(self):
        s = self.scene()
        docs = s.edit(CERT_DOC, "// docs only\n", "clean: cert-doc only", append=True)
        self.t.expect_green("f", "cert-doc-only change", s.repo, s.base, docs)
        self.settle()

    @expect(GREEN)
    def cell_g_federation_receive_red(self):
        s = self.scene()
        rel = "src/handlers/federation_receive.rs"
        recv = s.edit(rel, "// mutate receive\n", "violate", append=True)
        self.t.expect_red("g", "federation_receive.rs violation", s.repo, s.base, recv,
                          [(rel, "did not name federation_receive.rs")])
        self.settle()

    @expect(GREEN)
    def cell_h_federation_signing_check_red(self):
        s = self.scene()
        rel = "src/handlers/federation_signing_check.rs"
        sign = s.edit(rel, "// mutate signing\n", "violate", append=True)
        self.t.expect_red("h", "federation_signing_check.rs violation", s.repo, s.base, sign,
                          [(rel, "did not name federation_signing_check.rs")])
        self.settle()

    @expect(GREEN)
    def cell_h2_nested_federation_path_red(self):
        s = self.scene()
        rel = "src/federation/identity/mod.rs"
        nested = s.edit(rel, "fn identity() {}\n", "violate: nested path")
        self.t.expect_red("h2", "nested src/federation/identity/mod.rs", s.repo, s.base,
                          nested, [(rel, "did not name the nested watched path")])
        self.settle()

    @expect(GREEN)
    def cell_i_watched_file_rename_red(self):
        s = self.scene()
        (s.repo / "src/elsewhere").mkdir(parents=True, exist_ok=True)
        s.fx.g("mv", MOD_RS, "src/elsewhere/mod.rs")
        s.fx.g("commit", "-q", "-m", "violate: rename watched file away")
        rename = s.fx.g("rev-parse", "HEAD")
        self.t.expect_red("i", "watched-file rename", s.repo, s.base, rename,
                          [(MOD_RS, "rename rejection did not name the old watched path")])
        self.settle()

    @expect(GREEN)
    def cell_j_identifier_rename_red(self):
        s = self.scene()
        idren = s.edit("src/config.rs",
                       'pub const X: &str = "AI_MEMORY_FED_REQUIRE_SIGNATURE";\n', "violate: rename id")
        self.t.expect_red("j", "identifier-rename", s.repo, s.base, idren, [
            ("AI_MEMORY_FED_REQUIRE_SIGNATURE", "did not name the added identifier"),
            (LIVE_ID, "did not name the removed identifier"),
        ])
        self.settle()

    @expect(GREEN)
    def cell_p_non_ascii_watched_path_red(self):
        s = self.scene()
        rel = "src/federation/naïve_wire.rs"
        quoted = s.edit(rel, "fn wire() {}\n", "violate: non-ASCII watched path")
        self.t.expect_red("p", "non-ASCII watched path (core.quotePath bypass)", s.repo,
                          s.base, quoted, [(rel, "did not name the raw non-ASCII path")])
        self.settle()

    @expect(GREEN)
    def cell_q_incidental_cert_doc_edit_red(self):
        s = self.scene()
        s.fx.write(MOD_RS, "// mutate\n", append=True)
        s.fx.banner("LIVE", s.genesis, "An incidental prose edit.\n")
        incidental = s.fx.commit([MOD_RS, CERT_DOC], "violate: wire change + incidental doc edit")
        self.t.expect_red("q", "wire change + incidental cert-doc edit", s.repo, s.base,
                          incidental, [
            ("an incidental edit is not a re-issue and not a voiding record",
             "did not name the incidental edit"),
            (SENTENCE, "did not carry the required §7 expiry sentence"),
        ])
        self.settle()

    def void_commit(self, s):
        s.fx.write(MOD_RS, "// mutate\n", append=True)
        s.fx.banner("VOID", s.genesis)
        return s.fx.commit([MOD_RS, CERT_DOC], "satisfy: wire change + VOID record")

    @expect(GREEN)
    def cell_r_void_record_green(self):
        s = self.scene()
        void = self.void_commit(s)
        self.t.expect_green("r", "wire change + VOID record", s.repo, s.base, void, [
            ("banner STATUS=VOID", "did not report the VOID banner")])
        self.settle()

    @expect(GREEN)
    def cell_t_unrelated_over_void_green(self):
        s = self.scene()
        void = self.void_commit(s)
        over = s.edit(UNRELATED_RS, "// unrelated\n", "clean over VOID", append=True)
        self.t.expect_green("t", "unrelated change over a VOID banner", s.repo, void, over)
        self.settle()

    def stale_live(self, s):
        drifted = s.edit(MOD_RS, "// mutate\n", "earlier: wire change, no re-issue", append=True)
        stale = s.edit(UNRELATED_RS, "// unrelated\n", "later: unrelated over stale LIVE", append=True)
        return drifted, stale

    @expect(GREEN)
    def cell_s_live_banner_over_drift_red(self):
        s = self.scene()
        drifted, stale = self.stale_live(s)
        self.t.expect_red("s", "LIVE banner over wire drift", s.repo, drifted, stale, [
            (f"claims LIVE bound to {s.genesis} but 1 federation-wire change(s) landed since",
             "did not name the bound SHA and the drift count"),
            ("while its banner still says LIVE", "did not carry the banner-vs-drift sentence"),
            (MOD_RS, "did not list the drifted path"),
        ])
        self.settle()

    @expect(GREEN)
    def cell_u_stale_live_healed_by_expired_green(self):
        s = self.scene()
        _drifted, stale = self.stale_live(s)
        s.fx.banner("EXPIRED", s.genesis)
        healed = s.fx.commit([CERT_DOC], "heal: record EXPIRED")
        self.t.expect_green("u", "recording EXPIRED over the stale LIVE banner", s.repo,
                            stale, healed)
        self.settle()

    @expect(GREEN)
    def cell_v1_non_ancestor_bind_same_tree_green(self):
        s = self.scene()
        s.fx.g("checkout", "-q", "-b", "side", s.genesis)
        side = s.edit(UNRELATED_RS, "// side\n", "side commit (unwatched)", append=True)
        s.fx.g("checkout", "-q", "main")
        s.fx.banner("LIVE", side)
        nonanc = s.fx.commit([CERT_DOC], "bind to a non-ancestor with an identical watched tree")
        self.t.expect_green("v1", "a bind to a non-ancestor with an identical watched tree",
                            s.repo, s.base, nonanc, [
            ("federation-wire surface unchanged since the bind",
             "did not report zero drift since the bind")])
        self.settle()

    @expect(GREEN)
    def cell_v2_non_ancestor_bind_different_tree_red(self):
        s = self.scene()
        s.fx.g("checkout", "-q", "-b", "side2", s.genesis)
        side2 = s.edit(MOD_RS, "// side wire\n", "side commit (watched)", append=True)
        s.fx.g("checkout", "-q", "main")
        s.fx.banner("LIVE", side2)
        evasive = s.fx.commit([CERT_DOC], "bind to a non-ancestor whose watched tree differs")
        self.t.expect_red("v2", "a bind to a non-ancestor with a DIFFERENT watched tree",
                          s.repo, s.base, evasive, [
            (f"claims LIVE bound to {side2}", "did not name the evasive bound SHA")])
        self.settle()

    @expect(GREEN)
    def cell_w_unparseable_status_red(self):
        s = self.scene()
        bad = s.edit(CERT_DOC, "# cert\nno banner here\n", "break: banner unparseable")
        self.t.expect_red("w", "an unparseable STATUS line", s.repo, s.base, bad, [
            ("no parseable STATUS line", "did not name the missing STATUS line")])
        self.settle()

    @expect(GREEN)
    def cell_x1_decoy_status_line_red(self):
        s = self.scene()
        s.fx.write(MOD_RS, "// mutate\n", append=True)
        s.fx.banner("LIVE", s.genesis)
        s.fx.prepend(CERT_DOC, "> ## STATUS — **VOID as of 2026-01-02** (decoy)")
        decoy = s.fx.commit([MOD_RS, CERT_DOC], "violate: decoy STATUS line + wire change")
        self.t.expect_red("x1", "a decoy STATUS line above the real banner", s.repo, s.base,
                          decoy, [("not carry exactly one STATUS banner line",
                                   "did not name the duplicated banner")])
        self.settle()

    @expect(GREEN)
    def cell_x2_decoy_binds_line_red(self):
        s = self.scene()
        wire = s.edit(MOD_RS, "// mutate\n", "wire change", append=True)
        s.fx.banner("LIVE", s.genesis)
        s.fx.prepend(CERT_DOC, f"**Binds to:** `{wire}` (decoy)")
        decoy = s.fx.commit([CERT_DOC], "violate: decoy Binds-to line")
        self.t.expect_red("x2", "a decoy Binds-to line above the real one", s.repo, s.base,
                          decoy, [("at most one Binds-to line",
                                   "did not name the duplicated Binds-to")])
        self.settle()

    @expect(GREEN)
    def cell_y_cert_doc_deleted_red(self):
        s = self.scene()
        s.fx.write(MOD_RS, "// mutate\n", append=True)
        s.fx.g("rm", "-q", CERT_DOC)
        deleted = s.fx.commit([MOD_RS], "violate: delete the certification + wire change")
        self.t.expect_red("y", "deleting the cert doc alongside a wire change", s.repo,
                          s.base, deleted, [("ABSENT at HEAD (deleted in this change)",
                                             "did not name the deletion")])
        self.settle()

    def reformat(self, s):
        s.fx.write(
            CERT_DOC,
            "# Enterprise federation certification (fixture)\n\n"
            f"**Binds  to:**  {s.genesis.upper()}  (reformatted)\n\n"
            "#  STATUS  -  **LIVE as of 2026-01-01**  (reformatted)\n\nBody prose.\n",
        )
        return s.fx.commit([CERT_DOC], "docs: reformat the banner")

    @expect(GREEN)
    def cell_z_banner_reformat_green(self):
        s = self.scene()
        reformat = self.reformat(s)
        self.t.expect_green("z", "a pure banner reformat", s.repo, s.base, reformat, [
            (f"banner LIVE bound to {s.genesis}; federation-wire surface unchanged since the bind",
             "did not parse the reformatted banner to LIVE bound to genesis")])
        self.settle()

    @expect(GREEN)
    def cell_z2_reformat_plus_wire_change_red(self):
        s = self.scene()
        self.reformat(s)
        wire = s.edit(MOD_RS, "// mutate\n", "violate: wire change over the reformat", append=True)
        self.t.expect_red("z2", "reformat + wire change", s.repo, s.base, wire, [
            ("an incidental edit is not a re-issue",
             "did not classify the reformat as incidental")])
        self.settle()

    @expect(GREEN)
    def cell_pr1_merge_commit_judges_stale_live_green(self):
        s = self.scene()
        h = self.pr_history(s)
        self.t.expect_green("pr1", "stale-LIVE head with base EXPIRED, judged at the merge commit",
                            s.repo, h.healed_base, h.feature, [
            ("federation-wire surface unchanged", "did not pass at the merge commit"),
            ("banner STATUS=EXPIRED", "did not read the EXPIRED banner at the merge commit"),
        ], tip=h.pr_merge)
        self.t.expect_red("pr1-head", "head-only judgment of the same branch", s.repo,
                          h.healed_base, h.feature, [
            ("while its banner still says LIVE", "did not show the stale-LIVE head failure")])
        rc, out, err = run_gate(s.repo, h.env)
        if rc != 0:
            self.t.fail("(pr1-gate): pull_request event did not pass end to end:", out + err)
        self.settle()

    @expect(GREEN)
    def cell_pr3_stale_payload_base_ignored(self):
        s = self.scene()
        h = self.pr_history(s)
        captured = io.StringIO()
        with contextlib.redirect_stderr(captured):
            rc, out, err = run_gate(s.repo, dict(h.env, PR_BASE_SHA=s.genesis))
        err = err + captured.getvalue()
        if rc != 0:
            self.t.fail("(pr3): a stale payload PR_BASE_SHA broke the verdict:", out + err)
        elif f"unchanged in {h.healed_base}..{h.pr_merge}" not in out:
            self.t.fail("(pr3): the live base was NOT used:", out)
        elif "using the live base" not in err:
            self.t.fail("(pr3): the stale payload base was not reported:", err)
        stale_ok, stale_text = check_change(s.repo, s.genesis, h.feature, h.pr_merge)
        if stale_ok or "is not on the live base" not in stale_text:
            self.t.fail("(pr3b): a base not containing the first parent did not fail closed",
                        stale_text)
        self.settle()

    @expect(GREEN)
    def cell_pr2_head_flips_banner_over_moved_base(self):
        s = self.scene()
        fx = s.fx
        fx.g("checkout", "-q", "-b", "flip", s.base)
        fx.write(MOD_RS, "// flip branch wire change\n", append=True)
        fx.banner("VOID", s.genesis)
        flip = fx.commit([MOD_RS, CERT_DOC], "flip: wire change + VOID record")
        fx.g("checkout", "-q", "main")
        moved = s.edit(UNRELATED_RS, "// base moved\n", "base moves on", append=True)
        s.point_origin(moved)
        flip_merge = fx.merge("flip", "Merge flip into main")
        self.t.expect_green("pr2", "head that flips the banner with the base moved on", s.repo,
                            moved, flip, [
            ("cert doc re-issued/voided", "did not detect the banner flip"),
            (f"{moved}..{flip_merge}", "did not measure base tip..merge-commit")], tip=flip_merge)
        self.settle()

    @expect(GREEN)
    def cell_pr2b_wire_change_without_flip_over_moved_base_red(self):
        s = self.scene()
        fx = s.fx
        moved = s.edit(UNRELATED_RS, "// base moved\n", "base moves on", append=True)
        s.point_origin(moved)
        fx.g("checkout", "-q", "-b", "noflip", s.base)
        noflip = s.edit(MOD_RS, "// noflip branch wire change\n", "noflip: wire change", append=True)
        fx.g("checkout", "-q", "main")
        noflip_merge = fx.merge("noflip", "Merge noflip into main")
        self.t.expect_red("pr2b", "wire change without a banner flip over a moved base", s.repo,
                          moved, noflip, [
            (SENTENCE, "did not carry the required §7 expiry sentence"),
            (MOD_RS, "did not name the watched path"),
            ("judged at the pull_request merge commit", "did not say it judged the merge commit"),
        ], tip=noflip_merge)
        self.settle()

    @expect(GREEN)
    def cell_pr5_stale_branch_not_charged_for_base_wire_change(self):
        s = self.scene()
        fx = s.fx
        fx.banner("EXPIRED", s.genesis)
        fork5 = fx.commit([CERT_DOC], "base: banner EXPIRED at the fork point")
        fx.g("checkout", "-q", "-b", "stale5", fork5)
        stale5 = s.edit(UNRELATED_RS, "// stale5 branch work\n", "stale5: unrelated", append=True)
        fx.g("checkout", "-q", "main")
        base5 = s.edit(MOD_RS, "// base-side wire change after the fork\n",
                       "base gains a wire change after the fork", append=True)
        s.point_origin(base5)
        merge5 = fx.merge("stale5", "Merge stale5 into main")
        if MOD_RS not in changed_paths(s.repo, fork5, merge5):
            self.t.fail("(pr5): control: merge-base..merge-commit no longer sees the base change")
        self.t.expect_green("pr5", "stale branch with no wire change over a base that gained one",
                            s.repo, base5, stale5, [
            (f"unchanged in {base5}..{merge5}", "did not measure base tip..merge-commit")],
            tip=merge5)
        env = _gate_env(GITHUB_EVENT_NAME="pull_request", PR_HEAD_SHA=stale5,
                        GITHUB_BASE_REF="main", GITHUB_SHA=merge5, PATH=os.environ.get("PATH", ""))
        rc, out, err = run_gate(s.repo, env)
        if rc != 0:
            self.t.fail("(pr5-gate): pull_request event did not pass end to end:", out + err)
        self.settle()

    @expect(GREEN)
    def cell_pr6_pr_wire_change_without_flip_red(self):
        s = self.scene()
        fx = s.fx
        fx.g("checkout", "-q", "-b", "wire6", s.base)
        wire6 = s.edit(MOD_RS, "// wire6 branch wire change\n", "wire6: wire change", append=True)
        fx.g("checkout", "-q", "main")
        s.point_origin(s.base)
        merge6 = fx.merge("wire6", "Merge wire6 into main")
        self.t.expect_red("pr6", "PR wire change without a banner flip, base unchanged", s.repo,
                          s.base, wire6, [
            (SENTENCE, "did not carry the required section 7 expiry sentence"),
            (MOD_RS, "did not name the watched path"),
            (f"{s.base}..{merge6}", "did not measure base tip..merge-commit")], tip=merge6)
        self.settle()

    @expect(GREEN)
    def cell_pr7_merge_commit_structure(self):
        s = self.scene()
        fx, base, tmp = s.fx, s.base, self.tmp
        s.point_origin(base)
        fx.g("checkout", "-q", "-b", "h7", base)
        head7 = s.edit(UNRELATED_RS, "// h7 PR work\n", "h7: PR work", append=True)
        fx.g("checkout", "-q", "-b", "o7", base)
        s.edit("src/other7.rs", "fn other7() {}\n", "o7: an unrelated branch")
        fx.g("checkout", "-q", "main")
        good7 = fx.merge("h7", "Merge h7 into main")
        fx.reset(base)
        unrel7 = fx.merge("o7", "Merge o7 into main (an unrelated branch, not the PR head)")
        fx.reset(base)
        fx.g("merge", "-q", "--no-ff", "-m", "octopus: h7 and o7 into main", "h7", "o7")
        octo7 = fx.g("rev-parse", "HEAD")
        fx.reset(base)
        env7 = _gate_env(GITHUB_EVENT_NAME="pull_request", PR_HEAD_SHA=head7,
                         GITHUB_BASE_REF="main", GITHUB_SHA=good7, PATH=os.environ.get("PATH", ""))
        self.t.gate("pr7-ok", "control: a two-parent merge of the live tip and the PR head",
                    s.repo, env7)
        rc, out, err = run_gate_shimmed(tmp, s.repo, env7, version="git version 2.29.9")
        if rc != 1 or "git >= 2.30 is required" not in out + err:
            self.t.fail("(gitver): git 2.29.9 did not fail closed with the version guard:", out + err)
        rc, out, err = run_gate_shimmed(tmp, s.repo, env7, fail="--is-ancestor")
        if rc != 1 or "merge-base --is-ancestor exited 128" not in out + err:
            self.t.fail("(anc-error): an is-ancestor error did not fail closed:", out + err)
        rc, out, err = run_gate_shimmed(tmp, s.repo, env7)
        if rc != 0:
            self.t.fail("(shim-control): the pass-through git shim was REJECTED:", out + err)
        self.t.gate("pr7-second", "a merge whose second parent is not PR_HEAD_SHA", s.repo,
                    dict(env7, GITHUB_SHA=unrel7), "is not PR_HEAD_SHA")
        self.t.gate("pr7-octopus", "a three-parent (octopus) merge", s.repo,
                    dict(env7, GITHUB_SHA=octo7), "does not have exactly two parents")
        moved7 = s.edit("src/main7.rs", "fn main7() {}\n", "base moves on with an unrelated commit")
        s.point_origin(moved7)
        out = self.t.gate("pr4-moved", "base moved by an unrelated commit", s.repo, env7)
        if f"unchanged in {base}..{good7}" not in out:
            self.t.fail("(pr4-moved): the range did not start at the first parent:", out)
        fx.g("checkout", "-q", "h7")
        rev7 = fx.merge("main", "Merge main into h7 (reversed parents)")
        fx.g("checkout", "-q", "main")
        self.t.gate("pr4-reversed", "reversed parents (PR head first)", s.repo,
                    dict(env7, GITHUB_SHA=rev7), "reversed parents")
        fx.g("checkout", "-q", "-b", "side", s.genesis)
        side = s.edit(UNRELATED_RS, "// side\n", "side commit (unwatched)", append=True)
        fx.g("checkout", "-q", "main")
        s.point_origin(side)
        off = self.t.gate("pr4-offbase", "first parent not on the live base", s.repo, env7,
                          "is not on the live base")
        if "re-run the job" in off or "push a new commit or sync the branch" not in off:
            self.t.fail("(pr4-offbase): the remedy must say to push or sync, never re-run:", off)
        if "is not on the live base origin/main (tip " not in off:
            self.t.fail("(pr4-offbase): the message must name origin/<GITHUB_BASE_REF>:", off)
        for what, sha in (("first parent", fx.g("rev-parse", f"{good7}^1")), ("live tip", side)):
            if off.count(sha) != 1:
                self.t.fail(f"(pr4-offbase): the {what} sha must be printed exactly once:", off)
        self.settle()

    @expect(GREEN)
    def cell_pr4_pull_request_fail_closed(self):
        s = self.scene()
        h = self.pr_history(s)
        env = h.env
        hex_msg = "is not exactly 40 or 64 hex characters"
        closed = [
            ("no GITHUB_BASE_REF", {k: v for k, v in env.items() if k != "GITHUB_BASE_REF"},
             "GITHUB_BASE_REF is unset"),
            ("no PR_HEAD_SHA", {k: v for k, v in env.items() if k != "PR_HEAD_SHA"},
             "PR_HEAD_SHA is unset"),
            ("unresolvable PR_HEAD_SHA", dict(env, PR_HEAD_SHA="1" * 40),
             "does not resolve to a commit"),
            ("unresolvable merge commit", dict(env, GITHUB_SHA="2" * 40),
             "does not resolve to a commit"),
            ("a GITHUB_SHA that is not a two-parent merge", dict(env, GITHUB_SHA=s.base),
             "does not have exactly two parents"),
            ("base ref neither local nor fetchable", dict(env, GITHUB_BASE_REF="no-such-branch"),
             "cannot resolve the live base ref"),
            ("option-shaped base ref", dict(env, GITHUB_BASE_REF="--upload-pack=x"),
             "is not a plain branch name"),
            ("option-shaped PR_HEAD_SHA", dict(env, PR_HEAD_SHA="--upload-pack=x"), hex_msg),
            ("too-short PR_HEAD_SHA", dict(env, PR_HEAD_SHA=h.feature[:6]), hex_msg),
            ("12-char abbreviated PR_HEAD_SHA", dict(env, PR_HEAD_SHA=h.feature[:12]), hex_msg),
            ("40-hex GITHUB_SHA with a trailing newline",
             dict(env, GITHUB_SHA=h.pr_merge + "\n"), hex_msg),
            ("non-hex GITHUB_SHA", dict(env, GITHUB_SHA="zz" + h.pr_merge[2:]), hex_msg),
            ("non-hex PR_BASE_SHA", dict(env, PR_BASE_SHA="--oops"), hex_msg),
            ("option-shaped push GITHUB_EVENT_BEFORE",
             {"GITHUB_EVENT_NAME": "push", "GITHUB_EVENT_BEFORE": "--upload-pack=x",
              "GITHUB_SHA": s.base, "PATH": os.environ.get("PATH", "")}, hex_msg),
        ]
        for why, case_env, needle in closed:
            self.t.gate("pr4", f"pull_request with {why}", s.repo, case_env, needle)
        self.settle()

    @expect(GREEN)
    def cell_k_pull_request_nothing_set_fail_closed(self):
        s = self.scene()
        self.t.gate("k", "pull_request with PR_HEAD_SHA and GITHUB_BASE_REF unset", s.repo,
                    {"GITHUB_EVENT_NAME": "pull_request"}, "PR_HEAD_SHA is unset")
        self.settle()

    @expect(GREEN)
    def cell_ci_event_payload_authoritative(self):
        s = self.scene()
        viol = s.edit(MOD_RS, "// mutate\n", "violate", append=True)
        s.fx.reset(s.base)
        docs = s.edit(CERT_DOC, "// docs only\n", "clean: cert-doc only", append=True)
        base = s.base
        push_env = {"GITHUB_EVENT_NAME": "push", "GITHUB_EVENT_BEFORE": base, "GITHUB_SHA": docs,
                    "PATH": os.environ.get("PATH", "")}
        refuse = "refused (#5970, fail-closed)"
        t = self.t
        t.gate("ci1", "control: a push range from the payload under GitHub Actions", s.repo,
               dict(push_env, GITHUB_ACTIONS="true"))
        t.gate("ci2", "CERT_EXPIRY_BASE/HEAD overrides under GitHub Actions", s.repo,
               dict(push_env, GITHUB_ACTIONS="true", CERT_EXPIRY_BASE=base, CERT_EXPIRY_HEAD=docs),
               refuse)
        t.gate("ci3", "an empty CERT_EXPIRY_BASE under GitHub Actions", s.repo,
               dict(push_env, GITHUB_ACTIONS="true", CERT_EXPIRY_BASE=""), refuse)
        t.gate("ci4", "CERT_EXPIRY_HEAD alone under GitHub Actions", s.repo,
               dict(push_env, GITHUB_ACTIONS="true", CERT_EXPIRY_HEAD=viol), refuse)
        t.gate("ci5", "an empty event name under GitHub Actions", s.repo,
               {"GITHUB_ACTIONS": "true", "PATH": os.environ.get("PATH", "")},
               "GITHUB_EVENT_NAME is empty in a CI run")
        t.gate("ci6", "the CERT_EXPIRY_BASE override outside CI (honoured, RED range)", s.repo,
               {"CERT_EXPIRY_BASE": base, "CERT_EXPIRY_HEAD": viol,
                "PATH": os.environ.get("PATH", "")}, SENTENCE)
        t.gate("ci7", "the CERT_EXPIRY_BASE override outside CI (honoured, docs range)", s.repo,
               {"CERT_EXPIRY_BASE": base, "CERT_EXPIRY_HEAD": docs,
                "PATH": os.environ.get("PATH", "")})
        self.settle()

    @expect(GREEN)
    def cell_l_workflow_dispatch_skips(self):
        s = self.scene()
        rc, _o, skip_msg = run_gate(s.repo, {"GITHUB_EVENT_NAME": "workflow_dispatch"})
        if rc != 0:
            self.t.fail("(l): workflow_dispatch without CERT_EXPIRY_BASE did not skip")
        if "outside CI" not in skip_msg or "refused under GitHub Actions" not in skip_msg:
            self.t.fail("(l): the skip message must say the overrides work only outside CI:", skip_msg)
        self.settle()

    @expect(GREEN)
    def cell_m_push_zero_before_skips(self):
        s = self.scene()
        rc, _o, _e = run_gate(s.repo, {"GITHUB_EVENT_NAME": "push", "GITHUB_SHA": s.base,
                                       "GITHUB_EVENT_BEFORE": "0" * 40})
        if rc != 0:
            self.t.fail("(m): push with zero before-SHA did not skip")
        self.settle()

    @expect(GREEN)
    def cell_n_unresolvable_range_fail_closed(self):
        s = self.scene()
        if check_change(s.repo, "0" * 40, s.base)[0]:
            self.t.fail("(n): unresolvable base SHA did not fail closed")
        self.settle()

    @expect(GREEN)
    def cell_o_this_checkout_vs_release_green(self):
        own_base = ""
        for ref in ("origin/release/v1.0.0", "@{upstream}"):
            if is_commit(HARNESS_ROOT, ref):
                own_base = git_text(HARNESS_ROOT, "rev-parse", ref)
                break
        if own_base:
            own_head = git_text(HARNESS_ROOT, "rev-parse", "HEAD")
            ok, out = check_change(HARNESS_ROOT, own_base, own_head)
            if not ok:
                self.t.fail("(o): THIS change trips the cert-expiry gate without touching the "
                            "cert doc:", out)
        else:
            print("self-test NOTE (o): skipped own-PR check (no origin/release/v1.0.0 "
                  "and no @{upstream})", file=sys.stderr)
        self.settle()

    # ---- the #6145 git-shim and scratch cells ------------------------------

    @expect(GREEN)
    def cell_shim_isolation(self):
        res = shim_isolation_result(self.tmp)
        self.assertIsNone(res, res)

    @expect(GREEN)
    def cell_shim_interpreter(self):
        self.run_cell(shim_interpreter_violation, self.tmp)

    @expect(GREEN)
    def cell_shim_interpreter_robust(self):
        self.run_cell(shim_boundary_robustness_violation, self.tmp)

    @expect(GREEN)
    def cell_shim_deep_scratch(self):
        self.run_cell(deep_scratch_violation, self.tmp)

    @expect(GREEN)
    def cell_path_max_restore(self):
        self.run_cell(path_max_restore_violation, self.tmp)

    @expect(GREEN)
    def cell_path_max_diagnostic(self):
        self.run_cell(path_max_restore_diagnostic_violation, self.tmp)

    @expect(GREEN)
    def cell_shim_deep_cap(self):
        self.run_cell(deep_scratch_cap_violation, self.tmp)

    @expect(GREEN)
    def cell_guarded(self):
        self.run_cell(guarded_violation)

    @expect(GREEN)
    def cell_shim_isolation_crash(self):
        self.run_cell(shim_isolation_crash_violation)

    @expect(GREEN)
    def cell_checkout_depth_coverage(self):
        self.run_cell(checkout_depth_coverage_violation)

    @expect(GREEN)
    def cell_shim_scratch_limit(self):
        self.run_cell(scratch_limit_message_violation, self.tmp)

    @expect(GREEN)
    def cell_shim_deep_relative(self):
        self.run_cell(deep_scratch_relative_violation, self.tmp)

    @expect(GREEN)
    def cell_checkout_depth(self):
        self.run_cell(checkout_depth_violation, self.tmp)

    @expect(GREEN)
    def cell_shim_unexecutable(self):
        self.run_cell(shim_unexecutable_violation, self.tmp)


# ---------------------------------------------------------------------------
# The defect-class corpus: one case per member of the cert-expiry class
# ---------------------------------------------------------------------------

DEAD_ID_SOURCE = 'pub const X: &str = "{id}";\n{body}\n'  # the id stays named once: no id-set drift
GEN_DIR = "scripts/evidence"
RECAPTURE_PY = "scripts/recapture-cert-3607-posture.py"
REQUIRED_CONTEXTS_SH = "scripts/check-required-contexts.sh"
WORKFLOW = ".github/workflows/c8-precheck.yml"
LIVENESS_TEST = "tests/cert_fed_identifier_liveness.rs"
SIGNING_CHECK_RS = "src/handlers/federation_signing_check.rs"
DOC_ENTERPRISE = "docs/compliance/ENTERPRISE-FEDERATION-CERTIFICATION.md"
DOC_BALLOT = "docs/compliance/BALLOT-PROCEDURE.md"
DOC_STANDARD = "docs/compliance/MISSION-CRITICAL-CERTIFICATION-STANDARD-v1.md"
DELETED_GATE_SH = "check-cert-expiry.sh"
WORKFLOW_COPY_TIMEOUT_S = 600

REASON_LEXER = ("the 6560 lexer is not on the chain tip; the finished design (compiled liveness, "
                "#6911) rejects a patch that makes the id dead while it stays named once")
REASON_GENERATOR = "the vendored cert generator exists only on draft PR 7393, not on the chain tip"


def repo_text(rel):
    return (HARNESS_ROOT / rel).read_text(encoding="utf-8", errors="replace")


# #7988: every entry is a tuple of regular expressions searched (re.MULTILINE) in the comment-stripped text of the
# file; a leading ! means the pattern must NOT match. Each tuple was chosen to FAIL on the real pre-fix file of the
# fix commit and to PASS on the fixed file (PREFIX_REPLAY below replays that), so a probe is no longer a bare
# token that an unfixed generator also carries.
# #7988: every entry is a tuple of regular expressions searched (re.MULTILINE) in the comment-stripped text of the
# file; a leading ! means the pattern must NOT match. Each tuple was chosen to FAIL on the real pre-fix file of the
# fix commit and to PASS on the fixed file (PREFIX_REPLAY below replays that), so a probe is no longer a bare
# token that an unfixed generator also carries.
GENERATOR_NEEDLES = {
    (r"../ci/tests/test_evidence_fixture_identity.py", r"the fixture byte-identity test the cert procedure cites"):
        (r"def test_", r"identity", r"read_bytes\(\)|sha256|hashlib",),
    (r"build_bundle.py", r"recapture lookup must find the .py"):
        (r"RECAPTURE_CANDIDATES", 'endswith\\(\\s*"\\.py"\\s*\\)',),
    (r"run_cert.py", r"scripts picked from the tip tree, never the worktree"):
        (r"def pick_recapture\(", r"def tracked_at\(",),
    (r"run_cert.py", r"the output dir must be quoted in generated bash"):
        (r"OUT=\{shlex\.quote\(",),
    (r"run_cert.py", r"CERT_ env overrides validated and logged"):
        (r"class ConfigError", r"def anchored\(", r"def config_row\(",),
    (r"prep.py", r"commit-1 bytes hash-qualified, docstring true"):
        (r"scripts/check_cert_expiry\.py", r"^FED_ID = re\.compile\(", r"!check-cert-expiry\.sh",),
    (r"build_bundle.py", r"check_run rejects a later crashed chain run"):
        (r"SECTION_START", r"needs exactly one",),
    (r"run_cert.py", r"a missing wrapper writes a RED and an EXIT row"):
        (r"except OSError", r"RED launch", r"return 127",),
    (r"run_cert.py", r"relative CERT_TARGETS and CERT_TMPDIR refused or resolved"):
        (r"def anchored\(", r"os\.path\.isabs|is_absolute\(\)",),
    (r"run_cert.py", r"a failed cert commit push fails the gates leg"):
        (r"def push_gated\(", r"RED push",),
    (r"prep.py", r"a git grep error is an error, never an empty FED id set"):
        (r"returncode not in \(0, 1\)", r"sys\.exit\(3\)",),
    (r"run_cert.py", r"cert-alone.out records ionice only when it was used"):
        ('shutil\\.which\\("ionice"\\)', r"def priority_desc\(",),
    (r"run_cert.py", r"pick_expiry refuses look-alike, symlink and skip-worktree copies"):
        (r"def blob_bytes\(", r"100644", r"100755",),
    (r"run_cert.py", r"an output dir on tmpfs or under a tmp root is refused"):
        ('\\("--outd", Path\\(os\\.path\\.abspath\\(self\\.outd\\)\\)\\)',),
    (r"run_cert.py", r"wrapper, flock and timeout validated; CONFIG row names the source"):
        (r"def choose\(", r"def preflight\(",),
    (r"run_cert.py", r"is_tmpfs_path decodes proc-mounts octal escapes"):
        (r"def unescape_mount\(",),
    (r"prep.py", r"an empty FED id set at either end is an error"):
        (r"no AI_MEMORY_FED_\* identifier",),
    (r"run_cert.py", r"the docstring states ionice conditionally and exit 64"):
        (r"exit 64 = a refused configuration", r"ionice -c3 when installed",),
    (r"run_cert.py", r"PLANS has a gates entry"):
        ('"gates": \\("gates",\\)',),
    (r"run_cert.py", r"the expiry gate copy never follows a symlink"):
        (r"run from memory, nothing is written",),
    (r"run_cert.py", r"the preflight EXIT row says 64 where the exit is 64"):
        (r"EXIT=64 leg=",),
    (r"../ci/tests/test_evidence_generator_r3_7393.py", r"tests write under the scratch root only"):
        ('mock\\.patch\\.object\\(rc, "TMP_ROOTS"', r"!TMP \+",),
    (r"run_cert.py", r"an OSError creating the gate copy writes an EXIT row"):
        (r"expiry, gate_blob, gate_sha = self\.expiry_gate\(\)",),
    (r"run_cert.py", r"a relocated gate copy resolves its repo root to the checkout"):
        (r"PY_LOADER", r"__file__",),
    (r"run_cert.py", r"O_EXCL and O_NOFOLLOW pinned; a killed run is swept"):
        (r"def sweep_legacy\(", r"os\.kill\(int\(m\.group\(1\)\), 0\)",),
    (r"../ci/tests/test_evidence_generator_r2_7393.py", r"the tmp-root guard covers every spelling"):
        ('mock\\.patch\\.object\\(rc, "TMP_ROOTS"', r"fake-tmp-root",),
    (r"run_cert.py", r"push-branch and parent refused on legs that ignore them"):
        (r"given = \[", r"return 64",),
    (r"run_cert.py", r"the gate copy runs under python3 -I"):
        ('\\[sys\\.executable, "-I"',),
    (r"run_cert.py", r"the sweep goes through the directory fd"):
        (r"def remove_tree\(dfd, name\)", r"dir_fd=dfd",),
    (r"../ci/tests/test_evidence_generator_r6_7393.py", r"the AST guard checks tempfile and folds join"):
        (r"TEMPFILE_ALWAYS", r"TMP_ROOTS subscript", r"PATH_JOINS", r"without dir=",),
    (r"../ci/tests/test_evidence_generator_r6_7393.py", r"the posture OSError widening is pinned"):
        ('recapture_blob", side_effect=PermissionError', r"RED posture recapture script",),
    (r"../ci/tests/test_evidence_generator_r6_7393.py", r"the realpath comparison is pinned"):
        ('"TMP_ROOTS", \\(str\\(self\\.link\\),\\)',),
    (r"run_cert.py", r"the posture copy is never written through a symlink"):
        (r"PY_LOADER", '\\"bash\\", \\"-c\\", body',),
    (r"run_cert.py", r"the gate copy has no check-to-exec window"):
        (r"stdin_data=gate_blob",),
    (r"run_cert.py", r"a deeply nested stale dir does not crash the gates leg"):
        (r"def remove_tree\(", r"def sweep_legacy\(", r"SWEEP_MAX_DEPTH",),
    (r"run_cert.py", r"repo gate scripts run with an empty cwd"):
        (r"SCRUBBED_PYTHON_ENV", r"PYTHONSAFEPATH",),
}

# Pre-fix stand-ins: (commit, path) read with `git show <commit>:<path>` on PR 7393 (#7988). A probe must fail on
# each one that can be read; case_7988_prefix_replay replays them.
PREFIX_REPLAY = {
    (r"build_bundle.py", r"recapture lookup must find the .py"):  # case_7399
        ((r"ba50174474d6731f9039ca85a42b5fd28342ebed", r"scripts/evidence/build_bundle.py"),),
    (r"run_cert.py", r"scripts picked from the tip tree, never the worktree"):  # case_7411
        ((r"99cd91ae087dba4feb1bbb7b8d77e4a81587fb60", r"scripts/evidence/run_cert.py"),),
    (r"run_cert.py", r"the output dir must be quoted in generated bash"):  # case_7412
        ((r"99cd91ae087dba4feb1bbb7b8d77e4a81587fb60", r"scripts/evidence/run_cert.py"),),
    (r"run_cert.py", r"CERT_ env overrides validated and logged"):  # case_7413
        ((r"99cd91ae087dba4feb1bbb7b8d77e4a81587fb60", r"scripts/evidence/run_cert.py"),),
    (r"prep.py", r"commit-1 bytes hash-qualified, docstring true"):  # case_7417
        ((r"99cd91ae087dba4feb1bbb7b8d77e4a81587fb60", r"scripts/evidence/prep.py"),),
    (r"build_bundle.py", r"check_run rejects a later crashed chain run"):  # case_7419
        ((r"99cd91ae087dba4feb1bbb7b8d77e4a81587fb60", r"scripts/evidence/build_bundle.py"),),
    (r"run_cert.py", r"a missing wrapper writes a RED and an EXIT row"):  # case_7420
        ((r"99cd91ae087dba4feb1bbb7b8d77e4a81587fb60", r"scripts/evidence/run_cert.py"),),
    (r"run_cert.py", r"relative CERT_TARGETS and CERT_TMPDIR refused or resolved"):  # case_7421
        ((r"99cd91ae087dba4feb1bbb7b8d77e4a81587fb60", r"scripts/evidence/run_cert.py"),),
    (r"run_cert.py", r"a failed cert commit push fails the gates leg"):  # case_7422
        ((r"99cd91ae087dba4feb1bbb7b8d77e4a81587fb60", r"scripts/evidence/run_cert.py"),),
    (r"prep.py", r"a git grep error is an error, never an empty FED id set"):  # case_7423
        ((r"99cd91ae087dba4feb1bbb7b8d77e4a81587fb60", r"scripts/evidence/prep.py"),),
    (r"run_cert.py", r"cert-alone.out records ionice only when it was used"):  # case_7425
        ((r"99cd91ae087dba4feb1bbb7b8d77e4a81587fb60", r"scripts/evidence/run_cert.py"),),
    (r"run_cert.py", r"pick_expiry refuses look-alike, symlink and skip-worktree copies"):  # case_7439
        ((r"259115d99ace54535a77710111297b36af1a1ae5", r"scripts/evidence/run_cert.py"),),
    (r"run_cert.py", r"an output dir on tmpfs or under a tmp root is refused"):  # case_7440
        ((r"259115d99ace54535a77710111297b36af1a1ae5", r"scripts/evidence/run_cert.py"),),
    (r"run_cert.py", r"wrapper, flock and timeout validated; CONFIG row names the source"):  # case_7441
        ((r"259115d99ace54535a77710111297b36af1a1ae5", r"scripts/evidence/run_cert.py"),),
    (r"run_cert.py", r"is_tmpfs_path decodes proc-mounts octal escapes"):  # case_7442
        ((r"259115d99ace54535a77710111297b36af1a1ae5", r"scripts/evidence/run_cert.py"),),
    (r"prep.py", r"an empty FED id set at either end is an error"):  # case_7443
        ((r"259115d99ace54535a77710111297b36af1a1ae5", r"scripts/evidence/prep.py"),),
    (r"run_cert.py", r"the docstring states ionice conditionally and exit 64"):  # case_7446
        ((r"259115d99ace54535a77710111297b36af1a1ae5", r"scripts/evidence/run_cert.py"),),
    (r"run_cert.py", r"PLANS has a gates entry"):  # case_7486
        ((r"6fd1fc8aa60a12d235bb15c51d57a28dd4535b65", r"scripts/evidence/run_cert.py"),),
    (r"run_cert.py", r"the expiry gate copy never follows a symlink"):  # case_7489
        ((r"6fd1fc8aa60a12d235bb15c51d57a28dd4535b65", r"scripts/evidence/run_cert.py"),),
    (r"run_cert.py", r"the preflight EXIT row says 64 where the exit is 64"):  # case_7490
        ((r"6fd1fc8aa60a12d235bb15c51d57a28dd4535b65", r"scripts/evidence/run_cert.py"),),
    (r"../ci/tests/test_evidence_generator_r3_7393.py", r"tests write under the scratch root only"):  # case_7492
        ((r"6fd1fc8aa60a12d235bb15c51d57a28dd4535b65", r"scripts/ci/tests/test_evidence_generator_r3_7393.py"),),
    (r"run_cert.py", r"an OSError creating the gate copy writes an EXIT row"):  # case_7530
        ((r"1786e49f4b48cc728a009f86191b2905a9beab8b", r"scripts/evidence/run_cert.py"),),
    (r"run_cert.py", r"a relocated gate copy resolves its repo root to the checkout"):  # case_7531
        ((r"1786e49f4b48cc728a009f86191b2905a9beab8b", r"scripts/evidence/run_cert.py"),),
    (r"run_cert.py", r"O_EXCL and O_NOFOLLOW pinned; a killed run is swept"):  # case_7532
        ((r"1786e49f4b48cc728a009f86191b2905a9beab8b", r"scripts/evidence/run_cert.py"),),
    (r"../ci/tests/test_evidence_generator_r2_7393.py", r"the tmp-root guard covers every spelling"):  # case_7534
        ((r"2a9ca1b3ccea2a97d9c9bb18dc848066de9eec6a", r"scripts/ci/tests/test_evidence_generator_r2_7393.py"),),
    (r"run_cert.py", r"push-branch and parent refused on legs that ignore them"):  # case_7535
        ((r"2a9ca1b3ccea2a97d9c9bb18dc848066de9eec6a", r"scripts/evidence/run_cert.py"),),
    (r"run_cert.py", r"the gate copy runs under python3 -I"):  # case_7581
        ((r"c5729ab839950fd2351a0898cf16db70eb37e4be", r"scripts/evidence/run_cert.py"),),
    (r"run_cert.py", r"the sweep goes through the directory fd"):  # case_7582
        ((r"c5729ab839950fd2351a0898cf16db70eb37e4be", r"scripts/evidence/run_cert.py"),),
    (r"../ci/tests/test_evidence_generator_r6_7393.py", r"the AST guard checks tempfile and folds join"):  # case_7583
        ((r"61d78887b4f8757a9a0a62aca4be66fb195b8c34", r"scripts/ci/tests/test_evidence_generator_r5_7393.py"),),
    (r"../ci/tests/test_evidence_generator_r6_7393.py", r"the posture OSError widening is pinned"):  # case_7584
        ((r"61d78887b4f8757a9a0a62aca4be66fb195b8c34", r"scripts/ci/tests/test_evidence_generator_r5_7393.py"),),
    (r"../ci/tests/test_evidence_generator_r6_7393.py", r"the realpath comparison is pinned"):  # case_7585
        ((r"61d78887b4f8757a9a0a62aca4be66fb195b8c34", r"scripts/ci/tests/test_evidence_generator_r5_7393.py"),),
    (r"run_cert.py", r"the posture copy is never written through a symlink"):  # case_7617
        ((r"618d83b3c2723810e661ef0d5c3abd8bd0785097", r"scripts/evidence/run_cert.py"),),
    (r"run_cert.py", r"the gate copy has no check-to-exec window"):  # case_7618
        ((r"618d83b3c2723810e661ef0d5c3abd8bd0785097", r"scripts/evidence/run_cert.py"),),
    (r"run_cert.py", r"a deeply nested stale dir does not crash the gates leg"):  # case_7620
        ((r"618d83b3c2723810e661ef0d5c3abd8bd0785097", r"scripts/evidence/run_cert.py"),),
    (r"run_cert.py", r"repo gate scripts run with an empty cwd"):  # case_7665
        ((r"33a0535cc46439926f16afd3ab614bc32f3b2ef2", r"scripts/evidence/run_cert.py"),),
}
NO_PREFIX_STANDIN = {
    ("../ci/tests/test_evidence_fixture_identity.py", "the fixture byte-identity test the cert procedure cites"):
        "the file is on no ref this checkout can read, so no pre-fix stand-in exists; the case stays RED",
}
FIXED_REF = "f049ee0e4ec91ccd4ebc5273dfaa495f139cfcb4"  # PR 7393 tip the probes were verified against; pinned, so deleting the branch cannot move it

MIN_PROBE_BYTES = 120  # a stand-in shorter than this cannot carry the named acceptance
# #7988: the id must sit inside an assert macro of a #[test] body, so a bare mention beside assert!(true) fails.
LIVENESS_ASSERT_RE = re.compile(r"\bassert(?:_eq|_ne)?!\s*\([^;]*" + re.escape(LIVE_ID))
YAML_COMMENT_RE = re.compile(r"(^|\s)#.*$")
JOB_HEADER_RE = re.compile(r"^  [\w-]+:\s*$")
BASE_TRUST_RE = re.compile(r"github\.event\.pull_request\.base\.(sha|ref)")
GATE_JOB_NAME = "cert-expiry-gate"
PLAIN_WORKFLOW = "name: x\non: [push]\njobs: {}\n"
WORKFLOW_BAD = (("CR", "\r"), ("NEL", "\u0085"), ("LS", "\u2028"), ("PS", "\u2029"),
                ("NBSP", "\u00a0"), ("EM SPACE", "\u2003"), ("IDEOGRAPHIC SPACE", "\u3000"),
                ("ZWSP", "\u200b"))
LOG_SAFE_SAMPLES = {
    "bidi": ("a\u202eb", "x\u2066y\u2069", "p\u200bq", "m\u200fn"),
    "ignorable": ("a\u00adb", "a\u034fb", "a\u115fb", "a\ufe0fb", "a\u2060b", "a\U000e0100b"),
    "unassigned": ("a\u0378b", "a\U0010fffeb", "a\u0530b"),
}
LOG_SAFE_ONE_TO_ONE = ("\\u202e", "\u202e", "\\\\", "\\", "A", "\\x41", "a\\b")


def code_lines(text, comment_prefix):
    return "\n".join(ln for ln in text.splitlines()
                     if ln.strip() and not ln.strip().startswith(comment_prefix))


def liveness_problems(root):
    """#6911: the compiled liveness test exists, holds real test code that exercises the
    documented id, and the workflow runs it. Empty or comment-only files fail."""
    root = Path(root)
    path = root / LIVENESS_TEST
    if not path.is_file():
        return [f"{LIVENESS_TEST} is absent"]
    code = code_lines(path.read_text(encoding="utf-8", errors="replace"), "//")
    problems = []
    if len(code.splitlines()) < 3:
        problems.append("no code beyond comments")
    if "#[test]" not in code:
        problems.append("no #[test] function")
    if LIVE_ID not in code:
        problems.append(f"does not exercise {LIVE_ID}")
    elif not any(LIVENESS_ASSERT_RE.search(chunk) for chunk in code.split("#[test]")[1:]):
        problems.append(f"no #[test] asserts on the behaviour of {LIVE_ID}")
    wf = root / WORKFLOW
    wired = wf.is_file() and "cert_fed_identifier_liveness" in wf.read_text(encoding="utf-8", errors="replace")
    if not wired:
        problems.append(f"{WORKFLOW} does not run cert_fed_identifier_liveness")
    return problems


def generator_problems(root, rel, needles):
    """A vendored generator or its test: present, non-trivial, parses, and holds the
    named tokens outside comments (and a test function when it is a test file)."""
    path = Path(root) / GEN_DIR / rel
    if not path.is_file():
        return [f"{rel} is absent"]
    text = path.read_text(encoding="utf-8", errors="replace")
    problems = []
    if len(text.strip()) < MIN_PROBE_BYTES:
        problems.append(f"{rel} is trivially small")
    code = text
    if path.suffix == ".py":
        code = code_lines(text, "#")
        try:
            tree = ast.parse(text)
        except SyntaxError as exc:
            return problems + [f"{rel} does not parse: {exc.msg}"]
        if path.name.startswith("test_") and not any(
                isinstance(n, ast.FunctionDef) and n.name.startswith("test") for n in ast.walk(tree)):
            problems.append(f"{rel} defines no test function")
    for needle in needles:
        wanted = not needle.startswith("!")
        if (re.search(needle if wanted else needle[1:], code, re.MULTILINE) is not None) != wanted:
            verb = "lacks" if wanted else "still carries"
            problems.append(f"{rel} {verb} /{needle.lstrip('!')}/ outside comments")
    return problems


REPLAY_FETCH_FLAG = "--print-replay-shas"


def replay_objects():
    """Every commit the replay reads: each pre-fix stand-in and the fixed ref (#7988)."""
    shas = []
    for stands in PREFIX_REPLAY.values():
        for sha, _path in stands:
            if sha not in shas:
                shas.append(sha)
    return shas + [FIXED_REF]


def git_show(repo, rev, path):
    """(True, text) when `git show rev:path` reads, else (False, reason)."""
    rc, out = git_query(repo, ["show", f"{rev}:{path}"])
    return rc == 0, out


def prefix_replay_report(repo, scratch):
    """Replay every probe against the real pre-fix file and the fixed file (#7988). Returns
    (lines, wrong, unreadable): `lines` is one result per replay; `wrong` names every probe that
    PASSED a pre-fix stand-in or FAILED the fixed file; `unreadable` names every object missing."""
    lines, wrong, unreadable = [], [], []
    for key, stands in sorted(PREFIX_REPLAY.items()):
        rel, _why = key
        target = Path(scratch) / GEN_DIR / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        replays = [(f"pre-fix {sha[:9]}", sha, path, True) for sha, path in stands]
        replays.append(("fixed", FIXED_REF, posixpath.normpath(f"{GEN_DIR}/{rel}"), False))
        for label, rev, path, want_fail in replays:
            ok, text = git_show(repo, rev, path)
            if not ok:
                unreadable.append(f"{rev}:{path}")
                lines.append(f"UNREADABLE {rel} {label}")
                continue
            target.write_text(text, encoding="utf-8")
            problems = generator_problems(scratch, rel, GENERATOR_NEEDLES[key])
            verdict = "fails" if problems else "passes"
            good = bool(problems) == want_fail
            lines.append(f"{'ok ' if good else 'BAD'} {rel} {label}: probe {verdict}")
            if not good:
                wrong.append(f"{rel} {label}: probe {verdict}")
    return lines, wrong, unreadable


# #7990: issues this change does not satisfy. A GREEN manifest entry named for one claims it is fixed.
OPEN_ISSUES = {
    "6357": "fence cells f7b, f10b and f10d live on the unlanded fix/6124-promo6-ssh-r2 branch",
}


def open_issue_claims(manifest):
    """Names of GREEN cases whose number is an issue this change leaves open (#7990)."""
    claims = []
    for name, state in sorted(manifest.items()):
        m = re.match(r"case_(\d+)_", name)
        if state == GREEN and m and m.group(1) in OPEN_ISSUES:
            claims.append(f"{name} is GREEN but #{m.group(1)} stays open: {OPEN_ISSUES[m.group(1)]}")
    return claims


def probe_wiring_problems(source, needles, replay, no_standin, manifest):
    """#7988 ratchet over this file's own text: every generator_file(rel, why) call names a
    probe that has a pre-fix replay, or is listed as having none and then must stay RED; no
    probe is unreferenced, and a case whose probe cannot be replayed cannot be GREEN."""
    tree = ast.parse(source)
    problems, called = [], {}
    for fn in ast.walk(tree):
        if not isinstance(fn, ast.FunctionDef):
            continue
        for node in ast.walk(fn):
            if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                    and node.func.attr == "generator_file" and len(node.args) == 2
                    and all(isinstance(a, ast.Constant) and isinstance(a.value, str) for a in node.args)):
                called[(node.args[0].value, node.args[1].value)] = fn.name
    for key, case in sorted(called.items(), key=lambda kv: kv[1]):
        if key not in needles:
            problems.append(f"{case}: no GENERATOR_NEEDLES entry for {key[0]}")
        if key in replay:
            continue
        if key not in no_standin:
            problems.append(f"{case}: probe for {key[0]} has no PREFIX_REPLAY stand-in and no recorded reason")
        elif manifest.get(case) != RED:
            problems.append(f"{case}: probe for {key[0]} was never replayed against a pre-fix file, so the case must stay RED")
    for key in needles:
        if key not in called:
            problems.append(f"GENERATOR_NEEDLES entry {key[0]} is used by no case")
    return problems


def workflow_text_problems(fn, labels=None):
    """Behavioural probe of the workflow-text check: plain text passes, every named
    non-printable-ASCII byte is refused (truthy return or ValueError/GateError)."""
    def flags(text):
        try:
            return bool(fn(text))
        except (ValueError, GateError):
            return True
    problems = []
    if flags(PLAIN_WORKFLOW):
        problems.append("plain printable-ASCII LF text was refused")
    for label, ch in WORKFLOW_BAD:
        if (labels is None or label in labels) and not flags(f"name: x\n# a{ch}b\nrun: 'true'\n"):
            problems.append(f"{label} was accepted")
    return problems


def log_safe_problems(fn, aspects=None):
    """Behavioural probe of log_safe: printable-ASCII output, changed input escaped,
    no interpreter-table dependence, backslash doubling and one-to-one output."""
    def printable(text):
        return isinstance(text, str) and all(0x20 <= ord(c) <= 0x7E for c in text)
    problems = []
    for aspect, samples in LOG_SAFE_SAMPLES.items():
        if aspects is not None and aspect not in aspects:
            continue
        for sample in samples:
            out = fn(sample)
            if not printable(out) or out == sample:
                problems.append(f"{aspect}: {sample!r} printed as {out!r}")
        if aspect == "unassigned":
            try:
                if "unicodedata" in inspect.getsource(fn):
                    problems.append("unassigned: escaping depends on unicodedata tables")
            except (OSError, TypeError) as exc:
                problems.append(f"unassigned: the escaper source cannot be read to check unicodedata use ({type(exc).__name__})")
    if aspects is None or "backslash" in aspects:
        if fn("a\\b") != "a\\\\b":
            problems.append("backslash is not doubled")
        outs = [fn(x) for x in LOG_SAFE_ONE_TO_ONE]
        if len(set(outs)) != len(outs) or not all(printable(o) for o in outs):
            problems.append("escaping is not one-to-one printable ASCII")
    return problems


def trusted_copy_problems(text):
    """#6140: pull_request_target is configured and the cert-expiry-gate job runs a copy
    taken from the base ref, not the pull request's own."""
    lines = [YAML_COMMENT_RE.sub("", ln) for ln in text.splitlines()]
    if "pull_request_target" not in "\n".join(lines):
        return ["pull_request_target is not configured"]
    marks = [i for i, ln in enumerate(lines) if ln.strip() == f"name: {GATE_JOB_NAME}"]
    if not marks:
        return [f"no job named {GATE_JOB_NAME}"]
    start = marks[0]
    while start > 0 and not JOB_HEADER_RE.match(lines[start]):
        start -= 1
    end = marks[0] + 1
    while end < len(lines) and not JOB_HEADER_RE.match(lines[end]):
        end += 1
    if not BASE_TRUST_RE.search("\n".join(lines[start:end])):
        return [f"{GATE_JOB_NAME} does not take its gate copy from the base ref"]
    return []


def named_test_with_assert(text, fragments, *tokens):
    """True when a test function whose name holds every fragment mentions every token
    in its body and asserts something."""
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return False
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name.startswith("test") \
                and all(f in node.name for f in fragments):
            body = ast.get_source_segment(text, node) or ""
            asserts = any(isinstance(n, ast.Assert) or (isinstance(n, ast.Call) and
                          getattr(n.func, "attr", "").startswith("assert")) for n in ast.walk(node))
            if asserts and all(t in body for t in tokens):
                return True
    return False


def rebind_problems(test_text):
    if named_test_with_assert(test_text, ("rebind",), "ENV_SHA_RE"):
        return []
    return ["no rebind test that asserts on ENV_SHA_RE"]


def sidecar_problems(rust_text):
    code = code_lines(rust_text, "//")
    problems = []
    if "mem::forget" in code:
        problems.append("mem::forget leaks the test database")
    if "remove_file" not in code or not ("-wal" in code or "-shm" in code):
        problems.append("no removal of the -wal/-shm sidecars")
    return problems


def ladder_problems(script_text, test_text):
    problems = []
    if "ladder" not in code_lines(script_text, "#"):
        problems.append("the recapture script does not mention the ladder")
    if not named_test_with_assert(test_text, ("ladder",)):
        problems.append("no ladder test that asserts")
    return problems


class Corpus(CorpusBase):
    def need(self, obj, name, why):
        self.assertTrue(hasattr(obj, name), f"{name} is absent from the gate: {why}")
        return getattr(obj, name)

    def dead_id_rejected(self, body):
        """A patch that keeps the id named once yet makes it dead must be rejected."""
        text = DEAD_ID_SOURCE.format(id=LIVE_ID, body=body)
        ok, out, _s, _head = self.gate_over({"src/config.rs": text})
        self.assertFalse(ok, "the gate PASSED a patch that makes " + LIVE_ID +
                         f" dead while it stays named once: {out[:200]}")

    def generator_file(self, rel, why):
        problems = generator_problems(HARNESS_ROOT, rel, GENERATOR_NEEDLES[(rel, why)])
        self.assertEqual(problems, [], f"{GEN_DIR}/{rel}: {why}: " + "; ".join(problems))

    # ---- the four members this batch fixes (expected GREEN) ----------------

    @expect(GREEN)
    def case_6977_banner_read_error(self):
        s = self.scene()
        s.fx.write(MOD_RS, "// wire change\n", append=True)
        s.fx.write(CERT_DOC, "prose only, no banner change\n", append=True)
        head = s.fx.commit([MOD_RS, CERT_DOC], "wire change with a prose-only cert-doc edit")
        blob = s.fx.g("rev-parse", f"{s.base}:{CERT_DOC}")
        loose = s.repo / ".git" / "objects" / blob[:2] / blob[2:]
        self.assertTrue(loose.exists(), "the base cert-doc blob is not a loose object")
        loose.unlink()
        with self.assertRaises(GateError):
            cert_banner(s.repo, s.base)
        ok, out = check_change(s.repo, s.base, head)
        self.assertFalse(ok, f"a read error produced a clean verdict: {out[:200]}")
        self.assertNotIn("cert doc re-issued/voided", out)
        env = {"CERT_EXPIRY_BASE": s.base, "CERT_EXPIRY_HEAD": head,
               "PATH": os.environ.get("PATH", "")}
        rc, _o, err = run_gate(s.repo, env)
        self.assertEqual(rc, 1, f"the gate did not fail closed: {err[:200]}")

    @expect(GREEN)
    def case_6174_attr_hides_drift(self):
        s = self.scene()
        s.fx.write(".gitattributes", "src/hidden.rs binary\n")
        s.fx.write("src/hidden.rs", 'pub const H: &str = "AI_MEMORY_FED_HIDDEN_KNOB";\n')
        head = s.fx.commit([".gitattributes", "src/hidden.rs"],
                           "a new FED id in a file the head's attributes mark binary")
        ok, out = check_change(s.repo, s.base, head)
        self.assertFalse(ok, f"a head's .gitattributes hid a new FED id: {out[:200]}")
        self.assertIn("AI_MEMORY_FED_HIDDEN_KNOB", out)

    @expect(GREEN)
    def case_6445_cell_isolation(self):
        """#6445: the cells pass in reverse order, so none leans on a repository an earlier one built."""
        src = GATE_PATH.read_text(encoding="utf-8")
        for needle in ("class Fixture", "def _self_test"):
            self.assertNotIn(needle, src, f"the gate still carries its linear corpus ({needle})")
        first, second = self.scene("one"), self.scene("two")
        self.assertNotEqual(first.repo, second.repo)
        self.assertNotEqual(first.base, "")
        cells = sorted(n for n in dir(Cells) if n.startswith("cell_") and
                       not n.startswith(("cell_shim", "cell_path", "cell_checkout",
                                         "cell_guarded", "cell_o_")))
        suite = unittest.TestSuite(Cells(n) for n in reversed(cells))
        result = unittest.TestResult()
        suite.run(result)
        problems = [str(t) for t, _ in result.failures + result.errors]
        self.assertEqual(problems, [], f"cells depend on run order: {problems}")
        self.assertEqual(result.testsRun, len(cells))

    @spawning
    @expect(GREEN)
    def case_6445_base_nameerror(self):
        copy = self.tmp / "copy"
        (copy / "scripts" / "ci" / "tests").mkdir(parents=True)
        text = GATE_PATH.read_text(encoding="utf-8")
        self.assertIn("def cert_banner(", text)
        (copy / "scripts" / "check_cert_expiry.py").write_text(
            text.replace("def cert_banner(", "def cert_banner_missing(", 1), encoding="utf-8")
        shutil.copy(str(Path(__file__).resolve()),
                    str(copy / "scripts" / "ci" / "tests" / Path(__file__).name))
        (copy / "scripts" / "qc-allowlists").mkdir(parents=True)
        env = dict(os.environ)
        proc = subprocess.run(
            [sys.executable, "-I", str(copy / "scripts" / "check_cert_expiry.py"), "--self-test-subset", "cell_a_,cell_b_"],
            cwd=str(copy), env=env, capture_output=True, text=True, timeout=CHILD_TIMEOUT_S)
        out = proc.stdout + proc.stderr
        self.assertEqual(proc.returncode, SELF_TEST_FAIL_RC, out[-600:])
        self.assertNotIn("Traceback", out, "a missing production helper crashed the runner")
        self.assertIn("self-test FAILED", out)

    def stub_gate_tree(self, stub_body):
        """A scratch tree holding the real gate and a stub corpus harness."""
        self.stub_count = getattr(self, "stub_count", 0) + 1
        copy = self.tmp / f"stub{self.stub_count}"
        (copy / "scripts" / "ci" / "tests").mkdir(parents=True)
        shutil.copy(str(GATE_PATH), str(copy / "scripts" / "check_cert_expiry.py"))
        (copy / "scripts" / "ci" / "tests" / Path(__file__).name).write_text(stub_body, encoding="utf-8")
        return copy

    def run_stub_self_test(self, copy, extra_args=(), **env_extra):
        env = dict(os.environ, **env_extra)
        proc = subprocess.run(
            [sys.executable, "-I", str(copy / "scripts" / "check_cert_expiry.py"), "--self-test", *extra_args],
            cwd=str(copy), env=env, capture_output=True, text=True, timeout=CHILD_TIMEOUT_S)
        return proc.returncode, proc.stdout + proc.stderr

    @expect(GREEN)
    def case_7975_selftest_fail_closed(self):
        env_aware = ("import os\n"
                     "ran = 0 if os.environ.get('CERT_CORPUS_FILTER') or os.environ.get('CERT_CORPUS_NESTED') else 1000\n"
                     "print('CORPUS-SUMMARY ran=%d failed=0' % ran)\n")
        rc, out = self.run_stub_self_test(self.stub_gate_tree(env_aware),
                                          CERT_CORPUS_FILTER="zzz_nothing", CERT_CORPUS_NESTED="1")
        self.assertEqual(rc, 0, "an inherited CERT_CORPUS_* knob changed the self-test: " + out[-300:])
        self.assertIn("ran=1000", out, "the self-test ran with the inherited filter")
        zero = "print('CORPUS-SUMMARY ran=0 failed=0')\n"
        rc, out = self.run_stub_self_test(self.stub_gate_tree(zero))
        self.assertEqual(rc, SELF_TEST_FAIL_RC, "a corpus that ran zero cases reported OK: " + out[-300:])
        self.assertIn("self-test FAILED", out)
        few = "print('CORPUS-SUMMARY ran=3 failed=0')\n"
        rc, out = self.run_stub_self_test(self.stub_gate_tree(few))
        self.assertEqual(rc, SELF_TEST_FAIL_RC, "a corpus below the expected size reported OK: " + out[-300:])
        rc, out = self.run_stub_self_test(self.stub_gate_tree(few), extra_args=("--self-test-subset", "cell_a_"))
        self.assertEqual(rc, 0, "an explicit subset run needs only one case: " + out[-300:])

    @expect(GREEN)
    def case_7977_probe_mutants(self):
        """#7977: a RED probe must check the issue acceptance, not that a name exists.
        Empty, comment-only and unparsable stand-ins must keep every probe failing."""
        root = self.tmp / "mutroot"
        for rel in (Path(LIVENESS_TEST).parent, Path(GEN_DIR), Path(GEN_DIR) / ".." / "ci" / "tests",
                    Path(WORKFLOW).parent):
            (root / rel).mkdir(parents=True, exist_ok=True)
        live = root / LIVENESS_TEST
        for body in ("", "// cert_fed_identifier_liveness AI_MEMORY_FED_REQUIRE_SIG\n" * 30):
            live.write_text(body, encoding="utf-8")
            self.assertTrue(liveness_problems(root), "a stand-in liveness test satisfied #6911")
        (root / WORKFLOW).write_text("run: cargo test --test cert_fed_identifier_liveness\n", encoding="utf-8")
        live.write_text("#[test]\nfn documented_id_is_live() {\n    let _ = \"" + LIVE_ID + "\";\n}\n", encoding="utf-8")
        self.assertTrue(liveness_problems(root), "a vacuous test that only names the id passed #6911")
        live.write_text("#[test]\nfn documented_id_is_live() {\n    let _ = \"" + LIVE_ID + "\";\n    assert!(true);\n}\n",
                        encoding="utf-8")
        self.assertTrue(liveness_problems(root), "assert!(true) beside a bare mention passed #6911")
        live.write_text("#[test]\nfn documented_id_is_live() {\n    assert!(SRC.contains(\"" + LIVE_ID + "\"));\n}\n",
                        encoding="utf-8")
        self.assertEqual(liveness_problems(root), [])
        live.write_text("", encoding="utf-8")
        self.assertTrue(liveness_problems(root), "an empty liveness test passed with the workflow wired")
        self.assertGreaterEqual(len(GENERATOR_NEEDLES), 36)
        for (rel, _why), needles in GENERATOR_NEEDLES.items():
            target = root / GEN_DIR / rel
            for body in ("", "# " + " ".join(needles) + "\n" * 3, "def broken(:\n" + " ".join(needles)):
                target.write_text(body, encoding="utf-8")
                self.assertTrue(generator_problems(root, rel, needles),
                                f"a stand-in {rel} satisfied its probe: {body[:30]!r}")
        identity = lambda text: text
        self.assertTrue(log_safe_problems(identity), "an identity log_safe passed the escaping probes")
        self.assertTrue(workflow_text_problems(lambda text: None), "a workflow check that accepts everything passed")
        self.assertTrue(workflow_text_problems(lambda text: "bad"), "a workflow check that rejects everything passed")
        self.assertTrue(trusted_copy_problems("on:\n  pull_request_target:  # not used\njobs: {}\n"))
        self.assertTrue(rebind_problems("# rebind\n"))
        self.assertTrue(sidecar_problems("std::mem::forget(tmp);\n"))
        self.assertTrue(ladder_problems("ladder\n", "# ladder\n"))

    @expect(GREEN)
    def case_7989_unreadable_escaper_source(self):
        """#7989: log_safe_problems must not wave an escaper whose source it cannot read. An escaper
        built with exec has no source (OSError) and a builtin has none (TypeError); both are reported."""
        scope = {}
        exec("def esc(text):\n    import unicodedata\n    return ''.join(c if 0x20 <= ord(c) <= 0x7e else chr(92) + 'u%04x' % ord(c) for c in text)\n", scope)
        for fn in (scope["esc"], repr):
            problems = log_safe_problems(fn, ("unassigned",))
            self.assertTrue(any("source" in p and "cannot be read" in p for p in problems),
                            f"an escaper with no readable source passed the unicodedata check: {problems}")

    @expect(GREEN)
    def case_7988_prefix_replay(self):
        """#7988: every RED probe is replayed against the real pre-fix file of its fix commit
        (it must fail there) and against the fixed ref (it must pass), so no probe is a token that
        an unfixed generator also carries. An unreadable object fails the case; the CI step that
        runs this fetches them with --print-replay-shas."""
        lines, wrong, unreadable = prefix_replay_report(HARNESS_ROOT, self.tmp)
        print("\n".join(lines), file=sys.stderr)
        self.assertEqual(unreadable, [], "replay objects are missing from this checkout: " + "; ".join(unreadable))
        self.assertEqual(wrong, [], "probes that do not discriminate: " + "; ".join(wrong))
        self.assertGreaterEqual(len(lines), 2 * len(PREFIX_REPLAY))

    # ---- section 7 evasions: the per-file multiset and the funnel (P1, P3) --

    def base_with_second_mention(self):
        s = self.scene()
        s.edit("src/doc_mention.rs", f'// mentions {LIVE_ID}\n', "an unwatched second mention")
        return s, s.fx.g("rev-parse", "HEAD")

    @expect(RED, "section 7 reads a set difference: an id still named elsewhere is never reported removed")
    def case_6370_removed_id_named_elsewhere(self):
        s, base2 = self.base_with_second_mention()
        s.fx.write("src/config.rs", "pub const X: &str = \"\";\n")
        head = s.fx.commit(["src/config.rs"], "remove the definition, the id stays named elsewhere")
        ok, out = check_change(s.repo, base2, head)
        self.assertFalse(ok, f"removing the live definition passed: {out[:200]}")

    @expect(RED, "the occurrence count can be offset: one mention removed, one added elsewhere")
    def case_6427_offset_count(self):
        s, base2 = self.base_with_second_mention()
        s.fx.write("src/doc_mention.rs", "// no mention\n")
        s.fx.write("src/third.rs", f'// mentions {LIVE_ID}\n')
        head = s.fx.commit(["src/doc_mention.rs", "src/third.rs"], "move a mention between files")
        ok, out = check_change(s.repo, base2, head)
        self.assertFalse(ok, f"a per-file mention count change passed: {out[:200]}")

    @expect(RED, "a new FED definition for a name already mentioned is not reported as added")
    def case_6442_new_def_known_name(self):
        s, base2 = self.base_with_second_mention()
        s.fx.write("src/extra.rs", f'pub const Z: &str = "{LIVE_ID}";\n')
        head = s.fx.commit(["src/extra.rs"], "a second definition of a known id")
        ok, out = check_change(s.repo, base2, head)
        self.assertFalse(ok, f"a new definition of an already-named id passed: {out[:200]}")

    @expect(RED, "the compiled-liveness test tests/cert_fed_identifier_liveness.rs does not exist (#6911)")
    def case_6911_closed_denominator(self):
        problems = liveness_problems(HARNESS_ROOT)
        self.assertEqual(problems, [], "one behavioural test per documented FED id: " + "; ".join(problems))

    # ---- gate integrity, log_safe, docs ------------------------------------

    @expect(RED, "the gate runs the pull request's own copy: no base-ref (pull_request_target) trusted copy")
    def case_6140_pr_edits_gate_copy(self):
        self.assertEqual(trusted_copy_problems(repo_text(WORKFLOW)), [])

    @expect(RED, "the compliance standard and ballot docs still name the deleted check-cert-expiry.sh")
    def case_6141_docs_name_deleted_sh(self):
        named = [d for d in (DOC_BALLOT, DOC_STANDARD, DOC_ENTERPRISE)
                 if DELETED_GATE_SH in repo_text(d)]
        self.assertEqual(named, [], f"docs name the deleted {DELETED_GATE_SH}")

    @expect(RED, "no printable-ASCII/LF-only check for c8-precheck.yml (I3): YAML CR NEL LS PS breaks")
    def case_6228_yaml_nel_ls_ps_break(self):
        fn = self.need(cert, "workflow_text_violation", "refuse any workflow byte outside printable ASCII and LF")
        self.assertEqual(workflow_text_problems(fn, ("CR", "NEL", "LS", "PS")), [])

    @expect(RED, "no printable-ASCII/LF-only check for c8-precheck.yml (I3): Unicode whitespace")
    def case_6304_unicode_ws_comment(self):
        fn = self.need(cert, "workflow_text_violation", "refuse any workflow byte outside printable ASCII and LF")
        self.assertEqual(workflow_text_problems(fn, ("NBSP", "EM SPACE", "IDEOGRAPHIC SPACE", "ZWSP")), [])

    @expect(RED, "log_safe is not on the chain tip (6140 branch only); allow-list escaping (I4) absent")
    def case_6683_bidi_zero_width(self):
        fn = self.need(cert, "log_safe", "bidi and zero-width characters must print escaped")
        self.assertEqual(log_safe_problems(fn, ("bidi",)), [])

    @expect(RED, "log_safe is not on the chain tip; default-ignorable code points must print escaped")
    def case_6917_default_ignorable(self):
        fn = self.need(cert, "log_safe", "default-ignorable non-Cf code points must print escaped")
        self.assertEqual(log_safe_problems(fn, ("ignorable",)), [])

    @expect(RED, "log_safe is not on the chain tip; escaping must not depend on interpreter tables")
    def case_6918_unassigned_cn(self):
        fn = self.need(cert, "log_safe", "an allow-list of 0x20-0x7E, everything else escaped")
        self.assertEqual(log_safe_problems(fn, ("unassigned",)), [])

    @expect(RED, "log_safe is not on the chain tip; backslash doubling and one-to-one escaping unpinned")
    def case_6921_backslash_one_to_one(self):
        fn = self.need(cert, "log_safe", "a printed name must be reversible")
        self.assertEqual(log_safe_problems(fn, ("backslash",)), [])

    @expect(RED, "test_codeql_6163.py pins ENV_SHA_RE by name only: no pin against a rebinding")
    def case_6882_env_sha_rebind(self):
        self.assertEqual(rebind_problems(repo_text("scripts/ci/tests/test_codeql_6163.py")), [])

    # ---- the 6560 lexer-evasion family: Rust patches that make the id dead --

    @expect(RED, REASON_LEXER)
    def case_6838_rust_ws_class(self):
        self.dead_id_rejected('fn read() {\n    return;\u0085 let _ = std::env::var("' + LIVE_ID + '");\n}')

    @expect(RED, REASON_LEXER)
    def case_6839_module_shebang(self):
        text = "#!/usr/bin/env " + LIVE_ID + "\nfn main() {}\n"
        ok, out, _s, _h = self.gate_over({"src/config.rs": text})
        self.assertFalse(ok, f"a shebang-only mention passed as a live id: {out[:200]}")

    @expect(RED, REASON_LEXER)
    def case_6840_use_as_rebind(self):
        self.dead_id_rejected('use core::prelude::v1::cfg as live;\n#[live(any())]\n'
                              'fn read() { let _ = std::env::var("' + LIVE_ID + '"); }')

    @expect(RED, REASON_LEXER)
    def case_6841_raw_ident_macro(self):
        self.dead_id_rejected('fn read() { r#assert!(false); let _ = std::env::var("' + LIVE_ID + '"); }')

    @expect(RED, REASON_LEXER)
    def case_6842_expr_return_break(self):
        self.dead_id_rejected('fn read() -> u8 { let v = return 0; let _ = std::env::var("' + LIVE_ID + '"); 1 }')

    @expect(RED, REASON_LEXER)
    def case_6843_diverging_std_fn(self):
        self.dead_id_rejected('fn read() { std::panic::panic_any(1); let _ = std::env::var("' + LIVE_ID + '"); }')

    @expect(RED, REASON_LEXER)
    def case_6844_match_guard_if_false(self):
        self.dead_id_rejected('fn read(x: u8) { match x { 1 if false => { let _ = std::env::var("'
                              + LIVE_ID + '"); } _ => {} } }')

    @expect(RED, REASON_LEXER)
    def case_6944_assert_false_msg(self):
        self.dead_id_rejected('fn read() { assert!(false, "stop"); let _ = std::env::var("' + LIVE_ID + '"); }')

    @expect(RED, REASON_LEXER)
    def case_6970_assert_bracket_brace(self):
        self.dead_id_rejected('fn read() { assert![false]; let _ = std::env::var("' + LIVE_ID + '"); }')

    @expect(RED, REASON_LEXER)
    def case_6971_block_expr_exit(self):
        self.dead_id_rejected('fn read() { let _ = { return; }; let _ = std::env::var("' + LIVE_ID + '"); }')

    @expect(RED, REASON_LEXER)
    def case_6972_raw_else_header(self):
        self.dead_id_rejected('fn read() { if false { let _ = std::env::var("' + LIVE_ID + '"); } /* r#else */ }')

    @expect(RED, REASON_LEXER)
    def case_6973_assert_folded_false(self):
        self.dead_id_rejected('fn read(x: bool) { assert!((false)); assert!(!!false); '
                              'assert!(false && x); assert!(cfg!(any())); '
                              'let _ = std::env::var("' + LIVE_ID + '"); }')

    @expect(RED, REASON_LEXER)
    def case_6974_iife_panic_closure(self):
        self.dead_id_rejected('fn read() { (|| panic!("stop"))(); let _ = std::env::var("' + LIVE_ID + '"); }')

    @expect(RED, REASON_LEXER)
    def case_6985_exit_turbofish(self):
        self.dead_id_rejected('fn read() { std::process::exit::<>(1); let _ = std::env::var("' + LIVE_ID + '"); }')

    @expect(RED, REASON_LEXER)
    def case_6986_assert_eq_literals(self):
        self.dead_id_rejected('fn read() { assert_eq!(1, 2); let _ = std::env::var("' + LIVE_ID + '"); }')

    @expect(RED, REASON_LEXER)
    def case_6987_labelled_block_let_else(self):
        self.dead_id_rejected("fn read() { 'a: { break 'a; } let Some(_) = None::<u8> else { return }; "
                              'let _ = std::env::var("' + LIVE_ID + '"); }')

    @expect(RED, REASON_LEXER)
    def case_6988_err_question_none_unwrap(self):
        self.dead_id_rejected('fn read() -> Result<(), ()> { Err::<(), ()>(())?; None::<u8>.unwrap(); '
                              'let _ = std::env::var("' + LIVE_ID + '"); Ok(()) }')

    # ---- sub-class B: the vendored cert generator (draft PR 7393) -----------

    @expect(RED, "the cert procedure, T4 and the fixture byte-identity test are on PR 7393 only")
    def case_7392_procedure_cites_commit(self):
        self.generator_file("../ci/tests/test_evidence_fixture_identity.py",
                            "the fixture byte-identity test the cert procedure cites")

    @expect(RED, REASON_GENERATOR)
    def case_7399_recapture_py_lookup(self):
        self.generator_file("build_bundle.py", "recapture lookup must find the .py")

    @expect(RED, REASON_GENERATOR)
    def case_7411_untracked_runs_as_tip(self):
        self.generator_file("run_cert.py", "scripts picked from the tip tree, never the worktree")

    @expect(RED, REASON_GENERATOR)
    def case_7412_outdir_unescaped(self):
        self.generator_file("run_cert.py", "the output dir must be quoted in generated bash")

    @expect(RED, REASON_GENERATOR)
    def case_7413_cert_env_unvalidated(self):
        self.generator_file("run_cert.py", "CERT_ env overrides validated and logged")

    @expect(GREEN)
    def case_7416_passphrase_argv(self):
        gone = HARNESS_ROOT / "scripts" / "recapture-cert-3607-posture.sh"
        self.assertFalse(gone.exists(), "the .sh form still exists")
        text = repo_text(RECAPTURE_PY)
        self.assertNotIn("--passphrase", text)
        self.assertIn("AI_MEMORY_DB_PASSPHRASE", text, "the passphrase is no longer read from the environment")

    @expect(RED, REASON_GENERATOR)
    def case_7417_prep_hash_qualified(self):
        self.generator_file("prep.py", "commit-1 bytes hash-qualified, docstring true")

    @expect(RED, REASON_GENERATOR)
    def case_7419_crashed_run_after_done(self):
        self.generator_file("build_bundle.py", "check_run rejects a later crashed chain run")

    @expect(RED, REASON_GENERATOR)
    def case_7420_missing_wrapper_red(self):
        self.generator_file("run_cert.py", "a missing wrapper writes a RED and an EXIT row")

    @expect(RED, REASON_GENERATOR)
    def case_7421_relative_targets_cwd(self):
        self.generator_file("run_cert.py", "relative CERT_TARGETS and CERT_TMPDIR refused or resolved")

    @expect(RED, REASON_GENERATOR)
    def case_7422_push_fail_exit(self):
        self.generator_file("run_cert.py", "a failed cert commit push fails the gates leg")

    @expect(RED, REASON_GENERATOR)
    def case_7423_prep_grep_error(self):
        self.generator_file("prep.py", "a git grep error is an error, never an empty FED id set")

    @expect(RED, REASON_GENERATOR)
    def case_7425_ionice_recorded(self):
        self.generator_file("run_cert.py", "cert-alone.out records ionice only when it was used")

    @expect(RED, REASON_GENERATOR)
    def case_7439_lookalike_symlink_skipwt(self):
        self.generator_file("run_cert.py", "pick_expiry refuses look-alike, symlink and skip-worktree copies")

    @expect(RED, REASON_GENERATOR)
    def case_7440_tmpfs_outdir(self):
        self.generator_file("run_cert.py", "an output dir on tmpfs or under a tmp root is refused")

    @expect(RED, REASON_GENERATOR)
    def case_7441_wrapper_validated_config_row(self):
        self.generator_file("run_cert.py", "wrapper, flock and timeout validated; CONFIG row names the source")

    @expect(RED, REASON_GENERATOR)
    def case_7442_mount_octal_escape(self):
        self.generator_file("run_cert.py", "is_tmpfs_path decodes proc-mounts octal escapes")

    @expect(RED, REASON_GENERATOR)
    def case_7443_empty_fed_set(self):
        self.generator_file("prep.py", "an empty FED id set at either end is an error")

    @expect(RED, REASON_GENERATOR)
    def case_7446_docstring_exit64(self):
        self.generator_file("run_cert.py", "the docstring states ionice conditionally and exit 64")

    @expect(RED, REASON_GENERATOR)
    def case_7486_plans_gates_entry(self):
        self.generator_file("run_cert.py", "PLANS has a gates entry")

    @expect(RED, REASON_GENERATOR)
    def case_7489_copy_symlink_delete(self):
        self.generator_file("run_cert.py", "the expiry gate copy never follows a symlink")

    @expect(RED, REASON_GENERATOR)
    def case_7490_preflight_exit_row(self):
        self.generator_file("run_cert.py", "the preflight EXIT row says 64 where the exit is 64")

    @expect(RED, REASON_GENERATOR)
    def case_7492_tests_poison_tmp(self):
        self.generator_file("../ci/tests/test_evidence_generator_r3_7393.py", "tests write under the scratch root only")

    @expect(RED, REASON_GENERATOR)
    def case_7530_copy_oserror_row(self):
        self.generator_file("run_cert.py", "an OSError creating the gate copy writes an EXIT row")

    @expect(RED, REASON_GENERATOR)
    def case_7531_copy_repo_root(self):
        self.generator_file("run_cert.py", "a relocated gate copy resolves its repo root to the checkout")

    @expect(RED, REASON_GENERATOR)
    def case_7532_killed_run_cleanup_flags(self):
        self.generator_file("run_cert.py", "O_EXCL and O_NOFOLLOW pinned; a killed run is swept")

    @expect(RED, REASON_GENERATOR)
    def case_7534_tmp_root_spellings(self):
        self.generator_file("../ci/tests/test_evidence_generator_r2_7393.py", "the tmp-root guard covers every spelling")

    @expect(RED, REASON_GENERATOR)
    def case_7535_ignored_leg_flags(self):
        self.generator_file("run_cert.py", "push-branch and parent refused on legs that ignore them")

    @expect(RED, REASON_GENERATOR)
    def case_7581_copy_isolated_mode(self):
        self.generator_file("run_cert.py", "the gate copy runs under python3 -I")

    @expect(RED, REASON_GENERATOR)
    def case_7582_sweep_after_fd_open(self):
        self.generator_file("run_cert.py", "the sweep goes through the directory fd")

    @expect(RED, REASON_GENERATOR)
    def case_7583_ast_guard_tempfile_join(self):
        self.generator_file("../ci/tests/test_evidence_generator_r6_7393.py", "the AST guard checks tempfile and folds join")

    @expect(RED, REASON_GENERATOR)
    def case_7584_posture_oserror_pin(self):
        self.generator_file("../ci/tests/test_evidence_generator_r6_7393.py", "the posture OSError widening is pinned")

    @expect(RED, REASON_GENERATOR)
    def case_7585_realpath_pin(self):
        self.generator_file("../ci/tests/test_evidence_generator_r6_7393.py", "the realpath comparison is pinned")

    @expect(RED, REASON_GENERATOR)
    def case_7617_posture_copy_symlink(self):
        self.generator_file("run_cert.py", "the posture copy is never written through a symlink")

    @expect(RED, REASON_GENERATOR)
    def case_7618_check_to_exec_window(self):
        self.generator_file("run_cert.py", "the gate copy has no check-to-exec window")

    @expect(RED, REASON_GENERATOR)
    def case_7620_deep_stale_sweep(self):
        self.generator_file("run_cert.py", "a deeply nested stale dir does not crash the gates leg")

    @expect(RED, REASON_GENERATOR)
    def case_7665_cwd_stdlib_shadow(self):
        self.generator_file("run_cert.py", "repo gate scripts run with an empty cwd")

    # ---- sub-class C: keyword strays ----------------------------------------

    @expect(RED, "the 3607 posture ladder is recorded but no test or script step asserts it")
    def case_5036_ladder_asserted(self):
        problems = ladder_problems(repo_text(RECAPTURE_PY),
                                   repo_text("scripts/ci/tests/test_recapture_cert_3607_5038.py"))
        self.assertEqual(problems, [])

    @expect(RED, "check-required-contexts.sh accepts two jobs that report the same required context")
    def case_6177_duplicate_required_context(self):
        wf = self.tmp / "workflows"
        shutil.copytree(str(HARNESS_ROOT / ".github" / "workflows"), str(wf))
        target = wf / "c8-precheck.yml"
        text = target.read_text(encoding="utf-8")
        marker = "\n  foreign-text-to-caller-gate:\n"
        self.assertIn(marker, text)
        dup = "\n  second-reporting-job:\n    name: cert-expiry-gate\n    runs-on: ubuntu-latest\n    steps:\n      - run: 'true'\n"
        target.write_text(text.replace(marker, dup + marker, 1), encoding="utf-8")
        env = dict(os.environ, RQC_WORKFLOW_DIR=str(wf))
        proc = subprocess.run(["bash", str(HARNESS_ROOT / REQUIRED_CONTEXTS_SH)], cwd=str(HARNESS_ROOT),
                              env=env, capture_output=True, text=True, timeout=WORKFLOW_COPY_TIMEOUT_S)
        self.assertNotEqual(proc.returncode, 0, "two jobs reporting one required context passed")
        self.assertRegex(proc.stdout + proc.stderr, r"(?i)duplicate|twice|more than one job|reported by (two|2)")

    @expect(RED, "federation_signing_check.rs still leaks the sqlite sidecars of its test database")
    def case_7793_sidecar_clean_rebind(self):
        self.assertEqual(sidecar_problems(repo_text(SIGNING_CHECK_RS)), [])


# ---------------------------------------------------------------------------
# Loader and entry point
# ---------------------------------------------------------------------------

def read_manifest(path):
    """{name: verdict} from the committed manifest file; '#' lines and blanks skipped."""
    out = {}
    for raw in Path(path).read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        fields = line.split()
        if len(fields) != 2 or fields[1] not in (GREEN, RED):
            raise ValueError(f"malformed manifest line: {raw!r}")
        if fields[0] in out:
            raise ValueError(f"duplicate manifest entry: {fields[0]}")
        out[fields[0]] = fields[1]
    return out


def ratchet_problems(committed, current):
    """The V6 ratchet. Problems (empty = ok) between the committed manifest and the
    corpus: a committed name missing from the corpus (deleted), a committed GREEN
    that the corpus now registers RED (weakened), a RED/GREEN change that the
    committed file does not record, and a corpus name the committed file lacks."""
    problems = []
    for name in sorted(committed):
        if name not in current:
            problems.append(f"{name}: deleted from the corpus (the manifest never shrinks)")
        elif committed[name] == GREEN and current[name] == RED:
            problems.append(f"{name}: flipped GREEN -> RED (a passing case is never weakened)")
        elif committed[name] != current[name]:
            problems.append(f"{name}: now {current[name]}, manifest records {committed[name]}")
    for name in sorted(set(current) - set(committed)):
        problems.append(f"{name}: new case not recorded in the manifest")
    return problems


BASE_REF_ENV = "CERT_MANIFEST_BASE_REF"  # explicit base ref for the anchored ratchet
GITHUB_BASE_ENV = "GITHUB_BASE_REF"  # the pull-request base branch CI provides
DEFAULT_BASE_REFS = ("origin/chain/promo6-ssh-r2", "origin/release/v1.0.0")
GIT_QUERY_TIMEOUT_S = 60


def base_ref_candidates(environ):
    """Refs to try for the merge-base manifest, most specific first."""
    refs = []
    if environ.get(BASE_REF_ENV):
        refs.append(environ[BASE_REF_ENV])
    if environ.get(GITHUB_BASE_ENV):
        refs.append("origin/" + environ[GITHUB_BASE_ENV])
    refs.extend(DEFAULT_BASE_REFS)
    return refs


CANONICAL_MANIFEST_PATH = "scripts/qc-allowlists/cert-expiry-corpus-manifest.txt"  # where the base tree is read
CANONICAL_HARNESS_PATH = "scripts/ci/tests/test_check_cert_expiry_corpus.py"
ALLOW_INTREE_ENV = "CERT_MANIFEST_ALLOW_INTREE"  # explicit opt-in to the weaker in-tree-only ratchet
BASE_OK, BASE_NONE, BASE_ABSENT, BASE_ERROR = "ok", "no-ref", "absent", "error"


def git_query(repo, argv):
    """(returncode, stdout) of one git query in `repo`; a launch failure is (127, message)."""
    try:
        r = subprocess.run(["git"] + argv, cwd=str(repo), capture_output=True, text=True,
                           timeout=GIT_QUERY_TIMEOUT_S)
    except (OSError, subprocess.SubprocessError) as e:
        return 127, f"{type(e).__name__}: {e}"
    return r.returncode, r.stdout if r.returncode == 0 else (r.stderr or r.stdout)


def parse_manifest_text(text):
    out = {}
    for raw in text.splitlines():
        line = raw.strip()
        if line and not line.startswith("#"):
            fields = line.split()
            if len(fields) == 2 and fields[1] in (GREEN, RED):
                out[fields[0]] = fields[1]
    return out


def base_manifest(repo, refs):
    """(status, payload) for the manifest at the merge-base of HEAD and the first ref that resolves.

    The path read from the base tree is CANONICAL_MANIFEST_PATH, never the path of the tree under review, so moving
    the manifest in a change cannot hide it from the base lookup (#7987). BASE_OK carries {name: verdict};
    BASE_NONE means no ref resolved; BASE_ABSENT means the base predates both the harness and the manifest (the
    first introduction); BASE_ERROR carries a message naming the path, and covers every git failure and the case
    of a base that holds the harness but not the manifest."""
    mb = ""
    for ref in refs:
        rc, out = git_query(repo, ["merge-base", "HEAD", ref])
        if rc == 0 and out.strip():
            mb = out.strip()
            break
    if not mb:
        return BASE_NONE, None
    rc, listing = git_query(repo, ["ls-tree", "-r", "--name-only", mb, "--",
                                   CANONICAL_MANIFEST_PATH, CANONICAL_HARNESS_PATH])
    if rc != 0:
        return BASE_ERROR, f"cannot list {CANONICAL_MANIFEST_PATH} at base {mb}: {listing.strip()}"
    names = listing.split()
    if CANONICAL_MANIFEST_PATH not in names:
        if CANONICAL_HARNESS_PATH in names:
            return BASE_ERROR, (f"the base {mb} holds {CANONICAL_HARNESS_PATH} but not "
                                f"{CANONICAL_MANIFEST_PATH}; the ratchet baseline is missing")
        return BASE_ABSENT, mb
    rc, text = git_query(repo, ["cat-file", "blob", f"{mb}:{CANONICAL_MANIFEST_PATH}"])
    if rc != 0:
        return BASE_ERROR, f"cannot read {CANONICAL_MANIFEST_PATH} at base {mb}: {text.strip()}"
    return BASE_OK, parse_manifest_text(text)


def base_ratchet_problems(base, current):
    """Ratchet against the merge-base manifest: no name the base holds may vanish
    and no base GREEN may become RED. Growth and RED -> GREEN are allowed."""
    problems = []
    for name in sorted(base):
        if name not in current:
            problems.append(f"{name}: deleted since the merge-base (the manifest never shrinks)")
        elif base[name] == GREEN and current[name] == RED:
            problems.append(f"{name}: flipped GREEN -> RED since the merge-base")
    return problems


def ratchet_decision(repo, current, committed, environ):
    """(problems, notes) for the whole ratchet. The in-tree comparison always runs. The base-anchored one runs
    whenever a base ref resolves and fails closed on any error reading it. With no base ref at all the ratchet
    is refused unless ALLOW_INTREE_ENV is set, and then it says loudly that it is the weaker check (#7987)."""
    problems = ratchet_problems(committed, current)
    notes = []
    status, payload = base_manifest(repo, base_ref_candidates(environ))
    if status == BASE_OK:
        problems += base_ratchet_problems(payload, current)
    elif status == BASE_ERROR:
        problems.append(f"ratchet baseline unreadable: {payload}")
    elif status == BASE_ABSENT:
        notes.append(f"NOTE: the merge-base {payload} predates the corpus manifest; first introduction, no baseline")
    else:
        shallow = git_query(repo, ["rev-parse", "--is-shallow-repository"])[1].strip() == "true"
        prefix = "::warning::" if shallow else ""
        refs = ", ".join(base_ref_candidates(environ))
        if environ.get(ALLOW_INTREE_ENV):
            notes.append(f"{prefix}WARNING: no base ref resolves ({refs}); {ALLOW_INTREE_ENV} is set, so the "
                         "WEAKER in-tree-only ratchet ran: one identical edit to the corpus and the manifest passes it")
        else:
            problems.append(f"{prefix}no base ref resolves ({refs}), so the base-anchored ratchet cannot run; "
                            f"fetch the base branch (git fetch --no-tags --depth=1 origin BASE), set {BASE_REF_ENV}, "
                            f"or set {ALLOW_INTREE_ENV}=1 to accept the weaker in-tree-only check")
    return problems, notes


class Ratchet(unittest.TestCase):
    """The V6 guard: the corpus can grow and RED can become GREEN, nothing else. Anchored to
    the merge-base manifest when reachable (#7976); the in-tree comparison is the weaker fallback."""

    def test_manifest_ratchet(self):
        problems, notes = ratchet_decision(HARNESS_ROOT, MANIFEST, read_manifest(MANIFEST_FILE), os.environ)
        for note in notes:
            print(note, file=sys.stderr)
        self.assertEqual(problems, [], "\n".join(problems))

    def test_manifest_never_claims_an_open_issue(self):
        self.assertEqual(open_issue_claims(MANIFEST), [])
        self.assertTrue(open_issue_claims({"case_6357_x": GREEN}), "a GREEN case named for an open issue passed")
        self.assertEqual(open_issue_claims({"case_6357_x": RED, "case_6445_y": GREEN}), [])

    def test_probe_wiring_ratchet(self):
        """#7988: a RED case cannot become GREEN while its probe is an unreplayed token check."""
        src = Path(__file__).read_text(encoding="utf-8")
        self.assertEqual(probe_wiring_problems(src, GENERATOR_NEEDLES, PREFIX_REPLAY, NO_PREFIX_STANDIN, MANIFEST), [])
        key = ("x.py", "why")
        call = "class C:\n    def case_1_x(self):\n        self.generator_file('x.py', 'why')\n"
        self.assertEqual(probe_wiring_problems(call, {key: ("a",)}, {key: (("s", "p"),)}, {}, {"case_1_x": GREEN}), [])
        self.assertTrue(probe_wiring_problems(call, {key: ("a",)}, {}, {}, {"case_1_x": RED}),
                        "a probe with no replay and no recorded reason passed")
        self.assertTrue(probe_wiring_problems(call, {key: ("a",)}, {}, {key: "no file"}, {"case_1_x": GREEN}),
                        "an unreplayed probe was allowed to be GREEN")
        self.assertEqual(probe_wiring_problems(call, {key: ("a",)}, {}, {key: "no file"}, {"case_1_x": RED}), [])
        self.assertTrue(probe_wiring_problems("x = 1\n", {key: ("a",)}, {key: (("s", "p"),)}, {}, {}),
                        "an unreferenced probe passed")

    def test_every_case_is_registered(self):
        found = set()
        for cls in (Cells, Corpus):
            found.update(n for n in dir(cls) if n.startswith(("case_", "cell_"))
                         and callable(getattr(cls, n)))
        self.assertEqual(sorted(found ^ set(MANIFEST)), [], "a case is missing @expect or its body")

    def test_ratchet_detects_each_regression(self):
        committed = {"cell_x": GREEN, "case_1_y": RED, "case_2_z": GREEN}
        self.assertEqual(ratchet_problems(committed, dict(committed)), [])
        deleted = {k: v for k, v in committed.items() if k != "cell_x"}
        self.assertIn("deleted", " ".join(ratchet_problems(committed, deleted)))
        weakened = dict(committed, case_2_z=RED)
        self.assertIn("GREEN -> RED", " ".join(ratchet_problems(committed, weakened)))
        unrecorded = dict(committed, case_1_y=GREEN)
        self.assertIn("manifest records RED", " ".join(ratchet_problems(committed, unrecorded)))
        grown = dict(committed, case_3_new=RED)
        self.assertIn("not recorded", " ".join(ratchet_problems(committed, grown)))


    BASE_NAMES = {"cell_x": GREEN, "case_1_y": RED, "case_2_z": GREEN}
    SCENE_GIT = ["git", "-c", "user.name=t", "-c", "user.email=selftest@localhost", "-c", "commit.gpgsign=false"]
    MOVED_MANIFEST = "elsewhere/relocated-manifest.txt"

    def scene(self, tmp, manifest_at_base=True, harness_at_base=True, base_ref=True):
        """A scratch repo: a base commit (the canonical manifest and harness paths, as asked) and a HEAD commit on top.
        Returns (repo, environ). With base_ref the ref origin/basecand names the base commit."""
        repo = tmp / "r"
        repo.mkdir()
        text = "".join(f"{n} {v}\n" for n, v in sorted(self.BASE_NAMES.items()))
        adds = []
        if manifest_at_base:
            (repo / CANONICAL_MANIFEST_PATH).parent.mkdir(parents=True)
            (repo / CANONICAL_MANIFEST_PATH).write_text(text, encoding="utf-8")
            adds.append(CANONICAL_MANIFEST_PATH)
        if harness_at_base:
            (repo / CANONICAL_HARNESS_PATH).parent.mkdir(parents=True, exist_ok=True)
            (repo / CANONICAL_HARNESS_PATH).write_text("# harness\n", encoding="utf-8")
            adds.append(CANONICAL_HARNESS_PATH)
        if not adds:
            (repo / "README").write_text("base\n", encoding="utf-8")
            adds.append("README")
        steps = [["init", "-q"], ["add"] + adds, ["commit", "-q", "-m", "base"]]
        if base_ref:
            steps.append(["update-ref", "refs/remotes/origin/basecand", "HEAD"])
        steps.append(["commit", "-q", "--allow-empty", "-m", "change under review"])
        for argv in steps:
            subprocess.run(self.SCENE_GIT + argv, cwd=str(repo), check=True, capture_output=True)
        return repo, ({BASE_REF_ENV: "origin/basecand"} if base_ref else {})

    def decide(self, tmp, current, base_ref, relocate=False, **scene_kw):
        """ratchet_decision for the tree under review: `current` is the corpus and the in-tree manifest alike (the
        both-file edit); with relocate the in-tree manifest also lives at another path than the canonical one."""
        repo, environ = self.scene(tmp, base_ref=base_ref, **scene_kw)
        committed = dict(current)
        if relocate:
            moved = repo / self.MOVED_MANIFEST
            moved.parent.mkdir(parents=True, exist_ok=True)
            moved.write_text("".join(f"{n} {v}\n" for n, v in sorted(current.items())), encoding="utf-8")
            committed = parse_manifest_text(moved.read_text(encoding="utf-8"))
        return ratchet_decision(repo, current, committed, environ)

    def scratch_dir(self):
        tmp = Path(tempfile.mkdtemp(prefix=CASE_SCRATCH_PREFIX, dir=str(SCRATCH_ROOT)))
        self.addCleanup(shutil.rmtree, str(tmp), True)
        return tmp

    def test_base_anchor_refuses_both_file_edits(self):
        """#7976 and #7987: R1 (relocate the manifest, then delete a RED case in the corpus and the manifest) and
        E1/E2 (the same flip or delete in both files) are refused in a repo with a base ref (by the base manifest) and
        in a repo without one (the ratchet cannot run, so it fails closed)."""
        deleted_red = {k: v for k, v in self.BASE_NAMES.items() if k != "case_1_y"}
        deleted_green = {k: v for k, v in self.BASE_NAMES.items() if k != "cell_x"}
        flipped = dict(self.BASE_NAMES, case_2_z=RED)
        cases = (("R1", deleted_red, True, "deleted"), ("E1", flipped, False, "GREEN -> RED"),
                 ("E2", deleted_green, False, "deleted"))
        for label, current, relocate, want in cases:
            with self.subTest(label=label, mode="with-base-ref"):
                problems, _notes = self.decide(self.scratch_dir(), current, True, relocate=relocate)
                self.assertIn(want, " ".join(problems), f"{label} not refused with a base ref")
            with self.subTest(label=label, mode="no-base-ref"):
                problems, _notes = self.decide(self.scratch_dir(), current, False, relocate=relocate)
                self.assertIn("no base ref resolves", " ".join(problems), f"{label} not refused without a base ref")

    def test_base_anchor_fails_closed_on_missing_base_manifest(self):
        """#7987: a base that holds the harness but not the manifest, or any failure reading it, is a failure that
        names the canonical manifest path; a base with neither is the first introduction and is only noted."""
        problems, _notes = self.decide(self.scratch_dir(), dict(self.BASE_NAMES), True, manifest_at_base=False)
        self.assertIn(CANONICAL_MANIFEST_PATH, " ".join(problems))
        self.assertIn("baseline", " ".join(problems))
        problems, notes = self.decide(self.scratch_dir(), dict(self.BASE_NAMES), True,
                                      manifest_at_base=False, harness_at_base=False)
        self.assertEqual(problems, [])
        self.assertIn("first introduction", " ".join(notes))
        repo, _environ = self.scene(self.scratch_dir())
        status, payload = base_manifest(repo, ["origin/basecand"])
        self.assertEqual((status, payload), (BASE_OK, self.BASE_NAMES))
        broken = repo / ".git" / "objects"
        for sub in broken.iterdir():
            if len(sub.name) == 2:
                shutil.rmtree(str(sub))
        status, payload = base_manifest(repo, ["origin/basecand"])
        self.assertIn(status, (BASE_ERROR, BASE_NONE))
        self.assertNotEqual(status, BASE_OK)

    def test_no_base_ref_needs_the_explicit_opt_in(self):
        """#7987: with no base ref the in-tree-only check runs only when ALLOW_INTREE_ENV is set, with a loud note."""
        repo, environ = self.scene(self.scratch_dir(), base_ref=False)
        problems, notes = ratchet_decision(repo, dict(self.BASE_NAMES), dict(self.BASE_NAMES), environ)
        self.assertIn(ALLOW_INTREE_ENV, " ".join(problems))
        problems, notes = ratchet_decision(repo, dict(self.BASE_NAMES), dict(self.BASE_NAMES),
                                           dict(environ, **{ALLOW_INTREE_ENV: "1"}))
        self.assertEqual(problems, [])
        self.assertIn("WEAKER", " ".join(notes))

    def test_base_anchor_allows_growth_and_red_to_green(self):
        repo, environ = self.scene(self.scratch_dir())
        grown = dict(self.BASE_NAMES, case_3_new=RED, case_1_y=GREEN)
        problems, _notes = ratchet_decision(repo, grown, dict(grown), environ)
        self.assertEqual(problems, [])
        status, _payload = base_manifest(repo, ["origin/nosuchref"])
        self.assertEqual(status, BASE_NONE)


FILTER_ENV = "CERT_CORPUS_FILTER"  # comma-separated name prefixes; a debugging and nesting knob
CASE_PREFIXES = ("case_", "cell_", "test_")
CASE_CLASSES = (Cells, Corpus, Ratchet)


def case_names(cls):
    return sorted(n for n in dir(cls) if n.startswith(CASE_PREFIXES) and callable(getattr(cls, n)))


def selected(name):
    if os.environ.get(NESTED_ENV) and name in SPAWNING:
        return False
    prefixes = [p for p in os.environ.get(FILTER_ENV, "").split(",") if p]
    return not prefixes or name.startswith(tuple(prefixes))


def load_tests(loader, standard_tests, pattern):
    suite = unittest.TestSuite()
    for cls in CASE_CLASSES:
        suite.addTests(cls(n) for n in case_names(cls) if selected(n))
    return suite


class CorpusResult(unittest.TextTestResult):
    pass


def main(argv=None):
    """Run the corpus. `--machine` prints one `CORPUS-FAIL <name>: <reason>` line per
    failing case and a `CORPUS-SUMMARY` line, with no traceback, for the gate's thin
    `--self-test` runner (#6445)."""
    args = list(sys.argv[1:] if argv is None else argv)
    if REPLAY_FETCH_FLAG in args:
        print("\n".join(replay_objects()))
        return 0
    machine = "--machine" in args
    suite = load_tests(unittest.defaultTestLoader, None, None)
    stream = io.StringIO() if machine else sys.stderr
    result = unittest.TextTestRunner(stream=stream, verbosity=1).run(suite)
    if not machine:
        return 0 if result.wasSuccessful() else 1
    bad = list(result.failures) + list(result.errors)
    for case, trace in bad:
        reason = trace.strip().splitlines()[-1] if trace.strip() else "failed"
        print(f"CORPUS-FAIL {case.id().rsplit('.', 1)[-1]}: {reason[:300]}")
    for case in result.unexpectedSuccesses:
        print(f"CORPUS-FAIL {case.id().rsplit('.', 1)[-1]}: expected to fail (RED) but passed")
    print(f"CORPUS-SUMMARY ran={result.testsRun} failed={len(bad) + len(result.unexpectedSuccesses)}")
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    sys.exit(main())
