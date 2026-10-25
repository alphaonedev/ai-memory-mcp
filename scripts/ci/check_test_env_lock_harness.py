#!/usr/bin/env python3
"""Run the Test-env HOME-lock gate (#2146) census and its self-tests apart (#7913).

The gate census (``scripts/check-test-env-lock.sh``) scans ``src/`` and
``tests/`` of the checkout it runs in.  Its ``--self-test`` and the #4292
interrupt harness (``scripts/test/test-gate-selftest-interrupt-cleanup.sh``)
plant probe files INSIDE a tree, so when they shared the checkout with the
census the census counted the harness's own fixtures
(``src/check_test_env_arm_*_probe_*.rs``) as product offenders and the #4292
tree-clean guard fired (PR #7912, job 119604086298).

Sub-commands:

``census``     Refuse (exit 3) while a self-test fixture is present in the
               census tree, then run the census there.
``selftest``   Run ``check-test-env-lock.sh --self-test`` in a private copy
               of the tree under ``<root>/.local-runs/test-env-lock-selftest/``.
``interrupt``  Run the #4292 interrupt harness (``--harness-self-test`` with
               that flag) in a private copy, so its probes, its pre-existing
               probe cases and its ``git status`` guard never touch the census
               tree.

The private copy is removed on every exit path ``finally`` can reach: a pass,
a failing run, an exception, SIGTERM and SIGINT.  SIGKILL cannot be caught and
still strands the copy.  Exit codes: 0 pass, 1 a check failed, 2 usage or environment
error, 3 a self-test fixture is present in the census tree.
"""

import argparse
import errno
import fnmatch
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys

EXIT_OK = 0
EXIT_FAIL = 1
EXIT_ENV = 2
EXIT_FIXTURE = 3

# Every sub-command main() dispatches; ISOLATED_MODES run in a private copy (#7925).
ISOLATED_MODES = ("selftest", "interrupt")
MODES = ("census",) + ISOLATED_MODES
GATE = "scripts/check-test-env-lock.sh"
INTERRUPT_HARNESS = "scripts/test/test-gate-selftest-interrupt-cleanup.sh"
SELFTEST_DIR = Path(".local-runs") / "test-env-lock-selftest"
# Every probe file the gate --self-test plants under src/ and the census then
# counts: the plain arm (d)-(h) fixtures AND the dot-prefixed arm (a)-(c) and
# arm (f) fixtures (the `probe_*=` assignments in the gate script).
FIXTURE_GLOBS = (
    "check_test_env_arm_*_probe_*.rs",
    ".check_home_lock_*_probe.rs",
    ".check_passphrase_window_*probe_*.rs",
)
IDENT = ("-c", "user.name=selftest", "-c", "user.email=selftest@invalid",
         "-c", "commit.gpgsign=false")


def find_fixtures(root):
    """Return the self-test fixtures present under ``root/src``, sorted."""
    src = Path(root) / "src"
    if not src.is_dir():
        return []
    found = set()
    for pattern in FIXTURE_GLOBS:
        found.update(p for p in src.glob(pattern) if p.is_file())
    return sorted(found)


def is_fixture_name(name):
    """True when ``name`` is a file name the census would count as a fixture."""
    return any(fnmatch.fnmatchcase(name, pat) for pat in FIXTURE_GLOBS)


def precheck(root, out=sys.stderr):
    """Return EXIT_FIXTURE and name the first fixture, else EXIT_OK."""
    found = find_fixtures(root)
    if not found:
        return EXIT_OK
    print("self-test fixture present: %s" % found[0].relative_to(Path(root)), file=out)
    return EXIT_FIXTURE


def _tracked_paths(root):
    """Tracked and unignored untracked paths, so uncommitted edits are copied."""
    res = subprocess.run(
        ["git", "-C", str(root), "ls-files", "-z", "--cached", "--others",
         "--exclude-standard"],
        stdout=subprocess.PIPE, check=False)
    if res.returncode != 0:
        raise RuntimeError("git ls-files failed in %s" % root)
    return [p for p in res.stdout.decode().split("\0") if p]


def make_copy(root, dest):
    """Copy the tree to ``dest`` as a fresh git repo with one baseline commit."""
    root, dest = Path(root), Path(dest)
    if dest.exists():
        shutil.rmtree(str(dest))
    dest.mkdir(parents=True)
    for rel in _tracked_paths(root):
        # A fixture in the source tree must not leak into the copy.
        if is_fixture_name(Path(rel).name) and Path(rel).parent.name == "src":
            continue
        src = root / rel
        if not src.is_file() and not src.is_symlink():
            continue
        target = dest / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        if src.is_symlink():
            os.symlink(os.readlink(str(src)), str(target))
        else:
            shutil.copy2(str(src), str(target))
    for cmd in (["init", "-q"], ["add", "-A"],
                list(IDENT) + ["commit", "-q", "-m", "selftest baseline"]):
        res = subprocess.run(["git", "-C", str(dest)] + cmd, check=False,
                             stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        if res.returncode != 0:
            raise RuntimeError("git %s failed: %s" % (cmd[0], res.stderr.decode()[-200:]))
    return dest


class Interrupted(SystemExit):
    """Raised by the signal handlers so ``finally`` cleanup runs (#7922)."""


def _raise_interrupted(signum, _frame):
    raise Interrupted(128 + signum)


def _stderr_note(message):
    """Write one ``NOTE:`` line to stderr (looked up at call time, so it can be captured)."""
    print("NOTE: %s" % message, file=sys.stderr)


def _run_child(argv, cwd):
    """Run ``argv`` in its own process group; kill the whole group on any raise."""
    proc = subprocess.Popen(argv, cwd=cwd, start_new_session=True)
    try:
        return proc.wait()
    except BaseException:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except OSError as err:
            # Record it; the original exception still propagates below, so the
            # exit code is never masked (#7926).
            _stderr_note("could not kill process group %d: errno %s (%s)"
                         % (proc.pid, err.errno, err.strerror))
        proc.wait()
        raise


def run_isolated(root, argv_for, tag):
    """Run ``argv_for(copy)`` in a private tree copy; always remove the copy.

    SIGTERM and SIGINT become an exception while the copy exists so the
    ``finally`` cleanup runs.  SIGKILL cannot be caught and strands the copy.
    """
    root = Path(root)
    parent = root / SELFTEST_DIR
    copy = parent / ("%s-%d" % (tag, os.getpid()))
    previous = {}
    try:
        for sig in (signal.SIGTERM, signal.SIGINT):
            try:
                previous[sig] = signal.signal(sig, _raise_interrupted)
            except ValueError:  # not the main thread: handlers cannot be set
                break
        make_copy(root, copy)
        return _run_child(argv_for(copy), str(copy))
    finally:
        # An interrupt or exception already propagating keeps its exit code (#7933).
        in_flight = sys.exc_info()[1]
        for sig, handler in previous.items():
            signal.signal(sig, handler)
        shutil.rmtree(str(copy), ignore_errors=True)
        try:
            parent.rmdir()  # only when no sibling run still uses it
        except OSError as err:
            _stderr_note("could not remove %s: errno %s (%s)"
                         % (parent, err.errno, err.strerror))
            if err.errno != errno.ENOTEMPTY and in_flight is None:
                raise


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("command", choices=MODES)
    ap.add_argument("--root", default=str(Path(__file__).resolve().parents[2]))
    ap.add_argument("--gate", default=GATE,
                    help="gate script relative to --root (the workflow names it so "
                         "check-required-contexts rule (g) sees it wired)")
    ap.add_argument("--harness-self-test", action="store_true",
                    help="interrupt only: run the harness's own self-test")
    args = ap.parse_args(argv)
    root = Path(args.root).resolve()
    gate = args.gate
    if not (root / gate).is_file():
        print("ERROR: %s not found under %s" % (gate, root), file=sys.stderr)
        return EXIT_ENV
    try:
        if args.command == "census":
            rc = precheck(root)
            if rc != EXIT_OK:
                return rc
            return subprocess.run(["bash", gate], cwd=str(root), check=False).returncode
        if args.command == "selftest":
            return run_isolated(root, lambda c: ["bash", gate, "--self-test"], "selftest")
        extra = ["--harness-self-test"] if args.harness_self_test else []
        return run_isolated(
            root, lambda c: ["bash", INTERRUPT_HARNESS] + extra, "interrupt")
    except (RuntimeError, OSError) as err:
        print("ERROR: %s" % err, file=sys.stderr)
        return EXIT_ENV


if __name__ == "__main__":
    sys.exit(main())
