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

The private copy is removed on every exit path (``finally``), including a
failing run.  Exit codes: 0 pass, 1 a check failed, 2 usage or environment
error, 3 a self-test fixture is present in the census tree.
"""

import argparse
import fnmatch
import os
from pathlib import Path
import shutil
import subprocess
import sys

EXIT_OK = 0
EXIT_FAIL = 1
EXIT_ENV = 2
EXIT_FIXTURE = 3

GATE = "scripts/check-test-env-lock.sh"
INTERRUPT_HARNESS = "scripts/test/test-gate-selftest-interrupt-cleanup.sh"
SELFTEST_DIR = Path(".local-runs") / "test-env-lock-selftest"
FIXTURE_GLOB = "check_test_env_arm_*_probe_*.rs"
IDENT = ("-c", "user.name=selftest", "-c", "user.email=selftest@invalid",
         "-c", "commit.gpgsign=false")


def find_fixtures(root):
    """Return the self-test fixtures present under ``root/src``, sorted."""
    src = Path(root) / "src"
    if not src.is_dir():
        return []
    return sorted(p for p in src.glob(FIXTURE_GLOB) if p.is_file())


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
        if fnmatch.fnmatch(Path(rel).name, FIXTURE_GLOB) and Path(rel).parent.name == "src":
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


def run_isolated(root, argv_for, tag):
    """Run ``argv_for(copy)`` in a private tree copy; always remove the copy."""
    root = Path(root)
    parent = root / SELFTEST_DIR
    copy = parent / ("%s-%d" % (tag, os.getpid()))
    try:
        make_copy(root, copy)
        return subprocess.run(argv_for(copy), cwd=str(copy), check=False).returncode
    finally:
        shutil.rmtree(str(copy), ignore_errors=True)
        try:
            parent.rmdir()  # only when no sibling run still uses it
        except OSError:
            pass


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("command", choices=("census", "selftest", "interrupt"))
    ap.add_argument("--root", default=str(Path(__file__).resolve().parents[2]))
    ap.add_argument("--harness-self-test", action="store_true",
                    help="interrupt only: run the harness's own self-test")
    args = ap.parse_args(argv)
    root = Path(args.root).resolve()
    if not (root / GATE).is_file():
        print("ERROR: %s not found under %s" % (GATE, root), file=sys.stderr)
        return EXIT_ENV
    try:
        if args.command == "census":
            rc = precheck(root)
            if rc != EXIT_OK:
                return rc
            return subprocess.run(["bash", GATE], cwd=str(root), check=False).returncode
        if args.command == "selftest":
            return run_isolated(root, lambda c: ["bash", GATE, "--self-test"], "selftest")
        extra = ["--harness-self-test"] if args.harness_self_test else []
        return run_isolated(
            root, lambda c: ["bash", INTERRUPT_HARNESS] + extra, "interrupt")
    except (RuntimeError, OSError) as err:
        print("ERROR: %s" % err, file=sys.stderr)
        return EXIT_ENV


if __name__ == "__main__":
    sys.exit(main())
