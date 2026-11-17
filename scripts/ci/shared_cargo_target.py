#!/usr/bin/env python3
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""Resolve the PER-RUNNER cargo target directory for self-hosted legs (#7188).

Every linux-fed runner on one host runs as the same user, so a directory tree
under that user's home survives checkout cleaning (it lives outside the
workspace) and is per host by construction. Each runner gets its OWN target,
``~/.cache/ai-memory-ci/cargo-target/<runner-name>``: a target with exactly one
writer cannot have one PR's test binary replaced by another PR's build (cargo
releases its build lock before it executes test binaries), and the dependency
and workspace cache stays warm across the jobs of that runner (compile once).

The runner name is passed explicitly (``--runner-name``) from the workflow. It
FAILS CLOSED: a missing, empty, ``.``/``..`` or non ``[A-Za-z0-9._-]`` name
exits EXIT_USAGE, exports nothing and creates nothing; there is never a shared
fallback path.

This is the ONLY place the path root is defined: the workflow calls this helper
once and exports CARGO_TARGET_DIR (this runner) and AI_MEMORY_CI_TARGET_ROOT
(the whole root, protected by the prune step) through $GITHUB_ENV.

Exit codes: 0 ok, 2 bad arguments or an unusable home directory or runner name.
Python 3.9+, standard library only.
"""
import argparse
import contextlib
import fcntl
import os
import re
import stat
import sys
import time
from pathlib import Path


def _load_workflow_annotation():
    """The shared module at WA_RELATIVE_PATH from this file's real directory, by path only, never through
    sys.path; every name in WA_REQUIRED must be a callable of it (#9365, one shape in every script)."""
    import importlib.util
    import os
    path = os.path.normpath(os.path.join(os.path.dirname(os.path.realpath(__file__)), WA_RELATIVE_PATH))
    loaded = sys.modules.get("workflow_annotation")
    if loaded is not None and os.path.realpath(getattr(loaded, "__file__", None) or "") == path:
        module = loaded
    else:
        spec = importlib.util.spec_from_file_location("workflow_annotation", path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)  # absent, unreadable or broken: it raises here, the try below catches it
    missing = [name for name in WA_REQUIRED if not callable(getattr(module, name, None))]
    if missing:
        raise AttributeError("workflow_annotation.py lacks " + ", ".join(missing))
    if loaded is None:
        sys.modules["workflow_annotation"] = module
    return module


# The one shared-module load shape of scripts/ (#9365, ruling bcd0a15c; LoaderShape pins it).
WA_PROG = "shared_cargo_target"
WA_RELATIVE_PATH = "workflow_annotation.py"
WA_REQUIRED = ("env_file_value", "log_line")
WA_EXIT_LOAD_REFUSED = 3  # a failed shared-module load; no other meaning in this script
WA_ERROR_TO_STDERR = False


class SharedModuleNotLoadedError(RuntimeError):
    """A function that needs workflow_annotation.py ran before require_workflow_annotation() loaded it."""


class _NotLoaded:
    """The state of ``wa`` until the load ran: one explicit member per name this script uses from the shared module
    (a test pins the set against the ast), each a named error, never a half-working helper. No __getattr__, so
    hasattr and getattr with a default cannot turn a forgotten load into a silent fallback."""

    _WANTED = ("workflow_annotation.py is not loaded; call require_workflow_annotation() "
              "first (wanted %s)")

    def env_file_value(self, *args, **kwargs):
        raise SharedModuleNotLoadedError(self._WANTED % "env_file_value")

    def log_line(self, *args, **kwargs):
        raise SharedModuleNotLoadedError(self._WANTED % "log_line")


wa = _NotLoaded()


def require_workflow_annotation():
    """Load the shared module into ``wa`` or refuse: main calls it before any work, so importing prints nothing."""
    global wa
    try:
        wa = _load_workflow_annotation()
    except (Exception, SystemExit) as exc:  # any failed load: one fixed line built without the module, then exit
        wa_cause = type(exc).__name__
        print("%s: refused: shared module workflow_annotation.py next to the script cannot be loaded (%s)"
              % (WA_PROG, wa_cause if wa_cause.isidentifier() else "BaseException"), file=sys.stderr, flush=True)
        print("::error title=shared_cargo_target refused::shared_cargo_target: refused: shared module workflow_annotation.py"
              " next to the script cannot be loaded",
              file=sys.stderr if WA_ERROR_TO_STDERR else sys.stdout, flush=True)
        sys.exit(WA_EXIT_LOAD_REFUSED)

TARGET_ROOT_RELATIVE = Path(".cache") / "ai-memory-ci" / "cargo-target"
ENV_NAME = "CARGO_TARGET_DIR"
ROOT_ENV_NAME = "AI_MEMORY_CI_TARGET_ROOT"
RUNNER_NAME_PATTERN = re.compile(r"\A[A-Za-z0-9._-]+\Z")
DOT_NAMES = (".", "..")
# In-use marker (#7199): written into this runner's target at job start and
# removed by the post-job prune step. Eviction in a sibling runner skips a
# target whose marker is younger than IN_USE_MARKER_MAX_AGE_SECS, so a crashed
# job's marker expires instead of pinning the target forever (6 h is above the
# longest linux-fed job timeout).
IN_USE_MARKER_NAME = ".in-use"
IN_USE_MARKER_MAX_AGE_SECS = 6 * 3600
MARKER_TIME_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
# Eviction lock (#7292): an exclusive flock on <root>/.evict.lock serialises a
# job start (mkdir + marker write) against an eviction's busy check + rename.
# The lock file lives inside the protected root, so a prune never deletes it.
EVICT_LOCK_NAME = ".evict.lock"
EVICT_LOCK_TIMEOUT_SECS = 20.0
JOB_START_LOCK_TIMEOUT_SECS = 60.0
LOCK_POLL_SECS = 0.05
LOCK_FILE_MODE = 0o600
EXIT_OK = 0
EXIT_USAGE = 2


@contextlib.contextmanager
def evict_lock(root, timeout_secs):
    """Take ``<root>/.evict.lock`` exclusively for at most ``timeout_secs``; yield True if held.

    Never raises for a lock problem: a lock file that cannot be opened or a
    timeout yields False and the caller decides (eviction skips, a job start
    warns and proceeds). The lock is released when the block exits.
    """
    fd = None
    held = False
    try:
        flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(str(Path(root) / EVICT_LOCK_NAME), flags, LOCK_FILE_MODE)
    except OSError:
        fd = None
    try:
        if fd is not None:
            deadline = time.monotonic() + timeout_secs
            while True:
                try:
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    held = True
                    break
                except BlockingIOError:
                    if time.monotonic() >= deadline:
                        break
                    time.sleep(LOCK_POLL_SECS)
                except OSError:
                    break
        yield held
    finally:
        if fd is not None:
            os.close(fd)  # closing the descriptor releases the flock


def write_in_use_marker(target, runner_name, now=None):
    """Write the in-use marker (runner name + ISO UTC time) into ``target``."""
    stamp = time.strftime(MARKER_TIME_FORMAT, time.gmtime(time.time() if now is None else now))
    (Path(target) / IN_USE_MARKER_NAME).write_text(
        "%s %s\n" % (runner_name, stamp), encoding="utf-8")


def clear_in_use_marker(target):
    """Remove the in-use marker of ``target``; a missing marker is fine."""
    with contextlib.suppress(FileNotFoundError):
        (Path(target) / IN_USE_MARKER_NAME).unlink()


def marker_is_fresh(target, now, max_age_secs=IN_USE_MARKER_MAX_AGE_SECS):
    """True when ``target`` has a real (non-symlink) marker younger than ``max_age_secs``.

    Fail closed (#7289): only a missing marker (FileNotFoundError) or a target
    that is not a directory (NotADirectoryError) is "no marker". Any other
    OSError means the state is unknown, which counts as fresh (the target is
    treated as in use).
    """
    marker = Path(target) / IN_USE_MARKER_NAME
    try:
        info = marker.lstat()
    except (FileNotFoundError, NotADirectoryError):
        return False
    except OSError:
        return True
    return not stat.S_ISLNK(info.st_mode) and now - info.st_mtime < max_age_secs


def target_root_dir(home):
    """Return the root holding every runner target (never a tmp path)."""
    return Path(home) / TARGET_ROOT_RELATIVE


def valid_runner_name(name):
    """True for a non-empty name of ``[A-Za-z0-9._-]`` that is not ``.``/``..``."""
    return bool(name) and name not in DOT_NAMES and bool(RUNNER_NAME_PATTERN.match(name))


def runner_target_dir(home, runner_name):
    """Return this runner's target path; raises ValueError on a bad name."""
    if not valid_runner_name(runner_name):
        raise ValueError("invalid runner name %r" % (runner_name,))
    return target_root_dir(home) / runner_name


def main(argv=None):
    require_workflow_annotation()
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--home", default=str(Path.home()), help="runner user home")
    parser.add_argument("--runner-name", default=None, help="runner name (required)")
    parser.add_argument(
        "--github-env", help="append CARGO_TARGET_DIR and the root to this $GITHUB_ENV file"
    )
    parser.add_argument(
        "--lock-timeout", type=float, default=JOB_START_LOCK_TIMEOUT_SECS,
        help="seconds to wait for the eviction lock before proceeding with a warning")
    args = parser.parse_args(argv)
    home = Path(args.home)
    if not home.is_absolute() or str(home) in ("/", ""):
        print(wa.log_line("shared_cargo_target: refusing home %r" % args.home), file=sys.stderr)
        return EXIT_USAGE
    try:
        path = runner_target_dir(home, args.runner_name)
    except ValueError as err:
        print(wa.log_line("shared_cargo_target: refusing: %s" % err), file=sys.stderr)
        return EXIT_USAGE
    root = target_root_dir(home)
    root.mkdir(parents=True, exist_ok=True)
    with evict_lock(root, args.lock_timeout) as held:
        if not held:
            # A job start never fails or deadlocks on the lock (#7292).
            print(wa.log_line("shared_cargo_target: warning: eviction lock %s not taken within %s s; "
                  "proceeding without it" % (root / EVICT_LOCK_NAME, args.lock_timeout)),
                  file=sys.stderr)
        path.mkdir(parents=True, exist_ok=True)
        write_in_use_marker(path, args.runner_name)
    if args.github_env:
        with open(args.github_env, "a", encoding="utf-8") as handle:
            handle.write("%s=%s\n" % (ENV_NAME, wa.env_file_value(path)))
            handle.write("%s=%s\n" % (ROOT_ENV_NAME, wa.env_file_value(target_root_dir(home))))
    print(wa.log_line(path))
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
