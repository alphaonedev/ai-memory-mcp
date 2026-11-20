#!/usr/bin/env python3
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""Set a JOB-PRIVATE HF_HOME under the runner temp dir for every model-cache job (#9509).

A self-hosted runner keeps its user's home across jobs, so a model cache under
``~/.cache/huggingface`` is shared by every job and every PR that runs there: one
job's bytes become the next job's model (3-agent vote 71472661, D2-1). This
helper is the ONE place the cache root is defined: ``<runner-temp>/<PRIVATE_DIR_NAME>``,
outside the checkout tree (the #7188 precedent, scripts/ci/shared_cargo_target.py,
keeps state out of the workspace so checkout cleaning and clean-tree scans never
meet it). The workflow calls it once per job, before the cache restore, and it
exports HF_HOME through $GITHUB_ENV, so every later step of the job (the cache
restore and save, scripts/ci/stage_hf_cache.py and cargo test) reads the same root.

It FAILS CLOSED: a runner temp dir that is not absolute or is ``/``, a root inside
the checkout (or a checkout inside the root), a root that already exists as a
symlink, a non-directory or a directory of another user, and a path that would
not survive a $GITHUB_ENV line unchanged all exit EXIT_USAGE and export nothing.

Exit codes: 0 ok, 2 bad arguments or a refused root, 3 the shared module cannot be loaded.
Python 3.12 floor, standard library only.
"""
import argparse
import os
import stat
import sys


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
WA_PROG = "hf_home_private"
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
        print("::error title=hf_home_private refused::hf_home_private: refused: shared module workflow_annotation.py"
              " next to the script cannot be loaded",
              file=sys.stderr if WA_ERROR_TO_STDERR else sys.stdout, flush=True)
        sys.exit(WA_EXIT_LOAD_REFUSED)


# Pinned equal to scripts/ci/stage_hf_cache.py PRIVATE_DIR_NAME by a census cell.
PRIVATE_DIR_NAME = "ai-memory-hf-home"
ENV_NAME = "HF_HOME"
PRIVATE_DIR_MODE = 0o700
ROOT_DIR = os.sep
EXIT_OK = 0
EXIT_USAGE = 2


class RefusedRoot(ValueError):
    """The private root cannot be used; the message names why (never a secret, only paths)."""


def inside(path, root):
    """True when ``path`` is ``root`` or below it (both already real paths)."""
    return path == root or path.startswith(root.rstrip(os.sep) + os.sep)


def private_root(runner_temp, workspace):
    """The real path of ``<runner_temp>/PRIVATE_DIR_NAME``; raises RefusedRoot when it may not be used."""
    if not os.path.isabs(runner_temp) or os.path.realpath(runner_temp) == ROOT_DIR:
        raise RefusedRoot("runner temp dir %r is not an absolute directory other than /" % runner_temp)
    if not os.path.isabs(workspace):
        raise RefusedRoot("workspace %r is not an absolute path" % workspace)
    root = os.path.join(os.path.realpath(runner_temp), PRIVATE_DIR_NAME)
    real_workspace = os.path.realpath(workspace)
    if inside(root, real_workspace) or inside(real_workspace, root):
        raise RefusedRoot("private root %s overlaps the checkout %s" % (root, real_workspace))
    return root


def ensure_private_dir(root):
    """Create ``root`` mode 0700, or accept an existing real directory of this user; never follow a symlink."""
    try:
        os.mkdir(root, PRIVATE_DIR_MODE)
    except FileExistsError:
        pass
    except OSError as err:
        raise RefusedRoot("cannot create private root %s (%s)" % (root, type(err).__name__)) from err
    info = os.lstat(root)
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        raise RefusedRoot("private root %s is not a real directory" % root)
    if info.st_uid != os.geteuid():
        raise RefusedRoot("private root %s belongs to another user" % root)
    os.chmod(root, PRIVATE_DIR_MODE, follow_symlinks=False)


def main(argv=None):
    require_workflow_annotation()
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--runner-temp", required=True, help="the runner temp dir (runner.temp)")
    parser.add_argument("--workspace", required=True, help="the checkout (github.workspace)")
    parser.add_argument("--github-env", required=True, help="append HF_HOME to this $GITHUB_ENV file")
    args = parser.parse_args(argv)
    try:
        root = private_root(args.runner_temp, args.workspace)
        if wa.env_file_value(root) != root:
            raise RefusedRoot("private root %s does not fit one $GITHUB_ENV line" % root)
        ensure_private_dir(root)
    except RefusedRoot as err:
        print(wa.log_line("hf_home_private: refusing: %s" % err), file=sys.stderr)
        return EXIT_USAGE
    with open(args.github_env, "a", encoding="utf-8") as handle:
        handle.write("%s=%s\n" % (ENV_NAME, wa.env_file_value(root)))
    print(wa.log_line("%s=%s" % (ENV_NAME, root)))
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
