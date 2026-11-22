#!/usr/bin/env python3
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""Emit the hardware facts every published throughput number must carry (#2921).

docs/enterprise-deployment.md section 11.1: "If you need a committed throughput figure for a procurement gate, run
the measurement and record the host." This is that record, in machine-readable form, captured by the same code path
the producers embed in their own results JSON (``benchlib.host_facts``) so the standalone capture and the embedded
capture can never drift.

Emits ONLY device nodes and hardware identifiers -- never a filesystem path from the operator's home directory,
because this output is committed as evidence.

    scripts/bench/host-facts.py            # JSON to stdout
    scripts/bench/host-facts.py --check    # exit 1 if a required fact is absent

``benchlib`` is loaded from the real folder of this file by the shared loader block below (#9399), never through the
import search path. Exit codes: 0 ok, 1 a required fact is absent (--check), 2 usage (argparse), 3 benchlib cannot be
loaded (one stderr line naming the path).
"""
import argparse
import json
import sys

# >>> sibling-load 9399 (canonical text; scripts/ci/sibling_load.py; test_sibling_load_9399 pins every copy)
class SiblingLoadError(ImportError):
    """A refused sibling load; ``reason`` is one of the fixed words the refusal line prints."""

    def __init__(self, reason):
        super().__init__(reason)
        self.reason = reason


def _sibling_path(filename):
    import os
    return os.path.join(os.path.dirname(os.path.realpath(__file__)), filename)


def _load_sibling(filename, module_name):
    import os
    import stat
    import sys
    import types
    here = os.path.dirname(os.path.realpath(__file__))
    try:
        here_st = os.stat(here)
    except OSError:
        raise SiblingLoadError("unreadable") from None
    here_id = (here_st.st_dev, here_st.st_ino)
    path = os.path.realpath(os.path.join(here, filename))
    if os.path.commonpath([here, path]) != here:
        raise SiblingLoadError("symlink leaves the script folder")
    loaded = sys.modules.get(module_name)
    if loaded is not None:
        if os.path.realpath(getattr(loaded, "__file__", None) or "") == path:
            return loaded
        raise SiblingLoadError("module name taken")
    # The script folder opened must have the device and inode the stat above recorded, so a swap of that folder or of
    # any folder above it (for a symlink or by a rename) is refused; each component below it is opened relative to the
    # descriptor before it and never through a symlink; the type check, the read and the compile use one descriptor.
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    dir_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | nofollow
    parts = os.path.relpath(path, here).split(os.sep)
    fds = []
    try:
        try:
            fds.append(os.open(here, dir_flags))
            opened = os.fstat(fds[0])
            if (opened.st_dev, opened.st_ino) != here_id:
                raise SiblingLoadError("unreadable")
            for part in parts[:-1]:
                fds.append(os.open(part, dir_flags, dir_fd=fds[-1]))
            fds.append(os.open(parts[-1], os.O_RDONLY | nofollow | getattr(os, "O_NONBLOCK", 0), dir_fd=fds[-1]))
        except FileNotFoundError:
            raise SiblingLoadError("absent") from None
        except OSError:
            raise SiblingLoadError("unreadable") from None
        try:
            if not stat.S_ISREG(os.fstat(fds[-1]).st_mode):
                raise SiblingLoadError("not a regular file")
            with os.fdopen(fds[-1], "rb", closefd=False) as handle:
                source = handle.read()
        except OSError:
            raise SiblingLoadError("unreadable") from None
    finally:
        for fd in fds:
            os.close(fd)
    if not source:
        raise SiblingLoadError("empty")
    module = types.ModuleType(module_name)
    module.__file__ = path
    saved_path = list(sys.path)
    sys.modules[module_name] = module
    try:
        exec(compile(source, path, "exec"), module.__dict__)
    except BaseException:
        sys.modules.pop(module_name, None)
        raise
    finally:
        sys.path[:] = saved_path
    return module


def _sibling_refusal(prog, filename, exc):
    import sys
    why = exc.reason if isinstance(exc, SiblingLoadError) else type(exc).__name__
    if not why.replace(" ", "_").isidentifier():
        why = "BaseException"
    # The path comes from the checkout, so a control character in a folder name must not start a second output line
    # (a runner reads workflow commands at a line start): every non-printable character is written as its escape.
    shown = "".join(ch if ch.isprintable() else ascii(ch)[1:-1] for ch in _sibling_path(filename))
    print("%s: refused: sibling module %s at %s cannot be loaded (%s)" % (prog, filename, shown, why),
          file=sys.stderr, flush=True)
# <<< sibling-load 9399

SIBLING_PROG = "host-facts"
SIBLING_EXIT_LOAD_REFUSED = 3
try:
    _benchlib = _load_sibling("benchlib.py", "benchlib")
except (Exception, SystemExit) as exc:  # any failed load ends here with one fixed line (#9399)
    _sibling_refusal(SIBLING_PROG, "benchlib.py", exc)
    sys.exit(SIBLING_EXIT_LOAD_REFUSED)
host_facts, utc_stamp = _benchlib.host_facts, _benchlib.utc_stamp

REQUIRED_FACTS = ("cpu_model", "cpu_logical_cores", "mem_total_gib")
EXIT_OK = 0
EXIT_MISSING = 1


def main(argv=None):
    parser = argparse.ArgumentParser(prog=SIBLING_PROG, description=__doc__.split("\n\n")[0])
    parser.add_argument("--check", action="store_true", help="exit 1 when a required hardware fact is absent")
    args = parser.parse_args(argv)
    facts = host_facts()
    if args.check:
        missing = [key for key in REQUIRED_FACTS if not facts.get(key)]
        if missing:
            print("host-facts: MISSING " + ", ".join(missing), file=sys.stderr)
            return EXIT_MISSING
        print("host-facts: OK")
        return EXIT_OK
    print(json.dumps({"captured_at_utc": utc_stamp(), **facts}, indent=2))
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
