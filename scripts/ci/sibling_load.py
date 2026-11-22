#!/usr/bin/env python3
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""The one sibling-module loader of scripts/ (#9399, refs #9365 and #8216).

A script that needs a module from its own folder never asks the import search path for it: what runs would then be
whatever the search finds first (a same-named module on PYTHONPATH or in the working directory when the sibling is
absent, a module found beside a symlink instead of beside the real file, anything a ``sys.path`` insert leaves behind
for later callers). Every such script holds the block between the two marker lines below, byte for byte, and calls
``_load_sibling`` for each sibling it needs. A script cannot import this file by name either (that would be the same
defect), and a copy of the tree materialised from a base sha holds only the files the workflow lists, so the loader
travels INSIDE each script. ``test_sibling_load_9399`` pins every copy equal to this text, so there is one loader.

What ``_load_sibling(filename, module_name)`` does, for every way the script was started (by path from another working
directory, through a symlink, under ``python3 -I``, with decoys of the same name on PYTHONPATH and in the cwd):

* the trust anchor is the script's own folder, ``realpath(__file__)``'s folder: the file is that folder plus
  ``filename``, resolved; a result outside that folder raises ``SiblingLoadError`` ("symlink leaves the script
  folder"); a symlink that stays inside is resolved before the open;
* the resolved path is opened by descriptor, one component at a time: the script folder, then each folder below it
  with ``dir_fd`` on the folder before it, every one ``O_DIRECTORY | O_NOFOLLOW``, and the file ``O_NOFOLLOW |
  O_NONBLOCK`` (a FIFO open never blocks). The script folder opened must have the device and inode that a stat
  recorded right after the resolve, so a swap of that folder or of any folder above it, for a symlink or by a rename,
  is refused as "unreadable"; every folder below it and the file are opened relative to the descriptor before them
  and never through a symlink, so what is read lies inside that verified folder.
  ``fstat`` on the file descriptor must say regular file, and the bytes read from that descriptor are what gets
  compiled and run: no second open, no check on one object and use of another. Absent raises "absent", any other
  open or read failure "unreadable", a directory, FIFO or device "not a regular file", a file of zero bytes "empty".
  Every descriptor is non-inheritable (PEP 446: ``os.open`` sets it so), so no child started meanwhile holds one, and
  every descriptor is closed on every outcome;
* the module runs registered in ``sys.modules`` under ``module_name`` (a dataclass needs that during its own exec) and
  stays registered: a second script loading the same file in the same process gets the same object. A name already
  taken by a different file raises "module name taken", it is never reused;
* a failed exec removes the registration and the error reaches the caller with its own type;
* ``sys.path`` after the call equals ``sys.path`` before it, whatever the sibling did to it.

``_sibling_refusal`` prints the one fixed line a script prints before ending with its own exit code.
"""
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


if __name__ == "__main__":
    print("sibling_load.py holds the block every script embeds; it is not a command", file=sys.stderr)
    sys.exit(2)
