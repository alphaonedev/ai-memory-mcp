#!/usr/bin/env python3
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""Clear a self-hosted runner's own TMPDIR at the job boundary (#8634, #9820).

Removes ONLY direct entries of one directory. ``--mode job-end`` (the last step of a job, ``if: always()``)
removes every entry; ``--mode job-start`` (first step after checkout, for a job whose end step never ran) keeps
an entry whose own mtime (lstat, never a symlink target) is within JOB_START_GRACE_SECS, presumed owned by a
live writer. The clear is bound to the job boundary, never to polling for an idle runner. An entry that
carries an append-only or immutable flag has the flag cleared (descriptor-relative) and is removed. A removed
directory goes whole, whatever its children's mtimes. Symlinks are unlinked, never followed. Nothing
outside that directory is touched, so a sibling ``runner-N`` directory is safe. The directory is either
``<runner root>/runner-<digits>`` (Linux node) or ``<layout root>/<runner folder>/_tmp`` (macOS node).

The directory is PROVEN, by file identity and not by path text, to be this
runner's own ``<runner root>/runner-<digits>``: TMPDIR is opened once
(O_NOFOLLOW), the opened directory's own ``..`` must be the same file
(st_dev, st_ino) as one of the confirmed runner roots (ALLOWED_ROOTS, each a
named constant with the run that confirmed it), the last component must match
RUNNER_DIR_PATTERN, and every later check and every deletion goes through that
one descriptor. Anything it cannot prove ends in a named refusal (nothing
deleted; the reason goes to stderr and to a ``::warning`` annotation on stdout,
and the step still exits 0 so the rest of the job runs): TMPDIR unset, empty, relative, missing, a
symlink, not a directory, changed while opened, a forbidden path (``/``,
``/tmp``, the home directory, the workspace, the working directory), not owned
by the current user, not named runner-<digits>, outside the allowed roots,
containing the home directory or the workspace, resolving (by the kernel)
elsewhere than its normalized path; an allowed root that is relative or ``/``;
an interpreter older than MIN_PYTHON; a mount id of TMPDIR that cannot be read
(Linux); a platform where one of the descriptor-relative calls does not work.

The platform check is functional, never a membership table (the dir_fd
table of the os module differs between builds of one Python version):
inside the proven directory it creates a probe directory
``.prune-probe-<pid>-<hex>`` and a file in it, and makes one real
descriptor-relative call of each needed function (os.mkdir, os.open, os.lstat,
os.scandir, os.unlink, os.rmdir); the refusal names the first call that fails.
The probe removes what it made, also under ``--dry-run``; a probe it cannot
remove is named on stderr (``probe directory left in place``).

A per-entry failure is reported and counted, never fatal: exit 0 with
``pruned=<n> kept=<n> failed=<n> freed_bytes=<n> skipped=<n>``. A directory
on another device, or (Linux) on another mount than TMPDIR (the ``mnt_id`` of
``/proc/self/fdinfo/<fd>``, so a same-device bind mount is caught too), is
skipped and reported, never entered; a mount id that cannot be read is a skip
and a counted failure. A tree deeper than MAX_TREE_DEPTH levels or with more
than MAX_TREE_ENTRIES entries is one counted failure, counted before anything
under it is removed (a tree that grows past a bound while it is removed stops
there, partly removed, and is one counted failure). The facts line also goes
to the job summary (GITHUB_STEP_SUMMARY) when that is set. An unexpected
internal error stops the pruning, prints
a named line and exits 1 (the job goes red: that is a defect, not a
misconfiguration). ``--dry-run`` deletes nothing.

The top-level scan is one streaming ``os.scandir`` pass over a directory fd (no
list, no sort), so a directory of 600,000 entries costs constant memory.
Removal is an iterative, descriptor-relative walk (one open directory at a
time, no recursion, no ``shutil.rmtree``) with an identity re-check
(st_dev, st_ino, mode, st_ctime_ns) right before each entry is entered.
Python 3.12+, standard library only; the file itself parses on older
interpreters so the version refusal can run.
"""
import sys

MIN_PYTHON = (3, 12)
EXIT_OK = 0
EXIT_ERROR = 1
PROG = "prune_runner_tmp"
VERSION_REFUSAL_MAX_CHARS = 1000  # workflow_annotation.MAX_ANNOTATION_CHARS: the whole line, escapes included
VERSION_REFUSAL_CUT_MARK = "..."  # workflow_annotation.ANNOTATION_CUT_MARK


def python_refusal(version_info):
    """Return the refusal text when the interpreter is older than MIN_PYTHON, else None."""
    if tuple(version_info[:2]) < MIN_PYTHON:
        found = ".".join(str(part) for part in version_info[:3])
        wanted = ".".join(str(part) for part in MIN_PYTHON)
        return f"python {found} is older than {wanted}"
    return None


def version_text(text):
    """``workflow_annotation.safe_value`` restated for the version refusal, which runs before that module is loaded.

    Backslash doubles; ``%``, every ``:``, C0/C1 controls and DEL become ``\\xNN``; surrogates and U+2028/9 become
    ``\\uNNNN``; a ``#`` that is last or precedes ``#``/``[`` becomes ``\\x23`` and a ``[`` that follows ``#``
    becomes ``\\x5b`` (no v1 ``##[`` command, #9365); every other character stays. A test pins it byte-equal to
    ``safe_value`` over every code point.
    """
    text = str(text)
    last = len(text) - 1
    pieces = []
    for index, char in enumerate(text):
        code = ord(char)
        if char == "#" and (index == last or text[index + 1] in "#["):
            pieces.append("\\x23")
        elif char == "[" and index > 0 and text[index - 1] == "#":
            pieces.append("\\x5b")
        elif char == "\\":
            pieces.append("\\\\")
        elif char in "%:" or code < 0x20 or 0x7F <= code <= 0x9F:
            pieces.append("\\x%02x" % code)
        elif 0xD800 <= code <= 0xDFFF or code in (0x2028, 0x2029):
            pieces.append("\\u%04x" % code)
        else:
            pieces.append(char)
    return "".join(pieces)


def version_refusal_annotation(reason):
    """The version refusal's annotation, byte-equal to the shared module's ``annotation``/``render`` line, built without it."""
    # the fixed text is annotation("warning", render("{prog}: refused: {reason}", ...), title=f"{PROG} refused")
    line = "::warning title=prune_runner_tmp refused::prune_runner_tmp: refused: " + version_text(reason)
    if len(line) > VERSION_REFUSAL_MAX_CHARS:
        line = line[: VERSION_REFUSAL_MAX_CHARS - len(VERSION_REFUSAL_CUT_MARK)] + VERSION_REFUSAL_CUT_MARK
    return line


# The floor check runs before the shared module is loaded and before any name lookup but sys (ruling 598d069e):
# below MIN_PYTHON nothing else of this file runs.
if __name__ == "__main__" and python_refusal(sys.version_info) is not None:
    sys.stderr.write(f"{PROG}: refused: {python_refusal(sys.version_info)}\n")
    sys.stdout.write(version_refusal_annotation(python_refusal(sys.version_info)) + "\n")
    sys.exit(EXIT_OK)

SHARED_MODULE_FILE = "workflow_annotation.py"
SHARED_MODULE_USED = ("safe_value", "render", "join", "annotation", "log_line")  # every name this script takes from it
LOAD_CANNOT_READ = "cannot be read"
LOAD_RAISED = "raised while loading"
LOAD_LACKS = "lacks "


def load_shared_module(script_path):
    """Return ``(module, None)`` for the shared module next to ``script_path``'s real file, else ``(None, cause)``.

    The module is read from that one file and run in a fresh module object that is never put in ``sys.modules``:
    no import statement (the floor check above precedes every import except sys, pinned by a test), no finder and
    no ``sys.path`` lookup, nothing added to ``sys.path``. A module of the same name planted in the cwd, TMPDIR or
    PYTHONPATH, next to a symlink to this script, or already imported, is never the code this deleting tool runs.
    It runs only after the floor check (#9365, ruling 598d069e), where os is a frozen module.
    """
    paths = (sys.modules.get("os") or __import__("os")).path  # at or above the floor os is frozen (since 3.11)
    try:
        path = paths.join(paths.dirname(paths.realpath(script_path)), SHARED_MODULE_FILE)
        with open(path, "rb") as handle:
            source = handle.read()
    except (OSError, TypeError, ValueError):
        return None, LOAD_CANNOT_READ
    module = type(sys)(SHARED_MODULE_FILE[:-3])
    module.__file__ = path
    try:
        exec(compile(source, path, "exec", dont_inherit=True), module.__dict__)
    except (Exception, SystemExit):  # any failure of the sibling, a SyntaxError or a sys.exit in it included
        return None, LOAD_RAISED
    for name in SHARED_MODULE_USED:
        if not callable(getattr(module, name, None)):
            return None, LOAD_LACKS + name
    return module, None


wa, LOAD_FAILURE = load_shared_module(globals().get("__file__"))
safe_text = getattr(wa, "safe_value", None)  # the tests and the call sites below use it as a module attribute


def load_refused(out, err):
    """The load refusal: one fixed stderr line and one fixed annotation, both built without the shared module.

    It mirrors the version refusal (exit 0, not counted, nothing pruned): a sibling that cannot be loaded is a
    broken checkout, not a runner that could not be proven safe.
    """
    print(f"{PROG}: refused: shared module {SHARED_MODULE_FILE} next to the script cannot be loaded ({LOAD_FAILURE})",
          file=err)
    print("::warning title=prune_runner_tmp refused::prune_runner_tmp: refused: shared module workflow_annotation.py"
          " next to the script cannot be loaded", file=out)
    out.flush()
    return EXIT_OK


if __name__ == "__main__" and wa is None:
    sys.exit(load_refused(sys.stdout, sys.stderr))


def refusal_annotation(reason):
    """The workflow annotation for a refusal; ``reason`` is the raw text (a ``Refusal`` gives its ``raw``)."""
    raw = getattr(reason, "raw", reason)
    return wa.annotation("warning", wa.render("{prog}: refused: {reason}", prog=PROG, reason=raw), title=f"{PROG} refused")


import argparse  # noqa: E402  (the floor check above must run before anything newer is needed)
import errno  # noqa: E402
import fcntl  # noqa: E402
import os  # noqa: E402
import re  # noqa: E402
import stat  # noqa: E402
import struct  # noqa: E402
import time  # noqa: E402

# #9820: the clear is bound to the JOB BOUNDARY, never to polling for an idle runner (f1 runners go from one job
# to the next in 2 seconds, a 3-second poll never fired). Two modes, both run by a step of the job itself:
#   job-end   (``if: always()`` last step): nothing is kept, every entry of the runner's own TMPDIR goes.
#   job-start (first step after checkout, covers a cancelled or lost job whose end step never ran): an entry
#             touched within JOB_START_GRACE_SECS is presumed owned by a live writer and kept; the next
#             boundary removes it.
# decision: job-start plus job-end steps over polling an idle runner or a one-day age cut, because the runner
# has no event a poll can see in 2 seconds, and a one-day cut left up to 60 GiB a day in place.
MODE_JOB_START = "job-start"
MODE_JOB_END = "job-end"
MODES = (MODE_JOB_START, MODE_JOB_END)
JOB_START_GRACE_SECS = 30
GRACE_SECS_BY_MODE = {MODE_JOB_START: JOB_START_GRACE_SECS, MODE_JOB_END: 0}

# Confirmed runner roots (ruling f23a9ae4). A root is added only with the run
# whose prune-facts line shows a real runner TMPDIR under it; a guessed root was
# wrong on first contact (a lane-scratch directory on f2, run 43768137071). There is no f1
# root until its prune-facts line (run 43768136967) is quoted: the f1 step
# refuses visibly and the job continues.
F2_RUNNER_ROOT = "/ai-scratch/runner-tmp"  # confirmed: runs 43768137071, 43768136935, 43768136967 (runner-1, -3, -4)
ALLOWED_ROOTS = (F2_RUNNER_ROOT,)
# macOS node (f1) layouts: TMPDIR is ``<root>/<runner folder>/_tmp``. Confirmed 2026-11-21 from the runner ``.env``
# TMPDIR= lines (read only) of the two running f1 runners: /Users/Shared/actions-runner/_tmp and
# /Volumes/f1dev/rt/fed3/_tmp; the stopped runners use /Users/Shared/actions-runner-2/_tmp and
# /Users/Shared/f1-macos-fed-N/_tmp. No prune-facts line of an f1 run is quoted yet.
F1_SHARED_RUNNER_ROOT = "/Users/Shared"
F1_VOLUME_RUNNER_ROOT = "/Volumes/f1dev/rt"
RUNNER_FOLDER_LEAF = "_tmp"
RUNNER_FOLDER_LAYOUTS = (
    (F1_SHARED_RUNNER_ROOT, re.compile(r"(actions-runner|f1-macos-fed)(-[0-9]+)?")),
    (F1_VOLUME_RUNNER_ROOT, re.compile(r"fed[0-9]+")),
)
MAX_TREE_DEPTH = 10000  # directory levels below a top-level entry; deeper = one counted failure
MAX_TREE_ENTRIES = 5_000_000  # entries under one top-level entry; more = one counted failure
RUNNER_DIR_PATTERN = re.compile(r"runner-[0-9]+")
FORBIDDEN_PATHS = ("/", "/tmp", "/var/tmp", "/private/tmp")
DISK_BLOCK_BYTES = 512
MAX_FAILURE_LINES = 20
MAX_ANNOTATION_NAMES = 5  # names listed in the counted-failures annotation
MAX_ANNOTATION_NAME_CHARS = 120  # raw characters of one name before it is cut
MAX_ANNOTATION_CHARS = 1000  # the whole annotation line, escapes included
ANNOTATION_CUT_MARK = "..."
DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
FACTS_PREFIX = "prune-facts:"
SUMMARY_ENV = "GITHUB_STEP_SUMMARY"
SUMMARY_FLAGS = os.O_WRONLY | os.O_APPEND | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
PROBE_PREFIX = ".prune-probe-"
PROBE_FILE = ".prune-probe-file"
PROBE_DIR_MODE = 0o700
PROBE_FILE_MODE = 0o600
PROBE_FILE_FLAGS = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
PROBE_RANDOM_BYTES = 8
FDINFO_DIR = "/proc/self/fdinfo"  # Linux: one file per open fd; its mnt_id line names the fd's mount
FDINFO_MOUNT_FIELD = "mnt_id:"
FDINFO_MAX_BYTES = 65536
FDINFO_FLAGS = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
PLATFORM_LINUX = "linux"  # sys.platform, compared exactly: mount identity is the fd's mnt_id from fdinfo
PLATFORM_DARWIN = "darwin"  # sys.platform, compared exactly: mount identity is the fd's st_dev (no ctypes)
VERIFIABLE_PLATFORMS = (PLATFORM_LINUX, PLATFORM_DARWIN)  # decision 4: any other platform is a counted refusal
CANNOT_WRITE_ERRNOS = frozenset({errno.ENOSPC, errno.EDQUOT, errno.EROFS})  # decision 3: a full or read-only disk
PROBE_ABSENT_SUFFIX = "-absent"  # the read-only probe's name that is never created
SKIP_OTHER_DEVICE = "on another device, not entered"
SKIP_MOUNT_POINT = "a mount point, not entered"
SKIP_MOUNT_UNREADABLE = "mount id unreadable, not entered"

# Every refusal reason, one named template each. docs/DEV-CI-ENVIRONMENT.md
# section 3.3 lists each template's fixed text; a test pins the two together.
REFUSAL_REASONS = {
    "python": "python {found} is older than {wanted}",
    "platform": "this platform lacks a working descriptor-relative call: {call} raised {error} ({why})",
    "mount_unreadable": "the mount id of TMPDIR cannot be read: {why}",
    "mount_differs": "TMPDIR is not on its runner root's mount: {path}",
    "platform_unverifiable": "this platform cannot verify mount identity: {platform}",
    "root_relative": "allowed root is not an absolute path: {root}",
    "root_slash": "allowed root is '/'",
    "unset": "TMPDIR is unset",
    "empty": "TMPDIR is empty",
    "relative": "TMPDIR is not an absolute path: {path}",
    "missing": "TMPDIR does not exist: {path} ({why})",
    "symlink": "TMPDIR is a symlink: {path}",
    "not_dir": "TMPDIR is not a directory: {path}",
    "unopenable": "TMPDIR cannot be opened: {path} ({why})",
    "changed": "TMPDIR changed while it was opened: {path}",
    "resolves_elsewhere": "TMPDIR resolves elsewhere than its normalized path: {path}",
    "forbidden": "TMPDIR is a forbidden path: {path}",
    "not_owner": "TMPDIR is not owned by the current user: {path}",
    "not_runner_dir": "TMPDIR is not named runner-<digits>: {name}",
    "not_runner_folder": "TMPDIR is not <root>/<runner folder>/_tmp of an allowed layout: {path}",
    "outside_roots": "TMPDIR is outside the allowed roots {roots}: {path}",
    "contains": "TMPDIR contains the home directory or the workspace: {path}",
}


# Refusals about a runner that exists but cannot be proven safe: each is also one counted failure
# (decisions 1 and 4), so the summary reads failed=1 next to the one refusal annotation.
COUNTED_REFUSALS = frozenset({"mount_unreadable", "mount_differs", "platform_unverifiable"})


class Refusal(Exception):
    """TMPDIR cannot be pruned; the message is the exact reason (escaped for stderr), ``raw`` the same text as
    ``SafeText`` for the annotation; ``counted`` adds one counted failure."""

    counted = False

    def __init__(self, message, raw=None):
        super().__init__(message)
        self.raw = message if raw is None else raw


class EntryChanged(OSError):
    """An entry no longer is the one the scan saw."""


class TreeTooLarge(OSError):
    """A tree deeper than MAX_TREE_DEPTH or larger than MAX_TREE_ENTRIES: counted before anything under it is removed."""


class MountIdUnreadable(OSError):
    """The mount id of an open directory cannot be read (Linux only)."""


class NotEntered(OSError):
    """A place the walk does not enter (decision 2): one skip line, and always one counted failure.

    ``reason`` is the exact skip text.
    """

    def __init__(self, name, reason):
        super().__init__(f"{name}: {reason}")
        self.name = name
        self.reason = reason
        self.nested = False  # set when the directory is below a top-level entry
        self.escaped = f"{safe_text(name)}: {reason}"  # the reason is a constant; only the name is escaped


def error_text(exc):
    """The log text of ``exc``: escaped by safe_text unless the exception carries its own escaped text."""
    escaped = getattr(exc, "escaped", None)
    return escaped if isinstance(escaped, str) else safe_text(exc)


class PlatformMissing(Exception):
    """A descriptor-relative call does not work here; ``call`` names it."""

    def __init__(self, call, exc):
        super().__init__(call)
        self.call = call
        self.exc = exc

    def refusal(self):
        why = self.exc.strerror if isinstance(self.exc, OSError) and self.exc.strerror else str(self.exc)
        return refuse("platform", call=self.call, error=type(self.exc).__name__, why=why)


def refuse(key, **fields):
    """Build the Refusal for reason ``key`` with ``fields`` escaped for the log."""
    template = REFUSAL_REASONS[key]
    refusal = Refusal(template.format(**{k: safe_text(v) for k, v in fields.items()}), raw=wa.render(template, **fields))
    refusal.counted = key in COUNTED_REFUSALS
    return refusal


def failed_annotation(count, names):
    """The one ``::warning`` line for ``count`` entries that could not be removed; None when ``count`` is 0.

    ``names`` are the first MAX_ANNOTATION_NAMES failed names in sorted order. Every name goes
    through ``safe_text`` (findings L4, D-L1), so the only ``::`` in the line is the command's own.
    """
    if count <= 0:
        return None
    shown = []
    for name in list(names)[:MAX_ANNOTATION_NAMES]:
        cut = len(name) > MAX_ANNOTATION_NAME_CHARS
        shown.append(wa.render("{name}" + (ANNOTATION_CUT_MARK if cut else ""), name=name[:MAX_ANNOTATION_NAME_CHARS]))
    message = wa.render("{prog}: failed={count} not removed: {names}", prog=PROG, count=count, names=wa.join(", ", shown))
    if count > MAX_ANNOTATION_NAMES:
        message = wa.render("{message} (list cut at {limit} of {count})", message=message, limit=MAX_ANNOTATION_NAMES, count=count)
    return wa.annotation("warning", message, max_chars=MAX_ANNOTATION_CHARS, title=f"{PROG} failed")


def file_id(info):
    """Identity of a file: device and inode."""
    return (info.st_dev, info.st_ino)


def entry_id(info):
    """Identity of an entry for the re-check: device, inode, type bits and change time."""
    return (info.st_dev, info.st_ino, info.st_mode, info.st_ctime_ns)


def stat_or_none(path):
    """stat (following links) or None when the path cannot be stat-ed."""
    try:
        return os.stat(path)
    except OSError:
        return None


def ancestor_ids(path):
    """File identities of ``path`` (resolved) and every ancestor of it."""
    seen = set()
    current = os.path.realpath(path)
    while True:
        info = stat_or_none(current)
        if info is not None:
            seen.add(file_id(info))
        parent = os.path.dirname(current)
        if parent == current:
            return seen
        current = parent


def root_ids(roots):
    """Validate every root, return {(st_dev, st_ino): root} for the roots that exist."""
    found = {}
    slash = stat_or_none("/")
    for root in roots:
        if not os.path.isabs(root):
            raise refuse("root_relative", root=root)
        info = stat_or_none(root)
        if info is None:
            continue
        if slash is not None and file_id(info) == file_id(slash):
            raise refuse("root_slash")
        found[file_id(info)] = root
    return found


def guarded_paths(environ):
    """The home directory, the workspace and the working directory that must never be pruned or contained."""
    names = [os.path.expanduser("~"), environ.get("GITHUB_WORKSPACE"), os.getcwd()]
    return [name for name in names if name]


def open_runner_dir(raw, roots, environ):
    """Open TMPDIR once, prove it is ``<root>/runner-<digits>`` by identity; return (fd, info) or raise Refusal."""
    known_roots = root_ids(roots)
    if raw is None:
        raise refuse("unset")
    if raw == "":
        raise refuse("empty")
    if not os.path.isabs(raw):
        raise refuse("relative", path=raw)
    path = os.path.normpath(raw)
    try:
        first = os.lstat(path)
    except OSError as exc:
        raise refuse("missing", path=path, why=exc.strerror) from exc
    if stat.S_ISLNK(first.st_mode):
        raise refuse("symlink", path=path)
    if not stat.S_ISDIR(first.st_mode):
        raise refuse("not_dir", path=path)
    try:
        dir_fd = os.open(path, DIR_FLAGS)
    except OSError as exc:
        raise refuse("unopenable", path=path, why=exc.strerror) from exc
    try:
        info = os.fstat(dir_fd)
        if file_id(info) != file_id(first):
            raise refuse("changed", path=path)
        same_as_kernel_path(raw, info)
        prove_runner_dir(dir_fd, info, path, known_roots, roots, environ)
    except BaseException:
        os.close(dir_fd)
        raise
    return dir_fd, info


def same_as_kernel_path(raw, info):
    """LATE (:240): the kernel's resolution of ``raw`` must be the directory its normalized path opened.

    ``os.path.normpath`` drops ``<symlink>/..`` lexically, so ``<root>/lnk/../runner-2`` names the sibling
    ``<root>/runner-2`` while the kernel resolves it through the link target. Both are opened; a different
    identity, or a kernel path that cannot be opened, is a refusal.
    """
    try:
        kernel_fd = os.open(raw, DIR_FLAGS)
    except OSError as exc:
        raise refuse("resolves_elsewhere", path=raw) from exc
    try:
        if file_id(os.fstat(kernel_fd)) != file_id(info):
            raise refuse("resolves_elsewhere", path=raw)
    finally:
        os.close(kernel_fd)


def prove_runner_dir(dir_fd, info, path, known_roots, roots, environ):
    """Run the identity checks on the opened directory; raise Refusal on the first failure."""
    forbidden = [stat_or_none(p) for p in FORBIDDEN_PATHS]
    guarded = [stat_or_none(p) for p in guarded_paths(environ)]
    if any(item is not None and file_id(item) == file_id(info) for item in forbidden + guarded):
        raise refuse("forbidden", path=path)
    if info.st_uid != os.geteuid():
        raise refuse("not_owner", path=path)
    name = os.path.basename(path)
    if name == RUNNER_FOLDER_LEAF:
        prove_runner_folder_leaf(dir_fd, info, path)
    else:
        if RUNNER_DIR_PATTERN.fullmatch(name) is None:
            raise refuse("not_runner_dir", name=name)
        try:
            parent_fd = os.open("..", DIR_FLAGS, dir_fd=dir_fd)
        except (NotImplementedError, TypeError) as exc:
            raise PlatformMissing("os.open", exc) from exc
        try:
            parent = os.fstat(parent_fd)
            if file_id(parent) not in known_roots:
                raise refuse("outside_roots", roots=list(roots), path=os.path.realpath(path))
            same_mount_as_root(parent_fd, parent, dir_fd, info, path)
        finally:
            os.close(parent_fd)
    for name_ in guarded_paths(environ):
        if file_id(info) in ancestor_ids(name_):
            raise refuse("contains", path=path)


def prove_runner_folder_leaf(dir_fd, info, path):
    """#9820: prove TMPDIR is ``<layout root>/<runner folder>/_tmp`` by identity (the macOS node's form).

    The folder is TMPDIR's own ``..`` and the root is the folder's ``..`` (both opened without following a
    link); the root must be the same file as a RUNNER_FOLDER_LAYOUTS root whose pattern matches the folder's
    real name, and TMPDIR must be on that root's mount. Anything else is the refusal ``not_runner_folder``.
    """
    folder_name = os.path.basename(os.path.dirname(os.path.realpath(path)))
    try:
        folder_fd = os.open("..", DIR_FLAGS, dir_fd=dir_fd)
    except (NotImplementedError, TypeError) as exc:
        raise PlatformMissing("os.open", exc) from exc
    try:
        root_fd = os.open("..", DIR_FLAGS, dir_fd=folder_fd)
        try:
            root = os.fstat(root_fd)
            for layout_root, pattern in RUNNER_FOLDER_LAYOUTS:
                layout = stat_or_none(layout_root)
                if layout is not None and file_id(layout) == file_id(root) and pattern.fullmatch(folder_name):
                    same_mount_as_root(root_fd, root, dir_fd, info, path)
                    return
            raise refuse("not_runner_folder", path=os.path.realpath(path))
        finally:
            os.close(root_fd)
    finally:
        os.close(folder_fd)


def same_mount_as_root(parent_fd, parent, dir_fd, info, path):
    """SEC M1 (decision 1): TMPDIR's fd must be on the mount of its validated runner root fd.

    Checked before anything is made or opened under TMPDIR. A directory mounted over runner-<n> still has
    the root as its ``..``, so the root identity alone does not prove it. st_dev on every platform, and on
    Linux the fdinfo mnt_id of both fds (a same-device bind mount); unreadable or different is a refusal.
    """
    if parent.st_dev != info.st_dev:
        raise refuse("mount_differs", path=path)
    try:
        root_mnt, here = mount_id(parent_fd), mount_id(dir_fd)
    except MountIdUnreadable as exc:
        raise refuse("mount_unreadable", why=str(exc)) from exc
    if root_mnt != here:
        raise refuse("mount_differs", path=path)


class ProbeMismatch(OSError):
    """A probed call returned, but not what the call must return."""


def probe_platform(dir_fd, err):
    """D-H1: make one real descriptor-relative call of each needed function inside the proven directory.

    Creates ``.prune-probe-<pid>-<hex>`` and a file in it, then lstat, scandir, unlink and rmdir by dir_fd.
    Every call is looked up on ``os`` at call time, so the probe tests exactly the functions the walk uses.
    Raises PlatformMissing naming the first call that fails; a probe directory it cannot remove is named
    on ``err`` (before the refusal) and never touched again.
    """
    name = f"{PROBE_PREFIX}{os.getpid()}-{os.urandom(PROBE_RANDOM_BYTES).hex()}"
    call = "os.mkdir"
    creating = True  # only mkdir and the file create can fail for want of space (decision 3)
    cannot_write = None
    made_dir = made_file = False
    sub_fd = None
    try:
        os.mkdir(name, PROBE_DIR_MODE, dir_fd=dir_fd)
        made_dir = True
        call, creating = "os.open", False
        sub_fd = os.open(name, DIR_FLAGS, dir_fd=dir_fd)
        creating = True
        os.close(os.open(PROBE_FILE, PROBE_FILE_FLAGS, PROBE_FILE_MODE, dir_fd=sub_fd))
        made_file = True
        creating = False
        call = "os.lstat"
        seen = os.lstat(name, dir_fd=dir_fd)
        if not stat.S_ISDIR(seen.st_mode) or file_id(seen) != file_id(os.fstat(sub_fd)):
            raise ProbeMismatch("the probe directory is not the one opened")
        call = "os.scandir"
        with os.scandir(sub_fd) as scan:
            listed = [(entry.name, stat.S_ISREG(entry.stat(follow_symlinks=False).st_mode)) for entry in scan]
        if listed != [(PROBE_FILE, True)]:
            raise ProbeMismatch("the probe directory does not list its one file")
        call = "os.unlink"
        os.unlink(PROBE_FILE, dir_fd=sub_fd)
        made_file = False
        os.close(sub_fd)
        sub_fd = None
        call = "os.rmdir"
        os.rmdir(name, dir_fd=dir_fd)
        made_dir = False
    except OSError as exc:
        if not (creating and exc.errno in CANNOT_WRITE_ERRNOS):
            raise PlatformMissing(call, exc) from exc
        cannot_write = exc
    except (NotImplementedError, TypeError) as exc:
        raise PlatformMissing(call, exc) from exc
    finally:
        cleanup_probe(dir_fd, name, sub_fd, made_dir, made_file, err)
    if cannot_write is not None:
        probe_read_only(dir_fd, name + PROBE_ABSENT_SUFFIX, cannot_write.errno)
        why = safe_text(cannot_write.strerror or cannot_write)
        print(f"{PROG}: probe cannot write ({why}); the read-only probe passed, pruning goes on", file=err)


def probe_read_only(dir_fd, absent, cause):
    """CODE F1 (decision 3): the probe when the disk cannot take a file; it creates nothing.

    Every descriptor-relative function the walk uses must be in os.supports_dir_fd (os.stat also in
    os.supports_follow_symlinks, os.scandir in os.supports_fd); then lstat, unlink and rmdir of the name
    ``absent``, which does not exist, must fail with ENOENT (a read-only file system may answer EROFS when
    EROFS was the cause), and scandir of ``dir_fd`` must list. Raises PlatformMissing naming the first miss.
    """
    needed = (
        ("os.open", os.open, os.supports_dir_fd, "os.supports_dir_fd"),
        ("os.stat", os.stat, os.supports_dir_fd, "os.supports_dir_fd"),
        ("os.unlink", os.unlink, os.supports_dir_fd, "os.supports_dir_fd"),
        ("os.rmdir", os.rmdir, os.supports_dir_fd, "os.supports_dir_fd"),
        ("os.stat", os.stat, os.supports_follow_symlinks, "os.supports_follow_symlinks"),
        ("os.scandir", os.scandir, os.supports_fd, "os.supports_fd"),
    )
    for label, function, table, table_name in needed:
        if function not in table:
            raise PlatformMissing(label, ProbeMismatch(f"{label} not in {table_name}"))
    allowed = {errno.ENOENT} | ({errno.EROFS} if cause == errno.EROFS else set())
    for label, call in (
        ("os.lstat", lambda: os.lstat(absent, dir_fd=dir_fd)),
        ("os.unlink", lambda: os.unlink(absent, dir_fd=dir_fd)),
        ("os.rmdir", lambda: os.rmdir(absent, dir_fd=dir_fd)),
    ):
        try:
            call()
        except OSError as exc:
            if exc.errno in allowed:
                continue
            raise PlatformMissing(label, exc) from exc
        except (NotImplementedError, TypeError) as exc:
            raise PlatformMissing(label, exc) from exc
        raise PlatformMissing(label, ProbeMismatch(f"{label} of a name that does not exist returned"))
    try:
        with os.scandir(dir_fd) as scan:
            next(scan, None)
    except (NotImplementedError, TypeError, OSError) as exc:
        raise PlatformMissing("os.scandir", exc) from exc


def cleanup_probe(dir_fd, name, sub_fd, made_dir, made_file, err):
    """Best-effort removal of what the probe made, by dir_fd only; name a leftover, never raise."""
    if sub_fd is not None:
        if made_file:
            try:
                os.unlink(PROBE_FILE, dir_fd=sub_fd)
            except (NotImplementedError, TypeError, OSError):
                pass
        os.close(sub_fd)
    if made_dir:
        try:
            os.rmdir(name, dir_fd=dir_fd)
        except (NotImplementedError, TypeError, OSError):
            print(f"{PROG}: probe directory left in place: {safe_text(name)}", file=err)


def mount_id(fd):
    """The mount id of open ``fd``: the ``mnt_id:`` line of /proc/self/fdinfo/<fd> on Linux, None on Darwin
    (where st_dev per fd is the identity).

    Raises MountIdUnreadable when that line cannot be read on Linux, and on every other platform (CODE F3:
    fail closed, never "same mount").
    """
    if sys.platform == PLATFORM_DARWIN:
        return None
    if sys.platform != PLATFORM_LINUX:
        raise MountIdUnreadable(f"no mount id reader on {sys.platform}")
    try:
        info_fd = os.open(f"{FDINFO_DIR}/{int(fd)}", FDINFO_FLAGS)
        try:
            data = os.read(info_fd, FDINFO_MAX_BYTES)
        finally:
            os.close(info_fd)
    except OSError as exc:
        raise MountIdUnreadable(f"fdinfo unreadable ({exc.strerror})") from exc
    for line in data.decode("ascii", "replace").splitlines():
        if line.startswith(FDINFO_MOUNT_FIELD):
            value = line[len(FDINFO_MOUNT_FIELD):].strip()
            if value.isdigit():
                return int(value)
            break
    raise MountIdUnreadable("fdinfo has no mnt_id line")


def root_mount_id(dir_fd):
    """The mount id of the proven directory, or the mount_unreadable refusal."""
    try:
        return mount_id(dir_fd)
    except MountIdUnreadable as exc:
        raise refuse("mount_unreadable", why=str(exc)) from exc


def print_runner_facts(raw, roots, out):
    """Print one ``prune-facts:`` line and return it (no decision depends on it, an error is named, never raised)."""
    try:
        resolved = symlink = allowed = "unknown"
        if raw:
            norm = os.path.normpath(raw)
            real = os.path.realpath(raw)
            resolved = real
            symlink = "yes" if norm != real else "no"
            allowed = "none"
            parent = stat_or_none(os.path.dirname(real))
            for root in roots:
                info = stat_or_none(root)
                if parent is not None and info is not None and file_id(info) == file_id(parent):
                    allowed = root
                    break
        version = sys.version.splitlines()[0]
        line = (
            f"{FACTS_PREFIX} tmpdir={safe_text(raw)} resolved={safe_text(resolved)} symlink={symlink} "
            f"allowed_root={safe_text(allowed)} python={safe_text(version)} executable={safe_text(sys.executable)}"
        )
    except Exception as exc:  # print-only helper: never change the exit code
        line = f"{FACTS_PREFIX} error={type(exc).__name__}"
    print(wa.log_line(line), file=out)
    out.flush()
    return line


def write_job_summary(line, environ, err):
    """Append the (already escaped) facts line to GITHUB_STEP_SUMMARY when set; a failure is named, never raised.

    The file must exist (no O_CREAT) and must not be a symlink (O_NOFOLLOW); the exit code never changes.
    """
    path = environ.get(SUMMARY_ENV)
    if not path:
        return
    data = (line + "\n").encode("utf-8", "backslashreplace")
    try:
        summary_fd = os.open(path, SUMMARY_FLAGS)
        try:
            os.write(summary_fd, data)
        finally:
            os.close(summary_fd)
    except OSError as exc:
        print(f"{PROG}: job summary not written: {safe_text(exc.strerror or exc)}", file=err)


# Protected-entry flags (#9820): a test that leaves an append-only or immutable entry behind makes every
# unlink and rmdir below it fail with EPERM, so the clear drops the flag of the entry and of its directory
# (through the open descriptor, never a path) and retries once.
FS_IOC_GETFLAGS = 0x80086601  # linux, _IOR('f', 1, long)
FS_IOC_SETFLAGS = 0x40086602  # linux, _IOW('f', 2, long)
FS_APPEND_FL = 0x00000020
FS_IMMUTABLE_FL = 0x00000010
LINUX_PROTECT_FLAGS = FS_APPEND_FL | FS_IMMUTABLE_FL
DARWIN_PROTECT_FLAGS = getattr(stat, "UF_APPEND", 0x4) | getattr(stat, "UF_IMMUTABLE", 0x2)
ENTRY_OPEN_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_CLOEXEC", 0)
PROTECT_ERRNOS = frozenset({errno.EPERM, errno.EACCES})


def linux_flags(fd):
    """The ext-style inode flags of an open descriptor, or None when the file system has none."""
    try:
        return struct.unpack("l", fcntl.ioctl(fd, FS_IOC_GETFLAGS, struct.pack("l", 0)))[0]
    except OSError:
        return None


def linux_set_flags(fd, value):
    fcntl.ioctl(fd, FS_IOC_SETFLAGS, struct.pack("l", value))


def linux_clear_flags(dir_fd, name):
    """Clear append-only and immutable on the directory ``dir_fd`` and on its entry ``name``; True when one was cleared."""
    cleared = False
    for target, relative in ((".", True), (name, False)):
        try:
            fd = os.open(target, ENTRY_OPEN_FLAGS, dir_fd=dir_fd)
        except OSError:
            continue  # a symlink (O_NOFOLLOW), a vanished entry or an unopenable one has no flags to clear
        try:
            value = linux_flags(fd)
            if value is not None and value & LINUX_PROTECT_FLAGS:
                linux_set_flags(fd, value & ~LINUX_PROTECT_FLAGS)
                cleared = True
        except OSError:
            pass  # no capability to change the flag: the original removal error stands
        finally:
            os.close(fd)
    return cleared


def darwin_flags(target):
    """The BSD file flags (``st_flags``) of ``target`` (relative to the current directory), no link followed."""
    return getattr(os.lstat(target), "st_flags", 0)


def darwin_set_flags(target, value):
    os.chflags(target, value, follow_symlinks=False)


def darwin_clear_flags(dir_fd, name):
    """Clear user append-only and immutable on ``dir_fd`` and on its entry ``name``; True when one was cleared.

    ``chflags`` has no descriptor-relative form, so the process enters ``dir_fd`` (fchdir) for the call and goes
    back to where it was; the entry is named relative to that open directory, never by a path from TMPDIR.
    """
    cleared = False
    here = os.open(".", DIR_FLAGS)
    try:
        os.fchdir(dir_fd)
        for target in (".", name):
            try:
                value = darwin_flags(target)
                if value & DARWIN_PROTECT_FLAGS:
                    darwin_set_flags(target, value & ~DARWIN_PROTECT_FLAGS)
                    cleared = True
            except OSError:
                continue
    finally:
        os.fchdir(here)
        os.close(here)
    return cleared


FLAG_CLEARERS = {PLATFORM_LINUX: linux_clear_flags, PLATFORM_DARWIN: darwin_clear_flags}


def clear_flags(dir_fd, name):
    """Drop the protect flags for ``name`` in ``dir_fd`` on this platform; False when none was cleared."""
    clearer = FLAG_CLEARERS.get(sys.platform)
    return bool(clearer and clearer(dir_fd, name))


def unlink_entry(dir_fd, name):
    """``os.unlink`` that, on EPERM or EACCES, clears the protect flags once and retries."""
    try:
        os.unlink(name, dir_fd=dir_fd)
    except OSError as exc:
        if exc.errno not in PROTECT_ERRNOS or not clear_flags(dir_fd, name):
            raise
        os.unlink(name, dir_fd=dir_fd)


def rmdir_entry(dir_fd, name):
    """``os.rmdir`` with the same one clear-and-retry."""
    try:
        os.rmdir(name, dir_fd=dir_fd)
    except OSError as exc:
        if exc.errno not in PROTECT_ERRNOS or not clear_flags(dir_fd, name):
            raise
        os.rmdir(name, dir_fd=dir_fd)


class Tally:
    """Counters and the failure and skip lines (capped) of one run."""

    def __init__(self, err):
        self.pruned = self.kept = self.failed = self.skipped = self.freed = 0
        self.tree_entries = 0
        self.first_failed = []  # the MAX_ANNOTATION_NAMES smallest failed names, sorted
        self.internal_error = False
        self.err = err

    def fail(self, name, exc):
        self.failed += 1
        self.first_failed = sorted([*self.first_failed, name])[:MAX_ANNOTATION_NAMES]
        if self.failed <= MAX_FAILURE_LINES:
            # CODE F6: a top-level entry not entered is named once; its text is the constant reason alone
            text = exc.reason if isinstance(exc, NotEntered) and not exc.nested and exc.name == name else error_text(exc)
            print(wa.log_line(f"{PROG}: failed to remove {safe_text(name)}: {text}"), file=self.err)

    def skip(self, name, reason=SKIP_OTHER_DEVICE):
        self.skipped += 1
        if self.skipped <= MAX_FAILURE_LINES:
            print(wa.log_line(f"{PROG}: skipped {safe_text(name)}: {reason}"), file=self.err)

    def summary(self):
        text = f"pruned={self.pruned} kept={self.kept} failed={self.failed} freed_bytes={self.freed} skipped={self.skipped}"
        return text + (" internal_error=1" if self.internal_error else "")


class Level:
    """One directory of the iterative walk: its identity, size and the subdirectories still to enter."""

    __slots__ = ("name", "file_id", "blocks", "pending")

    def __init__(self, name, info, pending):
        self.name = name
        self.file_id = file_id(info)
        self.blocks = info.st_blocks
        self.pending = pending


def open_checked(parent_fd, name, expected, root_mnt):
    """Open directory ``name`` below ``parent_fd`` without following a symlink; prove it is the scanned entry
    and on the root's mount (D-M1: a mount point is never entered, whatever its st_dev)."""
    dir_fd = os.open(name, DIR_FLAGS, dir_fd=parent_fd)
    try:
        if entry_id(os.fstat(dir_fd)) != expected:
            raise EntryChanged("entry changed since scan")
        try:
            here = mount_id(dir_fd)
        except MountIdUnreadable as exc:
            raise NotEntered(name, SKIP_MOUNT_UNREADABLE) from exc
        if here != root_mnt:
            raise NotEntered(name, SKIP_MOUNT_POINT)
    except BaseException:
        os.close(dir_fd)
        raise
    return dir_fd


def list_level(dir_fd, root_dev, tally, errors, remove=True, dry_run=False):
    """List an open directory; return its subdirectories as (name, lstat) pairs.

    ``remove=False`` is the count pass: every entry is counted against MAX_TREE_ENTRIES, nothing is
    removed or printed. ``remove=True`` unlinks the non-directories; the bound is a backstop there
    against entries added after the count (TreeTooLarge stops the walk at once). ``dry_run`` takes the
    removal pass's decisions and prints its lines, and stops short of the unlink (decision 5).
    """
    pending = []
    try:
        with os.scandir(dir_fd) as scan:
            entries = list(scan)
    except OSError as exc:
        errors.append(exc)
        return pending
    for entry in entries:
        tally.tree_entries += 1
        if tally.tree_entries > MAX_TREE_ENTRIES:
            raise TreeTooLarge(f"more than {MAX_TREE_ENTRIES} entries under one top-level entry")
        try:
            info = entry.stat(follow_symlinks=False)
            if info.st_dev != root_dev:
                foreign = NotEntered(entry.name, SKIP_OTHER_DEVICE)
                foreign.nested = True  # decision 2: one skip line and a counted failure of its top-level entry
                if remove:
                    tally.skip(entry.name, foreign.reason)
                errors.append(foreign)
            elif stat.S_ISDIR(info.st_mode):
                pending.append((entry.name, info))
            elif remove and not dry_run:
                unlink_entry(dir_fd, entry.name)
                tally.freed += info.st_blocks * DISK_BLOCK_BYTES
        except OSError as exc:
            errors.append(exc)
    return pending


def count_tree(parent_fd, name, scanned, root_dev, root_mnt, tally):
    """D-L3: walk the tree once without removing anything; raise TreeTooLarge over either bound."""
    tally.tree_entries = 0
    errors = []
    dir_fd = open_checked(parent_fd, name, entry_id(scanned), root_mnt)
    try:
        # SEC L2 (decision 6): each level keeps its identity; the step up by ".." must land on it
        stack = [(file_id(os.fstat(dir_fd)), list_level(dir_fd, root_dev, tally, errors, remove=False))]
        while stack:
            pending = stack[-1][1]
            if not pending:
                stack.pop()
                if stack:
                    up_fd = os.open("..", DIR_FLAGS, dir_fd=dir_fd)
                    os.close(dir_fd)
                    dir_fd = up_fd
                    if file_id(os.fstat(dir_fd)) != stack[-1][0]:
                        raise EntryChanged("directory moved during count")
                continue
            child_name, child_info = pending.pop()
            if len(stack) > MAX_TREE_DEPTH:
                raise TreeTooLarge(f"deeper than {MAX_TREE_DEPTH} levels")
            try:
                child_fd = open_checked(dir_fd, child_name, entry_id(child_info), root_mnt)
            except OSError:
                continue  # not entered here; the removal pass reports it
            os.close(dir_fd)
            dir_fd = child_fd
            stack.append((file_id(os.fstat(dir_fd)), list_level(dir_fd, root_dev, tally, errors, remove=False)))
    finally:
        os.close(dir_fd)


def remove_tree(parent_fd, name, scanned, root_dev, tally, root_mnt=None, dry_run=False):
    """Remove directory ``name`` below ``parent_fd``: counted first, then iterative, one open directory at a
    time, never leaving ``root_dev`` or the root's mount. ``dry_run`` walks the same path and removes nothing."""
    if root_mnt is None:
        root_mnt = mount_id(parent_fd)
    count_tree(parent_fd, name, scanned, root_dev, root_mnt, tally)
    errors = []
    tally.tree_entries = 0
    dir_fd = open_checked(parent_fd, name, entry_id(scanned), root_mnt)
    try:
        stack = [Level(name, scanned, list_level(dir_fd, root_dev, tally, errors, remove=True, dry_run=dry_run))]
        while True:
            level = stack[-1]
            if level.pending:
                child_name, child_info = level.pending.pop()
                if len(stack) > MAX_TREE_DEPTH:
                    raise TreeTooLarge(f"deeper than {MAX_TREE_DEPTH} levels")
                try:
                    child_fd = open_checked(dir_fd, child_name, entry_id(child_info), root_mnt)
                except NotEntered as exc:
                    exc.nested = True
                    tally.skip(child_name, exc.reason)
                    errors.append(exc)
                    continue
                except OSError as exc:
                    errors.append(exc)
                    continue
                os.close(dir_fd)
                dir_fd = child_fd
                stack.append(Level(child_name, child_info,
                                   list_level(dir_fd, root_dev, tally, errors, remove=True, dry_run=dry_run)))
                continue
            stack.pop()
            if not stack:
                break
            up_fd = os.open("..", DIR_FLAGS, dir_fd=dir_fd)
            os.close(dir_fd)
            dir_fd = up_fd
            if file_id(os.fstat(dir_fd)) != stack[-1].file_id:
                raise EntryChanged("directory moved during removal")
            if dry_run:
                continue
            try:
                rmdir_entry(dir_fd, level.name)
                tally.freed += level.blocks * DISK_BLOCK_BYTES
            except OSError as exc:
                errors.append(exc)
        os.close(dir_fd)
        dir_fd = None
        if not dry_run:
            try:
                rmdir_entry(parent_fd, name)
                tally.freed += level.blocks * DISK_BLOCK_BYTES
            except OSError as exc:
                errors.append(exc)
    finally:
        if dir_fd is not None:
            os.close(dir_fd)
    if errors:
        raise errors[0]


def remove_entry(dir_fd, name, scanned, root_dev, tally, root_mnt=None, dry_run=False):
    """Remove one top-level entry after an identity re-check; raise OSError on any failure.

    ``dry_run`` makes every decision of the real run and stops short of the unlink (decision 5).
    """
    now_info = os.lstat(name, dir_fd=dir_fd)
    if entry_id(now_info) != entry_id(scanned):
        raise EntryChanged("entry changed since scan")
    if stat.S_ISDIR(now_info.st_mode):
        remove_tree(dir_fd, name, now_info, root_dev, tally, root_mnt, dry_run=dry_run)
        return
    if dry_run:
        return
    unlink_entry(dir_fd, name)
    tally.freed += now_info.st_blocks * DISK_BLOCK_BYTES


def prune(dir_fd, root_dev, dry_run, now, out, tally, root_mnt=None, grace_secs=JOB_START_GRACE_SECS):
    """Prune the direct entries of the proven directory ``dir_fd`` into ``tally``.

    An entry whose own mtime is within ``grace_secs`` of ``now`` is kept as owned by a live writer;
    ``grace_secs`` 0 (the job-end mode) keeps nothing.
    """
    if root_mnt is None:
        root_mnt = mount_id(dir_fd)
    cutoff = now - grace_secs
    with os.scandir(dir_fd) as scan:
        for entry in scan:
            try:
                info = entry.stat(follow_symlinks=False)
                if grace_secs > 0 and info.st_mtime >= cutoff:
                    tally.kept += 1
                    continue
                if info.st_dev != root_dev:
                    raise NotEntered(entry.name, SKIP_OTHER_DEVICE)
                remove_entry(dir_fd, entry.name, info, root_dev, tally, root_mnt, dry_run)
                if dry_run:
                    print(f"would-remove {safe_text(entry.name)}", file=out)
                tally.pruned += 1
            except NotEntered as exc:  # decision 2: every place not entered is one skip line and one counted failure
                if not exc.nested:  # the top-level entry itself is not entered; its nested skip is printed already
                    tally.skip(entry.name, exc.reason)
                tally.fail(entry.name, exc)
            except OSError as exc:  # one failed entry, counted
                tally.fail(entry.name, exc)


def refused(reason, out, err):
    """Print one refusal (stderr line and warning annotation); a refusal exits 0 and deletes nothing.

    A counted refusal (COUNTED_REFUSALS) also prints the summary with failed=1, so the runner that could
    not be proven safe shows as a counted failure next to its one annotation.
    """
    print(wa.log_line(f"{PROG}: refused: {reason}"), file=err)
    if getattr(reason, "counted", False):
        tally = Tally(err)
        tally.failed = 1
        print(wa.log_line(tally.summary()), file=out)
    print(refusal_annotation(reason), file=out)
    out.flush()
    return EXIT_OK  # ruling f23a9ae4: a refusal is green with its warning; only an internal error is red


def main(argv=None, environ=None, out=None, err=None):
    environ = os.environ if environ is None else environ
    out, err = out or sys.stdout, err or sys.stderr
    if wa is None:  # an in-process caller of a copy whose sibling did not load: the same refusal, nothing pruned
        return load_refused(out, err)
    parser = argparse.ArgumentParser(prog=PROG, description=__doc__.split("\n")[0])
    parser.add_argument("--dry-run", action="store_true", help="print what would go, delete nothing")
    parser.add_argument("--mode", choices=MODES, default=MODE_JOB_START,
                        help="job-start keeps entries touched in the last %d s; job-end removes every entry"
                        % JOB_START_GRACE_SECS)
    args = parser.parse_args(argv)
    raw = environ.get("TMPDIR")
    write_job_summary(print_runner_facts(raw, ALLOWED_ROOTS, out), environ, err)
    tally = Tally(err)
    dir_fd = None
    try:
        try:
            reason = python_refusal(sys.version_info)
            if reason:
                raise Refusal(reason)
            if sys.platform not in VERIFIABLE_PLATFORMS:  # CODE F3 (decision 4): no mount identity, no prune
                raise refuse("platform_unverifiable", platform=sys.platform)
            dir_fd, info = open_runner_dir(raw, ALLOWED_ROOTS, environ)
            root_mnt = root_mount_id(dir_fd)
            probe_platform(dir_fd, err)
        except PlatformMissing as exc:
            return refused(exc.refusal(), out, err)
        except Refusal as exc:
            return refused(exc, out, err)
        prune(dir_fd, info.st_dev, args.dry_run, time.time(), out, tally, root_mnt, GRACE_SECS_BY_MODE[args.mode])
    except Exception as exc:  # internal error: named, no traceback, the job goes red (exit 1)
        tally.internal_error = True
        print(wa.log_line(f"{PROG}: internal error, pruning stopped: {type(exc).__name__}: {safe_text(exc)}"), file=err)
    finally:
        if dir_fd is not None:
            os.close(dir_fd)
    print(wa.log_line(tally.summary()), file=out)
    if not tally.internal_error:
        annotation = failed_annotation(tally.failed, tally.first_failed)
        if annotation:
            print(annotation, file=out)
    out.flush()
    return EXIT_ERROR if tally.internal_error else EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
