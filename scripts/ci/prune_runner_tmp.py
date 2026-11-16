#!/usr/bin/env python3
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""Prune stale entries of a self-hosted runner's own TMPDIR at job start (#8634).

Removes ONLY direct entries of one directory whose own mtime (lstat, never a
symlink target) is older than MAX_AGE_SECS. An old directory goes whole,
whatever its children's mtimes. Symlinks are unlinked, never followed. Nothing
outside that directory is touched, so a sibling ``runner-N`` directory is safe.

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
elsewhere than its normalized or its canonical path; an allowed root that is
relative or ``/``; an interpreter older than MIN_PYTHON; a mount table that
cannot be read (a missing or unreadable file, a malformed line, or a platform
with no mount table reader, macOS among them: it never prunes blind); a
platform where one of the descriptor-relative calls does not work.

The platform check is functional, never a membership table (the dir_fd
table of the os module differs between builds of one Python version):
inside the proven directory it creates a probe directory
``.prune-probe-<pid>-<hex>`` and a file in it, and makes one real
descriptor-relative call of each needed function (os.mkdir, os.open, os.lstat,
os.scandir, os.unlink, os.rmdir); the refusal names the first call that fails.
The probe removes what it made, also under ``--dry-run``; a probe it cannot
remove is named on stderr (``probe directory left in place``).

A per-entry failure is reported and counted, never fatal: exit 0 with
``pruned=<n> kept=<n> failed=<n> freed_bytes=<n> skipped=<n>``. An entry
on another device is skipped and reported, never entered. A path that is a
mount point (field 5 of ``/proc/self/mountinfo``, octal escapes decoded, so a
same-device bind mount is caught too) is neither entered nor removed: the
table is read again before and after each directory is opened and directly
before each unlink and rmdir; a table that cannot be read during the walk
leaves that entry untouched and is a counted failure. A tree deeper than MAX_TREE_DEPTH levels or with more
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


def python_refusal(version_info):
    """Return the refusal text when the interpreter is older than MIN_PYTHON, else None."""
    if tuple(version_info[:2]) < MIN_PYTHON:
        found = ".".join(str(part) for part in version_info[:3])
        wanted = ".".join(str(part) for part in MIN_PYTHON)
        return f"python {found} is older than {wanted}"
    return None


def refusal_annotation(reason):
    """The workflow annotation for a refusal; ``reason`` is already escaped."""
    return f"::warning title={PROG} refused::{PROG}: refused: {reason}"


if __name__ == "__main__" and python_refusal(sys.version_info) is not None:
    sys.stderr.write(f"{PROG}: refused: {python_refusal(sys.version_info)}\n")
    sys.stdout.write(refusal_annotation(python_refusal(sys.version_info)) + "\n")
    sys.exit(EXIT_OK)

import argparse  # noqa: E402  (the floor check above must run before anything newer is needed)
import os  # noqa: E402
import re  # noqa: E402
import stat  # noqa: E402
import time  # noqa: E402

SECS_PER_DAY = 86400
MAX_AGE_SECS = SECS_PER_DAY

# Confirmed runner roots (ruling f23a9ae4). A root is added only with the run
# whose prune-facts line shows a real runner TMPDIR under it; a guessed root was
# wrong on first contact (a lane-scratch directory on f2, run 43768137071). There is no f1
# root until its prune-facts line (run 43768136967) is quoted: the f1 step
# refuses visibly and the job continues.
F2_RUNNER_ROOT = "/ai-scratch/runner-tmp"  # confirmed: runs 43768137071, 43768136935, 43768136967 (runner-1, -3, -4)
ALLOWED_ROOTS = (F2_RUNNER_ROOT,)
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
# D-M1 (ruling b29 ed0d39b5): the mount table, read by one function (read_mount_table).
MOUNTINFO_PATH = "/proc/self/mountinfo"  # Linux: one line per mount of this process's namespace
MOUNTINFO_FLAGS = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
MOUNTINFO_READ_BYTES = 65536
MOUNTINFO_MAX_BYTES = 16 * 1024 * 1024  # a larger table is refused, never read in part
MOUNTINFO_MIN_FIELDS = 10  # id, parent, major:minor, root, mount point, options, "-", type, source, super options
MOUNTINFO_POINT_FIELD = 4  # field 5: the mount point
MOUNTINFO_OPTIONAL_FROM = 6  # optional fields start here and end at the "-" separator
MOUNTINFO_TAIL_FIELDS = 3  # type, source and super options follow the separator
MOUNTINFO_SEPARATOR = b"-"
MOUNTINFO_DEVICE_RE = re.compile(rb"[0-9]+:[0-9]+")
MOUNTINFO_FIELD_RE = re.compile(rb"(?:[^\\]|\\[0-3][0-7]{2})+")  # a backslash only as an octal escape
MOUNTINFO_ESCAPE_RE = re.compile(rb"\\([0-3][0-7]{2})")
LINUX_PLATFORM_PREFIX = "linux"
SKIP_OTHER_DEVICE = "on another device, not entered"
SKIP_MOUNT_POINT = "a mount point, not entered or removed"
SKIP_MOUNT_UNREADABLE = "mount table unreadable, not entered or removed"

# Every refusal reason, one named template each. docs/DEV-CI-ENVIRONMENT.md
# section 3.3 lists each template's fixed text; a test pins the two together.
REFUSAL_REASONS = {
    "python": "python {found} is older than {wanted}",
    "platform": "this platform lacks a working descriptor-relative call: {call} raised {error} ({why})",
    "mount_table": "the mount table cannot be read: {why}",
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
    "canonical_elsewhere": "TMPDIR is not the directory at its canonical path: {path}",
    "forbidden": "TMPDIR is a forbidden path: {path}",
    "not_owner": "TMPDIR is not owned by the current user: {path}",
    "not_runner_dir": "TMPDIR is not named runner-<digits>: {name}",
    "outside_roots": "TMPDIR is outside the allowed roots {roots}: {path}",
    "contains": "TMPDIR contains the home directory or the workspace: {path}",
}


class Refusal(Exception):
    """TMPDIR cannot be pruned; the message is the exact reason."""


class EntryChanged(OSError):
    """An entry no longer is the one the scan saw."""


class TreeTooLarge(OSError):
    """A tree deeper than MAX_TREE_DEPTH or larger than MAX_TREE_ENTRIES: counted before anything under it is removed."""


class MountTableUnreadable(OSError):
    """The mount table cannot be read or parsed; the message is the exact reason (fail closed)."""


class NotEntered(OSError):
    """A directory the walk does not enter: ``reason`` is the exact skip text; ``counted`` adds a counted failure."""

    def __init__(self, name, reason, counted):
        super().__init__(f"{name}: {reason}")
        self.name = name
        self.reason = reason
        self.counted = counted
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
    return Refusal(REFUSAL_REASONS[key].format(**{k: safe_text(v) for k, v in fields.items()}))


def safe_text(text):
    """Escape control characters, backslashes, ``%`` and every ``:`` so a name cannot inject a log line or workflow command.

    Every ``:`` becomes ``\\x3a`` (one pass, no later replace), so no run of colons of any length survives (D-L1).
    """
    pieces = []
    for char in str(text):
        code = ord(char)
        if char == "\\":
            pieces.append("\\\\")
        elif char == "%":
            pieces.append("\\x25")
        elif char == ":":
            pieces.append("\\x3a")
        elif code < 0x20 or 0x7F <= code <= 0x9F:
            pieces.append(f"\\x{code:02x}")
        elif 0xD800 <= code <= 0xDFFF or code in (0x2028, 0x2029):
            pieces.append(f"\\u{code:04x}")
        else:
            pieces.append(char)
    return "".join(pieces)


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
        shown.append(safe_text(name[:MAX_ANNOTATION_NAME_CHARS]) + (ANNOTATION_CUT_MARK if cut else ""))
    line = f"::warning title={PROG} failed::{PROG}: failed={count} not removed: " + ", ".join(shown)
    if count > MAX_ANNOTATION_NAMES:
        line += f" (list cut at {MAX_ANNOTATION_NAMES} of {count})"
    if len(line) > MAX_ANNOTATION_CHARS:
        line = line[: MAX_ANNOTATION_CHARS - len(ANNOTATION_CUT_MARK)] + ANNOTATION_CUT_MARK
    return line


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
    if RUNNER_DIR_PATTERN.fullmatch(name) is None:
        raise refuse("not_runner_dir", name=name)
    try:
        parent_fd = os.open("..", DIR_FLAGS, dir_fd=dir_fd)
    except (NotImplementedError, TypeError) as exc:
        raise PlatformMissing("os.open", exc) from exc
    try:
        parent_id = file_id(os.fstat(parent_fd))
    finally:
        os.close(parent_fd)
    if parent_id not in known_roots:
        raise refuse("outside_roots", roots=list(roots), path=os.path.realpath(path))
    for name_ in guarded_paths(environ):
        if file_id(info) in ancestor_ids(name_):
            raise refuse("contains", path=path)


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
    made_dir = made_file = False
    sub_fd = None
    try:
        os.mkdir(name, PROBE_DIR_MODE, dir_fd=dir_fd)
        made_dir = True
        call = "os.open"
        sub_fd = os.open(name, DIR_FLAGS, dir_fd=dir_fd)
        os.close(os.open(PROBE_FILE, PROBE_FILE_FLAGS, PROBE_FILE_MODE, dir_fd=sub_fd))
        made_file = True
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
    except (NotImplementedError, TypeError, OSError) as exc:
        raise PlatformMissing(call, exc) from exc
    finally:
        cleanup_probe(dir_fd, name, sub_fd, made_dir, made_file, err)


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


def read_mount_table():
    """D-M1 (ruling ed0d39b5): the raw mount table of this process; the one reader, behind one platform key.

    Linux: /proc/self/mountinfo, read whole (at most MOUNTINFO_MAX_BYTES). Every other platform, macOS
    among them, has no reader here: MountTableUnreadable, so the step refuses and never prunes blind.
    """
    if not sys.platform.startswith(LINUX_PLATFORM_PREFIX):
        raise MountTableUnreadable(f"no mount table reader for platform {sys.platform}")
    chunks, size = [], 0
    try:
        table_fd = os.open(MOUNTINFO_PATH, MOUNTINFO_FLAGS)
        try:
            while chunk := os.read(table_fd, MOUNTINFO_READ_BYTES):
                size += len(chunk)
                if size > MOUNTINFO_MAX_BYTES:
                    raise MountTableUnreadable(f"{MOUNTINFO_PATH} is larger than {MOUNTINFO_MAX_BYTES} bytes")
                chunks.append(chunk)
        finally:
            os.close(table_fd)
    except MountTableUnreadable:
        raise
    except OSError as exc:
        raise MountTableUnreadable(f"{MOUNTINFO_PATH} ({exc.strerror or type(exc).__name__})") from exc
    return b"".join(chunks)


def decode_mount_field(field, number):
    """Field 5 of mountinfo line ``number`` as a path: octal escapes (``\\040`` and the like) decoded."""
    if MOUNTINFO_FIELD_RE.fullmatch(field) is None:
        raise MountTableUnreadable(f"malformed line {number} of {MOUNTINFO_PATH}")
    raw = MOUNTINFO_ESCAPE_RE.sub(lambda match: bytes([int(match.group(1), 8)]), field)
    return os.fsdecode(raw)


def parse_mount_points(data):
    """Every mount point named in mountinfo ``data``; any malformed line (or no line) raises MountTableUnreadable."""
    lines = data.split(b"\n")
    if lines and lines[-1] == b"":
        lines.pop()
    points = set()
    for number, line in enumerate(lines, start=1):
        fields = line.split(b" ")
        if (
            len(fields) < MOUNTINFO_MIN_FIELDS
            or not fields[0].isdigit()
            or not fields[1].isdigit()
            or MOUNTINFO_DEVICE_RE.fullmatch(fields[2]) is None
            or MOUNTINFO_SEPARATOR not in fields[MOUNTINFO_OPTIONAL_FROM:-MOUNTINFO_TAIL_FIELDS]
        ):
            raise MountTableUnreadable(f"malformed line {number} of {MOUNTINFO_PATH}")
        point = decode_mount_field(fields[MOUNTINFO_POINT_FIELD], number)
        if not point.startswith("/"):
            raise MountTableUnreadable(f"malformed line {number} of {MOUNTINFO_PATH}")
        points.add(point)
    if not points:
        raise MountTableUnreadable(f"no mount line in {MOUNTINFO_PATH}")
    return points


class MountGuard:
    """D-M1: path checks of the walk against the mount table, read again on every check.

    ``root_path`` is the canonical path of the proven TMPDIR; only mount points below it are kept. The
    parse is reused while the table bytes are unchanged, but the table itself is read on every check.
    """

    def __init__(self, root_path):
        self.root_path = root_path
        self.prefix = root_path.rstrip("/") + "/"
        self._raw = None
        self._points = frozenset()

    def points(self):
        """The mount points below the root now; raises MountTableUnreadable."""
        data = read_mount_table()
        if data != self._raw:
            below = frozenset(point for point in parse_mount_points(data) if point.startswith(self.prefix))
            self._points, self._raw = below, data
        return self._points

    def check(self, path, name):
        """Raise NotEntered when ``path`` is a mount point (skip) or the table cannot be read (skip, counted)."""
        try:
            points = self.points()
        except MountTableUnreadable as exc:
            raise NotEntered(name, SKIP_MOUNT_UNREADABLE, counted=True) from exc
        if path in points:
            raise NotEntered(name, SKIP_MOUNT_POINT, counted=False)


def mount_guard(root_path):
    """The MountGuard of the proven directory after one good read of the table, or the mount_table refusal."""
    guard = MountGuard(root_path)
    try:
        guard.points()
    except MountTableUnreadable as exc:
        raise refuse("mount_table", why=str(exc)) from exc
    return guard


def canonical_root(path, info):
    """The canonical path of the proven directory (the form mountinfo names); it must open to the same file."""
    real = os.path.realpath(path)
    try:
        real_fd = os.open(real, DIR_FLAGS)
    except OSError as exc:
        raise refuse("canonical_elsewhere", path=real) from exc
    try:
        if file_id(os.fstat(real_fd)) != file_id(info):
            raise refuse("canonical_elsewhere", path=real)
    finally:
        os.close(real_fd)
    return real


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
    print(line, file=out)
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
            print(f"{PROG}: failed to remove {safe_text(name)}: {error_text(exc)}", file=self.err)

    def skip(self, name, reason=SKIP_OTHER_DEVICE):
        self.skipped += 1
        if self.skipped <= MAX_FAILURE_LINES:
            print(f"{PROG}: skipped {safe_text(name)}: {reason}", file=self.err)

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


def child_path(parent_path, name):
    """The path of entry ``name`` below ``parent_path`` (text only; every call still goes through a fd)."""
    return f"{parent_path}/{name}"


def open_checked(parent_fd, name, expected, guard, path):
    """Open directory ``name`` below ``parent_fd`` without following a symlink; prove it is the scanned entry
    and not a mount point (D-M1: the table is read before and again after the open, so a mount made
    between the check and the open is seen)."""
    guard.check(path, name)
    dir_fd = os.open(name, DIR_FLAGS, dir_fd=parent_fd)
    try:
        if entry_id(os.fstat(dir_fd)) != expected:
            raise EntryChanged("entry changed since scan")
        guard.check(path, name)
    except BaseException:
        os.close(dir_fd)
        raise
    return dir_fd


def list_level(dir_fd, dir_path, root_dev, tally, errors, guard, remove=True):
    """List an open directory; return its subdirectories as (name, lstat) pairs.

    ``remove=False`` is the count pass: every entry is counted against MAX_TREE_ENTRIES, nothing is
    removed or printed. ``remove=True`` unlinks the non-directories, each after a fresh mount-table
    check of its path; the bound is a backstop there against entries added after the count
    (TreeTooLarge stops the walk at once).
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
                if remove:
                    tally.skip(entry.name)
                errors.append(OSError(f"{entry.name} is on another device"))
            elif stat.S_ISDIR(info.st_mode):
                pending.append((entry.name, info))
            elif remove:
                guard.check(child_path(dir_path, entry.name), entry.name)
                os.unlink(entry.name, dir_fd=dir_fd)
                tally.freed += info.st_blocks * DISK_BLOCK_BYTES
        except NotEntered as exc:
            exc.nested = True
            tally.skip(entry.name, exc.reason)
            errors.append(exc)
        except OSError as exc:
            errors.append(exc)
    return pending


def count_tree(parent_fd, name, scanned, root_dev, tally, guard, path):
    """D-L3: walk the tree once without removing anything; raise TreeTooLarge over either bound."""
    tally.tree_entries = 0
    errors = []
    dir_fd = open_checked(parent_fd, name, entry_id(scanned), guard, path)
    names = [name]
    try:
        stack = [list_level(dir_fd, path, root_dev, tally, errors, guard, remove=False)]
        while stack:
            pending = stack[-1]
            if not pending:
                stack.pop()
                path = path[: -(len(names.pop()) + 1)]
                if stack:
                    up_fd = os.open("..", DIR_FLAGS, dir_fd=dir_fd)
                    os.close(dir_fd)
                    dir_fd = up_fd
                continue
            child_name, child_info = pending.pop()
            if len(stack) > MAX_TREE_DEPTH:
                raise TreeTooLarge(f"deeper than {MAX_TREE_DEPTH} levels")
            sub_path = child_path(path, child_name)
            try:
                child_fd = open_checked(dir_fd, child_name, entry_id(child_info), guard, sub_path)
            except OSError:
                continue  # not entered here; the removal pass reports it
            os.close(dir_fd)
            dir_fd = child_fd
            names.append(child_name)
            path = sub_path
            stack.append(list_level(dir_fd, path, root_dev, tally, errors, guard, remove=False))
    finally:
        os.close(dir_fd)


def checked_rmdir(parent_fd, name, path, guard, tally, errors):
    """rmdir ``name`` below ``parent_fd`` after a fresh mount-table check of ``path``; True when removed."""
    try:
        guard.check(path, name)
        os.rmdir(name, dir_fd=parent_fd)
        return True
    except NotEntered as exc:
        exc.nested = True
        tally.skip(name, exc.reason)
        errors.append(exc)
    except OSError as exc:
        errors.append(exc)
    return False


def remove_tree(parent_fd, name, scanned, root_dev, tally, guard, path):
    """Remove directory ``name`` (at ``path``) below ``parent_fd``: counted first, then iterative, one open
    directory at a time, never leaving ``root_dev``, never entering or removing a mount point."""
    count_tree(parent_fd, name, scanned, root_dev, tally, guard, path)
    errors = []
    tally.tree_entries = 0
    top_path = path
    dir_fd = open_checked(parent_fd, name, entry_id(scanned), guard, path)
    try:
        stack = [Level(name, scanned, list_level(dir_fd, path, root_dev, tally, errors, guard, remove=True))]
        while True:
            level = stack[-1]
            if level.pending:
                child_name, child_info = level.pending.pop()
                if len(stack) > MAX_TREE_DEPTH:
                    raise TreeTooLarge(f"deeper than {MAX_TREE_DEPTH} levels")
                sub_path = child_path(path, child_name)
                try:
                    child_fd = open_checked(dir_fd, child_name, entry_id(child_info), guard, sub_path)
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
                path = sub_path
                stack.append(Level(child_name, child_info, list_level(dir_fd, path, root_dev, tally, errors, guard, remove=True)))
                continue
            stack.pop()
            if not stack:
                break
            level_path = path
            path = path[: -(len(level.name) + 1)]
            up_fd = os.open("..", DIR_FLAGS, dir_fd=dir_fd)
            os.close(dir_fd)
            dir_fd = up_fd
            if file_id(os.fstat(dir_fd)) != stack[-1].file_id:
                raise EntryChanged("directory moved during removal")
            if checked_rmdir(dir_fd, level.name, level_path, guard, tally, errors):
                tally.freed += level.blocks * DISK_BLOCK_BYTES
        os.close(dir_fd)
        dir_fd = None
        if checked_rmdir(parent_fd, name, top_path, guard, tally, errors):
            tally.freed += level.blocks * DISK_BLOCK_BYTES
    finally:
        if dir_fd is not None:
            os.close(dir_fd)
    if errors:
        raise errors[0]


def remove_entry(dir_fd, name, scanned, root_dev, tally, guard, path):
    """Remove one top-level entry after an identity re-check and a fresh mount-table check; raise OSError on any failure."""
    now_info = os.lstat(name, dir_fd=dir_fd)
    if entry_id(now_info) != entry_id(scanned):
        raise EntryChanged("entry changed since scan")
    if stat.S_ISDIR(now_info.st_mode):
        remove_tree(dir_fd, name, now_info, root_dev, tally, guard, path)
        return
    guard.check(path, name)
    os.unlink(name, dir_fd=dir_fd)
    tally.freed += now_info.st_blocks * DISK_BLOCK_BYTES


def prune(dir_fd, root_dev, dry_run, now, out, tally, guard):
    """Prune old direct entries of the proven directory ``dir_fd`` (canonical path ``guard.root_path``) into ``tally``."""
    cutoff = now - MAX_AGE_SECS
    with os.scandir(dir_fd) as scan:
        for entry in scan:
            try:
                info = entry.stat(follow_symlinks=False)
                if info.st_mtime >= cutoff:
                    tally.kept += 1
                    continue
                if info.st_dev != root_dev:
                    tally.skip(entry.name)
                    continue
                path = child_path(guard.root_path, entry.name)
                if dry_run:
                    guard.check(path, entry.name)
                    print(f"would-remove {safe_text(entry.name)}", file=out)
                else:
                    remove_entry(dir_fd, entry.name, info, root_dev, tally, guard, path)
                tally.pruned += 1
            except NotEntered as exc:
                if not exc.nested:  # the top-level entry itself is not entered or removed
                    tally.skip(entry.name, exc.reason)
                    if exc.counted:
                        tally.fail(entry.name, exc)
                else:
                    tally.fail(entry.name, exc)
            except OSError as exc:  # one failed entry, counted
                tally.fail(entry.name, exc)


def refused(reason, out, err):
    """Print one refusal (stderr line and warning annotation); a refusal exits 0 and deletes nothing."""
    print(f"{PROG}: refused: {reason}", file=err)
    print(refusal_annotation(reason), file=out)
    out.flush()
    return EXIT_OK


def main(argv=None, environ=None, out=None, err=None):
    environ = os.environ if environ is None else environ
    out, err = out or sys.stdout, err or sys.stderr
    parser = argparse.ArgumentParser(prog=PROG, description=__doc__.split("\n")[0])
    parser.add_argument("--dry-run", action="store_true", help="print what would go, delete nothing")
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
            dir_fd, info = open_runner_dir(raw, ALLOWED_ROOTS, environ)
            guard = mount_guard(canonical_root(os.path.normpath(raw), info))
            probe_platform(dir_fd, err)
        except PlatformMissing as exc:
            return refused(exc.refusal(), out, err)
        except Refusal as exc:
            return refused(exc, out, err)
        prune(dir_fd, info.st_dev, args.dry_run, time.time(), out, tally, guard)
    except Exception as exc:  # internal error: named, no traceback, the job goes red (exit 1)
        tally.internal_error = True
        print(f"{PROG}: internal error, pruning stopped: {type(exc).__name__}: {safe_text(exc)}", file=err)
    finally:
        if dir_fd is not None:
            os.close(dir_fd)
    print(tally.summary(), file=out)
    if not tally.internal_error:
        annotation = failed_annotation(tally.failed, tally.first_failed)
        if annotation:
            print(annotation, file=out)
    out.flush()
    return EXIT_ERROR if tally.internal_error else EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
