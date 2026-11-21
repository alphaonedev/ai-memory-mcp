# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""Remove one directory tree only if the object that was proven is the object that is removed (#8216).

This module is imported by ``runner_disk_hook.py`` and by later pruning scripts. It imports nothing from
them and its interface has no hook types: a directory file descriptor, a name, and plain values.

Contract of ``check_and_remove(parent_fd, name, ...)``
  1. ``name`` is one path component. The directory is opened ONCE, relative to ``parent_fd``, with
     O_NOFOLLOW and O_DIRECTORY. Every later step acts on that descriptor, never on a path.
  2. The directory is on the device of the parent (or of ``expected_dev``); otherwise it is refused.
  3. When a ``TagSpec`` is given, the tag is proven through THAT descriptor: it is examined without
     following links, opened relative to the directory descriptor with O_NOFOLLOW and O_NONBLOCK (a FIFO
     cannot block the open), ``fstat`` on the open descriptor must say a regular file, and its first
     line must equal the signature. Every state has its own exact reason: missing, symlink, directory,
     fifo / socket / device (not a regular file), unreadable, wrong signature.
  4. A first pass over the tree (descriptors only, no path) refuses a tree deeper than ``max_depth`` or
     with more than ``max_entries`` entries, or holding a directory on another device, BEFORE anything
     is unlinked.
  5. The removal walks the same descriptor tree (a symlink is unlinked, never entered; no step crosses a
     device) and removes the tag LAST, so a removal that fails part way leaves a directory that the next
     call can still prove and clear. Directories that lack the owner's rwx bits are fixed through their
     own descriptor (``fchmod``); no file is ever chmodded, and no subprocess runs.
  6. The final ``rmdir`` is made by name in the parent only while that name still refers to the emptied
     directory (device and inode compared); a name that now refers to something else is left alone and
     reported as ``partial``.
  7. Nothing raises for a refusal or a failure: the result carries the status and the exact reason.
     ``dry_run=True`` does steps 1 to 4 and removes nothing (``would-remove``).

``open_directory`` is the one way to open a directory component fd by fd; it raises ``NotProven`` with
the exact reason. Python 3.12+, standard library only.
"""

import dataclasses
import enum
import errno
import os
import stat
from collections.abc import Iterator

MAX_TREE_DEPTH = 256
MAX_REMOVE_ENTRIES = 5_000_000
TAG_READ_BYTES = 256
OWNER_RWX = 0o700
CLOEXEC = getattr(os, "O_CLOEXEC", 0)
DIR_OPEN_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | CLOEXEC
TAG_OPEN_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | CLOEXEC
DEFAULT_DEVICE_LABEL = "its parent"

REASON_NOT_COMPONENT = "name is not a single path component"
REASON_MISSING = "directory does not exist"
REASON_SYMLINK = "directory is a symlink"
REASON_NOT_DIR = "path is not a directory"
REASON_REPLACED = (
    "the name now refers to another object than the emptied directory; it is left as it is"
)


class Status(enum.Enum):
    REMOVED = "removed"
    WOULD_REMOVE = "would-remove"
    REFUSED = "refused"
    PARTIAL = "partial"
    ABSENT = "absent"


@dataclasses.dataclass(frozen=True)
class TagSpec:
    """The file that proves a directory may be removed: its name and the exact first line."""

    name: str
    signature: bytes


@dataclasses.dataclass(frozen=True)
class Result:
    status: Status
    reason: str
    entries: int  # entries removed (status removed / partial) or seen (would-remove), the top directory excluded


class NotProven(Exception):
    """A directory could not be opened or proven; ``reason`` is the exact text, ``absent`` marks ENOENT."""

    def __init__(self, reason: str, absent: bool = False):
        super().__init__(reason)
        self.reason = reason
        self.absent = absent


class _Stop(Exception):
    """Internal: the first pass refuses the tree."""


def _strerror(exc: OSError) -> str:
    return exc.strerror or str(exc)


def _kind(mode: int) -> str:
    """Name of a non-regular file kind."""
    kind = "other"
    if stat.S_ISLNK(mode):
        kind = "symlink"
    elif stat.S_ISDIR(mode):
        kind = "directory"
    elif stat.S_ISFIFO(mode):
        kind = "fifo"
    elif stat.S_ISSOCK(mode):
        kind = "socket"
    elif stat.S_ISBLK(mode):
        kind = "block device"
    elif stat.S_ISCHR(mode):
        kind = "character device"
    return kind


def _is_component(name: str) -> bool:
    return name not in ("", ".", "..") and "/" not in name and "\0" not in name


def _make_owner_usable(parent_fd: int, name: str) -> None:
    """Add the owner's rwx bits to a directory that cannot be opened, by name, never following a link."""
    if os.chmod not in os.supports_follow_symlinks:
        raise PermissionError(errno.EACCES, "Permission denied")
    info = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    if not stat.S_ISDIR(info.st_mode):
        raise NotADirectoryError(errno.ENOTDIR, "Not a directory")
    os.chmod(name, stat.S_IMODE(info.st_mode) | OWNER_RWX, dir_fd=parent_fd, follow_symlinks=False)


def _raw_open_directory(parent_fd: int, name: str) -> int:
    try:
        return os.open(name, DIR_OPEN_FLAGS, dir_fd=parent_fd)
    except PermissionError:
        _make_owner_usable(parent_fd, name)
        return os.open(name, DIR_OPEN_FLAGS, dir_fd=parent_fd)


def open_directory(
    parent_fd: int,
    name: str,
    *,
    expected_dev: int | None = None,
    device_label: str = DEFAULT_DEVICE_LABEL,
) -> int:
    """Open ``name`` below ``parent_fd`` as a directory descriptor; raise ``NotProven`` with the exact reason."""
    if not _is_component(name):
        raise NotProven(REASON_NOT_COMPONENT)
    try:
        fd = os.open(name, DIR_OPEN_FLAGS, dir_fd=parent_fd)
    except OSError as first:
        raise NotProven(*_open_failure(parent_fd, name, first)) from first
    try:
        wanted = expected_dev if expected_dev is not None else os.fstat(parent_fd).st_dev
        if os.fstat(fd).st_dev != wanted:
            raise NotProven(f"directory is on another device than {device_label}")
    except BaseException:
        os.close(fd)
        raise
    return fd


def _open_failure(parent_fd: int, name: str, exc: OSError) -> tuple[str, bool]:
    """Exact reason and absence flag for a failed directory open, classified without following a link."""
    try:
        info = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except FileNotFoundError:
        return REASON_MISSING, True
    except OSError as err:
        return f"directory cannot be examined: {_strerror(err)}", False
    if stat.S_ISLNK(info.st_mode):
        return REASON_SYMLINK, False
    if not stat.S_ISDIR(info.st_mode):
        return REASON_NOT_DIR, False
    return f"directory cannot be opened: {_strerror(exc)}", False


def _prove_tag(dir_fd: int, tag: TagSpec) -> str | None:
    """Return the reason the tag is not proven through ``dir_fd``, or None."""
    try:
        info = os.stat(tag.name, dir_fd=dir_fd, follow_symlinks=False)
    except FileNotFoundError:
        return f"{tag.name} is missing"
    except OSError as exc:
        return f"{tag.name} cannot be examined: {_strerror(exc)}"
    if not stat.S_ISREG(info.st_mode):
        return _tag_kind_reason(tag, info.st_mode)
    try:
        tag_fd = os.open(tag.name, TAG_OPEN_FLAGS, dir_fd=dir_fd)
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            return f"{tag.name} is a symlink"
        return f"{tag.name} cannot be read: {_strerror(exc)}"
    try:
        opened = os.fstat(tag_fd)
        if not stat.S_ISREG(opened.st_mode):
            return _tag_kind_reason(tag, opened.st_mode)
        try:
            head = os.read(tag_fd, TAG_READ_BYTES)
        except OSError as exc:
            return f"{tag.name} cannot be read: {_strerror(exc)}"
    finally:
        os.close(tag_fd)
    if head.split(b"\n", 1)[0] != tag.signature:
        return f"{tag.name} first line is not the expected signature"
    return None


def _tag_kind_reason(tag: TagSpec, mode: int) -> str:
    kind = _kind(mode)
    reason = f"{tag.name} is not a regular file ({kind})"
    if kind in ("symlink", "directory"):
        reason = f"{tag.name} is a {kind}"
    return reason


def _list(dir_fd: int) -> list[tuple[str, bool]]:
    with os.scandir(dir_fd) as scan:
        return sorted((entry.name, entry.is_dir(follow_symlinks=False)) for entry in scan)


def _first_pass(dir_fd: int, dev: int, depth: int, max_depth: int, count: list[int], max_entries: int) -> None:
    """Walk descriptors only; raise ``_Stop`` before anything is unlinked."""
    if depth > max_depth:
        raise _Stop(f"tree deeper than {max_depth} levels, nothing removed")
    for name, is_dir in _list(dir_fd):
        count[0] += 1
        if count[0] > max_entries:
            raise _Stop(f"more than {max_entries} entries, nothing removed")
        if not is_dir:
            continue
        child = _raw_open_directory(dir_fd, name)
        try:
            if os.fstat(child).st_dev != dev:
                raise _Stop("a directory inside is on another device, nothing removed")
            _first_pass(child, dev, depth + 1, max_depth, count, max_entries)
        finally:
            os.close(child)


def _empty(dir_fd: int, dev: int, depth: int, max_depth: int, skip: str | None, done: list[int]) -> None:
    if depth > max_depth:
        raise OSError(errno.ELOOP, f"tree deeper than {max_depth} levels")
    _fix_owner_bits(dir_fd)
    for name, is_dir in _list(dir_fd):
        if skip is not None and name == skip:
            continue
        if not is_dir:
            os.unlink(name, dir_fd=dir_fd)
            done[0] += 1
            continue
        child = _raw_open_directory(dir_fd, name)
        try:
            if os.fstat(child).st_dev != dev:
                raise OSError(errno.EXDEV, "crosses a device boundary")
            _empty(child, dev, depth + 1, max_depth, None, done)
        finally:
            os.close(child)
        os.rmdir(name, dir_fd=dir_fd)
        done[0] += 1


def _fix_owner_bits(dir_fd: int) -> None:
    mode = stat.S_IMODE(os.fstat(dir_fd).st_mode)
    if mode & OWNER_RWX != OWNER_RWX:
        os.fchmod(dir_fd, mode | OWNER_RWX)


def check_and_remove(
    parent_fd: int,
    name: str,
    *,
    tag: TagSpec | None,
    dry_run: bool = False,
    expected_dev: int | None = None,
    device_label: str = DEFAULT_DEVICE_LABEL,
    max_depth: int = MAX_TREE_DEPTH,
    max_entries: int = MAX_REMOVE_ENTRIES,
) -> Result:
    """Prove and remove ``parent_fd/name`` as one object; see the module docstring for the contract."""
    try:
        dir_fd = open_directory(parent_fd, name, expected_dev=expected_dev, device_label=device_label)
    except NotProven as exc:
        return Result(Status.ABSENT if exc.absent else Status.REFUSED, exc.reason, 0)
    try:
        return _prove_and_remove(parent_fd, name, dir_fd, tag, dry_run, max_depth, max_entries)
    finally:
        os.close(dir_fd)


def _prove_and_remove(
    parent_fd: int,
    name: str,
    dir_fd: int,
    tag: TagSpec | None,
    dry_run: bool,
    max_depth: int,
    max_entries: int,
) -> Result:
    opened = os.fstat(dir_fd)
    if tag is not None:
        reason = _prove_tag(dir_fd, tag)
        if reason is not None:
            return Result(Status.REFUSED, reason, 0)
    count = [0]
    try:
        _first_pass(dir_fd, opened.st_dev, 0, max_depth, count, max_entries)
    except _Stop as stop:
        return Result(Status.REFUSED, str(stop), 0)
    except OSError as exc:
        return Result(Status.REFUSED, f"tree cannot be read: {_strerror(exc)}, nothing removed", 0)
    if dry_run:
        return Result(Status.WOULD_REMOVE, "", count[0])
    done = [0]
    try:
        _empty(dir_fd, opened.st_dev, 0, max_depth, tag.name if tag is not None else None, done)
        if tag is not None:
            os.unlink(tag.name, dir_fd=dir_fd)
            done[0] += 1
        return _rmdir_if_same(parent_fd, name, opened, done[0])
    except OSError as exc:
        status = Status.PARTIAL if done[0] > 0 else Status.REFUSED
        return Result(status, f"remove failed: {_strerror(exc)}", done[0])


def _rmdir_if_same(parent_fd: int, name: str, opened: os.stat_result, done: int) -> Result:
    try:
        now = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except FileNotFoundError:
        return Result(Status.REMOVED, "", done)
    if (now.st_dev, now.st_ino) != (opened.st_dev, opened.st_ino):
        return Result(Status.PARTIAL, REASON_REPLACED, done)
    os.rmdir(name, dir_fd=parent_fd)
    return Result(Status.REMOVED, "", done)


def iter_names(dir_fd: int) -> Iterator[str]:
    """Names in a directory descriptor, sorted (a helper for callers that list by fd)."""
    for entry_name, _ in _list(dir_fd):
        yield entry_name
