#!/usr/bin/env python3
"""Cap the size of a self-hosted runner's ``target/debug`` build state (#7160).

Self-hosted jobs reuse the checkout's ``target/`` between runs, so
``target/debug/deps`` and friends grow without bound. This sweep sizes the
top-level entries of exactly four directories under ``<target>/debug``
(``deps``, ``incremental``, ``build``, ``.fingerprint``) and deletes the
oldest-mtime entries until the total is at or under ``--max-bytes``.

Safety:
  * ``--target`` must resolve (realpath) under ``$GITHUB_WORKSPACE`` unless
    ``--allow-root`` is given (node cron); otherwise exit 2 naming the path.
    ``--allow-root`` REQUIRES ``--within ROOT`` (exit 5 without it, and
    ``--within`` alone is exit 5 too; ``--lock`` and ``--lock-timeout`` are covered below): the script resolves BOTH the target and
    the root with ``os.path.realpath`` and exits 2 naming both resolved paths
    unless the resolved target is strictly inside the resolved root (not equal
    to it; the root ``/`` is refused). A symlinked parent such as the f2 runners'
    ``~/.cache/ai-memory-ci -> /mnt/t9/ai-memory-ci`` is therefore accepted only
    by containment, and a target resolving outside the root is refused. The
    descriptor walk below then runs on the RESOLVED path exactly as before, so a
    component swapped for a symlink after the resolution still fails closed
    (#7297 S11).
  * ``--lock FILE`` (the shared_target leg passes ``<root>/.evict.lock``, the
    flock of #7219's idle-target eviction) takes that lock exclusively while
    sweeping; ``FILE`` must sit directly in the resolved ``--within`` root and
    is opened ``O_NOFOLLOW``. If the lock is not taken within ``--lock-timeout``
    seconds (default 20; a finite number >= 0, ``0`` is one attempt) or cannot
    be opened or taken, one ``::warning::`` GitHub Actions annotation naming
    the real cause is printed on stdout, the summary line reads
    ``sweep skipped (<reason>)``, and the exit is 0 (the always-run step stays
    green; the next job sweeps). The reasons, verbatim: ``lock <path> not taken
    within <S> s (held by another process)`` (contention timeout, no errno);
    ``lock path is a symlink (not followed)``, ``lock path is a directory``,
    ``lock root is missing``, ``lock root or file is not writable`` and the
    fallback ``lock file cannot be opened``, each followed by ``: <path>
    [Errno N] <strerror>``; and ``lock <path> cannot be taken: [Errno N]
    <strerror>`` when the flock call itself fails. Every printed path and
    reason is escaped (``%``, CR, LF) so it stays on one line. The summary line also reports
    ``lock_wait=<s> lock_held=<s>`` (0.00 without ``--lock``); the lock is
    taken right before the walk and released right after the delete.
    Non-UTF-8 path bytes print as backslash escapes (no traceback). Nothing outside ``<target>/debug/{deps,incremental,
    build,.fingerprint}`` is ever read or deleted, so the in-use marker
    (``<target>/.in-use``), ``<root>/.evict.lock`` and the ``<root>/.evicting-*``
    directories are never entries of a sweep.
  * ``<target>/debug`` and the four swept directories must not be symlinks:
    otherwise exit 2 naming the path and nothing is deleted. A target path
    component that is not a directory (``--target`` names a regular file) exits
    2 with ``refused: <path> is not a directory``.
  * Every parent of the target must be searchable by the sweeping account;
    where the platform has ``O_PATH`` (Linux) the parents, the target and
    ``debug`` are opened with it and need no read permission. On macOS (no
    ``O_PATH``) every parent of the target must also be readable by the
    sweeping account, else nothing is swept (exit 4, ``cannot read``).
  * The target is opened once by a descriptor walk from ``/``: every path
    component (target, ``debug``, each swept directory) is opened relative to
    its parent with ``O_NOFOLLOW | O_DIRECTORY``, and every scan and every
    delete is relative to those handles (``dir_fd``). No path is looked up
    twice, so a component swapped for a symlink before the open, after the scan
    or during removal is never followed. A component that is no longer the
    directory that was opened is refused (exit 2) before anything is deleted.
  * Symlink entries inside a swept directory are unlinked, never descended.
  * Nothing outside the four directories is read for sizing or deleted.
  * An unreadable directory or entry at any depth is reported as
    ``warning: cannot read <path>`` (or ``cannot size`` / ``cannot remove``)
    naming the path and skipped; no traceback.
  * A top-level entry whose tree is deeper than ``MAX_TREE_DEPTH`` levels (or
    that hits a RecursionError) is skipped as a whole: one
    ``warning: cannot size <entry>: ... skipped`` names the entry, it is never
    counted and never on the delete list, so none of it is deleted (a partly
    deleted cargo output is worse than an oversized one).
  * A top-level entry that holds a directory that cannot be emptied (unreadable,
    or read-only so its files cannot be unlinked) is checked for that during the
    descriptor-relative sizing walk, before anything is deleted: it is kept
    whole, one ``warning: cannot remove <entry>: ... entry kept whole`` names it,
    and its bytes still count toward ``before=`` and ``after=`` (they stay on
    disk). The summary reports ``removed=`` (entries fully deleted) and
    ``freed=`` (bytes really unlinked, also after a removal that fails midway).

Exit codes: 0 success, 2 refused path (target outside the workspace, a
symlinked or swapped component, a target path component that is not a
directory, an ``--allow-root`` target not strictly inside ``--within``, or a
``--lock`` not directly inside the resolved ``--within`` root), 3 ``--max-bytes`` is zero or negative,
4 nothing could be sized because every swept directory or entry was
unreadable, 5 usage error (a missing, unknown or unparsable argument such as
``--max-bytes abc`` or an empty ``--max-bytes``; ``--allow-root`` without
``--within``, ``--within`` without ``--allow-root``, ``--lock`` without
``--allow-root``, or a negative, non-numeric or non-finite (``nan``, ``inf``)
``--lock-timeout``; ``--help`` exits 0). An unopenable or contended lock file
is not an error: the sweep is skipped with a warning and the exit is 0.
"""

import argparse
import errno
import fcntl
import math
import os
import stat
import sys
import time

DEBUG_DIR_NAME = "debug"
SWEPT_SUBDIRS = ("deps", "incremental", "build", ".fingerprint")
WORKSPACE_ENV = "GITHUB_WORKSPACE"
EXIT_OK = 0
EXIT_REFUSED = 2
EXIT_BAD_CAP = 3
EXIT_UNREADABLE = 4
EXIT_USAGE = 5
# Deeper than this an entry is skipped whole. Sizing and removal both recurse
# one frame per level, so a tree sized within this depth is also removable
# within it and removal can never stop half way on the interpreter limit.
MAX_TREE_DEPTH = 300
# errno values open() reports for a symlink (or non-directory) met under
# O_NOFOLLOW | O_DIRECTORY; Linux reports ENOTDIR, macOS reports ELOOP.
SWAPPED_ERRNOS = (errno.ELOOP, errno.ENOTDIR)
# Directories that are listed (scandir) need read permission: O_RDONLY.
OPEN_DIR_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_DIRECTORY
# Directories that are only walked through (``/``, every parent of the target,
# the target, ``debug``) are opened with O_PATH where the platform has it, so
# they need search permission only, as a full-path open does (Linux). Without
# O_PATH (macOS) this equals OPEN_DIR_FLAGS and every parent must be readable.
PARENT_OPEN_FLAGS = getattr(os, "O_PATH", 0) | os.O_NOFOLLOW | os.O_DIRECTORY


LOCK_POLL_SECS = 0.05
# One rule for every printed path or reason (#7297 R7-1): '%' first, then the
# line breaks, so a name can never split a line or start a workflow command.
LINE_ESCAPES = (("%", "%25"), ("\r", "%0D"), ("\n", "%0A"))
LOCK_FILE_MODE = 0o600
DEFAULT_LOCK_TIMEOUT_SECS = 20.0


def lock_open_reason(path, exc):
    """Name why ``path`` could not be opened as the lock file, with the OSError."""
    code = exc.errno
    if code == errno.ELOOP:
        what = "lock path is a symlink (not followed)"
    elif code == errno.EISDIR:
        what = "lock path is a directory"
    elif code == errno.ENOENT:
        what = "lock root is missing"
    elif code in (errno.EACCES, errno.EPERM, errno.EROFS):
        what = "lock root or file is not writable"
    else:
        what = "lock file cannot be opened"
    return "{}: {} [Errno {}] {}".format(what, path, code, exc.strerror)


def take_lock(path, timeout_secs):
    """Take the exclusive flock on ``path`` for at most ``timeout_secs``.

    Return ``(fd, None)`` when held, else ``(None, reason)`` where ``reason``
    names the real cause: an open failure (symlink, directory, unwritable or
    missing root, with the OSError errno and strerror) or a contention timeout
    (the caller skips the sweep, fail soft). The file is opened ``O_NOFOLLOW``
    so a symlinked lock file is never followed. Same primitive as
    ``evict_lock`` in scripts/ci/shared_cargo_target.py (#7219):
    ``LOCK_EX | LOCK_NB`` polled until the deadline.
    """
    try:
        fd = os.open(path, os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0),
                     LOCK_FILE_MODE)
    except OSError as exc:
        return None, lock_open_reason(path, exc)
    deadline = time.monotonic() + timeout_secs
    reason = "lock {} not taken within {} s (held by another process)".format(
        path, timeout_secs)
    while True:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return fd, None
        except BlockingIOError:
            if time.monotonic() >= deadline:
                break
            time.sleep(LOCK_POLL_SECS)
        except OSError as exc:
            reason = "lock {} cannot be taken: [Errno {}] {}".format(
                path, exc.errno, exc.strerror)
            break
    os.close(fd)
    return None, reason


def lock_timeout_arg(text):
    """argparse type: a finite float >= 0 (``nan``, ``inf`` and negatives are usage errors)."""
    try:
        value = float(text)
    except ValueError:
        raise argparse.ArgumentTypeError(
            "--lock-timeout must be a number of seconds, got {!r}".format(text))
    if not math.isfinite(value) or value < 0:
        raise argparse.ArgumentTypeError(
            "--lock-timeout must be a finite number >= 0, got {!r}".format(text))
    return value


def escape_line(text):
    """Escape ``%``, CR and LF (the Actions annotation rule) so ``text`` stays on one line."""
    text = str(text)
    for raw, escaped in LINE_ESCAPES:
        text = text.replace(raw, escaped)
    return text


def annotate_warning(message):
    """Print a GitHub Actions ``::warning::`` annotation on stdout (one line)."""
    print("::warning::ci-sweep-target: {}".format(escape_line(message)))


def configure_output():
    """Never raise on a non-UTF-8 path: undecodable bytes print as backslash escapes (#7297 S14)."""
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            reconfigure(errors="backslashreplace")


class UsageParser(argparse.ArgumentParser):
    """ArgumentParser whose parse errors exit EXIT_USAGE, not the refused-path code."""

    def error(self, message):
        self.print_usage(sys.stderr)
        self.exit(EXIT_USAGE, "{}: error: {}\n".format(self.prog, escape_line(message)))


class Refused(Exception):
    """A swept path is a symlink or was swapped after the scan."""


class SweptDir(object):
    """An open directory: its path, handle and the identity it had at open.

    ``parent_fd`` and ``name`` say how it was reached (``None`` for ``/``);
    ``chain`` lists every held directory from ``/`` down to this one, so the
    whole walk can be re-checked through descriptors, never through a path.
    """

    def __init__(self, path, fd, parent_fd, name, chain):
        opened = os.fstat(fd)
        self.path = path
        self.fd = fd
        self.parent_fd = parent_fd
        self.name = name
        self.dev = opened.st_dev
        self.ino = opened.st_ino
        self.chain = chain + [self]


def open_dir(name, dir_fd=None, listing=True):
    """Open a directory without following a symlink in its final component.

    ``listing=False`` opens a directory that is only walked through (see
    PARENT_OPEN_FLAGS); ``listing=True`` one that is scanned.
    """
    flags = OPEN_DIR_FLAGS if listing else PARENT_OPEN_FLAGS
    return os.open(name, flags, dir_fd=dir_fd)


class TooDeep(Exception):
    """An entry's tree is deeper than MAX_TREE_DEPTH."""


class SkippedWarning(str):
    """A warning for an entry skipped whole as too deep; it is not an unreadable-directory failure."""


def dir_is_writable(dir_fd):
    """Whether the account can unlink inside the open directory ``dir_fd``.

    ``os.access`` on ``"."`` relative to the held descriptor looks at that very
    directory (no path is resolved, a swapped component is irrelevant) and uses
    the effective ids where the platform supports it.
    """
    kwargs = {"dir_fd": dir_fd}
    if os.access in os.supports_effective_ids:
        kwargs["effective_ids"] = True
    return os.access(".", os.W_OK | os.X_OK, **kwargs)


def entry_size(dir_fd, name, path, warnings, depth=0, blockers=None):
    """Bytes under ``name`` (relative to ``dir_fd``) without following symlinks.

    A symlink counts as itself. A nested directory that cannot be listed is
    appended to ``warnings`` (same wording as the top-level unreadable-directory
    warning) and counts as its own size only. TooDeep (or RecursionError) is
    never caught here: it propagates so the caller drops the whole entry.

    ``blockers`` (a list, when given) collects one reason per directory in the
    entry that cannot be emptied: one that cannot be listed or opened, or one
    that is not writable (a read-only directory sizes cleanly but its files
    cannot be unlinked). An entry with any blocker is kept whole (S9).
    """
    st = os.lstat(name, dir_fd=dir_fd)
    if not stat.S_ISDIR(st.st_mode):
        return st.st_size
    if depth >= MAX_TREE_DEPTH:
        raise TooDeep("deeper than {} levels".format(MAX_TREE_DEPTH))
    total = st.st_size
    try:
        child_fd = open_dir(name, dir_fd)
    except OSError as exc:
        warnings.append("cannot read {}: {}".format(path, exc))
        if blockers is not None:
            blockers.append("{} cannot be read".format(path))
        return total
    try:
        try:
            with os.scandir(child_fd) as it:
                children = list(it)
        except OSError as exc:
            warnings.append("cannot read {}: {}".format(path, exc))
            if blockers is not None:
                blockers.append("{} cannot be read".format(path))
            return total
        if blockers is not None and not dir_is_writable(child_fd):
            blockers.append("{} is not writable".format(path))
        for child in children:
            try:
                child_path = os.path.join(path, child.name)
                total += entry_size(child_fd, child.name, child_path, warnings,
                                    depth + 1, blockers)
            except OSError as exc:
                warnings.append("cannot size {}/{}: {}".format(path, child.name, exc))
                if blockers is not None:
                    blockers.append("{} cannot be sized".format(child_path))
    finally:
        os.close(child_fd)
    return total


def is_under(path, root):
    try:
        return os.path.commonpath([path, root]) == root
    except ValueError:
        return False


def not_openable_message(parent, component, path):
    """Say why ``component`` under the held ``parent`` could not be opened as a directory.

    The target is a realpath, so a symlink here was swapped in after the check;
    anything else that is not a directory (a regular file) was never one.
    """
    try:
        kind = os.lstat(component, dir_fd=parent.fd).st_mode
    except OSError:
        kind = None
    if kind is not None and not stat.S_ISLNK(kind):
        return "{} is not a directory".format(path)
    return "{} was replaced by a symlink before it could be opened".format(path)


def open_target(real_target, warnings, handles):
    """Open ``real_target`` by walking it from ``/`` one component at a time.

    Each component is opened relative to its parent with ``O_NOFOLLOW |
    O_DIRECTORY``, so a component swapped for a symlink (or any non-directory)
    after the realpath check is refused, never followed. Returns the held
    ``SweptDir`` for the target, or ``None`` when the target does not exist or
    cannot be read (the latter is also appended to ``warnings``).
    """
    root_fd = open_dir(os.sep, listing=False)
    handles.append(root_fd)
    held = SweptDir(os.sep, root_fd, None, None, [])
    path = os.sep
    for component in [part for part in real_target.split(os.sep) if part]:
        path = os.path.join(path, component)
        try:
            fd = open_dir(component, held.fd, listing=False)
        except FileNotFoundError:
            return None
        except OSError as exc:
            if exc.errno in SWAPPED_ERRNOS:
                raise Refused(not_openable_message(held, component, path))
            warnings.append("cannot read {}: {}".format(path, exc))
            return None
        handles.append(fd)
        held = SweptDir(path, fd, held.fd, component, held.chain)
    return held


def open_child(parent, name, warnings, handles, listing=True):
    """Open directory ``name`` under the held ``parent``; None when absent or not a directory.

    Raises Refused when ``name`` is a symlink or is swapped for one while opening.
    """
    path = os.path.join(parent.path, name)
    try:
        st = os.lstat(name, dir_fd=parent.fd)
    except FileNotFoundError:
        return None
    except OSError as exc:
        warnings.append("cannot read {}: {}".format(path, exc))
        return None
    if stat.S_ISLNK(st.st_mode):
        raise Refused("{} is a symlink".format(path))
    if not stat.S_ISDIR(st.st_mode):
        return None
    try:
        fd = open_dir(name, parent.fd, listing=listing)
    except OSError as exc:
        if exc.errno in SWAPPED_ERRNOS:
            raise Refused("{} is a symlink".format(path))
        warnings.append("cannot read {}: {}".format(path, exc))
        return None
    handles.append(fd)
    return SweptDir(path, fd, parent.fd, name, parent.chain)


def open_swept_dirs(real_target, warnings, handles):
    """Open the existing swept directories; raise Refused on any symlink.

    The target, ``debug`` and each swept directory are reached through one
    descriptor walk (no path is looked up twice). Every opened descriptor is
    appended to ``handles`` for the caller to close.
    """
    target = open_target(real_target, warnings, handles)
    if target is None:
        return []
    debug = open_child(target, DEBUG_DIR_NAME, warnings, handles, listing=False)
    if debug is None:
        return []
    found = []
    for sub in SWEPT_SUBDIRS:
        swept = open_child(debug, sub, warnings, handles)
        if swept is not None:
            found.append(swept)
    return found


def collect_entries(target, warnings, handles):
    """Return (mtime, path, swept_dir, name, size, removable) for each top-level entry.

    Unreadable directories and entries are appended to ``warnings`` and skipped.
    An entry that holds a directory that cannot be emptied is returned with
    ``removable`` False after one warning naming it: it still counts toward the
    totals (its bytes stay on disk) but is never on the delete list.
    Descriptors stay open in ``handles`` so the delete phase reuses them.
    """
    entries = []
    for sdir in open_swept_dirs(target, warnings, handles):
        try:
            with os.scandir(sdir.fd) as it:
                children = list(it)
        except OSError as exc:
            warnings.append("cannot read {}: {}".format(sdir.path, exc))
            continue
        for child in children:
            child_path = os.path.join(sdir.path, child.name)
            blockers = []
            try:
                mtime = child.stat(follow_symlinks=False).st_mtime
                size = entry_size(sdir.fd, child.name, child_path, warnings,
                                  blockers=blockers)
            except (TooDeep, RecursionError) as exc:
                warnings.append(SkippedWarning(
                    "cannot size {}: too deep to walk ({}); entry skipped, nothing "
                    "of it deleted".format(child_path, exc)))
                continue
            except OSError as exc:
                warnings.append("cannot size {}: {}".format(child_path, exc))
                continue
            if blockers:
                warnings.append(SkippedWarning(
                    "cannot remove {}: {}; entry kept whole, nothing of it "
                    "deleted".format(child_path, blockers[0])))
            entries.append((mtime, child_path, sdir, child.name, size, not blockers))
    entries.sort(key=lambda item: (item[0], item[1]))
    return entries


def verify_unchanged(sdir):
    """Refuse when any held directory on the walk was replaced after the scan.

    Every link of the chain (``/`` to the swept directory) is looked up by name
    relative to the descriptor of its parent and compared with ``os.fstat`` of
    the handle that was opened; no full path is resolved.
    """
    for held in sdir.chain:
        if held.parent_fd is None:
            continue
        try:
            now = os.lstat(held.name, dir_fd=held.parent_fd)
            opened = os.fstat(held.fd)
        except OSError as exc:
            raise Refused("{} cannot be re-checked before delete: {}".format(held.path, exc))
        if stat.S_ISLNK(now.st_mode) or not stat.S_ISDIR(now.st_mode) \
                or (now.st_dev, now.st_ino) != (opened.st_dev, opened.st_ino):
            raise Refused("{} was replaced after the scan".format(held.path))


def remove_tree(parent_fd, name, freed):
    """Remove directory ``name`` under ``parent_fd`` using only descriptor-relative calls.

    ``freed`` is a one-element list that accumulates the bytes unlinked so far,
    so a removal that fails midway still reports what it really deleted.
    """
    fd = open_dir(name, parent_fd)
    try:
        with os.scandir(fd) as it:
            names = [child.name for child in it]
        for child in names:
            st = os.lstat(child, dir_fd=fd)
            if stat.S_ISDIR(st.st_mode):
                remove_tree(fd, child, freed)
            else:
                os.unlink(child, dir_fd=fd)
                freed[0] += st.st_size
    finally:
        os.close(fd)
    os.rmdir(name, dir_fd=parent_fd)


def remove_entry(sdir, name, freed):
    st = os.lstat(name, dir_fd=sdir.fd)
    if stat.S_ISDIR(st.st_mode):
        remove_tree(sdir.fd, name, freed)
    else:
        os.unlink(name, dir_fd=sdir.fd)
        freed[0] += st.st_size


def sweep(real_target, args, warnings, handles):
    """Scan, then delete oldest first; return (exit_code_or_None, before, remaining, removed)."""
    entries = collect_entries(real_target, warnings, handles)
    for line in warnings:
        print("warning: {}".format(escape_line(line)), file=sys.stderr)
    before = sum(item[4] for item in entries)
    remaining = before
    removed = 0
    verified = set()
    for _mtime, path, sdir, name, size, removable in entries:
        if remaining <= args.max_bytes:
            break
        if not removable:
            continue
        if not args.dry_run:
            if id(sdir) not in verified:
                verify_unchanged(sdir)
                verified.add(id(sdir))
            freed = [0]
            try:
                remove_entry(sdir, name, freed)
            except (OSError, RecursionError) as exc:
                remaining -= freed[0]
                print("warning: cannot remove {}: {} ({} bytes of it were deleted)".format(
                    escape_line(path), escape_line(exc), freed[0]), file=sys.stderr)
                continue
        remaining -= size
        removed += 1
    unreadable = [line for line in warnings if not isinstance(line, SkippedWarning)]
    code = EXIT_UNREADABLE if unreadable and not entries else EXIT_OK
    return code, before, remaining, removed


def main(argv=None):
    configure_output()
    parser = UsageParser(description=__doc__.splitlines()[0])
    parser.add_argument("--target", required=True, help="cargo target directory")
    parser.add_argument("--max-bytes", required=True, type=int, help="size cap in bytes")
    parser.add_argument("--allow-root", action="store_true",
                        help="permit a target outside $GITHUB_WORKSPACE (node cron); "
                             "requires --within")
    parser.add_argument("--within", default=None, metavar="ROOT",
                        help="with --allow-root: the directory the resolved target must "
                             "lie strictly inside")
    parser.add_argument("--lock", default=None, metavar="FILE",
                        help="with --allow-root: flock this file (it must sit directly in "
                             "the --within root, e.g. <root>/.evict.lock) while sweeping; "
                             "if it is not taken within --lock-timeout seconds print one "
                             "warning and skip the sweep with exit 0")
    parser.add_argument("--lock-timeout", type=lock_timeout_arg,
                        default=DEFAULT_LOCK_TIMEOUT_SECS, metavar="SECS",
                        help="longest wait for --lock, a finite number >= 0 (default {}; "
                             "0 is a single attempt)".format(DEFAULT_LOCK_TIMEOUT_SECS))
    parser.add_argument("--dry-run", action="store_true", help="report only; delete nothing")
    args = parser.parse_args(argv)
    if args.allow_root and not args.within:
        parser.error("--allow-root requires --within ROOT")
    if args.within and not args.allow_root:
        parser.error("--within is only valid with --allow-root")
    if args.lock and not args.allow_root:
        parser.error("--lock is only valid with --allow-root")
    if args.max_bytes <= 0:
        print("usage: --max-bytes must be a positive integer, got {}".format(
            args.max_bytes), file=sys.stderr)
        return EXIT_BAD_CAP

    real_target = os.path.realpath(args.target)
    if not args.allow_root:
        workspace = os.environ.get(WORKSPACE_ENV)
        real_ws = os.path.realpath(workspace) if workspace else None
        if real_ws is None or not is_under(real_target, real_ws):
            print("refused: {} is not under {} (use --allow-root)".format(
                escape_line(real_target), WORKSPACE_ENV), file=sys.stderr)
            return EXIT_REFUSED
    else:
        real_root = os.path.realpath(args.within)
        if (real_root == os.sep or real_target == real_root
                or not is_under(real_target, real_root)):
            print("refused: resolved target {} is not strictly inside resolved --within "
                  "root {}".format(escape_line(real_target), escape_line(real_root)),
                  file=sys.stderr)
            return EXIT_REFUSED

    lock_fd = None
    lock_held = 0.0
    lock_wait = 0.0
    lock_taken_at = None
    if args.lock:
        lock_dir, lock_name = os.path.split(os.path.abspath(args.lock))
        if (not lock_name or lock_name in (".", "..")
                or os.path.realpath(lock_dir) != real_root):
            print("refused: --lock {} is not a file directly inside the resolved --within "
                  "root {}".format(escape_line(args.lock), escape_line(real_root)),
                  file=sys.stderr)
            return EXIT_REFUSED
        wait_started = time.monotonic()
        lock_fd, skip_reason = take_lock(os.path.join(real_root, lock_name),
                                         args.lock_timeout)
        lock_taken_at = time.monotonic()
        lock_wait = lock_taken_at - wait_started
        if lock_fd is None:
            annotate_warning("{}; sweep skipped, target uncapped this run".format(skip_reason))
            print("ci-sweep-target: sweep skipped ({}) target={} lock_wait={:.2f} "
                  "lock_held=0.00".format(escape_line(skip_reason), escape_line(real_target),
                                     lock_wait))
            return EXIT_OK

    warnings = []
    handles = []
    try:
        code, before, remaining, removed = sweep(real_target, args, warnings, handles)
    except Refused as exc:
        print("refused: {}".format(escape_line(exc)), file=sys.stderr)
        return EXIT_REFUSED
    finally:
        for fd in handles:
            try:
                os.close(fd)
            except OSError:
                # Best-effort cleanup: a descriptor that is already closed or invalid needs no further action.
                pass
        if lock_fd is not None:
            os.close(lock_fd)  # closing the descriptor releases the flock
            lock_held = time.monotonic() - lock_taken_at
    print("ci-sweep-target: target={} cap={} before={} after={} removed={} freed={} "
          "lock_wait={:.2f} lock_held={:.2f}{}".format(
              escape_line(real_target), args.max_bytes, before, remaining, removed, before - remaining,
              lock_wait, lock_held, " (dry-run)" if args.dry_run else ""))
    return code


if __name__ == "__main__":
    sys.exit(main())
