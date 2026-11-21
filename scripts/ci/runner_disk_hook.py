#!/opt/homebrew/bin/python3.12
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""Self-hosted runner disk hook: clear this runner's cargo target directories when the boot disk runs low (#8216).

The GitHub Actions runner calls this file as its job-started hook and as its job-completed
hook (``ACTIONS_RUNNER_HOOK_JOB_STARTED`` and ``ACTIONS_RUNNER_HOOK_JOB_COMPLETED``, each set to
``<this file> --event <event>``). Three runners on one boot disk each keep a cargo ``target``
directory in their work folder (27 to 51 GiB each, growing per job); a full disk ends every job
and every lane on the host.

Behaviour
  --event job-completed   when the boot disk has less than CLEAR_BELOW_GIB_AFTER_JOB GiB free after a
                          job, remove the cargo target directories in THIS runner's work folder.
  --event job-started     the same check with the floor START_FLOOR_GIB GiB, so a job never starts
                          below that floor without clearing first. This event also does what the
                          old shell hook did: remove ``.local-runs/test-tmp`` below the workspace
                          after stripping macOS ACLs (``chmod -RN``, then ``chmod -R u+rwx``).
                          There is no sudo fallback: a hook must never wait on a password prompt; a
                          directory that still cannot be removed is one reason in the log line.

Layout supported (read from a real runner work folder and the runner's variable semantics)
  RUNNER_WORKSPACE is ``<runner root>/_work/<repo>`` and GITHUB_WORKSPACE is
  ``<RUNNER_WORKSPACE>/<repo>``. The work root is RUNNER_WORKSPACE (or ``--work-root``); a candidate
  is ``<work root>/<repo>/target``, which is ``$GITHUB_WORKSPACE/target``. Any other name
  (``Target``, ``target2``) or depth is kept. The work root of one runner is never another runner's.

Removal invariant: a directory is removed only when ALL hold, and every other case is a refusal
with its own exact reason, nothing removed
  1. the work root is set, non-empty, absolute, normalized, not ``/``, not the home directory, has at
     least WORK_ROOT_MIN_PARTS path parts below ``/``, exists, is a real directory (lstat, not a
     symlink) and is not a mount point (volume root);
  2. the candidate is named exactly ``target``, sits at ``<work root>/<repo>/target``, is a real
     directory (lstat), its resolved path stays inside the resolved work root, and it is on the work
     root's device;
  3. it holds cargo's ``CACHEDIR.TAG`` (a regular file, not a symlink) whose first line is the cache
     directory signature; a target without the tag is refused and never removed;
  4. the removal works through directory file descriptors opened with O_NOFOLLOW (a symlink inside
     the tree is unlinked, never entered) and never crosses a device boundary (st_dev).
A free-space read that fails, returns nothing or returns a negative value is a refusal to decide:
nothing is removed (not even the test-tmp directories), the reason is logged; it is never read as 0
free or as plenty free.

Exit code is 0 on every path, refusals and errors included, with the reason in the log line and on
stderr. decision: exit 0 over a failing exit, because a failing runner hook turns every job on that
runner red and hides the real result; the conductor's disk waiter is the backstop.

Log: every call appends exactly one line to the log (``--log``, else the absolute path in $RUNNER_DISK_HOOK_LOG,
else ``<home>/ai-tmp/runner-disk-hook.log``; no host path is written in this file; the line also carries
folder_bytes_before and folder_bytes_after, the work folder size at job start; WORK_FOLDER_CEILING_GIB is its ceiling):
  <UTC time> runner=<name> event=<event> free_before_gib=<n|unknown> free_after_gib=<n|unknown>
  folder_bytes_before=<n|unknown> folder_bytes_after=<n|unknown> decision=<clear|enough-free|refused> removed=<count> paths=<JSON list> reason=<JSON string>[ dry-run]
``removed`` counts the directories removed (in a dry run, the ones that would be). decision: a log
that cannot be written (a full disk is the usual cause) does not stop the removal; the failure goes
to stderr with the line, because refusing to clear would keep the disk full.

``--dry-run`` takes the full decision and writes the log line, and removes nothing. The old shell
hook's unbounded ``find`` fallback for a ``test-tmp`` directory is not ported: only
``<base>/.local-runs/test-tmp`` for the work root, the workspace and the workspace's parent.

Python 3.12+, standard library only.
"""

import argparse
import dataclasses
import datetime
import enum
import errno
import json
import math
import os
import re
import shutil
import stat
import subprocess
import sys
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path

GIB = 1024**3
CLEAR_BELOW_GIB_AFTER_JOB = 150
START_FLOOR_GIB = 60
WORK_FOLDER_CEILING_GIB = 40
WORK_FOLDER_CEILING_BYTES = WORK_FOLDER_CEILING_GIB * GIB
MAX_WALK_ENTRIES = 5_000_000
DEFAULT_LOG_ENV = "RUNNER_DISK_HOOK_LOG"
DEFAULT_LOG_PARTS = ("ai-tmp", "runner-disk-hook.log")
TARGET_DIR_NAME = "target"
MARKER_FILE_NAME = "CACHEDIR.TAG"
MARKER_SIGNATURE = "Signature: 8a477f597d28d172789f06886806bc55"
MARKER_READ_BYTES = 256
TEST_TMP_PARTS = (".local-runs", "test-tmp")
WORK_ROOT_MIN_PARTS = 3
MAX_TREE_DEPTH = 256
CHMOD_TIMEOUT_SECS = 300
RUNNER_NAME_PATTERN = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
ENV_WORK_ROOT = "RUNNER_WORKSPACE"
ENV_WORKSPACE = "GITHUB_WORKSPACE"
ENV_RUNNER_NAME = "RUNNER_NAME"
UNKNOWN = "unknown"
INVALID = "invalid"
EXIT_OK = 0
REASON_SEPARATOR = "; "
DIR_OPEN_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)


class Event(enum.Enum):
    JOB_STARTED = "job-started"
    JOB_COMPLETED = "job-completed"


class Decision(enum.Enum):
    CLEAR = "clear"
    ENOUGH_FREE = "enough-free"
    REFUSED = "refused"


def floor_gib(event: Event) -> int:
    match event:
        case Event.JOB_STARTED:
            return START_FLOOR_GIB
        case Event.JOB_COMPLETED:
            return CLEAR_BELOW_GIB_AFTER_JOB
        case _:
            raise ValueError(f"unknown event {event!r}")


@dataclasses.dataclass(frozen=True)
class LogContext:
    """What a log line needs even when the arguments could not be parsed."""

    event: str
    runner: str
    log_path: Path
    dry_run: bool


@dataclasses.dataclass(frozen=True)
class Config:
    event: Event
    work_root: Path
    workspace: Path | None
    runner_name: str
    log_path: Path
    dry_run: bool
    free_gib_override: float | None

    def context(self) -> LogContext:
        return LogContext(self.event.value, self.runner_name, self.log_path, self.dry_run)


class Refusal(Exception):
    """The inputs cannot be proven safe; carries the exact reason and what the log line can say."""

    def __init__(self, reason: str, context: LogContext):
        super().__init__(reason)
        self.reason = reason
        self.context = context


@dataclasses.dataclass(frozen=True)
class Outcome:
    context: LogContext
    free_before: str
    free_after: str
    decision: Decision
    removed: tuple[str, ...]
    reason: str
    notes: tuple[str, ...]
    folder_before: str = UNKNOWN
    folder_after: str = UNKNOWN


class _ArgError(Exception):
    pass


class _Parser(argparse.ArgumentParser):
    def error(self, message):
        raise _ArgError(message)


def _event_arg(value: str) -> Event:
    try:
        return Event(value)
    except ValueError as exc:
        choices = ", ".join(member.value for member in Event)
        raise argparse.ArgumentTypeError(f"invalid event {value!r} (choose from {choices})") from exc


def _finite_float(value: str) -> float:
    try:
        number = float(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"not a number: {value!r}") from exc
    if not math.isfinite(number):
        raise argparse.ArgumentTypeError(f"not a finite number: {value!r}")
    return number


def build_parser() -> argparse.ArgumentParser:
    parser = _Parser(
        prog="runner_disk_hook.py",
        description="Self-hosted runner hook: clear this runner's cargo target directories when the disk is low. "
        "Exits 0 on every path; the reason is in the log line and on stderr.",
        allow_abbrev=False,
    )
    parser.add_argument("--event", required=True, type=_event_arg, help="job-started or job-completed")
    parser.add_argument("--work-root", help=f"the runner's work folder (default: ${ENV_WORK_ROOT})")
    parser.add_argument("--workspace", help=f"the job workspace (default: ${ENV_WORKSPACE})")
    parser.add_argument("--runner-name", help=f"this runner's name (default: ${ENV_RUNNER_NAME})")
    parser.add_argument(
        "--log",
        help=f"append the one log line here (default: ${DEFAULT_LOG_ENV}, else <home>/{'/'.join(DEFAULT_LOG_PARTS)})",
    )
    parser.add_argument("--dry-run", action="store_true", help="decide and log, remove nothing")
    parser.add_argument(
        "--free-gib",
        type=_finite_float,
        help="test input only: use this free space (GiB) in place of the disk reading",
    )
    return parser


def resolve_log_path(explicit: str | None, env: Mapping[str, str], home: Path) -> Path:
    """``--log``, else an absolute $RUNNER_DISK_HOOK_LOG, else ``<home>/ai-tmp/runner-disk-hook.log``."""
    if explicit:
        return Path(explicit)
    from_env = env.get(DEFAULT_LOG_ENV, "")
    if from_env and os.path.isabs(from_env):
        return Path(from_env)
    return home.joinpath(*DEFAULT_LOG_PARTS)


def _scan_log_arg(argv: Sequence[str], env: Mapping[str, str], home: Path) -> Path:
    """Best-effort ``--log`` value from arguments that may not parse, so a refusal still reaches the right log."""
    items = list(argv)
    explicit: str | None = None
    for index, item in enumerate(items):
        if item == "--log" and index + 1 < len(items):
            explicit = items[index + 1]
        elif item.startswith("--log="):
            explicit = item[len("--log="):]
    return resolve_log_path(explicit, env, home)


def work_root_refusal(root: "str | os.PathLike[str] | None", home: Path) -> str | None:
    """Return the reason the work root cannot be trusted, or None. Lexical checks first, then the file system."""
    if root is None:
        return "work root is not set"
    text = os.fspath(root)
    if text.strip() == "":
        return "work root is empty"
    if not os.path.isabs(text):
        return "work root is not an absolute path"
    path = Path(text)
    if ".." in path.parts:
        return "work root contains a '..' component"
    if len(path.parts) == 1:
        return "work root is the filesystem root"
    if os.path.normpath(text) == os.path.normpath(os.fspath(home)):
        return "work root is the home directory"
    if len(path.parts) - 1 < WORK_ROOT_MIN_PARTS:
        return f"work root has fewer than {WORK_ROOT_MIN_PARTS} path parts"
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        return "work root does not exist"
    except OSError as exc:
        return f"work root cannot be examined: {exc.strerror or exc}"
    if stat.S_ISLNK(info.st_mode):
        return "work root is a symlink"
    if not stat.S_ISDIR(info.st_mode):
        return "work root is not a directory"
    if os.path.realpath(path) == os.path.realpath(home):
        return "work root is the home directory"
    if os.path.ismount(path):
        return "work root is a volume root"
    return None


def parse_config(argv: Sequence[str], env: Mapping[str, str], home: Path) -> Config:
    """Turn arguments and environment into a Config, or raise Refusal with the exact reason."""
    unparsed = LogContext(UNKNOWN, UNKNOWN, _scan_log_arg(argv, env, home), False)
    try:
        args = build_parser().parse_args(list(argv))
    except _ArgError as exc:
        raise Refusal(f"invalid arguments: {exc}", unparsed) from exc
    runner_raw = args.runner_name if args.runner_name is not None else env.get(ENV_RUNNER_NAME)
    log_path = resolve_log_path(args.log, env, home)
    context = LogContext(args.event.value, UNKNOWN, log_path, args.dry_run)
    if runner_raw is None or runner_raw == "":
        raise Refusal("runner name is not set", context)
    if RUNNER_NAME_PATTERN.match(runner_raw) is None:
        raise Refusal("runner name is invalid", dataclasses.replace(context, runner=INVALID))
    context = dataclasses.replace(context, runner=runner_raw)
    root_raw = args.work_root if args.work_root is not None else env.get(ENV_WORK_ROOT)
    reason = work_root_refusal(root_raw, home)
    if reason is not None:
        raise Refusal(reason, context)
    workspace_raw = args.workspace if args.workspace is not None else env.get(ENV_WORKSPACE)
    workspace = Path(workspace_raw) if workspace_raw and os.path.isabs(workspace_raw) else None
    return Config(
        event=args.event,
        work_root=Path(root_raw),
        workspace=workspace,
        runner_name=runner_raw,
        log_path=log_path,
        dry_run=args.dry_run,
        free_gib_override=args.free_gib,
    )


def _is_inside(path: Path, root: Path) -> bool:
    resolved_path = Path(os.path.realpath(path))
    resolved_root = Path(os.path.realpath(root))
    return resolved_path != resolved_root and resolved_path.is_relative_to(resolved_root)


def classify_candidate(root: Path, candidate: Path) -> str | None:
    """Return the reason this target must be kept, or None when it is proven removable."""
    try:
        info = os.lstat(candidate)
    except OSError as exc:
        return f"{candidate}: target cannot be examined: {exc.strerror or exc}"
    if stat.S_ISLNK(info.st_mode):
        return f"{candidate}: target is a symlink"
    if not stat.S_ISDIR(info.st_mode):
        return f"{candidate}: target is not a directory"
    if not _is_inside(candidate, root):
        return f"{candidate}: target resolves outside the work root"
    try:
        root_dev = os.lstat(root).st_dev
    except OSError as exc:
        return f"{candidate}: work root cannot be examined: {exc.strerror or exc}"
    if info.st_dev != root_dev:
        return f"{candidate}: target is on another device than the work root"
    marker = candidate / MARKER_FILE_NAME
    try:
        marker_info = os.lstat(marker)
    except FileNotFoundError:
        return f"{candidate}: target has no {MARKER_FILE_NAME}"
    except OSError as exc:
        return f"{candidate}: {MARKER_FILE_NAME} cannot be examined: {exc.strerror or exc}"
    if not stat.S_ISREG(marker_info.st_mode):
        return f"{candidate}: target has no {MARKER_FILE_NAME}"
    try:
        fd = os.open(marker, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            head = os.read(fd, MARKER_READ_BYTES)
        finally:
            os.close(fd)
    except OSError as exc:
        return f"{candidate}: {MARKER_FILE_NAME} cannot be read: {exc.strerror or exc}"
    if head.split(b"\n", 1)[0] != MARKER_SIGNATURE.encode("ascii"):
        return f"{candidate}: {MARKER_FILE_NAME} first line is not the cache directory signature"
    return None


def find_candidates(root: Path) -> tuple[list[Path], list[str]]:
    """List ``<root>/<repo>/target`` entries named exactly ``target``; return them with the notes."""
    candidates: list[Path] = []
    notes: list[str] = []
    try:
        repos = sorted(os.scandir(root), key=lambda entry: entry.name)
    except OSError as exc:
        return [], [f"{root}: cannot list the work root: {exc.strerror or exc}"]
    for repo in repos:
        repo_path = root / repo.name
        if repo.is_symlink():
            notes.append(f"{repo_path}: repo directory is a symlink, not entered")
            continue
        if not repo.is_dir(follow_symlinks=False):
            continue
        try:
            children = [child.name for child in os.scandir(repo_path)]
        except OSError as exc:
            notes.append(f"{repo_path}: cannot list: {exc.strerror or exc}")
            continue
        if TARGET_DIR_NAME in children:
            candidates.append(repo_path / TARGET_DIR_NAME)
    return candidates, notes


def _empty_directory(fd: int, dev: int, depth: int) -> None:
    if depth > MAX_TREE_DEPTH:
        raise OSError(errno.ELOOP, f"tree deeper than {MAX_TREE_DEPTH} levels")
    with os.scandir(fd) as scan:
        entries = [(entry.name, entry.is_dir(follow_symlinks=False)) for entry in scan]
    for name, is_dir in entries:
        if not is_dir:
            os.unlink(name, dir_fd=fd)
            continue
        child = os.open(name, DIR_OPEN_FLAGS, dir_fd=fd)
        try:
            if os.fstat(child).st_dev != dev:
                raise OSError(errno.EXDEV, "crosses a device boundary")
            _empty_directory(child, dev, depth + 1)
        finally:
            os.close(child)
        os.rmdir(name, dir_fd=fd)


def remove_directory(parent: Path, name: str) -> None:
    """Remove ``parent/name`` without following symlinks or crossing a device; raises OSError."""
    parent_fd = os.open(parent, DIR_OPEN_FLAGS)
    try:
        before = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        if not stat.S_ISDIR(before.st_mode):
            raise OSError(errno.ENOTDIR, "not a directory")
        fd = os.open(name, DIR_OPEN_FLAGS, dir_fd=parent_fd)
        try:
            after = os.fstat(fd)
            if (after.st_dev, after.st_ino) != (before.st_dev, before.st_ino):
                raise OSError(errno.ESTALE, "directory changed while it was opened")
            if after.st_dev != os.fstat(parent_fd).st_dev:
                raise OSError(errno.EXDEV, "crosses a device boundary")
            _empty_directory(fd, after.st_dev, 0)
        finally:
            os.close(fd)
        os.rmdir(name, dir_fd=parent_fd)
    finally:
        os.close(parent_fd)


def _reason_of(exc: OSError) -> str:
    return exc.strerror or str(exc)


def clear_targets(config: Config) -> tuple[list[str], list[str]]:
    """Remove (or, in a dry run, list) every proven cargo target; return (removed, notes)."""
    removed: list[str] = []
    candidates, notes = find_candidates(config.work_root)
    for candidate in candidates:
        reason = classify_candidate(config.work_root, candidate)
        if reason is not None:
            notes.append(reason)
            continue
        if config.dry_run:
            removed.append(str(candidate))
            continue
        try:
            remove_directory(candidate.parent, candidate.name)
        except OSError as exc:
            notes.append(f"{candidate}: remove failed: {_reason_of(exc)}")
            continue
        removed.append(str(candidate))
    return removed, notes


def _test_tmp_bases(config: Config) -> tuple[list[Path], list[str]]:
    bases = [config.work_root]
    notes: list[str] = []
    workspace = config.workspace
    if workspace is not None:
        if _is_inside(workspace, config.work_root) or workspace == config.work_root:
            bases.append(workspace)
            if workspace.parent != workspace and (
                _is_inside(workspace.parent, config.work_root) or workspace.parent == config.work_root
            ):
                bases.append(workspace.parent)
        else:
            notes.append(f"{workspace}: workspace is outside the work root")
    unique: list[Path] = []
    for base in bases:
        if base not in unique:
            unique.append(base)
    return unique, notes


def _test_tmp_refusal(config: Config, local_runs: Path, test_tmp: Path) -> str | None:
    try:
        root_dev = os.lstat(config.work_root).st_dev
        for part in (local_runs, test_tmp):
            info = os.lstat(part)
            if stat.S_ISLNK(info.st_mode):
                return f"{test_tmp}: test-tmp path has a symlink component"
            if not stat.S_ISDIR(info.st_mode):
                return f"{test_tmp}: test-tmp path is not a directory"
            if info.st_dev != root_dev:
                return f"{test_tmp}: test-tmp is on another device than the work root"
    except OSError as exc:
        return f"{test_tmp}: cannot be examined: {_reason_of(exc)}"
    return None


def _default_run_cmd(cmd: Sequence[str]) -> int:
    done = subprocess.run(
        list(cmd), check=False, capture_output=True, stdin=subprocess.DEVNULL, timeout=CHMOD_TIMEOUT_SECS
    )
    return done.returncode


def clear_test_tmp(config: Config, run_cmd: Callable[[Sequence[str]], int]) -> tuple[list[str], list[str]]:
    """The old shell hook: strip ACLs, then remove ``.local-runs/test-tmp``; return (removed, notes)."""
    removed: list[str] = []
    bases, notes = _test_tmp_bases(config)
    for base in bases:
        local_runs = base / TEST_TMP_PARTS[0]
        test_tmp = local_runs / TEST_TMP_PARTS[1]
        if not os.path.lexists(local_runs) or not os.path.lexists(test_tmp):
            if os.path.islink(local_runs):
                notes.append(f"{test_tmp}: test-tmp path has a symlink component")
            continue
        reason = _test_tmp_refusal(config, local_runs, test_tmp)
        if reason is not None:
            notes.append(reason)
            continue
        if config.dry_run:
            removed.append(str(test_tmp))
            continue
        for cmd in (["chmod", "-RN", str(test_tmp)], ["chmod", "-R", "u+rwx", str(test_tmp)]):
            try:
                run_cmd(cmd)
            except (OSError, subprocess.SubprocessError):
                continue  # as the old hook: a failed chmod is not fatal, the removal below says what is left
        try:
            remove_directory(local_runs, TEST_TMP_PARTS[1])
        except OSError as exc:
            notes.append(f"{test_tmp}: remove failed: {_reason_of(exc)}")
            continue
        removed.append(str(test_tmp))
    return removed, notes


class Undecidable(Exception):
    pass


def read_free_bytes(config: Config, disk_free: Callable[[Path], int | None]) -> int:
    """Measure free bytes of the work root's volume; raise Undecidable with the reason on any failure."""
    if config.free_gib_override is not None:
        value: int | None = int(config.free_gib_override * GIB)
    else:
        try:
            value = disk_free(config.work_root)
        except OSError as exc:
            raise Undecidable(f"free-space read failed: {exc}") from exc
    if value is None:
        raise Undecidable("free-space read returned nothing")
    if value < 0:
        raise Undecidable(f"free-space read returned a negative value: {value}")
    return value


def _walk_bytes(fd: int, dev: int, depth: int, seen: list[int], max_entries: int) -> int:
    if depth > MAX_TREE_DEPTH:
        raise OSError(errno.ELOOP, f"tree deeper than {MAX_TREE_DEPTH} levels")
    with os.scandir(fd) as scan:
        names = [entry.name for entry in scan]
    total = 0
    for name in names:
        seen[0] += 1
        if seen[0] > max_entries:
            raise OSError(errno.EFBIG, f"more than {max_entries} entries")
        try:
            info = os.stat(name, dir_fd=fd, follow_symlinks=False)
        except FileNotFoundError:
            continue  # removed while walking: it holds no bytes any more
        total += info.st_size
        if not stat.S_ISDIR(info.st_mode):
            continue  # a symlink is counted as the link, never followed
        child = os.open(name, DIR_OPEN_FLAGS, dir_fd=fd)
        try:
            if os.fstat(child).st_dev == dev:
                total += _walk_bytes(child, dev, depth + 1, seen, max_entries)
        finally:
            os.close(child)
    return total


def measure_folder_bytes(root: Path, max_entries: int = MAX_WALK_ENTRIES) -> int:
    """Bytes of every entry under ``root`` (symlinks not followed, other devices not entered); raise Undecidable."""
    try:
        fd = os.open(root, DIR_OPEN_FLAGS)
        try:
            return _walk_bytes(fd, os.fstat(fd).st_dev, 0, [0], max_entries)
        finally:
            os.close(fd)
    except OSError as exc:
        raise Undecidable(f"work folder size read failed under {root}: {_reason_of(exc)}") from exc


def _default_disk_free(path: Path) -> int:
    return shutil.disk_usage(path).free


def _gib_text(value: int) -> str:
    return f"{value / GIB:.2f}"


def run(
    config: Config,
    *,
    disk_free: Callable[[Path], int | None],
    run_cmd: Callable[[Sequence[str]], int],
    ceiling_bytes: int = WORK_FOLDER_CEILING_BYTES,
) -> Outcome:
    context = config.context()
    floor = floor_gib(config.event)
    try:
        before = read_free_bytes(config, disk_free)
    except Undecidable as exc:
        reason = str(exc)
        return Outcome(context, UNKNOWN, UNKNOWN, Decision.REFUSED, (), reason, (reason,))
    removed: list[str] = []
    notes: list[str] = []
    if config.event is Event.JOB_STARTED:
        got, more = clear_test_tmp(config, run_cmd)
        removed += got
        notes += more
    below = before < floor * GIB
    folder_before = UNKNOWN
    over = False
    if config.event is Event.JOB_STARTED:
        try:
            measured = measure_folder_bytes(config.work_root)
            folder_before = str(measured)
            over = measured > ceiling_bytes
        except Undecidable as exc:
            notes.append(str(exc))
    should_clear = below or over
    if should_clear:
        got, more = clear_targets(config)
        removed += got
        notes += more
    after_text = _gib_text(before)
    folder_after = folder_before
    if removed and not config.dry_run:
        try:
            after_text = _gib_text(read_free_bytes(config, disk_free))
        except Undecidable as exc:
            after_text = UNKNOWN
            notes.append(f"{exc} after the removal")
        if folder_before != UNKNOWN:
            try:
                folder_after = str(measure_folder_bytes(config.work_root))
            except Undecidable as exc:
                folder_after = UNKNOWN
                notes.append(f"{exc} after the removal")
    match (should_clear, bool(removed), bool(notes)):
        case (_, False, True):
            decision = Decision.REFUSED
        case (True, _, _):
            decision = Decision.CLEAR
        case (False, _, _):
            decision = Decision.ENOUGH_FREE
        case _:
            raise ValueError("unreachable decision state")
    parts: list[str] = []
    if not below:
        parts.append(f"free space {_gib_text(before)} GiB is at or above the {floor} GiB floor")
    if over:
        parts.append(f"work folder {folder_before} bytes is over the {ceiling_bytes} byte ceiling")
    parts += notes
    if should_clear and not removed and not notes:
        parts.append("no cargo target directory found")
    return Outcome(
        context, _gib_text(before), after_text, decision, tuple(removed), REASON_SEPARATOR.join(parts), tuple(notes),
        folder_before, folder_after,
    )


def format_line(outcome: Outcome, now: datetime.datetime) -> str:
    stamp = now.astimezone(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    context = outcome.context
    line = (
        f"{stamp} runner={context.runner} event={context.event} free_before_gib={outcome.free_before} "
        f"free_after_gib={outcome.free_after} folder_bytes_before={outcome.folder_before} "
        f"folder_bytes_after={outcome.folder_after} decision={outcome.decision.value} removed={len(outcome.removed)} "
        f"paths={json.dumps(list(outcome.removed))} reason={json.dumps(outcome.reason)}"
    )
    return line + " dry-run" if context.dry_run else line


def append_log(path: Path, line: str) -> str | None:
    """Append one line; return the failure text, or None."""
    data = (line + "\n").encode("utf-8", "backslashreplace")
    try:
        fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0), 0o644)
        try:
            view = memoryview(data)
            while view:
                view = view[os.write(fd, view) :]
        finally:
            os.close(fd)
    except OSError as exc:
        return f"log write failed: {path}: {_reason_of(exc)}"
    return None


def _emit(stderr, text: str) -> None:
    try:
        stderr.write(f"runner-disk-hook: {text}\n")
    except (OSError, UnicodeError):
        pass  # nothing left to report to; the exit code stays 0


def main(
    argv: Sequence[str] | None = None,
    env: Mapping[str, str] | None = None,
    *,
    home: Path | None = None,
    disk_free: Callable[[Path], int | None] | None = None,
    run_cmd: Callable[[Sequence[str]], int] | None = None,
    stderr=None,
    now: Callable[[], datetime.datetime] | None = None,
    ceiling_bytes: int = WORK_FOLDER_CEILING_BYTES,
) -> int:
    argv = sys.argv[1:] if argv is None else argv
    env = os.environ if env is None else env
    stderr = sys.stderr if stderr is None else stderr
    clock = now or (lambda: datetime.datetime.now(datetime.timezone.utc))
    try:
        home_dir = Path.home() if home is None else home
    except (RuntimeError, KeyError):
        home_dir = Path("/nonexistent-home")
    context = LogContext(UNKNOWN, UNKNOWN, _scan_log_arg(argv, env, home_dir), False)
    try:
        config = parse_config(argv, env, home_dir)
        context = config.context()
        outcome = run(config, disk_free=disk_free or _default_disk_free, run_cmd=run_cmd or _default_run_cmd,
                      ceiling_bytes=ceiling_bytes)
    except Refusal as refusal:
        outcome = Outcome(refusal.context, UNKNOWN, UNKNOWN, Decision.REFUSED, (), refusal.reason, (refusal.reason,))
    except Exception as exc:  # noqa: BLE001 - the hook exits 0 on every path; the reason is logged
        reason = f"internal error: {type(exc).__name__}: {exc}"
        outcome = Outcome(context, UNKNOWN, UNKNOWN, Decision.REFUSED, (), reason, (reason,))
    line = format_line(outcome, clock())
    failure = append_log(outcome.context.log_path, line)
    if failure is not None:
        _emit(stderr, f"{failure}; line: {line}")
    if outcome.notes:
        for note in outcome.notes:
            _emit(stderr, f"{outcome.decision.value}: {note}")
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
