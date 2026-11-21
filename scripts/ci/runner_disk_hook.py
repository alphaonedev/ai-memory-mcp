#!/opt/homebrew/bin/python3.12
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""Self-hosted macOS runner disk hook: clear this runner's cargo target directories when the work volume runs low (#8216).

The GitHub Actions runner calls a hook path only if it ends in ``.sh``, ``.ps1`` or ``.js`` and takes no
arguments, so the runner's ``.env`` points at ``runner_disk_hook.sh`` (one ``exec`` line that starts this
file). The event comes from the name the hook is started under (``--invoked-as``) or from ``--event``.
Several runners share one volume and each keeps a cargo ``target`` directory in its work folder (27 to 51
GiB each, growing per job); a full volume ends every job and every lane on the host.

Behaviour
  job-completed   when the volume of the work root has less than CLEAR_BELOW_GIB_AFTER_JOB GiB free, remove
                  the cargo target directories in THIS runner's work folder. Never exits non-zero for the floor.
  job-started     the same check with the floor START_FLOOR_GIB GiB, plus the work folder byte ceiling. When
                  the free space is still under START_FLOOR_GIB after the clear and ENFORCE_START_FLOOR is
                  True, the hook exits EXIT_BELOW_FLOOR with the fixed line ``decision=below-floor ...`` so
                  the job does not start (3-agent vote 71472661: a refused start costs seconds, a job that
                  dies of a full disk costs 40 to 60 minutes). A dry run never exits non-zero.
There is no sudo fallback and no subprocess: a hook must never wait on a password prompt or on a PATH lookup.

Layout supported: RUNNER_WORKSPACE is ``<runner root>/_work/<repo>`` and the work root is that path (or
``--work-root``); a candidate is ``<work root>/<repo>/target``. Any other name or depth is kept.

Removal invariant (``safe_remove.check_and_remove``): the directory is opened once by file descriptor with
O_NOFOLLOW, the tag is proven through that descriptor, the removal goes through the same descriptor on one
device, the tag is removed last, and a tree deeper than the cap is refused before anything is unlinked. Every
other case is a refusal with its own exact reason.

One function (``decide``) computes the decision, reason, removed count and exit code from the state after
the action, by an exhaustive ``match`` over ``Action``. Every text that reaches stderr or the log passes
``safe_text``. A free-space read that fails, returns a bool, a str, nothing or a negative value is a refusal
to decide: nothing is removed, the reason is logged, and the exit code is 0 (the floor cannot be proven).

Log: every call appends one line to the log (``--log`` or an absolute $RUNNER_DISK_HOOK_LOG, else
``<home>/ai-tmp/runner-disk-hook.log``; the default directory is created 0o700, the file 0o600):
  <UTC> runner=<n> event=<e> free_before_gib=<t> free_after_gib=<t> folder_bytes_before=<t> folder_bytes_after=<t>
  decision=<d> removed=<count> entries=<count> paths=<JSON list> reason=<JSON string>[ dry-run]
A GiB text is truncated (never rounded up); ``input:`` marks a ``--free-gib`` value, which is an input and not a
measurement. A below-floor refusal adds the fixed line
  <UTC> decision=below-floor event=<e> free_bytes=<n|unknown> floor_bytes=<n> runner=<name>
which is also the stderr line. A log that cannot be written does not stop the removal.

Python 3.12+, standard library only.
"""

import argparse
import dataclasses
import datetime
import enum
import importlib.util
import json
import math
import os
import re
import shutil
import stat
import sys
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path

_SAFE_REMOVE_PATH = Path(__file__).resolve().with_name("safe_remove.py")


def _load_safe_remove():
    """Load safe_remove.py from this file's directory (``-I`` leaves the script directory off sys.path)."""
    cached = sys.modules.get("safe_remove")
    if cached is not None:
        return cached
    spec = importlib.util.spec_from_file_location("safe_remove", _SAFE_REMOVE_PATH)
    if spec is None or spec.loader is None:
        raise ImportError(f"cannot load {_SAFE_REMOVE_PATH}")
    module = importlib.util.module_from_spec(spec)
    sys.modules["safe_remove"] = module
    spec.loader.exec_module(module)
    return module


safe_remove = _load_safe_remove()

GIB = 1024**3
CLEAR_BELOW_GIB_AFTER_JOB = 150
START_FLOOR_GIB = 60
WORK_FOLDER_CEILING_GIB = 40
WORK_FOLDER_CEILING_BYTES = WORK_FOLDER_CEILING_GIB * GIB
MAX_WALK_ENTRIES = 5_000_000
ENFORCE_START_FLOOR = True
EXIT_OK = 0
EXIT_BELOW_FLOOR = 75
BLOCK_BYTES = 512
DEFAULT_LOG_ENV = "RUNNER_DISK_HOOK_LOG"
DEFAULT_LOG_PARTS = ("ai-tmp", "runner-disk-hook.log")
LOG_DIR_MODE = 0o700
LOG_FILE_MODE = 0o600
TARGET_DIR_NAME = "target"
MARKER_FILE_NAME = "CACHEDIR.TAG"
MARKER_SIGNATURE = "Signature: 8a477f597d28d172789f06886806bc55"
RUNNER_WORK_DIR_NAME = "_work"
WORK_ROOT_MIN_PARTS = 3
FORBIDDEN_ROOTS = ("/System/Volumes/Data",)
SAFE_TEXT_MAX = 512
RUNNER_NAME_PATTERN = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
ENV_WORK_ROOT = "RUNNER_WORKSPACE"
ENV_RUNNER_NAME = "RUNNER_NAME"
UNKNOWN = "unknown"
INVALID = "invalid"
INPUT_MARK = "input:"
REASON_SEPARATOR = "; "
STDERR_PREFIX = "runner-disk-hook: "
DIR_OPEN_FLAGS = safe_remove.DIR_OPEN_FLAGS
INVOKED_AS_JOB_STARTED = "runner_disk_hook_job-started.sh"
INVOKED_AS_JOB_COMPLETED = "runner_disk_hook_job-completed.sh"


class Event(enum.Enum):
    JOB_STARTED = "job-started"
    JOB_COMPLETED = "job-completed"


INVOKED_AS_EVENTS = {INVOKED_AS_JOB_STARTED: Event.JOB_STARTED, INVOKED_AS_JOB_COMPLETED: Event.JOB_COMPLETED}


class Decision(enum.Enum):
    ENOUGH_FREE = "enough-free"
    CLEAR = "clear"
    WOULD_REMOVE = "would-remove"
    PARTIAL = "partial"
    NO_TARGET = "no-target"
    REFUSED_TARGET = "refused-target"
    REFUSED_MEASURE = "refused-measure"
    ENTRY_CAP = "entry-cap"
    BELOW_FLOOR = "below-floor"
    REFUSED = "refused"


class Action(enum.Enum):
    """What the clear step did, computed from the removal results."""

    NOT_NEEDED = "not-needed"
    CLEARED = "cleared"
    WOULD_CLEAR = "would-clear"
    PARTIAL = "partial"
    NO_TARGET = "no-target"
    REFUSED_TARGET = "refused-target"


class FolderState(enum.Enum):
    NOT_MEASURED = "not-measured"
    MEASURED = "measured"
    CAP = "cap"
    UNREADABLE = "unreadable"


def floor_gib(event: Event) -> int:
    floors = {Event.JOB_STARTED: START_FLOOR_GIB, Event.JOB_COMPLETED: CLEAR_BELOW_GIB_AFTER_JOB}
    return floors[event]


def safe_text(value: object) -> str:
    """The one funnel for untrusted text: control characters, backslash, ``::`` and ``%`` escaped, length capped."""
    text = str(value)
    out: list[str] = []
    for char in text:
        code = ord(char)
        if char == "\\":
            out.append("\\\\")
        elif char == "%":
            out.append("%25")
        elif code < 0x20 or code == 0x7F or 0x80 <= code < 0xA0:
            out.append(f"\\x{code:02x}")
        else:
            out.append(char)
    escaped = "".join(out).replace("::", ":\\x3a")
    if len(escaped) > SAFE_TEXT_MAX:
        cut = len(escaped) - SAFE_TEXT_MAX
        escaped = escaped[:SAFE_TEXT_MAX] + f"...(+{cut} chars)"
    return escaped


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


class Undecidable(Exception):
    pass


class MeasureError(Exception):
    """The folder walk was refused; ``state`` says whether the cap or a read failure."""

    def __init__(self, reason: str, state: FolderState):
        super().__init__(reason)
        self.reason = reason
        self.state = state


@dataclasses.dataclass(frozen=True)
class Facts:
    """The state after the action; ``decide`` computes every printed value from this."""

    event: Event
    dry_run: bool
    floor_bytes: int
    free_before: int | None
    free_after: int | None
    free_is_input: bool
    free_reason: str
    folder_state: FolderState
    folder_before: int | None
    folder_after: int | None
    folder_reason: str
    over_ceiling: bool
    ceiling_bytes: int
    action: Action
    completed: tuple[str, ...]
    partial: tuple[str, ...]
    would: tuple[str, ...]
    entries: int
    notes: tuple[str, ...]


@dataclasses.dataclass(frozen=True)
class Verdict:
    decision: Decision
    reason: str
    exit_code: int
    removed: int
    paths: tuple[str, ...]


@dataclasses.dataclass(frozen=True)
class Outcome:
    context: LogContext
    facts: Facts | None
    verdict: Verdict
    notes: tuple[str, ...]


def _gib_text(value: int) -> str:
    """GiB with two decimals, truncated: a value under the floor never prints as the floor."""
    hundredths = value * 100 // GIB
    return f"{hundredths // 100}.{hundredths % 100:02d}"


def _free_text(value: int | None, is_input: bool) -> str:
    if value is None:
        return UNKNOWN
    return (INPUT_MARK if is_input else "") + _gib_text(value)


def _bytes_text(value: int | None) -> str:
    return UNKNOWN if value is None else str(value)


def _below(free: int | None, floor_bytes: int) -> bool:
    return free is None or free < floor_bytes


def below_floor_line(event: str, free: int | None, floor_bytes: int, runner: str) -> str:
    """The one fixed, greppable below-floor form (stderr and log)."""
    return (
        f"decision={Decision.BELOW_FLOOR.value} event={safe_text(event)} free_bytes={_bytes_text(free)} "
        f"floor_bytes={floor_bytes} runner={safe_text(runner)}"
    )


def _folder_parts(facts: Facts) -> list[str]:
    parts: list[str] = []
    match facts.folder_state:
        case FolderState.NOT_MEASURED:
            pass
        case FolderState.MEASURED:
            relation = "over" if facts.over_ceiling else "at or under"
            parts.append(f"work folder {facts.folder_before} allocated bytes is {relation} the {facts.ceiling_bytes} byte ceiling")
        case FolderState.CAP | FolderState.UNREADABLE:
            parts.append(facts.folder_reason)
        case _:
            raise ValueError(f"unknown folder state {facts.folder_state!r}")
    return parts


def decide(facts: Facts) -> Verdict:
    """The decision, reason, removed count and exit code from the state after the action (exhaustive match)."""
    paths = facts.completed + facts.partial + facts.would
    if facts.free_before is None:
        return Verdict(Decision.REFUSED_MEASURE, facts.free_reason, EXIT_OK, 0, ())
    final = facts.free_after if facts.action in (Action.CLEARED, Action.PARTIAL) else facts.free_before
    parts: list[str] = []
    floor_gib_text = f"{facts.floor_bytes // GIB} GiB floor"
    match facts.action:
        case Action.NOT_NEEDED:
            capped = facts.folder_state in (FolderState.CAP, FolderState.UNREADABLE)
            if capped:
                decision = Decision.ENTRY_CAP if facts.folder_state is FolderState.CAP else Decision.REFUSED_MEASURE
            else:
                decision = Decision.ENOUGH_FREE
            parts.append(f"free space {_gib_text(facts.free_before)} GiB is at or above the {floor_gib_text}")
            parts += _folder_parts(facts)
        case Action.CLEARED:
            decision = Decision.CLEAR
            parts.append(_why_cleared(facts, floor_gib_text))
        case Action.WOULD_CLEAR:
            decision = Decision.WOULD_REMOVE
            parts.append(_why_cleared(facts, floor_gib_text))
        case Action.PARTIAL:
            decision = Decision.PARTIAL
            parts.append(_why_cleared(facts, floor_gib_text))
            parts.append(f"removal stopped part way after {facts.entries} entries removed")
        case Action.NO_TARGET:
            decision = Decision.NO_TARGET
            parts.append(_why_cleared(facts, floor_gib_text))
            parts.append("no cargo target directory found")
        case Action.REFUSED_TARGET:
            decision = Decision.REFUSED_TARGET
            parts.append(_why_cleared(facts, floor_gib_text))
        case _:
            raise ValueError(f"unknown action {facts.action!r}")
    if facts.action is not Action.NOT_NEEDED:
        parts += [part for part in _folder_parts(facts) if facts.folder_state in (FolderState.CAP, FolderState.UNREADABLE)]
    parts += facts.notes
    exit_code = EXIT_OK
    enforce = ENFORCE_START_FLOOR and facts.event is Event.JOB_STARTED and not facts.dry_run
    if enforce and facts.action is not Action.WOULD_CLEAR and _below(final, facts.floor_bytes):
        decision = Decision.BELOW_FLOOR
        exit_code = EXIT_BELOW_FLOOR
        if final is None:
            parts.append("free space after the removal could not be read, so the floor is not proven")
        else:
            parts.append(f"free space {_gib_text(final)} GiB is under the {floor_gib_text} after the clear")
    return Verdict(decision, REASON_SEPARATOR.join(parts), exit_code, len(facts.completed), paths)


def _why_cleared(facts: Facts, floor_gib_text: str) -> str:
    reasons: list[str] = []
    if facts.free_before is not None and facts.free_before < facts.floor_bytes:
        reasons.append(f"free space {_gib_text(facts.free_before)} GiB is under the {floor_gib_text}")
    if facts.over_ceiling:
        reasons.append(f"work folder {facts.folder_before} allocated bytes is over the {facts.ceiling_bytes} byte ceiling")
    return REASON_SEPARATOR.join(reasons)


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
        "Exits 75 at job-started when the free space is still under the start floor; 0 otherwise.",
        allow_abbrev=False,
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--event", type=_event_arg, help="job-started or job-completed")
    group.add_argument("--invoked-as", help="the file name the hook was started under (runner_disk_hook.sh passes $0)")
    parser.add_argument("--work-root", help=f"the runner's work folder (default: ${ENV_WORK_ROOT})")
    parser.add_argument("--runner-name", help=f"this runner's name (default: ${ENV_RUNNER_NAME})")
    parser.add_argument(
        "--log",
        help=f"append the log line here (default: ${DEFAULT_LOG_ENV}, else <home>/{'/'.join(DEFAULT_LOG_PARTS)})",
    )
    parser.add_argument("--dry-run", action="store_true", help="decide and log, remove nothing")
    parser.add_argument(
        "--free-gib",
        type=_finite_float,
        help="test input only: use this free space (GiB) in place of the disk reading",
    )
    return parser


def default_log_path(home: Path) -> Path:
    return home.joinpath(*DEFAULT_LOG_PARTS)


def resolve_log_path(explicit: str | None, env: Mapping[str, str], home: Path) -> tuple[Path, str | None]:
    """``--log``, else $RUNNER_DISK_HOOK_LOG, else the default; a relative value is a named refusal."""
    if explicit:
        if not os.path.isabs(explicit):
            return default_log_path(home), "--log is not an absolute path"
        return Path(explicit), None
    from_env = env.get(DEFAULT_LOG_ENV, "")
    if from_env:
        if not os.path.isabs(from_env):
            return default_log_path(home), f"{DEFAULT_LOG_ENV} is not an absolute path"
        return Path(from_env), None
    return default_log_path(home), None


def _scan_log_arg(argv: Sequence[str], env: Mapping[str, str], home: Path) -> Path:
    """Best-effort ``--log`` value from arguments that may not parse, so a refusal still reaches the right log."""
    items = list(argv)
    explicit: str | None = None
    for index, item in enumerate(items):
        if item == "--log" and index + 1 < len(items):
            explicit = items[index + 1]
        elif item.startswith("--log="):
            explicit = item[len("--log="):]
    return resolve_log_path(explicit, env, home)[0]


def _env_runner(env: Mapping[str, str]) -> str:
    """The runner name from the environment, read before the arguments, or UNKNOWN."""
    name = env.get(ENV_RUNNER_NAME, "")
    return name if RUNNER_NAME_PATTERN.match(name) else UNKNOWN


def _collapse(text: str) -> str:
    """An absolute path with repeated slashes and ``.`` parts removed (POSIX keeps a leading ``//``; the volume
    names are matched case-insensitively because the default APFS volume is)."""
    return "/" + "/".join(part for part in text.split("/") if part not in ("", "."))


def work_root_refusal(
    root: "str | os.PathLike[str] | None", home: Path, *, lstat: Callable[[Path], os.stat_result] = os.lstat
) -> str | None:
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
    norm = _collapse(text)
    if norm == _collapse(os.fspath(home)):
        return "work root is the home directory"
    for forbidden in FORBIDDEN_ROOTS:
        if norm.casefold() == forbidden.casefold() or norm.casefold().startswith(forbidden.casefold() + "/"):
            return f"work root is on the forbidden volume path {forbidden}"
    if len(path.parts) - 1 < WORK_ROOT_MIN_PARTS:
        return f"work root has fewer than {WORK_ROOT_MIN_PARTS} path parts"
    if path.parent.name != RUNNER_WORK_DIR_NAME:
        return f"work root is not <runner root>/{RUNNER_WORK_DIR_NAME}/<repo>"
    try:
        info = lstat(path)
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
    try:
        parent_info = lstat(path.parent)
    except OSError as exc:
        return f"work root parent cannot be examined: {exc.strerror or exc}"
    if info.st_dev != parent_info.st_dev:
        return "work root is a volume root"
    return None


def parse_config(argv: Sequence[str], env: Mapping[str, str], home: Path) -> Config:
    """Turn arguments and environment into a Config, or raise Refusal with the exact reason."""
    env_runner = _env_runner(env)
    unparsed = LogContext(UNKNOWN, env_runner, _scan_log_arg(argv, env, home), False)
    try:
        args = build_parser().parse_args(list(argv))
    except _ArgError as exc:
        raise Refusal(f"invalid arguments: {exc}", unparsed) from exc
    log_path, log_refusal = resolve_log_path(args.log, env, home)
    event = args.event
    if event is None:
        event = INVOKED_AS_EVENTS.get(args.invoked_as)
    context = LogContext(event.value if event else UNKNOWN, env_runner, log_path, args.dry_run)
    if log_refusal is not None:
        raise Refusal(log_refusal, context)
    if event is None:
        raise Refusal(f"invoked as {args.invoked_as!r}: no event (start it as {INVOKED_AS_JOB_STARTED} or {INVOKED_AS_JOB_COMPLETED})", context)
    runner_raw = args.runner_name if args.runner_name is not None else env.get(ENV_RUNNER_NAME)
    if runner_raw is None or runner_raw == "":
        raise Refusal("runner name is not set", dataclasses.replace(context, runner=UNKNOWN))
    if RUNNER_NAME_PATTERN.match(runner_raw) is None:
        raise Refusal("runner name is invalid", dataclasses.replace(context, runner=INVALID))
    context = dataclasses.replace(context, runner=runner_raw)
    root_raw = args.work_root if args.work_root is not None else env.get(ENV_WORK_ROOT)
    reason = work_root_refusal(root_raw, home)
    if reason is not None:
        raise Refusal(reason, context)
    return Config(
        event=event,
        work_root=Path(root_raw),
        runner_name=runner_raw,
        log_path=log_path,
        dry_run=args.dry_run,
        free_gib_override=args.free_gib,
    )


@dataclasses.dataclass(frozen=True)
class TargetReport:
    completed: tuple[str, ...]
    partial: tuple[str, ...]
    would: tuple[str, ...]
    entries: int
    candidates: int
    notes: tuple[str, ...]


def clear_targets(config: Config) -> TargetReport:
    """Remove (or, in a dry run, list) every proven cargo target through descriptors; one report."""
    completed: list[str] = []
    partial: list[str] = []
    would: list[str] = []
    notes: list[str] = []
    entries = 0
    candidates = 0
    root = config.work_root
    tag = safe_remove.TagSpec(MARKER_FILE_NAME, MARKER_SIGNATURE.encode("ascii"))
    try:
        before = os.lstat(root)
        root_fd = os.open(root, DIR_OPEN_FLAGS)
    except OSError as exc:
        return TargetReport((), (), (), 0, 0, (f"{root}: cannot open the work root: {exc.strerror or exc}",))
    try:
        opened = os.fstat(root_fd)
        if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
            return TargetReport((), (), (), 0, 0, (f"{root}: work root changed while it was opened",))
        with os.scandir(root_fd) as scan:
            repos = sorted((entry.name, entry.is_dir(follow_symlinks=False), entry.is_symlink()) for entry in scan)
        for name, is_dir, is_link in repos:
            if is_link:
                notes.append(f"{root}/{name}: repo directory is a symlink, not entered")
                continue
            if not is_dir:
                continue
            display = f"{root}/{name}/{TARGET_DIR_NAME}"
            try:
                repo_fd = safe_remove.open_directory(root_fd, name, expected_dev=opened.st_dev, device_label="the work root")
            except safe_remove.NotProven as exc:
                notes.append(f"{root}/{name}: {exc.reason}")
                continue
            try:
                try:
                    os.stat(TARGET_DIR_NAME, dir_fd=repo_fd, follow_symlinks=False)
                except FileNotFoundError:
                    continue
                except OSError as exc:
                    notes.append(f"{display}: cannot be examined: {exc.strerror or exc}")
                    continue
                candidates += 1
                result = safe_remove.check_and_remove(
                    repo_fd, TARGET_DIR_NAME, tag=tag, dry_run=config.dry_run, expected_dev=opened.st_dev,
                    device_label="the work root",
                )
                S = safe_remove.Status
                match result.status:
                    case S.REMOVED:
                        completed.append(display)
                        entries += result.entries
                    case S.WOULD_REMOVE:
                        would.append(display)
                    case S.PARTIAL:
                        partial.append(display)
                        entries += result.entries
                        notes.append(f"{display}: partial, {result.entries} entries removed: {result.reason}")
                    case S.REFUSED | S.ABSENT:
                        notes.append(f"{display}: {result.reason}")
                    case _:
                        raise ValueError(f"unknown status {result.status!r}")
            finally:
                os.close(repo_fd)
    except OSError as exc:
        notes.append(f"{root}: cannot list the work root: {exc.strerror or exc}")
    finally:
        os.close(root_fd)
    return TargetReport(tuple(completed), tuple(partial), tuple(would), entries, candidates, tuple(notes))


def read_free_bytes(config: Config, disk_free: Callable[[Path], object]) -> tuple[int, bool]:
    """Free bytes of the work root's volume and whether the value is an input; raise Undecidable with the reason."""
    if config.free_gib_override is not None:
        value: object = int(config.free_gib_override * GIB)
        is_input = True
    else:
        is_input = False
        try:
            value = disk_free(config.work_root)
        except OSError as exc:
            raise Undecidable(f"free-space read failed: {exc}") from exc
    if value is None:
        raise Undecidable("free-space read returned nothing")
    if isinstance(value, bool):
        raise Undecidable(f"free-space read returned a bool: {value}")
    if not isinstance(value, int):
        raise Undecidable(f"free-space read returned a {type(value).__name__}, not an integer")
    if value < 0:
        raise Undecidable(f"free-space read returned a negative value: {value}")
    return value, is_input


def _walk_bytes(
    fd: int, dev: int, depth: int, seen: list[int], links: set[tuple[int, int]], max_entries: int
) -> int:
    if depth > safe_remove.MAX_TREE_DEPTH:
        raise MeasureError(f"tree deeper than {safe_remove.MAX_TREE_DEPTH} levels", FolderState.UNREADABLE)
    with os.scandir(fd) as scan:
        names = [entry.name for entry in scan]
    total = 0
    for name in names:
        seen[0] += 1
        if seen[0] > max_entries:
            raise MeasureError(f"more than {max_entries} entries", FolderState.CAP)
        try:
            info = os.stat(name, dir_fd=fd, follow_symlinks=False)
        except FileNotFoundError:
            continue  # removed while walking: it holds no bytes any more
        if info.st_nlink > 1 and not stat.S_ISDIR(info.st_mode):
            key = (info.st_dev, info.st_ino)
            if key in links:
                continue  # a hard link to an inode that is already counted
            links.add(key)
        total += info.st_blocks * BLOCK_BYTES
        if not stat.S_ISDIR(info.st_mode):
            continue  # a symlink is counted as the link, never followed
        child = os.open(name, DIR_OPEN_FLAGS, dir_fd=fd)
        try:
            if os.fstat(child).st_dev == dev:
                total += _walk_bytes(child, dev, depth + 1, seen, links, max_entries)
        finally:
            os.close(child)
    return total


def measure_folder_bytes(root: Path, max_entries: int = MAX_WALK_ENTRIES) -> int:
    """Allocated bytes (``st_blocks * 512``, each inode once) under ``root``; raise MeasureError."""
    try:
        fd = os.open(root, DIR_OPEN_FLAGS)
        try:
            return _walk_bytes(fd, os.fstat(fd).st_dev, 0, [0], set(), max_entries)
        finally:
            os.close(fd)
    except OSError as exc:
        raise MeasureError(
            f"work folder size read failed under {root}: {exc.strerror or exc}", FolderState.UNREADABLE
        ) from exc


def _default_disk_free(path: Path) -> int:
    return shutil.disk_usage(path).free


def run(
    config: Config,
    *,
    disk_free: Callable[[Path], object],
    ceiling_bytes: int = WORK_FOLDER_CEILING_BYTES,
    max_walk_entries: int = MAX_WALK_ENTRIES,
) -> Outcome:
    context = config.context()
    floor_bytes = floor_gib(config.event) * GIB
    unmeasured = Facts(
        config.event, config.dry_run, floor_bytes, None, None, False, "", FolderState.NOT_MEASURED, None, None, "",
        False, ceiling_bytes, Action.NOT_NEEDED, (), (), (), 0, (),
    )
    try:
        before, is_input = read_free_bytes(config, disk_free)
    except Undecidable as exc:
        facts = dataclasses.replace(unmeasured, free_reason=str(exc), notes=(str(exc),))
        return Outcome(context, facts, decide(facts), (str(exc),))
    folder_state = FolderState.NOT_MEASURED
    folder_before: int | None = None
    folder_reason = ""
    over = False
    if config.event is Event.JOB_STARTED:
        try:
            folder_before = measure_folder_bytes(config.work_root, max_walk_entries)
            folder_state = FolderState.MEASURED
            over = folder_before > ceiling_bytes
        except MeasureError as exc:
            folder_state = exc.state
            folder_reason = exc.reason
    need_clear = before < floor_bytes or over
    report = TargetReport((), (), (), 0, 0, ())
    action = Action.NOT_NEEDED
    if need_clear:
        report = clear_targets(config)
        action = _action_of(report, config.dry_run)
    after: int | None = before
    folder_after = folder_before
    notes = list(report.notes)
    if report.completed or report.partial:
        try:
            after, _ = read_free_bytes(config, disk_free)
        except Undecidable as exc:
            after = None
            notes.append(f"{exc} after the removal")
        if folder_state is FolderState.MEASURED:
            try:
                folder_after = measure_folder_bytes(config.work_root, max_walk_entries)
            except MeasureError as exc:
                folder_after = None
                notes.append(f"{exc.reason} after the removal")
    facts = Facts(
        config.event, config.dry_run, floor_bytes, before, after, is_input, "", folder_state, folder_before,
        folder_after, folder_reason, over, ceiling_bytes, action, report.completed, report.partial, report.would,
        report.entries, tuple(notes),
    )
    shown = ([folder_reason] if folder_reason else []) + notes  # the reason line already holds folder_reason once
    return Outcome(context, facts, decide(facts), tuple(shown))


def _action_of(report: TargetReport, dry_run: bool) -> Action:
    if report.candidates == 0:
        return Action.NO_TARGET
    if report.partial:
        return Action.PARTIAL
    if dry_run:
        return Action.WOULD_CLEAR if report.would else Action.REFUSED_TARGET
    return Action.CLEARED if report.completed else Action.REFUSED_TARGET


def _stamp(now: datetime.datetime) -> str:
    return now.astimezone(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def format_line(outcome: Outcome, now: datetime.datetime) -> str:
    context = outcome.context
    verdict = outcome.verdict
    facts = outcome.facts
    if facts is None:
        before = after = folder_before = folder_after = UNKNOWN
        entries = 0
    else:
        before = _free_text(facts.free_before, facts.free_is_input)
        after = _free_text(facts.free_after, facts.free_is_input)
        if facts.free_before is not None and facts.action not in (Action.CLEARED, Action.PARTIAL):
            after = before
        folder_before = _bytes_text(facts.folder_before)
        folder_after = _bytes_text(facts.folder_after)
        entries = facts.entries
    paths = json.dumps([safe_text(path) for path in verdict.paths])
    line = (
        f"{_stamp(now)} runner={safe_text(context.runner)} event={safe_text(context.event)} free_before_gib={before} "
        f"free_after_gib={after} folder_bytes_before={folder_before} folder_bytes_after={folder_after} "
        f"decision={verdict.decision.value} removed={verdict.removed} entries={entries} paths={paths} "
        f"reason={json.dumps(safe_text(verdict.reason))}"
    )
    return line + " dry-run" if context.dry_run else line


def append_log(path: Path, line: str, *, create_dir: bool = False) -> str | None:
    """Append one line; the file is created 0o600 and, for the default path, its directory 0o700."""
    data = (line + "\n").encode("utf-8", "backslashreplace")
    try:
        if create_dir:
            os.makedirs(path.parent, mode=LOG_DIR_MODE, exist_ok=True)
        flags = os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
        fd = os.open(path, flags, LOG_FILE_MODE)
        try:
            view = memoryview(data)
            while view:
                view = view[os.write(fd, view):]
        finally:
            os.close(fd)
    except OSError as exc:
        return f"log write failed: {safe_text(path)}: {safe_text(exc.strerror or exc)}"
    return None


def _emit(stderr, safe: str) -> None:
    """Write one stderr line. ``safe`` is built only from ``safe_text`` parts (escaping twice would corrupt it)."""
    try:
        stderr.write(f"{STDERR_PREFIX}{safe}\n")
    except (OSError, UnicodeError):
        pass  # nothing left to report to; the exit code is already decided


def main(
    argv: Sequence[str] | None = None,
    env: Mapping[str, str] | None = None,
    *,
    home: Path | None = None,
    disk_free: Callable[[Path], object] | None = None,
    stderr=None,
    now: Callable[[], datetime.datetime] | None = None,
    ceiling_bytes: int = WORK_FOLDER_CEILING_BYTES,
    max_walk_entries: int = MAX_WALK_ENTRIES,
) -> int:
    argv = sys.argv[1:] if argv is None else argv
    env = os.environ if env is None else env
    stderr = sys.stderr if stderr is None else stderr
    clock = now or (lambda: datetime.datetime.now(datetime.timezone.utc))
    try:
        home_dir = Path.home() if home is None else home
    except (RuntimeError, KeyError):
        home_dir = Path("/nonexistent-home")
    context = LogContext(UNKNOWN, _env_runner(env), _scan_log_arg(argv, env, home_dir), False)
    try:
        config = parse_config(argv, env, home_dir)
        context = config.context()
        outcome = run(config, disk_free=disk_free or _default_disk_free, ceiling_bytes=ceiling_bytes,
                      max_walk_entries=max_walk_entries)
    except Refusal as refusal:
        verdict = Verdict(Decision.REFUSED, refusal.reason, EXIT_OK, 0, ())
        outcome = Outcome(refusal.context, None, verdict, (refusal.reason,))
    except Exception as exc:  # noqa: BLE001 - the reason is logged; the floor cannot be proven after a crash
        reason = f"internal error: {type(exc).__name__}: {exc}"
        outcome = Outcome(context, None, Verdict(Decision.REFUSED, reason, EXIT_OK, 0, ()), (reason,))
    moment = clock()
    stamp = _stamp(moment)
    line = format_line(outcome, moment)
    default_path = default_log_path(home_dir)
    failure = append_log(outcome.context.log_path, line, create_dir=outcome.context.log_path == default_path)
    if failure is not None:
        _emit(stderr, f"{failure}; line: {line}")
    verdict = outcome.verdict
    if verdict.decision is Decision.BELOW_FLOOR and outcome.facts is not None:
        facts = outcome.facts
        final = facts.free_after if facts.action in (Action.CLEARED, Action.PARTIAL) else facts.free_before
        fixed = below_floor_line(outcome.context.event, final, facts.floor_bytes, outcome.context.runner)
        append_log(outcome.context.log_path, f"{stamp} {fixed}", create_dir=outcome.context.log_path == default_path)
        _emit(stderr, fixed)
    for note in outcome.notes:
        _emit(stderr, f"{verdict.decision.value}: {safe_text(note)}")
    return verdict.exit_code


if __name__ == "__main__":
    sys.exit(main())
