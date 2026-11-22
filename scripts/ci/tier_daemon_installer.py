#!/usr/bin/env python3
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""Prepare (and, only on the operator's word, install) a launchd system daemon for the macOS CI PostgreSQL tier (#9853).

Why: the macos-fed test tier is one ``postgres -D <data dir>`` process.  It was supervised by a launchd agent of the
GUI login domain; when the login session ended (a WindowServer crash), launchd stopped the agent with it and every
enterprise-fed leg on the node failed or hung.  The only launchd domain that exists without a login session is the
system domain, which needs root.  This tool makes that lasting fix reviewable and reversible.

Modes (all three take the same required arguments, so ``--remove`` can prove the plist is the one it would write):

* no mode flag: the DRY RUN, the default.  It writes nothing and runs no state-changing command: it reads the account
  database, ``lstat``s the paths, reads the plist target and ``postmaster.pid``, runs ``ps -p <pid>`` and the read-only
  ``launchctl print system/<label>``, then prints the full plist it would write, the account the daemon runs as, the
  install commands in order, the hand-over order and the removal path, and one verdict line per mode.
* ``--install``: needs effective uid 0 (the tool never calls sudo; the refusal prints the command to run).  Refuses a
  plist target holding other bytes (prints sizes and sha256 only, never content), is a no-op when identical bytes
  are there and the service is loaded, refuses while a live postmaster holds the data directory unless
  ``--handover`` is given.  With ``--handover`` it waits (bounded) for that pid to exit, which the operator causes by
  stopping the interim supervisor and then the postmaster cleanly; the tool never signals a process.  Then it
  publishes the plist (temp file in the same directory, fsync, mode 0644, owner root:wheel, ``link`` so a target
  that appeared after the check is never replaced, directory fsync), runs ``launchctl bootstrap system <plist>``
  and proves ``127.0.0.1:<port>`` answers within a deadline.  A failure after the write prints the state it
  re-reads and the removal commands; it does not undo anything silently.
* ``--remove``: needs effective uid 0.  The exact inverse: ``launchctl bootout system/<label>`` when loaded, then
  removes the plist.  Refuses a plist whose bytes this tool would not have written; a second run is a no-op.

The daemon never runs as root: the plist names a non-root ``UserName`` and its primary ``GroupName`` (gid 0 refused).
``ProgramArguments`` is an argument list (no shell).  The tool never reads the tier URL file or any environment value
and never prints one; its child processes get a fixed environment.

Every host-specific value is an argument; every refusal has its own exact message (``REFUSE_*``) and exit code
(``EXIT_*``).  All host probes and changes go through one runner object (``HostRunner``); the tests inject a fake one.
``HostRunner(allow_changes=False)``, which the dry run uses, raises before any write, removal or launchctl change.

Usage:
  python3 scripts/ci/tier_daemon_installer.py --postgres-bin BIN --data-dir DIR --account NAME --label LABEL --port N
  ... --install [--handover]
  ... --remove
Python 3.12+, standard library only.
"""

from __future__ import annotations

import argparse
import dataclasses
import enum
import errno
import grp
import hashlib
import os
import plistlib
import pwd
import re
import shlex
import socket
import stat
import subprocess
import sys
import time
from pathlib import PurePosixPath

TOOL_NAME = "tier-daemon-installer"
SCRIPT_PATH = "scripts/ci/tier_daemon_installer.py"
LAUNCH_DAEMONS_DIR = "/Library/LaunchDaemons"
LAUNCHCTL = "/bin/launchctl"
PS = "/bin/ps"
CHILD_ENV = {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LC_ALL": "C"}
LAUNCHCTL_NOT_FOUND_RC = 113
PROBE_HOST = "127.0.0.1"
PROBE_DEADLINE_SECONDS = 60
PROBE_INTERVAL_SECONDS = 0.5
PROBE_CONNECT_TIMEOUT_SECONDS = 2.0
HANDOVER_DEADLINE_SECONDS = 300
HANDOVER_INTERVAL_SECONDS = 1.0
CHILD_TIMEOUT_SECONDS = 30
EXIT_TIMEOUT_SECONDS = 60
PLIST_MODE = 0o644
TEMP_MODE = 0o600
ROOT_UID = 0
WHEEL_GID = 0
WRITABLE_BY_GROUP_OR_OTHERS = stat.S_IWGRP | stat.S_IWOTH
ANY_EXECUTE = stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH
MAX_PLIST_BYTES = 65536
MAX_PIDFILE_BYTES = 4096
MAX_PID = 2**31 - 1
MIN_PORT = 1
MAX_PORT = 65535
MAX_PATH_CHARS = 1024
PIDFILE_NAME = "postmaster.pid"
PG_CTL_NAME = "pg_ctl"
ACCOUNT_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_.-]{0,63}")
LABEL_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}")
PORT_RE = re.compile(r"[0-9]{1,5}")
PID_RE = re.compile(r"[0-9]{1,10}")
ROOT_NAME = "root"

EXIT_OK = 0
EXIT_USAGE = 2
EXIT_NOT_ROOT = 3
EXIT_CONFLICT = 4
EXIT_POSTMASTER_RUNNING = 5
EXIT_COMMAND_FAILED = 6
EXIT_PROBE_FAILED = 7
EXIT_HANDOVER_TIMEOUT = 8
EXIT_HOST_ERROR = 9
EXIT_PLATFORM = 10

PLATFORM_DARWIN = "darwin"

REFUSE_PLATFORM = "this tool runs on macOS only (sys.platform is {platform!r})"
REFUSE_UNSET = "{flag} is not set"
REFUSE_EMPTY = "{flag} is empty"
REFUSE_CONTROL = "{flag} contains a control character"
REFUSE_NOT_UTF8 = "{flag} is not valid UTF-8"
REFUSE_HANDOVER_MODE = "--handover goes with --install only"
REFUSE_TOO_LONG = "{flag} is longer than {limit} characters"
REFUSE_RELATIVE = "{flag} is not an absolute path"
REFUSE_NOT_NORMAL = "{flag} is not in normal form (no '.', '..', '//' or trailing '/')"
REFUSE_MISSING = "{flag} {path} does not exist"
REFUSE_SYMLINK = "{flag} {path} is a symlink"
REFUSE_NOT_FILE = "{flag} {path} is not a regular file"
REFUSE_NOT_DIR = "{flag} {path} is not a directory"
REFUSE_NOT_EXEC = "{flag} {path} is not executable"
REFUSE_BIN_WRITABLE = "{flag} {path} is writable by group or others"
REFUSE_DATA_OWNER = "{flag} {path} is owned by uid {uid}, not by {account} (uid {account_uid})"
REFUSE_DATA_WRITABLE = "{flag} {path} is group or world writable"
REFUSE_ACCOUNT_ROOT = "--account root is refused: the daemon never runs as root"
REFUSE_ACCOUNT_INVALID = "--account {account!r} is not a valid account name"
REFUSE_ACCOUNT_UNKNOWN = "--account {account} is not a known account"
REFUSE_ACCOUNT_UID0 = "--account {account} has uid 0: the daemon never runs as root"
REFUSE_GROUP_UNKNOWN = "--account {account} has primary gid {gid}, which has no group entry"
REFUSE_GROUP_WHEEL = "--account {account} has primary gid 0: the daemon never runs with group {group}"
REFUSE_LABEL_INVALID = "--label {label!r} is not a valid launchd label (letters, digits, '.', '_', '-'; 128 at most)"
REFUSE_PORT_INVALID = "--port {port!r} is not a port number between 1 and 65535"
REFUSE_PLIST_DIR = "launchd directory {path} {why}"
REFUSE_TARGET_KIND = "plist target {path} {why}"
REFUSE_PIDFILE = "{path} {why}"
REFUSE_NOT_ROOT = "{mode} needs root (effective uid {euid}); this tool never calls sudo; run: sudo {command}"
REFUSE_DIFFERENT = "plist target {path} holds different bytes ({summary}); nothing changed"
REFUSE_NOT_OURS = "plist target {path} is not ours ({summary}); nothing changed"
REFUSE_LOADED_NO_PLIST = "system/{label} is loaded but {path} is absent; nothing changed; inspect: launchctl print system/{label}"
REFUSE_POSTMASTER = "postmaster pid {pid} holds {data_dir}; nothing changed; stop its supervisor, then pass --handover"
REFUSE_NEW_POSTMASTER = "postmaster pid {pid} started on {data_dir} during the hand-over; nothing changed; stop the interim supervisor first"
REFUSE_HANDOVER_TIMEOUT = "postmaster pid {pid} did not exit within {seconds} s; nothing changed"
REFUSE_HOST = "host probe failed: {why}"

PIDFILE_EMPTY = "is empty"
PIDFILE_BAD_PID = "does not start with a process id"
PIDFILE_TOO_BIG = "is larger than {limit} bytes".format(limit=MAX_PIDFILE_BYTES)


class Mode(enum.Enum):
    """What the invocation asked for."""

    DRY_RUN = "dry run"
    INSTALL = "--install"
    REMOVE = "--remove"


class Kind(enum.Enum):
    """What ``lstat`` found at a path."""

    ABSENT = "absent"
    FILE = "file"
    DIR = "dir"
    SYMLINK = "symlink"
    OTHER = "other"


class Target(enum.Enum):
    """The plist target compared with the bytes this tool would write."""

    ABSENT = "absent"
    IDENTICAL = "identical bytes"
    DIFFERENT = "different bytes"


class Postmaster(enum.Enum):
    """The data directory's postmaster.pid as found."""

    NONE = "none"
    ALIVE = "alive"
    STALE = "stale"


class Verdict(enum.Enum):
    """What a mode does with the checked state."""

    PROCEED = "proceed"
    NOOP = "no-op"
    REFUSE = "refuse"
    HANDOVER = "hand-over"


class Step(enum.Enum):
    """A state-changing or proving step, in the order it runs."""

    WAIT_EXIT = "wait"
    WRITE = "write"
    BOOTSTRAP = "bootstrap"
    PROBE = "probe"
    BOOTOUT = "bootout"
    REMOVE = "remove"


class HostError(Exception):
    """A read-only host probe failed; the tool refuses rather than guess."""


class ChangesNotAllowed(Exception):
    """A state-changing call reached a runner built for the dry run."""


@dataclasses.dataclass(frozen=True)
class Facts:
    """The part of an ``lstat`` result the checks read."""

    kind: Kind
    uid: int = -1
    mode: int = 0


@dataclasses.dataclass(frozen=True)
class Account:
    """A resolved non-root account."""

    name: str
    uid: int
    gid: int
    group: str


@dataclasses.dataclass(frozen=True)
class Config:
    """Validated arguments; built only by ``parse_config``."""

    mode: Mode
    handover: bool
    postgres_bin: str
    data_dir: str
    account: Account
    label: str
    port: int

    @property
    def plist_path(self) -> str:
        return f"{LAUNCH_DAEMONS_DIR}/{self.label}.plist"

    @property
    def pg_ctl(self) -> str:
        return str(PurePosixPath(self.postgres_bin).parent / PG_CTL_NAME)

    @property
    def service(self) -> str:
        return f"system/{self.label}"


@dataclasses.dataclass(frozen=True)
class State:
    """Everything the decision reads, checked at one moment."""

    euid: int
    target: Target
    target_summary: str
    loaded: bool
    postmaster: Postmaster
    pid: int


@dataclasses.dataclass(frozen=True)
class Plan:
    """The decision for one mode, computed from ``State`` only."""

    verdict: Verdict
    steps: tuple[Step, ...]
    exit_code: int
    reason: str


@dataclasses.dataclass
class Outcome:
    """What one invocation printed and returned."""

    code: int = EXIT_OK
    out: list[str] = dataclasses.field(default_factory=list)
    err: list[str] = dataclasses.field(default_factory=list)

    def refuse(self, code: int, message: str) -> Outcome:
        self.err.append(f"{TOOL_NAME}: refused: {message}")
        self.code = code
        return self


class Refusal(Exception):
    """An input or state the tool will not act on: exact message and exit code."""

    def __init__(self, code: int, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


class HostRunner:
    """The real host.  Every probe and every change of the tool goes through one of these methods."""

    def __init__(self, allow_changes: bool) -> None:
        self._allow_changes = allow_changes

    def _require_changes(self) -> None:
        if not self._allow_changes:
            raise ChangesNotAllowed("a state-changing call reached the dry-run runner")

    def platform(self) -> str:
        return sys.platform

    def euid(self) -> int:
        return os.geteuid()

    def lookup_account(self, name: str) -> tuple[int, int] | None:
        try:
            entry = pwd.getpwnam(name)
        except KeyError:
            return None
        return entry.pw_uid, entry.pw_gid

    def lookup_group(self, gid: int) -> str | None:
        try:
            return grp.getgrgid(gid).gr_name
        except KeyError:
            return None

    def lstat(self, path: str) -> Facts:
        try:
            st = os.lstat(path)
        except FileNotFoundError:
            return Facts(Kind.ABSENT)
        except OSError as exc:
            raise HostError(f"lstat {path}: {errno.errorcode.get(exc.errno or 0, 'error')}") from exc
        if stat.S_ISLNK(st.st_mode):
            kind = Kind.SYMLINK
        elif stat.S_ISREG(st.st_mode):
            kind = Kind.FILE
        elif stat.S_ISDIR(st.st_mode):
            kind = Kind.DIR
        else:
            kind = Kind.OTHER
        return Facts(kind, st.st_uid, stat.S_IMODE(st.st_mode))

    def read_file(self, path: str, limit: int) -> bytes | None:
        """Read at most ``limit + 1`` bytes of a regular file without following a symlink; None when absent."""
        try:
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        except FileNotFoundError:
            return None
        except OSError as exc:
            raise HostError(f"open {path}: {errno.errorcode.get(exc.errno or 0, 'error')}") from exc
        try:
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                raise HostError(f"open {path}: not a regular file")
            chunks: list[bytes] = []
            remaining = limit + 1
            while remaining > 0:
                chunk = os.read(fd, remaining)
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            return b"".join(chunks)
        except OSError as exc:
            raise HostError(f"read {path}: {errno.errorcode.get(exc.errno or 0, 'error')}") from exc
        finally:
            os.close(fd)

    def _run(self, argv: list[str]) -> subprocess.CompletedProcess[str]:
        try:
            return subprocess.run(
                argv,
                capture_output=True,
                text=True,
                env=CHILD_ENV,
                timeout=CHILD_TIMEOUT_SECONDS,
                check=False,
                stdin=subprocess.DEVNULL,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise HostError(f"{argv[0]} {argv[1]}: {type(exc).__name__}") from exc

    def service_loaded(self, service: str) -> bool:
        done = self._run([LAUNCHCTL, "print", service])
        if done.returncode == 0:
            return True
        if done.returncode == LAUNCHCTL_NOT_FOUND_RC:
            return False
        raise HostError(f"launchctl print {service} exited {done.returncode}")

    def pid_alive(self, pid: int) -> bool:
        done = self._run([PS, "-p", str(pid), "-o", "pid="])
        answer = done.stdout.strip()
        if done.returncode == 0 and answer == str(pid):
            return True
        if done.returncode == 1 and not answer:
            return False
        raise HostError(f"ps -p {pid} exited {done.returncode}")

    def wait_pid_exit(self, pid: int, seconds: int) -> bool:
        deadline = time.monotonic() + seconds
        while self.pid_alive(pid):
            if time.monotonic() >= deadline:
                return False
            time.sleep(HANDOVER_INTERVAL_SECONDS)
        return True

    def publish_file(self, path: str, data: bytes) -> None:
        """Write ``data`` to a new file at ``path``: same-directory temp file, fsync, mode, owner, link, dir fsync."""
        self._require_changes()
        target = PurePosixPath(path)
        dir_fd = os.open(str(target.parent), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        temp_name = f".{target.name}.tmp-{os.getpid()}"
        try:
            fd = os.open(temp_name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, TEMP_MODE, dir_fd=dir_fd)
            try:
                view = memoryview(data)
                while view:
                    view = view[os.write(fd, view) :]
                os.fchown(fd, ROOT_UID, WHEEL_GID)
                os.fchmod(fd, PLIST_MODE)
                os.fsync(fd)
            finally:
                os.close(fd)
            try:
                os.link(temp_name, target.name, src_dir_fd=dir_fd, dst_dir_fd=dir_fd, follow_symlinks=False)
            finally:
                os.unlink(temp_name, dir_fd=dir_fd)
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)

    def remove_file(self, path: str) -> None:
        self._require_changes()
        target = PurePosixPath(path)
        dir_fd = os.open(str(target.parent), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.unlink(target.name, dir_fd=dir_fd)
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)

    def launchctl(self, args: tuple[str, ...]) -> int:
        self._require_changes()
        return self._run([LAUNCHCTL, *args]).returncode

    def probe_port(self, port: int, seconds: int) -> bool:
        deadline = time.monotonic() + seconds
        while True:
            try:
                with socket.create_connection((PROBE_HOST, port), timeout=PROBE_CONNECT_TIMEOUT_SECONDS):
                    return True
            except OSError:
                if time.monotonic() >= deadline:
                    return False
                time.sleep(PROBE_INTERVAL_SECONDS)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog=SCRIPT_PATH, description=__doc__.split("\n\n", 1)[0])
    parser.add_argument("--postgres-bin", help="absolute path of the postgres server binary")
    parser.add_argument("--data-dir", help="absolute path of the tier's data directory")
    parser.add_argument("--account", help="non-root account the daemon runs as (owner of the data directory)")
    parser.add_argument("--label", help="launchd label; the plist is <launchd dir>/<label>.plist")
    parser.add_argument("--port", help="port postgres listens on (-p) and the install probe connects to")
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument("--install", action="store_true", help="install (root only; dry run without it)")
    modes.add_argument("--remove", action="store_true", help="remove what --install wrote (root only)")
    parser.add_argument("--handover", action="store_true", help="with --install: wait for the running postmaster to exit")
    return parser


def _text_arg(flag: str, value: str | None) -> str:
    if value is None:
        raise Refusal(EXIT_USAGE, REFUSE_UNSET.format(flag=flag))
    if value == "":
        raise Refusal(EXIT_USAGE, REFUSE_EMPTY.format(flag=flag))
    if len(value) > MAX_PATH_CHARS:
        raise Refusal(EXIT_USAGE, REFUSE_TOO_LONG.format(flag=flag, limit=MAX_PATH_CHARS))
    if any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in value):
        raise Refusal(EXIT_USAGE, REFUSE_CONTROL.format(flag=flag))
    try:
        value.encode("utf-8")
    except UnicodeEncodeError:
        raise Refusal(EXIT_USAGE, REFUSE_NOT_UTF8.format(flag=flag)) from None
    return value


def _path_arg(flag: str, value: str | None) -> str:
    path = _text_arg(flag, value)
    if not path.startswith("/"):
        raise Refusal(EXIT_USAGE, REFUSE_RELATIVE.format(flag=flag))
    if os.path.normpath(path) != path or path.startswith("//"):
        raise Refusal(EXIT_USAGE, REFUSE_NOT_NORMAL.format(flag=flag))
    return path


def _check_binary(runner: HostRunner, path: str) -> None:
    flag = "--postgres-bin"
    facts = runner.lstat(path)
    match facts.kind:
        case Kind.ABSENT:
            raise Refusal(EXIT_USAGE, REFUSE_MISSING.format(flag=flag, path=path))
        case Kind.SYMLINK:
            raise Refusal(EXIT_USAGE, REFUSE_SYMLINK.format(flag=flag, path=path))
        case Kind.DIR | Kind.OTHER:
            raise Refusal(EXIT_USAGE, REFUSE_NOT_FILE.format(flag=flag, path=path))
        case Kind.FILE:
            pass
        case _:
            raise AssertionError(facts.kind)
    if facts.mode & ANY_EXECUTE == 0:
        raise Refusal(EXIT_USAGE, REFUSE_NOT_EXEC.format(flag=flag, path=path))
    if facts.mode & WRITABLE_BY_GROUP_OR_OTHERS:
        raise Refusal(EXIT_USAGE, REFUSE_BIN_WRITABLE.format(flag=flag, path=path))


def _check_data_dir(runner: HostRunner, path: str, account: Account) -> None:
    flag = "--data-dir"
    facts = runner.lstat(path)
    match facts.kind:
        case Kind.ABSENT:
            raise Refusal(EXIT_USAGE, REFUSE_MISSING.format(flag=flag, path=path))
        case Kind.SYMLINK:
            raise Refusal(EXIT_USAGE, REFUSE_SYMLINK.format(flag=flag, path=path))
        case Kind.FILE | Kind.OTHER:
            raise Refusal(EXIT_USAGE, REFUSE_NOT_DIR.format(flag=flag, path=path))
        case Kind.DIR:
            pass
        case _:
            raise AssertionError(facts.kind)
    if facts.uid != account.uid:
        raise Refusal(
            EXIT_USAGE,
            REFUSE_DATA_OWNER.format(flag=flag, path=path, uid=facts.uid, account=account.name, account_uid=account.uid),
        )
    if facts.mode & WRITABLE_BY_GROUP_OR_OTHERS:
        raise Refusal(EXIT_USAGE, REFUSE_DATA_WRITABLE.format(flag=flag, path=path))


def _resolve_account(runner: HostRunner, value: str | None) -> Account:
    name = _text_arg("--account", value)
    if name == ROOT_NAME:
        raise Refusal(EXIT_USAGE, REFUSE_ACCOUNT_ROOT)
    if not ACCOUNT_RE.fullmatch(name):
        raise Refusal(EXIT_USAGE, REFUSE_ACCOUNT_INVALID.format(account=name))
    ids = runner.lookup_account(name)
    if ids is None:
        raise Refusal(EXIT_USAGE, REFUSE_ACCOUNT_UNKNOWN.format(account=name))
    uid, gid = ids
    if uid == ROOT_UID:
        raise Refusal(EXIT_USAGE, REFUSE_ACCOUNT_UID0.format(account=name))
    group = runner.lookup_group(gid)
    if group is None:
        raise Refusal(EXIT_USAGE, REFUSE_GROUP_UNKNOWN.format(account=name, gid=gid))
    if gid == WHEEL_GID:
        raise Refusal(EXIT_USAGE, REFUSE_GROUP_WHEEL.format(account=name, group=group))
    return Account(name, uid, gid, group)


def parse_config(args: argparse.Namespace, runner: HostRunner) -> Config:
    """The one way to a ``Config``: every argument checked, in a fixed order, each refusal exact."""
    mode = Mode.INSTALL if args.install else Mode.REMOVE if args.remove else Mode.DRY_RUN
    postgres_bin = _path_arg("--postgres-bin", args.postgres_bin)
    data_dir = _path_arg("--data-dir", args.data_dir)
    label = _text_arg("--label", args.label)
    if not LABEL_RE.fullmatch(label):
        raise Refusal(EXIT_USAGE, REFUSE_LABEL_INVALID.format(label=label))
    port_text = _text_arg("--port", args.port)
    if not PORT_RE.fullmatch(port_text) or not MIN_PORT <= int(port_text) <= MAX_PORT:
        raise Refusal(EXIT_USAGE, REFUSE_PORT_INVALID.format(port=port_text))
    account = _resolve_account(runner, args.account)
    _check_binary(runner, postgres_bin)
    _check_data_dir(runner, data_dir, account)
    return Config(mode, args.handover, postgres_bin, data_dir, account, label, int(port_text))


def plist_dict(config: Config) -> dict[str, object]:
    return {
        "Label": config.label,
        "ProgramArguments": [config.postgres_bin, "-D", config.data_dir, "-p", str(config.port)],
        "UserName": config.account.name,
        "GroupName": config.account.group,
        "WorkingDirectory": config.data_dir,
        "RunAtLoad": True,
        "KeepAlive": True,
        "ExitTimeOut": EXIT_TIMEOUT_SECONDS,
    }


def plist_bytes(config: Config) -> bytes:
    return plistlib.dumps(plist_dict(config), fmt=plistlib.FMT_XML, sort_keys=True)


def _summary(expected: bytes, found: bytes) -> str:
    if len(found) > MAX_PLIST_BYTES:
        return f"found more than {MAX_PLIST_BYTES} bytes, expected {len(expected)} bytes"
    expected_lines = expected.splitlines()
    found_lines = found.splitlines()
    differing = sum(1 for a, b in zip(expected_lines, found_lines) if a != b)
    differing += abs(len(expected_lines) - len(found_lines))
    return (
        f"found {len(found)} bytes sha256 {hashlib.sha256(found).hexdigest()[:16]}, "
        f"expected {len(expected)} bytes sha256 {hashlib.sha256(expected).hexdigest()[:16]}, "
        f"{differing} lines differ"
    )


def _check_plist_dir(runner: HostRunner) -> None:
    facts = runner.lstat(LAUNCH_DAEMONS_DIR)
    match facts.kind:
        case Kind.DIR:
            pass
        case Kind.ABSENT:
            raise Refusal(EXIT_HOST_ERROR, REFUSE_PLIST_DIR.format(path=LAUNCH_DAEMONS_DIR, why="does not exist"))
        case Kind.SYMLINK:
            raise Refusal(EXIT_HOST_ERROR, REFUSE_PLIST_DIR.format(path=LAUNCH_DAEMONS_DIR, why="is a symlink"))
        case Kind.FILE | Kind.OTHER:
            raise Refusal(EXIT_HOST_ERROR, REFUSE_PLIST_DIR.format(path=LAUNCH_DAEMONS_DIR, why="is not a directory"))
        case _:
            raise AssertionError(facts.kind)
    if facts.uid != ROOT_UID or facts.mode & WRITABLE_BY_GROUP_OR_OTHERS:
        raise Refusal(
            EXIT_HOST_ERROR,
            REFUSE_PLIST_DIR.format(path=LAUNCH_DAEMONS_DIR, why="is not owned by root or is group or world writable"),
        )


def _read_target(runner: HostRunner, config: Config, expected: bytes) -> tuple[Target, str]:
    path = config.plist_path
    facts = runner.lstat(path)
    match facts.kind:
        case Kind.ABSENT:
            return Target.ABSENT, ""
        case Kind.FILE:
            pass
        case Kind.SYMLINK:
            raise Refusal(EXIT_CONFLICT, REFUSE_TARGET_KIND.format(path=path, why="is a symlink; nothing changed"))
        case Kind.DIR | Kind.OTHER:
            raise Refusal(EXIT_CONFLICT, REFUSE_TARGET_KIND.format(path=path, why="is not a regular file; nothing changed"))
        case _:
            raise AssertionError(facts.kind)
    found = runner.read_file(path, MAX_PLIST_BYTES)
    if found is None:
        return Target.ABSENT, ""
    if found == expected:
        return Target.IDENTICAL, ""
    return Target.DIFFERENT, _summary(expected, found)


def _read_postmaster(runner: HostRunner, config: Config) -> tuple[Postmaster, int]:
    path = f"{config.data_dir}/{PIDFILE_NAME}"
    data = runner.read_file(path, MAX_PIDFILE_BYTES)
    if data is None:
        return Postmaster.NONE, 0
    if len(data) > MAX_PIDFILE_BYTES:
        raise Refusal(EXIT_HOST_ERROR, REFUSE_PIDFILE.format(path=path, why=PIDFILE_TOO_BIG))
    if not data:
        raise Refusal(EXIT_HOST_ERROR, REFUSE_PIDFILE.format(path=path, why=PIDFILE_EMPTY))
    first = data.split(b"\n", 1)[0].decode("ascii", errors="replace")
    if not PID_RE.fullmatch(first) or not 0 < int(first) <= MAX_PID:
        raise Refusal(EXIT_HOST_ERROR, REFUSE_PIDFILE.format(path=path, why=PIDFILE_BAD_PID))
    pid = int(first)
    return (Postmaster.ALIVE if runner.pid_alive(pid) else Postmaster.STALE), pid


def read_state(runner: HostRunner, config: Config, expected: bytes, euid: int) -> State:
    """Read every fact the decision needs; read-only calls only."""
    _check_plist_dir(runner)
    target, summary = _read_target(runner, config, expected)
    loaded = runner.service_loaded(config.service)
    postmaster, pid = _read_postmaster(runner, config)
    return State(euid, target, summary, loaded, postmaster, pid)


def decide_install(config: Config, state: State) -> Plan:
    """The install decision as a function of the checked state (root assumed; the euid gate runs first)."""
    path, label = config.plist_path, config.label
    match state.target:
        case Target.DIFFERENT:
            return Plan(Verdict.REFUSE, (), EXIT_CONFLICT, REFUSE_DIFFERENT.format(path=path, summary=state.target_summary))
        case Target.IDENTICAL if state.loaded:
            return Plan(Verdict.NOOP, (), EXIT_OK, f"{path} holds identical bytes and system/{label} is loaded")
        case Target.ABSENT if state.loaded:
            return Plan(Verdict.REFUSE, (), EXIT_CONFLICT, REFUSE_LOADED_NO_PLIST.format(label=label, path=path))
        case Target.IDENTICAL | Target.ABSENT:
            pass
        case _:
            raise AssertionError(state.target)
    publish = (Step.WRITE,) if state.target is Target.ABSENT else ()
    tail = (*publish, Step.BOOTSTRAP, Step.PROBE)
    match state.postmaster:
        case Postmaster.ALIVE if not config.handover:
            return Plan(
                Verdict.REFUSE, (), EXIT_POSTMASTER_RUNNING, REFUSE_POSTMASTER.format(pid=state.pid, data_dir=config.data_dir)
            )
        case Postmaster.ALIVE:
            return Plan(
                Verdict.HANDOVER,
                (Step.WAIT_EXIT, *tail),
                EXIT_OK,
                f"wait up to {HANDOVER_DEADLINE_SECONDS} s for pid {state.pid} to exit, then {_step_words(tail)}",
            )
        case Postmaster.NONE | Postmaster.STALE:
            return Plan(Verdict.PROCEED, tail, EXIT_OK, _step_words(tail))
        case _:
            raise AssertionError(state.postmaster)


def decide_remove(config: Config, state: State) -> Plan:
    """The remove decision as a function of the checked state (root assumed)."""
    path, label = config.plist_path, config.label
    match state.target:
        case Target.DIFFERENT:
            return Plan(Verdict.REFUSE, (), EXIT_CONFLICT, REFUSE_NOT_OURS.format(path=path, summary=state.target_summary))
        case Target.ABSENT if state.loaded:
            return Plan(Verdict.REFUSE, (), EXIT_CONFLICT, REFUSE_LOADED_NO_PLIST.format(label=label, path=path))
        case Target.ABSENT:
            return Plan(Verdict.NOOP, (), EXIT_OK, f"{path} is absent and system/{label} is not loaded")
        case Target.IDENTICAL:
            steps = (Step.BOOTOUT, Step.REMOVE) if state.loaded else (Step.REMOVE,)
            return Plan(Verdict.PROCEED, steps, EXIT_OK, _step_words(steps))
        case _:
            raise AssertionError(state.target)


STEP_WORDS = {
    Step.WAIT_EXIT: "wait",
    Step.WRITE: "write",
    Step.BOOTSTRAP: "bootstrap",
    Step.PROBE: "probe",
    Step.BOOTOUT: "bootout",
    Step.REMOVE: "remove plist",
}


def _step_words(steps: tuple[Step, ...]) -> str:
    return ", ".join(STEP_WORDS[step] for step in steps)


def _postmaster_line(state: State) -> str:
    match state.postmaster:
        case Postmaster.NONE:
            return "postmaster: none"
        case Postmaster.ALIVE:
            return f"postmaster: alive, pid {state.pid}"
        case Postmaster.STALE:
            return f"postmaster: stale pid file, pid {state.pid} is not running"
        case _:
            raise AssertionError(state.postmaster)


def _target_line(config: Config, state: State) -> str:
    match state.target:
        case Target.ABSENT | Target.IDENTICAL:
            return f"plist target: {config.plist_path} {state.target.value}"
        case Target.DIFFERENT:
            return f"plist target: {config.plist_path} {state.target.value} ({state.target_summary})"
        case _:
            raise AssertionError(state.target)


def removal_lines(config: Config) -> list[str]:
    return [
        f"  1. launchctl bootout {config.service}",
        f"  2. rm {config.plist_path}",
    ]


def dry_run_lines(config: Config, state: State, data: bytes, command: str) -> list[str]:
    account = config.account
    probe = f"probe {PROBE_HOST}:{config.port}, deadline {PROBE_DEADLINE_SECONDS} s"
    bootstrap = f"launchctl bootstrap system {config.plist_path}"
    lines = [
        f"{TOOL_NAME}: dry run, nothing is changed",
        f"account: {account.name} uid {account.uid} group {account.group} gid {account.gid}",
        _target_line(config, state),
        f"service {config.service}: {'loaded' if state.loaded else 'not loaded'}",
        _postmaster_line(state),
        f"effective uid: {state.euid}",
        "--- plist begin ---",
        *data.decode("utf-8").splitlines(),
        "--- plist end ---",
        f"install, in order (as root: sudo {command} --install):",
        f"  1. write {config.plist_path} atomically, mode 0644, owner root:wheel",
        f"  2. {bootstrap}",
        f"  3. {probe}",
        f"hand-over when a postmaster holds the data directory (as root: sudo {command} --install --handover):",
        "  1. stop the interim supervisor of the running postmaster",
        f"  2. stop the running postmaster cleanly as {account.name}: {config.pg_ctl} -D {config.data_dir} stop -m fast",
        f"  3. the tool waits up to {HANDOVER_DEADLINE_SECONDS} s for that pid to exit and refuses if a new postmaster holds the data directory",
        f"  4. write {config.plist_path} as in install step 1 when it is absent",
        f"  5. {bootstrap}",
        f"  6. {probe}",
        f"removal, in order (as root: sudo {command} --remove):",
        *removal_lines(config),
    ]
    install = decide_install(config, state)
    remove = decide_remove(config, state)
    lines.append(f"install verdict: {install.verdict.value}: {install.reason}")
    lines.append(f"remove verdict: {remove.verdict.value}: {remove.reason}")
    return lines


def _after_failure(runner: HostRunner, config: Config, outcome: Outcome, code: int, what: str) -> Outcome:
    """Report the state re-read after a failed change, and the removal path; never undo silently."""
    try:
        facts = runner.lstat(config.plist_path)
        plist_state = "present" if facts.kind is not Kind.ABSENT else "absent"
        service_state = "loaded" if runner.service_loaded(config.service) else "not loaded"
    except HostError as exc:
        plist_state = service_state = f"unknown ({exc})"
    outcome.err.append(f"{TOOL_NAME}: failed: {what}")
    outcome.err.append(f"state: plist {config.plist_path} {plist_state}; service {config.service} {service_state}")
    outcome.err.append("removal, in order:")
    outcome.err.extend(removal_lines(config))
    outcome.code = code
    return outcome


def _install(runner: HostRunner, config: Config, plan: Plan, state: State, data: bytes, outcome: Outcome) -> Outcome:
    for step in plan.steps:
        match step:
            case Step.WAIT_EXIT:
                if not runner.wait_pid_exit(state.pid, HANDOVER_DEADLINE_SECONDS):
                    return outcome.refuse(
                        EXIT_HANDOVER_TIMEOUT, REFUSE_HANDOVER_TIMEOUT.format(pid=state.pid, seconds=HANDOVER_DEADLINE_SECONDS)
                    )
                postmaster, pid = _read_postmaster(runner, config)
                if postmaster is Postmaster.ALIVE:
                    return outcome.refuse(EXIT_POSTMASTER_RUNNING, REFUSE_NEW_POSTMASTER.format(pid=pid, data_dir=config.data_dir))
                outcome.out.append(f"postmaster pid {state.pid} exited")
            case Step.WRITE:
                try:
                    runner.publish_file(config.plist_path, data)
                except OSError as exc:
                    name = errno.errorcode.get(exc.errno or 0, type(exc).__name__)
                    return _after_failure(runner, config, outcome, EXIT_COMMAND_FAILED, f"writing {config.plist_path}: {name}")
                outcome.out.append(f"wrote {config.plist_path} (mode 0644, owner root:wheel)")
            case Step.BOOTSTRAP:
                rc = runner.launchctl(("bootstrap", "system", config.plist_path))
                if rc != 0:
                    return _after_failure(
                        runner, config, outcome, EXIT_COMMAND_FAILED, f"launchctl bootstrap system {config.plist_path} exited {rc}"
                    )
                outcome.out.append(f"bootstrapped {config.service}")
            case Step.PROBE:
                if not runner.probe_port(config.port, PROBE_DEADLINE_SECONDS):
                    return _after_failure(
                        runner,
                        config,
                        outcome,
                        EXIT_PROBE_FAILED,
                        f"{PROBE_HOST}:{config.port} did not answer within {PROBE_DEADLINE_SECONDS} s",
                    )
                outcome.out.append(f"{PROBE_HOST}:{config.port} answers; installed")
            case Step.BOOTOUT | Step.REMOVE:
                raise AssertionError(step)
            case _:
                raise AssertionError(step)
    return outcome


def _remove(runner: HostRunner, config: Config, plan: Plan, outcome: Outcome) -> Outcome:
    for step in plan.steps:
        match step:
            case Step.BOOTOUT:
                rc = runner.launchctl(("bootout", config.service))
                if rc != 0:
                    return _after_failure(runner, config, outcome, EXIT_COMMAND_FAILED, f"launchctl bootout {config.service} exited {rc}")
                outcome.out.append(f"booted out {config.service}")
            case Step.REMOVE:
                try:
                    runner.remove_file(config.plist_path)
                except OSError as exc:
                    name = errno.errorcode.get(exc.errno or 0, type(exc).__name__)
                    return _after_failure(runner, config, outcome, EXIT_COMMAND_FAILED, f"removing {config.plist_path}: {name}")
                outcome.out.append(f"removed {config.plist_path}")
            case Step.WAIT_EXIT | Step.WRITE | Step.BOOTSTRAP | Step.PROBE:
                raise AssertionError(step)
            case _:
                raise AssertionError(step)
    return outcome


def host_args(config: Config) -> list[str]:
    """The host arguments as validated, in a fixed order (what every printed command repeats)."""
    return [
        "--postgres-bin",
        config.postgres_bin,
        "--data-dir",
        config.data_dir,
        "--account",
        config.account.name,
        "--label",
        config.label,
        "--port",
        str(config.port),
    ]


def run(argv: list[str], runner: HostRunner, invocation: list[str]) -> Outcome:
    """Parse, check, decide and (only for --install/--remove as root) act.  ``invocation`` is how the tool was started."""
    outcome = Outcome()
    args = build_parser().parse_args(argv)
    try:
        platform = runner.platform()
        if platform != PLATFORM_DARWIN:
            raise Refusal(EXIT_PLATFORM, REFUSE_PLATFORM.format(platform=platform))
        if args.handover and args.remove:
            raise Refusal(EXIT_USAGE, REFUSE_HANDOVER_MODE)
        config = parse_config(args, runner)
        command = shlex.join([*invocation, *host_args(config)])
        euid = runner.euid()
        if config.mode is not Mode.DRY_RUN and euid != ROOT_UID:
            flags = [config.mode.value, *(["--handover"] if config.handover else [])]
            return outcome.refuse(
                EXIT_NOT_ROOT,
                REFUSE_NOT_ROOT.format(mode=config.mode.value, euid=euid, command=shlex.join([*shlex.split(command), *flags])),
            )
        data = plist_bytes(config)
        state = read_state(runner, config, data, euid)
        match config.mode:
            case Mode.DRY_RUN:
                outcome.out.extend(dry_run_lines(config, state, data, command))
                return outcome
            case Mode.INSTALL:
                plan = decide_install(config, state)
            case Mode.REMOVE:
                plan = decide_remove(config, state)
            case _:
                raise AssertionError(config.mode)
        if plan.verdict is Verdict.REFUSE:
            return outcome.refuse(plan.exit_code, plan.reason)
        outcome.out.append(f"{TOOL_NAME}: {config.mode.value}: {plan.verdict.value}: {plan.reason}")
        if config.mode is Mode.INSTALL:
            return _install(runner, config, plan, state, data, outcome)
        return _remove(runner, config, plan, outcome)
    except Refusal as refusal:
        return outcome.refuse(refusal.code, refusal.message)
    except HostError as exc:
        return outcome.refuse(EXIT_HOST_ERROR, REFUSE_HOST.format(why=exc))


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    args = build_parser().parse_args(argv)
    runner = HostRunner(allow_changes=bool(args.install or args.remove))
    outcome = run(argv, runner, [sys.executable, SCRIPT_PATH])
    for line in outcome.out:
        print(line)
    for line in outcome.err:
        print(line, file=sys.stderr)
    return outcome.code


if __name__ == "__main__":
    sys.exit(main())
