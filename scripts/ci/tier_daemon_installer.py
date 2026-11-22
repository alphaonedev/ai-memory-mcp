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
  database, ``lstat``s the paths and every parent folder, opens the data directory and reads ``postmaster.pid``
  through that open directory, reads the plist target, runs ``ps -p <pid>`` and the read-only
  ``launchctl print system/<label>``, then prints the full plist it would write, the account the daemon runs as, the
  install steps in order, the hand-over order and the removal path (each rendered from the same plan the real run
  executes), and one verdict line per mode.
* ``--install``: needs effective uid 0 (the tool never calls sudo; the refusal prints the command to run).  Refuses a
  plist target holding other bytes (prints sizes and sha256 only, never content), is a no-op when identical bytes
  are there and the service is loaded, refuses while a live postmaster holds the data directory unless
  ``--handover --agent-label LABEL`` is given.  With ``--handover`` it waits (bounded) for that pid to exit, which
  the operator causes by disabling and stopping the interim login agent and then the postmaster; the tool never
  signals a process.  It then refuses while that login agent is not disabled (``launchctl print-disabled``), so only
  one supervisor can start the tier.  Every install then checks that nothing answers on ``127.0.0.1:<port>``,
  publishes the plist (temp file in the same directory, fsync, mode 0644, owner root:wheel, ``link`` so a target
  that appeared after the check is never replaced, directory fsync; a failed step unlinks the temp file with one retry, and a temp file left after both tries is
  named in the report with its ``rm`` undo), runs ``launchctl bootstrap system <plist>``, proves the port answers
  within a deadline and proves that ``postmaster.pid`` has 8 lines naming the pid launchd reports, the data
  directory, the port and status ``ready``, and that launchd reports the same pid after the read.  Only then does
  it print ``installed``.  A failure
  after the first change prints what was changed, the state it re-reads and the undo step for that state; it does
  not undo anything silently.
* ``--remove``: needs effective uid 0.  The exact inverse: ``launchctl bootout system/<label>`` when loaded (launchd
  sends postgres SIGTERM, a smart shutdown that waits for clients, then SIGKILL after ``ExitTimeOut`` = 60 s), then
  removes the plist.  Refuses a plist whose bytes this tool would not have written; a second run is a no-op.

The daemon never runs as root: the plist names a non-root ``UserName`` and its primary ``GroupName`` (gid 0 refused).
``ProgramArguments`` is an argument list (no shell); every printed command is built with ``shlex.join``.  The tool
never reads the tier URL file or any environment value and never prints one; its child processes get a fixed
environment.

Every host-specific value is an argument; every refusal has its own exact message (``REFUSE_*``) and exit code
(``EXIT_*``).  All host probes and changes go through one runner object (``HostRunner``); the tests inject a fake one.
``HostRunner(allow_changes=False)``, which the dry run uses, raises before any write, removal or launchctl change.

Usage:
  python3 -I /abs/path/scripts/ci/tier_daemon_installer.py --postgres-bin BIN --data-dir DIR --account NAME
  --label LABEL --port N  [--install [--handover --agent-label AGENT]] | [--remove]
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
import unicodedata
from collections.abc import Callable
from pathlib import Path, PurePosixPath

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
LOG_SUFFIX = ".log"
AGENT_LABEL_PLACEHOLDER = "AGENT_LABEL"
ACCOUNT_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_.-]{0,63}")
LABEL_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}")
PORT_RE = re.compile(r"[0-9]{1,5}")
PID_RE = re.compile(r"[0-9]{1,10}")
LAUNCHD_PID_RE = re.compile(r"^\tpid = ([0-9]{1,10})$", re.MULTILINE)
DISABLED_LINE_RE = re.compile(r'"([^"]*)" => (disabled|enabled|true|false)')
DISABLED_WORDS = frozenset({"disabled", "true"})
ROOT_NAME = "root"
# Unicode general categories the text check refuses (Cc control, Cf format incl. bidi, Zl/Zp separators).  A lone
# surrogate (Cs) is what an argument that is not UTF-8 decodes to, so REFUSE_NOT_UTF8 is its exact refusal.
REFUSED_CATEGORIES = frozenset({"Cf", "Zl", "Zp"})
NONCHARACTER_BLOCK = range(0xFDD0, 0xFDF0)
NONCHARACTER_LOW_BITS = 0xFFFE

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
EXIT_PORT_IN_USE = 11
EXIT_AGENT_ENABLED = 12

PLATFORM_DARWIN = "darwin"

REFUSE_PLATFORM = "this tool runs on macOS only (sys.platform is {platform!r})"
REFUSE_UNSET = "{flag} is not set"
REFUSE_EMPTY = "{flag} is empty"
REFUSE_CONTROL = "{flag} contains a control character"
REFUSE_CODEPOINT = "{flag} contains U+{code:04X} (category {category}), which is refused"
REFUSE_NONCHARACTER = "{flag} contains the noncharacter U+{code:04X}, which is refused"
REFUSE_NOT_UTF8 = "{flag} is not valid UTF-8"
REFUSE_HANDOVER_MODE = "--handover goes with --install or the dry run; --remove never waits for a postmaster"
REFUSE_AGENT_UNSET = "--handover needs --agent-label, the label of the interim login agent to be disabled"
REFUSE_AGENT_MODE = "--agent-label goes with --handover only"
REFUSE_AGENT_LABEL_INVALID = "--agent-label {label!r} is not a valid launchd label (letters, digits, '.', '_', '-'; 128 at most)"
REFUSE_TOO_LONG = "{flag} is longer than {limit} characters"
REFUSE_RELATIVE = "{flag} is not an absolute path"
REFUSE_NOT_NORMAL = "{flag} is not in normal form (no '.', '..', '//' or trailing '/')"
REFUSE_MISSING = "{flag} {path} does not exist"
REFUSE_SYMLINK = "{flag} {path} is a symlink"
REFUSE_NOT_FILE = "{flag} {path} is not a regular file"
REFUSE_NOT_DIR = "{flag} {path} is not a directory"
REFUSE_NOT_EXEC = "{flag} {path} is not executable"
REFUSE_BIN_WRITABLE = "{flag} {path} is writable by group or others"
REFUSE_BIN_OWNER = "{flag} {path} is owned by uid {uid}, not by root or {account} (uid {account_uid})"
REFUSE_PARENT = "{flag} {path}: parent folder {parent} {why}"
PARENT_MISSING = "does not exist"
PARENT_SYMLINK = "is a symlink"
PARENT_NOT_DIR = "is not a directory"
PARENT_OWNER = "is owned by uid {uid}, not by {owners}"
PARENT_WRITABLE = "is writable by group or others"
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
REFUSE_PLIST_ROUNDTRIP = "the plist for these arguments does not read back as written; nothing changed"
REFUSE_TARGET_KIND = "plist target {path} {why}"
REFUSE_PIDFILE = "{path} {why}"
REFUSE_NOT_ROOT = "{mode} needs root (effective uid {euid}); this tool never calls sudo; run: sudo {command}"
REFUSE_DIFFERENT = "plist target {path} holds different bytes ({summary}); nothing changed"
REFUSE_NOT_OURS = "plist target {path} is not ours ({summary}); nothing changed"
REFUSE_LOADED_NO_PLIST = "system/{label} is loaded but {path} is absent; nothing changed; inspect: launchctl print system/{label}"
REFUSE_POSTMASTER = "postmaster pid {pid} holds {data_dir}; nothing changed; stop its supervisor, then pass --handover"
REFUSE_NEW_POSTMASTER = "postmaster pid {pid} started on {data_dir} during the hand-over; nothing changed; stop the interim supervisor first"
REFUSE_HANDOVER_TIMEOUT = "postmaster pid {pid} did not exit within {seconds} s; nothing changed"
REFUSE_AGENT_ENABLED = (
    "login agent {label} of uid {uid} is not disabled and could start a second postmaster; nothing changed; "
    "disable it first: {command}"
)
REFUSE_PORT_IN_USE = "{host}:{port} already answers before bootstrap; another process holds the port; nothing changed"
REFUSE_RACE = "plist target {path} appeared during the install; nothing changed"
FAIL_RACE_TEMP_LEFT = "plist target {path} appeared during the install; temp file {temp} left in place"
REFUSE_HOST = "host probe failed: {why}; nothing changed"

FAIL_RC = "{command} exited {rc}"
FAIL_WRITE = "writing {path}: {name}"
FAIL_WRITE_LINKED = "writing {path}: {name} after the plist was linked in place"
TEMP_LEFT_SUFFIX = "; temp file {temp} left in place"
FAIL_REMOVE = "removing {path}: {name}"
FAIL_REMOVE_UNLINKED = "removing {path}: {name} after the plist was unlinked"
FAIL_PROBE = "{host}:{port} did not answer within {seconds} s"
FAIL_NO_LAUNCHD_PID = "launchd reports no pid for {service}"
FAIL_NO_POSTMASTER_PID = "{path} names no postmaster pid ({why})"
FAIL_PID_MISMATCH = "launchd pid {launchd_pid} of {service} is not the postmaster pid {pid} in {path}"
FAIL_DATA_DIR = "{why}"
FAIL_PIDFILE_UNREADABLE = "{path} is unreadable ({why})"
FAIL_PIDFILE_SHORT = "{path} has {lines} lines, not the {want} a started postmaster writes"
FAIL_PIDFILE_LONG = "{path} has text after line {want}"
FAIL_PIDFILE_DATA_DIR = "{path} names data directory {shown}, not {data_dir}"
FAIL_PIDFILE_PORT_EMPTY = "{path} has an empty port line"
FAIL_PIDFILE_PORT_NAN = "{path} port line {shown} is not a number"
FAIL_PIDFILE_PORT = "{path} names port {shown}, not {port}"
FAIL_PIDFILE_STATUS_EMPTY = "{path} has an empty status line"
FAIL_PIDFILE_STATUS = "{path} status is {shown}, not ready"
FAIL_REREAD_GONE = "launchd reports no pid for {service} after {path} was read"
FAIL_REREAD_CHANGED = "launchd pid of {service} changed from {before} to {after} while {path} was read"

# postmaster.pid as PostgreSQL writes it once the server accepts connections (pidfile.h): line 1 pid, line 2 data
# directory, line 4 port, line 8 the status padded with blanks.  Lines are counted from 1.
PIDFILE_LINES = 8
PIDFILE_DATA_DIR_LINE = 2
PIDFILE_PORT_LINE = 4
PIDFILE_STATUS_LINE = 8
PIDFILE_READY = b"ready"
PIDFILE_STATUS_PAD = b" "
PORT_LINE_RE = re.compile(rb"[0-9]+")
SHOWN_MAX_CHARS = 64
SHOWN_CUT = "..."
TEMP_LEFT_WORD = "left temp file "
UNLINK_TRIES = 2

PIDFILE_ABSENT = "absent"
PIDFILE_EMPTY = "is empty"
PIDFILE_BAD_PID = "does not start with a process id"
PIDFILE_TOO_BIG = "is larger than {limit} bytes".format(limit=MAX_PIDFILE_BYTES)

CHANGED_NOTHING = "nothing"
CHANGED_UNCONFIRMED = "nothing confirmed"
NOTHING_CHANGED_SUFFIX = "; nothing changed"


class Mode(enum.Enum):
    """What the invocation asked for."""

    DRY_RUN = "dry run"
    INSTALL = "--install"
    REMOVE = "--remove"


class Kind(enum.Enum):
    """What ``lstat`` (or ``fstat`` of an opened object) found at a path."""

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
    """A state-changing, checking or proving step, in the order it runs."""

    WAIT_EXIT = "wait"
    AGENT_DISABLED = "agent check"
    PORT_FREE = "port check"
    WRITE = "write"
    BOOTSTRAP = "bootstrap"
    PROBE = "probe"
    VERIFY = "verify"
    BOOTOUT = "bootout"
    REMOVE = "remove plist"


# Steps that change the host; a host error inside one leaves its effect unconfirmed.
CHANGING_STEPS = frozenset({Step.WRITE, Step.BOOTSTRAP, Step.BOOTOUT, Step.REMOVE})


class HostError(Exception):
    """A host probe or command failed in a way the tool cannot classify; it reports rather than guess."""


class ChangesNotAllowed(Exception):
    """A state-changing call reached a runner built for the dry run."""


class PartialWrite(OSError):
    """The plist was linked in place, then a later part of the publish (temp unlink, directory fsync, close) failed.

    ``strerror`` names what changed; ``left_temp`` is the full path of a temp file left behind, or None.
    """

    left_temp: str | None = None


class PartialRemove(OSError):
    """The plist was unlinked, then the directory fsync or close failed: the removal happened."""


class TempFileExists(OSError):
    """The publish temp file name was taken (a crashed earlier run); the target was not touched."""


@dataclasses.dataclass(frozen=True)
class Facts:
    """The part of an ``lstat`` / ``fstat`` result the checks read."""

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
    agent_label: str | None = None

    @property
    def plist_path(self) -> str:
        return f"{LAUNCH_DAEMONS_DIR}/{self.label}.plist"

    @property
    def pg_ctl(self) -> str:
        return str(PurePosixPath(self.postgres_bin).parent / PG_CTL_NAME)

    @property
    def service(self) -> str:
        return f"system/{self.label}"

    @property
    def pidfile(self) -> str:
        return f"{self.data_dir}/{PIDFILE_NAME}"

    @property
    def log_path(self) -> str:
        return f"{self.data_dir}/{self.label}{LOG_SUFFIX}"


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


def _errno_name(exc: OSError) -> str:
    return errno.errorcode.get(exc.errno or 0, type(exc).__name__)


def _close_quietly(fd: int) -> None:
    """Close ``fd`` while another error is already on its way out: a close error must not replace that error."""
    try:
        os.close(fd)
    except OSError:
        pass


def _close_reporting(fd: int, path: str) -> None:
    """Close ``fd`` on the success path: a close error there is the error."""
    try:
        os.close(fd)
    except OSError as exc:
        raise HostError(f"close {path}: {_errno_name(exc)}") from exc


def _unlink_retrying(name: str, dir_fd: int) -> None:
    """Unlink ``name`` in ``dir_fd``, trying UNLINK_TRIES times; a name already gone counts as removed."""
    last: OSError | None = None
    for _ in range(UNLINK_TRIES):
        try:
            os.unlink(name, dir_fd=dir_fd)
        except FileNotFoundError:
            return
        except OSError as exc:
            last = exc
        else:
            return
    assert last is not None
    raise last


def _drop_temp(dir_fd: int, temp_name: str, temp_path: str, error: BaseException) -> None:
    """Remove the temp file while ``error`` propagates.  When both unlinks fail the error keeps its kind and
    carries ``left_temp``, the full path of the file left behind, so the report can name it."""
    try:
        _unlink_retrying(temp_name, dir_fd)
    except OSError:
        error.left_temp = temp_path  # type: ignore[attr-defined]


def _kind_of(mode: int) -> Kind:
    if stat.S_ISLNK(mode):
        return Kind.SYMLINK
    if stat.S_ISREG(mode):
        return Kind.FILE
    if stat.S_ISDIR(mode):
        return Kind.DIR
    return Kind.OTHER


class HostRunner:
    """The real host.  Every probe and every change of the tool goes through one of these methods.

    The clock, sleep, socket connect, ``fchown``, ``fsync`` and child-process spawn are injectable so the tests run
    the real bodies (deadlines, write path, parsing) against a fake root without root, a port or launchd.
    """

    def __init__(
        self,
        allow_changes: bool,
        *,
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
        connect: Callable[..., socket.socket] = socket.create_connection,
        fchown: Callable[[int, int, int], None] = os.fchown,
        fsync: Callable[[int], None] = os.fsync,
        spawn: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
    ) -> None:
        self._allow_changes = allow_changes
        self._clock = clock
        self._sleep = sleep
        self._connect = connect
        self._fchown = fchown
        self._fsync = fsync
        self._spawn = spawn

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
            raise HostError(f"lstat {path}: {_errno_name(exc)}") from exc
        return Facts(_kind_of(st.st_mode), st.st_uid, stat.S_IMODE(st.st_mode))

    @staticmethod
    def _read_fd(fd: int, path: str, limit: int) -> bytes:
        try:
            mode = os.fstat(fd).st_mode
        except OSError as exc:
            raise HostError(f"fstat {path}: {_errno_name(exc)}") from exc
        if not stat.S_ISREG(mode):
            raise HostError(f"open {path}: not a regular file")
        chunks: list[bytes] = []
        remaining = limit + 1
        try:
            while remaining > 0:
                chunk = os.read(fd, remaining)
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
        except OSError as exc:
            raise HostError(f"read {path}: {_errno_name(exc)}") from exc
        return b"".join(chunks)

    def read_file(self, path: str, limit: int) -> bytes | None:
        """Read at most ``limit + 1`` bytes of a regular file without following a symlink; None when absent."""
        try:
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        except FileNotFoundError:
            return None
        except OSError as exc:
            raise HostError(f"open {path}: {_errno_name(exc)}") from exc
        try:
            data = self._read_fd(fd, path, limit)
        except BaseException:
            _close_quietly(fd)
            raise
        _close_reporting(fd, path)
        return data

    def read_data_dir(self, path: str, name: str, limit: int) -> tuple[Facts, bytes | None]:
        """Open the directory without following a symlink, ``fstat`` it, then read ``name`` through that open fd.

        Returns the directory's facts (from the opened object, not a second path lookup) and at most ``limit + 1``
        bytes of the regular file ``name`` in it, or None when that file is absent.  When ``path`` itself is not an
        openable directory the facts come from ``lstat`` and the bytes are None.
        """
        try:
            dir_fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        except FileNotFoundError:
            return Facts(Kind.ABSENT), None
        except OSError as exc:
            if exc.errno in (errno.ENOTDIR, errno.ELOOP):
                return self.lstat(path), None
            raise HostError(f"open {path}: {_errno_name(exc)}") from exc
        try:
            try:
                st = os.fstat(dir_fd)
            except OSError as exc:
                raise HostError(f"fstat {path}: {_errno_name(exc)}") from exc
            facts = Facts(_kind_of(st.st_mode), st.st_uid, stat.S_IMODE(st.st_mode))
            file_path = f"{path}/{name}"
            try:
                fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=dir_fd)
            except FileNotFoundError:
                data = None
            except OSError as exc:
                raise HostError(f"open {file_path}: {_errno_name(exc)}") from exc
            else:
                try:
                    data = self._read_fd(fd, file_path, limit)
                except BaseException:
                    _close_quietly(fd)
                    raise
                _close_reporting(fd, file_path)
        except BaseException:
            _close_quietly(dir_fd)
            raise
        _close_reporting(dir_fd, path)
        return facts, data

    def _run(self, argv: list[str]) -> subprocess.CompletedProcess[str]:
        try:
            return self._spawn(
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
        raise HostError(f"{LAUNCHCTL} print {service} exited {done.returncode}")

    def launchd_pid(self, service: str) -> int | None:
        """The pid launchd reports for a loaded service (one top-level ``pid = N`` line), or None when it has none."""
        done = self._run([LAUNCHCTL, "print", service])
        if done.returncode == LAUNCHCTL_NOT_FOUND_RC:
            return None
        if done.returncode != 0:
            raise HostError(f"{LAUNCHCTL} print {service} exited {done.returncode}")
        found = LAUNCHD_PID_RE.findall(done.stdout)
        if not found:
            return None
        if len(found) > 1:
            raise HostError(f"{LAUNCHCTL} print {service} reports {len(found)} pid lines")
        pid = int(found[0])
        if not 0 < pid <= MAX_PID:
            raise HostError(f"{LAUNCHCTL} print {service} reports pid {pid}")
        return pid

    def agent_disabled(self, uid: int, label: str) -> bool:
        """True only when ``launchctl print-disabled user/<uid>`` lists ``label`` once, as disabled."""
        argv = [LAUNCHCTL, "print-disabled", f"user/{uid}"]
        done = self._run(argv)
        if done.returncode != 0:
            raise HostError(f"{shlex.join(argv)} exited {done.returncode}")
        states: list[str] = []
        for line in done.stdout.splitlines():
            match = DISABLED_LINE_RE.fullmatch(line.strip())
            if match is not None and match.group(1) == label:
                states.append(match.group(2))
        if len(states) > 1:
            raise HostError(f"{shlex.join(argv)} lists {label} {len(states)} times")
        return bool(states) and states[0] in DISABLED_WORDS

    def pid_alive(self, pid: int) -> bool:
        done = self._run([PS, "-p", str(pid), "-o", "pid="])
        answer = done.stdout.strip()
        if done.returncode == 0 and answer == str(pid):
            return True
        if done.returncode == 1 and not answer:
            return False
        raise HostError(f"{PS} -p {pid} exited {done.returncode}")

    def wait_pid_exit(self, pid: int, seconds: int) -> bool:
        deadline = self._clock() + seconds
        while self.pid_alive(pid):
            if self._clock() >= deadline:
                return False
            self._sleep(HANDOVER_INTERVAL_SECONDS)
        return True

    def publish_file(self, path: str, data: bytes) -> None:
        """Write ``data`` to a new file at ``path``: same-directory temp file, fsync, mode, owner, link, dir fsync.

        Raises FileExistsError when the target exists and any other OSError when a step before the link failed:
        the plist was not written, the error keeps its kind, and the temp file is removed (two tries).  Once the
        plist is linked the only exception is PartialWrite, whose text names the plist and every later step that
        failed (temp unlink, directory fsync, directory close).  A temp file survives only when both of its unlinks
        fail; the error then carries its full path as ``left_temp`` and the text names it.
        """
        self._require_changes()
        target = PurePosixPath(path)
        dir_fd = os.open(str(target.parent), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        temp_name = f".{target.name}.tmp-{os.getpid()}"
        temp_path = f"{target.parent}/{temp_name}"
        try:
            self._write_temp(dir_fd, temp_name, temp_path, data)
            try:
                os.link(temp_name, target.name, src_dir_fd=dir_fd, dst_dir_fd=dir_fd, follow_symlinks=False)
            except BaseException as exc:
                _drop_temp(dir_fd, temp_name, temp_path, exc)
                raise
        except BaseException:
            _close_quietly(dir_fd)
            raise
        # The plist is linked in place: from here every failure is a PartialWrite naming what changed.
        problems: list[str] = []
        first: OSError | None = None
        left_temp: str | None = None
        try:
            _unlink_retrying(temp_name, dir_fd)
        except OSError as exc:
            first, left_temp = exc, temp_path
            problems.append(f"removing temp file {temp_path} failed ({_errno_name(exc)})")
        try:
            self._fsync(dir_fd)
        except OSError as exc:
            first = first or exc
            problems.append(f"the directory fsync failed ({_errno_name(exc)})")
        try:
            os.close(dir_fd)
        except OSError as exc:
            first = first or exc
            problems.append(f"closing the directory failed ({_errno_name(exc)})")
        if first is not None:
            text = f"{path} linked in place, then " + ", then ".join(problems)
            if left_temp is not None:
                text += TEMP_LEFT_SUFFIX.format(temp=left_temp)
            partial = PartialWrite(first.errno, text)
            partial.left_temp = left_temp
            raise partial from first

    def _write_temp(self, dir_fd: int, temp_name: str, temp_path: str, data: bytes) -> None:
        """Create the temp file exclusively and write, chown, chmod, fsync and close it; on any failure remove it."""
        try:
            fd = os.open(temp_name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, TEMP_MODE, dir_fd=dir_fd)
        except FileExistsError as exc:
            raise TempFileExists(errno.EEXIST, f"temp file {temp_name} exists") from exc
        try:
            try:
                view = memoryview(data)
                while view:
                    view = view[os.write(fd, view) :]
                self._fchown(fd, ROOT_UID, WHEEL_GID)
                os.fchmod(fd, PLIST_MODE)
                self._fsync(fd)
            except BaseException:
                _close_quietly(fd)
                raise
            os.close(fd)
        except BaseException as exc:
            _drop_temp(dir_fd, temp_name, temp_path, exc)
            raise

    def remove_file(self, path: str) -> None:
        """Unlink ``path`` through its opened parent.  An error before the unlink is the plain OSError (nothing
        changed); an fsync or close failure after it is PartialRemove (the plist is gone)."""
        self._require_changes()
        target = PurePosixPath(path)
        dir_fd = os.open(str(target.parent), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.unlink(target.name, dir_fd=dir_fd)
        except BaseException:
            _close_quietly(dir_fd)
            raise
        try:
            self._fsync(dir_fd)
        except OSError as exc:
            _close_quietly(dir_fd)
            raise PartialRemove(exc.errno, f"{path} unlinked, then the directory fsync failed ({_errno_name(exc)})") from exc
        try:
            os.close(dir_fd)
        except OSError as exc:
            raise PartialRemove(exc.errno, f"{path} unlinked, then closing the directory failed ({_errno_name(exc)})") from exc

    def launchctl(self, args: tuple[str, ...]) -> int:
        self._require_changes()
        return self._run([LAUNCHCTL, *args]).returncode

    def port_in_use(self, port: int) -> bool:
        """True when something accepts a connection on the probe address; False only on a refused connection."""
        try:
            with self._connect((PROBE_HOST, port), timeout=PROBE_CONNECT_TIMEOUT_SECONDS):
                return True
        except ConnectionRefusedError:
            return False
        except OSError as exc:
            raise HostError(f"connect {PROBE_HOST}:{port}: {_errno_name(exc)}") from exc

    def probe_port(self, port: int, seconds: int) -> bool:
        deadline = self._clock() + seconds
        while True:
            try:
                with self._connect((PROBE_HOST, port), timeout=PROBE_CONNECT_TIMEOUT_SECONDS):
                    return True
            except OSError:
                if self._clock() >= deadline:
                    return False
                self._sleep(PROBE_INTERVAL_SECONDS)


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
    parser.add_argument("--agent-label", help="with --handover: label of the interim login agent, which must be disabled")
    return parser


def _text_arg(flag: str, value: str | None) -> str:
    if value is None:
        raise Refusal(EXIT_USAGE, REFUSE_UNSET.format(flag=flag))
    if value == "":
        raise Refusal(EXIT_USAGE, REFUSE_EMPTY.format(flag=flag))
    if len(value) > MAX_PATH_CHARS:
        raise Refusal(EXIT_USAGE, REFUSE_TOO_LONG.format(flag=flag, limit=MAX_PATH_CHARS))
    if any(unicodedata.category(ch) == "Cc" for ch in value):
        raise Refusal(EXIT_USAGE, REFUSE_CONTROL.format(flag=flag))
    try:
        value.encode("utf-8")
    except UnicodeEncodeError:
        raise Refusal(EXIT_USAGE, REFUSE_NOT_UTF8.format(flag=flag)) from None
    for ch in value:
        code = ord(ch)
        if code in NONCHARACTER_BLOCK or code & NONCHARACTER_LOW_BITS == NONCHARACTER_LOW_BITS:
            raise Refusal(EXIT_USAGE, REFUSE_NONCHARACTER.format(flag=flag, code=code))
        category = unicodedata.category(ch)
        if category in REFUSED_CATEGORIES:
            raise Refusal(EXIT_USAGE, REFUSE_CODEPOINT.format(flag=flag, code=code, category=category))
    return value


def _path_arg(flag: str, value: str | None) -> str:
    path = _text_arg(flag, value)
    if not path.startswith("/"):
        raise Refusal(EXIT_USAGE, REFUSE_RELATIVE.format(flag=flag))
    if os.path.normpath(path) != path or path.startswith("//"):
        raise Refusal(EXIT_USAGE, REFUSE_NOT_NORMAL.format(flag=flag))
    return path


def _check_parents(runner: HostRunner, flag: str, path: str, owners: dict[int, str]) -> None:
    """Every parent folder of ``path`` (up to ``/``) is a real directory owned by one of ``owners``, not g/o-writable."""
    owner_words = " or ".join(owners.values())
    for parent in reversed(PurePosixPath(path).parents):
        facts = runner.lstat(str(parent))
        why = ""
        match facts.kind:
            case Kind.DIR:
                if facts.uid not in owners:
                    why = PARENT_OWNER.format(uid=facts.uid, owners=owner_words)
                elif facts.mode & WRITABLE_BY_GROUP_OR_OTHERS:
                    why = PARENT_WRITABLE
            case Kind.ABSENT:
                why = PARENT_MISSING
            case Kind.SYMLINK:
                why = PARENT_SYMLINK
            case Kind.FILE | Kind.OTHER:
                why = PARENT_NOT_DIR
            case _:
                raise AssertionError(facts.kind)
        if why:
            raise Refusal(EXIT_USAGE, REFUSE_PARENT.format(flag=flag, path=path, parent=parent, why=why))


def _owners(account: Account) -> dict[int, str]:
    return {ROOT_UID: ROOT_NAME, account.uid: account.name}


def _check_binary(runner: HostRunner, path: str, account: Account) -> None:
    flag = "--postgres-bin"
    _check_parents(runner, flag, path, _owners(account))
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
    if facts.uid not in _owners(account):
        raise Refusal(
            EXIT_USAGE,
            REFUSE_BIN_OWNER.format(flag=flag, path=path, uid=facts.uid, account=account.name, account_uid=account.uid),
        )


def _data_dir_refusal(path: str, account: Account, facts: Facts) -> Refusal | None:
    """The refusal for the data directory's facts (taken from the opened directory), or None when they pass."""
    flag = "--data-dir"
    match facts.kind:
        case Kind.ABSENT:
            return Refusal(EXIT_USAGE, REFUSE_MISSING.format(flag=flag, path=path))
        case Kind.SYMLINK:
            return Refusal(EXIT_USAGE, REFUSE_SYMLINK.format(flag=flag, path=path))
        case Kind.FILE | Kind.OTHER:
            return Refusal(EXIT_USAGE, REFUSE_NOT_DIR.format(flag=flag, path=path))
        case Kind.DIR:
            pass
        case _:
            raise AssertionError(facts.kind)
    if facts.uid != account.uid:
        return Refusal(
            EXIT_USAGE,
            REFUSE_DATA_OWNER.format(flag=flag, path=path, uid=facts.uid, account=account.name, account_uid=account.uid),
        )
    if facts.mode & WRITABLE_BY_GROUP_OR_OTHERS:
        return Refusal(EXIT_USAGE, REFUSE_DATA_WRITABLE.format(flag=flag, path=path))
    return None


def _check_data_dir(runner: HostRunner, path: str, account: Account) -> None:
    _check_parents(runner, "--data-dir", path, _owners(account))
    facts, _ = runner.read_data_dir(path, PIDFILE_NAME, MAX_PIDFILE_BYTES)
    refusal = _data_dir_refusal(path, account, facts)
    if refusal is not None:
        raise refusal


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


def _agent_label(args: argparse.Namespace) -> str | None:
    if args.agent_label is None:
        if args.handover:
            raise Refusal(EXIT_USAGE, REFUSE_AGENT_UNSET)
        return None
    if not args.handover:
        raise Refusal(EXIT_USAGE, REFUSE_AGENT_MODE)
    label = _text_arg("--agent-label", args.agent_label)
    if not LABEL_RE.fullmatch(label):
        raise Refusal(EXIT_USAGE, REFUSE_AGENT_LABEL_INVALID.format(label=label))
    return label


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
    agent_label = _agent_label(args)
    account = _resolve_account(runner, args.account)
    _check_binary(runner, postgres_bin, account)
    _check_data_dir(runner, data_dir, account)
    return Config(mode, args.handover, postgres_bin, data_dir, account, label, int(port_text), agent_label)


def plist_dict(config: Config) -> dict[str, object]:
    return {
        "Label": config.label,
        "ProgramArguments": [config.postgres_bin, "-D", config.data_dir, "-p", str(config.port)],
        "UserName": config.account.name,
        "GroupName": config.account.group,
        "WorkingDirectory": config.data_dir,
        "StandardOutPath": config.log_path,
        "StandardErrorPath": config.log_path,
        "RunAtLoad": True,
        "KeepAlive": True,
        "ExitTimeOut": EXIT_TIMEOUT_SECONDS,
    }


def plist_bytes(config: Config) -> bytes:
    """The plist bytes; refused unless they read back as exactly ``plist_dict(config)``."""
    expected = plist_dict(config)
    try:
        data = plistlib.dumps(expected, fmt=plistlib.FMT_XML, sort_keys=True)
        round_trip = plistlib.loads(data)
    except (plistlib.InvalidFileException, ValueError, TypeError, OverflowError):
        raise Refusal(EXIT_USAGE, REFUSE_PLIST_ROUNDTRIP) from None
    if round_trip != expected:
        raise Refusal(EXIT_USAGE, REFUSE_PLIST_ROUNDTRIP)
    return data


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
    for parent in reversed(PurePosixPath(LAUNCH_DAEMONS_DIR).parents):
        facts = runner.lstat(str(parent))
        if facts.kind is not Kind.DIR or facts.uid != ROOT_UID or facts.mode & WRITABLE_BY_GROUP_OR_OTHERS:
            raise Refusal(
                EXIT_HOST_ERROR,
                REFUSE_PLIST_DIR.format(
                    path=LAUNCH_DAEMONS_DIR,
                    why=f"has parent folder {parent} that is not a root-owned directory closed to group and others",
                ),
            )
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


def _parse_pidfile(data: bytes | None) -> tuple[int, str]:
    """The postmaster pid on the first line of postmaster.pid, or (0, the reason there is none)."""
    if data is None:
        return 0, PIDFILE_ABSENT
    if len(data) > MAX_PIDFILE_BYTES:
        return 0, PIDFILE_TOO_BIG
    if not data:
        return 0, PIDFILE_EMPTY
    first = data.split(b"\n", 1)[0].decode("ascii", errors="replace")
    if not PID_RE.fullmatch(first) or not 0 < int(first) <= MAX_PID:
        return 0, PIDFILE_BAD_PID
    return int(first), ""


def _read_pidfile(runner: HostRunner, config: Config) -> tuple[int, str]:
    """Open the data directory, re-check it on the opened object, and parse postmaster.pid read through it."""
    facts, data = runner.read_data_dir(config.data_dir, PIDFILE_NAME, MAX_PIDFILE_BYTES)
    refusal = _data_dir_refusal(config.data_dir, config.account, facts)
    if refusal is not None:
        raise refusal
    return _parse_pidfile(data)


def _read_postmaster(runner: HostRunner, config: Config) -> tuple[Postmaster, int]:
    pid, why = _read_pidfile(runner, config)
    if why == PIDFILE_ABSENT:
        return Postmaster.NONE, 0
    if why:
        raise Refusal(EXIT_HOST_ERROR, REFUSE_PIDFILE.format(path=config.pidfile, why=why))
    return (Postmaster.ALIVE if runner.pid_alive(pid) else Postmaster.STALE), pid


def read_state(runner: HostRunner, config: Config, expected: bytes, euid: int) -> State:
    """Read every fact the decision needs; read-only calls only."""
    _check_plist_dir(runner)
    target, summary = _read_target(runner, config, expected)
    loaded = runner.service_loaded(config.service)
    postmaster, pid = _read_postmaster(runner, config)
    return State(euid, target, summary, loaded, postmaster, pid)


def _step_words(steps: tuple[Step, ...]) -> str:
    return ", ".join(step.value for step in steps)


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
    tail = (Step.PORT_FREE, *publish, Step.BOOTSTRAP, Step.PROBE, Step.VERIFY)
    match state.postmaster:
        case Postmaster.ALIVE if not config.handover:
            return Plan(
                Verdict.REFUSE, (), EXIT_POSTMASTER_RUNNING, REFUSE_POSTMASTER.format(pid=state.pid, data_dir=config.data_dir)
            )
        case Postmaster.ALIVE:
            rest = (Step.AGENT_DISABLED, *tail)
            return Plan(
                Verdict.HANDOVER,
                (Step.WAIT_EXIT, *rest),
                EXIT_OK,
                f"wait up to {HANDOVER_DEADLINE_SECONDS} s for pid {state.pid} to exit, then {_step_words(rest)}",
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


# The one place each command line is built: the real run executes these argument lists and every printed line
# renders them with shlex.join.
def bootstrap_args(config: Config) -> tuple[str, ...]:
    return ("bootstrap", "system", config.plist_path)


def bootout_args(config: Config) -> tuple[str, ...]:
    return ("bootout", config.service)


def agent_target(config: Config) -> str:
    return f"gui/{config.account.uid}/{config.agent_label or AGENT_LABEL_PLACEHOLDER}"


def agent_disable_argv(config: Config) -> list[str]:
    return [LAUNCHCTL, "disable", agent_target(config)]


def agent_bootout_argv(config: Config) -> list[str]:
    return [LAUNCHCTL, "bootout", agent_target(config)]


def agent_print_argv(config: Config) -> list[str]:
    return [LAUNCHCTL, "print-disabled", f"user/{config.account.uid}"]


def pg_ctl_stop_argv(config: Config) -> list[str]:
    return [config.pg_ctl, "-D", config.data_dir, "stop", "-m", "fast"]


def remove_argv(config: Config) -> list[str]:
    return ["rm", config.plist_path]


def step_line(config: Config, step: Step) -> str:
    """How one plan step reads in the dry run."""
    match step:
        case Step.WAIT_EXIT:
            return (
                f"wait up to {HANDOVER_DEADLINE_SECONDS} s for the running postmaster to exit; "
                "refuse if a new postmaster holds the data directory"
            )
        case Step.AGENT_DISABLED:
            return f"refuse unless {shlex.join(agent_print_argv(config))} shows {agent_target(config)} disabled"
        case Step.PORT_FREE:
            return f"refuse if anything already answers on {PROBE_HOST}:{config.port}"
        case Step.WRITE:
            return f"write {shlex.quote(config.plist_path)} atomically, mode 0644, owner root:wheel, never over an existing file"
        case Step.BOOTSTRAP:
            return shlex.join([LAUNCHCTL, *bootstrap_args(config)])
        case Step.PROBE:
            return f"probe {PROBE_HOST}:{config.port}, deadline {PROBE_DEADLINE_SECONDS} s"
        case Step.VERIFY:
            return (
                f"verify that {shlex.quote(config.pidfile)} has {PIDFILE_LINES} lines naming the pid launchd reports "
                f"for {config.service}, data directory {shlex.quote(config.data_dir)}, port {config.port} and status "
                f"{PIDFILE_READY.decode('ascii')}, and that launchd reports the same pid after the read; "
                "only then print installed"
            )
        case Step.BOOTOUT:
            return shlex.join([LAUNCHCTL, *bootout_args(config)])
        case Step.REMOVE:
            return shlex.join(remove_argv(config))
        case _:
            raise AssertionError(step)


def plan_lines(config: Config, steps: tuple[Step, ...]) -> list[str]:
    return [f"  {number}. {step_line(config, step)}" for number, step in enumerate(steps, 1)]


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


def _handover_flags(config: Config) -> list[str]:
    return ["--handover", "--agent-label", config.agent_label or AGENT_LABEL_PLACEHOLDER]


def dry_run_lines(config: Config, state: State, data: bytes, command: str) -> list[str]:
    """The dry run: every step list is rendered from the plan ``decide_install`` / ``decide_remove`` return."""
    account = config.account
    fresh = dataclasses.replace(state, target=Target.ABSENT, loaded=False, postmaster=Postmaster.NONE, pid=0)
    install_steps = decide_install(config, fresh).steps
    handover_steps = decide_install(
        dataclasses.replace(config, handover=True), dataclasses.replace(fresh, postmaster=Postmaster.ALIVE)
    ).steps
    remove_steps = decide_remove(config, dataclasses.replace(fresh, target=Target.IDENTICAL, loaded=True)).steps
    handover_command = shlex.join([*shlex.split(command), Mode.INSTALL.value, *_handover_flags(config)])
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
        f"install, in order (as root: sudo {command} {Mode.INSTALL.value}):",
        *plan_lines(config, install_steps),
        "hand-over when a postmaster holds the data directory, first by hand:",
        f"  a. disable the interim login agent persistently: {shlex.join(agent_disable_argv(config))}",
        f"  b. stop it: {shlex.join(agent_bootout_argv(config))}",
        f"  c. if the postmaster still runs, stop it cleanly as {account.name}: {shlex.join(pg_ctl_stop_argv(config))}",
        f"then as root: sudo {handover_command}",
        *plan_lines(config, handover_steps),
        f"removal, in order (as root: sudo {command} {Mode.REMOVE.value}):",
        *plan_lines(config, remove_steps),
    ]
    install = decide_install(config, state)
    remove = decide_remove(config, state)
    lines.append(f"install verdict: {install.verdict.value}: {install.reason}")
    lines.append(f"remove verdict: {remove.verdict.value}: {remove.reason}")
    return lines


def _after_failure(
    runner: HostRunner,
    config: Config,
    outcome: Outcome,
    code: int,
    what: str,
    changed: list[str],
    unconfirmed: bool,
    command: str,
) -> Outcome:
    """Report a failure after the run began changing the host: what changed, the state re-read now, the true undo."""
    try:
        plist_present: bool | None = runner.lstat(config.plist_path).kind is not Kind.ABSENT
        plist_state = "present" if plist_present else "absent"
    except HostError as exc:
        plist_present, plist_state = None, f"unknown ({exc})"
    try:
        service_loaded: bool | None = runner.service_loaded(config.service)
        service_state = "loaded" if service_loaded else "not loaded"
    except HostError as exc:
        service_loaded, service_state = None, f"unknown ({exc})"
    state_line = f"state: plist {config.plist_path} {plist_state}; service {config.service} {service_state}"
    failed = f"{TOOL_NAME}: failed: {what}"
    changed_words = "; ".join(changed) if changed else CHANGED_UNCONFIRMED if unconfirmed else CHANGED_NOTHING
    match config.mode:
        case Mode.INSTALL:
            if not changed and not unconfirmed:
                outcome.err.extend([failed + NOTHING_CHANGED_SUFFIX, state_line])
            else:
                outcome.err.extend([failed, f"changed: {changed_words}", state_line])
                left_temps = [word[len(TEMP_LEFT_WORD) :] for word in changed if word.startswith(TEMP_LEFT_WORD)]
                if any(word.startswith("wrote ") for word in changed):
                    outcome.err.append(f"undo: sudo {command} {Mode.REMOVE.value}")
                elif service_loaded is not False and len(left_temps) < len(changed):
                    outcome.err.append(f"undo: sudo {shlex.join([LAUNCHCTL, *bootout_args(config)])}")
                outcome.err.extend(f"undo: sudo {shlex.join(['rm', temp])}" for temp in left_temps)
        case Mode.REMOVE:
            outcome.err.extend([failed, f"changed: {changed_words}", state_line])
            if any(word.startswith("booted out ") for word in changed) and plist_present:
                outcome.err.append(f"undo: sudo {shlex.join([LAUNCHCTL, *bootstrap_args(config)])}")
            outcome.err.append(f"to finish the removal: sudo {command} {Mode.REMOVE.value}")
        case Mode.DRY_RUN:
            raise AssertionError(config.mode)
        case _:
            raise AssertionError(config.mode)
    outcome.code = code
    return outcome


class _StepFailed(Exception):
    """A step after the plan began failed: exit code and exact reason (raised and caught inside ``_execute``)."""

    def __init__(self, code: int, what: str) -> None:
        super().__init__(what)
        self.code = code
        self.what = what


class _StepRefused(Exception):
    """A step refused before it changed anything (the race, the port, the agent): exit code and message."""

    def __init__(self, code: int, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


def _verify(runner: HostRunner, config: Config) -> str:
    """Prove the daemon launchd started owns the data directory and the port and is ready; return the installed
    line or raise _StepFailed.

    Installed only when all hold at once: launchd reports a pid; the data directory passes its check on the opened
    object; postmaster.pid has exactly PIDFILE_LINES lines; line 1 is that pid; line 2 is the configured data
    directory; line 4 is the configured port; line 8, blanks stripped, is exactly ``ready``; and launchd reports
    the same pid when asked again after the read.  The probe step ran before this one.  Every other state is its
    own reason with EXIT_PROBE_FAILED.
    """
    path = config.pidfile
    launchd_pid = runner.launchd_pid(config.service)
    if launchd_pid is None:
        raise _StepFailed(EXIT_PROBE_FAILED, FAIL_NO_LAUNCHD_PID.format(service=config.service))
    try:
        facts, data = runner.read_data_dir(config.data_dir, PIDFILE_NAME, MAX_PIDFILE_BYTES)
    except HostError as exc:
        raise _StepFailed(EXIT_PROBE_FAILED, FAIL_PIDFILE_UNREADABLE.format(path=path, why=exc)) from exc
    refusal = _data_dir_refusal(config.data_dir, config.account, facts)
    if refusal is not None:
        raise _StepFailed(EXIT_PROBE_FAILED, FAIL_DATA_DIR.format(why=refusal.message))
    pid, why = _parse_pidfile(data)
    if data is None or (why and why != PIDFILE_BAD_PID):
        raise _StepFailed(EXIT_PROBE_FAILED, FAIL_NO_POSTMASTER_PID.format(path=path, why=why))
    lines = data.split(b"\n")
    if lines[-1] == b"":
        lines.pop()
    if len(lines) < PIDFILE_LINES:
        raise _StepFailed(EXIT_PROBE_FAILED, FAIL_PIDFILE_SHORT.format(path=path, lines=len(lines), want=PIDFILE_LINES))
    if len(lines) > PIDFILE_LINES:
        raise _StepFailed(EXIT_PROBE_FAILED, FAIL_PIDFILE_LONG.format(path=path, want=PIDFILE_LINES))
    if why:
        raise _StepFailed(EXIT_PROBE_FAILED, FAIL_NO_POSTMASTER_PID.format(path=path, why=why))
    if pid != launchd_pid:
        raise _StepFailed(
            EXIT_PROBE_FAILED,
            FAIL_PID_MISMATCH.format(launchd_pid=launchd_pid, service=config.service, pid=pid, path=path),
        )
    data_line = lines[PIDFILE_DATA_DIR_LINE - 1]
    if data_line != os.fsencode(config.data_dir):
        raise _StepFailed(
            EXIT_PROBE_FAILED, FAIL_PIDFILE_DATA_DIR.format(path=path, shown=_shown(data_line), data_dir=config.data_dir)
        )
    port_line = lines[PIDFILE_PORT_LINE - 1]
    if not port_line:
        raise _StepFailed(EXIT_PROBE_FAILED, FAIL_PIDFILE_PORT_EMPTY.format(path=path))
    if not PORT_LINE_RE.fullmatch(port_line):
        raise _StepFailed(EXIT_PROBE_FAILED, FAIL_PIDFILE_PORT_NAN.format(path=path, shown=_shown(port_line)))
    if port_line != str(config.port).encode("ascii"):
        raise _StepFailed(EXIT_PROBE_FAILED, FAIL_PIDFILE_PORT.format(path=path, shown=_shown(port_line), port=config.port))
    status = lines[PIDFILE_STATUS_LINE - 1].strip(PIDFILE_STATUS_PAD)
    if not status:
        raise _StepFailed(EXIT_PROBE_FAILED, FAIL_PIDFILE_STATUS_EMPTY.format(path=path))
    if status != PIDFILE_READY:
        raise _StepFailed(EXIT_PROBE_FAILED, FAIL_PIDFILE_STATUS.format(path=path, shown=_shown(status)))
    again = runner.launchd_pid(config.service)
    if again is None:
        raise _StepFailed(EXIT_PROBE_FAILED, FAIL_REREAD_GONE.format(service=config.service, path=path))
    if again != launchd_pid:
        raise _StepFailed(
            EXIT_PROBE_FAILED, FAIL_REREAD_CHANGED.format(service=config.service, before=launchd_pid, after=again, path=path)
        )
    return f"launchd pid {launchd_pid} of {config.service} owns {config.data_dir} and {PROBE_HOST}:{config.port}; installed"


def _shown(raw: bytes) -> str:
    """A pid-file line as a report shows it: at most SHOWN_MAX_CHARS characters, then quoted with every
    non-ASCII and control character escaped, so a hostile line can neither flood nor drive the terminal."""
    text = raw.decode("utf-8", errors="backslashreplace")
    if len(text) > SHOWN_MAX_CHARS:
        text = text[:SHOWN_MAX_CHARS] + SHOWN_CUT
    return ascii(text)


def _run_step(
    runner: HostRunner, config: Config, step: Step, state: State, data: bytes, outcome: Outcome, changed: list[str]
) -> None:
    """Run one plan step; append its success line and what it changed, or raise _StepRefused / _StepFailed."""
    match step:
        case Step.WAIT_EXIT:
            if not runner.wait_pid_exit(state.pid, HANDOVER_DEADLINE_SECONDS):
                raise _StepRefused(
                    EXIT_HANDOVER_TIMEOUT, REFUSE_HANDOVER_TIMEOUT.format(pid=state.pid, seconds=HANDOVER_DEADLINE_SECONDS)
                )
            postmaster, pid = _read_postmaster(runner, config)
            if postmaster is Postmaster.ALIVE:
                raise _StepRefused(EXIT_POSTMASTER_RUNNING, REFUSE_NEW_POSTMASTER.format(pid=pid, data_dir=config.data_dir))
            outcome.out.append(f"postmaster pid {state.pid} exited")
        case Step.AGENT_DISABLED:
            label = config.agent_label
            if label is None or not runner.agent_disabled(config.account.uid, label):
                raise _StepRefused(
                    EXIT_AGENT_ENABLED,
                    REFUSE_AGENT_ENABLED.format(
                        label=label, uid=config.account.uid, command=shlex.join(agent_disable_argv(config))
                    ),
                )
            outcome.out.append(f"login agent {agent_target(config)} is disabled")
        case Step.PORT_FREE:
            if runner.port_in_use(config.port):
                raise _StepRefused(EXIT_PORT_IN_USE, REFUSE_PORT_IN_USE.format(host=PROBE_HOST, port=config.port))
            outcome.out.append(f"{PROBE_HOST}:{config.port} is free")
        case Step.WRITE:
            try:
                runner.publish_file(config.plist_path, data)
            except OSError as exc:
                left_temp: str | None = getattr(exc, "left_temp", None)
                suffix = "" if left_temp is None else TEMP_LEFT_SUFFIX.format(temp=left_temp)
                if isinstance(exc, PartialWrite):
                    changed.append(f"wrote {config.plist_path}")
                if left_temp is not None:
                    changed.append(TEMP_LEFT_WORD + left_temp)
                if isinstance(exc, PartialWrite):
                    what = FAIL_WRITE_LINKED.format(path=config.plist_path, name=_errno_name(exc))
                    raise _StepFailed(EXIT_COMMAND_FAILED, what + suffix) from exc
                if isinstance(exc, FileExistsError):
                    if left_temp is None:
                        raise _StepRefused(EXIT_CONFLICT, REFUSE_RACE.format(path=config.plist_path)) from None
                    raise _StepFailed(EXIT_CONFLICT, FAIL_RACE_TEMP_LEFT.format(path=config.plist_path, temp=left_temp))
                what = FAIL_WRITE.format(path=config.plist_path, name=_errno_name(exc))
                raise _StepFailed(EXIT_COMMAND_FAILED, what + suffix) from exc
            changed.append(f"wrote {config.plist_path}")
            outcome.out.append(f"wrote {config.plist_path} (mode 0644, owner root:wheel)")
        case Step.BOOTSTRAP:
            args = bootstrap_args(config)
            rc = runner.launchctl(args)
            if rc != 0:
                raise _StepFailed(EXIT_COMMAND_FAILED, FAIL_RC.format(command=shlex.join([LAUNCHCTL, *args]), rc=rc))
            changed.append(f"bootstrapped {config.service}")
            outcome.out.append(f"bootstrapped {config.service}")
        case Step.PROBE:
            if not runner.probe_port(config.port, PROBE_DEADLINE_SECONDS):
                raise _StepFailed(
                    EXIT_PROBE_FAILED, FAIL_PROBE.format(host=PROBE_HOST, port=config.port, seconds=PROBE_DEADLINE_SECONDS)
                )
            outcome.out.append(f"{PROBE_HOST}:{config.port} answers")
        case Step.VERIFY:
            outcome.out.append(_verify(runner, config))
        case Step.BOOTOUT:
            args = bootout_args(config)
            rc = runner.launchctl(args)
            if rc != 0:
                raise _StepFailed(EXIT_COMMAND_FAILED, FAIL_RC.format(command=shlex.join([LAUNCHCTL, *args]), rc=rc))
            changed.append(f"booted out {config.service}")
            outcome.out.append(f"booted out {config.service}")
        case Step.REMOVE:
            try:
                runner.remove_file(config.plist_path)
            except PartialRemove as exc:
                changed.append(f"removed {config.plist_path}")
                what = FAIL_REMOVE_UNLINKED.format(path=config.plist_path, name=_errno_name(exc))
                raise _StepFailed(EXIT_COMMAND_FAILED, what) from exc
            except OSError as exc:
                raise _StepFailed(EXIT_COMMAND_FAILED, FAIL_REMOVE.format(path=config.plist_path, name=_errno_name(exc)))
            changed.append(f"removed {config.plist_path}")
            outcome.out.append(f"removed {config.plist_path}")
        case _:
            raise AssertionError(step)


def _execute(runner: HostRunner, config: Config, plan: Plan, state: State, data: bytes, command: str, outcome: Outcome) -> Outcome:
    """Run the plan's steps in order.  Before the first change a failure is a refusal; after it, a failure report."""
    changed: list[str] = []
    for step in plan.steps:
        try:
            _run_step(runner, config, step, state, data, outcome, changed)
        except _StepRefused as refused:
            if changed:
                return _after_failure(runner, config, outcome, refused.code, refused.message, changed, False, command)
            return outcome.refuse(refused.code, refused.message)
        except Refusal as refusal:
            if changed:
                return _after_failure(runner, config, outcome, refusal.code, refusal.message, changed, False, command)
            return outcome.refuse(refusal.code, refusal.message)
        except _StepFailed as failure:
            return _after_failure(runner, config, outcome, failure.code, failure.what, changed, False, command)
        except HostError as exc:
            unconfirmed = step in CHANGING_STEPS
            if not changed and not unconfirmed:
                return outcome.refuse(EXIT_HOST_ERROR, REFUSE_HOST.format(why=exc))
            return _after_failure(runner, config, outcome, EXIT_COMMAND_FAILED, str(exc), changed, unconfirmed, command)
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
            flags = [config.mode.value, *(_handover_flags(config) if config.handover else [])]
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
        return _execute(runner, config, plan, state, data, command, outcome)
    except Refusal as refusal:
        return outcome.refuse(refusal.code, refusal.message)
    except HostError as exc:
        return outcome.refuse(EXIT_HOST_ERROR, REFUSE_HOST.format(why=exc))


def invocation_for(executable: str, script: str) -> list[str]:
    """How the printed root commands start the tool: isolated mode (-I) and the script's absolute path."""
    return [executable, "-I", str(Path(script).resolve())]


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    args = build_parser().parse_args(argv)
    runner = HostRunner(allow_changes=bool(args.install or args.remove))
    outcome = run(argv, runner, invocation_for(sys.executable, __file__))
    for line in outcome.out:
        print(line)
    for line in outcome.err:
        print(line, file=sys.stderr)
    return outcome.code


if __name__ == "__main__":
    sys.exit(main())
