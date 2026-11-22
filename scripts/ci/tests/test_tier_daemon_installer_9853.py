# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""Tests for scripts/ci/tier_daemon_installer.py (#9853, tooling scope #8216).

Invariants under test:
1. The dry run (no --install, no --remove) is side-effect free: the only commands it runs are the read-only
   ``launchctl print`` and ``ps -p``; it prints the full plist, the account, the install commands in order, the
   hand-over order and the removal path.
2. The daemon never runs as root; every non-root and unknown account form refuses with its own exact message.
3. Every host value is an argument; each degenerate value (unset, empty, relative, not normal, control character,
   missing, symlink, wrong kind, wrong owner, wrong mode, over the cap) refuses with its exact message.
4. --install/--remove refuse without euid 0 (and print the command to run); --install refuses different bytes, is a
   no-op on identical bytes with the service loaded, and reports the state plus removal path on a failure after the
   write.  --remove is the inverse, refuses a plist it would not write, and is idempotent.
5. A live postmaster refuses --install unless --handover; the tool never signals a process.

Every host probe goes through one injected runner (``FakeRunner``), so the module runs on Linux hosted CI and on
macOS without root and never touches launchd.  The expected outcomes are hand-written literals.

Run: python3 -m unittest scripts/ci/tests/test_tier_daemon_installer_9853.py
(CI: the step "Shard partition and wiring unit tests (#6344)" of the job build-script-vetting runs
``python3 -m unittest discover -s scripts/ci/tests``, which discovers this module.)
"""

from __future__ import annotations

import contextlib
import errno
import hashlib
import importlib.util
import io
import os
import plistlib
import posixpath
import shutil
import subprocess
import sys
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
SCRATCH_BASE = ROOT / ".local-runs"
SCRIPT_UNDER_TEST = Path(
    os.environ.get("TIER_DAEMON_INSTALLER_SCRIPT_UNDER_TEST") or ROOT / "scripts" / "ci" / "tier_daemon_installer.py"
)
MODULE_NAME = "tier_daemon_installer_9853"

_SPEC = importlib.util.spec_from_file_location(MODULE_NAME, SCRIPT_UNDER_TEST)
assert _SPEC is not None and _SPEC.loader is not None
tdi = importlib.util.module_from_spec(_SPEC)
sys.modules[MODULE_NAME] = tdi
_SPEC.loader.exec_module(tdi)

INVOCATION = ["python3", "scripts/ci/tier_daemon_installer.py"]
BIN = "/opt/tier/bin/postgres"
DATA = "/opt/tier/pgdata"
ACCOUNT = "pgtier"
ACCOUNT_UID = 501
GROUP = "staff"
GROUP_GID = 20
LABEL = "com.example.pg-tier"
PORT = "5445"
LAUNCH_DIR = "/Library/LaunchDaemons"
PLIST = "/Library/LaunchDaemons/com.example.pg-tier.plist"
SERVICE = "system/com.example.pg-tier"
PIDFILE = "/opt/tier/pgdata/postmaster.pid"
PID = 4242
NEW_PID = 5151
NON_ROOT_EUID = 501
CMD = (
    "python3 scripts/ci/tier_daemon_installer.py --postgres-bin /opt/tier/bin/postgres --data-dir /opt/tier/pgdata"
    " --account pgtier --label com.example.pg-tier --port 5445"
)
OUT = "tier-daemon-installer: "
REFUSED = "tier-daemon-installer: refused: "
FAILED = "tier-daemon-installer: failed: "

PRINT = ("/bin/launchctl", "print", SERVICE)
PS = ("/bin/ps", "-p", "4242", "-o", "pid=")
PS_NEW = ("/bin/ps", "-p", "5151", "-o", "pid=")
PUBLISH = ("publish", PLIST)
BOOTSTRAP = ("/bin/launchctl", "bootstrap", "system", PLIST)
PROBE = ("probe", 5445, 60)
BOOTOUT = ("/bin/launchctl", "bootout", SERVICE)
REMOVE = ("remove", PLIST)
WAIT = ("wait", 4242, 300)
READ_ONLY_CALLS = {PRINT, PS, PS_NEW}

# The plist the tool must write for the placeholder arguments, written out by hand.
PLIST_LINES = [
    '<?xml version="1.0" encoding="UTF-8"?>',
    '<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">',
    '<plist version="1.0">',
    "<dict>",
    "\t<key>ExitTimeOut</key>",
    "\t<integer>60</integer>",
    "\t<key>GroupName</key>",
    "\t<string>staff</string>",
    "\t<key>KeepAlive</key>",
    "\t<true/>",
    "\t<key>Label</key>",
    "\t<string>com.example.pg-tier</string>",
    "\t<key>ProgramArguments</key>",
    "\t<array>",
    "\t\t<string>/opt/tier/bin/postgres</string>",
    "\t\t<string>-D</string>",
    "\t\t<string>/opt/tier/pgdata</string>",
    "\t\t<string>-p</string>",
    "\t\t<string>5445</string>",
    "\t</array>",
    "\t<key>RunAtLoad</key>",
    "\t<true/>",
    "\t<key>UserName</key>",
    "\t<string>pgtier</string>",
    "\t<key>WorkingDirectory</key>",
    "\t<string>/opt/tier/pgdata</string>",
    "</dict>",
    "</plist>",
]
PLIST_BYTES = ("\n".join(PLIST_LINES) + "\n").encode("utf-8")
EXPECTED_DICT = {
    "Label": "com.example.pg-tier",
    "ProgramArguments": ["/opt/tier/bin/postgres", "-D", "/opt/tier/pgdata", "-p", "5445"],
    "UserName": "pgtier",
    "GroupName": "staff",
    "WorkingDirectory": "/opt/tier/pgdata",
    "RunAtLoad": True,
    "KeepAlive": True,
    "ExitTimeOut": 60,
}
FOREIGN_BYTES = b"<plist>someone else's daemon</plist>\n"
PIDFILE_BYTES = b"4242\n/opt/tier/pgdata\n1763768852\n5445\n"


def _sha16(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()[:16]


DIFF_SUMMARY = (
    f"found {len(FOREIGN_BYTES)} bytes sha256 {_sha16(FOREIGN_BYTES)}, "
    f"expected {len(PLIST_BYTES)} bytes sha256 {_sha16(PLIST_BYTES)}, 28 lines differ"
)


class FakeRunner(tdi.HostRunner):
    """The injected host: scripted facts, every command recorded, nothing on the real host touched."""

    def __init__(self, allow_changes: bool, euid: int = 0) -> None:
        super().__init__(allow_changes)
        self.platform_name = "darwin"
        self.euid_value = euid
        self.accounts = {
            ACCOUNT: (ACCOUNT_UID, GROUP_GID),
            "root": (0, 0),
            "toor": (0, GROUP_GID),
            "pgwheel": (502, 0),
            "pgnogroup": (503, 999),
        }
        self.groups = {GROUP_GID: GROUP, 0: "wheel"}
        self.facts = {
            LAUNCH_DIR: tdi.Facts(tdi.Kind.DIR, 0, 0o755),
            BIN: tdi.Facts(tdi.Kind.FILE, 0, 0o755),
            DATA: tdi.Facts(tdi.Kind.DIR, ACCOUNT_UID, 0o700),
        }
        self.files: dict[str, bytes] = {}
        self.alive: set[int] = set()
        self.loaded = False
        self.print_rc: int | None = None
        self.ps_rc: int | None = None
        self.launchctl_rc: dict[str, int] = {}
        self.wait_result = True
        self.new_pid_after_wait: int | None = None
        self.probe_result = True
        self.publish_error: OSError | None = None
        self.remove_error: OSError | None = None
        self.calls: list[tuple[object, ...]] = []

    def platform(self) -> str:
        return self.platform_name

    def euid(self) -> int:
        return self.euid_value

    def lookup_account(self, name: str) -> tuple[int, int] | None:
        return self.accounts.get(name)

    def lookup_group(self, gid: int) -> str | None:
        return self.groups.get(gid)

    def lstat(self, path: str):
        if path in self.facts:
            return self.facts[path]
        if path in self.files:
            return tdi.Facts(tdi.Kind.FILE, 0, 0o644)
        return tdi.Facts(tdi.Kind.ABSENT)

    def read_file(self, path: str, limit: int) -> bytes | None:
        data = self.files.get(path)
        return None if data is None else data[: limit + 1]

    def _run(self, argv: list[str]) -> subprocess.CompletedProcess[str]:
        self.calls.append(tuple(argv))
        if argv[:2] == [tdi.LAUNCHCTL, "print"]:
            rc = self.print_rc if self.print_rc is not None else (0 if self.loaded else 113)
            return subprocess.CompletedProcess(argv, rc, "", "")
        if argv[0] == tdi.LAUNCHCTL:
            rc = self.launchctl_rc.get(argv[1], 0)
            if rc == 0:
                self.loaded = argv[1] == "bootstrap"
            return subprocess.CompletedProcess(argv, rc, "", "")
        if argv[0] == tdi.PS:
            pid = int(argv[2])
            if self.ps_rc is not None:
                return subprocess.CompletedProcess(argv, self.ps_rc, "", "")
            if pid in self.alive:
                return subprocess.CompletedProcess(argv, 0, f"{pid:>6}\n", "")
            return subprocess.CompletedProcess(argv, 1, "", "")
        raise AssertionError(f"unexpected command {argv}")

    def wait_pid_exit(self, pid: int, seconds: int) -> bool:
        self.calls.append(("wait", pid, seconds))
        if not self.wait_result:
            return False
        self.alive.discard(pid)
        if self.new_pid_after_wait is not None:
            self.alive.add(self.new_pid_after_wait)
            self.files[PIDFILE] = f"{self.new_pid_after_wait}\n".encode()
        return True

    def publish_file(self, path: str, data: bytes) -> None:
        self._require_changes()
        self.calls.append(("publish", path))
        if self.publish_error is not None:
            raise self.publish_error
        if path in self.files:
            raise FileExistsError(errno.EEXIST, "exists")
        self.files[path] = data

    def remove_file(self, path: str) -> None:
        self._require_changes()
        self.calls.append(("remove", path))
        if self.remove_error is not None:
            raise self.remove_error
        del self.files[path]

    def probe_port(self, port: int, seconds: int) -> bool:
        self.calls.append(("probe", port, seconds))
        return self.probe_result


MODE_FLAGS = {"DRY_RUN": [], "INSTALL": ["--install"], "REMOVE": ["--remove"]}


def base_args() -> dict[str, str | None]:
    return {"--postgres-bin": BIN, "--data-dir": DATA, "--account": ACCOUNT, "--label": LABEL, "--port": PORT}


def argv_for(mode: str, handover: bool = False, overrides: dict[str, str | None] | None = None) -> list[str]:
    values = base_args()
    values.update(overrides or {})
    argv: list[str] = []
    for flag, value in values.items():
        if value is not None:
            argv.append(f"{flag}={value}")
    argv.extend(MODE_FLAGS[mode])
    if handover:
        argv.append("--handover")
    return argv


def fake_for(mode: str, euid: int, target: str, postmaster: str, loaded: bool | None = None) -> FakeRunner:
    fake = FakeRunner(allow_changes=mode != "DRY_RUN", euid=euid)
    match target:
        case "ABSENT":
            fake.loaded = False if loaded is None else loaded
        case "IDENTICAL":
            fake.files[PLIST] = PLIST_BYTES
            fake.loaded = True if loaded is None else loaded
        case "DIFFERENT":
            fake.files[PLIST] = FOREIGN_BYTES
            fake.loaded = True if loaded is None else loaded
        case _:
            raise AssertionError(target)
    match postmaster:
        case "NONE":
            pass
        case "ALIVE":
            fake.files[PIDFILE] = PIDFILE_BYTES
            fake.alive.add(PID)
        case "STALE":
            fake.files[PIDFILE] = PIDFILE_BYTES
        case _:
            raise AssertionError(postmaster)
    return fake


TARGET_LINES = {
    "ABSENT": f"plist target: {PLIST} absent",
    "IDENTICAL": f"plist target: {PLIST} identical bytes",
    "DIFFERENT": f"plist target: {PLIST} different bytes ({DIFF_SUMMARY})",
}
LOADED_LINES = {True: f"service {SERVICE}: loaded", False: f"service {SERVICE}: not loaded"}
PM_LINES = {
    "NONE": "postmaster: none",
    "ALIVE": "postmaster: alive, pid 4242",
    "STALE": "postmaster: stale pid file, pid 4242 is not running",
}
READ_CALLS = {"NONE": [PRINT], "ALIVE": [PRINT, PS], "STALE": [PRINT, PS]}
INSTALL_VERDICTS = {
    "write": "install verdict: proceed: write, bootstrap, probe",
    "pm": (
        "install verdict: refuse: postmaster pid 4242 holds /opt/tier/pgdata; nothing changed; "
        "stop its supervisor, then pass --handover"
    ),
    "handover": "install verdict: hand-over: wait up to 300 s for pid 4242 to exit, then write, bootstrap, probe",
    "noop": f"install verdict: no-op: {PLIST} holds identical bytes and {SERVICE} is loaded",
    "different": f"install verdict: refuse: plist target {PLIST} holds different bytes ({DIFF_SUMMARY}); nothing changed",
}
REMOVE_VERDICTS = {
    "noop": f"remove verdict: no-op: {PLIST} is absent and {SERVICE} is not loaded",
    "bootout_remove": "remove verdict: proceed: bootout, remove plist",
    "notours": f"remove verdict: refuse: plist target {PLIST} is not ours ({DIFF_SUMMARY}); nothing changed",
}


def dry_lines(target: str, loaded: bool, postmaster: str, euid: int, install: str, remove: str) -> list[str]:
    return [
        OUT + "dry run, nothing is changed",
        "account: pgtier uid 501 group staff gid 20",
        TARGET_LINES[target],
        LOADED_LINES[loaded],
        PM_LINES[postmaster],
        f"effective uid: {euid}",
        "--- plist begin ---",
        *PLIST_LINES,
        "--- plist end ---",
        f"install, in order (as root: sudo {CMD} --install):",
        f"  1. write {PLIST} atomically, mode 0644, owner root:wheel",
        f"  2. launchctl bootstrap system {PLIST}",
        "  3. probe 127.0.0.1:5445, deadline 60 s",
        f"hand-over when a postmaster holds the data directory (as root: sudo {CMD} --install --handover):",
        "  1. stop the interim supervisor of the running postmaster",
        "  2. stop the running postmaster cleanly as pgtier: /opt/tier/bin/pg_ctl -D /opt/tier/pgdata stop -m fast",
        "  3. the tool waits up to 300 s for that pid to exit and refuses if a new postmaster holds the data directory",
        f"  4. write {PLIST} as in install step 1 when it is absent",
        f"  5. launchctl bootstrap system {PLIST}",
        "  6. probe 127.0.0.1:5445, deadline 60 s",
        f"removal, in order (as root: sudo {CMD} --remove):",
        f"  1. launchctl bootout {SERVICE}",
        f"  2. rm {PLIST}",
        INSTALL_VERDICTS[install],
        REMOVE_VERDICTS[remove],
    ]


LOADED_NO_PLIST = f"{SERVICE} is loaded but {PLIST} is absent; nothing changed; inspect: launchctl print {SERVICE}"
WROTE = f"wrote {PLIST} (mode 0644, owner root:wheel)"
BOOTSTRAPPED = f"bootstrapped {SERVICE}"
ANSWERS = "127.0.0.1:5445 answers; installed"
REMOVAL_ERR = ["removal, in order:", f"  1. launchctl bootout {SERVICE}", f"  2. rm {PLIST}"]

# key -> (exit code, stdout lines, stderr lines, commands after the state reads, state is read)
OUTCOMES: dict[str, tuple[int, list[str], list[str], list[tuple[object, ...]], bool]] = {
    "NOTROOT_I": (
        3,
        [],
        [REFUSED + f"--install needs root (effective uid 501); this tool never calls sudo; run: sudo {CMD} --install"],
        [],
        False,
    ),
    "NOTROOT_IH": (
        3,
        [],
        [
            REFUSED
            + f"--install needs root (effective uid 501); this tool never calls sudo; run: sudo {CMD} --install --handover"
        ],
        [],
        False,
    ),
    "NOTROOT_R": (
        3,
        [],
        [REFUSED + f"--remove needs root (effective uid 501); this tool never calls sudo; run: sudo {CMD} --remove"],
        [],
        False,
    ),
    "USAGE_RH": (2, [], [REFUSED + "--handover goes with --install only"], [], False),
    "I_DIFFERENT": (
        4,
        [],
        [REFUSED + f"plist target {PLIST} holds different bytes ({DIFF_SUMMARY}); nothing changed"],
        [],
        True,
    ),
    "I_NOOP": (0, [OUT + f"--install: no-op: {PLIST} holds identical bytes and {SERVICE} is loaded"], [], [], True),
    "I_PM": (
        5,
        [],
        [REFUSED + "postmaster pid 4242 holds /opt/tier/pgdata; nothing changed; stop its supervisor, then pass --handover"],
        [],
        True,
    ),
    "I_WRITE": (
        0,
        [OUT + "--install: proceed: write, bootstrap, probe", WROTE, BOOTSTRAPPED, ANSWERS],
        [],
        [PUBLISH, BOOTSTRAP, PROBE],
        True,
    ),
    "I_HANDOVER": (
        0,
        [
            OUT + "--install: hand-over: wait up to 300 s for pid 4242 to exit, then write, bootstrap, probe",
            "postmaster pid 4242 exited",
            WROTE,
            BOOTSTRAPPED,
            ANSWERS,
        ],
        [],
        [WAIT, PS, PUBLISH, BOOTSTRAP, PROBE],
        True,
    ),
    "I_BOOTSTRAP": (0, [OUT + "--install: proceed: bootstrap, probe", BOOTSTRAPPED, ANSWERS], [], [BOOTSTRAP, PROBE], True),
    "LOADED_NO_PLIST": (4, [], [REFUSED + LOADED_NO_PLIST], [], True),
    "R_NOTOURS": (4, [], [REFUSED + f"plist target {PLIST} is not ours ({DIFF_SUMMARY}); nothing changed"], [], True),
    "R_NOOP": (0, [OUT + f"--remove: no-op: {PLIST} is absent and {SERVICE} is not loaded"], [], [], True),
    "R_BOOTOUT_REMOVE": (
        0,
        [OUT + "--remove: proceed: bootout, remove plist", f"booted out {SERVICE}", f"removed {PLIST}"],
        [],
        [BOOTOUT, REMOVE],
        True,
    ),
    "R_REMOVE": (0, [OUT + "--remove: proceed: remove plist", f"removed {PLIST}"], [], [REMOVE], True),
}

# The exhaustive table: mode x euid x plist target x postmaster x handover, expected column by hand.
# The plist target fixes the loaded state (absent: not loaded; identical, different: loaded).
TABLE = [
    ("DRY_RUN", 0, "ABSENT", "NONE", False, "D:write:noop"),
    ("DRY_RUN", 0, "ABSENT", "NONE", True, "D:write:noop"),
    ("DRY_RUN", 0, "ABSENT", "ALIVE", False, "D:pm:noop"),
    ("DRY_RUN", 0, "ABSENT", "ALIVE", True, "D:handover:noop"),
    ("DRY_RUN", 0, "ABSENT", "STALE", False, "D:write:noop"),
    ("DRY_RUN", 0, "ABSENT", "STALE", True, "D:write:noop"),
    ("DRY_RUN", 0, "IDENTICAL", "NONE", False, "D:noop:bootout_remove"),
    ("DRY_RUN", 0, "IDENTICAL", "NONE", True, "D:noop:bootout_remove"),
    ("DRY_RUN", 0, "IDENTICAL", "ALIVE", False, "D:noop:bootout_remove"),
    ("DRY_RUN", 0, "IDENTICAL", "ALIVE", True, "D:noop:bootout_remove"),
    ("DRY_RUN", 0, "IDENTICAL", "STALE", False, "D:noop:bootout_remove"),
    ("DRY_RUN", 0, "IDENTICAL", "STALE", True, "D:noop:bootout_remove"),
    ("DRY_RUN", 0, "DIFFERENT", "NONE", False, "D:different:notours"),
    ("DRY_RUN", 0, "DIFFERENT", "NONE", True, "D:different:notours"),
    ("DRY_RUN", 0, "DIFFERENT", "ALIVE", False, "D:different:notours"),
    ("DRY_RUN", 0, "DIFFERENT", "ALIVE", True, "D:different:notours"),
    ("DRY_RUN", 0, "DIFFERENT", "STALE", False, "D:different:notours"),
    ("DRY_RUN", 0, "DIFFERENT", "STALE", True, "D:different:notours"),
    ("DRY_RUN", 501, "ABSENT", "NONE", False, "D:write:noop"),
    ("DRY_RUN", 501, "ABSENT", "NONE", True, "D:write:noop"),
    ("DRY_RUN", 501, "ABSENT", "ALIVE", False, "D:pm:noop"),
    ("DRY_RUN", 501, "ABSENT", "ALIVE", True, "D:handover:noop"),
    ("DRY_RUN", 501, "ABSENT", "STALE", False, "D:write:noop"),
    ("DRY_RUN", 501, "ABSENT", "STALE", True, "D:write:noop"),
    ("DRY_RUN", 501, "IDENTICAL", "NONE", False, "D:noop:bootout_remove"),
    ("DRY_RUN", 501, "IDENTICAL", "NONE", True, "D:noop:bootout_remove"),
    ("DRY_RUN", 501, "IDENTICAL", "ALIVE", False, "D:noop:bootout_remove"),
    ("DRY_RUN", 501, "IDENTICAL", "ALIVE", True, "D:noop:bootout_remove"),
    ("DRY_RUN", 501, "IDENTICAL", "STALE", False, "D:noop:bootout_remove"),
    ("DRY_RUN", 501, "IDENTICAL", "STALE", True, "D:noop:bootout_remove"),
    ("DRY_RUN", 501, "DIFFERENT", "NONE", False, "D:different:notours"),
    ("DRY_RUN", 501, "DIFFERENT", "NONE", True, "D:different:notours"),
    ("DRY_RUN", 501, "DIFFERENT", "ALIVE", False, "D:different:notours"),
    ("DRY_RUN", 501, "DIFFERENT", "ALIVE", True, "D:different:notours"),
    ("DRY_RUN", 501, "DIFFERENT", "STALE", False, "D:different:notours"),
    ("DRY_RUN", 501, "DIFFERENT", "STALE", True, "D:different:notours"),
    ("INSTALL", 0, "ABSENT", "NONE", False, "I_WRITE"),
    ("INSTALL", 0, "ABSENT", "NONE", True, "I_WRITE"),
    ("INSTALL", 0, "ABSENT", "ALIVE", False, "I_PM"),
    ("INSTALL", 0, "ABSENT", "ALIVE", True, "I_HANDOVER"),
    ("INSTALL", 0, "ABSENT", "STALE", False, "I_WRITE"),
    ("INSTALL", 0, "ABSENT", "STALE", True, "I_WRITE"),
    ("INSTALL", 0, "IDENTICAL", "NONE", False, "I_NOOP"),
    ("INSTALL", 0, "IDENTICAL", "NONE", True, "I_NOOP"),
    ("INSTALL", 0, "IDENTICAL", "ALIVE", False, "I_NOOP"),
    ("INSTALL", 0, "IDENTICAL", "ALIVE", True, "I_NOOP"),
    ("INSTALL", 0, "IDENTICAL", "STALE", False, "I_NOOP"),
    ("INSTALL", 0, "IDENTICAL", "STALE", True, "I_NOOP"),
    ("INSTALL", 0, "DIFFERENT", "NONE", False, "I_DIFFERENT"),
    ("INSTALL", 0, "DIFFERENT", "NONE", True, "I_DIFFERENT"),
    ("INSTALL", 0, "DIFFERENT", "ALIVE", False, "I_DIFFERENT"),
    ("INSTALL", 0, "DIFFERENT", "ALIVE", True, "I_DIFFERENT"),
    ("INSTALL", 0, "DIFFERENT", "STALE", False, "I_DIFFERENT"),
    ("INSTALL", 0, "DIFFERENT", "STALE", True, "I_DIFFERENT"),
    ("INSTALL", 501, "ABSENT", "NONE", False, "NOTROOT_I"),
    ("INSTALL", 501, "ABSENT", "NONE", True, "NOTROOT_IH"),
    ("INSTALL", 501, "ABSENT", "ALIVE", False, "NOTROOT_I"),
    ("INSTALL", 501, "ABSENT", "ALIVE", True, "NOTROOT_IH"),
    ("INSTALL", 501, "ABSENT", "STALE", False, "NOTROOT_I"),
    ("INSTALL", 501, "ABSENT", "STALE", True, "NOTROOT_IH"),
    ("INSTALL", 501, "IDENTICAL", "NONE", False, "NOTROOT_I"),
    ("INSTALL", 501, "IDENTICAL", "NONE", True, "NOTROOT_IH"),
    ("INSTALL", 501, "IDENTICAL", "ALIVE", False, "NOTROOT_I"),
    ("INSTALL", 501, "IDENTICAL", "ALIVE", True, "NOTROOT_IH"),
    ("INSTALL", 501, "IDENTICAL", "STALE", False, "NOTROOT_I"),
    ("INSTALL", 501, "IDENTICAL", "STALE", True, "NOTROOT_IH"),
    ("INSTALL", 501, "DIFFERENT", "NONE", False, "NOTROOT_I"),
    ("INSTALL", 501, "DIFFERENT", "NONE", True, "NOTROOT_IH"),
    ("INSTALL", 501, "DIFFERENT", "ALIVE", False, "NOTROOT_I"),
    ("INSTALL", 501, "DIFFERENT", "ALIVE", True, "NOTROOT_IH"),
    ("INSTALL", 501, "DIFFERENT", "STALE", False, "NOTROOT_I"),
    ("INSTALL", 501, "DIFFERENT", "STALE", True, "NOTROOT_IH"),
    ("REMOVE", 0, "ABSENT", "NONE", False, "R_NOOP"),
    ("REMOVE", 0, "ABSENT", "NONE", True, "USAGE_RH"),
    ("REMOVE", 0, "ABSENT", "ALIVE", False, "R_NOOP"),
    ("REMOVE", 0, "ABSENT", "ALIVE", True, "USAGE_RH"),
    ("REMOVE", 0, "ABSENT", "STALE", False, "R_NOOP"),
    ("REMOVE", 0, "ABSENT", "STALE", True, "USAGE_RH"),
    ("REMOVE", 0, "IDENTICAL", "NONE", False, "R_BOOTOUT_REMOVE"),
    ("REMOVE", 0, "IDENTICAL", "NONE", True, "USAGE_RH"),
    ("REMOVE", 0, "IDENTICAL", "ALIVE", False, "R_BOOTOUT_REMOVE"),
    ("REMOVE", 0, "IDENTICAL", "ALIVE", True, "USAGE_RH"),
    ("REMOVE", 0, "IDENTICAL", "STALE", False, "R_BOOTOUT_REMOVE"),
    ("REMOVE", 0, "IDENTICAL", "STALE", True, "USAGE_RH"),
    ("REMOVE", 0, "DIFFERENT", "NONE", False, "R_NOTOURS"),
    ("REMOVE", 0, "DIFFERENT", "NONE", True, "USAGE_RH"),
    ("REMOVE", 0, "DIFFERENT", "ALIVE", False, "R_NOTOURS"),
    ("REMOVE", 0, "DIFFERENT", "ALIVE", True, "USAGE_RH"),
    ("REMOVE", 0, "DIFFERENT", "STALE", False, "R_NOTOURS"),
    ("REMOVE", 0, "DIFFERENT", "STALE", True, "USAGE_RH"),
    ("REMOVE", 501, "ABSENT", "NONE", False, "NOTROOT_R"),
    ("REMOVE", 501, "ABSENT", "NONE", True, "USAGE_RH"),
    ("REMOVE", 501, "ABSENT", "ALIVE", False, "NOTROOT_R"),
    ("REMOVE", 501, "ABSENT", "ALIVE", True, "USAGE_RH"),
    ("REMOVE", 501, "ABSENT", "STALE", False, "NOTROOT_R"),
    ("REMOVE", 501, "ABSENT", "STALE", True, "USAGE_RH"),
    ("REMOVE", 501, "IDENTICAL", "NONE", False, "NOTROOT_R"),
    ("REMOVE", 501, "IDENTICAL", "NONE", True, "USAGE_RH"),
    ("REMOVE", 501, "IDENTICAL", "ALIVE", False, "NOTROOT_R"),
    ("REMOVE", 501, "IDENTICAL", "ALIVE", True, "USAGE_RH"),
    ("REMOVE", 501, "IDENTICAL", "STALE", False, "NOTROOT_R"),
    ("REMOVE", 501, "IDENTICAL", "STALE", True, "USAGE_RH"),
    ("REMOVE", 501, "DIFFERENT", "NONE", False, "NOTROOT_R"),
    ("REMOVE", 501, "DIFFERENT", "NONE", True, "USAGE_RH"),
    ("REMOVE", 501, "DIFFERENT", "ALIVE", False, "NOTROOT_R"),
    ("REMOVE", 501, "DIFFERENT", "ALIVE", True, "USAGE_RH"),
    ("REMOVE", 501, "DIFFERENT", "STALE", False, "NOTROOT_R"),
    ("REMOVE", 501, "DIFFERENT", "STALE", True, "USAGE_RH"),
]

# The loaded states the table above fixes, crossed the other way (euid 0, no postmaster, no handover).
LOADED_TABLE = [
    ("INSTALL", "ABSENT", True, "LOADED_NO_PLIST"),
    ("INSTALL", "IDENTICAL", False, "I_BOOTSTRAP"),
    ("INSTALL", "DIFFERENT", False, "I_DIFFERENT"),
    ("REMOVE", "ABSENT", True, "LOADED_NO_PLIST"),
    ("REMOVE", "IDENTICAL", False, "R_REMOVE"),
    ("REMOVE", "DIFFERENT", False, "R_NOTOURS"),
    ("DRY_RUN", "ABSENT", True, "D:refuse_loaded:refuse_loaded"),
    ("DRY_RUN", "IDENTICAL", False, "D:bootstrap:remove"),
    ("DRY_RUN", "DIFFERENT", False, "D:different:notours"),
]
INSTALL_VERDICTS["refuse_loaded"] = "install verdict: refuse: " + LOADED_NO_PLIST
INSTALL_VERDICTS["bootstrap"] = "install verdict: proceed: bootstrap, probe"
REMOVE_VERDICTS["refuse_loaded"] = "remove verdict: refuse: " + LOADED_NO_PLIST
REMOVE_VERDICTS["remove"] = "remove verdict: proceed: remove plist"


def expected(key: str, target: str, loaded: bool, postmaster: str, euid: int):
    """The hand-written outcome for one key: (code, out, err, calls)."""
    if key.startswith("D:"):
        _, install, remove = key.split(":")
        return 0, dry_lines(target, loaded, postmaster, euid, install, remove), [], READ_CALLS[postmaster]
    code, out, err, actions, reads = OUTCOMES[key]
    return code, out, err, (READ_CALLS[postmaster] if reads else []) + actions


def run_fake(fake: FakeRunner, argv: list[str]):
    outcome = tdi.run(argv, fake, INVOCATION)
    return outcome.code, outcome.out, outcome.err, fake.calls


class ExhaustiveTableTests(unittest.TestCase):
    def test_table_covers_the_whole_product_once(self) -> None:
        seen = [(m, e, t, p, h) for m, e, t, p, h, _ in TABLE]
        self.assertEqual(len(seen), len(set(seen)))
        domain = {
            (m, e, t, p, h)
            for m in (mode.name for mode in tdi.Mode)
            for e in (0, NON_ROOT_EUID)
            for t in (target.name for target in tdi.Target)
            for p in (pm.name for pm in tdi.Postmaster)
            for h in (False, True)
        }
        self.assertEqual(set(seen), domain)
        self.assertEqual(len(TABLE), 108)

    def test_every_row(self) -> None:
        for mode, euid, target, postmaster, handover, key in TABLE:
            with self.subTest(mode=mode, euid=euid, target=target, postmaster=postmaster, handover=handover):
                fake = fake_for(mode, euid, target, postmaster)
                loaded = fake.loaded
                got = run_fake(fake, argv_for(mode, handover))
                self.assertEqual(got, expected(key, target, loaded, postmaster, euid))

    def test_loaded_rows(self) -> None:
        for mode, target, loaded, key in LOADED_TABLE:
            with self.subTest(mode=mode, target=target, loaded=loaded):
                fake = fake_for(mode, 0, target, "NONE", loaded=loaded)
                got = run_fake(fake, argv_for(mode))
                self.assertEqual(got, expected(key, target, loaded, "NONE", 0))

    def test_dry_run_changes_nothing_for_every_row(self) -> None:
        for mode, euid, target, postmaster, handover, _ in TABLE:
            if mode != "DRY_RUN":
                continue
            with self.subTest(euid=euid, target=target, postmaster=postmaster, handover=handover):
                fake = fake_for(mode, euid, target, postmaster)
                files_before = dict(fake.files)
                loaded_before = fake.loaded
                run_fake(fake, argv_for(mode, handover))
                self.assertEqual(fake.files, files_before)
                self.assertEqual(fake.loaded, loaded_before)
                self.assertTrue(set(fake.calls) <= READ_ONLY_CALLS, fake.calls)


class FailureAfterChangeTests(unittest.TestCase):
    """A failure after the write reports the re-read state and the removal path; nothing is undone silently."""

    def test_bootstrap_fails(self) -> None:
        fake = fake_for("INSTALL", 0, "ABSENT", "NONE")
        fake.launchctl_rc["bootstrap"] = 5
        self.assertEqual(
            run_fake(fake, argv_for("INSTALL")),
            (
                6,
                [OUT + "--install: proceed: write, bootstrap, probe", WROTE],
                [
                    FAILED + f"launchctl bootstrap system {PLIST} exited 5",
                    f"state: plist {PLIST} present; service {SERVICE} not loaded",
                    *REMOVAL_ERR,
                ],
                [PRINT, PUBLISH, BOOTSTRAP, PRINT],
            ),
        )
        self.assertEqual(fake.files[PLIST], PLIST_BYTES)

    def test_probe_fails(self) -> None:
        fake = fake_for("INSTALL", 0, "ABSENT", "NONE")
        fake.probe_result = False
        self.assertEqual(
            run_fake(fake, argv_for("INSTALL")),
            (
                7,
                [OUT + "--install: proceed: write, bootstrap, probe", WROTE, BOOTSTRAPPED],
                [
                    FAILED + "127.0.0.1:5445 did not answer within 60 s",
                    f"state: plist {PLIST} present; service {SERVICE} loaded",
                    *REMOVAL_ERR,
                ],
                [PRINT, PUBLISH, BOOTSTRAP, PROBE, PRINT],
            ),
        )

    def test_write_loses_a_race(self) -> None:
        fake = fake_for("INSTALL", 0, "ABSENT", "NONE")
        fake.publish_error = FileExistsError(errno.EEXIST, "exists")
        self.assertEqual(
            run_fake(fake, argv_for("INSTALL")),
            (
                6,
                [OUT + "--install: proceed: write, bootstrap, probe"],
                [
                    FAILED + f"writing {PLIST}: EEXIST",
                    f"state: plist {PLIST} absent; service {SERVICE} not loaded",
                    *REMOVAL_ERR,
                ],
                [PRINT, PUBLISH, PRINT],
            ),
        )

    def test_handover_timeout_changes_nothing(self) -> None:
        fake = fake_for("INSTALL", 0, "ABSENT", "ALIVE")
        fake.wait_result = False
        self.assertEqual(
            run_fake(fake, argv_for("INSTALL", handover=True)),
            (
                8,
                [OUT + "--install: hand-over: wait up to 300 s for pid 4242 to exit, then write, bootstrap, probe"],
                [REFUSED + "postmaster pid 4242 did not exit within 300 s; nothing changed"],
                [PRINT, PS, WAIT],
            ),
        )
        self.assertNotIn(PLIST, fake.files)

    def test_handover_new_postmaster_refuses(self) -> None:
        fake = fake_for("INSTALL", 0, "ABSENT", "ALIVE")
        fake.new_pid_after_wait = NEW_PID
        self.assertEqual(
            run_fake(fake, argv_for("INSTALL", handover=True)),
            (
                5,
                [OUT + "--install: hand-over: wait up to 300 s for pid 4242 to exit, then write, bootstrap, probe"],
                [
                    REFUSED
                    + "postmaster pid 5151 started on /opt/tier/pgdata during the hand-over; nothing changed; "
                    "stop the interim supervisor first"
                ],
                [PRINT, PS, WAIT, PS_NEW],
            ),
        )
        self.assertNotIn(PLIST, fake.files)

    def test_bootout_fails_keeps_the_plist(self) -> None:
        fake = fake_for("REMOVE", 0, "IDENTICAL", "NONE")
        fake.launchctl_rc["bootout"] = 3
        self.assertEqual(
            run_fake(fake, argv_for("REMOVE")),
            (
                6,
                [OUT + "--remove: proceed: bootout, remove plist"],
                [
                    FAILED + f"launchctl bootout {SERVICE} exited 3",
                    f"state: plist {PLIST} present; service {SERVICE} loaded",
                    *REMOVAL_ERR,
                ],
                [PRINT, BOOTOUT, PRINT],
            ),
        )
        self.assertEqual(fake.files[PLIST], PLIST_BYTES)

    def test_remove_fails(self) -> None:
        fake = fake_for("REMOVE", 0, "IDENTICAL", "NONE")
        fake.remove_error = PermissionError(errno.EPERM, "denied")
        self.assertEqual(
            run_fake(fake, argv_for("REMOVE")),
            (
                6,
                [OUT + "--remove: proceed: bootout, remove plist", f"booted out {SERVICE}"],
                [
                    FAILED + f"removing {PLIST}: EPERM",
                    f"state: plist {PLIST} present; service {SERVICE} not loaded",
                    *REMOVAL_ERR,
                ],
                [PRINT, BOOTOUT, REMOVE, PRINT],
            ),
        )

    def test_install_then_install_is_a_noop_and_remove_twice_is_idempotent(self) -> None:
        fake = fake_for("INSTALL", 0, "ABSENT", "NONE")
        self.assertEqual(run_fake(fake, argv_for("INSTALL"))[0], 0)
        self.assertEqual(fake.files[PLIST], PLIST_BYTES)
        fake.calls.clear()
        self.assertEqual(run_fake(fake, argv_for("INSTALL")), expected("I_NOOP", "IDENTICAL", True, "NONE", 0))
        fake.calls.clear()
        self.assertEqual(run_fake(fake, argv_for("REMOVE")), expected("R_BOOTOUT_REMOVE", "IDENTICAL", True, "NONE", 0))
        self.assertNotIn(PLIST, fake.files)
        fake.calls.clear()
        self.assertEqual(run_fake(fake, argv_for("REMOVE")), expected("R_NOOP", "ABSENT", False, "NONE", 0))


NOT_NORMAL = "is not in normal form (no '.', '..', '//' or trailing '/')"
LABEL_RULE = "is not a valid launchd label (letters, digits, '.', '_', '-'; 128 at most)"


def _set_fact(path: str, kind: str, uid: int, mode: int):
    def mutate(fake: FakeRunner) -> None:
        fake.facts[path] = tdi.Facts(getattr(tdi.Kind, kind), uid, mode)

    return mutate


def _drop_fact(path: str):
    def mutate(fake: FakeRunner) -> None:
        fake.facts.pop(path)

    return mutate


def _set_file(path: str, data: bytes, alive: bool = False):
    def mutate(fake: FakeRunner) -> None:
        fake.files[path] = data
        if alive:
            fake.alive.add(PID)

    return mutate


def _set_attr(name: str, value: object):
    def mutate(fake: FakeRunner) -> None:
        setattr(fake, name, value)

    return mutate


# (row name, argument overrides, fake mutation, exit code, exact refusal after the prefix)
DEGENERATE = [
    ("bin unset", {"--postgres-bin": None}, None, 2, "--postgres-bin is not set"),
    ("bin empty", {"--postgres-bin": ""}, None, 2, "--postgres-bin is empty"),
    ("bin relative", {"--postgres-bin": "opt/tier/bin/postgres"}, None, 2, "--postgres-bin is not an absolute path"),
    ("bin dot-dot", {"--postgres-bin": "/opt/tier/bin/../bin/postgres"}, None, 2, "--postgres-bin " + NOT_NORMAL),
    ("bin dot", {"--postgres-bin": "/opt/./tier/bin/postgres"}, None, 2, "--postgres-bin " + NOT_NORMAL),
    ("bin double slash", {"--postgres-bin": "/opt/tier//bin/postgres"}, None, 2, "--postgres-bin " + NOT_NORMAL),
    ("bin leading //", {"--postgres-bin": "//opt/tier/bin/postgres"}, None, 2, "--postgres-bin " + NOT_NORMAL),
    ("bin trailing /", {"--postgres-bin": "/opt/tier/bin/postgres/"}, None, 2, "--postgres-bin " + NOT_NORMAL),
    ("bin newline", {"--postgres-bin": "/opt/tier/bin/postgres\n"}, None, 2, "--postgres-bin contains a control character"),
    ("bin over cap", {"--postgres-bin": "/" + "a" * 1024}, None, 2, "--postgres-bin is longer than 1024 characters"),
    ("bin not utf-8", {"--postgres-bin": "/opt/tier/\udcff"}, None, 2, "--postgres-bin is not valid UTF-8"),
    ("bin missing", {}, _drop_fact(BIN), 2, f"--postgres-bin {BIN} does not exist"),
    ("bin symlink", {}, _set_fact(BIN, "SYMLINK", 0, 0o755), 2, f"--postgres-bin {BIN} is a symlink"),
    ("bin directory", {}, _set_fact(BIN, "DIR", 0, 0o755), 2, f"--postgres-bin {BIN} is not a regular file"),
    ("bin fifo", {}, _set_fact(BIN, "OTHER", 0, 0o755), 2, f"--postgres-bin {BIN} is not a regular file"),
    ("bin not executable", {}, _set_fact(BIN, "FILE", 0, 0o644), 2, f"--postgres-bin {BIN} is not executable"),
    ("bin group writable", {}, _set_fact(BIN, "FILE", 0, 0o775), 2, f"--postgres-bin {BIN} is writable by group or others"),
    ("bin world writable", {}, _set_fact(BIN, "FILE", 0, 0o757), 2, f"--postgres-bin {BIN} is writable by group or others"),
    ("data unset", {"--data-dir": None}, None, 2, "--data-dir is not set"),
    ("data empty", {"--data-dir": ""}, None, 2, "--data-dir is empty"),
    ("data relative", {"--data-dir": "pgdata"}, None, 2, "--data-dir is not an absolute path"),
    ("data trailing /", {"--data-dir": "/opt/tier/pgdata/"}, None, 2, "--data-dir " + NOT_NORMAL),
    ("data NUL", {"--data-dir": "/opt/tier/pg\x00data"}, None, 2, "--data-dir contains a control character"),
    ("data missing", {}, _drop_fact(DATA), 2, f"--data-dir {DATA} does not exist"),
    ("data symlink", {}, _set_fact(DATA, "SYMLINK", ACCOUNT_UID, 0o700), 2, f"--data-dir {DATA} is a symlink"),
    ("data is a file", {}, _set_fact(DATA, "FILE", ACCOUNT_UID, 0o700), 2, f"--data-dir {DATA} is not a directory"),
    (
        "data wrong owner",
        {},
        _set_fact(DATA, "DIR", 502, 0o700),
        2,
        f"--data-dir {DATA} is owned by uid 502, not by pgtier (uid 501)",
    ),
    (
        "data owned by root",
        {},
        _set_fact(DATA, "DIR", 0, 0o700),
        2,
        f"--data-dir {DATA} is owned by uid 0, not by pgtier (uid 501)",
    ),
    ("data group writable", {}, _set_fact(DATA, "DIR", ACCOUNT_UID, 0o770), 2, f"--data-dir {DATA} is group or world writable"),
    ("data world writable", {}, _set_fact(DATA, "DIR", ACCOUNT_UID, 0o702), 2, f"--data-dir {DATA} is group or world writable"),
    ("account unset", {"--account": None}, None, 2, "--account is not set"),
    ("account empty", {"--account": ""}, None, 2, "--account is empty"),
    ("account root", {"--account": "root"}, None, 2, "--account root is refused: the daemon never runs as root"),
    ("account blank inside", {"--account": "pg tier"}, None, 2, "--account 'pg tier' is not a valid account name"),
    ("account leading dash", {"--account": "-x"}, None, 2, "--account '-x' is not a valid account name"),
    ("account over 64", {"--account": "a" * 65}, None, 2, f"--account '{'a' * 65}' is not a valid account name"),
    ("account newline", {"--account": "pgtier\n"}, None, 2, "--account contains a control character"),
    ("account unknown", {"--account": "nosuchuser"}, None, 2, "--account nosuchuser is not a known account"),
    ("account uid 0", {"--account": "toor"}, None, 2, "--account toor has uid 0: the daemon never runs as root"),
    (
        "account group unknown",
        {"--account": "pgnogroup"},
        None,
        2,
        "--account pgnogroup has primary gid 999, which has no group entry",
    ),
    (
        "account gid 0",
        {"--account": "pgwheel"},
        None,
        2,
        "--account pgwheel has primary gid 0: the daemon never runs with group wheel",
    ),
    ("label unset", {"--label": None}, None, 2, "--label is not set"),
    ("label empty", {"--label": ""}, None, 2, "--label is empty"),
    ("label traversal", {"--label": "../evil"}, None, 2, "--label '../evil' " + LABEL_RULE),
    ("label slash", {"--label": "a/b"}, None, 2, "--label 'a/b' " + LABEL_RULE),
    ("label leading dot", {"--label": ".hidden"}, None, 2, "--label '.hidden' " + LABEL_RULE),
    ("label over 128", {"--label": "a" * 129}, None, 2, f"--label '{'a' * 129}' " + LABEL_RULE),
    ("label newline", {"--label": "com.example\n"}, None, 2, "--label contains a control character"),
    ("port unset", {"--port": None}, None, 2, "--port is not set"),
    ("port empty", {"--port": ""}, None, 2, "--port is empty"),
    ("port zero", {"--port": "0"}, None, 2, "--port '0' is not a port number between 1 and 65535"),
    ("port over", {"--port": "65536"}, None, 2, "--port '65536' is not a port number between 1 and 65535"),
    ("port six digits", {"--port": "100000"}, None, 2, "--port '100000' is not a port number between 1 and 65535"),
    ("port negative", {"--port": "-1"}, None, 2, "--port '-1' is not a port number between 1 and 65535"),
    ("port plus", {"--port": "+5445"}, None, 2, "--port '+5445' is not a port number between 1 and 65535"),
    ("port word", {"--port": "abc"}, None, 2, "--port 'abc' is not a port number between 1 and 65535"),
    ("port tab", {"--port": "5445\t"}, None, 2, "--port contains a control character"),
    ("not macOS", {}, _set_attr("platform_name", "linux"), 10, "this tool runs on macOS only (sys.platform is 'linux')"),
    ("launchd dir missing", {}, _drop_fact(LAUNCH_DIR), 9, f"launchd directory {LAUNCH_DIR} does not exist"),
    ("launchd dir symlink", {}, _set_fact(LAUNCH_DIR, "SYMLINK", 0, 0o755), 9, f"launchd directory {LAUNCH_DIR} is a symlink"),
    ("launchd dir file", {}, _set_fact(LAUNCH_DIR, "FILE", 0, 0o644), 9, f"launchd directory {LAUNCH_DIR} is not a directory"),
    (
        "launchd dir writable",
        {},
        _set_fact(LAUNCH_DIR, "DIR", 0, 0o775),
        9,
        f"launchd directory {LAUNCH_DIR} is not owned by root or is group or world writable",
    ),
    (
        "launchd dir not root",
        {},
        _set_fact(LAUNCH_DIR, "DIR", 501, 0o755),
        9,
        f"launchd directory {LAUNCH_DIR} is not owned by root or is group or world writable",
    ),
    ("target symlink", {}, _set_fact(PLIST, "SYMLINK", 0, 0o644), 4, f"plist target {PLIST} is a symlink; nothing changed"),
    ("target directory", {}, _set_fact(PLIST, "DIR", 0, 0o755), 4, f"plist target {PLIST} is not a regular file; nothing changed"),
    ("pidfile empty", {}, _set_file(PIDFILE, b""), 9, f"{PIDFILE} is empty"),
    ("pidfile garbage", {}, _set_file(PIDFILE, b"abc\n"), 9, f"{PIDFILE} does not start with a process id"),
    ("pidfile pid 0", {}, _set_file(PIDFILE, b"0\n"), 9, f"{PIDFILE} does not start with a process id"),
    ("pidfile pid over", {}, _set_file(PIDFILE, b"99999999999\n"), 9, f"{PIDFILE} does not start with a process id"),
    ("pidfile blank first", {}, _set_file(PIDFILE, b" 4242\n"), 9, f"{PIDFILE} does not start with a process id"),
    ("pidfile over cap", {}, _set_file(PIDFILE, b"4242\n" + b"x" * 4092), 9, f"{PIDFILE} is larger than 4096 bytes"),
    ("launchctl print fails", {}, _set_attr("print_rc", 5), 9, f"host probe failed: launchctl print {SERVICE} exited 5"),
    ("ps fails", {}, _set_file(PIDFILE, PIDFILE_BYTES, alive=True), 9, "host probe failed: ps -p 4242 exited 2"),
]
DEGENERATE_EXTRA = {"ps fails": _set_attr("ps_rc", 2)}


class DegenerateInputTests(unittest.TestCase):
    def test_every_degenerate_input_refuses_exactly(self) -> None:
        names = [row[0] for row in DEGENERATE]
        self.assertEqual(len(names), len(set(names)))
        for mode in ("DRY_RUN", "INSTALL", "REMOVE"):
            for name, overrides, mutate, code, message in DEGENERATE:
                with self.subTest(mode=mode, row=name):
                    fake = FakeRunner(allow_changes=mode != "DRY_RUN", euid=0)
                    if mutate is not None:
                        mutate(fake)
                    if name in DEGENERATE_EXTRA:
                        DEGENERATE_EXTRA[name](fake)
                    outcome = tdi.run(argv_for(mode, overrides=overrides), fake, INVOCATION)
                    self.assertEqual((outcome.code, outcome.out, outcome.err), (code, [], [REFUSED + message]))
                    self.assertTrue(set(fake.calls) <= READ_ONLY_CALLS, fake.calls)
                    self.assertNotIn(PLIST, fake.files)

    def test_valid_boundaries_pass(self) -> None:
        for overrides, program_tail in (
            ({"--port": "1"}, "1"),
            ({"--port": "65535"}, "65535"),
            ({"--label": "a" * 128}, PORT),
        ):
            with self.subTest(overrides=overrides):
                fake = FakeRunner(allow_changes=False)
                outcome = tdi.run(argv_for("DRY_RUN", overrides=overrides), fake, INVOCATION)
                self.assertEqual(outcome.code, 0, outcome.err)
                self.assertIn(f"\t\t<string>{program_tail}</string>", outcome.out)

    def test_over_cap_input_is_refused_in_bounded_time(self) -> None:
        fake = FakeRunner(allow_changes=False)
        started = time.monotonic()
        outcome = tdi.run(argv_for("DRY_RUN", overrides={"--postgres-bin": "/" + "a" * 200_000}), fake, INVOCATION)
        self.assertLess(time.monotonic() - started, 1.0)
        self.assertEqual(outcome.err, [REFUSED + "--postgres-bin is longer than 1024 characters"])
        self.assertEqual(fake.calls, [])

    def test_oversized_foreign_plist_is_summarised_without_content(self) -> None:
        fake = fake_for("INSTALL", 0, "ABSENT", "NONE")
        fake.files[PLIST] = b"S3CR3T-CANARY " * 100_000
        fake.loaded = True
        started = time.monotonic()
        outcome = tdi.run(argv_for("INSTALL"), fake, INVOCATION)
        self.assertLess(time.monotonic() - started, 1.0)
        self.assertEqual(
            outcome.err,
            [
                REFUSED
                + f"plist target {PLIST} holds different bytes (found more than 65536 bytes, expected {len(PLIST_BYTES)} bytes);"
                " nothing changed"
            ],
        )

    def test_foreign_plist_content_never_reaches_output(self) -> None:
        canary = b"<plist><string>postgres://user:S3CR3T-CANARY@host/db</string></plist>\n"
        for mode in ("DRY_RUN", "INSTALL", "REMOVE"):
            with self.subTest(mode=mode):
                fake = fake_for(mode, 0, "ABSENT", "NONE")
                fake.files[PLIST] = canary
                fake.loaded = True
                outcome = tdi.run(argv_for(mode), fake, INVOCATION)
                self.assertEqual(outcome.code, 0 if mode == "DRY_RUN" else 4)
                self.assertNotIn("S3CR3T", "\n".join(outcome.out + outcome.err))


CONTROL_CHARACTERS = ["\n", "\r", "\x00", "\t", "\x1b", "\x7f", "\x0b"]
TEXT_FLAGS = {"--postgres-bin": BIN, "--data-dir": DATA, "--account": ACCOUNT, "--label": LABEL, "--port": PORT}


class PlistTests(unittest.TestCase):
    def _config(self, overrides: dict[str, str | None] | None = None, fake: FakeRunner | None = None):
        fake = fake or FakeRunner(allow_changes=False)
        args = tdi.build_parser().parse_args(argv_for("DRY_RUN", overrides=overrides))
        return tdi.parse_config(args, fake)

    def test_plist_round_trips_to_the_hand_written_dict(self) -> None:
        data = tdi.plist_bytes(self._config())
        self.assertEqual(data, PLIST_BYTES)
        self.assertEqual(plistlib.loads(data), EXPECTED_DICT)

    def test_program_arguments_are_a_list_without_a_shell(self) -> None:
        odd_bin = "/opt/tier/bin/post gres;$(x)`y`|z&"
        fake = FakeRunner(allow_changes=False)
        fake.facts[odd_bin] = tdi.Facts(tdi.Kind.FILE, 0, 0o755)
        loaded = plistlib.loads(tdi.plist_bytes(self._config({"--postgres-bin": odd_bin}, fake)))
        self.assertEqual(loaded["ProgramArguments"], [odd_bin, "-D", DATA, "-p", PORT])
        self.assertNotEqual(loaded["UserName"], "root")
        self.assertNotIn("sh", [posixpath.basename(arg) for arg in loaded["ProgramArguments"]])

    def test_control_characters_in_any_value_refuse(self) -> None:
        for flag, good in TEXT_FLAGS.items():
            for char in CONTROL_CHARACTERS:
                for value in (char + good, good[:2] + char + good[2:], good + char):
                    with self.subTest(flag=flag, char=repr(char), value=repr(value)):
                        fake = FakeRunner(allow_changes=False)
                        outcome = tdi.run(argv_for("DRY_RUN", overrides={flag: value}), fake, INVOCATION)
                        self.assertEqual(outcome.code, 2)
                        self.assertEqual(outcome.err, [REFUSED + f"{flag} contains a control character"])
                        self.assertEqual(fake.calls, [])


class HostRunnerGuardTests(unittest.TestCase):
    """The real runner: dry-run instance refuses every change; reads never follow a symlink and are capped."""

    def setUp(self) -> None:
        SCRATCH_BASE.mkdir(parents=True, exist_ok=True)
        self.scratch = SCRATCH_BASE / f"tier-daemon-installer-9853-{os.getpid()}-{self._testMethodName}"
        self.scratch.mkdir()

    def tearDown(self) -> None:
        assert self.scratch.resolve().is_relative_to(SCRATCH_BASE.resolve())
        shutil.rmtree(self.scratch)

    def test_dry_run_runner_refuses_every_change(self) -> None:
        runner = tdi.HostRunner(allow_changes=False)
        target = self.scratch / "would-be.plist"
        existing = self.scratch / "existing.plist"
        existing.write_bytes(b"keep")
        original_run = subprocess.run

        def no_subprocess(*args: object, **kwargs: object) -> None:
            raise AssertionError("a subprocess ran")

        subprocess.run = no_subprocess  # type: ignore[assignment]
        try:
            with self.assertRaises(tdi.ChangesNotAllowed):
                runner.publish_file(str(target), b"data")
            with self.assertRaises(tdi.ChangesNotAllowed):
                runner.remove_file(str(existing))
            for args in (("bootstrap", "system", str(target)), ("bootout", "system/x"), ("enable", "system/x")):
                with self.assertRaises(tdi.ChangesNotAllowed):
                    runner.launchctl(args)
        finally:
            subprocess.run = original_run  # type: ignore[assignment]
        self.assertFalse(target.exists())
        self.assertEqual(existing.read_bytes(), b"keep")
        self.assertEqual(sorted(p.name for p in self.scratch.iterdir()), ["existing.plist"])

    def test_read_file_never_follows_a_symlink(self) -> None:
        real = self.scratch / "real.plist"
        real.write_bytes(PLIST_BYTES)
        link = self.scratch / "link.plist"
        link.symlink_to(real)
        runner = tdi.HostRunner(allow_changes=False)
        with self.assertRaises(tdi.HostError) as caught:
            runner.read_file(str(link), tdi.MAX_PLIST_BYTES)
        self.assertEqual(str(caught.exception), f"open {link}: ELOOP")
        self.assertEqual(runner.lstat(str(link)).kind, tdi.Kind.SYMLINK)
        self.assertEqual(runner.read_file(str(real), tdi.MAX_PLIST_BYTES), PLIST_BYTES)

    def test_read_file_is_capped_and_absent_is_none(self) -> None:
        big = self.scratch / "big"
        big.write_bytes(b"x" * (1 << 20))
        runner = tdi.HostRunner(allow_changes=False)
        self.assertEqual(len(runner.read_file(str(big), tdi.MAX_PLIST_BYTES) or b""), tdi.MAX_PLIST_BYTES + 1)
        self.assertIsNone(runner.read_file(str(self.scratch / "absent"), tdi.MAX_PLIST_BYTES))
        self.assertEqual(runner.lstat(str(self.scratch / "absent")).kind, tdi.Kind.ABSENT)
        self.assertEqual(runner.lstat(str(self.scratch)).kind, tdi.Kind.DIR)

    def test_read_file_refuses_a_directory(self) -> None:
        runner = tdi.HostRunner(allow_changes=False)
        with self.assertRaises(tdi.HostError) as caught:
            runner.read_file(str(self.scratch), tdi.MAX_PLIST_BYTES)
        self.assertIn(str(caught.exception), {f"open {self.scratch}: not a regular file", f"open {self.scratch}: EISDIR"})


class MainWiringTests(unittest.TestCase):
    def test_main_builds_a_change_capable_runner_only_for_install_and_remove(self) -> None:
        built: list[bool] = []

        class Recorder(FakeRunner):
            def __init__(self, allow_changes: bool) -> None:
                super().__init__(allow_changes)
                built.append(allow_changes)
                self.platform_name = "linux"

        original = tdi.HostRunner
        tdi.HostRunner = Recorder
        try:
            for mode, want in (("DRY_RUN", False), ("INSTALL", True), ("REMOVE", True)):
                with self.subTest(mode=mode):
                    err = io.StringIO()
                    with contextlib.redirect_stderr(err), contextlib.redirect_stdout(io.StringIO()):
                        code = tdi.main(argv_for(mode))
                    self.assertEqual(code, tdi.EXIT_PLATFORM)
                    self.assertEqual(built[-1], want)
                    self.assertEqual(err.getvalue(), REFUSED + "this tool runs on macOS only (sys.platform is 'linux')\n")
        finally:
            tdi.HostRunner = original

    def test_exit_codes_are_distinct_named_constants(self) -> None:
        codes = {
            "EXIT_OK": 0,
            "EXIT_USAGE": 2,
            "EXIT_NOT_ROOT": 3,
            "EXIT_CONFLICT": 4,
            "EXIT_POSTMASTER_RUNNING": 5,
            "EXIT_COMMAND_FAILED": 6,
            "EXIT_PROBE_FAILED": 7,
            "EXIT_HANDOVER_TIMEOUT": 8,
            "EXIT_HOST_ERROR": 9,
            "EXIT_PLATFORM": 10,
        }
        self.assertEqual({name: getattr(tdi, name) for name in codes}, codes)


if __name__ == "__main__":
    unittest.main()
