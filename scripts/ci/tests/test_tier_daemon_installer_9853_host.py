# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""Real-body tests for scripts/ci/tier_daemon_installer.py (#9853, PR 9872 round 1, umbrella #8216).

The ``HostRunner`` write path, data-directory read, deadlines, child spawn and output parsing run here as written,
against a fake root under ``<repo>/.local-runs/`` with only the clock, sleep, socket connect, ``fchown``, ``fsync``
and spawn injected (no root, no launchd, no port).  The refusal rows drive ``run`` through the base fake runner; every
expected text is written out by hand.

Run from scripts/ci/tests: python3 -m unittest test_tier_daemon_installer_9853_host
"""

from __future__ import annotations

import errno
import os
import shlex
import shutil
import stat
import subprocess
import unittest
from pathlib import Path
from unittest import mock

import test_tier_daemon_installer_9853 as base

tdi = base.tdi
REFUSED = base.REFUSED
FAILED = base.FAILED
OUT = base.OUT
PLIST = base.PLIST
SERVICE = base.SERVICE
BIN = base.BIN
DATA = base.DATA
LABEL = base.LABEL
AGENT_LABEL = base.AGENT_LABEL
PRINT = base.PRINT
PS = base.PS
WAIT = base.WAIT
PORT_CALL = base.PORT_CALL
BOOTSTRAP = base.BOOTSTRAP
PROBE = base.PROBE
PRINT_DISABLED = base.PRINT_DISABLED

PLIST_NAME = "com.example.pg-tier.plist"
DATA_BYTES = b"<plist>ours</plist>\n"
OTHER_BYTES = b"<plist>someone else's</plist>\n"
PIDFILE_NAME = "postmaster.pid"
PIDFILE_CAP = 4096
SWAPPED_PIDFILE = b"9999\n"
CHILD_ENV_EXPECTED = {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LC_ALL": "C"}
SPAWN_KWARGS_EXPECTED = {
    "capture_output": True,
    "text": True,
    "env": CHILD_ENV_EXPECTED,
    "timeout": 30,
    "check": False,
    "stdin": subprocess.DEVNULL,
}
# A wait that sleeps more than this many times has no deadline.
MAX_SLEEPS = 10_000
HANDOVER_SLEEPS = 300
PROBE_SLEEPS = 120
EXIT_CODES_EXPECTED = {
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
    "EXIT_PORT_IN_USE": 11,
    "EXIT_AGENT_ENABLED": 12,
}


class Scratch(unittest.TestCase):
    """A fresh folder under <repo>/.local-runs per test, removed only when it is under that root."""

    def setUp(self) -> None:
        self.root = base.SCRATCH_BASE / f"tier-daemon-installer-9853-host-{os.getpid()}-{self._testMethodName}"
        self.root.mkdir(parents=True, exist_ok=False)

    def tearDown(self) -> None:
        resolved = self.root.resolve()
        self.assertTrue(resolved.is_relative_to(base.SCRATCH_BASE.resolve()), resolved)
        shutil.rmtree(resolved)


class Recorder:
    """An injected ``fchown`` / ``fsync`` that records its calls and can fail on the n-th one."""

    def __init__(self, fail_on: int | None = None, error: OSError | None = None) -> None:
        self.calls: list[tuple[int, ...]] = []
        self.fail_on = fail_on
        self.error = error

    def __call__(self, *args: int) -> None:
        self.calls.append(args)
        if self.fail_on is not None and len(self.calls) == self.fail_on:
            assert self.error is not None
            raise self.error


def writer(fchown: Recorder | None = None, fsync: Recorder | None = None) -> tdi.HostRunner:
    return tdi.HostRunner(True, fchown=fchown or Recorder(), fsync=fsync or Recorder())


class PublishFileTests(Scratch):
    """The real ``publish_file`` against a fake root (R5, R6, R7 and the three M3 mutants)."""

    def target(self) -> Path:
        return self.root / PLIST_NAME

    def test_new_file_is_written_mode_0644_owner_root_wheel(self) -> None:
        chown = Recorder()
        sync = Recorder()
        writer(chown, sync).publish_file(str(self.target()), DATA_BYTES)
        self.assertEqual(self.target().read_bytes(), DATA_BYTES)
        self.assertEqual(stat.S_IMODE(os.lstat(self.target()).st_mode), 0o644)
        self.assertEqual([call[1:] for call in chown.calls], [(0, 0)])
        self.assertEqual(len(sync.calls), 2)
        self.assertEqual(sorted(os.listdir(self.root)), [PLIST_NAME])

    def test_an_existing_target_is_never_overwritten(self) -> None:
        self.target().write_bytes(OTHER_BYTES)
        with self.assertRaises(FileExistsError) as caught:
            writer().publish_file(str(self.target()), DATA_BYTES)
        self.assertNotIsInstance(caught.exception, tdi.PartialWrite)
        self.assertNotIsInstance(caught.exception, tdi.TempFileExists)
        self.assertEqual(self.target().read_bytes(), OTHER_BYTES)
        self.assertEqual(sorted(os.listdir(self.root)), [PLIST_NAME])

    def test_a_failure_before_the_link_leaves_no_temp_and_no_target(self) -> None:
        rows = [
            ("write", errno.ENOSPC),
            ("fchown", errno.EPERM),
            ("fchmod", errno.EPERM),
            ("fsync", errno.EIO),
        ]
        for step, code in rows:
            with self.subTest(step=step):
                error = OSError(code, step)
                chown = Recorder(1, error) if step == "fchown" else Recorder()
                sync = Recorder(1, error) if step == "fsync" else Recorder()
                runner = writer(chown, sync)
                if step in ("write", "fchmod"):
                    with mock.patch.object(tdi.os, step, side_effect=error):
                        with self.assertRaises(OSError) as caught:
                            runner.publish_file(str(self.target()), DATA_BYTES)
                else:
                    with self.assertRaises(OSError) as caught:
                        runner.publish_file(str(self.target()), DATA_BYTES)
                self.assertEqual(caught.exception.errno, code)
                self.assertNotIsInstance(caught.exception, tdi.PartialWrite)
                self.assertEqual(os.listdir(self.root), [])

    def test_a_dir_fsync_failure_after_the_link_is_a_partial_write(self) -> None:
        sync = Recorder(2, OSError(errno.EIO, "dir fsync"))
        with self.assertRaises(tdi.PartialWrite) as caught:
            writer(fsync=sync).publish_file(str(self.target()), DATA_BYTES)
        self.assertEqual(caught.exception.errno, errno.EIO)
        self.assertEqual(self.target().read_bytes(), DATA_BYTES)
        self.assertEqual(sorted(os.listdir(self.root)), [PLIST_NAME])

    def test_a_symlinked_folder_is_not_followed(self) -> None:
        real = self.root / "real"
        real.mkdir()
        (self.root / "link").symlink_to(real)
        with self.assertRaises(OSError) as caught:
            writer().publish_file(str(self.root / "link" / PLIST_NAME), DATA_BYTES)
        self.assertIn(caught.exception.errno, (errno.ELOOP, errno.ENOTDIR))
        self.assertEqual(os.listdir(real), [])

    def test_a_leftover_temp_file_refuses_and_is_left_alone(self) -> None:
        leftover = self.root / f".{PLIST_NAME}.tmp-{os.getpid()}"
        leftover.write_bytes(OTHER_BYTES)
        with self.assertRaises(tdi.TempFileExists) as caught:
            writer().publish_file(str(self.target()), DATA_BYTES)
        self.assertEqual(caught.exception.errno, errno.EEXIST)
        self.assertEqual(leftover.read_bytes(), OTHER_BYTES)
        self.assertFalse(self.target().exists())

    def test_remove_file_unlinks_and_never_follows_a_symlinked_folder(self) -> None:
        self.target().write_bytes(DATA_BYTES)
        sync = Recorder()
        writer(fsync=sync).remove_file(str(self.target()))
        self.assertEqual(os.listdir(self.root), [])
        self.assertEqual(len(sync.calls), 1)
        real = self.root / "real"
        real.mkdir()
        (real / PLIST_NAME).write_bytes(DATA_BYTES)
        (self.root / "link").symlink_to(real)
        with self.assertRaises(OSError) as caught:
            writer().remove_file(str(self.root / "link" / PLIST_NAME))
        self.assertIn(caught.exception.errno, (errno.ELOOP, errno.ENOTDIR))
        self.assertEqual(os.listdir(real), [PLIST_NAME])


class ReadDataDirTests(Scratch):
    """The data directory and postmaster.pid are checked on the opened object, never re-read by path."""

    def data_dir(self, mode: int = 0o700, pidfile: bytes | None = b"4242\n") -> Path:
        data = self.root / "pgdata"
        data.mkdir()
        if pidfile is not None:
            (data / PIDFILE_NAME).write_bytes(pidfile)
        data.chmod(mode)
        return data

    def test_facts_and_bytes_come_from_the_opened_directory(self) -> None:
        data = self.data_dir()
        facts, got = tdi.HostRunner(False).read_data_dir(str(data), PIDFILE_NAME, PIDFILE_CAP)
        self.assertEqual(facts, tdi.Facts(tdi.Kind.DIR, os.getuid(), 0o700))
        self.assertEqual(got, b"4242\n")

    def test_a_swap_after_the_open_does_not_change_the_answer(self) -> None:
        data = self.data_dir()
        moved = self.root / "moved"
        real_open = os.open
        swapped: list[str] = []

        def swapping_open(path, flags, *args, **kwargs):
            fd = real_open(path, flags, *args, **kwargs)
            if path == str(data) and not swapped:
                os.rename(data, moved)
                data.mkdir(mode=0o755)
                (data / PIDFILE_NAME).write_bytes(SWAPPED_PIDFILE)
                swapped.append(path)
            return fd

        with mock.patch.object(tdi.os, "open", side_effect=swapping_open):
            facts, got = tdi.HostRunner(False).read_data_dir(str(data), PIDFILE_NAME, PIDFILE_CAP)
        self.assertEqual(swapped, [str(data)])
        self.assertEqual(facts, tdi.Facts(tdi.Kind.DIR, os.getuid(), 0o700))
        self.assertEqual(got, b"4242\n")

    def test_a_symlinked_data_dir_reports_the_link(self) -> None:
        data = self.data_dir()
        link = self.root / "link"
        link.symlink_to(data)
        facts, got = tdi.HostRunner(False).read_data_dir(str(link), PIDFILE_NAME, PIDFILE_CAP)
        self.assertIs(facts.kind, tdi.Kind.SYMLINK)
        self.assertIsNone(got)

    def test_a_symlinked_pidfile_is_refused(self) -> None:
        data = self.data_dir(pidfile=None)
        data.chmod(0o700)
        (data / PIDFILE_NAME).symlink_to(self.root / "elsewhere")
        with self.assertRaises(tdi.HostError) as caught:
            tdi.HostRunner(False).read_data_dir(str(data), PIDFILE_NAME, PIDFILE_CAP)
        self.assertEqual(str(caught.exception), f"open {data}/{PIDFILE_NAME}: ELOOP")

    def test_a_fifo_pidfile_is_refused_without_blocking(self) -> None:
        data = self.data_dir(pidfile=None)
        os.mkfifo(data / PIDFILE_NAME)
        with self.assertRaises(tdi.HostError) as caught:
            tdi.HostRunner(False).read_data_dir(str(data), PIDFILE_NAME, PIDFILE_CAP)
        self.assertEqual(str(caught.exception), f"open {data}/{PIDFILE_NAME}: not a regular file")

    def test_absent_directory_absent_pidfile_and_the_cap(self) -> None:
        runner = tdi.HostRunner(False)
        self.assertEqual(runner.read_data_dir(str(self.root / "none"), PIDFILE_NAME, PIDFILE_CAP), (tdi.Facts(tdi.Kind.ABSENT), None))
        data = self.data_dir(pidfile=None)
        self.assertEqual(runner.read_data_dir(str(data), PIDFILE_NAME, PIDFILE_CAP)[1], None)
        (data / PIDFILE_NAME).write_bytes(b"7" * (PIDFILE_CAP * 4))
        self.assertEqual(len(runner.read_data_dir(str(data), PIDFILE_NAME, PIDFILE_CAP)[1]), PIDFILE_CAP + 1)


class FakeClock:
    """A monotonic clock that only ``sleep`` moves; more than MAX_SLEEPS sleeps means the wait has no deadline."""

    def __init__(self) -> None:
        self.now = 0.0
        self.sleeps: list[float] = []

    def clock(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds)
        if len(self.sleeps) > MAX_SLEEPS:
            raise AssertionError("unbounded wait: no deadline")
        self.now += seconds


class Spawn:
    """An injected spawn: scripted (rc, stdout) answers in order, every call recorded with its keyword arguments."""

    def __init__(self, *answers: tuple[int, str] | BaseException) -> None:
        self.answers = list(answers)
        self.calls: list[tuple[list[str], dict[str, object]]] = []

    def __call__(self, argv: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        self.calls.append((argv, kwargs))
        answer = self.answers.pop(0) if len(self.answers) > 1 else self.answers[0]
        if isinstance(answer, BaseException):
            raise answer
        rc, stdout = answer
        return subprocess.CompletedProcess(argv, rc, stdout, "")


class Connection:
    def __enter__(self) -> Connection:
        return self

    def __exit__(self, *exc: object) -> None:
        return None


class Connect:
    """An injected ``socket.create_connection``: refuse ``refusals`` times, then accept (or raise ``error``)."""

    def __init__(self, refusals: int, error: OSError | None = None) -> None:
        self.refusals = refusals
        self.error = error
        self.calls: list[tuple[object, dict[str, object]]] = []

    def __call__(self, address: object, **kwargs: object) -> Connection:
        self.calls.append((address, kwargs))
        if self.error is not None:
            raise self.error
        if len(self.calls) <= self.refusals:
            raise ConnectionRefusedError(errno.ECONNREFUSED, "refused")
        return Connection()


class ChildAndDeadlineTests(unittest.TestCase):
    """The real spawn wrapper, parsers and deadline loops (R3, R4, R12)."""

    def test_every_child_gets_the_fixed_env_a_timeout_and_no_stdin(self) -> None:
        spawn = Spawn((0, ""))
        self.assertTrue(tdi.HostRunner(False, spawn=spawn).service_loaded(SERVICE))
        self.assertEqual(spawn.calls, [(["/bin/launchctl", "print", SERVICE], SPAWN_KWARGS_EXPECTED)])

    def test_spawn_errors_are_host_errors_with_their_kind(self) -> None:
        rows = [
            (FileNotFoundError(errno.ENOENT, "no launchctl"), "/bin/launchctl print: FileNotFoundError"),
            (subprocess.TimeoutExpired(["/bin/launchctl"], 30), "/bin/launchctl print: TimeoutExpired"),
        ]
        for error, text in rows:
            with self.subTest(text=text):
                with self.assertRaises(tdi.HostError) as caught:
                    tdi.HostRunner(False, spawn=Spawn(error)).service_loaded(SERVICE)
                self.assertEqual(str(caught.exception), text)

    def test_service_loaded_rows(self) -> None:
        self.assertTrue(tdi.HostRunner(False, spawn=Spawn((0, ""))).service_loaded(SERVICE))
        self.assertFalse(tdi.HostRunner(False, spawn=Spawn((113, ""))).service_loaded(SERVICE))
        with self.assertRaises(tdi.HostError) as caught:
            tdi.HostRunner(False, spawn=Spawn((5, ""))).service_loaded(SERVICE)
        self.assertEqual(str(caught.exception), f"/bin/launchctl print {SERVICE} exited 5")

    def test_launchd_pid_rows(self) -> None:
        good = [
            ((113, ""), None),
            ((0, "system/x = {\n\tstate = running\n}\n"), None),
            ((0, "x = {\n\tpid = 5151\n}\n"), 5151),
            ((0, "x = {\n\tpid = 2147483647\n\t\tpid = 7\n}\n"), 2147483647),
        ]
        for answer, want in good:
            with self.subTest(answer=answer):
                self.assertEqual(tdi.HostRunner(False, spawn=Spawn(answer)).launchd_pid(SERVICE), want)
        bad = [
            ((5, ""), f"/bin/launchctl print {SERVICE} exited 5"),
            ((0, "\tpid = 1\n\tpid = 2\n"), f"/bin/launchctl print {SERVICE} reports 2 pid lines"),
            ((0, "\tpid = 0\n"), f"/bin/launchctl print {SERVICE} reports pid 0"),
            ((0, "\tpid = 2147483648\n"), f"/bin/launchctl print {SERVICE} reports pid 2147483648"),
        ]
        for answer, text in bad:
            with self.subTest(answer=answer):
                with self.assertRaises(tdi.HostError) as caught:
                    tdi.HostRunner(False, spawn=Spawn(answer)).launchd_pid(SERVICE)
                self.assertEqual(str(caught.exception), text)

    def test_agent_disabled_rows(self) -> None:
        def listing(*entries: str) -> tuple[int, str]:
            return 0, "disabled services = {\n" + "".join(f"\t{entry}\n" for entry in entries) + "}\n"

        rows = [
            (listing(f'"{AGENT_LABEL}" => disabled'), True),
            (listing(f'"{AGENT_LABEL}" => true'), True),
            (listing(f'"{AGENT_LABEL}" => enabled'), False),
            (listing(f'"{AGENT_LABEL}" => false'), False),
            (listing('"com.example.other" => disabled'), False),
            (listing(f'"{AGENT_LABEL}x" => disabled'), False),
            (listing(), False),
        ]
        for answer, want in rows:
            with self.subTest(answer=answer):
                self.assertIs(tdi.HostRunner(False, spawn=Spawn(answer)).agent_disabled(501, AGENT_LABEL), want)
        bad = [
            ((3, ""), "/bin/launchctl print-disabled user/501 exited 3"),
            (
                listing(f'"{AGENT_LABEL}" => disabled', f'"{AGENT_LABEL}" => enabled'),
                f"/bin/launchctl print-disabled user/501 lists {AGENT_LABEL} 2 times",
            ),
        ]
        for answer, text in bad:
            with self.subTest(answer=answer):
                with self.assertRaises(tdi.HostError) as caught:
                    tdi.HostRunner(False, spawn=Spawn(answer)).agent_disabled(501, AGENT_LABEL)
                self.assertEqual(str(caught.exception), text)

    def test_pid_alive_rows(self) -> None:
        self.assertTrue(tdi.HostRunner(False, spawn=Spawn((0, "  4242\n"))).pid_alive(4242))
        self.assertFalse(tdi.HostRunner(False, spawn=Spawn((1, ""))).pid_alive(4242))
        for answer in ((0, "4243\n"), (2, ""), (1, "4242\n")):
            with self.subTest(answer=answer):
                with self.assertRaises(tdi.HostError) as caught:
                    tdi.HostRunner(False, spawn=Spawn(answer)).pid_alive(4242)
                self.assertEqual(str(caught.exception), f"/bin/ps -p 4242 exited {answer[0]}")

    def test_wait_pid_exit_has_a_deadline(self) -> None:
        clock = FakeClock()
        spawn = Spawn((0, "4242\n"))
        runner = tdi.HostRunner(False, clock=clock.clock, sleep=clock.sleep, spawn=spawn)
        self.assertFalse(runner.wait_pid_exit(4242, 300))
        self.assertEqual(clock.sleeps, [1.0] * HANDOVER_SLEEPS)
        self.assertEqual(len(spawn.calls), HANDOVER_SLEEPS + 1)

    def test_wait_pid_exit_returns_when_the_pid_exits(self) -> None:
        clock = FakeClock()
        spawn = Spawn((0, "4242\n"), (0, "4242\n"), (1, ""))
        runner = tdi.HostRunner(False, clock=clock.clock, sleep=clock.sleep, spawn=spawn)
        self.assertTrue(runner.wait_pid_exit(4242, 300))
        self.assertEqual(clock.sleeps, [1.0, 1.0])

    def test_probe_port_has_a_deadline(self) -> None:
        clock = FakeClock()
        connect = Connect(refusals=MAX_SLEEPS * 2)
        runner = tdi.HostRunner(False, clock=clock.clock, sleep=clock.sleep, connect=connect)
        self.assertFalse(runner.probe_port(5445, 60))
        self.assertEqual(clock.sleeps, [0.5] * PROBE_SLEEPS)
        self.assertEqual(connect.calls[0], (("127.0.0.1", 5445), {"timeout": 2.0}))

    def test_probe_port_answers(self) -> None:
        clock = FakeClock()
        connect = Connect(refusals=2)
        runner = tdi.HostRunner(False, clock=clock.clock, sleep=clock.sleep, connect=connect)
        self.assertTrue(runner.probe_port(5445, 60))
        self.assertEqual(clock.sleeps, [0.5, 0.5])

    def test_port_in_use_rows(self) -> None:
        self.assertFalse(tdi.HostRunner(False, connect=Connect(refusals=1)).port_in_use(5445))
        connect = Connect(refusals=0)
        self.assertTrue(tdi.HostRunner(False, connect=connect).port_in_use(5445))
        self.assertEqual(connect.calls, [(("127.0.0.1", 5445), {"timeout": 2.0})])
        rows = [
            (OSError(errno.EHOSTUNREACH, "unreachable"), "connect 127.0.0.1:5445: EHOSTUNREACH"),
            (TimeoutError("timed out"), "connect 127.0.0.1:5445: TimeoutError"),
        ]
        for error, text in rows:
            with self.subTest(text=text):
                with self.assertRaises(tdi.HostError) as caught:
                    tdi.HostRunner(False, connect=Connect(0, error)).port_in_use(5445)
                self.assertEqual(str(caught.exception), text)


def run_fake(fake: base.FakeRunner, argv: list[str]) -> tuple[int, list[str], list[str], list[tuple[object, ...]]]:
    outcome = tdi.run(argv, fake, base.INVOCATION)
    return outcome.code, outcome.out, outcome.err, fake.calls


def refused(text: str, code: int = 2) -> tuple[int, list[str], list[str], list[tuple[object, ...]]]:
    return code, [], [REFUSED + text], []


# (name, character, exact refusal for --data-dir); written out by hand from the Unicode categories.
TEXT_ROWS = [
    ("RLO bidi override", "‮", "--data-dir contains U+202E (category Cf), which is refused"),
    ("LRI bidi isolate", "⁦", "--data-dir contains U+2066 (category Cf), which is refused"),
    ("zero width space", "​", "--data-dir contains U+200B (category Cf), which is refused"),
    ("byte order mark", "﻿", "--data-dir contains U+FEFF (category Cf), which is refused"),
    ("line separator", " ", "--data-dir contains U+2028 (category Zl), which is refused"),
    ("paragraph separator", " ", "--data-dir contains U+2029 (category Zp), which is refused"),
    ("U+FFFE", "￾", "--data-dir contains the noncharacter U+FFFE, which is refused"),
    ("U+FFFF", "￿", "--data-dir contains the noncharacter U+FFFF, which is refused"),
    ("U+FDD0", "﷐", "--data-dir contains the noncharacter U+FDD0, which is refused"),
    ("U+FDEF", "﷯", "--data-dir contains the noncharacter U+FDEF, which is refused"),
    ("U+1FFFE", "\U0001fffe", "--data-dir contains the noncharacter U+1FFFE, which is refused"),
    ("U+10FFFF", "\U0010ffff", "--data-dir contains the noncharacter U+10FFFF, which is refused"),
    ("C1 NEL", "\x85", "--data-dir contains a control character"),
    ("C1 CSI", "\x9b", "--data-dir contains a control character"),
    ("DEL", "\x7f", "--data-dir contains a control character"),
    ("NUL", "\x00", "--data-dir contains a control character"),
    ("lone surrogate", "\udcff", "--data-dir is not valid UTF-8"),
]
# Characters next to the refused ranges that are ordinary text.
TEXT_ALLOWED = ["﷏", "ﷰ", "�", "é", "日"]


def fake_with_data(mode: str, data_dir: str) -> base.FakeRunner:
    fake = base.fake_for(mode, 0, "ABSENT", "NONE")
    fake.facts[data_dir] = tdi.Facts(tdi.Kind.DIR, base.ACCOUNT_UID, 0o700)
    return fake


def _facts(path: str, kind: tdi.Kind, uid: int = 0, mode: int = 0o755):
    def apply(fake: base.FakeRunner) -> None:
        fake.facts[path] = tdi.Facts(kind, uid, mode)

    return apply


def _absent(path: str):
    def apply(fake: base.FakeRunner) -> None:
        fake.facts.pop(path)

    return apply


PARENT = "--postgres-bin /opt/tier/bin/postgres: parent folder"
PLIST_DIR = "launchd directory /Library/LaunchDaemons has parent folder {parent} that is not a root-owned directory closed to group and others"
# (name, change to the fake, overrides, exact refusal text, exit code)
HOST_ROWS = [
    ("bin parent owned by a stranger", _facts("/opt/tier", tdi.Kind.DIR, 777), {},
     f"{PARENT} /opt/tier is owned by uid 777, not by root or pgtier", 2),
    ("bin parent group writable", _facts("/opt/tier/bin", tdi.Kind.DIR, 0, 0o775), {},
     f"{PARENT} /opt/tier/bin is writable by group or others", 2),
    ("bin parent world writable", _facts("/opt/tier/bin", tdi.Kind.DIR, 0, 0o757), {},
     f"{PARENT} /opt/tier/bin is writable by group or others", 2),
    ("bin parent missing", _absent("/opt"), {}, f"{PARENT} /opt does not exist", 2),
    ("bin parent is a symlink", _facts("/opt/tier", tdi.Kind.SYMLINK), {}, f"{PARENT} /opt/tier is a symlink", 2),
    ("bin parent is a file", _facts("/opt/tier/bin", tdi.Kind.FILE), {}, f"{PARENT} /opt/tier/bin is not a directory", 2),
    ("bin parent is a fifo", _facts("/opt/tier/bin", tdi.Kind.OTHER), {}, f"{PARENT} /opt/tier/bin is not a directory", 2),
    ("root folder group writable", _facts("/", tdi.Kind.DIR, 0, 0o775), {},
     f"{PARENT} / is writable by group or others", 2),
    ("bin owned by a stranger", _facts(BIN, tdi.Kind.FILE, 777), {},
     "--postgres-bin /opt/tier/bin/postgres is owned by uid 777, not by root or pgtier (uid 501)", 2),
    ("data parent world writable",
     lambda fake: (_facts("/srv", tdi.Kind.DIR, 0, 0o777)(fake), _facts("/srv/pgdata", tdi.Kind.DIR, 501, 0o700)(fake)),
     {"--data-dir": "/srv/pgdata"}, "--data-dir /srv/pgdata: parent folder /srv is writable by group or others", 2),
    ("data parent owned by a stranger",
     lambda fake: (_facts("/srv", tdi.Kind.DIR, 777)(fake), _facts("/srv/pgdata", tdi.Kind.DIR, 501, 0o700)(fake)),
     {"--data-dir": "/srv/pgdata"}, "--data-dir /srv/pgdata: parent folder /srv is owned by uid 777, not by root or pgtier", 2),
    ("launchd dir parent owned by the account", _facts("/Library", tdi.Kind.DIR, 501), {},
     PLIST_DIR.format(parent="/Library"), 9),
    ("launchd dir parent group writable", _facts("/Library", tdi.Kind.DIR, 0, 0o775), {},
     PLIST_DIR.format(parent="/Library"), 9),
    ("launchd dir parent is a symlink", _facts("/Library", tdi.Kind.SYMLINK), {},
     PLIST_DIR.format(parent="/Library"), 9),
    ("root folder owned by the account (launchd dir)",
     lambda fake: _facts("/", tdi.Kind.DIR, 501)(fake), {}, PLIST_DIR.format(parent="/"), 9),
]
# Owners the parent check accepts: root and the account itself.
HOST_ALLOWED = [
    ("bin parent owned by the account", _facts("/opt/tier/bin", tdi.Kind.DIR, 501)),
    ("bin owned by the account", _facts(BIN, tdi.Kind.FILE, 501)),
]
LABEL_128 = "a" * 128
LABEL_129 = "a" * 129
VALID_LABEL = "(letters, digits, '.', '_', '-'; 128 at most)"
# (name, extra argv, exact refusal)
AGENT_ROWS = [
    ("--handover without --agent-label", ["--handover"],
     "--handover needs --agent-label, the label of the interim login agent to be disabled"),
    ("--agent-label without --handover", [f"--agent-label={AGENT_LABEL}"], "--agent-label goes with --handover only"),
    ("--agent-label empty", ["--handover", "--agent-label="], "--agent-label is empty"),
    ("--agent-label with a space", ["--handover", "--agent-label=bad label"],
     f"--agent-label 'bad label' is not a valid launchd label {VALID_LABEL}"),
    ("--agent-label with a slash", ["--handover", "--agent-label=gui/501/x"],
     f"--agent-label 'gui/501/x' is not a valid launchd label {VALID_LABEL}"),
    ("--agent-label 129 characters", ["--handover", f"--agent-label={LABEL_129}"],
     f"--agent-label {LABEL_129!r} is not a valid launchd label {VALID_LABEL}"),
    ("--agent-label with a bidi override", ["--handover", "--agent-label=a‮b"],
     "--agent-label contains U+202E (category Cf), which is refused"),
]
# Path values that a shell would split or expand; every printed command must carry each as one argument.
HOSTILE_DATA_DIRS = [
    "/opt/tier/pg data",
    "/opt/tier/pg;touch x",
    "/opt/tier/$(id)",
    "/opt/tier/it's",
    "/opt/tier/`id`",
    "/opt/tier/a|b&c>d",
]
INSTALL_HEADER = "install, in order (as root: sudo "
INSTALL_TAIL = " --install):"
UNDO_HEAD = "undo: sudo "


def host_argv(data_dir: str) -> list[str]:
    return [
        "python3", "scripts/ci/tier_daemon_installer.py", "--postgres-bin", BIN, "--data-dir", data_dir,
        "--account", "pgtier", "--label", LABEL, "--port", "5445",
    ]


class RefusalRowTests(unittest.TestCase):
    """Every new refusal through ``run``: the exact text, the exit code and no command reached."""

    def test_text_check_refuses_each_form(self) -> None:
        for name, char, text in TEXT_ROWS:
            for mode in ("DRY_RUN", "INSTALL"):
                with self.subTest(row=name, mode=mode):
                    fake = base.fake_for(mode, 0, "ABSENT", "NONE")
                    got = run_fake(fake, base.argv_for(mode, overrides={"--data-dir": f"/opt/tier/pg{char}data"}))
                    self.assertEqual(got, refused(text))

    def test_text_check_allows_the_neighbours(self) -> None:
        for char in TEXT_ALLOWED:
            with self.subTest(code=f"U+{ord(char):04X}"):
                data_dir = f"/opt/tier/pg{char}data"
                code, _, err, _ = run_fake(fake_with_data("DRY_RUN", data_dir), base.argv_for("DRY_RUN", overrides={"--data-dir": data_dir}))
                self.assertEqual((code, err), (0, []))

    def test_host_rows_refuse_exactly(self) -> None:
        for name, change, overrides, text, code in HOST_ROWS:
            for mode in ("DRY_RUN", "INSTALL", "REMOVE"):
                with self.subTest(row=name, mode=mode):
                    fake = base.fake_for(mode, 0, "ABSENT", "NONE")
                    change(fake)
                    self.assertEqual(run_fake(fake, base.argv_for(mode, overrides=overrides)), refused(text, code))

    def test_host_rows_allow_root_and_the_account(self) -> None:
        for name, change in HOST_ALLOWED:
            with self.subTest(row=name):
                fake = base.fake_for("DRY_RUN", 0, "ABSENT", "NONE")
                change(fake)
                code, _, err, _ = run_fake(fake, base.argv_for("DRY_RUN"))
                self.assertEqual((code, err), (0, []))

    def test_agent_label_rows(self) -> None:
        for name, extra, text in AGENT_ROWS:
            for mode in ("DRY_RUN", "INSTALL"):
                with self.subTest(row=name, mode=mode):
                    fake = base.fake_for(mode, 0, "ABSENT", "ALIVE")
                    self.assertEqual(run_fake(fake, base.argv_for(mode) + extra), refused(text))

    def test_agent_label_of_128_characters_is_accepted(self) -> None:
        fake = base.fake_for("DRY_RUN", 0, "ABSENT", "ALIVE")
        code, out, err, _ = run_fake(fake, base.argv_for("DRY_RUN") + ["--handover", f"--agent-label={LABEL_128}"])
        self.assertEqual((code, err), (0, []))
        self.assertIn(f"  a. disable the interim login agent persistently: /bin/launchctl disable gui/501/{LABEL_128}", out)

    def test_plist_that_does_not_read_back_is_refused(self) -> None:
        text = "the plist for these arguments does not read back as written; nothing changed"
        patches = [
            mock.patch.object(tdi.plistlib, "loads", return_value={}),
            mock.patch.object(tdi.plistlib, "loads", side_effect=ValueError("bad")),
            mock.patch.object(tdi.plistlib, "dumps", side_effect=TypeError("bad")),
        ]
        for number, patch in enumerate(patches):
            for mode in ("DRY_RUN", "INSTALL"):
                with self.subTest(patch=number, mode=mode), patch:
                    fake = base.fake_for(mode, 0, "ABSENT", "NONE")
                    self.assertEqual(run_fake(fake, base.argv_for(mode)), refused(text))
                    self.assertNotIn(PLIST, fake.files)

    def test_exit_codes_are_the_documented_set(self) -> None:
        found = {name: value for name, value in vars(tdi).items() if name.startswith("EXIT_") and name != "EXIT_TIMEOUT_SECONDS"}
        self.assertEqual(found, EXIT_CODES_EXPECTED)


class CommandQuotingTests(unittest.TestCase):
    """No printed command is built by joining unquoted text; the root command is absolute and isolated."""

    def test_invocation_is_isolated_and_absolute(self) -> None:
        got = tdi.invocation_for("/opt/homebrew/bin/python3.12", "scripts/ci/tier_daemon_installer.py")
        self.assertEqual(got[:2], ["/opt/homebrew/bin/python3.12", "-I"])
        self.assertEqual(got[2], str((Path.cwd() / "scripts/ci/tier_daemon_installer.py").resolve()))
        self.assertTrue(got[2].startswith("/"))

    def test_main_prints_an_isolated_absolute_command(self) -> None:
        runner = base.fake_for("DRY_RUN", 501, "ABSENT", "NONE")
        seen: list[list[str]] = []

        def fake_run(argv, given_runner, invocation):
            seen.append(invocation)
            return tdi.Outcome()

        with mock.patch.object(tdi, "run", side_effect=fake_run), mock.patch.object(tdi, "HostRunner", return_value=runner):
            self.assertEqual(tdi.main(base.argv_for("DRY_RUN")), 0)
        self.assertEqual(seen, [[tdi.sys.executable, "-I", str(Path(tdi.__file__).resolve())]])

    def test_space_in_the_data_dir_is_quoted_in_every_printed_line(self) -> None:
        data_dir = "/opt/tier/pg data"
        code, out, _, _ = run_fake(fake_with_data("DRY_RUN", data_dir), base.argv_for("DRY_RUN", overrides={"--data-dir": data_dir}))
        self.assertEqual(code, 0)
        command = (
            "python3 scripts/ci/tier_daemon_installer.py --postgres-bin /opt/tier/bin/postgres "
            "--data-dir '/opt/tier/pg data' --account pgtier --label com.example.pg-tier --port 5445"
        )
        self.assertIn(f"install, in order (as root: sudo {command} --install):", out)
        self.assertIn(
            "  c. if the postmaster still runs, stop it cleanly as pgtier: "
            "/opt/tier/bin/pg_ctl -D '/opt/tier/pg data' stop -m fast",
            out,
        )
        self.assertIn(
            f"  5. verify that the pid launchd reports for {SERVICE} is the first line of "
            "'/opt/tier/pg data/postmaster.pid'; only then print installed",
            out,
        )

    def test_every_printed_command_splits_back_to_its_arguments(self) -> None:
        for data_dir in HOSTILE_DATA_DIRS:
            with self.subTest(data_dir=data_dir):
                code, out, _, _ = run_fake(
                    fake_with_data("DRY_RUN", data_dir), base.argv_for("DRY_RUN", overrides={"--data-dir": data_dir})
                )
                self.assertEqual(code, 0)
                header = [line for line in out if line.startswith(INSTALL_HEADER)]
                self.assertEqual(len(header), 1)
                self.assertTrue(header[0].endswith(INSTALL_TAIL))
                command = header[0][len(INSTALL_HEADER) : -len(INSTALL_TAIL)]
                self.assertEqual(shlex.split(command), host_argv(data_dir))
                stop = [line for line in out if line.startswith("  c. ")]
                self.assertEqual(
                    shlex.split(stop[0].split(": ", 1)[1]),
                    ["/opt/tier/bin/pg_ctl", "-D", data_dir, "stop", "-m", "fast"],
                )
                fake = fake_with_data("INSTALL", data_dir)
                fake.launchctl_rc["bootstrap"] = 5
                code, _, err, _ = run_fake(fake, base.argv_for("INSTALL", overrides={"--data-dir": data_dir}))
                self.assertEqual(code, 6)
                self.assertTrue(err[-1].startswith(UNDO_HEAD), err)
                self.assertEqual(shlex.split(err[-1][len(UNDO_HEAD) :]), [*host_argv(data_dir), "--remove"])


class HandoverIdenticalTests(unittest.TestCase):
    """A hand-over onto an identical, unloaded plist bootstraps it and never writes (R2)."""

    def test_identical_unloaded_plist_hand_over_does_not_write(self) -> None:
        fake = base.fake_for("INSTALL", 0, "IDENTICAL", "ALIVE", loaded=False)
        got = run_fake(fake, base.argv_for("INSTALL", handover=True))
        self.assertEqual(
            got,
            (
                0,
                [
                    OUT + "--install: hand-over: wait up to 300 s for pid 4242 to exit, then agent check, port check, "
                    "bootstrap, probe, verify",
                    "postmaster pid 4242 exited",
                    f"login agent {base.AGENT_TARGET} is disabled",
                    "127.0.0.1:5445 is free",
                    f"bootstrapped {SERVICE}",
                    "127.0.0.1:5445 answers",
                    f"launchd pid 5151 of {SERVICE} owns /opt/tier/pgdata and 127.0.0.1:5445; installed",
                ],
                [],
                [PRINT, PS, WAIT, PS, PRINT_DISABLED, PORT_CALL, BOOTSTRAP, PROBE, PRINT],
            ),
        )

    def test_identical_unloaded_plist_with_a_live_postmaster_needs_handover(self) -> None:
        fake = base.fake_for("INSTALL", 0, "IDENTICAL", "ALIVE", loaded=False)
        self.assertEqual(
            run_fake(fake, base.argv_for("INSTALL")),
            (
                5,
                [],
                [REFUSED + "postmaster pid 4242 holds /opt/tier/pgdata; nothing changed; stop its supervisor, then pass --handover"],
                [PRINT, PS],
            ),
        )


if __name__ == "__main__":
    unittest.main()
