# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""Round-1 invariant tables for scripts/ci/tier_daemon_installer.py (#9853, PR 9872, umbrella #8216).

Class A (message from state): ``installed`` is printed only when the tool has proven, at that moment, that the port
was free before bootstrap, the readiness probe answered and the pid launchd started is the first line of
postmaster.pid.  Every other state prints its own exact reason and a non-success exit code.

Class B (failure kind): a failure after the first change to the host is never reported as ``refused: host probe
failed``; it says what was changed, the state left behind and an undo step that is true for that state.  A write that
loses the no-clobber race changes nothing and advises no removal.

Every row drives ``run`` through an injected runner (no launchd, no root, no real port); the expected column is
written out by hand.  Run from scripts/ci/tests: python3 -m unittest test_tier_daemon_installer_9853_r1
"""

from __future__ import annotations

import errno
import subprocess
import unittest

import test_tier_daemon_installer_9853 as base

tdi = base.tdi
PLIST = base.PLIST
SERVICE = base.SERVICE
PIDFILE = base.PIDFILE
CMD = base.CMD
OUT = base.OUT
REFUSED = base.REFUSED
FAILED = base.FAILED
PRINT = base.PRINT
PUBLISH = base.PUBLISH
BOOTSTRAP = base.BOOTSTRAP
PROBE = base.PROBE
BOOTOUT = base.BOOTOUT
REMOVE = base.REMOVE
PORT = ("port", 5445)
LAUNCHD_PID = 5151
OTHER_PID = 6262
HOST_TIMEOUT = "TimeoutExpired"

PROCEED = OUT + "--install: proceed: port check, write, bootstrap, probe, verify"
FREE = "127.0.0.1:5445 is free"
WROTE = f"wrote {PLIST} (mode 0644, owner root:wheel)"
BOOTSTRAPPED = f"bootstrapped {SERVICE}"
ANSWERS = "127.0.0.1:5445 answers"
INSTALLED = f"launchd pid 5151 of {SERVICE} owns /opt/tier/pgdata and 127.0.0.1:5445; installed"
UNDO_REMOVE = f"undo: sudo {CMD} --remove"
FINISH_REMOVAL = f"to finish the removal: sudo {CMD} --remove"
STATE_PRESENT_NOT_LOADED = f"state: plist {PLIST} present; service {SERVICE} not loaded"
STATE_PRESENT_LOADED = f"state: plist {PLIST} present; service {SERVICE} loaded"
STATE_ABSENT_NOT_LOADED = f"state: plist {PLIST} absent; service {SERVICE} not loaded"
REMOVE_PROCEED = OUT + "--remove: proceed: bootout, remove plist"


class R1Fake(base.FakeRunner):
    """The base fake plus a port, the pid launchd reports, the pid file postgres writes and injected host errors."""

    def __init__(self, allow_changes: bool = True, euid: int = 0) -> None:
        super().__init__(allow_changes, euid)
        self.port_taken = False
        self.launchd_pid_value: int | None = None
        self.started_pid: int | None = LAUNCHD_PID
        self.pidfile_pid: int | None = LAUNCHD_PID
        self.raise_from: dict[str, int] = {}
        self.verb_calls: dict[str, int] = {}

    def port_in_use(self, port: int) -> bool:
        self.calls.append(("port", port))
        return self.port_taken

    def read_data_dir(self, path: str, name: str, limit: int):
        data = self.files.get(f"{path}/{name}")
        return self.facts.get(path, tdi.Facts(tdi.Kind.ABSENT)), None if data is None else data[: limit + 1]

    def _run(self, argv: list[str]) -> subprocess.CompletedProcess[str]:
        verb = argv[1] if argv[0] == tdi.LAUNCHCTL else argv[0]
        count = self.verb_calls.get(verb, 0) + 1
        self.verb_calls[verb] = count
        if verb in self.raise_from and count >= self.raise_from[verb]:
            self.calls.append(tuple(argv))
            raise tdi.HostError(f"{argv[0]} {argv[1]}: {HOST_TIMEOUT}")
        if verb == "print":
            self.calls.append(tuple(argv))
            rc = self.print_rc if self.print_rc is not None else (0 if self.loaded else 113)
            pid_line = f"\tpid = {self.launchd_pid_value}\n" if self.loaded and self.launchd_pid_value else ""
            return subprocess.CompletedProcess(argv, rc, "system = {\n" + pid_line + "}\n", "")
        result = super()._run(argv)
        if verb == "bootstrap" and result.returncode == 0:
            self.launchd_pid_value = self.started_pid
            if self.pidfile_pid is not None:
                self.files[PIDFILE] = base.pidfile_text(self.pidfile_pid)
        return result


def absent_fake() -> R1Fake:
    return R1Fake()


def loaded_fake() -> R1Fake:
    fake = R1Fake()
    fake.files[PLIST] = base.PLIST_BYTES
    fake.loaded = True
    return fake


def _port_taken(fake: R1Fake) -> None:
    fake.port_taken = True


def _bootstrap_refused(fake: R1Fake) -> None:
    fake.launchctl_rc["bootstrap"] = 5


def _bootstrap_host_error(fake: R1Fake) -> None:
    fake.raise_from["bootstrap"] = 1


def _probe_timeout(fake: R1Fake) -> None:
    fake.probe_result = False


def _pid_mismatch(fake: R1Fake) -> None:
    fake.pidfile_pid = OTHER_PID


def _no_launchd_pid(fake: R1Fake) -> None:
    fake.started_pid = None


def _no_pidfile(fake: R1Fake) -> None:
    fake.pidfile_pid = None


def _verify_host_error(fake: R1Fake) -> None:
    fake.raise_from["print"] = 2


def _write_denied(fake: R1Fake) -> None:
    fake.publish_error = PermissionError(errno.EACCES, "denied")


def _write_race(fake: R1Fake) -> None:
    fake.publish_error = FileExistsError(errno.EEXIST, "exists")


def _write_after_link(fake: R1Fake) -> None:
    fake.publish_error = getattr(tdi, "PartialWrite", OSError)(errno.EIO, "io")


def _bootout_refused(fake: R1Fake) -> None:
    fake.launchctl_rc["bootout"] = 5


def _bootout_host_error(fake: R1Fake) -> None:
    fake.raise_from["bootout"] = 1


def _remove_denied(fake: R1Fake) -> None:
    fake.remove_error = PermissionError(errno.EACCES, "denied")


def _all_good(fake: R1Fake) -> None:
    del fake


VERIFY_HOST_STATE = f"state: plist {PLIST} present; service {SERVICE} unknown (/bin/launchctl print: {HOST_TIMEOUT})"

# Class A: --install from an absent plist, one row per state of the install proof.
# (name, inject, exit code, stdout, stderr, commands, plist left, loaded left)
CLASS_A = [
    ("all good", _all_good, 0, [PROCEED, FREE, WROTE, BOOTSTRAPPED, ANSWERS, INSTALLED], [],
     [PRINT, PORT, PUBLISH, BOOTSTRAP, PROBE, PRINT, PRINT], True, True),
    ("port taken by another process", _port_taken, 11, [PROCEED],
     [REFUSED + "127.0.0.1:5445 already answers before bootstrap; another process holds the port; nothing changed"],
     [PRINT, PORT], False, False),
    ("bootstrap refused", _bootstrap_refused, 6, [PROCEED, FREE, WROTE],
     [FAILED + f"/bin/launchctl bootstrap system {PLIST} exited 5", f"changed: wrote {PLIST}",
      STATE_PRESENT_NOT_LOADED, UNDO_REMOVE],
     [PRINT, PORT, PUBLISH, BOOTSTRAP, PRINT], True, False),
    ("probe timeout", _probe_timeout, 7, [PROCEED, FREE, WROTE, BOOTSTRAPPED],
     [FAILED + "127.0.0.1:5445 did not answer within 60 s", f"changed: wrote {PLIST}; bootstrapped {SERVICE}",
      STATE_PRESENT_LOADED, UNDO_REMOVE],
     [PRINT, PORT, PUBLISH, BOOTSTRAP, PROBE, PRINT], True, True),
    ("pid mismatch", _pid_mismatch, 7, [PROCEED, FREE, WROTE, BOOTSTRAPPED, ANSWERS],
     [FAILED + f"launchd pid 5151 of {SERVICE} is not the postmaster pid 6262 in {PIDFILE}",
      f"changed: wrote {PLIST}; bootstrapped {SERVICE}", STATE_PRESENT_LOADED, UNDO_REMOVE],
     [PRINT, PORT, PUBLISH, BOOTSTRAP, PROBE, PRINT, PRINT], True, True),
    ("launchd reports no pid", _no_launchd_pid, 7, [PROCEED, FREE, WROTE, BOOTSTRAPPED, ANSWERS],
     [FAILED + f"launchd reports no pid for {SERVICE}", f"changed: wrote {PLIST}; bootstrapped {SERVICE}",
      STATE_PRESENT_LOADED, UNDO_REMOVE],
     [PRINT, PORT, PUBLISH, BOOTSTRAP, PROBE, PRINT, PRINT], True, True),
    ("no pid file after the probe", _no_pidfile, 7, [PROCEED, FREE, WROTE, BOOTSTRAPPED, ANSWERS],
     [FAILED + f"{PIDFILE} names no postmaster pid (absent)", f"changed: wrote {PLIST}; bootstrapped {SERVICE}",
      STATE_PRESENT_LOADED, UNDO_REMOVE],
     [PRINT, PORT, PUBLISH, BOOTSTRAP, PROBE, PRINT, PRINT], True, True),
]

# Class B: a failure injected at each step after the first change (and the write race, which changes nothing).
CLASS_B_INSTALL = [
    ("bootstrap host error", _bootstrap_host_error, 6, [PROCEED, FREE, WROTE],
     [FAILED + f"/bin/launchctl bootstrap: {HOST_TIMEOUT}", f"changed: wrote {PLIST}", STATE_PRESENT_NOT_LOADED,
      UNDO_REMOVE],
     [PRINT, PORT, PUBLISH, BOOTSTRAP, PRINT], True, False),
    ("verify host error", _verify_host_error, 6, [PROCEED, FREE, WROTE, BOOTSTRAPPED, ANSWERS],
     [FAILED + f"/bin/launchctl print: {HOST_TIMEOUT}", f"changed: wrote {PLIST}; bootstrapped {SERVICE}",
      VERIFY_HOST_STATE, UNDO_REMOVE],
     [PRINT, PORT, PUBLISH, BOOTSTRAP, PROBE, PRINT, PRINT], True, True),
    ("write denied before the link", _write_denied, 6, [PROCEED, FREE],
     [FAILED + f"writing {PLIST}: EACCES; nothing changed", STATE_ABSENT_NOT_LOADED],
     [PRINT, PORT, PUBLISH, PRINT], False, False),
    ("write loses the no-clobber race", _write_race, 4, [PROCEED, FREE],
     [REFUSED + f"plist target {PLIST} appeared during the install; nothing changed"],
     [PRINT, PORT, PUBLISH], False, False),
    ("write fails after the link", _write_after_link, 6, [PROCEED, FREE],
     [FAILED + f"writing {PLIST}: EIO after the plist was linked in place", f"changed: wrote {PLIST}",
      STATE_ABSENT_NOT_LOADED, UNDO_REMOVE],
     [PRINT, PORT, PUBLISH, PRINT], False, False),
]

CLASS_B_REMOVE = [
    ("bootout refused", _bootout_refused, 6, [REMOVE_PROCEED],
     [FAILED + f"/bin/launchctl bootout {SERVICE} exited 5", "changed: nothing", STATE_PRESENT_LOADED, FINISH_REMOVAL],
     [PRINT, BOOTOUT, PRINT], True, True),
    ("bootout host error", _bootout_host_error, 6, [REMOVE_PROCEED],
     [FAILED + f"/bin/launchctl bootout: {HOST_TIMEOUT}", "changed: nothing confirmed", STATE_PRESENT_LOADED,
      FINISH_REMOVAL],
     [PRINT, BOOTOUT, PRINT], True, True),
    ("remove denied after the bootout", _remove_denied, 6, [REMOVE_PROCEED, f"booted out {SERVICE}"],
     [FAILED + f"removing {PLIST}: EACCES", f"changed: booted out {SERVICE}", STATE_PRESENT_NOT_LOADED,
      f"undo: sudo /bin/launchctl bootstrap system {PLIST}", FINISH_REMOVAL],
     [PRINT, BOOTOUT, REMOVE, PRINT], True, False),
]


def _run_row(test: unittest.TestCase, mode: str, make, row) -> None:
    name, inject, code, out, err, calls, plist_left, loaded_left = row
    fake = make()
    inject(fake)
    outcome = tdi.run(base.argv_for(mode), fake, base.INVOCATION)
    with test.subTest(row=name):
        test.assertEqual((outcome.code, outcome.out, outcome.err), (code, out, err))
        test.assertEqual(fake.calls, calls)
        test.assertEqual((PLIST in fake.files, fake.loaded), (plist_left, loaded_left))
        if code != 0:
            test.assertNotIn("installed", " ".join(outcome.out + outcome.err))
        test.assertFalse(any("host probe failed" in line for line in outcome.err), outcome.err)


class ClassAInstallProofTests(unittest.TestCase):
    def test_every_install_state_prints_its_own_reason(self) -> None:
        for row in CLASS_A:
            _run_row(self, "INSTALL", absent_fake, row)

    def test_the_table_covers_each_named_state(self) -> None:
        self.assertEqual(
            [row[0] for row in CLASS_A],
            ["all good", "port taken by another process", "bootstrap refused", "probe timeout", "pid mismatch",
             "launchd reports no pid", "no pid file after the probe"],
        )
        self.assertEqual([row[2] for row in CLASS_A], [0, 11, 6, 7, 7, 7, 7])


class ClassBFailureKindTests(unittest.TestCase):
    def test_install_failures_after_the_first_change(self) -> None:
        for row in CLASS_B_INSTALL:
            _run_row(self, "INSTALL", absent_fake, row)

    def test_remove_failures_after_the_first_change(self) -> None:
        for row in CLASS_B_REMOVE:
            _run_row(self, "REMOVE", loaded_fake, row)

    def test_handover_with_remove_states_the_real_reason(self) -> None:
        outcome = tdi.run(base.argv_for("REMOVE", handover=True), R1Fake(), base.INVOCATION)
        self.assertEqual(
            (outcome.code, outcome.out, outcome.err),
            (2, [], [REFUSED + "--handover goes with --install or the dry run; --remove never waits for a postmaster"]),
        )


class _OwnerSwapFake(R1Fake):
    """Bootstrap succeeds, and the data directory read by the verify step shows the given facts."""

    def __init__(self, verify_facts) -> None:
        super().__init__()
        self.verify_facts = verify_facts

    def _run(self, argv: list[str]) -> subprocess.CompletedProcess[str]:
        result = super()._run(argv)
        if argv[:2] == [tdi.LAUNCHCTL, "bootstrap"] and result.returncode == 0:
            self.facts[base.DATA] = self.verify_facts
        return result


class _RemoveThenFailFake(R1Fake):
    """The unlink takes effect, then the remove step still reports an error (a failed directory fsync)."""

    def remove_file(self, path: str) -> None:
        self._require_changes()
        self.calls.append(("remove", path))
        del self.files[path]
        raise getattr(tdi, "PartialRemove", OSError)(errno.EIO, "io")


CHANGED_WROTE_BOOTSTRAPPED = f"changed: wrote {PLIST}; bootstrapped {SERVICE}"
VERIFY_CALLS = [PRINT, PORT, PUBLISH, BOOTSTRAP, PROBE, PRINT, PRINT]
VERIFY_OUT = [PROCEED, FREE, WROTE, BOOTSTRAPPED, ANSWERS]
# (name, facts the verify step reads, the exact refusal it reports)
VERIFY_DATA_DIR_ROWS = [
    ("owned by root", tdi.Facts(tdi.Kind.DIR, 0, 0o700),
     f"--data-dir {base.DATA} is owned by uid 0, not by {base.ACCOUNT} (uid {base.ACCOUNT_UID})"),
    ("owned by another account", tdi.Facts(tdi.Kind.DIR, 502, 0o700),
     f"--data-dir {base.DATA} is owned by uid 502, not by {base.ACCOUNT} (uid {base.ACCOUNT_UID})"),
    ("group writable", tdi.Facts(tdi.Kind.DIR, base.ACCOUNT_UID, 0o770),
     f"--data-dir {base.DATA} is group or world writable"),
    ("world writable", tdi.Facts(tdi.Kind.DIR, base.ACCOUNT_UID, 0o702),
     f"--data-dir {base.DATA} is group or world writable"),
    ("replaced by a symlink", tdi.Facts(tdi.Kind.SYMLINK), f"--data-dir {base.DATA} is a symlink"),
]


class ClassAOwnershipAfterBootstrapTests(unittest.TestCase):
    def test_a_data_dir_that_fails_the_check_at_verify_is_never_installed(self) -> None:
        for name, facts, why in VERIFY_DATA_DIR_ROWS:
            fake = _OwnerSwapFake(facts)
            outcome = tdi.run(base.argv_for("INSTALL"), fake, base.INVOCATION)
            with self.subTest(row=name):
                self.assertEqual(
                    (outcome.code, outcome.out, outcome.err),
                    (7, VERIFY_OUT, [FAILED + why, CHANGED_WROTE_BOOTSTRAPPED, STATE_PRESENT_LOADED, UNDO_REMOVE]),
                )
                self.assertEqual(fake.calls, VERIFY_CALLS)
                self.assertNotIn("installed", " ".join(outcome.out + outcome.err))


class ClassBUndoFromStateTests(unittest.TestCase):
    def test_an_unknown_service_state_after_bootstrap_still_offers_the_bootout(self) -> None:
        fake = R1Fake()
        fake.files[PLIST] = base.PLIST_BYTES
        fake.probe_result = False
        fake.raise_from["print"] = 2
        outcome = tdi.run(base.argv_for("INSTALL"), fake, base.INVOCATION)
        self.assertEqual(
            (outcome.code, outcome.out, outcome.err),
            (
                7,
                [OUT + "--install: proceed: port check, bootstrap, probe, verify", FREE, BOOTSTRAPPED],
                [
                    FAILED + "127.0.0.1:5445 did not answer within 60 s",
                    f"changed: bootstrapped {SERVICE}",
                    VERIFY_HOST_STATE,
                    f"undo: sudo /bin/launchctl bootout {SERVICE}",
                ],
            ),
        )
        self.assertEqual(fake.calls, [PRINT, PORT, BOOTSTRAP, PROBE, PRINT])

    def test_a_remove_that_left_no_plist_never_offers_a_bootstrap(self) -> None:
        fake = _RemoveThenFailFake()
        fake.files[PLIST] = base.PLIST_BYTES
        fake.loaded = True
        outcome = tdi.run(base.argv_for("REMOVE"), fake, base.INVOCATION)
        self.assertEqual(
            (outcome.code, outcome.out, outcome.err),
            (
                6,
                [REMOVE_PROCEED, f"booted out {SERVICE}"],
                [FAILED + f"removing {PLIST}: EIO after the plist was unlinked",
                 f"changed: booted out {SERVICE}; removed {PLIST}", STATE_ABSENT_NOT_LOADED, FINISH_REMOVAL],
            ),
        )
        self.assertEqual(fake.calls, [PRINT, BOOTOUT, REMOVE, PRINT])
        self.assertFalse(any("bootstrap" in line for line in outcome.err), outcome.err)


# Round 2, finding 9872-r2-1: the install proof over every state of postmaster.pid and launchd.
# The dimensions of the table: the pid on line 1, the data directory on line 2, the port on line 4, the status on
# line 8, the readiness probe, and the pid launchd reports when it is asked again after the pid file was read.
PID_ROWS = {"pid same": LAUNCHD_PID, "pid other": OTHER_PID}
DATA_ROWS = {"data same": base.DATA, "data other": "/opt/tier/other"}
PORT_ROWS = {"port same": "5445", "port other": "5446"}
# The status column as postgres pads it to 8 characters; None leaves line 8 out (a start still in progress).
STATUS_ROWS = {
    "ready": "ready   ",
    "starting": "starting",
    "stopping": "stopping",
    "standby": "standby ",
    "empty": "",
    "missing": None,
}
PROBE_ROWS = {"probe answers": True, "probe silent": False}
REREAD_ROWS = {"reread same": LAUNCHD_PID, "reread changed": OTHER_PID, "reread gone": None}
PROOF_TABLE_SIZE = 2 * 2 * 2 * 6 * 2 * 3

# The exact reasons, written out by hand (never taken from the module under test).
WHY_PROBE = "127.0.0.1:5445 did not answer within 60 s"
WHY_SHORT = f"{PIDFILE} has 7 lines, not the 8 a started postmaster writes"
WHY_LONG = f"{PIDFILE} has text after line 8"
WHY_PID = f"launchd pid 5151 of {SERVICE} is not the postmaster pid 6262 in {PIDFILE}"
WHY_DATA = f"{PIDFILE} names data directory '/opt/tier/other', not /opt/tier/pgdata"
WHY_PORT = f"{PIDFILE} names port '5446', not 5445"
WHY_PORT_EMPTY = f"{PIDFILE} has an empty port line"
WHY_PORT_NAN = f"{PIDFILE} port line '54x5' is not a number"
WHY_STATUS_EMPTY = f"{PIDFILE} has an empty status line"
WHY_STATUS = {
    "starting": f"{PIDFILE} status is 'starting', not ready",
    "stopping": f"{PIDFILE} status is 'stopping', not ready",
    "standby": f"{PIDFILE} status is 'standby', not ready",
}
WHY_REREAD_CHANGED = f"launchd pid of {SERVICE} changed from 5151 to 6262 while {PIDFILE} was read"
WHY_REREAD_GONE = f"launchd reports no pid for {SERVICE} after {PIDFILE} was read"
WHY_TOO_BIG = f"{PIDFILE} names no postmaster pid (is larger than 4096 bytes)"
WHY_BAD_PID = f"{PIDFILE} names no postmaster pid (does not start with a process id)"
WHY_UNREADABLE = f"{PIDFILE} is unreadable (read {PIDFILE}: EIO)"
PROBE_FAILED_CALLS = [PRINT, PORT, PUBLISH, BOOTSTRAP, PROBE, PRINT]
PIDFILE_FAILED_CALLS = [PRINT, PORT, PUBLISH, BOOTSTRAP, PROBE, PRINT, PRINT]
REREAD_FAILED_CALLS = [PRINT, PORT, PUBLISH, BOOTSTRAP, PROBE, PRINT, PRINT, PRINT]
INSTALLED_CALLS = [PRINT, PORT, PUBLISH, BOOTSTRAP, PROBE, PRINT, PRINT]


def expected_proof(pid: str, data: str, port: str, status: str, probe: str, reread: str) -> tuple[int, str, list]:
    """The oracle: the exit code, the reason (empty for installed) and the commands, in the order the proof runs."""
    if probe == "probe silent":
        return 7, WHY_PROBE, PROBE_FAILED_CALLS
    if status == "missing":
        return 7, WHY_SHORT, PIDFILE_FAILED_CALLS
    if pid == "pid other":
        return 7, WHY_PID, PIDFILE_FAILED_CALLS
    if data == "data other":
        return 7, WHY_DATA, PIDFILE_FAILED_CALLS
    if port == "port other":
        return 7, WHY_PORT, PIDFILE_FAILED_CALLS
    if status == "empty":
        return 7, WHY_STATUS_EMPTY, PIDFILE_FAILED_CALLS
    if status != "ready":
        return 7, WHY_STATUS[status], PIDFILE_FAILED_CALLS
    if reread == "reread changed":
        return 7, WHY_REREAD_CHANGED, REREAD_FAILED_CALLS
    if reread == "reread gone":
        return 7, WHY_REREAD_GONE, REREAD_FAILED_CALLS
    return 0, "", INSTALLED_CALLS


class _ProofFake(R1Fake):
    """Bootstrap writes the given pid file bytes; the second launchd query after it answers with ``reread_pid``."""

    def __init__(self, pidfile_bytes: bytes | None, probe: bool, reread_pid: int | None, unreadable: bool = False) -> None:
        super().__init__()
        self.pidfile_bytes = pidfile_bytes
        self.probe_result = probe
        self.reread_pid = reread_pid
        self.unreadable = unreadable
        self.prints_after_bootstrap: int | None = None

    def read_data_dir(self, path: str, name: str, limit: int):
        if self.unreadable and self.prints_after_bootstrap is not None:
            raise tdi.HostError(f"read {path}/{name}: EIO")
        return super().read_data_dir(path, name, limit)

    def _run(self, argv: list[str]) -> subprocess.CompletedProcess[str]:
        if argv[:2] == [tdi.LAUNCHCTL, "print"] and self.prints_after_bootstrap is not None:
            self.prints_after_bootstrap += 1
            if self.prints_after_bootstrap == 2:
                self.launchd_pid_value = self.reread_pid
        result = super()._run(argv)
        if argv[:2] == [tdi.LAUNCHCTL, "bootstrap"] and result.returncode == 0:
            self.prints_after_bootstrap = 0
            if self.pidfile_bytes is None:
                self.files.pop(PIDFILE, None)
            else:
                self.files[PIDFILE] = self.pidfile_bytes
        return result


def _proof_row(test: unittest.TestCase, name: str, fake: _ProofFake, code: int, why: str, calls: list) -> None:
    outcome = tdi.run(base.argv_for("INSTALL"), fake, base.INVOCATION)
    with test.subTest(row=name):
        if code == 0:
            test.assertEqual((outcome.code, outcome.out, outcome.err), (0, VERIFY_OUT + [INSTALLED], []))
        else:
            out = VERIFY_OUT if why != WHY_PROBE else VERIFY_OUT[:-1]
            test.assertEqual(
                (outcome.code, outcome.out, outcome.err),
                (code, out, [FAILED + why, CHANGED_WROTE_BOOTSTRAPPED, STATE_PRESENT_LOADED, UNDO_REMOVE]),
            )
            test.assertNotIn("installed", " ".join(outcome.out + outcome.err))
        test.assertEqual(fake.calls, calls)


class ClassAExhaustiveProofTests(unittest.TestCase):
    def test_every_combination_of_pid_file_and_launchd_state(self) -> None:
        rows = 0
        installed = 0
        for pid_name, pid in PID_ROWS.items():
            for data_name, data_dir in DATA_ROWS.items():
                for port_name, port in PORT_ROWS.items():
                    for status_name, status in STATUS_ROWS.items():
                        for probe_name, probe in PROBE_ROWS.items():
                            for reread_name, reread in REREAD_ROWS.items():
                                code, why, calls = expected_proof(
                                    pid_name, data_name, port_name, status_name, probe_name, reread_name
                                )
                                fake = _ProofFake(base.pidfile_text(pid, data_dir, port, status), probe, reread)
                                name = " / ".join([pid_name, data_name, port_name, status_name, probe_name, reread_name])
                                _proof_row(self, name, fake, code, why, calls)
                                rows += 1
                                installed += code == 0
        self.assertEqual((rows, installed), (PROOF_TABLE_SIZE, 1))

    def test_degenerate_pid_files_are_states_with_their_own_reason(self) -> None:
        ready = base.pidfile_text(LAUNCHD_PID)
        degenerate = [
            ("seven lines", base.pidfile_text(LAUNCHD_PID, status=None), WHY_SHORT),
            ("trailing junk after line 8", ready + b"junk\n", WHY_LONG),
            ("a blank line after line 8", ready + b"\n", WHY_LONG),
            ("empty port line", base.pidfile_text(LAUNCHD_PID, port=""), WHY_PORT_EMPTY),
            ("non-numeric port", base.pidfile_text(LAUNCHD_PID, port="54x5"), WHY_PORT_NAN),
            ("port with a leading zero", base.pidfile_text(LAUNCHD_PID, port="05445"), f"{PIDFILE} names port '05445', not 5445"),
            ("empty status line", base.pidfile_text(LAUNCHD_PID, status=""), WHY_STATUS_EMPTY),
            ("blank status line", base.pidfile_text(LAUNCHD_PID, status="        "), WHY_STATUS_EMPTY),
            ("status with a suffix", base.pidfile_text(LAUNCHD_PID, status="readyX  "), f"{PIDFILE} status is 'readyX', not ready"),
            ("status cut short", base.pidfile_text(LAUNCHD_PID, status="rea"), f"{PIDFILE} status is 'rea', not ready"),
            ("status with a tab", base.pidfile_text(LAUNCHD_PID, status="ready\t"), f"{PIDFILE} status is 'ready\\t', not ready"),
            ("status in upper case", base.pidfile_text(LAUNCHD_PID, status="READY   "), f"{PIDFILE} status is 'READY', not ready"),
            ("data directory with a trailing slash", base.pidfile_text(LAUNCHD_PID, data_dir=base.DATA + "/"),
             f"{PIDFILE} names data directory '/opt/tier/pgdata/', not /opt/tier/pgdata"),
            ("data directory in another encoding", base.pidfile_text(LAUNCHD_PID, data_dir="/opt/tier/pgdäta"),
             f"{PIDFILE} names data directory '/opt/tier/pgd\\xe4ta', not /opt/tier/pgdata"),
            ("over the size cap", ready + b"x" * (tdi.MAX_PIDFILE_BYTES + 1), WHY_TOO_BIG),
            ("bad pid line", b"abc" + ready[4:], WHY_BAD_PID),
            ("empty file", b"", f"{PIDFILE} names no postmaster pid (is empty)"),
            ("absent", None, f"{PIDFILE} names no postmaster pid (absent)"),
        ]
        for name, data, why in degenerate:
            _proof_row(self, name, _ProofFake(data, True, LAUNCHD_PID), 7, why, PIDFILE_FAILED_CALLS)
        _proof_row(self, "unreadable", _ProofFake(ready, True, LAUNCHD_PID, unreadable=True), 7, WHY_UNREADABLE,
                   PIDFILE_FAILED_CALLS)

    def test_a_long_control_laden_line_is_shown_bounded_and_escaped(self) -> None:
        hostile = "\x1b[2J" + "z" * 100_000
        fake = _ProofFake(base.pidfile_text(LAUNCHD_PID, port=hostile), True, LAUNCHD_PID)
        outcome = tdi.run(base.argv_for("INSTALL"), fake, base.INVOCATION)
        self.assertEqual(outcome.code, 7)
        self.assertEqual(outcome.err[0], FAILED + WHY_TOO_BIG)
        fake = _ProofFake(base.pidfile_text(LAUNCHD_PID, port="\x1b[2J" + "z" * 200), True, LAUNCHD_PID)
        outcome = tdi.run(base.argv_for("INSTALL"), fake, base.INVOCATION)
        self.assertEqual(outcome.code, 7)
        self.assertEqual(outcome.err[0], FAILED + f"{PIDFILE} port line '\\x1b[2J{'z' * 60}...' is not a number")
        self.assertNotIn("\x1b", " ".join(outcome.err))


if __name__ == "__main__":
    unittest.main()
