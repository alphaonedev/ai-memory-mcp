# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""The sdk-python-live harness and its clients-ci job, round 7 of #6060.

* #6812: a SIGINT or SIGTERM, or an unexpected exception, while the harness
  starts the stack left ``serve`` and ``wake-hub`` running after it exited.
* #6831: the fixed default port 9077 collides with a local daemon or a second
  run; the harness now picks a free loopback port.
* #6813 / #6814: the live job's checkout persisted the token in the git
  config, and the harness ran without ``-I`` from the repository root.
* #6830: a change to the migrations, the vendored crates or the toolchain pin
  changes the binary but did not trigger the job.

A stub stands in for ``ai-memory``: CLI subcommands succeed at once, ``serve``
and ``wake-hub`` record their pid and argv and sleep, ``wake-hub --health``
fails so the harness keeps waiting.
"""

from __future__ import annotations

import os
import pathlib
import re
import signal
import socket
import subprocess
import sys
import time
from typing import Iterator

import pytest

from .test_ci_live_tests_6746 import _HARNESS, _WORKFLOW, _harness, _live_job

_POSIX_ONLY = pytest.mark.skipif(os.name == "nt", reason="POSIX signals and a shebang stub")

_STUB = """#!{python}
import json, os, sys, time
args = sys.argv[1:]
if args[:1] == ["serve"] or (args[:1] == ["wake-hub"] and "--health" not in args):
    with open(os.path.join({marks!r}, args[0] + "-" + str(os.getpid())), "w") as out:
        json.dump(args, out)
    time.sleep(3600)
if "--health" in args:
    sys.exit(1)
if args[:2] == ["identity", "export-pub"]:
    print("AAAA")
if args[:2] == ["identity", "hub-cache"]:
    if {write_allowlist!r}:
        with open(args[args.index("--out") + 1], "w") as out:
            out.write("{{}}")
    else:
        # Fail only once serve is up, so the error always has a child to leak.
        end = time.monotonic() + 30
        while time.monotonic() < end and not any(
            name.startswith("serve-") for name in os.listdir({marks!r})
        ):
            time.sleep(0.05)
sys.exit(0)
"""


class Run:
    """One harness run against the stub; kills every stub child it saw when done."""

    def __init__(self, work: pathlib.Path, *, write_allowlist: bool = True) -> None:
        self.marks = work / "marks"
        self.marks.mkdir()
        stub = work / "stub-ai-memory"
        stub.write_text(
            _STUB.format(
                python=sys.executable, marks=str(self.marks), write_allowlist=write_allowlist
            )
        )
        stub.chmod(0o755)
        self.stub = stub
        self.work = work
        self._closed = False
        self.proc: subprocess.Popen[bytes] | None = None

    def start(self, *extra: str) -> subprocess.Popen[bytes]:
        self.proc = subprocess.Popen(
            [
                sys.executable,
                "-I",
                str(_HARNESS),
                "--binary",
                str(self.stub),
                "--sdk",
                ".",
                "--run-dir",
                str(self.work / "run"),
                *extra,
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            # Its own group, so close() reaps a child whose marker is not written yet.
            start_new_session=True,
        )
        return self.proc

    def children(self) -> dict[str, int]:
        return {
            mark.name.split("-")[0]: int(mark.name.rsplit("-", 1)[1])
            for mark in self.marks.iterdir()
        }

    def wait_for(self, *names: str, timeout: float = 60) -> None:
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            if set(names) <= set(self.children()):
                return
            assert self.proc is not None and self.proc.poll() is None, self.output()
            time.sleep(0.2)
        pytest.fail(f"the stub never started {names}: {self.output()}")

    def output(self) -> str:
        assert self.proc is not None
        if self.proc.poll() is None:
            return "(still running)"
        assert self.proc.stdout is not None
        return self.proc.stdout.read().decode(errors="replace")[-2000:]

    def finish(self, timeout: float = 45) -> int:
        assert self.proc is not None
        return self.proc.wait(timeout=timeout)

    def alive(self) -> dict[str, int]:
        left = {}
        for name, pid in self.children().items():
            try:
                os.kill(pid, 0)
            except OSError:
                continue
            left[name] = pid
        return left

    def close(self) -> None:
        if self.proc is not None and not self._closed:
            self._closed = True  # the pid may be reused once reaped: signal the group once (#6935)
            try:
                os.killpg(self.proc.pid, signal.SIGKILL)
            except (ProcessLookupError, PermissionError):
                pass  # macOS answers EPERM for a group that holds only zombies (#6935)
            self.proc.wait()
        for pid in self.alive().values():
            os.kill(pid, signal.SIGKILL)


def leader_pgid(run: Run, attempts: int = 20) -> int:
    """The harness's process group, retrying the transient ESRCH a loaded host can answer (#6961)."""
    assert run.proc is not None
    for _ in range(attempts):
        try:
            return os.getpgid(run.proc.pid)
        except ProcessLookupError:
            if run.proc.poll() is not None:
                break
            time.sleep(0.05)
    pytest.fail(f"the harness is gone before its group could be read: {run.output()}")


@pytest.fixture
def run(tmp_path: pathlib.Path) -> Iterator[Run]:
    harness_run = Run(tmp_path)
    try:
        yield harness_run
    finally:
        harness_run.close()


def _group_alive(pgid: int) -> list[str]:
    """Live (non-zombie) members of a process group; killpg(pgid, 0) says EPERM for zombies on macOS."""
    table = subprocess.run(
        ["ps", "-axo", "pid=,pgid=,stat=,command="], capture_output=True, text=True, check=True
    ).stdout
    return [
        line.strip()
        for line in table.splitlines()
        if len(line.split()) >= 3
        and line.split()[1] == str(pgid)
        and not line.split()[2].startswith("Z")
    ]


def _gone(run: Run, timeout: float = 10) -> dict[str, int]:
    end = time.monotonic() + timeout
    while run.alive() and time.monotonic() < end:
        time.sleep(0.2)
    return run.alive()


# ---- #6812: teardown on a signal or an unexpected startup error -------------


@_POSIX_ONLY
@pytest.mark.parametrize("sig", [signal.SIGINT, signal.SIGTERM], ids=["SIGINT", "SIGTERM"])
def test_signal_during_startup_stops_the_daemon_and_the_hub_6812(
    run: Run, sig: signal.Signals
) -> None:
    run.start()
    run.wait_for("serve", "wake")
    assert run.proc is not None
    run.proc.send_signal(sig)
    code = run.finish()
    assert code != 0, run.output()
    assert _gone(run) == {}, f"left running after {sig.name}: {run.alive()} ({run.output()})"


@_POSIX_ONLY
def test_unexpected_startup_error_stops_the_daemon_6812(tmp_path: pathlib.Path) -> None:
    """The hub allowlist is never written, so publishing it raises OSError, not RuntimeError."""
    harness_run = Run(tmp_path, write_allowlist=False)
    try:
        harness_run.start()
        code = harness_run.finish()
        output = harness_run.output()
        assert "serve" in harness_run.children(), output
        assert _gone(harness_run) == {}, f"left running: {harness_run.alive()} ({output})"
        assert code == 2, output
        assert "could not start the stack" in output, output
    finally:
        harness_run.close()


# ---- #6831: a free port, not a fixed one ------------------------------------


@_POSIX_ONLY
def test_default_port_is_a_free_loopback_port_6831(run: Run) -> None:
    run.start()
    run.wait_for("serve")
    serve = (run.marks / f"serve-{run.children()['serve']}").read_text()
    port = int(re.search(r'"--port", "(\d+)"', serve).group(1))  # type: ignore[union-attr]
    assert port != 9077 and 0 < port < 65536, serve


@_POSIX_ONLY
def test_teardown_reaps_every_child_of_the_harness_6812(run: Run) -> None:
    """A child the harness spawns just before the test kills it must not outlive the test.

    The harness starts the hub right after serve; killing only the harness and the
    children whose marker already exists left that hub running.
    """
    run.start()
    assert run.proc is not None
    pgid = run.proc.pid
    assert leader_pgid(run) == pgid, "the harness must lead its own process group"
    run.wait_for("serve")
    run.close()
    end = time.monotonic() + 10
    while _group_alive(pgid) and time.monotonic() < end:
        time.sleep(0.1)
    assert _group_alive(pgid) == [], f"left running: {run.alive()}"


def test_free_port_is_bindable_on_loopback_6831() -> None:
    port = _harness().free_port()
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", port))


# ---- #6813 / #6814 / #6830: the clients-ci job ------------------------------


def test_live_job_checkout_does_not_persist_the_token_6813() -> None:
    checkout = re.search(r"- uses: actions/checkout@[^\n]*\n((?:\s{8,}[^\n]*\n)*)", _live_job())
    assert checkout is not None
    assert re.search(r"^\s+persist-credentials: false$", checkout.group(1), re.M), checkout.group(0)


def test_live_job_runs_the_harness_isolated_6814() -> None:
    assert re.search(r"\bpython -I scripts/sdk-python-live\.py ", _live_job()), (
        "the live job must run the harness with `python -I` (#6814)"
    )


def test_every_input_of_the_binary_triggers_the_live_job_6830() -> None:
    on = _WORKFLOW.read_text(encoding="utf-8").split("\njobs:\n", 1)[0]
    for event in ("push", "pull_request"):
        block = re.split(r"\n  [a-z_]+:\n", on.split(f"\n  {event}:\n", 1)[1], maxsplit=1)[0]
        for path in ('"migrations/**"', '"vendor/**"', '"rust-toolchain.toml"'):
            assert f"- {path}" in block, f"clients-ci {event} paths miss {path} (#6830)"


def test_live_docs_do_not_name_a_fixed_daemon_port_6831() -> None:
    """The harness picks a free port; its docstring and the job comment must not name 9077."""
    harness_doc = _HARNESS.read_text().split('"""', 2)[1]
    assert "9077" not in harness_doc
    job = _WORKFLOW.read_text()
    comment = job[job.index("# #6746") : job.index("sdk-python-live:")]
    assert "9077" not in comment
