#!/usr/bin/env python3
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""Host-local admission semaphore for the heavy self-hosted CI legs (#7914).

The #6795 load gate checks the host load once, at job start. Several f2 runners
share one 14-core host with the coder lanes, so legs that all passed the gate
at a quiet moment can still pile onto the box together and starve each other
(measured: load 12.7 at the gate, 36-68 during the test phase, the serial shard
killed by the #1492 watchdog at 5136 s). This wrapper bounds how many legs run
their compile+test phase at once on ONE host.

``host_semaphore.py --name N --slots S --max-wait-secs M --poll-secs P --label L
-- COMMAND...`` takes one of S numbered slot files (``fcntl.flock``, exclusive,
non-blocking, polled) under ``~/.cache/ai-memory-ci/semaphore/N/slot-<i>.lock``,
holds it for the whole life of COMMAND and exits with COMMAND's exit code. The
kernel drops a flock when its holder dies, so a crashed runner never leaks a slot.
SIGTERM/SIGINT/SIGHUP are forwarded to COMMAND's process group (then SIGKILL after
a grace period) and the lock is released in ``finally``.

Exit codes: the child's code; 2 bad arguments; 75 no slot free within the wait
budget (COMMAND never ran; one ``::error title=infra: no slot::`` line, #9231); 4 the shared workflow_annotation.py next to this file
cannot be loaded (COMMAND never ran, one ``::error`` line, #9365); 128+signal when
COMMAND died from a signal.
Python 3.9+, standard library only.
"""
import argparse
import fcntl
import json
import os
import re
import signal
import subprocess
import sys
import time
from pathlib import Path


def _load_workflow_annotation():
    """The shared module at WA_RELATIVE_PATH from this file's real directory, by path only, never through
    sys.path; every name in WA_REQUIRED must be a callable of it (#9365, one shape in every script)."""
    import importlib.util
    import os
    path = os.path.normpath(os.path.join(os.path.dirname(os.path.realpath(__file__)), WA_RELATIVE_PATH))
    loaded = sys.modules.get("workflow_annotation")
    if loaded is not None and os.path.realpath(getattr(loaded, "__file__", None) or "") == path:
        module = loaded
    else:
        spec = importlib.util.spec_from_file_location("workflow_annotation", path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)  # absent, unreadable or broken: it raises here, the try below catches it
    missing = [name for name in WA_REQUIRED if not callable(getattr(module, name, None))]
    if missing:
        raise AttributeError("workflow_annotation.py lacks " + ", ".join(missing))
    if loaded is None:
        sys.modules["workflow_annotation"] = module
    return module


EXIT_LOAD_REFUSED = 4  # the shared module cannot be loaded (2 = bad arguments, 75 = no slot, else the child's)

# The one shared-module load shape of scripts/ (#9365, ruling bcd0a15c; LoaderShape pins it).
WA_PROG = "host_semaphore"
WA_RELATIVE_PATH = "workflow_annotation.py"
WA_REQUIRED = ("annotation", "log_line")
WA_EXIT_LOAD_REFUSED = EXIT_LOAD_REFUSED  # the gate's own refusal code, unchanged
WA_ERROR_TO_STDERR = False

try:
    wa = _load_workflow_annotation()
except (Exception, SystemExit) as exc:  # any failed load: one fixed line built without the module, then exit
    wa_cause = type(exc).__name__
    print("%s: refused: shared module workflow_annotation.py next to the script cannot be loaded (%s)"
          % (WA_PROG, wa_cause if wa_cause.isidentifier() else "BaseException"), file=sys.stderr, flush=True)
    print("::error title=host_semaphore refused::host_semaphore: refused: shared module workflow_annotation.py"
          " next to the script cannot be loaded",
          file=sys.stderr if WA_ERROR_TO_STDERR else sys.stdout, flush=True)
    sys.exit(WA_EXIT_LOAD_REFUSED)

SEMAPHORE_SLOTS_DEFAULT = 2
# decision: 600 s over 3600 s because a waiter holds a runner seat idle for the whole wait
# and, with the serving runners tied to the slots (scripts/ci/host_slots.json), a wait only
# bridges a slot handover or a non-CI holder; a hold lasts about 2 h, so a longer wait never
# ends in a slot and only costs a runner an hour (#9231).
SEMAPHORE_MAX_WAIT_SECS_DEFAULT = 600
SEMAPHORE_POLL_SECS_DEFAULT = 30
# decision: a distinct exit code and the token infra-no-slot in the annotation message over a job
# output, because a job output is set after pull-request code ran (taint boundary class iii) and
# the gate is red either way (#9231). A job log line carries no title, so the message names the outcome.
# decision: reserved codes 82, 83 and 84 over sharing 75, because the product binary exits 75
# (src/main.rs) and a child's own code passes through this wrapper unchanged. 82-84 are none of
# 0-4 (this wrapper, load_gate.py), 64-78 (sysexits, the product binary), 86-87 (a test stub),
# 90-109 (nextest, cargo 101), 124-127 (timeout, shell), 128+signal; the table that pins this is
# scripts/ci/tests/test_slot_wait_outcome_9231.py.
EXIT_NO_SLOT = 82
EXIT_UNKNOWN_RUNNER = 83
EXIT_CHILD_RESERVED = 84  # the child itself ended with 82, 83 or 84; the wrapper never passes those through
RESERVED_EXIT_CODES = frozenset((EXIT_NO_SLOT, EXIT_UNKNOWN_RUNNER, EXIT_CHILD_RESERVED))
OUTCOME_NO_SLOT = 'infra-no-slot'  # token in the annotation message; scripts/ci/ci_failure_class.py classifies on it
OUTCOME_UNKNOWN_RUNNER = 'infra-unknown-runner'
OUTCOME_RESERVED_CODE = 'infra-reserved-code'
SLOT_ACQUIRED_MARKER = 'slot-acquired'  # printed as its own line when the slot is held, before the child starts
TITLE_NO_SLOT = 'infra no-slot'  # titles carry no colon or comma, so no property escape reaches the UI
TITLE_UNKNOWN_RUNNER = 'infra unknown-runner'
TITLE_RESERVED_CODE = 'infra reserved-code'
HOST_SLOTS_CONFIG = 'host_slots.json'
ENV_RUNNER_NAME = 'RUNNER_NAME'  # set by the GitHub runner for every step
KILL_GRACE_SECS = 20
TAG = '[#7914 semaphore]'
NAME_RE = re.compile(r'^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$')


def default_root():
    return Path.home() / '.cache' / 'ai-memory-ci' / 'semaphore'


def load_and_cores():
    try:
        load = os.getloadavg()[0]
    except (OSError, AttributeError):
        load = -1.0
    return load, (os.cpu_count() or 0)


def try_acquire(slot_dir, slots):
    """Return (index, fd) of the first free slot, or None. The fd holds the flock."""
    for i in range(slots):
        fd = os.open(str(slot_dir / ('slot-%d.lock' % i)), os.O_RDWR | os.O_CREAT, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            os.close(fd)
            continue
        return i, fd
    return None


def acquire(slot_dir, slots, label, max_wait, poll, sleep_fn=time.sleep):
    """Poll for a slot. Returns (index, fd, waited) or None after the wait budget."""
    waited = 0
    while True:
        got = try_acquire(slot_dir, slots)
        if got is not None:
            return got[0], got[1], waited
        if waited >= max_wait:
            return None
        step = min(poll, max_wait - waited)
        sleep_fn(step)
        waited += step
        print(wa.log_line('%s %r: waiting for a slot of %d, waited=%ds' % (TAG, label, slots, waited)), flush=True)


def _note(message):
    """Record a tolerated condition on stderr (#7929), never silently."""
    print(wa.log_line('%s note: %s' % (TAG, message)), file=sys.stderr, flush=True)


def serving_runners(name, config_path=None):
    """The runner names declared to serve gate NAME in host_slots.json, or None when unknown."""
    path = Path(config_path) if config_path else Path(__file__).resolve().parent / HOST_SLOTS_CONFIG
    try:
        names = json.loads(path.read_text(encoding='utf-8'))['gates'][name]['serving_runners']
        if isinstance(names, list) and all(isinstance(n, str) for n in names):
            return names
        raise TypeError('serving_runners is not a list of strings')
    except (OSError, ValueError, KeyError, TypeError) as exc:
        _note('serving runners of %r unavailable (%s)' % (name, type(exc).__name__))
        return None


def no_slot_annotation(label, max_wait, slots, runners):
    """The one error annotation of the named outcome infra-no-slot (#9231); no test ran, the job stays red.

    RUNNERS is the serving-runner list of the gate, or None when unknown. The message carries the token
    infra-no-slot because a job log shows the message only (`##[error]<message>`, no title).
    """
    return wa.annotation(
        'error',
        "%s '%s': %s: no slot free after %ds (all %d slots busy on this host, %s serving runners); "
        "no test ran, this is an infrastructure outcome, not a test failure; exit %d"
        % (TAG, label, OUTCOME_NO_SLOT, max_wait, slots, 'unknown' if runners is None else len(runners),
           EXIT_NO_SLOT),
        title=TITLE_NO_SLOT)


def unknown_runner_annotation(label, gate, runner):
    """Error annotation: the live runner is not a serving runner of GATE, so the slot count does not cover it."""
    return wa.annotation(
        'error',
        "%s '%s': %s: runner '%s' is not a serving runner of gate '%s' in %s; no test ran; exit %d"
        % (TAG, label, OUTCOME_UNKNOWN_RUNNER, runner, gate, HOST_SLOTS_CONFIG, EXIT_UNKNOWN_RUNNER),
        title=TITLE_UNKNOWN_RUNNER)


def reserved_code_annotation(label, child_rc):
    """Error annotation: the child ended with a code this wrapper reserves for its own outcomes."""
    return wa.annotation(
        'error',
        "%s '%s': %s: the command exited with %d, a code reserved for wrapper outcomes; reported as %d"
        % (TAG, label, OUTCOME_RESERVED_CODE, child_rc, EXIT_CHILD_RESERVED),
        title=TITLE_RESERVED_CODE)


def _signal_group(pgid, sig):
    try:
        os.killpg(pgid, sig)
    except ProcessLookupError:
        _note('process group %d already gone before signal %d (child exited); nothing to signal' % (pgid, sig))
    except PermissionError:
        _note('not permitted to signal process group %d with signal %d; leaving it to the kernel' % (pgid, sig))


def run_child(command):
    """Run COMMAND in its own process group; return its exit code.

    The slot lock fd stays in this wrapper only (#7927): Popen closes every fd above 2
    in the child (close_fds=True, the default), so a surviving descendant never keeps
    the host-wide slot after the wrapper prints ``released``.
    """
    proc = subprocess.Popen(command, start_new_session=True)
    got = []

    def forward(signum, _frame):
        got.append(signum)
        _signal_group(proc.pid, signal.SIGTERM)

    old = {s: signal.signal(s, forward) for s in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP)}
    try:
        deadline = None
        while True:
            try:
                rc = proc.wait(timeout=1)
            except subprocess.TimeoutExpired:
                rc = None  # still running: fall through to the signal/deadline checks
            if rc is not None:
                break
            if got and deadline is None:
                deadline = time.time() + KILL_GRACE_SECS
            if deadline is not None and time.time() > deadline:
                _signal_group(proc.pid, signal.SIGKILL)
        if got:
            _signal_group(proc.pid, signal.SIGKILL)
    finally:
        for s, handler in old.items():
            signal.signal(s, handler)
    if rc < 0:
        return 128 + (-rc)
    return rc


def _positive_int(text):
    value = int(text)
    if value <= 0:
        raise argparse.ArgumentTypeError('must be > 0')
    return value


def _non_negative_int(text):
    value = int(text)
    if value < 0:
        raise argparse.ArgumentTypeError('must be >= 0')
    return value


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument('--name', required=True)
    p.add_argument('--slots', type=_positive_int, default=SEMAPHORE_SLOTS_DEFAULT)
    p.add_argument('--max-wait-secs', type=_non_negative_int, default=SEMAPHORE_MAX_WAIT_SECS_DEFAULT)
    p.add_argument('--poll-secs', type=_positive_int, default=SEMAPHORE_POLL_SECS_DEFAULT)
    p.add_argument('--label', default='unlabelled')
    p.add_argument('--root', default=None, help='lock root (default ~/.cache/ai-memory-ci/semaphore)')
    p.add_argument('--config', default=None, help='slot configuration (default host_slots.json next to this file)')
    p.add_argument('command', nargs=argparse.REMAINDER)
    args = p.parse_args(argv)  # argparse exits 2 on bad arguments
    command = args.command[1:] if args.command[:1] == ['--'] else args.command
    if not command:
        p.error('a command is required after --')
    if not NAME_RE.fullmatch(args.name):
        p.error('--name must match %s' % NAME_RE.pattern)
    runners = serving_runners(args.name, args.config)
    runner = os.environ.get(ENV_RUNNER_NAME)
    if runner and runners is not None and runner not in runners:
        # decision: refuse an unlisted runner over a hand-kept list nothing reads, because the list is the
        # slot count's only source: a runner outside it is not covered by the slots (#9231).
        print(unknown_runner_annotation(args.label, args.name, runner), flush=True)
        return EXIT_UNKNOWN_RUNNER
    root = Path(args.root) if args.root else default_root()
    slot_dir = root / args.name
    slot_dir.mkdir(parents=True, exist_ok=True)
    got = acquire(slot_dir, args.slots, args.label, args.max_wait_secs, args.poll_secs)
    if got is None:
        print(no_slot_annotation(args.label, args.max_wait_secs, args.slots, runners), flush=True)
        return EXIT_NO_SLOT
    index, fd, waited = got
    try:
        load, cores = load_and_cores()
        print(wa.annotation("notice", "%s '%s': slot %d of %d acquired after %ds (load=%.2f cores=%d)"
                            % (TAG, args.label, index, args.slots, waited, load, cores)), flush=True)
        # One fixed line before the child starts: a log with the no-slot line and this line is not a no-slot job.
        print(wa.log_line("%s '%s': %s" % (TAG, args.label, SLOT_ACQUIRED_MARKER)), flush=True)
        child_rc = run_child(command)
        if child_rc in RESERVED_EXIT_CODES:
            print(reserved_code_annotation(args.label, child_rc), flush=True)
            return EXIT_CHILD_RESERVED
        return child_rc
    finally:
        os.close(fd)
        print(wa.log_line("%s '%s': slot %d of %d released" % (TAG, args.label, index, args.slots)), flush=True)


if __name__ == '__main__':
    sys.exit(main())
