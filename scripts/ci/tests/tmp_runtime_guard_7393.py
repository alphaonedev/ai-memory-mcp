"""Runtime tmp-root guard for the PR #7393 evidence tests (#7619).

An AST guard cannot see a string that is built at run time, so the rule "no test or script writes under a tmp root"
is also enforced while the tests run: `GuardedCase` switches on a `sys.addaudithook` hook for the length of each test.
The hook fails the test on any `open`, `os.mkdir`, `os.rename` / `os.replace`, `os.symlink`, `os.link`,
`sqlite3.connect`, `shutil.*` or `tempfile.*` event whose resolved path (realpath, case folded) is a tmp root or under
one, on a `socket.bind` of an AF_UNIX path there, and on a `subprocess.Popen` whose cwd is there (#7670). A violation is
raised at the call site and also recorded, so a test that swallows the exception still fails when it ends.

What it covers: the audit events named above, in this process, while a GuardedCase test is running, however the path
string was built (bytes decoded at run time, %c joins, rot13, an environment copy, tempfile's default lookup).
What it does not cover: what a child process does after it starts, an event with a descriptor instead of a path, and a
path that is only read or computed (the AST guard in test_evidence_generator_r6_7393.py covers the static spellings).

Every GuardedCase test also runs with the disk floors of run_cert.py set to 0 (#7661): the floors guard the cargo legs
of a certification run on the certifying host, and a hosted CI runner has far less free disk than that host. The tests
that exercise the floor patch their own values (and os.statvfs) inside the test.

The roots are the three names built from parts (the spelled names never appear in this file) plus each root's realpath.
Tests of the guard itself use `captured(fake_root)`, which swaps the roots for a fake directory under the checkout's
.local-runs/ and sinks the violations, so no real tmp root is ever touched.
"""
import contextlib
import os
import sys
import threading
import unittest
import unittest.mock as mock
from pathlib import Path

EVIDENCE_DIR = Path(__file__).resolve().parents[2] / "evidence"
FLOOR_CONSTANTS = ("FLOOR_BUILD_GIB", "FLOOR_ROOT_GIB")

_NAMES = ("tmp", "var/tmp", "private/tmp", "dev/shm")
REAL_ROOTS = tuple("/" + n for n in _NAMES)
CHECKED_EVENTS = ("open", "os.mkdir", "os.rename", "os.replace", "os.symlink", "os.link", "sqlite3.connect",
                  "socket.bind", "subprocess.Popen")
CHECKED_PREFIXES = ("shutil.", "tempfile.")

_state = threading.local()
_lock = threading.Lock()
_state_of = {"installed": False, "active": 0}
violations = []


class TmpRootViolation(AssertionError):
    """A test touched a path under a tmp root."""


def resolved_roots(roots=REAL_ROOTS):
    """The roots plus each one's realpath, case folded (macOS spells /tmp as /private/tmp, and is case-insensitive)."""
    out = set()
    for root in roots:
        out.add(os.path.realpath(root).casefold())
        out.add(root.casefold())
    return tuple(sorted(out))


def under(path, roots):
    """True when `path` resolves to one of `roots` or below it. A descriptor or an unreadable value is not a path."""
    if isinstance(path, int) or path is None:
        return False
    try:
        resolved = os.path.realpath(os.fsdecode(path)).casefold()
    except (TypeError, ValueError):
        return False
    return any(resolved == r or resolved.startswith(r.rstrip("/") + "/") for r in roots)


def finding(event, args, roots):
    """A reason string when the audit event touches a path under `roots`, else None. Pure: touches nothing."""
    if event == "socket.bind":  # (socket, address): only an AF_UNIX path is a str or bytes address
        paths = [a for a in args[1:2] if isinstance(a, (str, bytes))]
    elif event == "subprocess.Popen":  # (executable, args, cwd, env)
        paths = [a for a in args[2:3] if isinstance(a, (str, bytes, os.PathLike))]
    elif event in CHECKED_EVENTS:
        paths = args[:2] if event in ("os.rename", "os.replace", "os.symlink", "os.link") else args[:1]
    elif event.startswith(CHECKED_PREFIXES):
        paths = [a for a in args if isinstance(a, (str, bytes, os.PathLike))]
    else:
        return None
    for p in paths:
        if under(p, roots):
            return f"{event} {os.fsdecode(p)!r}"
    return None


def _hook(event, args):
    if not _state_of["active"]:
        return
    override = getattr(_state, "override", None)
    roots, sink = override if override else (_REAL, violations)
    reason = finding(event, args, roots)
    if reason:
        with _lock:
            sink.append(reason)
        raise TmpRootViolation(f"tmp-root access during a test: {reason}")


_REAL = resolved_roots()


def install():
    """Install the audit hook once per process; it is inert unless a GuardedCase test is running."""
    with _lock:
        if not _state_of["installed"]:
            sys.addaudithook(_hook)
            _state_of["installed"] = True


@contextlib.contextmanager
def captured(fake_root):
    """Treat `fake_root` as the only tmp root and collect violations in the yielded list instead of failing the test."""
    sink = []
    previous = getattr(_state, "override", None)
    _state.override = (resolved_roots([str(fake_root)]), sink)
    try:
        yield sink
    finally:
        _state.override = previous


class GuardedCase(unittest.TestCase):
    """Base class of every PR #7393 evidence test: the runtime tmp-root hook is live for the length of each test."""

    def setUp(self):
        install()
        with _lock:
            _state_of["active"] += 1
            start = len(violations)
        self.addCleanup(self._tmp_guard_done, start)
        if str(EVIDENCE_DIR) not in sys.path:
            sys.path.insert(0, str(EVIDENCE_DIR))
        import run_cert  # the floors are lifted for every test; the floor tests set their own values
        for name in FLOOR_CONSTANTS:
            patcher = mock.patch.object(run_cert, name, 0)
            patcher.start()
            self.addCleanup(patcher.stop)

    def _tmp_guard_done(self, start):
        with _lock:
            _state_of["active"] -= 1
            new = violations[start:]
        if new:
            raise TmpRootViolation(f"{len(new)} tmp-root access(es) during the test: {new[:3]}")
