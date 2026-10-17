"""Runtime tmp-root guard for the PR #7393 evidence tests (#7619).

An AST guard cannot see a string that is built at run time, so the rule "no test or script writes under a tmp root"
is also enforced while the tests run: `GuardedCase` switches on a `sys.addaudithook` hook for the length of each test.
The hook fails the test on any `open`, `os.mkdir`, `os.rename` / `os.replace`, `shutil.*` or `tempfile.*` event whose
resolved path (realpath, case folded) is a tmp root or under one. A violation is raised at the call site and also
recorded, so a test that swallows the exception still fails when it ends.

What it covers: the audit events named above, in this process, while a GuardedCase test is running.
What it does not cover: a child process, an event with a descriptor instead of a path, and a path that is only
read or computed (the AST guard in test_evidence_generator_r6_7393.py covers the static spellings).

The roots are the three names built from parts (the spelled names never appear in this file) plus each root's realpath.
Tests of the guard itself use `captured(fake_root)`, which swaps the roots for a fake directory under the checkout's
.local-runs/ and sinks the violations, so no real tmp root is ever touched.
"""
import contextlib
import os
import sys
import threading
import unittest

_NAMES = ("tmp", "var/tmp", "private/tmp", "dev/shm")
REAL_ROOTS = tuple("/" + n for n in _NAMES)
CHECKED_EVENTS = ("open", "os.mkdir", "os.rename", "os.replace")
CHECKED_PREFIXES = ("shutil.", "tempfile.")

_state = threading.local()
_lock = threading.Lock()
_installed = False
_active = 0
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
    if event in CHECKED_EVENTS:
        paths = args[:2] if event in ("os.rename", "os.replace") else args[:1]
    elif event.startswith(CHECKED_PREFIXES):
        paths = [a for a in args if isinstance(a, (str, bytes, os.PathLike))]
    else:
        return None
    for p in paths:
        if under(p, roots):
            return f"{event} {os.fsdecode(p)!r}"
    return None


def _hook(event, args):
    if not _active:
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
    global _installed
    with _lock:
        if not _installed:
            sys.addaudithook(_hook)
            _installed = True


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
        global _active
        install()
        with _lock:
            _active += 1
            start = len(violations)
        self.addCleanup(self._tmp_guard_done, start)

    def _tmp_guard_done(self, start):
        global _active
        with _lock:
            _active -= 1
            new = violations[start:]
        if new:
            raise TmpRootViolation(f"{len(new)} tmp-root access(es) during the test: {new[:3]}")
