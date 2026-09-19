# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""ONE owner-only, descriptor-bound reader for every local credential the SDK
loads from disk (#3780, #3784).

Why this module exists
----------------------

#3780 gave the wake delegation-bundle loader a reader that opens the file
ONCE, ``fstat``\\ s THAT descriptor, applies every check to it, and reads the
bytes from the same descriptor. #3784 then found that
:meth:`ai_memory.attestation.AgentSigningKey.from_file` — which loads the raw
32-byte Ed25519 **agent private key** — still did a bare
``Path(path).read_bytes()``: no regular-file check, no ``mode & 0o077`` check,
no owner check. A key file left world-readable by a copy, a backup or a bad
umask signed attestations with a key any local uid could read, and the SDK
said nothing, while the daemon-side loader
(``src/identity/keypair.rs::read_private_key_file``) would have refused the
very same file.

Two loaders of local private keys with two different standards is how the
weaker one survives. So the discipline lives here, once, and both callers
import it. There is deliberately no second copy to drift.

The standard
------------

A file that holds a private credential must be, proven on ONE descriptor:

* a **regular file** — not a directory, not a FIFO (a FIFO parks the reader),
  not a device;
* mode ``& 0o077 == 0`` — no group or other bit, i.e. 0600-or-tighter;
* owned by the **effective uid** of the caller.

Reached by a **symlink** it is refused at the open, so a link in the key
directory can never have its permissions checked on the target.

Callers pass their own ``error`` factory (``WakeError``, ``KeyFileError``, …)
so each surface refuses in its own exception type, and their own
``mode_advice`` so the mode refusal names the real consequence for that
credential. The other two refusals are worded identically everywhere: the
reason does not change with the caller.
"""

from __future__ import annotations

import errno
import os
import stat
from pathlib import Path
from typing import Callable

__all__ = [
    "BUNDLE_MODE_ADVICE",
    "check_owned_stat",
    "read_owner_only_bytes",
    "read_owner_only_text",
]

#: The mode-refusal tail the #3780 wake bundle loader shipped, kept verbatim as
#: the default so that loader's wording is byte-identical after the move.
BUNDLE_MODE_ADVICE = (
    "a bundle holding a private key must be 0600, or another local user can "
    "join the hub as this agent"
)

_SYMLINK_REFUSAL = (
    "is a symlink: a credential reached through a link is one whose "
    "permissions were checked on the wrong file"
)


def check_owned_stat(
    p: Path,
    st: os.stat_result,
    *,
    error: Callable[[str], Exception],
    mode_advice: str = BUNDLE_MODE_ADVICE,
) -> None:
    """Apply the credential's on-disk standard to an ALREADY-OBTAINED stat.

    Split out so the descriptor-bound path (:func:`os.fstat`) and the Windows
    path-based fallback refuse with the SAME words. ``p`` is only ever used to
    word the message; nothing here resolves it again. No refusal ever renders
    the file's CONTENT — the message names the path, the reason and (for the
    mode) the offending bits, and nothing else.
    """
    if not stat.S_ISREG(st.st_mode):
        raise error(f"{p} is not a regular file")
    if st.st_mode & 0o077:
        raise error(f"{p} is mode {st.st_mode & 0o7777:04o}; {mode_advice}")
    if st.st_uid != os.geteuid():
        raise error(f"{p} is owned by uid {st.st_uid}, not by the caller")


def _open_checked(
    p: Path,
    *,
    error: Callable[[str], Exception],
    mode_advice: str,
) -> int | None:
    """Open ``p`` once and prove the standard on THAT descriptor.

    Returns the open descriptor — the caller owns it and must close it — or
    ``None`` on a platform with no ``O_NOFOLLOW``, in which case the
    path-based check has ALREADY been applied and the caller reads by path.

    ``p.lstat()`` followed by ``p.read_bytes()`` resolves the path TWICE, and
    the bytes that are read are not the bytes that were checked. A local user
    who can write in the key directory wins that window twice over: swap a
    symlink in and the SDK reads a file it refused a moment earlier
    (confused-deputy read); swap a FIFO in and the second open PARKS the
    process, with no credential needed (availability). So: open ONCE,
    ``fstat`` THAT descriptor, apply every check to it, and read from it.

    ``O_NOFOLLOW`` refuses a symlink AT THE OPEN, so a link in the key
    directory can never have its permissions checked on the target.
    ``O_NONBLOCK`` keeps a FIFO planted at this path from parking the open; the
    regular-file check then refuses it. ``O_CLOEXEC`` keeps the descriptor out
    of any child this process spawns while the credential is being read. This
    is the pattern the Rust tree already ships in ``src/wake_client/bundle.rs``
    (``open_owner_only``), modelled in turn on ``AllowlistCache::open_checked``
    (#3504).

    **Platform caveat:** Windows has no ``O_NOFOLLOW`` and no ``O_NONBLOCK``,
    so there is no way to bind the check to the descriptor there. That leg
    keeps the historical path-based check-then-read, unchanged and still racy
    (and, as before #3780, still requiring a POSIX ``os.geteuid``), and says so
    rather than pretending otherwise. The hub socket and the key directory this
    loader serves are POSIX-only surfaces today.
    """
    no_follow = getattr(os, "O_NOFOLLOW", 0)
    non_block = getattr(os, "O_NONBLOCK", 0)
    if not no_follow:
        # Windows. Documented above: the pre-#3780 shape, verbatim.
        st = p.lstat()
        if stat.S_ISLNK(st.st_mode):
            raise error(f"{p} {_SYMLINK_REFUSAL}")
        check_owned_stat(p, st, error=error, mode_advice=mode_advice)
        return None

    flags = os.O_RDONLY | no_follow | non_block | getattr(os, "O_CLOEXEC", 0)
    try:
        fd = os.open(p, flags)
    except OSError as err:
        # ELOOP is what O_NOFOLLOW reports for a symlink on Linux and macOS
        # (EMLINK on the BSDs). Kept as its own refusal so the operator is told
        # what is actually wrong rather than handed a bare errno.
        if err.errno in (errno.ELOOP, errno.EMLINK):
            raise error(f"{p} {_SYMLINK_REFUSAL}") from err
        raise
    try:
        # fstat on the descriptor just opened — never a second look at the path.
        check_owned_stat(p, os.fstat(fd), error=error, mode_advice=mode_advice)
    except BaseException:
        os.close(fd)
        raise
    return fd


def _drain(fd: int) -> bytes:
    chunks: list[bytes] = []
    while True:
        chunk = os.read(fd, 65536)
        if not chunk:
            break
        chunks.append(chunk)
    return b"".join(chunks)


def read_owner_only_bytes(
    p: Path,
    *,
    error: Callable[[str], Exception],
    mode_advice: str = BUNDLE_MODE_ADVICE,
) -> bytes:
    """Read a credential no other local user could read or replace, through
    ONE descriptor. Raw bytes — nothing is decoded or newline-translated,
    because a 32-byte Ed25519 seed is not text.
    """
    fd = _open_checked(p, error=error, mode_advice=mode_advice)
    if fd is None:
        return p.read_bytes()
    try:
        return _drain(fd)
    finally:
        os.close(fd)


def read_owner_only_text(
    p: Path,
    *,
    error: Callable[[str], Exception],
    mode_advice: str = BUNDLE_MODE_ADVICE,
) -> str:
    """:func:`read_owner_only_bytes`, decoded as UTF-8, for JSON credentials."""
    fd = _open_checked(p, error=error, mode_advice=mode_advice)
    if fd is None:
        return p.read_text(encoding="utf-8")
    try:
        return _drain(fd).decode("utf-8")
    finally:
        os.close(fd)
