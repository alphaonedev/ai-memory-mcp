# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""``_open_checked`` never re-resolves the path after its check (#6317).

On a platform with no ``O_NOFOLLOW`` the owner-only reader used to check the
credential with ``lstat`` and then read it BY PATH, so the bytes read were not
the bytes checked: a file swapped in between the two (another file, a link, a
looser mode) was read as if it had passed. The Python twin of #3812.

The leg is reached here on POSIX by removing ``os.O_NOFOLLOW``; the swap is
made right after the first owner check, which is exactly the check-then-use
window. The fixed leg opens once, ``fstat``\\ s the descriptor, compares
device / inode / owner / mode with the checked ``lstat`` and refuses on any
mismatch; the caller always reads from that descriptor.
"""

from __future__ import annotations

import os
import pathlib
import stat
import sys
from collections.abc import Callable

import pytest

from ai_memory import _ownedfile

pytestmark = pytest.mark.skipif(
    sys.platform == "win32", reason="the swap is simulated with POSIX file modes"
)

#: Content of the credential that was checked, and of the file swapped in.
CHECKED_CONTENT = b"checked-credential"
SWAPPED_CONTENT = b"swapped-in-content"
OWNER_ONLY_MODE = 0o600
LOOSE_MODE = 0o644


class _Refused(Exception):
    """The caller's refusal type (WakeError / KeyFileError in production)."""


def _owner_only(path: pathlib.Path, content: bytes) -> pathlib.Path:
    path.write_bytes(content)
    path.chmod(OWNER_ONLY_MODE)
    return path


@pytest.fixture
def no_nofollow(monkeypatch: pytest.MonkeyPatch) -> None:
    """Take the platform leg that has no ``O_NOFOLLOW`` (Windows)."""
    monkeypatch.delattr(os, "O_NOFOLLOW", raising=False)


def _swap_after_first_check(monkeypatch: pytest.MonkeyPatch, swap: Callable[[], None]) -> None:
    """Run ``swap`` right after the first owner check passes."""
    real = _ownedfile.check_owned_stat
    calls = {"n": 0}

    def checked_then_swapped(*args: object, **kwargs: object) -> None:
        real(*args, **kwargs)  # type: ignore[arg-type]
        calls["n"] += 1
        if calls["n"] == 1:
            swap()

    monkeypatch.setattr(_ownedfile, "check_owned_stat", checked_then_swapped)


def _read(path: pathlib.Path) -> bytes:
    return _ownedfile.read_owner_only_bytes(path, error=_Refused)


@pytest.mark.usefixtures("no_nofollow")
def test_unchanged_credential_reads_on_the_no_nofollow_leg_6317(tmp_path: pathlib.Path) -> None:
    key = _owner_only(tmp_path / "key", CHECKED_CONTENT)
    assert _read(key) == CHECKED_CONTENT
    assert _ownedfile.read_owner_only_text(key, error=_Refused) == CHECKED_CONTENT.decode()


@pytest.mark.usefixtures("no_nofollow")
def test_no_nofollow_leg_returns_the_checked_descriptor_6317(tmp_path: pathlib.Path) -> None:
    key = _owner_only(tmp_path / "key", CHECKED_CONTENT)
    fd = _ownedfile._open_checked(key, error=_Refused, mode_advice="advice")
    assert isinstance(fd, int), "the caller must read the checked descriptor, never the path"
    try:
        assert os.fstat(fd).st_ino == key.stat().st_ino
    finally:
        os.close(fd)


@pytest.mark.usefixtures("no_nofollow")
def test_file_swapped_after_the_check_is_refused_6317(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    key = _owner_only(tmp_path / "key", CHECKED_CONTENT)
    other = _owner_only(tmp_path / "other", SWAPPED_CONTENT)
    _swap_after_first_check(monkeypatch, lambda: os.replace(other, key))
    with pytest.raises(_Refused, match="changed between"):
        _read(key)


@pytest.mark.usefixtures("no_nofollow")
def test_symlink_swapped_after_the_check_is_refused_6317(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    key = _owner_only(tmp_path / "key", CHECKED_CONTENT)
    target = _owner_only(tmp_path / "target", SWAPPED_CONTENT)

    def to_link() -> None:
        key.unlink()
        key.symlink_to(target)

    _swap_after_first_check(monkeypatch, to_link)
    with pytest.raises(_Refused, match="changed between"):
        _read(key)


@pytest.mark.usefixtures("no_nofollow")
def test_mode_loosened_after_the_check_is_refused_6317(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    key = _owner_only(tmp_path / "key", CHECKED_CONTENT)
    _swap_after_first_check(monkeypatch, lambda: key.chmod(LOOSE_MODE))
    with pytest.raises(_Refused):
        _read(key)


@pytest.mark.usefixtures("no_nofollow")
def test_text_reader_swap_is_refused_6317(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    key = _owner_only(tmp_path / "key", CHECKED_CONTENT)
    other = _owner_only(tmp_path / "other", SWAPPED_CONTENT)
    _swap_after_first_check(monkeypatch, lambda: os.replace(other, key))
    with pytest.raises(_Refused, match="changed between"):
        _ownedfile.read_owner_only_text(key, error=_Refused)


@pytest.mark.usefixtures("no_nofollow")
def test_symlink_at_check_time_is_still_refused_6317(tmp_path: pathlib.Path) -> None:
    target = _owner_only(tmp_path / "target", CHECKED_CONTENT)
    link = tmp_path / "link"
    link.symlink_to(target)
    with pytest.raises(_Refused, match="symlink"):
        _read(link)


@pytest.mark.usefixtures("no_nofollow")
def test_fifo_at_check_time_is_refused_without_an_open_6317(tmp_path: pathlib.Path) -> None:
    fifo = tmp_path / "fifo"
    os.mkfifo(fifo, OWNER_ONLY_MODE)
    assert stat.S_ISFIFO(fifo.lstat().st_mode)
    with pytest.raises(_Refused):
        _read(fifo)
