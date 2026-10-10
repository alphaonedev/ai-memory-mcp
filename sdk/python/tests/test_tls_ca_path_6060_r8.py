# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""The CA-path rule under a concurrent change, round 8 of #6060.

Round 7 left an untyped ``OSError`` from the ``os.fstat`` of the opened CA file
(#6829) and three branches of the post-open walk that no test pinned (#6959:
a failed re-check lstat, the device number, the second walk itself). Each test
here drives one interleaving deterministically.
"""

from __future__ import annotations

import errno
import os
import pathlib
import ssl
from typing import Any, Callable

import pytest

from ai_memory import _common

from ._tlslab import Lab
from .test_tls_session_6060_r5 import _CLIENTS, _POSIX_ONLY, _built, _bundle, _ca_dir


@pytest.fixture(scope="module")
def lab(tmp_path_factory: pytest.TempPathFactory) -> Lab:
    return Lab(tmp_path_factory.mktemp("lab6060r8"))


# ---- #6829: the opened file's fstat is the typed refusal, never a raw OSError


@_POSIX_ONLY
@pytest.mark.parametrize("client_cls", _CLIENTS)
@pytest.mark.parametrize("code", [errno.EIO, errno.ESTALE, errno.ENOENT])
def test_fstat_of_the_opened_ca_file_failing_is_a_value_error_6829(
    lab: Lab,
    tmp_path: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
    client_cls: type,
    code: int,
) -> None:
    """The descriptor was opened a moment ago; its ``fstat`` failing is a changed file."""
    bundle = _bundle(lab, _ca_dir(tmp_path))
    real_open, real_fstat = os.open, os.fstat
    opened: set[int] = set()

    def tracking_open(path: Any, *args: Any, **kwargs: Any) -> int:
        fd = real_open(path, *args, **kwargs)
        if os.fspath(path) == str(bundle.resolve()):
            opened.add(fd)
        return fd

    def failing_fstat(fd: Any, *args: Any, **kwargs: Any) -> os.stat_result:
        if fd in opened:
            raise OSError(code, os.strerror(code))
        return real_fstat(fd, *args, **kwargs)

    monkeypatch.setattr(os, "open", tracking_open)
    monkeypatch.setattr(os, "fstat", failing_fstat)
    with pytest.raises(ValueError, match="#6829") as refused:
        _built(client_cls, str(bundle))
    assert opened, "the CA file must have been opened for the injected fstat to matter"
    assert str(bundle) in str(refused.value)


# ---- #6959 / #6963: the second walk after the open (#6828) is pinned branch by branch


def _walk_two(
    monkeypatch: pytest.MonkeyPatch, *, before: Callable[[], None], after: Callable[[], None]
) -> None:
    """Run ``before`` / ``after`` around the SECOND ``_checked_realpath`` of one load.

    The first walk resolves the entry before the open; the second is the
    re-walk that must end at the inode the descriptor holds.
    """
    real_walk = _common._checked_realpath
    calls = {"n": 0}

    def walk(path: str) -> str:
        calls["n"] += 1
        second = calls["n"] == 2
        if second:
            before()
        resolved = real_walk(path)
        if second:
            after()
        return resolved

    monkeypatch.setattr(_common, "_checked_realpath", walk)


def _load(ca: pathlib.Path) -> None:
    _common._load_trust_file(ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT), str(ca), str(ca))


def _lstat_of(
    monkeypatch: pytest.MonkeyPatch, target: pathlib.Path, answer: Callable[[os.stat_result], Any]
) -> None:
    """Make ``os.lstat(target)`` (that path only) answer through ``answer``."""
    real_lstat = os.lstat
    wanted = str(target.resolve())

    def lstat(path: Any, *args: Any, **kwargs: Any) -> os.stat_result:
        found = real_lstat(path, *args, **kwargs)
        if os.fspath(path) == wanted:
            return answer(found)  # type: ignore[no-any-return]
        return found

    monkeypatch.setattr(os, "lstat", lstat)


@pytest.fixture
def ca_in_mid(lab: Lab, tmp_path: pathlib.Path) -> tuple[pathlib.Path, pathlib.Path]:
    """``<tmp>/outer/mid/ca.pem``, every directory 0755, the file 0644."""
    mid = _ca_dir(tmp_path, "outer")
    inner = mid / "mid"
    inner.mkdir()
    inner.chmod(0o755)
    return _bundle(lab, inner), inner


@_POSIX_ONLY
def test_directory_made_group_writable_after_the_open_is_refused_6959(
    monkeypatch: pytest.MonkeyPatch, ca_in_mid: tuple[pathlib.Path, pathlib.Path]
) -> None:
    """Kills the mutant that skips the re-walk's holder rule (walk of ``real``, not ``entry``)."""
    ca, mid = ca_in_mid
    _walk_two(monkeypatch, before=lambda: mid.chmod(0o775), after=lambda: None)
    with pytest.raises(ValueError, match="writable"):
        _load(ca)


@_POSIX_ONLY
def test_relstat_reporting_another_device_after_the_open_is_refused_6959(
    monkeypatch: pytest.MonkeyPatch, ca_in_mid: tuple[pathlib.Path, pathlib.Path]
) -> None:
    """Kills the mutant that compares ``st_ino`` alone: an inode number repeats across devices."""
    ca, _ = ca_in_mid

    def other_device(found: os.stat_result) -> os.stat_result:
        values = list(found)
        values[2] = found.st_dev + 1
        return os.stat_result(values)

    _walk_two(
        monkeypatch, before=lambda: None, after=lambda: _lstat_of(monkeypatch, ca, other_device)
    )
    with pytest.raises(ValueError, match="#6828"):
        _load(ca)


@_POSIX_ONLY
def test_entry_vanishing_at_the_relstat_is_refused_not_matched_6959(
    monkeypatch: pytest.MonkeyPatch, ca_in_mid: tuple[pathlib.Path, pathlib.Path]
) -> None:
    """Kills the mutant that treats a failed re-lstat as "the same inode"."""
    ca, _ = ca_in_mid

    def vanished(found: os.stat_result) -> os.stat_result:
        raise FileNotFoundError(errno.ENOENT, "injected", str(ca))

    _walk_two(monkeypatch, before=lambda: None, after=lambda: _lstat_of(monkeypatch, ca, vanished))
    with pytest.raises(ValueError, match="#6828"):
        _load(ca)
