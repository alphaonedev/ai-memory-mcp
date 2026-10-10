# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""The CA-path rule under a concurrent directory change, round 7 of #6060.

The 3-agent vote (6def5ab6) holds every directory a CA path passes through
to the CA-directory rule. Round 6 showed the check could still load a CA from
a directory the rule refuses when that directory changes while the check runs
(#6828): a component that was missing during the walk skipped the holder rule,
and the opened file was never tied to the checked walk. These tests drive each
interleaving deterministically, sync and async.
"""

from __future__ import annotations

import os
import pathlib
import shutil
import ssl
from typing import Any, Callable

import certifi
import pytest

from ai_memory import _common

from ._tlslab import Lab
from .test_tls_session_6060_r5 import (
    _CLIENTS,
    _FOREIGN_UID,
    _POSIX_ONLY,
    _as_foreign,
    _built,
    _bundle,
    _ca_dir,
)


@pytest.fixture(scope="module")
def lab(tmp_path_factory: pytest.TempPathFactory) -> Lab:
    return Lab(tmp_path_factory.mktemp("lab6060r7"))


def _evil_dir(parent: pathlib.Path, name: str = "stage") -> pathlib.Path:
    """A directory holding ``ca.pem`` with anchors the caller never named."""
    directory = _ca_dir(parent, name)
    shutil.copy(certifi.where(), directory / "ca.pem")
    (directory / "ca.pem").chmod(0o644)
    return directory


def _foreign(monkeypatch: pytest.MonkeyPatch, *paths: pathlib.Path) -> None:
    """Report ``paths`` (by inode, so across renames) as owned by another user."""
    for path in paths:
        found = os.lstat(path)
        inode = (found.st_dev, found.st_ino)
        for name in ("stat", "lstat", "fstat"):
            monkeypatch.setattr(os, name, _as_foreign(getattr(os, name), inode, _FOREIGN_UID))


def _racy_base(load: Callable[[Callable[[], None]], None]) -> Callable[[], ssl.SSLContext]:
    """``_pinned_base_context`` whose ``load_verify_locations`` runs inside ``load``."""

    class Racy(ssl.SSLContext):
        def load_verify_locations(self, *args: Any, **kwargs: Any) -> None:
            load(lambda: super(Racy, self).load_verify_locations(*args, **kwargs))

    def base() -> ssl.SSLContext:
        context = Racy(ssl.PROTOCOL_TLS_CLIENT)
        context.verify_mode = ssl.CERT_REQUIRED
        context.check_hostname = True
        return context

    return base


# ---- #6828: a missing component is held to the rule of its directory ------


@_POSIX_ONLY
@pytest.mark.parametrize("client_cls", _CLIENTS)
@pytest.mark.parametrize("mode", [0o1777, 0o777], ids=oct)
@pytest.mark.parametrize("missing", ["certs/ca.pem", "ca.pem"])
def test_missing_component_in_a_shared_writable_directory_is_refused_6828(
    tmp_path: pathlib.Path, client_cls: type, mode: int, missing: str
) -> None:
    """Whoever can write ``pub`` can create the missing name after the walk passed it."""
    pub = _ca_dir(tmp_path, "pub", mode)
    with pytest.raises(ValueError, match="writable") as refused:
        _built(client_cls, str(pub / missing))
    assert f"whose directory {str(pub)!r}" in str(refused.value)


@_POSIX_ONLY
@pytest.mark.parametrize("client_cls", _CLIENTS)
@pytest.mark.parametrize("mode", [0o1777, 0o777], ids=oct)
def test_directory_created_during_the_walk_is_refused_6828(
    tmp_path: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
    client_cls: type,
    mode: int,
) -> None:
    """The round-6 interleaving (probe ``missing_race_r6.py det``), driven deterministically.

    Another user owns ``pub/stage`` and moves it to ``pub/certs`` (absent when
    each walk runs) right after each walk, and away again before the next.
    """
    pub = _ca_dir(tmp_path, "pub")
    stage = _evil_dir(pub)
    _foreign(monkeypatch, stage, stage / "ca.pem")
    pub.chmod(mode)
    certs = pub / "certs"
    walk = _common._checked_realpath
    calls: list[str] = []

    def interleaved(path: str) -> str:
        calls.append(path)
        if certs.exists():
            os.rename(certs, stage)
        resolved = walk(path)
        os.rename(stage, certs)
        return resolved

    monkeypatch.setattr(_common, "_checked_realpath", interleaved)
    with pytest.raises(ValueError):
        _built(client_cls, str(certs / "ca.pem"))


@_POSIX_ONLY
@pytest.mark.parametrize("client_cls", _CLIENTS)
def test_file_opened_is_the_file_the_walk_checked_6828(
    lab: Lab,
    tmp_path: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
    client_cls: type,
) -> None:
    """ABA: the open sees another file, the path is restored, then swapped again for the load.

    Only binding the opened inode to a walk made after the open refuses it: the
    walks see the right file, and the post-load re-check sees the same inode
    the open saw.
    """
    directory = _ca_dir(tmp_path)
    victim = _bundle(lab, directory)
    shutil.copy(certifi.where(), directory / "evil.pem")
    (directory / "evil.pem").chmod(0o644)
    real_open = os.open
    opened: list[str] = []

    def swap_in() -> None:
        os.rename(victim, directory / "good.pem")
        os.rename(directory / "evil.pem", victim)

    def swap_out() -> None:
        os.rename(victim, directory / "evil.pem")
        os.rename(directory / "good.pem", victim)

    def open_the_other(path: Any, flags: int, *args: Any, **kwargs: Any) -> int:
        if os.fspath(path) == str(victim) and not opened:
            opened.append(os.fspath(path))
            swap_in()
            try:
                return real_open(path, flags, *args, **kwargs)
            finally:
                swap_out()
        return real_open(path, flags, *args, **kwargs)

    def load_the_other(load: Callable[[], None]) -> None:
        swap_in()
        load()

    monkeypatch.setattr(os, "open", open_the_other)
    monkeypatch.setattr(_common, "_pinned_base_context", _racy_base(load_the_other))
    with pytest.raises(ValueError, match="changed"):
        _built(client_cls, str(victim))
    assert opened == [str(victim)]


# ---- #6829: a concurrent change is the typed refusal, never a raw OSError --


@_POSIX_ONLY
@pytest.mark.parametrize("client_cls", _CLIENTS)
def test_directory_removed_during_the_holder_check_is_a_value_error_6829(
    lab: Lab,
    tmp_path: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
    client_cls: type,
) -> None:
    """The directory holding the CA file is gone between the entry's lstat and its stat."""
    directory = _ca_dir(tmp_path)
    bundle = _bundle(lab, directory)
    real_stat = os.stat

    def vanished(target: Any, *args: Any, **kwargs: Any) -> os.stat_result:
        if os.fspath(target) == str(directory):
            raise FileNotFoundError(2, "No such file or directory", os.fspath(target))
        return real_stat(target, *args, **kwargs)

    monkeypatch.setattr(os, "stat", vanished)
    with pytest.raises(ValueError, match="#6829"):
        _built(client_cls, str(bundle))


@_POSIX_ONLY
@pytest.mark.parametrize("client_cls", _CLIENTS)
def test_file_removed_during_the_load_is_a_value_error_6829(
    lab: Lab,
    tmp_path: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
    client_cls: type,
) -> None:
    bundle = _bundle(lab, _ca_dir(tmp_path))

    def load_then_remove(load: Callable[[], None]) -> None:
        load()
        bundle.unlink()

    monkeypatch.setattr(_common, "_pinned_base_context", _racy_base(load_then_remove))
    with pytest.raises(ValueError, match="changed while it was being read"):
        _built(client_cls, str(bundle))


@_POSIX_ONLY
@pytest.mark.parametrize("client_cls", _CLIENTS)
def test_removed_working_directory_is_a_value_error_6829(
    monkeypatch: pytest.MonkeyPatch, client_cls: type
) -> None:
    """A relative CA path needs the working directory; one removed under us is refused."""

    def gone() -> str:
        raise FileNotFoundError(2, "No such file or directory")

    monkeypatch.setattr(os, "getcwd", gone)
    with pytest.raises(ValueError, match="#6829"):
        _built(client_cls, "ca.pem")


# ---- #6811: nothing follows a file, as the kernel says (ENOTDIR) ----------


@_POSIX_ONLY
@pytest.mark.parametrize("client_cls", _CLIENTS)
@pytest.mark.parametrize("suffix", ["/.", "/..", "/./", "/../ca.pem", "/../."])
def test_component_after_a_file_is_refused_6811(
    lab: Lab, tmp_path: pathlib.Path, client_cls: type, suffix: str
) -> None:
    """``ca.pem/.`` and ``ca.pem/..`` are ENOTDIR to the kernel; never ``ca.pem`` or its directory."""
    directory = _ca_dir(tmp_path)
    bundle = _bundle(lab, directory)
    with pytest.raises(ValueError, match="not a directory"):
        _built(client_cls, str(bundle) + suffix)
