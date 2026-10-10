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
from typing import Any

import pytest

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
