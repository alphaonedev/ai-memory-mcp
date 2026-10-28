# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""The owner-only credential reader's owner check and single-descriptor read (#6963).

Round 7 mutation testing found two controls of ``ai_memory._ownedfile`` that no
test noticed losing:

* S18: the ``st_uid != geteuid()`` refusal replaced by ``if False``. A ``0600``
  file owned by someone else (a restore, a copy, a root caller) was accepted.
* S19: the read re-opened the path (``p.read_bytes()``) instead of draining the
  descriptor the checks were proven against, so a swap between ``fstat`` and
  the read was read instead of refused-or-ignored.
"""

from __future__ import annotations

import json
import os
import pathlib
import sys
from typing import Any

import pytest

from ai_memory import _ownedfile
from ai_memory.attestation import AgentSigningKey, KeyFileError
from ai_memory.wake import DelegationBundle, WakeError

pytestmark = pytest.mark.skipif(sys.platform == "win32", reason="owner-only modes are POSIX")


def _foreign_owner(monkeypatch: pytest.MonkeyPatch) -> None:
    """Every ``fstat`` in the reader reports uid + 1 (the file belongs to someone else)."""
    real = os.fstat

    def fstat(fd: Any, *args: Any, **kwargs: Any) -> os.stat_result:
        found = real(fd, *args, **kwargs)
        values = list(found)
        values[4] = found.st_uid + 1
        return os.stat_result(values)

    monkeypatch.setattr(os, "fstat", fstat)


def _mk(directory: pathlib.Path, name: str, data: bytes) -> pathlib.Path:
    path = directory / name
    path.write_bytes(data)
    path.chmod(0o600)
    return path


def _refusal(message: str) -> ValueError:
    return ValueError(message)


def test_a_0600_file_owned_by_another_uid_is_refused_by_the_reader_6963(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = _mk(tmp_path, "other.bin", b"OTHER-OWNER")
    _foreign_owner(monkeypatch)
    with pytest.raises(ValueError, match="owned by uid"):
        _ownedfile.read_owner_only_bytes(path, error=_refusal)
    with pytest.raises(ValueError, match="owned by uid"):
        _ownedfile.read_owner_only_text(path, error=_refusal)


def test_a_0600_signing_key_owned_by_another_uid_is_refused_6963(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = _mk(tmp_path, "k.priv", bytes(range(32)))
    assert AgentSigningKey.from_file(path).seed_bytes() == bytes(range(32))
    _foreign_owner(monkeypatch)
    with pytest.raises(KeyFileError, match="owned by uid"):
        AgentSigningKey.from_file(path)


def test_a_0600_delegation_bundle_owned_by_another_uid_is_refused_6963(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = _mk(tmp_path, "b.json", json.dumps({"version": 1}).encode())
    _foreign_owner(monkeypatch)
    with pytest.raises(WakeError, match="owned by uid"):
        DelegationBundle.load(path, hub_id="hub-6963")


@pytest.mark.parametrize("text", [False, True], ids=["bytes", "text"])
def test_a_path_swapped_after_the_fstat_is_not_read_6963(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch, text: bool
) -> None:
    """The bytes come from the descriptor that was checked, never from the path again."""
    good = _mk(tmp_path, "d.bin", b"ORIGINAL")
    real = os.fstat
    swapped = {"done": False}

    def fstat(fd: Any, *args: Any, **kwargs: Any) -> os.stat_result:
        found = real(fd, *args, **kwargs)
        if not swapped["done"]:
            swapped["done"] = True
            os.replace(_mk(tmp_path, "evil.bin", b"EVIL"), good)
        return found

    monkeypatch.setattr(_ownedfile.os, "fstat", fstat)
    reader = _ownedfile.read_owner_only_text if text else _ownedfile.read_owner_only_bytes
    got = reader(good, error=_refusal)
    assert swapped["done"], "the swap must have happened between the fstat and the read"
    assert got in (b"ORIGINAL", "ORIGINAL")
