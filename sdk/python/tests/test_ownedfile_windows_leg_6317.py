# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""The no-``O_NOFOLLOW`` leg of the owner-only reader is bound to a descriptor
(#6317, the Python twin of the TypeScript #3812 fix).

On a platform without ``os.O_NOFOLLOW`` the reader ran ``lstat`` + the mode and
owner checks, then read the credential BY PATH, so a file swapped in after the
check was read unchecked. The fix opens once, ``fstat``\\ s that descriptor,
applies every check to it and reads it.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from ai_memory import _ownedfile


class Refused(Exception):
    pass


def test_windows_leg_never_reads_a_file_swapped_in_after_the_check_6317(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    cred = tmp_path / "cred"
    cred.write_bytes(b"checked")
    cred.chmod(0o600)
    swapped = tmp_path / "swapped"
    swapped.write_bytes(b"UNCHECKED-SECRET")
    swapped.chmod(0o644)

    monkeypatch.delattr(os, "O_NOFOLLOW", raising=False)
    real_lstat = Path.lstat

    def swap_after_precheck(self: Path, *a, **k):  # type: ignore[no-untyped-def]
        st = real_lstat(self, *a, **k)
        if self == cred:
            os.replace(swapped, cred)
        return st

    monkeypatch.setattr(Path, "lstat", swap_after_precheck)

    with pytest.raises(Refused, match="mode 0644"):
        _ownedfile.read_owner_only_bytes(cred, error=Refused)


def test_windows_leg_still_reads_a_good_file_6317(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    cred = tmp_path / "cred"
    cred.write_bytes(b"good")
    cred.chmod(0o600)
    monkeypatch.delattr(os, "O_NOFOLLOW", raising=False)
    assert _ownedfile.read_owner_only_bytes(cred, error=Refused) == b"good"
    assert _ownedfile.read_owner_only_text(cred, error=Refused) == "good"
