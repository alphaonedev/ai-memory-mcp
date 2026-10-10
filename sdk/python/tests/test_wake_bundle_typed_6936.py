# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""A malformed delegation bundle is a typed refusal that holds no bundle bytes (#6936).

``DelegationBundle.load`` documents "Every failure is a refusal". A bundle that
was not JSON, or not UTF-8, used to escape as a raw ``JSONDecodeError`` /
``UnicodeDecodeError``. Both carry the WHOLE file (``.doc`` / ``.object``), and
the file holds ``delegate_private_b64``, so an error reporter that serialises
exception attributes would export the delegated private key.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from ai_memory.wake import DelegationBundle, WakeError

HUB_ID = "hub-6936-py"
MARKER = "SEED-MARKER-6936-do-not-leak"

pytestmark = pytest.mark.skipif(sys.platform == "win32", reason="owner-only modes are POSIX")


def _bundle(tmp_path: Path, data: bytes) -> Path:
    path = tmp_path / "bundle.json"
    path.write_bytes(data)
    path.chmod(0o600)
    return path


def _chain(exc: BaseException) -> list[BaseException]:
    seen: list[BaseException] = []
    cur: BaseException | None = exc
    while cur is not None and cur not in seen:
        seen.append(cur)
        cur = cur.__cause__ or cur.__context__
    return seen


def _holds_marker(exc: BaseException) -> bool:
    for link in _chain(exc):
        if MARKER in str(link) or MARKER in repr(link):
            return True
        for value in vars(link).values():
            blob = value if isinstance(value, (str, bytes)) else b""
            if isinstance(blob, str):
                blob = blob.encode()
            if MARKER.encode() in blob:
                return True
        for attr in ("doc", "object"):
            blob = getattr(link, attr, None)
            if isinstance(blob, str):
                blob = blob.encode()
            if isinstance(blob, bytes) and MARKER.encode() in blob:
                return True
    return False


@pytest.mark.parametrize(
    ("data", "klass"),
    [
        (('{"delegate_private_b64": "' + MARKER + '", ').encode(), "JSONDecodeError"),
        (b'{"delegate_private_b64": "' + MARKER.encode() + b'\xff\xfe"}', "UnicodeDecodeError"),
    ],
    ids=["invalid-json", "invalid-utf8"],
)
def test_a_malformed_bundle_is_a_wake_error_naming_only_the_class_6936(
    tmp_path: Path, data: bytes, klass: str
) -> None:
    path = _bundle(tmp_path, data)
    with pytest.raises(WakeError) as caught:
        DelegationBundle.load(path, hub_id=HUB_ID)
    assert klass in str(caught.value)
    assert MARKER not in str(caught.value)


@pytest.mark.parametrize(
    "data",
    [
        ('{"delegate_private_b64": "' + MARKER + '", ').encode(),
        b'{"delegate_private_b64": "' + MARKER.encode() + b'\xff\xfe"}',
    ],
    ids=["invalid-json", "invalid-utf8"],
)
def test_no_link_of_the_refusal_chain_holds_the_bundle_bytes_6936(
    tmp_path: Path, data: bytes
) -> None:
    path = _bundle(tmp_path, data)
    with pytest.raises(WakeError) as caught:
        DelegationBundle.load(path, hub_id=HUB_ID)
    assert caught.value.__cause__ is None
    assert caught.value.__suppress_context__ is True
    assert not _holds_marker(caught.value)
