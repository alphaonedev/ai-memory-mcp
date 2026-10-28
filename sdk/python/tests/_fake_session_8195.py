"""Test seam: let a duck-typed stand-in session stand for a handshaken C session (#8195 round 7).

The SDK reads a negotiated session through the C ``_ssl._SSLSocket`` (sec r6 S1-wire), which a Python
stand-in cannot be. ``install`` swaps ``_common._session_facts`` for a reader that takes a stand-in's
``context`` / ``getpeercert()`` / ``cipher()`` / ``version()`` and defers to the real reader for
everything else, so the branch tests keep exercising the gate's decisions.
"""
from __future__ import annotations

from typing import Any

import pytest

from ai_memory import _common


class _Facts:
    def __init__(self, session: Any) -> None:
        self.context = session.context
        getpeercert = getattr(session, "getpeercert", None)
        self.peer = None if getpeercert is None else getpeercert()
        cipher = getattr(session, "cipher", None)
        self.negotiated = None if cipher is None else cipher()
        version = getattr(session, "version", None)
        self.version = None if version is None else version()


def install(monkeypatch: pytest.MonkeyPatch) -> None:
    real = _common._session_facts  # noqa: SLF001

    def reader(session: object) -> Any:
        if (
            session is not None
            and type(session) is not _common._C_SSLOBJ  # noqa: SLF001
            and hasattr(session, "context")
            and not hasattr(session, "_sslobj")
        ):
            return _Facts(session)
        return real(session)

    monkeypatch.setattr(_common, "_session_facts", reader)
