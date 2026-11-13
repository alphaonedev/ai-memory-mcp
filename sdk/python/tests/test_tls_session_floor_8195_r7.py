"""Round 7, code r6 F1: the session gate applies the 112-bit floor (#8195).

A unit test on the comparison: this host's OpenSSL offers no suite below 112 bits, so there is no wire
row for it. The gate used ``bits > 0``; the construction predicate already used 112.
"""
from __future__ import annotations

import ssl
from types import SimpleNamespace

import pytest

from ai_memory import _common


def _facts(bits: int) -> SimpleNamespace:
    return SimpleNamespace(
        context=_CONTEXT,
        peer={"subjectAltName": (("DNS", "localhost"),)},
        negotiated=("ECDHE-RSA-AES256-GCM-SHA384", "TLSv1.2", bits),
        version="TLSv1.2",
    )


_CONTEXT = ssl.create_default_context()


def test_session_gate_applies_the_112_bit_floor_8195(monkeypatch: pytest.MonkeyPatch) -> None:
    assert _common._MINIMUM_SUITE_STRENGTH_BITS == 112  # noqa: SLF001
    for bits, admitted in ((0, False), (1, False), (111, False), (112, True), (256, True)):
        monkeypatch.setattr(_common, "_session_facts", lambda _s, b=bits: _facts(b))
        if admitted:
            _common._assert_negotiated_session(object(), _CONTEXT, "localhost")  # noqa: SLF001
        else:
            with pytest.raises(ValueError, match="verify=False"):
                _common._assert_negotiated_session(object(), _CONTEXT, "localhost")  # noqa: SLF001
