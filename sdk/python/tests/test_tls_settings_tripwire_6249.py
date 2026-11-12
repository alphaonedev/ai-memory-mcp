# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""Tripwire (#6249, X-6): every SSLContext setting of the running Python is classified.

The carry-or-refuse engine in ``ai_memory._tls`` is only never-weaker for the
state it knows. Each data descriptor and each ``set_*`` / ``load_*`` mutator of
``ssl.SSLContext`` and its C base must be a row of ``VERIFICATION_SETTINGS``
(carried or refused) or a key of ``NOT_VERIFICATION_RELEVANT`` (with a reason).
A new Python that adds one fails this test, by name, until it is classified.
The CI job ``sdk-python-tls-tripwire`` runs it on every declared Python and the
newest release.
"""

from __future__ import annotations

import sys

import pytest

from ai_memory import _tls

#: Where a failing attribute must be classified.
TABLE_HINT = "VERIFICATION_SETTINGS or NOT_VERIFICATION_RELEVANT in sdk/python/ai_memory/_tls.py"
#: Names a stand-in future Python class adds for the self-test.
FUTURE_DESCRIPTOR = "future_verify_policy"
FUTURE_MUTATOR = "set_future_trust"


def _classified() -> frozenset[str]:
    names = {row.name for row in _tls.VERIFICATION_SETTINGS}
    names |= {mutator for row in _tls.VERIFICATION_SETTINGS for mutator in row.mutators}
    names |= set(_tls.NOT_VERIFICATION_RELEVANT)
    return frozenset(names)


def _unclassified() -> list[str]:
    descriptors, mutators = _tls.settings_surface()
    return sorted((descriptors | mutators) - _classified())


def _message(names: list[str]) -> str:
    return (
        f"Python {sys.version.split()[0]} has SSLContext settings the ai-memory SDK does "
        f"not classify: {', '.join(names)}; add each to {TABLE_HINT}"
    )


def test_6249_every_sslcontext_setting_is_classified() -> None:
    unclassified = _unclassified()
    assert not unclassified, _message(unclassified)


def test_6249_the_surface_is_not_empty() -> None:
    """The enumeration itself works (an empty surface would pass vacuously)."""
    descriptors, mutators = _tls.settings_surface()
    assert {"verify_mode", "check_hostname", "verify_flags", "options"} <= descriptors
    assert {"load_verify_locations", "set_ciphers"} <= mutators


def test_6249_every_irrelevant_setting_has_a_one_line_reason() -> None:
    for name, reason in _tls.NOT_VERIFICATION_RELEVANT.items():
        assert reason.strip(), name
        assert "\n" not in reason, name


def test_6249_every_row_has_a_refusal_message() -> None:
    names = [row.name for row in _tls.VERIFICATION_SETTINGS]
    assert len(names) == len(set(names)), names
    for row in _tls.VERIFICATION_SETTINGS:
        assert row.message.startswith("verify=<{kind}> is refused: "), row.name
    assert not set(names) & set(_tls.NOT_VERIFICATION_RELEVANT)


def test_6249_tripwire_names_a_new_attribute_and_the_table(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Self-test: a class with a new property and a new mutator trips by name."""
    future = type(
        "FuturePythonSSLContext",
        (),
        {
            FUTURE_DESCRIPTOR: property(lambda self: None, lambda self, value: None),
            FUTURE_MUTATOR: lambda self, value: None,
        },
    )
    classes = (*_tls._SETTINGS_CLASSES, future)
    monkeypatch.setattr(_tls, "_SETTINGS_CLASSES", classes)
    unclassified = _unclassified()
    assert unclassified == sorted([FUTURE_DESCRIPTOR, FUTURE_MUTATOR])
    message = _message(unclassified)
    assert FUTURE_DESCRIPTOR in message
    assert FUTURE_MUTATOR in message
    assert TABLE_HINT in message
