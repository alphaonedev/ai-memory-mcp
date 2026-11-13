# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""Tripwire (#6249, X-6): every SSLContext setting of the running Python is classified.

The carry-or-refuse engine in ``ai_memory._tls`` is only never-weaker for the
state it knows. Each data descriptor and each ``set_*`` / ``load_*`` mutator of
``ssl.SSLContext`` and its C base must be a row of ``VERIFICATION_SETTINGS``
(carried or refused), a key of ``NOT_VERIFICATION_RELEVANT`` (with a reason) or
a key of ``UNREADABLE_RESIDUALS`` (a named residual with no getter).
A new Python that adds one fails this test, by name, until it is classified.
The CI job ``sdk-python-tls-tripwire`` runs it on every declared Python and the
newest release.
"""

from __future__ import annotations

import sys

import pytest

from ai_memory import _tls

#: Where a failing attribute must be classified.
TABLE_HINT = (
    "VERIFICATION_SETTINGS, NOT_VERIFICATION_RELEVANT or UNREADABLE_RESIDUALS"
    " in sdk/python/ai_memory/_tls.py"
)
#: Names a stand-in future Python class adds for the self-test.
FUTURE_DESCRIPTOR = "future_verify_policy"
FUTURE_MUTATOR = "set_future_trust"


def _classified() -> frozenset[str]:
    names = {row.name for row in _tls.VERIFICATION_SETTINGS}
    names |= {mutator for row in _tls.VERIFICATION_SETTINGS for mutator in row.mutators}
    names |= set(_tls.NOT_VERIFICATION_RELEVANT)
    names |= set(_tls.UNREADABLE_RESIDUALS)
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
    for table in (_tls.NOT_VERIFICATION_RELEVANT, _tls.UNREADABLE_RESIDUALS):
        for name, reason in table.items():
            assert reason.strip(), name
            assert "\n" not in reason, name
    assert not set(_tls.NOT_VERIFICATION_RELEVANT) & set(_tls.UNREADABLE_RESIDUALS)


def test_6249_every_row_has_a_refusal_message() -> None:
    names = [row.name for row in _tls.VERIFICATION_SETTINGS]
    assert len(names) == len(set(names)), names
    for row in _tls.VERIFICATION_SETTINGS:
        assert row.message.startswith("verify=<{kind}> is refused: "), row.name
    assert not set(names) & set(_tls.NOT_VERIFICATION_RELEVANT)
    assert not set(names) & set(_tls.UNREADABLE_RESIDUALS)


def _future_class() -> type:
    """A stand-in future ``_ssl._SSLContext``: two settings the table already
    classifies plus one new property and one new mutator."""
    return type(
        "FuturePythonSSLContext",
        (),
        {
            "verify_mode": property(lambda self: None, lambda self, value: None),
            "set_ciphers": lambda self, value: None,
            FUTURE_DESCRIPTOR: property(lambda self: None, lambda self, value: None),
            FUTURE_MUTATOR: lambda self, value: None,
        },
    )


def test_6249_tripwire_names_a_new_attribute_and_the_table(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Self-test, independent of the live interpreter: the enumeration runs
    over the stand-in class only, so it is red or green for its own reason on
    every Python, and the failure message names both attributes and the table."""
    monkeypatch.setattr(_tls, "_SETTINGS_CLASSES", (_future_class(),))
    unclassified = _unclassified()
    assert unclassified == sorted([FUTURE_DESCRIPTOR, FUTURE_MUTATOR])
    version = sys.version.split()[0]
    assert _message(unclassified) == (
        f"Python {version} has SSLContext settings the ai-memory SDK does not classify: "
        f"{FUTURE_DESCRIPTOR}, {FUTURE_MUTATOR}; add each to "
        "VERIFICATION_SETTINGS, NOT_VERIFICATION_RELEVANT or UNREADABLE_RESIDUALS in "
        "sdk/python/ai_memory/_tls.py"
    )


#: The SSLContext mutators Python 3.15 adds (CI run 43159353048, 3.x cell).
PY315_MUTATORS = ("set_ciphersuites", "set_client_sigalgs", "set_groups", "set_server_sigalgs")


def test_6249_tripwire_classifies_the_python_3_15_mutators(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The tripwire, run against a stand-in class with the 3.15 mutators, finds
    nothing unclassified on every Python; dropping a row names that mutator."""
    assert set(_tls.PY315_MUTATORS) == set(PY315_MUTATORS)
    python315 = type(
        "Python315SSLContext", (), {name: (lambda self, value: None) for name in PY315_MUTATORS}
    )
    monkeypatch.setattr(_tls, "_SETTINGS_CLASSES", (python315,))
    descriptors, mutators = _tls.settings_surface()
    assert descriptors == frozenset()
    assert mutators == frozenset(PY315_MUTATORS)
    unclassified = _unclassified()
    assert unclassified == [], _message(unclassified)
