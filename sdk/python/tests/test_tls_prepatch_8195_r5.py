"""A TLS bound replaced BEFORE ``ai_memory`` is imported is still refused (#8195 round 5, ``code r4 F3``).

``_STOCK_HANDSHAKE`` is captured at import, so a ``minimum_version`` / ``maximum_version`` descriptor
replaced before that import passes the stock-identity leg of ``_context_verifies``. The
``isinstance(..., ssl.TLSVersion)`` check in ``_tls_range_is_modern`` is then the only refusal: it
turns an ``int`` bound (the true value as a plain ``int``, or 771), a ``str`` or ``None`` bound into the
typed ``ValueError`` instead of an admitted context or an untyped ``TypeError``. A replacement that
reports a ``TLSVersion`` other than the context's real bound (``lie``) is refused too, because the
bounds are also read through the C-level ``getset_descriptor`` objects (resolved from the ``ssl.SSLContext`` MRO) and compared (sec r4 N2).
The ``int-raw`` form is the one only the type check refuses, so it kills mutant M66. The child runs
in a fresh interpreter so the import order is real.
"""
from __future__ import annotations

import os
import pathlib
import subprocess
import sys

import pytest

_TESTS = pathlib.Path(__file__).resolve().parent
_SDK = _TESTS.parent
_CHILD = _TESTS / "_prepatch_child_8195.py"


def _outcome(attr: str, kind: str) -> str:
    env = dict(os.environ, PYTHONPATH=str(_SDK))
    env.pop("SSL_CERT_FILE", None)
    env.pop("SSL_CERT_DIR", None)
    done = subprocess.run(
        [sys.executable, str(_CHILD), attr, kind], capture_output=True, text=True, env=env, timeout=120, check=False
    )
    lines = [ln for ln in done.stdout.splitlines() if ln.startswith("outcome=")]
    assert len(lines) == 1, f"child rc {done.returncode}: {done.stderr[-300:]}"
    return lines[0]


@pytest.mark.parametrize("kind", ["int-raw", "int-771", "str", "none", "lie"])
@pytest.mark.parametrize("attr", ["minimum_version", "maximum_version"])
def test_bound_replaced_before_import_is_refused_with_the_typed_error_8195(attr: str, kind: str) -> None:
    assert _outcome(attr, kind) == "outcome=REFUSED-ValueError"


_SUBST_CHILD = _TESTS / "_prepatch_subst_child_8195.py"


def _subst_lines(mode: str) -> list[str]:
    env = dict(os.environ, PYTHONPATH=str(_SDK))
    env.pop("SSL_CERT_FILE", None)
    env.pop("SSL_CERT_DIR", None)
    done = subprocess.run(
        [sys.executable, str(_SUBST_CHILD), mode], capture_output=True, text=True, env=env, timeout=120, check=False
    )
    assert done.returncode == 0, f"child rc {done.returncode}: {done.stderr[-300:]}"
    return done.stdout.splitlines()


def test_c_descriptors_are_the_real_getset_objects_of_the_ssl_context_mro_8195() -> None:
    import ssl

    from ai_memory import _common

    for name, found in (("minimum_version", _common._C_MIN_VERSION), ("maximum_version", _common._C_MAX_VERSION)):
        assert type(found).__name__ == "getset_descriptor"
        assert found.__objclass__ in ssl.SSLContext.__mro__
        assert found.__objclass__.__dict__[name] is found


def test_unresolved_c_descriptors_refuse_every_context_8195(monkeypatch: pytest.MonkeyPatch) -> None:
    import ssl

    from ai_memory import _common

    class _Plain:
        minimum_version = property(lambda self: 0)

    assert _common._resolve_c_bound((_Plain,), "minimum_version") is None
    assert _common._resolve_c_bound((ssl.SSLContext, _Plain), "minimum_version") is None
    context = ssl.create_default_context()
    assert _common._tls_range_is_modern(context) is True
    monkeypatch.setattr(_common, "_C_MIN_VERSION", None)
    assert _common._tls_range_is_modern(context) is False


@pytest.mark.parametrize("name", ["_C_VERIFY_MODE", "_C_CHECK_HOSTNAME", "_C_VERIFY_FLAGS"])
def test_unresolved_verification_descriptor_refuses_the_context_8195(
    monkeypatch: pytest.MonkeyPatch, name: str
) -> None:
    """code r5 F2: an unresolved C descriptor is a typed refusal, never an ``AttributeError``."""
    import ssl

    from ai_memory import _common

    context = ssl.create_default_context()
    assert _common._context_verifies(context) is True
    monkeypatch.setattr(_common, name, None)
    assert _common._context_verifies(context) is False


def test_resolver_refuses_a_descriptor_that_is_not_the_classs_own_getset_8195() -> None:
    import ssl

    from ai_memory import _common

    real_min = ssl.SSLContext.__mro__[1].__dict__["minimum_version"]
    real_max = ssl.SSLContext.__mro__[1].__dict__["maximum_version"]

    class _Foreign:  # holds a real getset whose __objclass__ is not on its MRO
        minimum_version = real_min

    class _Crossed(ssl.SSLContext):  # its minimum slot holds the maximum getset
        minimum_version = real_max

    class _NotGetset:
        minimum_version = 771

    assert _common._resolve_c_bound((ssl.SSLContext,), "minimum_version") is real_min
    assert _common._resolve_c_bound((_Foreign,), "minimum_version") is None
    assert _common._resolve_c_bound((ssl.SSLContext, _Crossed), "minimum_version") is None
    assert _common._resolve_c_bound((_NotGetset,), "minimum_version") is None


@pytest.mark.parametrize("mode", ["py-lie+attr", "py-lie+mods"])
def test_substituted_ssl_module_cannot_admit_a_tls_11_floor_8195(mode: str) -> None:
    """sec r5 S1: the C descriptors come from the real ``SSLContext`` MRO, not a ``_ssl`` lookup."""
    lines = _subst_lines(mode)
    assert "C_MIN is real getset: True" in lines
    assert "outcome=REFUSED-ValueError" in lines
