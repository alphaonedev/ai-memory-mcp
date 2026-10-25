"""Child process for ``test_tls_prepatch_8195_r5``: substitute ``_ssl`` BEFORE ``ai_memory`` is imported.

usage: ``python _prepatch_subst_child_8195.py <py-lie+attr|py-lie+mods>`` (sec r5 S1).

The caller's context really has a TLS 1.1 floor in the C object. ``ssl.SSLContext.minimum_version``
is replaced by a property reporting TLS 1.2 (``py-lie``) and, before ``ai_memory`` is imported, the
reference the SDK could read the C-level descriptors from is substituted too: the ``_ssl._SSLContext``
module attribute (``py-lie+attr``) or the ``sys.modules["_ssl"]`` entry (``py-lie+mods``), with a
stand-in class whose ``minimum_version`` also reports TLS 1.2. The child prints
``C_MIN is real getset: <bool>`` and ``outcome=<REFUSED-ValueError|ADMITTED|raises <Type>>``.
"""
from __future__ import annotations

import ssl
import sys
import types

import _ssl

MODE = sys.argv[1]
REAL_C_MIN = _ssl._SSLContext.__dict__["minimum_version"]
ORIG_PY_MIN = ssl.SSLContext.__dict__["minimum_version"]

setattr(ssl.SSLContext, "minimum_version", property(lambda self: ssl.TLSVersion.TLSv1_2, ORIG_PY_MIN.fset))
real = _ssl._SSLContext
stand_in = type(
    "_SSLContext",
    (),
    {
        "minimum_version": property(lambda self: 771),
        "maximum_version": real.__dict__["maximum_version"],
    },
)
if MODE == "py-lie+attr":
    _ssl._SSLContext = stand_in
else:
    fake = types.ModuleType("_ssl")
    fake.__dict__.update(_ssl.__dict__)
    fake._SSLContext = stand_in
    sys.modules["_ssl"] = fake

from ai_memory import _common  # noqa: E402  (imported AFTER the substitution on purpose)
from ai_memory.client import AiMemoryClient  # noqa: E402

print("C_MIN is real getset: " + str(getattr(_common, "_C_MIN_VERSION", None) is REAL_C_MIN))
context = ssl.create_default_context()
REAL_C_MIN.__set__(context, ssl.TLSVersion.TLSv1_1)
try:
    AiMemoryClient("https://localhost:9077", verify=context).close()
    outcome = "ADMITTED"
except ValueError:
    outcome = "REFUSED-ValueError"
except Exception as exc:  # noqa: BLE001
    outcome = "raises " + type(exc).__name__
print("outcome=" + outcome)
