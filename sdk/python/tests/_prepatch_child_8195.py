"""Child process for ``test_tls_prepatch_8195_r5``: patch a TLS bound BEFORE ``ai_memory`` is imported.

usage: ``python _prepatch_child_8195.py <minimum_version|maximum_version> <kind>`` where ``kind`` is
``int-raw`` (the true bound as a plain ``int``), ``int-771``, ``str``, ``none`` or ``lie`` (a
``TLSVersion`` that is not the context's real bound).

``_STOCK_HANDSHAKE`` is captured when ``ai_memory._common`` is imported, so a descriptor replaced
before that import passes the stock-identity leg. The bounds are then refused by the type check and
by the comparison with the C-level value (code r4 F3, sec r4 N2, mutant M66). The child prints one
line, ``outcome=<REFUSED-ValueError|ADMITTED|raises <Type>>``, and nothing else.
"""
from __future__ import annotations

import ssl
import sys

import _ssl

ATTR = sys.argv[1]
KIND = sys.argv[2]
ORIGINAL = ssl.SSLContext.__dict__[ATTR]
C_GETTER = _ssl._SSLContext.__dict__[ATTR]
LIE = ssl.TLSVersion.TLSv1_3  # modern as a floor or a ceiling, and not the context's real bound


def _reported(context: ssl.SSLContext) -> object:
    if KIND == "int-raw":
        return int(C_GETTER.__get__(context))
    return {"int-771": 771, "str": "TLSv1.2", "none": None, "lie": LIE}[KIND]


setattr(ssl.SSLContext, ATTR, property(_reported, ORIGINAL.fset))

from ai_memory.client import AiMemoryClient  # noqa: E402  (imported AFTER the patch on purpose)

context = ssl.create_default_context()
try:
    AiMemoryClient("https://localhost:9077", verify=context).close()
    outcome = "ADMITTED"
except ValueError:
    outcome = "REFUSED-ValueError"
except Exception as exc:  # noqa: BLE001
    outcome = "raises " + type(exc).__name__
finally:
    setattr(ssl.SSLContext, ATTR, ORIGINAL)
print("outcome=" + outcome)
