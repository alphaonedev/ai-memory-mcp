"""Child process for ``test_tls_getset_identity_8195_r7``: a forged ``getset_descriptor`` class (sec r6 S1).

usage: ``python _prepatch_getset_child_8195.py <minimum_version|maximum_version>``

The caller's context really has a TLS 1.1 bound in the C object. BEFORE ``ai_memory`` is imported, a
plain Python class literally named ``getset_descriptor`` with ``__objclass__ = ssl.SSLContext`` is
installed as the Python-visible bound, reporting TLS 1.2. Matching the descriptor by type name
resolves the forgery as the genuine C getset and both reads agree on the lie. Prints
``outcome=<REFUSED-ValueError|ADMITTED|raises <Type>>``.
"""
from __future__ import annotations

import ssl
import sys

import _ssl

ATTR = sys.argv[1]
REAL = _ssl._SSLContext.__dict__[ATTR]

context = ssl.create_default_context()
REAL.__set__(context, ssl.TLSVersion.TLSv1_1)

forged = type(
    "getset_descriptor",
    (),
    {"__get__": lambda self, obj, owner=None: self if obj is None else ssl.TLSVersion.TLSv1_2},
)()
forged.__objclass__ = ssl.SSLContext
setattr(ssl.SSLContext, ATTR, forged)

from ai_memory import _common  # noqa: E402  (imported AFTER the forgery on purpose)
from ai_memory.client import AiMemoryClient  # noqa: E402

print("module=" + _common.__name__)
print("forgery is genuine getset type: " + str(type(forged) is type(REAL)))
try:
    AiMemoryClient("https://localhost:9077", verify=context).close()
    outcome = "ADMITTED"
except ValueError:
    outcome = "REFUSED-ValueError"
except Exception as exc:  # noqa: BLE001
    outcome = "raises " + type(exc).__name__
print("outcome=" + outcome)
