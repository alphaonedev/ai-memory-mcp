"""Child process for ``test_tls_prepatch_8195_r5``: patch a TLS bound BEFORE ``ai_memory`` is imported.

usage: ``python _prepatch_child_8195.py <minimum_version|maximum_version> <int-771|str|none>``

``_STOCK_HANDSHAKE`` is captured when ``ai_memory._common`` is imported, so a descriptor replaced
before that import passes the stock-identity leg and the ``isinstance`` bound check in
``_tls_range_is_modern`` is the only refusal (code r4 F3, mutant M66). The child prints one line,
``outcome=<REFUSED-ValueError|ADMITTED|raises <Type>>``, and nothing else.
"""
from __future__ import annotations

import ssl
import sys

ATTR = sys.argv[1]
VALUES = {"int-771": 771, "str": "TLSv1.2", "none": None}
VALUE = VALUES[sys.argv[2]]
ORIGINAL = ssl.SSLContext.__dict__[ATTR]
setattr(ssl.SSLContext, ATTR, property(lambda _self, v=VALUE: v, ORIGINAL.fset))

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
