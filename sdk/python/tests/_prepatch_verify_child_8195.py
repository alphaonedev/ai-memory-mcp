"""Child process for ``test_tls_prepatch_8195_r6``: replace a verification attribute BEFORE ``ai_memory`` is imported.

usage: ``python _prepatch_verify_child_8195.py <verify_mode|check_hostname|verify_flags>`` (code r5 F2).

The caller's context really is weakened in the C object (``CERT_NONE``, ``check_hostname`` off, or
``verify_flags`` carrying ``NO_CHECK_TIME``), while the ``ssl.SSLContext`` property replaced before the
import reports the strong stock value. ``_STOCK_HANDSHAKE`` counts that property as stock, so only the
comparison with the C-level read refuses the context. The child prints one line,
``outcome=<REFUSED-ValueError|ADMITTED|raises <Type>>``.
"""
from __future__ import annotations

import ssl
import sys

MODE = sys.argv[1]  # verify_mode | verify_mode_optional | check_hostname | verify_flags
ATTR = "verify_mode" if MODE == "verify_mode_optional" else MODE
BASE = ssl.SSLContext.__mro__[1]
REAL = BASE.__dict__[ATTR]
REAL_HOST = BASE.__dict__["check_hostname"]
ORIGINAL = ssl.SSLContext.__dict__.get(ATTR)
NO_CHECK_TIME = 0x200000
STRONG = {"verify_mode": ssl.CERT_REQUIRED, "check_hostname": True}

if ATTR == "verify_flags":
    stock_flags = REAL.__get__(ssl.create_default_context())
    reported = lambda self: ssl.VerifyFlags(stock_flags)  # noqa: E731
else:
    reported = lambda self: STRONG[ATTR]  # noqa: E731
fset = ORIGINAL.fset if ORIGINAL is not None else lambda self, value: REAL.__set__(self, value)
setattr(ssl.SSLContext, ATTR, property(reported, fset))
if MODE == "verify_mode":
    # CERT_NONE forces the hostname check off in OpenSSL, so the lie covers both reads.
    setattr(ssl.SSLContext, "check_hostname", property(lambda self: True, lambda self, value: REAL_HOST.__set__(self, value)))

from ai_memory.client import AiMemoryClient  # noqa: E402  (imported AFTER the replacement on purpose)

context = ssl.create_default_context()
if MODE == "verify_mode_optional":
    # CERT_OPTIONAL keeps the hostname check on, so only the verify_mode comparison can refuse it.
    REAL.__set__(context, ssl.CERT_OPTIONAL)
elif MODE != "verify_flags":
    REAL_HOST.__set__(context, False)
if MODE == "verify_mode":
    REAL.__set__(context, ssl.CERT_NONE)
elif MODE == "verify_flags":
    REAL.__set__(context, int(REAL.__get__(context)) | NO_CHECK_TIME)
try:
    AiMemoryClient("https://localhost:9077", verify=context).close()
    outcome = "ADMITTED"
except ValueError:
    outcome = "REFUSED-ValueError"
except Exception as exc:  # noqa: BLE001
    outcome = "raises " + type(exc).__name__
print("outcome=" + outcome)
