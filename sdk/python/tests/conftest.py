# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""Session guard: in CI the TLS security tests must RUN, not skip (#6688).

The SOCKS legs of the session check (#6349, #6537) and the truststore pins
(#6267) skip when ``socksio`` / ``truststore`` cannot be imported. Locally
that is a convenience; in CI it would let a security regression ship green.
When ``CI`` is set (GitHub Actions sets ``CI=true``) the session refuses to
start without them.
"""

from __future__ import annotations

import importlib.util
import os

import pytest

#: Modules whose absence would silently skip security tests (#6688).
CI_REQUIRED_MODULES = ("socksio", "truststore")


def pytest_sessionstart(session: pytest.Session) -> None:
    if not os.environ.get("CI"):
        return
    missing = [name for name in CI_REQUIRED_MODULES if importlib.util.find_spec(name) is None]
    if missing:
        raise pytest.UsageError(
            f"CI is set but {', '.join(missing)} cannot be imported: the TLS security "
            "tests that need them would skip. Install sdk/python with the dev extra (#6688)."
        )
