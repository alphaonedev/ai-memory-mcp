# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""Pytest session setup for the SDK suites.

#6309: the TLS fixtures write private keys. The repository rule forbids agent
created files under the system temp dir, so pytest's temp root is the
repository's gitignored ``.local-runs/`` unless the caller already chose one.
"""

from __future__ import annotations

import os
import pathlib

_TEMP_ROOT_ENV = "PYTEST_DEBUG_TEMPROOT"

if _TEMP_ROOT_ENV not in os.environ:
    _root = pathlib.Path(__file__).resolve().parents[2] / ".local-runs" / "pytest-sdk"
    _root.mkdir(parents=True, exist_ok=True)
    os.environ[_TEMP_ROOT_ENV] = str(_root)
