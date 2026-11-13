# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""The documented ``verify=`` forms, type-checked under ``mypy --strict`` (#6270).

Not a test module (no ``test_`` prefix): ``tests/test_verify_false_3840.py``
runs mypy over it. Every statement here is a form the client docstring accepts.
"""

from __future__ import annotations

import pathlib
import ssl

from ai_memory import AiMemoryClient, AsyncAiMemoryClient

URL = "https://h:9077"

AiMemoryClient(base_url=URL)
AiMemoryClient(base_url=URL, verify=None)
AiMemoryClient(base_url=URL, verify=True)
AiMemoryClient(base_url=URL, verify="/etc/ca.pem")
AiMemoryClient(base_url=URL, verify=pathlib.Path("/etc/ca.pem"))
AiMemoryClient(base_url=URL, verify=ssl.create_default_context())
AsyncAiMemoryClient(base_url=URL)
AsyncAiMemoryClient(base_url=URL, verify=None)
AsyncAiMemoryClient(base_url=URL, verify=True)
AsyncAiMemoryClient(base_url=URL, verify="/etc/ca.pem")
AsyncAiMemoryClient(base_url=URL, verify=pathlib.Path("/etc/ca.pem"))
AsyncAiMemoryClient(base_url=URL, verify=ssl.create_default_context())
