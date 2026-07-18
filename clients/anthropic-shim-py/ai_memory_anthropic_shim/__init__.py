# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""ai-memory Anthropic shim — record each Anthropic Messages turn to ai-memory.

Reference (#1390) Direct-API SDK shim for callers who hit ``anthropic`` in
their own scripts without a host harness that writes a transcript. Wrap your
client once and every ``messages.create`` turn is captured:

    from anthropic import Anthropic
    from ai_memory_anthropic_shim import wrap

    client = wrap(Anthropic())
    client.messages.create(model="claude-...", max_tokens=256, messages=[...])

``anthropic`` is a PEER dependency — install it yourself. The shim is
non-wedging: a capture failure never disturbs your LLM call.
"""
from __future__ import annotations

from ._capture import capture_turn
from ._extract import extract_last_request_turn, extract_response_text
from .shim import wrap

__all__ = [
    "wrap",
    "capture_turn",
    "extract_last_request_turn",
    "extract_response_text",
]
__version__ = "0.1.0"
