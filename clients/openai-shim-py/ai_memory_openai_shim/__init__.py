# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""ai-memory OpenAI shim — record each OpenAI Chat Completions turn to ai-memory.

Reference (#1390) Direct-API SDK shim for callers who hit ``openai`` in their
own scripts without a host harness that writes a transcript. Wrap your client
once and every ``chat.completions.create`` turn is captured:

    from openai import OpenAI
    from ai_memory_openai_shim import wrap

    client = wrap(OpenAI())
    client.chat.completions.create(model="gpt-...", messages=[...])

``openai`` is a PEER dependency — install it yourself. The shim is
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
