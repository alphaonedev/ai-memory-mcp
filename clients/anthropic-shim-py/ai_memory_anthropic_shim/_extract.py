# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""Anthropic Messages request/response -> (role, content) extraction.

This is the ONE vendor-shape-sensitive seam in the shim. It is deliberately
OPAQUE: it flattens whatever text it can find and falls back to a JSON dump
for unrecognised blocks, so a vendor SDK shape change degrades to a
still-recorded (if less pretty) turn rather than a crash. Pinned against a
recorded real response payload in ``tests/cassettes/`` so the extraction is
verified against the vendor contract, not a hand-authored guess.
"""
from __future__ import annotations

import json
from typing import Any

ROLE_USER = "user"
ROLE_ASSISTANT = "assistant"


def _flatten_content(content: Any) -> str:
    """Flatten an Anthropic message ``content`` (str | list-of-blocks) to text."""
    if content is None:
        return ""
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts: list[str] = []
        for block in content:
            if isinstance(block, str):
                parts.append(block)
                continue
            # dict-shaped block (input messages) or SDK object (response block)
            text = None
            if isinstance(block, dict):
                if block.get("type") == "text":
                    text = block.get("text")
            else:
                if getattr(block, "type", None) == "text":
                    text = getattr(block, "text", None)
            if isinstance(text, str):
                parts.append(text)
            else:
                # Non-text block (tool_use, image, ...): record opaquely so the
                # turn is never silently dropped.
                parts.append(_dump(block))
        return "\n".join(p for p in parts if p)
    return str(content)


def _dump(obj: Any) -> str:
    try:
        if isinstance(obj, dict):
            return json.dumps(obj, default=str, sort_keys=True)
        # SDK objects commonly expose model_dump()/dict().
        for attr in ("model_dump", "dict"):
            fn = getattr(obj, attr, None)
            if callable(fn):
                return json.dumps(fn(), default=str, sort_keys=True)
    except Exception:  # noqa: BLE001 - extraction must never raise
        pass
    return str(obj)


def _msg_role(msg: Any) -> str:
    if isinstance(msg, dict):
        return str(msg.get("role") or ROLE_USER)
    return str(getattr(msg, "role", ROLE_USER) or ROLE_USER)


def _msg_content(msg: Any) -> Any:
    if isinstance(msg, dict):
        return msg.get("content")
    return getattr(msg, "content", None)


def extract_last_request_turn(kwargs: dict[str, Any]) -> tuple[str, str] | None:
    """The NEW turn of a ``messages.create`` call: the last message in the
    ``messages`` array (prior messages are already-recorded history).

    Returns ``(role, content)`` or ``None`` when there is nothing to record.
    """
    messages = kwargs.get("messages")
    if not messages:
        return None
    last = messages[-1]
    content = _flatten_content(_msg_content(last))
    if not content:
        return None
    return (_msg_role(last), content)


def extract_response_text(response: Any) -> str:
    """Concatenate the text blocks of an Anthropic Messages response."""
    content = getattr(response, "content", None)
    if content is None and isinstance(response, dict):
        content = response.get("content")
    return _flatten_content(content)
