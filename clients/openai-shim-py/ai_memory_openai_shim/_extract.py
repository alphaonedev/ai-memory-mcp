# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""OpenAI Chat Completions request/response -> (role, content) extraction.

The ONE vendor-shape-sensitive seam. Deliberately OPAQUE: it flattens whatever
text it can find and falls back to a JSON dump for unrecognised structures, so
a vendor SDK shape change degrades to a still-recorded turn rather than a
crash. Pinned against recorded real response payloads in ``tests/cassettes/``.
"""
from __future__ import annotations

import json
from typing import Any

ROLE_USER = "user"
ROLE_ASSISTANT = "assistant"


def _flatten_content(content: Any) -> str:
    """Flatten a Chat message ``content`` (str | list-of-parts) to text."""
    if content is None:
        return ""
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts: list[str] = []
        for part in content:
            if isinstance(part, str):
                parts.append(part)
                continue
            text = None
            if isinstance(part, dict):
                if part.get("type") == "text":
                    text = part.get("text")
            else:
                if getattr(part, "type", None) == "text":
                    text = getattr(part, "text", None)
            if isinstance(text, str):
                parts.append(text)
            else:
                parts.append(_dump(part))
        return "\n".join(p for p in parts if p)
    return str(content)


def _dump(obj: Any) -> str:
    try:
        if isinstance(obj, dict):
            return json.dumps(obj, default=str, sort_keys=True)
        for attr in ("model_dump", "dict"):
            fn = getattr(obj, attr, None)
            if callable(fn):
                return json.dumps(fn(), default=str, sort_keys=True)
    except Exception:  # noqa: BLE001 - extraction must never raise
        pass
    return str(obj)


def _get(obj: Any, key: str) -> Any:
    if isinstance(obj, dict):
        return obj.get(key)
    return getattr(obj, key, None)


def _msg_role(msg: Any) -> str:
    return str(_get(msg, "role") or ROLE_USER)


def extract_last_request_turn(kwargs: dict[str, Any]) -> tuple[str, str] | None:
    """The NEW turn of a ``chat.completions.create`` call: the last message in
    the ``messages`` array. Returns ``(role, content)`` or ``None``."""
    messages = kwargs.get("messages")
    if not messages:
        return None
    last = messages[-1]
    content = _flatten_content(_get(last, "content"))
    if not content:
        return None
    return (_msg_role(last), content)


def extract_response_text(response: Any) -> str:
    """Extract the assistant text of a Chat Completions response:
    ``choices[0].message.content`` (+ any ``tool_calls`` recorded opaquely)."""
    choices = _get(response, "choices")
    if not choices:
        return ""
    message = _get(choices[0], "message")
    if message is None:
        return ""
    text = _flatten_content(_get(message, "content"))
    tool_calls = _get(message, "tool_calls")
    if tool_calls:
        dumped = _dump(tool_calls)
        text = f"{text}\n{dumped}".strip() if text else dumped
    return text
