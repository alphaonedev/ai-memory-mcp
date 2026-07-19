# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""Offline extraction tests — the shape-sensitive seam, pinned against RECORDED
real OpenAI Chat Completions payloads (``tests/cassettes/``)."""
from __future__ import annotations

import json
import pathlib
from types import SimpleNamespace

from ai_memory_openai_shim import extract_last_request_turn, extract_response_text

CASSETTES = pathlib.Path(__file__).parent / "cassettes"


def _load(name: str) -> dict:
    return json.loads((CASSETTES / name).read_text())


def test_extract_response_text_from_recorded_payload() -> None:
    resp = _load("chat_completion_text.json")
    assert extract_response_text(resp) == "Paris is the capital of France."


def test_extract_response_toolcall_records_opaquely() -> None:
    resp = _load("chat_completion_toolcall.json")
    text = extract_response_text(resp)
    # content is null but the tool_call is recorded opaquely, never dropped
    assert "get_weather" in text


def test_extract_response_from_sdk_style_object() -> None:
    resp = SimpleNamespace(
        choices=[SimpleNamespace(message=SimpleNamespace(content="hi there", tool_calls=None))]
    )
    assert extract_response_text(resp) == "hi there"


def test_extract_response_empty() -> None:
    assert extract_response_text({"choices": []}) == ""
    assert extract_response_text(SimpleNamespace(choices=None)) == ""


def test_extract_last_request_turn_str_content() -> None:
    turn = extract_last_request_turn(
        {"messages": [{"role": "user", "content": "hi"}, {"role": "user", "content": "2+2?"}]}
    )
    assert turn == ("user", "2+2?")


def test_extract_last_request_turn_multipart_content() -> None:
    turn = extract_last_request_turn(
        {"messages": [{"role": "user", "content": [{"type": "text", "text": "hello"}]}]}
    )
    assert turn == ("user", "hello")


def test_extract_last_request_turn_empty_is_none() -> None:
    assert extract_last_request_turn({"messages": []}) is None
    assert extract_last_request_turn({}) is None
