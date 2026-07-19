# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""Offline extraction tests — the shape-sensitive seam, pinned against RECORDED
real Anthropic response payloads (``tests/cassettes/``) rather than a
hand-authored guess (a fake authored by the extraction author is
self-confirming; the cassette is the vendor contract)."""
from __future__ import annotations

import json
import pathlib
from types import SimpleNamespace

from ai_memory_anthropic_shim import extract_last_request_turn, extract_response_text

CASSETTES = pathlib.Path(__file__).parent / "cassettes"


def _load(name: str) -> dict:
    return json.loads((CASSETTES / name).read_text())


def test_extract_response_text_from_recorded_payload() -> None:
    resp = _load("messages_create_text.json")
    assert extract_response_text(resp) == "Paris is the capital of France."


def test_extract_response_multiblock_records_text_and_opaque_tooluse() -> None:
    resp = _load("messages_create_multiblock.json")
    text = extract_response_text(resp)
    assert "Let me look that up." in text
    # the tool_use block is recorded opaquely (JSON dump), never silently dropped
    assert "get_weather" in text


def test_extract_response_text_from_sdk_style_object() -> None:
    # Anthropic returns objects, not dicts; the seam must handle attribute access.
    resp = SimpleNamespace(content=[SimpleNamespace(type="text", text="hi there")])
    assert extract_response_text(resp) == "hi there"


def test_extract_response_empty_content() -> None:
    assert extract_response_text(SimpleNamespace(content=None)) == ""
    assert extract_response_text({"content": []}) == ""


def test_extract_last_request_turn_str_content() -> None:
    turn = extract_last_request_turn(
        {"messages": [{"role": "user", "content": "hi"}, {"role": "user", "content": "2+2?"}]}
    )
    assert turn == ("user", "2+2?")  # only the NEW (last) message


def test_extract_last_request_turn_block_content() -> None:
    turn = extract_last_request_turn(
        {"messages": [{"role": "user", "content": [{"type": "text", "text": "hello"}]}]}
    )
    assert turn == ("user", "hello")


def test_extract_last_request_turn_empty_is_none() -> None:
    assert extract_last_request_turn({"messages": []}) is None
    assert extract_last_request_turn({}) is None
    assert extract_last_request_turn({"messages": [{"role": "user", "content": ""}]}) is None
