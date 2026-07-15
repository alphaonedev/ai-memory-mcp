# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""Shim behavior tests (offline always-run + opt-in real legs)."""
from __future__ import annotations

import os
import pathlib
from types import SimpleNamespace

import pytest

import ai_memory_openai_shim.shim as shim_mod
from ai_memory_openai_shim import extract_response_text, wrap


def _text_response() -> SimpleNamespace:
    return SimpleNamespace(
        choices=[
            SimpleNamespace(
                message=SimpleNamespace(
                    role="assistant",
                    content="Paris is the capital of France.",
                    tool_calls=None,
                )
            )
        ]
    )


class _FakeCompletions:
    def __init__(self, response: object) -> None:
        self._response = response
        self.calls: list[dict] = []

    def create(self, **kwargs: object) -> object:
        self.calls.append(kwargs)
        return self._response


class _FakeChat:
    def __init__(self, response: object) -> None:
        self.completions = _FakeCompletions(response)


class _FakeClient:
    def __init__(self, response: object) -> None:
        self.chat = _FakeChat(response)
        self.api_key = "sk-fake"


@pytest.fixture
def spy(monkeypatch: pytest.MonkeyPatch) -> list[dict]:
    recorded: list[dict] = []

    def _fake_capture(**kwargs: object) -> bool:
        recorded.append(kwargs)
        return True

    monkeypatch.setattr(shim_mod, "capture_turn", _fake_capture)
    return recorded


# --------------------------------------------------------------------------- #
# Offline
# --------------------------------------------------------------------------- #


def test_records_user_then_assistant_and_passthrough(spy: list[dict]) -> None:
    resp = _text_response()
    wrapped = wrap(_FakeClient(resp), host_session_id="s1")
    out = wrapped.chat.completions.create(
        model="gpt-4o", messages=[{"role": "user", "content": "capital of France?"}]
    )
    assert out is resp
    assert [c["role"] for c in spy] == ["user", "assistant"]
    assert spy[0]["content"] == "capital of France?"
    assert spy[1]["content"] == "Paris is the capital of France."
    assert spy[0]["host_turn_index"] == 0 and spy[1]["host_turn_index"] == 1
    assert spy[0]["host_session_id"] == spy[1]["host_session_id"] == "s1"


def test_delegates_unknown_attributes(spy: list[dict]) -> None:
    wrapped = wrap(_FakeClient(_text_response()))
    assert wrapped.api_key == "sk-fake"


def test_non_wedging_when_capture_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    def _boom(**_kwargs: object) -> bool:
        raise RuntimeError("substrate down")

    monkeypatch.setattr(shim_mod, "capture_turn", _boom)
    resp = _text_response()
    wrapped = wrap(_FakeClient(resp))
    out = wrapped.chat.completions.create(messages=[{"role": "user", "content": "hi"}])
    assert out is resp


def test_streaming_records_request_only(spy: list[dict]) -> None:
    wrapped = wrap(_FakeClient(_text_response()))
    wrapped.chat.completions.create(
        stream=True, messages=[{"role": "user", "content": "stream me"}]
    )
    assert [c["role"] for c in spy] == ["user"]


def test_monotonic_turn_indices_across_calls(spy: list[dict]) -> None:
    wrapped = wrap(_FakeClient(_text_response()))
    wrapped.chat.completions.create(messages=[{"role": "user", "content": "one"}])
    wrapped.chat.completions.create(messages=[{"role": "user", "content": "two"}])
    assert [c["host_turn_index"] for c in spy] == [0, 1, 2, 3]
    assert len({c["host_session_id"] for c in spy}) == 1


def test_async_records_user_then_assistant(monkeypatch: pytest.MonkeyPatch) -> None:
    import asyncio

    recorded: list[dict] = []
    monkeypatch.setattr(shim_mod, "capture_turn", lambda **k: (recorded.append(k), True)[1])
    resp = _text_response()

    class _AsyncCompletions:
        async def create(self, **_kwargs: object) -> object:
            return resp

    class _AsyncChat:
        def __init__(self) -> None:
            self.completions = _AsyncCompletions()

    class _AsyncClient:
        def __init__(self) -> None:
            self.chat = _AsyncChat()

    async def _drive() -> object:
        wrapped = wrap(_AsyncClient())
        return await wrapped.chat.completions.create(
            messages=[{"role": "user", "content": "hi async"}]
        )

    out = asyncio.run(_drive())
    assert out is resp
    assert [c["role"] for c in recorded] == ["user", "assistant"]


# --------------------------------------------------------------------------- #
# Opt-in real legs (skipped by default)
# --------------------------------------------------------------------------- #

_OPENAI_KEY = os.environ.get("OPENAI_API_KEY")
_AI_MEMORY_BIN = os.environ.get("AI_MEMORY_TEST_BIN")


@pytest.mark.skipif(not _OPENAI_KEY, reason="OPENAI_API_KEY unset (opt-in real-SDK leg)")
def test_real_openai_response_shape_extraction() -> None:
    from openai import OpenAI  # noqa: PLC0415 - opt-in import

    client = OpenAI()
    resp = client.chat.completions.create(
        model="gpt-4o-mini",
        max_tokens=16,
        messages=[{"role": "user", "content": "Reply with the single word: ok"}],
    )
    text = extract_response_text(resp)
    assert isinstance(text, str) and text.strip()


@pytest.mark.skipif(not _AI_MEMORY_BIN, reason="AI_MEMORY_TEST_BIN unset (opt-in substrate leg)")
def test_selfspawned_mcp_capture_lands(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from ai_memory_openai_shim import capture_turn  # noqa: PLC0415

    monkeypatch.setenv("AI_MEMORY_DB", str(tmp_path / "shim-it.db"))
    monkeypatch.setenv("AI_MEMORY_NO_CONFIG", "1")
    ok = capture_turn(
        host_session_id="shim-it",
        host_turn_index=0,
        role="user",
        content="integration probe",
        ai_memory_bin=_AI_MEMORY_BIN,
    )
    assert ok is True
