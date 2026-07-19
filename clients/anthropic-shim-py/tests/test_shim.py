# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""Shim behavior tests.

Split (mirroring ``sdk/python/tests/test_client.py``):

* **Offline** (always run) — record-once, passthrough-unchanged, non-wedging,
  streaming, async, delegation. Uses a DI'd fake client + a monkeypatched
  capture spy, so no vendor key / running substrate is needed.
* **Opt-in real legs** — the one shape-sensitive seam against the REAL vendor
  SDK (``ANTHROPIC_API_KEY``) and a REAL self-spawned substrate
  (``AI_MEMORY_TEST_BIN``), skipped by default so CI stays green.
"""
from __future__ import annotations

import json
import os
import pathlib
from types import SimpleNamespace

import pytest

import ai_memory_anthropic_shim.shim as shim_mod
from ai_memory_anthropic_shim import extract_response_text, wrap

CASSETTES = pathlib.Path(__file__).parent / "cassettes"


def _text_response() -> SimpleNamespace:
    d = json.loads((CASSETTES / "messages_create_text.json").read_text())
    return SimpleNamespace(content=[SimpleNamespace(type="text", text=d["content"][0]["text"])])


class _FakeMessages:
    def __init__(self, response: object) -> None:
        self._response = response
        self.calls: list[dict] = []

    def create(self, **kwargs: object) -> object:
        self.calls.append(kwargs)
        return self._response


class _FakeClient:
    def __init__(self, response: object) -> None:
        self.messages = _FakeMessages(response)
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


def test_records_user_then_assistant_and_passes_response_through(spy: list[dict]) -> None:
    resp = _text_response()
    wrapped = wrap(_FakeClient(resp), host_session_id="s1")
    out = wrapped.messages.create(
        model="claude", max_tokens=10, messages=[{"role": "user", "content": "capital of France?"}]
    )
    assert out is resp  # passthrough: exact same object
    assert [c["role"] for c in spy] == ["user", "assistant"]
    assert spy[0]["content"] == "capital of France?"
    assert spy[1]["content"] == "Paris is the capital of France."
    assert spy[0]["host_turn_index"] == 0 and spy[1]["host_turn_index"] == 1
    assert spy[0]["host_session_id"] == spy[1]["host_session_id"] == "s1"


def test_delegates_unknown_attributes(spy: list[dict]) -> None:
    wrapped = wrap(_FakeClient(_text_response()))
    assert wrapped.api_key == "sk-fake"  # non-messages attrs pass through


def test_non_wedging_when_capture_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    def _boom(**_kwargs: object) -> bool:
        raise RuntimeError("substrate down")

    monkeypatch.setattr(shim_mod, "capture_turn", _boom)
    resp = _text_response()
    wrapped = wrap(_FakeClient(resp))
    out = wrapped.messages.create(messages=[{"role": "user", "content": "hi"}])
    assert out is resp  # caller undisturbed despite a hard capture failure


def test_streaming_records_request_only(spy: list[dict]) -> None:
    wrapped = wrap(_FakeClient(_text_response()))
    wrapped.messages.create(stream=True, messages=[{"role": "user", "content": "stream me"}])
    # assistant turn skipped for streams (consuming the stream would break passthrough)
    assert [c["role"] for c in spy] == ["user"]


def test_default_session_id_is_stable_across_calls(spy: list[dict]) -> None:
    wrapped = wrap(_FakeClient(_text_response()))
    wrapped.messages.create(messages=[{"role": "user", "content": "one"}])
    wrapped.messages.create(messages=[{"role": "user", "content": "two"}])
    session_ids = {c["host_session_id"] for c in spy}
    assert len(session_ids) == 1  # one stable session id per wrapped client
    assert [c["host_turn_index"] for c in spy] == [0, 1, 2, 3]  # monotonic


def test_async_records_user_then_assistant(monkeypatch: pytest.MonkeyPatch) -> None:
    # Driven via asyncio.run so the async path is truly exercised on stock
    # pytest (no pytest-asyncio plugin required).
    import asyncio

    recorded: list[dict] = []
    monkeypatch.setattr(shim_mod, "capture_turn", lambda **k: (recorded.append(k), True)[1])
    resp = _text_response()

    class _AsyncMessages:
        async def create(self, **_kwargs: object) -> object:
            return resp

    class _AsyncClient:
        def __init__(self) -> None:
            self.messages = _AsyncMessages()

    async def _drive() -> object:
        wrapped = wrap(_AsyncClient())  # detected async via iscoroutinefunction
        return await wrapped.messages.create(messages=[{"role": "user", "content": "hi async"}])

    out = asyncio.run(_drive())
    assert out is resp
    assert [c["role"] for c in recorded] == ["user", "assistant"]


def test_async_capture_does_not_block_event_loop(monkeypatch: pytest.MonkeyPatch) -> None:
    import asyncio
    import threading

    started = threading.Event()
    release = threading.Event()

    def slow_capture(**_kwargs: object) -> bool:
        started.set()
        return release.wait(0.5)

    monkeypatch.setattr(shim_mod, "capture_turn", slow_capture)

    class _AsyncMessages:
        async def create(self, **_kwargs: object) -> object:
            return _text_response()

    class _AsyncClient:
        def __init__(self) -> None:
            self.messages = _AsyncMessages()

    async def _drive() -> None:
        task = asyncio.create_task(
            wrap(_AsyncClient()).messages.create(
                messages=[{"role": "user", "content": "loop stays live"}]
            )
        )
        while not started.is_set():
            await asyncio.sleep(0)
        await asyncio.sleep(0.01)
        assert not task.done(), "capture must be waiting in a worker, not blocking the loop"
        release.set()
        await task

    asyncio.run(_drive())


# --------------------------------------------------------------------------- #
# Opt-in real legs (skipped by default; keep CI green)
# --------------------------------------------------------------------------- #

_ANTHROPIC_KEY = os.environ.get("ANTHROPIC_API_KEY")
_AI_MEMORY_BIN = os.environ.get("AI_MEMORY_TEST_BIN")


@pytest.mark.skipif(not _ANTHROPIC_KEY, reason="ANTHROPIC_API_KEY unset (opt-in real-SDK leg)")
def test_real_anthropic_response_shape_extraction() -> None:
    from anthropic import Anthropic  # noqa: PLC0415 - opt-in import

    client = Anthropic()
    resp = client.messages.create(
        model="claude-3-5-haiku-latest",
        max_tokens=16,
        messages=[{"role": "user", "content": "Reply with the single word: ok"}],
    )
    text = extract_response_text(resp)
    assert isinstance(text, str) and text.strip()  # the seam works on a REAL payload


@pytest.mark.skipif(not _AI_MEMORY_BIN, reason="AI_MEMORY_TEST_BIN unset (opt-in substrate leg)")
def test_selfspawned_mcp_capture_lands(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from ai_memory_anthropic_shim import capture_turn  # noqa: PLC0415

    monkeypatch.setenv("AI_MEMORY_DB", str(tmp_path / "shim-it.db"))  # never touch the live DB
    monkeypatch.setenv("AI_MEMORY_NO_CONFIG", "1")
    ok = capture_turn(
        host_session_id="shim-it",
        host_turn_index=0,
        role="user",
        content="integration probe",
        ai_memory_bin=_AI_MEMORY_BIN,
    )
    assert ok is True
