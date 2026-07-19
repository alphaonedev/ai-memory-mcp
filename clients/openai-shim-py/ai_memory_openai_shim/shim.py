# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""Delegating proxy that records each OpenAI Chat Completions turn to ai-memory.

``wrap(client)`` returns a transparent proxy over an ``OpenAI`` /
``AsyncOpenAI`` instance: every attribute delegates to the wrapped client
unchanged EXCEPT ``.chat.completions.create``, which — before returning the
response verbatim — records the new user turn and the assistant turn to
ai-memory via :func:`ai_memory_openai_shim._capture.capture_turn`.

Same design as the anthropic sibling (#1390; 5-agent vote 4d3ea1c5):
pass-through / opaque, non-wedging, streaming records the request turn only.
The only differences are the vendor shape (``chat.completions.create`` +
``choices[0].message.content``) and the deeper attribute nesting.
"""
from __future__ import annotations

import inspect
import itertools
import sys
import uuid
from typing import Any

from ._capture import capture_turn
from ._extract import ROLE_ASSISTANT, extract_last_request_turn, extract_response_text

_DEFAULT_HOST_KIND = "openai-sdk"


class _Recorder:
    def __init__(
        self,
        *,
        host_session_id: str | None,
        namespace: str | None,
        ai_memory_bin: str | None,
        host_kind: str | None,
    ) -> None:
        self._session_id = host_session_id or f"openai-shim-{uuid.uuid4().hex[:12]}"
        self._namespace = namespace
        self._bin = ai_memory_bin
        self._host_kind = host_kind or _DEFAULT_HOST_KIND
        self._counter = itertools.count()

    def _record(self, role: str, content: str) -> None:
        if not content:
            return
        try:
            capture_turn(
                host_session_id=self._session_id,
                host_turn_index=next(self._counter),
                role=role,
                content=content,
                namespace=self._namespace,
                host_kind=self._host_kind,
                ai_memory_bin=self._bin,
            )
        except Exception as e:  # noqa: BLE001 - shim must never wedge the caller
            print(f"WARN ai-memory-openai-shim: record failed: {e}", file=sys.stderr)

    def record_request(self, kwargs: dict[str, Any]) -> None:
        try:
            turn = extract_last_request_turn(kwargs)
        except Exception as e:  # noqa: BLE001
            print(f"WARN ai-memory-openai-shim: request extract failed: {e}", file=sys.stderr)
            return
        if turn is not None:
            self._record(turn[0], turn[1])

    def record_response(self, response: Any) -> None:
        try:
            text = extract_response_text(response)
        except Exception as e:  # noqa: BLE001
            print(f"WARN ai-memory-openai-shim: response extract failed: {e}", file=sys.stderr)
            return
        self._record(ROLE_ASSISTANT, text)


class _CompletionsProxy:
    def __init__(self, inner: Any, recorder: _Recorder, *, is_async: bool) -> None:
        self._inner = inner
        self._rec = recorder
        self._is_async = is_async

    def __getattr__(self, name: str) -> Any:
        return getattr(self._inner, name)

    def create(self, *args: Any, **kwargs: Any) -> Any:
        if self._is_async:
            return self._acreate(*args, **kwargs)
        self._rec.record_request(kwargs)
        response = self._inner.create(*args, **kwargs)
        if not kwargs.get("stream"):
            self._rec.record_response(response)
        return response

    async def _acreate(self, *args: Any, **kwargs: Any) -> Any:
        self._rec.record_request(kwargs)
        response = await self._inner.create(*args, **kwargs)
        if not kwargs.get("stream"):
            self._rec.record_response(response)
        return response


class _ChatProxy:
    def __init__(self, inner: Any, recorder: _Recorder, *, is_async: bool) -> None:
        self._inner = inner
        self._rec = recorder
        self._is_async = is_async

    def __getattr__(self, name: str) -> Any:
        return getattr(self._inner, name)

    @property
    def completions(self) -> Any:
        return _CompletionsProxy(self._inner.completions, self._rec, is_async=self._is_async)


class _ClientProxy:
    def __init__(self, client: Any, recorder: _Recorder, *, is_async: bool) -> None:
        self._client = client
        self._rec = recorder
        self._is_async = is_async

    def __getattr__(self, name: str) -> Any:
        return getattr(self._client, name)

    @property
    def chat(self) -> Any:
        return _ChatProxy(self._client.chat, self._rec, is_async=self._is_async)


def _detect_async(client: Any) -> bool:
    create = getattr(
        getattr(getattr(client, "chat", None), "completions", None), "create", None
    )
    if inspect.iscoroutinefunction(create):
        return True
    return type(client).__name__.startswith("Async")


def wrap(
    client: Any,
    *,
    host_session_id: str | None = None,
    namespace: str | None = None,
    ai_memory_bin: str | None = None,
    host_kind: str | None = None,
) -> Any:
    """Wrap an ``OpenAI`` / ``AsyncOpenAI`` client so each Chat Completions turn
    is recorded to ai-memory. Returns a transparent proxy; use it exactly like
    the original client. ``openai`` is a PEER dependency — bring your own
    instance."""
    recorder = _Recorder(
        host_session_id=host_session_id,
        namespace=namespace,
        ai_memory_bin=ai_memory_bin,
        host_kind=host_kind,
    )
    return _ClientProxy(client, recorder, is_async=_detect_async(client))
