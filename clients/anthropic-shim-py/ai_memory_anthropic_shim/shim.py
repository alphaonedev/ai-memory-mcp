# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""Delegating proxy that records each Anthropic Messages turn to ai-memory.

``wrap(client)`` returns a transparent proxy over an ``Anthropic`` /
``AsyncAnthropic`` instance: every attribute delegates to the wrapped client
unchanged EXCEPT ``.messages.create``, which — before returning the response
verbatim — records the new user turn and the assistant turn to ai-memory via
:func:`ai_memory_anthropic_shim._capture.capture_turn`.

Design (issue #1974's sibling, #1390; 5-agent vote 4d3ea1c5):

* **Pass-through / opaque** — the proxy forwards args + response unchanged and
  makes minimal assumptions about vendor shape, so it does not couple the GA
  contract to the anthropic SDK's evolving internals.
* **Non-wedging** — recording is wrapped so a capture failure (or an
  unexpected response shape) NEVER propagates into the caller's `create` call.
* **Streaming** — a ``stream=True`` call records the request turn only and
  passes the stream object through untouched; consuming it to record the
  assistant turn would break passthrough, so it is deliberately skipped.
"""
from __future__ import annotations

import inspect
import itertools
import sys
import uuid
from typing import Any

from ._capture import capture_turn
from ._extract import ROLE_ASSISTANT, extract_last_request_turn, extract_response_text

_DEFAULT_HOST_KIND = "anthropic-sdk"


class _Recorder:
    """Owns the per-wrapped-client session id + monotonic turn counter and the
    two non-wedging record entry points."""

    def __init__(
        self,
        *,
        host_session_id: str | None,
        namespace: str | None,
        ai_memory_bin: str | None,
        host_kind: str | None,
    ) -> None:
        self._session_id = host_session_id or f"anthropic-shim-{uuid.uuid4().hex[:12]}"
        self._namespace = namespace
        self._bin = ai_memory_bin
        self._host_kind = host_kind or _DEFAULT_HOST_KIND
        self._counter = itertools.count()

    def _record(self, role: str, content: str) -> None:
        if not content:
            return
        # capture_turn is already total, but guard the whole path so an
        # unexpected error can never reach the caller (non-wedging invariant).
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
            print(f"WARN ai-memory-anthropic-shim: record failed: {e}", file=sys.stderr)

    def record_request(self, kwargs: dict[str, Any]) -> None:
        try:
            turn = extract_last_request_turn(kwargs)
        except Exception as e:  # noqa: BLE001
            print(f"WARN ai-memory-anthropic-shim: request extract failed: {e}", file=sys.stderr)
            return
        if turn is not None:
            self._record(turn[0], turn[1])

    def record_response(self, response: Any) -> None:
        try:
            text = extract_response_text(response)
        except Exception as e:  # noqa: BLE001
            print(f"WARN ai-memory-anthropic-shim: response extract failed: {e}", file=sys.stderr)
            return
        self._record(ROLE_ASSISTANT, text)


class _MessagesProxy:
    def __init__(self, inner: Any, recorder: _Recorder) -> None:
        self._inner = inner
        self._rec = recorder

    def __getattr__(self, name: str) -> Any:
        return getattr(self._inner, name)

    def create(self, *args: Any, **kwargs: Any) -> Any:
        self._rec.record_request(kwargs)
        response = self._inner.create(*args, **kwargs)
        if not kwargs.get("stream"):
            self._rec.record_response(response)
        return response


class _AsyncMessagesProxy:
    def __init__(self, inner: Any, recorder: _Recorder) -> None:
        self._inner = inner
        self._rec = recorder

    def __getattr__(self, name: str) -> Any:
        return getattr(self._inner, name)

    async def create(self, *args: Any, **kwargs: Any) -> Any:
        self._rec.record_request(kwargs)
        response = await self._inner.create(*args, **kwargs)
        if not kwargs.get("stream"):
            self._rec.record_response(response)
        return response


class _ClientProxy:
    """Transparent proxy: delegates everything to the wrapped client except the
    ``messages`` accessor, which returns the recording proxy."""

    def __init__(self, client: Any, recorder: _Recorder, *, is_async: bool) -> None:
        self._client = client
        self._rec = recorder
        self._is_async = is_async

    def __getattr__(self, name: str) -> Any:
        return getattr(self._client, name)

    @property
    def messages(self) -> Any:
        inner = self._client.messages
        if self._is_async:
            return _AsyncMessagesProxy(inner, self._rec)
        return _MessagesProxy(inner, self._rec)


def _detect_async(client: Any) -> bool:
    create = getattr(getattr(client, "messages", None), "create", None)
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
    """Wrap an ``Anthropic`` / ``AsyncAnthropic`` client so each Messages turn
    is recorded to ai-memory. Returns a transparent proxy; use it exactly like
    the original client.

    Parameters
    ----------
    client:
        An ``anthropic.Anthropic`` or ``anthropic.AsyncAnthropic`` instance
        (peer dependency — the caller brings their own).
    host_session_id:
        Stable session id for dedup; defaults to a per-wrap UUID.
    namespace:
        Optional ai-memory namespace to record into.
    ai_memory_bin:
        Path to the ``ai-memory`` binary; defaults to ``$AI_MEMORY_BIN`` then
        ``ai-memory`` on ``$PATH``.
    host_kind:
        Provenance tag recorded on each turn (default ``anthropic-sdk``).
    """
    recorder = _Recorder(
        host_session_id=host_session_id,
        namespace=namespace,
        ai_memory_bin=ai_memory_bin,
        host_kind=host_kind,
    )
    return _ClientProxy(client, recorder, is_async=_detect_async(client))
