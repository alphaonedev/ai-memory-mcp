# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""Transport-level capture tests for the `_capture` JSON-RPC response parsing.

Offline + hermetic: `subprocess.run` is monkeypatched to return a canned
substrate stdout, so no real `ai-memory` binary is spawned. These pin the
non-wedging classification contract — in particular that a top-level
JSON-RPC ``error`` response is a FAILURE, not a mis-counted success.
"""
from __future__ import annotations

from types import SimpleNamespace

import pytest

from ai_memory_anthropic_shim import _capture


def _fake_run(stdout: str, returncode: int = 0):
    def _run(*_args: object, **_kwargs: object) -> SimpleNamespace:
        return SimpleNamespace(returncode=returncode, stdout=stdout, stderr="")

    return _run


def _call() -> bool:
    return _capture.capture_turn(
        host_session_id="s", host_turn_index=0, role="user", content="x"
    )


def test_jsonrpc_error_response_is_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    # A top-level JSON-RPC error carries no `result`; it must NOT count as a
    # captured turn (the pre-fix code returned True here).
    monkeypatch.setattr(
        _capture.subprocess,
        "run",
        _fake_run('{"jsonrpc":"2.0","id":2,"error":{"code":-32601,"message":"boom"}}\n'),
    )
    assert _call() is False


def test_tool_iserror_response_is_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        _capture.subprocess,
        "run",
        _fake_run('{"jsonrpc":"2.0","id":2,"result":{"isError":true}}\n'),
    )
    assert _call() is False


def test_ok_result_response_is_success(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        _capture.subprocess,
        "run",
        _fake_run('{"jsonrpc":"2.0","id":2,"result":{"content":[{"type":"text","text":"ok"}]}}\n'),
    )
    assert _call() is True
