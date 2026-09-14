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

from ai_memory_openai_shim import _capture


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


def _ask_stdout() -> str:
    """A capture_turn governance Ask result: status="ask", NO id — nothing persisted."""
    import json as _json

    inner = _json.dumps(
        {"status": "ask", "reason": "approval requested", "action": "memory_capture_turn"}
    )
    outer = _json.dumps(
        {"jsonrpc": "2.0", "id": 2, "result": {"content": [{"type": "text", "text": inner}]}}
    )
    return outer + "\n"


def _pending_stdout(pending_id: str) -> str:
    """A capture_turn Pending result: status="pending" + pending_id — DURABLY QUEUED."""
    import json as _json

    inner = _json.dumps(
        {
            "status": "pending",
            "pending_id": pending_id,
            "reason": "governance approval required",
            "action": "memory_capture_turn",
        }
    )
    outer = _json.dumps(
        {"jsonrpc": "2.0", "id": 2, "result": {"content": [{"type": "text", "text": inner}]}}
    )
    return outer + "\n"


def test_ask_status_is_not_captured_and_claims_no_recovery(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # #3544 — a governance Ask (capture_turn.rs:415) persists NOTHING and
    # returns no id. It is not a captured turn, and the message must NOT claim
    # a recovery that does not exist. Pre-fix the shim returned True here.
    monkeypatch.setattr(_capture.subprocess, "run", _fake_run(_ask_stdout()))
    assert _call() is False
    err = capsys.readouterr().err
    assert "status=ask" in err
    assert "pending_id" not in err
    assert "pending_approve" not in err


def test_pending_status_is_not_captured_but_surfaces_pending_id(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # #3544 — a Pending (capture_turn.rs:467) is DURABLY QUEUED and recoverable
    # via memory_pending_approve. It is not a captured turn, but the shim must
    # NOT discard the pending_id — the only recovery handle — nor claim nothing
    # persisted. The id must survive to the caller (stderr), distinct from Ask.
    monkeypatch.setattr(
        _capture.subprocess, "run", _fake_run(_pending_stdout("pend-xyz-42"))
    )
    assert _call() is False
    err = capsys.readouterr().err
    assert "status=pending" in err
    assert "pend-xyz-42" in err
    assert "pending_approve" in err
