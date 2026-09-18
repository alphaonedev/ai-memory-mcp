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


def _result_stdout(payload: dict[str, object]) -> str:
    """Wrap a capture_turn tool payload the way `mcp/mod.rs:3762` does.

    The handler `Value` is `serde_json::to_string_pretty`-serialised into
    `result.content[0].text`, so the payload rides one level of JSON nesting.
    """
    import json as _json

    return (
        _json.dumps(
            {
                "jsonrpc": "2.0",
                "id": 2,
                "result": {"content": [{"type": "text", "text": _json.dumps(payload)}]},
            }
        )
        + "\n"
    )


def _persisted_payload(*, dedup_hit: bool = False) -> dict[str, object]:
    """The real persisted envelope, copied from `capture_turn.rs:531-547`.

    Note it carries NO `status` key at all — `memory_id` is the only positive
    evidence the turn was stored, and RFC-0001 lists it in the tool result's
    `required` set (`docs/rfc/RFC-0001-mcp-turn-capture.md:160`).
    """
    payload: dict[str, object] = {
        "memory_id": "mem-0c9f4e11",
        "dedup_hit": dedup_hit,
        "layer": "L4",
        "agent_id": "ai:test@host",
        "elapsed_ms": 3,
    }
    if not dedup_hit:
        payload["attest_level"] = "none"
    return payload


def test_ok_result_response_is_success(monkeypatch: pytest.MonkeyPatch) -> None:
    # #3544 — ALLOWED-PATH CONTROL. The fixture is the substrate's real
    # persisted envelope, not a placeholder string: a predicate that refuses
    # everything would pin nothing, so the captured path must stay True.
    monkeypatch.setattr(
        _capture.subprocess, "run", _fake_run(_result_stdout(_persisted_payload()))
    )
    assert _call() is True


def test_dedup_hit_envelope_is_success(monkeypatch: pytest.MonkeyPatch) -> None:
    # `capture_turn.rs:531-538` — an idempotent re-delivery. The row exists and
    # the existing `memory_id` comes back, so the turn IS captured.
    monkeypatch.setattr(
        _capture.subprocess,
        "run",
        _fake_run(_result_stdout(_persisted_payload(dedup_hit=True))),
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


# ── #3544 fail-closed cells ───────────────────────────────────────────────
# The fix that landed for ask/pending was still the ABSENCE form: it asked
# "is this one of the two statuses I enumerated?" and treated everything else
# as a captured turn. These four cells drive the shapes that form lets
# through. Each returns True on the pre-fix module and False on the fix.


def test_unknown_status_is_not_captured(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # A `status` value outside the substrate's closed vocabulary
    # (`capture_turn.rs` renders exactly "ask" and "pending"). Nothing proves
    # this turn was stored, so the shim must NOT claim it was — including for
    # a status a future substrate release adds that this shim has never seen.
    monkeypatch.setattr(
        _capture.subprocess,
        "run",
        _fake_run(
            _result_stdout(
                {
                    "status": "quarantined",
                    "reason": "a status this shim has never seen",
                    "action": "memory_capture_turn",
                }
            )
        ),
    )
    assert _call() is False
    err = capsys.readouterr().err
    assert "no memory_id" in err
    assert "quarantined" in err
    assert "NOT persisted" in err


def test_payload_without_memory_id_is_not_captured(monkeypatch: pytest.MonkeyPatch) -> None:
    # An empty tool payload: no status, no id, no evidence of a write.
    monkeypatch.setattr(_capture.subprocess, "run", _fake_run(_result_stdout({})))
    assert _call() is False


def test_blank_memory_id_is_not_captured(monkeypatch: pytest.MonkeyPatch) -> None:
    # Presence is not enough — an empty string is not a memory id. Absence and
    # emptiness are different, and neither is a stored turn.
    monkeypatch.setattr(
        _capture.subprocess,
        "run",
        _fake_run(_result_stdout({"memory_id": "", "dedup_hit": False, "layer": "L4"})),
    )
    assert _call() is False


def test_unreadable_payload_is_not_captured(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # `result.content[0].text` that is not a JSON object at all. The shim
    # cannot read what the substrate did, so it fails CLOSED rather than
    # assume the turn was stored.
    monkeypatch.setattr(
        _capture.subprocess,
        "run",
        _fake_run('{"jsonrpc":"2.0","id":2,"result":{"content":[{"type":"text","text":"ok"}]}}\n'),
    )
    assert _call() is False
    assert "unreadable" in capsys.readouterr().err


def test_no_response_frame_is_not_captured(monkeypatch: pytest.MonkeyPatch) -> None:
    # The substrate produced no frame carrying the tools/call id.
    monkeypatch.setattr(_capture.subprocess, "run", _fake_run(""))
    assert _call() is False
