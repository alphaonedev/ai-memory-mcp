# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""#3544 — the three reference host-adapter shims must agree, exactly.

Before this change all three mapped the `memory_capture_turn` envelope to
success by the ABSENCE of an enumerated failure:

* ``python/capture_turn.py:180``  ``return 0``      reached unless the substrate
  exited non-zero, emitted no ``id:2`` frame, or set ``result.isError``.
* ``node/capture-turn.mjs:206``   ``process.exit(0)`` — same three screens.
* ``bash/capture-turn.sh:173-176`` — implicit ``exit 0`` unless the raw response
  line matched ``grep -q '"isError":true'``.

So governance ``ask`` (nothing persisted, no recovery handle), governance
``pending`` (durably queued, NOT persisted), an unreadable payload, and any
``status`` a later substrate release grows were all reported to the host as a
captured turn. The host then had no signal that its transcript was not durable.

The predicate is now the PRESENCE form — captured iff the payload carries a
non-empty string ``memory_id`` — and this suite pins it three ways:

1. every cell of ``envelopes.CASES`` produces the right exit code, per adapter;
2. the stderr text is byte-identical across the three, so they are ONE
   predicate rather than three lookalikes that will drift;
3. the allowed path still passes: a persisted receipt and a dedup hit both
   exit 0, so the fix is not "refuse everything".
"""
from __future__ import annotations

import json
import os
import shutil
from pathlib import Path

import pytest

from conftest import ADAPTERS, adapter_available, run_adapter, run_adapter_argv
from envelopes import (
    CASES,
    DETAIL_NO_FRAME,
    INIT_LINE,
    KNOWN_STATUSES,
    PENDING_ID,
    PENDING_APPROVE_TOOL,
    PERSISTED_PAYLOAD,
    tool_result_line,
)

CASE_IDS = [c[0] for c in CASES]


def warn_lines(stderr: str) -> list[str]:
    return [ln[len("WARN: ") :] for ln in stderr.splitlines() if ln.startswith("WARN: ")]


@pytest.mark.parametrize(("case_id", "line", "exit_code", "detail"), CASES, ids=CASE_IDS)
def test_adapter_exit_code_matches_the_presence_predicate(
    adapter: str,
    tmp_path: Path,
    case_id: str,
    line: str,
    exit_code: int,
    detail: str,
) -> None:
    proc = run_adapter(adapter, tmp_path, [INIT_LINE, line])
    assert proc.returncode == exit_code, (
        f"{adapter}/{case_id}: exit {proc.returncode} != {exit_code}\n"
        f"stdout={proc.stdout}\nstderr={proc.stderr}"
    )
    if detail:
        assert detail in warn_lines(proc.stderr), (
            f"{adapter}/{case_id}: stderr did not carry the expected WARN\n"
            f"expected: {detail!r}\ngot: {proc.stderr!r}"
        )


@pytest.mark.parametrize(("case_id", "line", "exit_code", "detail"), CASES, ids=CASE_IDS)
def test_the_three_adapters_render_one_identical_verdict(
    tmp_path: Path, case_id: str, line: str, exit_code: int, detail: str
) -> None:
    """Three languages, ONE predicate: same exit code AND same stderr text."""
    available = [n for n in sorted(ADAPTERS) if adapter_available(n)]
    if len(available) < 2:
        pytest.skip("need at least two adapter runtimes to compare")
    verdicts: dict[str, tuple[int, list[str]]] = {}
    for name in available:
        d = tmp_path / name
        d.mkdir()
        proc = run_adapter(name, d, [INIT_LINE, line])
        verdicts[name] = (proc.returncode, warn_lines(proc.stderr))
    first = verdicts[available[0]]
    for name in available[1:]:
        assert verdicts[name] == first, (
            f"{case_id}: {name} disagrees with {available[0]} — the three "
            f"adapters are no longer one predicate\n{verdicts}"
        )
    assert first[0] == exit_code
    if detail:
        assert first[1] == [detail]
    else:
        assert first[1] == []


def test_pending_surfaces_the_recovery_handle(adapter: str, tmp_path: Path) -> None:
    """A `pending` turn is DEFERRED, not lost — the id that redeems it must ship."""
    pending_line = next(c[1] for c in CASES if c[0] == "pending")
    proc = run_adapter(adapter, tmp_path, [INIT_LINE, pending_line])
    assert proc.returncode == 2
    assert PENDING_ID in proc.stderr
    assert PENDING_APPROVE_TOOL in proc.stderr


def test_ask_claims_no_recovery_that_does_not_exist(
    adapter: str, tmp_path: Path
) -> None:
    """`ask` persists NOTHING and queues nothing: naming a handle would be a lie."""
    ask_line = next(c[1] for c in CASES if c[0] == "ask")
    proc = run_adapter(adapter, tmp_path, [INIT_LINE, ask_line])
    assert proc.returncode == 2
    assert "pending_id" not in proc.stderr
    assert "pending_approve" not in proc.stderr


def test_no_tools_call_frame_is_not_a_captured_turn(
    adapter: str, tmp_path: Path
) -> None:
    """Only the init frame comes back: nothing proves a row exists.

    Before #3544 the bash adapter took the LAST JSON-looking line whatever it
    was, so it classified the INIT response as the capture receipt and exited
    0. All three now select the tools/call frame by its id and report the same
    thing when there is none.
    """
    proc = run_adapter(adapter, tmp_path, [INIT_LINE])
    assert proc.returncode == 2, f"stdout={proc.stdout}\nstderr={proc.stderr}"
    assert warn_lines(proc.stderr) == [DETAIL_NO_FRAME]


def test_a_trailing_notification_cannot_be_mistaken_for_the_receipt(
    adapter: str, tmp_path: Path
) -> None:
    """The receipt is chosen by JSON-RPC id, not by position in the stream."""
    persisted = next(c[1] for c in CASES if c[0] == "persisted")
    trailing = json.dumps({"jsonrpc": "2.0", "method": "notifications/message"})
    proc = run_adapter(adapter, tmp_path, [INIT_LINE, persisted, trailing])
    assert proc.returncode == 0, f"stdout={proc.stdout}\nstderr={proc.stderr}"


def test_the_status_vocabulary_is_exactly_ask_and_pending() -> None:
    """`grep -n '"status"' src/mcp/tools/capture_turn.rs` returns exactly two.

    If the substrate grows a third, this is where the adapters learn about it —
    and until then an unknown status fails closed rather than being counted.
    """
    assert sorted(KNOWN_STATUSES) == ["ask", "pending"]


def test_bash_adapter_fails_closed_without_jq(tmp_path: Path) -> None:
    """Reading the receipt is a two-level JSON parse; grep cannot do it.

    Without jq the bash adapter cannot PROVE the turn was persisted, so it must
    refuse to report success rather than guess. Degrade, never lie about
    durability.
    """
    if not adapter_available("bash"):
        pytest.skip("bash not on this host")
    # A PATH with every external the script needs EXCEPT jq.
    bindir = tmp_path / "bin"
    bindir.mkdir()
    needed = ["cat", "sed", "grep", "tail", "head", "tr", "bash", "sh", "printf"]
    found = 0
    for tool in needed:
        src = shutil.which(tool)
        if src:
            (bindir / tool).symlink_to(src)
            found += 1
    assert found >= 6, "harness could not assemble a usable jq-less PATH"
    assert shutil.which("jq", path=str(bindir)) is None

    env = dict(os.environ)
    env["PATH"] = str(bindir)
    persisted = tool_result_line(PERSISTED_PAYLOAD)
    proc = run_adapter("bash", tmp_path, [INIT_LINE, persisted], env=env)
    assert proc.returncode == 2, (
        "jq-less bash adapter must NOT claim a captured turn it cannot verify\n"
        f"stdout={proc.stdout}\nstderr={proc.stderr}"
    )
    assert "jq not found" in proc.stderr


# ── direct unit pins on the Python adapter's classifier ───────────────────
# The adapter is importable (its work is behind `if __name__ == "__main__"`),
# so the predicate can be driven directly — far faster than a subprocess, and
# it pins the non-wedging invariant that the classifier is TOTAL.
def _python_adapter_module():
    import importlib.util

    from conftest import SHIM_ROOT

    path = SHIM_ROOT / "python" / "capture_turn.py"
    spec = importlib.util.spec_from_file_location("host_adapter_capture_turn", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_python_adapter_classifier_never_raises_on_hostile_input() -> None:
    """Total for any input: a wedged shim would take the host down with it."""
    mod = _python_adapter_module()
    hostile = [
        None,
        0,
        "",
        "not json",
        [],
        {},
        {"result": 7},
        {"result": {"content": []}},
        {"result": {"content": ["nope"]}},
        {"result": {"content": [{"text": "{"}]}},
        {"result": {"content": [{"text": "[]"}]}},
        {"error": {"code": -1}},
        {"result": {"content": [{"text": '{"memory_id": 7}'}]}},
        {"result": {"content": [{"text": '{"status": "pending"}'}]}},
    ]
    for value in hostile:
        kind, detail = mod.classify_capture_response(value)
        assert kind != mod.CAPTURED, f"must fail closed: {value!r}"
        assert isinstance(detail, str)


def test_python_adapter_status_constants_match_the_substrate() -> None:
    mod = _python_adapter_module()
    assert mod.STATUS_ASK == "ask"
    assert mod.STATUS_PENDING == "pending"
    assert mod.PENDING_APPROVE_TOOL == PENDING_APPROVE_TOOL
    assert sorted({mod.STATUS_ASK, mod.STATUS_PENDING}) == sorted(KNOWN_STATUSES)


def test_python_adapter_pending_without_an_id_still_refuses_and_says_so() -> None:
    """A `pending` receipt with no usable handle must not be reported as stored."""
    mod = _python_adapter_module()
    resp = {
        "result": {"content": [{"type": "text", "text": '{"status": "pending"}'}]}
    }
    kind, detail = mod.classify_capture_response(resp)
    assert kind == mod.PENDING
    assert "pending_id=null" in detail


# ── the rest of the exit-code contract, unchanged by #3544 ────────────────
# #3544 changes what exit 0 MEANS and widens what reaches exit 2. The SET is
# unchanged, and these cells hold the other two arms still so that claim is
# checked rather than asserted.
def test_missing_required_arg_is_a_usage_error(adapter: str) -> None:
    proc = run_adapter_argv(adapter, ["--host-session-id", "only-this-one"])
    assert proc.returncode == 1, f"stdout={proc.stdout}\nstderr={proc.stderr}"


def test_unreadable_content_file_exits_3(adapter: str, tmp_path: Path) -> None:
    missing = tmp_path / "does-not-exist.txt"
    proc = run_adapter_argv(
        adapter,
        [
            "--host-session-id",
            "sess-1",
            "--host-turn-index",
            "0",
            "--role",
            "user",
            "--content-file",
            str(missing),
            "--ai-memory-bin",
            "/nonexistent/ai-memory",
        ],
    )
    assert proc.returncode == 3, f"stdout={proc.stdout}\nstderr={proc.stderr}"
