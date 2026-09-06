# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""Offline coverage for the harness wake gate (#3470).

The gate exists to replace "poll and hope" with "wait for the wake, then
read". These tests pin the two properties that make that safe:

* with NO hub configured it is INERT — the harness behaves exactly as it did
  before #3470, so adding the gate cannot make a lane flaky;
* an unreachable or misconfigured hub DEGRADES to the same inert behaviour
  rather than failing the lane, because the durable inbox row is the record
  and the wake is only an optimisation over reading it.
"""

from __future__ import annotations

import asyncio
from pathlib import Path

from swarm.wake import (
    DEFAULT_WAIT_SECS,
    WakeGate,
    resolve_gate,
    wait_for_mail,
)

from ai_memory.wake import BACKSTOP_POLL_MAX, DEFAULT_HUB_ID


def test_the_gate_is_inert_unless_both_knobs_are_set() -> None:
    assert resolve_gate({}) is None
    assert resolve_gate({"SWARM_WAKE_HUB_SOCKET": "/x.sock"}) is None
    assert resolve_gate({"SWARM_WAKE_HUB_BUNDLE_DIR": "/keys"}) is None
    gate = resolve_gate(
        {"SWARM_WAKE_HUB_SOCKET": "/x.sock", "SWARM_WAKE_HUB_BUNDLE_DIR": "/keys"}
    )
    assert gate == WakeGate(Path("/x.sock"), Path("/keys"), DEFAULT_HUB_ID)
    assert gate.bundle_for("ai:alice") == Path("/keys/ai:alice.a2a-hub.json")

    scoped = resolve_gate(
        {
            "SWARM_WAKE_HUB_SOCKET": "/x.sock",
            "SWARM_WAKE_HUB_BUNDLE_DIR": "/keys",
            "SWARM_WAKE_HUB_ID": "hub-b",
        }
    )
    assert scoped is not None and scoped.hub_id == "hub-b"


def test_waiting_with_no_hub_returns_immediately() -> None:
    # Inert by default: the caller's read is unchanged, so the gate can never
    # turn a passing lane red.
    assert asyncio.run(wait_for_mail("ai:alice", gate=None, timeout=0.1)) is None


def test_an_unreachable_hub_degrades_rather_than_failing_the_lane(tmp_path: Path) -> None:
    gate = WakeGate(tmp_path / "absent.sock", tmp_path, DEFAULT_HUB_ID)
    # No bundle, no socket: the wait must return None, not raise.
    assert asyncio.run(wait_for_mail("ai:nobody", gate=gate, timeout=0.5)) is None


def test_the_default_wait_is_inside_the_normative_backstop() -> None:
    assert 0 < DEFAULT_WAIT_SECS <= BACKSTOP_POLL_MAX
