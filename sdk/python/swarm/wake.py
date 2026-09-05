# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""Wake-plane gate for the swarm harness (#3470, EPIC #3466).

What this replaces
------------------

Wherever the harness needed to see an agent's mail it did what the fleet did:
read the inbox and hope the write had landed, or poll again. The fleet's
standing instruction was literally *"poll every 3 minutes"*, and the harness's
own consumer lanes read B's inbox immediately after A notified — a race that is
only ever won because both sides are on one host.

:func:`wait_for_mail` closes both: when a wake hub is configured it BLOCKS on
the wake plane until the recipient is told it has mail, then the caller does
the read it was going to do anyway. When no hub is configured it returns
immediately and the caller's read is exactly what it was before — this gate can
make a lane deterministic, never flaky, and never a new dependency.

Configuration
-------------

Three env vars, all optional; missing any one leaves the gate INERT:

===============================  =============================================
``SWARM_WAKE_HUB_SOCKET``        the ``ai-memory wake-hub`` Unix socket
``SWARM_WAKE_HUB_BUNDLE_DIR``    directory holding per-agent delegation
                                 bundles, as written by ``ai-memory identity
                                 delegate --scope a2a-hub``
``SWARM_WAKE_HUB_ID``            hub id (default ``ai-memory-wake-hub``)
===============================  =============================================

The bundle for agent ``X`` is ``<bundle-dir>/X.a2a-hub.json``, mode 0600,
holding a DELEGATED key and never an enrolled one — the harness mints no
identity of its own and embeds no second identity root.

Bounded, always
---------------

Every wait is bounded by ``timeout`` (default
:data:`DEFAULT_WAIT_SECS`, itself inside the normative
``wake_sink::BACKSTOP_POLL_MAX``). A hub that is down, refusing, or absent
makes :func:`wait_for_mail` return ``None`` promptly and the caller reads
anyway: the durable inbox row is the record, so a wake is only ever an
optimisation over the read that follows.
"""

from __future__ import annotations

import asyncio
import os
import threading
from dataclasses import dataclass
from pathlib import Path

from ai_memory.wake import (
    BACKSTOP_POLL_MAX,
    DEFAULT_HUB_ID,
    DelegationBundle,
    WakeError,
    WakeListener,
    WakeReason,
    WakeSignal,
)

__all__ = ["WakeGate", "DEFAULT_WAIT_SECS", "resolve_gate", "wait_for_mail"]

#: Default bound on one wait. Inside the normative backstop so a harness lane
#: can never wait longer than the plane's own contract.
DEFAULT_WAIT_SECS = 10.0

ENV_SOCKET = "SWARM_WAKE_HUB_SOCKET"
ENV_BUNDLE_DIR = "SWARM_WAKE_HUB_BUNDLE_DIR"
ENV_HUB_ID = "SWARM_WAKE_HUB_ID"


@dataclass(frozen=True)
class WakeGate:
    """A configured wake plane the harness may wait on."""

    socket_path: Path
    bundle_dir: Path
    hub_id: str = DEFAULT_HUB_ID

    def bundle_for(self, agent_id: str) -> Path:
        return DelegationBundle.default_path(self.bundle_dir, agent_id)


def resolve_gate(env: dict[str, str] | None = None) -> WakeGate | None:
    """Resolve the gate from the environment, or ``None`` when unconfigured.

    Unconfigured is the DEFAULT and is not an error: the harness then behaves
    exactly as it did before #3470.
    """
    src = os.environ if env is None else env
    socket_path = src.get(ENV_SOCKET, "").strip()
    bundle_dir = src.get(ENV_BUNDLE_DIR, "").strip()
    if not socket_path or not bundle_dir:
        return None
    return WakeGate(
        socket_path=Path(socket_path),
        bundle_dir=Path(bundle_dir),
        hub_id=src.get(ENV_HUB_ID, "").strip() or DEFAULT_HUB_ID,
    )


def _wait_blocking(gate: WakeGate, agent_id: str, timeout: float) -> WakeSignal | None:
    """Block until this agent is told it has mail, or the bound expires."""
    bundle = DelegationBundle.load(gate.bundle_for(agent_id), hub_id=gate.hub_id)
    captured: list[WakeSignal] = []
    arrived = threading.Event()
    stop = threading.Event()

    def on_signal(signal: WakeSignal) -> None:
        # An empty welcome means "you are attached", not "you have mail": on a
        # healthy hub every session is welcomed at once, so returning there
        # would make this gate a no-op.
        if signal.reason is WakeReason.WELCOME and signal.pending_count == 0:
            return
        captured.append(signal)
        arrived.set()
        stop.set()

    listener = WakeListener(
        gate.socket_path,
        bundle,
        on_signal,
        # Bounded by the caller's own timeout as well, so this can never wait
        # longer than the lane allows.
        poll_interval=max(0.1, min(timeout, BACKSTOP_POLL_MAX)),
    )
    thread = threading.Thread(target=listener.run, args=(stop,), daemon=True)
    thread.start()
    arrived.wait(timeout)
    # The run loop exits on `stop` and closes its socket on the way out.
    stop.set()
    thread.join(timeout=2.0)
    return captured[0] if captured else None


async def wait_for_mail(
    agent_id: str,
    *,
    gate: WakeGate | None = None,
    timeout: float = DEFAULT_WAIT_SECS,
) -> WakeSignal | None:
    """Wait for ``agent_id`` to be told it has mail, if a hub is configured.

    Returns the signal, or ``None`` when there is no hub, the wait timed out,
    or the plane is unreachable. In EVERY one of those cases the caller should
    simply perform the inbox read it was going to perform: the durable row is
    the record and this gate is a latency optimisation over it, never a
    precondition for it.
    """
    resolved = gate or resolve_gate()
    if resolved is None:
        return None
    try:
        return await asyncio.to_thread(_wait_blocking, resolved, agent_id, timeout)
    except (WakeError, OSError):
        # Degrade, never fail the lane: an unreachable or misconfigured wake
        # plane must not turn a durable-truth assertion into a red test.
        return None
