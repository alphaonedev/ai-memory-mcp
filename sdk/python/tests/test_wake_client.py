# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""Tests for the wake-hub client (#3470).

Two layers, on purpose:

* **Frame parsing and the state machine** run over a MOCK transport, so the
  wire contract and every refusal are pinned with no socket, no hub and no
  Rust binary.
* **One REAL-SOCKET test** against a running ``ai-memory wake-hub``, opt-in via
  ``AI_MEMORY_TEST_WAKE_HUB_SOCKET`` + ``AI_MEMORY_TEST_WAKE_HUB_BUNDLE``.
  Building the Rust hub is outside this pytest harness, so it skips cleanly
  when unset rather than pretending to have proved something it has not.
"""

from __future__ import annotations

import os
import socket
import struct
import threading
import time
from base64 import urlsafe_b64encode
from pathlib import Path

import pytest

from ai_memory.wake import (
    BACKSTOP_POLL_MAX,
    DelegationBundle,
    Frame,
    FrameReader,
    Kind,
    SeqTracker,
    WakeError,
    WakeListener,
    WakeMeta,
    WakeReason,
    Welcome,
    backoff_for,
    hello_transcript,
    topics_hash,
)

ed25519 = pytest.importorskip(
    "cryptography.hazmat.primitives.asymmetric.ed25519",
    reason="the wake client signs its hello with Ed25519",
)

HUB_ID = "hub-3470-py"
AGENT_ID = "ai:listener-3470"


# ---------------------------------------------------------------------------
# Fixtures: a bundle shaped exactly like `identity delegate --scope a2a-hub`
# ---------------------------------------------------------------------------


def _b64(raw: bytes) -> str:
    return urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _short(raw: bytes) -> bytes:
    return bytes([len(raw)]) + raw


def make_certificate(
    *,
    principal: str = AGENT_ID,
    scope: str = "a2a-hub",
    delegate_key_id: bytes,
    hub_id: str = HUB_ID,
    not_before: str | None = None,
    not_after: str | None = None,
) -> bytes:
    """The wire shape ``DelegationWire::encode`` produces."""
    from datetime import datetime, timedelta, timezone

    now = datetime.now(timezone.utc).replace(microsecond=0)
    nb = not_before or now.isoformat().replace("+00:00", "Z")
    na = not_after or (now + timedelta(hours=1)).isoformat().replace("+00:00", "Z")
    return (
        bytes([1])
        + _short(principal.encode())
        + _short(scope.encode())
        + delegate_key_id
        + _short(hub_id.encode())
        + _short(nb.encode())
        + _short(na.encode())
        # The issuer signature is opaque to this client: the HUB verifies it.
        + bytes(64)
    )


def make_bundle(**cert_kwargs) -> tuple[dict, ed25519.Ed25519PrivateKey]:
    key = ed25519.Ed25519PrivateKey.generate()
    public = key.public_key().public_bytes_raw()
    cert_kwargs.setdefault("delegate_key_id", public)
    cert = make_certificate(**cert_kwargs)
    bundle = {
        "version": 1,
        "agent_id": cert_kwargs.get("principal", AGENT_ID),
        "hub_id": cert_kwargs.get("hub_id", HUB_ID),
        "delegation_b64": _b64(cert),
        "delegate_private_b64": _b64(key.private_bytes_raw()),
        "not_before": "",
        "not_after": "",
    }
    return bundle, key


# ---------------------------------------------------------------------------
# Frame parsing
# ---------------------------------------------------------------------------


def test_frame_round_trips_and_carries_no_body_field() -> None:
    frame = Frame(Kind.WAKE, "producer", "ai:alice", b"\x01\x02")
    decoded = Frame.decode(frame.encode())
    assert decoded == frame
    # The v1 protocol has NO kind that admits a message body.
    assert not any(k.name in {"REQUEST", "REPLY", "NOTIFY"} for k in Kind)


@pytest.mark.parametrize("reserved", [11, 12, 13])
def test_reserved_body_kinds_are_refused_by_name(reserved: int) -> None:
    wire = bytearray(Frame(Kind.WAKE, "a", "b", b"").encode())
    wire[5] = reserved
    with pytest.raises(WakeError, match="permanently reserved"):
        Frame.decode(bytes(wire))


def test_a_malformed_frame_is_refused_rather_than_guessed_at() -> None:
    good = Frame(Kind.WAKE, "a", "b", b"xyz").encode()

    bad = bytearray(good)
    bad[0] ^= 0xFF
    with pytest.raises(WakeError, match="magic"):
        Frame.decode(bytes(bad))

    bad = bytearray(good)
    bad[4] = 9
    with pytest.raises(WakeError, match="unsupported wire version"):
        Frame.decode(bytes(bad))

    # Reserved header bytes are CHECKED, not ignored, so they stay available.
    for offset in (6, 9):
        bad = bytearray(good)
        bad[offset] = 1
        with pytest.raises(WakeError, match="reserved header byte"):
            Frame.decode(bytes(bad))

    with pytest.raises(WakeError, match="shorter than"):
        Frame.decode(good[:10])
    with pytest.raises(WakeError, match="declared length"):
        Frame.decode(good + b"trailing")


def test_wake_meta_decodes_the_hint_and_never_a_body() -> None:
    payload = (
        _short(b"row-3470")
        + _short(b"_inbox/ai:alice")
        + _short(b"ai:bob")
        + _short(bytes([0xAB]) * 32)
        + struct.pack(">Q", 42)
    )
    meta = WakeMeta.decode(payload)
    assert meta.inbox_row_id == "row-3470"
    assert meta.namespace == "_inbox/ai:alice"
    assert meta.sender == "ai:bob"
    assert meta.seq_high_watermark == 42
    assert meta.digest_hex == "ab" * 32
    assert not hasattr(meta, "body")

    # A digest is empty or exactly 32 bytes; anything else is a refusal.
    short_digest = (
        _short(b"r") + _short(b"n") + _short(b"s") + _short(b"\x01\x02") + struct.pack(">Q", 1)
    )
    with pytest.raises(WakeError, match="32 bytes"):
        WakeMeta.decode(short_digest)
    with pytest.raises(WakeError, match="ceiling"):
        WakeMeta.decode(b"\x00" * 300)


def test_welcome_decodes_the_offline_backlog_and_the_lagged_flag() -> None:
    raw = struct.pack(">IQI", 7, 3, 2) + bytes([1]) + struct.pack(">II", 250, 750)
    welcome = Welcome.decode(raw)
    assert (welcome.session, welcome.pending_count, welcome.pending_ids) == (7, 3, 2)
    assert welcome.lagged is True
    assert (welcome.reconnect_base_ms, welcome.reconnect_jitter_ms) == (250, 750)
    with pytest.raises(WakeError, match="25 bytes"):
        Welcome.decode(raw[:-1])


def test_the_hello_transcript_is_length_prefixed_so_it_is_injective() -> None:
    nonce = bytes(range(32))
    # Without length prefixes these two pairs would hash the same bytes and a
    # signature harvested for one would verify for the other.
    a = hello_transcript("ab", nonce, "c")
    b = hello_transcript("a", nonce, "bc")
    assert a != b
    assert a.startswith(b"a2a/v1/hello")
    assert a.endswith(topics_hash(()))
    with pytest.raises(WakeError, match="32 bytes"):
        hello_transcript("h", b"short", "a")


def test_the_frame_reader_survives_a_timeout_without_losing_its_buffer() -> None:
    """A generator that raises ``socket.timeout`` is dead; this must not be.

    The first backstop tick arrives as a timeout on a HEALTHY session, so a
    reader that could not resume would turn the poll into a session killer.
    """
    frame = Frame(Kind.WAKE, "p", "a", b"z").encode()
    wire = struct.pack(">I", len(frame)) + frame
    chunks = [wire[:3], socket.timeout(), wire[3:]]

    class Flaky:
        def recv(self, _size: int) -> bytes:
            item = chunks.pop(0)
            if isinstance(item, Exception):
                raise item
            return item

        def sendall(self, data: bytes) -> None: ...

        def settimeout(self, timeout: float | None) -> None: ...

        def close(self) -> None: ...

    reader = FrameReader(Flaky())
    with pytest.raises(socket.timeout):
        reader.next_frame()
    assert reader.next_frame() == Frame.decode(frame)


def test_an_oversize_length_prefix_is_refused_before_the_body_is_buffered() -> None:
    class Announcer:
        def recv(self, _size: int) -> bytes:
            return struct.pack(">I", 0xFFFFFFFF)

        def sendall(self, data: bytes) -> None: ...

        def settimeout(self, timeout: float | None) -> None: ...

        def close(self) -> None: ...

    with pytest.raises(WakeError, match="ceiling"):
        FrameReader(Announcer()).next_frame()


# ---------------------------------------------------------------------------
# Bundle: fail closed, with no flag that opens it
# ---------------------------------------------------------------------------


def test_a_freshly_minted_bundle_loads_and_signs_with_the_delegated_key() -> None:
    bundle, key = make_bundle()
    loaded = DelegationBundle.from_mapping(bundle, hub_id=HUB_ID)
    assert loaded.agent_id == AGENT_ID
    assert loaded.hub_id == HUB_ID

    nonce = bytes(32)
    transcript = hello_transcript(HUB_ID, nonce, AGENT_ID)
    payload = loaded.hello_payload(transcript)
    public = key.public_key().public_bytes_raw()
    assert payload[:32] == public
    key.public_key().verify(payload[32:96], transcript)
    # The topic list is EMPTY: own-inbox only (#3468).
    assert payload[-1] == 0
    # A repr is a log line: it never renders key material.
    assert "<delegated session key>" in repr(loaded)
    assert _b64(key.private_bytes_raw()) not in repr(loaded)


def test_a_bundle_for_another_hub_or_another_agent_is_refused() -> None:
    bundle, _ = make_bundle()
    with pytest.raises(WakeError, match="bound to ONE hub"):
        DelegationBundle.from_mapping(bundle, hub_id="some-other-hub")

    mismatched, _ = make_bundle(principal="ai:someone-else")
    mismatched["agent_id"] = AGENT_ID
    with pytest.raises(WakeError, match="speaks for"):
        DelegationBundle.from_mapping(mismatched, hub_id=HUB_ID)


def test_a_bundle_whose_key_is_not_the_certified_one_is_refused() -> None:
    bundle, _ = make_bundle()
    other = ed25519.Ed25519PrivateKey.generate()
    bundle["delegate_private_b64"] = _b64(other.private_bytes_raw())
    with pytest.raises(WakeError, match="NOT the key its certificate authorises"):
        DelegationBundle.from_mapping(bundle, hub_id=HUB_ID)


def test_a_foreign_scope_and_an_unknown_version_are_refused() -> None:
    bundle, _ = make_bundle(scope="write")
    with pytest.raises(WakeError, match="scope"):
        DelegationBundle.from_mapping(bundle, hub_id=HUB_ID)

    bundle, _ = make_bundle()
    bundle["version"] = 99
    with pytest.raises(WakeError, match="refused, never guessed at"):
        DelegationBundle.from_mapping(bundle, hub_id=HUB_ID)


def test_an_expired_bundle_is_refused_with_the_remediation() -> None:
    bundle, _ = make_bundle()
    future = time.time() + 86_400
    with pytest.raises(WakeError, match="identity delegate"):
        DelegationBundle.from_mapping(bundle, hub_id=HUB_ID, now=future)


def test_a_group_readable_or_symlinked_bundle_is_refused(tmp_path: Path) -> None:
    bundle, _ = make_bundle()
    import json

    path = tmp_path / "b.json"
    path.write_text(json.dumps(bundle), encoding="utf-8")
    path.chmod(0o600)
    DelegationBundle.load(path, hub_id=HUB_ID)

    path.chmod(0o644)
    with pytest.raises(WakeError, match="must be 0600"):
        DelegationBundle.load(path, hub_id=HUB_ID)
    path.chmod(0o600)

    link = tmp_path / "link.json"
    link.symlink_to(path)
    with pytest.raises(WakeError, match="symlink"):
        DelegationBundle.load(link, hub_id=HUB_ID)


def test_the_default_bundle_path_is_the_one_identity_delegate_writes() -> None:
    assert DelegationBundle.default_path("/keys", AGENT_ID) == Path(
        f"/keys/{AGENT_ID}.a2a-hub.json"
    )


# ---------------------------------------------------------------------------
# The state machine, over a mock transport
# ---------------------------------------------------------------------------


class MockTransport:
    """A scripted peer: one entry per ``recv``, in order.

    A frame per read rather than one big buffer, so a scripted
    ``socket.timeout()`` lands exactly where a real idle socket would put it —
    between frames, on a session that is still open.
    """

    def __init__(self, script: list[bytes | BaseException]) -> None:
        self.script: list[bytes | BaseException] = [
            item if isinstance(item, BaseException) else struct.pack(">I", len(item)) + item
            for item in script
        ]
        self.sent: list[Frame] = []
        self.timeouts: list[float | None] = []
        self._closed = False

    def recv(self, size: int) -> bytes:
        if not self.script:
            return b""  # peer closed
        item = self.script.pop(0)
        if isinstance(item, BaseException):
            raise item
        return item

    def sendall(self, data: bytes) -> None:
        (length,) = struct.unpack(">I", data[:4])
        self.sent.append(Frame.decode(data[4 : 4 + length]))

    def settimeout(self, timeout: float | None) -> None:
        self.timeouts.append(timeout)

    def close(self) -> None:
        self._closed = True


def listener(on_signal, **kwargs) -> WakeListener:
    bundle, _ = make_bundle()
    return WakeListener(
        "/nonexistent-3470.sock",
        DelegationBundle.from_mapping(bundle, hub_id=HUB_ID),
        on_signal,
        poll_interval=kwargs.pop("poll_interval", 5.0),
        **kwargs,
    )


def challenge_frame() -> bytes:
    return Frame(Kind.HELLO, "hub", "", bytes(32)).encode()


def welcome_frame(*, lagged: bool = False, pending: int = 0) -> bytes:
    payload = (
        struct.pack(">IQI", 1, pending, 0)
        + bytes([1 if lagged else 0])
        + struct.pack(">II", 250, 750)
    )
    return Frame(Kind.WELCOME, "hub", AGENT_ID, payload).encode()


def wake_frame(row: str, seq: int) -> bytes:
    payload = (
        _short(row.encode())
        + _short(b"_inbox/" + AGENT_ID.encode())
        + _short(b"ai:bob")
        + _short(bytes(32))
        + struct.pack(">Q", seq)
    )
    return Frame(Kind.WAKE, "wake-hub-producer", AGENT_ID, payload).encode()


def test_the_handshake_signs_the_hub_nonce_and_the_welcome_forces_one_read() -> None:
    signals = []
    transport = MockTransport([challenge_frame(), welcome_frame(pending=3)])
    with pytest.raises(WakeError, match="closed the connection"):
        listener(signals.append).pump(transport)

    hello = transport.sent[0]
    assert hello.kind is Kind.HELLO
    assert hello.from_id == AGENT_ID
    assert [s.reason for s in signals] == [WakeReason.WELCOME]
    assert signals[0].pending_count == 3
    assert signals[0].meta is None
    # The handshake is bounded, and the read loop is bounded by the poll.
    assert transport.timeouts[0] == 5.0 or transport.timeouts[0] > 0


def test_a_lagged_welcome_is_reported_as_lagged_not_as_a_plain_welcome() -> None:
    signals = []
    transport = MockTransport([challenge_frame(), welcome_frame(lagged=True)])
    with pytest.raises(WakeError):
        listener(signals.append).pump(transport)
    assert signals[0].reason is WakeReason.LAGGED


def test_each_wake_costs_exactly_one_read_and_a_gap_is_reported() -> None:
    signals = []
    transport = MockTransport(
        [challenge_frame(), welcome_frame(), wake_frame("row-a", 5), wake_frame("row-b", 9)]
    )
    with pytest.raises(WakeError):
        listener(signals.append).pump(transport)

    assert [s.reason for s in signals] == [
        WakeReason.WELCOME,
        WakeReason.WAKE,
        WakeReason.GAP,
    ]
    assert signals[1].missed == 0
    assert signals[2].missed == 3, "three wakes happened that this listener did not see"
    assert signals[2].meta.inbox_row_id == "row-b"


def test_a_ping_is_answered_in_place_and_costs_no_inbox_read() -> None:
    signals = []
    ping = Frame(Kind.PING, "hub", AGENT_ID, b"").encode()
    transport = MockTransport([challenge_frame(), welcome_frame(), ping])
    with pytest.raises(WakeError):
        listener(signals.append).pump(transport)
    assert [f.kind for f in transport.sent] == [Kind.HELLO, Kind.PONG]
    assert [s.reason for s in signals] == [WakeReason.WELCOME]


def test_an_unknown_frame_kind_is_ignored_rather_than_ending_the_session() -> None:
    signals = []
    depart = Frame(Kind.DEPART, "hub", AGENT_ID, b"").encode()
    transport = MockTransport(
        [challenge_frame(), welcome_frame(), depart, wake_frame("row-x", 1)]
    )
    with pytest.raises(WakeError):
        listener(signals.append).pump(transport)
    assert [s.reason for s in signals] == [WakeReason.WELCOME, WakeReason.WAKE]


def test_an_idle_session_fires_the_backstop_without_dropping_the_session() -> None:
    """A backstop tick on a HEALTHY session must not end the session.

    The poll arrives as a read timeout, so a client whose reader could not
    survive one would turn its own safety net into a session killer.
    """
    signals = []
    transport = MockTransport(
        [
            challenge_frame(),
            welcome_frame(),
            socket.timeout(),  # the backstop comes due while idle
            wake_frame("row-a", 1),  # ... and the SAME session keeps working
        ]
    )
    with pytest.raises(WakeError, match="closed the connection"):
        listener(signals.append).pump(transport)
    assert [s.reason for s in signals] == [
        WakeReason.WELCOME,
        WakeReason.BACKSTOP,
        WakeReason.WAKE,
    ]


def test_a_refused_handshake_is_a_legible_failure_not_a_silent_hang() -> None:
    error = Frame(Kind.ERROR, "hub", "", struct.pack(">H", 401) + b"unauthorized").encode()
    transport = MockTransport([challenge_frame(), error])
    with pytest.raises(WakeError, match="401 unauthorized"):
        listener(lambda _s: None).pump(transport)


def test_a_first_frame_that_is_not_a_challenge_is_refused() -> None:
    transport = MockTransport([welcome_frame()])
    with pytest.raises(WakeError, match="hello challenge"):
        listener(lambda _s: None).pump(transport)


# ---------------------------------------------------------------------------
# Bounds
# ---------------------------------------------------------------------------


def test_a_poll_interval_over_the_normative_bound_is_refused_not_clamped() -> None:
    with pytest.raises(WakeError, match="REFUSED rather than clamped"):
        listener(lambda _s: None, poll_interval=BACKSTOP_POLL_MAX + 1)
    with pytest.raises(WakeError):
        listener(lambda _s: None, poll_interval=0)
    assert listener(lambda _s: None, poll_interval=1).poll_interval == 1


def test_the_reconnect_ladder_is_capped_at_the_backstop() -> None:
    assert backoff_for(0.25, 1) == 0.25
    assert backoff_for(0.25, 2) == 0.5
    assert backoff_for(0.25, 30) == BACKSTOP_POLL_MAX
    assert backoff_for(3600.0, 1) == BACKSTOP_POLL_MAX


def test_the_seq_tracker_reports_a_gap_but_never_false_contiguity() -> None:
    t = SeqTracker()
    assert t.observe(100) == 0, "the welcome already forced a read"
    assert t.observe(101) == 0
    assert t.observe(105) == 3
    # A reordered or duplicated watermark must never rewind the baseline into
    # claiming a later gap that is not one.
    assert t.observe(103) == 0
    assert t.last == 105
    assert t.observe(106) == 0


def test_a_missing_hub_degrades_to_the_backstop_rather_than_dying() -> None:
    """No hub is the documented degraded mode, not an error."""
    signals: list = []
    stop = threading.Event()
    listen = listener(signals.append, poll_interval=0.05, reconnect_base=0.01, reconnect_jitter=0.0)

    thread = threading.Thread(target=listen.run, args=(stop,), daemon=True)
    thread.start()
    deadline = time.monotonic() + 5
    while not signals and time.monotonic() < deadline:
        time.sleep(0.02)
    stop.set()
    thread.join(timeout=5)

    assert signals, "the bounded poll must keep delivering with no hub at all"
    assert all(s.reason is WakeReason.BACKSTOP for s in signals)
    assert listen.metrics["reconnects"] >= 1
    assert listen.metrics["sessions"] == 0
    assert listen.last_error is not None


# ---------------------------------------------------------------------------
# Real socket, opt-in
# ---------------------------------------------------------------------------


@pytest.mark.skipif(
    not os.environ.get("AI_MEMORY_TEST_WAKE_HUB_SOCKET")
    or not os.environ.get("AI_MEMORY_TEST_WAKE_HUB_BUNDLE"),
    reason=(
        "set AI_MEMORY_TEST_WAKE_HUB_SOCKET + AI_MEMORY_TEST_WAKE_HUB_BUNDLE "
        "(and AI_MEMORY_TEST_WAKE_HUB_ID) to run against a live `ai-memory wake-hub`"
    ),
)
def test_a_real_hub_admits_this_client_over_a_real_socket() -> None:
    """The one leg that proves the wire contract against the Rust hub itself.

    Opt-in because building and running the hub is outside this harness; it
    skips rather than pretending to have proved something it has not.
    """
    sock_path = os.environ["AI_MEMORY_TEST_WAKE_HUB_SOCKET"]
    bundle_path = os.environ["AI_MEMORY_TEST_WAKE_HUB_BUNDLE"]
    hub_id = os.environ.get("AI_MEMORY_TEST_WAKE_HUB_ID", "ai-memory-wake-hub")

    bundle = DelegationBundle.load(bundle_path, hub_id=hub_id)
    signals: list = []
    listen = WakeListener(sock_path, bundle, signals.append, poll_interval=5.0)
    listen.assert_socket_is_owner_only()

    transport = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    transport.connect(sock_path)
    try:
        # The pump ends when the hub closes or the test stops it; one welcome
        # is all this leg needs to prove admission over the real wire.
        def stop_after_welcome(signal):
            signals.append(signal)
            raise KeyboardInterrupt

        listen.on_signal = stop_after_welcome
        with pytest.raises(KeyboardInterrupt):
            listen.pump(transport)
    finally:
        transport.close()

    assert signals and signals[0].reason in {WakeReason.WELCOME, WakeReason.LAGGED}
    assert listen.metrics["sessions"] == 1
