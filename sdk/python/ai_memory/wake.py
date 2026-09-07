# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""Minimal ``ai-memory wake-hub`` client (issue #3470, EPIC #3466).

Why this module exists
----------------------

Before the wake plane, an agent learned it had mail by polling
``GET /api/v1/inbox``. The reference fleet polled every three minutes. This
module is the Python half of the replacement: keep ONE authenticated session
on the hub's Unix domain socket and read the inbox when there is something to
read — with a bounded ``<= 60 s`` poll so a lost hub degrades LATENCY and
nothing else.

What it carries, and what it cannot
-----------------------------------

The hub is CONTENT-FREE by construction: the v1 protocol has no ``request`` /
``reply`` / ``notify`` kinds, and the largest routed payload is a 256-byte
hint ``{inbox_row_id, namespace, sender, digest, seq_high_watermark}``. So a
wake tells you WHICH row to read and gives you a SHA-256 you can verify it
against; the durable ai-memory inbox row is the record, and reading it is your
job (:meth:`AiMemoryClient.inbox` / :meth:`AsyncAiMemoryClient.inbox`).

One identity root
-----------------

This client embeds NO identity of its own. It loads the scoped
``a2a-hub/join/v1`` delegation bundle that ``ai-memory identity delegate
--scope a2a-hub`` writes into the agent's key directory
(``<key-dir>/<agent-id>.a2a-hub.json``, mode 0600). That bundle holds a
DELEGATED private key and never the agent's enrolled one, so a compromised
listener is worth "someone may be woken as me until this expires", never
"someone may write my history". It never reads an enrolled ``.priv``, never
generates key material, and never writes a key.

Every check :meth:`DelegationBundle.load` performs is a REFUSAL, and there is
deliberately no flag that skips one:

* the file must be a regular file (never a symlink) owned by the caller,
  mode 0600 — the standard the writer enforced;
* the ``version`` must be one this module understands;
* the certificate must carry scope ``a2a-hub``, the bundle's own principal,
  and the hub id about to be dialled;
* the private key must be the one the certificate authorises, so a bundle
  whose seed was swapped is refused here rather than becoming an opaque 401;
* the validity window must contain ``now``.

**Stated honestly:** the certificate's ISSUER SIGNATURE — the proof that the
agent's enrolled key minted it — is verified authoritatively by the HUB, and
additionally pre-checked locally by the Rust ``ai-memory wake-listen``. This
SDK does not reproduce the canonical-CBOR pre-image, so it does not re-verify
that signature. That is a DEGRADE, never a widening: this client can present a
bundle the hub then refuses, but it can never admit one the hub would refuse.

The catch-up read is yours, and there is exactly one per event
-------------------------------------------------------------

:class:`WakeListener` never reads your inbox for you; it calls the callback you
supply, exactly ONCE per event — on the welcome, on each wake, when the welcome
reports ``lagged``, and when a wake's ``seq_high_watermark`` skips (wakes
happened that you did not see). Never a read per queued hint.

The backstop is always armed
----------------------------

The bounded poll runs whether or not the hub is reachable, and its clock is
reset by every catch-up read rather than firing on a fixed schedule. A hub that
is down, refusing, or was never deployed therefore costs latency only, bounded
by :data:`BACKSTOP_POLL_MAX`. ``poll_interval`` above that bound is REFUSED
rather than clamped: a client that silently polled less often than the plane's
contract would be reporting a guarantee it does not provide. Reconnects use
jittered exponential backoff capped at the same bound, so a hub restart cannot
produce a synchronised reconnect blast across a fleet.

Example
-------
>>> from ai_memory import AiMemoryClient
>>> from ai_memory.wake import DelegationBundle, WakeListener
>>> bundle = DelegationBundle.load(  # doctest: +SKIP
...     "/home/alice/.config/ai-memory/keys/ai:alice.a2a-hub.json",
...     hub_id="ai-memory-wake-hub",
... )
>>> client = AiMemoryClient(base_url="http://localhost:9077")  # doctest: +SKIP
>>> def catch_up(signal):  # doctest: +SKIP
...     print(signal.reason, client.inbox(agent_id=bundle.agent_id, unread_only=True))
>>> WakeListener("/run/user/1000/ai-memory/wake-hub.sock", bundle, catch_up).run()  # doctest: +SKIP
"""

from __future__ import annotations

import hashlib
import os
import random
import socket
import stat
import struct
import threading
import time
from base64 import urlsafe_b64decode
from dataclasses import dataclass
from enum import Enum, IntEnum
from pathlib import Path
from typing import Any, Callable, Protocol

import json

__all__ = [
    "BACKSTOP_POLL_MAX",
    "DEFAULT_HUB_ID",
    "DelegationBundle",
    "Frame",
    "FrameReader",
    "Kind",
    "SeqTracker",
    "WakeError",
    "WakeListener",
    "WakeMeta",
    "WakeReason",
    "WakeSignal",
    "Welcome",
    "backoff_for",
    "hello_transcript",
    "topics_hash",
]

#: Normative maximum interval between inbox reads (``wake_sink::BACKSTOP_POLL_MAX``).
#: A wake-plane client MUST read at least this often; the hub holds no durable
#: truth, so this poll — not the hint — is the delivery guarantee.
BACKSTOP_POLL_MAX = 60.0

#: Compiled default hub identifier (``wake_hub::DEFAULT_HUB_ID``).
DEFAULT_HUB_ID = "ai-memory-wake-hub"

#: Wire constants (``wake_hub::limits``).
_MAGIC = b"AWH1"
_WIRE_VERSION = 1
_FRAME_HEADER_BYTES = 24
_MAX_FRAME_BYTES = _FRAME_HEADER_BYTES + (2 * 128) + 1_536
_HELLO_NONCE_BYTES = 32
_PUBKEY_BYTES = 32
_SIGNATURE_BYTES = 64
_WAKE_DIGEST_BYTES = 32
_MAX_WAKE_META_BYTES = 256
_WELCOME_BYTES = 4 + 8 + 4 + 1 + 4 + 4
_HELLO_TRANSCRIPT_DOMAIN = b"a2a/v1/hello"
_A2A_HUB_SCOPE = "a2a-hub"
_DELEGATION_WIRE_VERSION = 1
_DELEGATE_KEY_ID_BYTES = 32
_BUNDLE_VERSION = 1
_HANDSHAKE_TIMEOUT = 5.0
_DEFAULT_RECONNECT_BASE = 0.25
_DEFAULT_RECONNECT_JITTER = 0.75
#: A session must LAST this long before the reconnect ladder resets, so a hub
#: that accepts and instantly drops cannot become a hot loop.
_HEALTHY_SESSION = 30.0


class WakeError(Exception):
    """A refusal from the wake plane. Every one of these is fail-closed."""


class Kind(IntEnum):
    """Frame kinds the v1 protocol admits. There is no body kind."""

    HELLO = 1
    WELCOME = 2
    JOIN = 3
    DEPART = 4
    SUBSCRIBE = 5
    UNSUBSCRIBE = 6
    WAKE = 7
    PING = 8
    PONG = 9
    ERROR = 10


#: Wire numbers permanently reserved for the removed body-bearing kinds. A peer
#: that sends one is refused BY NAME rather than ignored, so a client built
#: against the pre-vote draft fails closed with a legible error.
RESERVED_PAYLOAD_KINDS = (11, 12, 13)


@dataclass(frozen=True)
class Frame:
    """One decoded wake-hub frame."""

    kind: Kind
    from_id: str
    to_id: str
    payload: bytes
    ts_ms: int = 0
    ttl_ms: int = 0

    def encode(self) -> bytes:
        """Encode the frame body (the codec adds the length prefix)."""
        f = self.from_id.encode("utf-8")
        t = self.to_id.encode("utf-8")
        if len(f) > 128 or len(t) > 128:
            raise WakeError("an agent id may not exceed 128 bytes")
        if len(self.payload) > 0xFFFF:
            raise WakeError("payload exceeds the u16 length field")
        return (
            _MAGIC
            + bytes([_WIRE_VERSION, int(self.kind), 0, len(f), len(t), 0])
            + struct.pack(">HQI", len(self.payload), self.ts_ms, self.ttl_ms)
            + f
            + t
            + self.payload
        )

    @staticmethod
    def decode(body: bytes) -> "Frame":
        """Decode a frame body, refusing every malformed or reserved shape."""
        if len(body) < _FRAME_HEADER_BYTES:
            raise WakeError(f"frame shorter than the {_FRAME_HEADER_BYTES}-byte header")
        if body[0:4] != _MAGIC:
            raise WakeError("frame did not start with the wake-hub magic")
        if body[4] != _WIRE_VERSION:
            raise WakeError(f"unsupported wire version {body[4]}")
        raw_kind = body[5]
        if raw_kind in RESERVED_PAYLOAD_KINDS:
            raise WakeError(
                f"wire kind {raw_kind} is permanently reserved: the wake plane "
                "carries no message bodies"
            )
        try:
            kind = Kind(raw_kind)
        except ValueError as exc:  # pragma: no cover - defensive
            raise WakeError(f"unknown wire kind {raw_kind}") from exc
        # Reserved bytes are CHECKED, not ignored, so they stay available for a
        # future version instead of being quietly accepted by today's parser.
        if body[6] != 0 or body[9] != 0:
            raise WakeError("a reserved header byte was non-zero")
        from_len, to_len = body[7], body[8]
        payload_len, ts_ms, ttl_ms = struct.unpack(">HQI", body[10:24])
        end = _FRAME_HEADER_BYTES + from_len + to_len + payload_len
        if len(body) != end:
            raise WakeError(f"declared length {end} != actual {len(body)}")
        off = _FRAME_HEADER_BYTES
        from_id = body[off : off + from_len].decode("utf-8")
        off += from_len
        to_id = body[off : off + to_len].decode("utf-8")
        off += to_len
        return Frame(kind, from_id, to_id, body[off:], ts_ms, ttl_ms)


@dataclass(frozen=True)
class WakeMeta:
    """The content-free hint a ``wake`` carries. There is no body field."""

    inbox_row_id: str
    namespace: str
    sender: str
    #: SHA-256 of the notification body, so a recipient can verify what it
    #: later READS without the hub ever having seen it.
    digest: bytes
    #: The producer's host-wide wake counter when the hint was minted. Read it
    #: as "wakes happened that you did not see"; the correct response to a gap
    #: is ONE catch-up read.
    seq_high_watermark: int

    @property
    def digest_hex(self) -> str:
        """Lowercase hex, comparable against ``sha256sum`` output."""
        return self.digest.hex()

    @staticmethod
    def decode(buf: bytes) -> "WakeMeta":
        if len(buf) > _MAX_WAKE_META_BYTES:
            raise WakeError(f"wake metadata {len(buf)} B exceeds the 256 B ceiling")
        fields: list[bytes] = []
        rest = buf
        for _ in range(4):
            if not rest:
                raise WakeError("wake metadata ended mid-field")
            length = rest[0]
            if len(rest) - 1 < length:
                raise WakeError("wake metadata ended mid-field")
            fields.append(rest[1 : 1 + length])
            rest = rest[1 + length :]
        if len(rest) != 8:
            raise WakeError("wake metadata ended mid-field")
        digest = fields[3]
        if digest and len(digest) != _WAKE_DIGEST_BYTES:
            raise WakeError("a digest is empty or exactly 32 bytes")
        return WakeMeta(
            inbox_row_id=fields[0].decode("utf-8"),
            namespace=fields[1].decode("utf-8"),
            sender=fields[2].decode("utf-8"),
            digest=digest,
            seq_high_watermark=struct.unpack(">Q", rest)[0],
        )


@dataclass(frozen=True)
class Welcome:
    """What the hub tells an accepted session."""

    session: int
    #: Wakes coalesced while this agent was offline.
    pending_count: int
    #: Distinct inbox-row ids retained from that window.
    pending_ids: int
    #: ``True`` when the pending set stopped retaining ids: the client MUST do
    #: a full catch-up read rather than trust the id set.
    lagged: bool
    reconnect_base_ms: int
    reconnect_jitter_ms: int

    @staticmethod
    def decode(buf: bytes) -> "Welcome":
        if len(buf) != _WELCOME_BYTES:
            raise WakeError(f"welcome is {_WELCOME_BYTES} bytes, got {len(buf)}")
        session, pending_count, pending_ids = struct.unpack(">IQI", buf[0:16])
        base, jitter = struct.unpack(">II", buf[17:25])
        return Welcome(session, pending_count, pending_ids, buf[16] != 0, base, jitter)


def topics_hash(topics: tuple[str, ...] = ()) -> bytes:
    """SHA-256 over the canonical topic list (``wake_hub::identity``)."""
    h = hashlib.sha256()
    for t in topics:
        raw = t.encode("utf-8")
        h.update(bytes([min(len(raw), 255)]))
        h.update(raw)
    return h.digest()


def hello_transcript(
    hub_id: str, nonce: bytes, agent_id: str, topics: tuple[str, ...] = ()
) -> bytes:
    """Build the domain-separated, length-prefixed hello transcript.

    The length prefixes are what make the encoding injective: without them
    ``hub_id="ab", agent_id="c"`` and ``hub_id="a", agent_id="bc"`` would hash
    the same bytes and a signature harvested for one pair would verify for the
    other.
    """
    if len(nonce) != _HELLO_NONCE_BYTES:
        raise WakeError(f"the hello nonce is {_HELLO_NONCE_BYTES} bytes")
    hub = hub_id.encode("utf-8")
    agent = agent_id.encode("utf-8")
    return (
        _HELLO_TRANSCRIPT_DOMAIN
        + bytes([len(hub)])
        + hub
        + nonce
        + bytes([len(agent)])
        + agent
        + topics_hash(topics)
    )


def _take_short(buf: bytes) -> tuple[bytes, bytes]:
    if not buf:
        raise WakeError("delegation certificate ended mid-field")
    length = buf[0]
    if len(buf) - 1 < length:
        raise WakeError("delegation certificate ended mid-field")
    return buf[1 : 1 + length], buf[1 + length :]


@dataclass
class _Certificate:
    principal: str
    scope: str
    delegate_key_id: bytes
    hub_id: str
    not_before: str
    not_after: str

    @staticmethod
    def decode(buf: bytes) -> "_Certificate":
        if not buf or buf[0] != _DELEGATION_WIRE_VERSION:
            raise WakeError("delegation certificate has an unsupported version")
        principal, rest = _take_short(buf[1:])
        scope, rest = _take_short(rest)
        if len(rest) < _DELEGATE_KEY_ID_BYTES:
            raise WakeError("delegation certificate ended mid-field")
        key_id, rest = rest[:_DELEGATE_KEY_ID_BYTES], rest[_DELEGATE_KEY_ID_BYTES:]
        hub_id, rest = _take_short(rest)
        not_before, rest = _take_short(rest)
        not_after, rest = _take_short(rest)
        if len(rest) != _SIGNATURE_BYTES:
            raise WakeError("delegation certificate ended mid-field")
        return _Certificate(
            principal.decode("utf-8"),
            scope.decode("utf-8"),
            key_id,
            hub_id.decode("utf-8"),
            not_before.decode("utf-8"),
            not_after.decode("utf-8"),
        )


class DelegationBundle:
    """The scoped ``a2a-hub/join/v1`` credential, loaded from the key dir.

    Construct it with :meth:`load` (or :meth:`from_mapping` in tests). The
    delegated private key stays in memory for the life of the process and is
    never rendered by ``repr``.
    """

    __slots__ = ("agent_id", "hub_id", "not_after", "_delegation", "_signing_key")

    def __init__(
        self,
        agent_id: str,
        hub_id: str,
        not_after: str,
        delegation: bytes,
        signing_key: Any,
    ) -> None:
        self.agent_id = agent_id
        self.hub_id = hub_id
        self.not_after = not_after
        self._delegation = delegation
        self._signing_key = signing_key

    def __repr__(self) -> str:  # pragma: no cover - trivial
        # A repr is a log line; it never renders key material.
        return (
            f"DelegationBundle(agent_id={self.agent_id!r}, hub_id={self.hub_id!r}, "
            f"not_after={self.not_after!r}, delegation_bytes={len(self._delegation)}, "
            "delegate='<delegated session key>')"
        )

    @staticmethod
    def default_path(key_dir: str | os.PathLike[str], agent_id: str) -> Path:
        """Where ``ai-memory identity delegate --scope a2a-hub`` writes it."""
        return Path(key_dir) / f"{agent_id}.a2a-hub.json"

    @classmethod
    def load(
        cls,
        path: str | os.PathLike[str],
        *,
        hub_id: str = DEFAULT_HUB_ID,
        now: float | None = None,
    ) -> "DelegationBundle":
        """Load and check a bundle. Every failure is a refusal."""
        p = Path(path)
        st = p.lstat()
        if stat.S_ISLNK(st.st_mode):
            raise WakeError(
                f"{p} is a symlink: a credential reached through a link is one whose "
                "permissions were checked on the wrong file"
            )
        if not stat.S_ISREG(st.st_mode):
            raise WakeError(f"{p} is not a regular file")
        if st.st_mode & 0o077:
            raise WakeError(
                f"{p} is mode {st.st_mode & 0o7777:04o}; a bundle holding a private key "
                "must be 0600, or another local user can join the hub as this agent"
            )
        if st.st_uid != os.geteuid():
            raise WakeError(f"{p} is owned by uid {st.st_uid}, not by the caller")
        return cls.from_mapping(
            json.loads(p.read_text(encoding="utf-8")),
            hub_id=hub_id,
            source=str(p),
            now=now,
        )

    @classmethod
    def from_mapping(
        cls,
        bundle: dict[str, Any],
        *,
        hub_id: str = DEFAULT_HUB_ID,
        source: str = "<bundle>",
        now: float | None = None,
    ) -> "DelegationBundle":
        """The verification core, over an already-parsed bundle."""
        version = bundle.get("version")
        if version != _BUNDLE_VERSION:
            raise WakeError(
                f"{source} is a v{version} delegation bundle; this client reads "
                f"v{_BUNDLE_VERSION}. A credential format this build does not "
                "understand is refused, never guessed at."
            )
        agent_id = bundle.get("agent_id") or ""
        if not agent_id:
            raise WakeError(f"{source} names no agent, so there is no identity to join as")
        if bundle.get("hub_id") != hub_id:
            raise WakeError(
                f"{source} was minted for hub {bundle.get('hub_id')!r} but this client "
                f"dials {hub_id!r}. A delegation is bound to ONE hub on purpose."
            )
        certificate = _b64(bundle.get("delegation_b64", ""), f"{source}: delegation_b64")
        cert = _Certificate.decode(certificate)
        if cert.scope != _A2A_HUB_SCOPE:
            raise WakeError(
                f"{source}: the certificate carries scope {cert.scope!r}, not "
                f"{_A2A_HUB_SCOPE!r}. The scope element exists to be CHECKED."
            )
        if cert.principal != agent_id:
            raise WakeError(
                f"{source}: the certificate speaks for {cert.principal!r} but the bundle "
                f"claims {agent_id!r}"
            )
        if cert.hub_id != hub_id:
            raise WakeError(f"{source}: the certificate is bound to hub {cert.hub_id!r}")

        seed = _b64(bundle.get("delegate_private_b64", ""), f"{source}: delegate_private_b64")
        if len(seed) != _DELEGATE_KEY_ID_BYTES:
            raise WakeError(
                f"{source}: the delegated seed is {len(seed)} bytes, not "
                f"{_DELEGATE_KEY_ID_BYTES}"
            )
        signing_key = _ed25519_key(seed)
        public = signing_key.public_key().public_bytes_raw()
        if public != cert.delegate_key_id:
            raise WakeError(
                f"{source}: the bundle's private key is NOT the key its certificate "
                "authorises. A mismatched pair is a tampered bundle, not a credential."
            )
        _check_window(cert, source, now)
        return cls(agent_id, hub_id, cert.not_after, certificate, signing_key)

    def sign_hello(self, transcript: bytes) -> bytes:
        """Sign one hub-issued hello transcript with the DELEGATED key."""
        return self._signing_key.sign(transcript)

    def hello_payload(self, transcript: bytes) -> bytes:
        """Build the ``hello`` payload: key, signature, delegation, no topics.

        NO topics: a substrate wake is addressed directly to the recipient and
        the hub's route table is keyed by the identity the hello authenticated,
        so this session can only ever be handed wakes for its own inbox.
        Subscribing to a topic would be asking for wakes the delegation does
        not cover.
        """
        public = self._signing_key.public_key().public_bytes_raw()
        signature = self.sign_hello(transcript)
        return (
            public
            + signature
            + struct.pack(">H", len(self._delegation))
            + self._delegation
            + bytes([0])  # zero topics
        )


def _b64(value: str, what: str) -> bytes:
    try:
        return urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except Exception as exc:  # noqa: BLE001 - any decode failure is one refusal
        raise WakeError(f"{what} is not base64url") from exc


def _ed25519_key(seed: bytes) -> Any:
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    except ImportError as exc:  # pragma: no cover - optional dependency
        raise WakeError(
            "Ed25519 support requires the `cryptography` package: "
            'pip install "ai-memory-mcp[attestation]"'
        ) from exc
    return Ed25519PrivateKey.from_private_bytes(seed)


def _check_window(cert: _Certificate, source: str, now: float | None) -> None:
    from datetime import datetime, timezone

    def parse(value: str) -> float:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()

    try:
        start, end = parse(cert.not_before), parse(cert.not_after)
    except ValueError as exc:
        raise WakeError(f"{source}: the certificate window does not parse") from exc
    stamp = time.time() if now is None else now
    if not start <= stamp < end:
        raise WakeError(
            f"{source}: the certificate is outside its validity window "
            f"[{cert.not_before}, {cert.not_after}). Mint a fresh one with "
            "`ai-memory identity delegate --scope a2a-hub`."
        )


class WakeReason(str, Enum):
    """Why a catch-up inbox read is due.

    Reported so an operator can tell "the hub told me" from "the backstop
    fired" — the second silently replacing the first is exactly what a broken
    wake plane looks like.
    """

    WELCOME = "welcome"
    LAGGED = "lagged"
    WAKE = "wake"
    GAP = "gap"
    BACKSTOP = "backstop"

    @property
    def is_hub_driven(self) -> bool:
        return self is not WakeReason.BACKSTOP


@dataclass(frozen=True)
class WakeSignal:
    """One "read your inbox now" signal."""

    reason: WakeReason
    meta: WakeMeta | None = None
    pending_count: int = 0
    missed: int = 0


@dataclass
class SeqTracker:
    """Turns a ``seq_high_watermark`` gap into exactly one extra read.

    Fail-safe in one direction only: it may report a gap that was not one
    (after a producer restart, say), costing one redundant read; it can never
    report contiguity across a real gap.
    """

    last: int | None = None

    def observe(self, seq: int) -> int:
        # The first wake of a session establishes the baseline: the session's
        # own welcome already forced a catch-up read.
        missed = 0 if self.last is None else max(0, seq - self.last - 1)
        self.last = seq if self.last is None else max(self.last, seq)
        return missed


def backoff_for(base: float, attempt: int) -> float:
    """Exponential reconnect delay, capped at :data:`BACKSTOP_POLL_MAX`.

    The cap IS the backstop: waiting longer than the interval a client polls at
    anyway would buy nothing and only widen the window in which a recovered hub
    sits idle.
    """
    shift = min(max(attempt - 1, 0), 16)
    return min(base * (2**shift), BACKSTOP_POLL_MAX)


class _Transport(Protocol):
    """The seam a test replaces with a mock instead of a real socket."""

    def sendall(self, data: bytes) -> None: ...

    def recv(self, size: int) -> bytes: ...

    def settimeout(self, timeout: float | None) -> None: ...

    def close(self) -> None: ...


class FrameReader:
    """Decodes length-delimited frames off a transport, across timeouts.

    Deliberately NOT a generator: a generator that raises ``socket.timeout``
    is closed and can never be resumed, which would turn the very first
    backstop tick into a permanently dead session. Holding the partial buffer
    as state means a timeout is exactly what it should be — "nothing arrived
    yet" — and the next read continues where this one stopped.
    """

    __slots__ = ("_transport", "_buf")

    def __init__(self, transport: _Transport) -> None:
        self._transport = transport
        self._buf = b""

    def next_frame(self) -> Frame | None:
        """The next frame, or ``None`` when the peer closed.

        Propagates ``socket.timeout`` / ``TimeoutError`` to the caller so the
        backstop can fire without ending the session.
        """
        while True:
            frame = self._try_parse()
            if frame is not None:
                return frame
            chunk = self._transport.recv(65536)
            if not chunk:
                return None
            self._buf += chunk

    def _try_parse(self) -> Frame | None:
        # The u32 length prefix is checked against the frame ceiling BEFORE a
        # byte of body is buffered, so a peer that announces a 4 GiB frame
        # gets a refusal rather than a 4 GiB allocation.
        if len(self._buf) < 4:
            return None
        (length,) = struct.unpack(">I", self._buf[:4])
        if length > _MAX_FRAME_BYTES:
            raise WakeError(f"peer announced a {length} B frame; ceiling is {_MAX_FRAME_BYTES}")
        if len(self._buf) < 4 + length:
            return None
        body = self._buf[4 : 4 + length]
        self._buf = self._buf[4 + length :]
        return Frame.decode(body)


def write_frame(transport: _Transport, frame: Frame) -> None:
    """Write one frame with the hub's own length prefix."""
    body = frame.encode()
    if len(body) > _MAX_FRAME_BYTES:
        raise WakeError("refusing to emit a frame the hub would refuse to read")
    transport.sendall(struct.pack(">I", len(body)) + body)


class WakeListener:
    """One long-lived session, plus the bounded poll that makes it safe.

    ``on_signal`` is called EXACTLY ONCE per event and is where you perform
    your catch-up inbox read. It is never called concurrently with itself.
    """

    def __init__(
        self,
        socket_path: str | os.PathLike[str],
        bundle: DelegationBundle,
        on_signal: Callable[[WakeSignal], None],
        *,
        poll_interval: float = BACKSTOP_POLL_MAX,
        reconnect_base: float = _DEFAULT_RECONNECT_BASE,
        reconnect_jitter: float = _DEFAULT_RECONNECT_JITTER,
        rng: random.Random | None = None,
    ) -> None:
        if not 0 < poll_interval <= BACKSTOP_POLL_MAX:
            raise WakeError(
                f"poll_interval {poll_interval}s is outside (0, {BACKSTOP_POLL_MAX}]. "
                "The ceiling is REFUSED rather than clamped so nothing silently runs "
                "slower than the wake plane's contract."
            )
        self.socket_path = Path(socket_path)
        self.bundle = bundle
        self.on_signal = on_signal
        self.poll_interval = poll_interval
        self.reconnect_base = reconnect_base
        self.reconnect_jitter = reconnect_jitter
        self._rng = rng or random.Random()
        #: Counters, so a listener that silently stopped reading does not look
        #: like a quiet inbox.
        self.metrics: dict[str, int] = {"signals": 0, "sessions": 0, "reconnects": 0}
        #: The most recent session failure, so a listener that is degraded to
        #: the backstop can say WHY rather than looking like a quiet inbox.
        self.last_error: str | None = None

    # -- socket posture ----------------------------------------------------
    def assert_socket_is_owner_only(self) -> None:
        """Refuse to dial a socket this host does not keep private.

        The mirror of the hub's own bind-time posture: an owner-only directory
        holding an owner-only socket, both owned by the caller. Dialling a
        socket another local user could have created would hand this client's
        handshake to whoever won that race.
        """
        parent = self.socket_path.parent
        pst = parent.stat()
        if pst.st_uid != os.geteuid():
            raise WakeError(f"{parent} is owned by uid {pst.st_uid}, not by the caller")
        if pst.st_mode & 0o077:
            raise WakeError(
                f"{parent} is mode {pst.st_mode & 0o7777:04o}; the wake-hub socket "
                "directory must be 0700"
            )
        st = self.socket_path.lstat()
        if stat.S_ISLNK(st.st_mode):
            raise WakeError(f"{self.socket_path} is a symlink")
        if not stat.S_ISSOCK(st.st_mode):
            raise WakeError(f"{self.socket_path} is not a socket")
        if st.st_uid != os.geteuid():
            raise WakeError(f"{self.socket_path} is owned by uid {st.st_uid}")
        if st.st_mode & 0o077:
            raise WakeError(
                f"{self.socket_path} is mode {st.st_mode & 0o7777:04o}; a wake-hub "
                "socket must be 0600"
            )

    # -- state machine -----------------------------------------------------
    def _emit(self, signal: WakeSignal) -> None:
        self.metrics["signals"] += 1
        self.on_signal(signal)

    def pump(self, transport: _Transport, seq: SeqTracker | None = None) -> None:
        """Handshake, then turn frames into signals until the peer closes.

        Split out from :meth:`run` so a test can drive it over a mock
        transport with no socket at all.
        """
        transport.settimeout(_HANDSHAKE_TIMEOUT)
        frames = FrameReader(transport)
        challenge = frames.next_frame()
        if challenge is None or challenge.kind is not Kind.HELLO:
            raise WakeError("the hub's first frame must be a hello challenge")
        if len(challenge.payload) != _HELLO_NONCE_BYTES:
            raise WakeError(f"the hello challenge is {_HELLO_NONCE_BYTES} bytes")
        transcript = hello_transcript(
            self.bundle.hub_id, challenge.payload, self.bundle.agent_id
        )
        write_frame(
            transport,
            Frame(Kind.HELLO, self.bundle.agent_id, "", self.bundle.hello_payload(transcript)),
        )
        reply = frames.next_frame()
        if reply is None:
            raise WakeError("the hub closed the connection before welcoming")
        if reply.kind is Kind.ERROR:
            raise WakeError(f"the hub refused the handshake: {_error_text(reply.payload)}")
        if reply.kind is not Kind.WELCOME:
            raise WakeError(f"the hub answered the hello with {reply.kind.name}, not a welcome")
        welcome = Welcome.decode(reply.payload)
        self.metrics["sessions"] += 1
        self._emit(
            WakeSignal(
                WakeReason.LAGGED if welcome.lagged else WakeReason.WELCOME,
                pending_count=welcome.pending_count,
            )
        )

        tracker = seq if seq is not None else SeqTracker()
        transport.settimeout(self.poll_interval)
        while True:
            try:
                frame = frames.next_frame()
            except (socket.timeout, TimeoutError):
                # Nothing arrived inside the bound: the backstop IS due, and
                # the hub session stays open.
                self._emit(WakeSignal(WakeReason.BACKSTOP))
                continue
            if frame is None:
                raise WakeError("the hub closed the connection")
            if frame.kind is Kind.WAKE:
                meta = WakeMeta.decode(frame.payload)
                missed = tracker.observe(meta.seq_high_watermark)
                self._emit(
                    WakeSignal(
                        WakeReason.GAP if missed else WakeReason.WAKE,
                        meta=meta,
                        missed=missed,
                    )
                )
            elif frame.kind is Kind.PING:
                write_frame(transport, Frame(Kind.PONG, self.bundle.agent_id, frame.from_id, b""))
            elif frame.kind is Kind.ERROR:
                raise WakeError(f"the hub refused this session: {_error_text(frame.payload)}")
            # Anything else is ignored rather than fatal: a future hub may send
            # frames this version has no opinion about, and dropping the
            # session over one would trade wake latency for nothing.

    # -- the loop ----------------------------------------------------------
    def _jitter(self) -> float:
        return self._rng.uniform(0.0, self.reconnect_jitter)

    def run(self, stop: threading.Event | None = None) -> None:
        """Connect, serve, back off, repeat — until ``stop`` is set.

        Every failure here degrades to LATENCY: the bounded backstop keeps
        firing while the reconnect ladder runs, and the durable inbox row is
        untouched.
        """
        attempt = 0
        next_backstop = time.monotonic() + self.poll_interval
        while not (stop is not None and stop.is_set()):
            started = time.monotonic()
            transport: socket.socket | None = None
            try:
                self.assert_socket_is_owner_only()
                transport = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                transport.connect(str(self.socket_path))
                self.pump(transport)
            except Exception as exc:  # noqa: BLE001 - every failure is one backoff
                if time.monotonic() - started >= _HEALTHY_SESSION:
                    # This session carried wakes for a while, so the ladder it
                    # inherited describes an outage that is over.
                    attempt = 0
                attempt += 1
                self.metrics["reconnects"] += 1
                self.last_error = str(exc)
                deadline = time.monotonic() + backoff_for(self.reconnect_base, attempt) + self._jitter()
                # The backstop stays armed WHILE disconnected: a hub that is
                # down, refusing, or absent must cost LATENCY and nothing else.
                while time.monotonic() < deadline:
                    naptime = min(deadline, next_backstop) - time.monotonic()
                    if naptime > 0:
                        if stop is not None:
                            if stop.wait(naptime):
                                return
                        else:
                            time.sleep(naptime)
                    if time.monotonic() >= next_backstop:
                        self._emit(WakeSignal(WakeReason.BACKSTOP))
                        next_backstop = time.monotonic() + self.poll_interval
            finally:
                if transport is not None:
                    transport.close()


def _error_text(payload: bytes) -> str:
    if len(payload) < 2:
        return "unparseable refusal"
    (code,) = struct.unpack(">H", payload[:2])
    return f"{code} {payload[2:].decode('utf-8', 'replace')}"
