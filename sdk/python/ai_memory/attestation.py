# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""Ed25519 agent-attestation signing for the HTTP store path (#626 / #2455).

Why this module exists
----------------------

``POST /api/v1/memories`` is classified ``WriteSurface::HttpDirect``, which
**fails closed by default** (``src/identity/attest.rs:130-136`` — the ``_``
arm of ``resolve_require_agent_attestation`` returns ``true`` for
``HttpDirect`` when the env var is unset). An unsigned HTTP store is answered
with ``403 ATTESTATION_FAILED``.

Before #2455 this SDK shipped no signing helper and ``CreateMemory`` carried
no ``signature`` / ``created_at`` fields, so :meth:`AiMemoryClient.store`
could not succeed against a stock daemon at all. This module closes that: it
reproduces the daemon's ``SignableWrite`` envelope byte-for-byte and signs it,
so the SDK works against the **shipped fail-closed default** rather than
requiring the operator to weaken the daemon with
``AI_MEMORY_REQUIRE_AGENT_ATTESTATION=0``.

The envelope
------------

The signature is Ed25519 over the RFC 8949 §4.2.1 deterministic-CBOR encoding
of exactly seven entries (``src/identity/sign.rs::canonical_cbor_write``):

===================  =========================================================
``_dst``             domain-separation tag, always ``"ai-memory/write/v1"``
``kind``             memory kind (e.g. ``"observation"``, ``"decision"``)
``title``            memory title
``agent_id``         the claiming agent id
``namespace``        target namespace
``created_at``       RFC3339 timestamp the caller signed
``content_sha256``   SHA-256 of the content's UTF-8 bytes (CBOR byte string)
===================  =========================================================

Map keys are emitted in *encoded-key* sort order (length first, then
lexicographic), which for this fixed key set is the order shown above. The
byte-level agreement with the Rust encoder is pinned by a fixture printed by
the Rust encoder itself — see ``sdk/fixtures/write_attestation_vector.json``
and ``tests/test_attestation.py``.

Enrolling the key
-----------------

A signature only attests if the daemon has the matching public key bound to
the agent. Bind it once (admin-gated) via
``PUT /api/v1/agents/{id}/pubkey`` with body ``{"pubkey_b64": "..."}`` —
:meth:`AgentSigningKey.public_key_b64` emits the accepted form, and
:meth:`AiMemoryClient.bind_agent_pubkey` calls the route. Without a bound key
the daemon cannot verify and still returns 403 (fail-closed, by design).

Known limits (stated rather than hidden)
----------------------------------------

* The daemon redacts secret-screened content *before* verifying
  (``identity::attest::redact_before_sign``). If your content trips the
  credential screen under ``AI_MEMORY_SECRET_SCREEN_MODE=redact``, the bytes
  the daemon verifies differ from the bytes you signed and the write is
  refused. Under the default ``refuse`` mode such content is rejected earlier
  anyway. Do not put credentials in memories.
* ``created_at`` must be within the daemon's ±300s attestation freshness
  window (``ATTEST_CREATED_AT_SKEW_SECS``); sign shortly before sending.
* ``created_at`` must be the canonical storage-stable rendering (#3422) —
  UTC, ``+00:00``, microsecond-truncated. :func:`canonicalize_created_at`
  produces it and :func:`attestation_fields` applies it for you; the daemon
  refuses anything else, because no other rendering survives a PostgreSQL
  ``TIMESTAMPTZ`` round-trip byte-for-byte.
* The signature commits to those six fields ONLY — not tags, priority, or
  metadata.

Optional dependency
-------------------

Ed25519 needs ``cryptography``; install with ``pip install
"ai-memory-mcp[attestation]"``. Importing this module without it raises a
clear :class:`ImportError` at call time, not at import time, so the rest of
the SDK keeps working.
"""

from __future__ import annotations

import base64
import hashlib
import os
import re
import secrets
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

__all__ = [
    "DOMAIN_SEPARATION_TAG",
    "AgentSigningKey",
    "attestation_fields",
    "canonical_cbor_write",
    "canonicalize_created_at",
    "content_sha256",
    "rfc3339_now",
    "sign_write",
]

#: The ``_dst`` domain-separation value for the write envelope (#1931).
DOMAIN_SEPARATION_TAG = "ai-memory/write/v1"

#: Length of an Ed25519 seed / public key in bytes.
_KEY_LEN = 32


def _require_cryptography() -> Any:
    try:
        from cryptography.hazmat.primitives.asymmetric import ed25519
    except ImportError as exc:  # pragma: no cover - exercised by env, not CI
        raise ImportError(
            "Ed25519 agent attestation requires the 'cryptography' package. "
            'Install it with: pip install "ai-memory-mcp[attestation]"'
        ) from exc
    return ed25519


# ---------------------------------------------------------------------------
# Deterministic CBOR (RFC 8949 §4.2.1) — only the shapes this envelope needs.
# ---------------------------------------------------------------------------


def _cbor_head(major: int, length: int) -> bytes:
    """Encode a CBOR head for ``major`` with the minimal-width length."""
    prefix = major << 5
    if length < 24:
        return bytes([prefix | length])
    if length < 0x100:
        return bytes([prefix | 24, length])
    if length < 0x10000:
        return bytes([prefix | 25]) + length.to_bytes(2, "big")
    if length < 0x1_0000_0000:
        return bytes([prefix | 26]) + length.to_bytes(4, "big")
    return bytes([prefix | 27]) + length.to_bytes(8, "big")


def _cbor_text(value: str) -> bytes:
    raw = value.encode("utf-8")
    return _cbor_head(3, len(raw)) + raw


def _cbor_bytes(value: bytes) -> bytes:
    return _cbor_head(2, len(value)) + value


def content_sha256(content: str) -> bytes:
    """SHA-256 over the UTF-8 bytes of ``content`` (the bounded commitment)."""
    return hashlib.sha256(content.encode("utf-8")).digest()


def canonical_cbor_write(
    *,
    agent_id: str,
    namespace: str,
    title: str,
    kind: str,
    created_at: str,
    content_hash: bytes,
) -> bytes:
    """Deterministic-CBOR encoding of the ``SignableWrite`` envelope.

    Byte-identical to ``crate::identity::sign::canonical_cbor_write``.

    Args:
        content_hash: 32-byte SHA-256 digest from :func:`content_sha256`.

    Raises:
        ValueError: if ``content_hash`` is not exactly 32 bytes.
    """
    if len(content_hash) != _KEY_LEN:
        raise ValueError(
            f"content_hash must be a 32-byte SHA-256 digest, got {len(content_hash)}"
        )
    # RFC 8949 §4.2.1 orders map keys by their ENCODED bytes: shorter keys
    # first, then bytewise. For this fixed key set that is the literal order
    # below ('_' 0x5F sorts before 'k' 0x6B at length 4). Hard-coding the
    # resolved order keeps the encoder allocation-free and, more importantly,
    # makes any future key addition an explicit, reviewable re-ordering rather
    # than a silent one. The order is pinned against the Rust-emitted fixture.
    entries = (
        ("_dst", _cbor_text(DOMAIN_SEPARATION_TAG)),
        ("kind", _cbor_text(kind)),
        ("title", _cbor_text(title)),
        ("agent_id", _cbor_text(agent_id)),
        ("namespace", _cbor_text(namespace)),
        ("created_at", _cbor_text(created_at)),
        ("content_sha256", _cbor_bytes(content_hash)),
    )
    out = bytearray(_cbor_head(5, len(entries)))
    for key, encoded_value in entries:
        out += _cbor_text(key)
        out += encoded_value
    return bytes(out)


#: RFC3339 date-time, decomposed so sub-second digits are handled explicitly.
_RFC3339_PATTERN = re.compile(
    r"^(\d{4})-(\d{2})-(\d{2})[Tt ](\d{2}):(\d{2}):(\d{2})"
    r"(?:\.(\d+))?([Zz]|[+-]\d{2}:\d{2})$"
)


def canonicalize_created_at(value: str) -> str:
    """Canonicalize an RFC3339 timestamp into the ONE ``created_at`` rendering
    both daemon storage backends return byte-for-byte (#3422).

    The daemon REFUSES to attest any other rendering. ``created_at`` sits inside
    the signed ``SignableWrite`` envelope as TEXT, and every re-verification
    (the store gate, and the federation receive path on a relayed row) rebuilds
    the envelope from the *persisted row*: SQLite returns the stored TEXT
    verbatim, while PostgreSQL stores ``TIMESTAMPTZ`` (microseconds) and
    re-renders the readback as ``+00:00``. A signature minted over ``"...Z"``,
    over a non-UTC offset, or over nanosecond precision could therefore never
    be re-derived from a PostgreSQL row.

    Canonical form: UTC, ``+00:00`` offset, microseconds TRUNCATED (never
    rounded — that is what ``TIMESTAMPTZ`` does), and 0, 3 or 6 fractional
    digits, the shortest width that represents the value exactly (chrono's
    ``SecondsFormat::AutoSi``).

    Raises:
        ValueError: if ``value`` is not an RFC3339 date-time.
    """
    match = _RFC3339_PATTERN.match(value.strip())
    if match is None:
        raise ValueError(f"created_at must be an RFC3339 date-time, got: {value!r}")
    year, month, day, hour, minute, second, fraction, offset = match.groups()
    # TIMESTAMPTZ keeps microseconds and drops the rest — truncate, never round.
    micros = int(f"{fraction or ''}000000"[:6])
    tz = timezone.utc if offset in ("Z", "z") else timezone(_offset_delta(offset))
    moment = datetime(
        int(year),
        int(month),
        int(day),
        int(hour),
        int(minute),
        int(second),
        micros,
        tzinfo=tz,
    ).astimezone(timezone.utc)
    # Explicit field formatting rather than strftime: %Y is not guaranteed to
    # zero-pad (or even accept) years below 1000 across platforms.
    whole = (
        f"{moment.year:04d}-{moment.month:02d}-{moment.day:02d}"
        f"T{moment.hour:02d}:{moment.minute:02d}:{moment.second:02d}"
    )
    if moment.microsecond == 0:
        frac = ""
    elif moment.microsecond % 1000 == 0:
        frac = f".{moment.microsecond // 1000:03d}"
    else:
        frac = f".{moment.microsecond:06d}"
    return f"{whole}{frac}+00:00"


def _offset_delta(offset: str) -> timedelta:
    """``+HH:MM`` / ``-HH:MM`` as a :class:`datetime.timedelta`."""
    sign = -1 if offset.startswith("-") else 1
    return sign * timedelta(hours=int(offset[1:3]), minutes=int(offset[4:6]))


def rfc3339_now() -> str:
    """Current UTC time in the canonical ``created_at`` form the daemon
    persists and re-derives signatures from (#3422) — UTC, ``+00:00``,
    microsecond-truncated.
    """
    return canonicalize_created_at(datetime.now(timezone.utc).isoformat())


# ---------------------------------------------------------------------------
# Key handling
# ---------------------------------------------------------------------------


class AgentSigningKey:
    """An Ed25519 signing key for agent write attestation.

    Wraps a 32-byte seed — the exact on-disk format the daemon's own key
    store uses (``<key_dir>/<agent_id>.priv``, 32 raw bytes, mode 0600), so a
    key generated by ``ai-memory identity generate`` can be loaded directly
    with :meth:`from_file`.
    """

    __slots__ = ("_private",)

    def __init__(self, seed: bytes) -> None:
        if len(seed) != _KEY_LEN:
            raise ValueError(f"Ed25519 seed must be 32 bytes, got {len(seed)}")
        ed25519 = _require_cryptography()
        self._private = ed25519.Ed25519PrivateKey.from_private_bytes(seed)

    @classmethod
    def generate(cls) -> AgentSigningKey:
        """Generate a fresh key from the OS CSPRNG."""
        return cls(secrets.token_bytes(_KEY_LEN))

    @classmethod
    def from_file(cls, path: str | os.PathLike[str]) -> AgentSigningKey:
        """Load a 32-raw-byte ``<agent_id>.priv`` file."""
        return cls(Path(path).read_bytes())

    @classmethod
    def from_base64(cls, seed_b64: str) -> AgentSigningKey:
        """Load a seed from base64 (standard or URL-safe, padded or not)."""
        return cls(_b64_decode_any(seed_b64))

    def seed_bytes(self) -> bytes:
        """The raw 32-byte seed — write it mode 0600 if you persist it."""
        from cryptography.hazmat.primitives import serialization

        return self._private.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )

    def public_key_bytes(self) -> bytes:
        """The raw 32-byte Ed25519 public key."""
        from cryptography.hazmat.primitives import serialization

        return self._private.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

    def public_key_b64(self) -> str:
        """URL-safe, unpadded base64 public key.

        This is the form ``PUT /api/v1/agents/{id}/pubkey`` expects in its
        ``pubkey_b64`` body field, matching ``AgentKeypair::public_base64``.
        """
        return base64.urlsafe_b64encode(self.public_key_bytes()).decode("ascii").rstrip("=")

    def sign(self, payload: bytes) -> bytes:
        """Raw 64-byte Ed25519 signature over ``payload``."""
        return self._private.sign(payload)


def _b64_decode_any(value: str) -> bytes:
    """Decode standard or URL-safe base64, with or without padding."""
    raw = value.strip()
    padded = raw + "=" * (-len(raw) % 4)
    try:
        return base64.urlsafe_b64decode(padded)
    except (ValueError, TypeError):
        return base64.b64decode(padded)


# ---------------------------------------------------------------------------
# Signing
# ---------------------------------------------------------------------------


def sign_write(
    key: AgentSigningKey,
    *,
    agent_id: str,
    namespace: str,
    title: str,
    kind: str,
    created_at: str,
    content: str,
) -> str:
    """Sign a write envelope and return the STANDARD-base64 signature.

    Standard (not URL-safe) base64 is what ``prepare_signed_store`` decodes
    from the ``signature`` wire field (``src/identity/attest.rs:194``).
    """
    envelope = canonical_cbor_write(
        agent_id=agent_id,
        namespace=namespace,
        title=title,
        kind=kind,
        created_at=created_at,
        content_hash=content_sha256(content),
    )
    return base64.b64encode(key.sign(envelope)).decode("ascii")


def attestation_fields(
    key: AgentSigningKey,
    *,
    agent_id: str,
    namespace: str,
    title: str,
    content: str,
    kind: str = "observation",
    created_at: str | None = None,
) -> dict[str, str]:
    """Build the ``{"signature", "created_at", "kind"}`` triple for a store.

    The three keys drop straight into a ``CreateMemory`` body. ``created_at``
    defaults to now — the daemon adopts the value verbatim after checking it
    against the ±300s freshness window, so it must be the SAME string that
    was signed, which is why it is returned rather than left to the caller.

    #3422 — a caller-supplied ``created_at`` is folded through
    :func:`canonicalize_created_at` BEFORE signing, so the SDK always signs
    (and sends) the exact string the daemon will store and later re-derive the
    signature from on either backend.

    ``kind`` defaults to ``"observation"``, the daemon's own default when the
    field is absent — so an unspecified kind signs what the server will store.
    """
    ts = rfc3339_now() if created_at is None else canonicalize_created_at(created_at)
    return {
        "signature": sign_write(
            key,
            agent_id=agent_id,
            namespace=namespace,
            title=title,
            kind=kind,
            created_at=ts,
            content=content,
        ),
        "created_at": ts,
        "kind": kind,
    }
