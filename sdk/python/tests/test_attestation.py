# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""Write-attestation conformance against a RUST-GENERATED vector (#2455).

``POST /api/v1/memories`` is ``WriteSurface::HttpDirect`` and fails CLOSED by
default, so before #2455 :meth:`AiMemoryClient.store` could not succeed at all
against a stock daemon: ``CreateMemory`` had no ``signature`` / ``created_at``
fields and the SDK shipped no Ed25519 helper.

The load-bearing assertion here is byte-equality of the canonical CBOR
envelope with the one the RUST encoder emits
(``sdk/fixtures/write_attestation_vector.json``, provenance documented in the
fixture). An SDK that signs a *different* byte sequence than the daemon
verifies produces a 403 that looks like a key-enrollment problem, so a
self-computed "expected" value would prove nothing.

The Ed25519 primitive itself is pinned separately against RFC 8032 §7.1
TEST 3 — an external authority, independent of ai-memory.
"""

from __future__ import annotations

import base64
import json
from pathlib import Path
from typing import Any

import pytest

from ai_memory._common import build_create_body

pytest.importorskip(
    "cryptography",
    reason="attestation extra not installed (pip install 'ai-memory-mcp[attestation]')",
)

from ai_memory.attestation import (  # after importorskip, by design
    DOMAIN_SEPARATION_TAG,
    AgentSigningKey,
    attestation_fields,
    canonical_cbor_write,
    canonicalize_created_at,
    content_sha256,
    rfc3339_now,
    sign_write,
)

_FIXTURE = (
    Path(__file__).resolve().parents[2] / "fixtures" / "write_attestation_vector.json"
)


@pytest.fixture(scope="module")
def vector() -> dict[str, Any]:
    return json.loads(_FIXTURE.read_text(encoding="utf-8"))


# ---------------------------------------------------------------------------
# Envelope conformance — the R-203 regression surface
# ---------------------------------------------------------------------------


def test_content_hash_matches_rust(vector: dict[str, Any]) -> None:
    assert content_sha256(vector["content"]).hex() == vector["content_sha256_hex"]


def test_canonical_cbor_is_byte_identical_to_rust(vector: dict[str, Any]) -> None:
    """The signed bytes must equal what the daemon re-derives, exactly."""
    encoded = canonical_cbor_write(
        agent_id=vector["agent_id"],
        namespace=vector["namespace"],
        title=vector["title"],
        kind=vector["kind"],
        created_at=vector["created_at"],
        content_hash=content_sha256(vector["content"]),
    )
    assert encoded.hex() == vector["canonical_cbor_hex"]


def test_domain_separation_tag_matches_rust(vector: dict[str, Any]) -> None:
    assert DOMAIN_SEPARATION_TAG == vector["domain_separation_tag"]


def test_envelope_commits_to_every_field(vector: dict[str, Any]) -> None:
    """Changing ANY signed field must change the envelope bytes.

    A field silently dropped from the encoding would let a signature minted
    for one write be replayed onto another — the exact reason the daemon puts
    these six inside the envelope.
    """
    base_kwargs = {
        "agent_id": vector["agent_id"],
        "namespace": vector["namespace"],
        "title": vector["title"],
        "kind": vector["kind"],
        "created_at": vector["created_at"],
        "content_hash": content_sha256(vector["content"]),
    }
    baseline = canonical_cbor_write(**base_kwargs)  # type: ignore[arg-type]
    for field in ("agent_id", "namespace", "title", "kind", "created_at"):
        mutated = dict(base_kwargs)
        mutated[field] = f"{base_kwargs[field]}-x"
        assert canonical_cbor_write(**mutated) != baseline, field  # type: ignore[arg-type]
    mutated = dict(base_kwargs)
    mutated["content_hash"] = content_sha256(vector["content"] + " changed")
    assert canonical_cbor_write(**mutated) != baseline  # type: ignore[arg-type]


def test_rejects_non_32_byte_content_hash(vector: dict[str, Any]) -> None:
    with pytest.raises(ValueError):
        canonical_cbor_write(
            agent_id=vector["agent_id"],
            namespace=vector["namespace"],
            title=vector["title"],
            kind=vector["kind"],
            created_at=vector["created_at"],
            content_hash=b"too-short",
        )


# ---------------------------------------------------------------------------
# Ed25519 primitive — pinned against RFC 8032, not against ourselves
# ---------------------------------------------------------------------------


def test_ed25519_matches_rfc8032_test3(vector: dict[str, Any]) -> None:
    tv = vector["rfc8032_test3"]
    key = AgentSigningKey(bytes.fromhex(tv["seed_hex"]))
    assert key.public_key_bytes().hex() == tv["public_key_hex"]
    assert key.sign(bytes.fromhex(tv["message_hex"])).hex() == tv["signature_hex"]


def test_public_key_b64_is_urlsafe_unpadded(vector: dict[str, Any]) -> None:
    """``PUT /agents/{id}/pubkey`` expects the `AgentKeypair::public_base64` form."""
    tv = vector["rfc8032_test3"]
    key = AgentSigningKey(bytes.fromhex(tv["seed_hex"]))
    b64 = key.public_key_b64()
    assert "=" not in b64 and "+" not in b64 and "/" not in b64
    assert base64.urlsafe_b64decode(b64 + "==").hex() == tv["public_key_hex"]


def test_seed_round_trips() -> None:
    key = AgentSigningKey.generate()
    assert AgentSigningKey(key.seed_bytes()).public_key_bytes() == key.public_key_bytes()


def test_rejects_wrong_length_seed() -> None:
    with pytest.raises(ValueError):
        AgentSigningKey(b"\x00" * 31)


# ---------------------------------------------------------------------------
# Wire-field assembly
# ---------------------------------------------------------------------------


def test_signature_is_standard_base64(vector: dict[str, Any]) -> None:
    """``prepare_signed_store`` decodes STANDARD base64, not URL-safe."""
    key = AgentSigningKey(bytes.fromhex(vector["rfc8032_test3"]["seed_hex"]))
    sig = sign_write(
        key,
        agent_id=vector["agent_id"],
        namespace=vector["namespace"],
        title=vector["title"],
        kind=vector["kind"],
        created_at=vector["created_at"],
        content=vector["content"],
    )
    assert len(base64.b64decode(sig, validate=True)) == 64


def test_attestation_fields_signs_the_returned_created_at(vector: dict[str, Any]) -> None:
    """The returned ``created_at`` must be the one that was signed.

    The daemon adopts the wire ``created_at`` verbatim and re-derives the
    envelope from it; a mismatch is an unexplainable 403.
    """
    key = AgentSigningKey.generate()
    fields = attestation_fields(
        key,
        agent_id=vector["agent_id"],
        namespace=vector["namespace"],
        title=vector["title"],
        content=vector["content"],
        kind=vector["kind"],
    )
    expected = sign_write(
        key,
        agent_id=vector["agent_id"],
        namespace=vector["namespace"],
        title=vector["title"],
        kind=vector["kind"],
        created_at=fields["created_at"],
        content=vector["content"],
    )
    assert fields["signature"] == expected
    assert fields["kind"] == vector["kind"]


def test_attestation_fields_defaults_kind_to_observation(vector: dict[str, Any]) -> None:
    """Default must equal the SERVER's default, or a signed write 403s."""
    key = AgentSigningKey.generate()
    fields = attestation_fields(
        key,
        agent_id=vector["agent_id"],
        namespace=vector["namespace"],
        title=vector["title"],
        content=vector["content"],
    )
    assert fields["kind"] == "observation"


def test_rfc3339_now_is_offset_form() -> None:
    assert rfc3339_now().endswith("+00:00")


# ---------------------------------------------------------------------------
# #3422 - canonical, storage-stable created_at
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        # `Z` suffix -> the `+00:00` form postgres returns.
        ("2026-09-01T12:00:00Z", "2026-09-01T12:00:00+00:00"),
        # Non-UTC offset -> the same instant, canonically rendered.
        ("2026-09-01T14:00:00+02:00", "2026-09-01T12:00:00+00:00"),
        # Already canonical -> unchanged (fixpoint).
        ("2026-09-01T12:00:00+00:00", "2026-09-01T12:00:00+00:00"),
        # Sub-microsecond digits cannot survive TIMESTAMPTZ: truncated.
        ("2026-09-01T12:00:00.123456789Z", "2026-09-01T12:00:00.123456+00:00"),
        # AutoSi widths: 0, 3 or 6 digits - the shortest exact rendering.
        ("2026-09-01T12:00:00.000Z", "2026-09-01T12:00:00+00:00"),
        ("2026-09-01T12:00:00.100000Z", "2026-09-01T12:00:00.100+00:00"),
        ("2026-09-01T12:00:00.123400Z", "2026-09-01T12:00:00.123400+00:00"),
    ],
)
def test_canonicalize_created_at_matches_the_daemon_form(raw: str, expected: str) -> None:
    """#3422 - the daemon refuses any rendering it cannot round-trip."""
    assert canonicalize_created_at(raw) == expected
    # Idempotent: the canonical form is its own fixpoint.
    assert canonicalize_created_at(expected) == expected


def test_canonicalize_created_at_rejects_non_rfc3339() -> None:
    with pytest.raises(ValueError):
        canonicalize_created_at("2026-09-01 noon")


def test_attestation_fields_signs_the_canonical_created_at() -> None:
    """#3422 - a caller-supplied `...Z` stamp is canonicalized BEFORE signing,
    so the SDK signs and sends exactly what the daemon will store."""
    key = AgentSigningKey.generate()
    fields = attestation_fields(
        key,
        agent_id="ai:sdk-demo@example",
        namespace="team/alpha",
        title="pg upgrade window",
        content="body",
        created_at="2026-09-01T12:00:00Z",
    )
    assert fields["created_at"] == "2026-09-01T12:00:00+00:00"
    assert fields["signature"] == sign_write(
        key,
        agent_id="ai:sdk-demo@example",
        namespace="team/alpha",
        title="pg upgrade window",
        kind="observation",
        created_at="2026-09-01T12:00:00+00:00",
        content="body",
    )


def test_rfc3339_now_is_storage_stable() -> None:
    """#3422 - the default stamp is already canonical (its own fixpoint)."""
    now = rfc3339_now()
    assert canonicalize_created_at(now) == now


# ---------------------------------------------------------------------------
# Client body assembly
# ---------------------------------------------------------------------------


def test_build_create_body_signs_the_namespace_it_sends(vector: dict[str, Any]) -> None:
    """The namespace on the wire must be the namespace inside the envelope."""
    key = AgentSigningKey.generate()
    body = build_create_body(
        title=vector["title"],
        content=vector["content"],
        signing_key=key,
        fields={"agent_id": vector["agent_id"], "namespace": None, "kind": None},
    )
    assert body.namespace == "global"
    assert body.kind == "observation"
    assert body.signature and body.created_at
    assert body.signature == sign_write(
        key,
        agent_id=vector["agent_id"],
        namespace=body.namespace,
        title=vector["title"],
        kind="observation",
        created_at=body.created_at,
        content=vector["content"],
    )


def test_build_create_body_requires_agent_id_when_signing(vector: dict[str, Any]) -> None:
    with pytest.raises(ValueError, match="agent_id"):
        build_create_body(
            title=vector["title"],
            content=vector["content"],
            signing_key=AgentSigningKey.generate(),
            fields={},
        )


def test_build_create_body_refuses_double_signature(vector: dict[str, Any]) -> None:
    with pytest.raises(ValueError, match="not both"):
        build_create_body(
            title=vector["title"],
            content=vector["content"],
            signing_key=AgentSigningKey.generate(),
            fields={"agent_id": "a", "signature": "AAAA"},
        )


def test_build_create_body_unsigned_omits_attestation(vector: dict[str, Any]) -> None:
    """Without a key the body is byte-identical to the pre-#2455 shape."""
    body = build_create_body(
        title=vector["title"], content=vector["content"], fields={"agent_id": "a"}
    )
    assert body.signature is None
    assert body.created_at is None
    assert body.kind is None
