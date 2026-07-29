# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""Webhook HMAC conformance against a RUST-GENERATED vector (#2455).

R-203: the first test here FAILS against the pre-#2455 implementation and
PASSES after. Recorded before-evidence, current verifier, genuine delivery::

    verify_webhook_signature(genuine Rust-signed delivery) -> False

That is the whole defect: the SDK keyed the HMAC on the PLAINTEXT secret over
the BARE body, while the daemon keys on ``SHA256(secret)`` over
``"{timestamp}.{body}"`` — so ``verify_webhook_signature`` could never return
``True`` for a real webhook.

The test that should have caught it was tautological: it built its "expected"
signature with the same wrong construction the implementation used, then
asserted the implementation agreed with itself. Every assertion below is
anchored to ``sdk/fixtures/webhook_hmac_vector.json``, whose values were
PRINTED BY THE RUST SIGNER (provenance is documented in the fixture). Nothing
in this file recomputes the expected signature from SDK code, so the suite can
never again agree with a wrong implementation.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from ai_memory.webhooks import (
    DEFAULT_MAX_AGE_SECS,
    DEFAULT_MAX_SKEW_SECS,
    sign_webhook_body,
    verify_webhook_signature,
)

_FIXTURE = Path(__file__).resolve().parents[2] / "fixtures" / "webhook_hmac_vector.json"


@pytest.fixture(scope="module")
def vector() -> dict[str, Any]:
    return json.loads(_FIXTURE.read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def body(vector: dict[str, Any]) -> bytes:
    return vector["body"].encode("utf-8")


def _fresh(vector: dict[str, Any]) -> int:
    """A 'now' 10s after the vector's timestamp — inside the replay window."""
    return int(vector["timestamp"]) + 10


# ---------------------------------------------------------------------------
# The R-203 regression test
# ---------------------------------------------------------------------------


def test_verifies_genuine_rust_signed_delivery(vector: dict[str, Any], body: bytes) -> None:
    """A signature produced by the DAEMON must verify. Failed before #2455."""
    assert verify_webhook_signature(
        body,
        vector["signature_header"],
        vector["secret"],
        timestamp=vector["timestamp"],
        now=_fresh(vector),
    )


def test_key_is_sha256_of_secret_not_the_secret(vector: dict[str, Any], body: bytes) -> None:
    """Pin defect #1: the HMAC key is SHA256(secret), not the secret itself.

    Passing the hex digest as if it were the secret must FAIL — that would
    double-hash. This asserts the SDK hashes exactly once, at the right layer.
    """
    assert not verify_webhook_signature(
        body,
        vector["signature_header"],
        vector["secret_sha256_hex"],
        timestamp=vector["timestamp"],
        now=_fresh(vector),
    )


def test_message_is_timestamp_dot_body_not_bare_body(
    vector: dict[str, Any], body: bytes
) -> None:
    """Pin defect #2: the timestamp is part of the signed message.

    Verifying the SAME body + secret under a DIFFERENT timestamp must fail
    even though both are otherwise identical — proving the timestamp really
    is inside the MAC rather than merely carried alongside it.
    """
    other_ts = str(int(vector["timestamp"]) + 1)
    assert not verify_webhook_signature(
        body,
        vector["signature_header"],
        vector["secret"],
        timestamp=other_ts,
        now=int(other_ts) + 10,
    )


def test_signer_reproduces_the_rust_signature(vector: dict[str, Any], body: bytes) -> None:
    """``sign_webhook_body`` must emit the byte-exact Rust header value."""
    assert (
        sign_webhook_body(body, vector["secret"], vector["timestamp"])
        == vector["signature_header"]
    )


# ---------------------------------------------------------------------------
# Rejection paths
# ---------------------------------------------------------------------------


def test_rejects_wrong_secret(vector: dict[str, Any], body: bytes) -> None:
    assert not verify_webhook_signature(
        body,
        vector["signature_header"],
        "not-the-secret",
        timestamp=vector["timestamp"],
        now=_fresh(vector),
    )


def test_rejects_tampered_body(vector: dict[str, Any], body: bytes) -> None:
    assert not verify_webhook_signature(
        body + b"tampered",
        vector["signature_header"],
        vector["secret"],
        timestamp=vector["timestamp"],
        now=_fresh(vector),
    )


def test_accepts_bare_hex_without_prefix(vector: dict[str, Any], body: bytes) -> None:
    bare = vector["signature_header"].removeprefix("sha256=")
    assert verify_webhook_signature(
        body, bare, vector["secret"], timestamp=vector["timestamp"], now=_fresh(vector)
    )


def test_rejects_malformed_signature(vector: dict[str, Any], body: bytes) -> None:
    for bad in ("", "sha256=notHex", "sha256=abc"):  # empty / non-hex / odd length
        assert not verify_webhook_signature(
            body, bad, vector["secret"], timestamp=vector["timestamp"], now=_fresh(vector)
        )


# ---------------------------------------------------------------------------
# Replay window
# ---------------------------------------------------------------------------


def test_rejects_stale_delivery(vector: dict[str, Any], body: bytes) -> None:
    """An authentic-but-old signature is a replay and must be refused."""
    stale_now = int(vector["timestamp"]) + DEFAULT_MAX_AGE_SECS + 1
    assert not verify_webhook_signature(
        body,
        vector["signature_header"],
        vector["secret"],
        timestamp=vector["timestamp"],
        now=stale_now,
    )


def test_accepts_at_the_age_boundary(vector: dict[str, Any], body: bytes) -> None:
    at_edge = int(vector["timestamp"]) + DEFAULT_MAX_AGE_SECS
    assert verify_webhook_signature(
        body,
        vector["signature_header"],
        vector["secret"],
        timestamp=vector["timestamp"],
        now=at_edge,
    )


def test_rejects_postdated_delivery(vector: dict[str, Any], body: bytes) -> None:
    """A timestamp beyond the skew tolerance is refused."""
    early_now = int(vector["timestamp"]) - DEFAULT_MAX_SKEW_SECS - 1
    assert not verify_webhook_signature(
        body,
        vector["signature_header"],
        vector["secret"],
        timestamp=vector["timestamp"],
        now=early_now,
    )


def test_rejects_unparseable_timestamp(vector: dict[str, Any], body: bytes) -> None:
    for bad in ("", "   ", "not-a-number", "2026-07-28T00:00:00Z"):
        assert not verify_webhook_signature(
            body, vector["signature_header"], vector["secret"], timestamp=bad
        )


def test_timestamp_is_required_and_fails_loudly(
    vector: dict[str, Any], body: bytes
) -> None:
    """A pre-#2455 3-argument call must raise, never silently mis-verify.

    Failing closed with a ``TypeError`` is deliberate: a caller that has not
    been updated for the wire contract gets a crash (-> 5xx -> the daemon
    retries) instead of a ``False`` that looks like a forged delivery, or —
    far worse — a ``True`` from the wrong construction.
    """
    with pytest.raises(TypeError):
        verify_webhook_signature(  # type: ignore[call-arg]
            body, vector["signature_header"], vector["secret"]
        )
