# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""Shared binary codec pins; no live-hub or JSON-input claim (#3578)."""

import dataclasses
import json
from pathlib import Path

import pytest

from ai_memory.wake import Frame, Kind, WakeError, WakeMeta

VECTORS = json.loads(
    (Path(__file__).resolve().parents[2] / "fixtures" / "wake_meta_3578.json").read_text()
)


def test_allowed_vectors_have_exactly_five_fields_3578() -> None:
    assert len(VECTORS["allowed"]) == 4
    for case in VECTORS["allowed"]:
        meta = WakeMeta.decode(bytes.fromhex(case["hex"]))
        actual = dataclasses.asdict(meta)
        actual["digest"] = meta.digest_hex
        assert actual == case["expected"], case["name"]


def test_exact_256_byte_boundary_and_257_byte_refusal_3578() -> None:
    raw = bytes.fromhex(VECTORS["allowed"][2]["hex"])
    assert len(raw) == 256
    assert WakeMeta.decode(raw).sender == "s" * 84
    with pytest.raises(WakeError, match="ceiling"):
        WakeMeta.decode(raw + b"\0")


def test_appended_content_title_and_other_denied_vectors_3578() -> None:
    assert len(VECTORS["denied"]) == 5
    for case in VECTORS["denied"]:
        with pytest.raises(WakeError):
            WakeMeta.decode(bytes.fromhex(case["hex"]))


def test_every_truncation_is_refused_3578() -> None:
    for case in VECTORS["allowed"]:
        raw = bytes.fromhex(case["hex"])
        for end in range(len(raw)):
            with pytest.raises(WakeError):
                WakeMeta.decode(raw[:end])


def test_reserved_body_kinds_with_allowed_control_3578() -> None:
    frame = Frame(Kind.WAKE, "producer", "ai:alice", bytes.fromhex(VECTORS["allowed"][1]["hex"]))
    raw = frame.encode()
    assert Frame.decode(raw) == frame
    assert VECTORS["reserved_kinds"] == [11, 12, 13]
    for kind in VECTORS["reserved_kinds"]:
        denied = bytearray(raw)
        denied[5] = kind
        with pytest.raises(WakeError, match="permanently reserved"):
            Frame.decode(bytes(denied))
