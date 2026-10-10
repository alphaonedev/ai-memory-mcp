# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""The wake-boundary review pins hold for the SDK sources (#6864).

``tests/qual_wake_content_boundary_3578.rs`` pins the SHA-256 of every
reviewed wake decoder in ``tests/fixtures/wake_content_boundary_3578.json``.
That gate only runs under cargo, so an edit to ``sdk/python/ai_memory/wake.py``
without a re-review and re-pin went unnoticed by the Python job (#6864). This
test hashes each ``sdk-source-bytes`` entry the way the Rust gate does (the
plain SHA-256 of the file bytes) and compares it with the pin.
"""

from __future__ import annotations

import hashlib
import json
import pathlib

import pytest

_REPO = pathlib.Path(__file__).resolve().parents[3]
_FIXTURE = _REPO / "tests" / "fixtures" / "wake_content_boundary_3578.json"


def _source_pins() -> list[dict[str, str]]:
    entries = json.loads(_FIXTURE.read_text(encoding="utf-8"))
    return [entry for entry in entries if entry["mode"] == "sdk-source-bytes"]


def test_fixture_pins_every_sdk_wake_decoder_6864() -> None:
    paths = {entry["path"] for entry in _source_pins()}
    assert {
        "sdk/python/ai_memory/wake.py",
        "sdk/python/swarm/wake.py",
        "sdk/typescript/src/wake.ts",
    } <= paths


@pytest.mark.parametrize("entry", _source_pins(), ids=lambda entry: entry["path"])
def test_sdk_source_matches_its_reviewed_pin_6864(entry: dict[str, str]) -> None:
    digest = hashlib.sha256((_REPO / entry["path"]).read_bytes()).hexdigest()
    assert digest == entry["sha256"], (
        f"{entry['path']} changed since its wake-boundary review: re-review the diff, "
        f"then re-pin it in {_FIXTURE.relative_to(_REPO)} (#6864, #3578)."
    )
