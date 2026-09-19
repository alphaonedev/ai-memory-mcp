# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""#3544 — the two published shims share ONE success predicate.

`_capture_outcome.py` is vendored into both wheels rather than imported from a
third package (each shim declares `dependencies = []` and is published
independently to PyPI, so a shared package would add a runtime dependency to
both). This pin is what makes "vendored" mean "the same predicate": if either
copy is edited, BOTH packages' suites go red, so the two wheels cannot drift
into disagreeing about what "captured" means.

Skipped — not silently passed — when the sibling package is not on disk (an
installed wheel outside the repo). Both CI legs (`clients-ci.yml` and the
`publish-sdk-shims.yml` test gate) run from a full checkout, where it runs.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from ai_memory_openai_shim import _capture_outcome

_MINE = Path(_capture_outcome.__file__).resolve()
_SIBLING = (
    _MINE.parents[2] / "anthropic-shim-py" / "ai_memory_anthropic_shim" / "_capture_outcome.py"
)


def test_shared_predicate_is_byte_identical_across_both_shims() -> None:
    if not _SIBLING.is_file():
        pytest.skip(f"sibling shim package not on disk: {_SIBLING}")
    assert _MINE.read_bytes() == _SIBLING.read_bytes(), (
        f"{_MINE} and {_SIBLING} have drifted. They are ONE predicate: edit "
        "one and copy it to the other, or the two published wheels will "
        "disagree about whether a turn was captured (#3544)."
    )


def test_closed_status_vocabulary_is_exactly_the_substrate_literals() -> None:
    # `grep -n '\"status\"' src/mcp/tools/capture_turn.rs` -> :439 "ask",
    # :490 "pending". Nothing else. A third literal appearing upstream must
    # arrive here deliberately, not by a shim guessing.
    assert _capture_outcome.STATUS_ASK == "ask"
    assert _capture_outcome.STATUS_PENDING == "pending"
    assert _capture_outcome.KNOWN_STATUSES == frozenset({"ask", "pending"})


def test_captured_is_true_only_for_the_persisted_kind() -> None:
    # The predicate is a single property on a single kind: no second path to
    # success can be added without this cell noticing.
    kinds = [
        _capture_outcome.CAPTURED,
        _capture_outcome.ASK,
        _capture_outcome.PENDING,
        _capture_outcome.NOT_CAPTURED,
    ]
    captured = [k for k in kinds if _capture_outcome.CaptureOutcome(k).captured]
    assert captured == [_capture_outcome.CAPTURED]


def test_classifier_never_raises_on_hostile_input() -> None:
    # Non-wedging invariant: total for ANY input.
    for bad in (None, 0, "", [], {}, {"result": 7}, {"result": {"content": []}}):
        assert _capture_outcome.classify_capture_response(bad).captured is False
