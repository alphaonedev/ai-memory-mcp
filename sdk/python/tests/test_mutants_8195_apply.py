"""Every mutant snippet in ``_mutants_8195`` still applies exactly once (#8195 r2).

A snippet that stops matching turns its row into a silent no-op, so a refactor of the
TLS code must update the table. ``run_mutants_8195.py`` runs the rows against the suite.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from ._mutants_8195 import MUTANTS, Mutant

SDK_ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize("mutant", MUTANTS, ids=lambda m: f"{m.label}-{m.name}")
def test_snippet_applies_exactly_once_8195(mutant: Mutant) -> None:
    text = (SDK_ROOT / mutant.path).read_text(encoding="utf-8")
    assert text.count(mutant.old) == 1, f"{mutant.label} {mutant.name}: snippet count {text.count(mutant.old)}"
    assert mutant.old != mutant.new, f"{mutant.label} {mutant.name}: noop row"


def test_rows_are_unique_8195() -> None:
    keys = [(m.path, m.old, m.new) for m in MUTANTS]
    assert len(keys) == len(set(keys))
