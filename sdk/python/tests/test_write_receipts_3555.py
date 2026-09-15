# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""#3555: receipt evidence survives typed bulk decoding."""
import pytest
from pydantic import ValidationError
from ai_memory.models import BulkCreateResponse

@pytest.mark.parametrize("durability", ["local-only", "quorum 2-of-3", "replicated+backup"])
def test_receipt_classes_roundtrip_3555(durability):
    body = dict(sent=1, created=1, updated=0, deduped=0, rejected=0,
                errors=[], pending=[], durability_class=durability, fsync="per-commit")
    receipt = BulkCreateResponse.model_validate(body)
    assert receipt.durability_class == durability
    assert receipt.model_dump()["fsync"] == "per-commit"
    del body["durability_class"]
    with pytest.raises(ValidationError):
        BulkCreateResponse.model_validate(body)
