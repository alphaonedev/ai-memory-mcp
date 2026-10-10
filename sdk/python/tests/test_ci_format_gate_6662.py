# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""clients-ci gates the sdk/python formatter, on a pinned ruff (#6662).

``ruff check .`` ran in the sdk-python job but ``ruff format --check .`` did
not, so 32 files drifted and formatting churn landed inside security diffs.
The gate is only stable if the formatter is: ruff changes its style between
minor releases, so the dev extra pins ruff to one minor and a new ruff is
a deliberate bump with its own reformat commit.
"""

from __future__ import annotations

import pathlib
import re

from .test_ci_install_6688 import _dev_extra, _requirement_name

_SDK = pathlib.Path(__file__).resolve().parents[1]
_WORKFLOW = _SDK.parents[1] / ".github" / "workflows" / "clients-ci.yml"


def _sdk_python_job() -> str:
    text = _WORKFLOW.read_text(encoding="utf-8")
    job = text.split("  sdk-python:", 1)
    assert len(job) == 2, "clients-ci.yml has no sdk-python job"
    return job[1].split("\n  sdk-", 1)[0]


def test_clients_ci_runs_ruff_format_check_6662() -> None:
    body = _sdk_python_job()
    assert re.search(r"run: python -m ruff format --check \.\s*$", body, re.MULTILINE), (
        "clients-ci sdk-python does not run `python -m ruff format --check .` (#6662)"
    )


def test_dev_extra_pins_ruff_to_one_minor_6662() -> None:
    specs = [spec for spec in _dev_extra() if _requirement_name(spec) == "ruff"]
    assert len(specs) == 1, f"dev extra ruff entries: {specs}"
    match = re.fullmatch(r"ruff>=(\d+)\.(\d+)(?:\.\d+)?,<(\d+)\.(\d+)", specs[0].replace(" ", ""))
    assert match is not None, f"ruff is not pinned to one minor: {specs[0]!r} (#6662)"
    low_major, low_minor, high_major, high_minor = map(int, match.groups())
    assert (high_major, high_minor) == (low_major, low_minor + 1), specs[0]
