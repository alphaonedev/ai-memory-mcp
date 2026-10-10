"""#7057: no checkout step of the workflows this branch touches persists the job token.

Run from sdk/python: python -m pytest -q <this file>
"""

import pathlib
import re

import pytest

WORKFLOWS = pathlib.Path(__file__).resolve().parents[3] / ".github" / "workflows"


@pytest.mark.parametrize("name", ["clients-ci.yml", "c8-precheck.yml"])
def test_7057_every_checkout_step_sets_persist_credentials_false(name):
    text = (WORKFLOWS / name).read_text(encoding="utf-8")
    steps = list(re.finditer(r"^( *)- uses: actions/checkout@[^\n]*\n((?:\1 {2,}[^\n]*\n)*)", text, re.M))
    uses = len(re.findall(r"^ *- uses: actions/checkout@", text, re.M))
    assert len(steps) == uses >= 6
    for step in steps:
        assert re.search(r"^\s+persist-credentials: false$", step.group(2), re.M), step.group(0)


def test_7057_the_two_checkouts_added_by_the_branch_are_covered():
    text = (WORKFLOWS / "c8-precheck.yml").read_text(encoding="utf-8")
    for job in ("inline-mod-tests-cfg-gate", "packaging-contract-gate"):
        body = text.split(f"\n  {job}:", 1)[1].split("\n  # ", 1)[0]
        assert "persist-credentials: false" in body, job
