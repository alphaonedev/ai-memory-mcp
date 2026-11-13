# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""The CI install carries every optional package the TLS security tests need (#6688).

``clients-ci.yml`` installs the SDK with ``pip install -e ".[dev]"``. The
SOCKS legs of the #6349/#6537 session check need ``socksio`` (httpx's
``socks`` extra) and the #6267 truststore pins need ``truststore``; without
them those tests SKIP and CI stays green while they never run. These pins
fail when either package leaves the ``dev`` extra or the workflow stops
installing that extra. ``conftest.py`` adds the runtime half: under ``CI``
the session refuses to start when either module cannot be imported.
"""

from __future__ import annotations

import pathlib
import re

import pytest

_SDK = pathlib.Path(__file__).resolve().parents[1]
_WORKFLOW = _SDK.parents[1] / ".github" / "workflows" / "clients-ci.yml"

#: Modules the security tests import, and the distribution that provides each.
SECURITY_TEST_EXTRAS = {"socksio": "socksio", "truststore": "truststore"}


def _dev_extra() -> list[str]:
    text = (_SDK / "pyproject.toml").read_text(encoding="utf-8")
    try:
        import tomllib
    except ModuleNotFoundError:  # Python 3.10: no tomllib in the stdlib
        block = re.search(r"^dev = \[(.*?)^\]", text, re.MULTILINE | re.DOTALL)
        assert block is not None, "pyproject.toml has no dev extra"
        return re.findall(r'"([^"]+)"', block.group(1))
    extras = tomllib.loads(text)["project"]["optional-dependencies"]
    return list(extras["dev"])


def _requirement_name(spec: str) -> str:
    match = re.match(r"[A-Za-z0-9_.-]+", spec)
    assert match is not None, spec
    return match.group(0).lower().replace("_", "-")


@pytest.mark.parametrize("distribution", sorted(SECURITY_TEST_EXTRAS.values()))
def test_dev_extra_carries_the_security_test_packages_6688(distribution: str) -> None:
    names = {_requirement_name(spec) for spec in _dev_extra()}
    assert distribution in names, (
        f"sdk/python dev extra lacks {distribution!r}: the TLS security tests that "
        "need it would SKIP in clients-ci (#6688)"
    )


def test_clients_ci_installs_the_dev_extra_6688() -> None:
    text = _WORKFLOW.read_text(encoding="utf-8")
    job = text.split("  sdk-python:", 1)
    assert len(job) == 2, "clients-ci.yml has no sdk-python job"
    body = job[1].split("\n  sdk-", 1)[0]
    assert 'pip install -e ".[dev]"' in body, (
        "clients-ci sdk-python no longer installs the dev extra, so the TLS "
        "security tests' optional packages are not installed (#6688)"
    )
