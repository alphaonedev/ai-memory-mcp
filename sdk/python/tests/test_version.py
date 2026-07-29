# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""Version-SSOT guard (#2455).

Before #2455 the SDK asserted its version in four places that had drifted to
three different answers:

* ``pyproject.toml:10``          -> ``1.0.0``
* ``ai_memory/__init__.py:60``   -> ``0.8.0``
* ``_common.py:52`` (User-Agent) -> ``0.6.0-alpha.0``
* ``README.md:8``                -> ``0.6.0-alpha.0 - scaffolding, unpublished``

A published wheel therefore told PyPI one version, ``ai_memory.__version__``
another, and every daemon's access log a third — making server-side triage of
a client bug actively misleading. All four now derive from
``ai_memory/_version.py``; these tests fail if any of them drifts again.
"""

from __future__ import annotations

import re
from pathlib import Path

import ai_memory
from ai_memory._common import SDK_VERSION, build_httpx_kwargs
from ai_memory._version import __version__ as VERSION_LITERAL

_SDK_ROOT = Path(__file__).resolve().parents[1]


def test_dunder_version_matches_the_literal() -> None:
    assert ai_memory.__version__ == VERSION_LITERAL


def test_user_agent_matches_the_literal() -> None:
    kwargs = build_httpx_kwargs(
        base_url="http://localhost:9077",
        api_key=None,
        agent_id=None,
        timeout=1.0,
        verify=None,
        cert=None,
        extra_headers=None,
    )
    assert kwargs["headers"]["User-Agent"] == f"ai-memory-python/{VERSION_LITERAL}"
    assert SDK_VERSION == VERSION_LITERAL


def test_pyproject_derives_version_dynamically() -> None:
    """pyproject must NOT carry a second literal to drift from."""
    text = (_SDK_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert 'dynamic = ["version"]' in text
    assert 'attr = "ai_memory._version.__version__"' in text
    # A bare `version = "<literal>"` is the drift vector; the
    # `version = { attr = ... }` indirection under [tool.setuptools.dynamic]
    # is the fix, so match only the quoted-literal form.
    assert not re.search(r"^version\s*=\s*[\"']", text, flags=re.MULTILINE)


def test_readme_status_line_matches_the_literal() -> None:
    """The README's Status line is operator-facing and must not lie."""
    readme = (_SDK_ROOT / "README.md").read_text(encoding="utf-8")
    match = re.search(r"^\*\*Status:\*\*\s*`([^`]+)`", readme, flags=re.MULTILINE)
    assert match is not None, "README lost its **Status:** `<version>` line"
    assert match.group(1) == VERSION_LITERAL


def test_installed_metadata_matches_when_available() -> None:
    """When installed, the distribution metadata must agree too."""
    from importlib.metadata import PackageNotFoundError, version

    try:
        installed = version("ai-memory-mcp")
    except PackageNotFoundError:  # running from a bare source tree
        return
    assert installed == VERSION_LITERAL
