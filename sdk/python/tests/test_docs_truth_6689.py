"""#6689: the trust-path docs describe the per-component walk, not realpath.

``verify=<path>`` and ``SSL_CERT_FILE`` / ``SSL_CERT_DIR`` are resolved by
``_checked_realpath``, which walks the path one component at a time, refuses
a missing component instead of normalising a later ``..`` away, and applies
the #6559 rule to what it walks. A doc that still says ``os.path.realpath``
promises a lexical normalisation the client does not do.
"""

from __future__ import annotations

import inspect
from pathlib import Path

import pytest

from ai_memory import _common
from ai_memory.async_client import AsyncAiMemoryClient
from ai_memory.client import AiMemoryClient

_README = Path(__file__).resolve().parents[1] / "README.md"

_STALE = (
    "resolved with ``os.path.realpath``",
    "resolved with `os.path.realpath`",
    "as ``os.path.realpath`` does",
    "as ``realpath`` does",
    "``os.path.realpath(path)``, refusing",
)


def _docs() -> dict[str, str]:
    return {
        "_checked_realpath": inspect.getdoc(_common._checked_realpath) or "",
        "_context_from_path": inspect.getdoc(_common._context_from_path) or "",
        "build_httpx_kwargs": inspect.getdoc(_common.build_httpx_kwargs) or "",
        "AiMemoryClient": AiMemoryClient.__doc__ or "",
        "AsyncAiMemoryClient": AsyncAiMemoryClient.__doc__ or "",
        "README.md": _README.read_text(encoding="utf-8"),
    }


@pytest.mark.parametrize("name", sorted(_docs()))
def test_trust_path_docs_do_not_promise_realpath_6689(name: str) -> None:
    text = " ".join(_docs()[name].split())
    stale = [phrase for phrase in _STALE if " ".join(phrase.split()) in text]
    assert not stale, f"{name} still documents realpath resolution: {stale}"


@pytest.mark.parametrize(
    "name", ["_checked_realpath", "build_httpx_kwargs", "AiMemoryClient", "README.md"]
)
def test_trust_path_docs_name_the_component_walk_6689(name: str) -> None:
    text = " ".join(_docs()[name].split())
    assert "component by component" in text, f"{name} does not describe the walk"
    assert "missing component" in text, f"{name} does not say a missing component is refused"
