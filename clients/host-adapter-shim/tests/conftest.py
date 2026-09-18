# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""Hermetic harness for the three reference host-adapter shims.

No real `ai-memory` binary, no network, no daemon: each adapter is invoked with
`--ai-memory-bin` pointing at a throwaway POSIX-shell "fake substrate" that
drains stdin and prints canned JSON-RPC response lines. That is enough, because
the thing under test is exactly how each adapter CLASSIFIES the receipt.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
SHIM_ROOT = HERE.parent

#: The three reference adapters, and how to run each one.
ADAPTERS: dict[str, list[str]] = {
    "python": [sys.executable, str(SHIM_ROOT / "python" / "capture_turn.py")],
    "node": ["node", str(SHIM_ROOT / "node" / "capture-turn.mjs")],
    "bash": ["bash", str(SHIM_ROOT / "bash" / "capture-turn.sh")],
}

#: Adapters whose interpreter is missing on this host are SKIPPED, never
#: silently dropped — a missing runtime must be visible in the report.
_INTERPRETERS = {"python": sys.executable, "node": "node", "bash": "bash"}


def adapter_available(name: str) -> bool:
    exe = _INTERPRETERS[name]
    return Path(exe).exists() or shutil.which(exe) is not None


def make_fake_substrate(tmp_path: Path, response_lines: list[str]) -> Path:
    """A fake `ai-memory` that drains stdin then prints `response_lines`."""
    body = tmp_path / "fake-substrate-response.txt"
    body.write_text("\n".join(response_lines) + "\n", encoding="utf-8")
    script = tmp_path / "fake-ai-memory"
    script.write_text(
        "#!/bin/sh\n"
        "# Drain stdin so the shim's write never SIGPIPEs, then emit the canned\n"
        "# frames the real substrate would have written.\n"
        "cat >/dev/null\n"
        f'cat "{body}"\n',
        encoding="utf-8",
    )
    script.chmod(0o755)
    return script


def run_adapter(
    name: str,
    tmp_path: Path,
    response_lines: list[str],
    *,
    env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    """Run one adapter against a fake substrate and return the completed process."""
    content = tmp_path / "content.txt"
    content.write_text("hello from the host", encoding="utf-8")
    fake = make_fake_substrate(tmp_path, response_lines)
    argv = [
        *ADAPTERS[name],
        "--host-session-id",
        "sess-1",
        "--host-turn-index",
        "0",
        "--role",
        "user",
        "--content-file",
        str(content),
        "--ai-memory-bin",
        str(fake),
    ]
    run_env = dict(os.environ) if env is None else env
    return subprocess.run(
        argv,
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
        env=run_env,
    )


def run_adapter_argv(name: str, args: list[str]) -> subprocess.CompletedProcess[str]:
    """Run one adapter with raw argv — for the usage / content-file arms."""
    return subprocess.run(
        [*ADAPTERS[name], *args],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
        stdin=subprocess.DEVNULL,
    )


@pytest.fixture(params=sorted(ADAPTERS))
def adapter(request: pytest.FixtureRequest) -> str:
    name: str = request.param
    if not adapter_available(name):
        pytest.skip(f"{name} interpreter not on this host")
    return name
