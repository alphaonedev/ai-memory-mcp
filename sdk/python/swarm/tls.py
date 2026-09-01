# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""Shared environment-to-SDK transport options for swarm/loadgen harnesses."""

from __future__ import annotations

from collections.abc import Mapping


def client_kwargs(environ: Mapping[str, str]) -> dict[str, object]:
    """Return fail-closed SDK kwargs from the ``SWARM_*`` auth variables."""
    cert = environ.get("SWARM_CLIENT_CERT")
    key = environ.get("SWARM_CLIENT_KEY")
    ca = environ.get("SWARM_CA_CERT")
    present = [bool(cert), bool(key), bool(ca)]
    if any(present) and not all(present):
        raise ValueError(
            "SWARM_CLIENT_CERT, SWARM_CLIENT_KEY, and SWARM_CA_CERT must be set together"
        )
    kwargs: dict[str, object] = {}
    if all(present):
        kwargs.update(cert=(cert, key), verify=ca)
    api_key = environ.get("SWARM_API_KEY")
    if api_key:
        kwargs["api_key"] = api_key
    return kwargs


__all__ = ["client_kwargs"]
