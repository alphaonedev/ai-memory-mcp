# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""Environment-driven configuration for the GLM-5.3-Flash acceptance swarm.

The swarm is TEST-ONLY infrastructure (never shipped in the ``ai-memory-mcp``
wheel). It stands up N lightweight GLM-5.3-Flash agents that drive a compiled
ai-memory daemon over its HTTP tool surface to prove the feature/tool surface
is reachable and behaves (attestation, isolation, replay-guard).

All knobs come from the environment so an operator can point the same driver
at Config-1 (single daemon) through Config-5 (federated mesh) without code
changes. Nothing here talks to a network — construction is pure so the config
can be unit-tested without a daemon or an API key.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

#: The acceptance model is PINNED. GLM-5.3-Flash is the cheap acceptance-TEST
#: workload only (it never writes product code). Pinning it here — rather than
#: reading it from the environment — is a guardrail: a stray ``MODEL`` env var
#: cannot silently swap the attested acceptance run onto a different model.
MODEL_ID = "glm-5.3-flash"

#: OpenRouter model slug for :data:`MODEL_ID`.
OPENROUTER_MODEL_SLUG = "z-ai/glm-5.3-flash"

DEFAULT_OPENROUTER_BASE_URL = "https://openrouter.ai/api/v1"
DEFAULT_DAEMON_BASE_URL = "http://localhost:9077"


class ConfigError(RuntimeError):
    """Raised when a required environment knob is missing or malformed.

    The swarm FAILS CLOSED on misconfiguration: it refuses to launch rather
    than silently degrade to a partial or wrongly-targeted run.
    """


def _split_urls(raw: str) -> list[str]:
    return [u.strip().rstrip("/") for u in raw.split(",") if u.strip()]


@dataclass(frozen=True)
class SwarmConfig:
    """Immutable, fully-resolved swarm configuration.

    Attributes:
        base_urls: One or more daemon base URLs. A single entry is Config-1
            (one daemon); several entries are a swarm/mesh (Config-2..5). An
            agent is round-robin-assigned to one URL at spawn.
        n_agents: Number of GLM-driven agents to spawn.
        max_steps: Hard ceiling on perceive->decide->act->record loop steps
            per agent (bounded work — no unbounded agent loops).
        stagger_secs: Delay between successive agent launches. Staggered, not
            synchronized-blast: never a thundering-herd against the daemon.
        backoff_base_secs / backoff_max_secs: Bounded exponential backoff for
            transient tool failures before the agent fails closed.
        key_dir: Directory holding (or receiving) per-agent Ed25519 seeds.
        openrouter_api_key: OpenRouter credential. ``None`` in offline/mock
            runs; required for a live run (checked by :meth:`require_live`).
        request_timeout_secs: Per-HTTP-request timeout for daemon + OpenRouter.
        namespace_prefix: Every agent gets its own namespace
            ``{prefix}-{agent_ordinal}`` for cross-agent isolation tests.
    """

    base_urls: list[str]
    n_agents: int = 4
    max_steps: int = 6
    stagger_secs: float = 0.75
    backoff_base_secs: float = 0.5
    backoff_max_secs: float = 8.0
    key_dir: Path = field(default_factory=lambda: Path.home() / ".ai-memory-swarm-keys")
    openrouter_api_key: str | None = None
    openrouter_base_url: str = DEFAULT_OPENROUTER_BASE_URL
    request_timeout_secs: float = 30.0
    namespace_prefix: str = "swarm"
    model_slug: str = OPENROUTER_MODEL_SLUG
    client_cert: str | None = None
    client_key: str | None = None
    ca_cert: str | None = None
    api_key: str | None = None
    admin_agent_id: str = "ai:hive-loadgen-f2"

    def __post_init__(self) -> None:
        if not self.base_urls:
            raise ConfigError("at least one daemon base URL is required")
        if self.n_agents < 1:
            raise ConfigError(f"n_agents must be >= 1, got {self.n_agents}")
        if self.max_steps < 1:
            raise ConfigError(f"max_steps must be >= 1, got {self.max_steps}")
        tls_values = (self.client_cert, self.client_key, self.ca_cert)
        if any(tls_values) and not all(tls_values):
            raise ConfigError(
                "SWARM_CLIENT_CERT, SWARM_CLIENT_KEY, and SWARM_CA_CERT must be set together"
            )

    @classmethod
    def from_env(cls, environ: dict[str, str] | None = None) -> SwarmConfig:
        """Build a config from environment variables.

        Recognised variables:

        ==========================  ===================================
        ``SWARM_BASE_URLS``         comma-separated daemon URLs (or
                                    ``SWARM_BASE_URL`` for a single one)
        ``SWARM_N``                 agent count
        ``SWARM_MAX_STEPS``         per-agent loop ceiling
        ``SWARM_STAGGER_SECS``      inter-launch delay
        ``SWARM_KEY_DIR``           per-agent key directory
        ``SWARM_NAMESPACE_PREFIX``  isolation-namespace prefix
        ``OPENROUTER_API_KEY``      OpenRouter credential (live runs)
        ``OPENROUTER_BASE_URL``     OpenRouter endpoint override
        ``SWARM_CLIENT_CERT``       loadgen mTLS certificate path
        ``SWARM_CLIENT_KEY``        loadgen mTLS private-key path
        ``SWARM_CA_CERT``            hive CA certificate path
        ``SWARM_API_KEY``            per-node HTTP request credential
        ==========================  ===================================
        """
        env = os.environ if environ is None else environ
        raw_urls = env.get("SWARM_BASE_URLS") or env.get("SWARM_BASE_URL", "")
        base_urls = _split_urls(raw_urls) or [DEFAULT_DAEMON_BASE_URL]
        key_dir = (
            Path(env["SWARM_KEY_DIR"])
            if env.get("SWARM_KEY_DIR")
            else Path.home() / ".ai-memory-swarm-keys"
        )
        return cls(
            base_urls=base_urls,
            n_agents=_int_env(env, "SWARM_N", 4),
            max_steps=_int_env(env, "SWARM_MAX_STEPS", 6),
            stagger_secs=_float_env(env, "SWARM_STAGGER_SECS", 0.75),
            backoff_base_secs=_float_env(env, "SWARM_BACKOFF_BASE_SECS", 0.5),
            backoff_max_secs=_float_env(env, "SWARM_BACKOFF_MAX_SECS", 8.0),
            key_dir=key_dir,
            openrouter_api_key=env.get("OPENROUTER_API_KEY") or None,
            openrouter_base_url=env.get(
                "OPENROUTER_BASE_URL", DEFAULT_OPENROUTER_BASE_URL
            ).rstrip("/"),
            request_timeout_secs=_float_env(env, "SWARM_REQUEST_TIMEOUT_SECS", 30.0),
            namespace_prefix=env.get("SWARM_NAMESPACE_PREFIX", "swarm"),
            client_cert=env.get("SWARM_CLIENT_CERT") or None,
            client_key=env.get("SWARM_CLIENT_KEY") or None,
            ca_cert=env.get("SWARM_CA_CERT") or None,
            api_key=env.get("SWARM_API_KEY") or None,
            admin_agent_id=env.get("SWARM_ADMIN_AGENT_ID", "ai:hive-loadgen-f2"),
        )

    def daemon_client_kwargs(self) -> dict[str, object]:
        """SDK auth/TLS kwargs shared by every daemon client."""
        kwargs: dict[str, object] = {}
        if self.client_cert and self.client_key and self.ca_cert:
            kwargs.update(cert=(self.client_cert, self.client_key), verify=self.ca_cert)
        if self.api_key:
            kwargs["api_key"] = self.api_key
        return kwargs

    def require_live(self) -> None:
        """Assert the config can drive a LIVE run; raise otherwise.

        A live run needs an OpenRouter key (the decide step calls the model).
        Fail closed here so a misconfigured launch stops before spawning
        agents that would all error on their first decide call.
        """
        if not self.openrouter_api_key:
            raise ConfigError(
                "OPENROUTER_API_KEY is required for a live swarm run; "
                "unset only for offline/mock dry-runs"
            )

    def namespace_for(self, ordinal: int) -> str:
        """The isolation namespace assigned to agent ``ordinal``."""
        return f"{self.namespace_prefix}-{ordinal:03d}"

    def base_url_for(self, ordinal: int) -> str:
        """Round-robin the agent onto one of the configured daemon URLs."""
        return self.base_urls[ordinal % len(self.base_urls)]


def _int_env(env: dict[str, str], name: str, default: int) -> int:
    raw = env.get(name)
    if raw is None or raw == "":
        return default
    try:
        return int(raw)
    except ValueError as exc:
        raise ConfigError(f"{name} must be an integer, got {raw!r}") from exc


def _float_env(env: dict[str, str], name: str, default: float) -> float:
    raw = env.get(name)
    if raw is None or raw == "":
        return default
    try:
        return float(raw)
    except ValueError as exc:
        raise ConfigError(f"{name} must be a number, got {raw!r}") from exc
