# ai-memory — Python SDK

Typed Python client for the [ai-memory](https://github.com/alphaonedev/ai-memory-mcp)
HTTP API. Wraps the daemon's `/api/v1/` surface with sync and async clients,
Pydantic v2 models that mirror the Rust structs, Ed25519 write attestation,
and HMAC-SHA256 webhook verification.

**Status:** `1.0.0`

<!-- The version above is checked against ai_memory/_version.py by
     tests/test_version.py — update the literal there, never here. -->

## Install

```bash
pip install "ai-memory-mcp[attestation]"

# or from a local checkout:
pip install -e "./sdk/python[attestation]"
```

Requires Python 3.10+. The `attestation` extra pulls in `cryptography`, which
you need to **store** against a default-configured daemon — see below.

## Storing requires a signature

`POST /api/v1/memories` is the network write surface
(`WriteSurface::HttpDirect`) and **fails closed by default**: an unsigned
store is answered with `403 ATTESTATION_FAILED`. Sign the write with an
Ed25519 key whose public half is bound to the agent:

```python
from ai_memory import AiMemoryClient, Tier
from ai_memory.attestation import AgentSigningKey

key = AgentSigningKey.generate()          # or .from_file("svc.priv")

with AiMemoryClient(base_url="http://localhost:9077") as client:
    # One-time, admin-gated: enroll the public key for this agent.
    client.bind_agent_pubkey("svc", key.public_key_b64())

    created = client.store(
        title="BIND9 build notes",
        content="Use --with-openssl=/opt/openssl, disable DoH for the lab.",
        tier=Tier.LONG,
        tags=["dns", "bind9"],
        agent_id="svc",       # required when signing — it is inside the envelope
        signing_key=key,
    )
    print(created["id"])

    hits = client.recall(context="how do I build BIND9?")
    for memory in hits.memories:
        print(memory.title, memory.confidence)
```

Notes:

- `agent_id` is **required** when signing: the signature commits to it, so the
  SDK cannot sign a write whose identity the server would resolve from the
  `X-Agent-Id` header or an anonymous fallback.
- The signature also commits to `namespace`, `title`, `kind`, `created_at`,
  and `sha256(content)`. When `namespace` is omitted the client signs the
  COMPILED default (`"global"`); a daemon configured with
  `[storage].default_namespace` would store the row elsewhere and the
  signature would not verify, so pass `namespace=` explicitly there — the
  client cannot see a server-side override.
- Reads (`recall`, `search`, `list`, `get`) need no signature.
- Omitting `signing_key` works only where the operator has explicitly set
  `AI_MEMORY_REQUIRE_AGENT_ATTESTATION=0`, i.e. against a deliberately
  weakened daemon.

## Async

```python
import asyncio
from ai_memory import AsyncAiMemoryClient

async def main() -> None:
    async with AsyncAiMemoryClient(base_url="http://localhost:9077") as client:
        resp = await client.recall(context="hello")
        for memory in resp.memories:
            print(memory.title)

asyncio.run(main())
```

## Authentication

### API key

```python
AiMemoryClient(base_url="https://memory.example.com", api_key="sk-...")
```

The key is sent as the `X-API-Key` header on every request. The server
exempts `/api/v1/health` from auth.

### mTLS

```python
AiMemoryClient(
    base_url="https://memory.example.com",
    verify="/etc/ssl/certs/server-ca.pem",
    cert=("/etc/ssl/client/client.pem", "/etc/ssl/client/client.key"),
)
```

### Agent identity (NHI)

Set `agent_id` to stamp the `X-Agent-Id` header on every request. The
server writes `metadata.agent_id` accordingly (see CLAUDE.md §Agent
Identity).

```python
AiMemoryClient(base_url="http://localhost:9077", agent_id="ai:claude-opus-4.7@host")
```

## All methods

| Method | Endpoint | Notes |
|---|---|---|
| `health()` | `GET /api/v1/health` | Exempt from auth. |
| `metrics()` | `GET /api/v1/metrics` | Prometheus text format. |
| `store(...)` | `POST /api/v1/memories` | Upsert on `(title, namespace)`. |
| `bulk_store([...])` | `POST /api/v1/memories/bulk` | Up to 1000 per call. |
| `get(id)` | `GET /api/v1/memories/{id}` | Returns `Memory`. |
| `update(id, UpdateMemory)` | `PUT /api/v1/memories/{id}` | Partial update. |
| `delete(id)` | `DELETE /api/v1/memories/{id}` | |
| `promote(id)` | `POST /api/v1/memories/{id}/promote` | Tier -> `long`. |
| `list(...)` | `GET /api/v1/memories` | Filters: namespace, tier, tags, agent_id. |
| `search(q, ...)` | `GET /api/v1/search` | FTS AND search. |
| `recall(context, ...)` | `POST /api/v1/recall` | Hybrid semantic + FTS. |
| `forget(...)` | `POST /api/v1/forget` | Bulk delete by pattern. |
| `link(a, b, relation)` | `POST /api/v1/links` | `related_to`, `supersedes`, `contradicts`, `derived_from`. |
| `get_links(id)` | `GET /api/v1/links/{id}` | |
| `stats()` | `GET /api/v1/stats` | |
| `namespaces()` | `GET /api/v1/namespaces` | |
| `gc()` | `POST /api/v1/gc` | |
| `export()` / `import_()` | `GET` / `POST /api/v1/export|import` | |
| `subscribe(req)` / `unsubscribe(id)` / `subscriptions()` | `/api/v1/subscriptions` | Webhook mgmt. |
| `notify(req)` / `inbox(...)` | `/api/v1/notify`, `/api/v1/inbox` | Agent-to-agent messaging. |
| `grant(id, agent)` / `revoke(id, agent)` | `/api/v1/memories/{id}/grant|revoke` | Per-memory ACL. |
| `cluster(req)` | `POST /api/v1/cluster` | Peer management. |
| `agents()` / `register_agent(...)` | `/api/v1/agents` | NHI registry. |
| `bind_agent_pubkey(id, b64)` | `PUT /api/v1/agents/{id}/pubkey` | Enroll an attestation key (admin). |

`update(...)` takes an optional `expected_version=` for optimistic
concurrency; it rides the `If-Match` header (the daemon's only version gate
for that route) and a stale value raises `ConflictError` (409).

## Webhook verification

```python
from ai_memory import verify_webhook_signature

def handle(request) -> None:
    sig = request.headers["X-AI-Memory-Signature"]
    ts = request.headers["X-AI-Memory-Timestamp"]
    if not verify_webhook_signature(request.body, sig, "...", timestamp=ts):
        raise PermissionError("bad signature")
    ...
```

The daemon signs `HMAC-SHA256(SHA256(secret), "{timestamp}.{body}")` and sends
the timestamp in its own header, so `timestamp` is **required** — omitting it
raises `TypeError` rather than silently verifying the wrong construction.
Deliveries older than 300s (or more than 60s in the future) are rejected as
replays even when the MAC is valid; tune with `max_age_secs` / `max_skew_secs`.

`body` must be the raw bytes as received — do not re-encode a parsed JSON
payload; whitespace differences will break the HMAC.

## Errors

All SDK errors derive from `AiMemoryError`:

| Exception | HTTP |
|---|---|
| `ValidationError` | 400 |
| `AuthError` | 401 |
| `ForbiddenError` | 403 |
| `NotFoundError` | 404 |
| `ConflictError` | 409 |
| `RateLimitError` | 429 |
| `ServerError` | 5xx |
| `TransportError` | network failure |

## License

Apache-2.0, see [LICENSE](../../LICENSE).
