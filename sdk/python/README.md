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
    client.bind_agent_pubkey("svc", key)  # #3464: proves possession

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
| `subscribe(req)` / `unsubscribe(id)` / `subscriptions()` | `POST` / `DELETE ?id=<id>` / `GET /api/v1/subscriptions` | Webhook mgmt. The delete takes the id in the QUERY STRING — the daemon registers `delete` on the collection path only. |
| `notify(req)` / `inbox(...)` | `/api/v1/notify`, `/api/v1/inbox` | Agent-to-agent messaging. |
| `agents()` / `register_agent(...)` | `/api/v1/agents` | NHI registry. |
| `bind_agent_pubkey(id, key)` | `PUT /api/v1/agents/{id}/pubkey` | Bootstrap/reassert an attestation key (admin). Takes the PRIVATE key and runs the #3464 challenge/response. Distinct rotation requires a current-key-signed lineage succession. |
| `bind_agent_pubkey_challenge(id, b64)` | `POST /api/v1/agents/{id}/pubkey/challenge` | Take the single-use bind nonce (admin). |

`update(...)` takes an optional `expected_version=` for optimistic
concurrency; it rides the `If-Match` header (the daemon's only version gate
for that route) and a stale value raises `ConflictError` (409).

### Removed at v1.0.0 — BREAKING

`grant()`, `revoke()` and `cluster()` are gone from both `AiMemoryClient` and
`AsyncAiMemoryClient`. They posted to `/api/v1/memories/{id}/grant`,
`/api/v1/memories/{id}/revoke` and `/api/v1/cluster`, none of which the daemon
registers — every call 404'd, in every release that shipped them. Replacements:

- **Per-memory access control** — set `metadata.scope` (`"private"` |
  `"collective"`) on the write, and attach a namespace governance standard for
  policy. See `docs/governance.md`.
- **Peer management** — federation peers are configured out of band
  (`--quorum-peers`, the peer-attestation allowlist,
  `AI_MEMORY_FED_INVENTORY_PATH`). The HTTP federation surface is
  `POST /api/v1/sync/push` and `GET /api/v1/sync/since`. See
  `docs/federation.md`.

`unsubscribe(id)` now issues `DELETE /api/v1/subscriptions?id=<id>` instead of
`DELETE /api/v1/subscriptions/{id}`. The old form matched no route, so webhook
teardown appeared to fail safe while leaving the decommissioned endpoint
receiving signed deliveries indefinitely. The method signature is unchanged;
check the returned `deleted` flag.

## Waking instead of polling (#3470)

`ai_memory.wake` is a minimal client for the same-host `ai-memory wake-hub`
wake plane. Instead of polling `GET /api/v1/inbox` on a timer, keep one
authenticated session on the hub's Unix domain socket and read the inbox when
there is something to read:

```python
from ai_memory import AiMemoryClient
from ai_memory.wake import DelegationBundle, WakeListener

bundle = DelegationBundle.load(
    "/home/alice/.config/ai-memory/keys/ai:alice.a2a-hub.json",
    hub_id="ai-memory-wake-hub",
)
client = AiMemoryClient(base_url="http://localhost:9077")

def catch_up(signal):
    # EXACTLY ONE inbox read per signal — never one per queued hint.
    for message in client.inbox(agent_id=bundle.agent_id, unread_only=True):
        handle(message)

WakeListener("/run/user/1000/ai-memory/wake-hub.sock", bundle, catch_up).run()
```

**The hint is not the message.** A wake carries
`{inbox_row_id, namespace, sender, digest, seq_high_watermark}` and never a
body — the v1 protocol has no kind that admits one. The durable ai-memory
inbox row is the record, and `digest` is the SHA-256 you can verify what you
read against without the hub ever having seen it.

**One identity root.** The client embeds no identity. It loads the scoped
`a2a-hub/join/v1` delegation bundle that
`ai-memory identity delegate --scope a2a-hub` wrote into the key directory —
a DELEGATED key, never the agent's enrolled one. Every check is a refusal
with no flag that skips it: mode 0600, caller-owned, not a symlink, a version
this build understands, scope `a2a-hub`, this hub's id, a private key that is
the one the certificate authorises, and a window that contains now. The
certificate's issuer signature is verified authoritatively by the HUB; this
SDK does not reproduce that pre-image, which is a degrade (it may present a
bundle the hub refuses) and never a widening.

**The backstop is always armed.** A bounded poll — at most 60 s
(`wake_sink::BACKSTOP_POLL_MAX`) — runs whether or not the hub is reachable,
so a hub that is down, refusing, or was never deployed costs LATENCY and
nothing else. A `poll_interval` above that bound is REFUSED rather than
clamped. Reconnects use jittered exponential backoff capped at the same bound.

Requires `cryptography` (`pip install "ai-memory-mcp[attestation]"`) to sign
the hello.

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
