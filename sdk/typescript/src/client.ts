// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

/**
 * `AiMemoryClient` — thin typed wrapper over the ai-memory HTTP API.
 *
 * The client uses `undici.fetch` under the hood. On Node 20+ `undici` is
 * already bundled as the platform fetch implementation, so this works in
 * both Node and the browser (with a WHATWG fetch polyfill).
 *
 * Auth:
 * - `apiKey` is sent as `X-API-Key` (see `handlers::api_key_auth`).
 * - `agentId` is sent as `X-Agent-Id`. Per-call `agentId` overrides the
 *   constructor default. `.store()` also accepts a body-level `agent_id`
 *   which the server prefers over the header (precedence documented in
 *   `docs/CLAUDE.md` Agent Identity §).
 *
 * mTLS: terminate TLS with client certificates at the reverse proxy (nginx,
 * Caddy, Envoy) in front of ai-memory. The daemon itself is HTTP-only; mTLS
 * is an edge concern. See README for a suggested nginx config.
 */

import { fetch as undiciFetch, Agent, type RequestInit } from "undici";

import { apiErrorFromResponse, NetworkError } from "./errors.js";
import { attestationFields, type AgentSigningKey } from "./attestation.js";
import type {
  AgentRegistration,
  ClientOptions,
  CreateMemoryRequest,
  CreateSubscriptionRequest,
  ForgetRequest,
  HealthResponse,
  InboxQuery,
  InboxResponse,
  LinkRequest,
  ListQuery,
  ListResponse,
  Memory,
  MemoryLink,
  MetricsResponse,
  NotifyRequest,
  RecallRequest,
  RecallResponse,
  RegisterAgentRequest,
  RequestOptions,
  SearchQuery,
  SearchResponse,
  Stats,
  Subscription,
  ListSubscriptionsResponse,
  UpdateMemoryRequest,
} from "./types.js";

type FetchImpl = typeof undiciFetch;

/** Minimal JSON type for generic bodies. */
type JsonValue =
  | string
  | number
  | boolean
  | null
  | JsonValue[]
  | { [k: string]: JsonValue };

/** Internal fetch-call options. */
interface CallOptions<TBody = unknown> {
  method: "GET" | "POST" | "PUT" | "DELETE";
  path: string;
  query?: Record<string, string | number | boolean | undefined>;
  body?: TBody;
  requestOpts?: RequestOptions;
  /** If true, return the raw text body (for Prometheus metrics). */
  asText?: boolean;
}

/**
 * The daemon's compiled default namespace for `POST /api/v1/memories`
 * (`src/models/memory.rs::default_namespace` -> `crate::DEFAULT_NAMESPACE`).
 *
 * Needed only when SIGNING: the namespace is inside the signed envelope, so
 * the client must commit to the exact value the server will store. Operators
 * who set `[storage].default_namespace` MUST pass `namespace` explicitly on
 * signed writes — the client cannot know a server-side override.
 */
export const DEFAULT_NAMESPACE = "global";

/** The daemon's default `memory_kind` when `kind` is absent. */
export const DEFAULT_MEMORY_KIND = "observation";

/** Options for {@link AiMemoryClient.store}. */
export interface StoreOptions extends RequestOptions {
  /**
   * Ed25519 key used to attest the write (#2455). Required against a stock
   * daemon, whose HTTP store surface fails closed. See `./attestation.js`.
   */
  signingKey?: AgentSigningKey;
}

/** Options for {@link AiMemoryClient.update}. */
export interface UpdateOptions extends RequestOptions {
  /**
   * Expected row version, sent as `If-Match`. A stale value yields `409`.
   */
  expectedVersion?: number | string;
}

export class AiMemoryClient {
  private readonly baseUrl: string;
  private readonly apiKey: string | undefined;
  private readonly agentId: string | undefined;
  private readonly defaultHeaders: Record<string, string>;
  private readonly timeoutMs: number;
  private readonly fetchImpl: FetchImpl;
  private readonly dispatcher: Agent | undefined;

  constructor(opts: ClientOptions, fetchImpl?: FetchImpl) {
    if (!opts.baseUrl) {
      throw new Error("AiMemoryClient: baseUrl is required");
    }
    this.baseUrl = opts.baseUrl.replace(/\/+$/, "");
    this.apiKey = opts.apiKey;
    this.agentId = opts.agentId;
    this.defaultHeaders = opts.headers ?? {};
    this.timeoutMs = opts.timeoutMs ?? 30_000;
    this.fetchImpl = fetchImpl ?? (undiciFetch as FetchImpl);
    // A shared Agent gives keep-alive across calls.
    this.dispatcher =
      typeof Agent === "function"
        ? new Agent({ connectTimeout: this.timeoutMs })
        : undefined;
  }

  // ---- HTTP plumbing ------------------------------------------------------

  private buildUrl(
    path: string,
    query?: Record<string, string | number | boolean | undefined>,
  ): string {
    const url = new URL(`${this.baseUrl}${path}`);
    if (query) {
      for (const [k, v] of Object.entries(query)) {
        if (v === undefined || v === null) continue;
        url.searchParams.set(k, String(v));
      }
    }
    return url.toString();
  }

  private buildHeaders(
    requestOpts?: RequestOptions,
    hasBody?: boolean,
  ): Record<string, string> {
    const headers: Record<string, string> = { ...this.defaultHeaders };
    if (hasBody) headers["content-type"] = "application/json";
    headers["accept"] = "application/json";
    if (this.apiKey) headers["x-api-key"] = this.apiKey;
    const effectiveAgentId = requestOpts?.agentId ?? this.agentId;
    if (effectiveAgentId) headers["x-agent-id"] = effectiveAgentId;
    if (requestOpts?.headers) {
      for (const [k, v] of Object.entries(requestOpts.headers)) {
        headers[k.toLowerCase()] = v;
      }
    }
    return headers;
  }

  private async call<TResp, TBody = unknown>(
    opts: CallOptions<TBody>,
  ): Promise<TResp> {
    const url = this.buildUrl(opts.path, opts.query);
    const hasBody = opts.body !== undefined && opts.body !== null;
    const headers = this.buildHeaders(opts.requestOpts, hasBody);

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), this.timeoutMs);
    const externalSignal = opts.requestOpts?.signal;
    if (externalSignal) {
      if (externalSignal.aborted) controller.abort();
      else externalSignal.addEventListener("abort", () => controller.abort(), { once: true });
    }

    const init: RequestInit = {
      method: opts.method,
      headers,
      signal: controller.signal,
    };
    if (this.dispatcher) {
      (init as RequestInit & { dispatcher?: Agent }).dispatcher = this.dispatcher;
    }
    if (hasBody) init.body = JSON.stringify(opts.body);

    let res: Awaited<ReturnType<FetchImpl>>;
    try {
      res = await this.fetchImpl(url, init);
    } catch (err) {
      clearTimeout(timeout);
      throw new NetworkError(
        err instanceof Error ? err.message : "network error",
        { url, cause: err },
      );
    }
    clearTimeout(timeout);

    if (opts.asText) {
      const text = await res.text();
      if (!res.ok) {
        throw apiErrorFromResponse(res.status, url, text);
      }
      const contentType = res.headers.get("content-type") ?? "text/plain";
      return { body: text, content_type: contentType } as unknown as TResp;
    }

    // Some endpoints (health) may return 503 with JSON — still parse as JSON.
    const contentType = res.headers.get("content-type") ?? "";
    let parsed: unknown = undefined;
    if (contentType.includes("application/json")) {
      try {
        parsed = await res.json();
      } catch {
        // fall through — treat as no body
      }
    } else {
      try {
        const text = await res.text();
        parsed = text.length > 0 ? text : undefined;
      } catch {
        parsed = undefined;
      }
    }

    if (!res.ok) {
      throw apiErrorFromResponse(
        res.status,
        url,
        parsed as Parameters<typeof apiErrorFromResponse>[2],
      );
    }

    return parsed as TResp;
  }

  // ========================================================================
  // Memory CRUD
  // ========================================================================

  /**
   * `POST /api/v1/memories` — create a new memory.
   *
   * #2455 — this endpoint is `WriteSurface::HttpDirect`, which fails CLOSED
   * by default: an UNSIGNED store gets `403 ATTESTATION_FAILED` from a stock
   * daemon. Pass `opts.signingKey` (plus a matching `body.agent_id`) to
   * attest the write:
   *
   * ```ts
   * import { AiMemoryClient, AgentSigningKey } from "@alphaone/ai-memory";
   *
   * const key = AgentSigningKey.fromSeed(readFileSync("svc.priv"));
   * await client.bindAgentPubkey("svc", key.publicKeyBase64()); // once, admin
   * await client.store(
   *   { title: "t", content: "c", agent_id: "svc" },
   *   { signingKey: key },
   * );
   * ```
   *
   * Omitting `signingKey` only works where the operator has explicitly set
   * `AI_MEMORY_REQUIRE_AGENT_ATTESTATION=0`.
   *
   * Signing requires `body.agent_id`: the signature commits to it, so the
   * client cannot sign a write whose identity the server would resolve from
   * the `X-Agent-Id` header or an anonymous fallback.
   */
  async store(
    body: CreateMemoryRequest,
    opts?: StoreOptions,
  ): Promise<Memory> {
    let payload = body;
    if (opts?.signingKey) {
      if (body.signature) {
        throw new TypeError(
          "pass either opts.signingKey or body.signature, not both",
        );
      }
      if (!body.agent_id) {
        throw new TypeError(
          "opts.signingKey requires body.agent_id: the signature commits to " +
            "the agent_id, so the client cannot sign a write whose identity " +
            "the server would resolve from the X-Agent-Id header or an " +
            "anonymous fallback.",
        );
      }
      // Resolve namespace + kind to the exact values that go on the wire
      // BEFORE signing — the envelope pins both, so signing anything else
      // yields a 403 that looks like a key-enrollment problem.
      const namespace = body.namespace ?? DEFAULT_NAMESPACE;
      const kind = body.kind ?? DEFAULT_MEMORY_KIND;
      payload = {
        ...body,
        namespace,
        ...attestationFields(opts.signingKey, {
          agentId: body.agent_id,
          namespace,
          title: body.title,
          content: body.content,
          kind,
          ...(body.created_at ? { createdAt: body.created_at } : {}),
        }),
      };
    }
    return this.call<Memory, CreateMemoryRequest>({
      method: "POST",
      path: "/api/v1/memories",
      body: payload,
      requestOpts: opts,
    });
  }

  /** `POST /api/v1/memories/bulk` — batch insert (<=1000). */
  async storeBulk(
    memories: CreateMemoryRequest[],
    opts?: RequestOptions,
  ): Promise<{ created: Memory[]; count: number }> {
    return this.call({
      method: "POST",
      path: "/api/v1/memories/bulk",
      body: { memories },
      requestOpts: opts,
    });
  }

  /** `GET /api/v1/memories/:id` — fetch by id. */
  async get(id: string, opts?: RequestOptions): Promise<Memory> {
    return this.call<Memory>({
      method: "GET",
      path: `/api/v1/memories/${encodeURIComponent(id)}`,
      requestOpts: opts,
    });
  }

  /**
   * `PUT /api/v1/memories/:id`.
   *
   * @param opts.expectedVersion Opt-in optimistic concurrency, sent as
   *   `If-Match` — the daemon's ONLY version gate for this route
   *   (`src/handlers/memories.rs:245-260`); there is no `version` body field,
   *   and adding one would be silently ignored. A stale version yields `409`
   *   (`ConflictError`) carrying both the expected and current versions.
   *   Omit for the legacy last-write-wins behaviour.
   */
  async update(
    id: string,
    body: UpdateMemoryRequest,
    opts?: UpdateOptions,
  ): Promise<Memory> {
    const requestOpts: RequestOptions | undefined =
      opts?.expectedVersion === undefined
        ? opts
        : {
            ...opts,
            headers: { ...(opts.headers ?? {}), "if-match": String(opts.expectedVersion) },
          };
    return this.call<Memory, UpdateMemoryRequest>({
      method: "PUT",
      path: `/api/v1/memories/${encodeURIComponent(id)}`,
      body,
      requestOpts,
    });
  }

  /** `DELETE /api/v1/memories/:id`. */
  async delete(id: string, opts?: RequestOptions): Promise<{ deleted: boolean }> {
    return this.call<{ deleted: boolean }>({
      method: "DELETE",
      path: `/api/v1/memories/${encodeURIComponent(id)}`,
      requestOpts: opts,
    });
  }

  /** `POST /api/v1/memories/:id/promote` — promote to long tier. */
  async promote(id: string, opts?: RequestOptions): Promise<Memory> {
    return this.call<Memory>({
      method: "POST",
      path: `/api/v1/memories/${encodeURIComponent(id)}/promote`,
      requestOpts: opts,
    });
  }

  /** `GET /api/v1/memories` — paginated list with filters. */
  async list(query?: ListQuery, opts?: RequestOptions): Promise<ListResponse> {
    return this.call<ListResponse>({
      method: "GET",
      path: "/api/v1/memories",
      query: query as Record<string, string | number | boolean | undefined>,
      requestOpts: opts,
    });
  }

  // ========================================================================
  // Recall / search / forget
  // ========================================================================

  /** `POST /api/v1/recall` — fuzzy hybrid recall (mutates access_count + TTL). */
  async recall(
    body: RecallRequest,
    opts?: RequestOptions,
  ): Promise<RecallResponse> {
    return this.call<RecallResponse, RecallRequest>({
      method: "POST",
      path: "/api/v1/recall",
      body,
      requestOpts: opts,
    });
  }

  /** `GET /api/v1/search` — AND keyword search (read-only). */
  async search(
    query: SearchQuery,
    opts?: RequestOptions,
  ): Promise<SearchResponse> {
    return this.call<SearchResponse>({
      method: "GET",
      path: "/api/v1/search",
      query: query as unknown as Record<string, string | number | boolean | undefined>,
      requestOpts: opts,
    });
  }

  /** `POST /api/v1/forget` — bulk delete by pattern/namespace/tier. */
  async forget(
    body: ForgetRequest,
    opts?: RequestOptions,
  ): Promise<{ deleted: number }> {
    return this.call<{ deleted: number }, ForgetRequest>({
      method: "POST",
      path: "/api/v1/forget",
      body,
      requestOpts: opts,
    });
  }

  // ========================================================================
  // Links
  // ========================================================================

  /** `POST /api/v1/links` — link two memories. */
  async link(body: LinkRequest, opts?: RequestOptions): Promise<MemoryLink> {
    return this.call<MemoryLink, LinkRequest>({
      method: "POST",
      path: "/api/v1/links",
      body,
      requestOpts: opts,
    });
  }

  /** `GET /api/v1/links/:id` — fetch all links for a memory. */
  async getLinks(
    id: string,
    opts?: RequestOptions,
  ): Promise<{ links: MemoryLink[]; count: number }> {
    return this.call({
      method: "GET",
      path: `/api/v1/links/${encodeURIComponent(id)}`,
      requestOpts: opts,
    });
  }

  // ========================================================================
  // Stats / health / namespaces
  // ========================================================================

  /** `GET /api/v1/health` — liveness + backend probe. */
  async health(opts?: RequestOptions): Promise<HealthResponse> {
    return this.call<HealthResponse>({
      method: "GET",
      path: "/api/v1/health",
      requestOpts: opts,
    });
  }

  /** `GET /api/v1/stats` — aggregate stats. */
  async stats(opts?: RequestOptions): Promise<Stats> {
    return this.call<Stats>({
      method: "GET",
      path: "/api/v1/stats",
      requestOpts: opts,
    });
  }

  /** `GET /api/v1/namespaces`. */
  async namespaces(opts?: RequestOptions): Promise<{ namespaces: { namespace: string; count: number }[] }> {
    return this.call({
      method: "GET",
      path: "/api/v1/namespaces",
      requestOpts: opts,
    });
  }

  // ========================================================================
  // Agents (registered NHI identities)
  // ========================================================================

  /** `GET /api/v1/agents` — list registered agents. */
  async agents(opts?: RequestOptions): Promise<{ agents: AgentRegistration[] }> {
    return this.call({
      method: "GET",
      path: "/api/v1/agents",
      requestOpts: opts,
    });
  }

  /** `POST /api/v1/agents` — register a new agent. */
  async registerAgent(
    body: RegisterAgentRequest,
    opts?: RequestOptions,
  ): Promise<AgentRegistration> {
    return this.call<AgentRegistration, RegisterAgentRequest>({
      method: "POST",
      path: "/api/v1/agents",
      body,
      requestOpts: opts,
    });
  }

  /**
   * `PUT /api/v1/agents/:id/pubkey` — enroll an attestation public key.
   *
   * ADMIN-GATED. Without a bound key the daemon cannot verify a signed store
   * and still answers `403` — fail-closed by design — so this is the required
   * one-time step before {@link AiMemoryClient.store} with `signingKey` can
   * succeed.
   *
   * @param pubkeyB64 Base64 32-byte Ed25519 public key; URL-safe unpadded is
   *   accepted. {@link AgentSigningKey.publicKeyBase64} emits it.
   */
  async bindAgentPubkey(
    agentId: string,
    pubkeyB64: string,
    opts?: RequestOptions,
  ): Promise<{ bound: boolean; agent_id: string }> {
    return this.call<{ bound: boolean; agent_id: string }, { pubkey_b64: string }>({
      method: "PUT",
      path: `/api/v1/agents/${encodeURIComponent(agentId)}/pubkey`,
      body: { pubkey_b64: pubkeyB64 },
      requestOpts: opts,
    });
  }

  // ========================================================================
  // v0.6.0.0 new endpoints — subscriptions, notify/inbox, grant/revoke,
  // cluster, Prometheus metrics. Some may not be merged server-side yet.
  // ========================================================================

  /** `GET /api/v1/metrics` — Prometheus text-format exposition. */
  async metrics(opts?: RequestOptions): Promise<MetricsResponse> {
    return this.call<MetricsResponse>({
      method: "GET",
      path: "/api/v1/metrics",
      requestOpts: opts,
      asText: true,
    });
  }

  /** `POST /api/v1/subscriptions` — register a webhook. */
  async subscribe(
    body: CreateSubscriptionRequest,
    opts?: RequestOptions,
  ): Promise<Subscription> {
    return this.call<Subscription, CreateSubscriptionRequest>({
      method: "POST",
      path: "/api/v1/subscriptions",
      body,
      requestOpts: opts,
    });
  }

  /**
   * `DELETE /api/v1/subscriptions?id=<id>` — remove a webhook.
   *
   * The subscription id rides the QUERY STRING, not the path. The daemon
   * registers `delete` on the collection path `/api/v1/subscriptions` only
   * (`src/lib.rs`, `handlers::routes::SUBSCRIPTIONS`) and reads the id from
   * `UnsubscribeQuery` (`src/handlers/subscriptions.rs`). The pre-v1.0.0 SDK
   * sent `DELETE /api/v1/subscriptions/:id`, which no route matches: the
   * teardown answered 405/404 and the decommissioned endpoint kept receiving
   * signed deliveries indefinitely. Verify the returned `deleted` flag.
   */
  async unsubscribe(
    id: string,
    opts?: RequestOptions,
  ): Promise<{ deleted: boolean }> {
    return this.call<{ deleted: boolean }>({
      method: "DELETE",
      path: "/api/v1/subscriptions",
      query: { id },
      requestOpts: opts,
    });
  }

  /** `GET /api/v1/subscriptions` — list current webhooks. */
  async listSubscriptions(
    opts?: RequestOptions,
  ): Promise<ListSubscriptionsResponse> {
    return this.call<ListSubscriptionsResponse>({
      method: "GET",
      path: "/api/v1/subscriptions",
      requestOpts: opts,
    });
  }

  // `grant()` / `revoke()` were REMOVED at v1.0.0. They posted to
  // `/api/v1/memories/:id/grant` and `/api/v1/memories/:id/revoke`, which are
  // not registered by the daemon and never were — every call 404'd. Per-memory
  // access control is expressed through `metadata.scope` (`private` /
  // `collective`) on the write, plus namespace governance standards; see
  // `docs/governance.md`.
  /** `POST /api/v1/notify` — send a message to another agent's inbox. */
  async notify(
    body: NotifyRequest,
    opts?: RequestOptions,
  ): Promise<{ id: string; sent: boolean }> {
    return this.call<{ id: string; sent: boolean }, NotifyRequest>({
      method: "POST",
      path: "/api/v1/notify",
      body,
      requestOpts: opts,
    });
  }

  /** `GET /api/v1/inbox` — fetch the calling agent's inbox. */
  async inbox(
    query?: InboxQuery,
    opts?: RequestOptions,
  ): Promise<InboxResponse> {
    return this.call<InboxResponse>({
      method: "GET",
      path: "/api/v1/inbox",
      query: query as Record<string, string | number | boolean | undefined>,
      requestOpts: opts,
    });
  }

  // `cluster()` was REMOVED at v1.0.0. It posted to `/api/v1/cluster`, which
  // the daemon does not register and never did — every call 404'd. Federation
  // peers are configured out of band (`--quorum-peers`, the peer-attestation
  // allowlist, `AI_MEMORY_FED_INVENTORY_PATH`); the HTTP federation surface is
  // `/api/v1/sync/push` + `/api/v1/sync/since`. See `docs/federation.md`.

  // ========================================================================
  // Low-level escape hatch
  // ========================================================================

  /**
   * Raw request for endpoints not yet wrapped. Returns parsed JSON with no
   * type refinement — cast at call site.
   */
  async raw<T = unknown>(
    method: "GET" | "POST" | "PUT" | "DELETE",
    path: string,
    body?: JsonValue,
    opts?: RequestOptions,
  ): Promise<T> {
    return this.call<T>({
      method,
      path,
      ...(body !== undefined ? { body } : {}),
      requestOpts: opts,
    });
  }
}
