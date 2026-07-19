// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

/**
 * ai-memory Anthropic shim (TypeScript) — record each Anthropic Messages turn
 * to ai-memory.
 *
 * Reference (#1390) Direct-API SDK shim for callers who use the `@anthropic-ai/sdk`
 * in their own scripts without a host harness that writes a recoverable
 * transcript. `wrap(client)` returns a transparent proxy: every property
 * delegates to the wrapped client unchanged except `messages.create`, which —
 * before returning the response verbatim — records the new user turn and the
 * assistant turn to ai-memory via the `memory_capture_turn` MCP tool
 * (RFC-0001). Transpose of the canonical Python reference (`anthropic-shim-py`).
 *
 * `@anthropic-ai/sdk` is a PEER dependency — bring your own client. The shim is
 * non-wedging: a capture failure never disturbs your LLM call.
 */
import { spawnSync } from "node:child_process";
import { randomUUID } from "node:crypto";

const DEFAULT_BIN = "ai-memory";
const CALL_ID = 2;
const TIMEOUT_MS = 30_000;
const HOST_KIND = "anthropic-sdk";

// --------------------------------------------------------------------------- //
// Capture transport (memory_capture_turn over MCP stdio; NEVER throws)
// --------------------------------------------------------------------------- //

export interface CaptureTurnParams {
  hostSessionId: string;
  hostTurnIndex: number;
  role: string;
  content: string;
  namespace?: string;
  hostKind?: string;
  hostVersion?: string;
  timestampIso?: string;
  aiMemoryBin?: string;
}

function buildRequest(p: CaptureTurnParams): Record<string, unknown> {
  const req: Record<string, unknown> = {
    host_session_id: p.hostSessionId,
    host_turn_index: p.hostTurnIndex,
    role: p.role,
    content: p.content,
  };
  if (p.namespace) req.namespace = p.namespace;
  if (p.hostKind) req.host_kind = p.hostKind;
  if (p.hostVersion) req.host_version = p.hostVersion;
  if (p.timestampIso) req.timestamp_iso = p.timestampIso;
  return req;
}

function buildFrames(captureRequest: Record<string, unknown>): string {
  const init = {
    jsonrpc: "2.0",
    id: 1,
    method: "initialize",
    params: {
      protocolVersion: "2025-03-26",
      capabilities: {},
      clientInfo: { name: "ai-memory-anthropic-shim-ts", version: "0.1" },
    },
  };
  const initialized = { jsonrpc: "2.0", method: "notifications/initialized" };
  const call = {
    jsonrpc: "2.0",
    id: CALL_ID,
    method: "tools/call",
    params: { name: "memory_capture_turn", arguments: captureRequest },
  };
  return [init, initialized, call].map((o) => JSON.stringify(o)).join("\n") + "\n";
}

function pickCallResponse(stdout: string): Record<string, unknown> | null {
  for (const line of stdout.split("\n")) {
    const trimmed = line.trim();
    if (!trimmed.startsWith("{")) continue;
    try {
      const obj = JSON.parse(trimmed) as Record<string, unknown>;
      if (obj.id === CALL_ID) return obj;
    } catch {
      /* not our line */
    }
  }
  return null;
}

function warn(msg: string): void {
  process.stderr.write(`WARN ai-memory-anthropic-shim: ${msg}\n`);
}

/** Record one turn to ai-memory. Returns true on success; NEVER throws. */
export function captureTurn(p: CaptureTurnParams): boolean {
  const bin = p.aiMemoryBin ?? process.env.AI_MEMORY_BIN ?? DEFAULT_BIN;
  const frames = buildFrames(buildRequest(p));
  const result = spawnSync(bin, ["mcp", "--profile", "full"], {
    input: frames,
    encoding: "utf-8",
    timeout: TIMEOUT_MS,
  });
  if (result.error) {
    warn(`capture spawn failed: ${result.error.message}`);
    return false;
  }
  if (result.status !== 0) {
    warn(`substrate exited ${String(result.status)}`);
    return false;
  }
  const resp = pickCallResponse(result.stdout ?? "");
  if (!resp) {
    warn("no capture response from substrate");
    return false;
  }
  const inner = resp.result as Record<string, unknown> | undefined;
  if (inner && typeof inner === "object" && inner.isError === true) {
    warn("substrate returned isError:true");
    return false;
  }
  return true;
}

// --------------------------------------------------------------------------- //
// Extraction seam (Anthropic Messages shape; pinned by recorded cassettes)
// --------------------------------------------------------------------------- //

function dump(o: unknown): string {
  try {
    return JSON.stringify(o);
  } catch {
    return String(o);
  }
}

function flattenContent(content: unknown): string {
  if (content == null) return "";
  if (typeof content === "string") return content;
  if (Array.isArray(content)) {
    const parts: string[] = [];
    for (const block of content) {
      if (typeof block === "string") {
        parts.push(block);
        continue;
      }
      const b = block as Record<string, unknown>;
      const text = b?.type === "text" ? b.text : undefined;
      if (typeof text === "string") parts.push(text);
      else parts.push(dump(block));
    }
    return parts.filter(Boolean).join("\n");
  }
  return String(content);
}

/** The NEW turn of a `messages.create` call: the last message in `messages`. */
export function extractLastRequestTurn(
  kwargs: Record<string, unknown>,
): [string, string] | null {
  const messages = kwargs?.messages as unknown[] | undefined;
  if (!messages || messages.length === 0) return null;
  const last = messages[messages.length - 1] as Record<string, unknown>;
  const content = flattenContent(last?.content);
  if (!content) return null;
  const role = (last?.role as string) ?? "user";
  return [role, content];
}

/** Concatenate the text blocks of an Anthropic Messages response. */
export function extractResponseText(response: unknown): string {
  const r = response as Record<string, unknown> | null;
  return flattenContent(r?.content);
}

// --------------------------------------------------------------------------- //
// Delegating proxy
// --------------------------------------------------------------------------- //

export type CaptureFn = (p: CaptureTurnParams) => boolean;

export interface WrapOptions {
  hostSessionId?: string;
  namespace?: string;
  aiMemoryBin?: string;
  hostKind?: string;
  /** @internal test seam — override the capture transport. */
  captureFn?: CaptureFn;
}

class Recorder {
  private readonly opts: WrapOptions;
  private readonly sessionId: string;
  private counter = 0;

  constructor(opts: WrapOptions) {
    this.opts = opts;
    this.sessionId = opts.hostSessionId ?? `anthropic-shim-${randomUUID().slice(0, 12)}`;
  }

  private record(role: string, content: string): void {
    if (!content) return;
    try {
      const cap = this.opts.captureFn ?? captureTurn;
      cap({
        hostSessionId: this.sessionId,
        hostTurnIndex: this.counter++,
        role,
        content,
        namespace: this.opts.namespace,
        hostKind: this.opts.hostKind ?? HOST_KIND,
        aiMemoryBin: this.opts.aiMemoryBin,
      });
    } catch (e) {
      warn(`record failed: ${String(e)}`);
    }
  }

  recordRequest(kwargs: Record<string, unknown>): void {
    try {
      const turn = extractLastRequestTurn(kwargs);
      if (turn) this.record(turn[0], turn[1]);
    } catch (e) {
      warn(`request extract failed: ${String(e)}`);
    }
  }

  recordResponse(response: unknown): void {
    try {
      this.record("assistant", extractResponseText(response));
    } catch (e) {
      warn(`response extract failed: ${String(e)}`);
    }
  }
}

function wrapMessages(inner: unknown, rec: Recorder): unknown {
  return new Proxy(inner as object, {
    get(target, prop, receiver) {
      if (prop === "create") {
        return (...args: unknown[]) => {
          const kwargs = (args[0] ?? {}) as Record<string, unknown>;
          rec.recordRequest(kwargs);
          const result = (target as Record<string, (...a: unknown[]) => unknown>).create(...args);
          if (kwargs.stream) return result; // stream: request-only, pass through
          return Promise.resolve(result).then((resp: unknown) => {
            rec.recordResponse(resp);
            return resp;
          });
        };
      }
      return Reflect.get(target, prop, receiver);
    },
  });
}

/**
 * Wrap an Anthropic / AsyncAnthropic client so each Messages turn is recorded
 * to ai-memory. Returns a transparent proxy — use it exactly like the original.
 */
export function wrap<T extends object>(client: T, opts: WrapOptions = {}): T {
  const rec = new Recorder(opts);
  return new Proxy(client, {
    get(target, prop, receiver) {
      if (prop === "messages") return wrapMessages((target as Record<string, unknown>).messages, rec);
      return Reflect.get(target, prop, receiver);
    },
  }) as T;
}
