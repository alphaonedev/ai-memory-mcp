<!-- Copyright 2026 AlphaOne LLC / SPDX-License-Identifier: Apache-2.0 -->
# Reference L4 host-adapter shims

Three self-contained reference implementations of the same job: call the
`memory_capture_turn` MCP tool over stdio, per
[RFC-0001](../../docs/rfc/RFC-0001-mcp-turn-capture.md), from a host whose only
integration surface is "spawn a process from a Stop / SessionEnd / per-turn
hook". Hosts with native MCP integration call the tool directly and need none
of these.

| Adapter | File | Requires |
| --- | --- | --- |
| Python | `python/capture_turn.py` | CPython >= 3.10, stdlib only |
| Node | `node/capture-turn.mjs` | Node >= 18, builtins only |
| Bash | `bash/capture-turn.sh` | bash, `jq` |

Each is ONE file on purpose: operators copy it onto the host. They therefore do
not share a module — they share a **pinned predicate** instead (below).

## The capture contract (#3544)

The shim exits `0` **only when the substrate confirms the turn was persisted** —
that is, when the `memory_capture_turn` receipt carries a non-empty `memory_id`
(`src/mcp/tools/capture_turn.rs`; the field RFC-0001 lists in the tool result's
`required` set). The exit-code SET is unchanged; the meaning of `0` is what this
fixes.

| Exit | Meaning |
| --- | --- |
| `0` | The substrate **persisted** the turn. A `dedup_hit` counts — the row exists. |
| `1` | Usage error. |
| `2` | The turn was **NOT persisted**: transport fault, substrate error, governance `ask` / `pending`, an unreadable receipt, or any receipt this release cannot prove describes a stored row. |
| `3` | Content file missing/unreadable. |

Exit `2` is "this turn is not stored", never "this turn is lost" — the stderr
`WARN:` line tells those apart:

| Receipt | Exit | stderr |
| --- | --- | --- |
| `memory_id` present (`dedup_hit` either way) | `0` | — |
| `status: "ask"` | `2` | **Nothing was persisted and there is no recovery handle** — re-send the turn if you need it. The message deliberately names no recovery path, because none exists. |
| `status: "pending"` | `2` | The write is **durably queued, not lost**; the `pending_id` is printed and redeems the turn via `memory_pending_approve`. |
| anything else | `2` | Fails **closed** — an unreadable payload, a payload with no provable `memory_id`, or a `status` a later substrate release grows. |

Every release before this one exited `0` for `ask`, for `pending`, and for every
receipt it did not enumerate, so a host had no signal that its transcript was
not durable.

**The bash adapter needs `jq`.** Reading the receipt is a two-level JSON parse
(the tool payload rides inside `result.content[0].text` as a JSON *string*),
which `grep` cannot do correctly. Without `jq` the shim cannot prove the turn
was persisted, so it exits `2` and says so rather than guessing: degrade, never
lie about durability.

## Tests

The suite is hermetic and offline — no `ai-memory` binary, no daemon, no
network. Each adapter is run with `--ai-memory-bin` pointed at a throwaway
POSIX-shell fake substrate that prints canned JSON-RPC frames.

```bash
cd clients/host-adapter-shim
python -m pytest -q          # needs python3 + node + bash + jq on PATH
```

`tests/envelopes.py` is the single source of truth for the receipt vocabulary
(every envelope is copied from `src/mcp/tools/capture_turn.rs`), and
`tests/test_capture_outcome_conformance.py` asserts that the three adapters
return the **same exit code and byte-identical stderr text** for every cell.
That cross-language identity is what makes three implementations one predicate:
change any one of them alone and the suite goes red.
