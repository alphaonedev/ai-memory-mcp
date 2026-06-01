# `src/mcp/tools/` — per-tool MCP module pattern

> **Status:** post-v0.7.0 #972 Tier-D1 refactor.
> **Owners:** any contributor adding or modifying an MCP tool.
> **Cross-refs:** [`CLAUDE.md` § "Adding New Functionality"](../../../CLAUDE.md),
> [`docs/DEVELOPER_GUIDE.md`](../../../docs/DEVELOPER_GUIDE.md),
> [`src/mcp/registry.rs`](../registry.rs) (the `McpTool` trait and the
> `registered_tools()` iterator).

This directory holds **one file per MCP tool**, each carrying the
tool's request DTO, `McpTool` impl, dispatch handler, and a
schema-parity test mod. Adding a new MCP tool is one file in this
directory plus one line in `registered_tools()`.

## File layout

```
src/mcp/tools/
├── README.md                      — this file
├── mod.rs                         — `pub mod <name>;` per tool
├── d1_4_985_helpers.rs            — early-D1 parity helpers (#985)
├── <name>.rs                      — ONE per MCP tool (e.g. `recall.rs`,
│                                    `store.rs`, `auto_tag.rs`)
└── store/                         — multi-file tools may use a directory
```

The top-level `mod.rs` declares each per-tool module with a single
`pub mod <name>;` line. The corresponding parity-test helpers live at
[`src/mcp/parity_test_helpers.rs`](../parity_test_helpers.rs) — they
are shared across every per-tool test mod and exist as `pub(crate)`
helpers behind `#[cfg(test)]`.

## Required exports per tool

Every `src/mcp/tools/<name>.rs` exports three items and an internal
handler:

1. **`<Name>Request`** — the request DTO derived from
   [`schemars::JsonSchema`].
2. **`<Name>Tool`** — a zero-sized type implementing
   [`crate::mcp::registry::McpTool`].
3. **`handle_<name>` (or `pub(super)`-scoped equivalent)** — the
   dispatch handler invoked by `src/mcp/mod.rs::handle_request`.

A minimal example (`auto_tag.rs`):

```rust
use crate::mcp::registry::McpTool;
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::{Value, json};

/// Request body for `memory_auto_tag`.
//
// Do NOT add `#[schemars(deny_unknown_fields)]` / `#[serde(deny_unknown_fields)]`.
// Per the #1052 (Agent-4 F2) wire-truthfulness decision, every tool-request
// struct stays permissive: the wire schema must not advertise
// `additionalProperties: false` while the runtime tolerates unknown fields
// (wider host compat for clients with newer field sets). The honesty pin is
// `tests/mcp_input_schema_no_false_strict_1052.rs` — re-introducing the
// attribute on ANY struct fails that test. Required fields are still enforced
// by serde (a field with no `#[serde(default)]` errors when missing).
#[derive(Debug, Clone, Default, Deserialize, JsonSchema)]
pub struct AutoTagRequest {
    /// Memory ID.
    pub id: String,
}

pub struct AutoTagTool;

impl McpTool for AutoTagTool {
    fn name() -> &'static str { "memory_auto_tag" }
    fn description() -> &'static str {
        "LLM-generate tags for a memory (smart/autonomous tier)."
    }
    fn docs() -> &'static str {
        "LLM auto-tagging. Smart/autonomous tier."
    }
    fn input_schema() -> Value {
        let schema = schemars::schema_for!(AutoTagRequest);
        serde_json::to_value(schema)
            .expect("schemars schema must serialize to Value")
    }
    fn family() -> &'static str { "power" }
}

pub(super) fn handle_auto_tag(
    conn: &rusqlite::Connection,
    llm: Option<&crate::llm::OllamaClient>,
    params: &Value,
) -> Result<Value, String> {
    // ... handler body ...
    Ok(json!({}))
}
```

The five `McpTool` methods are pure / cheap. `input_schema()` is
recomputed each `tools/list` call (no caching) because the per-request
budget is dominated by JSON serialisation, not schemars reflection.

## Registering the tool

Append one line to `registered_tools()` in
[`src/mcp/registry.rs`](../registry.rs):

```rust
RegisteredTool::of::<crate::mcp::auto_tag::AutoTagTool>(),
```

Order in `registered_tools()` matches the pre-D1.6 `tool_definitions()`
macro order; new tools append at the family-end. The dispatch arm in
`src/mcp/mod.rs::handle_request` matches on `<name>` and calls
`<name>::handle_<name>(...)` directly.

## Per-tool parity / metadata tests

Each module ships a `#[cfg(test)] mod d1_5_986_tests` block (or the
D1.6 successor `mod d1_6_987_tests`) that pins the schemars-derived
schema against the canonical wire shape via the shared helpers:

```rust
#[cfg(test)]
mod d1_5_986_tests {
    use super::*;
    use crate::mcp::parity_test_helpers::{
        assert_descriptions_match,
        assert_property_set_parity,
        derived_props_for,
    };

    #[test]
    fn auto_tag_parity_986() {
        let derived = derived_props_for::<AutoTagRequest>();
        assert_property_set_parity("memory_auto_tag", &derived);
        assert_descriptions_match("memory_auto_tag", &derived);
    }

    #[test]
    fn auto_tag_tool_metadata_986() {
        assert_eq!(AutoTagTool::name(), "memory_auto_tag");
        assert_eq!(AutoTagTool::family(), "power");
    }
}
```

`derived_props_for::<T>()` resolves the schemars `properties` map even
when schemars relocates it under
`definitions/<TypeName>/properties` (untagged-enum case). The
property-set + per-property `description` byte-equality checks are
the load-bearing invariants — see the doc-comment in
[`src/mcp/parity_test_helpers.rs`](../parity_test_helpers.rs) for the
documented allowed-diffs catalog (schemars `Option<T>` → nullable
union, schemars `null` defaults, `additionalProperties: false` from
`deny_unknown_fields`).

The legacy hand-coded `tool_definitions()` JSON catalog was deleted
in D1.6 (#987). The post-D1.6 wire-shape regression pinned in
[`src/mcp/registry.rs::d1_6_987_tests`](../registry.rs) compares the
live catalog against a stored pre-D1.6 snapshot at
`tests/snapshots/tool_definitions_pre_d1_6.json`.

## Schemars `#`-prefix description quirk + workaround

`schemars` interprets a doc-comment line that starts with `#` as a
markdown H1 heading and routes the leading line into the schema's
`title` field instead of the per-property `description`. Several
legacy descriptions lead with a `#NNN` issue reference (e.g.
`"#908 consolidator agent_id."`). For those fields, replace the
`///` doc-comment with an explicit `#[schemars(description = "...")]`
attribute:

```rust
// #908: leading `#` would otherwise become a markdown H1 and land in
// `title` instead of `description`. Force the byte-for-byte string
// with the attribute form.
#[schemars(description = "#908 consolidator agent_id.")]
#[serde(default)]
pub agent_id: Option<String>,
```

`grep -rn 'schemars(description' src/mcp/tools/` enumerates every
field that uses this workaround.

## Wire trimmer behavior (post-D1.6)

The bare `tools/list` payload is rendered through
[`crate::mcp::registry::strip_docs_from_tools`](../registry.rs) before
it goes on the wire. The trimmer drops every long-form
natural-language string so the C5 ≤ 3500 cl100k token ceiling holds
on the full profile.

**Stripped from the wire** (was emitted by schemars but never by the
pre-D1.6 hand-coded macro):

- Top-level `docs` field (the prose mirror of `description`).
- `inputSchema.description` (schemars emits this from the request
  struct's own doc-comment).
- `inputSchema.$schema` reference.
- `inputSchema.title`.
- Every nested `description` under `inputSchema.definitions.*` (for
  `$ref`-resolved untagged enums such as
  `RecallKindsFilter::Many(Vec<String>) | One(String)`).
- Every per-parameter `description` under
  `inputSchema.properties.*`.
- Long string `default` values (>32 chars of prose). Short numeric /
  boolean / short-enum defaults stay — they are load-bearing for
  client-side argument construction.

**Preserved on the bare wire:**

- The top-level short `description` (≤ 50 cl100k tokens).
- The full `inputSchema` shape — `type`, `enum`, `default`,
  `minimum`, `maximum`, `required`, `items` — so callers can still
  build valid argument objects without a verbose drilldown.

**Verbose drilldown.** NHI agents that need the full prose surface
call:

```json
{
  "method": "tools/call",
  "params": {
    "name": "memory_capabilities",
    "arguments": {
      "family": "<family>",
      "include_schema": true,
      "verbose": true
    }
  }
}
```

The verbose path goes through `tool_definitions()` directly **without**
stripping, returning the un-trimmed schemars schema with every
`description` and the full `docs` field.

## Counts at v0.7.0

- 74 per-tool `McpTool` impls (73 under `src/mcp/tools/*.rs` +
  `StoreTool` under `src/mcp/tools/store/mod.rs`).
- 74 entries in `registered_tools()`
  (`Profile::full().expected_tool_count() == 74 ==
  crate::mcp::registry::tool_names::ALL.len()`). 73 of these are
  callable memory tools; the 74th is the always-on
  `memory_capabilities` bootstrap — see issue #862 for the canonical
  73-callable / 74-advertised disambiguation.
- 4-line iteration over `registered_tools()` is the entire body of
  `tool_definitions()` post-D1.6.
- 7 always-on tools at the v0.7.0 default profile; additional tools
  load via `memory_load_family` / `memory_smart_load`.
