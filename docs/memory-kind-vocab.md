---
layout: doc
---
# Memory-Kind Vocabulary (Form 6, issue #759; Pillar 2, issue #1709)

v0.7.x extends the substrate's `MemoryKind` enum from the original
three lifecycle variants (`Observation` / `Reflection` / `Persona`)
with the seven-variant Batman taxonomy extension, v0.8.0
(Pillar 2, #1709) adds the three-variant typed-cognition cluster, and
v1.0.0 (#1945, spec §4) adds the three-variant epistemic-typing
cluster. The full set is now **16 kinds**:

| variant | purpose |
| --- | --- |
| `observation` | direct note from the caller — the default. |
| `reflection`  | curator-synthesised summary over lower-depth peers. |
| `persona`     | curator-generated entity profile (QW-2). |
| `concept`     | abstract definition / vocabulary term. |
| `entity`      | named real-world thing (person, org, product, system). |
| `claim`       | factual assertion the caller is committing to. |
| `relation`    | typed pair / triple anchored in the memory substrate. |
| `event`       | temporally-bounded happening. |
| `conversation`| captured dialogue turn. |
| `decision`    | choice point with rationale (L1-6 reservation). |
| `goal`        | a desired end-state / objective (Pillar 2 typed-cognition, #1709). |
| `plan`        | an ordered strategy to reach a goal (Pillar 2 typed-cognition, #1709). |
| `step`        | a single executable unit within a plan (Pillar 2 typed-cognition, #1709). |
| `told`        | RECEIVED hearsay — a claim the agent was told, epistemically below `observation` (v1.0.0 #1945). |
| `instruction` | a RECEIVED imperative / directive (fixes the L1 operator-directive mis-stamp) (v1.0.0 #1945). |
| `intervention`| an ENACTED `do(X)` ground-truth — the do-calculus complement of `observation` (v1.0.0 #1945). |

The first three are the v0.7.0 lifecycle variants and are unchanged.
The next seven (Form 6) give downstream readers a richer
filter-by-kind surface aligned with the Batman framework's exemplar
(Tolaria's frontmatter-as-type schema). The next three
(`goal` / `plan` / `step`, v0.8.0 #1709) are the Pillar-2
typed-cognition kinds: a `goal` names a desired end-state, a `plan`
is the ordered strategy to reach it, and a `step` is one executable
unit within that plan. The final three (`told` / `instruction` /
`intervention`, v1.0.0 #1945) are the epistemic-typing kinds: `told`
marks second-hand hearsay (below a first-person `observation`),
`instruction` marks a received directive, and `intervention` marks a
`do(X)` action the agent itself enacted. These three slugs are
committed into the signed `SignableWrite` v2 genesis bytes
(spec §2.2 [4]), so they are T4-frozen wire values at the v1.0 tag.
The default-flip that would make untyped caller silence sink to
`claim` (rather than `observation`) is PHASED to v0.10.0 (#1972) and is
**not** part of this change — the untyped default remains
`observation`.

## Provenance metadata: `kind_provenance` (v1.0.0 #1945, schema v79)

The additive nullable `memories.kind_provenance TEXT` column (schema
v79) records **how** the kind was assigned — a closed vocabulary of
`declared` / `channel_derived` / `regex` / `llm` (the
`ConfidenceSource` precedent, [`crate::models::KindProvenance`]). It is
**unsigned metadata** — NOT part of the signed envelope (unlike the
`memory_kind` slug itself) — so it is an ESTIMABLE provenance marker: it
records how the kind was assigned, not that the kind is true. It lets a
consumer distinguish a caller-DECLARED kind from a channel-DERIVED one.

## Schema impact: none

The `memories.memory_kind TEXT` column has no CHECK constraint on
either the SQLite or Postgres backends, so the new variants land as
new string values on the existing column. No migration required;
schema version stays at v37 / v18 respectively. Backward compat:

* Old rows with no `memory_kind` value read as `Observation` (the
  SQL `DEFAULT 'observation'`).
* Future variants emitted by a newer client to an older binary
  read as `Observation` via the `unwrap_or_default()` fallback in
  `row_to_memory`.
* Old binaries reading a new variant from the DB also fall through
  to `Observation` — the wire shape stays compatible across version
  drift.

The fallbacks above are **read-path** only (`row_to_memory` widening a
stored/unknown value). They do NOT apply to the **write path**.

## Write-path validation (#1467)

On every write surface — CLI `store`, MCP `memory_store`, and HTTP
`POST /api/v1/memories` — a supplied `kind` is validated before the row
is created:

* Omitting `kind` (absent / `null`) keeps the default `Observation`.
* A non-empty `kind` MUST be an exact match for one of the canonical
  lowercase variants in the table above; anything else (unknown token,
  wrong case, whitespace) is **rejected** with
  `invalid kind '<value>' (expected one of: …)`.

Prior to #1467 the MCP and HTTP surfaces silently coerced an
unknown/invalid `kind` to `observation` while the CLI rejected it; all
three surfaces now reject consistently, so a typo'd kind never lands a
misclassified row. The canonical accepted set is `MemoryKind::all()`
(the error message is generated from it, never a hardcoded list).

## Recall filter

The new `kinds` parameter on `memory_recall` (MCP), `?kinds=…` (HTTP
GET), and `kinds: …` (HTTP POST body) accepts either:

* a comma-separated string: `"concept,entity,claim"`
* a JSON array: `["concept", "entity", "claim"]`
* the literal `"all"` (case-insensitive) ⇒ no filter (equivalent to
  omission)

OR-of-kinds within the param; AND with the other filters (namespace,
tags, time-window, visibility). Unknown tokens are silently dropped
so a newer client emitting a future variant doesn't break recall on
an older binary.

### MCP

```jsonc
{
  "tool": "memory_recall",
  "args": {
    "context": "policy on token rotation",
    "kinds": ["claim", "decision"]
  }
}
```

### HTTP

```http
GET /api/v1/recall?q=policy+rotation&kinds=claim,decision
```

```jsonc
POST /api/v1/recall
{
  "context": "policy on token rotation",
  "kinds": ["claim", "decision"]
}
```

### CLI

```bash
ai-memory recall "policy on token rotation" --kind claim,decision
```

## Auto-classify pre-store hook

The substrate ships a namespace-policy-gated pre-store hook
([`auto_classify_kind`](../src/hooks/pre_store/auto_classify_kind.rs))
that may rewrite a stored memory's `memory_kind` from the default
`Observation` to a more specific Batman-taxonomy variant. Three
policy modes, set on the namespace standard's `metadata.governance`
JSON blob under `auto_classify_kind`:

```jsonc
{
  "governance": {
    "auto_classify_kind": "off" | "regex_only" | "regex_then_llm"
  }
}
```

* **`off` (default).** Substrate quiet — caller-supplied (or default
  `Observation`) kind stands.
* **`regex_only`.** Deterministic regex heuristics. ~tens of
  microseconds per call; safe to run on every write. Fires only
  when the content carries a strong signal (e.g. `is_a` ⇒
  `Concept`, `happened on` ⇒ `Event`, `X says:` ⇒ `Conversation`,
  `decided to` ⇒ `Decision`, `depends on` ⇒ `Relation`). Misses
  keep the row at `Observation`.
* **`regex_then_llm`.** Regex first; if no heuristic fires, fall
  through to a single-shot LLM classifier. Opt-in only — the
  substrate never spawns an LLM round-trip on a namespace whose
  policy is `off` or `regex_only`. The LLM round-trip path is
  feature-gated on `llm.classify_kind`; if a runtime doesn't
  carry a classifier, the hook degrades to `regex_only` semantics
  silently (logged at debug).

The caller-supplied `kind` parameter on `memory_store` always wins
— the hook only fills in `Observation` (the default) when no kind
was set. This keeps explicit-typing callers in full control while
giving operators an opt-in path to classify legacy / unstructured
content automatically.

### Operator surface

The substrate exposes the recall-filter and auto-classify wiring
under the `memory_kind_vocab` block of the v3 capabilities
response. Operators can read the live state via:

```bash
printf '%s\n' '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"memory_capabilities","arguments":{"accept":"3"}}}' \
  | ai-memory mcp --profile core | jq .
```

(The v0.7-alpha drafts referenced `ai-memory doctor --capabilities=v3`;
that flag was not shipped. The MCP `memory_capabilities` tool is the
canonical inspection surface — it works against any running daemon
regardless of profile because `memory_capabilities` is on the
`ALWAYS_ON_TOOLS` allowlist.)

```jsonc
{
  "vocabulary": ["observation", "reflection", "persona", "concept",
                 "entity", "claim", "relation", "event",
                 "conversation", "decision", "goal", "plan", "step"],
  "recall_filter": "implemented",
  "cli_filter": "implemented",
  "auto_classify": "implemented",
  "auto_classify_modes": ["off", "regex_only", "regex_then_llm"]
}
```

## Forward-compat reservations

`Decision` is the only L1-6 reservation in the v0.7.x set. The
L1-6 work (v0.8.0) will likely add columns for rationale /
alternatives on top of the variant; binaries that ship the
variant now can already type-tag decisions so downstream readers
get a stable filter surface from day one.

## Why no schema bump

The original L1-1 work (v0.7.0) landed the `memory_kind TEXT NOT
NULL DEFAULT 'observation'` column under migration 0025 / 0018
without a CHECK constraint. That was a deliberate forward-compat
choice: new variants land as new column values; no migration is
required to widen the accepted set. The decision is documented in
the L1-1 commit and validated by Form 6's no-migration ship.
