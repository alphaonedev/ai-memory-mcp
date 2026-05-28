# CLI Design Rationale

## Why there is no flat `ai-memory reflect` verb

The CLI exposes `ai-memory store` and `ai-memory recall` as flat verbs because storage and retrieval are model-neutral substrate operations — the operator invoking them is the author of the operation, and no architectural property depends on which model family is in the loop at invocation time.

Reflection is structurally different. Reflection composes with the **bias-displacement architecture** named in [`docs/strategy/moonshot-synthesis.md`](strategy/moonshot-synthesis.md) §2.6 — the cross-model reflection boundary where a decorrelated-family LLM reflects on the producing LLM's work to produce bias-displaced cognitive artifacts. This is the federalist-papers move applied to AI cognition: the substrate does not trust any single cognition's account of its own actions; it trusts only the intersection of cognitions with decorrelated errors.

There are two structurally distinct operations both called "reflection":

| Operation | What it is | How it is invoked |
|---|---|---|
| **Substrate-primitive reflection** | A depth-N memory write with `reflects_on` link edges (`memory_reflect` MCP tool). Model-neutral. The mechanism. | `ai-memory mcp` JSON-RPC subprocess; direct handler call from substrate-internal code paths |
| **Bias-displacement reflection** | The cross-model reflection pass where the second LLM (currently `models.llm` from capabilities — e.g., xAI Grok 4.3) reflects on the producing LLM's memories. The architectural property §2.6 requires. | `ai-memory curator --reflect`; periodic curator-daemon passes; `memory_consolidate` |

A flat `ai-memory reflect` CLI verb would expose the substrate primitive to the operator in a shape that visually parallels `ai-memory store` and `ai-memory recall`. The visual parallel is the problem: it would suggest reflection is a model-neutral storage operation, when in fact whether a reflection produces bias-displacement depends on which model family invoked it. An operator typing `ai-memory reflect --source-ids ... --content ...` would write a reflection authored by the operator (not by a decorrelated LLM), and the cognitive artifact would carry the visual shape of a reflection without the architectural property the substrate's §2.6 alignment claim depends on.

## The current CLI surface

The CLI surfaces reflection only through actor-named higher-level verbs that name what is happening:

- **`ai-memory curator --reflect`** — fires a curator pass. The curator uses `models.llm` (the configured second LLM, decorrelated from the producing LLM by deployment discipline) to reflect on memories in the namespace. This is the bias-displaced path.
- **`ai-memory consolidate`** — substrate-side merge of multiple source memories into a synthesized memory. Uses the curator path internally.
- **`ai-memory export-reflections`** — file-backed export of existing reflection chains for audit, archival, or pipeline handoff.
- **`ai-memory verify-reflection-chain`** — external verifier walking `reflects_on` edges. Audits chain integrity, not writes.
- **`ai-memory verify-signed-events-chain`** — V-4 cross-row hash chain integrity verifier. Confirms the audit chain that records reflections.
- **`ai-memory mcp`** — JSON-RPC subprocess. Direct primitive invocation when needed (debugging, bridge tooling, batch ingestion from upstream substrates).

The asymmetry with `store` / `recall` is intentional. Storage and retrieval do not compose with the bias-displacement architecture; reflection does. The CLI surface preserves the distinction by surfacing reflection through actor-named verbs at the shell layer and primitive invocation through MCP at the protocol layer.

## When this rationale might evolve

The current design is correct for v0.7.0's deployment shape (developer + single-agent + curator-mediated reflection). It may need to evolve in later releases:

- **If batch ingestion from upstream substrates needs operator-facing reflection invocation at scale** (e.g., a Knowledge Atlas → ai-memory bridge for multi-year corpus loading), address it as `ai-memory curator --reflect --batch < cards.jsonl` — preserving the bias-displacement path — not as a flat `reflect` verb.
- **If operator debugging needs direct primitive invocation outside JSON-RPC**, address it as a `dev`-tier subcommand explicitly named as bypassing the curator path: e.g., `ai-memory dev reflect-direct` with documentation that names what it does and does not do.
- **If the §2.6 bias-displacement architecture is ever explicitly removed from the substrate's load-bearing claims** (it is not, and is unlikely to be), revisit whether the CLI distinction is still necessary.

Any future revision of this rationale should engage the §2.6 architectural property explicitly. The question "should there be `ai-memory reflect`" cannot be answered by ergonomic symmetry alone; it requires engaging which structural property the verb would or would not preserve.

## Provenance

- Verification report at `release/v0.7.0` HEAD confirmed the CLI inventory (79 subcommands in the default build / 81 under `--features sal` or `--features sal-postgres`; `Reflect` and 15 other parity variants subsequently landed via the FX-C3 batch2 work) and recommended Hold Position.
- Operator-led architectural review surfaced the §2.6 composition that the verification report named only structurally.
- Final decision: hold position. Ship v0.7.0 with the current CLI surface unchanged. Document the rationale here so the question cannot resurface without engaging the architecture.
- See also: [`docs/strategy/moonshot-synthesis.md`](strategy/moonshot-synthesis.md) §2.6 (bias-displacement through architectural separation-of-powers); [`ROADMAP.md`](../ROADMAP.md) §2.6 (the seven properties that remain load-bearing through ASI).
