### Security

- **[skills] A failed skill export renders one closed text per failure class**
  ([#9174](https://github.com/alphaonedev/ai-memory-mcp/pull/9174)). The MCP tool, the CLI and the
  HTTP route render a failed `memory_skill_export` from the same class mapping, so the three
  surfaces are byte-identical. A stored resource path, a decoder message and a governance rule
  reason go to the operator log only; a resource-level read refusal names the skill
  (`skill integrity check failed: skill <id>`), never the stored path.
