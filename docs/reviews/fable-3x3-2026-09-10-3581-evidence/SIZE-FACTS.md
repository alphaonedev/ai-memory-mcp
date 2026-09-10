# Codebase size facts (measured on the chain-4 tip aae5320e, 2026-09-10)
- src/: 587,202 lines of Rust in 491 files; approx 331k lines (56%) are in-file #[cfg(test)] modules (heuristic: lines after the first cfg(test) marker per file) → production approx 256k.
- tests/: 351,543 lines in 847 files. docs/: 122,986 lines of markdown. sdk/: ~1 MB.
- Largest files (total lines): src/store/postgres.rs 42,410; src/storage/mod.rs 33,847; src/mcp/mod.rs 17,385; src/handlers/tests.rs 17,130; src/config.rs 15,029; src/daemon_runtime.rs 14,479; src/store/mod.rs 7,881; src/storage/migrations.rs 7,285; src/store/sqlite.rs 6,904.
- QUAL-10 module-size ceilings exist (tests/qual_10_module_size_ceiling.rs): postgres.rs 42_500, storage/mod.rs 34_000, mcp/mod.rs 17_400, config.rs 15_120.
- 104 MCP tools (tool_names::ALL), 86 unique HTTP paths / 100 route registrations, 65 files under src/mcp/tools, 43 under src/handlers. Single crate, no [workspace].
- Operator's question for waves 2-3: the codebase is becoming too big to manage. Would an integrity-kernel/core extraction REDUCE it, or only relocate code? What would actually reduce it (in-file test modules → tests/, sqlite/postgres twin handler branches behind the store trait, thin HTTP mirror wrappers, generated inventories)? Give numbers where you can verify them.
