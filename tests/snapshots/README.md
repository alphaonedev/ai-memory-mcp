# `tests/snapshots/` — MCP tool catalog wire snapshots

TEST-3 (med/low review batch, v0.7.0).

Per-profile, byte-for-byte JSON snapshots of `tools/list` for the five
named MCP profiles (`core`, `graph`, `admin`, `power`, `full`) plus the
pre-D1.6 union snapshot. The snapshots are load-bearing regression
fixtures consumed by:

| Snapshot file                          | Consumer                                                   |
|----------------------------------------|------------------------------------------------------------|
| `tools_list_core.json`                 | `tests/mcp_tools_list_snapshots.rs::d1_7_988_tools_list_snapshot_core` |
| `tools_list_graph.json`                | `tests/mcp_tools_list_snapshots.rs::d1_7_988_tools_list_snapshot_graph` |
| `tools_list_admin.json`                | `tests/mcp_tools_list_snapshots.rs::d1_7_988_tools_list_snapshot_admin` |
| `tools_list_power.json`                | `tests/mcp_tools_list_snapshots.rs::d1_7_988_tools_list_snapshot_power` |
| `tools_list_full.json`                 | `tests/mcp_tools_list_snapshots.rs::d1_7_988_tools_list_snapshot_full`  |
| `tool_definitions_pre_d1_6.json`       | `src/mcp/registry.rs::tool_definitions_pre_d1_6_parity_*`  |

Each test calls `ai_memory::mcp::tool_definitions_for_profile(&profile)`,
canonicalises the JSON (2-space indent + sorted object keys at every
level), and compares byte-for-byte against the committed snapshot. If
the substrate's catalog drifts (added/removed/renamed tool, schemars
property reshuffle, default change, …), the test fails with a
line-and-column diff hint.

## Regenerating snapshots (when a change is intentional)

Set `AI_MEMORY_BLESS_SNAPSHOTS=1` and re-run the snapshot test. The
test will overwrite the on-disk file in place with the newly-computed
canonical JSON instead of asserting:

```sh
AI_MEMORY_BLESS_SNAPSHOTS=1 cargo test \
    --no-default-features --features sqlite-bundled \
    --test mcp_tools_list_snapshots
```

Notes:

- **All five profile snapshots are produced from the same
  `Profile::*()` constructors.** A change to one profile's tool list
  (e.g. promoting a tool from `power` to `admin`) re-blesses every
  snapshot that contains that tool — the `core`, `graph`, `admin`,
  `power`, and `full` snapshots are NOT independent; they overlap by
  construction. Asymmetric on-disk timestamps after a bless run are
  expected (the kernel only touches the file when bytes actually
  changed; profiles whose set was unaffected by the change retain
  their prior timestamp).
- **Bless from a clean working tree.** Re-running with
  `AI_MEMORY_BLESS_SNAPSHOTS=1` rewrites whichever file the test
  visits; running with a partial set of `--test` targets only
  re-blesses those targets.
- **Commit the regenerated snapshot files together** with the catalog
  change that motivated the re-bless. Reviewers cross-check the diff
  to verify the wire shape change matches the PR's documented intent.

## Why the timestamps may look asymmetric

If you observe `tools_list_admin.json` / `tools_list_core.json` /
`tools_list_graph.json` carrying an earlier mtime than
`tool_definitions_pre_d1_6.json` / `tools_list_full.json` /
`tools_list_power.json`, this is NOT a refresh-skipped bug — it's a
result of the bless-only-on-byte-change behaviour described above. The
authoritative source-of-truth is whether the tests pass:

```sh
cargo test --no-default-features --features sqlite-bundled \
    --test mcp_tools_list_snapshots
```

Five `ok` lines = every profile's wire shape matches its committed
snapshot. Mtimes are advisory only.
