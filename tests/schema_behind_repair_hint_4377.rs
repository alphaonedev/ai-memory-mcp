// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #4377 — the schema-behind repair hint must name a command THIS build's
//! real clap tree accepts.
//!
//! `SCHEMA_BEHIND_REPAIR` is printed by `doctor` (Storage,
//! `SCHEMA_BEHIND_READ_ONLY_REFUSAL`), `boot`, and the read-only open funnel.
//! It named `ai-memory migrate --in-place`, a flag `migrate` never had (and
//! the default build has no `migrate` at all), so the one repair the tool
//! printed at a one-way schema step was a usage error. Parsing the hint with
//! the real `Cli` keeps it from drifting from the CLI again.

use ai_memory::daemon_runtime::Cli;
use ai_memory::storage::schema_guard::SCHEMA_BEHIND_REPAIR;
use clap::Parser;

#[test]
fn schema_behind_repair_hint_parses_with_the_real_cli_4377() {
    let argv: Vec<&str> = SCHEMA_BEHIND_REPAIR.split_whitespace().collect();
    assert_eq!(
        argv.first().copied(),
        Some("ai-memory"),
        "the hint is a full command line: {SCHEMA_BEHIND_REPAIR}"
    );
    if let Err(e) = Cli::try_parse_from(&argv) {
        panic!("repair hint `{SCHEMA_BEHIND_REPAIR}` is not a command this build accepts: {e}");
    }
}
