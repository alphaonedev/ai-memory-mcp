// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0
//
//! #8604 pin: the tracked `CLAUDE.md` crossroads section must prescribe the
//! 1x3 vote (3-agent vote (6def5ab6)), never the superseded 5-agent shape.

use std::fs;
use std::path::PathBuf;

fn claude_md() -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("CLAUDE.md");
    fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

#[test]
fn crossroads_section_prescribes_the_1x3_vote_8604() {
    let text = claude_md();
    assert!(
        !text
            .lines()
            .any(|l| l.contains("5 concurrent `Agent` calls")),
        "CLAUDE.md must not prescribe 5 concurrent `Agent` calls"
    );
    assert!(
        text.contains("3-agent vote (6def5ab6)"),
        "CLAUDE.md must cite `3-agent vote (6def5ab6)`"
    );
    assert!(
        text.contains(
            "## Crossroads decision protocol — deterministic 1x3 adversarial vote \
             (operator-set 2026-06-18, shape amended 2026-10-10)"
        ),
        "crossroads section title must name the 1x3 shape and the 2026-10-10 amendment"
    );
    assert!(
        text.contains("history is not rewritten"),
        "crossroads section must state that historical 5-agent citations stand"
    );
}
