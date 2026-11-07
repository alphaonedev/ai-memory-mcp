// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0
//
//! Pins the identity override classification (#8504) and shipped federation
//! attestation documentation (#8510), reading tracked prose at run time.

use std::fs;
use std::path::Path;

const ARCHITECTURE_REFERENCE: &str = "docs/reference/ARCHITECTURE_REFERENCE.md";
const ADMIN_GUIDE: &str = "docs/ADMIN_GUIDE.md";
const AGENT_ID_CELL: &str = "| `AI_MEMORY_AGENT_ID` |";
const AGENT_ID_CLASS: &str = "config (override-authority)";
const CLASS_COLUMN_INDEX: usize = 6;
const FIRST_LINE_NUMBER: usize = 1;
const SECRET_CLASS: &str = "secret";
const STALE_ATTESTATION: &str = "not yet attested (issue #238)";

fn read_doc(relative: &str) -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(relative);
    fs::read_to_string(&path).unwrap_or_else(|error| panic!("read {relative}: {error}"))
}

#[test]
fn agent_id_is_config_with_override_authority_8504() {
    let text = read_doc(ARCHITECTURE_REFERENCE);
    let mut rows = text
        .lines()
        .enumerate()
        .filter(|(_, line)| line.contains(AGENT_ID_CELL));
    let (index, row) = rows
        .next()
        .unwrap_or_else(|| panic!("{ARCHITECTURE_REFERENCE}: missing {AGENT_ID_CELL} row"));
    let line_number = index + FIRST_LINE_NUMBER;
    assert!(
        rows.next().is_none(),
        "{ARCHITECTURE_REFERENCE}:{line_number}: duplicate {AGENT_ID_CELL} row: {row}"
    );
    let class = row.split('|').nth(CLASS_COLUMN_INDEX).map(str::trim);
    assert_eq!(
        class,
        Some(AGENT_ID_CLASS),
        "{ARCHITECTURE_REFERENCE}:{line_number}: expected {AGENT_ID_CLASS}: {row}"
    );
    assert!(
        !row.contains(SECRET_CLASS),
        "{ARCHITECTURE_REFERENCE}:{line_number}: agent attribution is echoed: {row}"
    );
}

#[test]
fn admin_guide_does_not_claim_sender_is_unattested_8510() {
    let text = read_doc(ADMIN_GUIDE);
    for (index, line) in text.lines().enumerate() {
        let line_number = index + FIRST_LINE_NUMBER;
        assert!(
            !line.contains(STALE_ATTESTATION),
            "{ADMIN_GUIDE}:{line_number}: obsolete federation claim: {line}"
        );
    }
}
