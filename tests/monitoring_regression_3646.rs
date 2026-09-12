// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0
//! #3646 regression: scope configuration must survive parsing, not disappear.
//! Uses only pre-existing APIs so the same test runs on the exact base.
#[test]
fn issue_3646_scope_configuration_is_not_silently_ignored() {
    let config: ai_memory::config::AppConfig =
        toml::from_str("[monitoring]\nagent_ids = ['ai:monitor']\npeer_ids = ['peer-monitor']\n")
            .unwrap();
    let value = serde_json::to_value(config).unwrap();
    assert_eq!(value["monitoring"]["agent_ids"][0], "ai:monitor");
    assert!(
        toml::from_str::<ai_memory::config::AppConfig>("[monitoring]\nagent_idz = ['typo']\n")
            .is_err()
    );
}
