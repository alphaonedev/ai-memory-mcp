// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! Compile-time feature self-report (#2676 / Gate 3 packaging).
//!
//! Gate 3 measurement and provision must assert the binary's **compiled**
//! feature set, not merely `--version` success. Silent wrong-store /
//! missing-feature false-success is not the certified posture (handoff
//! §Tier 0 remainder).
//!
//! Every flag listed in `Cargo.toml` `[features]` (except the meta
//! `default` composition) is reported when compiled in. Zero-cost when
//! a feature is off — the `cfg` strips the token from the table.

/// Stable, sorted list of cargo features compiled into this binary.
///
/// Order is alphabetical so stdout/JSON is byte-stable across rebuilds
/// of the same feature set. Does **not** include the meta `default`
/// feature name — only leaf flags that change code generation.
#[must_use]
pub fn compiled_features() -> &'static [&'static str] {
    // Keep alphabetical. Adding a Cargo.toml feature requires a row here
    // (and a `cfg(feature=…)` consumer already required by arch-11).
    const FEATURES: &[&str] = &[
        #[cfg(feature = "e2e")]
        "e2e",
        #[cfg(feature = "fs-notify")]
        "fs-notify",
        #[cfg(feature = "sal")]
        "sal",
        #[cfg(feature = "sal-postgres")]
        "sal-postgres",
        #[cfg(feature = "sqlcipher")]
        "sqlcipher",
        #[cfg(feature = "sqlite-bundled")]
        "sqlite-bundled",
        #[cfg(feature = "syslog")]
        "syslog",
        #[cfg(feature = "test-with-models")]
        "test-with-models",
        #[cfg(feature = "vectorlite")]
        "vectorlite",
    ];
    FEATURES
}

/// Human + machine report lines for CLI / provision.
///
/// When `json` is true, emits a single JSON object:
/// `{"version":"…","features":[…]}`.
/// Otherwise emits two lines: `version: …` and `features: a,b,c` (or
/// `features: (none)` when the table is empty — should not happen on
/// default builds that always include `sqlite-bundled`).
#[must_use]
pub fn features_report(json: bool) -> String {
    let version = env!("CARGO_PKG_VERSION");
    let feats = compiled_features();
    if json {
        let list = feats
            .iter()
            .map(|f| format!("\"{f}\""))
            .collect::<Vec<_>>()
            .join(",");
        format!(r#"{{"version":"{version}","features":[{list}]}}"#)
    } else {
        let list = if feats.is_empty() {
            "(none)".to_string()
        } else {
            feats.join(",")
        };
        format!("version: {version}\nfeatures: {list}\n")
    }
}

/// True when `name` is among the compiled features (exact match).
#[must_use]
pub fn has_feature(name: &str) -> bool {
    compiled_features().iter().any(|f| *f == name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_build_reports_sqlite_bundled_2676() {
        // Default features = ["sqlite-bundled"]. Gate 3 / provision must
        // see at least this leaf so a stripped build cannot pretend.
        assert!(
            has_feature("sqlite-bundled"),
            "default binary must self-report sqlite-bundled; got {:?}",
            compiled_features()
        );
    }

    #[test]
    fn features_list_is_sorted_unique_2676() {
        let f = compiled_features();
        let mut sorted = f.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(
            f,
            sorted.as_slice(),
            "compiled_features must be sorted unique"
        );
    }

    #[test]
    fn features_report_human_and_json_roundtrip_shape_2676() {
        let human = features_report(false);
        assert!(human.contains("version:"), "{human}");
        assert!(human.contains("features:"), "{human}");
        assert!(human.contains(env!("CARGO_PKG_VERSION")), "{human}");

        let j = features_report(true);
        assert!(j.starts_with('{'), "{j}");
        assert!(j.contains("\"version\""), "{j}");
        assert!(j.contains("\"features\""), "{j}");
        assert!(j.contains(env!("CARGO_PKG_VERSION")), "{j}");
    }

    #[cfg(feature = "sal-postgres")]
    #[test]
    fn sal_postgres_build_reports_sal_chain_2676() {
        assert!(has_feature("sal"), "sal-postgres implies sal");
        assert!(has_feature("sal-postgres"));
    }
}
