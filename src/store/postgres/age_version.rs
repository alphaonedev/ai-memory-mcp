// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 #3756 — the ONE comparator that judges an installed Apache AGE
//! `extversion` against the certified substrate.
//!
//! ## Why this exists
//!
//! `ai-memory doctor` read the AGE version and DISPLAYED it; nothing compared
//! it to the tested floor, and `serve` booted silently on any version. On AGE
//! 1.5.0 the graph projection loses an edge's temporal validity (the
//! `MERGE … SET` shape is not persisted on the CREATE branch), so
//! `kg_timeline` omits an edge `kg_query` confirms — two answers from one
//! store, and a green doctor. 1.5.0 is an UNSUPPORTED substrate (the ruling
//! on #3756), so the substrate's job is to SAY so: RED in doctor with the
//! named remedy, one WARN at `serve` boot, never a boot refusal.
//!
//! ## The constants mirror the SSOT
//!
//! [`AGE_VERSION_CANONICAL`] mirrors `EXPECTED_AGE_VERSION` in
//! `deploy/docker-1461/provision/lib.sh` (the certified pin; the
//! `cert-postgres-age` lane refuses to certify any other) and
//! [`AGE_VERSION_FLOOR`] mirrors the tested alternate matrix
//! (`infra/lan-parity-test/Dockerfile.pg-age-vector`, PG 16 + AGE 1.6.0).
//! `scripts/check-docs-vs-ssot.sh` binds both to those files so the two
//! cannot drift apart silently.
//!
//! The comparator is PURE (a string in, a verdict out) so the doctor cell and
//! the boot WARN are unit-testable without a live cluster of any version.

use std::fmt;

/// The certified Apache AGE `extversion` — mirrors `EXPECTED_AGE_VERSION`
/// (`deploy/docker-1461/provision/lib.sh`).
pub const AGE_VERSION_CANONICAL: &str = "1.8.0";

/// The tested floor — the alternate matrix's AGE (`infra/lan-parity-test`,
/// PG 16 + AGE 1.6.0). Anything below it is an unsupported substrate.
pub const AGE_VERSION_FLOOR: &str = "1.6.0";

/// The `tracing` target of the boot WARN so an operator can filter it.
pub const AGE_VERSION_TRACE_TARGET: &str = "store::postgres::age_version";

/// Doctor / boot wording for a version below the floor. `{version}`,
/// `{floor}` and `{canonical}` are filled by [`age_version_remedy`].
const MSG_AGE_BELOW_FLOOR: &str = "Apache AGE {version} is below the tested floor {floor}: the \
     knowledge-graph projection does not persist edge validity on it, so \
     kg_timeline can omit an edge kg_query returns (#3756 — an unsupported \
     substrate). Upgrade the extension to the canonical pin {canonical} \
     (install the {canonical} package, then `ALTER EXTENSION age UPDATE TO \
     '{canonical}'`, or rebuild from deploy/docker-1461/Dockerfile.pg-age-vector)";

/// Doctor / boot wording for an `extversion` the comparator cannot parse.
const MSG_AGE_UNPARSEABLE: &str = "Apache AGE reports extversion {version:?}, which is not a \
     `major.minor.patch` version, so its posture cannot be judged (#3756). \
     Install the canonical pin {canonical} (deploy/docker-1461/provision/lib.sh \
     EXPECTED_AGE_VERSION) so the doctor can vouch for the graph substrate";

/// Doctor wording for a version at or above the floor that is not the
/// canonical pin.
const MSG_AGE_TESTED_ALTERNATE: &str = "Apache AGE {version} is at or above the tested floor {floor} \
     but is not the canonical pin {canonical}; {floor} is the tested \
     alternate matrix (PG 16, infra/lan-parity-test), any other version in \
     this band is untested by the certification lane (#3756)";

/// The verdict on an installed AGE `extversion`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AgeVersionVerdict {
    /// Exactly [`AGE_VERSION_CANONICAL`] — GREEN.
    Canonical,
    /// At or above [`AGE_VERSION_FLOOR`] but not the canonical pin — YELLOW.
    /// The floor itself is the tested alternate matrix; anything else in the
    /// band is untested-above-floor and the note says which.
    TestedAlternate,
    /// Below [`AGE_VERSION_FLOOR`] — RED, an unsupported substrate.
    BelowFloor,
    /// Not a `major.minor.patch` string — RED, because a version the
    /// comparator cannot read is a version nobody can vouch for.
    Unparseable,
}

impl AgeVersionVerdict {
    /// Stable lowercase label for the doctor fact row.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Canonical => "canonical",
            Self::TestedAlternate => "tested_alternate",
            Self::BelowFloor => "below_floor",
            Self::Unparseable => "unparseable",
        }
    }

    /// `true` for the two RED verdicts — the ones that warn at boot.
    #[must_use]
    pub const fn is_red(self) -> bool {
        matches!(self, Self::BelowFloor | Self::Unparseable)
    }
}

impl fmt::Display for AgeVersionVerdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

/// Parse `major.minor.patch` (surrounding whitespace tolerated, nothing else:
/// no pre-release tag, no missing component — `pg_extension.extversion` for
/// the pgdg packages is exactly three components).
fn parse_semver_triple(raw: &str) -> Option<(u64, u64, u64)> {
    let mut parts = raw.trim().split('.');
    let major = parts.next()?.parse::<u64>().ok()?;
    let minor = parts.next()?.parse::<u64>().ok()?;
    let patch = parts.next()?.parse::<u64>().ok()?;
    if parts.next().is_some() {
        return None;
    }
    Some((major, minor, patch))
}

/// A constant the module pins must parse; the unit tests assert both do.
fn parse_pinned(pin: &str) -> (u64, u64, u64) {
    parse_semver_triple(pin).expect("the AGE version pins are `major.minor.patch` by construction")
}

/// The comparator: judge `extversion` against the floor and the canonical
/// pin. Pure; never reads the environment.
#[must_use]
pub fn age_version_verdict(extversion: &str) -> AgeVersionVerdict {
    let Some(version) = parse_semver_triple(extversion) else {
        return AgeVersionVerdict::Unparseable;
    };
    if version == parse_pinned(AGE_VERSION_CANONICAL) {
        return AgeVersionVerdict::Canonical;
    }
    if version < parse_pinned(AGE_VERSION_FLOOR) {
        return AgeVersionVerdict::BelowFloor;
    }
    AgeVersionVerdict::TestedAlternate
}

/// The operator-facing note for a non-GREEN verdict: the named remedy on
/// RED, the explanation on YELLOW, `None` on GREEN. Shared by the doctor
/// section and the boot WARN so the two surfaces say the same thing.
#[must_use]
pub fn age_version_remedy(extversion: &str, verdict: AgeVersionVerdict) -> Option<String> {
    let template = match verdict {
        AgeVersionVerdict::Canonical => return None,
        AgeVersionVerdict::TestedAlternate => MSG_AGE_TESTED_ALTERNATE,
        AgeVersionVerdict::BelowFloor => MSG_AGE_BELOW_FLOOR,
        AgeVersionVerdict::Unparseable => MSG_AGE_UNPARSEABLE,
    };
    Some(
        template
            .replace("{version:?}", &format!("{:?}", extversion.trim()))
            .replace("{version}", extversion.trim())
            .replace("{floor}", AGE_VERSION_FLOOR)
            .replace("{canonical}", AGE_VERSION_CANONICAL),
    )
}

/// The ONE line `serve` logs at boot below the floor (or on an unparseable
/// version); `None` for every verdict that is not RED. No boot refusal under
/// the freeze — the doctor is the operator's instrument.
#[must_use]
pub fn age_version_boot_warning(extversion: &str) -> Option<String> {
    let verdict = age_version_verdict(extversion);
    if !verdict.is_red() {
        return None;
    }
    age_version_remedy(extversion, verdict)
}

#[cfg(test)]
mod tests {
    use super::{
        AGE_VERSION_CANONICAL, AGE_VERSION_FLOOR, AgeVersionVerdict, age_version_boot_warning,
        age_version_remedy, age_version_verdict, parse_semver_triple,
    };

    /// The pins themselves parse and are ordered (floor below canonical) —
    /// the precondition every other cell rests on.
    #[test]
    fn the_pins_parse_and_the_floor_is_below_the_canonical_3756() {
        let floor = parse_semver_triple(AGE_VERSION_FLOOR).expect("floor parses");
        let canonical = parse_semver_triple(AGE_VERSION_CANONICAL).expect("canonical parses");
        assert!(
            floor < canonical,
            "floor {floor:?} must sit below canonical {canonical:?}"
        );
        assert_eq!(
            age_version_verdict(AGE_VERSION_CANONICAL),
            AgeVersionVerdict::Canonical
        );
        assert_eq!(
            age_version_verdict(AGE_VERSION_FLOOR),
            AgeVersionVerdict::TestedAlternate
        );
    }

    /// The comparator table the ruling names: 1.5.0 → BelowFloor, 1.6.0 →
    /// TestedAlternate, 1.8.0 → Canonical, garbage → Unparseable.
    #[test]
    fn comparator_table_3756() {
        let table: [(&str, AgeVersionVerdict); 12] = [
            ("1.5.0", AgeVersionVerdict::BelowFloor),
            ("1.0.0", AgeVersionVerdict::BelowFloor),
            ("0.9.9", AgeVersionVerdict::BelowFloor),
            ("1.6.0", AgeVersionVerdict::TestedAlternate),
            ("1.7.0", AgeVersionVerdict::TestedAlternate),
            ("1.9.0", AgeVersionVerdict::TestedAlternate),
            ("2.0.0", AgeVersionVerdict::TestedAlternate),
            ("1.8.0", AgeVersionVerdict::Canonical),
            (" 1.8.0\n", AgeVersionVerdict::Canonical),
            ("garbage", AgeVersionVerdict::Unparseable),
            ("1.8", AgeVersionVerdict::Unparseable),
            ("1.8.0~rc0", AgeVersionVerdict::Unparseable),
        ];
        for (raw, want) in table {
            assert_eq!(age_version_verdict(raw), want, "extversion {raw:?}");
        }
        assert_eq!(
            age_version_verdict(""),
            AgeVersionVerdict::Unparseable,
            "empty"
        );
        assert_eq!(
            age_version_verdict("1.8.0.1"),
            AgeVersionVerdict::Unparseable,
            "a fourth component is not a version we vouch for"
        );
    }

    /// The RED remedy names the version, the floor and the canonical pin —
    /// the operator must not have to look any of them up.
    #[test]
    fn below_floor_remedy_names_version_floor_and_canonical_3756() {
        let note =
            age_version_remedy("1.5.0", AgeVersionVerdict::BelowFloor).expect("RED carries a note");
        for needle in [
            "1.5.0",
            AGE_VERSION_FLOOR,
            AGE_VERSION_CANONICAL,
            "#3756",
            "ALTER EXTENSION age",
        ] {
            assert!(note.contains(needle), "remedy must name {needle:?}: {note}");
        }
        assert!(
            !note.contains('{'),
            "every placeholder must be filled: {note}"
        );
    }

    /// Garbage is RED too, and its note quotes the raw value so the operator
    /// sees what the catalog actually returned.
    #[test]
    fn unparseable_remedy_quotes_the_raw_value_3756() {
        let note = age_version_remedy("garbage", AgeVersionVerdict::Unparseable)
            .expect("RED carries a note");
        assert!(
            note.contains("\"garbage\""),
            "the raw value is quoted: {note}"
        );
        assert!(
            note.contains(AGE_VERSION_CANONICAL),
            "names the canonical pin: {note}"
        );
        assert!(
            !note.contains('{'),
            "every placeholder must be filled: {note}"
        );
    }

    /// GREEN carries no note; YELLOW explains without a remedy verb.
    #[test]
    fn canonical_has_no_note_and_alternate_explains_3756() {
        assert_eq!(
            age_version_remedy("1.8.0", AgeVersionVerdict::Canonical),
            None
        );
        let note = age_version_remedy("1.6.0", AgeVersionVerdict::TestedAlternate)
            .expect("YELLOW carries a note");
        assert!(note.contains("tested alternate matrix"), "{note}");
        assert!(note.contains(AGE_VERSION_CANONICAL), "{note}");
        assert!(
            !note.contains('{'),
            "every placeholder must be filled: {note}"
        );
    }

    /// The boot WARN fires ONLY on the two RED verdicts.
    #[test]
    fn boot_warning_only_below_floor_or_unparseable_3756() {
        assert!(
            age_version_boot_warning("1.5.0").is_some(),
            "below floor warns"
        );
        assert!(
            age_version_boot_warning("garbage").is_some(),
            "unparseable warns"
        );
        assert_eq!(
            age_version_boot_warning("1.6.0"),
            None,
            "alternate does not warn at boot"
        );
        assert_eq!(
            age_version_boot_warning("1.8.0"),
            None,
            "canonical does not warn"
        );
    }

    /// The labels are stable wire/report tokens.
    #[test]
    fn labels_are_stable_3756() {
        assert_eq!(AgeVersionVerdict::Canonical.label(), "canonical");
        assert_eq!(
            AgeVersionVerdict::TestedAlternate.label(),
            "tested_alternate"
        );
        assert_eq!(AgeVersionVerdict::BelowFloor.label(), "below_floor");
        assert_eq!(AgeVersionVerdict::Unparseable.label(), "unparseable");
        assert!(AgeVersionVerdict::BelowFloor.is_red());
        assert!(AgeVersionVerdict::Unparseable.is_red());
        assert!(!AgeVersionVerdict::TestedAlternate.is_red());
        assert!(!AgeVersionVerdict::Canonical.is_red());
    }
}
