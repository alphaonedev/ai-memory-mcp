// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #4356 — the ancestor-owner gate on the FIRST bind of a namespace standard.
//!
//! An ancestor's standard governs its `/`-subtree by inheritance; the only
//! written way out is a child binding its own standard (most-specific wins).
//! Before #4356 nothing authorized THAT act: the bind gates (#929 / #2541 /
//! #2542 / #3758) judged the bound memory, the declared parent and the
//! standard CURRENTLY bound to the target, and a target with no binding of its
//! own (`NoMetaRow`) was admitted unconditionally — so any caller could open a
//! permissive child standard under a governed ancestor and strip the
//! ancestor's write / promote / delete / approval gates from that subtree
//! (CWE-284 / CWE-863, both backends).
//!
//! 5-agent vote (4d3ea1c5), unanimous option A: binding the first standard (or
//! repairing a severed binding: #3758 admits a SET on an unresolvable pointer
//! as the repair path, and this gate then decides it) under a governed
//! ancestor requires the caller to be the owner of the NEAREST governing
//! ancestor's standard. This
//! module is the ONE backend-blind verdict; each backend contributes only a
//! reader that yields [`AncestorLevel`]s and the shared selector
//! [`select_governing_ancestor`] picks the deciding one, so the two adapters
//! cannot classify the same chain differently (the #2488 lesson).
//!
//! Corrupt ancestor metadata (#4356 CR1): the deciding level is classified
//! from the stored metadata by the shared #4285 classifier
//! (`crate::storage::classify_standard_metadata_value` / `_text`: not JSON,
//! not an object, or a `governance` blob that fails the typed deserialise is
//! corrupt); this module only ADDS the owner dimension (a non-string
//! `agent_id` is corrupt too). A corrupt level is [`AncestorLevel::Severed`]
//! and refuses every non-bypass first bind below it, on both backends.
//!
//! Race safety (#4023/#4447 TOCTOU class): every funnel re-reads the chain
//! inside the bind's own write transaction. On sqlite that transaction is
//! `BEGIN IMMEDIATE` (one writer); on postgres the bind first takes the
//! transaction-scoped advisory lock [`PG_STANDARD_BIND_LOCK_KEY`], so a
//! concurrent ancestor bind is either committed before the child's chain read
//! or ordered after the child's bind, never interleaved.
//!
//! Deliberately NOT gated (vote rulings): the global `*` standard (a
//! substrate default, not a subtree — and gating it would make every first
//! bind anywhere depend on the `*` owner, breaking the allow-on-silence
//! cutline); the federated `namespace_meta` lanes (own #2479 peer-scope gate);
//! pending-queue delegation (no precedent; a follow-up).

use crate::visibility::{
    NamespaceStandardBinding, NamespaceStandardOp, NamespaceStandardRefusal,
    namespace_standard_mutation_admission,
};

/// What ONE ancestor level contributes to the gate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AncestorLevel {
    /// No `namespace_meta` row — keep walking.
    Absent,
    /// A bound standard that carries no `metadata.governance` — it does not
    /// shadow a governed grandparent (bypass-voter amendment a).
    NoPolicy,
    /// A row whose standard is severed (NULL pointer) or dangling —
    /// somebody governed this and the policy is gone (#2503): fail closed.
    Severed,
    /// A bound standard carrying `metadata.governance`. `owner` is the
    /// standard's `metadata.agent_id`, normalised (`None` = unowned).
    Governing {
        /// The concrete owner, or `None` when empty / `system` / absent.
        owner: Option<String>,
    },
}

/// The nearest ancestor that decides the gate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GoverningAncestor {
    /// No governing ancestor — the target is an ungoverned root (allow-on-silence).
    None,
    /// A governed ancestor; `owner` `None` = unowned (documented unowned-PASS).
    Standard {
        /// The concrete owner, or `None` when unowned.
        owner: Option<String>,
    },
    /// The nearest governed level is severed / dangling.
    Severed,
}

/// Why [`set_admission`] refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SetRefusal {
    /// The caller does not own the standard currently bound, or does not own
    /// the governing ancestor's standard.
    NotOwner,
    /// The governing ancestor's standard is severed / dangling.
    AncestorUnresolvable,
    /// A read fault while resolving the binding or the ancestor (fail-closed).
    Unverifiable,
}

/// Wire-pinned refusal text for [`SetRefusal::AncestorUnresolvable`].
pub const REASON_ANCESTOR_STANDARD_UNRESOLVABLE: &str = "cannot bind a namespace standard under a governed ancestor whose standard is \
     unresolvable (severed or dangling). Ask the ancestor's owner or an operator.";

/// Wire-pinned refusal text for [`SetRefusal::Unverifiable`].
pub const REASON_STANDARD_UNVERIFIABLE: &str = "cannot verify the namespace-standard owner chain; refusing the bind rather than \
     treating the standard as unowned";

/// #4356 — the postgres transaction-scoped advisory-lock key every
/// namespace-standard SET takes before it reads the binding and the ancestor
/// chain (single key, so trivially deadlock-free, CONCURRENCY-04). Public so
/// the race cell can stand in for an in-flight bind with the same lock.
pub const PG_STANDARD_BIND_LOCK_KEY: &str = "ai_memory:namespace_meta:standard_bind";

/// #4356 CR1 — what a bound standard's stored metadata contributes to the
/// gate. The corrupt / no-policy / policy partition is DELEGATED to the #4285
/// classifier (`classify_standard_metadata_value`) so the two cannot drift;
/// this adds only the owner: a governing standard's owner is
/// `metadata.agent_id` (absent / `null` / empty / `system` is unowned; a
/// non-string `agent_id` is corrupt, Severed, never "unowned" — stricter than
/// #4285, fail closed). Corrupt (not JSON, not an object, or a `governance`
/// blob failing the typed deserialise) is [`AncestorLevel::Severed`]; a
/// `governance` key absent or JSON `null` is [`AncestorLevel::NoPolicy`].
#[must_use]
pub fn classify_standard_metadata(metadata: &serde_json::Value) -> AncestorLevel {
    use crate::storage::{StandardMetadata, classify_standard_metadata_value};
    match classify_standard_metadata_value(metadata) {
        StandardMetadata::Corrupt(_) => AncestorLevel::Severed,
        StandardMetadata::NoGovernance => AncestorLevel::NoPolicy,
        StandardMetadata::Policy(..) => match metadata.get(crate::mcp::param_names::AGENT_ID) {
            None | Some(serde_json::Value::Null) => AncestorLevel::Governing { owner: None },
            Some(serde_json::Value::String(o)) => AncestorLevel::Governing {
                owner: normalise_owner(Some(o.clone())),
            },
            Some(_) => AncestorLevel::Severed,
        },
    }
}

/// [`classify_standard_metadata`] over the RAW stored text (the sqlite
/// column): the shared #4285 text classifier decides corrupt vs no-policy;
/// unparseable text is corrupt ([`AncestorLevel::Severed`]) — the lenient row
/// mapper would read it as `{}` ("no policy") and fail open.
#[must_use]
pub fn classify_standard_metadata_text(raw: &str) -> AncestorLevel {
    use crate::storage::{StandardMetadata, classify_standard_metadata_text as shared};
    match shared(raw) {
        StandardMetadata::Corrupt(_) => AncestorLevel::Severed,
        StandardMetadata::NoGovernance => AncestorLevel::NoPolicy,
        // Policy: parse once more for the owner (the shared Policy variant
        // carries only the governance blob).
        StandardMetadata::Policy(..) => serde_json::from_str::<serde_json::Value>(raw)
            .map_or(AncestorLevel::Severed, |v| classify_standard_metadata(&v)),
    }
}

/// Normalise a standard's owner: empty / `system` / absent = unowned.
#[must_use]
pub fn normalise_owner(owner: Option<String>) -> Option<String> {
    owner.filter(|o| !o.is_empty() && o != crate::identity::sentinels::SYSTEM_PRINCIPAL)
}

/// Pick the deciding ancestor from levels ordered NEAREST-FIRST (the target
/// itself and `*` already excluded by the caller). A fault on a level before
/// the decision propagates (fail-closed).
///
/// # Errors
///
/// The first reader error encountered before a deciding level.
pub fn select_governing_ancestor<E>(
    levels: impl IntoIterator<Item = Result<AncestorLevel, E>>,
) -> Result<GoverningAncestor, E> {
    for level in levels {
        match level? {
            AncestorLevel::Absent | AncestorLevel::NoPolicy => {}
            AncestorLevel::Severed => return Ok(GoverningAncestor::Severed),
            AncestorLevel::Governing { owner } => {
                return Ok(GoverningAncestor::Standard { owner });
            }
        }
    }
    Ok(GoverningAncestor::None)
}

/// Whether the ancestor must be consulted: a bind that creates (or repairs)
/// the target's OWN binding, AND (#4499, GOD ruling) a rebind of an UNOWNED
/// standard (owner absent, empty or `system`). #3758 lets anyone rebind an
/// unowned standard; that unowned-PASS holds only where NO owned governing
/// ancestor exists, so under one the ancestor's owner decides exactly as for
/// a first bind. A rebind of an OWNED standard is decided by its current
/// owner (#3758) alone.
#[must_use]
pub fn needs_ancestor(binding: &NamespaceStandardBinding) -> bool {
    match binding {
        NamespaceStandardBinding::NoMetaRow | NamespaceStandardBinding::Unresolvable => true,
        NamespaceStandardBinding::Resolved(owner) => normalise_owner(owner.clone()).is_none(),
    }
}

/// The ONE verdict for binding a namespace standard (SET): the #3758 rebind
/// gate first, then — for a first bind / repair — the #4356 ancestor gate.
///
/// # Errors
///
/// [`SetRefusal`].
pub fn set_admission(
    caller: &str,
    bypass: bool,
    namespace: &str,
    binding: &NamespaceStandardBinding,
    ancestor: &GoverningAncestor,
) -> Result<(), SetRefusal> {
    if bypass {
        return Ok(());
    }
    namespace_standard_mutation_admission(
        caller,
        false,
        namespace,
        binding,
        NamespaceStandardOp::Set,
    )
    .map_err(|r| match r {
        NamespaceStandardRefusal::NotOwner | NamespaceStandardRefusal::Unresolvable => {
            SetRefusal::NotOwner
        }
    })?;
    if !needs_ancestor(binding) {
        return Ok(());
    }
    match ancestor {
        GoverningAncestor::None | GoverningAncestor::Standard { owner: None } => Ok(()),
        GoverningAncestor::Standard { owner: Some(o) } if o == caller => Ok(()),
        GoverningAncestor::Standard { owner: Some(_) } => {
            tracing::warn!(
                target: crate::handlers::AUTHZ_TRACE_TARGET,
                "namespace-standard ancestor-owner refusal: first bind or unowned rebind on {namespace}: caller {caller} does not own the governing ancestor standard"
            );
            Err(SetRefusal::NotOwner)
        }
        GoverningAncestor::Severed => Err(SetRefusal::AncestorUnresolvable),
    }
}

/// The caller-facing reason for a refusal (never names the owner, #3407).
#[must_use]
pub fn refusal_reason(refusal: SetRefusal) -> &'static str {
    match refusal {
        SetRefusal::NotOwner => crate::errors::msg::CALLER_DOES_NOT_OWN_NAMESPACE_STANDARD,
        SetRefusal::AncestorUnresolvable => REASON_ANCESTOR_STANDARD_UNRESOLVABLE,
        SetRefusal::Unverifiable => REASON_STANDARD_UNVERIFIABLE,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn gov(o: Option<&str>) -> GoverningAncestor {
        GoverningAncestor::Standard {
            owner: o.map(str::to_string),
        }
    }

    #[test]
    fn stranger_first_bind_under_owned_ancestor_refused_4356() {
        let r = set_admission(
            "s",
            false,
            "gov/leaf",
            &NamespaceStandardBinding::NoMetaRow,
            &gov(Some("a")),
        );
        assert_eq!(r, Err(SetRefusal::NotOwner));
    }

    #[test]
    fn owner_unowned_root_bypass_and_rebind_pass_4356() {
        let nm = NamespaceStandardBinding::NoMetaRow;
        assert!(set_admission("a", false, "gov/leaf", &nm, &gov(Some("a"))).is_ok());
        assert!(set_admission("s", false, "gov/leaf", &nm, &gov(None)).is_ok());
        assert!(set_admission("s", false, "root", &nm, &GoverningAncestor::None).is_ok());
        assert!(set_admission("s", true, "gov/leaf", &nm, &gov(Some("a"))).is_ok());
        // rebind of a standard the caller owns never consults the ancestor
        let own = NamespaceStandardBinding::Resolved(Some("s".into()));
        assert!(set_admission("s", false, "gov/leaf", &own, &gov(Some("a"))).is_ok());
    }

    #[test]
    fn severed_ancestor_and_unresolvable_repair_fail_closed_4356() {
        let nm = NamespaceStandardBinding::NoMetaRow;
        assert_eq!(
            set_admission("s", false, "gov/leaf", &nm, &GoverningAncestor::Severed),
            Err(SetRefusal::AncestorUnresolvable)
        );
        let un = NamespaceStandardBinding::Unresolvable;
        assert_eq!(
            set_admission("s", false, "gov/leaf", &un, &gov(Some("a"))),
            Err(SetRefusal::NotOwner)
        );
    }

    #[test]
    fn selector_skips_nopolicy_and_picks_nearest_decider_4356() {
        let lv: Vec<Result<AncestorLevel, ()>> = vec![
            Ok(AncestorLevel::Absent),
            Ok(AncestorLevel::NoPolicy),
            Ok(AncestorLevel::Governing {
                owner: Some("a".into()),
            }),
            Ok(AncestorLevel::Severed),
        ];
        assert_eq!(select_governing_ancestor(lv), Ok(gov(Some("a"))));
        let lv: Vec<Result<AncestorLevel, ()>> = vec![Ok(AncestorLevel::Absent)];
        assert_eq!(select_governing_ancestor(lv), Ok(GoverningAncestor::None));
        let lv: Vec<Result<AncestorLevel, &str>> = vec![Err("fault")];
        assert_eq!(select_governing_ancestor(lv), Err("fault"));
    }

    /// #4356 N1: #3758 admits a SET on an unresolvable pointer (the repair
    /// path); the ancestor gate then decides it, so the governing ancestor's
    /// owner may repair and nobody else may.
    #[test]
    fn severed_target_repair_is_decided_by_the_ancestor_owner_4356() {
        let un = NamespaceStandardBinding::Unresolvable;
        assert!(set_admission("a", false, "gov/leaf", &un, &gov(Some("a"))).is_ok());
        assert_eq!(
            set_admission("s", false, "gov/leaf", &un, &gov(Some("a"))),
            Err(SetRefusal::NotOwner)
        );
    }

    /// #4356: owner match is EXACT (no case folding, no pid-suffix prefix match).
    #[test]
    fn owner_match_is_exact_4356() {
        let nm = NamespaceStandardBinding::NoMetaRow;
        for near in ["A", "a:pid-1", "a ", " a"] {
            assert_eq!(
                set_admission(near, false, "gov/leaf", &nm, &gov(Some("a"))),
                Err(SetRefusal::NotOwner),
                "{near:?}"
            );
        }
    }

    /// #4356 CR1: the corrupt shapes classify Severed, never `NoPolicy`.
    #[test]
    fn corrupt_metadata_classifies_severed_4356() {
        for raw in [
            "[]",
            r#""x""#,
            "7",
            "null",
            "{not json",
            r#"{"governance":{"write":42}}"#,
            r#"{"governance":"owner"}"#,
            r#"{"governance":{"write":"owner"},"agent_id":7}"#,
        ] {
            assert_eq!(
                classify_standard_metadata_text(raw),
                AncestorLevel::Severed,
                "{raw}"
            );
        }
        assert_eq!(
            classify_standard_metadata_text(r#"{"agent_id":"a"}"#),
            AncestorLevel::NoPolicy
        );
        assert_eq!(
            classify_standard_metadata_text(r#"{"agent_id":"a","governance":null}"#),
            AncestorLevel::NoPolicy
        );
        assert_eq!(
            classify_standard_metadata_text(r#"{"agent_id":"a","governance":{"write":"any"}}"#),
            AncestorLevel::Governing {
                owner: Some("a".into())
            }
        );
        for unowned in [
            r#"{"governance":{"write":"any"}}"#,
            r#"{"agent_id":null,"governance":{"write":"any"}}"#,
            r#"{"agent_id":"system","governance":{"write":"any"}}"#,
            r#"{"agent_id":"","governance":{"write":"any"}}"#,
        ] {
            assert_eq!(
                classify_standard_metadata_text(unowned),
                AncestorLevel::Governing { owner: None },
                "{unowned}"
            );
        }
    }

    /// #4499: a rebind of an UNOWNED standard under an OWNED governing
    /// ancestor needs that ancestor's owner; with no owned ancestor (none, or
    /// an unowned one) the #3758 unowned-PASS still admits anyone.
    #[test]
    fn unowned_rebind_under_an_owned_ancestor_needs_its_owner_4499() {
        for unowned in [
            NamespaceStandardBinding::Resolved(None),
            NamespaceStandardBinding::Resolved(Some(String::new())),
            NamespaceStandardBinding::Resolved(Some("system".into())),
        ] {
            assert!(needs_ancestor(&unowned));
            assert_eq!(
                set_admission("s", false, "gov/leaf", &unowned, &gov(Some("a"))),
                Err(SetRefusal::NotOwner)
            );
            assert!(set_admission("a", false, "gov/leaf", &unowned, &gov(Some("a"))).is_ok());
            assert!(set_admission("s", false, "root", &unowned, &GoverningAncestor::None).is_ok());
            assert!(set_admission("s", false, "gov/leaf", &unowned, &gov(None)).is_ok());
            assert_eq!(
                set_admission(
                    "s",
                    false,
                    "gov/leaf",
                    &unowned,
                    &GoverningAncestor::Severed
                ),
                Err(SetRefusal::AncestorUnresolvable)
            );
        }
        // An OWNED standard's rebind stays the current owner's call (#3758).
        let owned = NamespaceStandardBinding::Resolved(Some("c".into()));
        assert!(!needs_ancestor(&owned));
        assert!(set_admission("c", false, "gov/leaf", &owned, &gov(Some("a"))).is_ok());
    }

    /// #4713 — the descendant-side twin of the #4356 ancestor gate: a FIRST
    /// bind (or unowned rebind) at `root` is refused when another principal
    /// already owns a bound `root/proj` below it; the owner of every
    /// governing descendant, an unowned or policy-less descendant, and the
    /// operator bypass pass; a severed descendant fails closed.
    #[test]
    fn foreign_owned_descendant_refuses_a_first_bind_above_it_4713() {
        let governing = |o: Option<&str>| AncestorLevel::Governing {
            owner: o.map(str::to_string),
        };
        let ok = |levels: Vec<AncestorLevel>| -> Vec<Result<AncestorLevel, ()>> {
            levels.into_iter().map(Ok).collect()
        };
        // B owns root/proj; X first-binds root.
        assert_eq!(
            select_governing_descendant("x", ok(vec![governing(Some("b"))])),
            Ok(DescendantLevel::ForeignOwned)
        );
        // B binds root above its own root/proj.
        assert_eq!(
            select_governing_descendant("b", ok(vec![governing(Some("b"))])),
            Ok(DescendantLevel::Ungoverned)
        );
        // Unowned / policy-less / absent descendants do not govern.
        assert_eq!(
            select_governing_descendant(
                "x",
                ok(vec![
                    governing(None),
                    AncestorLevel::NoPolicy,
                    AncestorLevel::Absent
                ])
            ),
            Ok(DescendantLevel::Ungoverned)
        );
        assert_eq!(
            select_governing_descendant("x", ok(vec![])),
            Ok(DescendantLevel::Ungoverned)
        );
        // A severed descendant fails closed and outranks a foreign one.
        assert_eq!(
            select_governing_descendant(
                "x",
                ok(vec![governing(Some("b")), AncestorLevel::Severed])
            ),
            Ok(DescendantLevel::Severed)
        );
        // A read fault propagates (fail-closed at the caller).
        let faulty: Vec<Result<AncestorLevel, &str>> = vec![Err("fault")];
        assert_eq!(select_governing_descendant("x", faulty), Err("fault"));

        // The admission applies to a first bind / unowned rebind only.
        let nm = NamespaceStandardBinding::NoMetaRow;
        assert_eq!(
            descendant_admission(&nm, &DescendantLevel::ForeignOwned),
            Err(SetRefusal::NotOwner)
        );
        assert_eq!(
            descendant_admission(&nm, &DescendantLevel::Severed),
            Err(SetRefusal::DescendantUnresolvable)
        );
        assert!(descendant_admission(&nm, &DescendantLevel::Ungoverned).is_ok());
        let unowned = NamespaceStandardBinding::Resolved(None);
        assert_eq!(
            descendant_admission(&unowned, &DescendantLevel::ForeignOwned),
            Err(SetRefusal::NotOwner)
        );
        // A rebind of an OWNED standard stays the current owner's call (#3758).
        let owned = NamespaceStandardBinding::Resolved(Some("x".into()));
        assert!(descendant_admission(&owned, &DescendantLevel::ForeignOwned).is_ok());
        assert_eq!(
            refusal_reason(SetRefusal::DescendantUnresolvable),
            REASON_DESCENDANT_STANDARD_UNRESOLVABLE
        );
    }

    #[test]
    fn normalise_owner_treats_empty_and_system_as_unowned_4356() {
        assert_eq!(normalise_owner(Some(String::new())), None);
        assert_eq!(normalise_owner(Some("system".into())), None);
        assert_eq!(normalise_owner(Some("a".into())), Some("a".into()));
    }
}
