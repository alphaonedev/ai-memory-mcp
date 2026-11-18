// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #9466 — the ONE case table both backends' SAL `delete_link` cells run.
//!
//! The invariant pinned: a failed or unreadable owner read refuses with a
//! named error on both backends, never a decision taken from a default. A
//! present endpoint whose `metadata.agent_id` is not a string (or whose
//! metadata is not JSON at all) is never read as `""` and never matched as
//! text; a query error on either owner read is returned as the store error
//! it is. After every refused case the edge is still in `memory_links`.
//!
//! An ABSENT endpoint row (an orphan edge, seeded with the foreign keys off)
//! is its own state: an ordinary caller gets the same `Ok(false)` a
//! non-owner gets and the edge stays; the owner of the other endpoint, the
//! daemon and an operator lane still sever it (#9466 E-1, E-7, D-3). The
//! both-unstamped legacy admission needs an EMPTY source addressee (E-4) and
//! goes through `admit_unstamped`, so `refuse` mode refuses it (E-3).
//!
//! The backend cells live in `src/store/sqlite/delete_link_owner_9466.rs`
//! and `src/store/postgres/delete_link_owner_9466.rs`; this module holds the
//! table, the endpoint states, the expected outcomes and the test-only read
//! fault both adapters consult through [`super::delete_link_owner_sql`].

use crate::models::{ConfidenceSource, Memory, MemoryLink, Tier};
use crate::store::{
    DELETE_LINK_ENDPOINT_SOURCE, DELETE_LINK_ENDPOINT_TARGET, DELETE_LINK_UNREADABLE_OWNER,
};
use std::sync::Mutex;

/// The relation a read fault redirects an owner read to. It never exists, so
/// the read fails through each backend's real error path.
pub(crate) const READ_FAULT_TABLE: &str = "delete_link_fault_9466";
/// The SQL an armed owner read runs instead of the production one.
pub(crate) const READ_FAULT_SQL: &str = "SELECT metadata FROM delete_link_fault_9466 WHERE id = $1";

/// Row ids whose NEXT `delete_link` owner read fails. Keyed by id, so cells
/// running in parallel never see each other's fault.
static READ_FAULTS: Mutex<Vec<String>> = Mutex::new(Vec::new());

/// Make the next `delete_link` owner read of row `id` fail.
pub(crate) fn arm_read_fault(id: &str) {
    READ_FAULTS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .push(id.to_string());
}

/// `true` (once) when a read fault is armed for `id`.
pub(crate) fn take_read_fault(id: &str) -> bool {
    let mut armed = READ_FAULTS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    match armed.iter().position(|armed_id| armed_id == id) {
        Some(at) => {
            armed.swap_remove(at);
            true
        }
        None => false,
    }
}

/// The principal that seeds every row and edge (it owns nothing afterwards:
/// each present endpoint's metadata is overwritten with its case state).
pub(crate) const SEED_OWNER: &str = "seed-9466";
pub(crate) const ALICE: &str = "alice-9466";
pub(crate) const BOB: &str = "bob-9466";
pub(crate) const MALLORY: &str = "mallory-9466";
/// The JSON number a malformed owner field carries.
pub(crate) const MALFORMED_OWNER_NUMBER: u32 = 42;
/// A caller whose id is the TEXT of [`MALFORMED_OWNER_NUMBER`]. Pre-#9466
/// postgres read `metadata->>'agent_id'` of the number as `"42"` and let
/// this caller own the row.
pub(crate) const NUMERIC_TEXT_CALLER: &str = "42";
/// Metadata text that is not JSON (sqlite only: a postgres `jsonb` column
/// cannot hold it).
pub(crate) const UNDECODABLE_METADATA: &str = "{not json 9466";
/// Metadata that decodes but is not a JSON object, so it has no owner key to
/// read (sqlite only: the postgres `memories_metadata_is_object` CHECK
/// refuses it).
pub(crate) const NON_OBJECT_METADATA: &str = "[\"mallory-9466\"]";
/// The namespace every seeded row lives in.
pub(crate) const NAMESPACE: &str = "delete-link-owner-9466";

/// The owner state of one endpoint row.
#[derive(Debug, Clone, Copy)]
pub(crate) enum Endpoint {
    /// No row with that id.
    Absent,
    /// `{"agent_id": <owner>}`.
    Stamped(&'static str),
    /// `{}` — the legacy single-operator row.
    Unstamped,
    /// `{"agent_id": 42}` — present, not a string.
    MalformedOwner,
    /// Source only: `{"agent_id": <owner>, "target_agent_id": <addressee>}`.
    Addressed(&'static str, &'static str),
    /// Source only: `{"agent_id": <owner>, "target_agent_id": 42}`.
    MalformedAddressee(&'static str),
    /// Metadata text that does not decode (sqlite only).
    Undecodable,
    /// Metadata that decodes to a non-object (sqlite only).
    NonObject,
    /// `{"agent_id": null}` — unstamped, like `{}` (E-2 parity).
    NullOwner,
    /// `{"agent_id": ""}` — unstamped, like `{}` (E-2 parity).
    EmptyOwner,
    /// Source only: `{"target_agent_id": <addressee>}` — an unstamped row
    /// addressed to an agent (E-4).
    UnstampedAddressed(&'static str),
}

impl Endpoint {
    /// The raw metadata text the row is given, `None` for an absent row.
    pub(crate) fn metadata_text(self) -> Option<String> {
        let json = match self {
            Self::Absent => return None,
            Self::Undecodable => return Some(UNDECODABLE_METADATA.to_string()),
            Self::NonObject => return Some(NON_OBJECT_METADATA.to_string()),
            Self::Stamped(owner) => serde_json::json!({ crate::META_KEY_AGENT_ID: owner }),
            Self::Unstamped => serde_json::json!({}),
            Self::MalformedOwner => {
                serde_json::json!({ crate::META_KEY_AGENT_ID: MALFORMED_OWNER_NUMBER })
            }
            Self::Addressed(owner, addressee) => serde_json::json!({
                crate::META_KEY_AGENT_ID: owner,
                crate::META_KEY_TARGET_AGENT_ID: addressee,
            }),
            Self::MalformedAddressee(owner) => serde_json::json!({
                crate::META_KEY_AGENT_ID: owner,
                crate::META_KEY_TARGET_AGENT_ID: MALFORMED_OWNER_NUMBER,
            }),
            Self::NullOwner => serde_json::json!({ crate::META_KEY_AGENT_ID: null }),
            Self::EmptyOwner => serde_json::json!({ crate::META_KEY_AGENT_ID: "" }),
            Self::UnstampedAddressed(addressee) => {
                serde_json::json!({ crate::META_KEY_TARGET_AGENT_ID: addressee })
            }
        };
        Some(json.to_string())
    }

    /// `true` for a state a postgres `jsonb` column cannot hold.
    pub(crate) fn sqlite_only(self) -> bool {
        matches!(self, Self::Undecodable | Self::NonObject)
    }
}

/// Who calls `delete_link`.
#[derive(Debug, Clone, Copy)]
pub(crate) enum Caller {
    Agent(&'static str),
    /// [`crate::identity::sentinels::DAEMON_PRINCIPAL`].
    Daemon,
    /// An operator lane (`ctx.bypass_visibility`); the gate is skipped.
    Operator(&'static str),
}

impl Caller {
    pub(crate) fn ctx(self) -> crate::store::CallerContext {
        match self {
            Self::Agent(id) => crate::store::CallerContext::for_agent(id),
            Self::Daemon => {
                crate::store::CallerContext::for_agent(crate::identity::sentinels::DAEMON_PRINCIPAL)
            }
            Self::Operator(id) => crate::store::CallerContext::for_admin(id),
        }
    }
}

/// What `delete_link` must do.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Expect {
    /// `Ok(true)` and the edge is gone.
    Removed,
    /// `Ok(false)` and the edge is still there.
    Kept,
    /// `Err` with exactly [`refusal_text`] for this endpoint name; the edge
    /// is still there.
    Refused(&'static str),
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct Case {
    pub(crate) name: &'static str,
    pub(crate) source: Endpoint,
    pub(crate) target: Endpoint,
    pub(crate) caller: Caller,
    pub(crate) expect: Expect,
}

const SRC: &str = DELETE_LINK_ENDPOINT_SOURCE;
const TGT: &str = DELETE_LINK_ENDPOINT_TARGET;

/// The (source state x target state x caller) table. The first block pins
/// the answers #9466 must not change; the rest pin the invariant.
#[rustfmt::skip]
pub(crate) const CASES: &[Case] = &[
    // -- readable owners: today's answers, unchanged ------------------------
    Case { name: "owner of source removes", source: Endpoint::Stamped(ALICE), target: Endpoint::Stamped(BOB), caller: Caller::Agent(ALICE), expect: Expect::Removed },
    Case { name: "owner of target removes", source: Endpoint::Stamped(ALICE), target: Endpoint::Stamped(BOB), caller: Caller::Agent(BOB), expect: Expect::Removed },
    Case { name: "owner of neither keeps", source: Endpoint::Stamped(ALICE), target: Endpoint::Stamped(BOB), caller: Caller::Agent(MALLORY), expect: Expect::Kept },
    Case { name: "stamped source, unstamped target, stranger keeps", source: Endpoint::Stamped(ALICE), target: Endpoint::Unstamped, caller: Caller::Agent(MALLORY), expect: Expect::Kept },
    Case { name: "unstamped source, stamped target, stranger keeps", source: Endpoint::Unstamped, target: Endpoint::Stamped(ALICE), caller: Caller::Agent(MALLORY), expect: Expect::Kept },
    Case { name: "both unstamped: legacy admission", source: Endpoint::Unstamped, target: Endpoint::Unstamped, caller: Caller::Agent(MALLORY), expect: Expect::Removed },
    Case { name: "inbox addressee of source removes", source: Endpoint::Addressed(BOB, ALICE), target: Endpoint::Stamped(BOB), caller: Caller::Agent(ALICE), expect: Expect::Removed },
    Case { name: "daemon removes", source: Endpoint::Stamped(ALICE), target: Endpoint::Stamped(BOB), caller: Caller::Daemon, expect: Expect::Removed },
    Case { name: "operator lane removes", source: Endpoint::Stamped(ALICE), target: Endpoint::Stamped(BOB), caller: Caller::Operator(MALLORY), expect: Expect::Removed },
    // -- a non-string owner is never "" and never matched as text ----------
    Case { name: "malformed source owner, unstamped target, stranger refused", source: Endpoint::MalformedOwner, target: Endpoint::Unstamped, caller: Caller::Agent(MALLORY), expect: Expect::Refused(SRC) },
    Case { name: "unstamped source, malformed target owner, stranger refused", source: Endpoint::Unstamped, target: Endpoint::MalformedOwner, caller: Caller::Agent(MALLORY), expect: Expect::Refused(TGT) },
    Case { name: "both owners malformed, stranger refused", source: Endpoint::MalformedOwner, target: Endpoint::MalformedOwner, caller: Caller::Agent(MALLORY), expect: Expect::Refused(SRC) },
    Case { name: "malformed source owner is not its number's text", source: Endpoint::MalformedOwner, target: Endpoint::Unstamped, caller: Caller::Agent(NUMERIC_TEXT_CALLER), expect: Expect::Refused(SRC) },
    Case { name: "malformed target owner is not its number's text", source: Endpoint::Stamped(ALICE), target: Endpoint::MalformedOwner, caller: Caller::Agent(NUMERIC_TEXT_CALLER), expect: Expect::Refused(TGT) },
    Case { name: "malformed source owner, owner of target removes", source: Endpoint::MalformedOwner, target: Endpoint::Stamped(BOB), caller: Caller::Agent(BOB), expect: Expect::Removed },
    Case { name: "malformed source owner, stranger to target refused", source: Endpoint::MalformedOwner, target: Endpoint::Stamped(BOB), caller: Caller::Agent(MALLORY), expect: Expect::Refused(SRC) },
    Case { name: "malformed target owner, owner of source removes", source: Endpoint::Stamped(ALICE), target: Endpoint::MalformedOwner, caller: Caller::Agent(ALICE), expect: Expect::Removed },
    Case { name: "malformed target owner, stranger refused", source: Endpoint::Stamped(ALICE), target: Endpoint::MalformedOwner, caller: Caller::Agent(MALLORY), expect: Expect::Refused(TGT) },
    Case { name: "malformed target owner, source addressee removes", source: Endpoint::Addressed(BOB, ALICE), target: Endpoint::MalformedOwner, caller: Caller::Agent(ALICE), expect: Expect::Removed },
    Case { name: "malformed owner, daemon removes", source: Endpoint::MalformedOwner, target: Endpoint::Unstamped, caller: Caller::Daemon, expect: Expect::Removed },
    Case { name: "malformed owner, operator lane removes", source: Endpoint::MalformedOwner, target: Endpoint::MalformedOwner, caller: Caller::Operator(MALLORY), expect: Expect::Removed },
    Case { name: "malformed addressee addresses nobody", source: Endpoint::MalformedAddressee(BOB), target: Endpoint::Unstamped, caller: Caller::Agent(NUMERIC_TEXT_CALLER), expect: Expect::Kept },
    Case { name: "malformed addressee, owner of source removes", source: Endpoint::MalformedAddressee(BOB), target: Endpoint::Unstamped, caller: Caller::Agent(BOB), expect: Expect::Removed },
    // -- undecodable metadata (sqlite only) ---------------------------------
    Case { name: "undecodable source, unstamped target, stranger refused", source: Endpoint::Undecodable, target: Endpoint::Unstamped, caller: Caller::Agent(MALLORY), expect: Expect::Refused(SRC) },
    Case { name: "unstamped source, undecodable target, stranger refused", source: Endpoint::Unstamped, target: Endpoint::Undecodable, caller: Caller::Agent(MALLORY), expect: Expect::Refused(TGT) },
    Case { name: "undecodable source, owner of target removes", source: Endpoint::Undecodable, target: Endpoint::Stamped(BOB), caller: Caller::Agent(BOB), expect: Expect::Removed },
    Case { name: "undecodable target, owner of source removes", source: Endpoint::Stamped(ALICE), target: Endpoint::Undecodable, caller: Caller::Agent(ALICE), expect: Expect::Removed },
    Case { name: "undecodable source, daemon removes", source: Endpoint::Undecodable, target: Endpoint::Unstamped, caller: Caller::Daemon, expect: Expect::Removed },
    Case { name: "non-object source, unstamped target, stranger refused", source: Endpoint::NonObject, target: Endpoint::Unstamped, caller: Caller::Agent(MALLORY), expect: Expect::Refused(SRC) },
    Case { name: "unstamped source, non-object target, stranger refused", source: Endpoint::Unstamped, target: Endpoint::NonObject, caller: Caller::Agent(MALLORY), expect: Expect::Refused(TGT) },
    Case { name: "non-object target, owner of source removes", source: Endpoint::Stamped(ALICE), target: Endpoint::NonObject, caller: Caller::Agent(ALICE), expect: Expect::Removed },
    // -- an absent endpoint row (orphan edge): refused like a non-owner -----
    Case { name: "absent source, stamped target, stranger keeps", source: Endpoint::Absent, target: Endpoint::Stamped(ALICE), caller: Caller::Agent(MALLORY), expect: Expect::Kept },
    Case { name: "absent source, unstamped target, stranger keeps", source: Endpoint::Absent, target: Endpoint::Unstamped, caller: Caller::Agent(MALLORY), expect: Expect::Kept },
    Case { name: "unstamped source, absent target, stranger keeps", source: Endpoint::Unstamped, target: Endpoint::Absent, caller: Caller::Agent(MALLORY), expect: Expect::Kept },
    Case { name: "stamped source, absent target, stranger keeps", source: Endpoint::Stamped(ALICE), target: Endpoint::Absent, caller: Caller::Agent(MALLORY), expect: Expect::Kept },
    Case { name: "absent source, malformed target, stranger keeps", source: Endpoint::Absent, target: Endpoint::MalformedOwner, caller: Caller::Agent(MALLORY), expect: Expect::Kept },
    Case { name: "both absent, stranger keeps", source: Endpoint::Absent, target: Endpoint::Absent, caller: Caller::Agent(MALLORY), expect: Expect::Kept },
    Case { name: "absent source, owner of target removes", source: Endpoint::Absent, target: Endpoint::Stamped(ALICE), caller: Caller::Agent(ALICE), expect: Expect::Removed },
    Case { name: "absent target, owner of source removes", source: Endpoint::Stamped(ALICE), target: Endpoint::Absent, caller: Caller::Agent(ALICE), expect: Expect::Removed },
    Case { name: "both absent, daemon removes", source: Endpoint::Absent, target: Endpoint::Absent, caller: Caller::Daemon, expect: Expect::Removed },
    Case { name: "absent source, daemon removes", source: Endpoint::Absent, target: Endpoint::Stamped(ALICE), caller: Caller::Daemon, expect: Expect::Removed },
    Case { name: "both absent, operator lane removes", source: Endpoint::Absent, target: Endpoint::Absent, caller: Caller::Operator(MALLORY), expect: Expect::Removed },
    // -- E-4: the legacy admission needs an EMPTY source addressee ----------
    Case { name: "unstamped source addressed to another, unstamped target, stranger keeps", source: Endpoint::UnstampedAddressed(BOB), target: Endpoint::Unstamped, caller: Caller::Agent(MALLORY), expect: Expect::Kept },
    Case { name: "unstamped source addressed to caller, unstamped target, addressee removes", source: Endpoint::UnstampedAddressed(BOB), target: Endpoint::Unstamped, caller: Caller::Agent(BOB), expect: Expect::Removed },
    Case { name: "unstamped source addressed to another, stamped target, stranger keeps", source: Endpoint::UnstampedAddressed(BOB), target: Endpoint::Stamped(ALICE), caller: Caller::Agent(MALLORY), expect: Expect::Kept },
    // -- E-2: NULL and "" owners are unstamped, exactly like {} -------------
    Case { name: "null source owner, unstamped target: legacy admission", source: Endpoint::NullOwner, target: Endpoint::Unstamped, caller: Caller::Agent(MALLORY), expect: Expect::Removed },
    Case { name: "empty source owner, null target owner: legacy admission", source: Endpoint::EmptyOwner, target: Endpoint::NullOwner, caller: Caller::Agent(MALLORY), expect: Expect::Removed },
    Case { name: "null source owner, stamped target, stranger keeps", source: Endpoint::NullOwner, target: Endpoint::Stamped(ALICE), caller: Caller::Agent(MALLORY), expect: Expect::Kept },
    Case { name: "empty source owner, absent target, stranger keeps", source: Endpoint::EmptyOwner, target: Endpoint::Absent, caller: Caller::Agent(MALLORY), expect: Expect::Kept },
    Case { name: "empty owner is not the empty caller", source: Endpoint::EmptyOwner, target: Endpoint::Stamped(ALICE), caller: Caller::Agent(""), expect: Expect::Kept },
];

/// The exact `Display` of the unreadable-owner refusal for `endpoint`.
pub(crate) fn refusal_text(endpoint: &str) -> String {
    format!("integrity check failed: {DELETE_LINK_UNREADABLE_OWNER} {endpoint}")
}

/// A fresh endpoint row, seeded as [`SEED_OWNER`]'s.
pub(crate) fn seed_memory(title: &str) -> Memory {
    let now = chrono::Utc::now().to_rfc3339();
    Memory {
        cid: None,
        valid_from: None,
        valid_until: None,
        id: uuid::Uuid::new_v4().to_string(),
        tier: Tier::Mid,
        namespace: NAMESPACE.to_string(),
        title: format!("{title} {}", uuid::Uuid::new_v4()),
        content: format!("delete_link owner cell: {title}"),
        tags: vec![],
        priority: 5,
        confidence: 1.0,
        source: "test".to_string(),
        access_count: 0,
        created_at: now.clone(),
        updated_at: now,
        last_accessed_at: None,
        expires_at: None,
        metadata: serde_json::json!({ crate::META_KEY_AGENT_ID: SEED_OWNER }),
        reflection_depth: 0,
        memory_kind: crate::models::MemoryKind::Observation,
        entity_id: None,
        persona_version: None,
        citations: Vec::new(),
        source_uri: None,
        source_span: None,
        confidence_source: ConfidenceSource::CallerProvided,
        confidence_signals: None,
        confidence_decayed_at: None,
        version: 1,
        lifecycle_state: crate::models::LifecycleState::Open,
    }
}

/// The edge `source -> target`.
pub(crate) fn edge(source_id: &str, target_id: &str) -> MemoryLink {
    MemoryLink {
        source_id: source_id.to_string(),
        target_id: target_id.to_string(),
        relation: crate::models::MemoryLinkRelation::RelatedTo,
        created_at: chrono::Utc::now().to_rfc3339(),
        valid_from: None,
        valid_until: None,
        observed_by: None,
        signature: None,
        attest_level: None,
        source_cid: None,
        target_cid: None,
    }
}

/// Judge one case's outcome. `edges_after` is the `memory_links` row count
/// for the pair after the call. `Err(reason)` names what went wrong.
pub(crate) fn judge(
    case: &Case,
    got: &crate::store::StoreResult<bool>,
    edges_after: i64,
) -> Result<(), String> {
    let ok = match (case.expect, got) {
        (Expect::Removed, Ok(true)) => edges_after == 0,
        (Expect::Kept, Ok(false)) => edges_after == 1,
        (Expect::Refused(endpoint), Err(e)) => {
            e.to_string() == refusal_text(endpoint) && edges_after == 1
        }
        _ => false,
    };
    if ok {
        Ok(())
    } else {
        Err(format!(
            "{}: expected {:?}, got {:?} with {edges_after} edge(s) left",
            case.name,
            case.expect,
            got.as_ref().map_err(ToString::to_string)
        ))
    }
}

/// The owner field values both classifiers are checked over: `(JSON, the
/// postgres `jsonb_typeof`, the postgres `->>` text, expected stamp)`.
/// `None` JSON = the key is missing.
const FIELD_CORPUS: &[(
    Option<&str>,
    Option<&str>,
    Option<&str>,
    crate::identity::owner_stamp::OwnerStamp<'static>,
)] = {
    use crate::identity::owner_stamp::OwnerStamp as O;
    &[
        (None, None, None, O::Unstamped),
        (Some("null"), Some("null"), None, O::Unstamped),
        (
            Some("\"alice-9466\""),
            Some("string"),
            Some("alice-9466"),
            O::Stamped(ALICE),
        ),
        (Some("\"\""), Some("string"), Some(""), O::Unstamped),
        (Some("42"), Some("number"), Some("42"), O::Malformed),
        (Some("true"), Some("boolean"), Some("true"), O::Malformed),
        (
            Some("[\"alice-9466\"]"),
            Some("array"),
            Some("[\"alice-9466\"]"),
            O::Malformed,
        ),
        (
            Some("{\"id\": \"alice-9466\"}"),
            Some("object"),
            Some("{\"id\": \"alice-9466\"}"),
            O::Malformed,
        ),
    ]
};

/// `LinkEndpoint::of` and `LinkEndpoint::of_pg` give the same reading of
/// both the owner and the addressee for every corpus value (E-2: NULL, a
/// missing key and `""` are one unstamped state on both backends).
#[test]
fn delete_link_endpoint_classifiers_agree_9466() {
    use super::LinkEndpoint;
    for (json, pg_type, pg_text, want) in FIELD_CORPUS {
        let field: Option<serde_json::Value> =
            json.map(|j| serde_json::from_str(j).expect("corpus value is JSON"));
        for key in [crate::META_KEY_AGENT_ID, crate::META_KEY_TARGET_AGENT_ID] {
            let mut metadata = serde_json::json!({});
            if let Some(value) = field.clone() {
                metadata[key] = value;
            }
            let (owner, addressee) = if key == crate::META_KEY_AGENT_ID {
                (*want, crate::identity::owner_stamp::OwnerStamp::Unstamped)
            } else {
                (crate::identity::owner_stamp::OwnerStamp::Unstamped, *want)
            };
            let expected = LinkEndpoint::Present { owner, addressee };
            assert_eq!(LinkEndpoint::of(&metadata), expected, "of {key} {json:?}");
            let pg = if key == crate::META_KEY_AGENT_ID {
                LinkEndpoint::of_pg(*pg_type, *pg_text, None, None)
            } else {
                LinkEndpoint::of_pg(None, None, *pg_type, *pg_text)
            };
            assert_eq!(pg, expected, "of_pg {key} {pg_type:?}");
        }
    }
}

/// Metadata that is not a JSON object has no readable owner or addressee,
/// whatever it holds — never an unstamped row.
#[test]
fn delete_link_non_object_metadata_unreadable_9466() {
    for raw in [
        "[]",
        NON_OBJECT_METADATA,
        "42",
        "\"alice-9466\"",
        "null",
        "true",
    ] {
        let value: serde_json::Value = serde_json::from_str(raw).expect("JSON");
        assert_eq!(
            super::LinkEndpoint::of(&value),
            super::LinkEndpoint::UNDECODABLE,
            "{raw}"
        );
    }
}

/// The gate over the endpoints as read, with no store: an absent endpoint
/// is a refusal (never an unstamped row), a malformed owner on a present
/// pair refuses with the exact text unless the caller is the daemon or a
/// readable owner, and the legacy admission needs an empty addressee.
#[test]
fn delete_link_gate_decisions_9466() {
    use super::LinkEndpoint as E;
    use crate::identity::owner_stamp::OwnerStamp as O;
    let site = crate::identity::owner_stamp::MutationSite::sqlite(
        crate::identity::owner_stamp::funnel::UNLINK,
    );
    let gate = |source: E<'_>, target: E<'_>, caller: &str| {
        super::delete_link_gate(source, target, "src-9466", caller, site).map_err(|e| e.to_string())
    };
    let row = |owner: O<'static>| E::Present {
        owner,
        addressee: O::Unstamped,
    };
    let addressed = |owner: O<'static>, addressee: &'static str| E::Present {
        owner,
        addressee: O::Stamped(addressee),
    };
    let daemon = crate::identity::sentinels::DAEMON_PRINCIPAL;
    let (alice, bob) = (O::Stamped(ALICE), O::Stamped(BOB));
    // Both readable.
    assert_eq!(gate(row(alice), row(bob), ALICE), Ok(true));
    assert_eq!(gate(row(alice), row(bob), BOB), Ok(true));
    assert_eq!(gate(row(alice), row(bob), MALLORY), Ok(false));
    assert_eq!(
        gate(row(O::Unstamped), row(O::Unstamped), MALLORY),
        Ok(true)
    );
    // E-4: an addressed unstamped source admits its addressee, nobody else.
    assert_eq!(
        gate(addressed(O::Unstamped, BOB), row(O::Unstamped), MALLORY),
        Ok(false)
    );
    assert_eq!(
        gate(addressed(O::Unstamped, BOB), row(O::Unstamped), BOB),
        Ok(true)
    );
    // Malformed owner on a present pair.
    assert_eq!(
        gate(row(O::Malformed), row(O::Unstamped), MALLORY),
        Err(refusal_text(SRC))
    );
    assert_eq!(
        gate(row(O::Unstamped), row(O::Malformed), MALLORY),
        Err(refusal_text(TGT))
    );
    assert_eq!(
        gate(row(O::Malformed), row(O::Malformed), MALLORY),
        Err(refusal_text(SRC))
    );
    assert_eq!(gate(row(O::Malformed), row(O::Unstamped), daemon), Ok(true));
    assert_eq!(gate(row(O::Malformed), row(bob), BOB), Ok(true));
    assert_eq!(gate(row(alice), row(O::Malformed), ALICE), Ok(true));
    assert_eq!(
        gate(addressed(O::Malformed, BOB), row(O::Unstamped), BOB),
        Ok(true),
        "the addressee of a source that is not unstamped"
    );
    assert_eq!(
        gate(row(O::Malformed), row(O::Unstamped), NUMERIC_TEXT_CALLER),
        Err(refusal_text(SRC))
    );
    // An absent endpoint: refused like a non-owner, never unstamped.
    assert_eq!(gate(E::Absent, row(O::Malformed), MALLORY), Ok(false));
    assert_eq!(gate(E::UNDECODABLE, E::Absent, MALLORY), Ok(false));
    assert_eq!(gate(E::Absent, E::Absent, MALLORY), Ok(false));
    assert_eq!(gate(E::Absent, row(O::Unstamped), MALLORY), Ok(false));
    assert_eq!(gate(row(O::Unstamped), E::Absent, MALLORY), Ok(false));
    assert_eq!(gate(E::Absent, row(alice), ALICE), Ok(true));
    assert_eq!(gate(row(alice), E::Absent, ALICE), Ok(true));
    assert_eq!(gate(E::Absent, E::Absent, daemon), Ok(true));
    // The empty caller never matches an empty (unstamped) owner.
    assert_eq!(gate(row(O::Unstamped), row(alice), ""), Ok(false));
}

/// E-3: under `AI_MEMORY_UNSTAMPED_MUTATION=refuse` the both-unstamped
/// legacy admission (and the addressee of an unstamped source) is refused;
/// a stamped owner is unaffected. Runs in an env-isolated child so no
/// other test sees the knob.
#[test]
fn delete_link_gate_refuse_mode_9466() {
    use super::LinkEndpoint as E;
    use crate::identity::owner_stamp::OwnerStamp as O;
    if crate::test_support::run_env_isolated_child_or_spawn(
        "store::delete_link_owner_9466::delete_link_gate_refuse_mode_9466",
    ) {
        return;
    }
    // SAFETY: this body runs only in the isolated single-threaded child.
    unsafe {
        std::env::set_var(
            crate::identity::owner_stamp::ENV_UNSTAMPED_MUTATION,
            crate::identity::owner_stamp::MODE_REFUSE,
        );
    }
    let site = crate::identity::owner_stamp::MutationSite::postgres(
        crate::identity::owner_stamp::funnel::UNLINK,
    );
    let gate = |source: E<'_>, target: E<'_>, caller: &str| {
        super::delete_link_gate(source, target, "src-9466", caller, site).map_err(|e| e.to_string())
    };
    let row = |owner: O<'static>| E::Present {
        owner,
        addressee: O::Unstamped,
    };
    assert_eq!(
        gate(row(O::Unstamped), row(O::Unstamped), MALLORY),
        Ok(false)
    );
    assert_eq!(
        gate(
            E::Present {
                owner: O::Unstamped,
                addressee: O::Stamped(BOB)
            },
            row(O::Unstamped),
            BOB
        ),
        Ok(false)
    );
    assert_eq!(
        gate(row(O::Stamped(ALICE)), row(O::Unstamped), ALICE),
        Ok(true)
    );
}
