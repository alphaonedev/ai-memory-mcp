// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 #3200 — the ONE boolean env-token grammar.
//!
//! Before #3200 the binary carried more than fifty hand-written boolean
//! parsers in seven shapes (`1|true` only, exact `"1"`, the house
//! `1|true|yes|on`, case-sensitive and case-insensitive variants, trimmed and
//! untrimmed). Two readers of the same knob could disagree, and an `asi-hard`
//! floor could accept a token its live reader ignored (#3618, #3619). The
//! result was a control that reported ON while it was OFF: under `asi-hard`,
//! `AI_MEMORY_REQUIRE_AGENT_ATTESTATION=yes` met the floor and still let an
//! unsigned CLI store land.
//!
//! This module is the single parser. It is deliberately tiny and PURE: every
//! function here maps a token to a verdict without reading the environment,
//! so the grammar is proven by table tests and the env readers built on it
//! cannot drift from it.
//!
//! ## The grammar
//!
//! Tokens are trimmed and compared case-insensitively.
//!
//! | Token | Verdict |
//! |---|---|
//! | `1`, `true`, `yes`, `on` | [`FlagToken::True`] |
//! | `0`, `false`, `no`, `off` | [`FlagToken::False`] |
//! | absent, empty, whitespace-only | [`FlagToken::Unset`] |
//! | anything else | [`FlagToken::Unrecognised`] |
//!
//! Empty counts as UNSET, never unrecognised. `enforce_at_boot` pins a
//! permissive `asi-hard` knob by writing the empty string, and an unexpanded
//! `${VAR}` in a compose file renders as empty: neither may read as a typo.
//!
//! ## Unrecognised tokens fail closed by polarity
//!
//! A value outside the grammar is never silently read as "off" (the #131 /
//! FBL-14 rule: an unrecognised token must never widen a security control).
//! [`resolve`] maps it to the SECURE side of the knob's [`Polarity`]:
//! a [`Polarity::Mandate`] (truthy tightens) reads ON, a [`Polarity::Hatch`]
//! (truthy loosens) reads OFF.

/// The four-way verdict for one boolean env token.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlagToken {
    /// `1` / `true` / `yes` / `on` (trimmed, case-insensitive).
    True,
    /// `0` / `false` / `no` / `off` (trimmed, case-insensitive).
    False,
    /// Absent, empty, or whitespace-only.
    Unset,
    /// Any other value: a typo or a token outside the grammar.
    Unrecognised,
}

/// Which way a boolean knob moves a control when it is truthy. Decides the
/// fail-closed reading of an unrecognised token in [`resolve`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Polarity {
    /// Truthy TIGHTENS a control (e.g. `AI_MEMORY_REQUIRE_TLS`). An
    /// unrecognised token reads ON.
    Mandate,
    /// Truthy LOOSENS a control (e.g. `AI_MEMORY_ALLOW_PLAINTEXT_NONLOOPBACK`).
    /// An unrecognised token reads OFF.
    Hatch,
}

/// Classify one raw token. `None` is an absent variable.
#[must_use]
pub fn parse(value: Option<&str>) -> FlagToken {
    let Some(raw) = value else {
        return FlagToken::Unset;
    };
    let token = raw.trim();
    if token.is_empty() {
        return FlagToken::Unset;
    }
    if ["1", "true", "yes", "on"]
        .iter()
        .any(|t| token.eq_ignore_ascii_case(t))
    {
        FlagToken::True
    } else if ["0", "false", "no", "off"]
        .iter()
        .any(|t| token.eq_ignore_ascii_case(t))
    {
        FlagToken::False
    } else {
        FlagToken::Unrecognised
    }
}

/// `true` only for a token in the truthy half of the grammar.
#[must_use]
pub fn is_truthy(value: &str) -> bool {
    parse(Some(value)) == FlagToken::True
}

/// `true` only for a token in the falsy half of the grammar.
#[must_use]
pub fn is_falsy(value: &str) -> bool {
    parse(Some(value)) == FlagToken::False
}

/// The explicit env value of a knob, or `None` when it is unset.
///
/// A recognised token maps to its boolean. An unrecognised token maps to the
/// secure side of `polarity` (a mandate reads ON, a hatch reads OFF). Callers
/// with a config or compiled-default layer fall through on `None`.
#[must_use]
pub fn resolve(value: Option<&str>, polarity: Polarity) -> Option<bool> {
    match parse(value) {
        FlagToken::True => Some(true),
        FlagToken::False => Some(false),
        FlagToken::Unset => None,
        FlagToken::Unrecognised => Some(polarity == Polarity::Mandate),
    }
}

/// [`resolve`] with a compiled default for the unset case.
#[must_use]
pub fn resolve_or(value: Option<&str>, polarity: Polarity, default: bool) -> bool {
    resolve(value, polarity).unwrap_or(default)
}

/// The accepted grammar, spelled once for every operator-facing message.
pub const ACCEPTED_GRAMMAR: &str = "1|true|yes|on (enable) or 0|false|no|off (disable), \
     case-insensitive and trimmed; an empty value counts as unset";

/// Read an env var as a raw token. A non-UTF-8 value cannot be a token of the
/// grammar, so it is reported as `Err(())` and classified as unrecognised.
fn env_token(name: &str) -> Option<Result<String, ()>> {
    std::env::var_os(name).map(|os| os.into_string().map_err(|_| ()))
}

/// Reader for a NEUTRAL boolean knob (feature, performance, durability):
/// `true` only for a truthy token. An unrecognised token reads OFF and is not
/// refused at boot, because a NEUTRAL knob moves no security control. A knob
/// that tightens or loosens a control must be a registered [`BoolKnob`].
#[must_use]
pub fn neutral_enabled(name: &str) -> bool {
    matches!(env_token(name), Some(Ok(v)) if is_truthy(&v))
}

/// One registered security-relevant boolean knob.
///
/// Every MANDATE and HATCH knob reader, and every `asi-hard` floor for one,
/// goes through a `BoolKnob` so the live reader, the floor and the boot sweep
/// share one grammar. NEUTRAL knobs that are not migrated yet are tracked in
/// `scripts/qc-allowlists/truthy-grammar-neutral-ledger.txt` and may only
/// leave it (`scripts/check-truthy-grammar.sh`).
#[derive(Debug)]
pub struct BoolKnob {
    /// The environment variable name.
    pub env: &'static str,
    /// Which way a truthy value moves the control.
    pub polarity: Polarity,
    /// The compiled default when unset. `None` when the effective value comes
    /// from another layer (config file, per-surface default) the caller owns.
    pub default: Option<bool>,
    /// The grammar the reader used before #3200, for the one-shot
    /// meaning-changed WARN. Removed at v1.1.
    pub legacy: legacy::Legacy,
}

impl BoolKnob {
    /// The explicit env value, or `None` when unset. An unrecognised or
    /// non-UTF-8 value reads as the secure side of the polarity (the boot
    /// sweep has already refused it in a binary that booted through `main`).
    #[must_use]
    pub fn explicit(&self) -> Option<bool> {
        match env_token(self.env) {
            None => None,
            Some(Ok(v)) => resolve(Some(&v), self.polarity),
            Some(Err(())) => Some(self.polarity == Polarity::Mandate),
        }
    }

    /// The effective value: explicit env value, else the compiled default,
    /// else `false`.
    #[must_use]
    pub fn enabled(&self) -> bool {
        self.explicit().or(self.default).unwrap_or(false)
    }

    /// Value-level twin of [`BoolKnob::enabled`] for an already-read value.
    /// The `asi-hard` floors delegate here so a floor can never accept a
    /// token the live reader ignores (#3618, #3619).
    #[must_use]
    pub fn value_enabled(&self, value: &str) -> bool {
        resolve(Some(value), self.polarity)
            .or(self.default)
            .unwrap_or(false)
    }
}

/// Every registered MANDATE/HATCH knob. The boot sweep walks this table.
pub const REGISTRY: &[&BoolKnob] = &[
    &knobs::REQUIRE_API_KEY,
    &knobs::REQUIRE_TLS,
    &knobs::ALLOW_PLAINTEXT_NONLOOPBACK,
    &knobs::GOVERNANCE_FAIL_OPEN_ON_ERROR,
    &knobs::PASSPHRASE_FILE_ALLOW_LAX_PERMS,
    &knobs::STORE_URL_FILE_ALLOW_LAX_PERMS,
    &knobs::CAPABILITY_FILE_ALLOW_LAX_PERMS,
    &knobs::SSRF_GUARD_ALLOW_DNS_FAIL,
    &knobs::ALLOW_LOOPBACK_WEBHOOKS,
    &knobs::ADMIN_HEADER_TRUST,
    &knobs::CID_ENFORCE,
    &knobs::MIGRATION_REQUIRE_CORE_TABLES,
    &knobs::ALLOW_LINEAGE_REGRESSION,
    &knobs::APPEND_ONLY,
    &knobs::ENCRYPT_AT_REST,
    &knobs::PG_AT_REST_ATTESTED,
    &knobs::REQUIRE_ENTERPRISE_FEDERATION_POSTURE,
    &knobs::ERASURE_RECOVER_QUARANTINE,
    &knobs::FED_TRUST_BODY_AGENT_ID,
    &knobs::FED_SYNC_TRUST_PEER,
    &knobs::FED_REQUIRE_TRANSITION_SIG,
    &knobs::FED_REQUIRE_CHECKPOINT_SIG,
    &knobs::FED_REQUIRE_WRITE_SIG,
    &knobs::FED_REQUIRE_SIGNAL_SIG,
    &knobs::FED_QUARANTINE_UNATTRIBUTED,
    &knobs::FED_REQUIRE_POLICY_CURRENT,
    &knobs::FED_REQUIRE_PUSH_NAMESPACE_SCOPE,
    &knobs::FED_REQUIRE_SIG,
    &knobs::FED_REQUIRE_NONCE,
    &knobs::FED_REQUIRE_PEER_ENROLLMENT,
    &knobs::FED_ALLOW_UNENROLLED_PEERS,
    &knobs::FED_REQUIRE_SERVER_VERIFY,
    &knobs::FED_ALLOW_PLAINTEXT_PEERS,
    &knobs::REQUIRE_WITNESS,
    &knobs::REQUIRE_CAUSE_BINDING,
    &knobs::REQUIRE_ROLE_SEPARATION,
    &knobs::REQUIRE_ROLLBACK_CHECK,
    &knobs::PERMISSIONS_REQUIRE_GOVERNED_NAMESPACE,
    &knobs::REQUIRE_DIM_MATCH,
    &knobs::REQUIRE_EMBED_MODEL_MATCH,
    &knobs::REQUIRE_AGENT_ATTESTATION,
    &knobs::REQUIRE_IDENTITY_LINEAGE,
    &knobs::REQUIRE_OWNED_ROWS,
    &knobs::REQUIRE_WHY_TRACE,
    &knobs::REQUIRE_IMMUTABLE_AUTHORSHIP,
    &knobs::STRICT_DECRYPT_READS,
];

/// The registered knobs. Env names come from each owning module's const where
/// one exists; the few knobs that never had one are spelled here, once.
pub mod knobs {
    use super::legacy::Legacy;
    use super::{BoolKnob, Polarity};

    const fn mandate(env: &'static str, default: Option<bool>, legacy: Legacy) -> BoolKnob {
        BoolKnob {
            env,
            polarity: Polarity::Mandate,
            default,
            legacy,
        }
    }

    const fn hatch(env: &'static str, legacy: Legacy) -> BoolKnob {
        BoolKnob {
            env,
            polarity: Polarity::Hatch,
            default: Some(false),
            legacy,
        }
    }

    // --- daemon boot / TLS (#3200's three knobs) ---------------------------
    /// #1458 — refuse a keyless bind on every host, loopback included.
    pub const REQUIRE_API_KEY: BoolKnob =
        mandate("AI_MEMORY_REQUIRE_API_KEY", Some(false), Legacy::OneOrTrue);
    /// #2032 M2 — refuse a plaintext bind on every host.
    pub const REQUIRE_TLS: BoolKnob = mandate(
        crate::daemon_runtime::ENV_REQUIRE_TLS,
        Some(false),
        Legacy::OneOrTrue,
    );
    /// #2032 M2 — acknowledge upstream TLS termination (silences the WARN).
    pub const ALLOW_PLAINTEXT_NONLOOPBACK: BoolKnob = hatch(
        crate::daemon_runtime::ENV_ALLOW_PLAINTEXT_NONLOOPBACK,
        Legacy::OneOrTrue,
    );
    /// #1054 — governance consultation errors fail OPEN.
    pub const GOVERNANCE_FAIL_OPEN_ON_ERROR: BoolKnob = hatch(
        crate::daemon_runtime::ENV_GOVERNANCE_FAIL_OPEN,
        Legacy::OneOrTrue,
    );

    // --- lax-permission escape hatches -------------------------------------
    /// #1055 / #3620 — accept a group/world-readable passphrase or key file.
    pub const PASSPHRASE_FILE_ALLOW_LAX_PERMS: BoolKnob = hatch(
        "AI_MEMORY_PASSPHRASE_FILE_ALLOW_LAX_PERMS",
        Legacy::OneOrTrue,
    );
    /// #1927 — accept a group/world-readable store-url file.
    pub const STORE_URL_FILE_ALLOW_LAX_PERMS: BoolKnob = hatch(
        "AI_MEMORY_STORE_URL_FILE_ALLOW_LAX_PERMS",
        Legacy::OneOrTrue,
    );
    /// #1927-class — accept a group/world-readable capability-token file.
    pub const CAPABILITY_FILE_ALLOW_LAX_PERMS: BoolKnob = hatch(
        crate::governance::capability::CAPABILITY_FILE_ALLOW_LAX_PERMS_ENV,
        Legacy::OneOrTrue,
    );

    // --- network / identity hatches ----------------------------------------
    /// #1053 — an SSRF-guard DNS failure fails OPEN.
    pub const SSRF_GUARD_ALLOW_DNS_FAIL: BoolKnob =
        hatch("AI_MEMORY_SSRF_GUARD_ALLOW_DNS_FAIL", Legacy::OneOrTrue);
    /// #628 — permit loopback webhook targets. The config layer applies when
    /// unset, so there is no compiled default here.
    pub const ALLOW_LOOPBACK_WEBHOOKS: BoolKnob = BoolKnob {
        env: "AI_MEMORY_ALLOW_LOOPBACK_WEBHOOKS",
        polarity: Polarity::Hatch,
        default: None,
        legacy: Legacy::TriStateHouseUntrimmed,
    };
    /// #1570 — trust a bare self-asserted admin `X-Agent-Id`.
    pub const ADMIN_HEADER_TRUST: BoolKnob = hatch(
        crate::handlers::admin_role::ENV_ADMIN_HEADER_TRUST,
        Legacy::OneOrTrue,
    );
    /// #238 — trust the body `agent_id` on federated writes.
    pub const FED_TRUST_BODY_AGENT_ID: BoolKnob = hatch(
        crate::federation::peer_attestation::TRUST_BODY_AGENT_ID_ENV,
        Legacy::ExactOne,
    );
    /// #239 — trust peer-supplied sync metadata.
    pub const FED_SYNC_TRUST_PEER: BoolKnob = hatch(
        crate::federation::peer_attestation::SYNC_TRUST_PEER_ENV,
        Legacy::ExactOne,
    );
    /// #1056 — accept unenrolled-peer attribution.
    pub const FED_ALLOW_UNENROLLED_PEERS: BoolKnob = hatch(
        crate::handlers::federation_signing_check::ALLOW_UNENROLLED_PEERS_ENV,
        Legacy::House,
    );
    /// #2477 — permit plaintext transport to a non-loopback peer.
    pub const FED_ALLOW_PLAINTEXT_PEERS: BoolKnob =
        hatch(crate::tls::FED_ALLOW_PLAINTEXT_PEERS_ENV, Legacy::House);

    // --- schema / data-integrity -------------------------------------------
    /// #1825 — a cid mismatch is WARN-enforced.
    pub const CID_ENFORCE: BoolKnob =
        mandate(crate::config::ENV_CID_ENFORCE, Some(false), Legacy::House);
    /// #3113 — a lost core relation refuses the schema stamp.
    pub const MIGRATION_REQUIRE_CORE_TABLES: BoolKnob = mandate(
        crate::config::ENV_MIGRATION_REQUIRE_CORE_TABLES,
        Some(false),
        Legacy::House,
    );
    /// #3172 — acknowledge an append-only lineage regression (resets the mark).
    pub const ALLOW_LINEAGE_REGRESSION: BoolKnob =
        hatch(crate::config::ENV_ALLOW_LINEAGE_REGRESSION, Legacy::House);
    /// #1823 G6 — the append-only revision spine. The `[storage]` layer
    /// applies when unset.
    pub const APPEND_ONLY: BoolKnob = mandate(
        crate::config::ENV_APPEND_ONLY,
        None,
        Legacy::TriStateOneTrueTrimmed,
    );
    /// #228 / #3621 — at-rest encryption (sqlcipher build).
    pub const ENCRYPT_AT_REST: BoolKnob = mandate(
        crate::encryption::ENV_ENCRYPT_AT_REST,
        Some(false),
        Legacy::HouseUntrimmed,
    );
    /// #1946 — the open-time rollback check fails closed.
    pub const REQUIRE_ROLLBACK_CHECK: BoolKnob = mandate(
        crate::governance::audit::REQUIRE_ROLLBACK_CHECK_ENV,
        Some(false),
        Legacy::House,
    );
    /// #3113-class — the erasure cold tier stops quarantining rowless bundles.
    pub const ERASURE_RECOVER_QUARANTINE: BoolKnob = hatch(
        crate::erasure::ENV_ERASURE_RECOVER_QUARANTINE,
        Legacy::House,
    );
    /// #2383 — undecryptable rows fail every read closed.
    pub const STRICT_DECRYPT_READS: BoolKnob = mandate(
        crate::storage::ENV_STRICT_DECRYPT_READS,
        Some(false),
        Legacy::House,
    );

    // --- enterprise-federation posture -------------------------------------
    /// #3061 — operator attests the postgres volume is encrypted. A HATCH:
    /// truthy RELAXES certified-posture check #15, so a garbage token must
    /// read as "not attested".
    pub const PG_AT_REST_ATTESTED: BoolKnob = hatch(
        crate::enterprise_federation_posture::ENV_PG_AT_REST_ATTESTED,
        Legacy::House,
    );
    /// #3065 — the certified-posture boot gate.
    pub const REQUIRE_ENTERPRISE_FEDERATION_POSTURE: BoolKnob = mandate(
        crate::enterprise_federation_posture::ENV_REQUIRE_ENTERPRISE_FEDERATION_POSTURE,
        Some(false),
        Legacy::House,
    );

    // --- federation receive (default ON) -----------------------------------
    /// #1718 — inbound transitions must be attested.
    pub const FED_REQUIRE_TRANSITION_SIG: BoolKnob = mandate(
        crate::federation::receive_auth::REQUIRE_TRANSITION_SIG_ENV,
        Some(true),
        Legacy::DefaultOnCaseSensitive,
    );
    /// #1936 — inbound checkpoint resolutions must be attested.
    pub const FED_REQUIRE_CHECKPOINT_SIG: BoolKnob = mandate(
        crate::federation::receive_auth::REQUIRE_CHECKPOINT_SIG_ENV,
        Some(true),
        Legacy::DefaultOnCaseSensitive,
    );
    /// #1464 — inbound third-party writes must carry the author signature.
    pub const FED_REQUIRE_WRITE_SIG: BoolKnob = mandate(
        crate::federation::receive_auth::REQUIRE_WRITE_SIG_ENV,
        Some(crate::federation::receive_auth::FED_REQUIRE_WRITE_SIG_DEFAULT),
        Legacy::TriStateHouseCaseSensitive,
    );
    /// #1843 — inbound signals must verify against the author's key.
    pub const FED_REQUIRE_SIGNAL_SIG: BoolKnob = mandate(
        crate::federation::receive_auth::REQUIRE_SIGNAL_SIG_ENV,
        Some(crate::federation::receive_auth::FED_REQUIRE_SIGNAL_SIG_DEFAULT),
        Legacy::TriStateHouseCaseSensitive,
    );
    /// #1948 / #3619 — quarantine provenance-less inbound writes.
    pub const FED_QUARANTINE_UNATTRIBUTED: BoolKnob = mandate(
        crate::federation::receive_auth::FED_QUARANTINE_UNATTRIBUTED_ENV,
        Some(false),
        Legacy::HouseCaseSensitive,
    );
    /// #1947 — refuse a detected-stale policy epoch.
    pub const FED_REQUIRE_POLICY_CURRENT: BoolKnob = mandate(
        crate::federation::receive_auth::REQUIRE_POLICY_CURRENT_ENV,
        Some(true),
        Legacy::DefaultOnCaseSensitive,
    );
    /// #2447 — confine inbound writes to the peer's namespace scope.
    pub const FED_REQUIRE_PUSH_NAMESPACE_SCOPE: BoolKnob = mandate(
        crate::federation::receive_auth::REQUIRE_PUSH_NAMESPACE_SCOPE_ENV,
        Some(true),
        Legacy::DefaultOnCaseSensitive,
    );
    /// #791 — inbound pushes must carry a verified signature.
    pub const FED_REQUIRE_SIG: BoolKnob = mandate(
        crate::federation::signing::REQUIRE_SIG_ENV,
        Some(true),
        Legacy::DefaultOnCaseSensitive,
    );
    /// #922 — inbound pushes must carry a fresh nonce.
    pub const FED_REQUIRE_NONCE: BoolKnob = mandate(
        crate::federation::signing::REQUIRE_NONCE_ENV,
        Some(true),
        Legacy::DefaultOnCaseSensitive,
    );
    /// #1088 / #1789 — an inbound peer id must resolve to an enrolled key.
    pub const FED_REQUIRE_PEER_ENROLLMENT: BoolKnob = mandate(
        crate::handlers::federation_signing_check::REQUIRE_PEER_ENROLLMENT_ENV,
        Some(true),
        Legacy::DefaultOnCaseInsensitive,
    );
    /// #2448 — outbound federation TLS must verify the peer server cert.
    pub const FED_REQUIRE_SERVER_VERIFY: BoolKnob = mandate(
        crate::tls::FED_REQUIRE_SERVER_VERIFY_ENV,
        Some(true),
        Legacy::DefaultOnCaseSensitive,
    );

    // --- audit / governance require-modes ----------------------------------
    /// #1822 G5b — a missing witness anchor is dirty.
    pub const REQUIRE_WITNESS: BoolKnob = mandate(
        crate::governance::audit::REQUIRE_WITNESS_ENV,
        Some(false),
        Legacy::House,
    );
    /// #1822 G5b — an unbound cause is dirty.
    pub const REQUIRE_CAUSE_BINDING: BoolKnob = mandate(
        crate::governance::audit::REQUIRE_CAUSE_BINDING_ENV,
        Some(false),
        Legacy::House,
    );
    /// #1826 G9 — three-key role separation is required.
    pub const REQUIRE_ROLE_SEPARATION: BoolKnob = mandate(
        crate::governance::audit::REQUIRE_ROLE_SEPARATION_ENV,
        Some(false),
        Legacy::House,
    );
    /// v1.0.0 fail-open remediation — an ungoverned namespace is refused.
    pub const PERMISSIONS_REQUIRE_GOVERNED_NAMESPACE: BoolKnob = mandate(
        crate::governance::refusal::ENV_REQUIRE_GOVERNED_NAMESPACE,
        Some(false),
        Legacy::House,
    );
    /// #1828 G13 — an enrolled identity lineage is required.
    pub const REQUIRE_IDENTITY_LINEAGE: BoolKnob = mandate(
        crate::identity::lineage::REQUIRE_IDENTITY_LINEAGE_ENV,
        Some(false),
        Legacy::House,
    );
    /// #1720 B3 — the owner-lockout guard refuses boot.
    pub const REQUIRE_OWNED_ROWS: BoolKnob = mandate(
        crate::identity::ENV_REQUIRE_OWNED_ROWS,
        Some(false),
        Legacy::House,
    );
    /// #2059 — writes must carry a why-trace.
    pub const REQUIRE_WHY_TRACE: BoolKnob = mandate(
        crate::storage::REQUIRE_WHY_TRACE_ENV,
        Some(false),
        Legacy::House,
    );
    /// #2060 — an authorship rewrite is refused.
    pub const REQUIRE_IMMUTABLE_AUTHORSHIP: BoolKnob = mandate(
        crate::storage::REQUIRE_IMMUTABLE_AUTHORSHIP_ENV,
        Some(false),
        Legacy::House,
    );
    /// #3618 — attestation on every write surface. Unset keeps the
    /// per-surface default the caller owns.
    pub const REQUIRE_AGENT_ATTESTATION: BoolKnob = mandate(
        crate::identity::attest::ENV_REQUIRE_AGENT_ATTESTATION,
        None,
        Legacy::TriStateOneTrueUntrimmed,
    );

    // --- recall integrity --------------------------------------------------
    /// #1005 G4 — refuse mismatched embedding dimensions.
    pub const REQUIRE_DIM_MATCH: BoolKnob = mandate(
        crate::hnsw::ENV_REQUIRE_DIM_MATCH,
        Some(false),
        Legacy::House,
    );
    /// #2167 — refuse a heterogeneous embedding space.
    pub const REQUIRE_EMBED_MODEL_MATCH: BoolKnob = mandate(
        crate::hnsw::ENV_REQUIRE_EMBED_MODEL_MATCH,
        Some(false),
        Legacy::House,
    );
}

/// The pre-#3200 reader grammars, kept ONLY to tell an operator when a token
/// changed meaning (R4 / w2). Nothing reads a knob through them. Remove at
/// v1.1 together with [`meaning_changes`].
pub mod legacy {
    /// One pre-#3200 reader shape. `classify` returns the explicit value the
    /// old reader derived, `None` when it fell through to the next layer.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum Legacy {
        /// `1|true|yes|on`, trimmed, case-insensitive; anything else off.
        House,
        /// `1|true|yes|on`, trimmed, case-SENSITIVE; anything else off.
        HouseCaseSensitive,
        /// `1|true|yes|on`, lowercased but NOT trimmed; anything else off.
        HouseUntrimmed,
        /// Exact `1` or case-insensitive `true`, untrimmed; anything else off.
        OneOrTrue,
        /// Exact `1` only; anything else off.
        ExactOne,
        /// Default ON; off only for `0|false|no|off`, trimmed, case-SENSITIVE.
        DefaultOnCaseSensitive,
        /// Default ON; off only for `0|false|no|off`, trimmed, case-insensitive.
        DefaultOnCaseInsensitive,
        /// `1|true` on, `0|false` off (trimmed, case-insensitive); else falls through.
        TriStateOneTrueTrimmed,
        /// `1|true` on, `0|false` off (untrimmed, case-insensitive); else falls through.
        TriStateOneTrueUntrimmed,
        /// `1|true|yes|on` on, `0|false|no|off` off (trimmed, case-SENSITIVE);
        /// else falls through.
        TriStateHouseCaseSensitive,
        /// `1|true|yes|on` on, `0|false|no|off|""` off (lowercased, untrimmed);
        /// else falls through.
        TriStateHouseUntrimmed,
    }

    const ON: [&str; 4] = ["1", "true", "yes", "on"];
    const OFF: [&str; 4] = ["0", "false", "no", "off"];

    fn one_or_true(v: &str) -> bool {
        v == "1" || v.eq_ignore_ascii_case("true")
    }

    fn zero_or_false(v: &str) -> bool {
        v == "0" || v.eq_ignore_ascii_case("false")
    }

    impl Legacy {
        /// What the pre-#3200 reader made of `v`.
        #[must_use]
        pub fn classify(self, v: &str) -> Option<bool> {
            let trimmed = v.trim();
            let lower = v.to_ascii_lowercase();
            match self {
                Self::House => Some(ON.iter().any(|t| trimmed.eq_ignore_ascii_case(t))),
                Self::HouseCaseSensitive => Some(ON.contains(&trimmed)),
                Self::HouseUntrimmed => Some(ON.contains(&lower.as_str())),
                Self::OneOrTrue => Some(one_or_true(v)),
                Self::ExactOne => Some(v == "1"),
                Self::DefaultOnCaseSensitive => Some(!OFF.contains(&trimmed)),
                Self::DefaultOnCaseInsensitive => {
                    Some(!OFF.iter().any(|t| trimmed.eq_ignore_ascii_case(t)))
                }
                Self::TriStateOneTrueTrimmed => {
                    if one_or_true(trimmed) {
                        Some(true)
                    } else if zero_or_false(trimmed) {
                        Some(false)
                    } else {
                        None
                    }
                }
                Self::TriStateOneTrueUntrimmed => {
                    if zero_or_false(v) {
                        Some(false)
                    } else if one_or_true(v) {
                        Some(true)
                    } else {
                        None
                    }
                }
                Self::TriStateHouseCaseSensitive => {
                    if OFF.contains(&trimmed) {
                        Some(false)
                    } else if ON.contains(&trimmed) {
                        Some(true)
                    } else {
                        None
                    }
                }
                Self::TriStateHouseUntrimmed => {
                    if ON.contains(&lower.as_str()) {
                        Some(true)
                    } else if lower.is_empty() || OFF.contains(&lower.as_str()) {
                        Some(false)
                    } else {
                        None
                    }
                }
            }
        }
    }
}

/// Render an explicit value for an operator message.
fn describe(value: Option<bool>) -> &'static str {
    match value {
        Some(true) => "ON",
        Some(false) => "OFF",
        None => "unset (the next layer or default applied)",
    }
}

/// The meaning-changed WARN for one knob and token, or `None` when the new
/// grammar reads the token exactly as the pre-#3200 reader did. A knob with a
/// compiled default compares effective values, so an unset-versus-default
/// difference that changes nothing is not reported.
#[must_use]
pub fn meaning_change(knob: &BoolKnob, value: &str) -> Option<String> {
    let new = resolve(Some(value), knob.polarity);
    let old = knob.legacy.classify(value);
    let (new_eff, old_eff) = match knob.default {
        Some(d) => (Some(new.unwrap_or(d)), Some(old.unwrap_or(d))),
        None => (new, old),
    };
    (new_eff != old_eff).then(|| {
        format!(
            "{env}={value:?} changed meaning in v1.0.0 (#3200): the previous reader \
             read it as {old}, the shared grammar reads it as {new}. Accepted: {ACCEPTED_GRAMMAR}.",
            env = knob.env,
            old = describe(old_eff),
            new = describe(new_eff),
        )
    })
}

/// The boot refusal for one unrecognised token.
fn unrecognised(knob: &BoolKnob, shown: &str) -> String {
    format!(
        "{env}={shown} is not a recognised boolean. Accepted: {ACCEPTED_GRAMMAR}. \
         Fix or unset {env} (#3200).",
        env = knob.env,
    )
}

/// The pre-runtime sweep (R2 + R4). Returns the one-shot meaning-changed
/// warnings, or an error naming EVERY registered knob whose value is outside
/// the grammar. MANDATE and HATCH knobs refuse alike: a typo on a hatch must
/// be neither a silent widen nor a silent no-op.
///
/// # Errors
/// One or more registered knobs carry an unrecognised (or non-UTF-8) value.
pub fn sweep() -> Result<Vec<String>, String> {
    let mut refusals = Vec::new();
    let mut warnings = Vec::new();
    for knob in REGISTRY {
        match env_token(knob.env) {
            None => {}
            Some(Err(())) => refusals.push(unrecognised(knob, "<non-UTF-8 value>")),
            Some(Ok(v)) => {
                if parse(Some(&v)) == FlagToken::Unrecognised {
                    refusals.push(unrecognised(knob, &format!("{v:?}")));
                } else if let Some(w) = meaning_change(knob, &v) {
                    warnings.push(w);
                }
            }
        }
    }
    if refusals.is_empty() {
        Ok(warnings)
    } else {
        Err(refusals.join("\n"))
    }
}

/// Pre-runtime entry point, called from the binary's `fn main()` before the
/// `asi-hard` posture pins its knobs. Prints the one-shot warnings to stderr
/// (no tracing subscriber exists yet).
///
/// # Errors
/// Propagates [`sweep`]'s refusal.
pub fn enforce_at_boot_pre_runtime() -> anyhow::Result<()> {
    let warnings = sweep().map_err(|e| anyhow::anyhow!(e))?;
    for w in warnings {
        eprintln!("ai-memory: WARN {w}");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const TRUTHY: &[&str] = &[
        "1", "true", "TRUE", "True", "yes", "YES", "on", "On", " 1", "true ",
    ];
    const FALSY: &[&str] = &[
        "0", "false", "FALSE", "no", "No", "off", "OFF", " 0 ", "\tfalse",
    ];
    const UNSET: &[&str] = &["", " ", "\t", "\n"];
    const UNRECOGNISED: &[&str] = &["maybe", "2", "enable", "y", "n", "t", "1 1", "truee", "on!"];

    #[test]
    fn grammar_table_classifies_every_token_3200() {
        for t in TRUTHY {
            assert_eq!(parse(Some(t)), FlagToken::True, "{t:?}");
            assert!(is_truthy(t), "{t:?}");
            assert!(!is_falsy(t), "{t:?}");
        }
        for t in FALSY {
            assert_eq!(parse(Some(t)), FlagToken::False, "{t:?}");
            assert!(is_falsy(t), "{t:?}");
            assert!(!is_truthy(t), "{t:?}");
        }
        for t in UNSET {
            assert_eq!(parse(Some(t)), FlagToken::Unset, "{t:?}");
        }
        assert_eq!(parse(None), FlagToken::Unset);
        for t in UNRECOGNISED {
            assert_eq!(parse(Some(t)), FlagToken::Unrecognised, "{t:?}");
            assert!(!is_truthy(t) && !is_falsy(t), "{t:?}");
        }
    }

    #[test]
    fn unrecognised_fails_closed_by_polarity_3200() {
        for t in UNRECOGNISED {
            assert_eq!(resolve(Some(t), Polarity::Mandate), Some(true), "{t:?}");
            assert_eq!(resolve(Some(t), Polarity::Hatch), Some(false), "{t:?}");
        }
    }

    #[test]
    fn unset_falls_through_and_recognised_tokens_win_3200() {
        for polarity in [Polarity::Mandate, Polarity::Hatch] {
            for t in UNSET {
                assert_eq!(resolve(Some(t), polarity), None, "{t:?}");
                assert!(resolve_or(Some(t), polarity, true));
                assert!(!resolve_or(Some(t), polarity, false));
            }
            assert_eq!(resolve(None, polarity), None);
            for t in TRUTHY {
                assert!(resolve_or(Some(t), polarity, false), "{t:?}");
            }
            for t in FALSY {
                assert!(!resolve_or(Some(t), polarity, true), "{t:?}");
            }
        }
    }
}
