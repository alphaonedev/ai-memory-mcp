// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v0.8.0 Pillar 1 (#1709) — signed-signal [`Signal`] model. Backs the v60
//! `signals` table (typed, Ed25519-signed inter-agent messages). The SAL
//! `signal_*` methods + `memory_signal_*` MCP tools + the signing /
//! verification logic operate over these types in subsequent units; this
//! model is storage-only.

use serde::{Deserialize, Serialize};

/// Type of a signed [`Signal`] (the `signals.signal_type` column).
///
/// The canonical wire/DB spellings are
/// `authorize | notify | request | response | broadcast`. The set is
/// enforced by the SAL layer (not a SQL CHECK, so a future type needs no
/// migration). Defaults to [`SignalType::Notify`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum SignalType {
    /// An authorization grant / delegation signal.
    Authorize,
    /// A fire-and-forget notification (the default).
    #[default]
    Notify,
    /// A request expecting a `response`.
    Request,
    /// A response threaded back onto a `request` via `in_reply_to`.
    Response,
    /// A namespace-wide broadcast (`to_agent` NULL).
    Broadcast,
}

impl SignalType {
    /// Canonical wire/DB spelling.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Authorize => "authorize",
            Self::Notify => "notify",
            Self::Request => "request",
            Self::Response => "response",
            Self::Broadcast => "broadcast",
        }
    }

    /// Parse a DB/wire spelling. `None` on an unknown value.
    #[must_use]
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "authorize" => Some(Self::Authorize),
            "notify" => Some(Self::Notify),
            "request" => Some(Self::Request),
            "response" => Some(Self::Response),
            "broadcast" => Some(Self::Broadcast),
            _ => None,
        }
    }
}

/// A typed, signed inter-agent signal — one row in the Pillar-1 `signals`
/// table. Mirrors the v60 `signals` table 1:1.
///
/// `reference_ids` is renamed from the ROADMAP's `references` because
/// `references` is a SQL reserved word in both sqlite and postgres; the
/// rename is carried through the migration + postgres schema as well.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Signal {
    pub id: String,
    pub namespace: String,
    pub from_agent: String,
    /// Recipient agent; `None` = broadcast within the namespace.
    pub to_agent: Option<String>,
    pub subject: String,
    /// JSON-typed payload.
    pub body: serde_json::Value,
    pub signal_type: SignalType,
    /// Threads a `response` back onto its `request` (self-referential id).
    pub in_reply_to: Option<String>,
    pub correlation_id: Option<String>,
    /// JSON array of related signal/memory ids. Renamed from the ROADMAP's
    /// `references` (SQL reserved word).
    pub reference_ids: serde_json::Value,
    /// Epoch seconds.
    pub created_at: i64,
    pub expires_at: Option<i64>,
    pub delivered_at: Option<i64>,
    pub read_at: Option<i64>,
    pub acknowledged_at: Option<i64>,
    /// Ed25519 signature over the canonical signal content.
    pub signature: Vec<u8>,
    /// Sender's Ed25519 public key.
    pub sender_pubkey: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signal_type_roundtrips_str() {
        for s in [
            SignalType::Authorize,
            SignalType::Notify,
            SignalType::Request,
            SignalType::Response,
            SignalType::Broadcast,
        ] {
            assert_eq!(SignalType::from_str(s.as_str()), Some(s));
        }
    }

    #[test]
    fn signal_type_from_str_unknown_is_none() {
        assert_eq!(SignalType::from_str("bogus"), None);
        assert_eq!(SignalType::from_str(""), None);
        assert_eq!(SignalType::from_str("Notify"), None); // case-sensitive
    }

    #[test]
    fn signal_type_default_is_notify() {
        assert_eq!(SignalType::default(), SignalType::Notify);
    }
}
