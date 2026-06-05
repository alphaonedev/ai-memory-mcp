// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! Federation identity.
//!
//! Phase 1 (this commit) — [`resolver`] resolves the `sender_agent_id` a
//! node signs and presents as, de-hardcoding the historical
//! `host:<hostname>` bootstrap expression behind an explicit precedence
//! (env > operator config > hostname default).
//!
//! Subsequent phases (see `.local-runs/design/ADR-001-...`) add
//! CA-rooted short-lived credentials, trust bundles, the first-party
//! issuer, and mTLS attestation in sibling submodules — so federation
//! owns its own identity surface, distinct from the low-level crypto in
//! [`crate::identity`].

pub mod resolver;

pub use resolver::{FED_IDENTITY_ENV, default_hostname_identity, resolve_federation_identity};
