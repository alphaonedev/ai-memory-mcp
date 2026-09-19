// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 #3717 — every key ROLE a deployment needs, in ONE table, with a
//! typed state per role and ONE plan that `keys init --dry-run`, the real
//! `keys init`, `keys status` and the doctor section all consume.
//!
//! The rejected first cut (`073a14096`) judged every role by a single
//! `complete: bool` and minted through each role's own generator whenever
//! that bool was false — so a half-present role (private half lost,
//! interrupted write, offline CA key) was "minted" OVER: `owner.priv`
//! overwritten (F1), `<agent>.x25519.pub` overwritten when its `.priv` was
//! lost (F2), the singleton CA + leaf rewritten when `local-ca.key` was
//! offline (F4). [`roles::RoleState`] replaces the bool: an ABSENT role is
//! minted, a COMPLETE one is left alone, a RECOVERABLE partial is repaired
//! from the surviving private half, and a LOST-PRIVATE or UNREADABLE partial
//! REFUSES BEFORE ANY WRITE. [`roles::plan`] is pure and is the one decision
//! site; [`roles::execute`] only carries out a plan.

pub mod roles;
