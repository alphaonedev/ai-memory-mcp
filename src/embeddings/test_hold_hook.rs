// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #4089 — a test-only stand-in for a CPU-bound model forward pass, so the
//! HTTP embed/rerank sites can be driven end to end through the real router
//! with a REAL [`super::Embedder`] value (the handlers hold the concrete type, so a
//! trait-object double cannot be injected).
//!
//! A test arms a hold under a unique remote model name and builds the
//! embedder with [`embedder`]. Every embed by THAT embedder (and no other)
//! then returns a deterministic unit vector without touching the network;
//! an input containing the armed `marker` first reports that the embed has
//! started and then blocks the CALLING thread for `hold`, which is exactly
//! what a candle forward does to whichever thread runs it. A handler that
//! embeds inline therefore pins its tokio worker for `hold`; one that uses
//! the blocking pool does not.
//!
//! Compiled only for unit tests and for the `test-support` feature the
//! integration tests enable (the crate's self dev-dependency), never into a
//! release build.

use std::sync::mpsc::{Receiver, Sender, channel};
use std::sync::{Arc, LazyLock, Mutex, PoisonError};
use std::time::Duration;

struct Hold {
    model: String,
    marker: String,
    hold: Duration,
    entered: Option<Sender<()>>,
    /// #8907 — what a marked embed does after any hold.
    effect: Effect,
}

/// #8907 — the outcome of a marked embed on an armed model.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Effect {
    /// Deterministic vectors (the default of [`arm`]).
    Vectors,
    /// The provider-error stand-in: [`ARMED_FAILURE`].
    Fail,
    /// The provider answers with one EMPTY vector per input.
    EmptyVector,
    /// The embed panics, so the blocking task never completes.
    Panic,
}

/// #8907 — the panic text of an [`Effect::Panic`] embed.
pub const ARMED_PANIC: &str = "test hold hook: armed embed panic";

/// #8907 — the error text a [`arm_fail`]-armed embed returns for a marked
/// input, so a test can assert the exact degraded reason.
pub const ARMED_FAILURE: &str = "test hold hook: armed embed failure";

static HOLDS: LazyLock<Mutex<Vec<Hold>>> = LazyLock::new(|| Mutex::new(Vec::new()));

/// Arm `model`: see the module docs. Returns the receiver that gets ONE
/// message when the first marked embed starts. Re-arming a model
/// replaces its previous hold.
#[must_use]
pub fn arm(model: &str, marker: &str, hold: Duration) -> Receiver<()> {
    let (tx, rx) = channel();
    let mut holds = HOLDS.lock().unwrap_or_else(PoisonError::into_inner);
    holds.retain(|h| h.model != model);
    holds.push(Hold {
        model: model.to_string(),
        marker: marker.to_string(),
        hold,
        entered: Some(tx),
        effect: Effect::Vectors,
    });
    rx
}

/// #8907 — arm `model` so every embed whose input carries `marker` FAILS
/// with [`ARMED_FAILURE`] (no hold, no network); unmarked inputs get the
/// usual deterministic vectors. Re-arming a model replaces its previous
/// hold.
pub fn arm_fail(model: &str, marker: &str) {
    arm_effect(model, marker, Effect::Fail);
}

/// #8907 — arm `model` so every embed whose input carries `marker` has
/// `effect` (no hold, no network); unmarked inputs get the usual
/// deterministic vectors. Re-arming a model replaces its previous hold.
pub fn arm_effect(model: &str, marker: &str, effect: Effect) {
    let mut holds = HOLDS.lock().unwrap_or_else(PoisonError::into_inner);
    holds.retain(|h| h.model != model);
    holds.push(Hold {
        model: model.to_string(),
        marker: marker.to_string(),
        hold: Duration::ZERO,
        entered: None,
        effect,
    });
}

/// Remove the hold for `model` (idempotent).
pub fn disarm(model: &str) {
    HOLDS
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .retain(|h| h.model != model);
}

/// A remote [`super::Embedder`] named `model` with `dim`-wide vectors.
/// Its client points at an unroutable address and is never used while
/// the model is armed.
///
/// # Errors
///
/// The HTTP client cannot be built.
pub fn embedder(model: &str, dim: usize) -> anyhow::Result<super::Embedder> {
    let client =
        crate::llm::OllamaClient::new_with_url_no_health_check("http://127.0.0.1:9", model)?;
    Ok(super::Embedder::new_remote(
        Arc::new(client),
        model.to_string(),
        dim,
    ))
}

/// Deterministic unit vector for `text` (FNV-1a seeded), `dim` wide.
fn vector_for(text: &str, dim: usize) -> Vec<f32> {
    let mut seed: u64 = 0xcbf2_9ce4_8422_2325;
    for b in text.bytes() {
        seed ^= u64::from(b);
        seed = seed.wrapping_mul(0x0100_0000_01b3);
    }
    let raw: Vec<f32> = (0..dim)
        .map(|i| {
            let mixed = seed.wrapping_add(u64::try_from(i).unwrap_or(u64::MAX));
            f32::from(u16::try_from(mixed % 1000).unwrap_or(0)) + 1.0
        })
        .collect();
    let norm = raw.iter().map(|x| x * x).sum::<f32>().sqrt();
    raw.into_iter().map(|x| x / norm).collect()
}

/// `Some(vectors)` when `model` is armed (after holding the calling
/// thread if any input carries the marker); `None` otherwise, so every
/// other embedder behaves exactly as in production.
pub(super) fn intercept(
    model: &str,
    dim: usize,
    texts: &[&str],
) -> Option<anyhow::Result<Vec<Vec<f32>>>> {
    let (hold, entered, effect) = {
        let mut holds = HOLDS.lock().unwrap_or_else(PoisonError::into_inner);
        let h = holds.iter_mut().find(|h| h.model == model)?;
        if texts.iter().any(|t| t.contains(h.marker.as_str())) {
            (Some(h.hold), h.entered.take(), h.effect)
        } else {
            (None, None, Effect::Vectors)
        }
    };
    if let Some(hold) = hold {
        if let Some(tx) = entered {
            // The receiver may already be gone (test finished); the
            // hold itself is what matters.
            let _ = tx.send(());
        }
        std::thread::sleep(hold);
    }
    match effect {
        Effect::Vectors => Some(Ok(texts.iter().map(|t| vector_for(t, dim)).collect())),
        Effect::Fail => Some(Err(anyhow::anyhow!(ARMED_FAILURE))),
        Effect::EmptyVector => Some(Ok(texts.iter().map(|_| Vec::new()).collect())),
        Effect::Panic => panic!("{ARMED_PANIC}"),
    }
}
