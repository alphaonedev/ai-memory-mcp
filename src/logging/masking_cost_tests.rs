// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! Count bytes examined by URL discovery and authority searches, without clocks.
//! The counter measures actual search distances, including unsuccessful searches.

use std::cell::Cell;

thread_local! {
    static SEARCH_BYTES: Cell<usize> = const { Cell::new(0) };
}

const SMALL_REPEAT: usize = 256;
const SCALE: usize = 10;
const LINEAR_ALLOWANCE: usize = 4;

pub(super) fn visited(bytes: usize) {
    SEARCH_BYTES.with(|count| count.set(count.get().saturating_add(bytes)));
}

pub(super) fn reset_visited() {
    SEARCH_BYTES.with(|count| count.set(0));
}

pub(super) fn total_visited() -> usize {
    SEARCH_BYTES.with(Cell::get)
}

fn measured(input: &str) -> usize {
    SEARCH_BYTES.with(|count| count.set(0));
    std::hint::black_box(super::redact_connection_options(input));
    SEARCH_BYTES.with(Cell::get)
}

fn assert_linear(label: &str, make: impl Fn(usize) -> String) {
    let small = make(SMALL_REPEAT);
    let large = make(SMALL_REPEAT * SCALE);
    let small_work = measured(&small);
    let large_work = measured(&large);
    println!(
        "{label}: bytes={}/{}, search_bytes={small_work}/{large_work}",
        small.len(),
        large.len()
    );
    assert!(
        small_work > 0,
        "{label}: the search counter must observe work"
    );
    assert!(
        large_work <= small_work * SCALE * LINEAR_ALLOWANCE,
        "{label}: tenfold input caused superlinear search work: {small_work} -> {large_work}"
    );
}

#[test]
fn url_authority_separator_cost_is_linear_8205_r7() {
    assert_linear("F1 URL separators", |count| {
        format!("https://{}", "a=1:".repeat(count))
    });
}

#[test]
fn ambiguous_url_option_separator_cost_is_linear_8205_r7() {
    assert_linear("F1 ambiguous URL options", |count| {
        format!("https://user:secret {}", "limit=10 ".repeat(count))
    });
}

#[test]
fn credential_lines_search_cost_is_linear_8205_r7() {
    assert_linear("F2 credential lines", |count| {
        "password=private\n".repeat(count)
    });
}
