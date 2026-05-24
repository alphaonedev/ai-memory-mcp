// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! ANSI color output for CLI — zero dependencies.
//!
//! pm-v3.1 PR8 (issue #1174) — color enablement is determined ONCE at
//! process boot from `std::io::stdout().is_terminal()` and frozen for
//! the lifetime of the process via `OnceLock<bool>`. The pre-PR8
//! shape used a mutable `AtomicBool` which gave production callers no
//! protection against accidental late mutation. Tests that need to
//! force colour off route through a thread-local override consulted
//! by `enabled()` (compiled out of non-test builds).

use std::io::IsTerminal;
use std::sync::OnceLock;

/// One-shot snapshot of the boot-time `stdout` is-a-terminal probe.
/// Set exactly once by [`init`]; subsequent calls are no-ops thanks
/// to `OnceLock::set` semantics (first-writer-wins). Production code
/// SHOULD call [`init`] exactly once at process start (see
/// `src/main.rs`).
static COLOR_ENABLED: OnceLock<bool> = OnceLock::new();

pub fn init() {
    // `OnceLock::set` returns `Err` if already initialised; benign
    // for double-init paths (tests, repeat embedder bootstrap), so
    // the return value is intentionally discarded.
    let _ = COLOR_ENABLED.set(std::io::stdout().is_terminal());
}

fn enabled() -> bool {
    #[cfg(test)]
    if let Some(forced) = test_override::get() {
        return forced;
    }
    // Default true matches the pre-PR8 `AtomicBool::new(true)` posture
    // — if production code reads colour state before `init` runs the
    // colourised path stays on (the prior behaviour).
    *COLOR_ENABLED.get().unwrap_or(&true)
}

#[cfg(test)]
mod test_override {
    use std::cell::Cell;

    thread_local! {
        static OVERRIDE: Cell<Option<bool>> = const { Cell::new(None) };
    }

    pub(super) fn get() -> Option<bool> {
        OVERRIDE.with(Cell::get)
    }

    pub(super) fn set(value: Option<bool>) {
        OVERRIDE.with(|cell| cell.set(value));
    }
}

fn wrap(code: &str, text: &str) -> String {
    if enabled() {
        format!("\x1b[{code}m{text}\x1b[0m")
    } else {
        text.to_string()
    }
}

// Tier colors
pub fn short(text: &str) -> String {
    wrap("91", text)
} // red
pub fn mid(text: &str) -> String {
    wrap("93", text)
} // yellow
pub fn long(text: &str) -> String {
    wrap("92", text)
} // green

// Semantic colors
pub fn dim(text: &str) -> String {
    wrap("2", text)
}
pub fn bold(text: &str) -> String {
    wrap("1", text)
}
pub fn cyan(text: &str) -> String {
    wrap("96", text)
}

/// Colorize `text` according to the caller-supplied tier wire string.
///
/// The string literals in the match arms below are the **canonical
/// deserializer** for the `Tier` enum's wire form — they pair with
/// `crate::models::Tier::as_str` (Short → "short" / Mid → "mid" /
/// Long → "long"). They MUST stay as raw literals here because this
/// is the boundary where a caller-supplied `&str` (config, CLI flag,
/// JSON value) gets dispatched; the enum has nothing to plug in at
/// this point. Anywhere else that constructs a tier wire value should
/// route through `Tier::<X>.as_str()`. See pm-v3.1 PR6 (#1174) for the
/// sweep that pinned this invariant.
pub fn tier_color(tier: &str, text: &str) -> String {
    match tier {
        "short" => short(text),
        "mid" => mid(text),
        "long" => long(text),
        _ => text.to_string(),
    }
}

/// Priority as a colored bar: ████░░░░░░
pub fn priority_bar(p: i32) -> String {
    // B4 (R2-LOW) — clamp range is 1..=10 so try_from is infallible;
    // use `unwrap_or` to align with the campaign's no-panic discipline
    // (defensive against future refactors that drop the `clamp` call).
    let filled = usize::try_from(p.clamp(1, 10)).unwrap_or(1);
    let empty = 10 - filled;
    let bar = format!("{}{}", "█".repeat(filled), "░".repeat(empty));
    if p >= 8 {
        wrap("92", &bar)
    } else if p >= 5 {
        wrap("93", &bar)
    } else {
        wrap("91", &bar)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// pm-v3.1 PR8 (issue #1174) — thread-local override removes the
    /// need for a process-wide `Mutex<()>` to serialise tests. Each
    /// `cargo test` worker gets its own override slot, so the
    /// previously-required `--test-threads=1` style of serialisation
    /// is gone.
    fn with_color_off<F: FnOnce()>(f: F) {
        test_override::set(Some(false));
        f();
        test_override::set(None);
    }

    #[test]
    fn tier_colors_no_ansi() {
        with_color_off(|| {
            assert_eq!(short("test"), "test");
            assert_eq!(mid("test"), "test");
            assert_eq!(long("test"), "test");
        });
    }

    #[test]
    fn semantic_colors_no_ansi() {
        with_color_off(|| {
            assert_eq!(dim("test"), "test");
            assert_eq!(bold("test"), "test");
            assert_eq!(cyan("test"), "test");
        });
    }

    #[test]
    fn tier_color_dispatch() {
        use crate::models::Tier;
        with_color_off(|| {
            assert_eq!(tier_color(Tier::Short.as_str(), "x"), "x");
            assert_eq!(tier_color(Tier::Mid.as_str(), "x"), "x");
            assert_eq!(tier_color(Tier::Long.as_str(), "x"), "x");
            assert_eq!(tier_color("unknown", "x"), "x");
        });
    }

    #[test]
    fn priority_bar_length() {
        with_color_off(|| {
            let bar = priority_bar(5);
            // 5 filled + 5 empty = 10 chars (each is multi-byte unicode)
            assert!(bar.contains("█"));
            assert!(bar.contains("░"));
        });
    }

    #[test]
    fn priority_bar_clamps() {
        with_color_off(|| {
            let bar_min = priority_bar(0); // clamps to 1
            let bar_max = priority_bar(15); // clamps to 10
            assert!(bar_min.contains("░"));
            assert!(!bar_max.contains("░")); // all filled
        });
    }

    #[test]
    fn wrap_with_color_enabled() {
        test_override::set(Some(true));
        let result = wrap("91", "red");
        assert!(result.contains("\x1b[91m"));
        assert!(result.contains("\x1b[0m"));
        assert!(result.contains("red"));
        test_override::set(None);
    }
}
