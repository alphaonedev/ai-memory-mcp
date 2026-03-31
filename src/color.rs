//! ANSI color output for CLI — zero dependencies.

use std::io::IsTerminal;

static mut COLOR_ENABLED: bool = true;

pub fn init() {
    unsafe {
        COLOR_ENABLED = std::io::stdout().is_terminal();
    }
}

fn enabled() -> bool {
    unsafe { COLOR_ENABLED }
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
    let filled = p.clamp(1, 10) as usize;
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
