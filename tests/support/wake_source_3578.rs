// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

/// Keep literals opaque to delimiter handling but visible to config/path checks.
/// Nested block comments and Rust raw strings must not manufacture code edges.
pub fn tokens(source: &str) -> Vec<&str> {
    let b = source.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        let start = i;
        if b[i].is_ascii_whitespace() {
            i += 1;
        } else if b[i..].starts_with(b"//") {
            i += b[i..]
                .iter()
                .position(|&c| c == b'\n')
                .unwrap_or(b.len() - i);
        } else if b[i..].starts_with(b"/*") {
            i += 2;
            let mut depth = 1;
            while depth > 0 {
                assert!(i < b.len(), "unterminated comment");
                if b[i..].starts_with(b"/*") {
                    depth += 1;
                    i += 2;
                } else if b[i..].starts_with(b"*/") {
                    depth -= 1;
                    i += 2;
                } else {
                    i += 1;
                }
            }
        } else {
            // Include raw byte/C-string prefixes: treating br#"\\"# as a
            // normal escaped string could swallow the following code.
            let raw_start = if matches!(b[i], b'b' | b'c') && b.get(i + 1) == Some(&b'r') {
                i + 1
            } else {
                i
            };
            let mut raw_quote = raw_start + 1;
            if b[raw_start] == b'r' {
                while raw_quote < b.len() && b[raw_quote] == b'#' {
                    raw_quote += 1;
                }
            }
            if b[raw_start] == b'r' && b.get(raw_quote) == Some(&b'"') {
                let hashes = raw_quote - raw_start - 1;
                i = raw_quote + 1;
                loop {
                    assert!(i < b.len(), "unterminated raw string");
                    if b[i] == b'"'
                        && b.get(i + 1..i + 1 + hashes)
                            .is_some_and(|tail| tail.iter().all(|&c| c == b'#'))
                    {
                        i += 1 + hashes;
                        break;
                    }
                    i += 1;
                }
            } else if b[i] == b'"'
                || (b[i] == b'\''
                    && (source[i + 1..]
                        .chars()
                        .next()
                        .is_some_and(|ch| b.get(i + 1 + ch.len_utf8()) == Some(&b'\''))
                        || b.get(i + 1) == Some(&b'\\')))
            {
                let quote = b[i];
                i += 1;
                loop {
                    assert!(i < b.len(), "unterminated literal");
                    if b[i] == b'\\' {
                        i += 2;
                    } else if b[i] == quote {
                        i += 1;
                        break;
                    } else {
                        i += 1;
                    }
                }
            } else if b[i].is_ascii_alphanumeric() || b[i] == b'_' || b[i] >= 128 {
                i += 1;
                while i < b.len() && (b[i].is_ascii_alphanumeric() || b[i] == b'_' || b[i] >= 128) {
                    i += 1;
                }
            } else if b[i..].starts_with(b"::") {
                i += 2;
            } else {
                i += 1;
            }
            out.push(&source[start..i]);
        }
    }
    out
}

pub fn group_end(t: &[&str], start: usize) -> usize {
    let close = match t[start] {
        "{" => "}",
        "[" => "]",
        "(" => ")",
        _ => panic!("not a group"),
    };
    let mut i = start + 1;
    while i < t.len() {
        if t[i] == close {
            return i + 1;
        }
        if matches!(t[i], "{" | "[" | "(") {
            i = group_end(t, i);
        } else {
            i += 1;
        }
    }
    panic!("unclosed source group");
}

pub fn production_tokens(source: &str) -> Vec<&str> {
    let t = tokens(source);
    let mut out = Vec::new();
    let mut i = 0;
    while i < t.len() {
        if t[i..].starts_with(&["#", "[", "cfg", "(", "test", ")", "]"]) {
            let mut item = i + 7;
            while t.get(item) == Some(&"#") && t.get(item + 1) == Some(&"[") {
                item = group_end(&t, item + 1);
            }
            if t.get(item) == Some(&"mod") && t.get(item + 2) == Some(&"{") {
                i = group_end(&t, item + 2);
                continue;
            }
        }
        out.push(t[i]);
        i += 1;
    }
    out
}

/// End (exclusive token index) of the single item that starts at `item`, which
/// follows a `#[cfg(test)]` attribute (#6321). `mod`, `impl`, `fn`, `struct`,
/// `enum` and `trait` items end at their `{ ... }` body (or a bare `;`);
/// `const`, `static`, `use` and `type` items end at their `;`, skipping any
/// brace group inside the initialiser. `None` when no item can be delimited,
/// in which case the attribute is left counted as production (fail closed).
#[allow(dead_code)]
fn test_item_end(t: &[&str], item: usize) -> Option<usize> {
    let mut i = item;
    while matches!(t.get(i), Some(&("pub" | "unsafe" | "async" | "extern" | "default"))) {
        i += 1;
        if t.get(i) == Some(&"(") {
            i = group_end(t, i);
        }
    }
    let to_semicolon = match t.get(i)? {
        &("static" | "use" | "type") => true,
        &"const" => !matches!(t.get(i + 1), Some(&("fn" | "unsafe" | "async" | "extern"))),
        _ => false,
    };
    while i < t.len() {
        match t[i] {
            ";" => return Some(i + 1),
            "{" if !to_semicolon => return Some(group_end(t, i)),
            "{" | "[" | "(" => i = group_end(t, i),
            _ => i += 1,
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::production_tokens;

    /// #6321 — test-only fn, impl, const, static and use items outside a test
    /// module leave the production token stream unchanged.
    #[test]
    fn cfg_test_items_outside_a_test_module_are_not_production_6321() {
        let base = "fn decode() { metadata() }";
        for seam in [
            "#[cfg(test)] pub(crate) fn start_injectable(a: Option<(u8, u8)>) -> X { store(); }",
            "#[cfg(test)] impl Foo { fn seam(&self) { store(); } }",
            "#[cfg(test)] const FIXTURE: Foo = Foo { a: 1 };",
            "#[cfg(test)] static GATE: Mutex<()> = Mutex::new(());",
            "#[cfg(test)] #[allow(dead_code)] const fn seam() -> u8 { 1 }",
            "#[cfg(test)] use crate::mcp::handle_notify;",
        ] {
            let with = format!("{seam} {base}");
            assert_eq!(
                production_tokens(base),
                production_tokens(&with),
                "should skip: {seam}"
            );
        }
        let tail = format!("{base} #[cfg(feature = \"x\")] fn new_decoder() {{ store(); }}");
        assert_ne!(production_tokens(base), production_tokens(&tail));
    }
}
