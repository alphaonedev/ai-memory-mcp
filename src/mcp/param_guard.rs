// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #3171 — boundary guards for MCP `tools/call` argument extraction.
//!
//! MCP tool input schemas are schemars-derived from the per-tool
//! `*Request` structs, but the handlers read the raw `arguments` bag
//! (`params.get(...)` / `params["..."]`) rather than deserializing that
//! struct — and there is **no runtime JSON-Schema validation on the MCP
//! path**. A value whose JSON type or domain contradicts the advertised
//! schema therefore does not fail: it silently takes the handler's
//! fallback branch. The #3171 tool-contract audit found four shapes of
//! that, each of which FAILS OPEN:
//!
//! 1. A schema-**required** string read with `unwrap_or_default()` — a
//!    malformed call queries `""` and gets a plausible EMPTY SUCCESS
//!    instead of an error (ERRORS-08: a caller-contract violation must
//!    be refused, never answered).
//! 2. An enum/discriminant **filter** read with
//!    `.and_then(Enum::from_str)` — an unknown discriminant REMOVES the
//!    filter, so the caller gets strictly MORE rows than it asked for
//!    (and, on a destructive path, deletes strictly more).
//! 3. An `i64`-declared integer read with [`serde_json::Value::as_u64`]
//!    — a schema-valid NEGATIVE silently reads as absent and falls back
//!    to a server default (e.g. `ttl_seconds: -1` silently becomes the
//!    configured retention default: a retention-integrity gap).
//! 4. A boolean **safety flag** read with `.as_bool().unwrap_or(false)`
//!    — `dry_run: "true"` (a string) silently runs a REAL destructive
//!    delete when a preview was requested.
//!
//! Every helper here refuses instead, so the worst case is a loud
//! `-32602`-shaped error the caller can correct — never a wrong result
//! and never an unintended write. ABSENT optional values still take the
//! documented default; only a PRESENT-but-contradictory value refuses.

use serde_json::Value;

/// Read a schema-REQUIRED string argument, refusing a missing, non-string,
/// or blank value.
///
/// The returned `&str` is trimmed and guaranteed non-empty, so a caller
/// can pass it straight into a query predicate without re-checking.
///
/// # Errors
/// `"<key> is required"` when the key is absent, is not a JSON string, or
/// trims to the empty string.
pub fn require_str<'a>(params: &'a Value, key: &str) -> Result<&'a str, String> {
    params
        .get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| format!("{key} is required"))
}

/// Read an OPTIONAL enum-typed filter, refusing an unknown discriminant.
///
/// `parse` is the variant's `from_str`-style constructor (`&str ->
/// Option<T>`). An ABSENT key yields `Ok(None)` — "no filter", the
/// documented default. A PRESENT key that names no known variant is
/// REFUSED rather than silently dropped: dropping it widens the result
/// set (and, on `memory_forget`, widens a bulk DELETE), which is the
/// opposite of what the caller asked for. Mirrors
/// `handle_checkpoint_create`'s `condition_type` gate (#3007).
///
/// # Errors
/// `"invalid <key>: <value>"` when the key is present but is not a
/// string, or is a string naming no known variant.
pub fn optional_enum<T>(
    params: &Value,
    key: &str,
    parse: impl Fn(&str) -> Option<T>,
) -> Result<Option<T>, String> {
    match params.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(v) => {
            let raw = v
                .as_str()
                .ok_or_else(|| format!("invalid {key}: expected a string"))?;
            parse(raw)
                .map(Some)
                .ok_or_else(|| format!("invalid {key}: {raw}"))
        }
    }
}

/// Read an OPTIONAL non-negative integer argument, refusing a negative or
/// non-integer value.
///
/// The MCP schemas declare these counts/durations as `integer` (Rust
/// `i64`), but the handlers read them via [`Value::as_u64`], which
/// returns `None` for a negative — indistinguishable from "absent", so
/// the value silently becomes a server default. Refuse instead.
///
/// # Errors
/// `"<key> must be a non-negative integer"` when the key is present and
/// is not an integer `>= 0`.
pub fn optional_non_negative_u64(params: &Value, key: &str) -> Result<Option<u64>, String> {
    match params.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(v) => v
            .as_u64()
            .map(Some)
            .ok_or_else(|| format!("{key} must be a non-negative integer")),
    }
}

/// Read an OPTIONAL boolean argument, refusing a present-but-non-boolean
/// value.
///
/// Used for SAFETY flags (`dry_run`) where the `unwrap_or(false)` fallback
/// silently converts a requested preview into a real destructive run.
///
/// # Errors
/// `"<key> must be a boolean"` when the key is present and is not a JSON
/// boolean.
pub fn optional_bool(params: &Value, key: &str) -> Result<Option<bool>, String> {
    match params.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(v) => v
            .as_bool()
            .map(Some)
            .ok_or_else(|| format!("{key} must be a boolean")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn require_str_accepts_a_non_blank_string() {
        let p = json!({ "namespace": "  ns-1  " });
        assert_eq!(require_str(&p, "namespace").unwrap(), "ns-1");
    }

    #[test]
    fn require_str_refuses_missing_blank_and_non_string() {
        for bad in [json!({}), json!({ "namespace": "" }), json!({"namespace":"  "})] {
            assert_eq!(
                require_str(&bad, "namespace").unwrap_err(),
                "namespace is required"
            );
        }
        assert_eq!(
            require_str(&json!({ "namespace": 7 }), "namespace").unwrap_err(),
            "namespace is required"
        );
        assert_eq!(
            require_str(&json!({ "namespace": Value::Null }), "namespace").unwrap_err(),
            "namespace is required"
        );
    }

    fn parse_state(s: &str) -> Option<u8> {
        match s {
            "pending" => Some(0),
            "done" => Some(1),
            _ => None,
        }
    }

    #[test]
    fn optional_enum_absent_is_none_known_is_some() {
        assert_eq!(optional_enum(&json!({}), "state", parse_state).unwrap(), None);
        assert_eq!(
            optional_enum(&json!({ "state": Value::Null }), "state", parse_state).unwrap(),
            None
        );
        assert_eq!(
            optional_enum(&json!({ "state": "done" }), "state", parse_state).unwrap(),
            Some(1)
        );
    }

    #[test]
    fn optional_enum_refuses_unknown_discriminant_instead_of_widening() {
        let err = optional_enum(&json!({ "state": "bogus" }), "state", parse_state).unwrap_err();
        assert_eq!(err, "invalid state: bogus");
        let err = optional_enum(&json!({ "state": 3 }), "state", parse_state).unwrap_err();
        assert_eq!(err, "invalid state: expected a string");
    }

    #[test]
    fn optional_non_negative_u64_refuses_negatives() {
        assert_eq!(
            optional_non_negative_u64(&json!({}), "ttl_seconds").unwrap(),
            None
        );
        assert_eq!(
            optional_non_negative_u64(&json!({ "ttl_seconds": 0 }), "ttl_seconds").unwrap(),
            Some(0)
        );
        assert_eq!(
            optional_non_negative_u64(&json!({ "ttl_seconds": 90 }), "ttl_seconds").unwrap(),
            Some(90)
        );
        for bad in [json!({"ttl_seconds": -1}), json!({"ttl_seconds": "90"})] {
            assert_eq!(
                optional_non_negative_u64(&bad, "ttl_seconds").unwrap_err(),
                "ttl_seconds must be a non-negative integer"
            );
        }
    }

    #[test]
    fn optional_bool_refuses_stringy_truth() {
        assert_eq!(optional_bool(&json!({}), "dry_run").unwrap(), None);
        assert_eq!(
            optional_bool(&json!({ "dry_run": true }), "dry_run").unwrap(),
            Some(true)
        );
        for bad in [json!({"dry_run": "true"}), json!({"dry_run": 1})] {
            assert_eq!(
                optional_bool(&bad, "dry_run").unwrap_err(),
                "dry_run must be a boolean"
            );
        }
    }
}
