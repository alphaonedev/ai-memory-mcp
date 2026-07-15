// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #2006 (Portability-v2 §V2-2) — a provably-inverse lowercase-hex codec for
//! the `Vec<u8>` byte fields that cross the integrity-export envelope.
//!
//! ## Why a dedicated codec (the byte-preservation trap)
//!
//! serde's DEFAULT serialization of a `Vec<u8>` is a JSON **number array**
//! (`[12,255,…]`), not hex/base64. The signed record classes
//! (`signed_events`, `memory_revisions`, `forget_tombstones`, `agent_lineage`,
//! `model_attestations`) carry signature / hash bytes that L2 requires to
//! cross the envelope **byte-preserved and re-verifiable** — so the export
//! DTOs route every byte field through THIS module via `#[serde(with = …)]`.
//! One shared codec on BOTH the export and import DTOs is the only way to
//! guarantee the two directions use an identical, symmetric encoding for every
//! class (a per-field ad-hoc attribute would risk an export-hex / import-number
//! asymmetry that silently corrupts the round-trip).
//!
//! ## `None` vs `Some(empty)` (the present-only cliff)
//!
//! Several byte fields are `Option<Vec<u8>>` and PRESENT-ONLY: a `signed_events`
//! row on the unsigned daemon has `signature = None`; the v73 `cause_hash` is
//! `None` for an unbound cause and contributes ZERO bytes to the chain-hash
//! fold. Conflating `None` with `Some(empty)` would break both the chain
//! recompute and the per-row signature check, so the [`optional`] codec maps
//! `None` ⇒ absent (omitted) and `Some(v)` ⇒ a hex string (`Some(empty)` ⇒
//! `""`), never the same wire shape — pair it with
//! `#[serde(default, skip_serializing_if = "Option::is_none")]`.

/// Lowercase-hex encode. `encode(&[]) == ""`.
#[must_use]
pub(crate) fn encode(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        // `write!` to a String is infallible.
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// Decode a lowercase-or-uppercase hex string to bytes. `decode("") == Ok(vec![])`.
///
/// # Errors
/// The string has an odd length or contains a non-hex nibble.
pub(crate) fn decode(s: &str) -> Result<Vec<u8>, HexDecodeError> {
    if s.len() % 2 != 0 {
        return Err(HexDecodeError::OddLength);
    }
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(s.len() / 2);
    let mut i = 0;
    while i < bytes.len() {
        let hi = nibble(bytes[i])?;
        let lo = nibble(bytes[i + 1])?;
        out.push((hi << 4) | lo);
        i += 2;
    }
    Ok(out)
}

fn nibble(c: u8) -> Result<u8, HexDecodeError> {
    match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        b'A'..=b'F' => Ok(c - b'A' + 10),
        _ => Err(HexDecodeError::NotHex),
    }
}

/// A hex-decode failure (odd length or a non-hex character).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HexDecodeError {
    /// The input had an odd number of characters.
    OddLength,
    /// The input contained a character outside `[0-9a-fA-F]`.
    NotHex,
}

impl std::fmt::Display for HexDecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::OddLength => f.write_str("hex string has an odd length"),
            Self::NotHex => f.write_str("hex string contains a non-hex character"),
        }
    }
}

impl std::error::Error for HexDecodeError {}

/// `#[serde(with = "…")]` module for a REQUIRED `Vec<u8>` field ⇄ hex string.
pub mod required {
    use serde::{Deserialize, Deserializer, Serializer};

    /// Serialize `bytes` as a lowercase-hex string.
    ///
    /// # Errors
    /// Propagates the serializer's error.
    pub fn serialize<S: Serializer>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&super::encode(bytes))
    }

    /// Deserialize a hex string back to bytes.
    ///
    /// # Errors
    /// The value is not a string, or not valid hex.
    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(deserializer)?;
        super::decode(&s).map_err(serde::de::Error::custom)
    }
}

/// `#[serde(with = "…")]` module for an OPTIONAL `Option<Vec<u8>>` field.
///
/// Pair with `#[serde(default, skip_serializing_if = "Option::is_none")]`:
/// `None` ⇒ the field is OMITTED (absent ⇒ `None` on read); `Some(v)` ⇒ a hex
/// string, so `Some(empty)` ⇒ `""` and is NEVER conflated with `None`.
pub mod optional {
    use serde::{Deserialize, Deserializer, Serializer};

    /// Serialize `Some(bytes)` as a hex string, `None` as null.
    ///
    /// # Errors
    /// Propagates the serializer's error.
    pub fn serialize<S: Serializer>(
        opt: &Option<Vec<u8>>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        match opt {
            Some(bytes) => serializer.serialize_some(&super::encode(bytes)),
            None => serializer.serialize_none(),
        }
    }

    /// Deserialize an optional hex string back to `Option<Vec<u8>>`.
    ///
    /// # Errors
    /// A present value is not a string, or not valid hex.
    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Option<Vec<u8>>, D::Error> {
        let opt = Option::<String>::deserialize(deserializer)?;
        opt.map(|s| super::decode(&s).map_err(serde::de::Error::custom))
            .transpose()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::{Deserialize, Serialize};

    #[test]
    fn encode_decode_round_trips_arbitrary_bytes() {
        for case in [
            vec![],
            vec![0x00],
            vec![0xff],
            vec![0xde, 0xad, 0xbe, 0xef],
            (0u8..=255).collect::<Vec<u8>>(),
        ] {
            let hex = encode(&case);
            assert_eq!(decode(&hex).expect("round-trips"), case);
        }
    }

    #[test]
    fn encode_is_lowercase_and_empty_maps_to_empty() {
        assert_eq!(encode(&[]), "");
        assert_eq!(encode(&[0xAB, 0xCD]), "abcd");
        assert_eq!(decode("").expect("empty decodes"), Vec::<u8>::new());
    }

    #[test]
    fn decode_rejects_odd_length_and_non_hex() {
        assert_eq!(decode("abc"), Err(HexDecodeError::OddLength));
        assert_eq!(decode("zz"), Err(HexDecodeError::NotHex));
        assert_eq!(decode("gg"), Err(HexDecodeError::NotHex));
    }

    #[test]
    fn decode_accepts_uppercase() {
        assert_eq!(decode("DEADBEEF").unwrap(), vec![0xde, 0xad, 0xbe, 0xef]);
    }

    // The load-bearing property: the `required` + `optional` codecs are
    // symmetric AND distinguish None / Some(empty) / Some(bytes) through a
    // real serde round-trip on a struct that mirrors the export-DTO shape.
    #[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
    struct Sample {
        #[serde(with = "required")]
        head: Vec<u8>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "optional")]
        sig: Option<Vec<u8>>,
    }

    #[test]
    fn serde_with_modules_round_trip_and_preserve_bytes() {
        for sample in [
            Sample {
                head: vec![0x01, 0x02, 0x03],
                sig: Some(vec![0xaa, 0xbb]),
            },
            Sample {
                head: vec![0xff; 32],
                sig: None,
            },
            Sample {
                head: vec![],
                sig: Some(vec![]),
            },
        ] {
            let json = serde_json::to_string(&sample).expect("serialize");
            // Bytes cross as a hex STRING, never a JSON number array.
            assert!(
                !json.contains('['),
                "byte fields must not serialize as number arrays; got {json}"
            );
            let back: Sample = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(back, sample, "round-trip preserves bytes exactly");
        }
    }

    #[test]
    fn none_and_some_empty_are_distinct_on_the_wire() {
        let none = Sample {
            head: vec![0x00],
            sig: None,
        };
        let some_empty = Sample {
            head: vec![0x00],
            sig: Some(vec![]),
        };
        let none_json = serde_json::to_string(&none).unwrap();
        let some_empty_json = serde_json::to_string(&some_empty).unwrap();
        // None is OMITTED; Some(empty) is present as "".
        assert!(
            !none_json.contains("sig"),
            "None omits the field: {none_json}"
        );
        assert!(
            some_empty_json.contains("\"sig\":\"\""),
            "Some(empty) is an explicit empty hex string: {some_empty_json}"
        );
        // And they decode back to the distinct originals.
        assert_eq!(
            serde_json::from_str::<Sample>(&none_json).unwrap().sig,
            None
        );
        assert_eq!(
            serde_json::from_str::<Sample>(&some_empty_json)
                .unwrap()
                .sig,
            Some(vec![])
        );
    }
}
