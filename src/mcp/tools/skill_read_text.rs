// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #9174 R2 — the ONE closed vocabulary of a skill read or export failure,
//! shared by the HTTP routes and the MCP tools.
//!
//! The substrate error text is NEVER rendered. [`SkillReadClass::classify`]
//! only compares it with the text our own builders produce for this request's
//! `skill_id` (and the CALLER's resource path); [`SkillReadClass::caller_text`]
//! then rebuilds the caller text from those builders, so nothing the store
//! returned (SQL fragments, a decoder message, a stored resource path) reaches
//! a caller. The HTTP routes map the class to a status; the MCP export tool
//! renders the same [`SkillReadClass::caller_text`], so the two surfaces are
//! byte-identical by construction (#3762), not by a parity habit.

use crate::errors::msg;

/// The closed class of a skill read failure. A resource-path variant borrows
/// the CALLER's request path, never the store's text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SkillReadClass<'a> {
    NotFound,
    DigestMismatch,
    SignatureInvalid,
    SignerKeyUnavailable,
    /// A row names a signer but carries no signature (#8834).
    SignatureMissing,
    /// Every other integrity-family text: a resource-level failure names a
    /// stored resource path, so the caller gets the fixed skill-level text.
    ResourceIntegrity,
    ResourcePathRequired,
    ResourceNotFound(&'a str),
    ResourceReferenceOnly(&'a str),
    /// A stored blob failed to decode (`ZSTD_DECOMPRESS_PREFIX` family).
    Decode,
    /// The store failed (the sanitized `DB_ERROR_TEXT` of the loader's
    /// substrate class).
    Substrate,
    /// Text outside this vocabulary.
    Internal,
}

impl<'a> SkillReadClass<'a> {
    /// Classify `e` by exact comparison with our own builders' text for this
    /// request; only the integrity family is matched by its fixed prefix.
    #[must_use]
    pub fn classify(e: &str, skill_id: &str, resource_path: Option<&'a str>) -> Self {
        if e == msg::skill_not_found(skill_id) {
            return Self::NotFound;
        }
        if e == msg::skill_digest_mismatch(skill_id) {
            return Self::DigestMismatch;
        }
        if e == msg::skill_signature_invalid(skill_id) {
            return Self::SignatureInvalid;
        }
        if e == msg::skill_signer_key_unavailable(skill_id) {
            return Self::SignerKeyUnavailable;
        }
        if e == msg::skill_signature_missing(skill_id) {
            return Self::SignatureMissing;
        }
        if e.starts_with(msg::SKILL_INTEGRITY_FAILED) {
            return Self::ResourceIntegrity;
        }
        if e == msg::SKILL_RESOURCE_PATH_REQUIRED {
            return Self::ResourcePathRequired;
        }
        if e.starts_with(msg::ZSTD_DECOMPRESS_PREFIX) {
            return Self::Decode;
        }
        if e == crate::mcp::error_text::DB_ERROR_TEXT {
            return Self::Substrate;
        }
        if let Some(path) = resource_path {
            if e == msg::skill_resource_not_found(skill_id, path) {
                return Self::ResourceNotFound(path);
            }
            if e == msg::skill_resource_reference_only(path) {
                return Self::ResourceReferenceOnly(path);
            }
        }
        Self::Internal
    }

    /// `true` for the classes whose raw text is operator detail: the caller
    /// gets the sanitized #1261 text and the raw text goes to the operator log.
    #[must_use]
    pub const fn is_sanitized(self) -> bool {
        matches!(self, Self::Decode | Self::Substrate | Self::Internal)
    }

    /// The caller text of this class, rebuilt from our own builders.
    #[must_use]
    pub fn caller_text(self, skill_id: &str) -> String {
        match self {
            Self::NotFound => msg::skill_not_found(skill_id),
            Self::DigestMismatch => msg::skill_digest_mismatch(skill_id),
            Self::SignatureInvalid => msg::skill_signature_invalid(skill_id),
            Self::SignerKeyUnavailable => msg::skill_signer_key_unavailable(skill_id),
            Self::SignatureMissing => msg::skill_signature_missing(skill_id),
            Self::ResourceIntegrity => msg::skill_integrity_failed(skill_id),
            Self::ResourcePathRequired => msg::SKILL_RESOURCE_PATH_REQUIRED.to_owned(),
            Self::ResourceNotFound(path) => msg::skill_resource_not_found(skill_id, path),
            Self::ResourceReferenceOnly(path) => msg::skill_resource_reference_only(path),
            Self::Decode | Self::Substrate | Self::Internal => {
                msg::INTERNAL_SERVER_ERROR.to_owned()
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::SkillReadClass;
    use crate::errors::msg;

    const ID: &str = "skill-read-text-9174";

    /// Every class renders exactly one fixed text, and a stored-path or SQL
    /// fragment in the raw text never reaches it.
    #[test]
    fn every_class_renders_its_builder_text_9174() {
        let marker = "STORED-PATH-MARKER-9174/../../etc";
        let cases: [(String, String); 7] = [
            (msg::skill_not_found(ID), msg::skill_not_found(ID)),
            (
                msg::skill_digest_mismatch(ID),
                msg::skill_digest_mismatch(ID),
            ),
            (
                msg::skill_signature_invalid(ID),
                msg::skill_signature_invalid(ID),
            ),
            (
                msg::skill_signer_key_unavailable(ID),
                msg::skill_signer_key_unavailable(ID),
            ),
            (
                format!(
                    "{}: resource {marker} digest mismatch",
                    msg::SKILL_INTEGRITY_FAILED
                ),
                msg::skill_integrity_failed(ID),
            ),
            (
                format!("{}{marker}", msg::ZSTD_DECOMPRESS_PREFIX),
                msg::INTERNAL_SERVER_ERROR.to_owned(),
            ),
            (
                format!("no such table: {marker}"),
                msg::INTERNAL_SERVER_ERROR.to_owned(),
            ),
        ];
        for (raw, want) in cases {
            let text = SkillReadClass::classify(&raw, ID, None).caller_text(ID);
            assert_eq!(text, want, "raw {raw:?}");
            assert!(
                !text.contains(marker),
                "stored text reached the caller: {text}"
            );
        }
        assert_eq!(
            SkillReadClass::classify(&msg::skill_signature_missing(ID), ID, None).caller_text(ID),
            msg::skill_signature_missing(ID),
        );
    }
}
