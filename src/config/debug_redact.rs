// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! Manual `Debug` for the config sections that carry an endpoint URL or an
//! inline key (#1454, #6701). A `{:?}` of a section (or of the whole
//! `AppConfig`, which nests them) must never echo a credential: an inline
//! `api_key` renders as the redaction placeholder, and every URL renders
//! through `url_display::url_origin` (scheme, host and port only), so
//! userinfo, a query token or a path secret never reaches a log line or a
//! panic message (ERRORS-09, one renderer). `api_key_env` / `api_key_file`
//! are an env-var name and a file path (config, not secret) and stay
//! verbatim. KEEP IN SYNC: a new field must be mirrored here or it drops
//! from Debug.

use std::fmt::{Debug, Formatter, Result};

use super::{EmbeddingsSection, LlmAutoTagSection, LlmSection, ResolvedEmbeddings, ResolvedLlm};
use crate::url_display::url_origin;

/// Field names shared by the three section renderers (one literal each).
const KEY_ENV_FIELD: &str = "api_key_env";
const KEY_FILE_FIELD: &str = "api_key_file";

/// An optional URL as its origin only.
fn origin(url: Option<&String>) -> Option<String> {
    url.map(|u| url_origin(u))
}

/// An optional inline key as the placeholder, never the value.
fn redacted(key: Option<&String>) -> Option<&'static str> {
    key.map(|_| crate::REDACTED_PLACEHOLDER)
}

impl Debug for LlmSection {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        f.debug_struct("LlmSection")
            .field("backend", &self.backend)
            .field("model", &self.model)
            .field("base_url", &origin(self.base_url.as_ref()))
            .field(KEY_ENV_FIELD, &self.api_key_env)
            .field(KEY_FILE_FIELD, &self.api_key_file)
            .field("api_key", &redacted(self.api_key.as_ref()))
            .field("auto_tag", &self.auto_tag)
            .finish()
    }
}

impl Debug for LlmAutoTagSection {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        f.debug_struct("LlmAutoTagSection")
            .field("backend", &self.backend)
            .field("model", &self.model)
            .field("base_url", &origin(self.base_url.as_ref()))
            .field(KEY_ENV_FIELD, &self.api_key_env)
            .field(KEY_FILE_FIELD, &self.api_key_file)
            .finish()
    }
}

impl Debug for EmbeddingsSection {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        f.debug_struct("EmbeddingsSection")
            .field("backend", &self.backend)
            .field("url", &origin(self.url.as_ref()))
            .field("base_url", &origin(self.base_url.as_ref()))
            .field("model", &self.model)
            .field("api_key", &redacted(self.api_key.as_ref()))
            .field(KEY_ENV_FIELD, &self.api_key_env)
            .field(KEY_FILE_FIELD, &self.api_key_file)
            .field("dim", &self.dim)
            .field("backfill_batch", &self.backfill_batch)
            .field("backfill_on_boot", &self.backfill_on_boot)
            .finish()
    }
}

impl Debug for ResolvedLlm {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        f.debug_struct("ResolvedLlm")
            .field("backend", &self.backend)
            .field("model", &self.model)
            .field("base_url", &url_origin(&self.base_url))
            .field("api_key", &redacted(self.api_key.as_ref()))
            .field("api_key_source", &self.api_key_source)
            .field("source", &self.source)
            .finish()
    }
}

impl Debug for ResolvedEmbeddings {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        f.debug_struct("ResolvedEmbeddings")
            .field("backend", &self.backend)
            .field("url", &url_origin(&self.url))
            .field("model", &self.model)
            .field("backfill_batch", &self.backfill_batch)
            .field(
                crate::models::field_names::EMBEDDING_DIM,
                &self.embedding_dim,
            )
            .field("requested_dim", &self.requested_dim)
            .field("dim_source", &self.dim_source)
            .field("api_key", &redacted(self.api_key.as_ref()))
            .field("key_source", &self.key_source)
            .field("source", &self.source)
            .finish()
    }
}
