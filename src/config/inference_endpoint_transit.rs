// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #3823 — config-time transit-encryption discipline for inference endpoints.
//!
//! A NON-LOOPBACK plaintext `http://` inference endpoint ships memory content
//! (and the prompts derived from it) off the host IN CLEARTEXT, readable by
//! anything on the path. This module refuses such an endpoint at config-load
//! time — naming the config KEY and the scheme, never the credential — for the
//! `[llm]`, `[llm.auto_tag]` and `[embeddings]` endpoints and their legacy flat
//! twins, so the LLM and embedding egress classes cannot disagree.
//!
//! Loopback (`127.0.0.1` / `localhost` / `::1`) is the PINNED allowed-path
//! control: those targets never leave the host, so a local model served over
//! plaintext http stays permitted (the loopback-INCLUDED standard is #3824,
//! deferred past v1.0.0). The scheme judgement is the SSOT
//! [`crate::transit_encryption::url_is_plaintext_http`]; the boundary judgement
//! is [`crate::egress::target_is_loopback`] — neither is re-implemented here.

use crate::config::AppConfig;

/// True iff `url` is a plaintext `http` endpoint whose host is NOT loopback —
/// i.e. an endpoint that would carry memory content off the host in cleartext.
fn is_offhost_plaintext(url: &str) -> bool {
    crate::transit_encryption::url_is_plaintext_http(url) && !crate::egress::target_is_loopback(url)
}

impl AppConfig {
    /// #3823 — refuse a non-loopback plaintext inference endpoint at config
    /// load, naming the offending key and the scheme.
    ///
    /// # Errors
    ///
    /// Returns the operator-actionable rejection string (which config key, the
    /// plaintext scheme, and the `https` fix — never the credential) when any
    /// configured inference-endpoint base URL is a non-loopback plaintext
    /// `http` endpoint. Consumed at the same config-load chokepoint as
    /// [`AppConfig::validate_secret_handling`].
    // Reads the deprecated legacy `ollama_url` / `embed_url` twins on purpose:
    // they are still live resolution inputs, so a plaintext non-loopback legacy
    // endpoint is the same cleartext-egress path and must be refused too.
    #[allow(deprecated)]
    pub(crate) fn validate_inference_endpoint_transit(&self) -> Result<(), String> {
        // (config key label, configured value) for every inference endpoint.
        let mut candidates: Vec<(&str, Option<&str>)> = Vec::new();
        if let Some(llm) = &self.llm {
            candidates.push(("[llm].base_url", llm.base_url.as_deref()));
            if let Some(at) = &llm.auto_tag {
                candidates.push(("[llm.auto_tag].base_url", at.base_url.as_deref()));
            }
        }
        if let Some(emb) = &self.embeddings {
            candidates.push(("[embeddings].base_url", emb.base_url.as_deref()));
            candidates.push((
                crate::config::config_keys::EMBEDDINGS_URL,
                emb.url.as_deref(),
            ));
        }
        candidates.push(("ollama_url", self.ollama_url.as_deref()));
        candidates.push(("embed_url", self.embed_url.as_deref()));

        for (key, value) in candidates {
            let Some(url) = value.map(str::trim).filter(|s| !s.is_empty()) else {
                continue;
            };
            if is_offhost_plaintext(url) {
                return Err(format!(
                    "inference endpoint `{key}` uses the plaintext `http` scheme to a \
                     non-loopback host, so memory content would leave this host \
                     UNENCRYPTED. Use an `https://` endpoint (or a local \
                     TLS-terminating proxy). A loopback endpoint (127.0.0.1 / \
                     localhost) over http is the permitted allowed-path control."
                ));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::config::{AppConfig, EmbeddingsSection, LlmAutoTagSection, LlmSection};

    /// #3823 — MEASURE (not classify by code-read) that EVERY one of the six
    /// inference-endpoint keys is refused on a non-loopback plaintext value, and
    /// that the refusal NAMES that key. If any of the six does NOT refuse, that is
    /// a real finding, not a tidy green. The legacy `ollama_url` / `embed_url`
    /// twins are deprecated but still live resolution inputs, so they are covered.
    #[test]
    #[allow(deprecated)]
    fn every_one_of_the_six_keys_refuses_offhost_plaintext_3823() {
        let cases: [(&str, AppConfig); 6] = [
            (
                "[llm].base_url",
                AppConfig {
                    llm: Some(LlmSection {
                        base_url: Some("http://llm.internal:11434".into()),
                        ..LlmSection::default()
                    }),
                    ..AppConfig::default()
                },
            ),
            (
                "[llm.auto_tag].base_url",
                AppConfig {
                    llm: Some(LlmSection {
                        auto_tag: Some(LlmAutoTagSection {
                            base_url: Some("http://autotag.internal:11434".into()),
                            ..LlmAutoTagSection::default()
                        }),
                        ..LlmSection::default()
                    }),
                    ..AppConfig::default()
                },
            ),
            (
                "[embeddings].base_url",
                AppConfig {
                    embeddings: Some(EmbeddingsSection {
                        base_url: Some("http://embed.internal:8080".into()),
                        ..EmbeddingsSection::default()
                    }),
                    ..AppConfig::default()
                },
            ),
            (
                crate::config::config_keys::EMBEDDINGS_URL,
                AppConfig {
                    embeddings: Some(EmbeddingsSection {
                        url: Some("http://embed2.internal:8080".into()),
                        ..EmbeddingsSection::default()
                    }),
                    ..AppConfig::default()
                },
            ),
            (
                "ollama_url",
                AppConfig {
                    ollama_url: Some("http://ollama.internal:11434".into()),
                    ..AppConfig::default()
                },
            ),
            (
                "embed_url",
                AppConfig {
                    embed_url: Some("http://embedlegacy.internal:8080".into()),
                    ..AppConfig::default()
                },
            ),
        ];

        for (key, cfg) in &cases {
            match cfg.validate_inference_endpoint_transit() {
                Err(err) => assert!(
                    err.contains(key),
                    "the refusal for `{key}` must name that key: {err}"
                ),
                Ok(()) => panic!(
                    "key `{key}` with a non-loopback plaintext value was NOT refused \
                     (finding: the candidate list is incomplete)"
                ),
            }
        }
    }
}
