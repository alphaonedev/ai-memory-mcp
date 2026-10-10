// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #3742 (WP-EGRESS #6053) — the ONE way a request URL is derived from a
//! configured base URL (child module of `llm` so the parent stays under its
//! QUAL-10 ceiling).
//!
//! Every OpenAI-compatible and Ollama request URL used to be built as
//! `format!("{base_url}/<path>")`. A base URL that carries a query string —
//! Azure OpenAI's `?api-version=2024-02-01` is the common real case — had the
//! path appended AFTER the query (`…/v1?api-version=2024-02-01/models`): the
//! request went to the wrong resource and the query value was corrupted.
//!
//! [`join_api_path`] parses the base with the SAME parser the client sends
//! with (`reqwest::Url`), appends the path to the URL's path (trimming one
//! trailing `/`) and keeps the query and fragment where they were. This is
//! also half of the #4018 contract: the host the request is sent to is, by
//! construction, the host `reqwest::Url` reads from the base — the host the
//! egress gate admits.

/// Join `path` (leading `/`) onto the PATH of `base`, preserving `base`'s
/// query string and fragment.
///
/// A `base` that `reqwest::Url` cannot parse, or that cannot be a base
/// (`mailto:`-like), falls back to the plain string join: such a request
/// fails at send time anyway, and the fallback keeps the error message
/// naming what the operator configured.
#[must_use]
pub fn join_api_path(base: &str, path: &str) -> String {
    let fallback = || format!("{}{path}", base.trim_end_matches('/'));
    let Ok(mut url) = reqwest::Url::parse(base) else {
        return fallback();
    };
    if url.cannot_be_a_base() {
        return fallback();
    }
    let joined = format!(
        "{}/{}",
        url.path().trim_end_matches('/'),
        path.trim_start_matches('/')
    );
    url.set_path(&joined);
    url.to_string()
}

#[cfg(test)]
mod tests {
    use super::join_api_path;

    #[test]
    fn query_string_stays_after_the_joined_path_3742() {
        // The issue's case: Azure's api-version query on the base URL.
        assert_eq!(
            join_api_path(
                "https://host/openai/deployments/x?api-version=2024-02-01",
                "/chat/completions"
            ),
            "https://host/openai/deployments/x/chat/completions?api-version=2024-02-01"
        );
        // Query AND fragment both survive, in order.
        assert_eq!(
            join_api_path("https://host/v1?a=1&b=2#frag", "/models"),
            "https://host/v1/models?a=1&b=2#frag"
        );
    }

    #[test]
    fn trailing_slash_and_empty_path_join_cleanly_3742() {
        assert_eq!(
            join_api_path("https://api.openai.com/v1/", "/models"),
            "https://api.openai.com/v1/models"
        );
        assert_eq!(
            join_api_path("https://api.openai.com/v1", "/models"),
            "https://api.openai.com/v1/models"
        );
        // An origin-only base (empty path) gets exactly one slash.
        assert_eq!(
            join_api_path("http://localhost:11434", "/api/tags"),
            "http://localhost:11434/api/tags"
        );
        assert_eq!(
            join_api_path("http://localhost:11434/", "/api/tags"),
            "http://localhost:11434/api/tags"
        );
        // A path without the leading slash joins the same way.
        assert_eq!(
            join_api_path("http://localhost:11434", "api/tags"),
            "http://localhost:11434/api/tags"
        );
    }

    #[test]
    fn userinfo_port_and_ipv6_literal_are_preserved_3742() {
        assert_eq!(
            join_api_path("https://svc:pw@127.0.0.1:9/v1?k=v", "/models"),
            "https://svc:pw@127.0.0.1:9/v1/models?k=v"
        );
        assert_eq!(
            join_api_path("http://[::1]:11434", "/api/embed"),
            "http://[::1]:11434/api/embed"
        );
    }

    #[test]
    fn unparseable_base_falls_back_to_the_string_join_3742() {
        // reqwest rejects these at send time; the fallback keeps the
        // operator's text in the eventual error instead of panicking here.
        assert_eq!(join_api_path("not a url", "/models"), "not a url/models");
        assert_eq!(
            join_api_path("localhost:11434/", "/api/tags"),
            "localhost:11434/api/tags"
        );
    }
}
