//! #8945 / #8963 — reply-integrity primitives of the LLM client: the typed
//! completion status of a chat reply (read from the provider stop reason) and
//! the strict yes/no parser for contradiction verdicts. Split out of
//! `src/llm.rs` so the client module stays under its QUAL-10 ceiling; the
//! items are re-exported from `crate::llm`.

use serde_json::Value;

use super::LlmProvider;

/// #8963 — stop reasons that mean the model finished its answer normally.
/// `stop` is the OpenAI and Ollama value; the others are the same normal
/// end under the names other OpenAI-compatible servers use.
const COMPLETE_STOP_REASONS: &[&str] = &["stop", "eos", "eos_token", "stop_sequence", "end_turn"];
/// #8963 — stop reasons that mean the model stopped to call a tool.
const TOOL_STOP_REASONS: &[&str] = &["tool_calls", "function_call", "tool_use"];
/// #8963 — stop reasons that mean the reply was cut at the token limit.
const TRUNCATED_STOP_REASONS: &[&str] = &["length", "max_tokens", "model_length"];
/// #8963 — stop reasons that mean a provider filter withheld the reply.
const FILTERED_STOP_REASONS: &[&str] = &["content_filter", "safety", "refusal"];

/// #8963 — error text for a reply cut at the token limit.
pub const ERR_REPLY_TRUNCATED: &str =
    "incomplete LLM reply: cut at the token limit (finish_reason=length)";
/// #8963 — error text for a reply withheld by a provider content filter.
pub const ERR_REPLY_FILTERED: &str =
    "incomplete LLM reply: withheld by the provider content filter";
/// #8963 — error text for an Ollama reply with `done: false`.
pub const ERR_REPLY_NOT_DONE: &str = "incomplete LLM reply: generation not finished (done=false)";
/// #8963 — error text for a reply with no stop reason at all.
pub const ERR_REPLY_NO_STOP_REASON: &str = "incomplete LLM reply: no stop reason in the response";
/// #8963 — error text for a stop reason this client does not classify.
pub const ERR_REPLY_UNRECOGNISED_STOP: &str = "incomplete LLM reply: unrecognised stop reason";
/// #8963 — error text for a text reply that stopped for a tool call.
pub const ERR_REPLY_TOOL_STOP: &str =
    "incomplete LLM reply: stopped for a tool call on a text request";
/// #8963 — error text for a complete reply whose text is empty or blank.
pub const ERR_REPLY_EMPTY: &str = "empty LLM reply";
/// #8963 — error text for an Ollama chat body with no `message.content`
/// (one text for every chat caller, so the table tests pin one string).
pub const ERR_OLLAMA_NO_CONTENT: &str = "Missing 'message.content' field in chat output";
/// #8963 — error text for an OpenAI-compatible body with no
/// `choices[0].message.content`.
pub const ERR_OPENAI_NO_CONTENT: &str =
    "Missing 'choices[0].message.content' field in OpenAI-compatible chat response";

/// #8963 — the completion status of one chat reply, read from the
/// provider's stop-reason field (`choices[0].finish_reason` on the
/// OpenAI-compatible wire, `done` / `done_reason` on Ollama).
///
/// Only [`Self::Complete`] (and [`Self::ToolCalls`] on the tool path)
/// lets a reply through; every other form is an explicit error, so a
/// reply cut at `max_tokens` is never used as a complete answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplyCompletion {
    /// A normal stop.
    Complete,
    /// The model stopped to call a tool.
    ToolCalls,
    /// Cut at the token limit.
    Truncated,
    /// Withheld by a provider content filter.
    Filtered,
    /// Ollama `done: false`: the generation had not finished.
    NotDone,
    /// The body carries no stop reason.
    Missing,
    /// A stop reason this client does not classify.
    Unrecognised,
}

impl ReplyCompletion {
    /// Classify `body`, the parsed chat response of `provider`.
    #[must_use]
    pub fn of(provider: &LlmProvider, body: &Value) -> Self {
        let reason = match provider {
            LlmProvider::Ollama => {
                if body["done"] == Value::Bool(false) {
                    return Self::NotDone;
                }
                body["done_reason"].as_str()
            }
            LlmProvider::OpenAiCompatible { .. } => body["choices"][0]["finish_reason"].as_str(),
        };
        let Some(reason) = reason else {
            return Self::Missing;
        };
        let reason = reason.trim();
        let is = |set: &[&str]| set.iter().any(|r| reason.eq_ignore_ascii_case(r));
        if is(COMPLETE_STOP_REASONS) {
            Self::Complete
        } else if is(TOOL_STOP_REASONS) {
            Self::ToolCalls
        } else if is(TRUNCATED_STOP_REASONS) {
            Self::Truncated
        } else if is(FILTERED_STOP_REASONS) {
            Self::Filtered
        } else {
            Self::Unrecognised
        }
    }

    /// The exact error text a non-complete status surfaces as. The provider's
    /// own stop-reason string is never echoed (it is untrusted input).
    #[must_use]
    pub const fn error_text(self) -> &'static str {
        match self {
            Self::Complete => "",
            Self::ToolCalls => ERR_REPLY_TOOL_STOP,
            Self::Truncated => ERR_REPLY_TRUNCATED,
            Self::Filtered => ERR_REPLY_FILTERED,
            Self::NotDone => ERR_REPLY_NOT_DONE,
            Self::Missing => ERR_REPLY_NO_STOP_REASON,
            Self::Unrecognised => ERR_REPLY_UNRECOGNISED_STOP,
        }
    }
}

/// #8945 — error text for a contradiction reply that is not a single,
/// unambiguous yes or no. The reply itself is never echoed (it is
/// untrusted model output and may carry injected text).
pub const ERR_CONTRADICTION_UNCLASSIFIABLE: &str =
    "unclassifiable contradiction verdict: the reply is not a single yes or no";

/// #8945 — parse a contradiction reply into a verdict.
///
/// The first word (letters only, ASCII case-insensitive) must be exactly
/// `yes` or `no`, and no later word may be the opposite verdict. So
/// `"Yes."`, `"no"` and `"**Yes**, they conflict"` parse, while
/// `"yesterday"`, `"maybe"`, `"yes and no"`, `"No... actually yes"` and an
/// empty reply are `None`. One linear pass over the reply.
#[must_use]
pub fn parse_contradiction_verdict(reply: &str) -> Option<bool> {
    let mut words = reply
        .split(|c: char| !c.is_alphabetic())
        .filter(|w| !w.is_empty());
    let verdict = match words.next()? {
        w if w.eq_ignore_ascii_case("yes") => true,
        w if w.eq_ignore_ascii_case("no") => false,
        _ => return None,
    };
    let opposite = if verdict { "no" } else { "yes" };
    if words.any(|w| w.eq_ignore_ascii_case(opposite)) {
        return None;
    }
    Some(verdict)
}

#[cfg(test)]
#[path = "reply_integrity_tests.rs"]
mod tests;
