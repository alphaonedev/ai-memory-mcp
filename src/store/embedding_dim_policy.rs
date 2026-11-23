//! #9933 — the embedding-dimension migrate decision, as data.
//!
//! A boot or `schema-init` that derived the `memories.embedding` column
//! shape from a configured or compiled-default dimension used to NULL every
//! stored vector when that dimension disagreed with the live column (the
//! #877 auto-migrate ran the destructive conversion with the force flag
//! set). The invariant this module carries:
//!
//! 1. No boot path NULLs a stored embedding because a requested dimension
//!    differs from the live column. A populated mismatch is a refusal
//!    ([`EmbeddingDimMismatch`]) naming both dimensions and the explicit
//!    opt-in, `ai-memory schema-init --embedding-dim <N> --force-reembed`
//!    (the #1781 flag; no second convention).
//! 2. Where the dimension came from is part of the type
//!    ([`EmbeddingDimIntent`]): a defaulted value (tier preset, compiled
//!    default) or a configured value (environment variable, config file,
//!    configured model) is never mistaken for the `--embedding-dim`
//!    argument, and a defaulted `schema-init` adopts the live column
//!    instead of converting it.
//! 3. #9952 — the destructive conversion needs a [`ForceReembedOrder`],
//!    which only the `schema-init` argv parser can build, and only when that
//!    call carries BOTH `--embedding-dim N` and `--force-reembed`. The
//!    conversion function takes the order in its signature, so no caller
//!    (boot, a future route, a test helper) can reach the destructive branch
//!    with a dimension from the environment, a config file or a default.
//!
//! The decision is a pure function of `(live dim, intent, stored embeddings
//! at risk, embedder available)` so every row of that table is a unit test
//! with no database. The store adapter does the I/O and acts on the
//! returned [`AutoMigrateDecision`].

use std::fmt;

use super::StoreError;

/// Refusal label for a dimension the operator did not choose (tier preset or
/// compiled default).
pub const DEFAULTED_SOURCE_LABEL: &str = "a defaulted dimension (tier preset or compiled default)";

/// Refusal label for a dimension the operator configured outside the argv
/// of the call (`AI_MEMORY_EMBED_DIM`, `[embeddings].dim`, or a configured
/// embedding model).
pub const CONFIGURED_SOURCE_LABEL: &str =
    "a configured dimension (environment variable, config file or embedding model)";

/// Refusal label for a dimension given as `--embedding-dim N` in the argv of
/// the `schema-init` call.
pub const EXPLICIT_SOURCE_LABEL: &str = "an explicit --embedding-dim argument";

/// Opening words of every destructive-conversion refusal. Kept from the
/// #1781 text so operators' and tests' substring matches keep working.
pub const REFUSAL_PREFIX: &str = "refusing destructive embedding-dim conversion";

/// A requested embedding dimension together with where it came from.
///
/// The variant, not a bool beside a `u32`, decides how a mismatch with the
/// live column is handled: only [`Self::Explicit`] together with a
/// [`ForceReembedOrder`] may drive a destructive `schema-init` conversion; a
/// [`Self::Configured`] value converts only an empty column, and a
/// [`Self::Defaulted`] value adopts the live column there.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EmbeddingDimIntent {
    /// The dimension is the `--embedding-dim N` argument of this
    /// `schema-init` call. Built only by the argv path
    /// (`cli::schema_init::run`); the #9960 allowlist guard pins every
    /// construction site in the tree.
    Explicit(u32),
    /// The operator configured this dimension outside the call's argv
    /// (environment variable, config file or configured model).
    Configured(u32),
    /// The dimension is a default (tier preset or compiled constant).
    Defaulted(u32),
}

impl EmbeddingDimIntent {
    /// The requested dimension.
    #[must_use]
    pub const fn dim(self) -> u32 {
        match self {
            Self::Explicit(d) | Self::Configured(d) | Self::Defaulted(d) => d,
        }
    }

    /// The source phrase used in a refusal.
    #[must_use]
    pub const fn source_label(self) -> &'static str {
        match self {
            Self::Explicit(_) => EXPLICIT_SOURCE_LABEL,
            Self::Configured(_) => CONFIGURED_SOURCE_LABEL,
            Self::Defaulted(_) => DEFAULTED_SOURCE_LABEL,
        }
    }

    /// `true` when `live` is a declared column dimension equal to this one.
    /// Compared in `i64` so no narrowing conversion can make two different
    /// values look equal.
    #[must_use]
    pub fn matches_live(self, live: Option<i32>) -> bool {
        live.is_some_and(|l| i64::from(l) == i64::from(self.dim()))
    }
}

/// #9952 — the operator's order to NULL stored vectors and convert the
/// column: a value that exists only when ONE `schema-init` argv carried both
/// `--embedding-dim N` and `--force-reembed`.
///
/// The field is private and the only constructor is crate-private
/// [`Self::from_argv`], called from `SchemaInitArgs::force_reembed_order`
/// (the parsed argv). A dimension from the environment, a config file or a
/// default has no path to a value of this type, and the conversion function
/// requires one to take its destructive branch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ForceReembedOrder {
    dim: u32,
}

impl ForceReembedOrder {
    /// Build the order from the two argv flags of one `schema-init` call:
    /// `Some` only when both `--embedding-dim N` and `--force-reembed` are
    /// present.
    #[must_use]
    pub(crate) const fn from_argv(embedding_dim: Option<u32>, force_reembed: bool) -> Option<Self> {
        match (embedding_dim, force_reembed) {
            (Some(dim), true) => Some(Self { dim }),
            (Some(_) | None, false) | (None, true) => None,
        }
    }

    /// The dimension the order converts to.
    #[must_use]
    pub const fn dim(self) -> u32 {
        self.dim
    }

    /// `true` only for the [`EmbeddingDimIntent::Explicit`] dimension this
    /// order was given with. A configured or defaulted intent, or another
    /// dimension, is never authorised.
    #[must_use]
    pub const fn authorizes(self, intent: EmbeddingDimIntent) -> bool {
        match intent {
            EmbeddingDimIntent::Explicit(d) => d == self.dim,
            EmbeddingDimIntent::Configured(_) | EmbeddingDimIntent::Defaulted(_) => false,
        }
    }
}

/// What the `schema-init` argv asked for about re-embedding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReembedRequest {
    /// No `--force-reembed`.
    NotRequested,
    /// `--force-reembed` without `--embedding-dim`: never an order.
    WithoutDim,
    /// Both flags in the argv.
    Order(ForceReembedOrder),
}

impl ReembedRequest {
    /// The order carried by the request, if any.
    #[must_use]
    pub const fn order(self) -> Option<ForceReembedOrder> {
        match self {
            Self::Order(o) => Some(o),
            Self::NotRequested | Self::WithoutDim => None,
        }
    }

    /// `true` when the argv carried `--force-reembed`.
    #[must_use]
    pub const fn force_flag(self) -> bool {
        match self {
            Self::NotRequested => false,
            Self::WithoutDim | Self::Order(_) => true,
        }
    }
}

/// A refused destructive conversion: the live column, the requested
/// dimension and its source, and how many stored embeddings it would NULL.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EmbeddingDimMismatch {
    live: Option<i32>,
    intent: EmbeddingDimIntent,
    at_risk: i64,
}

impl EmbeddingDimMismatch {
    /// Build the refusal for `intent` against the live column `live` with
    /// `at_risk` stored embeddings.
    #[must_use]
    pub const fn new(live: Option<i32>, intent: EmbeddingDimIntent, at_risk: i64) -> Self {
        Self {
            live,
            intent,
            at_risk,
        }
    }

    /// The live column dimension (`None` when the column has no declared
    /// `vector(N)` type).
    #[must_use]
    pub const fn live(&self) -> Option<i32> {
        self.live
    }

    /// The requested dimension and its source.
    #[must_use]
    pub const fn intent(&self) -> EmbeddingDimIntent {
        self.intent
    }

    /// Stored embeddings the conversion would NULL.
    #[must_use]
    pub const fn at_risk(&self) -> i64 {
        self.at_risk
    }
}

impl fmt::Display for EmbeddingDimMismatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let requested = self.intent.dim();
        let label = self.intent.source_label();
        let at_risk = self.at_risk;
        match self.live {
            Some(live) => write!(
                f,
                "{REFUSAL_PREFIX}: live column is vector({live}), requested vector({requested}) \
                 from {label}; {at_risk} stored embeddings would be NULLed. To keep them, \
                 configure an embedder whose dimension is {live}; to convert them and re-embed, \
                 run `ai-memory schema-init --embedding-dim {requested} --force-reembed`."
            ),
            None => write!(
                f,
                "{REFUSAL_PREFIX}: live column has no declared vector dimension, requested \
                 vector({requested}) from {label}; {at_risk} stored embeddings would be NULLed. \
                 To convert them and re-embed, run \
                 `ai-memory schema-init --embedding-dim {requested} --force-reembed`."
            ),
        }
    }
}

impl std::error::Error for EmbeddingDimMismatch {}

impl From<EmbeddingDimMismatch> for StoreError {
    fn from(m: EmbeddingDimMismatch) -> Self {
        Self::InvalidInput {
            detail: m.to_string(),
        }
    }
}

/// What a daemon boot does with the live embedding column.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AutoMigrateDecision {
    /// The column already has the requested dimension.
    Keep,
    /// Mismatch, but no embedder could regenerate vectors: change nothing
    /// (#2567) and WARN.
    PreserveNoEmbedder,
    /// Mismatch on a column that holds no embeddings: converting loses
    /// nothing (#877). The adapter converts WITHOUT an order, so a row
    /// written after the count still makes the conversion refuse.
    ConvertEmpty,
    /// Mismatch on a populated column: refuse to boot.
    Refuse(EmbeddingDimMismatch),
}

/// Decide what a daemon boot does. `at_risk` is the number of stored
/// embeddings (live plus archived) the conversion would NULL; it is ignored
/// when the column already matches.
pub fn decide_auto_migrate(
    live: Option<i32>,
    intent: EmbeddingDimIntent,
    at_risk: i64,
    embedder_available: bool,
) -> AutoMigrateDecision {
    if intent.matches_live(live) {
        return AutoMigrateDecision::Keep;
    }
    if !embedder_available {
        return AutoMigrateDecision::PreserveNoEmbedder;
    }
    if at_risk == 0 {
        return AutoMigrateDecision::ConvertEmpty;
    }
    AutoMigrateDecision::Refuse(EmbeddingDimMismatch::new(live, intent, at_risk))
}

/// What `schema-init` does with the live embedding column.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SchemaInitDecision {
    /// Call the conversion with this order (it is a no-op when the column
    /// already matches, and refuses a populated column without an order).
    Migrate {
        /// The argv order, passed through only for the explicit dimension it
        /// was given with.
        order: Option<ForceReembedOrder>,
    },
    /// A defaulted dimension met a different live column: keep the live
    /// column and report it.
    AdoptLive,
    /// A defaulted or configured dimension over a populated column that
    /// differs: such a value never authorises destroying vectors.
    Refuse(EmbeddingDimMismatch),
}

/// Decide what `schema-init` does. `at_risk` as in [`decide_auto_migrate`].
pub fn decide_schema_init(
    live: Option<i32>,
    intent: EmbeddingDimIntent,
    request: ReembedRequest,
    at_risk: i64,
) -> SchemaInitDecision {
    if intent.matches_live(live) {
        return SchemaInitDecision::Migrate { order: None };
    }
    match intent {
        EmbeddingDimIntent::Explicit(_) => SchemaInitDecision::Migrate {
            order: request.order().filter(|o| o.authorizes(intent)),
        },
        EmbeddingDimIntent::Configured(_) => {
            if at_risk == 0 {
                SchemaInitDecision::Migrate { order: None }
            } else {
                SchemaInitDecision::Refuse(EmbeddingDimMismatch::new(live, intent, at_risk))
            }
        }
        EmbeddingDimIntent::Defaulted(_) => {
            if !request.force_flag() {
                SchemaInitDecision::AdoptLive
            } else if at_risk == 0 {
                SchemaInitDecision::Migrate { order: None }
            } else {
                SchemaInitDecision::Refuse(EmbeddingDimMismatch::new(live, intent, at_risk))
            }
        }
    }
}

/// Tags a dimension resolved from configuration with its source:
/// [`EmbeddingDimIntent::Configured`] when the operator configured it,
/// [`EmbeddingDimIntent::Defaulted`] otherwise. It never yields
/// [`EmbeddingDimIntent::Explicit`]: configuration is not the argv (#9952).
#[must_use]
pub const fn intent_for(dim: u32, operator_configured: bool) -> EmbeddingDimIntent {
    if operator_configured {
        EmbeddingDimIntent::Configured(dim)
    } else {
        EmbeddingDimIntent::Defaulted(dim)
    }
}

/// `true` when the config names an embedding model: a non-blank
/// `[embeddings].model` or legacy flat `embedding_model` (the two sources
/// the local embedder bootstrap honours before the tier preset). An unset,
/// empty or whitespace value is not a choice.
#[must_use]
pub fn config_names_embedder_model(app: &crate::config::AppConfig) -> bool {
    let named = |s: Option<&String>| s.is_some_and(|m| !m.trim().is_empty());
    #[allow(deprecated)]
    let legacy = app.embedding_model.as_ref();
    named(app.embeddings.as_ref().and_then(|e| e.model.as_ref())) || named(legacy)
}

/// `true` when an API backend's dim came from the operator
/// (`AI_MEMORY_EMBED_DIM` or `[embeddings].dim`), not a compiled table.
#[must_use]
pub const fn api_dim_is_configured(source: crate::config::EmbedDimSource) -> bool {
    matches!(
        source,
        crate::config::EmbedDimSource::Env | crate::config::EmbedDimSource::ConfigFile
    )
}

#[cfg(test)]
#[path = "embedding_dim_policy_tests.rs"]
mod tests;
