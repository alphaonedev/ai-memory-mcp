//! #9933 — the embedding-dimension migrate decision, as data.
//!
//! A boot or `schema-init` that derived the `memories.embedding` column
//! shape from a configured or compiled-default dimension used to NULL every
//! stored vector when that dimension disagreed with the live column (the
//! #877 auto-migrate ran `migrate_embedding_dim(dim, true)`). The invariant
//! this module carries:
//!
//! 1. No boot path NULLs a stored embedding because a requested dimension
//!    differs from the live column. A populated mismatch is a refusal
//!    ([`EmbeddingDimMismatch`]) naming both dimensions and the explicit
//!    opt-in, `ai-memory schema-init --embedding-dim <N> --force-reembed`
//!    (the #1781 flag; no second convention).
//! 2. Where the dimension came from is part of the type
//!    ([`EmbeddingDimIntent`]): a defaulted value (tier preset, compiled
//!    default) is never mistaken for an operator's explicit choice, and a
//!    defaulted `schema-init` adopts the live column instead of converting it.
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

/// Refusal label for a dimension the operator set (`--embedding-dim`,
/// `[embeddings].dim`, `AI_MEMORY_EMBED_DIM`, or a configured model).
pub const EXPLICIT_SOURCE_LABEL: &str = "an explicitly configured dimension";

/// Opening words of every destructive-conversion refusal. Kept from the
/// #1781 text so operators' and tests' substring matches keep working.
pub const REFUSAL_PREFIX: &str = "refusing destructive embedding-dim conversion";

/// A requested embedding dimension together with where it came from.
///
/// The variant, not a bool beside a `u32`, decides how a mismatch with the
/// live column is handled: only [`Self::Explicit`] may drive a `schema-init`
/// conversion, and a [`Self::Defaulted`] value adopts the live column there.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EmbeddingDimIntent {
    /// The operator chose this dimension.
    Explicit(u32),
    /// The dimension is a default (tier preset or compiled constant).
    Defaulted(u32),
}

impl EmbeddingDimIntent {
    /// The requested dimension.
    #[must_use]
    pub const fn dim(self) -> u32 {
        match self {
            Self::Explicit(d) | Self::Defaulted(d) => d,
        }
    }

    /// The source phrase used in a refusal.
    #[must_use]
    pub const fn source_label(self) -> &'static str {
        match self {
            Self::Explicit(_) => EXPLICIT_SOURCE_LABEL,
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
    /// nothing (#877). The adapter converts WITHOUT the force flag, so a row
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
    /// Call the conversion with this force flag (it is a no-op when the
    /// column already matches, and refuses a populated column unless
    /// forced).
    Migrate {
        /// The `--force-reembed` opt-in, passed through.
        force: bool,
    },
    /// A defaulted dimension met a different live column: keep the live
    /// column and report it.
    AdoptLive,
    /// A defaulted dimension with `--force-reembed` over a populated column:
    /// a defaulted value never authorises destroying vectors.
    Refuse(EmbeddingDimMismatch),
}

/// Decide what `schema-init` does. `at_risk` as in [`decide_auto_migrate`].
pub fn decide_schema_init(
    live: Option<i32>,
    intent: EmbeddingDimIntent,
    force_reembed: bool,
    at_risk: i64,
) -> SchemaInitDecision {
    match intent {
        EmbeddingDimIntent::Explicit(_) => SchemaInitDecision::Migrate {
            force: force_reembed,
        },
        EmbeddingDimIntent::Defaulted(_) => {
            if intent.matches_live(live) {
                SchemaInitDecision::Migrate { force: false }
            } else if !force_reembed {
                SchemaInitDecision::AdoptLive
            } else if at_risk == 0 {
                SchemaInitDecision::Migrate { force: false }
            } else {
                SchemaInitDecision::Refuse(EmbeddingDimMismatch::new(live, intent, at_risk))
            }
        }
    }
}

/// Tags `dim` with its source: [`EmbeddingDimIntent::Explicit`] when the
/// operator chose it, [`EmbeddingDimIntent::Defaulted`] otherwise.
#[must_use]
pub const fn intent_for(dim: u32, operator_chosen: bool) -> EmbeddingDimIntent {
    if operator_chosen {
        EmbeddingDimIntent::Explicit(dim)
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
pub const fn api_dim_is_explicit(source: crate::config::EmbedDimSource) -> bool {
    matches!(
        source,
        crate::config::EmbedDimSource::Env | crate::config::EmbedDimSource::ConfigFile
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const LIVE: i32 = 768;
    const OTHER: u32 = 384;
    const SAME: u32 = 768;
    const AT_RISK: i64 = 3;

    const EXPECTED_DEFAULTED: &str = "refusing destructive embedding-dim conversion: live column is vector(768), requested vector(384) from a defaulted dimension (tier preset or compiled default); 3 stored embeddings would be NULLed. To keep them, configure an embedder whose dimension is 768; to convert them and re-embed, run `ai-memory schema-init --embedding-dim 384 --force-reembed`.";
    const EXPECTED_EXPLICIT: &str = "refusing destructive embedding-dim conversion: live column is vector(768), requested vector(384) from an explicitly configured dimension; 3 stored embeddings would be NULLed. To keep them, configure an embedder whose dimension is 768; to convert them and re-embed, run `ai-memory schema-init --embedding-dim 384 --force-reembed`.";
    const EXPECTED_NO_COLUMN: &str = "refusing destructive embedding-dim conversion: live column has no declared vector dimension, requested vector(384) from an explicitly configured dimension; 3 stored embeddings would be NULLed. To convert them and re-embed, run `ai-memory schema-init --embedding-dim 384 --force-reembed`.";

    use AutoMigrateDecision as A;
    use EmbeddingDimIntent::{Defaulted, Explicit};

    fn refuse(live: Option<i32>, intent: EmbeddingDimIntent) -> EmbeddingDimMismatch {
        EmbeddingDimMismatch::new(live, intent, AT_RISK)
    }

    /// Every (live, intent, at_risk, embedder) combination over the corpus,
    /// with the expected decision written out by hand.
    #[test]
    fn auto_migrate_table_9933() {
        let rows: [(Option<i32>, EmbeddingDimIntent, i64, bool, A); 16] = [
            (Some(LIVE), Explicit(SAME), AT_RISK, true, A::Keep),
            (Some(LIVE), Explicit(SAME), 0, false, A::Keep),
            (Some(LIVE), Defaulted(SAME), AT_RISK, true, A::Keep),
            (Some(LIVE), Defaulted(SAME), 0, false, A::Keep),
            (
                Some(LIVE),
                Explicit(OTHER),
                AT_RISK,
                true,
                A::Refuse(refuse(Some(LIVE), Explicit(OTHER))),
            ),
            (
                Some(LIVE),
                Defaulted(OTHER),
                AT_RISK,
                true,
                A::Refuse(refuse(Some(LIVE), Defaulted(OTHER))),
            ),
            (
                Some(LIVE),
                Explicit(OTHER),
                AT_RISK,
                false,
                A::PreserveNoEmbedder,
            ),
            (
                Some(LIVE),
                Defaulted(OTHER),
                AT_RISK,
                false,
                A::PreserveNoEmbedder,
            ),
            (Some(LIVE), Explicit(OTHER), 0, true, A::ConvertEmpty),
            (Some(LIVE), Defaulted(OTHER), 0, true, A::ConvertEmpty),
            (Some(LIVE), Explicit(OTHER), 0, false, A::PreserveNoEmbedder),
            (
                Some(LIVE),
                Defaulted(OTHER),
                0,
                false,
                A::PreserveNoEmbedder,
            ),
            (
                None,
                Explicit(OTHER),
                AT_RISK,
                true,
                A::Refuse(refuse(None, Explicit(OTHER))),
            ),
            (None, Defaulted(OTHER), 0, true, A::ConvertEmpty),
            (None, Explicit(OTHER), AT_RISK, false, A::PreserveNoEmbedder),
            (Some(-1), Explicit(SAME), 0, true, A::ConvertEmpty),
        ];
        for (live, intent, at_risk, embedder, expected) in rows {
            assert_eq!(
                decide_auto_migrate(live, intent, at_risk, embedder),
                expected,
                "live={live:?} intent={intent:?} at_risk={at_risk} embedder={embedder}"
            );
        }
    }

    #[test]
    fn schema_init_table_9933() {
        use SchemaInitDecision as S;
        let rows: [(Option<i32>, EmbeddingDimIntent, bool, i64, S); 12] = [
            (
                Some(LIVE),
                Explicit(OTHER),
                false,
                AT_RISK,
                S::Migrate { force: false },
            ),
            (
                Some(LIVE),
                Explicit(OTHER),
                true,
                AT_RISK,
                S::Migrate { force: true },
            ),
            (
                Some(LIVE),
                Explicit(SAME),
                false,
                AT_RISK,
                S::Migrate { force: false },
            ),
            (
                Some(LIVE),
                Explicit(SAME),
                true,
                AT_RISK,
                S::Migrate { force: true },
            ),
            (
                Some(LIVE),
                Defaulted(SAME),
                false,
                AT_RISK,
                S::Migrate { force: false },
            ),
            (
                Some(LIVE),
                Defaulted(SAME),
                true,
                AT_RISK,
                S::Migrate { force: false },
            ),
            (Some(LIVE), Defaulted(OTHER), false, AT_RISK, S::AdoptLive),
            (Some(LIVE), Defaulted(OTHER), false, 0, S::AdoptLive),
            (
                Some(LIVE),
                Defaulted(OTHER),
                true,
                0,
                S::Migrate { force: false },
            ),
            (
                Some(LIVE),
                Defaulted(OTHER),
                true,
                AT_RISK,
                S::Refuse(refuse(Some(LIVE), Defaulted(OTHER))),
            ),
            (None, Defaulted(OTHER), false, 0, S::AdoptLive),
            (
                None,
                Defaulted(OTHER),
                true,
                AT_RISK,
                S::Refuse(refuse(None, Defaulted(OTHER))),
            ),
        ];
        for (live, intent, force, at_risk, expected) in rows {
            assert_eq!(
                decide_schema_init(live, intent, force, at_risk),
                expected,
                "live={live:?} intent={intent:?} force={force} at_risk={at_risk}"
            );
        }
    }

    #[test]
    fn refusal_text_names_both_dims_and_opt_in_9933() {
        assert_eq!(
            refuse(Some(LIVE), Defaulted(OTHER)).to_string(),
            EXPECTED_DEFAULTED
        );
        assert_eq!(
            refuse(Some(LIVE), Explicit(OTHER)).to_string(),
            EXPECTED_EXPLICIT
        );
        assert_eq!(
            refuse(None, Explicit(OTHER)).to_string(),
            EXPECTED_NO_COLUMN
        );
        let err: StoreError = refuse(Some(LIVE), Explicit(OTHER)).into();
        assert_eq!(
            err.to_string(),
            format!("invalid input: {EXPECTED_EXPLICIT}")
        );
    }

    #[test]
    fn intent_accessors_9933() {
        assert_eq!(Explicit(OTHER).dim(), OTHER);
        assert_eq!(Defaulted(SAME).dim(), SAME);
        assert_eq!(Explicit(OTHER).source_label(), EXPLICIT_SOURCE_LABEL);
        assert_eq!(Defaulted(OTHER).source_label(), DEFAULTED_SOURCE_LABEL);
        // No wrap: u32::MAX never equals a negative or smaller i32.
        assert!(!Explicit(u32::MAX).matches_live(Some(-1)));
        assert!(!Explicit(u32::MAX).matches_live(Some(i32::MAX)));
        assert!(Explicit(SAME).matches_live(Some(LIVE)));
        assert!(!Explicit(SAME).matches_live(None));
        let m = refuse(Some(LIVE), Defaulted(OTHER));
        assert_eq!(
            (m.live(), m.intent(), m.at_risk()),
            (Some(LIVE), Defaulted(OTHER), AT_RISK)
        );
    }

    #[test]
    fn intent_for_tags_the_source_9933() {
        assert_eq!(intent_for(OTHER, true), Explicit(OTHER));
        assert_eq!(intent_for(OTHER, false), Defaulted(OTHER));
    }

    /// Unset, empty and whitespace names are not a choice (they fall to the
    /// safe Defaulted side); a real name in either field is.
    #[test]
    #[allow(deprecated)]
    fn config_names_embedder_model_rows_9933() {
        use crate::config::{AppConfig, EmbeddingsSection};
        const NAME: &str = "nomic_embed_v15";
        let section = |m: Option<&str>| {
            Some(EmbeddingsSection {
                model: m.map(str::to_string),
                ..EmbeddingsSection::default()
            })
        };
        let rows: [(Option<EmbeddingsSection>, Option<&str>, bool); 9] = [
            (None, None, false),
            (section(None), None, false),
            (section(Some("")), None, false),
            (section(Some(" \t\n")), None, false),
            (None, Some(""), false),
            (None, Some("   "), false),
            (section(Some(NAME)), None, true),
            (None, Some(NAME), true),
            (section(Some(" ")), Some(NAME), true),
        ];
        for (embeddings, legacy, expected) in rows {
            let app = AppConfig {
                embeddings: embeddings.clone(),
                embedding_model: legacy.map(str::to_string),
                ..AppConfig::default()
            };
            assert_eq!(
                config_names_embedder_model(&app),
                expected,
                "embeddings={embeddings:?} legacy={legacy:?}"
            );
        }
    }

    #[test]
    fn api_dim_is_explicit_rows_9933() {
        use crate::config::EmbedDimSource as D;
        let rows = [
            (D::Env, true),
            (D::ConfigFile, true),
            (D::CompiledTable, false),
            (D::Unknown, false),
        ];
        for (source, expected) in rows {
            // No wildcard: a new variant breaks the build until its row exists.
            match source {
                D::Env | D::ConfigFile | D::CompiledTable | D::Unknown => {}
            }
            assert_eq!(api_dim_is_explicit(source), expected, "{source:?}");
        }
    }
}
