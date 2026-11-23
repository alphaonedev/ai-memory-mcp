//! Unit tables for `embedding_dim_policy` (#9933, #9952). Kept beside the
//! module so the decision tables stay readable without growing it.

use super::*;

const LIVE: i32 = 768;
const OTHER: u32 = 384;
const SAME: u32 = 768;
const AT_RISK: i64 = 3;

const EXPECTED_DEFAULTED: &str = "refusing destructive embedding-dim conversion: live column is vector(768), requested vector(384) from a defaulted dimension (tier preset or compiled default); 3 stored embeddings would be NULLed. To keep them, configure an embedder whose dimension is 768; to convert them and re-embed, run `ai-memory schema-init --embedding-dim 384 --force-reembed`.";
const EXPECTED_CONFIGURED: &str = "refusing destructive embedding-dim conversion: live column is vector(768), requested vector(384) from a configured dimension (environment variable, config file or embedding model); 3 stored embeddings would be NULLed. To keep them, configure an embedder whose dimension is 768; to convert them and re-embed, run `ai-memory schema-init --embedding-dim 384 --force-reembed`.";
const EXPECTED_EXPLICIT: &str = "refusing destructive embedding-dim conversion: live column is vector(768), requested vector(384) from an explicit --embedding-dim argument; 3 stored embeddings would be NULLed. To keep them, configure an embedder whose dimension is 768; to convert them and re-embed, run `ai-memory schema-init --embedding-dim 384 --force-reembed`.";
const EXPECTED_NO_COLUMN: &str = "refusing destructive embedding-dim conversion: live column has no declared vector dimension, requested vector(384) from an explicit --embedding-dim argument; 3 stored embeddings would be NULLed. To convert them and re-embed, run `ai-memory schema-init --embedding-dim 384 --force-reembed`.";

use AutoMigrateDecision as A;
use EmbeddingDimIntent::{Configured, Defaulted, Explicit};
use SchemaInitDecision as S;

fn refuse(live: Option<i32>, intent: EmbeddingDimIntent) -> EmbeddingDimMismatch {
    EmbeddingDimMismatch::new(live, intent, AT_RISK)
}

fn order(dim: u32) -> ForceReembedOrder {
    ForceReembedOrder::from_argv(Some(dim), true).expect("both flags build an order")
}

/// Every intent kind, both dims, for the exhaustive invariant sweeps.
fn all_intents() -> [EmbeddingDimIntent; 6] {
    [
        Explicit(SAME),
        Explicit(OTHER),
        Configured(SAME),
        Configured(OTHER),
        Defaulted(SAME),
        Defaulted(OTHER),
    ]
}

fn all_requests() -> [ReembedRequest; 4] {
    [
        ReembedRequest::NotRequested,
        ReembedRequest::WithoutDim,
        ReembedRequest::Order(order(SAME)),
        ReembedRequest::Order(order(OTHER)),
    ]
}

/// Every (live, intent, at_risk, embedder) combination over the corpus,
/// with the expected decision written out by hand.
#[test]
fn auto_migrate_table_9933() {
    let rows: [(Option<i32>, EmbeddingDimIntent, i64, bool, A); 20] = [
        (Some(LIVE), Explicit(SAME), AT_RISK, true, A::Keep),
        (Some(LIVE), Explicit(SAME), 0, false, A::Keep),
        (Some(LIVE), Configured(SAME), AT_RISK, true, A::Keep),
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
            Configured(OTHER),
            AT_RISK,
            true,
            A::Refuse(refuse(Some(LIVE), Configured(OTHER))),
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
            Configured(OTHER),
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
        (Some(LIVE), Configured(OTHER), 0, true, A::ConvertEmpty),
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
            Configured(OTHER),
            AT_RISK,
            true,
            A::Refuse(refuse(None, Configured(OTHER))),
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

/// #9952 — the hand-written schema-init table, one row per branch.
#[test]
fn schema_init_table_9952() {
    use ReembedRequest as R;
    let rows: [(Option<i32>, EmbeddingDimIntent, ReembedRequest, i64, S); 22] = [
        // Matching column: never an order, whatever the request.
        (
            Some(LIVE),
            Explicit(SAME),
            R::Order(order(SAME)),
            AT_RISK,
            S::Migrate { order: None },
        ),
        (
            Some(LIVE),
            Configured(SAME),
            R::WithoutDim,
            AT_RISK,
            S::Migrate { order: None },
        ),
        (
            Some(LIVE),
            Defaulted(SAME),
            R::WithoutDim,
            AT_RISK,
            S::Migrate { order: None },
        ),
        // Explicit: the order passes only for its own dim.
        (
            Some(LIVE),
            Explicit(OTHER),
            R::Order(order(OTHER)),
            AT_RISK,
            S::Migrate {
                order: Some(order(OTHER)),
            },
        ),
        (
            Some(LIVE),
            Explicit(OTHER),
            R::Order(order(SAME)),
            AT_RISK,
            S::Migrate { order: None },
        ),
        (
            Some(LIVE),
            Explicit(OTHER),
            R::WithoutDim,
            AT_RISK,
            S::Migrate { order: None },
        ),
        (
            Some(LIVE),
            Explicit(OTHER),
            R::NotRequested,
            AT_RISK,
            S::Migrate { order: None },
        ),
        (
            Some(LIVE),
            Explicit(OTHER),
            R::NotRequested,
            0,
            S::Migrate { order: None },
        ),
        (
            None,
            Explicit(OTHER),
            R::Order(order(OTHER)),
            AT_RISK,
            S::Migrate {
                order: Some(order(OTHER)),
            },
        ),
        // Configured (env / config file / model): never an order (#9956).
        (
            Some(LIVE),
            Configured(OTHER),
            R::WithoutDim,
            AT_RISK,
            S::Refuse(refuse(Some(LIVE), Configured(OTHER))),
        ),
        (
            Some(LIVE),
            Configured(OTHER),
            R::Order(order(OTHER)),
            AT_RISK,
            S::Refuse(refuse(Some(LIVE), Configured(OTHER))),
        ),
        (
            Some(LIVE),
            Configured(OTHER),
            R::NotRequested,
            AT_RISK,
            S::Refuse(refuse(Some(LIVE), Configured(OTHER))),
        ),
        (
            Some(LIVE),
            Configured(OTHER),
            R::WithoutDim,
            0,
            S::Migrate { order: None },
        ),
        (
            Some(LIVE),
            Configured(OTHER),
            R::NotRequested,
            0,
            S::Migrate { order: None },
        ),
        (
            None,
            Configured(OTHER),
            R::WithoutDim,
            AT_RISK,
            S::Refuse(refuse(None, Configured(OTHER))),
        ),
        // Defaulted: adopt the live column unless --force-reembed was given.
        (
            Some(LIVE),
            Defaulted(OTHER),
            R::NotRequested,
            AT_RISK,
            S::AdoptLive,
        ),
        (
            Some(LIVE),
            Defaulted(OTHER),
            R::NotRequested,
            0,
            S::AdoptLive,
        ),
        (
            Some(LIVE),
            Defaulted(OTHER),
            R::WithoutDim,
            0,
            S::Migrate { order: None },
        ),
        (
            Some(LIVE),
            Defaulted(OTHER),
            R::WithoutDim,
            AT_RISK,
            S::Refuse(refuse(Some(LIVE), Defaulted(OTHER))),
        ),
        (
            Some(LIVE),
            Defaulted(OTHER),
            R::Order(order(OTHER)),
            AT_RISK,
            S::Refuse(refuse(Some(LIVE), Defaulted(OTHER))),
        ),
        (None, Defaulted(OTHER), R::NotRequested, 0, S::AdoptLive),
        (
            None,
            Defaulted(OTHER),
            R::WithoutDim,
            AT_RISK,
            S::Refuse(refuse(None, Defaulted(OTHER))),
        ),
    ];
    for (live, intent, request, at_risk, expected) in rows {
        assert_eq!(
            decide_schema_init(live, intent, request, at_risk),
            expected,
            "live={live:?} intent={intent:?} request={request:?} at_risk={at_risk}"
        );
    }
}

/// #9952 — the invariant over the whole product of the domain: an order
/// leaves `decide_schema_init` only for an `Explicit(d)` intent whose argv
/// order names `d`, on a column that does not already match.
#[test]
fn schema_init_order_only_for_its_explicit_dim_9952() {
    let mut rows = 0_u32;
    for live in [Some(LIVE), None, Some(-1)] {
        for intent in all_intents() {
            for request in all_requests() {
                for at_risk in [0, AT_RISK] {
                    rows += 1;
                    let decision = decide_schema_init(live, intent, request, at_risk);
                    let carries_order = matches!(decision, S::Migrate { order: Some(_) });
                    let allowed = match (intent, request) {
                        (Explicit(d), ReembedRequest::Order(o)) => {
                            o.dim() == d && !intent.matches_live(live)
                        }
                        _ => false,
                    };
                    assert_eq!(
                        carries_order, allowed,
                        "live={live:?} intent={intent:?} request={request:?} at_risk={at_risk}"
                    );
                }
            }
        }
    }
    assert_eq!(rows, 144, "3 lives x 6 intents x 4 requests x 2 counts");
}

/// #9952 — `from_argv` builds an order only from both flags, exhaustively.
#[test]
fn force_reembed_order_from_argv_rows_9952() {
    let rows: [(Option<u32>, bool, Option<u32>); 6] = [
        (None, false, None),
        (None, true, None),
        (Some(OTHER), false, None),
        (Some(OTHER), true, Some(OTHER)),
        (Some(0), true, Some(0)),
        (Some(u32::MAX), true, Some(u32::MAX)),
    ];
    for (dim, force, expected) in rows {
        assert_eq!(
            ForceReembedOrder::from_argv(dim, force).map(ForceReembedOrder::dim),
            expected,
            "dim={dim:?} force={force}"
        );
    }
}

/// #9952 — an order authorises only the explicit intent of its own dim.
#[test]
fn force_reembed_order_authorizes_rows_9952() {
    let rows: [(u32, EmbeddingDimIntent, bool); 8] = [
        (OTHER, Explicit(OTHER), true),
        (OTHER, Explicit(SAME), false),
        (OTHER, Configured(OTHER), false),
        (OTHER, Defaulted(OTHER), false),
        (SAME, Explicit(SAME), true),
        (SAME, Configured(SAME), false),
        (SAME, Defaulted(SAME), false),
        (u32::MAX, Explicit(u32::MAX - 1), false),
    ];
    for (dim, intent, expected) in rows {
        assert_eq!(
            order(dim).authorizes(intent),
            expected,
            "dim={dim} intent={intent:?}"
        );
    }
}

#[test]
fn reembed_request_accessors_9952() {
    use ReembedRequest as R;
    let rows: [(ReembedRequest, Option<ForceReembedOrder>, bool); 3] = [
        (R::NotRequested, None, false),
        (R::WithoutDim, None, true),
        (R::Order(order(OTHER)), Some(order(OTHER)), true),
    ];
    for (request, expected_order, expected_flag) in rows {
        assert_eq!(request.order(), expected_order, "{request:?}");
        assert_eq!(request.force_flag(), expected_flag, "{request:?}");
    }
}

#[test]
fn refusal_text_names_both_dims_and_opt_in_9933() {
    assert_eq!(
        refuse(Some(LIVE), Defaulted(OTHER)).to_string(),
        EXPECTED_DEFAULTED
    );
    assert_eq!(
        refuse(Some(LIVE), Configured(OTHER)).to_string(),
        EXPECTED_CONFIGURED
    );
    assert_eq!(
        refuse(Some(LIVE), Explicit(OTHER)).to_string(),
        EXPECTED_EXPLICIT
    );
    assert_eq!(
        refuse(None, Explicit(OTHER)).to_string(),
        EXPECTED_NO_COLUMN
    );
    let err: StoreError = refuse(Some(LIVE), Configured(OTHER)).into();
    assert_eq!(
        err.to_string(),
        format!("invalid input: {EXPECTED_CONFIGURED}")
    );
}

#[test]
fn intent_accessors_9933() {
    assert_eq!(Explicit(OTHER).dim(), OTHER);
    assert_eq!(Configured(OTHER).dim(), OTHER);
    assert_eq!(Defaulted(SAME).dim(), SAME);
    assert_eq!(Explicit(OTHER).source_label(), EXPLICIT_SOURCE_LABEL);
    assert_eq!(Configured(OTHER).source_label(), CONFIGURED_SOURCE_LABEL);
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

/// #9952 — configuration never yields `Explicit`.
#[test]
fn intent_for_tags_the_source_9952() {
    assert_eq!(intent_for(OTHER, true), Configured(OTHER));
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
fn api_dim_is_configured_rows_9952() {
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
        assert_eq!(api_dim_is_configured(source), expected, "{source:?}");
    }
}
