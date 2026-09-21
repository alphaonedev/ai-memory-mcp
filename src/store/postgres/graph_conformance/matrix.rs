// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

#![cfg(test)]

use super::{
    capture, evidence,
    fixture_tests::{Fixture, STAMP},
};

#[tokio::test]
#[ignore = "live AGE certification; scripts/check-graph-conformance.sh"]
async fn executed_graph_matrix() {
    let f = Fixture::new().await;
    for depth in 1..=3 {
        let (cte, plans) = capture(f.store.kg_query_cte(&f.ids[0], depth)).await;
        evidence(&format!("query-cte-{depth}"), &plans, &["cte/query"]);
        let (age, plans) = capture(f.store.kg_query_cypher(&f.ids[0], depth)).await;
        evidence(&format!("query-age-{depth}"), &plans, &["age/query"]);
        let mut cte = cte.expect("CTE query");
        let mut age = age.expect("AGE query");
        for rows in [&cte, &age] {
            assert!(
                rows.iter().any(|r| r.target_id == f.ids[1]),
                "live neighbor required"
            );
            assert!(
                !rows.iter().any(|r| r.target_id == f.ids[6]),
                "invalidated neighbor excluded"
            );
            assert!(
                !rows.iter().any(|r| r.target_id == f.ids[7]),
                "isolated node excluded"
            );
        }
        let key = |r: &crate::store::KgQueryRow| {
            (
                r.depth,
                r.target_id.clone(),
                r.relation.clone(),
                r.path.clone(),
            )
        };
        cte.sort_by_key(key);
        age.sort_by_key(key);
        assert_eq!(cte, age, "query depth {depth}");
    }
    for ancestors in [true, false] {
        let root = if ancestors { 0 } else { 5 };
        let (cte, plans) = capture(f.store.lineage_cte(&f.ids[root], 3, ancestors)).await;
        evidence(
            &format!("lineage-cte-{ancestors}"),
            &plans,
            &["cte/lineage"],
        );
        let (age, plans) = capture(f.store.lineage_cypher(&f.ids[root], 3, ancestors)).await;
        evidence(
            &format!("lineage-age-{ancestors}"),
            &plans,
            &["age/lineage"],
        );
        let cte = cte.expect("CTE lineage");
        let age = age.expect("AGE lineage");
        assert_eq!(cte.len(), 2, "two provenance ancestors/descendants");
        assert_eq!(
            serde_json::to_value(cte).expect("serialize"),
            serde_json::to_value(age).expect("serialize")
        );
    }
    // find_paths is intentionally relational on AGE (#2582/#2613).
    let (paths, plans) = capture(f.store.find_paths(&f.ids[0], &f.ids[3], Some(3), Some(50))).await;
    evidence("paths-on-age", &plans, &["cte/paths"]);
    let paths = paths.expect("bounded path traversal");
    assert!(!paths.is_empty());
    assert!(plans.iter().all(|p| p.site == "cte/paths"));
    let (absent, plans) =
        capture(f.store.find_paths(&f.ids[0], &f.ids[6], Some(3), Some(50))).await;
    evidence("paths-invalidated", &plans, &["cte/paths"]);
    assert!(absent.expect("historical target paths").is_empty());

    // Timeline is compared raw for live rows. #3809 is pinned separately
    // below so E1 cannot silently normalize the measured divergence away.
    let (cte, plans) = capture(f.store.kg_timeline_cte(&f.ids[1], None, None, None)).await;
    evidence("timeline-cte", &plans, &["cte/timeline"]);
    let (age, plans) = capture(f.store.kg_timeline_cypher(&f.ids[1], None, None, None)).await;
    evidence("timeline-age", &plans, &["age/timeline"]);
    let mut cte = cte.expect("CTE timeline");
    let mut age = age.expect("AGE timeline");
    assert_eq!(cte.len(), 2);
    cte.sort_by(|a, b| a.target_id.cmp(&b.target_id));
    age.sort_by(|a, b| a.target_id.cmp(&b.target_id));
    assert_eq!(cte, age);
}

#[tokio::test]
#[ignore = "live AGE certification; scripts/check-graph-conformance.sh"]
async fn executed_invalidation_and_timestamp_divergence() {
    let f = Fixture::new().await;
    let (cte, plans) =
        capture(
            f.store
                .kg_invalidate_cte(&f.ids[0], &f.ids[1], "supersedes", Some(STAMP), None),
        )
        .await;
    evidence("invalidate-cte", &plans, &["cte/invalidate"]);
    assert_eq!(
        f.age_stamp(0, 1, "supersedes").await,
        None,
        "CTE does not update projection"
    );
    let (age, plans) = capture(f.store.kg_invalidate_cypher(
        &f.ids[0],
        &f.ids[1],
        "supersedes",
        Some(STAMP),
        None,
    ))
    .await;
    evidence(
        "invalidate-age",
        &plans,
        &[
            "age/invalidate-read",
            "age/invalidate-set",
            "cte/invalidate",
        ],
    );
    let cte = cte.expect("CTE invalidate");
    let age = age.expect("AGE invalidate");
    assert!(cte.found && age.found);
    assert_eq!(cte, age);
    assert_eq!(
        f.age_stamp(0, 1, "supersedes").await.as_deref(),
        Some(STAMP)
    );
    assert_eq!(
        f.age_stamp(0, 1, "related_to").await,
        None,
        "parallel live edge survives"
    );
    let (cte, plans) = capture(f.store.kg_timeline_cte(&f.ids[0], None, None, None)).await;
    evidence("divergence-timeline-cte", &plans, &["cte/timeline"]);
    let (age, plans) = capture(f.store.kg_timeline_cypher(&f.ids[0], None, None, None)).await;
    evidence("divergence-timeline-age", &plans, &["age/timeline"]);
    let cte = cte.expect("CTE historical timeline");
    let age = age.expect("AGE historical timeline");
    let c = cte
        .iter()
        .find(|r| r.relation == "supersedes")
        .expect("CTE historical edge");
    let a = age
        .iter()
        .find(|r| r.relation == "supersedes")
        .expect("AGE historical edge");
    assert_eq!(c.valid_until.as_deref(), Some("2020-01-01T00:00:00+00:00"));
    assert_eq!(a.valid_until.as_deref(), Some(STAMP));
    assert_ne!(
        c.valid_until, a.valid_until,
        "#3809 converged: replace this known-divergence pin in E2"
    );
}
