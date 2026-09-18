// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v0.9.0 G13-mem (#1859) — the postgres lineage walk: the recursive-CTE
//! builder, the Apache AGE Cypher walk with its relational cid fill, the
//! backend dispatcher, and the #3041 cycle check that guards a lineage edge
//! write — plus the two helpers only they use.
//!
//! Moved here VERBATIM from `src/store/postgres.rs` at v1.0.0 #3614 (rule l:
//! moved code is not added code). The #3614 change — a #1948 QUARANTINED
//! node never renders on either walk, through the ONE
//! [`crate::models::quarantine_hidden_clause`] both backends share — would
//! otherwise have crossed the `qual_10_module_size_ceiling` that file sat
//! one line under, and a ceiling bump to fit 21 lines ships a defect as a
//! ceiling (rule f). The wiring mirrors `postgres/parity_3064.rs`: an
//! `impl PostgresStore` block whose methods the trait arms in `postgres.rs`
//! forward to.

use super::{
    AGE_COL_PATH_EDGES, Agtype, CTX_BEGIN_AGE_TX, CTX_COMMIT_AGE_TX, CTX_SET_SEARCH_PATH,
    KgBackend, PostgresStore, READ_DEPTH, READ_PATH_EDGES, READ_RELATION, READ_RELATION_COL,
    SQL_SET_AGE_SEARCH_PATH, StoreError, StoreResult, age_cell_text_required,
    age_decode_entity_list, age_edge_is_lineage_relation, age_last_edge_relation, age_params_jsonb,
    is_age_runtime_failure, load_age_tolerated, strip_agtype_quotes, to_store_err,
    warn_age_fallback,
};

impl PostgresStore {
    /// v0.9.0 G13-mem (#1859) — recursive-CTE lineage walk over the
    /// provenance subset P = {`derived_from`, `reflects_on`,
    /// `derives_from`} (postgres twin of `db::lineage_ancestors` /
    /// `db::lineage_descendants`). `ancestors=true` walks source ->
    /// target (older provenance); `false` walks target -> source (newer
    /// derivatives). Resolves each node's cid from the edge's stored
    /// `*_cid` mirror with a LEFT JOIN fallback to `memories.cid`;
    /// deliberately does NOT filter a Tombstoned node — a Tombstoned
    /// ancestor is the whole point of a conserved lineage — while a #1948
    /// QUARANTINED node is never rendered (#3614, the one
    /// [`crate::models::quarantine_hidden_clause`] both backends share;
    /// the walk still passes through it).
    ///
    /// # Errors
    ///
    /// `StoreError::InvalidInput` for `max_depth` outside
    /// `[1, LINEAGE_MAX_DEPTH]`; `BackendUnavailable` for sqlx errors.
    pub async fn lineage_cte(
        &self,
        root_id: &str,
        max_depth: usize,
        ancestors: bool,
    ) -> StoreResult<Vec<crate::models::LineageNode>> {
        validate_lineage_depth(max_depth)?;
        let depth_cap = i32::try_from(max_depth).unwrap_or(i32::MAX);
        let p_in_list = lineage_relation_in_list();
        let (anchor_col, node_col, edge_cid_col) = if ancestors {
            ("source_id", "target_id", "target_cid")
        } else {
            ("target_id", "source_id", "source_cid")
        };
        // Diamond-shaped provenance can reach one node through several
        // paths; DISTINCT ON keeps the shortest-hop row per node so the
        // wire shape matches the sqlite MIN(depth) GROUP BY.
        let sql = format!(
            "SELECT node_id, cid, relation, depth FROM (
                SELECT DISTINCT ON (t.node_id)
                       t.node_id, COALESCE(t.edge_cid, m.cid) AS cid,
                       t.relation, t.depth
                FROM (
                    WITH RECURSIVE lineage(node_id, relation, edge_cid, depth, path) AS (
                        SELECT ml.{node_col}, ml.relation, ml.{edge_cid_col}, 1,
                               ARRAY[ml.{anchor_col}, ml.{node_col}]::TEXT[]
                        FROM memory_links ml
                        WHERE ml.{anchor_col} = $1 AND ml.relation IN ({p_in_list})
                        UNION ALL
                        SELECT ml.{node_col}, ml.relation, ml.{edge_cid_col}, t.depth + 1,
                               t.path || ml.{node_col}
                        FROM memory_links ml
                        JOIN lineage t ON ml.{anchor_col} = t.node_id
                        WHERE t.depth < $2 AND ml.relation IN ({p_in_list})
                          AND NOT (ml.{node_col} = ANY(t.path))
                    )
                    SELECT node_id, relation, edge_cid, depth FROM lineage
                ) t
                LEFT JOIN memories m ON m.id = t.node_id
                WHERE 1 = 1 {quarantine_hidden}
                ORDER BY t.node_id, t.depth ASC
            ) q
            ORDER BY depth ASC, node_id ASC",
            // #3614 (transitive arm) — same clause as the sqlite walk and the
            // direct lister: a quarantined node never renders.
            quarantine_hidden = crate::models::quarantine_hidden_clause("m"),
        );

        let rows = sqlx::query(&sql)
            .bind(root_id)
            .bind(depth_cap)
            .fetch_all(&self.pool)
            .await
            .map_err(|e| to_store_err("cte lineage", e))?;

        rows.iter()
            .map(|r| {
                use sqlx::Row;
                let depth_i: i32 = r
                    .try_get::<i32, _>("depth")
                    .map_err(|e| to_store_err(READ_DEPTH, e))?;
                Ok(crate::models::LineageNode {
                    id: r
                        .try_get::<String, _>("node_id")
                        .map_err(|e| to_store_err("read node_id", e))?,
                    cid: r
                        .try_get::<Option<String>, _>("cid")
                        .map_err(|e| to_store_err("read cid", e))?,
                    relation: r
                        .try_get::<String, _>(READ_RELATION_COL)
                        .map_err(|e| to_store_err(READ_RELATION, e))?,
                    depth: usize::try_from(depth_i).unwrap_or(0),
                })
            })
            .collect()
    }

    /// #3041 pg-twin — would adding the lineage edge `source_id` ->
    /// `target_id` (child -> parent) close a cycle in the provenance graph
    /// P = {`derived_from`, `reflects_on`, `derives_from`}? Returns `true`
    /// (REFUSE) iff `source_id` is ALREADY a lineage ancestor of `target_id`
    /// — i.e. a path `target -> … -> source` over P edges already exists — so
    /// the new edge would complete `source -> target -> … -> source`.
    ///
    /// This is the postgres structural twin of the sqlite
    /// `db::lineage_would_close_cycle`, backing the EQUAL-instant arm of
    /// [`Self::validate_link_pre_create_pg`] Pass 0. Before #3041 that pass
    /// used a bare `target_at > source_at`, which on an EXACT tie was `false`
    /// and ADMITTED the edge with NO structural check — while Pass 1 (the
    /// `reflects_on` cycle gate) runs only for `reflects_on`, so
    /// `derived_from` / `derives_from` equal-instant edges had NO backstop and
    /// a 2-cycle (that sqlite structurally refuses) could form on postgres.
    ///
    /// COMPLETENESS + fail-CLOSED (parity with sqlite): the recursive-CTE walk
    /// runs to [`crate::storage::LINEAGE_CYCLE_CHECK_MAX_DEPTH`] (far above the
    /// read budget, so a pathologically deep equal-instant clique is still
    /// resolved) and the `path` visited-set guarantees termination. Any sqlx
    /// error OR a ceiling-truncated walk (which could hide a deeper cycle)
    /// returns `true`: admitting a cycle-forming edge would corrupt the
    /// single-node acyclicity invariant, whereas refusing merely reduces
    /// function (North Star: degrade, never corrupt). The walk is purely
    /// STRUCTURAL (follows edge ids, never re-compares `created_at`).
    pub(super) async fn lineage_would_close_cycle_pg(
        &self,
        source_id: &str,
        target_id: &str,
    ) -> bool {
        let p_in_list = lineage_relation_in_list();
        let ceiling = crate::storage::LINEAGE_CYCLE_CHECK_MAX_DEPTH;
        let ceiling_i32 = i32::try_from(ceiling).unwrap_or(i32::MAX);
        // Lean id-only twin of `lineage_cte` (ancestors direction: anchor =
        // source_id, node = target_id). Same per-hop P filter and same
        // `= ANY(path)` visited-set guard; aggregates to (found, max_depth).
        let sql = format!(
            "WITH RECURSIVE walk(node_id, depth, path) AS (
                 SELECT ml.target_id, 1, ARRAY[ml.source_id, ml.target_id]::TEXT[]
                 FROM memory_links ml
                 WHERE ml.source_id = $1 AND ml.relation IN ({p_in_list})
               UNION ALL
                 SELECT ml.target_id, w.depth + 1, w.path || ml.target_id
                 FROM memory_links ml
                 JOIN walk w ON ml.source_id = w.node_id
                 WHERE w.depth < $2 AND ml.relation IN ({p_in_list})
                   AND NOT (ml.target_id = ANY(w.path))
             )
             SELECT COALESCE(bool_or(node_id = $3), false) AS found,
                    COALESCE(max(depth), 0) AS max_depth
             FROM walk"
        );
        match sqlx::query_as::<_, (bool, i32)>(&sql)
            .bind(target_id)
            .bind(ceiling_i32)
            .bind(source_id)
            .fetch_one(&self.pool)
            .await
        {
            // Refuse on a hit OR on truncation: the CTE caps `depth < $2`, so
            // a reached depth == the ceiling means the walk may have stopped
            // short of a deeper `source` — treat as a positive (fail CLOSED).
            Ok((found, max_depth)) => found || max_depth >= ceiling_i32,
            Err(e) => {
                // Fail CLOSED — a traversal error must never let a
                // cycle-forming edge through (the #3041 pg fail-open class).
                tracing::warn!(
                    "lineage cycle-check walk failed; refusing edge \
                     {source_id} -> {target_id}: {e}"
                );
                true
            }
        }
    }

    /// v0.9.0 G13-mem (#1859) — Cypher (Apache AGE) lineage walk over the
    /// `memory_graph` projection. COND 5: the relation is peeled from the
    /// path's RELATIONSHIPS (`last(r).relation`, the `kg_query_cypher`
    /// shape — an edge property, never `nodes(p)`), and cids live on the
    /// RELATIONAL side, so after the graph walk the node ids are JOINed
    /// back to `memories` for the cid fill — keeping the
    /// `{id, cid, relation, depth}` wire shape byte-compatible with the
    /// CTE branch. Duplicate multi-path hits collapse to the minimum
    /// depth per node (the CTE's DISTINCT ON twin).
    ///
    /// # Errors
    ///
    /// `StoreError::InvalidInput` for an out-of-range `max_depth`;
    /// `BackendUnavailable` for any sqlx or AGE error (the dispatcher
    /// falls back to [`Self::lineage_cte`] on the latter).
    pub async fn lineage_cypher(
        &self,
        root_id: &str,
        max_depth: usize,
        ancestors: bool,
    ) -> StoreResult<Vec<crate::models::LineageNode>> {
        validate_lineage_depth(max_depth)?;

        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| to_store_err(CTX_BEGIN_AGE_TX, e))?;
        load_age_tolerated(&mut tx).await?;
        sqlx::query(SQL_SET_AGE_SEARCH_PATH)
            .execute(&mut *tx)
            .await
            .map_err(|e| to_store_err(CTX_SET_SEARCH_PATH, e))?;

        // #2511 — the pattern is UNTYPED (`-[r*1..N]->`) and the
        // provenance-subset P filter is applied Rust-side per edge.
        //
        // Pre-#2511 this built a relationship-type ALTERNATION
        // (`-[r:derived_from|reflects_on|derives_from*1..N]->`), which
        // Apache AGE's cypher parser does not implement AT ALL —
        // `ERROR: syntax error at or near "|"`, with or without a
        // variable-length quantifier, verified live on AGE 1.7.0. Together
        // with `length(r)` (which parses but raises `length() argument must
        // resolve to a scalar` at RUNTIME on a var-length pattern's
        // relationship list) that made the whole statement unusable, so
        // `lineage` on AGE has always fallen through to `lineage_cte`.
        //
        // The Rust-side P filter is STRICTER than a per-hop label match has
        // to be, and deliberately so: EVERY edge on the path must be in P,
        // mirroring `lineage_cte`'s `relation IN (...)` on both the seed and
        // the recursive step. An untyped traversal would otherwise surface a
        // path that hops through a `related_to` edge, which the CTE can
        // never return — a wrong result, not merely a different one.
        //
        // `max_depth` is clamped upstream (no injection surface); the start
        // id binds through AGE's `$vars` JSON.
        let pattern = if ancestors {
            format!("(a)-[r*1..{max_depth}]->(b)")
        } else {
            format!("(a)<-[r*1..{max_depth}]-(b)")
        };
        let cypher = format!(
            "MATCH p = {pattern} WHERE a.id = $start_id \
             RETURN b.id AS node_id, relationships(p) AS path_edges"
        );
        // #2511 — bare `agtype`-typed `$1` Param, not an inlined
        // `'{…}'::agtype` literal (which AGE's analyzer rejects). See
        // [`Agtype`].
        let params = age_params_jsonb(&[("start_id", root_id)]);
        let sql = format!(
            "SELECT node_id, path_edges FROM cypher('memory_graph', $$ {cypher} $$, \
             $1) AS (node_id agtype, path_edges agtype)"
        );

        // #1482 — per-call-unique cypher text (label alternation +
        // interpolated depth); run unnamed.
        let rows = sqlx::query(&sql)
            .bind(Agtype(params))
            .persistent(false)
            .fetch_all(&mut *tx)
            .await
            .map_err(|e| to_store_err("cypher lineage", e))?;
        tx.commit()
            .await
            .map_err(|e| to_store_err(CTX_COMMIT_AGE_TX, e))?;

        // Decode agtype cells + collapse multi-path duplicates to the
        // minimum depth per node.
        let mut best: std::collections::BTreeMap<String, (String, usize)> =
            std::collections::BTreeMap::new();
        for r in &rows {
            // #2511 — agtype cells, not `String` cells (see `age_cell_text_opt`).
            let node_id = age_cell_text_required(r, "node_id", "read node_id")?;
            let edges_raw = age_cell_text_required(r, AGE_COL_PATH_EDGES, READ_PATH_EDGES)?;
            let edges = age_decode_entity_list(AGE_COL_PATH_EDGES, &edges_raw)?;
            if edges.is_empty() {
                // A `*1..N` pattern cannot match a zero-length path.
                return Err(StoreError::IntegrityFailed {
                    detail: "AGE lineage path carried no relationships".to_string(),
                });
            }
            // #2511 — the provenance-subset P filter AGE's parser cannot
            // express as a label alternation. EVERY edge must be in P, so a
            // path that hops through a non-lineage relation is dropped
            // exactly as `lineage_cte` drops it.
            if !edges.iter().all(age_edge_is_lineage_relation) {
                continue;
            }
            let depth = edges.len();
            let node_id = strip_agtype_quotes(&node_id).to_string();
            let relation = age_last_edge_relation(&edges);
            match best.get(&node_id) {
                Some((_, d)) if *d <= depth => {}
                _ => {
                    best.insert(node_id, (relation, depth));
                }
            }
        }

        // COND 5(c) — cid fill from the relational source of truth.
        // #3614 (transitive arm) — the same query names the QUARANTINED
        // nodes: the graph knows nothing of lifecycle, so the relational row
        // is the ONE predicate here too (`quarantine_hidden_clause`, applied
        // in SQL exactly as the CTE arms apply it), and those ids are dropped
        // before the render.
        let node_ids: Vec<String> = best.keys().cloned().collect();
        let mut cids: std::collections::BTreeMap<String, Option<String>> =
            std::collections::BTreeMap::new();
        let mut quarantined: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
        if !node_ids.is_empty() {
            let rows: Vec<(String, Option<String>)> =
                sqlx::query_as("SELECT id, cid FROM memories WHERE id = ANY($1)")
                    .bind(&node_ids)
                    .fetch_all(&self.pool)
                    .await
                    .map_err(|e| to_store_err("lineage cid fill", e))?;
            cids.extend(rows);
            let hidden_sql = format!(
                "SELECT id FROM memories WHERE id = ANY($1) AND NOT (1 = 1 {})",
                crate::models::quarantine_hidden_clause("")
            );
            let hidden: Vec<(String,)> = sqlx::query_as(&hidden_sql)
                .bind(&node_ids)
                .fetch_all(&self.pool)
                .await
                .map_err(|e| to_store_err("lineage quarantine filter", e))?;
            quarantined.extend(hidden.into_iter().map(|(id,)| id));
        }

        let mut out: Vec<crate::models::LineageNode> = best
            .into_iter()
            .filter(|(id, _)| !quarantined.contains(id))
            .map(|(id, (relation, depth))| crate::models::LineageNode {
                cid: cids.get(&id).cloned().flatten(),
                id,
                relation,
                depth,
            })
            .collect();
        out.sort_by(|a, b| a.depth.cmp(&b.depth).then_with(|| a.id.cmp(&b.id)));
        Ok(out)
    }

    /// v0.9.0 G13-mem (#1859) — backend dispatcher for a lineage walk.
    /// COND 5(a): mirrors `find_paths`'s FULL dispatch — under
    /// `KgBackend::Age` with `age_projection_mode() == Deferred` the walk
    /// routes to the always-current relational CTE (a just-written edge
    /// sits in `kg_projection_outbox`, and a healthy-but-stale AGE would
    /// return a successful-EMPTY ancestry the runtime-failure fallback
    /// cannot catch — breaking read-your-own-write on the
    /// store -> reflect -> consolidate acceptance path). Sync-mode AGE
    /// keeps the Cypher fast path with the graceful CTE fallback.
    pub async fn lineage_traverse(
        &self,
        root_id: &str,
        max_depth: usize,
        ancestors: bool,
    ) -> StoreResult<Vec<crate::models::LineageNode>> {
        match self.kg_backend {
            KgBackend::Age => {
                if matches!(
                    crate::config::age_projection_mode(),
                    crate::config::AgeProjectionMode::Deferred
                ) {
                    return self.lineage_cte(root_id, max_depth, ancestors).await;
                }
                match self.lineage_cypher(root_id, max_depth, ancestors).await {
                    Ok(rows) => Ok(rows),
                    Err(err) if is_age_runtime_failure(&err) => {
                        warn_age_fallback("lineage", root_id, &err);
                        self.lineage_cte(root_id, max_depth, ancestors).await
                    }
                    Err(err) => Err(err),
                }
            }
            KgBackend::Cte => self.lineage_cte(root_id, max_depth, ancestors).await,
        }
    }
}

/// v0.9.0 G13-mem (#1859) — validate a lineage-walk depth against the
/// shared [`crate::storage::LINEAGE_MAX_DEPTH`] budget (postgres twin of
/// the `db::lineage_traverse` gate, byte-identical error text).
fn validate_lineage_depth(max_depth: usize) -> StoreResult<()> {
    if max_depth == 0 {
        return Err(StoreError::InvalidInput {
            detail: crate::errors::msg::MAX_DEPTH_MIN.to_string(),
        });
    }
    let cap = crate::storage::LINEAGE_MAX_DEPTH;
    if max_depth > cap {
        return Err(StoreError::InvalidInput {
            detail: format!("max_depth={max_depth} exceeds supported depth={cap}"),
        });
    }
    Ok(())
}

/// v0.9.0 G13-mem (#1859) — the SQL `IN (...)` literal list for the
/// lineage provenance set, built from the typed SSOT
/// (`MemoryLinkRelation::LINEAGE`) so no traversal re-spells the strings.
fn lineage_relation_in_list() -> String {
    crate::models::MemoryLinkRelation::LINEAGE
        .iter()
        .map(|r| format!("'{}'", r.as_str()))
        .collect::<Vec<_>>()
        .join(", ")
}
