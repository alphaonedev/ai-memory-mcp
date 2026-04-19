// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v0.6.0.0 — semantic clustering over memory embeddings.
//!
//! Lightweight in-process k-means. No new crate dep; the embedding
//! and vector math already in-tree (cosine similarity, HNSW) give us
//! everything we need.
//!
//! Exposed via the `memory_cluster` MCP tool which takes a namespace +
//! optional k, groups the namespace's embeddings into k clusters, and
//! returns the cluster assignments with a centroid tag label chosen
//! from the most common tag across cluster members.
//!
//! Scope: a minimal, deterministic pass-good-enough clustering that
//! agents can drive without a Python/scikit dependency. When k is
//! omitted, it defaults to `sqrt(n/2)` (a conventional rule of thumb
//! for k when the true structure is unknown), clamped to `[2, 16]`.

use std::collections::HashMap;

use rusqlite::{Connection, params};
use serde::Serialize;

/// A single cluster in the result.
#[allow(clippy::struct_field_names)]
#[derive(Debug, Clone, Serialize)]
pub struct Cluster {
    pub cluster_id: usize,
    pub memory_ids: Vec<String>,
    pub centroid_tags: Vec<String>,
    pub member_count: usize,
}

/// Minimum number of memories required to attempt clustering. Below
/// this, we return every memory as its own cluster.
pub const MIN_MEMBERS_FOR_CLUSTERING: usize = 4;

/// Compute k-means clusters for a namespace's memories. Results are
/// deterministic for a given (embeddings, k) input (seed is
/// fixed-from-first-member).
///
/// Returns `Ok(Vec<Cluster>)` sorted by descending `member_count`, or
/// `Err(anyhow)` if the DB scan fails.
#[allow(clippy::cast_precision_loss)]
#[allow(clippy::cast_possible_truncation)]
#[allow(clippy::cast_sign_loss)]
pub fn cluster_namespace(
    conn: &Connection,
    namespace: &str,
    k: Option<usize>,
) -> anyhow::Result<Vec<Cluster>> {
    let members = load_members(conn, namespace)?;
    if members.len() < MIN_MEMBERS_FOR_CLUSTERING {
        // Each memory becomes its own cluster.
        return Ok(members
            .into_iter()
            .enumerate()
            .map(|(i, m)| Cluster {
                cluster_id: i,
                memory_ids: vec![m.id],
                centroid_tags: m.tags.into_iter().take(3).collect(),
                member_count: 1,
            })
            .collect());
    }
    let k = k
        .unwrap_or_else(|| (((members.len() as f64) / 2.0).sqrt().ceil() as usize).max(2))
        .clamp(2, members.len().min(16));

    let embeddings: Vec<&[f32]> = members.iter().map(|m| m.embedding.as_slice()).collect();
    let assignments = kmeans(&embeddings, k, 25);

    // Group by assigned cluster id; compute centroid-tag labels per cluster
    // from the most frequent tags across its members.
    let mut groups: HashMap<usize, Vec<usize>> = HashMap::new();
    for (idx, cluster_id) in assignments.iter().enumerate() {
        groups.entry(*cluster_id).or_default().push(idx);
    }
    let mut clusters: Vec<Cluster> = groups
        .into_iter()
        .map(|(cluster_id, member_indices)| {
            let mut tag_counts: HashMap<String, usize> = HashMap::new();
            for i in &member_indices {
                for tag in &members[*i].tags {
                    *tag_counts.entry(tag.clone()).or_default() += 1;
                }
            }
            let mut sorted_tags: Vec<_> = tag_counts.into_iter().collect();
            sorted_tags.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
            let centroid_tags: Vec<String> =
                sorted_tags.into_iter().take(3).map(|(t, _)| t).collect();
            let memory_ids: Vec<String> = member_indices
                .iter()
                .map(|i| members[*i].id.clone())
                .collect();
            let member_count = memory_ids.len();
            Cluster {
                cluster_id,
                memory_ids,
                centroid_tags,
                member_count,
            }
        })
        .collect();
    clusters.sort_by(|a, b| b.member_count.cmp(&a.member_count));
    Ok(clusters)
}

struct Member {
    id: String,
    tags: Vec<String>,
    embedding: Vec<f32>,
}

fn load_members(conn: &Connection, namespace: &str) -> anyhow::Result<Vec<Member>> {
    let mut stmt = conn.prepare(
        "SELECT id, tags, embedding FROM memories \
         WHERE namespace = ?1 AND embedding IS NOT NULL",
    )?;
    let rows = stmt.query_map(params![namespace], |row| {
        let id: String = row.get(0)?;
        let tags_json: String = row.get(1)?;
        let emb_bytes: Vec<u8> = row.get(2)?;
        let tags: Vec<String> = serde_json::from_str(&tags_json).unwrap_or_default();
        let embedding: Vec<f32> = emb_bytes
            .chunks_exact(4)
            .map(|c| f32::from_le_bytes([c[0], c[1], c[2], c[3]]))
            .collect();
        Ok(Member {
            id,
            tags,
            embedding,
        })
    })?;
    rows.collect::<rusqlite::Result<Vec<_>>>()
        .map_err(Into::into)
}

/// Deterministic k-means on unit-normalized vectors. The initial
/// centroids are sampled from the first `k` distinct members (no
/// RNG — reproducible across calls with the same data). `max_iter`
/// caps convergence.
///
/// Returns a vector of cluster assignments, one per input vector.
#[allow(clippy::cast_precision_loss)]
fn kmeans(embeddings: &[&[f32]], k: usize, max_iter: usize) -> Vec<usize> {
    if embeddings.is_empty() || k == 0 {
        return Vec::new();
    }
    let dim = embeddings[0].len();
    // Seed centroids by equal-index stride across the input so that
    // clusters that arrive in order (as rows tend to) get representative
    // seed points from each region rather than k nearly-identical
    // neighbors in the first few positions. Deterministic and cheap;
    // a k-means++ seeding pass is a v0.6.1 polish target.
    let n = embeddings.len();
    let stride = (n / k).max(1);
    let mut centroids: Vec<Vec<f32>> = (0..k)
        .map(|i| embeddings[(i * stride).min(n - 1)].to_vec())
        .collect();
    // Pad if there are fewer than k members (caller already clamps,
    // but defensive).
    while centroids.len() < k {
        centroids.push(vec![0.0; dim]);
    }

    let mut assignments = vec![0usize; embeddings.len()];
    for _ in 0..max_iter {
        let mut changed = false;
        // Assign each point to its nearest centroid.
        for (i, vec) in embeddings.iter().enumerate() {
            let (best, _) = centroids
                .iter()
                .enumerate()
                .map(|(j, c)| (j, squared_distance(vec, c)))
                .min_by(|a, b| a.1.partial_cmp(&b.1).unwrap_or(std::cmp::Ordering::Equal))
                .unwrap_or((0, 0.0));
            if assignments[i] != best {
                changed = true;
                assignments[i] = best;
            }
        }
        if !changed {
            break;
        }
        // Recompute centroids as the mean of each cluster's members.
        let mut sums: Vec<Vec<f32>> = vec![vec![0.0; dim]; k];
        let mut counts = vec![0usize; k];
        for (i, vec) in embeddings.iter().enumerate() {
            let c = assignments[i];
            for (d, v) in vec.iter().enumerate() {
                sums[c][d] += v;
            }
            counts[c] += 1;
        }
        for c in 0..k {
            if counts[c] > 0 {
                let inv = 1.0 / counts[c] as f32;
                for d in 0..dim {
                    centroids[c][d] = sums[c][d] * inv;
                }
            }
        }
    }
    assignments
}

fn squared_distance(a: &[f32], b: &[f32]) -> f32 {
    a.iter().zip(b.iter()).map(|(x, y)| (x - y) * (x - y)).sum()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(xs: &[f32]) -> Vec<f32> {
        xs.to_vec()
    }

    #[test]
    fn kmeans_separates_two_obvious_clusters() {
        // Two tight clusters far apart in 2-D space.
        let a1 = v(&[0.0, 0.0]);
        let a2 = v(&[0.01, -0.01]);
        let a3 = v(&[-0.02, 0.02]);
        let b1 = v(&[10.0, 10.0]);
        let b2 = v(&[10.01, 9.99]);
        let b3 = v(&[9.98, 10.02]);
        let vecs: Vec<&[f32]> = vec![&a1, &a2, &a3, &b1, &b2, &b3];
        let assignments = kmeans(&vecs, 2, 25);
        // All A-group samples land in the same cluster; all B-group in
        // the other.
        assert_eq!(assignments[0], assignments[1]);
        assert_eq!(assignments[0], assignments[2]);
        assert_eq!(assignments[3], assignments[4]);
        assert_eq!(assignments[3], assignments[5]);
        assert_ne!(assignments[0], assignments[3]);
    }

    #[test]
    fn kmeans_single_cluster_converges() {
        // All points identical → all in same cluster regardless of k.
        let p = v(&[1.0, 2.0, 3.0]);
        let vecs: Vec<&[f32]> = vec![&p, &p, &p, &p];
        let assignments = kmeans(&vecs, 2, 25);
        assert_eq!(
            assignments
                .iter()
                .collect::<std::collections::HashSet<_>>()
                .len(),
            1
        );
    }

    #[test]
    fn kmeans_empty_input_safe() {
        let assignments = kmeans(&[], 3, 25);
        assert!(assignments.is_empty());
    }

    #[test]
    fn squared_distance_zero_for_equal() {
        assert!(squared_distance(&[1.0, 2.0, 3.0], &[1.0, 2.0, 3.0]).abs() < 1e-6);
    }

    #[test]
    fn squared_distance_positive() {
        let d = squared_distance(&[0.0, 0.0], &[3.0, 4.0]);
        assert!((d - 25.0).abs() < 1e-6);
    }
}
