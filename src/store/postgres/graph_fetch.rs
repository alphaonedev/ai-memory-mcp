// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

// Preserve the exact production executor. Only library tests compile the
// observer; there is no environment switch or diagnostic API in the product.
macro_rules! graph_fetch {
    ($query:expr, &mut $executor:expr, $site:literal) => {{
        #[cfg(test)]
        {
            $crate::store::postgres::graph_conformance::fetch($query, &mut $executor, $site).await
        }
        #[cfg(not(test))]
        {
            $query.fetch_all(&mut $executor).await
        }
    }};
    ($query:expr, $executor:expr, $site:literal) => {{
        #[cfg(test)]
        {
            async {
                let query = $query;
                let mut connection = sqlx::Acquire::acquire($executor).await?;
                $crate::store::postgres::graph_conformance::fetch(query, &mut *connection, $site)
                    .await
            }
            .await
        }
        #[cfg(not(test))]
        {
            $query.fetch_all($executor).await
        }
    }};
}
