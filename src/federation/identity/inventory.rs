// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! Declarative federation inventory — the GitOps source of truth for
//! fleet membership, trust topology, and enforcement posture.
//!
//! Historically federation trust lived in on-disk `.pub` keyfiles placed
//! by hand: no reviewable, version-controlled description of *who is in
//! the fleet*. This module parses a declarative YAML inventory (a file
//! reviewed in a repo) into a validated [`FederationInventory`] that the
//! P3c reconciler diffs against observed live state.
//!
//! ## Why strict parsing
//!
//! Unlike an MCP tool-request struct (which stays permissive per #1052 so
//! the wire schema is truthful for heterogeneous hosts), this is an
//! operator-authored *trust* config. A silently-dropped typo —
//! `requir_sig:` parsing as the default `require_sig: false` — would
//! quietly weaken enforcement. So every struct here carries
//! `#[serde(deny_unknown_fields)]`: an unrecognised key is a hard parse
//! error the operator sees at load time, mirroring the inline-API-key
//! rejection in [`crate::config`]. (The #1052 honesty pin only scans the
//! MCP `tool_definitions()` payload, so this strictness is out of its
//! scope.)
//!
//! ## Reuse, not reinvention
//!
//! Node ids are validated with [`crate::validate::validate_agent_id_shape`]
//! (the SPIFFE-tolerant, path-traversal-guarded shape check every identity
//! string already passes), and durations with
//! [`crate::config::parse_duration_string`] (the same `<int><unit>` form
//! operators type into `--since` flags). No bespoke regex, no second
//! duration grammar.

use std::collections::BTreeSet;
use std::path::Path;

use serde::Deserialize;

/// Environment variable naming the inventory file. Part of the
/// `AI_MEMORY_FED_*` family (cf. [`super::resolver::FED_IDENTITY_ENV`]).
pub const FED_INVENTORY_PATH_ENV: &str = "AI_MEMORY_FED_INVENTORY_PATH";

/// Smallest sensible quorum width. A width of zero would mean "no peer
/// acknowledgement required", collapsing the W=N durability guarantee.
pub const MIN_QUORUM_WIDTH: u32 = 1;

/// How a node proves its identity to the issuer before a credential is
/// minted. Kebab-case on the wire so the YAML reads `attestor: mtls-cert`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub enum AttestorMethod {
    /// The node presents its existing mTLS client certificate; the
    /// issuer maps the verified CN/SAN to the requested agent-id
    /// (ADR-001 Decision 4 — the Phase-2 default, no new secret-handling).
    MtlsCert,
    /// A pluggable node-identity attestor (cloud instance identity, k8s
    /// service account, TPM). Trait seam only at v0.7.0; declaring it in
    /// an inventory is accepted but the backend is a later phase.
    NodePlugin,
}

/// One node's desired membership facts.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeSpec {
    /// SPIFFE-style agent id this node signs and presents as. Validated
    /// with [`crate::validate::validate_agent_id_shape`].
    pub id: String,
    /// How the node attests its identity to the issuer.
    pub attestor: AttestorMethod,
    /// Credential lifetime, `<int><unit>` (e.g. `1h`, `30m`). Parsed with
    /// [`crate::config::parse_duration_string`].
    pub cred_ttl: String,
    /// Lead window before expiry within which the node renews, same form
    /// as `cred_ttl`. Must be strictly shorter than `cred_ttl`.
    pub renew_before: String,
    /// Optional free-form roles (e.g. `writer`, `reader`). Not interpreted
    /// here; carried for the reconciler / future RBAC.
    #[serde(default)]
    pub roles: Vec<String>,
}

/// One region: an intermediate-CA scope containing nodes.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegionSpec {
    /// Region name (e.g. `nyc`). Non-empty.
    pub name: String,
    /// Reference to this region's intermediate CA (hierarchical trust,
    /// Phase 4). Optional at v0.7.0 — a single-tier fleet roots every
    /// node at the trust-domain root.
    #[serde(default)]
    pub intermediate_ca: Option<String>,
    /// Member nodes.
    #[serde(default)]
    pub nodes: Vec<NodeSpec>,
}

/// Quorum width — the `W` in W-of-N federated writes.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QuorumSpec {
    /// Number of acknowledgements a write must collect. `>= MIN_QUORUM_WIDTH`.
    pub width: u32,
}

/// Fleet enforcement posture.
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnforcementSpec {
    /// Whether receivers reject unsigned posts. Maps to
    /// `AI_MEMORY_FED_REQUIRE_SIG`. Defaults to `false` so an inventory
    /// that omits the block keeps the permissive rollout posture.
    #[serde(default)]
    pub require_sig: bool,
}

/// The declarative inventory: desired fleet membership + trust topology +
/// enforcement, as parsed from YAML and semantically validated.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FederationInventory {
    /// The trust-domain name every credential is scoped to. Non-empty.
    pub trust_domain: String,
    /// Reference to the trust-domain root CA. Optional — a brand-new
    /// inventory describing membership before the CA exists still parses.
    #[serde(default)]
    pub root_ca: Option<String>,
    /// Regional groupings of nodes.
    #[serde(default)]
    pub regions: Vec<RegionSpec>,
    /// Quorum width.
    pub quorum: QuorumSpec,
    /// Enforcement posture (defaults to permissive when omitted).
    #[serde(default)]
    pub enforcement: EnforcementSpec,
}

/// Reasons an inventory fails to load or validate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InventoryError {
    /// The YAML could not be parsed (syntax error or unknown field).
    Parse(String),
    /// The file could not be read.
    Io(String),
    /// `trust_domain` is empty / whitespace.
    EmptyTrustDomain,
    /// A region carried an empty `name`.
    EmptyRegionName,
    /// A node id failed the agent-id shape check.
    InvalidNodeId { id: String, reason: String },
    /// A `cred_ttl` / `renew_before` value did not parse to a positive
    /// duration.
    InvalidDuration {
        node: String,
        field: &'static str,
        value: String,
    },
    /// `renew_before` was not strictly shorter than `cred_ttl` — the node
    /// would consider itself due for renewal before it ever held a valid
    /// window.
    RenewBeforeNotShorterThanTtl { node: String },
    /// The same node id appeared more than once — an ambiguous identity.
    DuplicateNodeId { id: String },
    /// `quorum.width` is below [`MIN_QUORUM_WIDTH`].
    InvalidQuorumWidth { width: u32 },
}

impl InventoryError {
    /// Stable machine-readable tag for logs + JSON error envelopes.
    #[must_use]
    pub fn tag(&self) -> &'static str {
        match self {
            Self::Parse(_) => "inventory_parse_error",
            Self::Io(_) => "inventory_io_error",
            Self::EmptyTrustDomain => "inventory_empty_trust_domain",
            Self::EmptyRegionName => "inventory_empty_region_name",
            Self::InvalidNodeId { .. } => "inventory_invalid_node_id",
            Self::InvalidDuration { .. } => "inventory_invalid_duration",
            Self::RenewBeforeNotShorterThanTtl { .. } => "inventory_renew_before_not_shorter",
            Self::DuplicateNodeId { .. } => "inventory_duplicate_node_id",
            Self::InvalidQuorumWidth { .. } => "inventory_invalid_quorum_width",
        }
    }
}

impl std::fmt::Display for InventoryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Parse(msg) | Self::Io(msg) => write!(f, "{} ({msg})", self.tag()),
            Self::InvalidNodeId { id, reason } => {
                write!(f, "{} (id={id}: {reason})", self.tag())
            }
            Self::InvalidDuration { node, field, value } => {
                write!(f, "{} (node={node} {field}={value})", self.tag())
            }
            Self::RenewBeforeNotShorterThanTtl { node } => {
                write!(f, "{} (node={node})", self.tag())
            }
            Self::DuplicateNodeId { id } => write!(f, "{} (id={id})", self.tag()),
            Self::InvalidQuorumWidth { width } => write!(f, "{} (width={width})", self.tag()),
            _ => f.write_str(self.tag()),
        }
    }
}

impl std::error::Error for InventoryError {}

impl FederationInventory {
    /// Parse + validate an inventory from a YAML string.
    ///
    /// # Errors
    /// [`InventoryError::Parse`] on malformed / unknown-field YAML, or any
    /// of the semantic variants from [`validate`](Self::validate).
    pub fn from_yaml_str(yaml: &str) -> Result<Self, InventoryError> {
        let inventory: Self =
            serde_yaml::from_str(yaml).map_err(|e| InventoryError::Parse(e.to_string()))?;
        inventory.validate()?;
        Ok(inventory)
    }

    /// Load + validate an inventory from a file path.
    ///
    /// # Errors
    /// [`InventoryError::Io`] if the file cannot be read; otherwise the
    /// same errors as [`from_yaml_str`](Self::from_yaml_str).
    pub fn load_from_path(path: &Path) -> Result<Self, InventoryError> {
        let raw = std::fs::read_to_string(path).map_err(|e| InventoryError::Io(e.to_string()))?;
        Self::from_yaml_str(&raw)
    }

    /// Load the inventory named by [`FED_INVENTORY_PATH_ENV`].
    ///
    /// `Ok(None)` when the env var is unset — running without a declarative
    /// inventory is the normal pre-adoption state, not an error.
    ///
    /// # Errors
    /// The same errors as [`load_from_path`](Self::load_from_path) when the
    /// env var IS set but the file is missing / malformed / invalid.
    pub fn load_from_env() -> Result<Option<Self>, InventoryError> {
        match std::env::var(FED_INVENTORY_PATH_ENV) {
            Ok(path) => Self::load_from_path(Path::new(&path)).map(Some),
            Err(_) => Ok(None),
        }
    }

    /// Iterate every node across all regions.
    pub fn nodes(&self) -> impl Iterator<Item = &NodeSpec> {
        self.regions.iter().flat_map(|r| r.nodes.iter())
    }

    /// Semantic validation beyond what serde shape-checks: non-empty
    /// trust domain + region names, valid node ids, parsable + sane
    /// durations, unique ids, and a sane quorum width.
    ///
    /// # Errors
    /// One of the semantic [`InventoryError`] variants on the first
    /// violation found.
    pub fn validate(&self) -> Result<(), InventoryError> {
        if self.trust_domain.trim().is_empty() {
            return Err(InventoryError::EmptyTrustDomain);
        }
        if self.quorum.width < MIN_QUORUM_WIDTH {
            return Err(InventoryError::InvalidQuorumWidth {
                width: self.quorum.width,
            });
        }
        let mut seen_ids: BTreeSet<&str> = BTreeSet::new();
        for region in &self.regions {
            if region.name.trim().is_empty() {
                return Err(InventoryError::EmptyRegionName);
            }
            for node in &region.nodes {
                node.validate()?;
                if !seen_ids.insert(node.id.as_str()) {
                    return Err(InventoryError::DuplicateNodeId {
                        id: node.id.clone(),
                    });
                }
            }
        }
        Ok(())
    }
}

impl NodeSpec {
    /// The credential lifetime as a [`chrono::Duration`].
    #[must_use]
    pub fn cred_ttl_duration(&self) -> Option<chrono::Duration> {
        crate::config::parse_duration_string(&self.cred_ttl)
    }

    /// The renewal lead window as a [`chrono::Duration`].
    #[must_use]
    pub fn renew_before_duration(&self) -> Option<chrono::Duration> {
        crate::config::parse_duration_string(&self.renew_before)
    }

    /// Validate a single node's id + durations.
    fn validate(&self) -> Result<(), InventoryError> {
        crate::validate::validate_agent_id_shape(&self.id).map_err(|e| {
            InventoryError::InvalidNodeId {
                id: self.id.clone(),
                reason: e.to_string(),
            }
        })?;
        let ttl = positive_duration(self.cred_ttl_duration()).ok_or_else(|| {
            InventoryError::InvalidDuration {
                node: self.id.clone(),
                field: "cred_ttl",
                value: self.cred_ttl.clone(),
            }
        })?;
        let renew = positive_duration(self.renew_before_duration()).ok_or_else(|| {
            InventoryError::InvalidDuration {
                node: self.id.clone(),
                field: "renew_before",
                value: self.renew_before.clone(),
            }
        })?;
        if renew >= ttl {
            return Err(InventoryError::RenewBeforeNotShorterThanTtl {
                node: self.id.clone(),
            });
        }
        Ok(())
    }
}

/// `Some(d)` when `d` is present and strictly positive, else `None`. A
/// zero/negative TTL or renewal window is meaningless and rejected.
fn positive_duration(d: Option<chrono::Duration>) -> Option<chrono::Duration> {
    d.filter(|d| *d > chrono::Duration::zero())
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "\
trust_domain: fleet.example
root_ca: root.pub
regions:
  - name: nyc
    intermediate_ca: nyc-int.pub
    nodes:
      - id: region/nyc/node-1
        attestor: mtls-cert
        cred_ttl: 1h
        renew_before: 15m
        roles: [writer, reader]
      - id: region/nyc/node-2
        attestor: node-plugin
        cred_ttl: 2h
        renew_before: 30m
  - name: sfo
    nodes:
      - id: region/sfo/node-1
        attestor: mtls-cert
        cred_ttl: 1h
        renew_before: 10m
quorum:
  width: 2
enforcement:
  require_sig: true
";

    #[test]
    fn parses_and_validates_a_full_inventory() {
        let inv = FederationInventory::from_yaml_str(SAMPLE).expect("valid");
        assert_eq!(inv.trust_domain, "fleet.example");
        assert_eq!(inv.root_ca.as_deref(), Some("root.pub"));
        assert_eq!(inv.regions.len(), 2);
        assert_eq!(inv.quorum.width, 2);
        assert!(inv.enforcement.require_sig);
        assert_eq!(inv.nodes().count(), 3);
        let first = inv.nodes().next().expect("a node");
        assert_eq!(first.id, "region/nyc/node-1");
        assert_eq!(first.attestor, AttestorMethod::MtlsCert);
        assert_eq!(first.roles, vec!["writer", "reader"]);
        assert_eq!(first.cred_ttl_duration(), Some(chrono::Duration::hours(1)));
        assert_eq!(
            first.renew_before_duration(),
            Some(chrono::Duration::minutes(15))
        );
    }

    #[test]
    fn enforcement_defaults_to_permissive_when_omitted() {
        let yaml = "\
trust_domain: d
quorum:
  width: 1
";
        let inv = FederationInventory::from_yaml_str(yaml).expect("valid");
        assert!(!inv.enforcement.require_sig);
        assert_eq!(inv.nodes().count(), 0);
    }

    #[test]
    fn unknown_field_is_a_hard_parse_error() {
        let yaml = "\
trust_domain: d
quorum:
  width: 1
enforcement:
  requir_sig: true
";
        let err = FederationInventory::from_yaml_str(yaml).expect_err("typo must fail");
        assert_eq!(err.tag(), "inventory_parse_error");
    }

    #[test]
    fn empty_trust_domain_is_rejected() {
        let yaml = "\
trust_domain: '   '
quorum:
  width: 1
";
        let err = FederationInventory::from_yaml_str(yaml).expect_err("empty domain");
        assert_eq!(err, InventoryError::EmptyTrustDomain);
    }

    #[test]
    fn zero_quorum_width_is_rejected() {
        let yaml = "\
trust_domain: d
quorum:
  width: 0
";
        let err = FederationInventory::from_yaml_str(yaml).expect_err("zero width");
        assert_eq!(err, InventoryError::InvalidQuorumWidth { width: 0 });
    }

    #[test]
    fn path_traversal_node_id_is_rejected() {
        let yaml = "\
trust_domain: d
regions:
  - name: r
    nodes:
      - id: ../../etc/secret
        attestor: mtls-cert
        cred_ttl: 1h
        renew_before: 5m
quorum:
  width: 1
";
        let err = FederationInventory::from_yaml_str(yaml).expect_err("traversal");
        assert_eq!(err.tag(), "inventory_invalid_node_id");
    }

    #[test]
    fn unparsable_duration_is_rejected() {
        let yaml = "\
trust_domain: d
regions:
  - name: r
    nodes:
      - id: node-1
        attestor: mtls-cert
        cred_ttl: soon
        renew_before: 5m
quorum:
  width: 1
";
        let err = FederationInventory::from_yaml_str(yaml).expect_err("bad ttl");
        assert_eq!(
            err,
            InventoryError::InvalidDuration {
                node: "node-1".to_string(),
                field: "cred_ttl",
                value: "soon".to_string(),
            }
        );
    }

    #[test]
    fn renew_before_not_shorter_than_ttl_is_rejected() {
        let yaml = "\
trust_domain: d
regions:
  - name: r
    nodes:
      - id: node-1
        attestor: mtls-cert
        cred_ttl: 1h
        renew_before: 1h
quorum:
  width: 1
";
        let err = FederationInventory::from_yaml_str(yaml).expect_err("renew>=ttl");
        assert_eq!(
            err,
            InventoryError::RenewBeforeNotShorterThanTtl {
                node: "node-1".to_string()
            }
        );
    }

    #[test]
    fn duplicate_node_id_across_regions_is_rejected() {
        let yaml = "\
trust_domain: d
regions:
  - name: r1
    nodes:
      - id: dup
        attestor: mtls-cert
        cred_ttl: 1h
        renew_before: 5m
  - name: r2
    nodes:
      - id: dup
        attestor: mtls-cert
        cred_ttl: 1h
        renew_before: 5m
quorum:
  width: 1
";
        let err = FederationInventory::from_yaml_str(yaml).expect_err("dup id");
        assert_eq!(
            err,
            InventoryError::DuplicateNodeId {
                id: "dup".to_string()
            }
        );
    }

    #[test]
    fn empty_region_name_is_rejected() {
        let yaml = "\
trust_domain: d
regions:
  - name: '  '
    nodes: []
quorum:
  width: 1
";
        let err = FederationInventory::from_yaml_str(yaml).expect_err("empty region");
        assert_eq!(err, InventoryError::EmptyRegionName);
    }

    #[test]
    fn load_from_env_unset_is_none() {
        // SAFETY: single-threaded test; no other thread reads this var.
        unsafe { std::env::remove_var(FED_INVENTORY_PATH_ENV) };
        assert_eq!(FederationInventory::load_from_env().expect("ok"), None);
    }
}
