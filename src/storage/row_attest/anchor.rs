//! #10086 (GA standard 3) — the trust anchor of the row-attestation
//! verifier. 3-agent vote (71472661) V2-ROW-ATTEST-ANCHOR, option A.
//!
//! Threat model: an attacker who can write the database file directly and
//! holds no signing key. Such a writer controls every row of the database,
//! a key row beside the attestations included, so nothing the verifier
//! trusts may be read from the database it verifies. The verifier's public
//! keys come only from the key directory the deployment already configures
//! (`AI_MEMORY_KEY_DIR`, else the platform default): `<agent>.pub` is the
//! current key of an agent and every `<agent>.pub.<unix_ts>[-N]` archive a
//! key rotation leaves behind (`keypair::archive_public_key_at`) is a
//! retired key, valid up to its archive instant.
//!
//! [`TrustAnchor`] has private fields and no constructor that takes a
//! database handle: [`TrustAnchor::load_dir`] and
//! [`TrustAnchor::from_key_dir`] read the file system only. A missing,
//! empty, unreadable or malformed anchor is [`AnchorLoad::Unanchored`]
//! with its exact reason, never a fallback to a key stored in the database.

use std::collections::BTreeMap;
use std::fmt;
use std::path::{Path, PathBuf};

use ed25519_dalek::VerifyingKey;

use super::key_id_of;

/// Version of the anchor layout this verifier reads (A-9). An explicit
/// marker file [`ANCHOR_MARKER_FILE`] in the key directory, when present,
/// must hold exactly this number; any other content makes the anchor
/// malformed.
pub const ANCHOR_LAYOUT_VERSION: u32 = 1;
/// Name of the optional layout-version marker in the key directory (A-9).
pub const ANCHOR_MARKER_FILE: &str = "row-attest-anchor.version";
/// Suffix of a public-key file (mirrors `keypair::PUB_SUFFIX`).
const PUB_SUFFIX: &str = ".pub";
/// The archive infix: `<agent>.pub.<unix_ts>[-N]`.
const ARCHIVE_INFIX: &str = ".pub.";
/// The governance operator key written by `rules keygen` as base64 text
/// (A-5): it shares the key directory but is not a row signer, so the
/// loader skips it at the top level. Any other `.pub` that is not 32 raw
/// bytes stays a malformed anchor (fail closed).
const OPERATOR_KEYGEN_PUB_FILE: &str = crate::governance::rules_store::OPERATOR_PUBKEY_KEYGEN_FILE;
/// Stem suffix of an X25519 (encryption, escrow) public key such as
/// `recovery.x25519.pub` (A-5): never an Ed25519 row signer.
const X25519_STEM_SUFFIX: &str = ".x25519";
/// Ed25519 public key length in bytes.
const PUBLIC_KEY_LEN: usize = ed25519_dalek::PUBLIC_KEY_LENGTH;
/// Directory entries the loader reads before it refuses the anchor as
/// malformed (bounded input).
pub const MAX_ANCHOR_ENTRIES: usize = 65_536;
/// Nesting depth of a slashed agent id (#1514) the loader follows.
const MAX_ANCHOR_DEPTH: usize = 8;

/// Why no trust anchor is available (A-3). Never a clean outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Unanchored {
    /// No key directory could be resolved.
    NotConfigured {
        /// The resolution failure.
        why: String,
    },
    /// The key directory does not exist.
    Missing {
        /// The directory.
        path: PathBuf,
    },
    /// The key directory holds no public key.
    Empty {
        /// The directory.
        path: PathBuf,
    },
    /// The key directory, or a key file in it, cannot be read or is not
    /// owner-secure.
    Unreadable {
        /// The path that failed.
        path: PathBuf,
        /// The failure.
        why: String,
    },
    /// A file of the anchor is not a key, an archive name does not parse,
    /// the marker names another layout, or one key is listed twice.
    Malformed {
        /// The path that failed.
        path: PathBuf,
        /// The failure.
        why: String,
    },
}

impl Unanchored {
    /// Stable machine name of the reason (the JSON field value, A-3).
    #[must_use]
    pub fn kind(&self) -> &'static str {
        match self {
            Self::NotConfigured { .. } => "not_configured",
            Self::Missing { .. } => "missing",
            Self::Empty { .. } => "empty",
            Self::Unreadable { .. } => "unreadable",
            Self::Malformed { .. } => "malformed",
        }
    }
}

impl fmt::Display for Unanchored {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotConfigured { why } => write!(f, "no key directory is configured: {why}"),
            Self::Missing { path } => write!(f, "key directory {} does not exist", path.display()),
            Self::Empty { path } => {
                write!(f, "key directory {} holds no public key", path.display())
            }
            Self::Unreadable { path, why } => {
                write!(f, "anchor path {} is unreadable: {why}", path.display())
            }
            Self::Malformed { path, why } => {
                write!(f, "anchor path {} is malformed: {why}", path.display())
            }
        }
    }
}

/// One public key of the anchor with its validity window (A-6).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnchorKey {
    agent_id: String,
    key: VerifyingKey,
    /// Unix seconds the key became current (`None`: the first key).
    valid_from: Option<i64>,
    /// Unix seconds the key was retired (`None`: the current key).
    valid_to: Option<i64>,
}

impl AnchorKey {
    /// The agent the key belongs to.
    #[must_use]
    pub fn agent_id(&self) -> &str {
        &self.agent_id
    }

    /// True for a retired (archived) key.
    #[must_use]
    pub fn is_retired(&self) -> bool {
        self.valid_to.is_some()
    }
}

/// Why an attestation's key is refused by the anchor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyRefusal {
    /// The anchor holds no key at all for the agent.
    UnknownAgent,
    /// The anchor holds keys for the agent, but not this `key_id` (A-7:
    /// a retired key missing from the anchor is named, never guessed).
    UnknownKey,
    /// The `key_id` belongs to another agent in the anchor.
    OtherAgent(String),
    /// The attestation time is not a canonical timestamp.
    BadTime,
    /// The key is used outside its validity window (A-6).
    OutOfRange {
        /// Window start, unix seconds.
        valid_from: Option<i64>,
        /// Window end, unix seconds.
        valid_to: Option<i64>,
    },
}

/// The out-of-database trust anchor (A-2): every public key the verifier
/// trusts, by `key_id`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustAnchor {
    source: PathBuf,
    by_key_id: BTreeMap<String, AnchorKey>,
}

/// The result of loading the anchor: no `Option` and no bool stands in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AnchorLoad {
    /// A usable anchor.
    Anchored(TrustAnchor),
    /// No usable anchor, with the exact reason.
    Unanchored(Unanchored),
}

/// One parsed key-file name.
enum KeyName {
    Current(String),
    Retired(String, i64, u32),
}

impl KeyName {
    fn agent(&self) -> &str {
        match self {
            Self::Current(agent) | Self::Retired(agent, _, _) => agent,
        }
    }
}

fn parse_key_name(name: &str) -> Result<Option<KeyName>, String> {
    if let Some(agent) = name.strip_suffix(PUB_SUFFIX) {
        if agent.is_empty() {
            return Err("public key file has no agent name".to_string());
        }
        return Ok(Some(KeyName::Current(agent.to_string())));
    }
    let Some(at) = name.rfind(ARCHIVE_INFIX) else {
        return Ok(None);
    };
    let agent = &name[..at];
    let suffix = &name[at + ARCHIVE_INFIX.len()..];
    let (ts, n) = match suffix.split_once('-') {
        Some((ts, n)) => (ts, Some(n)),
        None => (suffix, None),
    };
    let digits = |s: &str| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit());
    if agent.is_empty() || !digits(ts) || n.is_some_and(|n| !digits(n)) {
        return Err(format!(
            "archive name {name:?} is not <agent>.pub.<unix_ts>[-N]"
        ));
    }
    let ts: i64 = ts
        .parse()
        .map_err(|e| format!("archive timestamp of {name:?}: {e}"))?;
    let n: u32 = match n {
        Some(n) => n
            .parse()
            .map_err(|e| format!("archive suffix of {name:?}: {e}"))?,
        None => 0,
    };
    Ok(Some(KeyName::Retired(agent.to_string(), ts, n)))
}

fn read_key(path: &Path) -> Result<VerifyingKey, Unanchored> {
    let bytes = std::fs::read(path).map_err(|e| Unanchored::Unreadable {
        path: path.to_path_buf(),
        why: e.to_string(),
    })?;
    let arr: [u8; PUBLIC_KEY_LEN] =
        bytes
            .as_slice()
            .try_into()
            .map_err(|_| Unanchored::Malformed {
                path: path.to_path_buf(),
                why: format!("{} bytes, expected {PUBLIC_KEY_LEN}", bytes.len()),
            })?;
    VerifyingKey::from_bytes(&arr).map_err(|e| Unanchored::Malformed {
        path: path.to_path_buf(),
        why: e.to_string(),
    })
}

/// Key files found per agent: the current key and the archives in order.
#[derive(Default)]
struct AgentFiles {
    current: Option<(PathBuf, VerifyingKey)>,
    retired: Vec<(i64, u32, PathBuf, VerifyingKey)>,
}

fn scan(
    root: &Path,
    dir: &Path,
    prefix: &str,
    depth: usize,
    seen: &mut usize,
    agents: &mut BTreeMap<String, AgentFiles>,
) -> Result<(), Unanchored> {
    crate::identity::keypair::enforce_key_dir_secure(dir).map_err(|e| Unanchored::Unreadable {
        path: dir.to_path_buf(),
        why: format!("{e:#}"),
    })?;
    let unreadable = |e: std::io::Error| Unanchored::Unreadable {
        path: dir.to_path_buf(),
        why: e.to_string(),
    };
    for entry in std::fs::read_dir(dir).map_err(unreadable)? {
        let entry = entry.map_err(unreadable)?;
        *seen = seen.saturating_add(1);
        if *seen > MAX_ANCHOR_ENTRIES {
            return Err(Unanchored::Malformed {
                path: root.to_path_buf(),
                why: format!("more than {MAX_ANCHOR_ENTRIES} entries"),
            });
        }
        let path = entry.path();
        let Some(name) = entry.file_name().to_str().map(str::to_string) else {
            continue;
        };
        // Staging siblings and the marker are not keys.
        if name.starts_with('.') || (depth == 0 && name == ANCHOR_MARKER_FILE) {
            continue;
        }
        let ty = entry.file_type().map_err(unreadable)?;
        if ty.is_dir() {
            if depth < MAX_ANCHOR_DEPTH {
                let nested = format!("{prefix}{name}/");
                scan(root, &path, &nested, depth + 1, seen, agents)?;
            }
            continue;
        }
        if depth == 0 && name == OPERATOR_KEYGEN_PUB_FILE {
            continue;
        }
        let parsed = parse_key_name(&name).map_err(|why| Unanchored::Malformed {
            path: path.clone(),
            why,
        })?;
        let parsed = parsed.filter(|k| !k.agent().ends_with(X25519_STEM_SUFFIX));
        match parsed {
            None => {}
            Some(KeyName::Current(agent)) => {
                let key = read_key(&path)?;
                agents
                    .entry(format!("{prefix}{agent}"))
                    .or_default()
                    .current = Some((path, key));
            }
            Some(KeyName::Retired(agent, ts, n)) => {
                let key = read_key(&path)?;
                agents
                    .entry(format!("{prefix}{agent}"))
                    .or_default()
                    .retired
                    .push((ts, n, path, key));
            }
        }
    }
    Ok(())
}

fn insert(
    out: &mut BTreeMap<String, AnchorKey>,
    path: &Path,
    key: AnchorKey,
) -> Result<(), Unanchored> {
    let id = key_id_of(&key.key);
    if out.insert(id.clone(), key).is_some() {
        return Err(Unanchored::Malformed {
            path: path.to_path_buf(),
            why: format!("key {id} is listed twice"),
        });
    }
    Ok(())
}

impl TrustAnchor {
    /// Load the anchor from the deployment's key directory
    /// (`AI_MEMORY_KEY_DIR`, else the platform default), the same source
    /// the session signer and `identity` verbs use.
    #[must_use]
    pub fn from_key_dir() -> AnchorLoad {
        match crate::identity::keypair::resolved_default_key_dir_path() {
            Ok(dir) => Self::load_dir(&dir),
            Err(e) => AnchorLoad::Unanchored(Unanchored::NotConfigured {
                why: format!("{e:#}"),
            }),
        }
    }

    /// Load the anchor from `dir` (A-3, A-6, A-9).
    #[must_use]
    pub fn load_dir(dir: &Path) -> AnchorLoad {
        match Self::try_load(dir) {
            Ok(anchor) => AnchorLoad::Anchored(anchor),
            Err(why) => AnchorLoad::Unanchored(why),
        }
    }

    fn try_load(dir: &Path) -> Result<Self, Unanchored> {
        match std::fs::metadata(dir) {
            Ok(md) if md.is_dir() => {}
            Ok(_) => {
                return Err(Unanchored::Malformed {
                    path: dir.to_path_buf(),
                    why: "not a directory".to_string(),
                });
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Err(Unanchored::Missing {
                    path: dir.to_path_buf(),
                });
            }
            Err(e) => {
                return Err(Unanchored::Unreadable {
                    path: dir.to_path_buf(),
                    why: e.to_string(),
                });
            }
        }
        let marker = dir.join(ANCHOR_MARKER_FILE);
        match std::fs::read_to_string(&marker) {
            Ok(text) if text.trim() == ANCHOR_LAYOUT_VERSION.to_string() => {}
            Ok(text) => {
                return Err(Unanchored::Malformed {
                    path: marker,
                    why: format!(
                        "layout version {:?}, this verifier reads {ANCHOR_LAYOUT_VERSION}",
                        text.trim()
                    ),
                });
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => {
                return Err(Unanchored::Unreadable {
                    path: marker,
                    why: e.to_string(),
                });
            }
        }
        let mut agents = BTreeMap::new();
        let mut seen = 0_usize;
        scan(dir, dir, "", 0, &mut seen, &mut agents)?;
        let mut by_key_id = BTreeMap::new();
        for (agent, mut files) in agents {
            files.retired.sort_by_key(|(ts, n, _, _)| (*ts, *n));
            let mut from: Option<i64> = None;
            for (ts, _, path, key) in files.retired {
                let k = AnchorKey {
                    agent_id: agent.clone(),
                    key,
                    valid_from: from,
                    valid_to: Some(ts),
                };
                insert(&mut by_key_id, &path, k)?;
                from = Some(ts);
            }
            if let Some((path, key)) = files.current {
                let k = AnchorKey {
                    agent_id: agent.clone(),
                    key,
                    valid_from: from,
                    valid_to: None,
                };
                insert(&mut by_key_id, &path, k)?;
            }
        }
        if by_key_id.is_empty() {
            return Err(Unanchored::Empty {
                path: dir.to_path_buf(),
            });
        }
        Ok(Self {
            source: dir.to_path_buf(),
            by_key_id,
        })
    }

    /// The directory the anchor was read from (A-9).
    #[must_use]
    pub fn source(&self) -> &Path {
        &self.source
    }

    /// Every `(agent_id, key_id, retired)` of the anchor, for output (A-9).
    #[must_use]
    pub fn fingerprints(&self) -> Vec<(String, String, bool)> {
        self.by_key_id
            .iter()
            .map(|(id, k)| (k.agent_id.clone(), id.clone(), k.is_retired()))
            .collect()
    }

    /// The key `agent_id` signed with as `key_id` at `attested_at` (A-6,
    /// A-7). The attestation time is inside the signed preimage, so a
    /// file writer cannot move it without breaking the signature.
    ///
    /// # Errors
    ///
    /// The exact [`KeyRefusal`].
    pub fn key_for(
        &self,
        agent_id: &str,
        key_id: &str,
        attested_at: &str,
    ) -> Result<&VerifyingKey, KeyRefusal> {
        let Some(k) = self.by_key_id.get(key_id) else {
            return Err(if self.by_key_id.values().any(|k| k.agent_id == agent_id) {
                KeyRefusal::UnknownKey
            } else {
                KeyRefusal::UnknownAgent
            });
        };
        if k.agent_id != agent_id {
            return Err(KeyRefusal::OtherAgent(k.agent_id.clone()));
        }
        let at = chrono::DateTime::parse_from_rfc3339(attested_at)
            .map_err(|_| KeyRefusal::BadTime)?
            .timestamp();
        let after_start = k.valid_from.is_none_or(|from| at >= from);
        let before_end = k.valid_to.is_none_or(|to| at <= to);
        if after_start && before_end {
            Ok(&k.key)
        } else {
            Err(KeyRefusal::OutOfRange {
                valid_from: k.valid_from,
                valid_to: k.valid_to,
            })
        }
    }

    /// An anchor built from explicit keys (unit tests only; still no
    /// database input).
    #[cfg(test)]
    pub(crate) fn for_test(
        source: &str,
        keys: &[(&str, VerifyingKey, Option<i64>, Option<i64>)],
    ) -> Self {
        let by_key_id = keys
            .iter()
            .map(|(agent, key, from, to)| {
                (
                    key_id_of(key),
                    AnchorKey {
                        agent_id: (*agent).to_string(),
                        key: *key,
                        valid_from: *from,
                        valid_to: *to,
                    },
                )
            })
            .collect();
        Self {
            source: PathBuf::from(source),
            by_key_id,
        }
    }
}
