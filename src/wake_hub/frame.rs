// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! `wake-hub` wire format (issue
//! [#3467](https://github.com/alphaonedev/ai-memory-mcp/issues/3467)).
//!
//! # The hub carries no message bodies
//!
//! This is a STRUCTURAL guarantee, not a policy one. [`Kind`] enumerates every
//! frame the hub will parse, and none of them has a body field: the largest
//! payload is a `hello` (public key + signature + asserted topics) and the
//! largest ROUTED payload is a 256-byte [`WakeMeta`] hint. The v1 protocol
//! deliberately has NO `request` / `reply` / `notify` kinds — their historical
//! wire numbers are permanently reserved and
//! [`FrameError::ReservedPayloadKind`] refuses them by name, so a client built
//! against the pre-vote draft fails closed with a legible error instead of
//! having its body silently routed.
//!
//! Durable truth is the ai-memory inbox row. A wake is a hint; a `<=60 s`
//! backstop poll is the guarantee.
//!
//! # Body layout
//!
//! The `u32` big-endian length prefix belongs to the codec
//! ([`super::codec`]); this module owns everything after it.
//!
//! ```text
//! off  len  field
//!   0    4  magic         = b"AWH1"
//!   4    1  version       = 1
//!   5    1  kind          (see `Kind`)
//!   6    1  flags         reserved, MUST be 0
//!   7    1  from_len      0..=128
//!   8    1  to_len        0..=128
//!   9    1  reserved      MUST be 0
//!  10    2  payload_len   u16be, 0..=1024
//!  12    8  ts_ms         u64be
//!  20    4  ttl_ms        u32be (0 = no expiry)
//!  24    N  from          UTF-8 agent id
//!  24+N  M  to            UTF-8 agent id, or `#topic`
//!       P   payload       kind-specific, bounded by `Kind::max_payload_bytes`
//! ```
//!
//! Every reserved field is CHECKED, not ignored: a non-zero `flags` or
//! `reserved` byte is a `400`, so the bytes stay available for a future
//! version instead of being quietly accepted by today's parser.

use std::fmt;

use bytes::{BufMut, Bytes, BytesMut};

use super::limits::{
    FRAME_HEADER_BYTES, MAX_DELEGATION_WIRE_BYTES, MAX_FRAME_BYTES, MAX_ID_BYTES,
    MAX_LIVENESS_PAYLOAD_BYTES, MAX_PAYLOAD_BYTES, MAX_TOPIC_BYTES, MAX_TOPICS_PER_FRAME,
    MAX_WAKE_META_BYTES, PUBKEY_BYTES, SIGNATURE_BYTES, WAKE_DIGEST_BYTES, WIRE_MAGIC,
    WIRE_VERSION,
};

// ---------------------------------------------------------------------------
// Error codes
// ---------------------------------------------------------------------------

/// Wire error code carried in an `error` frame payload. Mirrors the HTTP
/// vocabulary the rest of ai-memory already speaks so an operator reading a hub
/// log and an API log sees one numbering.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum ErrorCode {
    /// Malformed frame: bad magic, bad version, reserved byte set, bad lengths.
    Malformed,
    /// Not authenticated, or the hello was refused.
    Unauthorized,
    /// Authenticated, but the frame is not permitted — notably a `from` that is
    /// not the identity bound at hello (a forged sender).
    Forbidden,
    /// No such destination agent, and none is known to the hub.
    UnknownDestination,
    /// A second session claimed this agent id; this session is being replaced.
    Replaced,
    /// Frame exceeded a length bound.
    TooLarge,
    /// The connection's token bucket is empty.
    RateLimited,
    /// The hub hit an internal error handling the frame.
    Internal,
    /// A queue (per-recipient, or the hub-wide egress budget) is full.
    Overflow,
}

impl ErrorCode {
    /// Numeric wire value.
    #[must_use]
    pub const fn as_u16(self) -> u16 {
        match self {
            Self::Malformed => 400,
            Self::Unauthorized => 401,
            Self::Forbidden => 403,
            Self::UnknownDestination => 404,
            Self::Replaced => 409,
            Self::TooLarge => 413,
            Self::RateLimited => 429,
            Self::Internal => 500,
            Self::Overflow => 507,
        }
    }
}

impl fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_u16())
    }
}

// ---------------------------------------------------------------------------
// Kinds
// ---------------------------------------------------------------------------

/// Wire numbers permanently reserved for the payload-carrying kinds the
/// rust-a2a v2 adjusted plan REMOVED (`request` = 11, `reply` = 12,
/// `notify` = 13). They are refused by number so a pre-vote client gets a
/// legible refusal instead of silence, and so a future contributor cannot
/// reuse the number for something else and make an old client's body route.
// ---------------------------------------------------------------------------
// Shared peer-facing wording
// ---------------------------------------------------------------------------
//
// Every process that speaks this wire — the #3469 producer forwarder and the
// #3470 listener alike — reports the same three conditions, and an operator
// grepping a fleet's logs for one of them must find every occurrence. One
// definition site is also what keeps the pm-v3.1 no-duplicated-literal gate
// honest: the alternative is the same sentence drifting apart across modules.

/// Context for a frame that arrived from the hub but would not decode.
pub const CTX_DECODING_HUB_FRAME: &str = "decoding a frame from the hub";

/// The peer went away. Terminal for the session, never for the durable row.
pub const CTX_HUB_CLOSED: &str = "the hub closed the connection";

/// Stand-in when an `error` frame's own payload will not decode.
pub const CTX_UNPARSEABLE_REFUSAL: &str = "unparseable refusal";

/// `Debug` field naming the SIZE of a presented delegation — never its bytes.
pub const DEBUG_FIELD_DELEGATION_BYTES: &str = "delegation_bytes";

pub const RESERVED_PAYLOAD_KINDS: [u8; 3] = [11, 12, 13];

/// Every frame kind the v1 hub understands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Kind {
    /// Handshake, in BOTH directions. Hub -> client carries the 32-byte
    /// challenge nonce; client -> hub carries public key, transcript signature
    /// and the asserted topic list.
    Hello,
    /// Hub -> client: handshake accepted. Carries the session handle, the
    /// coalesced pending summary and jittered reconnect guidance.
    Welcome,
    /// Client -> hub: signed, nonce-bound membership join.
    Join,
    /// Client -> hub: signed, nonce-bound membership end. Disconnect is NOT
    /// depart.
    Depart,
    /// Client -> hub: add topics to this session's subscription set.
    Subscribe,
    /// Client -> hub: remove topics from this session's subscription set.
    Unsubscribe,
    /// The wake hint itself. Payload is a [`WakeMeta`], never a body.
    Wake,
    /// Liveness probe.
    Ping,
    /// Liveness response.
    Pong,
    /// Refusal, always to the sender, never a silent success.
    Error,
}

impl Kind {
    /// Numeric wire value.
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        match self {
            Self::Hello => 1,
            Self::Welcome => 2,
            Self::Join => 3,
            Self::Depart => 4,
            Self::Subscribe => 5,
            Self::Unsubscribe => 6,
            Self::Wake => 7,
            Self::Ping => 8,
            Self::Pong => 9,
            Self::Error => 10,
        }
    }

    /// Parse a wire kind.
    ///
    /// # Errors
    ///
    /// [`FrameError::ReservedPayloadKind`] for a removed payload kind,
    /// [`FrameError::UnknownKind`] for anything else outside the table.
    pub const fn from_u8(v: u8) -> Result<Self, FrameError> {
        match v {
            1 => Ok(Self::Hello),
            2 => Ok(Self::Welcome),
            3 => Ok(Self::Join),
            4 => Ok(Self::Depart),
            5 => Ok(Self::Subscribe),
            6 => Ok(Self::Unsubscribe),
            7 => Ok(Self::Wake),
            8 => Ok(Self::Ping),
            9 => Ok(Self::Pong),
            10 => Ok(Self::Error),
            11 | 12 | 13 => Err(FrameError::ReservedPayloadKind(v)),
            other => Err(FrameError::UnknownKind(other)),
        }
    }

    /// Per-kind payload ceiling in bytes. Tighter than the codec's frame
    /// ceiling for every kind, so a `wake` can never be inflated to hello size.
    #[must_use]
    pub const fn max_payload_bytes(self) -> usize {
        match self {
            Self::Hello | Self::Join | Self::Depart | Self::Subscribe | Self::Unsubscribe => {
                MAX_PAYLOAD_BYTES
            }
            Self::Wake | Self::Welcome | Self::Error => MAX_WAKE_META_BYTES,
            Self::Ping | Self::Pong => MAX_LIVENESS_PAYLOAD_BYTES,
        }
    }

    /// Human-readable name for logs and refusal messages.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Hello => "hello",
            Self::Welcome => "welcome",
            Self::Join => "join",
            Self::Depart => "depart",
            Self::Subscribe => "subscribe",
            Self::Unsubscribe => "unsubscribe",
            Self::Wake => "wake",
            Self::Ping => "ping",
            Self::Pong => "pong",
            Self::Error => "error",
        }
    }
}

impl fmt::Display for Kind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Every way a frame can be refused. `Send + Sync + 'static` per `ERRORS-12`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FrameError {
    /// Body shorter than the fixed header.
    TooShort {
        /// Bytes actually present.
        got: usize,
    },
    /// Body did not open with [`WIRE_MAGIC`].
    BadMagic,
    /// Version byte was not [`WIRE_VERSION`].
    UnsupportedVersion(u8),
    /// A payload kind removed from v1 by the rust-a2a v2 adjusted plan.
    ReservedPayloadKind(u8),
    /// Kind byte outside the table.
    UnknownKind(u8),
    /// A reserved header byte was non-zero.
    NonZeroReserved,
    /// `from` or `to` exceeded [`MAX_ID_BYTES`], or was empty where required.
    BadId {
        /// Which header field.
        field: &'static str,
        /// Observed length in bytes.
        len: usize,
    },
    /// An id was not valid UTF-8. Ids are refused, never lossily decoded.
    NonUtf8Id {
        /// Which header field.
        field: &'static str,
    },
    /// An id or topic carried a control character. Refused at the parse
    /// boundary so peer-supplied text can never forge a log line or emit a
    /// terminal escape sequence on an operator's console.
    ControlCharacter {
        /// Which field.
        field: &'static str,
    },
    /// Payload exceeded the kind's ceiling.
    PayloadTooLarge {
        /// Frame kind.
        kind: Kind,
        /// Observed payload length.
        len: usize,
        /// Ceiling for this kind.
        max: usize,
    },
    /// Declared lengths did not sum to the body length.
    LengthMismatch {
        /// Length the header declared.
        declared: usize,
        /// Length actually present.
        actual: usize,
    },
    /// Encoded frame exceeded [`MAX_FRAME_BYTES`].
    FrameTooLarge {
        /// Observed frame length.
        len: usize,
    },
    /// The presented delegation exceeded [`MAX_DELEGATION_WIRE_BYTES`].
    DelegationTooLarge {
        /// Observed delegation length.
        len: usize,
    },
    /// A [`WakeMeta`] did not fit [`MAX_WAKE_META_BYTES`].
    MetaTooLarge {
        /// Observed metadata length.
        len: usize,
    },
    /// A [`WakeMeta`] ended mid-field.
    MetaTruncated,
    /// A topic list was malformed, over-long, or over-count.
    BadTopics,
}

impl FrameError {
    /// The wire code this refusal is reported to the sender as.
    #[must_use]
    pub const fn wire_code(&self) -> ErrorCode {
        match self {
            Self::PayloadTooLarge { .. }
            | Self::FrameTooLarge { .. }
            | Self::MetaTooLarge { .. }
            | Self::DelegationTooLarge { .. } => ErrorCode::TooLarge,
            _ => ErrorCode::Malformed,
        }
    }
}

impl fmt::Display for FrameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooShort { got } => {
                write!(
                    f,
                    "frame shorter than the {FRAME_HEADER_BYTES}-byte header ({got} B)"
                )
            }
            Self::BadMagic => f.write_str("frame did not start with the wake-hub magic"),
            Self::UnsupportedVersion(v) => write!(f, "unsupported wire version {v}"),
            Self::ReservedPayloadKind(v) => write!(
                f,
                "wire kind {v} is a payload kind removed from the v1 wake protocol \
                 (request/reply/notify); the hub carries no message bodies"
            ),
            Self::UnknownKind(v) => write!(f, "unknown wire kind {v}"),
            Self::NonZeroReserved => f.write_str("a reserved header byte was non-zero"),
            Self::BadId { field, len } => {
                write!(f, "`{field}` length {len} outside 1..={MAX_ID_BYTES}")
            }
            Self::NonUtf8Id { field } => write!(f, "`{field}` was not valid UTF-8"),
            Self::ControlCharacter { field } => {
                write!(f, "`{field}` contained a control character")
            }
            Self::PayloadTooLarge { kind, len, max } => {
                write!(f, "{kind} payload {len} B exceeds its {max} B ceiling")
            }
            Self::LengthMismatch { declared, actual } => {
                write!(f, "declared body length {declared} B, got {actual} B")
            }
            Self::FrameTooLarge { len } => {
                write!(f, "frame {len} B exceeds the {MAX_FRAME_BYTES} B ceiling")
            }
            Self::DelegationTooLarge { len } => write!(
                f,
                "delegation {len} B exceeds the {MAX_DELEGATION_WIRE_BYTES} B ceiling"
            ),
            Self::MetaTooLarge { len } => {
                write!(
                    f,
                    "wake metadata {len} B exceeds the {MAX_WAKE_META_BYTES} B ceiling"
                )
            }
            Self::MetaTruncated => f.write_str("wake metadata ended mid-field"),
            Self::BadTopics => f.write_str("topic list malformed, over-long, or over-count"),
        }
    }
}

impl std::error::Error for FrameError {}

// ---------------------------------------------------------------------------
// Frame
// ---------------------------------------------------------------------------

/// One decoded wire frame.
///
/// `payload` is [`Bytes`] so a topic fan-out shares ONE heap buffer across
/// every recipient (refcounted fan-out, per the vote's delivery item 8).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    /// Sender agent id. On egress the hub always stamps the id it
    /// authenticated, never the one the client claimed.
    pub from: String,
    /// Destination: an agent id, or a `#topic`.
    pub to: String,
    /// Frame kind.
    pub kind: Kind,
    /// Sender clock, milliseconds since the Unix epoch. Advisory.
    pub ts_ms: u64,
    /// Time-to-live in milliseconds; `0` means no expiry.
    pub ttl_ms: u32,
    /// Kind-specific payload. Never a message body.
    pub payload: Bytes,
}

impl Frame {
    /// Build a frame with no TTL and no timestamp.
    #[must_use]
    pub fn new(kind: Kind, from: impl Into<String>, to: impl Into<String>, payload: Bytes) -> Self {
        Self {
            from: from.into(),
            to: to.into(),
            kind,
            ts_ms: 0,
            ttl_ms: 0,
            payload,
        }
    }

    /// Is `to` a topic (leading `#`) rather than an agent id?
    #[must_use]
    pub fn to_is_topic(&self) -> bool {
        is_topic(&self.to)
    }

    /// Encode to wire bytes.
    ///
    /// # Errors
    ///
    /// Any bound violation in [`FrameError`]. Encoding validates the SAME
    /// bounds as decoding, so the hub cannot emit a frame it would itself
    /// refuse.
    pub fn encode(&self) -> Result<Bytes, FrameError> {
        validate_id("from", &self.from, self.kind != Kind::Hello)?;
        validate_id("to", &self.to, false)?;
        let max = self.kind.max_payload_bytes();
        if self.payload.len() > max {
            return Err(FrameError::PayloadTooLarge {
                kind: self.kind,
                len: self.payload.len(),
                max,
            });
        }
        let total = FRAME_HEADER_BYTES + self.from.len() + self.to.len() + self.payload.len();
        if total > MAX_FRAME_BYTES {
            return Err(FrameError::FrameTooLarge { len: total });
        }
        // Both casts below are proven in range by the checks above, so they use
        // fallible conversion rather than `as` (`PERF-07`).
        let from_len = u8::try_from(self.from.len()).map_err(|_| FrameError::BadId {
            field: "from",
            len: self.from.len(),
        })?;
        let to_len = u8::try_from(self.to.len()).map_err(|_| FrameError::BadId {
            field: "to",
            len: self.to.len(),
        })?;
        let payload_len =
            u16::try_from(self.payload.len()).map_err(|_| FrameError::PayloadTooLarge {
                kind: self.kind,
                len: self.payload.len(),
                max,
            })?;

        let mut buf = BytesMut::with_capacity(total);
        buf.put_slice(&WIRE_MAGIC);
        buf.put_u8(WIRE_VERSION);
        buf.put_u8(self.kind.as_u8());
        buf.put_u8(0); // flags
        buf.put_u8(from_len);
        buf.put_u8(to_len);
        buf.put_u8(0); // reserved
        buf.put_u16(payload_len);
        buf.put_u64(self.ts_ms);
        buf.put_u32(self.ttl_ms);
        buf.put_slice(self.from.as_bytes());
        buf.put_slice(self.to.as_bytes());
        buf.put_slice(&self.payload);
        Ok(buf.freeze())
    }

    /// Decode wire bytes.
    ///
    /// # Errors
    ///
    /// Any bound violation in [`FrameError`]. Nothing is best-effort recovered:
    /// a frame that does not validate is refused whole.
    pub fn decode(body: &[u8]) -> Result<Self, FrameError> {
        if body.len() > MAX_FRAME_BYTES {
            return Err(FrameError::FrameTooLarge { len: body.len() });
        }
        if body.len() < FRAME_HEADER_BYTES {
            return Err(FrameError::TooShort { got: body.len() });
        }
        if body[0..4] != WIRE_MAGIC {
            return Err(FrameError::BadMagic);
        }
        if body[4] != WIRE_VERSION {
            return Err(FrameError::UnsupportedVersion(body[4]));
        }
        let kind = Kind::from_u8(body[5])?;
        if body[6] != 0 || body[9] != 0 {
            return Err(FrameError::NonZeroReserved);
        }
        let from_len = usize::from(body[7]);
        let to_len = usize::from(body[8]);
        let payload_len = usize::from(u16::from_be_bytes([body[10], body[11]]));

        let declared = FRAME_HEADER_BYTES
            .checked_add(from_len)
            .and_then(|n| n.checked_add(to_len))
            .and_then(|n| n.checked_add(payload_len))
            .ok_or(FrameError::LengthMismatch {
                declared: usize::MAX,
                actual: body.len(),
            })?;
        if declared != body.len() {
            return Err(FrameError::LengthMismatch {
                declared,
                actual: body.len(),
            });
        }
        let max = kind.max_payload_bytes();
        if payload_len > max {
            return Err(FrameError::PayloadTooLarge {
                kind,
                len: payload_len,
                max,
            });
        }

        let mut ts = [0u8; 8];
        ts.copy_from_slice(&body[12..20]);
        let mut ttl = [0u8; 4];
        ttl.copy_from_slice(&body[20..24]);

        let from_end = FRAME_HEADER_BYTES + from_len;
        let to_end = from_end + to_len;
        let from = decode_id("from", &body[FRAME_HEADER_BYTES..from_end])?;
        let to = decode_id("to", &body[from_end..to_end])?;
        validate_id("from", &from, kind != Kind::Hello)?;
        validate_id("to", &to, false)?;

        Ok(Self {
            from,
            to,
            kind,
            ts_ms: u64::from_be_bytes(ts),
            ttl_ms: u32::from_be_bytes(ttl),
            payload: Bytes::copy_from_slice(&body[to_end..]),
        })
    }
}

/// Is `s` a topic reference?
#[must_use]
pub fn is_topic(s: &str) -> bool {
    s.starts_with('#')
}

fn decode_id(field: &'static str, raw: &[u8]) -> Result<String, FrameError> {
    std::str::from_utf8(raw)
        .map(ToOwned::to_owned)
        .map_err(|_| FrameError::NonUtf8Id { field })
}

/// Enforce the id bounds shared by encode and decode. `require_non_empty`
/// distinguishes the hub-issued challenge (whose `from` is the hub itself and
/// may legitimately be empty before an identity exists) from every routed
/// frame.
///
/// Control characters are refused outright. An agent id is an identifier, so a
/// newline or an ANSI escape in one has no legitimate use — but it DOES reach
/// an operator's terminal and log file (the forged-`from` refusal logs the
/// claimed id), where it could forge a log line or drive a terminal escape
/// sequence. Refusing at the parse boundary is the fail-closed answer;
/// sanitising at each of the several log sites is the answer that eventually
/// misses one.
fn validate_id(field: &'static str, id: &str, require_non_empty: bool) -> Result<(), FrameError> {
    if id.len() > MAX_ID_BYTES || (require_non_empty && id.is_empty()) {
        return Err(FrameError::BadId {
            field,
            len: id.len(),
        });
    }
    if id.chars().any(char::is_control) {
        return Err(FrameError::ControlCharacter { field });
    }
    Ok(())
}

/// Validate one topic string. Topics are `#`-prefixed, bounded, and never
/// truncated to fit.
///
/// # Errors
///
/// [`FrameError::BadTopics`] when the topic is empty, unprefixed, or longer
/// than [`MAX_TOPIC_BYTES`].
pub fn validate_topic(topic: &str) -> Result<(), FrameError> {
    if !is_topic(topic) || topic.len() < 2 || topic.len() > MAX_TOPIC_BYTES {
        return Err(FrameError::BadTopics);
    }
    // Same reasoning as `validate_id`: a topic reaches operator-facing output.
    if topic.chars().any(char::is_control) {
        return Err(FrameError::BadTopics);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Topic lists
// ---------------------------------------------------------------------------

/// Encode a topic list as `count(u8)` then `len(u8) ‖ bytes` per topic.
///
/// # Errors
///
/// [`FrameError::BadTopics`] when the list is over-count or any topic is
/// invalid.
pub fn encode_topics(topics: &[String]) -> Result<Bytes, FrameError> {
    if topics.len() > MAX_TOPICS_PER_FRAME {
        return Err(FrameError::BadTopics);
    }
    let count = u8::try_from(topics.len()).map_err(|_| FrameError::BadTopics)?;
    let mut buf = BytesMut::with_capacity(1 + topics.len() * (1 + MAX_TOPIC_BYTES));
    buf.put_u8(count);
    for t in topics {
        validate_topic(t)?;
        let len = u8::try_from(t.len()).map_err(|_| FrameError::BadTopics)?;
        buf.put_u8(len);
        buf.put_slice(t.as_bytes());
    }
    Ok(buf.freeze())
}

/// Decode a topic list written by [`encode_topics`].
///
/// # Errors
///
/// [`FrameError::BadTopics`] on truncation, over-count, a bad topic, or
/// trailing bytes. Trailing bytes are an error rather than ignored so a
/// smuggled body cannot ride along behind a valid topic list.
pub fn decode_topics(buf: &[u8]) -> Result<Vec<String>, FrameError> {
    let (&count, mut rest) = buf.split_first().ok_or(FrameError::BadTopics)?;
    let count = usize::from(count);
    if count > MAX_TOPICS_PER_FRAME {
        return Err(FrameError::BadTopics);
    }
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        let (&len, tail) = rest.split_first().ok_or(FrameError::BadTopics)?;
        let len = usize::from(len);
        if tail.len() < len {
            return Err(FrameError::BadTopics);
        }
        let (raw, tail) = tail.split_at(len);
        let topic = std::str::from_utf8(raw).map_err(|_| FrameError::BadTopics)?;
        validate_topic(topic)?;
        out.push(topic.to_owned());
        rest = tail;
    }
    if !rest.is_empty() {
        return Err(FrameError::BadTopics);
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Wake metadata
// ---------------------------------------------------------------------------

/// The content-free hint a `wake` carries.
///
/// `digest` is the SHA-256 of the inbox body, so a recipient can deduplicate
/// and verify what it later reads WITHOUT the hub ever seeing the body. The
/// whole encoding is capped at [`MAX_WAKE_META_BYTES`], enforced at both encode
/// and decode.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct WakeMeta {
    /// ai-memory inbox row id — the durable record this wake points at.
    pub inbox_row_id: String,
    /// Namespace the row landed in.
    pub namespace: String,
    /// Agent that wrote the row.
    pub sender: String,
    /// SHA-256 of the row body: empty, or exactly [`WAKE_DIGEST_BYTES`].
    pub digest: Vec<u8>,
    /// The producer's wake sequence at the moment this hint was minted, so a
    /// client that missed wakes knows it missed them.
    ///
    /// For a SUBSTRATE wake (#3469) this is the producer's HOST-WIDE monotonic
    /// wake counter ([`crate::inbox_wake::seq_high_watermark`]), NOT a
    /// per-recipient inbox depth: the bus has no per-recipient counter and a
    /// truthful one would put a database read on the wake path this EPIC
    /// exists to remove. Read it as "wakes happened that you did not see" — a
    /// gap means do ONE catch-up inbox read. That is fail-safe by
    /// construction: a client may read once more than it had to, and can never
    /// conclude nothing was missed when something was.
    pub seq_high_watermark: u64,
}

impl WakeMeta {
    /// Encode to the `wake` payload form.
    ///
    /// # Errors
    ///
    /// [`FrameError::MetaTooLarge`] if the encoding would exceed
    /// [`MAX_WAKE_META_BYTES`], [`FrameError::BadId`] for an over-long field,
    /// [`FrameError::MetaTruncated`] for a digest that is neither empty nor
    /// exactly [`WAKE_DIGEST_BYTES`].
    pub fn encode(&self) -> Result<Bytes, FrameError> {
        if !self.digest.is_empty() && self.digest.len() != WAKE_DIGEST_BYTES {
            return Err(FrameError::MetaTruncated);
        }
        let mut buf = BytesMut::with_capacity(MAX_WAKE_META_BYTES);
        put_short("inbox_row_id", &mut buf, self.inbox_row_id.as_bytes())?;
        put_short("namespace", &mut buf, self.namespace.as_bytes())?;
        put_short("sender", &mut buf, self.sender.as_bytes())?;
        put_short("digest", &mut buf, &self.digest)?;
        buf.put_u64(self.seq_high_watermark);
        if buf.len() > MAX_WAKE_META_BYTES {
            return Err(FrameError::MetaTooLarge { len: buf.len() });
        }
        Ok(buf.freeze())
    }

    /// Decode a `wake` payload.
    ///
    /// # Errors
    ///
    /// [`FrameError::MetaTooLarge`] past the cap, [`FrameError::MetaTruncated`]
    /// on a short or trailing-byte encoding.
    pub fn decode(buf: &[u8]) -> Result<Self, FrameError> {
        if buf.len() > MAX_WAKE_META_BYTES {
            return Err(FrameError::MetaTooLarge { len: buf.len() });
        }
        let (inbox_row_id, rest) = take_short(buf)?;
        let (namespace, rest) = take_short(rest)?;
        let (sender, rest) = take_short(rest)?;
        let (digest, rest) = take_short(rest)?;
        if !digest.is_empty() && digest.len() != WAKE_DIGEST_BYTES {
            return Err(FrameError::MetaTruncated);
        }
        if rest.len() != 8 {
            return Err(FrameError::MetaTruncated);
        }
        let mut seq = [0u8; 8];
        seq.copy_from_slice(rest);
        Ok(Self {
            inbox_row_id: str_from(inbox_row_id)?,
            namespace: str_from(namespace)?,
            sender: str_from(sender)?,
            digest: digest.to_vec(),
            seq_high_watermark: u64::from_be_bytes(seq),
        })
    }
}

fn str_from(raw: &[u8]) -> Result<String, FrameError> {
    std::str::from_utf8(raw)
        .map(ToOwned::to_owned)
        .map_err(|_| FrameError::MetaTruncated)
}

fn put_short(field: &'static str, buf: &mut BytesMut, raw: &[u8]) -> Result<(), FrameError> {
    let len = u8::try_from(raw.len()).map_err(|_| FrameError::BadId {
        field,
        len: raw.len(),
    })?;
    buf.put_u8(len);
    buf.put_slice(raw);
    Ok(())
}

fn take_short(buf: &[u8]) -> Result<(&[u8], &[u8]), FrameError> {
    let (&len, rest) = buf.split_first().ok_or(FrameError::MetaTruncated)?;
    let len = usize::from(len);
    if rest.len() < len {
        return Err(FrameError::MetaTruncated);
    }
    Ok(rest.split_at(len))
}

// ---------------------------------------------------------------------------
// hello / welcome payloads
// ---------------------------------------------------------------------------

/// The client half of the handshake: public key, transcript signature and the
/// asserted topic list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HelloPayload {
    /// Ed25519 public key the client is authenticating with. This is the
    /// DELEGATED key; the delegation below is what ties it to an enrolled
    /// agent.
    pub pubkey: [u8; PUBKEY_BYTES],
    /// Signature over the domain-separated hello transcript.
    pub signature: [u8; SIGNATURE_BYTES],
    /// The scoped `a2a-hub/join/v1` delegation authorising `pubkey` to speak
    /// for an enrolled agent at this hub (#3468). Empty means "none
    /// presented", which every production verifier refuses — the field is
    /// optional on the WIRE so a malformed or absent delegation is a clean
    /// `401` rather than a framing error that closes the connection before the
    /// identity gate can log why.
    pub delegation: Bytes,
    /// Topics the client wants at handshake time.
    pub topics: Vec<String>,
}

impl HelloPayload {
    /// Encode to the `hello` payload form.
    ///
    /// # Errors
    ///
    /// [`FrameError::BadTopics`] for an invalid topic list.
    pub fn encode(&self) -> Result<Bytes, FrameError> {
        if self.delegation.len() > MAX_DELEGATION_WIRE_BYTES {
            return Err(FrameError::DelegationTooLarge {
                len: self.delegation.len(),
            });
        }
        let delegation_len =
            u16::try_from(self.delegation.len()).map_err(|_| FrameError::DelegationTooLarge {
                len: self.delegation.len(),
            })?;
        let topics = encode_topics(&self.topics)?;
        let mut buf = BytesMut::with_capacity(
            PUBKEY_BYTES + SIGNATURE_BYTES + 2 + self.delegation.len() + topics.len(),
        );
        buf.put_slice(&self.pubkey);
        buf.put_slice(&self.signature);
        buf.put_u16(delegation_len);
        buf.put_slice(&self.delegation);
        buf.put_slice(&topics);
        Ok(buf.freeze())
    }

    /// Decode a `hello` payload.
    ///
    /// # Errors
    ///
    /// [`FrameError::MetaTruncated`] when shorter than key + signature,
    /// [`FrameError::BadTopics`] for an invalid topic list.
    pub fn decode(buf: &[u8]) -> Result<Self, FrameError> {
        const FIXED: usize = PUBKEY_BYTES + SIGNATURE_BYTES + 2;
        if buf.len() < FIXED {
            return Err(FrameError::MetaTruncated);
        }
        let mut pubkey = [0u8; PUBKEY_BYTES];
        pubkey.copy_from_slice(&buf[..PUBKEY_BYTES]);
        let mut signature = [0u8; SIGNATURE_BYTES];
        signature.copy_from_slice(&buf[PUBKEY_BYTES..PUBKEY_BYTES + SIGNATURE_BYTES]);
        let delegation_len = usize::from(u16::from_be_bytes([buf[FIXED - 2], buf[FIXED - 1]]));
        if delegation_len > MAX_DELEGATION_WIRE_BYTES {
            return Err(FrameError::DelegationTooLarge {
                len: delegation_len,
            });
        }
        let delegation_end = FIXED
            .checked_add(delegation_len)
            .ok_or(FrameError::MetaTruncated)?;
        if buf.len() < delegation_end {
            return Err(FrameError::MetaTruncated);
        }
        Ok(Self {
            pubkey,
            signature,
            delegation: Bytes::copy_from_slice(&buf[FIXED..delegation_end]),
            // The topic list stays TRAILING so its no-trailing-bytes rule still
            // holds: a body cannot ride along behind it.
            topics: decode_topics(&buf[delegation_end..])?,
        })
    }
}

/// What the hub tells an accepted session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WelcomePayload {
    /// Session handle assigned to this connection.
    pub session: u32,
    /// Coalesced count of wakes that arrived while the agent was offline.
    pub pending_count: u64,
    /// Distinct inbox-row ids retained from that window.
    pub pending_ids: u32,
    /// `true` when the pending set stopped retaining ids: the client MUST do a
    /// catch-up inbox read rather than trust the id set.
    pub lagged: bool,
    /// Base reconnect backoff to use, in milliseconds.
    pub reconnect_base_ms: u32,
    /// Jitter span to add to the base, in milliseconds.
    pub reconnect_jitter_ms: u32,
}

impl WelcomePayload {
    /// Fixed encoded size in bytes.
    pub const ENCODED_BYTES: usize = 4 + 8 + 4 + 1 + 4 + 4;

    /// Encode to the `welcome` payload form.
    #[must_use]
    pub fn encode(&self) -> Bytes {
        let mut buf = BytesMut::with_capacity(Self::ENCODED_BYTES);
        buf.put_u32(self.session);
        buf.put_u64(self.pending_count);
        buf.put_u32(self.pending_ids);
        buf.put_u8(u8::from(self.lagged));
        buf.put_u32(self.reconnect_base_ms);
        buf.put_u32(self.reconnect_jitter_ms);
        buf.freeze()
    }

    /// Decode a `welcome` payload.
    ///
    /// # Errors
    ///
    /// [`FrameError::MetaTruncated`] when the length is not exactly
    /// [`Self::ENCODED_BYTES`].
    pub fn decode(buf: &[u8]) -> Result<Self, FrameError> {
        if buf.len() != Self::ENCODED_BYTES {
            return Err(FrameError::MetaTruncated);
        }
        let mut session = [0u8; 4];
        session.copy_from_slice(&buf[0..4]);
        let mut count = [0u8; 8];
        count.copy_from_slice(&buf[4..12]);
        let mut ids = [0u8; 4];
        ids.copy_from_slice(&buf[12..16]);
        let mut base = [0u8; 4];
        base.copy_from_slice(&buf[17..21]);
        let mut jitter = [0u8; 4];
        jitter.copy_from_slice(&buf[21..25]);
        Ok(Self {
            session: u32::from_be_bytes(session),
            pending_count: u64::from_be_bytes(count),
            pending_ids: u32::from_be_bytes(ids),
            lagged: buf[16] != 0,
            reconnect_base_ms: u32::from_be_bytes(base),
            reconnect_jitter_ms: u32::from_be_bytes(jitter),
        })
    }
}

/// Encode an `error` payload: `code(u16be)` then a bounded UTF-8 reason.
///
/// The reason is a FIXED string chosen by the hub, never an echo of peer input
/// and never a detail that would turn the refusal into an identity oracle.
#[must_use]
pub fn encode_error(code: ErrorCode, reason: &str) -> Bytes {
    let budget = MAX_WAKE_META_BYTES.saturating_sub(2);
    let mut end = reason.len().min(budget);
    while end > 0 && !reason.is_char_boundary(end) {
        end -= 1;
    }
    let mut buf = BytesMut::with_capacity(2 + end);
    buf.put_u16(code.as_u16());
    buf.put_slice(&reason.as_bytes()[..end]);
    buf.freeze()
}

/// Decode an `error` payload into `(code, reason)`.
///
/// # Errors
///
/// [`FrameError::MetaTruncated`] when shorter than the two-byte code or the
/// reason is not UTF-8.
pub fn decode_error(buf: &[u8]) -> Result<(u16, String), FrameError> {
    if buf.len() < 2 {
        return Err(FrameError::MetaTruncated);
    }
    let code = u16::from_be_bytes([buf[0], buf[1]]);
    let reason = std::str::from_utf8(&buf[2..])
        .map_err(|_| FrameError::MetaTruncated)?
        .to_owned();
    Ok((code, reason))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wake(from: &str, to: &str, payload: Bytes) -> Frame {
        Frame::new(Kind::Wake, from, to, payload)
    }

    fn meta() -> WakeMeta {
        WakeMeta {
            inbox_row_id: "01J8ZQ7X0000000000000000".into(),
            namespace: "hive".into(),
            sender: "agent-a".into(),
            digest: vec![0xAB; WAKE_DIGEST_BYTES],
            seq_high_watermark: 42,
        }
    }

    #[test]
    fn frame_roundtrips_every_kind() {
        for kind in [
            Kind::Hello,
            Kind::Welcome,
            Kind::Join,
            Kind::Depart,
            Kind::Subscribe,
            Kind::Unsubscribe,
            Kind::Wake,
            Kind::Ping,
            Kind::Pong,
            Kind::Error,
        ] {
            let f = Frame {
                from: "agent-a".into(),
                to: "#hive".into(),
                kind,
                ts_ms: 1_700_000_000_000,
                ttl_ms: 5_000,
                payload: Bytes::from_static(b"xyz"),
            };
            let wire = f.encode().expect("encode");
            let back = Frame::decode(&wire).expect("decode");
            assert_eq!(f, back, "roundtrip must be exact for {kind}");
        }
    }

    #[test]
    fn decode_refuses_the_removed_payload_kinds_by_name() {
        for k in RESERVED_PAYLOAD_KINDS {
            assert_eq!(
                Kind::from_u8(k),
                Err(FrameError::ReservedPayloadKind(k)),
                "wire kind {k} (request/reply/notify) must be refused by name"
            );
        }
        // And end-to-end through a real frame body.
        let mut wire = wake("a", "b", Bytes::new()).encode().unwrap().to_vec();
        wire[5] = RESERVED_PAYLOAD_KINDS[0];
        assert_eq!(
            Frame::decode(&wire),
            Err(FrameError::ReservedPayloadKind(RESERVED_PAYLOAD_KINDS[0]))
        );
    }

    #[test]
    fn decode_refuses_bad_magic_version_and_reserved_bytes() {
        let good = wake("a", "b", Bytes::new()).encode().unwrap();

        let mut bad = good.to_vec();
        bad[0] ^= 0xFF;
        assert_eq!(Frame::decode(&bad), Err(FrameError::BadMagic));

        let mut bad = good.to_vec();
        bad[4] = 2;
        assert_eq!(Frame::decode(&bad), Err(FrameError::UnsupportedVersion(2)));

        for idx in [6usize, 9] {
            let mut bad = good.to_vec();
            bad[idx] = 1;
            assert_eq!(
                Frame::decode(&bad),
                Err(FrameError::NonZeroReserved),
                "reserved header byte {idx} must be checked, not ignored"
            );
        }
    }

    #[test]
    fn decode_refuses_a_truncated_or_over_declared_body() {
        let good = wake("a", "b", Bytes::from_static(b"zz")).encode().unwrap();
        let short = &good[..good.len() - 1];
        assert!(matches!(
            Frame::decode(short),
            Err(FrameError::LengthMismatch { .. })
        ));
        assert!(matches!(
            Frame::decode(&good[..FRAME_HEADER_BYTES - 1]),
            Err(FrameError::TooShort { .. })
        ));
    }

    #[test]
    fn decode_refuses_an_oversize_frame_before_parsing_it() {
        let huge = vec![0u8; MAX_FRAME_BYTES + 1];
        assert_eq!(
            Frame::decode(&huge),
            Err(FrameError::FrameTooLarge {
                len: MAX_FRAME_BYTES + 1
            })
        );
    }

    #[test]
    fn encode_refuses_an_id_over_the_ceiling_instead_of_truncating() {
        let long = "a".repeat(MAX_ID_BYTES + 1);
        let err = wake(&long, "b", Bytes::new()).encode().unwrap_err();
        assert_eq!(
            err,
            FrameError::BadId {
                field: "from",
                len: MAX_ID_BYTES + 1
            }
        );
        // Exactly at the ceiling is legal — ai-memory ids go to 128.
        let at = "a".repeat(MAX_ID_BYTES);
        assert!(wake(&at, "b", Bytes::new()).encode().is_ok());
    }

    #[test]
    fn ids_and_topics_refuse_control_characters() {
        for bad in ["agent\na", "agent\u{1b}[2J", "agent\u{0}b", "agent\r\n"] {
            assert_eq!(
                wake(bad, "b", Bytes::new()).encode(),
                Err(FrameError::ControlCharacter { field: "from" }),
                "a control character in an id must be refused at the parse boundary, \
                 not sanitised at each of the log sites that render it"
            );
            assert_eq!(
                wake("a", bad, Bytes::new()).encode(),
                Err(FrameError::ControlCharacter { field: "to" })
            );
        }
        assert_eq!(validate_topic("#hi\nve"), Err(FrameError::BadTopics));
        // And a decode of a hand-built body carrying one is refused too.
        let mut body = wake("aa", "b", Bytes::new()).encode().unwrap().to_vec();
        body[FRAME_HEADER_BYTES] = b'\n';
        assert_eq!(
            Frame::decode(&body),
            Err(FrameError::ControlCharacter { field: "from" })
        );
    }

    #[test]
    fn wake_payload_is_capped_at_the_metadata_ceiling() {
        let over = Bytes::from(vec![0u8; MAX_WAKE_META_BYTES + 1]);
        let err = wake("a", "b", over).encode().unwrap_err();
        assert_eq!(
            err,
            FrameError::PayloadTooLarge {
                kind: Kind::Wake,
                len: MAX_WAKE_META_BYTES + 1,
                max: MAX_WAKE_META_BYTES,
            }
        );
    }

    #[test]
    fn no_kind_admits_a_message_body() {
        for kind in [
            Kind::Hello,
            Kind::Welcome,
            Kind::Join,
            Kind::Depart,
            Kind::Subscribe,
            Kind::Unsubscribe,
            Kind::Wake,
            Kind::Ping,
            Kind::Pong,
            Kind::Error,
        ] {
            assert!(
                kind.max_payload_bytes() <= MAX_PAYLOAD_BYTES,
                "{kind} must stay inside the payload ceiling"
            );
        }
        assert_eq!(Kind::Wake.max_payload_bytes(), MAX_WAKE_META_BYTES);
    }

    #[test]
    fn wake_meta_roundtrips_and_is_bounded() {
        let m = meta();
        let wire = m.encode().expect("encode");
        assert!(wire.len() <= MAX_WAKE_META_BYTES);
        assert_eq!(WakeMeta::decode(&wire).expect("decode"), m);
    }

    #[test]
    fn wake_meta_refuses_an_over_long_encoding() {
        let m = WakeMeta {
            inbox_row_id: "i".repeat(120),
            namespace: "n".repeat(120),
            sender: "s".repeat(120),
            digest: vec![0; WAKE_DIGEST_BYTES],
            seq_high_watermark: 1,
        };
        assert!(matches!(m.encode(), Err(FrameError::MetaTooLarge { .. })));
    }

    #[test]
    fn wake_meta_refuses_a_wrong_length_digest() {
        let mut m = meta();
        m.digest = vec![0; WAKE_DIGEST_BYTES - 1];
        assert_eq!(m.encode(), Err(FrameError::MetaTruncated));
        m.digest = Vec::new();
        assert!(m.encode().is_ok(), "an absent digest is legal");
    }

    #[test]
    fn wake_meta_refuses_trailing_bytes() {
        let wire = meta().encode().unwrap();
        let mut extra = wire.to_vec();
        extra.push(0);
        assert_eq!(WakeMeta::decode(&extra), Err(FrameError::MetaTruncated));
    }

    #[test]
    fn topic_list_roundtrips_and_refuses_abuse() {
        let topics = vec!["#hive".to_string(), "#swarm".to_string()];
        let wire = encode_topics(&topics).expect("encode");
        assert_eq!(decode_topics(&wire).expect("decode"), topics);

        let too_many: Vec<String> = (0..=MAX_TOPICS_PER_FRAME)
            .map(|i| format!("#t{i}"))
            .collect();
        assert_eq!(encode_topics(&too_many), Err(FrameError::BadTopics));

        assert_eq!(
            encode_topics(&["no-hash".to_string()]),
            Err(FrameError::BadTopics)
        );
        assert_eq!(
            encode_topics(&["#".to_string() + &"t".repeat(MAX_TOPIC_BYTES)]),
            Err(FrameError::BadTopics)
        );

        let mut smuggled = wire.to_vec();
        smuggled.extend_from_slice(b"body");
        assert_eq!(
            decode_topics(&smuggled),
            Err(FrameError::BadTopics),
            "trailing bytes must be refused so a body cannot ride a topic list"
        );
    }

    #[test]
    fn hello_payload_roundtrips() {
        let h = HelloPayload {
            pubkey: [7u8; PUBKEY_BYTES],
            signature: [9u8; SIGNATURE_BYTES],
            delegation: Bytes::from_static(b"delegation-bytes"),
            topics: vec!["#hive".into()],
        };
        let wire = h.encode().expect("encode");
        assert!(wire.len() <= Kind::Hello.max_payload_bytes());
        assert_eq!(HelloPayload::decode(&wire).expect("decode"), h);
        assert_eq!(
            HelloPayload::decode(&wire[..PUBKEY_BYTES]),
            Err(FrameError::MetaTruncated)
        );
    }

    #[test]
    fn hello_payload_carries_a_bounded_delegation() {
        let empty = HelloPayload {
            pubkey: [1u8; PUBKEY_BYTES],
            signature: [2u8; SIGNATURE_BYTES],
            delegation: Bytes::new(),
            topics: Vec::new(),
        };
        let wire = empty.encode().expect("encode");
        assert_eq!(HelloPayload::decode(&wire).expect("decode"), empty);

        let over = HelloPayload {
            pubkey: [1u8; PUBKEY_BYTES],
            signature: [2u8; SIGNATURE_BYTES],
            delegation: Bytes::from(vec![0u8; MAX_DELEGATION_WIRE_BYTES + 1]),
            topics: Vec::new(),
        };
        assert_eq!(
            over.encode(),
            Err(FrameError::DelegationTooLarge {
                len: MAX_DELEGATION_WIRE_BYTES + 1
            }),
            "the delegation is bounded at the wire boundary, before any parse"
        );

        // A declared length longer than the body is a truncation, not a
        // silently-short delegation.
        let mut truncated = wire.to_vec();
        truncated[PUBKEY_BYTES + SIGNATURE_BYTES] = 0;
        truncated[PUBKEY_BYTES + SIGNATURE_BYTES + 1] = 8;
        assert_eq!(
            HelloPayload::decode(&truncated),
            Err(FrameError::MetaTruncated)
        );
    }

    #[test]
    fn welcome_payload_roundtrips() {
        let w = WelcomePayload {
            session: 7,
            pending_count: 1_234,
            pending_ids: 12,
            lagged: true,
            reconnect_base_ms: 250,
            reconnect_jitter_ms: 750,
        };
        let wire = w.encode();
        assert_eq!(wire.len(), WelcomePayload::ENCODED_BYTES);
        assert_eq!(WelcomePayload::decode(&wire).expect("decode"), w);
        assert_eq!(
            WelcomePayload::decode(&wire[..3]),
            Err(FrameError::MetaTruncated)
        );
    }

    #[test]
    fn error_payload_is_bounded_and_char_boundary_safe() {
        let long = "é".repeat(MAX_WAKE_META_BYTES);
        let wire = encode_error(ErrorCode::Overflow, &long);
        assert!(wire.len() <= MAX_WAKE_META_BYTES);
        let (code, reason) = decode_error(&wire).expect("decode");
        assert_eq!(code, 507);
        assert!(
            long.starts_with(&reason),
            "truncation must land on a char boundary"
        );
    }

    #[test]
    fn error_codes_are_the_documented_numbers() {
        assert_eq!(ErrorCode::Malformed.as_u16(), 400);
        assert_eq!(ErrorCode::Unauthorized.as_u16(), 401);
        assert_eq!(ErrorCode::Forbidden.as_u16(), 403);
        assert_eq!(ErrorCode::UnknownDestination.as_u16(), 404);
        assert_eq!(ErrorCode::Replaced.as_u16(), 409);
        assert_eq!(ErrorCode::TooLarge.as_u16(), 413);
        assert_eq!(ErrorCode::RateLimited.as_u16(), 429);
        assert_eq!(ErrorCode::Internal.as_u16(), 500);
        assert_eq!(ErrorCode::Overflow.as_u16(), 507);
    }

    #[test]
    fn topic_detection_matches_the_routing_rule() {
        assert!(is_topic("#hive"));
        assert!(!is_topic("hive"));
        assert!(wake("a", "#hive", Bytes::new()).to_is_topic());
    }
}
