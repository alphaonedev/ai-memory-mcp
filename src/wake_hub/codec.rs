// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! Length-delimited framing for the `wake-hub` (issue
//! [#3467](https://github.com/alphaonedev/ai-memory-mcp/issues/3467)).
//!
//! One `u32` big-endian length prefix, one body, and a hard
//! `max_frame_length` of [`MAX_FRAME_BYTES`]. The ceiling is enforced by the
//! CODEC, before a byte of body is buffered: a peer that announces a 4 GiB
//! frame gets an `InvalidData` error and a closed connection, not a 4 GiB
//! allocation. That is the difference between a bounded hub and a
//! one-connection OOM.
//!
//! The same ceiling is applied on the write side, so the hub can never emit a
//! frame it would itself refuse to read.

use tokio_util::codec::{LengthDelimitedCodec, length_delimited};

use super::limits::MAX_FRAME_BYTES;

/// Byte width of the length prefix.
pub const LENGTH_FIELD_BYTES: usize = 4;

/// Build the one codec configuration both directions use.
#[must_use]
pub fn codec() -> LengthDelimitedCodec {
    builder().new_codec()
}

/// The shared builder, so read and write halves cannot drift apart.
fn builder() -> length_delimited::Builder {
    let mut b = LengthDelimitedCodec::builder();
    b.big_endian()
        .length_field_offset(0)
        .length_field_length(LENGTH_FIELD_BYTES)
        .max_frame_length(MAX_FRAME_BYTES);
    b
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::{BufMut, Bytes, BytesMut};
    use tokio_util::codec::{Decoder, Encoder};

    #[test]
    fn a_frame_at_the_ceiling_roundtrips() {
        let mut c = codec();
        let body = Bytes::from(vec![9u8; MAX_FRAME_BYTES]);
        let mut wire = BytesMut::new();
        c.encode(body.clone(), &mut wire).expect("encode");
        assert_eq!(wire.len(), LENGTH_FIELD_BYTES + MAX_FRAME_BYTES);
        let got = c.decode(&mut wire).expect("decode").expect("one frame");
        assert_eq!(got, body);
    }

    #[test]
    fn encoding_over_the_ceiling_is_refused() {
        let mut c = codec();
        let body = Bytes::from(vec![9u8; MAX_FRAME_BYTES + 1]);
        let mut wire = BytesMut::new();
        assert!(
            c.encode(body, &mut wire).is_err(),
            "the hub must never emit a frame it would refuse to read"
        );
    }

    #[test]
    fn an_oversize_length_prefix_is_refused_before_the_body_is_buffered() {
        let mut c = codec();
        // Announce 4 GiB, send nothing. The decoder must refuse on the header.
        let mut wire = BytesMut::new();
        wire.put_u32(u32::MAX);
        let err = c.decode(&mut wire).expect_err("must refuse");
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    }

    #[test]
    fn a_partial_frame_yields_none_rather_than_a_short_body() {
        let mut c = codec();
        let mut wire = BytesMut::new();
        wire.put_u32(8);
        wire.put_slice(b"abc");
        assert!(
            c.decode(&mut wire).expect("no error yet").is_none(),
            "a truncated frame must never be handed up as a short body"
        );
    }
}
