// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #4064 — delimiter-exact recovery after an oversized MCP stdio line.
//!
//! When a JSON-RPC line overruns [`super::MCP_MAX_LINE_BYTES`] the stdio loop
//! emits one `-32700` and must resume on the NEXT frame. The pre-#4064 drain
//! read whole 8 KiB chunks with `Read::read` and stopped at the first chunk
//! containing a newline — discarding every byte after that newline in the same
//! chunk. Valid requests a client had already pipelined behind the bad frame
//! (a coalesced pipe write, or a regular-file stdin) vanished with no response,
//! or survived as a truncated tail that produced a spurious later parse error.
//!
//! [`drain_oversize_line`] consumes through the first `\n` ONLY, via
//! `BufRead::fill_buf` / `consume`, leaving every later byte buffered for the
//! next `read_until`. The drain ceiling ([`super::MCP_MAX_DRAIN_BYTES`]) still
//! bounds work on a never-terminated stream.

use std::io::{self, BufRead};

/// How [`drain_oversize_line`] stopped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DrainOutcome {
    /// The offending line's `\n` was consumed; the reader is positioned on the
    /// first byte of the next frame (anything after the newline is untouched).
    Terminated,
    /// End of input before a newline — the offending line was the last one.
    Eof,
    /// `ceiling` bytes were discarded with no newline in sight; the caller
    /// closes the stream rather than serve an unbounded peer.
    CeilingHit,
}

/// Discard the remainder of an oversized line: every byte up to AND
/// including the first `\n`, never a byte past it, and at most `ceiling`
/// bytes of line content before giving up.
///
/// # Errors
/// Any non-`Interrupted` I/O error from the underlying reader.
pub fn drain_oversize_line<R: BufRead + ?Sized>(
    reader: &mut R,
    ceiling: usize,
) -> io::Result<DrainOutcome> {
    let mut drained: usize = 0;
    loop {
        if drained >= ceiling {
            return Ok(DrainOutcome::CeilingHit);
        }
        let buf = match reader.fill_buf() {
            Ok(buf) => buf,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        };
        if buf.is_empty() {
            return Ok(DrainOutcome::Eof);
        }
        // Only look inside the remaining budget, so the ceiling is exact.
        let window = &buf[..buf.len().min(ceiling - drained)];
        if let Some(pos) = window.iter().position(|&b| b == b'\n') {
            reader.consume(pos + 1);
            return Ok(DrainOutcome::Terminated);
        }
        let n = window.len();
        reader.consume(n);
        drained += n;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufReader, Read as _};

    /// The bytes after the terminating newline survive, whatever the
    /// terminator's position inside the reader's buffer.
    #[test]
    fn keeps_every_byte_after_the_newline_at_every_offset_4064() {
        for cap in [1usize, 2, 3, 7, 8, 64, 8192] {
            for junk in 0..20usize {
                let mut input = vec![b'x'; junk];
                input.extend_from_slice(b"\n{\"a\":1}\n{\"b\"");
                let mut reader = BufReader::with_capacity(cap, input.as_slice());
                assert_eq!(
                    drain_oversize_line(&mut reader, 1 << 20).expect("drain"),
                    DrainOutcome::Terminated
                );
                let mut rest = Vec::new();
                reader.read_to_end(&mut rest).expect("rest");
                assert_eq!(rest, b"{\"a\":1}\n{\"b\"", "cap={cap} junk={junk}");
            }
        }
    }

    #[test]
    fn eof_before_newline_is_reported_4064() {
        let mut reader = BufReader::with_capacity(4, &b"no newline here"[..]);
        assert_eq!(
            drain_oversize_line(&mut reader, 1 << 20).expect("drain"),
            DrainOutcome::Eof
        );
    }

    #[test]
    fn ceiling_bounds_the_drain_exactly_4064() {
        let input = vec![b'x'; 100];
        let mut reader = BufReader::with_capacity(7, input.as_slice());
        assert_eq!(
            drain_oversize_line(&mut reader, 50).expect("drain"),
            DrainOutcome::CeilingHit
        );
        let mut rest = Vec::new();
        reader.read_to_end(&mut rest).expect("rest");
        assert_eq!(rest.len(), 50, "exactly the ceiling was discarded");
        // A newline just past the ceiling does not rescue the stream.
        let mut input = vec![b'x'; 50];
        input.push(b'\n');
        let mut reader = BufReader::with_capacity(64, input.as_slice());
        assert_eq!(
            drain_oversize_line(&mut reader, 50).expect("drain"),
            DrainOutcome::CeilingHit
        );
    }
}
