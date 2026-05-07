// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Streaming encrypt/decrypt modes for live pipe usage.
//!
//! `stream-encrypt` reads plaintext lines from stdin and writes
//! `[[OHENC v1 ...]]` records back-to-back to stdout. There is no
//! delimiter between adjacent records — `]]` already terminates each
//! one unambiguously.
//!
//! `stream-decrypt` reads from stdin (which may contain a mix of
//! plaintext and `[[OHENC v1 ...]]` records) and writes decrypted
//! plaintext to stdout. Decoding is byte-stream-based and does not
//! depend on any in-band delimiter (newlines included): the scanner
//! finds sentinels in the buffer, decrypts them, and forwards
//! whatever sits between them as passthrough.
//!
//! Together, two instances can form a round-trip pipe:
//!
//! ```text
//! echo "hello" | decrypt-serial stream-encrypt --key k.bin \
//!     | decrypt-serial stream-decrypt --key k.bin
//! ```

use anyhow::Context;
use openhcl_serial_console_crypto::consts::AES_KEY_LEN;
use openhcl_serial_console_crypto::consts::MAX_PLAINTEXT_LEN;
use openhcl_serial_console_crypto::consts::MAX_SENTINEL_BASE64_LEN;
use openhcl_serial_console_crypto::consts::NONCE_LEN;
use openhcl_serial_console_crypto::consts::SENTINEL_CLOSE;
use openhcl_serial_console_crypto::consts::SENTINEL_OPEN;
use openhcl_serial_console_crypto::consts::SESSION_ID_LEN;
use openhcl_serial_console_crypto::crypto::GksKeyMaterial;
use openhcl_serial_console_crypto::crypto::derive_aes_key;
use openhcl_serial_console_crypto::crypto::encrypt;
use openhcl_serial_console_crypto::format::Record;
use openhcl_serial_console_crypto::format::SentinelError;
use openhcl_serial_console_crypto::format::SentinelMatch;
use openhcl_serial_console_crypto::format::find_next_sentinel;
use std::collections::HashMap;
use std::io::BufRead;
use std::io::Write;
use std::path::PathBuf;
use tracing::debug;
use tracing::info;
use tracing::trace;
use tracing::warn;

/// Read plaintext from stdin, encrypt each line, and write
/// `[[OHENC v1 ...]]` records to stdout.
pub fn stream_encrypt(key: &Option<PathBuf>, vmgs: &Option<PathBuf>) -> anyhow::Result<()> {
    let gks = super::resolve_key(key, vmgs).context("resolving key source")?;
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    stream_encrypt_io(&gks, &mut stdin.lock(), &mut stdout.lock())
}

/// Inner implementation of `stream-encrypt` that takes generic IO
/// handles, for testability.
fn stream_encrypt_io<R: BufRead, W: Write>(
    gks: &GksKeyMaterial,
    reader: &mut R,
    writer: &mut W,
) -> anyhow::Result<()> {
    let mut session_id = [0u8; SESSION_ID_LEN];
    getrandom::fill(&mut session_id).map_err(|e| anyhow::anyhow!("generating session_id: {e}"))?;

    let aes_key = derive_aes_key(gks, &session_id).context("deriving AES key")?;

    let mut seq: u64 = 0;

    for line in reader.lines() {
        let line = line.context("reading input")?;

        // `BufRead::lines()` strips the trailing `\n`. Re-attach it so
        // the encrypted plaintext is self-terminating — that matches
        // the in-VM producer's contract (each encrypted chunk
        // includes the original line terminator) and lets
        // `stream-decrypt` reproduce the line break without
        // synthesizing one.
        let mut plaintext = line.into_bytes();
        plaintext.push(b'\n');

        // Chunk if the line exceeds max plaintext size.
        for chunk in plaintext.chunks(MAX_PLAINTEXT_LEN) {
            let mut nonce = [0u8; NONCE_LEN];
            getrandom::fill(&mut nonce).map_err(|e| anyhow::anyhow!("generating nonce: {e}"))?;

            let (ciphertext, tag) =
                encrypt(&aes_key, &session_id, seq, &nonce, chunk).context("encrypting chunk")?;

            let record = Record {
                session_id,
                seq,
                nonce,
                ciphertext,
                tag,
            };

            // Wire framing carries no inter-record delimiter — `]]`
            // already terminates each record unambiguously.
            write!(writer, "{}", record.encode_to_string()).context("writing record")?;
            seq += 1;
        }
        writer.flush().context("flushing output")?;
    }

    Ok(())
}

/// Read from stdin (may contain plaintext + encrypted records),
/// decrypt any `[[OHENC v1 ...]]` records, and write all output
/// (decrypted records + passthrough plaintext) to stdout.
pub fn stream_decrypt(key: &Option<PathBuf>, vmgs: &Option<PathBuf>) -> anyhow::Result<()> {
    let gks = super::resolve_key(key, vmgs).context("resolving key source")?;
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    stream_decrypt_io(&gks, &mut stdin.lock(), &mut stdout.lock())
}

/// Inner implementation of `stream-decrypt` that takes generic IO
/// handles, for testability.
///
/// Streaming sentinel scanner — does not depend on any delimiter
/// between or around encrypted records on the wire. The scanner
/// pulls bytes from `reader` into a rolling buffer and processes as
/// many complete sentinels (and as much surrounding passthrough
/// plaintext) as possible on each pass, then refills.
fn stream_decrypt_io<R: BufRead, W: Write>(
    gks: &GksKeyMaterial,
    reader: &mut R,
    writer: &mut W,
) -> anyhow::Result<()> {
    let mut buf: Vec<u8> = Vec::new();
    let mut keys = HashMap::<[u8; SESSION_ID_LEN], [u8; AES_KEY_LEN]>::new();
    let mut total_in: u64 = 0;
    let mut total_out: u64 = 0;

    info!(
        sha = build_info::get().scm_revision(),
        branch = build_info::get().scm_branch(),
        "stream-decrypt started",
    );

    loop {
        let n = {
            let chunk = reader.fill_buf().context("reading input")?;
            if chunk.is_empty() {
                info!(
                    total_in,
                    total_out,
                    sessions = keys.len(),
                    "stream-decrypt EOF",
                );
                drain_buffer(
                    &mut buf,
                    &mut keys,
                    gks,
                    writer,
                    &mut total_out,
                    /* at_eof */ true,
                )?;
                writer.flush().context("flushing output")?;
                return Ok(());
            }
            debug!(
                bytes = chunk.len(),
                buf_before = buf.len(),
                buf_after = buf.len() + chunk.len(),
                "fill_buf",
            );
            trace!(hex = ?HexSlice(chunk), "fill_buf bytes");
            buf.extend_from_slice(chunk);
            chunk.len()
        };
        reader.consume(n);
        total_in += n as u64;

        drain_buffer(
            &mut buf,
            &mut keys,
            gks,
            writer,
            &mut total_out,
            /* at_eof */ false,
        )?;
        writer.flush().context("flushing output")?;
    }
}

/// Process as many complete sentinels (and surrounding passthrough)
/// from `buf` as possible. Removes consumed bytes from the front of
/// `buf`. When `at_eof` is false, leaves any in-flight sentinel and
/// up to `SENTINEL_OPEN.len() - 1` straddling tail bytes in `buf` so
/// the next `fill_buf` can complete them. When `at_eof` is true,
/// passes any remaining bytes through as plaintext.
fn drain_buffer<W: Write>(
    buf: &mut Vec<u8>,
    keys: &mut HashMap<[u8; SESSION_ID_LEN], [u8; AES_KEY_LEN]>,
    gks: &GksKeyMaterial,
    writer: &mut W,
    total_out: &mut u64,
    at_eof: bool,
) -> anyhow::Result<()> {
    let mut cursor = 0;
    loop {
        match find_next_sentinel(buf, cursor) {
            SentinelMatch::Found {
                start,
                end,
                payload,
            } => {
                if start > cursor {
                    let n = start - cursor;
                    debug!(bytes = n, "passthrough before sentinel");
                    writer
                        .write_all(&buf[cursor..start])
                        .context("writing passthrough")?;
                    *total_out += n as u64;
                }
                let n = decrypt_and_write(gks, keys, &payload, writer)?;
                *total_out += n as u64;
                debug!(
                    sentinel_start = start,
                    sentinel_len = end - start,
                    plaintext_bytes = n,
                    "decrypt OK",
                );
                cursor = end;
            }
            SentinelMatch::Malformed { start, reason } => {
                // Distinguish "we found `[[OHENC v1 ` but the buffer
                // doesn't yet contain enough bytes to determine
                // whether `]]` will appear inside the max-sentinel
                // window" from "definitely malformed". Only the
                // former should wait for more data.
                let needs_more = !at_eof && matches!(reason, SentinelError::Unterminated) && {
                    let max_search_end = start
                        .saturating_add(SENTINEL_OPEN.len())
                        .saturating_add(MAX_SENTINEL_BASE64_LEN)
                        .saturating_add(SENTINEL_CLOSE.len());
                    buf.len() < max_search_end
                };

                if needs_more {
                    debug!(
                        opener_at = start,
                        buf_len = buf.len(),
                        "in-flight sentinel — waiting for more bytes",
                    );
                    if start > cursor {
                        let n = start - cursor;
                        debug!(bytes = n, "passthrough before in-flight sentinel");
                        writer
                            .write_all(&buf[cursor..start])
                            .context("writing passthrough")?;
                        *total_out += n as u64;
                    }
                    cursor = start;
                    break;
                } else {
                    warn!(
                        opener_at = start,
                        ?reason,
                        "malformed sentinel — passing 1 byte through and resuming scan",
                    );
                    // Truly malformed (or EOF interrupted). Pass
                    // through one byte and resume scanning so a
                    // subsequent inner sentinel can still be
                    // recognised.
                    let pass_end = (start + 1).min(buf.len());
                    let n = pass_end - cursor;
                    writer
                        .write_all(&buf[cursor..pass_end])
                        .context("writing passthrough")?;
                    *total_out += n as u64;
                    cursor = pass_end;
                }
            }
            SentinelMatch::NotFound => {
                // Hold back the last `SENTINEL_OPEN.len() - 1` bytes
                // when not at EOF: an opener could be straddling the
                // tail of this read into the next fill.
                let safe = if at_eof {
                    buf.len()
                } else {
                    buf.len().saturating_sub(SENTINEL_OPEN.len() - 1)
                };
                if safe > cursor {
                    let n = safe - cursor;
                    debug!(
                        bytes = n,
                        held_back = buf.len() - safe,
                        "passthrough (no sentinel found)",
                    );
                    writer
                        .write_all(&buf[cursor..safe])
                        .context("writing passthrough")?;
                    *total_out += n as u64;
                    cursor = safe;
                }
                break;
            }
        }
    }
    buf.drain(..cursor);
    Ok(())
}

/// Decrypt one parsed payload and write its plaintext (or an
/// inline error marker) to `writer`. AES key material is cached
/// per `session_id` so repeated records reuse the KDF result.
/// Returns the number of bytes written to `writer`.
fn decrypt_and_write<W: Write>(
    gks: &GksKeyMaterial,
    keys: &mut HashMap<[u8; SESSION_ID_LEN], [u8; AES_KEY_LEN]>,
    payload: &[u8],
    writer: &mut W,
) -> anyhow::Result<usize> {
    match Record::parse_payload(payload) {
        Ok(record) => {
            let key = keys.entry(record.session_id).or_insert_with(|| {
                debug!(
                    session_id = ?HexSlice(&record.session_id),
                    "deriving key for new session",
                );
                derive_aes_key(gks, &record.session_id).expect("KDF should not fail")
            });
            match openhcl_serial_console_crypto::crypto::decrypt(
                key,
                &record.session_id,
                record.seq,
                &record.nonce,
                &record.ciphertext,
                &record.tag,
            ) {
                Ok(plaintext) => {
                    writer.write_all(&plaintext).context("writing decrypted")?;
                    Ok(plaintext.len())
                }
                Err(e) => {
                    warn!(
                        seq = record.seq,
                        ciphertext_len = record.ciphertext.len(),
                        error = ?e,
                        "decrypt failed",
                    );
                    let marker = format!("<<decrypt failed: {e}>>");
                    writer
                        .write_all(marker.as_bytes())
                        .context("writing error marker")?;
                    Ok(marker.len())
                }
            }
        }
        Err(e) => {
            warn!(error = ?e, payload_len = payload.len(), "parse failed");
            let marker = format!("<<parse failed: {e}>>");
            writer
                .write_all(marker.as_bytes())
                .context("writing parse error")?;
            Ok(marker.len())
        }
    }
}

/// Helper for hex-formatting byte slices in trace logs. Truncates
/// long slices to keep logs readable.
struct HexSlice<'a>(&'a [u8]);

impl std::fmt::Debug for HexSlice<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        const MAX: usize = 64;
        let bytes = if self.0.len() > MAX {
            &self.0[..MAX]
        } else {
            self.0
        };
        for b in bytes {
            write!(f, "{:02x}", b)?;
        }
        if self.0.len() > MAX {
            write!(f, "... ({} more bytes)", self.0.len() - MAX)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use openhcl_serial_console_crypto::consts::AES_KEY_LEN;
    use openhcl_serial_console_crypto::crypto::GKS_LEN;
    use openhcl_serial_console_crypto::crypto::GksKeyMaterial;
    use std::io::Cursor;
    use std::io::Read;

    /// Build a deterministic 2048-byte GKS for tests (matches the
    /// stub key shape used by the producer integration in
    /// `worker.rs:2310-2318`, but the tests don't depend on that
    /// exact pattern — they just need any well-formed GKS).
    fn test_gks() -> GksKeyMaterial {
        let mut buf = [0u8; GKS_LEN];
        for (i, b) in buf.iter_mut().enumerate() {
            *b = (i & 0xff) as u8;
        }
        GksKeyMaterial(buf)
    }

    fn round_trip(input: &[u8]) -> Vec<u8> {
        let gks = test_gks();
        let mut encrypted = Vec::new();
        stream_encrypt_io(&gks, &mut Cursor::new(input), &mut encrypted)
            .expect("stream_encrypt_io should succeed");
        let mut decrypted = Vec::new();
        stream_decrypt_io(&gks, &mut Cursor::new(&encrypted), &mut decrypted)
            .expect("stream_decrypt_io should succeed");
        decrypted
    }

    #[test]
    fn round_trip_single_line_lf_terminated() {
        let input = b"hello world\n";
        let output = round_trip(input);
        assert_eq!(output, input);
    }

    #[test]
    fn round_trip_multi_line() {
        let input = b"line one\nline two\nline three\n";
        let output = round_trip(input);
        assert_eq!(output, input);
    }

    #[test]
    fn round_trip_preserves_embedded_cr() {
        // `lines()` treats lone `\r` as a regular character (only
        // `\n` and `\r\n` are line terminators). Verify a `\r` in
        // the middle of a line round-trips faithfully.
        let input = b"long status line ending with cr\rshort overlay\n";
        let output = round_trip(input);
        assert_eq!(output, input);
    }

    #[test]
    fn round_trip_preserves_utf8_ellipsis() {
        // U+2026 (UTF-8 0xE2 0x80 0xA6) is the systemd ellipsize
        // marker. Verify it round-trips byte-for-byte without the
        // pipeline turning it into anything else.
        let mut input = Vec::new();
        input.extend_from_slice(b"Starting kmod-static-nodes.service");
        input.extend_from_slice(&[0xe2, 0x80, 0xa6]); // U+2026 …
        input.extend_from_slice(b"eate List of Static Device Nodes...\n");
        let output = round_trip(&input);
        assert_eq!(output, input);
    }

    #[test]
    fn stream_decrypt_does_not_add_newline_after_sentinel() {
        // Encrypt one line, then verify the decrypt side outputs
        // exactly one `\n` (from the producer's plaintext), not two.
        let input = b"abc\n";
        let output = round_trip(input);
        // No double newline.
        assert_eq!(output.iter().filter(|&&b| b == b'\n').count(), 1);
    }

    #[test]
    fn stream_decrypt_passes_through_plaintext_with_newline() {
        // Plaintext that doesn't contain any sentinel should pass
        // through verbatim, including its trailing `\n`.
        let gks = test_gks();
        let mut output = Vec::new();
        stream_decrypt_io(
            &gks,
            &mut Cursor::new(b"plain text line one\nplain text line two\n"),
            &mut output,
        )
        .expect("stream_decrypt_io should succeed");
        assert_eq!(output, b"plain text line one\nplain text line two\n");
    }

    #[test]
    fn stream_decrypt_preserves_blank_lines() {
        let gks = test_gks();
        let mut output = Vec::new();
        stream_decrypt_io(&gks, &mut Cursor::new(b"a\n\nb\n"), &mut output)
            .expect("stream_decrypt_io should succeed");
        assert_eq!(output, b"a\n\nb\n");
    }

    /// Encrypt a single plaintext payload outside of `stream_encrypt_io`
    /// so tests can construct exact wire-format inputs.
    fn encode_one(plaintext: &[u8], session_id: [u8; SESSION_ID_LEN], seq: u64) -> Vec<u8> {
        let gks = test_gks();
        let aes_key: [u8; AES_KEY_LEN] = derive_aes_key(&gks, &session_id).unwrap();
        let mut nonce = [0u8; NONCE_LEN];
        getrandom::fill(&mut nonce).expect("getrandom");
        let (ciphertext, tag) =
            encrypt(&aes_key, &session_id, seq, &nonce, plaintext).expect("encrypt should succeed");
        let record = Record {
            session_id,
            seq,
            nonce,
            ciphertext,
            tag,
        };
        record.encode_to_string().into_bytes()
    }

    #[test]
    fn stream_decrypt_handles_mixed_plaintext_and_records() {
        let gks = test_gks();
        let mut session_id = [0u8; SESSION_ID_LEN];
        getrandom::fill(&mut session_id).expect("getrandom");

        let sentinel = encode_one(b"encrypted line\n", session_id, 0);

        let mut input = Vec::new();
        input.extend_from_slice(b"first plaintext line\n");
        input.extend_from_slice(&sentinel);
        input.extend_from_slice(b"third plaintext line\n");

        let mut output = Vec::new();
        stream_decrypt_io(&gks, &mut Cursor::new(&input), &mut output)
            .expect("stream_decrypt_io should succeed");

        assert_eq!(
            output,
            b"first plaintext line\nencrypted line\nthird plaintext line\n"
        );
    }

    #[test]
    fn round_trip_no_wire_lf_between_records() {
        // Multi-line input encrypts to multiple records — confirm the
        // wire bytes contain exactly N sentinels, no `\n` between them,
        // and the round-trip restores the original input.
        let gks = test_gks();
        let input = b"alpha\nbeta\ngamma\n";

        let mut encrypted = Vec::new();
        stream_encrypt_io(&gks, &mut Cursor::new(input), &mut encrypted)
            .expect("stream_encrypt_io should succeed");

        // Wire should contain three `[[OHENC v1 ` openers and three
        // `]]` closers, with no `\n` characters anywhere in the
        // framing.
        let opens = count_subseq(&encrypted, SENTINEL_OPEN);
        let closes = count_subseq(&encrypted, SENTINEL_CLOSE);
        assert_eq!(opens, 3, "expected three sentinel openers on the wire");
        assert_eq!(closes, 3, "expected three sentinel closers on the wire");
        assert_eq!(
            encrypted.iter().filter(|&&b| b == b'\n').count(),
            0,
            "wire framing must not contain newline bytes"
        );

        let mut decrypted = Vec::new();
        stream_decrypt_io(&gks, &mut Cursor::new(&encrypted), &mut decrypted)
            .expect("stream_decrypt_io should succeed");
        assert_eq!(decrypted, input);
    }

    #[test]
    fn stream_decrypt_handles_back_to_back_records_no_separator() {
        // Three pre-built records concatenated with absolutely
        // nothing between them — exactly what the new producer wire
        // format will emit.
        let gks = test_gks();
        let mut session_id = [0u8; SESSION_ID_LEN];
        getrandom::fill(&mut session_id).expect("getrandom");
        let mut input = Vec::new();
        input.extend_from_slice(&encode_one(b"one\n", session_id, 0));
        input.extend_from_slice(&encode_one(b"two\n", session_id, 1));
        input.extend_from_slice(&encode_one(b"three\n", session_id, 2));

        let mut output = Vec::new();
        stream_decrypt_io(&gks, &mut Cursor::new(&input), &mut output)
            .expect("stream_decrypt_io should succeed");
        assert_eq!(output, b"one\ntwo\nthree\n");
    }

    /// `BufRead` adapter that surfaces input one byte at a time.
    /// Lets tests verify the streaming scanner correctly accumulates
    /// across multiple `fill_buf` calls.
    struct OneAtATime<'a> {
        inner: Cursor<&'a [u8]>,
        held: [u8; 1],
        held_filled: bool,
    }

    impl<'a> OneAtATime<'a> {
        fn new(data: &'a [u8]) -> Self {
            Self {
                inner: Cursor::new(data),
                held: [0],
                held_filled: false,
            }
        }
    }

    impl Read for OneAtATime<'_> {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            if buf.is_empty() {
                return Ok(0);
            }
            self.inner.read(&mut buf[..1])
        }
    }

    impl BufRead for OneAtATime<'_> {
        fn fill_buf(&mut self) -> std::io::Result<&[u8]> {
            if !self.held_filled {
                let n = self.inner.read(&mut self.held)?;
                if n == 0 {
                    return Ok(&[]);
                }
                self.held_filled = true;
            }
            Ok(&self.held[..1])
        }
        fn consume(&mut self, amt: usize) {
            assert!(amt <= 1);
            if amt == 1 {
                self.held_filled = false;
            }
        }
    }

    #[test]
    fn streaming_scanner_handles_byte_at_a_time_reads() {
        // The same wire bytes that round_trip_no_wire_lf_between_records
        // produces, but fed through a reader that surfaces one byte
        // per fill_buf call. Forces the scanner to accumulate across
        // many partial reads.
        let gks = test_gks();
        let input = b"alpha\nbeta\ngamma\n";
        let mut encrypted = Vec::new();
        stream_encrypt_io(&gks, &mut Cursor::new(input), &mut encrypted)
            .expect("stream_encrypt_io should succeed");

        let mut output = Vec::new();
        let mut reader = OneAtATime::new(&encrypted);
        stream_decrypt_io(&gks, &mut reader, &mut output)
            .expect("stream_decrypt_io should succeed");
        assert_eq!(output, input);
    }

    #[test]
    fn streaming_scanner_handles_opener_straddled_across_reads() {
        // First chunk ends mid-opener (`[[OHENC `), second chunk
        // completes the opener and the rest of the record. Verify
        // the scanner doesn't emit the partial opener bytes as
        // passthrough.
        let gks = test_gks();
        let mut session_id = [0u8; SESSION_ID_LEN];
        getrandom::fill(&mut session_id).expect("getrandom");
        let sentinel = encode_one(b"hello\n", session_id, 0);

        // Compose: leading plaintext, then the sentinel — split into
        // two chunks straddling the opener.
        let mut full = Vec::new();
        full.extend_from_slice(b"prefix ");
        full.extend_from_slice(&sentinel);

        // Find a split point that lands inside `[[OHENC v1 ` (opener
        // is 11 bytes, prefix is 7 bytes, so a split at byte 13
        // lands inside the opener).
        let split = "prefix [[OH".len();
        assert!(split < full.len());

        struct TwoChunk<'a> {
            chunks: [&'a [u8]; 2],
            i: usize,
            pos: usize,
        }
        impl Read for TwoChunk<'_> {
            fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
                unreachable!("test uses BufRead path")
            }
        }
        impl BufRead for TwoChunk<'_> {
            fn fill_buf(&mut self) -> std::io::Result<&[u8]> {
                if self.i >= self.chunks.len() {
                    return Ok(&[]);
                }
                Ok(&self.chunks[self.i][self.pos..])
            }
            fn consume(&mut self, amt: usize) {
                self.pos += amt;
                if self.pos >= self.chunks[self.i].len() {
                    self.i += 1;
                    self.pos = 0;
                }
            }
        }

        let mut reader = TwoChunk {
            chunks: [&full[..split], &full[split..]],
            i: 0,
            pos: 0,
        };
        let mut output = Vec::new();
        stream_decrypt_io(&gks, &mut reader, &mut output)
            .expect("stream_decrypt_io should succeed");
        assert_eq!(output, b"prefix hello\n");
    }

    #[test]
    fn streaming_scanner_passthrough_no_terminator() {
        // No newlines anywhere, no sentinels — must still emit the
        // bytes as plaintext rather than hanging waiting for `\n`.
        let gks = test_gks();
        let input = b"no newline anywhere in this stream";
        let mut output = Vec::new();
        stream_decrypt_io(&gks, &mut Cursor::new(input), &mut output)
            .expect("stream_decrypt_io should succeed");
        assert_eq!(output, input);
    }

    #[test]
    fn streaming_scanner_partial_sentinel_at_eof_passthrough() {
        // Reader ends mid-opener. The scanner has no way to know
        // whether the bytes are real sentinel start or coincidental
        // plaintext, so it must pass them through verbatim rather
        // than silently dropping them.
        let gks = test_gks();
        let input = b"plain prefix [[OHENC v1 ";
        let mut output = Vec::new();
        stream_decrypt_io(&gks, &mut Cursor::new(input), &mut output)
            .expect("stream_decrypt_io should succeed");
        assert_eq!(output, input);
    }

    #[test]
    fn streaming_scanner_truly_malformed_sentinel_passes_through() {
        // Opener present, no closer, and the buffer is larger than
        // the maximum legal sentinel size — so further reads can't
        // possibly complete a valid sentinel. Must pass through
        // (slowly, byte-at-a-time) rather than wait or hang.
        let gks = test_gks();
        let mut input = Vec::new();
        input.extend_from_slice(b"[[OHENC v1 ");
        input.resize(input.len() + MAX_SENTINEL_BASE64_LEN + 16, b'A');
        input.extend_from_slice(b"trailing\n");

        let mut output = Vec::new();
        stream_decrypt_io(&gks, &mut Cursor::new(&input), &mut output)
            .expect("stream_decrypt_io should succeed");
        // We don't assert exact byte-equality with input because the
        // scanner may legitimately interpret a coincidental inner
        // `[[OHENC v1 ` (there isn't one here) — but for this input
        // the entire payload should pass through verbatim.
        assert_eq!(output, input);
    }

    /// Count the number of (potentially overlapping) occurrences of
    /// `needle` in `haystack`. Used by tests to assert the number of
    /// sentinels on the wire.
    fn count_subseq(haystack: &[u8], needle: &[u8]) -> usize {
        if needle.is_empty() || haystack.len() < needle.len() {
            return 0;
        }
        haystack
            .windows(needle.len())
            .filter(|w| *w == needle)
            .count()
    }
}
