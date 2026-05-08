// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Streaming sentinel scanner for `[[OHENC v1 ...]]` records on a
//! byte stream.
//!
//! Drives a rolling buffer + per-session key cache. Callers feed
//! arbitrary bytes via [`StreamScanner::extend`] and ask for as much
//! processed output as possible via [`StreamScanner::drain`]. The
//! scanner does not perform I/O; it just transforms a byte stream
//! and writes the decrypted-or-passthrough plaintext into the
//! provided [`std::io::Write`] sink.
//!
//! Used by:
//! * the host CLI (`encrypted-serial decrypt-stream` / `bridge`)
//! * the OpenHCL VTL2 wrapper (`EncryptedSerialIo::poll_read`) to
//!   decrypt host-originated input before it reaches the guest UART
//! * `ohcldiag-dev`'s kmsg decrypt path
//!
//! No tracing is performed at this layer; callers should wrap calls
//! into their own instrumentation.

use crate::consts::AES_KEY_LEN;
use crate::consts::MAX_SENTINEL_BASE64_LEN;
use crate::consts::SENTINEL_CLOSE;
use crate::consts::SENTINEL_OPEN;
use crate::consts::SESSION_ID_LEN;
use crate::crypto::GksKeyMaterial;
use crate::crypto::derive_aes_key;
use crate::crypto::decrypt as aes_decrypt;
use crate::format::Record;
use crate::format::SentinelError;
use crate::format::SentinelMatch;
use crate::format::find_next_sentinel;
use std::collections::HashMap;
use std::io;

/// Statistics from one [`StreamScanner::drain`] call.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DrainStats {
    /// Bytes written to `writer` during this drain — sum of decrypted
    /// plaintext and passthrough.
    pub bytes_out: u64,
    /// Complete sentinels that decrypted successfully.
    pub records_ok: u64,
    /// Sentinels that failed to decrypt or parse (their bytes are
    /// surfaced through the writer as inline `<<...>>` markers).
    pub records_failed: u64,
}

/// A streaming sentinel scanner.
///
/// Fed bytes via [`extend`](Self::extend), then drained on demand via
/// [`drain`](Self::drain). Caches per-session AES keys so repeated
/// records under the same `session_id` skip the KDF.
pub struct StreamScanner {
    /// Bytes received from the wire but not yet processed.
    buf: Vec<u8>,
    /// AES keys derived per `session_id` observed in the input.
    keys: HashMap<[u8; SESSION_ID_LEN], [u8; AES_KEY_LEN]>,
}

impl StreamScanner {
    /// Create a new empty scanner.
    pub fn new() -> Self {
        Self {
            buf: Vec::new(),
            keys: HashMap::new(),
        }
    }

    /// Append bytes that just arrived on the wire. The scanner will
    /// process them on the next [`drain`](Self::drain) call.
    pub fn extend(&mut self, bytes: &[u8]) {
        self.buf.extend_from_slice(bytes);
    }

    /// Number of bytes currently buffered (not yet drained).
    pub fn buffered(&self) -> usize {
        self.buf.len()
    }

    /// Number of distinct sessions whose AES keys are cached.
    pub fn sessions(&self) -> usize {
        self.keys.len()
    }

    /// Process as much of the buffer as possible into `writer`.
    ///
    /// Each contiguous chunk of decrypted plaintext OR passthrough
    /// plaintext is written as one `write_all`. The scanner removes
    /// consumed bytes from the front of its internal buffer.
    ///
    /// When `at_eof` is `false`, the scanner leaves any in-flight
    /// sentinel and up to `SENTINEL_OPEN.len() - 1` straddling tail
    /// bytes in the buffer so the next [`extend`](Self::extend) can
    /// complete them.
    ///
    /// When `at_eof` is `true`, all remaining bytes are flushed
    /// (including any partial in-flight sentinel as passthrough).
    /// After that the buffer is empty and a subsequent `drain` is a
    /// no-op.
    ///
    /// Decrypt or parse failures are surfaced inline as `<<decrypt
    /// failed: ...>>` / `<<parse failed: ...>>` markers in the
    /// `writer` output, matching the existing host-side decrypter
    /// behaviour. Truly malformed sentinels (no closing `]]` within
    /// the maximum allowed window) result in a one-byte passthrough
    /// followed by a resumed scan from the next byte.
    pub fn drain(
        &mut self,
        gks: &GksKeyMaterial,
        at_eof: bool,
        writer: &mut dyn io::Write,
    ) -> io::Result<DrainStats> {
        let mut stats = DrainStats::default();
        let mut cursor = 0;

        loop {
            match find_next_sentinel(&self.buf, cursor) {
                SentinelMatch::Found {
                    start,
                    end,
                    payload,
                } => {
                    if start > cursor {
                        let chunk = &self.buf[cursor..start];
                        writer.write_all(chunk)?;
                        stats.bytes_out += chunk.len() as u64;
                    }
                    let n = decrypt_and_write(gks, &mut self.keys, &payload, writer)?;
                    stats.bytes_out += n.bytes_written as u64;
                    if n.success {
                        stats.records_ok += 1;
                    } else {
                        stats.records_failed += 1;
                    }
                    cursor = end;
                }
                SentinelMatch::Malformed { start, reason } => {
                    let needs_more =
                        !at_eof && matches!(reason, SentinelError::Unterminated) && {
                            let max_search_end = start
                                .saturating_add(SENTINEL_OPEN.len())
                                .saturating_add(MAX_SENTINEL_BASE64_LEN)
                                .saturating_add(SENTINEL_CLOSE.len());
                            self.buf.len() < max_search_end
                        };
                    if needs_more {
                        if start > cursor {
                            let chunk = &self.buf[cursor..start];
                            writer.write_all(chunk)?;
                            stats.bytes_out += chunk.len() as u64;
                        }
                        cursor = start;
                        break;
                    }
                    // Truly malformed (or EOF interrupted). Pass
                    // through one byte and resume scanning so a
                    // subsequent inner sentinel can still be
                    // recognised.
                    let pass_end = (start + 1).min(self.buf.len());
                    let chunk = &self.buf[cursor..pass_end];
                    writer.write_all(chunk)?;
                    stats.bytes_out += chunk.len() as u64;
                    cursor = pass_end;
                }
                SentinelMatch::NotFound => {
                    let safe = if at_eof {
                        self.buf.len()
                    } else {
                        self.buf.len().saturating_sub(SENTINEL_OPEN.len() - 1)
                    };
                    if safe > cursor {
                        let chunk = &self.buf[cursor..safe];
                        writer.write_all(chunk)?;
                        stats.bytes_out += chunk.len() as u64;
                        cursor = safe;
                    }
                    break;
                }
            }
        }
        self.buf.drain(..cursor);
        Ok(stats)
    }
}

impl Default for StreamScanner {
    fn default() -> Self {
        Self::new()
    }
}

struct DecryptOutcome {
    bytes_written: usize,
    success: bool,
}

fn decrypt_and_write(
    gks: &GksKeyMaterial,
    keys: &mut HashMap<[u8; SESSION_ID_LEN], [u8; AES_KEY_LEN]>,
    payload: &[u8],
    writer: &mut dyn io::Write,
) -> io::Result<DecryptOutcome> {
    match Record::parse_payload(payload) {
        Ok(record) => {
            let key = keys.entry(record.session_id).or_insert_with(|| {
                derive_aes_key(gks, &record.session_id).expect("KDF should not fail")
            });
            match aes_decrypt(
                key,
                &record.session_id,
                record.seq,
                &record.nonce,
                &record.ciphertext,
                &record.tag,
            ) {
                Ok(plaintext) => {
                    writer.write_all(&plaintext)?;
                    Ok(DecryptOutcome {
                        bytes_written: plaintext.len(),
                        success: true,
                    })
                }
                Err(e) => {
                    let marker = format!("<<decrypt failed: {e}>>");
                    writer.write_all(marker.as_bytes())?;
                    Ok(DecryptOutcome {
                        bytes_written: marker.len(),
                        success: false,
                    })
                }
            }
        }
        Err(e) => {
            let marker = format!("<<parse failed: {e}>>");
            writer.write_all(marker.as_bytes())?;
            Ok(DecryptOutcome {
                bytes_written: marker.len(),
                success: false,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consts::NONCE_LEN;
    use crate::crypto::GKS_LEN;
    use crate::crypto::encrypt as aes_encrypt;

    fn test_gks() -> GksKeyMaterial {
        let mut buf = [0u8; GKS_LEN];
        for (i, b) in buf.iter_mut().enumerate() {
            *b = (i & 0xff) as u8;
        }
        GksKeyMaterial(buf)
    }

    /// Build one wire-format record for the given plaintext under a
    /// fresh random session_id and nonce. Returns the bytes that
    /// would appear on the wire.
    fn build_record(plaintext: &[u8], session_id: [u8; SESSION_ID_LEN], seq: u64) -> Vec<u8> {
        let aes_key: [u8; AES_KEY_LEN] = derive_aes_key(&test_gks(), &session_id).unwrap();
        let mut nonce = [0u8; NONCE_LEN];
        for (i, b) in nonce.iter_mut().enumerate() {
            *b = ((i + (seq as usize)) & 0xff) as u8;
        }
        let (ciphertext, tag) =
            aes_encrypt(&aes_key, &session_id, seq, &nonce, plaintext).unwrap();
        let record = Record {
            session_id,
            seq,
            nonce,
            ciphertext,
            tag,
        };
        record.encode_to_string().into_bytes()
    }

    fn det_session_id(seed: u8) -> [u8; SESSION_ID_LEN] {
        let mut s = [0u8; SESSION_ID_LEN];
        for (i, b) in s.iter_mut().enumerate() {
            *b = seed.wrapping_add(i as u8);
        }
        s
    }

    #[test]
    fn extend_then_drain_single_record() {
        let sid = det_session_id(0x10);
        let wire = build_record(b"hello\n", sid, 0);
        let mut scanner = StreamScanner::new();
        scanner.extend(&wire);

        let mut out = Vec::new();
        let stats = scanner.drain(&test_gks(), false, &mut out).unwrap();
        assert_eq!(out, b"hello\n");
        assert_eq!(stats.records_ok, 1);
        assert_eq!(stats.records_failed, 0);
        assert_eq!(stats.bytes_out, b"hello\n".len() as u64);
        assert_eq!(scanner.buffered(), 0);
    }

    #[test]
    fn extend_partial_then_complete() {
        let sid = det_session_id(0x20);
        let wire = build_record(b"two-step\n", sid, 0);
        let split = wire.len() / 2;

        let mut scanner = StreamScanner::new();
        scanner.extend(&wire[..split]);
        let mut out = Vec::new();
        let stats = scanner.drain(&test_gks(), false, &mut out).unwrap();
        assert_eq!(out, b"", "partial sentinel should not emit yet");
        assert_eq!(stats.records_ok, 0);

        scanner.extend(&wire[split..]);
        let stats = scanner.drain(&test_gks(), false, &mut out).unwrap();
        assert_eq!(out, b"two-step\n");
        assert_eq!(stats.records_ok, 1);
        assert_eq!(scanner.buffered(), 0);
    }

    #[test]
    fn passthrough_then_record_then_passthrough() {
        let sid = det_session_id(0x30);
        let mut wire = Vec::new();
        wire.extend_from_slice(b"prefix ");
        wire.extend_from_slice(&build_record(b"middle\n", sid, 0));
        wire.extend_from_slice(b" suffix");

        let mut scanner = StreamScanner::new();
        scanner.extend(&wire);
        let mut out = Vec::new();
        scanner.drain(&test_gks(), true, &mut out).unwrap();
        assert_eq!(out, b"prefix middle\n suffix");
    }

    #[test]
    fn truly_malformed_passes_through_one_byte_at_a_time() {
        let mut wire = Vec::new();
        wire.extend_from_slice(b"[[OHENC v1 ");
        wire.resize(wire.len() + MAX_SENTINEL_BASE64_LEN + 16, b'A');
        wire.extend_from_slice(b"trailing\n");

        let mut scanner = StreamScanner::new();
        scanner.extend(&wire);
        let mut out = Vec::new();
        // at_eof=true so the trailing 10 bytes don't get held back
        // by the straddle-protection prefix in the NotFound branch.
        scanner.drain(&test_gks(), true, &mut out).unwrap();
        assert_eq!(out, wire);
    }

    #[test]
    fn drain_at_eof_flushes_partial_sentinel_as_passthrough() {
        let mut scanner = StreamScanner::new();
        scanner.extend(b"plain prefix [[OHENC v1 ");

        let mut out = Vec::new();
        scanner.drain(&test_gks(), true, &mut out).unwrap();
        assert_eq!(out, b"plain prefix [[OHENC v1 ");
        assert_eq!(scanner.buffered(), 0);
    }

    #[test]
    fn multiple_sessions_decrypt_independently() {
        let sid_a = det_session_id(0x40);
        let sid_b = det_session_id(0x80);
        let mut wire = Vec::new();
        wire.extend_from_slice(&build_record(b"alpha\n", sid_a, 0));
        wire.extend_from_slice(&build_record(b"bravo\n", sid_b, 0));
        wire.extend_from_slice(&build_record(b"alpha2\n", sid_a, 1));

        let mut scanner = StreamScanner::new();
        scanner.extend(&wire);
        let mut out = Vec::new();
        let stats = scanner.drain(&test_gks(), false, &mut out).unwrap();
        assert_eq!(out, b"alpha\nbravo\nalpha2\n");
        assert_eq!(stats.records_ok, 3);
        assert_eq!(scanner.sessions(), 2);
    }

    #[test]
    fn back_to_back_records_no_separator() {
        let sid = det_session_id(0x50);
        let mut wire = Vec::new();
        wire.extend_from_slice(&build_record(b"a", sid, 0));
        wire.extend_from_slice(&build_record(b"b", sid, 1));
        wire.extend_from_slice(&build_record(b"c", sid, 2));

        let mut scanner = StreamScanner::new();
        scanner.extend(&wire);
        let mut out = Vec::new();
        scanner.drain(&test_gks(), false, &mut out).unwrap();
        assert_eq!(out, b"abc");
    }

    #[test]
    fn no_data_drain_is_noop() {
        let mut scanner = StreamScanner::new();
        let mut out = Vec::new();
        let stats = scanner.drain(&test_gks(), false, &mut out).unwrap();
        assert_eq!(stats, DrainStats::default());
        assert!(out.is_empty());
    }

    #[test]
    fn straddle_protection_holds_back_partial_opener() {
        // No opener actually present, but the tail looks like the
        // start of one. Without holding back, we'd emit `[[OHENC v`
        // as passthrough and then never recognise the opener when
        // the rest arrived. The held-back tail is exactly
        // `SENTINEL_OPEN.len() - 1` = 10 bytes; for the input
        // "hello [[OHENC v" (15 bytes) that means we emit "hello"
        // and hold back " [[OHENC v" (10 bytes including the
        // trailing space).
        let mut scanner = StreamScanner::new();
        scanner.extend(b"hello [[OHENC v");
        let mut out = Vec::new();
        scanner.drain(&test_gks(), false, &mut out).unwrap();
        assert_eq!(out, b"hello");
        assert_eq!(scanner.buffered(), b" [[OHENC v".len());

        scanner.extend(b"oops not a sentinel\n");
        scanner.drain(&test_gks(), true, &mut out).unwrap();
        assert_eq!(out, b"hello [[OHENC voops not a sentinel\n");
    }
}
