// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Streaming encrypt/decrypt modes for live pipe usage.
//!
//! `stream-encrypt` reads plaintext lines from stdin and writes
//! `[[OHENC v1 ...]]` records to stdout.
//!
//! `stream-decrypt` reads from stdin (which may contain a mix of
//! plaintext and `[[OHENC v1 ...]]` records) and writes decrypted
//! plaintext to stdout.
//!
//! Together, two instances can form a round-trip pipe:
//!
//! ```text
//! echo "hello" | decrypt-serial stream-encrypt --key k.bin \
//!     | decrypt-serial stream-decrypt --key k.bin
//! ```

use anyhow::Context;
use openhcl_serial_console_crypto::consts::MAX_PLAINTEXT_LEN;
use openhcl_serial_console_crypto::consts::NONCE_LEN;
use openhcl_serial_console_crypto::consts::SESSION_ID_LEN;
use openhcl_serial_console_crypto::crypto::GksKeyMaterial;
use openhcl_serial_console_crypto::crypto::derive_aes_key;
use openhcl_serial_console_crypto::crypto::encrypt;
use openhcl_serial_console_crypto::format::Record;
use openhcl_serial_console_crypto::format::SentinelMatch;
use openhcl_serial_console_crypto::format::find_next_sentinel;
use std::io::BufRead;
use std::io::Write;
use std::path::PathBuf;

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
        // the in-VM producer's contract (`EncryptingSerialIo`
        // includes the terminator inside each encrypted chunk) and
        // lets `stream-decrypt` reproduce the line break without
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

            writeln!(writer, "{}", record.encode_to_string()).context("writing record")?;
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
fn stream_decrypt_io<R: BufRead, W: Write>(
    gks: &GksKeyMaterial,
    reader: &mut R,
    writer: &mut W,
) -> anyhow::Result<()> {
    let mut keys = std::collections::HashMap::<
        [u8; SESSION_ID_LEN],
        [u8; openhcl_serial_console_crypto::consts::AES_KEY_LEN],
    >::new();

    for line in reader.lines() {
        let line = line.context("reading input")?;
        let line_bytes = line.as_bytes();

        // Try to find a sentinel in this line.
        let mut cursor = 0;
        let mut found_record = false;

        while cursor < line_bytes.len() {
            match find_next_sentinel(line_bytes, cursor) {
                SentinelMatch::Found {
                    start,
                    end,
                    payload,
                } => {
                    // Write any plaintext before the sentinel.
                    if start > cursor {
                        writer
                            .write_all(&line_bytes[cursor..start])
                            .context("writing passthrough")?;
                    }
                    match Record::parse_payload(&payload) {
                        Ok(record) => {
                            let key = keys.entry(record.session_id).or_insert_with(|| {
                                derive_aes_key(gks, &record.session_id)
                                    .expect("KDF should not fail")
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
                                    found_record = true;
                                }
                                Err(e) => {
                                    write!(writer, "<<decrypt failed: {e}>>")
                                        .context("writing error marker")?;
                                }
                            }
                        }
                        Err(e) => {
                            write!(writer, "<<parse failed: {e}>>")
                                .context("writing parse error")?;
                        }
                    }
                    cursor = end;
                }
                SentinelMatch::Malformed { start, .. } => {
                    let pass_end = (start + 1).min(line_bytes.len());
                    writer
                        .write_all(&line_bytes[cursor..pass_end])
                        .context("writing passthrough")?;
                    cursor = pass_end;
                }
                SentinelMatch::NotFound => {
                    writer
                        .write_all(&line_bytes[cursor..])
                        .context("writing passthrough")?;
                    break;
                }
            }
        }

        // Re-add the line terminator that `BufRead::lines()` stripped,
        // but only for passthrough input lines. For sentinel-bearing
        // lines the producer already includes the original line
        // terminator inside the encrypted plaintext, so adding another
        // `\n` here would (a) double-space the output and (b) break
        // `\r`-based status overlays whose terminator is `\r`, not
        // `\n`.
        if !found_record {
            writeln!(writer).context("writing newline")?;
        }
        writer.flush().context("flushing output")?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use openhcl_serial_console_crypto::consts::AES_KEY_LEN;
    use openhcl_serial_console_crypto::crypto::GKS_LEN;
    use openhcl_serial_console_crypto::crypto::GksKeyMaterial;
    use std::io::Cursor;

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

    #[test]
    fn stream_decrypt_handles_mixed_plaintext_and_records() {
        // Build a stream where plaintext lines (without sentinels)
        // are interleaved with encrypted records. Each must come
        // through the decrypter in the right order with the right
        // terminators.
        let gks = test_gks();

        // First, encrypt one line by hand to get a real sentinel.
        let mut session_id = [0u8; SESSION_ID_LEN];
        getrandom::fill(&mut session_id).expect("getrandom");
        let aes_key: [u8; AES_KEY_LEN] = derive_aes_key(&gks, &session_id).unwrap();
        let mut nonce = [0u8; NONCE_LEN];
        getrandom::fill(&mut nonce).expect("getrandom");
        let plaintext = b"encrypted line\n";
        let (ciphertext, tag) =
            encrypt(&aes_key, &session_id, 0, &nonce, plaintext).expect("encrypt");
        let record = Record {
            session_id,
            seq: 0,
            nonce,
            ciphertext,
            tag,
        };
        let sentinel = record.encode_to_string();

        // Build the input stream: plaintext, then sentinel, then
        // plaintext.
        let mut input = Vec::new();
        input.extend_from_slice(b"first plaintext line\n");
        input.extend_from_slice(sentinel.as_bytes());
        input.extend_from_slice(b"\n");
        input.extend_from_slice(b"third plaintext line\n");

        let mut output = Vec::new();
        stream_decrypt_io(&gks, &mut Cursor::new(&input), &mut output)
            .expect("stream_decrypt_io should succeed");

        let expected = b"first plaintext line\nencrypted line\nthird plaintext line\n";
        assert_eq!(output, expected);
    }
}
