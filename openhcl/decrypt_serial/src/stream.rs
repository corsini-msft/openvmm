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

    let mut session_id = [0u8; SESSION_ID_LEN];
    getrandom::fill(&mut session_id).map_err(|e| anyhow::anyhow!("generating session_id: {e}"))?;

    let aes_key = derive_aes_key(&gks, &session_id).context("deriving AES key")?;

    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    let mut seq: u64 = 0;

    for line in stdin.lock().lines() {
        let line = line.context("reading stdin")?;
        let plaintext = line.as_bytes();

        // Chunk if the line exceeds max plaintext size.
        for chunk in plaintext.chunks(MAX_PLAINTEXT_LEN).chain(
            // If plaintext is empty (blank line), still emit one record.
            if plaintext.is_empty() {
                Some(&b""[..]).into_iter()
            } else {
                None.into_iter()
            },
        ) {
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

            writeln!(out, "{}", record.encode_to_string()).context("writing record")?;
            seq += 1;
        }
        out.flush().context("flushing stdout")?;
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
    let mut out = stdout.lock();

    let mut keys = std::collections::HashMap::<
        [u8; SESSION_ID_LEN],
        [u8; openhcl_serial_console_crypto::consts::AES_KEY_LEN],
    >::new();

    for line in stdin.lock().lines() {
        let line = line.context("reading stdin")?;
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
                        out.write_all(&line_bytes[cursor..start])
                            .context("writing passthrough")?;
                    }
                    match Record::parse_payload(&payload) {
                        Ok(record) => {
                            let key = keys.entry(record.session_id).or_insert_with(|| {
                                derive_aes_key(&gks, &record.session_id)
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
                                    out.write_all(&plaintext).context("writing decrypted")?;
                                    found_record = true;
                                }
                                Err(e) => {
                                    write!(out, "<<decrypt failed: {e}>>")
                                        .context("writing error marker")?;
                                }
                            }
                        }
                        Err(e) => {
                            write!(out, "<<parse failed: {e}>>").context("writing parse error")?;
                        }
                    }
                    cursor = end;
                }
                SentinelMatch::Malformed { start, .. } => {
                    let pass_end = (start + 1).min(line_bytes.len());
                    out.write_all(&line_bytes[cursor..pass_end])
                        .context("writing passthrough")?;
                    cursor = pass_end;
                }
                SentinelMatch::NotFound => {
                    out.write_all(&line_bytes[cursor..])
                        .context("writing passthrough")?;
                    break;
                }
            }
        }

        // Preserve line endings for passthrough text, add newline
        // after decrypted records too.
        if !found_record || !line_bytes.is_empty() {
            writeln!(out).context("writing newline")?;
        }
        out.flush().context("flushing stdout")?;
    }

    Ok(())
}
