// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Encrypting wrapper for [`kmsg_writer::KmsgWriter`] that encrypts
//! the message body of each trace event using the
//! `openhcl_serial_console_crypto` wire format before writing to
//! `/dev/kmsg`.
//!
//! The syslog priority prefix and target name remain in plaintext so
//! log routing and filtering still work. Only the formatted message
//! content is encrypted.
//!
//! Output visible via `ohcldiag-dev kmsg -f`:
//! ```text
//! <6>underhill_core::worker: [[OHENC v1 abc123...]]
//! ```
//!
//! Decrypt by piping through `decrypt-serial`:
//! ```text
//! ohcldiag-dev.exe MyVM kmsg -f | decrypt-serial.exe stream-decrypt --key key.bin
//! ```

use openhcl_serial_console_crypto::consts::MAX_PLAINTEXT_LEN;
use openhcl_serial_console_crypto::consts::NONCE_LEN;
use openhcl_serial_console_crypto::consts::SESSION_ID_LEN;
use openhcl_serial_console_crypto::crypto::GksKeyMaterial;
use openhcl_serial_console_crypto::crypto::derive_aes_key;
use openhcl_serial_console_crypto::crypto::encrypt;
use openhcl_serial_console_crypto::format::Record;
use std::io::Write;
use std::sync::Arc;
use std::sync::Mutex;
use tracing_subscriber::fmt::MakeWriter;

/// An encrypting wrapper around [`kmsg_writer::KmsgWriter`].
///
/// Implements [`MakeWriter`] so it can be used as a drop-in
/// replacement in the tracing subscriber layer.
pub struct EncryptingKmsgWriter {
    inner: kmsg_writer::KmsgWriter,
    state: Arc<Mutex<EncryptState>>,
}

struct EncryptState {
    aes_key: [u8; 32],
    session_id: [u8; SESSION_ID_LEN],
    seq: u64,
}

impl EncryptingKmsgWriter {
    /// Create a new encrypting kmsg writer.
    ///
    /// Derives a per-session AES key from the provided GKS material.
    pub fn new(inner: kmsg_writer::KmsgWriter, gks: &GksKeyMaterial) -> std::io::Result<Self> {
        let mut session_id = [0u8; SESSION_ID_LEN];
        getrandom::fill(&mut session_id)
            .map_err(|e| std::io::Error::other(format!("session_id generation failed: {e}")))?;

        let aes_key = derive_aes_key(gks, &session_id)
            .map_err(|e| std::io::Error::other(format!("AES key derivation failed: {e}")))?;

        Ok(Self {
            inner,
            state: Arc::new(Mutex::new(EncryptState {
                aes_key,
                session_id,
                seq: 0,
            })),
        })
    }
}

/// Writer returned by [`EncryptingKmsgWriter::make_writer_for`].
///
/// When `encrypt` is true, encrypts the message body. Otherwise
/// passes through to the inner writer as plaintext.
pub struct EncryptingKmsgWithPrefix<'a> {
    inner_writer: kmsg_writer::KmsgWithPrefix<'a>,
    state: Arc<Mutex<EncryptState>>,
    encrypt: bool,
}

impl<'a> MakeWriter<'a> for EncryptingKmsgWriter {
    type Writer = EncryptingKmsgWithPrefix<'a>;

    fn make_writer(&'a self) -> Self::Writer {
        EncryptingKmsgWithPrefix {
            inner_writer: self.inner.make_writer(),
            state: self.state.clone(),
            encrypt: false, // default: no encryption for untagged events
        }
    }

    fn make_writer_for(&'a self, meta: &tracing::Metadata<'_>) -> Self::Writer {
        // Only encrypt events tagged with CVM_CONFIDENTIAL.
        let encrypt = meta.fields().field("CVM_CONFIDENTIAL").is_some();
        EncryptingKmsgWithPrefix {
            inner_writer: self.inner.make_writer_for(meta),
            state: self.state.clone(),
            encrypt,
        }
    }
}

impl Write for EncryptingKmsgWithPrefix<'_> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if !self.encrypt {
            // Pass through as plaintext for non-confidential events.
            return self.inner_writer.write(buf);
        }

        let plaintext_len = buf.len();

        // Truncate to max plaintext size before encrypting.
        let to_encrypt = &buf[..plaintext_len.min(MAX_PLAINTEXT_LEN)];

        let encrypted = {
            let mut state = self.state.lock().expect("lock poisoned");

            let mut nonce = [0u8; NONCE_LEN];
            getrandom::fill(&mut nonce)
                .map_err(|e| std::io::Error::other(format!("nonce failed: {e}")))?;

            let (ciphertext, tag) = encrypt(
                &state.aes_key,
                &state.session_id,
                state.seq,
                &nonce,
                to_encrypt,
            )
            .map_err(|e| std::io::Error::other(format!("encrypt failed: {e}")))?;

            let record = Record {
                session_id: state.session_id,
                seq: state.seq,
                nonce,
                ciphertext,
                tag,
            };

            state.seq += 1;
            record.encode_to_string()
        };

        // Write the encrypted sentinel through the inner writer,
        // which prepends the syslog prefix.
        self.inner_writer.write_all(encrypted.as_bytes())?;

        // Report original plaintext length consumed.
        Ok(plaintext_len)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner_writer.flush()
    }
}
