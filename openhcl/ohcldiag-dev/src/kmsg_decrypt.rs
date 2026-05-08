// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Inline decryption of `[[OHENC v1 ...]]` sentinels in kmsg output.

use anyhow::Context;
use openhcl_serial_console_crypto::consts::AES_KEY_LEN;
use openhcl_serial_console_crypto::consts::SESSION_ID_LEN;
use openhcl_serial_console_crypto::crypto;
use openhcl_serial_console_crypto::crypto::GksKeyMaterial;
use openhcl_serial_console_crypto::format::Record;
use openhcl_serial_console_crypto::format::SentinelMatch;
use openhcl_serial_console_crypto::format::find_next_sentinel;
use std::collections::HashMap;
use std::path::Path;
use std::sync::Mutex;

/// Holds key material and session state for decrypting sentinels
/// inline within kmsg lines.
pub struct KmsgDecryptor {
    gks: GksKeyMaterial,
    state: Mutex<DecryptState>,
}

struct DecryptState {
    keys: HashMap<[u8; SESSION_ID_LEN], [u8; AES_KEY_LEN]>,
}

impl KmsgDecryptor {
    /// Create a new decryptor from a key file path.
    pub fn new(key_path: &Path) -> anyhow::Result<Self> {
        let key_bytes = fs_err::read(key_path).context("reading --decrypt-key file")?;
        anyhow::ensure!(
            !key_bytes.is_empty() && key_bytes.len() <= crypto::GKS_LEN,
            "key file must be 1..={} bytes, got {}",
            crypto::GKS_LEN,
            key_bytes.len()
        );
        let mut buf = [0u8; crypto::GKS_LEN];
        buf[..key_bytes.len()].copy_from_slice(&key_bytes);
        Ok(Self {
            gks: GksKeyMaterial(buf),
            state: Mutex::new(DecryptState {
                keys: HashMap::new(),
            }),
        })
    }

    /// Decrypt any `[[OHENC v1 ...]]` sentinels found in the line,
    /// returning the line with sentinels replaced by plaintext.
    /// Non-sentinel text passes through unchanged.
    pub fn decrypt_line(&self, line: &str) -> String {
        let bytes = line.as_bytes();
        let mut result = String::new();
        let mut cursor = 0;

        loop {
            match find_next_sentinel(bytes, cursor) {
                SentinelMatch::Found {
                    start,
                    end,
                    payload,
                } => {
                    // Pass through text before the sentinel.
                    result.push_str(&line[cursor..start]);
                    // Try to decrypt.
                    match Record::parse_payload(&payload) {
                        Ok(record) => match self.try_decrypt(&record) {
                            Ok(plaintext) => {
                                result.push_str(&String::from_utf8_lossy(&plaintext));
                            }
                            Err(_) => {
                                // Decrypt failed — keep the sentinel as-is.
                                result.push_str(&line[start..end]);
                            }
                        },
                        Err(_) => {
                            result.push_str(&line[start..end]);
                        }
                    }
                    cursor = end;
                }
                SentinelMatch::Malformed { start, .. } => {
                    let pass_end = (start + 1).min(bytes.len());
                    result.push_str(&line[cursor..pass_end]);
                    cursor = pass_end;
                }
                SentinelMatch::NotFound => {
                    result.push_str(&line[cursor..]);
                    break;
                }
            }
        }

        result
    }

    fn try_decrypt(&self, record: &Record) -> anyhow::Result<Vec<u8>> {
        let mut state = self.state.lock().expect("lock poisoned");
        let key = if let Some(key) = state.keys.get(&record.session_id) {
            *key
        } else {
            let key = crypto::derive_aes_key(&self.gks, &record.session_id)
                .context("deriving AES key")?;
            state.keys.insert(record.session_id, key);
            key
        };
        crypto::decrypt(
            &key,
            &record.session_id,
            record.seq,
            &record.nonce,
            &record.ciphertext,
            &record.tag,
        )
        .context("AES-GCM decrypt failed")
    }
}
