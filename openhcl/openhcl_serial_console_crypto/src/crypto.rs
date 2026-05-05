// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Key derivation and AES-256-GCM encrypt/decrypt for the encrypted
//! serial console wire format.

use crate::consts::AES_KEY_LEN;
use crate::consts::KDF_LABEL;
use crate::consts::NONCE_LEN;
use crate::consts::SESSION_ID_LEN;
use crate::consts::TAG_LEN;
use crate::format::build_aad;
use thiserror::Error;

/// The 2048-byte Guest Secret Key blob, sourced from
/// `FileId::GUEST_SECRET_KEY` of a VMGS file. Wrap it in this newtype
/// to make it harder to accidentally pass arbitrary bytes to
/// [`derive_aes_key`].
#[derive(Clone)]
pub struct GksKeyMaterial(pub [u8; GKS_LEN]);

/// Length in bytes of the GKS blob carried in
/// `FileId::GUEST_SECRET_KEY`. Mirrors the value in
/// `openhcl_attestation_protocol::vmgs::GUEST_SECRET_KEY_MAX_SIZE`;
/// duplicated here so this crate does not need to depend on the
/// attestation-protocol crate.
pub const GKS_LEN: usize = 2048;

const _: () = assert!(GKS_LEN > 0);

impl std::fmt::Debug for GksKeyMaterial {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Don't dump 2 KiB of secret bytes in Debug output.
        f.debug_struct("GksKeyMaterial")
            .field("len", &self.0.len())
            .finish_non_exhaustive()
    }
}

/// Derive the per-session AES-256-GCM key from the GKS blob and the
/// session identifier carried in the record.
///
/// The decryptor caches the resulting key per `session_id` so it does
/// not re-run the KDF for every record.
pub fn derive_aes_key(
    gks: &GksKeyMaterial,
    session_id: &[u8; SESSION_ID_LEN],
) -> Result<[u8; AES_KEY_LEN], CryptoError> {
    let derived =
        crypto::kdf::kbkdf_hmac_sha256(&gks.0, KDF_LABEL, session_id, AES_KEY_LEN)
            .map_err(CryptoError::Kdf)?;
    let arr: [u8; AES_KEY_LEN] = derived
        .as_slice()
        .try_into()
        .map_err(|_| CryptoError::DerivedKeyLength { got: derived.len() })?;
    Ok(arr)
}

/// Encrypt `plaintext` for inclusion in a record. The returned tuple
/// is `(ciphertext, tag)`; both go into the wire-format payload as-is
/// alongside `session_id`, `seq`, and `nonce`.
///
/// `session_id` and `seq` are bound to the AEAD via AAD so the
/// decryptor will reject any record where either has been tampered
/// with.
pub fn encrypt(
    aes_key: &[u8; AES_KEY_LEN],
    session_id: &[u8; SESSION_ID_LEN],
    seq: u64,
    nonce: &[u8; NONCE_LEN],
    plaintext: &[u8],
) -> Result<(Vec<u8>, [u8; TAG_LEN]), CryptoError> {
    let aad = build_aad(session_id, seq);
    let aes = crypto::aes_256_gcm::Aes256Gcm::new(aes_key).map_err(CryptoError::Aes)?;
    let mut enc_ctx = aes.encrypt().map_err(CryptoError::Aes)?;
    let mut tag = [0u8; TAG_LEN];
    let ciphertext = enc_ctx
        .cipher_with_aad(nonce, &aad, plaintext, &mut tag)
        .map_err(CryptoError::Aes)?;
    Ok((ciphertext, tag))
}

/// Decrypt and authenticate the ciphertext from a single record.
///
/// `session_id` and `seq` MUST be the values pulled from the wire
/// format payload; they are rebuilt into AAD and verified against the
/// `tag`. Any mutation to the wire-format header bits AAD covers (the
/// version domain string, `session_id`, `seq`) makes this fail.
pub fn decrypt(
    aes_key: &[u8; AES_KEY_LEN],
    session_id: &[u8; SESSION_ID_LEN],
    seq: u64,
    nonce: &[u8; NONCE_LEN],
    ciphertext: &[u8],
    tag: &[u8; TAG_LEN],
) -> Result<Vec<u8>, CryptoError> {
    let aad = build_aad(session_id, seq);
    let aes = crypto::aes_256_gcm::Aes256Gcm::new(aes_key).map_err(CryptoError::Aes)?;
    let mut dec_ctx = aes.decrypt().map_err(CryptoError::Aes)?;
    dec_ctx
        .cipher_with_aad(nonce, &aad, ciphertext, tag)
        .map_err(CryptoError::Aes)
}

/// Errors produced by the encrypt/decrypt helpers.
#[derive(Debug, Error)]
pub enum CryptoError {
    /// The KDF backend failed.
    #[error("failed to derive AES key from GKS")]
    Kdf(#[source] crypto::kdf::KdfError),
    /// The AES-256-GCM backend failed (e.g. tag verification).
    #[error("AES-256-GCM operation failed")]
    Aes(#[source] crypto::aes_256_gcm::Aes256GcmError),
    /// The KDF returned an unexpected number of bytes.
    #[error("KDF produced {got} bytes, expected {AES_KEY_LEN}")]
    DerivedKeyLength {
        /// The unexpected length returned by the KDF.
        got: usize,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_gks() -> GksKeyMaterial {
        // Deterministic but non-trivial fill so the KDF KAT below is
        // stable.
        let mut buf = [0u8; GKS_LEN];
        for (i, b) in buf.iter_mut().enumerate() {
            *b = (i & 0xff) as u8;
        }
        GksKeyMaterial(buf)
    }

    #[test]
    fn round_trip() {
        let gks = sample_gks();
        let session_id = [0xaau8; SESSION_ID_LEN];
        let key = derive_aes_key(&gks, &session_id).unwrap();
        let nonce = [0x11u8; NONCE_LEN];
        let plain = b"hello, encrypted serial console";

        let (cipher, tag) = encrypt(&key, &session_id, 7, &nonce, plain).unwrap();
        let recovered = decrypt(&key, &session_id, 7, &nonce, &cipher, &tag).unwrap();
        assert_eq!(recovered, plain);
    }

    #[test]
    fn empty_plaintext_round_trips() {
        let gks = sample_gks();
        let session_id = [0x55u8; SESSION_ID_LEN];
        let key = derive_aes_key(&gks, &session_id).unwrap();
        let nonce = [0x22u8; NONCE_LEN];

        let (cipher, tag) = encrypt(&key, &session_id, 0, &nonce, b"").unwrap();
        assert!(cipher.is_empty());
        let recovered = decrypt(&key, &session_id, 0, &nonce, &cipher, &tag).unwrap();
        assert_eq!(recovered, b"");
    }

    #[test]
    fn aad_binding_session_id() {
        let gks = sample_gks();
        let session_id = [0x55u8; SESSION_ID_LEN];
        let key = derive_aes_key(&gks, &session_id).unwrap();
        let nonce = [0x33u8; NONCE_LEN];
        let plain = b"x";

        let (cipher, tag) = encrypt(&key, &session_id, 1, &nonce, plain).unwrap();
        let mut tampered = session_id;
        tampered[0] ^= 1;
        let res = decrypt(&key, &tampered, 1, &nonce, &cipher, &tag);
        assert!(res.is_err(), "wrong session_id in AAD must fail");
    }

    #[test]
    fn aad_binding_seq() {
        let gks = sample_gks();
        let session_id = [0x66u8; SESSION_ID_LEN];
        let key = derive_aes_key(&gks, &session_id).unwrap();
        let nonce = [0x44u8; NONCE_LEN];
        let plain = b"x";

        let (cipher, tag) = encrypt(&key, &session_id, 1, &nonce, plain).unwrap();
        let res = decrypt(&key, &session_id, 2, &nonce, &cipher, &tag);
        assert!(res.is_err(), "wrong seq in AAD must fail");
    }

    #[test]
    fn nonce_tampering() {
        let gks = sample_gks();
        let session_id = [0x77u8; SESSION_ID_LEN];
        let key = derive_aes_key(&gks, &session_id).unwrap();
        let nonce = [0x55u8; NONCE_LEN];
        let plain = b"abc";

        let (cipher, tag) = encrypt(&key, &session_id, 9, &nonce, plain).unwrap();
        let mut bad_nonce = nonce;
        bad_nonce[0] ^= 1;
        let res = decrypt(&key, &session_id, 9, &bad_nonce, &cipher, &tag);
        assert!(res.is_err(), "wrong nonce must fail");
    }

    #[test]
    fn ciphertext_tampering() {
        let gks = sample_gks();
        let session_id = [0x88u8; SESSION_ID_LEN];
        let key = derive_aes_key(&gks, &session_id).unwrap();
        let nonce = [0x66u8; NONCE_LEN];
        let plain = b"abc";

        let (cipher, tag) = encrypt(&key, &session_id, 9, &nonce, plain).unwrap();
        let mut bad = cipher.clone();
        bad[0] ^= 1;
        let res = decrypt(&key, &session_id, 9, &nonce, &bad, &tag);
        assert!(res.is_err(), "tampered ciphertext must fail");
    }

    #[test]
    fn tag_tampering() {
        let gks = sample_gks();
        let session_id = [0x99u8; SESSION_ID_LEN];
        let key = derive_aes_key(&gks, &session_id).unwrap();
        let nonce = [0x77u8; NONCE_LEN];
        let plain = b"abc";

        let (cipher, mut tag) = encrypt(&key, &session_id, 9, &nonce, plain).unwrap();
        tag[0] ^= 1;
        let res = decrypt(&key, &session_id, 9, &nonce, &cipher, &tag);
        assert!(res.is_err(), "tampered tag must fail");
    }

    #[test]
    fn per_session_key_isolation() {
        let gks = sample_gks();
        let session_a = [0x01u8; SESSION_ID_LEN];
        let session_b = [0x02u8; SESSION_ID_LEN];
        let key_a = derive_aes_key(&gks, &session_a).unwrap();
        let key_b = derive_aes_key(&gks, &session_b).unwrap();
        assert_ne!(key_a, key_b, "different sessions must derive different keys");

        let nonce = [0x88u8; NONCE_LEN];
        let plain = b"x";
        let (cipher, tag) = encrypt(&key_a, &session_a, 0, &nonce, plain).unwrap();

        // Decrypting with session B's key should fail (different
        // key); decrypting with session A's key but session_b in AAD
        // should also fail.
        let res = decrypt(&key_b, &session_a, 0, &nonce, &cipher, &tag);
        assert!(res.is_err());
        let res = decrypt(&key_a, &session_b, 0, &nonce, &cipher, &tag);
        assert!(res.is_err());
    }

    #[test]
    fn kdf_known_answer() {
        // Pin the GKS+session_id -> AES key derivation. If a future
        // change to the KDF label, output length, or salt usage
        // breaks this test, that is by design -- the producer side
        // must derive the same key bit-for-bit.
        let gks = sample_gks();
        let session_id = [0u8; SESSION_ID_LEN];
        let key = derive_aes_key(&gks, &session_id).unwrap();
        let expected = "1185504272035c98351142cd7d80ab533de43b5b0bb2fffe8c4180e68ddbd4ce";
        assert_eq!(hex::encode(key), expected);
    }
}
