// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! AES-256-GCM encryption and decryption.

#![cfg(any(openssl, symcrypt, all(native, windows)))]

#[cfg(openssl)]
mod ossl;
#[cfg(openssl)]
use ossl as sys;

#[cfg(all(native, windows))]
mod win;
#[cfg(all(native, windows))]
use win as sys;

#[cfg(symcrypt)]
mod symcrypt;
#[cfg(symcrypt)]
use symcrypt as sys;

use thiserror::Error;

/// The required key length for the algorithm.
///
/// An AES-256-GCM key is 256 bits.
pub const KEY_LEN: usize = 32;

/// The required IV length for the algorithm.
///
/// An AES-256-GCM IV is 96 bits (12 bytes).
pub const IV_LEN: usize = 12;

/// AES-256-GCM encryption/decryption.
pub struct Aes256Gcm(sys::Aes256GcmInner);

/// An error for AES-256-GCM cryptographic operations.
#[derive(Clone, Debug, Error)]
#[error("AES-256-GCM error")]
pub struct Aes256GcmError(#[source] super::BackendError);

impl Aes256Gcm {
    /// Creates a new AES-256-GCM encryption/decryption context.
    pub fn new(key: &[u8; KEY_LEN]) -> Result<Self, Aes256GcmError> {
        sys::Aes256GcmInner::new(key).map(Self)
    }

    /// Returns a context for encrypting data.
    pub fn encrypt(&self) -> Result<Aes256GcmEncCtx<'_>, Aes256GcmError> {
        Ok(Aes256GcmEncCtx(self.0.enc_ctx()?))
    }

    /// Returns a context for decrypting data.
    pub fn decrypt(&self) -> Result<Aes256GcmDecCtx<'_>, Aes256GcmError> {
        Ok(Aes256GcmDecCtx(self.0.dec_ctx()?))
    }
}

/// Context for AES-256-GCM encryption.
pub struct Aes256GcmEncCtx<'a>(sys::Aes256GcmEncCtxInner<'a>);

impl Aes256GcmEncCtx<'_> {
    /// Encrypts `data` using the provided `iv` and produces the
    /// authentication tag in `tag`. Equivalent to
    /// [`Self::cipher_with_aad`] with an empty AAD.
    pub fn cipher(
        &mut self,
        iv: &[u8; IV_LEN],
        data: &[u8],
        tag: &mut [u8],
    ) -> Result<Vec<u8>, Aes256GcmError> {
        self.cipher_with_aad(iv, &[], data, tag)
    }

    /// Encrypts `data` using the provided `iv` and `aad` (additional
    /// authenticated data). The AAD is bound to the produced
    /// authentication tag in `tag` but is not encrypted; the
    /// decryptor must supply identical AAD bytes or the tag check
    /// will fail.
    pub fn cipher_with_aad(
        &mut self,
        iv: &[u8; IV_LEN],
        aad: &[u8],
        data: &[u8],
        tag: &mut [u8],
    ) -> Result<Vec<u8>, Aes256GcmError> {
        self.0.cipher(iv, aad, data, tag)
    }
}

/// Context for AES-256-GCM decryption.
pub struct Aes256GcmDecCtx<'a>(sys::Aes256GcmDecCtxInner<'a>);

impl Aes256GcmDecCtx<'_> {
    /// Decrypts `data` using the provided `iv` and verifies the
    /// authentication `tag`. Equivalent to
    /// [`Self::cipher_with_aad`] with an empty AAD.
    pub fn cipher(
        &mut self,
        iv: &[u8; IV_LEN],
        data: &[u8],
        tag: &[u8],
    ) -> Result<Vec<u8>, Aes256GcmError> {
        self.cipher_with_aad(iv, &[], data, tag)
    }

    /// Decrypts `data` using the provided `iv` and verifies the
    /// authentication `tag` against the supplied `aad` plus `data`.
    /// `aad` must be byte-for-byte identical to what the encryptor
    /// supplied or the tag check fails.
    pub fn cipher_with_aad(
        &mut self,
        iv: &[u8; IV_LEN],
        aad: &[u8],
        data: &[u8],
        tag: &[u8],
    ) -> Result<Vec<u8>, Aes256GcmError> {
        self.0.cipher(iv, aad, data, tag)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aes_256_gcm() {
        // Test Case 14 from the NIST GCM specification (gcm-spec.pdf).
        let key = hex::decode("feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308")
            .unwrap();
        let iv = hex::decode("cafebabefacedbaddecaf888")
            .unwrap()
            .try_into()
            .unwrap();
        let plain = hex::decode(
            "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72\
             1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255",
        )
        .unwrap();
        let cipher = hex::decode(
            "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa\
             8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662898015ad",
        )
        .unwrap();
        let tag = hex::decode("b094dac5d93471bdec1a502270e3cc6c").unwrap();

        let aes = Aes256Gcm::new(&key.try_into().unwrap()).unwrap();
        let mut enc_ctx = aes.encrypt().unwrap();
        let mut enc_tag = vec![0u8; tag.len()];
        let enc_cipher = enc_ctx.cipher(&iv, &plain, &mut enc_tag).unwrap();
        assert_eq!(enc_cipher, cipher);
        assert_eq!(enc_tag, tag);

        let mut dec_ctx = aes.decrypt().unwrap();
        let dec_plain = dec_ctx.cipher(&iv, &cipher, &tag).unwrap();
        assert_eq!(dec_plain, plain);
    }

    #[test]
    fn test_aes_256_gcm_with_aad() {
        let key = [0x42u8; KEY_LEN];
        let iv = [0x55u8; IV_LEN];
        let aad = b"some authenticated header bytes";
        let plain = b"the secret payload";

        let aes = Aes256Gcm::new(&key).unwrap();
        let mut enc_ctx = aes.encrypt().unwrap();
        let mut tag = vec![0u8; 16];
        let cipher = enc_ctx.cipher_with_aad(&iv, aad, plain, &mut tag).unwrap();

        // Decrypt with the same AAD succeeds.
        let mut dec_ctx = aes.decrypt().unwrap();
        let decrypted = dec_ctx.cipher_with_aad(&iv, aad, &cipher, &tag).unwrap();
        assert_eq!(decrypted, plain);

        // Decrypt with mismatched AAD fails the tag check.
        let mut dec_ctx = aes.decrypt().unwrap();
        let result = dec_ctx.cipher_with_aad(&iv, b"different aad", &cipher, &tag);
        assert!(result.is_err(), "decrypt with wrong AAD must fail");

        // Decrypt with empty AAD when encryption used non-empty AAD
        // also fails.
        let mut dec_ctx = aes.decrypt().unwrap();
        let result = dec_ctx.cipher_with_aad(&iv, &[], &cipher, &tag);
        assert!(result.is_err(), "decrypt with empty AAD must fail");
    }
}
