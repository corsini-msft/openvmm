// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! SP800-108 KBKDF implementation using Windows BCrypt.

use super::KdfError;

pub fn kbkdf_hmac_sha256(
    key: &[u8],
    context: &[u8],
    salt: &[u8],
    output_len: usize,
) -> Result<Vec<u8>, KdfError> {
    let l_bits = (output_len as u32 * 8).to_be_bytes();
    let mut output = Vec::with_capacity(output_len);
    let mut counter: u32 = 1;

    while output.len() < output_len {
        // Build PRF input: counter(4) || label || 0x00 || context || L(4)
        let mut prf_input = Vec::with_capacity(4 + salt.len() + 1 + context.len() + 4);
        prf_input.extend_from_slice(&counter.to_be_bytes());
        prf_input.extend_from_slice(salt);
        prf_input.push(0x00);
        prf_input.extend_from_slice(context);
        prf_input.extend_from_slice(&l_bits);

        let hmac_out = bcrypt_hmac_sha256(key, &prf_input)?;
        let needed = output_len - output.len();
        output.extend_from_slice(&hmac_out[..needed.min(32)]);
        counter += 1;
    }

    Ok(output)
}

/// Compute HMAC-SHA-256 using Windows BCrypt.
fn bcrypt_hmac_sha256(key: &[u8], data: &[u8]) -> Result<[u8; 32], KdfError> {
    use windows::Win32::Security::Cryptography::*;

    // SAFETY: BCrypt APIs are safe to call with valid parameters.
    unsafe {
        let mut h_alg = BCRYPT_ALG_HANDLE::default();
        let status = BCryptOpenAlgorithmProvider(
            &mut h_alg,
            BCRYPT_SHA256_ALGORITHM,
            None,
            BCRYPT_ALG_HANDLE_HMAC_FLAG,
        );
        if status.is_err() {
            return Err(KdfError(crate::BackendError(
                windows_result::Error::from(status),
                "BCryptOpenAlgorithmProvider for HMAC-SHA256",
            )));
        }

        let mut h_hash = BCRYPT_HASH_HANDLE::default();
        let status = BCryptCreateHash(h_alg, &mut h_hash, None, Some(key), 0);
        if status.is_err() {
            let _ = BCryptCloseAlgorithmProvider(h_alg, 0);
            return Err(KdfError(crate::BackendError(
                windows_result::Error::from(status),
                "BCryptCreateHash for HMAC-SHA256",
            )));
        }

        let status = BCryptHashData(h_hash, data, 0);
        if status.is_err() {
            let _ = BCryptDestroyHash(h_hash);
            let _ = BCryptCloseAlgorithmProvider(h_alg, 0);
            return Err(KdfError(crate::BackendError(
                windows_result::Error::from(status),
                "BCryptHashData for HMAC-SHA256",
            )));
        }

        let mut result = [0u8; 32];
        let status = BCryptFinishHash(h_hash, &mut result, 0);
        let _ = BCryptDestroyHash(h_hash);
        let _ = BCryptCloseAlgorithmProvider(h_alg, 0);
        if status.is_err() {
            return Err(KdfError(crate::BackendError(
                windows_result::Error::from(status),
                "BCryptFinishHash for HMAC-SHA256",
            )));
        }

        Ok(result)
    }
}
