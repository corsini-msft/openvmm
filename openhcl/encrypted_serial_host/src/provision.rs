// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Developer-only helper to seed `FileId::GUEST_SECRET_KEY` in a
//! plaintext VMGS file with a TPM2_Import-shaped duplicate blob that
//! the encrypted-serial producer (in OpenHCL VTL2) and the
//! `encrypted-serial` consumer can share.
//!
//! ⚠ **Not a production provisioning tool.** Real GSK provisioning
//! happens through CPS / attestation flows. This subcommand exists
//! solely so a developer can stand up a working PoC without those
//! flows by writing a developer-supplied importable blob directly
//! into a plaintext VMGS file.
//!
//! The bytes written must parse via
//! `tpm_protocol::tpm20proto::ImportCmd::deserialize_no_wrapping_key`
//! — i.e. they must form a valid TPM2_Import duplicate blob with no
//! inner wrapping key. The vTPM consumes this format at first boot;
//! the encrypted-serial KBKDF then runs over the same VMGS-stored
//! bytes, so both consumers see identical key material.
//!
//! For unit testing without a real TPM blob generator, see the
//! 422-byte `GUEST_SECRET_KEY_BLOB` fixture in
//! `vm/devices/tpm/tpm_lib/src/lib.rs::tests`.

use anyhow::Context;
use anyhow::bail;
use disk_backend::Disk;
use disk_vhd1::Vhd1Disk;
use openhcl_attestation_protocol::vmgs::GUEST_SECRET_KEY_MAX_SIZE;
use openhcl_attestation_protocol::vmgs::GuestSecretKey;
use std::path::Path;
use tpm_protocol::tpm20proto::protocol::ImportCmd;
use vmgs::Vmgs;
use vmgs_format::FileId;
use zerocopy::IntoBytes;

/// Source of the GSK material to write.
#[derive(Debug, Clone)]
pub enum ProvisionSource {
    /// Read up to `GUEST_SECRET_KEY_MAX_SIZE` bytes from a file
    /// containing a TPM2_Import duplicate blob (no inner wrapping
    /// key). The file is validated by `ImportCmd::
    /// deserialize_no_wrapping_key` before being written.
    FromBlob(std::path::PathBuf),
    /// Generate a fresh RSA-2048 keypair and format it as a
    /// TPM2_Import duplicate blob.
    Generate,
}

/// Open `vmgs_path` as a plaintext VHD-formatted VMGS, write GSK
/// material into `FileId::GUEST_SECRET_KEY`, and persist.
///
/// Refuses to operate on encrypted VMGS files. If the slot is already
/// populated, `force` must be `true` to overwrite.
pub async fn provision(
    vmgs_path: &Path,
    source: ProvisionSource,
    force: bool,
) -> anyhow::Result<Vec<u8>> {
    let bytes = build_payload(&source)?;

    tracing::info!(path = %vmgs_path.display(), "opening VMGS for read-write");
    let file = fs_err::OpenOptions::new()
        .read(true)
        .write(true)
        .open(vmgs_path)
        .context("opening VMGS file for read-write")?;
    let disk = Disk::new(
        Vhd1Disk::open_fixed(file.into(), /* read_only */ false)
            .context("opening VMGS file as a VHD")?,
    )
    .context("constructing Disk from VMGS VHD")?;

    provision_on_disk(disk, &bytes, force).await?;
    Ok(bytes.to_vec())
}

/// Provision a GSK payload into an already-opened `Disk`. Exposed
/// for tests that drive a ram-backed disk; CLI users go through
/// [`provision`].
pub(crate) async fn provision_on_disk(
    disk: Disk,
    bytes: &[u8; GUEST_SECRET_KEY_MAX_SIZE],
    force: bool,
) -> anyhow::Result<()> {
    let mut vmgs = Vmgs::open(disk, None)
        .await
        .context("parsing VMGS structure")?;
    if vmgs.encrypted() {
        bail!(
            "VMGS file is encrypted; provisioning into an encrypted VMGS is not supported by this tool. \
             Use a plaintext VMGS produced for development testing."
        );
    }

    if !force && vmgs.read_file_raw(FileId::GUEST_SECRET_KEY).await.is_ok() {
        bail!("FileId::GUEST_SECRET_KEY is already present; pass --force to overwrite");
    }

    let payload = GuestSecretKey {
        guest_secret_key: *bytes,
    };
    vmgs.write_file(FileId::GUEST_SECRET_KEY, payload.as_bytes())
        .await
        .context("writing FileId::GUEST_SECRET_KEY to VMGS")?;

    tracing::info!(
        len = GUEST_SECRET_KEY_MAX_SIZE,
        "wrote GUEST_SECRET_KEY to VMGS"
    );
    Ok(())
}

pub(crate) fn build_payload(
    source: &ProvisionSource,
) -> anyhow::Result<[u8; GUEST_SECRET_KEY_MAX_SIZE]> {
    let mut buf = [0u8; GUEST_SECRET_KEY_MAX_SIZE];
    match source {
        ProvisionSource::FromBlob(p) => {
            let bytes = fs_err::read(p).context("reading --from-blob file")?;
            if bytes.is_empty() {
                bail!("--from-blob file is empty");
            }
            if bytes.len() > GUEST_SECRET_KEY_MAX_SIZE {
                bail!(
                    "--from-blob file is {} bytes long; the GuestSecretKey slot is at most {GUEST_SECRET_KEY_MAX_SIZE} bytes",
                    bytes.len()
                );
            }
            validate_importable_blob(&bytes).context("validating --from-blob")?;
            buf[..bytes.len()].copy_from_slice(&bytes);
        }
        ProvisionSource::Generate => {
            let blob = generate_tpm_import_blob().context("generating TPM import blob")?;
            if blob.len() > GUEST_SECRET_KEY_MAX_SIZE {
                bail!(
                    "generated blob is {} bytes; max is {GUEST_SECRET_KEY_MAX_SIZE}",
                    blob.len()
                );
            }
            validate_importable_blob(&blob).context("validating generated blob")?;
            buf[..blob.len()].copy_from_slice(&blob);
            tracing::info!(len = blob.len(), "generated fresh RSA-2048 TPM import blob");
        }
    }
    Ok(buf)
}

/// Verify that `bytes` parses as a TPM2_Import duplicate blob with
/// no inner wrapping key. Mirrors the consumer-side parse done by
/// `tpm_lib::TpmEngineHelper::initialize_guest_secret_key`.
pub(crate) fn validate_importable_blob(bytes: &[u8]) -> anyhow::Result<()> {
    // The consumer pads short slots with zeros to
    // `GUEST_SECRET_KEY_MAX_SIZE` before parsing; mirror that here so
    // we accept the same shapes the vTPM will.
    let mut padded = vec![0u8; GUEST_SECRET_KEY_MAX_SIZE];
    padded[..bytes.len()].copy_from_slice(bytes);
    if ImportCmd::deserialize_no_wrapping_key(&padded).is_none() {
        bail!(
            "blob is not a valid TPM2_Import duplicate (no-inner-wrapping-key) structure; \
             expected concatenated TPM2B_PUBLIC || TPM2B_PRIVATE || TPM2B_ENCRYPTED_SECRET"
        );
    }
    Ok(())
}

/// Generate a fresh RSA-2048 keypair and serialize it as a TPM2_Import
/// duplicate blob (no inner wrapping key) matching the format expected
/// by `ImportCmd::deserialize_no_wrapping_key`.
fn generate_tpm_import_blob() -> anyhow::Result<Vec<u8>> {
    use tpm_protocol::tpm20proto::AlgIdEnum;
    use tpm_protocol::tpm20proto::TpmaObjectBits;
    use tpm_protocol::tpm20proto::protocol::Tpm2bPublic;
    use tpm_protocol::tpm20proto::protocol::TpmsRsaParams;
    use tpm_protocol::tpm20proto::protocol::TpmtPublic;
    use tpm_protocol::tpm20proto::protocol::TpmtRsaScheme;
    use tpm_protocol::tpm20proto::protocol::TpmtSymDefObject;
    use zerocopy::FromZeros as _;

    let rsa = openssl::rsa::Rsa::generate(2048).context("RSA-2048 keygen failed")?;

    let modulus = rsa.n().to_vec();
    let prime_p = rsa.p().context("private key missing prime p")?.to_vec();

    // Build TpmtPublic (RSA, SHA-256, sign+encrypt)
    let symmetric = TpmtSymDefObject::new(AlgIdEnum::NULL.into(), None, None);
    let scheme = TpmtRsaScheme::new(AlgIdEnum::RSASSA.into(), Some(AlgIdEnum::SHA256.into()));
    let rsa_params = TpmsRsaParams::new(symmetric, scheme, 2048, 0);

    let object_attributes = TpmaObjectBits::new()
        .with_user_with_auth(true)
        .with_sign_encrypt(true);

    let mut unique = [0u8; 256];
    let n = modulus.len().min(256);
    unique[..n].copy_from_slice(&modulus[..n]);

    let rsa_public = TpmtPublic::new(
        AlgIdEnum::RSA.into(),
        AlgIdEnum::SHA256.into(),
        object_attributes,
        &[],
        rsa_params,
        &unique,
    )
    .map_err(|e| anyhow::anyhow!("failed to build TpmtPublic: {e:?}"))?;

    let object_public = Tpm2bPublic::new(rsa_public);

    // Helper: compact TPM2B serialization (u16 size + data only).
    fn tpm2b_compact(data: &[u8]) -> Vec<u8> {
        let mut buf = Vec::with_capacity(2 + data.len());
        buf.extend_from_slice(&(data.len() as u16).to_be_bytes());
        buf.extend_from_slice(data);
        buf
    }

    // TpmtSensitive: type(u16) + authValue(TPM2B) + seedValue(TPM2B)
    // + sensitive(TPM2B with prime P)
    let mut sensitive_bytes = Vec::new();
    sensitive_bytes.extend_from_slice(&(AlgIdEnum::RSA as u16).to_be_bytes());
    sensitive_bytes.extend_from_slice(&tpm2b_compact(&[])); // authValue
    sensitive_bytes.extend_from_slice(&tpm2b_compact(&[])); // seedValue
    sensitive_bytes.extend_from_slice(&tpm2b_compact(&prime_p));

    let duplicate_bytes = tpm2b_compact(&sensitive_bytes);
    let in_sym_seed_bytes = tpm2b_compact(&[]);

    // TPM2B_PUBLIC || TPM2B_PRIVATE || TPM2B_ENCRYPTED_SECRET
    let mut blob = Vec::new();
    blob.extend_from_slice(&object_public.serialize());
    blob.extend_from_slice(&duplicate_bytes);
    blob.extend_from_slice(&in_sym_seed_bytes);

    Ok(blob)
}

#[cfg(test)]
mod tests {
    use super::*;
    use disklayer_ram::ram_disk;
    use openhcl_serial_console_crypto::consts::NONCE_LEN;
    use openhcl_serial_console_crypto::consts::SESSION_ID_LEN;
    use openhcl_serial_console_crypto::crypto::GksKeyMaterial;
    use openhcl_serial_console_crypto::crypto::decrypt;
    use openhcl_serial_console_crypto::crypto::derive_aes_key;
    use openhcl_serial_console_crypto::crypto::encrypt;
    use pal_async::async_test;
    use zerocopy::FromBytes;

    /// A known-good 422-byte TPM2_Import duplicate blob (no inner
    /// wrapping key). See `test_data/README.md`.
    const VALID_BLOB: &[u8] = include_bytes!("../test_data/tpm_import_blob.bin");

    /// Format a fresh ram-backed VMGS and return the disk.
    async fn fresh_vmgs() -> Disk {
        let disk = ram_disk(4 * 1024 * 1024, false).unwrap();
        let _ = Vmgs::format_new(disk.clone(), None).await.unwrap();
        disk
    }

    /// Read the GSK slot back as `GksKeyMaterial` (matches the
    /// consumer path in `key_source::resolve`).
    async fn read_back(disk: Disk) -> GksKeyMaterial {
        let mut vmgs = Vmgs::open(disk, None).await.unwrap();
        let bytes = vmgs.read_file_raw(FileId::GUEST_SECRET_KEY).await.unwrap();
        let payload = GuestSecretKey::read_from_bytes(bytes.as_slice()).unwrap();
        GksKeyMaterial(payload.guest_secret_key)
    }

    fn write_temp(bytes: &[u8]) -> tempfile::NamedTempFile {
        let f = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(f.path(), bytes).unwrap();
        f
    }

    #[test]
    fn validate_accepts_known_good_blob() {
        validate_importable_blob(VALID_BLOB).unwrap();
    }

    #[test]
    fn validate_rejects_random_bytes() {
        // 422 random-looking bytes should fail to parse as a
        // TPM2_Import structure.
        let bogus: Vec<u8> = (0..422u32).map(|i| (i & 0xff) as u8).collect();
        let err = validate_importable_blob(&bogus).unwrap_err();
        assert!(
            err.to_string().contains("TPM2_Import"),
            "unexpected: {err:#}"
        );
    }

    #[test]
    fn build_payload_from_blob_pads_to_max() {
        let f = write_temp(VALID_BLOB);
        let payload = build_payload(&ProvisionSource::FromBlob(f.path().to_path_buf())).unwrap();
        assert_eq!(&payload[..VALID_BLOB.len()], VALID_BLOB);
        assert!(
            payload[VALID_BLOB.len()..].iter().all(|b| *b == 0),
            "expected trailing zero padding"
        );
    }

    #[test]
    fn build_payload_rejects_empty_blob_file() {
        let f = write_temp(b"");
        let err = build_payload(&ProvisionSource::FromBlob(f.path().to_path_buf())).unwrap_err();
        assert!(err.to_string().contains("empty"), "unexpected: {err:#}");
    }

    #[test]
    fn build_payload_rejects_oversized_blob_file() {
        let f = write_temp(&vec![0u8; GUEST_SECRET_KEY_MAX_SIZE + 1]);
        let err = build_payload(&ProvisionSource::FromBlob(f.path().to_path_buf())).unwrap_err();
        assert!(err.to_string().contains("at most"), "unexpected: {err:#}");
    }

    #[test]
    fn build_payload_rejects_bogus_blob_file() {
        let f = write_temp(&[0xAAu8; 64]);
        let err = build_payload(&ProvisionSource::FromBlob(f.path().to_path_buf())).unwrap_err();
        assert!(
            err.to_string().contains("validating --from-blob"),
            "unexpected: {err:#}"
        );
    }

    #[async_test]
    async fn provision_from_blob_then_round_trip() {
        let disk = fresh_vmgs().await;
        let f = write_temp(VALID_BLOB);
        let payload = build_payload(&ProvisionSource::FromBlob(f.path().to_path_buf())).unwrap();
        provision_on_disk(disk.clone(), &payload, false)
            .await
            .unwrap();

        let gks = read_back(disk).await;
        assert_eq!(gks.0, payload, "round-trip mismatch");

        // The same VMGS bytes should serve both consumers: vTPM
        // (via ImportCmd) and encrypted serial (via KBKDF).
        validate_importable_blob(&gks.0[..VALID_BLOB.len()]).unwrap();

        // Encrypt/decrypt round-trip with the derived key.
        let session_id = [7u8; SESSION_ID_LEN];
        let aes_key = derive_aes_key(&gks, &session_id).unwrap();
        let nonce = [0u8; NONCE_LEN];
        let plaintext = b"hello provision-gsk";
        let (ciphertext, tag) = encrypt(&aes_key, &session_id, 0, &nonce, plaintext).unwrap();
        let recovered = decrypt(&aes_key, &session_id, 0, &nonce, &ciphertext, &tag).unwrap();
        assert_eq!(recovered, plaintext);
    }

    #[async_test]
    async fn provision_refuses_overwrite_without_force() {
        let disk = fresh_vmgs().await;
        let mut payload = [0u8; GUEST_SECRET_KEY_MAX_SIZE];
        payload[..VALID_BLOB.len()].copy_from_slice(VALID_BLOB);
        provision_on_disk(disk.clone(), &payload, false)
            .await
            .unwrap();
        let err = provision_on_disk(disk, &payload, false).await.unwrap_err();
        assert!(err.to_string().contains("--force"), "unexpected: {err:#}");
    }

    #[async_test]
    async fn provision_force_overwrites() {
        let disk = fresh_vmgs().await;
        let mut p1 = [0u8; GUEST_SECRET_KEY_MAX_SIZE];
        p1[..VALID_BLOB.len()].copy_from_slice(VALID_BLOB);
        // Second payload: same valid blob with the high byte of the
        // first field flipped is invalid TPM, but provisioning
        // (writing) accepts arbitrary bytes; only `build_payload`
        // validates. Use the same valid blob with a sentinel suffix
        // to verify overwrite happens.
        let mut p2 = p1;
        p2[VALID_BLOB.len()] = 0xCC;
        provision_on_disk(disk.clone(), &p1, false).await.unwrap();
        provision_on_disk(disk.clone(), &p2, true).await.unwrap();

        let gks = read_back(disk).await;
        assert_eq!(gks.0[VALID_BLOB.len()], 0xCC);
    }
}
