// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Developer-only helper to seed `FileId::GUEST_SECRET_KEY` in a
//! plaintext VMGS file with key material that the encrypted-serial
//! producer (in OpenHCL VTL2) and the `decrypt-serial` consumer can
//! share.
//!
//! ⚠ **Not a production provisioning tool.** Real GSK provisioning
//! happens through CPS / attestation flows. This subcommand exists
//! solely so a developer can stand up a working PoC without those
//! flows by writing GSK bytes directly into a plaintext VMGS file.
//!
//! The bytes written are interpreted as the raw KBKDF input by the
//! encrypted-serial consumer; they do **not** need to be (and by
//! default are not) a TPM2_Import-shaped duplicate blob. If the same
//! VMGS is also consumed by the vTPM at first boot, the import will
//! fail; that path is out of scope for the encrypted-serial PoC.

use anyhow::Context;
use anyhow::bail;
use disk_backend::Disk;
use disk_vhd1::Vhd1Disk;
use openhcl_attestation_protocol::vmgs::GUEST_SECRET_KEY_MAX_SIZE;
use openhcl_attestation_protocol::vmgs::GuestSecretKey;
use std::path::Path;
use vmgs::Vmgs;
use vmgs_format::FileId;
use zerocopy::IntoBytes;

/// Source of the GSK material to write.
#[derive(Debug, Clone)]
pub enum ProvisionSource {
    /// Generate `GUEST_SECRET_KEY_MAX_SIZE` bytes of random material
    /// using the OS RNG.
    Random,
    /// Read up to `GUEST_SECRET_KEY_MAX_SIZE` bytes verbatim from a
    /// file. Shorter inputs are zero-padded; longer inputs are an
    /// error.
    FromKey(std::path::PathBuf),
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
) -> anyhow::Result<()> {
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

    provision_on_disk(disk, &bytes, force).await
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
        ProvisionSource::Random => {
            getrandom::fill(&mut buf)
                .map_err(|e| anyhow::anyhow!("generating random GSK material: {e}"))?;
        }
        ProvisionSource::FromKey(p) => {
            let bytes = fs_err::read(p).context("reading --from-key file")?;
            if bytes.is_empty() {
                bail!("--from-key file is empty");
            }
            if bytes.len() > GUEST_SECRET_KEY_MAX_SIZE {
                bail!(
                    "--from-key file is {} bytes long; the GuestSecretKey is at most {GUEST_SECRET_KEY_MAX_SIZE} bytes",
                    bytes.len()
                );
            }
            buf[..bytes.len()].copy_from_slice(&bytes);
        }
    }
    Ok(buf)
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

    #[async_test]
    async fn provision_random_then_round_trip() {
        let disk = fresh_vmgs().await;
        let payload = build_payload(&ProvisionSource::Random).unwrap();
        provision_on_disk(disk.clone(), &payload, false)
            .await
            .unwrap();

        let gks = read_back(disk).await;
        assert_eq!(gks.0, payload, "round-trip mismatch");

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
    async fn build_payload_from_key_pads_short_input() {
        let key_file = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(key_file.path(), [0x42u8; 32]).unwrap();
        let payload =
            build_payload(&ProvisionSource::FromKey(key_file.path().to_path_buf())).unwrap();
        assert_eq!(&payload[..32], &[0x42u8; 32]);
        assert!(payload[32..].iter().all(|b| *b == 0));
    }

    #[async_test]
    async fn build_payload_rejects_empty_key_file() {
        let key_file = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(key_file.path(), b"").unwrap();
        let err =
            build_payload(&ProvisionSource::FromKey(key_file.path().to_path_buf())).unwrap_err();
        assert!(err.to_string().contains("empty"), "unexpected: {err:#}");
    }

    #[async_test]
    async fn build_payload_rejects_oversized_key_file() {
        let key_file = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(key_file.path(), [0u8; GUEST_SECRET_KEY_MAX_SIZE + 1]).unwrap();
        let err =
            build_payload(&ProvisionSource::FromKey(key_file.path().to_path_buf())).unwrap_err();
        assert!(err.to_string().contains("at most"), "unexpected: {err:#}");
    }

    #[async_test]
    async fn provision_refuses_overwrite_without_force() {
        let disk = fresh_vmgs().await;
        let payload = [0x33u8; GUEST_SECRET_KEY_MAX_SIZE];
        provision_on_disk(disk.clone(), &payload, false)
            .await
            .unwrap();
        let err = provision_on_disk(disk, &payload, false).await.unwrap_err();
        assert!(err.to_string().contains("--force"), "unexpected: {err:#}");
    }

    #[async_test]
    async fn provision_force_overwrites() {
        let disk = fresh_vmgs().await;
        let p1 = [0x11u8; GUEST_SECRET_KEY_MAX_SIZE];
        let mut p2 = [0u8; GUEST_SECRET_KEY_MAX_SIZE];
        p2[..16].copy_from_slice(&[0x22u8; 16]);
        provision_on_disk(disk.clone(), &p1, false).await.unwrap();
        provision_on_disk(disk.clone(), &p2, true).await.unwrap();

        let gks = read_back(disk).await;
        assert_eq!(&gks.0[..16], &[0x22u8; 16]);
    }
}
