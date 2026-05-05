// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Resolve the [`GksKeyMaterial`] from one of two CLI-supplied
//! sources: a pre-extracted GKS blob, or a plaintext VMGS file from
//! which we read `FileId::GUEST_SECRET_KEY` ourselves.

use anyhow::Context;
use anyhow::bail;
use disk_backend::Disk;
use disk_vhd1::Vhd1Disk;
use openhcl_attestation_protocol::vmgs::GUEST_SECRET_KEY_MAX_SIZE;
use openhcl_serial_console_crypto::crypto::GKS_LEN;
use openhcl_serial_console_crypto::crypto::GksKeyMaterial;
use std::path::Path;
use std::path::PathBuf;
use vmgs::Vmgs;
use vmgs_format::FileId;

// Belt-and-suspenders: keep the local constant in
// openhcl_serial_console_crypto in lockstep with the canonical
// definition in openhcl_attestation_protocol.
const _: () = assert!(GKS_LEN == GUEST_SECRET_KEY_MAX_SIZE);

/// Where the GKS bytes for decryption come from.
#[derive(Debug, Clone)]
pub enum KeySource {
    /// A file containing a raw, pre-extracted `GuestSecretKey` blob.
    /// Up to [`GKS_LEN`] bytes; shorter files are zero-padded to
    /// match the behavior of `underhill_attestation`'s
    /// `read_guest_secret_key`.
    Key(PathBuf),
    /// A plaintext VMGS file; the resolver will read
    /// `FileId::GUEST_SECRET_KEY` from it.
    Vmgs(PathBuf),
}

/// Resolve the [`KeySource`] into the 2048-byte GKS blob.
pub async fn resolve(source: &KeySource) -> anyhow::Result<GksKeyMaterial> {
    match source {
        KeySource::Key(p) => read_key_file(p),
        KeySource::Vmgs(p) => read_gks_from_vmgs_file(p).await,
    }
}

fn read_key_file(path: &Path) -> anyhow::Result<GksKeyMaterial> {
    tracing::info!(path = %path.display(), "reading GuestSecretKey blob from --key file");
    let bytes = fs_err::read(path).context("reading --key file")?;
    bytes_to_gks(&bytes, "--key file")
}

async fn read_gks_from_vmgs_file(path: &Path) -> anyhow::Result<GksKeyMaterial> {
    tracing::info!(path = %path.display(), "opening --vmgs file");
    let file = fs_err::OpenOptions::new()
        .read(true)
        .open(path)
        .context("opening --vmgs file")?;
    let disk = Disk::new(
        Vhd1Disk::open_fixed(file.into(), /* read_only */ true)
            .context("opening VMGS file as a VHD")?,
    )
    .context("constructing Disk from VMGS VHD")?;
    read_gks_from_disk(disk).await
}

async fn read_gks_from_disk(disk: Disk) -> anyhow::Result<GksKeyMaterial> {
    let mut vmgs = Vmgs::open(disk, None)
        .await
        .context("parsing VMGS structure")?;
    if vmgs.encrypted() {
        bail!(
            "VMGS file is encrypted; decrypt-serial does not support unlocking encrypted VMGS files. \
             Extract the GuestSecretKey via attestation (or another out-of-band path) and pass it with --key."
        );
    }
    let bytes = vmgs
        .read_file_raw(FileId::GUEST_SECRET_KEY)
        .await
        .context("reading FileId::GUEST_SECRET_KEY from the VMGS")?;
    bytes_to_gks(&bytes, "VMGS GUEST_SECRET_KEY entry")
}

fn bytes_to_gks(bytes: &[u8], source: &str) -> anyhow::Result<GksKeyMaterial> {
    if bytes.is_empty() {
        bail!(
            "{source} is empty; expected up to {GKS_LEN} bytes of GuestSecretKey material"
        );
    }
    if bytes.len() > GKS_LEN {
        bail!(
            "{source} is {} bytes long; the GuestSecretKey is at most {GKS_LEN} bytes",
            bytes.len()
        );
    }
    if bytes.len() < GKS_LEN {
        tracing::warn!(
            len = bytes.len(),
            expected = GKS_LEN,
            "{source} is shorter than the full GuestSecretKey; \
             zero-padding to {GKS_LEN} bytes (matches underhill_attestation behavior)"
        );
    }
    let mut material = [0u8; GKS_LEN];
    material[..bytes.len()].copy_from_slice(bytes);
    Ok(GksKeyMaterial(material))
}

#[cfg(test)]
mod tests {
    use super::*;
    use disklayer_ram::ram_disk;
    use pal_async::async_test;
    use vmgs::Vmgs;
    use zerocopy::IntoBytes;

    fn write_temp_key(bytes: &[u8]) -> tempfile::NamedTempFile {
        let f = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(f.path(), bytes).unwrap();
        f
    }

    #[test]
    fn key_file_full_length() {
        let key = vec![0xa5u8; GKS_LEN];
        let f = write_temp_key(&key);
        let gks = read_key_file(f.path()).unwrap();
        assert_eq!(gks.0.as_slice(), key.as_slice());
    }

    #[test]
    fn key_file_short_is_zero_padded() {
        let key = vec![0x42u8; 16];
        let f = write_temp_key(&key);
        let gks = read_key_file(f.path()).unwrap();
        assert_eq!(&gks.0[..16], key.as_slice());
        assert!(gks.0[16..].iter().all(|b| *b == 0));
    }

    #[test]
    fn key_file_empty_rejected() {
        let f = write_temp_key(&[]);
        let err = read_key_file(f.path()).unwrap_err();
        assert!(
            err.to_string().contains("empty"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn key_file_oversized_rejected() {
        let key = vec![0u8; GKS_LEN + 1];
        let f = write_temp_key(&key);
        let err = read_key_file(f.path()).unwrap_err();
        assert!(
            err.to_string().contains("at most"),
            "unexpected error: {err}"
        );
    }

    async fn make_vmgs_with_gks(secret: &[u8]) -> Disk {
        let disk = ram_disk(4 * 1024 * 1024, false).unwrap();
        let mut vmgs = Vmgs::format_new(disk.clone(), None).await.unwrap();
        let payload = openhcl_attestation_protocol::vmgs::GuestSecretKey {
            guest_secret_key: {
                let mut buf = [0u8; GUEST_SECRET_KEY_MAX_SIZE];
                buf[..secret.len()].copy_from_slice(secret);
                buf
            },
        };
        vmgs.write_file(FileId::GUEST_SECRET_KEY, payload.as_bytes())
            .await
            .unwrap();
        // Drop the in-memory Vmgs so the underlying disk can be re-opened.
        drop(vmgs);
        disk
    }

    #[async_test]
    async fn vmgs_path_round_trip() {
        let secret = vec![0xCDu8; GUEST_SECRET_KEY_MAX_SIZE];
        let disk = make_vmgs_with_gks(&secret).await;
        let gks = read_gks_from_disk(disk).await.unwrap();
        assert_eq!(gks.0.as_slice(), secret.as_slice());
    }

    #[async_test]
    async fn vmgs_path_short_secret_is_padded() {
        let secret = vec![0xEFu8; 32];
        let disk = make_vmgs_with_gks(&secret).await;
        let gks = read_gks_from_disk(disk).await.unwrap();
        // The producer (write_file with the full GuestSecretKey
        // struct above) already padded with zeros; verify the
        // resolver round-trips that.
        assert_eq!(&gks.0[..32], secret.as_slice());
        assert!(gks.0[32..].iter().all(|b| *b == 0));
    }

    #[async_test]
    async fn vmgs_path_missing_gks_errors() {
        let disk = ram_disk(4 * 1024 * 1024, false).unwrap();
        let _ = Vmgs::format_new(disk.clone(), None).await.unwrap();
        let err = read_gks_from_disk(disk).await.unwrap_err();
        // The vmgs crate returns a typed error when the file id is
        // unallocated; we just verify our context wrapper surfaces it
        // and does not panic.
        assert!(
            err.to_string()
                .contains("reading FileId::GUEST_SECRET_KEY from the VMGS"),
            "unexpected error: {err:#}"
        );
    }
}
