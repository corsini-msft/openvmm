// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Wire format and cryptographic primitives for OpenHCL's encrypted
//! serial console.
//!
//! VTL2/OpenHCL can emit and consume encrypted records on its serial
//! console once it has access to a guest secret (specifically, the
//! `FileId::GUEST_SECRET_KEY` blob from the VMGS). This crate defines:
//!
//! * The text-safe **wire format** producers emit and consumers parse.
//! * The **AES-256-GCM key derivation** from the 2048-byte GKS, keyed
//!   per-session by a 16-byte `session_id` so producers are free to
//!   use either random or counter nonces within a session without
//!   risking nonce reuse across reboots.
//!
//! This crate is intentionally small and dependency-light so that the
//! in-VM consumers and producers (the VTL2 `EncryptedSerialIo`
//! wrapper, the kmsg encrypter) can depend on it without inheriting
//! CLI, filesystem, async, or VMGS dependencies. The host-side CLI
//! that decrypts captures and bridges interactive serial sessions
//! lives in the separate `encrypted_serial_host` crate.
//!
//! The crate is currently Linux-only, matching the
//! `openhcl/underhill_attestation` pattern, because
//! `crypto::kdf::kbkdf_hmac_sha256` is implemented via the Unix-only
//! `openssl_kdf` crate in the workspace. Host-side tooling that
//! depends on this crate (notably `encrypted_serial_host`) is
//! therefore Linux-only too. Windows users can run the tool from
//! WSL2.

#![forbid(unsafe_code)]

pub mod consts;
pub mod crypto;
pub mod format;
pub mod stream;
