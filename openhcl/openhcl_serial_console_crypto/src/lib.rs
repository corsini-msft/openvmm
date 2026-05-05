// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Wire format and cryptographic primitives for OpenHCL's encrypted
//! serial console output.
//!
//! VTL2/OpenHCL can emit encrypted records on its serial console once
//! it has access to a guest secret (specifically, the
//! `FileId::GUEST_SECRET_KEY` blob from the VMGS). This crate defines:
//!
//! * The text-safe **wire format** the producer emits and the
//!   decryptor consumes.
//! * The **AES-256-GCM key derivation** from the 2048-byte GKS, keyed
//!   per-session by a 16-byte `session_id` so the producer is free to
//!   use either random or counter nonces within a session without
//!   risking nonce reuse across reboots.
//!
//! This crate is intentionally small and dependency-light so that a
//! future producer-side PR (which lives inside OpenHCL VTL2) can
//! depend on it without inheriting CLI, filesystem, async, or VMGS
//! dependencies. The host-side decryptor CLI lives in the separate
//! `decrypt_serial` crate.

#![forbid(unsafe_code)]

pub mod consts;
pub mod format;
