// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Wire-format constants for the encrypted serial console.

use std::time::Duration;

/// Length in bytes of the random per-session identifier in each
/// record.
pub const SESSION_ID_LEN: usize = 16;

/// Length in bytes of the AES-256-GCM nonce in each record.
pub const NONCE_LEN: usize = 12;

/// Length in bytes of the AES-256-GCM authentication tag in each
/// record.
pub const TAG_LEN: usize = 16;

/// Length in bytes of the AES-256-GCM key derived from the GKS.
pub const AES_KEY_LEN: usize = 32;

/// Maximum plaintext (and therefore ciphertext) length in bytes for a
/// single record. Producers that wish to encrypt a longer logical
/// message MUST split it across multiple records.
///
/// The limit exists to bound how much memory the decryptor can be
/// asked to allocate while parsing a single sentinel.
pub const MAX_PLAINTEXT_LEN: usize = 4096;

/// Maximum length in bytes of the binary record payload (the bytes
/// produced by base64-decoding the contents of a sentinel).
///
/// `SESSION_ID_LEN + 8 (seq) + NONCE_LEN + MAX_PLAINTEXT_LEN +
/// TAG_LEN` = 4148. We round up modestly to leave room for any v1
/// header tweaks that fit inside this commitment.
pub const MAX_PAYLOAD_LEN: usize = 4200;

/// Minimum length in bytes of a valid binary record payload (a record
/// with a zero-length ciphertext).
pub const MIN_PAYLOAD_LEN: usize = SESSION_ID_LEN + 8 + NONCE_LEN + TAG_LEN;

/// Maximum length in bytes of the base64 contents of a sentinel.
/// Used to bound parser scans.
pub const MAX_SENTINEL_BASE64_LEN: usize = 6000;

/// Opening sentinel literal. Producers MUST emit exactly this byte
/// sequence (including the trailing space) at the start of every
/// record.
pub const SENTINEL_OPEN: &[u8] = b"[[OHENC v1 ";

/// Closing sentinel literal.
pub const SENTINEL_CLOSE: &[u8] = b"]]";

/// Domain-separation string included as a prefix of the AES-GCM AAD
/// for every record.
///
/// Including the protocol name, version, and cipher in the AAD makes
/// it impossible for a record from this protocol to be confused with
/// a record from any future variant that uses a different label or
/// algorithm, even if the two share key material.
pub const AAD_DOMAIN: &[u8] = b"OpenHCL encrypted serial console v1 AES-256-GCM\0";

/// Context label for the SP800-108 KBKDF derivation that turns the
/// 2048-byte GKS into a per-session AES-256-GCM key.
pub const KDF_LABEL: &[u8] = b"OpenHCL encrypted serial console v1 AES-256-GCM key";

/// Soft size threshold for producer flushes.
///
/// When the encrypting wrapper's pending plaintext reaches this size
/// it encrypts and emits a record immediately, without waiting for
/// the idle timer. 256 bytes amortises the per-record framing
/// overhead (~100 bytes for nonce + tag + base64 + sentinel) while
/// keeping records small enough to ship promptly under interactive
/// load. Mirrors typical TLS record sizing.
pub const PRODUCER_SOFT_FLUSH_BYTES: usize = 256;

/// Idle flush timeout for the producer.
///
/// If no new bytes arrive for this duration after the buffer became
/// non-empty, any pending plaintext is flushed. 50 ms is below human
/// perception, well above scheduler granularity, and matches the
/// output-coalescing intervals used by tmux/screen and the GDB
/// remote serial protocol. Bounds the worst-case latency between a
/// producer write and the corresponding wire record.
pub const PRODUCER_IDLE_FLUSH: Duration = Duration::from_millis(50);
