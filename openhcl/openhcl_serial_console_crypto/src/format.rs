// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Wire format v1: `[[OHENC v1 <base64-payload>]]`.
//!
//! Records are wrapped in printable ASCII so that they survive a
//! text-mode serial transport and can be interleaved with plaintext
//! lines on the same console without binary corruption. The decoded
//! payload is the binary record:
//!
//! | Offset | Size | Field          |
//! | -----: | ---: | -------------- |
//! |      0 |   16 | `session_id`   |
//! |     16 |    8 | `seq` (u64 LE) |
//! |     24 |   12 | `nonce`        |
//! |     36 |    N | `ciphertext`   |
//! | 36 + N |   16 | `tag`          |
//!
//! The AAD bound to each record is
//! [`crate::consts::AAD_DOMAIN`] || `session_id` || `seq` (u64 LE).

use crate::consts::AAD_DOMAIN;
use crate::consts::MAX_PAYLOAD_LEN;
use crate::consts::MAX_PLAINTEXT_LEN;
use crate::consts::MAX_SENTINEL_BASE64_LEN;
use crate::consts::MIN_PAYLOAD_LEN;
use crate::consts::NONCE_LEN;
use crate::consts::SESSION_ID_LEN;
use crate::consts::SENTINEL_CLOSE;
use crate::consts::SENTINEL_OPEN;
use crate::consts::TAG_LEN;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use thiserror::Error;

const SEQ_OFFSET: usize = SESSION_ID_LEN;
const NONCE_OFFSET: usize = SEQ_OFFSET + 8;
const CIPHERTEXT_OFFSET: usize = NONCE_OFFSET + NONCE_LEN;

/// A single encrypted serial console record.
///
/// Construct one of these with the encryption helpers in this crate's
/// crypto module, or parse one from the wire with
/// [`Record::parse_payload`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Record {
    /// Random 16-byte identifier the producer generated at the start
    /// of its current session. The decryptor uses this to derive the
    /// AES-256-GCM key (per session, not per record).
    pub session_id: [u8; SESSION_ID_LEN],
    /// Producer-assigned monotonic sequence number within
    /// `session_id`. Authenticated as part of the AAD.
    pub seq: u64,
    /// 96-bit AES-256-GCM nonce. Producer guarantees uniqueness
    /// within `session_id`.
    pub nonce: [u8; NONCE_LEN],
    /// Encrypted payload. Bounded above by
    /// [`crate::consts::MAX_PLAINTEXT_LEN`].
    pub ciphertext: Vec<u8>,
    /// AES-256-GCM authentication tag.
    pub tag: [u8; TAG_LEN],
}

impl Record {
    /// Encode this record as a `[[OHENC v1 ...]]` sentinel string.
    ///
    /// Panics in debug builds (only) if the ciphertext would push the
    /// total payload over [`crate::consts::MAX_PAYLOAD_LEN`]. The
    /// asserts protect producer correctness; they do not run on
    /// untrusted input.
    pub fn encode_to_string(&self) -> String {
        let payload = self.encode_payload();
        debug_assert!(payload.len() <= MAX_PAYLOAD_LEN);
        let mut out = String::with_capacity(
            SENTINEL_OPEN.len() + (payload.len() * 4 / 3 + 4) + SENTINEL_CLOSE.len(),
        );
        out.push_str(std::str::from_utf8(SENTINEL_OPEN).expect("ASCII"));
        BASE64.encode_string(&payload, &mut out);
        out.push_str(std::str::from_utf8(SENTINEL_CLOSE).expect("ASCII"));
        out
    }

    /// Serialize the binary record payload (the bytes that go inside
    /// the sentinel before base64-encoding).
    pub fn encode_payload(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(
            SESSION_ID_LEN + 8 + NONCE_LEN + self.ciphertext.len() + TAG_LEN,
        );
        out.extend_from_slice(&self.session_id);
        out.extend_from_slice(&self.seq.to_le_bytes());
        out.extend_from_slice(&self.nonce);
        out.extend_from_slice(&self.ciphertext);
        out.extend_from_slice(&self.tag);
        out
    }

    /// Parse a binary record payload (post-base64-decode).
    pub fn parse_payload(bytes: &[u8]) -> Result<Self, ParseError> {
        if bytes.len() < MIN_PAYLOAD_LEN {
            return Err(ParseError::PayloadTooShort {
                len: bytes.len(),
                min: MIN_PAYLOAD_LEN,
            });
        }
        if bytes.len() > MAX_PAYLOAD_LEN {
            return Err(ParseError::PayloadTooLong {
                len: bytes.len(),
                max: MAX_PAYLOAD_LEN,
            });
        }

        let session_id: [u8; SESSION_ID_LEN] = bytes[..SESSION_ID_LEN]
            .try_into()
            .expect("range checked above");
        let seq = u64::from_le_bytes(
            bytes[SEQ_OFFSET..NONCE_OFFSET]
                .try_into()
                .expect("range checked above"),
        );
        let nonce: [u8; NONCE_LEN] = bytes[NONCE_OFFSET..CIPHERTEXT_OFFSET]
            .try_into()
            .expect("range checked above");

        let tag_offset = bytes.len() - TAG_LEN;
        let ciphertext = bytes[CIPHERTEXT_OFFSET..tag_offset].to_vec();
        let tag: [u8; TAG_LEN] = bytes[tag_offset..]
            .try_into()
            .expect("range checked above");

        if ciphertext.len() > MAX_PLAINTEXT_LEN {
            return Err(ParseError::CiphertextTooLong {
                len: ciphertext.len(),
                max: MAX_PLAINTEXT_LEN,
            });
        }

        Ok(Self {
            session_id,
            seq,
            nonce,
            ciphertext,
            tag,
        })
    }

    /// Construct the AAD bytes for this record. See module docs.
    pub fn aad(&self) -> Vec<u8> {
        build_aad(&self.session_id, self.seq)
    }
}

/// Construct the AAD bytes for a record with the given `session_id`
/// and `seq`. Exposed separately so that the encrypt path does not
/// need to materialize a full [`Record`] before encrypting.
pub fn build_aad(session_id: &[u8; SESSION_ID_LEN], seq: u64) -> Vec<u8> {
    let mut aad = Vec::with_capacity(AAD_DOMAIN.len() + SESSION_ID_LEN + 8);
    aad.extend_from_slice(AAD_DOMAIN);
    aad.extend_from_slice(session_id);
    aad.extend_from_slice(&seq.to_le_bytes());
    aad
}

/// Result of trying to extract one sentinel from a byte stream
/// starting at a given position.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SentinelMatch {
    /// A complete, well-formed sentinel was found.
    ///
    /// Callers should pass `payload` to [`Record::parse_payload`].
    Found {
        /// Byte offset into the input buffer of the first `[` of the
        /// opening sentinel.
        start: usize,
        /// Byte offset into the input buffer just past the last `]`
        /// of the closing sentinel.
        end: usize,
        /// The base64-decoded binary record bytes.
        payload: Vec<u8>,
    },
    /// A `[[OHENC v1 ` opener was found but the record could not be
    /// extracted (no closing `]]` within the size limit, base64
    /// decode failed, or the contents were too large).
    ///
    /// In strict mode this should be treated as fatal; in lenient
    /// mode the caller should pass the bytes through as plaintext
    /// and resume scanning after `start`.
    Malformed {
        /// Byte offset into the input buffer of the first `[` of the
        /// opening sentinel that triggered this match.
        start: usize,
        /// Why the candidate sentinel could not be extracted.
        reason: SentinelError,
    },
    /// No opener was found anywhere in the remaining input.
    NotFound,
}

/// Find the next `[[OHENC v1 ...]]` sentinel in `input` at or after
/// `from`. See [`SentinelMatch`] for possible outcomes.
pub fn find_next_sentinel(input: &[u8], from: usize) -> SentinelMatch {
    let from = from.min(input.len());
    let Some(rel_start) = input[from..]
        .windows(SENTINEL_OPEN.len())
        .position(|w| w == SENTINEL_OPEN)
    else {
        return SentinelMatch::NotFound;
    };
    let start = from + rel_start;
    let body_start = start + SENTINEL_OPEN.len();

    // Bound the scan for the closing sentinel.
    let max_close_search_end = body_start
        .saturating_add(MAX_SENTINEL_BASE64_LEN)
        .saturating_add(SENTINEL_CLOSE.len())
        .min(input.len());
    let search_slice = &input[body_start..max_close_search_end];
    let Some(rel_close) = search_slice
        .windows(SENTINEL_CLOSE.len())
        .position(|w| w == SENTINEL_CLOSE)
    else {
        return SentinelMatch::Malformed {
            start,
            reason: SentinelError::Unterminated,
        };
    };
    let body_end = body_start + rel_close;
    let end = body_end + SENTINEL_CLOSE.len();
    let body = &input[body_start..body_end];

    if body.len() > MAX_SENTINEL_BASE64_LEN {
        return SentinelMatch::Malformed {
            start,
            reason: SentinelError::TooLong {
                len: body.len(),
                max: MAX_SENTINEL_BASE64_LEN,
            },
        };
    }

    match BASE64.decode(body) {
        Ok(payload) => {
            if payload.len() > MAX_PAYLOAD_LEN {
                SentinelMatch::Malformed {
                    start,
                    reason: SentinelError::PayloadTooLong {
                        len: payload.len(),
                        max: MAX_PAYLOAD_LEN,
                    },
                }
            } else {
                SentinelMatch::Found {
                    start,
                    end,
                    payload,
                }
            }
        }
        Err(err) => SentinelMatch::Malformed {
            start,
            reason: SentinelError::Base64(err.to_string()),
        },
    }
}

/// Reasons a candidate sentinel could not be extracted from the byte
/// stream.
#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub enum SentinelError {
    /// An opener was found but no closing `]]` appeared within the
    /// allowed scan window.
    #[error("encrypted-serial sentinel was not terminated within the allowed window")]
    Unterminated,
    /// The base64 body inside a sentinel was longer than allowed.
    #[error("encrypted-serial sentinel body of {len} bytes exceeds the {max}-byte maximum")]
    TooLong {
        /// Observed body length.
        len: usize,
        /// Maximum allowed body length.
        max: usize,
    },
    /// The base64 decoded payload was longer than allowed.
    #[error("encrypted-serial sentinel payload of {len} bytes exceeds the {max}-byte maximum")]
    PayloadTooLong {
        /// Observed payload length.
        len: usize,
        /// Maximum allowed payload length.
        max: usize,
    },
    /// The base64 body inside a sentinel was not valid base64.
    #[error("encrypted-serial sentinel base64 decode failed: {0}")]
    Base64(
        /// The underlying base64 error message.
        String,
    ),
}

/// Reasons the binary payload bytes could not be parsed into a
/// [`Record`].
#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub enum ParseError {
    /// The payload was shorter than the minimum legal size.
    #[error(
        "encrypted-serial record payload of {len} bytes is shorter than the {min}-byte minimum"
    )]
    PayloadTooShort {
        /// Observed payload length.
        len: usize,
        /// Minimum required payload length.
        min: usize,
    },
    /// The payload exceeded the maximum legal size.
    #[error("encrypted-serial record payload of {len} bytes exceeds the {max}-byte maximum")]
    PayloadTooLong {
        /// Observed payload length.
        len: usize,
        /// Maximum allowed payload length.
        max: usize,
    },
    /// The ciphertext field of the parsed payload was longer than
    /// the per-record maximum.
    #[error("encrypted-serial record ciphertext of {len} bytes exceeds the {max}-byte maximum")]
    CiphertextTooLong {
        /// Observed ciphertext length.
        len: usize,
        /// Maximum allowed ciphertext length.
        max: usize,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_record(ciphertext: Vec<u8>) -> Record {
        Record {
            session_id: [
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
                0x0e, 0x0f, 0x10,
            ],
            seq: 0x1122_3344_5566_7788,
            nonce: [
                0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c,
            ],
            ciphertext,
            tag: [
                0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d,
                0x3e, 0x3f, 0x40,
            ],
        }
    }

    #[test]
    fn payload_round_trip_empty_ciphertext() {
        let r = sample_record(Vec::new());
        let payload = r.encode_payload();
        assert_eq!(payload.len(), MIN_PAYLOAD_LEN);
        let parsed = Record::parse_payload(&payload).unwrap();
        assert_eq!(parsed, r);
    }

    #[test]
    fn payload_round_trip_with_ciphertext() {
        let r = sample_record(b"hello world".to_vec());
        let payload = r.encode_payload();
        let parsed = Record::parse_payload(&payload).unwrap();
        assert_eq!(parsed, r);
    }

    #[test]
    fn sentinel_round_trip() {
        let r = sample_record(b"a serial line".to_vec());
        let s = r.encode_to_string();
        assert!(s.starts_with("[[OHENC v1 "));
        assert!(s.ends_with("]]"));
        match find_next_sentinel(s.as_bytes(), 0) {
            SentinelMatch::Found {
                start,
                end,
                payload,
            } => {
                assert_eq!(start, 0);
                assert_eq!(end, s.len());
                assert_eq!(Record::parse_payload(&payload).unwrap(), r);
            }
            other => panic!("expected Found, got {other:?}"),
        }
    }

    #[test]
    fn sentinel_in_a_stream_with_plaintext_around_it() {
        let r = sample_record(b"x".to_vec());
        let mut input = b"some plaintext\n".to_vec();
        let sentinel_start = input.len();
        input.extend_from_slice(r.encode_to_string().as_bytes());
        let sentinel_end = input.len();
        input.extend_from_slice(b"\nmore plaintext\n");

        match find_next_sentinel(&input, 0) {
            SentinelMatch::Found {
                start,
                end,
                payload,
            } => {
                assert_eq!(start, sentinel_start);
                assert_eq!(end, sentinel_end);
                assert_eq!(Record::parse_payload(&payload).unwrap(), r);
            }
            other => panic!("expected Found, got {other:?}"),
        }
    }

    #[test]
    fn no_sentinel_means_not_found() {
        assert_eq!(
            find_next_sentinel(b"plain text without any markers", 0),
            SentinelMatch::NotFound
        );
    }

    #[test]
    fn unterminated_sentinel_is_malformed() {
        let input = b"prefix [[OHENC v1 abcdef without close";
        match find_next_sentinel(input, 0) {
            SentinelMatch::Malformed {
                start,
                reason: SentinelError::Unterminated,
            } => {
                assert_eq!(start, 7);
            }
            other => panic!("expected Unterminated, got {other:?}"),
        }
    }

    #[test]
    fn invalid_base64_is_malformed() {
        // `]` is not in the standard base64 alphabet, so the body
        // here is "!!!" which is invalid base64.
        let input = b"[[OHENC v1 !!!]]";
        match find_next_sentinel(input, 0) {
            SentinelMatch::Malformed {
                reason: SentinelError::Base64(_),
                ..
            } => {}
            other => panic!("expected Base64 error, got {other:?}"),
        }
    }

    #[test]
    fn payload_too_short_is_rejected() {
        // Encode a 4-byte payload (well below MIN_PAYLOAD_LEN).
        let payload = [0u8; 4];
        let mut sentinel = String::from("[[OHENC v1 ");
        BASE64.encode_string(payload, &mut sentinel);
        sentinel.push_str("]]");
        match find_next_sentinel(sentinel.as_bytes(), 0) {
            SentinelMatch::Found { payload, .. } => {
                let err = Record::parse_payload(&payload).unwrap_err();
                assert!(matches!(err, ParseError::PayloadTooShort { .. }));
            }
            other => panic!("expected Found, got {other:?}"),
        }
    }

    #[test]
    fn sentinel_body_too_long_is_malformed() {
        // Body of (MAX_SENTINEL_BASE64_LEN + 1) `A`s. Decoder rejects
        // the body before attempting base64.
        let body = "A".repeat(MAX_SENTINEL_BASE64_LEN + 1);
        let input = format!("[[OHENC v1 {body}]]");
        match find_next_sentinel(input.as_bytes(), 0) {
            SentinelMatch::Malformed {
                reason: SentinelError::Unterminated,
                ..
            } => {
                // The body exceeds the scan window, so we never find
                // the closing `]]`. That's an Unterminated outcome,
                // not a TooLong outcome -- and that's the right
                // semantic: a >6KB run of base64-looking bytes is not
                // a legitimate v1 record.
            }
            other => panic!("expected Unterminated due to scan-window, got {other:?}"),
        }
    }

    #[test]
    fn aad_layout() {
        let session_id = [0xAAu8; SESSION_ID_LEN];
        let seq: u64 = 0x0102_0304_0506_0708;
        let aad = build_aad(&session_id, seq);
        assert_eq!(&aad[..AAD_DOMAIN.len()], AAD_DOMAIN);
        assert_eq!(
            &aad[AAD_DOMAIN.len()..AAD_DOMAIN.len() + SESSION_ID_LEN],
            &session_id
        );
        assert_eq!(
            &aad[AAD_DOMAIN.len() + SESSION_ID_LEN..],
            &seq.to_le_bytes()
        );
    }

    #[test]
    fn find_skips_to_explicit_offset() {
        // Two sentinels in a stream; with from=after_first we should
        // get the second.
        let r1 = sample_record(b"one".to_vec());
        let r2 = sample_record(b"two".to_vec());
        let mut input = r1.encode_to_string();
        let after_first = input.len();
        input.push_str("...");
        input.push_str(&r2.encode_to_string());
        match find_next_sentinel(input.as_bytes(), after_first) {
            SentinelMatch::Found { start, .. } => {
                assert!(start > after_first);
            }
            other => panic!("expected Found, got {other:?}"),
        }
    }
}
