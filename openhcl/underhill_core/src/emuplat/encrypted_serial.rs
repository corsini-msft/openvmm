// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Encrypting serial backend: wraps an inner `SerialIo` backend and
//! encrypts all outgoing writes using the `openhcl_serial_console_crypto`
//! wire format before forwarding them to the inner transport.
//!
//! The encryption key is held in the resolver instance (never
//! serialized through `MeshPayload`), while the resource payload only
//! carries a reference to the inner backend resource.

use async_trait::async_trait;
use futures::io::AsyncRead;
use futures::io::AsyncWrite;
use inspect::InspectMut;
use mesh::MeshPayload;
use openhcl_serial_console_crypto::consts::MAX_PLAINTEXT_LEN;
use openhcl_serial_console_crypto::consts::NONCE_LEN;
use openhcl_serial_console_crypto::consts::PRODUCER_IDLE_FLUSH;
use openhcl_serial_console_crypto::consts::PRODUCER_SOFT_FLUSH_BYTES;
use openhcl_serial_console_crypto::consts::SESSION_ID_LEN;
use openhcl_serial_console_crypto::crypto::GksKeyMaterial;
use openhcl_serial_console_crypto::crypto::derive_aes_key;
use openhcl_serial_console_crypto::crypto::encrypt;
use openhcl_serial_console_crypto::format::Record;
use pal_async::timer::Instant;
use pal_async::timer::PolledTimer;
use serial_core::SerialIo;
use serial_core::resources::ResolveSerialBackendParams;
use serial_core::resources::ResolvedSerialBackend;
use std::collections::VecDeque;
use std::io;
use std::io::IoSliceMut;
use std::pin::Pin;
use std::sync::Arc;
use std::task::Context;
use std::task::Poll;
use vm_resource::AsyncResolveResource;
use vm_resource::Resource;
use vm_resource::ResourceId;
use vm_resource::ResourceResolver;
use vm_resource::kind::SerialBackendHandle;

/// Resource handle for an encrypting serial backend. The `inner`
/// backend is resolved first, then wrapped with encryption.
///
/// Key material is intentionally **not** part of this payload — it
/// lives in [`EncryptedSerialBackendResolver`]'s instance state so
/// it is never serialized.
#[derive(MeshPayload)]
pub struct EncryptedSerialBackendHandle {
    /// The inner serial backend to wrap.
    pub inner: Resource<SerialBackendHandle>,
}

impl ResourceId<SerialBackendHandle> for EncryptedSerialBackendHandle {
    const ID: &'static str = "encrypted_serial";
}

/// Resolver for [`EncryptedSerialBackendHandle`]. Holds the GKS key
/// material used for AES-256-GCM key derivation.
pub struct EncryptedSerialBackendResolver {
    /// The guest secret key material used to derive per-session AES keys.
    pub gks: Arc<GksKeyMaterial>,
}

#[async_trait]
impl AsyncResolveResource<SerialBackendHandle, EncryptedSerialBackendHandle>
    for EncryptedSerialBackendResolver
{
    type Output = ResolvedSerialBackend;
    type Error = anyhow::Error;

    async fn resolve(
        &self,
        resolver: &ResourceResolver,
        resource: EncryptedSerialBackendHandle,
        input: ResolveSerialBackendParams<'_>,
    ) -> Result<Self::Output, Self::Error> {
        // Create the idle-flush timer from the resolver's driver
        // before `input` is moved into the inner resolver.
        // `Driver::new_dyn_timer` takes `&self`, so the borrow ends
        // before the move.
        let timer = PolledTimer::new(&*input.driver);

        // Resolve the inner backend first.
        let inner = resolver.resolve(resource.inner, input).await?;
        let inner_io = inner.0.into_io();

        // Generate a per-session identifier.
        let mut session_id = [0u8; SESSION_ID_LEN];
        getrandom::fill(&mut session_id)
            .map_err(|e| anyhow::anyhow!("failed to generate session_id: {e}"))?;

        // Derive the per-session AES key.
        let aes_key = derive_aes_key(&self.gks, &session_id)
            .map_err(|e| anyhow::anyhow!("failed to derive AES key: {e}"))?;

        let wrapper = EncryptingSerialIo::new(inner_io, aes_key, session_id, timer);
        Ok(ResolvedSerialBackend(Box::new(EncryptingSerialBackend {
            wrapper,
            gks: self.gks.clone(),
        })))
    }
}

/// A resolved encrypting serial backend. Wraps the inner IO and
/// provides `SerialBackend` implementation.
struct EncryptingSerialBackend {
    wrapper: EncryptingSerialIo,
    /// Retained for potential re-keying or resource reclamation.
    #[expect(dead_code)]
    gks: Arc<GksKeyMaterial>,
}

impl serial_core::resources::SerialBackend for EncryptingSerialBackend {
    fn into_resource(self: Box<Self>) -> Resource<SerialBackendHandle> {
        // We cannot reclaim the original resource after wrapping, so
        // return a disconnected placeholder. This is acceptable for
        // the PoC.
        Resource::new(serial_core::resources::DisconnectedSerialBackendHandle)
    }

    fn as_io(&self) -> &dyn SerialIo {
        &self.wrapper
    }

    fn as_io_mut(&mut self) -> &mut dyn SerialIo {
        &mut self.wrapper
    }

    fn into_io(self: Box<Self>) -> Box<dyn SerialIo> {
        Box::new(self.wrapper)
    }
}

/// Wraps a `Box<dyn SerialIo>` and encrypts all writes using
/// AES-256-GCM before forwarding them as `[[OHENC v1 ...]]` records.
///
/// Reads are passed through unmodified (decryption of incoming data
/// is not implemented).
///
/// # Wire framing
///
/// Each emitted record is `[[OHENC v1 BASE64]]` with **no** trailing
/// delimiter — `]]` already terminates each record unambiguously.
/// Records run back-to-back on the wire (`[[..]][[..]][[..]]`).
///
/// # Flush policy
///
/// The encryptor maintains a small plaintext staging buffer. It
/// emits a record (and tries to start draining it onto the inner
/// transport) when **any** of the following conditions holds:
///
/// - The buffer reaches
///   [`PRODUCER_SOFT_FLUSH_BYTES`](openhcl_serial_console_crypto::consts::PRODUCER_SOFT_FLUSH_BYTES)
///   bytes (256). Soft size threshold; mirrors typical TLS record
///   sizing.
/// - The buffer reaches
///   [`MAX_PLAINTEXT_LEN`](openhcl_serial_console_crypto::consts::MAX_PLAINTEXT_LEN)
///   bytes (4096). Hard upper bound — at most this many plaintext
///   bytes can fit into one record.
/// - [`PRODUCER_IDLE_FLUSH`](openhcl_serial_console_crypto::consts::PRODUCER_IDLE_FLUSH)
///   has elapsed since the buffer became non-empty (50 ms). Bounds
///   the worst-case latency between a producer write and the
///   corresponding wire record so partial output never sits in the
///   buffer indefinitely.
///
/// The encryptor deliberately does **not** look at byte content for
/// flush decisions (no `\n` / `\r` detection) — that previous
/// behaviour starved on output without line terminators (ANSI
/// escapes, prompts, partial UTF-8 across writes) and was just
/// glibc-style line buffering with the same brittleness.
pub struct EncryptingSerialIo {
    inner: Box<dyn SerialIo>,
    aes_key: [u8; 32],
    session_id: [u8; SESSION_ID_LEN],
    seq: u64,
    /// Plaintext bytes accumulated from `poll_write` calls, pending
    /// encryption.
    plaintext_buf: Vec<u8>,
    /// Encrypted sentinel records ready to be written to the inner
    /// transport.
    output_buf: VecDeque<u8>,
    /// Timer used to drive the idle flush. Polled from
    /// `poll_drain_output` and `poll_read` so the runtime wakes us
    /// from any active poll path when the deadline expires.
    timer: PolledTimer,
    /// Absolute time at which the current buffered plaintext must be
    /// flushed if no other flush trigger fires first. `None` when the
    /// buffer is empty (or has just been flushed).
    flush_deadline: Option<Instant>,
}

impl InspectMut for EncryptingSerialIo {
    fn inspect_mut(&mut self, req: inspect::Request<'_>) {
        let mut resp = req.respond();
        resp.field("seq", self.seq)
            .field("plaintext_pending", self.plaintext_buf.len())
            .field("output_pending", self.output_buf.len())
            .field(
                "flush_deadline_in_ms",
                self.flush_deadline
                    .map(|d| d.saturating_sub(Instant::now()).as_millis() as u64),
            );
    }
}

impl EncryptingSerialIo {
    fn new(
        inner: Box<dyn SerialIo>,
        aes_key: [u8; 32],
        session_id: [u8; SESSION_ID_LEN],
        timer: PolledTimer,
    ) -> Self {
        Self {
            inner,
            aes_key,
            session_id,
            seq: 0,
            plaintext_buf: Vec::new(),
            output_buf: VecDeque::new(),
            timer,
            flush_deadline: None,
        }
    }

    /// Encrypt all pending plaintext into output records, draining
    /// `plaintext_buf` in `MAX_PLAINTEXT_LEN`-sized chunks until it
    /// is empty. Clears the idle-flush deadline.
    ///
    /// Callers decide when to invoke this (see the flush-policy
    /// docs on [`EncryptingSerialIo`]). The function itself imposes
    /// no policy beyond the per-record size cap.
    fn flush_plaintext_to_output(&mut self) -> Result<(), io::Error> {
        while !self.plaintext_buf.is_empty() {
            let take = self.plaintext_buf.len().min(MAX_PLAINTEXT_LEN);
            let chunk: Vec<u8> = self.plaintext_buf.drain(..take).collect();
            self.encrypt_and_enqueue(&chunk)?;
        }
        self.flush_deadline = None;
        Ok(())
    }

    /// If `flush_deadline` has elapsed, flush. If it's set but in the
    /// future, register the waker against the timer so the runtime
    /// wakes us when it expires. Returns the deadline's outcome (so
    /// the caller can keep flowing if a flush actually happened).
    fn poll_flush_deadline(&mut self, cx: &mut Context<'_>) -> Result<(), io::Error> {
        if let Some(deadline) = self.flush_deadline {
            if Instant::now() >= deadline {
                self.flush_plaintext_to_output()?;
            } else {
                let _ = self.timer.poll_until(cx, deadline);
            }
        }
        Ok(())
    }

    /// Encrypt a single chunk and append the sentinel record to the
    /// output buffer.
    fn encrypt_and_enqueue(&mut self, plaintext: &[u8]) -> Result<(), io::Error> {
        let mut nonce = [0u8; NONCE_LEN];
        getrandom::fill(&mut nonce)
            .map_err(|e| io::Error::other(format!("nonce generation failed: {e}")))?;

        let (ciphertext, tag) =
            encrypt(&self.aes_key, &self.session_id, self.seq, &nonce, plaintext)
                .map_err(|e| io::Error::other(format!("encryption failed: {e}")))?;

        let record = Record {
            session_id: self.session_id,
            seq: self.seq,
            nonce,
            ciphertext,
            tag,
        };

        let sentinel = record.encode_to_string();
        self.output_buf.extend(sentinel.as_bytes());
        // No inter-record delimiter — `]]` already terminates each
        // record unambiguously, and adding a wire `\n` would couple
        // any line-oriented consumer to in-band data we never want
        // to forward to user output.

        self.seq += 1;
        Ok(())
    }

    /// Try to drain output_buf into the inner transport. Also checks
    /// the idle-flush deadline, since this poll path is on the
    /// natural wake surface (called from `poll_write`, `poll_flush`,
    /// and `poll_close`).
    fn poll_drain_output(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        // Honour any pending idle-flush deadline before draining,
        // so a wake from the timer turns into bytes on the wire.
        self.poll_flush_deadline(cx)?;

        while !self.output_buf.is_empty() {
            let (front, _) = self.output_buf.as_slices();
            if front.is_empty() {
                break;
            }
            match Pin::new(&mut *self.inner).poll_write(cx, front) {
                Poll::Ready(Ok(n)) => {
                    self.output_buf.drain(..n);
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
        Poll::Ready(Ok(()))
    }
}

impl SerialIo for EncryptingSerialIo {
    fn is_connected(&self) -> bool {
        self.inner.is_connected()
    }

    fn poll_connect(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.inner.poll_connect(cx)
    }

    fn poll_disconnect(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.inner.poll_disconnect(cx)
    }
}

impl AsyncRead for EncryptingSerialIo {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        // Mirror the deadline poll on the read path so an idle UART
        // (no concurrent writes) still wakes us when the flush
        // deadline expires. `Serial16550::poll_rx` polls us
        // continuously, so registering the timer waker here is
        // enough to drive the idle flush.
        self.poll_flush_deadline(cx)?;

        // Pass through reads unmodified.
        Pin::new(&mut *self.inner).poll_read(cx, buf)
    }

    fn poll_read_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &mut [IoSliceMut<'_>],
    ) -> Poll<io::Result<usize>> {
        self.poll_flush_deadline(cx)?;
        Pin::new(&mut *self.inner).poll_read_vectored(cx, bufs)
    }
}

impl AsyncWrite for EncryptingSerialIo {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        // First try to drain any pending encrypted output. This also
        // checks (and possibly satisfies) the idle-flush deadline,
        // so a write arriving after the deadline expired flushes
        // promptly.
        match self.poll_drain_output(cx) {
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Ok(())) => {}
        }

        // Accept plaintext into the buffer.
        let accepted = buf.len();
        self.plaintext_buf.extend_from_slice(buf);

        // Eager flush if the buffer crossed the soft size threshold
        // (or is so large that the next encrypt_and_enqueue would hit
        // MAX_PLAINTEXT_LEN anyway). Otherwise arm the idle timer if
        // it isn't already armed.
        if self.plaintext_buf.len() >= PRODUCER_SOFT_FLUSH_BYTES {
            self.flush_plaintext_to_output()?;
            // Start draining right away — most callers are 'fire and
            // forget' on poll_write and never call poll_flush.
            let _ = self.poll_drain_output(cx);
        } else if !self.plaintext_buf.is_empty() && self.flush_deadline.is_none() {
            // Arm the idle timer so a partial buffer doesn't sit
            // here indefinitely. Only set the deadline on the
            // empty -> non-empty transition; subsequent writes don't
            // refresh it, which bounds the worst-case time any byte
            // can spend in the buffer to PRODUCER_IDLE_FLUSH even
            // under steady write pressure.
            let deadline = Instant::now() + PRODUCER_IDLE_FLUSH;
            self.flush_deadline = Some(deadline);
            // Register the waker so we get re-polled when the
            // deadline expires.
            let _ = self.timer.poll_until(cx, deadline);
        }

        Poll::Ready(Ok(accepted))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // Encrypt any remaining plaintext, including partial chunks.
        self.flush_plaintext_to_output()?;

        // Drain all encrypted output.
        match self.poll_drain_output(cx) {
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Ok(())) => {}
        }

        // Flush the inner transport.
        Pin::new(&mut *self.inner).poll_flush(cx)
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // Flush everything before closing.
        match Pin::new(&mut self).poll_flush(cx) {
            Poll::Ready(Ok(())) => {}
            other => return other,
        }
        Pin::new(&mut *self.inner).poll_close(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::AsyncWriteExt;
    use openhcl_serial_console_crypto::consts::SENTINEL_CLOSE;
    use openhcl_serial_console_crypto::consts::SENTINEL_OPEN;
    use pal_async::DefaultDriver;
    use pal_async::async_test;
    use pal_async::timer::PolledTimer;
    use parking_lot::Mutex;
    use std::sync::Arc;
    use std::time::Duration;

    /// In-memory `SerialIo` backend that captures every byte written
    /// to it. Reads are never satisfied. Used by the producer tests
    /// to inspect the wire bytes the encryptor emitted.
    struct CapturingBackend {
        captured: Arc<Mutex<Vec<u8>>>,
    }

    impl CapturingBackend {
        fn new() -> (Self, Arc<Mutex<Vec<u8>>>) {
            let captured = Arc::new(Mutex::new(Vec::new()));
            (
                Self {
                    captured: captured.clone(),
                },
                captured,
            )
        }
    }

    impl InspectMut for CapturingBackend {
        fn inspect_mut(&mut self, req: inspect::Request<'_>) {
            req.respond();
        }
    }

    impl SerialIo for CapturingBackend {
        fn is_connected(&self) -> bool {
            true
        }
        fn poll_connect(&mut self, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
        fn poll_disconnect(&mut self, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Pending
        }
    }

    impl AsyncRead for CapturingBackend {
        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &mut [u8],
        ) -> Poll<io::Result<usize>> {
            Poll::Pending
        }
    }

    impl AsyncWrite for CapturingBackend {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            self.captured.lock().extend_from_slice(buf);
            Poll::Ready(Ok(buf.len()))
        }
        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
        fn poll_close(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    fn test_aes_key() -> [u8; 32] {
        let mut k = [0u8; 32];
        for (i, b) in k.iter_mut().enumerate() {
            *b = (i & 0xff) as u8;
        }
        k
    }

    fn test_session_id() -> [u8; SESSION_ID_LEN] {
        let mut s = [0u8; SESSION_ID_LEN];
        for (i, b) in s.iter_mut().enumerate() {
            *b = ((i + 0x40) & 0xff) as u8;
        }
        s
    }

    fn make_wrapper(driver: &DefaultDriver) -> (EncryptingSerialIo, Arc<Mutex<Vec<u8>>>) {
        let (backend, captured) = CapturingBackend::new();
        let timer = PolledTimer::new(driver);
        let session_id = test_session_id();
        let wrapper =
            EncryptingSerialIo::new(Box::new(backend), test_aes_key(), session_id, timer);
        (wrapper, captured)
    }

    fn count_subseq(haystack: &[u8], needle: &[u8]) -> usize {
        if needle.is_empty() || haystack.len() < needle.len() {
            return 0;
        }
        haystack.windows(needle.len()).filter(|w| *w == needle).count()
    }

    #[async_test]
    async fn flush_on_soft_threshold(driver: DefaultDriver) {
        let (mut wrapper, captured) = make_wrapper(&driver);

        // Write 200 bytes — below 256 threshold, no flush yet.
        wrapper.write_all(&[b'a'; 200]).await.unwrap();
        assert_eq!(
            captured.lock().len(),
            0,
            "no record expected before reaching soft threshold"
        );

        // Write 100 more bytes — total 300, crosses threshold, flush.
        wrapper.write_all(&[b'b'; 100]).await.unwrap();
        let bytes = captured.lock().clone();
        assert_eq!(
            count_subseq(&bytes, SENTINEL_OPEN),
            1,
            "expected one record on the wire after crossing soft threshold"
        );
        assert_eq!(count_subseq(&bytes, SENTINEL_CLOSE), 1);
    }

    #[async_test]
    async fn flush_on_max_plaintext_emits_full_chunk(driver: DefaultDriver) {
        let (mut wrapper, captured) = make_wrapper(&driver);

        // Single write larger than MAX_PLAINTEXT_LEN. Crosses the
        // soft threshold, so the wrapper flushes, encrypting in
        // MAX-sized chunks.
        let payload = vec![b'X'; MAX_PLAINTEXT_LEN + 904];
        wrapper.write_all(&payload).await.unwrap();

        let bytes = captured.lock().clone();
        // Two records: one of MAX_PLAINTEXT_LEN, one of 904 bytes.
        assert_eq!(
            count_subseq(&bytes, SENTINEL_OPEN),
            2,
            "expected two records to drain the over-MAX write"
        );
        assert_eq!(count_subseq(&bytes, SENTINEL_CLOSE), 2);
    }

    #[async_test]
    async fn idle_flush_after_timeout(driver: DefaultDriver) {
        let (mut wrapper, captured) = make_wrapper(&driver);

        // Write below threshold — buffered, idle timer armed.
        wrapper.write_all(b"hello").await.unwrap();
        assert_eq!(captured.lock().len(), 0);

        // Sleep past the idle timeout, then poll the wrapper to
        // give it a chance to act on the elapsed deadline. Use
        // poll_flush which exercises poll_drain_output (which
        // checks the deadline).
        let mut sleeper = PolledTimer::new(&driver);
        sleeper
            .sleep(PRODUCER_IDLE_FLUSH + Duration::from_millis(20))
            .await;
        wrapper.flush().await.unwrap();

        let bytes = captured.lock().clone();
        assert_eq!(
            count_subseq(&bytes, SENTINEL_OPEN),
            1,
            "expected the buffered partial write to flush after the idle timeout"
        );
    }

    #[async_test]
    async fn no_terminator_dependency(driver: DefaultDriver) {
        // 300 bytes containing no `\n` and no `\r`. Under the old
        // behaviour this would have hung waiting for a terminator
        // (or until the buffer hit MAX_PLAINTEXT_LEN). Under the
        // new policy the soft threshold catches it.
        let (mut wrapper, captured) = make_wrapper(&driver);
        let payload: Vec<u8> = (0..300u32)
            .map(|i| {
                // ASCII printable, no `\n` (0x0a) or `\r` (0x0d).
                let c = b'!' + ((i % 80) as u8);
                if c == b'\n' || c == b'\r' { b'?' } else { c }
            })
            .collect();
        wrapper.write_all(&payload).await.unwrap();
        let bytes = captured.lock().clone();
        assert_eq!(
            count_subseq(&bytes, SENTINEL_OPEN),
            1,
            "buffer crossed soft threshold and should have flushed without any terminator"
        );
    }

    #[async_test]
    async fn back_to_back_writes_coalesce_into_single_record(driver: DefaultDriver) {
        // Two writes of 100 bytes each (200 total) — below the soft
        // threshold, no flush. Then 100 more bytes (300 total)
        // crosses the threshold and produces exactly one record
        // containing all three writes.
        let (mut wrapper, captured) = make_wrapper(&driver);
        wrapper.write_all(&[b'1'; 100]).await.unwrap();
        wrapper.write_all(&[b'2'; 100]).await.unwrap();
        assert_eq!(captured.lock().len(), 0);
        wrapper.write_all(&[b'3'; 100]).await.unwrap();
        let bytes = captured.lock().clone();
        assert_eq!(
            count_subseq(&bytes, SENTINEL_OPEN),
            1,
            "expected the three sub-threshold writes to coalesce into one record"
        );
    }

    #[async_test]
    async fn wire_has_no_inter_record_delimiter(driver: DefaultDriver) {
        // Force several records via successive over-threshold
        // writes; verify the wire bytes contain no `\n` between
        // them. The closing `]]` is the only delimiter.
        let (mut wrapper, captured) = make_wrapper(&driver);
        for _ in 0..3 {
            wrapper.write_all(&[b'A'; 300]).await.unwrap();
        }
        let bytes = captured.lock().clone();
        assert_eq!(
            count_subseq(&bytes, SENTINEL_OPEN),
            3,
            "expected three records on the wire"
        );
        assert_eq!(count_subseq(&bytes, SENTINEL_CLOSE), 3);
        assert_eq!(
            bytes.iter().filter(|&&b| b == b'\n').count(),
            0,
            "wire framing must not contain a newline byte between records"
        );
    }
}
