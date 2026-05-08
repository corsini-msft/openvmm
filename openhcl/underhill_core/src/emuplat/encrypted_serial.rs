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
use openhcl_serial_console_crypto::stream::StreamScanner;
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

/// Resolver for [`EncryptedSerialBackendHandle`]. Holds the GSK key
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

        let wrapper = EncryptedSerialIo::new(inner_io, aes_key, session_id, timer, self.gks.clone());
        Ok(ResolvedSerialBackend(Box::new(EncryptedSerialBackend {
            wrapper,
        })))
    }
}

/// A resolved encrypted serial backend. Wraps the inner IO and
/// provides the [`SerialBackend`] implementation.
struct EncryptedSerialBackend {
    wrapper: EncryptedSerialIo,
}

impl serial_core::resources::SerialBackend for EncryptedSerialBackend {
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

/// Wraps a `Box<dyn SerialIo>` and runs encrypted serial in BOTH
/// directions: outgoing writes (from the guest VTL) get encrypted as
/// `[[OHENC v1 ...]]` records before reaching the inner transport,
/// and incoming reads from the inner transport get decrypted before
/// being delivered to the guest.
///
/// # Wire framing
///
/// Each emitted record is `[[OHENC v1 BASE64]]` with **no** trailing
/// delimiter — `]]` already terminates each record unambiguously.
/// Records run back-to-back on the wire (`[[..]][[..]][[..]]`).
///
/// # Two independent sessions
///
/// The producer (write side) and consumer (read side) each run their
/// own AES-256-GCM session, both keyed off the shared GKS but with
/// distinct `session_id`s. Distinct keys mean the two directions
/// can share one wire transport without risking nonce collision.
/// The producer's `session_id` is generated once at startup; the
/// consumer's `session_id`s are observed in incoming records and
/// cached per-session in the [`StreamScanner`].
///
/// # Producer flush policy
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
///
/// # Consumer behaviour
///
/// On `poll_read`, the wrapper pulls bytes from the inner transport
/// into a small scratch buffer, feeds them to a [`StreamScanner`],
/// and returns the decrypted plaintext (or any non-sentinel
/// passthrough bytes) to the guest UART. Plaintext bytes that
/// don't belong to any sentinel are forwarded verbatim, matching
/// the host-side decoder behaviour and preserving backward
/// compatibility with plaintext-only host clients.
pub struct EncryptedSerialIo {
    inner: Box<dyn SerialIo>,

    // Producer state.
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

    // Consumer state.
    /// Streaming sentinel scanner for decrypting incoming records.
    /// Owns its own per-session AES key cache.
    consumer_scanner: StreamScanner,
    /// Decrypted plaintext (and passthrough) bytes ready to deliver
    /// to the guest via `poll_read`.
    consumer_plaintext_out: VecDeque<u8>,
    /// GKS reference shared with the resolver. The consumer uses it
    /// to derive AES keys for each new session_id observed in
    /// incoming records.
    gks: Arc<GksKeyMaterial>,
}

impl InspectMut for EncryptedSerialIo {
    fn inspect_mut(&mut self, req: inspect::Request<'_>) {
        let mut resp = req.respond();
        resp.field("seq", self.seq)
            .field("plaintext_pending", self.plaintext_buf.len())
            .field("output_pending", self.output_buf.len())
            .field(
                "flush_deadline_in_ms",
                self.flush_deadline
                    .map(|d| d.saturating_sub(Instant::now()).as_millis() as u64),
            )
            .field(
                "consumer_buffered_wire",
                self.consumer_scanner.buffered(),
            )
            .field(
                "consumer_plaintext_pending",
                self.consumer_plaintext_out.len(),
            )
            .field("consumer_sessions", self.consumer_scanner.sessions());
    }
}

impl EncryptedSerialIo {
    fn new(
        inner: Box<dyn SerialIo>,
        aes_key: [u8; 32],
        session_id: [u8; SESSION_ID_LEN],
        timer: PolledTimer,
        gks: Arc<GksKeyMaterial>,
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
            consumer_scanner: StreamScanner::new(),
            consumer_plaintext_out: VecDeque::new(),
            gks,
        }
    }

    /// Encrypt all pending plaintext into output records, draining
    /// `plaintext_buf` in `MAX_PLAINTEXT_LEN`-sized chunks until it
    /// is empty. Clears the idle-flush deadline.
    ///
    /// Callers decide when to invoke this (see the flush-policy
    /// docs on [`EncryptedSerialIo`]). The function itself imposes
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

impl SerialIo for EncryptedSerialIo {
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

/// Scratch buffer size used by [`EncryptedSerialIo::poll_read`] when
/// pulling bytes from the inner transport into the scanner. One
/// `inner.poll_read` ever produces at most this many bytes per call.
const READ_SCRATCH_LEN: usize = 4096;

impl AsyncRead for EncryptedSerialIo {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        // Drive any pending encrypted output (and the idle-flush
        // deadline check baked into `poll_drain_output`) on every
        // read. Crucially, this is what gets encrypted bytes onto
        // the wire when the *timer* (not a fresh write) is the only
        // event that fired: the timer waker wakes the task that
        // owns Serial16550, which re-polls poll_rx, which calls us
        // here. Without the drain on this path, partial writes that
        // hit only the idle-flush trigger get encrypted into
        // `output_buf` but never make it to the inner transport,
        // so the host sees nothing past the most recent
        // soft-threshold flush.
        //
        // Errors propagate; Pending from the write side does NOT
        // block the read path — they're independent operations.
        if let Poll::Ready(Err(e)) = self.poll_drain_output(cx) {
            return Poll::Ready(Err(e));
        }

        // Loop: keep pulling wire bytes from the inner and feeding
        // them through the scanner until we either have plaintext
        // ready to deliver, hit EOF, or genuinely have to wait for
        // more inner bytes. A single inner read can land in the
        // middle of a sentinel (e.g. the inner's read budget caps
        // out before the full record arrives), in which case the
        // scanner emits nothing and we have to immediately try
        // pulling more — without that loop we'd return Pending with
        // no waker registered (the inner only registers its waker
        // when *it* returns Pending), and the task would hang.
        loop {
            // 1. Return any plaintext we already decrypted.
            if !self.consumer_plaintext_out.is_empty() {
                return Poll::Ready(Ok(copy_out(
                    &mut self.consumer_plaintext_out,
                    buf,
                )));
            }

            // 2. Pull more wire bytes from the inner transport.
            let mut scratch = [0u8; READ_SCRATCH_LEN];
            let max = scratch.len().min(buf.len().max(1));
            let n = match Pin::new(&mut *self.inner).poll_read(cx, &mut scratch[..max]) {
                Poll::Ready(Ok(n)) => n,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            };

            if n == 0 {
                // EOF on the inner. Flush any in-flight scanner
                // state as passthrough into the plaintext queue;
                // then either deliver it or report EOF to the
                // caller.
                let this = self.as_mut().get_mut();
                let mut writer = VecDequeWriter(&mut this.consumer_plaintext_out);
                this.consumer_scanner
                    .drain(&this.gks, /* at_eof */ true, &mut writer)
                    .map_err(io::Error::other)?;
                if this.consumer_plaintext_out.is_empty() {
                    return Poll::Ready(Ok(0));
                }
                return Poll::Ready(Ok(copy_out(
                    &mut this.consumer_plaintext_out,
                    buf,
                )));
            }

            // 3. Feed those bytes through the scanner.
            let this = self.as_mut().get_mut();
            this.consumer_scanner.extend(&scratch[..n]);
            let mut writer = VecDequeWriter(&mut this.consumer_plaintext_out);
            this.consumer_scanner
                .drain(&this.gks, /* at_eof */ false, &mut writer)
                .map_err(io::Error::other)?;

            // 4. Loop. If the scanner produced plaintext, the next
            //    iteration's check at step 1 will return it. If it
            //    didn't (partial sentinel), the next iteration
            //    pulls more from inner — eventually inner returns
            //    Pending (and registers its waker) or Ok(0).
        }
    }

    fn poll_read_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &mut [IoSliceMut<'_>],
    ) -> Poll<io::Result<usize>> {
        // Find the first non-empty buffer and delegate to poll_read
        // with it. Vectored reads on a serial port are a curiosity at
        // best — keeping the impl simple here is fine.
        for buf in bufs {
            if !buf.is_empty() {
                return self.as_mut().poll_read(cx, buf);
            }
        }
        Poll::Ready(Ok(0))
    }
}

/// Copy as many bytes as fit from `src` into `dst`, removing them
/// from the front of `src`. Returns the number copied.
fn copy_out(src: &mut VecDeque<u8>, dst: &mut [u8]) -> usize {
    let n = src.len().min(dst.len());
    for (i, b) in src.drain(..n).enumerate() {
        dst[i] = b;
    }
    n
}

/// Tiny adapter so [`StreamScanner::drain`] (which wants a
/// `&mut dyn io::Write`) can write into the consumer's queue.
struct VecDequeWriter<'a>(&'a mut VecDeque<u8>);

impl io::Write for VecDequeWriter<'_> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.extend(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl AsyncWrite for EncryptedSerialIo {
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
    use std::collections::VecDeque as TestVecDeque;
    use std::time::Duration;

    /// In-memory `SerialIo` backend that captures every byte written
    /// to it AND lets tests inject bytes for the wrapper's read path.
    /// Used for both producer-only tests (which ignore the read side)
    /// and consumer-side tests (which inject encrypted records and
    /// observe the decrypted output coming out of poll_read).
    struct CapturingBackend {
        captured: Arc<Mutex<Vec<u8>>>,
        inject: Arc<Mutex<TestVecDeque<u8>>>,
        eof_when_inject_empty: Arc<Mutex<bool>>,
    }

    /// Handle returned to the test for poking at backend state.
    #[derive(Clone)]
    struct BackendCtl {
        captured: Arc<Mutex<Vec<u8>>>,
        inject: Arc<Mutex<TestVecDeque<u8>>>,
        eof_when_inject_empty: Arc<Mutex<bool>>,
    }

    impl BackendCtl {
        fn captured_bytes(&self) -> Vec<u8> {
            self.captured.lock().clone()
        }
        /// Append bytes that the next inner `poll_read` should
        /// deliver upward.
        fn inject(&self, bytes: &[u8]) {
            self.inject.lock().extend(bytes);
        }
        /// After this is set, when the inject queue is empty, the
        /// inner `poll_read` returns `Ok(0)` (EOF) instead of
        /// `Pending`.
        fn signal_eof(&self) {
            *self.eof_when_inject_empty.lock() = true;
        }
    }

    impl CapturingBackend {
        fn new() -> (Self, BackendCtl) {
            let captured = Arc::new(Mutex::new(Vec::new()));
            let inject = Arc::new(Mutex::new(TestVecDeque::new()));
            let eof = Arc::new(Mutex::new(false));
            let backend = Self {
                captured: captured.clone(),
                inject: inject.clone(),
                eof_when_inject_empty: eof.clone(),
            };
            (
                backend,
                BackendCtl {
                    captured,
                    inject,
                    eof_when_inject_empty: eof,
                },
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
            buf: &mut [u8],
        ) -> Poll<io::Result<usize>> {
            let mut inject = self.inject.lock();
            if inject.is_empty() {
                if *self.eof_when_inject_empty.lock() {
                    return Poll::Ready(Ok(0));
                }
                return Poll::Pending;
            }
            let n = inject.len().min(buf.len());
            for (i, b) in inject.drain(..n).enumerate() {
                buf[i] = b;
            }
            Poll::Ready(Ok(n))
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

    fn make_wrapper(driver: &DefaultDriver) -> (EncryptedSerialIo, Arc<Mutex<Vec<u8>>>) {
        let (wrapper, ctl) = make_bidi_wrapper(driver);
        (wrapper, ctl.captured)
    }

    /// Like [`make_wrapper`] but exposes the full backend control
    /// handle so tests can also inject bytes for the read path and
    /// signal EOF.
    fn make_bidi_wrapper(driver: &DefaultDriver) -> (EncryptedSerialIo, BackendCtl) {
        let (backend, ctl) = CapturingBackend::new();
        let timer = PolledTimer::new(driver);
        let session_id = test_session_id();
        let gks = Arc::new(test_gks());
        let wrapper = EncryptedSerialIo::new(
            Box::new(backend),
            test_aes_key(),
            session_id,
            timer,
            gks,
        );
        (wrapper, ctl)
    }

    fn test_gks() -> GksKeyMaterial {
        let mut buf = [0u8; openhcl_serial_console_crypto::crypto::GKS_LEN];
        for (i, b) in buf.iter_mut().enumerate() {
            *b = (i & 0xff) as u8;
        }
        GksKeyMaterial(buf)
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
    async fn idle_flush_drains_on_poll_read(driver: DefaultDriver) {
        // Production path: in OpenHCL, Serial16550::poll_tx is only
        // called when the guest pushes bytes into the UART's TX
        // FIFO. After the idle timer fires there's no fresh write,
        // so the *only* thing the timer waker can wake is poll_rx
        // → our poll_read. This test reproduces that exact path:
        // write a sub-threshold amount, wait past the deadline,
        // then drive a single poll_read (which would normally come
        // from Serial16550::poll_rx). The encrypted record must
        // appear on the inner transport WITHOUT a poll_flush ever
        // being called.
        use futures::AsyncRead;
        use std::future::poll_fn;

        let (mut wrapper, captured) = make_wrapper(&driver);

        wrapper.write_all(b"partial").await.unwrap();
        assert_eq!(captured.lock().len(), 0);

        let mut sleeper = PolledTimer::new(&driver);
        sleeper
            .sleep(PRODUCER_IDLE_FLUSH + Duration::from_millis(20))
            .await;

        // Drive a single poll_read. The inner CapturingBackend
        // returns Poll::Pending for reads, so the outer future
        // also returns Pending — but the side effect (drain of
        // output_buf) has already happened by then.
        poll_fn(|cx| {
            let mut buf = [0u8; 16];
            let _ = Pin::new(&mut wrapper).poll_read(cx, &mut buf);
            Poll::Ready(())
        })
        .await;

        let bytes = captured.lock().clone();
        assert_eq!(
            count_subseq(&bytes, SENTINEL_OPEN),
            1,
            "poll_read must drain output_buf so timer-driven flushes reach the wire"
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

    // ---- Consumer (read-side) tests ----------------------------------

    use openhcl_serial_console_crypto::consts::AES_KEY_LEN;
    use openhcl_serial_console_crypto::consts::SESSION_ID_LEN as TEST_SESSION_ID_LEN;
    use openhcl_serial_console_crypto::consts::NONCE_LEN as TEST_NONCE_LEN;
    use openhcl_serial_console_crypto::crypto::derive_aes_key as test_derive_aes_key;
    use openhcl_serial_console_crypto::crypto::encrypt as test_encrypt;
    use openhcl_serial_console_crypto::format::Record as TestRecord;
    use futures::AsyncReadExt;

    /// Build one wire-format record under the test GKS.
    fn build_inbound_record(
        plaintext: &[u8],
        session_id: [u8; TEST_SESSION_ID_LEN],
        seq: u64,
    ) -> Vec<u8> {
        let aes_key: [u8; AES_KEY_LEN] = test_derive_aes_key(&test_gks(), &session_id).unwrap();
        let mut nonce = [0u8; TEST_NONCE_LEN];
        for (i, b) in nonce.iter_mut().enumerate() {
            *b = ((i as u64 + seq) & 0xff) as u8;
        }
        let (ciphertext, tag) =
            test_encrypt(&aes_key, &session_id, seq, &nonce, plaintext).unwrap();
        let record = TestRecord {
            session_id,
            seq,
            nonce,
            ciphertext,
            tag,
        };
        record.encode_to_string().into_bytes()
    }

    fn host_session_id() -> [u8; TEST_SESSION_ID_LEN] {
        // Distinct from `test_session_id()` (the producer's), so the
        // two directions are unambiguously different sessions.
        let mut s = [0u8; TEST_SESSION_ID_LEN];
        for (i, b) in s.iter_mut().enumerate() {
            *b = ((i + 0xa0) & 0xff) as u8;
        }
        s
    }

    #[async_test]
    async fn read_decrypts_single_record(driver: DefaultDriver) {
        let (mut wrapper, ctl) = make_bidi_wrapper(&driver);
        let sid = host_session_id();
        ctl.inject(&build_inbound_record(b"hello\n", sid, 0));
        ctl.signal_eof(); // tell the wrapper there's no more to come

        let mut out = Vec::new();
        wrapper.read_to_end(&mut out).await.unwrap();
        assert_eq!(out, b"hello\n");
    }

    #[async_test]
    async fn read_decrypts_multiple_back_to_back_records(driver: DefaultDriver) {
        let (mut wrapper, ctl) = make_bidi_wrapper(&driver);
        let sid = host_session_id();
        let mut wire = Vec::new();
        wire.extend_from_slice(&build_inbound_record(b"one\n", sid, 0));
        wire.extend_from_slice(&build_inbound_record(b"two\n", sid, 1));
        wire.extend_from_slice(&build_inbound_record(b"three\n", sid, 2));
        ctl.inject(&wire);
        ctl.signal_eof();

        let mut out = Vec::new();
        wrapper.read_to_end(&mut out).await.unwrap();
        assert_eq!(out, b"one\ntwo\nthree\n");
    }

    #[async_test]
    async fn read_passes_through_plaintext(driver: DefaultDriver) {
        let (mut wrapper, ctl) = make_bidi_wrapper(&driver);
        ctl.inject(b"raw plaintext from a non-encrypted client\n");
        ctl.signal_eof();

        let mut out = Vec::new();
        wrapper.read_to_end(&mut out).await.unwrap();
        assert_eq!(out, b"raw plaintext from a non-encrypted client\n");
    }

    #[async_test]
    async fn read_handles_mixed_plaintext_and_records(driver: DefaultDriver) {
        let (mut wrapper, ctl) = make_bidi_wrapper(&driver);
        let sid = host_session_id();
        let mut wire = Vec::new();
        wire.extend_from_slice(b"prefix ");
        wire.extend_from_slice(&build_inbound_record(b"middle", sid, 0));
        wire.extend_from_slice(b" suffix\n");
        ctl.inject(&wire);
        ctl.signal_eof();

        let mut out = Vec::new();
        wrapper.read_to_end(&mut out).await.unwrap();
        assert_eq!(out, b"prefix middle suffix\n");
    }

    #[async_test]
    async fn read_handles_partial_sentinel_across_inner_reads(driver: DefaultDriver) {
        // The first inject delivers the opener but no closing `]]`;
        // the second inject delivers the rest. The wrapper must
        // stitch them without dropping bytes or hanging.
        let (mut wrapper, ctl) = make_bidi_wrapper(&driver);
        let sid = host_session_id();
        let full = build_inbound_record(b"split\n", sid, 0);
        let split = full.len() / 2;
        ctl.inject(&full[..split]);

        // Drive a single poll_read to consume the partial. The
        // wrapper should NOT emit anything yet (whole record needed).
        // Then inject the rest and read to EOF.
        // Use AsyncReadExt::read which gives us one fill per call.
        let mut buf = [0u8; 64];
        let n = futures::future::poll_fn(|cx| {
            // Manually drive one poll_read so we can observe Pending
            // without stalling the test.
            match Pin::new(&mut wrapper).poll_read(cx, &mut buf) {
                Poll::Ready(Ok(n)) => Poll::Ready(Some(n)),
                Poll::Ready(Err(e)) => panic!("poll_read error: {e}"),
                Poll::Pending => Poll::Ready(None),
            }
        })
        .await;
        assert_eq!(n, None, "partial sentinel must not yield plaintext yet");

        ctl.inject(&full[split..]);
        ctl.signal_eof();

        let mut out = Vec::new();
        wrapper.read_to_end(&mut out).await.unwrap();
        assert_eq!(out, b"split\n");
    }

    #[async_test]
    async fn read_then_write_independent_sessions(driver: DefaultDriver) {
        // Confirm the producer (write) session and the consumer
        // (read) session are kept separate: a write of 300 bytes
        // produces one outbound record under the producer's
        // session_id, while a record arriving from a different
        // session_id decrypts cleanly on the read side.
        let (mut wrapper, ctl) = make_bidi_wrapper(&driver);

        let host_sid = host_session_id();
        ctl.inject(&build_inbound_record(b"in\n", host_sid, 0));

        // Drive the inbound read; needs at least one poll cycle.
        let mut buf = [0u8; 64];
        let n = wrapper.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"in\n");

        // Now exercise the producer side.
        wrapper.write_all(&[b'X'; 300]).await.unwrap();
        let outbound = ctl.captured_bytes();
        assert_eq!(
            count_subseq(&outbound, SENTINEL_OPEN),
            1,
            "one outbound record from the 300-byte write"
        );

        // The producer's session_id is `test_session_id()` (the
        // one passed to make_bidi_wrapper); the consumer cached
        // `host_sid`. They must be different.
        assert_ne!(test_session_id(), host_sid);
    }

    #[async_test]
    async fn read_eof_flushes_partial_sentinel_as_passthrough(driver: DefaultDriver) {
        // Inject only the opener bytes, then signal EOF. The
        // wrapper's at_eof drain should pass them through verbatim
        // so a buggy or aborted host doesn't cause silent data loss.
        let (mut wrapper, ctl) = make_bidi_wrapper(&driver);
        ctl.inject(b"hello [[OHENC v1 ");
        ctl.signal_eof();

        let mut out = Vec::new();
        wrapper.read_to_end(&mut out).await.unwrap();
        assert_eq!(out, b"hello [[OHENC v1 ");
    }

    #[async_test]
    async fn read_drains_producer_output(driver: DefaultDriver) {
        // A sub-threshold write arms the producer's idle timer
        // without flushing immediately. A subsequent poll_read must
        // pick that up via poll_drain_output and push the encrypted
        // record onto the wire — independent of whether any inbound
        // bytes are available.
        let (mut wrapper, ctl) = make_bidi_wrapper(&driver);
        wrapper.write_all(b"partial").await.unwrap();
        assert_eq!(ctl.captured_bytes().len(), 0);

        // Sleep past the idle deadline.
        let mut sleeper = PolledTimer::new(&driver);
        sleeper
            .sleep(PRODUCER_IDLE_FLUSH + Duration::from_millis(20))
            .await;

        // Drive one poll_read with no inbound data. The inner has
        // nothing to deliver (returns Pending) but the wrapper
        // should still flush + drain the producer side.
        let mut buf = [0u8; 64];
        let _ = futures::future::poll_fn(|cx| {
            let _ = Pin::new(&mut wrapper).poll_read(cx, &mut buf);
            Poll::Ready(())
        })
        .await;

        let captured = ctl.captured_bytes();
        assert_eq!(
            count_subseq(&captured, SENTINEL_OPEN),
            1,
            "poll_read must drive the producer drain so timer-flushed bytes reach the wire",
        );
    }
}
