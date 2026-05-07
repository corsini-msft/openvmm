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
use openhcl_serial_console_crypto::consts::SESSION_ID_LEN;
use openhcl_serial_console_crypto::crypto::GksKeyMaterial;
use openhcl_serial_console_crypto::crypto::derive_aes_key;
use openhcl_serial_console_crypto::crypto::encrypt;
use openhcl_serial_console_crypto::format::Record;
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

        let wrapper = EncryptingSerialIo::new(inner_io, aes_key, session_id);
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
/// is not yet implemented).
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
}

impl InspectMut for EncryptingSerialIo {
    fn inspect_mut(&mut self, req: inspect::Request<'_>) {
        let mut resp = req.respond();
        resp.field("seq", self.seq)
            .field("plaintext_pending", self.plaintext_buf.len())
            .field("output_pending", self.output_buf.len());
    }
}

impl EncryptingSerialIo {
    fn new(inner: Box<dyn SerialIo>, aes_key: [u8; 32], session_id: [u8; SESSION_ID_LEN]) -> Self {
        Self {
            inner,
            aes_key,
            session_id,
            seq: 0,
            plaintext_buf: Vec::new(),
            output_buf: VecDeque::new(),
        }
    }

    /// Encrypt any pending plaintext into output records. Splits on
    /// newlines so each line becomes one record. Any remaining bytes
    /// after the last newline stay in the buffer (flushed later by
    /// `poll_flush` or when a newline arrives).
    fn flush_plaintext_to_output(&mut self) -> Result<(), io::Error> {
        self.flush_plaintext_to_output_inner(false)
    }

    /// Flush all plaintext, including any partial line at the end.
    fn flush_all_plaintext_to_output(&mut self) -> Result<(), io::Error> {
        self.flush_plaintext_to_output_inner(true)
    }

    fn flush_plaintext_to_output_inner(&mut self, flush_partial: bool) -> Result<(), io::Error> {
        loop {
            if self.plaintext_buf.is_empty() {
                break;
            }

            // Find the next newline to split on.
            let chunk = if let Some(nl_pos) = self.plaintext_buf.iter().position(|&b| b == b'\n') {
                // Include the newline in the record.
                let chunk: Vec<u8> = self.plaintext_buf.drain(..=nl_pos).collect();
                chunk
            } else if self.plaintext_buf.len() >= MAX_PLAINTEXT_LEN {
                // Buffer overflow — flush a max-size chunk.
                let chunk: Vec<u8> = self.plaintext_buf.drain(..MAX_PLAINTEXT_LEN).collect();
                chunk
            } else if flush_partial {
                // Flush whatever remains (called from poll_flush).
                let chunk: Vec<u8> = self.plaintext_buf.drain(..).collect();
                chunk
            } else {
                // No newline yet and buffer not full — wait for more data.
                break;
            };

            self.encrypt_and_enqueue(&chunk)?;
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
        self.output_buf.push_back(b'\n');

        self.seq += 1;
        Ok(())
    }

    /// Try to drain output_buf into the inner transport.
    fn poll_drain_output(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
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
        // Pass through reads unmodified for now.
        Pin::new(&mut *self.inner).poll_read(cx, buf)
    }

    fn poll_read_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &mut [IoSliceMut<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut *self.inner).poll_read_vectored(cx, bufs)
    }
}

impl AsyncWrite for EncryptingSerialIo {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        // First try to drain any pending encrypted output.
        match self.poll_drain_output(cx) {
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Ok(())) => {}
        }

        // Accept plaintext into the buffer.
        let accepted = buf.len();
        self.plaintext_buf.extend_from_slice(buf);

        // Encrypt when we see a newline (line-buffered), which
        // batches typical serial output into one record per line
        // instead of one record per byte.
        if self.plaintext_buf.contains(&b'\n') {
            self.flush_plaintext_to_output()?;
            // Try to start draining right away.
            let _ = self.poll_drain_output(cx);
        }

        Poll::Ready(Ok(accepted))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // Encrypt any remaining plaintext, including partial lines.
        self.flush_all_plaintext_to_output()?;

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
