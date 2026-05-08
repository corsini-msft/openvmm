// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Bidirectional bridge between a Hyper-V serial pipe (or any
//! bidirectional file-like transport) and the user's terminal.
//!
//! Spawns two threads: one decrypts records arriving from the pipe
//! into stdout, the other encrypts user input from stdin into
//! records on the pipe. Each direction runs its own AES-256-GCM
//! session — both keyed off the shared GKS but with distinct
//! `session_id`s, so the two streams sharing one wire transport
//! cannot collide on AES-GCM nonces.
//!
//! Threading instead of `pal_async` here is deliberate: stdin reads
//! are inherently blocking and cancelling them across platforms is
//! awkward. When the pipe closes (decrypt thread sees EOF) the
//! caller process exits, which is enough to tear down the still-
//! blocked stdin reader.

use anyhow::Context;
use openhcl_serial_console_crypto::consts::MAX_PLAINTEXT_LEN;
use openhcl_serial_console_crypto::consts::NONCE_LEN;
use openhcl_serial_console_crypto::consts::SESSION_ID_LEN;
use openhcl_serial_console_crypto::crypto::GksKeyMaterial;
use openhcl_serial_console_crypto::crypto::derive_aes_key;
use openhcl_serial_console_crypto::crypto::encrypt;
use openhcl_serial_console_crypto::format::Record;
use openhcl_serial_console_crypto::stream::StreamScanner;
use std::fs::OpenOptions;
use std::io::BufRead;
use std::io::BufReader;
use std::io::Read;
use std::io::Write;
use std::path::Path;
use std::path::PathBuf;
use std::sync::Arc;
use std::thread;
use tracing::debug;
use tracing::info;
use tracing::warn;

/// Bridge stdin <-> a bidirectional pipe (Hyper-V named pipe or
/// any other file-like bidirectional transport).
pub fn bridge(
    key: &Option<PathBuf>,
    vmgs: &Option<PathBuf>,
    pipe_path: &Path,
) -> anyhow::Result<()> {
    let gks = Arc::new(super::resolve_key(key, vmgs).context("resolving key source")?);

    info!(
        sha = build_info::get().scm_revision(),
        branch = build_info::get().scm_branch(),
        pipe = ?pipe_path,
        "bridge started",
    );

    // Open the pipe twice. On Windows a named pipe opened with
    // GENERIC_READ | GENERIC_WRITE is bidirectional and
    // `File::try_clone()` returns a separate handle; on Unix the
    // same trick works for FIFOs and sockets.
    let pipe_for_decrypt = OpenOptions::new()
        .read(true)
        .write(true)
        .open(pipe_path)
        .with_context(|| format!("opening pipe for decrypt direction: {pipe_path:?}"))?;
    let pipe_for_encrypt = pipe_for_decrypt
        .try_clone()
        .context("cloning pipe handle for encrypt direction")?;

    let gks_decrypt = gks.clone();
    let decrypt_thread = thread::Builder::new()
        .name("encrypted-serial-bridge-decrypt".into())
        .spawn(move || -> anyhow::Result<()> {
            let mut reader = BufReader::new(pipe_for_decrypt);
            let stdout = std::io::stdout();
            let mut writer = stdout.lock();
            decrypt_loop(&gks_decrypt, &mut reader, &mut writer)
        })
        .context("spawning decrypt thread")?;

    let gks_encrypt = gks.clone();
    let encrypt_thread = thread::Builder::new()
        .name("encrypted-serial-bridge-encrypt".into())
        .spawn(move || -> anyhow::Result<()> {
            let stdin = std::io::stdin();
            let mut reader = stdin.lock();
            encrypt_loop(&gks_encrypt, &mut reader, pipe_for_encrypt)
        })
        .context("spawning encrypt thread")?;

    // Wait for the decrypt direction to end (pipe closed by VTL2,
    // or read error). When that happens, exit the whole process —
    // the encrypt thread is most likely blocked on a stdin read
    // that we have no clean way to cancel cross-platform.
    let decrypt_result = decrypt_thread.join();
    info!("bridge: decrypt direction ended, shutting down");
    match decrypt_result {
        Ok(Ok(())) => {}
        Ok(Err(e)) => warn!(error = ?e, "decrypt thread returned error"),
        Err(_) => warn!("decrypt thread panicked"),
    }
    drop(encrypt_thread); // detach; process exit will tear it down
    Ok(())
}

/// Read encrypted records (and any non-sentinel passthrough) from
/// the pipe, decrypt, write plaintext to stdout. Owns its own
/// `StreamScanner` (consumer session keys are observed in incoming
/// records).
fn decrypt_loop<R: BufRead, W: Write>(
    gks: &GksKeyMaterial,
    reader: &mut R,
    writer: &mut W,
) -> anyhow::Result<()> {
    let mut scanner = StreamScanner::new();
    let mut total_in: u64 = 0;
    let mut total_out: u64 = 0;
    loop {
        let n = {
            let chunk = reader.fill_buf().context("reading from pipe")?;
            if chunk.is_empty() {
                let stats = scanner
                    .drain(gks, /* at_eof */ true, writer)
                    .context("draining at EOF")?;
                total_out += stats.bytes_out;
                writer.flush().context("flushing stdout")?;
                info!(
                    total_in,
                    total_out,
                    sessions = scanner.sessions(),
                    "bridge decrypt: pipe EOF",
                );
                return Ok(());
            }
            debug!(
                bytes = chunk.len(),
                buf_before = scanner.buffered(),
                "bridge decrypt: fill_buf",
            );
            scanner.extend(chunk);
            chunk.len()
        };
        reader.consume(n);
        total_in += n as u64;

        let stats = scanner
            .drain(gks, /* at_eof */ false, writer)
            .context("draining")?;
        total_out += stats.bytes_out;
        writer.flush().context("flushing stdout")?;
    }
}

/// Read raw bytes from stdin, encrypt each chunk into a single
/// record, write to the pipe.
///
/// One encrypted record per `Read::read` call: when stdin is in
/// cooked mode (the default for a TTY) each call returns one line,
/// so each line becomes one record. When stdin is in raw mode each
/// call returns one keystroke, so each keystroke becomes one
/// record (higher framing overhead but predictable latency).
/// Chunks larger than `MAX_PLAINTEXT_LEN` are split across multiple
/// records.
fn encrypt_loop<R: Read>(
    gks: &GksKeyMaterial,
    reader: &mut R,
    mut writer: impl Write,
) -> anyhow::Result<()> {
    let mut session_id = [0u8; SESSION_ID_LEN];
    getrandom::fill(&mut session_id)
        .map_err(|e| anyhow::anyhow!("generating session_id: {e}"))?;
    let aes_key = derive_aes_key(gks, &session_id).context("deriving AES key")?;
    let mut seq: u64 = 0;
    let mut total_in: u64 = 0;
    let mut total_records: u64 = 0;

    info!(
        session_id_first8 = ?&session_id[..8],
        "bridge encrypt: session opened",
    );

    let mut buf = vec![0u8; MAX_PLAINTEXT_LEN];
    loop {
        let n = reader.read(&mut buf).context("reading stdin")?;
        if n == 0 {
            info!(
                total_in,
                total_records,
                "bridge encrypt: stdin EOF",
            );
            return Ok(());
        }
        total_in += n as u64;
        for chunk in buf[..n].chunks(MAX_PLAINTEXT_LEN) {
            let mut nonce = [0u8; NONCE_LEN];
            getrandom::fill(&mut nonce)
                .map_err(|e| anyhow::anyhow!("generating nonce: {e}"))?;
            let (ciphertext, tag) =
                encrypt(&aes_key, &session_id, seq, &nonce, chunk)
                    .context("encrypting chunk")?;
            let record = Record {
                session_id,
                seq,
                nonce,
                ciphertext,
                tag,
            };
            // Wire framing: just the sentinel back-to-back, no
            // delimiter — matches the in-VM producer's contract.
            write!(writer, "{}", record.encode_to_string())
                .context("writing record to pipe")?;
            seq += 1;
            total_records += 1;
        }
        writer.flush().context("flushing pipe")?;
        debug!(
            bytes_in = n,
            records_emitted = total_records,
            "bridge encrypt: read+emitted",
        );
    }
}
