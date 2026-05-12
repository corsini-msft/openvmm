// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Bidirectional bridge between a Hyper-V serial pipe (or any
//! bidirectional file-like transport) and the user's terminal.
//!
//! The pipe handle is wrapped in `pal_async::pipe::PolledPipe`, which
//! uses Windows' `FSCTL_PIPE_EVENT_SELECT` to provide non-blocking,
//! event-driven reads and writes on a single underlying handle. This
//! sidesteps the previous architecture's bug: opening one synchronous
//! pipe handle and using `try_clone()` to give the read and write
//! threads their own handles produced two handles to the **same kernel
//! File Object**, and the kernel serializes synchronous I/O at the
//! File Object level. As soon as the recv direction entered a blocking
//! `ReadFile` waiting for VM output, every subsequent `WriteFile` from
//! the send direction queued behind it. Symptom: first keystroke
//! reaches the VM, every subsequent one hangs until the pipe closes.
//! `PolledPipe` avoids the issue because all I/O on it is non-blocking
//! at the OS level and serialized only by our async runtime.
//!
//! Stdin reads still happen on a dedicated synchronous OS thread,
//! since neither std nor pal_async offer asynchronous stdin on
//! Windows. The thread forwards typed bytes to the async send task
//! over a `mesh::channel`.

use anyhow::Context;
use futures::AsyncReadExt;
use futures::AsyncWriteExt;
use futures::StreamExt;
use openhcl_serial_console_crypto::consts::MAX_PLAINTEXT_LEN;
use openhcl_serial_console_crypto::consts::NONCE_LEN;
use openhcl_serial_console_crypto::consts::SESSION_ID_LEN;
use openhcl_serial_console_crypto::crypto::GksKeyMaterial;
use openhcl_serial_console_crypto::crypto::derive_aes_key;
use openhcl_serial_console_crypto::crypto::encrypt;
use openhcl_serial_console_crypto::format::Record;
use openhcl_serial_console_crypto::stream::StreamScanner;
use pal_async::DefaultPool;
use pal_async::pipe::PolledPipe;
use pal_async::task::Spawn;
use std::fs::OpenOptions;
use std::io::IsTerminal;
use std::io::Read;
use std::io::Write;
use std::path::Path;
use std::path::PathBuf;
use std::sync::Arc;
use std::thread;
use std::time::Duration;
use tracing::debug;
use tracing::info;
use tracing::trace;
use tracing::warn;

/// Bridge stdin <-> a bidirectional pipe (Hyper-V named pipe or
/// any other file-like bidirectional transport).
///
/// When `wait` is true and the pipe doesn't yet exist (or the open
/// otherwise fails), retries every 500 ms forever instead of
/// failing fast. Press Ctrl+C to abort the wait.
///
/// When `plain` is true, encryption and decryption are skipped
/// entirely and bytes are forwarded raw between stdin/stdout and
/// the pipe. The OpenHCL side of the pipe must also have
/// encryption disabled (`OPENHCL_DISABLE_ENCRYPTED_SERIAL=1`) for
/// the guest to receive the bytes correctly.
///
/// On Windows, when stdin is attached to a console the bridge
/// switches it to raw mode for the duration of the session and
/// reads from `\\.\CONIN$` directly so each keystroke is forwarded
/// as one record. The console mode is restored on exit. Note that
/// in raw mode Ctrl+C is forwarded to the VM as a `0x03` byte
/// instead of terminating the bridge — close the terminal window
/// to exit.
pub fn bridge(
    key: &Option<PathBuf>,
    vmgs: &Option<PathBuf>,
    pipe_path: &Path,
    wait: bool,
    plain: bool,
) -> anyhow::Result<()> {
    if plain {
        return bridge_plain(pipe_path, wait);
    }

    let gks = Arc::new(super::resolve_key(key, vmgs).context("resolving key source")?);

    info!(
        sha = build_info::get().scm_revision(),
        branch = build_info::get().scm_branch(),
        pipe = ?pipe_path,
        wait,
        "bridge started",
    );

    DefaultPool::run_with(async move |driver| -> anyhow::Result<()> {
        let io = setup_bridge_io(&driver, pipe_path, wait, "encrypted-serial-bridge-stdin")?;
        let BridgeIo {
            pipe_reader,
            pipe_writer,
            stdin_rx,
            _raw_guard,
        } = io;

        let gks_decrypt = gks.clone();
        let recv_task = driver.spawn("bridge-decrypt", async move {
            decrypt_loop(&gks_decrypt, pipe_reader).await
        });

        let gks_encrypt = gks.clone();
        let send_task = driver.spawn("bridge-encrypt", async move {
            let result = encrypt_loop(&gks_encrypt, stdin_rx, pipe_writer).await;
            log_send_exit("bridge", &result);
            result
        });

        await_recv_then_drop_send("bridge", recv_task, send_task).await;
        Ok(())
    })?;
    Ok(())
}

/// Plain-bridge mode: forward raw bytes both directions, bypassing
/// encryption and decryption entirely. Same `PolledPipe` + raw-mode
/// + `\\.\CONIN$` plumbing as [`bridge`].
fn bridge_plain(pipe_path: &Path, wait: bool) -> anyhow::Result<()> {
    info!(
        sha = build_info::get().scm_revision(),
        branch = build_info::get().scm_branch(),
        pipe = ?pipe_path,
        wait,
        "bridge started (plain mode: encryption disabled)",
    );

    DefaultPool::run_with(async move |driver| -> anyhow::Result<()> {
        let io = setup_bridge_io(
            &driver,
            pipe_path,
            wait,
            "encrypted-serial-bridge-plain-stdin",
        )?;
        let BridgeIo {
            pipe_reader,
            pipe_writer,
            stdin_rx,
            _raw_guard,
        } = io;

        let recv_task = driver.spawn("bridge-plain-recv", async move {
            plain_recv_loop(pipe_reader).await
        });

        let send_task = driver.spawn("bridge-plain-send", async move {
            let result = plain_send_loop(stdin_rx, pipe_writer).await;
            log_send_exit("bridge plain", &result);
            result
        });

        await_recv_then_drop_send("bridge plain", recv_task, send_task).await;
        Ok(())
    })?;
    Ok(())
}

/// Plumbing shared by both bridge modes: opened pipe split into a
/// non-blocking reader/writer pair, a stdin -> async-task channel,
/// and the RAII guard that restores the cooked console mode on drop.
struct BridgeIo {
    pipe_reader: futures::io::ReadHalf<PolledPipe>,
    pipe_writer: futures::io::WriteHalf<PolledPipe>,
    stdin_rx: mesh::Receiver<Vec<u8>>,
    _raw_guard: RawConsoleGuard,
}

/// One-stop setup of the I/O scaffolding both `bridge()` and
/// `bridge_plain()` need: open the pipe (waiting if requested),
/// wrap it in `PolledPipe`, switch the console to raw mode, spawn
/// the synchronous stdin reader thread, and hand back the resulting
/// channels and RAII guard.
///
/// `stdin_thread_name` is used as the spawned thread's name so it
/// shows up identifiably in panic backtraces / debugger output.
fn setup_bridge_io(
    driver: &impl pal_async::driver::Driver,
    pipe_path: &Path,
    wait: bool,
    stdin_thread_name: &str,
) -> anyhow::Result<BridgeIo> {
    let pipe = open_pipe_waiting(pipe_path, wait)
        .with_context(|| format!("opening pipe: {pipe_path:?}"))?;
    let polled = PolledPipe::new(driver, pipe).context("wrapping pipe for async I/O")?;
    let (pipe_reader, pipe_writer) = AsyncReadExt::split(polled);

    let raw_guard = enable_raw_input_if_tty()?;

    // Sync stdin → channel → async send/encrypt task. See module
    // doc on why stdin stays on its own OS thread.
    let (stdin_tx, stdin_rx) = mesh::channel::<Vec<u8>>();
    thread::Builder::new()
        .name(stdin_thread_name.into())
        .spawn(move || stdin_reader_loop(stdin_tx))
        .context("spawning stdin reader thread")?;

    Ok(BridgeIo {
        pipe_reader,
        pipe_writer,
        stdin_rx,
        _raw_guard: raw_guard,
    })
}

/// Wait for the recv direction to end (pipe closed by the VM, or a
/// read error). Drop the send task; the receiver going away closes
/// the channel, and the stdin OS thread will exit on its next send
/// (or stay blocked in `read`, in which case process exit terminates
/// it).
async fn await_recv_then_drop_send<R, S>(
    label: &'static str,
    recv_task: pal_async::task::Task<R>,
    send_task: pal_async::task::Task<S>,
) where
    R: 'static + Send + std::fmt::Debug,
    S: 'static + Send,
{
    let recv_result = recv_task.await;
    info!(label, "bridge: recv direction ended, shutting down");
    debug!(label, recv_result = ?recv_result, "bridge recv result");
    drop(send_task);
}

/// Log the send-side task's exit reason. Silent failures here would
/// otherwise look like a frozen bridge with keystrokes queueing in
/// the OS console buffer until the process exits, so the warning is
/// load-bearing.
fn log_send_exit(label: &'static str, result: &anyhow::Result<()>) {
    match result {
        Ok(()) => info!(label, "bridge: send task exited cleanly (stdin EOF)"),
        Err(e) => warn!(label, error = ?e, "bridge: send task exited with error"),
    }
}

/// Synchronous stdin reader. Runs in its own OS thread; forwards
/// bytes to the async send/encrypt task via a `mesh::channel`.
/// Exits when stdin EOFs. Note: `mesh::Sender::send` is infallible
/// (it silently drops the message if the receiver is gone), so the
/// thread can't detect channel closure on its own — process exit
/// terminates it.
fn stdin_reader_loop(sender: mesh::Sender<Vec<u8>>) {
    let result = (|| -> anyhow::Result<()> {
        let mut reader = open_keystroke_source()?;
        let mut buf = vec![0u8; 4096];
        loop {
            trace!("bridge stdin: about to read");
            let n = reader.read(&mut buf).context("reading stdin")?;
            trace!(n, "bridge stdin: read returned");
            if n == 0 {
                info!("bridge stdin: EOF");
                return Ok(());
            }
            sender.send(buf[..n].to_vec());
        }
    })();
    if let Err(e) = result {
        warn!(error = ?e, "bridge stdin: reader thread exited with error");
    }
}

/// Async decrypt loop: read encrypted bytes from the pipe, decrypt
/// (and pass through any non-sentinel bytes), write plaintext to
/// stdout. Stdout writes stay synchronous — they're fast and don't
/// block on remote events.
async fn decrypt_loop<R>(gks: &GksKeyMaterial, mut reader: R) -> anyhow::Result<()>
where
    R: futures::AsyncRead + Unpin,
{
    let mut scanner = StreamScanner::new();
    let mut buf = vec![0u8; 4096];
    let mut total_in: u64 = 0;
    let mut total_out: u64 = 0;
    loop {
        // Don't hold the StdoutLock across await — it isn't Send,
        // and pal_async tasks must be Send.
        let n = reader.read(&mut buf).await.context("reading from pipe")?;
        let stdout = std::io::stdout();
        let mut writer = stdout.lock();
        if n == 0 {
            let stats = scanner
                .drain(gks, /* at_eof */ true, &mut writer)
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
        trace!(
            direction = "recv",
            bytes = n,
            buf_before = scanner.buffered(),
            "bridge: read from pipe",
        );
        scanner.extend(&buf[..n]);
        total_in += n as u64;
        let stats = scanner
            .drain(gks, /* at_eof */ false, &mut writer)
            .context("draining")?;
        total_out += stats.bytes_out;
        writer.flush().context("flushing stdout")?;
    }
}

/// Async encrypt loop: receive plaintext chunks from the stdin
/// reader thread via channel, encrypt each into a record, write to
/// the pipe.
///
/// Each channel message becomes one or more records: the message is
/// split into `MAX_PLAINTEXT_LEN`-sized chunks and each chunk is
/// encrypted into its own record.
async fn encrypt_loop<W>(
    gks: &GksKeyMaterial,
    mut stdin_rx: mesh::Receiver<Vec<u8>>,
    mut writer: W,
) -> anyhow::Result<()>
where
    W: futures::AsyncWrite + Unpin,
{
    let mut session_id = [0u8; SESSION_ID_LEN];
    getrandom::fill(&mut session_id).map_err(|e| anyhow::anyhow!("generating session_id: {e}"))?;
    let aes_key = derive_aes_key(gks, &session_id).context("deriving AES key")?;
    let mut seq: u64 = 0;
    let mut total_in: u64 = 0;
    let mut total_records: u64 = 0;

    info!(
        session_id_first8 = ?&session_id[..8],
        "bridge encrypt: session opened",
    );

    while let Some(bytes) = stdin_rx.next().await {
        let n = bytes.len();
        trace!(direction = "send", bytes = n, "bridge: received from stdin");
        total_in += n as u64;
        for chunk in bytes.chunks(MAX_PLAINTEXT_LEN) {
            let mut nonce = [0u8; NONCE_LEN];
            getrandom::fill(&mut nonce).map_err(|e| anyhow::anyhow!("generating nonce: {e}"))?;
            let (ciphertext, tag) =
                encrypt(&aes_key, &session_id, seq, &nonce, chunk).context("encrypting chunk")?;
            let record = Record {
                session_id,
                seq,
                nonce,
                ciphertext,
                tag,
            };
            let encoded = record.encode_to_string();
            trace!(
                direction = "send",
                seq,
                bytes = encoded.len(),
                "bridge: about to write record",
            );
            // Wire framing: just the sentinel back-to-back, no
            // delimiter — matches the in-VM producer's contract.
            writer
                .write_all(encoded.as_bytes())
                .await
                .context("writing record to pipe")?;
            trace!(direction = "send", seq, "bridge: wrote record");
            seq += 1;
            total_records += 1;
        }
        trace!(direction = "send", "bridge: about to flush");
        writer.flush().await.context("flushing pipe")?;
        debug!(
            direction = "send",
            bytes_in = n,
            records_emitted = total_records,
            "bridge: read+emitted",
        );
    }
    info!(
        total_in,
        total_records, "bridge encrypt: stdin channel closed",
    );
    Ok(())
}

/// Plain recv loop: pipe → stdout, raw bytes. Same instrumentation
/// shape as the encrypted decrypt loop so plain-mode logs are
/// directly comparable.
async fn plain_recv_loop<R>(mut reader: R) -> anyhow::Result<()>
where
    R: futures::AsyncRead + Unpin,
{
    let mut buf = vec![0u8; 4096];
    let mut total: u64 = 0;
    loop {
        trace!(direction = "recv", "bridge plain: about to read");
        let n = reader.read(&mut buf).await.context("reading from pipe")?;
        trace!(direction = "recv", n, "bridge plain: read returned");
        // Don't hold the StdoutLock across await; lock per chunk.
        let stdout = std::io::stdout();
        let mut writer = stdout.lock();
        if n == 0 {
            info!(direction = "recv", total, "bridge plain: pipe EOF");
            return Ok(());
        }
        writer.write_all(&buf[..n]).context("writing stdout")?;
        writer.flush().context("flushing stdout")?;
        total += n as u64;
    }
}

/// Plain send loop: stdin channel → pipe, raw bytes.
async fn plain_send_loop<W>(
    mut stdin_rx: mesh::Receiver<Vec<u8>>,
    mut writer: W,
) -> anyhow::Result<()>
where
    W: futures::AsyncWrite + Unpin,
{
    let mut total: u64 = 0;
    while let Some(bytes) = stdin_rx.next().await {
        let n = bytes.len();
        trace!(
            direction = "send",
            bytes = n,
            "bridge plain: about to write"
        );
        writer.write_all(&bytes).await.context("writing to pipe")?;
        trace!(direction = "send", bytes = n, "bridge plain: wrote");
        writer.flush().await.context("flushing pipe")?;
        total += n as u64;
    }
    info!(
        direction = "send",
        total, "bridge plain: stdin channel closed"
    );
    Ok(())
}

/// Open the byte source for the encrypt direction.
///
/// On Windows when stdin is a console TTY we deliberately bypass
/// `std::io::Stdin` (which uses `ReadConsoleW` and has its own
/// buffering quirks in raw mode) and open `\\.\CONIN$` directly.
/// `File::read` on that handle uses `ReadFile`, which in raw mode
/// returns each keystroke as it arrives.
///
/// On Unix or when stdin isn't a TTY, we just read from stdin
/// normally.
fn open_keystroke_source() -> anyhow::Result<Box<dyn Read + Send>> {
    if cfg!(windows) && std::io::stdin().is_terminal() {
        let conin = OpenOptions::new()
            .read(true)
            .open(r"\\.\CONIN$")
            .context("opening \\\\.\\CONIN$ for raw keystroke reads")?;
        Ok(Box::new(conin))
    } else {
        Ok(Box::new(std::io::stdin()))
    }
}

/// RAII guard returned by [`enable_raw_input_if_tty`]. Restores the
/// console mode on drop.
struct RawConsoleGuard {
    enabled: bool,
}

impl Drop for RawConsoleGuard {
    fn drop(&mut self) {
        if self.enabled {
            if let Err(e) = term::set_raw_console(false) {
                warn!(error = ?e, "failed to restore console mode on bridge exit");
            } else {
                debug!("bridge: restored cooked console mode");
            }
        }
    }
}

fn enable_raw_input_if_tty() -> anyhow::Result<RawConsoleGuard> {
    if !std::io::stdin().is_terminal() {
        return Ok(RawConsoleGuard { enabled: false });
    }
    term::set_raw_console(true).context("enabling raw console mode")?;
    info!(
        "bridge: stdin is a TTY, enabled raw mode (Ctrl+C forwarded to VM; \
         close the terminal window to exit)",
    );
    Ok(RawConsoleGuard { enabled: true })
}

/// Open the named pipe, optionally retrying until it succeeds.
///
/// When `wait` is `false`, the open is attempted exactly once and
/// any error propagates. When `wait` is `true`, retries on **any**
/// I/O error — `--wait` is the user explicitly asking us to keep
/// trying, so we don't try to enumerate transient-vs-permanent
/// error kinds; a truly permanent error just keeps logging until
/// the user Ctrl+C's.
fn open_pipe_waiting(path: &Path, wait: bool) -> std::io::Result<std::fs::File> {
    let attempt = || OpenOptions::new().read(true).write(true).open(path);
    if !wait {
        return attempt();
    }
    let mut tries: u64 = 0;
    loop {
        match attempt() {
            Ok(f) => {
                if tries > 0 {
                    info!(tries, "bridge: pipe became available");
                }
                return Ok(f);
            }
            Err(e) => {
                if tries == 0 {
                    info!(
                        path = ?path,
                        error = %e,
                        "bridge: pipe not yet available, waiting (Ctrl+C to abort)",
                    );
                } else if tries.is_multiple_of(20) {
                    // Re-log every ~10s so users staring at a
                    // quiet terminal know the binary is still
                    // alive.
                    info!(tries, error = %e, "bridge: still waiting for pipe");
                } else {
                    debug!(tries, error = %e, "bridge: pipe open retry");
                }
                tries += 1;
                thread::sleep(Duration::from_millis(500));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn open_pipe_waiting_no_wait_propagates_not_found() {
        // A path that nothing could possibly create on a real
        // host. We expect NotFound (not retried).
        let path = Path::new("./this-path-definitely-does-not-exist-bridge-test");
        let err = open_pipe_waiting(path, false).unwrap_err();
        assert_eq!(
            err.kind(),
            std::io::ErrorKind::NotFound,
            "expected NotFound, got {err:?}",
        );
    }

    #[test]
    fn open_pipe_waiting_with_wait_unblocks_when_path_appears() {
        // The helper just calls OpenOptions::open(path).read(true).write(true);
        // that works on any path the OS can open in r/w mode, regular
        // files included. No need to involve named pipes / FIFOs to
        // exercise the retry loop — we just need a path that doesn't
        // exist initially and shows up after a delay.
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("bridge-wait-test");

        let path_for_thread = path.clone();
        let creator = thread::spawn(move || {
            thread::sleep(Duration::from_millis(150));
            std::fs::File::create(&path_for_thread).expect("creating target file");
        });

        let f = open_pipe_waiting(&path, true)
            .expect("open_pipe_waiting should succeed once the path appears");
        drop(f);
        creator.join().expect("creator thread");
    }
}
