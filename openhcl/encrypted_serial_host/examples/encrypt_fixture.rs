// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Developer-only round-trip helper for `encrypted-serial`.
//!
//! ⚠ **This is not a sanctioned production encrypt tool.** It exists
//! solely so a developer can manually verify that the decryptor and
//! the wire-format spec match end-to-end without needing a real
//! VTL2 producer or a VM.
//!
//! Usage:
//!
//! ```text
//! cargo run --example encrypt_fixture -p encrypted-serial -- \
//!     --key gks.bin --input my.log > capture.txt
//! cargo run -p encrypted-serial -- decrypt-file \
//!     --key gks.bin --input capture.txt
//! # output should equal my.log
//! ```
//!
//! The example reuses the same key-source resolution code as the
//! decryptor, so `--vmgs <file>` works here too.

#![cfg_attr(not(target_os = "linux"), allow(dead_code, unused_imports))]
#![forbid(unsafe_code)]

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("encrypt_fixture is currently Linux-only; run via WSL2 on Windows.");
    std::process::exit(1);
}

#[cfg(target_os = "linux")]
#[path = "../src/key_source.rs"]
mod key_source;

#[cfg(target_os = "linux")]
fn main() -> anyhow::Result<()> {
    use anyhow::Context as _;
    use clap::ArgGroup;
    use clap::Parser;
    use openhcl_serial_console_crypto::consts::MAX_PLAINTEXT_LEN;
    use openhcl_serial_console_crypto::consts::NONCE_LEN;
    use openhcl_serial_console_crypto::consts::SESSION_ID_LEN;
    use openhcl_serial_console_crypto::crypto::derive_aes_key;
    use openhcl_serial_console_crypto::crypto::encrypt;
    use openhcl_serial_console_crypto::format::Record;
    use std::io::Read as _;
    use std::io::Write;

    /// Encrypt arbitrary plaintext into the v1 wire format used by
    /// `encrypted-serial`. Developer aid only.
    #[derive(Parser, Debug)]
    #[command(
        name = "encrypt_fixture",
        about = "Developer-only encrypt helper for encrypted-serial round-trip testing.",
        group = ArgGroup::new("key_source").required(true).args(["key", "vmgs"]),
    )]
    struct Args {
        /// Plaintext input file. Defaults to stdin.
        #[arg(short, long, value_name = "PATH")]
        input: Option<std::path::PathBuf>,

        /// Output file. Defaults to stdout.
        #[arg(short, long, value_name = "PATH")]
        output: Option<std::path::PathBuf>,

        /// Pre-extracted GuestSecretKey blob.
        #[arg(short, long, value_name = "PATH")]
        key: Option<std::path::PathBuf>,

        /// Plaintext VMGS file from which to read FileId::GUEST_SECRET_KEY.
        #[arg(short, long, value_name = "PATH")]
        vmgs: Option<std::path::PathBuf>,

        /// Maximum plaintext bytes per record. Larger inputs are
        /// chunked across multiple records. Defaults to 1024 bytes;
        /// must be in 1..=MAX_PLAINTEXT_LEN.
        #[arg(long, default_value_t = 1024)]
        chunk_size: usize,
    }

    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .init();

    let args = Args::parse();
    if args.chunk_size == 0 || args.chunk_size > MAX_PLAINTEXT_LEN {
        anyhow::bail!(
            "--chunk-size must be in 1..={MAX_PLAINTEXT_LEN}, got {}",
            args.chunk_size,
        );
    }

    let source = match (args.key, args.vmgs) {
        (Some(p), None) => key_source::KeySource::Key(p),
        (None, Some(p)) => key_source::KeySource::Vmgs(p),
        _ => unreachable!("clap ArgGroup ensures exactly one is set"),
    };

    let mut plaintext = Vec::new();
    if let Some(p) = args.input.as_ref() {
        plaintext = fs_err::read(p).context("reading --input file")?;
    } else {
        std::io::stdin()
            .read_to_end(&mut plaintext)
            .context("reading stdin")?;
    }

    let gks = pal_async::DefaultPool::run_with(async |_| key_source::resolve(&source).await)
        .context("resolving key source")?;

    // Generate one fresh session_id for this run.
    let mut session_id = [0u8; SESSION_ID_LEN];
    getrandom::fill(&mut session_id)
        .map_err(|e| anyhow::anyhow!("generating random session_id: {e}"))?;

    let aes_key = derive_aes_key(&gks, &session_id).context("deriving AES key")?;

    let mut out: Box<dyn Write> = match args.output.as_ref() {
        Some(p) => Box::new(fs_err::File::create(p).context("creating --output file")?),
        None => Box::new(std::io::stdout().lock()),
    };

    for (seq, chunk) in plaintext.chunks(args.chunk_size).enumerate() {
        let mut nonce = [0u8; NONCE_LEN];
        getrandom::fill(&mut nonce).map_err(|e| anyhow::anyhow!("generating random nonce: {e}"))?;
        let (ciphertext, tag) = encrypt(&aes_key, &session_id, seq as u64, &nonce, chunk)
            .context("encrypting chunk")?;
        let record = Record {
            session_id,
            seq: seq as u64,
            nonce,
            ciphertext,
            tag,
        };
        writeln!(out, "{}", record.encode_to_string()).context("writing record")?;
    }

    out.flush().context("flushing output")?;
    Ok(())
}
