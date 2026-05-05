// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! `decrypt-serial` --- decrypt encrypted serial console output
//! emitted by OpenHCL VTL2.
//!
//! See `Guide/src/reference/openhcl/diag/decrypt_serial.md` and the
//! `openhcl_serial_console_crypto` crate for the wire-format
//! definition.
//!
//! The crate is currently Linux-only; see the
//! `openhcl_serial_console_crypto` crate docs for why.

#![cfg_attr(not(target_os = "linux"), allow(dead_code, unused_imports))]
#![forbid(unsafe_code)]

#[cfg(target_os = "linux")]
mod decrypt;
#[cfg(target_os = "linux")]
mod key_source;

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!(
        "decrypt-serial is currently Linux-only; see the crate docs. \
         On Windows, run via WSL2."
    );
    std::process::exit(1);
}

#[cfg(target_os = "linux")]
use clap::ArgGroup;
#[cfg(target_os = "linux")]
use clap::Parser;

/// Decrypt encrypted serial console output emitted by OpenHCL VTL2.
///
/// The wire format is documented in
/// `Guide/src/reference/openhcl/diag/decrypt_serial.md`. The
/// AES-256-GCM key is derived from the GuestSecretKey blob
/// (`FileId::GUEST_SECRET_KEY` in the VMGS), which can be supplied
/// either pre-extracted via `--key` or read directly from a plaintext
/// VMGS file via `--vmgs`. Plaintext bytes that appear outside of any
/// record are passed through verbatim.
#[cfg(target_os = "linux")]
#[derive(Parser, Debug)]
#[command(
    name = "decrypt-serial",
    about = "Decrypt OpenHCL VTL2 encrypted serial console output.",
    group = ArgGroup::new("key_source").required(true).args(["key", "vmgs"]),
)]
struct Args {
    /// Path to the encrypted serial capture to decrypt.
    #[arg(short, long, value_name = "PATH")]
    input: std::path::PathBuf,

    /// Where to write the decrypted output. Defaults to stdout.
    #[arg(short, long, value_name = "PATH")]
    output: Option<std::path::PathBuf>,

    /// Pre-extracted GuestSecretKey blob (raw bytes; up to 2048 bytes).
    ///
    /// Mutually exclusive with `--vmgs`.
    #[arg(short, long, value_name = "PATH")]
    key: Option<std::path::PathBuf>,

    /// Plaintext VMGS file from which to read FileId::GUEST_SECRET_KEY.
    ///
    /// Encrypted VMGS files are not supported; extract the GKS out of
    /// band (e.g. via attestation) and pass it via `--key` instead.
    ///
    /// Mutually exclusive with `--key`.
    #[arg(short, long, value_name = "PATH")]
    vmgs: Option<std::path::PathBuf>,

    /// Treat the first malformed sentinel or decrypt failure as
    /// fatal. Default behavior emits an inline marker and keeps
    /// decoding the rest of the capture.
    #[arg(long)]
    strict: bool,
}

#[cfg(target_os = "linux")]
fn main() -> std::process::ExitCode {
    // Logs go to stderr (NEVER stdout) so the decrypted plaintext we
    // write to stdout is uncorrupted.
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_writer(std::io::stderr)
        .init();

    let args = Args::parse();
    // clap's ArgGroup(required=true, multiple=false) makes exactly
    // one of (--key, --vmgs) Some.
    let source = match (args.key.clone(), args.vmgs.clone()) {
        (Some(p), None) => key_source::KeySource::Key(p),
        (None, Some(p)) => key_source::KeySource::Vmgs(p),
        _ => unreachable!("clap ArgGroup ensures exactly one of --key or --vmgs is set"),
    };

    match run(&args, &source) {
        Ok(stats) => {
            tracing::info!(
                records_ok = stats.records_ok,
                records_failed = stats.records_failed,
                sessions = stats.sessions_observed,
                "decrypt-serial finished",
            );
            if args.strict && stats.records_failed > 0 {
                std::process::ExitCode::from(1)
            } else {
                std::process::ExitCode::SUCCESS
            }
        }
        Err(err) => {
            tracing::error!(error = ?err, "decrypt-serial failed");
            eprintln!("decrypt-serial: {err:#}");
            std::process::ExitCode::from(1)
        }
    }
}

#[cfg(target_os = "linux")]
fn run(args: &Args, source: &key_source::KeySource) -> anyhow::Result<decrypt::DecryptStats> {
    use anyhow::Context as _;
    use std::io::Write as _;

    let input = fs_err::read(&args.input).context("reading --input file")?;

    let gks = pal_async::DefaultPool::run_with(async |_| key_source::resolve(source).await)
        .context("resolving key source")?;

    let stats = if let Some(out_path) = args.output.as_ref() {
        let mut out = fs_err::File::create(out_path).context("creating --output file")?;
        let stats = decrypt::run(&input, &mut out, &gks, args.strict)?;
        out.flush().context("flushing --output file")?;
        stats
    } else {
        let stdout = std::io::stdout();
        let mut out = stdout.lock();
        let stats = decrypt::run(&input, &mut out, &gks, args.strict)?;
        out.flush().context("flushing stdout")?;
        stats
    };

    Ok(stats)
}
