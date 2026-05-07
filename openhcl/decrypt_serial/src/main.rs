// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! `decrypt-serial` --- decrypt encrypted serial console output
//! emitted by OpenHCL VTL2.
//!
//! See `Guide/src/reference/openhcl/diag/decrypt_serial.md` and the
//! `openhcl_serial_console_crypto` crate for the wire-format
//! definition.

#![forbid(unsafe_code)]

mod decrypt;
mod key_source;
mod stream;

use clap::ArgGroup;
use clap::Parser;
use clap::Subcommand;

/// Decrypt (or encrypt) serial console output for OpenHCL VTL2.
#[derive(Parser, Debug)]
#[command(name = "decrypt-serial")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Decrypt a captured serial file (existing behavior).
    Decrypt(DecryptArgs),
    /// Stream-decrypt from stdin, writing plaintext to stdout.
    /// Reads line-by-line for live pipe usage.
    StreamDecrypt(StreamKeyArgs),
    /// Stream-encrypt from stdin, writing encrypted records to stdout.
    /// Reads line-by-line for live pipe usage.
    StreamEncrypt(StreamKeyArgs),
}

#[derive(clap::Args, Debug)]
#[command(
    group = ArgGroup::new("key_source").required(true).args(["key", "vmgs"]),
)]
struct DecryptArgs {
    /// Path to the encrypted serial capture to decrypt.
    #[arg(short, long, value_name = "PATH")]
    input: std::path::PathBuf,

    /// Where to write the decrypted output. Defaults to stdout.
    #[arg(short, long, value_name = "PATH")]
    output: Option<std::path::PathBuf>,

    /// Pre-extracted GuestSecretKey blob (raw bytes; up to 2048 bytes).
    #[arg(short, long, value_name = "PATH")]
    key: Option<std::path::PathBuf>,

    /// Plaintext VMGS file from which to read FileId::GUEST_SECRET_KEY.
    #[arg(short, long, value_name = "PATH")]
    vmgs: Option<std::path::PathBuf>,

    /// Treat the first malformed sentinel or decrypt failure as fatal.
    #[arg(long)]
    strict: bool,
}

#[derive(clap::Args, Debug)]
#[command(
    group = ArgGroup::new("key_source").required(true).args(["key", "vmgs"]),
)]
struct StreamKeyArgs {
    /// Pre-extracted GuestSecretKey blob (raw bytes; up to 2048 bytes).
    #[arg(short, long, value_name = "PATH")]
    key: Option<std::path::PathBuf>,

    /// Plaintext VMGS file from which to read FileId::GUEST_SECRET_KEY.
    #[arg(short, long, value_name = "PATH")]
    vmgs: Option<std::path::PathBuf>,

    /// Increase log verbosity. Pass `--verbose` for debug-level
    /// (per fill_buf, per record, per passthrough). Pass twice
    /// (`--verbose --verbose`) for trace-level (also includes
    /// hex dumps of input bytes).
    ///
    /// Equivalent to setting `RUST_LOG=decrypt_serial=debug` (or
    /// `=trace`). Logs are written to stderr; decrypted output
    /// continues to go to stdout, so this is safe to leave on
    /// while piping output to a file.
    #[arg(long, action = clap::ArgAction::Count)]
    verbose: u8,
}

fn main() -> std::process::ExitCode {
    let cli = Cli::parse();

    // If a stream subcommand was passed `-v` / `-vv`, raise the
    // default log level before the env filter is built. An explicit
    // `RUST_LOG=...` still wins.
    let default_filter = match &cli.command {
        Commands::StreamDecrypt(args) | Commands::StreamEncrypt(args) => match args.verbose {
            0 => "info",
            1 => "decrypt_serial=debug,info",
            _ => "decrypt_serial=trace,info",
        },
        Commands::Decrypt(_) => "info",
    };

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(default_filter)),
        )
        .with_writer(std::io::stderr)
        .init();

    match cli.command {
        Commands::Decrypt(args) => run_decrypt(&args),
        Commands::StreamDecrypt(args) => run_stream_decrypt(&args),
        Commands::StreamEncrypt(args) => run_stream_encrypt(&args),
    }
}

fn resolve_key(
    key: &Option<std::path::PathBuf>,
    vmgs: &Option<std::path::PathBuf>,
) -> anyhow::Result<openhcl_serial_console_crypto::crypto::GksKeyMaterial> {
    let source = match (key.clone(), vmgs.clone()) {
        (Some(p), None) => key_source::KeySource::Key(p),
        (None, Some(p)) => key_source::KeySource::Vmgs(p),
        _ => unreachable!("clap ArgGroup ensures exactly one of --key or --vmgs is set"),
    };
    pal_async::DefaultPool::run_with(async |_| key_source::resolve(&source).await)
        .map_err(Into::into)
}

fn run_decrypt(args: &DecryptArgs) -> std::process::ExitCode {
    use anyhow::Context as _;
    use std::io::Write as _;

    let result = (|| -> anyhow::Result<decrypt::DecryptStats> {
        let input = fs_err::read(&args.input).context("reading --input file")?;
        let gks = resolve_key(&args.key, &args.vmgs).context("resolving key source")?;
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
    })();

    match result {
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

fn run_stream_decrypt(args: &StreamKeyArgs) -> std::process::ExitCode {
    match stream::stream_decrypt(&args.key, &args.vmgs) {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("decrypt-serial stream-decrypt: {err:#}");
            std::process::ExitCode::from(1)
        }
    }
}

fn run_stream_encrypt(args: &StreamKeyArgs) -> std::process::ExitCode {
    match stream::stream_encrypt(&args.key, &args.vmgs) {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("decrypt-serial stream-encrypt: {err:#}");
            std::process::ExitCode::from(1)
        }
    }
}
