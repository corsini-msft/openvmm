// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! `encrypted-serial` --- encrypt and decrypt serial console output
//! and input for OpenHCL VTL2's encrypted serial console.
//!
//! See `Guide/src/reference/openhcl/diag/encrypted_serial.md` and the
//! `openhcl_serial_console_crypto` crate for the wire-format
//! definition.

#![forbid(unsafe_code)]

mod bridge;
mod decrypt_file;
mod key_source;
mod stream;

use clap::ArgGroup;
use clap::Parser;
use clap::Subcommand;

/// Encrypt and decrypt serial console traffic for OpenHCL VTL2.
#[derive(Parser, Debug)]
#[command(name = "encrypted-serial")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Decrypt a captured serial file.
    DecryptFile(DecryptArgs),
    /// Stream-decrypt from stdin, writing plaintext to stdout.
    /// Reads bytes from a live pipe.
    DecryptStream(StreamKeyArgs),
    /// Stream-encrypt from stdin, writing encrypted records to stdout.
    /// Reads line-by-line for live pipe usage.
    EncryptStream(StreamKeyArgs),
    /// Bidirectional bridge between a Hyper-V serial pipe (or any
    /// other bidirectional file-like transport) and the user's
    /// terminal: decrypts what arrives from the pipe to stdout, and
    /// encrypts what the user types on stdin back to the pipe.
    /// Each direction runs its own encryption session.
    Bridge(BridgeArgs),
    /// Print build info (git SHA, branch, wire-format version) and exit.
    /// Useful for verifying that a freshly-built binary actually contains
    /// a specific change rather than a stale cached binary.
    Version,
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
    /// Equivalent to setting `RUST_LOG=encrypted_serial=debug` (or
    /// `=trace`). Logs are written to stderr; decrypted output
    /// continues to go to stdout, so this is safe to leave on
    /// while piping output to a file.
    #[arg(long, action = clap::ArgAction::Count)]
    verbose: u8,
}

#[derive(clap::Args, Debug)]
#[command(
    group = ArgGroup::new("key_source").required(true).args(["key", "vmgs"]),
)]
struct BridgeArgs {
    /// Pre-extracted GuestSecretKey blob (raw bytes; up to 2048 bytes).
    #[arg(short, long, value_name = "PATH")]
    key: Option<std::path::PathBuf>,

    /// Plaintext VMGS file from which to read FileId::GUEST_SECRET_KEY.
    #[arg(short, long, value_name = "PATH")]
    vmgs: Option<std::path::PathBuf>,

    /// Path to the bidirectional pipe to bridge against. On Windows
    /// this is typically a Hyper-V named pipe like
    /// `\\.\pipe\<name>`. On Unix it can be a FIFO or a Unix
    /// domain socket path that the OS supports opening via
    /// `OpenOptions`.
    #[arg(long, value_name = "PATH")]
    pipe: std::path::PathBuf,

    /// Increase log verbosity. Same semantics as on
    /// `decrypt-stream` / `encrypt-stream`.
    #[arg(long, action = clap::ArgAction::Count)]
    verbose: u8,
}

fn main() -> std::process::ExitCode {
    let cli = Cli::parse();

    // If a stream subcommand was passed `--verbose`, raise the
    // default log level before the env filter is built. An explicit
    // `RUST_LOG=...` still wins.
    let default_filter = match &cli.command {
        Commands::DecryptStream(args) | Commands::EncryptStream(args) => match args.verbose {
            0 => "info",
            1 => "encrypted_serial=debug,info",
            _ => "encrypted_serial=trace,info",
        },
        Commands::Bridge(args) => match args.verbose {
            0 => "info",
            1 => "encrypted_serial=debug,info",
            _ => "encrypted_serial=trace,info",
        },
        Commands::DecryptFile(_) | Commands::Version => "info",
    };

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(default_filter)),
        )
        .with_writer(std::io::stderr)
        .init();

    match cli.command {
        Commands::DecryptFile(args) => run_decrypt_file(&args),
        Commands::DecryptStream(args) => run_decrypt_stream(&args),
        Commands::EncryptStream(args) => run_encrypt_stream(&args),
        Commands::Bridge(args) => run_bridge(&args),
        Commands::Version => run_version(),
    }
}

/// Distinctive feature marker for this build. Bump when the wire
/// format or scanner contract changes meaningfully so users can
/// tell apart "old binary" vs "new binary" without grepping for a
/// SHA. Current values:
///
/// - `v1-back-to-back-no-lf`: producer emits records back-to-back
///   on the wire with no inter-record `\n`; consumer is a streaming
///   sentinel scanner that doesn't depend on any in-band delimiter.
const FEATURE_MARKER: &str = "v1-back-to-back-no-lf";

fn run_version() -> std::process::ExitCode {
    let info = build_info::get();
    println!("encrypted-serial");
    println!("  package version: {}", env!("CARGO_PKG_VERSION"));
    println!(
        "  git sha:         {}",
        if info.scm_revision().is_empty() {
            "(unknown - built outside a git checkout?)"
        } else {
            info.scm_revision()
        }
    );
    println!(
        "  git branch:      {}",
        if info.scm_branch().is_empty() {
            "(unknown)"
        } else {
            info.scm_branch()
        }
    );
    println!("  wire format:     {FEATURE_MARKER}");
    println!("  features:        --verbose, streaming sentinel scanner");
    std::process::ExitCode::SUCCESS
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

fn run_decrypt_file(args: &DecryptArgs) -> std::process::ExitCode {
    use anyhow::Context as _;
    use std::io::Write as _;

    let result = (|| -> anyhow::Result<decrypt_file::DecryptStats> {
        let input = fs_err::read(&args.input).context("reading --input file")?;
        let gks = resolve_key(&args.key, &args.vmgs).context("resolving key source")?;
        let stats = if let Some(out_path) = args.output.as_ref() {
            let mut out = fs_err::File::create(out_path).context("creating --output file")?;
            let stats = decrypt_file::run(&input, &mut out, &gks, args.strict)?;
            out.flush().context("flushing --output file")?;
            stats
        } else {
            let stdout = std::io::stdout();
            let mut out = stdout.lock();
            let stats = decrypt_file::run(&input, &mut out, &gks, args.strict)?;
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
                "encrypted-serial decrypt-file finished",
            );
            if args.strict && stats.records_failed > 0 {
                std::process::ExitCode::from(1)
            } else {
                std::process::ExitCode::SUCCESS
            }
        }
        Err(err) => {
            tracing::error!(error = ?err, "encrypted-serial decrypt-file failed");
            eprintln!("encrypted-serial: {err:#}");
            std::process::ExitCode::from(1)
        }
    }
}

fn run_decrypt_stream(args: &StreamKeyArgs) -> std::process::ExitCode {
    match stream::stream_decrypt(&args.key, &args.vmgs) {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("encrypted-serial decrypt-stream: {err:#}");
            std::process::ExitCode::from(1)
        }
    }
}

fn run_encrypt_stream(args: &StreamKeyArgs) -> std::process::ExitCode {
    match stream::stream_encrypt(&args.key, &args.vmgs) {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("encrypted-serial encrypt-stream: {err:#}");
            std::process::ExitCode::from(1)
        }
    }
}

fn run_bridge(args: &BridgeArgs) -> std::process::ExitCode {
    match bridge::bridge(&args.key, &args.vmgs, &args.pipe) {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("encrypted-serial bridge: {err:#}");
            std::process::ExitCode::from(1)
        }
    }
}
