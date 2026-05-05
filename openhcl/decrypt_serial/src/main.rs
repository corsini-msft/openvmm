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
fn main() -> anyhow::Result<()> {
    anyhow::bail!("decrypt-serial is not yet wired up; subsequent commits add the CLI")
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!(
        "decrypt-serial is currently Linux-only; see the crate docs. \
         On Windows, run via WSL2."
    );
    std::process::exit(1);
}
