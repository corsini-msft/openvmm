# encrypted-serial

`encrypted-serial` is a host-side dev/debug tool for encrypting and
decrypting serial console traffic that goes through OpenHCL VTL2 in
the **encrypted serial console v1** wire format. It supports both
directions: decrypting captures and live streams emitted by VTL2,
and (with the `bridge` subcommand) encrypting user input to be sent
back to VTL2.

The crate currently only builds on Linux, because the underlying
`crypto::kdf::kbkdf_hmac_sha256` primitive in the workspace `crypto` crate
is implemented via the Unix-only `openssl_kdf` crate. On Windows hosts, run
the tool from WSL2.

## Wire format (v1)

Each encrypted record is wrapped in a printable ASCII sentinel so that
records can be interleaved with plaintext lines on the same console
without binary corruption:

```
[[OHENC v1 <base64-payload>]]
```

The base64 payload (standard alphabet, padding required, no whitespace,
no line wrapping) decodes to the binary record:

| Offset  | Size | Field          | Notes                                                                  |
| ------: | ---: | -------------- | ---------------------------------------------------------------------- |
|       0 |   16 | `session_id`   | Random per-session identifier produced once per producer startup.      |
|      16 |    8 | `seq` (u64 LE) | Monotonic sequence number within the session.                          |
|      24 |   12 | `nonce`        | AES-256-GCM nonce. Producer guarantees uniqueness within `session_id`. |
|      36 |    N | `ciphertext`   | Encrypted plaintext bytes. `N ≤ 4096`.                                 |
|  36 + N |   16 | `tag`          | AES-256-GCM authentication tag.                                        |

The AES-GCM AAD bound to every record is:

```
"OpenHCL encrypted serial console v1 AES-256-GCM\0"
    || session_id (16 bytes)
    || seq (u64 LE)
```

Tampering with the version domain string, the `session_id`, or the `seq`
will fail tag verification.

### Inter-record framing

Records run **back-to-back** on the wire with no inter-record delimiter:

```
[[OHENC v1 <base64-A>]][[OHENC v1 <base64-B>]][[OHENC v1 <base64-C>]]
```

The closing `]]` of one record sits flush against the opening `[[` of the
next. There is no `\n` between records, and no `\n` after the final record.
Consumers MUST scan for `[[OHENC v1 ` openers / `]]` closers directly in
the byte stream and MUST NOT depend on any in-band delimiter.

When encrypted records are interleaved with passthrough plaintext (e.g.
GRUB output before VTL2 starts encrypting), any bytes outside `[[OHENC v1
...]]` brackets are forwarded to the consumer's output verbatim. Consumers
should therefore treat the wire as `(plaintext | record)*` rather than as
a line-oriented stream.

### Producer flush policy

The producer (`EncryptingSerialIo` in `underhill_core`) emits a record
when **any** of the following holds:

- The pending plaintext buffer reaches the soft size threshold
  (`PRODUCER_SOFT_FLUSH_BYTES` = 256 bytes). Mirrors typical TLS record
  sizing; amortises the ~100 bytes of per-record framing overhead.
- The buffer reaches the hard upper bound (`MAX_PLAINTEXT_LEN` = 4096
  bytes). Records cannot be larger than this.
- The buffer became non-empty `PRODUCER_IDLE_FLUSH` (50 ms) ago and no
  flush has fired since. Bounds the worst-case latency between a
  producer write and the corresponding wire record so partial output
  never sits in the buffer indefinitely.

Byte content does not affect flushing — the producer does not look for
`\n`, `\r`, or any other terminator. This avoids starving on output
without line terminators (ANSI escapes, prompts, partial UTF-8 across
writes) and keeps record boundaries time- and size-bounded rather than
content-dependent.

## Per-session keys

The AES-256-GCM key is derived per-`session_id` from the 2048-byte
`GUEST_SECRET_KEY` (GKS) blob in the VMGS:

```
aes_key = KBKDF-HMAC-SHA-256(
    key        = GKS bytes (2048),
    context    = b"OpenHCL encrypted serial console v1 AES-256-GCM key",
    salt       = session_id (16 bytes),
    output_len = 32,
)
```

Per-session keys mean the producer is free to use either random or counter
nonces within a session: nonce uniqueness only has to hold per-session,
not for the entire VM lifetime. The decryptor caches the derivation
result per `session_id` so it does not re-run the KDF for every record.

The shared library crate `openhcl_serial_console_crypto` (`openhcl/openhcl_serial_console_crypto/`)
owns the wire-format and key-derivation code. The eventual producer in
OpenHCL VTL2 will depend on the same crate, ensuring byte-for-byte
compatibility.

## Usage

```text
encrypted-serial decrypt-file --input <PATH> [--output <PATH>] (--key <PATH> | --vmgs <PATH>) [--strict]
encrypted-serial decrypt-stream (--key <PATH> | --vmgs <PATH>) [--verbose]
encrypted-serial encrypt-stream (--key <PATH> | --vmgs <PATH>) [--verbose]
encrypted-serial bridge --pipe <PATH> (--key <PATH> | --vmgs <PATH>) [--verbose]
encrypted-serial version
```

### `bridge` (bidirectional)

`bridge` is the recommended way to use the encrypted serial console
interactively. It opens a single bidirectional pipe (typically a
Hyper-V serial named pipe) and runs both directions over it:

```sh
encrypted-serial bridge --key gks.bin --pipe '\\.\pipe\my-vm-com3'
```

If the pipe doesn't exist yet (e.g. you launched `bridge` before
starting the VM), pass `--wait` to retry every 500 ms forever
until it's available — Ctrl+C aborts:

```sh
# Order-independent: works whether you start the VM before or
# after the bridge.
encrypted-serial bridge --key gks.bin --pipe '\\.\pipe\my-vm-com3' --wait
```

Behind the scenes the binary spawns two threads:

- **decrypt thread:** reads encrypted records from the pipe,
  decrypts them, and writes plaintext to stdout.
- **encrypt thread:** reads bytes from stdin, encrypts each chunk
  into a single record, and writes it to the pipe.

Each direction owns its own AES-256-GCM session (independent
`session_id`s, derived from the same shared GKS), so the two
streams sharing one wire transport cannot collide on AES-GCM
nonces.

For per-keystroke latency rather than per-line, put your terminal
in raw mode before invoking `bridge` — each `read()` call returns
when the OS has bytes for you, so a raw-mode terminal produces
one record per keystroke.

### File / stream subcommands

The most common flow extracts the GKS from the VM's VMGS file with
`vmgstool` and then feeds it to `encrypted-serial decrypt-file`:

```sh
# 1. Extract GUEST_SECRET_KEY (FileId 13) out of the VMGS file.
vmgstool dump --filepath my_vm.vmgs --fileid GUEST_SECRET_KEY \
              --datapath gks.bin --raw-stdout

# 2. Decrypt a captured serial log.
encrypted-serial decrypt-file --key gks.bin --input com3-capture.txt
```

If the VMGS file is plaintext (i.e. not encrypted at rest), you can pass
it directly and skip the manual extraction step:

```sh
encrypted-serial decrypt-file --vmgs my_vm.vmgs --input com3-capture.txt
```

Encrypted VMGS files are explicitly **not** supported by `--vmgs`;
unlocking those requires attestation, which is out of scope for a host
debug tool. The tool detects this case up front and produces a friendly
error pointing back at the `--key` workflow.

### Behavior summary

- **Plaintext passthrough.** Bytes that appear outside any sentinel are
  copied through to the output verbatim, so a capture that starts with
  plaintext boot output and switches to encrypted records once the GKS
  becomes available decrypts cleanly into a single readable stream.
- **Decrypt failures (default).** Tampered or malformed records are
  reported with an inline `<<decrypt failed offset=N reason=...>>`
  marker, and the scan continues. The reported offset is the byte
  position of the failed sentinel in the input file (the `seq` field is
  attacker-controlled on a failed record so we deliberately do not
  surface it).
- **Decrypt failures (`--strict`).** The first malformed sentinel or
  decrypt failure aborts the run with a non-zero exit code.
- **Sequence-gap warnings.** Once at least one record from a given
  session has authenticated successfully, missing or out-of-order
  sequence numbers within that session are reported as warnings on
  stderr.
- **Logging.** Tracing output goes strictly to stderr so the decrypted
  plaintext on stdout is never corrupted.

## Manual round-trip

To verify the tool works end-to-end without a real producer or VM, the
crate ships a Cargo example called `encrypt_fixture` that produces v1
records from arbitrary plaintext using the same library code the
decryptor consumes. **It is a developer aid only — not a sanctioned
encrypt CLI.** The eventual VTL2 producer will live in OpenHCL itself.

```sh
# Generate a random 2 KB GKS for testing.
head -c 2048 /dev/urandom > gks.bin

# Encrypt some plaintext.
cargo run --example encrypt_fixture -p encrypted-serial -- \
    --key gks.bin --input my.log --output capture.txt

# Decrypt and verify.
cargo run -p encrypted-serial -- decrypt-file \
    --key gks.bin --input capture.txt --output recovered.log

diff my.log recovered.log
```

## Provisioning a GSK in a VMGS for testing

Real GSK provisioning happens through CPS / attestation flows. For a
PoC where you want OpenHCL VTL2 itself (not just the `encrypt_fixture`
helper) to emit encrypted serial, you can seed `FileId::GUEST_SECRET_KEY`
in a plaintext development VMGS with the `provision-gsk` subcommand.

> ⚠ This is a **developer-only** path. The same VMGS slot is consumed
> by the vTPM at first boot, so the bytes written must form a valid
> TPM2_Import duplicate blob (no inner wrapping key) — the same
> structure that `tpm_lib::TpmEngineHelper::initialize_guest_secret_key`
> parses. The tool validates the blob up front using the same parser
> the vTPM uses, so a malformed file fails here rather than breaking
> first-boot. Encrypted VMGS files are rejected.

```sh
# Provision a TPM2_Import-shaped blob into the VMGS.
encrypted-serial provision-gsk --vmgs my_vm.vmgs --from-blob importable.bin

# Overwriting an existing slot requires --force.
encrypted-serial provision-gsk --vmgs my_vm.vmgs --from-blob importable.bin --force
```

Producing the importable blob itself is out of scope for this tool.
For a known-good test fixture, see `openhcl/encrypted_serial_host/test_data/
tpm_import_blob.bin` (a 422-byte mirror of the
`GUEST_SECRET_KEY_BLOB` constant in
`vm/devices/tpm/tpm_lib/src/lib.rs`). For real provisioning, generate
a duplicate blob using `tpm2-tools`, OpenSSL+marshalling, or
equivalent CPS tooling.

Once provisioned, the same `--vmgs` file can be passed back to
`encrypted-serial decrypt-file` (or the streaming subcommands) so the
host-side tool reads exactly the bytes the producer in OpenHCL VTL2
will derive its AES key from.

## When the producer ships

The follow-up PR that adds the VTL2 producer side should:

1. Take a dependency on `openhcl_serial_console_crypto` to inherit the
   wire format and key derivation.
2. Generate a fresh random 16-byte `session_id` once at startup, after
   the VMGS unlock makes the GKS available.
3. Emit framed records on COM3 (or wherever the encrypted serial sink
   lives) using the format spec above.
4. Add a petri/VMM test that boots a VM with the producer enabled,
   captures the serial output to a file, runs `encrypted-serial`
   against it, and asserts the recovered plaintext matches the
   expected in-guest log lines.
