# decrypt-serial

`decrypt-serial` is a host-side dev/debug tool for decrypting serial console
output that has been emitted by OpenHCL VTL2 in the **encrypted serial
console v1** wire format.

> ⚠ The producer side (VTL2 actually emitting encrypted records on COM3) is
> a planned future PR. The decryptor and the wire-format spec ship first so
> the producer can be developed against a stable target. Until that PR
> lands, you can still exercise the tool end-to-end with the
> [`encrypt_fixture`](#manual-round-trip) helper described below.

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
decrypt-serial --input <PATH> [--output <PATH>] (--key <PATH> | --vmgs <PATH>) [--strict]
```

The most common flow extracts the GKS from the VM's VMGS file with
`vmgstool` and then feeds it to `decrypt-serial`:

```sh
# 1. Extract GUEST_SECRET_KEY (FileId 13) out of the VMGS file.
vmgstool dump --filepath my_vm.vmgs --fileid GUEST_SECRET_KEY \
              --datapath gks.bin --raw-stdout

# 2. Decrypt a captured serial log.
decrypt-serial --key gks.bin --input com3-capture.txt
```

If the VMGS file is plaintext (i.e. not encrypted at rest), you can pass
it directly and skip the manual extraction step:

```sh
decrypt-serial --vmgs my_vm.vmgs --input com3-capture.txt
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
cargo run --example encrypt_fixture -p decrypt-serial -- \
    --key gks.bin --input my.log --output capture.txt

# Decrypt and verify.
cargo run -p decrypt-serial -- \
    --key gks.bin --input capture.txt --output recovered.log

diff my.log recovered.log
```

## Provisioning a GSK in a VMGS for testing

Real GSK provisioning happens through CPS / attestation flows. For a
PoC where you want OpenHCL VTL2 itself (not just the `encrypt_fixture`
helper) to emit encrypted serial, you can seed `FileId::GUEST_SECRET_KEY`
in a plaintext development VMGS with the `provision-gsk` subcommand.

> ⚠ This is a **developer-only** path. It writes raw bytes into the
> GSK slot and does **not** produce a TPM2_Import-shaped duplicate
> blob. The vTPM first-boot import will fail against a VMGS provisioned
> this way, so use it only for VMs that don't exercise vTPM
> provisioning. Encrypted VMGS files are rejected up front.

```sh
# Generate fresh random GSK material directly into the VMGS.
decrypt-serial provision-gsk --vmgs my_vm.vmgs --from-random

# Or, write specific bytes (≤ 2048; zero-padded if shorter).
decrypt-serial provision-gsk --vmgs my_vm.vmgs --from-key gks.bin

# Overwriting an existing slot requires --force.
decrypt-serial provision-gsk --vmgs my_vm.vmgs --from-random --force
```

Once provisioned, the same `--vmgs` file can be passed back to
`decrypt-serial decrypt` (or the streaming subcommands) so the host-side
tool reads exactly the bytes the producer in OpenHCL VTL2 will derive
its AES key from.

## When the producer ships

The follow-up PR that adds the VTL2 producer side should:

1. Take a dependency on `openhcl_serial_console_crypto` to inherit the
   wire format and key derivation.
2. Generate a fresh random 16-byte `session_id` once at startup, after
   the VMGS unlock makes the GKS available.
3. Emit framed records on COM3 (or wherever the encrypted serial sink
   lives) using the format spec above.
4. Add a petri/VMM test that boots a VM with the producer enabled,
   captures the serial output to a file, runs `decrypt-serial` against
   it, and asserts the recovered plaintext matches the expected
   in-guest log lines.
