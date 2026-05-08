# decrypt-serial test data

`tpm_import_blob.bin` — a 422-byte known-good TPM2_Import duplicate
blob (no inner wrapping key) used by `provision::tests` to exercise
the `--from-blob` validation path.

The blob is a verbatim copy of the `GUEST_SECRET_KEY_BLOB` constant
defined in `vm/devices/tpm/tpm_lib/src/lib.rs::tests::test_initialize_guest_secret_key`.
If that fixture is regenerated upstream, this file should be
regenerated to match.
