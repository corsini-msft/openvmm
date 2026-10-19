# Hackathon 2026 staged OpenVMM changes

This branch preserves the OpenVMM source changes used by the ACE hackathon
prototype so they can be built independently from the packaged OpenVMM release
and intentionally evolved from this point.

## Provenance

- Base commit: `e128eaa7bb44a988ad5f9ad26e24ad555f542932`
  (`virt_mshv: handle SNP GHCB unregister requests`, September 14, 2026).
- Branch: `hackathon2026-staged-changes`.
- The changes were recovered from the known-working hackathon checkout.
- Generated binaries, IGVM images, initrds, and other build artifacts are not
  included.
- Windows checkout type changes under `build_support/windows_cross` are not
  part of this branch.

## Preserved changes

- Forward SNP guest requests through MSHV to the PSP and complete the GHCB
  request.
- Add measured PCIe host-bridge configuration and fixed ECAM placement for the
  SNP Linux direct IGVM.
- Add PCIe virtio-vsock selection and device wiring.
- Add the hackathon headless-mode behavior.
- Preserve the related CLI documentation, configuration, petri, and VMM test
  updates.

The IGVM generator changes are required to reproduce the measured-PCIe image,
but they are not linked into the OpenVMM runtime binary.

## Validation

This historical snapshot was staged without rebuilding or reformatting it.
Before committing or consuming it, run the repository-required checks from WSL:

```bash
cargo xflowey restore-packages

for package in \
    openvmm_core \
    openvmm_defs \
    openvmm_entry \
    petri \
    igvmfilegen \
    igvmfilegen_config \
    virt_mshv \
    vmm_tests
do
    cargo check -p "$package"
    cargo clippy --all-targets -p "$package"
    cargo doc --no-deps -p "$package"
    cargo nextest run --profile agent -p "$package"
done

cargo xtask fmt --fix
```

Formatting is listed last because the repository requires it after the package
checks. Review any resulting formatting changes before committing.

## Compatibility note

This branch deliberately predates the explicit
`MSHV_PT_SNP_NORMAL_INJECTION` partition policy added after the hackathon base.
That distinction matters on the older L1/MSHV environment where the packaged
OpenVMM 0.2.0 currently fails `create_vm` with `EINVAL` before guest boot.
