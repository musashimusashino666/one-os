# ONE OS

**A security-first operating system research project.**

ONE OS is an experimental, from-scratch operating system. Its long-term goal is to combine a small trusted kernel, explicit capabilities, resilient updates, portable applications, and a human-centred interface.

**Status: bootstrap stage.** This repository is not a daily-use OS. The security principles below are design goals, not claims that all protections already exist.

## Current milestone

- [x] Establish a Rust workspace and automated checks.
- [x] Add an x86_64 bare-metal kernel entry point with COM1 serial diagnostics.
- [x] Add a no_std, testable capability-authorization model.
- [x] Add BIOS disk-image build tooling.
- [x] Document architecture boundaries, threat model, and roadmap.
- [x] Verify three independent QEMU boots in CI and document the local boot procedure.
- [x] Validate BootInfo memory-map ranges before reporting bootstrap completion.
- [x] Verify CPU exception diagnostics with QEMU fault injection for #UD, #GP, and #PF/CR2 (CI Run #120, commit `892b9268c9a6774229189c60557be4d0d22bf541`).
- [x] Define initial memory-region ownership and implement a fixed-capacity physical page allocator with unit and QEMU smoke tests.
- [x] Enable the bootloader recursive page-table mapping and verify read-only four-level translations for kernel code, the active stack, and BootInfo.
- [ ] Set up and test kernel virtual-memory mappings.
- [ ] Add process isolation and kernel-enforced capability/IPC.
- [ ] Add storage, networking, drivers, and a user-space service manager.

## Repository layout

- crates/oneos-core — small, host-testable no_std primitives
- kernel — x86_64 bare-metal kernel entry point
- tools/oneos-xtask — kernel build and BIOS image tooling
- docs/ARCHITECTURE.md — layering and design decisions
- docs/SECURITY.md — threat model and limitations
- docs/DEVELOPMENT.md — build and test instructions
- docs/ROADMAP.md — incremental milestones
- .github/workflows/ci.yml — automated checks and QEMU boot test

## Quick start

Install the nightly Rust toolchain and QEMU. The repository toolchain file requests rustfmt, clippy, llvm-tools-preview, rust-src, and x86_64-unknown-none.

From the repository root:

    cargo fmt --all -- --check
    cargo test --locked -p oneos-core
    cargo clippy --locked -p oneos-core --all-targets -- -D warnings
    cargo run --locked -p oneos-xtask -- image
    IMAGE_DIR="$(cargo metadata --locked --format-version 1 --no-deps | python3 -c 'import json, sys; print(json.load(sys.stdin)["target_directory"])')"
    qemu-system-x86_64 -drive format=raw,file="$IMAGE_DIR/one-os-bios.img" -serial stdio -display none -no-reboot -no-shutdown

The image directory is read from Cargo metadata, so the QEMU command follows a custom CARGO_TARGET_DIR and target-directory settings from Cargo configuration. Python 3 is required for this path lookup. The QEMU command intentionally leaves the guest running after the kernel's bootstrap-completion message; stop it with Ctrl-C. CI uses a non-default CARGO_TARGET_DIR to exercise the portable image-generation path and performs three independent QEMU boot attempts against the built image. See docs/DEVELOPMENT.md for the automated boot check.

## Design principles

1. Small trusted computing base: keep privileged code minimal and move services out of the kernel where practical.
2. Explicit authority: access is deliberate and limited to specific rights.
3. Memory safety by default: prefer memory-safe implementation languages and review unavoidable unsafe code.
4. Recoverability: make failures detectable and recovery testable.
5. Portability without overpromising: separate native, sandboxed, and compatibility execution paths.
6. User control: make data access, network activity, background work, and AI actions visible and revocable.
7. Evidence over claims: publish test conditions and limitations; do not claim security, speed, or compatibility without measurements.

## License

ONE OS is licensed under either the [MIT license](LICENSE-MIT) or the [Apache License, Version 2.0](LICENSE-APACHE), at your option. Cargo package metadata declares this as `MIT OR Apache-2.0`.

## Important limitations

The bootstrap kernel initializes COM1, disables maskable interrupts and masks the legacy PIC, installs a fail-stop x86_64 IDT, structurally validates the boot memory map, initializes a fixed-capacity bitmap allocator over bootloader-designated usable frames, smoke-tests allocation and release, reports startup status, and halts. The dedicated #UD, #GP, and #PF/CR2 QEMU checks passed in CI Run #120 at commit `892b9268c9a6774229189c60557be4d0d22bf541`; this verifies only controlled injection cases in the CI QEMU environment, not general hardware exception robustness. The double-fault gate is configured to use a dedicated TSS/IST stack, with a controlled QEMU fault-injection check; the other exception handlers still use the active stack. This test checks the configured diagnostic path in CI QEMU and does not establish general hardware exception robustness. The initial physical-frame allocator manages up to 16 GiB of aggregate usable RAM across at most 256 usable regions. It tracks 4 KiB frame ownership but does not yet map, zero, or otherwise access allocated data frames; that requires virtual-memory management. The kernel now walks the bootloader-provided four-level page tables through the recursive mapping and validates the kernel-code physical address plus supervisor/write/execute expectations for kernel code, the active stack, and BootInfo; it does not create or remove mappings or change page permissions. The kernel does not yet implement user processes, virtual-memory management, a scheduler, filesystem, networking, or graphical interface. The capability crate is a reference authorization model; it is not yet connected to hardware or a kernel enforcement boundary.

A successful compile or three successful QEMU boot attempts are only initial milestones, not proof of security, performance superiority, or production readiness.
