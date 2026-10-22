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
- [ ] Prove repeatable boot under QEMU in CI and on a documented local setup.
- [ ] Implement memory-map handling, exception/interrupt setup, and allocation strategy.
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

Install the nightly Rust toolchain and QEMU. The repository toolchain file requests rustfmt, clippy, llvm-tools-preview, and x86_64-unknown-none.

From the repository root:

    cargo fmt --all -- --check
    cargo test -p oneos-core
    cargo clippy -p oneos-core --all-targets -- -D warnings
    cargo run -p oneos-xtask -- image
    qemu-system-x86_64 -drive format=raw,file=target/one-os-bios.img -serial stdio -display none -no-reboot -no-shutdown

The QEMU command intentionally leaves the guest running after the kernel's startup message; stop it with Ctrl-C. See docs/DEVELOPMENT.md for the automated boot check.

## Design principles

1. Small trusted computing base: keep privileged code minimal and move services out of the kernel where practical.
2. Explicit authority: access is deliberate and limited to specific rights.
3. Memory safety by default: prefer memory-safe implementation languages and review unavoidable unsafe code.
4. Recoverability: make failures detectable and recovery testable.
5. Portability without overpromising: separate native, sandboxed, and compatibility execution paths.
6. User control: make data access, network activity, background work, and AI actions visible and revocable.
7. Evidence over claims: publish test conditions and limitations; do not claim security, speed, or compatibility without measurements.

## Important limitations

The current kernel only initializes a serial console, reports that it has started, and halts. It does not yet implement user processes, virtual-memory management, a scheduler, filesystem, networking, or graphical interface. The capability crate is a reference authorization model; it is not yet connected to hardware or a kernel enforcement boundary.

A successful compile or one successful QEMU boot is only an initial milestone, not proof of security, performance superiority, or production readiness.
