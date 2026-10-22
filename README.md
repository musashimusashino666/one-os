# ONE OS

**A security-first operating system research project.**

ONE OS is an experimental, from-scratch operating system. Its long-term goal is to combine a small trusted kernel, explicit capabilities, resilient updates, portable applications, and a human-centred interface.

**Status: bootstrap stage.** This repository is not a daily-use OS. The security principles below are design goals, not claims that all protections already exist.

## Current milestone

- [x] Establish a Rust workspace and automated checks.
- [x] Add an x86_64 bare-metal kernel entry point with COM1 serial diagnostics.
- [x] Add a small, no_std, testable capability-authorization model.
- [x] Document architecture boundaries, threat model, and roadmap.
- [ ] Build a bootable disk image and verify boot under QEMU.
- [ ] Implement memory-map handling, exception/interrupt setup, and allocation strategy.
- [ ] Add process isolation and kernel-enforced capability/IPC.
- [ ] Add storage, networking, drivers, and a user-space service manager.

## Repository layout

- crates/oneos-core — small, host-testable no_std primitives
- kernel — x86_64 bare-metal kernel entry point
- docs/ARCHITECTURE.md — layering and design decisions
- docs/SECURITY.md — threat model and limitations
- docs/DEVELOPMENT.md — build and test instructions
- docs/ROADMAP.md — incremental milestones
- .github/workflows/ci.yml — automated checks

## Quick start

Install stable Rust with rustfmt and clippy, then run these commands from the repository root:

    cargo fmt --all -- --check
    cargo test -p oneos-core
    cargo clippy -p oneos-core --all-targets -- -D warnings
    rustup target add x86_64-unknown-none
    cargo check -p one-os-kernel --target x86_64-unknown-none

See docs/DEVELOPMENT.md for details.

## Design principles

1. Small trusted computing base: keep privileged code minimal and move services out of the kernel where practical.
2. Explicit authority: access is deliberate and limited to specific rights.
3. Memory safety by default: prefer memory-safe implementation languages and review unavoidable unsafe code.
4. Recoverability: make failures detectable and recovery testable.
5. Portability without overpromising: separate native, sandboxed, and compatibility execution paths.
6. User control: make data access, network activity, background work, and AI actions visible and revocable.
7. Evidence over claims: publish test conditions and limitations; do not claim security, speed, or compatibility without measurements.

## Important limitations

The current kernel only initializes a serial console, reports that it has started, and halts. It does not yet implement user processes, virtual-memory management, a scheduler, filesystem, networking, graphical interface, or disk-image generation. The capability crate is a reference authorization model; it is not yet connected to hardware or a kernel enforcement boundary.

ONE OS will be considered usable only after repeatable boot tests, automated tests, hardware testing, security review, and documented compatibility results.
