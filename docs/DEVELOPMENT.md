# Development Guide

## Prerequisites

- Nightly Rust, selected by rust-toolchain.toml.
- rustfmt, clippy, llvm-tools-preview, and the x86_64-unknown-none target. The toolchain file requests these components and target.
- QEMU with the x86_64 system emulator. On Debian/Ubuntu, install the qemu-system-x86 package.
- Git.

## Checks

Run these from the repository root:

    cargo fmt --all -- --check
    cargo test -p oneos-core
    cargo clippy -p oneos-core --all-targets -- -D warnings
    cargo check -p one-os-kernel --target x86_64-unknown-none

## Build a BIOS image

Run:

    cargo run -p oneos-xtask -- image

The build tool compiles one-os-kernel for x86_64-unknown-none, then uses the bootloader crate to create target/one-os-bios.img. This is a BIOS image; UEFI support is not configured yet.

## Run in QEMU

Run:

    qemu-system-x86_64 -drive format=raw,file=target/one-os-bios.img -serial stdio -display none -no-reboot -no-shutdown

Expected serial output includes:

    ONE OS kernel booted
    Architecture: x86_64
    Milestone: serial bootstrap

The current kernel deliberately halts after writing the startup message. Stop the virtual machine with Ctrl-C. A successful build does not prove that the image boots, which is why CI captures the serial output and checks the startup marker.

## Contribution rules

- Keep pull requests narrowly scoped and describe observable behavior.
- Add tests for each new authorization, state-transition, parser, or recovery behavior.
- Do not add a security claim without an associated test or review artifact.
- Document every new use of unsafe and its safety invariant.
- Avoid adding dependencies to privileged kernel code without a clear need and review.
- Include exact commands and results when reporting validation.
