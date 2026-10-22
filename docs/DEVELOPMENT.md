# Development Guide

## Prerequisites

- A current stable Rust toolchain with rustfmt and clippy.
- The x86_64-unknown-none target for checking the kernel.
- Git.
- QEMU will be needed for the planned image/boot integration; disk-image generation is not yet configured.

## Checks

Run these from the repository root:

    cargo fmt --all -- --check
    cargo test -p oneos-core
    cargo clippy -p oneos-core --all-targets -- -D warnings
    rustup target add x86_64-unknown-none
    cargo check -p one-os-kernel --target x86_64-unknown-none

The core crate is the default workspace member so ordinary cargo test stays focused on host-testable primitives. The bare-metal kernel is checked explicitly for its target.

## Kernel status

The kernel writes a short startup message to COM1 (I/O port 0x3F8) and halts. It currently depends on the bootloader_api entry-point ABI but does not create a bootloader disk image. The next boot milestone must add a reproducible image-building command and verify output under QEMU.

## Contribution rules

- Keep pull requests narrowly scoped and describe observable behavior.
- Add tests for each new authorization, state-transition, parser, or recovery behavior.
- Do not add a security claim without an associated test or review artifact.
- Document every new use of unsafe and its safety invariant.
- Avoid adding dependencies to the privileged kernel without a clear need and review.
- Include exact commands and results when reporting validation.

## Test reporting

A local check and a CI check are different claims. Record which commands were run and whether they passed. If the kernel has not been booted in QEMU or on hardware, say so explicitly.
