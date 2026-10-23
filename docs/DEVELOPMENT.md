# Development Guide

## Prerequisites

- Nightly Rust, selected by rust-toolchain.toml.
- rustfmt, clippy, llvm-tools-preview, rust-src, and the x86_64-unknown-none target. The toolchain file requests these components and target.
- QEMU with the x86_64 system emulator. On Debian/Ubuntu, install the qemu-system-x86 package.
- Git.
- Python 3 (used to read Cargo's reported target directory for the QEMU command).

## Checks

Run these from the repository root:

    cargo fmt --all -- --check
    cargo test --locked -p oneos-core
    cargo clippy --locked -p oneos-core --all-targets -- -D warnings
    cargo check --locked -p one-os-kernel --target x86_64-unknown-none

## Build a BIOS image

Run:

    cargo run --locked -p oneos-xtask -- image

The build tool compiles one-os-kernel for x86_64-unknown-none, discovers the actual kernel executable from Cargo's compiler-artifact JSON, then uses the bootloader crate to create one-os-bios.img inside Cargo's reported target directory. It honors CARGO_TARGET_DIR; for example, use CARGO_TARGET_DIR=/tmp/one-os-target cargo run --locked -p oneos-xtask -- image to place outputs elsewhere. The bootloader builder needs the nightly toolchain, LLVM tools, and Rust sources so it can build its boot stages. This is a BIOS image; UEFI support is not configured yet.

## Run in QEMU

Run:

    IMAGE_DIR="$(cargo metadata --locked --format-version 1 --no-deps | python3 -c 'import json, sys; print(json.load(sys.stdin)["target_directory"])')"
    qemu-system-x86_64 -drive format=raw,file="$IMAGE_DIR/one-os-bios.img" -serial stdio -display none -no-reboot -no-shutdown

Expected serial output includes:

    ONE OS kernel booted
    Architecture: x86_64
    Milestone: serial bootstrap
    Memory map: structurally validated
    ONE OS BOOTSTRAP COMPLETE

The kernel rejects empty, inverted, or overlapping memory-map ranges before it emits the completion marker. It then deliberately halts; this does not mean physical allocation or virtual memory is implemented. Stop the virtual machine with Ctrl-C. A successful build does not prove that the image boots, which is why CI captures serial output and checks both startup and completion markers while rejecting panic and invalid-map markers.

## Automated boot smoke test

GitHub Actions builds a BIOS disk image, then performs three independent QEMU invocations against that image. Each attempt captures serial output and requires the startup and bootstrap-completion markers to appear in the correct order. Panic, invalid-memory-map markers, missing completion markers, and unexpected exit statuses fail the check. A timeout after the expected markers is normal because the bootstrap kernel deliberately halts without powering down. This smoke test checks boot integration, not OS completeness or security. CI installs the required toolchain components explicitly before building the image and imposes a job timeout to prevent hung runs.

## Contribution rules

- Keep pull requests narrowly scoped and describe observable behavior.
- Add tests for each new authorization, state-transition, parser, or recovery behavior.
- Do not add a security claim without an associated test or review artifact.
- Document every new use of unsafe and its safety invariant.
- Avoid adding dependencies to privileged kernel code without a clear need and review.
- Include exact commands and results when reporting validation.
