# ONE OS

**A security-first operating system research project.**

ONE OS aims to give people secure, understandable, and revocable control
over their digital environment, with resilience and practical choice.

“World-class” is an engineering target earned through evidence.
It is not a claim about current maturity.

> **Current status: bootstrap-stage research.**
> ONE OS is not a daily-use or production operating system.
> A design goal or passing test does not establish a global guarantee.

## Current implementation

The current target is an x86_64 Rust BIOS/QEMU kernel.

Implemented slices include:

- A bare-metal kernel and host-testable `no_std` core crate.
- BIOS image tooling and a fixed-capacity frame allocator.
- Selected boot-mapping inspection and guarded page-table operations.
- QEMU checks for selected protection and TLB transitions.
- CR3 checks at source, optimized-assembly, and linked-ELF levels.

The linked-ELF CR3 check covers the normal BIOS image.
It does not inspect every feature-specific test image.

Major incomplete areas:

- Global frame-wide W^X and complete boot-map classification.
- Ring 3 process isolation and kernel-enforced capabilities.
- IPC, scheduling, storage, networking, and integrated drivers.
- SMP, authenticated boot, signed updates, and recovery.
- A usable service manager and user environment.

See [Implementation Status](docs/project/IMPLEMENTATION_STATUS.md)
for verified scope and known exclusions.

## Start here

- [Documentation map](docs/README.md)
- [Contributing](CONTRIBUTING.md)
- [Security policy](SECURITY.md)

## Build and verification

Use the pinned Rust toolchain in `rust-toolchain.toml`.
QEMU and Python 3 are required for the full acceptance workflow.

Follow the [Development Guide](docs/engineering/DEVELOPMENT.md)
for setup, build, and local commands.
See the [Verification Strategy](docs/engineering/VERIFICATION.md)
for CI, QEMU profiles, and evidence requirements.

A successful build or boot is not proof of global security properties.

## Project rules

1. Requirements and aspirations are not implementation evidence.
2. Security claims state scope, assumptions, tests, and exclusions.
3. Milestones require evidence on the exact reviewed commit.
4. Security-boundary changes update specifications and tests.
5. Fail-closed behavior must not be weakened to make tests pass.

## License

Dual-licensed under MIT or Apache-2.0.
See [LICENSE-MIT](LICENSE-MIT) and [LICENSE-APACHE](LICENSE-APACHE).
