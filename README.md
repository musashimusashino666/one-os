# ONE OS

**A security-first operating system research project.**

ONE OS aims to give people secure, understandable, and revocable control over their digital environment, with resilience and practical software choice. “World-class” is a target that must be earned with reproducible evidence, not a claim of current maturity.

> **Current status: bootstrap-stage research.** ONE OS is not a daily-use or production operating system. Security principles describe design goals unless an implementation and its acceptance evidence are explicitly identified.

## What exists today

The current x86_64 Rust bootstrap includes a bare-metal kernel, a host-testable `no_std` core crate, BIOS image tooling, fixed-capacity physical-frame allocation, selected boot mapping inspection, guarded page-table operations, and QEMU acceptance paths for selected protection and TLB-transition behavior.

Important limitations remain: global frame-wide W^X is incomplete; Ring 3 process isolation and kernel-enforced capabilities are not complete; SMP and remote TLB shootdowns are unsupported; storage, networking, integrated drivers, a service manager, and a usable user environment are not implemented. See [Implementation Status](docs/project/IMPLEMENTATION_STATUS.md) for the bounded status snapshot.

## Start here

- [Documentation map](docs/README.md)
- [Vision and definition](docs/vision/VISION.md)
- [Design principles](docs/vision/PRINCIPLES.md)
- [Success criteria](docs/vision/SUCCESS_CRITERIA.md)
- [Architecture overview](docs/architecture/OVERVIEW.md)
- [Security model](docs/architecture/SECURITY_MODEL.md)
- [Specifications](docs/specs/)
- [Development guide](docs/engineering/DEVELOPMENT.md)
- [Verification strategy](docs/engineering/VERIFICATION.md)
- [Implementation status](docs/project/IMPLEMENTATION_STATUS.md)
- [Roadmap](docs/project/ROADMAP.md)
- [Architecture decision records](docs/project/decisions/)

## Quick start

Use the pinned nightly Rust toolchain, the components and target in `rust-toolchain.toml`, QEMU, and Python 3.

~~~sh
cargo fmt --all -- --check
cargo test --locked -p oneos-core
cargo clippy --locked -p oneos-core --all-targets -- -D warnings
cargo clippy --locked -p one-os-kernel --target x86_64-unknown-none -- -D warnings
cargo clippy --locked -p oneos-xtask --all-targets -- -D warnings
cargo check --locked -p one-os-kernel --target x86_64-unknown-none
cargo run --locked -p oneos-xtask -- image
~~~

The QEMU boot profile, expected markers, and full acceptance flow are documented in the [development guide](docs/engineering/DEVELOPMENT.md) and [verification strategy](docs/engineering/VERIFICATION.md). A successful build or boot is not proof of global security properties.

## Project rules

1. Requirements and aspirations are not evidence of implementation.
2. Security claims must state scope, assumptions, tests, and exclusions.
3. A milestone is complete only when its acceptance criteria pass on the exact reviewed commit.
4. Changes to security boundaries and long-lived architecture decisions require updated specifications and, where appropriate, an ADR.
5. Do not relax fail-closed behavior to make a test pass.

## License

Dual-licensed under MIT or Apache-2.0. See [LICENSE-MIT](LICENSE-MIT) and [LICENSE-APACHE](LICENSE-APACHE).
