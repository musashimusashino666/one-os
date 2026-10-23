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
- [x] Enable the bootloader recursive page-table mapping and perform read-only structural checks of sampled four-level translations for kernel code, the active stack, and BootInfo; this is not an exact ELF PT_LOAD virtual-to-physical mapping proof.
- [x] Set up and test initial active-kernel mappings and permission enforcement (limited map/unmap smoke test plus dedicated QEMU protection and TLB-transition cases).
- [ ] Add process isolation and kernel-enforced capability/IPC (see [docs/ISOLATION_PLAN.md](docs/ISOLATION_PLAN.md)).
- [ ] Add storage, networking, drivers, and a user-space service manager.

## Repository layout

- crates/oneos-core — small, host-testable no_std primitives
- kernel — x86_64 bare-metal kernel entry point
- tools/oneos-xtask — kernel build and BIOS image tooling
- docs/ARCHITECTURE.md — layering and design decisions
- docs/ISOLATION_PLAN.md — user-space isolation contract and acceptance tests
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

The bootstrap kernel initializes COM1, disables maskable interrupts and masks the legacy PIC, installs a fail-stop x86_64 IDT, structurally validates the boot memory map, initializes a fixed-capacity bitmap allocator over bootloader-designated usable frames, smoke-tests allocation and release, reports startup status, and halts. The dedicated #UD, #GP, and #PF/CR2 QEMU checks passed in CI Run #120 at commit `892b9268c9a6774229189c60557be4d0d22bf541`; this verifies only controlled injection cases in the CI QEMU environment, not general hardware exception robustness. The double-fault gate is configured to use a dedicated TSS/IST stack, with a controlled QEMU fault-injection check; the other exception handlers still use the active stack. This test checks the configured diagnostic path in CI QEMU and does not establish general hardware exception robustness. The initial physical-frame allocator manages up to 16 GiB of aggregate usable RAM across at most 256 usable regions. The guarded page-table editor uses owned usable frames to support limited active-kernel 4 KiB mapping operations, including a normal-boot map/access/unmap smoke cycle. This is not a general-purpose virtual-memory manager or a user-process address-space implementation. The kernel now walks the bootloader-provided four-level page tables through the recursive mapping. It checks that the reported recursive PML4 entry is present and references the CR3 root frame; this consistency check's initial read still relies on the bootloader API's recursive-mapping contract. It checks that one sampled kernel-code translation falls within the physical ELF backing interval reported by BootInfo, validates page-offset preservation and expected page-table permission bits for the sampled kernel-code address, active stack pointer, and BootInfo pointer; it also requires CR0.WP to be enabled before treating read-only page-table entries as supervisor-write protection, and requires every page-table page read (including the CR3 root) to be fully contained in a Bootloader-owned region. It does not verify the physical memory-map ownership of the stack or BootInfo leaf mappings, and its error messages describe only the checks actually performed. It does not parse ELF PT_LOAD program headers or compare each segment's p_offset, p_vaddr, p_filesz, and p_memsz against observed translations; these bootstrap checks therefore do not prove exact virtual-to-physical correspondence, completeness or correctness of all mappings, or system-wide memory protection. The read-only inspector does not create or remove mappings or change page permissions; a separate guarded editor now performs limited active-kernel map/unmap operations and is exercised by dedicated QEMU acceptance tests. The kernel does not yet implement independent user-process address spaces, a scheduler, IPC, filesystem, networking, a driver framework, or a graphical interface. The current mapping editor remains limited to bootstrap and acceptance-test operations; SMP synchronization and cross-CPU TLB shootdowns are not implemented. The capability crate is a reference authorization model; it is not yet connected to hardware or a kernel enforcement boundary.

A successful compile or three successful QEMU boot attempts are only initial milestones, not proof of security, performance superiority, or production readiness.
