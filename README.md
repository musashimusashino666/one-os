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
- [x] Enable the bootloader recursive page-table mapping and audit every page in each bounded ELF64 PT_LOAD segment for translation, physical backing, effective U/S, R/W, and NX permissions (including GNU_RELRO); verify p_offset-derived physical backing for read-only file-backed pages except a partial BSS-tail page, and reserve loaded PT_LOAD frames found in Usable regions before allocation. This does not audit all boot mappings or establish frame-wide W^X.
- [x] Add a bounded read-only inventory of writable/executable leaves, compare physical extents including large-page overlaps, and audit recursive aliases plus registered roots during runtime checks. The inventory is diagnostic, bounded to its declared scope, and does not by itself complete Issue #26.
- [x] Place the kernel at a fixed upper-half virtual base, constrain bootloader-created dynamic mappings to the upper half, and activate a verified root with supervisor-only kernel-half mappings during normal QEMU boot.
- [x] Set up and test initial active-kernel mappings and permission enforcement (limited map/unmap smoke test plus dedicated QEMU protection and TLB-transition cases).
- [x] Integrate the host-testable large-page demotion transaction into the active kernel page-table editor; normal QEMU boot exercises a physical-offset large leaf and verifies translation, effective permissions, and data access under the documented single-CPU, interrupts-disabled, PCID-disabled contract.
- [x] Before normal kernel-root activation, make the physical-memory-offset aliases of validated executable ELF PT_LOAD pages read-only and NX using break-before-make and local TLB invalidation. The exact-head QEMU suite requires zero W^X conflicts in the declared post-activation audit scope; this does not complete global W^X or enable arbitrary executable mappings.
- [ ] Complete full boot-mapping inventory and physical-frame-wide W^X enforcement across kernel/direct-map aliases, address spaces, and large-page overlaps (see [Issue #26](https://github.com/musashimusashino666/one-os/issues/26)).
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

ONE OS remains an experimental bootstrap-stage OS, not a daily-use or production system. The kernel initializes COM1, installs fail-stop x86_64 exception diagnostics, validates the boot memory map, initializes a fixed-capacity bitmap allocator, and halts after its bootstrap checks. The allocator supports up to 16 GiB of aggregate usable RAM across at most 256 usable regions. The configured double-fault TSS/IST diagnostic path and the controlled #UD, #GP, #PF/CR2, supervisor-write-protection, NX, mapping-transition, and address-space smoke tests exercise defined scenarios in the CI QEMU environment; they do not establish general hardware exception robustness or correctness on untested hardware.

The boot-mapping inspector uses the bootloader-provided recursive page-table mapping. Its initial read of the reported recursive PML4 self-reference necessarily relies on the bootloader API's recursive-mapping contract. It parses a bounded ELF64 program-header table and validates every 4 KiB page in every PT_LOAD memory range for a translation, physical backing in a Bootloader- or Usable-owned region, effective user/supervisor, writable, and executable permissions, including GNU_RELRO write protection. For read-only file-backed pages, it checks p_offset-derived physical-frame correspondence, except for a partial page the bootloader may copy while zeroing a BSS tail. Every PT_LOAD frame found in a Usable region is reserved before the allocator can hand out frames. The inspector also validates every 4 KiB page intersecting the active stack, the BootInfo object, and the separately backed memory-region array referenced by BootInfo as writable, supervisor-only, NX mappings. Each backing frame must be fully contained in a Bootloader- or Usable-owned region, and any Usable-backed pages are permanently reserved before the first allocator allocation. These checks do not enumerate every mapping outside PT_LOAD or inventory all aliases of every physical frame.

The kernel performs a bounded, read-only W^X inventory during boot and a separate post-activation audit of the active and registered kernel-created roots. The runtime walk verifies shared upper-half entries, visits declared private lower-half mappings, includes present direct-map leaves, and separately compares recursive page-table aliases with the writable/executable leaf inventory. Before activating the private kernel root, the current candidate also makes the physical-memory-offset aliases of each validated executable ELF PT_LOAD page read-only and NX, demoting 1 GiB/2 MiB leaves where needed and flushing local translations during the transition. CI requires zero observed conflicts in the declared post-activation audit scope. These mechanisms remain bounded and snapshot-based: they do not prove that every possible physical alias, future root, or unregistered mapping is covered. The `FrameWxRegistry` tracks managed 4 KiB mapping lifecycles but is not itself a complete reverse map. Arbitrary new executable mappings remain denied, and Issue #26 remains open for complete boot-mapping verification and frame-wide W^X guarantees.

The guarded page-table editor supports limited 4 KiB kernel mapping operations and dedicated protection/TLB-transition tests, not general-purpose virtual memory. The normal boot path activates a separately allocated supervisor-only kernel root. Runtime root switching and inactive-root teardown have been exercised at CPL 0 under the documented single-CPU, maskable-interrupts-disabled model; this is not Ring 3 execution or process isolation. Independent user processes, validated Ring 3 entry/return, kernel-enforced capabilities, IPC, scheduling, SMP synchronization, and cross-CPU TLB shootdowns are not implemented. The active-kernel mapping editor also does not reclaim every empty intermediate table as part of ordinary single-page unmapping.

The capability crate is a host-testable reference authorization model, not a hardware or kernel enforcement boundary. A successful build, CI run, or QEMU smoke test is evidence only for the scenarios actually tested on that revision; it is not proof of security, performance superiority, or production readiness.
